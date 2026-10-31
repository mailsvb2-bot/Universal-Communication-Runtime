use ucr_core::{CallStore, DurableRecordStatus, DurableStoreError, GroupCallLookupStore};
use ucr_model::{
    CallId, CallParticipantState, CallParticipantUpdateKind, CallSession, CallSignal,
    CallSignalKind, CallSignallingState, ConversationKind, GroupId, GroupMemberState,
    GroupMembership, GroupRecord, PrincipalRef, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    active_call_participant, apply_call_signal, call_creation_fingerprint, call_signal_fingerprint,
    canonical_call_creation, canonical_call_session, reconcile_group_call_membership,
};

use super::{
    MemoryLocalStore, MemoryState, call_key, call_signal_key, conversation_key,
    event_key_from_parts,
};

impl GroupCallLookupStore for MemoryLocalStore {
    fn calls_for_group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<CallSession>, DurableStoreError> {
        if max_items == 0 || max_items > 64 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(group) = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.group_id == *group_id)
        else {
            return Ok(Vec::new());
        };
        let mut call_ids = state
            .calls
            .values()
            .filter(|call| call.scope == *scope && call.conversation == group.conversation)
            .map(|call| call.call_id.clone())
            .collect::<Vec<_>>();
        call_ids.sort_by(|left, right| left.as_opaque().as_str().cmp(right.as_opaque().as_str()));
        call_ids.truncate(max_items);
        call_ids
            .into_iter()
            .map(|call_id| {
                validated_call_from_state(&state, scope, &call_id)?
                    .ok_or(DurableStoreError::Corrupt)
            })
            .collect()
    }

    fn active_calls_for_group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<CallSession>, DurableStoreError> {
        if max_items == 0 || max_items > 64 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(group) = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.group_id == *group_id)
        else {
            return Ok(Vec::new());
        };
        let mut call_ids = state
            .calls
            .values()
            .filter(|call| {
                call.scope == *scope
                    && call.conversation == group.conversation
                    && call.signalling_state != CallSignallingState::Terminated
            })
            .map(|call| call.call_id.clone())
            .collect::<Vec<_>>();
        call_ids.sort_by(|left, right| left.as_opaque().as_str().cmp(right.as_opaque().as_str()));
        call_ids.truncate(max_items);
        call_ids
            .into_iter()
            .map(|call_id| {
                validated_call_from_state(&state, scope, &call_id)?
                    .ok_or(DurableStoreError::Corrupt)
            })
            .collect()
    }

    fn call_belongs_to_group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        call_id: &CallId,
    ) -> Result<bool, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(group) = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.group_id == *group_id)
        else {
            return Ok(false);
        };
        let Some(call) = validated_call_from_state(&state, scope, call_id)? else {
            return Ok(false);
        };
        Ok(call.conversation == group.conversation)
    }
}

/// One in-memory canonical creation path under the same mutex as Call signals.
fn create_call_with_parent_guard(
    store: &MemoryLocalStore,
    creator: &ScopedPrincipal,
    session: &CallSession,
    parent: Option<&CallSession>,
) -> Result<DurableRecordStatus, DurableStoreError> {
    let session = canonical_call_creation(session, &creator.scope, &creator.principal)
        .map_err(map_call_error)?;
    let creation_fingerprint = call_creation_fingerprint(&session).map_err(map_call_error)?;
    let key = call_key(&session.scope, &session.call_id);
    let conversation_key =
        conversation_key(&session.scope, &session.conversation.conversation_id);
    let state = &mut *store.state.lock().map_err(|_| DurableStoreError::Internal)?;
    if let Some(parent) = parent {
        if parent.scope != session.scope
            || parent.call_id == session.call_id
            || parent.conversation.kind != ConversationKind::Direct
            || parent.signalling_state != CallSignallingState::Active
            || parent.participants.len() != 2
            || !parent.participants.iter().all(|participant| {
                participant.state == CallParticipantState::Accepted
                    && participant.left_revision.is_none()
            })
            || validated_call_from_state(state, &parent.scope, &parent.call_id)?.as_ref()
                != Some(parent)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
    }
    let conversation = state
        .conversations
        .get(&conversation_key)
        .ok_or(DurableStoreError::InvalidRecord)?;
    if conversation.conversation != session.conversation {
        return Err(DurableStoreError::InvalidRecord);
    }
    if let Some(existing) = validated_call_from_state(state, &session.scope, &session.call_id)?
    {
        if !group_actor_current_if_needed(state, &existing, &creator.principal) {
            return Err(DurableStoreError::PermissionDenied);
        }
        let recorded = state
            .call_creation_fingerprints
            .get(&key)
            .ok_or(DurableStoreError::Corrupt)?;
        return if recorded == &creation_fingerprint
            && creator.principal == existing.initiated_by
        {
            Ok(DurableRecordStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    require_group_participants_if_needed(state, &session)?;
    state
        .call_creation_fingerprints
        .insert(key.clone(), creation_fingerprint);
    state.calls.insert(key, session);
    Ok(DurableRecordStatus::Persisted)
}

impl CallStore for MemoryLocalStore {
    fn create_call(
        &self,
        creator: &ScopedPrincipal,
        session: &CallSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        create_call_with_parent_guard(self, creator, session, None)
    }

    fn create_call_if_parent_current(
        &self,
        creator: &ScopedPrincipal,
        session: &CallSession,
        parent: &CallSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        create_call_with_parent_guard(self, creator, session, Some(parent))
    }

    fn call(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        validated_call_from_state(&state, scope, call_id)
    }

    fn call_for_participant(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError> {
        if subject.scope != *scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(session) = validated_call_from_state(&state, scope, call_id)? else {
            return Ok(None);
        };
        if !active_call_participant(&session, &subject.principal)
            || !group_actor_current_if_needed(&state, &session, &subject.principal)
        {
            return Ok(None);
        }
        Ok(Some(session))
    }

    fn incoming_direct_calls(
        &self,
        recipient: &ScopedPrincipal,
        max_items: usize,
    ) -> Result<Vec<CallSession>, DurableStoreError> {
        if max_items == 0 || max_items > 64 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut ids = state
            .calls
            .values()
            .filter(|call| {
                call.scope == recipient.scope
                    && call.conversation.kind == ConversationKind::Direct
                    && call.initiated_by != recipient.principal
                    && matches!(
                        call.signalling_state,
                        CallSignallingState::Inviting | CallSignallingState::Ringing
                    )
                    && call.participants.iter().any(|participant| {
                        participant.principal == recipient.principal
                            && matches!(
                                participant.state,
                                CallParticipantState::Invited | CallParticipantState::Ringing
                            )
                    })
            })
            .map(|call| call.call_id.clone())
            .collect::<Vec<_>>();
        ids.sort_by(|a, b| a.as_opaque().as_str().cmp(b.as_opaque().as_str()));
        ids.truncate(max_items);
        ids.into_iter()
            .map(|id| {
                let call = validated_call_from_state(&state, &recipient.scope, &id)?
                    .ok_or(DurableStoreError::Corrupt)?;
                if !active_call_participant(&call, &recipient.principal) {
                    return Err(DurableStoreError::Corrupt);
                }
                Ok(call)
            })
            .collect()
    }

    fn apply_call_signal(
        &self,
        actor: &ScopedPrincipal,
        signal: &CallSignal,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != signal.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = call_signal_fingerprint(signal).map_err(map_call_error)?;
        let key = call_key(&signal.scope, &signal.call_id);
        let signal_key = call_signal_key(&signal.scope, signal.event_id.as_opaque().as_str());
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let current = validated_call_from_state(&state, &signal.scope, &signal.call_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if !group_actor_current_if_needed(&state, &current, &actor.principal) {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some((recorded_actor, existing, applied_revision)) =
            state.call_signals.get(&signal_key)
        {
            if recorded_actor != &actor.principal
                || !duplicate_actor_allowed(&current, &actor.principal, *applied_revision)
            {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if !active_call_participant(&current, &actor.principal) {
            return Err(DurableStoreError::PermissionDenied);
        }
        require_group_signal_target_if_needed(&state, &current, signal)?;
        let next = apply_call_signal(&current, &actor.scope, &actor.principal, signal)
            .map_err(map_call_error)?;
        let event_key = event_key_from_parts(&signal.scope, signal.event_id.as_opaque().as_str());
        if state.events.contains_key(&event_key) || state.group_changes.contains_key(&event_key) {
            return Err(DurableStoreError::Conflict);
        }
        let applied_revision = next.revision;
        state.calls.insert(key, next);
        state.call_signals.insert(
            signal_key,
            (actor.principal.clone(), fingerprint, applied_revision),
        );
        Ok(DurableRecordStatus::Persisted)
    }
}

fn validated_call_from_state(
    state: &MemoryState,
    scope: &TenantScope,
    call_id: &CallId,
) -> Result<Option<CallSession>, DurableStoreError> {
    let key = call_key(scope, call_id);
    let Some(session) = state.calls.get(&key) else {
        return if state.call_creation_fingerprints.contains_key(&key) {
            Err(DurableStoreError::Corrupt)
        } else {
            Ok(None)
        };
    };
    let canonical = canonical_call_session(session).map_err(map_call_error)?;
    let recorded = state
        .call_creation_fingerprints
        .get(&key)
        .ok_or(DurableStoreError::Corrupt)?;
    let derived = call_creation_fingerprint(&canonical).map_err(map_call_error)?;
    if recorded != &derived {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(Some(canonical))
}

pub(super) fn reconcile_group_calls_after_membership_change(
    state: &mut MemoryState,
    group: &GroupRecord,
    memberships: &[GroupMembership],
) -> Result<(), DurableStoreError> {
    let active_members = memberships
        .iter()
        .filter(|membership| membership.state == GroupMemberState::Active)
        .map(|membership| membership.member.clone())
        .collect::<Vec<_>>();
    let mut updates = Vec::new();
    for (key, current) in &state.calls {
        if current.scope != group.scope || current.conversation != group.conversation {
            continue;
        }
        let next =
            reconcile_group_call_membership(current, &active_members).map_err(map_call_error)?;
        if next != *current {
            updates.push((key.clone(), next));
        }
    }
    for (key, next) in updates {
        state.calls.insert(key, next);
    }
    Ok(())
}

fn require_group_participants_if_needed(
    state: &MemoryState,
    session: &CallSession,
) -> Result<(), DurableStoreError> {
    if !matches!(
        session.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Ok(());
    }
    let group = state
        .groups
        .values()
        .find(|group| group.scope == session.scope && group.conversation == session.conversation)
        .ok_or(DurableStoreError::PermissionDenied)?;
    for participant in &session.participants {
        let active = state.group_memberships.values().any(|membership| {
            membership.scope == session.scope
                && membership.group_id == group.group_id
                && membership.member == participant.principal
                && membership.state == GroupMemberState::Active
        });
        if !active {
            return Err(DurableStoreError::PermissionDenied);
        }
    }
    Ok(())
}

fn group_actor_current_if_needed(
    state: &MemoryState,
    session: &CallSession,
    actor: &PrincipalRef,
) -> bool {
    if !matches!(
        session.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return true;
    }
    let Some(group) = state
        .groups
        .values()
        .find(|group| group.scope == session.scope && group.conversation == session.conversation)
    else {
        return false;
    };
    state.group_memberships.values().any(|membership| {
        membership.scope == session.scope
            && membership.group_id == group.group_id
            && membership.member == *actor
            && membership.state == GroupMemberState::Active
    })
}

fn require_group_signal_target_if_needed(
    state: &MemoryState,
    session: &CallSession,
    signal: &CallSignal,
) -> Result<(), DurableStoreError> {
    let CallSignalKind::ParticipantUpdate {
        participant,
        kind: CallParticipantUpdateKind::Add,
    } = &signal.kind
    else {
        return Ok(());
    };
    if !matches!(
        session.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Ok(());
    }
    let group = state
        .groups
        .values()
        .find(|group| group.scope == session.scope && group.conversation == session.conversation)
        .ok_or(DurableStoreError::PermissionDenied)?;
    let active = state.group_memberships.values().any(|membership| {
        membership.scope == session.scope
            && membership.group_id == group.group_id
            && membership.member == *participant
            && membership.state == GroupMemberState::Active
    });
    if active {
        Ok(())
    } else {
        Err(DurableStoreError::PermissionDenied)
    }
}

fn duplicate_actor_allowed(
    session: &CallSession,
    actor: &PrincipalRef,
    applied_revision: u64,
) -> bool {
    let Some(participant) = session
        .participants
        .iter()
        .find(|value| value.principal == *actor)
    else {
        return false;
    };
    if session.signalling_state == CallSignallingState::Terminated {
        return session.revision == applied_revision;
    }
    if active_call_participant(session, actor) {
        return true;
    }
    match participant.state {
        CallParticipantState::Rejected | CallParticipantState::Busy => {
            participant.left_revision.is_none() && session.revision >= applied_revision
        }
        CallParticipantState::Left => participant.left_revision == Some(applied_revision),
        CallParticipantState::Invited
        | CallParticipantState::Ringing
        | CallParticipantState::Accepted => false,
    }
}

fn map_call_error(error: ucr_protocol::CallSignallingError) -> DurableStoreError {
    use ucr_protocol::CallSignallingError;
    match error {
        CallSignallingError::PermissionDenied => DurableStoreError::PermissionDenied,
        CallSignallingError::RevisionMismatch
        | CallSignallingError::InvalidTransition
        | CallSignallingError::ParticipantAlreadyExists
        | CallSignallingError::WouldRemoveInitiator => DurableStoreError::Conflict,
        CallSignallingError::TooManyParticipants => DurableStoreError::Full,
        _ => DurableStoreError::InvalidRecord,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_core::{
        AtomicTrustedDeviceEnrollmentStore, AuthorizedDurableRuntime, CallStore, ConversationStore,
        DeviceLifecycleStore, IdentityStore, PermissionGrantStore, PrincipalIdentityBindingStore,
    };
    use ucr_model::{
        CallParticipant, CallSignallingState, CallTerminationReason, ConversationId,
        ConversationRecord, ConversationRef, DeviceDescriptor, DeviceId, DeviceLifecycleState,
        EventId, IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord, KeyId,
        KeyPurpose, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalIdentityBinding, PrincipalKind, PublicKeyDescriptor, TenantId,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant")),
            namespace_id: None,
        }
    }

    fn subject(id: &str, kind: PrincipalKind) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind,
            },
        }
    }

    fn fixture() -> (
        ConversationRecord,
        CallSession,
        ScopedPrincipal,
        ScopedPrincipal,
    ) {
        let alice = subject("alice", PrincipalKind::Person);
        let bob = subject("bob", PrincipalKind::Person);
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        };
        let session = CallSession {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call")),
            conversation: conversation.conversation.clone(),
            initiated_by: alice.principal.clone(),
            participants: vec![
                CallParticipant {
                    principal: alice.principal.clone(),
                    state: CallParticipantState::Accepted,
                    joined_revision: 0,
                    left_revision: None,
                },
                CallParticipant {
                    principal: bob.principal.clone(),
                    state: CallParticipantState::Invited,
                    joined_revision: 0,
                    left_revision: None,
                },
            ],
            signalling_state: CallSignallingState::Inviting,
            reconnecting_participant: None,
            media_negotiation_ref: None,
            media_negotiation_generation: 0,
            replication_generation: 0,
            revision: 0,
            termination_reason: None,
        };
        (conversation, session, alice, bob)
    }

    fn prepare_first_party_person_device(
        store: &MemoryLocalStore,
        principal: &ScopedPrincipal,
        identity: &str,
        device: &str,
        key: &str,
    ) -> DeviceId {
        let identity_id = IdentityId::from_opaque(oid(identity));
        store
            .persist_identity(&IdentityRecord {
                scope: principal.scope.clone(),
                identity_id: identity_id.clone(),
                ownership: IdentityOwnership::UserManaged,
                evidence: IdentityEvidence::DeviceVerified,
                expires_at_unix_ms: None,
            })
            .unwrap();
        store
            .persist_principal_identity_binding(&PrincipalIdentityBinding {
                scope: principal.scope.clone(),
                principal: principal.principal.clone(),
                identity_id: identity_id.clone(),
            })
            .unwrap();
        let device_id = DeviceId::from_opaque(oid(device));
        store
            .enroll_new_trusted_device(
                &principal.scope,
                &DeviceDescriptor {
                    device_id: device_id.clone(),
                    identity_id,
                    state: DeviceLifecycleState::Active,
                },
                &PublicKeyDescriptor {
                    key_id: KeyId::from_opaque(oid(key)),
                    device_id: device_id.clone(),
                    purpose: KeyPurpose::Signing,
                    algorithm_id: ucr_protocol::SIGNATURE_ALGORITHM_ID.to_owned(),
                    algorithm_version: ucr_protocol::ALGORITHM_VERSION,
                    key_format_version: ucr_protocol::KEY_FORMAT_VERSION,
                    public_key: vec![9; 32],
                },
            )
            .unwrap();
        for permission in [
            ucr_protocol::CALL_START_PERMISSION,
            ucr_protocol::CALL_OBSERVE_PERMISSION,
            ucr_protocol::CALL_SIGNAL_PERMISSION,
        ] {
            store
                .grant_permission(&PermissionGrant {
                    grantee: principal.clone(),
                    permission: permission.to_owned(),
                    scope: PermissionScope::Exact(principal.scope.clone()),
                })
                .unwrap();
        }
        device_id
    }

    fn first_party_call_fixture() -> (
        MemoryLocalStore,
        CallSession,
        ScopedPrincipal,
        ScopedPrincipal,
        DeviceId,
        DeviceId,
    ) {
        let store = MemoryLocalStore::default();
        let (conversation, session, alice, bob) = fixture();
        store.persist_conversation(&conversation).unwrap();
        let alice_device = prepare_first_party_person_device(
            &store,
            &alice,
            "alice-identity",
            "alice-device",
            "alice-key",
        );
        let bob_device = prepare_first_party_person_device(
            &store,
            &bob,
            "bob-identity",
            "bob-device",
            "bob-key",
        );
        (store, session, alice, bob, alice_device, bob_device)
    }

    #[test]
    fn first_party_call_requires_current_trust_and_both_accepted_participants() {
        let (store, session, alice, bob, alice_device, bob_device) = first_party_call_fixture();
        let runtime = AuthorizedDurableRuntime::new(&store, &store);
        assert_eq!(
            runtime
                .first_party_call_start(&alice, &alice_device, &session)
                .unwrap(),
            DurableRecordStatus::Persisted
        );
        assert!(
            runtime
                .first_party_call_incoming(&alice, &alice_device, 64)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            runtime
                .first_party_call_incoming(&bob, &bob_device, 64)
                .unwrap()
                .len(),
            1
        );
        assert!(
            runtime
                .first_party_call_join_admission(&bob, &bob_device, &session.call_id, 0)
                .is_err()
        );
        assert!(
            runtime
                .first_party_call_get(&bob, &alice_device, &session.call_id)
                .is_err()
        );

        let accept = signal(&session, "first-party-accept", CallSignalKind::Accept);
        assert_eq!(
            runtime
                .first_party_call_signal(&bob, &bob_device, &accept)
                .unwrap(),
            DurableRecordStatus::Persisted
        );
        assert_eq!(
            runtime
                .first_party_call_join_admission(&alice, &alice_device, &session.call_id, 1)
                .unwrap()
                .signalling_state,
            CallSignallingState::Active
        );
        assert!(
            runtime
                .first_party_call_join_admission(&bob, &bob_device, &session.call_id, 0)
                .is_err()
        );
        assert!(
            runtime
                .first_party_call_incoming(&bob, &bob_device, 64)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn revoked_device_cannot_observe_join_or_signal_existing_call() {
        let (store, session, alice, bob, alice_device, bob_device) = first_party_call_fixture();
        let runtime = AuthorizedDurableRuntime::new(&store, &store);
        runtime
            .first_party_call_start(&alice, &alice_device, &session)
            .unwrap();
        let accept = signal(&session, "first-party-accept", CallSignalKind::Accept);
        runtime
            .first_party_call_signal(&bob, &bob_device, &accept)
            .unwrap();
        store
            .revoke_device(
                &scope(),
                &bob_device,
                &IdentityId::from_opaque(oid("bob-identity")),
            )
            .unwrap();
        assert!(
            runtime
                .first_party_call_join_admission(&bob, &bob_device, &session.call_id, 1)
                .is_err()
        );
        assert!(
            runtime
                .first_party_call_get(&bob, &bob_device, &session.call_id)
                .is_err()
        );
        assert!(
            runtime
                .first_party_call_incoming(&bob, &bob_device, 64)
                .is_err()
        );
        let hangup = signal(
            &store.call(&scope(), &session.call_id).unwrap().unwrap(),
            "revoke-should-block-hangup",
            CallSignalKind::Terminate {
                reason: CallTerminationReason::Completed,
            },
        );
        assert!(
            runtime
                .first_party_call_signal(&bob, &bob_device, &hangup)
                .is_err()
        );
    }

    fn signal(session: &CallSession, id: &str, kind: CallSignalKind) -> CallSignal {
        CallSignal {
            event_id: EventId::from_opaque(oid(id)),
            scope: session.scope.clone(),
            call_id: session.call_id.clone(),
            expected_revision: session.revision,
            kind,
        }
    }

    #[test]
    fn incoming_direct_calls_are_recipient_scoped_and_follow_canonical_signals() {
        let store = MemoryLocalStore::default();
        let (conversation, session, alice, bob) = fixture();
        store.persist_conversation(&conversation).unwrap();
        store.create_call(&alice, &session).unwrap();

        assert_eq!(store.incoming_direct_calls(&alice, 64), Ok(vec![]));
        assert_eq!(
            store.incoming_direct_calls(&subject("bob", PrincipalKind::Organization), 64),
            Ok(vec![])
        );
        assert_eq!(
            store.incoming_direct_calls(&subject("charlie", PrincipalKind::Person), 64),
            Ok(vec![])
        );
        assert_eq!(
            store.incoming_direct_calls(&bob, 0),
            Err(DurableStoreError::InvalidRecord)
        );
        assert_eq!(
            store.incoming_direct_calls(&bob, 65),
            Err(DurableStoreError::InvalidRecord)
        );
        let pending = store.incoming_direct_calls(&bob, 64).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].call_id, session.call_id);

        let ringing = signal(&session, "inbox-ring", CallSignalKind::Ringing);
        store.apply_call_signal(&bob, &ringing).unwrap();
        assert_eq!(store.incoming_direct_calls(&bob, 1).unwrap().len(), 1);

        let ringing_state = store.call(&scope(), &session.call_id).unwrap().unwrap();
        let accept = signal(&ringing_state, "inbox-accept", CallSignalKind::Accept);
        store.apply_call_signal(&bob, &accept).unwrap();
        assert!(store.incoming_direct_calls(&bob, 64).unwrap().is_empty());
        // The accepted Call remains in its canonical store, not in inbox.
        assert_eq!(
            store
                .call(&scope(), &session.call_id)
                .unwrap()
                .unwrap()
                .signalling_state,
            CallSignallingState::Active
        );
    }

    #[test]
    fn caller_cancellation_and_recipient_rejection_clear_the_same_inbox() {
        for reject in [false, true] {
            let store = MemoryLocalStore::default();
            let (conversation, session, alice, bob) = fixture();
            store.persist_conversation(&conversation).unwrap();
            store.create_call(&alice, &session).unwrap();
            assert_eq!(store.incoming_direct_calls(&bob, 64).unwrap().len(), 1);

            if reject {
                store
                    .apply_call_signal(
                        &bob,
                        &signal(&session, "inbox-reject", CallSignalKind::Reject),
                    )
                    .unwrap();
            } else {
                store
                    .apply_call_signal(
                        &alice,
                        &signal(&session, "inbox-cancel", CallSignalKind::Cancel),
                    )
                    .unwrap();
            }
            assert!(store.incoming_direct_calls(&bob, 64).unwrap().is_empty());
            assert_eq!(
                store
                    .call(&scope(), &session.call_id)
                    .unwrap()
                    .unwrap()
                    .signalling_state,
                CallSignallingState::Terminated
            );
        }
    }

    #[test]
    fn call_signalling_is_atomic_non_oracular_and_idempotent() {
        let store = MemoryLocalStore::default();
        let (conversation, session, alice, bob) = fixture();
        store.persist_conversation(&conversation).unwrap();
        assert_eq!(
            store.create_call(&alice, &session),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.create_call(&alice, &session),
            Ok(DurableRecordStatus::Duplicate)
        );
        let alias = subject("bob", PrincipalKind::Organization);
        assert_eq!(
            store.call_for_participant(&alias, &scope(), &session.call_id),
            Ok(None)
        );
        let accept = signal(&session, "accept", CallSignalKind::Accept);
        assert_eq!(
            store.apply_call_signal(&bob, &accept),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_call_signal(&bob, &accept),
            Ok(DurableRecordStatus::Duplicate)
        );
        let active = store
            .call_for_participant(&alice, &scope(), &session.call_id)
            .unwrap()
            .unwrap();
        assert_eq!(active.signalling_state, CallSignallingState::Active);
        assert_eq!(active.revision, 1);
        assert_eq!(
            store.create_call(&alice, &session),
            Ok(DurableRecordStatus::Duplicate)
        );
        let mut conflicting = session.clone();
        conflicting.participants[1].principal = subject("charlie", PrincipalKind::Person).principal;
        assert_eq!(
            store.create_call(&alice, &conflicting),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn independent_termination_revokes_old_duplicate_ledger_access() {
        let store = MemoryLocalStore::default();
        let (conversation, session, alice, bob) = fixture();
        store.persist_conversation(&conversation).unwrap();
        store.create_call(&alice, &session).unwrap();

        let ringing = signal(&session, "ring-before-cancel", CallSignalKind::Ringing);
        assert_eq!(
            store.apply_call_signal(&bob, &ringing),
            Ok(DurableRecordStatus::Persisted)
        );
        let ringing_state = store.call(&scope(), &session.call_id).unwrap().unwrap();
        let cancel = signal(&ringing_state, "cancel-after-ring", CallSignalKind::Cancel);
        assert_eq!(
            store.apply_call_signal(&alice, &cancel),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_call_signal(&bob, &ringing),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            store.apply_call_signal(&alice, &cancel),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn rejecting_actor_can_retry_own_fact_but_kind_alias_cannot() {
        let store = MemoryLocalStore::default();
        let (conversation, session, alice, bob) = fixture();
        store.persist_conversation(&conversation).unwrap();
        store.create_call(&alice, &session).unwrap();
        let reject = signal(&session, "reject", CallSignalKind::Reject);
        assert_eq!(
            store.apply_call_signal(&bob, &reject),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_call_signal(&bob, &reject),
            Ok(DurableRecordStatus::Duplicate)
        );
        let alias = subject("bob", PrincipalKind::Organization);
        assert_eq!(
            store.apply_call_signal(&alias, &reject),
            Err(DurableStoreError::PermissionDenied)
        );
        let ended = store.call(&scope(), &session.call_id).unwrap().unwrap();
        assert_eq!(
            ended.termination_reason,
            Some(CallTerminationReason::Rejected)
        );
    }
}
