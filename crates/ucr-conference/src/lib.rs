#![forbid(unsafe_code)]

use std::sync::Mutex;

use core::fmt;

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, DurableRecordStatus,
    DurableStoreError, GroupStore, PrincipalIdentityBindingStore,
};
use ucr_crypto::TrustedSigningKeyResolver;
use ucr_media_e2ee::GroupMediaE2eeCapabilityProvider;
use ucr_model::{
    AuthorizationRequest, CallId, CallParticipant, CallParticipantState, CallSession, CallSignal,
    CallSignalKind, CallSignallingState, ConferenceMediaSubscription, ConferenceSnapshot,
    ConferenceStart, ConferenceSubscriptionSet, ConferenceTopology, DeviceId, GroupMemberState,
    MediaKind, PrincipalRef, ScopedPrincipal, SfuForwardEnvelope, TenantScope,
};
use ucr_protocol::{
    AUDIO_RECEIVE_PERMISSION, CALL_OBSERVE_PERMISSION, CALL_SIGNAL_PERMISSION,
    CALL_START_PERMISSION, CONFERENCE_CAPABILITY, CONFERENCE_SUBSCRIBE_PERMISSION,
    ConferenceProtocolError, GROUP_MEDIA_E2EE_CAPABILITY, GROUP_MLS_CAPABILITY,
    MAX_CALL_PARTICIPANTS, MAX_TRACKED_CONFERENCE_RECIPIENT_SETS, SFU_MEDIA_CAPABILITY,
    VIDEO_RECEIVE_PERMISSION, canonical_capabilities, canonical_conference_start,
    canonical_conference_subscription_set, is_conference_group_kind,
    phase30_conference_capabilities, validate_conference_snapshot,
};
use ucr_sfu::{SfuCapabilityProvider, SfuError, SfuForwardOutcome, SfuForwardSink, SfuRuntime};

pub trait ConferenceCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<ucr_model::CapabilityDescriptor>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedConferenceCapabilities;

impl ConferenceCapabilityProvider for PreparedConferenceCapabilities {
    fn current_capabilities(&self) -> Vec<ucr_model::CapabilityDescriptor> {
        phase30_conference_capabilities()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConferenceError {
    Protocol(ConferenceProtocolError),
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    CapabilityUnavailable,
    GroupUnavailable,
    GroupMismatch,
    GroupCryptoUnavailable,
    MembershipUnavailable,
    CallUnavailable,
    NotConference,
    SubscriberNotAccepted,
    SourceUnavailable,
    SubscriptionStateUnavailable,
    SubscriptionCapacityExceeded,
    Sfu(SfuError),
}

impl From<ConferenceProtocolError> for ConferenceError {
    fn from(error: ConferenceProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DurableStoreError> for ConferenceError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<SfuError> for ConferenceError {
    fn from(error: SfuError) -> Self {
        Self::Sfu(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecipientSubscriptionState {
    scope: TenantScope,
    call_id: CallId,
    recipient: PrincipalRef,
    subscriptions: Vec<ConferenceMediaSubscription>,
}

#[derive(Debug)]
pub struct ConferenceRuntime<'a, A, S, E, F, C> {
    authorization: &'a A,
    store: &'a S,
    group_e2ee_capabilities: &'a E,
    sfu_capabilities: &'a F,
    conference_capabilities: &'a C,
    subscriptions: Mutex<Vec<RecipientSubscriptionState>>,
}

impl<'a, A, S, E, F, C> ConferenceRuntime<'a, A, S, E, F, C> {
    #[must_use]
    pub fn new(
        authorization: &'a A,
        store: &'a S,
        group_e2ee_capabilities: &'a E,
        sfu_capabilities: &'a F,
        conference_capabilities: &'a C,
    ) -> Self {
        Self {
            authorization,
            store,
            group_e2ee_capabilities,
            sfu_capabilities,
            conference_capabilities,
            subscriptions: Mutex::new(Vec::new()),
        }
    }
}

impl<A, S, E, F, C> ConferenceRuntime<'_, A, S, E, F, C>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
    E: GroupMediaE2eeCapabilityProvider,
    F: SfuCapabilityProvider,
    C: ConferenceCapabilityProvider,
{
    /// Starts/deduplicates one group Conference as the existing canonical `CallSession`.
    ///
    /// The Conference layer owns no durable roster or signalling lifecycle. It derives the Group
    /// conversation, validates every invited principal as a current active Group member, requires
    /// MLS + SFU capabilities, and persists only through `CallStore`.
    ///
    /// # Errors
    /// Rejects malformed/cross-scope requests, missing capabilities, non-members, non-MLS Groups,
    /// authorization failures, conflicts or durable-store failures.
    pub fn start(
        &self,
        actor: &ScopedPrincipal,
        start: &ConferenceStart,
    ) -> Result<(DurableRecordStatus, ConferenceSnapshot), ConferenceError> {
        require_conference_stack(
            self.conference_capabilities,
            self.sfu_capabilities,
            self.group_e2ee_capabilities,
        )?;
        let start = canonical_conference_start(start, &actor.scope, &actor.principal)?;
        authorize(self.authorization, actor, CALL_START_PERMISSION)?;
        let group = self
            .store
            .group(&start.scope, &start.group_id)?
            .ok_or(ConferenceError::GroupUnavailable)?;
        if !is_conference_group_kind(group.conversation.kind) {
            return Err(ConferenceError::GroupMismatch);
        }
        require_mls_group(&group)?;
        require_active_member(self.store, actor, &start.group_id, &actor.principal)?;
        for invitee in &start.invitees {
            require_active_member(self.store, actor, &start.group_id, invitee)?;
        }
        let mut participants = Vec::with_capacity(start.invitees.len() + 1);
        participants.push(CallParticipant {
            principal: actor.principal.clone(),
            state: CallParticipantState::Accepted,
            joined_revision: 0,
            left_revision: None,
        });
        participants.extend(
            start
                .invitees
                .iter()
                .cloned()
                .map(|principal| CallParticipant {
                    principal,
                    state: CallParticipantState::Invited,
                    joined_revision: 0,
                    left_revision: None,
                }),
        );
        if participants.len() > MAX_CALL_PARTICIPANTS {
            return Err(ConferenceError::Protocol(
                ConferenceProtocolError::TooManyInvitees,
            ));
        }
        let call = CallSession {
            scope: start.scope.clone(),
            call_id: start.call_id.clone(),
            conversation: group.conversation.clone(),
            initiated_by: actor.principal.clone(),
            participants,
            signalling_state: CallSignallingState::Inviting,
            reconnecting_participant: None,
            media_negotiation_ref: None,
            media_negotiation_generation: 0,
            replication_generation: 0,
            revision: 0,
            termination_reason: None,
        };
        let status = self.store.create_call(actor, &call)?;
        let snapshot = conference_projection(self.store, actor, &start.scope, &start.call_id)?;
        Ok((status, snapshot))
    }

    /// Returns a non-durable Conference projection from the current Call + Group + MLS state.
    ///
    /// # Errors
    /// Rejects unauthorized/non-participant reads, direct calls, missing Group/MLS state or storage
    /// failures. No Conference existence is disclosed to non-participants.
    pub fn snapshot(
        &self,
        actor: &ScopedPrincipal,
        scope: &ucr_model::TenantScope,
        call_id: &ucr_model::CallId,
    ) -> Result<ConferenceSnapshot, ConferenceError> {
        authorize(self.authorization, actor, CALL_OBSERVE_PERMISSION)?;
        conference_projection(self.store, actor, scope, call_id)
    }

    /// Applies one existing canonical `CallSignal` under Conference invariants.
    ///
    /// Participant additions are admitted only when the target is a current active Group member;
    /// all signalling/idempotency/termination/reconnect semantics remain owned by `CallStore`.
    ///
    /// # Errors
    /// Rejects missing Conference capability, unauthorized signalling, non-Conference calls,
    /// non-member participant additions, stale/conflicting signals or storage failures.
    pub fn signal(
        &self,
        actor: &ScopedPrincipal,
        signal: &CallSignal,
    ) -> Result<DurableRecordStatus, ConferenceError> {
        require_conference_stack(
            self.conference_capabilities,
            self.sfu_capabilities,
            self.group_e2ee_capabilities,
        )?;
        authorize(self.authorization, actor, CALL_SIGNAL_PERMISSION)?;
        let snapshot = conference_projection(self.store, actor, &signal.scope, &signal.call_id)?;
        if let CallSignalKind::ParticipantUpdate {
            participant,
            kind: ucr_model::CallParticipantUpdateKind::Add,
        } = &signal.kind
        {
            require_active_member(self.store, actor, &snapshot.group_id, participant)?;
        }
        let status = self.store.apply_call_signal(actor, signal)?;
        self.prune_subscriptions(&signal.scope, &signal.call_id)?;
        Ok(status)
    }

    /// Replaces the authenticated participant's complete ephemeral receive-subscription set.
    ///
    /// Subscription state is bounded and intentionally non-durable. It is routing preference only:
    /// Call/Group membership and receive permission remain canonical and are revalidated again by
    /// the SFU before any sink side effect.
    ///
    /// # Errors
    /// Rejects non-accepted participants, non-current sources, self/duplicate/oversized sets, missing
    /// receive permission, or exhausted bounded ephemeral state.
    pub fn set_subscriptions(
        &self,
        actor: &ScopedPrincipal,
        set: &ConferenceSubscriptionSet,
    ) -> Result<usize, ConferenceError> {
        require_conference_stack(
            self.conference_capabilities,
            self.sfu_capabilities,
            self.group_e2ee_capabilities,
        )?;
        let set = canonical_conference_subscription_set(set, &actor.scope, &actor.principal)?;
        authorize(self.authorization, actor, CONFERENCE_SUBSCRIBE_PERMISSION)?;
        self.prune_subscriptions(&set.scope, &set.call_id)?;
        let snapshot = conference_projection(self.store, actor, &set.scope, &set.call_id)?;
        require_accepted_participant(&snapshot.call, &actor.principal)?;
        for subscription in &set.subscriptions {
            require_accepted_participant(&snapshot.call, &subscription.source)
                .map_err(|_| ConferenceError::SourceUnavailable)?;
            require_active_member(self.store, actor, &snapshot.group_id, &subscription.source)?;
            authorize(
                self.authorization,
                actor,
                receive_permission(subscription.media_kind),
            )?;
        }
        let mut state = self
            .subscriptions
            .lock()
            .map_err(|_| ConferenceError::SubscriptionStateUnavailable)?;
        if set.subscriptions.is_empty() {
            state.retain(|entry| {
                entry.scope != set.scope
                    || entry.call_id != set.call_id
                    || entry.recipient != actor.principal
            });
            return Ok(0);
        }
        if let Some(existing) = state.iter_mut().find(|entry| {
            entry.scope == set.scope
                && entry.call_id == set.call_id
                && entry.recipient == actor.principal
        }) {
            existing.subscriptions = set.subscriptions;
            return Ok(existing.subscriptions.len());
        }
        if state.len() >= MAX_TRACKED_CONFERENCE_RECIPIENT_SETS {
            return Err(ConferenceError::SubscriptionCapacityExceeded);
        }
        let count = set.subscriptions.len();
        state.push(RecipientSubscriptionState {
            scope: set.scope,
            call_id: set.call_id,
            recipient: actor.principal.clone(),
            subscriptions: set.subscriptions,
        });
        Ok(count)
    }

    /// Routes one already-encrypted Conference frame through the Phase-29 SFU boundary.
    ///
    /// # Errors
    /// Fails closed if the source is not a current Conference participant or if any underlying SFU,
    /// Group/Call/MLS/Device/signature/permission invariant fails.
    pub fn forward(
        &self,
        actor: &ScopedPrincipal,
        actor_device_id: &DeviceId,
        envelope: &SfuForwardEnvelope,
        sink: &dyn SfuForwardSink,
    ) -> Result<SfuForwardOutcome, ConferenceError> {
        require_conference_stack(
            self.conference_capabilities,
            self.sfu_capabilities,
            self.group_e2ee_capabilities,
        )?;
        self.prune_subscriptions(&envelope.frame.header.scope, &envelope.frame.header.call_id)?;
        let snapshot = conference_projection(
            self.store,
            actor,
            &envelope.frame.header.scope,
            &envelope.frame.header.call_id,
        )?;
        require_accepted_participant(&snapshot.call, &actor.principal)?;
        let recipients = self.subscribers_for_source(
            &snapshot.call,
            &actor.principal,
            envelope.frame.header.media_kind,
        )?;
        if recipients.is_empty() {
            return Ok(SfuForwardOutcome {
                accepted_recipients: 0,
            });
        }
        let sfu = SfuRuntime::new(
            self.authorization,
            self.store,
            self.group_e2ee_capabilities,
            self.sfu_capabilities,
        );
        sfu.forward_selected(actor, actor_device_id, envelope, &recipients, sink)
            .map_err(ConferenceError::Sfu)
    }

    fn subscribers_for_source(
        &self,
        call: &CallSession,
        source: &PrincipalRef,
        media_kind: MediaKind,
    ) -> Result<Vec<PrincipalRef>, ConferenceError> {
        let state = self
            .subscriptions
            .lock()
            .map_err(|_| ConferenceError::SubscriptionStateUnavailable)?;
        let mut recipients = Vec::new();
        for entry in state.iter().filter(|entry| {
            entry.scope == call.scope
                && entry.call_id == call.call_id
                && entry.subscriptions.iter().any(|subscription| {
                    subscription.source == *source && subscription.media_kind == media_kind
                })
        }) {
            if is_accepted_participant(call, &entry.recipient) {
                recipients.push(entry.recipient.clone());
            }
        }
        Ok(recipients)
    }

    fn prune_subscriptions(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<(), ConferenceError> {
        let call = self.store.call(scope, call_id)?;
        let mut state = self
            .subscriptions
            .lock()
            .map_err(|_| ConferenceError::SubscriptionStateUnavailable)?;
        prune_subscription_state(&mut state, scope, call_id, call.as_ref());
        Ok(())
    }
}

fn prune_subscription_state(
    state: &mut Vec<RecipientSubscriptionState>,
    scope: &TenantScope,
    call_id: &CallId,
    call: Option<&CallSession>,
) {
    let Some(call) = call else {
        state.retain(|entry| entry.scope != *scope || entry.call_id != *call_id);
        return;
    };
    if call.signalling_state == CallSignallingState::Terminated {
        state.retain(|entry| entry.scope != *scope || entry.call_id != *call_id);
        return;
    }
    state.retain_mut(|entry| {
        if entry.scope != *scope || entry.call_id != *call_id {
            return true;
        }
        if !is_accepted_participant(call, &entry.recipient) {
            return false;
        }
        entry
            .subscriptions
            .retain(|subscription| is_accepted_participant(call, &subscription.source));
        !entry.subscriptions.is_empty()
    });
}

fn is_accepted_participant(call: &CallSession, principal: &PrincipalRef) -> bool {
    call.participants.iter().any(|participant| {
        participant.principal == *principal
            && participant.state == CallParticipantState::Accepted
            && participant.left_revision.is_none()
    })
}

fn require_accepted_participant(
    call: &CallSession,
    principal: &PrincipalRef,
) -> Result<(), ConferenceError> {
    if is_accepted_participant(call, principal) {
        Ok(())
    } else {
        Err(ConferenceError::SubscriberNotAccepted)
    }
}

const fn receive_permission(media_kind: MediaKind) -> &'static str {
    match media_kind {
        MediaKind::Audio => AUDIO_RECEIVE_PERMISSION,
        MediaKind::Video => VIDEO_RECEIVE_PERMISSION,
    }
}

fn conference_projection<S: CallStore + GroupStore>(
    store: &S,
    actor: &ScopedPrincipal,
    scope: &ucr_model::TenantScope,
    call_id: &ucr_model::CallId,
) -> Result<ConferenceSnapshot, ConferenceError> {
    let call = store
        .call_for_participant(actor, scope, call_id)?
        .ok_or(ConferenceError::CallUnavailable)?;
    if !is_conference_group_kind(call.conversation.kind) {
        return Err(ConferenceError::NotConference);
    }
    let group = store
        .group_for_conversation(scope, &call.conversation.conversation_id)?
        .ok_or(ConferenceError::GroupUnavailable)?;
    require_mls_group(&group)?;
    let snapshot = ConferenceSnapshot {
        call,
        group_id: group.group_id,
        topology: ConferenceTopology::Sfu,
        group_crypto_epoch: group.crypto_state.epoch,
        group_crypto_state_ref: group
            .crypto_state
            .state_ref
            .ok_or(ConferenceError::GroupCryptoUnavailable)?,
    };
    validate_conference_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn require_active_member<S: GroupStore>(
    store: &S,
    actor: &ScopedPrincipal,
    group_id: &ucr_model::GroupId,
    member: &ucr_model::PrincipalRef,
) -> Result<(), ConferenceError> {
    let membership = store
        .group_membership_for_active_member(actor, &actor.scope, group_id, member)?
        .ok_or(ConferenceError::MembershipUnavailable)?;
    if membership.state == GroupMemberState::Active {
        Ok(())
    } else {
        Err(ConferenceError::MembershipUnavailable)
    }
}

fn require_mls_group(group: &ucr_model::GroupRecord) -> Result<(), ConferenceError> {
    if group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY)
        || group.crypto_state.state_ref.is_none()
    {
        Err(ConferenceError::GroupCryptoUnavailable)
    } else {
        Ok(())
    }
}

fn authorize<A: AuthorizationEvaluator>(
    authorization: &A,
    subject: &ScopedPrincipal,
    permission: &str,
) -> Result<(), ConferenceError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: permission.to_owned(),
            resource_scope: subject.scope.clone(),
        })
        .map_err(ConferenceError::Authorization)
}

fn require_conference_stack<E, F, C>(
    conference: &C,
    sfu: &F,
    group_e2ee: &E,
) -> Result<(), ConferenceError>
where
    E: GroupMediaE2eeCapabilityProvider,
    F: SfuCapabilityProvider,
    C: ConferenceCapabilityProvider,
{
    require_capability(&conference.current_capabilities(), CONFERENCE_CAPABILITY)?;
    require_capability(&sfu.current_capabilities(), SFU_MEDIA_CAPABILITY)?;
    require_capability(
        &group_e2ee.current_capabilities(),
        GROUP_MEDIA_E2EE_CAPABILITY,
    )
}

fn require_capability(
    capabilities: &[ucr_model::CapabilityDescriptor],
    required: &str,
) -> Result<(), ConferenceError> {
    let capabilities =
        canonical_capabilities(capabilities).map_err(|_| ConferenceError::CapabilityUnavailable)?;
    if capabilities.iter().any(|capability| {
        capability.id == required
            && matches!(
                capability.maturity,
                ucr_model::CapabilityMaturity::Prepared
                    | ucr_model::CapabilityMaturity::Beta
                    | ucr_model::CapabilityMaturity::Production
            )
            && capability
                .extensions
                .iter()
                .all(|extension| !extension.critical)
    }) {
        Ok(())
    } else {
        Err(ConferenceError::CapabilityUnavailable)
    }
}

#[cfg(test)]
mod subscription_state_tests {
    use super::*;
    use ucr_model::{
        CallParticipant, ConversationId, ConversationKind, ConversationRef, OpaqueId, PrincipalId,
        PrincipalKind, TenantId,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-prune")),
            namespace_id: None,
        }
    }

    fn principal(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        }
    }

    fn call(
        state: CallSignallingState,
        alice_state: CallParticipantState,
        bob_state: CallParticipantState,
    ) -> CallSession {
        let alice = principal("alice");
        let bob = principal("bob");
        CallSession {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call-prune")),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-prune")),
                kind: ConversationKind::PrivateGroup,
            },
            initiated_by: alice.clone(),
            participants: vec![
                CallParticipant {
                    principal: alice,
                    state: alice_state,
                    joined_revision: 0,
                    left_revision: (alice_state == CallParticipantState::Left).then_some(1),
                },
                CallParticipant {
                    principal: bob,
                    state: bob_state,
                    joined_revision: 0,
                    left_revision: (bob_state == CallParticipantState::Left).then_some(1),
                },
            ],
            signalling_state: state,
            reconnecting_participant: None,
            media_negotiation_ref: None,
            media_negotiation_generation: 0,
            replication_generation: 0,
            revision: 1,
            termination_reason: (state == CallSignallingState::Terminated)
                .then_some(ucr_model::CallTerminationReason::Completed),
        }
    }

    fn entry() -> RecipientSubscriptionState {
        RecipientSubscriptionState {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call-prune")),
            recipient: principal("bob"),
            subscriptions: vec![ConferenceMediaSubscription {
                source: principal("alice"),
                media_kind: MediaKind::Video,
            }],
        }
    }

    #[test]
    fn pruning_releases_recipient_source_and_terminated_call_state() {
        let call_id = CallId::from_opaque(oid("call-prune"));

        let mut state = vec![entry()];
        let recipient_left = call(
            CallSignallingState::Active,
            CallParticipantState::Accepted,
            CallParticipantState::Left,
        );
        prune_subscription_state(&mut state, &scope(), &call_id, Some(&recipient_left));
        assert!(state.is_empty());

        let mut state = vec![entry()];
        let source_left = call(
            CallSignallingState::Active,
            CallParticipantState::Left,
            CallParticipantState::Accepted,
        );
        prune_subscription_state(&mut state, &scope(), &call_id, Some(&source_left));
        assert!(state.is_empty());

        let mut state = vec![entry()];
        let terminated = call(
            CallSignallingState::Terminated,
            CallParticipantState::Accepted,
            CallParticipantState::Accepted,
        );
        prune_subscription_state(&mut state, &scope(), &call_id, Some(&terminated));
        assert!(state.is_empty());
    }
}
