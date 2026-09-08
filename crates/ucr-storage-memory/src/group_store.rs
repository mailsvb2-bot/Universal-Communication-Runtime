use ucr_core::{DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore};
use ucr_model::{
    ConversationId, ConversationRecord, DeliveryState, GroupChange, GroupHistoryPolicy, GroupId,
    GroupMemberState, GroupMembership, GroupPermission, GroupRecord, MessageEnvelope, MessageId,
    PrincipalRef, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    apply_group_change, canonical_group_creation, canonical_group_memberships, canonical_message,
    group_change_fingerprint, is_group_conversation_kind, validate_conversation,
    validate_group_member_list_limit,
};

use super::{
    GroupChangeKey, GroupKey, GroupMembershipKey, MemoryLocalStore, MemoryState, conversation_key,
    message_key, persist_message_in_state, scope_key,
};

impl GroupStore for MemoryLocalStore {
    fn create_group(
        &self,
        conversation: &ConversationRecord,
        group: &GroupRecord,
        creator: &ScopedPrincipal,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_conversation(conversation).map_err(|_| DurableStoreError::InvalidRecord)?;
        if conversation.parent_conversation_id.is_some()
            || !is_group_conversation_kind(conversation.conversation.kind)
            || conversation.scope != group.scope
            || conversation.conversation != group.conversation
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let (group, mut creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
        let group_key = group_key(&group.scope, &group.group_id);
        let creator_key = membership_key(&group.scope, &group.group_id, &creator.principal);
        let conversation_key = conversation_key(
            &conversation.scope,
            &conversation.conversation.conversation_id,
        );
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.groups.get(&group_key) {
            let existing_creator = state.group_memberships.get(&creator_key);
            let duplicate = existing_creator.is_some_and(|persisted| {
                let mut expected = creator_membership.clone();
                expected.history_floor_logical_order = persisted.history_floor_logical_order;
                existing == &group && persisted == &expected
            });
            return if duplicate {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.groups.values().any(|existing| {
            existing.scope == group.scope && existing.conversation == group.conversation
        }) {
            return Err(DurableStoreError::Conflict);
        }
        if let Some(existing) = state.conversations.get(&conversation_key) {
            if existing != conversation {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state
                .conversations
                .insert(conversation_key, conversation.clone());
        }
        creator_membership.history_floor_logical_order = history_floor_for_add(&state, &group)?;
        state.groups.insert(group_key, group);
        state
            .group_memberships
            .insert(creator_key, creator_membership);
        Ok(DurableRecordStatus::Persisted)
    }

    fn group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
    ) -> Result<Option<GroupRecord>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.groups.get(&group_key(scope, group_id)).cloned())
    }

    fn group_for_conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<GroupRecord>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .groups
            .values()
            .find(|group| {
                group.scope == *scope && group.conversation.conversation_id == *conversation_id
            })
            .cloned())
    }

    fn group_membership(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        member: &PrincipalRef,
    ) -> Result<Option<GroupMembership>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .group_memberships
            .get(&membership_key(scope, group_id, member))
            .filter(|membership| membership.member == *member)
            .cloned())
    }

    fn group_memberships(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<GroupMembership>, DurableStoreError> {
        validate_group_member_list_limit(max_items).map_err(map_group_error)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let group = state
            .groups
            .get(&group_key(scope, group_id))
            .ok_or(DurableStoreError::InvalidRecord)?;
        let mut memberships = state
            .group_memberships
            .values()
            .filter(|membership| membership.scope == *scope && membership.group_id == *group_id)
            .cloned()
            .collect::<Vec<_>>();
        memberships = canonical_group_memberships(group, &memberships).map_err(map_group_error)?;
        if memberships.len() > max_items {
            return Err(DurableStoreError::Full);
        }
        Ok(memberships)
    }

    fn apply_group_change(
        &self,
        actor: &ScopedPrincipal,
        change: &GroupChange,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != change.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let group_key = group_key(&change.scope, &change.group_id);
        let change_key = change_key(&change.scope, change.event_id.as_opaque().as_str());
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some((recorded_actor, existing)) = state.group_changes.get(&change_key) {
            if recorded_actor != &actor.principal {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.events.contains_key(&change_key) {
            return Err(DurableStoreError::Conflict);
        }
        let group = state
            .groups
            .get(&group_key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        let memberships = state
            .group_memberships
            .values()
            .filter(|membership| {
                membership.scope == change.scope && membership.group_id == change.group_id
            })
            .cloned()
            .collect::<Vec<_>>();
        let history_floor = if matches!(change.kind, ucr_model::GroupChangeKind::AddMember { .. }) {
            Some(history_floor_for_add(&state, &group)?)
        } else {
            None
        };
        let transition = apply_group_change(
            &group,
            &memberships,
            &actor.scope,
            &actor.principal,
            change,
            history_floor,
        )
        .map_err(map_group_error)?;
        state.groups.insert(group_key, transition.group.clone());
        state.group_memberships.retain(|_, membership| {
            membership.scope != change.scope || membership.group_id != change.group_id
        });
        for membership in transition.memberships {
            state.group_memberships.insert(
                membership_key(&membership.scope, &membership.group_id, &membership.member),
                membership,
            );
        }
        state
            .group_changes
            .insert(change_key, (actor.principal.clone(), fingerprint));
        Ok(DurableRecordStatus::Persisted)
    }
}

impl GroupMessageStore for MemoryLocalStore {
    fn persist_group_message(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_message(message).map_err(|_| DurableStoreError::InvalidRecord)?;
        if !is_group_conversation_kind(canonical.conversation.kind)
            || !matches!(
                canonical.delivery_state,
                DeliveryState::Created | DeliveryState::Persisted
            )
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        if canonical.scope != subject.scope
            || canonical.origin.principal_id.as_ref() != Some(&subject.principal.principal_id)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let group = state
            .groups
            .values()
            .find(|group| {
                group.scope == canonical.scope && group.conversation == canonical.conversation
            })
            .cloned()
            .ok_or(DurableStoreError::PermissionDenied)?;
        if canonical.delivery_policy != group.delivery_policy {
            return Err(DurableStoreError::InvalidRecord);
        }
        let membership = state
            .group_memberships
            .get(&membership_key(
                &group.scope,
                &group.group_id,
                &subject.principal,
            ))
            .filter(|membership| membership.member == subject.principal)
            .ok_or(DurableStoreError::PermissionDenied)?;
        if membership.state != GroupMemberState::Active
            || !membership
                .permissions
                .contains(&GroupPermission::SendMessage)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        persist_message_in_state(&mut state, &canonical)
    }

    fn group_message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError> {
        if subject.scope != *scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(message) = state.messages.get(&message_key(scope, message_id)).cloned() else {
            return Ok(None);
        };
        if !is_group_conversation_kind(message.conversation.kind) {
            return Ok(None);
        }
        let Some(group) = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.conversation == message.conversation)
        else {
            return Ok(None);
        };
        let Some(membership) = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .filter(|membership| membership.member == subject.principal)
        else {
            return Ok(None);
        };
        if membership.state != GroupMemberState::Active
            || !membership
                .permissions
                .contains(&GroupPermission::ReadHistory)
            || !history_allows(group, membership, &message)
        {
            return Ok(None);
        }
        Ok(Some(message))
    }
}

fn group_key(scope: &TenantScope, group_id: &GroupId) -> GroupKey {
    (scope_key(scope), group_id.as_opaque().as_str().to_owned())
}

fn membership_key(
    scope: &TenantScope,
    group_id: &GroupId,
    member: &PrincipalRef,
) -> GroupMembershipKey {
    (
        scope_key(scope),
        group_id.as_opaque().as_str().to_owned(),
        member.clone(),
    )
}

fn change_key(scope: &TenantScope, event_id: &str) -> GroupChangeKey {
    (scope_key(scope), event_id.to_owned())
}

fn history_floor_for_add(
    state: &MemoryState,
    group: &GroupRecord,
) -> Result<u64, DurableStoreError> {
    let mut orders = state
        .messages
        .values()
        .filter(|message| {
            message.scope == group.scope && message.conversation == group.conversation
        })
        .map(|message| message.logical_order)
        .collect::<Vec<_>>();
    orders.sort_unstable();
    match &group.history_policy {
        GroupHistoryPolicy::FullHistory | GroupHistoryPolicy::FromTimestamp(_) => Ok(0),
        GroupHistoryPolicy::NoHistory | GroupHistoryPolicy::FromJoin => orders
            .last()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord),
        GroupHistoryPolicy::LastNMessages(count) => {
            let count = usize::try_from(*count).map_err(|_| DurableStoreError::InvalidRecord)?;
            if orders.len() <= count {
                return Ok(0);
            }
            let cutoff = orders[orders.len() - count];
            let visible_at_or_above = orders.iter().filter(|order| **order >= cutoff).count();
            if visible_at_or_above > count {
                cutoff
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidRecord)
            } else {
                Ok(cutoff)
            }
        }
        GroupHistoryPolicy::CustomPolicy(_) => Ok(u64::MAX),
    }
}

fn history_allows(
    group: &GroupRecord,
    membership: &GroupMembership,
    message: &MessageEnvelope,
) -> bool {
    if message.logical_order < membership.history_floor_logical_order {
        return false;
    }
    match group.history_policy {
        GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false,
        GroupHistoryPolicy::NoHistory
        | GroupHistoryPolicy::FromJoin
        | GroupHistoryPolicy::LastNMessages(_)
        | GroupHistoryPolicy::FullHistory => true,
    }
}

fn map_group_error(error: ucr_protocol::GroupError) -> DurableStoreError {
    use ucr_protocol::GroupError;
    match error {
        GroupError::PermissionDenied => DurableStoreError::PermissionDenied,
        GroupError::RevisionMismatch
        | GroupError::MemberAlreadyActive
        | GroupError::MemberNotActive
        | GroupError::InvalidRoleTransition
        | GroupError::OwnershipTransferNotSupported
        | GroupError::WouldOrphanGroup => DurableStoreError::Conflict,
        GroupError::TooManyMembers => DurableStoreError::Full,
        _ => DurableStoreError::InvalidRecord,
    }
}

#[cfg(test)]
mod phase18_memory_security_tests {
    use ucr_core::{
        ConversationStore, DurableRecordStatus, DurableStoreError, EventAppendStatus,
        EventJournalStore, GroupMessageStore, GroupStore, MessageStore,
    };
    use ucr_model::*;

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("phase18-security-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("phase18-security-namespace"))),
        }
    }

    fn subject(value: &str, kind: PrincipalKind) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(value)),
                kind,
            },
        }
    }

    fn group_fixture(suffix: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid(&format!(
                    "memory-conversation-{suffix}"
                ))),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid(&format!("memory-group-{suffix}"))),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: Vec::new(),
            replication_generation: 0,
            revision: 0,
        };
        (conversation, group)
    }

    fn message(
        conversation: &ConversationRef,
        principal_id: &PrincipalId,
        suffix: &str,
    ) -> MessageEnvelope {
        MessageEnvelope {
            message_id: MessageId::from_opaque(oid(&format!("memory-message-{suffix}"))),
            scope: scope(),
            conversation: conversation.clone(),
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid(&format!("memory-actor-{suffix}"))),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid(&format!("memory-device-{suffix}"))),
                identity_id: IdentityId::from_opaque(oid(&format!("memory-identity-{suffix}"))),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"group-message".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(principal_id.clone()),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid(&format!("memory-correlation-{suffix}")),
                causation_id: None,
                idempotency_key: Some(format!("memory-idempotency-{suffix}")),
            },
            extensions: Vec::new(),
            external_mappings: Vec::new(),
            signature: None,
        }
    }

    fn event(id: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.group.member_added".to_owned(),
            payload: b"projection".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("memory-event-actor")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("memory-event-device")),
                identity_id: IdentityId::from_opaque(oid("memory-event-identity")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("memory-event-correlation"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn principal_kind_alias_cannot_inherit_group_membership() {
        let store = MemoryLocalStore::default();
        let owner = subject("shared-principal-id", PrincipalKind::Person);
        let alias = subject("shared-principal-id", PrincipalKind::Organization);
        let (conversation, group) = group_fixture("principal-kind", &owner);
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Persisted)
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &alias.principal)
                .expect("alias lookup")
                .is_none()
        );
        let original = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "owner",
        );
        assert_eq!(
            store.persist_group_message(&owner, &original),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.group_message(&alias, &scope(), &original.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(
                &alias,
                &scope(),
                &MessageId::from_opaque(oid("memory-message-unknown"))
            ),
            Ok(None)
        );
        let forged = message(
            &conversation.conversation,
            &alias.principal.principal_id,
            "alias",
        );
        assert_eq!(
            store.persist_group_message(&alias, &forged),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn group_change_event_id_is_scope_wide_and_cannot_alias_event_journal() {
        let store = MemoryLocalStore::default();
        let owner = subject("memory-event-owner", PrincipalKind::Person);
        let (conversation_a, group_a) = group_fixture("event-a", &owner);
        let (conversation_b, group_b) = group_fixture("event-b", &owner);
        store
            .create_group(&conversation_a, &group_a, &owner)
            .expect("group a");
        store
            .create_group(&conversation_b, &group_b, &owner)
            .expect("group b");

        let shared_id = EventId::from_opaque(oid("memory-shared-event-id"));
        let change_a = GroupChange {
            event_id: shared_id.clone(),
            scope: scope(),
            group_id: group_a.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-a", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        let change_b = GroupChange {
            event_id: shared_id.clone(),
            scope: scope(),
            group_id: group_b.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-b", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &change_a),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_group_change(&owner, &change_a),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert_eq!(
            store.apply_group_change(&owner, &change_b),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.append_event(&event("memory-shared-event-id")),
            Err(DurableStoreError::Conflict)
        );

        assert_eq!(
            store.append_event(&event("memory-event-first-id")),
            Ok(EventAppendStatus::Appended)
        );
        let event_first_change = GroupChange {
            event_id: EventId::from_opaque(oid("memory-event-first-id")),
            scope: scope(),
            group_id: group_b.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-c", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &event_first_change),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn from_timestamp_history_fails_closed_on_untrusted_message_time() {
        let store = MemoryLocalStore::default();
        let owner = subject("timestamp-owner", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("timestamp", &owner);
        group.history_policy = GroupHistoryPolicy::FromTimestamp(1);
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let mut forged = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "timestamp",
        );
        forged.created_at_unix_ms = i64::MAX;
        forged.logical_order = 7;
        store
            .persist_group_message(&owner, &forged)
            .expect("persist");
        assert_eq!(
            store.group_message(&owner, &scope(), &forged.message_id),
            Ok(None)
        );
    }

    #[test]
    fn last_n_tied_cutoff_never_over_discloses_and_future_order_remains_visible() {
        let store = MemoryLocalStore::default();
        let owner = subject("lastn-owner", PrincipalKind::Person);
        let member = subject("lastn-member", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("lastn", &owner);
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let mut first = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "tie-a",
        );
        first.logical_order = 7;
        let mut second = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "tie-b",
        );
        second.logical_order = 7;
        store.persist_group_message(&owner, &first).expect("first");
        store
            .persist_group_message(&owner, &second)
            .expect("second");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("lastn-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: member.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add).expect("add member");
        assert_eq!(
            store.group_message(&member, &scope(), &first.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(&member, &scope(), &second.message_id),
            Ok(None)
        );
        let mut future = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "future",
        );
        future.logical_order = 8;
        store
            .persist_group_message(&owner, &future)
            .expect("future");
        assert!(
            store
                .group_message(&member, &scope(), &future.message_id)
                .expect("read")
                .is_some()
        );
    }

    #[test]
    fn creator_history_floor_is_derived_from_preexisting_transcript() {
        let store = MemoryLocalStore::default();
        let owner = subject("creator-floor-owner", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("creator-floor", &owner);
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        assert_eq!(
            store.persist_conversation(&conversation),
            Ok(DurableRecordStatus::Persisted)
        );
        let mut first = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "pre-first",
        );
        first.logical_order = 4;
        let mut last = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "pre-last",
        );
        last.logical_order = 5;
        assert_eq!(
            store.persist_message(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_message(&last),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Persisted)
        );
        let membership = store
            .group_membership(&scope(), &group.group_id, &owner.principal)
            .expect("membership read")
            .expect("creator membership");
        assert_eq!(membership.history_floor_logical_order, 5);
        assert_eq!(
            store.group_message(&owner, &scope(), &first.message_id),
            Ok(None)
        );
        assert!(
            store
                .group_message(&owner, &scope(), &last.message_id)
                .expect("last read")
                .is_some()
        );
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn group_message_without_group_aggregate_is_non_oracular() {
        let store = MemoryLocalStore::default();
        let owner = subject("aggregate-gap-owner", PrincipalKind::Person);
        let (conversation, _) = group_fixture("aggregate-gap", &owner);
        store
            .persist_conversation(&conversation)
            .expect("conversation");
        let orphan = message(
            &conversation.conversation,
            &owner.principal.principal_id,
            "aggregate-gap",
        );
        store.persist_message(&orphan).expect("message");
        assert_eq!(
            store.group_message(&owner, &scope(), &orphan.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(
                &owner,
                &scope(),
                &MessageId::from_opaque(oid("aggregate-gap-unknown"))
            ),
            Ok(None)
        );
    }

    #[test]
    fn duplicate_group_change_is_bound_to_original_actor() {
        let store = MemoryLocalStore::default();
        let owner = subject("duplicate-owner", PrincipalKind::Person);
        let intruder = subject("duplicate-intruder", PrincipalKind::Person);
        let (conversation, group) = group_fixture("duplicate-actor", &owner);
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("duplicate-actor-event")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("duplicate-member", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert_eq!(
            store.apply_group_change(&intruder, &change),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn same_opaque_id_different_principal_kinds_are_distinct_memberships() {
        let store = MemoryLocalStore::default();
        let owner = subject("dual-kind", PrincipalKind::Person);
        let alias = subject("dual-kind", PrincipalKind::Organization);
        let (conversation, group) = group_fixture("dual-kind", &owner);
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("dual-kind-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: alias.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Persisted)
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &owner.principal)
                .expect("owner lookup")
                .is_some()
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &alias.principal)
                .expect("alias lookup")
                .is_some()
        );
        assert_eq!(
            store
                .group_memberships(&scope(), &group.group_id, 8)
                .expect("members")
                .len(),
            2
        );
    }
}
