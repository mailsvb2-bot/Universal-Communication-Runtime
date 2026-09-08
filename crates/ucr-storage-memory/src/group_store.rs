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
        let (group, creator_membership) =
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
            return if existing == &group && existing_creator == Some(&creator_membership) {
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
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let group_key = group_key(&change.scope, &change.group_id);
        let change_key = change_key(
            &change.scope,
            &change.group_id,
            change.event_id.as_opaque().as_str(),
        );
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.group_changes.get(&change_key) {
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
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
        state.group_changes.insert(change_key, fingerprint);
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
        let group = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.conversation == message.conversation)
            .ok_or(DurableStoreError::Corrupt)?;
        let membership = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .ok_or(DurableStoreError::PermissionDenied)?;
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
        member.principal_id.as_opaque().as_str().to_owned(),
    )
}

fn change_key(scope: &TenantScope, group_id: &GroupId, event_id: &str) -> GroupChangeKey {
    (
        scope_key(scope),
        group_id.as_opaque().as_str().to_owned(),
        event_id.to_owned(),
    )
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
            Ok(if orders.len() <= count {
                0
            } else {
                orders[orders.len() - count]
            })
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
        GroupHistoryPolicy::FromTimestamp(timestamp) => message.created_at_unix_ms >= timestamp,
        GroupHistoryPolicy::CustomPolicy(_) => false,
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
