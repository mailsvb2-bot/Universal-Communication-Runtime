use ucr_model::{
    ConversationId, ConversationRecord, GroupChange, GroupId, GroupMembership, GroupRecord,
    MessageEnvelope, MessageId, ScopedPrincipal, TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, MessageStore, StorageProvider};

/// Durable canonical Group aggregate owner.
///
/// Conversation and Message remain their existing owners. Implementations persist Group-specific
/// membership/ownership/policy state and must apply security-sensitive membership changes atomically.
pub trait GroupStore: StorageProvider {
    /// Atomically creates/deduplicates the Group aggregate together with its existing canonical
    /// group-kind Conversation and creator membership.
    ///
    /// # Errors
    /// Rejects malformed/cross-scope state, conflicting IDs, or storage failures.
    fn create_group(
        &self,
        conversation: &ConversationRecord,
        group: &GroupRecord,
        creator: &ScopedPrincipal,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact Group aggregate. Absence is not an error.
    fn group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
    ) -> Result<Option<GroupRecord>, DurableStoreError>;

    /// Resolves the Group aggregate bound to one exact canonical Conversation.
    fn group_for_conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<GroupRecord>, DurableStoreError>;

    /// Loads one membership tombstone/active row by canonical principal.
    fn group_membership(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        member: &ucr_model::PrincipalRef,
    ) -> Result<Option<GroupMembership>, DurableStoreError>;

    /// Loads a bounded canonical membership set, including removed tombstones.
    fn group_memberships(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<GroupMembership>, DurableStoreError>;

    /// Applies one idempotent security-sensitive Group change with optimistic revision checking.
    /// The authenticated actor is supplied by the Core authorization façade and must be checked
    /// against the durable active membership/role inside the same atomic storage action.
    fn apply_group_change(
        &self,
        actor: &ScopedPrincipal,
        change: &GroupChange,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}

/// Atomic membership-gated access to the existing canonical Message owner.
///
/// Implementations MUST write/read the same Message storage used by [`MessageStore`]; this trait
/// exists only so membership cannot race or be bypassed between an external check and persistence.
pub trait GroupMessageStore: GroupStore + MessageStore {
    fn persist_group_message(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    fn group_message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError>;
}
