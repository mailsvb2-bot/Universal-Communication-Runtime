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
    ///
    /// # Errors
    /// Returns an explicit durable-store failure for unavailable, corrupt, or invalid persisted state.
    fn group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
    ) -> Result<Option<GroupRecord>, DurableStoreError>;

    /// Resolves the Group aggregate bound to one exact canonical Conversation.
    ///
    /// # Errors
    /// Returns an explicit durable-store failure for unavailable, corrupt, or invalid persisted state.
    fn group_for_conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<GroupRecord>, DurableStoreError>;

    /// Loads one membership tombstone/active row by canonical principal.
    ///
    /// # Errors
    /// Returns an explicit durable-store failure for unavailable, corrupt, or invalid persisted state.
    fn group_membership(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        member: &ucr_model::PrincipalRef,
    ) -> Result<Option<GroupMembership>, DurableStoreError>;

    /// Loads a bounded canonical membership set, including removed tombstones.
    ///
    /// # Errors
    /// Rejects an invalid list bound and returns explicit durable-store failures.
    fn group_memberships(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<GroupMembership>, DurableStoreError>;

    /// Atomically verifies the subject is an active Group member and loads one membership from the same storage snapshot.
    ///
    /// Inactive/missing callers return non-disclosing absence rather than allowing Core to compose a racy pre-check plus read.
    ///
    /// # Errors
    /// Rejects scope mismatches and returns explicit durable-store failures.
    fn group_membership_for_active_member(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        member: &ucr_model::PrincipalRef,
    ) -> Result<Option<GroupMembership>, DurableStoreError>;

    /// Atomically verifies the subject is an active Group member and loads the bounded membership set from the same storage snapshot.
    ///
    /// # Errors
    /// Rejects scope mismatches, inactive callers, invalid bounds, and explicit durable-store failures.
    fn group_memberships_for_active_member(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<GroupMembership>, DurableStoreError>;

    /// Applies one idempotent security-sensitive Group change with optimistic revision checking.
    /// The authenticated actor is supplied by the Core authorization façade and must be checked
    /// against durable active membership inside the same atomic storage action before duplicate/conflict
    /// evidence is returned; new transitions additionally enforce the canonical current-role rules. An
    /// idempotent retry by the original still-active actor remains valid when the original transition itself
    /// changed that actor's role.
    ///
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, cross-scope, or invalid transitions and storage failures.
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
    /// Persists one group Message only while the authenticated subject has active send membership.
    ///
    /// # Errors
    /// Rejects non-group/cross-scope messages, inactive or unauthorized members, conflicts, and storage failures.
    fn persist_group_message(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Reads one group Message only while the authenticated subject may access its Group history.
    ///
    /// # Errors
    /// Rejects inactive or unauthorized members, invalid history access, and durable-store failures.
    fn group_message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError>;
}
