use ucr_model::{CallId, CallSession, CallSignal, ScopedPrincipal, TenantScope};

use crate::{
    ConversationStore, DurableRecordStatus, DurableStoreError, GroupStore, StorageProvider,
};

/// Durable canonical `CallSession` owner.
///
/// Call signalling reuses the existing Conversation and Group owners. Implementations must apply
/// participant authority, signalling transition, `EventId` reservation and persistence atomically.
pub trait CallStore: StorageProvider + ConversationStore + GroupStore {
    /// Starts/deduplicates one canonical `CallSession` after validating its existing Conversation and
    /// the authenticated initiator in the same storage action.
    ///
    /// # Errors
    /// Rejects cross-scope, unauthorized, malformed, conflicting, or unavailable durable state.
    fn create_call(
        &self,
        creator: &ScopedPrincipal,
        session: &CallSession,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact raw `CallSession` for internal durable workflows. External/runtime reads must
    /// use [`CallStore::call_for_participant`] so existence is not disclosed to non-participants.
    ///
    /// # Errors
    /// Returns explicit durable-store failures.
    fn call(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError>;

    /// Atomically verifies exact active participant authority and loads the `CallSession` from the
    /// same storage snapshot. Missing/inactive callers receive non-disclosing absence.
    ///
    /// # Errors
    /// Rejects scope mismatch and explicit durable-store failures.
    fn call_for_participant(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError>;

    /// Applies one actor-bound idempotent signalling mutation atomically.
    /// Duplicate/conflict evidence is returned only after current exact participant authority is
    /// established. The signal `EventId` is scope-wide reserved against unrelated Event/Group/Call
    /// facts.
    ///
    /// # Errors
    /// Rejects unauthorized, stale, conflicting, cross-scope, invalid, or unavailable state.
    fn apply_call_signal(
        &self,
        actor: &ScopedPrincipal,
        signal: &CallSignal,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}
