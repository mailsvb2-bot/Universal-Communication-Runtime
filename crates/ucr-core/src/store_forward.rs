use ucr_model::{
    DeliveryId, StoreForwardId, StoreForwardJob, StoreForwardLease, StoreForwardLeaseId,
    TenantScope,
};

use crate::{CommunicationIntentStore, DeliveryStore, DurableRecordStatus, DurableStoreError};

/// Durable Store-and-Forward scheduling sidecar over canonical Intent, Message and Delivery owners.
///
/// Implementations persist opaque encrypted transport input plus bounded scheduling/lease metadata.
/// They MUST NOT create a second Message body, Delivery state machine, route graph, or relay identity.
pub trait StoreForwardStore: DeliveryStore + CommunicationIntentStore {
    /// Persists one new durable scheduling job. Identical retries deduplicate.
    ///
    /// # Errors
    /// Rejects invalid/cross-owner references, semantic ID reuse, or storage failures.
    fn persist_store_forward_job(
        &self,
        job: &StoreForwardJob,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact job. Absence is not an error.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures.
    fn store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
    ) -> Result<Option<StoreForwardJob>, DurableStoreError>;

    /// Enumerates a bounded deterministic set of due, non-leased jobs for one exact scope.
    /// Jobs whose last canonical Delivery attempt is `IN_FLIGHT` are intentionally excluded: after
    /// a crash their transport acceptance is ambiguous and automatic replay would be unsafe.
    ///
    /// # Errors
    /// Rejects invalid bounds and returns explicit storage/corruption failures.
    fn due_store_forward_jobs(
        &self,
        scope: &TenantScope,
        now_unix_ms: i64,
        max_items: usize,
    ) -> Result<Vec<StoreForwardId>, DurableStoreError>;

    /// Atomically claims one due job for a bounded lease.
    ///
    /// # Errors
    /// Rejects malformed lease timing or storage failures. Busy/not-due/ambiguous jobs return
    /// `Ok(None)` rather than leaking hidden state through a separate error channel.
    fn claim_store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
        lease_id: &StoreForwardLeaseId,
        now_unix_ms: i64,
        lease_until_unix_ms: i64,
    ) -> Result<Option<StoreForwardLease>, DurableStoreError>;

    /// Records the deterministic canonical `DeliveryId` consumed by this lease before any
    /// provider invocation. This makes crash recovery resume or block from Delivery truth rather
    /// than inventing a second transport state machine.
    ///
    /// # Errors
    /// Rejects stale leases, counter regressions, mismatched attempts, or storage failures.
    fn record_store_forward_attempt(
        &self,
        lease: &StoreForwardLease,
        delivery_id: &DeliveryId,
        attempts_used: u16,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError>;

    /// Releases a valid lease and moves the next scheduler eligibility time.
    ///
    /// # Errors
    /// Rejects stale leases, invalid timestamps, or storage failures.
    fn reschedule_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        next_attempt_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError>;

    /// Deletes the scheduling sidecar after canonical Delivery truth is terminal enough that no
    /// further sender-side forwarding work is required.
    ///
    /// # Errors
    /// Rejects a stale lease or storage failure.
    fn complete_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        now_unix_ms: i64,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}
