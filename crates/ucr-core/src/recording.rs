use ucr_model::{
    PrincipalRef, RecordingConsentState, RecordingId, RecordingSession, TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

/// Durable owner of recording policy, consent evidence and lifecycle only.
///
/// This store does not own Call/Group membership and never owns recorded media bytes or MLS keys.
/// Concrete media capture/storage remains a separate provider boundary.
pub trait RecordingStore: StorageProvider {
    /// Creates or deduplicates one recording lifecycle snapshot.
    ///
    /// # Errors
    /// Rejects malformed/conflicting state and explicit durable-store failures.
    fn persist_recording(
        &self,
        recording: &RecordingSession,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact recording lifecycle snapshot.
    ///
    /// # Errors
    /// Returns explicit durable-store or corruption failures.
    fn recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
    ) -> Result<Option<RecordingSession>, DurableStoreError>;

    /// Applies one participant-authenticated consent decision under optimistic revision.
    ///
    /// # Errors
    /// Rejects stale, invalid, unauthorized-by-caller-boundary, or final-state mutations.
    fn set_recording_consent(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        participant: &PrincipalRef,
        state: RecordingConsentState,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError>;

    /// Starts recording lifecycle after consent and retention gates pass.
    ///
    /// # Errors
    /// Rejects stale, non-ready, expired, or malformed transitions.
    fn start_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError>;

    /// Stops a waiting, ready or active lifecycle.
    ///
    /// # Errors
    /// Rejects stale/final/malformed transitions.
    fn stop_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError>;

    /// Applies finite-retention expiry.
    ///
    /// # Errors
    /// Rejects early/stale/malformed transitions.
    fn expire_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError>;

    /// Marks controlled recording state deleted.
    ///
    /// This mutation is lifecycle evidence only; a concrete media provider must separately prove
    /// deletion of its controlled encrypted media/key material before Production capability.
    ///
    /// # Errors
    /// Rejects stale/malformed transitions or explicit durable-store failures.
    fn delete_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError>;
}
