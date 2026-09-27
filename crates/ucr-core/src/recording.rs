use ucr_model::{
    EventEnvelope, PrincipalRef, RecordingConsentState, RecordingId, RecordingSession, TenantScope,
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

    /// Applies consent and, when it changes the lifecycle (for example ACTIVE -> STOPPED),
    /// atomically persists the matching canonical Event with the new snapshot.
    ///
    /// # Errors
    /// Rejects invalid/stale consent transitions, mismatched Event evidence, unsupported atomic
    /// persistence, or explicit durable-store failures.
    #[allow(clippy::too_many_arguments)]
    fn set_recording_consent_with_event(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        participant: &PrincipalRef,
        state: RecordingConsentState,
        now_unix_ms: i64,
        event: Option<&EventEnvelope>,
    ) -> Result<RecordingSession, DurableStoreError> {
        if event.is_some() {
            return Err(DurableStoreError::Unavailable);
        }
        self.set_recording_consent(
            scope,
            recording_id,
            expected_revision,
            participant,
            state,
            now_unix_ms,
        )
    }

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

    /// Starts lifecycle and atomically persists its canonical lifecycle Event.
    ///
    /// # Errors
    /// Rejects stale/non-ready recording state, invalid Event evidence, unsupported atomic
    /// persistence, or explicit durable-store failures.
    fn start_recording_with_event(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
        event: &EventEnvelope,
    ) -> Result<RecordingSession, DurableStoreError> {
        let _ = (scope, recording_id, expected_revision, now_unix_ms, event);
        Err(DurableStoreError::Unavailable)
    }

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

    /// Stops lifecycle and atomically persists its canonical lifecycle Event.
    ///
    /// # Errors
    /// Rejects stale/final recording state, invalid Event evidence, unsupported atomic
    /// persistence, or explicit durable-store failures.
    fn stop_recording_with_event(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
        event: &EventEnvelope,
    ) -> Result<RecordingSession, DurableStoreError> {
        let _ = (scope, recording_id, expected_revision, now_unix_ms, event);
        Err(DurableStoreError::Unavailable)
    }

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

    /// Expires lifecycle and atomically persists its canonical lifecycle Event.
    ///
    /// # Errors
    /// Rejects early/stale recording state, invalid Event evidence, unsupported atomic
    /// persistence, or explicit durable-store failures.
    fn expire_recording_with_event(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
        event: &EventEnvelope,
    ) -> Result<RecordingSession, DurableStoreError> {
        let _ = (scope, recording_id, expected_revision, now_unix_ms, event);
        Err(DurableStoreError::Unavailable)
    }

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

    /// Marks lifecycle deleted and atomically persists its canonical lifecycle Event.
    ///
    /// # Errors
    /// Rejects stale/malformed recording state, invalid Event evidence, unsupported atomic
    /// persistence, or explicit durable-store failures.
    fn delete_recording_with_event(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
        event: &EventEnvelope,
    ) -> Result<RecordingSession, DurableStoreError> {
        let _ = (scope, recording_id, expected_revision, now_unix_ms, event);
        Err(DurableStoreError::Unavailable)
    }
}
