use core::fmt;

use ucr_model::{
    CallId, EventEnvelope, PrincipalRef, RecordingConsentState, RecordingId, RecordingSession,
    RecordingState, TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

pub const MAX_RECORDING_RETENTION_BATCH: usize = 256;

/// Provider-side operation requested after the canonical Recording lifecycle authorizes it.
///
/// This is deliberately not another Recording state machine. The durable `RecordingStore` remains
/// authoritative; providers only perform bounded media/storage side effects for an already
/// authorized lifecycle revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordingProviderOperation {
    Start,
    Stop,
    Delete,
}

/// Minimal non-secret context a media provider may use to bind side effects to canonical state.
///
/// The tuple `(scope, recording_id, lifecycle_revision, operation)` is the provider idempotency
/// identity. Exact retries must not duplicate capture, finalization, or deletion effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingProviderRequest {
    pub scope: TenantScope,
    pub recording_id: RecordingId,
    pub call_id: CallId,
    pub lifecycle_revision: u64,
    pub operation: RecordingProviderOperation,
    pub expires_at_unix_ms: i64,
}

impl RecordingProviderRequest {
    #[must_use]
    pub fn for_session(session: &RecordingSession, operation: RecordingProviderOperation) -> Self {
        Self {
            scope: session.scope.clone(),
            recording_id: session.recording_id.clone(),
            call_id: session.call_id.clone(),
            lifecycle_revision: session.revision,
            operation,
            expires_at_unix_ms: session.expires_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingProviderHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingProviderError {
    Conflict,
    CapacityExceeded,
    TemporarilyUnavailable,
    PolicyDenied,
    Internal,
}

/// Pluggable encoded-media/storage boundary for Conference recording.
///
/// Implementations may represent an in-process recorder, S3-compatible encrypted object pipeline,
/// or an external media system. They must not own Conference/Call/Recording lifecycle state, must
/// not persist UCR MLS keys, and must treat exact provider requests idempotently across retries.
pub trait RecordingMediaProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn health(&self) -> RecordingProviderHealth;

    /// Applies one already-authorized provider side effect.
    ///
    /// # Errors
    /// Returns a bounded provider failure. A changed request reusing an already-applied canonical
    /// operation identity must fail with `Conflict` rather than silently widening behavior.
    fn apply(&self, request: &RecordingProviderRequest) -> Result<(), RecordingProviderError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingProviderOperationState {
    Pending,
    Applied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingProviderOperationRecord {
    pub request: RecordingProviderRequest,
    pub state: RecordingProviderOperationState,
    pub attempts: u32,
    pub available_at_unix_ms: i64,
}

pub const MAX_RECORDING_PROVIDER_OPERATION_BATCH: usize = 128;
pub const MAX_ACTIVE_RECORDINGS_PER_CALL: usize = 16;
pub const MAX_RECORDING_PROVIDER_ATTEMPTS: u32 = 8;
pub const RECORDING_PROVIDER_RETRY_BASE_MS: i64 = 1_000;
pub const RECORDING_PROVIDER_RETRY_MAX_MS: i64 = 60_000;

/// Durable restart-safe ledger for provider side effects authorized by canonical Recording state.
///
/// Implementations must keep the operation identity
/// `(scope, recording_id, lifecycle_revision, operation)` unique. Preparing the exact same
/// operation is idempotent; changed reuse conflicts.
pub trait RecordingProviderOperationStore: StorageProvider {
    /// Persists or deduplicates one pending provider operation.
    ///
    /// # Errors
    /// Rejects malformed/conflicting records and explicit durable-store failures.
    fn prepare_recording_provider_operation(
        &self,
        record: &RecordingProviderOperationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Returns a bounded deterministic batch of due pending operations.
    ///
    /// # Errors
    /// Rejects zero/oversized limits and explicit durable-store failures.
    fn pending_recording_provider_operations(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecordingProviderOperationRecord>, DurableStoreError>;

    /// Marks one exact pending operation applied.
    ///
    /// # Errors
    /// Rejects stale/mismatched state and explicit durable-store failures.
    fn mark_recording_provider_operation_applied(
        &self,
        request: &RecordingProviderRequest,
    ) -> Result<(), DurableStoreError>;

    /// Records a retry for one exact pending operation and moves its next-attempt deadline.
    ///
    /// # Errors
    /// Rejects stale/mismatched state, non-increasing deadlines and explicit store failures.
    fn retry_recording_provider_operation(
        &self,
        request: &RecordingProviderRequest,
        next_attempt_unix_ms: i64,
    ) -> Result<(), DurableStoreError>;

    /// Marks one exact pending operation terminally failed.
    ///
    /// # Errors
    /// Rejects stale/mismatched state and explicit durable-store failures.
    fn mark_recording_provider_operation_failed(
        &self,
        request: &RecordingProviderRequest,
    ) -> Result<(), DurableStoreError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecordingProviderDispatchSweep {
    pub examined: usize,
    pub applied: usize,
    pub retried: usize,
    pub failed: usize,
}

/// Applies one bounded batch of durable Recording provider operations.
///
/// The durable outbox remains authoritative for retry state. Exact provider retries use the
/// canonical provider-operation identity already embedded in each request.
///
/// # Errors
/// Returns explicit durable-store failures. Provider failures are converted into retry or terminal
/// outbox state and do not abort unrelated operations in the same batch.
pub fn dispatch_recording_provider_operations_once<S, P>(
    store: &S,
    provider: &P,
    now_unix_ms: i64,
    limit: usize,
) -> Result<RecordingProviderDispatchSweep, DurableStoreError>
where
    S: RecordingProviderOperationStore,
    P: RecordingMediaProvider + ?Sized,
{
    let pending = store.pending_recording_provider_operations(now_unix_ms, limit)?;
    let mut sweep = RecordingProviderDispatchSweep::default();

    for record in pending {
        sweep.examined = sweep.examined.saturating_add(1);
        match provider.apply(&record.request) {
            Ok(()) => {
                store.mark_recording_provider_operation_applied(&record.request)?;
                sweep.applied = sweep.applied.saturating_add(1);
            }
            Err(RecordingProviderError::Conflict | RecordingProviderError::PolicyDenied) => {
                store.mark_recording_provider_operation_failed(&record.request)?;
                sweep.failed = sweep.failed.saturating_add(1);
            }
            Err(
                RecordingProviderError::CapacityExceeded
                | RecordingProviderError::TemporarilyUnavailable
                | RecordingProviderError::Internal,
            ) => {
                if record.attempts.saturating_add(1) >= MAX_RECORDING_PROVIDER_ATTEMPTS {
                    store.mark_recording_provider_operation_failed(&record.request)?;
                    sweep.failed = sweep.failed.saturating_add(1);
                } else {
                    let next_attempt = now_unix_ms
                        .checked_add(recording_provider_retry_delay_ms(record.attempts))
                        .ok_or(DurableStoreError::InvalidRecord)?;
                    store.retry_recording_provider_operation(&record.request, next_attempt)?;
                    sweep.retried = sweep.retried.saturating_add(1);
                }
            }
        }
    }

    Ok(sweep)
}

#[must_use]
pub fn recording_provider_retry_delay_ms(previous_attempts: u32) -> i64 {
    let exponent = previous_attempts.min(6);
    let multiplier = 1_i64 << exponent;
    RECORDING_PROVIDER_RETRY_BASE_MS
        .saturating_mul(multiplier)
        .min(RECORDING_PROVIDER_RETRY_MAX_MS)
}

#[derive(Debug, Clone, Copy)]
pub struct RecordingConsentProviderStopRequest<'a> {
    pub scope: &'a TenantScope,
    pub recording_id: &'a RecordingId,
    pub expected_revision: u64,
    pub participant: &'a PrincipalRef,
    pub state: RecordingConsentState,
    pub now_unix_ms: i64,
    pub event: &'a EventEnvelope,
}

#[must_use]
pub fn recording_allows_realtime_participant(
    recording: &RecordingSession,
    participant: &PrincipalRef,
) -> bool {
    if recording.state != RecordingState::Active {
        return true;
    }
    let Some(consent) = recording
        .consents
        .iter()
        .find(|consent| consent.participant == *participant)
    else {
        return false;
    };
    match consent.state {
        RecordingConsentState::Granted => true,
        RecordingConsentState::Pending => !recording.policy.require_all_participant_consent,
        RecordingConsentState::Denied | RecordingConsentState::Revoked => false,
    }
}

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


    /// Returns a bounded deterministic set of ACTIVE recordings for one canonical Call.
    ///
    /// This lookup is used only for fail-closed realtime admission. It does not infer participant
    /// consent from Call membership and returns no non-active lifecycle state.
    ///
    /// # Errors
    /// Rejects zero/oversized limits and explicit durable-store failures.
    fn active_recordings_for_call(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        limit: usize,
    ) -> Result<Vec<RecordingSession>, DurableStoreError> {
        let _ = (scope, call_id, limit);
        Err(DurableStoreError::Unavailable)
    }

    /// Returns a bounded deterministic batch of non-final recordings whose retention deadline
    /// has elapsed. This is discovery only; callers must still apply expiry through the atomic
    /// `expire_recording_with_event` transition.
    ///
    /// # Errors
    /// Rejects zero/oversized limits and explicit durable-store failures.
    fn recordings_due_for_expiry(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecordingSession>, DurableStoreError> {
        let _ = (now_unix_ms, limit);
        Err(DurableStoreError::Unavailable)
    }

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

    /// Applies consent and atomically prepares a provider stop when the consent mutation stops an
    /// active recording.
    ///
    /// # Errors
    /// Fails closed when Recording state, Event and provider operation cannot be committed as one
    /// durable action.
    fn set_recording_consent_with_event_and_provider_stop(
        &self,
        request: RecordingConsentProviderStopRequest<'_>,
    ) -> Result<RecordingSession, DurableStoreError> {
        let _ = request;
        Err(DurableStoreError::Unavailable)
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

    /// Starts lifecycle and atomically prepares the matching provider side effect.
    ///
    /// # Errors
    /// Fails closed when the store cannot commit Recording state, Event and provider operation
    /// as one durable action.
    fn start_recording_with_event_and_provider_operation(
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

    /// Stops lifecycle and atomically prepares the provider stop operation.
    ///
    /// # Errors
    /// Fails closed when the combined durable action is unsupported or invalid.
    fn stop_recording_with_event_and_provider_operation(
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

    /// Expires lifecycle and atomically prepares controlled provider deletion.
    ///
    /// # Errors
    /// Fails closed when the combined durable action is unsupported or invalid.
    fn expire_recording_with_event_and_provider_operation(
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

    /// Deletes lifecycle and atomically prepares controlled provider deletion.
    ///
    /// # Errors
    /// Fails closed when the combined durable action is unsupported or invalid.
    fn delete_recording_with_event_and_provider_operation(
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Mutex};

    use ucr_model::{
        CallId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, RecordingConsent,
        RecordingConsentState, RecordingId, RecordingPolicy, RecordingSession, RecordingState,
        TenantId, TenantScope,
    };

    use super::{
        RecordingMediaProvider, RecordingProviderError, RecordingProviderHealth,
        RecordingProviderOperation, RecordingProviderRequest, recording_allows_realtime_participant,
    };

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid test id")
    }

    fn session() -> RecordingSession {
        RecordingSession {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque("tenant")),
                namespace_id: None,
            },
            recording_id: RecordingId::from_opaque(opaque("recording")),
            call_id: CallId::from_opaque(opaque("call")),
            requested_by: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("service")),
                kind: PrincipalKind::ServiceAccount,
            },
            policy: RecordingPolicy {
                require_all_participant_consent: true,
                notify_all_participants: true,
                retention_seconds: 3_600,
                policy_reference: None,
            },
            state: RecordingState::Active,
            consents: Vec::new(),
            requested_at_unix_ms: 10,
            started_at_unix_ms: Some(20),
            stopped_at_unix_ms: None,
            expires_at_unix_ms: 3_600_010,
            revision: 7,
        }
    }

    #[derive(Debug, Default)]
    struct IdempotentProvider {
        applied: Mutex<HashSet<(String, u64, RecordingProviderOperation)>>,
    }

    impl RecordingMediaProvider for IdempotentProvider {
        fn provider_id(&self) -> &'static str {
            "test.idempotent"
        }

        fn health(&self) -> RecordingProviderHealth {
            RecordingProviderHealth::Healthy
        }

        fn apply(&self, request: &RecordingProviderRequest) -> Result<(), RecordingProviderError> {
            self.applied.lock().expect("provider lock").insert((
                request.recording_id.as_opaque().as_str().to_owned(),
                request.lifecycle_revision,
                request.operation,
            ));
            Ok(())
        }
    }

    #[test]
    #[test]
    fn realtime_participant_gate_fails_closed_for_churn_without_consent_evidence() {
        let recording = session();
        let participant = PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque("late-participant")),
            kind: PrincipalKind::Person,
        };
        assert!(!recording_allows_realtime_participant(&recording, &participant));
    }

    #[test]
    fn realtime_participant_gate_respects_recording_consent_policy() {
        let participant = PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque("participant")),
            kind: PrincipalKind::Person,
        };
        let mut recording = session();
        recording.consents.push(RecordingConsent {
            participant: participant.clone(),
            state: RecordingConsentState::Pending,
            decided_at_unix_ms: 0,
        });
        assert!(!recording_allows_realtime_participant(&recording, &participant));

        recording.policy.require_all_participant_consent = false;
        assert!(recording_allows_realtime_participant(&recording, &participant));

        recording.consents[0].state = RecordingConsentState::Granted;
        recording.policy.require_all_participant_consent = true;
        assert!(recording_allows_realtime_participant(&recording, &participant));

        recording.consents[0].state = RecordingConsentState::Revoked;
        assert!(!recording_allows_realtime_participant(&recording, &participant));
    }

    fn provider_request_copies_only_bounded_canonical_recording_context() {
        let session = session();
        let request =
            RecordingProviderRequest::for_session(&session, RecordingProviderOperation::Start);
        assert_eq!(request.scope, session.scope);
        assert_eq!(request.recording_id, session.recording_id);
        assert_eq!(request.call_id, session.call_id);
        assert_eq!(request.lifecycle_revision, session.revision);
        assert_eq!(request.expires_at_unix_ms, session.expires_at_unix_ms);
        assert_eq!(request.operation, RecordingProviderOperation::Start);
    }

    #[test]
    fn provider_contract_supports_exact_retry_without_duplicate_effect_identity() {
        let provider = IdempotentProvider::default();
        let request =
            RecordingProviderRequest::for_session(&session(), RecordingProviderOperation::Delete);
        provider.apply(&request).expect("first apply");
        provider.apply(&request).expect("exact retry");
        assert_eq!(provider.applied.lock().expect("provider lock").len(), 1);
    }
}
