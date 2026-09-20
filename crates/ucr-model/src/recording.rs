use crate::{CallId, PrincipalRef, RecordingId, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    WaitingForConsent,
    Ready,
    Active,
    Stopped,
    Expired,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingConsentState {
    Pending,
    Granted,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingPolicy {
    pub require_all_participant_consent: bool,
    pub notify_all_participants: bool,
    pub retention_seconds: u64,
    pub policy_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingConsent {
    pub participant: PrincipalRef,
    pub state: RecordingConsentState,
    pub decided_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingSession {
    pub scope: TenantScope,
    pub recording_id: RecordingId,
    pub call_id: CallId,
    pub requested_by: PrincipalRef,
    pub policy: RecordingPolicy,
    pub state: RecordingState,
    pub consents: Vec<RecordingConsent>,
    pub requested_at_unix_ms: i64,
    pub started_at_unix_ms: Option<i64>,
    pub stopped_at_unix_ms: Option<i64>,
    pub expires_at_unix_ms: i64,
    pub revision: u64,
}
