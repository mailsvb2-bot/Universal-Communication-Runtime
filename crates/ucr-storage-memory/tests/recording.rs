use ucr_core::{DurableRecordStatus, DurableStoreError, RecordingStore};
use ucr_model::{
    CallId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, RecordingConsent,
    RecordingConsentState, RecordingId, RecordingPolicy, RecordingSession, RecordingState,
    TenantId, TenantScope,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("recording-tenant")),
        namespace_id: None,
    }
}

fn principal(value: &str) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid(value)),
        kind: PrincipalKind::Person,
    }
}

fn recording() -> RecordingSession {
    RecordingSession {
        scope: scope(),
        recording_id: RecordingId::from_opaque(oid("recording-1")),
        call_id: CallId::from_opaque(oid("recording-call")),
        requested_by: principal("host"),
        policy: RecordingPolicy {
            require_all_participant_consent: true,
            notify_all_participants: true,
            retention_seconds: 600,
            policy_reference: Some("policy-1".to_owned()),
        },
        state: RecordingState::WaitingForConsent,
        consents: vec![
            RecordingConsent {
                participant: principal("host"),
                state: RecordingConsentState::Pending,
                decided_at_unix_ms: 0,
            },
            RecordingConsent {
                participant: principal("guest"),
                state: RecordingConsentState::Pending,
                decided_at_unix_ms: 0,
            },
        ],
        requested_at_unix_ms: 1_000_000,
        started_at_unix_ms: None,
        stopped_at_unix_ms: None,
        expires_at_unix_ms: 1_600_000,
        revision: 1,
    }
}

#[test]
fn all_required_consents_gate_start_and_revocation_stops_active_recording() {
    let store = MemoryLocalStore::default();
    let initial = recording();
    assert_eq!(
        store.persist_recording(&initial),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.start_recording(
            &initial.scope,
            &initial.recording_id,
            initial.revision,
            1_010_000,
        ),
        Err(DurableStoreError::Conflict)
    );

    let host_granted = store
        .set_recording_consent(
            &initial.scope,
            &initial.recording_id,
            1,
            &principal("host"),
            RecordingConsentState::Granted,
            1_010_000,
        )
        .expect("host consent");
    assert_eq!(host_granted.state, RecordingState::WaitingForConsent);

    let ready = store
        .set_recording_consent(
            &initial.scope,
            &initial.recording_id,
            host_granted.revision,
            &principal("guest"),
            RecordingConsentState::Granted,
            1_020_000,
        )
        .expect("guest consent");
    assert_eq!(ready.state, RecordingState::Ready);

    let active = store
        .start_recording(
            &initial.scope,
            &initial.recording_id,
            ready.revision,
            1_030_000,
        )
        .expect("start");
    assert_eq!(active.state, RecordingState::Active);
    assert_eq!(active.started_at_unix_ms, Some(1_030_000));

    let stopped = store
        .set_recording_consent(
            &initial.scope,
            &initial.recording_id,
            active.revision,
            &principal("guest"),
            RecordingConsentState::Revoked,
            1_040_000,
        )
        .expect("revoke");
    assert_eq!(stopped.state, RecordingState::Stopped);
    assert_eq!(stopped.stopped_at_unix_ms, Some(1_040_000));
}

#[test]
fn retention_expiry_is_finite_and_delete_is_idempotent() {
    let store = MemoryLocalStore::default();
    let mut initial = recording();
    initial.policy.require_all_participant_consent = false;
    initial.state = RecordingState::Ready;
    store.persist_recording(&initial).expect("persist");

    let active = store
        .start_recording(
            &initial.scope,
            &initial.recording_id,
            initial.revision,
            1_010_000,
        )
        .expect("start");
    let expired = store
        .expire_recording(
            &initial.scope,
            &initial.recording_id,
            active.revision,
            initial.expires_at_unix_ms,
        )
        .expect("expire");
    assert_eq!(expired.state, RecordingState::Expired);
    assert_eq!(expired.stopped_at_unix_ms, Some(initial.expires_at_unix_ms));

    let deleted = store
        .delete_recording(
            &initial.scope,
            &initial.recording_id,
            expired.revision,
            initial.expires_at_unix_ms,
        )
        .expect("delete");
    assert_eq!(deleted.state, RecordingState::Deleted);

    let repeated = store
        .delete_recording(
            &initial.scope,
            &initial.recording_id,
            deleted.revision,
            initial.expires_at_unix_ms,
        )
        .expect("repeat delete");
    assert_eq!(repeated, deleted);
}
