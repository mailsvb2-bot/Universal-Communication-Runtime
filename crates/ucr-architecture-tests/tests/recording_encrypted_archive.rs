use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn encrypted_archive_is_a_separate_provider_not_sfu_authority() {
    let workspace_manifest = read("Cargo.toml");
    let manifest = read("crates/ucr-recording/Cargo.toml");
    let provider = read("crates/ucr-recording/src/lib.rs");
    let sfu_manifest = read("crates/ucr-sfu/Cargo.toml");

    assert!(workspace_manifest.contains("\"crates/ucr-recording\""));
    assert!(provider.contains("impl RecordingMediaProvider for EncryptedArchiveRecordingProvider"));
    assert!(provider.contains("fn capture_encrypted_frame("));
    assert!(provider.contains("XChaCha20Poly1305"));
    assert!(provider.contains("SecretPurpose::RecordingAtRest"));
    assert!(provider.contains("FRAME_PATH_DOMAIN"));
    assert!(provider.contains("fs::hard_link(&temporary_path, path)"));
    assert!(!manifest.contains("ucr-sfu"));
    assert!(!sfu_manifest.contains("ucr-recording"));
}

#[test]
fn recording_at_rest_uses_the_shared_secret_owner_and_remains_opt_in() {
    let secrets = read("crates/ucr-secrets/src/lib.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/recording.md");

    assert!(secrets.contains("RecordingAtRest"));
    assert!(runtime.contains("recording: false"));
    assert!(spec.contains("second, independent XChaCha20-Poly1305 at-rest layer"));
    assert!(spec.contains("does not automatically advertise Recording"));
    assert!(spec.contains("access/export authorization"));
    assert!(spec.contains("ucr.recording.ready"));
}

#[test]
fn encrypted_archive_locks_idempotency_rotation_tamper_and_delete_evidence() {
    let provider = read("crates/ucr-recording/src/lib.rs");

    for test_name in [
        "archive_uses_outer_encryption_and_exact_frame_retry_is_idempotent",
        "changed_payload_reusing_capture_identity_conflicts",
        "current_and_previous_storage_keys_support_rotation_overlap",
        "delete_removes_recording_objects_but_keeps_encrypted_operation_receipt",
        "tampered_archive_fails_closed",
        "wrong_secret_purpose_is_rejected",
    ] {
        assert!(
            provider.contains(test_name),
            "missing provider evidence: {test_name}"
        );
    }
    assert!(provider.contains("self.write_idempotent(&self.operation_path(request)"));
    assert!(provider.contains("self.delete_recording_objects(&request.scope"));
}

#[test]
fn encrypted_archive_runtime_wiring_is_opt_in_same_runtime_and_cancellation_safe() {
    let manifest = read("crates/ucr-runtime/Cargo.toml");
    let main = read("crates/ucr-runtime/src/main.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");

    assert!(manifest.contains("ucr-recording = { path = \"../ucr-recording\" }"));
    assert!(main.contains("UCR_RECORDING_PROVIDER"));
    assert!(main.contains("encrypted-archive-v1"));
    assert!(main.contains("UCR_RECORDING_ARCHIVE_ROOT"));
    assert!(main.contains("UCR_RECORDING_ARCHIVE_ROOT must be an absolute path"));
    assert!(main.contains("requires UCR_RECORDING_PROVIDER=encrypted-archive-v1"));
    assert!(main.contains("MIN_RECORDING_PROVIDER_POLL_INTERVAL"));
    assert!(main.contains("MAX_RECORDING_PROVIDER_POLL_INTERVAL"));
    assert!(main.contains("UCR_RECORDING_AT_REST_SECRET_PROVIDER"));
    assert!(main.contains("SecretPurpose::RecordingAtRest"));
    assert!(main.contains("EncryptedArchiveRecordingProvider::new"));
    assert!(main.contains("serve_realtime_with_optional_recording_provider"));
    assert!(main.contains("run_recording_provider_worker"));
    assert!(main.contains("tokio::select!"));
    assert!(main.contains("biased;"));
    assert!(runtime.contains("struct RecordingProviderWorkerLeaseGuard"));
    assert!(runtime.contains("impl Drop for RecordingProviderWorkerLeaseGuard"));
    assert!(
        runtime.contains("recording_provider_worker_cancellation_releases_lease_and_registration")
    );
    assert!(runtime.contains("recording: false"));
}

#[test]
fn recording_ready_is_atomic_recoverable_and_not_lifecycle_ready() {
    let proto = read("proto/ucr/v1/recording.proto");
    let core = read("crates/ucr-core/src/recording.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/recording_provider_store.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let api = read("crates/ucr-api-grpc/src/recording_service.rs");
    let spec = read("spec/recording.md");

    assert!(proto.contains("message RecordingReadyEvent"));
    assert!(proto.contains("bool recovered_after_upgrade = 7;"));
    assert!(core.contains("commit_recording_provider_stop_ready_event"));
    assert!(core.contains("recover_recording_provider_ready_events_once"));
    assert!(sqlite.contains("ready_event_emitted"));
    assert!(sqlite.contains("recording_provider_stops_needing_ready_event"));
    assert!(sqlite.contains("event_journal::append_event_in_transaction"));
    assert!(api.contains("event_type: \"ucr.recording.ready\""));
    assert!(
        api.contains("recording_provider_ready_event_is_deterministic_and_not_lifecycle_ready")
    );
    assert!(runtime.contains("recording_provider_stop_commits_ready_event_atomically"));
    assert!(runtime.contains("recording_provider_ready_recovery_does_not_repeat_provider_stop"));
    assert!(runtime.contains("recording: false"));
    assert!(spec.contains("SQLite schema v48"));
}

