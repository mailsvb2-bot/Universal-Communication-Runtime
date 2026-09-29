use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn recording_retention_worker_reuses_canonical_recording_and_event_owners() {
    let core = read("crates/ucr-core/src/recording.rs");
    let api = read("crates/ucr-api-grpc/src/recording_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let cli = read("crates/ucr-runtime/src/main.rs");
    let spec = read("spec/recording.md");

    assert!(core.contains("fn recordings_due_for_expiry("));
    assert!(api.contains("pub fn expire_due_recordings_once"));
    assert!(api.contains("expire_recording_with_event_and_provider_operation("));
    assert!(api.contains("RecordingState::Expired"));
    assert!(runtime.contains("run_recording_retention_worker"));
    assert!(runtime.contains("RECORDING_RETENTION_WORKER_KIND"));
    assert!(cli.contains("run-recording-retention-worker"));
    assert!(spec.contains("bounded, lease-coordinated retention worker"));
}

#[test]
fn recording_retention_worker_stays_bounded_and_does_not_enable_recorder_capability() {
    let core = read("crates/ucr-core/src/recording.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");

    assert!(core.contains("MAX_RECORDING_RETENTION_BATCH"));
    assert!(runtime.contains("MAX_RECORDING_RETENTION_BATCH"));
    assert!(runtime.contains("recording: false"));
    assert!(runtime.contains("recording provider is not configured"));
}
