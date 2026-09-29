use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn recording_provider_is_a_side_effect_boundary_not_a_second_lifecycle_owner() {
    let core = read("crates/ucr-core/src/recording.rs");
    let exports = read("crates/ucr-core/src/lib.rs");
    let spec = read("spec/recording.md");

    assert!(core.contains("pub trait RecordingMediaProvider"));
    assert!(core.contains("pub struct RecordingProviderRequest"));
    assert!(core.contains("pub enum RecordingProviderOperation"));
    assert!(core.contains("pub enum RecordingProviderHealth"));
    assert!(core.contains("pub enum RecordingProviderError"));
    assert!(exports.contains("RecordingMediaProvider"));
    assert!(core.contains("pub trait RecordingProviderOperationStore"));
    assert!(core.contains("dispatch_recording_provider_operations_once"));
    assert!(exports.contains("RecordingProviderOperationStore"));
    let sqlite = read("crates/ucr-storage-sqlite/src/recording_provider_store.rs");
    assert!(sqlite.contains("recording_provider_operations"));
    assert!(sqlite.contains("TransactionBehavior::Immediate"));
    let grpc = read("crates/ucr-api-grpc/src/recording_service.rs");
    assert!(grpc.contains("start_recording_with_event_and_provider_operation"));
    assert!(grpc.contains("set_recording_consent_with_event_and_provider_stop"));
    assert!(spec.contains("one pluggable `RecordingMediaProvider` boundary"));
    assert!(spec.contains("must not become a second Recording lifecycle owner"));
}

#[test]
fn recording_provider_request_does_not_carry_media_or_crypto_secrets() {
    let core = read("crates/ucr-core/src/recording.rs");
    let start = core
        .find("pub struct RecordingProviderRequest")
        .expect("provider request");
    let end = core[start..]
        .find("\n}\n")
        .map(|offset| start + offset)
        .expect("provider request end");
    let request = &core[start..end];

    assert!(request.contains("scope: TenantScope"));
    assert!(request.contains("recording_id: RecordingId"));
    assert!(request.contains("call_id: CallId"));
    assert!(request.contains("lifecycle_revision: u64"));
    assert!(!request.contains("payload"));
    assert!(!request.contains("ciphertext"));
    assert!(!request.contains("key"));
    assert!(!request.contains("token"));
}


#[test]
fn realtime_join_enforces_recording_participant_churn_policy() {
    let core = read("crates/ucr-core/src/recording.rs");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/recording_store.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");

    assert!(core.contains("recording_allows_realtime_participant"));
    assert!(core.contains("active_recordings_for_call"));
    assert!(realtime.contains("require_recording_participant_admission"));
    assert!(realtime.contains("recording_allows_realtime_participant"));
    assert!(sqlite.contains("state='active'"));
    assert!(memory.contains("recording.state == RecordingState::Active"));
}
