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

#[test]
fn recording_provider_outbox_has_restart_safe_single_owner_runtime_worker() {
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/runtime_worker_store.rs");
    let spec = read("spec/recording.md");

    assert!(sqlite.contains("RECORDING_PROVIDER_WORKER_KIND"));
    assert!(runtime.contains("run_recording_provider_worker"));
    assert!(runtime.contains("try_acquire_runtime_worker_lease"));
    assert!(runtime.contains("renew_recording_provider_worker_lease"));
    assert!(runtime.contains("dispatch_recording_provider_operations_once"));
    assert!(runtime.contains("UCR_RECORDING_PROVIDER_SWEEP"));
    assert!(spec.contains("durable single-owner provider dispatcher worker"));
    assert!(spec.contains("does not make Recording capability available"));
    assert!(runtime.contains("operator_recording_provider_health"));
    assert!(runtime.contains("register_recording_provider"));
    assert!(runtime.contains("RecordingProviderHealth::Healthy"));
    assert!(runtime.contains("RecordingProviderHealth::Degraded"));
    assert!(runtime.contains("RecordingProviderHealth::Unavailable"));
    assert!(runtime.contains("runtime_worker_lease(RECORDING_PROVIDER_WORKER_KIND)"));
    assert!(runtime.contains("lease.holder_id == registration.holder_id"));
    assert!(runtime.contains("lease.lease_expires_unix_ms > now_unix_ms"));
    assert!(runtime.contains("recording: false"));
    assert!(spec.contains("every health snapshot revalidates the"));
    assert!(spec.contains("exact registered holder plus an unexpired"));
    assert!(spec.contains("does not change the public recording capability flag"));
    let worker_start = runtime
        .find("pub async fn run_recording_provider_worker(")
        .expect("recording provider worker");
    let worker_end = runtime[worker_start..]
        .find("fn renew_recording_provider_worker_lease(")
        .map(|offset| worker_start + offset)
        .expect("recording provider worker end");
    let worker = &runtime[worker_start..worker_end];
    let lease_index = worker
        .find("try_acquire_runtime_worker_lease(")
        .expect("provider worker lease acquisition");
    let registration_index = worker
        .find("register_recording_provider(")
        .expect("provider health registration");
    assert!(
        lease_index < registration_index,
        "provider health must not register before the durable worker lease is acquired"
    );
}

#[test]
fn recording_media_observer_uses_canonical_source_validation_not_recipient_fanout() {
    let sfu = read("crates/ucr-sfu/src/lib.rs");
    let conference = read("crates/ucr-conference/src/lib.rs");
    let grpc = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let exports = read("crates/ucr-api-grpc/src/lib.rs");
    let spec = read("spec/recording.md");

    assert!(sfu.contains("pub struct SfuValidatedSourceFrame"));
    assert!(sfu.contains("pub fn validate_source_frame("));
    assert!(conference.contains("pub fn validate_source_frame("));
    assert!(grpc.contains("pub trait RealtimeValidatedMediaObserver"));
    assert!(grpc.contains("observe_validated_media_if_configured"));
    assert!(grpc.contains(".validate_source_frame(&actor_for(claims), device_id, envelope)"));
    assert!(exports.contains("RealtimeValidatedMediaObserver"));
    assert!(spec.contains("independent from subscription"));
    assert!(spec.contains("contains ciphertext plus authenticated routing metadata"));
    assert!(spec.contains("`ucr.conference.recording` remains unavailable"));
}
