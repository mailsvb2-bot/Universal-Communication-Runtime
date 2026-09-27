use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn recording_service_reuses_canonical_auth_and_store_owners() {
    let api = read("crates/ucr-api-grpc/src/recording_service.rs");
    let auth = read("crates/ucr-api-grpc/src/machine_api_auth.rs");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/recording.md");

    assert!(api.contains("RecordingStore"));
    assert!(api.contains("CONFERENCE_RECORDING_MANAGE_PERMISSION"));
    assert!(api.contains("decode_machine_api_authentication"));
    assert!(api.contains("authenticate_realtime_bearer_claims"));
    assert!(api.contains("claims.participant != participant"));
    assert!(api.contains("call_for_participant"));
    assert!(auth.contains("MachineBearerRequestGate"));
    assert!(realtime.contains("pub(crate) fn authenticate_realtime_bearer_claims"));
    assert!(runtime.contains("recording: false"));
    assert!(spec.contains("Capability discovery must continue to report recording unavailable"));
}

#[test]
fn recording_consent_does_not_accept_service_account_authority() {
    let api = read("crates/ucr-api-grpc/src/recording_service.rs");
    let proto = read("proto/ucr/v1/recording.proto");

    assert!(proto.contains("a Service Account cannot assert consent on someone's behalf"));
    assert!(api.contains("decode_bearer_token(request.metadata())"));
    assert!(!api.contains("admit_management(&scope, authentication)\n                    .and_then(|_| self.store.set_recording_consent"));
}
