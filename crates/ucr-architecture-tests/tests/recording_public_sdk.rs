use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn public_sdk_contract_includes_canonical_recording_service() {
    let manifest = read("sdk/contract.json");
    let rust = read("crates/ucr-sdk/src/lib.rs");

    assert!(manifest.contains("\"RecordingService\""));
    assert!(manifest.contains("\"SetRecordingConsent\""));
    assert!(manifest.contains("\"accepted_schemes\": [\"join_bearer\"]"));
    assert!(manifest.contains("\"RecordingService\": \"realtime\""));
    assert!(rust.contains("pb::recording_service_client::RecordingServiceClient"));
    assert!(rust.contains("pub async fn connect_with_recording_endpoint"));
    for method in [
        "pub async fn request_recording",
        "pub async fn get_recording",
        "pub async fn start_recording",
        "pub async fn stop_recording",
        "pub async fn delete_recording",
    ] {
        assert!(
            rust.contains(method),
            "missing recording SDK management method: {method}"
        );
    }
}

#[test]
fn service_credential_sdk_does_not_impersonate_participant_consent() {
    let rust = read("crates/ucr-sdk/src/lib.rs");
    let recording = read("crates/ucr-api-grpc/src/recording_service.rs");

    assert!(!rust.contains("pub async fn set_recording_consent"));
    assert!(recording.contains("decode_bearer_token(request.metadata())"));
    assert!(recording.contains("authenticate_realtime_bearer_claims"));
    assert!(recording.contains("claims.participant != participant"));
}
