use std::{fs, path::PathBuf};

use ucr_sdk::{
    SERVICE_CREDENTIAL_ID_METADATA_KEY, SERVICE_CREDENTIAL_SECRET_METADATA_KEY, ServiceCredential,
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn phase41_rust_sdk_preserves_auth_bytes_and_redacts_secret() {
    let credential_id = vec![0x00, 0x01, 0xfe, 0xff];
    let secret = vec![0xde, 0xad, 0xbe, 0xef];
    let credential = ServiceCredential::new(credential_id.clone(), secret.clone());
    let request = credential.authenticated_request(vec![0x10, 0x20, 0x30]);

    assert_eq!(request.get_ref(), &vec![0x10, 0x20, 0x30]);
    let id = request
        .metadata()
        .get_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY)
        .expect("credential id metadata")
        .to_bytes()
        .expect("binary credential id");
    let stored_secret = request
        .metadata()
        .get_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY)
        .expect("credential secret metadata")
        .to_bytes()
        .expect("binary credential secret");
    assert_eq!(id.as_ref(), credential_id.as_slice());
    assert_eq!(stored_secret.as_ref(), secret.as_slice());

    let rendered = format!("{credential:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.to_ascii_lowercase().contains("deadbeef"));
}

#[test]
fn phase41_rust_sdk_keeps_the_eight_canonical_semantics_observable() {
    let root = repository_root();
    let manifest = fs::read_to_string(root.join("sdk/contract.json")).expect("SDK manifest");
    let sdk = fs::read_to_string(root.join("crates/ucr-sdk/src/lib.rs")).expect("Rust SDK");
    let runtime = fs::read_to_string(root.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");
    let errors = fs::read_to_string(root.join("proto/ucr/v1/errors.proto")).expect("errors proto");

    for marker in [
        "pub async fn submit_command",
        "pub async fn publish_event",
        "pub async fn poll_events",
        "authenticated_request",
    ] {
        assert!(sdk.contains(marker), "missing Rust SDK marker: {marker}");
    }
    assert!(sdk.contains("performs no automatic application retry"));
    assert!(manifest.contains("\"automatic_application_retry\": false"));
    assert!(manifest.contains("\"event_cursor\": \"opaque\""));
    assert!(manifest.contains("\"canonical_errors_preserved\": true"));
    assert!(manifest.contains("\"direct_database_access\": false"));
    assert!(runtime.contains("message NegotiationHello"));
    assert!(runtime.contains("message NegotiationResult"));
    assert!(runtime.contains("COMMAND_RECEIPT_STATUS_DUPLICATE"));
    assert!(errors.contains("ERROR_CODE_PERMISSION_DENIED"));
    assert!(errors.contains("message ErrorEnvelope"));
}
