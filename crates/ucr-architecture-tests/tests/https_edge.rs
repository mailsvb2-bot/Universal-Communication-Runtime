use std::{fs, path::Path};

#[test]
fn https_edge_terminates_tls_and_proxies_only_to_loopback() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    let source = fs::read_to_string(workspace.join("crates/ucr-https-edge/src/main.rs"))
        .expect("HTTPS edge source");
    let spec = fs::read_to_string(workspace.join("spec/m2m-authentication.md"))
        .expect("machine auth spec");

    assert!(root.contains(r#""crates/ucr-https-edge""#));
    assert!(source.contains("validate_loopback_upstream(upstream)?"));
    assert!(source.contains("TlsAcceptor"));
    assert!(source.contains("copy_bidirectional"));
    assert!(source.contains("https_edge_proxies_tls_bytes_to_loopback_upstream"));
    assert!(source.contains("https_edge_proxies_an_http1_request_to_loopback"));
    assert!(source.contains("UCR_HTTPS_EDGE_CERT_FILE"));
    assert!(source.contains("UCR_HTTPS_EDGE_KEY_FILE"));
    assert!(spec.contains("ucr-https-edge"));

    for forbidden in [
        "MachineTokenSigningKey",
        "verify_machine_access_token(",
        "issue_machine_access_token(",
        "ServicePrincipalRequestGate",
        "PermissionGrant {",
        "UniversalConferenceService",
        "ClientPlatform",
        "CRM",
    ] {
        assert!(
            !source.contains(forbidden),
            "non-edge concern leaked into the HTTPS edge: {forbidden}"
        );
    }
}
