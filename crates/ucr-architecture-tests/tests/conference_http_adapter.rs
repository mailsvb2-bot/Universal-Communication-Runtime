use std::{fs, path::Path};

#[test]
fn conference_http_adapter_is_a_loopback_transport_over_universal_conference_grpc() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    let source = fs::read_to_string(workspace.join("crates/ucr-conference-web/src/main.rs"))
        .expect("conference HTTP adapter source");
    let openapi = fs::read_to_string(workspace.join("crates/ucr-conference-web/openapi.yaml"))
        .expect("conference OpenAPI");
    let spec = fs::read_to_string(workspace.join("spec/universal-conference-api.md"))
        .expect("Universal Conference spec");

    assert!(root.contains(r#""crates/ucr-conference-web""#));
    assert!(source.contains("UniversalConferenceServiceClient"));
    assert!(source.contains("validate_loopback_bind(bind)?"));
    assert!(source.contains("tls_edge=required"));
    assert!(source.contains(r#""/v1/conferences""#));
    assert!(source.contains(r#""/v1/participants""#));
    assert!(source.contains(r#""/v1/join-grants""#));
    assert!(source.contains(r#""/v1/capabilities""#));
    assert!(source.contains(r#".header(CACHE_CONTROL, "no-store")"#));
    assert!(source.contains(r#".header(PRAGMA, "no-cache")"#));
    assert!(source.contains("while let Some(frame) = body.frame().await"));
    assert!(!source.contains("body.collect().await"));
    assert!(openapi.contains("/v1/conferences:"));
    assert!(spec.contains("ucr-conference-web"));
    assert!(spec.contains("No REST-only business rules are allowed."));

    for forbidden in [
        "MachineTokenSigningKey",
        "verify_machine_access_token(",
        "issue_machine_access_token(",
        "ServicePrincipalRequestGate",
        "PermissionGrant {",
        "ClientPlatform",
        "CRM",
        "payment",
        "advertising",
    ] {
        assert!(
            !source.contains(forbidden),
            "non-transport concern leaked into the conference HTTP adapter: {forbidden}"
        );
    }
}
