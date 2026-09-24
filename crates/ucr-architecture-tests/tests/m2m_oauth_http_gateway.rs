use std::{fs, path::Path};

#[test]
fn oauth_http_gateway_is_transport_only_and_loopback_only() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    let source =
        fs::read_to_string(workspace.join("crates/ucr-auth-web/src/main.rs"))
            .expect("OAuth gateway source");

    assert!(root.contains(r#""crates/ucr-auth-web""#));
    assert!(source.contains(r#""/oauth2/token""#));
    assert!(source.contains(r#""/.well-known/oauth-authorization-server""#));
    assert!(source.contains(r#""/oauth2/jwks""#));
    assert!(source.contains("decode_oauth_client_secret"));
    assert!(source.contains("MachineAuthServiceClient"));
    assert!(source.contains("SERVICE_CREDENTIAL_ID_METADATA_KEY"));
    assert!(source.contains("SERVICE_CREDENTIAL_SECRET_METADATA_KEY"));
    assert!(source.contains("client_secret_basic is required"));
    assert!(source.contains("application/x-www-form-urlencoded"));
    assert!(source.contains("validate_loopback_bind(bind)?"));
    assert!(source.contains("tls_edge=required"));
    assert!(source.contains(r#".header(CACHE_CONTROL, "no-store")"#));
    assert!(source.contains(r#".header(PRAGMA, "no-cache")"#));

    for forbidden in [
        "MachineTokenSigningKey",
        "ServicePrincipalRequestGate",
        "PermissionGrant {",
        "issue_machine_access_token",
        "UCR_MACHINE_TOKEN_SIGNING_KEY_FILE",
        "ClientPlatform",
        "CRM",
        "payment",
        "advertising",
    ] {
        assert!(
            !source.contains(forbidden),
            "non-transport concern leaked into OAuth gateway: {forbidden}"
        );
    }
}

#[test]
fn oauth_gateway_keeps_secrets_out_of_diagnostics() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source =
        fs::read_to_string(workspace.join("crates/ucr-auth-web/src/main.rs"))
            .expect("OAuth gateway source");

    assert!(source.contains(r#".field("client_secret", &"<redacted>")"#));
    assert!(source.contains("self.client_secret.zeroize()"));
    assert!(source.contains("decoded.zeroize()"));
    assert!(source.contains("input.zeroize()"));
    assert!(!source.contains(r#"println!("client_secret"#));
    assert!(!source.contains(r#"eprintln!("client_secret"#));
}
