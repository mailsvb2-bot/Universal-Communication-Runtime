use std::{fs, path::Path};

#[test]
fn production_runtime_exposes_machine_auth_only_on_loopback_with_stable_key_loading() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-runtime/src/lib.rs"))
        .expect("runtime source");
    let main = fs::read_to_string(workspace.join("crates/ucr-runtime/src/main.rs"))
        .expect("runtime main");
    let crypto = fs::read_to_string(workspace.join("crates/ucr-crypto/src/machine_token.rs"))
        .expect("machine token crypto");

    assert!(runtime.contains("pub async fn serve_machine_auth"));
    assert!(runtime.contains("validate_local_bind(bind)?"));
    assert!(runtime.contains("GrpcMachineAuthService::new"));
    assert!(runtime.contains("machine_auth_service_server(service)"));
    assert!(runtime.contains("UCR_MACHINE_AUTH_READY endpoint=http://{address} tls_edge=required"));
    assert!(runtime.contains("MachineTokenSigningKey::from_seed"));

    assert!(main.contains(""serve-auth" => serve_auth_command"));
    assert!(main.contains("UCR_MACHINE_TOKEN_SIGNING_KEY_FILE"));
    assert!(main.contains("Zeroizing::new"));
    assert!(main.contains("read_machine_token_signing_key"));
    assert!(!main.contains("UCR_MACHINE_TOKEN_SIGNING_KEY_HEX"));

    assert!(crypto.contains("pub fn from_seed"));
    assert!(crypto.contains("seed.fill(0)"));
    assert!(crypto.contains(".field("key", &"<secret>")"));
}

#[test]
fn machine_auth_daemon_requires_public_https_discovery_and_stays_provider_neutral() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-runtime/src/lib.rs"))
        .expect("runtime source");

    assert!(runtime.contains("validate_public_https_url(&issuer"));
    assert!(runtime.contains("validate_public_https_url(&token_endpoint"));
    assert!(runtime.contains("validate_public_https_url(&jwks_uri"));
    assert!(runtime.contains("machine_auth=true test_mode=false"));

    for forbidden in ["ClientPlatform", "CRM", "payment", "advertising"] {
        assert!(
            !runtime.contains(forbidden),
            "business concept leaked into auth daemon: {forbidden}"
        );
    }
}
