use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn secret_provider_is_replaceable_and_does_not_become_a_second_security_owner() {
    let root = read("Cargo.toml");
    let secrets = read("crates/ucr-secrets/src/lib.rs");
    let realtime = read("crates/ucr-realtime/src/lib.rs");
    let spec = read("spec/secret-management.md");

    assert!(root.contains("\"crates/ucr-secrets\""));
    assert!(realtime.contains("JoinTokenIssuer::with_secret_provider"));
    assert!(realtime.contains("current_signing_key"));
    assert!(realtime.contains("verification_keys"));
    let webrtc = read("crates/ucr-webrtc/src/lib.rs");
    let webhook = read("crates/ucr-webhook/src/lib.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let https_edge = read("crates/ucr-https-edge/src/lib.rs");
    let https_edge_main = read("crates/ucr-https-edge/src/main.rs");
    let machine_auth = read("crates/ucr-api-grpc/src/machine_auth_service.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    assert!(webrtc.contains("TurnRestCredentialIssuer::with_secret_provider"));
    assert!(webrtc.contains("SecretPurpose::TurnCredentials"));
    assert!(webrtc.contains("self.current_secret()?"));
    assert!(webrtc.contains("turn_rest_secret_from_active_set"));
    assert!(webrtc.contains("u8::is_ascii_graphic"));
    assert!(webhook.contains("HardenedWebhookSink::with_secret_provider"));
    assert!(webhook.contains("SecretPurpose::WebhookSigning"));
    assert!(webhook.contains("self.current_signing_secret()?"));
    assert!(runtime.contains("dispatch_webhook_once_with_secret_provider"));
    assert!(runtime.contains("run_webhook_worker_with_secret_provider"));
    assert!(https_edge.contains("ProviderBackedTlsAcceptor"));
    assert!(https_edge.contains("SecretPurpose::TlsCertificate"));
    assert!(https_edge.contains("SecretPurpose::TlsPrivateKey"));
    assert!(https_edge.contains("current_acceptor"));
    assert!(https_edge.contains("ReloadingFileTlsSecretProvider"));
    assert!(https_edge.contains("UCR_HTTPS_EDGE_SECRET_PROVIDER"));
    assert!(https_edge_main.contains("run_configured"));
    assert!(machine_auth.contains("GrpcMachineAuthService::with_secret_provider"));
    assert!(machine_auth.contains("SecretPurpose::MachineTokenSigning"));
    assert!(machine_auth.contains("provider_key_material"));
    assert!(runtime.contains("MachineTokenVerificationKeyProvider"));
    assert!(runtime.contains("with_verification_provider"));
    assert!(runtime_main.contains("MachineAuthRuntimeConfig::with_secret_provider"));
    assert!(runtime_main.contains("UCR_MACHINE_TOKEN_SECRET_PROVIDER"));
    assert!(runtime_main.contains("ReloadingFileSecretProvider"));
    assert!(runtime_main.contains("ReloadingMachineTokenJwksProvider"));
    assert!(runtime_main.contains("UCR_MACHINE_TOKEN_VERIFICATION_PROVIDER"));
    assert!(runtime_main.contains("UCR_REALTIME_JOIN_SECRET_PROVIDER"));
    assert!(runtime_main.contains("UCR_REALTIME_JOIN_SECRET_FILE"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_SECRET_PROVIDER"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_SECRET_FILE"));
    assert!(runtime_main.contains("UCR_WEBHOOK_SECRET_PROVIDER"));
    assert!(runtime_main.contains("UCR_WEBHOOK_SIGNING_SECRET_FILE"));
    assert!(runtime.contains("RealtimeRuntimeConfig"));
    assert!(runtime.contains("with_join_secret_provider"));
    assert!(runtime.contains("with_webrtc_ice_secret_provider"));
    assert!(runtime_main.contains("run_webhook_worker_with_secret_provider"));
    assert!(runtime_main.contains("dispatch_webhook_once_with_secret_provider"));
    assert!(secrets.contains("pub trait SecretProvider"));
    assert!(secrets.contains("pub struct ReloadingFileSecretProvider"));
    assert!(secrets.contains("MAX_RELOADABLE_SECRET_MANIFEST_BYTES"));
    assert!(secrets.contains("pub enum SecretPurpose"));
    assert!(secrets.contains("MachineTokenSigning"));
    assert!(secrets.contains("JoinSigning"));
    assert!(secrets.contains("WebhookSigning"));
    assert!(secrets.contains("TlsPrivateKey"));
    assert!(secrets.contains("MediaCrypto"));
    assert!(secrets.contains("TurnCredentials"));
    assert!(secrets.contains("MAX_SECRET_VERSIONS_PER_HANDLE: usize = 2"));
    assert!(spec.contains("must not become a second authentication"));
    assert!(spec.contains("KMS"));
    assert!(spec.contains("Vault"));
}

#[test]
fn secret_material_is_bounded_redacted_and_overlap_rotation_is_explicit() {
    let secrets = read("crates/ucr-secrets/src/lib.rs");

    assert!(secrets.contains("MAX_SECRET_BYTES: usize = 64 * 1024"));
    assert!(secrets.contains(r#".field("bytes", &"<redacted>")"#));
    assert!(secrets.contains("self.0.zeroize()"));
    assert!(secrets.contains("pub previous: Option<SecretVersion>"));
    assert!(secrets.contains("Exact retries of the same version/material are idempotent"));
}
