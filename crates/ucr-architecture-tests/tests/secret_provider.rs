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
    assert!(webrtc.contains("TurnRestCredentialIssuer::with_secret_provider"));
    assert!(webrtc.contains("SecretPurpose::TurnCredentials"));
    assert!(webrtc.contains("self.current_secret()?"));
    assert!(secrets.contains("pub trait SecretProvider"));
    assert!(secrets.contains("pub enum SecretPurpose"));
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
