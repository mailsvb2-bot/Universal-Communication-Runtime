use std::{fs, path::Path};

#[test]
fn m2m_token_runtime_uses_canonical_service_identity_and_crypto_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-crypto/src/machine_token.rs"))
        .expect("machine token runtime");
    let manifest = fs::read_to_string(workspace.join("crates/ucr-crypto/Cargo.toml"))
        .expect("crypto manifest");
    let spec = fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("m2m spec");

    assert!(runtime.contains("PrincipalKind::ServiceAccount"));
    assert!(runtime.contains("MachineTokenKeyResolver"));
    assert!(runtime.contains("issue_machine_access_token"));
    assert!(runtime.contains("verify_machine_access_token"));
    assert!(runtime.contains("ScopeNotAllowed"));
    assert!(runtime.contains("WrongAudience"));
    assert!(runtime.contains("WrongIssuer"));
    assert!(runtime.contains("Expired"));
    assert!(runtime.contains("VerifyingKey::from_bytes"));
    assert!(runtime.contains("URL_SAFE_NO_PAD"));
    assert!(!runtime.contains("PermissionGrant {"));
    assert!(!runtime.contains("client_secret"));
    assert!(!runtime.contains("ServiceCredentialSecret"));
    assert!(manifest.contains("ed25519-dalek = \"=3.0.0\""));
    assert!(spec.contains("reference Ed25519 signed access-token issuer/verifier"));
}

#[test]
fn m2m_token_runtime_redacts_bearer_and_private_key_material() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-crypto/src/machine_token.rs"))
        .expect("machine token runtime");

    assert!(runtime.contains(".field(\"encoded\", &\"<redacted>\")"));
    assert!(runtime.contains(".field(\"key\", &\"<secret>\")"));
    assert!(!runtime.contains("pub private_key"));
    assert!(!runtime.contains("private_key:"));
    assert!(!runtime.contains(".field(\"private_key\""));
    assert!(!runtime.contains("secret_digest"));
}
