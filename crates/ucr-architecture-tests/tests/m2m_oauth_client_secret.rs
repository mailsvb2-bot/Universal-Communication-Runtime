use std::{fs, path::Path};

#[test]
fn oauth_client_secret_is_only_a_transport_binding_over_canonical_credentials() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/client_secret.rs"))
        .expect("OAuth client secret source");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("M2M auth spec");

    assert!(source.contains("ServiceCredentialSecret"));
    assert!(source.contains("ServiceCredentialId"));
    assert!(source.contains("TenantScope"));
    assert!(source.contains("encode_oauth_client_secret"));
    assert!(source.contains("decode_oauth_client_secret"));
    assert!(source.contains("URL_SAFE_NO_PAD.encode_string"));
    assert!(source.contains("raw.zeroize()"));
    assert!(source.contains("secret_bytes.zeroize()"));
    assert!(source.contains(r#".field("secret", &"<redacted>")"#));

    assert!(!source.contains("ServiceCredentialRecord {"));
    assert!(!source.contains("PermissionGrant {"));
    assert!(!source.contains("AuthorizationRequest {"));
    assert!(!source.contains("ClientPlatform"));

    assert!(spec.contains("opaque `client_id + client_secret` binding"));
    assert!(spec.contains("delegates exchange to `MachineAuthService`"));
}

#[test]
fn oauth_client_secret_never_enters_the_public_protobuf_body() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/m2m_auth.proto")).expect("M2M proto");

    assert!(proto.contains("OpaqueId client_id"));
    assert!(!proto.contains("client_secret"));
    assert!(!proto.contains("credential_secret"));
}
