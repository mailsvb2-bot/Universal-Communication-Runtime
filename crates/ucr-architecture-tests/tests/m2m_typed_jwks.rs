use std::{fs, path::Path};

#[test]
fn typed_machine_jwks_exposes_only_public_ed25519_material() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/m2m_auth.proto")).expect("M2M proto");
    let service =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/machine_auth_service.rs"))
            .expect("machine auth service");

    assert!(proto.contains("rpc GetJwks"));
    assert!(proto.contains("message MachineAuthJwk"));
    for field in ["string kty", "string crv", "string use", "string alg", "string kid", "string x"] {
        assert!(proto.contains(field), "missing public JWKS field: {field}");
    }
    for forbidden in ["private_key", "signing_seed", "client_secret", "credential_secret"] {
        assert!(
            !proto.contains(forbidden),
            "secret material leaked into typed JWKS contract: {forbidden}"
        );
    }

    assert!(service.contains(r#"kty: "OKP".to_owned()"#));
    assert!(service.contains(r#"crv: "Ed25519".to_owned()"#));
    assert!(service.contains(r#"r#use: "sig".to_owned()"#));
    assert!(service.contains(r#"alg: "EdDSA".to_owned()"#));
    assert!(service.contains("URL_SAFE_NO_PAD.encode(public_key.verifying_key.0)"));
    assert!(service.contains(r#"supported_token_endpoint_auth_methods: vec!["client_secret_basic".to_owned()]"#));
    assert!(!service.contains("UCR_MACHINE_TOKEN_SIGNING_KEY_HEX"));
}

#[test]
fn jwks_http_projection_remains_transport_only_future_work() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("M2M auth spec");

    assert!(spec.contains("MachineAuthService.GetJwks"));
    assert!(spec.contains("future HTTPS adapter"));
    assert!(spec.contains("durable active/previous signing-key rotation remain separate work"));
}
