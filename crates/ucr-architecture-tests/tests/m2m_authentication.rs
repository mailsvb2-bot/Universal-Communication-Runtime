use std::{fs, path::Path};

#[test]
fn m2m_auth_is_an_attenuation_layer_over_canonical_service_credentials() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/m2m_auth.proto")).expect("m2m proto");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("m2m spec");
    let service_auth = fs::read_to_string(
        workspace.join("spec/service-principal-authentication.md"),
    )
    .expect("service auth spec");

    assert!(proto.contains("service MachineAuthService"));
    assert!(proto.contains("rpc ExchangeClientCredentials"));
    assert!(proto.contains("TenantScope scope"));
    assert!(proto.contains("OpaqueId client_id"));
    assert!(proto.contains("repeated string requested_scopes"));
    assert!(proto.contains("string audience"));
    assert!(!proto.contains("client_secret"));
    assert!(!proto.contains("credential_secret"));

    assert!(spec.contains("existing canonical Service Credential"));
    assert!(spec.contains("can only remove authority"));
    assert!(spec.contains("canonical Service Account has the corresponding Permission Grant"));
    assert!(spec.contains("POST /oauth2/token"));
    assert!(spec.contains("JWKS"));
    assert!(spec.contains("unknown/revoked signing key"));
    assert!(service_auth.contains("m2m-authentication.md"));
}

#[test]
fn m2m_auth_contract_keeps_business_and_human_login_out() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("m2m spec");

    for forbidden in ["CRM", "payment", "advertising", "authorization-code flow", "refresh tokens"] {
        if ["authorization-code flow", "refresh tokens"].contains(&forbidden) {
            assert!(spec.contains(forbidden), "nonclaim must stay explicit: {forbidden}");
        } else {
            assert!(!spec.contains(forbidden), "business concept leaked into auth: {forbidden}");
        }
    }
}
