use std::{fs, path::Path};

#[test]
fn machine_bearer_audit_has_typed_authentication_reference_and_distinct_hash_domain() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs"))
        .expect("model source");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/service_control.rs"))
        .expect("service control protocol");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/service_control_store.rs"))
            .expect("sqlite service control");

    assert!(model.contains("pub enum ServiceAuthenticationRef"));
    assert!(model.contains("ServiceCredential(ServiceCredentialId)"));
    assert!(model.contains("MachineAccessToken(OpaqueId)"));
    assert!(model.contains("pub authentication: ServiceAuthenticationRef"));
    assert!(!model.contains("pub credential_id: ServiceCredentialId"));

    assert!(protocol.contains("SERVICE_AUDIT_HASH_V1_DOMAIN"));
    assert!(protocol.contains("SERVICE_AUDIT_HASH_V2_DOMAIN"));
    assert!(protocol.contains("SERVICE_AUDIT_HASH_V3_DOMAIN"));
    assert!(protocol.contains("ServiceAuthenticationRef::MachineAccessToken"));
    assert!(protocol.contains("service_audit_hash_v3"));

    assert!(sqlite.contains("authentication_kind"));
    assert!(sqlite.contains("machine_access_token"));
    assert!(sqlite.contains("verify_audit_chain_v44"));
    assert!(sqlite.contains("decode_audit_tuple_with_authentication"));
}

#[test]
fn legacy_credential_audit_hashing_remains_on_v1_v2_domains() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/service_control.rs"))
        .expect("service control protocol");

    let routing = protocol
        .split_once("pub fn service_audit_hash(")
        .expect("audit hash owner")
        .1
        .split_once("fn service_audit_hash_v1(")
        .expect("hash routing section")
        .0;

    assert!(routing.contains("ServiceAuthenticationRef::ServiceCredential"));
    assert!(routing.contains("service_audit_hash_v1"));
    assert!(routing.contains("service_audit_hash_v2"));
    assert!(routing.contains("ServiceAuthenticationRef::MachineAccessToken"));
    assert!(routing.contains("service_audit_hash_v3"));
}
