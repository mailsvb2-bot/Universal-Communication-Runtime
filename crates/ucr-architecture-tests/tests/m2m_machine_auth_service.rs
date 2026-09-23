use std::{fs, path::Path};

#[test]
fn machine_auth_runtime_owns_credentials_authorization_and_token_issuance() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/lib.rs"))
        .expect("machine auth runtime");
    let production = runtime
        .split_once("#[cfg(test)]")
        .map_or(runtime.as_str(), |(production, _)| production);
    let grpc =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/machine_auth_service.rs"))
            .expect("machine auth gRPC adapter");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
        .expect("authorization registry");

    assert!(production.contains("ServicePrincipalRequestGate::new"));
    assert!(production.contains("MACHINE_TOKEN_ISSUE_PERMISSION"));
    assert!(production.contains("admission.authorize(&AuthorizationRequest"));
    assert!(production.contains("authorize_additional_permission"));
    assert!(production.contains("require_client_id(&subject, request.client_id)"));
    assert!(production.contains("issue_machine_access_token"));
    assert!(production.contains("generate_opaque_id"));
    assert!(production.contains("request.audience != self.policy.audience"));

    for permission in [
        "CONFERENCE_CREATE_PERMISSION",
        "CONFERENCE_MANAGE_PERMISSION",
        "CONFERENCE_JOIN_ISSUE_PERMISSION",
        "CONFERENCE_READ_PERMISSION",
        "CONFERENCE_ATTENDANCE_READ_PERMISSION",
        "CONFERENCE_RECORDING_MANAGE_PERMISSION",
    ] {
        assert!(
            production.contains(permission),
            "missing canonical permission: {permission}"
        );
    }

    assert!(protocol.contains(
        r#"pub const MACHINE_TOKEN_ISSUE_PERMISSION: &str = "ucr.authentication.machine_token.issue""#
    ));
    assert!(!production.contains("PermissionGrant {"));
    assert!(!production.contains("client_secret"));
    assert!(!production.contains("ServiceCredentialRecord {"));

    assert!(grpc.contains("MachineAuthRuntime::new"));
    assert!(grpc.contains("MachineAuthExchangeRequest"));
    assert!(!grpc.contains("ServicePrincipalRequestGate::new"));
    assert!(!grpc.contains("authorize_additional_permission"));
    assert!(!grpc.contains("CONFERENCE_CREATE_PERMISSION"));
    assert!(!grpc.contains("CONFERENCE_MANAGE_PERMISSION"));
    assert!(!grpc.contains("PermissionGrant {"));
}

#[test]
fn machine_auth_runtime_is_shared_workspace_owner_not_transport_local_logic() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    let grpc_manifest = fs::read_to_string(workspace.join("crates/ucr-api-grpc/Cargo.toml"))
        .expect("gRPC manifest");

    assert!(root.contains(r#""crates/ucr-machine-auth""#));
    assert!(grpc_manifest.contains(r#"ucr-machine-auth = { path = "../ucr-machine-auth" }"#));
}

#[test]
fn machine_auth_scope_vocabulary_stays_bounded_and_provider_neutral() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/lib.rs"))
        .expect("machine auth runtime");

    for scope in [
        "conference:create",
        "conference:manage",
        "conference:join:issue",
        "conference:read",
        "attendance:read",
        "recording:manage",
    ] {
        assert!(runtime.contains(scope), "missing public scope: {scope}");
    }

    for forbidden in ["ClientPlatform", "CRM", "payment", "advertising"] {
        assert!(
            !runtime.contains(forbidden),
            "business concept leaked: {forbidden}"
        );
    }
}
