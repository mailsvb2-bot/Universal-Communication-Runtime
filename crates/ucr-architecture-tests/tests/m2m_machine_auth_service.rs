use std::{fs, path::Path};

#[test]
fn machine_auth_service_reuses_canonical_service_admission_and_permissions() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let service =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/machine_auth_service.rs"))
            .expect("machine auth service");

    assert!(service.contains("ServicePrincipalRequestGate::new"));
    assert!(service.contains("admission.authorize(&AuthorizationRequest"));
    assert!(service.contains("authorize_additional_permission"));
    assert!(service.contains("require_client_id(&subject, &client_id)"));
    assert!(service.contains("PrincipalKind::ServiceAccount"));
    assert!(service.contains("issue_machine_access_token"));
    assert!(service.contains("generate_opaque_id"));
    assert!(service.contains("request.audience != self.policy.audience"));

    for permission in [
        "CONFERENCE_CREATE_PERMISSION",
        "CONFERENCE_MANAGE_PERMISSION",
        "CONFERENCE_JOIN_ISSUE_PERMISSION",
        "CONFERENCE_READ_PERMISSION",
        "CONFERENCE_ATTENDANCE_READ_PERMISSION",
        "CONFERENCE_RECORDING_MANAGE_PERMISSION",
    ] {
        assert!(
            service.contains(permission),
            "missing canonical permission: {permission}"
        );
    }

    assert!(!service.contains("PermissionGrant {"));
    assert!(!service.contains("client_secret"));
    assert!(!service.contains("ServiceCredentialRecord {"));
}

#[test]
fn machine_auth_service_keeps_scope_vocabulary_bounded_and_provider_neutral() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let service =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/machine_auth_service.rs"))
            .expect("machine auth service");

    for scope in [
        "conference:create",
        "conference:manage",
        "conference:join:issue",
        "conference:read",
        "attendance:read",
        "recording:manage",
    ] {
        assert!(service.contains(scope), "missing public scope: {scope}");
    }

    for forbidden in ["ClientPlatform", "CRM", "payment", "advertising"] {
        assert!(
            !service.contains(forbidden),
            "business concept leaked: {forbidden}"
        );
    }
}
