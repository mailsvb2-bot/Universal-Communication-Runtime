use std::{fs, path::Path};

#[test]
fn bearer_admission_is_shared_and_rechecks_canonical_authority() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source =
        fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/bearer.rs"))
            .expect("Bearer admission source");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("M2M auth spec");

    assert!(source.contains("MachineBearerAdmissionRuntime"));
    assert!(source.contains("verify_machine_access_token"));
    assert!(source.contains("canonical_permission_for_scope"));
    assert!(source.contains("self.authorization.authorize(&AuthorizationRequest"));
    assert!(source.contains("CanonicalErrorCode::Unauthenticated"));
    assert!(source.contains("CanonicalErrorCode::PermissionDenied"));

    for forbidden in [
        "ServiceCredentialStore",
        "ServicePrincipalRequestGate",
        "MachineTokenSigningKey",
        "issue_machine_access_token",
        "PermissionGrant {",
        "client_secret",
        "ClientPlatform",
        "CRM",
    ] {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(production, _)| production);
        assert!(
            !production.contains(forbidden),
            "Bearer admission duplicated an owner: {forbidden}"
        );
    }

    assert!(spec.contains("shared Bearer-admission runtime"));
    assert!(spec.contains("re-evaluates the current canonical Permission Grant"));
}

#[test]
fn bearer_admission_keeps_token_scope_as_attenuation_not_authority() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source =
        fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/bearer.rs"))
            .expect("Bearer admission source");

    let scope_check = source
        .find(".granted_scopes")
        .expect("token scope check");
    let authorization_check = source
        .find("self.authorization.authorize(&AuthorizationRequest")
        .expect("canonical authorization check");
    assert!(
        scope_check < authorization_check,
        "token scope must attenuate before canonical authorization is rechecked"
    );
}
