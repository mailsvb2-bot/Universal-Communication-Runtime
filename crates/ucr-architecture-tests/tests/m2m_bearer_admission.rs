use std::{fs, path::Path};

#[test]
fn bearer_admission_is_shared_and_rechecks_canonical_authority() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/bearer.rs"))
        .expect("Bearer admission source");
    let spec =
        fs::read_to_string(workspace.join("spec/m2m-authentication.md")).expect("M2M auth spec");

    assert!(source.contains("MachineBearerAdmissionRuntime"));
    assert!(source.contains("MachineBearerRequestGate"));
    assert!(source.contains("ServicePrincipalRequestGate"));
    assert!(source.contains("bind_machine_bearer_request"));
    assert!(source.contains("verify_machine_access_token"));
    assert!(source.contains("canonical_permission_for_scope"));
    assert!(source.contains("self.authorization.authorize(&AuthorizationRequest"));
    assert!(source.contains("CanonicalErrorCode::Unauthenticated"));
    assert!(source.contains("CanonicalErrorCode::PermissionDenied"));

    for forbidden in [
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

    let production = source
        .split_once("#[cfg(test)]")
        .map_or(source.as_str(), |(production, _)| production);
    assert!(
        !production.contains(".consume_service_request_for_class("),
        "machine-auth must reuse the core quota owner"
    );
    assert!(
        !production.contains(".append_service_audit("),
        "machine-auth must reuse the core audit owner"
    );
    assert!(
        !production.contains("ServiceAuditRecord {"),
        "machine-auth must not construct a second audit record owner"
    );

    assert!(spec.contains("shared Bearer-admission runtime"));
    assert!(spec.contains("re-evaluates the current canonical Permission Grant"));
    assert!(spec.contains("same canonical request-rate quota and durable audit path"));
}

#[test]
fn bearer_admission_keeps_token_scope_as_attenuation_not_authority() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/bearer.rs"))
        .expect("Bearer admission source");

    let authentication_call = source
        .find("self.authenticate_scope(encoded, required_scope)?")
        .expect("shared token verification and scope check");
    let authorization_check = source
        .find("self.authorization.authorize(&AuthorizationRequest")
        .expect("canonical authorization check");
    assert!(
        authentication_call < authorization_check,
        "token verification and scope attenuation must run before canonical authorization"
    );

    let helper = source
        .find("fn authenticate_scope(")
        .expect("private Bearer authentication helper");
    assert!(
        source[helper..].contains(".granted_scopes"),
        "Bearer authentication helper must enforce token scope attenuation"
    );
}
