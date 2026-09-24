use std::{fs, path::Path};

#[test]
fn universal_conference_ingress_accepts_one_canonical_authentication_scheme() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = fs::read_to_string(
        workspace.join("crates/ucr-api-grpc/src/universal_conference_service.rs"),
    )
    .expect("Universal Conference gRPC source");
    let spec = fs::read_to_string(workspace.join("spec/universal-conference-api.md"))
        .expect("Universal Conference API spec");

    assert!(source.contains("decode_universal_conference_authentication"));
    assert!(source.contains("UniversalConferenceAuthentication::ServiceCredential"));
    assert!(source.contains("UniversalConferenceAuthentication::MachineBearer"));
    assert!(source.contains("MachineBearerRequestGate"));
    assert!(source.contains("authenticate_permission_request"));
    assert!(source.contains("with_machine_bearer_auth"));
    assert!(source.contains("has_credential_id || has_credential_secret"));
    assert!(spec.contains("exactly one machine-authentication scheme per request"));
    assert!(spec.contains("Authorization: Bearer <access-token>"));
    assert!(spec.contains("still re-evaluates the exact canonical permission"));

    let production = source
        .split_once("#[cfg(test)]")
        .map_or(source.as_str(), |(production, _)| production);
    assert_eq!(
        production
            .matches("decode_universal_conference_authentication(request.metadata())")
            .count(),
        16,
        "every Universal Conference RPC must pass through the typed auth selector",
    );
    assert_eq!(
        production
            .matches("decode_credentials(request.metadata())")
            .count(),
        0,
        "Universal Conference RPCs must not bypass the typed auth selector",
    );

    for forbidden in [
        "verify_machine_access_token(",
        "issue_machine_access_token(",
        "ServiceAuditRecord {",
        ".consume_service_request_for_class(",
    ] {
        assert!(
            !production.contains(forbidden),
            "gRPC ingress duplicated an authentication/quota/audit owner: {forbidden}"
        );
    }
}

#[test]
fn machine_scope_projection_remains_owned_by_machine_auth() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = fs::read_to_string(workspace.join("crates/ucr-machine-auth/src/lib.rs"))
        .expect("machine-auth source");

    assert!(source.contains("pub const fn machine_scope_for_permission"));
    assert!(source.contains("ucr.conference.participant.ensure"));
    assert!(source.contains("ucr.conference.participant.manage"));
    assert!(source.contains("ucr.identity.device.register"));
    assert!(source.contains("MACHINE_SCOPE_CONFERENCE_MANAGE"));
}
