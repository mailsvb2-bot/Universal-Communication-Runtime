use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn universal_conference_contract_hides_internal_ucr_identity_mechanics() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    assert!(proto.contains("service UniversalConferenceService"));
    assert!(proto.contains("rpc CreateConference"));
    assert!(proto.contains("rpc EnsureParticipant"));
    assert!(proto.contains("rpc IssueJoinGrant"));
    assert!(proto.contains("external_conference_id"));
    assert!(proto.contains("external_user_id"));
    assert!(!proto.contains("participant_id"));
    assert!(!proto.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with("//") && line.contains("PrincipalRef ")
    }));
    assert!(!proto.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with("//") && line.contains("DeviceId ")
    }));
    assert!(!proto.contains("clientplatform"));
    assert!(!proto.contains("crm"));
}

#[test]
fn universal_conference_keeps_webinar_as_configuration_not_a_second_engine() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let spec = read("spec/universal-conference-api.md");
    assert!(proto.contains("UNIVERSAL_CONFERENCE_MODE_MEETING"));
    assert!(proto.contains("UNIVERSAL_CONFERENCE_MODE_WEBINAR"));
    assert!(proto.contains("UNIVERSAL_CONFERENCE_MODE_BROADCAST"));
    assert!(proto.contains("UNIVERSAL_CONFERENCE_MODE_AUDIO_ROOM"));
    assert!(spec.contains("configuration, not a separate product"));
    assert!(spec.contains("must never become a second"));
}

#[test]
fn universal_conference_contract_reserves_required_roles_join_and_lifecycle_semantics() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    for required in [
        "CONFERENCE_PARTICIPANT_ROLE_OWNER",
        "CONFERENCE_PARTICIPANT_ROLE_HOST",
        "CONFERENCE_PARTICIPANT_ROLE_MODERATOR",
        "CONFERENCE_PARTICIPANT_ROLE_SPEAKER",
        "CONFERENCE_PARTICIPANT_ROLE_ATTENDEE",
        "JOIN_GRANT_USE_POLICY_SINGLE_USE",
        "JOIN_GRANT_USE_POLICY_REUSABLE",
        "UNIVERSAL_CONFERENCE_LIFECYCLE_SCHEDULED",
        "UNIVERSAL_CONFERENCE_LIFECYCLE_WAITING",
        "UNIVERSAL_CONFERENCE_LIFECYCLE_LIVE",
        "UNIVERSAL_CONFERENCE_LIFECYCLE_ENDING",
        "UNIVERSAL_CONFERENCE_LIFECYCLE_ENDED",
    ] {
        assert!(proto.contains(required), "missing {required}");
    }
}

#[test]
fn universal_conference_management_is_integration_scoped() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    assert!(proto.contains("rpc GetConference"));
    for message in [
        "UniversalGetConferenceRequest",
        "UniversalConferenceLifecycleRequest",
        "UniversalSetEntryOpenRequest",
        "UniversalUpdateParticipantRequest",
        "UniversalRemoveParticipantRequest",
        "UniversalListParticipantsRequest",
        "UniversalRevokeJoinGrantRequest",
        "UniversalGetParticipantAttendanceRequest",
    ] {
        let start = format!("message {message} {{");
        let block = proto
            .split_once(&start)
            .unwrap_or_else(|| panic!("missing {message}"))
            .1
            .split_once('}')
            .unwrap_or_else(|| panic!("unterminated {message}"))
            .0;
        assert!(
            block.contains("integration_id"),
            "{message} must remain integration-scoped"
        );
    }
}

#[test]
fn universal_conference_attendance_is_external_reference_projection() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let spec = read("spec/universal-conference-api.md");
    assert!(proto.contains("rpc GetParticipantAttendance"));
    assert!(proto.contains("first_join_at_unix_ms"));
    assert!(proto.contains("last_leave_at_unix_ms"));
    assert!(proto.contains("total_connected_seconds"));
    assert!(proto.contains("current_connected_seconds"));
    assert!(proto.contains("external_user_id"));
    assert!(spec.contains("projection over the canonical Event journal"));
}

#[test]
fn universal_conference_credentials_are_bound_to_integration_identity() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    assert!(service.contains("fn admit_integration("));
    assert!(service.contains("actor.principal.kind != PrincipalKind::ServiceAccount"));
    assert!(
        service.contains("actor.principal.principal_id.as_opaque() != integration_id.as_opaque()")
    );
    assert!(service.contains("CanonicalErrorCode::PermissionDenied"));
}
