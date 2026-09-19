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
        "UniversalEnsureParticipantDeviceRequest",
        "UniversalPrepareConferenceRuntimeRequest",
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

#[test]
fn universal_conference_capability_discovery_is_explicit_and_truthful() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let spec = read("spec/universal-conference-api.md");
    assert!(proto.contains("rpc GetCapabilities"));
    for field in [
        "browser_realtime_gateway",
        "production_webrtc",
        "turn",
        "recording",
        "horizontal_sfu",
    ] {
        assert!(
            proto.contains(field),
            "missing capability readiness field {field}"
        );
    }
    assert!(service.contains("browser_realtime_gateway: false"));
    assert!(service.contains("production_webrtc: false"));
    assert!(service.contains("turn: false"));
    assert!(service.contains("recording: false"));
    assert!(service.contains("horizontal_sfu: false"));
    assert!(spec.contains("must not claim production readiness"));
}

#[test]
fn universal_participant_device_enrollment_hides_canonical_device_id() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    assert!(proto.contains("rpc EnsureParticipantDevice"));
    let block = proto
        .split_once("message UniversalParticipantDeviceStatus {")
        .expect("device status")
        .1
        .split_once('}')
        .expect("device status close")
        .0;
    assert!(!block.contains("device_id"));
    assert!(block.contains("external_user_id"));
    assert!(service.contains("DEVICE_REGISTER_PERMISSION"));
    assert!(service.contains("register_device("));
}

#[test]
fn realtime_join_accepts_invited_participant_through_canonical_call_signal() {
    let universal = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    assert!(universal.contains("CallParticipantState::Invited"));
    assert!(universal.contains("CallParticipantState::Ringing"));
    assert!(realtime.contains("ensure_accepted_conference_participant_for_join"));
    assert!(realtime.contains("kind: CallSignalKind::Accept"));
    assert!(realtime.contains("self.store.apply_call_signal(&actor, &signal)"));
}

#[test]
fn universal_runtime_preparation_reuses_canonical_mls_group_and_call_owners() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let spec = read("spec/universal-conference-api.md");
    assert!(proto.contains("rpc PrepareConferenceRuntime"));
    assert!(service.contains("GroupMlsAtomicStore"));
    assert!(service.contains("create_mls_backed_group("));
    assert!(service.contains("apply_mls_backed_group_change("));
    assert!(service.contains("store.create_call(owner, &call)"));
    assert!(service.contains("store.apply_call_signal(owner, &signal)"));
    assert!(spec.contains("does not create a second Group, MLS, or Call owner"));
}

#[test]
fn universal_participant_policy_syncs_minimum_canonical_permissions() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    for required in [
        "CALL_OBSERVE_PERMISSION",
        "CONFERENCE_SUBSCRIBE_PERMISSION",
        "AUDIO_RECEIVE_PERMISSION",
        "VIDEO_RECEIVE_PERMISSION",
        "AUDIO_SEND_PERMISSION",
        "VIDEO_SEND_PERMISSION",
        "sync_participant_permissions",
    ] {
        assert!(service.contains(required), "missing participant permission policy {required}");
    }
    assert!(service.contains("store.revoke_permission(&grant)"));
}

#[test]
fn participant_remove_reconciles_call_and_mls_membership_and_protects_owner() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    assert!(service.contains("current.role == ConferenceParticipantRole::Owner"));
    assert!(service.contains("reconcile_removed_participant"));
    assert!(service.contains("CallParticipantUpdateKind::Remove"));
    assert!(service.contains("GroupChangeKind::RemoveMember"));
    assert!(service.contains("apply_mls_backed_group_change"));
}

#[test]
fn runtime_reconcile_projects_role_changes_into_group_crypto_epoch() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    assert!(service.contains("membership.role != desired_role"));
    assert!(service.contains("GroupChangeKind::ChangeRole"));
    assert!(service.contains("runtime_event_id("));
}
