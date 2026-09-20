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
    assert!(service.contains("apply_call_signal(owner, &signal)"));
    assert!(spec.contains("does not create a second Group, MLS, or Call owner"));
}

#[test]
fn universal_conference_owner_is_unique_and_not_transferred_by_generic_participant_mutations() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let spec = read("spec/universal-conference-api.md");
    assert!(service.contains("enforce_owner_role_transition"));
    assert!(service.contains("profile.role != requested_role"));
    assert!(service.contains("requested_role == ConferenceParticipantRole::Owner"));
    assert!(service.contains("owner.external_user_id.as_slice() == external_user_id"));
    let sqlite = read("crates/ucr-storage-sqlite/src/universal_conference_store.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    assert!(sqlite.contains("ensure_unique_active_owner"));
    assert!(memory.contains("has_conflicting_active_conference_owner"));
    assert!(
        spec.contains("Ordinary participant ensure/update operations never transfer ownership")
    );
    assert!(spec.contains("enforced atomically by every canonical `UniversalConferenceStore`"));
}

#[test]
fn universal_conference_live_capacity_uses_active_storage_projection() {
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/universal_conference_store.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let core = read("crates/ucr-core/src/universal_conference.rs");
    let spec = read("spec/universal-conference-api.md");

    assert!(
        service.contains("MAX_ACTIVE_PARTICIPANT_SCAN_ITEMS: usize = MAX_CALL_PARTICIPANTS + 1")
    );
    assert!(service.contains("active_universal_conference_participants"));
    assert!(service.contains("participants.len() > MAX_CALL_PARTICIPANTS"));
    assert!(sqlite.contains("ensure_participant_capacity"));
    assert!(sqlite.contains("AND conference_id = ?4 AND active = 1"));
    assert!(memory.contains("active_participant_count"));
    assert!(core.contains("fn active_universal_conference_participants"));
    assert!(spec.contains("1024 active participants"));
    assert!(spec.contains("Inactive historical participant projections"));
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
        assert!(
            service.contains(required),
            "missing participant permission policy {required}"
        );
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

#[test]
fn universal_conference_current_call_flows_do_not_depend_on_bounded_call_history() {
    let core = read("crates/ucr-core/src/call.rs");
    let memory = read("crates/ucr-storage-memory/src/call_store.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/call_store.rs");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");

    assert!(core.contains("fn active_calls_for_group"));
    assert!(core.contains("fn call_belongs_to_group"));
    assert!(memory.contains("call.signalling_state != CallSignallingState::Terminated"));
    assert!(sqlite.contains("AND signalling_state<>?6"));
    assert!(service.contains(".active_calls_for_group(&input.scope, &input.conference_id, 2)"));
    assert!(service.contains(".active_calls_for_group(scope, conference_id, 2)"));
    assert!(service.contains(".call_belongs_to_group(scope, conference_id, &record.call_id)"));
    assert!(
        service.contains("active_call_projection_ignores_more_than_sixty_four_terminated_calls")
    );
}

#[test]
fn universal_conference_current_device_flows_do_not_depend_on_bounded_device_history() {
    let core = read("crates/ucr-core/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/device_store.rs");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");

    assert!(core.contains("fn active_devices_for_identity"));
    assert!(memory.contains("descriptor.state == DeviceLifecycleState::Active"));
    assert!(sqlite.contains("AND identity_id=?4 AND state='active'"));
    assert!(
        service.contains(".active_devices_for_identity(&input.scope, &binding.identity_id, 2)")
    );
    assert!(service.contains(".active_devices_for_identity(scope, &binding.identity_id, 2)"));
    assert!(
        service.contains(".active_devices_for_identity(scope, &identity_binding.identity_id, 2)")
    );
    assert!(service.contains("active_device_projection_ignores_sixty_four_revoked_devices"));
}

#[test]
fn universal_conference_person_resolution_filters_unrelated_principal_history() {
    let core = read("crates/ucr-core/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/principal_identity_binding_store.rs");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");

    assert!(core.contains("fn principal_identity_bindings_for_identity_kind"));
    assert!(memory.contains("binding.principal.kind == kind"));
    assert!(sqlite.contains("AND identity_id=?4 AND principal_kind=?5"));
    assert!(service.contains("principal_identity_bindings_for_identity_kind("));
    assert!(service.contains("PrincipalKind::Person"));
    assert!(service.contains("person_principal_resolution_ignores_unrelated_principal_history"));
}

#[test]
fn universal_conference_attendance_filters_principal_before_history_bound() {
    let core = read("crates/ucr-core/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/event_journal.rs");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");

    assert!(core.contains("fn events_for_types_by_principal"));
    assert!(memory.contains("event_is_attributed_to_principal"));
    assert!(sqlite.contains("AND {actor_predicate}"));
    assert!(service.contains(".events_for_types_by_principal("));
    assert!(service.contains("&participant.participant"));
}

#[test]
fn realtime_browser_gateway_enforces_exact_origin_policy() {
    let gateway = read("crates/ucr-realtime-web/src/main.rs");

    assert!(gateway.contains("UCR_REALTIME_ALLOWED_ORIGINS"));
    assert!(gateway.contains("request_origin("));
    assert!(gateway.contains("origin_denied"));
    assert!(gateway.contains("ACCESS_CONTROL_ALLOW_ORIGIN"));
    assert!(gateway.contains("candidate == \"*\""));
    assert!(gateway.contains("origin == format!(\"https://{host}\")"));
    assert!(gateway.contains("origin == format!(\"http://{host}\")"));
}

#[test]
fn realtime_browser_waiting_room_uses_join_grant_window() {
    let client = read("crates/ucr-realtime-web/static/client.html");

    assert!(client.contains("scheduleWaitingRoom"));
    assert!(client.contains("claims.not_before-Date.now()"));
    assert!(client.contains("The conference has not started yet"));
    assert!(
        client.contains("setTimeout(()=>{waitTimer=null;ui.join.disabled=false;join();},delay)")
    );
    assert!(!client.contains("Join grant is not active yet"));
}

#[test]
fn waiting_room_separates_grant_issuance_from_attendee_admission() {
    let universal = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let gateway = read("crates/ucr-realtime-web/src/main.rs");
    let client = read("crates/ucr-realtime-web/static/client.html");

    assert!(!universal.contains("|| !conference.entry_open\n        || !matches!("));
    assert!(
        realtime.contains("participant.role == ucr_model::ConferenceParticipantRole::Attendee")
    );
    assert!(realtime.contains("CanonicalErrorCode::PolicyDenied"));
    assert!(realtime.contains(".with_retry_after(2_000)"));
    assert!(gateway.contains("\"waiting_room\""));
    assert!(gateway.contains("StatusCode::TOO_EARLY"));
    assert!(client.contains("scheduleEntryRetry"));
    assert!(client.contains("ENTRY_RETRY_MS=2000"));
    assert!(client.contains("e.code===\"waiting_room\""));
}

#[test]
fn universal_join_grants_are_durable_idempotent_and_restart_safe() {
    let proto = read("proto/ucr/v1/universal_conference.proto");
    let core = read("crates/ucr-core/src/universal_conference.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/conference_join_grant_store.rs");
    let service = read("crates/ucr-api-grpc/src/universal_conference_service.rs");
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let spec = read("spec/universal-conference-api.md");

    assert!(proto.contains("message UniversalIssueJoinGrantRequest"));
    assert!(proto.contains("string idempotency_key = 9;"));
    assert!(proto.contains(
        "message UniversalRevokeJoinGrantRequest {\n  TenantScope scope = 1;\n  OpaqueId conference_id = 2;\n  OpaqueId session_id = 3;\n  OpaqueId integration_id = 4;\n  string idempotency_key = 5;\n}"
    ));
    assert!(!proto.contains(
        "message UniversalListParticipantsRequest {\n  TenantScope scope = 1;\n  OpaqueId conference_id = 2;\n  uint32 max_items = 3;\n  OpaqueId integration_id = 4;\n  string idempotency_key = 5;"
    ));
    assert!(core.contains("pub trait ConferenceJoinGrantStore"));
    assert!(sqlite.contains("CREATE TABLE conference_join_grants"));
    assert!(service.contains("ucr.conference.join.issue.v1"));
    assert!(service.contains("ucr.conference.join.revoke.v1"));
    assert!(service.contains("SessionId::from_opaque(stable_command_id.as_opaque().clone())"));
    assert!(realtime.contains(".conference_join_grant(scope, session_id)"));
    assert!(realtime.contains(".redeem_conference_join_grant(scope, session_id)"));
    assert!(spec.contains("process restart does not reactivate a revoked grant"));
}
