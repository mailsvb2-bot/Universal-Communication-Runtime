use std::{fs, path::Path};

#[test]
fn integration_attendance_webhook_is_an_atomic_projection_not_an_owner_bypass() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/universal_conference.proto"))
        .expect("read Universal Conference proto");
    assert!(proto.contains("message UniversalConferenceAttendanceEvent"));
    assert!(proto.contains("bytes external_conference_id = 4;"));
    assert!(proto.contains("bytes external_user_id = 5;"));
    assert!(
        !proto
            .split("message UniversalConferenceAttendanceEvent")
            .nth(1)
            .and_then(|value| value
                .split("message UniversalGetCapabilitiesRequest")
                .next())
            .expect("attendance projection message")
            .contains("PrincipalRef"),
        "integration attendance payload must not expose canonical participant principals"
    );

    let realtime =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/realtime_service.rs"))
            .expect("read realtime service");
    assert!(realtime.contains("ucr.conference.attendance.integration.v1"));
    assert!(realtime.contains("append_events_atomically(&[event, integration_event])"));
    assert!(realtime.contains("on_behalf_of: Some(PrincipalId::from_opaque("));
    for participant_type in [
        "ucr.conference.attendance.joined.v1",
        "ucr.conference.attendance.left.v1",
        "ucr.conference.attendance.reconnected.v1",
        "ucr.conference.attendance.media_ready.v1",
    ] {
        assert!(
            realtime.contains(participant_type),
            "canonical participant attendance Event {participant_type} must remain present"
        );
    }

    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs"))
        .expect("read Event journal contract");
    assert!(core.contains("fn append_events_atomically("));
    assert!(core.contains("MAX_ATOMIC_EVENT_BATCH"));

    let event_spec =
        fs::read_to_string(workspace.join("spec/event-api.md")).expect("read Event API spec");
    assert!(event_spec.contains("ucr.conference.attendance.integration.v1"));
    assert!(event_spec.contains("Service Account owner filter"));
    assert!(event_spec.contains("participant-owned canonical attendance Event"));
    assert!(event_spec.contains("on_behalf_of"));
    assert!(event_spec.contains("granting a Service Account read access"));
}
