use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ucr_core::{DurableRecordStatus, StorageProvider, UniversalConferenceStore};
use ucr_model::{
    ConferenceParticipantRole, ConferenceScheduleMetadata, GroupId, IntegrationId, OpaqueId,
    PrincipalId, PrincipalKind, PrincipalRef, TenantId, TenantScope, UniversalConferenceLifecycle,
    UniversalConferenceMode, UniversalConferenceParticipantProfile, UniversalConferenceProfile,
};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("universal-conference-tenant")),
        namespace_id: None,
    }
}

fn conference() -> UniversalConferenceProfile {
    UniversalConferenceProfile {
        scope: scope(),
        conference_id: GroupId::from_opaque(oid("conference-1")),
        integration_id: IntegrationId::from_opaque(oid("integration-1")),
        external_conference_id: b"external-event-42".to_vec(),
        create_idempotency_key: "create-event-42".to_owned(),
        mode: UniversalConferenceMode::Webinar,
        lifecycle: UniversalConferenceLifecycle::Scheduled,
        schedule: ConferenceScheduleMetadata {
            starts_at_unix_ms: 2_000_000,
            planned_end_unix_ms: Some(5_600_000),
            join_before_seconds: 900,
            join_after_seconds: 300,
            timezone: Some("Europe/Amsterdam".to_owned()),
        },
        entry_open: false,
        revision: 1,
    }
}

fn participant() -> UniversalConferenceParticipantProfile {
    UniversalConferenceParticipantProfile {
        scope: scope(),
        conference_id: conference().conference_id,
        integration_id: conference().integration_id,
        external_user_id: b"external-user-7".to_vec(),
        participant: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("participant-7")),
            kind: PrincipalKind::Person,
        },
        role: ConferenceParticipantRole::Speaker,
        audio_muted: false,
        camera_allowed: true,
        publish_audio_allowed: true,
        publish_video_allowed: true,
        active: true,
        revision: 1,
    }
}

fn db_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("ucr-{label}-{}-{nonce}.sqlite", std::process::id()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = fs::remove_file(PathBuf::from(sidecar));
    }
}

#[test]
fn scheduled_conference_and_participant_policy_survive_restart() {
    let path = db_path("universal-conference-restart");
    {
        let store = SqliteLocalStore::open(&path).expect("open");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            store
                .persist_universal_conference_profile(&conference())
                .expect("conference"),
            DurableRecordStatus::Persisted
        );
        assert_eq!(
            store
                .persist_universal_conference_participant(&participant())
                .expect("participant"),
            DurableRecordStatus::Persisted
        );
        let live = store
            .transition_universal_conference(
                &scope(),
                &conference().conference_id,
                1,
                UniversalConferenceLifecycle::Waiting,
                true,
            )
            .expect("waiting");
        assert_eq!(live.revision, 2);
        assert!(live.entry_open);
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen");
        let loaded = store
            .universal_conference_profile_for_external(
                &scope(),
                &conference().integration_id,
                &conference().external_conference_id,
            )
            .expect("lookup")
            .expect("conference");
        assert_eq!(loaded.lifecycle, UniversalConferenceLifecycle::Waiting);
        assert_eq!(loaded.revision, 2);
        let participants = store
            .universal_conference_participants(&scope(), &conference().conference_id, 16)
            .expect("participants");
        assert_eq!(participants, vec![participant()]);
        let external = store
            .universal_conference_participant_for_external(
                &scope(),
                &conference().conference_id,
                &conference().integration_id,
                b"external-user-7",
            )
            .expect("external participant lookup")
            .expect("external participant");
        assert_eq!(external, participant());
    }
    cleanup(&path);
}

#[test]
fn create_idempotency_key_conflicts_when_semantics_change() {
    let path = db_path("universal-conference-idempotency");
    let store = SqliteLocalStore::open(&path).expect("open");
    assert_eq!(
        store.persist_universal_conference_profile(&conference()),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_universal_conference_profile(&conference()),
        Ok(DurableRecordStatus::Duplicate)
    );

    let mut changed = conference();
    changed.conference_id = GroupId::from_opaque(oid("conference-2"));
    changed.external_conference_id = b"different-event".to_vec();
    assert!(
        store
            .persist_universal_conference_profile(&changed)
            .is_err()
    );
    cleanup(&path);
}

#[test]
fn external_participant_reference_is_unique_within_integration_conference() {
    let path = db_path("universal-conference-external-participant");
    let store = SqliteLocalStore::open(&path).expect("open");
    store
        .persist_universal_conference_profile(&conference())
        .expect("conference");
    store
        .persist_universal_conference_participant(&participant())
        .expect("participant");

    let mut duplicate_external = participant();
    duplicate_external.participant = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("participant-8")),
        kind: PrincipalKind::Person,
    };
    assert_eq!(
        store.persist_universal_conference_participant(&duplicate_external),
        Err(ucr_core::DurableStoreError::Conflict)
    );

    cleanup(&path);
}
