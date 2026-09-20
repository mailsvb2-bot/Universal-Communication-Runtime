use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use ucr_core::{
    ConferenceJoinGrantStore, DurableRecordStatus, StorageProvider, UniversalConferenceStore,
};
use ucr_model::{
    CallId, ConferenceJoinGrantRecord, ConferenceJoinGrantUsePolicy, ConferenceParticipantRole,
    ConferenceScheduleMetadata, DeviceId, GroupId, IntegrationId, OpaqueId, PrincipalId,
    PrincipalKind, PrincipalRef, SessionId, TenantId, TenantScope, UniversalConferenceLifecycle,
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

fn join_grant() -> ConferenceJoinGrantRecord {
    ConferenceJoinGrantRecord {
        scope: scope(),
        conference_id: conference().conference_id,
        integration_id: conference().integration_id,
        call_id: CallId::from_opaque(oid("call-durable-grant")),
        participant: participant().participant,
        device_id: DeviceId::from_opaque(oid("device-durable-grant")),
        session_id: SessionId::from_opaque(oid("session-durable-grant")),
        issued_at_unix_ms: 1_000,
        not_before_unix_ms: 1_000,
        expires_at_unix_ms: 61_000,
        use_policy: ConferenceJoinGrantUsePolicy::SingleUse,
        revoked: false,
        redeemed: false,
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
fn inactive_history_is_excluded_from_the_active_runtime_roster() {
    let path = db_path("universal-conference-active-roster");
    let store = SqliteLocalStore::open(&path).expect("open");
    store
        .persist_universal_conference_profile(&conference())
        .expect("conference");

    let active = participant();
    store
        .persist_universal_conference_participant(&active)
        .expect("active participant");

    let mut inactive = participant();
    inactive.external_user_id = b"historical-user".to_vec();
    inactive.participant = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("historical-user")),
        kind: PrincipalKind::Person,
    };
    inactive.active = false;
    store
        .persist_universal_conference_participant(&inactive)
        .expect("inactive historical participant");

    let all = store
        .universal_conference_participants(&scope(), &conference().conference_id, 16)
        .expect("all participants");
    assert_eq!(all.len(), 2);
    let active_only = store
        .active_universal_conference_participants(&scope(), &conference().conference_id, 16)
        .expect("active participants");
    assert_eq!(active_only, vec![active]);

    cleanup(&path);
}

#[test]
fn active_owner_is_unique_at_the_atomic_storage_boundary() {
    let path = db_path("universal-conference-owner");
    let store = SqliteLocalStore::open(&path).expect("open");
    store
        .persist_universal_conference_profile(&conference())
        .expect("conference");

    let mut owner = participant();
    owner.external_user_id = b"owner-1".to_vec();
    owner.participant = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("owner-1")),
        kind: PrincipalKind::Person,
    };
    owner.role = ConferenceParticipantRole::Owner;
    assert_eq!(
        store.persist_universal_conference_participant(&owner),
        Ok(DurableRecordStatus::Persisted)
    );

    let mut second_owner = owner.clone();
    second_owner.external_user_id = b"owner-2".to_vec();
    second_owner.participant = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("owner-2")),
        kind: PrincipalKind::Person,
    };
    assert_eq!(
        store.persist_universal_conference_participant(&second_owner),
        Err(ucr_core::DurableStoreError::Conflict)
    );

    let mut attendee = participant();
    attendee.external_user_id = b"attendee-owner-check".to_vec();
    attendee.participant = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("attendee-owner-check")),
        kind: PrincipalKind::Person,
    };
    attendee.role = ConferenceParticipantRole::Attendee;
    store
        .persist_universal_conference_participant(&attendee)
        .expect("attendee");
    assert_eq!(
        store.update_universal_conference_participant(
            &scope(),
            &conference().conference_id,
            &attendee.participant,
            attendee.revision,
            ConferenceParticipantRole::Owner,
            attendee.audio_muted,
            attendee.camera_allowed,
            attendee.publish_audio_allowed,
            attendee.publish_video_allowed,
            true,
        ),
        Err(ucr_core::DurableStoreError::Conflict)
    );

    cleanup(&path);
}

#[test]
fn concurrent_stores_cannot_create_two_active_owners() {
    let path = db_path("universal-conference-owner-race");
    {
        let store = SqliteLocalStore::open(&path).expect("open seed store");
        store
            .persist_universal_conference_profile(&conference())
            .expect("conference");
    }

    let barrier = Arc::new(Barrier::new(2));
    let handles = ["race-owner-1", "race-owner-2"].map(|id| {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let store = SqliteLocalStore::open(&path).expect("open racing store");
            let mut owner = participant();
            owner.external_user_id = id.as_bytes().to_vec();
            owner.participant = PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::Person,
            };
            owner.role = ConferenceParticipantRole::Owner;
            barrier.wait();
            store.persist_universal_conference_participant(&owner)
        })
    });

    let mut outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("owner writer"))
        .collect::<Vec<_>>();
    outcomes.sort_by_key(|outcome| match outcome {
        Ok(DurableRecordStatus::Persisted) => 0,
        Err(ucr_core::DurableStoreError::Conflict) => 1,
        _ => 2,
    });
    assert_eq!(
        outcomes,
        vec![
            Ok(DurableRecordStatus::Persisted),
            Err(ucr_core::DurableStoreError::Conflict),
        ]
    );

    let store = SqliteLocalStore::open(&path).expect("reopen");
    let owners = store
        .universal_conference_participants(&scope(), &conference().conference_id, 16)
        .expect("participants")
        .into_iter()
        .filter(|profile| profile.active && profile.role == ConferenceParticipantRole::Owner)
        .count();
    assert_eq!(owners, 1);
    drop(store);
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

#[test]
fn durable_join_grant_redeem_and_revocation_survive_restart() {
    let path = db_path("universal-conference-join-grant-restart");
    {
        let store = SqliteLocalStore::open(&path).expect("open");
        store
            .persist_universal_conference_profile(&conference())
            .expect("conference");
        assert_eq!(
            store.persist_conference_join_grant(&join_grant()),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_conference_join_grant(&join_grant()),
            Ok(DurableRecordStatus::Duplicate)
        );
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen before redeem");
        let loaded = store
            .conference_join_grant(&scope(), &join_grant().session_id)
            .expect("load grant")
            .expect("grant");
        assert_eq!(loaded, join_grant());
        let redeemed = store
            .redeem_conference_join_grant(&scope(), &join_grant().session_id)
            .expect("redeem");
        assert!(redeemed.redeemed);
        assert!(!redeemed.revoked);
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen after redeem");
        let loaded = store
            .conference_join_grant(&scope(), &join_grant().session_id)
            .expect("load redeemed grant")
            .expect("redeemed grant");
        assert!(loaded.redeemed);
        assert_eq!(
            store.redeem_conference_join_grant(&scope(), &join_grant().session_id),
            Err(ucr_core::DurableStoreError::Conflict)
        );
        let revoked = store
            .revoke_conference_join_grant(&scope(), &join_grant().session_id)
            .expect("revoke");
        assert!(revoked.revoked);
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen after revoke");
        let loaded = store
            .conference_join_grant(&scope(), &join_grant().session_id)
            .expect("load revoked grant")
            .expect("revoked grant");
        assert!(loaded.redeemed);
        assert!(loaded.revoked);
        assert_eq!(
            store.redeem_conference_join_grant(&scope(), &join_grant().session_id),
            Err(ucr_core::DurableStoreError::PermissionDenied)
        );
    }
    cleanup(&path);
}
