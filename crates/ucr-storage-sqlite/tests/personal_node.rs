use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use ucr_core::{DurableRecordStatus, DurableStoreError, PersonalNodeStore, StorageProvider};
use ucr_model::{
    EndpointId, EndpointKind, OpaqueId, PersonalNodeObject, PersonalNodeObjectId,
    PersonalNodeObjectKind, PersonalNodeProfile, PersonalNodeService, PersonalNodeState, TenantId,
    TenantScope,
};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("personal-node-tenant")),
        namespace_id: None,
    }
}

fn endpoint() -> EndpointId {
    EndpointId::from_opaque(oid("personal-node-endpoint"))
}

fn profile() -> PersonalNodeProfile {
    PersonalNodeProfile {
        scope: scope(),
        endpoint_id: endpoint(),
        endpoint_kind: EndpointKind::PersonalNode,
        services: vec![
            PersonalNodeService::Sync,
            PersonalNodeService::EncryptedMailbox,
            PersonalNodeService::Relay,
            PersonalNodeService::Cache,
            PersonalNodeService::Bridge,
        ],
        state: PersonalNodeState::Active,
        generation: 1,
        mailbox_capacity_bytes: 16,
        cache_capacity_bytes: 16,
    }
}

fn object(id_value: &str, kind: PersonalNodeObjectKind, bytes: &[u8]) -> PersonalNodeObject {
    PersonalNodeObject {
        object_id: PersonalNodeObjectId::from_opaque(oid(id_value)),
        scope: scope(),
        endpoint_id: endpoint(),
        kind,
        encryption_scheme: "ucr.crypto.xchacha20poly1305.v1".to_owned(),
        ciphertext: bytes.to_vec(),
        ciphertext_sha256: Sha256::digest(bytes).into(),
        created_at_unix_ms: 10,
        expires_at_unix_ms: Some(100),
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
fn profile_mailbox_cache_and_disable_survive_restart() {
    let path = db_path("personal-node-restart");
    let mailbox = object("mail-a", PersonalNodeObjectKind::Mailbox, b"cipher-a");
    {
        let store = SqliteLocalStore::open(&path).expect("open");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            store
                .install_personal_node_profile(&profile())
                .expect("install"),
            DurableRecordStatus::Persisted
        );
        assert_eq!(
            store
                .persist_personal_node_object(&mailbox)
                .expect("mailbox"),
            DurableRecordStatus::Persisted
        );
        let too_large = object(
            "mail-b",
            PersonalNodeObjectKind::Mailbox,
            b"0123456789abcdef",
        );
        assert_eq!(
            store.persist_personal_node_object(&too_large),
            Err(DurableStoreError::Full)
        );
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen");
        assert_eq!(
            store
                .personal_node_object(&scope(), &endpoint(), &mailbox.object_id)
                .expect("load"),
            Some(mailbox.clone())
        );
        assert_eq!(
            store
                .transition_personal_node_profile(
                    &scope(),
                    &endpoint(),
                    1,
                    PersonalNodeState::Disabled
                )
                .expect("disable"),
            DurableRecordStatus::Persisted
        );
        let cache = object("cache-a", PersonalNodeObjectKind::Cache, b"cache");
        assert_eq!(
            store.persist_personal_node_object(&cache),
            Err(DurableStoreError::PermissionDenied)
        );
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen disabled");
        let loaded = store
            .personal_node_profile(&scope(), &endpoint())
            .expect("profile")
            .expect("profile exists");
        assert_eq!(loaded.state, PersonalNodeState::Disabled);
        assert_eq!(loaded.generation, 2);
        assert_eq!(
            store
                .remove_personal_node_object(&scope(), &endpoint(), &mailbox.object_id)
                .expect("remove"),
            DurableRecordStatus::Persisted
        );
    }
    cleanup(&path);
}

#[test]
fn v29_migration_adds_empty_personal_node_state_without_inference() {
    let path = db_path("personal-node-migration");
    {
        let store = SqliteLocalStore::open(&path).expect("initialize current store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    }
    {
        let connection = rusqlite::Connection::open(&path).expect("open raw sqlite");
        connection
            .execute_batch(
                "DROP TABLE IF EXISTS service_recording_usage;
                 DROP TABLE IF EXISTS service_resource_quota_policies;
                 DROP TABLE IF EXISTS service_rate_limit_usage;
                 DROP TABLE IF EXISTS service_rate_limit_policies;
                 DROP TABLE IF EXISTS event_subscription_owners;\n                 DROP INDEX IF EXISTS conference_join_grants_conference;
                 DROP TABLE IF EXISTS conference_join_grants;
                 DROP TABLE recording_consents;
                 DROP TABLE recordings;
                 DROP TABLE universal_conference_participants;
                 DROP TABLE universal_conferences;
                 DROP TABLE organization_managed_devices;
                 DROP TABLE organization_managed_identities;
                 DROP TABLE organization_mode_profiles;
                 DROP TABLE personal_node_objects;
                 DROP TABLE personal_node_profiles;
                 PRAGMA user_version=29;",
            )
            .expect("restore v29 shape");
    }
    {
        let store = SqliteLocalStore::open(&path).expect("migrate v29 to v30");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert!(
            store
                .personal_node_profile(&scope(), &endpoint())
                .expect("read migrated node state")
                .is_none()
        );
    }
    cleanup(&path);
}
