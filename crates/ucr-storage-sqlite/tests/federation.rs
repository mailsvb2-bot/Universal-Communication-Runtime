use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ucr_core::{DurableRecordStatus, FederationPeerStore, StorageProvider};
use ucr_model::{
    DeviceId, EndpointId, EndpointKind, FederationPeerRecord, FederationTrustState, KeyId,
    OpaqueId, TenantId, TenantScope,
};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope(tenant: &str) -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid(tenant)),
        namespace_id: None,
    }
}

fn peer() -> FederationPeerRecord {
    FederationPeerRecord {
        local_scope: scope("sqlite-fed-local"),
        remote_scope: scope("sqlite-fed-remote"),
        local_endpoint_id: EndpointId::from_opaque(oid("sqlite-local-node")),
        remote_endpoint_id: EndpointId::from_opaque(oid("sqlite-remote-node")),
        remote_endpoint_kind: EndpointKind::PersonalNode,
        expected_device_id: DeviceId::from_opaque(oid("sqlite-remote-device")),
        expected_signing_key_id: KeyId::from_opaque(oid("sqlite-remote-key")),
        allowed_capabilities: vec!["ucr.sync".to_owned(), "ucr.message.text".to_owned()],
        state: FederationTrustState::Known,
        generation: 1,
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
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let _ = fs::remove_file(PathBuf::from(wal));
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    let _ = fs::remove_file(PathBuf::from(shm));
}

#[test]
fn federation_trust_lifecycle_and_rotation_survive_restart() {
    let path = db_path("federation-restart");
    let mut current = ucr_protocol::canonical_federation_peer(&peer()).expect("canonical peer");
    {
        let store = SqliteLocalStore::open(&path).expect("open store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            store.install_federation_peer(&current).expect("install"),
            DurableRecordStatus::Persisted
        );
        for next in [
            FederationTrustState::Authenticated,
            FederationTrustState::Authorized,
            FederationTrustState::Trusted,
        ] {
            store
                .transition_federation_peer(
                    &current.local_scope,
                    &current.remote_scope,
                    &current.remote_endpoint_id,
                    current.generation,
                    next,
                )
                .expect("transition");
            current.state = next;
            current.generation += 1;
        }
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen trusted");
        let loaded = store
            .federation_peer(
                &current.local_scope,
                &current.remote_scope,
                &current.remote_endpoint_id,
            )
            .expect("load")
            .expect("peer");
        assert_eq!(loaded, current);
        store
            .transition_federation_peer(
                &current.local_scope,
                &current.remote_scope,
                &current.remote_endpoint_id,
                current.generation,
                FederationTrustState::Blocked,
            )
            .expect("block");
        current.state = FederationTrustState::Blocked;
        current.generation += 1;
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen blocked");
        let blocked = store
            .federation_peer(
                &current.local_scope,
                &current.remote_scope,
                &current.remote_endpoint_id,
            )
            .expect("load blocked")
            .expect("blocked peer");
        assert_eq!(blocked, current);
        let mut replacement = blocked.clone();
        replacement.expected_device_id = DeviceId::from_opaque(oid("sqlite-rotated-device"));
        replacement.expected_signing_key_id = KeyId::from_opaque(oid("sqlite-rotated-key"));
        replacement.state = FederationTrustState::Known;
        replacement.generation += 1;
        assert_eq!(
            store
                .rotate_federation_peer_credential(&blocked, &replacement)
                .expect("rotate"),
            DurableRecordStatus::Persisted
        );
        current = replacement;
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen rotated");
        let loaded = store
            .federation_peer(
                &current.local_scope,
                &current.remote_scope,
                &current.remote_endpoint_id,
            )
            .expect("load rotated")
            .expect("rotated peer");
        assert_eq!(loaded, current);
    }
    cleanup(&path);
}
#[test]
fn v28_migration_adds_empty_federation_state_without_inference() {
    let path = db_path("federation-migration");
    {
        let store = SqliteLocalStore::open(&path).expect("initialize current store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    }
    {
        let connection = rusqlite::Connection::open(&path).expect("open raw sqlite");
        connection
            .execute_batch(
                "DROP TABLE IF EXISTS endpoint_mls_key_package_offers;\n                 DROP TABLE IF EXISTS first_party_recovery_credentials;
                 DROP INDEX IF EXISTS group_mls_transition_admissions_device;
                 DROP TABLE IF EXISTS group_mls_transition_admissions;
                 DROP INDEX IF EXISTS recording_provider_ready_recovery;
                 DROP INDEX IF EXISTS recording_provider_operations_due;
                 DROP TABLE IF EXISTS recording_provider_operations;
                 DROP TABLE IF EXISTS universal_conference_metadata;
                 DROP TABLE IF EXISTS attachment_chunks;
                 DROP TABLE IF EXISTS attachments;
                 DROP TRIGGER IF EXISTS service_audit_authentication_no_update;
                 DROP TRIGGER IF EXISTS service_audit_authentication_no_delete;
                 DROP TABLE IF EXISTS service_audit_authentication;
                 DROP TABLE IF EXISTS runtime_worker_leases;
                 DROP TABLE IF EXISTS service_recording_usage;
                 DROP TABLE IF EXISTS service_resource_quota_policies;
                 DROP TABLE IF EXISTS service_rate_limit_usage;
                 DROP TABLE IF EXISTS service_rate_limit_policies;
                 DROP TRIGGER IF EXISTS authz_rev_calls_ins; DROP TRIGGER IF EXISTS authz_rev_calls_upd; DROP TRIGGER IF EXISTS authz_rev_calls_del; DROP TRIGGER IF EXISTS authz_rev_call_participants_ins; DROP TRIGGER IF EXISTS authz_rev_call_participants_upd; DROP TRIGGER IF EXISTS authz_rev_call_participants_del; DROP TRIGGER IF EXISTS authz_rev_call_permission_grants_ins; DROP TRIGGER IF EXISTS authz_rev_call_permission_grants_upd; DROP TRIGGER IF EXISTS authz_rev_call_permission_grants_del; DROP TRIGGER IF EXISTS authz_rev_permission_grants_ins; DROP TRIGGER IF EXISTS authz_rev_permission_grants_upd; DROP TRIGGER IF EXISTS authz_rev_permission_grants_del; DROP TRIGGER IF EXISTS authz_rev_groups_ins; DROP TRIGGER IF EXISTS authz_rev_groups_upd; DROP TRIGGER IF EXISTS authz_rev_groups_del; DROP TRIGGER IF EXISTS authz_rev_group_memberships_ins; DROP TRIGGER IF EXISTS authz_rev_group_memberships_upd; DROP TRIGGER IF EXISTS authz_rev_group_memberships_del; DROP TRIGGER IF EXISTS authz_rev_group_mls_transitions_ins; DROP TRIGGER IF EXISTS authz_rev_group_mls_transitions_upd; DROP TRIGGER IF EXISTS authz_rev_group_mls_transitions_del; DROP TRIGGER IF EXISTS authz_rev_group_mls_transition_admissions_ins; DROP TRIGGER IF EXISTS authz_rev_group_mls_transition_admissions_upd; DROP TRIGGER IF EXISTS authz_rev_group_mls_transition_admissions_del; DROP TRIGGER IF EXISTS authz_rev_server_mls_custody_quarantine_ins; DROP TRIGGER IF EXISTS authz_rev_server_mls_custody_quarantine_upd; DROP TRIGGER IF EXISTS authz_rev_server_mls_custody_quarantine_del; DROP TRIGGER IF EXISTS authz_rev_devices_ins; DROP TRIGGER IF EXISTS authz_rev_devices_upd; DROP TRIGGER IF EXISTS authz_rev_devices_del; DROP TRIGGER IF EXISTS authz_rev_trusted_signing_keys_ins; DROP TRIGGER IF EXISTS authz_rev_trusted_signing_keys_upd; DROP TRIGGER IF EXISTS authz_rev_trusted_signing_keys_del; DROP TRIGGER IF EXISTS authz_rev_principal_identity_bindings_ins; DROP TRIGGER IF EXISTS authz_rev_principal_identity_bindings_upd; DROP TRIGGER IF EXISTS authz_rev_principal_identity_bindings_del; DROP TRIGGER IF EXISTS authz_rev_identities_ins; DROP TRIGGER IF EXISTS authz_rev_identities_upd; DROP TRIGGER IF EXISTS authz_rev_identities_del; DROP TRIGGER IF EXISTS authz_rev_external_identity_bindings_ins; DROP TRIGGER IF EXISTS authz_rev_external_identity_bindings_upd; DROP TRIGGER IF EXISTS authz_rev_external_identity_bindings_del; DROP TRIGGER IF EXISTS authz_rev_organization_managed_devices_ins; DROP TRIGGER IF EXISTS authz_rev_organization_managed_devices_upd; DROP TRIGGER IF EXISTS authz_rev_organization_managed_devices_del; DROP TRIGGER IF EXISTS authz_rev_organization_managed_identities_ins; DROP TRIGGER IF EXISTS authz_rev_organization_managed_identities_upd; DROP TRIGGER IF EXISTS authz_rev_organization_managed_identities_del; DROP TRIGGER IF EXISTS authz_rev_organization_mode_profiles_ins; DROP TRIGGER IF EXISTS authz_rev_organization_mode_profiles_upd; DROP TRIGGER IF EXISTS authz_rev_organization_mode_profiles_del; DROP TRIGGER IF EXISTS authz_rev_service_credentials_ins; DROP TRIGGER IF EXISTS authz_rev_service_credentials_upd; DROP TRIGGER IF EXISTS authz_rev_service_credentials_del; DROP TABLE IF EXISTS authorization_revision;
                 DROP TABLE IF EXISTS first_party_sessions;
                 DROP TABLE IF EXISTS first_party_signup_admissions;
                 DROP TRIGGER IF EXISTS call_permission_grants_revoke_on_terminate;
                 DROP TRIGGER IF EXISTS call_permission_grants_revoke_on_leave;
                 DROP TABLE IF EXISTS call_permission_grants;
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
                 DROP TABLE federation_peer_capabilities;
                 DROP TABLE federation_peers;
                 PRAGMA user_version=28;",
            )
            .expect("restore v28 shape");
    }
    {
        let store = SqliteLocalStore::open(&path).expect("migrate v28 to v29");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let candidate = peer();
        assert!(
            store
                .federation_peer(
                    &candidate.local_scope,
                    &candidate.remote_scope,
                    &candidate.remote_endpoint_id,
                )
                .expect("read migrated federation state")
                .is_none()
        );
    }
    cleanup(&path);
}
