use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ucr_core::{DurableRecordStatus, OrganizationModeStore, StorageProvider};
use ucr_model::{
    DeviceId, EndpointId, EndpointKind, IdentityId, NamespaceId, OpaqueId,
    OrganizationManagedDeviceBinding, OrganizationManagedIdentityBinding, OrganizationModeProfile,
    OrganizationModeState, OrganizationService, PrincipalId, PrincipalKind, PrincipalRef, TenantId,
    TenantScope,
};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("organization-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("organization-private"))),
    }
}
fn organization() -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("organization-owner")),
        kind: PrincipalKind::Organization,
    }
}

fn profile() -> OrganizationModeProfile {
    OrganizationModeProfile {
        scope: scope(),
        organization: organization(),
        endpoint_id: EndpointId::from_opaque(oid("organization-node")),
        endpoint_kind: EndpointKind::OrganizationNode,
        services: vec![
            OrganizationService::PrivateDiscovery,
            OrganizationService::PrivateRelay,
            OrganizationService::PrivateSfu,
            OrganizationService::PrivateBridge,
            OrganizationService::ManagedIdentities,
            OrganizationService::ManagedDevices,
        ],
        state: OrganizationModeState::Active,
        generation: 1,
    }
}
fn identity_binding() -> OrganizationManagedIdentityBinding {
    OrganizationManagedIdentityBinding {
        scope: scope(),
        organization: organization(),
        identity_id: IdentityId::from_opaque(oid("organization-managed-identity")),
    }
}

fn device_binding() -> OrganizationManagedDeviceBinding {
    OrganizationManagedDeviceBinding {
        scope: scope(),
        organization: organization(),
        device_id: DeviceId::from_opaque(oid("organization-managed-device")),
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
fn profile_bindings_and_disable_survive_restart() {
    let path = db_path("organization-mode-restart");
    {
        let store = SqliteLocalStore::open(&path).expect("open");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            store
                .install_organization_mode_profile(&profile())
                .expect("profile"),
            DurableRecordStatus::Persisted
        );
        assert_eq!(
            store
                .bind_organization_managed_identity(&identity_binding())
                .expect("identity"),
            DurableRecordStatus::Persisted
        );
        assert_eq!(
            store
                .bind_organization_managed_device(&device_binding())
                .expect("device"),
            DurableRecordStatus::Persisted
        );
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen");
        assert_eq!(
            store
                .organization_managed_identities(&scope(), &organization(), 16)
                .expect("ids"),
            vec![identity_binding()]
        );
        assert_eq!(
            store
                .organization_managed_devices(&scope(), &organization(), 16)
                .expect("devices"),
            vec![device_binding()]
        );
        assert_eq!(
            store
                .transition_organization_mode_profile(
                    &scope(),
                    &organization(),
                    1,
                    OrganizationModeState::Disabled,
                )
                .expect("disable"),
            DurableRecordStatus::Persisted
        );
    }
    {
        let store = SqliteLocalStore::open(&path).expect("reopen disabled");
        let loaded = store
            .organization_mode_profile(&scope(), &organization())
            .expect("profile")
            .expect("profile exists");
        assert_eq!(loaded.state, OrganizationModeState::Disabled);
        assert_eq!(loaded.generation, 2);
        assert_eq!(
            store
                .organization_managed_identity_binding(&scope(), &identity_binding().identity_id)
                .expect("identity"),
            Some(identity_binding())
        );
        assert_eq!(
            store
                .organization_managed_device_binding(&scope(), &device_binding().device_id)
                .expect("device"),
            Some(device_binding())
        );
    }
    cleanup(&path);
}
#[test]
fn v30_migration_adds_empty_organization_state_without_inference() {
    let path = db_path("organization-mode-migration");
    {
        let store = SqliteLocalStore::open(&path).expect("initialize current store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    }
    {
        let connection = rusqlite::Connection::open(&path).expect("open raw sqlite");
        connection
            .execute_batch(
                "DROP TABLE IF EXISTS endpoint_mls_key_package_offers;
                 DROP TABLE IF EXISTS first_party_recovery_credentials;
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
                 PRAGMA user_version=30;",
            )
            .expect("restore v30 shape");
    }
    {
        let store = SqliteLocalStore::open(&path).expect("migrate v30 to v31");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert!(
            store
                .organization_mode_profile(&scope(), &organization())
                .expect("read migrated organization state")
                .is_none()
        );
    }
    cleanup(&path);
}
