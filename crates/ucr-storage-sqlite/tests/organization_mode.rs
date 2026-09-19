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
                "DROP TABLE recording_consents;
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
