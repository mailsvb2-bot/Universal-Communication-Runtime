use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DeviceLifecycleStore, DurableStoreError};
use ucr_model::{
    DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId, OpaqueId, TenantScope,
};
use ucr_protocol::device_allows_protected_access;

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V15_OBJECTS_SQL: &str = "
CREATE TABLE devices (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','stale','reverification_required','expired','revoked')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, device_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v15_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V15_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v15(connection: &Connection) -> Result<(), DurableStoreError> {
    super::service_control_store::verify_schema_v14(connection)?;
    verify_table_columns(
        connection,
        "devices",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("device_id", "TEXT", 1, 4),
            ("identity_id", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
        ],
    )?;
    verify_rows(connection)
}

impl DeviceLifecycleStore for SqliteLocalStore {
    fn register_device(
        &self,
        scope: &TenantScope,
        descriptor: &DeviceDescriptor,
    ) -> Result<(), DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_device(&transaction, scope, &descriptor.device_id)? {
            return if existing == *descriptor {
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_device(&transaction, scope, descriptor)?;
        if !device_allows_protected_access(descriptor) {
            revoke_active_device_key(&transaction, scope, &descriptor.device_id)?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn revoke_device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_identity_id: &IdentityId,
    ) -> Result<(), DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let device =
            load_device(&transaction, scope, device_id)?.ok_or(DurableStoreError::Conflict)?;
        if device.identity_id != *expected_identity_id {
            return Err(DurableStoreError::Conflict);
        }
        if device.state == DeviceLifecycleState::Revoked {
            if active_device_key_count(&transaction, scope, device_id)? != 0 {
                return Err(DurableStoreError::Corrupt);
            }
            return transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error));
        }
        revoke_active_device_key(&transaction, scope, device_id)?;
        let namespace = namespace_storage_key(scope);
        let changed = transaction
            .execute(
                "UPDATE devices SET state='revoked'
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND device_id=?4 AND identity_id=?5 AND state<>'revoked'",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    device_id.as_opaque().as_str(),
                    expected_identity_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Corrupt);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<DeviceDescriptor>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_device(&connection, scope, device_id)
    }
}

pub(super) fn protected_device_allows(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
    identity_id: Option<&IdentityId>,
) -> Result<bool, DurableStoreError> {
    let Some(device) = load_device(connection, scope, device_id)? else {
        return Ok(false);
    };
    Ok(device_allows_protected_access(&device)
        && identity_id.is_none_or(|expected| device.identity_id == *expected))
}

pub(super) fn insert_device(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    descriptor: &DeviceDescriptor,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "INSERT INTO devices (
                tenant_id, namespace_present, namespace_id, device_id, identity_id, state
             ) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                descriptor.device_id.as_opaque().as_str(),
                descriptor.identity_id.as_opaque().as_str(),
                encode_state(descriptor.state),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

pub(super) fn load_device(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<Option<DeviceDescriptor>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT identity_id, state FROM devices
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND device_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                device_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|(identity_id, state)| {
        Ok(DeviceDescriptor {
            device_id: device_id.clone(),
            identity_id: IdentityId::from_opaque(decode_id(&identity_id)?),
            state: decode_state(&state)?,
        })
    })
    .transpose()
}

fn verify_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, device_id, identity_id, state FROM devices")
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (tenant, namespace_present, namespace, device, identity, state) =
            row.map_err(|error| map_sqlite_error(&error))?;
        decode_id(&tenant)?;
        match namespace_present {
            0 if namespace.is_empty() => {}
            1 if !namespace.is_empty() => {
                decode_id(&namespace)?;
            }
            _ => return Err(DurableStoreError::Corrupt),
        }
        decode_id(&device)?;
        decode_id(&identity)?;
        decode_state(&state)?;
    }
    verify_non_active_devices_have_no_active_keys(connection)
}

fn verify_non_active_devices_have_no_active_keys(
    connection: &Connection,
) -> Result<(), DurableStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM devices d
             JOIN trusted_signing_keys k
               ON k.tenant_id=d.tenant_id
              AND k.namespace_present=d.namespace_present
              AND k.namespace_id=d.namespace_id
              AND k.device_id=d.device_id
             WHERE d.state<>'active' AND k.state='active'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if count == 0 {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

fn active_device_key_count(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<i64, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT COUNT(*) FROM trusted_signing_keys
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND device_id=?4 AND state='active'",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                device_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

pub(super) fn revoke_active_device_key(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "UPDATE trusted_signing_keys SET state='revoked'
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND device_id=?4 AND state='active'",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                device_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

const fn encode_state(state: DeviceLifecycleState) -> &'static str {
    match state {
        DeviceLifecycleState::Active => "active",
        DeviceLifecycleState::Stale => "stale",
        DeviceLifecycleState::ReverificationRequired => "reverification_required",
        DeviceLifecycleState::Expired => "expired",
        DeviceLifecycleState::Revoked => "revoked",
    }
}

fn decode_state(value: &str) -> Result<DeviceLifecycleState, DurableStoreError> {
    match value {
        "active" => Ok(DeviceLifecycleState::Active),
        "stale" => Ok(DeviceLifecycleState::Stale),
        "reverification_required" => Ok(DeviceLifecycleState::ReverificationRequired),
        "expired" => Ok(DeviceLifecycleState::Expired),
        "revoked" => Ok(DeviceLifecycleState::Revoked),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn decode_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };

    use rusqlite::Connection;
    use ucr_core::{
        DeviceLifecycleStore, DurableStoreError, StorageProvider, TrustedSigningKeyStore,
    };
    use ucr_crypto::{TrustedKeyResolutionError, TrustedSigningKeyResolver};
    use ucr_model::{
        DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId, KeyId, KeyPurpose,
        NamespaceId, OpaqueId, PublicKeyDescriptor, TenantId, TenantScope, TrustedSigningKeyState,
    };
    use ucr_protocol::{ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID};

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_V14, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static DB_SEQUENCE: AtomicU64 = AtomicU64::new(90_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-device-lifecycle-{}-{sequence}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-device")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-device"))),
        }
    }

    fn device(state: DeviceLifecycleState) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid("device-a")),
            identity_id: IdentityId::from_opaque(oid("identity-a")),
            state,
        }
    }

    fn key(id: &str, byte: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(id)),
            device_id: DeviceId::from_opaque(oid("device-a")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![byte; 32],
        }
    }

    #[test]
    fn device_revocation_and_key_invalidation_survive_restart() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let first_key = key("key-a", 21);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.register_device(&scope, &active).expect("register");
            store
                .provision_trusted_signing_key(&scope, &first_key)
                .expect("provision key");
            let wrong_identity = IdentityId::from_opaque(oid("identity-wrong"));
            assert_eq!(
                store.resolve_active_signing_key(
                    &scope,
                    &active.device_id,
                    Some(&wrong_identity),
                    &first_key.key_id,
                ),
                Err(TrustedKeyResolutionError::NotTrusted)
            );
            assert_eq!(
                store.resolve_active_signing_key(
                    &scope,
                    &active.device_id,
                    Some(&active.identity_id),
                    &first_key.key_id,
                ),
                Ok(first_key.clone())
            );
        }
        {
            let store = SqliteLocalStore::open(db.path()).expect("reopen");
            store
                .revoke_device(&scope, &active.device_id, &active.identity_id)
                .expect("revoke device");
            store
                .revoke_device(&scope, &active.device_id, &active.identity_id)
                .expect("idempotent revoke");
            assert_eq!(
                store
                    .device(&scope, &active.device_id)
                    .expect("device lookup")
                    .expect("device exists")
                    .state,
                DeviceLifecycleState::Revoked
            );
            assert_eq!(
                store.active_trusted_signing_key(&scope, &active.device_id),
                Ok(None)
            );
            assert_eq!(
                store
                    .trusted_signing_key(&scope, &first_key.key_id)
                    .expect("key lookup")
                    .expect("key exists")
                    .state,
                TrustedSigningKeyState::Revoked
            );
            assert_eq!(
                store.register_device(&scope, &active),
                Err(DurableStoreError::Conflict)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen revoked");
        assert_eq!(
            reopened.resolve_active_signing_key(
                &scope,
                &active.device_id,
                Some(&active.identity_id),
                &first_key.key_id,
            ),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            reopened.provision_trusted_signing_key(&scope, &key("key-b", 22)),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn concurrent_device_revoke_and_key_rotation_never_leave_active_key() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let first = key("key-race-first", 31);
        let replacement = key("key-race-replacement", 32);
        {
            let store = SqliteLocalStore::open(db.path()).expect("seed store");
            store.register_device(&scope, &active).expect("register");
            store
                .provision_trusted_signing_key(&scope, &first)
                .expect("provision first");
        }

        let barrier = Arc::new(Barrier::new(3));
        let revoke_path = db.path().to_owned();
        let revoke_scope = scope.clone();
        let revoke_device = active.clone();
        let revoke_barrier = Arc::clone(&barrier);
        let revoke = thread::spawn(move || {
            let store = SqliteLocalStore::open(revoke_path).expect("revoke store");
            revoke_barrier.wait();
            store.revoke_device(
                &revoke_scope,
                &revoke_device.device_id,
                &revoke_device.identity_id,
            )
        });

        let rotate_path = db.path().to_owned();
        let rotate_scope = scope.clone();
        let rotate_first = first.clone();
        let rotate_replacement = replacement.clone();
        let rotate_barrier = Arc::clone(&barrier);
        let rotate = thread::spawn(move || {
            let store = SqliteLocalStore::open(rotate_path).expect("rotate store");
            rotate_barrier.wait();
            store.rotate_trusted_signing_key(
                &rotate_scope,
                &rotate_first.device_id,
                &rotate_first.key_id,
                &rotate_replacement,
            )
        });

        barrier.wait();
        assert_eq!(revoke.join().expect("revoke thread"), Ok(()));
        assert!(matches!(
            rotate.join().expect("rotate thread"),
            Ok(()) | Err(DurableStoreError::PermissionDenied)
        ));

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen final state");
        assert_eq!(
            reopened
                .device(&scope, &active.device_id)
                .expect("device lookup")
                .expect("device exists")
                .state,
            DeviceLifecycleState::Revoked
        );
        assert_eq!(
            reopened.active_trusted_signing_key(&scope, &active.device_id),
            Ok(None)
        );
        for key_id in [&first.key_id, &replacement.key_id] {
            if let Some(record) = reopened
                .trusted_signing_key(&scope, key_id)
                .expect("key lookup")
            {
                assert_eq!(record.state, TrustedSigningKeyState::Revoked);
            }
        }
    }

    #[test]
    fn v14_to_v15_migration_preserves_key_but_does_not_invent_device_identity() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let key = key("legacy-key", 23);
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store.register_device(&scope, &active).expect("register");
            store
                .provision_trusted_signing_key(&scope, &key)
                .expect("seed legacy key");
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices;")
            .expect("remove v15 device owner");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V14)
            .expect("set v14");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v14 to v15");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(migrated.device(&scope, &active.device_id), Ok(None));
        assert_eq!(
            migrated.active_trusted_signing_key(&scope, &active.device_id),
            Ok(None)
        );
        assert_eq!(
            migrated
                .trusted_signing_key(&scope, &key.key_id)
                .expect("historical key lookup")
                .expect("historical key retained")
                .state,
            TrustedSigningKeyState::Active
        );
        assert_eq!(
            migrated.resolve_active_signing_key(
                &scope,
                &active.device_id,
                Some(&active.identity_id),
                &key.key_id,
            ),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        migrated
            .register_device(&scope, &active)
            .expect("explicitly bind migrated device identity");
        assert_eq!(
            migrated.resolve_active_signing_key(
                &scope,
                &active.device_id,
                Some(&active.identity_id),
                &key.key_id,
            ),
            Ok(key)
        );
    }

    #[test]
    fn corrupt_device_state_is_rejected_on_reopen() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.register_device(&scope, &active).expect("register");
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .expect("allow corruption fixture");
        connection
            .execute(
                "UPDATE devices SET state='impossible' WHERE device_id=?1",
                [active.device_id.as_opaque().as_str()],
            )
            .expect("corrupt device state");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }
    #[test]
    fn registering_non_active_device_after_v14_migration_revokes_residual_key() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let legacy_key = key("legacy-reverify-key", 31);
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store.register_device(&scope, &active).expect("register");
            store
                .provision_trusted_signing_key(&scope, &legacy_key)
                .expect("provision key");
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices;")
            .expect("drop devices");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V14)
            .expect("set v14");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate");
        let mut recovered = active.clone();
        recovered.state = DeviceLifecycleState::ReverificationRequired;
        migrated
            .register_device(&scope, &recovered)
            .expect("register recovered device");
        assert_eq!(
            migrated
                .trusted_signing_key(&scope, &legacy_key.key_id)
                .expect("key lookup")
                .expect("key retained")
                .state,
            TrustedSigningKeyState::Revoked
        );
        assert_eq!(
            migrated.active_trusted_signing_key(&scope, &active.device_id),
            Ok(None)
        );
    }

    #[test]
    fn non_active_device_with_active_key_is_rejected_on_reopen() {
        let db = TestDb::new();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let active_key = key("tamper-key", 32);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.register_device(&scope, &active).expect("register");
            store
                .provision_trusted_signing_key(&scope, &active_key)
                .expect("provision key");
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute("UPDATE devices SET state='reverification_required'", [])
            .expect("tamper state");
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).expect_err("inconsistent state must fail"),
            DurableStoreError::Corrupt
        );
    }
}
