use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableStoreError, TrustedSigningKeyStore};
use ucr_crypto::{TrustedKeyResolutionError, TrustedSigningKeyResolver};
use ucr_model::{
    DeviceId, IdentityId, KeyId, KeyPurpose, OpaqueId, PublicKeyDescriptor, TenantScope,
    TrustedSigningKeyRecord, TrustedSigningKeyState,
};
use ucr_protocol::validate_trusted_signing_key_descriptor;

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V11_OBJECTS_SQL: &str = "
CREATE TABLE trusted_signing_keys (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm_id TEXT NOT NULL CHECK(algorithm_id = 'ed25519'),
    algorithm_version INTEGER NOT NULL CHECK(algorithm_version = 1),
    key_format_version INTEGER NOT NULL CHECK(key_format_version = 1),
    public_key BLOB NOT NULL CHECK(length(public_key) = 32),
    state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, key_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE UNIQUE INDEX trusted_signing_keys_one_active_per_device
ON trusted_signing_keys(tenant_id, namespace_present, namespace_id, device_id)
WHERE state = 'active';
";

pub(super) fn create_v11_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V11_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v11(connection: &Connection) -> Result<(), DurableStoreError> {
    super::message_store::verify_schema_v10(connection)?;
    verify_table_columns(
        connection,
        "trusted_signing_keys",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("key_id", "TEXT", 1, 4),
            ("device_id", "TEXT", 1, 0),
            ("algorithm_id", "TEXT", 1, 0),
            ("algorithm_version", "INTEGER", 1, 0),
            ("key_format_version", "INTEGER", 1, 0),
            ("public_key", "BLOB", 1, 0),
            ("state", "TEXT", 1, 0),
        ],
    )?;
    verify_active_key_index(connection)?;
    verify_trusted_key_rows(connection)
}

impl TrustedSigningKeyStore for SqliteLocalStore {
    fn provision_trusted_signing_key(
        &self,
        scope: &TenantScope,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError> {
        validate_trusted_signing_key_descriptor(descriptor)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if !super::device_store::protected_device_allows(
            &transaction,
            scope,
            &descriptor.device_id,
            None,
        )? {
            return Err(DurableStoreError::PermissionDenied);
        }

        if let Some(existing) = load_key_record(&transaction, scope, &descriptor.key_id)? {
            return if existing.state == TrustedSigningKeyState::Active
                && existing.descriptor == *descriptor
            {
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if active_key_id(&transaction, scope, &descriptor.device_id)?.is_some() {
            return Err(DurableStoreError::Conflict);
        }
        insert_active_key(&transaction, scope, descriptor)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn rotate_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
        replacement: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError> {
        validate_trusted_signing_key_descriptor(replacement)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if replacement.device_id != *device_id || replacement.key_id == *expected_current {
            return Err(DurableStoreError::Conflict);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if !super::device_store::protected_device_allows(&transaction, scope, device_id, None)? {
            return Err(DurableStoreError::PermissionDenied);
        }
        let active = active_key_id(&transaction, scope, device_id)?;

        if active.as_ref() == Some(&replacement.key_id) {
            let old = load_key_record(&transaction, scope, expected_current)?;
            let new = load_key_record(&transaction, scope, &replacement.key_id)?;
            return if old.is_some_and(|record| {
                record.state == TrustedSigningKeyState::Revoked
                    && record.descriptor.device_id == *device_id
            }) && new.is_some_and(|record| {
                record.state == TrustedSigningKeyState::Active && record.descriptor == *replacement
            }) {
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if active.as_ref() != Some(expected_current) {
            return Err(DurableStoreError::Conflict);
        }
        if load_key_record(&transaction, scope, &replacement.key_id)?.is_some() {
            return Err(DurableStoreError::Conflict);
        }
        let changed = set_key_state(
            &transaction,
            scope,
            expected_current,
            TrustedSigningKeyState::Active,
            TrustedSigningKeyState::Revoked,
        )?;
        if changed != 1 {
            return Err(DurableStoreError::Corrupt);
        }
        insert_active_key(&transaction, scope, replacement)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn revoke_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
    ) -> Result<(), DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        match active_key_id(&transaction, scope, device_id)? {
            Some(active) if active == *expected_current => {
                let changed = set_key_state(
                    &transaction,
                    scope,
                    expected_current,
                    TrustedSigningKeyState::Active,
                    TrustedSigningKeyState::Revoked,
                )?;
                if changed != 1 {
                    return Err(DurableStoreError::Corrupt);
                }
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))
            }
            Some(_) => Err(DurableStoreError::Conflict),
            None => match load_key_record(&transaction, scope, expected_current)? {
                Some(record)
                    if record.state == TrustedSigningKeyState::Revoked
                        && record.descriptor.device_id == *device_id =>
                {
                    transaction
                        .commit()
                        .map_err(|error| map_sqlite_error(&error))
                }
                _ => Err(DurableStoreError::Conflict),
            },
        }
    }

    fn trusted_signing_key(
        &self,
        scope: &TenantScope,
        key_id: &KeyId,
    ) -> Result<Option<TrustedSigningKeyRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_key_record(&connection, scope, key_id)
    }

    fn active_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<PublicKeyDescriptor>, DurableStoreError> {
        let connection = self.lock_connection()?;
        if !super::device_store::protected_device_allows(&connection, scope, device_id, None)? {
            return Ok(None);
        }
        let Some(key_id) = active_key_id(&connection, scope, device_id)? else {
            return Ok(None);
        };
        let record =
            load_key_record(&connection, scope, &key_id)?.ok_or(DurableStoreError::Corrupt)?;
        if record.state != TrustedSigningKeyState::Active
            || record.descriptor.device_id != *device_id
        {
            return Err(DurableStoreError::Corrupt);
        }
        Ok(Some(record.descriptor))
    }
}

impl TrustedSigningKeyResolver for SqliteLocalStore {
    fn resolve_active_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        identity_id: Option<&IdentityId>,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
        let connection = self.lock_connection().map_err(map_resolution_store_error)?;
        if !super::device_store::protected_device_allows(&connection, scope, device_id, identity_id)
            .map_err(map_resolution_store_error)?
        {
            return Err(TrustedKeyResolutionError::NotTrusted);
        }
        let namespace = namespace_storage_key(scope);
        let row = connection
            .query_row(
                "SELECT algorithm_id, algorithm_version, key_format_version, public_key
                 FROM trusted_signing_keys
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND key_id=?4 AND device_id=?5 AND state='active'",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    key_id.as_opaque().as_str(),
                    device_id.as_opaque().as_str(),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| map_resolution_store_error(map_sqlite_error(&error)))?;
        let Some((algorithm_id, algorithm_version, key_format_version, public_key)) = row else {
            return Err(TrustedKeyResolutionError::NotTrusted);
        };
        let descriptor = PublicKeyDescriptor {
            key_id: key_id.clone(),
            device_id: device_id.clone(),
            purpose: KeyPurpose::Signing,
            algorithm_id,
            algorithm_version: decode_u32(algorithm_version).map_err(map_resolution_store_error)?,
            key_format_version: decode_u32(key_format_version)
                .map_err(map_resolution_store_error)?,
            public_key,
        };
        validate_trusted_signing_key_descriptor(&descriptor)
            .map_err(|_| TrustedKeyResolutionError::Corrupt)?;
        Ok(descriptor)
    }
}

fn insert_active_key(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    descriptor: &PublicKeyDescriptor,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "INSERT INTO trusted_signing_keys (
                tenant_id, namespace_present, namespace_id, key_id, device_id,
                algorithm_id, algorithm_version, key_format_version, public_key, state
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'active')",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                descriptor.key_id.as_opaque().as_str(),
                descriptor.device_id.as_opaque().as_str(),
                descriptor.algorithm_id,
                i64::from(descriptor.algorithm_version),
                i64::from(descriptor.key_format_version),
                descriptor.public_key,
            ],
        )
        .map_err(|error| map_write_error(&error))?;
    Ok(())
}

fn set_key_state(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    key_id: &KeyId,
    expected: TrustedSigningKeyState,
    next: TrustedSigningKeyState,
) -> Result<usize, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "UPDATE trusted_signing_keys SET state=?5
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND key_id=?4 AND state=?6",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                key_id.as_opaque().as_str(),
                state_text(next),
                state_text(expected),
            ],
        )
        .map_err(|error| map_write_error(&error))
}

fn active_key_id(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<Option<KeyId>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value = connection
        .query_row(
            "SELECT key_id FROM trusted_signing_keys
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND device_id=?4 AND state='active'",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                device_id.as_opaque().as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    value.map(|value| decode_key_id(&value)).transpose()
}

fn load_key_record(
    connection: &Connection,
    scope: &TenantScope,
    key_id: &KeyId,
) -> Result<Option<TrustedSigningKeyRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT device_id, algorithm_id, algorithm_version, key_format_version, public_key, state
             FROM trusted_signing_keys
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND key_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                key_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((device_id, algorithm_id, algorithm_version, key_format_version, public_key, state)) =
        row
    else {
        return Ok(None);
    };
    let descriptor = PublicKeyDescriptor {
        key_id: key_id.clone(),
        device_id: DeviceId::from_opaque(decode_opaque_id(&device_id)?),
        purpose: KeyPurpose::Signing,
        algorithm_id,
        algorithm_version: decode_u32(algorithm_version)?,
        key_format_version: decode_u32(key_format_version)?,
        public_key,
    };
    validate_trusted_signing_key_descriptor(&descriptor).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(Some(TrustedSigningKeyRecord {
        scope: scope.clone(),
        descriptor,
        state: decode_state(&state)?,
    }))
}

fn verify_trusted_key_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, key_id, device_id,
                    algorithm_id, algorithm_version, key_format_version, public_key, state
             FROM trusted_signing_keys",
        )
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
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (
            tenant_id,
            namespace_present,
            namespace_id,
            key_id,
            device_id,
            algorithm_id,
            algorithm_version,
            key_format_version,
            public_key,
            state,
        ) = row.map_err(|error| map_sqlite_error(&error))?;
        let tenant = decode_opaque_id(&tenant_id)?;
        let namespace = match namespace_present {
            0 if namespace_id.is_empty() => None,
            1 if !namespace_id.is_empty() => Some(decode_opaque_id(&namespace_id)?),
            _ => return Err(DurableStoreError::Corrupt),
        };
        let scope = TenantScope {
            tenant_id: ucr_model::TenantId::from_opaque(tenant),
            namespace_id: namespace.map(ucr_model::NamespaceId::from_opaque),
        };
        let descriptor = PublicKeyDescriptor {
            key_id: KeyId::from_opaque(decode_opaque_id(&key_id)?),
            device_id: DeviceId::from_opaque(decode_opaque_id(&device_id)?),
            purpose: KeyPurpose::Signing,
            algorithm_id,
            algorithm_version: decode_u32(algorithm_version)?,
            key_format_version: decode_u32(key_format_version)?,
            public_key,
        };
        validate_trusted_signing_key_descriptor(&descriptor)
            .map_err(|_| DurableStoreError::Corrupt)?;
        let record = TrustedSigningKeyRecord {
            scope,
            descriptor,
            state: decode_state(&state)?,
        };
        if record.state == TrustedSigningKeyState::Active {
            let resolved = active_key_id(connection, &record.scope, &record.descriptor.device_id)?
                .ok_or(DurableStoreError::Corrupt)?;
            if resolved != record.descriptor.key_id {
                return Err(DurableStoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn verify_active_key_index(connection: &Connection) -> Result<(), DurableStoreError> {
    let sql = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='index' AND name='trusted_signing_keys_one_active_per_device'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .ok_or(DurableStoreError::Corrupt)?;
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if normalized
        != "create unique index trusted_signing_keys_one_active_per_device on trusted_signing_keys(tenant_id, namespace_present, namespace_id, device_id) where state = 'active'"
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn decode_state(value: &str) -> Result<TrustedSigningKeyState, DurableStoreError> {
    match value {
        "active" => Ok(TrustedSigningKeyState::Active),
        "revoked" => Ok(TrustedSigningKeyState::Revoked),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn state_text(state: TrustedSigningKeyState) -> &'static str {
    match state {
        TrustedSigningKeyState::Active => "active",
        TrustedSigningKeyState::Revoked => "revoked",
    }
}

fn decode_key_id(value: &str) -> Result<KeyId, DurableStoreError> {
    Ok(KeyId::from_opaque(decode_opaque_id(value)?))
}

fn decode_opaque_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_u32(value: i64) -> Result<u32, DurableStoreError> {
    u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn map_write_error(error: &rusqlite::Error) -> DurableStoreError {
    match error {
        rusqlite::Error::SqliteFailure(details, _)
            if details.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            DurableStoreError::Conflict
        }
        _ => map_sqlite_error(error),
    }
}

const fn map_resolution_store_error(error: DurableStoreError) -> TrustedKeyResolutionError {
    match error {
        DurableStoreError::Corrupt => TrustedKeyResolutionError::Corrupt,
        DurableStoreError::Unavailable | DurableStoreError::Full => {
            TrustedKeyResolutionError::Unavailable
        }
        DurableStoreError::PermissionDenied => TrustedKeyResolutionError::PermissionDenied,
        DurableStoreError::InvalidRecord
        | DurableStoreError::Conflict
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => TrustedKeyResolutionError::Internal,
    }
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

    use rusqlite::{Connection, params};
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
    use crate::{SQLITE_SCHEMA_V10, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static DB_SEQUENCE: AtomicU64 = AtomicU64::new(40_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-trusted-key-{}-{sequence}.sqlite3",
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
            tenant_id: TenantId::from_opaque(oid("tenant-trust")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-trust"))),
        }
    }

    fn descriptor(key: &str, byte: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(key)),
            device_id: DeviceId::from_opaque(oid("device-trust")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![byte; 32],
        }
    }

    fn register_active_device(store: &SqliteLocalStore, scope: &TenantScope) -> IdentityId {
        let identity_id = IdentityId::from_opaque(oid("identity-trust"));
        store
            .register_device(
                scope,
                &DeviceDescriptor {
                    device_id: DeviceId::from_opaque(oid("device-trust")),
                    identity_id: identity_id.clone(),
                    state: DeviceLifecycleState::Active,
                },
            )
            .expect("register active device fixture");
        identity_id
    }

    #[test]
    fn trusted_key_rotation_revocation_and_resolver_survive_restart() {
        let db = TestDb::new();
        let scope = scope();
        let first = descriptor("key-first", 1);
        let second = descriptor("key-second", 2);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            register_active_device(&store, &scope);
            store
                .provision_trusted_signing_key(&scope, &first)
                .expect("provision first");
            assert_eq!(
                store.resolve_active_signing_key(&scope, &first.device_id, None, &first.key_id),
                Ok(first.clone())
            );
        }
        {
            let store = SqliteLocalStore::open(db.path()).expect("reopen store");
            assert_eq!(
                store.rotate_trusted_signing_key(&scope, &first.device_id, &first.key_id, &second,),
                Ok(())
            );
            assert_eq!(
                store.rotate_trusted_signing_key(&scope, &first.device_id, &first.key_id, &second,),
                Ok(())
            );
            assert_eq!(
                store
                    .trusted_signing_key(&scope, &first.key_id)
                    .expect("old lookup")
                    .expect("old record")
                    .state,
                TrustedSigningKeyState::Revoked
            );
            assert_eq!(
                store.resolve_active_signing_key(&scope, &first.device_id, None, &first.key_id),
                Err(TrustedKeyResolutionError::NotTrusted)
            );
            assert_eq!(
                store.resolve_active_signing_key(&scope, &second.device_id, None, &second.key_id),
                Ok(second.clone())
            );
            store
                .revoke_trusted_signing_key(&scope, &second.device_id, &second.key_id)
                .expect("revoke replacement");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen revoked store");
        assert_eq!(
            reopened.resolve_active_signing_key(&scope, &second.device_id, None, &second.key_id),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            reopened.revoke_trusted_signing_key(&scope, &second.device_id, &second.key_id),
            Ok(())
        );
        assert_eq!(
            reopened.provision_trusted_signing_key(&scope, &first),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn concurrent_trusted_key_rotation_has_single_winner() {
        let db = TestDb::new();
        let scope = scope();
        let first = descriptor("key-base", 3);
        let left = descriptor("key-left", 4);
        let right = descriptor("key-right", 5);
        let seed = SqliteLocalStore::open(db.path()).expect("open seed");
        register_active_device(&seed, &scope);
        seed.provision_trusted_signing_key(&scope, &first)
            .expect("seed key");

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for replacement in [left.clone(), right.clone()] {
            let path = db.path().to_owned();
            let scope = scope.clone();
            let first = first.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("thread store");
                barrier.wait();
                store.rotate_trusted_signing_key(
                    &scope,
                    &first.device_id,
                    &first.key_id,
                    &replacement,
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("rotation thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(DurableStoreError::Conflict))
                .count(),
            1
        );
        let store = SqliteLocalStore::open(db.path()).expect("reopen winner");
        let active = store
            .active_trusted_signing_key(&scope, &first.device_id)
            .expect("active lookup")
            .expect("one active key");
        assert!(active == left || active == right);
    }

    #[test]
    fn v10_to_v11_migration_preserves_existing_security_state_and_starts_empty_trust() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute(
                "INSERT INTO handshake_replay(peer_verifying_key, transcript_binding) VALUES (?1,?2)",
                params![vec![7_u8; 32], vec![9_u8; 32]],
            )
            .expect("seed v10 security state");
        connection
            .execute_batch("DROP TABLE identities; DROP TABLE external_identity_bindings; DROP TABLE service_audit_operations; DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices; DROP TRIGGER service_audit_no_update; DROP TRIGGER service_audit_no_delete; DROP INDEX service_audit_scope_sequence; DROP TABLE service_audit_records; DROP TABLE service_quota_usage; DROP TABLE service_quota_policies; DROP TABLE service_credentials; DROP TABLE permission_grants; DROP TABLE trusted_signing_keys;")
            .expect("remove v11 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V10)
            .expect("set v10");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v10 to v11");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated
                .active_trusted_signing_key(&scope(), &DeviceId::from_opaque(oid("device-trust"))),
            Ok(None)
        );
        let connection = Connection::open(db.path()).expect("inspect replay");
        let replay_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM handshake_replay", [], |row| {
                row.get(0)
            })
            .expect("replay count");
        assert_eq!(replay_count, 1);
    }

    #[test]
    fn corrupt_trusted_key_row_is_rejected_on_reopen() {
        let db = TestDb::new();
        let scope = scope();
        let key = descriptor("key-corrupt", 6);
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        register_active_device(&store, &scope);
        store
            .provision_trusted_signing_key(&scope, &key)
            .expect("provision key");
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .expect("allow corruption fixture");
        connection
            .execute(
                "UPDATE trusted_signing_keys SET public_key=?1 WHERE key_id=?2",
                params![vec![1_u8; 31], key.key_id.as_opaque().as_str()],
            )
            .expect("corrupt public key");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn missing_active_key_unique_index_is_rejected_on_reopen() {
        let db = TestDb::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("DROP INDEX trusted_signing_keys_one_active_per_device;")
            .expect("drop security index");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }
}
