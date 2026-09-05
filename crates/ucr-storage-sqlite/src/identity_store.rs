use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, IdentityStore};
use ucr_model::{
    IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord, NamespaceId, OpaqueId,
    TenantId, TenantScope,
};
use ucr_protocol::validate_identity_record;

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V19_OBJECTS_SQL: &str = r"
CREATE TABLE identities (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    ownership TEXT NOT NULL CHECK(ownership IN (
        'ucr_native', 'user_managed', 'platform_managed', 'organization_managed',
        'federated', 'temporary'
    )),
    evidence TEXT NOT NULL CHECK(evidence IN (
        'unverified', 'self_asserted', 'device_verified', 'contact_verified',
        'organization_verified', 'external_provider_verified'
    )),
    expires_at_unix_ms INTEGER CHECK(expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, identity_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v19_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V19_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v19(connection: &Connection) -> Result<(), DurableStoreError> {
    super::identity_binding_store::verify_schema_v18(connection)?;
    verify_table_columns(
        connection,
        "identities",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("identity_id", "TEXT", 1, 4),
            ("ownership", "TEXT", 1, 0),
            ("evidence", "TEXT", 1, 0),
            ("expires_at_unix_ms", "INTEGER", 0, 0),
        ],
    )?;

    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, identity_id,
                    ownership, evidence, expires_at_unix_ms FROM identities",
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
                row.get::<_, Option<i64>>(6)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (tenant, namespace_present, namespace, identity_id, ownership, evidence, expiry) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let identity = IdentityRecord {
            scope: stored_scope(tenant, namespace_present, namespace)?,
            identity_id: IdentityId::from_opaque(
                OpaqueId::new(identity_id).map_err(|_| DurableStoreError::Corrupt)?,
            ),
            ownership: decode_ownership(&ownership)?,
            evidence: decode_evidence(&evidence)?,
            expires_at_unix_ms: expiry,
        };
        validate_identity_record(&identity).map_err(|_| DurableStoreError::Corrupt)?;
    }
    Ok(())
}

impl IdentityStore for SqliteLocalStore {
    fn persist_identity(
        &self,
        identity: &IdentityRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_identity_record(identity).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_identity_from(&transaction, &identity.scope, &identity.identity_id)?
        {
            return if existing == *identity {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let namespace = namespace_storage_key(&identity.scope);
        transaction
            .execute(
                "INSERT INTO identities (
                    tenant_id, namespace_present, namespace_id, identity_id,
                    ownership, evidence, expires_at_unix_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    identity.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    identity.identity_id.as_opaque().as_str(),
                    encode_ownership(identity.ownership),
                    encode_evidence(identity.evidence),
                    identity.expires_at_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn identity(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<IdentityRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_identity_from(&connection, scope, identity_id)
    }
}

pub(super) fn identity_exists_in(
    connection: &Connection,
    scope: &TenantScope,
    identity_id: &IdentityId,
) -> Result<bool, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT 1 FROM identities
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                identity_id.as_opaque().as_str(),
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|error| map_sqlite_error(&error))
}

fn load_identity_from(
    connection: &Connection,
    scope: &TenantScope,
    identity_id: &IdentityId,
) -> Result<Option<IdentityRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT ownership, evidence, expires_at_unix_ms FROM identities
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                identity_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|(ownership, evidence, expiry)| {
        let identity = IdentityRecord {
            scope: scope.clone(),
            identity_id: identity_id.clone(),
            ownership: decode_ownership(&ownership)?,
            evidence: decode_evidence(&evidence)?,
            expires_at_unix_ms: expiry,
        };
        validate_identity_record(&identity).map_err(|_| DurableStoreError::Corrupt)?;
        Ok(identity)
    })
    .transpose()
}

const fn encode_ownership(value: IdentityOwnership) -> &'static str {
    match value {
        IdentityOwnership::UcrNative => "ucr_native",
        IdentityOwnership::UserManaged => "user_managed",
        IdentityOwnership::PlatformManaged => "platform_managed",
        IdentityOwnership::OrganizationManaged => "organization_managed",
        IdentityOwnership::Federated => "federated",
        IdentityOwnership::Temporary => "temporary",
    }
}

fn decode_ownership(value: &str) -> Result<IdentityOwnership, DurableStoreError> {
    match value {
        "ucr_native" => Ok(IdentityOwnership::UcrNative),
        "user_managed" => Ok(IdentityOwnership::UserManaged),
        "platform_managed" => Ok(IdentityOwnership::PlatformManaged),
        "organization_managed" => Ok(IdentityOwnership::OrganizationManaged),
        "federated" => Ok(IdentityOwnership::Federated),
        "temporary" => Ok(IdentityOwnership::Temporary),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn encode_evidence(value: IdentityEvidence) -> &'static str {
    match value {
        IdentityEvidence::Unverified => "unverified",
        IdentityEvidence::SelfAsserted => "self_asserted",
        IdentityEvidence::DeviceVerified => "device_verified",
        IdentityEvidence::ContactVerified => "contact_verified",
        IdentityEvidence::OrganizationVerified => "organization_verified",
        IdentityEvidence::ExternalProviderVerified => "external_provider_verified",
    }
}

fn decode_evidence(value: &str) -> Result<IdentityEvidence, DurableStoreError> {
    match value {
        "unverified" => Ok(IdentityEvidence::Unverified),
        "self_asserted" => Ok(IdentityEvidence::SelfAsserted),
        "device_verified" => Ok(IdentityEvidence::DeviceVerified),
        "contact_verified" => Ok(IdentityEvidence::ContactVerified),
        "organization_verified" => Ok(IdentityEvidence::OrganizationVerified),
        "external_provider_verified" => Ok(IdentityEvidence::ExternalProviderVerified),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn stored_scope(
    tenant: String,
    namespace_present: i64,
    namespace: String,
) -> Result<TenantScope, DurableStoreError> {
    let tenant_id =
        TenantId::from_opaque(OpaqueId::new(tenant).map_err(|_| DurableStoreError::Corrupt)?);
    let namespace_id = match namespace_present {
        0 if namespace.is_empty() => None,
        1 if !namespace.is_empty() => Some(NamespaceId::from_opaque(
            OpaqueId::new(namespace).map_err(|_| DurableStoreError::Corrupt)?,
        )),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id,
        namespace_id,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };

    use rusqlite::Connection;
    use ucr_core::{
        DurableRecordStatus, DurableStoreError, ExternalIdentityBindingStore, IdentityStore,
        StorageProvider,
    };
    use ucr_model::{
        ExternalIdentityBinding, IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord,
        IntegrationId, NamespaceId, OpaqueId, TenantId, TenantScope,
    };

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_V18, SQLITE_SCHEMA_VERSION};

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(140_000);

    struct TestDb(PathBuf);
    impl TestDb {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ucr-root-identity-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            Self(path)
        }
        fn path(&self) -> &PathBuf {
            &self.0
        }
    }
    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-root-identity")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-root-identity"))),
        }
    }
    fn identity(id: &str) -> IdentityRecord {
        IdentityRecord {
            scope: scope(),
            identity_id: IdentityId::from_opaque(oid(id)),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::Unverified,
            expires_at_unix_ms: None,
        }
    }
    fn binding(id: &str, entity: &[u8]) -> ExternalIdentityBinding {
        ExternalIdentityBinding {
            scope: scope(),
            integration_id: IntegrationId::from_opaque(oid("integration-root-identity")),
            external_namespace: "vendor.example.account".to_owned(),
            external_entity_id: entity.to_vec(),
            identity_id: IdentityId::from_opaque(oid(id)),
        }
    }

    #[test]
    fn root_identity_survives_restart_and_scoped_id_redefinition_conflicts() {
        let db = TestDb::new();
        let original = identity("identity-root-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            assert_eq!(
                store.persist_identity(&original),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.persist_identity(&original),
                Ok(DurableRecordStatus::Duplicate)
            );
            let mut changed = original.clone();
            changed.evidence = IdentityEvidence::SelfAsserted;
            assert_eq!(
                store.persist_identity(&changed),
                Err(DurableStoreError::Conflict)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(reopened.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            reopened.identity(&original.scope, &original.identity_id),
            Ok(Some(original))
        );
    }

    #[test]
    fn temporary_identity_expiry_round_trips_and_invalid_expiry_fails_closed() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        let mut temporary = identity("identity-temporary");
        temporary.ownership = IdentityOwnership::Temporary;
        temporary.evidence = IdentityEvidence::SelfAsserted;
        temporary.expires_at_unix_ms = Some(86_400_000);
        assert_eq!(
            store.persist_identity(&temporary),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.identity(&temporary.scope, &temporary.identity_id),
            Ok(Some(temporary.clone()))
        );
        let mut invalid = identity("identity-bad-expiry");
        invalid.expires_at_unix_ms = Some(0);
        assert_eq!(
            store.persist_identity(&invalid),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn concurrent_conflicting_root_identity_creates_have_one_winner() {
        let db = TestDb::new();
        SqliteLocalStore::open(db.path()).expect("initialize");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for evidence in [IdentityEvidence::Unverified, IdentityEvidence::SelfAsserted] {
            let path = db.path().clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("thread open");
                let mut value = identity("identity-race");
                value.evidence = evidence;
                barrier.wait();
                store.persist_identity(&value)
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join"))
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(DurableRecordStatus::Persisted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(DurableStoreError::Conflict))
                .count(),
            1
        );
    }

    #[test]
    fn v18_to_v19_migration_invents_no_identity_and_preserves_legacy_binding() {
        let db = TestDb::new();
        let original_identity = identity("identity-legacy-binding");
        let legacy_binding = binding("identity-legacy-binding", b"legacy-entity");
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store
                .persist_identity(&original_identity)
                .expect("seed identity before simulated downgrade");
            store
                .persist_external_identity_binding(&legacy_binding)
                .expect("seed binding before simulated downgrade");
        }
        let connection = Connection::open(db.path()).expect("raw v18 fixture");
        connection
            .execute_batch("DROP TABLE identities;")
            .expect("restore v18 shape");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V18)
            .expect("v18 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v18 to v19");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated.identity(&original_identity.scope, &original_identity.identity_id),
            Ok(None)
        );
        assert_eq!(
            migrated.external_identity_binding(
                &legacy_binding.scope,
                &legacy_binding.integration_id,
                &legacy_binding.external_namespace,
                &legacy_binding.external_entity_id,
            ),
            Ok(Some(legacy_binding.clone()))
        );
        assert_eq!(
            migrated.persist_external_identity_binding(&legacy_binding),
            Ok(DurableRecordStatus::Duplicate)
        );
        let new_key_same_missing_target = binding("identity-legacy-binding", b"new-entity");
        assert_eq!(
            migrated.persist_external_identity_binding(&new_key_same_missing_target),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn missing_or_corrupt_v19_identity_owner_is_rejected_on_reopen() {
        let missing = TestDb::new();
        {
            SqliteLocalStore::open(missing.path()).expect("initialize missing fixture");
        }
        let connection = Connection::open(missing.path()).expect("raw missing connection");
        connection
            .execute_batch("DROP TABLE identities;")
            .expect("drop identity owner");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(missing.path()),
            Err(DurableStoreError::Corrupt)
        ));

        let corrupt = TestDb::new();
        {
            SqliteLocalStore::open(corrupt.path()).expect("initialize corrupt fixture");
        }
        let connection = Connection::open(corrupt.path()).expect("raw corrupt connection");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .expect("allow corruption fixture");
        connection
            .execute(
                "INSERT INTO identities (
                    tenant_id, namespace_present, namespace_id, identity_id,
                    ownership, evidence, expires_at_unix_ms
                 ) VALUES (?1,1,?2,?3,'not_canonical','unverified',NULL)",
                rusqlite::params![
                    "tenant-root-identity",
                    "namespace-root-identity",
                    "identity-corrupt"
                ],
            )
            .expect("insert corrupt identity");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(corrupt.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }
}
