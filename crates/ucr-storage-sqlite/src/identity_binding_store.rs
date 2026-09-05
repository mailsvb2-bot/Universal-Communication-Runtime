use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, ExternalIdentityBindingStore};
use ucr_model::{
    ExternalIdentityBinding, IdentityId, IntegrationId, NamespaceId, OpaqueId, TenantId,
    TenantScope,
};
use ucr_protocol::{
    MAX_EXTERNAL_ENTITY_ID_LEN, validate_external_identity_binding,
    validate_external_identity_binding_key,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V18_OBJECTS_SQL: &str = r"
CREATE TABLE external_identity_bindings (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    external_namespace TEXT NOT NULL,
    external_entity_id BLOB NOT NULL CHECK(length(external_entity_id) > 0 AND length(external_entity_id) <= 2048),
    identity_id TEXT NOT NULL,
    PRIMARY KEY(
        tenant_id, namespace_present, namespace_id, integration_id,
        external_namespace, external_entity_id
    ),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v18_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V18_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v18(connection: &Connection) -> Result<(), DurableStoreError> {
    super::service_control_store::verify_schema_v17(connection)?;
    verify_table_columns(
        connection,
        "external_identity_bindings",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("integration_id", "TEXT", 1, 4),
            ("external_namespace", "TEXT", 1, 5),
            ("external_entity_id", "BLOB", 1, 6),
            ("identity_id", "TEXT", 1, 0),
        ],
    )?;

    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, integration_id,
                    external_namespace, external_entity_id, identity_id
             FROM external_identity_bindings",
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
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (
            tenant,
            namespace_present,
            namespace,
            integration,
            external_namespace,
            external_id,
            identity,
        ) = row.map_err(|error| map_sqlite_error(&error))?;
        let binding = ExternalIdentityBinding {
            scope: stored_scope(tenant, namespace_present, namespace)?,
            integration_id: IntegrationId::from_opaque(
                OpaqueId::new(integration).map_err(|_| DurableStoreError::Corrupt)?,
            ),
            external_namespace,
            external_entity_id: external_id,
            identity_id: IdentityId::from_opaque(
                OpaqueId::new(identity).map_err(|_| DurableStoreError::Corrupt)?,
            ),
        };
        validate_external_identity_binding(&binding).map_err(|_| DurableStoreError::Corrupt)?;
    }
    Ok(())
}

impl ExternalIdentityBindingStore for SqliteLocalStore {
    fn persist_external_identity_binding(
        &self,
        binding: &ExternalIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_external_identity_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_binding_from(
            &transaction,
            &binding.scope,
            &binding.integration_id,
            &binding.external_namespace,
            &binding.external_entity_id,
        )? {
            return if existing == *binding {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if !super::identity_store::identity_exists_in(
            &transaction,
            &binding.scope,
            &binding.identity_id,
        )? {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(&binding.scope);
        transaction
            .execute(
                "INSERT INTO external_identity_bindings (
                    tenant_id, namespace_present, namespace_id, integration_id,
                    external_namespace, external_entity_id, identity_id
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    binding.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    binding.integration_id.as_opaque().as_str(),
                    binding.external_namespace,
                    binding.external_entity_id,
                    binding.identity_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn external_identity_binding(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_namespace: &str,
        external_entity_id: &[u8],
    ) -> Result<Option<ExternalIdentityBinding>, DurableStoreError> {
        validate_external_identity_binding_key(external_namespace, external_entity_id)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let connection = self.lock_connection()?;
        load_binding_from(
            &connection,
            scope,
            integration_id,
            external_namespace,
            external_entity_id,
        )
    }
}

fn load_binding_from(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
    external_namespace: &str,
    external_entity_id: &[u8],
) -> Result<Option<ExternalIdentityBinding>, DurableStoreError> {
    if external_entity_id.len() > MAX_EXTERNAL_ENTITY_ID_LEN {
        return Err(DurableStoreError::InvalidRecord);
    }
    let namespace = namespace_storage_key(scope);
    let identity = connection
        .query_row(
            "SELECT identity_id FROM external_identity_bindings
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND integration_id=?4 AND external_namespace=?5 AND external_entity_id=?6",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                integration_id.as_opaque().as_str(),
                external_namespace,
                external_entity_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    identity
        .map(|identity| {
            Ok(ExternalIdentityBinding {
                scope: scope.clone(),
                integration_id: integration_id.clone(),
                external_namespace: external_namespace.to_owned(),
                external_entity_id: external_entity_id.to_vec(),
                identity_id: IdentityId::from_opaque(
                    OpaqueId::new(identity).map_err(|_| DurableStoreError::Corrupt)?,
                ),
            })
        })
        .transpose()
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
    use crate::{SQLITE_SCHEMA_V17, SQLITE_SCHEMA_VERSION};

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(120_000);

    struct TestDb {
        path: PathBuf,
    }
    impl TestDb {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ucr-identity-binding-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            Self { path }
        }
        fn path(&self) -> &PathBuf {
            &self.path
        }
    }
    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_file(self.path.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.path.with_extension("sqlite3-shm"));
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-binding-sqlite")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-binding-sqlite"))),
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

    fn seed_identity(store: &SqliteLocalStore, id: &str) {
        store
            .persist_identity(&identity(id))
            .expect("seed identity");
    }

    fn binding(identity: &str) -> ExternalIdentityBinding {
        ExternalIdentityBinding {
            scope: scope(),
            integration_id: IntegrationId::from_opaque(oid("integration-binding-sqlite")),
            external_namespace: "vendor.example.customer".to_owned(),
            external_entity_id: b"customer-42".to_vec(),
            identity_id: IdentityId::from_opaque(oid(identity)),
        }
    }

    #[test]
    fn external_identity_binding_survives_restart_and_relink_conflicts() {
        let db = TestDb::new();
        let original = binding("identity-original");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            seed_identity(&store, "identity-original");
            seed_identity(&store, "identity-other");
            assert_eq!(
                store.persist_external_identity_binding(&original),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.persist_external_identity_binding(&original),
                Ok(DurableRecordStatus::Duplicate)
            );
            assert_eq!(
                store.persist_external_identity_binding(&binding("identity-other")),
                Err(DurableStoreError::Conflict)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(reopened.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            reopened.external_identity_binding(
                &original.scope,
                &original.integration_id,
                &original.external_namespace,
                &original.external_entity_id,
            ),
            Ok(Some(original))
        );
    }

    #[test]
    fn concurrent_conflicting_external_identity_links_have_one_winner() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize");
            seed_identity(&store, "identity-a");
            seed_identity(&store, "identity-b");
        }
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for identity in ["identity-a", "identity-b"] {
            let path = db.path().clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("thread open");
                barrier.wait();
                store.persist_external_identity_binding(&binding(identity))
            }));
        }
        barrier.wait();
        let mut results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join"))
            .collect::<Vec<_>>();
        results.sort_by_key(|result| match result {
            Ok(DurableRecordStatus::Persisted) => 0,
            Ok(DurableRecordStatus::Duplicate) => 1,
            Err(DurableStoreError::Conflict) => 2,
            _ => 3,
        });
        assert_eq!(results[0], Ok(DurableRecordStatus::Persisted));
        assert_eq!(results[1], Err(DurableStoreError::Conflict));
    }

    #[test]
    fn v17_to_v18_migration_starts_with_no_inferred_identity_bindings() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute_batch("DROP TABLE identities; DROP TABLE external_identity_bindings;")
            .expect("restore exact v17 shape");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V17)
            .expect("v17 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v17 to v18");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let candidate = binding("identity-not-inferred");
        assert_eq!(
            migrated.external_identity_binding(
                &candidate.scope,
                &candidate.integration_id,
                &candidate.external_namespace,
                &candidate.external_entity_id,
            ),
            Ok(None)
        );
    }

    #[test]
    fn missing_or_malformed_v18_identity_binding_owner_is_rejected_on_reopen() {
        let missing = TestDb::new();
        {
            SqliteLocalStore::open(missing.path()).expect("initialize missing fixture");
        }
        let connection = Connection::open(missing.path()).expect("raw missing connection");
        connection
            .execute_batch("DROP TABLE external_identity_bindings;")
            .expect("drop owner");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(missing.path()),
            Err(DurableStoreError::Corrupt)
        ));

        let malformed = TestDb::new();
        {
            SqliteLocalStore::open(malformed.path()).expect("initialize malformed fixture");
        }
        let connection = Connection::open(malformed.path()).expect("raw malformed connection");
        connection
            .execute(
                "INSERT INTO external_identity_bindings (
                tenant_id, namespace_present, namespace_id, integration_id,
                external_namespace, external_entity_id, identity_id
             ) VALUES (?1,1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    "tenant-binding-sqlite",
                    "namespace-binding-sqlite",
                    "integration-binding-sqlite",
                    "not-namespaced",
                    b"customer-42".as_slice(),
                    "identity-malformed"
                ],
            )
            .expect("insert malformed namespace");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(malformed.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }
}
