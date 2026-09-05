use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{CommunicationIntentStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    CommunicationIntent, CorrelationContext, IdentityId, IntentConstraints, IntentId, NamespaceId,
    OpaqueId, ProtocolExtension, TenantId, TenantScope,
};
use ucr_protocol::{
    DEFAULT_MAX_PAYLOAD_LEN, MAX_EXTENSION_PAYLOAD_LEN, MAX_INTENT_IDEMPOTENCY_KEY_LEN,
    MAX_INTENT_POLICY_VALUE_LEN, MAX_INTENT_TRANSPORT_CONSTRAINTS, MAX_PROTOCOL_EXTENSIONS,
    canonical_communication_intent,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V16_OBJECTS_SQL: &str = r"
CREATE TABLE communication_intents (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    target_identity_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    privacy_profile TEXT,
    region_constraint TEXT,
    max_cost_microunits BLOB CHECK(max_cost_microunits IS NULL OR length(max_cost_microunits) = 8),
    priority_class INTEGER CHECK(priority_class IS NULL OR (priority_class >= 0 AND priority_class <= 4294967295)),
    correlation_id TEXT NOT NULL,
    causation_id TEXT,
    idempotency_key TEXT,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, intent_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE communication_intent_transports (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('allowed', 'forbidden')),
    position INTEGER NOT NULL CHECK(position >= 0),
    capability TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, intent_id, disposition, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, intent_id, capability),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, intent_id)
      REFERENCES communication_intents(tenant_id, namespace_present, namespace_id, intent_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE communication_intent_extensions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0),
    name TEXT NOT NULL,
    critical INTEGER NOT NULL CHECK(critical IN (0, 1)),
    payload BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, intent_id, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, intent_id, name),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, intent_id)
      REFERENCES communication_intents(tenant_id, namespace_present, namespace_id, intent_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v16_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V16_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v16(connection: &Connection) -> Result<(), DurableStoreError> {
    super::device_store::verify_schema_v15(connection)?;
    verify_table_columns(
        connection,
        "communication_intents",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("intent_id", "TEXT", 1, 4),
            ("target_identity_id", "TEXT", 1, 0),
            ("payload", "BLOB", 1, 0),
            ("privacy_profile", "TEXT", 0, 0),
            ("region_constraint", "TEXT", 0, 0),
            ("max_cost_microunits", "BLOB", 0, 0),
            ("priority_class", "INTEGER", 0, 0),
            ("correlation_id", "TEXT", 1, 0),
            ("causation_id", "TEXT", 0, 0),
            ("idempotency_key", "TEXT", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "communication_intent_transports",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("intent_id", "TEXT", 1, 4),
            ("disposition", "TEXT", 1, 5),
            ("position", "INTEGER", 1, 6),
            ("capability", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "communication_intent_extensions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("intent_id", "TEXT", 1, 4),
            ("position", "INTEGER", 1, 5),
            ("name", "TEXT", 1, 0),
            ("critical", "INTEGER", 1, 0),
            ("payload", "BLOB", 1, 0),
        ],
    )?;

    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error))?;
    if foreign_key_check
        .query([])
        .map_err(|error| map_sqlite_error(&error))?
        .next()
        .map_err(|error| map_sqlite_error(&error))?
        .is_some()
    {
        return Err(DurableStoreError::Corrupt);
    }
    drop(foreign_key_check);
    verify_intent_child_integrity(connection)?;

    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, intent_id
             FROM communication_intents",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut keys = Vec::new();
    for row in rows {
        keys.push(row.map_err(|error| map_sqlite_error(&error))?);
    }
    drop(statement);
    for (tenant, namespace_present, namespace, intent_id) in keys {
        let scope = stored_scope(tenant, namespace_present, namespace)?;
        let intent_id = IntentId::from_opaque(
            OpaqueId::new(intent_id).map_err(|_| DurableStoreError::Corrupt)?,
        );
        load_intent_from(connection, &scope, &intent_id)?.ok_or(DurableStoreError::Corrupt)?;
    }
    Ok(())
}

fn verify_intent_child_integrity(connection: &Connection) -> Result<(), DurableStoreError> {
    let invalid: bool = connection
        .query_row(
            r"SELECT
                EXISTS(
                    SELECT 1
                    FROM communication_intent_transports AS child
                    LEFT JOIN communication_intents AS parent
                      ON parent.tenant_id = child.tenant_id
                     AND parent.namespace_present = child.namespace_present
                     AND parent.namespace_id = child.namespace_id
                     AND parent.intent_id = child.intent_id
                    WHERE parent.intent_id IS NULL
                       OR child.disposition NOT IN ('allowed', 'forbidden')
                       OR child.position < 0
                )
                OR EXISTS(
                    SELECT 1
                    FROM communication_intent_extensions AS child
                    LEFT JOIN communication_intents AS parent
                      ON parent.tenant_id = child.tenant_id
                     AND parent.namespace_present = child.namespace_present
                     AND parent.namespace_id = child.namespace_id
                     AND parent.intent_id = child.intent_id
                    WHERE parent.intent_id IS NULL
                       OR child.position < 0
                       OR child.critical NOT IN (0, 1)
                )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid {
        Err(DurableStoreError::Corrupt)
    } else {
        Ok(())
    }
}

impl CommunicationIntentStore for SqliteLocalStore {
    fn persist_communication_intent(
        &self,
        intent: &CommunicationIntent,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical =
            canonical_communication_intent(intent).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_intent_from(&transaction, &canonical.scope, &canonical.intent_id)?
        {
            return if existing == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_intent(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn communication_intent(
        &self,
        scope: &TenantScope,
        intent_id: &IntentId,
    ) -> Result<Option<CommunicationIntent>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_intent_from(&connection, scope, intent_id)
    }
}

fn insert_intent(
    transaction: &Transaction<'_>,
    intent: &CommunicationIntent,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&intent.scope);
    let max_cost = intent
        .constraints
        .max_cost_microunits
        .map(|value| value.to_be_bytes().to_vec());
    let priority = intent.constraints.priority_class.map(i64::from);
    transaction
        .execute(
            "INSERT INTO communication_intents (
                tenant_id, namespace_present, namespace_id, intent_id, target_identity_id,
                payload, privacy_profile, region_constraint, max_cost_microunits, priority_class,
                correlation_id, causation_id, idempotency_key
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                intent.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                intent.intent_id.as_opaque().as_str(),
                intent.target_identity_id.as_opaque().as_str(),
                intent.payload.as_slice(),
                intent.constraints.privacy_profile.as_deref(),
                intent.constraints.region_constraint.as_deref(),
                max_cost,
                priority,
                intent.correlation.correlation_id.as_str(),
                intent
                    .correlation
                    .causation_id
                    .as_ref()
                    .map(OpaqueId::as_str),
                intent.correlation.idempotency_key.as_deref(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;

    for (disposition, values) in [
        (
            "allowed",
            &intent.constraints.allowed_transport_capabilities,
        ),
        (
            "forbidden",
            &intent.constraints.forbidden_transport_capabilities,
        ),
    ] {
        for (position, capability) in values.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO communication_intent_transports (
                        tenant_id, namespace_present, namespace_id, intent_id,
                        disposition, position, capability
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        intent.scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        intent.intent_id.as_opaque().as_str(),
                        disposition,
                        i64::try_from(position).map_err(|_| DurableStoreError::InvalidRecord)?,
                        capability,
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
        }
    }
    for (position, extension) in intent.extensions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO communication_intent_extensions (
                    tenant_id, namespace_present, namespace_id, intent_id,
                    position, name, critical, payload
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    intent.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    intent.intent_id.as_opaque().as_str(),
                    i64::try_from(position).map_err(|_| DurableStoreError::InvalidRecord)?,
                    extension.name,
                    i64::from(extension.critical),
                    extension.payload,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

struct StoredIntentRow {
    target_identity_id: String,
    payload: Vec<u8>,
    privacy_profile: Option<String>,
    region_constraint: Option<String>,
    max_cost_microunits: Option<Vec<u8>>,
    priority_class: Option<i64>,
    correlation_id: String,
    causation_id: Option<String>,
    idempotency_key: Option<String>,
}

fn load_intent_root(
    connection: &Connection,
    scope: &TenantScope,
    intent_id: &IntentId,
) -> Result<Option<StoredIntentRow>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT target_identity_id, payload, privacy_profile, region_constraint,
                    max_cost_microunits, priority_class, correlation_id, causation_id, idempotency_key,
                    length(payload), length(privacy_profile), length(region_constraint), length(idempotency_key)
             FROM communication_intents
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND intent_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                intent_id.as_opaque().as_str(),
            ],
            |row| {
                validate_root_field_lengths(row)?;
                Ok(StoredIntentRow {
                    target_identity_id: row.get(0)?,
                    payload: row.get(1)?,
                    privacy_profile: row.get(2)?,
                    region_constraint: row.get(3)?,
                    max_cost_microunits: row.get(4)?,
                    priority_class: row.get(5)?,
                    correlation_id: row.get(6)?,
                    causation_id: row.get(7)?,
                    idempotency_key: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|error| {
            if matches!(error, rusqlite::Error::InvalidQuery) {
                DurableStoreError::Corrupt
            } else {
                map_sqlite_error(&error)
            }
        })
}

fn validate_root_field_lengths(row: &rusqlite::Row<'_>) -> rusqlite::Result<()> {
    let payload_len = row.get::<_, i64>(9)?;
    let privacy_len = row.get::<_, Option<i64>>(10)?.unwrap_or(0);
    let region_len = row.get::<_, Option<i64>>(11)?.unwrap_or(0);
    let idempotency_len = row.get::<_, Option<i64>>(12)?.unwrap_or(0);
    let policy_limit = i64::try_from(MAX_INTENT_POLICY_VALUE_LEN).unwrap_or(i64::MAX);
    let idempotency_limit = i64::try_from(MAX_INTENT_IDEMPOTENCY_KEY_LEN).unwrap_or(i64::MAX);
    if payload_len < 0
        || payload_len > i64::from(DEFAULT_MAX_PAYLOAD_LEN)
        || privacy_len < 0
        || privacy_len > policy_limit
        || region_len < 0
        || region_len > policy_limit
        || idempotency_len < 0
        || idempotency_len > idempotency_limit
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn load_intent_from(
    connection: &Connection,
    scope: &TenantScope,
    intent_id: &IntentId,
) -> Result<Option<CommunicationIntent>, DurableStoreError> {
    let Some(row) = load_intent_root(connection, scope, intent_id)? else {
        return Ok(None);
    };
    let target_identity_id = IdentityId::from_opaque(
        OpaqueId::new(row.target_identity_id).map_err(|_| DurableStoreError::Corrupt)?,
    );
    let correlation_id =
        OpaqueId::new(row.correlation_id).map_err(|_| DurableStoreError::Corrupt)?;
    let causation_id = row
        .causation_id
        .map(OpaqueId::new)
        .transpose()
        .map_err(|_| DurableStoreError::Corrupt)?;
    let max_cost_microunits = row
        .max_cost_microunits
        .map(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| DurableStoreError::Corrupt)?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()?;
    let priority_class = row
        .priority_class
        .map(|value| u32::try_from(value).map_err(|_| DurableStoreError::Corrupt))
        .transpose()?;
    let allowed = load_transports(connection, scope, intent_id, "allowed")?;
    let forbidden = load_transports(connection, scope, intent_id, "forbidden")?;
    let total_transports = allowed
        .len()
        .checked_add(forbidden.len())
        .ok_or(DurableStoreError::Corrupt)?;
    if total_transports > MAX_INTENT_TRANSPORT_CONSTRAINTS {
        return Err(DurableStoreError::Corrupt);
    }
    let extensions = load_extensions(connection, scope, intent_id)?;
    let raw = CommunicationIntent {
        intent_id: intent_id.clone(),
        scope: scope.clone(),
        target_identity_id,
        payload: row.payload,
        constraints: IntentConstraints {
            allowed_transport_capabilities: allowed,
            forbidden_transport_capabilities: forbidden,
            privacy_profile: row.privacy_profile,
            region_constraint: row.region_constraint,
            max_cost_microunits,
            priority_class,
        },
        correlation: CorrelationContext {
            correlation_id,
            causation_id,
            idempotency_key: row.idempotency_key,
        },
        extensions,
    };
    let canonical = canonical_communication_intent(&raw).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical != raw {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(Some(canonical))
}

fn load_transports(
    connection: &Connection,
    scope: &TenantScope,
    intent_id: &IntentId,
    disposition: &str,
) -> Result<Vec<String>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT position, capability FROM communication_intent_transports
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND intent_id=?4 AND disposition=?5
             ORDER BY position",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                intent_id.as_opaque().as_str(),
                disposition,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut values = Vec::new();
    for row in rows {
        let (position, capability) = row.map_err(|error| map_sqlite_error(&error))?;
        if position != i64::try_from(values.len()).map_err(|_| DurableStoreError::Corrupt)?
            || values.len() >= MAX_INTENT_TRANSPORT_CONSTRAINTS
        {
            return Err(DurableStoreError::Corrupt);
        }
        values.push(capability);
    }
    Ok(values)
}

fn load_extensions(
    connection: &Connection,
    scope: &TenantScope,
    intent_id: &IntentId,
) -> Result<Vec<ProtocolExtension>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT position, name, critical, payload, length(payload) FROM communication_intent_extensions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND intent_id=?4
             ORDER BY position",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                intent_id.as_opaque().as_str(),
            ],
            |row| {
                let payload_len = row.get::<_, i64>(4)?;
                let payload_limit = i64::try_from(MAX_EXTENSION_PAYLOAD_LEN).unwrap_or(i64::MAX);
                let payload = if payload_len >= 0 && payload_len <= payload_limit {
                    Some(row.get::<_, Vec<u8>>(3)?)
                } else {
                    None
                };
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    payload,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut extensions = Vec::new();
    for row in rows {
        let (position, name, critical, payload) = row.map_err(|error| map_sqlite_error(&error))?;
        let payload = payload.ok_or(DurableStoreError::Corrupt)?;
        if position != i64::try_from(extensions.len()).map_err(|_| DurableStoreError::Corrupt)?
            || extensions.len() >= MAX_PROTOCOL_EXTENSIONS
        {
            return Err(DurableStoreError::Corrupt);
        }
        let critical = match critical {
            0 => false,
            1 => true,
            _ => return Err(DurableStoreError::Corrupt),
        };
        extensions.push(ProtocolExtension {
            name,
            critical,
            payload,
        });
    }
    Ok(extensions)
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
        CommunicationIntentStore, DurableRecordStatus, DurableStoreError, StorageProvider,
    };
    use ucr_model::{
        CommunicationIntent, CorrelationContext, IdentityId, IntentConstraints, IntentId,
        NamespaceId, OpaqueId, ProtocolExtension, TenantId, TenantScope,
    };
    use ucr_protocol::{
        MAX_EXTENSION_PAYLOAD_LEN, MAX_INTENT_POLICY_VALUE_LEN, canonical_communication_intent,
    };

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static DB_SEQUENCE: AtomicU64 = AtomicU64::new(90_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-intent-{}-{sequence}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &std::path::Path {
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

    fn scope(namespace: &str) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-intent")),
            namespace_id: Some(NamespaceId::from_opaque(oid(namespace))),
        }
    }

    fn intent(namespace: &str) -> CommunicationIntent {
        CommunicationIntent {
            intent_id: IntentId::from_opaque(oid("intent-a")),
            scope: scope(namespace),
            target_identity_id: IdentityId::from_opaque(oid("identity-target")),
            payload: b"hello intent".to_vec(),
            constraints: IntentConstraints {
                allowed_transport_capabilities: vec![
                    "ucr.transport.wifi".to_owned(),
                    "ucr.transport.direct".to_owned(),
                ],
                forbidden_transport_capabilities: vec!["ucr.transport.bridge".to_owned()],
                privacy_profile: Some("vendor.example.private".to_owned()),
                region_constraint: Some("region-eu".to_owned()),
                max_cost_microunits: Some(u64::MAX),
                priority_class: Some(u32::MAX),
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-intent"),
                causation_id: Some(oid("causation-intent")),
                idempotency_key: Some("intent-retry-key".to_owned()),
            },
            extensions: vec![
                ProtocolExtension {
                    name: "vendor.example.z".to_owned(),
                    critical: false,
                    payload: b"z".to_vec(),
                },
                ProtocolExtension {
                    name: "ucr.intent.a".to_owned(),
                    critical: false,
                    payload: b"a".to_vec(),
                },
            ],
        }
    }

    #[test]
    fn intent_survives_restart_and_canonical_retries_deduplicate() {
        let db = TestDb::new();
        let first = intent("namespace-a");
        let expected = canonical_communication_intent(&first).expect("canonical intent");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.persist_communication_intent(&first),
                Ok(DurableRecordStatus::Persisted)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened.communication_intent(&first.scope, &first.intent_id),
            Ok(Some(expected))
        );
        let mut reordered = first;
        reordered
            .constraints
            .allowed_transport_capabilities
            .reverse();
        reordered.extensions.reverse();
        assert_eq!(
            reopened.persist_communication_intent(&reordered),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn scoped_intent_id_reuse_with_changed_semantics_conflicts() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let first = intent("namespace-a");
        assert_eq!(
            store.persist_communication_intent(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        let mut changed = first.clone();
        changed.payload.push(b'!');
        assert_eq!(
            store.persist_communication_intent(&changed),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.persist_communication_intent(&first),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn concurrent_conflicting_intents_have_single_winner() {
        let db = TestDb::new();
        {
            let _store = SqliteLocalStore::open(db.path()).expect("initialize store");
        }
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |suffix: u8| {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                let mut value = intent("namespace-a");
                value.payload.push(suffix);
                barrier.wait();
                store.persist_communication_intent(&value)
            })
        };
        let first = spawn(b'1');
        let second = spawn(b'2');
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(DurableRecordStatus::Persisted)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DurableStoreError::Conflict)))
                .count(),
            1
        );
    }

    #[test]
    fn same_intent_id_is_isolated_by_exact_scope() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let first = intent("namespace-a");
        let second = intent("namespace-b");
        assert_eq!(
            store.persist_communication_intent(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_communication_intent(&second),
            Ok(DurableRecordStatus::Persisted)
        );
        assert!(
            store
                .communication_intent(&first.scope, &first.intent_id)
                .expect("load a")
                .is_some()
        );
        assert!(
            store
                .communication_intent(&second.scope, &second.intent_id)
                .expect("load b")
                .is_some()
        );
    }

    #[test]
    fn v15_to_v16_migration_starts_with_no_invented_intents() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current store");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     DROP TABLE external_identity_bindings; DROP TABLE service_audit_operations; DROP TABLE communication_intent_extensions;
                     DROP TABLE communication_intent_transports;
                     DROP TABLE communication_intents;
                     PRAGMA user_version=15;",
                )
                .expect("simulate v15");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v15");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let sample = intent("namespace-a");
        assert_eq!(
            migrated.communication_intent(&sample.scope, &sample.intent_id),
            Ok(None)
        );
    }

    #[test]
    fn malformed_persisted_transport_is_rejected_on_reopen() {
        let db = TestDb::new();
        let value = intent("namespace-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_communication_intent(&value)
                .expect("persist intent");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .execute(
                    "UPDATE communication_intent_transports
                     SET capability='provider-shortcut'
                     WHERE intent_id='intent-a' AND disposition='allowed' AND position=0",
                    [],
                )
                .expect("corrupt capability");
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn orphan_intent_child_is_rejected_on_reopen() {
        let db = TestDb::new();
        {
            let _store = SqliteLocalStore::open(db.path()).expect("open store");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .pragma_update(None, "foreign_keys", "OFF")
                .expect("disable FK only for corruption fixture");
            connection
                .execute(
                    "INSERT INTO communication_intent_transports (
                        tenant_id, namespace_present, namespace_id, intent_id,
                        disposition, position, capability
                     ) VALUES ('tenant-intent',1,'namespace-a','missing-intent',
                               'allowed',0,'ucr.transport.direct')",
                    [],
                )
                .expect("insert orphan child with raw FK-disabled connection");
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn oversized_persisted_root_fields_are_rejected_on_reopen() {
        let db = TestDb::new();
        let value = intent("namespace-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_communication_intent(&value)
                .expect("persist intent");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .execute(
                    "UPDATE communication_intents SET privacy_profile=?1 WHERE intent_id='intent-a'",
                    ["x".repeat(MAX_INTENT_POLICY_VALUE_LEN + 1)],
                )
                .expect("corrupt policy budget");
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn oversized_persisted_extension_payload_is_rejected_on_reopen() {
        let db = TestDb::new();
        let value = intent("namespace-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_communication_intent(&value)
                .expect("persist intent");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .execute(
                    "UPDATE communication_intent_extensions SET payload=?1
                     WHERE intent_id='intent-a' AND position=0",
                    [vec![0_u8; MAX_EXTENSION_PAYLOAD_LEN + 1]],
                )
                .expect("corrupt extension budget");
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn sqlite_application_id_remains_ucr_owned_after_intent_schema() {
        let db = TestDb::new();
        let _store = SqliteLocalStore::open(db.path()).expect("open store");
        let connection = Connection::open(db.path()).expect("raw sqlite");
        let application_id: u32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .expect("application id");
        assert_eq!(application_id, UCR_SQLITE_APPLICATION_ID);
    }
}
