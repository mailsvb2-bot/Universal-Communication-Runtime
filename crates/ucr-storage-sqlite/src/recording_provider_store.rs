use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{
    DurableRecordStatus, DurableStoreError, MAX_RECORDING_PROVIDER_OPERATION_BATCH,
    RecordingProviderOperationRecord, RecordingProviderOperationState, RecordingProviderOperationStore,
    RecordingProviderRequest, RecordingProviderOperation,
};
use ucr_model::{CallId, NamespaceId, OpaqueId, RecordingId, TenantId, TenantScope};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    recording_store, verify_table_columns,
};

pub(super) const V47_OBJECTS_SQL: &str = r"
CREATE TABLE recording_provider_operations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    lifecycle_revision BLOB NOT NULL CHECK(length(lifecycle_revision) = 8),
    operation TEXT NOT NULL CHECK(operation IN ('start','stop','delete')),
    call_id TEXT NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','applied')),
    attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 4294967295),
    available_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(
        tenant_id, namespace_present, namespace_id, recording_id,
        lifecycle_revision, operation
    ),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, recording_id)
        REFERENCES recordings(tenant_id, namespace_present, namespace_id, recording_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE INDEX recording_provider_operations_due
ON recording_provider_operations(state, available_at_unix_ms);
";

pub(super) fn create_v47_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V47_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v47(connection: &Connection) -> Result<(), DurableStoreError> {
    recording_store::verify_v33_objects(connection)?;
    verify_v47_objects(connection)
}

pub(super) fn verify_v47_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "recording_provider_operations",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("recording_id", "TEXT", 1, 4),
            ("lifecycle_revision", "BLOB", 1, 5),
            ("operation", "TEXT", 1, 6),
            ("call_id", "TEXT", 1, 0),
            ("expires_at_unix_ms", "INTEGER", 1, 0),
            ("state", "TEXT", 1, 0),
            ("attempts", "INTEGER", 1, 0),
            ("available_at_unix_ms", "INTEGER", 1, 0),
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
    Ok(())
}

pub(super) fn insert_provider_operation_in_transaction(
    transaction: &Transaction<'_>,
    record: &RecordingProviderOperationRecord,
) -> Result<DurableRecordStatus, DurableStoreError> {
    validate_record(record)?;
    let request = &record.request;
    let namespace = namespace_storage_key(&request.scope);
    let revision = request.lifecycle_revision.to_be_bytes();
    if let Some(existing) = load_operation(
        transaction,
        &request.scope,
        &request.recording_id,
        request.lifecycle_revision,
        request.operation,
    )? {
        return if existing == *record {
            Ok(DurableRecordStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    transaction
        .execute(
            "INSERT INTO recording_provider_operations (
                tenant_id, namespace_present, namespace_id, recording_id,
                lifecycle_revision, operation, call_id, expires_at_unix_ms,
                state, attempts, available_at_unix_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                request.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                request.recording_id.as_opaque().as_str(),
                revision.as_slice(),
                operation_text(request.operation),
                request.call_id.as_opaque().as_str(),
                request.expires_at_unix_ms,
                state_text(record.state),
                i64::from(record.attempts),
                record.available_at_unix_ms,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(DurableRecordStatus::Persisted)
}

impl RecordingProviderOperationStore for SqliteLocalStore {
    fn prepare_recording_provider_operation(
        &self,
        record: &RecordingProviderOperationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let status = insert_provider_operation_in_transaction(&transaction, record)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }

    fn pending_recording_provider_operations(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<RecordingProviderOperationRecord>, DurableStoreError> {
        if limit == 0 || limit > MAX_RECORDING_PROVIDER_OPERATION_BATCH {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT tenant_id, namespace_present, namespace_id, recording_id,
                        lifecycle_revision, operation
                 FROM recording_provider_operations
                 WHERE state='pending' AND available_at_unix_ms <= ?1
                 ORDER BY available_at_unix_ms, tenant_id, namespace_present,
                          namespace_id, recording_id, lifecycle_revision, operation
                 LIMIT ?2",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    now_unix_ms,
                    i64::try_from(limit).map_err(|_| DurableStoreError::InvalidRecord)?
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut keys = Vec::with_capacity(limit);
        for row in rows {
            keys.push(row.map_err(|error| map_sqlite_error(&error))?);
        }
        drop(statement);

        keys.into_iter()
            .map(|(tenant, present, namespace, recording, revision, operation)| {
                let scope = parse_scope(&tenant, present, &namespace)?;
                let revision = decode_u64(&revision)?;
                load_operation(
                    &connection,
                    &scope,
                    &RecordingId::from_opaque(parse_id(&recording)?),
                    revision,
                    parse_operation(&operation)?,
                )?
                .ok_or(DurableStoreError::Corrupt)
            })
            .collect()
    }

    fn mark_recording_provider_operation_applied(
        &self,
        request: &RecordingProviderRequest,
    ) -> Result<(), DurableStoreError> {
        let namespace = namespace_storage_key(&request.scope);
        let revision = request.lifecycle_revision.to_be_bytes();
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "UPDATE recording_provider_operations
                 SET state='applied', attempts=attempts+1
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND recording_id=?4 AND lifecycle_revision=?5 AND operation=?6
                   AND state='pending' AND call_id=?7 AND expires_at_unix_ms=?8",
                params![
                    request.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    request.recording_id.as_opaque().as_str(),
                    revision.as_slice(),
                    operation_text(request.operation),
                    request.call_id.as_opaque().as_str(),
                    request.expires_at_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed == 1 {
            Ok(())
        } else {
            match load_operation(
                &connection,
                &request.scope,
                &request.recording_id,
                request.lifecycle_revision,
                request.operation,
            )? {
                Some(record)
                    if record.request == *request
                        && record.state == RecordingProviderOperationState::Applied =>
                {
                    Ok(())
                }
                _ => Err(DurableStoreError::Conflict),
            }
        }
    }

    fn retry_recording_provider_operation(
        &self,
        request: &RecordingProviderRequest,
        next_attempt_unix_ms: i64,
    ) -> Result<(), DurableStoreError> {
        let namespace = namespace_storage_key(&request.scope);
        let revision = request.lifecycle_revision.to_be_bytes();
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "UPDATE recording_provider_operations
                 SET attempts=attempts+1, available_at_unix_ms=?9
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND recording_id=?4 AND lifecycle_revision=?5 AND operation=?6
                   AND state='pending' AND call_id=?7 AND expires_at_unix_ms=?8
                   AND available_at_unix_ms < ?9 AND attempts < 4294967295",
                params![
                    request.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    request.recording_id.as_opaque().as_str(),
                    revision.as_slice(),
                    operation_text(request.operation),
                    request.call_id.as_opaque().as_str(),
                    request.expires_at_unix_ms,
                    next_attempt_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(DurableStoreError::Conflict)
        }
    }
}

fn load_operation(
    connection: &Connection,
    scope: &TenantScope,
    recording_id: &RecordingId,
    lifecycle_revision: u64,
    operation: RecordingProviderOperation,
) -> Result<Option<RecordingProviderOperationRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let revision = lifecycle_revision.to_be_bytes();
    connection
        .query_row(
            "SELECT call_id, expires_at_unix_ms, state, attempts, available_at_unix_ms
             FROM recording_provider_operations
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND recording_id=?4 AND lifecycle_revision=?5 AND operation=?6",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording_id.as_opaque().as_str(),
                revision.as_slice(),
                operation_text(operation),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(call_id, expires_at_unix_ms, state, attempts, available_at_unix_ms)| {
            let record = RecordingProviderOperationRecord {
                request: RecordingProviderRequest {
                    scope: scope.clone(),
                    recording_id: recording_id.clone(),
                    call_id: CallId::from_opaque(parse_id(&call_id)?),
                    lifecycle_revision,
                    operation,
                    expires_at_unix_ms,
                },
                state: parse_state(&state)?,
                attempts: u32::try_from(attempts).map_err(|_| DurableStoreError::Corrupt)?,
                available_at_unix_ms,
            };
            validate_record(&record)?;
            Ok(record)
        })
        .transpose()
}

fn validate_record(record: &RecordingProviderOperationRecord) -> Result<(), DurableStoreError> {
    if record.request.lifecycle_revision == 0
        || record.request.expires_at_unix_ms < 0
        || record.available_at_unix_ms < 0
        || (record.state == RecordingProviderOperationState::Applied && record.attempts == 0)
    {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

const fn operation_text(operation: RecordingProviderOperation) -> &'static str {
    match operation {
        RecordingProviderOperation::Start => "start",
        RecordingProviderOperation::Stop => "stop",
        RecordingProviderOperation::Delete => "delete",
    }
}

fn parse_operation(value: &str) -> Result<RecordingProviderOperation, DurableStoreError> {
    match value {
        "start" => Ok(RecordingProviderOperation::Start),
        "stop" => Ok(RecordingProviderOperation::Stop),
        "delete" => Ok(RecordingProviderOperation::Delete),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn state_text(state: RecordingProviderOperationState) -> &'static str {
    match state {
        RecordingProviderOperationState::Pending => "pending",
        RecordingProviderOperationState::Applied => "applied",
    }
}

fn parse_state(value: &str) -> Result<RecordingProviderOperationState, DurableStoreError> {
    match value {
        "pending" => Ok(RecordingProviderOperationState::Pending),
        "applied" => Ok(RecordingProviderOperationState::Applied),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}

fn parse_scope(
    tenant: &str,
    namespace_present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match (namespace_present, namespace.is_empty()) {
        (0, true) => None,
        (1, false) => Some(NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}
