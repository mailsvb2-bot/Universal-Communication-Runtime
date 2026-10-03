use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{
    DurableRecordStatus, DurableStoreError, MAX_RECORDING_PROVIDER_OPERATION_BATCH,
    RecordingProviderOperation, RecordingProviderOperationRecord, RecordingProviderOperationState,
    RecordingProviderOperationStore, RecordingProviderRequest,
};
use ucr_model::{
    CallId, EventEnvelope, NamespaceId, OpaqueId, RecordingId, TenantId, TenantScope,
};

use super::{
    SqliteLocalStore, event_journal, map_schema_change_error, map_sqlite_error,
    namespace_storage_key, verify_table_columns,
};

pub(super) const V47_OBJECTS_SQL: &str = r"
CREATE TABLE IF NOT EXISTS recording_provider_operations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    lifecycle_revision BLOB NOT NULL CHECK(length(lifecycle_revision) = 8),
    operation TEXT NOT NULL CHECK(operation IN ('start','stop','delete')),
    call_id TEXT NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','applied','failed')),
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

CREATE INDEX IF NOT EXISTS recording_provider_operations_due
ON recording_provider_operations(state, available_at_unix_ms);
";

pub(super) fn create_v47_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V47_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
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

pub(super) fn create_v48_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE recording_provider_operations
                 ADD COLUMN ready_event_emitted INTEGER NOT NULL DEFAULT 0
                 CHECK(ready_event_emitted IN (0,1));
             CREATE INDEX IF NOT EXISTS recording_provider_ready_recovery
                 ON recording_provider_operations(
                     state, operation, ready_event_emitted, tenant_id, namespace_present,
                     namespace_id, recording_id, lifecycle_revision
                 );",
        )
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v48_objects(connection: &Connection) -> Result<(), DurableStoreError> {
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
            ("ready_event_emitted", "INTEGER", 1, 0),
        ],
    )?;
    let invalid_marker: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM recording_provider_operations
             WHERE ready_event_emitted NOT IN (0,1)
                OR (ready_event_emitted=1 AND (operation<>'stop' OR state<>'applied'))",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid_marker != 0 {
        return Err(DurableStoreError::Corrupt);
    }
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
            .map(
                |(tenant, present, namespace, recording, revision, operation)| {
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
                },
            )
            .collect()
    }

    fn recording_provider_operation(
        &self,
        request: &RecordingProviderRequest,
    ) -> Result<Option<RecordingProviderOperationRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        let record = load_operation(
            &connection,
            &request.scope,
            &request.recording_id,
            request.lifecycle_revision,
            request.operation,
        )?;
        match record {
            Some(record) if record.request == *request => Ok(Some(record)),
            Some(_) => Err(DurableStoreError::Conflict),
            None => Ok(None),
        }
    }

    fn latest_recording_provider_operation(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        operation: RecordingProviderOperation,
        max_lifecycle_revision: u64,
    ) -> Result<Option<RecordingProviderOperationRecord>, DurableStoreError> {
        if max_lifecycle_revision == 0 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(scope);
        let max_revision = max_lifecycle_revision.to_be_bytes();
        let connection = self.lock_connection()?;
        let revision = connection
            .query_row(
                "SELECT lifecycle_revision
                 FROM recording_provider_operations
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND recording_id=?4 AND operation=?5 AND lifecycle_revision<=?6
                 ORDER BY lifecycle_revision DESC
                 LIMIT 1",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    recording_id.as_opaque().as_str(),
                    operation_text(operation),
                    max_revision.as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        let Some(revision) = revision else {
            return Ok(None);
        };
        let revision = decode_u64(&revision)?;
        load_operation(&connection, scope, recording_id, revision, operation)?
            .map(Some)
            .ok_or(DurableStoreError::Corrupt)
    }

    fn recording_provider_stops_needing_ready_event(
        &self,
        limit: usize,
    ) -> Result<Vec<RecordingProviderOperationRecord>, DurableStoreError> {
        if limit == 0 || limit > MAX_RECORDING_PROVIDER_OPERATION_BATCH {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT tenant_id, namespace_present, namespace_id, recording_id,
                        lifecycle_revision
                 FROM recording_provider_operations
                 WHERE state='applied' AND operation='stop' AND ready_event_emitted=0
                 ORDER BY tenant_id, namespace_present, namespace_id, recording_id,
                          lifecycle_revision
                 LIMIT ?1",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![i64::try_from(limit).map_err(|_| DurableStoreError::InvalidRecord)?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
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
            .map(|(tenant, present, namespace, recording, revision)| {
                let scope = parse_scope(&tenant, present, &namespace)?;
                let revision = decode_u64(&revision)?;
                let record = load_operation(
                    &connection,
                    &scope,
                    &RecordingId::from_opaque(parse_id(&recording)?),
                    revision,
                    RecordingProviderOperation::Stop,
                )?
                .ok_or(DurableStoreError::Corrupt)?;
                if record.state != RecordingProviderOperationState::Applied {
                    return Err(DurableStoreError::Corrupt);
                }
                Ok(record)
            })
            .collect()
    }

    fn commit_recording_provider_stop_ready_event(
        &self,
        request: &RecordingProviderRequest,
        event: &EventEnvelope,
    ) -> Result<(), DurableStoreError> {
        if request.operation != RecordingProviderOperation::Stop
            || event.scope != request.scope
            || event.event_type != "ucr.recording.ready"
            || event.logical_order != request.lifecycle_revision
            || event.wall_time_unix_ms < 0
        {
            return Err(DurableStoreError::InvalidRecord);
        }

        let namespace = namespace_storage_key(&request.scope);
        let revision = request.lifecycle_revision.to_be_bytes();
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let record = load_operation(
            &transaction,
            &request.scope,
            &request.recording_id,
            request.lifecycle_revision,
            RecordingProviderOperation::Stop,
        )?
        .ok_or(DurableStoreError::Conflict)?;
        if record.request != *request {
            return Err(DurableStoreError::Conflict);
        }
        let marker: i64 = transaction
            .query_row(
                "SELECT ready_event_emitted
                 FROM recording_provider_operations
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND recording_id=?4 AND lifecycle_revision=?5 AND operation='stop'",
                params![
                    request.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    request.recording_id.as_opaque().as_str(),
                    revision.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;

        match record.state {
            RecordingProviderOperationState::Pending => {
                if marker != 0 {
                    return Err(DurableStoreError::Corrupt);
                }
                let changed = transaction
                    .execute(
                        "UPDATE recording_provider_operations
                         SET state='applied', attempts=attempts+1, ready_event_emitted=1
                         WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                           AND recording_id=?4 AND lifecycle_revision=?5 AND operation='stop'
                           AND state='pending' AND ready_event_emitted=0
                           AND call_id=?6 AND expires_at_unix_ms=?7",
                        params![
                            request.scope.tenant_id.as_opaque().as_str(),
                            namespace.present,
                            namespace.value,
                            request.recording_id.as_opaque().as_str(),
                            revision.as_slice(),
                            request.call_id.as_opaque().as_str(),
                            request.expires_at_unix_ms,
                        ],
                    )
                    .map_err(|error| map_sqlite_error(&error))?;
                if changed != 1 {
                    return Err(DurableStoreError::Conflict);
                }
            }
            RecordingProviderOperationState::Applied => {
                if marker == 0 {
                    let changed = transaction
                        .execute(
                            "UPDATE recording_provider_operations
                             SET ready_event_emitted=1
                             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                               AND recording_id=?4 AND lifecycle_revision=?5 AND operation='stop'
                               AND state='applied' AND ready_event_emitted=0
                               AND call_id=?6 AND expires_at_unix_ms=?7",
                            params![
                                request.scope.tenant_id.as_opaque().as_str(),
                                namespace.present,
                                namespace.value,
                                request.recording_id.as_opaque().as_str(),
                                revision.as_slice(),
                                request.call_id.as_opaque().as_str(),
                                request.expires_at_unix_ms,
                            ],
                        )
                        .map_err(|error| map_sqlite_error(&error))?;
                    if changed != 1 {
                        return Err(DurableStoreError::Conflict);
                    }
                } else if marker != 1 {
                    return Err(DurableStoreError::Corrupt);
                }
            }
            RecordingProviderOperationState::Failed => return Err(DurableStoreError::Conflict),
        }

        let _ = event_journal::append_event_in_transaction(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
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

    fn mark_recording_provider_operation_failed(
        &self,
        request: &RecordingProviderRequest,
    ) -> Result<(), DurableStoreError> {
        let namespace = namespace_storage_key(&request.scope);
        let revision = request.lifecycle_revision.to_be_bytes();
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "UPDATE recording_provider_operations
                 SET state='failed', attempts=attempts+1
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND recording_id=?4 AND lifecycle_revision=?5 AND operation=?6
                   AND state='pending' AND call_id=?7 AND expires_at_unix_ms=?8
                   AND attempts < 4294967295",
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
                        && record.state == RecordingProviderOperationState::Failed =>
                {
                    Ok(())
                }
                _ => Err(DurableStoreError::Conflict),
            }
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
        .map(
            |(call_id, expires_at_unix_ms, state, attempts, available_at_unix_ms)| {
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
            },
        )
        .transpose()
}

fn validate_record(record: &RecordingProviderOperationRecord) -> Result<(), DurableStoreError> {
    if record.request.lifecycle_revision == 0
        || record.request.expires_at_unix_ms < 0
        || record.available_at_unix_ms < 0
        || (matches!(
            record.state,
            RecordingProviderOperationState::Applied | RecordingProviderOperationState::Failed
        ) && record.attempts == 0)
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
        RecordingProviderOperationState::Failed => "failed",
    }
}

fn parse_state(value: &str) -> Result<RecordingProviderOperationState, DurableStoreError> {
    match value {
        "pending" => Ok(RecordingProviderOperationState::Pending),
        "applied" => Ok(RecordingProviderOperationState::Applied),
        "failed" => Ok(RecordingProviderOperationState::Failed),
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant").expect("tenant")),
            namespace_id: None,
        }
    }

    fn request(revision: u64, operation: RecordingProviderOperation) -> RecordingProviderRequest {
        RecordingProviderRequest {
            scope: scope(),
            recording_id: RecordingId::from_opaque(OpaqueId::new("recording").expect("recording")),
            call_id: CallId::from_opaque(OpaqueId::new("call").expect("call")),
            lifecycle_revision: revision,
            operation,
            expires_at_unix_ms: 50_000,
        }
    }

    fn store() -> SqliteLocalStore {
        let connection = Connection::open_in_memory().expect("memory");
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("foreign keys");
        connection
            .execute_batch(
                "CREATE TABLE recordings (
                    tenant_id TEXT NOT NULL,
                    namespace_present INTEGER NOT NULL,
                    namespace_id TEXT NOT NULL,
                    recording_id TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, namespace_present, namespace_id, recording_id)
                ) WITHOUT ROWID;",
            )
            .expect("recordings table");
        {
            let transaction = connection.unchecked_transaction().expect("transaction");
            event_journal::create_v8_objects(&transaction).expect("event journal");
            create_v47_objects(&transaction).expect("v47 objects");
            create_v48_objects(&transaction).expect("v48 objects");
            transaction.commit().expect("commit schema");
        }
        connection
            .execute(
                "INSERT INTO recordings
                 (tenant_id, namespace_present, namespace_id, recording_id)
                 VALUES ('tenant',0,'','recording')",
                [],
            )
            .expect("recording row");
        SqliteLocalStore {
            connection: Mutex::new(connection),
        }
    }

    #[test]
    fn exact_prepare_deduplicates_and_changed_reuse_conflicts() {
        let store = store();
        let record = RecordingProviderOperationRecord {
            request: request(2, RecordingProviderOperation::Start),
            state: RecordingProviderOperationState::Pending,
            attempts: 0,
            available_at_unix_ms: 100,
        };
        assert_eq!(
            store.prepare_recording_provider_operation(&record),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.prepare_recording_provider_operation(&record),
            Ok(DurableRecordStatus::Duplicate)
        );

        let mut changed = record.clone();
        changed.available_at_unix_ms = 101;
        assert_eq!(
            store.prepare_recording_provider_operation(&changed),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn due_retry_and_applied_state_are_restart_safe_semantics() {
        let store = store();
        let record = RecordingProviderOperationRecord {
            request: request(3, RecordingProviderOperation::Stop),
            state: RecordingProviderOperationState::Pending,
            attempts: 0,
            available_at_unix_ms: 100,
        };
        store
            .prepare_recording_provider_operation(&record)
            .expect("prepare");

        assert!(
            store
                .pending_recording_provider_operations(99, 10)
                .expect("before due")
                .is_empty()
        );
        let due = store
            .pending_recording_provider_operations(100, 10)
            .expect("due");
        assert_eq!(due, vec![record.clone()]);

        store
            .retry_recording_provider_operation(&record.request, 200)
            .expect("retry");
        let retried = store
            .pending_recording_provider_operations(200, 10)
            .expect("retried");
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].attempts, 1);
        assert_eq!(retried[0].available_at_unix_ms, 200);

        store
            .mark_recording_provider_operation_applied(&record.request)
            .expect("applied");
        assert!(
            store
                .pending_recording_provider_operations(1_000, 10)
                .expect("after applied")
                .is_empty()
        );
        store
            .mark_recording_provider_operation_applied(&record.request)
            .expect("applied retry is idempotent");
        let applied = store
            .recording_provider_operation(&record.request)
            .expect("load applied operation")
            .expect("applied operation");
        assert_eq!(applied.state, RecordingProviderOperationState::Applied);
        assert_eq!(applied.request, record.request);
    }

    fn ready_event(request: &RecordingProviderRequest, payload: &[u8]) -> EventEnvelope {
        use ucr_model::{
            ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventId,
            IdentityId, PrincipalId, ProtocolVersion,
        };

        EventEnvelope {
            event_id: EventId::from_opaque(
                OpaqueId::new(format!(
                    "ready-event-{}",
                    request.lifecycle_revision
                ))
                .expect("event id"),
            ),
            scope: request.scope.clone(),
            event_type: "ucr.recording.ready".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(OpaqueId::new("ready-actor").expect("actor")),
                kind: ActorKind::System,
                on_behalf_of: Some(PrincipalId::from_opaque(
                    OpaqueId::new("ready-requester").expect("requester"),
                )),
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(OpaqueId::new("ready-device").expect("device")),
                identity_id: IdentityId::from_opaque(
                    OpaqueId::new("ready-identity").expect("identity"),
                ),
            },
            wall_time_unix_ms: 200,
            logical_order: request.lifecycle_revision,
            correlation: CorrelationContext {
                correlation_id: OpaqueId::new("ready-correlation").expect("correlation"),
                causation_id: None,
                idempotency_key: Some("ready".to_owned()),
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn stop_ready_event_commit_is_atomic_and_idempotent() {
        let store = store();
        let record = RecordingProviderOperationRecord {
            request: request(3, RecordingProviderOperation::Stop),
            state: RecordingProviderOperationState::Pending,
            attempts: 0,
            available_at_unix_ms: 100,
        };
        store
            .prepare_recording_provider_operation(&record)
            .expect("prepare stop");
        let event = ready_event(&record.request, b"ready");
        store
            .commit_recording_provider_stop_ready_event(&record.request, &event)
            .expect("commit ready event");
        store
            .commit_recording_provider_stop_ready_event(&record.request, &event)
            .expect("exact ready retry");

        let applied = store
            .recording_provider_operation(&record.request)
            .expect("load stop")
            .expect("stop");
        assert_eq!(applied.state, RecordingProviderOperationState::Applied);
        assert_eq!(applied.attempts, 1);
        assert!(
            store
                .recording_provider_stops_needing_ready_event(10)
                .expect("recovery view")
                .is_empty()
        );
        let persisted = ucr_core::EventJournalStore::event(
            &store,
            &event.scope,
            &event.event_id,
        )
        .expect("event lookup")
        .expect("ready event");
        assert_eq!(persisted, event);
    }

    #[test]
    fn conflicting_ready_event_rolls_back_stop_application() {
        let store = store();
        let record = RecordingProviderOperationRecord {
            request: request(3, RecordingProviderOperation::Stop),
            state: RecordingProviderOperationState::Pending,
            attempts: 0,
            available_at_unix_ms: 100,
        };
        store
            .prepare_recording_provider_operation(&record)
            .expect("prepare stop");
        let expected = ready_event(&record.request, b"expected");
        let mut conflicting = expected.clone();
        conflicting.payload = b"conflict".to_vec();
        ucr_core::EventJournalStore::append_event(&store, &conflicting).expect("seed conflict");

        assert_eq!(
            store.commit_recording_provider_stop_ready_event(&record.request, &expected),
            Err(DurableStoreError::Conflict)
        );
        let pending = store
            .recording_provider_operation(&record.request)
            .expect("load stop")
            .expect("stop");
        assert_eq!(pending.state, RecordingProviderOperationState::Pending);
        assert_eq!(pending.attempts, 0);
    }

    #[test]
    fn legacy_applied_stop_is_discovered_for_ready_recovery() {
        let store = store();
        let record = RecordingProviderOperationRecord {
            request: request(3, RecordingProviderOperation::Stop),
            state: RecordingProviderOperationState::Pending,
            attempts: 0,
            available_at_unix_ms: 100,
        };
        store
            .prepare_recording_provider_operation(&record)
            .expect("prepare stop");
        store
            .mark_recording_provider_operation_applied(&record.request)
            .expect("legacy applied stop");

        let due = store
            .recording_provider_stops_needing_ready_event(10)
            .expect("recovery candidates");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].request, record.request);

        let event = ready_event(&record.request, b"recovered");
        store
            .commit_recording_provider_stop_ready_event(&record.request, &event)
            .expect("backfill event");
        assert!(
            store
                .recording_provider_stops_needing_ready_event(10)
                .expect("recovery candidates after backfill")
                .is_empty()
        );
    }

    #[test]
    fn latest_operation_before_revision_finds_start_that_authorized_active_capture() {
        let store = store();
        for revision in [2_u64, 5] {
            let record = RecordingProviderOperationRecord {
                request: request(revision, RecordingProviderOperation::Start),
                state: RecordingProviderOperationState::Applied,
                attempts: 1,
                available_at_unix_ms: 100,
            };
            store
                .prepare_recording_provider_operation(&record)
                .expect("prepare");
        }

        let current = request(7, RecordingProviderOperation::Start);
        let latest = store
            .latest_recording_provider_operation(
                &current.scope,
                &current.recording_id,
                RecordingProviderOperation::Start,
                7,
            )
            .expect("latest operation")
            .expect("start operation");
        assert_eq!(latest.request.lifecycle_revision, 5);
        assert_eq!(latest.state, RecordingProviderOperationState::Applied);

        let before_first = store
            .latest_recording_provider_operation(
                &current.scope,
                &current.recording_id,
                RecordingProviderOperation::Start,
                1,
            )
            .expect("before first");
        assert!(before_first.is_none());
    }

    #[test]
    fn pending_batch_is_bounded_and_deterministic() {
        let store = store();
        for (revision, operation) in [
            (4, RecordingProviderOperation::Delete),
            (2, RecordingProviderOperation::Start),
            (3, RecordingProviderOperation::Stop),
        ] {
            store
                .prepare_recording_provider_operation(&RecordingProviderOperationRecord {
                    request: request(revision, operation),
                    state: RecordingProviderOperationState::Pending,
                    attempts: 0,
                    available_at_unix_ms: i64::try_from(revision).expect("revision"),
                })
                .expect("prepare");
        }
        let due = store
            .pending_recording_provider_operations(10, 2)
            .expect("batch");
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].request.lifecycle_revision, 2);
        assert_eq!(due[1].request.lifecycle_revision, 3);
        assert_eq!(
            store.pending_recording_provider_operations(10, 0),
            Err(DurableStoreError::InvalidRecord)
        );
    }
}
