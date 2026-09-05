use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableStoreError, ServiceAuditStore, ServiceQuotaConsumeError, ServiceQuotaStore};
use ucr_model::{
    AuditRecordId, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef,
    ScopedPrincipal, ServiceAuditOperationRef, ServiceAuditOutcome, ServiceAuditRecord,
    ServiceCredentialId, ServiceQuotaPolicy, TenantId, TenantScope,
};
use ucr_protocol::{
    MAX_SERVICE_AUDIT_READ_ITEMS, service_audit_hash, validate_service_audit_operation_ref,
    validate_service_audit_record, validate_service_quota_policy,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V14_OBJECTS_SQL: &str = "
CREATE TABLE service_quota_policies (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    max_requests INTEGER NOT NULL CHECK(max_requests > 0),
    window_ms INTEGER NOT NULL CHECK(window_ms > 0),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, principal_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE service_quota_usage (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    window_start_unix_ms INTEGER NOT NULL CHECK(window_start_unix_ms >= 0),
    used_requests INTEGER NOT NULL CHECK(used_requests >= 0),
    last_observed_unix_ms INTEGER NOT NULL CHECK(last_observed_unix_ms >= 0),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, principal_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, principal_id)
        REFERENCES service_quota_policies(tenant_id, namespace_present, namespace_id, principal_id)
        ON DELETE CASCADE,
    CHECK(last_observed_unix_ms >= window_start_unix_ms),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE service_audit_records (
    audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL UNIQUE,
    credential_id TEXT NOT NULL,
    presented_tenant_id TEXT NOT NULL,
    presented_namespace_present INTEGER NOT NULL CHECK(presented_namespace_present IN (0, 1)),
    presented_namespace_id TEXT NOT NULL,
    subject_present INTEGER NOT NULL CHECK(subject_present IN (0, 1)),
    subject_principal_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    resource_tenant_id TEXT NOT NULL,
    resource_namespace_present INTEGER NOT NULL CHECK(resource_namespace_present IN (0, 1)),
    resource_namespace_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN (
        'authentication_failed','authentication_unavailable','rate_limited','quota_unavailable',
        'permission_denied','authorization_unavailable','authorized'
    )),
    occurred_at_unix_ms INTEGER NOT NULL CHECK(occurred_at_unix_ms >= 0),
    previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
    record_hash BLOB NOT NULL CHECK(length(record_hash) = 32),
    CHECK((presented_namespace_present = 0 AND presented_namespace_id = '') OR
          (presented_namespace_present = 1 AND presented_namespace_id <> '')),
    CHECK((resource_namespace_present = 0 AND resource_namespace_id = '') OR
          (resource_namespace_present = 1 AND resource_namespace_id <> '')),
    CHECK((subject_present = 0 AND subject_principal_id = '') OR
          (subject_present = 1 AND subject_principal_id <> ''))
);

CREATE INDEX service_audit_scope_sequence
ON service_audit_records(
    presented_tenant_id, presented_namespace_present, presented_namespace_id, audit_seq
);

CREATE TRIGGER service_audit_no_update
BEFORE UPDATE ON service_audit_records
BEGIN SELECT RAISE(ABORT, 'service audit is append-only'); END;

CREATE TRIGGER service_audit_no_delete
BEFORE DELETE ON service_audit_records
BEGIN SELECT RAISE(ABORT, 'service audit is append-only'); END;
";

const V17_OBJECTS_SQL: &str = "
CREATE TABLE service_audit_operations (
    audit_seq INTEGER PRIMARY KEY,
    operation_kind TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    FOREIGN KEY(audit_seq) REFERENCES service_audit_records(audit_seq) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX service_audit_operation_lookup
ON service_audit_operations(operation_kind, operation_id, audit_seq);

CREATE TRIGGER service_audit_operation_no_update
BEFORE UPDATE ON service_audit_operations
BEGIN SELECT RAISE(ABORT, 'service audit operation is append-only'); END;

CREATE TRIGGER service_audit_operation_no_delete
BEFORE DELETE ON service_audit_operations
BEGIN SELECT RAISE(ABORT, 'service audit operation is append-only'); END;
";

pub(super) fn create_v17_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V17_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn create_v14_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V14_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v14(connection: &Connection) -> Result<(), DurableStoreError> {
    super::service_credential_store::verify_schema_v13(connection)?;
    verify_table_columns(
        connection,
        "service_quota_policies",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("principal_id", "TEXT", 1, 4),
            ("max_requests", "INTEGER", 1, 0),
            ("window_ms", "INTEGER", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "service_quota_usage",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("principal_id", "TEXT", 1, 4),
            ("window_start_unix_ms", "INTEGER", 1, 0),
            ("used_requests", "INTEGER", 1, 0),
            ("last_observed_unix_ms", "INTEGER", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "service_audit_records",
        &[
            ("audit_seq", "INTEGER", 0, 1),
            ("audit_id", "TEXT", 1, 0),
            ("credential_id", "TEXT", 1, 0),
            ("presented_tenant_id", "TEXT", 1, 0),
            ("presented_namespace_present", "INTEGER", 1, 0),
            ("presented_namespace_id", "TEXT", 1, 0),
            ("subject_present", "INTEGER", 1, 0),
            ("subject_principal_id", "TEXT", 1, 0),
            ("permission", "TEXT", 1, 0),
            ("resource_tenant_id", "TEXT", 1, 0),
            ("resource_namespace_present", "INTEGER", 1, 0),
            ("resource_namespace_id", "TEXT", 1, 0),
            ("outcome", "TEXT", 1, 0),
            ("occurred_at_unix_ms", "INTEGER", 1, 0),
            ("previous_hash", "BLOB", 1, 0),
            ("record_hash", "BLOB", 1, 0),
        ],
    )?;
    verify_schema_object(connection, "index", "service_audit_scope_sequence")?;
    verify_schema_object(connection, "trigger", "service_audit_no_update")?;
    verify_schema_object(connection, "trigger", "service_audit_no_delete")?;
    verify_quota_rows(connection)?;
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error))?;
    if schema_version >= 17 {
        verify_audit_chain_v17(connection)
    } else {
        verify_audit_chain_v1(connection)
    }
}

pub(super) fn verify_schema_v17(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "service_audit_operations",
        &[
            ("audit_seq", "INTEGER", 1, 1),
            ("operation_kind", "TEXT", 1, 0),
            ("operation_id", "TEXT", 1, 0),
        ],
    )?;
    verify_schema_object(connection, "index", "service_audit_operation_lookup")?;
    verify_schema_object(connection, "trigger", "service_audit_operation_no_update")?;
    verify_schema_object(connection, "trigger", "service_audit_operation_no_delete")?;
    super::intent_store::verify_schema_v16(connection)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|error| map_sqlite_error(&error))?;
    if foreign_key_violations != 0 {
        return Err(DurableStoreError::Corrupt);
    }
    verify_audit_chain_v17(connection)
}

impl ServiceQuotaStore for SqliteLocalStore {
    fn set_service_quota_policy(
        &self,
        policy: &ServiceQuotaPolicy,
    ) -> Result<(), DurableStoreError> {
        validate_service_quota_policy(policy).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&policy.subject.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let existing = transaction
            .query_row(
                "SELECT max_requests, window_ms FROM service_quota_policies
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND principal_id=?4",
                params![
                    policy.subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    policy.subject.principal.principal_id.as_opaque().as_str(),
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        let requested = (
            i64::try_from(policy.max_requests).map_err(|_| DurableStoreError::InvalidRecord)?,
            i64::try_from(policy.window_ms).map_err(|_| DurableStoreError::InvalidRecord)?,
        );
        if existing == Some(requested) {
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO service_quota_policies (
                    tenant_id, namespace_present, namespace_id, principal_id, max_requests, window_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(tenant_id, namespace_present, namespace_id, principal_id)
                 DO UPDATE SET max_requests=excluded.max_requests, window_ms=excluded.window_ms",
                params![
                    policy.subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    policy.subject.principal.principal_id.as_opaque().as_str(),
                    requested.0,
                    requested.1,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .execute(
                "DELETE FROM service_quota_usage
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND principal_id=?4",
                params![
                    policy.subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    policy.subject.principal.principal_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn service_quota_policy(
        &self,
        subject: &ScopedPrincipal,
    ) -> Result<Option<ServiceQuotaPolicy>, DurableStoreError> {
        validate_service_subject(subject)?;
        let connection = self.lock_connection()?;
        load_quota_policy(&connection, subject)
    }

    fn consume_service_request(
        &self,
        subject: &ScopedPrincipal,
        now_unix_ms: i64,
    ) -> Result<(), ServiceQuotaConsumeError> {
        validate_service_subject(subject).map_err(ServiceQuotaConsumeError::Store)?;
        if now_unix_ms < 0 {
            return Err(ServiceQuotaConsumeError::ClockRollback);
        }
        let namespace = namespace_storage_key(&subject.scope);
        let mut connection = self
            .lock_connection()
            .map_err(ServiceQuotaConsumeError::Store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))?;
        let policy = load_quota_policy(&transaction, subject)
            .map_err(ServiceQuotaConsumeError::Store)?
            .ok_or(ServiceQuotaConsumeError::NotConfigured)?;
        let window_ms = i64::try_from(policy.window_ms)
            .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
        let window_start = now_unix_ms - now_unix_ms.rem_euclid(window_ms);
        let usage = transaction
            .query_row(
                "SELECT window_start_unix_ms, used_requests, last_observed_unix_ms
                 FROM service_quota_usage
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND principal_id=?4",
                params![
                    subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subject.principal.principal_id.as_opaque().as_str(),
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()
            .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))?;
        let (mut stored_window, mut used, last_observed) =
            usage.unwrap_or((window_start, 0, now_unix_ms));
        if now_unix_ms < last_observed || window_start < stored_window {
            return Err(ServiceQuotaConsumeError::ClockRollback);
        }
        if window_start > stored_window {
            stored_window = window_start;
            used = 0;
        }
        let max_requests = i64::try_from(policy.max_requests)
            .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
        if used >= max_requests {
            transaction
                .execute(
                    "UPDATE service_quota_usage SET last_observed_unix_ms=?5
                     WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND principal_id=?4",
                    params![
                        subject.scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        subject.principal.principal_id.as_opaque().as_str(),
                        now_unix_ms,
                    ],
                )
                .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))?;
            transaction
                .commit()
                .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))?;
            let retry_after_ms = u64::try_from(
                stored_window
                    .checked_add(window_ms)
                    .ok_or(ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?
                    .saturating_sub(now_unix_ms),
            )
            .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
            return Err(ServiceQuotaConsumeError::RateLimited { retry_after_ms });
        }
        let next_used = used
            .checked_add(1)
            .ok_or(ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
        transaction
            .execute(
                "INSERT INTO service_quota_usage (
                    tenant_id, namespace_present, namespace_id, principal_id,
                    window_start_unix_ms, used_requests, last_observed_unix_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(tenant_id, namespace_present, namespace_id, principal_id)
                 DO UPDATE SET window_start_unix_ms=excluded.window_start_unix_ms,
                               used_requests=excluded.used_requests,
                               last_observed_unix_ms=excluded.last_observed_unix_ms",
                params![
                    subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subject.principal.principal_id.as_opaque().as_str(),
                    stored_window,
                    next_used,
                    now_unix_ms,
                ],
            )
            .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))?;
        transaction
            .commit()
            .map_err(|error| ServiceQuotaConsumeError::Store(map_sqlite_error(&error)))
    }
}

impl ServiceAuditStore for SqliteLocalStore {
    fn append_service_audit(&self, record: &ServiceAuditRecord) -> Result<(), DurableStoreError> {
        validate_service_audit_record(record).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_audit_by_id(&transaction, &record.audit_id)? {
            return if existing == *record {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let previous_hash = transaction
            .query_row(
                "SELECT record_hash FROM service_audit_records ORDER BY audit_seq DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?
            .map_or(Ok([0_u8; 32]), |value| decode_hash(&value))?;
        let record_hash = service_audit_hash(previous_hash, record);
        insert_audit_record(&transaction, record, previous_hash, record_hash)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn service_audit_records(
        &self,
        scope: &TenantScope,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_SERVICE_AUDIT_READ_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(scope);
        let connection = self.lock_connection()?;
        let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut statement = connection
            .prepare(
                "SELECT r.audit_id, r.credential_id, r.presented_tenant_id,
                        r.presented_namespace_present, r.presented_namespace_id,
                        r.subject_present, r.subject_principal_id, r.permission,
                        r.resource_tenant_id, r.resource_namespace_present, r.resource_namespace_id,
                        r.outcome, r.occurred_at_unix_ms, o.operation_kind, o.operation_id
                 FROM service_audit_records r
                 LEFT JOIN service_audit_operations o ON o.audit_seq = r.audit_seq
                 WHERE r.presented_tenant_id=?1 AND r.presented_namespace_present=?2
                   AND r.presented_namespace_id=?3
                 ORDER BY r.audit_seq DESC LIMIT ?4",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    limit
                ],
                |row| {
                    Ok((
                        decode_audit_row(row)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, Option<String>>(14)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut records = rows
            .map(|row| {
                let (tuple, operation_kind, operation_id) =
                    row.map_err(|error| map_sqlite_error(&error))?;
                decode_audit_tuple_with_operation(tuple, operation_kind, operation_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        records.reverse();
        Ok(records)
    }

    fn service_audit_records_for_operation(
        &self,
        scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_SERVICE_AUDIT_READ_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        validate_service_audit_operation_ref(operation)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let connection = self.lock_connection()?;
        let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut statement = connection
            .prepare(
                "SELECT r.audit_id, r.credential_id, r.presented_tenant_id,
                        r.presented_namespace_present, r.presented_namespace_id,
                        r.subject_present, r.subject_principal_id, r.permission,
                        r.resource_tenant_id, r.resource_namespace_present, r.resource_namespace_id,
                        r.outcome, r.occurred_at_unix_ms
                 FROM service_audit_operations o
                 JOIN service_audit_records r ON r.audit_seq = o.audit_seq
                 WHERE r.presented_tenant_id=?1 AND r.presented_namespace_present=?2
                   AND r.presented_namespace_id=?3
                   AND o.operation_kind=?4 AND o.operation_id=?5
                 ORDER BY r.audit_seq DESC LIMIT ?6",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    operation.operation_kind,
                    operation.operation_id.as_str(),
                    limit
                ],
                decode_audit_row,
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut records = rows
            .map(|row| {
                let mut record =
                    decode_audit_tuple(row.map_err(|error| map_sqlite_error(&error))?)?;
                record.operation = Some(operation.clone());
                validate_service_audit_record(&record).map_err(|_| DurableStoreError::Corrupt)?;
                Ok(record)
            })
            .collect::<Result<Vec<_>, DurableStoreError>>()?;
        records.reverse();
        Ok(records)
    }
}

fn load_quota_policy(
    connection: &Connection,
    subject: &ScopedPrincipal,
) -> Result<Option<ServiceQuotaPolicy>, DurableStoreError> {
    let namespace = namespace_storage_key(&subject.scope);
    connection
        .query_row(
            "SELECT max_requests, window_ms FROM service_quota_policies
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND principal_id=?4",
            params![
                subject.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subject.principal.principal_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(max_requests, window_ms)| {
            decode_quota_policy(subject.clone(), max_requests, window_ms)
        })
        .transpose()
}

fn decode_quota_policy(
    subject: ScopedPrincipal,
    max_requests: i64,
    window_ms: i64,
) -> Result<ServiceQuotaPolicy, DurableStoreError> {
    let policy = ServiceQuotaPolicy {
        subject,
        max_requests: u64::try_from(max_requests).map_err(|_| DurableStoreError::Corrupt)?,
        window_ms: u64::try_from(window_ms).map_err(|_| DurableStoreError::Corrupt)?,
    };
    validate_service_quota_policy(&policy).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(policy)
}

fn verify_quota_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, principal_id, max_requests, window_ms
             FROM service_quota_policies",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (tenant, present, namespace, principal, max_requests, window_ms) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let subject = decode_service_subject(&tenant, present, &namespace, &principal)?;
        decode_quota_policy(subject, max_requests, window_ms)?;
    }
    let invalid_usage: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM service_quota_usage u
             JOIN service_quota_policies p USING(tenant_id,namespace_present,namespace_id,principal_id)
             WHERE u.used_requests > p.max_requests
                OR (u.window_start_unix_ms % p.window_ms) != 0
                OR u.last_observed_unix_ms < u.window_start_unix_ms",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid_usage != 0 {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

type AuditTuple = (
    String,
    String,
    String,
    i64,
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    i64,
);

fn decode_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditTuple> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn decode_audit_tuple(row: AuditTuple) -> Result<ServiceAuditRecord, DurableStoreError> {
    let (
        audit_id,
        credential_id,
        tenant,
        namespace_present,
        namespace_id,
        subject_present,
        subject_principal_id,
        permission,
        resource_tenant,
        resource_namespace_present,
        resource_namespace_id,
        outcome,
        occurred_at_unix_ms,
    ) = row;
    let presented_scope = decode_scope(&tenant, namespace_present, &namespace_id)?;
    let subject = match subject_present {
        0 if subject_principal_id.is_empty() => None,
        1 if !subject_principal_id.is_empty() => Some(ScopedPrincipal {
            scope: presented_scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(decode_id(&subject_principal_id)?),
                kind: PrincipalKind::ServiceAccount,
            },
        }),
        _ => return Err(DurableStoreError::Corrupt),
    };
    let record = ServiceAuditRecord {
        audit_id: AuditRecordId::from_opaque(decode_id(&audit_id)?),
        credential_id: ServiceCredentialId::from_opaque(decode_id(&credential_id)?),
        presented_scope,
        subject,
        permission,
        resource_scope: decode_scope(
            &resource_tenant,
            resource_namespace_present,
            &resource_namespace_id,
        )?,
        outcome: decode_audit_outcome(&outcome)?,
        occurred_at_unix_ms,
        operation: None,
    };
    validate_service_audit_record(&record).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(record)
}

fn decode_audit_operation(
    operation_kind: Option<String>,
    operation_id: Option<String>,
) -> Result<Option<ServiceAuditOperationRef>, DurableStoreError> {
    match (operation_kind, operation_id) {
        (None, None) => Ok(None),
        (Some(operation_kind), Some(operation_id)) => {
            let operation = ServiceAuditOperationRef {
                operation_kind,
                operation_id: decode_id(&operation_id)?,
            };
            validate_service_audit_operation_ref(&operation)
                .map_err(|_| DurableStoreError::Corrupt)?;
            Ok(Some(operation))
        }
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn decode_audit_tuple_with_operation(
    row: AuditTuple,
    operation_kind: Option<String>,
    operation_id: Option<String>,
) -> Result<ServiceAuditRecord, DurableStoreError> {
    let mut record = decode_audit_tuple(row)?;
    record.operation = decode_audit_operation(operation_kind, operation_id)?;
    validate_service_audit_record(&record).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(record)
}

fn insert_audit_record(
    transaction: &Transaction<'_>,
    record: &ServiceAuditRecord,
    previous_hash: [u8; 32],
    record_hash: [u8; 32],
) -> Result<(), DurableStoreError> {
    let presented = namespace_storage_key(&record.presented_scope);
    let resource = namespace_storage_key(&record.resource_scope);
    let (subject_present, subject_principal_id) =
        record.subject.as_ref().map_or((0_i64, ""), |subject| {
            (1_i64, subject.principal.principal_id.as_opaque().as_str())
        });
    transaction
        .execute(
            "INSERT INTO service_audit_records (
                audit_id, credential_id, presented_tenant_id, presented_namespace_present,
                presented_namespace_id, subject_present, subject_principal_id, permission,
                resource_tenant_id, resource_namespace_present, resource_namespace_id,
                outcome, occurred_at_unix_ms, previous_hash, record_hash
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                record.audit_id.as_opaque().as_str(),
                record.credential_id.as_opaque().as_str(),
                record.presented_scope.tenant_id.as_opaque().as_str(),
                presented.present,
                presented.value,
                subject_present,
                subject_principal_id,
                record.permission,
                record.resource_scope.tenant_id.as_opaque().as_str(),
                resource.present,
                resource.value,
                audit_outcome_text(record.outcome),
                record.occurred_at_unix_ms,
                previous_hash.as_slice(),
                record_hash.as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if let Some(operation) = &record.operation {
        let audit_seq = transaction.last_insert_rowid();
        transaction
            .execute(
                "INSERT INTO service_audit_operations (audit_seq, operation_kind, operation_id)
                 VALUES (?1, ?2, ?3)",
                params![
                    audit_seq,
                    operation.operation_kind,
                    operation.operation_id.as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn load_audit_by_id(
    connection: &Connection,
    audit_id: &AuditRecordId,
) -> Result<Option<ServiceAuditRecord>, DurableStoreError> {
    connection
        .query_row(
            "SELECT r.audit_id, r.credential_id, r.presented_tenant_id,
                    r.presented_namespace_present, r.presented_namespace_id,
                    r.subject_present, r.subject_principal_id, r.permission,
                    r.resource_tenant_id, r.resource_namespace_present, r.resource_namespace_id,
                    r.outcome, r.occurred_at_unix_ms, o.operation_kind, o.operation_id
             FROM service_audit_records r
             LEFT JOIN service_audit_operations o ON o.audit_seq = r.audit_seq
             WHERE r.audit_id=?1",
            params![audit_id.as_opaque().as_str()],
            |row| {
                Ok((
                    decode_audit_row(row)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(tuple, operation_kind, operation_id)| {
            decode_audit_tuple_with_operation(tuple, operation_kind, operation_id)
        })
        .transpose()
}

fn verify_audit_chain_v1(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT audit_id, credential_id, presented_tenant_id,
                    presented_namespace_present, presented_namespace_id,
                    subject_present, subject_principal_id, permission,
                    resource_tenant_id, resource_namespace_present, resource_namespace_id,
                    outcome, occurred_at_unix_ms, previous_hash, record_hash
             FROM service_audit_records ORDER BY audit_seq",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                decode_audit_row(row)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut previous_hash = [0_u8; 32];
    for row in rows {
        let (tuple, stored_previous, stored_hash) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let record = decode_audit_tuple(tuple)?;
        if decode_hash(&stored_previous)? != previous_hash {
            return Err(DurableStoreError::Corrupt);
        }
        let expected_hash = service_audit_hash(previous_hash, &record);
        if decode_hash(&stored_hash)? != expected_hash {
            return Err(DurableStoreError::Corrupt);
        }
        previous_hash = expected_hash;
    }
    Ok(())
}

fn verify_audit_chain_v17(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT r.audit_id, r.credential_id, r.presented_tenant_id,
                    r.presented_namespace_present, r.presented_namespace_id,
                    r.subject_present, r.subject_principal_id, r.permission,
                    r.resource_tenant_id, r.resource_namespace_present, r.resource_namespace_id,
                    r.outcome, r.occurred_at_unix_ms, r.previous_hash, r.record_hash,
                    o.operation_kind, o.operation_id
             FROM service_audit_records r
             LEFT JOIN service_audit_operations o ON o.audit_seq = r.audit_seq
             ORDER BY r.audit_seq",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                decode_audit_row(row)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut previous_hash = [0_u8; 32];
    for row in rows {
        let (tuple, stored_previous, stored_hash, operation_kind, operation_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let record = decode_audit_tuple_with_operation(tuple, operation_kind, operation_id)?;
        if decode_hash(&stored_previous)? != previous_hash {
            return Err(DurableStoreError::Corrupt);
        }
        let expected_hash = service_audit_hash(previous_hash, &record);
        if decode_hash(&stored_hash)? != expected_hash {
            return Err(DurableStoreError::Corrupt);
        }
        previous_hash = expected_hash;
    }
    Ok(())
}

fn verify_schema_object(
    connection: &Connection,
    kind: &str,
    name: &str,
) -> Result<(), DurableStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if count == 1 {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

fn decode_hash(value: &[u8]) -> Result<[u8; 32], DurableStoreError> {
    value.try_into().map_err(|_| DurableStoreError::Corrupt)
}

fn validate_service_subject(subject: &ScopedPrincipal) -> Result<(), DurableStoreError> {
    if subject.principal.kind != PrincipalKind::ServiceAccount {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn decode_service_subject(
    tenant: &str,
    namespace_present: i64,
    namespace_id: &str,
    principal_id: &str,
) -> Result<ScopedPrincipal, DurableStoreError> {
    Ok(ScopedPrincipal {
        scope: decode_scope(tenant, namespace_present, namespace_id)?,
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(decode_id(principal_id)?),
            kind: PrincipalKind::ServiceAccount,
        },
    })
}

fn decode_scope(
    tenant: &str,
    namespace_present: i64,
    namespace_id: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match namespace_present {
        0 if namespace_id.is_empty() => None,
        1 if !namespace_id.is_empty() => Some(NamespaceId::from_opaque(decode_id(namespace_id)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(decode_id(tenant)?),
        namespace_id,
    })
}

fn decode_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

const fn audit_outcome_text(outcome: ServiceAuditOutcome) -> &'static str {
    match outcome {
        ServiceAuditOutcome::AuthenticationFailed => "authentication_failed",
        ServiceAuditOutcome::AuthenticationUnavailable => "authentication_unavailable",
        ServiceAuditOutcome::RateLimited => "rate_limited",
        ServiceAuditOutcome::QuotaUnavailable => "quota_unavailable",
        ServiceAuditOutcome::PermissionDenied => "permission_denied",
        ServiceAuditOutcome::AuthorizationUnavailable => "authorization_unavailable",
        ServiceAuditOutcome::Authorized => "authorized",
    }
}

fn decode_audit_outcome(value: &str) -> Result<ServiceAuditOutcome, DurableStoreError> {
    match value {
        "authentication_failed" => Ok(ServiceAuditOutcome::AuthenticationFailed),
        "authentication_unavailable" => Ok(ServiceAuditOutcome::AuthenticationUnavailable),
        "rate_limited" => Ok(ServiceAuditOutcome::RateLimited),
        "quota_unavailable" => Ok(ServiceAuditOutcome::QuotaUnavailable),
        "permission_denied" => Ok(ServiceAuditOutcome::PermissionDenied),
        "authorization_unavailable" => Ok(ServiceAuditOutcome::AuthorizationUnavailable),
        "authorized" => Ok(ServiceAuditOutcome::Authorized),
        _ => Err(DurableStoreError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::Connection;
    use ucr_core::{
        PermissionGrantStore, ServiceAuditStore, ServiceCredentialStore, ServiceQuotaConsumeError,
        ServiceQuotaStore, StorageProvider, issue_service_credential,
    };
    use ucr_model::{
        AuditRecordId, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, ServiceAuditOperationRef,
        ServiceAuditOutcome, ServiceAuditRecord, ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{CONVERSATION_READ_PERMISSION, SERVICE_AUDIT_COMMAND_OPERATION_KIND};

    use super::SqliteLocalStore;
    use crate::{
        SQLITE_SCHEMA_V13, SQLITE_SCHEMA_V16, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID,
    };

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(80_000);

    struct TestDb {
        path: PathBuf,
    }

    impl TestDb {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ucr-service-control-{}-{sequence}.sqlite3",
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
            tenant_id: TenantId::from_opaque(oid("tenant-control")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-control"))),
        }
    }

    fn service(id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn audit(
        id: &str,
        outcome: ServiceAuditOutcome,
        subject: Option<ScopedPrincipal>,
    ) -> ServiceAuditRecord {
        ServiceAuditRecord {
            audit_id: AuditRecordId::from_opaque(oid(id)),
            credential_id: ucr_model::ServiceCredentialId::from_opaque(oid("credential-control")),
            presented_scope: scope(),
            subject,
            permission: CONVERSATION_READ_PERMISSION.to_owned(),
            resource_scope: scope(),
            outcome,
            occurred_at_unix_ms: 10_000,
            operation: None,
        }
    }

    fn operation(id: &str) -> ServiceAuditOperationRef {
        ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_COMMAND_OPERATION_KIND.to_owned(),
            operation_id: oid(id),
        }
    }

    #[test]
    fn quota_accounting_survives_restart_and_identical_policy_does_not_reset_usage() {
        let db = TestDb::new();
        let subject = service("service-quota-sqlite");
        let policy = ServiceQuotaPolicy {
            subject: subject.clone(),
            max_requests: 2,
            window_ms: 1_000,
        };
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.set_service_quota_policy(&policy).expect("set policy");
            store
                .consume_service_request(&subject, 10_000)
                .expect("first");
            store
                .set_service_quota_policy(&policy)
                .expect("identical policy is idempotent without reset");
            store
                .consume_service_request(&subject, 10_000)
                .expect("second");
            assert_eq!(
                store.consume_service_request(&subject, 10_000),
                Err(ServiceQuotaConsumeError::RateLimited {
                    retry_after_ms: 1_000
                })
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(
            reopened.consume_service_request(&subject, 10_000),
            Err(ServiceQuotaConsumeError::RateLimited {
                retry_after_ms: 1_000
            })
        );
        reopened
            .consume_service_request(&subject, 11_000)
            .expect("new window");
        assert_eq!(
            reopened.consume_service_request(&subject, 10_999),
            Err(ServiceQuotaConsumeError::ClockRollback)
        );
    }

    #[test]
    fn audit_is_append_only_and_offline_semantic_tampering_is_detected_on_reopen() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            let first = audit(
                "audit-a",
                ServiceAuditOutcome::Authorized,
                Some(service("service-audit")),
            );
            let second = audit("audit-b", ServiceAuditOutcome::AuthenticationFailed, None);
            store.append_service_audit(&first).expect("append first");
            store
                .append_service_audit(&first)
                .expect("idempotent exact retry");
            store.append_service_audit(&second).expect("append second");
            assert_eq!(
                store
                    .service_audit_records(&scope(), 10)
                    .expect("audit read"),
                vec![first, second]
            );
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        assert!(
            connection
                .execute("UPDATE service_audit_records SET permission='ucr.message.read' WHERE audit_seq=1", [])
                .is_err(),
            "normal writes must be blocked by append-only trigger"
        );
        connection
            .execute_batch(
                "DROP TRIGGER service_audit_no_update;
                 UPDATE service_audit_records SET permission='ucr.message.read' WHERE audit_seq=1;
                 CREATE TRIGGER service_audit_no_update
                 BEFORE UPDATE ON service_audit_records
                 BEGIN SELECT RAISE(ABORT, 'service audit is append-only'); END;",
            )
            .expect("simulate offline tampering while restoring schema shape");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn operation_bound_audit_survives_restart_and_exact_lookup() {
        let db = TestDb::new();
        let operation = operation("command-operation-a");
        let mut first = audit(
            "audit-operation-a",
            ServiceAuditOutcome::Authorized,
            Some(service("service-operation")),
        );
        first.operation = Some(operation.clone());
        let mut second = audit(
            "audit-operation-b",
            ServiceAuditOutcome::PermissionDenied,
            Some(service("service-operation")),
        );
        second.operation = Some(operation.clone());
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.append_service_audit(&first).expect("append first");
            store.append_service_audit(&second).expect("append second");
            assert_eq!(
                store
                    .service_audit_records_for_operation(&scope(), &operation, 10)
                    .expect("operation lookup"),
                vec![first.clone(), second.clone()]
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(
            reopened
                .service_audit_records_for_operation(&scope(), &operation, 10)
                .expect("restart lookup"),
            vec![first, second]
        );
    }

    #[test]
    fn operation_audit_child_is_append_only_and_offline_tampering_is_detected() {
        let db = TestDb::new();
        let mut record = audit(
            "audit-operation-tamper",
            ServiceAuditOutcome::Authorized,
            Some(service("service-operation-tamper")),
        );
        record.operation = Some(operation("command-operation-tamper"));
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store
                .append_service_audit(&record)
                .expect("append operation audit");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        assert!(
            connection
                .execute(
                    "UPDATE service_audit_operations SET operation_id='changed' WHERE audit_seq=1",
                    [],
                )
                .is_err(),
            "normal operation mutation must be blocked"
        );
        assert!(
            connection
                .execute("DELETE FROM service_audit_operations WHERE audit_seq=1", [])
                .is_err(),
            "normal operation deletion must be blocked"
        );
        connection
            .execute_batch(
                "DROP TRIGGER service_audit_operation_no_update;
                 UPDATE service_audit_operations SET operation_id='changed' WHERE audit_seq=1;
                 CREATE TRIGGER service_audit_operation_no_update
                 BEFORE UPDATE ON service_audit_operations
                 BEGIN SELECT RAISE(ABORT, 'service audit operation is append-only'); END;",
            )
            .expect("simulate offline operation tampering while restoring trigger");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn offline_operation_addition_to_legacy_v1_row_is_detected_on_reopen() {
        let db = TestDb::new();
        let legacy = audit(
            "audit-legacy-addition",
            ServiceAuditOutcome::Authorized,
            Some(service("service-legacy-addition")),
        );
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store
                .append_service_audit(&legacy)
                .expect("append legacy v1 row");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute(
                "INSERT INTO service_audit_operations (audit_seq, operation_kind, operation_id)
                 VALUES (1, 'ucr.command', 'invented-command')",
                [],
            )
            .expect("simulate offline attribution addition");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn offline_operation_deletion_from_v2_row_is_detected_on_reopen() {
        let db = TestDb::new();
        let mut record = audit(
            "audit-operation-deletion",
            ServiceAuditOutcome::Authorized,
            Some(service("service-operation-deletion")),
        );
        record.operation = Some(operation("command-operation-deletion"));
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.append_service_audit(&record).expect("append v2 row");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute_batch(
                "DROP TRIGGER service_audit_operation_no_delete;
                 DELETE FROM service_audit_operations WHERE audit_seq=1;
                 CREATE TRIGGER service_audit_operation_no_delete
                 BEFORE DELETE ON service_audit_operations
                 BEGIN SELECT RAISE(ABORT, 'service audit operation is append-only'); END;",
            )
            .expect("simulate offline attribution deletion while restoring trigger");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn missing_v17_operation_owner_is_rejected_on_reopen() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute_batch("DROP TABLE service_audit_operations;")
            .expect("remove required v17 operation owner");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn v16_to_v17_migration_preserves_legacy_v1_hash_without_inventing_operations() {
        let db = TestDb::new();
        let legacy = audit(
            "audit-legacy-v16",
            ServiceAuditOutcome::Authorized,
            Some(service("service-legacy-v16")),
        );
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store
                .append_service_audit(&legacy)
                .expect("append legacy v1 audit");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        let before: Vec<u8> = connection
            .query_row(
                "SELECT record_hash FROM service_audit_records WHERE audit_id='audit-legacy-v16'",
                [],
                |row| row.get(0),
            )
            .expect("legacy hash before migration fixture");
        connection
            .execute_batch(
                "DROP TRIGGER service_audit_operation_no_update;
                 DROP TRIGGER service_audit_operation_no_delete;
                 DROP INDEX service_audit_operation_lookup;
                 DROP TABLE service_audit_operations;",
            )
            .expect("restore exact v16 shape");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V16)
            .expect("v16 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v16 to v17");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated.service_audit_records(&scope(), 10),
            Ok(vec![legacy])
        );
        drop(migrated);
        let connection = Connection::open(db.path()).expect("raw migrated connection");
        let after: Vec<u8> = connection
            .query_row(
                "SELECT record_hash FROM service_audit_records WHERE audit_id='audit-legacy-v16'",
                [],
                |row| row.get(0),
            )
            .expect("legacy hash after migration");
        let operation_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM service_audit_operations", [], |row| {
                row.get(0)
            })
            .expect("operation count");
        assert_eq!(
            before, after,
            "migration must not rehash legacy audit evidence"
        );
        assert_eq!(
            operation_count, 0,
            "migration must not invent operation attribution"
        );
    }

    #[test]
    fn v13_to_v14_migration_preserves_credentials_and_permissions_and_starts_empty_controls() {
        let db = TestDb::new();
        let subject = service("service-migration");
        let (credential, _) = issue_service_credential(&subject).expect("issue");
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: CONVERSATION_READ_PERMISSION.to_owned(),
            scope: PermissionScope::Exact(scope()),
        };
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store
                .provision_service_credential(&credential)
                .expect("seed credential");
            store.grant_permission(&grant).expect("seed permission");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute_batch(
                "DROP TABLE service_audit_operations; DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices;
                 DROP TRIGGER service_audit_no_update;
                 DROP TRIGGER service_audit_no_delete;
                 DROP INDEX service_audit_scope_sequence;
                 DROP TABLE service_audit_records;
                 DROP TABLE service_quota_usage;
                 DROP TABLE service_quota_policies;",
            )
            .expect("remove v14 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V13)
            .expect("v13 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v13 to v14");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated
                .service_credential(&scope(), &credential.credential_id)
                .expect("credential read"),
            Some(credential)
        );
        assert_eq!(migrated.permission_grants_for(&subject), Ok(vec![grant]));
        assert_eq!(migrated.service_quota_policy(&subject), Ok(None));
        assert_eq!(migrated.service_audit_records(&scope(), 10), Ok(Vec::new()));
    }
}
