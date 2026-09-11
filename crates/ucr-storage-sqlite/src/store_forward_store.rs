use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, StoreForwardStore};
use ucr_model::{
    DeliveryId, IntentId, MessageId, OpaqueId, StoreForwardId, StoreForwardJob, StoreForwardLease,
    StoreForwardLeaseId, StoreForwardPolicy, TenantId, TenantScope,
};
use ucr_protocol::{
    store_forward_delivery_id, store_forward_job_fingerprint, validate_store_forward_job,
    validate_store_forward_page_size,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    offline_group_store, verify_table_columns,
};

pub(super) const V24_OBJECTS_SQL: &str = r"
CREATE TABLE store_forward_jobs (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    store_forward_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    encrypted_envelope BLOB NOT NULL CHECK(length(encrypted_envelope) > 0),
    max_delivery_attempts INTEGER NOT NULL CHECK(max_delivery_attempts BETWEEN 1 AND 64),
    base_retry_delay_ms BLOB NOT NULL CHECK(length(base_retry_delay_ms)=8),
    max_retry_delay_ms BLOB NOT NULL CHECK(length(max_retry_delay_ms)=8),
    lease_duration_ms BLOB NOT NULL CHECK(length(lease_duration_ms)=8),
    expires_at_unix_ms INTEGER,
    attempts_used INTEGER NOT NULL CHECK(attempts_used BETWEEN 0 AND 64),
    initial_attempt_at_unix_ms INTEGER NOT NULL,
    next_attempt_at_unix_ms INTEGER NOT NULL,
    last_delivery_id TEXT,
    lease_id TEXT,
    lease_until_unix_ms INTEGER,
    job_fingerprint BLOB NOT NULL CHECK(length(job_fingerprint)=32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, store_forward_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, intent_id)
      REFERENCES communication_intents(tenant_id, namespace_present, namespace_id, intent_id)
      ON DELETE CASCADE,
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id)
      ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>'')),
    CHECK((attempts_used=0 AND last_delivery_id IS NULL) OR
          (attempts_used>0 AND last_delivery_id IS NOT NULL)),
    CHECK((lease_id IS NULL AND lease_until_unix_ms IS NULL) OR
          (lease_id IS NOT NULL AND lease_until_unix_ms IS NOT NULL)),
    CHECK(expires_at_unix_ms IS NULL OR next_attempt_at_unix_ms <= expires_at_unix_ms)
) WITHOUT ROWID;
CREATE INDEX store_forward_jobs_due
ON store_forward_jobs(tenant_id, namespace_present, namespace_id, next_attempt_at_unix_ms, store_forward_id);
CREATE UNIQUE INDEX store_forward_jobs_last_delivery
ON store_forward_jobs(tenant_id, namespace_present, namespace_id, last_delivery_id)
WHERE last_delivery_id IS NOT NULL;

CREATE TABLE store_forward_tombstones (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    store_forward_id TEXT NOT NULL,
    job_fingerprint BLOB NOT NULL CHECK(length(job_fingerprint)=32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, store_forward_id),
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v24_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V24_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v24(connection: &Connection) -> Result<(), DurableStoreError> {
    offline_group_store::verify_schema_v23(connection)?;
    verify_table_columns(
        connection,
        "store_forward_jobs",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("store_forward_id", "TEXT", 1, 4),
            ("intent_id", "TEXT", 1, 0),
            ("message_id", "TEXT", 1, 0),
            ("encrypted_envelope", "BLOB", 1, 0),
            ("max_delivery_attempts", "INTEGER", 1, 0),
            ("base_retry_delay_ms", "BLOB", 1, 0),
            ("max_retry_delay_ms", "BLOB", 1, 0),
            ("lease_duration_ms", "BLOB", 1, 0),
            ("expires_at_unix_ms", "INTEGER", 0, 0),
            ("attempts_used", "INTEGER", 1, 0),
            ("initial_attempt_at_unix_ms", "INTEGER", 1, 0),
            ("next_attempt_at_unix_ms", "INTEGER", 1, 0),
            ("last_delivery_id", "TEXT", 0, 0),
            ("lease_id", "TEXT", 0, 0),
            ("lease_until_unix_ms", "INTEGER", 0, 0),
            ("job_fingerprint", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "store_forward_tombstones",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("store_forward_id", "TEXT", 1, 4),
            ("job_fingerprint", "BLOB", 1, 0),
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
    verify_job_rows(connection)?;
    verify_tombstones(connection)
}

#[derive(Debug, Clone)]
struct StoredStoreForwardJob {
    job: StoreForwardJob,
    initial_attempt_at_unix_ms: i64,
    fingerprint: [u8; 32],
    lease: Option<(StoreForwardLeaseId, i64)>,
}

impl StoreForwardStore for SqliteLocalStore {
    fn persist_store_forward_job(
        &self,
        job: &StoreForwardJob,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_store_forward_job(job).map_err(|_| DurableStoreError::InvalidRecord)?;
        let fingerprint =
            store_forward_job_fingerprint(job).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&job.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_tombstone_fingerprint(&transaction, &job.scope, &job.store_forward_id)?
        {
            return if existing == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if let Some(existing) = load_stored_job(&transaction, &job.scope, &job.store_forward_id)? {
            return if existing.fingerprint == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        require_owner_rows(&transaction, job)?;
        transaction
            .execute(
                "INSERT INTO store_forward_jobs (
                    tenant_id, namespace_present, namespace_id, store_forward_id, intent_id,
                    message_id, encrypted_envelope, max_delivery_attempts, base_retry_delay_ms,
                    max_retry_delay_ms, lease_duration_ms, expires_at_unix_ms, attempts_used,
                    initial_attempt_at_unix_ms, next_attempt_at_unix_ms, last_delivery_id,
                    lease_id, lease_until_unix_ms, job_fingerprint
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,?13,?13,NULL,NULL,NULL,?14)",
                params![
                    job.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    job.store_forward_id.as_opaque().as_str(),
                    job.intent_id.as_opaque().as_str(),
                    job.message_id.as_opaque().as_str(),
                    job.encrypted_envelope,
                    i64::from(job.policy.max_delivery_attempts),
                    job.policy.base_retry_delay_ms.to_be_bytes().as_slice(),
                    job.policy.max_retry_delay_ms.to_be_bytes().as_slice(),
                    job.policy.lease_duration_ms.to_be_bytes().as_slice(),
                    job.policy.expires_at_unix_ms,
                    job.next_attempt_at_unix_ms,
                    fingerprint.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
    ) -> Result<Option<StoreForwardJob>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_stored_job(&connection, scope, store_forward_id)
            .map(|value| value.map(|stored| stored.job))
    }

    fn due_store_forward_jobs(
        &self,
        scope: &TenantScope,
        now_unix_ms: i64,
        max_items: usize,
    ) -> Result<Vec<StoreForwardId>, DurableStoreError> {
        validate_store_forward_page_size(max_items)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT j.store_forward_id
                 FROM store_forward_jobs j
                 LEFT JOIN delivery_attempts d
                   ON d.tenant_id=j.tenant_id AND d.namespace_present=j.namespace_present
                  AND d.namespace_id=j.namespace_id AND d.delivery_id=j.last_delivery_id
                 WHERE j.tenant_id=?1 AND j.namespace_present=?2 AND j.namespace_id=?3
                   AND j.next_attempt_at_unix_ms<=?4
                   AND (j.lease_until_unix_ms IS NULL OR j.lease_until_unix_ms<=?4)
                   AND (j.last_delivery_id IS NULL OR d.state<>'in_flight')
                 ORDER BY j.next_attempt_at_unix_ms, j.store_forward_id
                 LIMIT ?5",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    now_unix_ms,
                    limit,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        rows.map(|row| {
            let value = row.map_err(|error| map_sqlite_error(&error))?;
            Ok(StoreForwardId::from_opaque(parse_id(&value)?))
        })
        .collect()
    }

    fn claim_store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
        lease_id: &StoreForwardLeaseId,
        now_unix_ms: i64,
        lease_until_unix_ms: i64,
    ) -> Result<Option<StoreForwardLease>, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let Some(stored) = load_stored_job(&transaction, scope, store_forward_id)? else {
            return Ok(None);
        };
        if !claim_timing_allows(&stored, now_unix_ms, lease_until_unix_ms)?
            || last_attempt_is_in_flight(&transaction, &stored.job)?
        {
            return Ok(None);
        }
        let namespace = namespace_storage_key(scope);
        transaction
            .execute(
                "UPDATE store_forward_jobs SET lease_id=?5, lease_until_unix_ms=?6
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    store_forward_id.as_opaque().as_str(),
                    lease_id.as_opaque().as_str(),
                    lease_until_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(Some(StoreForwardLease {
            job: stored.job,
            lease_id: lease_id.clone(),
            lease_until_unix_ms,
        }))
    }

    fn record_store_forward_attempt(
        &self,
        lease: &StoreForwardLease,
        delivery_id: &DeliveryId,
        attempts_used: u16,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let stored = load_stored_job(&transaction, &lease.job.scope, &lease.job.store_forward_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(&stored, lease, now_unix_ms)?;
        if attempts_used != stored.job.attempts_used.saturating_add(1)
            || attempts_used > stored.job.policy.max_delivery_attempts
            || *delivery_id
                != store_forward_delivery_id(
                    &stored.job.scope,
                    &stored.job.store_forward_id,
                    attempts_used,
                )
        {
            return Err(DurableStoreError::Conflict);
        }
        let (message_id, state) =
            load_delivery_binding(&transaction, &stored.job.scope, delivery_id)?
                .ok_or(DurableStoreError::InvalidRecord)?;
        if message_id != stored.job.message_id || state != "persisted" {
            return Err(DurableStoreError::Conflict);
        }
        let namespace = namespace_storage_key(&stored.job.scope);
        transaction
            .execute(
                "UPDATE store_forward_jobs SET attempts_used=?5, last_delivery_id=?6
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
                params![
                    stored.job.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    stored.job.store_forward_id.as_opaque().as_str(),
                    i64::from(attempts_used),
                    delivery_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut updated = stored.job;
        updated.attempts_used = attempts_used;
        updated.last_delivery_id = Some(delivery_id.clone());
        validate_store_forward_job(&updated).map_err(|_| DurableStoreError::Corrupt)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(updated)
    }

    fn reschedule_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        next_attempt_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let stored = load_stored_job(&transaction, &lease.job.scope, &lease.job.store_forward_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(&stored, lease, now_unix_ms)?;
        let mut updated = stored.job;
        updated.next_attempt_at_unix_ms = next_attempt_at_unix_ms;
        validate_store_forward_job(&updated).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&updated.scope);
        transaction
            .execute(
                "UPDATE store_forward_jobs
                 SET next_attempt_at_unix_ms=?5, lease_id=NULL, lease_until_unix_ms=NULL
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
                params![
                    updated.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    updated.store_forward_id.as_opaque().as_str(),
                    next_attempt_at_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(updated)
    }

    fn complete_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        now_unix_ms: i64,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let stored = load_stored_job(&transaction, &lease.job.scope, &lease.job.store_forward_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(&stored, lease, now_unix_ms)?;
        if let Some(existing) = load_tombstone_fingerprint(
            &transaction,
            &stored.job.scope,
            &stored.job.store_forward_id,
        )? {
            if existing != stored.fingerprint {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            let namespace = namespace_storage_key(&stored.job.scope);
            transaction
                .execute(
                    "INSERT INTO store_forward_tombstones (
                        tenant_id, namespace_present, namespace_id, store_forward_id, job_fingerprint
                     ) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        stored.job.scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        stored.job.store_forward_id.as_opaque().as_str(),
                        stored.fingerprint.as_slice(),
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
        }
        let namespace = namespace_storage_key(&stored.job.scope);
        transaction
            .execute(
                "DELETE FROM store_forward_jobs
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
                params![
                    stored.job.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    stored.job.store_forward_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

fn require_owner_rows(
    connection: &Connection,
    job: &StoreForwardJob,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&job.scope);
    let intent_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM communication_intents
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND intent_id=?4)",
            params![
                job.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                job.intent_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let message_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM messages
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4)",
            params![
                job.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                job.message_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if intent_exists && message_exists {
        Ok(())
    } else {
        Err(DurableStoreError::InvalidRecord)
    }
}

fn load_stored_job(
    connection: &Connection,
    scope: &TenantScope,
    store_forward_id: &StoreForwardId,
) -> Result<Option<StoredStoreForwardJob>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let raw = connection
        .query_row(
            "SELECT intent_id, message_id, encrypted_envelope, max_delivery_attempts,
                    base_retry_delay_ms, max_retry_delay_ms, lease_duration_ms,
                    expires_at_unix_ms, attempts_used, initial_attempt_at_unix_ms,
                    next_attempt_at_unix_ms, last_delivery_id, lease_id, lease_until_unix_ms,
                    job_fingerprint
             FROM store_forward_jobs
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                store_forward_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    raw.map(|raw| decode_stored_job(scope, store_forward_id, raw))
        .transpose()
}

type RawStoredJob = (
    String,
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Vec<u8>,
);

fn decode_stored_job(
    scope: &TenantScope,
    store_forward_id: &StoreForwardId,
    raw: RawStoredJob,
) -> Result<StoredStoreForwardJob, DurableStoreError> {
    let (
        intent_id,
        message_id,
        encrypted_envelope,
        max_delivery_attempts,
        base_retry_delay_ms,
        max_retry_delay_ms,
        lease_duration_ms,
        expires_at_unix_ms,
        attempts_used,
        initial_attempt_at_unix_ms,
        next_attempt_at_unix_ms,
        last_delivery_id,
        lease_id,
        lease_until_unix_ms,
        fingerprint,
    ) = raw;
    let max_delivery_attempts =
        u16::try_from(max_delivery_attempts).map_err(|_| DurableStoreError::Corrupt)?;
    let attempts_used = u16::try_from(attempts_used).map_err(|_| DurableStoreError::Corrupt)?;
    let lease = match (lease_id, lease_until_unix_ms) {
        (None, None) => None,
        (Some(id), Some(until)) => Some((StoreForwardLeaseId::from_opaque(parse_id(&id)?), until)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    let job = StoreForwardJob {
        store_forward_id: store_forward_id.clone(),
        scope: scope.clone(),
        intent_id: IntentId::from_opaque(parse_id(&intent_id)?),
        message_id: MessageId::from_opaque(parse_id(&message_id)?),
        encrypted_envelope,
        policy: StoreForwardPolicy {
            max_delivery_attempts,
            base_retry_delay_ms: decode_u64(&base_retry_delay_ms)?,
            max_retry_delay_ms: decode_u64(&max_retry_delay_ms)?,
            lease_duration_ms: decode_u64(&lease_duration_ms)?,
            expires_at_unix_ms,
        },
        attempts_used,
        next_attempt_at_unix_ms,
        last_delivery_id: last_delivery_id
            .map(|value| parse_id(&value).map(DeliveryId::from_opaque))
            .transpose()?,
    };
    validate_store_forward_job(&job).map_err(|_| DurableStoreError::Corrupt)?;
    let fingerprint: [u8; 32] = fingerprint
        .try_into()
        .map_err(|_| DurableStoreError::Corrupt)?;
    Ok(StoredStoreForwardJob {
        job,
        initial_attempt_at_unix_ms,
        fingerprint,
        lease,
    })
}

fn load_tombstone_fingerprint(
    connection: &Connection,
    scope: &TenantScope,
    store_forward_id: &StoreForwardId,
) -> Result<Option<[u8; 32]>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT job_fingerprint FROM store_forward_tombstones
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND store_forward_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                store_forward_id.as_opaque().as_str(),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|value| value.try_into().map_err(|_| DurableStoreError::Corrupt))
        .transpose()
}

fn claim_timing_allows(
    stored: &StoredStoreForwardJob,
    now_unix_ms: i64,
    lease_until_unix_ms: i64,
) -> Result<bool, DurableStoreError> {
    let lease_duration = i64::try_from(stored.job.policy.lease_duration_ms)
        .map_err(|_| DurableStoreError::Corrupt)?;
    let max_until = now_unix_ms
        .checked_add(lease_duration)
        .ok_or(DurableStoreError::InvalidRecord)?;
    Ok(lease_until_unix_ms > now_unix_ms
        && lease_until_unix_ms <= max_until
        && stored.job.next_attempt_at_unix_ms <= now_unix_ms
        && stored
            .lease
            .as_ref()
            .is_none_or(|(_, until)| *until <= now_unix_ms))
}

fn require_lease(
    stored: &StoredStoreForwardJob,
    lease: &StoreForwardLease,
    now_unix_ms: i64,
) -> Result<(), DurableStoreError> {
    let Some((lease_id, lease_until)) = stored.lease.as_ref() else {
        return Err(DurableStoreError::Conflict);
    };
    if lease_id != &lease.lease_id
        || *lease_until != lease.lease_until_unix_ms
        || now_unix_ms >= *lease_until
    {
        return Err(DurableStoreError::Conflict);
    }
    Ok(())
}

fn last_attempt_is_in_flight(
    connection: &Connection,
    job: &StoreForwardJob,
) -> Result<bool, DurableStoreError> {
    let Some(delivery_id) = job.last_delivery_id.as_ref() else {
        return Ok(false);
    };
    let Some((message_id, state)) = load_delivery_binding(connection, &job.scope, delivery_id)?
    else {
        return Err(DurableStoreError::Corrupt);
    };
    if message_id != job.message_id {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(state == "in_flight")
}

fn load_delivery_binding(
    connection: &Connection,
    scope: &TenantScope,
    delivery_id: &DeliveryId,
) -> Result<Option<(MessageId, String)>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT message_id, state FROM delivery_attempts
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND delivery_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                delivery_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(message, state)| Ok((MessageId::from_opaque(parse_id(&message)?), state)))
        .transpose()
}

fn verify_job_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, store_forward_id
             FROM store_forward_jobs",
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
    for (tenant, namespace_present, namespace, id) in keys {
        let scope = parse_scope(&tenant, namespace_present, &namespace)?;
        let store_forward_id = StoreForwardId::from_opaque(parse_id(&id)?);
        let stored = load_stored_job(connection, &scope, &store_forward_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        require_owner_rows(connection, &stored.job).map_err(|_| DurableStoreError::Corrupt)?;
        if let Some(delivery_id) = stored.job.last_delivery_id.as_ref() {
            let (message_id, _) = load_delivery_binding(connection, &scope, delivery_id)?
                .ok_or(DurableStoreError::Corrupt)?;
            if message_id != stored.job.message_id {
                return Err(DurableStoreError::Corrupt);
            }
        }
        let initial = StoreForwardJob {
            store_forward_id: stored.job.store_forward_id.clone(),
            scope: stored.job.scope.clone(),
            intent_id: stored.job.intent_id.clone(),
            message_id: stored.job.message_id.clone(),
            encrypted_envelope: stored.job.encrypted_envelope.clone(),
            policy: stored.job.policy,
            attempts_used: 0,
            next_attempt_at_unix_ms: stored.initial_attempt_at_unix_ms,
            last_delivery_id: None,
        };
        let expected =
            store_forward_job_fingerprint(&initial).map_err(|_| DurableStoreError::Corrupt)?;
        if expected != stored.fingerprint {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

fn verify_tombstones(connection: &Connection) -> Result<(), DurableStoreError> {
    let invalid: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM store_forward_tombstones WHERE length(job_fingerprint)<>32)",
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

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
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
        (1, false) => Some(ucr_model::NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

#[cfg(test)]
mod tests {
    use ucr_core::{
        CommunicationIntentStore, ConversationStore, DeliveryStore, DurableRecordStatus,
        MessageStore, StoreForwardStore,
    };
    use ucr_model::{
        CommunicationIntent, CorrelationContext, DeliveryAttempt, DeliveryEvidence,
        DeliveryEvidenceKind, DeliveryState, IdentityId, IntentConstraints, IntentId,
        StoreForwardId, StoreForwardJob, StoreForwardLeaseId, StoreForwardPolicy,
    };
    use ucr_protocol::store_forward_delivery_id;

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, conversation, message, scope};

    fn oid(value: &str) -> ucr_model::OpaqueId {
        ucr_model::OpaqueId::new(value).expect("test id")
    }

    fn intent() -> CommunicationIntent {
        CommunicationIntent {
            intent_id: IntentId::from_opaque(oid("sf-intent")),
            scope: scope(),
            target_identity_id: IdentityId::from_opaque(oid("sf-target")),
            payload: b"intent".to_vec(),
            constraints: IntentConstraints {
                allowed_transport_capabilities: Vec::new(),
                forbidden_transport_capabilities: Vec::new(),
                privacy_profile: None,
                region_constraint: None,
                max_cost_microunits: None,
                priority_class: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("sf-correlation"),
                causation_id: None,
                idempotency_key: Some("sf-intent-key".to_owned()),
            },
            extensions: Vec::new(),
        }
    }

    fn job() -> StoreForwardJob {
        StoreForwardJob {
            store_forward_id: StoreForwardId::from_opaque(oid("sf-job")),
            scope: scope(),
            intent_id: intent().intent_id,
            message_id: message(b"hello").message_id,
            encrypted_envelope: b"ciphertext".to_vec(),
            policy: StoreForwardPolicy {
                max_delivery_attempts: 3,
                base_retry_delay_ms: 100,
                max_retry_delay_ms: 1_000,
                lease_duration_ms: 5_000,
                expires_at_unix_ms: None,
            },
            attempts_used: 0,
            next_attempt_at_unix_ms: 1_000,
            last_delivery_id: None,
        }
    }

    fn seed(store: &SqliteLocalStore) {
        store
            .persist_conversation(&conversation())
            .expect("conversation");
        store.persist_message(&message(b"hello")).expect("message");
        store
            .persist_communication_intent(&intent())
            .expect("intent");
    }

    #[test]
    fn job_lease_attempt_and_reschedule_survive_restart() {
        let db = TestDb::new();
        let first = job();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            seed(&store);
            assert_eq!(
                store.persist_store_forward_job(&first),
                Ok(DurableRecordStatus::Persisted)
            );
            let lease_id = StoreForwardLeaseId::from_opaque(oid("sf-lease"));
            let lease = store
                .claim_store_forward_job(
                    &first.scope,
                    &first.store_forward_id,
                    &lease_id,
                    1_000,
                    2_000,
                )
                .expect("claim")
                .expect("lease");
            let delivery_id = store_forward_delivery_id(&first.scope, &first.store_forward_id, 1);
            let attempt = DeliveryAttempt {
                delivery_id: delivery_id.clone(),
                scope: first.scope.clone(),
                message_id: first.message_id.clone(),
                state: DeliveryState::Persisted,
            };
            let evidence = DeliveryEvidence {
                delivery_id: delivery_id.clone(),
                scope: first.scope.clone(),
                message_id: first.message_id.clone(),
                kind: DeliveryEvidenceKind::PersistedLocal,
                logical_order: 1,
            };
            store
                .create_delivery_attempt(&attempt, &evidence)
                .expect("delivery");
            store
                .record_store_forward_attempt(&lease, &delivery_id, 1, 1_100)
                .expect("record attempt");
            store
                .reschedule_store_forward_job(&lease, 1_500, 1_200)
                .expect("reschedule");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        let loaded = reopened
            .store_forward_job(&first.scope, &first.store_forward_id)
            .expect("load")
            .expect("job");
        assert_eq!(loaded.attempts_used, 1);
        assert_eq!(loaded.next_attempt_at_unix_ms, 1_500);
        assert!(loaded.last_delivery_id.is_some());
        assert_eq!(
            reopened.due_store_forward_jobs(&first.scope, 1_500, 8),
            Ok(vec![first.store_forward_id])
        );
    }

    #[test]
    fn v23_to_v24_migration_starts_store_forward_state_empty() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open current");
            seed(&store);
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("raw open");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     DROP TABLE IF EXISTS mesh_group_message_hops;
                     DROP TABLE store_forward_jobs;
                     DROP TABLE store_forward_tombstones;
                     PRAGMA user_version=23;",
                )
                .expect("restore v23 fixture");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v23 to v24");
        assert_eq!(
            ucr_core::StorageProvider::schema_version(&migrated),
            Ok(crate::SQLITE_SCHEMA_VERSION)
        );
        assert_eq!(
            migrated.due_store_forward_jobs(&scope(), i64::MAX, 8),
            Ok(Vec::new())
        );
    }

    #[test]
    fn completion_tombstone_prevents_resurrection_and_detects_conflict() {
        let db = TestDb::new();
        let first = job();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        seed(&store);
        store.persist_store_forward_job(&first).expect("persist");
        let lease = store
            .claim_store_forward_job(
                &first.scope,
                &first.store_forward_id,
                &StoreForwardLeaseId::from_opaque(oid("sf-lease-done")),
                1_000,
                2_000,
            )
            .expect("claim")
            .expect("lease");
        store
            .complete_store_forward_job(&lease, 1_100)
            .expect("complete");
        assert_eq!(
            store.persist_store_forward_job(&first),
            Ok(DurableRecordStatus::Duplicate)
        );
        let mut changed = first;
        changed.encrypted_envelope.push(9);
        assert_eq!(
            store.persist_store_forward_job(&changed),
            Err(ucr_core::DurableStoreError::Conflict)
        );
    }
}
