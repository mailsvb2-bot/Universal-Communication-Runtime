use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::DurableStoreError;

use super::{SqliteLocalStore, map_schema_change_error, map_sqlite_error, verify_table_columns};

pub const WEBHOOK_DELIVERY_WORKER_KIND: &str = "webhook_delivery";
const MAX_WORKER_KIND_BYTES: usize = 64;
const MAX_HOLDER_ID_BYTES: usize = 128;
const MAX_WORKER_LEASE_MS: i64 = 10 * 60 * 1000;

const V43_OBJECTS_SQL: &str = "
CREATE TABLE runtime_worker_leases (
    worker_kind TEXT PRIMARY KEY NOT NULL
        CHECK(length(worker_kind) BETWEEN 1 AND 64),
    holder_id TEXT NOT NULL
        CHECK(length(holder_id) BETWEEN 1 AND 128),
    heartbeat_unix_ms INTEGER NOT NULL CHECK(heartbeat_unix_ms >= 0),
    lease_expires_unix_ms INTEGER NOT NULL
        CHECK(lease_expires_unix_ms > heartbeat_unix_ms)
) WITHOUT ROWID;
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWorkerLease {
    pub holder_id: String,
    pub heartbeat_unix_ms: i64,
    pub lease_expires_unix_ms: i64,
}

pub(super) fn create_v43_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V43_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v43_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "runtime_worker_leases",
        &[
            ("worker_kind", "TEXT", 1, 1),
            ("holder_id", "TEXT", 1, 0),
            ("heartbeat_unix_ms", "INTEGER", 1, 0),
            ("lease_expires_unix_ms", "INTEGER", 1, 0),
        ],
    )?;
    let mut statement = connection
        .prepare(
            "SELECT worker_kind, holder_id, heartbeat_unix_ms, lease_expires_unix_ms
             FROM runtime_worker_leases",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (worker_kind, holder_id, heartbeat, expires) =
            row.map_err(|error| map_sqlite_error(&error))?;
        validate_persisted_lease(&worker_kind, &holder_id, heartbeat, expires)?;
    }
    Ok(())
}

impl SqliteLocalStore {
    /// Atomically acquires one deployment worker lease when it is absent, expired, or already
    /// owned by the same holder. Another live holder is never overwritten.
    ///
    /// # Errors
    /// Rejects invalid identifiers/timestamps and returns explicit storage failures.
    pub fn try_acquire_runtime_worker_lease(
        &self,
        worker_kind: &str,
        holder_id: &str,
        now_unix_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<bool, DurableStoreError> {
        let lease_expires_unix_ms =
            validated_expiry(worker_kind, holder_id, now_unix_ms, lease_duration_ms)?;
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "INSERT INTO runtime_worker_leases (
                    worker_kind, holder_id, heartbeat_unix_ms, lease_expires_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(worker_kind) DO UPDATE SET
                    holder_id = excluded.holder_id,
                    heartbeat_unix_ms = excluded.heartbeat_unix_ms,
                    lease_expires_unix_ms = excluded.lease_expires_unix_ms
                 WHERE runtime_worker_leases.holder_id = excluded.holder_id
                    OR runtime_worker_leases.lease_expires_unix_ms <= excluded.heartbeat_unix_ms",
                params![worker_kind, holder_id, now_unix_ms, lease_expires_unix_ms],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(changed == 1)
    }

    /// Renews an unexpired lease held by the exact same worker.
    ///
    /// Once a lease expires, renewal fails closed; the worker must reacquire before performing
    /// another external side effect.
    ///
    /// # Errors
    /// Rejects invalid identifiers/timestamps and returns explicit storage failures.
    pub fn renew_runtime_worker_lease(
        &self,
        worker_kind: &str,
        holder_id: &str,
        now_unix_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<bool, DurableStoreError> {
        let lease_expires_unix_ms =
            validated_expiry(worker_kind, holder_id, now_unix_ms, lease_duration_ms)?;
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "UPDATE runtime_worker_leases
                 SET heartbeat_unix_ms=?3, lease_expires_unix_ms=?4
                 WHERE worker_kind=?1 AND holder_id=?2
                   AND lease_expires_unix_ms > ?3",
                params![worker_kind, holder_id, now_unix_ms, lease_expires_unix_ms],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(changed == 1)
    }

    /// Releases one worker lease only when the exact holder still owns it.
    ///
    /// # Errors
    /// Rejects invalid identifiers and returns explicit storage failures.
    pub fn release_runtime_worker_lease(
        &self,
        worker_kind: &str,
        holder_id: &str,
    ) -> Result<bool, DurableStoreError> {
        validate_identifier(worker_kind, MAX_WORKER_KIND_BYTES)?;
        validate_identifier(holder_id, MAX_HOLDER_ID_BYTES)?;
        let connection = self.lock_connection()?;
        let changed = connection
            .execute(
                "DELETE FROM runtime_worker_leases WHERE worker_kind=?1 AND holder_id=?2",
                params![worker_kind, holder_id],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(changed == 1)
    }

    /// Returns the durable lease row for operator health/failover decisions.
    ///
    /// # Errors
    /// Rejects invalid worker kinds and returns explicit storage/corruption failures.
    pub fn runtime_worker_lease(
        &self,
        worker_kind: &str,
    ) -> Result<Option<RuntimeWorkerLease>, DurableStoreError> {
        validate_identifier(worker_kind, MAX_WORKER_KIND_BYTES)?;
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT holder_id, heartbeat_unix_ms, lease_expires_unix_ms
                 FROM runtime_worker_leases WHERE worker_kind=?1",
                params![worker_kind],
                |row| {
                    Ok(RuntimeWorkerLease {
                        holder_id: row.get(0)?,
                        heartbeat_unix_ms: row.get(1)?,
                        lease_expires_unix_ms: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?
            .map(|lease| {
                validate_persisted_lease(
                    worker_kind,
                    &lease.holder_id,
                    lease.heartbeat_unix_ms,
                    lease.lease_expires_unix_ms,
                )?;
                Ok(lease)
            })
            .transpose()
    }
}

fn validate_persisted_lease(
    worker_kind: &str,
    holder_id: &str,
    heartbeat_unix_ms: i64,
    lease_expires_unix_ms: i64,
) -> Result<(), DurableStoreError> {
    validate_identifier(worker_kind, MAX_WORKER_KIND_BYTES)
        .map_err(|_| DurableStoreError::Corrupt)?;
    validate_identifier(holder_id, MAX_HOLDER_ID_BYTES).map_err(|_| DurableStoreError::Corrupt)?;
    let duration = lease_expires_unix_ms
        .checked_sub(heartbeat_unix_ms)
        .ok_or(DurableStoreError::Corrupt)?;
    if heartbeat_unix_ms < 0
        || lease_expires_unix_ms <= heartbeat_unix_ms
        || duration > MAX_WORKER_LEASE_MS
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn validated_expiry(
    worker_kind: &str,
    holder_id: &str,
    now_unix_ms: i64,
    lease_duration_ms: i64,
) -> Result<i64, DurableStoreError> {
    validate_lease_input(worker_kind, holder_id, now_unix_ms, lease_duration_ms)?;
    now_unix_ms
        .checked_add(lease_duration_ms)
        .ok_or(DurableStoreError::InvalidRecord)
}

fn validate_lease_input(
    worker_kind: &str,
    holder_id: &str,
    now_unix_ms: i64,
    lease_duration_ms: i64,
) -> Result<(), DurableStoreError> {
    validate_identifier(worker_kind, MAX_WORKER_KIND_BYTES)?;
    validate_identifier(holder_id, MAX_HOLDER_ID_BYTES)?;
    if now_unix_ms < 0 || !(1..=MAX_WORKER_LEASE_MS).contains(&lease_duration_ms) {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), DurableStoreError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use ucr_core::StorageProvider;

    use super::*;

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(160_000);

    fn temp_db() -> PathBuf {
        let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ucr-runtime-worker-{}-{sequence}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn worker_lease_is_exclusive_restart_safe_and_takeover_requires_expiry() {
        let path = temp_db();
        {
            let store = SqliteLocalStore::open(&path).expect("open");
            assert!(
                store
                    .try_acquire_runtime_worker_lease(
                        WEBHOOK_DELIVERY_WORKER_KIND,
                        "worker-a",
                        1_000,
                        120_000,
                    )
                    .expect("acquire a")
            );
            assert!(
                !store
                    .try_acquire_runtime_worker_lease(
                        WEBHOOK_DELIVERY_WORKER_KIND,
                        "worker-b",
                        2_000,
                        120_000,
                    )
                    .expect("reject b")
            );
            assert!(
                store
                    .renew_runtime_worker_lease(
                        WEBHOOK_DELIVERY_WORKER_KIND,
                        "worker-a",
                        3_000,
                        120_000,
                    )
                    .expect("renew a")
            );
            assert_eq!(store.health(), Ok(ucr_core::StorageHealth::Healthy));
        }
        {
            let store = SqliteLocalStore::open(&path).expect("reopen");
            let lease = store
                .runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND)
                .expect("read")
                .expect("lease");
            assert_eq!(lease.holder_id, "worker-a");
            assert!(
                !store
                    .try_acquire_runtime_worker_lease(
                        WEBHOOK_DELIVERY_WORKER_KIND,
                        "worker-b",
                        100_000,
                        120_000,
                    )
                    .expect("still held")
            );
            assert!(
                store
                    .try_acquire_runtime_worker_lease(
                        WEBHOOK_DELIVERY_WORKER_KIND,
                        "worker-b",
                        123_001,
                        120_000,
                    )
                    .expect("take over expired")
            );
            assert!(
                !store
                    .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, "worker-a")
                    .expect("old holder cannot release")
            );
            assert!(
                store
                    .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, "worker-b")
                    .expect("release b")
            );
            assert_eq!(
                store
                    .runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND)
                    .expect("read empty"),
                None
            );
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn v42_to_v43_migration_adds_empty_worker_lease_state() {
        let path = temp_db();
        {
            let store = SqliteLocalStore::open(&path).expect("initialize current");
            assert_eq!(store.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
        }
        {
            let connection = rusqlite::Connection::open(&path).expect("raw connection");
            connection
                .execute_batch("DROP TABLE runtime_worker_leases;")
                .expect("remove v43 worker table");
            connection
                .pragma_update(None, "user_version", crate::SQLITE_SCHEMA_V42)
                .expect("set v42");
        }

        let migrated = SqliteLocalStore::open(&path).expect("migrate v42");
        assert_eq!(migrated.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated
                .runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND)
                .expect("read migrated lease"),
            None
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_holder_cannot_renew_without_reacquiring() {
        let path = temp_db();
        let store = SqliteLocalStore::open(&path).expect("open");
        assert!(
            store
                .try_acquire_runtime_worker_lease(
                    WEBHOOK_DELIVERY_WORKER_KIND,
                    "worker-a",
                    1_000,
                    1_000,
                )
                .expect("acquire")
        );
        assert!(
            !store
                .renew_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, "worker-a", 2_000, 1_000,)
                .expect("expired renewal")
        );
        let _ = fs::remove_file(path);
    }
}
