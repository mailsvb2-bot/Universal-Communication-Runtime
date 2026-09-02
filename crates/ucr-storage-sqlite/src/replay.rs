use rusqlite::{TransactionBehavior, params};
use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};

use super::{SqliteLocalStore, map_sqlite_error};

impl ReplayProtector for SqliteLocalStore {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut connection = self.lock_connection().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_store_error(map_sqlite_error(&error)))?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO handshake_replay (
                    peer_verifying_key, transcript_binding
                 ) VALUES (?1, ?2)",
                params![
                    peer_verifying_key.0.as_slice(),
                    binding.as_bytes().as_slice()
                ],
            )
            .map_err(|error| map_store_error(map_sqlite_error(&error)))?;
        if inserted == 0 {
            return Err(ReplayError::Replayed);
        }
        transaction
            .commit()
            .map_err(|error| map_store_error(map_sqlite_error(&error)))?;
        Ok(())
    }
}
fn map_store_error(error: ucr_core::DurableStoreError) -> ReplayError {
    match error {
        ucr_core::DurableStoreError::Full => ReplayError::StorageFull,
        ucr_core::DurableStoreError::Corrupt => ReplayError::CorruptState,
        ucr_core::DurableStoreError::Unavailable => ReplayError::Unavailable,
        ucr_core::DurableStoreError::PermissionDenied => ReplayError::PermissionDenied,
        ucr_core::DurableStoreError::InvalidRecord
        | ucr_core::DurableStoreError::Conflict
        | ucr_core::DurableStoreError::UnsupportedSchemaVersion
        | ucr_core::DurableStoreError::ForeignStore
        | ucr_core::DurableStoreError::Internal => ReplayError::Internal,
    }
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
    use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};

    use super::SqliteLocalStore;
    use crate::{
        SQLITE_SCHEMA_V2, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID, V2_OBJECTS_SQL,
    };

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(10_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-replay-{}-{sequence}.sqlite3",
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

    fn peer() -> VerifyingKeyBytes {
        VerifyingKeyBytes([7_u8; 32])
    }

    fn binding() -> TranscriptBinding {
        TranscriptBinding::from_bytes([9_u8; 32])
    }

    #[test]
    fn replay_record_survives_restart() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(store.record_once(&peer(), &binding()), Ok(()));
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened.record_once(&peer(), &binding()),
            Err(ReplayError::Replayed)
        );
    }

    #[test]
    fn concurrent_replay_record_has_single_winner() {
        let db = TestDb::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
        let barrier = Arc::new(Barrier::new(3));
        let run = || {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.record_once(&peer(), &binding())
            })
        };
        let first = run();
        let second = run();
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ReplayError::Replayed)))
                .count(),
            1
        );
    }

    #[test]
    fn v2_store_migrates_to_v3_without_losing_accepted_commands() {
        let db = TestDb::new();
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute_batch(
                "CREATE TABLE accepted_commands (
                tenant_id TEXT NOT NULL,
                namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
                namespace_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                command_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (tenant_id, namespace_present, namespace_id, idempotency_key),
                CHECK((namespace_present = 0 AND namespace_id = '') OR
                      (namespace_present = 1 AND namespace_id <> ''))
            ) WITHOUT ROWID;",
            )
            .expect("create v1 base");
        connection
            .execute_batch(V2_OBJECTS_SQL)
            .expect("create v2 objects");
        connection
            .execute(
                "INSERT INTO accepted_commands VALUES (?1,1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    "tenant-a",
                    "namespace-a",
                    "retry-a",
                    "command-a",
                    "ucr.message.send",
                    b"payload"
                ],
            )
            .expect("insert accepted command");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V2)
            .expect("v2 version");
        drop(connection);

        let store = SqliteLocalStore::open(db.path()).expect("migrate v2 to v3");
        assert_eq!(
            ucr_core::StorageProvider::schema_version(&store),
            Ok(SQLITE_SCHEMA_VERSION)
        );
        assert_eq!(store.record_once(&peer(), &binding()), Ok(()));
        drop(store);

        let connection = Connection::open(db.path()).expect("inspect migrated sqlite");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM accepted_commands WHERE command_id = 'command-a'",
                [],
                |row| row.get(0),
            )
            .expect("count preserved command");
        assert_eq!(count, 1);
    }
}
