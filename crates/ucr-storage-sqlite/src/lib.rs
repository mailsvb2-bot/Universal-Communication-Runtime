#![forbid(unsafe_code)]

use std::{fmt, path::Path, sync::Mutex, time::Duration};

use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OptionalExtension, TransactionBehavior, params,
};
use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageHealth, StorageProvider};
use ucr_model::{CommandEnvelope, CommandId, OpaqueId};
use ucr_protocol::{CommandError, CommandReceipt, CommandReceiptStatus, validate_command};

pub const SQLITE_SCHEMA_VERSION: u32 = 1;
pub const UCR_SQLITE_APPLICATION_ID: u32 = 0x5543_5231;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SqliteLocalStore {
    connection: Mutex<Connection>,
}

impl fmt::Debug for SqliteLocalStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteLocalStore")
            .field("connection", &"<sqlite>")
            .finish()
    }
}

impl SqliteLocalStore {
    /// Opens or initializes the local `SQLite` store.
    ///
    /// # Errors
    /// Fails explicitly for open/configuration/migration errors. A database
    /// newer than this binary is never silently downgraded.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableStoreError> {
        let path = path.as_ref();
        prepare_new_store_file(path)?;
        let mut connection = Connection::open(path).map_err(|error| map_sqlite_error(&error))?;
        configure_safe_connection(&connection)?;
        initialize_or_validate_schema(&mut connection)?;
        harden_store_permissions(path)?;
        configure_durability(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, DurableStoreError> {
        self.connection
            .lock()
            .map_err(|_| DurableStoreError::Internal)
    }
}

impl StorageProvider for SqliteLocalStore {
    fn schema_version(&self) -> Result<u32, DurableStoreError> {
        let connection = self.lock_connection()?;
        read_schema_version(&connection)
    }

    fn health(&self) -> Result<StorageHealth, DurableStoreError> {
        let connection = self.lock_connection()?;
        let result: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(|error| map_sqlite_error(&error))?;
        if result == "ok" {
            Ok(StorageHealth::Healthy)
        } else {
            Ok(StorageHealth::Corrupt)
        }
    }
}

impl CommandAcceptanceStore for SqliteLocalStore {
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError> {
        validate_command(command).map_err(map_command_error)?;
        let idempotency_key = command
            .correlation
            .idempotency_key
            .as_deref()
            .ok_or(DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(command);
        let tenant = command.scope.tenant_id.as_opaque().as_str();
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let existing = transaction
            .query_row(
                "SELECT command_id, command_type, payload FROM accepted_commands \
                 WHERE tenant_id = ?1 AND namespace_present = ?2 \
                 AND namespace_id = ?3 AND idempotency_key = ?4",
                params![tenant, namespace.present, namespace.value, idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;

        if let Some((original_id, command_type, payload)) = existing {
            let receipt = duplicate_receipt(command, original_id, &command_type, &payload)?;
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(receipt);
        }

        transaction
            .execute(
                "INSERT INTO accepted_commands (
                    tenant_id, namespace_present, namespace_id, idempotency_key,
                    command_id, command_type, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    tenant,
                    namespace.present,
                    namespace.value,
                    idempotency_key,
                    command.command_id.as_opaque().as_str(),
                    command.command_type,
                    command.payload,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;

        Ok(CommandReceipt {
            command_id: command.command_id.clone(),
            status: CommandReceiptStatus::Accepted,
            original_command_id: None,
        })
    }
}
#[derive(Debug)]
struct NamespaceStorageKey<'a> {
    present: i64,
    value: &'a str,
}

fn namespace_storage_key(command: &CommandEnvelope) -> NamespaceStorageKey<'_> {
    match command.scope.namespace_id.as_ref() {
        Some(namespace_id) => NamespaceStorageKey {
            present: 1,
            value: namespace_id.as_opaque().as_str(),
        },
        None => NamespaceStorageKey {
            present: 0,
            value: "",
        },
    }
}

fn duplicate_receipt(
    incoming: &CommandEnvelope,
    original_id: String,
    original_type: &str,
    original_payload: &[u8],
) -> Result<CommandReceipt, DurableStoreError> {
    if original_type != incoming.command_type || original_payload != incoming.payload {
        return Err(DurableStoreError::Conflict);
    }
    let original_id = OpaqueId::new(original_id).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(CommandReceipt {
        command_id: incoming.command_id.clone(),
        status: CommandReceiptStatus::Duplicate,
        original_command_id: Some(CommandId::from_opaque(original_id)),
    })
}

fn configure_safe_connection(connection: &Connection) -> Result<(), DurableStoreError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|error| map_sqlite_error(&error))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| map_sqlite_error(&error))?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn configure_durability(connection: &Connection) -> Result<(), DurableStoreError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| map_sqlite_error(&error))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}
fn initialize_or_validate_schema(connection: &mut Connection) -> Result<(), DurableStoreError> {
    let application_id = read_application_id(connection)?;
    let version = read_schema_version(connection)?;

    if application_id == 0 && version == 0 {
        if count_user_tables(connection)? != 0 {
            return Err(DurableStoreError::ForeignStore);
        }
        return initialize_schema_v1(connection);
    }
    if application_id != UCR_SQLITE_APPLICATION_ID {
        return Err(DurableStoreError::ForeignStore);
    }
    match version {
        SQLITE_SCHEMA_VERSION => verify_schema_v1(connection),
        _ => Err(DurableStoreError::UnsupportedSchemaVersion),
    }
}

fn initialize_schema_v1(connection: &mut Connection) -> Result<(), DurableStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
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
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))
}

fn verify_schema_v1(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("PRAGMA table_info('accepted_commands')")
        .map_err(|error| map_sqlite_error(&error))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error))?;
    let expected = [
        ("tenant_id", "TEXT", 1, 1),
        ("namespace_present", "INTEGER", 1, 2),
        ("namespace_id", "TEXT", 1, 3),
        ("idempotency_key", "TEXT", 1, 4),
        ("command_id", "TEXT", 1, 0),
        ("command_type", "TEXT", 1, 0),
        ("payload", "BLOB", 1, 0),
    ];
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1 != expected.1
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn count_user_tables(connection: &Connection) -> Result<u32, DurableStoreError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

fn read_application_id(connection: &Connection) -> Result<u32, DurableStoreError> {
    connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error))
}

fn read_schema_version(connection: &Connection) -> Result<u32, DurableStoreError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error))
}

fn map_command_error(error: CommandError) -> DurableStoreError {
    match error {
        CommandError::IdempotencyConflict => DurableStoreError::Conflict,
        CommandError::InvalidCommandType
        | CommandError::MissingIdempotencyKey
        | CommandError::EmptyIdempotencyKey
        | CommandError::IdempotencyKeyTooLong
        | CommandError::PayloadTooLarge => DurableStoreError::InvalidRecord,
    }
}

fn map_sqlite_error(error: &SqliteError) -> DurableStoreError {
    match error {
        SqliteError::SqliteFailure(details, _) => match details.code {
            ErrorCode::DiskFull => DurableStoreError::Full,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => DurableStoreError::Corrupt,
            ErrorCode::ReadOnly
            | ErrorCode::PermissionDenied
            | ErrorCode::AuthorizationForStatementDenied => DurableStoreError::PermissionDenied,
            ErrorCode::DatabaseBusy
            | ErrorCode::DatabaseLocked
            | ErrorCode::SystemIoFailure
            | ErrorCode::CannotOpen => DurableStoreError::Unavailable,
            _ => DurableStoreError::Internal,
        },
        SqliteError::QueryReturnedNoRows => DurableStoreError::Corrupt,
        _ => DurableStoreError::Internal,
    }
}

#[cfg(unix)]
fn prepare_new_store_file(path: &Path) -> Result<(), DurableStoreError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(map_io_error(&error)),
    }
}

#[cfg(not(unix))]
fn prepare_new_store_file(_path: &Path) -> Result<(), DurableStoreError> {
    Ok(())
}

#[cfg(unix)]
fn harden_store_permissions(path: &Path) -> Result<(), DurableStoreError> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let mut permissions = fs::metadata(path)
        .map_err(|error| map_io_error(&error))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|error| map_io_error(&error))
}

#[cfg(not(unix))]
fn harden_store_permissions(_path: &Path) -> Result<(), DurableStoreError> {
    Ok(())
}

fn map_io_error(error: &std::io::Error) -> DurableStoreError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        DurableStoreError::PermissionDenied
    } else {
        DurableStoreError::Unavailable
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

    use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageHealth, StorageProvider};
    use ucr_model::{
        CommandEnvelope, CommandId, CorrelationContext, NamespaceId, OpaqueId, TenantId,
        TenantScope,
    };
    use ucr_protocol::CommandReceiptStatus;

    use super::{SQLITE_SCHEMA_VERSION, SqliteLocalStore, UCR_SQLITE_APPLICATION_ID};

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    struct TestDbPath(PathBuf);

    impl TestDbPath {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ucr-storage-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDbPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn command(id: &str, key: &str, payload: &[u8], namespace: Option<&str>) -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(opaque(id)),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque("tenant-a")),
                namespace_id: namespace.map(|value| NamespaceId::from_opaque(opaque(value))),
            },
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: None,
                idempotency_key: Some(key.to_owned()),
            },
        }
    }
    #[test]
    fn sqlite_store_initializes_schema_and_is_healthy() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(store.health(), Ok(StorageHealth::Healthy));
    }

    #[test]
    fn accepted_command_is_deduplicated_after_restart() {
        let db = TestDbPath::new();
        let first = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            let accepted = store.accept_command(&first).expect("accept command");
            assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        }

        let retry = command("command-b", "retry-a", b"payload", Some("namespace-a"));
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let duplicate = reopened.accept_command(&retry).expect("deduplicate retry");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(first.command_id));
    }

    #[test]
    fn idempotency_conflict_survives_restart() {
        let db = TestDbPath::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .accept_command(&command(
                    "command-a",
                    "retry-a",
                    b"payload-a",
                    Some("namespace-a"),
                ))
                .expect("accept command");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened.accept_command(&command(
                "command-b",
                "retry-a",
                b"payload-b",
                Some("namespace-a"),
            )),
            Err(DurableStoreError::Conflict)
        );
    }
    #[test]
    fn namespace_none_and_named_namespace_are_distinct_keys() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let tenant_root = command("command-a", "same-key", b"root", None);
        let namespace = command("command-b", "same-key", b"namespace", Some("namespace-a"));
        assert_eq!(
            store
                .accept_command(&tenant_root)
                .expect("accept root")
                .status,
            CommandReceiptStatus::Accepted
        );
        assert_eq!(
            store
                .accept_command(&namespace)
                .expect("accept namespace")
                .status,
            CommandReceiptStatus::Accepted
        );
    }

    #[test]
    fn newer_schema_is_rejected_without_downgrade() {
        let db = TestDbPath::new();
        let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("set ucr application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION + 1)
            .expect("set future version");
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::UnsupportedSchemaVersion)
        );
    }

    #[test]
    fn corrupt_database_fails_explicitly() {
        let db = TestDbPath::new();
        fs::write(db.path(), b"not-a-sqlite-database").expect("write corrupt db");
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
    }

    #[test]
    fn sqlite_disk_full_maps_to_explicit_full_failure() {
        let sqlite_error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert_eq!(
            super::map_sqlite_error(&sqlite_error),
            DurableStoreError::Full
        );
    }
    #[test]
    fn foreign_sqlite_database_is_not_adopted_or_mutated() {
        let db = TestDbPath::new();
        let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute("CREATE TABLE foreign_data(value TEXT NOT NULL)", [])
            .expect("create foreign table");
        let journal_before: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("read foreign journal mode");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(db.path())
                .expect("foreign metadata")
                .permissions();
            permissions.set_mode(0o640);
            fs::set_permissions(db.path(), permissions).expect("set foreign permissions");
        }
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::ForeignStore)
        );
        let reopened = rusqlite::Connection::open(db.path()).expect("reopen foreign sqlite");
        let journal_after: String = reopened
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("read unchanged journal mode");
        assert_eq!(journal_after, journal_before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(db.path())
                .expect("foreign metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o640);
        }
    }

    #[test]
    fn concurrent_acceptance_has_single_winner() {
        let db = TestDbPath::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
        let barrier = Arc::new(Barrier::new(3));
        let run = |id: &'static str, payload: &'static [u8]| {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.accept_command(&command(id, "racing-key", payload, Some("namespace-a")))
            })
        };
        let first = run("command-a", b"payload-a");
        let second = run("command-b", b"payload-b");
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DurableStoreError::Conflict)))
                .count(),
            1
        );
    }
    #[test]
    fn sqlite_connection_uses_required_durability_pragmas() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let connection = store.connection.lock().expect("lock sqlite");
        let journal: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode");
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .expect("synchronous");
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign keys");
        let trusted_schema: i64 = connection
            .pragma_query_value(None, "trusted_schema", |row| row.get(0))
            .expect("trusted schema");
        let application_id: u32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .expect("application id");
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(trusted_schema, 0);
        assert_eq!(application_id, UCR_SQLITE_APPLICATION_ID);
    }

    #[test]
    fn uncommitted_acceptance_does_not_survive_reopen() {
        let db = TestDbPath::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
        let mut raw = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
        {
            let tx = raw
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("begin transaction");
            tx.execute(
                "INSERT INTO accepted_commands (tenant_id, namespace_present, namespace_id, idempotency_key, command_id, command_type, payload) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["tenant-a", "namespace-a", "rollback-key", "command-a", "ucr.message.send", b"old".as_slice()],
            ).expect("insert uncommitted row");
        }
        drop(raw);
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let receipt = reopened
            .accept_command(&command(
                "command-b",
                "rollback-key",
                b"new",
                Some("namespace-a"),
            ))
            .expect("accept after rollback");
        assert_eq!(receipt.status, CommandReceiptStatus::Accepted);
    }
    #[cfg(unix)]
    #[test]
    fn sqlite_database_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let db = TestDbPath::new();
        drop(SqliteLocalStore::open(db.path()).expect("open store"));
        let mode = fs::metadata(db.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    #[test]
    fn schema_shape_drift_is_rejected_even_at_known_version() {
        let db = TestDbPath::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
        let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute(
                "ALTER TABLE accepted_commands ADD COLUMN unexpected TEXT",
                [],
            )
            .expect("alter schema");
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
    }
    #[cfg(unix)]
    #[test]
    fn sqlite_sidecar_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .accept_command(&command(
                "command-a",
                "sidecar-key",
                b"payload",
                Some("namespace-a"),
            ))
            .expect("write record");
        for suffix in ["-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", db.path().display()));
            if path.exists() {
                let mode = fs::metadata(path)
                    .expect("sidecar metadata")
                    .permissions()
                    .mode()
                    & 0o077;
                assert_eq!(mode, 0);
            }
        }
    }
}
