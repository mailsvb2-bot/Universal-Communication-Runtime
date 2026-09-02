#![forbid(unsafe_code)]

mod anti_entropy_store;
mod delivery_store;
mod event_journal;
mod message_store;
mod recovery_plan;
mod replay;
mod sync_store;

use std::{fmt, path::Path, sync::Mutex, time::Duration};

use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OptionalExtension, TransactionBehavior, params,
};
use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageHealth, StorageProvider};
use ucr_model::{CommandEnvelope, CommandId, OpaqueId, TenantScope};
use ucr_protocol::{CommandError, CommandReceipt, CommandReceiptStatus, validate_command};

const SQLITE_SCHEMA_V1: u32 = 1;
const SQLITE_SCHEMA_V2: u32 = 2;
const SQLITE_SCHEMA_V3: u32 = 3;
const SQLITE_SCHEMA_V4: u32 = 4;
const SQLITE_SCHEMA_V5: u32 = 5;
const SQLITE_SCHEMA_V6: u32 = 6;
const SQLITE_SCHEMA_V7: u32 = 7;
pub const SQLITE_SCHEMA_VERSION: u32 = 8;
pub const UCR_SQLITE_APPLICATION_ID: u32 = 0x5543_5231;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const V2_OBJECTS_SQL: &str = "
CREATE UNIQUE INDEX accepted_commands_scope_command_id
ON accepted_commands(tenant_id, namespace_present, namespace_id, command_id);

CREATE TABLE events (
    journal_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload BLOB NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    on_behalf_of TEXT,
    source_device_id TEXT NOT NULL,
    source_identity_id TEXT NOT NULL,
    wall_time_unix_ms INTEGER NOT NULL,
    logical_order BLOB NOT NULL CHECK(length(logical_order) = 8),
    correlation_id TEXT NOT NULL,
    causation_id TEXT,
    idempotency_key TEXT,
    schema_major INTEGER NOT NULL,
    schema_minor INTEGER NOT NULL,
    integrity_metadata BLOB NOT NULL,
    UNIQUE(tenant_id, namespace_present, namespace_id, event_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
);

CREATE TABLE command_terminal_events (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    terminal_event_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, command_id),
    UNIQUE(tenant_id, namespace_present, namespace_id, terminal_event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, command_id)
        REFERENCES accepted_commands(tenant_id, namespace_present, namespace_id, command_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, terminal_event_id)
        REFERENCES events(tenant_id, namespace_present, namespace_id, event_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
);";

const V3_OBJECTS_SQL: &str = "
CREATE TABLE handshake_replay (
    peer_verifying_key BLOB NOT NULL CHECK(length(peer_verifying_key) = 32),
    transcript_binding BLOB NOT NULL CHECK(length(transcript_binding) = 32),
    PRIMARY KEY(peer_verifying_key, transcript_binding)
 ) WITHOUT ROWID;";

const V4_OBJECTS_SQL: &str = "
CREATE TABLE recovery_plans (
    plan_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    historical_access TEXT NOT NULL CHECK(historical_access IN ('none', 'explicit_encrypted_recovery')),
    trust_model TEXT NOT NULL CHECK(trust_model IN ('user_controlled', 'organization_managed')),
    recovered_device_state TEXT NOT NULL CHECK(recovered_device_state = 'reverification_required'),
    UNIQUE(tenant_id, namespace_present, namespace_id, identity_id, plan_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE recovery_authorities (
    plan_id TEXT NOT NULL,
    method TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    PRIMARY KEY(plan_id, method, authority_id),
    FOREIGN KEY(plan_id) REFERENCES recovery_plans(plan_id) ON DELETE CASCADE,
    CHECK(method IN ('recovery_code', 'recovery_key', 'trusted_device', 'hardware_backed', 'encrypted_backup', 'organization_managed')),
    CHECK((method IN ('recovery_code', 'recovery_key', 'encrypted_backup') AND authority_id = '') OR
          (method IN ('trusted_device', 'hardware_backed', 'organization_managed') AND authority_id <> ''))
) WITHOUT ROWID;

CREATE TABLE active_recovery_plans (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, identity_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, identity_id, plan_id)
        REFERENCES recovery_plans(tenant_id, namespace_present, namespace_id, identity_id, plan_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;";

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
        let namespace = namespace_storage_key(&command.scope);
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

        let command_id_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accepted_commands \
                 WHERE tenant_id = ?1 AND namespace_present = ?2 \
                 AND namespace_id = ?3 AND command_id = ?4)",
                params![
                    tenant,
                    namespace.present,
                    namespace.value,
                    command.command_id.as_opaque().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if command_id_exists {
            return Err(DurableStoreError::Conflict);
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

fn namespace_storage_key(scope: &TenantScope) -> NamespaceStorageKey<'_> {
    match scope.namespace_id.as_ref() {
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
        return initialize_schema_v8(connection);
    }
    if application_id != UCR_SQLITE_APPLICATION_ID {
        return Err(DurableStoreError::ForeignStore);
    }
    match version {
        SQLITE_SCHEMA_V1 => {
            migrate_v1_to_v2(connection)?;
            migrate_v2_to_v3(connection)?;
            migrate_v3_to_v4(connection)?;
            migrate_v4_to_v5(connection)?;
            migrate_v5_to_v6(connection)?;
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V2 => {
            migrate_v2_to_v3(connection)?;
            migrate_v3_to_v4(connection)?;
            migrate_v4_to_v5(connection)?;
            migrate_v5_to_v6(connection)?;
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V3 => {
            migrate_v3_to_v4(connection)?;
            migrate_v4_to_v5(connection)?;
            migrate_v5_to_v6(connection)?;
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V4 => {
            migrate_v4_to_v5(connection)?;
            migrate_v5_to_v6(connection)?;
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V5 => {
            migrate_v5_to_v6(connection)?;
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V6 => {
            migrate_v6_to_v7(connection)?;
            migrate_v7_to_v8(connection)
        }
        SQLITE_SCHEMA_V7 => migrate_v7_to_v8(connection),
        SQLITE_SCHEMA_VERSION => event_journal::verify_schema_v8(connection),
        _ => Err(DurableStoreError::UnsupportedSchemaVersion),
    }
}

fn initialize_schema_v8(connection: &mut Connection) -> Result<(), DurableStoreError> {
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
        .execute_batch(V2_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    transaction
        .execute_batch(V3_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    transaction
        .execute_batch(V4_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    message_store::create_v5_objects(&transaction)?;
    delivery_store::create_v6_objects(&transaction)?;
    sync_store::create_v7_objects(&transaction)?;
    event_journal::create_v8_objects(&transaction)?;
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

fn migrate_v1_to_v2(connection: &mut Connection) -> Result<(), DurableStoreError> {
    verify_accepted_commands_schema(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .execute_batch(V2_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V2)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    verify_schema_v2(connection)
}

fn migrate_v2_to_v3(connection: &mut Connection) -> Result<(), DurableStoreError> {
    verify_schema_v2(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .execute_batch(V3_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V3)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    verify_schema_v3(connection)
}

fn migrate_v3_to_v4(connection: &mut Connection) -> Result<(), DurableStoreError> {
    verify_schema_v3(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .execute_batch(V4_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V4)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    verify_schema_v4(connection)
}

fn migrate_v4_to_v5(connection: &mut Connection) -> Result<(), DurableStoreError> {
    verify_schema_v4(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    message_store::create_v5_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V5)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    message_store::verify_schema_v5(connection)
}

fn migrate_v5_to_v6(connection: &mut Connection) -> Result<(), DurableStoreError> {
    message_store::verify_schema_v5(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    delivery_store::create_v6_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V6)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    delivery_store::verify_schema_v6(connection)
}

fn migrate_v6_to_v7(connection: &mut Connection) -> Result<(), DurableStoreError> {
    delivery_store::verify_schema_v6(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    sync_store::create_v7_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V7)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    sync_store::verify_schema_v7(connection)
}

fn migrate_v7_to_v8(connection: &mut Connection) -> Result<(), DurableStoreError> {
    sync_store::verify_schema_v7(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    event_journal::create_v8_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    event_journal::verify_schema_v8(connection)
}

fn verify_schema_v2(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_accepted_commands_schema(connection)?;
    verify_table_columns(
        connection,
        "events",
        &[
            ("journal_seq", "INTEGER", 0, 1),
            ("tenant_id", "TEXT", 1, 0),
            ("namespace_present", "INTEGER", 1, 0),
            ("namespace_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 0),
            ("event_type", "TEXT", 1, 0),
            ("payload", "BLOB", 1, 0),
            ("actor_id", "TEXT", 1, 0),
            ("actor_kind", "TEXT", 1, 0),
            ("on_behalf_of", "TEXT", 0, 0),
            ("source_device_id", "TEXT", 1, 0),
            ("source_identity_id", "TEXT", 1, 0),
            ("wall_time_unix_ms", "INTEGER", 1, 0),
            ("logical_order", "BLOB", 1, 0),
            ("correlation_id", "TEXT", 1, 0),
            ("causation_id", "TEXT", 0, 0),
            ("idempotency_key", "TEXT", 0, 0),
            ("schema_major", "INTEGER", 1, 0),
            ("schema_minor", "INTEGER", 1, 0),
            ("integrity_metadata", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "command_terminal_events",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("command_id", "TEXT", 1, 4),
            ("terminal_event_id", "TEXT", 1, 0),
        ],
    )?;
    let index_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = ?1)",
            ["accepted_commands_scope_command_id"],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !index_exists {
        return Err(DurableStoreError::Corrupt);
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error))?;
    let mut violations = foreign_key_check
        .query([])
        .map_err(|error| map_sqlite_error(&error))?;
    if violations
        .next()
        .map_err(|error| map_sqlite_error(&error))?
        .is_some()
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn verify_schema_v3(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_schema_v2(connection)?;
    verify_table_columns(
        connection,
        "handshake_replay",
        &[
            ("peer_verifying_key", "BLOB", 1, 1),
            ("transcript_binding", "BLOB", 1, 2),
        ],
    )
}

fn verify_schema_v4(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_schema_v3(connection)?;
    verify_table_columns(
        connection,
        "recovery_plans",
        &[
            ("plan_id", "TEXT", 1, 1),
            ("tenant_id", "TEXT", 1, 0),
            ("namespace_present", "INTEGER", 1, 0),
            ("namespace_id", "TEXT", 1, 0),
            ("identity_id", "TEXT", 1, 0),
            ("historical_access", "TEXT", 1, 0),
            ("trust_model", "TEXT", 1, 0),
            ("recovered_device_state", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "recovery_authorities",
        &[
            ("plan_id", "TEXT", 1, 1),
            ("method", "TEXT", 1, 2),
            ("authority_id", "TEXT", 1, 3),
        ],
    )?;
    verify_table_columns(
        connection,
        "active_recovery_plans",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("identity_id", "TEXT", 1, 4),
            ("plan_id", "TEXT", 1, 0),
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

fn verify_accepted_commands_schema(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "accepted_commands",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("idempotency_key", "TEXT", 1, 4),
            ("command_id", "TEXT", 1, 0),
            ("command_type", "TEXT", 1, 0),
            ("payload", "BLOB", 1, 0),
        ],
    )
}

fn verify_table_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), DurableStoreError> {
    let sql = format!("PRAGMA table_info('{table}')");
    let mut statement = connection
        .prepare(&sql)
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

fn map_schema_change_error(error: &SqliteError) -> DurableStoreError {
    match error {
        SqliteError::SqliteFailure(details, _)
            if details.code == ErrorCode::ConstraintViolation =>
        {
            DurableStoreError::Corrupt
        }
        _ => map_sqlite_error(error),
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

    use ucr_core::{
        CommandAcceptanceStore, CommandOutcomeStore, DurableStoreError, EventAppendStatus,
        EventJournalStore, StorageHealth, StorageProvider,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, CorrelationContext, DeviceId,
        DeviceRef, EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, ProtocolVersion,
        TenantId, TenantScope,
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

    fn event(id: &str, causation: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(opaque(id)),
            scope: command("scope-source", "scope-key", b"", Some("namespace-a")).scope,
            event_type: "ucr.command.completed".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(opaque("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(opaque("device-a")),
                identity_id: IdentityId::from_opaque(opaque("identity-a")),
            },
            wall_time_unix_ms: 1_788_330_000_000,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: Some(opaque(causation)),
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn create_v1_store(path: &std::path::Path) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(path).expect("open v1 fixture");
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
            .expect("create v1 schema");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("set application id");
        connection
            .pragma_update(None, "user_version", 1_u32)
            .expect("set v1 version");
        connection
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
    fn v1_store_migrates_and_preserves_command_deduplication() {
        let db = TestDbPath::new();
        let connection = create_v1_store(db.path());
        connection
            .execute(
                "INSERT INTO accepted_commands VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    "tenant-a",
                    1_i64,
                    "namespace-a",
                    "retry-a",
                    "command-a",
                    "ucr.message.send",
                    b"payload".as_slice()
                ],
            )
            .expect("insert v1 acceptance");
        drop(connection);

        let store = SqliteLocalStore::open(db.path()).expect("migrate v1");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let retry = command("command-b", "retry-a", b"payload", Some("namespace-a"));
        let receipt = store
            .accept_command(&retry)
            .expect("deduplicate migrated command");
        assert_eq!(receipt.status, CommandReceiptStatus::Duplicate);
        assert_eq!(
            receipt.original_command_id,
            Some(CommandId::from_opaque(opaque("command-a")))
        );
    }

    #[test]
    fn v1_duplicate_scoped_command_ids_block_migration_without_version_bump() {
        let db = TestDbPath::new();
        let connection = create_v1_store(db.path());
        for key in ["retry-a", "retry-b"] {
            connection
                .execute(
                    "INSERT INTO accepted_commands VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        "tenant-a",
                        1_i64,
                        "namespace-a",
                        key,
                        "command-a",
                        "ucr.message.send",
                        b"payload".as_slice()
                    ],
                )
                .expect("insert duplicate command id fixture");
        }
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
        let reopened = rusqlite::Connection::open(db.path()).expect("reopen v1 fixture");
        let version: u32 = reopened
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read user version");
        assert_eq!(version, 1);
    }

    #[test]
    fn event_append_survives_restart_and_is_idempotent() {
        let db = TestDbPath::new();
        let first = event("event-a", "command-a", b"done");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(store.append_event(&first), Ok(EventAppendStatus::Appended));
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened.append_event(&first),
            Ok(EventAppendStatus::Duplicate)
        );
        let changed = event("event-a", "command-a", b"changed");
        assert_eq!(
            reopened.append_event(&changed),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn terminal_link_creation_is_appended_even_when_event_already_exists() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let accepted = command(
            "command-preexisting",
            "retry-preexisting",
            b"payload",
            Some("namespace-a"),
        );
        let terminal = event("event-preexisting", "command-preexisting", b"done");
        store.accept_command(&accepted).expect("accepted");
        assert_eq!(
            store.append_event(&terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.terminal_event(&accepted.scope, &accepted.command_id),
            Ok(Some(terminal.event_id.clone()))
        );
    }

    #[test]
    fn terminal_event_survives_restart_and_retry() {
        let db = TestDbPath::new();
        let accepted = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        let terminal = event("event-a", "command-a", b"done");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.accept_command(&accepted).expect("accept command");
            assert_eq!(
                store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
                Ok(EventAppendStatus::Appended)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened.terminal_event(&accepted.scope, &accepted.command_id),
            Ok(Some(terminal.event_id.clone()))
        );
        assert_eq!(
            reopened.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Duplicate)
        );
    }

    #[test]
    fn terminal_event_requires_accepted_command_and_matching_causation() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let accepted = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        let terminal = event("event-a", "command-a", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Err(DurableStoreError::InvalidRecord)
        );
        store.accept_command(&accepted).expect("accept command");
        let wrong = event("event-b", "command-b", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &wrong),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn second_terminal_event_for_same_command_conflicts() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let accepted = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        store.accept_command(&accepted).expect("accept command");
        store
            .record_terminal_event(
                &accepted.scope,
                &accepted.command_id,
                &event("event-a", "command-a", b"done"),
            )
            .expect("record terminal");
        assert_eq!(
            store.record_terminal_event(
                &accepted.scope,
                &accepted.command_id,
                &event("event-b", "command-a", b"done-again"),
            ),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn scoped_command_id_reuse_conflicts_even_with_new_idempotency_key() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .accept_command(&command(
                "command-a",
                "retry-a",
                b"payload",
                Some("namespace-a"),
            ))
            .expect("accept command");
        assert_eq!(
            store.accept_command(&command(
                "command-a",
                "retry-b",
                b"payload",
                Some("namespace-a"),
            )),
            Err(DurableStoreError::Conflict)
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
    fn foreign_key_violation_is_rejected_on_reopen() {
        let db = TestDbPath::new();
        let accepted = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        let terminal = event("event-a", "command-a", b"done");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.accept_command(&accepted).expect("accept command");
            store
                .record_terminal_event(&accepted.scope, &accepted.command_id, &terminal)
                .expect("record terminal");
        }
        let raw = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
        raw.pragma_update(None, "foreign_keys", "OFF")
            .expect("disable foreign keys for corruption fixture");
        raw.execute("DELETE FROM events WHERE event_id = ?1", ["event-a"])
            .expect("create dangling terminal link");
        drop(raw);
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
    fn concurrent_terminal_events_have_single_winner() {
        let db = TestDbPath::new();
        let accepted = command("command-a", "retry-a", b"payload", Some("namespace-a"));
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.accept_command(&accepted).expect("accept command");
        }
        let barrier = Arc::new(Barrier::new(3));
        let run = |event_id: &'static str| {
            let path = db.path().to_owned();
            let scope = accepted.scope.clone();
            let command_id = accepted.command_id.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.record_terminal_event(
                    &scope,
                    &command_id,
                    &event(event_id, "command-a", event_id.as_bytes()),
                )
            })
        };
        let first = run("event-a");
        let second = run("event-b");
        barrier.wait();
        let results = [
            first.join().expect("first terminal thread"),
            second.join().expect("second terminal thread"),
        ];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(EventAppendStatus::Appended)))
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
