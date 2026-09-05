#![forbid(unsafe_code)]

mod anti_entropy_store;
mod command_store;
mod delivery_store;
mod device_store;
mod event_journal;
mod identity_binding_store;
mod identity_store;
mod intent_store;
mod message_store;
mod permission_store;
mod recovery_plan;
mod replay;
mod service_control_store;
mod service_credential_store;
mod sync_store;
mod trusted_key_store;

use std::{fmt, path::Path, sync::Mutex, time::Duration};

use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OptionalExtension, TransactionBehavior, params,
};
use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageHealth, StorageProvider};
use ucr_model::{CommandEnvelope, CommandId, OpaqueId, TenantScope};
use ucr_protocol::{
    CommandError, CommandReceipt, accepted_command_receipt, canonical_command,
    duplicate_command_receipt,
};

const SQLITE_SCHEMA_V1: u32 = 1;
const SQLITE_SCHEMA_V2: u32 = 2;
const SQLITE_SCHEMA_V3: u32 = 3;
const SQLITE_SCHEMA_V4: u32 = 4;
const SQLITE_SCHEMA_V5: u32 = 5;
const SQLITE_SCHEMA_V6: u32 = 6;
const SQLITE_SCHEMA_V7: u32 = 7;
const SQLITE_SCHEMA_V8: u32 = 8;
const SQLITE_SCHEMA_V9: u32 = 9;
const SQLITE_SCHEMA_V10: u32 = 10;
const SQLITE_SCHEMA_V11: u32 = 11;
const SQLITE_SCHEMA_V12: u32 = 12;
const SQLITE_SCHEMA_V13: u32 = 13;
const SQLITE_SCHEMA_V14: u32 = 14;
const SQLITE_SCHEMA_V15: u32 = 15;
const SQLITE_SCHEMA_V16: u32 = 16;
const SQLITE_SCHEMA_V17: u32 = 17;
const SQLITE_SCHEMA_V18: u32 = 18;
pub const SQLITE_SCHEMA_VERSION: u32 = 19;
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
        let command = canonical_command(command).map_err(map_command_error)?;
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
            let original_command_id = CommandId::from_opaque(
                OpaqueId::new(original_id).map_err(|_| DurableStoreError::Corrupt)?,
            );
            let protocol = command_store::load_protocol_metadata(
                &transaction,
                &command.scope,
                &original_command_id,
            )?
            .ok_or(DurableStoreError::Corrupt)?;
            let receipt = duplicate_receipt(
                &command,
                original_command_id,
                &command_type,
                &payload,
                &protocol,
            )?;
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
                    command.command_type.as_str(),
                    command.payload.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        command_store::insert_protocol_metadata(&transaction, &command)?;
        #[cfg(test)]
        test_pause_command_acceptance_before_commit(&command.command_id);
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;

        Ok(accepted_command_receipt(command.command_id.clone()))
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
    original_id: CommandId,
    original_type: &str,
    original_payload: &[u8],
    original_protocol: &command_store::StoredCommandProtocol,
) -> Result<CommandReceipt, DurableStoreError> {
    if original_type != incoming.command_type
        || original_payload != incoming.payload
        || original_protocol.schema_version != incoming.schema_version
        || original_protocol.extensions != incoming.extensions
    {
        return Err(DurableStoreError::Conflict);
    }
    Ok(duplicate_command_receipt(
        incoming.command_id.clone(),
        original_id,
    ))
}

#[cfg(test)]
fn test_pause_command_acceptance_before_commit(command_id: &CommandId) {
    use std::{fs, thread, time::Duration};

    let Some(expected_id) = std::env::var_os("UCR_TEST_PROCESS_KILL_COMMAND_ID") else {
        return;
    };
    if command_id.as_opaque().as_str() != expected_id.to_string_lossy() {
        return;
    }
    let ready_path = std::env::var_os("UCR_TEST_PROCESS_KILL_READY_PATH")
        .expect("process-kill child must provide ready path");
    fs::write(ready_path, b"before-commit").expect("signal process-kill parent");
    loop {
        thread::sleep(Duration::from_mins(1));
    }
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
        return initialize_schema_v19(connection);
    }
    if application_id != UCR_SQLITE_APPLICATION_ID {
        return Err(DurableStoreError::ForeignStore);
    }
    if version > SQLITE_SCHEMA_VERSION {
        return Err(DurableStoreError::UnsupportedSchemaVersion);
    }
    if version == SQLITE_SCHEMA_VERSION {
        return identity_store::verify_schema_v19(connection);
    }
    migrate_known_schema_to_current(connection, version)
}

fn migrate_known_schema_to_current(
    connection: &mut Connection,
    mut version: u32,
) -> Result<(), DurableStoreError> {
    while version < SQLITE_SCHEMA_VERSION {
        match version {
            SQLITE_SCHEMA_V1 => migrate_v1_to_v2(connection)?,
            SQLITE_SCHEMA_V2 => migrate_v2_to_v3(connection)?,
            SQLITE_SCHEMA_V3 => migrate_v3_to_v4(connection)?,
            SQLITE_SCHEMA_V4 => migrate_v4_to_v5(connection)?,
            SQLITE_SCHEMA_V5 => migrate_v5_to_v6(connection)?,
            SQLITE_SCHEMA_V6 => migrate_v6_to_v7(connection)?,
            SQLITE_SCHEMA_V7 => migrate_v7_to_v8(connection)?,
            SQLITE_SCHEMA_V8 => migrate_v8_to_v9(connection)?,
            SQLITE_SCHEMA_V9 => migrate_v9_to_v10(connection)?,
            SQLITE_SCHEMA_V10 => migrate_v10_to_v11(connection)?,
            SQLITE_SCHEMA_V11 => migrate_v11_to_v12(connection)?,
            SQLITE_SCHEMA_V12 => migrate_v12_to_v13(connection)?,
            SQLITE_SCHEMA_V13 => migrate_v13_to_v14(connection)?,
            SQLITE_SCHEMA_V14 => migrate_v14_to_v15(connection)?,
            SQLITE_SCHEMA_V15 => migrate_v15_to_v16(connection)?,
            SQLITE_SCHEMA_V16 => migrate_v16_to_v17(connection)?,
            SQLITE_SCHEMA_V17 => migrate_v17_to_v18(connection)?,
            SQLITE_SCHEMA_V18 => migrate_v18_to_v19(connection)?,
            _ => return Err(DurableStoreError::UnsupportedSchemaVersion),
        }
        version += 1;
    }
    identity_store::verify_schema_v19(connection)
}

fn initialize_schema_v19(connection: &mut Connection) -> Result<(), DurableStoreError> {
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
    command_store::create_v9_objects(&transaction)?;
    message_store::create_v10_objects(&transaction)?;
    trusted_key_store::create_v11_objects(&transaction)?;
    permission_store::create_v12_objects(&transaction)?;
    service_credential_store::create_v13_objects(&transaction)?;
    service_control_store::create_v14_objects(&transaction)?;
    device_store::create_v15_objects(&transaction)?;
    intent_store::create_v16_objects(&transaction)?;
    service_control_store::create_v17_objects(&transaction)?;
    identity_binding_store::create_v18_objects(&transaction)?;
    identity_store::create_v19_objects(&transaction)?;
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
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V8)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    event_journal::verify_schema_v8(connection)
}

fn migrate_v8_to_v9(connection: &mut Connection) -> Result<(), DurableStoreError> {
    event_journal::verify_schema_v8(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    command_store::create_v9_objects(&transaction)?;
    command_store::backfill_legacy_v8_commands(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V9)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    command_store::verify_schema_v9(connection)
}

fn migrate_v9_to_v10(connection: &mut Connection) -> Result<(), DurableStoreError> {
    command_store::verify_schema_v9(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    message_store::create_v10_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V10)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    message_store::verify_schema_v10(connection)
}

fn migrate_v10_to_v11(connection: &mut Connection) -> Result<(), DurableStoreError> {
    message_store::verify_schema_v10(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    trusted_key_store::create_v11_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V11)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    trusted_key_store::verify_schema_v11(connection)
}

fn migrate_v11_to_v12(connection: &mut Connection) -> Result<(), DurableStoreError> {
    trusted_key_store::verify_schema_v11(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    permission_store::create_v12_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V12)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    permission_store::verify_schema_v12(connection)
}

fn migrate_v12_to_v13(connection: &mut Connection) -> Result<(), DurableStoreError> {
    permission_store::verify_schema_v12(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    service_credential_store::create_v13_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V13)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    service_credential_store::verify_schema_v13(connection)
}

fn migrate_v13_to_v14(connection: &mut Connection) -> Result<(), DurableStoreError> {
    service_credential_store::verify_schema_v13(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    service_control_store::create_v14_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V14)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    service_control_store::verify_schema_v14(connection)
}

fn migrate_v14_to_v15(connection: &mut Connection) -> Result<(), DurableStoreError> {
    service_control_store::verify_schema_v14(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    device_store::create_v15_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V15)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    device_store::verify_schema_v15(connection)
}

fn migrate_v15_to_v16(connection: &mut Connection) -> Result<(), DurableStoreError> {
    device_store::verify_schema_v15(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    intent_store::create_v16_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V16)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    intent_store::verify_schema_v16(connection)
}

fn migrate_v16_to_v17(connection: &mut Connection) -> Result<(), DurableStoreError> {
    intent_store::verify_schema_v16(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    service_control_store::create_v17_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V17)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    service_control_store::verify_schema_v17(connection)
}

fn migrate_v17_to_v18(connection: &mut Connection) -> Result<(), DurableStoreError> {
    service_control_store::verify_schema_v17(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    identity_binding_store::create_v18_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_V18)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    identity_binding_store::verify_schema_v18(connection)
}

fn migrate_v18_to_v19(connection: &mut Connection) -> Result<(), DurableStoreError> {
    identity_binding_store::verify_schema_v18(connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    identity_store::create_v19_objects(&transaction)?;
    transaction
        .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
        .map_err(|error| map_sqlite_error(&error))?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    identity_store::verify_schema_v19(connection)
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
        | CommandError::PayloadTooLarge
        | CommandError::InvalidSchemaVersion
        | CommandError::InvalidExtension
        | CommandError::DuplicateExtension
        | CommandError::TooManyExtensions
        | CommandError::ExtensionPayloadTooLarge => DurableStoreError::InvalidRecord,
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
        process::Command,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use ucr_core::{
        CommandAcceptanceStore, CommandOutcomeStore, ConversationStore, DurableStoreError,
        EventAppendStatus, EventJournalStore, ExternalIdentityBindingLookup,
        ExternalIdentityBindingStore, IdentityStore, IntegrationCommandIngress, IntegrationIngress,
        PermissionGrantStore, ServiceAuditStore, ServiceCredentialStore, ServiceQuotaStore,
        StorageHealth, StorageProvider, SystemServiceQuotaClock, issue_service_credential,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, ConversationId, ConversationKind,
        ConversationRecord, ConversationRef, CorrelationContext, DeviceId, DeviceRef,
        EventEnvelope, EventId, ExternalIdentityBinding, IdentityEvidence, IdentityId,
        IdentityOwnership, IdentityRecord, IntegrationId, NamespaceId, OpaqueId, PermissionGrant,
        PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, ProtocolExtension,
        ProtocolVersion, ScopedPrincipal, ServiceAuditOperationRef, ServiceAuditOutcome,
        ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{
        COMMAND_ACCEPT_PERMISSION, CONVERSATION_READ_PERMISSION, CONVERSATION_WRITE_PERMISSION,
        CommandReceiptStatus, DEFAULT_MAX_PAYLOAD_LEN, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
        EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, IDENTITY_CREATE_PERMISSION,
        IDENTITY_READ_PERMISSION, MAX_PROTOCOL_EXTENSIONS, SERVICE_AUDIT_COMMAND_OPERATION_KIND,
        SERVICE_AUDIT_CONVERSATION_CREATE_OPERATION_KIND,
        SERVICE_AUDIT_CONVERSATION_READ_OPERATION_KIND,
        SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND,
        SERVICE_AUDIT_EXTERNAL_IDENTITY_READ_OPERATION_KIND,
        SERVICE_AUDIT_IDENTITY_READ_OPERATION_KIND,
    };

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
            schema_version: ProtocolVersion::new(1, 0),
            extensions: Vec::new(),
        }
    }

    fn service_subject(scope: &TenantScope, id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque(id)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn exact_grant(
        subject: &ScopedPrincipal,
        permission: &str,
        scope: &TenantScope,
    ) -> PermissionGrant {
        PermissionGrant {
            grantee: subject.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(scope.clone()),
        }
    }

    fn assert_single_operation_audit(
        store: &SqliteLocalStore,
        scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
        context: &str,
    ) {
        let rows = store
            .service_audit_records_for_operation(scope, operation, 4)
            .unwrap_or_else(|error| panic!("{context}: {error:?}"));
        assert_eq!(rows.len(), 1, "{context}");
    }

    fn grant_exact_permission(
        store: &SqliteLocalStore,
        subject: &ScopedPrincipal,
        permission: &str,
        scope: &TenantScope,
        context: &str,
    ) {
        store
            .grant_permission(&exact_grant(subject, permission, scope))
            .unwrap_or_else(|error| panic!("{context}: {error:?}"));
    }

    fn seed_conversation_api_fixture(
        store: &SqliteLocalStore,
        subject: &ScopedPrincipal,
        credential: &ucr_model::ServiceCredentialRecord,
        scope: &TenantScope,
        quota: &ServiceQuotaPolicy,
    ) {
        store
            .provision_service_credential(credential)
            .expect("persist credential");
        grant_exact_permission(
            store,
            subject,
            CONVERSATION_WRITE_PERMISSION,
            scope,
            "persist conversation write permission",
        );
        grant_exact_permission(
            store,
            subject,
            CONVERSATION_READ_PERMISSION,
            scope,
            "persist conversation read permission",
        );
        store
            .set_service_quota_policy(quota)
            .expect("persist quota");
    }

    fn seed_identity_read_fixture(
        store: &SqliteLocalStore,
        subject: &ScopedPrincipal,
        credential: &ucr_model::ServiceCredentialRecord,
        identity: &IdentityRecord,
        binding: &ExternalIdentityBinding,
    ) {
        store
            .provision_service_credential(credential)
            .expect("persist credential");
        grant_exact_permission(
            store,
            subject,
            IDENTITY_READ_PERMISSION,
            &subject.scope,
            "persist identity read permission",
        );
        grant_exact_permission(
            store,
            subject,
            EXTERNAL_IDENTITY_BINDING_READ_PERMISSION,
            &subject.scope,
            "persist binding read permission",
        );
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: subject.clone(),
                max_requests: 4,
                window_ms: 60_000,
            })
            .expect("persist quota");
        store.persist_identity(identity).expect("persist identity");
        store
            .persist_external_identity_binding(binding)
            .expect("persist binding");
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
            assert_eq!(accepted.schema_version, ProtocolVersion::new(1, 0));
            assert!(accepted.extensions.is_empty());
        }

        let retry = command("command-b", "retry-a", b"payload", Some("namespace-a"));
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let duplicate = reopened.accept_command(&retry).expect("deduplicate retry");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(first.command_id));
        assert_eq!(duplicate.schema_version, ProtocolVersion::new(1, 0));
        assert!(duplicate.extensions.is_empty());
    }

    #[test]
    fn utf8_opaque_ids_survive_restart_without_normalization() {
        let db = TestDbPath::new();
        let mut composed = command(
            "команда-é",
            "retry-unicode",
            b"payload",
            Some("пространство-é"),
        );
        composed.scope.tenant_id = TenantId::from_opaque(opaque("арендатор-é"));
        composed.correlation.correlation_id = opaque("корреляция-é");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store
                    .accept_command(&composed)
                    .expect("accept unicode command")
                    .status,
                CommandReceiptStatus::Accepted
            );
        }
        let retry = {
            let mut value = command(
                "команда-повтор-é",
                "retry-unicode",
                b"payload",
                Some("пространство-é"),
            );
            value.scope.tenant_id = TenantId::from_opaque(opaque("арендатор-é"));
            value.correlation.correlation_id = opaque("другая-корреляция-é");
            value
        };
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen unicode store");
        let duplicate = reopened
            .accept_command(&retry)
            .expect("deduplicate unicode retry");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(
            duplicate.original_command_id,
            Some(composed.command_id.clone())
        );
        assert_eq!(
            duplicate
                .original_command_id
                .expect("original")
                .as_opaque()
                .as_wire_bytes(),
            "команда-é".as_bytes()
        );

        let mut decomposed_scope = command("command-decomposed", "retry-unicode", b"payload", None);
        let decomposed_tenant = format!("арендатор-e{}", '\u{301}');
        decomposed_scope.scope.tenant_id = TenantId::from_opaque(opaque(&decomposed_tenant));
        assert_eq!(
            reopened
                .accept_command(&decomposed_scope)
                .expect("distinct decomposed tenant")
                .status,
            CommandReceiptStatus::Accepted
        );
    }

    #[test]
    fn command_protocol_semantics_survive_restart_and_extension_order_is_canonical() {
        let db = TestDbPath::new();
        let mut first = command(
            "command-ext-a",
            "retry-ext",
            b"payload",
            Some("namespace-a"),
        );
        first.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: true,
                payload: b"a".to_vec(),
            },
        ];
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.accept_command(&first).expect("accept").status,
                CommandReceiptStatus::Accepted
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let mut reordered = command(
            "command-ext-b",
            "retry-ext",
            b"payload",
            Some("namespace-a"),
        );
        reordered.extensions = first.extensions.clone();
        reordered.extensions.reverse();
        assert_eq!(
            reopened
                .accept_command(&reordered)
                .expect("deduplicate")
                .status,
            CommandReceiptStatus::Duplicate
        );

        let mut changed_extension = reordered.clone();
        changed_extension.command_id = CommandId::from_opaque(opaque("command-ext-c"));
        changed_extension.extensions[0].payload.push(b'!');
        assert_eq!(
            reopened.accept_command(&changed_extension),
            Err(DurableStoreError::Conflict)
        );

        let mut changed_schema = reordered;
        changed_schema.command_id = CommandId::from_opaque(opaque("command-ext-d"));
        changed_schema.schema_version = ProtocolVersion::new(1, 1);
        assert_eq!(
            reopened.accept_command(&changed_schema),
            Err(DurableStoreError::Conflict)
        );
        drop(reopened);

        let connection = rusqlite::Connection::open(db.path()).expect("inspect command extensions");
        let names: Vec<String> = {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM command_extensions
                     WHERE command_id='command-ext-a' ORDER BY position",
                )
                .expect("prepare");
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("rows")
        };
        assert_eq!(names, vec!["ucr.example.a", "vendor.example.z"]);
    }

    #[test]
    fn v8_to_v9_migration_backfills_legacy_command_protocol_semantics() {
        let db = TestDbPath::new();
        let legacy = command(
            "command-pre-v9",
            "retry-pre-v9",
            b"legacy",
            Some("namespace-a"),
        );
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current store");
            store
                .accept_command(&legacy)
                .expect("accept legacy command");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     DROP TABLE identities; DROP TABLE external_identity_bindings; DROP TABLE service_audit_operations; DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices; DROP TRIGGER service_audit_no_update; DROP TRIGGER service_audit_no_delete; DROP INDEX service_audit_scope_sequence; DROP TABLE service_audit_records; DROP TABLE service_quota_usage; DROP TABLE service_quota_policies; DROP TABLE service_credentials; DROP TABLE permission_grants; DROP TABLE trusted_signing_keys;
                     DROP TABLE message_extensions;
                     DROP TABLE command_extensions;
                     DROP TABLE command_protocol_metadata;
                     PRAGMA user_version=8;",
                )
                .expect("simulate exact v8 command shape");
        }

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v8 to v9");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let retry = command(
            "command-pre-v9-retry",
            "retry-pre-v9",
            b"legacy",
            Some("namespace-a"),
        );
        assert_eq!(
            migrated
                .accept_command(&retry)
                .expect("legacy duplicate")
                .status,
            CommandReceiptStatus::Duplicate
        );
        let mut changed_schema = retry;
        changed_schema.command_id = CommandId::from_opaque(opaque("command-pre-v9-changed"));
        changed_schema.schema_version = ProtocolVersion::new(1, 1);
        assert_eq!(
            migrated.accept_command(&changed_schema),
            Err(DurableStoreError::Conflict)
        );
        drop(migrated);

        let connection = rusqlite::Connection::open(db.path()).expect("inspect migrated metadata");
        let version: (i64, i64) = connection
            .query_row(
                "SELECT schema_major, schema_minor FROM command_protocol_metadata
                 WHERE command_id='command-pre-v9'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("backfilled version");
        assert_eq!(version, (1, 0));
        let extensions: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM command_extensions WHERE command_id='command-pre-v9'",
                [],
                |row| row.get(0),
            )
            .expect("extension count");
        assert_eq!(extensions, 0);
    }

    #[test]
    fn missing_command_protocol_metadata_is_rejected_on_reopen() {
        let db = TestDbPath::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .accept_command(&command(
                    "command-corrupt-protocol",
                    "retry-corrupt-protocol",
                    b"payload",
                    Some("namespace-a"),
                ))
                .expect("accept command");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     DELETE FROM command_protocol_metadata
                     WHERE command_id='command-corrupt-protocol';",
                )
                .expect("remove protocol metadata");
        }
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
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
    fn oversized_persisted_command_extension_set_is_rejected_on_reopen() {
        let db = TestDbPath::new();
        let value = command(
            "command-extension-budget",
            "retry-extension-budget",
            b"payload",
            Some("namespace-a"),
        );
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.accept_command(&value).expect("accept command");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            for position in 0..=MAX_PROTOCOL_EXTENSIONS {
                connection
                    .execute(
                        "INSERT INTO command_extensions (
                            tenant_id, namespace_present, namespace_id, command_id,
                            position, name, critical, payload
                         ) VALUES (?1,1,?2,?3,?4,?5,0,?6)",
                        rusqlite::params![
                            "tenant-a",
                            "namespace-a",
                            value.command_id.as_opaque().as_str(),
                            i64::try_from(position).expect("position"),
                            format!("vendor.example.command-{position}"),
                            Vec::<u8>::new(),
                        ],
                    )
                    .expect("insert corrupt command extension");
            }
        }
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
    }

    #[test]
    fn oversized_persisted_event_extension_set_is_rejected_on_reopen() {
        let db = TestDbPath::new();
        let value = event("event-extension-budget", "command-a", b"payload");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.append_event(&value).expect("append event");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            for position in 0..=MAX_PROTOCOL_EXTENSIONS {
                connection
                    .execute(
                        "INSERT INTO event_extensions (
                            tenant_id, namespace_present, namespace_id, event_id,
                            position, name, critical, payload
                         ) VALUES (?1,1,?2,?3,?4,?5,0,?6)",
                        rusqlite::params![
                            "tenant-a",
                            "namespace-a",
                            value.event_id.as_opaque().as_str(),
                            i64::try_from(position).expect("position"),
                            format!("vendor.example.event-{position}"),
                            Vec::<u8>::new(),
                        ],
                    )
                    .expect("insert corrupt event extension");
            }
        }
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
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
    fn sqlite_storage_full_rolls_back_command_acceptance_atomically() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open capacity-limited store");
        {
            let connection = store.connection.lock().expect("lock capacity connection");
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .expect("checkpoint before capacity limit");
            let page_count: i64 = connection
                .pragma_query_value(None, "page_count", |row| row.get(0))
                .expect("read current page count");
            connection
                .pragma_update(None, "max_page_count", page_count)
                .expect("set exact page ceiling");
            let max_page_count: i64 = connection
                .pragma_query_value(None, "max_page_count", |row| row.get(0))
                .expect("read page ceiling");
            assert_eq!(max_page_count, page_count);
        }

        let large_payload = vec![0xA5; DEFAULT_MAX_PAYLOAD_LEN as usize];
        let full_attempt = command(
            "storage-full-large",
            "storage-full-key",
            &large_payload,
            Some("namespace-a"),
        );
        assert_eq!(
            store.accept_command(&full_attempt),
            Err(DurableStoreError::Full)
        );

        drop(store);
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen after capacity failure");
        assert_eq!(reopened.health(), Ok(StorageHealth::Healthy));
        let recovery = command(
            "storage-full-recovery",
            "storage-full-key",
            b"after-full",
            Some("namespace-a"),
        );
        let accepted = reopened
            .accept_command(&recovery)
            .expect("accept after capacity returns");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        let retry = command(
            "storage-full-retry",
            "storage-full-key",
            b"after-full",
            Some("namespace-a"),
        );
        let duplicate = reopened
            .accept_command(&retry)
            .expect("deduplicate recovery");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(recovery.command_id));
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
    #[test]
    fn process_kill_child_runs_real_accept_command() {
        if std::env::var_os("UCR_TEST_PROCESS_KILL_CHILD").is_none() {
            return;
        }
        let db_path = PathBuf::from(
            std::env::var_os("UCR_TEST_PROCESS_KILL_DB_PATH")
                .expect("process-kill child database path"),
        );
        let store = SqliteLocalStore::open(db_path).expect("open process-kill child store");
        let interrupted = command(
            "process-kill-original",
            "process-kill-key",
            b"before-kill",
            Some("namespace-a"),
        );
        let outcome = store.accept_command(&interrupted);
        panic!("process-kill hook returned unexpectedly: {outcome:?}");
    }

    #[test]
    fn mid_operation_process_kill_rolls_back_command_acceptance_atomically() {
        let db = TestDbPath::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize process-kill store"));
        let ready_path = PathBuf::from(format!("{}.kill-ready", db.path().display()));
        let _ = fs::remove_file(&ready_path);

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--exact")
            .arg("tests::process_kill_child_runs_real_accept_command")
            .arg("--nocapture")
            .env("UCR_TEST_PROCESS_KILL_CHILD", "1")
            .env("UCR_TEST_PROCESS_KILL_DB_PATH", db.path())
            .env("UCR_TEST_PROCESS_KILL_COMMAND_ID", "process-kill-original")
            .env("UCR_TEST_PROCESS_KILL_READY_PATH", &ready_path)
            .spawn()
            .expect("spawn process-kill child");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_path.exists() {
            if let Some(status) = child.try_wait().expect("poll process-kill child") {
                panic!("process-kill child exited before commit boundary: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "process-kill child never reached pre-commit boundary"
            );
            thread::sleep(Duration::from_millis(10));
        }

        child.kill().expect("kill child at pre-commit boundary");
        let status = child.wait().expect("wait for killed child");
        assert!(!status.success());
        let _ = fs::remove_file(&ready_path);

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen after process kill");
        assert_eq!(reopened.health(), Ok(StorageHealth::Healthy));
        let recovery = command(
            "process-kill-recovery",
            "process-kill-key",
            b"after-kill",
            Some("namespace-a"),
        );
        let accepted = reopened
            .accept_command(&recovery)
            .expect("accept same idempotency key after killed transaction");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        let retry = command(
            "process-kill-retry",
            "process-kill-key",
            b"after-kill",
            Some("namespace-a"),
        );
        let duplicate = reopened
            .accept_command(&retry)
            .expect("deduplicate post-kill recovery");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(recovery.command_id));
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

    #[test]
    fn integration_command_ingress_deduplicates_after_sqlite_restart() {
        let db = TestDbPath::new();
        let scope = command(
            "integration-scope",
            "integration-scope-key",
            b"",
            Some("namespace-integration"),
        )
        .scope;
        let subject = ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("service-integration-sqlite")),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: COMMAND_ACCEPT_PERMISSION.to_owned(),
            scope: PermissionScope::Exact(scope.clone()),
        };
        let quota = ServiceQuotaPolicy {
            subject: subject.clone(),
            max_requests: 4,
            window_ms: 60_000,
        };
        let value = CommandEnvelope {
            scope: scope.clone(),
            ..command(
                "integration-command-sqlite",
                "integration-command-key",
                b"persist me",
                Some("namespace-integration"),
            )
        };

        {
            let store = SqliteLocalStore::open(db.path()).expect("open integration store");
            store
                .provision_service_credential(&credential)
                .expect("persist credential");
            store.grant_permission(&grant).expect("persist permission");
            store
                .set_service_quota_policy(&quota)
                .expect("persist quota");
            let ingress = IntegrationCommandIngress::new(&SystemServiceQuotaClock, &store, &store);
            assert_eq!(
                ingress
                    .submit_command(&scope, &credential.credential_id, &secret, &value)
                    .expect("first command")
                    .status,
                CommandReceiptStatus::Accepted
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen integration store");
        let ingress =
            IntegrationCommandIngress::new(&SystemServiceQuotaClock, &reopened, &reopened);
        assert_eq!(
            ingress
                .submit_command(&scope, &credential.credential_id, &secret, &value)
                .expect("retry after restart")
                .status,
            CommandReceiptStatus::Duplicate
        );
        let audit = reopened
            .service_audit_records(&scope, 4)
            .expect("read restart-safe admission audit");
        assert_eq!(audit.len(), 2);
        assert!(
            audit
                .iter()
                .all(|record| record.outcome == ServiceAuditOutcome::Authorized)
        );
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_COMMAND_OPERATION_KIND.to_owned(),
            operation_id: value.command_id.as_opaque().clone(),
        };
        assert!(
            audit
                .iter()
                .all(|record| record.operation.as_ref() == Some(&operation))
        );
        assert_eq!(
            reopened
                .service_audit_records_for_operation(&scope, &operation, 4)
                .expect("exact command audit after restart")
                .len(),
            2
        );
    }

    #[test]
    fn integration_identity_read_side_survives_sqlite_restart_through_canonical_owners() {
        let db = TestDbPath::new();
        let scope = command(
            "identity-read-scope",
            "identity-read-scope-key",
            b"",
            Some("namespace-identity-read"),
        )
        .scope;
        let subject = service_subject(&scope, "service-identity-read-sqlite");
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        let identity = IdentityRecord {
            scope: scope.clone(),
            identity_id: IdentityId::from_opaque(opaque("identity-read-target")),
            ownership: IdentityOwnership::UserManaged,
            evidence: IdentityEvidence::SelfAsserted,
            expires_at_unix_ms: None,
        };
        let binding = ExternalIdentityBinding {
            scope: scope.clone(),
            integration_id: IntegrationId::from_opaque(opaque("integration-read-api")),
            external_namespace: "vendor.example.account".to_owned(),
            external_entity_id: b"Sensitive-External-42".to_vec(),
            identity_id: identity.identity_id.clone(),
        };

        {
            let store = SqliteLocalStore::open(db.path()).expect("open read-side fixture");
            seed_identity_read_fixture(&store, &subject, &credential, &identity, &binding);
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen read-side fixture");
        let ingress = IntegrationIngress::new(&SystemServiceQuotaClock, &reopened, &reopened);
        assert_eq!(
            ingress
                .get_identity(
                    &scope,
                    &credential.credential_id,
                    &secret,
                    &scope,
                    &identity.identity_id,
                )
                .expect("public identity read after restart"),
            identity
        );
        assert_eq!(
            ingress
                .resolve_identity_binding(
                    &scope,
                    &credential.credential_id,
                    &secret,
                    ExternalIdentityBindingLookup::new(
                        &scope,
                        &binding.integration_id,
                        &binding.external_namespace,
                        &binding.external_entity_id,
                    ),
                )
                .expect("public binding resolution after restart"),
            binding
        );

        let identity_operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_IDENTITY_READ_OPERATION_KIND.to_owned(),
            operation_id: identity.identity_id.as_opaque().clone(),
        };
        let binding_operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_EXTERNAL_IDENTITY_READ_OPERATION_KIND.to_owned(),
            operation_id: binding.integration_id.as_opaque().clone(),
        };
        assert_single_operation_audit(
            &reopened,
            &scope,
            &identity_operation,
            "identity read audit after restart",
        );
        assert_single_operation_audit(
            &reopened,
            &scope,
            &binding_operation,
            "binding read audit after restart",
        );
    }

    #[test]
    fn integration_conversation_api_survives_sqlite_restart_through_canonical_owner() {
        let db = TestDbPath::new();
        let scope = command(
            "conversation-api-scope",
            "conversation-api-scope-key",
            b"",
            Some("namespace-conversation-api"),
        )
        .scope;
        let subject = service_subject(&scope, "service-conversation-api-sqlite");
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        let conversation = ConversationRecord {
            scope: scope.clone(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(opaque("conversation-api-root")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        };
        let quota = ServiceQuotaPolicy {
            subject: subject.clone(),
            max_requests: 4,
            window_ms: 60_000,
        };

        {
            let store = SqliteLocalStore::open(db.path()).expect("open conversation API store");
            seed_conversation_api_fixture(&store, &subject, &credential, &scope, &quota);
            let ingress = IntegrationIngress::new(&SystemServiceQuotaClock, &store, &store);
            assert_eq!(
                ingress
                    .create_conversation(&scope, &credential.credential_id, &secret, &conversation,)
                    .expect("first public conversation create"),
                conversation
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen conversation API store");
        let ingress = IntegrationIngress::new(&SystemServiceQuotaClock, &reopened, &reopened);
        assert_eq!(
            ingress
                .get_conversation(
                    &scope,
                    &credential.credential_id,
                    &secret,
                    &scope,
                    &conversation.conversation.conversation_id,
                )
                .expect("public conversation read after restart"),
            conversation
        );
        assert_eq!(
            ingress
                .create_conversation(&scope, &credential.credential_id, &secret, &conversation,)
                .expect("idempotent public conversation create after restart"),
            conversation
        );
        assert_eq!(
            reopened
                .conversation(&scope, &conversation.conversation.conversation_id)
                .expect("canonical conversation lookup after restart"),
            Some(conversation.clone())
        );

        let create_operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_CONVERSATION_CREATE_OPERATION_KIND.to_owned(),
            operation_id: conversation
                .conversation
                .conversation_id
                .as_opaque()
                .clone(),
        };
        let read_operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_CONVERSATION_READ_OPERATION_KIND.to_owned(),
            operation_id: conversation
                .conversation
                .conversation_id
                .as_opaque()
                .clone(),
        };
        assert_eq!(
            reopened
                .service_audit_records_for_operation(&scope, &create_operation, 4)
                .expect("restart-safe conversation create audit")
                .len(),
            2
        );
        assert_single_operation_audit(
            &reopened,
            &scope,
            &read_operation,
            "conversation read audit after restart",
        );
    }

    #[test]
    fn integration_link_identity_ingress_survives_sqlite_restart_without_parallel_owner() {
        let db = TestDbPath::new();
        let scope = command(
            "identity-api-scope",
            "identity-api-scope-key",
            b"",
            Some("namespace-identity-api"),
        )
        .scope;
        let subject = service_subject(&scope, "service-identity-api-sqlite");
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        let identity_create_grant = exact_grant(&subject, IDENTITY_CREATE_PERMISSION, &scope);
        let binding_grant =
            exact_grant(&subject, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION, &scope);
        let quota = ServiceQuotaPolicy {
            subject: subject.clone(),
            max_requests: 4,
            window_ms: 60_000,
        };
        let identity = IdentityRecord {
            scope: scope.clone(),
            identity_id: IdentityId::from_opaque(opaque("identity-api-target")),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::Unverified,
            expires_at_unix_ms: None,
        };
        let binding = ExternalIdentityBinding {
            scope: scope.clone(),
            integration_id: IntegrationId::from_opaque(opaque("integration-identity-api")),
            external_namespace: "vendor.example.account".to_owned(),
            external_entity_id: b"Opaque-External-Account-77".to_vec(),
            identity_id: identity.identity_id.clone(),
        };

        {
            let store = SqliteLocalStore::open(db.path()).expect("open identity API store");
            store
                .provision_service_credential(&credential)
                .expect("persist credential");
            store
                .grant_permission(&identity_create_grant)
                .expect("persist identity create permission");
            store
                .grant_permission(&binding_grant)
                .expect("persist binding link permission");
            store
                .set_service_quota_policy(&quota)
                .expect("persist quota");
            let ingress = IntegrationIngress::new(&SystemServiceQuotaClock, &store, &store);
            assert_eq!(
                ingress
                    .create_identity(&scope, &credential.credential_id, &secret, &identity)
                    .expect("first public root identity create"),
                identity
            );
            assert_eq!(
                ingress
                    .link_identity(&scope, &credential.credential_id, &secret, &binding)
                    .expect("first public identity link"),
                binding
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen identity API store");
        let ingress = IntegrationIngress::new(&SystemServiceQuotaClock, &reopened, &reopened);
        assert_eq!(
            reopened.identity(&scope, &identity.identity_id),
            Ok(Some(identity.clone()))
        );
        assert_eq!(
            ingress
                .link_identity(&scope, &credential.credential_id, &secret, &binding)
                .expect("idempotent public identity link after restart"),
            binding
        );
        assert_eq!(
            reopened
                .external_identity_binding(
                    &binding.scope,
                    &binding.integration_id,
                    &binding.external_namespace,
                    &binding.external_entity_id,
                )
                .expect("restart-safe binding lookup"),
            Some(binding.clone())
        );
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND.to_owned(),
            operation_id: binding.identity_id.as_opaque().clone(),
        };
        let audit = reopened
            .service_audit_records_for_operation(&scope, &operation, 4)
            .expect("restart-safe identity-link audit");
        assert_eq!(audit.len(), 2);
        assert!(
            audit
                .iter()
                .all(|record| record.outcome == ServiceAuditOutcome::Authorized)
        );
    }
}
