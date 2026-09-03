use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::DurableStoreError;
use ucr_model::{
    CommandEnvelope, CommandId, OpaqueId, ProtocolExtension, ProtocolVersion, TenantId, TenantScope,
};
use ucr_protocol::{MAX_PROTOCOL_EXTENSIONS, canonical_protocol_extensions};

use super::{
    map_schema_change_error, map_sqlite_error, namespace_storage_key, verify_table_columns,
};

const V9_OBJECTS_SQL: &str = "
CREATE TABLE command_protocol_metadata (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    schema_major INTEGER NOT NULL CHECK(schema_major > 0),
    schema_minor INTEGER NOT NULL CHECK(schema_minor >= 0),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, command_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, command_id)
        REFERENCES accepted_commands(tenant_id, namespace_present, namespace_id, command_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE command_extensions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0),
    name TEXT NOT NULL,
    critical INTEGER NOT NULL CHECK(critical IN (0, 1)),
    payload BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, command_id, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, command_id, name),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, command_id)
        REFERENCES command_protocol_metadata(tenant_id, namespace_present, namespace_id, command_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCommandProtocol {
    pub schema_version: ProtocolVersion,
    pub extensions: Vec<ProtocolExtension>,
}

pub(super) fn create_v9_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V9_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn backfill_legacy_v8_commands(
    transaction: &Transaction<'_>,
) -> Result<(), DurableStoreError> {
    transaction
        .execute(
            "INSERT INTO command_protocol_metadata (
                tenant_id, namespace_present, namespace_id, command_id, schema_major, schema_minor
             )
             SELECT tenant_id, namespace_present, namespace_id, command_id, 1, 0
             FROM accepted_commands",
            [],
        )
        .map_err(|error| map_schema_change_error(&error))?;
    Ok(())
}

pub(super) fn insert_protocol_metadata(
    transaction: &Transaction<'_>,
    command: &CommandEnvelope,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&command.scope);
    transaction
        .execute(
            "INSERT INTO command_protocol_metadata (
                tenant_id, namespace_present, namespace_id, command_id, schema_major, schema_minor
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                command.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                command.command_id.as_opaque().as_str(),
                i64::from(command.schema_version.major),
                i64::from(command.schema_version.minor),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    for (position, extension) in command.extensions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO command_extensions (
                    tenant_id, namespace_present, namespace_id, command_id,
                    position, name, critical, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    command.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    command.command_id.as_opaque().as_str(),
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

pub(super) fn load_protocol_metadata(
    connection: &Connection,
    scope: &TenantScope,
    command_id: &CommandId,
) -> Result<Option<StoredCommandProtocol>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let version = connection
        .query_row(
            "SELECT schema_major, schema_minor FROM command_protocol_metadata
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND command_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                command_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((schema_major, schema_minor)) = version else {
        return Ok(None);
    };
    let schema_version = ProtocolVersion::new(decode_u32(schema_major)?, decode_u32(schema_minor)?);
    if schema_version.major == 0 {
        return Err(DurableStoreError::Corrupt);
    }

    let mut statement = connection
        .prepare(
            "SELECT position, name, critical, payload FROM command_extensions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND command_id=?4
             ORDER BY position",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                command_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut extensions = Vec::new();
    for (expected_position, row) in rows.enumerate() {
        if expected_position >= MAX_PROTOCOL_EXTENSIONS {
            return Err(DurableStoreError::Corrupt);
        }
        let (position, name, critical, payload) = row.map_err(|error| map_sqlite_error(&error))?;
        if position != i64::try_from(expected_position).map_err(|_| DurableStoreError::Corrupt)? {
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
    let canonical =
        canonical_protocol_extensions(&extensions).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical != extensions {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(Some(StoredCommandProtocol {
        schema_version,
        extensions,
    }))
}

pub(super) fn verify_schema_v9(connection: &Connection) -> Result<(), DurableStoreError> {
    super::event_journal::verify_schema_v8(connection)?;
    verify_table_columns(
        connection,
        "command_protocol_metadata",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("command_id", "TEXT", 1, 4),
            ("schema_major", "INTEGER", 1, 0),
            ("schema_minor", "INTEGER", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "command_extensions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("command_id", "TEXT", 1, 4),
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
    verify_command_protocol_rows(connection)
}

fn verify_command_protocol_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, command_id FROM accepted_commands",
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
    for (tenant, present, namespace, command_id) in keys {
        let scope = parse_scope(&tenant, present, &namespace)?;
        let command_id = CommandId::from_opaque(parse_id(&command_id)?);
        if load_protocol_metadata(connection, &scope, &command_id)?.is_none() {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

fn parse_scope(
    tenant: &str,
    present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match (present, namespace.is_empty()) {
        (0, true) => None,
        (1, false) => Some(ucr_model::NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_u32(value: i64) -> Result<u32, DurableStoreError> {
    u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}
