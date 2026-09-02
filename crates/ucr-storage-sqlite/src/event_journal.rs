use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::{CommandOutcomeStore, DurableStoreError, EventAppendStatus, EventJournalStore};
use ucr_model::{
    ActorId, ActorKind, ActorRef, CommandId, CorrelationContext, DeviceId, DeviceRef,
    EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, PrincipalId, ProtocolExtension,
    ProtocolVersion, TenantId, TenantScope,
};
use ucr_protocol::{EventError, canonical_event};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

pub(super) const V8_OBJECTS_SQL: &str = "
CREATE TABLE event_extensions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0),
    name TEXT NOT NULL,
    critical INTEGER NOT NULL CHECK(critical IN (0, 1)),
    payload BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, event_id, name),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES events(tenant_id, namespace_present, namespace_id, event_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v8_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V8_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v8(connection: &Connection) -> Result<(), DurableStoreError> {
    super::sync_store::verify_schema_v7(connection)?;
    verify_table_columns(
        connection,
        "event_extensions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("event_id", "TEXT", 1, 4),
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
    verify_event_rows(connection)
}

fn verify_event_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, event_id FROM events")
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
    for (tenant, present, namespace, event_id) in keys {
        let scope = parse_scope(&tenant, present, &namespace)?;
        let event_id = EventId::from_opaque(parse_id(&event_id)?);
        if load_event_by_id(connection, &scope, &event_id)?.is_none() {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Person => "person",
        ActorKind::AiAgent => "ai_agent",
        ActorKind::Bot => "bot",
        ActorKind::Organization => "organization",
        ActorKind::System => "system",
    }
}

fn parse_actor_kind(value: &str) -> Result<ActorKind, DurableStoreError> {
    match value {
        "person" => Ok(ActorKind::Person),
        "ai_agent" => Ok(ActorKind::AiAgent),
        "bot" => Ok(ActorKind::Bot),
        "organization" => Ok(ActorKind::Organization),
        "system" => Ok(ActorKind::System),
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

fn decode_u64(value: Vec<u8>) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_u32(value: i64) -> Result<u32, DurableStoreError> {
    u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn map_event_error(_error: EventError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

fn load_extensions(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &EventId,
) -> Result<Vec<ProtocolExtension>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT position, name, critical, payload FROM event_extensions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4
             ORDER BY position",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id.as_opaque().as_str()
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
    Ok(extensions)
}

pub(super) fn load_event_by_id(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &EventId,
) -> Result<Option<EventEnvelope>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT event_type, payload, actor_id, actor_kind, on_behalf_of,
             source_device_id, source_identity_id, wall_time_unix_ms, logical_order,
             correlation_id, causation_id, idempotency_key, schema_major, schema_minor,
             integrity_metadata FROM events WHERE tenant_id=?1 AND namespace_present=?2
             AND namespace_id=?3 AND event_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((
        event_type,
        payload,
        actor_id,
        actor_kind,
        on_behalf_of,
        source_device_id,
        source_identity_id,
        wall_time_unix_ms,
        logical_order,
        correlation_id,
        causation_id,
        idempotency_key,
        schema_major,
        schema_minor,
        integrity_metadata,
    )) = row
    else {
        return Ok(None);
    };
    let extensions = load_extensions(connection, scope, event_id)?;
    let event = EventEnvelope {
        event_id: event_id.clone(),
        scope: scope.clone(),
        event_type,
        payload,
        actor: ActorRef {
            actor_id: ActorId::from_opaque(parse_id(&actor_id)?),
            kind: parse_actor_kind(&actor_kind)?,
            on_behalf_of: on_behalf_of
                .map(|value| parse_id(&value).map(PrincipalId::from_opaque))
                .transpose()?,
        },
        source_device: DeviceRef {
            device_id: DeviceId::from_opaque(parse_id(&source_device_id)?),
            identity_id: IdentityId::from_opaque(parse_id(&source_identity_id)?),
        },
        wall_time_unix_ms,
        logical_order: decode_u64(logical_order)?,
        correlation: CorrelationContext {
            correlation_id: parse_id(&correlation_id)?,
            causation_id: causation_id.map(|value| parse_id(&value)).transpose()?,
            idempotency_key,
        },
        schema_version: ProtocolVersion::new(decode_u32(schema_major)?, decode_u32(schema_minor)?),
        integrity_metadata,
        extensions,
    };
    let canonical = canonical_event(&event).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical != event {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(Some(event))
}

fn insert_extensions(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&event.scope);
    for (position, extension) in event.extensions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO event_extensions (
                    tenant_id, namespace_present, namespace_id, event_id, position, name, critical, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    event.event_id.as_opaque().as_str(),
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

pub(super) fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<EventAppendStatus, DurableStoreError> {
    let event = canonical_event(event).map_err(map_event_error)?;
    if let Some(existing) = load_event_by_id(transaction, &event.scope, &event.event_id)? {
        return if existing == event {
            Ok(EventAppendStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    let namespace = namespace_storage_key(&event.scope);
    transaction
        .execute(
            "INSERT INTO events (
                tenant_id, namespace_present, namespace_id, event_id, event_type, payload,
                actor_id, actor_kind, on_behalf_of, source_device_id, source_identity_id,
                wall_time_unix_ms, logical_order, correlation_id, causation_id, idempotency_key,
                schema_major, schema_minor, integrity_metadata
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                       ?16, ?17, ?18, ?19)",
            params![
                event.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event.event_id.as_opaque().as_str(),
                event.event_type,
                event.payload,
                event.actor.actor_id.as_opaque().as_str(),
                actor_kind_name(event.actor.kind),
                event
                    .actor
                    .on_behalf_of
                    .as_ref()
                    .map(|value| value.as_opaque().as_str()),
                event.source_device.device_id.as_opaque().as_str(),
                event.source_device.identity_id.as_opaque().as_str(),
                event.wall_time_unix_ms,
                event.logical_order.to_be_bytes().as_slice(),
                event.correlation.correlation_id.as_str(),
                event
                    .correlation
                    .causation_id
                    .as_ref()
                    .map(OpaqueId::as_str),
                event.correlation.idempotency_key,
                i64::from(event.schema_version.major),
                i64::from(event.schema_version.minor),
                event.integrity_metadata,
            ],
        )
        .map_err(|error| match &error {
            rusqlite::Error::SqliteFailure(details, _)
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                DurableStoreError::Conflict
            }
            _ => map_sqlite_error(&error),
        })?;
    insert_extensions(transaction, &event)?;
    Ok(EventAppendStatus::Appended)
}

impl EventJournalStore for SqliteLocalStore {
    fn append_event(&self, event: &EventEnvelope) -> Result<EventAppendStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let status = append_event_in_transaction(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }
}

impl CommandOutcomeStore for SqliteLocalStore {
    fn record_terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError> {
        let event = canonical_event(event).map_err(map_event_error)?;
        if &event.scope != scope
            || event.correlation.causation_id.as_ref() != Some(command_id.as_opaque())
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let accepted: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accepted_commands
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND command_id=?4)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    command_id.as_opaque().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if !accepted {
            return Err(DurableStoreError::InvalidRecord);
        }
        let existing_terminal: Option<String> = transaction
            .query_row(
                "SELECT terminal_event_id FROM command_terminal_events
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND command_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    command_id.as_opaque().as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing_terminal) = existing_terminal {
            if existing_terminal != event.event_id.as_opaque().as_str() {
                return Err(DurableStoreError::Conflict);
            }
            return match load_event_by_id(&transaction, scope, &event.event_id)? {
                Some(existing) if existing == event => Ok(EventAppendStatus::Duplicate),
                _ => Err(DurableStoreError::Corrupt),
            };
        }
        let _ = append_event_in_transaction(&transaction, &event)?;
        transaction
            .execute(
                "INSERT INTO command_terminal_events (
                    tenant_id, namespace_present, namespace_id, command_id, terminal_event_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    command_id.as_opaque().as_str(),
                    event.event_id.as_opaque().as_str()
                ],
            )
            .map_err(|error| match &error {
                rusqlite::Error::SqliteFailure(details, _)
                    if details.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    DurableStoreError::Conflict
                }
                _ => map_sqlite_error(&error),
            })?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(EventAppendStatus::Appended)
    }

    fn terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
    ) -> Result<Option<EventId>, DurableStoreError> {
        let namespace = namespace_storage_key(scope);
        let connection = self.lock_connection()?;
        let event_id = connection
            .query_row(
                "SELECT terminal_event_id FROM command_terminal_events
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND command_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    command_id.as_opaque().as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        event_id
            .map(|value| {
                OpaqueId::new(value)
                    .map(EventId::from_opaque)
                    .map_err(|_| DurableStoreError::Corrupt)
            })
            .transpose()
    }
}
