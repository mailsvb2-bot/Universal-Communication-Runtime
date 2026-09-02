use rusqlite::{OptionalExtension, Transaction, params};
use ucr_core::{CommandOutcomeStore, DurableStoreError, EventAppendStatus, EventJournalStore};
use ucr_model::{ActorKind, CommandId, EventEnvelope, EventId, OpaqueId, TenantScope};
use ucr_protocol::{EventError, validate_event};

use super::{SqliteLocalStore, map_sqlite_error, namespace_storage_key};

#[derive(Debug, PartialEq, Eq)]
struct StoredEvent {
    event_type: String,
    payload: Vec<u8>,
    actor_id: String,
    actor_kind: String,
    on_behalf_of: Option<String>,
    source_device_id: String,
    source_identity_id: String,
    wall_time_unix_ms: i64,
    logical_order: Vec<u8>,
    correlation_id: String,
    causation_id: Option<String>,
    idempotency_key: Option<String>,
    schema_major: i64,
    schema_minor: i64,
    integrity_metadata: Vec<u8>,
}
impl StoredEvent {
    fn from_event(event: &EventEnvelope) -> Self {
        Self {
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            actor_id: event.actor.actor_id.as_opaque().as_str().to_owned(),
            actor_kind: actor_kind_name(event.actor.kind).to_owned(),
            on_behalf_of: event
                .actor
                .on_behalf_of
                .as_ref()
                .map(|value| value.as_opaque().as_str().to_owned()),
            source_device_id: event
                .source_device
                .device_id
                .as_opaque()
                .as_str()
                .to_owned(),
            source_identity_id: event
                .source_device
                .identity_id
                .as_opaque()
                .as_str()
                .to_owned(),
            wall_time_unix_ms: event.wall_time_unix_ms,
            logical_order: event.logical_order.to_be_bytes().to_vec(),
            correlation_id: event.correlation.correlation_id.as_str().to_owned(),
            causation_id: event
                .correlation
                .causation_id
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            idempotency_key: event.correlation.idempotency_key.clone(),
            schema_major: i64::from(event.schema_version.major),
            schema_minor: i64::from(event.schema_version.minor),
            integrity_metadata: event.integrity_metadata.clone(),
        }
    }
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

fn map_event_error(_error: EventError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}
fn load_event(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<Option<StoredEvent>, DurableStoreError> {
    let namespace = namespace_storage_key(&event.scope);
    transaction
        .query_row(
            "SELECT event_type, payload, actor_id, actor_kind, on_behalf_of, \
             source_device_id, source_identity_id, wall_time_unix_ms, logical_order, \
             correlation_id, causation_id, idempotency_key, schema_major, schema_minor, \
             integrity_metadata FROM events WHERE tenant_id = ?1 AND namespace_present = ?2 \
             AND namespace_id = ?3 AND event_id = ?4",
            params![
                event.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event.event_id.as_opaque().as_str()
            ],
            |row| {
                Ok(StoredEvent {
                    event_type: row.get(0)?,
                    payload: row.get(1)?,
                    actor_id: row.get(2)?,
                    actor_kind: row.get(3)?,
                    on_behalf_of: row.get(4)?,
                    source_device_id: row.get(5)?,
                    source_identity_id: row.get(6)?,
                    wall_time_unix_ms: row.get(7)?,
                    logical_order: row.get(8)?,
                    correlation_id: row.get(9)?,
                    causation_id: row.get(10)?,
                    idempotency_key: row.get(11)?,
                    schema_major: row.get(12)?,
                    schema_minor: row.get(13)?,
                    integrity_metadata: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))
}

fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<EventAppendStatus, DurableStoreError> {
    validate_event(event).map_err(map_event_error)?;
    let expected = StoredEvent::from_event(event);
    if let Some(existing) = load_event(transaction, event)? {
        return if existing == expected {
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
        validate_event(event).map_err(map_event_error)?;
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
                 WHERE tenant_id = ?1 AND namespace_present = ?2
                 AND namespace_id = ?3 AND command_id = ?4)",
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
                 WHERE tenant_id = ?1 AND namespace_present = ?2
                 AND namespace_id = ?3 AND command_id = ?4",
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
            return match load_event(&transaction, event)? {
                Some(existing) if existing == StoredEvent::from_event(event) => {
                    Ok(EventAppendStatus::Duplicate)
                }
                _ => Err(DurableStoreError::Corrupt),
            };
        }

        let _ = append_event_in_transaction(&transaction, event)?;
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
                 WHERE tenant_id = ?1 AND namespace_present = ?2
                 AND namespace_id = ?3 AND command_id = ?4",
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
