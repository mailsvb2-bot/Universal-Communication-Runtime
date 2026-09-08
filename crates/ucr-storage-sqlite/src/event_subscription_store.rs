use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, EventSubscriptionStore};
use ucr_model::{
    EventConsumerCursor, EventDeadLetter, EventDeliveryBatch, EventDeliveryFailureKind,
    EventEnvelope, EventPollResult, EventSubscription, EventSubscriptionId, EventSubscriptionMode,
    EventSubscriptionStart, NamespaceId, OpaqueId, TenantId, TenantScope,
};
use ucr_protocol::{
    EventApiError, canonical_event_subscription, event_consumer_cursor_token,
    event_delivery_batch_next_size, event_retry_delay_ms, validate_event_batch_size,
    validate_event_consumer_cursor,
};

use super::{
    SqliteLocalStore, event_journal, map_schema_change_error, map_sqlite_error,
    namespace_storage_key, verify_table_columns,
};

pub(super) const V20_OBJECTS_SQL: &str = "
CREATE TABLE event_subscriptions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('durable_stream', 'webhook')),
    webhook_uri TEXT,
    max_in_flight INTEGER NOT NULL CHECK(max_in_flight > 0),
    max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
    start_mode TEXT NOT NULL CHECK(start_mode IN ('beginning', 'latest')),
    committed_seq INTEGER NOT NULL CHECK(committed_seq >= 0),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    last_replay_id TEXT,
    last_cursor_token BLOB,
    last_cursor_action TEXT CHECK(last_cursor_action IN ('ack', 'reject')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, subscription_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> '')),
    CHECK((last_cursor_token IS NULL AND last_cursor_action IS NULL) OR
          (last_cursor_token IS NOT NULL AND last_cursor_action IS NOT NULL)),
    CHECK((mode = 'durable_stream' AND webhook_uri IS NULL) OR
          (mode = 'webhook' AND webhook_uri IS NOT NULL))
) WITHOUT ROWID;

CREATE TABLE event_subscription_filters (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0),
    event_type TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, subscription_id, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, subscription_id, event_type),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, subscription_id)
      REFERENCES event_subscriptions(tenant_id, namespace_present, namespace_id, subscription_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE event_subscription_active_batches (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    end_seq INTEGER NOT NULL CHECK(end_seq > 0),
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    not_before_unix_ms INTEGER NOT NULL CHECK(not_before_unix_ms >= 0),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, subscription_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, subscription_id)
      REFERENCES event_subscriptions(tenant_id, namespace_present, namespace_id, subscription_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE event_dead_letters (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    journal_seq INTEGER NOT NULL CHECK(journal_seq > 0),
    event_id TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK(attempts > 0),
    failure_kind TEXT NOT NULL CHECK(failure_kind IN ('retryable', 'permanent')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, subscription_id, generation, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, subscription_id)
      REFERENCES event_subscriptions(tenant_id, namespace_present, namespace_id, subscription_id)
      ON DELETE CASCADE,
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES events(tenant_id, namespace_present, namespace_id, event_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE INDEX event_dead_letters_by_subscription_sequence
ON event_dead_letters(tenant_id, namespace_present, namespace_id, subscription_id, journal_seq);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorAction {
    Acknowledge,
    Reject,
}

#[derive(Debug, Clone)]
struct ActiveBatch {
    generation: u64,
    end_seq: u64,
    attempt: u32,
    not_before_unix_ms: i64,
}

#[derive(Debug, Clone)]
struct LoadedSubscription {
    subscription: EventSubscription,
    committed_seq: u64,
    generation: u64,
    last_replay_id: Option<OpaqueId>,
    last_cursor: Option<(Vec<u8>, CursorAction)>,
    active: Option<ActiveBatch>,
}

pub(super) fn create_v20_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V20_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v20(connection: &Connection) -> Result<(), DurableStoreError> {
    super::identity_store::verify_schema_v19(connection)?;
    verify_table_columns(
        connection,
        "event_subscriptions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("subscription_id", "TEXT", 1, 4),
            ("mode", "TEXT", 1, 0),
            ("webhook_uri", "TEXT", 0, 0),
            ("max_in_flight", "INTEGER", 1, 0),
            ("max_attempts", "INTEGER", 1, 0),
            ("start_mode", "TEXT", 1, 0),
            ("committed_seq", "INTEGER", 1, 0),
            ("generation", "INTEGER", 1, 0),
            ("last_replay_id", "TEXT", 0, 0),
            ("last_cursor_token", "BLOB", 0, 0),
            ("last_cursor_action", "TEXT", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "event_subscription_filters",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("subscription_id", "TEXT", 1, 4),
            ("position", "INTEGER", 1, 5),
            ("event_type", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "event_subscription_active_batches",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("subscription_id", "TEXT", 1, 4),
            ("generation", "INTEGER", 1, 0),
            ("end_seq", "INTEGER", 1, 0),
            ("attempt", "INTEGER", 1, 0),
            ("not_before_unix_ms", "INTEGER", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "event_dead_letters",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("subscription_id", "TEXT", 1, 4),
            ("generation", "INTEGER", 1, 5),
            ("journal_seq", "INTEGER", 1, 0),
            ("event_id", "TEXT", 1, 6),
            ("attempts", "INTEGER", 1, 0),
            ("failure_kind", "TEXT", 1, 0),
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
    verify_subscription_rows(connection)
}

fn verify_subscription_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, subscription_id
             FROM event_subscriptions",
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
    for (tenant, present, namespace, subscription_id) in keys {
        let scope = parse_scope(&tenant, present, &namespace)?;
        let subscription_id = EventSubscriptionId::from_opaque(parse_id(&subscription_id)?);
        let loaded = load_subscription(connection, &scope, &subscription_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        if loaded.subscription.scope != scope
            || loaded.generation == 0
            || loaded.active.as_ref().is_some_and(|active| {
                active.generation != loaded.generation
                    || active.end_seq <= loaded.committed_seq
                    || active.attempt == 0
                    || active.attempt > loaded.subscription.max_attempts
                    || active.not_before_unix_ms < 0
            })
        {
            return Err(DurableStoreError::Corrupt);
        }
        if let Some(active) = &loaded.active {
            let events = load_matching_events(
                connection,
                &loaded,
                loaded.committed_seq,
                active.end_seq,
                usize::try_from(loaded.subscription.max_in_flight)
                    .map_err(|_| DurableStoreError::Corrupt)?,
            )?;
            if events.is_empty() {
                return Err(DurableStoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn mode_name(mode: EventSubscriptionMode) -> &'static str {
    match mode {
        EventSubscriptionMode::DurableStream => "durable_stream",
        EventSubscriptionMode::Webhook => "webhook",
    }
}

fn parse_mode(value: &str) -> Result<EventSubscriptionMode, DurableStoreError> {
    match value {
        "durable_stream" => Ok(EventSubscriptionMode::DurableStream),
        "webhook" => Ok(EventSubscriptionMode::Webhook),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn start_name(start: EventSubscriptionStart) -> &'static str {
    match start {
        EventSubscriptionStart::Beginning => "beginning",
        EventSubscriptionStart::Latest => "latest",
    }
}

fn parse_start(value: &str) -> Result<EventSubscriptionStart, DurableStoreError> {
    match value {
        "beginning" => Ok(EventSubscriptionStart::Beginning),
        "latest" => Ok(EventSubscriptionStart::Latest),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn parse_action(value: &str) -> Result<CursorAction, DurableStoreError> {
    match value {
        "ack" => Ok(CursorAction::Acknowledge),
        "reject" => Ok(CursorAction::Reject),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn failure_name(failure: EventDeliveryFailureKind) -> &'static str {
    match failure {
        EventDeliveryFailureKind::Retryable => "retryable",
        EventDeliveryFailureKind::Permanent => "permanent",
    }
}

fn parse_failure(value: &str) -> Result<EventDeliveryFailureKind, DurableStoreError> {
    match value {
        "retryable" => Ok(EventDeliveryFailureKind::Retryable),
        "permanent" => Ok(EventDeliveryFailureKind::Permanent),
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

fn decode_u64(value: i64) -> Result<u64, DurableStoreError> {
    u64::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_u32(value: i64) -> Result<u32, DurableStoreError> {
    u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn map_event_api_error(_error: EventApiError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

fn load_filters(
    connection: &Connection,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
) -> Result<Vec<String>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT position, event_type FROM event_subscription_filters
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4
             ORDER BY position",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str()
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut filters = Vec::new();
    for (expected, row) in rows.enumerate() {
        let (position, event_type) = row.map_err(|error| map_sqlite_error(&error))?;
        if position != i64::try_from(expected).map_err(|_| DurableStoreError::Corrupt)? {
            return Err(DurableStoreError::Corrupt);
        }
        filters.push(event_type);
    }
    Ok(filters)
}

type SubscriptionRow = (
    String,
    Option<String>,
    i64,
    i64,
    String,
    i64,
    i64,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
);

fn load_subscription(
    connection: &Connection,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
) -> Result<Option<LoadedSubscription>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row: Option<SubscriptionRow> = connection
        .query_row(
            "SELECT mode, webhook_uri, max_in_flight, max_attempts, start_mode, committed_seq,
                    generation, last_replay_id, last_cursor_token, last_cursor_action
             FROM event_subscriptions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str()
            ],
            |row| {
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
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((
        mode,
        webhook_uri,
        max_in_flight,
        max_attempts,
        start_mode,
        committed_seq,
        generation,
        last_replay_id,
        last_cursor_token,
        last_cursor_action,
    )) = row
    else {
        return Ok(None);
    };
    let filters = load_filters(connection, scope, subscription_id)?;
    let subscription = EventSubscription {
        subscription_id: subscription_id.clone(),
        scope: scope.clone(),
        mode: parse_mode(&mode)?,
        webhook_uri,
        event_types: filters,
        max_in_flight: decode_u32(max_in_flight)?,
        max_attempts: decode_u32(max_attempts)?,
        start: parse_start(&start_mode)?,
    };
    let canonical =
        canonical_event_subscription(&subscription).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical != subscription {
        return Err(DurableStoreError::Corrupt);
    }
    let last_cursor = match (last_cursor_token, last_cursor_action) {
        (None, None) => None,
        (Some(token), Some(action)) => Some((token, parse_action(&action)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    let active_row: Option<(i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT generation, end_seq, attempt, not_before_unix_ms
             FROM event_subscription_active_batches
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let active = active_row
        .map(|(generation, end_seq, attempt, not_before_unix_ms)| {
            Ok(ActiveBatch {
                generation: decode_u64(generation)?,
                end_seq: decode_u64(end_seq)?,
                attempt: decode_u32(attempt)?,
                not_before_unix_ms,
            })
        })
        .transpose()?;
    Ok(Some(LoadedSubscription {
        subscription,
        committed_seq: decode_u64(committed_seq)?,
        generation: decode_u64(generation)?,
        last_replay_id: last_replay_id.map(|value| parse_id(&value)).transpose()?,
        last_cursor,
        active,
    }))
}

fn latest_journal_seq(connection: &Connection) -> Result<u64, DurableStoreError> {
    let value: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(journal_seq), 0) FROM events",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    decode_u64(value)
}

fn load_matching_event_refs(
    connection: &Connection,
    loaded: &LoadedSubscription,
    after_seq: u64,
    through_seq: Option<u64>,
    max_items: usize,
) -> Result<Vec<(u64, EventEnvelope)>, DurableStoreError> {
    let namespace = namespace_storage_key(&loaded.subscription.scope);
    let after_seq = i64::try_from(after_seq).map_err(|_| DurableStoreError::Corrupt)?;
    let through_seq = through_seq
        .map(|value| i64::try_from(value).map_err(|_| DurableStoreError::Corrupt))
        .transpose()?;
    let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
    let mut statement = connection
        .prepare(
            "SELECT e.journal_seq, e.event_id
             FROM events e
             WHERE e.journal_seq > ?5
               AND (?6 IS NULL OR e.journal_seq <= ?6)
               AND e.tenant_id=?1 AND e.namespace_present=?2 AND e.namespace_id=?3
               AND (
                 NOT EXISTS (
                   SELECT 1 FROM event_subscription_filters f
                   WHERE f.tenant_id=?1 AND f.namespace_present=?2 AND f.namespace_id=?3
                     AND f.subscription_id=?4
                 )
                 OR EXISTS (
                   SELECT 1 FROM event_subscription_filters f
                   WHERE f.tenant_id=?1 AND f.namespace_present=?2 AND f.namespace_id=?3
                     AND f.subscription_id=?4 AND f.event_type=e.event_type
                 )
               )
             ORDER BY e.journal_seq
             LIMIT ?7",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                loaded.subscription.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                loaded.subscription.subscription_id.as_opaque().as_str(),
                after_seq,
                through_seq,
                limit,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut refs = Vec::new();
    let mut batch_bytes = 0_usize;
    for row in rows {
        let (sequence, event_id) = row.map_err(|error| map_sqlite_error(&error))?;
        let event_id = ucr_model::EventId::from_opaque(parse_id(&event_id)?);
        let event =
            event_journal::load_event_by_id(connection, &loaded.subscription.scope, &event_id)?
                .ok_or(DurableStoreError::Corrupt)?;
        let Some(next_batch_bytes) = event_delivery_batch_next_size(batch_bytes, &event)
            .map_err(|_| DurableStoreError::Corrupt)?
        else {
            if refs.is_empty() {
                return Err(DurableStoreError::Corrupt);
            }
            break;
        };
        refs.push((decode_u64(sequence)?, event));
        batch_bytes = next_batch_bytes;
    }
    Ok(refs)
}

fn load_matching_events(
    connection: &Connection,
    loaded: &LoadedSubscription,
    after_seq: u64,
    through_seq: u64,
    max_items: usize,
) -> Result<Vec<EventEnvelope>, DurableStoreError> {
    let refs =
        load_matching_event_refs(connection, loaded, after_seq, Some(through_seq), max_items)?;
    if refs
        .last()
        .is_none_or(|(sequence, _)| *sequence != through_seq)
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(refs.into_iter().map(|(_, event)| event).collect())
}

fn last_action_result(
    loaded: &LoadedSubscription,
    cursor: &EventConsumerCursor,
    expected_action: CursorAction,
) -> Option<Result<DurableRecordStatus, DurableStoreError>> {
    loaded.last_cursor.as_ref().and_then(|(token, action)| {
        (token == &cursor.token).then(|| {
            if *action == expected_action {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            }
        })
    })
}

fn expected_active_cursor(
    scope: &TenantScope,
    loaded: &LoadedSubscription,
) -> Result<EventConsumerCursor, DurableStoreError> {
    let active = loaded.active.as_ref().ok_or(DurableStoreError::Conflict)?;
    if active.generation != loaded.generation || active.end_seq <= loaded.committed_seq {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(event_consumer_cursor_token(
        scope,
        &loaded.subscription,
        loaded.generation,
        active.end_seq,
        active.attempt,
    ))
}

fn persist_last_cursor_action(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
    cursor: &EventConsumerCursor,
    action: CursorAction,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "UPDATE event_subscriptions SET last_cursor_token=?5, last_cursor_action=?6
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str(),
                cursor.token,
                match action {
                    CursorAction::Acknowledge => "ack",
                    CursorAction::Reject => "reject",
                },
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn persist_terminal_rejection(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
    loaded: &LoadedSubscription,
    active: &ActiveBatch,
    failure_kind: EventDeliveryFailureKind,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let refs = load_matching_event_refs(
        transaction,
        loaded,
        loaded.committed_seq,
        Some(active.end_seq),
        usize::try_from(loaded.subscription.max_in_flight)
            .map_err(|_| DurableStoreError::Corrupt)?,
    )?;
    if refs.is_empty() || refs.last().is_none_or(|(seq, _)| *seq != active.end_seq) {
        return Err(DurableStoreError::Corrupt);
    }
    for (sequence, event) in refs {
        transaction
            .execute(
                "INSERT INTO event_dead_letters (
                    tenant_id, namespace_present, namespace_id, subscription_id, generation,
                    journal_seq, event_id, attempts, failure_kind
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    i64::try_from(loaded.generation).map_err(|_| DurableStoreError::Corrupt)?,
                    i64::try_from(sequence).map_err(|_| DurableStoreError::Corrupt)?,
                    event.event_id.as_opaque().as_str(),
                    i64::from(active.attempt),
                    failure_name(failure_kind),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    transaction
        .execute(
            "UPDATE event_subscriptions SET committed_seq=?5
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str(),
                i64::try_from(active.end_seq).map_err(|_| DurableStoreError::Corrupt)?,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    delete_active(transaction, scope, subscription_id)
}

fn persist_retry_rejection(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
    active: &ActiveBatch,
    now_unix_ms: i64,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let next_attempt = active
        .attempt
        .checked_add(1)
        .ok_or(DurableStoreError::Corrupt)?;
    let delay = i64::try_from(event_retry_delay_ms(next_attempt))
        .map_err(|_| DurableStoreError::Internal)?;
    let not_before_unix_ms = now_unix_ms
        .checked_add(delay)
        .ok_or(DurableStoreError::InvalidRecord)?;
    transaction
        .execute(
            "UPDATE event_subscription_active_batches
             SET attempt=?5, not_before_unix_ms=?6
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str(),
                i64::from(next_attempt),
                not_before_unix_ms,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

impl EventSubscriptionStore for SqliteLocalStore {
    fn persist_event_subscription(
        &self,
        subscription: &EventSubscription,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_event_subscription(subscription).map_err(map_event_api_error)?;
        let namespace = namespace_storage_key(&canonical.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_subscription(&transaction, &canonical.scope, &canonical.subscription_id)?
        {
            return if existing.subscription == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let committed_seq = match canonical.start {
            EventSubscriptionStart::Beginning => 0,
            EventSubscriptionStart::Latest => latest_journal_seq(&transaction)?,
        };
        transaction
            .execute(
                "INSERT INTO event_subscriptions (
                    tenant_id, namespace_present, namespace_id, subscription_id, mode, webhook_uri,
                    max_in_flight, max_attempts, start_mode, committed_seq, generation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
                params![
                    canonical.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    canonical.subscription_id.as_opaque().as_str(),
                    mode_name(canonical.mode),
                    canonical.webhook_uri,
                    i64::from(canonical.max_in_flight),
                    i64::from(canonical.max_attempts),
                    start_name(canonical.start),
                    i64::try_from(committed_seq).map_err(|_| DurableStoreError::Internal)?,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        for (position, event_type) in canonical.event_types.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO event_subscription_filters (
                        tenant_id, namespace_present, namespace_id, subscription_id, position, event_type
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        canonical.scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        canonical.subscription_id.as_opaque().as_str(),
                        i64::try_from(position).map_err(|_| DurableStoreError::InvalidRecord)?,
                        event_type,
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn event_subscription(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
    ) -> Result<Option<EventSubscription>, DurableStoreError> {
        let connection = self.lock_connection()?;
        Ok(load_subscription(&connection, scope, subscription_id)?.map(|value| value.subscription))
    }

    fn poll_event_subscription(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        max_items: usize,
        now_unix_ms: i64,
    ) -> Result<EventPollResult, DurableStoreError> {
        validate_event_batch_size(max_items).map_err(map_event_api_error)?;
        if now_unix_ms < 0 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let loaded = load_subscription(&transaction, scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if let Some(active) = &loaded.active {
            if now_unix_ms < active.not_before_unix_ms {
                let retry_after_ms = u64::try_from(active.not_before_unix_ms - now_unix_ms)
                    .map_err(|_| DurableStoreError::Corrupt)?;
                return Ok(EventPollResult::RetryAfter { retry_after_ms });
            }
            let events = load_matching_events(
                &transaction,
                &loaded,
                loaded.committed_seq,
                active.end_seq,
                usize::try_from(loaded.subscription.max_in_flight)
                    .map_err(|_| DurableStoreError::Corrupt)?,
            )?;
            let cursor = expected_active_cursor(scope, &loaded)?;
            return Ok(EventPollResult::Batch(EventDeliveryBatch {
                subscription_id: subscription_id.clone(),
                scope: scope.clone(),
                events,
                cursor,
                attempt: active.attempt,
            }));
        }
        let limit = max_items.min(
            usize::try_from(loaded.subscription.max_in_flight)
                .map_err(|_| DurableStoreError::Corrupt)?,
        );
        let refs =
            load_matching_event_refs(&transaction, &loaded, loaded.committed_seq, None, limit)?;
        if refs.is_empty() {
            let latest = latest_journal_seq(&transaction)?;
            transaction
                .execute(
                    "UPDATE event_subscriptions SET committed_seq=?5
                     WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
                    params![
                        scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        subscription_id.as_opaque().as_str(),
                        i64::try_from(latest).map_err(|_| DurableStoreError::Internal)?,
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(EventPollResult::Empty);
        }
        let end_seq = refs.last().ok_or(DurableStoreError::Corrupt)?.0;
        transaction
            .execute(
                "INSERT INTO event_subscription_active_batches (
                    tenant_id, namespace_present, namespace_id, subscription_id, generation,
                    end_seq, attempt, not_before_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    i64::try_from(loaded.generation).map_err(|_| DurableStoreError::Corrupt)?,
                    i64::try_from(end_seq).map_err(|_| DurableStoreError::Corrupt)?,
                    now_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let cursor =
            event_consumer_cursor_token(scope, &loaded.subscription, loaded.generation, end_seq, 1);
        let events = refs.into_iter().map(|(_, event)| event).collect();
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(EventPollResult::Batch(EventDeliveryBatch {
            subscription_id: subscription_id.clone(),
            scope: scope.clone(),
            events,
            cursor,
            attempt: 1,
        }))
    }

    fn acknowledge_event_cursor(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        cursor: &EventConsumerCursor,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_event_consumer_cursor(cursor).map_err(map_event_api_error)?;
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let loaded = load_subscription(&transaction, scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if let Some(result) = last_action_result(&loaded, cursor, CursorAction::Acknowledge) {
            return result;
        }
        let expected = expected_active_cursor(scope, &loaded)?;
        if expected != *cursor {
            return Err(DurableStoreError::Conflict);
        }
        let active = loaded.active.ok_or(DurableStoreError::Corrupt)?;
        transaction
            .execute(
                "UPDATE event_subscriptions
                 SET committed_seq=?5, last_cursor_token=?6, last_cursor_action='ack'
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    i64::try_from(active.end_seq).map_err(|_| DurableStoreError::Corrupt)?,
                    cursor.token,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        delete_active(&transaction, scope, subscription_id)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn reject_event_cursor(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        cursor: &EventConsumerCursor,
        failure_kind: EventDeliveryFailureKind,
        now_unix_ms: i64,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_event_consumer_cursor(cursor).map_err(map_event_api_error)?;
        if now_unix_ms < 0 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let loaded = load_subscription(&transaction, scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if let Some(result) = last_action_result(&loaded, cursor, CursorAction::Reject) {
            return result;
        }
        if expected_active_cursor(scope, &loaded)? != *cursor {
            return Err(DurableStoreError::Conflict);
        }
        let active = loaded.active.clone().ok_or(DurableStoreError::Corrupt)?;
        persist_last_cursor_action(
            &transaction,
            scope,
            subscription_id,
            cursor,
            CursorAction::Reject,
        )?;
        if failure_kind == EventDeliveryFailureKind::Permanent
            || active.attempt >= loaded.subscription.max_attempts
        {
            persist_terminal_rejection(
                &transaction,
                scope,
                subscription_id,
                &loaded,
                &active,
                failure_kind,
            )?;
        } else {
            persist_retry_rejection(&transaction, scope, subscription_id, &active, now_unix_ms)?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn replay_event_subscription(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        replay_id: &OpaqueId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let loaded = load_subscription(&transaction, scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if loaded.last_replay_id.as_ref() == Some(replay_id) {
            return Ok(DurableRecordStatus::Duplicate);
        }
        let generation = loaded
            .generation
            .checked_add(1)
            .ok_or(DurableStoreError::Corrupt)?;
        transaction
            .execute(
                "UPDATE event_subscriptions
                 SET committed_seq=0, generation=?5, last_replay_id=?6,
                     last_cursor_token=NULL, last_cursor_action=NULL
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    i64::try_from(generation).map_err(|_| DurableStoreError::Corrupt)?,
                    replay_id.as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        delete_active(&transaction, scope, subscription_id)?;
        transaction
            .execute(
                "DELETE FROM event_dead_letters
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn event_dead_letters(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        max_items: usize,
    ) -> Result<Vec<EventDeadLetter>, DurableStoreError> {
        validate_event_batch_size(max_items).map_err(map_event_api_error)?;
        let connection = self.lock_connection()?;
        let loaded = load_subscription(&connection, scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let mut statement = connection
            .prepare(
                "SELECT event_id, attempts, failure_kind FROM event_dead_letters
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4
                 ORDER BY journal_seq LIMIT ?5",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut dead_letters = Vec::new();
        for row in rows {
            let (event_id, attempts, failure_kind) =
                row.map_err(|error| map_sqlite_error(&error))?;
            let event_id = ucr_model::EventId::from_opaque(parse_id(&event_id)?);
            let event = event_journal::load_event_by_id(&connection, scope, &event_id)?
                .ok_or(DurableStoreError::Corrupt)?;
            dead_letters.push(EventDeadLetter {
                subscription_id: loaded.subscription.subscription_id.clone(),
                scope: scope.clone(),
                event,
                attempts: decode_u32(attempts)?,
                failure_kind: parse_failure(&failure_kind)?,
            });
        }
        Ok(dead_letters)
    }
}

fn delete_active(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    transaction
        .execute(
            "DELETE FROM event_subscription_active_batches
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use ucr_core::{
        DurableRecordStatus, DurableStoreError, EventJournalStore, EventSubscriptionStore,
        StorageProvider,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventConsumerCursor,
        EventDeliveryFailureKind, EventEnvelope, EventId, EventPollResult, EventSubscription,
        EventSubscriptionId, EventSubscriptionMode, EventSubscriptionStart, IdentityId, OpaqueId,
        ProtocolVersion, TenantId, TenantScope,
    };

    use super::SqliteLocalStore;

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDbPath(PathBuf);

    impl TestDbPath {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-phase14-event-api-{}-{sequence}.sqlite3",
                std::process::id()
            )))
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

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-phase14")),
            namespace_id: None,
        }
    }

    fn event(id: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.message.created".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-phase14")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-phase14")),
                identity_id: IdentityId::from_opaque(oid("identity-phase14")),
            },
            wall_time_unix_ms: 1_000,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("correlation-phase14"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: vec![1, 2, 3],
            extensions: Vec::new(),
        }
    }

    fn subscription() -> EventSubscription {
        EventSubscription {
            subscription_id: EventSubscriptionId::from_opaque(oid("subscription-phase14")),
            scope: scope(),
            mode: EventSubscriptionMode::DurableStream,
            webhook_uri: None,
            event_types: vec!["ucr.message.created".to_owned()],
            max_in_flight: 1,
            max_attempts: 2,
            start: EventSubscriptionStart::Beginning,
        }
    }

    fn seed_retry_state(db: &TestDbPath, subscription: &EventSubscription) -> EventConsumerCursor {
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .persist_event_subscription(subscription)
            .expect("subscription");
        store
            .append_event(&event("event-phase14", b"payload"))
            .expect("event");
        let first = match store
            .poll_event_subscription(&scope(), &subscription.subscription_id, 1, 10_000)
            .expect("first poll")
        {
            EventPollResult::Batch(batch) => batch,
            other => panic!("unexpected first poll: {other:?}"),
        };
        store
            .reject_event_cursor(
                &scope(),
                &subscription.subscription_id,
                &first.cursor,
                EventDeliveryFailureKind::Retryable,
                10_000,
            )
            .expect("retry reject");
        first.cursor
    }

    fn finish_retry_after_restart(
        db: &TestDbPath,
        subscription: &EventSubscription,
        first_cursor: &EventConsumerCursor,
    ) -> EventConsumerCursor {
        let store = SqliteLocalStore::open(db.path()).expect("reopen retry state");
        assert!(matches!(
            store
                .poll_event_subscription(&scope(), &subscription.subscription_id, 1, 10_500)
                .expect("retry delay"),
            EventPollResult::RetryAfter {
                retry_after_ms: 500
            }
        ));
        let retry = match store
            .poll_event_subscription(&scope(), &subscription.subscription_id, 1, 11_000)
            .expect("second attempt")
        {
            EventPollResult::Batch(batch) => batch,
            other => panic!("unexpected retry: {other:?}"),
        };
        assert_eq!(retry.attempt, 2);
        assert_ne!(&retry.cursor, first_cursor);
        store
            .reject_event_cursor(
                &scope(),
                &subscription.subscription_id,
                &retry.cursor,
                EventDeliveryFailureKind::Retryable,
                11_000,
            )
            .expect("dead letter at max attempts");
        retry.cursor
    }

    fn replay_after_restart(db: &TestDbPath, subscription: &EventSubscription) {
        let store = SqliteLocalStore::open(db.path()).expect("reopen dead letter state");
        let dead = store
            .event_dead_letters(&scope(), &subscription.subscription_id, 8)
            .expect("dead letters");
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].event.event_id.as_opaque().as_str(), "event-phase14");
        let replay_id = oid("replay-phase14");
        assert_eq!(
            store.replay_event_subscription(&scope(), &subscription.subscription_id, &replay_id),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.replay_event_subscription(&scope(), &subscription.subscription_id, &replay_id),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn retry_cursor_dead_letter_and_replay_survive_restart() {
        let db = TestDbPath::new();
        let subscription = subscription();
        let first_cursor = seed_retry_state(&db, &subscription);
        let retry_cursor = finish_retry_after_restart(&db, &subscription, &first_cursor);
        replay_after_restart(&db, &subscription);

        let store = SqliteLocalStore::open(db.path()).expect("reopen replay state");
        assert!(
            store
                .event_dead_letters(&scope(), &subscription.subscription_id, 8)
                .expect("replay clears dlq")
                .is_empty()
        );
        let replayed = match store
            .poll_event_subscription(&scope(), &subscription.subscription_id, 1, 20_000)
            .expect("replayed event")
        {
            EventPollResult::Batch(batch) => batch,
            other => panic!("unexpected replay: {other:?}"),
        };
        assert_eq!(
            replayed.events[0].event_id.as_opaque().as_str(),
            "event-phase14"
        );
        assert_ne!(replayed.cursor, retry_cursor);
        assert_eq!(
            store.acknowledge_event_cursor(&scope(), &subscription.subscription_id, &retry_cursor,),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn v19_to_v20_migration_preserves_events_and_invents_no_subscriptions() {
        let db = TestDbPath::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize v20");
            store
                .append_event(&event("event-before-v20", b"before"))
                .expect("seed event");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("downgrade fixture");
            connection
                .execute_batch(
                    "DROP TABLE event_dead_letters;
                     DROP TABLE event_subscription_active_batches;
                     DROP TABLE event_subscription_filters;
                     DROP TABLE event_subscriptions;
                     DROP TABLE IF EXISTS group_changes; DROP TABLE IF EXISTS group_bridge_mappings; DROP TABLE IF EXISTS group_memberships; DROP TABLE IF EXISTS groups; PRAGMA user_version=19;",
                )
                .expect("construct exact v19 fixture");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v19 to v20");
        assert_eq!(
            migrated.schema_version(),
            Ok(super::super::SQLITE_SCHEMA_VERSION)
        );
        let connection = rusqlite::Connection::open(db.path()).expect("inspect migration");
        let subscriptions: i64 = connection
            .query_row("SELECT COUNT(*) FROM event_subscriptions", [], |row| {
                row.get(0)
            })
            .expect("subscription count");
        let events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id='event-before-v20'",
                [],
                |row| row.get(0),
            )
            .expect("event count");
        assert_eq!(subscriptions, 0);
        assert_eq!(events, 1);
    }
}
