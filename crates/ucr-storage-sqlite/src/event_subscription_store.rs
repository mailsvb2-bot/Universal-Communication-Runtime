use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, EventSubscriptionStore};
use ucr_model::{
    EventConsumerCursor, EventDeadLetter, EventDeliveryBatch, EventDeliveryFailureKind,
    EventEnvelope, EventPollResult, EventSubscription, EventSubscriptionId, EventSubscriptionMode,
    EventSubscriptionStart, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef,
    ScopedPrincipal, TenantId, TenantScope,
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

pub(super) const V36_OBJECTS_SQL: &str = "
CREATE TABLE event_subscription_owners (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    owner_principal_id TEXT NOT NULL,
    owner_principal_kind TEXT NOT NULL CHECK(owner_principal_kind IN (
        'person', 'device', 'service_account', 'ai_agent', 'bot', 'organization',
        'automation', 'external_platform'
    )),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, subscription_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, subscription_id)
      REFERENCES event_subscriptions(tenant_id, namespace_present, namespace_id, subscription_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
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
    owner: Option<ScopedPrincipal>,
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

pub(super) fn create_v36_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V36_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v36_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "event_subscription_owners",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("subscription_id", "TEXT", 1, 4),
            ("owner_principal_id", "TEXT", 1, 0),
            ("owner_principal_kind", "TEXT", 1, 0),
        ],
    )?;
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, subscription_id
             FROM event_subscription_owners",
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
        let owner = load_subscription_owner(connection, &scope, &subscription_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        if owner.scope != scope {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
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

const fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Person => "person",
        PrincipalKind::Device => "device",
        PrincipalKind::ServiceAccount => "service_account",
        PrincipalKind::AiAgent => "ai_agent",
        PrincipalKind::Bot => "bot",
        PrincipalKind::Organization => "organization",
        PrincipalKind::Automation => "automation",
        PrincipalKind::ExternalPlatform => "external_platform",
    }
}

fn parse_principal_kind(value: &str) -> Result<PrincipalKind, DurableStoreError> {
    match value {
        "person" => Ok(PrincipalKind::Person),
        "device" => Ok(PrincipalKind::Device),
        "service_account" => Ok(PrincipalKind::ServiceAccount),
        "ai_agent" => Ok(PrincipalKind::AiAgent),
        "bot" => Ok(PrincipalKind::Bot),
        "organization" => Ok(PrincipalKind::Organization),
        "automation" => Ok(PrincipalKind::Automation),
        "external_platform" => Ok(PrincipalKind::ExternalPlatform),
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

fn load_subscription_owner(
    connection: &Connection,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
) -> Result<Option<ScopedPrincipal>, DurableStoreError> {
    let owner_table_exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name='event_subscription_owners'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if owner_table_exists == 0 {
        return Ok(None);
    }
    let namespace = namespace_storage_key(scope);
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT owner_principal_id, owner_principal_kind
             FROM event_subscription_owners
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND subscription_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subscription_id.as_opaque().as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|(principal_id, principal_kind)| {
        Ok(ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&principal_id)?),
                kind: parse_principal_kind(&principal_kind)?,
            },
        })
    })
    .transpose()
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

fn load_active_batch(
    connection: &Connection,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
) -> Result<Option<ActiveBatch>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
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
    active_row
        .map(|(generation, end_seq, attempt, not_before_unix_ms)| {
            Ok(ActiveBatch {
                generation: decode_u64(generation)?,
                end_seq: decode_u64(end_seq)?,
                attempt: decode_u32(attempt)?,
                not_before_unix_ms,
            })
        })
        .transpose()
}

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
    let owner = load_subscription_owner(connection, scope, subscription_id)?;
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
    let active = load_active_batch(connection, scope, subscription_id)?;
    Ok(Some(LoadedSubscription {
        subscription,
        owner,
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
    let owner = loaded
        .owner
        .as_ref()
        .ok_or(DurableStoreError::PermissionDenied)?;
    if owner.scope != loaded.subscription.scope {
        return Err(DurableStoreError::Corrupt);
    }
    let (enforce_owner, owner_principal_id) =
        if owner.principal.kind == PrincipalKind::ServiceAccount {
            (1_i64, owner.principal.principal_id.as_opaque().as_str())
        } else {
            (0_i64, "")
        };
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
               AND (?8 = 0 OR (e.actor_kind='system' AND e.on_behalf_of=?9))
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
                enforce_owner,
                owner_principal_id,
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

const MAX_WEBHOOK_DISPATCH_TARGET_PAGE: usize = 256;

type WebhookDispatchTarget = (TenantScope, EventSubscriptionId);

impl SqliteLocalStore {
    /// Lists one bounded page of canonical Service Account-owned webhook subscriptions.
    ///
    /// This is an operator/runtime discovery surface only. It does not create a second queue or
    /// delivery owner: every returned target must still pass `EventWebhookDispatcher` ownership
    /// validation immediately before polling or network I/O.
    ///
    /// # Errors
    /// Returns invalid-record for an empty/oversized page request and explicit storage/corruption
    /// failures otherwise.
    pub fn service_webhook_dispatch_targets(
        &self,
        after: Option<&(TenantScope, EventSubscriptionId)>,
        max_items: usize,
    ) -> Result<Vec<(TenantScope, EventSubscriptionId)>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_WEBHOOK_DISPATCH_TARGET_PAGE {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
        match after {
            Some((scope, subscription_id)) => {
                service_webhook_dispatch_targets_after(&connection, scope, subscription_id, limit)
            }
            None => service_webhook_dispatch_targets_first(&connection, limit),
        }
    }
}

fn service_webhook_dispatch_targets_first(
    connection: &Connection,
    limit: i64,
) -> Result<Vec<WebhookDispatchTarget>, DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT s.tenant_id, s.namespace_present, s.namespace_id, s.subscription_id
             FROM event_subscriptions AS s
             INNER JOIN event_subscription_owners AS o
               ON o.tenant_id = s.tenant_id
              AND o.namespace_present = s.namespace_present
              AND o.namespace_id = s.namespace_id
              AND o.subscription_id = s.subscription_id
             WHERE s.mode = 'webhook'
               AND o.owner_principal_kind = 'service_account'
             ORDER BY s.tenant_id, s.namespace_present, s.namespace_id, s.subscription_id
             LIMIT ?1",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    collect_webhook_dispatch_targets(
        statement
            .query_map(params![limit], read_webhook_dispatch_target)
            .map_err(|error| map_sqlite_error(&error))?,
    )
}

fn service_webhook_dispatch_targets_after(
    connection: &Connection,
    scope: &TenantScope,
    subscription_id: &EventSubscriptionId,
    limit: i64,
) -> Result<Vec<WebhookDispatchTarget>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT s.tenant_id, s.namespace_present, s.namespace_id, s.subscription_id
             FROM event_subscriptions AS s
             INNER JOIN event_subscription_owners AS o
               ON o.tenant_id = s.tenant_id
              AND o.namespace_present = s.namespace_present
              AND o.namespace_id = s.namespace_id
              AND o.subscription_id = s.subscription_id
             WHERE s.mode = 'webhook'
               AND o.owner_principal_kind = 'service_account'
               AND (
                    s.tenant_id > ?1
                 OR (s.tenant_id = ?1 AND s.namespace_present > ?2)
                 OR (s.tenant_id = ?1 AND s.namespace_present = ?2 AND s.namespace_id > ?3)
                 OR (s.tenant_id = ?1 AND s.namespace_present = ?2 AND s.namespace_id = ?3
                     AND s.subscription_id > ?4)
               )
             ORDER BY s.tenant_id, s.namespace_present, s.namespace_id, s.subscription_id
             LIMIT ?5",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    collect_webhook_dispatch_targets(
        statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    subscription_id.as_opaque().as_str(),
                    limit,
                ],
                read_webhook_dispatch_target,
            )
            .map_err(|error| map_sqlite_error(&error))?,
    )
}

fn read_webhook_dispatch_target(
    row: &rusqlite::Row<'_>,
) -> Result<(String, i64, String, String), rusqlite::Error> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn collect_webhook_dispatch_targets<F>(
    rows: rusqlite::MappedRows<'_, F>,
) -> Result<Vec<WebhookDispatchTarget>, DurableStoreError>
where
    F: FnMut(&rusqlite::Row<'_>) -> Result<(String, i64, String, String), rusqlite::Error>,
{
    let mut targets = Vec::new();
    for row in rows {
        let (tenant, namespace_present, namespace, subscription_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        targets.push((
            parse_scope(&tenant, namespace_present, &namespace)?,
            EventSubscriptionId::from_opaque(parse_id(&subscription_id)?),
        ));
    }
    Ok(targets)
}

impl EventSubscriptionStore for SqliteLocalStore {
    fn persist_event_subscription(
        &self,
        owner: &ScopedPrincipal,
        subscription: &EventSubscription,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_event_subscription(subscription).map_err(map_event_api_error)?;
        if owner.scope != canonical.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let namespace = namespace_storage_key(&canonical.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_subscription(&transaction, &canonical.scope, &canonical.subscription_id)?
        {
            return if existing.subscription == canonical && existing.owner.as_ref() == Some(owner) {
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
        transaction
            .execute(
                "INSERT INTO event_subscription_owners (
                    tenant_id, namespace_present, namespace_id, subscription_id,
                    owner_principal_id, owner_principal_kind
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    canonical.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    canonical.subscription_id.as_opaque().as_str(),
                    owner.principal.principal_id.as_opaque().as_str(),
                    principal_kind_name(owner.principal.kind),
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

    fn event_subscription_owner(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
    ) -> Result<Option<ScopedPrincipal>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_subscription_owner(&connection, scope, subscription_id)
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
        PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion, ScopedPrincipal, TenantId,
        TenantScope,
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

    fn subscription_owner() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("event-subscription-owner")),
                kind: PrincipalKind::Person,
            },
        }
    }

    fn service_owner(id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn attributed_event(id: &str, owner: &ScopedPrincipal, payload: &[u8]) -> EventEnvelope {
        let mut value = event(id, payload);
        value.actor.on_behalf_of = Some(owner.principal.principal_id.clone());
        value
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

    fn webhook_subscription(id: &str) -> EventSubscription {
        let mut value = subscription();
        value.subscription_id = EventSubscriptionId::from_opaque(oid(id));
        value.mode = EventSubscriptionMode::Webhook;
        value.webhook_uri = Some("https://webhook.example.test/ucr".to_owned());
        value
    }

    fn seed_retry_state(db: &TestDbPath, subscription: &EventSubscription) -> EventConsumerCursor {
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .persist_event_subscription(&subscription_owner(), subscription)
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
    fn webhook_dispatch_target_discovery_is_bounded_paginated_and_service_only() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let service = service_owner("dispatch-service");
        let first_webhook = webhook_subscription("dispatch-webhook-a");
        let second_webhook = webhook_subscription("dispatch-webhook-b");
        let person_webhook = webhook_subscription("dispatch-webhook-person");
        let mut durable_stream = subscription();
        durable_stream.subscription_id =
            EventSubscriptionId::from_opaque(oid("dispatch-durable-service"));

        store
            .persist_event_subscription(&service, &first_webhook)
            .expect("first service webhook");
        store
            .persist_event_subscription(&service, &second_webhook)
            .expect("second service webhook");
        store
            .persist_event_subscription(&subscription_owner(), &person_webhook)
            .expect("person webhook");
        store
            .persist_event_subscription(&service, &durable_stream)
            .expect("service durable stream");

        let first_page = store
            .service_webhook_dispatch_targets(None, 1)
            .expect("first dispatch page");
        assert_eq!(first_page.len(), 1);
        assert_eq!(
            first_page[0].1.as_opaque().as_str(),
            first_webhook.subscription_id.as_opaque().as_str()
        );

        let second_page = store
            .service_webhook_dispatch_targets(first_page.last(), 1)
            .expect("second dispatch page");
        assert_eq!(second_page.len(), 1);
        assert_eq!(
            second_page[0].1.as_opaque().as_str(),
            second_webhook.subscription_id.as_opaque().as_str()
        );
        assert!(
            store
                .service_webhook_dispatch_targets(second_page.last(), 1)
                .expect("last dispatch page")
                .is_empty()
        );
        assert_eq!(
            store.service_webhook_dispatch_targets(None, 0),
            Err(DurableStoreError::InvalidRecord)
        );
        assert_eq!(
            store.service_webhook_dispatch_targets(None, super::MAX_WEBHOOK_DISPATCH_TARGET_PAGE + 1),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn service_account_owner_and_filter_survive_sqlite_restart() {
        let db = TestDbPath::new();
        let owner_a = service_owner("sqlite-service-a");
        let owner_b = service_owner("sqlite-service-b");
        let subscription = subscription();

        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.persist_event_subscription(&owner_a, &subscription),
                Ok(DurableRecordStatus::Persisted)
            );
            store
                .append_event(&attributed_event("sqlite-event-b", &owner_b, b"private-b"))
                .expect("append B event");
            store
                .append_event(&attributed_event("sqlite-event-a", &owner_a, b"private-a"))
                .expect("append A event");
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened
                .event_subscription_owner(&scope(), &subscription.subscription_id)
                .expect("load durable owner"),
            Some(owner_a)
        );
        let batch = match reopened
            .poll_event_subscription(&scope(), &subscription.subscription_id, 8, 9_000)
            .expect("poll after restart")
        {
            EventPollResult::Batch(batch) => batch,
            other => panic!("expected durable batch, got {other:?}"),
        };
        assert_eq!(batch.events.len(), 1);
        assert_eq!(
            batch.events[0].event_id.as_opaque().as_str(),
            "sqlite-event-a"
        );
    }

    #[test]
    fn v35_subscription_migration_keeps_legacy_owner_unknown_and_fail_closed() {
        let db = TestDbPath::new();
        let owner = service_owner("sqlite-legacy-service");
        let subscription = subscription();
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current store");
            store
                .persist_event_subscription(&owner, &subscription)
                .expect("persist current subscription");
            store
                .append_event(&attributed_event("sqlite-legacy-event", &owner, b"legacy"))
                .expect("append legacy event");
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            connection
                .execute_batch(
                    "DROP TABLE service_recording_usage;
                 DROP TABLE service_resource_quota_policies;
                     DROP TABLE service_rate_limit_usage;
                     DROP TABLE service_rate_limit_policies;
                     DROP TABLE event_subscription_owners;
                     PRAGMA user_version=35;",
                )
                .expect("simulate exact v35 subscription state");
        }

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v35 to v36");
        assert_eq!(
            migrated.schema_version(),
            Ok(super::super::SQLITE_SCHEMA_VERSION)
        );
        assert_eq!(
            migrated
                .event_subscription_owner(&scope(), &subscription.subscription_id)
                .expect("load migrated owner"),
            None
        );
        assert_eq!(
            migrated.poll_event_subscription(&scope(), &subscription.subscription_id, 1, 10_000),
            Err(DurableStoreError::PermissionDenied)
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
    fn canonical_event_projection_filters_types_and_preserves_journal_order() {
        let db = TestDbPath::new();
        let store = SqliteLocalStore::open(db.path()).expect("open projection store");
        let first = event("event-projection-a", b"a");
        let mut ignored = event("event-projection-ignored", b"ignored");
        ignored.event_type = "ucr.other.event.v1".to_owned();
        let third = event("event-projection-b", b"b");
        store.append_event(&first).expect("append first");
        store.append_event(&ignored).expect("append ignored");
        store.append_event(&third).expect("append third");

        let projected = store
            .events_for_types(&scope(), &["ucr.message.created"], 8)
            .expect("project events");
        assert_eq!(projected.len(), 2);
        assert_eq!(
            projected[0].event_id.as_opaque().as_str(),
            "event-projection-a"
        );
        assert_eq!(
            projected[1].event_id.as_opaque().as_str(),
            "event-projection-b"
        );
        assert_eq!(
            store.events_for_types(&scope(), &["ucr.message.created"], 0),
            Err(DurableStoreError::InvalidRecord)
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
            crate::test_remove_v26_objects(&connection).expect("remove future v26 objects");
            connection
                .execute_batch(
                    "DROP TABLE IF EXISTS mesh_group_message_hops;
         DROP TABLE IF EXISTS mesh_group_message_hops;\n                     DROP TABLE IF EXISTS store_forward_jobs;\n                     DROP TABLE IF EXISTS store_forward_tombstones;\n                     DROP TABLE IF EXISTS offline_group_messages;
                     DROP TABLE IF EXISTS offline_group_changes;
                     DROP TRIGGER IF EXISTS event_id_owner_events;
                     DROP TRIGGER IF EXISTS event_id_owner_group_changes;
                     DROP TRIGGER IF EXISTS event_id_owner_call_signals;
                     DROP TABLE IF EXISTS call_signals;
                     DROP TABLE IF EXISTS call_participants;
                     DROP TABLE IF EXISTS calls;
                     DROP TABLE event_dead_letters;
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
