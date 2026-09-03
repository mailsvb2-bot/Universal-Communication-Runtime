use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, SyncStore};
use ucr_model::{
    ConversationId, EndpointId, NamespaceId, OpaqueId, SessionId, SyncCheckpoint, SyncLinkKind,
    SyncMode, SyncSelection, SyncSession, SyncState, TenantId, TenantScope,
};
use ucr_protocol::{
    SyncError, canonical_sync_session, validate_sync_checkpoint, validate_sync_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

pub(super) const V7_OBJECTS_SQL: &str = "
CREATE TABLE sync_sessions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_endpoint_id TEXT NOT NULL,
    target_endpoint_id TEXT NOT NULL,
    link_kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, session_id),
    CHECK(source_endpoint_id <> target_endpoint_id),
    CHECK(link_kind IN ('device_device','device_node','peer_peer','device_cloud')),
    CHECK(mode IN ('full','partial')),
    CHECK(state IN ('prepared','active','paused','completed','cancelled','failed')),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE sync_session_conversations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, session_id, conversation_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, session_id)
      REFERENCES sync_sessions(tenant_id, namespace_present, namespace_id, session_id)
      ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE sync_checkpoints (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    generation BLOB NOT NULL CHECK(length(generation) = 8),
    resume_token BLOB NOT NULL CHECK(length(resume_token) BETWEEN 1 AND 4096),
    applied_items BLOB NOT NULL CHECK(length(applied_items) = 8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, session_id, generation),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, session_id)
      REFERENCES sync_sessions(tenant_id, namespace_present, namespace_id, session_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v7_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V7_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v7(connection: &Connection) -> Result<(), DurableStoreError> {
    super::delivery_store::verify_schema_v6(connection)?;
    verify_table_columns(
        connection,
        "sync_sessions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("session_id", "TEXT", 1, 4),
            ("source_endpoint_id", "TEXT", 1, 0),
            ("target_endpoint_id", "TEXT", 1, 0),
            ("link_kind", "TEXT", 1, 0),
            ("mode", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "sync_session_conversations",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("session_id", "TEXT", 1, 4),
            ("conversation_id", "TEXT", 1, 5),
        ],
    )?;
    verify_table_columns(
        connection,
        "sync_checkpoints",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("session_id", "TEXT", 1, 4),
            ("generation", "BLOB", 1, 5),
            ("resume_token", "BLOB", 1, 0),
            ("applied_items", "BLOB", 1, 0),
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
    verify_sync_rows(connection)
}

fn link_kind_name(kind: SyncLinkKind) -> &'static str {
    match kind {
        SyncLinkKind::DeviceDevice => "device_device",
        SyncLinkKind::DeviceNode => "device_node",
        SyncLinkKind::PeerPeer => "peer_peer",
        SyncLinkKind::DeviceCloud => "device_cloud",
    }
}

fn parse_link_kind(value: &str) -> Result<SyncLinkKind, DurableStoreError> {
    match value {
        "device_device" => Ok(SyncLinkKind::DeviceDevice),
        "device_node" => Ok(SyncLinkKind::DeviceNode),
        "peer_peer" => Ok(SyncLinkKind::PeerPeer),
        "device_cloud" => Ok(SyncLinkKind::DeviceCloud),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn mode_name(mode: SyncMode) -> &'static str {
    match mode {
        SyncMode::Full => "full",
        SyncMode::Partial => "partial",
    }
}

fn parse_mode(value: &str) -> Result<SyncMode, DurableStoreError> {
    match value {
        "full" => Ok(SyncMode::Full),
        "partial" => Ok(SyncMode::Partial),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn state_name(state: SyncState) -> &'static str {
    match state {
        SyncState::Prepared => "prepared",
        SyncState::Active => "active",
        SyncState::Paused => "paused",
        SyncState::Completed => "completed",
        SyncState::Cancelled => "cancelled",
        SyncState::Failed => "failed",
    }
}

fn parse_state(value: &str) -> Result<SyncState, DurableStoreError> {
    match value {
        "prepared" => Ok(SyncState::Prepared),
        "active" => Ok(SyncState::Active),
        "paused" => Ok(SyncState::Paused),
        "completed" => Ok(SyncState::Completed),
        "cancelled" => Ok(SyncState::Cancelled),
        "failed" => Ok(SyncState::Failed),
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

fn load_selection(
    connection: &Connection,
    scope: &TenantScope,
    session_id: &SessionId,
    mode: SyncMode,
) -> Result<SyncSelection, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT conversation_id FROM sync_session_conversations \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND session_id=?4 \
             ORDER BY conversation_id",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session_id.as_opaque().as_str()
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut conversation_ids = Vec::new();
    for row in rows {
        conversation_ids.push(ConversationId::from_opaque(parse_id(
            &row.map_err(|error| map_sqlite_error(&error))?,
        )?));
    }
    Ok(SyncSelection {
        mode,
        conversation_ids,
    })
}

pub(super) fn load_session_from(
    connection: &Connection,
    scope: &TenantScope,
    session_id: &SessionId,
) -> Result<Option<SyncSession>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT source_endpoint_id, target_endpoint_id, link_kind, mode, state \
             FROM sync_sessions WHERE tenant_id=?1 AND namespace_present=?2 \
             AND namespace_id=?3 AND session_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((local, remote, link_kind, mode, state)) = row else {
        return Ok(None);
    };
    let mode = parse_mode(&mode)?;
    Ok(Some(SyncSession {
        session_id: session_id.clone(),
        scope: scope.clone(),
        source_endpoint_id: EndpointId::from_opaque(parse_id(&local)?),
        target_endpoint_id: EndpointId::from_opaque(parse_id(&remote)?),
        link_kind: parse_link_kind(&link_kind)?,
        selection: load_selection(connection, scope, session_id, mode)?,
        state: parse_state(&state)?,
    }))
}

fn load_latest_checkpoint_from(
    connection: &Connection,
    scope: &TenantScope,
    session_id: &SessionId,
) -> Result<Option<SyncCheckpoint>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT generation, resume_token, applied_items FROM sync_checkpoints \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND session_id=?4 \
             ORDER BY generation DESC LIMIT 1",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(generation, resume_token, applied_items)| {
            Ok(SyncCheckpoint {
                session_id: session_id.clone(),
                scope: scope.clone(),
                generation: decode_u64(generation)?,
                resume_token,
                applied_items: decode_u64(applied_items)?,
            })
        })
        .transpose()
}

fn validate_persisted_session(session: &SyncSession) -> Result<(), DurableStoreError> {
    let mut prepared = session.clone();
    prepared.state = SyncState::Prepared;
    let canonical = canonical_sync_session(prepared).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical.selection == session.selection {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

fn load_checkpoints_from(
    connection: &Connection,
    session: &SyncSession,
) -> Result<Vec<SyncCheckpoint>, DurableStoreError> {
    let namespace = namespace_storage_key(&session.scope);
    let mut statement = connection
        .prepare(
            "SELECT generation, resume_token, applied_items FROM sync_checkpoints \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND session_id=?4 \
             ORDER BY generation",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                session.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session.session_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut checkpoints = Vec::new();
    for row in rows {
        let (generation, resume_token, applied_items) =
            row.map_err(|error| map_sqlite_error(&error))?;
        checkpoints.push(SyncCheckpoint {
            session_id: session.session_id.clone(),
            scope: session.scope.clone(),
            generation: decode_u64(generation)?,
            resume_token,
            applied_items: decode_u64(applied_items)?,
        });
    }
    Ok(checkpoints)
}

fn verify_sync_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, session_id FROM sync_sessions")
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
        let (tenant, present, namespace, session_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        keys.push((
            parse_scope(&tenant, present, &namespace)?,
            SessionId::from_opaque(parse_id(&session_id)?),
        ));
    }
    drop(statement);

    for (scope, session_id) in keys {
        let session = load_session_from(connection, &scope, &session_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        validate_persisted_session(&session)?;
        let mut validation_session = session.clone();
        validation_session.state = SyncState::Active;
        let checkpoints = load_checkpoints_from(connection, &session)?;
        let mut previous: Option<&SyncCheckpoint> = None;
        for checkpoint in &checkpoints {
            validate_sync_checkpoint(&validation_session, previous, checkpoint)
                .map_err(|_| DurableStoreError::Corrupt)?;
            previous = Some(checkpoint);
        }
    }
    Ok(())
}

fn insert_selection(
    transaction: &Transaction<'_>,
    session: &SyncSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&session.scope);
    for conversation_id in &session.selection.conversation_ids {
        transaction
            .execute(
                "INSERT INTO sync_session_conversations (
                    tenant_id, namespace_present, namespace_id, session_id, conversation_id
                 ) VALUES (?1,?2,?3,?4,?5)",
                params![
                    session.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    session.session_id.as_opaque().as_str(),
                    conversation_id.as_opaque().as_str()
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn map_sync_checkpoint_error(error: SyncError) -> DurableStoreError {
    match error {
        SyncError::InvalidCheckpointGeneration | SyncError::AppliedItemsRegression => {
            DurableStoreError::Conflict
        }
        _ => DurableStoreError::InvalidRecord,
    }
}

impl SyncStore for SqliteLocalStore {
    fn create_sync_session(
        &self,
        session: &SyncSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_sync_session(session.clone())
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&canonical.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_session_from(&transaction, &canonical.scope, &canonical.session_id)?
        {
            return if existing == canonical {
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))?;
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        transaction
            .execute(
                "INSERT INTO sync_sessions (
                    tenant_id, namespace_present, namespace_id, session_id,
                    source_endpoint_id, target_endpoint_id, link_kind, mode, state
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    canonical.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    canonical.session_id.as_opaque().as_str(),
                    canonical.source_endpoint_id.as_opaque().as_str(),
                    canonical.target_endpoint_id.as_opaque().as_str(),
                    link_kind_name(canonical.link_kind),
                    mode_name(canonical.selection.mode),
                    state_name(canonical.state)
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        insert_selection(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn transition_sync(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        expected_state: SyncState,
        next_state: SyncState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_session_from(&transaction, scope, session_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.state != expected_state {
            return Err(DurableStoreError::Conflict);
        }
        if expected_state == next_state {
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(DurableRecordStatus::Duplicate);
        }
        validate_sync_transition(expected_state, next_state)
            .map_err(|_| DurableStoreError::Conflict)?;
        let updated = transaction
            .execute(
                "UPDATE sync_sessions SET state=?1 WHERE tenant_id=?2 AND namespace_present=?3 \
                 AND namespace_id=?4 AND session_id=?5 AND state=?6",
                params![
                    state_name(next_state),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    session_id.as_opaque().as_str(),
                    state_name(expected_state)
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if updated != 1 {
            return Err(DurableStoreError::Conflict);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn record_sync_checkpoint(
        &self,
        checkpoint: &SyncCheckpoint,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let namespace = namespace_storage_key(&checkpoint.scope);
        let generation = checkpoint.generation.to_be_bytes();
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let session = load_session_from(&transaction, &checkpoint.scope, &checkpoint.session_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let existing = transaction
            .query_row(
                "SELECT resume_token, applied_items FROM sync_checkpoints \
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 \
                 AND session_id=?4 AND generation=?5",
                params![
                    checkpoint.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    checkpoint.session_id.as_opaque().as_str(),
                    generation
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some((resume_token, applied_items)) = existing {
            let same = resume_token == checkpoint.resume_token
                && decode_u64(applied_items)? == checkpoint.applied_items;
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return if same {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let previous =
            load_latest_checkpoint_from(&transaction, &checkpoint.scope, &checkpoint.session_id)?;
        validate_sync_checkpoint(&session, previous.as_ref(), checkpoint)
            .map_err(map_sync_checkpoint_error)?;
        transaction
            .execute(
                "INSERT INTO sync_checkpoints (
                    tenant_id, namespace_present, namespace_id, session_id,
                    generation, resume_token, applied_items
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    checkpoint.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    checkpoint.session_id.as_opaque().as_str(),
                    generation,
                    checkpoint.resume_token,
                    checkpoint.applied_items.to_be_bytes()
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn sync_session(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncSession>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_session_from(&connection, scope, session_id)
    }

    fn latest_sync_checkpoint(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncCheckpoint>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_latest_checkpoint_from(&connection, scope, session_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use rusqlite::{Connection, params};
    use ucr_core::{
        ConversationStore, DurableRecordStatus, DurableStoreError, MessageStore, StorageProvider,
        SyncStore,
    };
    use ucr_model::{
        ConversationId, EndpointId, OpaqueId, SessionId, SyncCheckpoint, SyncLinkKind, SyncMode,
        SyncSelection, SyncSession, SyncState,
    };

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, conversation, message, scope};
    use crate::{SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn session(id: &str) -> SyncSession {
        SyncSession {
            session_id: SessionId::from_opaque(oid(id)),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid("sync-local")),
            target_endpoint_id: EndpointId::from_opaque(oid("sync-remote")),
            link_kind: SyncLinkKind::DeviceDevice,
            selection: SyncSelection {
                mode: SyncMode::Partial,
                conversation_ids: vec![
                    ConversationId::from_opaque(oid("conversation-b")),
                    ConversationId::from_opaque(oid("conversation-a")),
                ],
            },
            state: SyncState::Prepared,
        }
    }

    fn checkpoint(session: &SyncSession, generation: u64, applied_items: u64) -> SyncCheckpoint {
        SyncCheckpoint {
            session_id: session.session_id.clone(),
            scope: session.scope.clone(),
            generation,
            resume_token: format!("resume-{generation}").into_bytes(),
            applied_items,
        }
    }

    #[test]
    fn sync_session_checkpoint_pause_and_resume_survive_restart() {
        let db = TestDb::new();
        let session = session("sync-restart");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.create_sync_session(&session),
                Ok(DurableRecordStatus::Persisted)
            );
            store
                .transition_sync(
                    &session.scope,
                    &session.session_id,
                    SyncState::Prepared,
                    SyncState::Active,
                )
                .expect("activate");
            let mut active = store
                .sync_session(&session.scope, &session.session_id)
                .expect("load")
                .expect("exists");
            store
                .record_sync_checkpoint(&checkpoint(&active, 1, 4))
                .expect("checkpoint");
            store
                .transition_sync(
                    &session.scope,
                    &session.session_id,
                    SyncState::Active,
                    SyncState::Paused,
                )
                .expect("pause");
            active.state = SyncState::Paused;
            store
                .record_sync_checkpoint(&checkpoint(&active, 2, 9))
                .expect("paused checkpoint");
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        let loaded = reopened
            .sync_session(&session.scope, &session.session_id)
            .expect("load")
            .expect("exists");
        assert_eq!(loaded.state, SyncState::Paused);
        assert_eq!(
            loaded.selection.conversation_ids[0].as_opaque().as_str(),
            "conversation-a"
        );
        let latest = reopened
            .latest_sync_checkpoint(&session.scope, &session.session_id)
            .expect("load checkpoint")
            .expect("checkpoint exists");
        assert_eq!(latest.generation, 2);
        assert_eq!(latest.applied_items, 9);
        assert_eq!(
            reopened.transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Paused,
                SyncState::Active,
            ),
            Ok(DurableRecordStatus::Persisted)
        );
    }

    #[test]
    fn concurrent_sync_activation_has_single_winner() {
        let db = TestDb::new();
        let session = session("sync-race");
        SqliteLocalStore::open(db.path())
            .expect("open")
            .create_sync_session(&session)
            .expect("create");
        let barrier = Arc::new(Barrier::new(3));
        let path = db.path().to_path_buf();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                let scope = session.scope.clone();
                let session_id = session.session_id.clone();
                std::thread::spawn(move || {
                    let store = SqliteLocalStore::open(path).expect("thread store");
                    barrier.wait();
                    store.transition_sync(
                        &scope,
                        &session_id,
                        SyncState::Prepared,
                        SyncState::Active,
                    )
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(DurableRecordStatus::Persisted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(DurableStoreError::Conflict))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_checkpoint_generation_has_single_winner() {
        let db = TestDb::new();
        let session = session("sync-checkpoint-race");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store.create_sync_session(&session).expect("create");
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate");
        drop(store);

        let barrier = Arc::new(Barrier::new(3));
        let path = db.path().to_path_buf();
        let handles: Vec<_> = [b"resume-a".to_vec(), b"resume-b".to_vec()]
            .into_iter()
            .map(|resume_token| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                let session = session.clone();
                std::thread::spawn(move || {
                    let store = SqliteLocalStore::open(path).expect("thread store");
                    let mut checkpoint = checkpoint(&session, 1, 5);
                    checkpoint.resume_token = resume_token;
                    barrier.wait();
                    store.record_sync_checkpoint(&checkpoint)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(DurableRecordStatus::Persisted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(DurableStoreError::Conflict))
                .count(),
            1
        );
    }

    #[test]
    fn v6_store_migrates_to_v7_without_losing_message_state() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize v7");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
            store
                .persist_message(&message(b"before-v7"))
                .expect("persist message");
        }
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute_batch(
                "DROP TABLE permission_grants; DROP TABLE trusted_signing_keys;
                 DROP TABLE message_extensions;
                 DROP TABLE command_extensions;
                 DROP TABLE command_protocol_metadata;
                 DROP TABLE event_extensions;
                 DROP TABLE sync_checkpoints;
                 DROP TABLE sync_session_conversations;
                 DROP TABLE sync_sessions;",
            )
            .expect("remove v7 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", 6_u32)
            .expect("set v6");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v6 to v7");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let loaded = migrated
            .message(&scope(), &message(b"before-v7").message_id)
            .expect("load message")
            .expect("message preserved");
        assert_eq!(loaded.content, b"before-v7");
    }

    #[test]
    fn checkpoint_generation_gap_is_rejected_on_reopen() {
        let db = TestDb::new();
        let session = session("sync-gap");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.create_sync_session(&session).expect("create");
            store
                .transition_sync(
                    &session.scope,
                    &session.session_id,
                    SyncState::Prepared,
                    SyncState::Active,
                )
                .expect("activate");
        }
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        let namespace = super::namespace_storage_key(&session.scope);
        connection
            .execute(
                "INSERT INTO sync_checkpoints (
                    tenant_id, namespace_present, namespace_id, session_id,
                    generation, resume_token, applied_items
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    session.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    session.session_id.as_opaque().as_str(),
                    2_u64.to_be_bytes(),
                    b"resume-gap",
                    5_u64.to_be_bytes()
                ],
            )
            .expect("inject generation gap");
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
    }

    #[test]
    fn corrupt_partial_sync_selection_is_rejected_on_reopen() {
        let db = TestDb::new();
        let mut full = session("sync-corrupt");
        full.selection.mode = SyncMode::Full;
        full.selection.conversation_ids.clear();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.create_sync_session(&full).expect("create full sync");
        }
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        let namespace = super::namespace_storage_key(&full.scope);
        connection
            .execute(
                "INSERT INTO sync_session_conversations (
                    tenant_id, namespace_present, namespace_id, session_id, conversation_id
                 ) VALUES (?1,?2,?3,?4,?5)",
                params![
                    full.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    full.session_id.as_opaque().as_str(),
                    "conversation-illegal"
                ],
            )
            .expect("inject corrupt selection");
        drop(connection);
        assert_eq!(
            SqliteLocalStore::open(db.path()).err(),
            Some(DurableStoreError::Corrupt)
        );
    }
}
