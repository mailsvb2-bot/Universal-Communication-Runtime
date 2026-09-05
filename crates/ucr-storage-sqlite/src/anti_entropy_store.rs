use std::collections::HashSet;

use rusqlite::params;
use ucr_core::{AntiEntropyStore, DurableStoreError, EventAppendStatus};
use ucr_model::{
    AntiEntropyCursor, AntiEntropyPage, EventEnvelope, EventId, EventReconciliation,
    EventReplicaState, EventSummary, OpaqueId, SessionId, SyncSession, TenantScope,
};
use ucr_protocol::{
    AntiEntropyError, anti_entropy_session_binding, canonical_event, event_fingerprint,
    validate_anti_entropy_cursor, validate_anti_entropy_page_size, validate_anti_entropy_session,
    validate_anti_entropy_summary_count,
};

use super::{SqliteLocalStore, event_journal, map_sqlite_error, namespace_storage_key, sync_store};

const SQLITE_CURSOR_VERSION: u8 = 1;
const SQLITE_CURSOR_LEN: usize = 1 + 32 + 8 + 8;

fn map_anti_entropy_error(_error: AntiEntropyError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

fn load_session(
    connection: &rusqlite::Connection,
    scope: &TenantScope,
    session_id: &SessionId,
) -> Result<SyncSession, DurableStoreError> {
    let session = sync_store::load_session_from(connection, scope, session_id)?
        .ok_or(DurableStoreError::InvalidRecord)?;
    validate_anti_entropy_session(&session).map_err(map_anti_entropy_error)?;
    Ok(session)
}

fn encode_cursor(session: &SyncSession, snapshot: u64, position: u64) -> AntiEntropyCursor {
    let mut token = Vec::with_capacity(SQLITE_CURSOR_LEN);
    token.push(SQLITE_CURSOR_VERSION);
    token.extend_from_slice(&anti_entropy_session_binding(session));
    token.extend_from_slice(&snapshot.to_be_bytes());
    token.extend_from_slice(&position.to_be_bytes());
    AntiEntropyCursor { token }
}

fn decode_cursor(
    session: &SyncSession,
    cursor: &AntiEntropyCursor,
) -> Result<(u64, u64), DurableStoreError> {
    validate_anti_entropy_cursor(&cursor.token).map_err(map_anti_entropy_error)?;
    if cursor.token.len() != SQLITE_CURSOR_LEN || cursor.token[0] != SQLITE_CURSOR_VERSION {
        return Err(DurableStoreError::InvalidRecord);
    }
    if cursor.token[1..33] != anti_entropy_session_binding(session) {
        return Err(DurableStoreError::InvalidRecord);
    }
    let snapshot = u64::from_be_bytes(
        cursor.token[33..41]
            .try_into()
            .map_err(|_| DurableStoreError::InvalidRecord)?,
    );
    let position = u64::from_be_bytes(
        cursor.token[41..49]
            .try_into()
            .map_err(|_| DurableStoreError::InvalidRecord)?,
    );
    if position > snapshot {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok((snapshot, position))
}

fn to_sql_seq(value: u64) -> Result<i64, DurableStoreError> {
    i64::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn from_sql_seq(value: i64) -> Result<u64, DurableStoreError> {
    u64::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn snapshot_boundary(
    connection: &rusqlite::Connection,
    scope: &TenantScope,
) -> Result<u64, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value: Option<i64> = connection
        .query_row(
            "SELECT MAX(journal_seq) FROM events
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    value.map_or(Ok(0), from_sql_seq)
}

impl AntiEntropyStore for SqliteLocalStore {
    fn anti_entropy_summary_page(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        cursor: Option<&AntiEntropyCursor>,
        max_items: usize,
    ) -> Result<AntiEntropyPage, DurableStoreError> {
        validate_anti_entropy_page_size(max_items).map_err(map_anti_entropy_error)?;
        let connection = self.lock_connection()?;
        let session = load_session(&connection, scope, session_id)?;
        let current_boundary = snapshot_boundary(&connection, scope)?;
        let (snapshot, position) = match cursor {
            Some(cursor) => decode_cursor(&session, cursor)?,
            None => (current_boundary, 0),
        };
        if snapshot > current_boundary {
            return Err(DurableStoreError::Corrupt);
        }
        let namespace = namespace_storage_key(scope);
        let limit = i64::try_from(
            max_items
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidRecord)?,
        )
        .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut statement = connection
            .prepare(
                "SELECT journal_seq, event_id FROM events
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND journal_seq>?4 AND journal_seq<=?5
                 ORDER BY journal_seq LIMIT ?6",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    to_sql_seq(position)?,
                    to_sql_seq(snapshot)?,
                    limit
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|error| map_sqlite_error(&error))?);
        }
        drop(statement);
        let has_more = entries.len() > max_items;
        if has_more {
            entries.truncate(max_items);
        }
        let mut summaries = Vec::with_capacity(entries.len());
        let mut last_position = position;
        for (sequence, event_id) in entries {
            last_position = from_sql_seq(sequence)?;
            let event_id = EventId::from_opaque(
                OpaqueId::new(event_id).map_err(|_| DurableStoreError::Corrupt)?,
            );
            let event = event_journal::load_event_by_id(&connection, scope, &event_id)?
                .ok_or(DurableStoreError::Corrupt)?;
            summaries.push(EventSummary {
                event_id,
                fingerprint: event_fingerprint(&event).map_err(|_| DurableStoreError::Corrupt)?,
            });
        }
        let next_cursor = has_more.then(|| encode_cursor(&session, snapshot, last_position));
        Ok(AntiEntropyPage {
            session_id: session.session_id,
            scope: session.scope,
            summaries,
            next_cursor,
        })
    }

    fn classify_event_summaries(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        summaries: &[EventSummary],
    ) -> Result<Vec<EventReconciliation>, DurableStoreError> {
        validate_anti_entropy_summary_count(summaries.len()).map_err(map_anti_entropy_error)?;
        let connection = self.lock_connection()?;
        let _session = load_session(&connection, scope, session_id)?;
        let mut seen = HashSet::with_capacity(summaries.len());
        let mut result = Vec::with_capacity(summaries.len());
        for summary in summaries {
            if !seen.insert(summary.event_id.clone()) {
                return Err(DurableStoreError::InvalidRecord);
            }
            let state =
                match event_journal::load_event_by_id(&connection, scope, &summary.event_id)? {
                    None => EventReplicaState::Missing,
                    Some(local) => {
                        if event_fingerprint(&local).map_err(|_| DurableStoreError::Corrupt)?
                            == summary.fingerprint
                        {
                            EventReplicaState::Matching
                        } else {
                            EventReplicaState::Damaged
                        }
                    }
                };
            result.push(EventReconciliation {
                event_id: summary.event_id.clone(),
                state,
            });
        }
        Ok(result)
    }

    fn reconcile_event(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError> {
        let event = canonical_event(event).map_err(|_| DurableStoreError::InvalidRecord)?;
        if &event.scope != scope {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let session = sync_store::load_session_from(&transaction, scope, session_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        validate_anti_entropy_session(&session).map_err(map_anti_entropy_error)?;
        if let Some(local) = event_journal::load_event_by_id(&transaction, scope, &event.event_id)?
        {
            return if event_fingerprint(&local).map_err(|_| DurableStoreError::Corrupt)?
                == event_fingerprint(&event).map_err(|_| DurableStoreError::InvalidRecord)?
            {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let status = event_journal::append_event_in_transaction(&transaction, &event)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use ucr_core::{
        AntiEntropyStore, DurableStoreError, EventAppendStatus, EventJournalStore, StorageProvider,
        SyncStore,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EndpointId,
        EventEnvelope, EventFingerprint, EventFingerprintAlgorithm, EventId, EventReplicaState,
        EventSummary, IdentityId, OpaqueId, ProtocolExtension, ProtocolVersion, SessionId,
        SyncLinkKind, SyncMode, SyncSelection, SyncSession, SyncState,
    };

    use super::SqliteLocalStore;
    use crate::SQLITE_SCHEMA_VERSION;
    use crate::event_journal::load_event_by_id;
    use crate::message_store::tests::{TestDb, scope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn session(id: &str, target: &str, mode: SyncMode) -> SyncSession {
        SyncSession {
            session_id: SessionId::from_opaque(oid(id)),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid("endpoint-source")),
            target_endpoint_id: EndpointId::from_opaque(oid(target)),
            link_kind: SyncLinkKind::DeviceDevice,
            selection: SyncSelection {
                mode,
                conversation_ids: if mode == SyncMode::Partial {
                    vec![ucr_model::ConversationId::from_opaque(oid(
                        "conversation-a",
                    ))]
                } else {
                    Vec::new()
                },
            },
            state: SyncState::Prepared,
        }
    }

    fn activate(store: &SqliteLocalStore, session: &SyncSession) {
        store.create_sync_session(session).expect("create session");
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate session");
    }

    fn event(id: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.test.event".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn sqlite_snapshot_resume_excludes_mid_pass_event_until_next_pass() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        let sync = session("sync-a", "endpoint-target", SyncMode::Full);
        activate(&store, &sync);
        store
            .append_event(&event("event-a", b"a"))
            .expect("event a");
        store
            .append_event(&event("event-b", b"b"))
            .expect("event b");
        let first = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 1)
            .expect("page one");
        let cursor = first.next_cursor.expect("cursor");
        store
            .append_event(&event("event-c", b"c"))
            .expect("event c");
        let resumed = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, Some(&cursor), 8)
            .expect("resume");
        assert_eq!(resumed.summaries.len(), 1);
        assert_eq!(
            resumed.summaries[0].event_id.as_opaque().as_str(),
            "event-b"
        );
        assert!(resumed.next_cursor.is_none());
        let next = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 8)
            .expect("next pass");
        assert_eq!(next.summaries.len(), 3);
        assert_eq!(next.summaries[2].event_id.as_opaque().as_str(), "event-c");
    }

    #[test]
    fn sqlite_reconciliation_classifies_and_never_overwrites_damaged_event() {
        let source_db = TestDb::new();
        let target_db = TestDb::new();
        let source = SqliteLocalStore::open(source_db.path()).expect("source");
        let target = SqliteLocalStore::open(target_db.path()).expect("target");
        let sync = session("sync-a", "endpoint-target", SyncMode::Full);
        activate(&source, &sync);
        activate(&target, &sync);
        let matching = event("event-a", b"same");
        let damaged_source = event("event-b", b"source");
        let missing = event("event-c", b"missing");
        for value in [&matching, &damaged_source, &missing] {
            source.append_event(value).expect("source event");
        }
        target.append_event(&matching).expect("matching");
        target
            .append_event(&event("event-b", b"different-local"))
            .expect("damaged local");
        let page = source
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 8)
            .expect("summaries");
        let states = target
            .classify_event_summaries(&sync.scope, &sync.session_id, &page.summaries)
            .expect("classify");
        assert_eq!(states[0].state, EventReplicaState::Matching);
        assert_eq!(states[1].state, EventReplicaState::Damaged);
        assert_eq!(states[2].state, EventReplicaState::Missing);
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &matching),
            Ok(EventAppendStatus::Duplicate)
        );
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &damaged_source),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &missing),
            Ok(EventAppendStatus::Appended)
        );
    }

    #[test]
    fn sqlite_cursor_binding_partial_fail_closed_and_extensions_round_trip() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        let first = session("sync-a", "endpoint-target-a", SyncMode::Full);
        let second = session("sync-b", "endpoint-target-b", SyncMode::Full);
        let partial = session("sync-partial", "endpoint-target-c", SyncMode::Partial);
        activate(&store, &first);
        activate(&store, &second);
        activate(&store, &partial);
        let mut value = event("event-ext", b"payload");
        value.extensions = vec![
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
        store.append_event(&value).expect("extension event");
        store
            .append_event(&event("event-b", b"b"))
            .expect("event b");
        let cursor = store
            .anti_entropy_summary_page(&first.scope, &first.session_id, None, 1)
            .expect("page")
            .next_cursor
            .expect("cursor");
        assert_eq!(
            store.anti_entropy_summary_page(&second.scope, &second.session_id, Some(&cursor), 1),
            Err(DurableStoreError::InvalidRecord)
        );
        let oversized = vec![
            EventSummary {
                event_id: EventId::from_opaque(oid("event-summary")),
                fingerprint: EventFingerprint {
                    algorithm: EventFingerprintAlgorithm::Sha256V1,
                    digest: [0; 32],
                },
            };
            ucr_protocol::MAX_ANTI_ENTROPY_PAGE_ITEMS + 1
        ];
        assert_eq!(
            store.classify_event_summaries(&first.scope, &first.session_id, &oversized),
            Err(DurableStoreError::InvalidRecord)
        );
        assert_eq!(
            store.anti_entropy_summary_page(&partial.scope, &partial.session_id, None, 1),
            Err(DurableStoreError::InvalidRecord)
        );
        let connection = store.lock_connection().expect("lock");
        let loaded = load_event_by_id(&connection, &value.scope, &value.event_id)
            .expect("load")
            .expect("exists");
        assert_eq!(loaded.extensions.len(), 2);
        assert_eq!(loaded.extensions[0].name, "ucr.example.a");
        assert_eq!(loaded.extensions[1].payload, b"z");
    }

    #[test]
    fn v7_to_v8_migration_preserves_existing_events_as_empty_extensions() {
        let db = TestDb::new();
        let value = event("event-pre-v8", b"legacy");
        {
            let store = SqliteLocalStore::open(db.path()).expect("create v8");
            store
                .append_event(&value)
                .expect("persist legacy-shaped event");
        }
        {
            let connection = Connection::open(db.path()).expect("raw open");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF; DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices; DROP TRIGGER service_audit_no_update; DROP TRIGGER service_audit_no_delete; DROP INDEX service_audit_scope_sequence; DROP TABLE service_audit_records; DROP TABLE service_quota_usage; DROP TABLE service_quota_policies; DROP TABLE service_credentials; DROP TABLE permission_grants; DROP TABLE trusted_signing_keys; DROP TABLE message_extensions; DROP TABLE command_extensions; DROP TABLE command_protocol_metadata; DROP TABLE event_extensions; PRAGMA user_version=7;",
                )
                .expect("simulate exact v7 shape");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v7 to v8");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let connection = migrated.lock_connection().expect("lock");
        let loaded = load_event_by_id(&connection, &value.scope, &value.event_id)
            .expect("load")
            .expect("exists");
        assert!(loaded.extensions.is_empty());
        assert_eq!(loaded.payload, b"legacy");
    }
}
