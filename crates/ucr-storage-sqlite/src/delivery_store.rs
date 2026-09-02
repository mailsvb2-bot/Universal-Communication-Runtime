use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DeliveryStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryId, DeliveryState, MessageId,
    OpaqueId, TenantId, TenantScope,
};
use ucr_protocol::{
    validate_delivery_attempt, validate_delivery_evidence, validate_delivery_evidence_binding,
    validate_delivery_evidence_order, validate_delivery_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

pub(super) const V6_OBJECTS_SQL: &str = "
CREATE TABLE delivery_attempts (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, delivery_id),    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> '')),
    CHECK(state IN ('persisted','encrypted','queued','route_planned','in_flight',
                    'acknowledged','delivered','read','failed','expired'))
) WITHOUT ROWID;

CREATE TABLE delivery_evidence (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    logical_order BLOB NOT NULL CHECK(length(logical_order) = 8),
    message_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, delivery_id, logical_order),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, delivery_id)
      REFERENCES delivery_attempts(tenant_id, namespace_present, namespace_id, delivery_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";
pub(super) fn create_v6_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V6_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v6(connection: &Connection) -> Result<(), DurableStoreError> {
    super::message_store::verify_schema_v5(connection)?;
    verify_table_columns(
        connection,
        "delivery_attempts",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("delivery_id", "TEXT", 1, 4),
            ("message_id", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "delivery_evidence",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("delivery_id", "TEXT", 1, 4),
            ("logical_order", "BLOB", 1, 5),
            ("message_id", "TEXT", 1, 0),
            ("kind", "TEXT", 1, 0),
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
    verify_delivery_rows(connection)
}

fn verify_delivery_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, delivery_id, message_id, state FROM delivery_attempts")
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut attempts = Vec::new();
    for row in rows {
        let (tenant, present, namespace, delivery, message, state) =
            row.map_err(|error| map_sqlite_error(&error))?;
        attempts.push(DeliveryAttempt {
            delivery_id: DeliveryId::from_opaque(parse_id(&delivery)?),
            scope: parse_scope(&tenant, present, &namespace)?,
            message_id: MessageId::from_opaque(parse_id(&message)?),
            state: parse_delivery_state(&state)?,
        });
    }
    drop(statement);
    for attempt in attempts {
        verify_evidence_for_attempt(connection, &attempt)?;
    }
    Ok(())
}

fn verify_evidence_for_attempt(
    connection: &Connection,
    attempt: &DeliveryAttempt,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&attempt.scope);
    let mut statement = connection
        .prepare("SELECT logical_order, message_id, kind FROM delivery_evidence WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND delivery_id=?4 ORDER BY logical_order")
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                attempt.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attempt.delivery_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut saw_any = false;
    for (index, row) in rows.enumerate() {
        let (order, message, kind) = row.map_err(|error| map_sqlite_error(&error))?;
        let bytes: [u8; 8] = order.try_into().map_err(|_| DurableStoreError::Corrupt)?;
        let evidence = DeliveryEvidence {
            delivery_id: attempt.delivery_id.clone(),
            scope: attempt.scope.clone(),
            message_id: MessageId::from_opaque(parse_id(&message)?),
            kind: parse_evidence_kind(&kind)?,
            logical_order: u64::from_be_bytes(bytes),
        };
        validate_delivery_evidence_binding(attempt, &evidence)
            .map_err(|_| DurableStoreError::Corrupt)?;
        if index == 0 && evidence.kind != DeliveryEvidenceKind::PersistedLocal {
            return Err(DurableStoreError::Corrupt);
        }
        saw_any = true;
    }
    if saw_any {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

fn delivery_state_name(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Persisted => "persisted",
        DeliveryState::Encrypted => "encrypted",
        DeliveryState::Queued => "queued",
        DeliveryState::RoutePlanned => "route_planned",
        DeliveryState::InFlight => "in_flight",
        DeliveryState::Acknowledged => "acknowledged",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Read => "read",
        DeliveryState::Failed => "failed",
        DeliveryState::Expired => "expired",
        DeliveryState::Created => "created",
    }
}

fn parse_delivery_state(value: &str) -> Result<DeliveryState, DurableStoreError> {
    match value {
        "persisted" => Ok(DeliveryState::Persisted),
        "encrypted" => Ok(DeliveryState::Encrypted),
        "queued" => Ok(DeliveryState::Queued),
        "route_planned" => Ok(DeliveryState::RoutePlanned),
        "in_flight" => Ok(DeliveryState::InFlight),
        "acknowledged" => Ok(DeliveryState::Acknowledged),
        "delivered" => Ok(DeliveryState::Delivered),
        "read" => Ok(DeliveryState::Read),
        "failed" => Ok(DeliveryState::Failed),
        "expired" => Ok(DeliveryState::Expired),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn evidence_kind_name(kind: DeliveryEvidenceKind) -> &'static str {
    match kind {
        DeliveryEvidenceKind::CreatedLocal => "created_local",
        DeliveryEvidenceKind::PersistedLocal => "persisted_local",
        DeliveryEvidenceKind::AcceptedByTransport => "accepted_by_transport",
        DeliveryEvidenceKind::ReplicatedToRelay => "replicated_to_relay",
        DeliveryEvidenceKind::ReceivedByDevice => "received_by_device",
        DeliveryEvidenceKind::DecryptedByDevice => "decrypted_by_device",
        DeliveryEvidenceKind::PresentedToUser => "presented_to_user",
        DeliveryEvidenceKind::ReadByUser => "read_by_user",
    }
}

fn parse_evidence_kind(value: &str) -> Result<DeliveryEvidenceKind, DurableStoreError> {
    match value {
        "created_local" => Ok(DeliveryEvidenceKind::CreatedLocal),
        "persisted_local" => Ok(DeliveryEvidenceKind::PersistedLocal),
        "accepted_by_transport" => Ok(DeliveryEvidenceKind::AcceptedByTransport),
        "replicated_to_relay" => Ok(DeliveryEvidenceKind::ReplicatedToRelay),
        "received_by_device" => Ok(DeliveryEvidenceKind::ReceivedByDevice),
        "decrypted_by_device" => Ok(DeliveryEvidenceKind::DecryptedByDevice),
        "presented_to_user" => Ok(DeliveryEvidenceKind::PresentedToUser),
        "read_by_user" => Ok(DeliveryEvidenceKind::ReadByUser),
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
        (1, false) => Some(ucr_model::NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}
fn load_attempt_from(
    connection: &Connection,
    scope: &TenantScope,
    delivery_id: &DeliveryId,
) -> Result<Option<DeliveryAttempt>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT message_id, state FROM delivery_attempts \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND delivery_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                delivery_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(message, state)| {
            Ok(DeliveryAttempt {
                delivery_id: delivery_id.clone(),
                scope: scope.clone(),
                message_id: MessageId::from_opaque(parse_id(&message)?),
                state: parse_delivery_state(&state)?,
            })
        })
        .transpose()
}
fn append_evidence(
    transaction: &Transaction<'_>,
    attempt: &DeliveryAttempt,
    evidence: &DeliveryEvidence,
) -> Result<DurableRecordStatus, DurableStoreError> {
    validate_delivery_evidence_binding(attempt, evidence)
        .map_err(|_| DurableStoreError::InvalidRecord)?;
    let namespace = namespace_storage_key(&attempt.scope);
    let order = evidence.logical_order.to_be_bytes();
    let existing = transaction
        .query_row(
            "SELECT message_id, kind FROM delivery_evidence \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 \
             AND delivery_id=?4 AND logical_order=?5",
            params![
                attempt.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attempt.delivery_id.as_opaque().as_str(),
                order,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    if let Some((message_id, kind)) = existing {
        return if message_id == evidence.message_id.as_opaque().as_str()
            && parse_evidence_kind(&kind)? == evidence.kind
        {
            Ok(DurableRecordStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    let latest: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT logical_order FROM delivery_evidence \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND delivery_id=?4 \
             ORDER BY logical_order DESC LIMIT 1",
            params![
                attempt.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attempt.delivery_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let previous_order = latest
        .map(|latest| {
            let bytes: [u8; 8] = latest.try_into().map_err(|_| DurableStoreError::Corrupt)?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()?;
    validate_delivery_evidence_order(previous_order, evidence.logical_order)
        .map_err(|_| DurableStoreError::Conflict)?;
    transaction
        .execute(
            "INSERT INTO delivery_evidence (
                tenant_id, namespace_present, namespace_id, delivery_id,
                logical_order, message_id, kind
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                attempt.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attempt.delivery_id.as_opaque().as_str(),
                order,
                evidence.message_id.as_opaque().as_str(),
                evidence_kind_name(evidence.kind),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(DurableRecordStatus::Persisted)
}
impl DeliveryStore for SqliteLocalStore {
    fn create_delivery_attempt(
        &self,
        attempt: &DeliveryAttempt,
        persisted_evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_delivery_attempt(attempt).map_err(|_| DurableStoreError::InvalidRecord)?;
        validate_delivery_evidence(attempt, persisted_evidence, DeliveryState::Persisted)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&attempt.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let message_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE tenant_id=?1 AND namespace_present=?2 \
                 AND namespace_id=?3 AND message_id=?4 AND delivery_state='persisted')",
                params![
                    attempt.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    attempt.message_id.as_opaque().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if !message_exists {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing) =
            load_attempt_from(&transaction, &attempt.scope, &attempt.delivery_id)?
        {
            if existing != *attempt {
                return Err(DurableStoreError::Conflict);
            }
            let status = append_evidence(&transaction, &existing, persisted_evidence)?;
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return match status {
                DurableRecordStatus::Duplicate => Ok(DurableRecordStatus::Duplicate),
                DurableRecordStatus::Persisted => Err(DurableStoreError::Conflict),
            };
        }
        transaction
            .execute(
                "INSERT INTO delivery_attempts (
                    tenant_id, namespace_present, namespace_id, delivery_id, message_id, state
                 ) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    attempt.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    attempt.delivery_id.as_opaque().as_str(),
                    attempt.message_id.as_opaque().as_str(),
                    delivery_state_name(attempt.state)
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        append_evidence(&transaction, attempt, persisted_evidence)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
    fn transition_delivery(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
        expected_state: DeliveryState,
        next_state: DeliveryState,
        evidence: Option<&DeliveryEvidence>,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_attempt_from(&transaction, scope, delivery_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.state != expected_state {
            return Err(DurableStoreError::Conflict);
        }
        validate_delivery_transition(&current, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let proof_required = matches!(
            next_state,
            DeliveryState::Acknowledged | DeliveryState::Delivered | DeliveryState::Read
        );
        if proof_required && evidence.is_none() {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(evidence) = evidence {
            validate_delivery_evidence(&current, evidence, next_state)
                .map_err(|_| DurableStoreError::InvalidRecord)?;
            append_evidence(&transaction, &current, evidence)?;
        }
        let namespace = namespace_storage_key(scope);
        let updated = transaction
            .execute(
                "UPDATE delivery_attempts SET state=?5 WHERE tenant_id=?1 AND namespace_present=?2 \
                 AND namespace_id=?3 AND delivery_id=?4 AND state=?6",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    delivery_id.as_opaque().as_str(),
                    delivery_state_name(next_state),
                    delivery_state_name(expected_state)
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

    fn record_delivery_evidence(
        &self,
        evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_attempt_from(&transaction, &evidence.scope, &evidence.delivery_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let status = append_evidence(&transaction, &current, evidence)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }

    fn delivery_attempt(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_attempt_from(&connection, scope, delivery_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use rusqlite::Connection;
    use ucr_core::{
        ConversationStore, DeliveryStore, DurableRecordStatus, DurableStoreError, MessageStore,
        StorageProvider,
    };
    use ucr_model::{
        DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryId, DeliveryState,
        OpaqueId,
    };

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, conversation, message, scope};
    use crate::{SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn attempt(id: &str) -> DeliveryAttempt {
        DeliveryAttempt {
            delivery_id: DeliveryId::from_opaque(oid(id)),
            scope: scope(),
            message_id: message(b"delivery-message").message_id,
            state: DeliveryState::Persisted,
        }
    }

    fn evidence(
        attempt: &DeliveryAttempt,
        kind: DeliveryEvidenceKind,
        logical_order: u64,
    ) -> DeliveryEvidence {
        DeliveryEvidence {
            delivery_id: attempt.delivery_id.clone(),
            scope: attempt.scope.clone(),
            message_id: attempt.message_id.clone(),
            kind,
            logical_order,
        }
    }

    fn seed_message(store: &SqliteLocalStore) {
        store
            .persist_conversation(&conversation())
            .expect("conversation");
        store
            .persist_message(&message(b"delivery-message"))
            .expect("message");
    }
    fn advance_to_in_flight(store: &SqliteLocalStore, attempt: &DeliveryAttempt) {
        for (from, to) in [
            (DeliveryState::Persisted, DeliveryState::Encrypted),
            (DeliveryState::Encrypted, DeliveryState::Queued),
            (DeliveryState::Queued, DeliveryState::RoutePlanned),
            (DeliveryState::RoutePlanned, DeliveryState::InFlight),
        ] {
            assert_eq!(
                store.transition_delivery(&attempt.scope, &attempt.delivery_id, from, to, None),
                Ok(DurableRecordStatus::Persisted)
            );
        }
    }

    #[test]
    fn delivery_transition_chain_survives_restart_with_evidence() {
        let db = TestDb::new();
        let attempt = attempt("delivery-restart");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            seed_message(&store);
            assert_eq!(
                store.create_delivery_attempt(
                    &attempt,
                    &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1)
                ),
                Ok(DurableRecordStatus::Persisted)
            );
            advance_to_in_flight(&store, &attempt);
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let loaded = reopened
            .delivery_attempt(&attempt.scope, &attempt.delivery_id)
            .expect("load attempt")
            .expect("attempt exists");
        assert_eq!(loaded.state, DeliveryState::InFlight);
        let ack = evidence(&attempt, DeliveryEvidenceKind::AcceptedByTransport, 2);
        assert_eq!(
            reopened.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                DeliveryState::InFlight,
                DeliveryState::Acknowledged,
                Some(&ack),
            ),
            Ok(DurableRecordStatus::Persisted)
        );
        let relay = evidence(&attempt, DeliveryEvidenceKind::ReplicatedToRelay, 3);
        assert_eq!(
            reopened.record_delivery_evidence(&relay),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            reopened
                .delivery_attempt(&attempt.scope, &attempt.delivery_id)
                .expect("load")
                .expect("exists")
                .state,
            DeliveryState::Acknowledged
        );
        let delivered = evidence(&attempt, DeliveryEvidenceKind::ReceivedByDevice, 4);
        assert_eq!(
            reopened.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                DeliveryState::Acknowledged,
                DeliveryState::Delivered,
                Some(&delivered),
            ),
            Ok(DurableRecordStatus::Persisted)
        );
        let read = evidence(&attempt, DeliveryEvidenceKind::ReadByUser, 5);
        assert_eq!(
            reopened.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                DeliveryState::Delivered,
                DeliveryState::Read,
                Some(&read),
            ),
            Ok(DurableRecordStatus::Persisted)
        );
        drop(reopened);
        let final_store = SqliteLocalStore::open(db.path()).expect("final reopen");
        assert_eq!(
            final_store
                .delivery_attempt(&attempt.scope, &attempt.delivery_id)
                .expect("load")
                .expect("exists")
                .state,
            DeliveryState::Read
        );
    }
    #[test]
    fn concurrent_ack_transition_has_single_winner() {
        let db = TestDb::new();
        let attempt = attempt("delivery-race");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            seed_message(&store);
            store
                .create_delivery_attempt(
                    &attempt,
                    &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1),
                )
                .expect("create attempt");
            advance_to_in_flight(&store, &attempt);
        }
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |order| {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            let attempt = attempt.clone();
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                let proof = evidence(&attempt, DeliveryEvidenceKind::AcceptedByTransport, order);
                barrier.wait();
                store.transition_delivery(
                    &attempt.scope,
                    &attempt.delivery_id,
                    DeliveryState::InFlight,
                    DeliveryState::Acknowledged,
                    Some(&proof),
                )
            })
        };
        let first = spawn(2);
        let second = spawn(3);
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(DurableRecordStatus::Persisted)))
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
    fn v5_store_migrates_to_v6_without_losing_message_state() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize v6");
            seed_message(&store);
        }
        let connection = Connection::open(db.path()).expect("raw sqlite");
        connection
            .execute_batch("DROP TABLE event_extensions;
                 DROP TABLE sync_checkpoints; DROP TABLE sync_session_conversations; DROP TABLE sync_sessions; DROP TABLE delivery_evidence; DROP TABLE delivery_attempts;")
            .expect("remove v6 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("keep application id");
        connection
            .pragma_update(None, "user_version", 5_u32)
            .expect("set v5");
        drop(connection);
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v5 to v6");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert!(
            migrated
                .message(&scope(), &message(b"delivery-message").message_id)
                .expect("message lookup")
                .is_some()
        );
        let attempt = attempt("delivery-after-migration");
        assert_eq!(
            migrated.create_delivery_attempt(
                &attempt,
                &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1),
            ),
            Ok(DurableRecordStatus::Persisted)
        );
    }
    #[test]
    fn corrupt_delivery_evidence_binding_is_rejected_on_reopen() {
        let db = TestDb::new();
        let attempt = attempt("delivery-corrupt");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            seed_message(&store);
            store
                .create_delivery_attempt(
                    &attempt,
                    &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1),
                )
                .expect("create attempt");
        }
        let raw = Connection::open(db.path()).expect("raw sqlite");
        raw.execute(
            "UPDATE delivery_evidence SET message_id='other-message' WHERE delivery_id=?1",
            [attempt.delivery_id.as_opaque().as_str()],
        )
        .expect("corrupt binding");
        drop(raw);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }
}
