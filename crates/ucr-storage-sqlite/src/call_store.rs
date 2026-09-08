use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{CallStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    CallId, CallParticipant, CallParticipantState, CallParticipantUpdateKind, CallSession,
    CallSignal, CallSignalKind, CallSignallingState, CallTerminationReason, ConversationId,
    ConversationKind, ConversationRef, GroupMemberState, NamespaceId, OpaqueId, PrincipalId,
    PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{
    active_call_participant, apply_call_signal, call_signal_fingerprint, canonical_call_creation,
    canonical_call_session,
};

use super::{
    SqliteLocalStore, group_store, map_schema_change_error, map_sqlite_error, message_store,
    namespace_storage_key, verify_table_columns,
};

pub(super) const V22_OBJECTS_SQL: &str = r"
CREATE TABLE calls (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    conversation_kind TEXT NOT NULL CHECK(conversation_kind IN ('direct','private_group','public_group')),
    initiated_by_principal_id TEXT NOT NULL,
    initiated_by_principal_kind TEXT NOT NULL,
    signalling_state TEXT NOT NULL CHECK(signalling_state IN ('inviting','ringing','active','reconnecting','terminated')),
    media_negotiation_ref TEXT,
    media_negotiation_generation BLOB NOT NULL CHECK(length(media_negotiation_generation)=8),
    replication_generation BLOB NOT NULL CHECK(length(replication_generation)=8),
    revision BLOB NOT NULL CHECK(length(revision)=8),
    termination_reason TEXT CHECK(termination_reason IS NULL OR termination_reason IN ('rejected','busy','cancelled','timed_out','completed','failed')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, call_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, conversation_id)
      REFERENCES conversations(tenant_id, namespace_present, namespace_id, conversation_id),
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE call_participants (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('invited','ringing','accepted','rejected','busy','left')),
    joined_revision BLOB NOT NULL CHECK(length(joined_revision)=8),
    left_revision BLOB CHECK(left_revision IS NULL OR length(left_revision)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, call_id, principal_id, principal_kind),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, call_id)
      REFERENCES calls(tenant_id, namespace_present, namespace_id, call_id) ON DELETE CASCADE,
    CHECK((state='left' AND left_revision IS NOT NULL) OR (state<>'left' AND left_revision IS NULL)),
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE call_signals (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    actor_principal_kind TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    applied_revision BLOB NOT NULL CHECK(length(applied_revision)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, call_id)
      REFERENCES calls(tenant_id, namespace_present, namespace_id, call_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TRIGGER event_id_owner_events BEFORE INSERT ON events
WHEN EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;

CREATE TRIGGER event_id_owner_group_changes BEFORE INSERT ON group_changes
WHEN EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;

CREATE TRIGGER event_id_owner_call_signals BEFORE INSERT ON call_signals
WHEN EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;
";

pub(super) fn create_v22_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V22_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v22(connection: &Connection) -> Result<(), DurableStoreError> {
    group_store::verify_schema_v21(connection)?;
    verify_call_table_shapes(connection)?;
    verify_event_id_owner_triggers(connection)?;
    verify_no_cross_owner_event_ids(connection)?;
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
    verify_call_rows(connection)
}

fn verify_call_table_shapes(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "calls",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("call_id", "TEXT", 1, 4),
            ("conversation_id", "TEXT", 1, 0),
            ("conversation_kind", "TEXT", 1, 0),
            ("initiated_by_principal_id", "TEXT", 1, 0),
            ("initiated_by_principal_kind", "TEXT", 1, 0),
            ("signalling_state", "TEXT", 1, 0),
            ("media_negotiation_ref", "TEXT", 0, 0),
            ("media_negotiation_generation", "BLOB", 1, 0),
            ("replication_generation", "BLOB", 1, 0),
            ("revision", "BLOB", 1, 0),
            ("termination_reason", "TEXT", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "call_participants",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("call_id", "TEXT", 1, 4),
            ("principal_id", "TEXT", 1, 5),
            ("principal_kind", "TEXT", 1, 6),
            ("state", "TEXT", 1, 0),
            ("joined_revision", "BLOB", 1, 0),
            ("left_revision", "BLOB", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "call_signals",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("call_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 4),
            ("actor_principal_id", "TEXT", 1, 0),
            ("actor_principal_kind", "TEXT", 1, 0),
            ("fingerprint", "BLOB", 1, 0),
            ("applied_revision", "BLOB", 1, 0),
        ],
    )
}

fn verify_event_id_owner_triggers(connection: &Connection) -> Result<(), DurableStoreError> {
    for name in [
        "event_id_owner_events",
        "event_id_owner_group_changes",
        "event_id_owner_call_signals",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name=?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if !exists {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

fn verify_no_cross_owner_event_ids(connection: &Connection) -> Result<(), DurableStoreError> {
    let collision: bool = connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM events e JOIN group_changes g
                 ON e.tenant_id=g.tenant_id AND e.namespace_present=g.namespace_present
                AND e.namespace_id=g.namespace_id AND e.event_id=g.event_id
               UNION ALL
               SELECT 1 FROM events e JOIN call_signals c
                 ON e.tenant_id=c.tenant_id AND e.namespace_present=c.namespace_present
                AND e.namespace_id=c.namespace_id AND e.event_id=c.event_id
               UNION ALL
               SELECT 1 FROM group_changes g JOIN call_signals c
                 ON g.tenant_id=c.tenant_id AND g.namespace_present=c.namespace_present
                AND g.namespace_id=c.namespace_id AND g.event_id=c.event_id
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if collision {
        Err(DurableStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn verify_call_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, call_id FROM calls")
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
    for (tenant, present, namespace, call_id) in keys {
        let scope = parse_scope(&tenant, present, &namespace)?;
        let call_id = CallId::from_opaque(parse_id(&call_id)?);
        load_call_from(connection, &scope, &call_id)?.ok_or(DurableStoreError::Corrupt)?;
    }
    Ok(())
}

impl CallStore for SqliteLocalStore {
    fn create_call(
        &self,
        creator: &ScopedPrincipal,
        session: &CallSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let session = canonical_call_creation(session, &creator.scope, &creator.principal)
            .map_err(map_call_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let conversation = message_store::load_conversation_from(
            &transaction,
            &session.scope,
            &session.conversation.conversation_id,
        )?
        .ok_or(DurableStoreError::InvalidRecord)?;
        if conversation.conversation != session.conversation {
            return Err(DurableStoreError::InvalidRecord);
        }
        require_group_participants_if_needed(&transaction, &session)?;
        if let Some(existing) = load_call_from(&transaction, &session.scope, &session.call_id)? {
            return if existing == session && creator.principal == existing.initiated_by {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_call(&transaction, &session)?;
        replace_participants(&transaction, &session)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn call(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_call_from(&connection, scope, call_id)
    }

    fn call_for_participant(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<Option<CallSession>, DurableStoreError> {
        if subject.scope != *scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error))?;
        let Some(session) = load_call_from(&transaction, scope, call_id)? else {
            return Ok(None);
        };
        if !active_call_participant(&session, &subject.principal)
            || !group_actor_current_if_needed(&transaction, &session, &subject.principal)?
        {
            return Ok(None);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(Some(session))
    }

    fn apply_call_signal(
        &self,
        actor: &ScopedPrincipal,
        signal: &CallSignal,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != signal.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = call_signal_fingerprint(signal).map_err(map_call_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_call_from(&transaction, &signal.scope, &signal.call_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if !group_actor_current_if_needed(&transaction, &current, &actor.principal)? {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some((recorded_actor, existing, applied_revision)) = load_signal_record(
            &transaction,
            &signal.scope,
            signal.event_id.as_opaque().as_str(),
        )? {
            if recorded_actor != actor.principal
                || !duplicate_actor_allowed(&current, &actor.principal, applied_revision)
            {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if !active_call_participant(&current, &actor.principal) {
            return Err(DurableStoreError::PermissionDenied);
        }
        require_group_signal_target_if_needed(&transaction, &current, signal)?;
        let next = apply_call_signal(&current, &actor.scope, &actor.principal, signal)
            .map_err(map_call_error)?;
        if super::event_journal::load_event_by_id(&transaction, &signal.scope, &signal.event_id)?
            .is_some()
            || group_change_reserves_event_id(
                &transaction,
                &signal.scope,
                signal.event_id.as_opaque().as_str(),
            )?
        {
            return Err(DurableStoreError::Conflict);
        }
        update_call(&transaction, &next)?;
        replace_participants(&transaction, &next)?;
        insert_signal_record(&transaction, actor, signal, &fingerprint, next.revision)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

pub(super) fn call_signal_reserves_event_id(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<bool, DurableStoreError> {
    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='call_signals')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !table_exists {
        return Ok(false);
    }
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4)",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

fn group_change_reserves_event_id(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<bool, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4)",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

fn require_group_participants_if_needed(
    connection: &Connection,
    session: &CallSession,
) -> Result<(), DurableStoreError> {
    if !is_group_kind(session.conversation.kind) {
        return Ok(());
    }
    let group = group_store::load_group_for_conversation_from(
        connection,
        &session.scope,
        &session.conversation.conversation_id,
    )?
    .ok_or(DurableStoreError::PermissionDenied)?;
    if group.conversation != session.conversation {
        return Err(DurableStoreError::InvalidRecord);
    }
    for participant in &session.participants {
        let membership = group_store::load_membership_from(
            connection,
            &session.scope,
            &group.group_id,
            &participant.principal,
        )?;
        if !membership.is_some_and(|value| value.state == GroupMemberState::Active) {
            return Err(DurableStoreError::PermissionDenied);
        }
    }
    Ok(())
}

fn group_actor_current_if_needed(
    connection: &Connection,
    session: &CallSession,
    actor: &PrincipalRef,
) -> Result<bool, DurableStoreError> {
    if !is_group_kind(session.conversation.kind) {
        return Ok(true);
    }
    let Some(group) = group_store::load_group_for_conversation_from(
        connection,
        &session.scope,
        &session.conversation.conversation_id,
    )?
    else {
        return Ok(false);
    };
    let membership =
        group_store::load_membership_from(connection, &session.scope, &group.group_id, actor)?;
    Ok(membership.is_some_and(|value| value.state == GroupMemberState::Active))
}

fn require_group_signal_target_if_needed(
    connection: &Connection,
    session: &CallSession,
    signal: &CallSignal,
) -> Result<(), DurableStoreError> {
    let CallSignalKind::ParticipantUpdate {
        participant,
        kind: CallParticipantUpdateKind::Add,
    } = &signal.kind
    else {
        return Ok(());
    };
    if !is_group_kind(session.conversation.kind) {
        return Ok(());
    }
    let group = group_store::load_group_for_conversation_from(
        connection,
        &session.scope,
        &session.conversation.conversation_id,
    )?
    .ok_or(DurableStoreError::PermissionDenied)?;
    let membership = group_store::load_membership_from(
        connection,
        &session.scope,
        &group.group_id,
        participant,
    )?;
    if membership.is_some_and(|value| value.state == GroupMemberState::Active) {
        Ok(())
    } else {
        Err(DurableStoreError::PermissionDenied)
    }
}

fn load_call_from(
    connection: &Connection,
    scope: &TenantScope,
    call_id: &CallId,
) -> Result<Option<CallSession>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT conversation_id, conversation_kind, initiated_by_principal_id,
                    initiated_by_principal_kind, signalling_state, media_negotiation_ref,
                    media_negotiation_generation, replication_generation, revision,
                    termination_reason
             FROM calls WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND call_id=?4",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, call_id.as_opaque().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<String>>(5)?,
                    row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?, row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let conversation = ConversationRef {
        conversation_id: ConversationId::from_opaque(parse_id(&row.0)?),
        kind: parse_call_conversation_kind(&row.1)?,
    };
    let persisted_conversation =
        message_store::load_conversation_from(connection, scope, &conversation.conversation_id)?
            .ok_or(DurableStoreError::Corrupt)?;
    if persisted_conversation.conversation != conversation {
        return Err(DurableStoreError::Corrupt);
    }
    let session = CallSession {
        scope: scope.clone(),
        call_id: call_id.clone(),
        conversation,
        initiated_by: PrincipalRef {
            principal_id: PrincipalId::from_opaque(parse_id(&row.2)?),
            kind: group_store::parse_principal_kind(&row.3)?,
        },
        participants: load_participants(connection, scope, call_id)?,
        signalling_state: parse_signalling_state(&row.4)?,
        media_negotiation_ref: row.5.map(|value| parse_id(&value)).transpose()?,
        media_negotiation_generation: decode_u64(&row.6)?,
        replication_generation: decode_u64(&row.7)?,
        revision: decode_u64(&row.8)?,
        termination_reason: row.9.as_deref().map(parse_termination_reason).transpose()?,
    };
    canonical_call_session(&session)
        .map(Some)
        .map_err(map_call_error)
}

fn load_participants(
    connection: &Connection,
    scope: &TenantScope,
    call_id: &CallId,
) -> Result<Vec<CallParticipant>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT principal_id, principal_kind, state, joined_revision, left_revision
             FROM call_participants
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND call_id=?4
             ORDER BY principal_id, principal_kind",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                call_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut participants = Vec::new();
    for row in rows {
        let row = row.map_err(|error| map_sqlite_error(&error))?;
        participants.push(CallParticipant {
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&row.0)?),
                kind: group_store::parse_principal_kind(&row.1)?,
            },
            state: parse_participant_state(&row.2)?,
            joined_revision: decode_u64(&row.3)?,
            left_revision: row.4.as_deref().map(decode_u64).transpose()?,
        });
    }
    Ok(participants)
}

fn insert_call(
    transaction: &Transaction<'_>,
    session: &CallSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&session.scope);
    transaction
        .execute(
            "INSERT INTO calls VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                session.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session.call_id.as_opaque().as_str(),
                session.conversation.conversation_id.as_opaque().as_str(),
                call_conversation_kind_name(session.conversation.kind),
                session.initiated_by.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(session.initiated_by.kind),
                signalling_state_name(session.signalling_state),
                session.media_negotiation_ref.as_ref().map(OpaqueId::as_str),
                encode_u64(session.media_negotiation_generation).as_slice(),
                encode_u64(session.replication_generation).as_slice(),
                encode_u64(session.revision).as_slice(),
                session.termination_reason.map(termination_reason_name),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn update_call(
    transaction: &Transaction<'_>,
    session: &CallSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&session.scope);
    let changed = transaction
        .execute(
            "UPDATE calls SET signalling_state=?5, media_negotiation_ref=?6,
                    media_negotiation_generation=?7, replication_generation=?8, revision=?9,
                    termination_reason=?10
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND call_id=?4",
            params![
                session.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session.call_id.as_opaque().as_str(),
                signalling_state_name(session.signalling_state),
                session.media_negotiation_ref.as_ref().map(OpaqueId::as_str),
                encode_u64(session.media_negotiation_generation).as_slice(),
                encode_u64(session.replication_generation).as_slice(),
                encode_u64(session.revision).as_slice(),
                session.termination_reason.map(termination_reason_name),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

fn replace_participants(
    transaction: &Transaction<'_>,
    session: &CallSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&session.scope);
    transaction
        .execute(
            "DELETE FROM call_participants WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND call_id=?4",
            params![session.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, session.call_id.as_opaque().as_str()],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    for participant in &session.participants {
        transaction
            .execute(
                "INSERT INTO call_participants VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    session.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    session.call_id.as_opaque().as_str(),
                    participant.principal.principal_id.as_opaque().as_str(),
                    group_store::principal_kind_name(participant.principal.kind),
                    participant_state_name(participant.state),
                    encode_u64(participant.joined_revision).as_slice(),
                    participant.left_revision.map(encode_u64),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn load_signal_record(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<Option<(PrincipalRef, [u8; 32], u64)>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT actor_principal_id, actor_principal_kind, fingerprint, applied_revision
             FROM call_signals WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
            |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,Vec<u8>>(2)?, row.get::<_,Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|row| {
        Ok((
            PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&row.0)?),
                kind: group_store::parse_principal_kind(&row.1)?,
            },
            row.2.try_into().map_err(|_| DurableStoreError::Corrupt)?,
            decode_u64(&row.3)?,
        ))
    })
    .transpose()
}

fn insert_signal_record(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    signal: &CallSignal,
    fingerprint: &[u8; 32],
    applied_revision: u64,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&signal.scope);
    transaction
        .execute(
            "INSERT INTO call_signals VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                signal.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                signal.call_id.as_opaque().as_str(),
                signal.event_id.as_opaque().as_str(),
                actor.principal.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(actor.principal.kind),
                fingerprint.as_slice(),
                encode_u64(applied_revision).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn duplicate_actor_allowed(
    session: &CallSession,
    actor: &PrincipalRef,
    applied_revision: u64,
) -> bool {
    let Some(participant) = session
        .participants
        .iter()
        .find(|value| value.principal == *actor)
    else {
        return false;
    };
    if active_call_participant(session, actor) {
        return true;
    }
    match participant.state {
        CallParticipantState::Rejected | CallParticipantState::Busy => {
            participant.left_revision.is_none() && session.revision >= applied_revision
        }
        CallParticipantState::Left => participant.left_revision == Some(applied_revision),
        CallParticipantState::Invited
        | CallParticipantState::Ringing
        | CallParticipantState::Accepted => false,
    }
}

const fn is_group_kind(kind: ConversationKind) -> bool {
    matches!(
        kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    )
}

const fn call_conversation_kind_name(kind: ConversationKind) -> &'static str {
    match kind {
        ConversationKind::Direct => "direct",
        ConversationKind::PrivateGroup => "private_group",
        ConversationKind::PublicGroup => "public_group",
        _ => "invalid",
    }
}

fn parse_call_conversation_kind(value: &str) -> Result<ConversationKind, DurableStoreError> {
    match value {
        "direct" => Ok(ConversationKind::Direct),
        "private_group" => Ok(ConversationKind::PrivateGroup),
        "public_group" => Ok(ConversationKind::PublicGroup),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn signalling_state_name(value: CallSignallingState) -> &'static str {
    match value {
        CallSignallingState::Inviting => "inviting",
        CallSignallingState::Ringing => "ringing",
        CallSignallingState::Active => "active",
        CallSignallingState::Reconnecting => "reconnecting",
        CallSignallingState::Terminated => "terminated",
    }
}

fn parse_signalling_state(value: &str) -> Result<CallSignallingState, DurableStoreError> {
    match value {
        "inviting" => Ok(CallSignallingState::Inviting),
        "ringing" => Ok(CallSignallingState::Ringing),
        "active" => Ok(CallSignallingState::Active),
        "reconnecting" => Ok(CallSignallingState::Reconnecting),
        "terminated" => Ok(CallSignallingState::Terminated),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn participant_state_name(value: CallParticipantState) -> &'static str {
    match value {
        CallParticipantState::Invited => "invited",
        CallParticipantState::Ringing => "ringing",
        CallParticipantState::Accepted => "accepted",
        CallParticipantState::Rejected => "rejected",
        CallParticipantState::Busy => "busy",
        CallParticipantState::Left => "left",
    }
}

fn parse_participant_state(value: &str) -> Result<CallParticipantState, DurableStoreError> {
    match value {
        "invited" => Ok(CallParticipantState::Invited),
        "ringing" => Ok(CallParticipantState::Ringing),
        "accepted" => Ok(CallParticipantState::Accepted),
        "rejected" => Ok(CallParticipantState::Rejected),
        "busy" => Ok(CallParticipantState::Busy),
        "left" => Ok(CallParticipantState::Left),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn termination_reason_name(value: CallTerminationReason) -> &'static str {
    match value {
        CallTerminationReason::Rejected => "rejected",
        CallTerminationReason::Busy => "busy",
        CallTerminationReason::Cancelled => "cancelled",
        CallTerminationReason::TimedOut => "timed_out",
        CallTerminationReason::Completed => "completed",
        CallTerminationReason::Failed => "failed",
    }
}

fn parse_termination_reason(value: &str) -> Result<CallTerminationReason, DurableStoreError> {
    match value {
        "rejected" => Ok(CallTerminationReason::Rejected),
        "busy" => Ok(CallTerminationReason::Busy),
        "cancelled" => Ok(CallTerminationReason::Cancelled),
        "timed_out" => Ok(CallTerminationReason::TimedOut),
        "completed" => Ok(CallTerminationReason::Completed),
        "failed" => Ok(CallTerminationReason::Failed),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn parse_scope(
    tenant: &str,
    present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match (present, namespace.is_empty()) {
        (0, true) => None,
        (1, false) => Some(NamespaceId::from_opaque(parse_id(namespace)?)),
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

const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    Ok(u64::from_be_bytes(
        value.try_into().map_err(|_| DurableStoreError::Corrupt)?,
    ))
}

fn map_call_error(error: ucr_protocol::CallSignallingError) -> DurableStoreError {
    use ucr_protocol::CallSignallingError;
    match error {
        CallSignallingError::PermissionDenied => DurableStoreError::PermissionDenied,
        CallSignallingError::RevisionMismatch
        | CallSignallingError::InvalidTransition
        | CallSignallingError::ParticipantAlreadyExists
        | CallSignallingError::WouldRemoveInitiator => DurableStoreError::Conflict,
        CallSignallingError::TooManyParticipants => DurableStoreError::Full,
        _ => DurableStoreError::InvalidRecord,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SQLITE_SCHEMA_VERSION, message_store::tests::TestDb};
    use ucr_core::{CallStore, ConversationStore, EventJournalStore, StorageProvider};
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CallParticipant, CorrelationContext, DeviceId, DeviceRef,
        EventEnvelope, EventId, IdentityId, ProtocolVersion,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("call-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("call-namespace"))),
        }
    }

    fn subject(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(value)),
                kind: ucr_model::PrincipalKind::Person,
            },
        }
    }

    fn conversation() -> ucr_model::ConversationRecord {
        ucr_model::ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("call-conversation")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        }
    }

    fn session() -> (CallSession, ScopedPrincipal, ScopedPrincipal) {
        let alice = subject("call-alice");
        let bob = subject("call-bob");
        let session = CallSession {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call-session")),
            conversation: conversation().conversation,
            initiated_by: alice.principal.clone(),
            participants: vec![
                CallParticipant {
                    principal: alice.principal.clone(),
                    state: CallParticipantState::Accepted,
                    joined_revision: 0,
                    left_revision: None,
                },
                CallParticipant {
                    principal: bob.principal.clone(),
                    state: CallParticipantState::Invited,
                    joined_revision: 0,
                    left_revision: None,
                },
            ],
            signalling_state: CallSignallingState::Inviting,
            media_negotiation_ref: None,
            media_negotiation_generation: 0,
            replication_generation: 0,
            revision: 0,
            termination_reason: None,
        };
        (session, alice, bob)
    }

    fn signal(session: &CallSession, id: &str, kind: CallSignalKind) -> CallSignal {
        CallSignal {
            event_id: EventId::from_opaque(oid(id)),
            scope: session.scope.clone(),
            call_id: session.call_id.clone(),
            expected_revision: session.revision,
            kind,
        }
    }

    fn event(id: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.test.event".to_owned(),
            payload: b"event".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("call-event-actor")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("call-event-device")),
                identity_id: IdentityId::from_opaque(oid("call-event-identity")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("call-event-correlation"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn call_state_and_idempotency_survive_sqlite_reopen() {
        let db = TestDb::new();
        let (session, alice, bob) = session();
        let accept = signal(&session, "call-accept", CallSignalKind::Accept);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
            store
                .persist_conversation(&conversation())
                .expect("conversation");
            assert_eq!(
                store.create_call(&alice, &session),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.apply_call_signal(&bob, &accept),
                Ok(DurableRecordStatus::Persisted)
            );
        }
        {
            let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
            let loaded = reopened
                .call_for_participant(&alice, &scope(), &session.call_id)
                .expect("read")
                .expect("call");
            assert_eq!(loaded.signalling_state, CallSignallingState::Active);
            assert_eq!(loaded.revision, 1);
            assert_eq!(
                reopened.apply_call_signal(&bob, &accept),
                Ok(DurableRecordStatus::Duplicate)
            );
        }
    }

    #[test]
    fn call_signal_event_id_is_exclusive_with_event_journal_in_both_orders() {
        let first_db = TestDb::new();
        let (session, alice, bob) = session();
        let signal = signal(&session, "shared-call-event", CallSignalKind::Accept);
        let store = SqliteLocalStore::open(first_db.path()).expect("open");
        store
            .persist_conversation(&conversation())
            .expect("conversation");
        store.create_call(&alice, &session).expect("call");
        store.apply_call_signal(&bob, &signal).expect("signal");
        assert_eq!(
            store.append_event(&event("shared-call-event")),
            Err(DurableStoreError::Conflict)
        );

        let second_db = TestDb::new();
        let store = SqliteLocalStore::open(second_db.path()).expect("open second");
        store
            .persist_conversation(&conversation())
            .expect("conversation");
        store.create_call(&alice, &session).expect("call");
        store
            .append_event(&event("shared-call-event"))
            .expect("event first");
        assert_eq!(
            store.apply_call_signal(&bob, &signal),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn rejected_actor_can_retry_after_reopen_without_restoring_call_authority() {
        let db = TestDb::new();
        let (session, alice, bob) = session();
        let reject = signal(&session, "call-reject", CallSignalKind::Reject);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store
                .persist_conversation(&conversation())
                .expect("conversation");
            store.create_call(&alice, &session).expect("call");
            store.apply_call_signal(&bob, &reject).expect("reject");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(
            reopened.call_for_participant(&bob, &scope(), &session.call_id),
            Ok(None)
        );
        assert_eq!(
            reopened.apply_call_signal(&bob, &reject),
            Ok(DurableRecordStatus::Duplicate)
        );
    }
}
