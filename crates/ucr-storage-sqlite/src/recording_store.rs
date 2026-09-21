use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, RecordingStore};
use ucr_model::{
    CallId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, RecordingConsent,
    RecordingConsentState, RecordingId, RecordingPolicy, RecordingSession, RecordingState,
    TenantScope,
};
use ucr_protocol::{
    RecordingProtocolError, apply_recording_consent, delete_recording, expire_recording,
    start_recording, stop_recording, validate_recording_session,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    universal_conference_store, verify_table_columns,
};

const V33_OBJECTS_SQL: &str = r"
CREATE TABLE recordings (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    requested_by_principal_id TEXT NOT NULL,
    requested_by_principal_kind TEXT NOT NULL,
    require_all_participant_consent INTEGER NOT NULL CHECK(require_all_participant_consent IN (0, 1)),
    notify_all_participants INTEGER NOT NULL CHECK(notify_all_participants IN (0, 1)),
    retention_seconds INTEGER NOT NULL CHECK(retention_seconds BETWEEN 60 AND 31536000),
    policy_reference TEXT,
    state TEXT NOT NULL CHECK(state IN ('waiting_for_consent','ready','active','stopped','expired','deleted')),
    requested_at_unix_ms INTEGER NOT NULL CHECK(requested_at_unix_ms >= 0),
    started_at_unix_ms INTEGER,
    stopped_at_unix_ms INTEGER,
    expires_at_unix_ms INTEGER NOT NULL,
    revision BLOB NOT NULL CHECK(length(revision) = 8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, recording_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, call_id)
        REFERENCES calls(tenant_id, namespace_present, namespace_id, call_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE recording_consents (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    participant_principal_id TEXT NOT NULL,
    participant_principal_kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','granted','denied','revoked')),
    decided_at_unix_ms INTEGER NOT NULL CHECK(decided_at_unix_ms >= 0),
    PRIMARY KEY(
        tenant_id, namespace_present, namespace_id, recording_id,
        participant_principal_kind, participant_principal_id
    ),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, recording_id)
        REFERENCES recordings(tenant_id, namespace_present, namespace_id, recording_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v33_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V33_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v33(connection: &Connection) -> Result<(), DurableStoreError> {
    universal_conference_store::verify_schema_v32(connection)?;
    verify_v33_objects(connection)
}

pub(super) fn verify_v33_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "recordings",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("recording_id", "TEXT", 1, 4),
            ("call_id", "TEXT", 1, 0),
            ("requested_by_principal_id", "TEXT", 1, 0),
            ("requested_by_principal_kind", "TEXT", 1, 0),
            ("require_all_participant_consent", "INTEGER", 1, 0),
            ("notify_all_participants", "INTEGER", 1, 0),
            ("retention_seconds", "INTEGER", 1, 0),
            ("policy_reference", "TEXT", 0, 0),
            ("state", "TEXT", 1, 0),
            ("requested_at_unix_ms", "INTEGER", 1, 0),
            ("started_at_unix_ms", "INTEGER", 0, 0),
            ("stopped_at_unix_ms", "INTEGER", 0, 0),
            ("expires_at_unix_ms", "INTEGER", 1, 0),
            ("revision", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "recording_consents",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("recording_id", "TEXT", 1, 4),
            ("participant_principal_id", "TEXT", 1, 6),
            ("participant_principal_kind", "TEXT", 1, 5),
            ("state", "TEXT", 1, 0),
            ("decided_at_unix_ms", "INTEGER", 1, 0),
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

impl RecordingStore for SqliteLocalStore {
    fn persist_recording(
        &self,
        recording: &RecordingSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_recording_session(recording).map_err(map_recording_protocol_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_recording(&transaction, &recording.scope, &recording.recording_id)?
        {
            return if existing == *recording {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_recording(&transaction, recording)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
    ) -> Result<Option<RecordingSession>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_recording(&connection, scope, recording_id)
    }

    fn set_recording_consent(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        participant: &PrincipalRef,
        consent_state: RecordingConsentState,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError> {
        transition_recording(self, scope, recording_id, expected_revision, |current| {
            apply_recording_consent(current, participant, consent_state, now_unix_ms)
        })
    }

    fn start_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError> {
        transition_recording(self, scope, recording_id, expected_revision, |current| {
            start_recording(current, now_unix_ms)
        })
    }

    fn stop_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError> {
        transition_recording(self, scope, recording_id, expected_revision, |current| {
            stop_recording(current, now_unix_ms)
        })
    }

    fn expire_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError> {
        transition_recording(self, scope, recording_id, expected_revision, |current| {
            expire_recording(current, now_unix_ms)
        })
    }

    fn delete_recording(
        &self,
        scope: &TenantScope,
        recording_id: &RecordingId,
        expected_revision: u64,
        now_unix_ms: i64,
    ) -> Result<RecordingSession, DurableStoreError> {
        transition_recording(self, scope, recording_id, expected_revision, |current| {
            delete_recording(current, now_unix_ms)
        })
    }
}

fn transition_recording<F>(
    store: &SqliteLocalStore,
    scope: &TenantScope,
    recording_id: &RecordingId,
    expected_revision: u64,
    transition: F,
) -> Result<RecordingSession, DurableStoreError>
where
    F: FnOnce(&RecordingSession) -> Result<RecordingSession, RecordingProtocolError>,
{
    let mut connection = store.lock_connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error))?;
    let current =
        load_recording(&transaction, scope, recording_id)?.ok_or(DurableStoreError::Conflict)?;
    if current.revision != expected_revision {
        return Err(DurableStoreError::Conflict);
    }
    let next = transition(&current).map_err(map_recording_protocol_error)?;
    if next == current {
        return Ok(current);
    }
    replace_recording_snapshot(&transaction, &next, expected_revision)?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(next)
}

fn insert_recording(
    transaction: &Transaction<'_>,
    recording: &RecordingSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&recording.scope);
    transaction
        .execute(
            "INSERT INTO recordings (
                tenant_id, namespace_present, namespace_id, recording_id, call_id,
                requested_by_principal_id, requested_by_principal_kind,
                require_all_participant_consent, notify_all_participants, retention_seconds,
                policy_reference, state, requested_at_unix_ms, started_at_unix_ms,
                stopped_at_unix_ms, expires_at_unix_ms, revision
             ) VALUES (
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17
             )",
            params![
                recording.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording.recording_id.as_opaque().as_str(),
                recording.call_id.as_opaque().as_str(),
                recording.requested_by.principal_id.as_opaque().as_str(),
                principal_kind_text(recording.requested_by.kind),
                bool_to_i64(recording.policy.require_all_participant_consent),
                bool_to_i64(recording.policy.notify_all_participants),
                i64::try_from(recording.policy.retention_seconds)
                    .map_err(|_| DurableStoreError::InvalidRecord)?,
                recording.policy.policy_reference.as_deref(),
                state_text(recording.state),
                recording.requested_at_unix_ms,
                recording.started_at_unix_ms,
                recording.stopped_at_unix_ms,
                recording.expires_at_unix_ms,
                encode_u64(recording.revision).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    insert_consents(transaction, recording)
}

fn insert_consents(
    transaction: &Transaction<'_>,
    recording: &RecordingSession,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&recording.scope);
    for consent in &recording.consents {
        transaction
            .execute(
                "INSERT INTO recording_consents (
                    tenant_id, namespace_present, namespace_id, recording_id,
                    participant_principal_id, participant_principal_kind, state,
                    decided_at_unix_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    recording.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    recording.recording_id.as_opaque().as_str(),
                    consent.participant.principal_id.as_opaque().as_str(),
                    principal_kind_text(consent.participant.kind),
                    consent_state_text(consent.state),
                    consent.decided_at_unix_ms,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn replace_recording_snapshot(
    transaction: &Transaction<'_>,
    recording: &RecordingSession,
    expected_revision: u64,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&recording.scope);
    let changed = transaction
        .execute(
            "UPDATE recordings
             SET state=?1, started_at_unix_ms=?2, stopped_at_unix_ms=?3, revision=?4
             WHERE tenant_id=?5 AND namespace_present=?6 AND namespace_id=?7
               AND recording_id=?8 AND revision=?9",
            params![
                state_text(recording.state),
                recording.started_at_unix_ms,
                recording.stopped_at_unix_ms,
                encode_u64(recording.revision).as_slice(),
                recording.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording.recording_id.as_opaque().as_str(),
                encode_u64(expected_revision).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if changed != 1 {
        return Err(DurableStoreError::Conflict);
    }
    transaction
        .execute(
            "DELETE FROM recording_consents
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND recording_id=?4",
            params![
                recording.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording.recording_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    insert_consents(transaction, recording)
}

fn load_recording(
    connection: &Connection,
    scope: &TenantScope,
    recording_id: &RecordingId,
) -> Result<Option<RecordingSession>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let stored = connection
        .query_row(
            "SELECT call_id, requested_by_principal_id, requested_by_principal_kind,
                    require_all_participant_consent, notify_all_participants, retention_seconds,
                    policy_reference, state, requested_at_unix_ms, started_at_unix_ms,
                    stopped_at_unix_ms, expires_at_unix_ms, revision
             FROM recordings
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND recording_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((
        call_id,
        requested_by_id,
        requested_by_kind,
        require_consent,
        notify,
        retention_seconds,
        policy_reference,
        state,
        requested_at_unix_ms,
        started_at_unix_ms,
        stopped_at_unix_ms,
        expires_at_unix_ms,
        revision,
    )) = stored
    else {
        return Ok(None);
    };

    let consents = load_consents(connection, scope, recording_id)?;
    let recording = RecordingSession {
        scope: scope.clone(),
        recording_id: recording_id.clone(),
        call_id: CallId::from_opaque(parse_id(&call_id)?),
        requested_by: PrincipalRef {
            principal_id: PrincipalId::from_opaque(parse_id(&requested_by_id)?),
            kind: parse_principal_kind(&requested_by_kind)?,
        },
        policy: RecordingPolicy {
            require_all_participant_consent: parse_bool(require_consent)?,
            notify_all_participants: parse_bool(notify)?,
            retention_seconds: u64::try_from(retention_seconds)
                .map_err(|_| DurableStoreError::Corrupt)?,
            policy_reference,
        },
        state: parse_state(&state)?,
        consents,
        requested_at_unix_ms,
        started_at_unix_ms,
        stopped_at_unix_ms,
        expires_at_unix_ms,
        revision: decode_u64(&revision)?,
    };
    validate_recording_session(&recording).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(Some(recording))
}

fn load_consents(
    connection: &Connection,
    scope: &TenantScope,
    recording_id: &RecordingId,
) -> Result<Vec<RecordingConsent>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT participant_principal_id, participant_principal_kind, state, decided_at_unix_ms
             FROM recording_consents
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND recording_id=?4
             ORDER BY participant_principal_kind, participant_principal_id",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                recording_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut consents = Vec::new();
    for row in rows {
        let (principal_id, principal_kind, state, decided_at_unix_ms) =
            row.map_err(|error| map_sqlite_error(&error))?;
        consents.push(RecordingConsent {
            participant: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&principal_id)?),
                kind: parse_principal_kind(&principal_kind)?,
            },
            state: parse_consent_state(&state)?,
            decided_at_unix_ms,
        });
    }
    Ok(consents)
}

const fn map_recording_protocol_error(error: RecordingProtocolError) -> DurableStoreError {
    match error {
        RecordingProtocolError::InvalidPolicy
        | RecordingProtocolError::InvalidSession
        | RecordingProtocolError::InvalidConsent
        | RecordingProtocolError::Overflow => DurableStoreError::InvalidRecord,
        RecordingProtocolError::InvalidTransition
        | RecordingProtocolError::ConsentRequired
        | RecordingProtocolError::Expired => DurableStoreError::Conflict,
    }
}

const fn state_text(value: RecordingState) -> &'static str {
    match value {
        RecordingState::WaitingForConsent => "waiting_for_consent",
        RecordingState::Ready => "ready",
        RecordingState::Active => "active",
        RecordingState::Stopped => "stopped",
        RecordingState::Expired => "expired",
        RecordingState::Deleted => "deleted",
    }
}

fn parse_state(value: &str) -> Result<RecordingState, DurableStoreError> {
    match value {
        "waiting_for_consent" => Ok(RecordingState::WaitingForConsent),
        "ready" => Ok(RecordingState::Ready),
        "active" => Ok(RecordingState::Active),
        "stopped" => Ok(RecordingState::Stopped),
        "expired" => Ok(RecordingState::Expired),
        "deleted" => Ok(RecordingState::Deleted),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn consent_state_text(value: RecordingConsentState) -> &'static str {
    match value {
        RecordingConsentState::Pending => "pending",
        RecordingConsentState::Granted => "granted",
        RecordingConsentState::Denied => "denied",
        RecordingConsentState::Revoked => "revoked",
    }
}

fn parse_consent_state(value: &str) -> Result<RecordingConsentState, DurableStoreError> {
    match value {
        "pending" => Ok(RecordingConsentState::Pending),
        "granted" => Ok(RecordingConsentState::Granted),
        "denied" => Ok(RecordingConsentState::Denied),
        "revoked" => Ok(RecordingConsentState::Revoked),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn principal_kind_text(value: PrincipalKind) -> &'static str {
    match value {
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

const fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

const fn parse_bool(value: i64) -> Result<bool, DurableStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use ucr_core::{CallStore, ConversationStore, RecordingStore, StorageProvider};
    use ucr_model::{
        CallParticipant, CallParticipantState, CallSession, CallSignallingState, ConversationId,
        ConversationKind, ConversationRecord, ConversationRef, NamespaceId, PrincipalId,
        RecordingConsent, RecordingConsentState, RecordingPolicy, RecordingState, ScopedPrincipal,
        TenantId,
    };

    use super::*;
    use crate::{
        SQLITE_SCHEMA_V32, SQLITE_SCHEMA_VERSION, message_store::tests::TestDb,
        test_remove_v33_objects,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("recording-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("recording-namespace"))),
        }
    }

    fn subject(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(value)),
                kind: PrincipalKind::Person,
            },
        }
    }

    fn conversation() -> ConversationRecord {
        ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("recording-conversation")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        }
    }

    fn call() -> (CallSession, ScopedPrincipal, ScopedPrincipal) {
        let host = subject("recording-host");
        let guest = subject("recording-guest");
        (
            CallSession {
                scope: scope(),
                call_id: CallId::from_opaque(oid("recording-call")),
                conversation: conversation().conversation,
                initiated_by: host.principal.clone(),
                participants: vec![
                    CallParticipant {
                        principal: host.principal.clone(),
                        state: CallParticipantState::Accepted,
                        joined_revision: 0,
                        left_revision: None,
                    },
                    CallParticipant {
                        principal: guest.principal.clone(),
                        state: CallParticipantState::Invited,
                        joined_revision: 0,
                        left_revision: None,
                    },
                ],
                signalling_state: CallSignallingState::Inviting,
                reconnecting_participant: None,
                media_negotiation_ref: None,
                media_negotiation_generation: 0,
                replication_generation: 0,
                revision: 0,
                termination_reason: None,
            },
            host,
            guest,
        )
    }

    fn recording(
        call: &CallSession,
        host: &ScopedPrincipal,
        guest: &ScopedPrincipal,
    ) -> RecordingSession {
        RecordingSession {
            scope: scope(),
            recording_id: RecordingId::from_opaque(oid("recording-session")),
            call_id: call.call_id.clone(),
            requested_by: host.principal.clone(),
            policy: RecordingPolicy {
                require_all_participant_consent: true,
                notify_all_participants: true,
                retention_seconds: 600,
                policy_reference: Some("recording-policy".to_owned()),
            },
            state: RecordingState::WaitingForConsent,
            consents: vec![
                RecordingConsent {
                    participant: host.principal.clone(),
                    state: RecordingConsentState::Pending,
                    decided_at_unix_ms: 0,
                },
                RecordingConsent {
                    participant: guest.principal.clone(),
                    state: RecordingConsentState::Pending,
                    decided_at_unix_ms: 0,
                },
            ],
            requested_at_unix_ms: 1_000_000,
            started_at_unix_ms: None,
            stopped_at_unix_ms: None,
            expires_at_unix_ms: 1_600_000,
            revision: 1,
        }
    }

    #[test]
    fn recording_lifecycle_and_consents_survive_sqlite_reopen() {
        let db = TestDb::new();
        let (call, host, guest) = call();
        let initial = recording(&call, &host, &guest);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
            store
                .persist_conversation(&conversation())
                .expect("conversation");
            store.create_call(&host, &call).expect("call");
            store.persist_recording(&initial).expect("recording");

            let host_granted = store
                .set_recording_consent(
                    &initial.scope,
                    &initial.recording_id,
                    initial.revision,
                    &host.principal,
                    RecordingConsentState::Granted,
                    1_010_000,
                )
                .expect("host consent");
            let ready = store
                .set_recording_consent(
                    &initial.scope,
                    &initial.recording_id,
                    host_granted.revision,
                    &guest.principal,
                    RecordingConsentState::Granted,
                    1_020_000,
                )
                .expect("guest consent");
            assert_eq!(ready.state, RecordingState::Ready);
            let active = store
                .start_recording(
                    &initial.scope,
                    &initial.recording_id,
                    ready.revision,
                    1_030_000,
                )
                .expect("start");
            assert_eq!(active.state, RecordingState::Active);
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        let active = reopened
            .recording(&initial.scope, &initial.recording_id)
            .expect("read")
            .expect("recording");
        assert_eq!(active.state, RecordingState::Active);
        let stopped = reopened
            .set_recording_consent(
                &initial.scope,
                &initial.recording_id,
                active.revision,
                &guest.principal,
                RecordingConsentState::Revoked,
                1_040_000,
            )
            .expect("revoke");
        assert_eq!(stopped.state, RecordingState::Stopped);
        assert_eq!(stopped.stopped_at_unix_ms, Some(1_040_000));
    }

    #[test]
    fn v32_store_migrates_to_v33_recording_schema() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        {
            let connection = Connection::open(db.path()).expect("open migration fixture");
            test_remove_v33_objects(&connection).expect("remove v33 objects");
            connection
                .pragma_update(None, "user_version", SQLITE_SCHEMA_V32)
                .expect("set v32");
        }

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v32 to v33");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let connection = migrated.lock_connection().expect("connection");
        verify_schema_v33(&connection).expect("verify v33");
    }
}
