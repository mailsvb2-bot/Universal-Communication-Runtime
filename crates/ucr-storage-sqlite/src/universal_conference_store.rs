use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, UniversalConferenceStore};
use ucr_model::{
    ConferenceParticipantRole, ConferenceScheduleMetadata, EventEnvelope, GroupId, IntegrationId,
    OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, TenantScope, UniversalConferenceLifecycle,
    UniversalConferenceMode, UniversalConferenceParticipantProfile, UniversalConferenceProfile,
};

use super::{
    SqliteLocalStore, event_journal::append_event_in_transaction, map_schema_change_error,
    map_sqlite_error, namespace_storage_key, verify_table_columns,
};

const MAX_EXTERNAL_REFERENCE_BYTES: usize = 512;
const MAX_PARTICIPANTS: usize = 1024;
const MAX_PARTICIPANTS_DB: i64 = 1024;
const MAX_PARTICIPANT_SCAN_ITEMS: usize = MAX_PARTICIPANTS + 1;

const V32_OBJECTS_SQL: &str = r"
CREATE TABLE universal_conferences (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    conference_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    external_conference_id BLOB NOT NULL CHECK(length(external_conference_id) BETWEEN 1 AND 512),
    create_idempotency_key TEXT NOT NULL CHECK(length(create_idempotency_key) BETWEEN 1 AND 256),
    mode TEXT NOT NULL CHECK(mode IN ('meeting', 'webinar', 'broadcast', 'audio_room')),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('scheduled', 'waiting', 'live', 'ending', 'ended')),
    starts_at_unix_ms INTEGER NOT NULL,
    planned_end_unix_ms INTEGER,
    join_before_seconds INTEGER NOT NULL CHECK(join_before_seconds >= 0),
    join_after_seconds INTEGER NOT NULL CHECK(join_after_seconds >= 0),
    timezone TEXT,
    entry_open INTEGER NOT NULL CHECK(entry_open IN (0, 1)),
    revision BLOB NOT NULL CHECK(length(revision) = 8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, conference_id),
    UNIQUE(tenant_id, namespace_present, namespace_id, integration_id, external_conference_id),
    UNIQUE(tenant_id, namespace_present, namespace_id, integration_id, create_idempotency_key),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE universal_conference_participants (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    conference_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    external_user_id BLOB NOT NULL CHECK(length(external_user_id) BETWEEN 1 AND 512),
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'host', 'moderator', 'speaker', 'attendee')),
    audio_muted INTEGER NOT NULL CHECK(audio_muted IN (0, 1)),
    camera_allowed INTEGER NOT NULL CHECK(camera_allowed IN (0, 1)),
    publish_audio_allowed INTEGER NOT NULL CHECK(publish_audio_allowed IN (0, 1)),
    publish_video_allowed INTEGER NOT NULL CHECK(publish_video_allowed IN (0, 1)),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    revision BLOB NOT NULL CHECK(length(revision) = 8),
    PRIMARY KEY(
        tenant_id, namespace_present, namespace_id, conference_id, principal_kind, principal_id
    ),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, conference_id)
        REFERENCES universal_conferences(tenant_id, namespace_present, namespace_id, conference_id)
        ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE UNIQUE INDEX universal_conference_participants_external_user
ON universal_conference_participants(
    tenant_id, namespace_present, namespace_id, conference_id, integration_id, external_user_id
);
";

pub(super) fn create_v32_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V32_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn create_v35_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE universal_conference_participants
             ADD COLUMN screen_share_allowed INTEGER NOT NULL DEFAULT 0
             CHECK(screen_share_allowed IN (0, 1));",
        )
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v32(connection: &Connection) -> Result<(), DurableStoreError> {
    super::organization_store::verify_schema_v31(connection)?;
    verify_table_columns(
        connection,
        "universal_conferences",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("conference_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 0),
            ("external_conference_id", "BLOB", 1, 0),
            ("create_idempotency_key", "TEXT", 1, 0),
            ("mode", "TEXT", 1, 0),
            ("lifecycle", "TEXT", 1, 0),
            ("starts_at_unix_ms", "INTEGER", 1, 0),
            ("planned_end_unix_ms", "INTEGER", 0, 0),
            ("join_before_seconds", "INTEGER", 1, 0),
            ("join_after_seconds", "INTEGER", 1, 0),
            ("timezone", "TEXT", 0, 0),
            ("entry_open", "INTEGER", 1, 0),
            ("revision", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "universal_conference_participants",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("conference_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 0),
            ("external_user_id", "BLOB", 1, 0),
            ("principal_kind", "TEXT", 1, 5),
            ("principal_id", "TEXT", 1, 6),
            ("role", "TEXT", 1, 0),
            ("audio_muted", "INTEGER", 1, 0),
            ("camera_allowed", "INTEGER", 1, 0),
            ("publish_audio_allowed", "INTEGER", 1, 0),
            ("publish_video_allowed", "INTEGER", 1, 0),
            ("active", "INTEGER", 1, 0),
            ("revision", "BLOB", 1, 0),
        ],
    )?;
    let external_participant_index_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'index' AND name = 'universal_conference_participants_external_user'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !external_participant_index_exists {
        return Err(DurableStoreError::Corrupt);
    }
    let duplicate_active_owner_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM universal_conference_participants
                WHERE active = 1 AND role = 'owner'
                GROUP BY tenant_id, namespace_present, namespace_id, conference_id
                HAVING COUNT(*) > 1
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if duplicate_active_owner_exists {
        return Err(DurableStoreError::Corrupt);
    }
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

pub(super) fn verify_schema_v35(connection: &Connection) -> Result<(), DurableStoreError> {
    super::organization_store::verify_schema_v31(connection)?;
    verify_table_columns(
        connection,
        "universal_conferences",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("conference_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 0),
            ("external_conference_id", "BLOB", 1, 0),
            ("create_idempotency_key", "TEXT", 1, 0),
            ("mode", "TEXT", 1, 0),
            ("lifecycle", "TEXT", 1, 0),
            ("starts_at_unix_ms", "INTEGER", 1, 0),
            ("planned_end_unix_ms", "INTEGER", 0, 0),
            ("join_before_seconds", "INTEGER", 1, 0),
            ("join_after_seconds", "INTEGER", 1, 0),
            ("timezone", "TEXT", 0, 0),
            ("entry_open", "INTEGER", 1, 0),
            ("revision", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "universal_conference_participants",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("conference_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 0),
            ("external_user_id", "BLOB", 1, 0),
            ("principal_kind", "TEXT", 1, 5),
            ("principal_id", "TEXT", 1, 6),
            ("role", "TEXT", 1, 0),
            ("audio_muted", "INTEGER", 1, 0),
            ("camera_allowed", "INTEGER", 1, 0),
            ("publish_audio_allowed", "INTEGER", 1, 0),
            ("publish_video_allowed", "INTEGER", 1, 0),
            ("active", "INTEGER", 1, 0),
            ("revision", "BLOB", 1, 0),
            ("screen_share_allowed", "INTEGER", 1, 0),
        ],
    )?;
    let external_participant_index_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'index' AND name = 'universal_conference_participants_external_user'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !external_participant_index_exists {
        return Err(DurableStoreError::Corrupt);
    }
    let duplicate_active_owner_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM universal_conference_participants
                WHERE active = 1 AND role = 'owner'
                GROUP BY tenant_id, namespace_present, namespace_id, conference_id
                HAVING COUNT(*) > 1
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if duplicate_active_owner_exists {
        return Err(DurableStoreError::Corrupt);
    }
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

#[derive(Debug)]
struct StoredConference {
    integration_id: String,
    external_conference_id: Vec<u8>,
    create_idempotency_key: String,
    mode: String,
    lifecycle: String,
    starts_at_unix_ms: i64,
    planned_end_unix_ms: Option<i64>,
    join_before_seconds: i64,
    join_after_seconds: i64,
    timezone: Option<String>,
    entry_open: i64,
    revision: Vec<u8>,
}

#[derive(Debug)]
struct StoredParticipant {
    integration_id: String,
    external_user_id: Vec<u8>,
    principal_kind: String,
    principal_id: String,
    role: String,
    audio_muted: i64,
    camera_allowed: i64,
    publish_audio_allowed: i64,
    publish_video_allowed: i64,
    active: i64,
    screen_share_allowed: i64,
    revision: Vec<u8>,
}

impl UniversalConferenceStore for SqliteLocalStore {
    fn persist_universal_conference_profile(
        &self,
        profile: &UniversalConferenceProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_profile(profile)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;

        if let Some(existing) = load_profile(&transaction, &profile.scope, &profile.conference_id)?
        {
            return if existing == *profile {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if let Some(existing) = load_profile_for_external(
            &transaction,
            &profile.scope,
            &profile.integration_id,
            &profile.external_conference_id,
        )? {
            return if existing == *profile {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        insert_profile(&transaction, profile)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn universal_conference_profile(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_profile(&connection, scope, conference_id)
    }

    fn universal_conference_profile_for_external(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_conference_id: &[u8],
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError> {
        validate_external_reference(external_conference_id)?;
        let connection = self.lock_connection()?;
        load_profile_for_external(&connection, scope, integration_id, external_conference_id)
    }

    fn transition_universal_conference(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        lifecycle: UniversalConferenceLifecycle,
        entry_open: bool,
    ) -> Result<UniversalConferenceProfile, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current =
            load_profile(&transaction, scope, conference_id)?.ok_or(DurableStoreError::Conflict)?;

        if current.revision == expected_revision.saturating_add(1)
            && current.lifecycle == lifecycle
            && current.entry_open == entry_open
        {
            return Ok(current);
        }
        let lifecycle_change_allowed = current.lifecycle == lifecycle
            && current.entry_open != entry_open
            || valid_lifecycle_transition(current.lifecycle, lifecycle);
        if current.revision != expected_revision || !lifecycle_change_allowed {
            return Err(DurableStoreError::Conflict);
        }

        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let changed = transaction
            .execute(
                "UPDATE universal_conferences \
                 SET lifecycle = ?1, entry_open = ?2, revision = ?3 \
                 WHERE tenant_id = ?4 AND namespace_present = ?5 AND namespace_id = ?6 \
                   AND conference_id = ?7 AND revision = ?8",
                params![
                    lifecycle_text(lifecycle),
                    bool_to_i64(entry_open),
                    encode_u64(next_revision).as_slice(),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    conference_id.as_opaque().as_str(),
                    encode_u64(expected_revision).as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Conflict);
        }
        let updated =
            load_profile(&transaction, scope, conference_id)?.ok_or(DurableStoreError::Corrupt)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(updated)
    }

    fn transition_universal_conference_with_event(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        lifecycle: UniversalConferenceLifecycle,
        entry_open: bool,
        event: Option<&EventEnvelope>,
    ) -> Result<UniversalConferenceProfile, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current =
            load_profile(&transaction, scope, conference_id)?.ok_or(DurableStoreError::Conflict)?;

        validate_conference_lifecycle_event(&current, expected_revision, lifecycle, event)?;

        if current.revision == expected_revision.saturating_add(1)
            && current.lifecycle == lifecycle
            && current.entry_open == entry_open
        {
            if let Some(event) = event {
                let _ = append_event_in_transaction(&transaction, event)?;
            }
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(current);
        }

        if current.revision != expected_revision
            || !valid_lifecycle_transition(current.lifecycle, lifecycle)
        {
            return Err(DurableStoreError::Conflict);
        }

        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if let Some(event) = event
            && event.logical_order != next_revision
        {
            return Err(DurableStoreError::InvalidRecord);
        }

        let namespace = namespace_storage_key(scope);
        let changed = transaction
            .execute(
                "UPDATE universal_conferences \
                 SET lifecycle = ?1, entry_open = ?2, revision = ?3 \
                 WHERE tenant_id = ?4 AND namespace_present = ?5 AND namespace_id = ?6 \
                   AND conference_id = ?7 AND revision = ?8",
                params![
                    lifecycle_text(lifecycle),
                    bool_to_i64(entry_open),
                    encode_u64(next_revision).as_slice(),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    conference_id.as_opaque().as_str(),
                    encode_u64(expected_revision).as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Conflict);
        }

        if let Some(event) = event {
            let _ = append_event_in_transaction(&transaction, event)?;
        }

        let updated =
            load_profile(&transaction, scope, conference_id)?.ok_or(DurableStoreError::Corrupt)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(updated)
    }

    fn persist_universal_conference_participant(
        &self,
        participant: &UniversalConferenceParticipantProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_participant(participant)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if load_profile(&transaction, &participant.scope, &participant.conference_id)?.is_none() {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing) = load_participant(
            &transaction,
            &participant.scope,
            &participant.conference_id,
            &participant.participant,
        )? {
            return if existing == *participant {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if let Some(existing) = load_participant_for_external(
            &transaction,
            &participant.scope,
            &participant.conference_id,
            &participant.integration_id,
            &participant.external_user_id,
        )? {
            return if existing == *participant {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        if participant.active {
            ensure_participant_capacity(
                &transaction,
                &participant.scope,
                &participant.conference_id,
            )?;
        }
        ensure_unique_active_owner(
            &transaction,
            &participant.scope,
            &participant.conference_id,
            &participant.participant,
            participant.role,
            participant.active,
        )?;
        insert_participant(&transaction, participant)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn universal_conference_participant(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        participant: &PrincipalRef,
    ) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_participant(&connection, scope, conference_id, participant)
    }

    fn universal_conference_participant_for_external(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        integration_id: &IntegrationId,
        external_user_id: &[u8],
    ) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError> {
        validate_external_reference(external_user_id)?;
        let connection = self.lock_connection()?;
        load_participant_for_external(
            &connection,
            scope,
            conference_id,
            integration_id,
            external_user_id,
        )
    }

    fn universal_conference_participants(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_PARTICIPANT_SCAN_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        load_participants(&connection, scope, conference_id, max_items)
    }

    fn active_universal_conference_participants(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_PARTICIPANT_SCAN_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        load_active_participants(&connection, scope, conference_id, max_items)
    }

    fn update_universal_conference_participant(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        participant: &PrincipalRef,
        expected_revision: u64,
        role: ConferenceParticipantRole,
        audio_muted: bool,
        camera_allowed: bool,
        publish_audio_allowed: bool,
        publish_video_allowed: bool,
        screen_share_allowed: bool,
        active: bool,
    ) -> Result<UniversalConferenceParticipantProfile, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_participant(&transaction, scope, conference_id, participant)?
            .ok_or(DurableStoreError::Conflict)?;

        if current.revision == expected_revision.saturating_add(1)
            && current.role == role
            && current.audio_muted == audio_muted
            && current.camera_allowed == camera_allowed
            && current.publish_audio_allowed == publish_audio_allowed
            && current.publish_video_allowed == publish_video_allowed
            && current.screen_share_allowed == screen_share_allowed
            && current.active == active
        {
            return Ok(current);
        }
        if current.revision != expected_revision {
            return Err(DurableStoreError::Conflict);
        }
        if active && !current.active {
            ensure_participant_capacity(&transaction, scope, conference_id)?;
        }
        ensure_unique_active_owner(
            &transaction,
            scope,
            conference_id,
            participant,
            role,
            active,
        )?;

        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let changed = transaction
            .execute(
                "UPDATE universal_conference_participants \
                 SET role = ?1, audio_muted = ?2, camera_allowed = ?3, \
                     publish_audio_allowed = ?4, publish_video_allowed = ?5, active = ?6, \
                     revision = ?7, screen_share_allowed = ?8 \
                 WHERE tenant_id = ?9 AND namespace_present = ?10 AND namespace_id = ?11 \
                   AND conference_id = ?12 AND principal_kind = ?13 AND principal_id = ?14 \
                   AND revision = ?15",
                params![
                    role_text(role),
                    bool_to_i64(audio_muted),
                    bool_to_i64(camera_allowed),
                    bool_to_i64(publish_audio_allowed),
                    bool_to_i64(publish_video_allowed),
                    bool_to_i64(active),
                    encode_u64(next_revision).as_slice(),
                    bool_to_i64(screen_share_allowed),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    conference_id.as_opaque().as_str(),
                    principal_kind_text(participant.kind),
                    participant.principal_id.as_opaque().as_str(),
                    encode_u64(expected_revision).as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Conflict);
        }

        let updated = load_participant(&transaction, scope, conference_id, participant)?
            .ok_or(DurableStoreError::Corrupt)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(updated)
    }
}

fn insert_profile(
    transaction: &Transaction<'_>,
    profile: &UniversalConferenceProfile,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&profile.scope);
    transaction
        .execute(
            "INSERT INTO universal_conferences (
                tenant_id, namespace_present, namespace_id, conference_id, integration_id,
                external_conference_id, create_idempotency_key, mode, lifecycle, starts_at_unix_ms,
                planned_end_unix_ms, join_before_seconds, join_after_seconds, timezone, entry_open, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                profile.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                profile.conference_id.as_opaque().as_str(),
                profile.integration_id.as_opaque().as_str(),
                profile.external_conference_id.as_slice(),
                profile.create_idempotency_key.as_str(),
                mode_text(profile.mode),
                lifecycle_text(profile.lifecycle),
                profile.schedule.starts_at_unix_ms,
                profile.schedule.planned_end_unix_ms,
                i64::from(profile.schedule.join_before_seconds),
                i64::from(profile.schedule.join_after_seconds),
                profile.schedule.timezone.as_deref(),
                bool_to_i64(profile.entry_open),
                encode_u64(profile.revision).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn ensure_participant_capacity(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let participant_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM universal_conference_participants
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4 AND active = 1",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if participant_count >= MAX_PARTICIPANTS_DB {
        Err(DurableStoreError::Full)
    } else {
        Ok(())
    }
}

fn ensure_unique_active_owner(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
    participant: &PrincipalRef,
    role: ConferenceParticipantRole,
    active: bool,
) -> Result<(), DurableStoreError> {
    if !active || role != ConferenceParticipantRole::Owner {
        return Ok(());
    }
    let namespace = namespace_storage_key(scope);
    let conflicting_owner_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM universal_conference_participants
                WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
                  AND conference_id = ?4 AND active = 1 AND role = 'owner'
                  AND NOT (principal_kind = ?5 AND principal_id = ?6)
            )",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
                principal_kind_text(participant.kind),
                participant.principal_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if conflicting_owner_exists {
        Err(DurableStoreError::Conflict)
    } else {
        Ok(())
    }
}

fn insert_participant(
    transaction: &Transaction<'_>,
    participant: &UniversalConferenceParticipantProfile,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&participant.scope);
    transaction
        .execute(
            "INSERT INTO universal_conference_participants (
                tenant_id, namespace_present, namespace_id, conference_id, integration_id,
                external_user_id, principal_kind, principal_id, role, audio_muted, camera_allowed,
                publish_audio_allowed, publish_video_allowed, active, revision, screen_share_allowed
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                participant.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                participant.conference_id.as_opaque().as_str(),
                participant.integration_id.as_opaque().as_str(),
                participant.external_user_id.as_slice(),
                principal_kind_text(participant.participant.kind),
                participant.participant.principal_id.as_opaque().as_str(),
                role_text(participant.role),
                bool_to_i64(participant.audio_muted),
                bool_to_i64(participant.camera_allowed),
                bool_to_i64(participant.publish_audio_allowed),
                bool_to_i64(participant.publish_video_allowed),
                bool_to_i64(participant.active),
                encode_u64(participant.revision).as_slice(),
                bool_to_i64(participant.screen_share_allowed),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_profile(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
) -> Result<Option<UniversalConferenceProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let stored = connection
        .query_row(
            "SELECT integration_id, external_conference_id, mode, lifecycle, starts_at_unix_ms,
                    create_idempotency_key, planned_end_unix_ms, join_before_seconds,
                    join_after_seconds, timezone, entry_open, revision
             FROM universal_conferences
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
            ],
            |row| {
                Ok(StoredConference {
                    integration_id: row.get(0)?,
                    external_conference_id: row.get(1)?,
                    mode: row.get(2)?,
                    lifecycle: row.get(3)?,
                    starts_at_unix_ms: row.get(4)?,
                    create_idempotency_key: row.get(5)?,
                    planned_end_unix_ms: row.get(6)?,
                    join_before_seconds: row.get(7)?,
                    join_after_seconds: row.get(8)?,
                    timezone: row.get(9)?,
                    entry_open: row.get(10)?,
                    revision: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    stored
        .map(|row| decode_profile(scope, conference_id, row))
        .transpose()
}

fn load_profile_for_external(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
    external_conference_id: &[u8],
) -> Result<Option<UniversalConferenceProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let conference_id = connection
        .query_row(
            "SELECT conference_id FROM universal_conferences
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND integration_id = ?4 AND external_conference_id = ?5",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                integration_id.as_opaque().as_str(),
                external_conference_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    match conference_id {
        Some(value) => {
            let id =
                GroupId::from_opaque(OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)?);
            load_profile(connection, scope, &id)
        }
        None => Ok(None),
    }
}

fn decode_profile(
    scope: &TenantScope,
    conference_id: &GroupId,
    row: StoredConference,
) -> Result<UniversalConferenceProfile, DurableStoreError> {
    let profile = UniversalConferenceProfile {
        scope: scope.clone(),
        conference_id: conference_id.clone(),
        integration_id: IntegrationId::from_opaque(
            OpaqueId::new(row.integration_id).map_err(|_| DurableStoreError::Corrupt)?,
        ),
        external_conference_id: row.external_conference_id,
        create_idempotency_key: row.create_idempotency_key,
        mode: parse_mode(&row.mode)?,
        lifecycle: parse_lifecycle(&row.lifecycle)?,
        schedule: ConferenceScheduleMetadata {
            starts_at_unix_ms: row.starts_at_unix_ms,
            planned_end_unix_ms: row.planned_end_unix_ms,
            join_before_seconds: u32::try_from(row.join_before_seconds)
                .map_err(|_| DurableStoreError::Corrupt)?,
            join_after_seconds: u32::try_from(row.join_after_seconds)
                .map_err(|_| DurableStoreError::Corrupt)?,
            timezone: row.timezone,
        },
        entry_open: parse_bool(row.entry_open)?,
        revision: decode_u64(&row.revision)?,
    };
    validate_profile(&profile)?;
    Ok(profile)
}

fn load_participant(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
    participant: &PrincipalRef,
) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let stored = connection
        .query_row(
            "SELECT integration_id, external_user_id, principal_kind, principal_id, role,
                    audio_muted, camera_allowed, publish_audio_allowed, publish_video_allowed,
                    active, revision, screen_share_allowed
             FROM universal_conference_participants
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4 AND principal_kind = ?5 AND principal_id = ?6",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
                principal_kind_text(participant.kind),
                participant.principal_id.as_opaque().as_str(),
            ],
            decode_stored_participant,
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    stored
        .map(|row| decode_participant(scope, conference_id, row))
        .transpose()
}

fn load_participant_for_external(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
    external_user_id: &[u8],
) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let stored = connection
        .query_row(
            "SELECT integration_id, external_user_id, principal_kind, principal_id, role,
                    audio_muted, camera_allowed, publish_audio_allowed, publish_video_allowed,
                    active, revision, screen_share_allowed
             FROM universal_conference_participants
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4 AND integration_id = ?5 AND external_user_id = ?6",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
                integration_id.as_opaque().as_str(),
                external_user_id,
            ],
            decode_stored_participant,
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    stored
        .map(|row| decode_participant(scope, conference_id, row))
        .transpose()
}

fn load_participants(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
    max_items: usize,
) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
    let mut statement = connection
        .prepare(
            "SELECT integration_id, external_user_id, principal_kind, principal_id, role,
                    audio_muted, camera_allowed, publish_audio_allowed, publish_video_allowed,
                    active, revision, screen_share_allowed
             FROM universal_conference_participants
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4
             ORDER BY principal_kind, principal_id
             LIMIT ?5",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
                limit,
            ],
            decode_stored_participant,
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        result.push(decode_participant(
            scope,
            conference_id,
            row.map_err(|error| map_sqlite_error(&error))?,
        )?);
    }
    Ok(result)
}

fn load_active_participants(
    connection: &Connection,
    scope: &TenantScope,
    conference_id: &GroupId,
    max_items: usize,
) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
    let mut statement = connection
        .prepare(
            "SELECT integration_id, external_user_id, principal_kind, principal_id, role,
                    audio_muted, camera_allowed, publish_audio_allowed, publish_video_allowed,
                    active, revision, screen_share_allowed
             FROM universal_conference_participants
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND conference_id = ?4 AND active = 1
             ORDER BY principal_kind, principal_id
             LIMIT ?5",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conference_id.as_opaque().as_str(),
                limit,
            ],
            decode_stored_participant,
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        result.push(decode_participant(
            scope,
            conference_id,
            row.map_err(|error| map_sqlite_error(&error))?,
        )?);
    }
    Ok(result)
}

fn decode_stored_participant(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredParticipant> {
    Ok(StoredParticipant {
        integration_id: row.get(0)?,
        external_user_id: row.get(1)?,
        principal_kind: row.get(2)?,
        principal_id: row.get(3)?,
        role: row.get(4)?,
        audio_muted: row.get(5)?,
        camera_allowed: row.get(6)?,
        publish_audio_allowed: row.get(7)?,
        publish_video_allowed: row.get(8)?,
        active: row.get(9)?,
        revision: row.get(10)?,
        screen_share_allowed: row.get(11)?,
    })
}

fn decode_participant(
    scope: &TenantScope,
    conference_id: &GroupId,
    row: StoredParticipant,
) -> Result<UniversalConferenceParticipantProfile, DurableStoreError> {
    let profile = UniversalConferenceParticipantProfile {
        scope: scope.clone(),
        conference_id: conference_id.clone(),
        integration_id: IntegrationId::from_opaque(
            OpaqueId::new(row.integration_id).map_err(|_| DurableStoreError::Corrupt)?,
        ),
        external_user_id: row.external_user_id,
        participant: PrincipalRef {
            principal_id: PrincipalId::from_opaque(
                OpaqueId::new(row.principal_id).map_err(|_| DurableStoreError::Corrupt)?,
            ),
            kind: parse_principal_kind(&row.principal_kind)?,
        },
        role: parse_role(&row.role)?,
        audio_muted: parse_bool(row.audio_muted)?,
        camera_allowed: parse_bool(row.camera_allowed)?,
        publish_audio_allowed: parse_bool(row.publish_audio_allowed)?,
        publish_video_allowed: parse_bool(row.publish_video_allowed)?,
        active: parse_bool(row.active)?,
        revision: decode_u64(&row.revision)?,
        screen_share_allowed: parse_bool(row.screen_share_allowed)?,
    };
    validate_participant(&profile)?;
    Ok(profile)
}

fn validate_profile(profile: &UniversalConferenceProfile) -> Result<(), DurableStoreError> {
    validate_external_reference(&profile.external_conference_id)?;
    if profile.revision == 0
        || profile.create_idempotency_key.is_empty()
        || profile.create_idempotency_key.len() > 256
        || profile.schedule.join_before_seconds > 31_536_000
        || profile.schedule.join_after_seconds > 31_536_000
        || profile
            .schedule
            .planned_end_unix_ms
            .is_some_and(|end| end < profile.schedule.starts_at_unix_ms)
        || profile
            .schedule
            .timezone
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 128)
    {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_participant(
    profile: &UniversalConferenceParticipantProfile,
) -> Result<(), DurableStoreError> {
    validate_external_reference(&profile.external_user_id)?;
    if profile.revision == 0 {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_external_reference(value: &[u8]) -> Result<(), DurableStoreError> {
    if value.is_empty() || value.len() > MAX_EXTERNAL_REFERENCE_BYTES {
        Err(DurableStoreError::InvalidRecord)
    } else {
        Ok(())
    }
}

fn validate_conference_lifecycle_event(
    current: &UniversalConferenceProfile,
    expected_revision: u64,
    lifecycle: UniversalConferenceLifecycle,
    event: Option<&EventEnvelope>,
) -> Result<(), DurableStoreError> {
    let expected_type = match lifecycle {
        UniversalConferenceLifecycle::Live => Some("conference.started"),
        UniversalConferenceLifecycle::Ended => Some("conference.ended"),
        UniversalConferenceLifecycle::Scheduled
        | UniversalConferenceLifecycle::Waiting
        | UniversalConferenceLifecycle::Ending => None,
    };
    match (expected_type, event) {
        (None, None) => Ok(()),
        (Some(expected_type), Some(event))
            if event.scope == current.scope
                && event.event_type == expected_type
                && event.logical_order == expected_revision.saturating_add(1)
                && event.actor.kind == ucr_model::ActorKind::System
                && event
                    .actor
                    .on_behalf_of
                    .as_ref()
                    .is_some_and(|principal_id| {
                        principal_id.as_opaque() == current.integration_id.as_opaque()
                    }) =>
        {
            Ok(())
        }
        _ => Err(DurableStoreError::InvalidRecord),
    }
}

const fn valid_lifecycle_transition(
    current: UniversalConferenceLifecycle,
    next: UniversalConferenceLifecycle,
) -> bool {
    matches!(
        (current, next),
        (
            UniversalConferenceLifecycle::Scheduled,
            UniversalConferenceLifecycle::Waiting | UniversalConferenceLifecycle::Live
        ) | (
            UniversalConferenceLifecycle::Waiting,
            UniversalConferenceLifecycle::Live
        ) | (
            UniversalConferenceLifecycle::Live,
            UniversalConferenceLifecycle::Ending
        ) | (
            UniversalConferenceLifecycle::Ending,
            UniversalConferenceLifecycle::Ended
        )
    )
}

const fn mode_text(value: UniversalConferenceMode) -> &'static str {
    match value {
        UniversalConferenceMode::Meeting => "meeting",
        UniversalConferenceMode::Webinar => "webinar",
        UniversalConferenceMode::Broadcast => "broadcast",
        UniversalConferenceMode::AudioRoom => "audio_room",
    }
}

fn parse_mode(value: &str) -> Result<UniversalConferenceMode, DurableStoreError> {
    match value {
        "meeting" => Ok(UniversalConferenceMode::Meeting),
        "webinar" => Ok(UniversalConferenceMode::Webinar),
        "broadcast" => Ok(UniversalConferenceMode::Broadcast),
        "audio_room" => Ok(UniversalConferenceMode::AudioRoom),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn lifecycle_text(value: UniversalConferenceLifecycle) -> &'static str {
    match value {
        UniversalConferenceLifecycle::Scheduled => "scheduled",
        UniversalConferenceLifecycle::Waiting => "waiting",
        UniversalConferenceLifecycle::Live => "live",
        UniversalConferenceLifecycle::Ending => "ending",
        UniversalConferenceLifecycle::Ended => "ended",
    }
}

fn parse_lifecycle(value: &str) -> Result<UniversalConferenceLifecycle, DurableStoreError> {
    match value {
        "scheduled" => Ok(UniversalConferenceLifecycle::Scheduled),
        "waiting" => Ok(UniversalConferenceLifecycle::Waiting),
        "live" => Ok(UniversalConferenceLifecycle::Live),
        "ending" => Ok(UniversalConferenceLifecycle::Ending),
        "ended" => Ok(UniversalConferenceLifecycle::Ended),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn role_text(value: ConferenceParticipantRole) -> &'static str {
    match value {
        ConferenceParticipantRole::Owner => "owner",
        ConferenceParticipantRole::Host => "host",
        ConferenceParticipantRole::Moderator => "moderator",
        ConferenceParticipantRole::Speaker => "speaker",
        ConferenceParticipantRole::Attendee => "attendee",
    }
}

fn parse_role(value: &str) -> Result<ConferenceParticipantRole, DurableStoreError> {
    match value {
        "owner" => Ok(ConferenceParticipantRole::Owner),
        "host" => Ok(ConferenceParticipantRole::Host),
        "moderator" => Ok(ConferenceParticipantRole::Moderator),
        "speaker" => Ok(ConferenceParticipantRole::Speaker),
        "attendee" => Ok(ConferenceParticipantRole::Attendee),
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

const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}
