use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{ConferenceJoinGrantStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    CallId, ConferenceJoinGrantRecord, ConferenceJoinGrantUsePolicy, DeviceId, GroupId,
    IntegrationId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, SessionId, TenantScope,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const FIRST_PARTY_MEDIA_JOIN_INTEGRATION: &str = "ucr-first-party-direct-media";

const V34_OBJECTS_SQL: &str = r"
CREATE TABLE conference_join_grants (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    conference_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    participant_kind TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    issued_at_unix_ms INTEGER NOT NULL CHECK(issued_at_unix_ms >= 0),
    not_before_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    use_policy TEXT NOT NULL CHECK(use_policy IN ('single_use', 'reusable')),
    revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
    redeemed INTEGER NOT NULL CHECK(redeemed IN (0, 1)),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, session_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, conference_id)
        REFERENCES universal_conferences(tenant_id, namespace_present, namespace_id, conference_id)
        ON DELETE CASCADE,
    CHECK(not_before_unix_ms >= issued_at_unix_ms),
    CHECK(expires_at_unix_ms > not_before_unix_ms),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE INDEX conference_join_grants_conference
ON conference_join_grants(tenant_id, namespace_present, namespace_id, conference_id);
";

pub(super) fn create_v34_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V34_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

/// New schema index: bounded expiry sweeps must not scan a growing history of
/// long-lived replay-prevention tombstones.
pub(super) fn create_v51_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    // Historical migration fixtures can already contain the v55 canonical
    // grant table while replaying an older user_version. Do not attempt to
    // add the same redaction column twice. For a genuinely old v50 table,
    // missing metadata_redacted must still be added by this migration.
    if has_metadata_redacted_column(transaction)? {
        if !has_media_group_column(transaction)? {
            return Err(DurableStoreError::Corrupt);
        }
    } else {
        transaction
            .execute_batch(
                "ALTER TABLE conference_join_grants
                 ADD COLUMN metadata_redacted INTEGER NOT NULL DEFAULT 0
                 CHECK(metadata_redacted IN (0,1));",
            )
            .map_err(|error| map_schema_change_error(&error))?;
    }
    transaction
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS conference_join_grants_expiry
             ON conference_join_grants(expires_at_unix_ms);
             -- Only unredacted rows appear in the bounded privacy sweep.
             CREATE INDEX IF NOT EXISTS conference_join_grants_pending_redaction
             ON conference_join_grants(expires_at_unix_ms)
             WHERE metadata_redacted=0;",
        )
        .map_err(|error| map_schema_change_error(&error))
}

// v55 keeps the SAME canonical grant owner while admitting an endpoint-owned
// first-party MLS Group as a different FK target from UniversalConference.
// The two references are mutually exclusive and both are durable FK-checked.
// Never fabricate a UniversalConference to make a first-party Join persist.
pub(super) fn create_v55_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    if has_media_group_column(transaction)? {
        // Historical migration fixtures can retain this newer table shape
        // while replaying an earlier user_version. Verify it after upgrade.
        return Ok(());
    }
    transaction.execute_batch(r"
        CREATE TABLE conference_join_grants_v55 (
            tenant_id TEXT NOT NULL,
            namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
            namespace_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            conference_id TEXT,
            integration_id TEXT NOT NULL,
            call_id TEXT NOT NULL,
            participant_kind TEXT NOT NULL,
            participant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            issued_at_unix_ms INTEGER NOT NULL CHECK(issued_at_unix_ms >= 0),
            not_before_unix_ms INTEGER NOT NULL,
            expires_at_unix_ms INTEGER NOT NULL,
            use_policy TEXT NOT NULL CHECK(use_policy IN ('single_use', 'reusable')),
            revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
            redeemed INTEGER NOT NULL CHECK(redeemed IN (0, 1)),
            metadata_redacted INTEGER NOT NULL DEFAULT 0 CHECK(metadata_redacted IN (0,1)),
            media_group_id TEXT,
            PRIMARY KEY(tenant_id, namespace_present, namespace_id, session_id),
            FOREIGN KEY(tenant_id, namespace_present, namespace_id, conference_id)
                REFERENCES universal_conferences(tenant_id, namespace_present, namespace_id, conference_id)
                ON DELETE CASCADE,
            FOREIGN KEY(tenant_id, namespace_present, namespace_id, media_group_id)
                REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id)
                ON DELETE CASCADE,
            CHECK((conference_id IS NULL) != (media_group_id IS NULL)),
            CHECK(media_group_id IS NULL OR
                  integration_id IN ('ucr-first-party-direct-media', 'expired')),
            CHECK(integration_id != 'ucr-first-party-direct-media' OR media_group_id IS NOT NULL),
            CHECK(not_before_unix_ms >= issued_at_unix_ms),
            CHECK(expires_at_unix_ms > not_before_unix_ms),
            CHECK((namespace_present = 0 AND namespace_id = '') OR
                  (namespace_present = 1 AND namespace_id <> ''))
        ) WITHOUT ROWID;
        INSERT INTO conference_join_grants_v55 (
            tenant_id, namespace_present, namespace_id, session_id, conference_id,
            integration_id, call_id, participant_kind, participant_id, device_id,
            issued_at_unix_ms, not_before_unix_ms, expires_at_unix_ms, use_policy,
            revoked, redeemed, metadata_redacted, media_group_id
        )
        SELECT tenant_id, namespace_present, namespace_id, session_id, conference_id,
               integration_id, call_id, participant_kind, participant_id, device_id,
               issued_at_unix_ms, not_before_unix_ms, expires_at_unix_ms, use_policy,
               revoked, redeemed, metadata_redacted, NULL
        FROM conference_join_grants;
        DROP TABLE conference_join_grants;
        ALTER TABLE conference_join_grants_v55 RENAME TO conference_join_grants;
        CREATE INDEX conference_join_grants_conference
            ON conference_join_grants(tenant_id, namespace_present, namespace_id, conference_id);
        CREATE INDEX conference_join_grants_media_group
            ON conference_join_grants(tenant_id, namespace_present, namespace_id, media_group_id);
        CREATE INDEX conference_join_grants_expiry
            ON conference_join_grants(expires_at_unix_ms);
        CREATE INDEX conference_join_grants_pending_redaction
            ON conference_join_grants(expires_at_unix_ms)
            WHERE metadata_redacted=0;
    ").map_err(|error| map_schema_change_error(&error))
}

fn has_metadata_redacted_column(connection: &Connection) -> Result<bool, DurableStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('conference_join_grants')
                       WHERE name='metadata_redacted')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

fn has_media_group_column(connection: &Connection) -> Result<bool, DurableStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('conference_join_grants')
                       WHERE name='media_group_id')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

pub(super) fn verify_v55_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    if !has_media_group_column(connection)? {
        return Err(DurableStoreError::Corrupt);
    }
    let group_fk: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list('conference_join_grants')
                       WHERE \"table\"='groups' AND \"from\"='media_group_id')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let index: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index'
                       AND name='conference_join_grants_media_group')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !group_fk || !index {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

pub(super) fn verify_v51_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    for name in [
        "conference_join_grants_expiry",
        "conference_join_grants_pending_redaction",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE type='index' AND name=?1)",
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

pub(super) fn verify_schema_v34(connection: &Connection) -> Result<(), DurableStoreError> {
    super::recording_store::verify_schema_v33(connection)?;
    verify_v34_objects(connection)
}

pub(super) fn verify_v34_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    // v34..v50 have the original shape. v51 adds an explicit redaction bit;
    // silently accepting a missing bit could re-expose previously scrubbed IDs.
    let mut columns = vec![
        ("tenant_id", "TEXT", 1, 1),
        ("namespace_present", "INTEGER", 1, 2),
        ("namespace_id", "TEXT", 1, 3),
        ("session_id", "TEXT", 1, 4),
        (
            "conference_id",
            "TEXT",
            i64::from(!has_media_group_column(connection)?),
            0,
        ),
        ("integration_id", "TEXT", 1, 0),
        ("call_id", "TEXT", 1, 0),
        ("participant_kind", "TEXT", 1, 0),
        ("participant_id", "TEXT", 1, 0),
        ("device_id", "TEXT", 1, 0),
        ("issued_at_unix_ms", "INTEGER", 1, 0),
        ("not_before_unix_ms", "INTEGER", 1, 0),
        ("expires_at_unix_ms", "INTEGER", 1, 0),
        ("use_policy", "TEXT", 1, 0),
        ("revoked", "INTEGER", 1, 0),
        ("redeemed", "INTEGER", 1, 0),
    ];
    if super::read_schema_version(connection)? >= 51
        || (has_media_group_column(connection)? && has_metadata_redacted_column(connection)?)
    {
        columns.push(("metadata_redacted", "INTEGER", 1, 0));
    }
    if has_media_group_column(connection)? {
        columns.push(("media_group_id", "TEXT", 0, 0));
    }
    // A legacy test fixture may remove the v51 redaction column from a v55
    // table, then replay the real v51 ALTER TABLE migration. SQLite appends
    // that column after media_group_id. Column order has no authority meaning,
    // but accept ONLY these two fully specified layouts (never extra columns).
    if verify_table_columns(connection, "conference_join_grants", &columns).is_err() {
        if !(has_media_group_column(connection)? && has_metadata_redacted_column(connection)?) {
            return Err(DurableStoreError::Corrupt);
        }
        let len = columns.len();
        columns.swap(len - 2, len - 1);
        verify_table_columns(connection, "conference_join_grants", &columns)?;
    }
    let index_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
            ["conference_join_grants_conference"],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !index_exists {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

impl ConferenceJoinGrantStore for SqliteLocalStore {
    fn persist_conference_join_grant(
        &self,
        grant: &ConferenceJoinGrantRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_grant(grant)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_grant(&transaction, &grant.scope, &grant.session_id)? {
            return if existing == *grant {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let namespace = namespace_storage_key(&grant.scope);
        let group_id = grant.conference_id.as_opaque().as_str();
        let (conference_id, media_group_id) =
            if grant.integration_id.as_opaque().as_str() == FIRST_PARTY_MEDIA_JOIN_INTEGRATION {
                (None, Some(group_id))
            } else {
                (Some(group_id), None)
            };
        transaction
            .execute(
                "INSERT INTO conference_join_grants (
                    tenant_id, namespace_present, namespace_id, session_id, conference_id,
                    integration_id, call_id, participant_kind, participant_id, device_id,
                    issued_at_unix_ms, not_before_unix_ms, expires_at_unix_ms, use_policy,
                    revoked, redeemed, metadata_redacted, media_group_id
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0, 0, 0, ?15
                )",
                params![
                    grant.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    grant.session_id.as_opaque().as_str(),
                    conference_id,
                    grant.integration_id.as_opaque().as_str(),
                    grant.call_id.as_opaque().as_str(),
                    principal_kind_text(grant.participant.kind),
                    grant.participant.principal_id.as_opaque().as_str(),
                    grant.device_id.as_opaque().as_str(),
                    grant.issued_at_unix_ms,
                    grant.not_before_unix_ms,
                    grant.expires_at_unix_ms,
                    use_policy_text(grant.use_policy),
                    media_group_id,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<ConferenceJoinGrantRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_grant(&connection, scope, session_id)
    }

    fn revoke_conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<ConferenceJoinGrantRecord, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current =
            load_grant(&transaction, scope, session_id)?.ok_or(DurableStoreError::Conflict)?;
        if !current.revoked {
            let namespace = namespace_storage_key(scope);
            transaction
                .execute(
                    "UPDATE conference_join_grants SET revoked=1
                     WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                       AND session_id=?4",
                    params![
                        scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        session_id.as_opaque().as_str(),
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        load_grant(&connection, scope, session_id)?.ok_or(DurableStoreError::Corrupt)
    }

    fn redeem_conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<ConferenceJoinGrantRecord, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current =
            load_grant(&transaction, scope, session_id)?.ok_or(DurableStoreError::Conflict)?;
        if current.revoked {
            return Err(DurableStoreError::PermissionDenied);
        }
        if current.use_policy == ConferenceJoinGrantUsePolicy::SingleUse && current.redeemed {
            return Err(DurableStoreError::Conflict);
        }
        if !current.redeemed {
            let namespace = namespace_storage_key(scope);
            transaction
                .execute(
                    "UPDATE conference_join_grants SET redeemed=1
                     WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                       AND session_id=?4 AND revoked=0",
                    params![
                        scope.tenant_id.as_opaque().as_str(),
                        namespace.present,
                        namespace.value,
                        session_id.as_opaque().as_str(),
                    ],
                )
                .map_err(|error| map_sqlite_error(&error))?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        load_grant(&connection, scope, session_id)?.ok_or(DurableStoreError::Corrupt)
    }

    fn prune_expired_conference_join_grants(
        &self,
        now_unix_ms: i64,
    ) -> Result<usize, DurableStoreError> {
        if now_unix_ms < 0 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        // Expired grants cannot authorize realtime activity, but their
        // original exact session IDs MUST remain to prevent an idempotent
        // IssueJoinGrant replay from minting a fresh, valid credential.
        // Sanitize identity-bearing fields in the same canonical table;
        // preserve the irreversible revoked/redeemed tombstone.
        // The bounded batch limits time holding the canonical store mutex.
        let sanitized = transaction
            .execute(
                "UPDATE conference_join_grants
                 SET integration_id='expired', call_id='expired',
                     participant_kind='person', participant_id='expired',
                     device_id='expired', revoked=1, redeemed=1,
                     metadata_redacted=1
                 WHERE (tenant_id, namespace_present, namespace_id, session_id) IN (
                   SELECT tenant_id, namespace_present, namespace_id, session_id
                   FROM conference_join_grants INDEXED BY conference_join_grants_pending_redaction
                   WHERE expires_at_unix_ms <= ?1 AND metadata_redacted=0
                   LIMIT 4096
                 )",
                params![now_unix_ms],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(sanitized)
    }
}

fn validate_grant(grant: &ConferenceJoinGrantRecord) -> Result<(), DurableStoreError> {
    if grant.issued_at_unix_ms < 0
        || grant.not_before_unix_ms < grant.issued_at_unix_ms
        || grant.expires_at_unix_ms <= grant.not_before_unix_ms
        || grant.revoked
        || grant.redeemed
    {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn load_grant(
    connection: &Connection,
    scope: &TenantScope,
    session_id: &SessionId,
) -> Result<Option<ConferenceJoinGrantRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT COALESCE(conference_id, media_group_id), integration_id, call_id, participant_kind, participant_id,
                    device_id, issued_at_unix_ms, not_before_unix_ms, expires_at_unix_ms,
                    use_policy, revoked, redeemed
             FROM conference_join_grants
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND session_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                session_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|stored| decode_grant(scope, session_id, stored))
        .transpose()
}

type StoredGrant = (
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    i64,
    i64,
);

fn decode_grant(
    scope: &TenantScope,
    session_id: &SessionId,
    stored: StoredGrant,
) -> Result<ConferenceJoinGrantRecord, DurableStoreError> {
    let (
        conference_id,
        integration_id,
        call_id,
        participant_kind,
        participant_id,
        device_id,
        issued_at_unix_ms,
        not_before_unix_ms,
        expires_at_unix_ms,
        use_policy,
        revoked,
        redeemed,
    ) = stored;
    let record = ConferenceJoinGrantRecord {
        scope: scope.clone(),
        conference_id: GroupId::from_opaque(opaque(conference_id)?),
        integration_id: IntegrationId::from_opaque(opaque(integration_id)?),
        call_id: CallId::from_opaque(opaque(call_id)?),
        participant: PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque(participant_id)?),
            kind: parse_principal_kind(&participant_kind)?,
        },
        device_id: DeviceId::from_opaque(opaque(device_id)?),
        session_id: session_id.clone(),
        issued_at_unix_ms,
        not_before_unix_ms,
        expires_at_unix_ms,
        use_policy: parse_use_policy(&use_policy)?,
        revoked: parse_bool(revoked)?,
        redeemed: parse_bool(redeemed)?,
    };
    if record.not_before_unix_ms < record.issued_at_unix_ms
        || record.expires_at_unix_ms <= record.not_before_unix_ms
    {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(record)
}

fn opaque(value: String) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}

fn parse_bool(value: i64) -> Result<bool, DurableStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn use_policy_text(value: ConferenceJoinGrantUsePolicy) -> &'static str {
    match value {
        ConferenceJoinGrantUsePolicy::SingleUse => "single_use",
        ConferenceJoinGrantUsePolicy::Reusable => "reusable",
    }
}

fn parse_use_policy(value: &str) -> Result<ConferenceJoinGrantUsePolicy, DurableStoreError> {
    match value {
        "single_use" => Ok(ConferenceJoinGrantUsePolicy::SingleUse),
        "reusable" => Ok(ConferenceJoinGrantUsePolicy::Reusable),
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

#[cfg(test)]
mod media_join_grant_tests {
    use super::*;
    use crate::message_store::tests::TestDb;
    use ucr_core::StorageProvider;
    use ucr_model::{PrincipalId, TenantId};

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test identifier")
    }

    #[test]
    fn first_party_media_grant_requires_existing_canonical_group() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("canonical store");
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(id("media-grant-tenant")),
            namespace_id: None,
        };
        let grant = ConferenceJoinGrantRecord {
            scope: scope.clone(),
            conference_id: GroupId::from_opaque(id("fp-mg-nonexistent")),
            integration_id: IntegrationId::from_opaque(id(FIRST_PARTY_MEDIA_JOIN_INTEGRATION)),
            call_id: CallId::from_opaque(id("fp-m-nonexistent")),
            participant: PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("alice")),
                kind: PrincipalKind::Person,
            },
            device_id: DeviceId::from_opaque(id("alice-device")),
            session_id: SessionId::from_opaque(id("missing-group-session")),
            issued_at_unix_ms: 1000,
            not_before_unix_ms: 1000,
            expires_at_unix_ms: 60000,
            use_policy: ConferenceJoinGrantUsePolicy::Reusable,
            revoked: false,
            redeemed: false,
        };
        assert!(
            store.persist_conference_join_grant(&grant).is_err(),
            "a media grant cannot create its own MLS Group or bypass the Group FK"
        );
        assert_eq!(
            store
                .conference_join_grant(&scope, &grant.session_id)
                .unwrap(),
            None
        );
    }

    #[test]
    fn v54_empty_grant_table_migrates_without_weakening_legacy_fk() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("current schema");
        drop(store);
        {
            let mut connection = Connection::open(db.path()).expect("historical fixture");
            connection
                .execute_batch("DROP TABLE conference_join_grants;")
                .expect("remove v55 table");
            let tx = connection.transaction().expect("fixture transaction");
            tx.execute_batch(V34_OBJECTS_SQL).expect("v34 grant schema");
            create_v51_objects(&tx).expect("v51 redaction schema");
            tx.pragma_update(None, "user_version", 54)
                .expect("v54 marker");
            tx.commit().expect("fixture commit");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v54 to v55");
        assert_eq!(migrated.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
        let connection = migrated.lock_connection().expect("read schema");
        verify_v55_objects(&connection).expect("media and legacy FKs");
    }
}
