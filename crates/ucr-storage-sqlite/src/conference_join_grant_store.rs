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

pub(super) fn verify_schema_v34(connection: &Connection) -> Result<(), DurableStoreError> {
    super::recording_store::verify_schema_v33(connection)?;
    verify_table_columns(
        connection,
        "conference_join_grants",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("session_id", "TEXT", 1, 4),
            ("conference_id", "TEXT", 1, 0),
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
        ],
    )?;
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
        transaction
            .execute(
                "INSERT INTO conference_join_grants (
                    tenant_id, namespace_present, namespace_id, session_id, conference_id,
                    integration_id, call_id, participant_kind, participant_id, device_id,
                    issued_at_unix_ms, not_before_unix_ms, expires_at_unix_ms, use_policy,
                    revoked, redeemed
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0, 0
                )",
                params![
                    grant.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    grant.session_id.as_opaque().as_str(),
                    grant.conference_id.as_opaque().as_str(),
                    grant.integration_id.as_opaque().as_str(),
                    grant.call_id.as_opaque().as_str(),
                    principal_kind_text(grant.participant.kind),
                    grant.participant.principal_id.as_opaque().as_str(),
                    grant.device_id.as_opaque().as_str(),
                    grant.issued_at_unix_ms,
                    grant.not_before_unix_ms,
                    grant.expires_at_unix_ms,
                    use_policy_text(grant.use_policy),
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
            "SELECT conference_id, integration_id, call_id, participant_kind, participant_id,
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
