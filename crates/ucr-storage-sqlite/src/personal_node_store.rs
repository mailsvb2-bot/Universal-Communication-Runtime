use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, PersonalNodeStore};
use ucr_model::{
    EndpointId, EndpointKind, NamespaceId, OpaqueId, PersonalNodeObject, PersonalNodeObjectId,
    PersonalNodeObjectKind, PersonalNodeProfile, PersonalNodeService, PersonalNodeState, TenantId,
    TenantScope,
};
use ucr_protocol::{
    MAX_PERSONAL_NODE_OBJECTS_PER_LIST, canonical_personal_node_object,
    canonical_personal_node_profile, validate_personal_node_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V30_OBJECTS_SQL: &str = r"
CREATE TABLE personal_node_profiles (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    endpoint_kind TEXT NOT NULL CHECK(endpoint_kind='personal_node'),
    services_mask INTEGER NOT NULL CHECK(services_mask BETWEEN 1 AND 31),
    state TEXT NOT NULL CHECK(state IN ('active','disabled')),
    generation BLOB NOT NULL CHECK(length(generation)=8),
    mailbox_capacity_bytes BLOB NOT NULL CHECK(length(mailbox_capacity_bytes)=8),
    cache_capacity_bytes BLOB NOT NULL CHECK(length(cache_capacity_bytes)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, endpoint_id),
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

const V30_OBJECTS_SQL_TAIL: &str = r"
CREATE TABLE personal_node_objects (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('mailbox','cache')),
    encryption_scheme TEXT NOT NULL,
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 16777216),
    ciphertext_sha256 BLOB NOT NULL CHECK(length(ciphertext_sha256)=32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    expires_at_unix_ms INTEGER,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, endpoint_id, object_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, endpoint_id)
      REFERENCES personal_node_profiles(tenant_id, namespace_present, namespace_id, endpoint_id)
      ON DELETE CASCADE,
    CHECK(expires_at_unix_ms IS NULL OR expires_at_unix_ms > created_at_unix_ms),
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v30_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V30_OBJECTS_SQL)
        .and_then(|()| transaction.execute_batch(V30_OBJECTS_SQL_TAIL))
        .map_err(|error| map_schema_change_error(&error))
}
pub(super) fn verify_schema_v30(connection: &Connection) -> Result<(), DurableStoreError> {
    super::federation_store::verify_schema_v29(connection)?;
    verify_table_columns(
        connection,
        "personal_node_profiles",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("endpoint_id", "TEXT", 1, 4),
            ("endpoint_kind", "TEXT", 1, 0),
            ("services_mask", "INTEGER", 1, 0),
            ("state", "TEXT", 1, 0),
            ("generation", "BLOB", 1, 0),
            ("mailbox_capacity_bytes", "BLOB", 1, 0),
            ("cache_capacity_bytes", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "personal_node_objects",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("endpoint_id", "TEXT", 1, 4),
            ("object_id", "TEXT", 1, 5),
            ("kind", "TEXT", 1, 0),
            ("encryption_scheme", "TEXT", 1, 0),
            ("ciphertext", "BLOB", 1, 0),
            ("ciphertext_sha256", "BLOB", 1, 0),
            ("created_at_unix_ms", "INTEGER", 1, 0),
            ("expires_at_unix_ms", "INTEGER", 0, 0),
        ],
    )?;
    verify_personal_node_rows(connection)?;
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error))?;
    let has_violation = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error))?
        .next()
        .map_err(|error| map_sqlite_error(&error))?
        .is_some();
    if has_violation {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn verify_personal_node_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, endpoint_id FROM personal_node_profiles")
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
    for (tenant, present, namespace, endpoint) in keys {
        let scope = stored_scope(&tenant, present, &namespace)?;
        let endpoint_id = EndpointId::from_opaque(parse_id(&endpoint)?);
        let profile = load_profile_from(connection, &scope, &endpoint_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        canonical_personal_node_profile(&profile).map_err(|_| DurableStoreError::Corrupt)?;
        for object in load_objects_from(connection, &scope, &endpoint_id, None, usize::MAX)? {
            canonical_personal_node_object(&object).map_err(|_| DurableStoreError::Corrupt)?;
        }
    }
    Ok(())
}
impl PersonalNodeStore for SqliteLocalStore {
    fn install_personal_node_profile(
        &self,
        profile: &PersonalNodeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_personal_node_profile(profile)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.state != PersonalNodeState::Active || canonical.generation != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_profile_from(&transaction, &canonical.scope, &canonical.endpoint_id)?
        {
            return if existing == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_profile(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<Option<PersonalNodeProfile>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_profile_from(&connection, scope, endpoint_id)
    }

    fn transition_personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: PersonalNodeState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_profile_from(&transaction, scope, endpoint_id)?
            .ok_or(DurableStoreError::Conflict)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.generation == next_generation && current.state == next_state {
            return Ok(DurableRecordStatus::Duplicate);
        }
        if current.generation != expected_generation {
            return Err(DurableStoreError::Conflict);
        }
        validate_personal_node_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let changed = transaction
            .execute(
                "UPDATE personal_node_profiles SET state=?1, generation=?2 \
                 WHERE tenant_id=?3 AND namespace_present=?4 AND namespace_id=?5 \
                   AND endpoint_id=?6 AND generation=?7",
                params![
                    state_text(next_state),
                    encode_u64(next_generation).as_slice(),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace_storage_key(scope).present,
                    namespace_storage_key(scope).value,
                    endpoint_id.as_opaque().as_str(),
                    encode_u64(expected_generation).as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Conflict);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn persist_personal_node_object(
        &self,
        object: &PersonalNodeObject,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical =
            canonical_personal_node_object(object).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_object_from(
            &transaction,
            &canonical.scope,
            &canonical.endpoint_id,
            &canonical.object_id,
        )? {
            return if existing == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let profile = load_profile_from(&transaction, &canonical.scope, &canonical.endpoint_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if profile.state != PersonalNodeState::Active
            || !profile_allows_object(&profile, canonical.kind)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        enforce_object_capacity(&transaction, &profile, &canonical)?;
        insert_object(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<Option<PersonalNodeObject>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_object_from(&connection, scope, endpoint_id, object_id)
    }

    fn personal_node_objects(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        kind: Option<PersonalNodeObjectKind>,
        max_items: usize,
    ) -> Result<Vec<PersonalNodeObject>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_PERSONAL_NODE_OBJECTS_PER_LIST {
            return Err(DurableStoreError::InvalidRecord);
        }
        let connection = self.lock_connection()?;
        load_objects_from(&connection, scope, endpoint_id, kind, max_items)
    }

    fn remove_personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let connection = self.lock_connection()?;
        let namespace = namespace_storage_key(scope);
        let changed = connection
            .execute(
                "DELETE FROM personal_node_objects \
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 \
                   AND endpoint_id=?4 AND object_id=?5",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    endpoint_id.as_opaque().as_str(),
                    object_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(if changed == 1 {
            DurableRecordStatus::Persisted
        } else {
            DurableRecordStatus::Duplicate
        })
    }
}

fn insert_profile(
    transaction: &Transaction<'_>,
    profile: &PersonalNodeProfile,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&profile.scope);
    transaction
        .execute(
            "INSERT INTO personal_node_profiles(
                tenant_id, namespace_present, namespace_id, endpoint_id, endpoint_kind, services_mask, state,
                generation, mailbox_capacity_bytes, cache_capacity_bytes)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                profile.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                profile.endpoint_id.as_opaque().as_str(),
                "personal_node",
                services_mask(&profile.services),
                state_text(profile.state),
                encode_u64(profile.generation).as_slice(),
                encode_u64(profile.mailbox_capacity_bytes).as_slice(),
                encode_u64(profile.cache_capacity_bytes).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_profile_from(
    connection: &Connection,
    scope: &TenantScope,
    endpoint_id: &EndpointId,
) -> Result<Option<PersonalNodeProfile>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT endpoint_kind, services_mask, state, generation, mailbox_capacity_bytes, cache_capacity_bytes \
             FROM personal_node_profiles WHERE tenant_id=?1 AND namespace_present=?2 \
             AND namespace_id=?3 AND endpoint_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                endpoint_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((endpoint_kind, mask, state, generation, mailbox_capacity, cache_capacity)) = row
    else {
        return Ok(None);
    };
    let profile = PersonalNodeProfile {
        scope: scope.clone(),
        endpoint_id: endpoint_id.clone(),
        endpoint_kind: parse_endpoint_kind(&endpoint_kind)?,
        services: services_from_mask(mask)?,
        state: parse_state(&state)?,
        generation: decode_u64(&generation)?,
        mailbox_capacity_bytes: decode_u64(&mailbox_capacity)?,
        cache_capacity_bytes: decode_u64(&cache_capacity)?,
    };
    canonical_personal_node_profile(&profile)
        .map(Some)
        .map_err(|_| DurableStoreError::Corrupt)
}

fn insert_object(
    transaction: &Transaction<'_>,
    object: &PersonalNodeObject,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&object.scope);
    transaction
        .execute(
            "INSERT INTO personal_node_objects(
                tenant_id, namespace_present, namespace_id, endpoint_id, object_id, kind,
                encryption_scheme, ciphertext, ciphertext_sha256, created_at_unix_ms,
                expires_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                object.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                object.endpoint_id.as_opaque().as_str(),
                object.object_id.as_opaque().as_str(),
                kind_text(object.kind),
                object.encryption_scheme,
                object.ciphertext,
                object.ciphertext_sha256.as_slice(),
                object.created_at_unix_ms,
                object.expires_at_unix_ms,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_object_from(
    connection: &Connection,
    scope: &TenantScope,
    endpoint_id: &EndpointId,
    object_id: &PersonalNodeObjectId,
) -> Result<Option<PersonalNodeObject>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT kind, encryption_scheme, ciphertext, ciphertext_sha256, \
             created_at_unix_ms, expires_at_unix_ms FROM personal_node_objects \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 \
             AND endpoint_id=?4 AND object_id=?5",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                endpoint_id.as_opaque().as_str(),
                object_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((kind, encryption_scheme, ciphertext, digest, created, expires)) = row else {
        return Ok(None);
    };
    let digest: [u8; 32] = digest.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    let object = PersonalNodeObject {
        object_id: object_id.clone(),
        scope: scope.clone(),
        endpoint_id: endpoint_id.clone(),
        kind: parse_kind(&kind)?,
        encryption_scheme,
        ciphertext,
        ciphertext_sha256: digest,
        created_at_unix_ms: created,
        expires_at_unix_ms: expires,
    };
    canonical_personal_node_object(&object)
        .map(Some)
        .map_err(|_| DurableStoreError::Corrupt)
}

fn load_objects_from(
    connection: &Connection,
    scope: &TenantScope,
    endpoint_id: &EndpointId,
    kind: Option<PersonalNodeObjectKind>,
    max_items: usize,
) -> Result<Vec<PersonalNodeObject>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = if max_items == usize::MAX {
        i64::MAX
    } else {
        i64::try_from(max_items).map_err(|_| DurableStoreError::InvalidRecord)?
    };
    let mut statement = connection
        .prepare(
            "SELECT object_id FROM personal_node_objects WHERE tenant_id=?1 \
             AND namespace_present=?2 AND namespace_id=?3 AND endpoint_id=?4 \
             AND (?5 IS NULL OR kind=?5) ORDER BY object_id LIMIT ?6",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let kind = kind.map(kind_text);
    let object_ids = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                endpoint_id.as_opaque().as_str(),
                kind,
                limit,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error))?;
    drop(statement);
    let mut objects = Vec::with_capacity(object_ids.len());
    for object_id in object_ids {
        let object_id = PersonalNodeObjectId::from_opaque(parse_id(&object_id)?);
        let object = load_object_from(connection, scope, endpoint_id, &object_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        objects.push(object);
    }
    Ok(objects)
}

fn enforce_object_capacity(
    transaction: &Transaction<'_>,
    profile: &PersonalNodeProfile,
    object: &PersonalNodeObject,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&profile.scope);
    let used: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(length(ciphertext)),0) FROM personal_node_objects \
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 \
             AND endpoint_id=?4 AND kind=?5",
            params![
                profile.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                profile.endpoint_id.as_opaque().as_str(),
                kind_text(object.kind),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let used = u64::try_from(used).map_err(|_| DurableStoreError::Corrupt)?;
    let incoming =
        u64::try_from(object.ciphertext.len()).map_err(|_| DurableStoreError::InvalidRecord)?;
    let capacity = match object.kind {
        PersonalNodeObjectKind::Mailbox => profile.mailbox_capacity_bytes,
        PersonalNodeObjectKind::Cache => profile.cache_capacity_bytes,
    };
    if used.checked_add(incoming).ok_or(DurableStoreError::Full)? > capacity {
        return Err(DurableStoreError::Full);
    }
    Ok(())
}

fn profile_allows_object(profile: &PersonalNodeProfile, kind: PersonalNodeObjectKind) -> bool {
    let service = match kind {
        PersonalNodeObjectKind::Mailbox => PersonalNodeService::EncryptedMailbox,
        PersonalNodeObjectKind::Cache => PersonalNodeService::Cache,
    };
    profile.services.contains(&service)
}

fn services_mask(services: &[PersonalNodeService]) -> i64 {
    services
        .iter()
        .fold(0_i64, |mask, service| mask | service_bit(*service))
}

const fn service_bit(service: PersonalNodeService) -> i64 {
    match service {
        PersonalNodeService::Sync => 1,
        PersonalNodeService::EncryptedMailbox => 2,
        PersonalNodeService::Relay => 4,
        PersonalNodeService::Cache => 8,
        PersonalNodeService::Bridge => 16,
    }
}

fn services_from_mask(mask: i64) -> Result<Vec<PersonalNodeService>, DurableStoreError> {
    if !(1..=31).contains(&mask) {
        return Err(DurableStoreError::Corrupt);
    }
    let mut services = Vec::new();
    for service in [
        PersonalNodeService::Sync,
        PersonalNodeService::EncryptedMailbox,
        PersonalNodeService::Relay,
        PersonalNodeService::Cache,
        PersonalNodeService::Bridge,
    ] {
        if mask & service_bit(service) != 0 {
            services.push(service);
        }
    }
    Ok(services)
}

fn parse_endpoint_kind(value: &str) -> Result<EndpointKind, DurableStoreError> {
    match value {
        "personal_node" => Ok(EndpointKind::PersonalNode),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn state_text(state: PersonalNodeState) -> &'static str {
    match state {
        PersonalNodeState::Active => "active",
        PersonalNodeState::Disabled => "disabled",
    }
}

fn parse_state(value: &str) -> Result<PersonalNodeState, DurableStoreError> {
    match value {
        "active" => Ok(PersonalNodeState::Active),
        "disabled" => Ok(PersonalNodeState::Disabled),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn kind_text(kind: PersonalNodeObjectKind) -> &'static str {
    match kind {
        PersonalNodeObjectKind::Mailbox => "mailbox",
        PersonalNodeObjectKind::Cache => "cache",
    }
}

fn parse_kind(value: &str) -> Result<PersonalNodeObjectKind, DurableStoreError> {
    match value {
        "mailbox" => Ok(PersonalNodeObjectKind::Mailbox),
        "cache" => Ok(PersonalNodeObjectKind::Cache),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn stored_scope(
    tenant: &str,
    namespace_present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let tenant_id = TenantId::from_opaque(parse_id(tenant)?);
    let namespace_id = match namespace_present {
        0 if namespace.is_empty() => None,
        1 if !namespace.is_empty() => Some(NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id,
        namespace_id,
    })
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(bytes: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}
