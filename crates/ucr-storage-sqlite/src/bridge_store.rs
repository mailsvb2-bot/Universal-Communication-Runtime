use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{
    BridgeActionStore, BridgeRegistrationStore, DurableRecordStatus, DurableStoreError,
};
use ucr_model::{
    BridgeActionId, BridgeActionRecord, BridgeActionState, BridgeCapability, BridgeDataPermission,
    BridgeDegradation, BridgeDegradationReason, BridgeProviderAcceptance, BridgeProviderManifest,
    BridgeRegistration, BridgeRegistrationState, IntegrationId, NamespaceId, OpaqueId,
    ProtocolExtension, ProtocolVersion, TenantId, TenantScope,
};
use ucr_protocol::{
    bridge_manifest_supports, canonical_bridge_registration, validate_bridge_action_record,
    validate_bridge_action_transition, validate_bridge_registration_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V27_OBJECTS_SQL: &str = r"
CREATE TABLE bridge_registrations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    sdk_min_major INTEGER NOT NULL CHECK(sdk_min_major BETWEEN 0 AND 4294967295),
    sdk_min_minor INTEGER NOT NULL CHECK(sdk_min_minor BETWEEN 0 AND 4294967295),
    sdk_max_major INTEGER NOT NULL CHECK(sdk_max_major BETWEEN 0 AND 4294967295),
    sdk_max_minor INTEGER NOT NULL CHECK(sdk_max_minor BETWEEN 0 AND 4294967295),
    protocol_min_major INTEGER NOT NULL CHECK(protocol_min_major BETWEEN 0 AND 4294967295),
    protocol_min_minor INTEGER NOT NULL CHECK(protocol_min_minor BETWEEN 0 AND 4294967295),
    protocol_max_major INTEGER NOT NULL CHECK(protocol_max_major BETWEEN 0 AND 4294967295),
    protocol_max_minor INTEGER NOT NULL CHECK(protocol_max_minor BETWEEN 0 AND 4294967295),
    state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')),
    generation BLOB NOT NULL CHECK(length(generation)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, integration_id),
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE bridge_registration_capabilities (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    capability INTEGER NOT NULL CHECK(capability BETWEEN 1 AND 13),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, integration_id, capability),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, integration_id)
      REFERENCES bridge_registrations(tenant_id, namespace_present, namespace_id, integration_id)
      ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE bridge_registration_permissions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    permission INTEGER NOT NULL CHECK(permission BETWEEN 1 AND 4),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, integration_id, permission),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, integration_id)
      REFERENCES bridge_registrations(tenant_id, namespace_present, namespace_id, integration_id)
      ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE bridge_registration_extensions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    extension_index INTEGER NOT NULL CHECK(extension_index>=0),
    name TEXT NOT NULL,
    critical INTEGER NOT NULL CHECK(critical IN (0,1)),
    payload BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, integration_id, extension_index),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, integration_id)
      REFERENCES bridge_registrations(tenant_id, namespace_present, namespace_id, integration_id)
      ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE bridge_actions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    capability INTEGER NOT NULL CHECK(capability BETWEEN 1 AND 13),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    state TEXT NOT NULL CHECK(state IN ('prepared','in_flight','accepted','failed_not_accepted','acceptance_unknown')),
    external_message_id BLOB,
    degradation_requested INTEGER CHECK(degradation_requested IS NULL OR degradation_requested BETWEEN 1 AND 13),
    degradation_fallback INTEGER CHECK(degradation_fallback IS NULL OR degradation_fallback BETWEEN 1 AND 13),
    degradation_reason TEXT CHECK(degradation_reason IS NULL OR degradation_reason IN ('unsupported_capability','policy_restricted','provider_limited')),
    generation BLOB NOT NULL CHECK(length(generation)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, action_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, integration_id)
      REFERENCES bridge_registrations(tenant_id, namespace_present, namespace_id, integration_id),
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v27_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V27_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v27(connection: &Connection) -> Result<(), DurableStoreError> {
    super::principal_identity_binding_store::verify_schema_v26(connection)?;
    verify_v27_table_shapes(connection)?;
    verify_v27_registration_rows(connection)?;
    verify_v27_action_rows(connection)
}

fn verify_v27_table_shapes(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "bridge_registrations",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("integration_id", "TEXT", 1, 4),
            ("provider_id", "TEXT", 1, 0),
            ("sdk_min_major", "INTEGER", 1, 0),
            ("sdk_min_minor", "INTEGER", 1, 0),
            ("sdk_max_major", "INTEGER", 1, 0),
            ("sdk_max_minor", "INTEGER", 1, 0),
            ("protocol_min_major", "INTEGER", 1, 0),
            ("protocol_min_minor", "INTEGER", 1, 0),
            ("protocol_max_major", "INTEGER", 1, 0),
            ("protocol_max_minor", "INTEGER", 1, 0),
            ("state", "TEXT", 1, 0),
            ("generation", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "bridge_registration_capabilities",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("integration_id", "TEXT", 1, 4),
            ("capability", "INTEGER", 1, 5),
        ],
    )?;
    verify_table_columns(
        connection,
        "bridge_registration_permissions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("integration_id", "TEXT", 1, 4),
            ("permission", "INTEGER", 1, 5),
        ],
    )?;
    verify_table_columns(
        connection,
        "bridge_registration_extensions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("integration_id", "TEXT", 1, 4),
            ("extension_index", "INTEGER", 1, 5),
            ("name", "TEXT", 1, 0),
            ("critical", "INTEGER", 1, 0),
            ("payload", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "bridge_actions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("action_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 0),
            ("capability", "INTEGER", 1, 0),
            ("fingerprint", "BLOB", 1, 0),
            ("state", "TEXT", 1, 0),
            ("external_message_id", "BLOB", 0, 0),
            ("degradation_requested", "INTEGER", 0, 0),
            ("degradation_fallback", "INTEGER", 0, 0),
            ("degradation_reason", "TEXT", 0, 0),
            ("generation", "BLOB", 1, 0),
        ],
    )
}

fn verify_v27_registration_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, integration_id FROM bridge_registrations")
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
    for row in rows {
        let (tenant, present, namespace, integration) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let scope = stored_scope(&tenant, present, &namespace)?;
        let integration_id = IntegrationId::from_opaque(parse_id(&integration)?);
        load_registration_from(connection, &scope, &integration_id)?
            .ok_or(DurableStoreError::Corrupt)?;
    }
    Ok(())
}

fn verify_v27_action_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, action_id FROM bridge_actions")
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
    for row in rows {
        let (tenant, present, namespace, action) = row.map_err(|error| map_sqlite_error(&error))?;
        let scope = stored_scope(&tenant, present, &namespace)?;
        let action_id = BridgeActionId::from_opaque(parse_id(&action)?);
        let record =
            load_action_from(connection, &scope, &action_id)?.ok_or(DurableStoreError::Corrupt)?;
        let registration = load_registration_from(connection, &scope, &record.integration_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        if !bridge_manifest_supports(&registration.manifest, record.capability) {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

impl BridgeRegistrationStore for SqliteLocalStore {
    fn install_bridge_registration(
        &self,
        registration: &BridgeRegistration,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_bridge_registration(registration)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.generation != 1 || canonical.state != BridgeRegistrationState::Active {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_registration_from(&transaction, &canonical.scope, &canonical.integration_id)?
        {
            return if existing == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_registration(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn bridge_registration(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
    ) -> Result<Option<BridgeRegistration>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_registration_from(&connection, scope, integration_id)
    }

    fn transition_bridge_registration(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        expected_generation: u64,
        next_state: BridgeRegistrationState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_registration_from(&transaction, scope, integration_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.generation != expected_generation {
            if current.generation == expected_generation.saturating_add(1)
                && current.state == next_state
            {
                return Ok(DurableRecordStatus::Duplicate);
            }
            return Err(DurableStoreError::Conflict);
        }
        validate_bridge_registration_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(DurableStoreError::Full)?;
        let namespace = namespace_storage_key(scope);
        transaction
            .execute(
                "UPDATE bridge_registrations SET state=?5, generation=?6 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND integration_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    integration_id.as_opaque().as_str(),
                    encode_registration_state(next_state),
                    encode_u64(next_generation),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

impl BridgeActionStore for SqliteLocalStore {
    fn prepare_bridge_action(
        &self,
        record: &BridgeActionRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_bridge_action_record(record).map_err(|_| DurableStoreError::InvalidRecord)?;
        if record.generation != 1
            || record.state != BridgeActionState::Prepared
            || record.acceptance.is_some()
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let registration =
            load_registration_from(&transaction, &record.scope, &record.integration_id)?
                .ok_or(DurableStoreError::PermissionDenied)?;
        if registration.state != BridgeRegistrationState::Active
            || !bridge_manifest_supports(&registration.manifest, record.capability)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some(existing) = load_action_from(&transaction, &record.scope, &record.action_id)? {
            return if existing == *record {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let namespace = namespace_storage_key(&record.scope);
        transaction
            .execute(
                "INSERT INTO bridge_actions VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,NULL,NULL,NULL,?9)",
                params![
                    record.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    record.action_id.as_opaque().as_str(),
                    record.integration_id.as_opaque().as_str(),
                    encode_capability(record.capability),
                    record.fingerprint.as_slice(),
                    encode_action_state(record.state),
                    encode_u64(record.generation),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn bridge_action(
        &self,
        scope: &TenantScope,
        action_id: &BridgeActionId,
    ) -> Result<Option<BridgeActionRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_action_from(&connection, scope, action_id)
    }

    fn transition_bridge_action(
        &self,
        scope: &TenantScope,
        action_id: &BridgeActionId,
        expected_generation: u64,
        expected_state: BridgeActionState,
        next_state: BridgeActionState,
        acceptance: Option<&BridgeProviderAcceptance>,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_action_from(&transaction, scope, action_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let desired_acceptance = acceptance.cloned();
        if current.generation != expected_generation || current.state != expected_state {
            if current.generation == expected_generation.saturating_add(1)
                && current.state == next_state
                && current.acceptance == desired_acceptance
            {
                return Ok(DurableRecordStatus::Duplicate);
            }
            return Err(DurableStoreError::Conflict);
        }
        let registration = load_registration_from(&transaction, scope, &current.integration_id)?
            .ok_or(DurableStoreError::PermissionDenied)?;
        if expected_state != BridgeActionState::InFlight
            && (registration.state != BridgeRegistrationState::Active
                || !bridge_manifest_supports(&registration.manifest, current.capability))
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        validate_bridge_action_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(DurableStoreError::Full)?;
        let mut next = current.clone();
        next.state = next_state;
        next.generation = next_generation;
        next.acceptance.clone_from(&desired_acceptance);
        validate_bridge_action_record(&next).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(scope);
        let acceptance_columns = encode_acceptance_columns(desired_acceptance.as_ref());
        transaction
            .execute(
                "UPDATE bridge_actions SET state=?5, external_message_id=?6, degradation_requested=?7, degradation_fallback=?8, degradation_reason=?9, generation=?10 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND action_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    action_id.as_opaque().as_str(),
                    encode_action_state(next_state),
                    acceptance_columns.external_message_id,
                    acceptance_columns.degradation_requested,
                    acceptance_columns.degradation_fallback,
                    acceptance_columns.degradation_reason,
                    encode_u64(next_generation),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

fn insert_registration(
    transaction: &Transaction<'_>,
    registration: &BridgeRegistration,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&registration.scope);
    let manifest = &registration.manifest;
    transaction
        .execute(
            "INSERT INTO bridge_registrations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                registration.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                registration.integration_id.as_opaque().as_str(),
                manifest.provider_id,
                i64::from(manifest.sdk_min.major),
                i64::from(manifest.sdk_min.minor),
                i64::from(manifest.sdk_max.major),
                i64::from(manifest.sdk_max.minor),
                i64::from(manifest.protocol_min.major),
                i64::from(manifest.protocol_min.minor),
                i64::from(manifest.protocol_max.major),
                i64::from(manifest.protocol_max.minor),
                encode_registration_state(registration.state),
                encode_u64(registration.generation),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    for capability in &manifest.capabilities {
        transaction
            .execute(
                "INSERT INTO bridge_registration_capabilities VALUES (?1,?2,?3,?4,?5)",
                params![
                    registration.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    registration.integration_id.as_opaque().as_str(),
                    encode_capability(*capability)
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    for permission in &manifest.permissions {
        transaction
            .execute(
                "INSERT INTO bridge_registration_permissions VALUES (?1,?2,?3,?4,?5)",
                params![
                    registration.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    registration.integration_id.as_opaque().as_str(),
                    encode_permission(*permission)
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    for (index, extension) in manifest.extensions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO bridge_registration_extensions VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    registration.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    registration.integration_id.as_opaque().as_str(),
                    i64::try_from(index).map_err(|_| DurableStoreError::Full)?,
                    extension.name,
                    i64::from(extension.critical),
                    extension.payload
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn load_registration_from(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
) -> Result<Option<BridgeRegistration>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT provider_id,sdk_min_major,sdk_min_minor,sdk_max_major,sdk_max_minor,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,state,generation FROM bridge_registrations WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND integration_id=?4",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, integration_id.as_opaque().as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, i64>(8)?, row.get::<_, String>(9)?, row.get::<_, Vec<u8>>(10)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((
        provider_id,
        sdk_min_major,
        sdk_min_minor,
        sdk_max_major,
        sdk_max_minor,
        protocol_min_major,
        protocol_min_minor,
        protocol_max_major,
        protocol_max_minor,
        state,
        generation,
    )) = row
    else {
        return Ok(None);
    };
    let registration = BridgeRegistration {
        scope: scope.clone(),
        integration_id: integration_id.clone(),
        manifest: BridgeProviderManifest {
            provider_id,
            sdk_min: version(sdk_min_major, sdk_min_minor)?,
            sdk_max: version(sdk_max_major, sdk_max_minor)?,
            protocol_min: version(protocol_min_major, protocol_min_minor)?,
            protocol_max: version(protocol_max_major, protocol_max_minor)?,
            capabilities: load_capabilities(connection, scope, integration_id)?,
            permissions: load_permissions(connection, scope, integration_id)?,
            extensions: load_extensions(connection, scope, integration_id)?,
        },
        state: decode_registration_state(&state)?,
        generation: decode_u64(&generation)?,
    };
    canonical_bridge_registration(&registration)
        .map_err(|_| DurableStoreError::Corrupt)
        .map(Some)
}

fn load_capabilities(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
) -> Result<Vec<BridgeCapability>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection.prepare("SELECT capability FROM bridge_registration_capabilities WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND integration_id=?4 ORDER BY capability").map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                integration_id.as_opaque().as_str()
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| decode_capability(row.map_err(|error| map_sqlite_error(&error))?))
        .collect()
}

fn load_permissions(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
) -> Result<Vec<BridgeDataPermission>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection.prepare("SELECT permission FROM bridge_registration_permissions WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND integration_id=?4 ORDER BY permission").map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                integration_id.as_opaque().as_str()
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| decode_permission(row.map_err(|error| map_sqlite_error(&error))?))
        .collect()
}

fn load_extensions(
    connection: &Connection,
    scope: &TenantScope,
    integration_id: &IntegrationId,
) -> Result<Vec<ProtocolExtension>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection.prepare("SELECT name,critical,payload FROM bridge_registration_extensions WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND integration_id=?4 ORDER BY extension_index").map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                integration_id.as_opaque().as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| {
        let (name, critical, payload) = row.map_err(|error| map_sqlite_error(&error))?;
        let critical = match critical {
            0 => false,
            1 => true,
            _ => return Err(DurableStoreError::Corrupt),
        };
        Ok(ProtocolExtension {
            name,
            critical,
            payload,
        })
    })
    .collect()
}

fn load_action_from(
    connection: &Connection,
    scope: &TenantScope,
    action_id: &BridgeActionId,
) -> Result<Option<BridgeActionRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection.query_row(
        "SELECT integration_id,capability,fingerprint,state,external_message_id,degradation_requested,degradation_fallback,degradation_reason,generation FROM bridge_actions WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND action_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, action_id.as_opaque().as_str()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<Vec<u8>>>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<i64>>(6)?, row.get::<_, Option<String>>(7)?, row.get::<_, Vec<u8>>(8)?)),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    let Some((
        integration,
        capability,
        fingerprint,
        state,
        external_message_id,
        degradation_requested,
        degradation_fallback,
        degradation_reason,
        generation,
    )) = row
    else {
        return Ok(None);
    };
    let record = BridgeActionRecord {
        scope: scope.clone(),
        action_id: action_id.clone(),
        integration_id: IntegrationId::from_opaque(parse_id(&integration)?),
        capability: decode_capability(capability)?,
        fingerprint: fingerprint
            .try_into()
            .map_err(|_| DurableStoreError::Corrupt)?,
        state: decode_action_state(&state)?,
        acceptance: decode_acceptance_columns(
            decode_action_state(&state)?,
            external_message_id,
            degradation_requested,
            degradation_fallback,
            degradation_reason.as_deref(),
        )?,
        generation: decode_u64(&generation)?,
    };
    validate_bridge_action_record(&record).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(Some(record))
}

fn stored_scope(
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
fn version(major: i64, minor: i64) -> Result<ProtocolVersion, DurableStoreError> {
    Ok(ProtocolVersion::new(
        u32::try_from(major).map_err(|_| DurableStoreError::Corrupt)?,
        u32::try_from(minor).map_err(|_| DurableStoreError::Corrupt)?,
    ))
}
const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}
fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    Ok(u64::from_be_bytes(
        value.try_into().map_err(|_| DurableStoreError::Corrupt)?,
    ))
}
const fn encode_registration_state(value: BridgeRegistrationState) -> &'static str {
    match value {
        BridgeRegistrationState::Active => "active",
        BridgeRegistrationState::Disabled => "disabled",
        BridgeRegistrationState::Revoked => "revoked",
    }
}
fn decode_registration_state(value: &str) -> Result<BridgeRegistrationState, DurableStoreError> {
    match value {
        "active" => Ok(BridgeRegistrationState::Active),
        "disabled" => Ok(BridgeRegistrationState::Disabled),
        "revoked" => Ok(BridgeRegistrationState::Revoked),
        _ => Err(DurableStoreError::Corrupt),
    }
}
const fn encode_action_state(value: BridgeActionState) -> &'static str {
    match value {
        BridgeActionState::Prepared => "prepared",
        BridgeActionState::InFlight => "in_flight",
        BridgeActionState::Accepted => "accepted",
        BridgeActionState::FailedNotAccepted => "failed_not_accepted",
        BridgeActionState::AcceptanceUnknown => "acceptance_unknown",
    }
}
fn decode_action_state(value: &str) -> Result<BridgeActionState, DurableStoreError> {
    match value {
        "prepared" => Ok(BridgeActionState::Prepared),
        "in_flight" => Ok(BridgeActionState::InFlight),
        "accepted" => Ok(BridgeActionState::Accepted),
        "failed_not_accepted" => Ok(BridgeActionState::FailedNotAccepted),
        "acceptance_unknown" => Ok(BridgeActionState::AcceptanceUnknown),
        _ => Err(DurableStoreError::Corrupt),
    }
}
const fn encode_capability(value: BridgeCapability) -> i64 {
    value as i64
}
fn decode_capability(value: i64) -> Result<BridgeCapability, DurableStoreError> {
    match value {
        1 => Ok(BridgeCapability::Text),
        2 => Ok(BridgeCapability::Edit),
        3 => Ok(BridgeCapability::Delete),
        4 => Ok(BridgeCapability::Reaction),
        5 => Ok(BridgeCapability::Files),
        6 => Ok(BridgeCapability::Audio),
        7 => Ok(BridgeCapability::Video),
        8 => Ok(BridgeCapability::Group),
        9 => Ok(BridgeCapability::Presence),
        10 => Ok(BridgeCapability::Typing),
        11 => Ok(BridgeCapability::Calls),
        12 => Ok(BridgeCapability::Threads),
        13 => Ok(BridgeCapability::Reply),
        _ => Err(DurableStoreError::Corrupt),
    }
}
const fn encode_permission(value: BridgeDataPermission) -> i64 {
    value as i64
}
fn decode_permission(value: i64) -> Result<BridgeDataPermission, DurableStoreError> {
    match value {
        1 => Ok(BridgeDataPermission::MessageContent),
        2 => Ok(BridgeDataPermission::AttachmentReferences),
        3 => Ok(BridgeDataPermission::ExternalIdentityReferences),
        4 => Ok(BridgeDataPermission::InboundEvents),
        _ => Err(DurableStoreError::Corrupt),
    }
}

#[derive(Debug)]
struct BridgeAcceptanceColumns {
    external_message_id: Option<Vec<u8>>,
    degradation_requested: Option<i64>,
    degradation_fallback: Option<i64>,
    degradation_reason: Option<&'static str>,
}

fn encode_acceptance_columns(
    acceptance: Option<&BridgeProviderAcceptance>,
) -> BridgeAcceptanceColumns {
    let Some(acceptance) = acceptance else {
        return BridgeAcceptanceColumns {
            external_message_id: None,
            degradation_requested: None,
            degradation_fallback: None,
            degradation_reason: None,
        };
    };
    let (degradation_requested, degradation_fallback, degradation_reason) = acceptance
        .degradation
        .as_ref()
        .map_or((None, None, None), |degradation| {
            (
                Some(encode_capability(degradation.requested)),
                degradation.fallback.map(encode_capability),
                Some(encode_degradation_reason(degradation.reason)),
            )
        });
    BridgeAcceptanceColumns {
        external_message_id: acceptance.external_message_id.clone(),
        degradation_requested,
        degradation_fallback,
        degradation_reason,
    }
}

fn decode_acceptance_columns(
    state: BridgeActionState,
    external_message_id: Option<Vec<u8>>,
    requested: Option<i64>,
    fallback: Option<i64>,
    reason: Option<&str>,
) -> Result<Option<BridgeProviderAcceptance>, DurableStoreError> {
    if state != BridgeActionState::Accepted {
        if external_message_id.is_some()
            || requested.is_some()
            || fallback.is_some()
            || reason.is_some()
        {
            return Err(DurableStoreError::Corrupt);
        }
        return Ok(None);
    }
    let degradation = match (requested, fallback, reason) {
        (None, None, None) => None,
        (Some(requested), fallback, Some(reason)) => Some(BridgeDegradation {
            requested: decode_capability(requested)?,
            fallback: fallback.map(decode_capability).transpose()?,
            reason: decode_degradation_reason(reason)?,
        }),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(Some(BridgeProviderAcceptance {
        external_message_id,
        degradation,
    }))
}

const fn encode_degradation_reason(value: BridgeDegradationReason) -> &'static str {
    match value {
        BridgeDegradationReason::UnsupportedCapability => "unsupported_capability",
        BridgeDegradationReason::PolicyRestricted => "policy_restricted",
        BridgeDegradationReason::ProviderLimited => "provider_limited",
    }
}

fn decode_degradation_reason(value: &str) -> Result<BridgeDegradationReason, DurableStoreError> {
    match value {
        "unsupported_capability" => Ok(BridgeDegradationReason::UnsupportedCapability),
        "policy_restricted" => Ok(BridgeDegradationReason::PolicyRestricted),
        "provider_limited" => Ok(BridgeDegradationReason::ProviderLimited),
        _ => Err(DurableStoreError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SQLITE_SCHEMA_V26, SQLITE_SCHEMA_VERSION, message_store::tests::TestDb};
    use ucr_core::{BridgeActionStore, BridgeRegistrationStore, StorageProvider};
    use ucr_model::{
        BridgeActionId, BridgeActionRecord, BridgeActionState, BridgeCapability,
        BridgeDataPermission, BridgeProviderManifest, BridgeRegistration, BridgeRegistrationState,
        IntegrationId, NamespaceId, OpaqueId, ProtocolVersion, TenantId, TenantScope,
    };
    use ucr_protocol::BRIDGE_SDK_VERSION;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("bridge-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("bridge-namespace"))),
        }
    }

    fn integration(value: &str) -> IntegrationId {
        IntegrationId::from_opaque(oid(value))
    }

    fn manifest(capabilities: Vec<BridgeCapability>) -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: "vendor.reference.bridge".to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities,
            permissions: vec![
                BridgeDataPermission::MessageContent,
                BridgeDataPermission::InboundEvents,
            ],
            extensions: vec![],
        }
    }

    fn registration(id: &str, capabilities: Vec<BridgeCapability>) -> BridgeRegistration {
        BridgeRegistration {
            scope: scope(),
            integration_id: integration(id),
            manifest: manifest(capabilities),
            state: BridgeRegistrationState::Active,
            generation: 1,
        }
    }

    fn action(
        id: &str,
        integration_id: &IntegrationId,
        capability: BridgeCapability,
    ) -> BridgeActionRecord {
        BridgeActionRecord {
            scope: scope(),
            action_id: BridgeActionId::from_opaque(oid(id)),
            integration_id: integration_id.clone(),
            capability,
            fingerprint: [0x5a; 32],
            state: BridgeActionState::Prepared,
            acceptance: None,
            generation: 1,
        }
    }

    fn provider_acceptance(id: &[u8]) -> BridgeProviderAcceptance {
        BridgeProviderAcceptance {
            external_message_id: Some(id.to_vec()),
            degradation: None,
        }
    }

    #[test]
    fn bridge_registration_and_action_lifecycle_survive_restart() {
        let db = TestDb::new();
        let integration_id = integration("bridge-restart");
        let action_id = BridgeActionId::from_opaque(oid("bridge-action-restart"));
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            let registration = registration("bridge-restart", vec![BridgeCapability::Text]);
            assert_eq!(
                store.install_bridge_registration(&registration),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.install_bridge_registration(&registration),
                Ok(DurableRecordStatus::Duplicate)
            );
            let record = action(
                "bridge-action-restart",
                &integration_id,
                BridgeCapability::Text,
            );
            assert_eq!(
                store.prepare_bridge_action(&record),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.transition_bridge_action(
                    &scope(),
                    &action_id,
                    1,
                    BridgeActionState::Prepared,
                    BridgeActionState::InFlight,
                    None,
                ),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.transition_bridge_action(
                    &scope(),
                    &action_id,
                    2,
                    BridgeActionState::InFlight,
                    BridgeActionState::Accepted,
                    Some(&provider_acceptance(b"provider-message-1")),
                ),
                Ok(DurableRecordStatus::Persisted)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(reopened.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let registration = reopened
            .bridge_registration(&scope(), &integration_id)
            .expect("read registration")
            .expect("registration exists");
        assert_eq!(registration.state, BridgeRegistrationState::Active);
        assert_eq!(registration.generation, 1);
        let record = reopened
            .bridge_action(&scope(), &action_id)
            .expect("read action")
            .expect("action exists");
        assert_eq!(record.state, BridgeActionState::Accepted);
        assert_eq!(record.generation, 3);
        assert_eq!(
            record
                .acceptance
                .as_ref()
                .and_then(|value| value.external_message_id.as_deref()),
            Some(b"provider-message-1".as_slice())
        );
        assert_eq!(
            reopened.transition_bridge_action(
                &scope(),
                &action_id,
                2,
                BridgeActionState::InFlight,
                BridgeActionState::Accepted,
                Some(&provider_acceptance(b"provider-message-1")),
            ),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn disabled_or_unsupported_bridge_cannot_start_provider_action() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let integration_id = integration("bridge-disabled");
        let registration = registration("bridge-disabled", vec![BridgeCapability::Text]);
        store
            .install_bridge_registration(&registration)
            .expect("install registration");
        let unsupported = action(
            "bridge-action-unsupported",
            &integration_id,
            BridgeCapability::Video,
        );
        assert_eq!(
            store.prepare_bridge_action(&unsupported),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            store.transition_bridge_registration(
                &scope(),
                &integration_id,
                1,
                BridgeRegistrationState::Disabled,
            ),
            Ok(DurableRecordStatus::Persisted)
        );
        let disabled = action(
            "bridge-action-disabled",
            &integration_id,
            BridgeCapability::Text,
        );
        assert_eq!(
            store.prepare_bridge_action(&disabled),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn revoked_registration_and_unknown_acceptance_are_terminal() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let integration_id = integration("bridge-terminal");
        store
            .install_bridge_registration(&registration(
                "bridge-terminal",
                vec![BridgeCapability::Text],
            ))
            .expect("install registration");
        let action_id = BridgeActionId::from_opaque(oid("bridge-action-unknown"));
        store
            .prepare_bridge_action(&action(
                "bridge-action-unknown",
                &integration_id,
                BridgeCapability::Text,
            ))
            .expect("prepare action");
        store
            .transition_bridge_action(
                &scope(),
                &action_id,
                1,
                BridgeActionState::Prepared,
                BridgeActionState::InFlight,
                None,
            )
            .expect("start action");
        store
            .transition_bridge_action(
                &scope(),
                &action_id,
                2,
                BridgeActionState::InFlight,
                BridgeActionState::AcceptanceUnknown,
                None,
            )
            .expect("record ambiguity");
        assert_eq!(
            store.transition_bridge_action(
                &scope(),
                &action_id,
                3,
                BridgeActionState::AcceptanceUnknown,
                BridgeActionState::InFlight,
                None,
            ),
            Err(DurableStoreError::InvalidRecord)
        );
        store
            .transition_bridge_registration(
                &scope(),
                &integration_id,
                1,
                BridgeRegistrationState::Revoked,
            )
            .expect("revoke registration");
        assert_eq!(
            store.transition_bridge_registration(
                &scope(),
                &integration_id,
                2,
                BridgeRegistrationState::Active,
            ),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn migration_v26_to_v27_invents_no_bridge_state() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current store");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        {
            let connection = rusqlite::Connection::open(db.path()).expect("open raw sqlite");
            crate::test_remove_v27_objects(&connection).expect("remove v27 objects");
            connection
                .pragma_update(None, "user_version", SQLITE_SCHEMA_V26)
                .expect("downgrade schema marker to v26");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v26 to v27");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated.bridge_registration(&scope(), &integration("missing")),
            Ok(None)
        );
        assert_eq!(
            migrated.bridge_action(
                &scope(),
                &BridgeActionId::from_opaque(oid("missing-action")),
            ),
            Ok(None)
        );
    }
}
