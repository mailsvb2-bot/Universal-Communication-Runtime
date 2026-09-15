use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, OrganizationModeStore};
use ucr_model::{
    DeviceId, EndpointId, EndpointKind, IdentityId, NamespaceId, OpaqueId,
    OrganizationManagedDeviceBinding, OrganizationManagedIdentityBinding, OrganizationModeProfile,
    OrganizationModeState, OrganizationService, PrincipalKind, PrincipalRef, TenantId, TenantScope,
};
use ucr_protocol::{
    MAX_ORGANIZATION_DIRECTORY_ITEMS, canonical_organization_mode_profile,
    validate_organization_managed_device_binding, validate_organization_managed_identity_binding,
    validate_organization_mode_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V31_OBJECTS_SQL: &str = r"
CREATE TABLE organization_mode_profiles (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present=1),
    namespace_id TEXT NOT NULL CHECK(namespace_id<>''),
    organization_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    endpoint_kind TEXT NOT NULL CHECK(endpoint_kind='organization_node'),
    services_mask INTEGER NOT NULL CHECK(services_mask BETWEEN 1 AND 63),
    state TEXT NOT NULL CHECK(state IN ('active','disabled')),
    generation BLOB NOT NULL CHECK(length(generation)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, organization_id)
) WITHOUT ROWID;
";
const V31_BINDINGS_SQL: &str = r"
CREATE TABLE organization_managed_identities (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present=1),
    namespace_id TEXT NOT NULL CHECK(namespace_id<>''),
    identity_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, identity_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, organization_id)
      REFERENCES organization_mode_profiles(tenant_id, namespace_present, namespace_id, organization_id)
      ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE organization_managed_devices (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present=1),
    namespace_id TEXT NOT NULL CHECK(namespace_id<>''),
    device_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, device_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, organization_id)
      REFERENCES organization_mode_profiles(tenant_id, namespace_present, namespace_id, organization_id)
      ON DELETE CASCADE
) WITHOUT ROWID;
";

pub(super) fn create_v31_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V31_OBJECTS_SQL)
        .and_then(|()| transaction.execute_batch(V31_BINDINGS_SQL))
        .map_err(|error| map_schema_change_error(&error))
}
pub(super) fn verify_schema_v31(connection: &Connection) -> Result<(), DurableStoreError> {
    super::personal_node_store::verify_schema_v30(connection)?;
    verify_table_columns(
        connection,
        "organization_mode_profiles",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("organization_id", "TEXT", 1, 4),
            ("endpoint_id", "TEXT", 1, 0),
            ("endpoint_kind", "TEXT", 1, 0),
            ("services_mask", "INTEGER", 1, 0),
            ("state", "TEXT", 1, 0),
            ("generation", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "organization_managed_identities",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("identity_id", "TEXT", 1, 4),
            ("organization_id", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "organization_managed_devices",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("device_id", "TEXT", 1, 4),
            ("organization_id", "TEXT", 1, 0),
        ],
    )?;
    verify_rows(connection)?;
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

fn verify_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, organization_id FROM organization_mode_profiles")
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
    for (tenant, present, namespace, organization) in keys {
        let scope = stored_scope(&tenant, present, &namespace)?;
        let principal = organization_principal(&organization)?;
        let profile =
            load_profile_from(connection, &scope, &principal)?.ok_or(DurableStoreError::Corrupt)?;
        canonical_organization_mode_profile(&profile).map_err(|_| DurableStoreError::Corrupt)?;
        for binding in load_identity_bindings(connection, &scope, &principal, usize::MAX)? {
            validate_organization_managed_identity_binding(&binding)
                .map_err(|_| DurableStoreError::Corrupt)?;
        }
        for binding in load_device_bindings(connection, &scope, &principal, usize::MAX)? {
            validate_organization_managed_device_binding(&binding)
                .map_err(|_| DurableStoreError::Corrupt)?;
        }
    }
    Ok(())
}
impl OrganizationModeStore for SqliteLocalStore {
    fn install_organization_mode_profile(
        &self,
        profile: &OrganizationModeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_organization_mode_profile(profile)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.state != OrganizationModeState::Active || canonical.generation != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) =
            load_profile_from(&transaction, &canonical.scope, &canonical.organization)?
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

    fn organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
    ) -> Result<Option<OrganizationModeProfile>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_profile_from(&connection, scope, organization)
    }
    fn transition_organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        expected_generation: u64,
        next_state: OrganizationModeState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_profile_from(&transaction, scope, organization)?
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
        validate_organization_mode_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let changed = transaction
            .execute(
                "UPDATE organization_mode_profiles SET state=?1, generation=?2 WHERE tenant_id=?3 AND namespace_present=?4 AND namespace_id=?5 AND organization_id=?6 AND generation=?7",
                params![
                    state_text(next_state),
                    encode_u64(next_generation).as_slice(),
                    scope.tenant_id.as_opaque().as_str(),
                    namespace_storage_key(scope).present,
                    namespace_storage_key(scope).value,
                    organization.principal_id.as_opaque().as_str(),
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
    fn bind_organization_managed_identity(
        &self,
        binding: &OrganizationManagedIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_organization_managed_identity_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let profile = load_profile_from(&transaction, &binding.scope, &binding.organization)?
            .ok_or(DurableStoreError::PermissionDenied)?;
        require_binding_service(&profile, OrganizationService::ManagedIdentities)?;
        if let Some(existing) =
            load_identity_binding(&transaction, &binding.scope, &binding.identity_id)?
        {
            return if existing == *binding {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_identity_binding(&transaction, binding)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn organization_managed_identity_binding(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<OrganizationManagedIdentityBinding>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_identity_binding(&connection, scope, identity_id)
    }
    fn organization_managed_identities(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedIdentityBinding>, DurableStoreError> {
        validate_list_bound(max_items)?;
        let connection = self.lock_connection()?;
        load_identity_bindings(&connection, scope, organization, max_items)
    }

    fn unbind_organization_managed_identity(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let connection = self.lock_connection()?;
        let key = namespace_storage_key(scope);
        let changed = connection
            .execute(
                "DELETE FROM organization_managed_identities WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    key.present,
                    key.value,
                    identity_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed == 1 {
            Ok(DurableRecordStatus::Persisted)
        } else {
            Err(DurableStoreError::Conflict)
        }
    }
    fn bind_organization_managed_device(
        &self,
        binding: &OrganizationManagedDeviceBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_organization_managed_device_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let profile = load_profile_from(&transaction, &binding.scope, &binding.organization)?
            .ok_or(DurableStoreError::PermissionDenied)?;
        require_binding_service(&profile, OrganizationService::ManagedDevices)?;
        if let Some(existing) =
            load_device_binding(&transaction, &binding.scope, &binding.device_id)?
        {
            return if existing == *binding {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_device_binding(&transaction, binding)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn organization_managed_device_binding(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<OrganizationManagedDeviceBinding>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_device_binding(&connection, scope, device_id)
    }
    fn organization_managed_devices(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedDeviceBinding>, DurableStoreError> {
        validate_list_bound(max_items)?;
        let connection = self.lock_connection()?;
        load_device_bindings(&connection, scope, organization, max_items)
    }

    fn unbind_organization_managed_device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let connection = self.lock_connection()?;
        let key = namespace_storage_key(scope);
        let changed = connection
            .execute(
                "DELETE FROM organization_managed_devices WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND device_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    key.present,
                    key.value,
                    device_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed == 1 {
            Ok(DurableRecordStatus::Persisted)
        } else {
            Err(DurableStoreError::Conflict)
        }
    }
}
fn require_binding_service(
    profile: &OrganizationModeProfile,
    service: OrganizationService,
) -> Result<(), DurableStoreError> {
    if profile.state != OrganizationModeState::Active || !profile.services.contains(&service) {
        return Err(DurableStoreError::PermissionDenied);
    }
    Ok(())
}

fn validate_list_bound(max_items: usize) -> Result<(), DurableStoreError> {
    if max_items == 0 || max_items > MAX_ORGANIZATION_DIRECTORY_ITEMS {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn insert_profile(
    transaction: &Transaction<'_>,
    profile: &OrganizationModeProfile,
) -> Result<(), DurableStoreError> {
    let key = namespace_storage_key(&profile.scope);
    transaction
        .execute(
            "INSERT INTO organization_mode_profiles (tenant_id,namespace_present,namespace_id,organization_id,endpoint_id,endpoint_kind,services_mask,state,generation) VALUES (?1,?2,?3,?4,?5,'organization_node',?6,?7,?8)",
            params![
                profile.scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                profile.organization.principal_id.as_opaque().as_str(),
                profile.endpoint_id.as_opaque().as_str(),
                services_mask(&profile.services),
                state_text(profile.state),
                encode_u64(profile.generation).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}
fn load_profile_from(
    connection: &Connection,
    scope: &TenantScope,
    organization: &PrincipalRef,
) -> Result<Option<OrganizationModeProfile>, DurableStoreError> {
    let key = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT endpoint_id,endpoint_kind,services_mask,state,generation FROM organization_mode_profiles WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND organization_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                organization.principal_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|(endpoint, kind, mask, state, generation)| {
        let endpoint_kind = parse_endpoint_kind(&kind)?;
        Ok(OrganizationModeProfile {
            scope: scope.clone(),
            organization: organization.clone(),
            endpoint_id: EndpointId::from_opaque(parse_id(&endpoint)?),
            endpoint_kind,
            services: parse_services_mask(mask)?,
            state: parse_state(&state)?,
            generation: decode_u64(&generation)?,
        })
    })
    .transpose()
}
fn insert_identity_binding(
    transaction: &Transaction<'_>,
    binding: &OrganizationManagedIdentityBinding,
) -> Result<(), DurableStoreError> {
    let key = namespace_storage_key(&binding.scope);
    transaction
        .execute(
            "INSERT INTO organization_managed_identities (tenant_id,namespace_present,namespace_id,identity_id,organization_id) VALUES (?1,?2,?3,?4,?5)",
            params![
                binding.scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                binding.identity_id.as_opaque().as_str(),
                binding.organization.principal_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_identity_binding(
    connection: &Connection,
    scope: &TenantScope,
    identity_id: &IdentityId,
) -> Result<Option<OrganizationManagedIdentityBinding>, DurableStoreError> {
    let key = namespace_storage_key(scope);
    let organization = connection
        .query_row(
            "SELECT organization_id FROM organization_managed_identities WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![scope.tenant_id.as_opaque().as_str(), key.present, key.value, identity_id.as_opaque().as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    organization
        .map(|value| {
            Ok(OrganizationManagedIdentityBinding {
                scope: scope.clone(),
                organization: organization_principal(&value)?,
                identity_id: identity_id.clone(),
            })
        })
        .transpose()
}
fn load_identity_bindings(
    connection: &Connection,
    scope: &TenantScope,
    organization: &PrincipalRef,
    max_items: usize,
) -> Result<Vec<OrganizationManagedIdentityBinding>, DurableStoreError> {
    let key = namespace_storage_key(scope);
    let limit = sql_limit(max_items);
    let mut statement = connection
        .prepare(
            "SELECT identity_id FROM organization_managed_identities WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND organization_id=?4 ORDER BY identity_id LIMIT ?5",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                organization.principal_id.as_opaque().as_str(),
                limit,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        let identity = row.map_err(|error| map_sqlite_error(&error))?;
        result.push(OrganizationManagedIdentityBinding {
            scope: scope.clone(),
            organization: organization.clone(),
            identity_id: IdentityId::from_opaque(parse_id(&identity)?),
        });
    }
    Ok(result)
}
fn insert_device_binding(
    transaction: &Transaction<'_>,
    binding: &OrganizationManagedDeviceBinding,
) -> Result<(), DurableStoreError> {
    let key = namespace_storage_key(&binding.scope);
    transaction
        .execute(
            "INSERT INTO organization_managed_devices (tenant_id,namespace_present,namespace_id,device_id,organization_id) VALUES (?1,?2,?3,?4,?5)",
            params![
                binding.scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                binding.device_id.as_opaque().as_str(),
                binding.organization.principal_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_device_binding(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<Option<OrganizationManagedDeviceBinding>, DurableStoreError> {
    let key = namespace_storage_key(scope);
    let organization = connection
        .query_row(
            "SELECT organization_id FROM organization_managed_devices WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND device_id=?4",
            params![scope.tenant_id.as_opaque().as_str(), key.present, key.value, device_id.as_opaque().as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    organization
        .map(|value| {
            Ok(OrganizationManagedDeviceBinding {
                scope: scope.clone(),
                organization: organization_principal(&value)?,
                device_id: device_id.clone(),
            })
        })
        .transpose()
}
fn load_device_bindings(
    connection: &Connection,
    scope: &TenantScope,
    organization: &PrincipalRef,
    max_items: usize,
) -> Result<Vec<OrganizationManagedDeviceBinding>, DurableStoreError> {
    let key = namespace_storage_key(scope);
    let limit = sql_limit(max_items);
    let mut statement = connection
        .prepare(
            "SELECT device_id FROM organization_managed_devices WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND organization_id=?4 ORDER BY device_id LIMIT ?5",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                key.present,
                key.value,
                organization.principal_id.as_opaque().as_str(),
                limit,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        let device = row.map_err(|error| map_sqlite_error(&error))?;
        result.push(OrganizationManagedDeviceBinding {
            scope: scope.clone(),
            organization: organization.clone(),
            device_id: DeviceId::from_opaque(parse_id(&device)?),
        });
    }
    Ok(result)
}
fn services_mask(services: &[OrganizationService]) -> i64 {
    services
        .iter()
        .fold(0_i64, |mask, service| mask | service_bit(*service))
}

fn service_bit(service: OrganizationService) -> i64 {
    match service {
        OrganizationService::PrivateDiscovery => 1,
        OrganizationService::PrivateRelay => 2,
        OrganizationService::PrivateSfu => 4,
        OrganizationService::PrivateBridge => 8,
        OrganizationService::ManagedIdentities => 16,
        OrganizationService::ManagedDevices => 32,
    }
}

fn parse_services_mask(mask: i64) -> Result<Vec<OrganizationService>, DurableStoreError> {
    if !(1..=63).contains(&mask) {
        return Err(DurableStoreError::Corrupt);
    }
    let mut services = Vec::new();
    for service in [
        OrganizationService::PrivateDiscovery,
        OrganizationService::PrivateRelay,
        OrganizationService::PrivateSfu,
        OrganizationService::PrivateBridge,
        OrganizationService::ManagedIdentities,
        OrganizationService::ManagedDevices,
    ] {
        if mask & service_bit(service) != 0 {
            services.push(service);
        }
    }
    Ok(services)
}
fn parse_endpoint_kind(value: &str) -> Result<EndpointKind, DurableStoreError> {
    match value {
        "organization_node" => Ok(EndpointKind::OrganizationNode),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn state_text(state: OrganizationModeState) -> &'static str {
    match state {
        OrganizationModeState::Active => "active",
        OrganizationModeState::Disabled => "disabled",
    }
}

fn parse_state(value: &str) -> Result<OrganizationModeState, DurableStoreError> {
    match value {
        "active" => Ok(OrganizationModeState::Active),
        "disabled" => Ok(OrganizationModeState::Disabled),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn organization_principal(value: &str) -> Result<PrincipalRef, DurableStoreError> {
    Ok(PrincipalRef {
        principal_id: ucr_model::PrincipalId::from_opaque(parse_id(value)?),
        kind: PrincipalKind::Organization,
    })
}

fn stored_scope(
    tenant: &str,
    namespace_present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    if namespace_present != 1 || namespace.is_empty() {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id: Some(NamespaceId::from_opaque(parse_id(namespace)?)),
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

fn sql_limit(max_items: usize) -> i64 {
    if max_items == usize::MAX {
        i64::MAX
    } else {
        i64::try_from(max_items).unwrap_or(i64::MAX)
    }
}
