use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, PrincipalIdentityBindingStore};
use ucr_model::{
    IdentityId, NamespaceId, OpaqueId, PrincipalId, PrincipalIdentityBinding, PrincipalKind,
    PrincipalRef, TenantId, TenantScope,
};
use ucr_protocol::validate_principal_identity_binding;

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V26_OBJECTS_SQL: &str = r"
CREATE TABLE principal_identity_bindings (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, principal_id, principal_kind),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> '')),
    CHECK(principal_kind <> 'device')
) WITHOUT ROWID;

CREATE TABLE group_mls_transitions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    actor_device_id TEXT NOT NULL,
    request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
    commit_bytes BLOB NOT NULL CHECK(length(commit_bytes) BETWEEN 1 AND 2097152),
    welcome_bytes BLOB CHECK(welcome_bytes IS NULL OR length(welcome_bytes) BETWEEN 1 AND 2097152),
    crypto_epoch BLOB NOT NULL CHECK(length(crypto_epoch)=8),
    crypto_state_ref TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES group_changes(tenant_id, namespace_present, namespace_id, event_id) ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v26_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V26_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v26(connection: &Connection) -> Result<(), DurableStoreError> {
    super::mesh_store::verify_schema_v25(connection)?;
    verify_table_columns(
        connection,
        "principal_identity_bindings",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("principal_id", "TEXT", 1, 4),
            ("principal_kind", "TEXT", 1, 5),
            ("identity_id", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "group_mls_transitions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("event_id", "TEXT", 1, 4),
            ("group_id", "TEXT", 1, 0),
            ("actor_device_id", "TEXT", 1, 0),
            ("request_fingerprint", "BLOB", 1, 0),
            ("commit_bytes", "BLOB", 1, 0),
            ("welcome_bytes", "BLOB", 0, 0),
            ("crypto_epoch", "BLOB", 1, 0),
            ("crypto_state_ref", "TEXT", 1, 0),
        ],
    )?;
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, principal_id,
                    principal_kind, identity_id FROM principal_identity_bindings",
        )
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
    for row in rows {
        let (tenant, namespace_present, namespace, principal_id, principal_kind, identity_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let binding = PrincipalIdentityBinding {
            scope: stored_scope(&tenant, namespace_present, &namespace)?,
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&principal_id)?),
                kind: decode_principal_kind(&principal_kind)?,
            },
            identity_id: IdentityId::from_opaque(parse_id(&identity_id)?),
        };
        validate_principal_identity_binding(&binding).map_err(|_| DurableStoreError::Corrupt)?;
        if !super::identity_store::identity_exists_in(
            connection,
            &binding.scope,
            &binding.identity_id,
        )? {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

impl PrincipalIdentityBindingStore for SqliteLocalStore {
    fn persist_principal_identity_binding(
        &self,
        binding: &PrincipalIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_principal_identity_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_binding_from(&transaction, &binding.scope, &binding.principal)?
        {
            return if existing == *binding {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if !super::identity_store::identity_exists_in(
            &transaction,
            &binding.scope,
            &binding.identity_id,
        )? {
            return Err(DurableStoreError::InvalidRecord);
        }
        let namespace = namespace_storage_key(&binding.scope);
        transaction
            .execute(
                "INSERT INTO principal_identity_bindings (
                    tenant_id, namespace_present, namespace_id,
                    principal_id, principal_kind, identity_id
                 ) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    binding.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    binding.principal.principal_id.as_opaque().as_str(),
                    encode_principal_kind(binding.principal.kind),
                    binding.identity_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn principal_identity_binding(
        &self,
        scope: &TenantScope,
        principal: &PrincipalRef,
    ) -> Result<Option<PrincipalIdentityBinding>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_binding_from(&connection, scope, principal)
    }
}

pub(super) fn load_binding_from(
    connection: &Connection,
    scope: &TenantScope,
    principal: &PrincipalRef,
) -> Result<Option<PrincipalIdentityBinding>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let identity = connection
        .query_row(
            "SELECT identity_id FROM principal_identity_bindings
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND principal_id=?4 AND principal_kind=?5",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                principal.principal_id.as_opaque().as_str(),
                encode_principal_kind(principal.kind),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    identity
        .map(|identity_id| {
            let binding = PrincipalIdentityBinding {
                scope: scope.clone(),
                principal: principal.clone(),
                identity_id: IdentityId::from_opaque(parse_id(&identity_id)?),
            };
            validate_principal_identity_binding(&binding)
                .map_err(|_| DurableStoreError::Corrupt)?;
            Ok(binding)
        })
        .transpose()
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
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

const fn encode_principal_kind(kind: PrincipalKind) -> &'static str {
    match kind {
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

fn decode_principal_kind(value: &str) -> Result<PrincipalKind, DurableStoreError> {
    match value {
        "person" => Ok(PrincipalKind::Person),
        "service_account" => Ok(PrincipalKind::ServiceAccount),
        "ai_agent" => Ok(PrincipalKind::AiAgent),
        "bot" => Ok(PrincipalKind::Bot),
        "organization" => Ok(PrincipalKind::Organization),
        "automation" => Ok(PrincipalKind::Automation),
        "external_platform" => Ok(PrincipalKind::ExternalPlatform),
        _ => Err(DurableStoreError::Corrupt),
    }
}
