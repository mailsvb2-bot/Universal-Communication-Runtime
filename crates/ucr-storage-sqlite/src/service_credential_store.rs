use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ucr_core::{DurableStoreError, ServiceCredentialStore};
use ucr_model::{
    NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal,
    ServiceCredentialId, ServiceCredentialRecord, ServiceCredentialState, TenantId, TenantScope,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V13_OBJECTS_SQL: &str = "
CREATE TABLE service_credentials (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    secret_digest BLOB NOT NULL CHECK(length(secret_digest) = 32),
    state TEXT NOT NULL CHECK(state IN ('active','revoked')),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, credential_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v13_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V13_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v13(connection: &Connection) -> Result<(), DurableStoreError> {
    super::permission_store::verify_schema_v12(connection)?;
    verify_table_columns(
        connection,
        "service_credentials",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("credential_id", "TEXT", 1, 4),
            ("principal_id", "TEXT", 1, 0),
            ("secret_digest", "BLOB", 1, 0),
            ("state", "TEXT", 1, 0),
        ],
    )?;
    verify_rows(connection)
}

impl ServiceCredentialStore for SqliteLocalStore {
    fn provision_service_credential(
        &self,
        record: &ServiceCredentialRecord,
    ) -> Result<(), DurableStoreError> {
        validate_new_record(record)?;
        let namespace = namespace_storage_key(&record.subject.scope);
        let connection = self.lock_connection()?;
        let existing = load_record(&connection, &record.subject.scope, &record.credential_id)?;
        if let Some(existing) = existing {
            return if existing == *record {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        connection
            .execute(
                "INSERT INTO service_credentials (
                    tenant_id, namespace_present, namespace_id, credential_id,
                    principal_id, secret_digest, state
                 ) VALUES (?1,?2,?3,?4,?5,?6,'active')",
                params![
                    record.subject.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    record.credential_id.as_opaque().as_str(),
                    record.subject.principal.principal_id.as_opaque().as_str(),
                    record.secret_digest.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(())
    }

    fn revoke_service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<(), DurableStoreError> {
        let namespace = namespace_storage_key(scope);
        let connection = self.lock_connection()?;
        connection
            .execute(
                "UPDATE service_credentials SET state='revoked'
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                   AND credential_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    credential_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(())
    }

    fn service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<Option<ServiceCredentialRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_record(&connection, scope, credential_id)
    }
}

fn load_record(
    connection: &Connection,
    scope: &TenantScope,
    credential_id: &ServiceCredentialId,
) -> Result<Option<ServiceCredentialRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT principal_id, secret_digest, state
             FROM service_credentials
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND credential_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                credential_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    row.map(|(principal_id, digest, state)| {
        decode_record(
            scope.clone(),
            credential_id.clone(),
            &principal_id,
            &digest,
            &state,
        )
    })
    .transpose()
}

fn verify_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, credential_id,
                    principal_id, secret_digest, state
             FROM service_credentials",
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
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (tenant, present, namespace, credential, principal, digest, state) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let scope = decode_scope(&tenant, present, &namespace)?;
        let credential_id = ServiceCredentialId::from_opaque(decode_id(&credential)?);
        decode_record(scope, credential_id, &principal, &digest, &state)?;
    }
    Ok(())
}

fn decode_record(
    scope: TenantScope,
    credential_id: ServiceCredentialId,
    principal_id: &str,
    digest: &[u8],
    state: &str,
) -> Result<ServiceCredentialRecord, DurableStoreError> {
    let secret_digest: [u8; 32] = digest.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    let state = match state {
        "active" => ServiceCredentialState::Active,
        "revoked" => ServiceCredentialState::Revoked,
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(ServiceCredentialRecord {
        credential_id,
        subject: ScopedPrincipal {
            scope,
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(decode_id(principal_id)?),
                kind: PrincipalKind::ServiceAccount,
            },
        },
        secret_digest,
        state,
    })
}

fn decode_scope(
    tenant: &str,
    namespace_present: i64,
    namespace_id: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match namespace_present {
        0 if namespace_id.is_empty() => None,
        1 if !namespace_id.is_empty() => Some(NamespaceId::from_opaque(decode_id(namespace_id)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(decode_id(tenant)?),
        namespace_id,
    })
}

fn decode_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

fn validate_new_record(record: &ServiceCredentialRecord) -> Result<(), DurableStoreError> {
    if record.subject.principal.kind != PrincipalKind::ServiceAccount
        || record.state != ServiceCredentialState::Active
    {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use ucr_core::{
        PermissionGrantStore, ServiceAuthenticationError, ServiceCredentialStore, StorageProvider,
        authenticate_service_principal, issue_service_credential,
    };
    use ucr_model::{
        NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId, PrincipalKind,
        PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
    };

    use ucr_protocol::CONVERSATION_READ_PERMISSION;

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_V12, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(90_000);

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn subject() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(oid("namespace-a"))),
            },
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("service-a")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn temp_db(label: &str) -> PathBuf {
        let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ucr-{label}-{}-{sequence}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn credential_survives_restart_and_revocation_remains_effective() {
        let path = temp_db("service-credential");
        let service = subject();
        let (record, secret) = issue_service_credential(&service).expect("issue");
        {
            let store = SqliteLocalStore::open(&path).expect("open");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
            store
                .provision_service_credential(&record)
                .expect("persist credential");
            assert_eq!(
                authenticate_service_principal(
                    &store,
                    &service.scope,
                    &record.credential_id,
                    &secret,
                ),
                Ok(service.clone())
            );
        }
        {
            let store = SqliteLocalStore::open(&path).expect("reopen");
            assert_eq!(
                authenticate_service_principal(
                    &store,
                    &service.scope,
                    &record.credential_id,
                    &secret,
                ),
                Ok(service.clone())
            );
            store
                .revoke_service_credential(&service.scope, &record.credential_id)
                .expect("revoke");
        }
        {
            let store = SqliteLocalStore::open(&path).expect("reopen revoked");
            assert_eq!(
                authenticate_service_principal(
                    &store,
                    &service.scope,
                    &record.credential_id,
                    &secret,
                ),
                Err(ServiceAuthenticationError::AuthenticationFailed)
            );
        }
        let _ = fs::remove_file(path);
    }
    #[test]
    fn v12_to_v13_migration_preserves_permissions_and_starts_without_credentials() {
        let path = temp_db("service-credential-migration");
        let service = subject();
        let grant = PermissionGrant {
            grantee: service.clone(),
            permission: CONVERSATION_READ_PERMISSION.to_owned(),
            scope: PermissionScope::Exact(service.scope.clone()),
        };
        {
            let store = SqliteLocalStore::open(&path).expect("initialize current");
            store
                .grant_permission(&grant)
                .expect("seed v12 permission state");
        }
        let connection = rusqlite::Connection::open(&path).expect("raw connection");
        connection
            .execute_batch("DROP TABLE external_identity_bindings; DROP TABLE service_audit_operations; DROP TABLE communication_intent_extensions; DROP TABLE communication_intent_transports; DROP TABLE communication_intents; DROP TABLE devices; DROP TRIGGER service_audit_no_update; DROP TRIGGER service_audit_no_delete; DROP INDEX service_audit_scope_sequence; DROP TABLE service_audit_records; DROP TABLE service_quota_usage; DROP TABLE service_quota_policies; DROP TABLE service_credentials;")
            .expect("remove v13 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V12)
            .expect("v12 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(&path).expect("migrate v12 to v13");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(migrated.permission_grants_for(&service), Ok(vec![grant]));
        let (record, _) = issue_service_credential(&service).expect("issue test credential");
        assert_eq!(
            migrated.service_credential(&service.scope, &record.credential_id),
            Ok(None)
        );
        let _ = fs::remove_file(path);
    }
}
