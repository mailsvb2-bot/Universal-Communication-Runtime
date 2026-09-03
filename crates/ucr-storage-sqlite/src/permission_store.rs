use rusqlite::{Connection, Transaction, params};
use ucr_core::{AuthorizationEvaluator, DurableStoreError, PermissionGrantStore};
use ucr_model::{
    AuthorizationRequest, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalKind,
    ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{CanonicalError, CanonicalErrorCode, validate_permission_grant};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V12_OBJECTS_SQL: &str = "
CREATE TABLE permission_grants (
    grantee_tenant_id TEXT NOT NULL,
    grantee_namespace_present INTEGER NOT NULL CHECK(grantee_namespace_present IN (0, 1)),
    grantee_namespace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL CHECK(principal_kind IN (
        'person','device','service_account','ai_agent','bot','organization','automation','external_platform'
    )),
    permission TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('exact','tenant_wide')),
    resource_tenant_id TEXT NOT NULL,
    resource_namespace_present INTEGER NOT NULL CHECK(resource_namespace_present IN (0, 1)),
    resource_namespace_id TEXT NOT NULL,
    PRIMARY KEY(
        grantee_tenant_id, grantee_namespace_present, grantee_namespace_id,
        principal_id, principal_kind, permission, scope_kind,
        resource_tenant_id, resource_namespace_present, resource_namespace_id
    ),
    CHECK((grantee_namespace_present = 0 AND grantee_namespace_id = '') OR
          (grantee_namespace_present = 1 AND grantee_namespace_id <> '')),
    CHECK((resource_namespace_present = 0 AND resource_namespace_id = '') OR
          (resource_namespace_present = 1 AND resource_namespace_id <> '')),
    CHECK(scope_kind = 'exact' OR (
        grantee_namespace_present = 0 AND
        resource_tenant_id = grantee_tenant_id AND
        resource_namespace_present = 0 AND resource_namespace_id = ''
    ))
) WITHOUT ROWID;
";

pub(super) fn create_v12_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V12_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v12(connection: &Connection) -> Result<(), DurableStoreError> {
    super::trusted_key_store::verify_schema_v11(connection)?;
    verify_table_columns(
        connection,
        "permission_grants",
        &[
            ("grantee_tenant_id", "TEXT", 1, 1),
            ("grantee_namespace_present", "INTEGER", 1, 2),
            ("grantee_namespace_id", "TEXT", 1, 3),
            ("principal_id", "TEXT", 1, 4),
            ("principal_kind", "TEXT", 1, 5),
            ("permission", "TEXT", 1, 6),
            ("scope_kind", "TEXT", 1, 7),
            ("resource_tenant_id", "TEXT", 1, 8),
            ("resource_namespace_present", "INTEGER", 1, 9),
            ("resource_namespace_id", "TEXT", 1, 10),
        ],
    )?;
    verify_permission_rows(connection)
}

impl PermissionGrantStore for SqliteLocalStore {
    fn grant_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError> {
        validate_permission_grant(grant).map_err(|_| DurableStoreError::InvalidRecord)?;
        let connection = self.lock_connection()?;
        let grantee_namespace = namespace_storage_key(&grant.grantee.scope);
        let (scope_kind, resource_scope) = grant_scope_storage(grant);
        let resource_namespace = namespace_storage_key(&resource_scope);
        connection
            .execute(
                "INSERT OR IGNORE INTO permission_grants (
                    grantee_tenant_id, grantee_namespace_present, grantee_namespace_id,
                    principal_id, principal_kind, permission, scope_kind,
                    resource_tenant_id, resource_namespace_present, resource_namespace_id
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    grant.grantee.scope.tenant_id.as_opaque().as_str(),
                    grantee_namespace.present,
                    grantee_namespace.value,
                    grant.grantee.principal.principal_id.as_opaque().as_str(),
                    principal_kind_text(grant.grantee.principal.kind),
                    grant.permission,
                    scope_kind,
                    resource_scope.tenant_id.as_opaque().as_str(),
                    resource_namespace.present,
                    resource_namespace.value,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(())
    }

    fn revoke_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError> {
        validate_permission_grant(grant).map_err(|_| DurableStoreError::InvalidRecord)?;
        let connection = self.lock_connection()?;
        let grantee_namespace = namespace_storage_key(&grant.grantee.scope);
        let (scope_kind, resource_scope) = grant_scope_storage(grant);
        let resource_namespace = namespace_storage_key(&resource_scope);
        connection
            .execute(
                "DELETE FROM permission_grants
                 WHERE grantee_tenant_id=?1 AND grantee_namespace_present=?2
                   AND grantee_namespace_id=?3 AND principal_id=?4 AND principal_kind=?5
                   AND permission=?6 AND scope_kind=?7 AND resource_tenant_id=?8
                   AND resource_namespace_present=?9 AND resource_namespace_id=?10",
                params![
                    grant.grantee.scope.tenant_id.as_opaque().as_str(),
                    grantee_namespace.present,
                    grantee_namespace.value,
                    grant.grantee.principal.principal_id.as_opaque().as_str(),
                    principal_kind_text(grant.grantee.principal.kind),
                    grant.permission,
                    scope_kind,
                    resource_scope.tenant_id.as_opaque().as_str(),
                    resource_namespace.present,
                    resource_namespace.value,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(())
    }

    fn permission_grants_for(
        &self,
        subject: &ScopedPrincipal,
    ) -> Result<Vec<PermissionGrant>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_permission_grants(&connection, subject)
    }
}

impl AuthorizationEvaluator for SqliteLocalStore {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        let grants = self
            .permission_grants_for(&request.subject)
            .map_err(map_authorization_store_error)?;
        ucr_protocol::authorize(request, &grants).map_err(CanonicalError::from)
    }
}

fn load_permission_grants(
    connection: &Connection,
    subject: &ScopedPrincipal,
) -> Result<Vec<PermissionGrant>, DurableStoreError> {
    let namespace = namespace_storage_key(&subject.scope);
    let mut statement = connection
        .prepare(
            "SELECT permission, scope_kind, resource_tenant_id,
                    resource_namespace_present, resource_namespace_id
             FROM permission_grants
             WHERE grantee_tenant_id=?1 AND grantee_namespace_present=?2
               AND grantee_namespace_id=?3 AND principal_id=?4 AND principal_kind=?5
             ORDER BY permission, scope_kind, resource_tenant_id,
                      resource_namespace_present, resource_namespace_id",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                subject.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                subject.principal.principal_id.as_opaque().as_str(),
                principal_kind_text(subject.principal.kind),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| {
        let (permission, scope_kind, tenant, namespace_present, namespace_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        decode_grant(
            subject.clone(),
            permission,
            &scope_kind,
            &tenant,
            namespace_present,
            &namespace_id,
        )
    })
    .collect()
}

fn verify_permission_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT grantee_tenant_id, grantee_namespace_present, grantee_namespace_id,
                    principal_id, principal_kind, permission, scope_kind,
                    resource_tenant_id, resource_namespace_present, resource_namespace_id
             FROM permission_grants",
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
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (
            grantee_tenant,
            grantee_namespace_present,
            grantee_namespace_id,
            principal_id,
            principal_kind,
            permission,
            scope_kind,
            resource_tenant,
            resource_namespace_present,
            resource_namespace_id,
        ) = row.map_err(|error| map_sqlite_error(&error))?;
        let subject = ScopedPrincipal {
            scope: decode_scope(
                &grantee_tenant,
                grantee_namespace_present,
                &grantee_namespace_id,
            )?,
            principal: ucr_model::PrincipalRef {
                principal_id: ucr_model::PrincipalId::from_opaque(decode_id(&principal_id)?),
                kind: decode_principal_kind(&principal_kind)?,
            },
        };
        decode_grant(
            subject,
            permission,
            &scope_kind,
            &resource_tenant,
            resource_namespace_present,
            &resource_namespace_id,
        )?;
    }
    Ok(())
}

fn decode_grant(
    grantee: ScopedPrincipal,
    permission: String,
    scope_kind: &str,
    tenant: &str,
    namespace_present: i64,
    namespace_id: &str,
) -> Result<PermissionGrant, DurableStoreError> {
    let resource_scope = decode_scope(tenant, namespace_present, namespace_id)?;
    let scope = match scope_kind {
        "exact" => PermissionScope::Exact(resource_scope),
        "tenant_wide" if resource_scope.namespace_id.is_none() => {
            PermissionScope::TenantWide(resource_scope.tenant_id)
        }
        _ => return Err(DurableStoreError::Corrupt),
    };
    let grant = PermissionGrant {
        grantee,
        permission,
        scope,
    };
    validate_permission_grant(&grant).map_err(|_| DurableStoreError::Corrupt)?;
    Ok(grant)
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

fn grant_scope_storage(grant: &PermissionGrant) -> (&'static str, TenantScope) {
    match &grant.scope {
        PermissionScope::Exact(scope) => ("exact", scope.clone()),
        PermissionScope::TenantWide(tenant_id) => (
            "tenant_wide",
            TenantScope {
                tenant_id: tenant_id.clone(),
                namespace_id: None,
            },
        ),
    }
}

const fn principal_kind_text(kind: PrincipalKind) -> &'static str {
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

const fn map_authorization_store_error(error: DurableStoreError) -> CanonicalError {
    let code = match error {
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::InvalidRecord
        | DurableStoreError::Conflict
        | DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{Connection, params};
    use ucr_core::{
        AuthorizationEvaluator, AuthorizedMutationError, AuthorizedTrustedSigningKeyMutations,
        PermissionGrantStore, StorageProvider, TrustedSigningKeyStore,
    };
    use ucr_model::{
        AuthorizationRequest, DeviceId, KeyId, KeyPurpose, NamespaceId, OpaqueId, PermissionGrant,
        PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, PublicKeyDescriptor,
        ScopedPrincipal, TenantId, TenantScope,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, CanonicalError, CanonicalErrorCode, KEY_FORMAT_VERSION,
        SIGNATURE_ALGORITHM_ID, TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
    };

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_V11, SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static TEST_DB_SEQUENCE: AtomicU64 = AtomicU64::new(70_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = TEST_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-permissions-{}-{sequence}.sqlite3",
                std::process::id()
            )))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid(tenant)),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(oid(value))),
        }
    }

    fn subject(tenant: &str, namespace: Option<&str>) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(tenant, namespace),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("service-a")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn exact_grant(subject: &ScopedPrincipal, resource: &TenantScope) -> PermissionGrant {
        PermissionGrant {
            grantee: subject.clone(),
            permission: TRUSTED_SIGNING_KEY_PROVISION_PERMISSION.to_owned(),
            scope: PermissionScope::Exact(resource.clone()),
        }
    }

    fn request(subject: &ScopedPrincipal, resource: &TenantScope) -> AuthorizationRequest {
        AuthorizationRequest {
            subject: subject.clone(),
            permission: TRUSTED_SIGNING_KEY_PROVISION_PERMISSION.to_owned(),
            resource_scope: resource.clone(),
        }
    }

    fn descriptor(key: &str, device: &str, byte: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(key)),
            device_id: DeviceId::from_opaque(oid(device)),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![byte; 32],
        }
    }

    #[test]
    fn exact_grant_authorization_and_revocation_survive_restart() {
        let db = TestDb::new();
        let subject = subject("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-a"));
        let grant = exact_grant(&subject, &resource);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.authorize(&request(&subject, &resource)),
                Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
            );
            store.grant_permission(&grant).expect("grant");
            store.grant_permission(&grant).expect("idempotent grant");
            assert_eq!(store.authorize(&request(&subject, &resource)), Ok(()));
        }
        {
            let store = SqliteLocalStore::open(db.path()).expect("reopen granted");
            assert_eq!(store.authorize(&request(&subject, &resource)), Ok(()));
            assert_eq!(
                store.permission_grants_for(&subject),
                Ok(vec![grant.clone()])
            );
            store.revoke_permission(&grant).expect("revoke");
            store.revoke_permission(&grant).expect("idempotent revoke");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen revoked");
        assert_eq!(
            reopened.authorize(&request(&subject, &resource)),
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        );
        assert_eq!(reopened.permission_grants_for(&subject), Ok(Vec::new()));
    }

    #[test]
    fn tenant_wide_grant_never_crosses_tenant() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let subject = subject("tenant-a", None);
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: TRUSTED_SIGNING_KEY_PROVISION_PERMISSION.to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(oid("tenant-a"))),
        };
        store.grant_permission(&grant).expect("tenant wide grant");
        assert_eq!(
            store.authorize(&request(&subject, &scope("tenant-a", Some("namespace-b")),)),
            Ok(())
        );
        assert_eq!(
            store.authorize(&request(&subject, &scope("tenant-b", Some("namespace-b")),)),
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        );
    }

    #[test]
    fn authorized_trusted_key_mutation_uses_persisted_grant_after_restart() {
        let db = TestDb::new();
        let subject = subject("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-a"));
        let grant = exact_grant(&subject, &resource);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store.grant_permission(&grant).expect("grant");
        }
        let store = SqliteLocalStore::open(db.path()).expect("reopen");
        let facade = AuthorizedTrustedSigningKeyMutations::new(&store, &store);
        let key = descriptor("key-a", "device-a", 9);
        assert_eq!(facade.provision(&subject, &resource, &key), Ok(()));
        store.revoke_permission(&grant).expect("remove grant");
        assert_eq!(
            facade.provision(&subject, &resource, &descriptor("key-b", "device-b", 10),),
            Err(AuthorizedMutationError::Authorization(CanonicalError::new(
                CanonicalErrorCode::PermissionDenied,
            )))
        );
        assert_eq!(
            store.active_trusted_signing_key(&resource, &DeviceId::from_opaque(oid("device-b")),),
            Ok(None)
        );
    }

    #[test]
    fn malformed_persisted_permission_is_rejected_on_reopen() {
        let db = TestDb::new();
        drop(SqliteLocalStore::open(db.path()).expect("initialize"));
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute(
                "INSERT INTO permission_grants (
                    grantee_tenant_id, grantee_namespace_present, grantee_namespace_id,
                    principal_id, principal_kind, permission, scope_kind,
                    resource_tenant_id, resource_namespace_present, resource_namespace_id
                 ) VALUES (?1,1,?2,?3,'service_account','not-namespaced','exact',?1,1,?2)",
                params!["tenant-a", "namespace-a", "service-a"],
            )
            .expect("inject malformed permission");
        drop(connection);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(ucr_core::DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn v11_to_v12_migration_preserves_trusted_key_state_and_starts_without_grants() {
        let db = TestDb::new();
        let resource = scope("tenant-a", Some("namespace-a"));
        let key = descriptor("key-a", "device-a", 11);
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            store
                .provision_trusted_signing_key(&resource, &key)
                .expect("seed v11 security state");
        }
        let connection = Connection::open(db.path()).expect("raw connection");
        connection
            .execute_batch("DROP TABLE permission_grants;")
            .expect("remove v12 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_V11)
            .expect("v11 version");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v11 to v12");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            migrated.active_trusted_signing_key(&resource, &key.device_id),
            Ok(Some(key))
        );
        assert_eq!(
            migrated.permission_grants_for(&subject("tenant-a", Some("namespace-a"))),
            Ok(Vec::new())
        );
    }
}
