use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableStoreError, RecoveryPlanStore};
use ucr_model::{
    DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, NamespaceId, OpaqueId,
    PrincipalId, RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryTrustModel, TenantId,
    TenantScope,
};
use ucr_protocol::canonical_recovery_plan;

use super::{SqliteLocalStore, map_sqlite_error, namespace_storage_key};

impl RecoveryPlanStore for SqliteLocalStore {
    fn install_recovery_plan(&self, plan: &RecoveryPlan) -> Result<(), DurableStoreError> {
        let plan = canonical(plan)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let identity = identity_key(&plan.scope, &plan.identity_id);
        if let Some(existing) = load_plan(&transaction, plan.plan_id.as_opaque().as_str())? {
            let active = active_plan_id(&transaction, &identity)?;
            return if existing == plan
                && active.as_deref() == Some(plan.plan_id.as_opaque().as_str())
            {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if active_plan_id(&transaction, &identity)?.is_some() {
            return Err(DurableStoreError::Conflict);
        }
        insert_plan(&transaction, &plan)?;
        insert_active_mapping(&transaction, &plan)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn rotate_recovery_plan(
        &self,
        expected_current: &RecoveryPlanId,
        replacement: &RecoveryPlan,
    ) -> Result<(), DurableStoreError> {
        let replacement = canonical(replacement)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let expected_id = expected_current.as_opaque().as_str();
        let current = load_plan(&transaction, expected_id)?.ok_or(DurableStoreError::Conflict)?;
        if current.scope != replacement.scope || current.identity_id != replacement.identity_id {
            return Err(DurableStoreError::Conflict);
        }
        let identity = identity_key(&replacement.scope, &replacement.identity_id);
        if active_plan_id(&transaction, &identity)?.as_deref() != Some(expected_id) {
            return Err(DurableStoreError::Conflict);
        }
        let replacement_id = replacement.plan_id.as_opaque().as_str();
        if replacement_id == expected_id {
            return if current == replacement {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if load_plan(&transaction, replacement_id)?.is_some() {
            return Err(DurableStoreError::Conflict);
        }
        insert_plan(&transaction, &replacement)?;
        let changed = transaction
            .execute(
                "UPDATE active_recovery_plans SET plan_id = ?1
                 WHERE tenant_id = ?2 AND namespace_present = ?3 AND namespace_id = ?4
                   AND identity_id = ?5 AND plan_id = ?6",
                params![
                    replacement_id,
                    identity.tenant_id,
                    identity.namespace_present,
                    identity.namespace_id,
                    identity.identity_id,
                    expected_id
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if changed != 1 {
            return Err(DurableStoreError::Conflict);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))
    }

    fn revoke_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        expected_current: &RecoveryPlanId,
    ) -> Result<(), DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let identity = identity_key(scope, identity_id);
        let expected_id = expected_current.as_opaque().as_str();
        match active_plan_id(&transaction, &identity)? {
            Some(active) if active == expected_id => {
                let changed = transaction
                    .execute(
                        "DELETE FROM active_recovery_plans
                         WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
                           AND identity_id = ?4 AND plan_id = ?5",
                        params![
                            identity.tenant_id,
                            identity.namespace_present,
                            identity.namespace_id,
                            identity.identity_id,
                            expected_id
                        ],
                    )
                    .map_err(|error| map_sqlite_error(&error))?;
                if changed != 1 {
                    return Err(DurableStoreError::Conflict);
                }
                transaction
                    .commit()
                    .map_err(|error| map_sqlite_error(&error))
            }
            Some(_) => Err(DurableStoreError::Conflict),
            None => {
                let Some(plan) = load_plan(&transaction, expected_id)? else {
                    return Err(DurableStoreError::Conflict);
                };
                if &plan.scope == scope && &plan.identity_id == identity_id {
                    Ok(())
                } else {
                    Err(DurableStoreError::Conflict)
                }
            }
        }
    }

    fn active_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<RecoveryPlan>, DurableStoreError> {
        let connection = self.lock_connection()?;
        let identity = identity_key(scope, identity_id);
        let Some(plan_id) = active_plan_id(&connection, &identity)? else {
            return Ok(None);
        };
        load_plan(&connection, &plan_id)?
            .ok_or(DurableStoreError::Corrupt)
            .map(Some)
    }
}

struct IdentityKey<'a> {
    tenant_id: &'a str,
    namespace_present: i64,
    namespace_id: &'a str,
    identity_id: &'a str,
}

fn identity_key<'a>(scope: &'a TenantScope, identity_id: &'a IdentityId) -> IdentityKey<'a> {
    let namespace = namespace_storage_key(scope);
    IdentityKey {
        tenant_id: scope.tenant_id.as_opaque().as_str(),
        namespace_present: namespace.present,
        namespace_id: namespace.value,
        identity_id: identity_id.as_opaque().as_str(),
    }
}

fn canonical(plan: &RecoveryPlan) -> Result<RecoveryPlan, DurableStoreError> {
    canonical_recovery_plan(plan).map_err(|_| DurableStoreError::InvalidRecord)
}

fn active_plan_id(
    connection: &Connection,
    identity: &IdentityKey<'_>,
) -> Result<Option<String>, DurableStoreError> {
    connection
        .query_row(
            "SELECT plan_id FROM active_recovery_plans
             WHERE tenant_id = ?1 AND namespace_present = ?2 AND namespace_id = ?3
               AND identity_id = ?4",
            params![
                identity.tenant_id,
                identity.namespace_present,
                identity.namespace_id,
                identity.identity_id
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))
}

fn insert_plan(
    transaction: &Transaction<'_>,
    plan: &RecoveryPlan,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&plan.scope);
    transaction
        .execute(
            "INSERT INTO recovery_plans(
                plan_id, tenant_id, namespace_present, namespace_id, identity_id,
                historical_access, trust_model, recovered_device_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'reverification_required')",
            params![
                plan.plan_id.as_opaque().as_str(),
                plan.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                plan.identity_id.as_opaque().as_str(),
                historical_access_name(plan.historical_message_access),
                trust_model_name(plan.trust_model),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    for authority in &plan.authorities {
        let (method, authority_id) = authority_storage(authority);
        transaction
            .execute(
                "INSERT INTO recovery_authorities(plan_id, method, authority_id)
                 VALUES (?1, ?2, ?3)",
                params![plan.plan_id.as_opaque().as_str(), method, authority_id],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn insert_active_mapping(
    transaction: &Transaction<'_>,
    plan: &RecoveryPlan,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&plan.scope);
    transaction
        .execute(
            "INSERT INTO active_recovery_plans(
                tenant_id, namespace_present, namespace_id, identity_id, plan_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                plan.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                plan.identity_id.as_opaque().as_str(),
                plan.plan_id.as_opaque().as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn historical_access_name(access: HistoricalMessageAccess) -> &'static str {
    match access {
        HistoricalMessageAccess::None => "none",
        HistoricalMessageAccess::ExplicitEncryptedRecovery => "explicit_encrypted_recovery",
    }
}

fn trust_model_name(model: RecoveryTrustModel) -> &'static str {
    match model {
        RecoveryTrustModel::UserControlled => "user_controlled",
        RecoveryTrustModel::OrganizationManaged => "organization_managed",
    }
}

fn authority_storage(authority: &RecoveryAuthority) -> (&'static str, &str) {
    match authority {
        RecoveryAuthority::RecoveryCode => ("recovery_code", ""),
        RecoveryAuthority::RecoveryKey => ("recovery_key", ""),
        RecoveryAuthority::TrustedDevice(device) => ("trusted_device", device.as_opaque().as_str()),
        RecoveryAuthority::HardwareBacked(device) => {
            ("hardware_backed", device.as_opaque().as_str())
        }
        RecoveryAuthority::EncryptedBackup => ("encrypted_backup", ""),
        RecoveryAuthority::OrganizationManaged(principal) => {
            ("organization_managed", principal.as_opaque().as_str())
        }
    }
}

fn load_plan(
    connection: &Connection,
    plan_id: &str,
) -> Result<Option<RecoveryPlan>, DurableStoreError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, namespace_present, namespace_id, identity_id,
                    historical_access, trust_model, recovered_device_state
             FROM recovery_plans WHERE plan_id = ?1",
            [plan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((
        tenant,
        namespace_present,
        namespace,
        identity,
        historical,
        trust_model,
        recovered_state,
    )) = row
    else {
        return Ok(None);
    };
    if recovered_state != "reverification_required" {
        return Err(DurableStoreError::Corrupt);
    }
    let scope = decode_scope(tenant, namespace_present, &namespace)?;
    let identity_id =
        IdentityId::from_opaque(OpaqueId::new(identity).map_err(|_| DurableStoreError::Corrupt)?);
    let plan_id = RecoveryPlanId::from_opaque(
        OpaqueId::new(plan_id).map_err(|_| DurableStoreError::Corrupt)?,
    );
    let historical_message_access = match historical.as_str() {
        "none" => HistoricalMessageAccess::None,
        "explicit_encrypted_recovery" => HistoricalMessageAccess::ExplicitEncryptedRecovery,
        _ => return Err(DurableStoreError::Corrupt),
    };
    let trust_model = match trust_model.as_str() {
        "user_controlled" => RecoveryTrustModel::UserControlled,
        "organization_managed" => RecoveryTrustModel::OrganizationManaged,
        _ => return Err(DurableStoreError::Corrupt),
    };
    let authorities = load_authorities(connection, plan_id.as_opaque().as_str())?;
    let plan = RecoveryPlan {
        plan_id,
        scope,
        identity_id,
        authorities,
        historical_message_access,
        trust_model,
        recovered_device_state: DeviceLifecycleState::ReverificationRequired,
    };
    canonical(&plan).map(Some)
}

fn decode_scope(
    tenant: String,
    namespace_present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let tenant_id =
        TenantId::from_opaque(OpaqueId::new(tenant).map_err(|_| DurableStoreError::Corrupt)?);
    let namespace_id = match (namespace_present, namespace) {
        (0, "") => None,
        (1, value) if !value.is_empty() => Some(NamespaceId::from_opaque(
            OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)?,
        )),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id,
        namespace_id,
    })
}

fn load_authorities(
    connection: &Connection,
    plan_id: &str,
) -> Result<Vec<RecoveryAuthority>, DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT method, authority_id FROM recovery_authorities
             WHERE plan_id = ?1 ORDER BY method, authority_id",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([plan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut authorities = Vec::new();
    for row in rows {
        let (method, authority_id) = row.map_err(|error| map_sqlite_error(&error))?;
        authorities.push(decode_authority(&method, &authority_id)?);
    }
    if authorities.is_empty() {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(authorities)
}

fn decode_authority(
    method: &str,
    authority_id: &str,
) -> Result<RecoveryAuthority, DurableStoreError> {
    match (method, authority_id) {
        ("recovery_code", "") => Ok(RecoveryAuthority::RecoveryCode),
        ("recovery_key", "") => Ok(RecoveryAuthority::RecoveryKey),
        ("encrypted_backup", "") => Ok(RecoveryAuthority::EncryptedBackup),
        ("trusted_device", value) if !value.is_empty() => Ok(RecoveryAuthority::TrustedDevice(
            DeviceId::from_opaque(OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)?),
        )),
        ("hardware_backed", value) if !value.is_empty() => Ok(RecoveryAuthority::HardwareBacked(
            DeviceId::from_opaque(OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)?),
        )),
        ("organization_managed", value) if !value.is_empty() => Ok(
            RecoveryAuthority::OrganizationManaged(PrincipalId::from_opaque(
                OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)?,
            )),
        ),
        _ => Err(DurableStoreError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };

    use rusqlite::Connection;
    use ucr_core::{DurableStoreError, RecoveryPlanStore, StorageProvider};
    use ucr_model::{
        DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, NamespaceId, OpaqueId,
        RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryTrustModel, TenantId, TenantScope,
    };

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static SEQUENCE: AtomicU64 = AtomicU64::new(30_000);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-recovery-{}-{sequence}.sqlite3",
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

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-a"))),
        }
    }

    fn plan(id: &str) -> RecoveryPlan {
        RecoveryPlan {
            plan_id: RecoveryPlanId::from_opaque(opaque(id)),
            scope: scope(),
            identity_id: IdentityId::from_opaque(opaque("identity-a")),
            authorities: vec![
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(opaque("trusted-device"))),
                RecoveryAuthority::RecoveryKey,
            ],
            historical_message_access: HistoricalMessageAccess::ExplicitEncryptedRecovery,
            trust_model: RecoveryTrustModel::UserControlled,
            recovered_device_state: DeviceLifecycleState::ReverificationRequired,
        }
    }

    #[test]
    fn recovery_plan_survives_restart_and_is_canonicalized() {
        let db = TestDb::new();
        let original = plan("plan-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .install_recovery_plan(&original)
                .expect("install plan");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let loaded = reopened
            .active_recovery_plan(&original.scope, &original.identity_id)
            .expect("load plan")
            .expect("active plan");
        assert_eq!(loaded.plan_id, original.plan_id);
        assert_eq!(
            loaded.authorities,
            vec![
                RecoveryAuthority::RecoveryKey,
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(opaque("trusted-device"))),
            ]
        );
    }

    #[test]
    fn recovery_revoke_survives_restart() {
        let db = TestDb::new();
        let original = plan("plan-a");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .install_recovery_plan(&original)
                .expect("install plan");
            store
                .revoke_recovery_plan(&original.scope, &original.identity_id, &original.plan_id)
                .expect("revoke plan");
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        assert_eq!(
            reopened
                .active_recovery_plan(&original.scope, &original.identity_id)
                .expect("lookup after restart"),
            None
        );
        reopened
            .revoke_recovery_plan(&original.scope, &original.identity_id, &original.plan_id)
            .expect("idempotent revoke");
    }

    #[test]
    fn concurrent_recovery_rotation_has_single_winner() {
        let db = TestDb::new();
        let original = plan("plan-a");
        SqliteLocalStore::open(db.path())
            .expect("open store")
            .install_recovery_plan(&original)
            .expect("install original");

        let barrier = Arc::new(Barrier::new(3));
        let run = |replacement: RecoveryPlan| {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            let expected = original.plan_id.clone();
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.rotate_recovery_plan(&expected, &replacement)
            })
        };
        let first = run(plan("plan-b"));
        let second = run(plan("plan-c"));
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DurableStoreError::Conflict)))
                .count(),
            1
        );

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let active = reopened
            .active_recovery_plan(&original.scope, &original.identity_id)
            .expect("lookup")
            .expect("active replacement");
        assert!(matches!(
            active.plan_id.as_opaque().as_str(),
            "plan-b" | "plan-c"
        ));
    }

    #[test]
    fn v3_store_migrates_through_v4_to_current_without_losing_existing_schema() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize v4");
            assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        }
        let connection = Connection::open(db.path()).expect("open raw store");
        connection
            .execute_batch(
                "DROP TABLE permission_grants; DROP TABLE trusted_signing_keys;
                 DROP TABLE message_extensions;
                 DROP TABLE command_extensions;
                 DROP TABLE command_protocol_metadata;
                 DROP TABLE event_extensions;
                 DROP TABLE sync_checkpoints;
                 DROP TABLE sync_session_conversations;
                 DROP TABLE sync_sessions;
                 DROP TABLE delivery_evidence;
                 DROP TABLE delivery_attempts;
                 DROP TABLE message_external_mappings;
                 DROP TABLE message_relations;
                 DROP TABLE message_attachments;
                 DROP TABLE messages;
                 DROP TABLE conversations;
                 DROP TABLE active_recovery_plans;
                 DROP TABLE recovery_authorities;
                 DROP TABLE recovery_plans;",
            )
            .expect("remove v4 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("keep application id");
        connection
            .pragma_update(None, "user_version", 3_u32)
            .expect("set v3");
        drop(connection);

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v3 to v4");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let original = plan("plan-after-migration");
        migrated
            .install_recovery_plan(&original)
            .expect("recovery store usable after migration");
        assert_eq!(
            migrated
                .active_recovery_plan(&original.scope, &original.identity_id)
                .expect("lookup")
                .expect("active")
                .plan_id,
            original.plan_id
        );
    }
}
