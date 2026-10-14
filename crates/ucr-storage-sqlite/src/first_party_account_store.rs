//! Self-service pseudonymous Identity bootstrap and recovery verifier.
//! Canonical identities, principals, devices and trusted signing keys stay
//! in their EXISTING owner tables. This is only a recovery credential index.
//! Recovery credentials MUST be uniformly random 256-bit values; never a
//! human password, phone number, or server-retained Device private key.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use ucr_core::DurableStoreError;
use ucr_model::{
    DeviceDescriptor, DeviceLifecycleState, IdentityEvidence, IdentityId, IdentityOwnership,
    IdentityRecord, KeyPurpose, PublicKeyDescriptor, TenantScope,
};
use ucr_protocol::{validate_identity_record, validate_trusted_signing_key_descriptor};

use super::{
    SqliteLocalStore, device_store, identity_store, map_schema_change_error, map_sqlite_error,
    namespace_storage_key, trusted_key_store, verify_table_columns,
};

const V52_SQL: &str = r"
CREATE TABLE first_party_recovery_credentials (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    verifier BLOB NOT NULL CHECK(length(verifier)=32),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    PRIMARY KEY(tenant_id,namespace_present,namespace_id,identity_id),
    FOREIGN KEY(tenant_id,namespace_present,namespace_id,identity_id)
      REFERENCES identities(tenant_id,namespace_present,namespace_id,identity_id)
      ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v52_objects(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V52_SQL)
        .map_err(|e| map_schema_change_error(&e))
}

pub(super) fn verify_v52_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "first_party_recovery_credentials",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("identity_id", "TEXT", 1, 4),
            ("verifier", "BLOB", 1, 0),
            ("generation", "INTEGER", 1, 0),
        ],
    )?;
    let invalid: i64 = connection
        .query_row(
            "SELECT count(*) FROM first_party_recovery_credentials c
         LEFT JOIN identities i ON c.tenant_id=i.tenant_id
           AND c.namespace_present=i.namespace_present AND c.namespace_id=i.namespace_id
           AND c.identity_id=i.identity_id
         WHERE i.identity_id IS NULL OR length(c.verifier)<>32 OR c.generation<1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| map_sqlite_error(&e))?;
    if invalid != 0 {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

impl SqliteLocalStore {
    /// All canonical owner rows + a single recovery verifier commit atomically.
    /// Only callers that verified a fresh Device signer proof may invoke this.
    ///
    /// # Errors
    /// Rejects invalid identifiers, conflicting owners or keys, failed transactions,
    /// and storage corruption without leaving partially registered accounts.
    pub fn first_party_register_account(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        descriptor: &DeviceDescriptor,
        key: &PublicKeyDescriptor,
        verifier: [u8; 32],
    ) -> Result<(), DurableStoreError> {
        if descriptor.identity_id != *identity_id
            || descriptor.state != DeviceLifecycleState::Active
            || key.device_id != descriptor.device_id
            || key.purpose != KeyPurpose::Signing
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let identity = IdentityRecord {
            scope: scope.clone(),
            identity_id: identity_id.clone(),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::SelfAsserted,
            expires_at_unix_ms: None,
        };
        validate_identity_record(&identity).map_err(|_| DurableStoreError::InvalidRecord)?;
        validate_trusted_signing_key_descriptor(key)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut c = self.lock_connection()?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| map_sqlite_error(&e))?;
        if identity_store::identity_exists_in(&tx, scope, identity_id)?
            || device_store::load_device(&tx, scope, &descriptor.device_id)?.is_some()
            || trusted_key_store::load_key_record(&tx, scope, &key.key_id)?.is_some()
        {
            return Err(DurableStoreError::Conflict);
        }
        let ns = namespace_storage_key(scope);
        tx.execute(
            "INSERT INTO identities (tenant_id,namespace_present,namespace_id,identity_id,ownership,evidence,expires_at_unix_ms)
             VALUES (?1,?2,?3,?4,'ucr_native','self_asserted',NULL)",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,identity_id.as_opaque().as_str()],
        ).map_err(|e|map_sqlite_error(&e))?;
        // Exactly one Person principal per self-service Identity; use a scoped
        // opaque principal ID distinct from Device ID (no shadow user owner).
        let principal_id = identity_id.as_opaque().as_str();
        tx.execute(
            "INSERT INTO principal_identity_bindings
             (tenant_id,namespace_present,namespace_id,principal_id,principal_kind,identity_id)
             VALUES (?1,?2,?3,?4,'person',?4)",
            params![
                scope.tenant_id.as_opaque().as_str(),
                ns.present,
                ns.value,
                principal_id
            ],
        )
        .map_err(|e| map_sqlite_error(&e))?;
        device_store::insert_device(&tx, scope, descriptor)?;
        trusted_key_store::insert_active_key(&tx, scope, key)?;
        // A self-service person may exercise ONLY the canonical first-party
        // direct-call journey. Grants live in the existing PermissionGrant owner.
        // No wildcard, Service Principal or administrative rights are issued.
        for permission in [
            ucr_protocol::CALL_START_PERMISSION,
            ucr_protocol::CALL_OBSERVE_PERMISSION,
            ucr_protocol::CALL_SIGNAL_PERMISSION,
            ucr_protocol::CONVERSATION_WRITE_PERMISSION,
        ] {
            tx.execute(
                "INSERT INTO permission_grants
                 (grantee_tenant_id,grantee_namespace_present,grantee_namespace_id,
                  principal_id,principal_kind,permission,scope_kind,
                  resource_tenant_id,resource_namespace_present,resource_namespace_id)
                 VALUES (?1,?2,?3,?4,'person',?5,'exact',?1,?2,?3)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    principal_id,
                    permission
                ],
            )
            .map_err(|e| map_sqlite_error(&e))?;
        }
        tx.execute(
            "INSERT INTO first_party_recovery_credentials
             (tenant_id,namespace_present,namespace_id,identity_id,verifier,generation)
             VALUES (?1,?2,?3,?4,?5,1)",
            params![
                scope.tenant_id.as_opaque().as_str(),
                ns.present,
                ns.value,
                principal_id,
                verifier.as_slice()
            ],
        )
        .map_err(|e| map_sqlite_error(&e))?;
        tx.commit().map_err(|e| map_sqlite_error(&e))
    }

    /// One-time 256-bit recovery credential, consumed transactionally while
    /// adding a NEW canonical Device and signer. The next credential replaces
    /// the old one in that SAME `SQLite` commit, so replay cannot add devices.
    ///
    /// # Errors
    /// Rejects incorrect or previously spent verifiers, revoked/reused Device IDs,
    /// conflicting keys, missing canonical Identity, and durable failures.
    pub fn first_party_recover_device(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        descriptor: &DeviceDescriptor,
        key: &PublicKeyDescriptor,
        old_verifier: [u8; 32],
        next_verifier: [u8; 32],
    ) -> Result<(), DurableStoreError> {
        if descriptor.identity_id != *identity_id
            || descriptor.state != DeviceLifecycleState::Active
            || key.device_id != descriptor.device_id
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        validate_trusted_signing_key_descriptor(key)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut c = self.lock_connection()?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| map_sqlite_error(&e))?;
        let ns = namespace_storage_key(scope);
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT verifier FROM first_party_recovery_credentials
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    identity_id.as_opaque().as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_sqlite_error(&e))?;
        let mut difference = 0u8;
        let stored = current.ok_or(DurableStoreError::PermissionDenied)?;
        if stored.len() != 32 {
            return Err(DurableStoreError::Corrupt);
        }
        for (a, b) in stored.iter().zip(old_verifier.iter()) {
            difference |= *a ^ *b;
        }
        if difference != 0 {
            return Err(DurableStoreError::PermissionDenied);
        }
        if device_store::load_device(&tx, scope, &descriptor.device_id)?.is_some()
            || trusted_key_store::load_key_record(&tx, scope, &key.key_id)?.is_some()
        {
            // A revoked Device may NEVER be resurrected by an old recovery code.
            return Err(DurableStoreError::Conflict);
        }
        let owner = identity_store::identity_exists_in(&tx, scope, identity_id)?;
        if !owner {
            return Err(DurableStoreError::PermissionDenied);
        }
        device_store::insert_device(&tx, scope, descriptor)?;
        trusted_key_store::insert_active_key(&tx, scope, key)?;
        let changed = tx
            .execute(
                "UPDATE first_party_recovery_credentials SET verifier=?5,generation=generation+1
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    identity_id.as_opaque().as_str(),
                    next_verifier.as_slice()
                ],
            )
            .map_err(|e| map_sqlite_error(&e))?;
        if changed != 1 {
            return Err(DurableStoreError::Corrupt);
        }
        tx.commit().map_err(|e| map_sqlite_error(&e))
    }

    /// Authenticated, active Device session only; caller checks authority.
    ///
    /// # Errors
    /// Denies identities without a recovery credential and propagates any
    /// canonical `SQLite` storage failure.
    pub fn first_party_rotate_recovery(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        next_verifier: [u8; 32],
    ) -> Result<(), DurableStoreError> {
        let c = self.lock_connection()?;
        let ns = namespace_storage_key(scope);
        let rows = c
            .execute(
                "UPDATE first_party_recovery_credentials SET verifier=?5,generation=generation+1
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    identity_id.as_opaque().as_str(),
                    next_verifier.as_slice()
                ],
            )
            .map_err(|e| map_sqlite_error(&e))?;
        if rows != 1 {
            return Err(DurableStoreError::PermissionDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteLocalStore;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use ucr_core::{
        DeviceLifecycleStore, DurableStoreError, IdentityDeviceLookupStore, IdentityStore,
        StorageProvider, TrustedSigningKeyStore,
    };
    use ucr_model::{
        DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId, KeyId, KeyPurpose, OpaqueId,
        PublicKeyDescriptor, TenantId, TenantScope,
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(555_000);
    struct Db(PathBuf);
    impl Db {
        fn new() -> Self {
            let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let file = std::env::temp_dir().join(format!(
                "ucr-self-service-{}-{n}.sqlite3",
                std::process::id()
            ));
            let _ = fs::remove_file(&file);
            Self(file)
        }
    }
    impl Drop for Db {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }
    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque")
    }
    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("shared-first-party")),
            namespace_id: None,
        }
    }
    fn account() -> IdentityId {
        IdentityId::from_opaque(id("self-service-identity"))
    }
    fn descriptor(device: &str) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(id(device)),
            identity_id: account(),
            state: DeviceLifecycleState::Active,
        }
    }
    fn key(device: &str, key_id: &str, seed: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(id(key_id)),
            device_id: DeviceId::from_opaque(id(device)),
            purpose: KeyPurpose::Signing,
            algorithm_id: "ed25519".to_owned(),
            algorithm_version: 1,
            key_format_version: 1,
            public_key: vec![seed; 32],
        }
    }

    #[test]
    fn two_identities_first_devices_and_persisted_trust_are_canonical() {
        let db = Db::new();
        let store = SqliteLocalStore::open(&db.0).unwrap();
        assert_eq!(store.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
        let one = account();
        store
            .first_party_register_account(
                &scope(),
                &one,
                &descriptor("device-one"),
                &key("device-one", "key-one", 17),
                [21; 32],
            )
            .unwrap();
        assert!(store.identity(&scope(), &one).unwrap().is_some());
        assert_eq!(
            store
                .active_trusted_signing_key(&scope(), &DeviceId::from_opaque(id("device-one")))
                .unwrap()
                .unwrap()
                .public_key,
            vec![17; 32]
        );
        assert_eq!(
            store.first_party_register_account(
                &scope(),
                &one,
                &descriptor("device-duplicate"),
                &key("device-duplicate", "key-two", 17),
                [21; 32]
            ),
            Err(DurableStoreError::Conflict)
        );
        // Two newly created independent canonical People, each with a first
        // Device and a separately recovered second Device. Both rows of the
        // SAME canonical Identity/Device/Trust owners survive restart.
        let two = IdentityId::from_opaque(id("self-service-identity-two"));
        let second_user_first = DeviceDescriptor {
            device_id: DeviceId::from_opaque(id("user-two-first")),
            identity_id: two.clone(),
            state: DeviceLifecycleState::Active,
        };
        let second_user_second = DeviceDescriptor {
            device_id: DeviceId::from_opaque(id("user-two-second")),
            identity_id: two.clone(),
            state: DeviceLifecycleState::Active,
        };
        store
            .first_party_register_account(
                &scope(),
                &two,
                &second_user_first,
                &key("user-two-first", "user-two-key-one", 25),
                [22; 32],
            )
            .unwrap();
        store
            .first_party_recover_device(
                &scope(),
                &one,
                &descriptor("user-one-second"),
                &key("user-one-second", "user-one-key-two", 19),
                [21; 32],
                [31; 32],
            )
            .unwrap();
        store
            .first_party_recover_device(
                &scope(),
                &two,
                &second_user_second,
                &key("user-two-second", "user-two-key-two", 29),
                [22; 32],
                [32; 32],
            )
            .unwrap();
        drop(store);
        let again = SqliteLocalStore::open(&db.0).unwrap();
        for identity in [&one, &two] {
            assert_eq!(
                again
                    .devices_for_identity(&scope(), identity, 64)
                    .unwrap()
                    .len(),
                2
            );
        }
        assert_eq!(
            again
                .active_trusted_signing_key(&scope(), &DeviceId::from_opaque(id("user-two-second")))
                .unwrap()
                .unwrap()
                .public_key,
            vec![29; 32]
        );
        assert_eq!(again.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
    }

    #[test]
    fn recovery_is_atomic_single_use_and_revoked_devices_never_resurrect() {
        let db = Db::new();
        let store = SqliteLocalStore::open(&db.0).unwrap();
        let identity = account();
        store
            .first_party_register_account(
                &scope(),
                &identity,
                &descriptor("device-original"),
                &key("device-original", "key-original", 12),
                [10; 32],
            )
            .unwrap();
        assert_eq!(
            store.first_party_recover_device(
                &scope(),
                &identity,
                &descriptor("device-second"),
                &key("device-second", "key-second", 19),
                [99; 32],
                [11; 32]
            ),
            Err(DurableStoreError::PermissionDenied)
        );
        store
            .first_party_recover_device(
                &scope(),
                &identity,
                &descriptor("device-second"),
                &key("device-second", "key-second", 19),
                [10; 32],
                [11; 32],
            )
            .unwrap();
        assert_eq!(
            store.first_party_recover_device(
                &scope(),
                &identity,
                &descriptor("device-third"),
                &key("device-third", "key-third", 22),
                [10; 32],
                [12; 32]
            ),
            Err(DurableStoreError::PermissionDenied)
        );
        assert!(
            store
                .device(&scope(), &DeviceId::from_opaque(id("device-third")))
                .unwrap()
                .is_none()
        );
        store
            .revoke_device(
                &scope(),
                &DeviceId::from_opaque(id("device-second")),
                &identity,
            )
            .unwrap();
        assert_eq!(
            store.first_party_recover_device(
                &scope(),
                &identity,
                &descriptor("device-second"),
                &key("device-second", "key-second-new", 30),
                [11; 32],
                [12; 32]
            ),
            Err(DurableStoreError::Conflict)
        );
        store
            .first_party_rotate_recovery(&scope(), &identity, [40; 32])
            .unwrap();
        drop(store);
        verify_rotated_recovery_after_restart(&db, &identity);
    }

    fn verify_rotated_recovery_after_restart(db: &Db, identity: &IdentityId) {
        let again = SqliteLocalStore::open(&db.0).unwrap();
        assert_eq!(
            again.first_party_recover_device(
                &scope(),
                identity,
                &descriptor("device-third"),
                &key("device-third", "key-third", 22),
                [11; 32],
                [41; 32]
            ),
            Err(DurableStoreError::PermissionDenied)
        );
        again
            .first_party_recover_device(
                &scope(),
                identity,
                &descriptor("device-third"),
                &key("device-third", "key-third", 22),
                [40; 32],
                [41; 32],
            )
            .unwrap();
        assert_eq!(
            again
                .active_devices_for_identity(&scope(), identity, 64)
                .unwrap()
                .len(),
            2
        );
    }
}
