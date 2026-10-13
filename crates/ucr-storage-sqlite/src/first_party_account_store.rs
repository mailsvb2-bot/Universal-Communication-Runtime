//! Self-service pseudonymous Identity bootstrap and recovery verifier.
//! Canonical identities, principals, devices and trusted signing keys stay
//! in their EXISTING owner tables. This is only a recovery credential index.
//! Recovery credentials MUST be uniformly random 256-bit values; never a
//! human password, phone number, or server-retained Device private key.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use ucr_core::DurableStoreError;
use ucr_model::{
    DeviceDescriptor, DeviceLifecycleState, IdentityEvidence, IdentityId,
    IdentityOwnership, IdentityRecord, KeyPurpose,
    PublicKeyDescriptor, TenantScope,
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

pub(super) fn create_v52_objects(transaction: &rusqlite::Transaction<'_>) -> Result<(),DurableStoreError> {
    transaction.execute_batch(V52_SQL).map_err(|e|map_schema_change_error(&e))
}

pub(super) fn verify_v52_objects(connection:&Connection)->Result<(),DurableStoreError>{
    verify_table_columns(connection,"first_party_recovery_credentials",&[
        ("tenant_id","TEXT",1,1),
        ("namespace_present","INTEGER",1,2),
        ("namespace_id","TEXT",1,3),
        ("identity_id","TEXT",1,4),
        ("verifier","BLOB",1,0),
        ("generation","INTEGER",1,0),
    ])?;
    let invalid:i64=connection.query_row(
        "SELECT count(*) FROM first_party_recovery_credentials c
         LEFT JOIN identities i ON c.tenant_id=i.tenant_id
           AND c.namespace_present=i.namespace_present AND c.namespace_id=i.namespace_id
           AND c.identity_id=i.identity_id
         WHERE i.identity_id IS NULL OR length(c.verifier)<>32 OR c.generation<1",
        [],|row|row.get(0)).map_err(|e|map_sqlite_error(&e))?;
    if invalid!=0 {return Err(DurableStoreError::Corrupt);}
    Ok(())
}

impl SqliteLocalStore {
    /// All canonical owner rows + a single recovery verifier commit atomically.
    /// Only callers that verified a fresh Device signer proof may invoke this.
    pub fn first_party_register_account(
        &self,scope:&TenantScope,identity_id:&IdentityId,
        descriptor:&DeviceDescriptor,key:&PublicKeyDescriptor,verifier:[u8;32],
    )->Result<(),DurableStoreError>{
        if descriptor.identity_id!=*identity_id ||
            descriptor.state!=DeviceLifecycleState::Active ||key.device_id!=descriptor.device_id ||
            key.purpose!=KeyPurpose::Signing {
            return Err(DurableStoreError::InvalidRecord);
        }
        let identity=IdentityRecord{
            scope:scope.clone(),identity_id:identity_id.clone(),
            ownership:IdentityOwnership::UcrNative,
            evidence:IdentityEvidence::DeviceVerified,expires_at_unix_ms:None,
        };
        validate_identity_record(&identity).map_err(|_|DurableStoreError::InvalidRecord)?;
        validate_trusted_signing_key_descriptor(key).map_err(|_|DurableStoreError::InvalidRecord)?;
        let mut c=self.lock_connection()?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e|map_sqlite_error(&e))?;
        if identity_store::identity_exists_in(&tx,scope,identity_id)? ||
            device_store::load_device(&tx,scope,&descriptor.device_id)?.is_some() ||
            trusted_key_store::load_key_record(&tx,scope,&key.key_id)?.is_some(){
            return Err(DurableStoreError::Conflict);
        }
        let ns=namespace_storage_key(scope);
        tx.execute(
            "INSERT INTO identities (tenant_id,namespace_present,namespace_id,identity_id,ownership,evidence,expires_at_unix_ms)
             VALUES (?1,?2,?3,?4,'ucr_native','device_verified',NULL)",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,identity_id.as_opaque().as_str()],
        ).map_err(|e|map_sqlite_error(&e))?;
        // Exactly one Person principal per self-service Identity; use a scoped
        // opaque principal ID distinct from Device ID (no shadow user owner).
        let principal_id=identity_id.as_opaque().as_str();
        tx.execute(
            "INSERT INTO principal_identity_bindings
             (tenant_id,namespace_present,namespace_id,principal_id,principal_kind,identity_id)
             VALUES (?1,?2,?3,?4,'person',?4)",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,principal_id],
        ).map_err(|e|map_sqlite_error(&e))?;
        device_store::insert_device(&tx,scope,descriptor)?;
        trusted_key_store::insert_active_key(&tx,scope,key)?;
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
                params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,
                    principal_id,permission],
            ).map_err(|e|map_sqlite_error(&e))?;
        }
        tx.execute(
            "INSERT INTO first_party_recovery_credentials
             (tenant_id,namespace_present,namespace_id,identity_id,verifier,generation)
             VALUES (?1,?2,?3,?4,?5,1)",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,principal_id,verifier.as_slice()],
        ).map_err(|e|map_sqlite_error(&e))?;
        tx.commit().map_err(|e|map_sqlite_error(&e))
    }

    /// One-time 256-bit recovery credential, consumed transactionally while
    /// adding a NEW canonical Device and signer. The next credential replaces
    /// the old one in that SAME SQLite commit, so replay cannot add devices.
    pub fn first_party_recover_device(
        &self,scope:&TenantScope,identity_id:&IdentityId,descriptor:&DeviceDescriptor,
        key:&PublicKeyDescriptor,old_verifier:[u8;32],next_verifier:[u8;32],
    )->Result<(),DurableStoreError>{
        if descriptor.identity_id!=*identity_id ||
            descriptor.state!=DeviceLifecycleState::Active ||key.device_id!=descriptor.device_id{
            return Err(DurableStoreError::InvalidRecord);
        }
        validate_trusted_signing_key_descriptor(key).map_err(|_|DurableStoreError::InvalidRecord)?;
        let mut c=self.lock_connection()?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e|map_sqlite_error(&e))?;
        let ns=namespace_storage_key(scope);
        let current:Option<Vec<u8>>=tx.query_row(
            "SELECT verifier FROM first_party_recovery_credentials
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,identity_id.as_opaque().as_str()],
            |row|row.get(0),
        ).optional().map_err(|e|map_sqlite_error(&e))?;
        let mut difference=0u8;
        let stored=current.ok_or(DurableStoreError::PermissionDenied)?;
        if stored.len()!=32 {return Err(DurableStoreError::Corrupt);}
        for (a,b) in stored.iter().zip(old_verifier.iter()) {difference|=*a ^ *b;}
        if difference!=0 {return Err(DurableStoreError::PermissionDenied);}
        if device_store::load_device(&tx,scope,&descriptor.device_id)?.is_some() ||
            trusted_key_store::load_key_record(&tx,scope,&key.key_id)?.is_some(){
            // A revoked Device may NEVER be resurrected by an old recovery code.
            return Err(DurableStoreError::Conflict);
        }
        let owner=identity_store::identity_exists_in(&tx,scope,identity_id)?;
        if !owner {return Err(DurableStoreError::PermissionDenied);}
        device_store::insert_device(&tx,scope,descriptor)?;
        trusted_key_store::insert_active_key(&tx,scope,key)?;
        let changed=tx.execute(
            "UPDATE first_party_recovery_credentials SET verifier=?5,generation=generation+1
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,identity_id.as_opaque().as_str(),next_verifier.as_slice()],
        ).map_err(|e|map_sqlite_error(&e))?;
        if changed!=1{return Err(DurableStoreError::Corrupt);}
        tx.commit().map_err(|e|map_sqlite_error(&e))
    }

    /// Authenticated, active Device session only; caller checks authority.
    pub fn first_party_rotate_recovery(
        &self,scope:&TenantScope,identity_id:&IdentityId,next_verifier:[u8;32],
    )->Result<(),DurableStoreError>{
        let c=self.lock_connection()?;
        let ns=namespace_storage_key(scope);
        let rows=c.execute(
            "UPDATE first_party_recovery_credentials SET verifier=?5,generation=generation+1
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND identity_id=?4",
            params![scope.tenant_id.as_opaque().as_str(),ns.present,ns.value,identity_id.as_opaque().as_str(),next_verifier.as_slice()],
        ).map_err(|e|map_sqlite_error(&e))?;
        if rows!=1 {return Err(DurableStoreError::PermissionDenied);}
        Ok(())
    }
}
