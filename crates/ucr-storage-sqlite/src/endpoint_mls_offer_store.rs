//! Durable PUBLIC endpoint MLS `KeyPackage` offers, scoped to the existing
//! canonical Group. Never contains MLS private keys or exporter secrets.
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::DurableStoreError;
use ucr_model::{DeviceId, GroupId, TenantScope};

use super::{
    SqliteLocalStore, group_store, map_schema_change_error, map_sqlite_error,
    namespace_storage_key, verify_table_columns,
};

const V53_SQL: &str = r"
CREATE TABLE endpoint_mls_key_package_offers (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    package BLOB NOT NULL CHECK(length(package) BETWEEN 1 AND 8192),
    signature BLOB NOT NULL CHECK(length(signature)=64),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, device_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id)
      ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR
          (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v53_objects(tx: &Transaction<'_>) -> Result<(), DurableStoreError> {
    tx.execute_batch(V53_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v53_objects(conn: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        conn,
        "endpoint_mls_key_package_offers",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("group_id", "TEXT", 1, 4),
            ("device_id", "TEXT", 1, 5),
            ("signer_key_id", "TEXT", 1, 0),
            ("package", "BLOB", 1, 0),
            ("signature", "BLOB", 1, 0),
        ],
    )
}

/// Strictly public signed MLS `KeyPackage` material, addressed to the exact
/// authenticated Device and canonical Group. No bearer grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointMlsKeyPackageOffer {
    pub signer_key_id: String,
    pub package: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SqliteLocalStore {
    /// Persist a recipient-signed offer exactly once. The first signed offer
    /// is immutable within this Group; different retries fail, never overwrite.
    /// The HTTP owner MUST verify the canonical Device signature first.
    ///
    /// # Errors
    /// Rejects missing Group/Device, changed retries, disabled Devices and SQL errors.
    pub fn put_endpoint_mls_offer(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        device_id: &DeviceId,
        offer: &EndpointMlsKeyPackageOffer,
    ) -> Result<(), DurableStoreError> {
        if offer.signer_key_id.is_empty()
            || offer.signer_key_id.len() > 128
            || offer.package.is_empty()
            || offer.package.len() > 8192
            || offer.signature.len() != 64
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut conn = self.lock_connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if group_store::load_group_from(&tx, scope, group_id)?.is_none() {
            return Err(DurableStoreError::InvalidRecord);
        }
        let active = super::device_store::load_device(&tx, scope, device_id)?
            .is_some_and(|device| ucr_protocol::device_allows_protected_access(&device));
        if !active {
            return Err(DurableStoreError::PermissionDenied);
        }
        let ns = namespace_storage_key(scope);
        let existing: Option<(String, Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT signer_key_id, package, signature
             FROM endpoint_mls_key_package_offers
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND group_id=?4 AND device_id=?5",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    group_id.as_opaque().as_str(),
                    device_id.as_opaque().as_str(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some((key, package, signature)) = existing {
            if key != offer.signer_key_id
                || package != offer.package
                || signature != offer.signature
            {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO endpoint_mls_key_package_offers (
                  tenant_id,namespace_present,namespace_id,group_id,device_id,
                  signer_key_id,package,signature
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    group_id.as_opaque().as_str(),
                    device_id.as_opaque().as_str(),
                    &offer.signer_key_id,
                    &offer.package,
                    &offer.signature,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        }
        tx.commit().map_err(|error| map_sqlite_error(&error))
    }

    /// Bounded candidate Device IDs only. The BFF must authorize the direct Call,
    /// resolve each ID to the expected peer principal and verify the current key.
    ///
    /// # Errors
    /// Rejects oversized enumeration and unavailable/corrupt storage.
    pub fn endpoint_mls_offer_device_ids(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<String>, DurableStoreError> {
        if max_items == 0 || max_items > 16 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let conn = self.lock_connection()?;
        let ns = namespace_storage_key(scope);
        let mut stmt = conn
            .prepare(
                "SELECT device_id FROM endpoint_mls_key_package_offers
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4
             ORDER BY device_id LIMIT ?5",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = stmt
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    group_id.as_opaque().as_str(),
                    i64::try_from(max_items).unwrap_or(16),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_sqlite_error(&error))
    }

    /// Read a specific Device's signed PUBLIC `KeyPackage` (not an MLS secret).
    /// HTTP caller MUST independently authorize the same accepted Call and
    /// verify the current trusted Device signer before forwarding the offer.
    ///
    /// # Errors
    /// Returns durable/storage failures explicitly.
    pub fn endpoint_mls_offer(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<Option<EndpointMlsKeyPackageOffer>, DurableStoreError> {
        let conn = self.lock_connection()?;
        let ns = namespace_storage_key(scope);
        conn.query_row(
            "SELECT signer_key_id, package, signature
             FROM endpoint_mls_key_package_offers
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND group_id=?4 AND device_id=?5",
            params![
                scope.tenant_id.as_opaque().as_str(),
                ns.present,
                ns.value,
                group_id.as_opaque().as_str(),
                device_id.as_opaque().as_str(),
            ],
            |row| {
                Ok(EndpointMlsKeyPackageOffer {
                    signer_key_id: row.get(0)?,
                    package: row.get(1)?,
                    signature: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))
    }
}
