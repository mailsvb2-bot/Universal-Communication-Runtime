use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, FederationPeerStore};
use ucr_model::{
    DeviceId, EndpointId, EndpointKind, FederationPeerRecord, FederationTrustState, KeyId,
    NamespaceId, OpaqueId, TenantId, TenantScope,
};
use ucr_protocol::{
    canonical_federation_peer, validate_federation_credential_rotation,
    validate_federation_transition,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V29_OBJECTS_SQL: &str = r"
CREATE TABLE federation_peers (
    local_tenant_id TEXT NOT NULL,
    local_namespace_present INTEGER NOT NULL CHECK(local_namespace_present IN (0,1)),
    local_namespace_id TEXT NOT NULL,
    remote_tenant_id TEXT NOT NULL,
    remote_namespace_present INTEGER NOT NULL CHECK(remote_namespace_present IN (0,1)),
    remote_namespace_id TEXT NOT NULL,
    local_endpoint_id TEXT NOT NULL,
    remote_endpoint_id TEXT NOT NULL,
    remote_endpoint_kind TEXT NOT NULL CHECK(remote_endpoint_kind IN ('personal_node','organization_node')),
    expected_device_id TEXT NOT NULL,
    expected_signing_key_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('known','authenticated','authorized','trusted','revoked','blocked')),
    generation BLOB NOT NULL CHECK(length(generation)=8),
    PRIMARY KEY(local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id, remote_endpoint_id),
    CHECK((local_namespace_present=0 AND local_namespace_id='') OR
          (local_namespace_present=1 AND local_namespace_id<>'')),
    CHECK((remote_namespace_present=0 AND remote_namespace_id='') OR
          (remote_namespace_present=1 AND remote_namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE federation_peer_capabilities (
    local_tenant_id TEXT NOT NULL,
    local_namespace_present INTEGER NOT NULL,
    local_namespace_id TEXT NOT NULL,
    remote_tenant_id TEXT NOT NULL,
    remote_namespace_present INTEGER NOT NULL,
    remote_namespace_id TEXT NOT NULL,
    remote_endpoint_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    PRIMARY KEY(local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id,
                remote_endpoint_id, capability),
    FOREIGN KEY(local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id, remote_endpoint_id)
      REFERENCES federation_peers(local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id, remote_endpoint_id)
      ON DELETE CASCADE
) WITHOUT ROWID;
";

pub(super) fn create_v29_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V29_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}
pub(super) fn verify_schema_v29(connection: &Connection) -> Result<(), DurableStoreError> {
    super::offline_group_store::verify_schema_v28(connection)?;
    verify_table_columns(
        connection,
        "federation_peers",
        &[
            ("local_tenant_id", "TEXT", 1, 1),
            ("local_namespace_present", "INTEGER", 1, 2),
            ("local_namespace_id", "TEXT", 1, 3),
            ("remote_tenant_id", "TEXT", 1, 4),
            ("remote_namespace_present", "INTEGER", 1, 5),
            ("remote_namespace_id", "TEXT", 1, 6),
            ("local_endpoint_id", "TEXT", 1, 0),
            ("remote_endpoint_id", "TEXT", 1, 7),
            ("remote_endpoint_kind", "TEXT", 1, 0),
            ("expected_device_id", "TEXT", 1, 0),
            ("expected_signing_key_id", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
            ("generation", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "federation_peer_capabilities",
        &[
            ("local_tenant_id", "TEXT", 1, 1),
            ("local_namespace_present", "INTEGER", 1, 2),
            ("local_namespace_id", "TEXT", 1, 3),
            ("remote_tenant_id", "TEXT", 1, 4),
            ("remote_namespace_present", "INTEGER", 1, 5),
            ("remote_namespace_id", "TEXT", 1, 6),
            ("remote_endpoint_id", "TEXT", 1, 7),
            ("capability", "TEXT", 1, 8),
        ],
    )?;
    let mut statement = connection
        .prepare(
            "SELECT local_tenant_id, local_namespace_present, local_namespace_id,
                    remote_tenant_id, remote_namespace_present, remote_namespace_id,
                    remote_endpoint_id FROM federation_peers",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (lt, lp, ln, rt, rp, rn, endpoint) = row.map_err(|error| map_sqlite_error(&error))?;
        let local = stored_scope(&lt, lp, &ln)?;
        let remote = stored_scope(&rt, rp, &rn)?;
        let endpoint = EndpointId::from_opaque(parse_id(&endpoint)?);
        load_peer_from(connection, &local, &remote, &endpoint)?
            .ok_or(DurableStoreError::Corrupt)?;
    }
    Ok(())
}
impl FederationPeerStore for SqliteLocalStore {
    fn install_federation_peer(
        &self,
        record: &FederationPeerRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical =
            canonical_federation_peer(record).map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.state != FederationTrustState::Known || canonical.generation != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_peer_from(
            &transaction,
            &canonical.local_scope,
            &canonical.remote_scope,
            &canonical.remote_endpoint_id,
        )? {
            return if existing == canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_peer(&transaction, &canonical)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn federation_peer(
        &self,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
    ) -> Result<Option<FederationPeerRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_peer_from(&connection, local_scope, remote_scope, remote_endpoint_id)
    }

    fn transition_federation_peer(
        &self,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: FederationTrustState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let current = load_peer_from(&transaction, local_scope, remote_scope, remote_endpoint_id)?
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
        validate_federation_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        update_state(
            &transaction,
            &current,
            expected_generation,
            next_state,
            next_generation,
        )?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn rotate_federation_peer_credential(
        &self,
        current: &FederationPeerRecord,
        replacement: &FederationPeerRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let current =
            canonical_federation_peer(current).map_err(|_| DurableStoreError::InvalidRecord)?;
        let replacement =
            canonical_federation_peer(replacement).map_err(|_| DurableStoreError::InvalidRecord)?;
        validate_federation_credential_rotation(&current, &replacement)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let persisted = load_peer_from(
            &transaction,
            &current.local_scope,
            &current.remote_scope,
            &current.remote_endpoint_id,
        )?
        .ok_or(DurableStoreError::Conflict)?;
        if persisted == replacement {
            return Ok(DurableRecordStatus::Duplicate);
        }
        if persisted != current {
            return Err(DurableStoreError::Conflict);
        }
        update_credential(&transaction, &current, &replacement)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}
fn insert_peer(
    transaction: &Transaction<'_>,
    record: &FederationPeerRecord,
) -> Result<(), DurableStoreError> {
    let local_ns = namespace_storage_key(&record.local_scope);
    let remote_ns = namespace_storage_key(&record.remote_scope);
    transaction
        .execute(
            "INSERT INTO federation_peers(
                local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id,
                local_endpoint_id, remote_endpoint_id, remote_endpoint_kind,
                expected_device_id, expected_signing_key_id, state, generation)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.local_scope.tenant_id.as_opaque().as_str(),
                local_ns.present,
                local_ns.value,
                record.remote_scope.tenant_id.as_opaque().as_str(),
                remote_ns.present,
                remote_ns.value,
                record.local_endpoint_id.as_opaque().as_str(),
                record.remote_endpoint_id.as_opaque().as_str(),
                endpoint_kind_text(record.remote_endpoint_kind),
                record.expected_device_id.as_opaque().as_str(),
                record.expected_signing_key_id.as_opaque().as_str(),
                state_text(record.state),
                encode_u64(record.generation).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    for capability in &record.allowed_capabilities {
        transaction
            .execute(
                "INSERT INTO federation_peer_capabilities(
                local_tenant_id, local_namespace_present, local_namespace_id,
                remote_tenant_id, remote_namespace_present, remote_namespace_id,
                remote_endpoint_id, capability) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    record.local_scope.tenant_id.as_opaque().as_str(),
                    local_ns.present,
                    local_ns.value,
                    record.remote_scope.tenant_id.as_opaque().as_str(),
                    remote_ns.present,
                    remote_ns.value,
                    record.remote_endpoint_id.as_opaque().as_str(),
                    capability,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}
fn load_peer_from(
    connection: &Connection,
    local_scope: &TenantScope,
    remote_scope: &TenantScope,
    remote_endpoint_id: &EndpointId,
) -> Result<Option<FederationPeerRecord>, DurableStoreError> {
    let local_ns = namespace_storage_key(local_scope);
    let remote_ns = namespace_storage_key(remote_scope);
    let row = connection
        .query_row(
            "SELECT local_endpoint_id, remote_endpoint_kind, expected_device_id,
                    expected_signing_key_id, state, generation
             FROM federation_peers
             WHERE local_tenant_id=?1 AND local_namespace_present=?2 AND local_namespace_id=?3
               AND remote_tenant_id=?4 AND remote_namespace_present=?5 AND remote_namespace_id=?6
               AND remote_endpoint_id=?7",
            params![
                local_scope.tenant_id.as_opaque().as_str(),
                local_ns.present,
                local_ns.value,
                remote_scope.tenant_id.as_opaque().as_str(),
                remote_ns.present,
                remote_ns.value,
                remote_endpoint_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((local_endpoint, endpoint_kind, device, key, state, generation)) = row else {
        return Ok(None);
    };
    let mut statement = connection
        .prepare(
            "SELECT capability FROM federation_peer_capabilities
             WHERE local_tenant_id=?1 AND local_namespace_present=?2 AND local_namespace_id=?3
               AND remote_tenant_id=?4 AND remote_namespace_present=?5 AND remote_namespace_id=?6
               AND remote_endpoint_id=?7 ORDER BY capability",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let capabilities = statement
        .query_map(
            params![
                local_scope.tenant_id.as_opaque().as_str(),
                local_ns.present,
                local_ns.value,
                remote_scope.tenant_id.as_opaque().as_str(),
                remote_ns.present,
                remote_ns.value,
                remote_endpoint_id.as_opaque().as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error))?;
    let record = FederationPeerRecord {
        local_scope: local_scope.clone(),
        remote_scope: remote_scope.clone(),
        local_endpoint_id: EndpointId::from_opaque(parse_id(&local_endpoint)?),
        remote_endpoint_id: remote_endpoint_id.clone(),
        remote_endpoint_kind: parse_endpoint_kind(&endpoint_kind)?,
        expected_device_id: DeviceId::from_opaque(parse_id(&device)?),
        expected_signing_key_id: KeyId::from_opaque(parse_id(&key)?),
        allowed_capabilities: capabilities,
        state: parse_state(&state)?,
        generation: decode_u64(&generation)?,
    };
    canonical_federation_peer(&record)
        .map(Some)
        .map_err(|_| DurableStoreError::Corrupt)
}
fn update_state(
    transaction: &Transaction<'_>,
    current: &FederationPeerRecord,
    expected_generation: u64,
    next_state: FederationTrustState,
    next_generation: u64,
) -> Result<(), DurableStoreError> {
    let local_ns = namespace_storage_key(&current.local_scope);
    let remote_ns = namespace_storage_key(&current.remote_scope);
    let changed = transaction
        .execute(
            "UPDATE federation_peers SET state=?1, generation=?2
         WHERE local_tenant_id=?3 AND local_namespace_present=?4 AND local_namespace_id=?5
           AND remote_tenant_id=?6 AND remote_namespace_present=?7 AND remote_namespace_id=?8
           AND remote_endpoint_id=?9 AND generation=?10",
            params![
                state_text(next_state),
                encode_u64(next_generation).as_slice(),
                current.local_scope.tenant_id.as_opaque().as_str(),
                local_ns.present,
                local_ns.value,
                current.remote_scope.tenant_id.as_opaque().as_str(),
                remote_ns.present,
                remote_ns.value,
                current.remote_endpoint_id.as_opaque().as_str(),
                encode_u64(expected_generation).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(DurableStoreError::Conflict)
    }
}

fn update_credential(
    transaction: &Transaction<'_>,
    current: &FederationPeerRecord,
    replacement: &FederationPeerRecord,
) -> Result<(), DurableStoreError> {
    let local_ns = namespace_storage_key(&current.local_scope);
    let remote_ns = namespace_storage_key(&current.remote_scope);
    let changed = transaction
        .execute(
            "UPDATE federation_peers
         SET expected_device_id=?1, expected_signing_key_id=?2, state='known', generation=?3
         WHERE local_tenant_id=?4 AND local_namespace_present=?5 AND local_namespace_id=?6
           AND remote_tenant_id=?7 AND remote_namespace_present=?8 AND remote_namespace_id=?9
           AND remote_endpoint_id=?10 AND expected_device_id=?11
           AND expected_signing_key_id=?12 AND state=?13 AND generation=?14",
            params![
                replacement.expected_device_id.as_opaque().as_str(),
                replacement.expected_signing_key_id.as_opaque().as_str(),
                encode_u64(replacement.generation).as_slice(),
                current.local_scope.tenant_id.as_opaque().as_str(),
                local_ns.present,
                local_ns.value,
                current.remote_scope.tenant_id.as_opaque().as_str(),
                remote_ns.present,
                remote_ns.value,
                current.remote_endpoint_id.as_opaque().as_str(),
                current.expected_device_id.as_opaque().as_str(),
                current.expected_signing_key_id.as_opaque().as_str(),
                state_text(current.state),
                encode_u64(current.generation).as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(DurableStoreError::Conflict)
    }
}

const fn endpoint_kind_text(kind: EndpointKind) -> &'static str {
    match kind {
        EndpointKind::PersonalNode => "personal_node",
        EndpointKind::OrganizationNode => "organization_node",
        EndpointKind::Device
        | EndpointKind::ExternalAccount
        | EndpointKind::WebSession
        | EndpointKind::TemporaryPeer => "invalid",
    }
}
fn parse_endpoint_kind(value: &str) -> Result<EndpointKind, DurableStoreError> {
    match value {
        "personal_node" => Ok(EndpointKind::PersonalNode),
        "organization_node" => Ok(EndpointKind::OrganizationNode),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn state_text(state: FederationTrustState) -> &'static str {
    match state {
        FederationTrustState::Known => "known",
        FederationTrustState::Authenticated => "authenticated",
        FederationTrustState::Authorized => "authorized",
        FederationTrustState::Trusted => "trusted",
        FederationTrustState::Revoked => "revoked",
        FederationTrustState::Blocked => "blocked",
    }
}

fn parse_state(value: &str) -> Result<FederationTrustState, DurableStoreError> {
    match value {
        "known" => Ok(FederationTrustState::Known),
        "authenticated" => Ok(FederationTrustState::Authenticated),
        "authorized" => Ok(FederationTrustState::Authorized),
        "trusted" => Ok(FederationTrustState::Trusted),
        "revoked" => Ok(FederationTrustState::Revoked),
        "blocked" => Ok(FederationTrustState::Blocked),
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

const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}
