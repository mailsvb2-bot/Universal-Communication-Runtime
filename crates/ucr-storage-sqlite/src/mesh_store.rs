use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, MeshGroupStore};
use ucr_model::{
    DeviceId, GroupId, GroupMemberState, GroupPermission, MeshCursor, MeshGroupMessagePage,
    MeshGroupMessageReplica, OfflineGroupMessageReplica, PrincipalId, PrincipalKind, PrincipalRef,
    ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    MAX_MESH_PATH_DEVICES, append_mesh_recipient, canonical_mesh_group_message_replica,
    canonical_offline_group_message_replica, mesh_group_cursor, mesh_group_cursor_sequence,
    validate_mesh_group_page_size, validate_mesh_source,
};

use super::{
    SqliteLocalStore, group_store, map_schema_change_error, map_sqlite_error, message_store,
    namespace_storage_key, store_forward_store, verify_table_columns,
};

pub(super) const V25_OBJECTS_SQL: &str = r"
CREATE TABLE mesh_group_message_hops (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    hop_index INTEGER NOT NULL CHECK(hop_index BETWEEN 0 AND 7),
    device_id TEXT NOT NULL CHECK(device_id<>''),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id, hop_index),
    UNIQUE(tenant_id, namespace_present, namespace_id, message_id, device_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES offline_group_messages(tenant_id, namespace_present, namespace_id, message_id)
      ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v25_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V25_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v25(connection: &Connection) -> Result<(), DurableStoreError> {
    store_forward_store::verify_schema_v24(connection)?;
    verify_table_columns(
        connection,
        "mesh_group_message_hops",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("hop_index", "INTEGER", 1, 5),
            ("device_id", "TEXT", 1, 0),
        ],
    )?;
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error))?;
    if foreign_key_check
        .query([])
        .map_err(|error| map_sqlite_error(&error))?
        .next()
        .map_err(|error| map_sqlite_error(&error))?
        .is_some()
    {
        return Err(DurableStoreError::Corrupt);
    }
    drop(foreign_key_check);
    verify_mesh_paths(connection)
}

impl MeshGroupStore for SqliteLocalStore {
    fn mesh_group_message_page(
        &self,
        source: &ScopedPrincipal,
        recipient: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        cursor: Option<&MeshCursor>,
        max_items: usize,
    ) -> Result<MeshGroupMessagePage, DurableStoreError> {
        validate_mesh_group_page_size(max_items).map_err(|_| DurableStoreError::InvalidRecord)?;
        if source.scope != *scope || recipient.scope != *scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let source_device = scoped_device_id(source)?;
        let recipient_device = scoped_device_id(recipient)?;
        let after = cursor.map_or(Ok(0), |cursor| {
            mesh_group_cursor_sequence(scope, group_id, cursor)
                .map_err(|_| DurableStoreError::InvalidRecord)
        })?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = group_store::load_group_from(&transaction, scope, group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_active_reader(&transaction, &group, source)?;
        let recipient_membership = require_active_reader(&transaction, &group, recipient)?;
        let (raw, has_more, scanned_sequence) =
            load_mesh_replica_rows(&transaction, scope, group_id, after, max_items)?;
        let eligibility = MeshEligibility {
            scope,
            group_id,
            group: &group,
            recipient_membership: &recipient_membership,
            source_device: &source_device,
            recipient_device: &recipient_device,
        };
        let mut records = Vec::new();
        for row in raw {
            if let Some(record) = eligible_mesh_record(&transaction, &eligibility, row)? {
                records.push(record);
            }
        }
        let next_cursor = next_mesh_cursor(scope, group_id, has_more, scanned_sequence)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(MeshGroupMessagePage {
            scope: scope.clone(),
            group_id: group_id.clone(),
            records,
            next_cursor,
        })
    }

    fn reconcile_mesh_group_message(
        &self,
        recipient: &ScopedPrincipal,
        record: &MeshGroupMessageReplica,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_mesh_group_message_replica(record)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let recipient_device = scoped_device_id(recipient)?;
        let extended = append_mesh_recipient(&canonical, &recipient_device)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if recipient.scope != extended.record.message.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = group_store::load_group_from(
            &transaction,
            &extended.record.message.scope,
            &extended.record.group_id,
        )?
        .ok_or(DurableStoreError::InvalidRecord)?;
        if extended.record.message.conversation != group.conversation
            || extended.record.message.delivery_policy != group.delivery_policy
            || extended.record.group_generation > group.replication_generation
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let recipient_membership = require_active_reader(&transaction, &group, recipient)?;
        if !group_store::history_allows(&group, &recipient_membership, &extended.record.message) {
            return Err(DurableStoreError::PermissionDenied);
        }
        let author_membership = group_store::load_membership_from(
            &transaction,
            &group.scope,
            &group.group_id,
            &extended.record.author.principal,
        )?
        .filter(|membership| membership.member == extended.record.author.principal)
        .ok_or(DurableStoreError::PermissionDenied)?;
        if !membership_active_at_generation(&author_membership, extended.record.group_generation) {
            return Err(DurableStoreError::PermissionDenied);
        }
        let existing = message_store::load_message_from(
            &transaction,
            &extended.record.message.scope,
            &extended.record.message.message_id,
        )?;
        let status = match existing {
            Some(existing) if existing == extended.record.message => DurableRecordStatus::Duplicate,
            Some(_) => return Err(DurableStoreError::Conflict),
            None => {
                message_store::insert_message_row(&transaction, &extended.record.message)?;
                message_store::insert_message_children(&transaction, &extended.record.message)?;
                DurableRecordStatus::Persisted
            }
        };
        let has_replica = offline_replica_exists(
            &transaction,
            &extended.record.message.scope,
            &extended.record.message.message_id,
        )?;
        if !has_replica {
            insert_forwarded_replica(&transaction, &extended.record)?;
            insert_mesh_path(&transaction, &extended)?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }
}

type MeshReplicaRow = (i64, String, Vec<u8>, String, String);

fn load_mesh_replica_rows(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
    after: u64,
    max_items: usize,
) -> Result<(Vec<MeshReplicaRow>, bool, Option<i64>), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = i64::try_from(max_items.saturating_add(1)).unwrap_or(i64::MAX);
    let mut statement = connection
        .prepare(
            "SELECT replica_seq, message_id, group_generation, author_principal_id,
                    author_principal_kind
             FROM offline_group_messages
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND group_id=?4 AND replica_seq>?5
             ORDER BY replica_seq LIMIT ?6",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group_id.as_opaque().as_str(),
                i64::try_from(after).unwrap_or(i64::MAX),
                limit,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut raw = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error))?;
    let has_more = raw.len() > max_items;
    if has_more {
        raw.pop();
    }
    let scanned_sequence = raw.last().map(|row| row.0);
    Ok((raw, has_more, scanned_sequence))
}

struct MeshEligibility<'a> {
    scope: &'a TenantScope,
    group_id: &'a GroupId,
    group: &'a ucr_model::GroupRecord,
    recipient_membership: &'a ucr_model::GroupMembership,
    source_device: &'a DeviceId,
    recipient_device: &'a DeviceId,
}

fn eligible_mesh_record(
    connection: &Connection,
    context: &MeshEligibility<'_>,
    row: MeshReplicaRow,
) -> Result<Option<MeshGroupMessageReplica>, DurableStoreError> {
    let (_, message_id, generation, author_id, author_kind) = row;
    let message_id = ucr_model::MessageId::from_opaque(parse_id(&message_id)?);
    let message = message_store::load_message_from(connection, context.scope, &message_id)?
        .ok_or(DurableStoreError::Corrupt)?;
    if !group_store::history_allows(context.group, context.recipient_membership, &message) {
        return Ok(None);
    }
    let record = OfflineGroupMessageReplica {
        author: ScopedPrincipal {
            scope: context.scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&author_id)?),
                kind: group_store::parse_principal_kind(&author_kind)?,
            },
        },
        group_id: context.group_id.clone(),
        group_generation: decode_u64(&generation)?,
        message,
    };
    let path = load_mesh_path(connection, context.scope, &message_id)?
        .unwrap_or_else(|| vec![record.message.author_device.device_id.clone()]);
    if path.len() >= MAX_MESH_PATH_DEVICES || path.contains(context.recipient_device) {
        return Ok(None);
    }
    let mesh = MeshGroupMessageReplica {
        record,
        forward_path: path,
    };
    if canonical_mesh_group_message_replica(&mesh).is_err()
        || validate_mesh_source(&mesh, context.source_device).is_err()
    {
        return Ok(None);
    }
    Ok(Some(mesh))
}

fn next_mesh_cursor(
    scope: &TenantScope,
    group_id: &GroupId,
    has_more: bool,
    scanned_sequence: Option<i64>,
) -> Result<Option<MeshCursor>, DurableStoreError> {
    if !has_more {
        return Ok(None);
    }
    let sequence = u64::try_from(scanned_sequence.ok_or(DurableStoreError::Corrupt)?)
        .map_err(|_| DurableStoreError::Corrupt)?;
    Ok(Some(mesh_group_cursor(scope, group_id, sequence)))
}

fn require_active_reader(
    connection: &Connection,
    group: &ucr_model::GroupRecord,
    principal: &ScopedPrincipal,
) -> Result<ucr_model::GroupMembership, DurableStoreError> {
    let membership = group_store::load_membership_from(
        connection,
        &group.scope,
        &group.group_id,
        &principal.principal,
    )?
    .filter(|membership| membership.member == principal.principal)
    .ok_or(DurableStoreError::PermissionDenied)?;
    if membership.state != GroupMemberState::Active
        || !membership
            .permissions
            .contains(&GroupPermission::ReadHistory)
    {
        return Err(DurableStoreError::PermissionDenied);
    }
    Ok(membership)
}

fn membership_active_at_generation(
    membership: &ucr_model::GroupMembership,
    generation: u64,
) -> bool {
    membership.joined_revision <= generation
        && membership
            .removed_revision
            .is_none_or(|removed| generation < removed)
}

fn scoped_device_id(principal: &ScopedPrincipal) -> Result<DeviceId, DurableStoreError> {
    if principal.principal.kind != PrincipalKind::Device {
        return Err(DurableStoreError::PermissionDenied);
    }
    Ok(DeviceId::from_opaque(
        principal.principal.principal_id.as_opaque().clone(),
    ))
}

fn offline_replica_exists(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &ucr_model::MessageId,
) -> Result<bool, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT 1 FROM offline_group_messages
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|error| map_sqlite_error(&error))
}

fn insert_forwarded_replica(
    transaction: &Transaction<'_>,
    record: &OfflineGroupMessageReplica,
) -> Result<(), DurableStoreError> {
    let record = canonical_offline_group_message_replica(record)
        .map_err(|_| DurableStoreError::InvalidRecord)?;
    let namespace = namespace_storage_key(&record.message.scope);
    transaction
        .execute(
            "INSERT INTO offline_group_messages (
                tenant_id, namespace_present, namespace_id, group_id, message_id,
                group_generation, author_principal_id, author_principal_kind
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                record.message.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                record.group_id.as_opaque().as_str(),
                record.message.message_id.as_opaque().as_str(),
                record.group_generation.to_be_bytes().as_slice(),
                record.author.principal.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(record.author.principal.kind),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn insert_mesh_path(
    transaction: &Transaction<'_>,
    record: &MeshGroupMessageReplica,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&record.record.message.scope);
    for (index, device) in record.forward_path.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO mesh_group_message_hops (
                    tenant_id, namespace_present, namespace_id, message_id, hop_index, device_id
                 ) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    record.record.message.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    record.record.message.message_id.as_opaque().as_str(),
                    i64::try_from(index).map_err(|_| DurableStoreError::Full)?,
                    device.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn load_mesh_path(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &ucr_model::MessageId,
) -> Result<Option<Vec<DeviceId>>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT hop_index, device_id FROM mesh_group_message_hops
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4
             ORDER BY hop_index",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut path = Vec::new();
    for row in rows {
        let (index, device) = row.map_err(|error| map_sqlite_error(&error))?;
        if usize::try_from(index).ok() != Some(path.len()) {
            return Err(DurableStoreError::Corrupt);
        }
        path.push(DeviceId::from_opaque(parse_id(&device)?));
    }
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

fn verify_mesh_paths(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT h.tenant_id, h.namespace_present, h.namespace_id, h.message_id,
                    COUNT(*), MIN(h.hop_index), MAX(h.hop_index), COUNT(DISTINCT h.device_id),
                    m.author_device_id,
                    MIN(CASE WHEN h.hop_index=0 THEN h.device_id END),
                    o.author_principal_id, o.author_principal_kind
             FROM mesh_group_message_hops h
             JOIN messages m USING(tenant_id, namespace_present, namespace_id, message_id)
             JOIN offline_group_messages o USING(tenant_id, namespace_present, namespace_id, message_id)
             GROUP BY h.tenant_id, h.namespace_present, h.namespace_id, h.message_id",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (count, min, max, distinct, author_device, first, author_id, author_kind) =
            row.map_err(|error| map_sqlite_error(&error))?;
        if !(2..=i64::try_from(MAX_MESH_PATH_DEVICES).unwrap_or(8)).contains(&count)
            || min != 0
            || max != count - 1
            || distinct != count
            || first.as_deref() != Some(author_device.as_str())
            || author_kind != "device"
            || author_id != author_device
        {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

fn parse_id(value: &str) -> Result<ucr_model::OpaqueId, DurableStoreError> {
    ucr_model::OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_store::tests::TestDb;
    use ucr_core::{GroupStore, MeshGroupStore, StorageProvider};
    use ucr_model::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("phase28-sqlite-tenant")),
            namespace_id: None,
        }
    }

    fn device(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(value)),
                kind: PrincipalKind::Device,
            },
        }
    }

    fn setup_group(
        store: &SqliteLocalStore,
    ) -> (
        GroupRecord,
        ScopedPrincipal,
        ScopedPrincipal,
        ScopedPrincipal,
    ) {
        let a = device("phase28-sqlite-device-a");
        let b = device("phase28-sqlite-device-b");
        let c = device("phase28-sqlite-device-c");
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase28-sqlite-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase28-sqlite-group")),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::Temporary {
                owner: Some(b.principal.clone()),
                expires_at_unix_ms: 9_999_999_999_999,
            },
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: vec![],
            replication_generation: 0,
            revision: 0,
        };
        store
            .create_group(&conversation, &group, &b)
            .expect("group");
        for (event, expected_revision, member) in [
            ("phase28-sqlite-add-a", 0, a.principal.clone()),
            ("phase28-sqlite-add-c", 1, c.principal.clone()),
        ] {
            store
                .apply_group_change(
                    &b,
                    &GroupChange {
                        event_id: EventId::from_opaque(oid(event)),
                        scope: scope(),
                        group_id: group.group_id.clone(),
                        expected_revision,
                        kind: GroupChangeKind::AddMember {
                            member,
                            role: GroupRole::Member,
                        },
                        next_crypto_state: None,
                    },
                )
                .expect("add member");
        }
        (group, a, b, c)
    }

    fn incoming(group: &GroupRecord, a: &ScopedPrincipal) -> MeshGroupMessageReplica {
        MeshGroupMessageReplica {
            record: OfflineGroupMessageReplica {
                author: a.clone(),
                group_id: group.group_id.clone(),
                group_generation: 2,
                message: MessageEnvelope {
                    message_id: MessageId::from_opaque(oid("phase28-sqlite-message")),
                    scope: scope(),
                    conversation: group.conversation.clone(),
                    author: ActorRef {
                        actor_id: ActorId::from_opaque(oid("phase28-sqlite-actor")),
                        kind: ActorKind::Person,
                        on_behalf_of: None,
                    },
                    author_device: DeviceRef {
                        device_id: DeviceId::from_opaque(oid("phase28-sqlite-device-a")),
                        identity_id: IdentityId::from_opaque(oid("phase28-sqlite-identity-a")),
                    },
                    created_at_unix_ms: 1,
                    logical_order: 1,
                    content: b"mesh restart hello".to_vec(),
                    attachment_ids: vec![],
                    reply_to: None,
                    relations: vec![],
                    crypto_metadata: None,
                    delivery_policy: DeliveryPolicy::Durable,
                    delivery_state: DeliveryState::Persisted,
                    origin: OriginRef {
                        principal_id: Some(a.principal.principal_id.clone()),
                        endpoint_id: None,
                        integration_id: None,
                    },
                    correlation: CorrelationContext {
                        correlation_id: oid("phase28-sqlite-correlation"),
                        causation_id: None,
                        idempotency_key: Some("phase28-sqlite-idempotency".into()),
                    },
                    extensions: vec![],
                    external_mappings: vec![],
                    signature: Some(MessageSignature {
                        key_id: KeyId::from_opaque(oid("phase28-sqlite-key")),
                        algorithm_id: "ed25519".into(),
                        algorithm_version: 1,
                        signature: vec![9; 64],
                    }),
                },
            },
            forward_path: vec![DeviceId::from_opaque(oid("phase28-sqlite-device-a"))],
        }
    }

    #[test]
    fn mesh_path_survives_restart_and_reexports_from_current_tail_only() {
        let db = TestDb::new();
        let (group, a, b, c) = {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            let (group, a, b, c) = setup_group(&store);
            let record = incoming(&group, &a);
            assert_eq!(
                store.reconcile_mesh_group_message(&b, &record),
                Ok(DurableRecordStatus::Persisted)
            );
            (group, a, b, c)
        };
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        let page = reopened
            .mesh_group_message_page(&b, &c, &scope(), &group.group_id, None, 8)
            .expect("mesh page");
        assert_eq!(page.records.len(), 1);
        assert_eq!(
            page.records[0].forward_path,
            vec![
                DeviceId::from_opaque(oid("phase28-sqlite-device-a")),
                DeviceId::from_opaque(oid("phase28-sqlite-device-b")),
            ]
        );
        let no_backtrack = reopened
            .mesh_group_message_page(&b, &a, &scope(), &group.group_id, None, 8)
            .expect("loop filtered");
        assert!(no_backtrack.records.is_empty());
    }

    #[test]
    fn v24_to_v25_migration_creates_empty_mesh_sidecar_without_inference() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize current");
            assert_eq!(store.schema_version(), Ok(25));
        }
        {
            let connection = Connection::open(db.path()).expect("raw open");
            connection
                .execute_batch("DROP TABLE mesh_group_message_hops; PRAGMA user_version=24;")
                .expect("downgrade fixture");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v24 to v25");
        assert_eq!(migrated.schema_version(), Ok(25));
        let connection = Connection::open(db.path()).expect("verify raw");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM mesh_group_message_hops", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 0);
    }
}
