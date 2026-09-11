use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, OfflineGroupStore};
use ucr_model::{
    DeliveryPolicy, GroupChange, GroupChangeKind, GroupCryptoState, GroupHistoryPolicy, GroupId,
    GroupMemberState, GroupMembership, GroupPermission, GroupRecord, GroupRole, MessageEnvelope,
    OfflineGroupChangePage, OfflineGroupChangeReplica, OfflineGroupCursor, OfflineGroupMessagePage,
    OfflineGroupMessageReplica, OfflineGroupStreamKind, OpaqueId, PrincipalId, PrincipalRef,
    PublicGroupDiscovery, PublicGroupJoinPolicy, PublicGroupPolicy, ScopedPrincipal, TenantId,
    TenantScope,
};
use ucr_protocol::{
    OfflineGroupError, canonical_offline_group_change_replica,
    canonical_offline_group_message_replica, offline_group_cursor, offline_group_cursor_sequence,
    validate_offline_group_page_size,
};

use super::{
    SqliteLocalStore, call_store, group_store, map_schema_change_error, map_sqlite_error,
    message_store, namespace_storage_key, verify_table_columns,
};

pub const V23_OBJECTS_SQL: &str = r"
CREATE TABLE offline_group_changes (
    replica_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    group_generation BLOB NOT NULL CHECK(length(group_generation)=8),
    actor_principal_id TEXT NOT NULL,
    actor_principal_kind TEXT NOT NULL,
    expected_revision BLOB NOT NULL CHECK(length(expected_revision)=8),
    change_kind TEXT NOT NULL CHECK(change_kind IN ('add_member','remove_member','change_role','transfer_ownership','set_history_policy','set_public_policy','set_delivery_policy')),
    target_principal_id TEXT,
    target_principal_kind TEXT,
    role TEXT CHECK(role IS NULL OR role IN ('owner','admin','member')),
    history_kind TEXT CHECK(history_kind IS NULL OR history_kind IN ('none','from_join','last_n','from_timestamp','full','custom')),
    history_value INTEGER,
    history_custom TEXT,
    public_join_policy TEXT CHECK(public_join_policy IS NULL OR public_join_policy IN ('open','approval_required','invite_only')),
    public_discovery TEXT CHECK(public_discovery IS NULL OR public_discovery IN ('unlisted','discoverable')),
    public_indexed INTEGER CHECK(public_indexed IS NULL OR public_indexed IN (0,1)),
    delivery_policy TEXT,
    crypto_capability_id TEXT,
    crypto_epoch BLOB CHECK(crypto_epoch IS NULL OR length(crypto_epoch)=8),
    crypto_state_ref TEXT,
    UNIQUE(tenant_id, namespace_present, namespace_id, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES group_changes(tenant_id, namespace_present, namespace_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>'')),
    CHECK((crypto_capability_id IS NULL AND crypto_epoch IS NULL AND crypto_state_ref IS NULL) OR
          (crypto_capability_id IS NOT NULL AND crypto_epoch IS NOT NULL AND crypto_state_ref IS NOT NULL))
);
CREATE INDEX offline_group_changes_group_seq
ON offline_group_changes(tenant_id, namespace_present, namespace_id, group_id, replica_seq);

CREATE TABLE offline_group_messages (
    replica_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    group_generation BLOB NOT NULL CHECK(length(group_generation)=8),
    author_principal_id TEXT NOT NULL,
    author_principal_kind TEXT NOT NULL,
    UNIQUE(tenant_id, namespace_present, namespace_id, message_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
);
CREATE INDEX offline_group_messages_group_seq
ON offline_group_messages(tenant_id, namespace_present, namespace_id, group_id, replica_seq);
";

pub fn create_v23_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V23_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub fn verify_schema_v23(connection: &Connection) -> Result<(), DurableStoreError> {
    call_store::verify_schema_v22(connection)?;
    verify_table_columns(
        connection,
        "offline_group_changes",
        &[
            ("replica_seq", "INTEGER", 0, 1),
            ("tenant_id", "TEXT", 1, 0),
            ("namespace_present", "INTEGER", 1, 0),
            ("namespace_id", "TEXT", 1, 0),
            ("group_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 0),
            ("group_generation", "BLOB", 1, 0),
            ("actor_principal_id", "TEXT", 1, 0),
            ("actor_principal_kind", "TEXT", 1, 0),
            ("expected_revision", "BLOB", 1, 0),
            ("change_kind", "TEXT", 1, 0),
            ("target_principal_id", "TEXT", 0, 0),
            ("target_principal_kind", "TEXT", 0, 0),
            ("role", "TEXT", 0, 0),
            ("history_kind", "TEXT", 0, 0),
            ("history_value", "INTEGER", 0, 0),
            ("history_custom", "TEXT", 0, 0),
            ("public_join_policy", "TEXT", 0, 0),
            ("public_discovery", "TEXT", 0, 0),
            ("public_indexed", "INTEGER", 0, 0),
            ("delivery_policy", "TEXT", 0, 0),
            ("crypto_capability_id", "TEXT", 0, 0),
            ("crypto_epoch", "BLOB", 0, 0),
            ("crypto_state_ref", "TEXT", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "offline_group_messages",
        &[
            ("replica_seq", "INTEGER", 0, 1),
            ("tenant_id", "TEXT", 1, 0),
            ("namespace_present", "INTEGER", 1, 0),
            ("namespace_id", "TEXT", 1, 0),
            ("group_id", "TEXT", 1, 0),
            ("message_id", "TEXT", 1, 0),
            ("group_generation", "BLOB", 1, 0),
            ("author_principal_id", "TEXT", 1, 0),
            ("author_principal_kind", "TEXT", 1, 0),
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
    verify_change_rows(connection)?;
    verify_message_rows(connection)
}

pub fn record_change_replica(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    change: &GroupChange,
    group_generation: u64,
) -> Result<(), DurableStoreError> {
    let replica = OfflineGroupChangeReplica {
        actor: actor.clone(),
        group_generation,
        change: change.clone(),
    };
    canonical_offline_group_change_replica(&replica)
        .map_err(|_| DurableStoreError::InvalidRecord)?;
    let fields = encode_change(change);
    let namespace = namespace_storage_key(&change.scope);
    transaction
        .execute(
            "INSERT INTO offline_group_changes (
                tenant_id, namespace_present, namespace_id, group_id, event_id,
                group_generation, actor_principal_id, actor_principal_kind, expected_revision,
                change_kind, target_principal_id, target_principal_kind, role,
                history_kind, history_value, history_custom, public_join_policy,
                public_discovery, public_indexed, delivery_policy, crypto_capability_id,
                crypto_epoch, crypto_state_ref
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            params![
                change.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                change.group_id.as_opaque().as_str(),
                change.event_id.as_opaque().as_str(),
                group_generation.to_be_bytes().as_slice(),
                actor.principal.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(actor.principal.kind),
                change.expected_revision.to_be_bytes().as_slice(),
                fields.kind,
                fields.target_id,
                fields.target_kind,
                fields.role,
                fields.history_kind,
                fields.history_value,
                fields.history_custom,
                fields.public_join,
                fields.public_discovery,
                fields.public_indexed,
                fields.delivery_policy,
                fields.crypto_capability,
                fields.crypto_epoch.as_ref().map(<[u8; 8]>::as_slice),
                fields.crypto_state_ref,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

pub fn record_message_replica(
    transaction: &Transaction<'_>,
    author: &ScopedPrincipal,
    group: &GroupRecord,
    message: &MessageEnvelope,
) -> Result<(), DurableStoreError> {
    let replica = OfflineGroupMessageReplica {
        author: author.clone(),
        group_id: group.group_id.clone(),
        group_generation: group.replication_generation,
        message: message.clone(),
    };
    match canonical_offline_group_message_replica(&replica) {
        Ok(_) => {}
        Err(OfflineGroupError::MissingSignature) => {
            return Ok(());
        }
        Err(_) => return Err(DurableStoreError::InvalidRecord),
    }
    let namespace = namespace_storage_key(&message.scope);
    transaction
        .execute(
            "INSERT INTO offline_group_messages (
                tenant_id, namespace_present, namespace_id, group_id, message_id,
                group_generation, author_principal_id, author_principal_kind
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                message.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group.group_id.as_opaque().as_str(),
                message.message_id.as_opaque().as_str(),
                group.replication_generation.to_be_bytes().as_slice(),
                author.principal.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(author.principal.kind),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

impl OfflineGroupStore for SqliteLocalStore {
    fn offline_group_change_page(
        &self,
        source: &ScopedPrincipal,
        recipient: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        cursor: Option<&OfflineGroupCursor>,
        max_items: usize,
    ) -> Result<OfflineGroupChangePage, DurableStoreError> {
        validate_offline_group_page_size(max_items)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        require_scope(source, recipient, scope)?;
        let after = decode_cursor(scope, group_id, OfflineGroupStreamKind::Changes, cursor)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = group_store::load_group_from(&transaction, scope, group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_two_active_members(&transaction, &group, source, recipient)?;
        let namespace = namespace_storage_key(scope);
        let limit = i64::try_from(max_items.saturating_add(1)).unwrap_or(i64::MAX);
        let mut statement = transaction
            .prepare(
                "SELECT replica_seq, event_id, group_generation, actor_principal_id,
                        actor_principal_kind, expected_revision, change_kind, target_principal_id,
                        target_principal_kind, role, history_kind, history_value, history_custom,
                        public_join_policy, public_discovery, public_indexed, delivery_policy,
                        crypto_capability_id, crypto_epoch, crypto_state_ref
                 FROM offline_group_changes
                 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4
                   AND actor_principal_id=?5 AND actor_principal_kind=?6 AND replica_seq>?7
                 ORDER BY replica_seq LIMIT ?8",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let rows = statement
            .query_map(
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    group_id.as_opaque().as_str(),
                    source.principal.principal_id.as_opaque().as_str(),
                    group_store::principal_kind_name(source.principal.kind),
                    i64::try_from(after).unwrap_or(i64::MAX),
                    limit,
                ],
                read_change_row,
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let mut entries = Vec::new();
        for row in rows {
            let row = row.map_err(|error| map_sqlite_error(&error))?;
            entries.push((row.sequence, decode_change_row(scope, group_id, row)?));
        }
        drop(statement);
        let has_more = entries.len() > max_items;
        if has_more {
            entries.pop();
        }
        let next_cursor = has_more.then(|| {
            offline_group_cursor(
                scope,
                group_id,
                OfflineGroupStreamKind::Changes,
                entries.last().expect("bounded nonempty page").0,
            )
        });
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(OfflineGroupChangePage {
            scope: scope.clone(),
            group_id: group_id.clone(),
            records: entries.into_iter().map(|(_, record)| record).collect(),
            next_cursor,
        })
    }

    fn offline_group_message_page(
        &self,
        source: &ScopedPrincipal,
        recipient: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        cursor: Option<&OfflineGroupCursor>,
        max_items: usize,
    ) -> Result<OfflineGroupMessagePage, DurableStoreError> {
        validate_offline_group_page_size(max_items)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        require_scope(source, recipient, scope)?;
        let after = decode_cursor(scope, group_id, OfflineGroupStreamKind::Messages, cursor)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = group_store::load_group_from(&transaction, scope, group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let recipient_membership =
            require_two_active_members(&transaction, &group, source, recipient)?;
        let mut raw =
            load_raw_message_rows(&transaction, source, scope, group_id, after, max_items)?;
        let has_more = raw.len() > max_items;
        if has_more {
            raw.pop();
        }
        let scanned_sequence = raw
            .last()
            .map(|row| u64::try_from(row.sequence).map_err(|_| DurableStoreError::Corrupt))
            .transpose()?;
        let mut records = Vec::new();
        for row in raw {
            let message_id = ucr_model::MessageId::from_opaque(parse_id(&row.message_id)?);
            let message = message_store::load_message_from(&transaction, scope, &message_id)?
                .ok_or(DurableStoreError::Corrupt)?;
            if !group_store::history_allows(&group, &recipient_membership, &message) {
                continue;
            }
            let record = OfflineGroupMessageReplica {
                author: ScopedPrincipal {
                    scope: scope.clone(),
                    principal: PrincipalRef {
                        principal_id: PrincipalId::from_opaque(parse_id(&row.author_id)?),
                        kind: group_store::parse_principal_kind(&row.author_kind)?,
                    },
                },
                group_id: group_id.clone(),
                group_generation: decode_u64(&row.generation)?,
                message,
            };
            records.push(
                canonical_offline_group_message_replica(&record)
                    .map_err(|_| DurableStoreError::Corrupt)?,
            );
        }
        let next_cursor = if has_more {
            Some(offline_group_cursor(
                scope,
                group_id,
                OfflineGroupStreamKind::Messages,
                scanned_sequence.ok_or(DurableStoreError::Corrupt)?,
            ))
        } else {
            None
        };
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(OfflineGroupMessagePage {
            scope: scope.clone(),
            group_id: group_id.clone(),
            records,
            next_cursor,
        })
    }

    fn reconcile_offline_group_change(
        &self,
        recipient: &ScopedPrincipal,
        record: &OfflineGroupChangeReplica,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let record = canonical_offline_group_change_replica(record)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if recipient.scope != record.change.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = group_store::load_group_from(
            &transaction,
            &record.change.scope,
            &record.change.group_id,
        )?
        .ok_or(DurableStoreError::InvalidRecord)?;
        require_active_reader(&transaction, &group, recipient)?;
        let expected_generation = group
            .replication_generation
            .checked_add(1)
            .ok_or(DurableStoreError::Full)?;
        if record.group_generation > expected_generation {
            return Err(DurableStoreError::Conflict);
        }
        let status = group_store::apply_group_change_in_transaction(
            &transaction,
            &record.actor,
            &record.change,
            false,
        )?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(status)
    }

    fn reconcile_offline_group_message(
        &self,
        recipient: &ScopedPrincipal,
        record: &OfflineGroupMessageReplica,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let record = canonical_offline_group_message_replica(record)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if recipient.scope != record.message.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let group =
            group_store::load_group_from(&transaction, &record.message.scope, &record.group_id)?
                .ok_or(DurableStoreError::InvalidRecord)?;
        if record.message.conversation != group.conversation
            || record.message.delivery_policy != group.delivery_policy
            || record.group_generation > group.replication_generation
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let recipient_membership = require_active_reader(&transaction, &group, recipient)?;
        if !group_store::history_allows(&group, &recipient_membership, &record.message) {
            return Err(DurableStoreError::PermissionDenied);
        }
        let author_membership = group_store::load_membership_from(
            &transaction,
            &group.scope,
            &group.group_id,
            &record.author.principal,
        )?
        .filter(|membership| membership.member == record.author.principal)
        .ok_or(DurableStoreError::PermissionDenied)?;
        if !membership_active_at_generation(&author_membership, record.group_generation) {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some(existing) = message_store::load_message_from(
            &transaction,
            &record.message.scope,
            &record.message.message_id,
        )? {
            return if existing == record.message {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        message_store::insert_message_row(&transaction, &record.message)?;
        message_store::insert_message_children(&transaction, &record.message)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

fn require_active_reader(
    connection: &Connection,
    group: &GroupRecord,
    principal: &ScopedPrincipal,
) -> Result<GroupMembership, DurableStoreError> {
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

fn membership_active_at_generation(membership: &GroupMembership, generation: u64) -> bool {
    membership.joined_revision <= generation
        && membership
            .removed_revision
            .is_none_or(|removed| generation < removed)
}

#[derive(Debug)]
struct RawOfflineGroupMessageRow {
    sequence: i64,
    message_id: String,
    generation: Vec<u8>,
    author_id: String,
    author_kind: String,
}

fn load_raw_message_rows(
    transaction: &Transaction<'_>,
    source: &ScopedPrincipal,
    scope: &TenantScope,
    group_id: &GroupId,
    after: u64,
    max_items: usize,
) -> Result<Vec<RawOfflineGroupMessageRow>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = i64::try_from(max_items.saturating_add(1)).unwrap_or(i64::MAX);
    let mut statement = transaction
        .prepare(
            "SELECT replica_seq, message_id, group_generation, author_principal_id, author_principal_kind
             FROM offline_group_messages
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4
               AND author_principal_id=?5 AND author_principal_kind=?6 AND replica_seq>?7
             ORDER BY replica_seq LIMIT ?8",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group_id.as_opaque().as_str(),
                source.principal.principal_id.as_opaque().as_str(),
                group_store::principal_kind_name(source.principal.kind),
                i64::try_from(after).unwrap_or(i64::MAX),
                limit,
            ],
            |row| {
                Ok(RawOfflineGroupMessageRow {
                    sequence: row.get(0)?,
                    message_id: row.get(1)?,
                    generation: row.get(2)?,
                    author_id: row.get(3)?,
                    author_kind: row.get(4)?,
                })
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| row.map_err(|error| map_sqlite_error(&error)))
        .collect()
}

fn decode_cursor(
    scope: &TenantScope,
    group_id: &GroupId,
    stream: OfflineGroupStreamKind,
    cursor: Option<&OfflineGroupCursor>,
) -> Result<u64, DurableStoreError> {
    cursor.map_or(Ok(0), |cursor| {
        offline_group_cursor_sequence(scope, group_id, stream, cursor)
            .map_err(|_| DurableStoreError::InvalidRecord)
    })
}

fn require_scope(
    source: &ScopedPrincipal,
    recipient: &ScopedPrincipal,
    scope: &TenantScope,
) -> Result<(), DurableStoreError> {
    if source.scope != *scope || recipient.scope != *scope {
        Err(DurableStoreError::PermissionDenied)
    } else {
        Ok(())
    }
}

fn require_two_active_members(
    connection: &Connection,
    group: &GroupRecord,
    source: &ScopedPrincipal,
    recipient: &ScopedPrincipal,
) -> Result<GroupMembership, DurableStoreError> {
    let source_membership = group_store::load_membership_from(
        connection,
        &group.scope,
        &group.group_id,
        &source.principal,
    )?
    .ok_or(DurableStoreError::PermissionDenied)?;
    let recipient_membership = group_store::load_membership_from(
        connection,
        &group.scope,
        &group.group_id,
        &recipient.principal,
    )?
    .ok_or(DurableStoreError::PermissionDenied)?;
    if source_membership.state != GroupMemberState::Active
        || recipient_membership.state != GroupMemberState::Active
    {
        return Err(DurableStoreError::PermissionDenied);
    }
    Ok(recipient_membership)
}

#[derive(Debug)]
struct EncodedChange {
    kind: &'static str,
    target_id: Option<String>,
    target_kind: Option<&'static str>,
    role: Option<&'static str>,
    history_kind: Option<&'static str>,
    history_value: Option<i64>,
    history_custom: Option<String>,
    public_join: Option<&'static str>,
    public_discovery: Option<&'static str>,
    public_indexed: Option<i64>,
    delivery_policy: Option<&'static str>,
    crypto_capability: Option<String>,
    crypto_epoch: Option<[u8; 8]>,
    crypto_state_ref: Option<String>,
}

fn encode_change(change: &GroupChange) -> EncodedChange {
    let mut encoded = EncodedChange {
        kind: "",
        target_id: None,
        target_kind: None,
        role: None,
        history_kind: None,
        history_value: None,
        history_custom: None,
        public_join: None,
        public_discovery: None,
        public_indexed: None,
        delivery_policy: None,
        crypto_capability: change
            .next_crypto_state
            .as_ref()
            .and_then(|state| state.capability_id.clone()),
        crypto_epoch: change
            .next_crypto_state
            .as_ref()
            .map(|state| state.epoch.to_be_bytes()),
        crypto_state_ref: change.next_crypto_state.as_ref().and_then(|state| {
            state
                .state_ref
                .as_ref()
                .map(|value| value.as_str().to_owned())
        }),
    };
    match &change.kind {
        GroupChangeKind::AddMember { member, role } => {
            encoded.kind = "add_member";
            set_target(&mut encoded, member);
            encoded.role = Some(role_name(*role));
        }
        GroupChangeKind::RemoveMember { member } => {
            encoded.kind = "remove_member";
            set_target(&mut encoded, member);
        }
        GroupChangeKind::ChangeRole { member, role } => {
            encoded.kind = "change_role";
            set_target(&mut encoded, member);
            encoded.role = Some(role_name(*role));
        }
        GroupChangeKind::TransferOwnership { new_owner } => {
            encoded.kind = "transfer_ownership";
            set_target(&mut encoded, new_owner);
        }
        GroupChangeKind::SetHistoryPolicy { policy } => {
            encoded.kind = "set_history_policy";
            let (kind, value, custom) = encode_history(policy);
            encoded.history_kind = Some(kind);
            encoded.history_value = value;
            encoded.history_custom = custom;
        }
        GroupChangeKind::SetPublicPolicy { policy } => {
            encoded.kind = "set_public_policy";
            encoded.public_join = Some(join_policy_name(policy.join_policy));
            encoded.public_discovery = Some(discovery_name(policy.discovery));
            encoded.public_indexed = Some(i64::from(policy.indexed));
        }
        GroupChangeKind::SetDeliveryPolicy { policy } => {
            encoded.kind = "set_delivery_policy";
            encoded.delivery_policy = Some(delivery_policy_name(*policy));
        }
    }
    encoded
}

fn set_target(encoded: &mut EncodedChange, principal: &PrincipalRef) {
    encoded.target_id = Some(principal.principal_id.as_opaque().as_str().to_owned());
    encoded.target_kind = Some(group_store::principal_kind_name(principal.kind));
}

#[derive(Debug)]
struct ChangeRow {
    sequence: u64,
    event_id: String,
    generation: Vec<u8>,
    actor_id: String,
    actor_kind: String,
    expected_revision: Vec<u8>,
    kind: String,
    target_id: Option<String>,
    target_kind: Option<String>,
    role: Option<String>,
    history_kind: Option<String>,
    history_value: Option<i64>,
    history_custom: Option<String>,
    public_join: Option<String>,
    public_discovery: Option<String>,
    public_indexed: Option<i64>,
    delivery_policy: Option<String>,
    crypto_capability: Option<String>,
    crypto_epoch: Option<Vec<u8>>,
    crypto_state_ref: Option<String>,
}

fn read_change_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeRow> {
    let sequence = row.get::<_, i64>(0)?;
    Ok(ChangeRow {
        sequence: u64::try_from(sequence).unwrap_or(0),
        event_id: row.get(1)?,
        generation: row.get(2)?,
        actor_id: row.get(3)?,
        actor_kind: row.get(4)?,
        expected_revision: row.get(5)?,
        kind: row.get(6)?,
        target_id: row.get(7)?,
        target_kind: row.get(8)?,
        role: row.get(9)?,
        history_kind: row.get(10)?,
        history_value: row.get(11)?,
        history_custom: row.get(12)?,
        public_join: row.get(13)?,
        public_discovery: row.get(14)?,
        public_indexed: row.get(15)?,
        delivery_policy: row.get(16)?,
        crypto_capability: row.get(17)?,
        crypto_epoch: row.get(18)?,
        crypto_state_ref: row.get(19)?,
    })
}

fn decode_change_row(
    scope: &TenantScope,
    group_id: &GroupId,
    row: ChangeRow,
) -> Result<OfflineGroupChangeReplica, DurableStoreError> {
    if row.sequence == 0 {
        return Err(DurableStoreError::Corrupt);
    }
    let target = match (&row.target_id, &row.target_kind) {
        (Some(id), Some(kind)) => Some(PrincipalRef {
            principal_id: PrincipalId::from_opaque(parse_id(id)?),
            kind: group_store::parse_principal_kind(kind)?,
        }),
        (None, None) => None,
        _ => return Err(DurableStoreError::Corrupt),
    };
    let kind = match row.kind.as_str() {
        "add_member" => GroupChangeKind::AddMember {
            member: target.ok_or(DurableStoreError::Corrupt)?,
            role: parse_role(row.role.as_deref().ok_or(DurableStoreError::Corrupt)?)?,
        },
        "remove_member" => GroupChangeKind::RemoveMember {
            member: target.ok_or(DurableStoreError::Corrupt)?,
        },
        "change_role" => GroupChangeKind::ChangeRole {
            member: target.ok_or(DurableStoreError::Corrupt)?,
            role: parse_role(row.role.as_deref().ok_or(DurableStoreError::Corrupt)?)?,
        },
        "transfer_ownership" => GroupChangeKind::TransferOwnership {
            new_owner: target.ok_or(DurableStoreError::Corrupt)?,
        },
        "set_history_policy" => GroupChangeKind::SetHistoryPolicy {
            policy: decode_history(
                row.history_kind
                    .as_deref()
                    .ok_or(DurableStoreError::Corrupt)?,
                row.history_value,
                row.history_custom,
            )?,
        },
        "set_public_policy" => GroupChangeKind::SetPublicPolicy {
            policy: PublicGroupPolicy {
                join_policy: parse_join_policy(
                    row.public_join
                        .as_deref()
                        .ok_or(DurableStoreError::Corrupt)?,
                )?,
                discovery: parse_discovery(
                    row.public_discovery
                        .as_deref()
                        .ok_or(DurableStoreError::Corrupt)?,
                )?,
                indexed: match row.public_indexed {
                    Some(0) => false,
                    Some(1) => true,
                    _ => return Err(DurableStoreError::Corrupt),
                },
            },
        },
        "set_delivery_policy" => GroupChangeKind::SetDeliveryPolicy {
            policy: parse_delivery_policy(
                row.delivery_policy
                    .as_deref()
                    .ok_or(DurableStoreError::Corrupt)?,
            )?,
        },
        _ => return Err(DurableStoreError::Corrupt),
    };
    let next_crypto_state = match (
        row.crypto_capability,
        row.crypto_epoch,
        row.crypto_state_ref,
    ) {
        (None, None, None) => None,
        (Some(capability_id), Some(epoch), Some(state_ref)) => Some(GroupCryptoState {
            capability_id: Some(capability_id),
            epoch: decode_u64(&epoch)?,
            state_ref: Some(parse_id(&state_ref)?),
        }),
        _ => return Err(DurableStoreError::Corrupt),
    };
    let record = OfflineGroupChangeReplica {
        actor: ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(parse_id(&row.actor_id)?),
                kind: group_store::parse_principal_kind(&row.actor_kind)?,
            },
        },
        group_generation: decode_u64(&row.generation)?,
        change: GroupChange {
            event_id: ucr_model::EventId::from_opaque(parse_id(&row.event_id)?),
            scope: scope.clone(),
            group_id: group_id.clone(),
            expected_revision: decode_u64(&row.expected_revision)?,
            kind,
            next_crypto_state,
        },
    };
    canonical_offline_group_change_replica(&record).map_err(|_| DurableStoreError::Corrupt)
}

fn verify_change_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT replica_seq, tenant_id, namespace_present, namespace_id, group_id,
                    event_id, group_generation, actor_principal_id, actor_principal_kind,
                    expected_revision, change_kind, target_principal_id, target_principal_kind,
                    role, history_kind, history_value, history_custom, public_join_policy,
                    public_discovery, public_indexed, delivery_policy, crypto_capability_id,
                    crypto_epoch, crypto_state_ref FROM offline_group_changes ORDER BY replica_seq",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                ChangeRow {
                    sequence: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                    event_id: row.get(5)?,
                    generation: row.get(6)?,
                    actor_id: row.get(7)?,
                    actor_kind: row.get(8)?,
                    expected_revision: row.get(9)?,
                    kind: row.get(10)?,
                    target_id: row.get(11)?,
                    target_kind: row.get(12)?,
                    role: row.get(13)?,
                    history_kind: row.get(14)?,
                    history_value: row.get(15)?,
                    history_custom: row.get(16)?,
                    public_join: row.get(17)?,
                    public_discovery: row.get(18)?,
                    public_indexed: row.get(19)?,
                    delivery_policy: row.get(20)?,
                    crypto_capability: row.get(21)?,
                    crypto_epoch: row.get(22)?,
                    crypto_state_ref: row.get(23)?,
                },
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (_, tenant, present, namespace, group, change) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let scope = parse_scope(&tenant, present, &namespace)?;
        let group_id = GroupId::from_opaque(parse_id(&group)?);
        decode_change_row(&scope, &group_id, change)?;
    }
    Ok(())
}

fn verify_message_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, group_id, message_id,
                    group_generation, author_principal_id, author_principal_kind
             FROM offline_group_messages ORDER BY replica_seq",
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
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    for row in rows {
        let (tenant, present, namespace, group, message_id, generation, author_id, author_kind) =
            row.map_err(|error| map_sqlite_error(&error))?;
        let scope = parse_scope(&tenant, present, &namespace)?;
        let group_id = GroupId::from_opaque(parse_id(&group)?);
        let message_id = ucr_model::MessageId::from_opaque(parse_id(&message_id)?);
        let message = message_store::load_message_from(connection, &scope, &message_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        let record = OfflineGroupMessageReplica {
            author: ScopedPrincipal {
                scope: scope.clone(),
                principal: PrincipalRef {
                    principal_id: PrincipalId::from_opaque(parse_id(&author_id)?),
                    kind: group_store::parse_principal_kind(&author_kind)?,
                },
            },
            group_id,
            group_generation: decode_u64(&generation)?,
            message,
        };
        canonical_offline_group_message_replica(&record).map_err(|_| DurableStoreError::Corrupt)?;
    }
    Ok(())
}

fn parse_scope(
    tenant: &str,
    namespace_present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match namespace_present {
        0 if namespace.is_empty() => None,
        1 if !namespace.is_empty() => {
            Some(ucr_model::NamespaceId::from_opaque(parse_id(namespace)?))
        }
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value.to_owned()).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

const fn role_name(role: GroupRole) -> &'static str {
    match role {
        GroupRole::Owner => "owner",
        GroupRole::Admin => "admin",
        GroupRole::Member => "member",
    }
}

fn parse_role(value: &str) -> Result<GroupRole, DurableStoreError> {
    match value {
        "owner" => Ok(GroupRole::Owner),
        "admin" => Ok(GroupRole::Admin),
        "member" => Ok(GroupRole::Member),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn encode_history(policy: &GroupHistoryPolicy) -> (&'static str, Option<i64>, Option<String>) {
    match policy {
        GroupHistoryPolicy::NoHistory => ("none", None, None),
        GroupHistoryPolicy::FromJoin => ("from_join", None, None),
        GroupHistoryPolicy::LastNMessages(value) => ("last_n", Some(i64::from(*value)), None),
        GroupHistoryPolicy::FromTimestamp(value) => ("from_timestamp", Some(*value), None),
        GroupHistoryPolicy::FullHistory => ("full", None, None),
        GroupHistoryPolicy::CustomPolicy(value) => ("custom", None, Some(value.clone())),
    }
}

fn decode_history(
    kind: &str,
    value: Option<i64>,
    custom: Option<String>,
) -> Result<GroupHistoryPolicy, DurableStoreError> {
    match (kind, value, custom) {
        ("none", None, None) => Ok(GroupHistoryPolicy::NoHistory),
        ("from_join", None, None) => Ok(GroupHistoryPolicy::FromJoin),
        ("last_n", Some(value), None) => Ok(GroupHistoryPolicy::LastNMessages(
            u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)?,
        )),
        ("from_timestamp", Some(value), None) => Ok(GroupHistoryPolicy::FromTimestamp(value)),
        ("full", None, None) => Ok(GroupHistoryPolicy::FullHistory),
        ("custom", None, Some(value)) => Ok(GroupHistoryPolicy::CustomPolicy(value)),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn join_policy_name(policy: PublicGroupJoinPolicy) -> &'static str {
    match policy {
        PublicGroupJoinPolicy::Open => "open",
        PublicGroupJoinPolicy::ApprovalRequired => "approval_required",
        PublicGroupJoinPolicy::InviteOnly => "invite_only",
    }
}

fn parse_join_policy(value: &str) -> Result<PublicGroupJoinPolicy, DurableStoreError> {
    match value {
        "open" => Ok(PublicGroupJoinPolicy::Open),
        "approval_required" => Ok(PublicGroupJoinPolicy::ApprovalRequired),
        "invite_only" => Ok(PublicGroupJoinPolicy::InviteOnly),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn discovery_name(value: PublicGroupDiscovery) -> &'static str {
    match value {
        PublicGroupDiscovery::Unlisted => "unlisted",
        PublicGroupDiscovery::Discoverable => "discoverable",
    }
}

fn parse_discovery(value: &str) -> Result<PublicGroupDiscovery, DurableStoreError> {
    match value {
        "unlisted" => Ok(PublicGroupDiscovery::Unlisted),
        "discoverable" => Ok(PublicGroupDiscovery::Discoverable),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn delivery_policy_name(value: DeliveryPolicy) -> &'static str {
    match value {
        DeliveryPolicy::BestEffort => "best_effort",
        DeliveryPolicy::Durable => "durable",
        DeliveryPolicy::Urgent => "urgent",
        DeliveryPolicy::Expiring => "expiring",
        DeliveryPolicy::LocalOnly => "local_only",
        DeliveryPolicy::DirectOnly => "direct_only",
        DeliveryPolicy::NoRelay => "no_relay",
        DeliveryPolicy::NoExternalBridge => "no_external_bridge",
        DeliveryPolicy::PrivateNetworkOnly => "private_network_only",
    }
}

fn parse_delivery_policy(value: &str) -> Result<DeliveryPolicy, DurableStoreError> {
    match value {
        "best_effort" => Ok(DeliveryPolicy::BestEffort),
        "durable" => Ok(DeliveryPolicy::Durable),
        "urgent" => Ok(DeliveryPolicy::Urgent),
        "expiring" => Ok(DeliveryPolicy::Expiring),
        "local_only" => Ok(DeliveryPolicy::LocalOnly),
        "direct_only" => Ok(DeliveryPolicy::DirectOnly),
        "no_relay" => Ok(DeliveryPolicy::NoRelay),
        "no_external_bridge" => Ok(DeliveryPolicy::NoExternalBridge),
        "private_network_only" => Ok(DeliveryPolicy::PrivateNetworkOnly),
        _ => Err(DurableStoreError::Corrupt),
    }
}
