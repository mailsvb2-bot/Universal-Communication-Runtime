use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore};
use ucr_model::{
    ConversationId, ConversationKind, ConversationRecord, ConversationRef, DeliveryPolicy,
    DeliveryState, GroupBridgeMapping, GroupChange, GroupHistoryPolicy, GroupId, GroupMediaState,
    GroupMemberState, GroupMembership, GroupOwnership, GroupPermission, GroupRecord, GroupRole,
    IntegrationId, MessageEnvelope, MessageId, NamespaceId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, PublicGroupDiscovery, PublicGroupJoinPolicy, PublicGroupPolicy, ScopedPrincipal,
    TenantId, TenantScope,
};
use ucr_protocol::{
    MAX_EXTERNAL_GROUP_ID_LEN, active_group_actor_role, apply_group_change,
    canonical_group_creation, canonical_group_memberships, canonical_group_record,
    canonical_message, group_change_fingerprint, group_permissions_for_role,
    is_group_conversation_kind, validate_conversation, validate_group_member_list_limit,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, message_store,
    namespace_storage_key, verify_table_columns,
};

pub(super) const V21_OBJECTS_SQL: &str = r"
CREATE TABLE groups (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    conversation_kind TEXT NOT NULL CHECK(conversation_kind IN ('private_group','public_group')),
    ownership_kind TEXT NOT NULL CHECK(ownership_kind IN ('person','organization','shared_admin','ownerless_federated','temporary')),
    owner_principal_id TEXT,
    owner_principal_kind TEXT,
    ownership_expires_at_unix_ms INTEGER,
    history_kind TEXT NOT NULL CHECK(history_kind IN ('none','from_join','last_n','from_timestamp','full','custom')),
    history_value INTEGER,
    history_custom TEXT,
    delivery_policy TEXT NOT NULL,
    crypto_capability_id TEXT,
    crypto_epoch BLOB NOT NULL CHECK(length(crypto_epoch)=8),
    crypto_state_ref TEXT,
    public_join_policy TEXT,
    public_discovery TEXT,
    public_indexed INTEGER CHECK(public_indexed IS NULL OR public_indexed IN (0,1)),
    media_state TEXT NOT NULL CHECK(media_state='idle'),
    replication_generation BLOB NOT NULL CHECK(length(replication_generation)=8),
    revision BLOB NOT NULL CHECK(length(revision)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id),
    UNIQUE(tenant_id, namespace_present, namespace_id, conversation_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, conversation_id)
      REFERENCES conversations(tenant_id, namespace_present, namespace_id, conversation_id),
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE group_memberships (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
    state TEXT NOT NULL CHECK(state IN ('active','removed')),
    joined_revision BLOB NOT NULL CHECK(length(joined_revision)=8),
    removed_revision BLOB CHECK(removed_revision IS NULL OR length(removed_revision)=8),
    history_floor_logical_order BLOB NOT NULL CHECK(length(history_floor_logical_order)=8),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, principal_id, principal_kind),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    CHECK((state='active' AND removed_revision IS NULL) OR
          (state='removed' AND removed_revision IS NOT NULL)),
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE group_bridge_mappings (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    external_group_id BLOB NOT NULL CHECK(length(external_group_id) BETWEEN 1 AND 4096),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, integration_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TABLE group_changes (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    actor_principal_kind TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;
";

pub(super) fn create_v21_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V21_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v21(connection: &Connection) -> Result<(), DurableStoreError> {
    super::event_subscription_store::verify_schema_v20(connection)?;
    verify_group_table_shapes(connection)?;
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
    verify_group_rows(connection)
}

fn verify_group_table_shapes(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "groups",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("group_id", "TEXT", 1, 4),
            ("conversation_id", "TEXT", 1, 0),
            ("conversation_kind", "TEXT", 1, 0),
            ("ownership_kind", "TEXT", 1, 0),
            ("owner_principal_id", "TEXT", 0, 0),
            ("owner_principal_kind", "TEXT", 0, 0),
            ("ownership_expires_at_unix_ms", "INTEGER", 0, 0),
            ("history_kind", "TEXT", 1, 0),
            ("history_value", "INTEGER", 0, 0),
            ("history_custom", "TEXT", 0, 0),
            ("delivery_policy", "TEXT", 1, 0),
            ("crypto_capability_id", "TEXT", 0, 0),
            ("crypto_epoch", "BLOB", 1, 0),
            ("crypto_state_ref", "TEXT", 0, 0),
            ("public_join_policy", "TEXT", 0, 0),
            ("public_discovery", "TEXT", 0, 0),
            ("public_indexed", "INTEGER", 0, 0),
            ("media_state", "TEXT", 1, 0),
            ("replication_generation", "BLOB", 1, 0),
            ("revision", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "group_memberships",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("group_id", "TEXT", 1, 4),
            ("principal_id", "TEXT", 1, 5),
            ("principal_kind", "TEXT", 1, 6),
            ("role", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
            ("joined_revision", "BLOB", 1, 0),
            ("removed_revision", "BLOB", 0, 0),
            ("history_floor_logical_order", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "group_bridge_mappings",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("group_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 5),
            ("external_group_id", "BLOB", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "group_changes",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("group_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 4),
            ("actor_principal_id", "TEXT", 1, 0),
            ("actor_principal_kind", "TEXT", 1, 0),
            ("fingerprint", "BLOB", 1, 0),
        ],
    )
}

fn verify_group_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, group_id FROM groups")
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut keys = Vec::new();
    for row in rows {
        keys.push(row.map_err(|error| map_sqlite_error(&error))?);
    }
    drop(statement);
    for (tenant, present, namespace, group_id) in keys {
        let scope = parse_scope(&tenant, present, &namespace)?;
        let group_id = GroupId::from_opaque(parse_id(&group_id)?);
        let group =
            load_group_from(connection, &scope, &group_id)?.ok_or(DurableStoreError::Corrupt)?;
        let memberships = load_memberships_from(connection, &group, usize::MAX)?;
        canonical_group_memberships(&group, &memberships).map_err(map_group_error)?;
    }
    Ok(())
}

impl GroupStore for SqliteLocalStore {
    fn create_group(
        &self,
        conversation: &ConversationRecord,
        group: &GroupRecord,
        creator: &ScopedPrincipal,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_conversation(conversation).map_err(|_| DurableStoreError::InvalidRecord)?;
        if conversation.parent_conversation_id.is_some()
            || !is_group_conversation_kind(conversation.conversation.kind)
            || conversation.scope != group.scope
            || conversation.conversation != group.conversation
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let (group, mut creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(existing) = load_group_from(&transaction, &group.scope, &group.group_id)? {
            let existing_creator = load_membership_from(
                &transaction,
                &group.scope,
                &group.group_id,
                &creator.principal,
            )?;
            let duplicate = existing_creator.is_some_and(|persisted| {
                let mut expected = creator_membership.clone();
                expected.history_floor_logical_order = persisted.history_floor_logical_order;
                existing == group && persisted == expected
            });
            return if duplicate {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if load_group_for_conversation_from(
            &transaction,
            &group.scope,
            &group.conversation.conversation_id,
        )?
        .is_some()
        {
            return Err(DurableStoreError::Conflict);
        }
        match message_store::load_conversation_from(
            &transaction,
            &conversation.scope,
            &conversation.conversation.conversation_id,
        )? {
            Some(existing) if existing != *conversation => return Err(DurableStoreError::Conflict),
            Some(_) => {}
            None => insert_group_conversation(&transaction, conversation)?,
        }
        creator_membership.history_floor_logical_order =
            history_floor_for_add(&transaction, &group)?;
        insert_group(&transaction, &group)?;
        insert_membership(&transaction, &creator_membership)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn group(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
    ) -> Result<Option<GroupRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_group_from(&connection, scope, group_id)
    }

    fn group_for_conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<GroupRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_group_for_conversation_from(&connection, scope, conversation_id)
    }

    fn group_membership(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        member: &PrincipalRef,
    ) -> Result<Option<GroupMembership>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_membership_from(&connection, scope, group_id, member)
    }

    fn group_memberships(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<GroupMembership>, DurableStoreError> {
        validate_group_member_list_limit(max_items).map_err(map_group_error)?;
        let connection = self.lock_connection()?;
        let group = load_group_from(&connection, scope, group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        load_memberships_from(&connection, &group, max_items)
    }

    fn apply_group_change(
        &self,
        actor: &ScopedPrincipal,
        change: &GroupChange,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != change.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = load_group_from(&transaction, &change.scope, &change.group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let memberships = load_memberships_from(&transaction, &group, usize::MAX)?;
        active_group_actor_role(&group, &memberships, &actor.scope, &actor.principal)
            .map_err(map_group_error)?;
        if let Some((recorded_actor, existing)) = load_change_record(
            &transaction,
            &change.scope,
            change.event_id.as_opaque().as_str(),
        )? {
            if recorded_actor != actor.principal {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let history_floor = if matches!(change.kind, ucr_model::GroupChangeKind::AddMember { .. }) {
            Some(history_floor_for_add(&transaction, &group)?)
        } else {
            None
        };
        let transition = apply_group_change(
            &group,
            &memberships,
            &actor.scope,
            &actor.principal,
            change,
            history_floor,
        )
        .map_err(map_group_error)?;
        if super::event_journal::load_event_by_id(&transaction, &change.scope, &change.event_id)?
            .is_some()
        {
            return Err(DurableStoreError::Conflict);
        }
        update_group(&transaction, &transition.group)?;
        replace_memberships(&transaction, &transition.group, &transition.memberships)?;
        insert_change_fingerprint(&transaction, actor, change, &fingerprint)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }
}

impl GroupMessageStore for SqliteLocalStore {
    fn persist_group_message(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut persisted =
            canonical_message(message).map_err(|_| DurableStoreError::InvalidRecord)?;
        if !is_group_conversation_kind(persisted.conversation.kind)
            || !matches!(
                persisted.delivery_state,
                DeliveryState::Created | DeliveryState::Persisted
            )
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        if persisted.scope != subject.scope
            || persisted.origin.principal_id.as_ref() != Some(&subject.principal.principal_id)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        persisted.delivery_state = DeliveryState::Persisted;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let group = load_group_for_conversation_from(
            &transaction,
            &persisted.scope,
            &persisted.conversation.conversation_id,
        )?
        .ok_or(DurableStoreError::PermissionDenied)?;
        if group.conversation != persisted.conversation
            || group.delivery_policy != persisted.delivery_policy
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let membership = load_membership_from(
            &transaction,
            &group.scope,
            &group.group_id,
            &subject.principal,
        )?
        .ok_or(DurableStoreError::PermissionDenied)?;
        if membership.state != GroupMemberState::Active
            || !membership
                .permissions
                .contains(&GroupPermission::SendMessage)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some(existing) =
            message_store::load_message_from(&transaction, &persisted.scope, &persisted.message_id)?
        {
            return if existing == persisted {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        message_store::insert_message_row(&transaction, &persisted)?;
        message_store::insert_message_children(&transaction, &persisted)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn group_message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError> {
        if subject.scope != *scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error))?;
        let Some(message) = message_store::load_message_from(&transaction, scope, message_id)?
        else {
            return Ok(None);
        };
        if !is_group_conversation_kind(message.conversation.kind) {
            return Ok(None);
        }
        let Some(group) = load_group_for_conversation_from(
            &transaction,
            scope,
            &message.conversation.conversation_id,
        )?
        else {
            return Ok(None);
        };
        let Some(membership) =
            load_membership_from(&transaction, scope, &group.group_id, &subject.principal)?
        else {
            return Ok(None);
        };
        if membership.state != GroupMemberState::Active
            || !membership
                .permissions
                .contains(&GroupPermission::ReadHistory)
            || !history_allows(&group, &membership, &message)
        {
            return Ok(None);
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(Some(message))
    }
}

fn insert_group_conversation(
    transaction: &Transaction<'_>,
    conversation: &ConversationRecord,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&conversation.scope);
    transaction.execute(
        "INSERT INTO conversations (tenant_id, namespace_present, namespace_id, conversation_id, kind, parent_conversation_id) VALUES (?1,?2,?3,?4,?5,NULL)",
        params![
            conversation.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value,
            conversation.conversation.conversation_id.as_opaque().as_str(),
            conversation_kind_name(conversation.conversation.kind),
        ],
    ).map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn insert_group(
    transaction: &Transaction<'_>,
    group: &GroupRecord,
) -> Result<(), DurableStoreError> {
    let group = canonical_group_record(group).map_err(map_group_error)?;
    let namespace = namespace_storage_key(&group.scope);
    let ownership = encode_ownership(&group.ownership);
    let history = encode_history(&group.history_policy);
    let public = encode_public_policy(group.public_policy.as_ref());
    transaction.execute(
        "INSERT INTO groups VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
        params![
            group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value,
            group.group_id.as_opaque().as_str(), group.conversation.conversation_id.as_opaque().as_str(),
            conversation_kind_name(group.conversation.kind), ownership.0, ownership.1, ownership.2, ownership.3,
            history.0, history.1, history.2, delivery_policy_name(group.delivery_policy),
            group.crypto_state.capability_id.as_deref(), group.crypto_state.epoch.to_be_bytes().as_slice(),
            group.crypto_state.state_ref.as_ref().map(OpaqueId::as_str), public.0, public.1, public.2,
            "idle", group.replication_generation.to_be_bytes().as_slice(), group.revision.to_be_bytes().as_slice(),
        ],
    ).map_err(|error| map_sqlite_error(&error))?;
    insert_bridges(transaction, &group)?;
    Ok(())
}

fn update_group(
    transaction: &Transaction<'_>,
    group: &GroupRecord,
) -> Result<(), DurableStoreError> {
    let group = canonical_group_record(group).map_err(map_group_error)?;
    let namespace = namespace_storage_key(&group.scope);
    let ownership = encode_ownership(&group.ownership);
    let history = encode_history(&group.history_policy);
    let public = encode_public_policy(group.public_policy.as_ref());
    let changed = transaction.execute(
        "UPDATE groups SET conversation_id=?5, conversation_kind=?6, ownership_kind=?7, owner_principal_id=?8, owner_principal_kind=?9, ownership_expires_at_unix_ms=?10, history_kind=?11, history_value=?12, history_custom=?13, delivery_policy=?14, crypto_capability_id=?15, crypto_epoch=?16, crypto_state_ref=?17, public_join_policy=?18, public_discovery=?19, public_indexed=?20, media_state='idle', replication_generation=?21, revision=?22 WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4",
        params![
            group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value,
            group.group_id.as_opaque().as_str(), group.conversation.conversation_id.as_opaque().as_str(),
            conversation_kind_name(group.conversation.kind), ownership.0, ownership.1, ownership.2, ownership.3,
            history.0, history.1, history.2, delivery_policy_name(group.delivery_policy),
            group.crypto_state.capability_id.as_deref(), group.crypto_state.epoch.to_be_bytes().as_slice(),
            group.crypto_state.state_ref.as_ref().map(OpaqueId::as_str), public.0, public.1, public.2,
            group.replication_generation.to_be_bytes().as_slice(), group.revision.to_be_bytes().as_slice(),
        ],
    ).map_err(|error| map_sqlite_error(&error))?;
    if changed != 1 {
        return Err(DurableStoreError::Corrupt);
    }
    transaction.execute(
        "DELETE FROM group_bridge_mappings WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4",
        params![group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group.group_id.as_opaque().as_str()],
    ).map_err(|error| map_sqlite_error(&error))?;
    insert_bridges(transaction, &group)
}

fn insert_bridges(
    transaction: &Transaction<'_>,
    group: &GroupRecord,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&group.scope);
    for mapping in &group.bridge_mappings {
        transaction
            .execute(
                "INSERT INTO group_bridge_mappings VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    group.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    group.group_id.as_opaque().as_str(),
                    mapping.integration_id.as_opaque().as_str(),
                    mapping.external_group_id
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

fn insert_membership(
    transaction: &Transaction<'_>,
    membership: &GroupMembership,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&membership.scope);
    transaction
        .execute(
            "INSERT INTO group_memberships VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                membership.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                membership.group_id.as_opaque().as_str(),
                membership.member.principal_id.as_opaque().as_str(),
                principal_kind_name(membership.member.kind),
                role_name(membership.role),
                member_state_name(membership.state),
                membership.joined_revision.to_be_bytes().as_slice(),
                membership
                    .removed_revision
                    .map(u64::to_be_bytes)
                    .as_ref()
                    .map(<[u8; 8]>::as_slice),
                membership
                    .history_floor_logical_order
                    .to_be_bytes()
                    .as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn replace_memberships(
    transaction: &Transaction<'_>,
    group: &GroupRecord,
    memberships: &[GroupMembership],
) -> Result<(), DurableStoreError> {
    let canonical = canonical_group_memberships(group, memberships).map_err(map_group_error)?;
    let namespace = namespace_storage_key(&group.scope);
    transaction.execute(
        "DELETE FROM group_memberships WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4",
        params![group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group.group_id.as_opaque().as_str()],
    ).map_err(|error| map_sqlite_error(&error))?;
    for membership in &canonical {
        insert_membership(transaction, membership)?;
    }
    Ok(())
}

fn load_group_from(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
) -> Result<Option<GroupRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection.query_row(
        "SELECT conversation_id, conversation_kind, ownership_kind, owner_principal_id, owner_principal_kind, ownership_expires_at_unix_ms, history_kind, history_value, history_custom, delivery_policy, crypto_capability_id, crypto_epoch, crypto_state_ref, public_join_policy, public_discovery, public_indexed, media_state, replication_generation, revision FROM groups WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group_id.as_opaque().as_str()],
        |row| Ok((
            row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,String>(2)?,
            row.get::<_,Option<String>>(3)?, row.get::<_,Option<String>>(4)?, row.get::<_,Option<i64>>(5)?,
            row.get::<_,String>(6)?, row.get::<_,Option<i64>>(7)?, row.get::<_,Option<String>>(8)?,
            row.get::<_,String>(9)?, row.get::<_,Option<String>>(10)?, row.get::<_,Vec<u8>>(11)?,
            row.get::<_,Option<String>>(12)?, row.get::<_,Option<String>>(13)?, row.get::<_,Option<String>>(14)?,
            row.get::<_,Option<i64>>(15)?, row.get::<_,String>(16)?, row.get::<_,Vec<u8>>(17)?, row.get::<_,Vec<u8>>(18)?
        )),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.16 != "idle" {
        return Err(DurableStoreError::Corrupt);
    }
    let conversation = ConversationRef {
        conversation_id: ConversationId::from_opaque(parse_id(&row.0)?),
        kind: parse_conversation_kind(&row.1)?,
    };
    let bridges = load_bridges(connection, scope, group_id)?;
    let group = GroupRecord {
        scope: scope.clone(),
        group_id: group_id.clone(),
        conversation,
        ownership: decode_ownership(&row.2, row.3, row.4, row.5)?,
        history_policy: decode_history(&row.6, row.7, row.8)?,
        delivery_policy: parse_delivery_policy(&row.9)?,
        crypto_state: ucr_model::GroupCryptoState {
            capability_id: row.10,
            epoch: decode_u64(&row.11)?,
            state_ref: row.12.map(|value| parse_id(&value)).transpose()?,
        },
        public_policy: decode_public_policy(row.13, row.14, row.15)?,
        media_state: GroupMediaState::Idle,
        bridge_mappings: bridges,
        replication_generation: decode_u64(&row.17)?,
        revision: decode_u64(&row.18)?,
    };
    canonical_group_record(&group)
        .map(Some)
        .map_err(map_group_error)
}

fn load_group_for_conversation_from(
    connection: &Connection,
    scope: &TenantScope,
    conversation_id: &ConversationId,
) -> Result<Option<GroupRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let group_id = connection.query_row(
        "SELECT group_id FROM groups WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, conversation_id.as_opaque().as_str()],
        |row| row.get::<_,String>(0),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    group_id
        .map(|value| load_group_from(connection, scope, &GroupId::from_opaque(parse_id(&value)?)))
        .transpose()
        .map(Option::flatten)
}

fn load_bridges(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
) -> Result<Vec<GroupBridgeMapping>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection.prepare(
        "SELECT integration_id, external_group_id FROM group_bridge_mappings WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 ORDER BY integration_id"
    ).map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group_id.as_opaque().as_str()
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        let (integration, external) = row.map_err(|error| map_sqlite_error(&error))?;
        if external.is_empty() || external.len() > MAX_EXTERNAL_GROUP_ID_LEN {
            return Err(DurableStoreError::Corrupt);
        }
        result.push(GroupBridgeMapping {
            integration_id: IntegrationId::from_opaque(parse_id(&integration)?),
            external_group_id: external,
        });
    }
    Ok(result)
}

fn load_membership_from(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
    member: &PrincipalRef,
) -> Result<Option<GroupMembership>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection.query_row(
        "SELECT principal_kind, role, state, joined_revision, removed_revision, history_floor_logical_order FROM group_memberships WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 AND principal_id=?5 AND principal_kind=?6",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group_id.as_opaque().as_str(), member.principal_id.as_opaque().as_str(), principal_kind_name(member.kind)],
        |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,String>(2)?, row.get::<_,Vec<u8>>(3)?, row.get::<_,Option<Vec<u8>>>(4)?, row.get::<_,Vec<u8>>(5)?)),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_kind = parse_principal_kind(&row.0)?;
    if stored_kind != member.kind {
        return Ok(None);
    }
    let group = load_group_from(connection, scope, group_id)?.ok_or(DurableStoreError::Corrupt)?;
    let fields = StoredMembershipFields {
        role: &row.1,
        state: &row.2,
        joined: &row.3,
        removed: row.4.as_deref(),
        floor: &row.5,
    };
    decode_membership(&group, member.principal_id.clone(), stored_kind, &fields).map(Some)
}

fn load_memberships_from(
    connection: &Connection,
    group: &GroupRecord,
    max_items: usize,
) -> Result<Vec<GroupMembership>, DurableStoreError> {
    let namespace = namespace_storage_key(&group.scope);
    let limit = max_items.saturating_add(1);
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = connection.prepare(
        "SELECT principal_id, principal_kind, role, state, joined_revision, removed_revision, history_floor_logical_order FROM group_memberships WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 ORDER BY principal_id, principal_kind LIMIT ?5"
    ).map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                group.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group.group_id.as_opaque().as_str(),
                sql_limit
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut result = Vec::new();
    for row in rows {
        let row = row.map_err(|error| map_sqlite_error(&error))?;
        let kind = parse_principal_kind(&row.1)?;
        let fields = StoredMembershipFields {
            role: &row.2,
            state: &row.3,
            joined: &row.4,
            removed: row.5.as_deref(),
            floor: &row.6,
        };
        result.push(decode_membership(
            group,
            PrincipalId::from_opaque(parse_id(&row.0)?),
            kind,
            &fields,
        )?);
    }
    if result.len() > max_items {
        return Err(DurableStoreError::Full);
    }
    canonical_group_memberships(group, &result).map_err(map_group_error)
}

struct StoredMembershipFields<'a> {
    role: &'a str,
    state: &'a str,
    joined: &'a [u8],
    removed: Option<&'a [u8]>,
    floor: &'a [u8],
}

fn decode_membership(
    group: &GroupRecord,
    principal_id: PrincipalId,
    kind: PrincipalKind,
    fields: &StoredMembershipFields<'_>,
) -> Result<GroupMembership, DurableStoreError> {
    let role = parse_role(fields.role)?;
    let membership = GroupMembership {
        scope: group.scope.clone(),
        group_id: group.group_id.clone(),
        member: PrincipalRef { principal_id, kind },
        role,
        permissions: group_permissions_for_role(role),
        state: parse_member_state(fields.state)?,
        joined_revision: decode_u64(fields.joined)?,
        removed_revision: fields.removed.map(decode_u64).transpose()?,
        history_floor_logical_order: decode_u64(fields.floor)?,
    };
    ucr_protocol::canonical_group_membership(group, &membership).map_err(map_group_error)
}

fn load_change_record(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<Option<(PrincipalRef, [u8; 32])>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value = connection.query_row(
        "SELECT actor_principal_id, actor_principal_kind, fingerprint FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
        |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,Vec<u8>>(2)?)),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    value
        .map(|(principal_id, kind, bytes)| {
            Ok((
                PrincipalRef {
                    principal_id: PrincipalId::from_opaque(parse_id(&principal_id)?),
                    kind: parse_principal_kind(&kind)?,
                },
                bytes.try_into().map_err(|_| DurableStoreError::Corrupt)?,
            ))
        })
        .transpose()
}

fn insert_change_fingerprint(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    change: &GroupChange,
    fingerprint: &[u8; 32],
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&change.scope);
    transaction
        .execute(
            "INSERT INTO group_changes VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                change.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                change.group_id.as_opaque().as_str(),
                change.event_id.as_opaque().as_str(),
                actor.principal.principal_id.as_opaque().as_str(),
                principal_kind_name(actor.principal.kind),
                fingerprint.as_slice()
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn history_floor_for_add(
    connection: &Connection,
    group: &GroupRecord,
) -> Result<u64, DurableStoreError> {
    let namespace = namespace_storage_key(&group.scope);
    let base = params![
        group.scope.tenant_id.as_opaque().as_str(),
        namespace.present,
        namespace.value,
        group.conversation.conversation_id.as_opaque().as_str()
    ];
    match &group.history_policy {
        GroupHistoryPolicy::FullHistory | GroupHistoryPolicy::FromTimestamp(_) => Ok(0),
        GroupHistoryPolicy::NoHistory | GroupHistoryPolicy::FromJoin => {
            let last = connection.query_row(
                "SELECT logical_order FROM messages WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4 ORDER BY logical_order DESC LIMIT 1",
                base, |row| row.get::<_,Vec<u8>>(0),
            ).optional().map_err(|error| map_sqlite_error(&error))?;
            last.map_or(Ok(0), |bytes| {
                decode_u64(&bytes)?
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidRecord)
            })
        }
        GroupHistoryPolicy::LastNMessages(count) => {
            let offset = i64::from(count.saturating_sub(1));
            let floor = connection.query_row(
                "SELECT logical_order FROM messages WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4 ORDER BY logical_order DESC LIMIT 1 OFFSET ?5",
                params![group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group.conversation.conversation_id.as_opaque().as_str(), offset],
                |row| row.get::<_,Vec<u8>>(0),
            ).optional().map_err(|error| map_sqlite_error(&error))?;
            let Some(bytes) = floor else {
                return Ok(0);
            };
            let cutoff = decode_u64(&bytes)?;
            let visible_at_or_above: i64 = connection.query_row(
                "SELECT COUNT(*) FROM messages WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4 AND logical_order>=?5",
                params![group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group.conversation.conversation_id.as_opaque().as_str(), bytes],
                |row| row.get(0),
            ).map_err(|error| map_sqlite_error(&error))?;
            if visible_at_or_above > i64::from(*count) {
                cutoff
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidRecord)
            } else {
                Ok(cutoff)
            }
        }
        GroupHistoryPolicy::CustomPolicy(_) => Ok(u64::MAX),
    }
}

fn history_allows(
    group: &GroupRecord,
    membership: &GroupMembership,
    message: &MessageEnvelope,
) -> bool {
    if message.logical_order < membership.history_floor_logical_order {
        return false;
    }
    match group.history_policy {
        GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false,
        GroupHistoryPolicy::NoHistory
        | GroupHistoryPolicy::FromJoin
        | GroupHistoryPolicy::LastNMessages(_)
        | GroupHistoryPolicy::FullHistory => true,
    }
}

fn encode_ownership(
    value: &GroupOwnership,
) -> (
    &'static str,
    Option<&str>,
    Option<&'static str>,
    Option<i64>,
) {
    match value {
        GroupOwnership::PersonOwned(owner) => (
            "person",
            Some(owner.principal_id.as_opaque().as_str()),
            Some(principal_kind_name(owner.kind)),
            None,
        ),
        GroupOwnership::OrganizationOwned(owner) => (
            "organization",
            Some(owner.principal_id.as_opaque().as_str()),
            Some(principal_kind_name(owner.kind)),
            None,
        ),
        GroupOwnership::SharedAdmin => ("shared_admin", None, None, None),
        GroupOwnership::OwnerlessFederated => ("ownerless_federated", None, None, None),
        GroupOwnership::Temporary {
            owner,
            expires_at_unix_ms,
        } => (
            "temporary",
            owner.as_ref().map(|v| v.principal_id.as_opaque().as_str()),
            owner.as_ref().map(|v| principal_kind_name(v.kind)),
            Some(*expires_at_unix_ms),
        ),
    }
}

fn decode_ownership(
    kind: &str,
    id: Option<String>,
    principal_kind: Option<String>,
    expires: Option<i64>,
) -> Result<GroupOwnership, DurableStoreError> {
    let owner = match (id, principal_kind) {
        (None, None) => None,
        (Some(id), Some(kind)) => Some(PrincipalRef {
            principal_id: PrincipalId::from_opaque(parse_id(&id)?),
            kind: parse_principal_kind(&kind)?,
        }),
        _ => return Err(DurableStoreError::Corrupt),
    };
    match kind {
        "person" => Ok(GroupOwnership::PersonOwned(
            owner.ok_or(DurableStoreError::Corrupt)?,
        )),
        "organization" => Ok(GroupOwnership::OrganizationOwned(
            owner.ok_or(DurableStoreError::Corrupt)?,
        )),
        "shared_admin" if owner.is_none() && expires.is_none() => Ok(GroupOwnership::SharedAdmin),
        "ownerless_federated" if owner.is_none() && expires.is_none() => {
            Ok(GroupOwnership::OwnerlessFederated)
        }
        "temporary" => Ok(GroupOwnership::Temporary {
            owner,
            expires_at_unix_ms: expires.ok_or(DurableStoreError::Corrupt)?,
        }),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn encode_history(value: &GroupHistoryPolicy) -> (&'static str, Option<i64>, Option<&str>) {
    match value {
        GroupHistoryPolicy::NoHistory => ("none", None, None),
        GroupHistoryPolicy::FromJoin => ("from_join", None, None),
        GroupHistoryPolicy::LastNMessages(count) => ("last_n", Some(i64::from(*count)), None),
        GroupHistoryPolicy::FromTimestamp(value) => ("from_timestamp", Some(*value), None),
        GroupHistoryPolicy::FullHistory => ("full", None, None),
        GroupHistoryPolicy::CustomPolicy(value) => ("custom", None, Some(value.as_str())),
    }
}

fn decode_history(
    kind: &str,
    value: Option<i64>,
    custom: Option<String>,
) -> Result<GroupHistoryPolicy, DurableStoreError> {
    match kind {
        "none" if value.is_none() && custom.is_none() => Ok(GroupHistoryPolicy::NoHistory),
        "from_join" if value.is_none() && custom.is_none() => Ok(GroupHistoryPolicy::FromJoin),
        "last_n" if custom.is_none() => Ok(GroupHistoryPolicy::LastNMessages(
            u32::try_from(value.ok_or(DurableStoreError::Corrupt)?)
                .map_err(|_| DurableStoreError::Corrupt)?,
        )),
        "from_timestamp" if custom.is_none() => Ok(GroupHistoryPolicy::FromTimestamp(
            value.ok_or(DurableStoreError::Corrupt)?,
        )),
        "full" if value.is_none() && custom.is_none() => Ok(GroupHistoryPolicy::FullHistory),
        "custom" if value.is_none() => Ok(GroupHistoryPolicy::CustomPolicy(
            custom.ok_or(DurableStoreError::Corrupt)?,
        )),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn encode_public_policy(
    value: Option<&PublicGroupPolicy>,
) -> (Option<&'static str>, Option<&'static str>, Option<i64>) {
    value.map_or((None, None, None), |policy| {
        (
            Some(join_policy_name(policy.join_policy)),
            Some(discovery_name(policy.discovery)),
            Some(i64::from(policy.indexed)),
        )
    })
}

fn decode_public_policy(
    join: Option<String>,
    discovery: Option<String>,
    indexed: Option<i64>,
) -> Result<Option<PublicGroupPolicy>, DurableStoreError> {
    match (join, discovery, indexed) {
        (None, None, None) => Ok(None),
        (Some(join), Some(discovery), Some(indexed)) if matches!(indexed, 0 | 1) => {
            Ok(Some(PublicGroupPolicy {
                join_policy: parse_join_policy(&join)?,
                discovery: parse_discovery(&discovery)?,
                indexed: indexed == 1,
            }))
        }
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn parse_scope(
    tenant: &str,
    present: i64,
    namespace: &str,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match (present, namespace.is_empty()) {
        (0, true) => None,
        (1, false) => Some(NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

fn parse_id(value: &str) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}
fn decode_u64(value: &[u8]) -> Result<u64, DurableStoreError> {
    Ok(u64::from_be_bytes(
        value.try_into().map_err(|_| DurableStoreError::Corrupt)?,
    ))
}

const fn principal_kind_name(value: PrincipalKind) -> &'static str {
    match value {
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
fn parse_principal_kind(value: &str) -> Result<PrincipalKind, DurableStoreError> {
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
const fn role_name(value: GroupRole) -> &'static str {
    match value {
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
const fn member_state_name(value: GroupMemberState) -> &'static str {
    match value {
        GroupMemberState::Active => "active",
        GroupMemberState::Removed => "removed",
    }
}
fn parse_member_state(value: &str) -> Result<GroupMemberState, DurableStoreError> {
    match value {
        "active" => Ok(GroupMemberState::Active),
        "removed" => Ok(GroupMemberState::Removed),
        _ => Err(DurableStoreError::Corrupt),
    }
}
const fn conversation_kind_name(value: ConversationKind) -> &'static str {
    match value {
        ConversationKind::PrivateGroup => "private_group",
        ConversationKind::PublicGroup => "public_group",
        _ => "invalid",
    }
}
fn parse_conversation_kind(value: &str) -> Result<ConversationKind, DurableStoreError> {
    match value {
        "private_group" => Ok(ConversationKind::PrivateGroup),
        "public_group" => Ok(ConversationKind::PublicGroup),
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
const fn join_policy_name(value: PublicGroupJoinPolicy) -> &'static str {
    match value {
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

fn map_group_error(error: ucr_protocol::GroupError) -> DurableStoreError {
    use ucr_protocol::GroupError;
    match error {
        GroupError::PermissionDenied => DurableStoreError::PermissionDenied,
        GroupError::RevisionMismatch
        | GroupError::MemberAlreadyActive
        | GroupError::MemberNotActive
        | GroupError::InvalidRoleTransition
        | GroupError::OwnershipTransferNotSupported
        | GroupError::WouldOrphanGroup => DurableStoreError::Conflict,
        GroupError::TooManyMembers => DurableStoreError::Full,
        _ => DurableStoreError::InvalidRecord,
    }
}

#[cfg(test)]
mod phase18_migration_tests {
    use ucr_core::StorageProvider;

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_VERSION, message_store::tests::TestDb};

    #[test]
    fn v20_store_migrates_to_v21_without_inventing_groups() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open current store");
            let connection = store.lock_connection().expect("lock current store");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF; \
                     DROP TABLE group_changes; \
                     DROP TABLE group_bridge_mappings; \
                     DROP TABLE group_memberships; \
                     DROP TABLE groups; \
                     PRAGMA user_version=20;",
                )
                .expect("simulate exact v20 shape");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v20 to v21");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let connection = migrated.lock_connection().expect("lock migrated store");
        let groups: i64 = connection
            .query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
            .expect("count groups");
        let memberships: i64 = connection
            .query_row("SELECT COUNT(*) FROM group_memberships", [], |row| {
                row.get(0)
            })
            .expect("count memberships");
        assert_eq!(groups, 0);
        assert_eq!(memberships, 0);
    }
}

#[cfg(test)]
mod phase18_restart_security_tests {
    use ucr_core::{
        ConversationStore, DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore,
        MessageStore,
    };
    use ucr_model::*;

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, message, scope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn principal(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        }
    }

    fn subject(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: principal(value),
        }
    }

    fn group_fixture() -> (ConversationRecord, GroupRecord, ScopedPrincipal) {
        let owner = subject("phase18-owner");
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase18-group-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase18-group")),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: Vec::new(),
            replication_generation: 0,
            revision: 0,
        };
        (conversation, group, owner)
    }

    fn member_message(
        conversation: &ConversationRef,
        member: &PrincipalRef,
        suffix: &str,
    ) -> MessageEnvelope {
        let mut value = message(format!("group-{suffix}").as_bytes());
        value.message_id = MessageId::from_opaque(oid(&format!("phase18-message-{suffix}")));
        value.conversation = conversation.clone();
        value.delivery_policy = DeliveryPolicy::Durable;
        value.origin.principal_id = Some(member.principal_id.clone());
        value.correlation.correlation_id = oid(&format!("phase18-correlation-{suffix}"));
        value.correlation.idempotency_key = Some(format!("phase18-idempotency-{suffix}"));
        value
    }

    #[test]
    fn membership_tombstone_and_group_message_gate_survive_restart() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let member = subject("phase18-member");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("phase18-add-member")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: member.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        let remove = GroupChange {
            event_id: EventId::from_opaque(oid("phase18-remove-member")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 1,
            kind: GroupChangeKind::RemoveMember {
                member: member.principal.clone(),
            },
            next_crypto_state: None,
        };
        let first_message = member_message(
            &conversation.conversation,
            &member.principal,
            "before-remove",
        );

        {
            let store = SqliteLocalStore::open(db.path()).expect("open Group store");
            assert_eq!(
                store.create_group(&conversation, &group, &owner),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.apply_group_change(&owner, &add),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.persist_group_message(&member, &first_message),
                Ok(DurableRecordStatus::Persisted)
            );
        }

        {
            let reopened = SqliteLocalStore::open(db.path()).expect("reopen before removal");
            assert_eq!(
                reopened
                    .group(&scope(), &group.group_id)
                    .expect("load group")
                    .expect("group exists")
                    .revision,
                1
            );
            assert!(
                reopened
                    .group_message(&member, &scope(), &first_message.message_id)
                    .expect("member history read")
                    .is_some()
            );
            assert_eq!(
                reopened.apply_group_change(&owner, &remove),
                Ok(DurableRecordStatus::Persisted)
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen after removal");
        let tombstone = reopened
            .group_membership(&scope(), &group.group_id, &member.principal)
            .expect("load membership")
            .expect("tombstone exists");
        assert_eq!(tombstone.state, GroupMemberState::Removed);
        assert_eq!(tombstone.removed_revision, Some(2));
        assert_eq!(
            reopened.apply_group_change(&owner, &remove),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert!(
            reopened
                .group_message(&member, &scope(), &first_message.message_id)
                .expect("removed member history query")
                .is_none()
        );
        let denied = member_message(
            &conversation.conversation,
            &member.principal,
            "after-remove",
        );
        assert_eq!(
            reopened.persist_group_message(&member, &denied),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            reopened
                .group(&scope(), &group.group_id)
                .expect("load final group")
                .expect("final group exists")
                .revision,
            2
        );
    }

    #[test]
    fn private_group_message_read_is_non_oracular_for_kind_alias() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let original = member_message(&conversation.conversation, &owner.principal, "oracle");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        store
            .persist_group_message(&owner, &original)
            .expect("message");
        let alias = ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: owner.principal.principal_id.clone(),
                kind: PrincipalKind::Organization,
            },
        };
        assert_eq!(
            store.group_message(&alias, &scope(), &original.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(
                &alias,
                &scope(),
                &MessageId::from_opaque(oid("sqlite-unknown-message"))
            ),
            Ok(None)
        );
    }

    #[test]
    fn from_timestamp_history_fails_closed_on_untrusted_message_time() {
        let db = TestDb::new();
        let (conversation, mut group, owner) = group_fixture();
        group.history_policy = GroupHistoryPolicy::FromTimestamp(1);
        let mut forged = member_message(&conversation.conversation, &owner.principal, "timestamp");
        forged.created_at_unix_ms = i64::MAX;
        forged.logical_order = 7;
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        store
            .persist_group_message(&owner, &forged)
            .expect("message");
        assert_eq!(
            store.group_message(&owner, &scope(), &forged.message_id),
            Ok(None)
        );
    }

    #[test]
    fn last_n_tied_cutoff_never_over_discloses_and_future_order_remains_visible() {
        let db = TestDb::new();
        let (conversation, mut group, owner) = group_fixture();
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        let member = subject("lastn-member");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let mut first = member_message(&conversation.conversation, &owner.principal, "tie-a");
        first.logical_order = 7;
        let mut second = member_message(&conversation.conversation, &owner.principal, "tie-b");
        second.logical_order = 7;
        store.persist_group_message(&owner, &first).expect("first");
        store
            .persist_group_message(&owner, &second)
            .expect("second");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-lastn-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: member.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add).expect("add member");
        assert_eq!(
            store.group_message(&member, &scope(), &first.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(&member, &scope(), &second.message_id),
            Ok(None)
        );
        let mut future = member_message(&conversation.conversation, &owner.principal, "future");
        future.logical_order = 8;
        store
            .persist_group_message(&owner, &future)
            .expect("future");
        assert!(
            store
                .group_message(&member, &scope(), &future.message_id)
                .expect("read")
                .is_some()
        );
    }

    #[test]
    fn sqlite_creator_history_floor_is_derived_from_preexisting_transcript() {
        let db = TestDb::new();
        let (conversation, mut group, owner) = group_fixture();
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        let store = SqliteLocalStore::open(db.path()).expect("open");
        assert_eq!(
            store.persist_conversation(&conversation),
            Ok(DurableRecordStatus::Persisted)
        );
        let mut first = member_message(&conversation.conversation, &owner.principal, "pre-first");
        first.logical_order = 4;
        let mut last = member_message(&conversation.conversation, &owner.principal, "pre-last");
        last.logical_order = 5;
        assert_eq!(
            store.persist_message(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_message(&last),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Persisted)
        );
        let membership = store
            .group_membership(&scope(), &group.group_id, &owner.principal)
            .expect("membership read")
            .expect("creator membership");
        assert_eq!(membership.history_floor_logical_order, 5);
        assert_eq!(
            store.group_message(&owner, &scope(), &first.message_id),
            Ok(None)
        );
        assert!(
            store
                .group_message(&owner, &scope(), &last.message_id)
                .expect("last read")
                .is_some()
        );
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn sqlite_group_message_without_group_aggregate_is_non_oracular() {
        let db = TestDb::new();
        let (conversation, _, owner) = group_fixture();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .persist_conversation(&conversation)
            .expect("conversation");
        let orphan = member_message(
            &conversation.conversation,
            &owner.principal,
            "aggregate-gap",
        );
        store.persist_message(&orphan).expect("message");
        assert_eq!(
            store.group_message(&owner, &scope(), &orphan.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(
                &owner,
                &scope(),
                &MessageId::from_opaque(oid("sqlite-aggregate-gap-unknown"))
            ),
            Ok(None)
        );
    }

    #[test]
    fn sqlite_duplicate_group_change_is_bound_to_original_actor() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let intruder = subject("duplicate-intruder");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-duplicate-actor-event")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("duplicate-member").principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert_eq!(
            store.apply_group_change(&intruder, &change),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn sqlite_same_opaque_id_different_principal_kinds_are_distinct_memberships() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let alias = ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: owner.principal.principal_id.clone(),
                kind: PrincipalKind::Organization,
            },
        };
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-dual-kind-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: alias.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&owner, &change),
            Ok(DurableRecordStatus::Persisted)
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &owner.principal)
                .expect("owner lookup")
                .is_some()
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &alias.principal)
                .expect("alias lookup")
                .is_some()
        );
        assert_eq!(
            store
                .group_memberships(&scope(), &group.group_id, 8)
                .expect("members")
                .len(),
            2
        );
    }

    #[test]
    fn sqlite_removed_original_actor_cannot_replay_duplicate_group_change() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let admin = subject("sqlite-removed-dup-admin");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store
            .create_group(&conversation, &group, &owner)
            .expect("group");
        let add_admin = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-add-admin")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: admin.principal.clone(),
                role: GroupRole::Admin,
            },
            next_crypto_state: None,
        };
        store
            .apply_group_change(&owner, &add_admin)
            .expect("add admin");
        let admin_change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-admin-change")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 1,
            kind: GroupChangeKind::AddMember {
                member: subject("sqlite-removed-dup-member").principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(
            store.apply_group_change(&admin, &admin_change),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.apply_group_change(&admin, &admin_change),
            Ok(DurableRecordStatus::Duplicate)
        );
        let remove_admin = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-remove-admin")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 2,
            kind: GroupChangeKind::RemoveMember {
                member: admin.principal.clone(),
            },
            next_crypto_state: None,
        };
        store
            .apply_group_change(&owner, &remove_admin)
            .expect("remove admin");
        assert_eq!(
            store.apply_group_change(&admin, &admin_change),
            Err(DurableStoreError::PermissionDenied)
        );
    }
}

#[cfg(test)]
mod phase18_event_identity_security_tests {
    use ucr_core::{
        DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore, GroupStore,
    };
    use ucr_model::*;

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, scope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }
    fn owner() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("sqlite-event-owner")),
                kind: PrincipalKind::Person,
            },
        }
    }
    fn group_fixture(suffix: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid(&format!(
                    "sqlite-event-conversation-{suffix}"
                ))),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid(&format!("sqlite-event-group-{suffix}"))),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: Vec::new(),
            replication_generation: 0,
            revision: 0,
        };
        (conversation, group)
    }
    fn member(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        }
    }
    fn change(group: &GroupRecord, event_id: &str, member_id: &str) -> GroupChange {
        GroupChange {
            event_id: EventId::from_opaque(oid(event_id)),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: member(member_id),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        }
    }
    fn event(id: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.group.member_added".to_owned(),
            payload: b"projection".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("sqlite-event-actor")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("sqlite-event-device")),
                identity_id: IdentityId::from_opaque(oid("sqlite-event-identity")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("sqlite-event-correlation"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn group_change_event_id_is_scope_wide_and_event_journal_exclusive() {
        let db = TestDb::new();
        let owner = owner();
        let (conversation_a, group_a) = group_fixture("a", &owner);
        let (conversation_b, group_b) = group_fixture("b", &owner);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store
                .create_group(&conversation_a, &group_a, &owner)
                .expect("group a");
            store
                .create_group(&conversation_b, &group_b, &owner)
                .expect("group b");
            let first = change(&group_a, "sqlite-shared-event", "sqlite-member-a");
            assert_eq!(
                store.apply_group_change(&owner, &first),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.apply_group_change(&owner, &first),
                Ok(DurableRecordStatus::Duplicate)
            );
            assert_eq!(
                store.apply_group_change(
                    &owner,
                    &change(&group_b, "sqlite-shared-event", "sqlite-member-b")
                ),
                Err(DurableStoreError::Conflict)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(
            reopened.append_event(&event("sqlite-shared-event")),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            reopened.append_event(&event("sqlite-event-first")),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            reopened.apply_group_change(
                &owner,
                &change(&group_b, "sqlite-event-first", "sqlite-member-c")
            ),
            Err(DurableStoreError::Conflict)
        );
    }
}
