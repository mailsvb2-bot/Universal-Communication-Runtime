from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise SystemExit(f"missing marker: {label}")
    return text.replace(old, new, 1)


# P1: PrincipalRef identity includes PrincipalKind. Memory membership lookup keys are
# intentionally compact, so every authority-bearing lookup must compare the stored PrincipalRef.
mem_group = Path("crates/ucr-storage-memory/src/group_store.rs")
text = mem_group.read_text()
text = replace_once(
    text,
    '''        Ok(state
            .group_memberships
            .get(&membership_key(scope, group_id, member))
            .cloned())''',
    '''        Ok(state
            .group_memberships
            .get(&membership_key(scope, group_id, member))
            .filter(|membership| membership.member == *member)
            .cloned())''',
    "memory membership read principal kind",
)
text = replace_once(
    text,
    '''        let membership = state
            .group_memberships
            .get(&membership_key(
                &group.scope,
                &group.group_id,
                &subject.principal,
            ))
            .ok_or(DurableStoreError::PermissionDenied)?;''',
    '''        let membership = state
            .group_memberships
            .get(&membership_key(
                &group.scope,
                &group.group_id,
                &subject.principal,
            ))
            .filter(|membership| membership.member == subject.principal)
            .ok_or(DurableStoreError::PermissionDenied)?;''',
    "memory group write principal kind",
)
text = replace_once(
    text,
    '''        let membership = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .ok_or(DurableStoreError::PermissionDenied)?;''',
    '''        let membership = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .filter(|membership| membership.member == subject.principal)
            .ok_or(DurableStoreError::PermissionDenied)?;''',
    "memory group read principal kind",
)

# P2: EventId is one exact-scope fact namespace, not per Group. The Group mutation
# idempotency reservation must conflict with every other Group and ordinary Event append.
text = replace_once(
    text,
    '''        let change_key = change_key(
            &change.scope,
            &change.group_id,
            change.event_id.as_opaque().as_str(),
        );''',
    '''        let change_key = change_key(&change.scope, change.event_id.as_opaque().as_str());''',
    "memory scope-wide change key call",
)
text = replace_once(
    text,
    '''        if let Some(existing) = state.group_changes.get(&change_key) {
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let group = state''',
    '''        if let Some(existing) = state.group_changes.get(&change_key) {
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.events.contains_key(&change_key) {
            return Err(DurableStoreError::Conflict);
        }
        let group = state''',
    "memory group change vs event journal collision",
)
text = replace_once(
    text,
    '''fn change_key(scope: &TenantScope, group_id: &GroupId, event_id: &str) -> GroupChangeKey {
    (
        scope_key(scope),
        group_id.as_opaque().as_str().to_owned(),
        event_id.to_owned(),
    )
}''',
    '''fn change_key(scope: &TenantScope, event_id: &str) -> GroupChangeKey {
    (scope_key(scope), event_id.to_owned())
}''',
    "memory scope-wide change key definition",
)

if "principal_kind_alias_cannot_inherit_group_membership" not in text:
    text += r'''

#[cfg(test)]
mod phase18_memory_security_tests {
    use ucr_core::{DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore, GroupMessageStore, GroupStore};
    use ucr_model::*;

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("phase18-security-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("phase18-security-namespace"))),
        }
    }

    fn subject(value: &str, kind: PrincipalKind) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(value)),
                kind,
            },
        }
    }

    fn group_fixture(suffix: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid(&format!("memory-conversation-{suffix}"))),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid(&format!("memory-group-{suffix}"))),
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

    fn message(conversation: &ConversationRef, principal_id: &PrincipalId, suffix: &str) -> MessageEnvelope {
        MessageEnvelope {
            message_id: MessageId::from_opaque(oid(&format!("memory-message-{suffix}"))),
            scope: scope(),
            conversation: conversation.clone(),
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid(&format!("memory-actor-{suffix}"))),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid(&format!("memory-device-{suffix}"))),
                identity_id: IdentityId::from_opaque(oid(&format!("memory-identity-{suffix}"))),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"group-message".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(principal_id.clone()),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid(&format!("memory-correlation-{suffix}")),
                causation_id: None,
                idempotency_key: Some(format!("memory-idempotency-{suffix}")),
            },
            extensions: Vec::new(),
            external_mappings: Vec::new(),
            signature: None,
        }
    }

    fn event(id: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.group.member_added".to_owned(),
            payload: b"projection".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("memory-event-actor")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("memory-event-device")),
                identity_id: IdentityId::from_opaque(oid("memory-event-identity")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("memory-event-correlation"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn principal_kind_alias_cannot_inherit_group_membership() {
        let store = MemoryLocalStore::default();
        let owner = subject("shared-principal-id", PrincipalKind::Person);
        let alias = subject("shared-principal-id", PrincipalKind::Organization);
        let (conversation, group) = group_fixture("principal-kind", &owner);
        assert_eq!(
            store.create_group(&conversation, &group, &owner),
            Ok(DurableRecordStatus::Persisted)
        );
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &alias.principal)
                .expect("alias lookup")
                .is_none()
        );
        let original = message(&conversation.conversation, &owner.principal.principal_id, "owner");
        assert_eq!(
            store.persist_group_message(&owner, &original),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.group_message(&alias, &scope(), &original.message_id),
            Err(DurableStoreError::PermissionDenied)
        );
        let forged = message(&conversation.conversation, &alias.principal.principal_id, "alias");
        assert_eq!(
            store.persist_group_message(&alias, &forged),
            Err(DurableStoreError::PermissionDenied)
        );
    }

    #[test]
    fn group_change_event_id_is_scope_wide_and_cannot_alias_event_journal() {
        let store = MemoryLocalStore::default();
        let owner = subject("memory-event-owner", PrincipalKind::Person);
        let (conversation_a, group_a) = group_fixture("event-a", &owner);
        let (conversation_b, group_b) = group_fixture("event-b", &owner);
        store.create_group(&conversation_a, &group_a, &owner).expect("group a");
        store.create_group(&conversation_b, &group_b, &owner).expect("group b");

        let shared_id = EventId::from_opaque(oid("memory-shared-event-id"));
        let change_a = GroupChange {
            event_id: shared_id.clone(),
            scope: scope(),
            group_id: group_a.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-a", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        let change_b = GroupChange {
            event_id: shared_id.clone(),
            scope: scope(),
            group_id: group_b.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-b", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &change_a), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.apply_group_change(&owner, &change_a), Ok(DurableRecordStatus::Duplicate));
        assert_eq!(store.apply_group_change(&owner, &change_b), Err(DurableStoreError::Conflict));
        assert_eq!(store.append_event(&event("memory-shared-event-id")), Err(DurableStoreError::Conflict));

        assert_eq!(store.append_event(&event("memory-event-first-id")), Ok(EventAppendStatus::Appended));
        let event_first_change = GroupChange {
            event_id: EventId::from_opaque(oid("memory-event-first-id")),
            scope: scope(),
            group_id: group_b.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("memory-member-c", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &event_first_change), Err(DurableStoreError::Conflict));
    }
}
'''
mem_group.write_text(text)

mem_lib = Path("crates/ucr-storage-memory/src/lib.rs")
text = mem_lib.read_text()
text = replace_once(text, "type GroupChangeKey = (ScopeKey, String, String);", "type GroupChangeKey = (ScopeKey, String);", "memory group change key type")
text = replace_once(
    text,
    '''        if let Some(original) = state.events.get(&key) {
            return if original == &event {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key.clone(), event);''',
    '''        if let Some(original) = state.events.get(&key) {
            return if original == &event {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.group_changes.contains_key(&key) {
            return Err(DurableStoreError::Conflict);
        }
        state.events.insert(key.clone(), event);''',
    "memory event journal vs group reservation",
)
text = replace_once(
    text,
    '''        if let Some(local) = state.events.get(&key) {
            return if event_fingerprint(local).map_err(|_| DurableStoreError::Corrupt)?
                == event_fingerprint(&event).map_err(map_event_error)?
            {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key.clone(), event);''',
    '''        if let Some(local) = state.events.get(&key) {
            return if event_fingerprint(local).map_err(|_| DurableStoreError::Corrupt)?
                == event_fingerprint(&event).map_err(map_event_error)?
            {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.group_changes.contains_key(&key) {
            return Err(DurableStoreError::Conflict);
        }
        state.events.insert(key.clone(), event);''',
    "memory anti-entropy vs group reservation",
)
text = replace_once(
    text,
    '''        if let Some(original) = state.events.get(&event_key) {
            if original != &event {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state.events.insert(event_key.clone(), event.clone());''',
    '''        if state.group_changes.contains_key(&event_key) {
            return Err(DurableStoreError::Conflict);
        }
        if let Some(original) = state.events.get(&event_key) {
            if original != &event {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state.events.insert(event_key.clone(), event.clone());''',
    "memory command outcome vs group reservation",
)
mem_lib.write_text(text)

# SQLite uses the same scope-wide EventId namespace and composes with the canonical Event journal.
sql_group = Path("crates/ucr-storage-sqlite/src/group_store.rs")
text = sql_group.read_text()
text = replace_once(text, "    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, event_id),", "    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),", "sqlite scope-wide group change primary key")
text = replace_once(
    text,
    '''            ("group_id", "TEXT", 1, 4),
            ("event_id", "TEXT", 1, 5),
            ("fingerprint", "BLOB", 1, 0),''',
    '''            ("group_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 4),
            ("fingerprint", "BLOB", 1, 0),''',
    "sqlite group change PK shape",
)
text = replace_once(
    text,
    '''        if let Some(existing) = load_change_fingerprint(
            &transaction,
            &change.scope,
            &change.group_id,
            change.event_id.as_opaque().as_str(),
        )? {''',
    '''        if let Some(existing) = load_change_fingerprint(
            &transaction,
            &change.scope,
            change.event_id.as_opaque().as_str(),
        )? {''',
    "sqlite scope-wide change fingerprint lookup",
)
text = replace_once(
    text,
    '''        if let Some(existing) = load_change_fingerprint(
            &transaction,
            &change.scope,
            change.event_id.as_opaque().as_str(),
        )? {
            return if existing == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let group = load_group_from''',
    '''        if let Some(existing) = load_change_fingerprint(
            &transaction,
            &change.scope,
            change.event_id.as_opaque().as_str(),
        )? {
            return if existing == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if super::event_journal::load_event_by_id(&transaction, &change.scope, &change.event_id)?
            .is_some()
        {
            return Err(DurableStoreError::Conflict);
        }
        let group = load_group_from''',
    "sqlite group change vs canonical event",
)
text = replace_once(
    text,
    '''fn load_change_fingerprint(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
    event_id: &str,
) -> Result<Option<[u8; 32]>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value = connection.query_row(
        "SELECT fingerprint FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 AND event_id=?5",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group_id.as_opaque().as_str(), event_id],
        |row| row.get::<_,Vec<u8>>(0),
    ).optional().map_err(|error| map_sqlite_error(&error))?;''',
    '''fn load_change_fingerprint(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<Option<[u8; 32]>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value = connection.query_row(
        "SELECT fingerprint FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
        |row| row.get::<_,Vec<u8>>(0),
    ).optional().map_err(|error| map_sqlite_error(&error))?;''',
    "sqlite load scope-wide change fingerprint",
)

if "group_change_event_id_is_scope_wide_and_event_journal_exclusive" not in text:
    text += r'''

#[cfg(test)]
mod phase18_event_identity_security_tests {
    use ucr_core::{DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore, GroupStore};
    use ucr_model::*;

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, scope};

    fn oid(value: &str) -> OpaqueId { OpaqueId::new(value).expect("test id") }
    fn owner() -> ScopedPrincipal {
        ScopedPrincipal { scope: scope(), principal: PrincipalRef { principal_id: PrincipalId::from_opaque(oid("sqlite-event-owner")), kind: PrincipalKind::Person } }
    }
    fn group_fixture(suffix: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
        let conversation = ConversationRecord { scope: scope(), conversation: ConversationRef { conversation_id: ConversationId::from_opaque(oid(&format!("sqlite-event-conversation-{suffix}"))), kind: ConversationKind::PrivateGroup }, parent_conversation_id: None };
        let group = GroupRecord { scope: scope(), group_id: GroupId::from_opaque(oid(&format!("sqlite-event-group-{suffix}"))), conversation: conversation.conversation.clone(), ownership: GroupOwnership::PersonOwned(owner.principal.clone()), history_policy: GroupHistoryPolicy::FullHistory, delivery_policy: DeliveryPolicy::Durable, crypto_state: GroupCryptoState { capability_id: None, epoch: 0, state_ref: None }, public_policy: None, media_state: GroupMediaState::Idle, bridge_mappings: Vec::new(), replication_generation: 0, revision: 0 };
        (conversation, group)
    }
    fn member(value: &str) -> PrincipalRef { PrincipalRef { principal_id: PrincipalId::from_opaque(oid(value)), kind: PrincipalKind::Person } }
    fn change(group: &GroupRecord, event_id: &str, member_id: &str) -> GroupChange {
        GroupChange { event_id: EventId::from_opaque(oid(event_id)), scope: scope(), group_id: group.group_id.clone(), expected_revision: 0, kind: GroupChangeKind::AddMember { member: member(member_id), role: GroupRole::Member }, next_crypto_state: None }
    }
    fn event(id: &str) -> EventEnvelope {
        EventEnvelope { event_id: EventId::from_opaque(oid(id)), scope: scope(), event_type: "ucr.group.member_added".to_owned(), payload: b"projection".to_vec(), actor: ActorRef { actor_id: ActorId::from_opaque(oid("sqlite-event-actor")), kind: ActorKind::System, on_behalf_of: None }, source_device: DeviceRef { device_id: DeviceId::from_opaque(oid("sqlite-event-device")), identity_id: IdentityId::from_opaque(oid("sqlite-event-identity")) }, wall_time_unix_ms: 1, logical_order: 1, correlation: CorrelationContext { correlation_id: oid("sqlite-event-correlation"), causation_id: None, idempotency_key: None }, schema_version: ProtocolVersion::new(1, 0), integrity_metadata: Vec::new(), extensions: Vec::new() }
    }

    #[test]
    fn group_change_event_id_is_scope_wide_and_event_journal_exclusive() {
        let db = TestDb::new();
        let owner = owner();
        let (conversation_a, group_a) = group_fixture("a", &owner);
        let (conversation_b, group_b) = group_fixture("b", &owner);
        {
            let store = SqliteLocalStore::open(db.path()).expect("open");
            store.create_group(&conversation_a, &group_a, &owner).expect("group a");
            store.create_group(&conversation_b, &group_b, &owner).expect("group b");
            let first = change(&group_a, "sqlite-shared-event", "sqlite-member-a");
            assert_eq!(store.apply_group_change(&owner, &first), Ok(DurableRecordStatus::Persisted));
            assert_eq!(store.apply_group_change(&owner, &first), Ok(DurableRecordStatus::Duplicate));
            assert_eq!(store.apply_group_change(&owner, &change(&group_b, "sqlite-shared-event", "sqlite-member-b")), Err(DurableStoreError::Conflict));
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen");
        assert_eq!(reopened.append_event(&event("sqlite-shared-event")), Err(DurableStoreError::Conflict));
        assert_eq!(reopened.append_event(&event("sqlite-event-first")), Ok(EventAppendStatus::Appended));
        assert_eq!(reopened.apply_group_change(&owner, &change(&group_b, "sqlite-event-first", "sqlite-member-c")), Err(DurableStoreError::Conflict));
    }
}
'''
sql_group.write_text(text)

sql_event = Path("crates/ucr-storage-sqlite/src/event_journal.rs")
text = sql_event.read_text()
marker = '''pub(super) fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<EventAppendStatus, DurableStoreError> {'''
helper = '''fn group_change_reserves_event_id(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &EventId,
) -> Result<bool, DurableStoreError> {
    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='group_changes')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !table_exists {
        return Ok(false);
    }
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4)",
            params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id.as_opaque().as_str()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

'''
if "fn group_change_reserves_event_id(" not in text:
    if marker not in text: raise SystemExit("sqlite append-event marker missing")
    text = text.replace(marker, helper + marker, 1)
text = replace_once(
    text,
    '''    if let Some(existing) = load_event_by_id(transaction, &event.scope, &event.event_id)? {
        return if existing == event {
            Ok(EventAppendStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    let namespace = namespace_storage_key(&event.scope);''',
    '''    if let Some(existing) = load_event_by_id(transaction, &event.scope, &event.event_id)? {
        return if existing == event {
            Ok(EventAppendStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    if group_change_reserves_event_id(transaction, &event.scope, &event.event_id)? {
        return Err(DurableStoreError::Conflict);
    }
    let namespace = namespace_storage_key(&event.scope);''',
    "sqlite event journal vs group reservation",
)
sql_event.write_text(text)

model = Path("crates/ucr-model/src/group.rs")
text = model.read_text()
text = replace_once(
    text,
    '''/// `event_id` is the unique fact identifier. The generic Event API may project the same fact later;
/// this structure never stores localized human-readable system text.''',
    '''/// `event_id` is the exact-scope unique fact identifier. A committed Group change reserves that
/// identity against unrelated generic Event append; any future same-fact Event projection must use
/// an explicit reconciliation path rather than silently reusing the identifier.
/// This structure never stores localized human-readable system text.''',
    "GroupChange EventId model contract",
)
model.write_text(text)

spec = Path("spec/groups.md")
text = spec.read_text()
text = replace_once(
    text,
    '''Every Group change has a canonical `EventId` and fingerprint. Replaying the same scoped event with identical semantics is a duplicate. Reusing that event identity with different semantics is a conflict. Membership/role/ownership transitions and the Group revision are committed in one storage action.''',
    '''Every Group change has a canonical `EventId` and fingerprint. `EventId` is unique across the entire exact `TenantScope`, not merely inside one Group: the same scoped identifier cannot name changes in two different Groups. Replaying the same scoped Group fact with identical semantics is a duplicate; reusing that identity with different semantics is a conflict. Membership/role/ownership transitions and the Group revision are committed in one storage action.

A committed Group change also reserves its scoped `EventId` against ordinary canonical Event append, and an existing canonical Event reserves the same identity against Group mutation. Phase 18 therefore fails closed instead of creating two facts with one ID. A future same-fact projection into the Event journal requires an explicit reconciliation contract; generic Event append is not that contract.''',
    "groups spec scope-wide EventId",
)
spec.write_text(text)

adr = Path("docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md")
text = adr.read_text()
text = replace_once(
    text,
    '''Group management remains behind existing explicit tenant-scoped UCR permissions. Durable membership/role checks are additional authorization facts evaluated inside the Group storage action. Membership changes use optimistic Group revision plus a canonical Event-ID fingerprint so exact retries deduplicate and changed semantics conflict.''',
    '''Group management remains behind existing explicit tenant-scoped UCR permissions. Durable membership/role checks are additional authorization facts evaluated inside the Group storage action. Membership changes use optimistic Group revision plus a canonical Event-ID fingerprint so exact retries deduplicate and changed semantics conflict. The Event ID namespace is exact-scope-wide: Group changes cannot reuse an ID across Groups, and Group/Event writes mutually reject ordinary reuse so two canonical facts cannot silently acquire one identity. Future same-fact Event projection requires an explicit reconciliation path rather than a second Event owner.''',
    "ADR0056 scope-wide EventId decision",
)
text = replace_once(text, "- Add/remove/role/ownership changes and their idempotency record are atomic.", "- Add/remove/role/ownership changes and their idempotency record are atomic.\n- `EventId` remains one exact-scope fact namespace across Group changes and the canonical Event journal.", "ADR0056 EventId consequence")
adr.write_text(text)

arch = Path("crates/ucr-architecture-tests/tests/phase18_groups.rs")
text = arch.read_text()
text = replace_once(
    text,
    '''    assert!(memory.contains("persist_message_in_state"));
    assert!(sqlite.contains("insert_message_row"));''',
    '''    assert!(memory.contains("persist_message_in_state"));
    assert!(memory.contains("membership.member == *member"));
    assert!(memory.contains("membership.member == subject.principal"));
    assert!(memory.contains("state.events.contains_key(&change_key)"));
    assert!(sqlite.contains("insert_message_row"));''',
    "Phase18 architecture memory security locks",
)
text = replace_once(
    text,
    '''    assert!(sqlite.contains("group_changes"));
    assert!(sqlite.contains("group_memberships"));''',
    '''    assert!(sqlite.contains("group_changes"));
    assert!(sqlite.contains("PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id)"));
    assert!(sqlite.contains("load_event_by_id(&transaction, &change.scope, &change.event_id)"));
    assert!(sqlite.contains("group_memberships"));''',
    "Phase18 architecture SQLite EventId locks",
)
arch.write_text(text)
