from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise SystemExit(f"missing marker: {label}")
    return text.replace(old, new, 1)

# PrincipalRef is the canonical identity pair (opaque id + kind); make it directly hashable
# so in-memory durable keys cannot accidentally collapse the kind dimension.
model = Path("crates/ucr-model/src/lib.rs")
text = model.read_text()
text = replace_once(
    text,
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum PrincipalKind {",
    "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\npub enum PrincipalKind {",
    "PrincipalKind Hash",
)
text = replace_once(
    text,
    "#[derive(Debug, Clone, PartialEq, Eq)]\npub struct PrincipalRef {",
    "#[derive(Debug, Clone, PartialEq, Eq, Hash)]\npub struct PrincipalRef {",
    "PrincipalRef Hash",
)
model.write_text(text)

# Canonical membership deduplication is by the complete PrincipalRef, not only principal_id.
protocol = Path("crates/ucr-protocol/src/group.rs")
text = protocol.read_text()
text = replace_once(
    text,
    """    if canonical
        .windows(2)
        .any(|pair| pair[0].member.principal_id == pair[1].member.principal_id)
    {
        return Err(GroupError::DuplicateMembership);
    }
""",
    """    if canonical
        .windows(2)
        .any(|pair| pair[0].member == pair[1].member)
    {
        return Err(GroupError::DuplicateMembership);
    }
""",
    "canonical full PrincipalRef dedup",
)
protocol.write_text(text)

# Memory storage keys preserve full PrincipalRef identity, and Group-change idempotency
# records bind the original authenticated actor as well as the fingerprint.
mem_lib = Path("crates/ucr-storage-memory/src/lib.rs")
text = mem_lib.read_text()
text = replace_once(
    text,
    "type GroupMembershipKey = (ScopeKey, String, String);",
    "type GroupMembershipKey = (ScopeKey, String, ucr_model::PrincipalRef);",
    "memory membership key full PrincipalRef",
)
text = replace_once(
    text,
    "    group_changes: HashMap<GroupChangeKey, [u8; 32]>,",
    "    group_changes: HashMap<GroupChangeKey, (ucr_model::PrincipalRef, [u8; 32])>,",
    "memory change actor binding",
)
mem_lib.write_text(text)

mem = Path("crates/ucr-storage-memory/src/group_store.rs")
text = mem.read_text()
text = replace_once(
    text,
    """        let (group, creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
""",
    """        let (group, mut creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
""",
    "memory mutable creator membership",
)
text = replace_once(
    text,
    """        if let Some(existing) = state.groups.get(&group_key) {
            let existing_creator = state.group_memberships.get(&creator_key);
            return if existing == &group && existing_creator == Some(&creator_membership) {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
""",
    """        if let Some(existing) = state.groups.get(&group_key) {
            let existing_creator = state.group_memberships.get(&creator_key);
            let duplicate = existing_creator.is_some_and(|persisted| {
                let mut expected = creator_membership.clone();
                expected.history_floor_logical_order = persisted.history_floor_logical_order;
                existing == &group && persisted == &expected
            });
            return if duplicate {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
""",
    "memory idempotent create with durable floor",
)
text = replace_once(
    text,
    """        } else {
            state
                .conversations
                .insert(conversation_key, conversation.clone());
        }
        state.groups.insert(group_key, group);
""",
    """        } else {
            state
                .conversations
                .insert(conversation_key, conversation.clone());
        }
        creator_membership.history_floor_logical_order = history_floor_for_add(&state, &group)?;
        state.groups.insert(group_key, group);
""",
    "memory creator history floor",
)
text = replace_once(
    text,
    """    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let group_key = group_key(&change.scope, &change.group_id);
""",
    """    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != change.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let group_key = group_key(&change.scope, &change.group_id);
""",
    "memory duplicate scope authorization",
)
text = replace_once(
    text,
    """        if let Some(existing) = state.group_changes.get(&change_key) {
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
""",
    """        if let Some((recorded_actor, existing)) = state.group_changes.get(&change_key) {
            if recorded_actor != &actor.principal {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
""",
    "memory duplicate actor binding",
)
text = replace_once(
    text,
    "        state.group_changes.insert(change_key, fingerprint);",
    "        state\n            .group_changes\n            .insert(change_key, (actor.principal.clone(), fingerprint));",
    "memory persist change actor",
)
text = replace_once(
    text,
    """        let group = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.conversation == message.conversation)
            .ok_or(DurableStoreError::Corrupt)?;
""",
    """        let Some(group) = state
            .groups
            .values()
            .find(|group| group.scope == *scope && group.conversation == message.conversation)
        else {
            return Ok(None);
        };
""",
    "memory missing aggregate non-oracle",
)
text = replace_once(
    text,
    """    (
        scope_key(scope),
        group_id.as_opaque().as_str().to_owned(),
        member.principal_id.as_opaque().as_str().to_owned(),
    )
""",
    """    (
        scope_key(scope),
        group_id.as_opaque().as_str().to_owned(),
        member.clone(),
    )
""",
    "memory full membership key",
)
text = text.replace(
    "        DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore,\n        GroupMessageStore, GroupStore,\n",
    "        ConversationStore, DurableRecordStatus, DurableStoreError, EventAppendStatus,\n        EventJournalStore, GroupMessageStore, GroupStore, MessageStore,\n",
    1,
)
if "creator_history_floor_is_derived_from_preexisting_transcript" not in text:
    insert = r'''

    #[test]
    fn creator_history_floor_is_derived_from_preexisting_transcript() {
        let store = MemoryLocalStore::default();
        let owner = subject("creator-floor-owner", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("creator-floor", &owner);
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        assert_eq!(store.persist_conversation(&conversation), Ok(DurableRecordStatus::Persisted));
        let mut first = message(&conversation.conversation, &owner.principal.principal_id, "pre-first");
        first.logical_order = 4;
        let mut last = message(&conversation.conversation, &owner.principal.principal_id, "pre-last");
        last.logical_order = 5;
        assert_eq!(store.persist_message(&first), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.persist_message(&last), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.create_group(&conversation, &group, &owner), Ok(DurableRecordStatus::Persisted));
        let membership = store.group_membership(&scope(), &group.group_id, &owner.principal)
            .expect("membership read").expect("creator membership");
        assert_eq!(membership.history_floor_logical_order, 5);
        assert_eq!(store.group_message(&owner, &scope(), &first.message_id), Ok(None));
        assert!(store.group_message(&owner, &scope(), &last.message_id).expect("last read").is_some());
        assert_eq!(store.create_group(&conversation, &group, &owner), Ok(DurableRecordStatus::Duplicate));
    }

    #[test]
    fn group_message_without_group_aggregate_is_non_oracular() {
        let store = MemoryLocalStore::default();
        let owner = subject("aggregate-gap-owner", PrincipalKind::Person);
        let (conversation, _) = group_fixture("aggregate-gap", &owner);
        store.persist_conversation(&conversation).expect("conversation");
        let orphan = message(&conversation.conversation, &owner.principal.principal_id, "aggregate-gap");
        store.persist_message(&orphan).expect("message");
        assert_eq!(store.group_message(&owner, &scope(), &orphan.message_id), Ok(None));
        assert_eq!(store.group_message(&owner, &scope(), &MessageId::from_opaque(oid("aggregate-gap-unknown"))), Ok(None));
    }

    #[test]
    fn duplicate_group_change_is_bound_to_original_actor() {
        let store = MemoryLocalStore::default();
        let owner = subject("duplicate-owner", PrincipalKind::Person);
        let intruder = subject("duplicate-intruder", PrincipalKind::Person);
        let (conversation, group) = group_fixture("duplicate-actor", &owner);
        store.create_group(&conversation, &group, &owner).expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("duplicate-actor-event")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: subject("duplicate-member", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Duplicate));
        assert_eq!(store.apply_group_change(&intruder, &change), Err(DurableStoreError::PermissionDenied));
    }

    #[test]
    fn same_opaque_id_different_principal_kinds_are_distinct_memberships() {
        let store = MemoryLocalStore::default();
        let owner = subject("dual-kind", PrincipalKind::Person);
        let alias = subject("dual-kind", PrincipalKind::Organization);
        let (conversation, group) = group_fixture("dual-kind", &owner);
        store.create_group(&conversation, &group, &owner).expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("dual-kind-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: alias.principal.clone(), role: GroupRole::Member },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Persisted));
        assert!(store.group_membership(&scope(), &group.group_id, &owner.principal).expect("owner lookup").is_some());
        assert!(store.group_membership(&scope(), &group.group_id, &alias.principal).expect("alias lookup").is_some());
        assert_eq!(store.group_memberships(&scope(), &group.group_id, 8).expect("members").len(), 2);
    }
'''
    pos = text.rfind("\n}")
    if pos < 0:
        raise SystemExit("memory test module end missing")
    text = text[:pos] + insert + text[pos:]
mem.write_text(text)

# SQLite v21 is not released yet, so strengthen its Phase-18 schema in place: membership identity
# includes kind, and change idempotency stores the authenticated actor.
sql = Path("crates/ucr-storage-sqlite/src/group_store.rs")
text = sql.read_text()
text = replace_once(
    text,
    "    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, principal_id),",
    "    PRIMARY KEY(tenant_id, namespace_present, namespace_id, group_id, principal_id, principal_kind),",
    "sqlite membership full identity pk",
)
text = replace_once(
    text,
    """    event_id TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
""",
    """    event_id TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    actor_principal_kind TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
""",
    "sqlite group change actor columns",
)
text = replace_once(
    text,
    '            ("principal_kind", "TEXT", 1, 0),',
    '            ("principal_kind", "TEXT", 1, 6),',
    "sqlite membership kind pk verification",
)
text = replace_once(
    text,
    """            ("group_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 4),
            ("fingerprint", "BLOB", 1, 0),
""",
    """            ("group_id", "TEXT", 1, 0),
            ("event_id", "TEXT", 1, 4),
            ("actor_principal_id", "TEXT", 1, 0),
            ("actor_principal_kind", "TEXT", 1, 0),
            ("fingerprint", "BLOB", 1, 0),
""",
    "sqlite change actor schema verification",
)
text = replace_once(
    text,
    """        let (group, creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
""",
    """        let (group, mut creator_membership) =
            canonical_group_creation(group, &creator.scope, &creator.principal)
                .map_err(map_group_error)?;
""",
    "sqlite mutable creator membership",
)
text = replace_once(
    text,
    """            return if existing == group && existing_creator == Some(creator_membership) {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
""",
    """            let duplicate = existing_creator.is_some_and(|persisted| {
                let mut expected = creator_membership.clone();
                expected.history_floor_logical_order = persisted.history_floor_logical_order;
                existing == group && persisted == expected
            });
            return if duplicate {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
""",
    "sqlite idempotent create with durable floor",
)
text = replace_once(
    text,
    """            Some(existing) if existing != *conversation => return Err(DurableStoreError::Conflict),
            Some(_) => {}
            None => insert_group_conversation(&transaction, conversation)?,
        }
        insert_group(&transaction, &group)?;
""",
    """            Some(existing) if existing != *conversation => return Err(DurableStoreError::Conflict),
            Some(_) => {}
            None => insert_group_conversation(&transaction, conversation)?,
        }
        creator_membership.history_floor_logical_order = history_floor_for_add(&transaction, &group)?;
        insert_group(&transaction, &group)?;
""",
    "sqlite creator history floor",
)
text = replace_once(
    text,
    """    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let mut connection = self.lock_connection()?;
""",
    """    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if actor.scope != change.scope {
            return Err(DurableStoreError::PermissionDenied);
        }
        let fingerprint = group_change_fingerprint(change).map_err(map_group_error)?;
        let mut connection = self.lock_connection()?;
""",
    "sqlite duplicate scope authorization",
)
text = replace_once(
    text,
    """        if let Some(existing) = load_change_fingerprint(
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
""",
    """        if let Some((recorded_actor, existing)) = load_change_record(
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
""",
    "sqlite duplicate actor binding",
)
text = replace_once(
    text,
    "        insert_change_fingerprint(&transaction, change, &fingerprint)?;",
    "        insert_change_fingerprint(&transaction, actor, change, &fingerprint)?;",
    "sqlite persist change actor call",
)
text = replace_once(
    text,
    """        let group = load_group_for_conversation_from(
            &transaction,
            scope,
            &message.conversation.conversation_id,
        )?
        .ok_or(DurableStoreError::Corrupt)?;
""",
    """        let Some(group) = load_group_for_conversation_from(
            &transaction,
            scope,
            &message.conversation.conversation_id,
        )?
        else {
            return Ok(None);
        };
""",
    "sqlite missing aggregate non-oracle",
)
text = replace_once(
    text,
    '"SELECT principal_kind, role, state, joined_revision, removed_revision, history_floor_logical_order FROM group_memberships WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 AND principal_id=?5",\n        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group_id.as_opaque().as_str(), member.principal_id.as_opaque().as_str()],',
    '"SELECT principal_kind, role, state, joined_revision, removed_revision, history_floor_logical_order FROM group_memberships WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND group_id=?4 AND principal_id=?5 AND principal_kind=?6",\n        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group_id.as_opaque().as_str(), member.principal_id.as_opaque().as_str(), principal_kind_name(member.kind)],',
    "sqlite exact membership lookup kind",
)
text = replace_once(
    text,
    'ORDER BY principal_id LIMIT ?5"',
    'ORDER BY principal_id, principal_kind LIMIT ?5"',
    "sqlite deterministic membership order",
)
text = replace_once(
    text,
    """fn load_change_fingerprint(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<Option<[u8; 32]>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let value = connection.query_row(
        "SELECT fingerprint FROM group_changes WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4",
        params![scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, event_id],
        |row| row.get::<_,Vec<u8>>(0),
    ).optional().map_err(|error| map_sqlite_error(&error))?;
    value
        .map(|bytes| bytes.try_into().map_err(|_| DurableStoreError::Corrupt))
        .transpose()
}
""",
    """fn load_change_record(
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
""",
    "sqlite load change actor record",
)
text = replace_once(
    text,
    """fn insert_change_fingerprint(
    transaction: &Transaction<'_>,
    change: &GroupChange,
    fingerprint: &[u8; 32],
) -> Result<(), DurableStoreError> {
""",
    """fn insert_change_fingerprint(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    change: &GroupChange,
    fingerprint: &[u8; 32],
) -> Result<(), DurableStoreError> {
""",
    "sqlite insert change actor signature",
)
text = replace_once(
    text,
    '"INSERT INTO group_changes VALUES (?1,?2,?3,?4,?5,?6)",',
    '"INSERT INTO group_changes VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",',
    "sqlite insert change actor sql",
)
text = replace_once(
    text,
    """                change.group_id.as_opaque().as_str(),
                change.event_id.as_opaque().as_str(),
                fingerprint.as_slice()
""",
    """                change.group_id.as_opaque().as_str(),
                change.event_id.as_opaque().as_str(),
                actor.principal.principal_id.as_opaque().as_str(),
                principal_kind_name(actor.principal.kind),
                fingerprint.as_slice()
""",
    "sqlite insert change actor params",
)
text = text.replace(
    "    use ucr_core::{DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore};",
    "    use ucr_core::{ConversationStore, DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore, MessageStore};",
    1,
)
if "sqlite_creator_history_floor_is_derived_from_preexisting_transcript" not in text:
    marker = "\n}\n\n#[cfg(test)]\nmod phase18_event_identity_security_tests"
    extra = r'''

    #[test]
    fn sqlite_creator_history_floor_is_derived_from_preexisting_transcript() {
        let db = TestDb::new();
        let (conversation, mut group, owner) = group_fixture();
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        let store = SqliteLocalStore::open(db.path()).expect("open");
        assert_eq!(store.persist_conversation(&conversation), Ok(DurableRecordStatus::Persisted));
        let mut first = member_message(&conversation.conversation, &owner.principal, "pre-first");
        first.logical_order = 4;
        let mut last = member_message(&conversation.conversation, &owner.principal, "pre-last");
        last.logical_order = 5;
        assert_eq!(store.persist_message(&first), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.persist_message(&last), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.create_group(&conversation, &group, &owner), Ok(DurableRecordStatus::Persisted));
        let membership = store.group_membership(&scope(), &group.group_id, &owner.principal)
            .expect("membership read").expect("creator membership");
        assert_eq!(membership.history_floor_logical_order, 5);
        assert_eq!(store.group_message(&owner, &scope(), &first.message_id), Ok(None));
        assert!(store.group_message(&owner, &scope(), &last.message_id).expect("last read").is_some());
        assert_eq!(store.create_group(&conversation, &group, &owner), Ok(DurableRecordStatus::Duplicate));
    }

    #[test]
    fn sqlite_group_message_without_group_aggregate_is_non_oracular() {
        let db = TestDb::new();
        let (conversation, _, owner) = group_fixture();
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store.persist_conversation(&conversation).expect("conversation");
        let orphan = member_message(&conversation.conversation, &owner.principal, "aggregate-gap");
        store.persist_message(&orphan).expect("message");
        assert_eq!(store.group_message(&owner, &scope(), &orphan.message_id), Ok(None));
        assert_eq!(store.group_message(&owner, &scope(), &MessageId::from_opaque(oid("sqlite-aggregate-gap-unknown"))), Ok(None));
    }

    #[test]
    fn sqlite_duplicate_group_change_is_bound_to_original_actor() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let intruder = subject("duplicate-intruder");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store.create_group(&conversation, &group, &owner).expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-duplicate-actor-event")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: subject("duplicate-member").principal, role: GroupRole::Member },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Duplicate));
        assert_eq!(store.apply_group_change(&intruder, &change), Err(DurableStoreError::PermissionDenied));
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
        store.create_group(&conversation, &group, &owner).expect("group");
        let change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-dual-kind-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: alias.principal.clone(), role: GroupRole::Member },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&owner, &change), Ok(DurableRecordStatus::Persisted));
        assert!(store.group_membership(&scope(), &group.group_id, &owner.principal).expect("owner lookup").is_some());
        assert!(store.group_membership(&scope(), &group.group_id, &alias.principal).expect("alias lookup").is_some());
        assert_eq!(store.group_memberships(&scope(), &group.group_id, 8).expect("members").len(), 2);
    }
'''
    if marker not in text:
        raise SystemExit("sqlite restart module end marker missing")
    text = text.replace(marker, extra + marker, 1)
sql.write_text(text)

# Release truth: document the two security-relevant invariants now enforced by the durable owners.
spec = Path("spec/groups.md")
text = spec.read_text()
if "Group-change duplicate recognition is actor-bound" not in text:
    text += "\n- Group-change duplicate recognition is actor-bound: an identical `EventId`/fingerprint replay is a duplicate only for the exact original `PrincipalRef`; another principal is denied.\n- Group membership identity is the complete `PrincipalRef` (`principal_id` plus `PrincipalKind`), including durable tombstones and storage keys.\n- When a Group aggregate is attached to an already-existing group-kind Conversation, the creator history floor is derived atomically from the canonical pre-existing Message transcript using the same history-policy logic as later joins.\n- A group-kind Message whose Conversation has no Group aggregate is non-disclosing through Group reads and returns absence rather than a corruption/existence oracle.\n"
spec.write_text(text)

adr = Path("docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md")
text = adr.read_text()
if "Duplicate Group mutations are bound to the exact original PrincipalRef" not in text:
    text += "\nDuplicate Group mutations are bound to the exact original PrincipalRef in the durable idempotency reservation. Membership keys use the full PrincipalRef rather than only the opaque ID. Group creation over a pre-existing group-kind Conversation derives the creator history floor from the canonical Message transcript inside the same storage transaction/critical section, and Group reads return non-disclosing absence when a migrated group-kind Conversation has no inferred Group aggregate.\n"
adr.write_text(text)
