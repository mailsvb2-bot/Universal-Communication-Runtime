from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"missing marker: {label}")
    path.write_text(text.replace(old, new, 1))


mem = Path("crates/ucr-storage-memory/src/group_store.rs")
replace_once(
    mem,
    '''        let membership = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .filter(|membership| membership.member == subject.principal)
            .ok_or(DurableStoreError::PermissionDenied)?;
        if membership.state != GroupMemberState::Active''',
    '''        let Some(membership) = state
            .group_memberships
            .get(&membership_key(scope, &group.group_id, &subject.principal))
            .filter(|membership| membership.member == subject.principal)
        else {
            return Ok(None);
        };
        if membership.state != GroupMemberState::Active''',
    "memory non-oracular membership read",
)
replace_once(
    mem,
    '''        GroupHistoryPolicy::LastNMessages(count) => {
            let count = usize::try_from(*count).map_err(|_| DurableStoreError::InvalidRecord)?;
            Ok(if orders.len() <= count {
                0
            } else {
                orders[orders.len() - count]
            })
        }''',
    '''        GroupHistoryPolicy::LastNMessages(count) => {
            let count = usize::try_from(*count).map_err(|_| DurableStoreError::InvalidRecord)?;
            if orders.len() <= count {
                return Ok(0);
            }
            let cutoff = orders[orders.len() - count];
            let visible_at_or_above = orders.iter().filter(|order| **order >= cutoff).count();
            if visible_at_or_above > count {
                cutoff
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidRecord)
            } else {
                Ok(cutoff)
            }
        }''',
    "memory LastN tied cutoff fail closed",
)
replace_once(
    mem,
    '''        GroupHistoryPolicy::FromTimestamp(timestamp) => message.created_at_unix_ms >= timestamp,
        GroupHistoryPolicy::CustomPolicy(_) => false,''',
    '''        GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false,''',
    "memory untrusted timestamp fail closed",
)
replace_once(
    mem,
    '''        assert_eq!(
            store.group_message(&alias, &scope(), &original.message_id),
            Err(DurableStoreError::PermissionDenied)
        );''',
    '''        assert_eq!(
            store.group_message(&alias, &scope(), &original.message_id),
            Ok(None)
        );
        assert_eq!(
            store.group_message(
                &alias,
                &scope(),
                &MessageId::from_opaque(oid("memory-message-unknown"))
            ),
            Ok(None)
        );''',
    "memory alias read is non-oracular",
)

mem_text = mem.read_text()
mem_marker = '''        assert_eq!(
            store.apply_group_change(&owner, &event_first_change),
            Err(DurableStoreError::Conflict)
        );
    }
}'''
mem_tests = '''        assert_eq!(
            store.apply_group_change(&owner, &event_first_change),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn from_timestamp_history_fails_closed_on_untrusted_message_time() {
        let store = MemoryLocalStore::default();
        let owner = subject("timestamp-owner", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("timestamp", &owner);
        group.history_policy = GroupHistoryPolicy::FromTimestamp(1);
        store.create_group(&conversation, &group, &owner).expect("group");
        let mut forged = message(&conversation.conversation, &owner.principal.principal_id, "timestamp");
        forged.created_at_unix_ms = i64::MAX;
        forged.logical_order = 7;
        store.persist_group_message(&owner, &forged).expect("persist");
        assert_eq!(store.group_message(&owner, &scope(), &forged.message_id), Ok(None));
    }

    #[test]
    fn last_n_tied_cutoff_never_over_discloses_and_future_order_remains_visible() {
        let store = MemoryLocalStore::default();
        let owner = subject("lastn-owner", PrincipalKind::Person);
        let member = subject("lastn-member", PrincipalKind::Person);
        let (conversation, mut group) = group_fixture("lastn", &owner);
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        store.create_group(&conversation, &group, &owner).expect("group");
        let mut first = message(&conversation.conversation, &owner.principal.principal_id, "tie-a");
        first.logical_order = 7;
        let mut second = message(&conversation.conversation, &owner.principal.principal_id, "tie-b");
        second.logical_order = 7;
        store.persist_group_message(&owner, &first).expect("first");
        store.persist_group_message(&owner, &second).expect("second");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("lastn-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: member.principal.clone(), role: GroupRole::Member },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add).expect("add member");
        assert_eq!(store.group_message(&member, &scope(), &first.message_id), Ok(None));
        assert_eq!(store.group_message(&member, &scope(), &second.message_id), Ok(None));
        let mut future = message(&conversation.conversation, &owner.principal.principal_id, "future");
        future.logical_order = 8;
        store.persist_group_message(&owner, &future).expect("future");
        assert!(store.group_message(&member, &scope(), &future.message_id).expect("read").is_some());
    }
}'''
if "last_n_tied_cutoff_never_over_discloses_and_future_order_remains_visible" not in mem_text:
    if mem_marker not in mem_text:
        raise SystemExit("memory security test tail missing")
    mem.write_text(mem_text.replace(mem_marker, mem_tests, 1))

sql = Path("crates/ucr-storage-sqlite/src/group_store.rs")
replace_once(
    sql,
    '''    if stored_kind != member.kind {
        return Err(DurableStoreError::PermissionDenied);
    }''',
    '''    if stored_kind != member.kind {
        return Ok(None);
    }''',
    "sqlite non-oracular principal kind mismatch",
)
replace_once(
    sql,
    '''        let membership =
            load_membership_from(&transaction, scope, &group.group_id, &subject.principal)?
                .ok_or(DurableStoreError::PermissionDenied)?;
        if membership.state != GroupMemberState::Active''',
    '''        let Some(membership) =
            load_membership_from(&transaction, scope, &group.group_id, &subject.principal)?
        else {
            return Ok(None);
        };
        if membership.state != GroupMemberState::Active''',
    "sqlite non-oracular group message read",
)
replace_once(
    sql,
    '''        GroupHistoryPolicy::LastNMessages(count) => {
            let offset = i64::from(count.saturating_sub(1));
            let floor = connection.query_row(
                "SELECT logical_order FROM messages WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4 ORDER BY logical_order DESC LIMIT 1 OFFSET ?5",
                params![group.scope.tenant_id.as_opaque().as_str(), namespace.present, namespace.value, group.conversation.conversation_id.as_opaque().as_str(), offset],
                |row| row.get::<_,Vec<u8>>(0),
            ).optional().map_err(|error| map_sqlite_error(&error))?;
            floor.map_or(Ok(0), |bytes| decode_u64(&bytes))
        }''',
    '''        GroupHistoryPolicy::LastNMessages(count) => {
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
                cutoff.checked_add(1).ok_or(DurableStoreError::InvalidRecord)
            } else {
                Ok(cutoff)
            }
        }''',
    "sqlite LastN tied cutoff fail closed",
)
replace_once(
    sql,
    '''        GroupHistoryPolicy::FromTimestamp(timestamp) => message.created_at_unix_ms >= timestamp,
        GroupHistoryPolicy::CustomPolicy(_) => false,''',
    '''        GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false,''',
    "sqlite untrusted timestamp fail closed",
)

sql_text = sql.read_text()
sql_marker = '''        assert_eq!(
            reopened
                .group(&scope(), &group.group_id)
                .expect("load final group")
                .expect("final group exists")
                .revision,
            2
        );
    }
}

#[cfg(test)]
mod phase18_event_identity_security_tests'''
sql_tests = '''        assert_eq!(
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
        store.create_group(&conversation, &group, &owner).expect("group");
        store.persist_group_message(&owner, &original).expect("message");
        let alias = ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: owner.principal.principal_id.clone(),
                kind: PrincipalKind::Organization,
            },
        };
        assert_eq!(store.group_message(&alias, &scope(), &original.message_id), Ok(None));
        assert_eq!(
            store.group_message(&alias, &scope(), &MessageId::from_opaque(oid("sqlite-unknown-message"))),
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
        store.create_group(&conversation, &group, &owner).expect("group");
        store.persist_group_message(&owner, &forged).expect("message");
        assert_eq!(store.group_message(&owner, &scope(), &forged.message_id), Ok(None));
    }

    #[test]
    fn last_n_tied_cutoff_never_over_discloses_and_future_order_remains_visible() {
        let db = TestDb::new();
        let (conversation, mut group, owner) = group_fixture();
        group.history_policy = GroupHistoryPolicy::LastNMessages(1);
        let member = subject("lastn-member");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store.create_group(&conversation, &group, &owner).expect("group");
        let mut first = member_message(&conversation.conversation, &owner.principal, "tie-a");
        first.logical_order = 7;
        let mut second = member_message(&conversation.conversation, &owner.principal, "tie-b");
        second.logical_order = 7;
        store.persist_group_message(&owner, &first).expect("first");
        store.persist_group_message(&owner, &second).expect("second");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-lastn-add")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: member.principal.clone(), role: GroupRole::Member },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add).expect("add member");
        assert_eq!(store.group_message(&member, &scope(), &first.message_id), Ok(None));
        assert_eq!(store.group_message(&member, &scope(), &second.message_id), Ok(None));
        let mut future = member_message(&conversation.conversation, &owner.principal, "future");
        future.logical_order = 8;
        store.persist_group_message(&owner, &future).expect("future");
        assert!(store.group_message(&member, &scope(), &future.message_id).expect("read").is_some());
    }
}

#[cfg(test)]
mod phase18_event_identity_security_tests'''
if "private_group_message_read_is_non_oracular_for_kind_alias" not in sql_text:
    if sql_marker not in sql_text:
        raise SystemExit("sqlite restart security test tail missing")
    sql.write_text(sql_text.replace(sql_marker, sql_tests, 1))

spec = Path("spec/groups.md")
text = spec.read_text()
old = "History reads require active membership plus `ReadHistory`. `NoHistory`, `FromJoin`, `LastNMessages`, `FromTimestamp`, `FullHistory`, and opaque `CustomPolicy` are represented explicitly. The reference implementation fails closed for unsupported custom history behavior rather than guessing policy semantics."
new = "History reads require active membership plus `ReadHistory`. `NoHistory`, `FromJoin`, `LastNMessages`, `FromTimestamp`, `FullHistory`, and opaque `CustomPolicy` are represented explicitly. The Prepared reference implementation does not trust `MessageEnvelope.created_at_unix_ms` as a security clock, so `FromTimestamp` fails closed until a trusted timestamp/order source exists. `LastNMessages` uses the durable logical-order floor when it is unambiguous; if the Nth cutoff is tied on `logical_order`, the reference store advances the floor past the tied order and may expose fewer than N historical messages rather than over-disclose without a durable `(logical_order, MessageId)` boundary. Unsupported custom history behavior also fails closed."
if old not in text and new not in text:
    raise SystemExit("groups history paragraph missing")
if old in text:
    spec.write_text(text.replace(old, new, 1))

adr = Path("docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md")
text = adr.read_text()
marker = "- Unsupported custom history/crypto behavior fails closed."
replacement = "- Unsupported custom history/crypto behavior fails closed.\n- `FromTimestamp` never trusts caller-supplied message display time as authorization evidence; the Prepared store fails closed until trusted time/order evidence exists.\n- `LastNMessages` never over-discloses across a tied logical-order cutoff; without a durable MessageId tie boundary it advances past the ambiguous order and may return fewer historical messages."
if marker not in text and replacement not in text:
    raise SystemExit("ADR security marker missing")
if marker in text:
    adr.write_text(text.replace(marker, replacement, 1))

arch = Path("crates/ucr-architecture-tests/tests/phase18_groups.rs")
text = arch.read_text()
needle = '''    assert!(spec.contains("Removed members remain tombstones"));
    assert!(spec.contains("existing `MessageStore`"));'''
replacement = '''    assert!(spec.contains("Removed members remain tombstones"));
    assert!(spec.contains("existing `MessageStore`"));
    assert!(spec.contains("does not trust `MessageEnvelope.created_at_unix_ms` as a security clock"));
    assert!(spec.contains("may expose fewer than N historical messages rather than over-disclose"));
    assert!(memory.contains("GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false"));
    assert!(sqlite.contains("GroupHistoryPolicy::FromTimestamp(_) | GroupHistoryPolicy::CustomPolicy(_) => false"));'''
if needle not in text and replacement not in text:
    raise SystemExit("phase18 architecture history marker missing")
if needle in text:
    arch.write_text(text.replace(needle, replacement, 1))
