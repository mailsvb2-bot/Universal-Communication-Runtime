from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise SystemExit(f"missing marker: {label}")
    return text.replace(old, new, 1)

protocol = Path("crates/ucr-protocol/src/group.rs")
text = protocol.read_text()
marker = '''/// Applies one optimistic-concurrency Group mutation through the canonical transition owner.
'''
helper = '''/// Returns the current active role for one exact Group actor.
///
/// This is intentionally narrower than change authorization: idempotent retries may remain valid
/// after the original transition changed the actor's role (for example ownership transfer), but a
/// removed actor must not receive duplicate/conflict existence evidence.
///
/// # Errors
/// Returns an explicit Group error for invalid aggregate/membership state, cross-scope actors, or
/// an actor without an active exact-PrincipalRef membership.
pub fn active_group_actor_role(
    group: &GroupRecord,
    memberships: &[GroupMembership],
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
) -> Result<GroupRole, GroupError> {
    let group = canonical_group_record(group)?;
    let memberships = canonical_group_memberships(&group, memberships)?;
    if actor_scope != &group.scope {
        return Err(GroupError::ScopeMismatch);
    }
    let actor_index =
        active_member_index(&memberships, actor).ok_or(GroupError::PermissionDenied)?;
    Ok(memberships[actor_index].role)
}

'''
if "pub fn active_group_actor_role(" not in text:
    if marker not in text:
        raise SystemExit("protocol helper marker missing")
    text = text.replace(marker, helper + marker, 1)
protocol.write_text(text)

protocol_lib = Path("crates/ucr-protocol/src/lib.rs")
text = protocol_lib.read_text()
text = replace_once(
    text,
    "    MAX_GROUP_MEMBER_LIST, MAX_GROUP_MEMBERS, apply_group_change, canonical_group_creation,\n",
    "    MAX_GROUP_MEMBER_LIST, MAX_GROUP_MEMBERS, active_group_actor_role, apply_group_change, canonical_group_creation,\n",
    "protocol export active actor role",
)
protocol_lib.write_text(text)

mem = Path("crates/ucr-storage-memory/src/group_store.rs")
text = mem.read_text()
text = replace_once(
    text,
    """    apply_group_change, canonical_group_creation, canonical_group_memberships, canonical_message,
    group_change_fingerprint, is_group_conversation_kind, validate_conversation,
""",
    """    active_group_actor_role, apply_group_change, canonical_group_creation,
    canonical_group_memberships, canonical_message, group_change_fingerprint,
    is_group_conversation_kind, validate_conversation,
""",
    "memory import active role",
)
old = '''        let change_key = change_key(&change.scope, change.event_id.as_opaque().as_str());
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some((recorded_actor, existing)) = state.group_changes.get(&change_key) {
            if recorded_actor != &actor.principal {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.events.contains_key(&change_key) {
            return Err(DurableStoreError::Conflict);
        }
        let group = state
            .groups
            .get(&group_key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        let memberships = state
            .group_memberships
            .values()
            .filter(|membership| {
                membership.scope == change.scope && membership.group_id == change.group_id
            })
            .cloned()
            .collect::<Vec<_>>();
        let history_floor = if matches!(change.kind, ucr_model::GroupChangeKind::AddMember { .. }) {
            Some(history_floor_for_add(&state, &group)?)
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
'''
new = '''        let change_key = change_key(&change.scope, change.event_id.as_opaque().as_str());
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let group = state
            .groups
            .get(&group_key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        let memberships = state
            .group_memberships
            .values()
            .filter(|membership| {
                membership.scope == change.scope && membership.group_id == change.group_id
            })
            .cloned()
            .collect::<Vec<_>>();
        active_group_actor_role(&group, &memberships, &actor.scope, &actor.principal)
            .map_err(map_group_error)?;
        if let Some((recorded_actor, existing)) = state.group_changes.get(&change_key) {
            if recorded_actor != &actor.principal {
                return Err(DurableStoreError::PermissionDenied);
            }
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let history_floor = if matches!(change.kind, ucr_model::GroupChangeKind::AddMember { .. }) {
            Some(history_floor_for_add(&state, &group)?)
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
        if state.events.contains_key(&change_key) {
            return Err(DurableStoreError::Conflict);
        }
'''
text = replace_once(text, old, new, "memory authorize before duplicate and collision")
if "removed_original_actor_cannot_replay_duplicate_group_change" not in text:
    insert = r'''

    #[test]
    fn removed_original_actor_cannot_replay_duplicate_group_change() {
        let store = MemoryLocalStore::default();
        let owner = subject("removed-dup-owner", PrincipalKind::Person);
        let admin = subject("removed-dup-admin", PrincipalKind::Person);
        let (conversation, group) = group_fixture("removed-dup", &owner);
        store.create_group(&conversation, &group, &owner).expect("group");
        let add_admin = GroupChange {
            event_id: EventId::from_opaque(oid("removed-dup-add-admin")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: admin.principal.clone(), role: GroupRole::Admin },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add_admin).expect("add admin");
        let admin_change = GroupChange {
            event_id: EventId::from_opaque(oid("removed-dup-admin-change")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 1,
            kind: GroupChangeKind::AddMember {
                member: subject("removed-dup-member", PrincipalKind::Person).principal,
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&admin, &admin_change), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.apply_group_change(&admin, &admin_change), Ok(DurableRecordStatus::Duplicate));
        let remove_admin = GroupChange {
            event_id: EventId::from_opaque(oid("removed-dup-remove-admin")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 2,
            kind: GroupChangeKind::RemoveMember { member: admin.principal.clone() },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &remove_admin).expect("remove admin");
        assert_eq!(store.apply_group_change(&admin, &admin_change), Err(DurableStoreError::PermissionDenied));
    }
'''
    pos = text.rfind("\n}")
    if pos < 0:
        raise SystemExit("memory module end missing")
    text = text[:pos] + insert + text[pos:]
mem.write_text(text)

sql = Path("crates/ucr-storage-sqlite/src/group_store.rs")
text = sql.read_text()
text = replace_once(
    text,
    """    MAX_EXTERNAL_GROUP_ID_LEN, apply_group_change, canonical_group_creation,
    canonical_group_memberships, canonical_group_record, canonical_message,
""",
    """    MAX_EXTERNAL_GROUP_ID_LEN, active_group_actor_role, apply_group_change,
    canonical_group_creation, canonical_group_memberships, canonical_group_record, canonical_message,
""",
    "sqlite import active role",
)
old = '''        if let Some((recorded_actor, existing)) = load_change_record(
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
        if super::event_journal::load_event_by_id(&transaction, &change.scope, &change.event_id)?
            .is_some()
        {
            return Err(DurableStoreError::Conflict);
        }
        let group = load_group_from(&transaction, &change.scope, &change.group_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        let memberships = load_memberships_from(&transaction, &group, usize::MAX)?;
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
'''
new = '''        let group = load_group_from(&transaction, &change.scope, &change.group_id)?
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
'''
text = replace_once(text, old, new, "sqlite authorize before duplicate and collision")
if "sqlite_removed_original_actor_cannot_replay_duplicate_group_change" not in text:
    marker = "\n}\n\n#[cfg(test)]\nmod phase18_event_identity_security_tests"
    insert = r'''

    #[test]
    fn sqlite_removed_original_actor_cannot_replay_duplicate_group_change() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let admin = subject("sqlite-removed-dup-admin");
        let store = SqliteLocalStore::open(db.path()).expect("open");
        store.create_group(&conversation, &group, &owner).expect("group");
        let add_admin = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-add-admin")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 0,
            kind: GroupChangeKind::AddMember { member: admin.principal.clone(), role: GroupRole::Admin },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &add_admin).expect("add admin");
        let admin_change = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-admin-change")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 1,
            kind: GroupChangeKind::AddMember { member: subject("sqlite-removed-dup-member").principal, role: GroupRole::Member },
            next_crypto_state: None,
        };
        assert_eq!(store.apply_group_change(&admin, &admin_change), Ok(DurableRecordStatus::Persisted));
        assert_eq!(store.apply_group_change(&admin, &admin_change), Ok(DurableRecordStatus::Duplicate));
        let remove_admin = GroupChange {
            event_id: EventId::from_opaque(oid("sqlite-removed-dup-remove-admin")), scope: scope(),
            group_id: group.group_id.clone(), expected_revision: 2,
            kind: GroupChangeKind::RemoveMember { member: admin.principal.clone() },
            next_crypto_state: None,
        };
        store.apply_group_change(&owner, &remove_admin).expect("remove admin");
        assert_eq!(store.apply_group_change(&admin, &admin_change), Err(DurableStoreError::PermissionDenied));
    }
'''
    if marker not in text:
        raise SystemExit("sqlite test insertion marker missing")
    text = text.replace(marker, insert + marker, 1)
sql.write_text(text)

core = Path("crates/ucr-core/src/group.rs")
text = core.read_text()
text = text.replace(
    "The authenticated actor is supplied by the Core authorization façade and must be checked\n    /// against the durable active membership/role inside the same atomic storage action.",
    "The authenticated actor is supplied by the Core authorization façade and must be checked\n    /// against durable active membership inside the same atomic storage action before duplicate/conflict\n    /// evidence is returned; new transitions additionally enforce the canonical current-role rules. An\n    /// idempotent retry by the original still-active actor remains valid when the original transition itself\n    /// changed that actor's role.",
    1,
)
core.write_text(text)

adr = Path("docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md")
text = adr.read_text()
if "Duplicate/conflict recognition is preceded by a durable active-membership check" not in text:
    text += "\nDuplicate/conflict recognition is preceded by a durable active-membership check for the exact actor. The idempotency record remains bound to the original `PrincipalRef`; this denies removed actors and unrelated principals without breaking legitimate retries when the committed transition itself changed the original actor's role (for example ownership transfer). New transitions still pass the canonical current-role authorization before EventId collision evidence is returned.\n"
adr.write_text(text)
