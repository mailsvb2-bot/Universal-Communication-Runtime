from pathlib import Path


def once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"marker missing in {path}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))

# Sibling Group store reuses the one canonical Conversation/Message SQLite implementation.
p = Path("crates/ucr-storage-sqlite/src/message_store.rs")
text = p.read_text()
for name in ["load_conversation_from", "load_message_from", "insert_message_row", "insert_message_children"]:
    text = text.replace(f"fn {name}(", f"pub(super) fn {name}(", 1)
p.write_text(text)

lib = "crates/ucr-storage-sqlite/src/lib.rs"
once(lib, "mod event_subscription_store;\n", "mod event_subscription_store;\nmod group_store;\n")
once(
    lib,
    "const SQLITE_SCHEMA_V19: u32 = 19;\npub const SQLITE_SCHEMA_VERSION: u32 = 20;",
    "const SQLITE_SCHEMA_V19: u32 = 19;\nconst SQLITE_SCHEMA_V20: u32 = 20;\npub const SQLITE_SCHEMA_VERSION: u32 = 21;",
)
once(lib, "return initialize_schema_v20(connection);", "return initialize_schema_v21(connection);")
once(
    lib,
    "if version == SQLITE_SCHEMA_VERSION {\n        return event_subscription_store::verify_schema_v20(connection);\n    }",
    "if version == SQLITE_SCHEMA_VERSION {\n        return group_store::verify_schema_v21(connection);\n    }",
)
once(
    lib,
    "            SQLITE_SCHEMA_V19 => migrate_v19_to_v20(connection)?,\n            _ => return Err(DurableStoreError::UnsupportedSchemaVersion),",
    "            SQLITE_SCHEMA_V19 => migrate_v19_to_v20(connection)?,\n            SQLITE_SCHEMA_V20 => migrate_v20_to_v21(connection)?,\n            _ => return Err(DurableStoreError::UnsupportedSchemaVersion),",
)
once(
    lib,
    "    event_subscription_store::verify_schema_v20(connection)\n}\n\nfn initialize_schema_v20",
    "    group_store::verify_schema_v21(connection)\n}\n\nfn initialize_schema_v21",
)
once(
    lib,
    "    event_subscription_store::create_v20_objects(&transaction)?;\n    transaction\n        .pragma_update(None, \"application_id\", UCR_SQLITE_APPLICATION_ID)",
    "    event_subscription_store::create_v20_objects(&transaction)?;\n    group_store::create_v21_objects(&transaction)?;\n    transaction\n        .pragma_update(None, \"application_id\", UCR_SQLITE_APPLICATION_ID)",
)
once(
    lib,
    "    transaction\n        .pragma_update(None, \"user_version\", SQLITE_SCHEMA_VERSION)\n        .map_err(|error| map_sqlite_error(&error))?;\n    transaction\n        .commit()\n        .map_err(|error| map_sqlite_error(&error))?;\n    event_subscription_store::verify_schema_v20(connection)\n}\n\nfn verify_schema_v2",
    "    transaction\n        .pragma_update(None, \"user_version\", SQLITE_SCHEMA_V20)\n        .map_err(|error| map_sqlite_error(&error))?;\n    transaction\n        .commit()\n        .map_err(|error| map_sqlite_error(&error))?;\n    event_subscription_store::verify_schema_v20(connection)\n}\n\nfn migrate_v20_to_v21(connection: &mut Connection) -> Result<(), DurableStoreError> {\n    event_subscription_store::verify_schema_v20(connection)?;\n    let transaction = connection\n        .transaction_with_behavior(TransactionBehavior::Immediate)\n        .map_err(|error| map_sqlite_error(&error))?;\n    group_store::create_v21_objects(&transaction)?;\n    transaction\n        .pragma_update(None, \"user_version\", SQLITE_SCHEMA_VERSION)\n        .map_err(|error| map_sqlite_error(&error))?;\n    transaction\n        .commit()\n        .map_err(|error| map_sqlite_error(&error))?;\n    group_store::verify_schema_v21(connection)\n}\n\nfn verify_schema_v2",
)

# Historical migration tests simulate old schemas by starting from the current schema and
# setting PRAGMA user_version back after dropping newer objects. Phase 18 adds four v21 tables;
# remove them immediately before every fixture version marker so every simulated schema is exact.
fixture_version_marker = 'PRAGMA user_version='
fixture_cleanup = (
    'DROP TABLE IF EXISTS group_changes; '
    'DROP TABLE IF EXISTS group_bridge_mappings; '
    'DROP TABLE IF EXISTS group_memberships; '
    'DROP TABLE IF EXISTS groups; '
)
patched_fixtures = 0
for fixture_path in Path("crates/ucr-storage-sqlite/src").glob("*.rs"):
    fixture_text = fixture_path.read_text()
    if fixture_version_marker not in fixture_text:
        continue
    count = fixture_text.count(fixture_version_marker)
    fixture_text = fixture_text.replace(
        fixture_version_marker,
        fixture_cleanup + fixture_version_marker,
    )
    fixture_path.write_text(fixture_text)
    patched_fixtures += count
if patched_fixtures < 18:
    raise SystemExit(f"expected at least 18 historical migration fixtures, patched {patched_fixtures}")

# Keep the SQLite decoder below strict Clippy's argument ceiling without suppressions.
p = Path("crates/ucr-storage-sqlite/src/group_store.rs")
text = p.read_text()
old_call_one = '''    decode_membership(&group, member.principal_id.clone(), stored_kind, &row.1, &row.2, &row.3, row.4.as_deref(), &row.5).map(Some)'''
new_call_one = '''    let fields = StoredMembershipFields { role: &row.1, state: &row.2, joined: &row.3, removed: row.4.as_deref(), floor: &row.5 };
    decode_membership(&group, member.principal_id.clone(), stored_kind, &fields).map(Some)'''
if old_call_one in text:
    text = text.replace(old_call_one, new_call_one, 1)
old_call_two = '''        result.push(decode_membership(group, PrincipalId::from_opaque(parse_id(&row.0)?), kind, &row.2, &row.3, &row.4, row.5.as_deref(), &row.6)?);'''
new_call_two = '''        let fields = StoredMembershipFields { role: &row.2, state: &row.3, joined: &row.4, removed: row.5.as_deref(), floor: &row.6 };
        result.push(decode_membership(group, PrincipalId::from_opaque(parse_id(&row.0)?), kind, &fields)?);'''
if old_call_two in text:
    text = text.replace(old_call_two, new_call_two, 1)
old_fn = '''fn decode_membership(group: &GroupRecord, principal_id: PrincipalId, kind: PrincipalKind, role: &str, state: &str, joined: &[u8], removed: Option<&[u8]>, floor: &[u8]) -> Result<GroupMembership, DurableStoreError> {
    let role = parse_role(role)?;
    let membership = GroupMembership {
        scope: group.scope.clone(), group_id: group.group_id.clone(),
        member: PrincipalRef { principal_id, kind }, role,
        permissions: group_permissions_for_role(role), state: parse_member_state(state)?,
        joined_revision: decode_u64(joined)?,
        removed_revision: removed.map(decode_u64).transpose()?,
        history_floor_logical_order: decode_u64(floor)?,
    };
    ucr_protocol::canonical_group_membership(group, &membership).map_err(map_group_error)
}
'''
new_fn = '''struct StoredMembershipFields<'a> {
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
        scope: group.scope.clone(), group_id: group.group_id.clone(),
        member: PrincipalRef { principal_id, kind }, role,
        permissions: group_permissions_for_role(role), state: parse_member_state(fields.state)?,
        joined_revision: decode_u64(fields.joined)?,
        removed_revision: fields.removed.map(decode_u64).transpose()?,
        history_floor_logical_order: decode_u64(fields.floor)?,
    };
    ucr_protocol::canonical_group_membership(group, &membership).map_err(map_group_error)
}
'''
if new_fn not in text:
    if old_fn not in text:
        raise SystemExit("decode_membership marker missing")
    text = text.replace(old_fn, new_fn, 1)

# Direct v20->v21 evidence: the migration creates an empty Group owner without inventing state.
if "fn v20_store_migrates_to_v21_without_inventing_groups" not in text:
    text += r'''

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
            .query_row("SELECT COUNT(*) FROM group_memberships", [], |row| row.get(0))
            .expect("count memberships");
        assert_eq!(groups, 0);
        assert_eq!(memberships, 0);
    }
}
'''
p.write_text(text)