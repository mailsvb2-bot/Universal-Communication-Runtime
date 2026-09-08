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
