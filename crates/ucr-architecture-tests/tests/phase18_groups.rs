use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase18_groups_reuse_canonical_owners_and_are_restart_safe() {
    let workspace = workspace();
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/group.rs")).expect("model");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/group.rs")).expect("core");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let protocol =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/group.rs")).expect("protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/group_store.rs"))
        .expect("memory group store");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/group_store.rs"))
        .expect("sqlite group store");
    let sqlite_root =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    let spec = fs::read_to_string(workspace.join("spec/groups.md")).expect("groups spec");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md",
    ))
    .expect("ADR 0056");

    assert!(model.contains("pub struct GroupRecord"));
    assert!(model.contains("pub struct GroupMembership"));
    assert!(model.contains("pub enum GroupChangeKind"));
    assert!(core.contains("pub trait GroupStore"));
    assert!(core.contains("pub trait GroupMessageStore: GroupStore + MessageStore"));
    assert!(runtime.contains("persist_group_message"));
    assert!(protocol.contains("group_change_fingerprint"));
    assert!(protocol.contains("WouldOrphanGroup"));
    assert!(memory.contains("persist_message_in_state"));
    assert!(sqlite.contains("insert_message_row"));
    assert!(sqlite.contains("insert_message_children"));
    assert!(sqlite.contains("group_changes"));
    assert!(sqlite.contains("group_memberships"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 21"));
    assert!(sqlite_root.contains("migrate_v20_to_v21"));
    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("Removed members remain tombstones"));
    assert!(spec.contains("existing `MessageStore`"));
    assert!(adr.contains("second communication brain"));
    assert!(adr.contains("membership could race removal"));
}

#[test]
fn phase18_groups_create_no_second_conversation_message_delivery_or_identity_brain() {
    let workspace = workspace();
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/group.rs")).expect("model");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/group.rs")).expect("core");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/group_store.rs"))
        .expect("sqlite group store");

    for forbidden in [
        "struct GroupMessage",
        "struct GroupConversation",
        "struct GroupDelivery",
        "struct GroupIdentity",
        "trait GroupConversationStore",
        "trait GroupDeliveryStore",
        "trait GroupIdentityStore",
        "CREATE TABLE group_messages",
        "CREATE TABLE group_conversations",
        "CREATE TABLE group_deliveries",
        "CREATE TABLE group_identities",
    ] {
        assert!(!model.contains(forbidden), "model leaked second owner: {forbidden}");
        assert!(!core.contains(forbidden), "core leaked second owner: {forbidden}");
        assert!(!sqlite.contains(forbidden), "sqlite leaked second owner: {forbidden}");
    }

    assert!(core.contains("MessageStore"));
    assert!(sqlite.contains("messages"));
    assert!(sqlite.contains("conversations"));
}

#[test]
fn phase18_release_truth_and_repository_guards_are_machine_locked() {
    let workspace = workspace();
    let readme = fs::read_to_string(workspace.join("README.md")).expect("readme");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(readme.contains(
        "**Phase 18 — Groups (Prepared/reference complete; Phase 19 not started).**"
    ));
    assert!(readme.contains("Phase 19 is not started"));
    assert!(ci.contains("test -s spec/groups.md"));
    assert!(ci.contains(
        "0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md"
    ));
}
