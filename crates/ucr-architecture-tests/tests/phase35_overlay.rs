use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase35_overlay_reuses_group_conversation_and_bridge_owners_without_second_brain() {
    let source = read("crates/ucr-overlay/src/lib.rs");
    let manifest = read("crates/ucr-overlay/Cargo.toml");
    let spec = read("spec/overlay-conversations.md");
    assert!(source.contains("pub const OVERLAY_CONVERSATIONS_CAPABILITY"));
    assert!(source.contains("pub trait OverlayStore: GroupStore + BridgeRegistrationStore"));
    assert!(source.contains("GroupChangeKind::AddBridgeMapping"));
    assert!(source.contains("GroupChangeKind::RemoveBridgeMapping"));
    assert!(source.contains("group_for_bridge_mapping"));
    assert!(!source.contains("persist_message"));
    assert!(!source.contains("BridgeRuntime"));
    assert!(!source.contains("DeliveryStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
    assert!(spec.contains("not a second communication brain"));
    assert!(spec.contains(
        "introduces no Overlay Message store, Conversation store, Identity store, Delivery store"
    ));
    assert!(spec.contains("Provider side effects remain owned by `BridgeRuntime`"));
}

#[test]
fn phase35_mapping_lifecycle_uniqueness_restart_and_offline_semantics_are_locked() {
    let model = read("crates/ucr-model/src/group.rs");
    let protocol = read("crates/ucr-protocol/src/group.rs");
    let core = read("crates/ucr-core/src/group.rs");
    let memory = read("crates/ucr-storage-memory/src/group_store.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/group_store.rs");
    let offline = read("crates/ucr-storage-sqlite/src/offline_group_store.rs");
    let sqlite_root = read("crates/ucr-storage-sqlite/src/lib.rs");
    let proto = read("proto/ucr/v1/offline_groups.proto");
    assert!(model.contains("AddBridgeMapping"));
    assert!(model.contains("RemoveBridgeMapping"));
    assert!(protocol.contains("ucr.group.bridge_mapping_added"));
    assert!(protocol.contains("ucr.group.bridge_mapping_removed"));
    assert!(protocol.contains("mapping.integration_id.as_opaque().as_wire_bytes()"));
    assert!(core.contains("fn group_for_bridge_mapping"));
    assert!(memory.contains("ensure_bridge_mapping_uniqueness"));
    assert!(memory.contains("BridgeRegistrationState::Active"));
    assert!(sqlite.contains("group_bridge_mappings_external_endpoint"));
    assert!(sqlite.contains("PRAGMA index_list('group_bridge_mappings')"));
    assert!(sqlite.contains("PRAGMA index_xinfo('group_bridge_mappings_external_endpoint')"));
    assert!(sqlite.contains("schema_v28_rejects_same_named_unique_index_with_wrong_columns"));
    assert!(sqlite.contains("map_bridge_mapping_insert_error"));
    assert!(sqlite.contains("BridgeRegistrationState::Active"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 28"));
    assert!(offline.contains("offline_group_bridge_changes"));
    assert!(offline.contains("offline_group_change_sequence"));
    assert!(offline.contains("entries.sort_by_key(|(sequence, _)| *sequence)"));
    assert!(proto.contains("GroupAddBridgeMappingChange"));
    assert!(proto.contains("GroupRemoveBridgeMappingChange"));
    let tests = sqlite;
    for name in [
        "overlay_mapping_and_reverse_resolution_survive_restart",
        "sqlite_rejects_one_external_endpoint_for_two_groups",
        "v27_migration_preserves_existing_bridge_mapping_and_adds_overlay_sidecars",
        "offline_group_cursor_orders_legacy_and_overlay_changes_together",
    ] {
        assert!(tests.contains(name));
    }
}

#[test]
fn phase35_permissions_privacy_docs_ci_and_security_evidence_are_machine_locked() {
    let source = read("crates/ucr-overlay/src/lib.rs");
    let tests = read("crates/ucr-overlay/tests/reference.rs");
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let spec = read("spec/overlay-conversations.md");
    let metadata = read("spec/metadata-visibility.tsv");
    let adr = read(
        "docs/adr/0073-phase35-overlay-conversations-reuse-group-conversation-and-bridge-owners.md",
    );
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/overlay_threat.rs");
    let ci = read(".github/workflows/ci.yml");
    assert!(
        readme.contains(
            "**Phase 35 — Overlay Conversations (Prepared cross-network logical groups).**"
        )
    );
    assert!(spec_index.contains("Phase 35 adds `overlay-conversations.md`"));
    assert!(spec.contains("Provider side effects remain owned by `BridgeRuntime`"));
    assert!(adr.contains("Overlay Conversations reuse Group, Conversation and Bridge owners"));
    assert!(source.contains("BRIDGE_EVENTS_READ_PERMISSION"));
    assert!(source.contains("GROUP_READ_PERMISSION"));
    assert!(source.contains("GROUP_MANAGE_PERMISSION"));
    assert!(source.contains("BridgeDataPermission::InboundEvents"));
    assert!(source.contains("BridgeDataPermission::ExternalIdentityReferences"));
    assert!(source.contains("BridgeDataPermission::MessageContent"));
    assert!(source.contains("group.conversation.kind != ConversationKind::PrivateGroup"));
    assert!(tests.contains("private_overlay_is_non_disclosing_to_non_member"));
    assert!(tests.contains("inbound_resolution_requires_all_consumed_data_permissions"));
    assert!(tests.contains("endpoint_debug_redacts_provider_conversation_id"));
    assert!(
        security.contains("fn compromised_overlay_boundary_cannot_alias_groups_or_choose_scope()")
    );
    assert!(matrix.contains("Compromised Overlay endpoint"));
    assert!(threat.contains("Phase 35 Overlay Conversations treats external endpoint aliasing"));
    assert!(metadata.contains("Phase-35 Overlay"));
    assert!(ci.contains("test -s spec/overlay-conversations.md"));
    assert!(ci.contains(
        "0073-phase35-overlay-conversations-reuse-group-conversation-and-bridge-owners.md"
    ));
}
