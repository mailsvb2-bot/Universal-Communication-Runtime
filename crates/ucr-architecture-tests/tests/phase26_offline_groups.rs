use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase26_reuses_group_message_sync_and_trust_owners() {
    let root = workspace();
    let core = fs::read_to_string(root.join("crates/ucr-core/src/group.rs")).expect("core group");
    let runtime = fs::read_to_string(root.join("crates/ucr-offline-groups/src/lib.rs"))
        .expect("offline runtime");
    let memory = fs::read_to_string(root.join("crates/ucr-storage-memory/src/group_store.rs"))
        .expect("memory group");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/offline_group_store.rs"))
            .expect("sqlite sidecar");

    assert!(core.contains("pub trait OfflineGroupStore: GroupMessageStore + SyncStore"));
    assert!(runtime.contains("SyncLinkKind::PeerPeer"));
    assert!(runtime.contains("authenticated_peer_device_id"));
    assert!(runtime.contains("resolve_active_signing_key"));
    assert!(runtime.contains("verify_message_signature_with_trust"));
    assert!(memory.contains("apply_group_change_in_state"));
    assert!(sqlite.contains("apply_group_change_in_transaction"));
    assert!(sqlite.contains("record_message_replica"));
}
#[test]
fn phase26_one_hop_and_schema_boundary_is_machine_locked() {
    let root = workspace();
    let protocol = fs::read_to_string(root.join("crates/ucr-protocol/src/offline_group.rs"))
        .expect("protocol");
    let sqlite_root =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite root");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/offline_groups.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/offline-groups.md")).expect("spec");

    assert!(protocol.contains("MAX_OFFLINE_GROUP_PAGE_ITEMS: usize = 256"));
    assert!(protocol.contains("UCR-OFFLINE-GROUP-CURSOR-V1"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 23"));
    assert!(sqlite_root.contains("migrate_v22_to_v23"));
    assert!(!proto.contains("service OfflineGroup"));
    assert!(!proto.contains("EndpointAddress"));
    assert!(!proto.contains("Relay"));
    assert!(spec.contains("do **not** receive local export sidecars"));
    assert!(spec.contains("Phase 27 Store-and-Forward remains not started"));
}

#[test]
fn phase26_release_truth_contract_docs_and_fuzz_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    let fuzz = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0064-phase26-offline-groups-reuses-group-message-sync-and-trust-owners.md",
    ))
    .expect("ADR 0064");

    assert!(readme.contains(
        "**Phase 26 — Offline Groups (Prepared/reference complete; Phase 27 Store-and-Forward not started).**"
    ));
    assert!(ci.contains("test -s spec/offline-groups.md"));
    assert!(ci.contains("test -s proto/ucr/v1/offline_groups.proto"));
    assert!(ci.contains("0064-phase26-offline-groups"));
    assert!(spec_readme.contains("Phase 26 adds `offline-groups.md`"));
    assert!(threat.contains("Phase 26 Offline Groups treats Group membership"));
    assert!(fuzz.contains("offline_group_replica"));
    assert!(smoke.contains("run_target offline_group_replica 4096 768"));
    assert!(adr.contains("Phase 27 Store-and-Forward remains separate and not started"));
}
