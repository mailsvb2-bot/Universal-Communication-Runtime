use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase28_reuses_group_message_sync_and_trust_owners() {
    let root = workspace();
    let core = fs::read_to_string(root.join("crates/ucr-core/src/mesh.rs")).expect("core");
    let runtime = fs::read_to_string(root.join("crates/ucr-mesh/src/lib.rs")).expect("runtime");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/mesh.rs")).expect("protocol");
    let sqlite = fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/mesh_store.rs"))
        .expect("sqlite");

    assert!(core.contains("pub trait MeshGroupStore: OfflineGroupStore"));
    assert!(runtime.contains("OfflineGroupsRuntime::new"));
    assert!(runtime.contains("authorize_peer_group_sync"));
    assert!(runtime.contains("verify_message_signature_with_trust"));
    assert!(protocol.contains("MAX_MESH_PATH_DEVICES: usize = 8"));
    assert!(protocol.contains("validate_mesh_source"));
    assert!(protocol.contains("append_mesh_recipient"));
    assert!(sqlite.contains("mesh_group_message_hops"));
    assert!(sqlite.contains("REFERENCES offline_group_messages"));
}

#[test]
fn phase28_schema_and_public_boundary_are_machine_locked() {
    let root = workspace();
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite root");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/mesh.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/mesh.md")).expect("spec");

    assert!(sqlite.contains("const SQLITE_SCHEMA_V24: u32 = 24"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 25"));
    assert!(sqlite.contains("migrate_v24_to_v25"));
    assert!(!proto.contains("service Mesh"));
    assert!(!proto.contains("message Relay"));
    assert!(!proto.contains("service Relay"));
    assert!(!proto.contains("EndpointAddress"));
    assert!(spec.contains("signed Group Messages only"));
    assert!(spec.contains("at most 8 Devices"));
    assert!(spec.contains("v24→v25 migration creates an empty hop table"));
}

#[test]
fn phase28_release_truth_docs_and_fuzz_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    let fuzz = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let adr =
        fs::read_to_string(root.join(
            "docs/adr/0066-phase28-mesh-reuses-group-message-sync-device-and-trust-owners.md",
        ))
        .expect("ADR 0066");

    assert!(readme.contains("**Phase 28 — Mesh (Prepared/reference complete; Relay/NAT traversal and multipath not started).**"));
    assert!(ci.contains("test -s spec/mesh.md"));
    assert!(ci.contains("test -s proto/ucr/v1/mesh.proto"));
    assert!(ci.contains("0066-phase28-mesh"));
    assert!(threat.contains("Phase 28 Mesh reuses the existing User Device"));
    assert!(fuzz.contains("mesh_group_path"));
    assert!(smoke.contains("run_target mesh_group_path 4096 768"));
    assert!(adr.contains("Relay/NAT traversal, discovery"));
}
