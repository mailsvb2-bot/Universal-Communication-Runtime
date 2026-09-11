use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase27_reuses_canonical_delivery_and_transport_owners() {
    let root = workspace();
    let core = fs::read_to_string(root.join("crates/ucr-core/src/store_forward.rs")).expect("core");
    let runtime =
        fs::read_to_string(root.join("crates/ucr-store-forward/src/lib.rs")).expect("runtime");
    let memory =
        fs::read_to_string(root.join("crates/ucr-storage-memory/src/store_forward_store.rs"))
            .expect("memory");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/store_forward_store.rs"))
            .expect("sqlite");

    assert!(core.contains("pub trait StoreForwardStore: DeliveryStore + CommunicationIntentStore"));
    assert!(runtime.contains("max_route_attempts: 1"));
    assert!(runtime.contains("DeliveryState::InFlight"));
    assert!(runtime.contains("StoreForwardOutcome::AcceptanceUnknown"));
    assert!(runtime.contains("store_forward_delivery_id"));
    assert!(runtime.contains("resources: TransportResourceSnapshot"));
    assert!(runtime.contains("hints: &[TransportRoutingHint]"));
    assert!(!runtime.contains("battery_percent: 100"));
    assert!(memory.contains("store_forward_tombstones"));
    assert!(sqlite.contains("store_forward_tombstones"));
    assert!(sqlite.contains("job_fingerprint"));
}

#[test]
fn phase27_schema_and_public_boundary_are_machine_locked() {
    let root = workspace();
    let protocol = fs::read_to_string(root.join("crates/ucr-protocol/src/store_forward.rs"))
        .expect("protocol");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite root");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/store_forward.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/store-forward.md")).expect("spec");

    assert!(protocol.contains("MAX_STORE_FORWARD_DELIVERY_ATTEMPTS: u16 = 64"));
    assert!(protocol.contains("MAX_STORE_FORWARD_PAGE_ITEMS: usize = 256"));
    assert!(protocol.contains("store_forward_job_fingerprint"));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V24: u32 = 24"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 25"));
    assert!(sqlite.contains("migrate_v23_to_v24"));
    assert!(!proto.contains("service StoreForward"));
    assert!(!proto.contains("EndpointAddress"));
    assert!(!proto.contains("message StoreForwardLease"));
    assert!(!proto.contains("message Relay"));
    assert!(!proto.contains("service Relay"));
    assert!(spec.contains("No-route planning does not consume a Delivery attempt"));
    assert!(spec.contains("max_route_attempts = 1"));
    assert!(spec.contains("Ambiguous acceptance leaves the canonical attempt `InFlight`"));
}

#[test]
fn phase27_release_truth_docs_and_fuzz_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    let fuzz = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let adr = fs::read_to_string(root.join("docs/adr/0065-phase27-store-and-forward-reuses-intent-message-delivery-and-transport-owners.md")).expect("ADR 0065");

    assert!(readme.contains("**Phase 28 — Mesh (Prepared/reference complete; Relay/NAT traversal and multipath not started).**"));
    assert!(ci.contains("test -s spec/store-forward.md"));
    assert!(ci.contains("test -s proto/ucr/v1/store_forward.proto"));
    assert!(ci.contains("0065-phase27-store-and-forward"));
    assert!(spec_readme.contains("Phase 27 adds `store-forward.md`"));
    assert!(threat.contains("Phase 27 Store-and-Forward treats retry scheduling"));
    assert!(fuzz.contains("store_forward_job"));
    assert!(smoke.contains("run_target store_forward_job 4096 768"));
    assert!(adr.contains("Relay and multipath remain separate later phases"));
}
