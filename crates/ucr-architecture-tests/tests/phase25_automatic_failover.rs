use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase25_duplicate_safe_failover_boundary_is_machine_locked() {
    let root = workspace();
    let core = fs::read_to_string(root.join("crates/ucr-core/src/lib.rs")).expect("core");
    let runtime =
        fs::read_to_string(root.join("crates/ucr-transport-orchestrator/src/failover.rs"))
            .expect("failover runtime");
    let internet = fs::read_to_string(root.join("crates/ucr-transport-internet/src/provider.rs"))
        .expect("internet");
    let local =
        fs::read_to_string(root.join("crates/ucr-transport-internet/src/local.rs")).expect("local");
    let spec = fs::read_to_string(root.join("spec/transport-failover.md")).expect("spec");

    assert!(core.contains("TransportFailureDisposition"));
    assert!(core.contains("NotAccepted"));
    assert!(core.contains("AcceptanceUnknown"));
    assert!(core.contains("map_err(ClassifiedTransportFailure::acceptance_unknown)"));
    assert!(runtime.contains("transmit_with_failover"));
    assert!(runtime.contains("TransportFailureDisposition::AcceptanceUnknown"));
    assert!(runtime.contains("validate_transport_failover_policy"));
    assert!(runtime.contains("deadline_expired"));
    assert!(internet.contains("transmit_once_classified"));
    assert!(local.contains("transmit_once_classified"));
    assert!(spec.contains("A later route is eligible only after `NotAccepted`"));
    assert!(spec.contains("does not promise exactly-once"));
}

#[test]
fn phase25_does_not_create_future_or_second_owner() {
    let root = workspace();
    let runtime =
        fs::read_to_string(root.join("crates/ucr-transport-orchestrator/src/failover.rs"))
            .expect("runtime");
    let proto =
        fs::read_to_string(root.join("proto/ucr/v1/transport_failover.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/transport-failover.md")).expect("spec");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");

    for forbidden in [
        "DeliveryStore",
        "MessageStore",
        "CommunicationIntentStore",
        "CREATE TABLE",
        "StoreAndForward",
        "OfflineGroup",
        "struct InternetTransportProvider",
        "struct LocalTransportProvider",
    ] {
        assert!(
            !runtime.contains(forbidden),
            "future/second owner leak: {forbidden}"
        );
    }
    assert!(!proto.contains("service TransportFailover"));
    assert!(!proto.contains("EndpointAddress"));
    assert!(spec.contains("Phase 26 Offline Groups"));
    assert!(spec.contains("Phase 27 Store-and-Forward"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 23"));
}

#[test]
fn phase25_release_truth_contract_docs_and_fuzz_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let fuzz_smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0063-phase25-automatic-failover-reuses-transport-orchestrator-and-provider-acceptance-evidence.md",
    ))
    .expect("ADR 0063");

    assert!(readme.contains(
        "**Phase 26 — Offline Groups (Prepared/reference complete; Phase 27 Store-and-Forward not started).**"
    ));
    assert!(ci.contains("test -s spec/transport-failover.md"));
    assert!(ci.contains("test -s proto/ucr/v1/transport_failover.proto"));
    assert!(ci.contains("0063-phase25-automatic-failover"));
    assert!(spec_readme.contains("Phase 25 adds `transport-failover.md`"));
    assert!(fuzz_manifest.contains("transport_failover_execution"));
    assert!(fuzz_smoke.contains("run_target transport_failover_execution 64 512"));
    assert!(threat.contains("Phase 25 Automatic Failover treats duplicate creation"));
    assert!(threat.contains("transport_failover_execution"));
    assert!(adr.contains("Phase 26 Offline Groups"));
    assert!(adr.contains("Phase 27 Store-and-Forward"));
}
