use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase24_canon_factors_and_owner_reuse_are_machine_locked() {
    let root = workspace();
    let model = fs::read_to_string(root.join("crates/ucr-model/src/transport_orchestrator.rs"))
        .expect("model");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/transport_orchestrator.rs"))
            .expect("protocol");
    let runtime = fs::read_to_string(root.join("crates/ucr-transport-orchestrator/src/lib.rs"))
        .expect("runtime");
    let spec = fs::read_to_string(root.join("spec/transport-orchestrator.md")).expect("spec");
    let proto =
        fs::read_to_string(root.join("proto/ucr/v1/transport_orchestrator.proto")).expect("proto");

    for required in [
        "estimated_bandwidth_bps",
        "packet_loss_basis_points",
        "jitter_ms",
        "rtt_ms",
        "cost_microunits",
        "energy_cost_percent",
        "reliability_basis_points",
        "recipient_reachable",
        "privacy_profile",
        "region",
    ] {
        assert!(model.contains(required), "missing route factor: {required}");
        assert!(
            proto.contains(required),
            "missing public route factor: {required}"
        );
    }
    assert!(model.contains("battery_percent"));
    assert!(model.contains("thermal_state"));
    assert!(protocol.contains("MAX_TRANSPORT_PRIORITY_CLASS"));
    assert!(runtime.contains("PolicyEvaluator"));
    assert!(runtime.contains("validate_endpoint_descriptor"));
    assert!(runtime.contains("provider.health()"));
    assert!(runtime.contains("recipient_endpoint.capabilities"));
    assert!(spec.contains("Hard constraints always run before preference scoring"));
    assert!(
        spec.contains("External hints are exactly `Urgent`, `PreferLocal`, and `AvoidExpensive`")
    );
}

#[test]
fn phase24_does_not_create_a_second_transport_delivery_or_failover_brain() {
    let root = workspace();
    let runtime = fs::read_to_string(root.join("crates/ucr-transport-orchestrator/src/lib.rs"))
        .expect("runtime");
    let proto =
        fs::read_to_string(root.join("proto/ucr/v1/transport_orchestrator.proto")).expect("proto");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0062-phase24-transport-orchestrator-reuses-canonical-intent-endpoint-policy-and-transport-owners.md",
    ))
    .expect("adr");

    for forbidden in [
        "DeliveryStore",
        "MessageStore",
        "CommunicationIntentStore",
        "CREATE TABLE",
        "struct InternetTransportProvider",
        "struct LocalTransportProvider",
        "struct AutomaticFailover",
        "retry_next_route",
    ] {
        assert!(
            !runtime.contains(forbidden),
            "second/future owner leak: {forbidden}"
        );
    }
    assert!(!proto.contains("service TransportOrchestrator"));
    assert!(!proto.contains("EndpointAddress address"));
    assert!(!proto.contains("identity.proto"));
    assert!(runtime.contains("transmit_primary"));
    assert!(runtime.contains("Phase 24 does not try the next ranked route"));
    assert!(adr.contains("Phase 25 owns Automatic Failover"));
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 24"));
}

#[test]
fn phase24_release_truth_public_contract_and_fuzz_gate_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let fuzz_smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");

    assert!(readme.contains("Phase 24"));
    assert!(readme.contains("**Phase 27 — Store-and-Forward (Prepared/reference complete; Relay and multipath not started).**"));
    assert!(ci.contains("test -s spec/transport-orchestrator.md"));
    assert!(ci.contains("test -s proto/ucr/v1/transport_orchestrator.proto"));
    assert!(ci.contains("0062-phase24-transport-orchestrator-reuses-canonical-intent-endpoint-policy-and-transport-owners.md"));
    assert!(spec_readme.contains("Phase 24 adds `transport-orchestrator.md`"));
    assert!(fuzz_manifest.contains("transport_orchestrator_plan"));
    assert!(fuzz_smoke.contains("run_target transport_orchestrator_plan 128 512"));
    assert!(threat.contains("Phase 24 Transport Orchestrator treats route telemetry"));
    assert!(threat.contains("Phase-24 `transport_orchestrator_plan`"));
}
