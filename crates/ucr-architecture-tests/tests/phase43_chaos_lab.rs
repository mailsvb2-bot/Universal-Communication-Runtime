use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase43_chaos_lab_covers_the_canonical_failure_surface() {
    let implementation = read("crates/ucr-chaos-lab/src/lib.rs");
    let spec = read("spec/chaos-lab.md");

    for marker in [
        "NetworkLoss",
        "NetworkSwitch",
        "DnsFailure",
        "RelayFailure",
        "SfuFailure",
        "ProcessKill",
        "AppRestart",
        "PeerDisappearance",
        "ClockDrift",
        "PacketDuplication",
        "PacketReorder",
        "Corruption",
        "StorageFull",
        "NetworkPartition",
        "NetworkMerge",
        "OldClient",
        "RevokedDevice",
        "SlowConsumer",
    ] {
        assert!(
            implementation.contains(marker),
            "missing chaos scenario {marker}"
        );
    }
    assert!(spec.contains("100 peers"));
    assert!(implementation.contains("canonical_100_peers"));
}

#[test]
fn phase43_is_test_infrastructure_not_a_second_communication_brain() {
    let manifest = read("crates/ucr-chaos-lab/Cargo.toml");
    let implementation = read("crates/ucr-chaos-lab/src/lib.rs");
    let adr = read("docs/adr/0089-phase43-chaos-lab-is-deterministic-test-infrastructure.md");

    assert!(!manifest.contains("ucr-core"));
    assert!(!manifest.contains("ucr-storage"));
    assert!(!manifest.contains("ucr-transport"));
    assert!(!manifest.contains("ucr-protocol"));
    for forbidden in [
        "struct MessageEngine",
        "struct DeliveryEngine",
        "struct TransportOrchestrator",
        "trait MessageStore",
        "trait ConversationStore",
        "pub struct Conversation",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "Chaos Lab introduced forbidden production owner: {forbidden}"
        );
    }
    assert!(adr.contains("standalone, non-production crate"));
}

#[test]
fn phase43_locks_data_safety_and_explicit_failure_evidence() {
    let implementation = read("crates/ucr-chaos-lab/src/lib.rs");
    let workflow = read(".github/workflows/phase43-chaos-lab.yml");

    for test in [
        "duplicate_and_reorder_are_wire_faults_not_user_visible_duplicates",
        "corruption_is_explicitly_rejected",
        "partition_merge_and_network_switch_are_recoverable",
        "infrastructure_failures_are_never_false_successes",
        "process_restart_preserves_durable_pending_state_and_storage_full_is_atomic",
        "revoked_or_disappeared_peer_fails_closed",
        "clock_drift_does_not_change_monotonic_test_time",
        "slow_consumer_is_bounded_as_latency_not_silent_loss",
        "canonical_network_simulation_has_100_peers_and_survives_partition_merge",
    ] {
        assert!(
            implementation.contains(test),
            "missing executable chaos evidence {test}"
        );
    }
    assert!(workflow.contains("cargo clippy"));
    assert!(workflow.contains("cargo test"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("|| true"));
}
