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
    for primitive in [
        "DropNext",
        "DuplicateNext",
        "ReorderNextPair",
        "CorruptNext",
        "SetPeerOnline",
        "SetLatency",
        "SetJitter",
        "SetLossBasisPoints",
        "SetThrottle",
    ] {
        assert!(
            implementation.contains(primitive),
            "missing canonical test-transport primitive {primitive}"
        );
    }
    assert!(spec.contains("100 peers"));
    assert!(spec.contains("battery"));
    assert!(implementation.contains("canonical_100_peers"));
    assert!(implementation.contains("SetMinimumSendBatteryPercent"));
}

#[test]
fn phase43_is_test_infrastructure_not_a_second_communication_brain() {
    let manifest = read("crates/ucr-chaos-lab/Cargo.toml");
    let lock = read("crates/ucr-chaos-lab/Cargo.lock");
    let implementation = read("crates/ucr-chaos-lab/src/lib.rs");
    let adr = read("docs/adr/0089-phase43-chaos-lab-is-deterministic-test-infrastructure.md");

    assert!(!manifest.contains("ucr-core"));
    assert!(!manifest.contains("ucr-storage"));
    assert!(!manifest.contains("ucr-transport"));
    assert!(!manifest.contains("ucr-protocol"));
    assert!(manifest.contains("ucr-realtime"));
    assert!(manifest.contains("ucr-webrtc"));
    assert!(lock.contains("name = \"ucr-realtime\""));
    assert!(lock.contains("name = \"ucr-webrtc\""));
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
    let adversity = read("crates/ucr-chaos-lab/tests/network_adversity.rs");
    let sfu_adversity = read("crates/ucr-sfu/tests/network_adversity.rs");
    let live_webrtc_adversity = read("crates/ucr-webrtc/tests/live_loopback_adversity.rs");
    let realtime_spec = read("spec/realtime.md");
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
        "disconnect_reconnect_and_throttle_are_deterministic",
        "canonical_network_simulation_has_100_peers_and_survives_partition_merge",
    ] {
        assert!(
            implementation.contains(test),
            "missing executable chaos evidence {test}"
        );
    }
    for marker in [
        "network_switch_recovers_single_use_realtime_downlink_without_second_redemption",
        "packet_loss_recovery_restarts_ice_for_the_same_live_webrtc_session",
        "deterministic_jitter_stays_bounded_on_high_latency_links",
        "Fault::SetJitter",
        "RealtimeSessionRegistry",
        "LiveWebRtcProvider",
        "Fault::SwitchNetwork",
        "Fault::SetLossBasisPoints",
        "2_000",
        "restart_session",
        "JoinGrantUsePolicy::SingleUse",
    ] {
        assert!(
            adversity.contains(marker),
            "missing cross-boundary network-adversity evidence {marker}"
        );
    }
    for marker in [
        "sfu_node_restart_fails_over_without_rebinding_canonical_call",
        "SfuClusterDirectory",
        "remove_node",
        "retained_sticky_placement",
    ] {
        assert!(
            sfu_adversity.contains(marker),
            "missing SFU restart adversity evidence {marker}"
        );
    }
    for marker in [
        "live_loopback_connects_and_renegotiates_fresh_ice_generation_on_same_session",
        "LiveWebRtcProvider",
        "create_session",
        "restart_session",
        "set_remote_description",
        "RTCPeerConnectionState::Connected",
        "a=ice-ufrag:",
        "initial_ufrags",
        "restarted_ufrags",
    ] {
        assert!(
            live_webrtc_adversity.contains(marker),
            "missing live WebRTC loopback evidence {marker}"
        );
    }
    assert!(
        realtime_spec.contains("controlled loopback ICE/DTLS connectivity"),
        "realtime spec must describe bounded loopback evidence"
    );
    assert!(
        realtime_spec.contains("does not prove live public TURN traversal"),
        "loopback evidence must not be promoted to public TURN evidence"
    );
    assert!(workflow.contains("cargo clippy"));
    assert!(workflow.contains("cargo test"));
    assert!(workflow.contains("-p ucr-sfu --test network_adversity"));
    assert!(workflow.contains("-p ucr-webrtc --test live_loopback_adversity"));
    assert!(workflow.matches("--locked").count() >= 4);
    assert!(!workflow.contains("cargo generate-lockfile"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("|| true"));
}
