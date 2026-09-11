use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase23_reuses_existing_media_controls_and_canon_signal_model() {
    let root = workspace();
    let model =
        fs::read_to_string(root.join("crates/ucr-model/src/adaptive_media.rs")).expect("model");
    let protocol = fs::read_to_string(root.join("crates/ucr-protocol/src/adaptive_media.rs"))
        .expect("protocol");
    let runtime =
        fs::read_to_string(root.join("crates/ucr-media-adaptive/src/lib.rs")).expect("runtime");
    let audio = fs::read_to_string(root.join("crates/ucr-audio/src/lib.rs")).expect("audio");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/adaptive_media.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/adaptive-media.md")).expect("spec");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0061-phase23-adaptive-media-reuses-canonical-media-and-security-owners.md",
    ))
    .expect("adr");

    for required in [
        "estimated_bandwidth_bps",
        "packet_loss_basis_points",
        "jitter_ms",
        "rtt_ms",
        "cpu_utilization_percent",
        "gpu_utilization_percent",
        "battery_percent",
        "thermal_state",
    ] {
        assert!(model.contains(required), "missing Canon signal: {required}");
        assert!(
            proto.contains(required),
            "missing public Canon signal: {required}"
        );
    }
    assert!(protocol.contains("ADAPTIVE_MEDIA_CAPABILITY"));
    assert!(protocol.contains("reference_stage_for_telemetry"));
    assert!(protocol.contains("reference_video_config"));
    assert!(protocol.contains("OPUS_LOW_TARGET_BITRATE_BPS"));
    assert!(proto.contains("optional uint32 opus_target_bitrate_bps = 5;"));
    assert!(runtime.contains("ADAPTIVE_DEGRADE_CONFIRM_SAMPLES"));
    assert!(runtime.contains("ADAPTIVE_RECOVERY_CONFIRM_SAMPLES"));
    assert!(runtime.contains("one_step_better"));
    assert!(audio.contains("set_target_bitrate_bps"));
    assert!(spec.contains("1080p -> 720p -> 480p -> low-FPS video -> audio -> low-bitrate audio"));
    assert!(spec.contains("VoiceMessage -> Text -> StoreAndForward"));
    assert!(spec.contains("has no API that converts protected media to plaintext"));
    assert!(adr.contains("No SQLite migration is introduced; schema remains v22"));
}

#[test]
fn phase23_creates_no_second_call_crypto_delivery_or_transport_brain() {
    let root = workspace();
    let sources = [
        fs::read_to_string(root.join("crates/ucr-model/src/adaptive_media.rs")).expect("model"),
        fs::read_to_string(root.join("crates/ucr-protocol/src/adaptive_media.rs"))
            .expect("protocol"),
        fs::read_to_string(root.join("crates/ucr-media-adaptive/src/lib.rs")).expect("runtime"),
    ];
    for forbidden in [
        "CallStore",
        "TransportProvider",
        "RouteCandidate",
        "DeliveryStore",
        "MessageStore",
        "EstablishedSession",
        "TrafficKey",
        "CREATE TABLE",
        "struct AdaptiveCall",
        "struct TransportOrchestrator",
    ] {
        assert!(
            sources.iter().all(|source| !source.contains(forbidden)),
            "future/second-brain leak: {forbidden}"
        );
    }
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 ="));
}

#[test]
fn phase23_release_truth_public_contract_and_fuzz_gate_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let fuzz_smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");

    assert!(readme.contains(
        "**Phase 28 — Mesh (Prepared/reference complete; Relay/NAT traversal and multipath not started).**"
    ));
    assert!(ci.contains("test -s spec/adaptive-media.md"));
    assert!(ci.contains("test -s proto/ucr/v1/adaptive_media.proto"));
    assert!(
        ci.contains("0061-phase23-adaptive-media-reuses-canonical-media-and-security-owners.md")
    );
    assert!(spec_readme.contains("Phase 23 adds `adaptive-media.md`"));
    assert!(fuzz_manifest.contains("adaptive_media_telemetry"));
    assert!(fuzz_smoke.contains("run_target adaptive_media_telemetry 64 512"));
    assert!(
        threat.contains("Phase 23 Adaptive Media treats measurements as bounded control input")
    );
    assert!(threat.contains("Phase-23 `adaptive_media_telemetry`"));
}
