use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn broadcast_processing_is_separate_from_sfu_authority() {
    let workspace_manifest = read("Cargo.toml");
    let broadcast = read("crates/ucr-broadcast/src/lib.rs");
    let broadcast_manifest = read("crates/ucr-broadcast/Cargo.toml");
    let sfu_manifest = read("crates/ucr-sfu/Cargo.toml");
    let spec = read("spec/broadcast.md");

    assert!(workspace_manifest.contains(""crates/ucr-broadcast""));
    assert!(broadcast.contains("pub trait CompositionProvider"));
    assert!(broadcast.contains("pub trait BroadcastProvider"));
    assert!(broadcast.contains("CompositionLayout::ScreenWithSpeaker"));
    assert!(!broadcast_manifest.contains("ucr-sfu"));
    assert!(!sfu_manifest.contains("ucr-broadcast"));
    assert!(spec.contains("explicitly outside SFU authority"));
}

#[test]
fn broadcast_control_contract_keeps_destination_secrets_out_of_canonical_values() {
    let broadcast = read("crates/ucr-broadcast/src/lib.rs");
    let request_start = broadcast
        .find("pub struct BroadcastRequest")
        .expect("broadcast request");
    let request_end = broadcast[request_start..]
        .find("\n}\n")
        .map(|offset| request_start + offset)
        .expect("broadcast request end");
    let request = &broadcast[request_start..request_end];

    assert!(request.contains("destinations: Vec<BroadcastDestination>"));
    assert!(!request.contains("url"));
    assert!(!request.contains("stream_key"));
    assert!(!request.contains("credential"));
    assert!(!request.contains("secret"));
}

#[test]
fn rtmp_hls_dash_capabilities_remain_prepared() {
    let protocol = read("crates/ucr-protocol/src/broadcast.rs");
    assert!(protocol.contains(""ucr.broadcast.rtmp""));
    assert!(protocol.contains(""ucr.broadcast.hls""));
    assert!(protocol.contains(""ucr.broadcast.dash""));
    assert!(protocol.contains("CapabilityMaturity::Prepared"));
}
