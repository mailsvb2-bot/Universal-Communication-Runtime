use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn horizontal_sfu_placement_remains_ephemeral_and_non_authoritative() {
    let sfu = read("crates/ucr-sfu/src/lib.rs");
    let spec = read("spec/sfu.md");

    assert!(sfu.contains("pub struct SfuClusterDirectory"));
    assert!(sfu.contains("pub struct SfuNodeDescriptor"));
    assert!(sfu.contains("pub enum SfuNodeState"));
    assert!(sfu.contains("pub fn select_node"));
    assert!(sfu.contains("pub fn mark_draining"));
    assert!(sfu.contains("placement_score"));
    assert!(spec.contains("Horizontal placement foundation"));

    for forbidden in [
        "ConferenceStore",
        "DeliveryStore",
        "RecordingStore",
        "MessageStore",
        "GroupStore for SfuClusterDirectory",
    ] {
        assert!(
            !sfu.contains(forbidden),
            "horizontal placement gained forbidden canonical ownership: {forbidden}"
        );
    }
}

#[test]
fn horizontal_sfu_capability_stays_fail_closed_until_transport_is_wired() {
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/universal-conference-api.md");

    assert!(runtime.contains("horizontal_sfu: false"));
    assert!(spec.contains(
        "Recording and horizontal-SFU remain false until corresponding providers are wired"
    ));
}
