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
    assert!(sfu.contains("pub fn place_session"));
    assert!(sfu.contains("pub fn mark_draining"));
    assert!(sfu.contains("pub fn release_session"));
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
fn horizontal_sfu_operator_control_wires_heartbeat_list_and_drain_without_public_claim() {
    let operator = read("proto/ucr/v1/operator_runtime.proto");
    let api = read("crates/ucr-api-grpc/src/operator_runtime_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/sfu.md");

    for rpc in ["HeartbeatSfuNode", "DrainSfuNode", "ListSfuNodes"] {
        assert!(operator.contains(rpc), "missing operator SFU RPC {rpc}");
    }
    assert!(operator.contains("endpoint_ip"));
    assert!(operator.contains("endpoint_port"));
    assert!(api.contains("OperatorSfuClusterControl"));
    assert!(runtime.contains("sfu_cluster: Some"));
    assert!(runtime.contains("SfuClusterDirectory::default()"));
    assert!(runtime.contains("heartbeat_sfu_node"));
    assert!(runtime.contains("prune_expired_nodes"));
    assert!(runtime.contains("mark_draining"));
    assert!(spec.contains("Workers must re-register after process restart"));
    assert!(spec.contains("`ResolveNode` separately resolves"));
    assert!(spec.contains("concrete inter-node encrypted-media transport"));
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
