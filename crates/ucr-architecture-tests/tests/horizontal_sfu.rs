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
    assert!(sfu.contains("reservations: BTreeMap<String, u32>"));
    assert!(sfu.contains("pub struct SfuNodeCapacitySnapshot"));
    assert!(sfu.contains("pub fn nodes_with_capacity"));
    assert!(sfu.contains("active_sessions"));
    assert!(sfu.contains("u64::from(self.reserved_sessions"));
    assert!(sfu.contains("placement_score"));
    assert!(spec.contains("Horizontal placement foundation"));
    assert!(spec.contains("Worker heartbeat"));
    assert!(spec.contains("coordinator reservations"));

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
    assert!(operator.contains("reserved_sessions"));
    assert!(operator.contains("effective_sessions"));
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

#[test]
fn horizontal_sfu_node_media_contract_is_private_ciphertext_only_and_non_authoritative() {
    let sfu_proto = read("proto/ucr/v1/sfu.proto");
    let spec = read("spec/sfu.md");
    let adr = read("docs/adr/0113-horizontal-sfu-node-media-infrastructure-trust.md");
    let universal = read("proto/ucr/v1/universal_conference.proto");
    let realtime = read("proto/ucr/v1/realtime.proto");

    assert!(sfu_proto.contains("service SfuNodeMediaService"));
    assert!(sfu_proto.contains("rpc ForwardEncrypted(stream SfuNodeEncryptedMedia)"));
    assert!(sfu_proto.contains("SfuForwardTarget target = 2"));
    assert!(sfu_proto.contains("SfuForwardEnvelope envelope = 3"));
    assert!(sfu_proto.contains("SFU_NODE_FORWARD_STATUS_BACKPRESSURE"));
    let normalized_spec = spec.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_spec.contains("mutually authenticated infrastructure node transport"));
    assert!(normalized_spec.contains("not canonical Delivery"));
    assert!(adr.contains("Status: Accepted"));
    assert!(adr.contains("not UCR"));
    assert!(adr.contains("tenant Service Accounts"));

    for forbidden in [
        "plaintext_media",
        "media_private_key",
        "traffic_key",
        "service_credential_secret",
        "join_token",
    ] {
        assert!(
            !sfu_proto.contains(forbidden),
            "private SFU node wire gained forbidden secret/plaintext field: {forbidden}"
        );
    }
    assert!(!universal.contains("SfuNodeMediaService"));
    assert!(!realtime.contains("SfuNodeMediaService"));
}

#[test]
fn horizontal_sfu_node_identity_does_not_reuse_tenant_machine_auth() {
    let adr = read("docs/adr/0113-horizontal-sfu-node-media-infrastructure-trust.md");
    let machine_token = read("crates/ucr-crypto/src/machine_token.rs");

    assert!(machine_token.contains("PrincipalKind::ServiceAccount"));
    assert!(machine_token.contains("tenant_id"));
    assert!(
        adr.contains("machine access tokens authenticate tenant-scoped canonical Service Accounts")
    );
    assert!(adr.contains("infrastructure node identity"));
}

#[test]
fn horizontal_sfu_async_handoff_separates_validation_from_transport_acceptance() {
    let sfu = read("crates/ucr-sfu/src/lib.rs");
    let spec = read("spec/sfu.md");

    assert!(sfu.contains("pub struct SfuValidatedForwardBatch"));
    assert!(sfu.contains("pub fn prepare_forward_selected"));
    assert!(sfu.contains("pub fn dispatch_validated_forward_batch"));
    assert!(sfu.contains("envelope: SfuForwardEnvelope"));
    assert!(sfu.contains("targets: Vec<SfuForwardTarget>"));
    assert!(spec.contains("immutable validated forward batch"));
    assert!(spec.contains("local queue admission"));
    assert!(spec.contains("remote `Accepted`"));
}
