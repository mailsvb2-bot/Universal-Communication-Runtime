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
    let spec_words = spec.split_whitespace().collect::<Vec<_>>().join(" ");

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
    assert!(spec_words.contains("receiving network boundary is now concrete"));
    assert!(spec_words.contains("outbound node client tied to `SfuPlacementService.ResolveNode`"));
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
    let spec_words = spec.split_whitespace().collect::<Vec<_>>().join(" ");
    let adr = read("docs/adr/0113-horizontal-sfu-node-media-infrastructure-trust.md");
    let universal = read("proto/ucr/v1/universal_conference.proto");
    let realtime = read("proto/ucr/v1/realtime.proto");

    assert!(sfu_proto.contains("service SfuNodeMediaService"));
    assert!(sfu_proto.contains("rpc ForwardEncrypted(stream SfuNodeEncryptedMedia)"));
    assert!(sfu_proto.contains("SfuForwardTarget target = 2"));
    assert!(sfu_proto.contains("SfuForwardEnvelope envelope = 3"));
    assert!(sfu_proto.contains("SFU_NODE_FORWARD_STATUS_BACKPRESSURE"));
    assert!(spec_words.contains("private mTLS node listener for this exact service"));
    assert!(spec_words.contains("explicitly configured client CA roots"));
    assert!(spec.contains("not canonical Delivery"));
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
fn horizontal_sfu_node_media_service_requires_tls_peer_and_revalidates_canonical_media() {
    let api = read("crates/ucr-api-grpc/src/sfu_node_media_service.rs");
    let manifest = read("crates/ucr-api-grpc/Cargo.toml");

    assert!(manifest.contains("\"tls-ring\""));
    assert!(api.contains("require_mtls_peer(&request)?;"));
    assert!(api.contains(".peer_certs()"));
    assert!(api.contains("SfuRuntime::new"));
    assert!(api.contains("forward_selected"));
    assert!(api.contains("PreparedGroupMediaE2eeCapabilities"));
    assert!(api.contains("PreparedSfuCapabilities"));
    assert!(api.contains("SFU_NODE_RECEIPT_CHANNEL_CAPACITY"));
    assert!(api.contains("SfuForwardSinkError::Backpressure"));
    assert!(api.contains("Status::unauthenticated"));
    assert!(!api.contains("MachineAccessToken"));
    assert!(!api.contains("ServiceCredentialSecret"));
}

#[test]
fn horizontal_sfu_async_handoff_separates_validation_from_transport_acceptance() {
    let sfu = read("crates/ucr-sfu/src/lib.rs");
    let conference = read("crates/ucr-conference/src/lib.rs");
    let spec = read("spec/sfu.md");

    assert!(sfu.contains("pub struct SfuValidatedForwardBatch"));
    assert!(sfu.contains("pub fn prepare_forward_selected"));
    assert!(sfu.contains("pub fn dispatch_validated_forward_batch"));
    assert!(sfu.contains("envelope: SfuForwardEnvelope"));
    assert!(sfu.contains("targets: Vec<SfuForwardTarget>"));
    assert!(conference.contains("pub fn prepare_forward"));
    assert!(conference.contains("Result<Option<SfuValidatedForwardBatch>, ConferenceError>"));
    assert!(conference.contains("self.subscribers_for_source"));
    assert!(conference.contains("dispatch_validated_forward_batch(&batch, sink)"));
    assert!(spec.contains("immutable validated forward batch"));
    assert!(spec.contains("canonical Conference subscription selection"));
    assert!(spec.contains("local queue admission"));
    assert!(spec.contains("remote `Accepted`"));
}

#[test]
fn horizontal_sfu_node_media_listener_is_private_mtls_and_not_a_public_capability_claim() {
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    let manifest = read("crates/ucr-runtime/Cargo.toml");
    let spec = read("spec/sfu.md");

    assert!(manifest.contains("\"tls-ring\""));
    assert!(runtime.contains("pub struct SfuNodeMediaRuntimeConfig"));
    assert!(runtime.contains("validate_private_sfu_node_bind"));
    assert!(runtime.contains("ServerTlsConfig::new()"));
    assert!(runtime.contains(".client_ca_root("));
    assert!(runtime.contains("sfu_node_media_service_server(service)"));
    assert!(runtime.contains("UCR_SFU_NODE_MEDIA_READY"));
    assert!(runtime.contains("horizontal_sfu: false"));
    assert!(runtime_main.contains("UCR_SFU_NODE_BIND"));
    assert!(runtime_main.contains("UCR_SFU_NODE_CERT_FILE"));
    assert!(runtime_main.contains("UCR_SFU_NODE_KEY_FILE"));
    assert!(runtime_main.contains("UCR_SFU_NODE_CLIENT_CA_FILE"));
    assert!(runtime_main.contains("ReloadingFileTlsSecretProvider"));
    assert!(spec.contains("private mTLS node listener"));
    assert!(spec.contains("outbound node client"));
}

#[test]
fn horizontal_sfu_outbound_node_client_is_mtls_receipt_driven_and_still_fail_closed() {
    let client = read("crates/ucr-api-grpc/src/sfu_node_media_client.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/sfu.md");
    let adr = read("docs/adr/0113-horizontal-sfu-node-media-infrastructure-trust.md");

    assert!(client.contains("pub struct SfuNodeMediaClientTlsConfig"));
    assert!(client.contains("pub struct GrpcSfuNodeMediaClient"));
    assert!(client.contains("SfuValidatedForwardBatch"));
    assert!(client.contains("ClientTlsConfig::new()"));
    assert!(client.contains(".identity(Identity::from_pem("));
    assert!(client.contains(".ca_certificate(Certificate::from_pem("));
    assert!(client.contains("forward_batch"));
    assert!(client.contains("receipt.stream_sequence"));
    assert!(client.contains("SfuNodeForwardStatus::Backpressure"));
    assert!(client.contains("accepted_before_failure"));
    assert!(client.contains("active_secret_set"));
    assert!(runtime.contains("horizontal_sfu: false"));
    assert!(spec.contains("outbound mTLS node client foundation"));
    assert!(adr.contains("outbound client now consumes only"));
}

#[test]
fn horizontal_sfu_placement_router_binds_resolve_node_to_outbound_mtls_without_overclaim() {
    let router = read("crates/ucr-api-grpc/src/sfu_placement_media_router.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/sfu.md");

    assert!(router.contains("pub struct PlacementAwareSfuNodeRouter"));
    assert!(router.contains(".place_call(pb::SfuPlaceCallRequest"));
    assert!(router.contains(".resolve_node(pb::SfuResolveNodeRequest"));
    assert!(router.contains("SfuValidatedForwardBatch"));
    assert!(router.contains("self.node_tls"));
    assert!(router.contains(".connect(resolved.endpoint.address)"));
    assert!(router.contains(".forward_batch(batch)"));
    assert!(router.contains("route_node.value != selected_pb.value"));
    assert!(router.contains("is_private_node_endpoint"));
    assert!(router.contains("requires a loopback operator endpoint"));
    assert!(runtime.contains("horizontal_sfu: false"));
    assert!(spec.contains("placement-aware outbound router"));
    assert!(spec.contains("realtime-session binding"));
}

#[test]
fn horizontal_sfu_realtime_lifecycle_uses_the_canonical_session_registry_and_stays_fail_closed() {
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let registry = read("crates/ucr-realtime/src/lib.rs");
    let placement = read("crates/ucr-api-grpc/src/sfu_placement_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    let spec = read("spec/sfu.md");

    assert!(realtime.contains("pub trait RealtimeSfuPlacementLifecycle"));
    let ensure_index = realtime
        .find("self.ensure_sfu_call_placement(&claims).await")
        .expect("placement ensure");
    let join_index = realtime
        .find("self.registry.join(claims.clone(), now_unix_ms)")
        .expect("registry join");
    assert!(
        ensure_index < join_index,
        "placement must fail before reconnect/session registry mutation"
    );
    assert!(realtime.contains("admit_realtime_session_with_sfu_placement"));
    assert!(realtime.contains("leave_realtime_session_with_sfu_placement"));
    assert!(realtime.contains("sfu_placement_transition_guard"));
    assert!(realtime.contains("release_sfu_call_placement_if_inactive"));
    assert!(realtime.contains("rollback_realtime_join(&claims, now).await"));
    assert!(realtime.contains("release_sfu_call_placement_if_inactive"));
    assert!(registry.contains("pub fn active_call_session_count_at"));
    assert!(registry.contains("with_expired_call_cleanup"));
    assert!(registry.contains("track_expired_call_cleanup"));
    assert!(registry.contains("expired_call_cleanup_candidates_at"));
    assert!(registry.contains("acknowledge_expired_call_cleanup"));
    assert!(
        placement.contains("impl<C> RealtimeSfuPlacementLifecycle for GrpcSfuPlacementService<C>")
    );
    assert!(placement.contains("release_session_if_present"));
    assert!(registry.contains("pub fn active_call_session_count_at"));
    assert!(runtime.contains("with_sfu_placement_lifecycle"));
    assert!(runtime.contains("horizontal_sfu: false"));
    let machine_auth_start = runtime
        .find("async fn serve_machine_auth_inner(")
        .expect("machine auth serve");
    let realtime_start = runtime
        .find("async fn serve_realtime_inner(")
        .expect("realtime serve");
    assert!(
        machine_auth_start < realtime_start,
        "expected machine-auth serve before realtime serve in runtime source"
    );
    assert!(
        !runtime[machine_auth_start..realtime_start].contains("sfu_placement_lifecycle"),
        "SFU placement lifecycle gate must never cross-wire into machine-auth config"
    );
    assert!(
        runtime[realtime_start..].contains(".prepare_realtime_listeners("),
        "realtime serve must route listener setup through the guarded preparation path"
    );
    assert!(
        runtime[realtime_start..].contains("if sfu_placement_lifecycle && operator_bind.is_none()"),
        "realtime listener preparation must fail closed without its private operator plane"
    );
    assert!(runtime_main.contains("UCR_SFU_PLACEMENT_LIFECYCLE_ENABLED"));
    assert!(runtime.contains("DEFAULT_SFU_PLACEMENT_EXPIRY_SWEEP_INTERVAL"));
    assert!(runtime.contains("RealtimeSessionRegistry::with_expired_call_cleanup"));
    assert!(runtime.contains("spawn_sfu_placement_expiry_sweeper"));
    assert!(realtime.contains("sweep_expired_sfu_placements_at"));
    assert!(
        spec.contains("The realtime-session binding now has an explicit optional lifecycle gate")
    );
    assert!(spec.contains("bounded expiry sweeper"));
    assert!(spec.contains("cleanup candidate remains pending until"));
}

#[test]
fn horizontal_sfu_realtime_publication_uses_validated_placement_router_and_stays_fail_closed() {
    let realtime = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let router = read("crates/ucr-api-grpc/src/sfu_placement_media_router.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    let spec = read("spec/sfu.md");

    assert!(realtime.contains("pub trait RealtimeSfuMediaRouter"));
    assert!(realtime.contains("pub fn with_sfu_media_router"));
    assert!(realtime.contains("forward_authenticated_e2ee_media_via_configured_route"));
    assert!(realtime.contains(".prepare_forward(&actor_for(claims), device_id, envelope)"));
    assert!(realtime.contains("router.forward_validated_batch(&batch).await"));
    assert!(realtime.contains("SfuValidatedForwardBatch"));

    let placement = read("crates/ucr-api-grpc/src/sfu_placement_service.rs");
    assert!(placement.contains("lifecycle_policy: Option<SfuPlacementPolicy>"));
    assert!(placement.contains(".place_session(scope, call_id, &self.lifecycle_policy"));

    assert!(router.contains("pub fn connect_lazy"));
    assert!(router.contains("impl RealtimeSfuMediaRouter for PlacementAwareSfuNodeRouter"));
    assert!(router.contains("let mut router = self.clone();"));
    assert!(router.contains(".forward_batch(batch)"));
    assert!(router.contains("requires a loopback operator endpoint"));

    assert!(runtime.contains("pub struct SfuPlacementMediaRuntimeConfig"));
    assert!(runtime.contains("configure_sfu_placement_media_router"));
    assert!(runtime.contains("lifecycle_placement_policy"));
    assert!(runtime.contains("GrpcSfuPlacementService::with_lifecycle_policy"));
    assert!(runtime.contains("resolved_operator_endpoint"));
    assert!(runtime.contains("operator_incoming.as_ref().map(|(_, address)| *address)"));
    assert!(runtime.contains("PlacementAwareSfuNodeRouter::connect_lazy"));
    assert!(runtime.contains("with_sfu_media_router"));
    assert!(runtime.contains("route_webrtc_e2ee_frame_via_configured_route"));
    assert!(runtime.contains("SFU placement media routing requires the placement lifecycle gate"));
    assert!(runtime.contains("horizontal_sfu: false"));

    assert!(runtime_main.contains("UCR_SFU_PLACEMENT_MEDIA_ENABLED"));
    assert!(runtime_main.contains("UCR_SFU_ROUTER_CLIENT_CERT_FILE"));
    assert!(runtime_main.contains("UCR_SFU_ROUTER_CLIENT_KEY_FILE"));
    assert!(runtime_main.contains("UCR_SFU_ROUTER_SERVER_CA_FILE"));
    assert!(runtime_main.contains("UCR_SFU_ROUTER_SERVER_NAME"));

    assert!(spec.contains("placement-aware realtime media routing gate"));
    assert!(spec.contains("gRPC `PublishMedia`"));
    assert!(spec.contains("WebRTC E2EE ingress"));
    assert!(spec.contains("horizontal_sfu"));
}
