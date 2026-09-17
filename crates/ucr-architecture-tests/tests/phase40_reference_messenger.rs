use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase40_reference_messenger_has_only_public_ucr_dependency() {
    let cargo = read("crates/ucr-reference-messenger/Cargo.toml");
    let workspace_cargo = read("Cargo.toml");
    let client = read("crates/ucr-reference-messenger/src/client.rs");

    assert!(cargo.contains("ucr-sdk = { path = \"../ucr-sdk\" }"));
    for forbidden in [
        "ucr-core",
        "ucr-storage-memory",
        "ucr-storage-sqlite",
        "ucr-chat",
        "ucr-offline-groups",
        "ucr-store-forward",
        "ucr-transport-internet",
        "ucr-organization-mode",
    ] {
        assert!(
            !cargo.contains(forbidden),
            "hidden Reference Messenger dependency: {forbidden}"
        );
    }
    assert!(workspace_cargo.contains("\"crates/ucr-reference-messenger\""));
    assert!(client.contains("use ucr_sdk::"));
    assert!(!client.contains("ucr_core"));
    assert!(!client.contains("ucr_storage"));
}

#[test]
fn phase40_calls_are_reachable_through_the_same_public_sdk_boundary() {
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let contract = read("sdk/contract.json");
    let call_proto = read("proto/ucr/v1/call.proto");

    assert!(contract.contains("\"CallService\""));
    assert!(call_proto.contains("service CallService"));
    for method in ["start_call", "get_call", "signal_call"] {
        assert!(sdk.contains(&format!("pub async fn {method}")));
    }
    assert!(sdk.contains("pb::call_service_client::CallServiceClient<Channel>"));
    assert!(sdk.contains("ucr-service-credential-id-bin"));
    assert!(sdk.contains("ucr-service-credential-secret-bin"));
}

#[test]
fn phase40_closes_all_nine_areas_without_hidden_apis() {
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/reference-messenger.md");
    let adr = read("docs/adr/0078-phase40-reference-messenger-is-a-public-api-consumer.md");

    for required in [
        "Chat",
        "Groups",
        "Calls",
        "MultiDevice",
        "Local",
        "Offline",
        "P2p",
        "Recovery",
        "Accessibility",
    ] {
        assert!(
            capability.contains(required),
            "missing Phase-40 proof area: {required}"
        );
    }
    assert_eq!(
        capability
            .matches("state: ProofState::PublicApiGap")
            .count(),
        0
    );
    assert!(capability.contains("ConcretePlatformEvidence"));
    assert!(
        spec.contains("All nine Canon proof areas now have explicit Reference Messenger evidence")
    );
    assert!(spec.contains("Concrete browser accessibility evidence"));
    assert!(spec.contains(
        "must not close a gap by linking the Reference Messenger directly to an internal owner"
    ));
    assert!(adr.contains("only UCR dependency is `ucr-sdk`"));
}

#[test]
fn phase40_presentation_contract_is_accessibility_and_localization_ready() {
    let accessibility = read("crates/ucr-reference-messenger/src/accessibility.rs");
    let presentation = read("crates/ucr-reference-messenger/src/presentation.rs");

    for required in [
        "screen_reader_semantics",
        "keyboard_navigation",
        "text_scaling",
        "captions",
        "subtitles",
        "transcription_surfaces",
        "high_contrast",
        "rtl_layout",
    ] {
        assert!(
            accessibility.contains(required),
            "missing accessibility requirement: {required}"
        );
    }
    for concept in ["Person", "Group", "Message", "Call", "Result"] {
        assert!(
            presentation.contains(concept),
            "missing primary user concept: {concept}"
        );
    }
    for forbidden in ["Stun", "Turn", "Quic", "Relay", "ProviderApi"] {
        assert!(
            !presentation.contains(forbidden),
            "infrastructure leaked into primary UX: {forbidden}"
        );
    }
    assert!(presentation.contains("AwaitingDeliveryOpportunity"));
}

#[test]
fn phase40_concrete_browser_accessibility_surface_covers_canon_requirements() {
    let html = read("crates/ucr-reference-messenger/web/index.html");
    let css = read("crates/ucr-reference-messenger/web/styles.css");
    let js = read("crates/ucr-reference-messenger/web/app.js");
    let validator = read("crates/ucr-reference-messenger/web/validate_accessibility.py");
    let readme = read("crates/ucr-reference-messenger/web/README.md");

    for required in [
        "data-ucr-boundary=\"presentation-only\"",
        "role=\"log\"",
        "aria-live=\"polite\"",
        "kind=\"captions\"",
        "kind=\"subtitles\"",
        "id=\"transcript\"",
        "id=\"direction-toggle\"",
        "id=\"text-scale\"",
        "id=\"contrast-toggle\"",
        "dir=\"auto\"",
    ] {
        assert!(
            html.contains(required),
            "missing browser accessibility evidence: {required}"
        );
    }
    for required in [
        ":focus-visible",
        "prefers-contrast: more",
        "forced-colors: active",
        "[dir=\"rtl\"]",
        "1rem",
    ] {
        assert!(
            css.contains(required),
            "missing accessibility CSS evidence: {required}"
        );
    }
    for required in [
        "root.dir = nextDirection",
        "root.dataset.textScale = textScale.value",
        "root.dataset.contrast = \"high\"",
        "setAttribute(\"aria-pressed\"",
    ] {
        assert!(
            js.contains(required),
            "missing interactive accessibility wiring: {required}"
        );
    }
    for forbidden in [
        "fetch(",
        "WebSocket",
        "RTCPeerConnection",
        "navigator.mediaDevices",
    ] {
        assert!(
            !js.contains(forbidden),
            "browser presentation leaked capability: {forbidden}"
        );
    }
    assert!(validator.contains("positive tabindex is forbidden"));
    assert!(validator.contains("ACCESSIBILITY_WEB_EVIDENCE_OK"));
    assert!(readme.contains("presentation-only"));
    assert!(readme.contains("public SDK/API"));
}

#[test]
fn phase40_groups_use_public_service_and_existing_canonical_owners() {
    let proto = read("proto/ucr/v1/group_api.proto");
    let ingress = read("crates/ucr-core/src/integration_api.rs");
    let grpc = read("crates/ucr-api-grpc/src/lib.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let adr =
        read("docs/adr/0079-phase40-group-service-reuses-canonical-group-and-message-owners.md");

    assert!(proto.contains("service GroupService"));
    for rpc in [
        "rpc CreateGroup",
        "rpc GetGroup",
        "rpc GetMembership",
        "rpc ListMemberships",
        "rpc ApplyChange",
        "rpc SendGroupMessage",
        "rpc GetGroupMessage",
    ] {
        assert!(proto.contains(rpc), "missing public Group RPC: {rpc}");
    }
    assert!(proto.contains("OfflineGroupChange change"));
    assert!(ingress.contains("CONVERSATION_WRITE_PERMISSION"));
    assert!(ingress.contains("GROUP_CREATE_PERMISSION"));
    assert!(ingress.contains("GroupMessageStore"));
    assert!(grpc.contains("pb::group_service_server::GroupService"));
    assert!(sdk.contains("pb::group_service_client::GroupServiceClient<Channel>"));
    assert!(capability.contains("GroupService lifecycle/membership/message RPCs"));
    assert!(adr.contains("writes a separate audit decision"));
    assert!(adr.contains("does not consume request quota twice"));
}
#[test]
fn phase40_multidevice_uses_public_device_sync_services_and_existing_canonical_owners() {
    let proto = read("proto/ucr/v1/device_sync_api.proto");
    let ingress = read("crates/ucr-core/src/integration_api.rs");
    let grpc = read("crates/ucr-api-grpc/src/lib.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let adr =
        read("docs/adr/0080-phase40-device-and-sync-services-reuse-canonical-lifecycle-owners.md");

    assert!(proto.contains("service DeviceService"));
    assert!(proto.contains("service SyncService"));
    for rpc in [
        "rpc RegisterDevice",
        "rpc GetDevice",
        "rpc RevokeDevice",
        "rpc CreateSyncSession",
        "rpc GetSyncSession",
        "rpc TransitionSync",
        "rpc RecordSyncCheckpoint",
        "rpc GetLatestSyncCheckpoint",
    ] {
        assert!(
            proto.contains(rpc),
            "missing public multi-device RPC: {rpc}"
        );
    }
    assert!(ingress.contains("DeviceLifecycleStore"));
    assert!(ingress.contains("SyncStore"));
    assert!(grpc.contains("pb::device_service_server::DeviceService"));
    assert!(grpc.contains("pb::sync_service_server::SyncService"));
    assert!(sdk.contains("pb::device_service_client::DeviceServiceClient<Channel>"));
    assert!(sdk.contains("pb::sync_service_client::SyncServiceClient<Channel>"));
    assert!(client.contains("self.sdk.register_device(request).await"));
    assert!(client.contains("self.sdk.create_sync_session(request).await"));
    assert!(capability.contains("DeviceService lifecycle + SyncService session/checkpoint RPCs"));
    assert!(
        adr.contains("Resume tokens are canonical opaque source-issued cursors")
            || adr.contains("resume tokens are canonical opaque source-issued cursors")
    );
}

#[test]
fn phase40_multidevice_does_not_move_sync_brain_into_public_sdk() {
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let reference = read("crates/ucr-reference-messenger/src/client.rs");
    let spec = read("spec/device-sync-api.md");

    for forbidden in [
        "anti_entropy_session",
        "TransportOrchestrator",
        "StoreForwardJob",
        "retry_sync",
        "merge_checkpoint",
    ] {
        assert!(
            !sdk.contains(forbidden),
            "SDK acquired sync-brain symbol: {forbidden}"
        );
        assert!(
            !reference.contains(forbidden),
            "Reference Messenger acquired sync-brain symbol: {forbidden}"
        );
    }
    assert!(spec.contains("resume tokens remain opaque"));
    assert!(spec.contains("no automatic retry, anti-entropy, route selection or transport state"));
}

#[test]
fn phase40_offline_uses_public_store_forward_service_without_exporting_worker_brain() {
    let proto = read("proto/ucr/v1/store_forward.proto");
    let owner = read("crates/ucr-store-forward/src/lib.rs");
    let grpc = read("crates/ucr-api-grpc/src/lib.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/store-forward-api.md");
    let adr =
        read("docs/adr/0081-phase40-store-forward-service-reuses-canonical-scheduler-owner.md");

    assert!(proto.contains("service StoreForwardService"));
    assert!(proto.contains("rpc Enqueue"));
    assert!(proto.contains("rpc GetStatus"));
    for forbidden_rpc in ["Claim", "Due", "Process", "Retry", "Route", "Transmit"] {
        assert!(
            !proto.contains(&format!("rpc {forbidden_rpc}")),
            "worker/scheduler control leaked into public StoreForwardService: {forbidden_rpc}"
        );
    }
    let status = proto
        .split("message StoreForwardStatus")
        .nth(1)
        .and_then(|tail| tail.split("message StoreForwardEnqueueRequest").next())
        .expect("StoreForwardStatus section");
    for forbidden in [
        "encrypted_envelope",
        "lease_id",
        "lease_duration_ms",
        "EndpointAddress",
    ] {
        assert!(
            !status.contains(forbidden),
            "private field leaked into public status: {forbidden}"
        );
    }

    assert!(owner.contains("pub struct StoreForwardIngress"));
    assert!(owner.contains("enqueue_canonical_job(self.store, job)"));
    assert!(grpc.contains("StoreForwardIngress::new"));
    assert!(grpc.contains("pb::store_forward_service_server::StoreForwardService"));
    assert!(sdk.contains("pb::store_forward_service_client::StoreForwardServiceClient<Channel>"));
    assert!(sdk.contains("pub async fn enqueue_store_forward"));
    assert!(sdk.contains("pub async fn get_store_forward_status"));
    assert!(client.contains("self.sdk.enqueue_store_forward(request).await"));
    assert!(client.contains("self.sdk.get_store_forward_status(request).await"));
    assert!(capability.contains("StoreForwardService enqueue + payload-free status RPCs"));
    assert!(spec.contains("Worker orchestration remains internal"));
    assert!(adr.contains("No second enqueue implementation is permitted"));
}

#[test]
fn phase40_local_uses_public_service_and_existing_phase16_provider() {
    let proto = read("proto/ucr/v1/local_transport_api.proto");
    let phase16 = read("crates/ucr-transport-internet/src/local.rs");
    let grpc = read("crates/ucr-api-grpc/src/lib.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/local-transport-api.md");
    let adr = read("docs/adr/0082-phase40-local-transport-service-reuses-phase16-provider.md");

    assert!(proto.contains("service LocalTransportService"));
    assert!(proto.contains("rpc Transmit"));
    assert_eq!(proto.matches("rpc ").count(), 1);
    let route = proto
        .split("message LocalTransportRoute")
        .nth(1)
        .and_then(|tail| tail.split("enum LocalTransportFailureDisposition").next())
        .expect("LocalTransportRoute section");
    assert!(route.contains("destination_endpoint_id"));
    assert!(route.contains("EndpointAddress address"));
    assert!(!route.contains("transport_capability"));

    assert!(phase16.contains("impl TransportProvider for LocalTransportProvider"));
    assert!(phase16.contains("transmit_classified_inner"));
    assert!(grpc.contains("GrpcLocalTransportService"));
    assert!(grpc.contains("LocalTransportProvider"));
    assert!(grpc.contains("provider.transmit_classified"));
    assert!(grpc.contains("tokio::task::spawn_blocking"));
    assert!(grpc.contains("LOCAL_TRANSPORT_USE_PERMISSION"));
    assert!(grpc.contains("SERVICE_AUDIT_LOCAL_TRANSPORT_TRANSMIT_OPERATION_KIND"));
    assert!(
        sdk.contains("pb::local_transport_service_client::LocalTransportServiceClient<Channel>")
    );
    assert!(sdk.contains("pub async fn transmit_local"));
    assert!(client.contains("self.sdk.transmit_local(request).await"));
    assert!(capability.contains("LocalTransportService authenticated direct transmit RPC"));
    assert!(capability.contains("MeshService authenticated peer export/reconcile RPCs"));
    assert!(spec.contains("Success means only authenticated peer-side transport acceptance"));
    assert!(spec.contains("No retry is added above the provider"));
    assert!(
        adr.contains("does not make Phase 40 complete")
            || spec.contains("does not make Phase 40 complete")
    );
}

#[test]
fn phase40_p2p_uses_public_mesh_service_without_exporting_topology_brain() {
    let proto = read("proto/ucr/v1/mesh_api.proto");
    let grpc = read("crates/ucr-api-grpc/src/mesh_service.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/mesh-api.md");
    let adr = read("docs/adr/0083-phase40-mesh-service-reuses-phase28-runtime.md");

    assert!(proto.contains("service MeshService"));
    assert!(proto.contains("rpc ExportGroupMessages"));
    assert!(proto.contains("rpc ReconcileGroupMessage"));
    for forbidden in [
        "PeerAddress peer",
        "RouteCandidate route",
        "string transport_capability",
        "rpc Discover",
        "rpc SelectRoute",
        "rpc Retry",
        "uint32 retry",
    ] {
        assert!(
            !proto.contains(forbidden),
            "topology/routing control leaked into MeshService: {forbidden}"
        );
    }
    assert!(grpc.contains("MeshGroupsRuntime::new"));
    assert!(grpc.contains("MeshPeerSessionResolver"));
    assert!(grpc.contains("SYNC_READ_PERMISSION"));
    assert!(grpc.contains("SYNC_WRITE_PERMISSION"));
    assert!(sdk.contains("pb::mesh_service_client::MeshServiceClient<Channel>"));
    assert!(sdk.contains("pub async fn export_mesh_group_messages"));
    assert!(sdk.contains("pub async fn reconcile_mesh_group_message"));
    assert!(client.contains("self.sdk.export_mesh_group_messages(request).await"));
    assert!(client.contains("self.sdk.reconcile_mesh_group_message(request).await"));
    assert!(capability.contains("MeshService authenticated peer export/reconcile RPCs"));
    assert!(spec.contains(
        "does not expose discovery, topology, NAT traversal, Relay, route selection or retry"
    ));
    assert!(adr.contains("existing Phase-28 `MeshGroupsRuntime` remains the canonical Mesh owner"));
}
#[test]
fn phase40_recovery_uses_public_service_and_existing_proof_gates() {
    let proto = read("proto/ucr/v1/recovery_api.proto");
    let workflow = read("crates/ucr-core/src/recovery_workflow.rs");
    let grpc = read("crates/ucr-api-grpc/src/recovery_service.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/recovery-api.md");
    let adr = read("docs/adr/0084-phase40-recovery-service-reuses-canonical-proof-gates.md");

    assert!(proto.contains("service RecoveryService"));
    for rpc in [
        "rpc InstallPlan",
        "rpc RotatePlan",
        "rpc RevokePlan",
        "rpc GetActivePlan",
        "rpc StageRecoveredDevice",
        "rpc ActivateRecoveredDevice",
    ] {
        assert!(proto.contains(rpc), "missing public Recovery RPC: {rpc}");
    }
    assert!(workflow.contains("pub struct RecoveryPlanIngress"));
    assert!(workflow.contains("pub struct RecoveryExecutionIngress"));
    assert!(workflow.contains("RecoveryRequestGate"));
    assert!(workflow.contains("DeviceReverificationGate"));
    assert!(workflow.contains("RECOVERY_STAGE_PERMISSION"));
    assert!(workflow.contains("RECOVERY_ACTIVATE_PERMISSION"));
    assert!(grpc.contains("RecoveryExecutionIngress::new"));
    assert!(!grpc.contains("authorize_and_stage_recovered_device("));
    assert!(!grpc.contains("authorize_and_activate_reverified_device("));
    assert!(sdk.contains("pb::recovery_service_client::RecoveryServiceClient<Channel>"));
    assert!(sdk.contains("pub async fn stage_recovered_device"));
    assert!(sdk.contains("pub async fn activate_recovered_device"));
    assert!(client.contains("self.sdk.stage_recovered_device(request).await"));
    assert!(client.contains("self.sdk.activate_recovered_device(request).await"));
    assert!(capability.contains("RecoveryService plan + proof-gated Device recovery RPCs"));
    assert!(spec.contains("An ordinary `PermissionGrant` is not recovery authority"));
    assert!(adr.contains("independent verifier decision remains mandatory"));
}

#[test]
fn phase40_recovery_does_not_move_recovery_brain_into_sdk_or_reference_client() {
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let client = read("crates/ucr-reference-messenger/src/client.rs");
    for forbidden in [
        "RecoveryRequestGate",
        "RecoveryAuthorityVerifier",
        "DeviceReverificationGate",
        "DeviceReverificationVerifier",
        "RecoveryDeviceStagingStore",
        "ReverifiedDeviceActivationStore",
    ] {
        assert!(
            !sdk.contains(forbidden),
            "SDK acquired recovery-brain symbol: {forbidden}"
        );
        assert!(
            !client.contains(forbidden),
            "Reference Messenger acquired recovery-brain symbol: {forbidden}"
        );
    }
}

#[test]
fn phase40_dev_mode_keeps_auth_on_and_exercises_public_api() {
    let workspace = read("Cargo.toml");
    let dev = read("crates/ucr-dev/src/lib.rs");
    let cli = read("crates/ucr-dev/src/main.rs");
    let spec = read("spec/dev-mode.md");
    let adr = read("docs/adr/0086-phase40-dev-mode-composes-canonical-owners-behind-public-api.md");

    assert!(workspace.contains("\"crates/ucr-dev\""));
    for required in [
        "MemoryLocalStore::default()",
        "issue_service_credential",
        "RUNTIME_PERMISSION_IDS",
        "SystemServiceQuotaClock",
        "integration_service_server",
        "group_service_server",
        "call_service_server",
        "verify_integration_round_trip",
        "verify_group_round_trip",
        "verify_call_round_trip",
        "127.0.0.1:50051",
        "is_loopback()",
    ] {
        assert!(
            dev.contains(required),
            "missing Dev Mode evidence: {required}"
        );
    }
    for scenario in [
        "message",
        "delivery",
        "group",
        "call",
        "retry",
        "failure",
        "offline",
        "reconnect",
        "bridge-degradation",
    ] {
        assert!(
            dev.contains(scenario),
            "missing sandbox scenario: {scenario}"
        );
    }
    for fault in [
        "Delay",
        "Drop",
        "Duplicate",
        "Reorder",
        "Disconnect",
        "Corrupt",
        "Throttle",
    ] {
        assert!(dev.contains(fault), "missing TestTransport fault: {fault}");
    }
    assert!(dev.contains("pub fn reconnect"));
    assert!(cli.contains("Some(\"dev\")"));
    assert!(cli.contains("\"--check\""));
    assert!(cli.contains("\"--simulate\""));
    assert!(cli.contains("refuses non-loopback bind addresses"));
    assert!(spec.contains("Authentication, authorization and quota admission remain enabled"));
    assert!(spec.contains("Full cross-implementation behavior and conformance remain Phase 41"));
    assert!(
        adr.contains("no second Message, Group, Call, Delivery, Identity, routing or retry owner")
    );
}
