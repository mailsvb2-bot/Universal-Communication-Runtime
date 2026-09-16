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
fn phase40_keeps_required_proof_gaps_visible_instead_of_using_hidden_apis() {
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
    assert!(capability.contains("PublicApiGap"));
    assert!(capability.contains("PresentationModelOnly"));
    assert!(spec.contains("Phase 40 is incomplete"));
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
