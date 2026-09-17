#!/usr/bin/env python3
"""Dependency-free Phase 40 Reference Messenger purity/proof guard."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates/ucr-reference-messenger"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    cargo = (CRATE / "Cargo.toml").read_text(encoding="utf-8")
    require('ucr-sdk = { path = "../ucr-sdk" }' in cargo, "Reference Messenger must depend on public ucr-sdk")
    for forbidden in (
        "ucr-core",
        "ucr-storage",
        "ucr-chat",
        "ucr-offline-groups",
        "ucr-store-forward",
        "ucr-transport-internet",
        "ucr-organization-mode",
    ):
        require(forbidden not in cargo, f"hidden/internal dependency present: {forbidden}")

    workspace = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    require('"crates/ucr-reference-messenger"' in workspace, "Reference Messenger must remain outside internal workspace")

    sdk = (ROOT / "crates/ucr-sdk/src/lib.rs").read_text(encoding="utf-8")
    require("pb::call_service_client::CallServiceClient<Channel>" in sdk, "public SDK missing CallService client")
    for method in ("start_call", "get_call", "signal_call"):
        require(f"pub async fn {method}" in sdk, f"public SDK missing {method}")
    require("pb::group_service_client::GroupServiceClient<Channel>" in sdk, "public SDK missing GroupService client")
    for method in ("create_group", "get_group", "get_group_membership", "list_group_memberships", "apply_group_change", "send_group_message", "get_group_message"):
        require(f"pub async fn {method}" in sdk, f"public SDK missing {method}")
    require("pb::device_service_client::DeviceServiceClient<Channel>" in sdk, "public SDK missing DeviceService client")
    require("pb::sync_service_client::SyncServiceClient<Channel>" in sdk, "public SDK missing SyncService client")
    require("pb::store_forward_service_client::StoreForwardServiceClient<Channel>" in sdk, "public SDK missing StoreForwardService client")
    require("pb::local_transport_service_client::LocalTransportServiceClient<Channel>" in sdk, "public SDK missing LocalTransportService client")
    require("pb::mesh_service_client::MeshServiceClient<Channel>" in sdk, "public SDK missing MeshService client")
    require("pb::recovery_service_client::RecoveryServiceClient<Channel>" in sdk, "public SDK missing RecoveryService client")
    for method in ("register_device", "get_device", "revoke_device", "create_sync_session", "get_sync_session", "transition_sync", "record_sync_checkpoint", "get_latest_sync_checkpoint"):
        require(f"pub async fn {method}" in sdk, f"public SDK missing {method}")

    capability = (CRATE / "src/capability.rs").read_text(encoding="utf-8")
    for item in ("Chat", "Groups", "Calls", "MultiDevice", "Local", "Offline", "P2p", "Recovery", "Accessibility"):
        require(item in capability, f"Phase-40 proof area missing: {item}")
    require(capability.count("ProofState::PublicApiGap") == 0, "Phase-40 public API gaps must be closed")
    require("ProofState::PresentationModelOnly" in capability, "accessibility maturity gap hidden")

    accessibility = (CRATE / "src/accessibility.rs").read_text(encoding="utf-8")
    for item in ("screen_reader_semantics", "keyboard_navigation", "text_scaling", "captions", "subtitles", "transcription_surfaces", "high_contrast", "rtl_layout"):
        require(item in accessibility, f"accessibility requirement missing: {item}")

    presentation = (CRATE / "src/presentation.rs").read_text(encoding="utf-8")
    for forbidden in ("Stun", "Turn", "Quic", "Relay", "ProviderApi"):
        require(forbidden not in presentation, f"infrastructure leaked into primary UX: {forbidden}")
    require("AwaitingDeliveryOpportunity" in presentation, "offline waiting UX missing")
    group_proto = (ROOT / "proto/ucr/v1/group_api.proto").read_text(encoding="utf-8")
    require("service GroupService" in group_proto, "public GroupService missing")
    require("OfflineGroupChange change" in group_proto, "GroupService invented a second mutation vocabulary")
    require("GroupService lifecycle/membership/message RPCs" in capability, "Groups not marked with public evidence")
    multi_proto = (ROOT / "proto/ucr/v1/device_sync_api.proto").read_text(encoding="utf-8")
    require("service DeviceService" in multi_proto, "public DeviceService missing")
    require("service SyncService" in multi_proto, "public SyncService missing")
    require("DeviceService lifecycle + SyncService session/checkpoint RPCs" in capability, "Multi-device not marked with public evidence")
    store_forward_proto = (ROOT / "proto/ucr/v1/store_forward.proto").read_text(encoding="utf-8")
    require("service StoreForwardService" in store_forward_proto, "public StoreForwardService missing")
    require("StoreForwardService enqueue + payload-free status RPCs" in capability, "Offline not marked with public evidence")
    local_proto = (ROOT / "proto/ucr/v1/local_transport_api.proto").read_text(encoding="utf-8")
    require("service LocalTransportService" in local_proto, "public LocalTransportService missing")
    require("LocalTransportFailureDisposition" in local_proto, "local acceptance classification missing")
    require("LocalTransportService authenticated direct transmit RPC" in capability, "Local not marked with public evidence")
    mesh_proto = (ROOT / "proto/ucr/v1/mesh_api.proto").read_text(encoding="utf-8")
    require("service MeshService" in mesh_proto, "public MeshService missing")
    require("MeshService authenticated peer export/reconcile RPCs" in capability, "P2P not marked with public evidence")
    recovery_proto = (ROOT / "proto/ucr/v1/recovery_api.proto").read_text(encoding="utf-8")
    require("service RecoveryService" in recovery_proto, "public RecoveryService missing")
    for rpc in ("InstallPlan", "RotatePlan", "RevokePlan", "GetActivePlan", "StageRecoveredDevice", "ActivateRecoveredDevice"):
        require(f"rpc {rpc}" in recovery_proto, f"RecoveryService missing {rpc}")
    require("RecoveryService plan + proof-gated Device recovery RPCs" in capability, "Recovery not marked with public evidence")
    local_spec = (ROOT / "spec/local-transport-api.md").read_text(encoding="utf-8")
    require("existing Phase-16 local/direct transport owner" in local_spec, "Local public API owner reuse missing")
    require("NotAccepted" in local_spec and "AcceptanceUnknown" in local_spec, "Local failure ambiguity hidden")
    client = (CRATE / "src/client.rs").read_text(encoding="utf-8")
    require("self.sdk.enqueue_store_forward(request).await" in client, "Reference Messenger missing offline enqueue")
    require("self.sdk.get_store_forward_status(request).await" in client, "Reference Messenger missing offline status read")
    require("self.sdk.transmit_local(request).await" in client, "Reference Messenger missing direct local transmit")
    require("self.sdk.export_mesh_group_messages(request).await" in client, "Reference Messenger missing P2P export")
    require("self.sdk.reconcile_mesh_group_message(request).await" in client, "Reference Messenger missing P2P reconcile")
    for method in ("install_recovery_plan", "rotate_recovery_plan", "revoke_recovery_plan", "get_active_recovery_plan", "stage_recovered_device", "activate_recovered_device"):
        require(f"self.sdk.{method}(request).await" in client, f"Reference Messenger missing Recovery method: {method}")

    spec = (ROOT / "spec/reference-messenger.md").read_text(encoding="utf-8")
    require("Concrete platform accessibility" in spec or "concrete platform accessibility" in spec, "Phase 40 accessibility blocker hidden")
    require("Recovery | Public API available" in spec, "Recovery public proof hidden from spec")
    require("Accessibility | Presentation model only" in spec, "accessibility blocker hidden from spec")


if __name__ == "__main__":
    main()
