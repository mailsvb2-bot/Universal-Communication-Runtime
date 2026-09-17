#!/usr/bin/env python3
"""Dependency-free Phase 39 source/contract guard."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk"
ID_KEY = "ucr-service-credential-id-bin"
SECRET_KEY = "ucr-service-credential-secret-bin"
LANGUAGES = ["rust", "python", "typescript", "kotlin", "swift"]
HELPERS = [
    ROOT / "crates/ucr-sdk/src/lib.rs",
    SDK / "python/ucr_sdk/auth.py",
    SDK / "typescript/src/auth.ts",
    SDK / "kotlin/src/main/kotlin/org/ucr/sdk/ServiceCredential.kt",
    SDK / "swift/Sources/UCRSDK/ServiceCredential.swift",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    manifest = json.loads((SDK / "contract.json").read_text(encoding="utf-8"))
    require(manifest["protocol_package"] == "ucr.v1", "wrong protocol package")
    require(manifest["languages"] == LANGUAGES, "required SDK language set drifted")
    require(
        manifest["services"] == ["IntegrationService", "EventService", "CallService", "GroupService", "DeviceService", "SyncService", "StoreForwardService", "LocalTransportService", "MeshService", "RecoveryService"],
        "required SDK service set drifted",
    )
    auth = manifest["authentication"]
    require(auth["credential_id_key"] == ID_KEY, "credential id metadata drifted")
    require(auth["credential_secret_key"] == SECRET_KEY, "credential secret metadata drifted")
    semantics = manifest["semantics"]
    require(semantics["automatic_application_retry"] is False, "hidden retry enabled")
    require(semantics["event_cursor"] == "opaque", "event cursor ceased to be opaque")
    require(semantics["canonical_errors_preserved"] is True, "canonical errors not preserved")
    require(semantics["direct_database_access"] is False, "SDK direct DB access enabled")

    for helper in HELPERS:
        require(helper.is_file(), f"missing SDK helper: {helper.relative_to(ROOT)}")
        text = helper.read_text(encoding="utf-8")
        require(ID_KEY in text, f"credential id key missing from {helper.relative_to(ROOT)}")
        require(SECRET_KEY in text, f"credential secret key missing from {helper.relative_to(ROOT)}")
        require("[REDACTED]" in text, f"secret redaction missing from {helper.relative_to(ROOT)}")
        lowered = text.lower()
        for forbidden in ("sqlite", "ucr-storage", "ucr_core", "ucr-core"):
            require(forbidden not in lowered, f"forbidden SDK owner dependency {forbidden}: {helper}")

    rust_cargo = (ROOT / "crates/ucr-sdk/Cargo.toml").read_text(encoding="utf-8")
    for forbidden in ("ucr-core", "ucr-storage-memory", "ucr-storage-sqlite"):
        require(forbidden not in rust_cargo, f"Rust SDK depends on {forbidden}")
    build = (ROOT / "crates/ucr-sdk/build.rs").read_text(encoding="utf-8")
    require(".build_client(true)" in build, "Rust SDK client generation disabled")
    require(".build_server(false)" in build, "Rust SDK unexpectedly generates server code")
    rust_sdk = (ROOT / "crates/ucr-sdk/src/lib.rs").read_text(encoding="utf-8")
    for method in ("start_call", "get_call", "signal_call"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing CallService method: {method}")
    for method in ("create_group", "get_group", "get_group_membership", "list_group_memberships", "apply_group_change", "send_group_message", "get_group_message"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing GroupService method: {method}")
    require("pb::device_service_client::DeviceServiceClient<Channel>" in rust_sdk, "Rust SDK missing DeviceService client")
    require("pb::sync_service_client::SyncServiceClient<Channel>" in rust_sdk, "Rust SDK missing SyncService client")
    require("pb::store_forward_service_client::StoreForwardServiceClient<Channel>" in rust_sdk, "Rust SDK missing StoreForwardService client")
    require("pb::local_transport_service_client::LocalTransportServiceClient<Channel>" in rust_sdk, "Rust SDK missing LocalTransportService client")
    require("pb::mesh_service_client::MeshServiceClient<Channel>" in rust_sdk, "Rust SDK missing MeshService client")
    require("pb::recovery_service_client::RecoveryServiceClient<Channel>" in rust_sdk, "Rust SDK missing RecoveryService client")
    for method in ("register_device", "get_device", "revoke_device", "create_sync_session", "get_sync_session", "transition_sync", "record_sync_checkpoint", "get_latest_sync_checkpoint"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing multi-device method: {method}")
    for method in ("enqueue_store_forward", "get_store_forward_status"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing StoreForwardService method: {method}")
    require("pub async fn transmit_local" in rust_sdk, "Rust SDK missing LocalTransportService transmit")
    for method in ("export_mesh_group_messages", "reconcile_mesh_group_message"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing MeshService method: {method}")
    for method in ("install_recovery_plan", "rotate_recovery_plan", "revoke_recovery_plan", "get_active_recovery_plan", "stage_recovered_device", "activate_recovered_device"):
        require(f"pub async fn {method}" in rust_sdk, f"Rust SDK missing RecoveryService method: {method}")


if __name__ == "__main__":
    main()
