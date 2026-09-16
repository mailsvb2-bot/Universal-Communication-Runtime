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

    capability = (CRATE / "src/capability.rs").read_text(encoding="utf-8")
    for item in ("Chat", "Groups", "Calls", "MultiDevice", "Local", "Offline", "P2p", "Recovery", "Accessibility"):
        require(item in capability, f"Phase-40 proof area missing: {item}")
    require(capability.count("ProofState::PublicApiGap") == 6, "Phase-40 public API gap count drifted")
    require("ProofState::PresentationModelOnly" in capability, "accessibility maturity gap hidden")

    accessibility = (CRATE / "src/accessibility.rs").read_text(encoding="utf-8")
    for item in ("screen_reader_semantics", "keyboard_navigation", "text_scaling", "captions", "subtitles", "transcription_surfaces", "high_contrast", "rtl_layout"):
        require(item in accessibility, f"accessibility requirement missing: {item}")

    presentation = (CRATE / "src/presentation.rs").read_text(encoding="utf-8")
    for forbidden in ("Stun", "Turn", "Quic", "Relay", "ProviderApi"):
        require(forbidden not in presentation, f"infrastructure leaked into primary UX: {forbidden}")
    require("AwaitingDeliveryOpportunity" in presentation, "offline waiting UX missing")

    spec = (ROOT / "spec/reference-messenger.md").read_text(encoding="utf-8")
    require("Phase 40 is incomplete" in spec, "Phase 40 completion is overclaimed")
    require("PublicApiGap" in spec, "public API blockers hidden from spec")


if __name__ == "__main__":
    main()
