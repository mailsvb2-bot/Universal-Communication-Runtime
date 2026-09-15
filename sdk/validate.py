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


if __name__ == "__main__":
    main()
