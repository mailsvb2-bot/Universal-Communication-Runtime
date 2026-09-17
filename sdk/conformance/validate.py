#!/usr/bin/env python3
"""Fail-closed Phase-41 SDK conformance matrix validator."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "sdk/conformance/matrix.json"
CONTRACT = ROOT / "sdk/contract.json"
CATEGORIES = [
    "auth",
    "commands",
    "events",
    "retries",
    "permissions",
    "version_negotiation",
    "errors",
    "idempotency",
]
LANGUAGES = ["rust", "python", "typescript", "kotlin", "swift"]
ID_KEY = "ucr-service-credential-id-bin"
SECRET_KEY = "ucr-service-credential-secret-bin"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def read(path: str) -> str:
    file = ROOT / path
    require(file.is_file(), f"missing Phase-41 evidence: {path}")
    return file.read_text(encoding="utf-8")


def main() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    require(matrix["schema_version"] == 1, "unsupported conformance matrix schema")
    require(matrix["phase"] == 41, "conformance matrix is not Phase 41")
    require(matrix["maturity"] == "prepared", "Phase 41 overclaims maturity")
    require(matrix["profile"] == "sdk", "unexpected Phase-41 profile")
    require(matrix["protocol_package"] == contract["protocol_package"] == "ucr.v1", "protocol package drifted")
    require(matrix["required_categories"] == CATEGORIES, "canonical SDK conformance categories drifted")
    require(matrix["required_languages"] == LANGUAGES, "required SDK language set drifted")
    require(contract["languages"] == LANGUAGES, "Phase-39 SDK language set drifted")

    expected_levels = {
        "rust": ["contract", "host-probe", "runtime-binding"],
        "python": ["contract", "host-probe"],
        "typescript": ["contract", "host-probe"],
        "kotlin": ["contract", "host-probe"],
        "swift": ["contract", "host-probe"],
    }
    for language in LANGUAGES:
        evidence = matrix["languages"].get(language)
        require(isinstance(evidence, dict), f"missing language evidence: {language}")
        require(evidence.get("levels") == expected_levels[language], f"evidence level drifted: {language}")
        helper = evidence.get("helper")
        probe = evidence.get("probe")
        require(isinstance(helper, str) and (ROOT / helper).is_file(), f"missing helper: {language}")
        require(isinstance(probe, str) and (ROOT / probe).is_file(), f"missing probe: {language}")

        helper_source = read(helper)
        require(ID_KEY in helper_source, f"credential id metadata drifted: {language}")
        require(SECRET_KEY in helper_source, f"credential secret metadata drifted: {language}")
        require("[REDACTED]" in helper_source, f"credential redaction missing: {language}")
        lowered = helper_source.lower()
        for forbidden in ("ucr-storage", "ucr_core", "ucr-core", "sqlite"):
            require(forbidden not in lowered, f"SDK helper imports canonical owner {forbidden}: {language}")

    semantics = contract["semantics"]
    require(semantics["automatic_application_retry"] is False, "hidden SDK retry enabled")
    require(semantics["event_cursor"] == "opaque", "Event cursor ceased to be opaque")
    require(semantics["canonical_errors_preserved"] is True, "canonical errors are not preserved")
    require(semantics["direct_database_access"] is False, "SDK direct database access enabled")

    integration = read("proto/ucr/v1/integration.proto")
    events = read("proto/ucr/v1/event_api.proto")
    runtime = read("proto/ucr/v1/runtime.proto")
    errors = read("proto/ucr/v1/errors.proto")
    public_sdks = read("spec/public-sdks.md")

    for marker in (
        "rpc SubmitCommand(IntegrationCommandRequest)",
        "CommandEnvelope command = 1;",
        "rpc SendMessage(IntegrationSendMessageRequest)",
    ):
        require(marker in integration, f"command contract anchor missing: {marker}")
    for marker in (
        "bytes token = 1;",
        "rpc PublishEvent(EventPublishRequest)",
        "rpc PollEvents(EventPollRequest)",
        "rpc AcknowledgeEvents(EventAcknowledgeRequest)",
    ):
        require(marker in events, f"event contract anchor missing: {marker}")
    for marker in (
        "message NegotiationHello",
        "message NegotiationResult",
        "OpaqueId command_id = 1;",
        "COMMAND_RECEIPT_STATUS_DUPLICATE",
    ):
        require(marker in runtime, f"runtime conformance anchor missing: {marker}")
    for marker in (
        "ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION",
        "ERROR_CODE_DOWNGRADE_REJECTED",
        "ERROR_CODE_PERMISSION_DENIED",
        "message ErrorEnvelope",
    ):
        require(marker in errors, f"error conformance anchor missing: {marker}")
    require("There is no hidden automatic application retry" in public_sdks, "retry boundary documentation drifted")
    require("Phase 41 owns the complete SDK conformance matrix" in public_sdks, "Phase-39 handoff to Phase 41 disappeared")

    workflow = read(".github/workflows/conformance.yml")
    for marker in (
        "python3 sdk/conformance/validate.py",
        "sdk/python/phase41_conformance.py",
        "sdk/typescript/phase41_conformance.ts",
        "Phase41Conformance.kt",
        "sdk/swift/Tests/main.swift",
        "--test phase41_conformance",
    ):
        require(marker in workflow, f"Phase-41 workflow evidence missing: {marker}")
    require("continue-on-error" not in workflow, "Phase-41 workflow permits soft failure")
    require("|| true" not in workflow, "Phase-41 workflow masks failures")

    spec = read("spec/conformance-suite.md")
    adr = read("docs/adr/0087-phase41-conformance-suite-is-language-independent-and-fail-closed.md")
    require("eight semantic areas" in spec, "Phase-41 spec lost canonical eight-axis scope")
    require("not a new runtime" in spec, "Phase-41 second-brain boundary disappeared")
    require("Missing probes" in adr, "Phase-41 ADR lost fail-closed decision")

    print("UCR_PHASE41_CONFORMANCE_MATRIX_OK")


if __name__ == "__main__":
    main()
