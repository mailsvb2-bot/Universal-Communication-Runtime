#!/usr/bin/env python3
"""Fail-closed UCR Phase 45 production-readiness evidence verifier.

This helper deliberately does not run the underlying tests. CI creates evidence only after
those commands succeed, then this verifier prevents a partial/unknown candidate from being
presented as Production. It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

SCHEMA = "ucr.production-readiness.v1"
PASS = "pass"
NOT_RUN = "not-run"
ALLOWED_STATUS = {PASS, "fail", NOT_RUN}
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# These gates are already expected for every Phase-45 candidate. They correspond to the
# Canon release boundaries and may never be skipped even before platform signing exists.
CANDIDATE_REQUIRED = (
    "security",
    "data_safety",
    "compatibility",
    "conformance",
    "critical_chaos",
    "public_contract",
)

# Production additionally requires real runtime/operational/performance/signing evidence.
PRODUCTION_REQUIRED = CANDIDATE_REQUIRED + (
    "performance",
    "metrics",
    "diagnostics",
    "telemetry_privacy",
    "production_runtime",
    "platform_signing",
)

ALL_GATES = tuple(dict.fromkeys(PRODUCTION_REQUIRED))


class EvidenceError(ValueError):
    """Evidence is missing, malformed, contradictory, or insufficient."""


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read evidence: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError("evidence root must be an object")
    return value


def _validate_shape(document: dict[str, object]) -> None:
    if document.get("schema") != SCHEMA:
        raise EvidenceError(f"schema must be {SCHEMA}")

    commit = document.get("source_commit")
    if not isinstance(commit, str) or SOURCE_COMMIT_RE.fullmatch(commit) is None:
        raise EvidenceError("source_commit must be a lowercase 40-hex commit")

    profile = document.get("build_profile")
    if profile not in {"development", "test", "staging", "production"}:
        raise EvidenceError("build_profile is not canonical")

    claim = document.get("maturity_claim")
    if claim not in {"candidate", "production"}:
        raise EvidenceError("maturity_claim must be candidate or production")

    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise EvidenceError("gates must be an object")
    unknown = set(gates) - set(ALL_GATES)
    if unknown:
        raise EvidenceError(f"unknown gates: {', '.join(sorted(unknown))}")

    for gate_name in ALL_GATES:
        record = gates.get(gate_name)
        if not isinstance(record, dict):
            raise EvidenceError(f"missing gate record: {gate_name}")
        status = record.get("status")
        if status not in ALLOWED_STATUS:
            raise EvidenceError(f"invalid status for {gate_name}")
        evidence = record.get("evidence")
        if not isinstance(evidence, str):
            raise EvidenceError(f"evidence text for {gate_name} must be a string")
        if status == PASS and not evidence.strip():
            raise EvidenceError(f"passing gate lacks evidence: {gate_name}")


def validate(document: dict[str, object], mode: str) -> None:
    _validate_shape(document)
    gates = document["gates"]
    assert isinstance(gates, dict)

    if mode == "candidate":
        if document["maturity_claim"] != "candidate":
            raise EvidenceError("candidate validation forbids a Production maturity claim")
        if document["build_profile"] not in {"staging", "production"}:
            raise EvidenceError("candidate must be built with staging or production profile")
        required = CANDIDATE_REQUIRED
    elif mode == "production":
        if document["maturity_claim"] != "production":
            raise EvidenceError("production validation requires an explicit Production claim")
        if document["build_profile"] != "production":
            raise EvidenceError("Production requires the production build profile")
        required = PRODUCTION_REQUIRED
    else:
        raise EvidenceError(f"unsupported validation mode: {mode}")

    failed = []
    for name in required:
        record = gates[name]
        assert isinstance(record, dict)
        if record["status"] != PASS:
            failed.append(f"{name}={record['status']}")
    if failed:
        raise EvidenceError("required gates are not proven: " + ", ".join(failed))

    # A production claim is impossible unless the signature is a distinct platform-signing proof.
    if mode == "production":
        signing = gates["platform_signing"]
        assert isinstance(signing, dict)
        text = signing["evidence"]
        assert isinstance(text, str)
        if "sigstore-only" in text.lower() or "not-claimed-phase44" in text.lower():
            raise EvidenceError("supply-chain attestation is not platform artifact signing")
        _validate_live_signing_binding(document, signing_verification)


def _sample(*, claim: str = "candidate", profile: str = "staging") -> dict[str, object]:
    gates: dict[str, dict[str, str]] = {}
    for name in ALL_GATES:
        gates[name] = {
            "status": PASS if name in CANDIDATE_REQUIRED else NOT_RUN,
            "evidence": f"self-test:{name}" if name in CANDIDATE_REQUIRED else "",
        }
    return {
        "schema": SCHEMA,
        "source_commit": "a" * 40,
        "build_profile": profile,
        "maturity_claim": claim,
        "gates": gates,
    }


def self_test() -> None:
    candidate = _sample()
    validate(candidate, "candidate")

    false_production = _sample(claim="production", profile="production")
    try:
        validate(false_production, "production")
    except EvidenceError:
        pass
    else:
        raise AssertionError("Production claim survived missing production-only gates")

    complete = _sample(claim="production", profile="production")
    complete_gates = complete["gates"]
    assert isinstance(complete_gates, dict)
    for name in ALL_GATES:
        record = complete_gates[name]
        assert isinstance(record, dict)
        record["status"] = PASS
        record["evidence"] = f"self-test:{name}:claimed-proof"

    try:
        validate(complete, "production")
    except EvidenceError as error:
        if "live platform signature verification" not in str(error):
            raise
    else:
        raise AssertionError("self-reported signing evidence bypassed live verification")

    signing = complete_gates["platform_signing"]
    assert isinstance(signing, dict)
    signing["evidence"] = "sigstore-only provenance"
    try:
        validate(complete, "production")
    except EvidenceError:
        pass
    else:
        raise AssertionError("Sigstore-only evidence was accepted as platform signing")

    malformed = _sample()
    malformed["source_commit"] = "main"
    try:
        validate(malformed, "candidate")
    except EvidenceError:
        pass
    else:
        raise AssertionError("non-exact source commit was accepted")

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "evidence.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        loaded = _load(path)
        validate(loaded, "candidate")

    print("PRODUCTION_READINESS_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--evidence", type=Path, required=True)
    validate_parser.add_argument("--mode", choices=("candidate", "production"), required=True)
    validate_parser.add_argument("--platform", choices=PLATFORMS)
    validate_parser.add_argument("--artifact", type=Path)
    validate_parser.add_argument("--signature", type=Path)
    validate_parser.add_argument("--signing-identity")
    args = parser.parse_args()

    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "validate":
            document = _load(args.evidence)
            _validate_shape(document)
            signing_verification = None
            gates = document["gates"]
            assert isinstance(gates, dict)
            signing = gates["platform_signing"]
            assert isinstance(signing, dict)
            if args.mode == "production" and signing["status"] == PASS:
                if args.platform is None or args.artifact is None or args.signing_identity is None:
                    raise EvidenceError(
                        "Production requires --platform, --artifact and --signing-identity "
                        "for live platform signature verification"
                    )
                source_commit = document["source_commit"]
                assert isinstance(source_commit, str)
                try:
                    signing_verification = verify_platform_signature(
                        platform_name=args.platform,
                        artifact=args.artifact,
                        signature=args.signature,
                        expected_identity=args.signing_identity,
                        source_commit=source_commit,
                    )
                except PlatformVerificationError as error:
                    raise EvidenceError(
                        f"live platform signature verification failed: {error}"
                    ) from error
            validate(
                document,
                args.mode,
                signing_verification=signing_verification,
            )
            print(f"PRODUCTION_READINESS_{args.mode.upper()}_OK")
        else:  # pragma: no cover - argparse prevents this
            raise EvidenceError("unknown command")
    except (EvidenceError, AssertionError) as error:
        print(f"PRODUCTION_READINESS_ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
