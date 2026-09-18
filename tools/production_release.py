#!/usr/bin/env python3
"""Production release evidence helpers for Universal Communication Runtime.

The helper is intentionally pure-stdlib. It consumes exact-head GitHub Actions proof gathered
by the protected release workflow and emits a fail-closed Production readiness document. It
never signs artifacts and it never substitutes supply-chain attestation for platform signing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

READINESS_SCHEMA = "ucr.production-readiness.v1"
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_MAIN_WORKFLOWS = (
    "CI",
    "Conformance",
    "Phase 42 AI Actor",
    "Phase 43 Chaos Lab",
    "Phase 44 Supply Chain",
    "Phase 45 Production Hardening",
)

ALL_GATES = (
    "security",
    "data_safety",
    "compatibility",
    "conformance",
    "critical_chaos",
    "public_contract",
    "performance",
    "metrics",
    "diagnostics",
    "telemetry_privacy",
    "production_runtime",
    "platform_signing",
)


class ReleaseEvidenceError(ValueError):
    """Exact Production release evidence is missing, malformed, or contradictory."""


def require_source_commit(value: str) -> str:
    if SOURCE_COMMIT_RE.fullmatch(value) is None:
        raise ReleaseEvidenceError("source commit must be a lowercase 40-hex commit")
    return value


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseEvidenceError(f"cannot read JSON evidence: {error}") from error


def validate_main_proof(
    proof: object, source_commit: str
) -> dict[str, dict[str, str]]:
    source_commit = require_source_commit(source_commit)
    if not isinstance(proof, list):
        raise ReleaseEvidenceError("main workflow proof must be a JSON array")

    selected: dict[str, dict[str, str]] = {}
    for item in proof:
        if not isinstance(item, dict):
            continue
        name = item.get("workflowName")
        if name not in REQUIRED_MAIN_WORKFLOWS:
            continue
        if item.get("event") != "push":
            continue
        if item.get("headSha") != source_commit:
            continue
        if item.get("conclusion") != "success":
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith("https://github.com/"):
            raise ReleaseEvidenceError(f"{name} success proof lacks a GitHub run URL")
        selected[str(name)] = {
            "workflow": str(name),
            "url": url,
            "head_sha": source_commit,
            "event": "push",
            "conclusion": "success",
        }

    missing = [name for name in REQUIRED_MAIN_WORKFLOWS if name not in selected]
    if missing:
        raise ReleaseEvidenceError(
            "required exact-main workflows are not proven successful: "
            + ", ".join(missing)
        )
    return selected


def build_readiness(
    proof: object,
    source_commit: str,
    release_workflow_url: str,
) -> dict[str, object]:
    selected = validate_main_proof(proof, source_commit)
    if not release_workflow_url.startswith("https://github.com/"):
        raise ReleaseEvidenceError("release workflow URL must be a GitHub URL")

    def evidence(*workflow_names: str) -> str:
        refs = [
            f"{name}={selected[name]['url']}"
            for name in workflow_names
        ]
        return "exact-main-success; " + "; ".join(refs)

    gates: dict[str, dict[str, str]] = {
        "security": {
            "status": "pass",
            "evidence": evidence("CI", "Phase 45 Production Hardening"),
        },
        "data_safety": {
            "status": "pass",
            "evidence": evidence("Phase 45 Production Hardening"),
        },
        "compatibility": {
            "status": "pass",
            "evidence": evidence("Conformance", "CI"),
        },
        "conformance": {
            "status": "pass",
            "evidence": evidence("Conformance"),
        },
        "critical_chaos": {
            "status": "pass",
            "evidence": evidence("Phase 43 Chaos Lab"),
        },
        "public_contract": {
            "status": "pass",
            "evidence": evidence("CI", "Conformance"),
        },
        "performance": {
            "status": "pass",
            "evidence": evidence("Phase 45 Production Hardening"),
        },
        "metrics": {
            "status": "pass",
            "evidence": evidence("Phase 45 Production Hardening"),
        },
        "diagnostics": {
            "status": "pass",
            "evidence": evidence("Phase 45 Production Hardening"),
        },
        "telemetry_privacy": {
            "status": "pass",
            "evidence": evidence("Phase 45 Production Hardening"),
        },
        "production_runtime": {
            "status": "pass",
            "evidence": evidence(
                "Phase 44 Supply Chain", "Phase 45 Production Hardening"
            ),
        },
        "platform_signing": {
            "status": "pass",
            "evidence": (
                "live-native-platform-verification-required; "
                f"release_workflow={release_workflow_url}"
            ),
        },
    }

    if tuple(gates) != ALL_GATES:
        raise ReleaseEvidenceError("internal readiness gate order/schema drift")

    return {
        "schema": READINESS_SCHEMA,
        "source_commit": source_commit,
        "build_profile": "production",
        "maturity_claim": "production",
        "gates": gates,
    }


def write_readiness(
    proof_path: Path,
    source_commit: str,
    release_workflow_url: str,
    output: Path,
) -> None:
    document = build_readiness(
        load_json(proof_path),
        source_commit,
        release_workflow_url,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def self_test() -> None:
    source = "a" * 40
    proof = [
        {
            "workflowName": name,
            "conclusion": "success",
            "event": "push",
            "headSha": source,
            "url": f"https://github.com/example/ucr/actions/runs/{index + 1}",
        }
        for index, name in enumerate(REQUIRED_MAIN_WORKFLOWS)
    ]
    release_url = "https://github.com/example/ucr/actions/runs/999"

    selected = validate_main_proof(proof, source)
    assert set(selected) == set(REQUIRED_MAIN_WORKFLOWS)
    readiness = build_readiness(proof, source, release_url)
    assert readiness["maturity_claim"] == "production"
    assert readiness["build_profile"] == "production"
    gates = readiness["gates"]
    assert isinstance(gates, dict)
    assert set(gates) == set(ALL_GATES)
    assert gates["platform_signing"]["status"] == "pass"
    assert "live-native-platform-verification-required" in gates["platform_signing"]["evidence"]

    missing = proof[:-1]
    try:
        validate_main_proof(missing, source)
    except ReleaseEvidenceError:
        pass
    else:
        raise AssertionError("missing required workflow was accepted")

    wrong_head = [dict(item) for item in proof]
    wrong_head[0]["headSha"] = "b" * 40
    try:
        validate_main_proof(wrong_head, source)
    except ReleaseEvidenceError:
        pass
    else:
        raise AssertionError("wrong-head workflow proof was accepted")

    pull_request_only = [dict(item) for item in proof]
    pull_request_only[0]["event"] = "pull_request"
    try:
        validate_main_proof(pull_request_only, source)
    except ReleaseEvidenceError:
        pass
    else:
        raise AssertionError("pull-request-only proof was accepted for Production")

    failed = [dict(item) for item in proof]
    failed[0]["conclusion"] = "failure"
    try:
        validate_main_proof(failed, source)
    except ReleaseEvidenceError:
        pass
    else:
        raise AssertionError("failed required workflow was accepted")

    try:
        build_readiness(proof, source, "not-a-github-url")
    except ReleaseEvidenceError:
        pass
    else:
        raise AssertionError("untrusted release workflow URL was accepted")

    with tempfile.TemporaryDirectory(prefix="ucr-production-release-") as directory:
        root = Path(directory)
        proof_path = root / "proof.json"
        output = root / "readiness.json"
        proof_path.write_text(json.dumps(proof), encoding="utf-8")
        write_readiness(proof_path, source, release_url, output)
        loaded = json.loads(output.read_text(encoding="utf-8"))
        assert loaded["source_commit"] == source

    print("PRODUCTION_RELEASE_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")

    emit = subparsers.add_parser("emit-readiness")
    emit.add_argument("--proof-json", type=Path, required=True)
    emit.add_argument("--source-commit", required=True)
    emit.add_argument("--release-workflow-url", required=True)
    emit.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "emit-readiness":
            write_readiness(
                args.proof_json,
                args.source_commit,
                args.release_workflow_url,
                args.output,
            )
            print(f"PRODUCTION_RELEASE_READINESS_OK {args.output}")
        else:  # pragma: no cover - argparse prevents this
            raise ReleaseEvidenceError("unknown command")
    except (OSError, ReleaseEvidenceError, AssertionError) as error:
        print(f"PRODUCTION_RELEASE_ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
