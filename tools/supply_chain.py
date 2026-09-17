#!/usr/bin/env python3
"""Prepared Phase 44 supply-chain evidence helpers for UCR.

Pure-stdlib by design: these checks must not add a package-manager bootstrap
dependency to the supply-chain gate they protect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = 1
SKIP_DIRS = {".git", "target", "dist", "node_modules", ".venv", "venv", "__pycache__"}
TEXT_SUFFIXES = {
    ".md", ".txt", ".toml", ".yml", ".yaml", ".json", ".rs", ".py", ".sh",
    ".proto", ".kt", ".swift", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".lock",
}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe-live-secret", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
)
ACTION_USE_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s#'\"]+)['\"]?",
    re.MULTILINE,
)
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class SupplyChainError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(data: object) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(data))


def run_version(command: list[str]) -> str:
    try:
        proc = subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    output = (proc.stdout or proc.stderr).strip()
    return output or "unavailable"


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.name in {"Cargo.lock"} or path.suffix.lower() in TEXT_SUFFIXES:
            try:
                if path.stat().st_size <= 2 * 1024 * 1024:
                    yield path
            except OSError:
                continue


def scan_secrets(root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {"path": path.relative_to(root).as_posix(), "line": line_no, "rule": rule}
                    )
    return findings


def scan_actions(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return [{"path": ".github/workflows", "use": "", "reason": "workflow directory missing"}]
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        text = path.read_text(encoding="utf-8")
        for use in ACTION_USE_RE.findall(text):
            if use.startswith("./"):
                continue
            if "@" not in use:
                findings.append(
                    {"path": path.relative_to(root).as_posix(), "use": use, "reason": "missing ref"}
                )
                continue
            _, ref = use.rsplit("@", 1)
            if not FULL_SHA_RE.fullmatch(ref):
                findings.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "use": use,
                        "reason": "external action is not pinned to a full 40-hex commit SHA",
                    }
                )
    return findings


def package_spdx_id(name: str, version: str, source: str) -> str:
    raw = f"{name}-{version}-{source}"
    suffix = hashlib.sha256(raw.encode()).hexdigest()[:12]
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", f"{name}-{version}")
    return f"SPDXRef-Package-{safe}-{suffix}"


def generate_sbom(metadata_paths: list[Path], output: Path, namespace_seed: str) -> None:
    packages_by_key: dict[tuple[str, str, str], dict[str, object]] = {}
    for metadata_path in metadata_paths:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        for package in metadata.get("packages", []):
            name = str(package["name"])
            version = str(package["version"])
            source = str(package.get("source") or f"path:{package.get('manifest_path', 'unknown')}")
            key = (name, version, source)
            if key in packages_by_key:
                continue
            declared = package.get("license") or "NOASSERTION"
            packages_by_key[key] = {
                "SPDXID": package_spdx_id(name, version, source),
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": declared,
                "supplier": "NOASSERTION",
                "filesAnalyzed": False,
            }

    namespace_hash = hashlib.sha256(namespace_seed.encode()).hexdigest()
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ucr-phase44-sbom",
        "documentNamespace": f"https://github.com/mailsvb2-bot/Universal-Communication-Runtime/sbom/{namespace_hash}",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: UCR Phase 44 supply_chain.py"],
        },
        "packages": sorted(packages_by_key.values(), key=lambda p: (p["name"], p["versionInfo"], p["SPDXID"])),
    }
    write_json(output, document)


def artifact_record(path: Path, base: Path | None = None) -> dict[str, object]:
    name = path.relative_to(base).as_posix() if base is not None else path.as_posix()
    return {"path": name, "sha256": sha256_file(path), "size": path.stat().st_size}


def generate_evidence(
    output: Path,
    commit: str,
    profile: str,
    tests: list[str],
    artifacts: list[Path],
    lockfiles: list[Path],
    supply_chain_identity: str,
    supply_chain_status: str,
    platform_binary_status: str,
) -> None:
    data = {
        "schema_version": SCHEMA_VERSION,
        "source_commit": commit,
        "dependency_state": [artifact_record(path) for path in sorted(lockfiles)],
        "build_environment": {
            "os": platform.platform(),
            "python": sys.version.split()[0],
            "rustc": run_version(["rustc", "-Vv"]),
            "cargo": run_version(["cargo", "-V"]),
            "github_runner_os": os.environ.get("RUNNER_OS", ""),
            "github_image_os": os.environ.get("ImageOS", ""),
        },
        "profile": profile,
        "tests": tests,
        "artifacts": [artifact_record(path) for path in sorted(artifacts)],
        "signing": {
            "supply_chain_identity": supply_chain_identity,
            "supply_chain_status": supply_chain_status,
            "platform_binary_status": platform_binary_status,
        },
    }
    write_json(output, data)


def create_release_manifest(
    output: Path,
    commit: str,
    release_sequence: int,
    artifacts: list[Path],
    required_artifact_names: list[str],
) -> None:
    records = {path.name: artifact_record(path) for path in sorted(artifacts)}
    missing = sorted(set(required_artifact_names) - set(records))
    if missing:
        raise SupplyChainError(f"cannot create partial release manifest; missing: {', '.join(missing)}")
    data = {
        "schema_version": SCHEMA_VERSION,
        "source_commit": commit,
        "release_sequence": release_sequence,
        "required_artifacts": sorted(required_artifact_names),
        "artifacts": records,
    }
    write_json(output, data)


def verify_release_manifest(
    manifest_path: Path,
    artifact_dir: Path,
    minimum_release_sequence: int,
) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if int(manifest.get("schema_version", 0)) != SCHEMA_VERSION:
        raise SupplyChainError("unsupported release manifest schema")
    sequence = int(manifest.get("release_sequence", -1))
    if sequence < minimum_release_sequence:
        raise SupplyChainError(
            f"rollback blocked: release sequence {sequence} < required {minimum_release_sequence}"
        )
    required = manifest.get("required_artifacts")
    records = manifest.get("artifacts")
    if not isinstance(required, list) or not isinstance(records, dict):
        raise SupplyChainError("malformed release manifest")
    if set(required) != set(records):
        raise SupplyChainError("partial/inconsistent release manifest")
    for name in required:
        if Path(name).name != name or "/" in name or "\\" in name:
            raise SupplyChainError(f"unsafe artifact name: {name}")
        path = artifact_dir / name
        if not path.is_file():
            raise SupplyChainError(f"partial update blocked: missing artifact {name}")
        record = records[name]
        if path.stat().st_size != int(record["size"]):
            raise SupplyChainError(f"tamper blocked: size mismatch for {name}")
        if sha256_file(path) != record["sha256"]:
            raise SupplyChainError(f"tamper blocked: hash mismatch for {name}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="ucr-phase44-") as temp:
        root = Path(temp)
        artifact_dir = root / "artifacts"
        artifact_dir.mkdir()
        binary = artifact_dir / "ucr-linux-x86_64"
        binary.write_bytes(b"ucr-release-candidate")
        manifest = root / "release-manifest.json"
        create_release_manifest(manifest, "a" * 40, 7, [binary], [binary.name])
        verify_release_manifest(manifest, artifact_dir, 7)

        binary.write_bytes(b"tampered")
        try:
            verify_release_manifest(manifest, artifact_dir, 7)
        except SupplyChainError:
            pass
        else:
            raise AssertionError("tampered artifact was accepted")

        binary.write_bytes(b"ucr-release-candidate")
        try:
            verify_release_manifest(manifest, artifact_dir, 8)
        except SupplyChainError:
            pass
        else:
            raise AssertionError("rollback was accepted")

        binary.unlink()
        try:
            verify_release_manifest(manifest, artifact_dir, 7)
        except SupplyChainError:
            pass
        else:
            raise AssertionError("partial update was accepted")


def cmd_scan_secrets(args: argparse.Namespace) -> int:
    findings = scan_secrets(Path(args.root).resolve())
    if findings:
        print(json.dumps({"secret_findings": findings}, indent=2))
        return 1
    print("SECRET_SCAN_OK")
    return 0


def cmd_scan_actions(args: argparse.Namespace) -> int:
    findings = scan_actions(Path(args.root).resolve())
    if findings:
        print(json.dumps({"action_pin_findings": findings}, indent=2))
        return 1
    print("ACTION_PIN_SCAN_OK")
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    generate_sbom([Path(p) for p in args.metadata], Path(args.output), args.namespace_seed)
    print(f"SBOM_OK {args.output}")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    generate_evidence(
        Path(args.output),
        args.commit,
        args.profile,
        args.test,
        [Path(p) for p in args.artifact],
        [Path(p) for p in args.lockfile],
        args.supply_chain_identity,
        args.supply_chain_status,
        args.platform_binary_status,
    )
    print(f"BUILD_EVIDENCE_OK {args.output}")
    return 0


def cmd_manifest_create(args: argparse.Namespace) -> int:
    create_release_manifest(
        Path(args.output),
        args.commit,
        args.release_sequence,
        [Path(p) for p in args.artifact],
        args.required_artifact,
    )
    print(f"RELEASE_MANIFEST_OK {args.output}")
    return 0


def cmd_manifest_verify(args: argparse.Namespace) -> int:
    verify_release_manifest(Path(args.manifest), Path(args.artifact_dir), args.minimum_release_sequence)
    print("RELEASE_VERIFY_OK")
    return 0


def cmd_self_test(_: argparse.Namespace) -> int:
    self_test()
    print("SUPPLY_CHAIN_SELF_TEST_OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan-secrets")
    p.add_argument("--root", default=".")
    p.set_defaults(func=cmd_scan_secrets)

    p = sub.add_parser("scan-actions")
    p.add_argument("--root", default=".")
    p.set_defaults(func=cmd_scan_actions)

    p = sub.add_parser("sbom")
    p.add_argument("--metadata", action="append", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--namespace-seed", required=True)
    p.set_defaults(func=cmd_sbom)

    p = sub.add_parser("evidence")
    p.add_argument("--output", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--test", action="append", default=[])
    p.add_argument("--artifact", action="append", default=[])
    p.add_argument("--lockfile", action="append", default=[])
    p.add_argument("--supply-chain-identity", required=True)
    p.add_argument("--supply-chain-status", required=True)
    p.add_argument("--platform-binary-status", required=True)
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("manifest-create")
    p.add_argument("--output", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--release-sequence", type=int, required=True)
    p.add_argument("--artifact", action="append", required=True)
    p.add_argument("--required-artifact", action="append", required=True)
    p.set_defaults(func=cmd_manifest_create)

    p = sub.add_parser("manifest-verify")
    p.add_argument("--manifest", required=True)
    p.add_argument("--artifact-dir", required=True)
    p.add_argument("--minimum-release-sequence", type=int, required=True)
    p.set_defaults(func=cmd_manifest_verify)

    p = sub.add_parser("self-test")
    p.set_defaults(func=cmd_self_test)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (SupplyChainError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"SUPPLY_CHAIN_ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
