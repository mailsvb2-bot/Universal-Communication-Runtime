#!/usr/bin/env python3
"""Live platform-signature verification for UCR Production artifacts.

This tool never signs artifacts. It verifies a platform-native signature that was produced by
an external publisher identity, binds the verified identity to the exact artifact SHA-256, and
emits a machine-readable receipt only after the native verifier succeeds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "ucr.platform-signing-verification.v1"
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLATFORMS = ("windows-authenticode", "macos-codesign", "linux-openpgp")


class VerificationError(ValueError):
    """The platform signature cannot be proven for the requested identity/artifact."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise VerificationError(f"cannot hash artifact: {error}") from error
    return digest.hexdigest()


def _normalize_fingerprint(value: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if not normalized:
        raise VerificationError("signing identity fingerprint is empty")
    return normalized


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        raise VerificationError(f"cannot execute platform verifier: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise VerificationError(
            f"platform verifier failed with exit {result.returncode}: {detail[-3000:]}"
        )
    return result


def _verify_linux_openpgp(
    artifact: Path, signature: Path | None, expected_identity: str
) -> tuple[str, str]:
    if signature is None:
        raise VerificationError("linux-openpgp verification requires --signature")
    if not signature.is_file():
        raise VerificationError("OpenPGP detached signature does not exist")
    gpg = shutil.which("gpg")
    if gpg is None:
        raise VerificationError("gpg is not available")
    result = _run(
        [
            gpg,
            "--batch",
            "--status-fd=1",
            "--verify",
            str(signature),
            str(artifact),
        ]
    )
    fingerprints = []
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            parts = line.split()
            if len(parts) >= 3:
                fingerprints.append(_normalize_fingerprint(parts[2]))
    if len(fingerprints) != 1:
        raise VerificationError("expected exactly one OpenPGP VALIDSIG identity")
    actual = fingerprints[0]
    expected = _normalize_fingerprint(expected_identity)
    if actual != expected:
        raise VerificationError(
            f"OpenPGP signer mismatch: expected {expected}, verified {actual}"
        )
    return actual, "gpg --status-fd=1 --verify"


def _verify_macos_codesign(
    artifact: Path, signature: Path | None, expected_identity: str
) -> tuple[str, str]:
    if signature is not None:
        raise VerificationError("macos-codesign uses the embedded signature; omit --signature")
    codesign = shutil.which("codesign")
    if codesign is None:
        raise VerificationError("codesign is not available")
    _run([codesign, "--verify", "--deep", "--strict", "--verbose=2", str(artifact)])
    details = _run([codesign, "-dv", "--verbose=4", str(artifact)])
    combined = "\n".join(part for part in [details.stdout, details.stderr] if part)
    match = re.search(r"^TeamIdentifier=(.+)$", combined, re.MULTILINE)
    if match is None:
        raise VerificationError("codesign verification did not expose TeamIdentifier")
    actual = match.group(1).strip()
    expected = expected_identity.strip()
    if not expected or actual != expected:
        raise VerificationError(
            f"codesign TeamIdentifier mismatch: expected {expected!r}, verified {actual!r}"
        )
    return actual, "codesign --verify --deep --strict"


def _verify_windows_authenticode(
    artifact: Path, signature: Path | None, expected_identity: str
) -> tuple[str, str]:
    if signature is not None:
        raise VerificationError(
            "windows-authenticode uses the embedded signature; omit --signature"
        )
    if os.name != "nt":
        raise VerificationError("windows-authenticode verification must run on Windows")
    signtool = shutil.which("signtool")
    if signtool is None:
        raise VerificationError("signtool is not available")
    _run([signtool, "verify", "/pa", "/all", "/v", str(artifact)])

    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        raise VerificationError("PowerShell is required to read the Authenticode signer identity")
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "if ($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate) { exit 3 }; "
        "$s.SignerCertificate.Thumbprint"
    )
    result = _run([powershell, "-NoProfile", "-Command", script, str(artifact)])
    actual = _normalize_fingerprint(result.stdout.strip())
    expected = _normalize_fingerprint(expected_identity)
    if actual != expected:
        raise VerificationError(
            f"Authenticode signer mismatch: expected {expected}, verified {actual}"
        )
    return actual, "signtool verify /pa /all /v + Get-AuthenticodeSignature"


def verify_platform_signature(
    *,
    platform_name: str,
    artifact: Path,
    signature: Path | None,
    expected_identity: str,
    source_commit: str,
) -> dict[str, object]:
    if platform_name not in PLATFORMS:
        raise VerificationError(f"unsupported platform signing mode: {platform_name}")
    if not SOURCE_COMMIT_RE.fullmatch(source_commit):
        raise VerificationError("source_commit must be a lowercase 40-hex commit")
    if not artifact.is_file():
        raise VerificationError("production artifact does not exist")

    if platform_name == "linux-openpgp":
        identity, verifier = _verify_linux_openpgp(artifact, signature, expected_identity)
    elif platform_name == "macos-codesign":
        identity, verifier = _verify_macos_codesign(artifact, signature, expected_identity)
    else:
        identity, verifier = _verify_windows_authenticode(
            artifact, signature, expected_identity
        )

    return {
        "schema": SCHEMA,
        "source_commit": source_commit,
        "platform": platform_name,
        "artifact_sha256": _sha256(artifact),
        "signing_identity": identity,
        "verifier": verifier,
        "verified": True,
    }


def self_test() -> None:
    assert _normalize_fingerprint("AA:bb 01") == "AABB01"
    try:
        _normalize_fingerprint("not-a-fingerprint")
    except VerificationError:
        pass
    else:
        raise AssertionError("invalid signing fingerprint was accepted")

    with tempfile.TemporaryDirectory() as directory:
        artifact = Path(directory) / "artifact.bin"
        artifact.write_bytes(b"ucr-platform-signing-self-test")
        assert _sha256(artifact) == hashlib.sha256(artifact.read_bytes()).hexdigest()

    try:
        verify_platform_signature(
            platform_name="linux-openpgp",
            artifact=Path("/definitely/missing/ucr-artifact"),
            signature=None,
            expected_identity="AA",
            source_commit="a" * 40,
        )
    except VerificationError:
        pass
    else:
        raise AssertionError("missing unsigned artifact was accepted")

    print("PLATFORM_SIGNING_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--platform", choices=PLATFORMS, required=True)
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument("--signature", type=Path)
    verify.add_argument("--expected-identity", required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "verify":
            receipt = verify_platform_signature(
                platform_name=args.platform,
                artifact=args.artifact,
                signature=args.signature,
                expected_identity=args.expected_identity,
                source_commit=args.source_commit,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(
                "PLATFORM_SIGNING_VERIFIED "
                f"platform={receipt['platform']} "
                f"identity={receipt['signing_identity']} "
                f"sha256={receipt['artifact_sha256']}"
            )
        else:  # pragma: no cover
            raise VerificationError("unknown command")
    except (OSError, VerificationError, AssertionError) as error:
        print(f"PLATFORM_SIGNING_ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
