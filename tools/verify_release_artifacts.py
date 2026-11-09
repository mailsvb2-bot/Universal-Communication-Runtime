#!/usr/bin/env python3
"""Fail-closed browser E2EE release manifest, bound to one source Git SHA.

The manifest carries public hashes only, never a Device key, Join grant or
credential. The runtime independently checks it when both relevant environment
variables are configured.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

FILES = (
    "endpoint-wasm/ucr_endpoint_wasm.js",
    "endpoint-wasm/ucr_endpoint_wasm_bg.wasm",
    "endpoint-media/reference_browser_media_installer.js",
)
STATIC = Path("crates/ucr-realtime-web/static")


def hashes(root: Path) -> dict[str, dict[str, int | str]]:
    result = {}
    for relative in FILES:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"required generated file unavailable: {relative}")
        body = path.read_bytes()
        if not 0 < len(body) <= 16 * 1024 * 1024:
            raise ValueError(f"invalid generated file length: {relative}")
        if relative.endswith(".wasm") and body[:4] != b"\\x00asm":
            raise ValueError("invalid WebAssembly magic")
        result[relative] = {
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    return result


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--create", action="store_true")
    args = p.parse_args()
    repo = args.repo.resolve()
    sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha):
        raise ValueError("unable to pin Git commit")
    expected = {"schema": 1, "source_sha": sha, "files": hashes(repo / STATIC)}
    manifest = repo / STATIC / "ucr-browser-release-manifest.json"
    if args.create:
        if manifest.is_symlink():
            raise ValueError("refusing symlinked release manifest")
        temp = manifest.with_suffix(".json.tmp")
        temp.write_text(json.dumps(expected, sort_keys=True, indent=2) + "\n")
        os.replace(temp, manifest)
        print(f"CREATED release manifest for {sha[:12]}")
        return
    actual = json.loads(manifest.read_text())
    if actual != expected:
        raise ValueError("generated browser media hashes or Git SHA differ")
    print(f"PASS release artifact SHA-256 + source Git SHA: {sha[:12]}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        sys.exit(1)
