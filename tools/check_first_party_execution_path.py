#!/usr/bin/env python3
"""Fail-closed first-party executable-path / release-integrity gate.

SOURCE mode checks ownership and test instrumentation at code level. It does
not claim a successful call. LIVE mode additionally compares every public
first-party page and the revision-pinned E2EE assets with the exact local
release, preventing a green healthz from masking stale embedded Rust content.

This utility never reads a Device private key, grant, browser storage, or a
live call's encrypted frames.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

EMBEDDED = {
    "/client.html": "client.html",
    "/start.html": "start.html",
    "/start.js": "start.js",
    "/phonebook.js": "phonebook.js",
    "/consumer-actions.js": "consumer-actions.js",
    "/readiness.js": "readiness.js",
    "/mobile-browser-probe.js": "mobile-browser-probe.js",
}
MEDIA = (
    "endpoint-wasm/ucr_endpoint_wasm.js",
    "endpoint-wasm/ucr_endpoint_wasm_bg.wasm",
    "endpoint-media/reference_browser_media_installer.js",
)
STATIC = Path("crates/ucr-realtime-web/static")
MANIFEST = "ucr-browser-release-manifest.json"


class ExecutionGateError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ExecutionGateError(message)


def source_sha(root: Path) -> str:
    value = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    require(len(value) == 40 and all(c in "0123456789abcdef" for c in value),
            "invalid source SHA")
    return value


def source_contract(root: Path) -> None:
    gateway = (root / "crates/ucr-realtime-web/src/main.rs").read_text()
    page = (root / STATIC / "client.html").read_text()
    start = (root / STATIC / "start.js").read_text()
    codec = (root / "sdk/typescript/src/browser_webcodecs_media.ts").read_text()
    transport = (root / "sdk/typescript/src/portable_endpoint_media.ts").read_text()
    webrtc = (root / "crates/ucr-webrtc/src/e2ee_bridge.rs").read_text()
    builder = (root / "scripts/linux/build-browser-media.sh").read_text()
    release = (root / "tools/verify_release_artifacts.py").read_text()

    for route, name in EMBEDDED.items():
        require(f'include_str!("../static/{name}")' in gateway,
                f"{route}: no matching compile-time Rust embed")
        require((root / STATIC / name).is_file(), f"missing {name}")
    for label, text, needle in (
        ("canonical direct call", start, 'prepareFirstPartyEndpointMls'),
        ("verified peer handoff", page, "verifyFirstPartyAutoJoinHandoff"),
        ("MLS admission", page, "ensureEndpointMlsReady"),
        ("WebRTC ownership", page, "startWebRtc.offerOwner"),
        ("E2EE endpoint", page, "e2eeManagedAdapter"),
        ("transport pressure", codec, "readTransportCongestion()"),
        ("actual E2EE send counter", transport, "sendQueueCongested++"),
        ("transport to video adaptation", codec, "devicePressure || transportPressure || bwe.pressure"),
        ("bounded v2 Rust channel", webrtc, 'WEBRTC_E2EE_UNORDERED_DATA_CHANNEL_LABEL'),
        ("v2 server explicit opt-in", webrtc, 'UCR_WEBRTC_E2EE_UNORDERED'),
        ("one canonical v1 E2EE owner", page, 'E2EE_CHANNEL_LABEL="ucr.e2ee.media.v1"'),
        ("optional v2 is same E2EE owner", page, "adapter.onEnvelope(wire)"),
        ("v2 reassembly bound", page, "E2EE_V2_PENDING_LIMIT=32"),
        ("v2 does not watermark across frames", page, "e2eeV2ForgetThrough"),
        ("v2 fallback", page, 'const v2=typeof e2eeChannelV2!=="undefined"'),
        ("bounded audio age", transport, 'frame.mediaKind === "audio" ? 150 : 250'),
        ("encrypted media, no RTP fallback", page, "Unexpected RTP track rejected"),
        ("MLS timing", page, 'ucrRecordDiagnostic("MLS admission ready","lifecycle")'),
        ("WebRTC ICE timing", page, 'ucrRecordDiagnostic("WebRTC ICE connected","webrtc")'),
        ("WebRTC SDP timing", page, 'ucrRecordDiagnostic("WebRTC remote SDP accepted","webrtc")'),
        ("browser media builder", builder, "reference_browser_media_installer.ts"),
        ("bundle manifest", builder, "verify_release_artifacts.py"),
        ("WASM binary magic check", release, r'b"\x00asm"'),
    ):
        require(needle in text, f"execution-path component missing: {label}")
    require(r'b"\\x00asm"' not in release,
            "manifest verifier compares escaped text rather than WASM magic")
    print("PASS SOURCE: canonical call/MLS/WebRTC/E2EE/media/release ownership checked")
    print("NOTE: SOURCE gate is not proof of real two-device performance")


def checked_file(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), f"missing or symlinked {path.name}")
    data = path.read_bytes()
    require(0 < len(data) <= 16 * 1024 * 1024,
            f"empty or oversized file: {path.name}")
    return data


def release_assets(root: Path, sha: str) -> dict[str, dict[str, object]]:
    static = root / STATIC
    manifest = json.loads(checked_file(static / MANIFEST))
    require(manifest.get("schema") == 1 and manifest.get("source_sha") == sha,
            "E2EE manifest does not match exact source commit")
    require(isinstance(manifest.get("files"), dict) and
            set(manifest["files"]) == set(MEDIA), "manifest asset list mismatch")
    for name in MEDIA:
        data = checked_file(static / name)
        if name.endswith(".wasm"):
            require(data.startswith(b"\x00asm"), "invalid WebAssembly magic")
        expected = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        require(manifest["files"][name] == expected,
                f"E2EE asset differs from revision-pinned manifest: {name}")
    print("PASS ASSETS: exact Git SHA + 3 generated public media assets")
    return manifest["files"]


def public_url(base: str, route: str) -> str:
    parts = urlparse(base)
    require(parts.scheme == "https" and parts.hostname and
            not parts.username and not parts.password and
            parts.path in ("", "/") and not parts.query and not parts.fragment,
            "live base must be a clean HTTPS origin")
    return base.rstrip("/") + route


def fetch_public(url: str) -> bytes:
    with urlopen(Request(url, headers={"Cache-Control": "no-cache"}),
                 timeout=12) as response:
        require(response.status == 200, f"public route not HTTP 200: {url}")
        data = response.read(16 * 1024 * 1024 + 1)
        require(0 < len(data) <= 16 * 1024 * 1024,
                f"public route empty or oversized: {url}")
        return data


def live_contract(root: Path, origin: str, sha: str) -> None:
    release_assets(root, sha)
    for route, name in EMBEDDED.items():
        require(fetch_public(public_url(origin, route)) ==
                checked_file(root / STATIC / name),
                f"STALE EMBEDDED WEB CODE: {route}; rebuild Rust gateway")
    for name in MEDIA:
        require(fetch_public(public_url(origin, "/" + name)) ==
                checked_file(root / STATIC / name),
                f"STALE E2EE MEDIA BUNDLE: {name}; rebuild/bind pinned SDK+WASM")
    print("PASS LIVE: public embedded pages, E2EE/WASM match exact pinned source")
    print("NOTE: LIVE integrity gate does not prove audio/video latency, ICE or E2EE call completion")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--release-assets", action="store_true")
    parser.add_argument("--live-base-url", help="Public HTTPS origin; requires --release-assets")
    args = parser.parse_args()
    root = args.repo.resolve()
    sha = source_sha(root)
    source_contract(root)
    if args.live_base_url and not args.release_assets:
        raise ExecutionGateError("live verification requires pinned release assets")
    if args.release_assets:
        release_assets(root, sha)
    if args.live_base_url:
        live_contract(root, args.live_base_url, sha)


if __name__ == "__main__":
    try:
        main()
    except (ExecutionGateError, OSError, ValueError, KeyError,
            subprocess.CalledProcessError) as error:
        print(f"BLOCKED EXECUTION PATH: {error}", file=sys.stderr)
        sys.exit(1)
