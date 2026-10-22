#!/usr/bin/env python3
"""Guard the first-party Call creation revision contract across Rust and TS."""
from pathlib import Path
root = Path(__file__).resolve().parents[1]
server = (root / "crates/ucr-runtime/src/first_party_web.rs").read_text(encoding="utf-8")
protocol = (root / "crates/ucr-protocol/src/call.rs").read_text(encoding="utf-8")
client = (root / "sdk/typescript/src/contact_call_journey.ts").read_text(encoding="utf-8")
launcher = (root / "scripts/windows/start-local-first-party-https.ps1").read_text(encoding="utf-8")
assert "revision: 0," in server, "server must start calls at revision 0"
assert "session.revision != 0" in protocol, "canonical create enforces revision 0"
assert "!Number.isSafeInteger(raw.revision) || raw.revision < 0" in client, "browser must accept revision 0 and reject negative/unsafe revisions"
assert "!Number.isSafeInteger(raw.revision) || raw.revision < 1" not in client, "browser rejects valid revision-zero Call"
builder = (root / "scripts/windows/build-browser-media.ps1").read_text(encoding="utf-8")
assert "build-browser-media.ps1" in launcher, "launcher must invoke revision-matched builder"
assert "reference_browser_media_installer.ts" in builder and '"--bundle"' in builder, "builder must rebuild ignored browser bundle"
assert "wasm-bindgen" in builder and "ucr_endpoint_wasm" in builder, "builder must regenerate endpoint WASM"
print("PASS: server, canonical protocol, browser SDK and Windows installer agree on revision-zero calls")
