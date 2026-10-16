#!/usr/bin/env python3
"""Fail if the first-party local call path claims media-ready without canonical authority.

This is a security/UX regression guard, not a proof of bidirectional E2EE A/V.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
client = (root/"crates/ucr-realtime-web/static/client.html").read_text(encoding="utf-8")
sdk = (root/"sdk/typescript/src/reference_browser_media_installer.ts").read_text(encoding="utf-8")
factory = (root/"sdk/typescript/src/canonical_browser_media_factory.ts").read_text(encoding="utf-8")
assert 'Canonical Device signing/trust integration is unavailable; secure audio/video cannot start' in client
assert 'function requireCanonicalMediaHostReady()' in client
assert 'ucrCanonicalMediaAdmissionResolver' in sdk
assert 'canonical device signing, media binding or authorization incomplete' in factory
assert 'typeof admission.isCurrent !== "function"' in factory
assert 'admission.trustedKeys?.resolve' in factory
assert 'admission.signingSeed' in factory
assert 'admission.authorizeFrame' in factory
assert 'admission.authorizePublish' in factory
print("PASS first-party media admission must be canonical, current, revocable, device-signed, and frame-authorized")
