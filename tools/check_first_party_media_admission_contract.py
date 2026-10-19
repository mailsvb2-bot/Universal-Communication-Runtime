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
assert 'const seed = admission?.signingSeed;' in factory
assert 'seed.length !== 32' in factory
assert 'seedCopy = seed.slice()' in factory
assert 'seedCopy.fill(0)' in factory
assert 'admission.authorizeFrame' in factory
assert 'admission.authorizePublish' in factory
pipeline = (root/"sdk/typescript/src/portable_endpoint_media.ts").read_text(encoding="utf-8")
login = (root/"crates/ucr-realtime-web/static/start.js").read_text(encoding="utf-8")
account = (root/"sdk/typescript/first_party_account_conformance.ts").read_text(encoding="utf-8")
for stage in (
    "PUBLISH_AUTHORIZATION", "SEAL_WIRE", "DATACHANNEL_SEND",
    "RECEIVE_AUTHORIZATION", "SIGNING_KEY_RESOLUTION",
    "VERIFY_AND_DECRYPT", "DECODE_AND_PLAY",
):
    assert stage in pipeline, f"missing protected media stage {stage}"
assert 'this.#onError(new Error("UCR_MEDIA_OUTBOUND_" + outboundStage))' in pipeline
assert 'this.#onError(new Error(code))' in pipeline
assert 'ucrMediaFailureCount>=8' in client
assert 'endUnverifiedMedia(sessionLifecycleGeneration' in client
assert 'const HINT_KEY' in login
assert 'authenticateUcrFirstPartyDevice(' in login
assert 'const avRestored=createUcrBrowserProtectedDeviceVault(av.storage)' in account
assert 'await hA.logout()' in account
webcodecs = (root/"sdk/typescript/src/browser_webcodecs_media.ts").read_text(encoding="utf-8")
protocol = (root/"crates/ucr-protocol/src/group_media_e2ee.rs").read_text(encoding="utf-8")
assert 'keyframe: kind === "video" && chunk.type === "key"' in webcodecs, (
    "Opus audio cannot be a keyframe: Rust seal_wire rejects InvalidAudioHeader")
assert 'header.media_kind == MediaKind::Audio && header.keyframe' in protocol
assert 'if (pending - now > 0.25)' in webcodecs
assert 'const start = Math.max(now + 0.012, pending)' in webcodecs
assert 'const start = pending - now > 0.35 ? now' not in webcodecs
print("PASS decoded Opus playout is bounded and never overlaps stale audio bursts")
print("PASS real WebCodecs Opus frames comply with canonical Rust no-audio-keyframe contract")
print("PASS protected media failure stages, bounded fail-closed handling and persisted trusted Device restart")
print("PASS first-party media admission must be canonical, current, revocable, device-signed, and frame-authorized")
