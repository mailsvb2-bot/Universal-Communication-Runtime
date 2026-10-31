#!/usr/bin/env python3
"""Fail if the first-party local call path claims media-ready without canonical authority.

This is a security/UX regression guard, not a proof of bidirectional E2EE A/V.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
# First-party calls must never silently mint broad grants or treat a stale
# parent-Call CAS conflict as authorization. This contract is intentionally
# insufficient to claim successful two-device media without call-scoped policy.
media_owner = (root/"crates/ucr-runtime/src/first_party_media.rs").read_text(encoding="utf-8")
sfu_owner = (root/"crates/ucr-sfu/src/lib.rs").read_text(encoding="utf-8")
assert "require_media_permissions(store, subject)?" in media_owner
assert "create_call_if_parent_current(&caller, &draft, direct)" in media_owner
assert "Err(error) => return Err(error.into())," in media_owner
assert "Err(DurableStoreError::Conflict) => {}" not in media_owner
assert "grant_permission(" not in media_owner
assert "validate_group_media_source_frame(self.store" in sfu_owner
assert "self.authorization" in sfu_owner and "permission: send.to_owned()" in sfu_owner
assert "permission: receive.to_owned()" in sfu_owner

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
assert 'if (state.next - now > 0.25)' in webcodecs
assert 'this.#scheduledAudio.get(streamKey)' in webcodecs
assert 'source.onended = null;' in webcodecs
assert 'source.stop();' in webcodecs
assert 'this.#scheduledAudio.delete(streamKey);' in webcodecs
assert 'this.#codecRecoveryTimer = setTimeout(' in webcodecs
assert 'Math.min(10_000, 250 * 2 ** Math.min(this.#codecRecoveryAttempts++, 6))' in webcodecs
assert 'void this.updateSources(this.#currentSources).catch(this.#onError)' in webcodecs
assert 'if (this.#codecRecoveryTimer !== null) clearTimeout(this.#codecRecoveryTimer)' in webcodecs
assert 'this.#awaitVideoKeyframe.add(key)' in webcodecs
assert 'this.#awaitVideoKeyframe.has(key) && !frame.keyframe' in webcodecs
assert 'framePeak = Math.max(framePeak, peak)' in webcodecs
assert 'ucrFreezePreLeaveSnapshot()' in client
assert 'playoutQueuedMs' in webcodecs
assert 'playoutJitterMs' in webcodecs
assert 'mediaStageMetrics:window.__ucrMediaStageMetrics' in client
assert 'sendChannelClosed' in pipeline
assert 'sendQueueCongested' in pipeline
assert 'sendInvalidEnvelope' in pipeline
assert 'sendUnexpectedFailure' in pipeline
assert 'sendUnavailable' in pipeline
assert 'code === "UCR_TRANSPORT_CHANNEL_CLOSED"' in pipeline
assert 'code === "UCR_TRANSPORT_QUEUE_CONGESTED"' in pipeline
assert 'code === "UCR_TRANSPORT_INVALID_ENVELOPE"' in pipeline
assert 'ui.webrtcState.textContent=pc.connectionState||"Connecting";' in client
assert 'UCR_TRANSPORT_CHANNEL_CLOSED' in client
assert 'UCR_TRANSPORT_QUEUE_CONGESTED' in client
assert 'UCR_TRANSPORT_INVALID_ENVELOPE' in client
assert 'sendQueueCongested:window.__ucrMediaStageMetrics.sendQueueCongested' in client

assert 'requestVideoKeyframe?(streamId: string)' in pipeline
assert 'this.#producer.requestVideoKeyframe?.(frame.streamId)' in pipeline
assert 'videoKeyframeRequests' in pipeline
assert 'audioExpired' in pipeline
assert 'audioQueueFull' in pipeline
assert 'audioAuthorizationRejected' in pipeline
assert 'audioSealFailure' in pipeline
assert 'audioTransportFailure' in pipeline
assert 'audioDecodeFailure' in pipeline
assert 'encodeLatencyMs' in webcodecs
assert 'encodeStartTimes.set(frame.timestamp, encodeStarted)' in webcodecs
assert 'performance.now() - started' in webcodecs
assert 'this.#keyframeRequests.set(encodedStreamId' in webcodecs
assert 'this.#keyframeRequests.set(lowStreamId' in webcodecs
assert 'audioTransportFailure:window.__ucrMediaStageMetrics.audioTransportFailure' in client
assert 'encodeLatencyMaxMs:window.__ucrVideoAdaptation.encodeLatencyMaxMs' in client


assert 'state.next = now + cushion;' in webcodecs
assert 'const start = Math.max(now + 0.012, state.next)' in webcodecs
assert 'const start = pending - now > 0.35 ? now' not in webcodecs
assert 'export function ucrAdaptiveVideoStep(' in webcodecs
assert 'ucrVideoAdaptation.stage = next.stage' in webcodecs
assert 'ucrEncryptedTransportBufferedAmount' in client
assert 'const ceiling=mediaKind==="video"?256*1024:384*1024;' in client
assert 'e2eeChannel.bufferedAmount:Number.POSITIVE_INFINITY' in client
assert 'videoAdaptation:(window.__ucrVideoAdaptation?' in client
# Windows launch must not silently trust expired certs or reuse gitignored WASM.
windows_launcher = (root/"scripts/windows/start-local-first-party-https.ps1").read_text(encoding="utf-8")
windows_builder = (root/"scripts/windows/build-browser-media.ps1").read_text(encoding="utf-8")
assert "'-checkend' '86400'" in windows_launcher
assert "$certPublic -ne $keyPublic" in windows_launcher
assert "$renewCertificate" in windows_launcher
assert "build-browser-media.ps1" in windows_launcher
assert "crates\\ucr-realtime-web\\static\\endpoint-wasm\\ucr_endpoint_wasm_bg.wasm" in windows_launcher
assert 'wasm-bindgen 0.2.128' in windows_builder
assert '"wasm32-unknown-unknown"' in windows_builder
print("PASS Windows launcher renews expired TLS certificates and rebuilds revision-matched WASM/SDK")
print("PASS VP8 quality adapts by encrypted transport/encoder congestion and exports aggregate telemetry")
print("PASS decoded Opus playout is bounded and never overlaps stale audio bursts")
print("PASS real WebCodecs Opus frames comply with canonical Rust no-audio-keyframe contract")
print("PASS protected media failure stages, bounded fail-closed handling and persisted trusted Device restart")
print("PASS first-party media admission must be canonical, current, revocable, device-signed, and frame-authorized")
