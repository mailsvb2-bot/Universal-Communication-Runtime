# PetrelLink first-party execution closure (2026-11-18)

## Scope and non-claims

This audit is grounded in executed code, not README feature inventory. Green CI, /healthz and /readyz 200 are NOT proof of a usable PC ↔ Android video call.

## Canonical execution path and responsible owners

| Stage | Current code owner | Proof / fail boundary |
| --- | --- | --- |
| Authenticated Device | crates/ucr-realtime-web/static/start.js | Current account generation; logout cancels in-flight work |
| Direct Call, ringing and acceptance | start.js: calls.start / calls.signal / rememberActiveCall / beginMedia | Callee alerted; authorized acceptance, no duplicate; no media for unverified acceptance |
| MLS admission and consent | start.js: prepareFirstPartyEndpointMls; client.html: verifyFirstPartyAutoJoinHandoff and ensureEndpointMlsReady | Both devices authenticated; Join → MLS timestamps; no audio-to-video permission escalation |
| WebRTC and ICE | client.html: startWebRtcOnce, offer-scoped owner, SDP/ICE callbacks | Offer → capture → SDP → ICE timestamps; no stale owner reuse or RTP fallback |
| Authenticated E2EE | sdk/typescript/src/portable_endpoint_media.ts and Rust endpoint WASM | Per-epoch signed/verified sender and encrypted frame; revoked Device fails closed |
| WebCodecs capture and playback | sdk/typescript/src/browser_webcodecs_media.ts | Encode and decode stages, real rendered video, scheduled audible PCM |
| Shared transport | client.html: sendE2eeEnvelope | Real sendQueueCongested and bufferedAmount; known remaining ordered-reliable HOL risk |
| Production binary | crates/ucr-realtime-web/src/main.rs: include_str! | Must rebuild Rust executable to update embedded HTML or JavaScript |
| Separate browser E2EE | generated endpoint-media installer plus endpoint-wasm JavaScript/WASM | Exact same Git SHA and manifest; never reuse stale JS bundle |
| User acceptance | tools/check_first_party_real_call_evidence.py | Both actual devices plus independently measured end-to-end delays; fail on missing measurement |

The Phase-45 performance workflow benchmarks SFU conference profiles. This is NOT a direct measurement of PetrelLink first-party two-device A/V performance.

## Release and execution integrity (P0)

Use the same exact source SHA for Rust web executable, embedded HTML/JS, generated TypeScript media installer, Rust endpoint WASM and release manifest. Build media using scripts/linux/build-browser-media.sh with pinned wasm-bindgen 0.2.128 and esbuild 0.25.5. The browser media outputs are gitignored; they must not be silently inherited from an earlier release.

The web gateway embeds HTML/JS using Rust include_str!, so copying static assets without rebuilding the gateway does not publish a changed interface. Keep web-only rollback of binary, source, assets and manifest atomic; do not restart unrelated runtime, SQLite or coturn.

Source checks before build:

    python3 tools/check_first_party_execution_path.py
    python3 -m unittest discover -s tools -p 'test_first_party_execution_path.py'
    python3 -m unittest discover -s tools -p 'test_first_party_real_call_evidence.py'

Post-deploy mandatory byte comparison (from same exact SHA and generated assets):

    python3 tools/check_first_party_execution_path.py --release-assets --live-base-url https://app.petrellink.ru

The existing gateway readiness explicitly permits UCR_REALTIME_WEB_RELEASE_MANIFEST and UCR_REALTIME_WEB_EXPECTED_SOURCE_SHA to be absent for local development, so /readyz 200 alone is not evidence of a source-bound production release. A post-deploy integrity mismatch must trigger rollback.

## Real two-device quality acceptance (P0)

Collect desktop and Android diagnostic JSON from the SAME call while both receive video and audio. Measure actual one-way audio and glass-to-glass video with an independently synchronized method. Buffer occupancy or frame counts cannot substitute for those measurements.

    python3 tools/check_first_party_real_call_evidence.py --pc desktop.json --phone android.json --audio-one-way-ms MEASURED --video-glass-to-glass-ms MEASURED --output call-evidence.json

Initial acceptance targets (not current achievements): Join→E2EE ≤10s, visible freeze ≤500ms, audio one-way ≤300ms, video glass-to-glass ≤500ms. A passing single call does not establish p95 fleet quality or recovery under network switching.

## Explicitly open architectural gaps

- P0: reliable ordered v1 DataChannel multiplexes encrypted audio and fragmented video; head-of-line blocking can stall audio. The existing Rust optional unordered v2 transport is now wired through client.html and the SAME signed E2EE adapter, with bounded reassembly, keyframe metadata, and v1 fallback. The Rust UCR_WEBRTC_E2EE_UNORDERED switch remains OFF by default. Do NOT enable it in production without live two-device v2 negotiation, loss/reorder, audio-delay and reconnection measurements; code conformance alone is not proof.
- P0: Android MEDIA_ACTIVATION_FAILURE is too generic in old snapshots. Use separated producer/consumer/transport stage error categories in future real diagnostics.
- P0: setup delay comprises remote acceptance, MLS, offer, local capture, SDP and ICE. The source now uses bounded parallel posting of pre-collected ICE candidates instead of serialized HTTP requests. Its impact and behavior with real networks still need two-device confirmation.
- P1: background ringing, forced TURN, VPN routing, simultaneous hangup, Device revocation, network switch, camera toggles, BFCache and fail-closed media recovery require real-device exercising.
- P1: code CI green is not production quality; add multi-run p95 A/V timing and loss/stall evidence across network/device types.
- P1: enforce production-manifest opt-in at actual web release and compare exact published assets; do not claim safety solely from a green build.

## Closure map

PR may merge after required code/security checks pass. RELEASE-INTEGRITY requires byte-matched public browser assets and Rust executable for one source SHA. USER-CALL-READY requires a real PC+phone call with measured A/V quality. Missing measurements remain BLOCKED; never report success from simulated browser tests or HTTP 200 alone.
