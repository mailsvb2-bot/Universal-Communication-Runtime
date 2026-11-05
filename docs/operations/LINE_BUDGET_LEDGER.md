# Line-budget ledger (cross-device call series)

`metrics_baseline.json` is intentionally untouched. This ledger records intentional
growth of hot call-path files for the phone↔PC call fix series on top of
`842ba25`.

| File | Approx. delta | Justification |
|---|---|---|
| `crates/ucr-realtime-web/static/client.html` | +~120 lines | Opt-in soft offline grace, mobile capture caps/`facingMode`, AudioContext resume on visibility/online, ICE failure diagnostics for empty STUN/TURN |
| `sdk/typescript/src/browser_webcodecs_media.ts` | +~25 lines | H.264 Baseline 3.1 probe fallback; resume suspended AudioContext before PCM playout |
| `sdk/typescript/src/ice_cascade.ts` | new ~70 lines | Operator helper for UDP→TCP→TURNS:443 cascade (no invented public hosts) |
| `scripts/windows/start-local-first-party-https.ps1` | +~60 lines | `-TurnUrls` CSV cascade, `-StunUrls`, clearer cross-network warnings |
| `scripts/windows/start-remote-device-test.ps1` | +~25 lines | Accept TURN cascade; require at least one `turns:` URL |
| `docs/testing/android-cellular-remote-call.md` | +~25 lines | Document cascade and opt-in soft recovery |
| `crates/ucr-architecture-tests/tests/webrtc_provider.rs` | +~45 lines | String gates for the above invariants |
| `sdk/typescript/endpoint_e2ee_conformance.ts` | +~15 lines | Cascade helper + codec detect still Baseline 4.2 by default |

| `crates/ucr-realtime-web/static/start.js` | +~165 lines | Fresh MLS expectedRevision after WASM, isolate Join/MLS errors from session refresh, session diagnostics v2 |
| `crates/ucr-realtime-web/static/start.html` | +~2 lines | Diagnostics panel describes MLS/ICE |
| `crates/ucr-realtime-web/static/client.html` | +~80 lines | Sanitized ICE candidate types, SDP completion, ICE server types, sessionStorage snapshot |
| `crates/ucr-realtime-web/src/main.rs` | +~15 lines | Gates for session diagnostics and ICE |
| `crates/ucr-architecture-tests/tests/webrtc_provider.rs` | +~10 lines | Gates for revision refresh and diagnostics |

Session diagnostics fields are allowlisted; never record grants, SDP or keys. Risky behavior (`ucrSoftNetworkRecovery`) defaults **off**.

## Series 3 on PR #344 head `4d7fc7d`

The rows above document series 1–2 work already folded into PR #344
(`review/ucr-series-c-20261104`, base `4d7fc7d32cd6e28c0562a8020210da25e51e9d93`).
The rows below are call-survival fixes ON TOP of that PR, not bare main
`842ba25`. `metrics_baseline.json` remains unchanged.

| File | Approx. delta | Justification |
|---|---|---|
| `sdk/typescript/src/portable_endpoint_media.ts` | +~20 lines | Congestion is backpressure: count sendQueueCongested, notify page, don't fail-close or request keyframe |
| `crates/ucr-realtime-web/static/client.html` | +~120 lines | ICE pending vs none, retry Join without retiring live grant, close before Leave, outgoing encryptedPackets, congestion UX, AudioContext resume |
| `sdk/typescript/endpoint_e2ee_conformance.ts` | +~65 lines | Verify congestion does not terminate E2EE or request larger keyframe; count outgoing sealed packets |
| `crates/ucr-architecture-tests/tests/webrtc_provider.rs` | +~40 lines | Static gates for Join, ICE, congestion, first-party handoff |
| `crates/ucr-realtime-web/src/main.rs` | +~3 lines | Diagnostics export remains bounded, with offeredIceServerKinds and lastFailure |

Congestion/retry safety are correctness fixes, not new default-on risky flags.
`ucrSoftNetworkRecovery` still defaults off.
