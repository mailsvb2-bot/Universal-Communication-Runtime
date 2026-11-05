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

Risky behavior (`ucrSoftNetworkRecovery`) defaults **off**.
