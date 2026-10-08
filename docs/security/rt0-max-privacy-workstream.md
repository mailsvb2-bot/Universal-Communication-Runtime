# RT0 maximum privacy hardening — compatibility-first work branch

**Status:** active implementation branch; NOT a production-security certification.

**Canonical owners remain unchanged:** Group/Call and membership, MLS key lifecycle, identity/device authority, SfuRuntime recipient authorization, realtime session registry, WebRTC transport. No parallel crypto/policy/runtime engine. Branch forked from `main` deliberately so that in-progress PR #259 stays independent; reconcile with PR #259 before integration.

## First implemented change
- `crates/ucr-endpoint-wasm/src/lib.rs`: `EndpointGroupMediaBridge.revoke()` transitions an endpoint crypto bridge to a permanently closed state.
- Subsequent `seal_wire` and `open_wire` calls fail closed rather than silently reusing old MLS media secrets after a leave, rekey or device revocation.
- Both construction paths (explicit constructor and `EndpointMlsState.media_bridge`) initialize the guard.
- The browser adapter must explicitly call `revoke()` when canonical join/MLS state changes. This branch does NOT yet auto-subscribe to that event; never claim automatic revocation is delivered.

## Tracked end-to-end security work (must be implemented, exercised and CI-verified)

1. **Canonical Rust replay/epoch ownership.** Move final replay cursor acceptance and active epoch validation to the existing Rust group-media crypto owner, atomically under concurrent inbounds; browser TS checks remain early DoS filters, never a second authority. Test replay, epoch rollback, concurrent race, old group, duplicate and revocation.
2. **Source authorization lifecycle.** Link web client to existing realtime registry/group-device identity, active MLS membership and trusted signer state. Reject wrong call/scope/device and revoked entries. No blanket allow-all fallback.
3. **Short-lived identifiers.** Derive transport-scoped opaque session handles from canonical issued grants; bind expiry, call, principal/device and rotation/rejoin, ensure the SFU can still authorize. Avoid introducing a shadow identity store.
4. **Network privacy.** Reuse existing ICE/TURN configuration and authoritative privacy policy. Relay-only option must fail closed if TURN missing. A truly independent relay requires separate deployment and measured topology; configuration alone does not anonymize.
5. **Supply-chain security.** Signed/artifact-verified JS/WASM delivery, pinned immutable artifacts, secure headers/CSP/Trusted Types as supported; forbid key/plaintext logging and protect sealed endpoint snapshot lifecycle. No claim of complete isolation from same-origin malicious JS.
6. **Privacy observability & latency.** Introduce opt-in, bounded, privacy-safe measurements for connect/ICE/DTLS/first-audio/video/p95/p99. Test browser+mobile on real NAT/TURN, no raw IP/private IDs/keys in telemetry.
7. **Security/performance regression gates.** Enforce no plaintext fallback, no accidental downgrade, bounded media queues, zero unbounded per-frame network preflights. Cache locally validated public key refs only until canonical revocation/epoch changes; benchmark and prove speed rather than advertise instant connection.
8. **Media trace minimization.** Split public routing header from private metadata only after backwards-compatible protocol migration plan and security review. No blind encryption of SFU-required IDs, which would break authentication/routing.

## Exit criterion
Two genuinely separate browsers/devices, real microphone and camera, authentic canonical join/auth, E2EE end to end, revoked attendee immediately blocked, no plaintext fallback, privacy/TURN failures safely handled, and measured latency under representative networks. CI plus real-device production-like test evidence required. Do not merge an unverified isolated security claim.
