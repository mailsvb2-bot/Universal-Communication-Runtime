# RT0 secure call recovery — end-to-end workstream

Scope: audio calls, video calls, screen sharing, and multiparty conferences. This branch is deliberately independent of active endpoint adapter and privacy hardening PRs. Reuse canonical Call/Group/session/device/MLS owners; no separate call registry or credential store.

## Implemented in this branch
- Browser retries WebRTC ICE recovery with bounded exponential backoff, reset after successful connectivity/network return.
- Unexpected E2EE DataChannel closure schedules media recovery; never fall back to unencrypted RTP.
- Existing authenticated session and Call ID are retained for transport retries; no token-extension bypass.
- Existing expiry guards remain in place, and `pagehide` leave behavior is unchanged pending canonical resume semantics.

## Required production journeys — not yet complete
1. **Short interruption:** during an authorized encrypted A→B call, disconnect Wi-Fi and restore. ICE restart, DataChannel open and audio/video playback must resume; measure p50/p95 reconnect delay.
2. **Changed NAT/transport:** Wi-Fi→mobile and VPN switch, with real TURN credentials and different browsers; rebuild WebRTC only after failed ICE recovery, preserve active canonical session.
3. **Long outage:** preserve server-defined active attendance only within explicitly issued session lease. After expiry require normal authenticated admission; never silently reauthorize from saved browser tokens.
4. **App/page restart:** distinguish unintentional tab suspension/navigation from explicit Leave. Implement canonical resumable session grant and idempotent resume before relaxing `pagehide`. Current pagehide performs Leave deliberately; this scenario is NOT implemented.
5. **Revoked/excluded attendee:** on reconnection, authoritative Group/Call/Device and active MLS epoch must refuse both publish and receive. Do not rehydrate revoked crypto state.
6. **Conference membership:** participants retain authoritative Call ID and MLS group membership. On legal rejoin, MLS epoch transitions and endpoint bridge invalidation must be verified.
7. **Stop semantics:** explicit Hang up/Leave must cancel all pending retries, close server and endpoint state exactly once, and never auto-call again.
8. **Performance/telemetry:** record bounded latency timings (ICE-restart, first encrypted frame, first playable audio/video), without storing IP, keys or private participant identifiers. Assess on real phones and desktop under NAT/TURN.

Exit criterion: two separate real devices, caller and callee automatically regain E2EE audio/video within valid grants after interruption; permission revocations and expired tokens always stop reconnect. No success claim based only on loopback CI.
