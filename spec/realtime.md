# Realtime Conference Transport

Status: **contract-stable / bounded runtime and browser-mobile transport implemented; Production certification pending**.

The public realtime boundary is `ucr.v1.RealtimeService`. It exposes conference join/session liveness plus uplink/downlink of already-encrypted MLS group-media frames. It is a transport/service boundary over the canonical Conference/SFU implementation, not a new Call, Group, membership, authorization, crypto, Delivery or recording owner.

## Join URL and authentication

`ConferenceService.IssueJoinUrl` issues a short-lived, single-participant session grant only after current Call/Group authorization succeeds. The join URL carries the signed credential in its URL fragment, not the query string. Browser clients extract the fragment locally and present the credential through Authorization metadata when calling the realtime boundary. Gateways must redact the credential and full join URL from access logs, metrics, errors and traces.

A grant is bound to exact TenantScope, Call ID, participant, **active canonical Device ID**, session ID and expiry. Join issuance resolves the Device and its Principal→Identity association before signing; realtime attendance therefore never invents a synthetic source device. It cannot be widened by client-provided request fields. Expired, malformed, wrong-scope, wrong-call or wrong-session credentials fail closed. Production signing keys are deployment secrets, never protocol payloads.

When a valid grant has a future `not_before`, the reference browser client enters a waiting-room state instead of treating the grant as an error. It keeps the bearer in the fragment, does not call realtime APIs early, and automatically attempts admission when the signed window opens. Universal grant issuance is intentionally separate from the operator `entry_open` gate: a personalized attendee grant may be created while entry is closed. At realtime admission, active Attendees receive a retryable temporary-unavailable result until `entry_open=true`; Owner/Host/Moderator/Speaker roles are not held by the attendee gate so they can enter and operate the room. The browser maps that retryable result to `waiting_room` and retries at a bounded interval without redeeming a single-use grant before admission succeeds. Expiry, removal, revocation and other policy failures still fail closed.

## Media path

`PublishMedia` accepts only `SfuForwardEnvelope`, whose payload is already endpoint-encrypted and source-signed. The runtime revalidates the authenticated session Principal/Device against the frame header and canonical Call/Group/MLS state before delegating to `SfuRuntime`.

`SubscribeMedia` streams only encrypted envelopes selected for the authenticated recipient. Subscription preference remains owned by `ConferenceSubscriptionSet`; receiving a stream never grants membership or media permission. Backpressure is bounded and explicit. A full per-session queue rejects new forwarding work rather than buffering without bound.

The reference browser/mobile binding is `ucr-realtime-web`: it serves a self-contained join client plus bounded JSON/protobuf POST uplink and authenticated streaming/SSE downlink over a loopback listener. The public edge must terminate HTTPS and proxy only to that loopback boundary. The join client reads the signed grant from the URL fragment, derives only the non-secret routing coordinates needed for the request, and never places the bearer token in the request URL.

A dropped browser downlink may be reattached to the exact still-authenticated realtime session without redeeming the join grant again. The registry creates a fresh bounded queue only after the prior receiver is actually closed, advances the session sequence, and emits the canonical `reconnected` attendance transition; a competing live second consumer is rejected. The browser retries the media stream after temporary network loss and `offline -> online` transitions while the signed session remains valid. This preserves one-time join-grant semantics while allowing transport reconnection.

The same authenticated session now owns the WebRTC signalling lifecycle. `StartWebRtc`, `SetWebRtcRemoteDescription`, `AddWebRtcIceCandidate`, and `CloseWebRtc` are methods of the existing `ucr.v1.RealtimeService`; they do not introduce a second signalling/authentication owner. Each call revalidates the signed grant, exact scope/call/session tuple, accepted Conference participant and active realtime registry session before touching ephemeral peer state. Blocking peer-engine operations execute outside the Tokio gRPC executor.

Browser-origin policy is fail-closed. Same-origin browser requests are accepted by exact `Origin` + `Host` match. Additional embedding/application origins must be enumerated in `UCR_REALTIME_ALLOWED_ORIGINS`; wildcard origins are rejected. Allowed cross-origin responses echo only the validated exact origin, include `Vary: Origin`, and expose only the bounded POST/OPTIONS + Authorization/Content-Type preflight surface. A disallowed browser origin is rejected before bearer-token or request-body processing.

## Attendance

Successful realtime join, explicit leave, reconnect restoration and first media-ready transition append canonical `EventEnvelope` records using these versioned event types:

- `ucr.conference.attendance.joined.v1`
- `ucr.conference.attendance.left.v1`
- `ucr.conference.attendance.reconnected.v1`
- `ucr.conference.attendance.media_ready.v1`

The payload is `ConferenceAttendanceEvent`. Attendance uses the canonical Event journal/subscription pipeline; no second attendance database is introduced. Heartbeats are liveness input and need not become durable attendance events by default.

## WebRTC / ICE / TURN provider boundary

`ucr-webrtc` defines the universal WebRTC transport provider boundary without becoming a second Call, Conference, SFU, membership or authorization owner. It models bounded SDP offer/answer exchange, trickle ICE candidates, ICE transport policy and deployment-supplied STUN/TURN server configuration. TURN usernames and credentials are transport secrets: model debug output redacts credential material and the provider contract does not persist them.

The canonical protocol exposes three capability identifiers: `ucr.realtime.webrtc.browser`, `ucr.realtime.webrtc.ice`, and `ucr.realtime.webrtc.turn`. They are currently reported as `Prepared`, not `Production`. `PreparedWebRtcProvider` validates the contract and fails closed with `TemporarilyUnavailable`; it deliberately does not pretend that a live peer connection exists.

The provider lifecycle is ephemeral: create session, apply remote description, add remote candidate, and close session. Closing provider state does not end the canonical Call. A concrete WebRTC engine adapter must remain beneath this boundary and must preserve UCR ownership of signalling policy, authorization, Conference lifecycle and encrypted media routing.

`LiveWebRtcProvider` is the first concrete engine adapter. It runs `webrtc-rs 0.17.2` on an isolated bounded worker, caps both queued commands and live peer sessions, maps deployment STUN/TURN settings into the engine, creates receive-only audio and video transceivers, emits a fully gathered SDP offer, applies a remote offer/answer and trickle ICE candidates, and closes ephemeral peer state deterministically. The synchronous provider contract never calls `block_on` inside an application Tokio runtime.

The authenticated RealtimeService signalling surface and reference browser camera/microphone client are now implemented. The browser obtains the server offer and per-session ICE servers only after authenticated realtime admission, creates a native `RTCPeerConnection`, acquires local audio/video with `getUserMedia` for endpoint capture/preview, sends its SDP answer and trickle ICE candidates, supports microphone/camera toggles and device selection, and performs bounded reconnect using the same still-valid realtime session. Signalling responses that may contain TURN credentials are `Cache-Control: no-store`.

The reference browser also supports endpoint-only screen capture through `getDisplayMedia` when
the browser and endpoint E2EE adapter both support live source updates. Screen capture is previewed
locally and handed to the adapter as `screenStream`; it is stopped deterministically when the
browser ends sharing, the participant leaves, the E2EE DataChannel closes, or the page is torn
down. Explicit Leave stops local display capture before any best-effort server shutdown request, so
a stalled network cleanup cannot keep the screen capture alive. The screen track is never attached
to server-visible RTP. Browsers without display-capture support (including mobile environments
where the API is unavailable) keep the control disabled. This browser capture boundary does not by
itself claim a distinct canonical screen-share authorization policy; server authorization still
applies to every encrypted video envelope and a later public policy layer must differentiate
screen-share authority before that part of the capability can be promoted.

Conference media uses the server-created ordered DataChannel `ucr.e2ee.media.v1`, not raw browser RTP. The transport-neutral `SfuForwardEnvelope` wire v1 codec is owned by `ucr-protocol`; WebRTC owns only bounded 16,000-byte chunking/reassembly and delegates envelope encode/decode back to that protocol owner. The TypeScript endpoint mirror is byte-for-byte locked to the Rust codec by a fixed cross-language Conformance vector. The server canonical-validates the reassembled envelope, binds it to the active scope/call/session, revalidates current grant/device/publish policy, and routes the unchanged ciphertext through the existing `ConferenceRuntime -> SfuRuntime` path. Downlink ciphertext is chunked through the same DataChannel. The reference browser deliberately does not call `pc.addTrack(...)` and rejects unexpected RTP tracks, so endpoint camera/microphone samples are not exposed to the server merely because WebRTC signalling is connected.

Endpoint cryptography remains an endpoint responsibility. The reference browser only activates media publication when an application supplies `window.ucrE2eeEndpoint` with `start` and `onEnvelope` hooks; the adapter receives the local `MediaStream` plus a bounded `sendEnvelope` callback and is responsible for producing/opening canonical encrypted envelopes using endpoint-held MLS/group-media key material. If that adapter is absent or fails, the browser keeps the transport connected but publishes no media. UCR runtime/provider code receives neither exporter secrets nor plaintext media.

This still does **not** promote the public WebRTC capabilities above `Prepared`. Production maturity continues to require a concrete browser/native endpoint E2EE adapter with interoperable crypto evidence, live public TURN traversal evidence, ICE-restart/network-adversity proof, browser/mobile interoperability, media-to-SFU load/backpressure evidence, and protected release evidence.

TURN credentials are issued per realtime session through `TurnRestCredentialIssuer`, never as a repository/static client password. The issuer follows coturn TURN REST shared-secret semantics: the username is `expiry_unix_seconds:session_id`, the credential is Base64(HMAC-SHA1(shared_secret, username)), TTL is bounded to 30–3600 seconds, and the in-memory shared secret is zeroized on drop. Realtime signalling additionally caps the issued TURN expiry at the signed realtime-session expiry and refuses fresh TURN issuance when less than the minimum 30-second credential lifetime remains. Credential/debug output is redacted. This closes credential issuance semantics but does not by itself make ICE/TURN connectivity Production; that still requires a live TURN deployment and interoperability evidence.

The production realtime daemon accepts STUN URLs from `UCR_WEBRTC_STUN_URLS` and TURN URLs from `UCR_WEBRTC_TURN_URLS`. TURN configuration requires `UCR_WEBRTC_TURN_SECRET_HEX`; `UCR_WEBRTC_TURN_TTL_SECONDS` defaults to 300 seconds and remains bounded by the provider policy. `UCR_WEBRTC_RELAY_ONLY=true` enforces relay-only ICE. Invalid or inconsistent ICE configuration fails daemon startup rather than silently falling back to static or unauthenticated credentials.

## Production boundary

A Production claim requires: bounded session/queue limits, authenticated public TLS edge, secret rotation, expiry/replay tests, concurrent join/leave tests, SFU backpressure evidence, restart behavior, browser/mobile interoperability tests, real ICE/STUN/TURN connectivity and protected release evidence. Contract presence alone is not a Production claim.
