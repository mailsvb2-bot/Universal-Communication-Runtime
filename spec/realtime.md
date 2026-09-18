# Realtime Conference Transport

Status: **contract-stable / runtime implementation pending in this slice**.

The public realtime boundary is `ucr.v1.RealtimeService`. It exposes conference join/session liveness plus uplink/downlink of already-encrypted MLS group-media frames. It is a transport/service boundary over the canonical Conference/SFU implementation, not a new Call, Group, membership, authorization, crypto, Delivery or recording owner.

## Join URL and authentication

`ConferenceService.IssueJoinUrl` issues a short-lived, single-participant session grant only after current Call/Group authorization succeeds. The join URL carries the signed credential in its URL fragment, not the query string. Browser clients extract the fragment locally and present the credential through Authorization metadata when calling the realtime boundary. Gateways must redact the credential and full join URL from access logs, metrics, errors and traces.

A grant is bound to exact TenantScope, Call ID, participant, **active canonical Device ID**, session ID and expiry. Join issuance resolves the Device and its Principal→Identity association before signing; realtime attendance therefore never invents a synthetic source device. It cannot be widened by client-provided request fields. Expired, malformed, wrong-scope, wrong-call or wrong-session credentials fail closed. Production signing keys are deployment secrets, never protocol payloads.

## Media path

`PublishMedia` accepts only `SfuForwardEnvelope`, whose payload is already endpoint-encrypted and source-signed. The runtime revalidates the authenticated session Principal/Device against the frame header and canonical Call/Group/MLS state before delegating to `SfuRuntime`.

`SubscribeMedia` streams only encrypted envelopes selected for the authenticated recipient. Subscription preference remains owned by `ConferenceSubscriptionSet`; receiving a stream never grants membership or media permission. Backpressure is bounded and explicit. A full per-session queue rejects new forwarding work rather than buffering without bound.

The production HTTP/browser binding may map protobuf POST uplink plus authenticated server-streaming/SSE or HTTP/2 downlink onto the same semantics. That binding must use HTTPS at the public edge. It must not widen the existing loopback-only plaintext daemon. A future WebRTC/ICE/TURN provider may implement the same service semantics without changing canonical owners.

## Attendance

Successful realtime join, explicit leave, reconnect restoration and first media-ready transition append canonical `EventEnvelope` records using these versioned event types:

- `ucr.conference.attendance.joined.v1`
- `ucr.conference.attendance.left.v1`
- `ucr.conference.attendance.reconnected.v1`
- `ucr.conference.attendance.media_ready.v1`

The payload is `ConferenceAttendanceEvent`. Attendance uses the canonical Event journal/subscription pipeline; no second attendance database is introduced. Heartbeats are liveness input and need not become durable attendance events by default.

## Production boundary

A Production claim requires: bounded session/queue limits, authenticated public TLS edge, secret rotation, expiry/replay tests, concurrent join/leave tests, SFU backpressure evidence, restart behavior, browser/mobile interoperability tests and protected release evidence. Contract presence alone is not a Production claim.
