# Conferences

Conference composes the existing Group Call + group Audio/Video + MLS group-media E2EE + SFU stack into one coherent workflow. It does **not** create a second CallSession, participant roster, membership database, signalling state machine, crypto owner, or durable SFU routing graph.

## Canonical ownership

- `GroupRecord` remains Group identity, membership and role authority.
- `CallSession` remains the only durable realtime signalling lifecycle and participant tombstone owner.
- Audio and Video remain media codec/stream owners.
- OpenMLS/RFC 9420 remains group-key epoch owner.
- `SfuRuntime` remains encrypted fan-out owner and receives no plaintext/key material.
- Conference is a bounded coordinator/projection over those owners.
- `ConferenceService` is the stable public service facade over that same coordinator; it is not a second durable owner.

`ConferenceStart` carries only scope, Call ID, Group ID and remote invitees. The authenticated caller becomes the Call initiator. Every invitee must already be an active Group member. Exact retries reuse `CallStore` creation idempotency; changed semantics conflict through the existing Call owner.

`ConferenceSnapshot` is derived on demand from current `CallSession` + Group MLS state. It is never persisted as a second source of truth. Participant add/remove, accept/reject, reconnect, media renegotiation and termination remain canonical `CallSignal` operations.

## Stable public boundary

`ucr.v1.ConferenceService` exposes Start/Get/Signal, recipient subscription preferences and short-lived participant join URLs. Authentication credentials stay in binding metadata. Every service operation delegates to the existing Conference/Call/Group authorization path and returns canonical `ErrorEnvelope` semantics.

Join URLs are bounded grants, not membership invitations by themselves. Issuance revalidates the current participant and Group/Call state, binds exact scope/call/participant/device/session/expiry, and places the opaque signed credential in the URL fragment so ordinary HTTP request logs do not receive it. The realtime service revalidates the grant again on use.

## Scale and selective forwarding

The shared bounded Call/Audio/Video/SFU ceiling is **1024 participants**. Reference evidence drives a **1000-person Conference to 1000 accepted participants**; the 1025th participant fails closed. This is a protocol/reference capacity claim, not a Production load/SLA claim. Production operation at this scale still requires explicit CPU/RAM/bandwidth/backpressure/load evidence and may use sharded or federated SFU infrastructure.

A 1000-person Conference must not imply all-to-all media fan-out. Each accepted recipient owns an ephemeral `ConferenceSubscriptionSet` of at most **32 source/media pairs**. The Conference coordinator derives selected recipients from those sets and delegates encrypted forwarding to `SfuRuntime::forward_selected`. SFU still revalidates current Call participation, Group membership and receive permission for every selected recipient before any sink side effect; a subscription is routing preference, never authorization.

Subscription state is bounded and non-durable. Empty sets unsubscribe from all streams and release the tracked entry. Stale entries/sources are pruned on signalling and before subscription/forward operations; leave/removal/termination therefore cannot retain routing capacity. After restart clients re-establish desired subscriptions while durable Call/Group/MLS state remains canonical.

All Conference media topology is SFU in this reference layer. Uncontrolled full-mesh Conference topology is not introduced.

## Permissions and failure semantics

Conference start reuses `ucr.call.start`; signalling reuses `ucr.call.signal`; explicit reads reuse `ucr.call.observe`; recipient subscription changes require `ucr.conference.subscribe`. Join URL issuance requires its own service-bound authorization plus current participant eligibility. These permissions are independent. Audio/video send/receive permissions are still revalidated by the existing media/SFU owners.

Conference coordination does not convert SFU acceptance into Delivery/Read evidence and does not claim exactly-once media forwarding. SFU backpressure/partial acceptance retains the SFU semantics and cannot mutate Call authority.

Group removal immediately invalidates Call participation through the existing Group↔Call reconciliation owner. MLS epoch changes invalidate stale encrypted media through the existing SFU checks.

## Recording and transport

Realtime external transport is defined separately in `spec/realtime.md` and `realtime.proto`. It carries only encrypted SFU media and authenticated session liveness.

Recording is defined separately in `spec/recording.md` and `recording.proto`. SFU forwarding never enables recording implicitly. Recording requires explicit capability, policy, participant notification/consent rules, encrypted storage and finite retention.

Data channels/reactions/whiteboard/collaborative state, mixer/compositor, transcoding, WebRTC/ICE/STUN/TURN and sharded/federated SFU remain separate providers/features unless their capabilities are explicitly implemented and advertised.
