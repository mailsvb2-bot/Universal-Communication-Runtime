# Phase 19 Call Signalling

Status: **Prepared reference implementation**, not Production.

Phase 19 adds a canonical, transport-independent `CallSession` signalling layer. It reuses existing `TenantScope`, `PrincipalRef`, `ConversationRef`, Group membership, Service Principal admission, authorization, Event identity, and durable Memory/SQLite owners. It does not create a second identity, conversation, message, delivery, transport, or media system.

## Session and participants

A CallSession has one exact scope, `CallId`, existing Direct/private-group/public-group Conversation, authenticated initiator, canonical participants, signalling state, revision, replication generation, and optional opaque media-negotiation reference. Participant identity is the complete `PrincipalRef` (`principal_id` plus `PrincipalKind`). Participant removal is represented durably; restart or retry cannot silently restore authority.

Initial creation starts at revision/generation zero with the initiator Accepted and all remote participants Invited. Direct calls require the referenced Conversation to exist. Group calls additionally require every initial participant to be an active member of the canonical Group aggregate.

## Signalling state machine

Prepared signalling supports invite creation plus `Ringing`, `Accept`, `Reject`, `Busy`, `Cancel`, `Timeout`, reconnect start/restored, participant add/remove, opaque media renegotiation signalling, and termination. Every mutation carries an exact-scope `EventId` and expected revision. Stale revisions and invalid state transitions fail closed. Once a session is `Reconnecting`, unrelated participant ringing/accept/reject/remove progress does not silently clear that state while at least one accepted remote remains; returning to `Active` requires an explicit `Reconnect::Restored` signal.

`Active` means only that signalling acceptance has completed. It is not proof that RTP, audio, video, E2EE media, ICE, TURN, SFU, device capture, playback, or any real media path exists.

## Authority and idempotency

`ucr.call.start`, `ucr.call.observe`, and `ucr.call.signal` are independent protocol-owned permissions. Public gRPC calls authenticate through the existing Service Principal credential metadata and single-use quota/audit request gate. The actor for a signal is resolved from the authenticated credential; protobuf bodies cannot supply or override it.

Durable stores apply participant authority, transition validation, `EventId` reservation, revision update, and signal-ledger persistence atomically. Duplicate recognition is bound to the original full `PrincipalRef` and exact signal fingerprint. A signal that itself changes the actor to Rejected/Busy/Left remains exactly retryable, but later independent loss of authority cannot be used to probe duplicate/conflict state.

`EventId` is one exact-scope fact namespace across ordinary canonical Event rows, Group changes, and Call signals. Reuse by an unrelated fact is a conflict in either insertion order.

## Reads and non-disclosure

`GetCall` is a participant-gated read over the same storage snapshot used to verify current authority. Missing calls and existing calls for which the authenticated principal has no current signalling authority both return non-disclosing absence at the store boundary. The public binding maps authorized absence to canonical `NOT_FOUND` only after Service Principal admission and `ucr.call.observe` authorization succeed.

For group-backed calls, current Group membership is also rechecked inside the same store operation. Removal from the canonical Group therefore removes call-read/signal authority without requiring a second membership database.

## Durability

SQLite schema v22 adds normalized `calls`, `call_participants`, and `call_signals` state. Migration from v21 creates no inferred calls, participants, or signalling facts. Reopen preserves session revision/state and exact duplicate semantics. The existing Conversation and Group tables remain canonical referenced owners.

Memory is the reference/contract store; SQLite is the restart-safe reference store. Both implement the same actor-bound transition and non-disclosure contract.

## Public reference binding

`proto/ucr/v1/call.proto` defines `CallService` with `StartCall`, `GetCall`, and `SignalCall`. Tonic/Prost generated Rust is a disposable binding. The service delegates through the existing `IntegrationIngress`/`ServicePrincipalRequestGate`/`AuthorizedDurableRuntime` path and never exposes raw stores.

Reference loopback HTTP/2 evidence proves credential-bound start/signal/get, exact duplicate retry, canonical errors, bad-secret rejection, and non-participant non-disclosure. Repeating the exact original `StartCall` remains a duplicate after later signalling progress or restart because creation identity is stored separately from mutable call state. `StartCall` returns the accepted creation fact; clients use `GetCall` for the current signalling state. It is interoperability evidence, not a production listener.

## Explicit nonclaims

Phase 19 does **not** claim audio transport, video transport, microphone/camera capture, playback, codecs, RTP/SRTP, WebRTC, ICE/STUN/TURN, Relay/NAT traversal, SFU/conferencing, E2EE media implementation, adaptive bitrate/media policy, media quality telemetry, push ringing delivery, OS call UI, Reference Messenger call UI, provider call bridges, Transport Orchestrator behavior, or production listener/deployment hardening.

Phase 20 Audio and later media phases own those capabilities. They must consume the canonical CallSession/signalling state rather than replace it with a second call brain.
