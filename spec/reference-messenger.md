# Phase 40 — Reference Messenger

## Status

Phase 40 begins the **Prepared Reference Messenger** as an ordinary external consumer of the public UCR contract.
This initial Phase-40 slice establishes the public-client purity boundary and exposes the already-public CallService through the Rust SDK. It does **not** claim the full Canon proof is complete.

## Canonical boundary

The only allowed dependency direction is:

```text
Reference Messenger
        ↓
Public UCR SDK / API
        ↓
UCR
```

The Reference Messenger must not import `ucr-core`, storage providers, Chat/Group runtime crates, transport internals, or any hidden API. It has no direct database access and owns no Identity, Conversation, Message, Group, Call, Delivery, Sync, Recovery, routing, policy or retry state.

## User-facing model

Primary concepts are Person, Group, Message, Call and Result. Infrastructure implementation names such as STUN, TURN, QUIC, relay or provider API are not primary user concepts.

Presentation state uses localization keys rather than baked event sentences. The model is Unicode-safe and direction-aware. A concrete platform client must support screen-reader semantics, keyboard navigation, text scaling, captions, subtitles, transcription surfaces, high contrast and RTL-ready layout.

## Current public proof matrix

The code-level states are `PublicApiAvailable`, `PublicApiGap` and `PresentationModelOnly`.

| Canon proof area | Phase-40 state | Public evidence / blocker |
| --- | --- | --- |
| Chat | Public API available | IntegrationService Conversation/Message RPCs |
| Groups | Public API available | GroupService lifecycle/membership/message RPCs |
| Calls | Public API available | CallService StartCall/GetCall/SignalCall |
| Multi-device | Public API gap | no public Sync/Device lifecycle service |
| Local | Public API gap | no public local-route consumer service |
| Offline | Public API gap | no public Store-and-Forward consumer service |
| P2P | Public API gap | no public P2P/local transport consumer service |
| Recovery | Public API gap | no public Recovery workflow service |
| Accessibility | Presentation model only | concrete platform UI evidence still required |

A gap must remain explicit until the corresponding functionality is reachable through a versioned public API. Phase 40 must not close a gap by linking the Reference Messenger directly to an internal owner.

## Calls through the public SDK

The existing versioned `CallService` is part of the public protobuf contract and already has a thin authenticated gRPC server binding over canonical Call owners. The Rust SDK therefore exposes `start_call`, `get_call` and `signal_call` with the same Service Principal metadata, message ceiling and no hidden application retry.

Call response envelopes remain canonical protobuf responses. SDK or Reference Messenger code must not translate signalling acknowledgement into media, delivery or call-quality success.

## Offline and partial-availability UX

The presentation vocabulary contains an explicit `AwaitingDeliveryOpportunity` state. Absence of an allowed route is not automatically presented as a terminal send failure. Partial availability is representable without claiming that an entire Conversation is unavailable.

This slice does not yet expose cancel/expiry/retry/priority operations because the required public Store-and-Forward consumer service is not present. Those controls must not be simulated locally.

## Accessibility and localization maturity

The checked-in Rust presentation contract records the Canon requirements, but it is not itself proof that a native/web platform has passed screen-reader, keyboard, scaling, caption/subtitle/transcription and high-contrast tests. That proof remains required before Phase 40 can be called complete.

## Nonclaims and next closure work

Phase 40 is incomplete until public consumer surfaces and executable Reference Messenger evidence cover multi-device, local, offline, P2P, recovery and concrete accessibility. Creating those surfaces must reuse the existing canonical owners and must not add a second communication brain.

Phase 41 remains the owner of the full cross-implementation Conformance Suite; Phase 40 may add focused evidence only for its Reference Messenger boundary.
