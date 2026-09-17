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

The code-level states are `PublicApiAvailable`, `PublicApiGap` and `ConcretePlatformEvidence`.

| Canon proof area | Phase-40 state | Public evidence / blocker |
| --- | --- | --- |
| Chat | Public API available | IntegrationService Conversation/Message RPCs |
| Groups | Public API available | GroupService lifecycle/membership/message RPCs |
| Calls | Public API available | CallService StartCall/GetCall/SignalCall |
| Multi-device | Public API available | DeviceService lifecycle + SyncService session/checkpoint RPCs |
| Local | Public API available | LocalTransportService authenticated direct transmit RPC |
| Offline | Public API available | StoreForwardService enqueue + payload-free status RPCs |
| P2P | Public API available | MeshService authenticated peer export/reconcile RPCs |
| Recovery | Public API available | RecoveryService plan + proof-gated Device recovery RPCs |
| Accessibility | Concrete platform evidence | browser semantic UI + executable accessibility validator |

A gap must remain explicit until the corresponding functionality is reachable through a versioned public API. Phase 40 must not close a gap by linking the Reference Messenger directly to an internal owner.

## Calls through the public SDK

The existing versioned `CallService` is part of the public protobuf contract and already has a thin authenticated gRPC server binding over canonical Call owners. The Rust SDK therefore exposes `start_call`, `get_call` and `signal_call` with the same Service Principal metadata, message ceiling and no hidden application retry.

Call response envelopes remain canonical protobuf responses. SDK or Reference Messenger code must not translate signalling acknowledgement into media, delivery or call-quality success.


## Direct local communication

The public `LocalTransportService` exposes one explicit direct transmit through the existing Phase-16 local provider. The caller supplies the destination endpoint, transient local address and already-encrypted envelope; capability selection is fixed by UCR, and the service performs no discovery, listener creation, route ranking or cross-route fallback.

The public `MeshService` exposes only bounded export/reconcile of signed Group Message replicas through the existing Phase-28 `MeshGroupsRuntime`. Peer identity and cryptographic session state are resolved by the UCR host from an already-authenticated live Sync session; callers cannot nominate peer identity, topology, relay, NAT traversal, route selection or retry behavior.

A successful response means only authenticated peer-side transport acceptance/deduplication. Failure preserves `NotAccepted` versus `AcceptanceUnknown`, so the Reference Messenger must not present an ambiguous transport result as safely retryable or as Delivery/Read success. The primary UI concept remains `DirectCommunication`; TCP/address/provider vocabulary is not promoted to a primary user concept.

## Offline and partial-availability UX

The presentation vocabulary contains an explicit `AwaitingDeliveryOpportunity` state. Absence of an allowed route is not automatically presented as a terminal send failure. Partial availability is representable without claiming that an entire Conversation is unavailable.

The public `StoreForwardService` now exposes durable enqueue plus payload-free status through the same public SDK boundary. Reference Messenger maps queued work to `AwaitingDeliveryOpportunity`; enqueue acknowledgement is not Delivery/Read proof. Worker leases, due scans, route selection and retry execution remain internal, and cancel/manual-retry controls are still not simulated locally.

## Recovery

The public `RecoveryService` exposes Recovery Plan install/rotate/revoke/read plus proof-gated recovered-Device staging and independent re-verification activation. Service Principal auth/quota/audit admits the application channel, but ordinary permissions never substitute for the active Recovery Plan, `RecoveryAuthorityVerifier`, or `DeviceReverificationVerifier`. A recovered Device is first staged as `REVERIFICATION_REQUIRED`; only a separate verifier decision can promote that exact Device/Identity to `ACTIVE`.

## Concrete browser accessibility evidence

The checked-in Rust presentation contract is paired with a concrete browser presentation adapter under `crates/ucr-reference-messenger/web/`. The adapter uses semantic landmarks and labels for screen-reader exposure, native keyboard controls and a skip link, scalable `rem`/percentage typography with working 100/125/150% controls, visible focus, explicit high-contrast plus `prefers-contrast`/forced-colors handling, caption and subtitle WebVTT tracks, a live transcript surface, direction-aware content and a working LTR/RTL control. State changes are announced through an `aria-live` status surface. `web/validate_accessibility.py` is executable evidence that these requirements remain present and rejects positive tabindex or browser-side network/native capability leakage.

The browser artifact is presentation-only. It does not claim native-node, LAN transport, background execution, media capture, filesystem or push capabilities, and it does not own communication state. The Reference Messenger still reaches UCR only through the public SDK/API.

## Developer-first Dev Mode

Phase 40 also includes the development-only `ucr dev` host. It seeds canonical local/mock-peer Identity+Device state, memory test storage, authenticated Service Principal admission, a test transport, debug events and diagnostics, then exposes public UCR services on loopback. `ucr dev --check` executes authenticated Identity, Conversation, Message, Group and Call operations and the sandbox fault matrix. Auth, permissions and quota admission remain enabled; non-loopback bind is rejected. Full conformance remains Phase 41.

## Phase-40 closure

All nine Canon proof areas now have explicit Reference Messenger evidence: eight communication areas through public UCR services and accessibility through the concrete browser presentation adapter. The developer-first requirement is independently exercised by `ucr dev --check` with auth-on loopback public API and the required sandbox/test-transport matrix. Phase 40 does not claim Phase-41 cross-implementation conformance or production platform certification; those remain later work.

Phase 41 remains the owner of the full cross-implementation Conformance Suite.
