# Phase 27 — Store-and-Forward

Status: **Prepared/reference**.

Phase 27 adds restart-safe sender-side durable scheduling over the existing canonical Communication Intent, Message, Delivery, Policy, Endpoint and Transport owners. It does not create a second Message body, Delivery state machine, route graph, Relay, Mesh layer, or exactly-once claim.

## Scope

The Prepared reference runtime accepts an already-encrypted opaque envelope associated with one existing canonical `CommunicationIntent` and one existing persisted canonical `MessageEnvelope`. `DeliveryPolicy::BestEffort` is excluded. Expiring jobs require an explicit expiry.

The capability is `ucr.delivery.store_forward`. The current Phase-27 execution path intentionally admits only the already-implemented direct `ucr.transport.internet.tcp` and `ucr.transport.local.tcp` capabilities. Phase 28 Mesh is a separate signed-Group-Message peer layer; Relay, intermediary infrastructure and discovery remain later work.

## Durable scheduling owner

`StoreForwardStore` is a scheduling sidecar over `DeliveryStore + CommunicationIntentStore`; `MessageStore` remains the canonical Message owner inherited through Delivery. A job stores the exact scope, Intent/Message IDs, opaque encrypted transport input, bounded retry/lease policy, due time, consumed-attempt count and the latest canonical `DeliveryId`.

The encrypted envelope is transport input, not a second canonical Message body. Debug surfaces redact it. The sidecar never owns Delivery truth: state transitions remain in the existing `DeliveryAttempt` state machine.

Jobs are bounded to at most 64 provider-bearing Delivery attempts, pages are bounded to 256 jobs, retry delay is capped at seven days, and a processing lease is capped at five minutes. Exponential backoff saturates at the configured maximum.

## Attempt identity and duplicate safety

No-route planning does not consume a Delivery attempt. Route planning receives the current caller-supplied resource snapshot and bounded routing hints on every processing iteration; Store-and-Forward never fabricates battery, power, or thermal state. Only after route planning succeeds does the scheduler create or resume a canonical `DeliveryAttempt`, move it through `Persisted -> Encrypted -> Queued -> RoutePlanned -> InFlight`, and invoke a provider.

Each real provider invocation is bound to exactly one canonical `DeliveryId`. Phase 27 invokes the existing Phase-25 failover engine with `max_route_attempts = 1`; a later proven retry receives a new deterministic `DeliveryId`. A terminal Delivery attempt is never rewound in place.

The deterministic retry ID binds exact TenantScope + StoreForward ID + attempt ordinal. It contains no wall clock, host, route, provider or business identifier semantics.

## Acceptance ambiguity

A provider success supplies only `AcceptedByTransport` evidence and moves the canonical Delivery attempt to `Acknowledged`; it is not `Delivered`, `PresentedToUser`, or `ReadByUser` evidence.

A failure classified as proven non-acceptance closes the current attempt as `Failed` and may schedule a later attempt within the configured bounds. Ambiguous acceptance leaves the canonical attempt `InFlight`. Once that state exists, due enumeration and lease claiming exclude the job and the runtime returns `AcceptanceUnknown` rather than automatically replaying the envelope.

This is deliberate crash behavior. If the process dies after `InFlight` is persisted but before a receipt is durably interpreted, restart does not guess whether the peer accepted the bytes. Phase 27 prefers an explicit stuck/ambiguous state to duplicate side effects.

## Leases and restart behavior

A processing lease is bounded, restart-safe store-private concurrency metadata. It is not authorization, identity, route evidence, Delivery evidence or part of the public protobuf surface. Expired leases may be reclaimed only when canonical Delivery truth permits another action.

SQLite v24 persists jobs, lease metadata, immutable enqueue fingerprints and completion tombstones. Migration v23->v24 creates the new tables empty; it never invents pending jobs from historical Messages, Intents or Delivery attempts.

## Completion tombstones

Completion removes the live scheduling row but persists a SHA-256 fingerprint of the immutable initial enqueue semantics. Retrying the same `StoreForwardId` with the exact original semantics is `Duplicate`; reusing that ID with changed ciphertext, owner references, policy or initial due time is `Conflict`.

The tombstone prevents a caller from resurrecting a successfully completed or exhausted job and causing a second send merely because the live queue row was deleted.

## Public contract

`proto/ucr/v1/store_forward.proto` defines bounded policy/job/outcome data parity only. It intentionally defines no service, no `EndpointAddress`, no Relay type and no public lease message. Production service lifecycle, worker orchestration and remote intermediary protocols remain separate phases.

## Non-claims

Phase 27 does not itself claim exactly-once delivery, recipient delivery/read evidence, Relay, multi-hop forwarding, mesh, multipath simultaneous execution, NAT traversal, discovery, Bridge forwarding, SFU/conferencing, production worker deployment, or automatic resolution of ambiguous `InFlight` attempts. A later phase must add any intermediary node as an explicit trust boundary rather than widening this sender-side scheduler silently.
