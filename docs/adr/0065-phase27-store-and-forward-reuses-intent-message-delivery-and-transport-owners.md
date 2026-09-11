# ADR-0065: Phase 27 Store-and-Forward reuses Intent, Message, Delivery and Transport owners

Status: Accepted

## Context

Phase 26 deliberately prevents a peer from re-exporting remotely reconciled records. Phase 27 needs durable sender-side retry while a recipient or route is temporarily unavailable, but UCR already has canonical Communication Intent, Message, Delivery, Policy, Endpoint, Transport Orchestrator and duplicate-safe provider-acceptance semantics.

A separate forwarding Message database, Delivery state machine or route owner would create a second communication brain. Retrying after an ambiguous provider outcome would also risk duplicate effects.

## Decision

Phase 27 introduces `StoreForwardStore` as a bounded durable scheduling sidecar over the existing canonical owners plus a Prepared `ucr-store-forward` runtime. Jobs persist only owner references, opaque encrypted transport input and scheduling metadata.

No-route planning consumes no Delivery attempt. Every actual provider invocation uses one canonical `DeliveryAttempt` and one `DeliveryId`; the Phase-25 failover executor is called with a provider-attempt budget of one. Proven non-acceptance may close that attempt and schedule a new deterministic Delivery ID. Ambiguous acceptance leaves the attempt `InFlight` and blocks automatic replay.

SQLite v24 persists jobs and bounded leases plus completion tombstones keyed by a stable SHA-256 fingerprint of the immutable initial enqueue semantics. Migration from v23 creates no inferred pending work.

The public protobuf describes policy/job/outcome data only. Processing leases remain store-private. Relay, Mesh, intermediary node protocols, discovery, multipath and exactly-once delivery are not Phase-27 claims.

## Rejected alternatives

- A second Message body or forwarding-message database.
- A second Delivery state machine owned by the queue.
- Rewinding `Failed`, `Expired` or other terminal `DeliveryAttempt` rows for retry.
- Counting no-route planning as a provider-bearing Delivery attempt.
- Multiple provider invocations under one Delivery ID.
- Automatically replaying an `InFlight` attempt after restart or lease expiry.
- Deleting all completion evidence and allowing the same job ID to resurrect.
- Introducing Relay/mesh/intermediary semantics through the direct sender scheduler.

## Consequences

Availability is intentionally conservative. An ambiguous `InFlight` attempt may require later explicit reconciliation/evidence rather than automatic resend. This is preferred to silently creating duplicates.

Phase 27 is Prepared/reference complete when its bounded runtime, SQLite v24 migration/restart evidence, public data parity, architecture locks and fuzz/release gates are green. Relay and multipath remain separate later phases.
