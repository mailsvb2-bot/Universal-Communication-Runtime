# ADR-0052: Phase 14 Event API reuses the append-only Event journal with durable consumer state

Status: Accepted

Date: 2026-09-06

## Context

The Canon requires Phase 14 Event API to support webhook, durable stream, consumer cursor, retry, replay, backpressure, idempotency, and dead-letter handling. Phase 12 already owns canonical Events and an append-only Event journal. Creating a second outbound Event log or provider queue would create a second brain and make replay/dedup semantics diverge.

Phase 13 also established the external Service Principal admission chain and concrete gRPC credential binding. Event consumers must reuse those authentication/quota/audit/permission boundaries instead of receiving direct database access.

## Decision

Add `EventSubscriptionStore` as durable consumer state layered over `EventJournalStore`. It owns subscription configuration, committed private journal position, replay generation, one active batch, idempotent cursor action state, retry scheduling, and dead letters. It does not own Event facts.

A subscription has bounded canonical filters and explicit `Beginning`/`Latest` start behavior. Public cursors are opaque hashes bound to scope/subscription/generation/private position/attempt. One active batch is the backpressure boundary: polling cannot advance until the batch is acknowledged or rejected. Retry uses bounded exponential backoff; permanent failure or max attempts atomically dead-letters the active Events. Explicit replay increments generation, resets consumer progress, and invalidates old cursors without mutating Events.

Webhook uses exactly the same consumer state machine. `EventWebhookDispatcher` calls an injected `EventWebhookSink`; only the sink classification (`success`, `retryable`, `permanent`) feeds durable ACK/retry/DLQ transitions. The canonical subscription stores a bounded HTTPS destination but no authentication secret.

Expose a separate protobuf/gRPC `EventService` rather than adding Event methods to `IntegrationService`. The Tonic adapter terminates binary credential metadata and delegates every operation to `EventApiIngress`. The shared decode budget includes the maximum canonical Event wire shape, including the 16 MiB Event payload and integrity metadata.

SQLite schema v20 adds only consumer state and normalized filters/dead letters. v19 -> v20 preserves all existing canonical state and creates no inferred subscriptions.

## Security and failure semantics

`ucr.event.append`, `ucr.event.subscribe`, `ucr.event.consume`, `ucr.event.replay`, and `ucr.event.dead_letter.read` remain distinct authorities. Service Principal calls consume quota and append audit before the authorized operation. Subscription absence is not disclosed before authorization.

Cursor bytes are not authorization credentials and raw store positions are never exported. Stale/opposite cursor actions fail closed. Repeating the same completed action is idempotent. Replay is explicit, scoped, generation-bound, and cannot resurrect or alter Event facts.

A webhook URI is configuration, not trusted network identity. Phase 14 has no production HTTP/DNS/TLS implementation; a future network sink must own egress/SSRF/DNS/TLS protections rather than smuggling them into Event persistence.

## Evidence

Protocol tests lock filter canonicalization, webhook URI constraints, bounded retry, and cursor attempt binding. Memory tests lock filtering, Beginning/Latest, bounded in-flight redelivery, ACK/reject idempotency, retry, DLQ, and replay. SQLite tests lock v19 migration plus restart-safe retry/cursor/DLQ/replay. gRPC loopback tests lock publish/dedup, create/poll/backpressure/ACK, DLQ/replay, permission non-disclosure, and payloads above Tonic's 4 MiB default. Cross-crate chaos evidence now includes a real slow-consumer scenario; webhook dispatcher evidence proves retry scheduling and max-attempt dead-lettering through the same store.

The consumer boundary is bounded in two dimensions: item count and aggregate semantic bytes. The byte decision is protocol-owned and shared by Memory/SQLite; the next Event is deferred rather than skipped when it would cross the batch ceiling. Event correlation idempotency keys are bounded before storage, and the reference gRPC adapter uses explicit finite request/response message budgets rather than Tonic defaults.

## Consequences

External applications can consume canonical Events without direct DB access and without introducing a second Event owner. Slow consumers are bounded by explicit in-flight state instead of unbounded queue growth. Restart and replay have explicit durable semantics.

This completes Phase 14 at the local/reference API layer. It does not implement Phase 15 Internet Transport, a production HTTP webhook sink, DNS/TLS/egress policy, or production deployment. Phase 15 is not started.
