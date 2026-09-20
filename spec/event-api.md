# Event API

Status: **Phase 14 local/reference complete; Phase 15 exists separately and does not change Event API semantics**.

Phase 14 exposes canonical UCR Events to authenticated external consumers without exposing the database or creating a second Event model. The one canonical append-only Event journal, `EventJournalStore`, remains authoritative for Event facts; `EventSubscriptionStore` owns only durable consumer state layered over that journal.

## Public contract

`proto/ucr/v1/event_api.proto` defines `EventService` with eight operations: `PublishEvent`, `CreateSubscription`, `GetSubscription`, `PollEvents`, `AcknowledgeEvents`, `RejectEvents`, `ReplaySubscription`, and `ListDeadLetters`. Credential ID and secret remain binding metadata and never enter protobuf bodies.

Every external operation passes Service Principal authentication -> durable quota/audit -> explicit permission -> canonical runtime owner. The Event permissions are independent: append, subscribe/read configuration, consume/ack/reject, replay, and dead-letter read. `NOT_FOUND` is disclosed only after successful admission/authorization.

## Durable stream and backpressure

Subscriptions have exact `TenantScope`, opaque `EventSubscriptionId`, bounded canonical filters, `Beginning` or `Latest` start semantics, bounded `max_in_flight`, and bounded `max_attempts`. Empty filters mean all canonical Event types in the exact scope. Filter ordering is non-semantic and canonicalized.

A poll returns at most `min(requested_items, max_in_flight)` Events **and** is bounded by `MAX_EVENT_DELIVERY_BATCH_BYTES`. The aggregate byte budget is protocol-owned and at least large enough for one maximum canonical Event; if adding the next matching Event would cross the ceiling, that Event is left for the next poll rather than skipped. Event delivery weight charges payload, integrity metadata, extensions, identifiers, correlation/idempotency metadata, and a conservative scalar allowance. Once a batch is active, another poll cannot advance past it: the same Events, attempt, and opaque cursor are redelivered until the exact cursor is acknowledged or rejected. This is the Phase-14 backpressure boundary; there is no unbounded per-consumer queue.

Event correlation idempotency keys use the canonical `MAX_IDEMPOTENCY_KEY_LEN` budget; an over-budget Event is rejected before storage. Consumer cursors are opaque bounded SHA-256-derived tokens binding scope, subscription, replay generation, private journal position, and attempt. Raw SQLite `journal_seq` or Memory vector positions never become public ordering or cursor semantics. Stale/opposite cursor actions fail closed; identical ACK/reject retries are idempotent.

## Retry, dead letters, and replay

Retry uses bounded deterministic exponential backoff from 1 second up to 60 seconds. Retry advances the attempt and therefore the cursor; it does not advance the committed journal position. Permanent failure or `max_attempts` exhaustion atomically moves the active Events to durable dead-letter state and advances the consumer position.

Replay is explicit and idempotent through an opaque replay ID. A new replay generation resets the committed consumer position to the beginning, clears active cursor state and dead letters, and makes all old cursors invalid. Replay does not rewrite or duplicate canonical Events.

## Webhook semantics

Webhook subscriptions use the same durable subscription/retry/cursor/DLQ owner as polling. The canonical subscription persists only a bounded HTTPS destination; credentials, bearer tokens, signing secrets, DNS results, and provider-specific state are not persisted in it. Userinfo, query strings, and fragments are rejected from the canonical URI.

`EventWebhookDispatcher` remains the single durable delivery owner over an injected `EventWebhookSink`. It performs one bounded Event attempt and commits ACK/retry/DLQ only after the sink result.

`ucr-webhook::HardenedWebhookSink` now provides the transport-adapter security boundary for production HTTPS delivery without creating a second Event queue or journal. It accepts HTTPS endpoints only; rejects userinfo, query strings and fragments; resolves the destination for each attempt; rejects loopback, private, link-local, multicast, documentation, carrier-grade NAT and other non-public addresses; passes the exact resolved IP set to the executor; disables redirects; emits a deterministic JSON Event envelope; and signs the timestamp, subscription, Event ID and body digest with HMAC-SHA256. Signing secrets remain deployment-owned and are zeroized rather than persisted in the canonical subscription.

`ucr-webhook::NativeTlsWebhookExecutor` now provides the built-in blocking HTTPS executor. It connects only to the prevalidated exact IP set, preserves the original hostname for TLS SNI/HTTP Host and certificate validation, applies bounded connect/read/write timeouts, sends a bounded HTTP/1.1 POST, never follows redirects, and classifies the returned status back into the canonical retry/DLQ path. `SystemWebhookDnsResolver` performs per-attempt resolution before the SSRF policy is applied.

`ucr-runtime dispatch-webhook-once` wires this path to the existing durable SQLite Event subscription owner. Tenant/subscription coordinates are explicit operator inputs, while `UCR_WEBHOOK_SIGNING_KEY_HEX` is process environment only and is never persisted or printed. One invocation performs exactly one bounded dispatch iteration; scheduling/continuous worker orchestration remains deployment-owned. The Phase-15 UCR TCP transport is not reused as an HTTP client.

## Persistence

Memory and SQLite implement the same contract. SQLite schema v20 adds subscription configuration, consumer runtime/cursor action state, filters, and dead letters while continuing to read Events from the existing `events` journal. Migration v19 -> v20 is additive: all existing Events/Identity/Message/etc. state is preserved and no subscription, cursor, replay, or dead letter is inferred.

Restart evidence proves active retry state, cursors, dead letters, and replay behavior survive reopen. Corrupt/noncanonical subscription state fails reopen verification. Memory and SQLite both call the same protocol-owned aggregate batch-budget decision, preventing backend-specific truncation or skip semantics.

## gRPC resource budgets

The reference Tonic binding derives a finite request decode budget from the maximum canonical Command, Message, Communication Intent, and Event wire shapes. It also sets a finite response encoding budget that covers the Phase-14 aggregate Event batch ceiling plus protobuf overhead. Loopback regression evidence sends and polls a 5 MiB Event, proving both request and response paths do not silently reintroduce Tonic's 4 MiB default. These are resource/interoperability bounds, not a production listener claim.

## Nonclaims

Phase 14 does not claim exactly-once side effects, an always-running webhook scheduler, distributed queues, a globally ordered Event log, or automatic deployment. The shipped one-shot runtime path provides real HTTPS delivery with DNS/TLS/SSRF/signature policy and canonical retry/DLQ state; continuous dispatch cadence remains an operator/deployment concern. Effectively-once consumer behavior is obtained only from canonical Event IDs, durable cursor state, idempotent ACK/reject/replay operations, and consumer-side idempotency. Phase 15 is implemented separately as a Prepared UCR TCP transport; Event webhook networking remains unimplemented.
