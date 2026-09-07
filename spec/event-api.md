# Event API

Status: **Phase 14 local/reference complete; Phase 15 Internet Transport not started**.

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

`EventWebhookDispatcher` is a reference dispatcher over an injected `EventWebhookSink`. It performs one bounded Event attempt and commits ACK/retry/DLQ only after the sink result. Phase 14 deliberately does not implement an HTTP client, DNS resolver, TLS/listener, Internet route, or egress policy. A production network webhook sink belongs to Phase 15+ deployment/transport work and must enforce SSRF/egress/DNS/TLS policy there.

## Persistence

Memory and SQLite implement the same contract. SQLite schema v20 adds subscription configuration, consumer runtime/cursor action state, filters, and dead letters while continuing to read Events from the existing `events` journal. Migration v19 -> v20 is additive: all existing Events/Identity/Message/etc. state is preserved and no subscription, cursor, replay, or dead letter is inferred.

Restart evidence proves active retry state, cursors, dead letters, and replay behavior survive reopen. Corrupt/noncanonical subscription state fails reopen verification. Memory and SQLite both call the same protocol-owned aggregate batch-budget decision, preventing backend-specific truncation or skip semantics.

## gRPC resource budgets

The reference Tonic binding derives a finite request decode budget from the maximum canonical Command, Message, Communication Intent, and Event wire shapes. It also sets a finite response encoding budget that covers the Phase-14 aggregate Event batch ceiling plus protobuf overhead. Loopback regression evidence sends and polls a 5 MiB Event, proving both request and response paths do not silently reintroduce Tonic's 4 MiB default. These are resource/interoperability bounds, not a production listener claim.

## Nonclaims

Phase 14 does not claim exactly-once side effects, HTTP webhook delivery over the public Internet, Internet transport, DNS safety, distributed queues, a globally ordered Event log, or production deployment. Effectively-once consumer behavior is obtained only from canonical Event IDs, durable cursor state, idempotent ACK/reject/replay operations, and consumer-side idempotency. Phase 15 remains unstarted.
