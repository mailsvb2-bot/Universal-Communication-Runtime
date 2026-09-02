# Delivery State and Evidence Contract

Status: Experimental / Phase 10 foundation.

## 1. Fundamental rule

Delivery is a separate UCR subsystem. A canonical Message outlives any route,
transport, relay, provider, or individual delivery attempt.

A `DeliveryAttempt` is one immutable delivery identity for one scoped Message.
Retry and multi-path delivery create a new `DeliveryId`; they never rewind or
reuse a terminal attempt.

`MessageId` remains the user-visible deduplication identity. `DeliveryId` is
operational/audit identity and must not become a second Message identity.

## 2. State machine

The positive path is:

`PERSISTED -> ENCRYPTED -> QUEUED -> ROUTE_PLANNED -> IN_FLIGHT -> ACKNOWLEDGED -> DELIVERED -> READ`

Any non-terminal attempt may transition to `FAILED` or `EXPIRED`. `READ`,
`FAILED`, and `EXPIRED` are terminal for that attempt.Skipping states, rewinding, or reopening a terminal attempt is invalid.

The Message row is not a second mutable delivery state machine. Per-attempt
state plus append-only evidence is authoritative. A later message-level status
must be a deterministic projection over canonical attempts/evidence.

## 3. Evidence model

Canonical evidence kinds are:

- `CREATED_LOCAL`
- `PERSISTED_LOCAL`
- `ACCEPTED_BY_TRANSPORT`
- `REPLICATED_TO_RELAY`
- `RECEIVED_BY_DEVICE`
- `DECRYPTED_BY_DEVICE`
- `PRESENTED_TO_USER`
- `READ_BY_USER`

Evidence is bound to exact Tenant/Namespace, `DeliveryId`, and `MessageId` and
has a monotonically increasing logical order per attempt.

The first persisted evidence for an attempt is `PERSISTED_LOCAL`.

`ACKNOWLEDGED` requires `ACCEPTED_BY_TRANSPORT` evidence. It means only that
the selected transport accepted the attempt; it is not user/device delivery.

`DELIVERED` requires `RECEIVED_BY_DEVICE`, `DECRYPTED_BY_DEVICE`, or
`PRESENTED_TO_USER` evidence. `REPLICATED_TO_RELAY` never proves `DELIVERED`.

`READ` requires `READ_BY_USER` evidence. Provider or relay acknowledgements
cannot be promoted to read state.

## 4. Durable transition boundary

`DeliveryStore` is a capability-specific Core interface. Core does not depend
on SQLite or any transport provider.

Creation of an attempt and its initial `PERSISTED_LOCAL` evidence is atomic.
A proof-bearing state transition and the evidence that justifies it are stored
in one transaction. Crash between evidence and state update therefore cannot
leave a committed half-transition.

Evidence append is idempotent for the same logical order and identical
semantics. Reusing a logical order with different evidence is `CONFLICT`.
Evidence logical order may not regress; stale regression is a conflict.

SQLite schema v6 adds normalized `delivery_attempts` and append-only
`delivery_evidence` tables. Migration from v5 is additive and preserves
Conversation/Message and every earlier durable capability.

## 5. Retry, multi-path, and effectively-once semantics

Failure of one attempt does not rewrite or delete the Message. A retry creates
a new `DeliveryId` for the same canonical `MessageId`.

This foundation does not claim network exactly-once delivery. Effectively-once
user experience must be built from stable Message IDs, durable state,
idempotency, deduplication, and later receive-side reconciliation.

Multiple routes may carry the same Message in later phases; provider/transport
specific delivery state machines are forbidden.

## 6. Security and privacy nonclaims

Phase 10 defines evidence semantics and durable state. It does not yet provide real transport adapters. Route selection, retry scheduling, backoff, receive-side deduplication, Sync/Anti-Entropy, and remote signed delivery receipts remain separate work.

Relay compromise must not be able to upgrade `REPLICATED_TO_RELAY` into
`DELIVERED` or `READ` merely by returning an acknowledgement.

Evidence in this foundation is local canonical runtime evidence. Cryptographic
remote receipt authentication, trust evaluation, and anti-replay integration
for receipt messages remain explicit later security work.

## 7. Required evidence

Reference implementations must prove:

- restart-safe DeliveryAttempt and evidence persistence;
- relay evidence cannot inflate user delivery state;
- proof-required transitions fail closed without matching evidence;
- concurrent stale transitions have exactly one winner;
- evidence logical order is monotonic and conflicting reuse fails;
- corrupt evidence binding is rejected on reopen;
- v5-to-v6 migration preserves existing Message state.

Public protobuf mirrors the same provider-independent attempt/evidence model.
No Telegram, VK, MAX, product, route, relay, or transport identifier is allowed
to become the owner of canonical Delivery state.