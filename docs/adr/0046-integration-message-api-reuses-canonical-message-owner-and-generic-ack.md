# ADR-0046: Integration Message API reuses the canonical Message owner and generic acknowledgement

- Status: Accepted
- Date: 2026-09-06
- Supersedes: none

## Problem

Phase 13 already lets a generic external consumer authenticate as a Service Principal, create/link
Identity, and create/read a canonical Conversation. The next Canon step is to send a Message without
exposing raw storage, inventing a provider-specific Message model, or treating persistence as delivery.

A second security issue appears at this boundary. `MessageEnvelope.author`, `on_behalf_of`, and
`origin` are provenance, not permission grants. A Service Principal with Message write authority must
not be able to hide the actual authenticated API source by submitting an unrelated
`origin.principal_id`.

## Decision

`IntegrationService` adds two additive Experimental methods:

- `SendMessage`, carrying the existing canonical `MessageEnvelope` and returning the existing generic
  `AcknowledgementEnvelope`;
- `GetMessage`, keyed by exact `TenantScope + MessageId` and returning the persisted canonical Message.

Both methods reuse the existing `MessageStore` through `AuthorizedDurableRuntime`. No Integration
Message table, receipt model, provider Message owner, or direct database path is introduced.

The public request order remains:

`credential authentication -> quota consumption/audit -> permission evaluation -> canonical durable operation`.

`SendMessage` requires `ucr.message.write`; `GetMessage` requires `ucr.message.read`. Generic audit
attribution binds `ucr.message.send + MessageId` or `ucr.message.read + MessageId` and never copies
Message content into admission audit.

After Message write admission succeeds, `AuthorizedDurableRuntime::persist_message` requires a
Service Account caller's canonical Principal ID to be present as `Message.origin.principal_id` before
the Message can reach storage. This preserves the authenticated API source. It does not rewrite the
Message author or `on_behalf_of`; Actor/delegation provenance remains explicit and separate from
authorization.

The canonical Message owner remains authoritative for semantic validation, exact Conversation
existence/kind, canonicalization, `CREATED`/`PERSISTED` acceptance, durable normalization to
`PERSISTED`, equal retry deduplication, and scoped `MessageId` conflict detection.

## Why the generic acknowledgement

A new Message receipt was rejected because durable Message persistence already has canonical
identity/idempotency semantics. The existing `AcknowledgementEnvelope` is sufficient and already has
the required nonclaim: it acknowledges only the identified protocol object. It is not delivery,
read, provider acceptance, routing success, or real-world effect evidence.

Returning the request Message from `SendMessage` was also rejected. A valid incoming Message may be
`CREATED`, while the durable owner stores it as `PERSISTED`; echoing the request would misrepresent
stored canonical state. `GetMessage` is the read path for the actual persisted record.

## Storage and compatibility

No storage schema changes are required. Memory and SQLite continue to use the existing
`MessageStore`; SQLite remains schema v19. The protobuf additions are additive and Experimental.
Existing Integration methods and fields remain unchanged.

## Security and privacy impact

Unauthenticated or unauthorized reads cannot probe Message existence; authorized absence is
canonical non-retryable `NOT_FOUND`. Message content is not copied into Service Principal admission
audit. A Service Account cannot submit a Message whose `origin.principal_id` hides or contradicts
the authenticated principal.

The origin binding proves only the authenticated API source. This slice does **not** claim that an
arbitrary `author`, `on_behalf_of`, or unsigned Message is cryptographically authentic. Where
verified authorship is required, the existing trusted Device/signing-key Message verification
boundary remains authoritative.

## Testing strategy

Memory evidence covers authenticated send, generic ACK semantics, equal retry, semantic conflict,
permission denial, bad-secret rejection, forged-origin rejection, missing-Conversation rejection,
no ghost state, persisted-state reads, and non-disclosing `NOT_FOUND`. SQLite evidence sends through
the public ingress, reopens the same database, reads the persisted Message, retries send
idempotently, and verifies exact-operation audit records after restart. Architecture gates forbid a
parallel Message owner/direct SQLite path and require the Service Account origin binding after the
existing runtime authorization call.

## Non-claims

This ADR does not implement Delivery creation/progression, routing, transport selection, provider
bridges, Message delivery/read receipts, automatic trusted-author signature verification, Message
listing/search/edit/delete, Attachment transfer, Event subscriptions, production gRPC/HTTP server,
SDK generation, or network transport. Phase 14 still owns Event API semantics.
