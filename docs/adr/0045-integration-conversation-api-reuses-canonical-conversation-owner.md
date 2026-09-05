# ADR-0045: Integration Conversation API reuses the canonical Conversation owner

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

The Canon requires a generic third-party application to create/link Identity and then create a
Conversation before sending a Message. Phase 13 already exposes Identity operations, but an external
consumer still cannot create or read the provider-independent Conversation through the public
Integration API. Asking the consumer to keep a parallel conversation mapping or use direct database
access would create a second communication brain and bypass the existing security boundary.

Conversation reads also carry an existence-disclosure risk. Returning `NOT_FOUND` before Service
Principal authentication and authorization would allow probing scoped Conversation identifiers.

## Decision

`IntegrationService` adds two additive Experimental Phase-13 methods:

- `CreateConversation`, carrying the canonical `ConversationRecord`;
- `GetConversation`, keyed by exact `TenantScope + ConversationId`.

Both methods reuse the existing `ConversationStore` through `AuthorizedDurableRuntime`; no
Integration-specific Conversation model, table, cache, or mapping owner is introduced.

The transport-neutral `IntegrationIngress` keeps the existing admission order:

`credential authentication -> quota consumption/audit -> permission evaluation -> canonical durable operation`.

`CreateConversation` requires `ucr.conversation.write`. `GetConversation` requires
`ucr.conversation.read`. Generic audit attribution uses `ucr.conversation.create + ConversationId`
or `ucr.conversation.read + ConversationId` without copying provider/business metadata.

The existing Conversation owner remains authoritative for validation, hierarchy, idempotent equal
retries, and conflict semantics. A missing Conversation becomes canonical non-retryable `NOT_FOUND`
only after successful admission and read authorization.

## Alternatives rejected

Direct database access was rejected because it bypasses Service Principal authentication, quota,
audit, permissions, canonical validation, and storage abstraction. A consumer-maintained canonical
Conversation mirror was rejected as a second communication brain. A new Integration Conversation
receipt/state machine was rejected because durable `ConversationRecord` persistence already owns the
semantics required by this slice.

## Storage and compatibility

No storage schema changes are required. The methods reuse the existing Memory and SQLite
`ConversationStore`; SQLite remains schema v19. The protobuf changes are additive and Experimental.
Existing Integration RPC fields and methods remain unchanged.

## Security and privacy impact

Unauthorized and unauthenticated reads do not reveal whether a Conversation exists. Admission audit
is operation-bound to the canonical Conversation ID. Provider IDs, business relationship labels,
message content, membership, and transport routing are not introduced into the public Conversation
operation or its generic audit metadata.

## Testing strategy

Memory evidence covers authenticated create, exact retry deduplication, semantic conflict,
permission denial, bad-secret rejection without ghost state, authorized reads, and authorized
`NOT_FOUND`. SQLite evidence creates through the public ingress, reopens the database, reads through
the same public ingress, retries create idempotently, and verifies operation-bound audit records.
Architecture gates forbid a parallel Conversation store or direct SQLite dependency in the ingress.

## Non-claims

This ADR does not implement Message send/read APIs, Event subscriptions, group membership or
moderation, Conversation discovery/listing, delete/merge, provider overlays, production gRPC/HTTP
servers, SDK generation, or network transport. Message API is the next separate Phase-13 slice;
Phase 14 still owns Event API semantics.
