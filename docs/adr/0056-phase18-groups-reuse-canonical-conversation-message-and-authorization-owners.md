# ADR 0056: Phase 18 Groups reuse canonical Conversation, Message, and authorization owners

- Status: Accepted
- Scope: Phase 18 Prepared/reference Groups

## Context

UCR already owns provider-independent Conversation, Message, Identity, Delivery, Event/Sync, tenant-scoped authorization, and durable Memory/SQLite state. Adding Groups creates security-sensitive membership, role, ownership, history and public-policy state, but must not create a second communication brain.

A tempting design is to make a self-contained Group subsystem with its own conversation rows, group-message rows, membership pre-checks, crypto claims, or provider-specific identities. That would violate the Canon laws that Conversation outlives Provider and that there is one canonical communication model. It would also make membership races possible if authorization were checked outside the same durable action that writes a Group message.

## Decision

Phase 18 introduces one Group aggregate for Group-specific state only. `GroupRecord.conversation` references the existing canonical group-kind `ConversationRef`; Group creation atomically establishes the existing Conversation plus Group and creator membership, but does not redefine Conversation identity.

Messages in Groups are ordinary canonical `MessageEnvelope`s. `GroupMessageStore` is an atomic membership-gated access boundary over the same `MessageStore` data. Memory writes the same message map, and SQLite writes the existing `messages`/children tables. There is no `GroupMessage` model, second message database, or alternate delivery state machine.

Group management remains behind existing explicit tenant-scoped UCR permissions. Durable membership/role checks are additional authorization facts evaluated inside the Group storage action. Membership changes use optimistic Group revision plus a canonical Event-ID fingerprint so exact retries deduplicate and changed semantics conflict. The Event ID namespace is exact-scope-wide: Group changes cannot reuse an ID across Groups, and Group/Event writes mutually reject ordinary reuse so two canonical facts cannot silently acquire one identity. Future same-fact Event projection requires an explicit reconciliation path rather than a second Event owner.

Removed members are durable tombstones. SQLite schema v21 stores normalized Group, membership, bridge-mapping and change-fingerprint state while deriving role permissions from the canonical protocol mapping rather than persisting a second permission truth.

Group crypto state remains an opaque capability/state reference owned by the standardized crypto provider. Phase 18 does not implement or claim MLS merely by storing `GroupCryptoState`.

## Security consequences

- Exact `TenantScope` remains mandatory.
- Group existence/membership must not become an authorization oracle through generic Message or Group reads.
- Generic Message paths cannot be used to bypass Group membership checks.
- Service Account Message provenance remains Core-owned and applies to Group writes too.
- Add/remove/role/ownership changes and their idempotency record are atomic.
- `EventId` remains one exact-scope fact namespace across Group changes and the canonical Event journal.
- A removed member cannot regain authority merely because the process restarts or a mutation is retried.
- Public discovery metadata is not identity, authorization, or membership evidence.
- Unsupported custom history/crypto behavior fails closed.
- `FromTimestamp` never trusts caller-supplied message display time as authorization evidence; the Prepared store fails closed until trusted time/order evidence exists.
- `LastNMessages` never over-discloses across a tied logical-order cutoff; without a durable MessageId tie boundary it advances past the ambiguous order and may return fewer historical messages.

## Durability consequences

SQLite v21 references existing Conversation rows and reuses existing Message rows. Migration from v20 creates no inferred Groups or memberships. Reopen verification checks table shape, foreign keys, normalized child rows, and canonical Group/membership semantics.

## Nonclaims

This ADR does not claim production directory/search, invitation/approval delivery, bans/moderation UI, MLS implementation, provider federation/bridge execution, attachment workflows, calls, Group UI, Transport Orchestrator behavior, or production listener deployment.

## Rejected alternatives

1. **Separate Group conversation/message store.** Rejected as a second communication brain.
2. **Check membership in Core and then call generic MessageStore.** Rejected because membership could race removal between check and persistence.
3. **Treat transport/provider group IDs as canonical Group identity.** Rejected because provider bindings are mappings, not canonical identity.
4. **Delete membership rows on removal.** Rejected because tombstones are required for restart-safe authority history and stale-retry safety.
5. **Persist an independent permission list as mutable truth.** Rejected because role permissions are canonical derivations and must not drift.
