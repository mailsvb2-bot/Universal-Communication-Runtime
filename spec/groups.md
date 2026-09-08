# Phase 18 Groups

Status: **Prepared reference implementation**, not Production.

Phase 18 adds canonical private/public Group semantics over the existing provider-independent Conversation, Message, authorization, Event/Sync, and durable storage owners. A Group is not a second Conversation or Message model: it binds Group-specific membership, ownership, history, public-policy, crypto-capability and bridge metadata to one existing group-kind `ConversationRef`.

## Canonical aggregate

A Group has one exact `TenantScope`, `GroupId`, and existing `ConversationRef`. The Conversation kind must be `PRIVATE_GROUP` or `PUBLIC_GROUP`. Group state carries ownership, history policy, delivery policy, optional public policy, opaque standardized group-crypto capability state, bridge mappings, replication generation, and an optimistic `revision`.

Group membership is durable security state. Each membership binds one canonical `PrincipalRef` to one Group, one role, lifecycle state, join/remove revisions, and a history floor. Role permissions are derived canonically and are not an independent mutable source of truth. Removed members remain tombstones; a retry or restart cannot silently reactivate them.

## Roles and authorization

Prepared roles are `Owner`, `Admin`, and `Member`. Their permissions are canonical derivations. Group creation, read and management still cross the existing UCR permission boundary; role/membership checks are an additional Group-specific security boundary, not a replacement for tenant-scoped authorization.

Security-sensitive Group changes are applied atomically against the authenticated actor's durable active membership and the caller-supplied expected revision. Stale revisions, unauthorized role transitions, ownership orphaning, scope mismatch and conflicting event reuse fail closed.

## Idempotent changes

Every Group change has a canonical `EventId` and fingerprint. `EventId` is unique across the entire exact `TenantScope`, not merely inside one Group: the same scoped identifier cannot name changes in two different Groups. Replaying the same scoped Group fact with identical semantics is a duplicate; reusing that identity with different semantics is a conflict. Membership/role/ownership transitions and the Group revision are committed in one storage action.

A committed Group change also reserves its scoped `EventId` against ordinary canonical Event append, and an existing canonical Event reserves the same identity against Group mutation. Phase 18 therefore fails closed instead of creating two facts with one ID. A future same-fact projection into the Event journal requires an explicit reconciliation contract; generic Event append is not that contract.

The Prepared change set includes add member, remove member, change role, transfer ownership, set history policy, set public policy, and set delivery policy.

## Messages and history

Group messages remain canonical `MessageEnvelope`s in the existing `MessageStore`. Phase 18 does not create a Group-message database or alternate message identity. A Group message write requires an active membership with `SendMessage`, exact scope and canonical provenance; Service Account provenance remains enforced by Core.

History reads require active membership plus `ReadHistory`. `NoHistory`, `FromJoin`, `LastNMessages`, `FromTimestamp`, `FullHistory`, and opaque `CustomPolicy` are represented explicitly. The Prepared reference implementation does not trust `MessageEnvelope.created_at_unix_ms` as a security clock, so `FromTimestamp` fails closed until a trusted timestamp/order source exists. `LastNMessages` uses the durable logical-order floor when it is unambiguous; if the Nth cutoff is tied on `logical_order`, the reference store advances the floor past the tied order and may expose fewer than N historical messages rather than over-disclose without a durable `(logical_order, MessageId)` boundary. Unsupported custom history behavior also fails closed.

Membership change and message persistence are restart-safe in SQLite schema v21. The Group-message path checks membership and writes the same canonical `messages` tables under one SQLite transaction so membership cannot race an external pre-check.

## Public groups

A public Group has an explicit join policy (`Open`, `ApprovalRequired`, or `InviteOnly`) and discovery policy (`Unlisted` or `Discoverable`), plus an explicit indexing flag. A private Group cannot carry public policy, and a public Group cannot omit it.

Discovery metadata is not identity or membership evidence. Phase 18 does not claim a public directory/search service, moderation service, invite-delivery service, federation discovery, or external-platform bridge runtime.

## Crypto boundary

`GroupCryptoState` is capability metadata and opaque provider state reference, not a second crypto implementation. If a standardized Group crypto capability is configured, membership/role/ownership changes require the next crypto state explicitly. Phase 18 does not implement MLS itself and does not silently claim E2EE from the presence of metadata.

## Durability and migration

Memory is the contract/reference test store. SQLite schema v21 adds normalized `groups`, `group_memberships`, `group_bridge_mappings`, and `group_changes` tables while retaining existing `conversations` and `messages` as their canonical owners. Migration from v20 creates no inferred Groups or memberships.

## Explicit nonclaims

Phase 18 does **not** claim:

- production group directory/search, invitations, approval queues, bans, moderation tooling, or admin UI;
- standardized MLS implementation, key-package service, epoch distribution, or production E2EE deployment;
- external bridge execution, provider federation, or bridge conflict reconciliation;
- attachments/file transfer, edit/delete/reaction workflows, calls, rooms, communities, or broadcast product behavior;
- route orchestration/failover, Relay/NAT traversal, or Transport Orchestrator behavior;
- Reference Messenger Group UI/UX;
- production listener hardening or Production maturity.

Later phases may add those capabilities, but they must reuse the canonical Group, Conversation, Message, Delivery, Identity and authorization owners rather than create parallel sources of truth.
- Group-change duplicate recognition is actor-bound: an identical `EventId`/fingerprint replay is a duplicate only for the exact original `PrincipalRef`; another principal is denied.
- Group membership identity is the complete `PrincipalRef` (`principal_id` plus `PrincipalKind`), including durable tombstones and storage keys.
- When a Group aggregate is attached to an already-existing group-kind Conversation, the creator history floor is derived atomically from the canonical pre-existing Message transcript using the same history-policy logic as later joins.
- A group-kind Message whose Conversation has no Group aggregate is non-disclosing through Group reads and returns absence rather than a corruption/existence oracle.
