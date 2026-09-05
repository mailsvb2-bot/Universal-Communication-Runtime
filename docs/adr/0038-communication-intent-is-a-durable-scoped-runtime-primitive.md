# ADR-0038: Communication Intent is a durable scoped runtime primitive

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

The Canon says that Communication Intent outlives Transport and must survive route, provider, server, and network unavailability. The public protobuf and canonical Rust model already represent complete Intent semantics, but the durable runtime has no `CommunicationIntentStore`. An Intent can therefore be validated and passed to policy code yet disappear before any route exists.

ADR-0020 explicitly left Intent persistence out because lifecycle/idempotency required a separate storage contract and evidence set. Leaving that debt open after local storage, durable Message, Delivery, Sync, and Anti-Entropy are already implemented violates the architecture invariant that Intent is independent of Transport.

## Existing state

`CommunicationIntent` has scoped identity, target Identity, payload, policy constraints, correlation, and extensions. `canonical_communication_intent` already normalizes transport capability and extension ordering and rejects contradictory/duplicate constraints.

Memory and SQLite persist other canonical runtime entities through capability-specific Core traits. `AuthorizedDurableRuntime` is the permission-enforcing façade for implemented tenant-scoped durable methods. SQLite schema v15 is the current pre-change durable layout and owns Device lifecycle.

## Options considered

1. Keep Intent transient until Internet Transport exists.
2. Persist Intent inside Message or Delivery tables.
3. Add a separate canonical `CommunicationIntentStore` with Memory/SQLite parity, exact-scope authorization, and a transactional SQLite v16 migration.
## Decision

Adopt option 3.

Core owns one `CommunicationIntentStore`. Its durable key is `(TenantScope, IntentId)`. Persisting a canonically equivalent retry returns `Duplicate`; reusing the same scoped `IntentId` with changed canonical semantics returns `Conflict`. `CorrelationContext.idempotency_key` remains persisted semantic data but is not promoted into a second global deduplication identity without a separate lifecycle/API decision.

Memory stores the canonical Intent directly. SQLite schema v16 adds normalized `communication_intents`, `communication_intent_transports`, and `communication_intent_extensions` tables. Migration v15→v16 creates no inferred Intent rows.

The protocol bounds persisted Intent policy strings to 1024 bytes each and the optional Intent idempotency key to 256 bytes, in addition to the existing payload, transport-count, and extension budgets. SQLite reopen verifies every stored Intent through the same canonical validator and rejects malformed/noncanonical persisted state.

`AuthorizedDurableRuntime` adds independent `ucr.intent.read` and `ucr.intent.write` permissions. Raw store traits remain local/bootstrap capabilities, not external authorization APIs.

## Rationale

Intent is neither Message nor Delivery. Folding it into either would make later route selection or delivery evidence a second owner of why communication should exist. A capability-specific store preserves the Canon flow `Communication Intent → Policy → Delivery → Events` and allows Intent to exist before any route is available.

Scoped `IntentId` matches the durable identity pattern used by provider-independent Message state and avoids inventing undocumented semantics for the optional correlation idempotency key.

## Advantages

- closes the explicit architecture gap without implementing future Transport/Relay/Bridge/SDK layers;
- survives SQLite restart independently from route availability;
- preserves full public Intent semantics including unknown privacy-profile strings and extensions;
- keeps duplicate/conflict behavior deterministic across Memory and SQLite;
- keeps read/write authorization deny-by-default and exact-scope;
- makes v15 history truthful through a separate v16 migration.
## Disadvantages

- SQLite gains three tables and one schema migration.
- Authorization vocabulary gains two permissions.
- Persisted private policy data increases local-at-rest sensitivity; production at-rest encryption policy remains a separate blocker.

## Risks

A corrupt database could attempt to inject malformed policy, capability, extension, or oversized values. Reopen verification therefore reconstructs each Intent and applies canonical validation; count and payload/policy budgets fail closed. Concurrent reuse of one scoped `IntentId` must serialize through an immediate SQLite transaction so only one semantic value can win.

## Security impact

Positive. Intent read/write now passes through the same explicit deny-by-default runtime boundary as other tenant-scoped durable operations. Exact scope remains part of every SQLite key. SQLite stores `u64` maximum cost as an exact eight-byte value rather than narrowing it through SQLite's signed integer range.

This ADR does not claim remote-peer authentication, transport authorization, at-rest encryption, hardware-backed keys, or delivery authenticity.

## Privacy impact

Intent payload, privacy profile, region constraint, idempotency key, and extension payloads are durable private data. Ordinary Rust `Debug` remains redacted. Storage does not expose those fields as a public database API and no provider/route metadata is added.

## Compatibility impact

Public protobuf fields do not change. The Rust model does not change shape. Existing SQLite v15 databases migrate transactionally to v16 with empty Intent tables. Older binaries must reject schema v16 as newer rather than downgrade it.

## Migration strategy

Verify exact v15 shape, create the three v16 Intent tables in one immediate transaction, set `user_version=16`, commit, then verify the full v16 schema. No Intent is inferred from Message, Delivery, Event, or external provider state.
## Rollback strategy

Before deployment with persisted v16 data, roll back the application and restore the pre-migration database backup. Do not relabel a v16 database as v15 or discard Intent tables in place, because that would silently lose durable communication intent.

## Testing strategy

- protocol budget tests for private policy and Intent idempotency values;
- Memory canonical persist/duplicate/conflict parity;
- SQLite all-field restart round trip including `u64::MAX`/`u32::MAX`;
- canonical reorder deduplication and same-ID semantic conflict;
- exact-scope isolation;
- v15→v16 migration with no invented Intent rows;
- malformed persisted capability/policy/extension rejection on reopen;
- authorized runtime deny-before-store/read and independent read/write permissions;
- architecture locks for single ownership, schema migration, evidence names, permission coverage, and future-layer nonclaims;
- full workspace fmt/check/clippy/test/release validation.