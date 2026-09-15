# ADR-0075: Phase 37 Personal Node composes existing communication owners

Status: Accepted

## Context

The Canon defines a Personal Node as a user-controlled UCR node deployable on PC, NAS, mini-PC or home server, with sync, encrypted mailbox, relay, cache and bridge functions. UCR already has canonical Endpoint, Sync, Store-and-Forward, Delivery, Message and Bridge owners.

Creating Personal-Node-specific Message, Sync, Relay, Bridge, routing or identity state machines would duplicate those owners and violate the one-communication-model rule.

Phase 36 also established `EndpointKind::PersonalNode` as an existing canonical endpoint kind and explicit federation trust as a separate policy boundary.

## Decision

Phase 37 introduces a durable `PersonalNodeProfile` keyed by exact `TenantScope + EndpointId`. The profile requires `EndpointKind::PersonalNode`, an explicit service set, Active/Disabled lifecycle, optimistic generation and bounded mailbox/cache capacities.

`Sync` is admitted only by reference to an existing Active canonical `SyncSession` with `DeviceNode` binding to the Personal Node endpoint. Phase 37 does not own Sync state.

`Relay` is admitted only by reference to an existing canonical Store-and-Forward job and its canonical Message delivery policy. Phase 37 creates no forwarding queue, Delivery state machine, route graph or transport acceptance state.

`Bridge` is admitted only by reference to an existing Active canonical `BridgeRegistration`. Provider side effects remain outside Personal Node ownership.

The only new payload-bearing storage is an opaque encrypted mailbox/cache sidecar. It has no canonical Message semantics and stores only encryption-scheme identifier, ciphertext, SHA-256 digest, timestamps and object identity. Capacity is enforced atomically.

Every operation remains exact-scope permission gated. Disabled nodes deny new Personal Node admissions without mutating canonical owner state.

SQLite v30 adds explicit profile/object tables. v29→v30 migration creates empty tables and infers no node ownership or service state from existing data.

## Rejected alternatives

- New Personal Node Message/Conversation store: rejected as a second communication brain.
- New node-specific Sync state machine: rejected because canonical Sync already owns session/checkpoint state.
- New relay scheduler/Delivery state: rejected because Store-and-Forward + Delivery already own those semantics.
- Node-owned provider bridge execution: rejected because Bridge runtime/adapters remain the provider boundary.
- Inferring a Personal Node from any Federation peer or Device: rejected because possession/reachability is not authority.
- Treating Sync as Backup: rejected by the Canon; backup/recovery is a separate future capability.

## Consequences and nonclaims

Positive: PC/NAS/mini-PC/home-server deployments now have one explicit, restart-safe owner-controlled node profile and encrypted mailbox/cache storage while reusing the canonical communication owners.

Negative: Phase 37 still needs deployment-specific process/service management, discovery, NAT traversal, backup/restore, migration orchestration and production operations before it can be called Production.

This phase remains **Prepared**. It does not claim automatic discovery, federated Relay, managed backup, Organization Mode, HA/SLA or Production maturity.
