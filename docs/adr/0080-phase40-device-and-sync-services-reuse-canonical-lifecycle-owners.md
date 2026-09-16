# ADR-0080: Phase 40 DeviceService and SyncService reuse canonical lifecycle owners

- Status: Accepted
- Date: 2026-09-16
- Phase: 40 — Reference Messenger

## Problem

The Reference Messenger Canon requires multi-device behavior to be demonstrated through the public UCR boundary. Device lifecycle and durable Sync sessions/checkpoints already exist as canonical Core/storage capabilities, but Phase 40 initially exposed no consumer-facing Device or Sync service.

Allowing the Reference Messenger to import `DeviceLifecycleStore`, `SyncStore`, SQLite or another internal runtime directly would give the reference product privileged authority unavailable to ordinary SDK consumers and would make the public-contract proof false.

## Decision

Add versioned `DeviceService` and `SyncService` services to `ucr.v1`. Their gRPC adapters terminate Service Principal metadata and delegate to `IntegrationIngress`, which reuses `AuthorizedDurableRuntime`, `DeviceLifecycleStore` and `SyncStore`.

The API reuses existing `DeviceDescriptor`, `SyncSession` and `SyncCheckpoint` messages rather than defining UI-specific lifecycle or synchronization records. Device and Sync remain separate services because they are separate canonical owners.

`SyncService` deliberately exposes durable session/checkpoint lifecycle only. It does not move anti-entropy, transport, retry, route selection or reconciliation logic into the public SDK or Reference Messenger.

## Consequences

External consumers can register/read/revoke Devices and create/read/transition Sync sessions plus persist/read opaque checkpoints using the same public Service Principal admission/audit boundary as other UCR services.

The Reference Messenger can now mark `Multi-device` as `PublicApiAvailable` based on executable public operations instead of internal implementation existence. Local, offline, P2P, recovery and concrete accessibility remain separate Phase-40 work.

## Rejected alternatives

### Let Reference Messenger import DeviceLifecycleStore or SyncStore

Rejected because that creates a hidden product-only API and bypasses public authentication, quota and audit.

### Merge Device and Sync into one new product-specific owner

Rejected because canonical Device lifecycle and Sync state already have separate authorities; merging them would create a second communication brain.

### Interpret resume tokens in the SDK

Rejected because resume tokens are canonical opaque source-issued cursors. Interpretation or synthesis outside the Sync owner would fork synchronization semantics.

### Expose anti-entropy and transport policy as part of this slice

Rejected because those are distinct owners and proof areas. This slice closes the multi-device public lifecycle boundary only.
