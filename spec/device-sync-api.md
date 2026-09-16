# Phase 40 — Public Device and Sync Services

## Status

Prepared public consumer API for the existing canonical Device lifecycle and Sync owners.
It closes the Reference Messenger `Multi-device` public-API gap without creating a second Device, Identity, Sync, anti-entropy, routing, retry, transport, or storage model.

## Boundary

The allowed execution path is:

```text
Reference Messenger / external SDK consumer
                 ↓
       DeviceService / SyncService
                 ↓
        IntegrationIngress
                 ↓
 Service Principal admission + audit
                 ↓
AuthorizedDurableRuntime / DeviceLifecycleStore / SyncStore
```

Both services are thin authenticated bindings. Existing `DeviceDescriptor`, `SyncSession` and `SyncCheckpoint` protobuf records remain the wire model and map directly to the existing canonical `ucr_model` owners.

## Device lifecycle operations

`DeviceService` exposes:

- `RegisterDevice` — persists one canonical Device descriptor with existing lifecycle/idempotency rules;
- `GetDevice` — reads one exact-scope Device descriptor;
- `RevokeDevice` — performs existing irreversible Device revocation and associated protected-key invalidation through the canonical durable owner.

The service preserves `ucr.identity.device.register`, `ucr.identity.device.read` and `ucr.identity.device.revoke` permissions. The caller cannot rebind an existing Device ID to another Identity or bypass irreversible revocation semantics.

## Sync operations

`SyncService` exposes:

- `CreateSyncSession` — creates/deduplicates one canonical Prepared session;
- `GetSyncSession` — reads one exact-scope session;
- `TransitionSync` — performs existing expected-state compare-and-swap lifecycle transition;
- `RecordSyncCheckpoint` — records one monotonic opaque resume checkpoint;
- `GetLatestSyncCheckpoint` — returns the latest durable checkpoint for the session.

The service preserves `ucr.sync.write` and `ucr.sync.read`. Partial conversation selections retain canonical set-like sorting and duplicate rejection. Resume tokens remain opaque source-issued cursors: SDK and Reference Messenger code must not parse, compare, merge, or synthesize them.

## Authentication, quota and audit

Every RPC uses the same binary Service Principal credential metadata as the rest of the public UCR API. One external RPC performs one normal credential/quota/permission admission and writes the corresponding Device/Sync audit operation outcome before entering the durable owner.

No direct database handle, internal store reference or long-lived authorization proof is exposed to consumers.

## Semantics preserved

- exact tenant/namespace scope remains authoritative;
- Device lifecycle remains separate from Identity and key ownership;
- Device revocation remains irreversible and canonical-store-owned;
- Sync session creation remains Prepared-only;
- illegal state skips, rewinds and terminal reopen attempts remain rejected;
- checkpoint generation and applied-item progress remain monotonic;
- resume tokens remain opaque;
- acknowledgement means durable acceptance/deduplication only;
- no automatic retry, anti-entropy, route selection or transport state is added to the SDK.

## Nonclaims

This service closes only the Phase-40 `Multi-device` public-API gap. It does not itself prove local/direct transport, offline Store-and-Forward, P2P/mesh transport, Recovery or concrete platform accessibility.
