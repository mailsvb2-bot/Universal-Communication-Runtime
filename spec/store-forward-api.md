# Phase 40 — Public Store-and-Forward API

Status: **Prepared public consumer surface**.

## Purpose

Phase 40 exposes the existing Phase-27 Store-and-Forward owner to ordinary external consumers without moving scheduler, retry, routing or Delivery truth into the SDK or Reference Messenger.

The dependency direction is strictly:

```text
Reference Messenger / external client
        ↓
Public StoreForwardService
        ↓
StoreForwardIngress
        ↓
StoreForwardRuntime / StoreForwardStore
        ↓
canonical Intent + Message + Delivery + Transport owners
```

## Public operations

`StoreForwardService.Enqueue` accepts one already-canonical `StoreForwardJob` and returns only a canonical acknowledgement/error envelope. Equal retries keep the Phase-27 idempotency/tombstone semantics; a conflicting reuse of the same StoreForward ID fails explicitly.

`StoreForwardService.GetStatus` returns a payload-free `StoreForwardStatus`. It exposes only scheduling identity and bounded progress metadata: scope, Intent/Message references, attempt count, next eligibility time, optional last canonical Delivery ID and optional expiry.

The status response MUST NOT return `encrypted_envelope`, worker lease IDs/durations, route candidates, provider state or transport addresses.

## Admission and authorization

Every RPC uses the existing Service Principal authentication/quota/audit gate. `Enqueue` requires `ucr.delivery.store_forward.write`; `GetStatus` requires `ucr.delivery.store_forward.read`. Audit operation IDs are the canonical StoreForward ID.

Unauthorized reads fail before job lookup so callers cannot probe queue existence.

## Runtime ownership

Worker orchestration remains internal. The public service does not expose due-job scans, lease claiming, lease renewal, `process_one`, retry triggering, route discovery, route ranking, failover controls or `TransportProvider` invocation. Those remain runtime-owned.

The SDK performs no hidden application retry. Reference Messenger presents queued work as `AwaitingDeliveryOpportunity`; it does not synthesize successful Delivery/Read evidence from enqueue acknowledgement or StoreForward status.

## Nonclaims

This slice does not add Relay, discovery, NAT traversal, P2P routing, exactly-once delivery, recipient delivery/read evidence, manual retry controls, cancellation controls or production worker orchestration. Local and P2P remain separate Phase-40 proof gaps.
