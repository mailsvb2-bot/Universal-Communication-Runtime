# ADR 0081 — Phase 40 StoreForwardService reuses the canonical scheduler owner

## Status

Accepted.

## Context

The Reference Messenger Canon requires executable offline behavior through the public UCR API. Phase 27 already owns durable Store-and-Forward scheduling, idempotency, restart behavior, Delivery-attempt reuse and acceptance ambiguity. Exposing that behavior by importing `ucr-store-forward` into the Reference Messenger or by recreating retry/lease logic in the SDK would create a second communication brain.

## Decision

Add a versioned public `StoreForwardService` with only `Enqueue` and payload-free `GetStatus` operations. The service delegates through `StoreForwardIngress` in the existing `ucr-store-forward` crate.

`StoreForwardIngress` reuses the Core Service Principal request gate and dedicated read/write permissions, then calls the same canonical enqueue validation/storage path used by `StoreForwardRuntime`. No second enqueue implementation is permitted.

Worker-only operations remain private: due enumeration, lease claiming, scheduler iteration, retry execution, route candidate construction and provider invocation are not public RPCs.

The public status projection intentionally omits ciphertext and worker-private fields. An enqueue acknowledgement proves durable acceptance/deduplication only; it is not recipient Delivery or Read evidence.

## Consequences

Reference Messenger can now prove the Canon Offline area through only `ucr-sdk`, while Local, P2P, Recovery and concrete accessibility remain separate gaps. SDKs remain transport clients and do not gain scheduler state machines or hidden retries.
