# ADR-0008: Command/Event and idempotency semantics

Status: Accepted

## Context

Retries, restarts, external transports, and provider acknowledgements make it unsafe to equate request acceptance with the requested effect. UCR also requires an effectively-once user experience without claiming universal exactly-once execution.

## Decision

Commands request actions; Events record facts. A `CommandReceipt` records acceptance or deduplication only and is never evidence that the requested effect occurred.

Accepted commands require a bounded non-empty idempotency key scoped by explicit `TenantScope`. The same scoped key plus the same command type/payload is a duplicate. The same scoped key with different semantics is a canonical conflict.
Idempotency key equality is not global: different tenant/namespace scope means a different command domain.

Durable idempotency is not claimed until persistent state survives process restart and storage failures. Phase 5 defines deterministic validation/comparison semantics; Phase 6 must supply persistence evidence.

## Consequences

- Generic ACK cannot be used as proof of delivery or external effect.
- Retried commands can be deduplicated deterministically once durable state exists.
- Idempotency-key misuse produces conflict rather than silent duplicate execution.
- Provider timestamps/acknowledgements do not replace canonical Event semantics.
- Storage, authorization, policy, transport, and Event emission remain separate responsibilities.
