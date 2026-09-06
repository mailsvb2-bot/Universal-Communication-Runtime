# ADR-0048: Public namespaced identifiers have an explicit byte budget

Status: Accepted
Date: 2026-09-06

## Context

The protocol uses one shared `validate_namespaced_identifier` owner for extension names, Command and
Event types, Capability identifiers, Communication Intent transport-capability constraints, Endpoint
address schemes, external Identity namespaces, permissions, and Service Principal audit operation
kinds. The validator enforced namespace syntax but previously had no common length ceiling.

That made otherwise syntactically valid attacker-controlled identifiers unbounded. It also made a
concrete API binding unable to choose a finite request-size budget without silently rejecting some
inputs that Core would otherwise call valid. Per-field adapter limits would create competing protocol
rules and a second validation brain.

## Decision

The protocol-owned `validate_namespaced_identifier` enforces a maximum encoded length of 1024 bytes,
exported as `MAX_NAMESPACED_IDENTIFIER_LEN`. The existing namespace vocabulary and allowed ASCII
identifier characters are unchanged. Exactly 1024 bytes is valid when the namespace syntax is valid;
1025 bytes is rejected before storage, hashing, routing, or provider use.

More sensitive capabilities may keep narrower limits in their existing owners. In particular,
Service Principal permissions and audit operation kinds retain their 256-byte limits. The shared
1024-byte ceiling is therefore a maximum public vocabulary budget, not a widening of narrower fields.

The common validator remains the single owner. gRPC, HTTP, SDK, storage, provider, and application
layers must not introduce alternate namespaced-identifier validity rules.

## Consequences

- Public namespaced strings are bounded before allocation-heavy or durable downstream work.
- Command/Event types, extension names, capabilities, transport constraints, address schemes and
  external namespaces receive the same maximum ceiling automatically.
- Existing normal identifiers are unaffected; the limit is intentionally much larger than current
  built-in vocabulary.
- Concrete API message-size budgets can be derived from finite canonical maxima rather than guessed.
- This changes validation only; it adds no storage owner, permission, schema, routing or provider logic.

## Required evidence

Protocol tests must prove an exactly-1024-byte valid identifier succeeds and a 1025-byte identifier
fails. Architecture tests must lock the exported constant, shared-validator enforcement and protocol
documentation, and must prevent the gRPC adapter from becoming an alternate identifier-length owner.

## Non-claims

This ADR does not define business display-name limits, opaque ID length, payload limits, URL limits,
provider identifier semantics, Unicode normalization, routing policy, or transport framing. It does
not make every field 1024 bytes: existing narrower field-specific budgets remain authoritative.
