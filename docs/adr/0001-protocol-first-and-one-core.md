# ADR-0001: Protocol-first boundary and one canonical communication core

- Status: Accepted
- Date: 2026-09-01
- Supersedes: none

## Problem

UCR must serve many applications, platforms, devices and transports without allowing any one consumer/provider implementation to become the canonical communication model.

## Existing state

The repository was empty. There was no legacy implementation to preserve or migrate.

## Options considered

1. Start from a Rust application model and later expose it as an API.
2. Start from a specific messenger/provider integration and generalize later.
3. Define a language-independent protocol boundary first, then implement a Rust reference runtime against it.

## Decision

Choose option 3. There is one canonical UCR communication model. Protocol specification and public schemas are separate from Rust implementation structures. Product/provider-specific communication cores are prohibited.

## Rationale

This preserves product independence, language independence, future transport extensibility and the ability for multiple external consumers to use exactly the same public contract.

## Advantages

- Avoids a second communication brain.
- Avoids Rust ABI as the public contract.
- Avoids privileged consumer APIs.
- Allows future transports/providers without redefining core entities.

## Disadvantages

- More up-front specification work.
- Implementation cannot use convenient product-specific shortcuts.

## Risks

An underspecified protocol could still allow divergent implementations. Conformance tests are therefore required as the project matures.

## Security impact

Positive: security policy and tenant boundaries are defined above transports/providers rather than delegated to each adapter.

## Privacy impact

Positive: provider-specific metadata is prevented from becoming canonical identity by default.

## Compatibility impact

Protocol versioning starts immediately; consumers cannot rely on Rust ABI/private database structures.

## Migration strategy

No migration is required because the repository has no prior implementation.

## Rollback strategy

Reverting this decision would violate the Canon and requires a new ADR/RFC explicitly superseding it.

## Testing strategy

Architecture tests scan canonical source/proto directories for forbidden product/provider coupling and verify protocol version-negotiation invariants.
