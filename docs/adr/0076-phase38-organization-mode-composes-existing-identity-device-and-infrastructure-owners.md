# ADR-0076: Phase 38 Organization Mode composes existing Identity, Device and infrastructure owners

Status: Accepted

## Context

The Canon allows an Organization to have private namespace, private discovery, private relay, private SFU, private bridge, managed identities and managed devices, and requires self-hosting without a fork of UCR Protocol.

UCR already has canonical Tenant/Namespace scope, Organization principals, OrganizationNode endpoints, Root Identity, Device lifecycle, Store-and-Forward, SFU and Bridge owners. Creating organization-specific copies of those state machines would violate the one-communication-model rule.

## Decision

Phase 38 introduces one durable `OrganizationModeProfile` keyed by exact tenant/namespace plus Organization principal. A namespace is mandatory, the principal kind must be `Organization`, and the endpoint kind must be `OrganizationNode`.
The profile stores only enabled organization services, Active/Disabled lifecycle and optimistic generation. Separate organization-managed Identity/Device bindings are association evidence only; they do not duplicate canonical records or grant authority by themselves.

Private discovery projects only explicitly bound canonical `IdentityRecord` values and revalidates `OrganizationManaged` ownership. Managed Device admission revalidates live canonical Device lifecycle and requires its Identity to be managed by the same Organization.

Private Relay admission reuses an existing Store-and-Forward job plus canonical Message delivery policy. Private SFU is policy admission over the existing encrypted SFU boundary. Private Bridge admission reuses an existing Active `BridgeRegistration`.

Organization-specific permissions are additive. Existing Identity, Device and Bridge read authorities remain required where those canonical records are inspected.

SQLite v31 persists only profile and association policy state. v30→v31 migration creates empty Organization Mode state and infers no ownership from existing records.
## Rejected alternatives

- Organization-specific Identity or Device stores: rejected as duplicate canonical authority.
- Organization-specific Message/Delivery/relay queues: rejected as a second communication brain.
- Organization-owned SFU roster/media key state: rejected because Group/Call/MLS/SFU already own those semantics.
- Bridge execution embedded in Organization Mode: rejected because Bridge runtime/adapters remain the provider boundary.
- Inferring organization ownership from tenant membership, endpoint possession or existing Devices: rejected because scope and possession are not authority.
- Forking UCR Protocol for self-hosted deployments: rejected by the Canon self-hosting test.

## Consequences and nonclaims

Positive: an organization can now express and restart-safely persist its private namespace policy and managed associations while using the same canonical UCR protocol/runtime owners as managed deployment.

Negative: production discovery infrastructure, Relay/SFU hosting, enterprise backup/compliance operations, HA/SLA and deployment automation still require separate implementation and evidence.

This phase remains **Prepared** and does not claim Production maturity.
