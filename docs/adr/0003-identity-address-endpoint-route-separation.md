# ADR-0003: Separate Identity, Address, Endpoint, and Route

Status: Accepted

## Problem

Provider/account locators are easy to mistake for identity. If a transport address becomes canonical identity, provider replacement, offline identity, multi-device operation, and future transports require changing the model of the user.

## Existing state

The Canon requires Identity to outlive Endpoint and explicitly separates Identity, Address, Endpoint, and Route. Phase-0 code previously exposed route address as raw bytes without an explicit Endpoint reference.

## Decision

Canonical Identity IDs remain opaque and independent of address material. EndpointAddress is `(namespaced scheme, opaque bytes)`. EndpointDescriptor owns addresses/capabilities. RouteCandidate references an Endpoint ID plus one EndpointAddress and remains transient runtime state.
## External bindings

ExternalIdentityBinding is tenant/integration scoped. External namespace/entity IDs are opaque mapping material and do not import business-domain meaning into Core.

## Alternatives rejected

- Provider/account ID as Identity: violates longevity and provider independence.
- Raw address bytes without scheme: loses interpretation boundary and encourages implicit routing assumptions.
- Persisted Route as source of truth: makes temporary network state canonical.
- Product-specific endpoint types in Core: creates a second communication model.

## Security impact

Namespaced schemes/capabilities are validated. Collection/value limits are enforced before route planning. Device endpoints require explicit Device and Identity binding. Invalid combinations fail closed.
## Privacy impact

Generic Debug output redacts EndpointAddress values and external entity identifiers. Schemes and opaque-value lengths remain visible for diagnostics. Plain locator values require an explicitly authorized diagnostic path.

## Compatibility impact

The protobuf contract gains new messages/enums without reusing existing field numbers. Existing EndpointRef remains a lightweight reference; EndpointDescriptor carries full endpoint metadata.

## Migration and rollback

There is no persisted production data yet. Runtime users must replace raw route address bytes with Endpoint ID plus EndpointAddress. Rollback is source-only at this phase; no database migration is required.

## Testing strategy

Unit tests cover invalid schemes, bounds, duplicate declarations, Device binding invariants, external-binding validation, and redaction. Architecture gates assert the separation across model/core/protobuf. Public protobuf compilation remains a required CI check.
