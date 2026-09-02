# ADR-0007: Deny-by-default explicit permission grants

Status: Accepted

## Context

UCR must authorize people, service accounts, bots, AI agents, automations, organizations, devices, and external-platform principals without creating product-specific role systems or a second identity model.

Tenant/namespace scope is already fail-closed. The permissions layer needs a controlled way to widen authority without interpreting tenant-root scope as an implicit wildcard.

## Decision

Authorization is deny-by-default. Authority exists only through explicit `PermissionGrant` records using namespaced permission identifiers.

A grant is either exact-scope or explicitly tenant-wide. Tenant-wide grants require a tenant-root scoped principal for the same tenant. Namespace-bound principals cannot receive tenant-wide grants.
Service accounts use `PrincipalKind::ServiceAccount` and `ScopedPrincipal`; no parallel service identity type is introduced. Authentication credentials are deliberately not encoded in permission grants.

Malformed persisted grant state fails closed as an internal authorization error. It is not silently ignored.

## Consequences

- Missing grants cannot turn into allow through defaults.
- Adding a namespace does not expand a principal's authority unless an explicit tenant-wide grant already exists.
- Service accounts, people, AI agents, bots, and other principals share one permission mechanism.
- Future authentication/credential implementations can change without changing authorization identity semantics.
- Product-specific roles may map to UCR permission grants at integration boundaries, but do not become canonical UCR roles.
