# ADR-0006: Exact tenant/namespace scope by default

Status: Accepted

## Context

UCR is multi-tenant from the first version and treats `Tenant` as a security boundary. `Namespace` is an optional explicit subdivision. If an absent namespace were interpreted as a wildcard, a caller scoped only to a tenant could accidentally gain access to every namespace created later.

The Canon also requires that tenant scope not be inferred from transport/provider metadata and that authorization remain explicit.

## Decision

The default scope precondition is exact equality of `tenant_id` and optional `namespace_id`. Missing namespace means no namespace selected, never wildcard authority.
Broader tenant-wide or cross-namespace authority is introduced only as an explicit permission grant in the authorization layer.

Cross-tenant and cross-namespace mismatches map to the same public `PERMISSION_DENIED` category. This avoids leaking resource existence through different error classes.

`ScopedPrincipal` binds a Principal to an explicit `TenantScope`; it does not imply any permission beyond that scope binding.

## Consequences

- New namespaces cannot expand an existing principal's authority by accident.
- Provider/account/network metadata cannot select a tenant implicitly.
- Authorization code has a conservative exact-scope primitive on which broader grants can be built.
- Cross-scope resource probing does not receive a distinct not-found signal.
