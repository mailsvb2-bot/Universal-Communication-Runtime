# ADR-0040: Integration API reuses canonical Command and Service Principal boundaries

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

Phase 13 requires a language-independent Integration API for external consumers. The runtime
already has canonical Commands, durable acceptance/idempotency, Service Principal credentials,
quota/audit admission, and permission enforcement, but external callers have no public API
surface that composes those owners without exposing Rust internals or raw storage.

Creating a separate Integration command model, direct database API, or provider-specific ingress
would violate the single canonical communication model and create a second authorization brain.

## Decision

The Phase-13 public v1 ingress is `IntegrationService.SubmitCommand` in protobuf. It carries the
existing `CommandEnvelope` and returns either the existing `CommandReceipt` or `ErrorEnvelope`.
Authentication credentials are presented by the concrete API binding, never embedded into the
canonical Command.

The Rust reference boundary is `IntegrationCommandIngress`. It composes the existing
`ServicePrincipalRequestGate` with `AuthorizedDurableRuntime::accept_command`; it does not own
credentials, grants, quotas, audit, command state, or idempotency itself.

The required order is authentication, quota/audit admission, exact permission evaluation, then
durable command acceptance. External adapters receive no raw `CommandAcceptanceStore` access.

## Alternatives rejected

A second Integration-specific Command model was rejected because it would fork canonical command
semantics and idempotency. Direct database access was rejected because it bypasses authorization,
quota, audit, migrations, and durable invariants. Exposing `AuthorizedDurableRuntime` as the public
contract was rejected because the Canon requires a language-independent API rather than Rust ABI.

Embedding Service Principal plaintext credentials inside canonical request messages was rejected
because those messages may be persisted, correlated, retried, or inspected independently of the
binding that authenticates the caller.

## Security and privacy impact

The new boundary reduces bypass surface: an external Service Account command cannot reach durable
acceptance without an unforgeable single-use admission proof. Wrong credentials remain
non-disclosing, quota/audit stays mandatory, and command payloads do not acquire authentication
secrets or a second identity field.

## Compatibility, migration, and rollback

The change is additive: one new protobuf file/service and one Core reference ingress. Existing
wire fields, stores, SQLite schema, and internal runtime methods are unchanged. Rollback removes
the new API surface without data migration because accepted commands use the existing durable
command owner and schema.

The initial API maturity is `Experimental`; promotion to Stable requires a separate reviewed
compatibility decision and cannot reinterpret existing v1 fields.

## Testing strategy

Architecture gates lock the one-owner composition and prohibit product/provider/storage-specific
logic in the ingress. Memory integration tests exercise real credential, quota, audit, permission,
and command-acceptance owners. Existing SQLite command restart/process-kill/storage-full evidence
continues to prove the durable owner used underneath this API. CI compiles every public protobuf
file, including the new Integration service.

## Non-claims

This ADR does not implement Event API, webhook/stream subscriptions, SDKs, HTTP/gRPC server
processes, Internet message transport, routing, command execution effects, or a new durable
per-command audit join field beyond the existing Service Principal admission audit.
