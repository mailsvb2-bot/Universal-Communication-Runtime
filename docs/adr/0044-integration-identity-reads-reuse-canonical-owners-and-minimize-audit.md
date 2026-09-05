# ADR-0044: Integration Identity reads reuse canonical owners and minimize audit metadata

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

Phase 13 now lets an external Service Principal create a Root Identity and link an integration-scoped
external entity to it, but the public Integration API has no read side for those same canonical
resources. Core already owns `IdentityStore::identity` and
`ExternalIdentityBindingStore::external_identity_binding` behind independent read permissions.
Leaving those reads internal would force a restart-safe external consumer either to keep a second
Identity mapping or to request direct database access, violating the single-owner public-contract
boundary.

A lookup also has an existence-disclosure risk: returning `NOT_FOUND` before authentication and
authorization would turn the API into an Identity/binding oracle. External namespace/entity bytes
are private provider metadata and should not be copied into the append-only Service Principal audit
chain merely to identify a lookup.

## Decision

`IntegrationService` adds two additive Experimental Phase-13 methods:

- `GetIdentity`, keyed by exact `TenantScope + IdentityId`;
- `ResolveIdentityBinding`, keyed by exact `TenantScope + IntegrationId + external_namespace +
  external_entity_id bytes`.

The transport-neutral `IntegrationIngress` reuses the existing Service Principal admission chain
for both methods:

`credential authentication -> quota consumption/audit -> permission evaluation -> canonical durable read`.

`GetIdentity` requires `ucr.identity.read` and delegates only to
`AuthorizedDurableRuntime::identity` / `IdentityStore`. `ResolveIdentityBinding` requires
`ucr.identity.external_binding.read` and delegates only to
`AuthorizedDurableRuntime::external_identity_binding` / `ExternalIdentityBindingStore`.

A missing record becomes canonical non-retryable `NOT_FOUND` only after the complete admission and
permission boundary succeeds. Authentication or permission failure therefore does not disclose
whether the requested object exists.

Audit attribution for `GetIdentity` uses `ucr.identity.read + IdentityId`. Audit attribution for
`ResolveIdentityBinding` uses `ucr.identity.external_binding.read + IntegrationId`. The exact
external namespace and entity bytes remain authorized request data and are not copied, encoded, or
hashed into the generic admission audit operation reference. This intentionally trades exact-key
audit joinability for data minimization without inventing a second external-identifier scheme.

No storage schema changes are required. The methods read the existing v19 Root Identity owner and
v18 External Identity Binding owner.

## Alternatives rejected

Direct database reads were rejected because they bypass Service Principal authentication,
quota/audit, permissions, canonical validation, and storage abstraction. A consumer-maintained
reverse mapping was rejected as a second identity brain. Returning `NOT_FOUND` before admission was
rejected as an existence oracle. Copying or hashing the external entity ID into generic audit was
rejected because the current Canon does not define a stable audit pseudonymization contract and the
raw identifier is sensitive provider metadata.

## Security and privacy impact

Unauthorized and unauthenticated requests remain non-disclosing. Authorized absence is explicit
`NOT_FOUND`, allowing deterministic consumer recovery without weakening tenant isolation. Quota is
consumed and admission is audited before the durable lookup just like other Phase-13 public
operations.

The binding read audit identifies the Integration but not the external entity. Consumers that need
purpose-specific high-cardinality business audit must implement it in their own business domain;
UCR does not import external entity semantics into its security audit.

## Compatibility

The protobuf change is additive and Experimental. Existing `SubmitCommand`, `CreateIdentity`, and
`LinkIdentity` fields and methods are unchanged. No SQLite migration is introduced.

## Testing strategy

Memory tests prove existing-object non-disclosure before permission, bad-credential non-disclosure,
authorized `NOT_FOUND`, successful canonical reads, and absence of external entity bytes from audit
metadata. SQLite restart evidence proves both public reads resolve through the existing durable
owners after reopen. Architecture tests forbid a parallel read store, direct database dependency,
or external-identifier audit copy.

## Non-claims

This ADR does not define discovery/search, list identities, reverse listing of every external
binding for an Identity, relink/unlink, Persona/Profile resolution, evidence mutation, tenant or
Service Principal provisioning, SDK generation, Event API, or network transport. It does not claim
that generic admission audit can answer which exact external entity key was resolved.
