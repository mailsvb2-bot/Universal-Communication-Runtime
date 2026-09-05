# ADR-0043: Root Identity is durable, accountless, and provider-independent

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

The Canon requires `Identity` to outlive replaceable Endpoints, to exist without a phone, email,
password, provider account, or cloud registration, and to remain distinct from Address, Endpoint,
Route, Persona/Profile, and external business identifiers. It also requires a reviewed Root
Identity Model before production 1.0.

The reference runtime previously had canonical `IdentityId` references and Identity evidence
vocabulary, but no durable Root Identity record or owner. Consequently a new
`ExternalIdentityBinding` could persist a target `IdentityId` whose canonical existence was not
independently provable. Treating a provider ID, Device row, external binding, or profile as the
implicit Identity owner would create exactly the parallel/derived identity model forbidden by the
Canon.

## Decision

The minimal Root Identity is one exact-scope `IdentityRecord` containing only:

- `TenantScope`;
- canonical offline-capable `IdentityId`;
- `IdentityOwnership`;
- typed `IdentityEvidence`;
- optional `expires_at_unix_ms` lifecycle metadata.

`IdentityOwnership` uses the Canon vocabulary: `UCR_NATIVE`, `USER_MANAGED`,
`PLATFORM_MANAGED`, `ORGANIZATION_MANAGED`, `FEDERATED`, and `TEMPORARY`.
`IdentityEvidence` remains the existing typed evidence vocabulary rather than a single
`verified=true` bit.

Phone, email, username, provider ID, external business ID, display name, avatar, Endpoint, Device,
Route, and Persona/Profile fields are deliberately absent from the Root Identity record. They may
refer to Identity through their own canonical contracts, but they do not define Identity by
representation alone.

`IdentityStore` is the single durable owner. Its key is exact `(TenantScope, IdentityId)`.
Canonically equal create retries are duplicates. Reusing the same scoped `IdentityId` with changed
ownership, evidence, or expiry metadata is a conflict; this first Root Identity slice does not
silently mutate verification or lifecycle state through create.

SQLite schema v19 adds only the `identities` table. Migration v18→v19 starts that owner empty and
never invents Identity from Device, Recovery, Message, ExternalIdentityBinding, Service Principal,
or provider state. Historical pre-v19 references therefore remain historical references rather
than fabricated Root Identity evidence.

For new `ExternalIdentityBinding` keys, the durable binding owner now requires the target exact
Root Identity to exist. A legacy v18 exact binding remains readable and an identical retry remains
idempotent after v19 migration even when no Root Identity was backfilled; a new external key may
not exploit that compatibility rule to create another dangling reference.

Phase 13 exposes `IntegrationService.CreateIdentity` and `IntegrationService.LinkIdentity` over the
same public protobuf contract. Both authenticate as the existing Service Principal and pass
through the existing quota/audit, permission, and `AuthorizedDurableRuntime` boundaries. No raw
Identity/Binding store or direct database access becomes a public escape hatch.

## Alternatives rejected

Using phone/email/provider/account IDs as Identity was rejected because locators and providers are
replaceable. Deriving Root Identity from Device rows or historical external bindings was rejected
because migration would manufacture ownership/evidence that was never recorded. Embedding profile
or Persona data into Root Identity was rejected because one physical person may intentionally have
separate private, work, anonymous, event, organization, or temporary identities. A provider- or
product-specific Identity store was rejected as a second brain.

A SQL foreign key from every v18 binding row to v19 Identity was also rejected for this migration:
it would make legitimate historical v18 rows impossible to preserve without fabricating a target
Identity. Reference integrity is enforced for every new binding in the canonical store operation
instead.

## Security and privacy impact

The model reduces accidental identity correlation: Root Identity does not require phone, email,
display name, provider account, or external entity ID. Ownership and evidence are explicit
security/governance metadata rather than inference. External entity bytes remain private provider
metadata and are not copied into Service Principal audit operation references; Identity API audit
attribution uses the canonical `IdentityId` only.

`ucr.identity.create` and `ucr.identity.read` are independent permissions. External binding link
continues to require `ucr.identity.external_binding.link`. Service Principal admission still
requires authentication, quota, mandatory audit, and the single-use admission proof before these
permissions can authorize a durable operation.

## Compatibility, migration, and rollback

v18→v19 is additive and transactional. Existing v18 tables and rows are preserved. `identities`
starts empty because older state cannot prove ownership/evidence. An older v18 binary rejects v19
as newer; rollback therefore uses a documented pre-migration database copy or a forward-compatible
binary rather than destructive schema downgrade.

The protobuf additions are additive Experimental Phase-13 methods/messages. Existing
`SubmitCommand` wire fields and the compatibility alias `IntegrationCommandIngress` remain intact.

## Testing strategy

Protocol tests prove accountless Root Identity validation and expiry failure semantics. Memory and
SQLite stores prove exact-scope persistence, duplicate retry, changed-semantics conflict, invalid
expiry rejection, and lookup. SQLite additionally proves concurrent conflicting creates have one
winner, corrupt/missing v19 owner rejection, restart durability, and v18→v19 migration without
inventing Identity while preserving legacy binding compatibility.

Authorization tests prove Root Identity create/read permissions are independent and deny before
storage. Integration API tests compose real Service Principal credential authentication,
quota/audit, permission evaluation, CreateIdentity, restart-safe Identity storage, and
LinkIdentity; denied, unauthenticated, rate-limited, conflicting, or missing-target operations do
not create ghost state.

## Non-claims

This ADR does not define Person↔Identity ownership, Persona/Profile data, discovery, usernames,
verified phone/email, evidence-transition authority, Identity merge, unlink/relink, deletion,
cryptographic erasure, expiry execution, federation trust, or full data-export lifecycle. Optional
expiry is durable metadata only; no background expiry engine is claimed.

The migration also does not retroactively assert that every pre-v19 Device, Recovery Plan,
Message provenance reference, or historical ExternalIdentityBinding has a v19 Root Identity row.
Those older references remain preserved without invented evidence; later reference-integrity
hardening must define its own migration and trust evidence instead of silently guessing.
