# ADR-0042: External Identity Binding is a durable scoped integration primitive

- Status: Accepted
- Date: 2026-09-05

## Context

The canonical model already defines `ExternalIdentityBinding`: an integration-scoped external entity maps to one canonical UCR Identity inside an explicit `TenantScope`. Phase 13 requires third-party consumers to create/link Identity without direct database access. Before this ADR the model and validator existed, but Memory/SQLite had no durable owner, so the link could not survive restart through the authorization-enforced runtime.

The external identifier is opaque locator material. UCR must not infer customer, patient, lead, employee, payer, or other business meaning from it, and it must not normalize provider identifiers into canonical Identity.

## Decision

`ExternalIdentityBindingStore` is the single durable owner for external Identity links. The exact durable key is:

`TenantScope + IntegrationId + external_namespace + external_entity_id bytes`.

The external entity bytes are preserved exactly. No case, Unicode, provider, CRM, or application normalization is performed by Core. The first valid link is `Persisted`; a canonically equal retry is `Duplicate`; reuse of the exact key with a different `IdentityId` is `Conflict`.

No implicit relink or unlink operation is defined. A future lifecycle for replacing or removing a binding requires a separate canonical contract and reviewed ADR; storage `UPDATE` is not an API.

The authorization façade uses independent `ucr.identity.external_binding.link` and `ucr.identity.external_binding.read` permissions. Raw storage remains an internal capability and is not an external Service Principal bypass.

SQLite schema v18 adds only the normalized `external_identity_bindings` owner. Migration from v17 creates an empty binding set and does not infer links from Device, Message, Conversation, Service Principal, provider, or other persisted state.

## Consequences

Memory and SQLite implement identical duplicate/conflict semantics. SQLite uses an exact composite primary key and an immediate transaction, so concurrent attempts to assign the same external key to different Identities have one winner and one conflict rather than last-writer-wins reassignment.

Current-schema reopen validates every persisted binding using the protocol-owned key rules. Missing schema shape or malformed persisted namespace/opaque identifier fails closed as corrupt state.

## Rejected alternatives

A product-specific customer/contact mapping table was rejected because it imports business meaning and creates a second identity brain. Provider-specific normalization was rejected because external IDs are opaque. Silent upsert/relink was rejected because the Canon defines `LinkIdentity` but no replacement lifecycle. Direct integration database access was rejected because it bypasses tenant authorization and canonical validation.

## Non-claims

This ADR does not create canonical Identity records, tenant provisioning, reverse business-object lookup, relink/unlink lifecycle, Event API subscriptions, network transport, routing, or public SDK generation. Phase-13 public Integration API methods may compose this owner, but they must not duplicate it.
