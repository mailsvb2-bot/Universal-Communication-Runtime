# Principal, Actor, Device, and Provenance Contract

Status: **Experimental / Phase 0**

## 1. Principal vs Actor

A Principal is a subject of authorization. An Actor is a participant represented in communication activity.

Principal kinds are Person, Device, Service Account, AI Agent, Bot, Organization, Automation, and External Platform. Actor kinds are Person, AI Agent, Bot, Organization, and System.

Actor kind is explicit and security-relevant. `on_behalf_of` records delegation/proxy context; it does not rewrite the Actor into the represented Principal. An AI agent or bot must never be serialized as a Person merely because it acts on behalf of one.
## 2. Message origin

`MessageEnvelope.author` identifies the Actor. `MessageEnvelope.origin` describes where the message entered the canonical communication graph.

Origin uses only canonical UCR references: optional Principal ID, Endpoint ID, and Integration ID. Product/provider-specific origin fields are forbidden in Core.

An OriginRef object with no source references is invalid. Whether a specific future message class requires origin is defined by message semantics; absence must never be silently replaced with guessed provider metadata.

## 3. Identity evidence

UCR does not use one boolean `verified=true` as its identity trust model. Evidence is typed as Unverified, Self Asserted, Device Verified, Contact Verified, Organization Verified, or External Provider Verified.

`IDENTITY_EVIDENCE_UNSPECIFIED` is only a protobuf wire default and is invalid as semantic evidence after decoding.
## 4. Device lifecycle

Canonical device lifecycle states are Active, Stale, Reverification Required, Expired, and Revoked.

`DEVICE_LIFECYCLE_STATE_UNSPECIFIED` is a protobuf wire default only and is invalid after semantic decoding.

Revocation is security-significant: a revoked device must not receive new protected content or new credentials. `Reverification Required` has one explicit recovery path back to service: an independent Core-owned re-verification verifier must approve the exact staged Device before the durable owner atomically promotes only that state to Active. Stale and Expired behavior remains separate policy work and must not be guessed by transports.

The reference runtime now has one exact-scope durable `DeviceLifecycleStore` for this canonical state. Registration cannot rebind an existing Device ID to another Identity or replace its lifecycle state. Revocation is irreversible through registration, is idempotent for the same Device/Identity, and atomically revokes the currently active trusted signing key for that Device. New trusted-key provision/rotation and resolver-backed authentication require a registered `Active` Device; all non-Active states fail closed. Ordinary registration cannot perform the re-verification promotion, and a stale re-verification proof cannot reactivate a revoked Device. Message-signature trust additionally requires the persisted Device → Identity binding to match `author_device.identity_id`.

Trusted signing-key lifecycle remains deliberately narrower than Device lifecycle: key rows do not copy Device state. Device lifecycle is the owner consulted by protected-key paths. Device-bound credential/content delivery that does not yet exist in the reference runtime remains separate work rather than an inferred implementation.

## 5. Multi-device invariant

One Identity may own multiple Devices. Device ID is not Identity ID. Per-device delivery, keys, linking, verification, recovery, stale-device policy, and revocation must remain separable.

Endpoint remains distinct from Device: a Device can have one or more Endpoint representations over time, and an Endpoint may represent something other than a Device.
## 6. Service principals

External consumers integrate through a Service Principal rather than hidden product access. A production Service Principal requires identity, authentication, permissions, tenant scope, namespace scope, quotas, and audit trail.

The reference Service Principal authentication lifecycle is defined in `service-principal-authentication.md`; permission semantics remain in `permissions.md`. Authentication resolves an existing canonical Service Account `ScopedPrincipal`, then the same deny-by-default permission boundary applies. The local/reference Service Principal quota and admission-audit boundary is defined in `service-principal-control.md`; no consumer receives direct database access or an alternate authorization path. Distributed/global edge throttling and cryptographically external audit anchoring remain deployment/security work rather than alternate identity semantics.
