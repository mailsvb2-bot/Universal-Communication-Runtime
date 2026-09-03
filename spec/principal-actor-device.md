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

Revocation is security-significant: a revoked device must not receive new protected content or new credentials. Exact behavior for Stale, Reverification Required, and Expired is policy/recovery work and must not be guessed by transports.
Trusted signing-key lifecycle is deliberately narrower than Device lifecycle. Revoking a trusted signing key prevents that key from authenticating new UCR Message/handshake operations through the trust resolver, but it does not mutate or duplicate the canonical Device state. Conversely, complete Device revocation must eventually revoke/deny all relevant credential and key-delivery paths, not merely one signing key.

## 5. Multi-device invariant

One Identity may own multiple Devices. Device ID is not Identity ID. Per-device delivery, keys, linking, verification, recovery, stale-device policy, and revocation must remain separable.

Endpoint remains distinct from Device: a Device can have one or more Endpoint representations over time, and an Endpoint may represent something other than a Device.
## 6. Service principals

External consumers integrate through a Service Principal rather than hidden product access. A production Service Principal requires identity, authentication, permissions, tenant scope, namespace scope, quotas, and audit trail.

The reference Service Principal authentication lifecycle is defined in `service-principal-authentication.md`; permission semantics remain in `permissions.md`. Authentication resolves an existing canonical Service Account `ScopedPrincipal`, then the same deny-by-default permission boundary applies. Quota/rate-limit and audit persistence remain separate production work. No consumer receives direct database access or an alternate authorization path.
