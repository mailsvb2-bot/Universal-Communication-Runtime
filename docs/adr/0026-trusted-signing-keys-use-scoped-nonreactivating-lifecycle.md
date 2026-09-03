# ADR-0026: Trusted signing keys use scoped non-reactivating lifecycle

Status: Accepted

## Context

Canonical Message signatures and authenticated handshakes can verify Ed25519 proofs only after a caller supplies a trusted device signing key. Treating a peer-supplied `PublicKeyDescriptor` or Message `key_id` as its own trust proof would let an attacker self-provision. Conversely, copying Device lifecycle into a key table would create a second revocation brain.

The trust owner therefore needs durable exact-scope key lifecycle while preserving the existing separation between Identity, Device, cryptographic verification, authorization, and private-key providers.

## Decision

Trusted public signing-key state is keyed by exact `TenantScope` plus `key_id` and bound to one Device. Only valid UCR-v1 `Signing` descriptors may enter trust state. Key lifecycle is `Active` or `Revoked`; this state describes trust in the key, not the canonical Device lifecycle.

Provisioning is idempotent only for the identical active descriptor. A second active key for the same exact scope/device conflicts. Rotation is one atomic expected-current compare-and-swap: the expected key becomes Revoked and one same-device replacement becomes Active. Retrying that exact completed rotation is idempotent. Revoked key IDs are never reactivated. Revocation is idempotent for the same already-revoked expected key and conflicts with a different active key.

`TrustedSigningKeyResolver` exposes only an independently resolved Active descriptor for an exact `(scope, device_id, key_id)` tuple. Absence, revocation, or ordinary mismatch returns the non-disclosing `NotTrusted` result. Peer-supplied descriptors remain claims and must exactly equal the resolved Active descriptor before handshake authentication proceeds. Message verification resolves trust before cryptographic verification.

SQLite schema v11 is the restart-safe reference owner. It stores normalized public signing descriptors and key trust state, with a partial unique index enforcing at most one Active key per exact scope/device. Migration from v10 is additive and starts with no trusted keys because pre-v11 UCR had no durable trust state to backfill.

## Consequences

A trusted key survives restart, rotation/revocation are conflict-safe, and stale/revoked keys cannot authenticate new Messages or handshakes through the integrated resolver path. Same key identifiers in different tenant/namespace scopes do not share trust.

This ADR does not define who is authorized to provision/rotate/revoke trust, does not provide an OS/hardware private-key backend, and does not duplicate or close Device lifecycle revocation enforcement. Those remain separate production blockers. Private signing-key bytes never enter this store.

## Evidence

Memory tests exercise lifecycle/idempotency/scoping plus real Message and handshake integration. SQLite tests prove restart, v10-to-v11 migration preserving existing replay state, concurrent rotation single-winner behavior, irreversible revocation, resolver behavior, and fail-closed detection of corrupt rows or the missing active-key uniqueness index.

## Rejected alternatives

Trust the descriptor carried by a peer or Message: rejected because identifiers and public keys are claims, not trust decisions. Store key trust globally by `key_id`: rejected because trust is tenant/namespace scoped. Copy `DeviceLifecycleState` into key records: rejected because Device lifecycle already has a canonical owner. Delete revoked rows: rejected because it permits accidental re-provisioning and erases security history. Allow multiple Active signing keys per Device without a separate rotation model: rejected because current suite-v1 lifecycle would become ambiguous.
