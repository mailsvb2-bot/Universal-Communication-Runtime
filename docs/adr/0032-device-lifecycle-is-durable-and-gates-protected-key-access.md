# ADR-0032: Device lifecycle is durable and gates protected key access

Status: Accepted

## Context

The Canon already defines `DeviceLifecycleState` and requires revoked Devices to stop receiving new protected material. Trusted signing keys had their own restart-safe Active/Revoked lifecycle, but no durable owner existed for the canonical Device state itself. Checking only a key row would make key trust a second Device-revocation brain, while inferring Identity from an old key during migration would invent canonical identity evidence.

## Decision

UCR keeps `DeviceLifecycleState` in one exact-`TenantScope` `DeviceLifecycleStore`. Device registration is idempotent only for the identical descriptor and cannot rebind Device ID to another Identity or replace an existing lifecycle state. Device revocation requires the expected Identity, is irreversible through registration, and atomically revokes the current active trusted signing key in the same durable operation.

Only a registered `Active` Device may participate in new trusted signing-key provision, rotation, or resolver-backed authentication. `Stale`, `ReverificationRequired`, `Expired`, `Revoked`, and absence fail closed. Trusted key records do not copy Device lifecycle state. Message-signature verification supplies the canonical author Identity to the resolver and therefore rejects Device-to-Identity rebinding; handshake resolution, whose current input has no Identity field, still requires an Active registered Device.

SQLite schema v15 adds the `devices` table. Migration from v14 preserves existing trusted-key rows but creates no Device rows from them. A migrated trusted key is therefore unusable for new protected access until trusted deployment/recovery code explicitly registers the correct Device/Identity. No guessed Identity, implicit Active state, or compatibility allowlist is introduced.

Device read/register/revoke operations use protocol-owned `ucr.identity.device.*` permissions through `AuthorizedDurableRuntime`. Atomic key invalidation performed inside Device revocation is an internal security consequence, not a second externally callable authorization path.

## Consequences

Revoking a Device now blocks the implemented trusted-key-backed Message and handshake authentication paths across restart and prevents later key provision/rotation for that Device. A correctly signed Message cannot substitute another Identity for the persisted Device owner. Existing databases migrate without losing key history and without manufacturing identity state.

This ADR does not claim a device-bound credential/content-delivery API that does not exist in the current reference runtime, does not complete recovery credential re-issuance or end-user re-verification UX, and does not provide production OS/hardware private-key storage. Those remain explicit production blockers.

## Rejected alternatives

Copy Device state into `trusted_signing_keys`: rejected as a second revocation brain. Infer Device Identity from a v14 key: rejected because key descriptors do not carry canonical Identity evidence. Treat missing Device state as Active for compatibility: rejected as fail-open. Delete migrated trusted keys: rejected because it destroys valid historical trust state. Reactivate a revoked Device through registration: rejected because reconnect/retry must not undo revocation. Add a fictional device credential format solely to close a blocker: rejected because Specification must not claim an unimplemented surface.
