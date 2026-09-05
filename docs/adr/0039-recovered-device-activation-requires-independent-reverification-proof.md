# ADR-0039: Recovered Device activation requires independent re-verification proof

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

Recovery already stages an authority-verified Device only as `REVERIFICATION_REQUIRED`, and protected key access accepts only `ACTIVE`. The reference runtime had no canonical transition between those states, so a safely recovered Device could never return to protected service without bypassing lifecycle ownership.

Ordinary `register_device(... ACTIVE)` cannot be that transition: registration deliberately rejects replacement of an existing Device's Identity or state. Recovery authority also cannot silently imply re-verification, because the Canon requires recovery and post-recovery trust establishment to remain distinct security decisions.

## Existing state

`RecoveryAdmissionProof` is Core-owned and non-forgeable. Memory and SQLite atomically re-check the active Recovery Plan while staging `REVERIFICATION_REQUIRED`. Device revocation is durable and irreversible, and non-Active Devices cannot retain an Active trusted signing key.
## Decision

Core owns a separate `DeviceReverificationVerifier` boundary. It validates deployment-specific re-verification evidence for one exact durable Device that is still `REVERIFICATION_REQUIRED`. Successful verification mints a private-field `DeviceReverificationProof`; callers cannot fabricate activation authority.

`ReverifiedDeviceActivationStore` is the only durable promotion path. It atomically compares exact Tenant/Namespace, Device ID, Identity ID, and current state before changing only `REVERIFICATION_REQUIRED -> ACTIVE`. Any other state is a conflict. A stale proof therefore cannot resurrect a revoked Device.

Re-verification authority is deliberately not represented as a `PermissionGrant`. Ordinary administration may manage Device registration/revocation, but it cannot self-authorize this recovery trust transition.

No SQLite schema migration is required: schema v15 already represents both lifecycle states and v16 adds no competing Device owner.

## Rationale

Recovery authority answers whether recovery may stage a replacement Device. Re-verification answers whether that staged Device has subsequently re-established enough trust to participate in protected access. Keeping those proofs independent prevents possession of one recovery factor from becoming automatic long-term Device trust.
## Security impact

The transition is deny-by-default, exact-scope, Identity-bound, and fail-closed on verifier/storage unavailability. Concurrent activation and revocation serialize through the durable owner. If revocation wins first, activation conflicts; if activation wins first, the subsequent revocation still irreversibly produces `REVOKED` and invalidates active signing-key trust.

## Compatibility and migration

This adds Core/reference-runtime APIs without changing protobuf or SQLite schema. Existing staged Devices remain `REVERIFICATION_REQUIRED` until a trusted re-verification provider explicitly approves them.

## Non-claims

This does not supply production challenge/attestation/organization-approval providers, credential re-issuance, content/key delivery, backup restore conformance, or end-user recovery UX. Those remain separate parts of the end-to-end recovery blocker.

## Testing strategy

Memory evidence covers denied re-verification, successful activation, protected-key admission after activation, and stale-proof rejection after revocation. SQLite evidence covers restart-safe activation and a concurrent reverify/revoke race that can never leave a revoked Device resurrected.