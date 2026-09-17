# Phase 40 Recovery API

## Purpose

`RecoveryService` makes the existing canonical Recovery Plan and proof-gated Device recovery workflow reachable by an ordinary external UCR consumer through the versioned public contract.

It does not create a second Recovery, Identity, Device, trust, credential, or key owner.

## Public operations

The service exposes bounded operations for:

- install, rotate, revoke, and read the active canonical Recovery Plan;
- stage one recovered Device after active-plan and recovery-authority verification;
- activate one exact staged Device after a second independent re-verification decision.

Plan administration uses the existing recovery-plan permissions and canonical durable owner.
## Security boundary

Service Principal authentication, quota, audit, and `ucr.recovery.stage` / `ucr.recovery.activate` permissions gate the public application channel only.

An ordinary `PermissionGrant` is not recovery authority. Staging still requires the active Recovery Plan plus an independent `RecoveryAuthorityVerifier` decision. A successful staging operation can create only the plan-declared `REVERIFICATION_REQUIRED` Device state.

Activation is a separate security decision. `DeviceReverificationVerifier` must verify the exact staged Device/Identity before the existing atomic lifecycle owner may promote it to `ACTIVE`.

Missing plans, authority mismatch, wrong Identity, stale Device state, denied proof, and verifier unavailability fail closed. Recovery secrets and provider evidence do not enter the public protobuf model.

## Ownership and nonclaims

The public adapter delegates to existing Core gates and durable owners. It does not issue new Service Principal credentials, restore protected content, transport recovery secrets, mint trusted signing keys, or bypass Device lifecycle checks.

Concrete recovery-code/key storage, trusted-device challenge UX, hardware-backed attestation, encrypted-backup retrieval, organization approval, credential re-issuance, and protected-content restoration remain deployment/provider responsibilities.

The Reference Messenger may call this service through `ucr-sdk`; it must not link to `ucr-core` or storage directly.
