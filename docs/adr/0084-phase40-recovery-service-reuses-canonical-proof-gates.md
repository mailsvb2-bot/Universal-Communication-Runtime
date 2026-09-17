# ADR 0084: Phase-40 RecoveryService reuses canonical proof gates

## Status

Accepted.

## Context

Phase 40 requires the Reference Messenger to prove Recovery through the same public UCR boundary as every other external consumer. The repository already has one canonical Recovery Plan owner, `RecoveryRequestGate`, `RecoveryAuthorityVerifier`, `DeviceReverificationGate`, and atomic Device staging/activation stores.

Exposing those owners must not turn an ordinary Service Principal permission into recovery authority or create a second recovery workflow in gRPC, SDK, or Reference Messenger code.

## Decision

Add a versioned public `RecoveryService` for Recovery Plan administration plus recovered-Device staging and activation.

Service Principal authentication, quota, audit, and dedicated stage/activate permissions are application-channel admission only. They do not prove possession or control of a recovery authority.
Staging delegates to the existing `RecoveryAuthorityVerifier` and `RecoveryDeviceStagingStore`. The durable Device is created only in the plan-declared re-verification-required state.

Activation delegates to the existing independent `DeviceReverificationVerifier` and atomic `ReverifiedDeviceActivationStore`. It cannot reactivate a stale, rebound, already-active, or revoked Device through a stale proof.

No second Recovery Plan store, recovery-authority model, Device lifecycle, credential owner, protected-content owner, or key owner is permitted in the public adapter.

## Consequences

A third-party consumer can administer a Recovery Plan and drive the canonical recovery workflow through the public SDK without direct Core/storage access.

Compromise of a Service Principal with `ucr.recovery.stage` or `ucr.recovery.activate` is insufficient by itself to recover or trust a Device: the independent verifier decision remains mandatory.

Concrete authority-proof transport and post-recovery credential/content delivery remain deployment concerns and are intentionally not simulated by the SDK.

This closes the Phase-40 Recovery public-API gap. It does not close the separate concrete accessibility evidence requirement.
