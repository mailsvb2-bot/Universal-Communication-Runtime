# ADR-0012: Recovery is an explicit trust transition

- Status: Accepted
- Phase: 8 — Recovery Model

## Context

Account recovery is often implemented as a generic password reset. That model is unsafe for UCR because Identity may be accountless, Devices have independent keys, historical E2EE access may differ from account access, and organization-managed recovery changes who can authorize trust.

The Canon requires recovery to define what is recovered, who authorizes it, what historical data remains available, what guarantees change, and whether re-verification is required. It also distinguishes backup from sync and forbids silent E2EE degradation.

## Decision

UCR models recovery through one canonical `RecoveryPlan` scoped to one Tenant/Namespace and Identity.

Recovery authority is typed. Possession-based recovery code/key/backup authorities are distinct from specifically named trusted/hardware Devices and specifically named organization Principals.

A method name alone is never authority.
Recovered Devices enter `REVERIFICATION_REQUIRED`; recovery cannot auto-promote them to `ACTIVE`.

The plan explicitly declares user-controlled or organization-managed trust. Organization authority is invalid unless organization-managed trust is also explicit.

Historical protected data defaults to unavailable. Historical-key recovery is only permitted through an explicit encrypted recovery design; public plan metadata never grants decryption.

Recovery packages are versioned ciphertext bound with canonical AEAD associated data to the entire recovery-plan security context. Secrets remain outside protobuf and the general SQLite store.

Recovery plan persistence is capability-specific. One Identity has at most one active plan; rotation is compare-and-swap; revocation is durable and idempotent.

## Consequences

Recovery works for accountless and multi-device identities without inventing a password/account as a second identity model.

A stolen provider account, email address, display name, endpoint, or route cannot become recovery authority by implication.

Recovery UX must surface re-verification and trust-model changes rather than presenting recovery as transparent restoration.
A decryptable recovery package proves possession of the package secret for that bound plan; it does not prove that a recovered Device is already trusted or that old messages must exist.

SQLite schema v4 stores only plan metadata and authority identifiers. Recovery key/code bytes are intentionally absent.

## Rejected alternatives

- Treating email/phone/provider login as universal recovery authority — rejected because canonical Identity is independent of those addresses/providers.
- Automatically marking a recovered Device Active — rejected because it silently bypasses re-verification.
- Giving infrastructure implicit historical-message access during recovery — rejected as silent E2EE degradation.
- Storing raw recovery secrets in the general local database — rejected because recovery secrets are `SECRET`/`KEY_MATERIAL` and require a separate security boundary.
- Treating Sync as Backup — rejected by the Canon and because sync propagation cannot substitute for versioned restore evidence.

## Follow-up

Credential re-issuance, delivery/key revocation enforcement, historical-message key archive policy, platform-specific secure recovery providers, full backup/restore conformance, and recovery UX remain separate implementation/release work.