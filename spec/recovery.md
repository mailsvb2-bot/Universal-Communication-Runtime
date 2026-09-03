# UCR recovery contract

Status: **Experimental / Phase 8**

Recovery is a security-boundary transition, not a password-reset synonym and not an availability shortcut. A recovery workflow MUST state what is recovered, who is authorized to recover it, whether historical protected data can be recovered, which trust guarantees change, and whether device/peer re-verification is required.

Recovery MUST NOT silently make infrastructure able to read history that was previously protected from infrastructure. Recovery MUST NOT infer authority from display name, phone, email, provider account, presence, endpoint address, or route.

## Recovery plan

A `RecoveryPlan` is scoped to exactly one Tenant/Namespace and one Identity. `namespace=None` is not a wildcard.

The plan contains:

- stable `plan_id`;
- exact scope and target Identity;
- a semantic set of typed recovery authorities;
- historical-message access policy;
- explicit post-recovery trust model;
- required recovered-device lifecycle state.

Authorities are canonicalized into deterministic order before storage or cryptographic binding. Ordering in an API request does not change plan meaning. A plan contains at most **64** authorities; larger plans fail before canonical encoding or cryptographic work.
## Typed recovery authorities

Supported authority forms are:

- possession of a recovery code;
- possession of a recovery key;
- one explicitly named trusted Device;
- one explicitly named hardware-backed Device;
- possession of an encrypted-backup recovery capability;
- one explicitly named organization Principal.

A method label alone does not authorize recovery. Trusted-device, hardware-backed, and organization-managed recovery MUST identify the concrete Device or Principal that is authorized.

A request is authorized only when `plan_id`, scope, Identity, and typed authority all match the active plan. Mismatches map to canonical `PERMISSION_DENIED` so callers do not learn whether another plan, tenant resource, or Identity exists.

## Trust transition and re-verification

Phase-8 recovery never auto-promotes a recovered Device to `ACTIVE`. The only accepted recovered-device state is `REVERIFICATION_REQUIRED`.

A plan explicitly selects `USER_CONTROLLED` or `ORGANIZATION_MANAGED`. An organization recovery authority is valid only with the explicit organization-managed trust model; organization control must never be introduced implicitly.
## Historical protected data

Historical access defaults to `NONE`. `EXPLICIT_ENCRYPTED_RECOVERY` is permitted only when the plan includes an authority capable of an encrypted recovery workflow.

The existence of account recovery does not imply access to old message keys. Infrastructure possession of the public recovery plan does not grant decryption capability.

## Encrypted recovery package

The Phase-8 reference package uses a versioned recovery format and a user-controlled recovery secret. The secret is generated with the production OS CSPRNG, redacted from `Debug`, and zeroized when dropped.

The public package contains only algorithm/version metadata, nonce, and ciphertext. Recovery secret bytes are intentionally absent from protobuf and the general SQLite schema.

The canonical recovery-plan binding covers plan ID, exact Tenant/Namespace, Identity, canonical authority set, historical-access policy, trust model, and re-verification state. It is used as the HKDF salt and as AEAD associated data, so derived recovery keys and ciphertext authentication are both plan-specific. A package therefore cannot be transplanted to a different recovery plan without authentication failure.

Wrong secret, modified nonce/ciphertext, unsafe plan, wrong Identity/scope, and unsupported format fail closed. Decrypted recovery material is returned in zeroizing memory.

## Durable plan lifecycle

One scoped Identity has at most one active recovery plan. Install, compare-and-swap rotation, revocation, and lookup are storage capabilities rather than direct database APIs.
Rotation requires the caller's expected current plan ID. Exactly one concurrent replacement may win. A revoked plan cannot become active again through idempotent reinstall; restoration requires a new explicit plan lifecycle decision.

The SQLite reference store persists only public recovery-plan metadata and typed authority identifiers. Schema v4 migrates v3 transactionally by adding recovery plan/authority/active-plan tables while preserving commands, Events, and replay state.

## Verified recovery execution and Device staging

`validate_recovery_request` proves only that a request is structurally covered by the active plan. It is never authority proof by itself. The reference Core therefore resolves the active plan through `RecoveryRequestGate` and then requires a trusted `RecoveryAuthorityVerifier` to prove the concrete selected authority. The verifier is a trusted provider boundary configured by the embedding runtime; untrusted request data must never choose an always-allow verifier.

Only after both checks succeed does Core mint a `RecoveryAdmissionProof`. Its binding fields are private, so callers cannot fabricate a staging capability. `RecoveryDeviceStagingStore` accepts that proof and must atomically re-check that the same plan is still active for the exact scope + Identity while staging the target Device. A plan revoke or rotation that wins first therefore makes an already-issued proof unusable; an identical completed staging retry is idempotent.

The staged Device is always the plan-required `REVERIFICATION_REQUIRED` descriptor. Recovery staging never creates `ACTIVE`, never overwrites a differently bound/existing Device, and does not define how re-verification later succeeds. Any residual Active trusted signing key for a Device being registered/staged as non-Active is revoked in the same durable action; reopening SQLite rejects a non-Active Device row paired with an Active trusted key. This is especially important for v14→v15 databases whose historical trusted-key rows were intentionally preserved without inventing Device identity.

This proof-gated recovery staging path is separate from `AuthorizedDurableRuntime`: recovery authority is defined by the active Recovery Plan, not by an ordinary PermissionGrant. The normal permission boundary still governs Recovery Plan administration itself.

## Backup is not sync

`SYNC != BACKUP`. Sync distributes current state; backup exists for recovery. A future complete backup provider must define encryption, integrity, versioning, restore tests, and documented key ownership before Production maturity.

The Phase-8 encrypted recovery package is a cryptographic building block, not a claim that a complete backup/restore product exists.

## Device theft and recovery

Recovery does not undo compromise. When a device is lost or stolen, the security workflow still requires revocation, stopping new key/content delivery, credential invalidation, key rotation where needed, and audit evidence.

UCR cannot guarantee deletion of plaintext or secrets already extracted from an offline or compromised device.

## Explicit nonclaims

Phase 8 establishes the canonical recovery policy, cryptographic recovery-package primitive, durable plan lifecycle, and proof-gated atomic staging of a verified recovered Device into `REVERIFICATION_REQUIRED`. The current reference runtime additionally enforces durable Device revocation on trusted-key/authentication paths, but it does not yet claim concrete production authority-verifier coverage for every RecoveryMethod, credential re-issuance, device-bound credential/content delivery across recovery, the transition from re-verification to Active, historical message-key archive design, end-user recovery UX, or full backup/restore conformance.

Those capabilities remain separate release blockers and must not be inferred from a valid `RecoveryPlan` or decryptable recovery package.