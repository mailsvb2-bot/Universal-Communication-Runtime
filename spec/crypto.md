# UCR cryptographic foundation

Status: **Experimental / Phase 7**

Cryptography is a protocol capability, not transport decoration. A negotiated transport, capability set, or protocol version is not an authenticated session until the cryptographic handshake completes.

## Crypto Suite UCR v1

`CRYPTO_SUITE_UCR_V1` is the first versioned suite:

- signature: Ed25519, algorithm version 1;
- key agreement: X25519, algorithm version 1;
- derivation: HKDF-SHA-256, algorithm version 1;
- traffic AEAD: XChaCha20-Poly1305, algorithm version 1;
- key format version: 1.

Suite and key-format identifiers are protocol data. Implementations must not infer algorithms from key length or provider/platform name.

Crypto negotiation is explicit and downgrade-protected. Empty or duplicate suite advertisements fail closed. Local policy provides an explicit ordered allowlist of acceptable suites; numeric suite IDs do not encode security strength or preference. An empty allowlist is an intentional deny-all policy. If peers overlap only on suites disabled by local policy, negotiation is `DOWNGRADE_REJECTED`; insecure fallback is forbidden.
## Handshake invariants

Each hello carries exactly one fresh 32-byte nonce plus the advertised crypto suites. All-zero nonces and equal local/remote nonces fail closed before authentication; production nonces come only from the OS CSPRNG.

The legacy `NegotiationResult.transcript_binding` protobuf field (field 4) is deprecated and MUST be empty. Including a binding inside the result being hashed would be circular. The computed binding is carried later by `HandshakeAuthentication` and compared against the locally computed value. Existing field number 4 is retained only for wire/source compatibility during the pre-1.0 transition.

The authenticated transcript binds, in initiator/responder order:

1. exact canonical initiator hello frame bytes;
2. exact canonical responder hello frame bytes;
3. exact canonical negotiation-result frame bytes;
4. initiator X25519 ephemeral public key;
5. responder X25519 ephemeral public key.

The transcript hash is SHA-256 under the `UCR-TRANSCRIPT-V1` domain. Exact frame bytes are bound so unknown fields cannot disappear through decode/re-encode reconstruction.

Each peer authenticates that transcript with its trusted Ed25519 device signing key. X25519 agreement must reject non-contributory/all-zero shared-secret results.

HKDF derives separate initiator→responder and responder→initiator traffic keys plus separate per-role key-confirmation keys. One shared traffic key for both directions is forbidden.
## Key confirmation and session state

A session is `Pending` after peer signature verification, replay recording, contributory key agreement, and key derivation. Traffic APIs are exposed only after the expected peer confirmation tag validates.

Key confirmation uses HMAC-SHA-256 over the transcript binding under direction/role-specific derived confirmation keys and the `UCR-KEY-CONFIRMATION-V1` domain.

`Pending` is not `Established`. Parameter negotiation alone is not `Pending`, and neither state may be represented as secure before its required checks complete.

## Replay protection

Accepted authenticated transcript bindings are recorded durably per trusted peer verifying key. Recording is atomic. Repeating the same `(peer verifying key, transcript binding)` is `REPLAYED` after process restart and under concurrent attempts.

Replay security does not depend on wall-clock expiry. Retention/compaction policy must not be introduced until it preserves the security guarantee and is governed explicitly.

SQLite schema v3 is the reference durable replay store. Migration from v2 preserves existing command/event data and adds replay state transactionally.
## Traffic protection

Traffic uses XChaCha20-Poly1305 with a fresh 24-byte nonce from the OS CSPRNG for every encryption operation. Associated data is mandatory and binds ciphertext to its canonical context/header.

The crypto layer rejects empty AAD, oversized AAD, oversized plaintext, and oversized ciphertext before expensive processing/allocation. Integrity failure returns no partial plaintext.

Random nonce use does not authorize callers to reuse a `TrafficKey` indefinitely. Rekey policy and long-lived session limits remain explicit future work under crypto agility and transport/session policy.

## Key material boundary

Private key bytes are never part of the public UCR protocol or storage schema. `SigningKeyHandle` exposes domain-separated handshake-transcript and canonical Message-binding signing operations without private-key export. Message signatures use `UCR-MESSAGE-SIGNATURE-V1\0` plus the 32-byte canonical authored-Message binding; the Message verifier still requires an already trusted signing-key descriptor. Handshake X25519 uses a single-use in-memory `AgreementKeyPair`; its private scalar is never exported and is consumed by one agreement.

The in-memory key implementations are reference/test implementations. Production device integrations should use OS/hardware-backed key storage where available. Lack of such a backend must not silently cause private keys to be written into the general SQLite store.

Temporary in-memory seed buffers are zeroized. Secret traffic/confirmation/shared-secret buffers are wrapped in zeroizing containers and their `Debug` representations redact secret values.
## Validation and test evidence

Public signing/agreement descriptors are validated against the negotiated suite: purpose, algorithm identifier, algorithm version, key-format version, and exact public-key length must agree.

Reference tests include RFC 7748 X25519, RFC 8032 Ed25519, RFC 5869 HKDF-SHA-256, AEAD tamper/AAD tests, transcript boundary/order tests, canonical Message-signing golden/order tests, Message content/key/device tamper rejection, key confirmation, replay, restart, concurrency, and migration evidence.

## Explicit nonclaims and blockers

Phase 7 crypto plus the Phase-8 Recovery Model now provide an explicit encrypted recovery-package primitive and recovery policy binding. They still do not claim complete credential re-issuance, historical-message key archive design, production OS keystore coverage on every target, formal verification, post-quantum security, or long-lived rekey policy.

A successful Phase-7 session authenticates the trusted device key supplied by the caller. How that device key became trusted, how it is linked/revoked, and recovery consequences remain governed by Identity/Device and Phase-8 recovery contracts.

Crypto algorithms are replaceable only through a new versioned suite/key format and explicit compatibility policy. Compromised algorithms must be disabled by policy; peers must never silently downgrade to keep a connection alive.
