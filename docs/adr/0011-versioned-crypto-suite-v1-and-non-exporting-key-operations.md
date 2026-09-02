# ADR-0011: Versioned crypto suite v1 and non-exporting key operations

- Status: Accepted
- Date: 2026-09-02

## Problem

UCR needs an authenticated, replay-resistant, downgrade-resistant cryptographic foundation without making one device keystore, transport, or Rust library part of the protocol identity.

A loose list of algorithms would create ambiguity around key formats, transcript binding, rekey, compatibility, and compromised-algorithm response. Exporting private bytes through Core APIs would also prevent safe TPM/Keychain/Keystore implementations.

## Decision

Define `CRYPTO_SUITE_UCR_V1` as one versioned protocol suite using Ed25519 signatures, X25519 agreement, HKDF-SHA-256 derivation, and XChaCha20-Poly1305 traffic protection.

Algorithm version and key-format version are explicit. Suite negotiation is mandatory and policy-gated; insecure fallback is forbidden.
## Handshake decision

The exact canonical hello/result frame bytes and ordered ephemeral X25519 public keys are hashed into a domain-separated transcript binding. Each peer signs that binding with a trusted Ed25519 device signing key.

Non-contributory X25519 shared secrets are rejected. HKDF derives separate traffic keys for each direction and separate role-specific confirmation keys. A session is not established until peer key confirmation succeeds.

Durable replay state is keyed by peer verifying key plus transcript binding. Replay detection survives restart and concurrent attempts; it does not use wall-clock expiry.

## Key material decision

Private-key export is not part of the UCR runtime boundary. `SigningKeyHandle` exposes long-lived signing operations only, enabling future OS/hardware-backed implementations. Handshake X25519 keys are single-use ephemeral in-memory keys whose private scalar is never exported.

The in-memory reference implementation zeroizes temporary seeds and secret buffers. General SQLite storage is not an allowed silent fallback for private keys.
## Rationale

Ed25519/X25519 provide compact widely implemented Curve25519-family primitives. HKDF-SHA-256 gives explicit extract/expand separation. XChaCha20-Poly1305 provides a large nonce space suitable for fresh random nonces without making a persistent nonce counter a hidden prerequisite of the foundation layer.

Direction-specific traffic keys reduce cross-direction misuse. Mandatory AAD binds encrypted payload to canonical context. Domain separation is explicit for transcript hashing, signatures, KDF labels, and confirmation tags.

## Alternatives considered

- one symmetric key for both directions: rejected because it weakens separation and increases misuse impact;
- implicit algorithms inferred from key size: rejected because it blocks crypto agility;
- private-key byte export from a generic key store: rejected because it prevents non-exportable hardware/OS keys;
- SQLite plaintext key storage as a universal fallback: rejected because key material requires a separate security boundary;
- availability-first downgrade to an older suite: rejected by Canon.
## Risks and tradeoffs

Suite v1 is not post-quantum. XChaCha20-Poly1305 is deliberately selected for nonce-misuse risk reduction in this layer, but future compliance profiles may require another suite. OS/hardware-backed key support varies by platform and remains an implementation matrix, not a protocol assumption.

Durable replay records require retention policy and storage capacity. Compaction cannot be added without preserving replay guarantees.

## Compatibility and migration

Existing Phase-0 negotiation gains an additive `supported_crypto_suites` field and selected `crypto_suite`; existing protobuf field numbers are preserved. SQLite schema v2 migrates transactionally to v3 by adding replay state while preserving accepted commands/events.

Future algorithm changes require a new suite/key-format version. A compromised suite is removed from the explicit allowed-suite policy; peers must fail rather than downgrade silently.

## Rollback

Code rollback across SQLite v3 requires documented schema compatibility. An older binary that does not understand v3 must reject the newer database rather than mutate or downgrade it. Crypto-suite rollback is prohibited when the explicit local allowlist disallows the old suite.

## Testing

Required evidence includes RFC vectors, transcript mutation/order tests, signature failure, non-contributory X25519 rejection, AEAD tamper/AAD/budget tests, key confirmation, durable replay restart/concurrency, migration tests, strict clippy/rustdoc, debug/release suites, and dependency vulnerability audit.

## Crypto policy ordering

Numeric suite identifiers are identifiers only and never encode security strength. Local security policy owns the explicit ordered allowlist of acceptable suites. The allowlist may be empty to disable all crypto suites fail-closed. Compromised or forbidden suites are removed from that policy; no implementation may select a suite by numeric max/min ordering.
