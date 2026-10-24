# RUSTSEC-2026-0387 migration status — draft PR #310

## Dependency resolution (2026-10-24)

PR #310 pins the complete OpenMLS RustCrypto family to upstream revision
`be248d4b1306d87a641ce24ed0ffcab2b27967f6`, updates its dependent
HPKE/curve family, and tests a local DTLS 0.17.2 migration candidate. The
vendored DTLS source was imported from a SHA-256-verified upstream crate and
adapted for p256/p384 0.14, sec1 0.8, and a compatible cryptographic RNG.

**Cargo-generated lockfiles at commit `3663ba78` (and later `a3f8e459`):**
- Root `Cargo.lock`: `crypto-bigint 0.7.6` only.
- `crates/ucr-chaos-lab/Cargo.lock`: `crypto-bigint 0.7.6` only.
- `fuzz/Cargo.lock`, `crates/ucr-sdk/Cargo.lock`,
  `crates/ucr-reference-messenger/Cargo.lock`, and
  `crates/ucr-ai-actor/Cargo.lock`: no `crypto-bigint` package.

The chaos lab is an **excluded, independent Cargo root**: the main workspace
`[patch.crates-io]` does not propagate to it. Its manifest now explicitly
reuses `../../third_party/dtls`, and Cargo regenerated its lockfile in
commit `3663ba78`. Without this fix, it retained vulnerable
`crypto-bigint 0.5.5` despite the main workspace being updated.

The migration lockfile workflow is now manual-only after regeneration, to
avoid GitHub Actions bot commit churn and `action_required` check results.
The vendored DTLS verification workflow is read-only and checks that both
Cargo roots reference the same patched candidate.

## Release gates — NOT YET REMEDIATED OR PRODUCTION READY

A resolver that no longer lists `crypto-bigint 0.5.5` is necessary but
insufficient. Before merge, require:

1. `cargo audit --deny warnings` on **all six** lockfiles, without waivers,
   ignores or advisory suppression; all exact-head security and supply-chain
   checks must pass.
2. Full locked Rust compilation, Clippy, formatting, tests, WebRTC/DTLS
   handshake interoperability, MLS persisted-state compatibility, epoch
   rotation, key revocation, E2EE media encrypt/decrypt and regression tests.
3. A real, independently authenticated two-physical-Device one-click
   A↔B E2EE audio/video call with TURN/NAT, actual capture/playback and
   measured media quality/latency. CI/browser simulators do not prove this.
4. Preserve the sole canonical Identity/Device/Trust/crypto owners and
   endpoint-held private signing keys. No server-held private seed, browser
   ServicePrincipal secret, second phone/key store, or host access without
   the owner's exact UCR host authorization.

This branch remains draft. No server, SSH, VM, staging, production or remote
computer was accessed as part of this repository-local migration.
