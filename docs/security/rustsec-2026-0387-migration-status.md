# RUSTSEC-2026-0387 migration status

PR #310 pins the complete OpenMLS RustCrypto family to upstream revision
`be248d4b1306d87a641ce24ed0ffcab2b27967f6` and aligns SQLite
with `rusqlite 0.40.0`. Cargo-generated lockfiles now contain both
`crypto-bigint 0.7.6` **and vulnerable 0.5.5**.

The sole remaining 0.13 curve consumer in root Cargo.lock is
`dtls 0.17.2` (via `webrtc 0.17.2`), which holds
`p256 0.13.2` / `p384 0.13.1` and `elliptic-curve 0.13.8`.
This migration is **NOT COMPLETE**. No RustSec ignore/allowlisting.

Before merging: remove the DTLS legacy branch using an audited and
compatible WebRTC/DTLS upgrade, regenerate all six lockfiles with Cargo,
run `cargo audit --deny warnings` for every lockfile, and validate
UCR peer-connection compatibility, MLS persisted state and E2EE calls.


## DTLS candidate

The migration branch now vendors the upstream dtls 0.17.2 crate with its published
SHA-256 verified before import and changes its curve dependency declarations to
p256/p384 0.14 and sec1 0.8. This is an unverified API migration until Cargo.lock
regeneration, full compilation, DTLS interoperability and all RustSec audits pass.
