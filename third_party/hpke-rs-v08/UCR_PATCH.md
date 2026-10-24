# UCR security patch for hpke-rs 0.8.0

Source: hpke-rs 0.8.0 crates.io, checksum `deb74477a6c7f6e8e9c68de06fe928db79b3b8b9e04c900bfb729bf096df7d22`.
License: MPL-2.0, original license text retained as LICENSE-MPL-2.0.

UCR changes:
- Replace the unconditional Libcrux SHA3 dependency with RustCrypto `sha3 =0.11.0`.
- Preserve the **same SHAKE256 algorithm** and output lengths (32 and 64 bytes)
  for X-Wing and ML-KEM deterministic key derivation, using `shake256_seed`.
- Exclude the unused optional Libcrux backend and its development dependencies.
- Preserve the RustCrypto backend used by the current OpenMLS runtime.

These changes remove the `libcrux-sha3 -> hax-lib -> proc-macro-error2`
dependency chain reported by RUSTSEC-2026-0173. No RustSec ignore or
allowlisting has been introduced. E2EE interoperability must still be tested
before this branch is merged.
