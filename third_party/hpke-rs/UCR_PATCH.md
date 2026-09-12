# UCR security patch for hpke-rs 0.7.0

Source: `hpke-rs` 0.7.0 from crates.io / `celabshq/libcrux`.
License: MPL-2.0, as declared by the upstream package.

UCR changes exactly one implementation dependency:

- remove unconditional `libcrux-sha3 = 0.0.10`;
- use RustCrypto `sha3 = 0.11.0` for the two SHAKE256 seed derivations in
  `src/kem.rs` used by X-Wing/ML-KEM deterministic key derivation.

The selected Phase-29 MLS ciphersuite is X25519 + ChaCha20-Poly1305 + SHA-256,
so these PQ branches are not on its runtime path. They are nevertheless preserved
with the same SHAKE256 algorithm rather than deleted or disabled.

Reason: `libcrux-sha3` currently pulls `hax-lib 0.3.7`, whose cfg(hax) macro
implementation pulls unmaintained `proc-macro-error2 2.0.1`
(RUSTSEC-2026-0173). UCR does not suppress that audit warning.

The crates.io package also ships upstream test/bench dev-dependencies. They are
removed from this vendored dependency because Cargo records them in the root lockfile
even though they are not compiled for UCR; one of those dev-only edges reintroduced
`hpke-rs-libcrux -> hax` into `cargo audit`. Runtime dependencies and library code are
unchanged by that cleanup.

UCR also removes the unused optional `hpke-rs-libcrux` backend and its feature
edges from the vendored manifest. OpenMLS Phase 29 uses only
`hpke-rs-rust-crypto`; retaining an unused optional backend would still pull
Libcrux/Hax packages into Cargo.lock and make strict RustSec auditing fail even
though those packages are never compiled.
