# RUSTSEC-2026-0387 — crypto dependency-chain diagnostics

**Status:** diagnostic tooling only; the security issue is NOT yet fixed.
Do not merge or deploy until existing `cargo audit --deny warnings` checks pass
without allow-lists, and end-to-end encrypted workflows are verified.

Observed dependency chain in PR #306: `crypto-bigint 0.5.5` via
`elliptic-curve 0.13.8` via `p256 0.13.2`, `p384 0.13.1`,
`k256 0.13.4`, referenced by `openmls_rust_crypto 0.6.0`,
`hpke-rs-rust-crypto 0.7.0` and `dtls 0.17.2`.
The advisory specifies `crypto-bigint >=0.7.6`.

## Safe usage

```bash
python3 -m unittest discover -s tests -p test_audit_crypto_chain.py -v
python3 scripts/audit_crypto_chain.py --allow-vulnerable --report crypto-chain-before.json
cargo tree --locked -i crypto-bigint@0.5.5
bash scripts/crypto_chain_migration_probe.sh
```

The `--allow-vulnerable` flag is solely for baseline diagnostic reports.
The normal audit command exits 1 if any of the six lockfiles remains unsafe
and exits 2 if a lockfile is missing or invalid. Existing RustSec CI remains
unchanged and blocking.

The migration probe creates a disposable `git archive HEAD` checkout,
copies the diagnostic script, attempts a precise upgrade with Cargo, checks
each lockfile and, only if resolution succeeds, runs build/tests/audit in
the disposable directory. **It never modifies the real checkout.**
Exit 12 means the existing parent dependencies block the direct upgrade;
it is NOT a successful remediation.

## Required actual fix

1. Find compatible upstream versions for OpenMLS/HPKE and DTLS/WebRTC that
   no longer depend on the vulnerable `elliptic-curve 0.13` chain.
2. Preserve the existing local `third_party/hpke-rs` SHAKE256 semantics
   when replacing the old override; do not remove the patch blindly.
3. Re-resolve all six Cargo.lock files through Cargo; never hand-edit checksums.
4. Run all security audits, compiler and workspace tests with locked dependencies.
5. Test saved MLS identities/group state and epochs, browser DTLS interop,
   E2EE messaging and calls with independent endpoints, rollback and revocation.

Official advisory: https://rustsec.org/advisories/RUSTSEC-2026-0387.html
