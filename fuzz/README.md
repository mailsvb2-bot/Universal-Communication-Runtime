# UCR bounded fuzzing

This package is intentionally a separate Cargo workspace. The production workspace stays on the pinned stable toolchain; fuzzing uses a separately pinned nightly toolchain because `cargo-fuzz`/libFuzzer sanitizer instrumentation requires it.

## Current targets

- `framing_parser`: raw frame-header/prefix bytes and stream-boundary invariants.
- `opaque_id_wire`: raw `OpaqueId` wire bytes, UTF-8/budget validation, and exact round-trip.
- `message_envelope`: bounded adversarial Message construction, validation/canonicalization idempotence, and signing-binding eligibility.
- `crypto_wrapper`: arbitrary Ed25519 public-key/signature/binding bytes plus public-key descriptor validation.

These are the implemented parser/wrapper boundaries that exist today. Bridge normalization, file-chunk parsing, signalling parsing, and generated protobuf Message decoding require their own fuzz targets when those implementations appear; this directory must not fake coverage for code that does not yet exist.

## Reproducible smoke run

Install `nightly-2026-09-02` with `rust-src`, then install `cargo-fuzz 0.13.2 --locked`. Run:

```sh
./fuzz/run-smoke.sh
```

## Budgets and corpus policy

`run-smoke.sh` is the single owner of smoke budgets. Each target has an explicit maximum input size, per-input timeout, RSS limit, and total runtime. The committed seed corpus is copied to a temporary directory before fuzzing so routine runs never mutate Git state.

Crash artifacts are written under `fuzz/artifacts/<target>/` and uploaded by CI on failure. A discovered crash is not considered resolved by deleting the artifact: minimize it, promote the minimized input into the committed corpus, add a deterministic regression test when practical, and only then fix/close the finding.

The required CI fuzz job is a bounded smoke/release gate, not a substitute for longer campaigns. Longer scheduled/manual campaigns may extend runtime, corpus, and sanitizers, but must use the same target owners and must not weaken the bounded required gate.
