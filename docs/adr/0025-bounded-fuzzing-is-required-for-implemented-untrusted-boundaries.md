# ADR-0025: Bounded fuzzing is required for implemented untrusted boundaries

Status: Accepted

## Context

The Canon and threat model require fuzzing before parser/wrapper capabilities can be treated as Production. Deterministic unit tests already cover many malformed cases, but they cannot substitute for mutation-driven exploration of parser boundaries, length arithmetic, validation/canonicalization wrappers, and cryptographic verification inputs.

The repository does not yet implement every future UCR boundary named by the threat model. There is currently no production bridge normalizer, file-chunk parser, signalling parser, or generated protobuf Message decoder in the Rust reference runtime. Creating placeholder fuzz targets for absent code would create false security evidence.

The implemented untrusted or adversarial boundaries today are the framing byte parser, `OpaqueId` semantic wire decoder, canonical Message validation/canonicalization wrapper, and Ed25519/public-key crypto verification wrappers.

## Decision

Maintain a separate `fuzz/` Cargo workspace using pinned `libfuzzer-sys`. The production workspace remains on stable Rust. Required fuzz CI installs the dated `nightly-2026-09-02` toolchain with `rust-src` and pinned `cargo-fuzz 0.13.2 --locked`.

The required bounded targets are:

1. `framing_parser`;
2. `opaque_id_wire`;
3. `message_envelope`;
4. `crypto_wrapper`.

`fuzz/run-smoke.sh` is the single owner of required smoke budgets. Every target has an explicit maximum input length, per-input timeout, RSS limit, and total-time budget. CI executes the same script used locally.

Committed corpora are seed/regression inputs, not mutable fuzzer state. The smoke script copies seeds into a temporary corpus before execution. Crash artifacts are retained by CI; a real crash must be minimized and promoted into committed corpus/regression evidence rather than deleted.

The `fuzz-smoke` job is a required branch-protection check. Adding a new parser/wrapper that consumes untrusted or persisted bytes requires adding its fuzz target before claiming Production maturity for that boundary.

## Consequences

- Main stable-Rust quality/release gates do not depend on nightly.
- Fuzz dependencies are isolated from the production Cargo workspace and lockfile.
- Parser/wrapper crash, panic, sanitizer, timeout, and runaway-memory failures fail the required fuzz job.
- Existing framing, ID, Message wrapper, and crypto-wrapper fuzz obligations have executable evidence rather than documentation-only claims.
- Future bridge/file/signalling/protobuf parser work cannot inherit fuzz coverage by assertion; it must add real targets.

## Nonclaims

A bounded required fuzz smoke is not proof of memory safety, formal verification, exhaustive state coverage, transport security, authorization, chaos resilience, or absence of cryptographic flaws. Longer campaigns remain valuable and may find failures that the required smoke window does not.

This ADR closes only the production blocker for **required fuzz targets for implemented parsers/wrappers**. Other threat-model blockers remain independent.

## Rejected alternatives

- Unit tests only: rejected because the Canon explicitly requires fuzzing.
- Placeholder targets for absent bridge/file/signalling parsers: rejected because they create false evidence.
- Move the entire repository to nightly: rejected because fuzz tooling must not weaken the pinned stable production toolchain.
- Unbounded fuzzing in required CI: rejected because required checks need bounded time/resource behavior and predictable release governance.
