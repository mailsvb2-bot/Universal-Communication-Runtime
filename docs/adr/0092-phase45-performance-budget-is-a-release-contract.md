# ADR 0092: Phase-45 performance budget is a release contract

Status: Accepted

## Context

The Canon requires load tests for production-ready capabilities and states that, once an SLO or performance threshold is fixed, it must not be weakened merely to restore green CI without an ADR and evidence.

The repository has one canonical SFU Conference lifecycle that builds Group membership, creates the canonical Call, accepts invited participants and verifies active topology/state. Phase 45 originally fixed the 1000-participant regression budget. The contract is now strengthened with 10, 100 and 500 participant profiles while preserving the original 1000-person ceiling unchanged.

A hosted CI timing budget is not a complete end-user latency SLA and must not be described as one. It is, however, a reproducible regression contract over a large canonical workload when the build profile, workload, sample count and threshold are all source-controlled.

## Decision

Phase 45 defines the production-profile performance regression matrix as follows:

- 10 participants: `ten_person_sfu_conference_profile`, fixed **5.0 seconds per sample**;
- 100 participants: `hundred_person_sfu_conference_profile`, fixed **6.0 seconds per sample**;
- 500 participants: `five_hundred_person_sfu_conference_profile`, fixed **8.0 seconds per sample**;
- 1000 participants: `thousand_person_sfu_conference_fits_bounded_call_ceiling`, fixed **10.0 seconds per sample**;
- build profile: Cargo `production`;
- measured samples: 3 for every level;
- runner family: GitHub-hosted Ubuntu 24.04 with the repository-pinned Rust toolchain;
- evidence: exact source commit, per-profile measured durations, median, worst sample, Rust/Cargo versions and runner OS.

All four reference tests use the same canonical lifecycle helper, so the matrix changes scale rather than business semantics. The 1000-participant ceiling is unchanged from the original contract.

`tools/performance_gate.py` owns this exact matrix. Participant levels and thresholds are constants in source code, not workflow inputs or environment variables.

The performance gate fails closed if any workload fails or any sample exceeds its fixed budget. CI must not use retries, `continue-on-error`, shell success masking or dynamically relaxed thresholds.

Adding a stricter profile may strengthen this contract without weakening an existing budget. Removing a level, reducing sample count, or relaxing any existing ceiling requires an explicit follow-up ADR with replacement evidence. A red build by itself is not sufficient justification.

## Non-claims

This contract does not claim:

- a public API latency SLA;
- Internet/WAN media quality or throughput;
- 1000 simultaneous encoded media streams on one host;
- production capacity planning for every hardware class;
- replacement of long-running soak/stress testing.

Those can be added as stronger performance contracts without weakening this baseline.

## Consequences

- Phase-45 release evidence gains a concrete, immutable performance gate instead of a prose-only performance requirement.
- 10/100/500/1000 participant functional regressions run under the production build profile with fixed per-level timing budgets.
- Performance evidence is tied to the exact source commit and retained in machine-readable JSON.
- Future threshold relaxation is reviewable architectural change, not a CI tweak.
