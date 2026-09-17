# ADR 0092: Phase-45 performance budget is a release contract

Status: Accepted

## Context

The Canon requires load tests for production-ready capabilities and states that, once an SLO or performance threshold is fixed, it must not be weakened merely to restore green CI without an ADR and evidence.

The repository already has a canonical conference regression that builds a 1000-participant SFU call, accepts all invited participants and verifies the active topology/state. That test proves functional bounded scale but previously had no release-time latency budget.

A hosted CI timing budget is not a complete end-user latency SLA and must not be described as one. It is, however, a reproducible regression contract over a large canonical workload when the build profile, workload, sample count and threshold are all source-controlled.

## Decision

Phase 45 defines the initial production-profile performance regression contract as follows:

- workload: `1000-person-sfu-conference-lifecycle`;
- implementation: existing `thousand_person_sfu_conference_fits_bounded_call_ceiling` reference test;
- build profile: Cargo `production`;
- measured samples: 3;
- fixed maximum duration: **10.0 seconds per sample**;
- runner family: GitHub-hosted Ubuntu 24.04 with the repository-pinned Rust toolchain;
- evidence: exact source commit, three measured durations, median, worst sample, Rust/Cargo versions and runner OS.

`tools/performance_gate.py` owns this exact contract. The threshold is a constant in source code, not a workflow input or environment variable.

The performance gate fails closed if the workload fails or any sample exceeds the fixed budget. CI must not use retries, `continue-on-error`, shell success masking or a dynamically relaxed threshold.

Changing the workload, sample count or 10.0-second ceiling requires an explicit follow-up ADR that records why the old contract is no longer appropriate and supplies replacement evidence. A red build by itself is not sufficient justification.

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
- A 1000-participant functional regression now runs under the production build profile and a fixed timing budget.
- Performance evidence is tied to the exact source commit and retained in machine-readable JSON.
- Future threshold relaxation is reviewable architectural change, not a CI tweak.
