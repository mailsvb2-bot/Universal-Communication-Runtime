# ADR-0089: Phase 43 Chaos Lab is deterministic test infrastructure

- Status: Accepted
- Date: 2026-09-17
- Phase: 43

## Problem

The Canon requires a Chaos Lab that can exercise network, infrastructure, process, storage, time, compatibility, revocation and slow-consumer failures, plus a 100-peer network simulation. The project also prohibits a second communication brain and requires data-safety failures to be explicit.

## Existing state

UCR already has canonical production owners for Message, Delivery, transport orchestration, storage, version negotiation, revocation, relay/SFU behavior and public contracts. Existing CI includes security, fuzz, release and conformance evidence, but there was no Phase-43 deterministic fault substrate that could compose failures without changing those owners.

## Options considered

### Put chaos flags into production transports

Rejected. Production behavior would become polluted by test-only branches and accidental production activation would become a security/reliability risk.

### Create a second simulated communication stack

Rejected. It would duplicate Message/Delivery/routing semantics and prove the simulator rather than UCR boundaries.

### Depend only on external network emulators

Rejected as the only strategy. Kernel/container chaos is useful later, but deterministic unit-level failure evidence is needed for fast reproducible CI and data-safety invariants.

### Selected: standalone deterministic Chaos Lab

Create a standalone, non-production crate with explicit peer, route and failure fixtures. It models only the fault surface and observable evidence needed for testing. It does not own canonical Message, Delivery, routing, persistence, cryptography or compatibility semantics.

## Decision

Phase 43 adds `ucr-chaos-lab` as an excluded standalone test-infrastructure crate. The root locked workspace remains unchanged. The lab provides:

- deterministic one-shot drop/duplicate/reorder/corruption;
- online/offline and network-switch peer state;
- DNS/relay/SFU availability;
- partition/merge;
- latency, clock drift and slow-consumer controls;
- explicit peer revocation;
- bounded durable-queue fixture with atomic storage-full failure;
- snapshot/restart fixture for process-kill/restart evidence;
- receiver-side duplicate suppression and corruption rejection evidence;
- canonical 100-peer simulation fixture.

Old-client compatibility remains owned by protocol/conformance version negotiation; Chaos Lab records the scenario but does not create another compatibility implementation.

## Security impact

Positive. The lab fails closed for revoked/offline peers and unavailable infrastructure, and corruption never becomes accepted data. Test/debug machinery is isolated from production workspace ownership.

## Privacy impact

Neutral to positive. Fixtures use synthetic payloads and identifiers. No production plaintext, credentials, keys or user data are required.

## Compatibility impact

None on public wire/API contracts. The Phase-43 crate is additive test infrastructure and excluded from the production workspace lock.

## Migration strategy

None. Existing production state is untouched.

## Rollback strategy

Remove the Phase-43 crate, spec, ADR, architecture tests and dedicated workflow together. No production schema or runtime migration is required.

## Testing strategy

Dedicated CI must prove:

- format/check/clippy/test for the standalone crate;
- duplicate suppression despite duplicate wire delivery;
- deterministic reorder evidence;
- corruption rejection;
- partition/merge recovery;
- explicit DNS/relay/SFU failure mapping;
- storage-full atomicity and restart persistence;
- revoked/offline peer fail-closed behavior;
- clock drift isolation from monotonic test time;
- slow-consumer observable latency;
- 100-peer fixture and partition/merge behavior;
- architecture guards preventing production-owner duplication.
