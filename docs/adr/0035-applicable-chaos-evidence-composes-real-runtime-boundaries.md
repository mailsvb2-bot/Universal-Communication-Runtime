# ADR-0035: Applicable chaos evidence composes real runtime boundaries

Status: Accepted

## Context

The Canon requires chaos coverage for restart, clock drift, duplication/reorder/corruption, storage exhaustion, partitions/merge, old clients, revoked Devices, and future network/Relay/SFU/consumer failures. The repository already contains several real local/reference boundaries, but counting isolated unit tests or fabricating nonexistent network components would not demonstrate the required cross-boundary failure semantics.

## Decision

`ucr-security-tests` owns executable chaos **evidence only**. `chaos_scenarios.rs` composes the existing Core, Protocol, Crypto, Memory, and SQLite public boundaries and currently proves seven applicable local/reference scenarios: app restart with durable command deduplication, concurrent duplicate ingress, clock rollback with mandatory audit, local replica partition/merge, old-client downgrade refusal, authenticated Message corruption, and revoked-Device restart behavior.

The test crate does not implement fallback, retry, authorization, Sync, Device, crypto, or storage policy. Each scenario invokes the existing production/reference owner and asserts a durable/security invariant rather than mere process survival.

`docs/architecture/CHAOS_SCENARIOS.md` is the evidence index. Architecture CI locks the executable scenario names to that matrix and keeps unsupported scenarios explicitly open.

## Fail-closed limitations

An application restart is not claimed to be a process-kill test. At adoption, the SQLite `SQLITE_FULL` mapping test was not claimed as end-to-end storage-full chaos evidence; ADR-0036 later adds provider-owned page-capacity exhaustion evidence without adding a public fault-injection API. Local two-store Anti-Entropy convergence is not claimed as authenticated production network partition recovery. Authenticated Message corruption is not claimed as a production packet-reorder/receive pipeline. DNS, Relay, SFU, peer-disappearance, transport reorder, and slow-consumer scenarios remain unimplemented until those real boundaries exist.

## Rejected alternatives

Treat existing unit tests with matching words as chaos evidence: rejected because they may not cross the relevant boundary. Create fake Relay/SFU/network implementations only to satisfy the checklist: rejected because it would manufacture a second runtime and false production evidence. Rename app restart as process kill: rejected because the failure point is materially different. Treat an error-code mapping for `SQLITE_FULL` as durable storage-exhaustion evidence: rejected because it does not prove transaction outcome under exhaustion. Remove the generic chaos blocker entirely: rejected until all currently applicable failure injection exists and future real boundaries carry their own evidence.
