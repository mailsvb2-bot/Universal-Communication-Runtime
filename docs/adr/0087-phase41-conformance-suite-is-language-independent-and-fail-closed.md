# ADR-0087: Phase 41 conformance is language-independent and fail-closed

- Status: Accepted
- Date: 2026-09-17
- Phase: 41

## Context

Phase 39 introduced five public SDK language surfaces over one `ucr.v1` contract and deliberately deferred complete cross-language conformance. Phase 40 then proved that an ordinary public consumer can use the public API without hidden Core access. The Canon places Conformance Suite next and requires SDK checks for auth, commands, events, retries, permissions, version negotiation, errors, and idempotency.

A conformance implementation must not become a second source of protocol or domain truth. It also must not declare compatibility from documentation or static naming alone.

## Decision

UCR uses one machine-readable Phase-41 SDK matrix shared by Rust, Python, TypeScript, Kotlin, and Swift.

The checked-in `ucr.v1` protobuf contract and the existing Phase-39 SDK semantic manifest remain authoritative inputs. The suite only verifies that a candidate preserves those semantics.

Every required language must have an executable host probe that exercises its actual credential helper on CI. The Rust reference SDK additionally carries runtime-binding evidence through its public `ServiceCredential`/request surface. Missing probes, unavailable required categories, or skipped required evidence fail closed.

Conformance is profile-scoped and evidence-level-scoped. Passing the Prepared SDK profile does not silently certify Production deployment, a transport, a bridge, or a compatible node.

## Alternatives considered

### Treat Phase 39 static guards as conformance

Rejected. They protect architecture boundaries but do not independently execute all five language helpers and do not establish a Phase-41 matrix.

### Generate a separate protocol model for the suite

Rejected. That would create a second wire truth and allow the conformance implementation to drift away from `ucr.v1`.

### Let every SDK define its own tests and vocabulary

Rejected. Divergent language-specific criteria would make “conformant” incomparable and could hide semantic drift.

### Require package signing and registry publication now

Rejected. Those are supply-chain concerns assigned to Phase 44. Phase 41 must not collapse later release phases into semantic conformance.

## Consequences

### Advantages

- one explicit eight-axis SDK matrix;
- all five language helpers execute on CI rather than being accepted from comments alone;
- failures are fail-closed and cannot be converted into a compatibility claim;
- public contract and canonical runtime ownership remain unchanged;
- later transport/bridge/node profiles can reuse the same framework.

### Costs

- CI gains an additional cross-language job matrix;
- runner toolchain availability becomes explicit evidence input;
- Prepared conformance remains distinct from package/release certification.

## Security impact

Positive. Authentication metadata, credential redaction, permission-denial preservation, downgrade/version boundaries, canonical errors, and idempotency/retry constraints become explicit release evidence. The suite is forbidden from importing privileged Core/storage paths into SDKs.

## Privacy impact

Positive/neutral. Conformance fixtures contain only synthetic bytes. Credential secrets are never logged by the probes; diagnostics check redaction rather than printing secret material.

## Compatibility impact

The public wire contract does not change. This ADR adds evidence around the existing contract and makes compatibility claims stricter.

## Migration strategy

Existing Phase-39 SDK surfaces become Phase-41 candidates without API migration. Add the common matrix, validator, language host probes, Rust runtime-binding test, workflow, and architecture guard.

## Rollback strategy

The Phase-41 evidence files can be reverted without changing canonical user data or protocol state. A rollback must also remove any Phase-41 compatibility claim; it must not leave the claim while deleting its evidence.

## Testing strategy

- dependency-free matrix validation;
- executable Python, TypeScript, Kotlin, Swift, and Rust host probes;
- Rust public-SDK runtime-binding test;
- existing public protobuf compilation;
- Phase-41 architecture regression test requiring the spec, ADR, matrix, validator, probes, and workflow;
- existing workspace, release, security, fuzz, public-contract, and repository-guard CI remain unchanged.
