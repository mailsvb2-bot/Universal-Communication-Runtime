# ADR-0005: Threat model is a release gate

Status: Accepted

## Context

UCR crosses device, application, SDK, runtime, relay, bridge, SFU, personal-node, organization-node, and cloud trust boundaries. Ordinary unit tests and green CI cannot by themselves prove that security claims are implemented or that a production capability is safe.

The Canon requires explicit threat modeling, minimum disclosure, fail-closed behavior, device revocation, recovery analysis, threat tests, fuzzing, and chaos evidence before relevant capabilities are treated as Production.

## Decision

`docs/architecture/THREAT_MODEL.md` is a required living release-gating artifact. It must keep the canonical trust boundaries, required threat classes, security invariants, and explicit production blockers visible until implementation and evidence close them.
A blocker may be removed only in a reviewed change that supplies the corresponding implementation and test/review evidence. Documentation edits alone cannot close a blocker.

Architecture regression tests enforce the continued presence of the required threat classes, boundaries, minimum-disclosure statements, and blocker categories. These tests protect the model from accidental erosion; they are not evidence that the threats themselves have been mitigated.

## Consequences

- Security maturity cannot be promoted by relabeling documentation.
- New transports/infrastructure must extend the threat model before production promotion.
- A green repository can still honestly remain non-production for a security capability while blockers are open.
- Security claims remain narrower than demonstrated evidence.
- Removing a blocker requires an auditable repository change rather than an implicit operational assumption.

## Rejected alternatives

Treating the threat model as advisory documentation was rejected because it permits drift. Treating ordinary CI as security-completeness evidence was rejected because it conflates regression coverage with adversarial assurance.
