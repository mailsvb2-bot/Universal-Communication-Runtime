# ADR-0029: Infrastructure metadata visibility is explicit and machine-checked

Status: Accepted

## Context

The threat model requires minimum metadata disclosure and says every infrastructure component must document what it can observe. The repository already named ten canonical trust boundaries and stated special rules for Relay, Bridge, SFU, Cloud Infrastructure, and observability, but the rules were distributed across prose. A new infrastructure boundary could therefore be added without a complete visibility contract.

A metadata document alone is insufficient release evidence because it can silently drift away from the architecture. Conversely, pretending that future Relay/Bridge/SFU implementations already exist would overstate the reference runtime.

## Decision

`spec/metadata-visibility.tsv` is the machine-readable inventory and `spec/metadata-visibility.md` is its normative interpretation. Every numbered canonical trust boundary in `THREAT_MODEL.md` must have exactly one row. Observability is an additional mandatory cross-cutting row.

Each row declares implementation status, maximum metadata it may observe, hard negative visibility, retention expectation, and export rule. For `not_implemented` components, `may_observe` is a future privacy ceiling, not evidence of deployed code. Widening that ceiling requires explicit security review/ADR rather than accidental implementation drift.

The architecture suite dynamically parses the threat-model boundary list and the TSV. A new or renamed boundary without matching metadata classification fails CI. The same gate preserves the special minimum-disclosure invariants for Relay, Bridge, SFU, Cloud Infrastructure, and Observability.

## Consequences

The production blocker `metadata-visibility documentation for each infrastructure component` can be removed because the authoritative boundary set and the visibility inventory are now coupled by executable release evidence. This does not claim that future Relay, Bridge, SFU, Personal Node, Organization Node, Cloud, SDK, or External App implementations exist.

This ADR also does not close telemetry leak testing, Service Principal authentication, remote transport authentication, or content-at-rest encryption. Observability rules define what telemetry is allowed to see; separate regression tests must prove that actual telemetry paths obey those rules when implemented.

## Rejected alternatives

- Prose-only metadata notes: rejected because architecture changes could drift without CI failure.
- Treat encrypted content as making all metadata public: rejected because social graph, addresses, routing history, membership, presence, and discovery metadata remain privacy-sensitive.
- Universal “Bridge never sees plaintext” rule: rejected because an explicitly configured bridge to a provider may require provider-visible content; disclosure must instead be action- and policy-specific.
- Give cloud infrastructure a superset of every child component: rejected because hosting location creates no additional authority.
