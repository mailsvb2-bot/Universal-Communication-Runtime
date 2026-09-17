# ADR-0088: Phase 42 AI Actor Layer reuses canonical identity, policy and authorization

- Status: Accepted
- Date: 2026-09-17
- Phase: 42

## Context

The Canon requires AI to remain optional and outside the communication critical path. It also requires an AI Actor to have canonical identity, permissions, quotas, attribution and audit, plus explicit conversation data policies `AI_FORBIDDEN`, `LOCAL_AI_ONLY`, `ORGANIZATION_AI` and `EXTERNAL_AI_ALLOWED`. AI resource routing must remain distinct from transport routing.

The canonical model already contains `PrincipalKind::AiAgent`, `ActorKind::AiAgent`, `ActorRef`, tenant/namespace scope and the ordinary authorization engine. Creating a separate AI identity, permission store, Message pipeline or route owner would violate the single communication-model boundary.

## Decision

Phase 42 introduces a small standalone Prepared admission layer. It composes existing canonical Principal/Actor and authorization types and adds only AI-specific policy inputs:

- execution class: local, organization or external;
- conversation AI data policy;
- explicit attribution requirement;
- bounded quota units;
- metadata-only admission evidence.

AI permission checks are delegated to the existing `ucr_protocol::authorize` implementation. AI admission does not invoke a model, persist communication state, select a transport, execute Delivery, or alter retry semantics.

A profile whose Principal or Actor is not explicitly AI fails closed. A human Actor cannot be relabelled as AI by this layer. Empty attribution fails closed. AI data policy is evaluated before provider/model execution. Ordinary communication remains independent of this crate.

## Alternatives considered

### Add an AI Message Core

Rejected. AI-produced communication must still use the canonical Message/Conversation/Delivery owners.

### Add an AI-specific ACL store

Rejected. This would create a second authorization truth and could diverge from tenant/namespace security boundaries.

### Route communication through an AI resource router

Rejected. AI resource selection and communication transport routing are separate concerns. `TransportOrchestrator` remains authoritative for communication routes.

### Treat AI as a human Person Actor

Rejected. It would defeat attribution and allow AI to masquerade as a human participant.

## Security impact

Positive. AI access is deny-by-default across exact scope, canonical identity kind, explicit attribution, conversation data policy, canonical permission and quota. No AI action is authorized solely because a model/provider is reachable.

## Privacy impact

Positive. Conversation data policy can completely prohibit AI or constrain execution locality. Admission audit intentionally carries no prompt/response/plaintext or provider credential material.

## Compatibility impact

No wire or persisted communication schema changes are required for this Prepared slice. Existing communication owners and public contracts remain unchanged.

## Migration strategy

None for existing user data. The standalone Phase-42 crate is additive and consumes existing canonical types.

## Rollback strategy

Remove the Phase-42 crate, specification, ADR and evidence gates together. Ordinary UCR communication remains unchanged because AI is not in its critical path.

## Testing strategy

- `AI_FORBIDDEN` denies an otherwise authorized AI Principal;
- `LOCAL_AI_ONLY` rejects external execution;
- canonical permission authorization is required;
- quota is fail-closed;
- a human Actor cannot be admitted as AI;
- audit evidence contains no prompt, response, plaintext or secret fields;
- architecture guards ensure no new Message/Conversation/Delivery/transport owner is introduced;
- standalone format/check/clippy/test runs in CI.
