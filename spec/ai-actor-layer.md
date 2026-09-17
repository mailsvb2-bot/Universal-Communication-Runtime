# UCR AI Actor Layer — Phase 42

Status: **Prepared**.

## Purpose

Phase 42 adds an admission boundary for AI Actors without placing AI in the communication critical path and without creating an AI-specific Message, Conversation, Delivery, Identity, authorization, routing, or storage brain.

Canonical communication continues to work when no AI system is available. Message, sync, call and file execution remain owned by their existing UCR subsystems.

## Canonical actor identity

An AI participant uses the existing canonical principal/actor vocabulary:

- `PrincipalKind::AiAgent` for rights, scope and quota ownership;
- `ActorKind::AiAgent` for communication attribution;
- `ActorRef.on_behalf_of` where the canonical action is performed on behalf of another Principal.

An AI Actor must not be admitted with a human Actor kind. A non-empty attribution label is mandatory for Prepared Phase-42 AI admission.

## Conversation AI data policy

Every AI admission is evaluated against one of four explicit policies:

- `AI_FORBIDDEN` — no AI processing is admitted;
- `LOCAL_AI_ONLY` — only local execution is admitted;
- `ORGANIZATION_AI` — local or organization-controlled execution is admitted;
- `EXTERNAL_AI_ALLOWED` — local, organization or external execution may be admitted.

The policy is deny-by-default at the AI boundary. It never weakens ordinary UCR transport/privacy policy.

## Permission and quota ownership

Phase 42 reuses the canonical UCR authorization engine and ordinary namespaced permissions. It does not create an AI permission database or alternate ACL evaluator.

AI admission requires all of:

1. exact tenant/namespace scope agreement;
2. canonical AI Principal and Actor kinds;
3. explicit attribution;
4. conversation AI data policy allowing the requested execution class;
5. canonical permission authorization;
6. positive requested quota units not exceeding the configured AI Actor quota.

## Audit and privacy

Prepared admission returns metadata-only evidence containing scope, conversation ID, actor reference, execution class, permission, requested quota units and outcome.

Admission evidence must not contain prompt text, response text, message plaintext, credentials, model secrets, private keys or provider tokens.

## Routing boundary

AI resource selection is not transport routing. Phase 42 does not alter `TransportOrchestrator`, route ranking, Delivery state, Message persistence, retry execution or provider-acceptance semantics.

## Non-claims

Prepared Phase 42 does not claim:

- an AI model runtime;
- model/provider selection;
- prompt orchestration;
- RAG or memory;
- AI-generated message execution without ordinary canonical admission;
- new transport routes;
- production AI governance/compliance certification.

Later AI-resource routing may compose this admission boundary but must remain separate from communication transport routing.
