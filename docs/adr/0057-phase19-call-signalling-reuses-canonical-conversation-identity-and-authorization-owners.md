# ADR 0057: Phase 19 Call Signalling reuses canonical Conversation, Identity, Group, Event and authorization owners

- Status: Accepted
- Scope: Phase 19 Prepared/reference Call Signalling

## Context

After Phase 18, UCR already owns provider-independent Identity/Principal, Conversation, Group membership, authorization, Service Principal admission, Event identity, and restart-safe storage. Call signalling requires durable participant state and idempotent lifecycle transitions, but creating a self-contained call stack with its own identities, conversations, group membership, event namespace, or media engine would create a second communication brain.

The Canon separates Call Signalling from later Audio/Video/E2EE/adaptive-media phases. Therefore signalling must be useful and durable without claiming that any media packet flowed.

## Decision

Phase 19 introduces one canonical `CallSession` aggregate for signalling-specific state only. The aggregate references an existing Direct/private-group/public-group `ConversationRef`; participants are exact canonical `PrincipalRef`s. Group-backed sessions consult the existing Group membership owner rather than copying membership into an independent authority system.

`CallStore` composes `ConversationStore` and `GroupStore`. Creation and mutations run in one storage critical section/SQLite transaction. Signal application combines current participant/Group authority, optimistic revision, canonical transition, EventId reservation and idempotency ledger atomically.

Signal duplicate records are actor-bound and include the applied revision. This permits an exact retry when the committed signal itself made the actor terminal while denying old retries after an independent later loss of authority. `EventId` remains a single exact-scope identity namespace across Event, GroupChange and CallSignal facts.

SQLite v22 adds `calls`, `call_participants`, and `call_signals`. It references existing Conversations and invents no calls during v21 migration. Memory and SQLite expose participant-gated reads that verify authority and return state from the same snapshot, preventing TOCTOU existence disclosure.

The public `CallService` is a thin Tonic binding. It reuses the existing binary Service Principal credential metadata, quota/audit admission, protocol permissions, `IntegrationIngress`, and `AuthorizedDurableRuntime`. Signal actor identity is never caller-controlled protobuf data.

Media renegotiation is represented only as an opaque signalling reference and monotonically increasing generation. Phase 19 does not parse codecs, candidates, media keys, RTP parameters, or transport descriptions.

## Security consequences

- Exact TenantScope is mandatory.
- Full PrincipalRef identity prevents principal-kind aliasing.
- Non-participants cannot distinguish a missing CallSession from an existing unauthorized one through the CallStore read boundary.
- Group removal immediately removes group-backed call authority because the existing Group owner is consulted in the same storage operation.
- Stale revisions, invalid transitions, forged actors and cross-scope calls fail closed.
- Duplicate/conflict evidence is actor-bound and is not an existence oracle after unrelated authority loss.
- EventId cannot name an unrelated Event, GroupChange and CallSignal in the same exact scope.
- Service Principal credential, quota, audit, and permission checks remain the existing single admission path.

## Durability consequences

SQLite v22 is restart-safe for CallSession, participant lifecycle and signal idempotency. Reopen preserves signalling state/revision and exact retry behavior. Migration from v21 creates empty call tables only; no Conversation/Group/Message/Event state is reinterpreted as a call.

## Nonclaims

This ADR does not claim audio/video media transport, RTP/SRTP/WebRTC, ICE/STUN/TURN, E2EE media, SFU/conferencing, adaptive media, push ringing, OS call integration, provider call bridges, Reference Messenger UI, route orchestration, or production network listener hardening.

## Rejected alternatives

1. **Separate call identities or conversation rows.** Rejected as a second Identity/Conversation brain.
2. **Copy Group membership into Call authority.** Rejected because Group membership would drift and removals could race signalling.
3. **Check authorization in Core then mutate a raw call store.** Rejected because authority could change between check and durable transition.
4. **Use a Call-local EventId namespace.** Rejected because one canonical fact identity must not silently name multiple unrelated durable facts.
5. **Treat `Active` signalling as media-connected evidence.** Rejected because Phase 19 owns signalling only; later media phases require their own evidence.
6. **Embed SDP/ICE/codecs/media keys in the canonical Phase19 model.** Rejected because it would prematurely make signalling the media owner.
