# ADR 0055: Phase 17 Chat reuses canonical Conversation, Message, and Delivery owners

- Status: Accepted
- Date: 2026-09-08
- Phase: 17 — Chat

## Context

The Canon orders Phase 17 after LAN/Direct transport and before Groups. UCR already owns canonical Conversation, Message, Delivery, Identity, authorization, Event/Sync, and transport boundaries. Building a chat-specific message database, delivery state machine, identity map, or routing layer would violate the one-canonical-model and no-second-brain rules.

The Canon also separates durable messages from ephemeral typing and separates relay/transport acknowledgement from actual user-read evidence.

## Decision

Phase 17 is a Prepared direct-chat reference layer in `ucr-chat`.

It composes existing canonical owners through `AuthorizedDurableRuntime` and `DeliveryStore`. It owns no durable Message, Conversation, Delivery, Identity, Event, or route state.

Direct chat creation uses the existing Conversation owner and is restricted to `ConversationKind::Direct`. Text send uses the existing Message owner. Exact reads and bounded transcript projection reuse canonical Message reads. User read transitions reuse the existing Delivery state machine and require explicit `ReadByUser` evidence. Typing is sent only through a non-durable TTL-bounded `EphemeralChatSink`.

The transcript projection intentionally accepts explicit canonical Message IDs rather than inventing a second timeline index. Canonical Event/Sync/integration/future query layers may provide those IDs.

## Alternatives rejected

### A. Add a ChatMessage/ChatConversation database

Rejected. That creates a second communication brain and makes canonical Message/Conversation state ambiguous.

### B. Treat transport ACK as message read

Rejected. Relay or transport acknowledgement proves neither device receipt nor a human read action.

### C. Persist typing in the Event or Message journal

Rejected. The Canon defines typing as ephemeral and TTL-bound. Persisting it would manufacture durable history from a lossy hint.

### D. Implement Groups as part of Chat

Rejected. The Canon explicitly models Group as more than “chat + users” and schedules Groups in Phase 18.

### E. Add routing/failover inside Chat

Rejected. Route orchestration belongs to the later Transport Orchestrator phase and must remain below/alongside policy rather than inside the Chat application layer.

## Consequences

Phase 17 has a useful direct-chat reference API without changing storage schema or canonical model identity. Existing permissions, idempotency, tenant scope, delivery evidence, sync, and transport semantics remain authoritative.

The reference layer is intentionally not a messenger UI, group engine, presence authority, attachment service, or production network listener. Phase 18 Groups remains outside this ADR.
