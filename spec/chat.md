# Phase 17 Chat

Status: **Prepared reference implementation**, not Production.

Phase 17 adds a transport-neutral direct-chat application layer over the canonical UCR Conversation, Message, Delivery, Identity, authorization, Event/Sync, and storage owners. It does not create a second communication model, message database, delivery state machine, route planner, or user-interface source of truth.

## Scope

The Prepared reference surface supports:

- creation/deduplication of `DIRECT` conversations through the existing `ConversationStore` owner;
- durable text Message persistence/deduplication through the existing `MessageStore` owner;
- exact Message reads and bounded transcript projection for explicitly supplied canonical `MessageId`s;
- deterministic transcript ordering by canonical `logical_order`, then `MessageId` only as a deterministic tie-breaker;
- explicit user-read action as `DeliveryEvidenceKind::ReadByUser` and `DELIVERED -> READ` through the existing `DeliveryStore` state machine;
- best-effort typing updates with bounded TTL through a non-durable ephemeral sink.

## Durable versus ephemeral

Messages remain durable canonical objects. A successful Chat send means the canonical Message owner persisted or deduplicated the Message; it is not proof of route selection, transport acceptance, device receipt, user delivery, or user read.

Typing is deliberately ephemeral. It has no durable event ID, no Message ID, no delivery state, no retry queue, and no storage schema. A typing update may be lost. Its expiry is evaluated through an injected clock and is capped by `MAX_TYPING_TTL_MS`.

## Read evidence

Transport or Relay acknowledgement is never promoted to `READ`. Phase 17 advances a delivery to `READ` only from canonical `DELIVERED` state and only with explicit `READ_BY_USER` evidence. An already-Read delivery is an idempotent retry.

## Transcript projection

Phase 17 does not add a parallel timeline index. `load_transcript_batch` accepts a bounded list of canonical Message IDs, reads those Messages through the existing authorized Message owner, rejects cross-conversation material, and produces a deterministic projection. The projection is bounded both by `MAX_TRANSCRIPT_BATCH_ITEMS` and by `MAX_TRANSCRIPT_BATCH_BYTES`; the aggregate byte budget counts Message content plus variable envelope material such as IDs, relations, crypto metadata, extensions, external mappings, correlation data, and signatures so item-count limits cannot be bypassed through large canonical Messages. Message IDs may come from existing Event, Sync, integration, or future canonical query surfaces.

## Security and scope

Every durable operation crosses the existing `AuthorizedDurableRuntime`. The Chat layer additionally rejects a subject whose exact `TenantScope` differs from the requested resource scope. Ephemeral typing requires Conversation read authorization and Message write authorization. Service Accounts cannot bypass the existing Core-owned Service Principal admission proof.

## Explicit nonclaims

Phase 17 does **not** claim:

- private/public groups, membership, roles, invitations, moderation, join/leave/kick/ban semantics (Phase 18+);
- message edit/delete, reactions, thread lifecycle, forwarding workflow, or attachment/file transfer;
- presence durability or presence as a security signal;
- calls, WebRTC, SFU, voice/video, screen sharing;
- discovery, Relay/NAT traversal, route planning, failover, or Transport Orchestrator behavior;
- Reference Messenger UI/UX;
- production listener hardening or Production maturity.

Existing canonical relation vocabulary is not removed. Phase 17 text send accepts only `Reply`, `Quote`, and `Reference` relations; other already-defined relation kinds remain reserved for later behavior rather than being silently reinterpreted.
