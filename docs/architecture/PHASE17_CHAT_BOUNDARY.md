# Phase 17 Chat Boundary

Phase 17 is a Prepared reference application layer, not a new canonical model and not the Reference Messenger.

## Canonical owners reused

| Concern | Owner used by Phase 17 |
| --- | --- |
| Conversation identity/kind | existing `ConversationStore` |
| Message identity/content/idempotency | existing `MessageStore` |
| Delivery state/evidence | existing `DeliveryStore` |
| authorization | existing `AuthorizationEvaluator` / `AuthorizedDurableRuntime` |
| tenant/namespace | canonical `TenantScope` |
| transport | existing transport providers; no selection in Chat |
| event/sync discovery | existing/future canonical Event/Sync/query surfaces |
| typing | ephemeral `EphemeralChatSink`, never durable |

## State split

Durable: Conversation, Message, Delivery attempt/evidence.

Ephemeral: typing Started/Stopped hint with bounded TTL.

A relay or transport acknowledgement does not imply Delivered or Read. A user read is represented only by the canonical `READ_BY_USER` evidence transition.

## Phase boundary

Phase 18 Groups is intentionally not implemented here. The Phase-17 runtime rejects non-Direct conversations rather than treating Group as a thin alias for Direct chat.

The layer also does not own message edit/delete/reaction workflows, attachment transfer, presence truth, calls, route orchestration, messenger UI, or production listener lifecycle.
