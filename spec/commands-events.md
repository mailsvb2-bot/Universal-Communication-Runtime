# Commands, Events, Correlation, and Idempotency

Status: **Phase 5 foundational contract**.

A `Command` requests an action. An accepted command is not evidence that the requested effect occurred. An `Event` records a fact in UCR state.

Command and event types are namespaced identifiers. Provider/product action names do not become canonical command/event types.

## Command idempotency

Every accepted command requires a non-empty bounded idempotency key. The key is interpreted inside the command's explicit `TenantScope`; different tenant/namespace scope means a different command domain.

A retry using the same scope, idempotency key, command type, and payload is a duplicate of the original command. It must not create a second user-visible operation.
Reusing the same scoped idempotency key for a different command type or payload is `CONFLICT`. The runtime must not guess which request the caller intended.

Idempotency provides an effectively-once user experience under defined retry conditions; UCR does not claim universal exactly-once execution across arbitrary external systems.

## Command receipts

`CommandReceipt(ACCEPTED)` means the runtime accepted responsibility for the command according to the current layer's contract. `CommandReceipt(DUPLICATE)` points to the original accepted command.

Neither receipt is an Event. Neither proves message delivery, external side effect, user observation, payment, provider acceptance, or any other real-world outcome.
## Events and causation

A canonical Event carries event ID, explicit tenant/namespace scope, actor, source device, wall-clock timestamp, logical ordering, correlation/causation, schema version, integrity metadata, event type, and payload. Actor and source device are provenance, not display strings.

Events carry correlation metadata and may identify a causation ID when a command or prior event caused the fact. Not every event is command-caused, so causation remains optional.

`wall_time_unix_ms` exists for audit/display context and interoperability. It is not the sole ordering rule and must not be trusted as authorization, freshness, replay, or identity evidence. Logical ordering remains explicit canonical runtime metadata. Provider timestamps do not replace either field.

## Persistence boundary

Phase-6 local storage provides restart-safe command acceptance/deduplication and an append-only canonical Event journal. A terminal Event may be atomically linked to a previously accepted Command when its scope matches and its causation ID references that Command.

This terminal link records UCR processing state. It does not prove an arbitrary external side effect happened exactly once. Crash-safe handler claiming/recovery and downstream/external idempotency remain separate responsibilities and must not be inferred from a terminal Event.
