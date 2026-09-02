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

Events carry correlation metadata and may identify a causation ID when a command or prior event caused the fact. Not every event is command-caused, so causation remains optional.

Logical ordering is explicit runtime metadata; it must not be substituted with provider timestamps as the sole canonical ordering rule.

## Persistence boundary

Durable idempotency requires persistent acceptance/deduplication state and restart-safe semantics. The current Phase-5 reference logic defines comparison/validation semantics only; it does not claim restart-safe durable command processing until the Local Storage phase implements and tests that state.
