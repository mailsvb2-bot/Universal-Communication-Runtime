# ADR 0086 — Phase-40 Dev Mode composes canonical owners behind the public API

## Decision

Phase 40 adds `ucr dev` as a development-only local host. It seeds canonical in-memory Identity/Device state and Service Principal admission, then exposes the existing public gRPC services on loopback. External dev interactions use the public contract; no second Message, Group, Call, Delivery, Identity, routing or retry owner is introduced.

## Security boundary

Authentication, permissions and quota admission stay enabled. The host refuses non-loopback bind addresses. Test credentials and state are ephemeral to the development process. Dev Mode must not create an insecure production profile or silently weaken protocol/security rules.

## Sandbox

Fault injection belongs to a development-only `TestTransport`. Delay, drop, duplicate, reorder, disconnect/reconnect, corruption and throttling are simulation controls, not production transport policy. `ucr dev --check` also executes representative authenticated public Identity, Conversation, Message, Group and Call operations.

## Consequence

The developer-first `install -> ucr dev -> ready` goal has executable Phase-40 evidence without turning the Reference Messenger or dev harness into another communication brain. Full SDK/transport/bridge/node conformance remains Phase 41.
