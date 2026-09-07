# UCR Protocol Specification

The `spec/` directory is normative protocol design material. Rust structures are a reference implementation mapping only.

The protocol must cover identity, principal, actor, device, endpoint, addressing, handshake, commands, events, messages, conversations, groups, calls, media, attachments, delivery, sync, permissions, policy, crypto negotiation, capability negotiation, errors, extensions and version negotiation.

Phase 0 defines common envelopes and negotiation rules first. Later phases refine entity-specific semantics without replacing the fundamental model.

Phase 13 adds the first external-consumer boundary in `integration-api.md`; it reuses canonical Commands, Identity/Conversation/Message/Communication Intent owners and Service Principal admission rather than exposing Rust/storage internals. Phase 14 adds `event-api.md`: a separate eight-RPC `EventService` over the one canonical append-only Event journal plus durable consumer cursor/retry/replay/dead-letter state. Generated Rust/Tonic code is not normative protocol logic. Phase 15 Internet Transport remains unstarted.
