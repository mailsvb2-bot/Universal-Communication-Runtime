# UCR Protocol Specification

The `spec/` directory is normative protocol design material. Rust structures are a reference implementation mapping only.

The protocol must cover identity, principal, actor, device, endpoint, addressing, handshake, commands, events, messages, conversations, groups, calls, media, attachments, delivery, sync, permissions, policy, crypto negotiation, capability negotiation, errors, extensions and version negotiation.

Phase 0 defines common envelopes and negotiation rules first. Later phases refine entity-specific semantics without replacing the fundamental model.

Phase 13 adds the first external-consumer boundary in `integration-api.md`; it reuses canonical Commands and Service Principal admission rather than exposing Rust/storage internals.
