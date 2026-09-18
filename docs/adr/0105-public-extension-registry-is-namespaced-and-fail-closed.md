# ADR 0105: Public extension registry is namespaced and fail-closed

Status: Accepted

## Context

The Canon requires a public extension/capability registry, stable namespaces and compatibility behavior for unknown optional versus critical extensions.

## Decision

UCR extension identifiers use these ownership namespaces:

- `ucr.*` — canonical stable identifiers governed by UCR protocol changes;
- `experimental.*` — explicitly unstable experiments;
- `vendor.<name>.*` — vendor-owned extensions;
- `organization.<id>.*` — organization-scoped extensions.

Canonical capability examples include `ucr.message.edit`, `ucr.call.video`, `ucr.transport.quic`, `ucr.group.mls` and `ucr.mesh.forward`.

The versioned protocol specification is the registry authority for `ucr.*`; runtime code may implement entries but may not silently mint conflicting canonical meanings. Optional unknown extensions are preserved/tolerated according to their enclosing schema. An unsupported critical extension fails negotiation explicitly.

Registration never grants permission: capability advertisement, policy and authorization remain separate checks. Extension payloads are bounded and redacted from unsafe diagnostics.

## Consequences

Third parties can extend UCR without changing Message/Conversation/Person semantics or colliding with canonical identifiers. Critical semantics cannot be silently ignored by old clients.
