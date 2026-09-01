# ADR-0002: Phase-0 wire framing baseline

Status: Accepted (Experimental, pre-1.0)

## Problem

UCR needs deterministic byte-stream boundaries shared by SDK, IPC, relay, test, and future transports without letting any transport become the protocol definition.

## Existing state

The repository had protobuf envelopes and version negotiation but no canonical byte-stream frame. Implementations could therefore invent incompatible length-prefixing, size limits, and unknown-flag behavior.

## Options considered

1. Leave framing transport-specific.
2. Use only protobuf length-delimited encoding and make frame kind implicit.
3. Define a small versioned transport-neutral fixed header around protobuf payloads.

## Decision

Adopt option 3: `UCRF` magic, 16-bit framing version, explicit frame kind, reserved flags, and 32-bit big-endian payload length. Framing v1 requires zero flags and defaults to a 16 MiB payload safety ceiling.

## Reasons and tradeoffs

The header is deterministic, language-independent, cheap to parse, independently versioned, and usable over streams while protobuf remains the public message schema.

The cost is small framing overhead and another governed version number. The 32-bit length field does not make giant payloads valid; attachment transport remains separate.

## Security and privacy impact

Magic bytes are not authentication. Parsers enforce size limits and fail closed on unsupported flags, versions, and kinds. Integrity and peer authentication belong to the authenticated handshake/crypto layer.

The header exposes frame size and coarse frame kind to an observer able to see the unprotected boundary. Metadata minimization remains part of the threat model.

## Compatibility, migration, rollback

Framing v1 is experimental before 1.0. Future framing versions are added alongside supported old versions; v1 fields are never reinterpreted in place. Rollback retains parsers required by persisted/conformance vectors.

## Testing strategy

Regression tests cover round-trip headers, stream remainder handling, reserved flags, unsupported versions, incomplete payloads, and oversize lengths. CI compiles every public protobuf schema.
