# ADR-0049: Phase-13 gRPC SubmitCommand is a thin binding over IntegrationIngress

Status: Accepted
Date: 2026-09-06

## Context

The Canon requires a versioned language-independent public contract with protobuf and gRPC support,
while keeping SDK/API/IPC below the Core Runtime and above applications. Phase 13 already defines
`ucr.v1.IntegrationService` in protobuf and implements the transport-neutral `IntegrationIngress` in
Core, but there was no concrete gRPC binding. A binding must not become a second authentication,
authorization, quota, audit, command, storage, or error-semantics owner.

The public protobuf service already contains eleven RPCs. Implementing a transport adapter must not
pretend that every RPC is production-ready merely because generated Tonic traits expose every method.

## Decision

Add a separate workspace crate, `ucr-api-grpc`, outside `ucr-core`. It compiles the checked-in
`proto/ucr/v1/*.proto` contract with pinned Tonic/Prost versions and a build-time vendored `protoc`.
Generated Rust types are a mapping of the public contract, never a normative replacement for `.proto`.

The first concrete binding implements only `IntegrationService.SubmitCommand`. It decodes the public
protobuf `CommandEnvelope`, presents the exact command scope to the existing `IntegrationIngress`,
and delegates authentication, quota consumption, append-only admission audit, permission evaluation,
canonical validation/idempotency and durable acceptance to the existing Core owners.

Service Principal credentials remain binding metadata. The experimental gRPC binding uses two binary
metadata fields:

- `ucr-service-credential-id-bin` for exact `ServiceCredentialId` wire bytes;
- `ucr-service-credential-secret-bin` for the 32-byte credential secret.

Both are marked sensitive by the reference client helper. Neither field is added to protobuf request
messages, Commands, Events, extensions, logs, or storage. Malformed/missing credential metadata maps
to canonical `UNAUTHENTICATED` without inventing a gRPC-specific identity model.

Structurally incomplete decoded protobuf Commands map to canonical `INVALID_ARGUMENT`. After decoding,
all normal UCR failures are returned through the existing `IntegrationCommandResponse.error` envelope.
The binding does not remap canonical authorization, quota, conflict, storage, or retry semantics into a
second status vocabulary. gRPC `UNIMPLEMENTED` is reserved for the ten service methods that this slice
deliberately has not bound yet; transport/protobuf failures may still be represented by normal gRPC
transport status before application semantics exist.

The generated server is configured with a bounded decode budget derived from the complete `IntegrationCommandRequest`: canonical Command payload, IDs, scope, command type, correlation/idempotency, schema version, maximum extension count/name/payload budgets, and protobuf tag/length-prefix upper bounds. No adapter-specific guessed envelope allowance is used. This avoids Tonic's smaller default silently narrowing the UCR Command contract while still rejecting unbounded request bodies.

The reference evidence uses plaintext HTTP/2 only on an ephemeral loopback listener. This is a test
harness for actual gRPC framing/interoperability, not a production listener, TLS policy, public edge,
Internet Transport implementation, anonymous abuse-control layer, or deployment recommendation.

## Consequences

- Core remains independent of Tonic, Hyper, Tokio and generated protobuf Rust code.
- There is one Service Principal security gate and one Command durable owner.
- Binary metadata preserves exact credential-ID bytes and keeps the secret outside canonical bodies.
- External Rust clients can use generated Tonic types without making Rust the protocol definition.
- The checked-in public protobuf remains source-of-contract; build output is disposable.
- Other Integration RPCs fail explicitly with `UNIMPLEMENTED` until each adapter is implemented and
  tested against its existing Core owner.
- No SQLite schema, permission vocabulary, audit schema, Command model, or protobuf field changes are
  required by this binding.

## Required evidence

The workspace must prove that:

1. vendored `protoc` can generate client/server bindings without a system compiler dependency;
2. handwritten adapter code passes the normal workspace Clippy policy while lint exemptions are
   scoped only to generated protobuf code;
3. binary credential metadata round-trips exact bytes and is marked sensitive;
4. a real loopback gRPC client/server accepts one Command and deduplicates its retry through the
   existing Memory durable owner;
5. bad credentials return canonical `UNAUTHENTICATED` and a later correct retry of the same Command is
   still `ACCEPTED`, proving no ghost acceptance;
6. a correctly authenticated caller without `ucr.command.accept` receives canonical `PERMISSION_DENIED`,
   and granting that permission makes the same CommandId retry `ACCEPTED` rather than `DUPLICATE`;
7. the configured decode budget contains the encoded size of a maximum canonical Command, including all
   bounded extensions, while a real 5 MiB request proves Tonic's smaller default is not reintroduced;
8. a structurally malformed request returns canonical `INVALID_ARGUMENT`;
9. an unbound Integration RPC returns gRPC `UNIMPLEMENTED` rather than fabricated behavior;
10. RustSec, debug/release workspace tests, public protobuf compilation and existing fuzz/security gates
   remain green.

## Non-claims

This ADR does not implement the remaining ten gRPC methods, HTTP API, local IPC, SDK language packages,
production TLS/mTLS, public listener configuration, remote-peer authentication, edge throttling,
observability, load balancing, deployment manifests, Phase-14 Event API, Phase-15 Internet Transport,
routing, delivery, Attachment transfer, Calls, or provider bridges.
