# Phase 39 — Public SDKs

## Status

Phase 39 defines **Prepared** public SDK surfaces for Rust, Python, TypeScript, Kotlin and Swift.
They are clients of the single versioned `ucr.v1` public contract; they are not alternate UCR runtimes.

## Canonical boundary

The checked-in protobuf contract under `proto/ucr/v1` remains the language-independent source of wire truth.
SDK code may provide transport setup, generated types/stubs, credential attachment and ergonomic call helpers.
The Service Principal SDK surface includes the business-neutral `UniversalConferenceService`; realtime participant-session authentication remains a separate join/session-token boundary rather than being reinterpreted as Service Principal authentication.
It must not own Identity, Conversation, Message, Delivery, Event, routing, policy, permission or retry semantics.

SDKs have no direct database API and no privileged path into `ucr-core` or a storage provider.
A consumer using an SDK has exactly the authority represented by its authenticated Service Principal.

## Authentication

Service Principal credentials are binding metadata, not protobuf payload fields.
Every SDK uses the exact binary gRPC metadata keys:

- `ucr-service-credential-id-bin`
- `ucr-service-credential-secret-bin`

Credential bytes are opaque. SDK diagnostics must redact the secret and must not promote the identifier into identity evidence.
## Calls and failures

Generated service methods preserve canonical request and response envelopes unchanged.
An SDK must not translate a canonical `ErrorEnvelope` into success or infer Delivery/Read from transport success.
Event cursors are opaque bytes and are never parsed or reconstructed by an SDK.

There is no hidden automatic application retry in Phase 39.
Callers may explicitly retry only according to canonical idempotency and provider-acceptance semantics.
Transport libraries may reconnect their channel, but reconnection alone never resubmits a UCR operation.

The Rust reference SDK is deliberately excluded from the internal Core workspace and is compiled/audited as an external-consumer package.
The Rust reference SDK raises its gRPC transport ceiling above the current canonical public message maxima.
That transport ceiling is not a new semantic payload limit; canonical protocol/server validation remains authoritative.

## Language surfaces

- Rust: generated client-only Tonic bindings plus the common credential helper.
- Python: canonical protobuf/gRPC code generation plus the common credential helper.
- TypeScript: canonical protobuf/gRPC code generation plus the common credential helper.
- Kotlin: canonical protobuf/gRPC code generation plus the common credential helper.
- Swift: canonical protobuf/gRPC code generation plus the common credential helper.

Generated wire code is derivative output. The checked-in `.proto` files, not generated language classes, define the contract.
## Compatibility and maturity

The package major follows the public protocol major. Stable SDK API cannot silently reinterpret stable protobuf fields.
Optional unknown protobuf fields/extensions remain forward-compatible according to the canonical protocol rules.
Unsupported critical extensions continue to fail through protocol negotiation rather than SDK guessing.

Phase 39 is Prepared source-distribution evidence, not a claim that registry publishing, mobile lifecycle integration,
production TLS discovery, package signing or long-term support policy is complete. Those require later release hardening.

Phase 41 owns the complete SDK conformance matrix for auth, commands, events, retries, permissions,
version negotiation, errors and idempotency. Phase 39 must nevertheless keep those semantics observable and unmodified.

## Required evidence

1. Rust client bindings compile from the checked-in public protobuf contract with server generation disabled.
2. Rust SDK dependencies contain no `ucr-core` or storage crate.
3. All five language surfaces use the same contract package and binary authentication metadata names.
4. Credential diagnostics redact secrets.
5. SDK documentation explicitly forbids hidden business/domain models and automatic application retry.
6. Repository guards require this specification, the Phase 39 ADR and every language surface.
