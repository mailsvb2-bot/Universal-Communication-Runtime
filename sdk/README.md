# UCR Public SDKs — Phase 39 + Phase 41 conformance

This directory contains Prepared language surfaces for the single `ucr.v1` public contract.
The canonical schemas stay in `proto/ucr/v1`; generated language files are derivative build output.

The five required language surfaces are Rust, Python, TypeScript, Kotlin and Swift.
Rust has the compiled reference client in `crates/ucr-sdk`.
The other language directories define the same code-generation boundary and exact credential helper.
`UniversalConferenceService` is part of that Service Principal SDK contract; `RealtimeService` remains a separate participant-session boundary authenticated by join/session credentials.

All SDKs use binary gRPC metadata keys `ucr-service-credential-id-bin` and
`ucr-service-credential-secret-bin`. Credential secrets must be redacted from diagnostics.

No SDK owns canonical Identity, Conversation, Message, Delivery, Event, policy, routing,
permission, offline queue or provider-acceptance logic. No SDK has a direct storage API.

There is no hidden automatic application retry. A caller explicitly decides whether a
canonical operation is safe to retry. Event cursor bytes are opaque and must round-trip unchanged.

`contract.json` is the machine-readable Phase-39 semantic guard for these common boundaries.
`sdk/conformance/matrix.json` is the Phase-41 fail-closed SDK conformance matrix for auth,
commands, events, retries, permissions, version negotiation, errors and idempotency.

Phase 41 executes host probes against the actual Service Credential helper in all five required
languages. The Rust reference SDK additionally carries runtime-binding evidence. These are
Prepared semantic conformance claims, not registry/package/supply-chain or Production certification.

Registry publication, package signing and broader supply-chain hardening remain Phase 44 work.
