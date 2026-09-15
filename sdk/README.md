# UCR Public SDKs — Phase 39

This directory contains Prepared language surfaces for the single `ucr.v1` public contract.
The canonical schemas stay in `proto/ucr/v1`; generated language files are derivative build output.

The five required language surfaces are Rust, Python, TypeScript, Kotlin and Swift.
Rust has the compiled reference client in `crates/ucr-sdk`.
The other language directories define the same code-generation boundary and exact credential helper.

All SDKs use binary gRPC metadata keys `ucr-service-credential-id-bin` and
`ucr-service-credential-secret-bin`. Credential secrets must be redacted from diagnostics.

No SDK owns canonical Identity, Conversation, Message, Delivery, Event, policy, routing,
permission, offline queue or provider-acceptance logic. No SDK has a direct storage API.

There is no hidden automatic application retry. A caller explicitly decides whether a
canonical operation is safe to retry. Event cursor bytes are opaque and must round-trip unchanged.

`contract.json` is a machine-readable release guard for these common Phase 39 boundaries.
Full cross-language conformance remains Phase 41; registry publication/signing remains later hardening.
