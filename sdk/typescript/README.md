# TypeScript SDK surface

Generate TypeScript protobuf/gRPC clients from the repository `proto/ucr/v1` schema root.
`src/auth.ts` supplies exact binary metadata entries for the generated external-consumer clients.

The helper clones credential bytes, redacts diagnostics and owns no UCR domain, storage or retry semantics.
Generated code is derivative build output; canonical request/response envelopes remain defined by protobuf.

Phase 39 does not publish an npm artifact or select a permanent generator plugin; that is later release hardening.
