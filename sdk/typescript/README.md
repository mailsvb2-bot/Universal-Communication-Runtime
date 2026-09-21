# TypeScript SDK surface

Generate TypeScript protobuf/gRPC clients from the repository `proto/ucr/v1` schema root.
`src/auth.ts` supplies exact binary metadata entries for the generated external-consumer clients.

The helper clones credential bytes, redacts diagnostics and owns no UCR domain, storage or retry semantics.
Generated code is derivative build output; canonical request/response envelopes remain defined by protobuf.

Phase 39 does not publish an npm artifact or select a permanent generator plugin; that is later release hardening.


## WebRTC endpoint E2EE transport

`src/webrtc_e2ee.ts` provides the bounded ordered DataChannel framing for already-encrypted
canonical media envelopes on `ucr.e2ee.media.v1`. `src/sfu_forward_wire.ts` mirrors the
protocol-owned `SfuForwardEnvelope` wire v1 codec and is locked byte-for-byte against the Rust
implementation by the Conformance workflow. The WebRTC transport owns only bounded chunking and
reassembly; it owns no MLS keys, encryption/decryption, Conference policy or SFU routing.
Applications connect it to their endpoint crypto adapter and keep all group-media key material on
the endpoint.

The reference browser keeps camera/microphone and display capture endpoint-only. An adapter started
by `window.ucrE2eeEndpoint.start(...)` receives `stream` (the backwards-compatible camera/mic
stream), `cameraStream`, optional `screenStream`, and `sendEnvelope`. Live screen-share
changes use an explicit `updateSources({stream, cameraStream, screenStream})` hook. If the browser
does not expose `getDisplayMedia` or the adapter does not expose `updateSources`, the reference
client keeps the Share screen control disabled rather than pretending screen media is published.
No captured track is attached to WebRTC RTP; the adapter remains responsible for producing
canonical endpoint-encrypted envelopes. The reference browser stops display capture locally before
awaiting server-side Leave cleanup and also stops it if the encrypted media DataChannel closes.
