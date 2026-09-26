# TypeScript SDK surface

Generate TypeScript protobuf/gRPC clients from the repository `proto/ucr/v1` schema root.
`src/auth.ts` supplies exact binary Service Credential metadata entries for generated
external-consumer clients.

For `UniversalConferenceService`, callers may instead use the standard
`Authorization: Bearer <access-token>` metadata accepted by the public Conference ingress.
Do not send Bearer and Service Credential metadata together: mixed authentication schemes fail
closed. The REST projection of the same typed Conference contract is available under `/v1`;
`/v1/openapi.yaml` is the route description, not a second semantic contract.

The helper clones credential bytes, redacts diagnostics and owns no UCR domain, storage or retry semantics.
Generated code is derivative build output; canonical request/response envelopes remain defined by protobuf.

Phase 39 does not publish an npm artifact or select a permanent generator plugin; that is later release hardening.


## WebRTC endpoint E2EE transport

`src/webrtc_e2ee.ts` provides the bounded ordered DataChannel framing for already-encrypted
canonical media envelopes on `ucr.e2ee.media.v1`. `src/sfu_forward_wire.ts` mirrors the
protocol-owned `SfuForwardEnvelope` wire codec and is locked byte-for-byte against the Rust
implementation by the Conformance workflow. The decoder preserves legacy wire v1 compatibility
(`video` means camera there); the current wire v2 adds `headerVersion` plus authenticated
`videoSourceKind`, allowing `camera` and `screen_share` to remain distinct through the
ciphertext-only SFU path. Wire v1 is deliberately unable to claim `screen_share`. The WebRTC
transport owns only bounded chunking and reassembly; it owns no MLS keys, encryption/decryption,
Conference policy or SFU routing.
Applications connect it to their endpoint crypto adapter and keep all group-media key material on
the endpoint.

The reference browser keeps camera/microphone and display capture endpoint-only. An adapter started
by `window.ucrE2eeEndpoint.start(...)` receives `stream` (the backwards-compatible camera/mic
stream), `cameraStream`, optional `screenStream`, and `sendEnvelope`. Live screen-share
changes use an explicit `updateSources({stream, cameraStream, screenStream})` hook. If the browser
does not expose `getDisplayMedia` or the adapter does not expose `updateSources`, the reference
client keeps the Share screen control disabled rather than pretending screen media is published.
No captured track is attached to WebRTC RTP; the adapter remains responsible for producing
canonical endpoint-encrypted envelopes. A display-capture envelope must use the current v2 header
with `mediaKind: "video"` and `videoSourceKind: "screen_share"`; a legacy v1 video envelope is
camera-only and cannot assert screen-share authority. The reference browser stops display capture
locally before awaiting server-side Leave cleanup and also stops it if the encrypted media
DataChannel closes.

## Embeddable conference UI

`src/conference_embed.ts` adds the thin `mountConference(...)` browser helper required for
embedding the existing UCR join surface without introducing a second conference model.

- `mode: "iframe"` mounts the issued UCR join URL into a caller-owned container.
- `mode: "headless"` validates and returns the same join URL without creating DOM.
- join URLs must use HTTP(S) and retain the personal `#ucr_join` fragment issued by UCR.
- iframe mounts use a bounded permission surface for camera, microphone, display capture and
  fullscreen, a sandbox, and `no-referrer`.
- the helper owns no identity, conference lifecycle, authorization, media encryption, storage,
  routing or retry semantics.

Applications may wrap this primitive as a widget, component or full-page experience while keeping
all conference semantics in the public UCR contract.

