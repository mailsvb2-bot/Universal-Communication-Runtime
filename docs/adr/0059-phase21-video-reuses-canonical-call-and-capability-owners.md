# ADR-0059: Phase 21 Video reuses canonical Call and capability owners

Status: Accepted

## Context

The Canon requires 1:1/group video, screen share and media renegotiation while keeping `CallSession` transport-independent. Phase 20 already established the realtime Audio pattern over canonical Call/Group/authorization/capability owners. Phase 21 must add real video without creating a second call, membership, negotiation, transport, security or persistence brain, and must not silently implement Phase 22–24.

## Decision

Add `ucr-video` as a Prepared reference layer. `VideoStreamDescriptor` and `EncodedVideoFrame` bind exact tenant/call/source/stream plus canonical negotiation ref/generation. `VideoNegotiationResolver` is read-only: it resolves the existing Call reference and returns the canonical negotiation result, selected `VideoCodecConfig`, and exact negotiated participant set. It does not negotiate or persist media state.

Require `Active` signalling, exact `Accepted` subject/source membership, `ucr.call.video.send` / `ucr.call.video.receive`, current local video/codec/source capabilities, exact negotiated video/codec/source capabilities, exact selected codec config, and exact current Accepted participant-set equality before every encode/decode. Unknown critical negotiation/capability extensions fail closed.

Keep camera/screen-share as stream source semantics, not codec semantics. Screen share additionally requires `ucr.media.video.screen_share` so generic camera agreement cannot authorize it implicitly.

Use H.264 through `openh264` 0.9.8 as the real Prepared reference codec. Configure the safe Rust wrapper for Baseline, Level 4.0 and realtime usage. Canonical configuration enforces the Level-4.0 coded-frame and macroblocks/second ceilings rather than accepting frame rate independently from resolution. Preflight H.264 SPS in safe Rust through `h264-reader` 0.8.0 before native decode and require both the cropped display dimensions and uncropped coded macroblock canvas to match the negotiated configuration; frame cropping cannot conceal a larger allocation surface. Commit SPS-validation state only after a successfully decoded frame. Any rejected native decode/no-frame/dimension result reconstructs the decoder and clears parameter-set validation before subsequent input. The wrapper and OpenH264 core report BSD-2-Clause licensing. RFC 7742 informs the 320x240/20fps reference default and interoperability direction, but Phase 21 does not claim WebRTC conformance, VP8 support, SDP or RTP/SRTP.

No SQLite migration is introduced; schema remains v22. No realtime network service is added. Public `video.proto` defines media shape only.

## Consequences

The runtime can now perform real camera/screen RGB8 -> H.264 encode and H.264 -> RGB8 decode under canonical Call authority, including direct/group participant changes and renegotiation revocation. Rejected decoder input reconstructs decoder state, and an encoded frame rejected for the 2 MiB bound reconstructs encoder state before any later accepted frame, so discarded media cannot become an implicit codec dependency. Safe-Rust coded-canvas validation and fail-closed decoder reconstruction prevent rejected H.264 input from expanding the native allocation boundary or leaking receiver validation state into later frames. Native C/C++ is isolated inside the existing codec library/binding dependency; UCR Domain/Core stays Rust and the new crate forbids unsafe code.

The implementation deliberately does not own adaptive bitrate, transport selection, E2EE keys/replay, SFU/conference topology, OS capture, recording or WebRTC session machinery. Those remain Phase 22+ concerns.

## Rejected alternatives

- A `VideoCall` / `VideoStore` aggregate: duplicates canonical Call ownership.
- Treating screen share as just another codec profile: confuses capture/source authority with codec parameters.
- Sending raw RGB over the wire: unbounded/inefficient and not a real video codec path.
- Routing video frames through durable Message delivery: mixes realtime and eventual communication.
- Adding WebRTC/ICE/RTP/SRTP now: prematurely owns Phase 22/24 concerns and a second session/transport brain.
- Calling encoded H.264 "encrypted": compression is not E2EE.
