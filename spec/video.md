# Phase 21 Video

Status: **Prepared reference implementation**, not Production.

## Scope and canonical ownership

Phase 21 adds realtime video over the existing canonical `CallSession`. It creates no second Call, Group, Principal, authorization, capability-negotiation, routing, transport, or durable media owner. Every `VideoStreamDescriptor` is bound to exact `TenantScope`, `CallId`, source `PrincipalRef`, `VideoStreamId`, source kind, the canonical `media_negotiation_ref`, and the current media-negotiation generation.

Video uses the same authority rules as Phase-20 Audio: signalling must be `Active`; sender/receiver and stream source must be current `Accepted` participants; `ucr.call.video.send` / `ucr.call.video.receive`, local capabilities, canonical Call/Group authority, negotiation reference/generation, and exact negotiated participant set are re-checked before every frame operation. A newly accepted group participant therefore invalidates stale negotiated video evidence until a fresh `MediaRenegotiation` is installed.

## Camera and screen sharing

`VideoSourceKind` distinguishes `Camera` from `ScreenShare`; source type is stream metadata, not a codec property. Camera requires negotiated/local `ucr.media.video` plus the selected codec capability. Screen sharing additionally requires `ucr.media.video.screen_share`. This prevents a peer from treating generic camera-video agreement as implicit screen-capture consent/capability.

Phase 21 supports the media shape for direct and group Call participants. It does not introduce an SFU, conference coordinator, mixer/compositor, fan-out topology, or large-group scaling policy; those are later phases.

## Codec strategy

The Prepared reference codec is H.264 through `openh264`/Cisco OpenH264, capability ID `ucr.media.video.h264`. The generic video capability is `ucr.media.video`; screen sharing is `ucr.media.video.screen_share`. All advertise `Prepared` maturity.

The bounded reference config supports even display dimensions from 16x16 through 1920x1080 and a fixed negotiated target bitrate from 64 kbit/s through 20 Mbit/s. Frame rate is additionally constrained by the fixed H.264 Level 4.0 profile: at most 245,760 coded macroblocks/second and 8,192 coded macroblocks/frame. Consequently 1920x1080 is represented by a 1920x1088 coded canvas and is accepted at 30 fps but rejected at 60 fps; lower resolutions may reach the independent 60 fps ceiling when the Level-4.0 macroblock-rate budget permits it. The RFC-7742 minimum decode shape (320x240 at 20 fps unless otherwise signalled) is used as the Phase-21 reference default. The implementation configures OpenH264 Baseline/Level 4.0 and a realtime camera/screen usage mode, but UCR does **not** claim WebRTC/RFC-7742 conformance: VP8, SDP, RTP payload mapping, ICE and the WebRTC data plane are not Phase-21 claims.

`target_bitrate_bps` is a negotiated fixed encoder parameter in this phase. Dynamic bitrate/resolution/frame-rate adaptation based on loss, jitter, RTT, CPU/GPU, battery or thermal state belongs to Phase 23 Adaptive Media.

## Realtime frame semantics

The reference sender accepts one exact contiguous RGB8 frame, converts it to YUV420 through the codec library, encodes real H.264, and emits a bounded `EncodedVideoFrame`. Before native decode, the receiver parses any H.264 SPS in safe Rust and validates both the cropped display dimensions and the uncropped coded macroblock canvas against the exact negotiated Level-4.0 configuration. Cropping therefore cannot hide a larger native allocation surface. The first decodable stream must include a successfully validated SPS. This safe-Rust SPS boundary is included in the bounded fuzz-smoke matrix. Native decoder state is transactional at the frame boundary: SPS validation is committed only after successful frame decode, and any rejected native decode/no-frame/dimension result reconstructs the decoder and clears SPS validation so rejected input cannot authorize a later SPS-less frame. The receiver then re-checks decoded dimensions and returns owned RGB8 pixels. Encoded and decoded pixel payloads are redacted from `Debug` output.

Frames carry sequence, media timestamp, keyframe indication, and exact call/stream/source/negotiation binding. `keyframe` is sender metadata for scheduling/UI hints only; it is never authorization, security, negotiation, or replay evidence. Duplicate/non-increasing sequence suppression is realtime hygiene only, not cryptographic replay protection. Phase 22 owns media encryption, authenticated replay protection, key lifecycle and rotation.

The maximum single encoded reference frame is 2 MiB. Raw RGB length is derived from the already-bounded negotiated dimensions and checked before the native encoder wrapper is invoked.

## Public contract

`proto/ucr/v1/video.proto` defines the language-independent Video source/config/stream/frame/negotiation-binding shape. No `VideoService` is created. Phase 21 intentionally does not push realtime video through durable Message/Event APIs and does not invent the Phase-24 transport data plane.

## Native dependency and licensing boundary

The Rust reference uses `openh264` 0.9.8 with its source feature, which builds the OpenH264 codec library through the crate's native build path. The wrapper and OpenH264 core are BSD-2-Clause according to the crate metadata/documentation. Native codec code remains a media-library dependency; UCR domain/core logic stays safe Rust and `ucr-video` forbids unsafe code.

## Nonclaims

Phase 21 does **not** claim E2EE Media (Phase 22), Adaptive Media (Phase 23), Transport Orchestrator/failover (Phase 24+), RTP/SRTP/WebRTC compatibility, ICE/STUN/TURN, SFU/conferences, OS camera/display capture, GPU/hardware acceleration selection, production device permission UX, recording, background effects, echo/audio processing, provider-call bridges, or production listener/deployment hardening.

Encoded H.264 bytes are not automatically encrypted. Security must never silently downgrade a later protected profile to plaintext.
