# Phase 20 Audio

Status: **Prepared reference implementation**, not Production.

## Scope and canonical ownership

Phase 20 adds realtime audio as an ephemeral media capability over the existing canonical `CallSession`. It does not create a second Call, Conversation, Group, Principal, authorization, transport, routing, or durable media owner. Every stream is bound to exact `TenantScope`, `CallId`, source `PrincipalRef`, `AudioStreamId`, the exact canonical `media_negotiation_ref`, and the current Call media-negotiation generation.

`CallSession` remains the authority owner. A sender or receiver must be an `Accepted` current participant, the stream source must also be an accepted current participant, and signalling must be `Active`. An invited/ringing participant cannot receive media merely because another participant already made the group Call active. The reference runtime re-checks these facts and `ucr.call.audio.send` / `ucr.call.audio.receive` permission before every encoded/decoded frame. Group-backed Calls therefore inherit the existing canonical Group-membership revocation boundary; Audio does not copy membership.

A media-renegotiation signal increments the existing Call media-negotiation generation and installs an opaque canonical `media_negotiation_ref`. Audio MUST NOT start when that reference is absent. The Audio layer resolves the exact reference through a read-only `AudioNegotiationResolver`, validates the canonical `NegotiationResult`, requires the negotiated `ucr.media.audio` and selected codec capability, requires the exact selected `AudioCodecConfig` to match the stream descriptor, and requires the resolver's exact `negotiated_participants` set to equal the Call's current `Accepted` participant set. The resolver does not perform negotiation and owns no parallel Call/media state. An open sender/receiver using an older reference/generation or a negotiation bound to a different Accepted participant set fails closed before processing another frame. Adding an invited participant alone does not invalidate media because the Accepted set is unchanged; once that participant accepts, existing media fails closed until a fresh `MediaRenegotiation` installs evidence bound to the new set. Participant removal and Group membership revocation likewise change/revoke media authority through the existing Call owner.

The reference runtime separately consumes the existing canonical `CapabilityDescriptor` vocabulary through a local availability adapter and re-checks both `ucr.media.audio` and the selected codec capability per frame. Local runtime capability loss therefore stops an already-open stream instead of assuming that a startup-time capability remains true forever. Local availability is never treated as proof of peer negotiation. Phase 20 understands no negotiation/capability extensions yet, so unknown critical extensions in the resolved negotiated result fail closed rather than being ignored.

## Codec strategy

The mandatory Phase-20 interoperable audio codec is **Opus** with capability ID `ucr.media.audio.opus`. The general Audio capability is `ucr.media.audio`. Both advertise `Prepared` maturity.

The reference profile uses 48 kHz as the mandatory interoperable sample rate and supports Opus rates 8/12/16/24/48 kHz, mono/stereo, and one-frame durations of 2.5/5/10/20/40/60 ms. One reference encoded frame is bounded to 1275 bytes. Codec configuration remains capability-ID based rather than a closed enum so future negotiated audio codecs/modalities do not require a new media model.

The Rust reference uses the maintained `opus` safe binding over libopus. libopus is a codec/media library, not UCR Domain Core. Building this crate therefore requires the normal native C/CMake toolchain used by that dependency.

## Realtime frame semantics

`EncodedAudioFrame` carries exact stream/call/source/negotiation-ref/generation binding, a stream-local sequence, media timestamp in samples, and encoded bytes. Debug output must never print encoded payload bytes. The reference sender generates monotonically increasing sequence/timestamps; the receiver rejects duplicate or non-increasing sequences before decode.

That duplicate suppression is realtime hygiene only. It is **not** a claim of cryptographic replay protection. Phase 22 owns E2EE Media and its cryptographic replay/key lifecycle semantics.

Voice messages remain durable Message + Attachment data. Phase-20 VoiceCall audio is realtime `CallSession` media and is not persisted as Message/Event history by this layer.

## Direct and group audio

The stream model is participant-based rather than hard-coded to 1:1, so private/public Group Call participants can each own independent audio streams while retaining the one canonical Group/Call authority. Phase 20 does not invent an SFU, mixer, conference coordinator, fan-out policy, or large-group topology; those belong to later SFU/Conference phases.

## Public contract

`proto/ucr/v1/audio.proto` is the language-independent Phase-20 media shape, including the read-only `AudioNegotiationBinding` that carries the exact referenced canonical `NegotiationResult`, selected codec configuration, and full negotiated `PrincipalRef` participant set. Rust structs/codecs are reference implementation mappings, not the protocol definition. Phase 20 intentionally does not define a unary gRPC media transport and does not smuggle realtime media through the durable Message transport. The future transport/orchestration layer consumes these canonical media frames.

## Nonclaims

Phase 20 does **not** claim Video (Phase 21), E2EE Media (Phase 22), Adaptive Media (Phase 23), Transport Orchestrator/failover (Phase 24+), ICE/STUN/TURN, RTP/SRTP/WebRTC data-plane compatibility, SFU/conferences, microphone/speaker OS integration, echo cancellation, noise suppression, recording, push ringing, provider-call bridges, or production listener/deployment hardening.

Encoded Opus bytes are not automatically encrypted. No network transport in Phase 20 may represent them as E2EE media. Security must not silently degrade from a later protected profile to plaintext.
