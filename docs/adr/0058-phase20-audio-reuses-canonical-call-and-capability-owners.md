# ADR 0058: Phase 20 Audio reuses canonical Call, Principal, Group, authorization and Capability owners

- Status: Accepted
- Scope: Phase 20 Prepared/reference Audio

## Context

Phase 19 established the durable, transport-independent `CallSession` signalling authority. The Canon makes Phase 20 Audio a separate step before Video, E2EE Media, Adaptive Media and Transport Orchestration. Audio therefore needs a real codec/data model without turning signalling into media evidence or creating a second Call/Group/Identity/routing brain.

The Canon also requires a codec strategy before media production and permits C/C++ for established codecs/media libraries when justified. Interoperability with WebRTC-class endpoints makes Opus the appropriate mandatory audio codec; RFC 7874 requires WebRTC endpoints to implement Opus, while the `opusic-sys` package declares BSD-3-Clause and the vendored libopus COPYING grants permissive source/binary redistribution terms. The Rust `opus` binding is MIT/Apache-2.0 and keeps unsafe FFI outside UCR-owned Rust code.

## Decision

Add one capability-ID based `AudioCodecConfig`, ephemeral `AudioStreamDescriptor`, and bounded `EncodedAudioFrame` to the canonical language-independent media model. Phase 20 advertises `ucr.media.audio` and `ucr.media.audio.opus` at Prepared maturity. The mandatory interoperable profile is Opus at 48 kHz; the reference accepts Opus-native 8/12/16/24/48 kHz sample rates, mono/stereo, and 2.5/5/10/20/40/60 ms one-frame packets.

`ucr-audio` is a thin Prepared reference layer. It performs real libopus encode/decode but owns no durable state. Every encode/decode rechecks exact Call participant authority, subject acceptance, source acceptance, Active signalling state, negotiation generation, and the protocol-owned `ucr.call.audio.send` or `ucr.call.audio.receive` permission. Group Calls therefore continue to use the Group authority already composed by `CallStore`.

Audio streams use a typed offline-capable `AudioStreamId` and stream-local sequence/media timestamps. Receivers reject duplicate/non-increasing sequence values, but this is not presented as cryptographic replay protection.

No SQLite migration is added. Realtime Audio state is ephemeral and the existing durable `CallSession` remains the state/authority owner. `audio.proto` defines the public wire shape; Phase 20 does not invent a gRPC media transport or reuse durable Message delivery as a media data plane.

## Security and privacy impact

- Exact TenantScope and full PrincipalRef equality are required.
- Permission and accepted-participant/source authority are rechecked per frame, so an already-open codec object cannot outlive permission, Call, or Group authority. Invited/ringing participants cannot receive active group media before acceptance.
- Media renegotiation invalidates stale stream generations before another frame is encoded/decoded. Unknown critical extensions on required Phase-20 audio capabilities fail closed.
- Encoded frame Debug output redacts payload bytes.
- Encoded Opus is not claimed to be ciphertext. E2EE media/key lifecycle/replay protection remain Phase 22.
- No recording, hidden persistence, telemetry plaintext, or new media-history store is introduced.

## Compatibility and migration

Phase 19 SQLite v22 remains unchanged. Existing Calls require no migration. Future codecs are added through canonical capability identifiers and negotiation rather than new Call identities or forks of the Audio model.

## Rejected alternatives

1. **Put PCM/Opus state inside CallSession.** Rejected because durable signalling would become a media engine and restart state would be confused with realtime codec state.
2. **Create an AudioCall/AudioParticipant store.** Rejected as a second Call/Group authority brain.
3. **Send raw PCM.** Rejected as an unsuitable mandatory interoperable realtime format and an unbounded bandwidth choice.
4. **Define video/E2EE/adaptation now.** Rejected because the Canon assigns them to Phases 21–23.
5. **Treat encoded Opus as encrypted media.** Rejected because compression is not confidentiality and would silently violate the security boundary.
6. **Use durable Message/Delivery as the audio packet path.** Rejected because realtime Call media and durable VoiceMessage semantics are explicitly distinct.
