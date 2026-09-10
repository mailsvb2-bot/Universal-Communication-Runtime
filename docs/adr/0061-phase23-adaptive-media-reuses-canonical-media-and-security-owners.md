# ADR-0061: Phase 23 Adaptive Media reuses canonical media and security owners

- Status: Accepted
- Scope: Phase 23 Prepared/reference Adaptive Media

## Context

The Canon requires the Media Engine to consider bandwidth, packet loss, jitter, RTT, CPU, GPU,
battery and thermal state, and gives a graceful degradation example from 1080p through lower video,
audio, low-bitrate audio, Voice Message, Text and Store-and-Forward. It separately forbids silent
security degradation such as E2EE to plaintext. Phase 24 is the distinct Transport Orchestrator.

## Decision

Add an ephemeral `ucr-media-adaptive` controller and language-independent telemetry/decision model.
The reference policy validates every observation, derives a worst-signal quality ceiling, uses
bounded hysteresis, emits only Phase-21-valid H.264 targets and Phase-20-compatible Opus bitrate
targets, and stops at an explicit deferred-continuity boundary when realtime is no longer viable.

Video target changes must pass through the existing Call media-renegotiation path before a new
`H264VideoSender` is opened. Low-bitrate Opus may use the existing live encoder CTL because bitrate
changes do not redefine the negotiated Opus codec or wire envelope. The adaptive owner never gains
Call authority, transport routing, delivery persistence, crypto keys, or plaintext fallback control.

The eventual continuity list is advisory only. It preserves Canon order but does not implement
Voice Message/Text/Store-and-Forward execution ahead of their owners/phases.

No SQLite migration is introduced; schema remains v22.

## Rejected alternatives

1. Put adaptation fields into `CallSession`: rejected because signalling would become a media-policy brain.
2. Mutate H.264 dimensions/FPS inside an open sender: rejected because it bypasses exact negotiated codec binding.
3. Let adaptation pick Internet/LAN/Relay: rejected because Phase 24 owns route/transport orchestration.
4. Treat E2EE removal as a quality rung: rejected because the Canon forbids silent security degradation.
5. Implement Voice Message/Text/Store-and-Forward effects here: rejected as a second Message/Delivery brain.
6. Persist raw telemetry: rejected because Phase 23 needs ephemeral control state, not a new analytics store.

## Evidence

Protocol tests prove all eight Canon signal families can independently lower quality and every
reference video profile remains valid under the existing H.264 contract. Controller tests prove
fast degradation, slower one-rung recovery, anti-flap behavior, immediate critical fallback, and
the exact deferred-continuity order. Audio integration tests exercise real Opus 48 kbps -> 16 kbps
live adaptation without changing stream identity. Architecture/fuzz gates lock the phase boundary.
