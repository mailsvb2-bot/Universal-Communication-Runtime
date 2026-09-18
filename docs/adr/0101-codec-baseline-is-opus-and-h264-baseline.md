# ADR 0101: Codec baseline is Opus and H.264 Baseline

Status: Accepted

## Context

The Canon requires mandatory audio/video codec baselines, fallback behavior, browser/hardware considerations and licensing implications before media Production.

## Decision

The UCR 1.0 reference media baseline is:

- audio: Opus for realtime audio;
- video: H.264 Baseline Profile, Level 4 for the current reference video path.

Codec selection remains capability-negotiated. Optional future codecs (for example AV1/VPx where implemented) are extensions, not alternate media brains.

There is no mandatory second video fallback codec in 1.0. If peers have no mutually supported allowed video codec, video is explicitly unavailable/degraded while compatible audio/text capabilities may continue. UCR must not silently downgrade security or invent a codec.

Hardware acceleration is capability data and may optimize an agreed codec but does not change protocol ownership. Distribution/deployment must satisfy the applicable codec implementation/patent/license obligations; this ADR does not grant third-party codec rights.

## Consequences

The implemented libopus/OpenH264 reference path has an explicit baseline. New codecs can be added by capability negotiation without changing Call/Conversation/Identity semantics.
