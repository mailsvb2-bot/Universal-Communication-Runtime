# Phase 23 Adaptive Media

## Scope

Phase 23 adds a Prepared/reference media adaptation policy above the existing Audio, Video, Call,
Capability and E2EE owners. It consumes ephemeral resource/network observations and produces bounded
media targets. It does not select a route, migrate a transport, persist telemetry, own Call state,
or create a second codec/security implementation.

The Canon-required observation set is represented explicitly: estimated bandwidth, packet loss,
jitter, RTT, CPU utilization, optional GPU utilization, battery state, external-power state and
thermal state. Percentages/loss/latency/bandwidth are bounded before policy evaluation.

## Graceful degradation

The reference realtime ladder is:

`1080p -> 720p -> 480p -> low-FPS video -> audio -> low-bitrate audio`.

If no realtime rung remains sustainable, the result is `EventualFallbackRequired` with the Canon
continuity order `VoiceMessage -> Text -> StoreAndForward`. Phase 23 only returns that boundary;
Voice Message, Text delivery and Store-and-Forward execution remain with their existing/future
Message/Delivery phases, including Phase 27 for Store-and-Forward.

Reference H.264 targets are 1920x1080@30/4 Mbps, 1280x720@30/2 Mbps,
854x480@30/1 Mbps and 640x360@12/384 kbps. Every point is revalidated through the existing Phase-21
H.264 Level-4.0 contract. Opus targets are 48 kbps and 16 kbps; the existing Phase-20 sender exposes
a bounded live bitrate control without changing the Audio wire shape.

## Reference policy and hysteresis

The checked-in thresholds are deterministic Prepared tuning, not a universal production claim.
Each Canon signal independently imposes a maximum quality ceiling; the worst ceiling wins.
Degradation normally requires two consecutive matching samples. Recovery requires four consecutive
samples and climbs only one rung at a time. Critical thermal pressure and loss of every sustainable
realtime rung degrade immediately. A contradictory sample resets pending hysteresis evidence.

## Security invariants

Adaptive Media has no API that converts protected media to plaintext and does not mutate the
Phase-22 E2EE context. Quality may degrade automatically; the negotiated security boundary does not.
Any future policy-permitted E2EE-to-plaintext transition must be an explicit security-policy action
outside this adaptation engine.

## Phase boundary

Phase 23 does not inspect interface availability, cost, privacy, recipient reachability, route
health or transport candidates and does not invoke `TransportProvider`. Those are Transport
Orchestrator concerns beginning in Phase 24. Automatic failover remains Phase 25. Store-and-Forward
execution remains Phase 27. Phase 29 provides Prepared RFC-9420/OpenMLS-backed group-media E2EE and encrypted SFU fan-out; Phase 30 now composes that foundation into bounded Conference coordination with selective recipient-owned subscriptions.

No SQLite migration is introduced; schema remains v22. Adaptive controller state is ephemeral.
