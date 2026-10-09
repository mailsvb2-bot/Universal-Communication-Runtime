# UCR — QUALITY FIRST / INVISIBLE ADAPTIVE MEDIA
**Status:** staged implementation in progress. The quality-first selector and browser endpoint control are experimental integration foundations, NOT a completed automatic media transport / 1000-participant system.  
**Date:** 2026-10-09  
**Source of truth:** existing canonical UCR owners and production journeys.  
**Important:** This branch is a **reminder/vision branch**. Do not merge it wholesale into main or create a parallel runtime. Plan staged changes against the real production branch after RT0 is demonstrably working.

## Implemented groundwork on this branch (not a production claim)

- The existing Phase-23 `ucr-media-adaptive` module now selects bounded quality layers independently for each viewport/viewer. It never takes a room label or a participant threshold as input, never invents a missing Full HD layer, and does not bypass canonical subscription authorization.
- The reference browser no longer calls WebRTC/ICE reconnect merely in response to a quality-profile change. It validates the server's adaptive target and offers it only to the endpoint-owned optional `applyAdaptiveMediaDecision` callback, without changing encrypted media or grants itself.
- The TypeScript endpoint adapter contract exposes the optional quality and observed-telemetry hooks; conformance tests cover hook validation and the no-ICE-restart invariant.
- **Integration limitations:** a deployed codec adapter must implement those hooks; the SFU must connect authorized subscriptions to actual advertised simulcast/SVC layers; E2EE epoch-aware transport switching, native codec negotiation, and large-scale edge fan-out are NOT implemented by this groundwork.
- This branch is not a second media/crypto owner. No 15-person cutoff, implicit publication revocation, or WebTransport/CDN claim is introduced.

## The one product promise
**Quality. Quality. Quality. Simplicity.** A participant opens the invitation and sees a sharp, stable, fluid picture and hears intelligible, low-delay sound. The infrastructure may change routes, select codecs and layers, optimize rendering and fan-out, but these choices must remain invisible unless user action, permissions or policy demand otherwise.

*Aim to deliver at least 1920×1080 effective source/video quality to a viewer when source resolution, device decode/display, connection, permissions and available throughput allow it.* 1080p is the **premium operating target** and quality-regression alert threshold, NOT a mathematically guaranteed floor in a failed network, a 720p webcam or tiny preview tile. Never fake Full HD by upscaling poor source and labeling it 1080p. Prefer preserving useful quality and intelligible audio during impairment and restore actual 1080p quickly. For document/screen sharing, sharp text may matter more than nominal 1080p/30fps.

The user-facing UI must **not expose internal architecture**: no labels like “webinar transport”, “conference transport”, “WebTransport”, “SVC”, “Edge”, “CDN”, “SFU”. Role controls (host/speaker/viewer and approval to speak) remain meaningful product permissions, not switches for transports. No automatic muting or revoking publication just because a participant threshold is crossed.

## Single system, not second brain
- Rust/Tokio: authoritative signaling, conference admission, role grants, membership, negotiation/relay selection, authorization and SFU.
- Endpoint Rust/MLS: sole cryptographic state owner, changes of epoch on joins/leaves/revocations, end-to-end key governance.
- Browser native WebRTC: capture/playback, hardware codecs where available, congestion control, jitter and RTP.
- Worker + Encoded Transforms: SFrame E2EE of **encoded** media; never transmit plaintext media upon worker/crypto failure.
- Rust SFU: forward ciphertext, authenticate/authorize subscriptions, manage RTP/RTCP, layers and congestion without content decode in strict E2EE mode.
- Viewer transports: interchangeable only through **negotiated secure capabilities**, not room labels. WebRTC RTP primary. WebTransport/HTTP3 and edge fan-out are future validated adapters, not assumed automatically E2EE compatible.
- Recording is a separate explicitly consented flow, endpoint-side plaintext processing, recording-specific keys, verified containers, chunk integrity and resumable manifest; server stores ciphertext only where strict E2EE is promised.
- Invite fragment contains signed scoped admission material (never raw sole master media key); clear from location with history.replaceState after reading/validation. Neither URL-clearing nor worker termination promises physical RAM erasure or perfect anonymity.

## Transport selection: quality- and resource-driven, not “webinar” vs “conference”
Selection happens per subscriber and publishing stream. Evaluate each candidate path against authorization and E2EE invariants first, then quality and resource economics.

Inputs (validated, not trusted blindly):
- Original source resolution/fps, screen text content type, active track, codec offer/answer support, encode/decode hardware availability, expected power/thermal state.
- Available downlink/uplink bandwidth, RTT, jitter, loss and trend, congestion; receive FPS and dropped/late frames.
- Effective displayed size, viewer full-screen/pinned status, visible tiles, viewport/device pixel ratio.
- Subscribers and egress fan-out, cloud/edge regional routing, per-node CPU and memory, TURN usage, service budget, geographic latency.
- Local audio priority and voice quality, keyframe/SVC dependencies, MLS epoch readiness, stream subscription rights and active-speaker hints without server media decryption.
- Multiple E2EE-compatible transports may be capable, but transition must be seamless only after both paths are authenticated and tested.

Decisions:
1. Choose hardware-efficient AV1 if mutually supported with satisfactory encode latency/thermals; otherwise VP9, VP8 or H.264 according to actual support and measurements. No universal forced AV1.
2. Negotiate WebRTC SVC / simulcast where sender/SFU/decoder and codec header-extension intersection permits; selectively forward the **highest decodable layer** meeting target quality and bandwidth/viewport constraints, without breaking dependency structure. Keep source high-quality for viewers that can receive it; don't downscale every viewer because one has a bad link.
3. Forward only visible/pinned feeds at high resolution and preferred frame rate. Idle, hidden, or thumbnail feeds receive appropriately smaller layers or no video when allowed; keep audio responsive. A pinned main 1080p feed is the priority.
4. Offload fan-out to regional/edge nodes **only if they can forward end-to-end ciphertext and preserve authorization** and proven network/CPU/egress cost improves. No invisible downgrade to provider-managed plaintext ingest/transcode.
5. Change transport only through explicit negotiated media-path generation: prepare new encrypted path, confirm decoder readiness/keyframe/MLS binding, switch atomically, retire old path; no duplicate media publishers, replay, key reuse or plaintext gaps.
6. Use client/server backpressure: bounded queues, zero or limited raw frame caches, no unnecessary copying, no server mixing/transcoding in strict E2EE mode. Avoid per-frame authorization RPC and per-packet persistent writes.
7. Rate limit adaptation; use hysteresis, minimum dwell time, and headroom to prevent continuous quality/transport oscillation. Recover 1080p rapidly when conditions improve, without harming audio.

## Quality budgets / objective acceptance
Instrument p50/p95/p99:
- **True full-HD ratio**: wall-clock percent of time main displayed feed receives and decodes >=1920x1080 source-quality video when all prerequisites are fulfilled. Distinguish source pixel dimensions, encoded dimensions, decoded dimensions and actual displayed resolution.
- Time-to-first-audio and first-decrypted-video frame from real invite acceptance.
- Actual played fps, decode/render dropped frames, frame freeze events and durations; media end-to-end glass-to-glass and voice mouth-to-ear latency.
- Audio gaps, jitter, concealment and loss; recovery after ICE restart, device swap, permission revocation and MLS epoch change.
- Sender/receiver CPU, GPU pressure (when exposed), memory, thermal/battery cost, bandwidth, server CPU/GB egress, TURN/edge egress and **cost per viewer-hour**.
- E2EE failure, unauthorized publishing/receiving, stale epochs, plaintext path count (must be zero).
- Accessibility and low-end Android/iOS browser support where applicable.

Test matrix (not just green CI): real Alice/Bob devices and browsers; 2/5/15/30/100/1000 subscribers; 1/5 simultaneous speakers; low-end phone, battery saver, hardware-codec incompatibility, 720p source, screen share, 1080p source, high-DPI full-screen, TURN-only, Wi-Fi->mobile handover, packet loss, limited uplink, high RTT, cold start, old generation/key revocation, recording failure. Simulate only as supplement to physical e2e.

**Do not declare a guaranteed 1080p floor** across all network/device states. Product UI should accurately show “HD / Full HD available”, not claim a resolution the receiver never received.

## Progressive technical roadmap and gates
**Gate 0 — first working call (P0):** finish one canonical Rust/MLS/SFrame/Encoded-Transforms/Rust-SFU browser path, two real devices, encrypted audio+video, deny on crypto failure, interruption/reconnect, authorized join/leave. Do not distract RT0 by implementing CDN/WebTransport/P2P before this gate.

**Gate 1 — quality-led browser media (P1):** test negotiated AV1/VP9/VP8/H.264, hardware encode/decode, layered simulcast/SVC, dependency descriptors, high-quality main video, audio protection, getStats instrumentation, visibility-aware track decoding, min quality dwell and fast recovery. Quality decisions are per viewer, not based on type/name of room.

**Gate 2 — adaptive ciphertext forwarding (P2):** SFU selective subscriptions and sender/receiver layer switching, regional distribution with consistent admission, backpressure, bounded buffers, QoS regression tests, protection from replays and unexpected duplicate publishers.

**Gate 3 — high-fan-out edge media (P3):** independent edge ciphertext relay proof; compare WebRTC SFU meshes vs QUIC/WebTransport custom encrypted datagrams vs compatible managed edge offerings with measured 1080p QoE, latency, cost and mobile performance. Keep E2EE invariant; require actual interoperability before shipping. External CDN MUST NOT acquire plaintext or long-term MLS keys. No assumption that single 2GB VPS can fan out 1000 viewers.

**Gate 4 — recording (P4):** opt-in separate privilege, local composition on authorized endpoint, MediaRecorder/WebCodecs and supported container checks, encrypted independently keyed segments, ordering/hash manifest, crash recovery, transparent access policy and retention.

**Gate 5 — privacy and PQ readiness (P5):** optional relay-only and metadata minimization, optional padding only against measured threat model, standards-compatible hybrid post-quantum MLS evolution (including authentication implications), no parallel ECDH key owner or advertising absolute anonymity. Use zeroize for owned secret buffers where possible; don't promise physical RAM wipe.

## Additional technologies worth evaluating (NOT mandates)
- WebRTC AV1/VP9 spatial+temporal SVC, simulcast, dependency descriptor, RTX/NACK/PLI/TWCC, packet pacing and bandwidth estimation.
- WebRTC Encoded Transforms, SFrame (RFC 9605), IETF MLS RFC 9420, browser hardware MediaCapabilities, WebCodecs feature detection.
- Screen content specialization: low-motion high-clarity encode; source-appropriate sharpness and keyframe cadence.
- Jitter-buffer tuning, audio Opus FEC/DTX where suitable, CPU/thermal-aware encoding, battery-aware tile subscription without arbitrarily lowering the pinned video.
- Dedicated Worker and AudioWorklet for *necessary* browser processing; transfer instead of copying buffers when permitted; pooled bounded buffers. Avoid many Workers or expensive crypto boundary crossings for every frame.
- Adaptive edge routing/anycast/TURN based on measured path; WebTransport datagram evaluation for receive-only encrypted fanout, not assumed faster than native WebRTC.
- Stateless short-lived capability tickets for edge subscriptions; authoritative Rust call control and locally verified revocation; avoid broadcasting identity details.
- Efficient ABR state machine with hysteresis, fast upshift on sustained bandwidth recovery, guarded downshift, video-only degradation ahead of speech.
- Region-level egress price and fanout optimizer; cloud provider comparison, not hardcoding one vendor.
- Optional client-assisted P2P fan-out only for opt-in capable devices with explicit bandwidth/privacy budgets, never required for availability.

## Reference standards and cost assumptions (verify when implementing)
- SFrame RFC 9605: https://www.rfc-editor.org/rfc/rfc9605.html
- MLS RFC 9420: https://www.rfc-editor.org/rfc/rfc9420.html
- W3C WebRTC SVC (Working Draft, Sep 2026): https://www.w3.org/TR/webrtc-svc/
- Cloudflare Realtime pricing example (as of Sep 2026): https://developers.cloudflare.com/realtime/sfu/platform/pricing/
  Such providers bill for egress; “free compute” is not free distribution. Do not assume a third-party SFU/CDN provides strict endpoint E2EE compatibility.

## Non-negotiables
**Never hide unfinished work behind green checks.** All status claims require actual Alice→call signaling→canonical authority→MLS/SFrame encrypt→SFU/edge cipher-forward→Bob decrypt/play→quality/telemetry outcome. Never imply benchmark results that have not been measured.

**No second brain. No parallel cryptographic owner. No branch zoo.** This branch is a long-lived architecture reminder only. Implementation belongs in existing canonical owners and deliberately staged PRs; reconcile and retire redundant branches once integrated.

**User-facing product = SIMPLE + QUALITY.** Internal transport choices remain invisible, but accurate security state, microphone/camera permissions, meaningful participant controls, and exceptional connectivity errors remain clear.
