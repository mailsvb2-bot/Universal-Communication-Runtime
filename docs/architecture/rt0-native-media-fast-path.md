# RT0 native media fast path: implementation boundaries

## Production success criterion
Two distinct browsers complete the authenticated call journey: canonical admission,
endpoint MLS, sender encryption of encoded audio/video, SFU forwards ciphertext,
receiver verifies authorization and decrypts, browser plays audio/video. Measure
first audible frame, end-to-end delay, CPU, memory and relayed bytes under NAT/TURN.

## One pipeline contract; platform-specific execution
- Canonical Rust MLS/media bridge is the ONLY cryptographic owner.
- Canonical Call/Group/Device and grant/epoch state is the ONLY authorization owner.
- Native RTP media planning is a fail-closed admission contract for future
  RTCRtpScriptTransform integration, NOT an enabled native media pipeline.
- Browser WebRTC engine should own capture, codecs, congestion control, jitter
  buffer and rendering. Cryptography processes only encoded frames in Worker.
- Existing WebCodecs/DataChannel implementation remains a constrained E2EE
  alternative, not an unencrypted fallback or a second identity store.
- No new language is required: Rust/WASM on device, TypeScript control plane,
  native browser codecs and Rust SFU. Avoid raw video through WASM.

## Required implementation before native RTP activation
1. SFU supports ciphertext-only RTP forwarding and advertises capability through
   canonical signaling. Current browser explicitly rejects unexpected RTP tracks.
2. Install sender AND receiver encoded transforms before any packet flows.
   Missing transform aborts; never permit plaintext fallback.
3. Define interoperable encoded-frame encryption and canonical stream/epoch/replay
   validation. Preserve required codec headers. Test Opus, VP8/H.264/AV1.
4. Initialize Worker/WASM once, bound buffering and use transferable buffers.
   Do not cache raw audio/video.
5. Bind transport to authenticated Call/Group/device and MLS epoch, not just
   browser feature detection; reject expired or revoked participant grants.
6. Ensure native RTP and DataChannel are mutually exclusive per media session.
7. Test actual browsers, mobile and native adapters for interoperability.

## Lightweight runtime budgets
- No server-side decode/mix of normal E2EE calls.
- No unbounded buffers, waits, promises or frame allocations.
- Avoid per-packet IndexedDB writes, remote auth RPCs and UI-thread codecs.
- Prioritize audio and drop delayed video only at decode-safe boundaries.
- Measure p50/p95 time to first audio, mouth-to-ear latency, per-participant
  memory, SFU CPU per forwarded bitrate, network-change recovery and battery.

Passing CI does not establish a live protected call. Only an actual production
journey through two devices and real networks establishes readiness.
