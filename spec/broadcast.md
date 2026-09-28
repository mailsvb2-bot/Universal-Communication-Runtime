# Transcoding, Composition and Broadcast Providers

Status: **Prepared provider boundaries; no Production broadcast capability is advertised**.

Broadcast media processing is explicitly outside SFU authority. The SFU remains responsible only for
bounded realtime forwarding under the existing Conference/Call authorization model. It must not
become a compositor, transcoder, recorder, RTMP publisher, HLS/DASH packager, CDN credential store,
or broadcast lifecycle owner.

## Composition provider

The separate `CompositionProvider` accepts one already-authorized, bounded operation containing:
- exact Tenant scope and Call ID;
- an opaque idempotent operation ID;
- one of the required layouts: gallery, active speaker, or screen-with-speaker;
- bounded unique typed audio-stream IDs and video-stream IDs from the existing Call media model.

The request may be audio-only or audio+video; it may not be media-empty. Typed stream IDs prevent the
composition boundary from inventing a parallel source identifier namespace. The provider may process
the selected media, but the existing Call/media descriptors remain the source-of-truth for stream
identity and authorization.

The provider owns only media-processing side effects. It creates no canonical Conference roster,
Call state, participant authority, SFU routing state, or Recording lifecycle.

## Broadcast provider

The separate `BroadcastProvider` publishes one already-composed output to a bounded set of
destinations. The current provider contract supports RTMP, HLS, and DASH destination classes.

Canonical requests contain only opaque destination IDs and protocol kinds. A destination reference
may appear at most once in one publish operation, even if a caller tries to pair the same reference
with multiple protocol kinds. RTMP stream keys, signed CDN URLs, storage credentials and other
provider secrets are resolved behind the provider boundary and must not be persisted or logged
through canonical UCR request values.

## Capability contract

The current capability IDs are:
- `ucr.media.composition`;
- `ucr.broadcast.rtmp`;
- `ucr.broadcast.hls`;
- `ucr.broadcast.dash`.

All are **Prepared**. Merely compiling the provider boundary does not authorize a deployment to
advertise Production broadcast.

## Production evidence still required

A Production provider needs executable evidence for actual encode/transcode/composition behavior,
RTMP publishing, HLS/DASH packaging, destination authentication, bounded retry/backpressure,
credential redaction, reconnect/failure recovery, CDN integration where configured, load behavior,
and operator health. Those concerns must remain replaceable provider implementations rather than
being moved into the SFU or canonical Conference model.
