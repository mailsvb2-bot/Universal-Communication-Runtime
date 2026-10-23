import type {
  UcrEncodedMediaFrame,
  UcrMediaConsumer,
  UcrMediaProducer,
} from "./portable_endpoint_media.ts";
import type { SfuForwardEnvelopeWire } from "./sfu_forward_wire.ts";
import type { UcrEndpointMediaSources, UcrEndpointAdaptiveQualityV1, UcrVerifiedReceiveVideoStream } from "./endpoint_e2ee.ts";

/**
 * WebCodecs platform implementation. Opt-in: browsers without required APIs must
 * use a different producer/consumer; never send raw microphone/video plaintext.
 *
 * MediaStreamTrackProcessor supplies endpoint-only frames. WebCodecs outputs
 * codec payloads; the portable E2EE adapter seals them using canonical Rust/WASM.
 * Designed to be replaceable by native codecs on Android/iOS/desktop.
 */
// Aggregate-only observability: no media samples, participant identities or keys.
const ucrAudioCounters = {captured: 0, encoded: 0, received: 0, decoded: 0, scheduled: 0, dropped: 0, transportQueued: 0, inputPeak: 0, outputPeak: 0, playoutQueuedMs: 0, playoutJitterMs: 0, playoutRebases: 0};
// Count actual encoded and rendered video separately; a connected DataChannel
// and encrypted packet count are not evidence of remote picture delivery.
const ucrVideoCounters = {captured: 0, encoded: 0, received: 0, decoded: 0, rendered: 0, keyframes: 0, lastRenderedAt: 0};
(globalThis as unknown as {__ucrVideoCounters?: typeof ucrVideoCounters}).__ucrVideoCounters = ucrVideoCounters;
(globalThis as unknown as {__ucrAudioCounters?: typeof ucrAudioCounters}).__ucrAudioCounters = ucrAudioCounters;
interface EncodedChunkLike {
  readonly byteLength: number;
  readonly timestamp: number;
  readonly type?: string;
  copyTo(destination: Uint8Array): void;
}
interface EncoderLike {
  readonly encodeQueueSize: number;
  configure(config: object): void;
  encode(frame: unknown, options?: object): void;
  flush(): Promise<void>;
  close(): void;
}
interface DecoderLike {
  configure(config: object): void;
  decode(chunk: unknown): void;
  close(): void;
}
// Omit the lib.dom WebCodecs declarations: intersecting them with these
// structural shapes made every configure()/encode() argument an impossible
// `VideoEncoderConfig & AudioEncoderConfig` under strict tsc.
type WebCodecsGlobals = Omit<typeof globalThis,
  "MediaStreamTrackProcessor" | "AudioEncoder" | "VideoEncoder" | "AudioDecoder" |
  "VideoDecoder" | "EncodedAudioChunk" | "EncodedVideoChunk"> & {
  MediaStreamTrackProcessor?: new (options: {track: MediaStreamTrack}) => {
    readable: ReadableStream<VideoFrame | AudioData>;
  };
  AudioEncoder?: new (options: {output: (chunk: EncodedChunkLike) => void; error: (error: Error) => void}) => EncoderLike;
  VideoEncoder?: new (options: {output: (chunk: EncodedChunkLike) => void; error: (error: Error) => void}) => EncoderLike;
  AudioDecoder?: new (options: {output: (data: AudioData) => void; error: (error: Error) => void}) => DecoderLike;
  VideoDecoder?: new (options: {output: (frame: VideoFrame) => void; error: (error: Error) => void}) => DecoderLike;
  EncodedAudioChunk?: new (config: {type: "key"; timestamp: number; data: Uint8Array}) => unknown;
  EncodedVideoChunk?: new (config: {type: "key" | "delta"; timestamp: number; data: Uint8Array}) => unknown;
};
const browser = (): WebCodecsGlobals => globalThis as WebCodecsGlobals;

export function ucrWebCodecsSupported(): boolean {
  const b = browser();
  return !!(b.MediaStreamTrackProcessor && b.AudioEncoder && b.VideoEncoder &&
    b.AudioDecoder && b.VideoDecoder && b.EncodedAudioChunk && b.EncodedVideoChunk);
}

const AUDIO_CODEC = "opus";
const VIDEO_CODEC = "vp8";
const VIDEO_CODEC_H264 = "avc1.42002a";
/** H.264 Annex B start codes are carried inside authenticated E2EE frames. */
export function ucrDetectVideoCodec(bytes: Uint8Array): string {
  return bytes.length >= 5 && bytes[0] === 0 && bytes[1] === 0 &&
    (bytes[2] === 1 || (bytes[2] === 0 && bytes[3] === 1))
    ? VIDEO_CODEC_H264 : VIDEO_CODEC;
}
const AUDIO_RATE = 48_000;
const AUDIO_CHANNELS = 1;

/** Opus publish contract is 48 kHz mono. Microphones commonly produce
 * 44.1 kHz stereo; passing that AudioData directly to the configured
 * AudioEncoder rejects frames while video continues to work.
 * Convert at the endpoint, before any encryption or transport.
 */
export function ucrNormalizeOpusAudio(input: AudioData): AudioData {
  if (input.sampleRate === AUDIO_RATE && input.numberOfChannels === AUDIO_CHANNELS) return input;
  const sourceRate = input.sampleRate;
  const channels = input.numberOfChannels;
  const length = input.numberOfFrames;
  if (!Number.isFinite(sourceRate) || sourceRate < 8000 || sourceRate > 192000 ||
      !Number.isInteger(channels) || channels < 1 || channels > 8 ||
      !Number.isInteger(length) || length < 1 || length > 192000) {
    throw new Error("Unsupported microphone PCM format");
  }
  const planes: Float32Array[] = [];
  for (let channel = 0; channel < channels; channel++) {
    const plane = new Float32Array(length);
    input.copyTo(plane, {planeIndex: channel, format: "f32-planar"});
    planes.push(plane);
  }
  const outputFrames = Math.max(1, Math.round(length * AUDIO_RATE / sourceRate));
  const mono = new Float32Array(outputFrames);
  for (let i = 0; i < outputFrames; i++) {
    const position = Math.min(length - 1, i * sourceRate / AUDIO_RATE);
    const left = Math.floor(position), right = Math.min(length - 1, left + 1);
    const fraction = position - left;
    let sample = 0;
    for (const plane of planes) sample += plane[left] * (1 - fraction) + plane[right] * fraction;
    mono[i] = Math.max(-1, Math.min(1, sample / channels));
  }
  return new AudioData({
    format: "f32-planar", sampleRate: AUDIO_RATE, numberOfFrames: outputFrames,
    numberOfChannels: AUDIO_CHANNELS, timestamp: input.timestamp, data: mono,
  });
}
const VIDEO_WIDTH = 640;
const VIDEO_HEIGHT = 480;
const VIDEO_FRAMERATE = 30;
const MAX_CAPTURE_FRAME_BYTES = 1_048_576;

/** Source bitrate from actual camera dimensions, never from a weak viewer's downlink. */
export function ucrVideoEncodingTarget(width: number, height: number): {
  frameRate: number; bitrate: number;
} {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) ||
      width < 1 || height < 1 || width > 7680 || height > 4320) {
    throw new Error("invalid measured source video dimensions");
  }
  const {width: w, height: h} = ucrVideoEncodeSize(width, height, 1);
  const bitrate = Math.round(Math.min(2_500_000, Math.max(600_000, w * h * 30 * 0.09)) / 1000) * 1000;
  return {frameRate: 30, bitrate};
}
export function ucrVideoEncodeSize(width: number, height: number, scale: number): {
  width: number; height: number;
} {
  const cap = Math.min(1, 1280 / Math.max(width, height), 720 / Math.min(width, height));
  const f = Math.min(1, cap) * Math.min(1, Math.max(0.25, scale));
  const even = (v: number) => Math.max(2, Math.round(v * f / 2) * 2);
  return {width: even(width), height: even(height)};
}
export function ucrVideoStageProfile(stage: number): {scale: number; bitrateFactor: number; frameRate: number} {
  if (stage <= 0) return {scale: 1, bitrateFactor: 1, frameRate: 30};
  if (stage === 1) return {scale: 0.75, bitrateFactor: 0.6, frameRate: 30};
  return {scale: 0.5, bitrateFactor: 0.35, frameRate: 24};
}
let ucrVideoForceSoftware = false;
let ucrVideoH264Hardware: boolean | null = null;
const ucrVideoUsesH264 = (): boolean =>
  !ucrVideoForceSoftware && ucrVideoH264Hardware === true &&
  (globalThis as {ucrVideoCodecPreference?: unknown}).ucrVideoCodecPreference !== "vp8";
const ucrVideoHw = (): "no-preference" | "prefer-software" | "prefer-hardware" =>
  ucrVideoForceSoftware ? "prefer-software" :
  ucrVideoUsesH264() ? "prefer-hardware" : "no-preference";
const ucrVideoCodecConfig = (): {codec: string; avc?: {format: "annexb"}} =>
  ucrVideoUsesH264() ? {codec: VIDEO_CODEC_H264, avc: {format: "annexb"}} : {codec: VIDEO_CODEC};
async function ucrProbeH264Hardware(): Promise<void> {
  if (ucrVideoH264Hardware !== null) return;
  ucrVideoH264Hardware = false;
  const b = browser() as {VideoEncoder?: {isConfigSupported?(c: unknown): Promise<{supported?: boolean}>};
    VideoDecoder?: {isConfigSupported?(c: unknown): Promise<{supported?: boolean}>}};
  try {
    const enc = await b.VideoEncoder?.isConfigSupported?.({codec: VIDEO_CODEC_H264,
      width: 1280, height: 720, framerate: 30, bitrate: 2_500_000,
      bitrateMode: "variable", latencyMode: "realtime", avc: {format: "annexb"},
      hardwareAcceleration: "prefer-hardware"});
    const dec = await b.VideoDecoder?.isConfigSupported?.({codec: VIDEO_CODEC_H264});
    ucrVideoH264Hardware = enc?.supported === true && dec?.supported === true;
  } catch { ucrVideoH264Hardware = false; }
}
/** Source-owned congestion adaptation. Only verified encrypted transport queue
 * depth and local encoder pressure influence publish quality. Never change MLS
 * keys, Device authority, or a different participant's receive policy.
 */
export function ucrAdaptiveVideoStep(
  stage: number, bufferedBytes: number, encoderQueued: number,
  healthySamples: number, devicePressure = false,
): {stage: number; healthySamples: number} {
  if (![stage, bufferedBytes, encoderQueued, healthySamples].every(Number.isFinite) ||
      stage < 0 || stage > 2 || bufferedBytes < 0 || encoderQueued < 0) {
    throw new Error("invalid video congestion sample");
  }
  if (devicePressure || bufferedBytes > 1_048_576 || encoderQueued >= 2)
    return {stage: Math.min(2, stage + 1), healthySamples: 0};
  if (bufferedBytes > 256_000 || encoderQueued >= 1)
    return {stage, healthySamples: 0};
  const next = healthySamples + 1;
  return next >= 5 && stage > 0 ?
    {stage: stage - 1, healthySamples: 0} :
    {stage, healthySamples: Math.min(5, next)};
}
// Aggregate quality telemetry exposed to privacy-safe call diagnostics.
const ucrVideoAdaptation = {stage: 0, changes: 0, bufferedBytes: 0, encoderQueued: 0, encodeLatencyMs: 0, encodeLatencyMaxMs: 0};
(globalThis as unknown as {__ucrVideoAdaptation?: typeof ucrVideoAdaptation})
  .__ucrVideoAdaptation = ucrVideoAdaptation;
const MAX_VIDEO_ENCODER_QUEUE = 2;
const LOW_CAMERA_WIDTH = 640;
const LOW_CAMERA_HEIGHT = 360;
const LOW_CAMERA_FPS = 12;
const LOW_CAMERA_BITRATE_BPS = 384_000;
/** Fractional-timestamp scheduler: 30 fps capture must yield 24/12 fps, not 15/10.
 * Advance the deadline only after the encoder actually accepts a frame.
 * Large capture gaps re-anchor rather than creating a catch-up burst.
 */
export function ucrAdvanceVideoPacing(
  timestampUs: number, nextDueUs: number, targetFps: number,
): {publish: boolean; nextDueUs: number} {
  if (!Number.isFinite(timestampUs) || !Number.isFinite(targetFps) ||
      targetFps <= 0 || targetFps > 240 ||
      (!Number.isFinite(nextDueUs) && nextDueUs !== Number.NEGATIVE_INFINITY)) {
    throw new Error("invalid video pacing timestamp or frame rate");
  }
  const intervalUs = 1_000_000 / targetFps;
  if (timestampUs + 1 < nextDueUs) return {publish: false, nextDueUs};
  return {publish: true, nextDueUs:
    !Number.isFinite(nextDueUs) || timestampUs - nextDueUs > intervalUs
      ? timestampUs + intervalUs : nextDueUs + intervalUs};
}
// A subscriber can decode only from a keyframe. Tie that to wall time, not to
// a fixed frame count: a busy or slow camera would otherwise hide the picture
// for many seconds after someone joins.
// No confirmed receiver-to-sender keyframe request for joining/rekeying peers.
// Bound decoder recovery at startup, then reduce steady-state refresh overhead.
const VIDEO_KEYFRAME_INTERVAL_US = 3_000_000;
const VIDEO_STARTUP_KEYFRAME_INTERVAL_US = 1_000_000;
const VIDEO_STARTUP_WINDOW_US = 5_000_000;

/** Stable, bounded stream identity for one actual encrypted camera quality layer.
 * Each derived stream gets a distinct MLS traffic key context through its stream ID.
 */
export function ucrCameraLayerStreamId(trackId: string, layer: "full" | "low"): string {
  if (typeof trackId !== "string" || trackId.length < 1 ||
      trackId.length > 112 || trackId.endsWith("-low") ||
      !/^[a-zA-Z0-9_-]+$/.test(trackId)) {
    throw new Error("invalid authenticated camera track identity");
  }
  return layer === "full" ? trackId : trackId + "-low";
}
const MAX_AUDIO_ENCODER_QUEUE = 8;

/** Bounded low-latency admission: discard stale source frames, never buffer indefinitely. */
export function ucrCodecCanEnqueue(kind: "audio" | "video", queued: number): boolean {
  if (!Number.isSafeInteger(queued) || queued < 0) return false;
  return queued < (kind === "video" ? MAX_VIDEO_ENCODER_QUEUE : MAX_AUDIO_ENCODER_QUEUE);
}

function wireTimestamp(timestamp: number): bigint {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error("invalid WebCodecs timestamp");
  return BigInt(timestamp);
}

export interface UcrBrowserCodecOptions {
  readonly videoCanvas?: HTMLCanvasElement | OffscreenCanvas;
  readonly audioContext?: AudioContext;
  readonly onError?: (error: unknown) => void;
}

/** WebCodecs capture/encode owner. No crypto or transport access. */
export class UcrBrowserWebCodecsProducer implements UcrMediaProducer {
  readonly #onError: (error: unknown) => void;
  readonly #encoders: EncoderLike[] = [];
  readonly #readers: ReadableStreamDefaultReader<VideoFrame | AudioData>[] = [];
  #generation = 0;
  #emit: ((frame: UcrEncodedMediaFrame) => void | Promise<void>) | null = null;
  #sourceUpdateTail: Promise<void> = Promise.resolve();
  readonly #layeredCamera: boolean;
  #currentSources: UcrEndpointMediaSources | null = null;
  #codecRecoveryAttempts = 0;
  #lastCodecFailureAt = 0;
  #codecRecoveryTimer: ReturnType<typeof setTimeout> | null = null;
  readonly #keyframeRequests = new Map<string, () => void>();

  constructor(
    onError: (error: unknown) => void = () => {},
    layeredCamera = false,
  ) {
    this.#onError = onError;
    this.#layeredCamera = layeredCamera;
  }

  async start(
    sources: UcrEndpointMediaSources,
    emit: (frame: UcrEncodedMediaFrame) => void | Promise<void>,
  ): Promise<void> {
    if (!ucrWebCodecsSupported()) throw new Error("WebCodecs media capture/codec unavailable");
    if (this.#emit) throw new Error("WebCodecs producer already started");
    this.#emit = emit;
    this.#currentSources = sources;
    this.#codecRecoveryAttempts = 0;
    try {
      await this.#attach(sources, ++this.#generation);
    } catch (error) {
      await this.stop();
      throw error;
    }
  }

  requestVideoKeyframe(streamId: string): void {
    this.#keyframeRequests.get(streamId)?.();
  }

  async updateSources(sources: UcrEndpointMediaSources): Promise<void> {
    if (!this.#emit) throw new Error("WebCodecs producer not running");
    this.#currentSources = sources;
    const generation = ++this.#generation;
    // A screen-share revocation may arrive while an earlier reader.cancel()
    // awaits. Serialize resets and attach ONLY that update's generation:
    // otherwise an older capture can be reattached after the newer revoke.
    const next = this.#sourceUpdateTail.catch(() => {}).then(async () => {
      if (generation !== this.#generation || !this.#emit) return;
      await this.#reset();
      if (generation !== this.#generation || !this.#emit) return;
      try {
        await this.#attach(sources, generation);
      } catch (error) {
        // Partial attachment may already have opened one or more codecs.
        // A failed replacement must never leave orphaned capture loops running
        // while the caller believes the source update succeeded.
        if (generation === this.#generation) {
          ++this.#generation;
          this.#emit = null;
          await this.#reset();
          this.#onError(error);
        }
        throw error;
      }
    });
    this.#sourceUpdateTail = next;
    await next;
  }

  async stop(): Promise<void> {
    ++this.#generation;
    this.#emit = null;
    this.#currentSources = null;
    if (this.#codecRecoveryTimer !== null) clearTimeout(this.#codecRecoveryTimer);
    this.#codecRecoveryTimer = null;
    // No post-stop update may reattach an encoder after cleanup has finished.
    await this.#sourceUpdateTail.catch(() => {});
    await this.#reset();
  }

  async #reset(): Promise<void> {
    this.#keyframeRequests.clear();
    for (const reader of this.#readers.splice(0)) {
      try { await reader.cancel(); } catch (_) { /* already closed */ }
    }
    for (const encoder of this.#encoders.splice(0)) {
      try { encoder.close(); } catch (_) { /* already closed */ }
    }
  }

  async #attach(sources: UcrEndpointMediaSources, generation: number): Promise<void> {
    const audio = sources.stream.getAudioTracks()[0];
    const video = sources.cameraStream.getVideoTracks()[0];
    const screen = sources.screenStream?.getVideoTracks()[0];
    if (audio) this.#capture(audio, "audio", undefined, generation);
    if (video || screen) await ucrProbeH264Hardware();
    if (generation !== this.#generation) return;
    if (video) this.#capture(video, "video", "camera", generation);
    if (screen) this.#capture(screen, "video", "screen_share", generation);
  }

  #capture(
    track: MediaStreamTrack,
    kind: "audio" | "video",
    source: "camera" | "screen_share" | undefined,
    generation: number,
  ): void {
    const b = browser();
    const processor = new b.MediaStreamTrackProcessor!({track});
    const streamId = track.id;
    if (!streamId) throw new Error("media track must have stream identity");
    let forceKeyframe = false;
    let forceLowKeyframe = false;
    const encodeStartTimes = new Map<number, number>();
    const emitChunkFor = (encodedStreamId: string) => (chunk: EncodedChunkLike) => {
      if (generation !== this.#generation || !this.#emit) return;
      if (chunk.byteLength < 1 || chunk.byteLength > MAX_CAPTURE_FRAME_BYTES) {
        this.#onError(new Error("WebCodecs frame exceeds bounded E2EE payload"));
        return;
      }
      const bytes = new Uint8Array(chunk.byteLength);
      chunk.copyTo(bytes);
      try {
        if (kind === "audio") ucrAudioCounters.encoded++;
        else {
          ucrVideoCounters.encoded++;
          if (chunk.type === "key") ucrVideoCounters.keyframes++;
          const started = encodeStartTimes.get(chunk.timestamp);
          if (started !== undefined) {
            encodeStartTimes.delete(chunk.timestamp);
            const elapsed = performance.now() - started;
            ucrVideoAdaptation.encodeLatencyMs = Math.round(elapsed);
            ucrVideoAdaptation.encodeLatencyMaxMs = Math.max(
              ucrVideoAdaptation.encodeLatencyMaxMs, Math.round(elapsed));
          }
        }
        void Promise.resolve(this.#emit({
          mediaKind: kind,
          videoSourceKind: source,
          streamId: encodedStreamId,
          timestamp: wireTimestamp(chunk.timestamp),
          keyframe: kind === "video" && chunk.type === "key",
          bytes,
        })).catch((error) => {
          if (kind === "video") {
            if (encodedStreamId.endsWith("-low") && this.#layeredCamera) {
              forceLowKeyframe = true;
            } else {
              forceKeyframe = true;
            }
          }
          this.#onError(error);
        });
      } catch (error) { this.#onError(error); }
    };
    const encodedStreamId = kind === "video" && source === "camera" &&
      this.#layeredCamera ? ucrCameraLayerStreamId(streamId, "full") : streamId;
    if (kind === "video") this.#keyframeRequests.set(encodedStreamId, () => { forceKeyframe = true; });
    const onError = (error: Error) => {
      if (generation !== this.#generation || !this.#emit) return;
      if (kind === "video") ucrVideoForceSoftware = true;
      this.#onError(error);
      const now = Date.now();
      if (now - this.#lastCodecFailureAt > 60_000) this.#codecRecoveryAttempts = 0;
      this.#lastCodecFailureAt = now;
      if (!this.#currentSources || this.#codecRecoveryTimer !== null) return;
      const delay = Math.min(10_000, 250 * 2 ** Math.min(this.#codecRecoveryAttempts++, 6));
      this.#codecRecoveryTimer = setTimeout(() => {
        this.#codecRecoveryTimer = null;
        if (!this.#emit || !this.#currentSources) return;
        void this.updateSources(this.#currentSources).catch(this.#onError);
      }, delay);
    };
    const encoder = kind === "audio"
      ? new b.AudioEncoder!({output: emitChunkFor(encodedStreamId), error: onError})
      : new b.VideoEncoder!({output: emitChunkFor(encodedStreamId), error: onError});
    if (kind === "audio") {
      encoder.configure({codec: AUDIO_CODEC, sampleRate: AUDIO_RATE,
        numberOfChannels: AUDIO_CHANNELS, bitrate: 48_000,
        opus: {complexity: 8, useinbandfec: true, frameDuration: 20_000}} as never);
    } else {
      const settings = track.getSettings();
      const width = settings.width ?? VIDEO_WIDTH;
      const height = settings.height ?? VIDEO_HEIGHT;
      const quality = ucrVideoEncodingTarget(width, height);
      const size = ucrVideoEncodeSize(width, height, 1);
      const config = {...ucrVideoCodecConfig(), width: size.width, height: size.height,
        framerate: Math.min(
          Math.max(1, settings.frameRate ?? VIDEO_FRAMERATE), quality.frameRate,
        ),
        bitrate: quality.bitrate, bitrateMode: "variable", latencyMode: "realtime"};
      // On some Windows GPU stacks configure(prefer-hardware) succeeds but
      // the asynchronous first encode fails, leaving a live camera and zero
      // encoded video frames. Prefer a software VP8 encoder for the first call;
      // preserve resolution and bitrate, and fall back to default negotiation
      // only if this browser rejects that preference synchronously.
      try {
        encoder.configure({...config, hardwareAcceleration: ucrVideoHw()});
      } catch {
        encoder.configure(config);
      }
    }
    this.#encoders.push(encoder);
    // A second *real* encrypted source layer is opt-in, not a viewer-count mode.
    // Limit it to a source with enough pixels and browsers with OffscreenCanvas.
    let lowEncoder: EncoderLike | null = null;
    let lowCanvas: OffscreenCanvas | null = null;
    if (kind === "video" && source === "camera" && this.#layeredCamera) {
      const settings = track.getSettings();
      if ((settings.width ?? VIDEO_WIDTH) >= 1280 &&
          (settings.height ?? VIDEO_HEIGHT) >= 720) {
        if (typeof OffscreenCanvas !== "function" || typeof VideoFrame !== "function") {
          throw new Error("layered WebCodecs requires endpoint OffscreenCanvas and VideoFrame");
        }
        lowCanvas = new OffscreenCanvas(LOW_CAMERA_WIDTH, LOW_CAMERA_HEIGHT);
        const lowStreamId = ucrCameraLayerStreamId(streamId, "low");
        lowEncoder = new b.VideoEncoder!({
          output: emitChunkFor(lowStreamId), error: onError,
        });
        lowEncoder.configure({
          codec: VIDEO_CODEC, width: LOW_CAMERA_WIDTH, height: LOW_CAMERA_HEIGHT,
          framerate: LOW_CAMERA_FPS, bitrate: LOW_CAMERA_BITRATE_BPS,
          latencyMode: "realtime", hardwareAcceleration: ucrVideoHw(),
        });
        this.#encoders.push(lowEncoder);
        this.#keyframeRequests.set(lowStreamId, () => { forceLowKeyframe = true; });
      }
    }
    // A transport-pressure probe is installed by the first-party encrypted
    // DataChannel owner; absence is treated as no observed network congestion.
    let qualityStage = 0, healthySamples = 0, lastQualitySample = 0;
    let lastVideoEncodeTimestamp = Number.NEGATIVE_INFINITY;
    let nextVideoEncodeTimestamp = Number.NEGATIVE_INFINITY;
    let videoEncodeCostMs = 0;
    let videoPressureSamples = 0;
    let lastWallSample = performance.now();
    let lastMediaSample = -1;

    const readBuffered = () => {
      const probe = (globalThis as unknown as {
        ucrEncryptedTransportBufferedAmount?: () => number;
      }).ucrEncryptedTransportBufferedAmount;
      // Missing or invalid transport telemetry is NOT proof of a healthy link.
      // Fail toward the most conservative publish stage until real measurements return.
      if (typeof probe !== "function") return 1_048_577;
      try {
        const measured = Number(probe());
        return Number.isFinite(measured) && measured >= 0 ? measured : 1_048_577;
      } catch { return 1_048_577; }
    };
    const reader = processor.readable.getReader();
    this.#readers.push(reader);
    const pump = async () => {
      let lastKeyframeTimestamp = Number.NEGATIVE_INFINITY;
      let framesSinceKeyframe = Number.POSITIVE_INFINITY;
      let lastLowKeyframeTimestamp = Number.NEGATIVE_INFINITY;
      let lowFramesSinceKeyframe = Number.POSITIVE_INFINITY;
      let nextLowEncodeTimestamp = Number.NEGATIVE_INFINITY;
      let lastLowEncodeTimestamp = Number.NEGATIVE_INFINITY;
      let streamStartTimestamp = Number.NaN;
      const due = (timestamp: number, last: number, since: number) => {
        const clock = Number.isFinite(timestamp) ? timestamp : 0;
        if (Number.isNaN(streamStartTimestamp)) streamStartTimestamp = clock;
        const interval = clock - streamStartTimestamp < VIDEO_STARTUP_WINDOW_US
          ? VIDEO_STARTUP_KEYFRAME_INTERVAL_US : VIDEO_KEYFRAME_INTERVAL_US;
        return since >= 300 || clock - last >= interval;
      };
      while (generation === this.#generation) {
        const result = await reader.read();
        if (result.done) break;
        const frame = result.value;
        try {
          if (kind === "video") ucrVideoCounters.captured++;
          if (kind === "video" && Number.isFinite(frame.timestamp)) {
            // Detect a stalled local capture/encode loop: compare media capture
            // time progression against monotonic wall time, ignoring timestamp
            // resets or large capture gaps caused by background tabs.
            const wall = performance.now();
            if (lastMediaSample >= 0 && frame.timestamp >= lastMediaSample) {
              const wallElapsed = wall - lastWallSample;
              const mediaElapsed = (frame.timestamp - lastMediaSample) / 1000;
              if (wallElapsed > 150 && mediaElapsed < wallElapsed * 0.6)
                videoPressureSamples++;
            }
            lastWallSample = wall;
            lastMediaSample = frame.timestamp;
          }
          if (kind === "video" && frame.timestamp - lastQualitySample >= 1_000_000) {
            lastQualitySample = frame.timestamp;
            // Delayed encoder work and elevated queue pressure indicate local
            // CPU/GPU contention even when the network DataChannel is empty.
            // Recover only after sustained healthy samples.
            const devicePressure = videoPressureSamples >= 3;
            const next = ucrAdaptiveVideoStep(qualityStage, readBuffered(),
              encoder.encodeQueueSize, healthySamples, devicePressure);
            videoPressureSamples = 0;
            healthySamples = next.healthySamples;
            ucrVideoAdaptation.bufferedBytes = readBuffered();
            ucrVideoAdaptation.encoderQueued = encoder.encodeQueueSize;
            if (next.stage !== qualityStage) {
              ucrVideoAdaptation.changes++;
              ucrVideoAdaptation.stage = next.stage;
              qualityStage = next.stage;
              nextVideoEncodeTimestamp = lastVideoEncodeTimestamp +
                1_000_000 / ucrVideoStageProfile(qualityStage).frameRate;
              const settings = track.getSettings();
              const width = settings.width ?? VIDEO_WIDTH;
              const height = settings.height ?? VIDEO_HEIGHT;
              const full = ucrVideoEncodingTarget(width, height);
              const profile = ucrVideoStageProfile(qualityStage);
              const size = ucrVideoEncodeSize(width, height, profile.scale);
              const config = {...ucrVideoCodecConfig(), width: size.width, height: size.height,
                framerate: Math.min(settings.frameRate ?? VIDEO_FRAMERATE, profile.frameRate),
                bitrate: Math.max(250_000, Math.round(full.bitrate * profile.bitrateFactor)),
                bitrateMode: "variable", latencyMode: "realtime"};
              try {
                encoder.configure({...config, hardwareAcceleration: ucrVideoHw()});
              } catch {
                encoder.configure(config);
              }
              forceKeyframe = true;
            }
          }
          if (kind === "video" && frame.timestamp < lastVideoEncodeTimestamp)
            nextVideoEncodeTimestamp = Number.NEGATIVE_INFINITY;
          if (kind === "video" && frame.timestamp < lastLowEncodeTimestamp)
            nextLowEncodeTimestamp = Number.NEGATIVE_INFINITY;
          const videoPacing = kind === "video" ?
            ucrAdvanceVideoPacing(frame.timestamp, nextVideoEncodeTimestamp,
              ucrVideoStageProfile(qualityStage).frameRate) : null;
          const videoPacingOk = videoPacing?.publish ?? true;
          if (videoPacingOk && ucrCodecCanEnqueue(kind, encoder.encodeQueueSize)) {
            const keyframe = kind === "video" &&
              (forceKeyframe || due(frame.timestamp, lastKeyframeTimestamp, framesSinceKeyframe));
            if (kind === "audio") {
              ucrAudioCounters.captured++;
              const pcm = ucrNormalizeOpusAudio(frame as AudioData);
              try {
                if ((ucrAudioCounters.captured & 15) === 0) {
                  const samples = new Float32Array(pcm.numberOfFrames);
                  pcm.copyTo(samples, {planeIndex: 0, format: "f32-planar"});
                  let peak = 0;
                  for (let i = 0; i < samples.length; i++) peak = Math.max(peak, Math.abs(samples[i]));
                  ucrAudioCounters.inputPeak = Math.round(peak * 1000) / 1000;
                }
                encoder.encode(pcm);
              }
              finally { if (pcm !== frame) pcm.close(); }
            } else {
              const encodeStarted = performance.now();
              encodeStartTimes.set(frame.timestamp, encodeStarted);
              if (encodeStartTimes.size > 32) encodeStartTimes.delete(encodeStartTimes.keys().next().value!);
              encoder.encode(frame, {keyFrame: keyframe});
              const encodeCost = performance.now() - encodeStarted;
              videoEncodeCostMs = videoEncodeCostMs * 0.8 + encodeCost * 0.2;
              if (ucrVideoAdaptation.encodeLatencyMs > 120 || videoEncodeCostMs > 12 || encoder.encodeQueueSize >= 2)
                videoPressureSamples++;
              lastVideoEncodeTimestamp = frame.timestamp;
              nextVideoEncodeTimestamp = videoPacing!.nextDueUs;
              forceKeyframe = false;
            }
            if (kind === "video") {
              if (keyframe) {
                framesSinceKeyframe = 0;
                if (Number.isFinite(frame.timestamp)) lastKeyframeTimestamp = frame.timestamp;
              } else framesSinceKeyframe++;
            }
          }
          const lowPacing = lowEncoder ?
            ucrAdvanceVideoPacing(frame.timestamp, nextLowEncodeTimestamp, LOW_CAMERA_FPS) : null;
          if (lowEncoder && lowCanvas && generation === this.#generation &&
              ucrCodecCanEnqueue("video", lowEncoder.encodeQueueSize) &&
              lowPacing?.publish) {
            const context = lowCanvas.getContext("2d");
            if (!context) throw new Error("layered capture canvas unavailable");
            context.drawImage(frame as VideoFrame, 0, 0, LOW_CAMERA_WIDTH, LOW_CAMERA_HEIGHT);
            const downscaled = new VideoFrame(lowCanvas, {timestamp: frame.timestamp});
            try {
              const keyframe = forceLowKeyframe ||
                due(frame.timestamp, lastLowKeyframeTimestamp, lowFramesSinceKeyframe);
              lowEncoder.encode(downscaled, {keyFrame: keyframe});
              if (keyframe) {
                lowFramesSinceKeyframe = 0;
                if (Number.isFinite(frame.timestamp)) lastLowKeyframeTimestamp = frame.timestamp;
              } else lowFramesSinceKeyframe++;
              lastLowEncodeTimestamp = frame.timestamp;
              nextLowEncodeTimestamp = lowPacing.nextDueUs;
              forceLowKeyframe = false;
            } finally {
              downscaled.close();
            }
          }
        } finally {
          frame.close();
        }
      }
    };
    void pump().catch((error) => {
      if (generation === this.#generation) this.#onError(error);
    });
  }
}

/** Decode/render owner; incoming frames are already verified and opened by Rust/WASM. */
export class UcrBrowserWebCodecsConsumer implements UcrMediaConsumer {
  readonly #onError: (error: unknown) => void;
  readonly #videoCanvas?: HTMLCanvasElement | OffscreenCanvas;
  readonly #audioContext?: AudioContext;
  readonly #decoders = new Map<string, DecoderLike>();
  readonly #decoderCodecs = new Map<string, string>();
  // WebAudio mixes independent AudioBufferSources automatically. Only frames
  // from the SAME authenticated audio stream must be sequenced; a global clock
  // serializes different speakers and makes conferences fall behind real time.
  // One receiver-local playout state per authenticated sender. Jitter is
  // estimated from actual decoded packet arrival spacing, never fabricated
  // from network statistics. Keep audio sources independent when mixing.
  readonly #audioPlayout = new Map<string, {
    next: number; lastArrival: number; lastDuration: number; jitter: number;
  }>();
  readonly #scheduledAudio = new Map<string, Set<AudioBufferSourceNode>>();
  #videoEnabled = true;
  #renderGeneration = 0;
  #lowVideoPreferred = false;
  readonly #activeVideoStreams = new Map<string, string>();
  readonly #pendingVideoStreams = new Map<string, {streamId: string; decoderKey: string}>();
  readonly #awaitVideoKeyframe = new Set<string>();
  // A single reference canvas may show exactly ONE authenticated video source,
  // even while a keyframe for its replacement is decoding. Retire all old
  // decoders only after the replacement has actually rendered successfully.
  #visibleVideoDecoderKey: string | null = null;
  #pendingVisibleVideoDecoderKey: string | null = null;
  #visibleVideoKind: "camera" | "screen_share" | null = null;
  #lastScreenVideoAt = 0;

  constructor(options: UcrBrowserCodecOptions = {}) {
    this.#videoCanvas = options.videoCanvas;
    this.#audioContext = options.audioContext;
    this.#onError = options.onError ?? (() => {});
  }

  /** Receiver-only downgrade: video decoding stops at the local endpoint.
   * Higher stages remain advisory until actual E2EE SVC/simulcast layering exists.
   */
  setReceiveQuality(target: UcrEndpointAdaptiveQualityV1): void {
    const video = target.stage.startsWith("video_");
    if ((video && !target.video) || (!video && target.video !== null)) {
      throw new Error("invalid receive quality decision");
    }
    // Never cancel a working decoder merely because a preferred layer has changed.
    // Discard any prepared candidate from the old preference.
    const lowPreferred = video && target.stage !== "video_1080p";
    if (this.#lowVideoPreferred !== lowPreferred) this.#discardPendingVideo();
    this.#lowVideoPreferred = lowPreferred;
    if (this.#videoEnabled === video) return;
    this.#videoEnabled = video;
    ++this.#renderGeneration;
    if (!video) {
      this.#activeVideoStreams.clear();
      this.#discardPendingVideo();
      this.#visibleVideoDecoderKey = null;
      this.#pendingVisibleVideoDecoderKey = null;
      this.#visibleVideoKind = null;
      this.#lastScreenVideoAt = 0;
      for (const [key, decoder] of this.#decoders) {
        if (key.startsWith("video:")) {
          decoder.close();
          this.#decoders.delete(key);
        }
      }
    }
  }

  #discardPendingVideo(): void {
    for (const pending of this.#pendingVideoStreams.values()) {
      const decoder = this.#decoders.get(pending.decoderKey);
      if (decoder) {
        decoder.close();
        this.#decoders.delete(pending.decoderKey);
      }
    }
    this.#pendingVideoStreams.clear();
    this.#pendingVisibleVideoDecoderKey = null;
  }

  /** These stream IDs have reached the local video canvas, not just a decoder queue. */
  getActiveReceiveVideoStreams(): readonly UcrVerifiedReceiveVideoStream[] {
    return [...this.#activeVideoStreams.entries()].map(([key, streamId]) => {
      const [sourceId, sourceDeviceId] = JSON.parse(key) as [string, string, string, string];
      return {sourceId, sourceDeviceId, streamId};
    });
  }

  /** Decoder identity includes canonical signed source identity, not only a media
   * track ID that may collide across different speakers or devices.
   */
  #decoderKey(
    mediaKind: "audio" | "video",
    videoSourceKind: string | undefined,
    streamId: string,
    header?: SfuForwardEnvelopeWire["frame"]["header"],
  ): string {
    return mediaKind + ":" + JSON.stringify([
      header?.source?.principalId ?? "",
      header?.sourceDeviceId ?? "",
      videoSourceKind ?? "",
      streamId,
    ]);
  }

  play(
    frame: UcrEncodedMediaFrame,
    source?: SfuForwardEnvelopeWire["frame"]["header"],
  ): void {
    if (frame.mediaKind === "video" && !this.#videoEnabled) return;
    const key = this.#decoderKey(frame.mediaKind, frame.videoSourceKind, frame.streamId, source);
    let videoSourceKey: string | null = null;
    if (frame.mediaKind === "video") {
      const videoKind = frame.videoSourceKind === "screen_share" ? "screen_share" : "camera";
      // While an authenticated screen-share is playing, do not let concurrent
      // camera frames overwrite its canvas. Resume camera from a real keyframe
      // when the screen-share stops transmitting (bounded 1.5s freshness).
      if (videoKind === "camera" && this.#visibleVideoKind === "screen_share" &&
          Date.now() - this.#lastScreenVideoAt < 1_500) return;
      if (videoKind === "screen_share") this.#lastScreenVideoAt = Date.now();
      const isLow = videoKind === "camera" && frame.streamId.endsWith("-low");
      const baseTrack = isLow ? frame.streamId.slice(0, -4) : frame.streamId;
      // The source/device identity is already verified by the MLS endpoint.
      videoSourceKey = JSON.stringify([
        source?.source?.principalId ?? "",
        source?.sourceDeviceId ?? "",
        videoKind,
        baseTrack,
      ]);
      const active = this.#activeVideoStreams.get(videoSourceKey);
      if (active !== frame.streamId) {
        const preferred = videoKind === "camera" && this.#lowVideoPreferred ?
          baseTrack + "-low" : baseTrack;
        if (active && frame.streamId !== preferred) return;
        const pending = this.#pendingVideoStreams.get(videoSourceKey);
        if (pending?.streamId !== frame.streamId) {
          if (!frame.keyframe) return;
          if (pending) {
            const discarded = this.#decoders.get(pending.decoderKey);
            if (discarded) {
              discarded.close();
              this.#decoders.delete(pending.decoderKey);
            }
          }
          // Preparation only: the currently visible layer stays alive until
          // the new authenticated keyframe has ACTUALLY decoded and rendered.
          this.#pendingVideoStreams.set(videoSourceKey, {
            streamId: frame.streamId, decoderKey: key,
          });
        }
      }
    }
    const b = browser();
    if (!ucrWebCodecsSupported()) throw new Error("WebCodecs playback unavailable");
    let decoder = this.#decoders.get(key);
    // A newly selected encrypted video layer must start from its keyframe.
    if (frame.mediaKind === "video" && this.#awaitVideoKeyframe.has(key) && !frame.keyframe) return;
    if (frame.mediaKind === "video" && !decoder && !frame.keyframe) return;
    if (frame.mediaKind === "video" && frame.keyframe) this.#awaitVideoKeyframe.delete(key);
    if (frame.mediaKind === "video" && key !== this.#visibleVideoDecoderKey &&
        this.#pendingVisibleVideoDecoderKey !== key) {
      // Only the currently displayed decoder and one candidate may be alive.
      const pendingKey = this.#pendingVisibleVideoDecoderKey;
      if (pendingKey && pendingKey !== this.#visibleVideoDecoderKey) {
        this.#decoders.get(pendingKey)?.close();
        this.#decoders.delete(pendingKey);
      }
      this.#pendingVisibleVideoDecoderKey = key;
    }
    if (!decoder) {
      if (frame.mediaKind === "audio") {
        if (!this.#audioContext) throw new Error("audio playback context not provided");
        decoder = new b.AudioDecoder!({
          output: (data) => this.#playAudio(data, key),
          error: this.#onError,
        });
        decoder.configure({codec: AUDIO_CODEC, sampleRate: AUDIO_RATE, numberOfChannels: AUDIO_CHANNELS});
      } else {
        if (!this.#videoCanvas) throw new Error("video rendering canvas not provided");
        const renderGeneration = this.#renderGeneration;
        const selectedSourceKey = videoSourceKey;
        const selectedStreamId = frame.streamId;
        decoder = new b.VideoDecoder!({
          output: (video) => {
            try {
              if (!this.#videoEnabled || this.#renderGeneration !== renderGeneration) return;
              // Late decoded output from retired sources may never replace the
              // one selected canvas, including after an active-speaker switch.
              if (this.#visibleVideoDecoderKey !== key &&
                  this.#pendingVisibleVideoDecoderKey !== key) return;
              const oldVisible = selectedSourceKey === null ? undefined
                : this.#activeVideoStreams.get(selectedSourceKey);
              const pending = selectedSourceKey === null ? undefined
                : this.#pendingVideoStreams.get(selectedSourceKey);
              if (selectedSourceKey !== null && oldVisible !== selectedStreamId &&
                  (pending?.streamId !== selectedStreamId || pending.decoderKey !== key)) return;
              const canvas = this.#videoCanvas!;
              ucrVideoCounters.decoded++;
              const width = video.displayWidth, height = video.displayHeight;
              if (width < 1 || height < 1 || width > 7680 || height > 4320) {
                throw new Error("decoded frame exceeds secure display bounds");
              }
              const context = canvas.getContext("2d");
              if (!context) throw new Error("video canvas 2D context unavailable");
              // Render the new frame before retiring the old decoder. An invalid
              // keyframe, failed decode or rendering error must retain live video.
              if (canvas.width !== width) canvas.width = width;
              if (canvas.height !== height) canvas.height = height;
              // Preserve decode reference frames, but avoid unnecessary canvas
              // copies while this page is hidden or minimized.
              const doc = (globalThis as {document?: {hidden?: boolean}}).document;
              if (!doc?.hidden) {
                (context as CanvasRenderingContext2D).drawImage(video, 0, 0, width, height);
                ucrVideoCounters.rendered++;
                ucrVideoCounters.lastRenderedAt = Date.now();
              }
              if (selectedSourceKey !== null && oldVisible !== selectedStreamId) {
                this.#activeVideoStreams.set(selectedSourceKey, selectedStreamId);
                this.#pendingVideoStreams.delete(selectedSourceKey);
              }
              if (this.#visibleVideoDecoderKey !== key) {
                // Successful rendering commits the source/quality handover.
                // Active-speaker and camera/screen transitions must free every
                // previous VideoDecoder, not only a layer of this same source.
                this.#visibleVideoDecoderKey = key;
                this.#pendingVisibleVideoDecoderKey = null;
                this.#visibleVideoKind = frame.videoSourceKind === "screen_share" ?
                  "screen_share" : "camera";
                for (const [oldKey, oldDecoder] of this.#decoders) {
                  if (oldKey.startsWith("video:") && oldKey !== key) {
                    oldDecoder.close();
                    this.#decoders.delete(oldKey);
                  }
                }
                for (const oldSourceKey of this.#activeVideoStreams.keys()) {
                  if (oldSourceKey !== selectedSourceKey) this.#activeVideoStreams.delete(oldSourceKey);
                }
                this.#pendingVideoStreams.clear();
              }
            } finally { video.close(); }
          },
          error: (error) => {
            this.#awaitVideoKeyframe.add(key);
            const failed = this.#decoders.get(key);
            if (failed) {
              this.#decoders.delete(key);
              try { failed.close(); } catch { /* codec already closed */ }
            }
            if (this.#visibleVideoDecoderKey === key) this.#visibleVideoDecoderKey = null;
            if (this.#pendingVisibleVideoDecoderKey === key) this.#pendingVisibleVideoDecoderKey = null;
            if (selectedSourceKey !== null) {
              const pending = this.#pendingVideoStreams.get(selectedSourceKey);
              if (pending?.streamId === selectedStreamId && pending.decoderKey === key) {
                this.#pendingVideoStreams.delete(selectedSourceKey);
                // An asynchronous VideoDecoder error permanently invalidates
                // this pending decoder. Close it before allowing the next
                // authenticated keyframe to construct a clean decoder.
                const failedDecoder = this.#decoders.get(key);
                if (failedDecoder) {
                  this.#decoders.delete(key);
                  try { failedDecoder.close(); } catch { /* codec already closed */ }
                }
                if (this.#pendingVisibleVideoDecoderKey === key) {
                  this.#pendingVisibleVideoDecoderKey = null;
                }
              }
            }
            this.#onError(error);
          },
        });
        const codec = ucrDetectVideoCodec(frame.bytes);
        decoder.configure({codec});
        this.#decoderCodecs.set(key, codec);
      }
      this.#decoders.set(key, decoder);
    } else if (frame.mediaKind === "video" && frame.keyframe) {
      const codec = ucrDetectVideoCodec(frame.bytes);
      if (this.#decoderCodecs.get(key) !== codec) {
        (decoder as {configure(c: unknown): void}).configure({codec});
        this.#decoderCodecs.set(key, codec);
      }
    }
    const data = frame.bytes;
    const timestamp = Number(frame.timestamp);
    if (!Number.isSafeInteger(timestamp)) throw new Error("media timestamp exceeds browser bounds");
    if (frame.mediaKind === "audio") {
      ucrAudioCounters.received++;
      decoder.decode(new b.EncodedAudioChunk!({type: "key", timestamp, data}));
    } else {
      ucrVideoCounters.received++;
      try {
        decoder.decode(new b.EncodedVideoChunk!({
          type: frame.keyframe ? "key" : "delta", timestamp, data,
        }));
      } catch (error) {
        this.#awaitVideoKeyframe.add(key);
        const failed = this.#decoders.get(key);
        if (failed) {
          this.#decoders.delete(key);
          try { failed.close(); } catch { /* codec already closed */ }
        }
        if (this.#visibleVideoDecoderKey === key) this.#visibleVideoDecoderKey = null;
        if (this.#pendingVisibleVideoDecoderKey === key) this.#pendingVisibleVideoDecoderKey = null;
        if (videoSourceKey !== null) {
          const pending = this.#pendingVideoStreams.get(videoSourceKey);
          if (pending?.streamId === frame.streamId && pending.decoderKey === key) {
            this.#pendingVideoStreams.delete(videoSourceKey);
            const brokenDecoder = this.#decoders.get(key);
            if (brokenDecoder) {
              brokenDecoder.close();
              this.#decoders.delete(key);
            }
          }
        }
        throw error;
      }
    }
  }

  #playAudio(data: AudioData, streamKey: string): void {
    ucrAudioCounters.decoded++;
    try {
      const context = this.#audioContext!;
      const buffer = context.createBuffer(data.numberOfChannels, data.numberOfFrames, data.sampleRate);
      let framePeak = 0;
      for (let ch = 0; ch < data.numberOfChannels; ch++) {
        const pcm = new Float32Array(data.numberOfFrames);
        data.copyTo(pcm, {planeIndex: ch, format: "f32-planar"});
        let peak = 0;
        for (let i = 0; i < pcm.length; i++) peak = Math.max(peak, Math.abs(pcm[i]));
        framePeak = Math.max(framePeak, peak);
        buffer.copyToChannel(pcm, ch);
      }
      ucrAudioCounters.outputPeak = Math.round(framePeak * 1000) / 1000;
      const node = context.createBufferSource();
      node.buffer = buffer;
      node.connect(context.destination);
      const now = context.currentTime;
      let state = this.#audioPlayout.get(streamKey);
      if (!state) {
        state = {next: now + 0.06, lastArrival: now,
          lastDuration: buffer.duration, jitter: 0};
        this.#audioPlayout.set(streamKey, state);
      } else {
        // RFC3550-style EWMA, measured from actual consecutive PCM arrivals.
        // Clamp spikes to keep a tab suspension from inflating playout forever.
        const arrivalGap = Math.max(0, now - state.lastArrival);
        const variation = Math.min(0.25, Math.abs(arrivalGap - state.lastDuration));
        state.jitter += (variation - state.jitter) / 16;
        state.lastArrival = now;
        state.lastDuration = buffer.duration;
      }
      const cushion = Math.min(0.12, Math.max(0.04, 0.04 + 2 * state.jitter));
      ucrAudioCounters.playoutJitterMs = Math.round(state.jitter * 1000);
      ucrAudioCounters.playoutQueuedMs = Math.max(0, Math.round((state.next - now) * 1000));
      // Bound queued audio by elapsed wall-clock time. On overflow cancel
      // obsolete scheduled PCM, then rebuild from a fresh bounded cushion.
      // Merely rebasing a timestamp would overlap old and new speech.
      if (state.next - now > 0.25) {
        ucrAudioCounters.dropped++;
        ucrAudioCounters.playoutRebases++;
        const scheduled = this.#scheduledAudio.get(streamKey);
        if (scheduled) {
          this.#scheduledAudio.delete(streamKey);
          for (const source of scheduled) {
            source.onended = null;
            try { source.stop(); } catch { /* source already finished */ }
            if (typeof source.disconnect === "function") source.disconnect();
          }
          scheduled.clear();
        }
        state.next = now + cushion;
        if (typeof node.disconnect === "function") node.disconnect();
        return;
      }
      // Following starvation, restart promptly with a small measured cushion.
      if (state.next < now) state.next = now + cushion;
      const start = Math.max(now + 0.012, state.next);
      let scheduled = this.#scheduledAudio.get(streamKey);
      if (!scheduled) {
        scheduled = new Set<AudioBufferSourceNode>();
        this.#scheduledAudio.set(streamKey, scheduled);
      }
      const owner = scheduled;
      owner.add(node);
      node.onended = () => {
        owner.delete(node);
        if (typeof node.disconnect === "function") node.disconnect();
        if (owner.size === 0 && this.#scheduledAudio.get(streamKey) === owner)
          this.#scheduledAudio.delete(streamKey);
      };
      node.start(start);
      ucrAudioCounters.scheduled++;
      state.next = start + buffer.duration;
    } catch (error) { this.#onError(error); }
    finally { data.close(); }
  }

  stop(): void {
    ++this.#renderGeneration;
    for (const decoder of this.#decoders.values()) decoder.close();
    this.#decoders.clear();
    this.#pendingVideoStreams.clear();
    this.#awaitVideoKeyframe.clear();
    this.#activeVideoStreams.clear();
    this.#visibleVideoDecoderKey = null;
    this.#pendingVisibleVideoDecoderKey = null;
    this.#visibleVideoKind = null;
    this.#lastScreenVideoAt = 0;
    this.#videoEnabled = true;
    this.#lowVideoPreferred = false;
    this.#audioPlayout.clear();
    for (const sources of this.#scheduledAudio.values()) {
      for (const source of sources) {
        source.onended = null;
        try { source.stop(); } catch { /* already ended */ }
        if (typeof source.disconnect === "function") source.disconnect();
      }
    }
    this.#scheduledAudio.clear();
  }
}
