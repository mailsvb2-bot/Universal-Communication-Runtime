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
type WebCodecsGlobals = typeof globalThis & {
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
const AUDIO_RATE = 48_000;
const AUDIO_CHANNELS = 1;
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
  const pixels = width * height;
  if (pixels >= 1920 * 1080) return {frameRate: 30, bitrate: 4_000_000};
  if (pixels >= 1280 * 720) return {frameRate: 30, bitrate: 2_000_000};
  if (pixels >= 854 * 480) return {frameRate: 30, bitrate: 1_000_000};
  return {frameRate: 12, bitrate: 384_000};
}
const MAX_VIDEO_ENCODER_QUEUE = 2;
const LOW_CAMERA_WIDTH = 640;
const LOW_CAMERA_HEIGHT = 360;
const LOW_CAMERA_FPS = 12;
const LOW_CAMERA_BITRATE_BPS = 384_000;
const LOW_CAMERA_INTERVAL_US = 1_000_000 / LOW_CAMERA_FPS;

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
    try {
      await this.#attach(sources, ++this.#generation);
    } catch (error) {
      await this.stop();
      throw error;
    }
  }

  async updateSources(sources: UcrEndpointMediaSources): Promise<void> {
    if (!this.#emit) throw new Error("WebCodecs producer not running");
    const generation = ++this.#generation;
    // A screen-share revocation may arrive while an earlier reader.cancel()
    // awaits. Serialize resets and attach ONLY that update's generation:
    // otherwise an older capture can be reattached after the newer revoke.
    const next = this.#sourceUpdateTail.catch(() => {}).then(async () => {
      if (generation !== this.#generation || !this.#emit) return;
      await this.#reset();
      if (generation !== this.#generation || !this.#emit) return;
      await this.#attach(sources, generation);
    });
    this.#sourceUpdateTail = next;
    await next;
  }

  async stop(): Promise<void> {
    ++this.#generation;
    this.#emit = null;
    // No post-stop update may reattach an encoder after cleanup has finished.
    await this.#sourceUpdateTail.catch(() => {});
    await this.#reset();
  }

  async #reset(): Promise<void> {
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
    const emitChunkFor = (encodedStreamId: string) => (chunk: EncodedChunkLike) => {
      if (generation !== this.#generation || !this.#emit) return;
      if (chunk.byteLength < 1 || chunk.byteLength > MAX_CAPTURE_FRAME_BYTES) {
        this.#onError(new Error("WebCodecs frame exceeds bounded E2EE payload"));
        return;
      }
      const bytes = new Uint8Array(chunk.byteLength);
      chunk.copyTo(bytes);
      try {
        void Promise.resolve(this.#emit({
          mediaKind: kind,
          videoSourceKind: source,
          streamId: encodedStreamId,
          timestamp: wireTimestamp(chunk.timestamp),
          keyframe: kind === "audio" || chunk.type === "key",
          bytes,
        })).catch(this.#onError);
      } catch (error) { this.#onError(error); }
    };
    const encodedStreamId = kind === "video" && source === "camera" &&
      this.#layeredCamera ? ucrCameraLayerStreamId(streamId, "full") : streamId;
    const onError = (error: Error) => this.#onError(error);
    const encoder = kind === "audio"
      ? new b.AudioEncoder!({output: emitChunkFor(encodedStreamId), error: onError})
      : new b.VideoEncoder!({output: emitChunkFor(encodedStreamId), error: onError});
    if (kind === "audio") {
      encoder.configure({codec: AUDIO_CODEC, sampleRate: AUDIO_RATE,
        numberOfChannels: AUDIO_CHANNELS, bitrate: 32_000});
    } else {
      const settings = track.getSettings();
      const width = settings.width ?? VIDEO_WIDTH;
      const height = settings.height ?? VIDEO_HEIGHT;
      const quality = ucrVideoEncodingTarget(width, height);
      encoder.configure({codec: VIDEO_CODEC,
        width, height,
        framerate: Math.min(
          Math.max(1, settings.frameRate ?? VIDEO_FRAMERATE), quality.frameRate,
        ),
        bitrate: quality.bitrate, latencyMode: "realtime"});
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
          latencyMode: "realtime",
        });
        this.#encoders.push(lowEncoder);
      }
    }
    const reader = processor.readable.getReader();
    this.#readers.push(reader);
    const pump = async () => {
      let count = 0;
      let lowCount = 0;
      let lastLowTimestamp = -LOW_CAMERA_INTERVAL_US;
      while (generation === this.#generation) {
        const result = await reader.read();
        if (result.done) break;
        const frame = result.value;
        try {
          if (ucrCodecCanEnqueue(kind, encoder.encodeQueueSize)) {
            encoder.encode(frame, kind === "video" ? {keyFrame: count++ % 60 === 0} : undefined);
          }
          if (lowEncoder && lowCanvas && generation === this.#generation &&
              ucrCodecCanEnqueue("video", lowEncoder.encodeQueueSize) &&
              frame.timestamp - lastLowTimestamp >= LOW_CAMERA_INTERVAL_US) {
            const context = lowCanvas.getContext("2d");
            if (!context) throw new Error("layered capture canvas unavailable");
            context.drawImage(frame as VideoFrame, 0, 0, LOW_CAMERA_WIDTH, LOW_CAMERA_HEIGHT);
            const downscaled = new VideoFrame(lowCanvas, {timestamp: frame.timestamp});
            try {
              lowEncoder.encode(downscaled, {keyFrame: lowCount++ % 24 === 0});
              lastLowTimestamp = frame.timestamp;
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
  // WebAudio mixes independent AudioBufferSources automatically. Only frames
  // from the SAME authenticated audio stream must be sequenced; a global clock
  // serializes different speakers and makes conferences fall behind real time.
  readonly #nextAudioTime = new Map<string, number>();
  #videoEnabled = true;
  #renderGeneration = 0;
  #lowVideoPreferred = false;
  readonly #activeVideoStreams = new Map<string, string>();
  readonly #pendingVideoStreams = new Map<string, {streamId: string; decoderKey: string}>();
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
    if (frame.mediaKind === "video" && !decoder && !frame.keyframe) return;
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
              (context as CanvasRenderingContext2D).drawImage(video, 0, 0, width, height);
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
            if (selectedSourceKey !== null) {
              const pending = this.#pendingVideoStreams.get(selectedSourceKey);
              if (pending?.streamId === selectedStreamId && pending.decoderKey === key) {
                this.#pendingVideoStreams.delete(selectedSourceKey);
                this.#decoders.delete(key);
                if (this.#pendingVisibleVideoDecoderKey === key) {
                  this.#pendingVisibleVideoDecoderKey = null;
                }
              }
            }
            this.#onError(error);
          },
        });
        decoder.configure({codec: VIDEO_CODEC});
      }
      this.#decoders.set(key, decoder);
    }
    const data = frame.bytes;
    const timestamp = Number(frame.timestamp);
    if (!Number.isSafeInteger(timestamp)) throw new Error("media timestamp exceeds browser bounds");
    if (frame.mediaKind === "audio") {
      decoder.decode(new b.EncodedAudioChunk!({type: "key", timestamp, data}));
    } else {
      try {
        decoder.decode(new b.EncodedVideoChunk!({
          type: frame.keyframe ? "key" : "delta", timestamp, data,
        }));
      } catch (error) {
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
    try {
      const context = this.#audioContext!;
      const buffer = context.createBuffer(data.numberOfChannels, data.numberOfFrames, data.sampleRate);
      for (let ch = 0; ch < data.numberOfChannels; ch++) {
        const pcm = new Float32Array(data.numberOfFrames);
        data.copyTo(pcm, {planeIndex: ch, format: "f32-planar"});
        buffer.copyToChannel(pcm, ch);
      }
      const node = context.createBufferSource();
      node.buffer = buffer;
      node.connect(context.destination);
      const start = Math.max(context.currentTime, this.#nextAudioTime.get(streamKey) ?? context.currentTime);
      node.start(start);
      this.#nextAudioTime.set(streamKey, start + buffer.duration);
    } catch (error) { this.#onError(error); }
    finally { data.close(); }
  }

  stop(): void {
    ++this.#renderGeneration;
    for (const decoder of this.#decoders.values()) decoder.close();
    this.#decoders.clear();
    this.#pendingVideoStreams.clear();
    this.#activeVideoStreams.clear();
    this.#visibleVideoDecoderKey = null;
    this.#pendingVisibleVideoDecoderKey = null;
    this.#visibleVideoKind = null;
    this.#lastScreenVideoAt = 0;
    this.#videoEnabled = true;
    this.#lowVideoPreferred = false;
    this.#nextAudioTime.clear();
  }
}
