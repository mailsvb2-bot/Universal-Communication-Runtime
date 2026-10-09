import type {
  UcrEncodedMediaFrame,
  UcrMediaConsumer,
  UcrMediaProducer,
} from "./portable_endpoint_media.ts";
import type { UcrEndpointMediaSources } from "./endpoint_e2ee.ts";

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
const VIDEO_FRAMERATE = 15;
const MAX_CAPTURE_FRAME_BYTES = 1_048_576;
const MAX_VIDEO_ENCODER_QUEUE = 2;
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

  constructor(onError: (error: unknown) => void = () => {}) {
    this.#onError = onError;
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
    ++this.#generation;
    await this.#reset();
    await this.#attach(sources, this.#generation);
  }

  async stop(): Promise<void> {
    ++this.#generation;
    this.#emit = null;
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
    const emitChunk = (chunk: EncodedChunkLike) => {
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
          streamId,
          timestamp: wireTimestamp(chunk.timestamp),
          keyframe: kind === "audio" || chunk.type === "key",
          bytes,
        })).catch(this.#onError);
      } catch (error) { this.#onError(error); }
    };
    const onError = (error: Error) => this.#onError(error);
    const encoder = kind === "audio"
      ? new b.AudioEncoder!({output: emitChunk, error: onError})
      : new b.VideoEncoder!({output: emitChunk, error: onError});
    if (kind === "audio") {
      encoder.configure({codec: AUDIO_CODEC, sampleRate: AUDIO_RATE,
        numberOfChannels: AUDIO_CHANNELS, bitrate: 32_000});
    } else {
      const settings = track.getSettings();
      encoder.configure({codec: VIDEO_CODEC,
        width: settings.width ?? VIDEO_WIDTH,
        height: settings.height ?? VIDEO_HEIGHT,
        framerate: VIDEO_FRAMERATE, bitrate: 600_000});
    }
    this.#encoders.push(encoder);
    const reader = processor.readable.getReader();
    this.#readers.push(reader);
    const pump = async () => {
      let count = 0;
      while (generation === this.#generation) {
        const result = await reader.read();
        if (result.done) break;
        const frame = result.value;
        try {
          if (ucrCodecCanEnqueue(kind, encoder.encodeQueueSize)) {
            encoder.encode(frame, kind === "video" ? {keyFrame: count++ % 60 === 0} : undefined);
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
  #nextAudioTime = 0;

  constructor(options: UcrBrowserCodecOptions = {}) {
    this.#videoCanvas = options.videoCanvas;
    this.#audioContext = options.audioContext;
    this.#onError = options.onError ?? (() => {});
  }

  play(frame: UcrEncodedMediaFrame): void {
    const b = browser();
    if (!ucrWebCodecsSupported()) throw new Error("WebCodecs playback unavailable");
    const key = [frame.mediaKind, frame.videoSourceKind ?? "", frame.streamId].join(":");
    let decoder = this.#decoders.get(key);
    if (!decoder) {
      if (frame.mediaKind === "audio") {
        if (!this.#audioContext) throw new Error("audio playback context not provided");
        decoder = new b.AudioDecoder!({
          output: (data) => this.#playAudio(data),
          error: this.#onError,
        });
        decoder.configure({codec: AUDIO_CODEC, sampleRate: AUDIO_RATE, numberOfChannels: AUDIO_CHANNELS});
      } else {
        if (!this.#videoCanvas) throw new Error("video rendering canvas not provided");
        decoder = new b.VideoDecoder!({
          output: (video) => {
            try {
              const context = this.#videoCanvas!.getContext("2d");
              if (!context) throw new Error("video canvas 2D context unavailable");
              (context as CanvasRenderingContext2D).drawImage(video, 0, 0);
            } finally { video.close(); }
          },
          error: this.#onError,
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
      decoder.decode(new b.EncodedVideoChunk!({
        type: frame.keyframe ? "key" : "delta", timestamp, data,
      }));
    }
  }

  #playAudio(data: AudioData): void {
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
      const start = Math.max(context.currentTime, this.#nextAudioTime);
      node.start(start);
      this.#nextAudioTime = start + buffer.duration;
    } catch (error) { this.#onError(error); }
    finally { data.close(); }
  }

  stop(): void {
    for (const decoder of this.#decoders.values()) decoder.close();
    this.#decoders.clear();
    this.#nextAudioTime = 0;
  }
}
