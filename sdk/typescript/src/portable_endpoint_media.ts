import {
  UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  type UcrEndpointE2eeAdapterV1,
  type UcrEndpointE2eeStartInput,
  type UcrEndpointMediaSources,
} from "./endpoint_e2ee.ts";
import {
  decodeSfuForwardEnvelopeWire,
  type SfuForwardEnvelopeWire,
  type MediaKind,
  type VideoSourceKind,
} from "./sfu_forward_wire.ts";

/**
 * Platform-independent endpoint media pipeline.
 *
 * The Rust/WASM MLS bridge is the sole owner of authenticated group-media cryptography.
 * Encoders/capture/playback are injected by the host (browser, mobile, desktop, native).
 * No server-side plaintext, alternate encryption protocol, or platform-specific key store.
 */
export interface UcrGroupMediaCryptoBridge {
  seal_wire(
    streamId: string,
    mediaKind: number,
    videoSourceKind: number,
    sequence: bigint,
    timestamp: bigint,
    keyframe: boolean,
    plaintext: Uint8Array,
  ): Uint8Array;
  open_wire(wire: Uint8Array, sourceVerifyingKey: Uint8Array): Uint8Array;
}

export interface UcrEncodedMediaFrame {
  readonly mediaKind: MediaKind;
  readonly videoSourceKind?: VideoSourceKind;
  readonly streamId: string;
  readonly timestamp: bigint;
  readonly keyframe: boolean;
  readonly bytes: Uint8Array;
}

export interface UcrMediaProducer {
  start(
    sources: UcrEndpointMediaSources,
    emit: (frame: UcrEncodedMediaFrame) => void | Promise<void>,
  ): void | Promise<void>;
  updateSources?(sources: UcrEndpointMediaSources): void | Promise<void>;
  stop(): void | Promise<void>;
}

export interface UcrMediaConsumer {
  play(frame: UcrEncodedMediaFrame, source: SfuForwardEnvelopeWire["frame"]["header"]): void | Promise<void>;
  stop(): void | Promise<void>;
}

export interface UcrTrustedSourceKeys {
  /** Resolve trusted current device signing key from canonical identity/MLS membership state. */
  resolve(header: SfuForwardEnvelopeWire["frame"]["header"], keyId: string): Uint8Array | Promise<Uint8Array>;
}

export interface UcrEndpointPipelineOptions {
  readonly bridge: UcrGroupMediaCryptoBridge;
  readonly producer: UcrMediaProducer;
  readonly consumer: UcrMediaConsumer;
  readonly trustedKeys: UcrTrustedSourceKeys;
  readonly maxFrameBytes?: number;
  readonly maxPendingFrames?: number;
  readonly maxReplayStreams?: number;
  readonly onError?: (error: unknown) => void;
}

type InboundHeader = SfuForwardEnvelopeWire["frame"]["header"];

export class UcrPortableEndpointMediaAdapter implements UcrEndpointE2eeAdapterV1 {
  readonly contractVersion = UCR_ENDPOINT_E2EE_CONTRACT_VERSION;
  readonly #bridge: UcrGroupMediaCryptoBridge;
  readonly #producer: UcrMediaProducer;
  readonly #consumer: UcrMediaConsumer;
  readonly #trustedKeys: UcrTrustedSourceKeys;
  readonly #onError: (error: unknown) => void;
  readonly #maxFrameBytes: number;
  readonly #maxPendingFrames: number;
  readonly #maxReplayStreams: number;
  readonly #sequences = new Map<string, bigint>();
  readonly #received = new Map<string, bigint>();
  #pending = 0;
  #active = false;
  #generation = 0;
  #sender: ((wire: Uint8Array) => void) | null = null;

  constructor(options: UcrEndpointPipelineOptions) {
    this.#bridge = options.bridge;
    this.#producer = options.producer;
    this.#consumer = options.consumer;
    this.#trustedKeys = options.trustedKeys;
    this.#onError = options.onError ?? (() => {});
    this.#maxFrameBytes = options.maxFrameBytes ?? 1_048_576;
    this.#maxPendingFrames = options.maxPendingFrames ?? 64;
    this.#maxReplayStreams = options.maxReplayStreams ?? 4_096;
    if (!Number.isSafeInteger(this.#maxFrameBytes) || this.#maxFrameBytes < 1 ||
        !Number.isSafeInteger(this.#maxPendingFrames) || this.#maxPendingFrames < 1 ||
        !Number.isSafeInteger(this.#maxReplayStreams) || this.#maxReplayStreams < 1) {
      throw new Error("invalid endpoint media bounds");
    }
  }

  async start(input: UcrEndpointE2eeStartInput): Promise<void> {
    if (this.#active) throw new Error("endpoint media already started");
    this.#active = true;
    const generation = ++this.#generation;
    this.#sender = input.sendEnvelope;
    try {
      await this.#producer.start(input, (frame) => this.#sendFrame(frame, generation));
    } catch (error) {
      this.#active = false;
      this.#sender = null;
      this.#generation++;
      await this.#producer.stop();
      throw error;
    }
  }

  async updateSources(sources: UcrEndpointMediaSources): Promise<void> {
    if (!this.#active) throw new Error("endpoint media not started");
    if (!this.#producer.updateSources) throw new Error("media source updates unsupported by platform producer");
    await this.#producer.updateSources(sources);
  }

  async onEnvelope(wire: Uint8Array): Promise<void> {
    if (!this.#active) return;
    if (!(wire instanceof Uint8Array) || wire.byteLength === 0 ||
        wire.byteLength > this.#maxFrameBytes + 8_192) {
      throw new Error("invalid encrypted endpoint frame size");
    }
    if (this.#pending >= this.#maxPendingFrames) {
      throw new Error("endpoint receive queue capacity exceeded");
    }
    this.#pending++;
    const generation = this.#generation;
    try {
      const envelope = decodeSfuForwardEnvelopeWire(wire);
      const header = envelope.frame.header;
      const replayKey = [header.tenantId, header.callId, header.groupId,
        header.source.principalId, header.sourceDeviceId, header.cryptoEpoch.toString(),
        header.streamId].join("\u0000");
      const last = this.#received.get(replayKey);
      if (last !== undefined && header.sequence <= last) throw new Error("replayed endpoint media frame");
      const key = await this.#trustedKeys.resolve(header, envelope.frame.sourceSignature.keyId);
      if (!(key instanceof Uint8Array) || key.byteLength !== 32) throw new Error("untrusted endpoint signing key");
      if (!this.#active || this.#generation !== generation) return;
      const plaintext = this.#bridge.open_wire(wire, key);
      if (!(plaintext instanceof Uint8Array) || plaintext.byteLength > this.#maxFrameBytes) {
        throw new Error("invalid decrypted media payload");
      }
      if (!this.#received.has(replayKey) && this.#received.size >= this.#maxReplayStreams) {
        throw new Error("endpoint replay-stream capacity exceeded");
      }
      if (!this.#active || this.#generation !== generation) return;
      this.#received.set(replayKey, header.sequence);
      await this.#consumer.play({
        mediaKind: header.mediaKind,
        videoSourceKind: header.videoSourceKind ?? undefined,
        streamId: header.streamId,
        timestamp: header.mediaTimestamp,
        keyframe: header.keyframe,
        bytes: plaintext,
      }, header);
    } finally {
      this.#pending--;
    }
  }

  async stop(): Promise<void> {
    if (!this.#active) return;
    this.#active = false;
    this.#generation++;
    this.#sender = null;
    this.#sequences.clear();
    this.#received.clear();
    await Promise.all([this.#producer.stop(), this.#consumer.stop()]);
  }

  async #sendFrame(frame: UcrEncodedMediaFrame, generation: number): Promise<void> {
    if (!this.#active || generation !== this.#generation) return;
    if (!(frame.bytes instanceof Uint8Array) || frame.bytes.length === 0 ||
        frame.bytes.length > this.#maxFrameBytes) {
      this.#onError(new Error("outbound encoded media exceeds bound"));
      return;
    }
    if (!frame.streamId || frame.timestamp < 0n ||
        (frame.mediaKind !== "audio" && frame.mediaKind !== "video")) {
      this.#onError(new Error("invalid encoded media metadata"));
      return;
    }
    const videoSourceCode = frame.mediaKind === "audio" ? 0 :
      frame.videoSourceKind === "screen_share" ? 2 : 1;
    const streamKey = [frame.mediaKind, videoSourceCode, frame.streamId].join(":");
    const sequence = (this.#sequences.get(streamKey) ?? 0n) + 1n;
    if (sequence > 18_446_744_073_709_551_615n) {
      this.#onError(new Error("media sequence exhausted; rotate session"));
      return;
    }
    if (!this.#sequences.has(streamKey) && this.#sequences.size >= this.#maxReplayStreams) {
      this.#onError(new Error("outbound stream capacity exceeded"));
      return;
    }
    try {
      const wire = this.#bridge.seal_wire(
        frame.streamId, frame.mediaKind === "audio" ? 1 : 2,
        videoSourceCode, sequence, frame.timestamp, frame.keyframe, frame.bytes,
      );
      if (!(wire instanceof Uint8Array) || wire.byteLength > this.#maxFrameBytes + 8_192) {
        throw new Error("encrypted media exceeds transport bounds");
      }
      if (!this.#active || generation !== this.#generation) return;
      this.#sender?.(wire);
      this.#sequences.set(streamKey, sequence);
    } catch (error) {
      this.#onError(error);
    }
  }
}

export function createUcrPortableEndpointMediaAdapter(
  options: UcrEndpointPipelineOptions,
): UcrEndpointE2eeAdapterV1 {
  return new UcrPortableEndpointMediaAdapter(options);
}
