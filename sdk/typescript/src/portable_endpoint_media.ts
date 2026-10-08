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
  /** Optional on older deployed bridges; required for bridge-level fail-closed revocation. */
  revoke?(): void;
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
  /** Expected authenticated conference scope, obtained at canonical join. */
  readonly binding?: Readonly<{ tenantId: string; namespaceId: string | null; callId: string; groupId: string; cryptoEpoch: bigint; negotiationRef: string; negotiationGeneration: bigint }>;
  /** Call on leave/revocation/rekey before accepting or sending another frame. */
  readonly authorizeFrame?: (header: SfuForwardEnvelopeWire["frame"]["header"]) => boolean | Promise<boolean>;
  /** Locally cached canonical publish grant; must be updated on revocation/epoch change. */
  readonly authorizePublish?: (frame: UcrEncodedMediaFrame) => boolean | Promise<boolean>;
  readonly onError?: (error: unknown) => void;
}

type InboundHeader = SfuForwardEnvelopeWire["frame"]["header"];

export class UcrPortableEndpointMediaAdapter implements UcrEndpointE2eeAdapterV1 {
  readonly contractVersion = UCR_ENDPOINT_E2EE_CONTRACT_VERSION;
  readonly #bridge: UcrGroupMediaCryptoBridge;
  readonly #producer: UcrMediaProducer;
  readonly #consumer: UcrMediaConsumer;
  readonly #trustedKeys: UcrTrustedSourceKeys;
  readonly #binding: UcrEndpointPipelineOptions["binding"];
  readonly #authorizeFrame: UcrEndpointPipelineOptions["authorizeFrame"];
  readonly #authorizePublish: NonNullable<UcrEndpointPipelineOptions["authorizePublish"]>;
  readonly #onError: (error: unknown) => void;
  readonly #maxFrameBytes: number;
  readonly #maxPendingFrames: number;
  readonly #maxReplayStreams: number;
  readonly #sequences = new Map<string, bigint>();
  readonly #received = new Map<string, bigint>();
  readonly #reserved = new Set<string>();
  #pending = 0;
  #active = false;
  #retired = false;
  #generation = 0;
  #sender: ((wire: Uint8Array) => void) | null = null;

  constructor(options: UcrEndpointPipelineOptions) {
    this.#bridge = options.bridge;
    this.#producer = options.producer;
    this.#consumer = options.consumer;
    this.#trustedKeys = options.trustedKeys;
    if (!options.binding || !options.authorizeFrame || !options.authorizePublish) {
      throw new Error("canonical call binding and bidirectional live media authorization are required");
    }
    this.#binding = options.binding;
    this.#authorizeFrame = options.authorizeFrame;
    this.#authorizePublish = options.authorizePublish;
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
    if (this.#retired) throw new Error("endpoint media bridge retired; create a new authorized MLS bridge");
    if (this.#active) throw new Error("endpoint media already started");
    this.#active = true;
    const generation = ++this.#generation;
    this.#sender = input.sendEnvelope;
    try {
      await this.#producer.start(input, (frame) => this.#sendFrame(frame, generation));
    } catch (error) {
      this.#active = false;
      this.#retired = true;
      this.#sender = null;
      this.#generation++;
      this.#bridge.revoke?.();
      try {
        await Promise.all([this.#producer.stop(), this.#consumer.stop()]);
      } catch (cleanupError) {
        this.#onError(cleanupError);
      }
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
      const binding = this.#binding;
      if (binding && (header.tenantId !== binding.tenantId ||
          header.namespaceId !== binding.namespaceId ||
          header.callId !== binding.callId ||
          header.groupId !== binding.groupId ||
          header.cryptoEpoch !== binding.cryptoEpoch ||
          header.negotiationRef !== binding.negotiationRef ||
          header.negotiationGeneration !== binding.negotiationGeneration)) {
        throw new Error("encrypted media outside authenticated conference binding");
      }
      const replayKey = [header.tenantId, header.callId, header.groupId,
        header.source.principalId, header.sourceDeviceId, header.cryptoEpoch.toString(),
        header.streamId].join("\u0000");
      const last = this.#received.get(replayKey);
      const reservation = replayKey + "\u0000" + header.sequence.toString();
      if ((last !== undefined && header.sequence <= last) || this.#reserved.has(reservation)) {
        throw new Error("replayed endpoint media frame");
      }
      if (this.#reserved.size >= this.#maxPendingFrames) {
        throw new Error("endpoint verification queue capacity exceeded");
      }
      this.#reserved.add(reservation);
      try {
      if (this.#authorizeFrame && !(await this.#authorizeFrame(header))) {
        throw new Error("media recipient or source authorization revoked");
      }
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
      const latest = this.#received.get(replayKey);
      if (latest !== undefined && header.sequence <= latest) {
        throw new Error("replayed endpoint media frame");
      }
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
        this.#reserved.delete(reservation);
      }
    } finally {
      this.#pending--;
    }
  }

  async stop(): Promise<void> {
    if (!this.#active) return;
    this.#active = false;
    this.#retired = true;
    this.#generation++;
    this.#sender = null;
    this.#sequences.clear();
    this.#received.clear();
    this.#reserved.clear();
    // Retire the endpoint's cryptographic bridge before asynchronous media cleanup.
    // A revoked bridge must never be reused for a resumed call or a new MLS epoch.
    this.#bridge.revoke?.();
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
      if (!(await this.#authorizePublish(frame))) {
        throw new Error("media publish authorization revoked");
      }
      if (!this.#active || generation !== this.#generation) return;
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
