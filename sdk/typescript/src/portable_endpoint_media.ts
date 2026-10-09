import {
  UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  type UcrEndpointE2eeAdapterV1,
  type UcrEndpointE2eeStartInput,
  type UcrEndpointMediaSources,
  type UcrEndpointAdaptiveQualityV1,
  type UcrVerifiedReceiveVideoStream,
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
  /** Required: retiring a call must permanently revoke this Rust/WASM epoch bridge. */
  revoke(): void;
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
  /** Local authenticated-receiver quality control only; never changes the shared sender. */
  setReceiveQuality?(target: UcrEndpointAdaptiveQualityV1): void | Promise<void>;
  getActiveReceiveVideoStreams?(): readonly UcrVerifiedReceiveVideoStream[];
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
  /** Actual subscriber-side measurements supplied by the trusted host; never estimated/faked here. */
  readonly measureReceiveTelemetry?: () => unknown | Promise<unknown>;
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
  readonly #measureReceiveTelemetry: UcrEndpointPipelineOptions["measureReceiveTelemetry"];
  readonly #maxFrameBytes: number;
  readonly #maxPendingFrames: number;
  readonly #maxReplayStreams: number;
  readonly #sequences = new Map<string, bigint>();
  readonly #received = new Map<string, bigint>();
  readonly #reserved = new Set<string>();
  // Auth/key lookups are asynchronous. Preserve ciphertext DataChannel arrival
  // order PER verified stream while allowing distinct speakers to progress in
  // parallel. Bounded by #pending/#maxPendingFrames, never a global queue.
  readonly #receiveTails = new Map<string, Promise<void>>();
  /** Endpoint-only, bounded authenticated video layer observations. */
  readonly #verifiedVideoStreams = new Map<string, UcrVerifiedReceiveVideoStream>();
  // Serialize emission for each stream: concurrent async authorization must never
  // reuse a media sequence/nonce or reorder authenticated frames.
  readonly #sendTails = new Map<string, Promise<void>>();
  #pending = 0;
  #pendingOutbound = 0;
  #active = false;
  #retired = false;
  #generation = 0;
  #sender: ((wire: Uint8Array) => void) | null = null;

  constructor(options: UcrEndpointPipelineOptions) {
    if (!options.bridge || typeof options.bridge.revoke !== "function") {
      throw new Error("endpoint media bridge must support permanent revocation");
    }
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
    this.#measureReceiveTelemetry = options.measureReceiveTelemetry;
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
      try {
        this.#bridge.revoke();
      } catch (revokeError) {
        this.#onError(revokeError);
      }
      const cleanup = await Promise.allSettled([
        Promise.resolve().then(() => this.#producer.stop()),
        Promise.resolve().then(() => this.#consumer.stop()),
      ]);
      for (const result of cleanup) {
        if (result.status === "rejected") this.#onError(result.reason);
      }
      throw error;
    }
  }

  async updateSources(sources: UcrEndpointMediaSources): Promise<void> {
    if (!this.#active) throw new Error("endpoint media not started");
    if (!this.#producer.updateSources) throw new Error("media source updates unsupported by platform producer");
    await this.#producer.updateSources(sources);
  }

  /** No placeholder CPU/battery/thermal metrics: absent measurement means no report. */
  async getReceiveMediaTelemetry(): Promise<unknown> {
    if (!this.#active || this.#retired || !this.#measureReceiveTelemetry) return null;
    const generation = this.#generation;
    const value = await this.#measureReceiveTelemetry();
    return this.#active && !this.#retired && this.#generation === generation ? value : null;
  }

  getVerifiedReceiveVideoStreams(): readonly UcrVerifiedReceiveVideoStream[] {
    return this.#active && !this.#retired ? [...this.#verifiedVideoStreams.values()] : [];
  }

  getActiveReceiveVideoStreams(): readonly UcrVerifiedReceiveVideoStream[] {
    if (!this.#active || this.#retired) return [];
    return this.#consumer.getActiveReceiveVideoStreams?.() ?? [];
  }

  /** Applies only local decoder/receive policy, after canonical authorization and MLS binding.
   * The caller must never interpret this as publisher encoding or permission authority.
   */
  async applyReceiveMediaDecision(target: UcrEndpointAdaptiveQualityV1): Promise<void> {
    if (!this.#active || this.#retired) throw new Error("protected endpoint media is not active");
    if (!this.#consumer.setReceiveQuality) {
      throw new Error("receiver does not support adaptive media quality");
    }
    const generation = this.#generation;
    await this.#consumer.setReceiveQuality(target);
    if (!this.#active || this.#generation !== generation) {
      throw new Error("protected receive quality change cancelled by session retirement");
    }
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
        header.mediaKind, header.videoSourceKind ?? "", header.streamId].join("\u0000");
      const last = this.#received.get(replayKey);
      const reservation = replayKey + "\u0000" + header.sequence.toString();
      if ((last !== undefined && header.sequence <= last) || this.#reserved.has(reservation)) {
        throw new Error("replayed endpoint media frame");
      }
      if (this.#reserved.size >= this.#maxPendingFrames) {
        throw new Error("endpoint verification queue capacity exceeded");
      }
      this.#reserved.add(reservation);
      const previous = this.#receiveTails.get(replayKey) ?? Promise.resolve();
      const current: Promise<void> = previous.catch(() => {}).then(async () => {
      if (!this.#active || this.#generation !== generation) return;
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
      if (this.#active && this.#generation === generation &&
          header.mediaKind === "video" && header.videoSourceKind === "camera") {
        const metadata: UcrVerifiedReceiveVideoStream = {
          sourceId: header.source.principalId,
          sourceDeviceId: header.sourceDeviceId,
          streamId: header.streamId,
        };
        const id = JSON.stringify([metadata.sourceId, metadata.sourceDeviceId, metadata.streamId]);
        if (this.#verifiedVideoStreams.has(id) || this.#verifiedVideoStreams.size < 128) {
          this.#verifiedVideoStreams.set(id, metadata);
        }
      }
      });
      this.#receiveTails.set(replayKey, current);
      try {
        await current;
      } finally {
        this.#reserved.delete(reservation);
        if (this.#receiveTails.get(replayKey) === current) {
          this.#receiveTails.delete(replayKey);
        }
      }
    } finally {
      this.#pending--;
    }
  }

  async stop(): Promise<void> {
    // The installer can be cancelled before start() runs. Retire the Rust/WASM
    // media bridge even in that state: a late async installer must not leave a
    // live, never-started epoch signer behind after admission withdrawal.
    if (this.#retired) return;
    this.#active = false;
    this.#retired = true;
    this.#generation++;
    this.#sender = null;
    this.#sequences.clear();
    this.#received.clear();
    this.#reserved.clear();
    this.#receiveTails.clear();
    this.#verifiedVideoStreams.clear();
    this.#sendTails.clear();
    // Retire crypto BEFORE asynchronous media cleanup. A revocation failure
    // cannot skip microphone/camera/decoder teardown or keep this adapter active.
    let stopError: unknown;
    try {
      this.#bridge.revoke();
    } catch (error) {
      stopError = error;
    }
    const cleanup = await Promise.allSettled([
        Promise.resolve().then(() => this.#producer.stop()),
        Promise.resolve().then(() => this.#consumer.stop()),
      ]);
    for (const result of cleanup) {
      if (result.status === "rejected" && stopError === undefined) {
        stopError = result.reason;
      }
    }
    if (stopError !== undefined) throw stopError;
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
    if (this.#pendingOutbound >= this.#maxPendingFrames) {
      this.#onError(new Error("outbound endpoint media queue capacity exceeded"));
      return;
    }
    const videoSourceCode = frame.mediaKind === "audio" ? 0 :
      frame.videoSourceKind === "screen_share" ? 2 : 1;
    const streamKey = [frame.mediaKind, videoSourceCode, frame.streamId].join(":");
    // A codec/producer may recycle its output buffer as soon as emit() returns.
    // Keep an owned, bounded snapshot until the authorization queue drains.
    const ownedFrame = {...frame, bytes: frame.bytes.slice()};
    const previous = this.#sendTails.get(streamKey) ?? Promise.resolve();
    this.#pendingOutbound++;
    const current: Promise<void> = previous.then(async () => {
      if (!this.#active || generation !== this.#generation) return;
      if (!(await this.#authorizePublish(ownedFrame))) {
        throw new Error("media publish authorization revoked");
      }
      if (!this.#active || generation !== this.#generation) return;
      const sequence = (this.#sequences.get(streamKey) ?? 0n) + 1n;
      if (sequence > 18_446_744_073_709_551_615n) {
        throw new Error("media sequence exhausted; rotate session");
      }
      if (!this.#sequences.has(streamKey) && this.#sequences.size >= this.#maxReplayStreams) {
        throw new Error("outbound stream capacity exceeded");
      }
      // Reserve BEFORE encryption: even a crypto or transport error must never
      // allow a previously used sequence/nonce to be retried with new plaintext.
      this.#sequences.set(streamKey, sequence);
      const wire = this.#bridge.seal_wire(
        ownedFrame.streamId, ownedFrame.mediaKind === "audio" ? 1 : 2,
        videoSourceCode, sequence, ownedFrame.timestamp, ownedFrame.keyframe, ownedFrame.bytes,
      );
      if (!(wire instanceof Uint8Array) || wire.byteLength > this.#maxFrameBytes + 8_192) {
        throw new Error("encrypted media exceeds transport bounds");
      }
      if (!this.#active || generation !== this.#generation) return;
      this.#sender?.(wire);
    }).catch((error: unknown) => {
      this.#onError(error);
    }).finally(() => {
      this.#pendingOutbound--;
      if (this.#sendTails.get(streamKey) === current) {
        this.#sendTails.delete(streamKey);
      }
    });
    this.#sendTails.set(streamKey, current);
    await current;
  }
}

export function createUcrPortableEndpointMediaAdapter(
  options: UcrEndpointPipelineOptions,
): UcrEndpointE2eeAdapterV1 {
  return new UcrPortableEndpointMediaAdapter(options);
}
