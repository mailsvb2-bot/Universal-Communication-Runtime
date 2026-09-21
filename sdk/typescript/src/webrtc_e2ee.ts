import {
  encodeSfuForwardEnvelopeWire,
  type SfuForwardEnvelopeWire,
} from "./sfu_forward_wire.ts";

export const UCR_WEBRTC_E2EE_DATA_CHANNEL_LABEL = "ucr.e2ee.media.v1" as const;
export const UCR_WEBRTC_E2EE_DATA_MESSAGE_BYTES = 16_000;
export const UCR_WEBRTC_E2EE_MAX_WIRE_BYTES = 2 * 1024 * 1024 + 8_192;

const CHUNK_MAGIC = "UCRCHK01";
const CHUNK_HEADER_BYTES = 24;
const CHUNK_PAYLOAD_BYTES = UCR_WEBRTC_E2EE_DATA_MESSAGE_BYTES - CHUNK_HEADER_BYTES;

export interface BinaryDataChannel {
  readonly label: string;
  readonly readyState: string;
  binaryType?: string;
  send(data: Uint8Array): void;
}

export type EncryptedEnvelopeHandler = (wireEnvelope: Uint8Array) => void | Promise<void>;

interface PendingMessage {
  readonly messageId: bigint;
  readonly chunkCount: number;
  readonly totalLength: number;
  nextChunkIndex: number;
  received: number;
  readonly parts: Uint8Array[];
}

/**
 * Browser/native-web transport framing for already-encrypted canonical UCR media envelopes.
 *
 * This helper owns no identity, conference, SFU, MLS, key schedule, encryption or decryption
 * policy. Callers provide ciphertext produced by the endpoint crypto owner and receive unchanged
 * ciphertext for endpoint opening.
 */
export class UcrWebRtcE2eeTransport {
  readonly #channel: BinaryDataChannel;
  readonly #onEnvelope: EncryptedEnvelopeHandler;
  #nextMessageId = 1n;
  #pending: PendingMessage | null = null;

  constructor(channel: BinaryDataChannel, onEnvelope: EncryptedEnvelopeHandler) {
    if (channel.label !== UCR_WEBRTC_E2EE_DATA_CHANNEL_LABEL) {
      throw new Error("unexpected UCR E2EE DataChannel label");
    }
    this.#channel = channel;
    this.#onEnvelope = onEnvelope;
    if ("binaryType" in channel) {
      channel.binaryType = "arraybuffer";
    }
  }

  sendCanonicalEnvelope(envelope: SfuForwardEnvelopeWire): void {
    this.sendEnvelope(encodeSfuForwardEnvelopeWire(envelope));
  }

  sendEnvelope(wireEnvelope: Uint8Array): void {
    if (this.#channel.readyState !== "open") {
      throw new Error("UCR E2EE DataChannel is not open");
    }
    if (
      wireEnvelope.byteLength === 0 ||
      wireEnvelope.byteLength > UCR_WEBRTC_E2EE_MAX_WIRE_BYTES
    ) {
      throw new Error("encrypted media envelope exceeds transport bounds");
    }

    const chunkCount = Math.ceil(wireEnvelope.byteLength / CHUNK_PAYLOAD_BYTES);
    if (chunkCount > 0xffff) {
      throw new Error("encrypted media envelope requires too many chunks");
    }

    const messageId = this.#nextMessageId++;
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
      const start = chunkIndex * CHUNK_PAYLOAD_BYTES;
      const end = Math.min(wireEnvelope.byteLength, start + CHUNK_PAYLOAD_BYTES);
      const chunk = new Uint8Array(CHUNK_HEADER_BYTES + end - start);
      writeAscii(chunk, 0, CHUNK_MAGIC);
      const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      view.setBigUint64(8, messageId, false);
      view.setUint16(16, chunkIndex, false);
      view.setUint16(18, chunkCount, false);
      view.setUint32(20, wireEnvelope.byteLength, false);
      chunk.set(wireEnvelope.subarray(start, end), CHUNK_HEADER_BYTES);
      this.#channel.send(chunk);
    }
  }

  async receiveChunk(data: ArrayBuffer | Uint8Array): Promise<boolean> {
    try {
      const complete = this.#reassemble(data);
      if (complete === null) {
        return false;
      }
      await this.#onEnvelope(complete);
      return true;
    } catch (error) {
      this.#pending = null;
      throw error;
    }
  }

  reset(): void {
    this.#pending = null;
  }

  #reassemble(data: ArrayBuffer | Uint8Array): Uint8Array | null {
    const bytes =
      data instanceof Uint8Array
        ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
        : new Uint8Array(data);

    if (
      bytes.byteLength < CHUNK_HEADER_BYTES ||
      bytes.byteLength > UCR_WEBRTC_E2EE_DATA_MESSAGE_BYTES
    ) {
      throw new Error("invalid encrypted media chunk size");
    }
    if (readAscii(bytes, 0, 8) !== CHUNK_MAGIC) {
      throw new Error("invalid encrypted media chunk");
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const messageId = view.getBigUint64(8, false);
    const chunkIndex = view.getUint16(16, false);
    const chunkCount = view.getUint16(18, false);
    const totalLength = view.getUint32(20, false);

    if (
      chunkCount === 0 ||
      chunkIndex >= chunkCount ||
      totalLength === 0 ||
      totalLength > UCR_WEBRTC_E2EE_MAX_WIRE_BYTES
    ) {
      throw new Error("invalid encrypted media chunk header");
    }

    const payload = bytes.slice(CHUNK_HEADER_BYTES);
    if (chunkIndex === 0) {
      if (this.#pending !== null) {
        throw new Error("overlapping encrypted media messages");
      }
      this.#pending = {
        messageId,
        chunkCount,
        totalLength,
        nextChunkIndex: 0,
        received: 0,
        parts: [],
      };
    }

    const pending = this.#pending;
    if (
      pending === null ||
      pending.messageId !== messageId ||
      pending.chunkCount !== chunkCount ||
      pending.totalLength !== totalLength ||
      pending.nextChunkIndex !== chunkIndex
    ) {
      throw new Error("out-of-order encrypted media chunk");
    }

    pending.parts.push(payload);
    pending.received += payload.byteLength;
    pending.nextChunkIndex += 1;
    if (pending.received > pending.totalLength) {
      throw new Error("oversized encrypted media message");
    }
    if (pending.nextChunkIndex !== pending.chunkCount) {
      return null;
    }

    this.#pending = null;
    if (pending.received !== pending.totalLength) {
      throw new Error("incomplete encrypted media message");
    }

    const wireEnvelope = new Uint8Array(pending.totalLength);
    let offset = 0;
    for (const part of pending.parts) {
      wireEnvelope.set(part, offset);
      offset += part.byteLength;
    }
    return wireEnvelope;
  }
}

function readAscii(bytes: Uint8Array, start: number, length: number): string {
  let value = "";
  for (let index = 0; index < length; index += 1) {
    value += String.fromCharCode(bytes[start + index]);
  }
  return value;
}

function writeAscii(bytes: Uint8Array, start: number, value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    bytes[start + index] = value.charCodeAt(index);
  }
}
