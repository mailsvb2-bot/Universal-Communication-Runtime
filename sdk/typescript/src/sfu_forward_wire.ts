export const SFU_FORWARD_WIRE_MAGIC = "UCRE2EE1" as const;
export const SFU_FORWARD_WIRE_VERSION = 1 as const;
export const MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES = 2 * 1024 * 1024 + 16;
export const MAX_SFU_FORWARD_WIRE_BYTES = MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES + 8_192;

const MAX_ID_BYTES = 128;
const MAX_WIRE_STRING_BYTES = 256;
const NONCE_BYTES = 24;
const SIGNATURE_BYTES = 64;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export type PrincipalKind =
  | "person"
  | "device"
  | "service_account"
  | "ai_agent"
  | "bot"
  | "organization"
  | "automation"
  | "external_platform";
export type MediaKind = "audio" | "video";

export interface SfuForwardEnvelopeWire {
  readonly frame: {
    readonly header: {
      readonly tenantId: string;
      readonly namespaceId: string | null;
      readonly callId: string;
      readonly groupId: string;
      readonly streamId: string;
      readonly source: {
        readonly principalId: string;
        readonly kind: PrincipalKind;
      };
      readonly sourceDeviceId: string;
      readonly negotiationRef: string;
      readonly negotiationGeneration: bigint;
      readonly cryptoEpoch: bigint;
      readonly cryptoStateRef: string;
      readonly cryptoSuite: "ucr.v1";
      readonly mediaKind: MediaKind;
      readonly sequence: bigint;
      readonly mediaTimestamp: bigint;
      readonly keyframe: boolean;
    };
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly sourceSignature: {
      readonly keyId: string;
      readonly algorithmId: "ed25519";
      readonly algorithmVersion: 1;
      readonly signature: Uint8Array;
    };
  };
}

export function encodeSfuForwardEnvelopeWire(envelope: SfuForwardEnvelopeWire): Uint8Array {
  validateEnvelopeShape(envelope);
  const frame = envelope.frame;
  const writer = new WireWriter();
  writer.raw(textEncoder.encode(SFU_FORWARD_WIRE_MAGIC));
  writer.u8(SFU_FORWARD_WIRE_VERSION);
  writer.id(frame.header.tenantId);
  if (frame.header.namespaceId === null) {
    writer.u8(0);
  } else {
    writer.u8(1);
    writer.id(frame.header.namespaceId);
  }
  writer.id(frame.header.callId);
  writer.id(frame.header.groupId);
  writer.id(frame.header.streamId);
  writer.u8(principalKindCode(frame.header.source.kind));
  writer.id(frame.header.source.principalId);
  writer.id(frame.header.sourceDeviceId);
  writer.id(frame.header.negotiationRef);
  writer.u64(frame.header.negotiationGeneration);
  writer.u64(frame.header.cryptoEpoch);
  writer.id(frame.header.cryptoStateRef);
  writer.u8(1);
  writer.u8(mediaKindCode(frame.header.mediaKind));
  writer.u64(frame.header.sequence);
  writer.u64(frame.header.mediaTimestamp);
  writer.u8(frame.header.keyframe ? 1 : 0);
  writer.raw(frame.nonce);
  writer.bytesU32(frame.ciphertext);
  writer.id(frame.sourceSignature.keyId);
  writer.stringU16(frame.sourceSignature.algorithmId, MAX_WIRE_STRING_BYTES);
  writer.u32(frame.sourceSignature.algorithmVersion);
  writer.bytesU16(frame.sourceSignature.signature);
  const wire = writer.finish();
  if (wire.byteLength > MAX_SFU_FORWARD_WIRE_BYTES) {
    throw new Error("SFU forward envelope exceeds wire bound");
  }
  return wire;
}

export function decodeSfuForwardEnvelopeWire(bytes: Uint8Array): SfuForwardEnvelopeWire {
  if (bytes.byteLength > MAX_SFU_FORWARD_WIRE_BYTES) {
    throw new Error("SFU forward envelope exceeds wire bound");
  }
  const reader = new WireReader(bytes);
  const magic = textDecoder.decode(reader.take(SFU_FORWARD_WIRE_MAGIC.length));
  if (magic !== SFU_FORWARD_WIRE_MAGIC) {
    throw new Error("invalid SFU forward wire magic");
  }
  if (reader.u8() !== SFU_FORWARD_WIRE_VERSION) {
    throw new Error("unsupported SFU forward wire version");
  }
  const tenantId = reader.id();
  const namespaceMarker = reader.u8();
  const namespaceId =
    namespaceMarker === 0
      ? null
      : namespaceMarker === 1
        ? reader.id()
        : fail("invalid namespace marker");
  const callId = reader.id();
  const groupId = reader.id();
  const streamId = reader.id();
  const sourceKind = principalKindFromCode(reader.u8());
  const sourcePrincipalId = reader.id();
  const sourceDeviceId = reader.id();
  const negotiationRef = reader.id();
  const negotiationGeneration = reader.u64();
  const cryptoEpoch = reader.u64();
  const cryptoStateRef = reader.id();
  if (reader.u8() !== 1) {
    throw new Error("unsupported SFU forward crypto suite");
  }
  const mediaKind = mediaKindFromCode(reader.u8());
  const sequence = reader.u64();
  const mediaTimestamp = reader.u64();
  const keyframeCode = reader.u8();
  if (keyframeCode !== 0 && keyframeCode !== 1) {
    throw new Error("invalid SFU forward keyframe marker");
  }
  const nonce = reader.take(NONCE_BYTES);
  const ciphertext = reader.bytesU32(MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES);
  const keyId = reader.id();
  const algorithmId = reader.stringU16(MAX_WIRE_STRING_BYTES);
  if (algorithmId !== "ed25519") {
    throw new Error("unsupported SFU forward signature algorithm");
  }
  const algorithmVersion = reader.u32();
  if (algorithmVersion !== 1) {
    throw new Error("unsupported SFU forward signature version");
  }
  const signature = reader.bytesU16(SIGNATURE_BYTES);
  if (signature.byteLength !== SIGNATURE_BYTES || !reader.done()) {
    throw new Error("malformed SFU forward envelope");
  }

  const envelope: SfuForwardEnvelopeWire = {
    frame: {
      header: {
        tenantId,
        namespaceId,
        callId,
        groupId,
        streamId,
        source: { principalId: sourcePrincipalId, kind: sourceKind },
        sourceDeviceId,
        negotiationRef,
        negotiationGeneration,
        cryptoEpoch,
        cryptoStateRef,
        cryptoSuite: "ucr.v1",
        mediaKind,
        sequence,
        mediaTimestamp,
        keyframe: keyframeCode === 1,
      },
      nonce,
      ciphertext,
      sourceSignature: {
        keyId,
        algorithmId: "ed25519",
        algorithmVersion: 1,
        signature,
      },
    },
  };
  validateEnvelopeShape(envelope);
  return envelope;
}

function validateEnvelopeShape(envelope: SfuForwardEnvelopeWire): void {
  const { frame } = envelope;
  for (const id of [
    frame.header.tenantId,
    frame.header.callId,
    frame.header.groupId,
    frame.header.streamId,
    frame.header.source.principalId,
    frame.header.sourceDeviceId,
    frame.header.negotiationRef,
    frame.header.cryptoStateRef,
    frame.sourceSignature.keyId,
  ]) {
    validateId(id);
  }
  if (frame.header.namespaceId !== null) {
    validateId(frame.header.namespaceId);
  }
  requireU64(frame.header.negotiationGeneration);
  requireU64(frame.header.cryptoEpoch);
  requireU64(frame.header.sequence);
  requireU64(frame.header.mediaTimestamp);
  if (frame.header.negotiationGeneration === 0n || frame.header.cryptoEpoch === 0n) {
    throw new Error("invalid SFU forward epoch/negotiation");
  }
  if (frame.header.cryptoSuite !== "ucr.v1") {
    throw new Error("unsupported SFU forward crypto suite");
  }
  principalKindCode(frame.header.source.kind);
  mediaKindCode(frame.header.mediaKind);
  if (frame.header.mediaKind === "audio" && frame.header.keyframe) {
    throw new Error("audio SFU forward frames cannot be keyframes");
  }
  if (frame.nonce.byteLength !== NONCE_BYTES) {
    throw new Error("invalid SFU forward nonce length");
  }
  if (
    frame.ciphertext.byteLength === 0 ||
    frame.ciphertext.byteLength > MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES
  ) {
    throw new Error("invalid SFU forward ciphertext length");
  }
  if (
    frame.sourceSignature.algorithmId !== "ed25519" ||
    frame.sourceSignature.algorithmVersion !== 1 ||
    frame.sourceSignature.signature.byteLength !== SIGNATURE_BYTES
  ) {
    throw new Error("invalid SFU forward source signature metadata");
  }
}

function validateId(value: string): void {
  const bytes = textEncoder.encode(value);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_ID_BYTES) {
    throw new Error("invalid canonical opaque id");
  }
}

function requireU64(value: bigint): void {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error("value exceeds unsigned 64-bit wire range");
  }
}

function principalKindCode(kind: PrincipalKind): number {
  switch (kind) {
    case "person":
      return 1;
    case "device":
      return 2;
    case "service_account":
      return 3;
    case "ai_agent":
      return 4;
    case "bot":
      return 5;
    case "organization":
      return 6;
    case "automation":
      return 7;
    case "external_platform":
      return 8;
    default:
      throw new Error("invalid SFU forward principal kind");
  }
}

function principalKindFromCode(code: number): PrincipalKind {
  switch (code) {
    case 1:
      return "person";
    case 2:
      return "device";
    case 3:
      return "service_account";
    case 4:
      return "ai_agent";
    case 5:
      return "bot";
    case 6:
      return "organization";
    case 7:
      return "automation";
    case 8:
      return "external_platform";
    default:
      throw new Error("invalid SFU forward principal kind");
  }
}

function mediaKindCode(kind: MediaKind): number {
  if (kind === "audio") return 1;
  if (kind === "video") return 2;
  throw new Error("invalid SFU forward media kind");
}

function mediaKindFromCode(code: number): MediaKind {
  if (code === 1) return "audio";
  if (code === 2) return "video";
  throw new Error("invalid SFU forward media kind");
}

function fail(message: string): never {
  throw new Error(message);
}

class WireWriter {
  readonly #parts: Uint8Array[] = [];
  #length = 0;

  raw(value: Uint8Array): void {
    this.#parts.push(value);
    this.#length += value.byteLength;
  }

  u8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new Error("wire byte exceeds u8 range");
    }
    this.raw(Uint8Array.of(value));
  }

  u16(value: number): void {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, false);
    this.raw(bytes);
  }

  u32(value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.raw(bytes);
  }

  u64(value: bigint): void {
    requireU64(value);
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    this.raw(bytes);
  }

  id(value: string): void {
    validateId(value);
    this.bytesU16(textEncoder.encode(value));
  }

  stringU16(value: string, maximum: number): void {
    const bytes = textEncoder.encode(value);
    if (bytes.byteLength > maximum) {
      throw new Error("wire string exceeds bound");
    }
    this.bytesU16(bytes);
  }

  bytesU16(value: Uint8Array): void {
    if (value.byteLength > 0xffff) {
      throw new Error("wire bytes exceed u16 bound");
    }
    this.u16(value.byteLength);
    this.raw(value);
  }

  bytesU32(value: Uint8Array): void {
    if (value.byteLength > 0xffff_ffff) {
      throw new Error("wire bytes exceed u32 bound");
    }
    this.u32(value.byteLength);
    this.raw(value);
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.#length);
    let offset = 0;
    for (const part of this.#parts) {
      output.set(part, offset);
      offset += part.byteLength;
    }
    return output;
  }
}

class WireReader {
  #cursor = 0;

  constructor(readonly bytes: Uint8Array) {}

  take(length: number): Uint8Array {
    const end = this.#cursor + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.bytes.byteLength) {
      throw new Error("truncated SFU forward wire data");
    }
    const value = this.bytes.slice(this.#cursor, end);
    this.#cursor = end;
    return value;
  }

  u8(): number {
    return this.take(1)[0];
  }

  u16(): number {
    const bytes = this.take(2);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, false);
  }

  u32(): number {
    const bytes = this.take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  }

  u64(): bigint {
    const bytes = this.take(8);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false);
  }

  id(): string {
    const bytes = this.take(this.u16());
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_ID_BYTES) {
      throw new Error("invalid canonical opaque id");
    }
    return textDecoder.decode(bytes);
  }

  stringU16(maximum: number): string {
    const bytes = this.take(this.u16());
    if (bytes.byteLength > maximum) {
      throw new Error("wire string exceeds bound");
    }
    return textDecoder.decode(bytes);
  }

  bytesU16(maximum: number): Uint8Array {
    const length = this.u16();
    if (length > maximum) {
      throw new Error("wire bytes exceed bound");
    }
    return this.take(length);
  }

  bytesU32(maximum: number): Uint8Array {
    const length = this.u32();
    if (length > maximum) {
      throw new Error("wire bytes exceed bound");
    }
    return this.take(length);
  }

  done(): boolean {
    return this.#cursor === this.bytes.byteLength;
  }
}
