import {
  decodeSfuForwardEnvelopeWire,
  encodeSfuForwardEnvelopeWire,
  type SfuForwardEnvelopeWire,
} from "./src/sfu_forward_wire.ts";
import {
  UCR_WEBRTC_E2EE_DATA_CHANNEL_LABEL,
  UcrWebRtcE2eeTransport,
  type BinaryDataChannel,
} from "./src/webrtc_e2ee.ts";

const WIRE_V1_VECTOR_HEX =
  "554352453245453101000674656e616e740100096e616d657370616365000463616c6c000567726f7570000a766964656f2d6d61696e010005616c696365000c616c6963652d646576696365000b6e65676f74696174696f6e00000000000000020000000000000009000c63727970746f2d73746174650102000000000000002c0000000000015f900103030303030303030303030303030303030303030303030300000003070809000b7369676e696e672d6b657900076564323535313900000001004005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505";
const WIRE_V2_SCREEN_VECTOR_HEX =
  "554352453245453102000674656e616e740100096e616d657370616365000463616c6c000567726f7570000a766964656f2d6d61696e010005616c696365000c616c6963652d646576696365000b6e65676f74696174696f6e00000000000000020000000000000009000c63727970746f2d7374617465010203000000000000002c0000000000015f900103030303030303030303030303030303030303030303030300000003070809000b7369676e696e672d6b657900076564323535313900000001004005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505";

function requireCondition(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const envelope: SfuForwardEnvelopeWire = {
  frame: {
    header: {
      tenantId: "tenant",
      namespaceId: "namespace",
      callId: "call",
      groupId: "group",
      streamId: "video-main",
      source: { principalId: "alice", kind: "person" },
      sourceDeviceId: "alice-device",
      negotiationRef: "negotiation",
      negotiationGeneration: 2n,
      cryptoEpoch: 9n,
      cryptoStateRef: "crypto-state",
      cryptoSuite: "ucr.v1",
      mediaKind: "video",
      sourceKind: "screen_share",
      authVersion: 2,
      sequence: 44n,
      mediaTimestamp: 90_000n,
      keyframe: true,
    },
    nonce: new Uint8Array(24).fill(3),
    ciphertext: Uint8Array.of(7, 8, 9),
    sourceSignature: {
      keyId: "signing-key",
      algorithmId: "ed25519",
      algorithmVersion: 1,
      signature: new Uint8Array(64).fill(5),
    },
  },
};

const wire = encodeSfuForwardEnvelopeWire(envelope);
requireCondition(
  Buffer.from(wire).toString("hex") === WIRE_V2_SCREEN_VECTOR_HEX,
  "Rust/TypeScript SFU wire v2 drifted",
);

const decoded = decodeSfuForwardEnvelopeWire(wire);
requireCondition(decoded.frame.header.source.kind === "person", "principal kind drifted");
requireCondition(decoded.frame.header.mediaKind === "video", "media kind drifted");
requireCondition(decoded.frame.header.sourceKind === "screen_share", "media source kind drifted");
requireCondition(decoded.frame.header.authVersion === 2, "media auth version drifted");
requireCondition(decoded.frame.header.sequence === 44n, "sequence drifted");
requireCondition(decoded.frame.header.mediaTimestamp === 90_000n, "timestamp drifted");
requireCondition(Buffer.from(decoded.frame.ciphertext).equals(Buffer.from([7, 8, 9])), "ciphertext drifted");

const legacy = decodeSfuForwardEnvelopeWire(Uint8Array.from(Buffer.from(WIRE_V1_VECTOR_HEX, "hex")));
requireCondition(legacy.frame.header.authVersion === 1, "legacy SFU wire auth version drifted");
requireCondition(legacy.frame.header.sourceKind === "camera", "legacy video must canonicalize to camera");
requireCondition(
  Buffer.from(encodeSfuForwardEnvelopeWire(legacy)).toString("hex") === WIRE_V1_VECTOR_HEX,
  "legacy SFU wire v1 was not byte-preserving",
);

const { sourceKind: _sourceKind, authVersion: _authVersion, ...legacyHeader } = envelope.frame.header;
const legacyOmittedMetadata: SfuForwardEnvelopeWire = {
  ...envelope,
  frame: {
    ...envelope.frame,
    header: legacyHeader,
  },
};
requireCondition(
  Buffer.from(encodeSfuForwardEnvelopeWire(legacyOmittedMetadata)).toString("hex") === WIRE_V1_VECTOR_HEX,
  "omitted auth metadata no longer preserves legacy SFU wire v1",
);

const epochZeroEnvelope: SfuForwardEnvelopeWire = {
  ...envelope,
  frame: {
    ...envelope.frame,
    header: { ...envelope.frame.header, cryptoEpoch: 0n },
  },
};
requireCondition(
  decodeSfuForwardEnvelopeWire(encodeSfuForwardEnvelopeWire(epochZeroEnvelope)).frame.header.cryptoEpoch === 0n,
  "TypeScript wire codec rejected canonical MLS epoch zero",
);

for (const malformedId of [
  JSON.parse('"\\ud800"') as string,
  JSON.parse('"\\udc00"') as string,
]) {
  let malformedIdRejected = false;
  try {
    encodeSfuForwardEnvelopeWire({
      ...envelope,
      frame: {
        ...envelope.frame,
        header: { ...envelope.frame.header, tenantId: malformedId },
      },
    });
  } catch {
    malformedIdRejected = true;
  }
  requireCondition(malformedIdRejected, "TypeScript encoder accepted ill-formed UTF-16 canonical ID");
}

const supplementaryPlaneId = "tenant-😀";
requireCondition(
  decodeSfuForwardEnvelopeWire(
    encodeSfuForwardEnvelopeWire({
      ...envelope,
      frame: {
        ...envelope.frame,
        header: { ...envelope.frame.header, tenantId: supplementaryPlaneId },
      },
    }),
  ).frame.header.tenantId === supplementaryPlaneId,
  "TypeScript codec rejected a valid UTF-16 surrogate pair",
);

let trailingRejected = false;
try {
  decodeSfuForwardEnvelopeWire(Uint8Array.from([...wire, 0]));
} catch {
  trailingRejected = true;
}
requireCondition(trailingRejected, "TypeScript decoder accepted trailing bytes");

class FakeDataChannel implements BinaryDataChannel {
  readonly label = UCR_WEBRTC_E2EE_DATA_CHANNEL_LABEL;
  readonly readyState = "open";
  binaryType = "arraybuffer";
  readonly sent: Uint8Array[] = [];

  send(data: Uint8Array): void {
    this.sent.push(data.slice());
  }
}

const senderChannel = new FakeDataChannel();
const sender = new UcrWebRtcE2eeTransport(senderChannel, () => {});
sender.sendCanonicalEnvelope(envelope);
requireCondition(senderChannel.sent.length > 0, "WebRTC E2EE transport emitted no chunks");

const receiverChannel = new FakeDataChannel();
let received: Uint8Array | null = null;
const receiver = new UcrWebRtcE2eeTransport(receiverChannel, (value) => {
  received = value.slice();
});
for (const chunk of senderChannel.sent) {
  await receiver.receiveChunk(chunk);
}
requireCondition(received !== null, "WebRTC E2EE transport did not reassemble canonical envelope");
requireCondition(
  Buffer.from(received!).toString("hex") === WIRE_V2_SCREEN_VECTOR_HEX,
  "WebRTC E2EE transport changed canonical envelope bytes",
);

console.log("UCR_SFU_FORWARD_WIRE_TYPESCRIPT_OK");
