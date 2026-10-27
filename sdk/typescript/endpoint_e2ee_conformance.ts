import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { runInNewContext } from "node:vm";

import {
  installUcrEndpointE2eeAdapter,
  resolveUcrEndpointE2eeAdapter,
  UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  type UcrEndpointE2eeAdapterV1,
} from "./src/endpoint_e2ee.ts";
import { createUcrEndpointWasmPersistence } from "./src/endpoint_wasm_persistence.ts";
import {
  UcrPortableEndpointMediaAdapter,
} from "./src/portable_endpoint_media.ts";
import {
  UcrBrowserWebCodecsConsumer,
  UcrBrowserWebCodecsProducer,
  ucrCameraLayerStreamId,
  ucrVideoEncodingTarget,
  ucrVideoEncodeSize,
  ucrVideoStageProfile,
  ucrAdvanceVideoPacing,
  ucrDetectVideoCodec,
  ucrAdaptiveVideoStep,
  ucrNormalizeOpusAudio,
} from "./src/browser_webcodecs_media.ts";
import { createUcrCanonicalBrowserMediaFactory } from "./src/canonical_browser_media_factory.ts";
import { createUcrCanonicalDevicePreparation } from "./src/canonical_device_enrollment.ts";
import { encodeSfuForwardEnvelopeWire } from "./src/sfu_forward_wire.ts";
import {
  UcrChameleonReceiveHandover,
  type UcrEncryptedReceivePath,
} from "./src/chameleon_receive_handover.ts";

// The real capture cadence must be preserved at each adaptive encode target.
// Integer microsecond timestamps must not turn 24 fps into 15 or 12 into 10.
{
  const pacedFrames = (targetFps: number, integerStepUs?: number): number => {
    let nextDueUs = Number.NEGATIVE_INFINITY;
    let published = 0;
    for (let i = 0; i < 300; i++) {
      const timestamp = integerStepUs === undefined ? Math.round(i * 1_000_000 / 30) : i * integerStepUs;
      const frame = ucrAdvanceVideoPacing(timestamp,
        nextDueUs, targetFps);
      if (frame.publish) {
        published++;
        nextDueUs = frame.nextDueUs;
      }
    }
    return published;
  };
  assert.equal(pacedFrames(30), 300, "uncongested camera must retain 30 fps");
  assert.equal(pacedFrames(30, 33_333), 300,
    "integer-truncated 30 fps capture timestamps must not drop every 12th frame");
  assert.equal(pacedFrames(24, 33_333), 240);
  assert.equal(pacedFrames(12, 33_333), 120);
  assert.equal(pacedFrames(24), 240, "stage-2 encoder must actually publish 24 fps");
  assert.equal(pacedFrames(12), 120, "low camera layer must actually publish 12 fps");
  const afterGap = ucrAdvanceVideoPacing(20_000_000, 1_000_000 / 24, 24);
  assert.equal(afterGap.publish, true);
  assert.equal(afterGap.nextDueUs, 20_000_000 + 1_000_000 / 24,
    "large capture gap must not trigger a burst of catch-up encodes");
  assert.throws(() => ucrAdvanceVideoPacing(Number.NaN, 0, 24), /invalid video pacing/);
}

// Real microphone PCM is not guaranteed to match the configured Opus profile.
// Exercise endpoint-only conversion without requiring browser permissions.
{
  const original = globalThis.AudioData;
  const created: Array<Record<string, unknown>> = [];
  class FakeAudioData {
    sampleRate: number; numberOfChannels: number; numberOfFrames: number; timestamp: number;
    planes: Float32Array[];
    constructor(config: {sampleRate: number; numberOfChannels: number;
      numberOfFrames: number; timestamp: number; data: Float32Array}) {
      this.sampleRate=config.sampleRate;this.numberOfChannels=config.numberOfChannels;
      this.numberOfFrames=config.numberOfFrames;this.timestamp=config.timestamp;
      this.planes=[config.data];
      created.push(config);
    }
    copyTo(dest: Float32Array,{planeIndex}: {planeIndex: number}) {
      dest.set(this.planes[planeIndex]);
    }
    close() {}
  }
  try {
    Object.assign(globalThis,{AudioData:FakeAudioData});
    const stereo=Object.create(FakeAudioData.prototype) as FakeAudioData;
    stereo.sampleRate=44100;stereo.numberOfChannels=2;stereo.numberOfFrames=441;
    stereo.timestamp=1234;
    stereo.planes=[new Float32Array(441).fill(.5),new Float32Array(441).fill(-.25)];
    const output=ucrNormalizeOpusAudio(stereo as unknown as AudioData);
    assert.equal(output.sampleRate,48000);
    assert.equal(output.numberOfChannels,1);
    assert.equal(output.numberOfFrames,480);
    assert.equal(output.timestamp,1234);
    assert.ok(Math.abs((created[0].data as Float32Array)[0]-.125)<.0001);
    assert.equal(ucrNormalizeOpusAudio(output),output);
  } finally {
    if(original===undefined) Reflect.deleteProperty(globalThis,"AudioData");
    else Object.assign(globalThis,{AudioData:original});
  }
}

// Real first/repeat-login orchestration over externally authenticated canonical
// Device/Trust and endpoint-owned key vault; never create a second key owner.
const testDeviceKeyPair = generateKeyPairSync("ed25519");
const keyBytes = new Uint8Array(testDeviceKeyPair.publicKey.export({format:"der", type:"spki"}).subarray(-32));
if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", {value: webcrypto});
const signDeviceChallenge = async (binding: unknown, challenge: Uint8Array) => {
  assert.deepEqual(Object.keys(binding as object).sort(),
    ["deviceId", "namespaceId", "tenantId"],
    "permanent Device signer vault must never receive transient Call/Session/participant IDs");
  return new Uint8Array(sign(null, challenge, testDeviceKeyPair.privateKey));
};
const deviceBinding = {tenantId: "tenant", namespaceId: null, deviceId: "device",
  participantId: "user", callId: "call", sessionId: "session"};
let enrolled = false, revoked = false, localSigner: {keyId: string; publicKey: Uint8Array} | null = null;
let enrollRequests = 0, stagedKeys = 0;
const prepareDevice = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: enrolled, deviceRevoked: revoked,
    activeKey: enrolled ? {keyId: "key-1", publicKey: keyBytes} : null};},
  async approveNewDevice(_binding, signer) {
    assert.equal(signer.keyId, "key-1");
    enrollRequests++; enrolled = true;
  },
}, {
  signChallenge: signDeviceChallenge,
  async load() {return localSigner;},
  async stageNew(scope) {
    assert.deepEqual(Object.keys(scope).sort(), ["deviceId", "namespaceId", "tenantId"]);
    stagedKeys++; localSigner = {keyId: "key-1", publicKey: keyBytes};
    return localSigner;},
});
await prepareDevice(deviceBinding);
assert.equal(enrollRequests, 1);
assert.equal(stagedKeys, 1);
await prepareDevice(deviceBinding);
await prepareDevice({...deviceBinding, callId: "another-call", sessionId: "another-session"});
assert.equal(enrollRequests, 1, "subsequent login must restore same trusted signer");
assert.equal(stagedKeys, 1, "no new key when canonical Device is already trusted");
localSigner = {keyId: "key-1", publicKey: new Uint8Array(32).fill(4)};
await assert.rejects(prepareDevice(deviceBinding), /local signer differs/);
assert.equal(enrollRequests, 1, "mismatched local signer must never re-register trust");
localSigner = {keyId: "key-1", publicKey: keyBytes};
revoked = true;
await assert.rejects(prepareDevice(deviceBinding), /Device revoked/);
revoked = false;
localSigner = null;
await assert.rejects(prepareDevice(deviceBinding), /local device signer is absent/);
assert.equal(enrollRequests, 1, "missing local signer requires explicit recovery");
// A compromised vault cannot swap the mutable trusted key while signing is awaited.
const foreignKey = generateKeyPairSync("ed25519");
const foreignPublic = new Uint8Array(foreignKey.publicKey.export({format:"der", type:"spki"}).subarray(-32));
const mutableTrusted = keyBytes.slice();
let tamperedLocal: {keyId: string; publicKey: Uint8Array} = {keyId: "tampered", publicKey: mutableTrusted};
const rejectKeySwap = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: true, deviceRevoked: false,
    activeKey: {keyId: "tampered", publicKey: mutableTrusted}};},
  async approveNewDevice() {throw new Error("unexpected approval");},
}, {
  async load() {return tamperedLocal;},
  async stageNew() {throw new Error("unexpected staging");},
  async signChallenge(_binding, challenge) {
    mutableTrusted.set(foreignPublic);
    return new Uint8Array(sign(null, challenge, foreignKey.privateKey));
  },
});
await assert.rejects(rejectKeySwap(deviceBinding), /private key does not match trusted signer/);
assert.equal(tamperedLocal.keyId, "tampered");

// The protected vault may sign successfully while the canonical owner revokes
// or rotates its key. A successful signature is NOT sufficient to join.
for (const changed of ["revoked", "rotated"] as const) {
  let inspections = 0, registrations = 0;
  const timeOfCheckAuthority = {
    async inspect() {
      inspections++;
      return inspections === 1
        ? {deviceActive: true, deviceRevoked: false,
           activeKey: {keyId: "key-1", publicKey: keyBytes.slice()}}
        : {deviceActive: changed !== "revoked", deviceRevoked: changed === "revoked",
           activeKey: changed === "rotated"
             ? {keyId: "foreign", publicKey: foreignPublic}
             : {keyId: "key-1", publicKey: keyBytes.slice()}};
    },
    async approveNewDevice() { registrations++; },
  };
  const guard = createUcrCanonicalDevicePreparation(timeOfCheckAuthority, {
    signChallenge: signDeviceChallenge,
    async load() { return {keyId: "key-1", publicKey: keyBytes.slice()}; },
    async stageNew() { throw new Error("unexpected stage"); },
  });
  await assert.rejects(guard(deviceBinding), /canonical Device trust changed during signing/);
  assert.equal(inspections, 2, "canonical trust must be re-read after signing");
  assert.equal(registrations, 0);
}

// The fresh Ed25519 challenge must bind the same Device and the specific
// participant/session without creating call-scoped private signing keys.
const possessionChallenges: Uint8Array[] = [];
const scopedPossession = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: true, deviceRevoked: false,
    activeKey: {keyId: "key-1", publicKey: keyBytes.slice()}};},
  async approveNewDevice() {throw new Error("unexpected registration");},
}, {
  async load() {return {keyId: "key-1", publicKey: keyBytes.slice()};},
  async stageNew() {throw new Error("unexpected key creation");},
  async signChallenge(vaultScope, challenge) {
    assert.deepEqual(Object.keys(vaultScope).sort(), ["deviceId", "namespaceId", "tenantId"]);
    possessionChallenges.push(challenge.slice());
    return new Uint8Array(sign(null, challenge, testDeviceKeyPair.privateKey));
  },
});
await scopedPossession(deviceBinding);
await scopedPossession({...deviceBinding, deviceId: "different-device"});
await scopedPossession({...deviceBinding, callId: "new-call", sessionId: "new-session"});
const decodedChallengeScope = (challenge: Uint8Array): Array<string | null> => {
  const bytes = challenge.subarray(0, challenge.length - 48);
  let offset = 0;
  const values: Array<string | null> = [];
  for (let i = 0; i < 8; i++) {
    assert.ok(offset + 2 <= bytes.length, "missing challenge field length");
    const length = bytes[offset++] * 256 + bytes[offset++];
    if (length === 0xffff) {values.push(null); continue;}
    assert.ok(offset + length <= bytes.length, "truncated challenge scope");
    values.push(new TextDecoder().decode(bytes.subarray(offset, offset + length)));
    offset += length;
  }
  assert.equal(offset, bytes.length, "no extra unsigned scope metadata");
  return values;
};
assert.deepEqual(decodedChallengeScope(possessionChallenges[0]), [
  "ucr.device-signer-possession.v1", "tenant", null, "device", "user",
  "call", "session", "key-1",
]);
assert.equal(decodedChallengeScope(possessionChallenges[1])[3], "different-device");
assert.equal(decodedChallengeScope(possessionChallenges[2])[5], "new-call");
assert.notDeepEqual(possessionChallenges[0], possessionChallenges[1]);
await scopedPossession({tenantId: "tenant", namespaceId: null,
  deviceId: "device", participantId: "user"});
assert.deepEqual(decodedChallengeScope(possessionChallenges[3]).slice(5, 7), [null, null],
  "first-entry device registration must be possible before Call/Session exist");
// Valid 128-byte opaque identifiers, including escaped JSON/control characters,
// must remain encodable without a spurious sixfold JSON expansion.
const controlId = String.fromCharCode(0).repeat(128);
await scopedPossession({
  tenantId: controlId, namespaceId: controlId,
  deviceId: controlId, participantId: controlId,
  callId: controlId, sessionId: controlId,
});
assert.equal(decodedChallengeScope(possessionChallenges[4])[3], controlId);
await assert.rejects(scopedPossession({...deviceBinding, callId: "A".repeat(1500)}),
  /challenge scope exceeds bounds/);
// The caller must not switch a Device or Call while a previous possession
// check is queued (or during the asynchronous signer operation).
const mutableQueuedBinding = {...deviceBinding};
const queuedPossession = scopedPossession(mutableQueuedBinding);
mutableQueuedBinding.deviceId = "attacker-device";
mutableQueuedBinding.callId = "attacker-call";
mutableQueuedBinding.sessionId = "attacker-session";
await queuedPossession;
assert.equal(decodedChallengeScope(possessionChallenges[5])[3], "device");
assert.equal(decodedChallengeScope(possessionChallenges[5])[5], "call");
await assert.rejects(scopedPossession({...deviceBinding, deviceId: 42} as any),
  /independently authenticated canonical Device identity/);

// A hostile vault receives only a COPY. Mutating it and signing that new value
// must not satisfy the original canonical Device-bound verifier challenge.
const rejectChallengeMutation = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: true, deviceRevoked: false,
    activeKey: {keyId: "key-1", publicKey: keyBytes.slice()}};},
  async approveNewDevice() {throw new Error("unexpected approval");},
}, {
  async load() {return {keyId: "key-1", publicKey: keyBytes.slice()};},
  async stageNew() {throw new Error("unexpected key creation");},
  async signChallenge(_scope, challenge) {
    challenge.fill(0);
    return new Uint8Array(sign(null, challenge, testDeviceKeyPair.privateKey));
  },
});
await assert.rejects(rejectChallengeMutation(deviceBinding),
  /private key does not match trusted signer/);

// Interrupted enrollment must reuse the staged signer, never silently create
// a new key after the server response is lost.
let stagedRetryCount = 0, approvalAttempt = 0, retryConfirmed = false;
let stagedRetrySigner: {keyId: string; publicKey: Uint8Array} | null = null;
const retryDevice = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: retryConfirmed, deviceRevoked: false,
    activeKey: retryConfirmed ? {keyId: "retry-key", publicKey: keyBytes} : null};},
  async approveNewDevice(_binding, signer) {
    assert.equal(signer.keyId, "retry-key");
    if (++approvalAttempt === 1) throw new Error("registration response lost");
    retryConfirmed = true;
  },
}, {
  signChallenge: signDeviceChallenge,
  async load() {return stagedRetrySigner;},
  async stageNew() {
    stagedRetryCount++;
    stagedRetrySigner = {keyId: "retry-key", publicKey: keyBytes};
    return stagedRetrySigner;
  },
});
await assert.rejects(retryDevice(deviceBinding), /registration response lost/);
await retryDevice(deviceBinding);
assert.equal(stagedRetryCount, 1, "transport retry must not create a second Device signing identity");
assert.equal(approvalAttempt, 2);

// A real first registration precedes issuance of any Call/Session join grant.
// Canonical Device identity is stable and independent of that future grant.
const identityOnly = {tenantId: "tenant", namespaceId: null, deviceId: "new-device", participantId: "user"};
let firstEntryConfirmed = false, issuedGrants = 0;
const prepareFirstEntry = createUcrCanonicalDevicePreparation({
  async inspect() {return {deviceActive: firstEntryConfirmed, deviceRevoked: false,
    activeKey: firstEntryConfirmed ? {keyId: "key-1", publicKey: keyBytes.slice()} : null};},
  async approveNewDevice(binding, signer) {
    assert.equal(binding.deviceId, "new-device");
    assert.equal(binding.callId, undefined);
    assert.equal(binding.sessionId, undefined);
    assert.equal(signer.keyId, "key-1");
    firstEntryConfirmed = true;
  },
}, {
  signChallenge: signDeviceChallenge,
  async load() {return null;},
  async stageNew() {return {keyId: "key-1", publicKey: keyBytes.slice()};},
});
await prepareFirstEntry(identityOnly);
assert.equal(firstEntryConfirmed, true);
if (firstEntryConfirmed) issuedGrants++;
assert.equal(issuedGrants, 1, "only independently prepared Device can request a canonical grant");
await assert.rejects(prepareFirstEntry({...identityOnly, callId: "call"}),
  /Call and Session must both be supplied or both omitted/);

const v1 = {
  contractVersion: UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  start() {},
  onEnvelope() {},
  stop() {},
  persistence: {
    restoreSealedState() {
      return true;
    },
    sealState() {
      return new Uint8Array([1, 2, 3]);
    },
  },
} satisfies UcrEndpointE2eeAdapterV1;

const resolved = resolveUcrEndpointE2eeAdapter(v1, { allowLegacy: false });
assert.equal(resolved.adapter, v1);
assert.equal(resolved.legacy, false);

const legacy = {
  start() {},
  onEnvelope() {},
};
assert.equal(resolveUcrEndpointE2eeAdapter(legacy).legacy, true);
assert.throws(
  () => resolveUcrEndpointE2eeAdapter(legacy, { allowLegacy: false }),
  /legacy UCR endpoint E2EE adapter is not allowed/,
);

assert.throws(
  () =>
    resolveUcrEndpointE2eeAdapter({
      contractVersion: "ucr.endpoint-e2ee.v2",
      start() {},
      onEnvelope() {},
      stop() {},
    }),
  /unsupported UCR endpoint E2EE adapter contract version/,
);

assert.throws(
  () =>
    resolveUcrEndpointE2eeAdapter({
      contractVersion: UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
      start() {},
      onEnvelope() {},
    }),
  /requires a stop hook/,
);

assert.throws(
  () =>
    resolveUcrEndpointE2eeAdapter({
      contractVersion: UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
      start() {},
      onEnvelope() {},
      stop() {},
      persistence: {
        sealState() {
          return new Uint8Array([1]);
        },
      },
    }),
  /persistence requires restoreSealedState and sealState hooks/,
);

// Chameleon is an optional codec control, not a replacement for endpoint E2EE.
// Subscriber quality decisions are independent of the publisher encoder.
const qualityTargets: unknown[] = [];
const withQuality = {
  ...v1,
  getReceiveMediaTelemetry() {
    return { estimated_bandwidth_bps: 8_000_000 };
  },
  applyReceiveMediaDecision(target: unknown) { qualityTargets.push(target); },
} satisfies UcrEndpointE2eeAdapterV1;
assert.equal(resolveUcrEndpointE2eeAdapter(withQuality, { allowLegacy: false }).adapter, withQuality);
await withQuality.applyReceiveMediaDecision({
  stage: "video_1080p",
  video: { codec_capability_id: "ucr.video.h264", width: 1920, height: 1080,
    frame_rate: 30, target_bitrate_bps: 4_000_000 },
  opus_target_bitrate_bps: null,
});
assert.equal(qualityTargets.length, 1);
assert.throws(() => resolveUcrEndpointE2eeAdapter({
  ...v1, applyReceiveMediaDecision: "fullscreen",
}), /receive quality control must be a function/);
assert.throws(() => resolveUcrEndpointE2eeAdapter({
  ...v1, getReceiveMediaTelemetry: 123,
}), /receive telemetry must be a function/);

const target: Record<string, unknown> = {};
installUcrEndpointE2eeAdapter(target, v1);
assert.equal(target.ucrE2eeEndpoint, v1);
installUcrEndpointE2eeAdapter(target, v1);

assert.throws(
  () =>
    installUcrEndpointE2eeAdapter(target, {
      contractVersion: UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
      start() {},
      onEnvelope() {},
      stop() {},
    }),
  /already installed/,
);

class FakeMlsState {
  readonly sealed = new Uint8Array([4, 5, 6]);

  seal_snapshot(key: Uint8Array): Uint8Array {
    assert.equal(key.length, 32);
    assert.equal(key[0], 7);
    return this.sealed.slice();
  }
}

const restoredState = new FakeMlsState();
let restoreArgs: unknown[] | null = null;
const fakeStatic = {
  restore(...args: unknown[]) {
    restoreArgs = args;
    return restoredState;
  },
};
const holder = { current: new FakeMlsState() };
let issuedKey: Uint8Array | null = null;
const keyProvider = {
  getWrappingKey() {
    issuedKey = new Uint8Array(32);
    issuedKey.fill(7);
    return issuedKey;
  },
};
const persistence = createUcrEndpointWasmPersistence(
  holder,
  fakeStatic,
  {
    tenantId: "tenant-1",
    namespaceId: "namespace-1",
    groupId: "group-1",
    deviceId: "device-1",
  },
  () => ({ cryptoEpoch: 12n, cryptoStateRef: "state-12" }),
  keyProvider,
);

const sealed = await persistence.sealState();
assert.deepEqual([...sealed], [4, 5, 6]);
assert.ok(issuedKey);
assert.ok(issuedKey.every((value) => value === 0));

const restored = await persistence.restoreSealedState(new Uint8Array([8, 9, 10]));
assert.equal(restored, true);
assert.equal(holder.current, restoredState);
assert.ok(restoreArgs);
assert.equal(restoreArgs[0], "tenant-1");
assert.equal(restoreArgs[1], "namespace-1");
assert.equal(restoreArgs[2], "group-1");
assert.equal(restoreArgs[3], "device-1");
assert.deepEqual([...restoreArgs[5] as Uint8Array], [8, 9, 10]);
assert.equal(restoreArgs[6], 12n);
assert.equal(restoreArgs[7], "state-12");
assert.ok(issuedKey);
assert.ok(issuedKey.every((value) => value === 0));

const rejecting = createUcrEndpointWasmPersistence(
  holder,
  { restore() { throw new Error("invalid snapshot"); } },
  { tenantId: "tenant-1", groupId: "group-1", deviceId: "device-1" },
  () => ({ cryptoEpoch: 13, cryptoStateRef: "state-13" }),
  keyProvider,
);
assert.equal(
  await rejecting.restoreSealedState(new Uint8Array([1])),
  false,
);
assert.ok(issuedKey);
assert.ok(issuedKey.every((value) => value === 0));

const zeroKeyPersistence = createUcrEndpointWasmPersistence(
  holder,
  fakeStatic,
  { tenantId: "tenant-1", groupId: "group-1", deviceId: "device-1" },
  () => ({ cryptoEpoch: 1, cryptoStateRef: "state-1" }),
  { getWrappingKey: () => new Uint8Array(32) },
);
await assert.rejects(() => zeroKeyPersistence.sealState(), /must not be all-zero/);

// Chameleon: no sender/encoder mutation; transport changes are subscriber-only and
// the old ciphertext path stays live until the new authenticated keyframe is decodable.
const handoverEvents: string[] = [];
const binding = {callId: "call1", sessionId: "session1", cryptoEpoch: 4n};
function receivePath(
  id: string,
  readiness: {authenticatedKeyframe: boolean; decoderReady: boolean;
    pathId?: string; cryptoEpoch?: bigint} =
    {authenticatedKeyframe: true, decoderReady: true},
  wait?: Promise<void>,
): UcrEncryptedReceivePath {
  return {
    pathId: id,
    binding,
    async prepare() {
      handoverEvents.push("prepare:" + id);
      if (wait) await wait;
      return {pathId: id, cryptoEpoch: binding.cryptoEpoch, ...readiness};
    },
    async activate(guard) {
      guard();
      handoverEvents.push("activate:" + id);
    },
    async retire() { handoverEvents.push("retire:" + id); },
  };
}
let receiveAllowed = true;
const pathA = receivePath("A");
const chameleon = new UcrChameleonReceiveHandover(
  pathA, (candidate) => receiveAllowed && candidate.pathId !== "unauthorized",
);
assert.equal(chameleon.activePathId, "A");
assert.equal(await chameleon.handover(receivePath("B")), true);
assert.equal(chameleon.activePathId, "B");
assert.deepEqual(handoverEvents, ["prepare:B", "activate:B", "retire:A"]);
await assert.rejects(chameleon.handover(receivePath("bad", {
  authenticatedKeyframe: false, decoderReady: true,
})), /cannot decode an authenticated keyframe/);
assert.equal(chameleon.activePathId, "B");
assert.ok(handoverEvents.includes("retire:bad"));
receiveAllowed = false;
await assert.rejects(chameleon.handover(receivePath("revoked")), /authorization revoked/);
assert.equal(chameleon.activePathId, "B");
assert.ok(!handoverEvents.includes("activate:revoked"));
assert.ok(handoverEvents.includes("retire:revoked"));
receiveAllowed = true;
await assert.rejects(chameleon.handover(receivePath("unauthorized")), /authorization revoked/);
assert.ok(!handoverEvents.includes("activate:unauthorized"));
await assert.rejects(chameleon.handover(receivePath("spoof", {
  pathId: "other-route", authenticatedKeyframe: true, decoderReady: true,
})), /cannot decode an authenticated keyframe/);
assert.ok(!handoverEvents.includes("activate:spoof"));
receiveAllowed = true;
await assert.rejects(chameleon.handover({
  ...receivePath("wrong-epoch"), binding: {...binding, cryptoEpoch: 5n},
}), /retain canonical session and crypto epoch/);
assert.equal(chameleon.activePathId, "B");
let releasePrepare: () => void = () => {};
const delayedPrepare = new Promise<void>((resolve) => { releasePrepare = resolve; });
const pending = chameleon.handover(receivePath("late", undefined, delayedPrepare));
await Promise.resolve();
await chameleon.stop();
releasePrepare();
await assert.rejects(pending, /cancelled or authorization revoked/);
assert.ok(!handoverEvents.includes("activate:late"));
assert.ok(handoverEvents.includes("retire:B"));
assert.ok(handoverEvents.includes("retire:late"));
await assert.rejects(chameleon.handover(receivePath("after-close")), /receive session retired/);

// A simultaneous stop must retire a candidate while activate() is still
// awaiting host work. Merely invalidating its generation leaves ciphertext
// reception alive until that host promise completes (or forever if it stalls).
const receiveRaceEvents: string[] = [];
let activateEntered: () => void = () => {};
const activationEntered = new Promise<void>((resolve) => { activateEntered = resolve; });
let releaseActivation: () => void = () => {};
const activationStalled = new Promise<void>((resolve) => { releaseActivation = resolve; });
const receiveRace = new UcrChameleonReceiveHandover({
  ...receivePath("race-old"),
  async retire() { receiveRaceEvents.push("old-retired"); },
}, () => true);
const racingHandover = receiveRace.handover({
  ...receivePath("race-candidate"),
  async activate(guard) {
    guard();
    activateEntered();
    await activationStalled;
  },
  async retire() { receiveRaceEvents.push("candidate-retired"); },
});
await activationEntered;
await receiveRace.stop();
assert.ok(receiveRaceEvents.includes("old-retired"));
assert.ok(receiveRaceEvents.includes("candidate-retired"),
  "stop must retire the uncommitted in-flight encrypted receiver immediately");
releaseActivation();
await assert.rejects(racingHandover, /cancelled or authorization revoked/);
await assert.rejects(receiveRace.handover(receivePath("after-race")), /receive session retired/);

// Every caller must wait for the same actual cleanup, not an immediate return
// when a first stop has set the closed flag but is still awaiting retire().
let releaseRetire: () => void = () => {};
const retireStalled = new Promise<void>((resolve) => { releaseRetire = resolve; });
let retireCalls = 0;
const delayedStop = new UcrChameleonReceiveHandover({
  ...receivePath("delayed-stop"),
  async retire() { ++retireCalls; await retireStalled; },
}, () => true);
const firstStop = delayedStop.stop();
const secondStop = delayedStop.stop();
let secondStopFinished = false;
void secondStop.then(() => { secondStopFinished = true; });
await Promise.resolve();
await Promise.resolve();
assert.equal(secondStopFinished, false, "concurrent stop cannot report finished early");
releaseRetire();
await Promise.all([firstStop, secondStop]);
assert.equal(retireCalls, 1);
await delayedStop.stop();

const browser = readFileSync("crates/ucr-realtime-web/static/client.html", "utf8");
// The first successful E2EE activation permanently settles its startup timer.
// A later MLS refresh can temporarily reset readiness without reviving it.
const startupGuardSnippet = browser.slice(
  browser.indexOf("let pendingMediaStartupWatchdog=null;"),
  browser.indexOf("// This signed session grant is retired"),
);
assert.ok(startupGuardSnippet.startsWith("let pendingMediaStartupWatchdog=null;"));
let startupTimerSequence=0,startupRevocations=0;
const startupCallbacks = new Map<number, () => void>();
const startupCtx: Record<string, any> = {
  sessionActive:true,sessionLifecycleGeneration:7,token:"renewed",
  e2eeAdapterReady:false,
  setTimeout(callback: () => void) {
    const id=++startupTimerSequence;
    startupCallbacks.set(id,callback);
    return id;
  },
  clearTimeout(id: number) {startupCallbacks.delete(id);},
  endUnverifiedMedia() {startupRevocations++;},
};
runInNewContext(startupGuardSnippet +
  "\nthis.arm = armMediaStartupWatchdog; this.cancel = cancelMediaStartupWatchdog;",
  startupCtx);
startupCtx.arm(7,"renewed",12000);
const staleStartupCallback=startupCallbacks.get(1);
assert.ok(staleStartupCallback);
startupCtx.e2eeAdapterReady=true;
startupCtx.cancel(7,"renewed");
startupCtx.e2eeAdapterReady=false; // MLS epoch refresh
staleStartupCallback();
assert.equal(startupRevocations,0,
  "settled startup watchdog must not revoke a refreshed encrypted call");
assert.equal(startupCallbacks.size,0);
startupCtx.arm(8,"next",12000);
const pendingStartupCallback=startupCallbacks.get(2);
assert.ok(pendingStartupCallback);
startupCtx.cancel(7,"renewed");
assert.equal(startupCallbacks.size,1,
  "old Join cleanup must not cancel the new signed grant's deadline");
startupCtx.sessionLifecycleGeneration=8;startupCtx.token="next";
startupCallbacks.delete(2); // the fake timer has fired
pendingStartupCallback();
assert.equal(startupRevocations,1,
  "a genuinely stalled encrypted startup must still fail closed");
startupCtx.arm(9,"later",12000);
startupCtx.cancel(); // Leave
assert.equal(startupCallbacks.size,0,"Leave must disarm its startup watchdog");
const activationSnippet=browser.slice(
  browser.indexOf("async function activateE2eeAdapter(){"),
  browser.indexOf("function attachE2eeDataChannel("),
);
assert.match(activationSnippet,
  /e2eeAdapterReady=true;\s*cancelMediaStartupWatchdog\(sessionGeneration,sessionToken\)/);
const leaveSnippet=browser.slice(
  browser.indexOf("async function leave(){"),
  browser.indexOf("function scheduleWaitingRoom(){"),
);
assert.ok(leaveSnippet.includes("cancelMediaStartupWatchdog();"));
console.log("UCR_E2EE_STARTUP_WATCHDOG_SETTLEMENT_OK");

// Run the browser's *actual* MLS bootstrap and retirement against delayed
// canonical network responses. A late Welcome or registration reply after
// leaving the call must not publish a signer or leak an endpoint WASM state.
const mlsSnippet = browser.slice(
  browser.indexOf("function retireEndpointMlsState(){"),
  browser.indexOf("function endpointPersistence(adapter){"),
);
assert.ok(mlsSnippet.startsWith("function retireEndpointMlsState(){"));
let releaseMlsContext: ((value: any) => void) | undefined;
const mlsContextGate = new Promise<any>(resolve => {releaseMlsContext = resolve;});
let releaseMlsRegistration: (() => void) | undefined;
const mlsRegistrationGate = new Promise<void>(resolve => {releaseMlsRegistration = resolve;});
let registeredPackages = 0, freedMlsStates = 0, publishedSnapshots = 0;
let capturedMlsSignal: AbortSignal | undefined;
const mlsClaims = {tenant_id: "tenant", namespace_id: null,
  call_id: "call", device_id: "device"};
const mlsFixture = {
  group_id: "group", endpoint_state_mode: "register",
};
const mlsBootstrap = {
  group_id: "group",
  welcome_base64: "welcome",
  welcome_crypto_state: {crypto_epoch: 1, crypto_state_ref: "state"},
  current_crypto_state: {crypto_epoch: 1, crypto_state_ref: "state"},
  subsequent_commits: [],
};
const mlsContext: Record<string, any> = {
  claims: mlsClaims, sessionActive: true, sessionLifecycleGeneration: 1,
  endpointMlsState: null, endpointMlsGroupId: null,
  endpointMlsInvalidationGeneration: 0, endpointMlsBootstrapPromise: null,
  endpointMlsBootstrapAbort: null, AbortController, window: {},
  fetchEndpointMlsContext: async (signal: AbortSignal) => {
    capturedMlsSignal=signal;return mlsContextGate;
  },
  loadEndpointWasmModule: async () => ({
    EndpointMlsState: class {
      key_package() {return Uint8Array.of(1);}
      join_from_welcome() {}
      crypto_epoch() {return 1n;}
      free() {freedMlsStates++;}
    },
  }),
  endpointPersistenceStorageKey: () => "sealed-device",
  loadEndpointState: async () => null,
  fetchEndpointMlsBootstrap: async () => mlsBootstrap,
  endpointBytesToBase64: () => "package",
  endpointBase64ToBytes: () => Uint8Array.of(1),
  endpointApplyBootstrapCommits() {},
  sealEndpointMlsSnapshot: async () => {publishedSnapshots++;},
  body: () => ({}),
  api: async (_path: string, _body: object, signal: AbortSignal) => {
    capturedMlsSignal=signal;
    registeredPackages++;
    await mlsRegistrationGate;
  },
  ENDPOINT_WASM_CONTRACT_VERSION: "ucr.endpoint-wasm.v1",
};
runInNewContext(mlsSnippet +
  "\nthis.ensureMls = ensureEndpointMlsReady; this.retireMls = retireEndpointMlsState;",
  mlsContext);
const waitingForContext = mlsContext.ensureMls();
mlsContext.retireMls();
assert.equal(capturedMlsSignal?.aborted, true,
  "retirement must abort an in-flight canonical MLS context request");
mlsContext.sessionActive = false;
releaseMlsContext?.(mlsFixture);
await assert.rejects(waitingForContext, /cancelled by admission withdrawal/);
assert.equal(registeredPackages, 0,
  "revoked Welcome must not start a Device key-package registration");
assert.equal(mlsContext.window.ucrEndpointMlsSession, undefined);

mlsContext.sessionActive = true;
mlsContext.sessionLifecycleGeneration++;
mlsContext.fetchEndpointMlsContext = async () => mlsFixture;
const waitingForRegistration = mlsContext.ensureMls();
for(let i=0;i<16&&registeredPackages===0;i++)await Promise.resolve();
assert.equal(registeredPackages, 1, "one canonical Device registration required");
const sameRegistration = mlsContext.ensureMls();
mlsContext.retireMls();
assert.equal(capturedMlsSignal?.aborted, true,
  "retirement must abort pending canonical Device registration");
mlsContext.sessionActive = false;
releaseMlsRegistration?.();
await assert.rejects(waitingForRegistration, /cancelled by admission withdrawal/);
await assert.rejects(sameRegistration, /cancelled by admission withdrawal/);
assert.equal(registeredPackages, 1, "concurrent MLS activation cannot duplicate registration");
assert.equal(freedMlsStates, 1, "revoked bootstrap must free endpoint WASM state");
assert.equal(publishedSnapshots, 0, "revoked bootstrap must not publish MLS snapshots");
assert.equal(mlsContext.endpointMlsState, null);
assert.equal(mlsContext.window.ucrEndpointMlsSession, undefined);

// A fresh accepted session must still be able to initialize normally.
mlsContext.sessionActive = true;
mlsContext.sessionLifecycleGeneration++;
const freshMls = await mlsContext.ensureMls();
assert.ok(freshMls, "new admission must establish a live endpoint MLS state");
assert.equal(registeredPackages, 2);
assert.equal(publishedSnapshots, 1);
assert.equal(mlsContext.endpointMlsState, freshMls);
mlsContext.retireMls();
assert.equal(freedMlsStates, 2, "retirement frees the current local state synchronously");

// The reference WebRTC browser must not report a protected connection when
// a legacy/non-revocable host object is injected instead of the canonical v1
// media bridge. The separate SDK may parse legacy contracts, not this path.
const strictAdapterSnippet = browser.slice(
  browser.indexOf("function requireCompatibleE2eeAdapter(adapter){"),
  browser.indexOf("function closeE2eeTransport(){"),
);
assert.ok(strictAdapterSnippet.startsWith("function requireCompatibleE2eeAdapter(adapter){"));
const strictAdapterCtx: Record<string, any> = {
  E2EE_ENDPOINT_CONTRACT_VERSION: "ucr.endpoint-e2ee.v1",
  endpointPersistence() {},
};
runInNewContext(strictAdapterSnippet +
  "\nthis.verifyAdapter = requireCompatibleE2eeAdapter;", strictAdapterCtx);
assert.equal(strictAdapterCtx.verifyAdapter(null), null);
for(const candidate of [
  {start() {}, onEnvelope() {}, stop() {}},
  {contractVersion: "ucr.endpoint-e2ee.v1", start() {}, onEnvelope() {}},
  {contractVersion: "ucr.endpoint-e2ee.v2", start() {}, onEnvelope() {}, stop() {}},
]){
  assert.throws(() => strictAdapterCtx.verifyAdapter(candidate), /E2EE adapter v1/,
    "unversioned, non-revocable or unknown E2EE contracts must be rejected");
}
assert.doesNotThrow(() => strictAdapterCtx.verifyAdapter({
  contractVersion: "ucr.endpoint-e2ee.v1",
  start() {}, onEnvelope() {}, stop() {},
}));

// Production device preflight: never trigger a camera prompt, signaling, or
// MLS registration when the canonical trusted Device media host is absent.
// Enrollment/recovery is independently host-authorized BEFORE using a join
// URL, and re-validated after joining. The URL itself approves no Device.
const devicePrepareCode = browser.slice(
  browser.indexOf("async function prepareCanonicalDeviceAfterJoin("),
  browser.indexOf("async function join(){"),
);
assert.ok(devicePrepareCode.startsWith("async function prepareCanonicalDeviceAfterJoin("));
assert.match(devicePrepareCode, /ucrCanonicalDeviceAuthority/);
assert.match(devicePrepareCode, /ucrProtectedDeviceKeyVault/);
assert.match(devicePrepareCode, /createUcrCanonicalDevicePreparation/);
let canonicalDevicePreparations = 0;
// Deliberately use the legacy ONE-argument enrollment override. It ignores
// a second requireExistingTrust argument and must NEVER run after Join.
const devicePrepareCtx: Record<string, any> = {
  claims: {tenant_id: "tenant", namespace_id: null, device_id: "device",
    participant_id: "member", call_id: "call", session_id: "session"},
  sessionLifecycleGeneration: 4, sessionActive: true,
  window: {ucrPrepareCanonicalDevice: async (binding: any) => {
    assert.equal(binding.deviceId, "device");
    canonicalDevicePreparations++;
  }},
  requireCanonicalMediaHostReady() {},
};
runInNewContext(devicePrepareCode + "\nthis.prepare = prepareCanonicalDeviceAfterJoin;", devicePrepareCtx);
devicePrepareCtx.sessionActive = false;
await devicePrepareCtx.prepare(4, true);
assert.equal(canonicalDevicePreparations, 1,
  "legacy enrollment override is allowed before signed Join");
devicePrepareCtx.sessionActive = true;
await assert.rejects(devicePrepareCtx.prepare(4), /authenticated canonical Device.Trust authority required after Join/i);
assert.equal(canonicalDevicePreparations, 1,
  "a legacy one-argument enrollment hook cannot be called after Join");
assert.ok(devicePrepareCode.includes('if(authority&&(!beforeJoin||typeof prepare!=="function"))'),
  "the canonical post-Join path must not select a mutable enrollment override");
const joinScript = browser.slice(browser.indexOf("async function join(){"),
  browser.indexOf("function scheduleEntryRetry(){"));
const preJoinIndex = joinScript.indexOf("await prepareCanonicalDeviceAfterJoin(generation,true);");
const serverJoinIndex = joinScript.indexOf('api("/v1/realtime/join"');
const postJoinIndex = joinScript.indexOf("await prepareCanonicalDeviceAfterJoin(generation);");
assert.ok(preJoinIndex >= 0 && serverJoinIndex > preJoinIndex && postJoinIndex > serverJoinIndex,
  "canonical Device is prepared before redeeming the join grant and rechecked afterwards");
devicePrepareCtx.claims.device_id = null;
await assert.rejects(devicePrepareCtx.prepare(4), /Canonical Device identifier/);
assert.equal(canonicalDevicePreparations, 1, "unbound grant cannot register a Device");
devicePrepareCtx.claims.device_id = "device";
devicePrepareCtx.sessionLifecycleGeneration = 5;
await assert.rejects(devicePrepareCtx.prepare(4), /session retired/);
assert.equal(canonicalDevicePreparations, 1, "stale enrollment must not invoke host callbacks");

const preflightSnippet = browser.slice(
  browser.indexOf("function requireCanonicalMediaHostReady(){"),
  browser.indexOf("function closeE2eeTransport(){"),
);
assert.ok(preflightSnippet.startsWith("function requireCanonicalMediaHostReady(){"));
const preflightCtx: Record<string, any> = {
  window: {}, e2eeAdapter: () => null,
  requireCompatibleE2eeAdapter: (x: any) => x,
};
runInNewContext(preflightSnippet +
  "\nthis.preflight = requireCanonicalMediaHostReady;", preflightCtx);
assert.throws(() => preflightCtx.preflight(), /Canonical Device signing\/trust integration is unavailable/);
preflightCtx.window.ucrCanonicalAuthorizedMediaFactory = () => ({});
assert.doesNotThrow(() => preflightCtx.preflight(),
  "registered host authority allows capture to proceed to real E2EE validation");
delete preflightCtx.window.ucrCanonicalAuthorizedMediaFactory;
preflightCtx.window.ucrCanonicalMediaAdmissionResolver = async () => ({});
assert.doesNotThrow(() => preflightCtx.preflight(),
  "existing canonical host admission resolver is recognized without manual factory registration");
delete preflightCtx.window.ucrCanonicalMediaAdmissionResolver;
preflightCtx.window.ucrInstallAuthorizedMediaEndpoint = () => ({});
assert.doesNotThrow(() => preflightCtx.preflight(),
  "custom canonical host installer is permitted only under later strict E2EE checks");
delete preflightCtx.window.ucrInstallAuthorizedMediaEndpoint;
let unexpectedCapture = 0, unexpectedSignalling = 0, unexpectedGrantReads = 0;
const earlyBlockedCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, navigator: {onLine: true},
  claims: {expires: Date.now() + 5000},
  token: "untrusted-join-fragment",
  body: () => {unexpectedGrantReads++;throw new Error("grant inspected before canonical trust");},
  ui: {privacyMode: {value: "secure"}},
  mediaCaptureGeneration: 1,
  installFirstPartyDeviceAuthority: async () => {},
  requireCanonicalMediaHostReady: preflightCtx.preflight,
  ensureLocalMedia: async () => {unexpectedCapture++;},
  api: async () => {unexpectedSignalling++;},
};
const preflightStartCode = browser.slice(
  browser.indexOf("async function startWebRtc("),
  browser.indexOf("async function restartIce("),
);
assert.ok(preflightStartCode.startsWith("async function startWebRtc("));
runInNewContext(preflightStartCode + "\nthis.start = startWebRtc;", earlyBlockedCtx);
await assert.rejects(earlyBlockedCtx.start(),
  /Canonical Device signing\/trust integration is unavailable/);
assert.equal(unexpectedGrantReads, 0, "no grant inspection before canonical trust preflight");
assert.equal(unexpectedCapture, 0, "no microphone/camera prompt without trusted signer");
assert.equal(unexpectedSignalling, 0, "no network offer without trusted signer");

// Code prewarming must never mint trust, join sessions or touch camera/audio.
const warmSnippet = browser.slice(
  browser.indexOf("function prewarmAuthorizedMediaRuntime(){"),
  browser.indexOf("async function activateE2eeAdapter(){"),
);
assert.ok(warmSnippet.startsWith("function prewarmAuthorizedMediaRuntime(){"));
let warmWasm = 0, warmInstaller = 0;
const warmCtx: Record<string, any> = {
  window: {}, Promise, e2eeAdapter: () => null,
  requireCompatibleE2eeAdapter: (x: unknown) => x,
  loadEndpointWasmModule: async () => {warmWasm++;},
  requireAuthorizedMediaInstaller: async () => {warmInstaller++;},
};
runInNewContext(warmSnippet + "\nthis.warm = prewarmAuthorizedMediaRuntime;", warmCtx);
warmCtx.warm();
await Promise.resolve();
assert.equal(warmWasm, 0, "no preload without canonical trust integration");
assert.equal(warmInstaller, 0, "no installer without canonical host");
warmCtx.window.ucrCanonicalAuthorizedMediaFactory = () => ({});
warmCtx.warm();
await Promise.resolve();
assert.equal(warmWasm, 1, "public WASM can be loaded before Join");
assert.equal(warmInstaller, 1, "public endpoint code can be loaded before Join");
// A preinstalled, validated adapter needs no new installer, but MLS WASM
// should still be warm before admission.
warmCtx.window.ucrCanonicalAuthorizedMediaFactory = undefined;
warmCtx.e2eeAdapter = () => ({contractVersion: "ucr.endpoint-e2ee.v1"});
warmCtx.warm();
await Promise.resolve();
assert.equal(warmWasm, 2, "installed endpoint still prewarms WASM");
assert.equal(warmInstaller, 1, "installed endpoint skips installer preload");
// Invalid injected adapters fail at the actual Join gate, not during page load.
warmCtx.requireCompatibleE2eeAdapter = () => {throw new Error("incompatible adapter");};
assert.doesNotThrow(() => warmCtx.warm(), "optional warmup must not crash startup");
await Promise.resolve();
assert.equal(warmWasm, 2, "invalid adapter cannot trigger WASM preload");
assert.equal(warmInstaller, 1, "invalid adapter cannot trigger installer preload");

// The same preflight must happen even earlier: before a signed invite can
// create a realtime session or start a heartbeat in the first place.
const preflightJoinSnippet = browser.slice(
  browser.indexOf("async function join(){"),
  browser.indexOf("function scheduleEntryRetry(){"),
);
assert.ok(preflightJoinSnippet.startsWith("async function join(){"));
let unauthorizedJoinRequests = 0;
const preflightJoinCtx: Record<string, any> = {
  claims: {not_before: 0}, token: "fixture-signed-join", sessionLifecycleGeneration: 0,
  signedGrantRetired: false,
  ui: {state: {textContent: ""}, status: {textContent: ""},
    join: {disabled: false}},
  requireCanonicalMediaHostReady: preflightCtx.preflight,
  api: async () => {unauthorizedJoinRequests++;throw new Error("unexpected join");},
  scheduleWaitingRoom() {},
};
runInNewContext(preflightJoinSnippet + "\nthis.joinCall = join;", preflightJoinCtx);
await preflightJoinCtx.joinCall();
assert.equal(unauthorizedJoinRequests, 0,
  "missing trusted media authority cannot create a realtime session");
assert.equal(preflightJoinCtx.sessionLifecycleGeneration, 0,
  "preflight rejection must not activate a session lifecycle");
assert.equal(preflightJoinCtx.ui.state.textContent, "Secure media unavailable");
assert.equal(preflightJoinCtx.ui.join.disabled, false,
  "user can retry after canonical media authority is installed");

// A server-accepted join followed by MLS/policy activation failure must
// synchronously retire its active session rather than leave a heartbeat alive.
let acceptedJoinCleanup = 0;
let acceptedJoinHeartbeats = 0;
const acceptedJoinCtx: Record<string, any> = {
  claims: {not_before: 0}, token: "fixture-signed-join", sessionLifecycleGeneration: 0,
  signedGrantRetired: false, activeSessionSequence: 0,
  sessionActive: false, mediaActive: false, heartbeatTimer: null,
  ui: {state: {textContent: ""}, status: {textContent: ""},
    join: {disabled: false}, leave: {disabled: true},
    privacyMode: {disabled: false}, expires: {textContent: ""}},
  installFirstPartyDeviceAuthority: async () => {},
  requireCanonicalMediaHostReady() {}, prewarmAuthorizedMediaRuntime() {},
  prepareCanonicalDeviceAfterJoin: async (_generation: number, beforeJoin = false) => {
    // This fixture models an already trusted Device: prepare prior to Join,
    // then revalidate it after server admission before MLS policy activation.
    assert.equal(typeof beforeJoin, "boolean");
  },
  api: async () => ({json: async () => ({ok: true, admission_state: "admitted",
    session_sequence: 1})}),
  body: () => ({}),
  applyMediaPolicy: async () => {throw new Error("MLS activation refused");},
  clearTimeout() {}, cancelMediaStartupWatchdog() {},
  setInterval: () => {acceptedJoinHeartbeats++;return 1;},
  leave: async () => {acceptedJoinCleanup++;acceptedJoinCtx.sessionActive = false;},
  scheduleWaitingRoom() {}, scheduleEntryRetry() {},
};
runInNewContext(preflightJoinSnippet + "\nthis.joinCall = join;", acceptedJoinCtx);
await acceptedJoinCtx.joinCall();
assert.equal(acceptedJoinCleanup, 1, "accepted session is retired on activation failure");
assert.equal(acceptedJoinCtx.sessionActive, false, "no orphan active session");
assert.equal(acceptedJoinHeartbeats, 0, "no heartbeat before failed policy activation");
assert.equal(acceptedJoinCtx.ui.state.textContent, "Rejected");

// The old grant's expiry must stop a pending/untrusted replacement, but it
// must NOT terminate an independently authorized replacement Join whose
// Device/Trust inspection has completed. Its new grant owns startup expiry.
const oldHandoffWatchdog = browser.split("handoffWatchdog=setTimeout(()=>{")[1]
  ?.split("},handoffDeadlineMs);")[0];
assert.ok(oldHandoffWatchdog?.includes("handoffState.trusted"));
assert.ok(browser.includes("armMediaStartupWatchdog(generation,handoff.token,newGrantDeadlineMs);"));
assert.ok(browser.includes("token===grantToken&&!e2eeAdapterReady"),
  "startup watchdog must not mistake SDP completion for endpoint E2EE readiness");
assert.ok(browser.includes("if(!sessionActive||!mediaActive||e2eeAdapterReady)\n      cancelMediaStartupWatchdog(generation);"),
  "keep startup deadline armed when WebRTC signaling completes before E2EE adapter activation");
for (const scenario of [
  {name: "old pending", generation: 10, token: "old", trusted: false, expected: 1},
  {name: "new untrusted", generation: 11, token: "new", trusted: false, expected: 1},
  {name: "new trusted", generation: 11, token: "new", trusted: true, expected: 0},
  {name: "new unrelated", generation: 12, token: "new", trusted: false, expected: 0},
  {name: "foreign token", generation: 11, token: "foreign", trusted: false, expected: 0},
]) {
  let leaveCalls = 0;
  const handoffState = {trusted: scenario.trusted};
  const ctx: Record<string, any> = {
    handoff: 10, oldToken: "old", next: "new",
    token: scenario.token, sessionLifecycleGeneration: scenario.generation,
    handoffState, pendingRenewalHandoff: handoffState,
    signedGrantRetired: false,
    ui: {state: {textContent: ""}, status: {textContent: ""}},
    leave: () => {leaveCalls++;},
    ucrRecordDiagnostic() {},
  };
  runInNewContext("(()=>{" + oldHandoffWatchdog + "})()", ctx);
  assert.equal(leaveCalls, scenario.expected, scenario.name);
  assert.equal(ctx.signedGrantRetired, scenario.expected === 1, scenario.name);
}
// The executable startupGuardSnippet cases above cover stalled startup,
 // settled E2EE activation, old-generation cleanup and Leave.

// A pending asynchronous authority import must not resurrect a grant after
// Leave or an old-grant watchdog advances the canonical lifecycle generation.
let unblockStalePreflight: (() => void) | undefined;
const blockedPreflight = new Promise<void>(resolve => {
  unblockStalePreflight = resolve;
});
let staleJoinRequests = 0;
const staleJoinCtx: Record<string, any> = {
  claims: {not_before: 0}, token: "old", sessionLifecycleGeneration: 5,
  signedGrantRetired: false,
  ui: {state: {textContent: ""}, status: {textContent: ""},
    join: {disabled: false}},
  installFirstPartyDeviceAuthority: () => blockedPreflight,
  requireCanonicalMediaHostReady() {}, prewarmAuthorizedMediaRuntime() {},
  api: () => {staleJoinRequests++;throw new Error("stale Join resurrected");},
};
runInNewContext(preflightJoinSnippet + "\nthis.joinCall = join;", staleJoinCtx);
const staleJoinPending = staleJoinCtx.joinCall();
staleJoinCtx.signedGrantRetired = true;
staleJoinCtx.sessionLifecycleGeneration = 6;
unblockStalePreflight!();
await staleJoinPending;
assert.equal(staleJoinRequests, 0, "late preflight cannot redeem a retired signed grant");
assert.equal(staleJoinCtx.sessionLifecycleGeneration, 6,
  "late preflight cannot allocate a fresh lifecycle generation");

// Chameleon lifecycle: no telemetry may be reported before the endpoint is
// authenticated and running; the first report must start after E2EE activation.
const activateSnippet = browser.slice(
  browser.indexOf("async function activateE2eeAdapter(){"),
  browser.indexOf("function attachE2eeDataChannel("),
);
const closeSnippet = browser.slice(
  browser.indexOf("function closeE2eeTransport(){"),
  browser.indexOf("function readAscii("),
);
assert.ok(activateSnippet.startsWith("async function activateE2eeAdapter()"));
assert.ok(closeSnippet.startsWith("function closeE2eeTransport()"));
let releaseProtectedStartup: (() => void) | undefined;
const protectedStartupGate = new Promise<void>((resolve) => {
  releaseProtectedStartup = resolve;
});
const protectedLifecycleEvents: string[] = [];
const lifecycleChannel = {readyState: "open", close() {}, onopen: null,
  onmessage: null, onclose: null, onerror: null};
const protectedAdapter = {
  start: async () => {
    protectedLifecycleEvents.push("start-begins");
    await protectedStartupGate;
    protectedLifecycleEvents.push("start-completes");
  },
  stop: () => { protectedLifecycleEvents.push("stop"); },
  onEnvelope() {},
};
const lifecycleCtx: Record<string, any> = {
  window: {}, token: "fixture-e2ee-token",
  sessionLifecycleGeneration: 0,
  e2eeActivationGeneration: 0,
  e2eeChannel: lifecycleChannel,
  e2eeAdapterReady: false,
  e2eeManagedAdapter: null,
  e2eePending: null,
  appliedAdaptiveQuality: null,
  sessionActive: true,
  mediaActive: true,
  screenStream: null,
  ui: {
    remoteVideo: {classList: {add() {}, remove() {}}},
    remoteCanvas: {classList: {add() {}, remove() {}},
      width: 640, height: 360, getContext: () => ({clearRect() {}})},
    screenToggle: {disabled: false},
    state: {textContent: "Securing"},
    status: {textContent: ""},
  },
  e2eeAdapter: () => protectedAdapter,
  requireCompatibleE2eeAdapter: () => protectedAdapter,
  restoreEndpointPersistedState: async () => "empty",
  endpointMediaSources: () => ({}),
  sendE2eeEnvelope() {},
  persistEndpointState: async () => true,
  refreshScreenShareControl() {},
  stopAdaptiveMediaMonitoring: () => {protectedLifecycleEvents.push("monitor-stops");},
  startAdaptiveMediaMonitoring: () => {protectedLifecycleEvents.push("monitor-starts");},
  syncReceiveSubscriptions: async () => {protectedLifecycleEvents.push("roster-synced");},
  resetReceiveRoster: () => {protectedLifecycleEvents.push("roster-reset");},
  cancelMediaStartupWatchdog() {},
};
runInNewContext(
  closeSnippet + "\n" + activateSnippet +
  "\nthis.activate = activateE2eeAdapter; this.close = closeE2eeTransport;",
  lifecycleCtx,
);
const activating = lifecycleCtx.activate();
await Promise.resolve();
assert.equal(lifecycleCtx.e2eeAdapterReady, false);
assert.equal(lifecycleCtx.ui.state.textContent, "Securing",
  "ICE connectivity alone must never claim a verified E2EE call");
assert.ok(!protectedLifecycleEvents.includes("monitor-starts"),
  "a missing or unfinished E2EE endpoint must never produce adaptive telemetry");
releaseProtectedStartup?.();
await activating;
assert.equal(lifecycleCtx.e2eeAdapterReady, true);
assert.equal(lifecycleCtx.ui.state.textContent, "Connected",
  "the reference UI becomes connected only after protected endpoint startup");
assert.deepEqual(protectedLifecycleEvents.slice(0, 3),
  ["start-begins", "start-completes", "monitor-starts"]);
lifecycleCtx.close();
assert.equal(lifecycleCtx.e2eeAdapterReady, false);
assert.ok(protectedLifecycleEvents.includes("monitor-stops"),
  "on transport retirement quality polling must stop");
assert.ok(protectedLifecycleEvents.includes("stop"),
  "on transport retirement E2EE adapter must be revoked");
assert.doesNotMatch(
  browser.slice(browser.indexOf("async function activateAdmittedMedia(){"),
    browser.indexOf("async function applyAdmissionState(", browser.indexOf("async function activateAdmittedMedia(){") + 1)),
  /startAdaptiveMediaMonitoring\\(\\)/,
  "admission must not begin sampling before the channel and endpoint are active",
);

// Execute the real DataChannel encrypted-frame handler: per-frame media must
// never trigger a sealed-state IndexedDB write, including large live audiences.
const frameHandlerSnippet = browser.slice(
  browser.indexOf("function attachE2eeDataChannel(channel){"),
  browser.indexOf("function scheduleStreamRetry(){"),
);
assert.ok(frameHandlerSnippet.startsWith("function attachE2eeDataChannel("));
let openedFrameCount = 0;
let persistedFrameCount = 0;
let lastChannel: Record<string, any> | null = null;
const frameCtx: Record<string, any> = {
  E2EE_CHANNEL_LABEL: "ucr.e2ee.media.v1",
  closeE2eeTransport() {},
  receiveE2eeChunk: (wire: unknown) => wire,
  packetCount: 0,
  ui: {packets: {textContent: ""}, status: {textContent: ""},
    webrtcState: {textContent: ""}},
  e2eePending: null,
  e2eeAdapter() {
    return {onEnvelope: async () => {openedFrameCount++;}};
  },
  requireCompatibleE2eeAdapter: (x: unknown) => x,
  persistEndpointState: async () => {persistedFrameCount++;},
  activateE2eeAdapter: async () => {},
};
runInNewContext(frameHandlerSnippet + "\nthis.attach = attachE2eeDataChannel;", frameCtx);
lastChannel = {
  label: "ucr.e2ee.media.v1",
  readyState: "open",
  close() {},
};
frameCtx.attach(lastChannel);
for (let i = 0; i < 80; i++) {
  lastChannel.onmessage({data: new Uint8Array([1, 2, i])});
}
await Promise.resolve();
await Promise.resolve();
assert.equal(openedFrameCount, 80, "80 protected ciphertext frames must be accepted");
assert.equal(persistedFrameCount, 0,
  "media hot path must not persist MLS state on every decrypted frame");


// A real browser permission dialog can resolve AFTER Leave/host withdrawal.
// Execute the actual browser functions rather than asserting only code strings.
const captureCode = browser.slice(
  browser.indexOf("function preferredCameraCapture("),
  browser.indexOf("async function replaceLocalTrack("),
);
assert.ok(captureCode.startsWith("function preferredCameraCapture("));
const capturedResolvers: Array<(stream: any) => void> = [];
let stoppedCaptureTracks = 0;
const capturedTrack = () => ({
  readyState: "live",
  stop() { stoppedCaptureTracks++; },
});
const fakeCapture = (track: any) => ({
  getTracks: () => [track],
  getAudioTracks: () => [track],
  getVideoTracks: () => [],
});
const mediaCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 0,
  localStream: null,
  navigator: {mediaDevices: {
    getUserMedia: () => new Promise((resolve) => { capturedResolvers.push(resolve); }),
  }},
  ui: {mic: {value: ""}, camera: {value: ""}, localVideo: {srcObject: null}},
  policyAllows: (kind: string) => kind === "audio",
  refreshLocalMediaControls() {},
  refreshDevices: async () => {},
  MediaStream: class {},
  e2eeChannel: null,
};
runInNewContext(captureCode +
  "\nthis.getMedia = ensureLocalMedia; this.getTrack = ensureLocalTrack;", mediaCtx);
const mediaPermissionPending = mediaCtx.getMedia();
assert.equal(capturedResolvers.length, 1);
mediaCtx.mediaCaptureGeneration++;
mediaCtx.mediaActive = false;
capturedResolvers.shift()?.(fakeCapture(capturedTrack()));
await assert.rejects(mediaPermissionPending, /authorization changed/);
assert.equal(stoppedCaptureTracks, 1, "late permission grant must stop the microphone");
assert.equal(mediaCtx.localStream, null, "late capture cannot restore a left session");

mediaCtx.mediaActive = true;
mediaCtx.sessionActive = true;
mediaCtx.localStream = {
  getAudioTracks: () => [], getVideoTracks: () => [],
  addTrack() { throw new Error("revoked track must not be added"); },
};
const trackPermissionPending = mediaCtx.getTrack("audio");
assert.equal(capturedResolvers.length, 1);
mediaCtx.sessionActive = false;
mediaCtx.mediaCaptureGeneration++;
mediaCtx.localStream = null;
capturedResolvers.shift()?.(fakeCapture(capturedTrack()));
await assert.rejects(trackPermissionPending, /authorization changed/);
assert.equal(stoppedCaptureTracks, 2, "late individual device grant must stop its track");

// One-click media must not require camera repair/selection before an audio
// conversation is possible. Exercise the real browser capture function.
let cameraRequests = 0, voiceFallbackRequests = 0;
const voiceTrack = capturedTrack();
const voiceStream = fakeCapture(voiceTrack);
const fallbackCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 0,
  localStream: null,
  navigator: {mediaDevices: {
    async getUserMedia({audio, video}: {audio: unknown; video: unknown}) {
      assert.ok(audio, "audio fallback never bypasses media admission");
      if (video) {
        cameraRequests++;
        throw Object.assign(new Error("No camera found"), {name: "NotFoundError"});
      }
      voiceFallbackRequests++;
      return voiceStream;
    },
  }},
  ui: {mic: {value: ""}, camera: {value: ""}, localVideo: {srcObject: null},
    status: {textContent: ""}},
  policyAllows: (kind: string) => kind === "audio" || kind === "camera",
  refreshLocalMediaControls() {},
  refreshDevices: async () => {},
  MediaStream: class {},
  e2eeChannel: null,
};
runInNewContext(captureCode + "\nthis.getMedia = ensureLocalMedia;", fallbackCtx);
assert.equal(await fallbackCtx.getMedia(), voiceStream);
assert.equal(cameraRequests, 1, "first attempt uses permitted video and audio");
assert.equal(voiceFallbackRequests, 1, "unavailable camera must trigger audio-only retry");
assert.match(fallbackCtx.ui.status.textContent, /protected audio call automatically/);
assert.equal(fallbackCtx.ui.localVideo.srcObject, voiceStream);

// A delayed camera failure after Leave/revocation must NOT request the mic.
// This tests the real capture helper across the initial async permission gap.
let rejectPendingCamera: (error: Error) => void = () => {};
let lateCaptureAttempts = 0;
const lateFallbackCtx: Record<string, any> = {
  ...fallbackCtx,
  localStream: null,
  mediaCaptureGeneration: 0,
  sessionActive: true,
  mediaActive: true,
  navigator: {mediaDevices: {
    getUserMedia() {
      lateCaptureAttempts++;
      if (lateCaptureAttempts !== 1)throw new Error("post-Leave microphone capture attempted");
      return new Promise((_resolve, reject) => {rejectPendingCamera = reject;});
    },
  }},
  ui: {mic: {value: ""}, camera: {value: ""}, localVideo: {srcObject: null},
    status: {textContent: ""}},
};
runInNewContext(captureCode + "\nthis.getMedia = ensureLocalMedia;", lateFallbackCtx);
const cameraPermissionPending = lateFallbackCtx.getMedia();
assert.equal(lateCaptureAttempts, 1);
lateFallbackCtx.mediaCaptureGeneration++;
lateFallbackCtx.mediaActive = false;
lateFallbackCtx.sessionActive = false;
rejectPendingCamera(Object.assign(new Error("Camera no longer accessible"), {name: "NotReadableError"}));
await assert.rejects(cameraPermissionPending, /authorization changed/);
assert.equal(lateCaptureAttempts, 1, "revoked admission must not trigger a second OS permission prompt");
assert.equal(lateFallbackCtx.localStream, null);

let blockedPermissionAttempts = 0;
const blockedCtx: Record<string, any> = {
  ...fallbackCtx, localStream: null,
  navigator: {mediaDevices: {
    async getUserMedia() {
      blockedPermissionAttempts++;
      throw Object.assign(new Error("User denied access"), {name: "NotAllowedError"});
    },
  }},
  ui: {mic: {value: ""}, camera: {value: ""}, localVideo: {srcObject: null},
    status: {textContent: ""}},
};
runInNewContext(captureCode + "\nthis.getMedia = ensureLocalMedia;", blockedCtx);
await assert.rejects(blockedCtx.getMedia(), /User denied access/);
assert.equal(blockedPermissionAttempts, 1,
  "explicit operating-system/browser permission denial must never trigger alternate capture");


const startCode = browser.slice(
  browser.indexOf("async function startWebRtc("),
  browser.indexOf("async function restartIce("),
);
assert.ok(startCode.startsWith("async function startWebRtc("));
let releaseStartCapture: () => void = () => {};
const startCaptureGate = new Promise<void>(resolve => { releaseStartCapture = resolve; });
let enterStartCapture: () => void = () => {};
const startCaptureEntered = new Promise<void>(resolve => { enterStartCapture = resolve; });
let serverOffers = 0, stalePeerCreates = 0, stalePeerCloses = 0;
const startCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  peer: null,
  navigator: {onLine: true}, ui: {privacyMode: {value: "secure"}},
  requireCanonicalMediaHostReady() {}, body: () => ({}),
  rtcNetworkConfiguration: () => ({}),
  ensureLocalMedia: async () => {enterStartCapture(); await startCaptureGate;},
  api: async () => {
    serverOffers++;
    return {json: async () => ({ice_servers: [], offer_id: "A".repeat(43), sdp_type: "offer", sdp: "offer"})};
  },
  closeServerPeer: async () => {stalePeerCloses++;},
  RTCPeerConnection: class {constructor() {stalePeerCreates++;}},
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", startCtx);
const staleStart = startCtx.start();
await startCaptureEntered;
startCtx.mediaCaptureGeneration++;
startCtx.mediaActive = false;
releaseStartCapture();
await assert.rejects(staleStart, /cancelled by conference media teardown/);
assert.equal(serverOffers, 1, "server offer is validated before device capture");
assert.equal(stalePeerCreates, 0, "revoked admission cannot create a stale peer");
assert.equal(stalePeerCloses, 1, "withdrawn admission retires its orphaned server offer");
// A client peer newly owned by another path must never be closed by stale cleanup.
// A replacement peer and grant may become current while the old offer is
// awaiting local media. Retire only the old offer with its captured authority.
const retiredClaims = {session_id: "retired-session"};
const replacementClaims = {session_id: "replacement-session"};
const replacementPeer = {connectionState: "connected"};
const retiredOfferId = "A".repeat(43);
const retiredOffers: Array<{offerId: string; claims: unknown; grant: string}> = [];
const replacementCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  navigator: {onLine: true}, peer: null,
  ui: {privacyMode: {value: "secure"}},
  requireCanonicalMediaHostReady() {}, body: () => retiredClaims,
  rtcNetworkConfiguration: () => ({}),
  api: async () => ({json: async () => ({ice_servers: [], offer_id: retiredOfferId})}),
  ensureLocalMedia: async () => {
    replacementCtx.peer = replacementPeer;
    replacementCtx.token = "replacement-grant";
    replacementCtx.body = () => replacementClaims;
    replacementCtx.mediaCaptureGeneration++;
  },
  closeServerPeer: async (_keepalive: boolean, offerId: string, claims: unknown, grant: string) => {
    retiredOffers.push({offerId, claims, grant});
  },
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", replacementCtx);
await assert.rejects(replacementCtx.start(), /cancelled by conference media teardown/);
assert.equal(retiredOffers.length, 1, "stale offer must be retired exactly once");
assert.equal(retiredOffers[0].offerId, retiredOfferId, "cleanup must target the retired offer");
assert.equal(retiredOffers[0].claims, retiredClaims, "cleanup must retain the original session");
assert.equal(retiredOffers[0].grant, "fixture-signed-join", "cleanup must not borrow a replacement grant");
assert.equal(replacementCtx.peer, replacementPeer, "stale cleanup cannot close newly owned peer");

// A missing TURN relay in private mode must fail before microphone/camera prompts.
let privateCaptures = 0, privateServerCloses = 0;
const privateCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  peer: null,
  navigator: {onLine: true}, ui: {privacyMode: {value: "private"}},
  requireCanonicalMediaHostReady() {}, body: () => ({}),
  ensureLocalMedia: async () => {privateCaptures++;},
  api: async () => ({json: async () => ({ice_servers: [], offer_id: "A".repeat(43), sdp_type: "offer", sdp: "offer"})}),
  closeServerPeer: async () => {privateServerCloses++;},
};
const rtcConfigCode = browser.slice(
  browser.indexOf("function rtcNetworkConfiguration("),
  browser.indexOf("async function startWebRtc("),
);
runInNewContext(rtcConfigCode + startCode + "\nthis.start = startWebRtc;", privateCtx);
await assert.rejects(privateCtx.start(), /Higher privacy requires configured TURN relay/);
assert.equal(privateCaptures, 0, "missing TURN cannot prompt for media");
assert.equal(privateServerCloses, 1, "failed privacy negotiation closes the server peer");

let rejectedCaptures = 0;
const rejectedCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  navigator: {onLine: true}, ui: {privacyMode: {value: "secure"}},
  requireCanonicalMediaHostReady() {}, body: () => ({}),
  ensureLocalMedia: async () => {rejectedCaptures++;},
  api: async () => {throw new Error("server rejected offer");},
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", rejectedCtx);
await assert.rejects(rejectedCtx.start(), /server rejected offer/);
assert.equal(rejectedCaptures, 0, "failed signaling cannot prompt for camera or microphone");

// An authorized offer with an unusable local browser peer must not poison
// the next attempt with a lingering server session.
let constructorCloses = 0;
const constructorCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  peer: null, navigator: {onLine: true},
  ui: {privacyMode: {value: "secure"}},
  requireCanonicalMediaHostReady() {}, body: () => ({}),
  rtcNetworkConfiguration: () => ({}),
  api: async () => ({json: async () => ({ice_servers: [], offer_id: "A".repeat(43)})}),
  ensureLocalMedia: async () => {},
  closeServerPeer: async () => {constructorCloses++;},
  RTCPeerConnection: class {constructor() {throw new Error("browser peer unavailable");}},
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", constructorCtx);
await assert.rejects(constructorCtx.start(), /browser peer unavailable/);
assert.equal(constructorCloses, 1, "failed peer construction must retire its server offer");

// Session-scoped close must finish before a later start allocates a new offer.
let releaseOrphanClose: () => void = () => {};
let orphanCloseEntered: () => void = () => {};
const orphanCloseGate = new Promise<void>(resolve => {releaseOrphanClose = resolve;});
const orphanCloseStarted = new Promise<void>(resolve => {orphanCloseEntered = resolve;});
let serializedOffers = 0, serializedCloses = 0;
const serializedCtx: Record<string, any> = {
  token: "fixture-signed-join",
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 1,
  peer: null, navigator: {onLine: true},
  ui: {privacyMode: {value: "secure"}},
  requireCanonicalMediaHostReady() {}, body: () => ({}),
  rtcNetworkConfiguration: () => ({}),
  api: async () => {serializedOffers++; return {json: async () => ({ice_servers: [], offer_id: "A".repeat(43)})};},
  ensureLocalMedia: async () => {},
  closeServerPeer: async () => {
    serializedCloses++;
    if(serializedCloses===1){orphanCloseEntered();await orphanCloseGate;}
  },
  RTCPeerConnection: class {constructor() {throw new Error("peer constructor refused");}},
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", serializedCtx);
const firstOrphanStart = serializedCtx.start();
await orphanCloseStarted;
const secondOrphanStart = serializedCtx.start();
await Promise.resolve();
assert.equal(serializedOffers, 1, "replacement offer must wait for orphan cleanup");
releaseOrphanClose();
await assert.rejects(firstOrphanStart, /peer constructor refused/);
await assert.rejects(secondOrphanStart, /peer constructor refused/);
assert.equal(serializedOffers, 2, "retry can allocate an offer after cleanup");
assert.equal(serializedCloses, 2, "each failed attempt cleans up only its own offer");

// A delayed HTTP close must be fenced by the offer that initiated it; its
// response cannot clear ownership of a newer transport attempt.
const browserCloseCode = browser.slice(
  browser.indexOf("async function closeServerPeer("),
  browser.indexOf("function scheduleWebRtcRetry("),
);
let releaseFencedClose: () => void = () => {};
let enteredFencedClose: () => void = () => {};
const fencedCloseGate = new Promise<void>(resolve => {releaseFencedClose = resolve;});
const fencedCloseEntered = new Promise<void>(resolve => {enteredFencedClose = resolve;});
const observedFencedCloses: string[] = [];
const fencedCtx: Record<string, any> = {
  sessionActive: true,
  startWebRtc: Object.assign(() => {}, {offerId: "A".repeat(43)}),
  body: () => ({session_id: "session"}),
  api: async (_route: string, payload: any) => {
    observedFencedCloses.push(payload.offer_id);
    if(observedFencedCloses.length===1){enteredFencedClose();await fencedCloseGate;}
  },
};
runInNewContext(browserCloseCode + "\nthis.closeOffer = closeServerPeer;", fencedCtx);
const oldCloseInFlight = fencedCtx.closeOffer();
await fencedCloseEntered;
fencedCtx.startWebRtc.offerId = "B".repeat(43);
releaseFencedClose();
await oldCloseInFlight;
assert.equal(fencedCtx.startWebRtc.offerId, "B".repeat(43), "stale response must preserve new offer");
await fencedCtx.closeOffer();
assert.deepEqual(observedFencedCloses, ["A".repeat(43), "B".repeat(43)]);
assert.equal(fencedCtx.startWebRtc.offerId, null, "owner clears only after its own close");
await fencedCtx.closeOffer();
assert.equal(observedFencedCloses.length, 2, "no unfenced session-wide close");

// Real browser conference admission withdrawal must turn OFF physical
// camera/microphone capture, not only close the encrypted DataChannel.
const captureStopCode = browser.slice(
  browser.indexOf("function stopLocalCapture(){"),
  browser.indexOf("function teardownPeer(){"),
);
const admissionCode = browser.slice(
  browser.indexOf("async function activateAdmittedMedia(){"),
  browser.indexOf("function scheduleWaitingRoom(){"),
);
assert.ok(captureStopCode.startsWith("function stopLocalCapture(){"));
assert.ok(admissionCode.startsWith("async function activateAdmittedMedia(){"));
const stoppedPhysical: string[] = [];
const makePhysicalStream = () => ({
  getTracks: () => [
    {stop() {stoppedPhysical.push("microphone");}},
    {stop() {stoppedPhysical.push("camera");}},
  ],
});
let protectedTeardowns = 0;
let policyApplications = 0;
let resurrectionAttempts = 0;
const admissionUi: Record<string, any> = {
  localVideo: {srcObject: {}},
  handToggle: {disabled: false}, reactionSend: {disabled: false},
  chatInput: {disabled: false}, chatSend: {disabled: false},
  state: {textContent: ""}, webrtcState: {textContent: ""},
  status: {textContent: ""}, join: {disabled: false},
  leave: {disabled: false}, privacyMode: {disabled: false},
  expires: {textContent: ""},
};
const admissionCtx: Record<string, any> = {
  ui: admissionUi, claims: {not_before: 0}, token: "fixture-signed-join", sessionActive: true,
  mediaActive: true, mediaCaptureGeneration: 0, sessionLifecycleGeneration: 0,
  heartbeatRequestGeneration: 0, heartbeatInFlight: false, heartbeatWatchdog: null,
  signedGrantRetired: false, activeSessionSequence: 1,
  HEARTBEAT_AUTH_TIMEOUT_MS: 12000, setTimeout: () => 1,
  requireCanonicalMediaHostReady() {},
  endpointMlsInvalidationGeneration: 0, endpointMlsBootstrapAbort: null,
  endpointMlsState: null, endpointMlsGroupId: null, window: {},
  localStream: makePhysicalStream(), streamAbort: {abort() {}},
  webrtcRetryTimer: 1, streamRetryTimer: 2, reactionTimer: null, chatTimer: null,
  clearTimeout() {}, clearInterval() {}, cancelMediaStartupWatchdog() {},
  stopAdaptiveMediaMonitoring() {}, stopActiveSpeakerMonitoring() {},
  refreshLocalMediaControls() {}, waitCopy: () => "Waiting for host",
  teardownPeer() { protectedTeardowns++; },
  applyMediaPolicy: async () => {policyApplications++;},
  syncReceiveSubscriptions: async () => {},
  e2eeAdapterReady: false, body: () => ({}),
  api: async () => {throw new Error("unexpected network request");},
};
runInNewContext(
  mlsSnippet + "\n" + captureStopCode + "\n" + admissionCode +
  "\nthis.admission = applyAdmissionState;" +
  "\nthis.heartbeat = heartbeat; this.joinConference = join;" +
  "\nthis.activateAdmitted = activateAdmittedMedia;",
  admissionCtx,
);
await admissionCtx.admission("waiting_room");
assert.deepEqual(stoppedPhysical, ["microphone", "camera"],
  "waiting room must stop the real microphone/camera tracks");
assert.equal(admissionCtx.localStream, null);
assert.equal(admissionUi.localVideo.srcObject, null);
assert.equal(admissionCtx.mediaActive, false);
assert.equal(admissionCtx.streamAbort, null, "waiting room must abort realtime stream");
assert.equal(admissionCtx.streamRetryTimer, null);
assert.equal(protectedTeardowns, 1);
admissionCtx.mediaActive = true;
admissionCtx.localStream = makePhysicalStream();
await admissionCtx.admission("closed");
assert.deepEqual(stoppedPhysical, ["microphone", "camera", "microphone", "camera"]);
assert.equal(admissionCtx.localStream, null, "closed conference must stop devices");
assert.equal(protectedTeardowns, 2, "closed conference must not double teardown");

// A heartbeat already in the network must not restore admission after Leave.
let releaseHeartbeat: ((response: any) => void) | undefined;
const heartbeatGate = new Promise<any>(resolve => {releaseHeartbeat = resolve;});
admissionCtx.sessionActive = true;
admissionCtx.mediaActive = false;
admissionCtx.api = async () => heartbeatGate;
const lateHeartbeat = admissionCtx.heartbeat();
admissionCtx.sessionLifecycleGeneration++;
admissionCtx.sessionActive = false;
releaseHeartbeat?.({json: async () => ({admission_state: "admitted"})});
await lateHeartbeat;
assert.equal(policyApplications, 0, "late heartbeat cannot change policy after Leave");
assert.equal(admissionCtx.mediaActive, false);

// A stale heartbeat rejection cannot call the interval's access-revoked
// catch handler and accidentally leave a newly admitted session.
let rejectLateHeartbeat: ((reason: Error) => void) | undefined;
admissionCtx.sessionActive = true;
admissionCtx.api = async () => new Promise((_resolve, reject) => {
  rejectLateHeartbeat = reject;
});
const staleRejectedHeartbeat = admissionCtx.heartbeat();
admissionCtx.sessionLifecycleGeneration++;
rejectLateHeartbeat?.(new Error("heartbeat_rejected"));
await staleRejectedHeartbeat;
// A retired heartbeat belongs to the previous lifecycle; Leave resets the
// in-flight latch before a fresh session can perform authorization.
admissionCtx.heartbeatInFlight = false;
admissionCtx.api = async () => {throw new Error("heartbeat_rejected");};
await assert.rejects(admissionCtx.heartbeat(), /heartbeat_rejected/,
  "current heartbeat denial must still propagate to revocation handler");

// Single-in-flight: repeated timer ticks cannot overlap an unverified heartbeat.
const pendingHeartbeatResponses: Array<(value: any) => void> = [];
admissionCtx.sessionActive = true;
admissionCtx.api = async () => new Promise(resolve => {
  pendingHeartbeatResponses.push(resolve);
});
const olderHeartbeat = admissionCtx.heartbeat();
const ignoredConcurrentHeartbeat = admissionCtx.heartbeat();
assert.equal(pendingHeartbeatResponses.length, 1,
  "heartbeat must allow at most one in-flight authorization request");
await ignoredConcurrentHeartbeat;
pendingHeartbeatResponses[0]({json: async () =>
  ({admission_state: "waiting_room", media_policy: null})});
await olderHeartbeat;
assert.equal(admissionCtx.mediaActive, false,
  "completed heartbeat must preserve withdrawn admission");

// An already authorized join response can arrive after navigation/Leave.
// It must not create a new active session or start microphone capture.
let releaseJoin: ((response: any) => void) | undefined;
admissionCtx.api = async () => new Promise(resolve => {releaseJoin = resolve;});
admissionCtx.sessionActive = false;
const lateJoin = admissionCtx.joinConference();
admissionCtx.sessionLifecycleGeneration++;
releaseJoin?.({json: async () => ({ok: true, admission_state: "admitted"})});
await lateJoin;
assert.equal(admissionCtx.sessionActive, false, "stale join response cannot resurrect session");

// MLS bootstrap may also resolve after Leave. An old bootstrap must not start
// a new WebRTC sender when admission was already revoked.
let releaseMls: (() => void) | undefined;
const mlsGate = new Promise<void>(resolve => {releaseMls = resolve;});
admissionCtx.sessionActive = true;
admissionCtx.mediaActive = false;
admissionCtx.ensureEndpointMlsReady = async () => mlsGate;
admissionCtx.startWebRtc = async () => {resurrectionAttempts++;};
const pendingAdmission = admissionCtx.activateAdmitted();
admissionCtx.sessionLifecycleGeneration++;
admissionCtx.sessionActive = false;
releaseMls?.();
await pendingAdmission;
assert.equal(admissionCtx.mediaActive, false);
assert.equal(resurrectionAttempts, 0, "revoked MLS bootstrap cannot start WebRTC");

// A real SDP answer may still be pending after the user leaves. Verify the
// browser aborts the actual negotiation before sending stale server signaling.
let signalRemoteDescriptionEntered: () => void = () => {};
const remoteDescriptionEntered = new Promise<void>(resolve => {
  signalRemoteDescriptionEntered = resolve;
});
let releaseRemoteDescription: () => void = () => {};
const remoteDescriptionGate = new Promise<void>(resolve => {
  releaseRemoteDescription = resolve;
});
let attemptedStaleAnswer = 0;
let staleRemoteDescriptionPosts = 0;
class NegotiationPeer {
  connectionState = "connecting";
  localDescription = {type: "answer", sdp: "local-answer"};
  async setRemoteDescription() {
    signalRemoteDescriptionEntered();
    await remoteDescriptionGate;
  }
  async createAnswer() { attemptedStaleAnswer++; return this.localDescription; }
  async setLocalDescription() {}
}
const negotiationCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 2,
  navigator: {onLine: true}, peer: null, remoteStream: null,
  ui: {privacyMode: {value: "secure"}, remoteVideo: {srcObject: null},
    webrtcState: {textContent: ""}, state: {textContent: ""},
    status: {textContent: ""}},
  requireCanonicalMediaHostReady() {},
  ensureLocalMedia: async () => ({}),
  api: async (path: string) => {
    if(path.endsWith("/webrtc/start"))return {json: async () => ({
      ice_servers: [], offer_id: "A".repeat(43), sdp_type: "offer", sdp: "remote-offer",
    })};
    staleRemoteDescriptionPosts++;
    return {ok: true};
  },
  body: () => ({}), rtcNetworkConfiguration: () => ({}),
  RTCPeerConnection: NegotiationPeer, MediaStream: class {},
  webrtcRetryTimer: null, e2eeChannel: null, scheduleWebRtcRetry() {},
  closeServerPeer: async () => {throw new Error("unexpected orphan close during SDP test");},
};
runInNewContext(startCode + "\nthis.start = startWebRtc;", negotiationCtx);
const blockedNegotiation = negotiationCtx.start();
await remoteDescriptionEntered;
negotiationCtx.mediaCaptureGeneration++;
negotiationCtx.sessionActive = false;
releaseRemoteDescription();
await assert.rejects(blockedNegotiation, /cancelled by conference media teardown/);
assert.equal(attemptedStaleAnswer, 0, "teardown must prevent stale SDP answer");
assert.equal(staleRemoteDescriptionPosts, 0, "teardown must prevent server SDP write");

const restartCode = browser.slice(
  browser.indexOf("async function restartIce(){"),
  browser.indexOf("async function recoverWebRtc(){"),
);
assert.ok(restartCode.startsWith("async function restartIce(){"));
let releaseRestartOffer: ((value: any) => void) | undefined;
const pendingRestartOffer = new Promise<any>(resolve => {
  releaseRestartOffer = resolve;
});
let staleRestartConfigWrites = 0;
const iceCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 3,
  navigator: {onLine: true}, restarting: false,
  peer: {connectionState: "connected", setConfiguration() {
    staleRestartConfigWrites++;
  }},
  webrtcRetryTimer: null,
  ui: {privacyMode: {value: "secure"}, webrtcState: {textContent: ""},
    status: {textContent: ""}},
  api: async () => pendingRestartOffer,
  body: () => ({}), rtcNetworkConfiguration: () => ({}),
  clearTimeout() {},
};
runInNewContext(restartCode + "\nthis.restart = restartIce;", iceCtx);
const staleIce = iceCtx.restart();
iceCtx.mediaActive = false;
iceCtx.mediaCaptureGeneration++;
releaseRestartOffer?.({json: async () => ({
  ice_servers: [], sdp_type: "offer", sdp: "stale-restart",
})});
await assert.rejects(staleIce, /ICE restart cancelled by conference media teardown/);
assert.equal(staleRestartConfigWrites, 0,
  "revoked conference must not install new ICE configuration");
assert.equal(iceCtx.restarting, false, "aborted ICE restart must release restart guard");

// ICE restart may update SDP, but cannot silently switch the transport's
// original close fence to an unrelated/replaced WebRTC peer.
let changedFenceConfigurationWrites = 0;
const changedFenceCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, mediaCaptureGeneration: 3,
  navigator: {onLine: true}, restarting: false,
  startWebRtc: {offerId: "A".repeat(43)},
  peer: {connectionState: "connected", setConfiguration() {changedFenceConfigurationWrites++;}},
  webrtcRetryTimer: null,
  ui: {privacyMode: {value: "secure"}, webrtcState: {textContent: ""},
    status: {textContent: ""}},
  api: async () => ({json: async () => ({
    ice_servers: [], offer_id: "B".repeat(43), sdp_type: "offer", sdp: "unowned-restart",
  })}),
  body: () => ({}), rtcNetworkConfiguration: () => ({}),
  clearTimeout() {},
};
runInNewContext(restartCode + "\nthis.restart = restartIce;", changedFenceCtx);
await assert.rejects(changedFenceCtx.restart(), /ICE restart changed immutable WebRTC transport offer identity/);
assert.equal(changedFenceConfigurationWrites, 0, "wrong-owner ICE restart cannot alter network configuration");
assert.equal(changedFenceCtx.restarting, false, "rejected ICE restart must release restart guard");

// Execute browser's canonical roster -> per-viewer SFU subscription journey.
// The VM never supplies a parallel admission owner or a forged roster.
const rosterCode = browser.slice(
  browser.indexOf("function resetReceiveRoster(){"),
  browser.indexOf("function stopAdaptiveMediaMonitoring(){"),
);
assert.ok(rosterCode.startsWith("function resetReceiveRoster(){"));
const sourceList = [
  {source_id: "self", source_kind: 1},
  {source_id: "alice", source_kind: 1},
  {source_id: "bob", source_kind: 1},
];
const rosterRequests: Array<{path: string; subscriptions?: any[]}> = [];
const rosterChannel = {readyState: "open"};
const rosterClaims = {participant_id: "self"};
const rosterCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, e2eeAdapterReady: true,
  e2eeChannel: rosterChannel, claims: rosterClaims,
  receiveRosterGeneration: 0, receiveRosterInFlight: false,
  appliedAdaptiveQuality: null,
  receiveSubscriptionFingerprint: null, receiveSubscriptionInFlight: false,
  receiveSubscriptionDirty: false, receiveRosterSources: [],
  receiveSpeakerId: null, receiveSpeakerCandidate: null, receiveSpeakerSamples: 0,
  ui: {status: {textContent: ""}},
  TextEncoder, body: () => ({}), e2eeAdapter: () => ({}),
  api: async (path: string, payload: any) => {
    rosterRequests.push({path, subscriptions: payload?.subscriptions});
    return path.endsWith("/receive-roster")
      ? {ok: true, json: async () => ({ok: true, call_revision: 8,
          sources: sourceList})}
      : {ok: true, json: async () => ({ok: true})};
  },
};
runInNewContext(rosterCode +
  "\nthis.syncRoster = syncReceiveSubscriptions;" +
  "\nthis.updateSpeaker = updateReceiveActiveSpeaker;" +
  "\nthis.resetRoster = resetReceiveRoster;" +
  "\nthis.planRoster = planReceiveSubscriptions;" +
  "\nthis.validRoster = validReceiveRoster;",
  rosterCtx);
await rosterCtx.syncRoster();
assert.equal(rosterRequests.length, 2, "accepted roster fetch must precede SFU selection");
assert.equal(rosterRequests[0]?.path, "/v1/realtime/receive-roster");
assert.equal(rosterRequests[1]?.path, "/v1/realtime/subscriptions");
assert.deepEqual(
  Array.from(rosterRequests[1].subscriptions).map((s: any) => [s.source_id, s.media_kind]),
  [["alice", 1], ["bob", 1], ["alice", 2]],
  "self must be excluded; one video source plus bounded audio are chosen"
);
await rosterCtx.syncRoster();
assert.equal(rosterRequests.length, 3,
  "stable roster must not repeat an identical SFU selection");
const many = Array.from({length: 1000}, (_, i) => ({
  source_id: "participant-" + i, source_kind: 1,
}));
const bounded = rosterCtx.planRoster(many, "participant-990");
assert.equal(bounded.length, 32, "viewer never exceeds canonical 32 subscriptions");
assert.equal(bounded.filter((x: any) => x.media_kind === 2).length, 1,
  "one video canvas must never mix multiple speakers");
assert.equal(bounded[31].source_id, "participant-990",
  "a chosen speaker outside the first audio page is still viewable");
assert.equal(bounded.filter((x: any) => x.media_kind === 1 &&
  x.source_id === "participant-990").length, 1,
  "the selected video speaker must remain audible beyond the 32-item roster cap");
// Exact SFU stream IDs are selected only from authenticated, actually
// observed endpoint frames. HD stays subscribed until low is rendered.
const verifiedLayers = [
  {sourceId: "bob", sourceDeviceId: "device-b", streamId: "camera-b"},
  {sourceId: "bob", sourceDeviceId: "device-b", streamId: "camera-b-low"},
];
let displayedLayer = "camera-b";
const layerAdapter = {
  getVerifiedReceiveVideoStreams: () => verifiedLayers,
  getActiveReceiveVideoStreams: () => [{sourceId: "bob",
    sourceDeviceId: "device-b", streamId: displayedLayer}],
};
rosterCtx.appliedAdaptiveQuality = JSON.stringify({
  stage: "video_720p", video: {width: 1280, height: 720},
});
const selectedVideoIds = (items: any[]) =>
  Array.from(items).filter((item: any) => item.media_kind === 2)
    .map((item: any) => item.stream_id);
const preparing = rosterCtx.planRoster(sourceList.slice(1), "bob", layerAdapter);
assert.equal(preparing.length, 4);
assert.deepEqual(selectedVideoIds(preparing), ["camera-b", "camera-b-low"],
  "keep old ciphertext while waiting for the new authenticated decoded layer");
displayedLayer = "camera-b-low";
const committed = rosterCtx.planRoster(sourceList.slice(1), "bob", layerAdapter);
assert.deepEqual(selectedVideoIds(committed), ["camera-b-low"],
  "unsubscribe old HD only after the low layer has actually rendered");
rosterCtx.appliedAdaptiveQuality = JSON.stringify({stage: "video_1080p"});
const upshift = rosterCtx.planRoster(sourceList.slice(1), "bob", layerAdapter);
assert.deepEqual(selectedVideoIds(upshift), ["camera-b-low", "camera-b"],
  "Full HD upshift must preserve old video until decode completes");
const missingLow = rosterCtx.planRoster(sourceList.slice(1), "bob", {
  ...layerAdapter, getVerifiedReceiveVideoStreams: () => verifiedLayers.slice(0, 1),
});
assert.deepEqual(selectedVideoIds(missingLow), [null],
  "missing real layer cannot be invented or prematurely unsubscribe video");
rosterCtx.appliedAdaptiveQuality = JSON.stringify({stage: "audio"});
const audioFallback = rosterCtx.planRoster(sourceList.slice(1), "bob", layerAdapter);
assert.equal(audioFallback.some((x: any) => x.media_kind === 2), false,
  "audio-only policy must stop forwarding encrypted video");
rosterCtx.appliedAdaptiveQuality = null;
assert.equal(rosterCtx.validRoster({ok: true, sources: [
  {source_id: "alice", source_kind: 1},
  {source_id: "alice", source_kind: 1},
]}), null, "duplicated canonical identity must be rejected");
rosterCtx.updateSpeaker("bob");
rosterCtx.updateSpeaker("bob");
for(let i=0;i<6;i++)await Promise.resolve();
assert.ok(rosterRequests.some(r=>r.subscriptions?.some(s=>
  s.media_kind===2&&s.source_id==="bob"
)), "a stable authorized active speaker must switch the single video subscription");
rosterCtx.updateSpeaker("outsider");
assert.equal(rosterCtx.receiveSpeakerId, "bob",
  "unlisted speaker must never influence canonical receive subscriptions");

// Stale roster response cannot resurrect a revoked E2EE receiver.
let releaseRoster: (() => void) | undefined;
const revokedRosterGate = new Promise<void>(resolve => { releaseRoster = resolve; });
let staleSubscriptionWrites = 0;
rosterCtx.api = async (path: string) => {
  if(path.endsWith("/receive-roster")) {
    await revokedRosterGate;
    return {ok: true, json: async () => ({ok: true, sources: sourceList})};
  }
  staleSubscriptionWrites++;
  return {ok: true};
};
const revokedRoster = rosterCtx.syncRoster();
await Promise.resolve();
rosterCtx.resetRoster();
rosterCtx.e2eeAdapterReady = false;
releaseRoster?.();
await revokedRoster;
assert.equal(staleSubscriptionWrites, 0,
  "outdated roster must never write SFU subscriptions after E2EE retirement");

assert.match(browser, /ucr\.endpoint-e2ee\.v1/);
assert.match(browser, /Protected endpoint E2EE adapter v1 with revocation is required/);
assert.match(browser, /restoreSealedState/);
assert.match(browser, /sealState/);
assert.match(browser, /validAdaptiveQualityTarget/);
assert.match(browser, /preferredCameraCapture\(ui\.camera\.value\)/);
assert.match(browser, /width:\{ideal:1280,max:1920\},height:\{ideal:720,max:1080\}/);
assert.match(browser, /e2eeAdapterReady=true/);
assert.match(browser, /!e2eeAdapterReady/);
assert.match(browser, /adapter\.applyReceiveMediaDecision\(target\)/);
assert.doesNotMatch(browser.slice(browser.indexOf("async function reportAdaptiveMedia()"), browser.indexOf("function startAdaptiveMediaMonitoring()")), /scheduleWebRtcRetry/);

// Execute the real reference-browser adaptation path, not merely a string check.
// The VM supplies a stubbed authenticated endpoint; no camera, plaintext path, or
// parallel protocol is introduced by these boundary/epoch/reconnect tests.
const qualityCode = browser.slice(
  browser.indexOf("function validAdaptiveQualityTarget("),
  browser.indexOf("function startAdaptiveMediaMonitoring()"),
);
assert.ok(qualityCode.startsWith("function validAdaptiveQualityTarget("));
assert.ok(qualityCode.includes("async function reportAdaptiveMedia()"));
const appliedReceive: unknown[] = [];
let retryAttempted = 0;
const qualityTarget = {
  ok: true, stage: "video_1080p",
  video: {codec_capability_id: "ucr.video.h264", width: 1920, height: 1080,
    frame_rate: 30, target_bitrate_bps: 4_000_000},
  opus_target_bitrate_bps: null,
};
const adapter = {
  getReceiveMediaTelemetry: () => ({
    estimated_bandwidth_bps: 8_000_000,
    packet_loss_basis_points: 0,
    jitter_ms: 2, rtt_ms: 12,
    cpu_utilization_percent: 30, gpu_utilization_percent: null,
    battery_percent: 80, external_power: true, thermal_state: "nominal",
  }),
  applyReceiveMediaDecision: async (target: unknown) => { appliedReceive.push(target); },
};
const sessionClaims = {session: "1"};
const channel = {readyState: "open"};
const ctx: Record<string, any> = {
  sessionActive: true, mediaActive: true, adaptiveMediaReportInFlight: false,
  adaptiveMediaGeneration: 0, receiveRosterSources: [],
  applyReceiveSubscriptions: async () => {},
  e2eeAdapterReady: true, e2eeChannel: channel, appliedAdaptiveQuality: null,
  claims: sessionClaims, e2eeAdapter: () => adapter,
  validAdaptiveMediaTelemetry: (value: unknown) => value,
  api: async () => ({ok: true, json: async () => qualityTarget}),
  body: () => ({}), ui: {status: {textContent: ""}},
  scheduleWebRtcRetry: () => { retryAttempted++; },
};
runInNewContext(qualityCode + "\nthis.report = reportAdaptiveMedia; this.validate = validAdaptiveQualityTarget;", ctx);
assert.equal(typeof ctx.report, "function");
assert.equal(ctx.validate(qualityTarget)?.video.width, 1920);
await ctx.report();
await ctx.report();
assert.equal(appliedReceive.length, 1, "repeated decision must not reconfigure active receiver");
assert.equal(retryAttempted, 0, "quality adjustment must never restart WebRTC");
let unsupportedReports = 0;
ctx.e2eeAdapter = () => ({getReceiveMediaTelemetry: adapter.getReceiveMediaTelemetry});
ctx.api = async () => { unsupportedReports++; return {ok: true, json: async () => qualityTarget}; };
await ctx.report();
assert.equal(unsupportedReports, 0, "must not ask server to degrade video when codec cannot apply it");
ctx.e2eeAdapter = () => adapter;
const beforeInvalid = appliedReceive.length;
ctx.api = async () => ({ok: true, json: async () => ({
  ...qualityTarget, video: {...qualityTarget.video, width: -1},
})});
await ctx.report();
assert.equal(appliedReceive.length, beforeInvalid, "invalid profile may not reach E2EE endpoint");
assert.match(ctx.ui.status.textContent, /adjustment unavailable/);
ctx.api = async () => ({ok: true, json: async () => ({
  ...qualityTarget, stage: "video_720p",
  video: {...qualityTarget.video, width: 1280, height: 720, target_bitrate_bps: 2_000_000},
})});
ctx.e2eeAdapterReady = false;
await ctx.report();
assert.equal(appliedReceive.length, beforeInvalid, "uninitialized endpoint must not adapt");
ctx.e2eeAdapterReady = true;
let releaseServerResponse: (() => void) | undefined;
const serverGate = new Promise<void>((resolve) => { releaseServerResponse = resolve; });
ctx.api = async () => { await serverGate; return {
  ok: true, json: async () => ({
    ...qualityTarget, stage: "video_720p",
    video: {...qualityTarget.video, width: 1280, height: 720, target_bitrate_bps: 2_000_000},
  }),
}; };
const staleReport = ctx.report();
await Promise.resolve();
ctx.e2eeChannel = {readyState: "open"};
releaseServerResponse?.();
await staleReport;
assert.equal(appliedReceive.length, beforeInvalid, "stale encrypted channel must not adapt");
assert.equal(retryAttempted, 0);

// A stale measurement must NOT reach the server after a revoked/reconnected
// encrypted media generation. Old finally must not unlock a newer in-flight report.
let releaseTelemetry: (() => void) | undefined;
const telemetryGate = new Promise<void>((resolve) => {releaseTelemetry = resolve;});
let serverCallsAfterRevoke = 0;
ctx.e2eeAdapter = () => ({
  getReceiveMediaTelemetry: async () => {
    await telemetryGate;
    return adapter.getReceiveMediaTelemetry();
  },
  applyReceiveMediaDecision: adapter.applyReceiveMediaDecision,
});
ctx.api = async () => {
  serverCallsAfterRevoke++;
  return {ok: true, json: async () => qualityTarget};
};
const revokedDuringTelemetry = ctx.report();
await Promise.resolve();
ctx.adaptiveMediaGeneration++;
ctx.e2eeChannel = {readyState: "open"};
ctx.adaptiveMediaReportInFlight = false; // stopAdaptiveMediaMonitoring reset
releaseTelemetry?.();
await revokedDuringTelemetry;
assert.equal(serverCallsAfterRevoke, 0,
  "late telemetry from revoked E2EE channel must not be sent to server");
assert.equal(appliedReceive.length, beforeInvalid,
  "old telemetry must not change decoder after endpoint revocation");

// A previous generation's finally may not clear the busy flag belonging to
// a replacement generation's report (which would allow overlapping submissions).
let releaseOld: (() => void) | undefined;
const oldGate = new Promise<void>((resolve) => {releaseOld = resolve;});
ctx.e2eeAdapter = () => ({
  getReceiveMediaTelemetry: async () => {
    await oldGate;
    return adapter.getReceiveMediaTelemetry();
  },
  applyReceiveMediaDecision: adapter.applyReceiveMediaDecision,
});
const oldInFlight = ctx.report();
await Promise.resolve();
ctx.adaptiveMediaGeneration++;
ctx.adaptiveMediaReportInFlight = false;
ctx.e2eeAdapter = () => adapter;
let releaseNew: (() => void) | undefined;
const newGate = new Promise<void>((resolve) => {releaseNew = resolve;});
ctx.api = async () => {
  await newGate;
  return {ok: true, json: async () => qualityTarget};
};
const nextInFlight = ctx.report();
await Promise.resolve();
assert.equal(ctx.adaptiveMediaReportInFlight, true);
releaseOld?.();
await oldInFlight;
assert.equal(ctx.adaptiveMediaReportInFlight, true,
  "stale request completion cannot clear new request's in-flight lock");
releaseNew?.();
await nextInFlight;
assert.equal(ctx.adaptiveMediaReportInFlight, false);

// Execute the real reference-browser screen permission and publication
// lifecycle. Authorization can disappear inside a native window picker or
// while the asynchronous E2EE encoder source update is still pending.
const screenCode = browser.slice(
  browser.indexOf("function policyAllows(kind){"),
  browser.indexOf("async function activateE2eeAdapter(){"),
);
assert.ok(screenCode.startsWith("function policyAllows(kind){"));
let resolveScreenPicker: ((stream: any) => void) | undefined;
const chosenScreen = new Promise<any>(resolve => {resolveScreenPicker = resolve;});
const stoppedScreenTracks: string[] = [];
const screenTrack = {readyState: "live", stop() {stoppedScreenTracks.push("stop");},
  addEventListener() {}};
const screenCapture = {
  getVideoTracks: () => [screenTrack],
  getTracks: () => [screenTrack],
};
const allowedScreenPolicy = {
  publish_audio_allowed: false, publish_camera_allowed: false,
  screen_share_allowed: true,
};
const screenCtx: Record<string, any> = {
  sessionActive: true, mediaActive: true, localStream: null,
  screenStream: null, screenShareBusy: false,
  e2eeChannel: {readyState: "open"}, mediaPolicy: allowedScreenPolicy,
  navigator: {mediaDevices: {getDisplayMedia: async () => chosenScreen}},
  ui: {
    // The VM evaluates the actual browser control refresh code, including
    // microphone/camera selectors and toggle labels, during policy changes.
    mic: {disabled: false}, camera: {disabled: false},
    micToggle: {disabled: false, textContent: ""},
    cameraToggle: {disabled: false, textContent: ""},
    screenToggle: {disabled: false, textContent: ""},
    screenCard: {classList: {toggle() {}}},
    screenVideo: {srcObject: null}, status: {textContent: ""},
  },
  tr: (key: string) => key,
  e2eeAdapter: () => ({updateSources: async () => {}}),
  endpointMediaSources: () => ({screenStream: screenCtx.screenStream}),
  // This slice deliberately excludes the unrelated microphone/camera label
  // function; execute the real policy controls with a harmless text stub.
  applyToggleLabels() {},
};
runInNewContext(screenCode +
  "\nthis.startScreen = startScreenShare; this.applyPolicy = applyMediaPolicy;",
  screenCtx);
const revokedInPicker = screenCtx.startScreen();
await screenCtx.applyPolicy({...allowedScreenPolicy, screen_share_allowed: false});
resolveScreenPicker?.(screenCapture);
await assert.rejects(revokedInPicker, /authorization changed/);
assert.equal(screenCtx.screenStream, null);
assert.equal(stoppedScreenTracks.length, 1, "revoked native picker must close its late screen track");

// A later revocation must stop capture even when startScreenShare holds
// screenShareBusy=true awaiting a slow WebCodecs updateSources().
screenCtx.mediaPolicy = allowedScreenPolicy;
screenCtx.navigator.mediaDevices.getDisplayMedia = async () => screenCapture;
let firstScreenSourceUpdate: () => void = () => {};
const firstScreenUpdateEntered = new Promise<void>(resolve => {
  firstScreenSourceUpdate = resolve;
});
let releaseScreenUpdate: () => void = () => {};
const delayedScreenUpdate = new Promise<void>(resolve => {
  releaseScreenUpdate = resolve;
});
let screenUpdates = 0;
screenCtx.e2eeAdapter = () => ({updateSources: async () => {
  if(++screenUpdates === 1){
    firstScreenSourceUpdate();
    await delayedScreenUpdate;
  }
}});
const publishingScreen = screenCtx.startScreen();
await firstScreenUpdateEntered;
await screenCtx.applyPolicy({...allowedScreenPolicy, screen_share_allowed: false});
assert.equal(screenCtx.screenStream, null, "policy must stop pending screen capture immediately");
assert.ok(stoppedScreenTracks.length >= 2,
  "revocation must stop a screen track even while publication update is pending");
releaseScreenUpdate();
await assert.rejects(publishingScreen, /authorization changed/);
assert.equal(screenCtx.screenStream, null, "stale screen source cannot be restored");
assert.ok(screenUpdates >= 2, "revocation must signal empty E2EE source list");

// Real RT0 portable pipeline integration: an authenticated, active adapter receives
// per-subscriber quality commands, leaves the sender alone, and stops after revocation.
assert.deepEqual(ucrVideoEncodingTarget(1920, 1080), {frameRate: 30, bitrate: 2_488_000});
assert.deepEqual(ucrVideoEncodingTarget(1280, 720), {frameRate: 30, bitrate: 2_488_000});
assert.deepEqual(ucrVideoEncodingTarget(640, 480), {frameRate: 30, bitrate: 829_000});
assert.deepEqual(ucrVideoEncodingTarget(640, 360), {frameRate: 30, bitrate: 622_000});
assert.deepEqual(ucrVideoEncodeSize(1920, 1080, 1), {width: 1280, height: 720});
assert.deepEqual(ucrVideoEncodeSize(1080, 1920, 1), {width: 720, height: 1280});
assert.deepEqual(ucrVideoEncodeSize(1280, 720, 0.5), {width: 640, height: 360});
assert.deepEqual(ucrVideoEncodeSize(640, 480, 1), {width: 640, height: 480});
assert.equal(ucrVideoStageProfile(2).frameRate, 24);
assert.equal(ucrDetectVideoCodec(new Uint8Array([0, 0, 0, 1, 0x65, 0x88])), "avc1.42002a");
assert.equal(ucrDetectVideoCodec(new Uint8Array([0, 0, 1, 0x65, 0x88])), "avc1.42002a");
assert.equal(ucrDetectVideoCodec(new Uint8Array([0x10, 0x00, 0x00, 0x9d, 0x01])), "vp8");
assert.throws(() => ucrVideoEncodingTarget(0, 1080), /invalid measured source video dimensions/);
assert.deepEqual(ucrAdaptiveVideoStep(0, 1_500_000, 0, 0), {stage:1, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(1, 1_500_000, 0, 0), {stage:2, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(2, 1_500_000, 0, 0), {stage:2, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(2, 0, 0, 4), {stage:1, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(1, 0, 0, 4), {stage:0, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(1, 300_000, 0, 4), {stage:1, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(0, 0, 2, 0), {stage:1, healthySamples:0});
assert.deepEqual(ucrAdaptiveVideoStep(0, 0, 0, 0, true), {stage:1, healthySamples:0},
  "local encode pressure must reduce quality without transport congestion");
assert.deepEqual(ucrAdaptiveVideoStep(1, 0, 0, 4, false), {stage:0, healthySamples:0},
  "quality must recover after five healthy device and transport samples");
assert.throws(() => ucrAdaptiveVideoStep(0, -1, 0, 0), /invalid video congestion sample/);

const endpointQualityCalls: string[] = [];
const crypto = {
  seal_wire() { return new Uint8Array([1, 2]); },
  open_wire() { return new Uint8Array([1, 2]); },
  revoke() { endpointQualityCalls.push("revoke"); },
};
const receive = {
  play() {},
  setReceiveQuality(target: {stage: string}) { endpointQualityCalls.push("recv:" + target.stage); },
  stop() { endpointQualityCalls.push("recv:stop"); },
};
const publish = {
  start() { endpointQualityCalls.push("sender:start"); },
  stop() { endpointQualityCalls.push("sender:stop"); },
};
const endpoint = new UcrPortableEndpointMediaAdapter({
  bridge: crypto,
  consumer: receive,
  producer: publish,
  trustedKeys: {resolve() { return new Uint8Array(32).fill(7); }},
  binding: {tenantId: "tenant", namespaceId: null, callId: "call",
    groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
    negotiationGeneration: 1n},
  authorizeFrame: () => true,
  authorizePublish: () => true,
  measureReceiveTelemetry: () => adapter.getReceiveMediaTelemetry(),
});
const src = {stream: {}, cameraStream: {}, screenStream: null};
assert.equal(await endpoint.getReceiveMediaTelemetry(), null);
await endpoint.start({...src, sendEnvelope() {}});
assert.equal((await endpoint.getReceiveMediaTelemetry() as any).estimated_bandwidth_bps, 8_000_000);
await endpoint.applyReceiveMediaDecision({
  stage: "video_720p",
  video: {codec_capability_id: "ucr.video.h264",
    width: 1280, height: 720, frame_rate: 30, target_bitrate_bps: 2_000_000},
  opus_target_bitrate_bps: null,
});
assert.deepEqual(endpointQualityCalls, ["sender:start", "recv:video_720p"]);
await endpoint.stop();
assert.deepEqual(endpointQualityCalls, [
  "sender:start", "recv:video_720p", "revoke", "sender:stop", "recv:stop",
]);
assert.equal(await endpoint.getReceiveMediaTelemetry(), null);
await assert.rejects(endpoint.applyReceiveMediaDecision({
  stage: "audio", video: null, opus_target_bitrate_bps: 48_000,
}), /not active/);
// A failed capture replacement must atomically retire encryption and stop
// BOTH platform endpoints: a media-less UI must never keep a live MLS signer.
const failedSourceEvents: string[] = [];
const failedSourceEndpoint = new UcrPortableEndpointMediaAdapter({
  bridge: {
    seal_wire() { return new Uint8Array(); },
    open_wire() { return new Uint8Array(); },
    revoke() { failedSourceEvents.push("revoke"); },
  },
  consumer: {
    play() {},
    stop() { failedSourceEvents.push("consumer:stop"); },
  },
  producer: {
    start() { failedSourceEvents.push("producer:start"); },
    updateSources() { throw new Error("capture replacement failed"); },
    stop() { failedSourceEvents.push("producer:stop"); },
  },
  trustedKeys: {resolve() { return new Uint8Array(32); }},
  binding: {tenantId: "tenant", namespaceId: null, callId: "call",
    groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
    negotiationGeneration: 1n},
  authorizeFrame: () => true,
  authorizePublish: () => true,
});
await failedSourceEndpoint.start({...src, sendEnvelope() {}});
await assert.rejects(failedSourceEndpoint.updateSources(src), /capture replacement failed/);
assert.deepEqual(failedSourceEvents, [
  "producer:start", "revoke", "producer:stop", "consumer:stop",
]);
await assert.rejects(failedSourceEndpoint.start({...src, sendEnvelope() {}}),
  /retired/);
const decoder = new UcrBrowserWebCodecsConsumer();
decoder.setReceiveQuality({stage: "audio", video: null, opus_target_bitrate_bps: 48_000});
// Video is ignored before needing WebCodecs APIs: no forbidden plaintext fallbacks.
decoder.play({mediaKind: "video", streamId: "source", timestamp: 1n,
  keyframe: true, bytes: new Uint8Array([1])});
decoder.stop();

// Actual WebCodecs consumer rendering contract: a 1080p decrypted frame must
// resize the visible canvas rather than clipping it into the old 640x360 bitmap.
const visualCalls: string[] = [];
const canvas = {
  width: 640, height: 360,
  getContext() {
    return {
      drawImage(_frame: unknown, x: number, y: number, w: number, h: number) {
        visualCalls.push([x, y, w, h].join(":"));
      },
    };
  },
};
const globals = ["MediaStreamTrackProcessor", "AudioEncoder", "VideoEncoder",
  "AudioDecoder", "VideoDecoder", "EncodedAudioChunk", "EncodedVideoChunk"] as const;
const savedGlobals = globals.map((key) => ({
  key, original: Object.getOwnPropertyDescriptor(globalThis, key),
}));
let savedVideoOutput: ((frame: any) => void) | null = null;
let decoderCreations = 0;
let decoderCloses = 0;
let rejectNextVideoDecode = false;
let deferNextVideoOutput = false;
let releaseDeferredVideoOutput: (() => void) | null = null;
for (const key of globals) {
  Object.defineProperty(globalThis, key, {configurable: true, writable: true, value: class {}});
}
Object.defineProperty(globalThis, "VideoDecoder", {
  configurable: true, writable: true,
  value: class {
    readonly #output: (frame: any) => void;
    constructor(options: {output: (frame: any) => void}) {
      this.#output = options.output;
      savedVideoOutput = options.output;
      decoderCreations++;
    }
    configure() {}
    decode() {
      if (rejectNextVideoDecode) {
        rejectNextVideoDecode = false;
        throw new Error("simulated corrupt candidate video keyframe");
      }
      const render = () => this.#output({
        displayWidth: 1920, displayHeight: 1080, close() {},
      });
      if (deferNextVideoOutput) {
        deferNextVideoOutput = false;
        releaseDeferredVideoOutput = render;
      } else {
        render();
      }
    }
    close() {decoderCloses++;}
  },
});
Object.defineProperty(globalThis, "EncodedVideoChunk", {
  configurable: true, writable: true, value: class { constructor(_input: unknown) {} },
});
try {
  const rendering = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  rendering.play({mediaKind: "video", videoSourceKind: "camera",
    streamId: "camera-hd", timestamp: 12n, keyframe: true,
    bytes: new Uint8Array([1, 2])});
  assert.equal(canvas.width, 1920);
  assert.equal(canvas.height, 1080);
  assert.deepEqual(visualCalls, ["0:0:1920:1080"]);
  const oldOutput = savedVideoOutput;
  rendering.setReceiveQuality({stage: "audio", video: null,
    opus_target_bitrate_bps: 48_000});
  oldOutput?.({displayWidth: 1920, displayHeight: 1080, close() {}});
  assert.equal(visualCalls.length, 1, "late callback after downgrade must not render");
  rendering.stop();

  // A decoder that keeps producing frames while canvas drawing fails must
  // report time since the FIRST unrendered decode, not the latest frame.
  // This exercises the real WebCodecs consumer callback and its counters.
  const videoCounters = (globalThis as unknown as {__ucrVideoCounters: {
    firstVisibleUnrenderedDecodeAt: number; lastDecodedAt: number;
  }}).__ucrVideoCounters;
  const actualNow = Date.now;
  let simulatedNow = actualNow() + 1000;
  try {
    Date.now = () => simulatedNow;
    const failingCanvas = {width: 0, height: 0, getContext() {return null;}};
    const failingRender = new UcrBrowserWebCodecsConsumer({
      videoCanvas: failingCanvas as unknown as HTMLCanvasElement,
    });
    const failedFrame = {mediaKind: "video" as const,
      videoSourceKind: "camera" as const, streamId: "failure-canvas",
      timestamp: 100n, keyframe: true, bytes: new Uint8Array([1, 2])};
    assert.throws(() => failingRender.play(failedFrame), /video canvas 2D context unavailable/);
    assert.equal(videoCounters.firstVisibleUnrenderedDecodeAt, simulatedNow);
    simulatedNow += 800;
    assert.throws(() => failingRender.play({...failedFrame, timestamp: 101n}),
      /video canvas 2D context unavailable/);
    assert.equal(videoCounters.lastDecodedAt, simulatedNow);
    assert.equal(videoCounters.firstVisibleUnrenderedDecodeAt, simulatedNow - 800,
      "later failed decodes must not erase accumulated render stall duration");
    failingRender.stop();
    assert.equal(videoCounters.firstVisibleUnrenderedDecodeAt, 0,
      "stopping playback must clear stale render failures");
    // Keep this recovery draw independent of the dual-layer test's shared
    // visualCalls array, whose expected counts start before this regression.
    let recoveredDraws = 0;
    const recoveredCanvas = {
      width: 0, height: 0,
      getContext() {return {drawImage() {recoveredDraws++;}};},
    };
    const recoveredRender = new UcrBrowserWebCodecsConsumer({
      videoCanvas: recoveredCanvas as unknown as HTMLCanvasElement,
    });
    recoveredRender.play({...failedFrame, streamId: "recovered-canvas"});
    assert.equal(recoveredDraws, 1, "recovery must draw one decoded frame");
    assert.equal(videoCounters.firstVisibleUnrenderedDecodeAt, 0,
      "successful canvas draw clears the unrendered-decode latch");
    recoveredRender.stop();
  } finally {
    Date.now = actualNow;
  }

  // Actual dual-layer receive journey: the wrong encrypted camera layer may
  // arrive first or arrive late, but it must not flicker into the visible canvas.
  const switching = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  const videoFrame = (streamId: string, keyframe: boolean) => ({
    mediaKind: "video" as const, videoSourceKind: "camera" as const,
    streamId, timestamp: 24n, keyframe, bytes: new Uint8Array([1, 2]),
  });
  switching.play(videoFrame("camera123", true));
  assert.equal(visualCalls.length, 2, "HD initial keyframe should be visible");
  switching.play(videoFrame("camera123-low", true));
  assert.equal(visualCalls.length, 2, "unselected low layer cannot replace HD");
  const lowTarget = {
    stage: "video_720p" as const,
    video: {codec_capability_id: "ucr.video.h264",
      width: 1280, height: 720, frame_rate: 30, target_bitrate_bps: 2_000_000},
    opus_target_bitrate_bps: null,
  };
  switching.setReceiveQuality(lowTarget);
  switching.play(videoFrame("camera123-low", false));
  assert.equal(visualCalls.length, 2, "delta frame cannot start low-layer switch");
  switching.play(videoFrame("camera123", false));
  assert.equal(visualCalls.length, 3, "HD must stay visible until low keyframe");
  const previousHdOutput = savedVideoOutput;
  switching.play(videoFrame("camera123-low", true));
  assert.equal(visualCalls.length, 4, "low keyframe commits local decoder switch");
  previousHdOutput?.({displayWidth: 1920, displayHeight: 1080, close() {}});
  assert.equal(visualCalls.length, 4, "late HD output after handover must be discarded");
  switching.play(videoFrame("camera123", true));
  assert.equal(visualCalls.length, 4, "HD is not selected during low target");
  switching.setReceiveQuality({
    stage: "video_1080p", video: {...lowTarget.video,
      width: 1920, height: 1080, target_bitrate_bps: 4_000_000},
    opus_target_bitrate_bps: null,
  });
  switching.play(videoFrame("camera123", true));
  assert.equal(visualCalls.length, 5, "HD resumes only after authenticated keyframe");
  switching.stop();

  // Old HD remains visible if the replacement decoder rejects its first keyframe.
  const brokenSwitch = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  brokenSwitch.play(videoFrame("failure-camera", true));
  brokenSwitch.setReceiveQuality(lowTarget);
  rejectNextVideoDecode = true;
  assert.throws(() => brokenSwitch.play(videoFrame("failure-camera-low", true)),
    /corrupt candidate video keyframe/);
  const afterFailedSwitch = visualCalls.length;
  brokenSwitch.play(videoFrame("failure-camera", false));
  assert.equal(visualCalls.length, afterFailedSwitch + 1,
    "HD frames must continue after failed replacement keyframe decode");
  brokenSwitch.play(videoFrame("failure-camera-low", true));
  assert.equal(visualCalls.length, afterFailedSwitch + 2,
    "subsequent valid keyframe should complete protected layer handover");
  brokenSwitch.stop();

  // Decoder output is asynchronous in real WebCodecs: receiving an encoded
  // keyframe alone must NOT retire old video before the new output is ready.
  const deferredSwitch = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  deferredSwitch.play(videoFrame("async-camera", true));
  deferredSwitch.setReceiveQuality(lowTarget);
  deferNextVideoOutput = true;
  const beforeDeferred = visualCalls.length;
  deferredSwitch.play(videoFrame("async-camera-low", true));
  assert.equal(visualCalls.length, beforeDeferred,
    "new encoded keyframe alone must not replace visible HD");
  deferredSwitch.play(videoFrame("async-camera", false));
  assert.equal(visualCalls.length, beforeDeferred + 1,
    "old HD continues while the replacement decoder is still preparing");
  const activatePreparedLayer = releaseDeferredVideoOutput;
  assert.ok(activatePreparedLayer);
  activatePreparedLayer();
  assert.equal(visualCalls.length, beforeDeferred + 2,
    "new layer activates only on successfully decoded frame output");
  deferredSwitch.stop();

  // Two authorized publishers can supply identical track IDs. They still need
  // independent decoder state and replay/keyframe pipelines.
  const collisionReceiver = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  const createdBefore = decoderCreations;
  const sourceHeader = (principalId: string) => ({
    source: {principalId, kind: "person"}, sourceDeviceId: "device-1",
  } as any);
  collisionReceiver.play(videoFrame("shared-camera", true), sourceHeader("alice"));
  collisionReceiver.play(videoFrame("shared-camera", true), sourceHeader("bob"));
  assert.equal(decoderCreations - createdBefore, 2,
    "same stream ID from distinct verified participants must use two decoders");
  collisionReceiver.stop();

  // Camera and screen-share frames from one authenticated participant arrive
  // simultaneously under wildcard SFU subscription. Only the selected video
  // source may draw on the single canvas, never alternating by decode timing.
  const sharedCanvas = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  const countBeforeScreens = visualCalls.length;
  sharedCanvas.play(videoFrame("camera-main", true), sourceHeader("alice"));
  sharedCanvas.play({...videoFrame("screen-1", true),
    videoSourceKind: "screen_share"}, sourceHeader("alice"));
  assert.equal(visualCalls.length, countBeforeScreens + 2,
    "screen share must take the canvas on its first decoded keyframe");
  sharedCanvas.play(videoFrame("camera-main", true), sourceHeader("alice"));
  assert.equal(visualCalls.length, countBeforeScreens + 2,
    "camera must not flicker over a still-active screen-share");
  sharedCanvas.play({...videoFrame("screen-1", false),
    videoSourceKind: "screen_share"}, sourceHeader("alice"));
  assert.equal(visualCalls.length, countBeforeScreens + 3,
    "screen-share frames must remain visible while source is active");
  sharedCanvas.stop();

  // Each new speaker must retire the previous decoder, not accumulate
  // one VideoDecoder per roster change until browser hardware exhaustion.
  const rotating = new UcrBrowserWebCodecsConsumer({
    videoCanvas: canvas as unknown as HTMLCanvasElement,
  });
  const createdBeforeRotation = decoderCreations;
  const closedBeforeRotation = decoderCloses;
  for (let i = 0; i < 30; i++) {
    rotating.play(videoFrame("shared-camera", true), sourceHeader("speaker-" + i));
  }
  assert.equal(decoderCreations - createdBeforeRotation, 30);
  assert.ok(decoderCloses - closedBeforeRotation >= 29,
    "all replaced authenticated speaker video decoders must be retired");
  rotating.stop();

  // Two speakers' audio is mixed in parallel on WebAudio. A shared playback
  // watermark must not serialize independent speaker buffers back-to-back.
  const audioStartTimes: number[] = [];
  let audioStops = 0;
  let audioDisconnects = 0;
  const audioSink = {
    currentTime: 100,
    destination: {},
    createBuffer(_channels: number, _frames: number, _rate: number) {
      return {duration: 0.01, copyToChannel() {}};
    },
    createBufferSource() {
      return {buffer: null as unknown, connect() {},
        stop() {audioStops++;}, disconnect() {audioDisconnects++;},
        start(time: number) {audioStartTimes.push(time);}};
    },
  };
  Object.defineProperty(globalThis, "AudioDecoder", {
    configurable: true, writable: true, value: class {
      readonly output: (data: unknown) => void;
      constructor({output}: {output: (data: unknown) => void}) {this.output = output;}
      configure() {}
      decode() {
        this.output({numberOfChannels: 1, numberOfFrames: 480, sampleRate: 48000,
          copyTo() {}, close() {}});
      }
      close() {}
    },
  });
  const mixing = new UcrBrowserWebCodecsConsumer({
    audioContext: audioSink as unknown as AudioContext,
  });
  const audioFrame = (id: string) => ({
    mediaKind: "audio" as const, streamId: id, timestamp: 1n,
    keyframe: false, bytes: Uint8Array.of(1, 2),
  });
  mixing.play(audioFrame("mic-a"), sourceHeader("alice"));
  mixing.play(audioFrame("mic-a"), sourceHeader("alice"));
  mixing.play(audioFrame("mic-b"), sourceHeader("bob"));
  assert.equal(audioStartTimes.length, 3);
  assert.ok(Math.abs(audioStartTimes[0] - 100.06) < 0.000001);
  assert.ok(Math.abs(audioStartTimes[1] - 100.07) < 0.000001);
  assert.ok(Math.abs(audioStartTimes[2] - audioStartTimes[0]) < 0.000001,
    "independent authenticated speakers must overlap while own frames stay ordered");
  // Drive a stalled sender queue past the bounded playout horizon.
  // Old WebAudio nodes must be stopped and disconnected before rebasing.
  for (let i = 0; i < 30; i++) mixing.play(audioFrame("mic-a"), sourceHeader("alice"));
  assert.ok(audioStops > 0, "congested audio must cancel old scheduled PCM");
  const disconnectedBeforeStop = audioDisconnects;
  assert.ok(disconnectedBeforeStop > 0, "congested audio must release old audio nodes");
  mixing.stop();
  assert.ok(audioDisconnects >= disconnectedBeforeStop,
    "consumer teardown must not leak its remaining scheduled audio nodes");

  // A burst of jitter must not poison a fresh audio session or cause the
  // sender's queue to grow unbounded when wall-clock arrival catches up.
  const adaptive = new UcrBrowserWebCodecsConsumer({
    audioContext: audioSink as unknown as AudioContext,
  });
  const startsBefore = audioStartTimes.length;
  audioSink.currentTime = 200;
  adaptive.play(audioFrame("jitter-test"), sourceHeader("alice"));
  audioSink.currentTime = 200.03;
  adaptive.play(audioFrame("jitter-test"), sourceHeader("alice"));
  audioSink.currentTime = 200.12;
  adaptive.play(audioFrame("jitter-test"), sourceHeader("alice"));
  assert.equal(audioStartTimes.length, startsBefore + 3);
  assert.ok(audioStartTimes[startsBefore + 2] >= 200.12,
    "playout must recover after input starvation instead of scheduling in the past");
  adaptive.stop();
} finally {
  for (const item of savedGlobals) {
    if (item.original) Object.defineProperty(globalThis, item.key, item.original);
    else Reflect.deleteProperty(globalThis, item.key);
  }
}

// Execute the real WebCodecs producer with bounded injected host APIs. One camera
// reader feeds exactly two independent encrypted stream IDs, never per-viewer encoders.
assert.equal(ucrCameraLayerStreamId("track123", "full"), "track123");
assert.equal(ucrCameraLayerStreamId("track123", "low"), "track123-low");
assert.throws(() => ucrCameraLayerStreamId("track-low", "full"), /invalid authenticated/);
assert.throws(() => ucrCameraLayerStreamId("x".repeat(113), "low"), /invalid authenticated/);
const originalGlobals = [
  "MediaStreamTrackProcessor", "AudioEncoder", "VideoEncoder", "AudioDecoder",
  "VideoDecoder", "EncodedAudioChunk", "EncodedVideoChunk", "OffscreenCanvas",
  "VideoFrame",
].map((key) => ({key, descriptor: Object.getOwnPropertyDescriptor(globalThis, key)}));
const producerConfigured: object[] = [];
let lowDraws = 0;
const outputFrames: {streamId: string; timestamp: bigint; keyframe: boolean}[] = [];
let captureCount = 0;
const fakeReader = {
  async read() {
    if (captureCount >= 12) return {done: true};
    const timestamp = captureCount++ * 33_333;
    return {done: false, value: {timestamp, close() {}}};
  },
  async cancel() {},
};
for (const {key} of originalGlobals) {
  Object.defineProperty(globalThis, key, {configurable: true, writable: true, value: class {}});
}
Object.defineProperty(globalThis, "MediaStreamTrackProcessor", {
  configurable: true, value: class {
    readonly readable = {getReader() {return fakeReader;}};
  },
});
Object.defineProperty(globalThis, "OffscreenCanvas", {
  configurable: true, value: class {
    readonly width: number;
    readonly height: number;
    constructor(width: number, height: number) { this.width = width; this.height = height; }
    getContext() {return {drawImage() {lowDraws++;}};}
  },
});
Object.defineProperty(globalThis, "VideoFrame", {
  configurable: true, value: class {
    readonly timestamp: number;
    constructor(_canvas: unknown, opts: {timestamp: number}) {this.timestamp = opts.timestamp;}
    close() {}
  },
});
Object.defineProperty(globalThis, "VideoEncoder", {
  configurable: true, value: class {
    readonly encodeQueueSize = 0;
    readonly #output: (chunk: unknown) => void;
    constructor({output}: {output: (chunk: unknown) => void}) {this.#output = output;}
    configure(config: object) {producerConfigured.push(config);}
    encode(frame: {timestamp: number}, opts: {keyFrame: boolean}) {
      this.#output({
        timestamp: frame.timestamp, byteLength: 2,
        type: opts.keyFrame ? "key" : "delta",
        copyTo(out: Uint8Array) {out.set([1, 2]);},
      });
    }
    async flush() {}
    close() {}
  },
});
try {
  const layerProducer = new UcrBrowserWebCodecsProducer(() => {}, true);
  const videoTrack = {
    id: "camera123",
    getSettings: () => ({width: 1920, height: 1080, frameRate: 30}),
  };
  await layerProducer.start({
    stream: {getAudioTracks: () => []},
    cameraStream: {getVideoTracks: () => [videoTrack]},
    screenStream: null,
  } as unknown as any, (frame) => {
    outputFrames.push({streamId: frame.streamId,
      timestamp: frame.timestamp, keyframe: frame.keyframe});
  });
  for (let spin = 0; spin < 24; spin++) await Promise.resolve();
  await layerProducer.stop();
  assert.equal(producerConfigured.length, 2, "one camera creates at most two encoders");
  assert.deepEqual(producerConfigured.map((c: any) => [c.width, c.height]),
    [[1280, 720], [640, 360]]);
  assert.equal(outputFrames.filter(f => f.streamId === "camera123").length, 12);
  assert.ok(outputFrames.filter(f => f.streamId === "camera123-low").length >= 3);
  assert.ok(outputFrames.filter(f => f.streamId === "camera123-low").length <= 6);
  assert.equal(lowDraws, outputFrames.filter(f => f.streamId === "camera123-low").length);

  // A revoked screen source must never re-attach after an earlier async reader
  // cancellation finishes. This exercises the real producer's updateSources.
  captureCount = 12;
  let sourceResetEntered: () => void = () => {};
  const sourceResetStarted = new Promise<void>(resolve => {
    sourceResetEntered = resolve;
  });
  let releaseSourceReset: () => void = () => {};
  const sourceResetGate = new Promise<void>(resolve => {
    releaseSourceReset = resolve;
  });
  fakeReader.cancel = async () => {
    sourceResetEntered();
    await sourceResetGate;
  };
  const serialized = new UcrBrowserWebCodecsProducer();
  const bareSources = {
    stream: {getAudioTracks: () => []},
    cameraStream: {getVideoTracks: () => []},
    screenStream: null,
  };
  await serialized.start({
    ...bareSources, cameraStream: {getVideoTracks: () => [videoTrack]},
  } as any, () => {});
  const encodersBeforeRace = producerConfigured.length;
  const staleAttach = serialized.updateSources({
    ...bareSources, screenStream: {getVideoTracks: () => [
      {id: "screen-1", getSettings: () => ({width: 1280, height: 720})},
    ]},
  } as any);
  await sourceResetStarted;
  const revokeSource = serialized.updateSources(bareSources as any);
  releaseSourceReset();
  await Promise.all([staleAttach, revokeSource]);
  assert.equal(producerConfigured.length, encodersBeforeRace,
    "pending screen publication cannot reattach after source revocation");
  await serialized.stop();
} finally {
  for (const {key, descriptor} of originalGlobals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
}

// Audio always retains protected DataChannel headroom under heavy encrypted
// video. This tests the real browser transport function, not a mock priority
// implementation; permission/MLS checks stay in the portable adapter.
{
  const start = browser.indexOf("function ucrTransportError(code,message){");
  const end = browser.indexOf("function endpointMediaSources(){", start);
  assert.ok(start >= 0 && end > start, "encrypted sender must accept media class");
  const sentChunks: Uint8Array[] = [];
  const context: Record<string, any> = {
    e2eeChannel: {readyState: "open", bufferedAmount: 300_000,
      send(chunk: Uint8Array) {sentChunks.push(chunk);}},
    e2eeMessageId: 1, E2EE_MAX_WIRE_BYTES: 2 * 1024 * 1024 + 8192,
    E2EE_MAX_BUFFERED_SEND_BYTES: 2 * 1024 * 1024,
    E2EE_CHUNK_HEADER_BYTES: 24, E2EE_CHUNK_PAYLOAD_BYTES: 16000 - 24,
    E2EE_CHUNK_MAGIC: "UCRCHK01", window: {__ucrAudioCounters: {transportQueued: 0}},
    BigInt, Uint8Array, TextEncoder, DataView, Math, Error,
  };
  runInNewContext(browser.slice(start,end) +
    "\nthis.publish = sendE2eeEnvelope;",context);
  assert.throws(()=>context.publish(Uint8Array.of(7,8), "video"),/congested/);
  assert.equal(sentChunks.length,0,"congested camera must not starve protected audio");
  context.publish(Uint8Array.of(1,2), "audio");
  assert.equal(sentChunks.length,1,"encrypted Opus must use reserved channel capacity");
  assert.equal(context.window.__ucrAudioCounters.transportQueued,1);
  // Bounded latency is more important than accepting ever-growing Opus
  // backlog: above the audio limit even voice frames must be refused.
  context.e2eeChannel.bufferedAmount = 400_000;
  assert.throws(()=>context.publish(Uint8Array.of(3,4), "audio"),/congested/);
  assert.equal(sentChunks.length,1,"overloaded transport must not accumulate stale voice");
}

// The same canonical MLS transport must preserve the authenticated media class
// on the outbound path. Audio metadata is necessary for protecting Opus queue
// space; it must never select a different key or skip the secure bridge.
{
  const sent: Array<{kind: string | undefined; sealed: number}> = [];
  const outbound = new UcrPortableEndpointMediaAdapter({
    bridge: {
      seal_wire(_streamId, mediaKind) { return Uint8Array.of(mediaKind); },
      open_wire() { return Uint8Array.of(1); },
      revoke() {},
    },
    producer: {
      async start(_sources, emit) {
        await emit({mediaKind: "audio", streamId: "microphone", timestamp: 1n,
          keyframe: false, bytes: Uint8Array.of(9)});
        await emit({mediaKind: "video", videoSourceKind: "camera", streamId: "camera",
          timestamp: 2n, keyframe: true, bytes: Uint8Array.of(8)});
      },
      stop() {},
    },
    consumer: {play() {}, stop() {}},
    trustedKeys: {resolve() { return new Uint8Array(32); }},
    binding: {tenantId: "tenant", namespaceId: null, callId: "call",
      groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
      negotiationGeneration: 1n},
    authorizeFrame: () => true, authorizePublish: () => true,
  });
  await outbound.start({
    stream: {} as MediaStream, cameraStream: {} as MediaStream,
    sendEnvelope(wire, kind) {sent.push({kind, sealed: wire[0]});},
  });
  assert.deepEqual(sent, [
    {kind: "audio", sealed: 1}, {kind: "video", sealed: 2},
  ], "sealing and transport must both preserve real audio/video kind");
  await outbound.stop();
}

// Authorization can be temporarily slow on a real Windows machine. Frames
// must not be encrypted/sent after they become obsolete while awaiting it.
{
  let sealed = 0, delivered = 0;
  const delayed = new UcrPortableEndpointMediaAdapter({
    bridge: {
      seal_wire() { sealed++; return Uint8Array.of(1); },
      open_wire() { return Uint8Array.of(1); }, revoke() {},
    },
    producer: {
      async start(_sources, emit) {
        await emit({mediaKind: "audio", streamId: "mic", timestamp: 1n,
          keyframe: false, bytes: Uint8Array.of(9)});
      },
      stop() {},
    },
    consumer: {play() {}, stop() {}},
    trustedKeys: {resolve() { return new Uint8Array(32); }},
    binding: {tenantId: "tenant", namespaceId: null, callId: "call",
      groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
      negotiationGeneration: 1n},
    authorizeFrame: () => true,
    authorizePublish: async () => {
      await new Promise(resolve => setTimeout(resolve, 180));
      return true;
    },
  });
  await delayed.start({stream: {} as MediaStream, cameraStream: {} as MediaStream,
    sendEnvelope() {delivered++;}});
  assert.equal(sealed, 0, "stale authorized speech must not be encrypted");
  assert.equal(delivered, 0, "stale authorized speech must not reach DataChannel");
  await delayed.stop();
}

// Exercise fail-closed stage attribution for the real portable sender. The
// failure must remain observable without leaking transport payloads or keys.
for (const [name, publish, seal, transport] of [
  ["PUBLISH_AUTHORIZATION", false, false, false],
  ["SEAL_WIRE", true, true, false],
  ["DATACHANNEL_SEND", true, false, true],
] as const) {
  const errors: string[] = [];
  const stageAdapter = new UcrPortableEndpointMediaAdapter({
    bridge: {
      seal_wire() { if (seal) throw Error("sensitive crypto detail"); return Uint8Array.of(3); },
      open_wire() { return Uint8Array.of(2); },
      revoke() {},
    },
    producer: {
      async start(_sources, emit) {
        await emit({mediaKind: "audio", streamId: "mic", timestamp: 1n,
          keyframe: true, bytes: Uint8Array.of(4)});
      },
      stop() {},
    },
    consumer: {play() {}, stop() {}},
    trustedKeys: {resolve() { return new Uint8Array(32); }},
    binding: {tenantId: "tenant", namespaceId: null, callId: "call",
      groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
      negotiationGeneration: 1n},
    authorizeFrame: () => true,
    authorizePublish: () => publish,
    onError(error) { errors.push((error as Error).message); },
  });
  await stageAdapter.start({...src, sendEnvelope() {
    if (transport) throw Error("sensitive websocket detail");
  }});
  assert.deepEqual(errors, ["UCR_MEDIA_OUTBOUND_" + name],
    "outbound failure must identify the exact failing stage without leaking details");
  await stageAdapter.stop();
}

// Different frames on one DataChannel may finish async trust lookups out of
// order. The E2EE receiver must commit them in arrival order PER source/stream,
// without stalling another participant and without weakening replay rejection.
let releaseFirstKey: (() => void) | undefined;
const firstKeyGate = new Promise<void>(resolve => {releaseFirstKey = resolve;});
const receivedSequences: string[] = [];
const inbound = new UcrPortableEndpointMediaAdapter({
  bridge: {seal_wire() {return Uint8Array.of(1);},
    open_wire() {return Uint8Array.of(9);}, revoke() {}},
  producer: {start() {}, stop() {}},
  consumer: {play(_frame, header) {
    receivedSequences.push(header.source.principalId + ":" + header.sequence);
  }, stop() {}},
  trustedKeys: {async resolve(header) {
    if(header.source.principalId === "alice" && header.sequence === 1n)
      await firstKeyGate;
    return new Uint8Array(32).fill(3);
  }},
  binding: {tenantId: "tenant", namespaceId: null, callId: "call",
    groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
    negotiationGeneration: 1n},
  authorizeFrame: () => true, authorizePublish: () => true,
});
const inboundWire = (sequence: bigint, principalId: string,
  mediaKind: "audio" | "video" = "video") =>
  encodeSfuForwardEnvelopeWire({frame: {
    header: {
      tenantId: "tenant", namespaceId: null, callId: "call", groupId: "group",
      source: {principalId, kind: "person"}, sourceDeviceId: principalId + "-dev",
      streamId: "camera", negotiationRef: "current", negotiationGeneration: 1n,
      cryptoEpoch: 3n, cryptoStateRef: "state", cryptoSuite: "ucr.v1",
      headerVersion: 2, mediaKind, videoSourceKind: mediaKind === "video" ? "camera" : null,
      sequence, mediaTimestamp: sequence, keyframe: mediaKind === "video",
    },
    nonce: new Uint8Array(24), ciphertext: Uint8Array.of(1),
    sourceSignature: {keyId: "trusted", algorithmId: "ed25519",
      algorithmVersion: 1, signature: new Uint8Array(64)},
  }});
await inbound.start({...src, sendEnvelope() {}});
const firstEncrypted = inbound.onEnvelope(inboundWire(1n, "alice"));
const secondEncrypted = inbound.onEnvelope(inboundWire(2n, "alice"));
await inbound.onEnvelope(inboundWire(1n, "bob"));
assert.deepEqual(receivedSequences, ["bob:1"],
  "a slow first key lookup must not reorder later frames or block other speakers");
releaseFirstKey?.();
await Promise.all([firstEncrypted, secondEncrypted]);
assert.deepEqual(receivedSequences, ["bob:1", "alice:1", "alice:2"],
  "protected inbound frames of each stream must render in signed sequence order");
await assert.rejects(inbound.onEnvelope(inboundWire(1n, "alice")),
  /replayed endpoint media frame/);
// The same signed stream identifier is legal in different media namespaces;
// replay tracking must never discard audio simply because video seq=1 arrived.
await inbound.onEnvelope(inboundWire(1n, "alice", "audio"));
assert.deepEqual(receivedSequences, ["bob:1", "alice:1", "alice:2", "alice:1"],
  "same source/stream/sequence in audio and video must not collide");
await assert.rejects(inbound.onEnvelope(inboundWire(1n, "alice", "audio")),
  /replayed endpoint media frame/);
await inbound.stop();

// Verify the inbound pipeline identifies authorization, key resolution, authenticated
// decryption and decoder/playout failures without exposing private exception strings.
for (const stage of ["RECEIVE_AUTHORIZATION", "SIGNING_KEY_RESOLUTION",
  "VERIFY_AND_DECRYPT", "DECODE_AND_PLAY"] as const) {
  const errors: string[] = [];
  const receiver = new UcrPortableEndpointMediaAdapter({
    bridge: {seal_wire() {return Uint8Array.of(1);},
      open_wire() {
        if (stage === "VERIFY_AND_DECRYPT") throw Error("private key material");
        return Uint8Array.of(8);
      }, revoke() {}},
    producer: {start() {}, stop() {}},
    consumer: {play() {
      if (stage === "DECODE_AND_PLAY") throw Error("private decoder detail");
    }, stop() {}},
    trustedKeys: {resolve() {
      if (stage === "SIGNING_KEY_RESOLUTION") throw Error("private trust detail");
      return new Uint8Array(32).fill(3);
    }},
    binding: {tenantId: "tenant", namespaceId: null, callId: "call",
      groupId: "group", cryptoEpoch: 3n, negotiationRef: "current",
      negotiationGeneration: 1n},
    authorizeFrame: () => stage !== "RECEIVE_AUTHORIZATION",
    authorizePublish: () => true,
    onError(error) {errors.push((error as Error).message);},
  });
  await receiver.start({...src, sendEnvelope() {}});
  await assert.rejects(receiver.onEnvelope(inboundWire(1n, "alice", "audio")));
  assert.deepEqual(errors, ["UCR_MEDIA_INBOUND_" + stage]);
  await receiver.stop();
}

// The only permitted default browser factory needs active canonical identity,
// locally held device signing seed, exact epoch and matching published signer.
// This is actual WASM media_bridge composition, not a second crypto function.
const canonicalBootstrap = {
  state: {
    crypto_epoch() { return 12n; },
    media_bridge(...args: unknown[]) {
      observedMediaBridgeArguments = args;
      return {
        revoke() { revokedMediaBridges++; },
        local_verifying_key: () => new Uint8Array(32).fill(7),
        seal_wire: () => new Uint8Array(1),
        open_wire: () => new Uint8Array(1),
      };
    },
  },
  claims: {tenantId: "tenant", namespaceId: null, callId: "call",
    participantId: "alice", participantKind: "person", deviceId: "device-a",
    sessionId: "session-a"},
  groupId: "group",
  loadWasm: async () => ({}),
} as const;
let observedMediaBridgeArguments: unknown[] = [];
let revokedMediaBridges = 0;
let canonicalMediaCurrent = true;
const canonicalAdmission = {
  sessionId: "session-a", deviceId: "device-a", participantId: "alice",
  principalKindCode: 1,
  binding: {tenantId: "tenant", namespaceId: null, callId: "call", groupId: "group",
    cryptoEpoch: 12n, negotiationRef: "live-negotiation",
    negotiationGeneration: 1n},
  signingKeyId: "canonical-signer", signingSeed: new Uint8Array(32).fill(9),
  trustedLocalVerifyingKey: new Uint8Array(32).fill(7),
  trustedKeys: {resolve: () => new Uint8Array(32).fill(7)},
  audioContext: {} as AudioContext,
  isCurrent() { return canonicalMediaCurrent; },
  authorizeFrame: () => true,
  authorizePublish: () => true,
};
const canonicalFactory = createUcrCanonicalBrowserMediaFactory(
  async () => canonicalAdmission,
);
const canonicalOptions = await canonicalFactory(canonicalBootstrap);
assert.equal(canonicalOptions.binding.cryptoEpoch, 12n);
assert.equal(observedMediaBridgeArguments[0], "call");
assert.equal(observedMediaBridgeArguments[1], "live-negotiation");
assert.equal(observedMediaBridgeArguments[2], 1n);
assert.equal(observedMediaBridgeArguments[3], "alice");
assert.equal(observedMediaBridgeArguments[4], 1);
assert.equal(observedMediaBridgeArguments[5], "canonical-signer");
assert.deepEqual(Array.from(observedMediaBridgeArguments[6] as Uint8Array),
  Array.from(new Uint8Array(32)), "only temporary signing seed is erased");
assert.ok(canonicalAdmission.signingSeed.every(b => b === 9),
  "canonical device key store remains unmodified");
assert.equal(await canonicalOptions.authorizePublish({} as any), true);
canonicalMediaCurrent = false;
assert.equal(await canonicalOptions.authorizePublish({} as any), false);
assert.equal(await canonicalOptions.authorizeFrame({} as any), false);
await assert.rejects(canonicalOptions.trustedKeys.resolve({} as any, "signer"),
  /authorization revoked/);
canonicalMediaCurrent = true;
// Revocation DURING an asynchronous trusted descriptor lookup must also abort
// decryption, not just revoke admission at the start of the lookup.
let finishKeyLookup: ((key: Uint8Array) => void) | undefined;
const delayedKey = new Promise<Uint8Array>(resolve => {finishKeyLookup = resolve;});
const midflightFactory = createUcrCanonicalBrowserMediaFactory(async () => ({
  ...canonicalAdmission,
  trustedKeys: {resolve: async () => delayedKey},
}));
const midflightOptions = await midflightFactory(canonicalBootstrap);
const lateKey = midflightOptions.trustedKeys.resolve({} as any, "source");
canonicalMediaCurrent = false;
finishKeyLookup?.(new Uint8Array(32).fill(7));
await assert.rejects(lateKey, /authorization revoked/,
  "revocation after trusted-key await must prevent crypto/decode");
canonicalMediaCurrent = true;
await assert.rejects(
  createUcrCanonicalBrowserMediaFactory(async () => ({
    ...canonicalAdmission, binding: {...canonicalAdmission.binding, cryptoEpoch: 13n},
  }))(canonicalBootstrap),
  /MLS epoch differs/,
);
const revokedBeforeMismatchedSigner = revokedMediaBridges;
await assert.rejects(
  createUcrCanonicalBrowserMediaFactory(async () => ({
    ...canonicalAdmission, trustedLocalVerifyingKey: new Uint8Array(32).fill(3),
  }))(canonicalBootstrap),
  /endpoint signer differs/,
);
assert.equal(revokedMediaBridges, revokedBeforeMismatchedSigner + 1,
  "misbound signer must retire the Rust bridge");
await assert.rejects(
  createUcrCanonicalBrowserMediaFactory(async () => ({
    ...canonicalAdmission, sessionId: "different-session",
  }))(canonicalBootstrap),
  /canonical device signing, media binding or authorization incomplete/,
);

// Cancelling an installed but unstarted adapter must irreversibly retire the
// signer. A cancelled installer must never leave a usable MLS media epoch.
let prestartRevoked = 0;
const unstarted = new UcrPortableEndpointMediaAdapter({
  bridge: {...crypto, revoke() {prestartRevoked++;}},
  producer: {start() {}, stop() {}},
  consumer: {play() {}, stop() {}},
  trustedKeys: {resolve() {return new Uint8Array(32).fill(7);}},
  binding: {tenantId: "tenant", namespaceId: null, callId: "call",
    groupId: "group", cryptoEpoch: 12n, negotiationRef: "n",
    negotiationGeneration: 1n},
  authorizeFrame: () => true, authorizePublish: () => true,
});
await unstarted.stop();
assert.equal(prestartRevoked, 1, "unstarted adapter signer must be revoked");
await assert.rejects(unstarted.start({...src, sendEnvelope() {}}),
  /endpoint media bridge retired/);

console.log("UCR_ENDPOINT_E2EE_TYPESCRIPT_OK");
