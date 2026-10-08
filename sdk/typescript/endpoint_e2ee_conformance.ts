import {planUcrPrivacyNetwork, assertUcrPrivacyNetworkReady} from "./src/privacy_network.ts";
import { createUcrPortableEndpointMediaAdapter } from "./src/portable_endpoint_media.ts";
import { encodeSfuForwardEnvelopeWire } from "./src/sfu_forward_wire.ts";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  installUcrEndpointE2eeAdapter,
  resolveUcrEndpointE2eeAdapter,
  UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  type UcrEndpointE2eeAdapterV1,
} from "./src/endpoint_e2ee.ts";
import { createUcrEndpointWasmPersistence } from "./src/endpoint_wasm_persistence.ts";

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

const browser = readFileSync("crates/ucr-realtime-web/static/client.html", "utf8");
assert.match(browser, /ucr\.endpoint-e2ee\.v1/);
assert.match(browser, /Unsupported endpoint E2EE adapter contract version/);
assert.match(browser, /restoreSealedState/);
assert.match(browser, /sealState/);


{
  const outbound: Uint8Array[] = [];
  const played: Uint8Array[] = [];
  const failures: unknown[] = [];
  let emit: ((frame: {mediaKind: "audio"; streamId: string; timestamp: bigint; keyframe: boolean; bytes: Uint8Array}) => void | Promise<void>) | null = null;
  let stopped = 0;
  let seq = 0n;
  const canonical = {
    frame: {
      header: {
        tenantId: "tenant-1", namespaceId: null, callId: "call-1", groupId: "group-1",
        streamId: "audio-1", source: {principalId: "alice", kind: "person" as const},
        sourceDeviceId: "alice-device", negotiationRef: "neg-1",
        negotiationGeneration: 1n, cryptoEpoch: 2n, cryptoStateRef: "state-2",
        cryptoSuite: "ucr.v1" as const, headerVersion: 2 as const,
        mediaKind: "audio" as const, videoSourceKind: null,
        sequence: 1n, mediaTimestamp: 48000n, keyframe: false,
      },
      nonce: new Uint8Array(24), ciphertext: new Uint8Array([7, 8, 9]),
      sourceSignature: {
        keyId: "alice-key", algorithmId: "ed25519" as const,
        algorithmVersion: 1 as const, signature: new Uint8Array(64),
      },
    },
  };
  const wire = encodeSfuForwardEnvelopeWire(canonical);
  const adapter = createUcrPortableEndpointMediaAdapter({
    bridge: {
      seal_wire(_stream, mediaKind, videoKind, sequence, _timestamp, _keyframe, plaintext) {
        assert.equal(mediaKind, 1);
        assert.equal(videoKind, 0);
        assert.equal(sequence, ++seq);
        assert.deepEqual([...plaintext], [1, 2, 3]);
        return wire;
      },
      open_wire(inbound, key) {
        assert.deepEqual(inbound, wire);
        assert.equal(key.length, 32);
        return new Uint8Array([1, 2, 3]);
      },
    },
    producer: {
      start(_sources, send) { emit = send; },
      stop() { stopped++; },
    },
    consumer: {
      play(frame) { played.push(frame.bytes); },
      stop() { stopped++; },
    },
    trustedKeys: {
      resolve(_header, keyId) {
        assert.equal(keyId, "alice-key");
        return new Uint8Array(32).fill(1);
      },
    },
    onError(error) { failures.push(error); },
  });
  assert.equal(adapter.contractVersion, UCR_ENDPOINT_E2EE_CONTRACT_VERSION);
  const stream = {getTracks: () => []} as unknown as MediaStream;
  await adapter.start({stream, cameraStream: stream, sendEnvelope: (payload) => outbound.push(payload)});
  assert.ok(emit);
  await emit!({mediaKind: "audio", streamId: "audio-1", timestamp: 48000n,
    keyframe: false, bytes: new Uint8Array([1, 2, 3])});
  assert.deepEqual(outbound, [wire]);
  await adapter.onEnvelope(wire);
  assert.deepEqual([...played[0]], [1, 2, 3]);
  await assert.rejects(adapter.onEnvelope(wire), /replayed endpoint media frame/);
  await assert.rejects(adapter.start({stream, cameraStream: stream, sendEnvelope() {}}), /already started/);
  assert.equal(failures.length, 0);
  await adapter.stop();
  assert.equal(stopped, 2);
  await adapter.onEnvelope(wire);
  assert.equal(played.length, 1);
}


{
  const turn = [{urls: "turns:relay.example.invalid:5349", username: "ephemeral", credential: "secret"}];
  const privatePlan = planUcrPrivacyNetwork({
    mode: "private", iceServers: turn, trustedRelayAvailable: true,
  });
  assert.equal(privatePlan.rtcConfiguration.iceTransportPolicy, "relay");
  assert.equal(privatePlan.dataMinimization, "strict");
  assert.deepEqual(privatePlan.rtcConfiguration.iceServers, turn);
  assert.throws(() => planUcrPrivacyNetwork({
    mode: "private", iceServers: [{urls: "stun:stun.example.invalid"}],
    trustedRelayAvailable: true,
  }), /needs TURN/);
  assert.throws(() => planUcrPrivacyNetwork({
    mode: "private", iceServers: turn, trustedRelayAvailable: false,
  }), /requires a trusted TURN/);
  const max = planUcrPrivacyNetwork({
    mode: "maximum", iceServers: turn, trustedRelayAvailable: true,
  });
  assert.throws(() => assertUcrPrivacyNetworkReady(max, false), /independently deployed relay/);
  assertUcrPrivacyNetworkReady(max, true);
  assert.equal(planUcrPrivacyNetwork({
    mode: "secure", iceServers: [], trustedRelayAvailable: false,
  }).rtcConfiguration.iceTransportPolicy, "all");
}

console.log("UCR_ENDPOINT_E2EE_TYPESCRIPT_OK");
