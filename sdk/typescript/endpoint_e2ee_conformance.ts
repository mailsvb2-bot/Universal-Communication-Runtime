import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

import {
  installUcrEndpointE2eeAdapter,
  resolveUcrEndpointE2eeAdapter,
  UCR_ENDPOINT_E2EE_CONTRACT_VERSION,
  type UcrEndpointE2eeAdapterV1,
} from "./src/endpoint_e2ee.ts";
import { createUcrEndpointWasmPersistence } from "./src/endpoint_wasm_persistence.ts";
import {
  UcrChameleonReceiveHandover,
  type UcrEncryptedReceivePath,
} from "./src/chameleon_receive_handover.ts";

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

const browser = readFileSync("crates/ucr-realtime-web/static/client.html", "utf8");
assert.match(browser, /ucr\.endpoint-e2ee\.v1/);
assert.match(browser, /Unsupported endpoint E2EE adapter contract version/);
assert.match(browser, /restoreSealedState/);
assert.match(browser, /sealState/);
assert.match(browser, /validAdaptiveQualityTarget/);
assert.match(browser, /preferredCameraCapture\(ui\.camera\.value\)/);
assert.match(browser, /width:\{ideal:1920\},height:\{ideal:1080\}/);
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

console.log("UCR_ENDPOINT_E2EE_TYPESCRIPT_OK");
