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
  UcrPortableEndpointMediaAdapter,
} from "./src/portable_endpoint_media.ts";
import {
  UcrBrowserWebCodecsConsumer,
  UcrBrowserWebCodecsProducer,
  ucrCameraLayerStreamId,
  ucrVideoEncodingTarget,
} from "./src/browser_webcodecs_media.ts";
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
  window: {},
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
};
runInNewContext(
  closeSnippet + "\n" + activateSnippet +
  "\nthis.activate = activateE2eeAdapter; this.close = closeE2eeTransport;",
  lifecycleCtx,
);
const activating = lifecycleCtx.activate();
await Promise.resolve();
assert.equal(lifecycleCtx.e2eeAdapterReady, false);
assert.ok(!protectedLifecycleEvents.includes("monitor-starts"),
  "a missing or unfinished E2EE endpoint must never produce adaptive telemetry");
releaseProtectedStartup?.();
await activating;
assert.equal(lifecycleCtx.e2eeAdapterReady, true);
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
  receiveSubscriptionFingerprint: null, receiveSubscriptionInFlight: false,
  receiveSubscriptionDirty: false, receiveRosterSources: [],
  receiveSpeakerId: null, receiveSpeakerCandidate: null, receiveSpeakerSamples: 0,
  ui: {status: {textContent: ""}},
  TextEncoder, body: () => ({}),
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
  rosterRequests[1].subscriptions.map((s: any) => [s.source_id, s.media_kind]),
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
  adaptiveMediaGeneration: 0,
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

// Real RT0 portable pipeline integration: an authenticated, active adapter receives
// per-subscriber quality commands, leaves the sender alone, and stops after revocation.
assert.deepEqual(ucrVideoEncodingTarget(1920, 1080), {frameRate: 30, bitrate: 4_000_000});
assert.deepEqual(ucrVideoEncodingTarget(1280, 720), {frameRate: 30, bitrate: 2_000_000});
assert.deepEqual(ucrVideoEncodingTarget(640, 360), {frameRate: 12, bitrate: 384_000});
assert.throws(() => ucrVideoEncodingTarget(0, 1080), /invalid measured source video dimensions/);
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
    close() {}
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
    [[1920, 1080], [640, 360]]);
  assert.equal(outputFrames.filter(f => f.streamId === "camera123").length, 12);
  assert.ok(outputFrames.filter(f => f.streamId === "camera123-low").length >= 3);
  assert.ok(outputFrames.filter(f => f.streamId === "camera123-low").length <= 6);
  assert.equal(lowDraws, outputFrames.filter(f => f.streamId === "camera123-low").length);
} finally {
  for (const {key, descriptor} of originalGlobals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
}

console.log("UCR_ENDPOINT_E2EE_TYPESCRIPT_OK");
