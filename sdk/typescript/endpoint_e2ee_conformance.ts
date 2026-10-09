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
    browser.indexOf("async function start", browser.indexOf("async function activateAdmittedMedia(){") + 1)),
  /startAdaptiveMediaMonitoring\\(\\)/,
  "admission must not begin sampling before the channel and endpoint are active",
);

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
for (const key of globals) {
  Object.defineProperty(globalThis, key, {configurable: true, writable: true, value: class {}});
}
Object.defineProperty(globalThis, "VideoDecoder", {
  configurable: true, writable: true,
  value: class {
    constructor(options: {output: (frame: any) => void}) {
      savedVideoOutput = options.output;
    }
    configure() {}
    decode() {
      savedVideoOutput?.({displayWidth: 1920, displayHeight: 1080, close() {}});
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
