// Items C3/C4: pure feature-detection helpers for browser media paths.
import assert from "node:assert/strict";
import {
  ucrBrowserMediaPath,
  ucrSelectTemporalScalableConfig,
} from "./src/browser_webcodecs_media.ts";

const fn = function () {};
const codecs = {AudioEncoder: fn, VideoEncoder: fn, AudioDecoder: fn, VideoDecoder: fn,
  EncodedAudioChunk: fn, EncodedVideoChunk: fn};

// Chromium (incl. Win10 1607 Chrome/Edge): unchanged WebCodecs path.
assert.deepEqual(ucrBrowserMediaPath({...codecs, MediaStreamTrackProcessor: fn}), {path: "webcodecs"});
// Firefox / Safari window: no MSTP, but RTCRtpScriptTransform -> native RTP path.
const firefox = ucrBrowserMediaPath({...codecs, RTCPeerConnection: fn, RTCRtpScriptTransform: fn});
assert.equal(firefox.path, "native-rtp");
assert.match((firefox as {reason: string}).reason, /MediaStreamTrackProcessor/);
// Neither: explicit, actionable error text.
const old = ucrBrowserMediaPath({RTCPeerConnection: fn});
assert.equal(old.path, "unsupported");
assert.match((old as {reason: string}).reason, /RTCRtpScriptTransform/);

// C3: L1T3 hardware first, then fallbacks, null when unsupported.
const seen: string[] = [];
const enc = (ok: (c: Record<string, unknown>) => boolean) => ({
  async isConfigSupported(c: unknown) {
    const cfg = c as Record<string, unknown>;
    seen.push(`${cfg.scalabilityMode}/${cfg.hardwareAcceleration}`);
    if (cfg.scalabilityMode === "boom") throw new Error("x");
    return {supported: ok(cfg)};
  },
});
const base = {codec: "vp8", width: 1280, height: 720};
assert.deepEqual(await ucrSelectTemporalScalableConfig(enc(() => true), base),
  {...base, scalabilityMode: "L1T3", hardwareAcceleration: "prefer-hardware"});
seen.length = 0;
assert.deepEqual(await ucrSelectTemporalScalableConfig(enc((c) => c.scalabilityMode === "L1T2" && c.hardwareAcceleration === "no-preference"), base),
  {...base, scalabilityMode: "L1T2", hardwareAcceleration: "no-preference"});
assert.deepEqual(seen, ["L1T3/prefer-hardware", "L1T3/no-preference", "L1T2/prefer-hardware", "L1T2/no-preference"]);
assert.equal(await ucrSelectTemporalScalableConfig(enc(() => false), base), null);
assert.equal(await ucrSelectTemporalScalableConfig(undefined, base), null);
console.log("UCR_BROWSER_MEDIA_PATH_CONFORMANCE_OK");

// C5: loss/RTT signal.
import { ucrLossRttPressure } from "./src/browser_webcodecs_media.ts";
let st = {minRttMs: Number.POSITIVE_INFINITY, smoothedRttMs: 0};
let r = ucrLossRttPressure(st, null);
assert.deepEqual([r.pressure, r.hold], [false, false]);
r = ucrLossRttPressure(st, {lossFraction: Number.NaN, rttMs: 50});
assert.equal(r.state, st, "invalid sample changes nothing");
r = ucrLossRttPressure(st, {lossFraction: 0, rttMs: 50}); st = r.state;
assert.deepEqual([r.pressure, r.hold], [false, false]);
r = ucrLossRttPressure(st, {lossFraction: 0.05, rttMs: 50}); st = r.state;
assert.deepEqual([r.pressure, r.hold], [false, true], "moderate loss blocks recovery");
r = ucrLossRttPressure(st, {lossFraction: 0.2, rttMs: 50}); st = r.state;
assert.equal(r.pressure, true, "heavy loss steps down");
let rtt = ucrLossRttPressure({minRttMs: 40, smoothedRttMs: 40}, {lossFraction: 0, rttMs: 40});
for (let i = 0; i < 20 && !rtt.pressure; i++) rtt = ucrLossRttPressure(rtt.state, {lossFraction: 0, rttMs: 200});
assert.equal(rtt.pressure, true, "sustained RTT growth steps down");
console.log("UCR_BWE_LOSS_RTT_CONFORMANCE_OK");
