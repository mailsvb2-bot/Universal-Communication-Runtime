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
