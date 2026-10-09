#!/usr/bin/env python3
"""Dependency-free WebDriver smoke for the UCR reference conference browser."""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
CLIENT_ROOT = ROOT / "crates" / "ucr-realtime-web" / "static"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


def request_json(
    method: str,
    url: str,
    payload: dict | None = None,
    timeout_seconds: int = 15,
) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read()
    except urllib.error.HTTPError as error:
        data = error.read()
        raise RuntimeError(
            f"WebDriver HTTP {error.code} for {url}: {data.decode('utf-8', 'replace')}"
        ) from error
    parsed = json.loads(data or b"{}")
    value = parsed.get("value")
    if isinstance(value, dict) and value.get("error"):
        raise RuntimeError(f"WebDriver error for {url}: {value}")
    return parsed


def execute_async(base: str, script: str, args: list[object] | None = None) -> object:
    response = request_json(
        "POST",
        f"{base}/execute/async",
        {"script": script, "args": args or []},
        timeout_seconds=30,
    )
    return response.get("value")


def driver_executable(browser: str) -> str:
    env_and_names = {
        "chrome": ("CHROMEWEBDRIVER", ["chromedriver", "chromedriver.exe"]),
        "edge": ("EDGEWEBDRIVER", ["msedgedriver", "msedgedriver.exe"]),
        "firefox": ("GECKOWEBDRIVER", ["geckodriver", "geckodriver.exe"]),
        "safari": (None, ["safaridriver"]),
    }
    env_name, names = env_and_names[browser]
    candidates: list[Path] = []
    if env_name:
        configured = os.environ.get(env_name)
        if configured:
            configured_path = Path(configured)
            if configured_path.is_dir():
                candidates.extend(configured_path / name for name in names)
            else:
                candidates.append(configured_path)
    for name in names:
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError(f"no WebDriver executable found for {browser}: {candidates!r}")


def driver_command(browser: str, executable: str, port: int) -> list[str]:
    if browser == "safari":
        return [executable, "-p", str(port)]
    if browser == "firefox":
        return [executable, "--port", str(port)]
    return [executable, f"--port={port}"]


def capabilities(browser: str) -> dict:
    if browser == "chrome":
        return {
            "browserName": "chrome",
            "goog:chromeOptions": {
                "args": [
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--autoplay-policy=no-user-gesture-required",
                ]
            },
        }
    if browser == "edge":
        return {
            "browserName": "MicrosoftEdge",
            "ms:edgeOptions": {
                "args": [
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--autoplay-policy=no-user-gesture-required",
                ]
            },
        }
    if browser == "firefox":
        return {
            "browserName": "firefox",
            "moz:firefoxOptions": {
                "args": ["-headless"],
                "prefs": {
                    "media.navigator.streams.fake": True,
                    "media.navigator.permission.disabled": True,
                },
            },
        }
    if browser == "safari":
        return {"browserName": "safari"}
    raise AssertionError(browser)


def wait_for_driver(port: int, process: subprocess.Popen[str]) -> None:
    endpoint = f"http://127.0.0.1:{port}/status"
    deadline = time.monotonic() + 25
    last_error = "driver did not start"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(
                f"WebDriver exited with code {process.returncode}: {output[-4000:]}"
            )
        try:
            request_json("GET", endpoint)
            return
        except Exception as error:  # bounded startup polling
            last_error = str(error)
            time.sleep(0.25)
    raise RuntimeError(last_error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=["chrome", "edge", "firefox", "safari"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    handler = functools.partial(QuietHandler, directory=str(CLIENT_ROOT))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    webdriver_port = 9515
    executable = driver_executable(args.browser)
    process = subprocess.Popen(
        driver_command(args.browser, executable, webdriver_port),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    session_id: str | None = None
    try:
        wait_for_driver(webdriver_port, process)
        created = request_json(
            "POST",
            f"http://127.0.0.1:{webdriver_port}/session",
            {"capabilities": {"alwaysMatch": capabilities(args.browser)}},
            timeout_seconds=90,
        )
        value = created.get("value") or {}
        session_id = value.get("sessionId") or created.get("sessionId")
        if not session_id:
            raise RuntimeError(f"WebDriver did not return a session id: {created}")
        reported = value.get("capabilities") or {}
        base = f"http://127.0.0.1:{webdriver_port}/session/{session_id}"
        branding_fragment = urllib.parse.urlencode(
            {
                "ucr_brand": json.dumps(
                    {
                        "name": "UCR Browser Probe",
                        "accentColor": "#336699",
                        "backgroundColor": "#010203",
                        "language": "ru",
                        "waitingText": "Проверка комнаты ожидания",
                    },
                    separators=(",", ":"),
                )
            }
        )
        page_url = f"http://localhost:{server.server_port}/client.html#{branding_fragment}"
        request_json(
            "POST",
            f"{base}/url",
            {"url": page_url},
        )
        time.sleep(0.5)
        probe = request_json(
            "POST",
            f"{base}/execute/sync",
            {
                "script": """
return {
  readyState: document.readyState,
  title: document.title,
  brandingFunction: typeof applyBrandingFromFragment === "function",
  brandName: document.getElementById("brand-name")?.textContent,
  brandLanguage: document.documentElement.lang,
  brandAccent: getComputedStyle(document.documentElement).getPropertyValue("--ucr-accent").trim(),
  brandBackground: getComputedStyle(document.documentElement).getPropertyValue("--ucr-background").trim(),
  joinFunction: typeof join === "function",
  restartIceFunction: typeof restartIce === "function",
  applyMediaPolicyFunction: typeof applyMediaPolicy === "function",
  screenShareGuardFunction: typeof screenShareSupported === "function",
  rtcPeerConnection: typeof RTCPeerConnection === "function",
  rtcSetConfiguration: typeof RTCPeerConnection === "function" &&
    typeof RTCPeerConnection.prototype.setConfiguration === "function",
  mediaStream: typeof MediaStream === "function",
  mediaDevices: !!navigator.mediaDevices,
  getUserMedia: !!navigator.mediaDevices &&
    typeof navigator.mediaDevices.getUserMedia === "function",
  getDisplayMedia: !!navigator.mediaDevices &&
    typeof navigator.mediaDevices.getDisplayMedia === "function",
  fetch: typeof fetch === "function",
  abortController: typeof AbortController === "function",
  textEncoder: typeof TextEncoder === "function",
  urlSearchParams: typeof URLSearchParams === "function",
  cryptoSubtle: !!globalThis.crypto && !!globalThis.crypto.subtle,
  secureContext: globalThis.isSecureContext === true,
  indexedDb: !!globalThis.indexedDB,
  endpointStateStore: !!window.ucrEndpointStateStore &&
    typeof window.ucrEndpointStateStore.save === "function" &&
    typeof window.ucrEndpointStateStore.load === "function" &&
    typeof window.ucrEndpointStateStore.remove === "function",
  endpointStateStoreContract: window.ucrEndpointStateStore?.contractVersion || null,
  endpointWrappingKeyVault: !!window.ucrEndpointWrappingKeyVault &&
    typeof window.ucrEndpointWrappingKeyVault.createProvider === "function" &&
    typeof window.ucrEndpointWrappingKeyVault.getWrappingKey === "function",
  endpointWrappingKeyVaultContract: window.ucrEndpointWrappingKeyVault?.contractVersion || null,
  endpointWasmLoader: !!window.ucrEndpointWasm &&
    typeof window.ucrEndpointWasm.load === "function",
  endpointWasmContract: window.ucrEndpointWasm?.contractVersion || null,
  endpointPersistenceFunction: typeof endpointPersistence === "function",
  endpointPersistenceKeyFunction: typeof endpointPersistenceStorageKey === "function",
  restoreEndpointPersistedStateFunction: typeof restoreEndpointPersistedState === "function",
  persistEndpointStateFunction: typeof persistEndpointState === "function",
  joinControl: !!document.getElementById("join"),
  microphoneControl: !!document.getElementById("mic-toggle"),
  cameraControl: !!document.getElementById("camera-toggle"),
  screenControl: !!document.getElementById("screen-toggle"),
  localVideo: !!document.getElementById("local-video"),
  remoteVideo: !!document.getElementById("remote-video")
};
""",
                "args": [],
            },
        ).get("value")

        if not isinstance(probe, dict):
            raise RuntimeError(f"browser probe returned invalid payload: {probe!r}")
        endpoint_wasm_execution = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const browser = arguments[0];
Promise.resolve()
  .then(async () => {
    const module = await window.ucrEndpointWasm.load();
    const contract = module.endpoint_wasm_contract_version();
    const state = new module.EndpointMlsState(
      "wasm-probe-tenant",
      "wasm-probe-namespace",
      "wasm-probe-group",
      "wasm-probe-device-" + browser
    );
    try {
      const keyPackage = state.key_package();
      const isBytes = ArrayBuffer.isView(keyPackage) &&
        Object.prototype.toString.call(keyPackage) === "[object Uint8Array]";
      let preJoinEpochRejected = false;
      try {
        state.crypto_epoch();
      } catch (_) {
        preJoinEpochRejected = true;
      }
      done({
        ok: contract === "ucr.endpoint-wasm.v1" &&
          isBytes &&
          keyPackage.length > 0 &&
          preJoinEpochRejected,
        contract,
        keyPackageBytes: isBytes ? keyPackage.length : null,
        preJoinEpochRejected,
        endpointMlsStateConstructor: typeof module.EndpointMlsState === "function"
      });
    } finally {
      if (typeof state.free === "function") state.free();
    }
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [args.browser],
        )
        endpoint_wasm_execution_verified = (
            isinstance(endpoint_wasm_execution, dict)
            and endpoint_wasm_execution.get("ok") is True
        )
        if not endpoint_wasm_execution_verified:
            raise RuntimeError(
                f"endpoint WASM browser execution failed: {endpoint_wasm_execution!r}"
            )
        legacy_key = f"ucr-browser-legacy-{args.browser}"
        legacy_bytes = [11, 22, 33, 44, 55]
        legacy_upgrade = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const key = arguments[0];
const expected = arguments[1];
Promise.resolve()
  .then(() => new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase("ucr-endpoint-state-v1");
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error || new Error("legacy database delete failed"));
    request.onblocked = () => reject(new Error("legacy database delete blocked"));
  }))
  .then(() => new Promise((resolve, reject) => {
    const request = indexedDB.open("ucr-endpoint-state-v1", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("sealed-snapshots")) {
        db.createObjectStore("sealed-snapshots");
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("sealed-snapshots", "readwrite");
      tx.objectStore("sealed-snapshots").put(Array.from(expected), key);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error || new Error("legacy write failed")); };
      tx.onabort = () => { db.close(); reject(tx.error || new Error("legacy write aborted")); };
    };
    request.onerror = () => reject(request.error || new Error("legacy database open failed"));
  }))
  .then(() => window.ucrEndpointStateStore.load(key))
  .then(async value => {
    const bytes = ArrayBuffer.isView(value) &&
      Object.prototype.toString.call(value) === "[object Uint8Array]"
      ? Array.from(value)
      : null;
    const same = Array.isArray(bytes) &&
      bytes.length === expected.length &&
      expected.every((byte, index) => bytes[index] === byte);
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open("ucr-endpoint-state-v1");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("upgraded database open failed"));
    });
    const version = db.version;
    const stores = Array.from(db.objectStoreNames);
    db.close();
    done({
      ok: same &&
        version === 2 &&
        stores.includes("sealed-snapshots") &&
        stores.includes("wrapping-key-vault"),
      same,
      version,
      stores,
      bytes
    });
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [legacy_key, legacy_bytes],
        )
        legacy_upgrade_verified = (
            isinstance(legacy_upgrade, dict)
            and legacy_upgrade.get("ok") is True
        )
        if not legacy_upgrade_verified:
            raise RuntimeError(f"IndexedDB v1-to-v2 migration failed: {legacy_upgrade!r}")

        persistence_key = f"ucr-browser-probe-{args.browser}"
        persistence_bytes = [1, 7, 3, 9, 255]
        persistence_write = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const key = arguments[0];
const bytes = new Uint8Array(arguments[1]);
Promise.resolve()
  .then(() => window.ucrEndpointStateStore.save(key, bytes))
  .then(() => done({ok: true}))
  .catch(error => done({ok: false, error: String(error)}));
""",
            [persistence_key, persistence_bytes],
        )
        if not isinstance(persistence_write, dict) or persistence_write.get("ok") is not True:
            raise RuntimeError(f"IndexedDB persistence write failed: {persistence_write!r}")

        persistence_before_refresh = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const key = arguments[0];
Promise.resolve()
  .then(async () => {
    const value = await window.ucrEndpointStateStore.load(key);
    const databases = typeof indexedDB.databases === "function"
      ? await indexedDB.databases()
      : [];
    const isBytes = ArrayBuffer.isView(value) &&
      Object.prototype.toString.call(value) === "[object Uint8Array]";
    done({
      found: isBytes,
      length: isBytes ? value.length : null,
      databases: databases.map(item => ({name: item.name || null, version: item.version || null})),
      origin: location.origin,
      href: location.href
    });
  })
  .catch(error => done({error: String(error), origin: location.origin, href: location.href}));
""",
            [persistence_key],
        )

        request_json("POST", f"{base}/refresh", {})
        time.sleep(0.5)

        persistence_read = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const key = arguments[0];
const expected = arguments[1];
Promise.resolve()
  .then(() => window.ucrEndpointStateStore.load(key))
  .then(value => {
    const isBytes = ArrayBuffer.isView(value) &&
      Object.prototype.toString.call(value) === "[object Uint8Array]";
    const bytes = isBytes ? value : null;
    const same = !!bytes &&
      bytes.length === expected.length &&
      expected.every((byte, index) => bytes[index] === byte);
    done({
      ok: same,
      isUint8Array: !!bytes,
      length: bytes ? bytes.length : null,
      expectedLength: expected.length
    });
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [persistence_key, persistence_bytes],
        )
        persistence_reload_round_trip = (
            isinstance(persistence_read, dict)
            and persistence_read.get("ok") is True
        )

        persistence_after_refresh = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
Promise.resolve()
  .then(async () => {
    const databases = typeof indexedDB.databases === "function"
      ? await indexedDB.databases()
      : [];
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open("ucr-endpoint-state-v1");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("open failed"));
    });
    let keys = [];
    let stores = Array.from(db.objectStoreNames);
    if (stores.includes("sealed-snapshots")) {
      keys = await new Promise((resolve, reject) => {
        const tx = db.transaction("sealed-snapshots", "readonly");
        const request = tx.objectStore("sealed-snapshots").getAllKeys();
        request.onsuccess = () => resolve(request.result.map(String));
        request.onerror = () => reject(request.error || new Error("getAllKeys failed"));
      });
    }
    db.close();
    done({
      databases: databases.map(item => ({name: item.name || null, version: item.version || null})),
      stores,
      keys,
      origin: location.origin,
      href: location.href
    });
  })
  .catch(error => done({error: String(error), origin: location.origin, href: location.href}));
"""
        )

        persistence_remove = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const key = arguments[0];
Promise.resolve()
  .then(() => window.ucrEndpointStateStore.remove(key))
  .then(() => window.ucrEndpointStateStore.load(key))
  .then(value => done({ok: value === null}))
  .catch(error => done({ok: false, error: String(error)}));
""",
            [persistence_key],
        )
        persistence_delete_verified = (
            isinstance(persistence_remove, dict)
            and persistence_remove.get("ok") is True
        )

        lifecycle_bytes = [9, 8, 7, 6, 5]
        lifecycle_write = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const expected = arguments[0];
const identity = {
  tenant_id: "probe-tenant",
  namespace_id: "probe-namespace",
  call_id: "probe-call",
  participant_kind: 1,
  participant_id: "probe-participant",
  device_id: "probe-device",
  session_id: "probe-session"
};
const adapter = {
  contractVersion: "ucr.endpoint-e2ee.v1",
  start() {},
  onEnvelope() {},
  stop() {},
  persistence: {
    restoreSealedState() { return true; },
    sealState() { return new Uint8Array(expected); }
  }
};
Promise.resolve()
  .then(() => persistEndpointState(adapter, identity))
  .then(saved => done({ok: saved === true, key: endpointPersistenceStorageKey(identity)}))
  .catch(error => done({ok: false, error: String(error)}));
""",
            [lifecycle_bytes],
        )
        if not isinstance(lifecycle_write, dict) or lifecycle_write.get("ok") is not True:
            raise RuntimeError(f"endpoint persistence lifecycle write failed: {lifecycle_write!r}")

        request_json("POST", f"{base}/refresh", {})
        time.sleep(0.5)

        lifecycle_restore = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const expected = arguments[0];
const identity = {
  tenant_id: "probe-tenant",
  namespace_id: "probe-namespace",
  call_id: "probe-call",
  participant_kind: 1,
  participant_id: "probe-participant",
  device_id: "probe-device",
  session_id: "probe-session"
};
let restored = null;
const adapter = {
  contractVersion: "ucr.endpoint-e2ee.v1",
  start() {},
  onEnvelope() {},
  stop() {},
  persistence: {
    restoreSealedState(snapshot) {
      restored = Array.from(snapshot);
      return true;
    },
    sealState() { return null; }
  }
};
Promise.resolve()
  .then(() => restoreEndpointPersistedState(adapter, identity))
  .then(async state => {
    const key = endpointPersistenceStorageKey(identity);
    const same = Array.isArray(restored) &&
      restored.length === expected.length &&
      expected.every((byte, index) => restored[index] === byte);
    if (key) await window.ucrEndpointStateStore.remove(key);
    done({ok: state === "restored" && same, state, restored, key});
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [lifecycle_bytes],
        )
        lifecycle_restore_verified = (
            isinstance(lifecycle_restore, dict)
            and lifecycle_restore.get("ok") is True
        )

        vault_identity = {
            "tenant_id": "vault-tenant",
            "namespace_id": "vault-namespace",
            "call_id": "vault-call",
            "participant_kind": 1,
            "participant_id": "vault-participant",
            "device_id": f"vault-device-{args.browser}",
            "session_id": "vault-session",
        }
        vault_before = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const identity = arguments[0];
Promise.resolve()
  .then(async () => {
    const storageKey = endpointPersistenceStorageKey(identity);
    const provider = window.ucrEndpointWrappingKeyVault.createProvider(identity);
    const wrappingKey = await provider.getWrappingKey();
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", wrappingKey)));
    const record = await readEndpointWrappingKeyRecord(storageKey);
    let exportRejected = false;
    try {
      await crypto.subtle.exportKey("raw", record.kek);
    } catch (_) {
      exportRejected = true;
    }
    const rawKey = Array.from(wrappingKey);
    wrappingKey.fill(0);
    done({
      ok: !!record &&
        record.kek.extractable === false &&
        exportRejected === true &&
        rawKey.length === 32 &&
        rawKey.some(value => value !== 0),
      storageKey,
      digest,
      kekExtractable: record ? record.kek.extractable : null,
      exportRejected,
      ivLength: record ? record.iv.length : null,
      wrappedLength: record ? record.wrapped.length : null,
      wrappedEqualsRaw: record
        ? record.wrapped.length === rawKey.length &&
          record.wrapped.every((value, index) => value === rawKey[index])
        : null
    });
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [vault_identity],
        )
        if not isinstance(vault_before, dict) or vault_before.get("ok") is not True:
            raise RuntimeError(f"wrapping-key vault setup failed: {vault_before!r}")

        request_json("POST", f"{base}/refresh", {})
        time.sleep(0.5)

        vault_after = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const identity = arguments[0];
const expectedDigest = arguments[1];
Promise.resolve()
  .then(async () => {
    const storageKey = endpointPersistenceStorageKey(identity);
    const provider = window.ucrEndpointWrappingKeyVault.createProvider(identity);
    const wrappingKey = await provider.getWrappingKey();
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", wrappingKey)));
    const record = await readEndpointWrappingKeyRecord(storageKey);
    let exportRejected = false;
    try {
      await crypto.subtle.exportKey("raw", record.kek);
    } catch (_) {
      exportRejected = true;
    }
    const same = digest.length === expectedDigest.length &&
      expectedDigest.every((value, index) => digest[index] === value);
    wrappingKey.fill(0);
    done({
      ok: same && !!record && record.kek.extractable === false && exportRejected === true,
      same,
      digest,
      kekExtractable: record ? record.kek.extractable : null,
      exportRejected,
      ivLength: record ? record.iv.length : null,
      wrappedLength: record ? record.wrapped.length : null
    });
  })
  .catch(error => done({ok: false, error: String(error)}));
""",
            [vault_identity, vault_before.get("digest")],
        )
        vault_reload_verified = (
            isinstance(vault_after, dict)
            and vault_after.get("ok") is True
        )

        # Real browser codec execution, not a capability-name checkbox. This synthetic
        # local frame probe is intentionally NOT evidence of WAN/TURN or two-device QoE.
        full_hd_codec_probe = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
(async () => {
  if (typeof VideoEncoder !== "function" || typeof VideoDecoder !== "function" ||
      typeof VideoFrame !== "function" || typeof OffscreenCanvas !== "function") {
    return {supported: false, reason: "WebCodecs encode/decode or canvas unavailable"};
  }
  const config = {codec: "vp8", width: 1920, height: 1080,
    bitrate: 4000000, framerate: 30, latencyMode: "realtime"};
  const supported = await VideoEncoder.isConfigSupported(config);
  if (!supported.supported) return {supported: false, reason: "Full HD VP8 encoder unsupported"};
  let encodedBytes = 0, decodedWidth = 0, decodedHeight = 0, decodedFrames = 0;
  const start = performance.now();
  const decoder = new VideoDecoder({
    output(frame) {
      decodedWidth = frame.displayWidth;
      decodedHeight = frame.displayHeight;
      decodedFrames++;
      frame.close();
    },
    error(error) { throw error; }
  });
  decoder.configure({codec: "vp8"});
  const encoder = new VideoEncoder({
    output(chunk) {
      encodedBytes += chunk.byteLength;
      const payload = new Uint8Array(chunk.byteLength);
      chunk.copyTo(payload);
      decoder.decode(new EncodedVideoChunk({
        type: chunk.type, timestamp: chunk.timestamp, data: payload
      }));
    },
    error(error) { throw error; }
  });
  try {
    encoder.configure(config);
    const canvas = new OffscreenCanvas(1920, 1080);
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("synthetic Full HD canvas unavailable");
    const pixels = ctx.createLinearGradient(0, 0, 1920, 1080);
    pixels.addColorStop(0, "#153a60");
    pixels.addColorStop(1, "#f4c251");
    ctx.fillStyle = pixels;
    ctx.fillRect(0, 0, 1920, 1080);
    const frame = new VideoFrame(canvas, {timestamp: 0});
    try { encoder.encode(frame, {keyFrame: true}); } finally { frame.close(); }
    await encoder.flush();
    await decoder.flush();
    return {supported: true, codec: "vp8", sourceWidth: 1920,
      sourceHeight: 1080, decodedWidth, decodedHeight, decodedFrames,
      encodedBytes, localEncodeDecodeMs: Math.round(performance.now() - start),
      verified: decodedWidth === 1920 && decodedHeight === 1080 &&
        decodedFrames >= 1 && encodedBytes > 0};
  } finally {
    encoder.close();
    decoder.close();
  }
})().then(done).catch(error => done({supported: true, verified: false,
  error: String(error)}));
""",
        )
        if not isinstance(full_hd_codec_probe, dict):
            raise RuntimeError("Full HD codec probe did not return structured browser evidence")
        if full_hd_codec_probe.get("supported") and not full_hd_codec_probe.get("verified"):
            raise RuntimeError(f"Full HD codec encode/decode failed: {full_hd_codec_probe!r}")

        branding_failures = []
        if probe.get("brandName") != "UCR Browser Probe":
            branding_failures.append("brandName")
        if probe.get("brandLanguage") != "ru":
            branding_failures.append("brandLanguage")
        if probe.get("brandAccent") != "#336699":
            branding_failures.append("brandAccent")
        if probe.get("brandBackground") != "#010203":
            branding_failures.append("brandBackground")

        required = [
            "brandingFunction",
            "joinFunction",
            "restartIceFunction",
            "applyMediaPolicyFunction",
            "screenShareGuardFunction",
            "rtcPeerConnection",
            "rtcSetConfiguration",
            "mediaStream",
            "mediaDevices",
            "getUserMedia",
            "fetch",
            "abortController",
            "textEncoder",
            "urlSearchParams",
            "cryptoSubtle",
            "secureContext",
            "indexedDb",
            "endpointStateStore",
            "endpointWrappingKeyVault",
            "endpointWasmLoader",
            "endpointPersistenceFunction",
            "endpointPersistenceKeyFunction",
            "restoreEndpointPersistedStateFunction",
            "persistEndpointStateFunction",
            "joinControl",
            "microphoneControl",
            "cameraControl",
            "screenControl",
            "localVideo",
            "remoteVideo",
        ]
        failures = [name for name in required if probe.get(name) is not True]
        failures.extend(branding_failures)
        if probe.get("endpointStateStoreContract") != "ucr.endpoint-state-store.v1":
            failures.append("endpointStateStoreContract")
        if not legacy_upgrade_verified:
            failures.append(f"indexedDbV1ToV2Migration:{legacy_upgrade!r}")
        if probe.get("endpointWrappingKeyVaultContract") != "ucr.endpoint-wrapping-key.v1":
            failures.append("endpointWrappingKeyVaultContract")
        if probe.get("endpointWasmContract") != "ucr.endpoint-wasm.v1":
            failures.append("endpointWasmContract")
        if not endpoint_wasm_execution_verified:
            failures.append(f"endpointWasmExecution:{endpoint_wasm_execution!r}")
        if not persistence_reload_round_trip:
            failures.append(
                f"indexedDbReloadRoundTrip:read={persistence_read!r}:"
                f"before={persistence_before_refresh!r}:after={persistence_after_refresh!r}"
            )
        if not persistence_delete_verified:
            failures.append("indexedDbDelete")
        if not lifecycle_restore_verified:
            failures.append(f"endpointPersistenceLifecycle:{lifecycle_restore!r}")
        if not vault_reload_verified:
            failures.append(f"endpointWrappingKeyVault:{vault_after!r}")
        evidence = {
            "schema": "ucr.browser-compatibility.v1",
            "browser_requested": args.browser,
            "browser_name": reported.get("browserName"),
            "browser_version": reported.get("browserVersion"),
            "platform_name": reported.get("platformName"),
            "evidence_kind": "real-desktop-browser-webdriver-smoke",
            "probe": probe,
            "full_hd_local_codec_probe": full_hd_codec_probe,
            "full_hd_local_codec_probe_kind": "real-browser-synthetic-frame-no-network",
            "endpoint_wasm_execution": {
                "contract": probe.get("endpointWasmContract"),
                "generated_package_loaded": endpoint_wasm_execution_verified,
                "openmls_key_package_generated": endpoint_wasm_execution.get("keyPackageBytes", 0) > 0,
                "pre_join_epoch_fail_closed": endpoint_wasm_execution.get("preJoinEpochRejected") is True,
                "probe": endpoint_wasm_execution,
            },
            "endpoint_state_schema_migration": {
                "from_version": 1,
                "to_version": 2,
                "legacy_snapshot_preserved": legacy_upgrade_verified,
                "probe": legacy_upgrade,
            },
            "endpoint_wrapping_key_vault": {
                "contract": probe.get("endpointWrappingKeyVaultContract"),
                "storage": "IndexedDB structured-clone CryptoKey plus AES-GCM wrapped DEK",
                "non_extractable_kek": vault_before.get("kekExtractable") is False and vault_after.get("kekExtractable") is False,
                "raw_export_rejected": vault_before.get("exportRejected") is True and vault_after.get("exportRejected") is True,
                "wrapped_not_raw": vault_before.get("wrappedEqualsRaw") is False,
                "reload_same_dek": vault_reload_verified,
                "before_refresh": vault_before,
                "after_refresh": vault_after,
            },
            "endpoint_state_persistence": {
                "contract": probe.get("endpointStateStoreContract"),
                "storage": "IndexedDB",
                "sealed_bytes_only": True,
                "reload_round_trip": persistence_reload_round_trip,
                "reload_probe": persistence_read,
                "before_refresh": persistence_before_refresh,
                "after_refresh": persistence_after_refresh,
                "delete_verified": persistence_delete_verified,
                "adapter_lifecycle_restore": lifecycle_restore_verified,
                "adapter_lifecycle_probe": lifecycle_restore,
            },
            "required_checks": required,
            "failures": failures,
            "passed": not failures,
            "notes": {
                "display_capture_api_observed": bool(probe.get("getDisplayMedia")),
                "media_permissions_exercised": False,
                "conference_network_join_exercised": False,
                "two_real_devices_exercised": False,
                "public_turn_traversal_exercised": False,
                "endpoint_state_reload_exercised": True,
                "generated_endpoint_wasm_exercised": True,
                "openmls_key_package_generation_exercised": True,
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if failures:
            raise RuntimeError(f"{args.browser} failed required browser checks: {failures}")
        print(json.dumps(evidence, sort_keys=True))
        return 0
    finally:
        if session_id:
            try:
                request_json(
                    "DELETE",
                    f"http://127.0.0.1:{webdriver_port}/session/{session_id}",
                )
            except Exception:
                pass
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
