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
      let preJoinRefRejected = false;
      try {
        state.crypto_epoch();
      } catch (_) {
        preJoinEpochRejected = true;
      }
      try {
        state.crypto_state_ref();
      } catch (_) {
        preJoinRefRejected = true;
      }
      // Exercise the REAL browser WASM/OpenMLS epoch-zero creator. This is
      // public authenticator metadata, not a server or JavaScript exporter.
      state.create_endpoint_group();
      const initialEpoch = state.crypto_epoch();
      const initialRef = state.crypto_state_ref();
      const verifiedEpochZero = initialEpoch === 0n &&
        typeof initialRef === "string" && /^[0-9a-f]{64}$/.test(initialRef);
      // Crash-safe prepublication snapshot: the creator must recover its
      // EXACT same epoch-zero OpenMLS group after a lost HTTP acknowledgement.
      // A different Device, wrapping key or snapshot domain must fail closed.
      let creatorRecoveryVerified = false;
      let creatorWrongDeviceRejected = false;
      let creatorWrongKeyRejected = false;
      let creatorDomainRejected = false;
      const creatorWrapping = new Uint8Array(32).fill(31);
      const unpublished = state.seal_unpublished_group(creatorWrapping);
      let recoveredCreator = null;
      try {
        recoveredCreator = module.EndpointMlsState.restore_unpublished_group(
          "wasm-probe-tenant", "wasm-probe-namespace",
          "wasm-probe-group", "wasm-probe-device-" + browser,
          creatorWrapping, unpublished
        );
        const canonicalSnapshot = recoveredCreator.seal_snapshot(creatorWrapping);
        const admittedCreator = module.EndpointMlsState.restore(
          "wasm-probe-tenant", "wasm-probe-namespace",
          "wasm-probe-group", "wasm-probe-device-" + browser,
          creatorWrapping, canonicalSnapshot, 0n, initialRef
        );
        creatorRecoveryVerified = recoveredCreator.crypto_epoch() === 0n &&
          recoveredCreator.crypto_state_ref() === initialRef &&
          admittedCreator.crypto_state_ref() === initialRef;
        admittedCreator.free();
        try {
          module.EndpointMlsState.restore_unpublished_group(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", "wrong-device", creatorWrapping, unpublished
          );
        } catch (_) { creatorWrongDeviceRejected = true; }
        try {
          module.EndpointMlsState.restore_unpublished_group(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", "wasm-probe-device-" + browser,
            new Uint8Array(32).fill(32), unpublished
          );
        } catch (_) { creatorWrongKeyRejected = true; }
        try {
          module.EndpointMlsState.restore_unjoined_key_package(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", "wasm-probe-device-" + browser,
            creatorWrapping, unpublished
          );
        } catch (_) { creatorDomainRejected = true; }
      } finally {
        creatorWrapping.fill(0);
        if (recoveredCreator) recoveredCreator.free();
      }
      // Actual browser OpenMLS KeyPackage -> encrypted unjoined snapshot ->
      // reload/restore -> endpoint-owned Add/Welcome. No server-held seed.
      const recipientDevice = "wasm-probe-recipient-" + browser;
      const recipient = new module.EndpointMlsState(
        "wasm-probe-tenant", "wasm-probe-namespace",
        "wasm-probe-group", recipientDevice
      );
      let recovered = null;
      let persistedRecipientWelcome = false;
      let wrongDeviceRejected = false;
      let wrongKeyRejected = false;
      let activeAsUnjoinedRejected = false;
      try {
        const wrappingKey = new Uint8Array(32).fill(17);
        const originalOffer = recipient.key_package();
        const sealedOffer = recipient.seal_unjoined_key_package(wrappingKey);
        recovered = module.EndpointMlsState.restore_unjoined_key_package(
          "wasm-probe-tenant", "wasm-probe-namespace",
          "wasm-probe-group", recipientDevice, wrappingKey, sealedOffer
        );
        try {
          module.EndpointMlsState.restore_unjoined_key_package(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", "other-device", wrappingKey, sealedOffer
          );
        } catch (_) { wrongDeviceRejected = true; }
        try {
          module.EndpointMlsState.restore_unjoined_key_package(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", recipientDevice,
            new Uint8Array(32).fill(18), sealedOffer
          );
        } catch (_) { wrongKeyRejected = true; }
        const recoveredOffer = recovered.key_package();
        const sameOffer = originalOffer.length === recoveredOffer.length &&
          originalOffer.every((byte, index) => byte === recoveredOffer[index]);
        const commit = state.stage_add_device(recipientDevice, recoveredOffer);
        const welcome = state.pending_welcome();
        const nextEpoch = state.pending_epoch();
        const nextRef = state.pending_state_ref();
        state.merge_endpoint_transition(nextEpoch, nextRef);
        recovered.join_from_welcome(welcome, nextEpoch, nextRef);
        persistedRecipientWelcome = sameOffer && commit.length > 0 &&
          welcome.length > 0 && nextEpoch === 1n &&
          recovered.crypto_epoch() === nextEpoch &&
          recovered.crypto_state_ref() === nextRef;
        const joinedSnapshot = recovered.seal_snapshot(wrappingKey);
        try {
          module.EndpointMlsState.restore_unjoined_key_package(
            "wasm-probe-tenant", "wasm-probe-namespace",
            "wasm-probe-group", recipientDevice, wrappingKey, joinedSnapshot
          );
        } catch (_) { activeAsUnjoinedRejected = true; }
        wrappingKey.fill(0);
      } finally {
        if (recovered && typeof recovered.free === "function") recovered.free();
        if (typeof recipient.free === "function") recipient.free();
      }
      done({
        ok: contract === "ucr.endpoint-wasm.v1" &&
          isBytes &&
          keyPackage.length > 0 &&
          preJoinEpochRejected &&
          preJoinRefRejected &&
          verifiedEpochZero &&
          creatorRecoveryVerified &&
          creatorWrongDeviceRejected &&
          creatorWrongKeyRejected &&
          creatorDomainRejected &&
          persistedRecipientWelcome &&
          wrongDeviceRejected &&
          wrongKeyRejected &&
          activeAsUnjoinedRejected,
        contract,
        keyPackageBytes: isBytes ? keyPackage.length : null,
        preJoinEpochRejected,
        preJoinRefRejected,
        verifiedEpochZero,
        creatorRecoveryVerified,
        creatorWrongDeviceRejected,
        creatorWrongKeyRejected,
        creatorDomainRejected,
        persistedRecipientWelcome,
        wrongDeviceRejected,
        wrongKeyRejected,
        activeAsUnjoinedRejected,
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
        # Import the SAME ESM bundle that the actual DataChannel will load.
        # With no canonical device signer/trusted keys provisioned, activation
        # must refuse rather than creating keys in JS or falling back to RTP.
        media_installer_probe = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
Promise.resolve().then(async () => {
  const module = await import("./endpoint-media/reference_browser_media_installer.js");
  let denied = "";
  try {
    await module.installUcrReferenceBrowserMedia({
      state: {}, groupId: "probe-group",
      claims: {
        tenantId: "probe-tenant", namespaceId: null,
        callId: "probe-call", participantId: "probe-person",
        participantKind: "person", deviceId: "probe-device",
        sessionId: "probe-session"
      },
      loadWasm: () => window.ucrEndpointWasm.load()
    });
  } catch (error) { denied = String(error); }
  done({
    ok: typeof module.installUcrReferenceBrowserMedia === "function" &&
      denied.includes("Canonical device media signing/trust authority is not wired"),
    entrypoint: typeof module.installUcrReferenceBrowserMedia,
    noAuthorityRejected: denied.includes("Canonical device media signing/trust authority is not wired")
  });
}).catch(error => done({ok: false, error: String(error)}));
""",
        )
        media_installer_verified = (
            isinstance(media_installer_probe, dict)
            and media_installer_probe.get("ok") is True
        )
        if not media_installer_verified:
            raise RuntimeError(
                f"bundled E2EE installer did not reject missing canonical authority: "
                f"{media_installer_probe!r}"
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

        # Exercise the real browser's existing IndexedDB object store and
        # WebCrypto: a Device signer MUST survive page reload without minting
        # another private key or requiring a Call/Session-scoped vault key.
        probe_device_id = f"browser-device-signer-{args.browser}"
        signer_initial = execute_async(
            base,
            """
const done=arguments[arguments.length-1], deviceId=arguments[0];
(async()=>{
 const mod=await import("./endpoint-media/reference_browser_media_installer.js");
 const vault=mod.createUcrBrowserProtectedDeviceVault();
 const scope={tenantId:"browser-probe",namespaceId:null,deviceId};
 const first=await vault.stageNew(scope);
 const challenge=crypto.getRandomValues(new Uint8Array(64));
 const sig=await vault.signChallenge(scope,challenge);
 const key=await crypto.subtle.importKey("raw",first.publicKey,{name:"Ed25519"},false,["verify"]);
 const ok=await crypto.subtle.verify("Ed25519",key,sig,challenge);
 done({ok,keyId:first.keyId});
})().catch(e=>done({ok:false,error:String(e)}));
""",
            [probe_device_id],
        )
        if not isinstance(signer_initial, dict) or signer_initial.get("ok") is not True:
            raise RuntimeError(f"protected Device key staging failed: {signer_initial!r}")

        request_json("POST", f"{base}/refresh", {})
        time.sleep(0.5)

        signer_restored = execute_async(
            base,
            """
const done=arguments[arguments.length-1], deviceId=arguments[0], expected=arguments[1];
(async()=>{
 const mod=await import("./endpoint-media/reference_browser_media_installer.js");
 const vault=mod.createUcrBrowserProtectedDeviceVault();
 const scope={tenantId:"browser-probe",namespaceId:null,deviceId};
 const restored=await vault.load(scope);
 if(!restored||restored.keyId!==expected)throw Error("Device signer changed on restart");
 const challenge=crypto.getRandomValues(new Uint8Array(64));
 const sig=await vault.signChallenge(scope,challenge);
 const key=await crypto.subtle.importKey("raw",restored.publicKey,{name:"Ed25519"},false,["verify"]);
 done({ok:await crypto.subtle.verify("Ed25519",key,sig,challenge)});
})().catch(e=>done({ok:false,error:String(e)}));
""",
            [probe_device_id, signer_initial["keyId"]],
        )
        if not isinstance(signer_restored, dict) or signer_restored.get("ok") is not True:
            raise RuntimeError(f"protected Device key restoration failed: {signer_restored!r}")

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

        # Real browser race: simultaneous tabs/callers must recover the SAME
        # atomically inserted MLS snapshot wrapping key, never last-writer-wins.
        # A lost KEK would permanently strand an endpoint-owned MLS state.
        wrapping_key_race = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
(async () => {
  const key = "ucr-mls-wrapping-race:" + crypto.randomUUID();
  const candidates = await Promise.all(Array.from({length: 16}, () =>
    window.ucrEndpointWrappingKeyVault.getWrappingKey(key)));
  const first = candidates[0];
  const same = candidates.every(bytes =>
    bytes.length === 32 && bytes.every((value, index) => value === first[index]));
  const record = await readEndpointWrappingKeyRecord(key);
  const persisted = await window.ucrEndpointWrappingKeyVault.getWrappingKey(key);
  const restored = persisted.every((value, index) => value === first[index]);
  // A missing KEK during restore must fail without silently minting another
  // key that could never decrypt the old sealed MLS state.
  const missingKey = "ucr-mls-missing-kek:" + crypto.randomUUID();
  let missingRejected = false;
  try {
    await window.ucrEndpointWrappingKeyVault.getWrappingKey(
      missingKey, {requireExisting:true});
  } catch (_) { missingRejected = true; }
  const missingWasNotCreated = (await readEndpointWrappingKeyRecord(missingKey)) === null;
  for (const bytes of candidates) bytes.fill(0);
  persisted.fill(0);
  return {ok:same && restored && !!record && record.kek.extractable === false &&
      missingRejected && missingWasNotCreated,
    contenders:16, same, restored, missingRejected, missingWasNotCreated,
    nonExtractable:record?.kek.extractable === false};
})().then(done).catch(error => done({ok:false,error:String(error)}));
""",
        )
        if not isinstance(wrapping_key_race, dict) or wrapping_key_race.get("ok") is not True:
            raise RuntimeError(f"concurrent MLS wrapping-key creation failed: {wrapping_key_race!r}")

        # Real IndexedDB CAS: two independently restored first-party MLS tabs
        # must not overwrite each other's encrypted next-epoch snapshots.
        # Also race a direct IndexedDB writer (the /start.js owner), which does
        # not rely on client.html's Web Locks for the atomic transaction fence.
        snapshot_cas_browser = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
(async () => {
  if (!navigator.locks?.request)
    return {ok:true,supported:false,reason:"Web Locks unavailable; first-party Join fails closed"};
  const key = "ucr-e2ee-state:fp-v1:" + JSON.stringify([
    "cas-tenant",null,"fp-m-cas","alice","device-a",crypto.randomUUID()
  ]);
  const initial = Uint8Array.of(10,11,12);
  const winnerA = Uint8Array.of(20,21,22);
  const winnerB = Uint8Array.of(30,31,32);
  const fromStart = Uint8Array.of(40,41,42);
  const equals = (a,b) => !!a && a.length===b.length &&
    a.every((value,index)=>value===b[index]);
  try {
    await saveEndpointState(key,initial);
    const observed = await loadEndpointState(key);
    const competing = await Promise.allSettled([
      saveEndpointState(key,winnerA,observed),
      saveEndpointState(key,winnerB,observed)
    ]);
    const successes = competing.filter(result=>result.status==="fulfilled").length;
    const rejections = competing.filter(result=>
      result.status==="rejected" &&
      String(result.reason).includes("snapshot changed during restore")).length;
    const persisted = await loadEndpointState(key);
    const singleWinner = (equals(persisted,winnerA)||equals(persisted,winnerB)) &&
      successes===1 && rejections===1;
    const stale = await loadEndpointState(key);
    // Simulate a /start.js snapshot write after client.html read but before
    // its conditional promotion. The IndexedDB CAS must still reject it.
    const db = await openEndpointStateDb();
    try {
      await new Promise((resolve,reject)=>{
        const tx=db.transaction("sealed-snapshots","readwrite");
        tx.objectStore("sealed-snapshots").put(Array.from(fromStart),key);
        tx.oncomplete=resolve;
        tx.onerror=()=>reject(tx.error||Error("start writer failed"));
        tx.onabort=()=>reject(tx.error||Error("start writer aborted"));
      });
    } finally { db.close(); }
    let rollbackRejected = false;
    try { await saveEndpointState(key,initial,stale); }
    catch(error) {
      rollbackRejected=String(error).includes("snapshot changed during restore");
    }
    const newest = await loadEndpointState(key);
    const preserved = equals(newest,fromStart);
    return {ok:singleWinner&&rollbackRejected&&preserved,supported:true,
      successes,rejections,singleWinner,rollbackRejected,preserved};
  } finally { await removeEndpointState(key); }
})().then(done).catch(error=>done({ok:false,error:String(error)}));
""",
        )
        if not isinstance(snapshot_cas_browser, dict) or snapshot_cas_browser.get("ok") is not True:
            raise RuntimeError(f"first-party MLS snapshot CAS failed: {snapshot_cas_browser!r}")

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


        # Execute the production page's real heartbeat/Leave/offline handlers in
        # each desktop WebDriver browser. Only media tracks and HTTP are mocked:
        # no device permissions, signed grants, or remote server are involved.
        heartbeat_revocation_browser = execute_async(
            base,
            """
const done = arguments[arguments.length - 1];
const pageScript = arguments[0];
// Gecko WebDriver uses an isolated JS realm. Inject into the page realm so
// the regression exercises the actual client.html lexical state/functions.
const output = document.createElement("div");
output.id = "__ucr_regression_result";
output.hidden = true;
document.body.appendChild(output);
let finished = false;
const finish = value => {
  if (finished) return;
  finished = true;
  observer.disconnect();
  output.remove();
  done(value);
};
const observer = new MutationObserver(() => {
  const value = output.getAttribute("data-result");
  if (value !== null) {
    try { finish(JSON.parse(value)); }
    catch (error) { finish({ok:false,error:String(error)}); }
  }
});
observer.observe(output, {attributes:true,attributeFilter:["data-result"]});
const injected = document.createElement("script");
injected.textContent = pageScript;
document.documentElement.appendChild(injected);
injected.remove();
""",
            ["""
(async () => {
  const previousApi = api;
  const previousSetTimeout = window.setTimeout;
  const previousClaims = claims;
  const previousSignedGrantRetired = signedGrantRetired;
  const previousActiveSessionSequence = activeSessionSequence;
  const previousE2eeEndpoint = window.ucrE2eeEndpoint;
  const deferred = () => {
    let resolve, reject;
    const promise = new Promise((res, rej) => {resolve = res; reject = rej;});
    return {promise, resolve, reject};
  };
  const check = (ok, detail) => {if (!ok) throw new Error(detail);};
  const events = [];
  const track = name => ({stop() {events.push("stop:" + name);}});
  const capture = label => {
    const tracks = [track(label + ":microphone"), track(label + ":camera")];
    localStream = {getTracks: () => tracks};
    screenStream = {getTracks: () => [track(label + ":screen")]};
    peer = {close() {events.push("peer:" + label);}};
  };
  const oldHeartbeat = deferred(), oldLeave = deferred(), oldClose = deferred();
  let heartbeatCalls = 0, watchdog = null, closeOffer = null, joinCalls = 0;
  let oldLeaveSequence = null, offlineLeaveSequence = null;
  try {
    claims = {tenant_id:"test-tenant",namespace_id:"test-namespace",
      call_id:"test-call",session_id:"test-session",not_before:0};
    window.setTimeout = function(fn, delay, ...args) {
      if (delay === HEARTBEAT_AUTH_TIMEOUT_MS) {
        watchdog = {fire: () => fn(...args), delay};
        return 999999;
      }
      return previousSetTimeout.call(window, fn, delay, ...args);
    };
    api = async (path, payload) => {
      if (path === "/v1/realtime/join") {joinCalls++; throw new Error("Retired grant tried to Join");}
      if (path === "/v1/realtime/heartbeat") {
        heartbeatCalls++;
        return oldHeartbeat.promise;
      }
      if (path === "/v1/realtime/webrtc/close") {
        closeOffer = payload.offer_id;
        return oldClose.promise;
      }
      if (path === "/v1/realtime/leave") {
        oldLeaveSequence = payload.expected_session_sequence;
        return oldLeave.promise;
      }
      throw new Error("Unexpected HTTP path: " + path);
    };
    signedGrantRetired = false;
    activeSessionSequence = 1;
    sessionLifecycleGeneration++;
    sessionActive = true;mediaActive = true;
    heartbeatInFlight = false;
    startWebRtc.offerId = "A".repeat(43);
    ui.join.disabled = true;
    capture("watchdog");
    const pendingHeartbeat = heartbeat();
    await heartbeat(); // A second tick must not create another request.
    check(heartbeatCalls === 1, "overlapping heartbeat HTTP requests");
    check(watchdog?.delay === 12000, "missing bounded 12-second watchdog");
    watchdog.fire(); // Deterministically simulate a stalled HTTP authorization.
    check(!sessionActive && !mediaActive, "watchdog did not revoke session");
    check(signedGrantRetired && ui.join.disabled,
      "retired signed grant must block same-token Join despite hung Leave");
    await join();
    check(ui.join.disabled && ui.status.textContent.includes("fresh authorized call link"),
      "retired signed grant did not reject rejoin");
    check(joinCalls === 0, "retired session grant issued a second server Join");
    for (const name of ["microphone","camera","screen"]) {
      check(events.includes("stop:watchdog:" + name), "watchdog kept " + name + " capturing");
    }
    check(events.includes("peer:watchdog"), "watchdog left WebRTC peer open");
    check(closeOffer === "A".repeat(43), "old owned WebRTC offer not closed");
    check(oldLeaveSequence === 1, "retired Leave missing original server generation");

    // Emulate a separate, independently issued signed grant with a new
    // canonical session identity, not reuse of the retired grant.
    signedGrantRetired = false;
    claims = {...claims,session_id:"fresh-server-issued-session"};
    activeSessionSequence = 2;
    // The old Leave and close requests remain pending during new admission.
    // They must not erase the new peer's identity or overwrite its UI.
    sessionLifecycleGeneration++;
    sessionActive = true;mediaActive = true;
    startWebRtc.offerId = "B".repeat(43);
    ui.state.textContent = "New joined";
    ui.status.textContent = "New session active";
    ui.join.disabled = true;
    oldClose.resolve({ok:true});
    oldLeave.resolve({ok:true});
    oldHeartbeat.resolve({json: async () => ({
      admission_state:"admitted",media_policy:null
    })});
    await pendingHeartbeat;
    for (let i = 0; i < 6; i++) await Promise.resolve();
    check(startWebRtc.offerId === "B".repeat(43), "old close erased new offer");
    check(sessionActive && mediaActive, "stale heartbeat revoked new session");
    check(ui.state.textContent === "New joined" &&
      ui.status.textContent === "New session active" && ui.join.disabled,
      "late Leave overwrote new Join UI");

    // Dispatch the browser's actual offline event, including a busy screen
    // capture. Local tracks and the peer must stop before HTTP completes.
    api = async (path, payload) => {
      if (path === "/v1/realtime/webrtc/close") {
        closeOffer = payload.offer_id;
        return {ok:true};
      }
      if (path === "/v1/realtime/leave") {
        offlineLeaveSequence = payload.expected_session_sequence;
        return {ok:true};
      }
      throw new Error("Unexpected offline HTTP path: " + path);
    };
    capture("offline");
    screenShareBusy = true;
    window.dispatchEvent(new Event("offline"));
    check(!sessionActive && !mediaActive, "offline retained media authorization");
    check(offlineLeaveSequence === 2, "offline Leave did not use new Join generation");
    for (const name of ["microphone","camera","screen"]) {
      check(events.includes("stop:offline:" + name), "offline kept " + name + " capturing");
    }
    check(events.includes("peer:offline"), "offline left WebRTC peer open");
    window.dispatchEvent(new Event("online"));
    check(!sessionActive, "online silently reauthorized revoked session");
    check(signedGrantRetired && ui.join.disabled,
      "offline termination must retire the consumed signed grant");

    // A retiring E2EE adapter may reject its asynchronous stop after a fresh
    // Join has replaced the old session. Its error must not corrupt the UI.
    const retiredAdapterStop = deferred();
    window.ucrE2eeEndpoint = {stop: () => retiredAdapterStop.promise};
    sessionLifecycleGeneration++;
    sessionActive = true;
    closeE2eeTransport();
    sessionLifecycleGeneration++;
    sessionActive = true;
    ui.status.textContent = "New encrypted session active";
    retiredAdapterStop.reject(new Error("retired adapter stop failed"));
    for (let i = 0; i < 6; i++) await Promise.resolve();
    check(ui.status.textContent === "New encrypted session active",
      "late E2EE teardown error overwrote newly joined session");

    // A cleanup failure belonging to the current live session must still be
    // reported, rather than suppressed by the lifecycle guard.
    window.ucrE2eeEndpoint = {stop() {throw new Error("active adapter stop failed");}};
    sessionLifecycleGeneration++;
    sessionActive = true;
    ui.status.textContent = "Active encrypted session";
    closeE2eeTransport();
    check(ui.status.textContent === "Encrypted media cleanup failed; rejoin required.",
      "current E2EE teardown error was hidden");
    return {ok:true,heartbeatCalls,watchdogMs:watchdog.delay,
      localCaptureStopped:true,screenCaptureStopped:true,
      ownedPeerClosed:true,staleLeaveJoinGuarded:true,
      offlineStopped:true,onlineDidNotReauthorize:true,
      lateE2eeCleanupGuarded:true,currentE2eeCleanupReported:true,
      sequenceFencedLeave:true};
  } finally {
    api = previousApi;
    window.setTimeout = previousSetTimeout;
    claims = previousClaims;
    signedGrantRetired = previousSignedGrantRetired;
    activeSessionSequence = previousActiveSessionSequence;
    if (previousE2eeEndpoint === undefined) delete window.ucrE2eeEndpoint;
    else window.ucrE2eeEndpoint = previousE2eeEndpoint;
    screenShareBusy = false;
    sessionActive = false;mediaActive = false;
    startWebRtc.offerId = null;
  }
})().then(result => {
  document.getElementById("__ucr_regression_result").setAttribute(
    "data-result", JSON.stringify(result));
}).catch(error => {
  document.getElementById("__ucr_regression_result").setAttribute(
    "data-result", JSON.stringify({ok:false,error:String(error)}));
});
"""],
        )
        if not isinstance(heartbeat_revocation_browser, dict) or not heartbeat_revocation_browser.get("ok"):
            raise RuntimeError(
                f"{args.browser} failed heartbeat/offline browser regression: "
                f"{heartbeat_revocation_browser!r}"
            )

        # Real Chrome IndexedDB regression: an old version-1 connection
        # blocks the canonical vault's version-2 open. The vault must reject,
        # and its late request must not retain a handle that blocks version 3.
        # This is isolated to the disposable browser-probe origin, AFTER all
        # existing persistence/reload checks. It is NOT a two-device call.
        blocked_upgrade_browser = None
        if args.browser == "chrome":
            blocked_upgrade_browser = execute_async(
                base,
                """
const done = arguments[arguments.length - 1];
(async () => {
  const name = "ucr-endpoint-state-v1";
  const timeout = (label) => new Promise((_, reject) =>
    setTimeout(() => reject(new Error(label + " timed out")), 5000));
  const deleteDb = () => Promise.race([
    new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(name);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error || new Error("delete failed"));
      request.onblocked = () => reject(new Error("probe database delete blocked"));
    }),
    timeout("probe database delete")
  ]);
  await deleteDb();
  const old = await Promise.race([
    new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("sealed-snapshots");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("v1 open failed"));
    }),
    timeout("version 1 open")
  ]);
  let rejected = false;
  try {
    const mod = await import("./endpoint-media/reference_browser_media_installer.js");
    const vault = mod.createUcrBrowserProtectedDeviceVault();
    try {
      await Promise.race([
        vault.load({tenantId:"probe",namespaceId:null,deviceId:"blocked-upgrade"}),
        timeout("blocked vault open")
      ]);
    } catch (error) {
      rejected = String(error).includes("Device vault upgrade blocked");
    }
  } finally {
    old.close();
  }
  if (!rejected) throw new Error("blocked vault open did not fail closed");
  // If the rejected v2 request later succeeds without closing its IDBDatabase,
  // this real v3 upgrade remains blocked. A bounded success proves cleanup.
  const upgraded = await Promise.race([
    new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 3);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("v3 open failed"));
    }),
    timeout("late-open orphan blocked version 3")
  ]);
  upgraded.close();
  await deleteDb();
  // Repeat against client.html's own MLS snapshot database opener. It shares
  // the same DB but has a separate blocked-upgrade/late-onsuccess lifecycle.
  const oldClient = await Promise.race([
    new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("sealed-snapshots");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("client v1 open failed"));
    }),
    timeout("client version 1 open")
  ]);
  let clientRejected = false;
  try {
    try {
      await Promise.race([openEndpointStateDb(), timeout("blocked client MLS open")]);
    } catch (error) {
      clientRejected = String(error).includes("IndexedDB upgrade blocked");
    }
  } finally {
    oldClient.close();
  }
  if (!clientRejected) throw new Error("blocked client MLS open did not fail closed");
  const upgradedClient = await Promise.race([
    new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 3);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("client v3 open failed"));
    }),
    timeout("client late-open orphan blocked version 3")
  ]);
  upgradedClient.close();
  await deleteDb();
  done({ok:true,blockedRejected:rejected,clientBlockedRejected:clientRejected,
    lateConnectionDidNotBlockNextUpgrade:true,clientLateConnectionClosed:true});
})().catch(error => done({ok:false,error:String(error)}));
""",
            )
            if (
                not isinstance(blocked_upgrade_browser, dict)
                or blocked_upgrade_browser.get("ok") is not True
            ):
                raise RuntimeError(
                    "Chrome IndexedDB blocked-upgrade regression failed: "
                    f"{blocked_upgrade_browser!r}"
                )

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
            "heartbeat_revocation_browser": heartbeat_revocation_browser,
            "indexeddb_blocked_upgrade_browser": blocked_upgrade_browser,
            "endpoint_wrapping_key_concurrency": wrapping_key_race,
            "endpoint_mls_snapshot_cas_browser": snapshot_cas_browser,
            "browser_requested": args.browser,
            "browser_name": reported.get("browserName"),
            "browser_version": reported.get("browserVersion"),
            "platform_name": reported.get("platformName"),
            "evidence_kind": "real-desktop-browser-webdriver-smoke",
            "probe": probe,
            "full_hd_local_codec_probe": full_hd_codec_probe,
            "full_hd_local_codec_probe_kind": "real-browser-synthetic-frame-no-network",
            "endpoint_media_installer": {
                "module_imported": media_installer_verified,
                "no_authority_fails_closed": media_installer_probe.get("noAuthorityRejected") is True,
                "probe": media_installer_probe,
            },
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
                "atomic_first_writer_wins": wrapping_key_race.get("ok") is True,
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
