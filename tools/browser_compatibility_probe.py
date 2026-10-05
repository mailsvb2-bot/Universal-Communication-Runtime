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
    done({
      found: value instanceof Uint8Array,
      length: value instanceof Uint8Array ? value.length : null,
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
    const bytes = value instanceof Uint8Array ? value : null;
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
      const request = indexedDB.open("ucr-endpoint-state-v1", 1);
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
        if not persistence_reload_round_trip:
            failures.append(
                f"indexedDbReloadRoundTrip:read={persistence_read!r}:"
                f"before={persistence_before_refresh!r}:after={persistence_after_refresh!r}"
            )
        if not persistence_delete_verified:
            failures.append("indexedDbDelete")
        evidence = {
            "schema": "ucr.browser-compatibility.v1",
            "browser_requested": args.browser,
            "browser_name": reported.get("browserName"),
            "browser_version": reported.get("browserVersion"),
            "platform_name": reported.get("platformName"),
            "evidence_kind": "real-desktop-browser-webdriver-smoke",
            "probe": probe,
            "endpoint_state_persistence": {
                "contract": probe.get("endpointStateStoreContract"),
                "storage": "IndexedDB",
                "sealed_bytes_only": True,
                "reload_round_trip": persistence_reload_round_trip,
                "reload_probe": persistence_read,
                "before_refresh": persistence_before_refresh,
                "after_refresh": persistence_after_refresh,
                "delete_verified": persistence_delete_verified,
            },
            "required_checks": required,
            "failures": failures,
            "passed": not failures,
            "notes": {
                "display_capture_api_observed": bool(probe.get("getDisplayMedia")),
                "media_permissions_exercised": False,
                "conference_network_join_exercised": False,
                "endpoint_state_reload_exercised": True,
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
