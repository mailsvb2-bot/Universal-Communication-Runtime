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
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
CLIENT_ROOT = ROOT / "crates" / "ucr-realtime-web" / "static"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


def request_json(method: str, url: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
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
        )
        value = created.get("value") or {}
        session_id = value.get("sessionId") or created.get("sessionId")
        if not session_id:
            raise RuntimeError(f"WebDriver did not return a session id: {created}")
        reported = value.get("capabilities") or {}
        base = f"http://127.0.0.1:{webdriver_port}/session/{session_id}"
        request_json(
            "POST",
            f"{base}/url",
            {"url": f"http://localhost:{server.server_port}/client.html"},
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
        required = [
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
            "joinControl",
            "microphoneControl",
            "cameraControl",
            "screenControl",
            "localVideo",
            "remoteVideo",
        ]
        failures = [name for name in required if probe.get(name) is not True]
        evidence = {
            "schema": "ucr.browser-compatibility.v1",
            "browser_requested": args.browser,
            "browser_name": reported.get("browserName"),
            "browser_version": reported.get("browserVersion"),
            "platform_name": reported.get("platformName"),
            "evidence_kind": "real-desktop-browser-webdriver-smoke",
            "probe": probe,
            "required_checks": required,
            "failures": failures,
            "passed": not failures,
            "notes": {
                "display_capture_api_observed": bool(probe.get("getDisplayMedia")),
                "media_permissions_exercised": False,
                "conference_network_join_exercised": False,
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
