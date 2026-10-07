#!/usr/bin/env python3
"""Serve the reference client and collect fail-closed mobile browser evidence."""

from __future__ import annotations

import argparse
import functools
import http.server
import json
from pathlib import Path
import threading
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CLIENT_ROOT = ROOT / "crates" / "ucr-realtime-web" / "static"
MAX_RESULT_BYTES = 1024 * 1024


class ProbeServer(http.server.ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[http.server.BaseHTTPRequestHandler],
        expected_browser: str,
    ) -> None:
        super().__init__(server_address, handler)
        self.expected_browser = expected_browser
        self.result_event = threading.Event()
        self.result_payload: dict[str, Any] | None = None


class ProbeHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler contract
        if self.path != "/__mobile_probe_result":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length <= 0 or length > MAX_RESULT_BYTES:
            self.send_error(413)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400)
            return
        server = self.server
        if not isinstance(server, ProbeServer):
            self.send_error(500)
            return
        if not isinstance(payload, dict):
            self.send_error(400)
            return
        if payload.get("browser_requested") != server.expected_browser:
            self.send_error(409)
            return
        if server.result_payload is not None:
            self.send_error(409)
            return
        server.result_payload = payload
        server.result_event.set()
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def evidence_kind(browser: str) -> str:
    if browser == "android-chrome":
        return "real-android-emulator-chrome-self-probe"
    if browser == "ios-safari":
        return "real-ios-simulator-safari-self-probe"
    raise AssertionError(browser)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--browser",
        choices=["android-chrome", "ios-safari"],
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--timeout-seconds", type=int, default=240)
    args = parser.parse_args()

    handler = functools.partial(ProbeHandler, directory=str(CLIENT_ROOT))
    server = ProbeServer(("0.0.0.0", args.port), handler, args.browser)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    started_at = time.time()
    try:
        if not server.result_event.wait(args.timeout_seconds):
            raise RuntimeError(
                f"timed out waiting for {args.browser} mobile browser evidence"
            )
        payload = server.result_payload
        if payload is None:
            raise RuntimeError("mobile browser probe signalled without evidence")
        envelope = {
            "schema": "ucr.mobile-browser-compatibility.v1",
            "browser_requested": args.browser,
            "evidence_kind": evidence_kind(args.browser),
            "reference_page": "crates/ucr-realtime-web/static/client.html",
            "probe": payload,
            "elapsed_seconds": round(time.time() - started_at, 3),
            "passed": payload.get("passed") is True,
            "notes": {
                "simulator_or_emulator_backed": True,
                "desktop_user_agent_emulation": False,
                "media_permission_prompt_exercised": False,
                "conference_network_join_exercised": False,
                "generated_endpoint_wasm_exercised": True,
                "indexeddb_round_trip_exercised": True,
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not envelope["passed"]:
            raise RuntimeError(
                f"{args.browser} failed mobile browser checks: "
                f"{payload.get('failures', [])!r}"
            )
        print(json.dumps(envelope, sort_keys=True))
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
