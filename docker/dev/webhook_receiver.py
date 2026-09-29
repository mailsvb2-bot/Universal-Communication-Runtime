#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 1024 * 1024


class Receiver(BaseHTTPRequestHandler):
    server_version = "ucr-dev-webhook/1"

    def log_message(self, fmt: str, *args: object) -> None:
        print("UCR_DEV_WEBHOOK_HTTP " + (fmt % args), flush=True)

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self.send_error(411)
            return
        try:
            length = int(length_header)
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413)
            return

        body = self.rfile.read(length)
        digest = hashlib.sha256(body).hexdigest()
        event_type = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                value = parsed.get("type") or parsed.get("event_type")
                if isinstance(value, str) and len(value) <= 128:
                    event_type = value
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        print(
            "UCR_DEV_WEBHOOK_RECEIVED "
            f"path={self.path!r} bytes={len(body)} sha256={digest} "
            f"event_type={event_type!r}",
            flush=True,
        )
        self.send_response(204)
        self.end_headers()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), Receiver)
    print(f"UCR_DEV_WEBHOOK_READY endpoint=http://{args.bind}:{args.port}/", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
