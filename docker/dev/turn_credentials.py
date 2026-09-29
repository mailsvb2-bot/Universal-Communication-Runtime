#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", default="ucr-dev")
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    args = parser.parse_args()

    if not 30 <= args.ttl_seconds <= 86400:
        raise SystemExit("ttl must be between 30 and 86400 seconds")
    if not args.session or any(ch.isspace() for ch in args.session):
        raise SystemExit("session must be non-empty and contain no whitespace")

    secret = os.environ.get("UCR_DEV_TURN_SECRET")
    if not secret:
        raise SystemExit("UCR_DEV_TURN_SECRET is required")

    expires = int(time.time()) + args.ttl_seconds
    username = f"{expires}:{args.session}"
    credential = base64.b64encode(
        hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    ).decode("ascii")
    print(f"UCR_DEV_TURN_USERNAME={username}")
    print(f"UCR_DEV_TURN_CREDENTIAL={credential}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
