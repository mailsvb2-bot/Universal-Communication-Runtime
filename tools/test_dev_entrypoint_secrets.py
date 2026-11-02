#!/usr/bin/env python3
"""The dev entrypoint must not print TURN secrets or derived credentials."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = (ROOT / "docker/dev/entrypoint.sh").read_text(encoding="utf-8")


def main() -> int:
    for line in ENTRY.splitlines():
        code = line.split("#", 1)[0]
        if re.search(r"\b(echo|printf)\b", code) and re.search(r"\$\{?TURN_SECRET\b", code) \
                and "TURN_CONFIG" not in code:
            raise SystemExit(f"entrypoint prints a TURN secret: {line.strip()}")
        if "turn_credentials.py" in code and ">" not in code:
            raise SystemExit("derived TURN credentials must be redirected to a file")
    assert "umask 077" in ENTRY and "turn-credentials.env" in ENTRY
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "c.env"
        with out.open("w", encoding="utf-8") as handle:
            subprocess.run(
                [sys.executable, str(ROOT / "docker/dev/turn_credentials.py")],
                env={**os.environ, "UCR_DEV_TURN_SECRET": "x" * 40},
                stdout=handle, check=True,
            )
        assert "UCR_DEV_TURN_CREDENTIAL=" in out.read_text(encoding="utf-8")
    print("UCR_DEV_ENTRYPOINT_SECRETS_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
