#!/usr/bin/env python3
"""Fixed Phase-45 performance regression gate for the canonical 1000-person SFU lifecycle.

The threshold is deliberately a source-controlled constant, not a CI argument. Changing it
requires changing reviewed source and the governing ADR instead of weakening a workflow input.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "ucr.performance-evidence.v1"
WORKLOAD = "1000-person-sfu-conference-lifecycle"
SAMPLES = 3
MAX_SAMPLE_SECONDS = 10.0
TEST_COMMAND = [
    "cargo",
    "test",
    "--locked",
    "--profile",
    "production",
    "-p",
    "ucr-conference",
    "--test",
    "reference",
    "thousand_person_sfu_conference_fits_bounded_call_ceiling",
    "--",
    "--exact",
]


def _version(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def run_sample(root: Path) -> float:
    started = time.monotonic()
    try:
        subprocess.run(
            TEST_COMMAND,
            cwd=root,
            check=True,
            timeout=MAX_SAMPLE_SECONDS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"{WORKLOAD} exceeded fixed {MAX_SAMPLE_SECONDS:.1f}s sample budget"
        ) from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        raise RuntimeError(f"{WORKLOAD} failed: {detail[-2000:]}") from error
    elapsed = time.monotonic() - started
    if elapsed > MAX_SAMPLE_SECONDS:
        raise RuntimeError(
            f"{WORKLOAD} took {elapsed:.3f}s > fixed {MAX_SAMPLE_SECONDS:.1f}s sample budget"
        )
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()

    if len(args.source_commit) != 40 or any(ch not in "0123456789abcdef" for ch in args.source_commit):
        print("PERFORMANCE_GATE_ERROR: source commit must be lowercase 40-hex", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parent.parent
    try:
        durations = [run_sample(root) for _ in range(SAMPLES)]
        evidence = {
            "schema": SCHEMA,
            "source_commit": args.source_commit,
            "workload": WORKLOAD,
            "build_profile": "production",
            "sample_count": SAMPLES,
            "max_sample_seconds": MAX_SAMPLE_SECONDS,
            "sample_seconds": [round(value, 6) for value in durations],
            "median_seconds": round(statistics.median(durations), 6),
            "worst_seconds": round(max(durations), 6),
            "runner_os": platform.platform(),
            "rustc": _version(["rustc", "--version"]),
            "cargo": _version(["cargo", "--version"]),
            "result": "pass",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"PERFORMANCE_GATE_ERROR: {error}", file=sys.stderr)
        return 2

    print(
        "PERFORMANCE_GATE_OK "
        f"workload={WORKLOAD} samples={SAMPLES} worst={max(durations):.3f}s "
        f"limit={MAX_SAMPLE_SECONDS:.1f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
