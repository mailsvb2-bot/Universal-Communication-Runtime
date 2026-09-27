#!/usr/bin/env python3
"""Fixed Phase-45 performance regression gate for canonical SFU conference profiles.

The participant levels and thresholds are deliberately source-controlled constants, not CI
arguments. Changing them requires a reviewed source change rather than weakening a workflow input.
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

SCHEMA = "ucr.performance-evidence.v2"
SAMPLES = 3
PROFILES = [
    {
        "participants": 10,
        "test": "ten_person_sfu_conference_profile",
        "max_sample_seconds": 5.0,
    },
    {
        "participants": 100,
        "test": "hundred_person_sfu_conference_profile",
        "max_sample_seconds": 6.0,
    },
    {
        "participants": 500,
        "test": "five_hundred_person_sfu_conference_profile",
        "max_sample_seconds": 8.0,
    },
    {
        "participants": 1000,
        "test": "thousand_person_sfu_conference_fits_bounded_call_ceiling",
        "max_sample_seconds": 10.0,
    },
]


def _version(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _test_command(test_name: str) -> list[str]:
    return [
        "cargo",
        "test",
        "--locked",
        "--profile",
        "production",
        "-p",
        "ucr-conference",
        "--test",
        "reference",
        test_name,
        "--",
        "--exact",
    ]


def run_sample(root: Path, test_name: str, max_sample_seconds: float) -> float:
    started = time.monotonic()
    try:
        subprocess.run(
            _test_command(test_name),
            cwd=root,
            check=True,
            timeout=max_sample_seconds,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"{test_name} exceeded fixed {max_sample_seconds:.1f}s sample budget"
        ) from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        raise RuntimeError(f"{test_name} failed: {detail[-2000:]}") from error
    elapsed = time.monotonic() - started
    if elapsed > max_sample_seconds:
        raise RuntimeError(
            f"{test_name} took {elapsed:.3f}s > fixed {max_sample_seconds:.1f}s sample budget"
        )
    return elapsed


def run_profile(root: Path, profile: dict[str, object]) -> dict[str, object]:
    participants = int(profile["participants"])
    test_name = str(profile["test"])
    max_sample_seconds = float(profile["max_sample_seconds"])
    durations = [
        run_sample(root, test_name, max_sample_seconds)
        for _ in range(SAMPLES)
    ]
    return {
        "participants": participants,
        "workload": f"{participants}-person-sfu-conference-lifecycle",
        "test": test_name,
        "sample_count": SAMPLES,
        "max_sample_seconds": max_sample_seconds,
        "sample_seconds": [round(value, 6) for value in durations],
        "median_seconds": round(statistics.median(durations), 6),
        "worst_seconds": round(max(durations), 6),
        "result": "pass",
    }


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
        profiles = [run_profile(root, profile) for profile in PROFILES]
        evidence = {
            "schema": SCHEMA,
            "source_commit": args.source_commit,
            "build_profile": "production",
            "profiles": profiles,
            "runner_os": platform.platform(),
            "rustc": _version(["rustc", "--version"]),
            "cargo": _version(["cargo", "--version"]),
            "result": "pass",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError) as error:
        print(f"PERFORMANCE_GATE_ERROR: {error}", file=sys.stderr)
        return 2

    summary = " ".join(
        f"{profile['participants']}p={profile['worst_seconds']:.3f}s/"
        f"{profile['max_sample_seconds']:.1f}s"
        for profile in profiles
    )
    print(f"PERFORMANCE_GATE_OK profiles={len(profiles)} {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
