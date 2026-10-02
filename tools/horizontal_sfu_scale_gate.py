#!/usr/bin/env python3
"""Fixed encrypted-SFU fanout scale evidence for the horizontal runtime boundary.

This is deliberately not browser/WebRTC end-to-end evidence. It exercises the production-profile
SFU authorization/E2EE/fanout path at the required participant scales and records that narrower
scope explicitly so the repository cannot relabel it as requirement-55 browser load proof.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "ucr.horizontal-sfu-scale-evidence.v1"
SAMPLES = 2
PROFILES = [
    {
        "participants": 10,
        "publishers": 1,
        "test": "ten_participant_one_publisher_encrypted_sfu_fanout",
        "max_sample_seconds": 5.0,
    },
    {
        "participants": 100,
        "publishers": 2,
        "test": "hundred_participant_two_publisher_encrypted_sfu_fanout",
        "max_sample_seconds": 7.0,
    },
    {
        "participants": 500,
        "publishers": 4,
        "test": "five_hundred_participant_four_publisher_encrypted_sfu_fanout",
        "max_sample_seconds": 10.0,
    },
    {
        "participants": 1000,
        "publishers": 8,
        "test": "thousand_participant_eight_publisher_encrypted_sfu_fanout",
        "max_sample_seconds": 15.0,
    },
]
BACKPRESSURE_TEST = "thousand_participant_fanout_reports_backpressure_without_false_acceptance"
BACKPRESSURE_MAX_SECONDS = 15.0
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _version(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _build_test_binary(root: Path) -> Path:
    command = [
        "cargo",
        "test",
        "--locked",
        "--profile",
        "production",
        "-p",
        "ucr-sfu",
        "--test",
        "scale_matrix",
        "--no-run",
        "--message-format=json",
    ]
    result = subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
    executable: Path | None = None
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-artifact":
            continue
        target = record.get("target")
        if not isinstance(target, dict) or target.get("name") != "scale_matrix":
            continue
        value = record.get("executable")
        if isinstance(value, str) and value:
            executable = Path(value)
    if executable is None or not executable.is_file():
        raise RuntimeError("cargo did not report the production scale_matrix test executable")
    return executable


def run_sample(test_binary: Path, test_name: str, budget: float) -> float:
    started = time.monotonic()
    try:
        subprocess.run(
            [str(test_binary), test_name, "--exact"],
            check=True,
            timeout=budget,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{test_name} exceeded fixed {budget:.1f}s sample budget") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        raise RuntimeError(f"{test_name} failed: {detail[-2000:]}") from error
    elapsed = time.monotonic() - started
    if elapsed > budget:
        raise RuntimeError(f"{test_name} took {elapsed:.3f}s > fixed {budget:.1f}s sample budget")
    return elapsed


def run_profile(test_binary: Path, profile: dict[str, object]) -> dict[str, object]:
    test_name = str(profile["test"])
    budget = float(profile["max_sample_seconds"])
    durations = [run_sample(test_binary, test_name, budget) for _ in range(SAMPLES)]
    participants = int(profile["participants"])
    publishers = int(profile["publishers"])
    return {
        "participants": participants,
        "publishers": publishers,
        "encrypted_fanout_attempts": publishers * (participants - 1),
        "test": test_name,
        "sample_count": SAMPLES,
        "max_sample_seconds": budget,
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

    if SOURCE_COMMIT_RE.fullmatch(args.source_commit) is None:
        print("HORIZONTAL_SFU_SCALE_GATE_ERROR: source commit must be lowercase 40-hex", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parent.parent
    try:
        test_binary = _build_test_binary(root)
        profiles = [run_profile(test_binary, profile) for profile in PROFILES]
        backpressure_seconds = run_sample(
            test_binary, BACKPRESSURE_TEST, BACKPRESSURE_MAX_SECONDS
        )
        evidence = {
            "schema": SCHEMA,
            "source_commit": args.source_commit,
            "build_profile": "production",
            "evidence_scope": "in_process_encrypted_sfu_authorization_and_fanout",
            "browser_webrtc_end_to_end_proven": False,
            "wan_capacity_proven": False,
            "requirement_55_status": "partial",
            "profiles": profiles,
            "backpressure": {
                "participants": 1000,
                "test": BACKPRESSURE_TEST,
                "max_sample_seconds": BACKPRESSURE_MAX_SECONDS,
                "sample_seconds": round(backpressure_seconds, 6),
                "result": "pass",
            },
            "runner_os": platform.platform(),
            "rustc": _version(["rustc", "--version"]),
            "cargo": _version(["cargo", "--version"]),
            "result": "pass",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError) as error:
        print(f"HORIZONTAL_SFU_SCALE_GATE_ERROR: {error}", file=sys.stderr)
        return 2

    summary = " ".join(
        f"{profile['participants']}p/{profile['publishers']}pub={profile['worst_seconds']:.3f}s/"
        f"{profile['max_sample_seconds']:.1f}s"
        for profile in profiles
    )
    print(
        "HORIZONTAL_SFU_SCALE_GATE_OK "
        f"profiles={len(profiles)} backpressure={backpressure_seconds:.3f}s "
        f"browser_e2e=false {summary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
