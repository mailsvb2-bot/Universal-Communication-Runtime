#!/usr/bin/env python3
"""Run the real iOS Simulator Safari mobile probe with bounded recovery.

The evidence still comes from tools/mobile_browser_compatibility_probe.py and
the real Mobile Safari process. This wrapper only makes CoreSimulator/openurl
startup deterministic enough for CI: every simctl operation is bounded and a
failed simulator is fully recycled before trying another available iPhone.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "mobile_browser_compatibility_probe.py"
SAFARI_BUNDLE_ID = "com.apple.mobilesafari"


def run(
    args: Sequence[str],
    *,
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def restart_coresimulator_control_plane() -> None:
    best_effort(["killall", "-9", "Simulator"], timeout=5)
    best_effort(
        ["killall", "-9", "com.apple.CoreSimulator.CoreSimulatorService"],
        timeout=5,
    )
    time.sleep(3)


def available_iphones() -> list[tuple[tuple[int, int], str, str]]:
    result: subprocess.CompletedProcess[str] | None = None
    failures: list[str] = []
    for attempt in range(1, 4):
        try:
            candidate = run(
                ["xcrun", "simctl", "list", "devices", "available", "-j"],
                timeout=20,
                check=False,
            )
            if candidate.returncode == 0:
                result = candidate
                break
            failures.append(
                f"attempt {attempt}: rc={candidate.returncode} "
                f"output={candidate.stdout[-2000:]!r}"
            )
        except subprocess.TimeoutExpired:
            failures.append(f"attempt {attempt}: simctl list timed out after 20s")

        print(
            f"CoreSimulator discovery failed; recycling control plane: "
            f"{failures[-1]}",
            flush=True,
        )
        restart_coresimulator_control_plane()

    if result is None:
        raise RuntimeError(
            "could not enumerate available iPhone simulators after recovery: "
            + " | ".join(failures)
        )

    data = json.loads(result.stdout)
    candidates: list[tuple[tuple[int, int], str, str]] = []
    for runtime, devices in data.get("devices", {}).items():
        if ".iOS-" not in runtime:
            continue
        match = re.search(r"iOS-(\d+)(?:-(\d+))?", runtime)
        version = (
            (int(match.group(1)), int(match.group(2) or 0))
            if match
            else (0, 0)
        )
        for device in devices:
            name = str(device.get("name", ""))
            udid = str(device.get("udid", ""))
            if device.get("isAvailable") and name.startswith("iPhone") and udid:
                candidates.append((version, name, udid))
    candidates.sort(reverse=True)
    return candidates


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def best_effort(args: Sequence[str], *, timeout: int) -> None:
    try:
        result = run(args, timeout=timeout, check=False)
        if result.returncode != 0:
            print(
                f"best-effort command rc={result.returncode}: "
                f"{' '.join(args)}: {result.stdout[-1000:]!r}",
                flush=True,
            )
    except subprocess.TimeoutExpired:
        print(
            f"best-effort command timed out after {timeout}s: {' '.join(args)}",
            flush=True,
        )


def simulator_cleanup(udid: str) -> None:
    best_effort(
        ["xcrun", "simctl", "terminate", udid, SAFARI_BUNDLE_ID],
        timeout=8,
    )
    best_effort(["xcrun", "simctl", "shutdown", udid], timeout=20)


def recover_coresimulator() -> None:
    best_effort(["xcrun", "simctl", "shutdown", "all"], timeout=20)
    restart_coresimulator_control_plane()
    # Force CoreSimulator.framework to relaunch and prove the control plane is responsive.
    available_iphones()


def boot_simulator(udid: str) -> None:
    run(["xcrun", "simctl", "boot", udid], timeout=30, check=False)
    status = run(
        ["xcrun", "simctl", "bootstatus", udid, "-b"],
        timeout=180,
        check=False,
    )
    if status.returncode != 0:
        raise RuntimeError(f"bootstatus failed: {status.stdout[-4000:]}")


def wait_for_probe(
    process: subprocess.Popen[str],
    output: Path,
    seconds: int,
) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if output.is_file() and output.stat().st_size > 0:
            return True
        code = process.poll()
        if code is not None:
            if code != 0:
                raise RuntimeError(f"mobile probe exited early with code {code}")
            return output.is_file() and output.stat().st_size > 0
        time.sleep(1)
    return False


def probe_device(
    *,
    udid: str,
    name: str,
    output: Path,
    port: int,
    probe_timeout: int,
    openurl_timeout: int,
    open_attempts: int,
) -> bool:
    output.unlink(missing_ok=True)
    simulator_cleanup(udid)
    boot_simulator(udid)

    run(
        ["open", "-a", "Simulator", "--args", "-CurrentDeviceUDID", udid],
        timeout=15,
        check=False,
    )
    time.sleep(3)

    command = [
        sys.executable,
        str(PROBE),
        "--browser",
        "ios-safari",
        "--port",
        str(port),
        "--timeout-seconds",
        str(probe_timeout),
        "--output",
        str(output),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        time.sleep(1)
        if process.poll() is not None:
            stdout = process.communicate(timeout=5)[0]
            raise RuntimeError(f"mobile probe failed to start: {stdout[-4000:]}")

        url = f"http://127.0.0.1:{port}/client.html?ucr_mobile_probe=ios-safari"
        for attempt in range(1, open_attempts + 1):
            try:
                opened = run(
                    ["xcrun", "simctl", "openurl", udid, url],
                    timeout=openurl_timeout,
                    check=False,
                )
                print(
                    f"Safari openurl attempt {attempt}/{open_attempts} "
                    f"on {name} ({udid}): rc={opened.returncode} "
                    f"output={opened.stdout[-1000:]!r}",
                    flush=True,
                )
            except subprocess.TimeoutExpired:
                print(
                    f"Safari openurl attempt {attempt}/{open_attempts} "
                    f"timed out after {openurl_timeout}s on {name} ({udid})",
                    flush=True,
                )

            if wait_for_probe(process, output, 25):
                code = process.wait(timeout=10)
                stdout = process.stdout.read() if process.stdout is not None else ""
                print(stdout, end="")
                if code != 0:
                    raise RuntimeError(f"mobile probe returned {code}")
                return True

            best_effort(
                ["xcrun", "simctl", "terminate", udid, SAFARI_BUNDLE_ID],
                timeout=8,
            )
            time.sleep(2)

        return False
    finally:
        if process.poll() is None:
            stop_process(process)
        if process.stdout is not None:
            remaining = process.stdout.read()
            if remaining:
                print(remaining, end="")
        simulator_cleanup(udid)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--probe-timeout-seconds", type=int, default=210)
    parser.add_argument("--openurl-timeout-seconds", type=int, default=15)
    parser.add_argument("--open-attempts", type=int, default=4)
    parser.add_argument("--max-simulators", type=int, default=2)
    args = parser.parse_args()

    candidates = available_iphones()
    if not candidates:
        raise RuntimeError("no available iPhone simulators")

    selected = candidates[: max(1, args.max_simulators)]
    if len(selected) == 1 and args.max_simulators > 1:
        selected.append(selected[0])

    failures: list[str] = []
    for index, (_version, name, udid) in enumerate(selected, start=1):
        print(
            f"iOS Safari simulator attempt {index}/{len(selected)}: "
            f"{name} ({udid})",
            flush=True,
        )
        try:
            if index > 1:
                recover_coresimulator()
                simulator_cleanup(udid)
                try:
                    erased = run(
                        ["xcrun", "simctl", "erase", udid],
                        timeout=120,
                        check=False,
                    )
                    print(
                        f"Simulator recycle erase rc={erased.returncode}: "
                        f"{erased.stdout[-1000:]!r}",
                        flush=True,
                    )
                except subprocess.TimeoutExpired:
                    print(
                        f"Simulator erase timed out for {name} ({udid}); "
                        "continuing with a cold boot",
                        flush=True,
                    )
            if probe_device(
                udid=udid,
                name=name,
                output=args.output,
                port=args.port,
                probe_timeout=args.probe_timeout_seconds,
                openurl_timeout=args.openurl_timeout_seconds,
                open_attempts=args.open_attempts,
            ):
                return 0
        except Exception as error:
            failures.append(f"{name} ({udid}): {error}")
            print(f"iOS Safari attempt failed: {failures[-1]}", flush=True)

    raise RuntimeError(
        "iOS Safari simulator evidence failed after bounded recovery: "
        + " | ".join(failures or ["no evidence produced"])
    )


if __name__ == "__main__":
    raise SystemExit(main())
