#!/usr/bin/env python3
"""Run the real Android Chrome mobile probe with bounded navigation recovery.

The browser evidence is still produced by mobile_browser_compatibility_probe.py
and real Chrome running inside the Android emulator. This runner only
orchestrates startup/navigation retries around the flaky emulator/Chrome edge.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
HOST_PROBE = ROOT / "tools" / "mobile_browser_compatibility_probe.py"
FIRST_RUN = ROOT / "tools" / "android_chrome_first_run.py"
CHROME_PACKAGE = "com.android.chrome"
CHROME_ACTIVITY = "org.chromium.chrome.browser.ChromeTabbedActivity"


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


def best_effort(args: Sequence[str], *, timeout: int) -> str:
    try:
        result = run(args, timeout=timeout, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout}s: {' '.join(args)}"


def wait_port(port: int, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"host probe did not listen on 127.0.0.1:{port}")


def wait_for_evidence(
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
                stdout = process.stdout.read() if process.stdout is not None else ""
                raise RuntimeError(
                    f"mobile probe exited early with code {code}: {stdout[-4000:]}"
                )
            return output.is_file() and output.stat().st_size > 0
        time.sleep(1)
    return False


def top_activity() -> str:
    return best_effort(
        ["adb", "shell", "dumpsys", "activity", "activities"],
        timeout=15,
    )


def start_chrome(url: str) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "adb",
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{CHROME_PACKAGE}/{CHROME_ACTIVITY}",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            url,
        ],
        timeout=45,
        check=False,
    )


def prove_reverse(port: int) -> None:
    result = run(["adb", "reverse", "--list"], timeout=15, check=False)
    expected = f"tcp:{port} tcp:{port}"
    if result.returncode != 0 or expected not in result.stdout:
        run(
            ["adb", "reverse", f"tcp:{port}", f"tcp:{port}"],
            timeout=15,
            check=True,
        )
        result = run(["adb", "reverse", "--list"], timeout=15, check=False)
    if expected not in result.stdout:
        raise RuntimeError(
            f"adb reverse did not expose tcp:{port}: {result.stdout[-2000:]}"
        )


def clear_first_run() -> None:
    result = start_chrome("about:blank")
    print(
        f"Chrome bootstrap rc={result.returncode}: {result.stdout[-2000:]!r}",
        flush=True,
    )
    helper = run(
        [sys.executable, str(FIRST_RUN), "--timeout-seconds", "120"],
        timeout=140,
        check=False,
    )
    print(helper.stdout, end="", flush=True)
    if helper.returncode != 0:
        raise RuntimeError(
            f"Chrome first-run helper failed with {helper.returncode}: "
            f"{helper.stdout[-4000:]}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--probe-timeout-seconds", type=int, default=300)
    parser.add_argument("--navigation-attempts", type=int, default=4)
    parser.add_argument("--evidence-wait-seconds", type=int, default=40)
    args = parser.parse_args()

    args.output.unlink(missing_ok=True)
    package = run(
        ["adb", "shell", "pm", "path", CHROME_PACKAGE],
        timeout=20,
        check=False,
    )
    if package.returncode != 0 or "package:" not in package.stdout:
        raise RuntimeError("Google Chrome package is not installed in the emulator")

    command = [
        sys.executable,
        str(HOST_PROBE),
        "--browser",
        "android-chrome",
        "--port",
        str(args.port),
        "--timeout-seconds",
        str(args.probe_timeout_seconds),
        "--output",
        str(args.output),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        wait_port(args.port)
        prove_reverse(args.port)
        clear_first_run()

        url = (
            f"http://127.0.0.1:{args.port}/client.html"
            "?ucr_mobile_probe=android-chrome"
        )
        for attempt in range(1, args.navigation_attempts + 1):
            best_effort(
                ["adb", "shell", "am", "force-stop", CHROME_PACKAGE],
                timeout=15,
            )
            prove_reverse(args.port)
            launched = start_chrome(url)
            print(
                f"Android Chrome probe navigation {attempt}/"
                f"{args.navigation_attempts}: rc={launched.returncode} "
                f"output={launched.stdout[-2000:]!r}",
                flush=True,
            )

            activity = top_activity()
            if "FirstRunActivity" in activity or "LightweightFirstRunActivity" in activity:
                helper = run(
                    [sys.executable, str(FIRST_RUN), "--timeout-seconds", "60"],
                    timeout=80,
                    check=False,
                )
                print(helper.stdout, end="", flush=True)

            if wait_for_evidence(
                process,
                args.output,
                args.evidence_wait_seconds,
            ):
                code = process.wait(timeout=15)
                stdout = process.stdout.read() if process.stdout is not None else ""
                print(stdout, end="", flush=True)
                if code != 0:
                    raise RuntimeError(f"mobile probe returned {code}")
                return 0

            print(
                "No Android Chrome evidence yet; retrying navigation. "
                f"Top activity snapshot: {top_activity()[-3000:]}",
                flush=True,
            )

        diagnostics = []
        diagnostics.append("reverse=" + best_effort(["adb", "reverse", "--list"], timeout=15))
        diagnostics.append("activity=" + top_activity()[-5000:])
        diagnostics.append(
            "chrome-logcat="
            + best_effort(
                [
                    "adb",
                    "logcat",
                    "-d",
                    "-t",
                    "250",
                    "chromium:D",
                    "cr_*:D",
                    "*:S",
                ],
                timeout=20,
            )[-8000:]
        )
        raise RuntimeError(
            "Android Chrome produced no mobile browser evidence after bounded "
            "navigation recovery. " + " | ".join(diagnostics)
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if process.stdout is not None:
            remaining = process.stdout.read()
            if remaining:
                print(remaining, end="", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
