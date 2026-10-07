#!/usr/bin/env python3
"""Complete Google Chrome Android first-run UI on a test emulator.

This does not replace browser evidence. It only clears Chrome's own first-run
gate so the real com.android.chrome runtime can load the UCR reference page.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import time
import xml.etree.ElementTree as ET


FIRST_RUN_MARKERS = (
    "org.chromium.chrome.browser.firstrun.FirstRunActivity",
    "org.chromium.chrome.browser.firstrun.LightweightFirstRunActivity",
)

PREFERRED_TEXTS = (
    "Use without an account",
    "Accept & continue",
    "Stay signed out",
    "No thanks",
)

FALLBACK_TEXTS = (
    "Continue",
    "Got it",
)


def adb(*args: str, timeout: int = 20, check: bool = True) -> str:
    completed = subprocess.run(
        ["adb", *args],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return completed.stdout


def current_activity() -> str:
    output = adb("shell", "dumpsys", "activity", "activities", timeout=15)
    for line in output.splitlines():
        if "mResumedActivity" in line or "topResumedActivity" in line:
            return line.strip()
    return output[-4000:]


def ui_tree() -> ET.Element:
    remote = "/data/local/tmp/ucr-chrome-first-run.xml"
    last_error = "UI tree was not produced"
    for attempt in range(1, 11):
        dump = adb(
            "shell",
            "uiautomator",
            "dump",
            "--compressed",
            remote,
            timeout=20,
            check=False,
        )
        xml = adb("exec-out", "cat", remote, timeout=15, check=False)
        start = xml.find("<")
        end = xml.rfind(">")
        if start >= 0 and end >= start:
            candidate = xml[start : end + 1]
            try:
                return ET.fromstring(candidate)
            except ET.ParseError as error:
                last_error = f"attempt {attempt}: {error}; dump={dump!r}"
        else:
            last_error = (
                f"attempt {attempt}: no XML document; "
                f"dump={dump!r}; payload={xml[:500]!r}"
            )
        time.sleep(1)
    raise RuntimeError(f"could not obtain Android UI hierarchy: {last_error}")


def center(bounds: str) -> tuple[int, int]:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    if match is None:
        raise ValueError(f"invalid UI bounds: {bounds!r}")
    x1, y1, x2, y2 = map(int, match.groups())
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def clickable_candidates(root: ET.Element) -> list[ET.Element]:
    nodes = []
    for node in root.iter("node"):
        text = node.attrib.get("text", "").strip()
        description = node.attrib.get("content-desc", "").strip()
        resource_id = node.attrib.get("resource-id", "")
        if node.attrib.get("clickable") != "true":
            continue
        if text or description or resource_id:
            nodes.append(node)
    return nodes


def choose_target(root: ET.Element) -> ET.Element | None:
    nodes = clickable_candidates(root)
    for wanted in PREFERRED_TEXTS:
        for node in nodes:
            if node.attrib.get("text", "").strip() == wanted:
                return node
    for suffix in (
        "terms_accept",
        "dismiss_button",
        "signin_fre_dismiss_button",
        "negative_button",
    ):
        for node in nodes:
            if node.attrib.get("resource-id", "").endswith(suffix):
                return node
    for wanted in FALLBACK_TEXTS:
        for node in nodes:
            if node.attrib.get("text", "").strip() == wanted:
                return node
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    deadline = time.monotonic() + args.timeout_seconds
    last_activity = ""
    last_visible: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        last_activity = current_activity()
        if not any(marker in last_activity for marker in FIRST_RUN_MARKERS):
            print(f"Chrome first-run gate cleared: {last_activity}")
            return 0

        root = ui_tree()
        target = choose_target(root)
        if target is None:
            last_visible = [
                {
                    "text": node.attrib.get("text", ""),
                    "content_desc": node.attrib.get("content-desc", ""),
                    "resource_id": node.attrib.get("resource-id", ""),
                    "clickable": node.attrib.get("clickable", ""),
                }
                for node in root.iter("node")
                if (
                    node.attrib.get("text")
                    or node.attrib.get("content-desc")
                    or node.attrib.get("resource-id")
                )
            ]
            loading = any(
                item["resource_id"].endswith(
                    "fre_native_and_policy_load_progress_spinner"
                )
                for item in last_visible
            )
            state = "loading native/policy state" if loading else "waiting for safe action"
            print(f"Chrome first-run {state}: {last_visible[-20:]!r}")
            time.sleep(2)
            continue

        x, y = center(target.attrib["bounds"])
        label = (
            target.attrib.get("text")
            or target.attrib.get("content-desc")
            or target.attrib.get("resource-id")
        )
        print(f"Chrome first-run action: {label!r} at ({x}, {y})")
        adb("shell", "input", "tap", str(x), str(y))
        time.sleep(2)

    raise RuntimeError(
        "Chrome first-run gate did not clear before timeout; "
        f"activity={last_activity!r}; visible={last_visible[-80:]!r}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
