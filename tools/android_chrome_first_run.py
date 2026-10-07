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
    remote = "/sdcard/ucr-chrome-first-run.xml"
    adb("shell", "uiautomator", "dump", remote, timeout=20)
    xml = adb("exec-out", "cat", remote, timeout=15)
    return ET.fromstring(xml)


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
    while time.monotonic() < deadline:
        last_activity = current_activity()
        if not any(marker in last_activity for marker in FIRST_RUN_MARKERS):
            print(f"Chrome first-run gate cleared: {last_activity}")
            return 0

        root = ui_tree()
        target = choose_target(root)
        if target is None:
            visible = [
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
            raise RuntimeError(
                "Chrome first-run screen has no recognized safe action: "
                + repr(visible[-80:])
            )

        x, y = center(target.attrib["bounds"])
        label = (
            target.attrib.get("text")
            or target.attrib.get("content-desc")
            or target.attrib.get("resource-id")
        )
        print(f"Chrome first-run action: {label!r} at ({x}, {y})")
        adb("shell", "input", "tap", str(x), str(y))
        time.sleep(2)

    raise RuntimeError(f"Chrome first-run gate did not clear: {last_activity}")


if __name__ == "__main__":
    raise SystemExit(main())
