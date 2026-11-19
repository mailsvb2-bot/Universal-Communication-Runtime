#!/usr/bin/env python3
"""Evidence gate for a REAL two-device PetrelLink media call.

Unlike repository CI/healthz/SFU benchmarks, accepts only two independent,
local browser diagnostic exports plus explicitly measured end-to-end A/V lag.
No synthetic defaults. Missing or invalid evidence blocks production-quality
claims; it does not stop a running call or send private data anywhere.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

SCHEMA = "ucr-local-diagnostics-v1"
MAX_JOIN_TO_E2EE_SECONDS = 10.0
# This is a real measured user-visible boundary, not merely a transport signal.
MAX_JOIN_TO_FIRST_VIDEO_SECONDS = 8.0
MAX_E2EE_TO_FIRST_VIDEO_SECONDS = 2.0
MAX_VIDEO_STALL_MS = 500
MIN_SUSTAINED_VIDEO_MS = 5000
MIN_SUSTAINED_VIDEO_FPS = 8
MAX_ONE_WAY_AUDIO_MS = 300
MAX_GLASS_TO_GLASS_VIDEO_MS = 500


class EvidenceError(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise EvidenceError(why)


def _timestamp(value: object) -> datetime:
    require(isinstance(value, str), "missing event timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid event timestamp") from exc
    require(result.tzinfo is not None, "event timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def _events(report: dict) -> dict[str, datetime]:
    events = report.get("recentEvents")
    require(isinstance(events, list), "recent event history missing")
    found: dict[str, datetime] = {}
    for item in events:
        if isinstance(item, dict) and isinstance(item.get("safe"), str):
            safe = item["safe"]
            if safe in ("Join requested", "MLS admission ready",
                        "WebRTC server offer received",
                        "Local capture ready for WebRTC",
                        "WebRTC remote SDP accepted",
                        "WebRTC ICE connected",
                        "Endpoint E2EE transport active",
                        "First authenticated video rendered"):
                stamp = _timestamp(item.get("time"))
                if safe == "Join requested":
                    # Use last Join to avoid accidental conflation of an earlier call.
                    found = {"Join requested": stamp}
                elif "Join requested" in found and safe not in found:
                    found[safe] = stamp
    return found


def _active_snapshot(report: dict, label: str) -> dict:
    # The Save diagnostics action may run just after Leave. The frozen
    # preDisconnect snapshot is the actual authenticated in-call measurement;
    # the post-Leave root intentionally has revoked media and reset counters.
    auth = report.get("authorization") or {}
    if auth.get("sessionActive") is True:
        return report
    earlier = report.get("preDisconnect")
    require(isinstance(earlier, dict), f"{label}: no active media snapshot")
    require(earlier.get("schema") == SCHEMA and earlier.get("page") == "conference",
            f"{label}: malformed pre-disconnect snapshot")
    age = (_timestamp(report.get("capturedAt")) -
           _timestamp(earlier.get("capturedAt"))).total_seconds()
    require(0 <= age <= 15, f"{label}: pre-disconnect snapshot stale")
    return earlier


def inspect(report: dict, label: str) -> dict[str, object]:
    report = _active_snapshot(report, label)
    require(report.get("schema") == SCHEMA and report.get("page") == "conference",
            f"{label}: not a conference diagnostics export")
    auth = report.get("authorization") or {}
    crypto = report.get("crypto") or {}
    require(auth.get("sessionActive") is True and
            auth.get("mediaActive") is True, f"{label}: media not active")
    require(crypto.get("adapterReady") is True and
            crypto.get("transportOpen") is True, f"{label}: authenticated E2EE not open")
    require((report.get("ice") or {}).get("connectionState") == "connected",
            f"{label}: WebRTC not connected")
    media_policy = report.get("localMediaPolicy") or {}
    require(media_policy.get("acceptedCallMedia") == "video",
            f"{label}: not a verified video Call")
    video = report.get("videoFrames") or {}
    audio = report.get("audioFrames") or {}
    require(isinstance(video.get("rendered"), int) and video["rendered"] > 0,
            f"{label}: no remote video rendered")
    # First-paint success is not continuous video. Require a foreground
    # observation spanning at least five seconds and meaningful rendered FPS.
    # Using two timestamps from the SAME endpoint avoids unsynchronized
    # device clocks or fabricated glass-to-glass estimates.
    first_rendered = video.get("firstRenderedAt")
    last_rendered = video.get("lastRenderedAt")
    require(isinstance(first_rendered, int) and isinstance(last_rendered, int) and
            first_rendered > 0 and last_rendered >= first_rendered,
            f"{label}: video continuity timestamps missing")
    observed_ms = last_rendered - first_rendered
    require(observed_ms >= MIN_SUSTAINED_VIDEO_MS,
            f"{label}: insufficient sustained video observation")
    fps = (video["rendered"] - 1) * 1000 / observed_ms if observed_ms else 0
    require(fps >= MIN_SUSTAINED_VIDEO_FPS,
            f"{label}: rendered video {fps:.1f}fps below {MIN_SUSTAINED_VIDEO_FPS}fps")
    visibility = report.get("videoVisibility") or {}
    require(visibility.get("hiddenTotalMs") == 0,
            f"{label}: video observation includes background/hidden time")
    captured_ms = int(_timestamp(report.get("capturedAt")).timestamp() * 1000)
    require(0 <= captured_ms - last_rendered <= MAX_VIDEO_STALL_MS,
            f"{label}: final remote video frame stale")
    require(isinstance(audio.get("received"), int) and audio["received"] > 0,
            f"{label}: no remote audio received")
    require(isinstance(audio.get("scheduled"), int) and audio["scheduled"] > 0,
            f"{label}: no remote audio scheduled for playback")
    stall = video.get("renderStallMs")
    require(isinstance(stall, (float, int)) and 0 <= stall <= MAX_VIDEO_STALL_MS,
            f"{label}: video stall {stall!r} ms exceeds {MAX_VIDEO_STALL_MS}")
    failure = report.get("mediaFailure") or {}
    require(failure.get("stopped") is not True,
            f"{label}: protected media was fail-closed")
    require(not failure.get("category"),
            f"{label}: media failure reported: {failure.get('category')}")
    events = _events(report)
    require("Join requested" in events and "Endpoint E2EE transport active" in events,
            f"{label}: Join→E2EE timing evidence missing")
    start = events["Join requested"]
    end = events["Endpoint E2EE transport active"]
    first_video = events.get("First authenticated video rendered")
    require(first_video is not None,
            f"{label}: first authenticated video render timing evidence missing")
    elapsed = (end - start).total_seconds()
    first_video_elapsed = (first_video - start).total_seconds()
    e2ee_to_video_elapsed = (first_video - end).total_seconds()
    require(0 <= elapsed <= MAX_JOIN_TO_E2EE_SECONDS,
            f"{label}: Join→E2EE {elapsed:.2f}s exceeds {MAX_JOIN_TO_E2EE_SECONDS:.1f}s")
    require(0 <= first_video_elapsed <= MAX_JOIN_TO_FIRST_VIDEO_SECONDS,
            f"{label}: Join→first video {first_video_elapsed:.2f}s exceeds "
            f"{MAX_JOIN_TO_FIRST_VIDEO_SECONDS:.1f}s")
    # On a fast path the authorized adapter may render a frame while its
    # asynchronous persisted-state/diagnostic E2EE_ACTIVE marker is still
    # completing. A negative E2EE→video gap is not a slow-first-video failure;
    # Join→video remains mandatory and monotonic.
    require(e2ee_to_video_elapsed <= MAX_E2EE_TO_FIRST_VIDEO_SECONDS,
            f"{label}: E2EE→first video {e2ee_to_video_elapsed:.2f}s exceeds "
            f"{MAX_E2EE_TO_FIRST_VIDEO_SECONDS:.1f}s")
    # All reached phases are causally after Join. Timestamping order is
    # diagnostic only: ICE can finish before E2EE adapter is fully activated.
    for stage, stamp in events.items():
        if stage != "Join requested":
            require(stamp >= start, f"{label}: event order reversed at {stage}")
    return {"join_to_e2ee_seconds": round(elapsed, 3),
            "join_to_first_video_seconds": round(first_video_elapsed, 3),
            "e2ee_to_first_video_seconds": round(e2ee_to_video_elapsed, 3),
            "video_render_stall_ms": stall,
            "rendered_frames": video["rendered"],
            "sustained_video_fps": round(fps, 2),
            "sustained_observation_ms": observed_ms,
            "received_audio_frames": audio["received"],
            "observed_phases": sorted(events)}


def quality_gate(
    pc: dict, phone: dict, audio_one_way_ms: float | None,
    video_glass_to_glass_ms: float | None,
) -> dict[str, object]:
    # Do not turn buffer occupancy or packet counts into imaginary end-to-end
    # acoustic/visual latency measurements.
    require(audio_one_way_ms is not None and video_glass_to_glass_ms is not None,
            "independent synchronized audio and video latency measurements are required")
    require(0 <= audio_one_way_ms <= MAX_ONE_WAY_AUDIO_MS,
            f"one-way audio {audio_one_way_ms}ms exceeds {MAX_ONE_WAY_AUDIO_MS}ms")
    require(0 <= video_glass_to_glass_ms <= MAX_GLASS_TO_GLASS_VIDEO_MS,
            f"glass-to-glass video {video_glass_to_glass_ms}ms exceeds {MAX_GLASS_TO_GLASS_VIDEO_MS}ms")
    return {"schema": "ucr.first-party-real-call-evidence.v1",
            "device_a": inspect(pc, "computer"),
            "device_b": inspect(phone, "phone"),
            "audio_one_way_ms": audio_one_way_ms,
            "video_glass_to_glass_ms": video_glass_to_glass_ms,
            "quality_gate": "pass",
            "limitations": "one measured call; no percentile, background, packet-loss or mobile-network switching proof"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pc", required=True, type=Path)
    parser.add_argument("--phone", required=True, type=Path)
    parser.add_argument("--audio-one-way-ms", type=float)
    parser.add_argument("--video-glass-to-glass-ms", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    for value in (args.audio_one_way_ms, args.video_glass_to_glass_ms):
        if value is not None:
            require(value == value and value not in (float("inf"), float("-inf")),
                    "non-finite measured latency")
    evidence = quality_gate(
        json.loads(args.pc.read_text()), json.loads(args.phone.read_text()),
        args.audio_one_way_ms, args.video_glass_to_glass_ms,
    )
    if args.output:
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"BLOCKED REAL CALL QUALITY: {exc}", file=sys.stderr)
        sys.exit(1)
