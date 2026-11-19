#!/usr/bin/env python3
"""Only measured two-device user journeys can pass real-call quality."""
import importlib.util
from pathlib import Path
from datetime import datetime, timedelta, timezone
from copy import deepcopy
from unittest import TestCase, main

FILE = Path(__file__).with_name("check_first_party_real_call_evidence.py")
spec = importlib.util.spec_from_file_location("ucr_real_call_evidence", FILE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def fixture(elapsed=6, stall=75, audio=True, first_video_delay=1):
    events = [
        {"time": "2026-11-18T09:00:00.000Z", "safe": "Join requested"},
        {"time": "2026-11-18T09:00:02.000Z", "safe": "MLS admission ready"},
        {"time": f"2026-11-18T09:00:{elapsed:02d}.000Z",
         "safe": "Endpoint E2EE transport active"},
        {"time": f"2026-11-18T09:00:{elapsed + first_video_delay:02d}.000Z",
         "safe": "First authenticated video rendered"},
    ]
    first = datetime(2026, 11, 18, 9, 0, elapsed + first_video_delay,
                     tzinfo=timezone.utc)
    # The fixture asserts seven seconds of uninterrupted foreground rendering
    # and captures the report 75 ms after the latest real frame.
    first_ms = int(first.timestamp() * 1000)
    last_ms = first_ms + 7000
    return {
        "schema": "ucr-local-diagnostics-v1", "page": "conference",
        "capturedAt": (first + timedelta(milliseconds=7075)).isoformat(),
        "authorization": {"sessionActive": True, "mediaActive": True},
        "crypto": {"adapterReady": True, "transportOpen": True},
        "ice": {"connectionState": "connected"},
        "localMediaPolicy": {"acceptedCallMedia": "video"},
        "videoFrames": {"rendered": 120, "renderStallMs": stall,
                        "firstRenderedAt": first_ms, "lastRenderedAt": last_ms},
        "videoVisibility": {"hiddenTotalMs": 0},
        "audioFrames": {"received": 10 if audio else 0,
                        "scheduled": 9 if audio else 0},
        "mediaFailure": {"category": None, "stopped": False},
        "recentEvents": events,
    }


class RealCallEvidenceTest(TestCase):
    def test_proven_call_with_measured_end_to_end_latency(self):
        r = gate.quality_gate(fixture(), fixture(), 130, 220)
        self.assertEqual(r["quality_gate"], "pass")

    def test_only_two_video_frames_never_prove_a_real_video_call(self):
        a = fixture()
        a["videoFrames"]["rendered"] = 2
        with self.assertRaisesRegex(gate.EvidenceError, "rendered video"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_thirty_frames_over_thirty_seconds_are_not_continuous_video(self):
        a = fixture()
        a["videoFrames"]["rendered"] = 30
        a["videoFrames"]["lastRenderedAt"] = a["videoFrames"]["firstRenderedAt"] + 30000
        a["capturedAt"] = datetime.fromtimestamp(
            (a["videoFrames"]["lastRenderedAt"] + 75) / 1000,
            timezone.utc).isoformat()
        with self.assertRaisesRegex(gate.EvidenceError, "rendered video"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_short_one_frame_success_is_not_enough(self):
        a = fixture()
        a["videoFrames"]["lastRenderedAt"] = a["videoFrames"]["firstRenderedAt"] + 1000
        with self.assertRaisesRegex(gate.EvidenceError, "insufficient sustained"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_hidden_tab_cannot_supply_sustained_video_proof(self):
        a = fixture()
        a["videoVisibility"]["hiddenTotalMs"] = 39000
        with self.assertRaisesRegex(gate.EvidenceError, "hidden"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_pre_disconnect_snapshot_must_be_recent_and_authenticated(self):
        original = fixture()
        post = {"authorization": {"sessionActive": False},
                "capturedAt": (datetime.fromisoformat(original["capturedAt"]) +
                               timedelta(seconds=3)).isoformat(),
                "preDisconnect": deepcopy(original)}
        self.assertEqual(gate.quality_gate(post, fixture(), 90, 120)["quality_gate"], "pass")
        post["capturedAt"] = (datetime.fromisoformat(original["capturedAt"]) +
                              timedelta(seconds=30)).isoformat()
        with self.assertRaisesRegex(gate.EvidenceError, "snapshot stale"):
            gate.quality_gate(post, fixture(), 90, 120)

    def test_missing_first_render_evidence_is_blocked(self):
        a = fixture()
        a["recentEvents"] = [e for e in a["recentEvents"]
                             if e["safe"] != "First authenticated video rendered"]
        with self.assertRaisesRegex(gate.EvidenceError, "first authenticated video render"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_slow_first_video_is_blocked_even_if_e2ee_is_fast(self):
        with self.assertRaisesRegex(gate.EvidenceError, "first video"):
            gate.quality_gate(fixture(first_video_delay=4), fixture(), 90, 120)

    def test_slow_join_to_first_frame_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "Join→first video"):
            gate.quality_gate(fixture(elapsed=8), fixture(), 90, 120)

    def test_authorized_video_before_async_e2ee_status_marker_is_valid(self):
        a = fixture(elapsed=6, first_video_delay=-1)
        r = gate.quality_gate(a, fixture(), 90, 120)
        self.assertEqual(r["device_a"]["e2ee_to_first_video_seconds"], -1.0)

    def test_missing_real_audio_video_lag_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "independent synchronized"):
            gate.quality_gate(fixture(), fixture(), None, None)

    def test_long_initial_connection_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "Join→(?:first video|E2EE)"):
            gate.quality_gate(fixture(26), fixture(), 90, 120)

    def test_audio_without_playback_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "remote audio"):
            gate.quality_gate(fixture(audio=False), fixture(), 90, 120)

    def test_visible_video_stall_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "video stall"):
            gate.quality_gate(fixture(stall=2800), fixture(), 90, 120)

    def test_mls_and_ice_connected_do_not_override_media_failure(self):
        a = fixture()
        a["mediaFailure"]["category"] = "MEDIA_CODEC_PRODUCER_FAILURE"
        with self.assertRaisesRegex(gate.EvidenceError, "media failure"):
            gate.quality_gate(a, fixture(), 90, 120)

    def test_one_way_latency_not_synthesized_from_playout_queue(self):
        with self.assertRaisesRegex(gate.EvidenceError, "one-way audio"):
            gate.quality_gate(fixture(), fixture(), 3000, 120)

    def test_missing_timing_is_blocked(self):
        a = fixture()
        a["recentEvents"] = []
        with self.assertRaisesRegex(gate.EvidenceError, "timing evidence missing"):
            gate.quality_gate(a, fixture(), 90, 120)


if __name__ == "__main__":
    main()
