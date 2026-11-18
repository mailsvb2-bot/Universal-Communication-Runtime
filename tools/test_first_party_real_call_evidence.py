#!/usr/bin/env python3
"""Only measured two-device user journeys can pass real-call quality."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main

FILE = Path(__file__).with_name("check_first_party_real_call_evidence.py")
spec = importlib.util.spec_from_file_location("ucr_real_call_evidence", FILE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def fixture(elapsed=6, stall=75, audio=True):
    events = [
        {"time": "2026-11-18T09:00:00.000Z", "safe": "Join requested"},
        {"time": "2026-11-18T09:00:02.000Z", "safe": "MLS admission ready"},
        {"time": f"2026-11-18T09:00:{elapsed:02d}.000Z",
         "safe": "Endpoint E2EE transport active"},
    ]
    return {
        "schema": "ucr-local-diagnostics-v1", "page": "conference",
        "authorization": {"sessionActive": True, "mediaActive": True},
        "crypto": {"adapterReady": True, "transportOpen": True},
        "ice": {"connectionState": "connected"},
        "localMediaPolicy": {"acceptedCallMedia": "video"},
        "videoFrames": {"rendered": 12, "renderStallMs": stall},
        "audioFrames": {"received": 10 if audio else 0,
                        "scheduled": 9 if audio else 0},
        "mediaFailure": {"category": None, "stopped": False},
        "recentEvents": events,
    }


class RealCallEvidenceTest(TestCase):
    def test_proven_call_with_measured_end_to_end_latency(self):
        r = gate.quality_gate(fixture(), fixture(), 130, 220)
        self.assertEqual(r["quality_gate"], "pass")

    def test_missing_real_audio_video_lag_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "independent synchronized"):
            gate.quality_gate(fixture(), fixture(), None, None)

    def test_long_initial_connection_is_blocked(self):
        with self.assertRaisesRegex(gate.EvidenceError, "Join.to.E2EE"):
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
