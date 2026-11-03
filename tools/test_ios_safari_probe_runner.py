"""Regression checks for fail-closed, event-driven iOS Safari evidence."""
import json
import tempfile
import unittest
from pathlib import Path

from tools.ios_safari_probe_runner import validated_safari_evidence


class SafariEvidenceTests(unittest.TestCase):
    def test_only_completed_real_safari_evidence_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safari.json"
            self.assertFalse(validated_safari_evidence(path))
            good = {
                "schema": "ucr.mobile-browser-compatibility.v1",
                "browser_requested": "ios-safari",
                "evidence_kind": "real-ios-simulator-safari-self-probe",
                "passed": True,
                "probe": {
                    "browser_requested": "ios-safari",
                    "passed": True,
                    "failures": [],
                    "checks": {"browserIdentity": True},
                    "endpoint_wasm_execution": {"ok": True},
                    "endpoint_state_persistence": {"ok": True},
                },
            }
            path.write_text(json.dumps(good))
            self.assertTrue(validated_safari_evidence(path))
            for edit in (
                {"browser_requested": "android-chrome"},
                {"passed": False},
                {"evidence_kind": "desktop-user-agent-emulation"},
                {"probe": {**good["probe"], "failures": ["wasm"]}},
                {"probe": {**good["probe"], "endpoint_wasm_execution": {"ok": False}}},
            ):
                path.write_text(json.dumps({**good, **edit}))
                self.assertFalse(validated_safari_evidence(path))
            path.write_text("{incomplete")
            self.assertFalse(validated_safari_evidence(path))


if __name__ == "__main__":
    unittest.main()
