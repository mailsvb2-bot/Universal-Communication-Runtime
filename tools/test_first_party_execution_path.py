#!/usr/bin/env python3
"""Regression tests: green health checks must not hide stale browser code."""
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

PATH = Path(__file__).with_name("check_first_party_execution_path.py")
SPEC = importlib.util.spec_from_file_location("ucr_execution_gate", PATH)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
SHA = "a" * 40


class ExecutionGateTest(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.static = self.root / gate.STATIC
        self.static.mkdir(parents=True)
        self.bodies = {}
        for route, name in gate.EMBEDDED.items():
            self.bodies[route] = (f"first-party:{route}:{SHA}").encode()
            (self.static / name).write_bytes(self.bodies[route])
        for name in gate.MEDIA:
            body = b"\x00asm\x01\x00\x00\x00" if name.endswith(".wasm") else (
                f"public-asset:{name}:{SHA}".encode()
            )
            self.bodies["/" + name] = body
            target = self.static / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        self.write_manifest()

    def write_manifest(self, source=SHA):
        items = {}
        for name in gate.MEDIA:
            data = (self.static / name).read_bytes()
            items[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (self.static / gate.MANIFEST).write_text(json.dumps({
            "schema": 1, "source_sha": source, "files": items,
        }))

    def test_actual_binary_wasm_magic_passes(self):
        self.assertEqual(len(gate.release_assets(self.root, SHA)), 3)

    def test_literal_backslash_wasm_magic_is_rejected(self):
        (self.static / gate.MEDIA[1]).write_bytes(b"\\x00asm\x01\x00\x00\x00")
        self.write_manifest()
        with self.assertRaisesRegex(gate.ExecutionGateError, "WebAssembly magic"):
            gate.release_assets(self.root, SHA)

    def test_stale_source_sha_fails(self):
        self.write_manifest("b" * 40)
        with self.assertRaisesRegex(gate.ExecutionGateError, "exact source"):
            gate.release_assets(self.root, SHA)

    def test_sdk_bundle_modified_after_manifest_fails(self):
        (self.static / gate.MEDIA[2]).write_bytes(b"stale-sdk")
        with self.assertRaisesRegex(gate.ExecutionGateError, "revision-pinned"):
            gate.release_assets(self.root, SHA)

    def test_live_public_web_matches_all_compiled_sources_and_e2ee_assets(self):
        with patch.object(gate, "fetch_public",
                          side_effect=lambda url: self.bodies[url.split("test.invalid")[1]]):
            gate.live_contract(self.root, "https://test.invalid", SHA)

    def test_green_readyz_cannot_hide_old_web_binary(self):
        wrong = dict(self.bodies)
        wrong["/client.html"] = b"previous embedded release"
        with patch.object(gate, "fetch_public",
                          side_effect=lambda url: wrong[url.split("test.invalid")[1]]):
            with self.assertRaisesRegex(gate.ExecutionGateError, "STALE EMBEDDED WEB CODE"):
                gate.live_contract(self.root, "https://test.invalid", SHA)

    def test_green_readyz_cannot_hide_old_e2ee_sdk_bundle(self):
        wrong = dict(self.bodies)
        wrong["/" + gate.MEDIA[2]] = b"old SDK bundle"
        with patch.object(gate, "fetch_public",
                          side_effect=lambda url: wrong[url.split("test.invalid")[1]]):
            with self.assertRaisesRegex(gate.ExecutionGateError, "STALE E2EE MEDIA BUNDLE"):
                gate.live_contract(self.root, "https://test.invalid", SHA)

    def test_http_and_credentialed_origin_is_rejected(self):
        for origin in ("http://test.invalid", "https://x:y@test.invalid",
                       "https://test.invalid/path"):
            with self.assertRaises(gate.ExecutionGateError):
                gate.public_url(origin, "/client.html")


if __name__ == "__main__":
    main()
