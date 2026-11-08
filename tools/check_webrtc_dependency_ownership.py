#!/usr/bin/env python3
"""Guard the single canonical WebRTC dependency remediation in all Cargo roots."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "third_party/webrtc-util-v0172"
assert VENDOR.is_dir(), "canonical upstream-pinned WebRTC util patch missing"

for manifest, expected in [
    ("Cargo.toml", "third_party/webrtc-util-v0172"),
    ("crates/ucr-chaos-lab/Cargo.toml", "../../third_party/webrtc-util-v0172"),
]:
    data = tomllib.loads((ROOT / manifest).read_text())
    patch = data["patch"]["crates-io"]["webrtc-util"]
    assert patch == {"path": expected}, f"unexpected WebRTC utility patch in {manifest}: {patch}"

source = tomllib.loads((VENDOR / "Cargo.toml").read_text())
dep = [val["dependencies"]["nix"] for val in source.get("target", {}).values()
       if "nix" in val.get("dependencies", {})]
assert len(dep) == 1, "unexpected nix owners in patched utility"
assert dep[0]["default-features"] is False, "unsafe nix default feature expansion"
assert "aio" not in dep[0]["features"], "aio reintroduces pin-utils"
assert "net" in dep[0]["features"] and "socket" in dep[0]["features"], "network functions lost"
for path in ("Cargo.lock", "crates/ucr-chaos-lab/Cargo.lock"):
    lock = tomllib.loads((ROOT / path).read_text())
    pkgs = lock["package"]
    assert not any(p["name"] == "pin-utils" for p in pkgs), f"RUSTSEC-2026-0441 reintroduced: {path}"
    patch = [p for p in pkgs if p["name"] == "webrtc-util"]
    assert len(patch) == 1 and patch[0]["version"] == "0.17.2", f"unexpected util version: {path}"
    assert "source" not in patch[0], f"vendored WebRTC util not selected: {path}"
    assert any(d.split(" ")[0] == "nix" for d in patch[0]["dependencies"]), f"nix owner absent: {path}"
    print(f"PASS: {path}: one patched webrtc-util, no unmaintained pin-utils")
