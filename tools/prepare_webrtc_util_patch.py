#!/usr/bin/env python3
"""Create the single verified webrtc-util source patch used by both Cargo roots."""
import hashlib
import io
from pathlib import Path
import re
import tarfile
import tomllib
from urllib.request import urlopen

root = Path(__file__).resolve().parents[1]
version = "0.17.2"
crate = "webrtc-util"
lock = tomllib.loads((root / "Cargo.lock").read_text())
matches = [p for p in lock["package"] if p["name"] == crate and p["version"] == version]
assert len(matches) == 1 and matches[0].get("checksum"), "published crate not pinned"
checksum = matches[0]["checksum"]
with urlopen(f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate", timeout=60) as stream:
    content = stream.read()
assert hashlib.sha256(content).hexdigest() == checksum, "upstream source checksum mismatch"
target = root / "third_party" / "webrtc-util-v0172"
assert not target.exists(), "will not overwrite existing local patch"
target.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
    for member in tar:
        parts = Path(member.name).parts
        assert len(parts) > 1 and parts[0] == f"{crate}-{version}"
        dest = target.joinpath(*parts[1:])
        if member.isdir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            assert member.isfile(), "unexpected symlink or archive type"
            dest.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src:
                dest.write_bytes(src.read())

path = target / "Cargo.toml"
original = path.read_text()
parsed = tomllib.loads(original)
nix_targets = [name for name, data in parsed.get("target", {}).items()
               if "nix" in data.get("dependencies", {})]
assert len(nix_targets) == 1, f"unexpected nix dependency targets: {nix_targets}"
nix = parsed["target"][nix_targets[0]]["dependencies"]["nix"]
assert str(nix["version"]).startswith("0.26") and "features" not in nix
assert nix.get("default-features", True), "unexpected existing nix feature policy"
head = re.search(r"(?m)^\[target\.[^\n]+\.dependencies\.nix\]\s*$", original)
assert head, "nix manifest table absent"
next_header = re.search(r"(?m)^\[", original[head.end():])
end = head.end() + next_header.start() if next_header else len(original)
# Preserve the exact old nix default feature set except aio, which pulls pin-utils.
features = ("acct dir env event feature fs hostname inotify ioctl kmod mman mount "
            "mqueue net personality poll process pthread ptrace quota reboot resource "
            "sched signal socket term time ucontext uio user zerocopy").split()
replacement = original[head.end():end].rstrip() + "\ndefault-features = false\nfeatures = [\n"
replacement += "".join(f'    "{f}",\n' for f in features) + "]\n\n"
updated = original[:head.end()] + "\n" + replacement + original[end:]
assert "aio" not in tomllib.loads(updated)["target"][nix_targets[0]]["dependencies"]["nix"]["features"]
path.write_text(updated)
for file, rel in [("Cargo.toml", "third_party/webrtc-util-v0172"),
                  ("crates/ucr-chaos-lab/Cargo.toml", "../../third_party/webrtc-util-v0172")]:
    dest = root / file
    text = dest.read_text()
    previous = tomllib.loads(text).get("patch", {}).get("crates-io", {}).get(crate)
    assert previous is None, f"unexpected duplicate WebRTC patch in {file}"
    stanza = f'{crate} = {{ path = "{rel}" }}\n'
    text = text.replace("[patch.crates-io]", "[patch.crates-io]\n" + stanza, 1)
    assert tomllib.loads(text)["patch"]["crates-io"][crate]["path"] == rel
    dest.write_text(text)
(target / "UCR_PATCH.md").write_text(
    f"Source: published webrtc-util {version}, SHA256 {checksum}.\n"
    "The only change to upstream crate files is Cargo.toml: nix default features "
    "are disabled, all previous default features except aio are explicit. "
    "This removes the unmaintained pin-utils transitively without changing "
    "Rust media/crypto implementation. The root and excluded chaos-lab share "
    "one patched crate. Revisit when upstream is maintained.\n"
)
print(f"Verified and patched {crate} {version}: {checksum}")
