#!/usr/bin/env bash
# Build or verify the endpoint-owned browser E2EE media assets for the exact
# checked-out UCR source revision. No credentials or signer secrets are bundled.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WASM_BINDGEN="${UCR_WASM_BINDGEN_BIN:-wasm-bindgen}"
ESBUILD="${UCR_ESBUILD_BIN:-esbuild}"
WASM_DIR="$ROOT/crates/ucr-realtime-web/static/endpoint-wasm"
MEDIA_DIR="$ROOT/crates/ucr-realtime-web/static/endpoint-media"
WASM="$WASM_DIR/ucr_endpoint_wasm_bg.wasm"
WASM_JS="$WASM_DIR/ucr_endpoint_wasm.js"
INSTALLER="$MEDIA_DIR/reference_browser_media_installer.js"

verify() {
  python3 - "$WASM" "$WASM_JS" "$INSTALLER" <<'PY'
from pathlib import Path
import sys
wasm, wasm_js, installer = [Path(arg) for arg in sys.argv[1:]]
for asset in (wasm, wasm_js, installer):
    if not asset.is_file() or asset.is_symlink() or asset.stat().st_size == 0:
        raise SystemExit(f"UCR_BROWSER_MEDIA_MISSING: {asset.name}")
if wasm.read_bytes()[:4] != b"\\x00asm":
    raise SystemExit("UCR_BROWSER_WASM_INVALID")
if b"reference_browser" not in installer.read_bytes().lower():
    raise SystemExit("UCR_BROWSER_MEDIA_INSTALLER_INVALID")
print("UCR_BROWSER_MEDIA_READY")
PY
}

case "${1:-build}" in
  --check)
    verify
    ;;
  build)
    command -v cargo >/dev/null
    command -v python3 >/dev/null
    command -v "$WASM_BINDGEN" >/dev/null
    command -v "$ESBUILD" >/dev/null
    if [[ "$("$WASM_BINDGEN" --version)" != "wasm-bindgen 0.2.128" ]]; then
      echo "UCR_BROWSER_MEDIA_ERROR: wasm-bindgen 0.2.128 required" >&2
      exit 2
    fi
    if [[ "$("$ESBUILD" --version)" != "0.25.5" ]]; then
      echo "UCR_BROWSER_MEDIA_ERROR: esbuild 0.25.5 required" >&2
      exit 2
    fi
    for dir in "$WASM_DIR" "$MEDIA_DIR"; do
      if [[ -L "$dir" ]]; then
        echo "UCR_BROWSER_MEDIA_ERROR: symlink asset directory rejected" >&2
        exit 2
      fi
      mkdir -p "$dir"
    done
    cargo build --locked --release \
      --manifest-path crates/ucr-endpoint-wasm/Cargo.toml \
      --target wasm32-unknown-unknown
    "$WASM_BINDGEN" "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/ucr_endpoint_wasm.wasm" \
      --target web --out-dir "$WASM_DIR" --out-name ucr_endpoint_wasm
    "$ESBUILD" sdk/typescript/src/reference_browser_media_installer.ts \
      --bundle --platform=browser --format=esm --target=es2022 \
      --outfile="$INSTALLER"
    verify
    sha256sum "$WASM" "$WASM_JS" "$INSTALLER"
    ;;
  *)
    echo "Usage: $0 [build|--check]" >&2
    exit 2
    ;;
esac
