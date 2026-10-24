#!/usr/bin/env bash
# Compatibility-only migration exercise. Does not modify tracked checkout.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
git -C "$repo" archive HEAD | tar -x -C "$tmp"
cd "$tmp"
echo "=== Baseline dependency path ==="
cargo tree --locked --workspace -i crypto-bigint@0.5.5 || true
echo "=== Try RustSec-fixed bigint against current parent constraints ==="
if cargo update -p crypto-bigint@0.5.5 --precise 0.7.6; then
    echo "Direct update unexpectedly succeeded; validate all six locks before accepting."
else
    echo "Direct update blocked as expected; upstream elliptic-curve/p256/p384 migration required."
fi
echo "=== Try new RustCrypto curve chain in a scratch probe crate ==="
mkdir -p migration-probe/src
cat > migration-probe/Cargo.toml <<'EOF'
[package]
name = "ucr-crypto-migration-probe"
version = "0.0.1"
edition = "2024"
[workspace]
[dependencies]
crypto-bigint = "=0.7.6"
elliptic-curve = "=0.14.1"
p256 = "=0.14.0"
p384 = "=0.14.0"
EOF
echo 'fn main() {}' > migration-probe/src/main.rs
(cd migration-probe && cargo check)
echo "=== Current workspace remains unchanged; no security-audit bypass ==="
