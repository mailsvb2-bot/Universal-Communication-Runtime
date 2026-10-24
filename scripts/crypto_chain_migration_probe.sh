#!/usr/bin/env bash
# Non-mutating compatibility probe: all changes happen inside a disposable archive.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/repo/scripts"
git -C "$root" archive HEAD | tar -x -C "$work/repo"
cp -- "$script_dir/audit_crypto_chain.py" "$work/repo/scripts/audit_crypto_chain.py"
cd "$work/repo"
python3 scripts/audit_crypto_chain.py --allow-vulnerable --report "$work/baseline.json" >/dev/null
printf '=== Reverse dependencies ===\n'
cargo tree --locked -i crypto-bigint@0.5.5 || true
printf '=== Resolver compatibility probe (not a full fix) ===\n'
if ! cargo update -p crypto-bigint@0.5.5 --precise 0.7.6; then
  echo 'BLOCKED: current parents cannot resolve patched crypto-bigint directly.' >&2
  echo 'Migrate the parents in a coordinated branch; do not bypass the security audit.' >&2
  exit 12
fi
for lock in Cargo.lock fuzz/Cargo.lock crates/ucr-sdk/Cargo.lock crates/ucr-reference-messenger/Cargo.lock crates/ucr-ai-actor/Cargo.lock crates/ucr-chaos-lab/Cargo.lock; do
  (cd "$(dirname "$lock")" && cargo update)
done
python3 scripts/audit_crypto_chain.py
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
for lock in Cargo.lock fuzz/Cargo.lock crates/ucr-sdk/Cargo.lock crates/ucr-reference-messenger/Cargo.lock crates/ucr-ai-actor/Cargo.lock crates/ucr-chaos-lab/Cargo.lock; do
  cargo audit --file "$lock" --deny warnings
done
echo 'Probe passed in temporary tree; no working files changed. Verify actual E2E before release.'
