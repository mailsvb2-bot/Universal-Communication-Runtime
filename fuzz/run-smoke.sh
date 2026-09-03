#!/usr/bin/env bash
set -euo pipefail

FUZZ_TOOLCHAIN="${UCR_FUZZ_TOOLCHAIN:-nightly-2026-09-02}"
TOTAL_SECONDS="${UCR_FUZZ_SECONDS:-10}"
PER_INPUT_SECONDS=2
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

run_target() {
    local target="$1"
    local max_len="$2"
    local rss_mb="$3"
    local corpus="${TMP_ROOT}/${target}"

    mkdir -p "${corpus}"
    cp -a "fuzz/corpus/${target}/." "${corpus}/"
    cargo +"${FUZZ_TOOLCHAIN}" fuzz run "${target}" "${corpus}" -- \
        -max_total_time="${TOTAL_SECONDS}" \
        -timeout="${PER_INPUT_SECONDS}" \
        -rss_limit_mb="${rss_mb}" \
        -max_len="${max_len}"
}

run_target framing_parser 65536 512
run_target opaque_id_wire 512 512
run_target message_envelope 4096 768
run_target crypto_wrapper 256 512
