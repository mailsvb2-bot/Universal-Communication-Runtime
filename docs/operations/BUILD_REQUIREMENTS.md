# Build requirements

| Component | Version / note |
|---|---|
| Rust | `rust-toolchain.toml` (1.97.1), `rust-version = 1.97` |
| C/C++ toolchain | C++17 compiler (MSVC 2022 on Windows, gcc/clang with glibc >= 2.34 on Linux), CMake >= 3.20 and Ninja for bundled native crates |
| OpenSSL | development headers + libs. Linux: `OPENSSL_DIR`/`OPENSSL_LIB_DIR`/`OPENSSL_INCLUDE_DIR`. Windows: `-OpenSslRoot` parameter or `UCR_OPENSSL_ROOT` (default `C:\UCR-OpenSSL`) |
| Node.js | >= 22.6 (contract tests use `--experimental-strip-types`; Node 20 cannot run them) |
| Python | >= 3.10 for `tools/` and `sdk/conformance/validate.py` |
| Browsers (manual/CI probe) | Chromium-based, Firefox ESR, Safari 16.4+; Windows 10 1607 supported via Edge Chromium/Firefox |

## Test scope (honest note)

Most realtime tests use in-process mocks (mock `VideoEncoder`, mock
`RTCPeerConnection`, in-memory SFU sinks). They prove contracts and state
machines, **not** real codec, NAT/TURN or browser behaviour. Real-browser
coverage is limited to `tools/browser_compatibility_probe.py`, which reports
`mediaStreamTrackProcessor`, `videoEncoder`, `audioEncoder` and
`rtcRtpScriptTransform` as informational capabilities.
