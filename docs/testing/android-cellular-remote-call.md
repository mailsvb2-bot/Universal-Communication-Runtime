# Android over cellular: remote-first-party test boundary

The working `start-local-first-party-https.ps1` uses `https://localhost:8443`, `127.0.0.1` bindings, and a localhost-only TLS certificate. It **cannot** provide an Android handset on a different ISP with a working address. Do not copy its localhost URL or forward ports from it.

Run the conservative check from the repository directory:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\windows\start-remote-device-test.ps1"
```

This prints specific blockers and exits nonzero, leaving the existing successful local test untouched. Even a public HTTPS origin and a TURN relay do not establish secure device admission or a working ICE candidate pair; the probe still requires a genuine external test. This is **not yet** the promised single-command public session launcher.

Production-grade remote mode must add: authenticated/restricted public ingress to only the first-party UI and intended APIs, externally valid TLS/Origin, issuer-bound accepted-Call Join, a publicly reachable ICE media candidate or authenticated TURN relaying configured on the actual media implementation, and handset-side verification of A/V/E2EE over mobile data. A generic HTTPS quick tunnel does not relay arbitrary WebRTC UDP and is **not** sufficient. Do not publish the self-service BFF or the operator gRPC endpoint over an unauthenticated quick tunnel.

Acceptance: start one command on Windows, get a time-limited HTTPS address, Android Chrome joins with independently authenticated Device over cellular, maintain >30 minutes bidirectional audio/video across renewal, prove E2EE and proper capture teardown, emit two redacted diagnostics. Until demonstrated, fail closed rather than claiming production-ready remote calling.
