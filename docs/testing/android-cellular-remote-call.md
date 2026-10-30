# Android over cellular: remote-first-party test boundary

The working `start-local-first-party-https.ps1` uses `https://localhost:8443`, `127.0.0.1` bindings, and a localhost-only TLS certificate. It **cannot** provide an Android handset on a different ISP with a working address. Do not copy its localhost URL or forward ports from it.

Run the conservative check from the repository directory:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\windows\start-remote-device-test.ps1"
```

This prints specific blockers and exits nonzero, leaving the existing successful local test untouched. Even a public HTTPS origin and a TURN relay do not establish secure device admission or a working ICE candidate pair; the probe still requires a genuine external test. This is **not yet** the promised single-command public session launcher.

Production-grade remote mode must add: authenticated/restricted public ingress to only the first-party UI and intended APIs, externally valid TLS/Origin, issuer-bound accepted-Call Join, a publicly reachable ICE media candidate or authenticated TURN relaying configured on the actual media implementation, and handset-side verification of A/V/E2EE over mobile data. A generic HTTPS quick tunnel does not relay arbitrary WebRTC UDP and is **not** sufficient. Do not publish the self-service BFF or the operator gRPC endpoint over an unauthenticated quick tunnel.

Acceptance: start one command on Windows, get a time-limited HTTPS address, Android Chrome joins with independently authenticated Device over cellular, maintain >30 minutes bidirectional audio/video across renewal, prove E2EE and proper capture teardown, emit two redacted diagnostics. Until demonstrated, fail closed rather than claiming production-ready remote calling.

## Opt-in public HTTPS edge on the same Windows UCR runtime (PR #330)

The canonical Windows launcher accepts `-PublicOrigin`, `-PublicCertificate`,
`-PublicPrivateKey`, `-PublicEdgeBind`, `-TurnUrl` and `-TurnSecretFile`. It builds the same runtime,
BFF and HTTPS edge. The gRPC, operator, HTTP gateway and first-party BFF
remain bound to loopback; only the TLS edge can bind publicly on TCP 443.
This is **not** a tunnel and **does not** provision DNS, an internet-routable
host, firewall/NAT mapping, public trust, TURN or second Device enrollment.

Invoke only with a publicly trusted DNS certificate and verified network
configuration (example paths/names are placeholders, not a live endpoint):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\windows\start-local-first-party-https.ps1" -PublicOrigin "https://call.example.org" -PublicCertificate "C:\certs\fullchain.pem" -PublicPrivateKey "C:\certs\privkey.pem" -TurnUrl "turns:turn.example.org:5349?transport=tcp" -TurnSecretFile "C:\certs\turn-rest-secret.hex"
```

The launcher validates HTTPS origin, expiry, key/certificate match and
hostname; it never installs a public CA into Windows trust. It checks edge
and bootstrap readiness through HTTPS and explicitly prints
`UCR_PUBLIC_HTTPS_EDGE_STARTED_NOT_A_CALL_PROOF`, not a successful call.
Do not use publicly reachable ingress without independently authenticated
Devices, explicit firewall restrictions, tested public ICE/TURN on the actual
media provider, rate limiting and an operational security review. The TLS
edge being reachable is **not** evidence that remote WebRTC works.

The Android-cellular acceptance criteria below remain mandatory: Call →
authenticated Join → endpoint MLS → actual two-sided media → enforced
revocation and measured stop, across independent networks.

The TURN REST file is provisioned **separately**, contains a cryptographically
random 32-byte shared secret (raw bytes or 64 hexadecimal digits), and must
match the configured coturn `use-auth-secret` secret; protect it with Windows
file ACLs. The launcher sets the canonical runtime's `UCR_WEBRTC_TURN_URLS`,
`UCR_WEBRTC_TURN_SECRET_HEX`, and `UCR_WEBRTC_RELAY_ONLY=true` before
starting the existing realtime owner. The realtime server issues bounded,
per-session TURN REST credentials; the browser receives only session ICE
credentials, never the root secret. This does **not** start coturn, provision a
public DNS hostname, configure the router/firewall or verify an actual relay.
If TLS or TURN inputs are missing, public mode fails before exposing ingress.
