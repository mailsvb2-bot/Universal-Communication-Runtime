# Browser → first-party BFF → realtime: one canonical path

The browser entry point at `/start` uses same-origin `/v1/first-party/*` requests.
The owner of Identity, Device, Contact/Call state and Join issuance remains
`ucr-runtime`; the browser gateway is not a second identity or signaling store.

## Required deployment topology

```text
Browser (HTTPS, origin https://calls.example.org)
  -> trusted HTTPS terminator
  -> 127.0.0.1:8080  ucr-realtime-web
       /v1/first-party/* -> 127.0.0.1:18081 first-party BFF in serve-realtime
       /v1/realtime/*   -> 127.0.0.1:50051 realtime gRPC
  -> 127.0.0.1:50052  operator endpoint (NOT public)
```

Set `UCR_FIRST_PARTY_UPSTREAM=127.0.0.1:18081` on `ucr-realtime-web`.
Set `UCR_FIRST_PARTY_BIND=127.0.0.1:18081`,
`UCR_FIRST_PARTY_PUBLIC_ORIGIN=https://calls.example.org` and
`UCR_FIRST_PARTY_SELF_SERVICE_TENANT=<existing canonical tenant ID>`
on `ucr-runtime serve-realtime`.

`serve-realtime` also requires a real `--join-base-url` and the appropriately
scoped `UCR_REALTIME_JOIN_SECRET_PROVIDER` or
`UCR_REALTIME_JOIN_KEY_HEX` configuration. ICE/TURN/SFU and endpoint
E2EE media packages must be provisioned independently. Do not use dummy keys
or bypass signer/device checks.

The HTTPS terminator must preserve the exact public Host and Origin.
The BFF requires the exact HTTPS Origin and first-party CSRF header
`X-UCR-First-Party-Request: v1` for POST operations; its session cookies
are `Secure; HttpOnly; SameSite=Strict`. The gateway explicitly forwards
only required first-party headers, including `Cookie`, and preserves
`Set-Cookie`. The upstream must be loopback. GET and POST are the only
allowed methods; query strings and excessive request bodies are rejected.

Without `UCR_FIRST_PARTY_UPSTREAM` the gateway returns 503
`first_party_unconfigured` for these routes, not a misleading 405
suggesting a valid registration route. The gateway intentionally does not
translate HTTP-localhost testing into a production HTTPS authentication proof.

## Verification contract

1. `GET /healthz` on gateway returns 200.
2. `GET /v1/first-party/bootstrap` through the HTTPS origin reaches BFF
   and returns canonical tenant scope, or an explicit BFF failure.
3. Sign up two independent Identities and devices; verify their distinct
   sessions, grants and revocation.
4. Add contact, call, accept and obtain server-issued Join on each device.
5. Establish encrypted live audio and video (real browsers, ICE/TURN/SFU).
6. Hang up, reconnect and verify persisted call outcome after runtime restart.

Green unit tests, `LISTENING` ports, and the fact that `/start` renders
**do not** substitute for steps 3–6.

## Windows 10 local media preparation

The `/start` HTML alone is insufficient. Media assets are intentionally
**gitignored** and must be generated from the checked-out source revision.
After installing a supported Rust/Node toolchain, run PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/build-browser-media.ps1
```

The script pins wasm-bindgen-cli 0.2.128 and esbuild 0.25.5, builds the
endpoint WASM and the local first-party SDK module and verifies all three
nonempty output files. It never invents device signers, recovery keys or
Join grants. The generated files are excluded from Git commits.

### Readiness is not a call proof

- `GET /healthz` checks only the running browser gateway.
- `GET /readyz` returns 503 until **all** browser media assets exist,
  `UCR_FIRST_PARTY_UPSTREAM` is configured, and the BFF is reachable on
  loopback; returns 200 `ready` otherwise.
- `/readyz` does not claim the HTTPS terminator, ICE/TURN, SFU placement,
  authenticated Identity, device trust, or any actual media call works.

On the Windows 10 1607 smoke machine, initially the browser displayed
`Проверка независимой авторизации…`. This is consistent with absent
browser media assets, but a browser developer-console or network trace
must confirm the missing module response; do not mistake that UI symptom
alone for an authenticated or unauthenticated server result.

## GitHub Actions media bundle (no local WASM compilation)

The existing `Browser Compatibility` desktop Chrome job now uploads
`ucr-browser-media-<commit-sha>` with three public browser files and
`SHA256SUMS`. Use **only an artifact whose SHA equals the checked-out UCR
revision**, otherwise the generated E2EE WASM and JavaScript may disagree
with the runtime and SDK. Verify the checksums before copying the two
`endpoint-*` directories into
`crates/ucr-realtime-web/static/` on the same revision.

The bundle does not contain any private keys, sessions, signers or grants.
It does not eliminate the need for a trusted HTTPS origin and actual
ICE/TURN/SFU configuration. The browser compatibility run provides
an endpoint build and browser smoke probe, **not** live 2-person calling
proof.

## First real call: Windows fail-closed preflight

After deploying the **real** HTTPS edge, starting `serve-realtime` and the
first-party BFF with canonical tenant and Join credentials, and producing the
exact-revision browser media assets, run on the Windows host:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/check-first-real-call.ps1 -PublicOrigin https://calls.example.org
~~~

The script checks that pinned media assets exist, gateway `/healthz` and
`/readyz` return HTTP 200, first-party `/bootstrap` returns a nonempty
canonical `tenantId` through the trusted HTTPS origin, anonymous `/session`
is denied (401), and public HTTPS serves the browser entry and endpoint WASM.
It exits nonzero if **any** check fails; it never logs or invents signers,
recovery material, bearer credentials or Join tokens.

**This is only a deployment preflight**, not media proof. Complete two-device
acceptance and real encrypted audio/video transmission before claiming the
calling journey is complete.
