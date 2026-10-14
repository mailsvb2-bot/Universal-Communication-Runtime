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
