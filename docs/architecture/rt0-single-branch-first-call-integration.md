# RT0 first-call integration: one branch, one canonical route

**Integration head:** `feat/ucr-first-real-call-integration-20261012` (draft PR #286).
**Protected target:** `main`. Never merge source PRs #283–#285 independently or auto-merge #286.
**Authority:** existing Identity, Device/Trust, Call, Conference/Join, Realtime/MLS owners.
No shadow Identity/Call database, second signer, alternate media protocol, or central contacts directory.

## Source branches and conflict resolution

| Source | Contribution kept in #286 | Resolution |
|---|---|---|
| #283 | Heartbeat-driven fail-closed capture shutdown; Join/Leave fencing; stale Leave cannot revoke a newer connection; provider peer closes on canonical Leave | Retain a single Rust Realtime registry/service and one reference web client. In #286 the stable **join_generation** fences Leave and Join rollback; `session_sequence` is still allowed to change on attendance/media events. |
| #284 | Encrypted local contacts, password-encrypted owner-bound export/import, CAS and conformance | One `private_contacts.ts` implementation; #286 adds integration with contact picker. No central phonebook. |
| #285 | Authenticated first-party Device signer proof, same-origin BFF SDK, Ed25519 protected browser vault and endpoint media installer | One `first_party_browser_http.ts` adapter, one canonical Device authority, one protected signer vault. |
| #286 | Caller/recipient-scoped canonical Call lifecycle, durable Call stores, recipient acceptance, signed Device-bound Join and browser UI, loopback Rust first-party BFF | **Integration owner.** Only this draft PR is a candidate to eventually merge to `main` after exact-head evidence. |

Comparison against source heads found identical content for #283's browser `client.html`, `realtime.proto`, endpoint E2EE conformance, dev library and browser probe; #284's contacts conformance; and #285's first-party conformance and core integration API. Other overlapping files have **integration edits**, not an instruction to cherry-pick whole source branches. The previous PR #285 adapter had the wrong bare Device-inspect request; #286 now uses the server's strict `{binding}` envelope.

## Exact first-party BFF ↔ browser HTTP contract

Both endpoints and the SDK live on the same integration head. The first-party Rust server requires loopback bind behind a separately configured trusted HTTPS reverse proxy. All POST routes require an exact Origin, `X-UCR-First-Party-Request: v1`, JSON and an independently authenticated HttpOnly Secure SameSite cookie after login.

| Route | Request envelope | Canonical outcome |
|---|---|---|
| `POST /v1/first-party/login/challenge` | `{tenantId,namespaceId,participantId,deviceId}` | Scoped one-time login challenge |
| `POST /v1/first-party/login/verify` | `{binding,challengeId,signatureBase64Url}` | Independently verified existing Device key; sets session cookie |
| `GET /v1/first-party/session` | Cookie, no body | Authenticated Identity/Device binding |
| `POST /v1/first-party/device/inspect` | **`{binding}`**, never bare binding | Live canonical Device trust and active key |
| `POST /v1/first-party/device/challenge` | `{binding,keyId,publicKeyBase64Url}` | Scoped one-time signer proof challenge |
| `POST /v1/first-party/device/approve` | `{binding,keyId,publicKeyBase64Url,challengeId,signatureBase64Url}` | Signer possession confirmed **only if already canonically trusted** |
| `POST /v1/first-party/call/start` | `{binding,intent:{peerIdentityId,media,idempotencyKey}}` | Persisted two-principal canonical direct Call |
| `POST /v1/first-party/call/get` | `{binding,callId}` | Scoped Call snapshot and revision |
| `POST /v1/first-party/call/incoming` | `{binding}` | Recipient-only pending Calls |
| `POST /v1/first-party/call/signal` | `{binding,callId,expectedRevision,action}` | Authorization + CAS state transition |
| `POST /v1/first-party/call/join-accepted` | `{binding,callId,expectedRevision}` | Fresh Device-bound signed Conference Join **only for accepted active Call** |
| `POST /v1/first-party/call/join` | Any bare Device Join | **403 Forbidden**: no Call-free admission |

Rust request structs use `deny_unknown_fields`. Browser conformance asserts exact POST envelopes; Rust unit conformance rejects bare Device inspection. Independent first-party authentication does not mean anyone can self-enroll: the BFF intentionally refuses first-time Device/signer registration without an already-existing, independently trusted Device. A real onboarding/recovery workflow still needs to be integrated through the existing canonical authority.

## Canonical user journey to verify

1. A and B have individually authenticated *existing* trusted Devices and preserved endpoint-only Ed25519 signers.
2. A opens her encrypted local contacts, selects B's canonical Identity, chooses audio/video and presses Call once.
3. Server verifies A and recipient membership; canonical Call owner persists Start with idempotency and authenticates A's Device.
4. B's separately authenticated browser receives only B-addressed incoming Call information; B accepts or rejects via CAS. Neither can acquire a Join before acceptance.
5. Both users independently request an accepted-Call Join; server verifies current Device/Call/revision and issues separate fresh grants from the **existing** Conference issuer.
6. Browser validates bound signer/trust/MLS and connects over actual ICE/TURN/SFU; media is sent/received only under real endpoint E2EE. Revoke, hangup, heartbeat loss, offline state or stale generation terminates capture and publication.
7. Call cancellation/busy/rejection/reconnect/end updates the canonical durable Call state; after process restart, the supported authenticated user sees a truthful final Call outcome, not a synthetic success.

## Evidence gates — none may be replaced by green isolated mocks

- [ ] Latest **same HEAD** Rust format, compilation, Clippy, all tests including BFF schema tests.
- [ ] Latest **same HEAD** Node/TypeScript conformance, browser bundle/WASM, device/signing tests, server request-body parity.
- [ ] Live HTTPS proxy → Rust BFF → SQLite canonical Identity/Device/Call → Conference issuer integration with actual enrolled A and B; Origin/CSRF, wrong-user, revoked signer, logout and request replay.
- [ ] Actual incoming notification/polling under separate B session; no cross-tenant incoming leaks.
- [ ] Two independent browsers/physical Devices across NAT/TURN with audible and visible E2EE media through real SFU, plus negative revocation/reconnect and crash/restart scenarios.
- [ ] Review/approval of call metadata retention, backup/recovery, operational limits and revocation security.

**Current limitation:** Node conformance mocks, passing Rust unit tests, a successful WASM build or the existence of an HTTP route do **not** prove a real first-party two-Device phone/video call. Until the above real tests pass, this is an integration candidate, not RELEASED.

## Promotion policy

Keep PR #286 draft and `main` untouched while any required job fails or live user journey is unproven. Source PRs #283–#285 are provenance, not additional merge candidates. When evidence is sufficient, promote **one reviewed commit lineage** through PR #286 only. Re-run required checks on that final SHA; never assume a prior PR's green check proves a changed integration HEAD.
