# PetrelLink /room production admission contract

**Incident:** `GET /room` can return 200 while `POST /v1/room/enter` fails with 502 `room_unreachable`. The HTML route and generic `/readyz` cannot establish that a real room can admit participants.

## Explicit contract

The gateway's `GET /v1/room/status` sends, via its operator-configured loopback `UCR_ROOM_API`, this probe:

```http
POST /v1/room/capabilities HTTP/1.1
Content-Type: application/json

{}
```

A **production-only**, canonical UCR runtime-backed adapter may respond:

```json
{"ok":true,"owner":"canonical-ucr-runtime","capability":"production-room-enrollment-v1"}
```

Anything else—including an unbound port, a listening TCP endpoint, an HTTP 200 with unrelated content, the dev room, a timeout, and an unavailable runtime—results in **503** from `GET /v1/room/status` and disables the lobby's Join action. The response indicates only that the API supports the production enrollment contract, **not** that any particular Device or end-to-end MLS call has been authenticated.

The adapter must be backed by the existing production store, device trust, conference lifecycle, durable signed join grants, endpoint MLS and realtime runtime. A second owner/SQLite/issuer or port-only health probe is forbidden. `ucr dev --room` deliberately does not advertise this contract; it is never a production substitute.

## Release stop condition

Do not publish or claim a working broadcast until an actual canonical production implementation of `/v1/room/enter` and its related role/revocation operations exists, can verify ownership and signer proofs, and passes speaker/attendee admission and encrypted media on **two devices**. The gap is tracked in #358. `/readyz=200` and `/room=200` alone do not satisfy it.
