# Universal Conference integration quickstart

This is the business-neutral integration path for products that want UCR Conference/Webinar
capabilities without importing UCR's internal Group, Call, Principal or Device identifiers.

The canonical scenario is:

```text
Authenticate
  -> Create conference
  -> Ensure participants
  -> Ensure participant devices
  -> Prepare runtime
  -> Create attendance webhook subscription
  -> Open entry / move conference live
  -> Issue personal join URL
  -> Participant joins UCR
  -> Receive integration attendance webhook
  -> Read attendance when needed
  -> End conference
```

The REST/OpenAPI Conference adapter and the protobuf EventService are thin transports over the same
canonical runtime. CRM, sales, payments, funnels and other product logic stay outside UCR.

## 1. Authenticate the integration

For the Universal Conference REST/gRPC boundary, use a short-lived machine Bearer issued through
the OAuth2-compatible client-credentials flow. The token subject is the same canonical Service
Account represented by `integration_id`; OAuth scope can attenuate authority but never replaces
the exact UCR Permission Grant.

Typical Conference scopes are:

- `conference:create`;
- `conference:manage`;
- `conference:join:issue`;
- `conference:read`;
- `attendance:read`.

Never place the machine access token in browser/mobile source. A trusted backend creates the
Conference and issues the participant's short-lived personal join URL.

Direct EventService clients currently use the canonical Service Credential metadata described by
`proto/ucr/v1/event_api.proto` and the public SDK contract. The Event subscription must be created
by the same Service Account/integration that owns the Universal Conference.

## 2. Create a Conference

HTTP adapter:

```text
POST /v1/conferences
Authorization: Bearer <machine-access-token>
Content-Type: application/json
```

Use your own stable `external_conference_id` plus an idempotency key. UCR returns a stable
`conference_id`. The external reference remains the product's correlation key; the integration
does not need a Group ID or Call ID.

The checked-in runnable examples construct the exact request shape:

- `examples/reference-integrations/python_backend.py`;
- `examples/reference-integrations/node_backend.mjs`.

## 3. Ensure participants and devices

For each external user:

```text
POST /v1/participants
POST /v1/participant-devices
```

Participants are addressed by `external_user_id`. Assign one of the public Conference roles:
`owner`, `host`, `moderator`, `speaker`, or `attendee`.

`participant-devices` prepares the canonical UCR Device lifecycle without exposing DeviceId to the
integrator. It is not permission to manufacture a browser/WebRTC identity client-side.

## 4. Prepare the canonical realtime runtime

```text
POST /v1/conferences/runtime
```

This reconciles the Universal Conference projection into the existing Group/MLS/Call owners. It does
not create a second Conference or media engine. A first realtime Call needs enough device-ready
participants for the canonical Call rules; the operation can truthfully report Group ready while
Call is not ready yet.

## 5. Create the attendance webhook subscription

Before participants join, create a durable `ucr.v1.EventService` subscription with:

```text
mode: EVENT_SUBSCRIPTION_MODE_WEBHOOK
event_types:
  - ucr.conference.attendance.integration.v1
webhook_uri: https://events.example.com/ucr
start: EVENT_SUBSCRIPTION_START_LATEST
max_in_flight: <bounded value>
max_attempts: <bounded value>
```

The webhook URL must be HTTPS and resolve to a public address. UCR deliberately rejects loopback,
private/link-local addresses, URL credentials, query strings, fragments and redirects at the
hardened webhook boundary.

The subscription owner is the authenticated Service Account. EventService does not give that
Service Account visibility into arbitrary participant-authored Events. Instead, for a Universal
Conference join/leave/reconnect/media-ready transition, UCR atomically records:

1. the canonical participant-owned attendance Event; and
2. `ucr.conference.attendance.integration.v1`, a System projection attributed
   `on_behalf_of=integration_id`.

The integration payload is `UniversalConferenceAttendanceEvent` and contains only:

- tenant/namespace scope;
- `conference_id`;
- `integration_id`;
- your `external_conference_id`;
- your `external_user_id`;
- the public join `session_id`;
- attendance kind and occurrence time;
- session sequence.

Internal PrincipalId, DeviceId and CallId are deliberately absent.

### Webhook envelope and signature

The HTTP webhook body uses schema `ucr.webhook.event.v1` and carries the canonical Event payload as
Base64 in `payload_base64`. Important headers are:

- `x-ucr-webhook-id`;
- `x-ucr-webhook-timestamp`;
- `x-ucr-webhook-signature: sha256=<hex-hmac>`.

The HMAC-SHA256 input is exactly:

```text
<timestamp> "\n"
<subscription_id> "\n"
<event_id> "\n"
SHA256(<exact HTTP body bytes>)
```

The signing secret is deployment-owned and never persisted in the Event subscription. Consumers
should verify the HMAC before decoding/processing the payload and deduplicate external side effects
by canonical Event ID.

## 6. Open the room and move it live

Use the normal lifecycle operations:

```text
POST /v1/conferences/entry
POST /v1/conferences/lifecycle
```

A typical webinar transitions `scheduled -> waiting -> live`. Entry gating and lifecycle are
server policy. A browser in the waiting room does not gain media authority until the Conference is
admitted/live.

## 7. Issue the personal join URL

```text
POST /v1/join-grants
```

Address the participant by `external_user_id`. The returned URL contains the signed personal
`ucr_join` grant in the URL fragment. Give that URL to the participant; do not turn it into a
server query parameter.

The TypeScript embed helper can mount the same URL in an iframe or headless flow and can attach
presentation-only white-label metadata. Branding never changes the signed join authority.

## 8. Participant joins and the webhook arrives

The participant browser/native client presents the signed join Bearer to the realtime boundary. UCR
then enforces the current Conference lifecycle, participant status, Device binding, media policy,
recording consent gates and realtime session rules.

Successful join/reconnect/leave/media-ready transitions produce canonical attendance evidence. For a
Universal Conference, the paired integration projection becomes eligible for the EventService
webhook subscription created in step 5.

Webhook delivery is durable at-least-once delivery with canonical retry/cursor/dead-letter state,
not a claim of exactly-once external side effects. Consumer-side Event-ID deduplication remains
required.

## 9. Read the attendance projection

For an integration-facing participant summary:

```text
POST /v1/attendance
```

The request uses `conference_id + integration_id + external_user_id`. UCR computes the result from
the participant-owned canonical Event history. The integration webhook projection is intentionally
not included in that calculation, so it cannot double-count attendance.

## 10. End the Conference

Move the lifecycle through `ending -> ended` using:

```text
POST /v1/conferences/lifecycle
```

The externally observable `live` and `ended` lifecycle transitions also use canonical
integration-attributed Events.

## Contracts and runnable examples

- REST route map: `crates/ucr-conference-web/openapi.yaml`;
- Conference protobuf: `proto/ucr/v1/universal_conference.proto`;
- Event/Webhook protobuf: `proto/ucr/v1/event_api.proto`;
- OAuth/M2M protobuf: `proto/ucr/v1/m2m_auth.proto`;
- Python runnable reference backend: `examples/reference-integrations/python_backend.py`;
- Node.js runnable reference backend: `examples/reference-integrations/node_backend.mjs`;
- simple HTML consumer: `examples/reference-integrations/simple-html/index.html`;
- mobile-web consumer: `examples/reference-integrations/mobile-web/index.html`;
- one-command local package: `docker compose up ucr` after the local-dev package lands.

The reference backend self-tests can be run without a live deployment:

```bash
python3 examples/reference-integrations/python_backend.py --self-test
node examples/reference-integrations/node_backend.mjs --self-test
```

A real end-to-end webhook run additionally requires an externally reachable trusted HTTPS webhook
endpoint because the hardened dispatcher intentionally refuses loopback/private destinations.
