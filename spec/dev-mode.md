# Phase 40 — Developer-first Dev Mode

## Status

Prepared developer harness for the Reference Messenger/public UCR boundary. The target experience is `install -> ucr dev -> ready`; this is development evidence, not a Production node claim.

## Provided environment

`ucr dev` creates one isolated local environment with a canonical local Identity and Active Device, a canonical mock-peer Identity and Active Device, in-memory test storage, an authenticated Service Principal with exact dev-scope permissions and quota, a test transport, redaction-safe debug events, diagnostics, and a loopback public gRPC API.

Authentication, authorization and quota admission remain enabled. The CLI refuses non-loopback binds. The generated dev credential is ephemeral to the process and is printed only so a local developer can call the authenticated loopback API.

## Public API proof

`ucr dev --check` starts real loopback public services and proves authenticated Identity creation, Conversation creation, Message persistence, Group creation and Call start through the same `ucr.v1` service bindings used by external consumers.

The same dev host also serves the public `UniversalConferenceService`, `RealtimeService` and `EventService` over one shared canonical in-memory store, `JoinTokenIssuer`, `ConferenceRuntimeState` and `RealtimeSessionRegistry`. Its self-check executes a business-neutral integration flow through those public RPCs: Conference creation plus exact idempotent retry, owner/attendee provisioning, canonical Device provisioning, runtime preparation, waiting -> live lifecycle, signed personal join-grant issuance, realtime join/leave and the integration-owned attendance Event projection. The self-check does not call a private Conference mutation path to simulate success; only the signed-grant claim lookup needed to construct the same Realtime request fields that the reference browser derives from `#ucr_join` is performed locally.

The dev harness may compose canonical owners to host the local node, but it does not add alternate Message, Group, Call, Conference, Event, Delivery, routing, retry or Identity owners.

## Sandbox and test transport

The sandbox exposes the Canon scenario names: `message`, `delivery`, `group`, `call`, `retry`, `failure`, `offline`, `reconnect`, and `bridge-degradation`. The development-only `TestTransport` can inject delay, drop, duplicate, reorder, disconnect/reconnect, corrupt and throttle behavior while preserving canonical acceptance classification.

The scenario layer is fault/situation simulation, not a second communication engine. Full cross-implementation behavior and conformance remain Phase 41.

## Docker local development package

The repository root ships a development-only `compose.yaml` so an external integrator can run:

```bash
docker compose up ucr
```

The `ucr` service builds the pinned Rust dev binary and composes only developer tooling around the
existing canonical dev host:

- the authenticated gRPC API is still owned by `ucr dev` and still binds only
  `127.0.0.1:50051` inside the container;
- a byte-only TCP forwarder publishes that loopback API through a container port 50052 that Compose maps
  only to host `127.0.0.1:50051`; it adds no protocol, auth, retry or domain semantics;
- the reference Conference browser HTML is served on host loopback for integration/UI work;
- a coturn process provides an explicitly insecure **test-only** TURN deployment with a fixed
  development shared secret and bounded relay port range;
- a bounded webhook receiver example accepts local POSTs and logs only request size, SHA-256 and an
  optional bounded event type instead of dumping headers or payloads;
- temporary TURN REST credentials and the canonical `ucr dev` Service Credential are printed to
  container logs for local testing.

The package is intentionally ephemeral: UCR canonical state remains the existing in-memory
`ucr dev` state, and all published host ports bind to `127.0.0.1`. The package does not weaken
the dev binary's loopback rule or claim that the static browser page can mint its own join authority.
A real `#ucr_join` grant is still required by the Conference client.

## Nonclaims

Dev Mode is memory-backed and loopback-only. It is not a production listener, durable production deployment, browser-native node, Relay, discovery service, production bridge, or insecure mode. It must never be used to justify disabling authentication, tenant scope, cryptography, permissions or other production security controls.
