# Phase 40 — Developer-first Dev Mode

## Status

Prepared developer harness for the Reference Messenger/public UCR boundary. The target experience is `install -> ucr dev -> ready`; this is development evidence, not a Production node claim.

## Provided environment

`ucr dev` creates one isolated local environment with a canonical local Identity and Active Device, a canonical mock-peer Identity and Active Device, in-memory test storage, an authenticated Service Principal with exact dev-scope permissions and quota, a test transport, redaction-safe debug events, diagnostics, and a loopback public gRPC API.

Authentication, authorization and quota admission remain enabled. The CLI refuses non-loopback binds. The generated dev credential is ephemeral to the process and is printed only so a local developer can call the authenticated loopback API.

## Public API proof

`ucr dev --check` starts real loopback public services and proves authenticated Identity creation, Conversation creation, Message persistence, Group creation and Call start through the same `ucr.v1` service bindings used by external consumers. The dev harness may compose canonical owners to host the local node, but it does not add alternate Message, Group, Call, Delivery, routing, retry or Identity owners.

## Sandbox and test transport

The sandbox exposes the Canon scenario names: `message`, `delivery`, `group`, `call`, `retry`, `failure`, `offline`, `reconnect`, and `bridge-degradation`. The development-only `TestTransport` can inject delay, drop, duplicate, reorder, disconnect/reconnect, corrupt and throttle behavior while preserving canonical acceptance classification.

The scenario layer is fault/situation simulation, not a second communication engine. Full cross-implementation behavior and conformance remain Phase 41.

## Nonclaims

Dev Mode is memory-backed and loopback-only. It is not a production listener, durable production deployment, browser-native node, Relay, discovery service, production bridge, or insecure mode. It must never be used to justify disabling authentication, tenant scope, cryptography, permissions or other production security controls.
