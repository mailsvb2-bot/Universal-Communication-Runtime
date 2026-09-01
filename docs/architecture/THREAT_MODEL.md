# UCR threat model — baseline

Status: **initial Phase-1 seed; not production-complete**.

This document exists now so that Phase 0 interfaces do not accidentally erase security boundaries. It is not evidence that the production threat-model phase is complete.

## Trust boundaries

- User Device
- External Application
- SDK
- UCR Core
- Relay
- Bridge
- SFU
- Personal Node
- Organization Node
- Cloud Infrastructure

## Required threat classes

The production threat model must cover at minimum malicious peers, compromised/stolen devices, malicious bridges, compromised relays/SFUs, malicious tenants/service accounts, MITM, replay, downgrade, impersonation, spam/flooding, malformed packets, attachment bombs, Sybil-like abuse and compromised personal/organization nodes.

## Phase-0 security invariants

- Never silently downgrade an explicitly required security property.
- Version negotiation must be explicit and deterministic.
- Protocol framing must eventually provide authenticated handshake, key confirmation, nonces, replay protection, integrity, downgrade protection, malformed-frame handling, size limits and timeout limits.
- Plaintext messages, decrypted attachments, private keys, recovery secrets and auth secrets must never become telemetry payloads.
- Tenant scope is part of every security-sensitive canonical envelope.
- Debug/test facilities must not implicitly disable tenant isolation or security in production builds.
