# UCR Threat Model

Status: **Phase 1 baseline / release-gating living document**.

This document defines the minimum security model for Universal Communication Runtime. It is not a checklist that becomes complete because ordinary CI is green. Production releases must keep it current as new transports, bridges, media paths, storage backends, recovery mechanisms, and deployment modes appear.

## 1. Security goals

UCR must preserve, subject to explicit policy and physical/network reality:

- authenticity of communicating principals/devices;
- integrity of protocol state and protected content;
- confidentiality promised by the negotiated security profile;
- tenant and namespace isolation;
- durable state without silent loss;
- explicit failure and downgrade semantics;
- revocation of future access for revoked devices/credentials;
- minimum disclosure of metadata to infrastructure components.
## 2. Security non-goals and physical limits

UCR cannot guarantee delivery when no permitted physical communication path exists. It cannot erase data already extracted from a compromised device. It must not claim that relay acknowledgement proves user delivery, that presence proves identity, or that availability permits silent reduction of a security guarantee.

Central infrastructure may improve availability or scale but must not become the only reason Identity, Conversation, or durable local state exists.

## 3. Protected assets

Key assets include canonical Identity/Device/Principal bindings, private keys and recovery secrets, authentication credentials, plaintext messages, decrypted attachments, conversation/group membership, durable queues, sync state, policy decisions, permission grants, audit records, and integrity metadata.

Metadata such as social graph, IP history, routing history, group membership, presence, and contact-discovery information is security/privacy sensitive even when content remains encrypted.
## 4. Data classification

UCR uses the Canon classifications `PUBLIC`, `INTERNAL`, `PRIVATE`, `SECRET`, `KEY_MATERIAL`, `EPHEMERAL`, and `AUDIT`.

Minimum handling rules:

- `KEY_MATERIAL` is separated from ordinary state, never logged, and excluded from crash reports.
- plaintext messages, decrypted attachments, recovery secrets, and authentication secrets never enter telemetry.
- `AUDIT` records must be integrity-protected and access-controlled; audit is not a plaintext-content archive.
- `EPHEMERAL` data such as typing/presence must not accidentally become durable security truth.
- diagnostics may reveal only the minimum data required for their declared purpose.
## 5. Trust boundaries

The canonical boundaries are:

1. User Device
2. External App
3. SDK
4. UCR Core
5. Relay
6. Bridge
7. SFU
8. Personal Node
9. Organization Node
10. Cloud Infrastructure

No boundary is trusted merely because it is operated by the same organization. A compromised User Device, Personal Node, Organization Node, Relay, Bridge, SFU, or cloud component is an explicit threat case.
### Boundary crossing rules

- External App → SDK/API → UCR Core requires authenticated Service Principal context, tenant/namespace scope, permissions, quotas, and auditability. Direct database access is forbidden.
- SDK is a client of the public contract, not an alternate source of authorization or communication logic.
- Core → Transport/Relay/Bridge/SFU crosses an explicit capability and policy boundary. Infrastructure cannot silently weaken privacy/security policy.
- Relay receives only relay-required routing material; it must not require plaintext message content.
- Bridge receives only provider context required to perform the configured bridge action.
- SFU receives only media-routing context required by the selected media architecture and must not automatically gain plaintext access.
- Cloud Infrastructure is optional infrastructure. Native/local Identity and durable state must not require a cloud account to exist.
## 6. Required threat actors and failure classes

The model explicitly covers:

- malicious peer;
- compromised device;
- stolen device;
- malicious bridge;
- compromised relay;
- compromised SFU;
- malicious tenant;
- malicious service account;
- MITM;
- replay;
- downgrade;
- impersonation;
- spam;
- flooding;
- malformed packets;
- attachment bombs;
- Sybil-like abuse;
- compromised personal node;
- compromised organization node.
## 7. Threat-to-control matrix

| Threat | Primary boundary | Required control | Current evidence |
|---|---|---|---|
| MITM / forged peer | Device/Core/transport | authenticated handshake, key confirmation, peer identity binding | protocol requirement; crypto implementation pending |
| Replay | protocol/session | nonces, replay window/state, idempotency | requirement specified; replay engine pending |
| Downgrade | handshake | integrity-bound negotiation transcript, minimum security policy | version policy implemented; authenticated binding pending |
| Malformed packets | network/Core | deterministic parser, size limits, unknown-kind rejection | framing parser tests present |
| Flooding / spam | API/network | quotas, rate limits, backpressure, block/abuse policy | policy work pending |
| Malicious tenant | API/Core/storage | tenant-scoped authz, resource visibility, policies and storage | canonical scope exists; enforcement phase pending |
| Malicious service account | External App/API | authenticated principal, least privilege, quotas, audit | contract requirement; authz phase pending |
| Stolen/revoked device | Device/Core/crypto | revoke, stop new key/content delivery, credential invalidation, audit | lifecycle vocabulary present; key enforcement pending |
| Compromised bridge | Core/Bridge | least privilege, minimum disclosure, canonical failure mapping | boundary specified; bridge implementation pending |
| Compromised relay | Core/Relay | encrypted payload, minimum routing metadata, no plaintext dependency | boundary specified; relay implementation pending |
| Compromised SFU | Core/SFU | explicit media encryption boundary and group-key policy | media/crypto phase pending |
| Attachment bomb | API/storage | declared size, streaming limits, integrity check, quota/backpressure | attachment phase pending |
## 8. Protocol security invariants

Production protocol paths require all of the following where applicable:

- authenticated handshake;
- key confirmation;
- nonces;
- replay protection;
- integrity protection;
- downgrade protection;
- malformed-frame handling;
- size limits before unbounded allocation;
- deadline/timeout limits;
- explicit unsupported-critical-extension failure.

Successful version/capability negotiation alone is not proof of an authenticated secure session. The negotiated transcript must eventually be cryptographically bound before security-sensitive session establishment is considered complete.
## 9. Device compromise, theft, and revocation

A stolen or compromised device is not made trustworthy by server ownership or account login.

Required response capability includes revoke, stop new protected-content/key delivery, invalidate credentials, rotate affected material where required, and emit auditable security events. A revoked device must not be silently returned to Active state by transport reconnect.

UCR cannot promise deletion of secrets or plaintext already extracted from a compromised device. Recovery UX and documentation must state that limit explicitly.

Device lifecycle states remain distinct: Active, Stale, Reverification Required, Expired, and Revoked. Policy for stale/expired devices must be explicit rather than inferred from presence.
## 10. Recovery threats

Account/key recovery is a security-boundary change, not merely an availability feature. Before recovery ships, UCR must define what is recovered, who authorizes recovery, which historical messages remain accessible, which guarantees change, and whether peer/device re-verification is required.

Potential mechanisms may include recovery code/key, trusted device, hardware-backed recovery, encrypted backup, and organization-managed recovery. No mechanism may silently convert previously promised E2EE into infrastructure-readable history.

Recovery secrets are `SECRET`/`KEY_MATERIAL` and are excluded from telemetry and ordinary diagnostics.
## 11. Metadata privacy and minimum disclosure

Each infrastructure component must document which metadata it can observe. The design minimizes social-graph exposure, IP history, routing history, group membership leakage, presence leakage, and contact-discovery leakage.

Minimum disclosure rules are component-specific: Relay learns only relay-required routing context; Bridge learns only provider context required for the bridge action; SFU learns only media-routing context required by the negotiated media architecture.

Presence, display name, avatar, phone, email, or provider account ID must not become security truth merely because they are visible to infrastructure.

Observability may be local, organization-hosted, or managed. The protocol must not require central telemetry upload to function.
## 12. Mandatory threat tests

The security test suite must eventually include explicit scenarios for:

- replay;
- MITM simulation;
- forged identity;
- malicious tenant;
- malicious peer;
- compromised bridge;
- invalid permissions;
- revoked devices.

A test is not considered satisfied by a unit test with the same word in its name; it must exercise the relevant trust boundary and expected failure semantics.
## 13. Mandatory fuzz targets

Fuzzing targets include protocol parser, message envelope, identity parser, bridge normalization, file-chunk parser, signalling, and crypto wrapper.

Fuzz harnesses must enforce memory/time budgets and retain minimized regression cases. Parser fuzzing is required before parser maturity can be promoted to Production.

Current Phase-0 framing unit tests are deterministic regression coverage, not a substitute for fuzzing.
## 14. Mandatory chaos scenarios

Chaos coverage includes network loss/switch, DNS failure, relay failure, SFU failure, process kill, app restart, peer disappearance, clock drift, packet duplication/reorder/corruption, storage full, network partition/merge, old client, revoked device, and slow consumer.

Chaos tests must assert durable-state and security invariants, not merely process survival. In particular, failover/reconciliation must not create user-visible duplicates, silently lose messages, revive revoked devices, or weaken policy.

No transport/capability is promoted to Production maturity without the relevant failure, security, and observability evidence required by the Canon.
## 15. Production release blockers

The following are explicit blockers until implementation and evidence exist:

- authenticated handshake and key confirmation;
- replay protection state;
- cryptographic transcript/downgrade binding;
- tenant-scoped authorization enforcement;
- Service Principal authentication/least-privilege enforcement;
- device revocation enforcement in credential/key delivery;
- account/key recovery model and tests;
- metadata-visibility documentation for each infrastructure component;
- required threat simulations;
- required fuzz targets for implemented parsers/wrappers;
- applicable chaos scenarios;
- secret/plaintext telemetry regression tests.

A blocker may be removed only with implementation, tests, and review evidence. Documentation alone does not close it.
## 16. Current verified foundation evidence

Current repository evidence includes fail-closed framing bounds/unknown-kind rejection, explicit protocol-version minimum policy, unsupported-critical-extension failure, capability maturity negotiation, canonical error mapping, redaction of opaque IDs/address values, and architectural separation of Identity/Endpoint/Route and Actor/Origin.

These controls reduce attack surface but do not imply crypto, authorization, recovery, bridge, relay, SFU, or device-revocation implementation exists. Their absence remains visible in the blocker list above.

Relevant normative material: `spec/framing.md`, `spec/negotiation.md`, `spec/errors.md`, `spec/identity-addressing.md`, `spec/principal-actor-device.md`, ADR-0002, ADR-0003, and ADR-0004.
