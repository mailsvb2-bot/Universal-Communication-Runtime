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
| MITM / forged peer | Device/Core/transport | authenticated handshake, key confirmation, peer identity binding | signed transcript + key confirmation implemented; trust provisioning/revocation integration pending |
| Replay | protocol/session | nonces, durable replay state, idempotency | memory/SQLite replay guards pass restart and concurrency tests |
| Downgrade | handshake | integrity-bound negotiation transcript, explicit allowed-suite security policy | protocol + explicit crypto-suite allowlist policy and authenticated transcript binding implemented |
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

Successful version/capability negotiation alone is not proof of an authenticated secure session. The negotiated transcript is cryptographically bound in Phase 7; peer signature, durable replay protection, contributory agreement, derivation, and key confirmation must all succeed before security-sensitive session establishment is complete.
## 9. Device compromise, theft, and revocation

A stolen or compromised device is not made trustworthy by server ownership or account login.

Required response capability includes revoke, stop new protected-content/key delivery, invalidate credentials, rotate affected material where required, and emit auditable security events. A revoked device must not be silently returned to Active state by transport reconnect.

UCR cannot promise deletion of secrets or plaintext already extracted from a compromised device. Recovery UX and documentation must state that limit explicitly.

Device lifecycle states remain distinct: Active, Stale, Reverification Required, Expired, and Revoked. Policy for stale/expired devices must be explicit rather than inferred from presence.
## 10. Recovery threats

Account/key recovery is a security-boundary change, not merely an availability feature. Phase 8 now requires every Recovery Plan to define what Identity/scope is recovered, typed recovery authorities, historical-message access, the post-recovery trust model, and mandatory device re-verification.

Supported authority forms include recovery code/key, specifically named trusted or hardware-backed Devices, encrypted-backup recovery capability, and specifically named organization Principals. Organization-managed recovery must be explicit; no mechanism may silently convert previously promised E2EE into infrastructure-readable history.

Recovery packages are versioned ciphertext cryptographically bound to the canonical plan. Recovery secrets are `SECRET`/`KEY_MATERIAL`, excluded from protobuf/general SQLite, telemetry, and ordinary diagnostics. A recovered Device remains `REVERIFICATION_REQUIRED`; decrypting a recovery package does not auto-trust it.
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

- trusted peer signing-key provisioning and lifecycle integration;
- production OS/hardware-backed key providers for supported targets;
- tenant-scoped authorization enforcement;
- Service Principal authentication/least-privilege enforcement;
- device revocation enforcement in credential/key delivery;
- end-to-end recovery workflow: credential re-issuance, device revocation/key-delivery enforcement, backup restore conformance, and re-verification UX evidence;
- cryptographic Message-signature verification over canonical signing bytes;
- message-content encryption-at-rest policy for local durable stores where required;
- cryptographic authentication and anti-replay for remote delivery receipts;
- metadata-visibility documentation for each infrastructure component;
- required threat simulations;
- required fuzz targets for implemented parsers/wrappers;
- applicable chaos scenarios;
- secret/plaintext telemetry regression tests.

A blocker may be removed only with implementation, tests, and review evidence. Documentation alone does not close it.
## 16. Current verified foundation evidence

Current repository evidence includes fail-closed framing, protocol/crypto downgrade policy, unsupported-critical-extension failure, capability negotiation, canonical error mapping, redaction, Identity/Endpoint/Route separation, signed transcript authentication, contributory X25519 agreement, directional HKDF keys, key confirmation, AEAD integrity, durable replay protection, typed Recovery Plans, plan-bound encrypted recovery packages, durable CAS recovery-plan rotation/revocation, provider-independent Conversation/Message entities, validated Topic/Thread hierarchy, restart-safe canonical Message persistence, and evidence-gated restart-safe DeliveryAttempt state with relay/transport/user evidence separation.

These controls establish the Phase-10 Delivery state/evidence foundation but do not imply Message signatures are cryptographically verified, SQLite Message content is encrypted at rest, real routing/transports/retry/receive-side deduplication/Sync/Attachment/Group-MLS behavior is complete, or remote delivery receipts are cryptographically authenticated. Those absences remain visible in the blocker list above.

Relevant normative material includes `spec/framing.md`, `spec/negotiation.md`, `spec/crypto.md`, `spec/recovery.md`, `spec/errors.md`, `spec/identity-addressing.md`, `spec/principal-actor-device.md`, `spec/conversation-message.md`, `spec/delivery.md`, ADR-0002, ADR-0003, ADR-0004, ADR-0011, ADR-0012, ADR-0013, and ADR-0014.
