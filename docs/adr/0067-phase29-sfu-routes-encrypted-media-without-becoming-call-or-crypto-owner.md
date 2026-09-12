# ADR-0067: Phase 29 SFU routes MLS-backed encrypted group media without becoming Group, Call, or crypto owner

## Status
Accepted

## Context
The Canon places SFU before Conferences and requires large-group media to avoid uncontrolled full mesh while preserving an explicit E2EE boundary, standardized group key management and rekey on security-sensitive membership changes. Phase 22 proved pairwise direct-call E2EE but intentionally had no group-key owner. A Phase-29 direct-pair forwarding shim would therefore satisfy neither the SFU scaling goal nor the group-key requirements.

## Decision
Phase 29 introduces a Prepared SFU boundary above standardized RFC-9420 OpenMLS state. Canonical Group membership/roles remain owned by GroupStore; Call participation remains owned by CallSession; Identity, Device lifecycle, permissions and signing-key trust keep their existing owners.

`GroupCryptoState` references the real MLS epoch. Endpoint-local MLS state uses the official OpenMLS SQLite backend. UCR SQLite schema v26 adds explicit non-Device Principal→Root-Identity association and idempotent Group/MLS transition evidence. The official MLS storage and canonical Group mutation share one SQLite transaction, so the next MLS epoch is derived rather than caller supplied and crash/validation failure cannot commit only one side.

MLS membership is Device-sensitive while canonical Group membership is Principal-sensitive. A Device is admitted explicitly and must resolve through an Active `DeviceDescriptor` to the Root Identity explicitly associated with that non-Device Principal. Identity ownership alone is not authorization and new Devices are not silently admitted.

Group-media payloads are endpoint-encrypted with keys derived from an MLS exporter. Each ciphertext frame additionally carries an Ed25519 signature from its claimed source Device because possession of the common group exporter does not prove which member emitted a frame. The SFU revalidates current Group/Call/Device/permission/epoch/signature authority but has no exporter-key, decrypt or plaintext interface.

Fan-out recipients are derived from the current accepted Call participant set and active Group membership. All permission/membership checks happen before the first sink side effect. Sink failure reports partial infrastructure acceptance rather than claiming rollback, exactly-once delivery, endpoint receipt or Read evidence.

## Consequences
A Prepared SFU can fan out encrypted group media without becoming a plaintext media endpoint or a second membership/conference database. Principal and Device IDs remain separate; Device revocation/signing-key rotation/member removal/MLS epoch change invalidate stale frames at the next operation. SQLite restart preserves exact Group↔MLS epoch binding and duplicate transition artifacts.

Phase 29 is intentionally not a Conference implementation. Phase 30 owns Conference coordination/lifecycle. Production listener deployment, recording, transcoding, mixing/compositing, RTP/WebRTC/ICE/STUN/TURN, Relay/NAT traversal and Production maturity remain separate work.

## Rejected alternatives
1. Keep Phase 29 as direct-call-only SFU forwarding: rejected because it does not implement the Canon's large-group SFU/group-key boundary.
2. Invent a UCR-specific group KDF: rejected in favor of standardized OpenMLS/RFC 9420.
3. Treat Principal ID as Device ID or Identity ID: rejected because those are separate canonical owners and would break multi-device semantics.
4. Infer all Identity Devices into MLS automatically: rejected because Device ownership is not Group authorization and device admission/rekey policy must be explicit.
5. Use two independent SQLite databases plus best-effort compensation: rejected because Group and MLS security epochs can be committed atomically with one compatible connection.
6. Decrypt/re-encrypt at the SFU: rejected because it would widen the infrastructure trust boundary to plaintext/key ownership.
7. Persist SFU recipients/routes as a second Call/Conference graph: rejected because current Call and Group state are already authoritative.
8. Treat SFU sink ACK as Delivery/Read: rejected because infrastructure acceptance is not endpoint/user evidence.
9. Fold Conference coordination into Phase 29: rejected because Conferences are Phase 30 and require separate authority/evidence.
