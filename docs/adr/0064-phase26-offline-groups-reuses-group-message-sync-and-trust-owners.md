# ADR-0064: Phase 26 Offline Groups reuses Group, Message, Sync and trust owners

Status: Accepted

## Context

Offline Groups require local-first Group/messages/sync state, peer-to-peer delayed/partial synchronization, duplicate suppression and restart-safe resume. Group membership is security-sensitive. Existing UCR already owns canonical Group transitions/tombstones, Message persistence/signatures, Sync sessions/checkpoints, Device lifecycle, trusted signing keys and authenticated Crypto sessions.

Creating a separate offline Group store, Message log, membership authority or sync lifecycle would create a second communication brain. Allowing a peer to relay third-party Group records in Phase 26 would also implement Phase 27 Store-and-Forward prematurely.

## Decision

Phase 26 introduces `OfflineGroupStore` only as a replication sidecar over the existing Group/Message/Sync owners plus a Prepared `ucr-offline-groups` runtime.

Local canonical Group changes/messages receive source-local export evidence after successful canonical persistence. Inbound reconciled records never receive export evidence, so one-hop reconciliation cannot silently become intermediary forwarding.

The reference runtime accepts only authenticated Device principals: the peer Principal ID must exactly equal the Device ID proven by the existing trusted Crypto session. Every operation revalidates current Active Device state and the session's exact trusted signing key. Messages additionally re-run canonical trusted signature verification.SQLite v23 contains only restart-safe replication sidecars. Migration from v22 starts them empty rather than fabricating source/generation evidence for historical rows.

The public protobuf describes replica/page/change data only and defines no service. Existing Sync/Crypto/Transport boundaries remain responsible for session establishment and movement of bytes.

## Rejected alternatives

- A second `OfflineGroup` aggregate or Group membership database.
- A second Message log containing copied Message bodies.
- A separate offline-sync session/checkpoint state machine.
- Trusting a wire `PrincipalRef`, source IP, endpoint address or caller boolean as peer authentication.
- Inferring Person/AI/Bot/Organization→Device ownership from matching identifiers or Message metadata.
- Re-exporting records received from another peer.
- A durable pending-recipient queue, relay retry scheduler or multi-hop propagation in Phase 26.
- Backfilling v22 rows with guessed replication generations.

## Consequences

Offline synchronization is deliberately conservative. Some legitimate non-Device-principal relationships remain unsupported until a canonical authenticated Principal↔Device binding exists. This is preferred to silently inventing identity authority.

Phase 27 Store-and-Forward remains separate and not started. Later phases must explicitly add intermediary semantics rather than repurposing the Phase-26 one-hop sidecar.