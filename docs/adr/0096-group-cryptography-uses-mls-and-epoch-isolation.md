# ADR 0096: Group cryptography uses MLS and epoch isolation

Status: Accepted

## Context

The Canon forbids custom group cryptography and requires safe member add/remove, epoch transition, key update and revoked-member isolation. Phase 29 already introduced OpenMLS/RFC 9420 ownership for implemented group-media key epochs.

## Decision

MLS (RFC 9420) is the canonical group-key-management baseline for UCR capabilities that claim group E2EE. UCR does not invent a parallel group key schedule.

Membership-changing security state is bound to an MLS epoch transition. A removed or revoked member is not eligible for new epoch key material. Group membership/authorization remains owned by canonical Group/Policy owners; MLS owns cryptographic epoch state, not Group business state.

The current implementation evidence covers the Phase-29 group-media path. Any future encrypted group-message/file capability must reuse the same MLS ownership boundary or introduce a superseding ADR with equivalent reviewed security evidence.

## Consequences

A capability may remain unavailable rather than fall back to weaker ad-hoc group crypto. Relay/SFU/bridge components never become group-key owners merely because they forward ciphertext.
