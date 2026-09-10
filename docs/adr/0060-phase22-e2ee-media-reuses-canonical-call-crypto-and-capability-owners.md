# ADR-0060: Phase 22 E2EE Media reuses canonical Call, Crypto, and Capability owners

- Status: Accepted
- Date: 2026-09-10

## Problem

Realtime Audio/Video payloads must gain authenticated end-to-end protection, replay protection, and explicit key lifecycle without creating a second Call/Identity/negotiation/transport brain or silently weakening security for availability. Group media additionally requires safe membership-bound rekey semantics, but inventing custom group cryptography is prohibited.

## Decision

Add a Prepared `ucr-media-e2ee` reference layer. It accepts only direct `CallSession` media whose exact negotiation result includes `ucr.media.e2ee` and the exact accepted participant set. It reuses existing Audio/Video frame models, `ucr-crypto` UCR-v1 primitives, trusted Active-Device signing-key resolution, and existing per-media permissions.

`MediaE2eeContext` binds scope, Call, ordered principals, exact Device IDs, negotiation ref/generation, key epoch, and crypto suite. A domain-separated media transcript additionally binds fresh ordered X25519 ephemerals. `EstablishedSession` records only the trusted peer Device identifier proven during existing trusted-key resolution; raw sessions retain `None` and cannot satisfy Phase 22.

Encoded Opus/H.264 payload bytes are encrypted with the existing direction-specific XChaCha20-Poly1305 session traffic key. All clear media headers are mandatory AEAD associated data. No plaintext fallback function exists.

Replay cursors are advanced only after successful AEAD authentication. Outbound sequence regression is rejected. Stream cursor state is bounded. Key rotation requires exact `epoch + 1`, immutable context except epoch, fresh role-specific ephemerals, current Call/negotiation authority, and a newly authenticated peer session.

Group calls fail closed until a standardized group-media crypto owner exists. Phase 22 does not implement an ad-hoc pairwise mesh, MLS engine, SFU, route selection, or media transport service.

## Rationale

This preserves Canon ownership boundaries and makes authenticated peer provenance explicit at the point where media security needs it. Reusing the existing cryptographic suite avoids a parallel cipher/KDF/signature stack. Authenticating headers prevents moving valid ciphertext between calls, streams, recipients, epochs, media types, or negotiated generations. Authenticating before replay-state mutation prevents unauthenticated sequence poisoning.

Failing group media closed is safer than shipping a custom group scheme that cannot prove secure member add/remove, epoch transition, rekey, and revoked-member isolation.

## Compatibility and storage

The change is additive before UCR 1.0. A new `media_e2ee.proto` surface describes the language-independent context/header/ciphertext and read-only negotiation binding. No `MediaE2eeService` is introduced because transport orchestration is a later owner.

No SQLite migration is introduced; schema remains v22. Media keys, replay cursors, and encrypted realtime frames are ephemeral and are not persisted by a new media store.

## Security and privacy

Private/traffic key bytes remain non-exporting/redacted. Encrypted frame `Debug` output redacts nonce/ciphertext. Runtime authority and negotiated E2EE capability are rechecked for every frame. Security failure never enables plaintext fallback.

## Alternatives rejected

- reuse transport encryption as “E2EE”: rejected because transport/SFU/relay trust is a different boundary;
- caller-supplied public key without trusted Device resolution: rejected as unauthenticated identity evidence;
- one long-lived epoch with no rotation contract: rejected;
- advance replay cursor before AEAD verification: rejected because forged high sequences could cause denial of service;
- custom group pairwise/full mesh or home-grown group KDF: rejected by Canon and scaling/security requirements;
- add routing/SRTP/WebRTC here: rejected because those belong to later phases.

## Testing

Required evidence is strict Rust quality/docs/tests in debug and release, real Opus/H.264 E2EE round trips, tamper/replay/rotation/authority negative tests, protobuf compilation, architecture ownership guards, bounded fuzz smoke, dependency audit, exact-head PR CI, review, and post-merge main CI.

## Codex security hardening

The Phase 22 reference path binds direct media to canonical `Device` principals rather than inferring a missing Person→Identity relationship. The exact participant Principal ID must match the declared Device ID, and the durable Device must remain `Active`. Every frame additionally re-resolves the authenticated peer's exact signing descriptor through the canonical trusted-key resolver using the Device's durable Identity, so Device or signing-key revocation invalidates an already-open media session immediately.

Key rotation retains a bounded history of all role ephemerals for up to 64 media-key epochs and rejects reuse from any earlier epoch. The bound makes freshness enforceable without unbounded state; once exhausted, the session fails closed and must be re-established rather than forgetting old keys.
