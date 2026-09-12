# UCR E2EE Media

Status: **Prepared reference implementation, not Production.**

Phase 22 protects realtime encoded Audio and Video payloads without creating a second Call, Identity, Group, capability-negotiation, or transport owner. It composes the existing UCR v1 cryptographic suite and the exact media negotiation referenced by `CallSession`.

## Direct-call security context

One `MediaE2eeContext` binds the exact tenant/namespace scope, Call ID, ordered initiator/responder principals, their exact Device IDs, media negotiation reference and generation, explicit non-zero key epoch, and negotiated crypto suite. The context is ephemeral security metadata rather than durable Call or route state.

The context fingerprint uses the domain `UCR-MEDIA-E2EE-CONTEXT-V1`. A media handshake binding then adds fresh ordered X25519 ephemeral public keys under `UCR-MEDIA-E2EE-HANDSHAKE-V1`. Reusing the same initiator/responder ephemeral key or using an invalid context fails closed.

## Authenticated peer requirement

E2EE Media accepts only an already-established UCR Crypto session whose peer was independently resolved through the trusted signing-key/Active Device boundary. A raw crypto session that verified a caller-supplied public key but has no trusted Device provenance is insufficient. In the Phase 22 reference path, direct-call media participants are exact `Device` principals: the participant Principal ID must equal the declared canonical Device ID, and that Device must exist as an `Active` durable `DeviceDescriptor`. This deliberately avoids guessing an unimplemented Person→Identity association. A different trusted Device, even one with a valid signature and another durable Identity, cannot impersonate the accepted Call participant.

Peer signature verification, handshake replay protection, contributory X25519 agreement, directional HKDF keys, and key confirmation remain owned by `ucr-crypto`; Phase 22 does not reimplement them.

## Frame protection

Phase 22 encrypts the encoded Opus or H.264 payload with the existing direction-specific XChaCha20-Poly1305 traffic key. There is no plaintext fallback API.

Every clear header field is authenticated as AEAD associated data under `UCR-MEDIA-E2EE-FRAME-AAD-V1`: scope, Call, stream, source, recipient, negotiation reference/generation, key epoch, crypto suite, exact authenticated session binding, media kind, sequence, media timestamp, and video keyframe bit. Nonce, ciphertext, payload and debug surfaces are bounded/redacted.

Tampering with ciphertext, nonce, or any authenticated header field returns no plaintext. Audio/video codec validation is performed at the existing media boundaries before sealing and after opening.

## Cryptographic replay protection

Replay state is per `(media kind, stream ID)` and key epoch. An inbound sequence must strictly increase. Crucially, the replay cursor is advanced only after AEAD authentication succeeds, so forged unauthenticated high sequence numbers cannot poison receiver state.

Outbound sequence reuse/regression within one key epoch is rejected before encryption. Per-epoch sender/receiver stream state is bounded to 64 distinct stream keys.

## Key lifecycle and rotation

Key epoch starts at 1. Explicit rotation requires exactly `epoch + 1`, identical Call/participants/Devices/negotiation/suite context, a newly authenticated peer session, and fresh role-specific X25519 ephemeral keys. Successful rotation clears per-stream replay/sequence cursors for the new epoch. Skipping epochs, changing the bound context, or reusing either role ephemeral from any earlier epoch in the same session lifecycle fails closed. Ephemeral-history state is bounded to 64 key epochs; further rotation fails closed instead of forgetting older keys.

A Call media renegotiation changes the canonical negotiation generation/ref and therefore invalidates an open E2EE media session until a fresh E2EE context/session is established.

## Runtime authority and downgrade behavior

Every seal/open operation rechecks current Call participant authority, exact direct-call participant set, current media-negotiation ref/generation, negotiated `ucr.media.e2ee`, runtime E2EE capability availability, and the existing Audio/Video send/receive permission. It also re-resolves both bound Devices through the canonical `DeviceLifecycleStore` and re-validates the exact peer signing descriptor through the canonical `TrustedSigningKeyResolver` using the Device's durable Identity. Revoking a bound Device, revoking/rotating its authenticated signing key, removing E2EE capability, or removing authority therefore stops an already-open session on the next frame. No code path silently converts E2EE media to plaintext for availability.

Unsupported critical negotiation extensions fail closed.

## Group/SFU boundary

Phase 22 deliberately did **not** invent pairwise full-mesh group crypto, a home-grown group KDF, or an SFU plaintext model. Its direct-call path still fails closed for Group calls. Phase 29 now adds a separate standardized OpenMLS/RFC-9420 group-media owner that satisfies membership-bound epoch/rekey and removed-member isolation, while preserving this Phase-22 direct-call contract unchanged.

Phase 29 adds Prepared RFC-9420/OpenMLS-backed group-media E2EE and encrypted SFU fan-out without plaintext/key access. Phase 30 now composes that boundary into Conference coordination while retaining the same no-plaintext/no-key SFU rule; an SFU never automatically gains plaintext media access.

## Explicit nonclaims

Phase 22 itself does not implement OS microphone/camera capture, speaker/display output, RTP/SRTP/WebRTC, a media network data plane, Adaptive Media, Transport Orchestrator, Automatic Failover, group MLS key establishment, SFU, conferences, production OS/hardware-backed key providers, or production deployment. Group MLS/SFU are implemented by the separate Phase-29 layer; they do not widen Phase-22 direct-call semantics. Prepared is not Production.

## Evidence

Reference tests cover real Opus and H.264 encode → E2EE seal → authenticated open → decode; ciphertext/nonce/AAD tamper; exact Call-participant↔Device binding including a foreign trusted-Device impersonation attempt; raw-session rejection; post-open Device and signing-key revocation; cryptographic replay; forged-high-sequence non-poisoning; outbound sequence regression; media-renegotiation invalidation; permission/capability revocation; bounded stream state; explicit epoch rotation including non-adjacent historical ephemeral reuse rejection; unsupported/missing negotiation state; and fail-closed group calls. Public protocol validation has a bounded fuzz target.
