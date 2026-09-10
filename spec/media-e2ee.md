# UCR E2EE Media

Status: **Prepared reference implementation, not Production.**

Phase 22 protects realtime encoded Audio and Video payloads without creating a second Call, Identity, Group, capability-negotiation, or transport owner. It composes the existing UCR v1 cryptographic suite and the exact media negotiation referenced by `CallSession`.

## Direct-call security context

One `MediaE2eeContext` binds the exact tenant/namespace scope, Call ID, ordered initiator/responder principals, their exact Device IDs, media negotiation reference and generation, explicit non-zero key epoch, and negotiated crypto suite. The context is ephemeral security metadata rather than durable Call or route state.

The context fingerprint uses the domain `UCR-MEDIA-E2EE-CONTEXT-V1`. A media handshake binding then adds fresh ordered X25519 ephemeral public keys under `UCR-MEDIA-E2EE-HANDSHAKE-V1`. Reusing the same initiator/responder ephemeral key or using an invalid context fails closed.

## Authenticated peer requirement

E2EE Media accepts only an already-established UCR Crypto session whose peer was independently resolved through the trusted signing-key/Active Device boundary. A raw crypto session that verified a caller-supplied public key but has no trusted Device provenance is insufficient. The proven peer Device must exactly match the Device declared for the opposite media participant.

Peer signature verification, handshake replay protection, contributory X25519 agreement, directional HKDF keys, and key confirmation remain owned by `ucr-crypto`; Phase 22 does not reimplement them.

## Frame protection

Phase 22 encrypts the encoded Opus or H.264 payload with the existing direction-specific XChaCha20-Poly1305 traffic key. There is no plaintext fallback API.

Every clear header field is authenticated as AEAD associated data under `UCR-MEDIA-E2EE-FRAME-AAD-V1`: scope, Call, stream, source, recipient, negotiation reference/generation, key epoch, crypto suite, exact authenticated session binding, media kind, sequence, media timestamp, and video keyframe bit. Nonce, ciphertext, payload and debug surfaces are bounded/redacted.

Tampering with ciphertext, nonce, or any authenticated header field returns no plaintext. Audio/video codec validation is performed at the existing media boundaries before sealing and after opening.

## Cryptographic replay protection

Replay state is per `(media kind, stream ID)` and key epoch. An inbound sequence must strictly increase. Crucially, the replay cursor is advanced only after AEAD authentication succeeds, so forged unauthenticated high sequence numbers cannot poison receiver state.

Outbound sequence reuse/regression within one key epoch is rejected before encryption. Per-epoch sender/receiver stream state is bounded to 64 distinct stream keys.

## Key lifecycle and rotation

Key epoch starts at 1. Explicit rotation requires exactly `epoch + 1`, identical Call/participants/Devices/negotiation/suite context, a newly authenticated peer session, and fresh role-specific X25519 ephemeral keys. Successful rotation clears per-stream replay/sequence cursors for the new epoch. Skipping epochs, changing the bound context, or reusing either role ephemeral fails closed.

A Call media renegotiation changes the canonical negotiation generation/ref and therefore invalidates an open E2EE media session until a fresh E2EE context/session is established.

## Runtime authority and downgrade behavior

Every seal/open operation rechecks current Call participant authority, exact direct-call participant set, current media-negotiation ref/generation, negotiated `ucr.media.e2ee`, runtime E2EE capability availability, and the existing Audio/Video send/receive permission. Removing E2EE capability or authority stops an already-open session. No code path silently converts E2EE media to plaintext for availability.

Unsupported critical negotiation extensions fail closed.

## Group/SFU boundary

Phase 22 deliberately does **not** invent pairwise full-mesh group crypto, a home-grown group KDF, or an SFU plaintext model. Group calls fail closed with `GroupCryptoUnavailable` until a standardized group-media crypto owner can satisfy membership-bound epoch/rekey and revoked-member isolation requirements. The existing Group model already has an opaque MLS-capability crypto-state boundary; this phase does not claim that group/SFU E2EE is implemented.

SFU routing and conferences remain Phase 29/30. An SFU must not automatically gain plaintext media access.

## Explicit nonclaims

Phase 22 does not implement OS microphone/camera capture, speaker/display output, RTP/SRTP/WebRTC, a media network data plane, Adaptive Media, Transport Orchestrator, Automatic Failover, group MLS key establishment, SFU, conferences, production OS/hardware-backed key providers, or production deployment. Prepared is not Production.

## Evidence

Reference tests cover real Opus and H.264 encode → E2EE seal → authenticated open → decode; ciphertext/nonce/AAD tamper; trusted-peer Device binding; raw-session rejection; cryptographic replay; forged-high-sequence non-poisoning; outbound sequence regression; media-renegotiation invalidation; permission/capability revocation; bounded stream state; explicit epoch rotation and ephemeral reuse rejection; unsupported/missing negotiation state; and fail-closed group calls. Public protocol validation has a bounded fuzz target.
