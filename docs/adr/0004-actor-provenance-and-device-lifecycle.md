# ADR-0004: Actor Provenance and Device Lifecycle Vocabulary

Status: Accepted

## Problem

Communication provenance becomes ambiguous if author, delegated principal, source endpoint/integration, identity evidence, and device state are collapsed into booleans or provider-specific fields. That permits AI/bot impersonation and makes revocation semantics transport-dependent.

## Existing state

The Canon separates Principal from Actor, requires `author`, `on_behalf_of`, and `origin`, requires typed identity evidence, and defines Active/Stale/Reverification Required/Expired/Revoked device states.

## Decision

Keep ActorKind explicit. Delegation uses `on_behalf_of` without changing ActorKind. Add generic OriginRef composed only of canonical Principal/Endpoint/Integration references. Add typed identity-evidence and device-lifecycle vocabularies to the public contract.
## Alternatives rejected

- `verified: bool`: loses evidence type and provenance.
- Provider-specific `origin_*` fields: couples canonical messages to current integrations.
- Encoding AI/bot actions as Person when delegated: violates actor transparency.
- Device status owned by each transport: creates multiple revocation truths.

## Security impact

An OriginRef with no canonical source is invalid. Revoked remains a distinct security state; later crypto/device-key code must deny new protected content and credentials to revoked devices. ActorKind remains visible even with delegation.

## Privacy impact

Origin contains opaque canonical IDs only. It does not require plaintext phone/email/provider account data. Normal OpaqueId debug redaction continues to apply.
## Compatibility impact

New protobuf enums/messages and MessageEnvelope field 11 are additive. Existing field numbers are not reused. `UNSPECIFIED` enum zero values remain wire defaults only and are not valid semantic states.

## Migration and rollback

There is no production persisted message/device data yet. Rollback is source-only at this phase. Any future persisted origin/device state will require explicit migration and compatibility rules.

## Testing strategy

Architecture tests verify the public Actor/Origin/Device vocabulary and prohibit collapsing author into a Person-only field. Unit tests reject empty OriginRef. Public protobuf compilation and debug/release test suites remain mandatory CI checks.
