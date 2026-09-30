# ADR-0112: Protected device delivery reuses canonical Device lifecycle

Status: Accepted

## Context

Canon requires a revoked Device to receive no new protected content. UCR already had one durable
`DeviceLifecycleStore` and used it to gate trusted-key provisioning and resolver-backed
authentication, but protected Store-and-Forward delivery planned routes from Endpoint/Identity
metadata without consulting durable Device lifecycle. A stale discovered Endpoint could therefore
remain route-eligible after its Device was revoked.

Creating a transport-local revocation registry would violate the single canonical Device owner and
the prohibition on a second communication/security brain.

## Decision

`TransportOrchestrator` exposes `plan_protected`, which composes normal policy/identity/capability
route eligibility with the canonical durable `DeviceLifecycleStore`.

For `EndpointKind::Device`, a protected route is eligible only when the exact scoped Device:

- exists in the canonical lifecycle store;
- owns the target Identity represented by the CommunicationIntent;
- is in `DeviceLifecycleState::Active`.

Missing, Stale, ReverificationRequired, Expired, and Revoked Devices are filtered before any
`TransportProvider` invocation. A durable-store read failure fails closed as
`DeviceLifecycleUnavailable`. Non-Device endpoints retain the normal transport eligibility rules.

`StoreForwardRuntime::new_protected_origin` uses this protected planner for newly created protected
Device content at the origin. The ordinary `StoreForwardRuntime::new` path remains the opaque relay
mode: it forwards an already-created encrypted envelope without requiring the intermediary to own or
replicate the recipient's Device lifecycle state. This preserves minimum disclosure while ensuring
content created after revocation cannot be emitted toward the revoked Device by the origin.

## Security and privacy impact

Revocation now blocks the implemented origin-side protected Store-and-Forward transport path before
ciphertext is handed to a provider. The origin transport receives no new envelope for a revoked
Device. An intermediary receives only the already-created opaque envelope and routing material it
needs; it does not receive or own the recipient Device lifecycle registry. No plaintext is introduced
into routing and no second Device registry is created.

## Compatibility and migration

The durable Device schema is unchanged. Origin stores used with `new_protected_origin` implement the
existing `DeviceLifecycleStore`; both reference Memory and SQLite stores already do. The origin must
have the recipient Device lifecycle record before newly protected Device routing can succeed.
Unknown Device state intentionally fails closed. Opaque relay mode does not require that lifecycle
record and therefore does not expand intermediary metadata visibility.

## Rollback

Rollback means reverting the protected planner and protected-origin StoreForward wiring together.
Retaining only the protected-origin DeviceLifecycleStore dependency without the routing gate, or
retaining only the routing API without using it in protected delivery, is not a valid rollback
because either state would provide misleading security evidence.

## Testing

- TransportOrchestrator unit evidence proves Active succeeds and Revoked becomes NoEligibleRoute.
- StoreForward integration evidence proves a revoked Device causes zero origin provider invocations.
- Opaque relay evidence proves forwarding succeeds without a recipient Device lifecycle record.
- Canon §263 system E2E proves post-restart revocation prevents new protected content from reaching
  the transport provider.
- architecture guards bind StoreForwardRuntime to `plan_protected` and preserve the single
  DeviceLifecycleStore owner.
