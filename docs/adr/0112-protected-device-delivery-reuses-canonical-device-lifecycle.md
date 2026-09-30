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

`StoreForwardRuntime` uses this protected planner for every opaque `encrypted_envelope`, so delayed
or intermediary delivery cannot bypass Device revocation merely because an old Endpoint remains
discoverable.

## Security and privacy impact

Revocation now blocks the implemented protected Store-and-Forward transport path before ciphertext
is handed to a provider. The transport receives no new envelope for a revoked Device. No plaintext
is introduced into routing and no new Device registry is created.

## Compatibility and migration

The durable Device schema is unchanged. Stores used by StoreForwardRuntime must implement the
existing `DeviceLifecycleStore`; both reference Memory and SQLite stores already do. Deployments
must have the recipient Device lifecycle record before protected Device routing can succeed.
Unknown Device state intentionally fails closed.

## Rollback

Rollback means reverting the protected planner and StoreForward wiring together. Retaining only the
StoreForward trait-bound without the routing gate, or retaining only the routing API without using
it in protected delivery, is not a valid rollback because either state would provide misleading
security evidence.

## Testing

- TransportOrchestrator unit evidence proves Active succeeds and Revoked becomes NoEligibleRoute.
- StoreForward integration evidence proves a revoked Device causes zero provider invocations.
- Canon §263 system E2E proves post-restart revocation prevents new protected content from reaching
  the transport provider.
- architecture guards bind StoreForwardRuntime to `plan_protected` and preserve the single
  DeviceLifecycleStore owner.
