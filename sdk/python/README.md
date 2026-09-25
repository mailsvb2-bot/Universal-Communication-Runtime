# Python SDK surface

Generate Python protobuf and gRPC client stubs from the repository `proto/ucr/v1` schema root.
Use `ucr_sdk.auth.ServiceCredential.metadata()` as call metadata for generated `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService`, `StoreForwardService`, `LocalTransportService`, `MeshService`, `RecoveryService` and `UniversalConferenceService` stubs.

`UniversalConferenceService` may alternatively use the standard `Authorization: Bearer <access-token>` machine credential accepted by the public Conference ingress. Do not present Bearer and Service Credential metadata together; mixed authentication schemes fail closed. Participant-session services such as `RealtimeService` remain join/session-credential boundaries and are not covered by the Service Credential helper.

The helper keeps credential bytes opaque, redacts diagnostics and contains no canonical domain model or retry engine.
Generated code is build output; the checked-in `.proto` files remain the contract source.

Phase 39 does not publish a PyPI artifact or pin external generator tooling; that belongs to later supply-chain hardening.
