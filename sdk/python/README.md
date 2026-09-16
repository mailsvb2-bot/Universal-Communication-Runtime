# Python SDK surface

Generate Python protobuf and gRPC client stubs from the repository `proto/ucr/v1` schema root.
Use `ucr_sdk.auth.ServiceCredential.metadata()` as call metadata for generated `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService` and `StoreForwardService` stubs.

The helper keeps credential bytes opaque, redacts diagnostics and contains no canonical domain model or retry engine.
Generated code is build output; the checked-in `.proto` files remain the contract source.

Phase 39 does not publish a PyPI artifact or pin external generator tooling; that belongs to later supply-chain hardening.
