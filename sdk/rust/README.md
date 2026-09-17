# Rust SDK

The executable Prepared Rust SDK lives in `crates/ucr-sdk`.
Its build script generates client-only Tonic bindings from every checked-in `proto/ucr/v1/*.proto` file.

`UcrSdkClient` wraps the `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService`, `StoreForwardService`, `LocalTransportService`, `MeshService` and `RecoveryService` RPCs, attaches authentication automatically, and returns canonical generated responses unchanged.
It has no runtime dependency on `ucr-core` or a storage crate and performs no automatic UCR operation retry.

The SDK is source-distribution evidence only; crates.io publication and package signing are not claimed in Phase 39.
