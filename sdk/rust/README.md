# Rust SDK

The executable Prepared Rust SDK lives in `crates/ucr-sdk`.
Its build script generates client-only Tonic bindings from every checked-in `proto/ucr/v1/*.proto` file.

`UcrSdkClient` wraps the `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService`, `StoreForwardService`, `LocalTransportService`, `MeshService`, `RecoveryService` and `UniversalConferenceService` RPCs, attaches Service Credential authentication automatically, and returns canonical generated responses unchanged.

The public Conference ingress also accepts standard `Authorization: Bearer <access-token>` machine credentials. The current `UcrSdkClient` helper is the Service Credential path; callers using Bearer must construct the generated `UniversalConferenceServiceClient` request metadata explicitly and must not mix Bearer with Service Credential metadata. Participant-session services such as `RealtimeService` remain join/session-credential boundaries.

It has no runtime dependency on `ucr-core` or a storage crate and performs no automatic UCR operation retry.

The SDK is source-distribution evidence only; crates.io publication and package signing are not claimed in Phase 39.
