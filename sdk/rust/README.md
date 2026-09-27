# Rust SDK

The executable Prepared Rust SDK lives in `crates/ucr-sdk`.
Its build script generates client-only Tonic bindings from every checked-in `proto/ucr/v1/*.proto` file.

`UcrSdkClient` wraps the `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService`, `StoreForwardService`, `LocalTransportService`, `MeshService`, `RecoveryService`, `UniversalConferenceService` and `RecordingService` management RPCs, attaches Service Credential authentication automatically, and returns canonical generated responses unchanged.

The public Conference and Recording management ingress also accepts standard `Authorization: Bearer <access-token>` machine credentials. The current `UcrSdkClient` helper is the Service Credential path; callers using machine Bearer must construct the generated client request metadata explicitly and must not mix Bearer with Service Credential metadata. `RecordingService.SetRecordingConsent` is deliberately not wrapped by the Service Credential helper: participant consent requires the participant's short-lived join Bearer and remains a join/session credential boundary, like `RealtimeService`. Direct deployments should use `UcrSdkClient::connect_with_recording_endpoint(...)` with the ordinary API listener and the realtime listener; `connect(...)` remains valid when a trusted gateway co-hosts/routes both service paths.

It has no runtime dependency on `ucr-core` or a storage crate and performs no automatic UCR operation retry.

The SDK is source-distribution evidence only; crates.io publication and package signing are not claimed in Phase 39.
