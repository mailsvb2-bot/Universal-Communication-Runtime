# Python SDK surface

Generate Python protobuf and gRPC client stubs from the repository `proto/ucr/v1` schema root.
Use `ucr_sdk.auth.ServiceCredential.metadata()` as call metadata for generated `IntegrationService`, `EventService`, `CallService`, `GroupService`, `DeviceService`, `SyncService`, `StoreForwardService`, `LocalTransportService`, `MeshService`, `RecoveryService`, `UniversalConferenceService` and `RecordingService` stubs.

## High-level Universal Conference client

The high-level client also covers conference resolution, participant removal/listing, raised-hand listing and capability discovery through the same canonical `/v1` boundary.

`ucr_sdk.UniversalConferenceClient` is a thin REST facade over the same canonical `/v1` Universal Conference contract. It covers conference lifecycle, bounded conference metadata create/replacement, participant/device enrollment, host participant controls through the canonical participant update path, runtime preparation, join-grant issuance/revocation, media subscriptions and attendance. Metadata values are supplied as bytes-like values and the SDK only performs the Base64 REST encoding; canonical namespacing, limits and idempotency remain server-owned.

The client:
- accepts integration-owned external references rather than internal UCR Principal/Device/Call/Group IDs;
- requires HTTPS outside explicit loopback development;
- rejects authenticated redirects so a machine Bearer cannot be forwarded to another origin;
- performs exactly one request per method call and never hides retry policy;
- preserves canonical error `code`, `retryable` and `retry_after_ms`;
- validates participant mutation field names instead of silently forwarding arbitrary data.

`UniversalConferenceService` and Recording management RPCs may alternatively use the standard `Authorization: Bearer <access-token>` machine credential accepted by the public ingress. Do not present Bearer and Service Credential metadata together; mixed authentication schemes fail closed. `RecordingService.SetRecordingConsent` instead requires the participant's short-lived join Bearer; participant-session services such as that consent RPC and `RealtimeService` are not covered by the Service Credential helper.

In a direct UCR deployment, generated `RecordingService` clients target the realtime gRPC listener while ordinary machine APIs target the API listener; a trusted gateway may co-host or route both. The helpers keep credential bytes opaque, redact diagnostics and contain no canonical domain model or retry engine.
Generated code is build output; the checked-in `.proto` files remain the contract source.

Phase 39 does not publish a PyPI artifact or pin external generator tooling; package publication belongs to later supply-chain hardening.
