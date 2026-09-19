# Universal Conference Integration API

Status: **v1 public contract introduced; runtime wiring follows the existing canonical owners**.

This boundary exists so an external product can use UCR without understanding internal Group, Call, Principal or Device mechanics. It is business-neutral and must not contain product-specific names.

## External identity and room references

The integration key is `(TenantScope, IntegrationId, external reference bytes)`. Conference room resolution reuses the existing durable `GroupBridgeMapping` owner. Participant identity resolution reuses the existing durable `ExternalIdentityBinding` owner. UCR must not create a second user registry or require an integrator to persist internal UCR IDs.

`UniversalConferenceDescriptor.conference_id` is the stable UCR-facing conference handle. Internal Group/Call/MLS identifiers remain implementation details of the coordinator.

## Conference modes and lifecycle

The same Conference system supports `meeting`, `webinar`, `broadcast` and `audio_room`. Webinar is therefore a configuration, not a separate product or second communication engine.

Lifecycle metadata is separate from Call signalling:

`scheduled -> waiting -> live -> ending -> ended`

The lifecycle coordinator may project into canonical Group/Call state but must never become a second CallSession authority. Scheduled rooms may exist before a realtime Call is started.

## Participant roles and media policy

The public role vocabulary is `owner`, `host`, `moderator`, `speaker`, `attendee`. Role and media policy must be server-enforced; UI labels are never authorization evidence. Group membership remains canonical membership. Any role projection must fail closed if it conflicts with current membership.

## Join grants

`IssueJoinGrant` accepts external user identity and resolves canonical Identity/Principal/Device inside UCR. The integrator is not required to submit `PrincipalRef` or `DeviceId`.

Join grants are short-lived and conference-scoped. The contract reserves single-use/reusable policy, explicit not-before/not-after bounds and revocation. Runtime implementations must reject unsupported semantics rather than silently weakening them.

## Idempotency

All create/mutate operations carry an explicit idempotency key where appropriate. Exact retries must deduplicate durably; changed requests under the same idempotency identity must conflict.

## Transport adapters

gRPC is the typed source contract. REST/JSON, OpenAPI, JavaScript/TypeScript, Python, Kotlin, Swift and Rust SDKs must remain thin adapters over the same contract. No REST-only business rules are allowed.

## Product boundary

No CRM, funnel, payment, advertising, warm-up campaign or ClientPlatform-specific business concept belongs here. External products consume communication facts and apply their own business logic.
