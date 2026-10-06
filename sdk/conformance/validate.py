#!/usr/bin/env python3
"""Fail-closed Phase-41 SDK conformance matrix validator."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "sdk/conformance/matrix.json"
CONTRACT = ROOT / "sdk/contract.json"
CATEGORIES = [
    "auth",
    "commands",
    "events",
    "retries",
    "permissions",
    "version_negotiation",
    "errors",
    "idempotency",
]
LANGUAGES = ["rust", "python", "typescript", "kotlin", "swift"]
INTEGRATION_CATEGORIES = [
    "auth",
    "create",
    "join",
    "leave",
    "webhook",
    "idempotency",
    "expiry",
    "permissions",
    "tenant_isolation",
]
ID_KEY = "ucr-service-credential-id-bin"
SECRET_KEY = "ucr-service-credential-secret-bin"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def read(path: str) -> str:
    file = ROOT / path
    require(file.is_file(), f"missing Phase-41 evidence: {path}")
    return file.read_text(encoding="utf-8")


def main() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    require(matrix["schema_version"] == 1, "unsupported conformance matrix schema")
    require(matrix["phase"] == 41, "conformance matrix is not Phase 41")
    require(matrix["maturity"] == "prepared", "Phase 41 overclaims maturity")
    require(matrix["profile"] == "sdk", "unexpected Phase-41 profile")
    require(matrix["protocol_package"] == contract["protocol_package"] == "ucr.v1", "protocol package drifted")
    require(matrix["required_categories"] == CATEGORIES, "canonical SDK conformance categories drifted")
    require(matrix["required_languages"] == LANGUAGES, "required SDK language set drifted")
    require(contract["languages"] == LANGUAGES, "Phase-39 SDK language set drifted")
    integration_profile = matrix.get("integration_profile")
    require(isinstance(integration_profile, dict), "missing integration conformance profile")
    require(
        integration_profile.get("required_categories") == INTEGRATION_CATEGORIES,
        "integration conformance categories drifted",
    )
    require(
        integration_profile.get("evidence_levels") == ["contract", "runtime-binding"],
        "integration conformance evidence levels drifted",
    )

    expected_levels = {
        "rust": ["contract", "host-probe", "runtime-binding"],
        "python": ["contract", "host-probe"],
        "typescript": ["contract", "host-probe"],
        "kotlin": ["contract", "host-probe"],
        "swift": ["contract", "host-probe"],
    }
    for language in LANGUAGES:
        evidence = matrix["languages"].get(language)
        require(isinstance(evidence, dict), f"missing language evidence: {language}")
        require(evidence.get("levels") == expected_levels[language], f"evidence level drifted: {language}")
        helper = evidence.get("helper")
        probe = evidence.get("probe")
        require(isinstance(helper, str) and (ROOT / helper).is_file(), f"missing helper: {language}")
        require(isinstance(probe, str) and (ROOT / probe).is_file(), f"missing probe: {language}")

        helper_source = read(helper)
        require(ID_KEY in helper_source, f"credential id metadata drifted: {language}")
        require(SECRET_KEY in helper_source, f"credential secret metadata drifted: {language}")
        require("[REDACTED]" in helper_source, f"credential redaction missing: {language}")
        lowered = helper_source.lower()
        for forbidden in ("ucr-storage", "ucr_core", "ucr-core", "sqlite"):
            require(forbidden not in lowered, f"SDK helper imports canonical owner {forbidden}: {language}")

    services = contract["services"]
    require("UniversalConferenceService" in services, "UniversalConferenceService disappeared from SDK contract")
    require("RecordingService" in services, "RecordingService disappeared from SDK contract")
    recording_auth = contract["authentication"]["service_overrides"].get("RecordingService")
    require(isinstance(recording_auth, dict), "RecordingService auth boundary missing")
    require(
        recording_auth.get("accepted_schemes")
        == ["service_principal_binary_metadata", "oauth2_bearer"],
        "RecordingService management auth schemes drifted",
    )
    consent_auth = recording_auth.get("method_overrides", {}).get("SetRecordingConsent")
    require(isinstance(consent_auth, dict), "Recording consent method override missing")
    require(
        consent_auth.get("accepted_schemes") == ["join_bearer"],
        "Recording participant consent ceased to be join-Bearer authenticated",
    )

    transport = contract["transport"]
    require(transport.get("default_grpc_role") == "api", "default SDK gRPC endpoint role drifted")
    require(
        transport.get("service_endpoint_roles", {}).get("RecordingService") == "realtime",
        "RecordingService realtime endpoint role drifted",
    )

    semantics = contract["semantics"]
    require(semantics["automatic_application_retry"] is False, "hidden SDK retry enabled")
    require(semantics["event_cursor"] == "opaque", "Event cursor ceased to be opaque")
    require(semantics["canonical_errors_preserved"] is True, "canonical errors are not preserved")
    require(semantics["direct_database_access"] is False, "SDK direct database access enabled")

    integration = read("proto/ucr/v1/integration.proto")
    events = read("proto/ucr/v1/event_api.proto")
    runtime = read("proto/ucr/v1/runtime.proto")
    errors = read("proto/ucr/v1/errors.proto")
    public_sdks = read("spec/public-sdks.md")
    universal = read("proto/ucr/v1/universal_conference.proto")
    universal_service = read("crates/ucr-api-grpc/src/universal_conference_service.rs")
    authorized_runtime = read("crates/ucr-core/src/authorized_runtime.rs")
    memory_store = read("crates/ucr-storage-memory/src/lib.rs")
    sqlite_event_subscriptions = read(
        "crates/ucr-storage-sqlite/src/event_subscription_store.rs"
    )
    sqlite_universal_conferences = read(
        "crates/ucr-storage-sqlite/src/universal_conference_store.rs"
    )
    universal_store_contract = read("crates/ucr-core/src/universal_conference.rs")
    universal_spec = read("spec/universal-conference-api.md")
    service_request = read("crates/ucr-core/src/service_request.rs")
    service_control_protocol = read("crates/ucr-protocol/src/service_control.rs")
    memory_store = read("crates/ucr-storage-memory/src/lib.rs")
    sqlite_service_control = read("crates/ucr-storage-sqlite/src/service_control_store.rs")
    sqlite_store = read("crates/ucr-storage-sqlite/src/lib.rs")
    sqlite_recording_provider = read(
        "crates/ucr-storage-sqlite/src/recording_provider_store.rs"
    )
    sqlite_group_mls = read("crates/ucr-storage-sqlite/src/group_mls_store.rs")
    realtime_registry = read("crates/ucr-realtime/src/lib.rs")
    realtime_service = read("crates/ucr-api-grpc/src/realtime_service.rs")
    universal_conference_service = read("crates/ucr-api-grpc/src/universal_conference_service.rs")
    realtime_proto = read("proto/ucr/v1/realtime.proto")
    grpc_lib = read("crates/ucr-api-grpc/src/lib.rs")
    runtime_lib = read("crates/ucr-runtime/src/lib.rs")
    realtime_web = read("crates/ucr-realtime-web/src/main.rs")
    group_mls = read("crates/ucr-group-mls/src/lib.rs")
    sqlite_group_mls = read("crates/ucr-storage-sqlite/src/group_mls_store.rs")
    rate_limit_spec = read("spec/service-principal-rate-limits.md")
    resource_quota_spec = read("spec/service-resource-quotas.md")

    for marker in (
        "rpc SubmitCommand(IntegrationCommandRequest)",
        "CommandEnvelope command = 1;",
        "rpc SendMessage(IntegrationSendMessageRequest)",
    ):
        require(marker in integration, f"command contract anchor missing: {marker}")
    for marker in (
        "bytes token = 1;",
        "rpc PublishEvent(EventPublishRequest)",
        "rpc PollEvents(EventPollRequest)",
        "rpc AcknowledgeEvents(EventAcknowledgeRequest)",
    ):
        require(marker in events, f"event contract anchor missing: {marker}")
    for marker in (
        "message NegotiationHello",
        "message NegotiationResult",
        "OpaqueId command_id = 1;",
        "COMMAND_RECEIPT_STATUS_DUPLICATE",
    ):
        require(marker in runtime, f"runtime conformance anchor missing: {marker}")
    for marker in (
        "ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION",
        "ERROR_CODE_DOWNGRADE_REJECTED",
        "ERROR_CODE_PERMISSION_DENIED",
        "message ErrorEnvelope",
    ):
        require(marker in errors, f"error conformance anchor missing: {marker}")
    require("There is no hidden automatic application retry" in public_sdks, "retry boundary documentation drifted")
    require("Phase 41 owns the complete SDK conformance matrix" in public_sdks, "Phase-39 handoff to Phase 41 disappeared")

    integration_markers = (
        "rpc CreateConference",
        "rpc EnsureParticipant",
        "rpc IssueJoinGrant",
        "rpc RevokeJoinGrant",
        "rpc RemoveParticipant",
        "external_conference_id",
        "external_user_id",
        "integration_id",
        "idempotency_key",
        "ttl_seconds",
    )
    for marker in integration_markers:
        require(marker in universal, f"integration conformance anchor missing: {marker}")
    require("fn admit_integration(" in universal_service, "integration admission boundary missing")
    require(
        "actor.principal.principal_id.as_opaque() != integration_id.as_opaque()" in universal_service,
        "integration identity binding drifted",
    )
    for marker in (
        "EVENT_SUBSCRIPTION_MODE_WEBHOOK",
        "optional string webhook_uri = 4;",
        "repeated string event_types = 5;",
        "rpc CreateSubscription(EventCreateSubscriptionRequest)",
    ):
        require(marker in events, f"webhook transport anchor missing: {marker}")
    for marker, source in (
        ("require_event_subscription_owner", authorized_runtime),
        ("event.actor.on_behalf_of.as_ref() == Some(&subject.principal.principal_id)", authorized_runtime),
        ("event_visible_to_subscription_owner", memory_store),
        ("event_subscription_owners", sqlite_event_subscriptions),
        ("owner_principal_kind", sqlite_event_subscriptions),
    ):
        require(marker in source, f"Event subscription isolation anchor missing: {marker}")
    for marker in (
        "ucr.conference.attendance.joined.v1",
        "ucr.conference.attendance.left.v1",
        "ucr.conference.attendance.reconnected.v1",
        "ucr.conference.attendance.media_ready.v1",
    ):
        require(marker in universal_service, f"conference event anchor missing: {marker}")
    for marker in (
        "message UniversalConferenceLifecycleEvent",
        "UniversalConferenceLifecycle previous = 5;",
        "UniversalConferenceLifecycle current = 6;",
        "occurred_at_unix_ms = 8;",
    ):
        require(marker in universal, f"conference lifecycle payload anchor missing: {marker}")
    for marker in (
        '"ucr.conference.started"',
        '"ucr.conference.ended"',
        "transition_universal_conference_with_event",
        "UniversalConferenceLifecycleEvent",
    ):
        require(marker in universal_service, f"conference lifecycle event anchor missing: {marker}")
    require(
        "transition_universal_conference_with_event" in universal_store_contract,
        "atomic conference lifecycle Event store boundary missing",
    )
    require(
        "append_event_to_memory_state" in memory_store
        and "transition_universal_conference_with_event" in memory_store,
        "memory conference lifecycle Event atomicity missing",
    )
    require(
        "append_event_in_transaction" in sqlite_universal_conferences
        and "transition_universal_conference_with_event" in sqlite_universal_conferences,
        "SQLite conference lifecycle Event atomicity missing",
    )

    require(
        "ServiceRequestRateClass::ALL" in memory_store
        and "service_rate_limit_policies" in memory_store
        and "service_rate_limit_usage" in memory_store,
        "memory request rate-class storage boundary missing",
    )
    for marker in (
        "ServiceRequestRateClass::Management",
        "ServiceRequestRateClass::JoinIssuance",
        "ServiceRequestRateClass::Signaling",
        "ServiceRequestRateClass::MediaTransport",
    ):
        require(
            marker in service_control_protocol,
            f"canonical request rate classifier missing: {marker}",
        )
    require(
        "service_request_rate_class(&self.proof.permission)" in service_request,
        "Service Principal request gate lost canonical rate-class selection",
    )
    for marker in (
        "service_rate_limit_policies",
        "service_rate_limit_usage",
        "backfill_v37_rate_limits",
    ):
        require(marker in sqlite_service_control, f"SQLite request rate-limit anchor missing: {marker}")
    require(
        "SQLITE_SCHEMA_V37: u32 = 37" in sqlite_store,
        "request rate-limit migration anchor v37 missing",
    )
    require(
        "SQLITE_SCHEMA_V38: u32 = 38" in sqlite_store
        and "SQLITE_SCHEMA_V39: u32 = 39" in sqlite_store
        and "SQLITE_SCHEMA_V40: u32 = 40" in sqlite_store
        and "SQLITE_SCHEMA_V41: u32 = 41" in sqlite_store
        and "SQLITE_SCHEMA_V42: u32 = 42" in sqlite_store
        and "SQLITE_SCHEMA_V43: u32 = 43" in sqlite_store
        and "SQLITE_SCHEMA_V44: u32 = 44" in sqlite_store
        and "SQLITE_SCHEMA_V45: u32 = 45" in sqlite_store
        and "SQLITE_SCHEMA_V46: u32 = 46" in sqlite_store
        and "SQLITE_SCHEMA_V47: u32 = 47" in sqlite_store
        and "SQLITE_SCHEMA_V48: u32 = 48" in sqlite_store
        and "SQLITE_SCHEMA_VERSION: u32 = 49" in sqlite_store
        and "migrate_v38_to_v39" in sqlite_store
        and "migrate_v39_to_v40" in sqlite_store
        and "migrate_v40_to_v41" in sqlite_store
        and "migrate_v41_to_v42" in sqlite_store
        and "migrate_v42_to_v43" in sqlite_store
        and "migrate_v43_to_v44" in sqlite_store
        and "migrate_v44_to_v45" in sqlite_store
        and "migrate_v45_to_v46" in sqlite_store
        and "migrate_v46_to_v47" in sqlite_store
        and "migrate_v47_to_v48" in sqlite_store
        and "migrate_v48_to_v49" in sqlite_store
        and "create_v46_objects" in sqlite_universal_conferences
        and "verify_v46_objects" in sqlite_universal_conferences
        and "create_v47_objects" in sqlite_recording_provider
        and "verify_v47_objects" in sqlite_recording_provider
        and "create_v48_objects" in sqlite_recording_provider
        and "verify_v48_objects" in sqlite_recording_provider
        and "create_v49_objects" in sqlite_group_mls
        and "verify_v49_objects" in sqlite_group_mls
        and "group_mls_transition_admissions" in sqlite_group_mls
        and "service_audit_authentication" in sqlite_service_control
        and "verify_v44_objects" in sqlite_service_control,
        "resource quota v42, runtime worker lease v43, typed audit v44, attachment v45, conference metadata v46, recording provider outbox v47, ready marker v48, and device-bound MLS bootstrap v49 migration chain missing",
    )
    for marker in (
        "ServiceResourceQuotaPolicy",
        "max_concurrent_participants",
        "max_concurrent_conferences",
        "max_concurrent_publishers",
        "max_aggregate_bandwidth_bps",
        "max_recording_minutes",
        "service_resource_quota_policies",
        "service_recording_usage",
        "consume_service_recording_duration",
        "reset_service_recording_usage",
        "ensure_integration_participant_quota",
        "ensure_integration_conference_quota",
    ):
        require(
            marker in (
                service_control_protocol
                + sqlite_service_control
                + sqlite_universal_conferences
            ),
            f"resource quota contract anchor missing: {marker}",
        )
    for marker in (
        "concurrent participant, conference, publisher, aggregate bandwidth, and recording-minute quotas implemented",
        "`Scheduled` conferences do not consume quota",
        "first policy-authorized encrypted media publish attempt claims one slot",
        "every SFU recipient consumes one additional egress copy",
        "`max_recording_minutes`",
        "`consume_service_recording_duration`",
        "`reset_service_recording_usage`",
        "UCR owns no month, billing period, subscription renewal, or calendar-reset semantics",
    ):
        require(marker in resource_quota_spec, f"resource quota specification drifted: {marker}")
    for marker in (
        "claim_publisher_slot",
        "publisher_owner",
    ):
        require(marker in realtime_registry, f"publisher quota registry anchor missing: {marker}")
    for marker in (
        "claim_universal_publisher_quota",
        "claim_publisher_slot",
        "forward_authenticated_e2ee_media",
    ):
        require(marker in realtime_service, f"publisher quota ingress anchor missing: {marker}")
    for marker in (
        "charge_aggregate_bandwidth",
        "BandwidthWindow",
    ):
        require(marker in realtime_registry, f"bandwidth quota registry anchor missing: {marker}")
    for marker in (
        "universal_bandwidth_quota",
        "BandwidthQuotaSink",
        "encode_sfu_forward_envelope",
        "charge_aggregate_bandwidth",
    ):
        require(marker in realtime_service, f"bandwidth quota fanout anchor missing: {marker}")
    for marker in (
        "rpc GetMlsAdmissionContext(RealtimeGetMlsAdmissionContextRequest)",
        "rpc RegisterMlsKeyPackage(RealtimeRegisterMlsKeyPackageRequest)",
        "message RealtimeRegisterMlsKeyPackageRequest",
        "RealtimeMlsEndpointStateMode",
        "REALTIME_MLS_ENDPOINT_STATE_MODE_REGISTER",
        "REALTIME_MLS_ENDPOINT_STATE_MODE_RESTORE",
        "REALTIME_MLS_ENDPOINT_STATE_MODE_LEGACY_SERVER_OWNED",
    ):
        require(marker in realtime_proto, f"endpoint-owned MLS admission public contract missing: {marker}")
    for marker in (
        "RealtimeMlsAdmissionStore",
        "with_mls_admission_store",
        "mls_admission_context",
        "register_endpoint_mls_key_package",
        "MAX_MLS_KEY_PACKAGE_BYTES",
    ):
        require(marker in realtime_service, f"endpoint-owned MLS admission core missing: {marker}")
    require(
        ".with_mls_admission_store(Arc::clone(&store))" in runtime_lib,
        "production runtime does not wire canonical endpoint MLS admission store",
    )
    require(
        '"/v1/realtime/mls-context"' in realtime_web
        and '"/v1/realtime/mls-key-package"' in realtime_web
        and "client.get_mls_admission_context(request).await" in realtime_web
        and "client.register_mls_key_package(request).await" in realtime_web
        and "legacy_server_owned" in realtime_web,
        "reference browser gateway does not expose endpoint-owned MLS admission handshake",
    )
    require(
        "create_mls_device_key_package(&owner.scope, &participant.device_id)"
        not in universal_conference_service,
        "Universal Conference still creates participant MLS KeyPackages server-side",
    )
    require(
        "REALTIME_MLS_KEY_PACKAGE_REQUEST_WIRE_MAX_BYTES" in grpc_lib
        and "GRPC_MAX_DECODING_MESSAGE_SIZE >= REALTIME_MLS_KEY_PACKAGE_REQUEST_WIRE_MAX_BYTES" in grpc_lib,
        "gRPC receive budget does not cover endpoint MLS KeyPackage registration",
    )

    for marker in (
        "rpc GetMlsBootstrap(RealtimeGetMlsBootstrapRequest)",
        "message RealtimeMlsBootstrap",
        "message RealtimeMlsBootstrapCommit",
    ):
        require(marker in realtime_proto, f"realtime MLS bootstrap public contract missing: {marker}")
    for marker in (
        "with_mls_bootstrap_store",
        "device_bound_mls_bootstrap",
        "mls_bootstrap_for_device(&claims.scope, &snapshot.group_id, device_id)",
        "bootstrap.current_crypto_state.epoch != snapshot.group_crypto_epoch",
        "current_ref != &snapshot.group_crypto_state_ref",
    ):
        require(marker in realtime_service, f"realtime MLS bootstrap ingress anchor missing: {marker}")
    require(
        ".with_mls_bootstrap_store(Arc::clone(&store))" in runtime_lib,
        "production runtime does not wire canonical SQLite MLS bootstrap store",
    )
    require(
        '"/v1/realtime/mls-bootstrap"' in realtime_web
        and "client.get_mls_bootstrap(request).await" in realtime_web
        and "welcome_base64: STANDARD.encode(bootstrap.welcome)" in realtime_web,
        "reference browser gateway does not expose authenticated MLS bootstrap projection",
    )
    require(
        "REALTIME_MLS_BOOTSTRAP_RESPONSE_WIRE_MAX_BYTES" in grpc_lib
        and "GRPC_MAX_ENCODING_MESSAGE_SIZE >= REALTIME_MLS_BOOTSTRAP_RESPONSE_WIRE_MAX_BYTES" in grpc_lib,
        "gRPC send budget does not cover bounded MLS bootstrap response",
    )
    require(
        "MAX_MLS_BOOTSTRAP_COMMITS: usize = 64" in group_mls
        and "MAX_MLS_BOOTSTRAP_BYTES: usize = 8 * 1024 * 1024" in group_mls
        and "BootstrapTooLarge" in group_mls
        and "group_mls_transition_admissions" in sqlite_group_mls
        and "commits.len() > MAX_MLS_BOOTSTRAP_COMMITS" in sqlite_group_mls
        and "total_bytes > MAX_MLS_BOOTSTRAP_BYTES" in sqlite_group_mls,
        "bounded exact-device MLS bootstrap storage anchors missing",
    )

    for marker in (
        "management",
        "join_issuance",
        "signaling",
        "media_transport",
        "does **not** complete UCR resource quotas",
    ):
        require(marker in rate_limit_spec, f"request rate-limit specification drifted: {marker}")

    workflow = read(".github/workflows/conformance.yml")
    for marker in (
        "python3 sdk/conformance/validate.py",
        "sdk/python/phase41_conformance.py",
        "sdk/typescript/phase41_conformance.ts",
        "Phase41Conformance.kt",
        "sdk/swift/Tests/main.swift",
        "--test phase41_conformance",
    ):
        require(marker in workflow, f"Phase-41 workflow evidence missing: {marker}")
    require("continue-on-error" not in workflow, "Phase-41 workflow permits soft failure")
    require("|| true" not in workflow, "Phase-41 workflow masks failures")

    spec = read("spec/conformance-suite.md")
    adr = read("docs/adr/0087-phase41-conformance-suite-is-language-independent-and-fail-closed.md")
    require("eight semantic areas" in spec, "Phase-41 spec lost canonical eight-axis scope")
    require("integration profile" in spec, "integration conformance profile documentation missing")
    require("tenant isolation" in spec, "integration tenant-isolation conformance disappeared")
    require("not a new runtime" in spec, "Phase-41 second-brain boundary disappeared")
    require("Missing probes" in adr, "Phase-41 ADR lost fail-closed decision")

    print("UCR_PHASE41_CONFORMANCE_MATRIX_OK")


if __name__ == "__main__":
    main()
