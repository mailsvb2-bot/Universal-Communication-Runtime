#![forbid(unsafe_code)]

mod acknowledgement;
mod adaptive_media;
mod addressing;
mod anti_entropy;
mod audio;
mod authorization;
mod call;
mod capability;
mod commands;
mod crypto_contract;
mod crypto_negotiation;
mod delivery;
mod device_lifecycle;
mod error;
mod event_api;
mod extension;
mod framing;
mod group;
mod handshake;
mod id;
mod identity;
mod intent;
mod media_e2ee;
mod message;
mod message_signature;
mod provenance;
mod recovery;
mod scope;
mod service_control;
mod sync;
mod transport_failover;
mod transport_orchestrator;
mod trusted_key;
mod version;
mod video;

pub use acknowledgement::{
    AcknowledgementEnvelope, AcknowledgementError, acknowledgement_for, canonical_acknowledgement,
    validate_acknowledgement,
};
pub use adaptive_media::{
    ADAPTIVE_DEGRADE_CONFIRM_SAMPLES, ADAPTIVE_MEDIA_CAPABILITY, ADAPTIVE_RECOVERY_CONFIRM_SAMPLES,
    AdaptiveMediaProtocolError, MAX_ADAPTIVE_BANDWIDTH_BPS, MAX_ADAPTIVE_LATENCY_MS,
    OPUS_LOW_TARGET_BITRATE_BPS, OPUS_NORMAL_TARGET_BITRATE_BPS, adaptive_media_pressures,
    canonical_adaptive_media_telemetry, is_video_stage, one_step_better,
    phase23_adaptive_media_capabilities, reference_deferred_fallbacks,
    reference_opus_target_bitrate, reference_stage_for_telemetry, reference_video_config,
    stage_requires_media_renegotiation,
};
pub use addressing::{
    AddressingError, MAX_ADDRESS_VALUE_LEN, MAX_ENDPOINT_ADDRESSES, MAX_ENDPOINT_CAPABILITIES,
    MAX_EXTERNAL_ENTITY_ID_LEN, validate_endpoint_address, validate_endpoint_descriptor,
    validate_external_identity_binding, validate_external_identity_binding_key,
};
pub use anti_entropy::{
    ANTI_ENTROPY_SESSION_BINDING_V1_DOMAIN, AntiEntropyError, EVENT_FINGERPRINT_SHA256_V1_DOMAIN,
    MAX_ANTI_ENTROPY_CURSOR_LEN, MAX_ANTI_ENTROPY_PAGE_ITEMS, anti_entropy_session_binding,
    event_fingerprint, validate_anti_entropy_cursor, validate_anti_entropy_page_size,
    validate_anti_entropy_session, validate_anti_entropy_summary_count,
};
pub use audio::{
    AUDIO_MEDIA_CAPABILITY, AudioProtocolError, MANDATORY_AUDIO_SAMPLE_RATE_HZ,
    MAX_ENCODED_AUDIO_FRAME_BYTES, OPUS_AUDIO_CODEC_CAPABILITY, audio_samples_per_channel,
    canonical_audio_codec_config, canonical_audio_stream_descriptor, phase20_audio_capabilities,
    validate_audio_frame_for_stream,
};
pub use authorization::{
    ANTI_ENTROPY_READ_PERMISSION, ANTI_ENTROPY_RECONCILE_PERMISSION, AUDIO_RECEIVE_PERMISSION,
    AUDIO_SEND_PERMISSION, AuthorizationError, CALL_OBSERVE_PERMISSION, CALL_SIGNAL_PERMISSION,
    CALL_START_PERMISSION, COMMAND_ACCEPT_PERMISSION, COMMAND_OUTCOME_READ_PERMISSION,
    COMMAND_OUTCOME_WRITE_PERMISSION, COMMUNICATION_INTENT_READ_PERMISSION,
    COMMUNICATION_INTENT_WRITE_PERMISSION, CONVERSATION_READ_PERMISSION,
    CONVERSATION_WRITE_PERMISSION, DELIVERY_READ_PERMISSION, DELIVERY_WRITE_PERMISSION,
    DEVICE_READ_PERMISSION, DEVICE_REGISTER_PERMISSION, DEVICE_REVOKE_PERMISSION,
    EVENT_APPEND_PERMISSION, EVENT_CONSUME_PERMISSION, EVENT_DEAD_LETTER_READ_PERMISSION,
    EVENT_REPLAY_PERMISSION, EVENT_SUBSCRIBE_PERMISSION, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
    EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, GROUP_CREATE_PERMISSION, GROUP_MANAGE_PERMISSION,
    GROUP_READ_PERMISSION, GrantValidationError, IDENTITY_CREATE_PERMISSION,
    IDENTITY_READ_PERMISSION, MESSAGE_READ_PERMISSION, MESSAGE_WRITE_PERMISSION,
    PERMISSION_GRANT_CREATE_PERMISSION, PERMISSION_GRANT_READ_PERMISSION,
    PERMISSION_GRANT_REVOKE_PERMISSION, RECOVERY_PLAN_INSTALL_PERMISSION,
    RECOVERY_PLAN_READ_PERMISSION, RECOVERY_PLAN_REVOKE_PERMISSION,
    RECOVERY_PLAN_ROTATE_PERMISSION, RUNTIME_PERMISSION_IDS, SERVICE_AUDIT_READ_PERMISSION,
    SERVICE_CREDENTIAL_PROVISION_PERMISSION, SERVICE_CREDENTIAL_REVOKE_PERMISSION,
    SERVICE_QUOTA_READ_PERMISSION, SERVICE_QUOTA_WRITE_PERMISSION, SYNC_READ_PERMISSION,
    SYNC_WRITE_PERMISSION, TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
    TRUSTED_SIGNING_KEY_READ_PERMISSION, TRUSTED_SIGNING_KEY_REVOKE_PERMISSION,
    TRUSTED_SIGNING_KEY_ROTATE_PERMISSION, VIDEO_RECEIVE_PERMISSION, VIDEO_SEND_PERMISSION,
    authorize, is_service_principal, validate_permission_grant,
};
pub use call::{
    CALL_CREATION_FINGERPRINT_V1_DOMAIN, CALL_SIGNAL_FINGERPRINT_V1_DOMAIN, CallSignallingError,
    MAX_CALL_PARTICIPANTS, active_call_participant, apply_call_signal, call_creation_fingerprint,
    call_signal_event_type, call_signal_fingerprint, canonical_call_creation,
    canonical_call_session, is_call_conversation_kind, reconcile_group_call_membership,
};
pub use capability::{
    CapabilityDescriptor, CapabilityError, CapabilityMaturity, CapabilityRequirement,
    canonical_capabilities, canonical_capability_descriptor, negotiate_capabilities,
};
pub use commands::{
    CommandError, CommandReceipt, CommandReceiptStatus, EventError, IdempotencyDecision,
    MAX_COMMAND_PAYLOAD_LEN, MAX_EVENT_INTEGRITY_METADATA_LEN, MAX_EVENT_PAYLOAD_LEN,
    MAX_IDEMPOTENCY_KEY_LEN, ReceiptError, accepted_command_receipt, canonical_command,
    canonical_command_receipt, canonical_event, compare_command_idempotency,
    duplicate_command_receipt, validate_command, validate_command_receipt, validate_event,
};
pub use crypto_contract::{
    AEAD_ALGORITHM_ID, AGREEMENT_ALGORITHM_ID, ALGORITHM_VERSION, CRYPTO_SUITE_ID,
    CryptoContractError, ED25519_PUBLIC_KEY_LEN, HANDSHAKE_NONCE_LEN, KDF_ALGORITHM_ID,
    KEY_CONFIRMATION_TAG_LEN, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, SIGNATURE_LEN,
    TRANSCRIPT_BINDING_LEN, X25519_PUBLIC_KEY_LEN, validate_public_key_descriptor,
};
pub use crypto_negotiation::{
    CryptoNegotiationError, CryptoPolicy, CryptoSuite, negotiate_crypto_suite,
};
pub use delivery::{
    DeliveryError, can_transition_delivery, evidence_supports_state, is_terminal_delivery_state,
    validate_delivery_attempt, validate_delivery_evidence, validate_delivery_evidence_binding,
    validate_delivery_evidence_order, validate_delivery_transition,
};
pub use device_lifecycle::device_allows_protected_access;
pub use error::{
    CanonicalError, CanonicalErrorCode, ErrorEnvelope, ErrorEnvelopeError,
    canonical_error_envelope, error_envelope_from_canonical, validate_error_envelope,
};
pub use event_api::{
    EVENT_CONSUMER_CURSOR_V1_DOMAIN, EVENT_RETRY_BASE_MS, EVENT_RETRY_MAX_MS, EventApiError,
    MAX_EVENT_BATCH_ITEMS, MAX_EVENT_CONSUMER_CURSOR_LEN, MAX_EVENT_DELIVERY_ATTEMPTS,
    MAX_EVENT_DELIVERY_BATCH_BYTES, MAX_EVENT_DELIVERY_SIZE, MAX_EVENT_SUBSCRIPTION_FILTERS,
    MAX_WEBHOOK_URI_LEN, canonical_event_subscription, event_consumer_cursor_token,
    event_delivery_batch_next_size, event_delivery_size, event_matches_subscription,
    event_retry_delay_ms, validate_event_batch_size, validate_event_consumer_cursor,
    validate_event_subscription,
};
pub use extension::{
    ExtensionError, MAX_EXTENSION_PAYLOAD_LEN, MAX_NAMESPACED_IDENTIFIER_LEN,
    MAX_PROTOCOL_EXTENSIONS, canonical_protocol_extensions, require_supported_extensions,
    validate_extension_name, validate_namespaced_identifier,
};
pub use framing::{
    CURRENT_FRAMING_VERSION, DEFAULT_MAX_PAYLOAD_LEN, FRAME_HEADER_LEN, FRAME_MAGIC, FrameError,
    FrameHeader, FrameKind, FramePolicy, decode_frame_prefix, decode_header,
};
pub use group::{
    GROUP_CHANGE_FINGERPRINT_V1_DOMAIN, GROUP_MLS_CAPABILITY, GroupError, GroupTransition,
    MAX_EXTERNAL_GROUP_ID_LEN, MAX_GROUP_BRIDGE_MAPPINGS, MAX_GROUP_HISTORY_MESSAGES,
    MAX_GROUP_MEMBER_LIST, MAX_GROUP_MEMBERS, active_group_actor_role, apply_group_change,
    canonical_group_creation, canonical_group_membership, canonical_group_memberships,
    canonical_group_record, group_change_event_type, group_change_fingerprint,
    group_permissions_for_role, is_group_conversation_kind, validate_group_member_list_limit,
};
pub use handshake::{
    HandshakeError, NegotiatedSession, NegotiationPolicy, NegotiationResultEnvelope,
    NegotiationResultError, PeerHello, canonical_negotiation_result, negotiate_session,
    negotiation_result_for_session, validate_negotiation_result,
};
pub use id::{
    CANONICAL_ID_GENERATION_ALGORITHM_ID, CANONICAL_ID_RANDOM_BYTES, CANONICAL_ID_TEXT_LEN,
    NativeIdEncodingError, encode_native_opaque_id,
};
pub use identity::{IdentityError, validate_identity_record};
pub use intent::{
    IntentError, MAX_INTENT_IDEMPOTENCY_KEY_LEN, MAX_INTENT_POLICY_VALUE_LEN,
    MAX_INTENT_TRANSPORT_CONSTRAINTS, canonical_communication_intent,
    validate_communication_intent,
};
pub use media_e2ee::{
    MAX_ENCRYPTED_MEDIA_PAYLOAD_BYTES, MAX_MEDIA_KEY_EPOCHS_PER_SESSION,
    MAX_MEDIA_STREAMS_PER_EPOCH, MEDIA_E2EE_AEAD_TAG_LEN, MEDIA_E2EE_CAPABILITY,
    MEDIA_E2EE_CONTEXT_V1_DOMAIN, MEDIA_E2EE_FRAME_AAD_V1_DOMAIN, MEDIA_E2EE_NONCE_LEN,
    MEDIA_E2EE_SESSION_BINDING_LEN, MediaE2eeProtocolError, canonical_media_e2ee_context,
    media_e2ee_context_binding, media_e2ee_frame_aad, phase22_media_e2ee_capabilities,
    validate_encrypted_media_frame,
};
pub use message::{
    ConversationError, EXTERNAL_MESSAGE_ID_LIMIT, EXTERNAL_MESSAGE_MAPPING_LIMIT,
    MESSAGE_ATTACHMENT_LIMIT, MESSAGE_CRYPTO_METADATA_LIMIT, MESSAGE_RELATION_LIMIT, MessageError,
    canonical_message, validate_conversation, validate_conversation_parent_kind, validate_message,
};
pub use message_signature::{
    MESSAGE_SIGNING_BINDING_V1_DOMAIN, MessageSigningBinding, message_signing_binding,
};
pub use provenance::{ProvenanceError, validate_origin_ref};
pub use recovery::{
    MAX_RECOVERY_AUTHORITIES, RecoveryError, canonical_recovery_plan, recovery_plan_aad,
    validate_recovery_plan, validate_recovery_request,
};
pub use scope::{ScopeError, ScopeRelation, require_exact_scope, scope_relation};
pub use service_control::{
    MAX_SERVICE_AUDIT_OPERATION_KIND_LEN, MAX_SERVICE_AUDIT_READ_ITEMS,
    MAX_SERVICE_REQUEST_PERMISSION_LEN, SERVICE_AUDIT_CALL_OBSERVE_OPERATION_KIND,
    SERVICE_AUDIT_CALL_SIGNAL_OPERATION_KIND, SERVICE_AUDIT_CALL_START_OPERATION_KIND,
    SERVICE_AUDIT_COMMAND_OPERATION_KIND, SERVICE_AUDIT_COMMUNICATION_INTENT_CREATE_OPERATION_KIND,
    SERVICE_AUDIT_COMMUNICATION_INTENT_READ_OPERATION_KIND,
    SERVICE_AUDIT_CONVERSATION_CREATE_OPERATION_KIND,
    SERVICE_AUDIT_CONVERSATION_READ_OPERATION_KIND, SERVICE_AUDIT_EVENT_ACK_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_DEAD_LETTER_READ_OPERATION_KIND, SERVICE_AUDIT_EVENT_POLL_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_PUBLISH_OPERATION_KIND, SERVICE_AUDIT_EVENT_REJECT_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_REPLAY_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_SUBSCRIPTION_CREATE_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_SUBSCRIPTION_READ_OPERATION_KIND,
    SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND,
    SERVICE_AUDIT_EXTERNAL_IDENTITY_READ_OPERATION_KIND, SERVICE_AUDIT_HASH_LEN,
    SERVICE_AUDIT_HASH_V1_DOMAIN, SERVICE_AUDIT_HASH_V2_DOMAIN,
    SERVICE_AUDIT_IDENTITY_CREATE_OPERATION_KIND, SERVICE_AUDIT_IDENTITY_READ_OPERATION_KIND,
    SERVICE_AUDIT_MESSAGE_READ_OPERATION_KIND, SERVICE_AUDIT_MESSAGE_SEND_OPERATION_KIND,
    ServiceControlValidationError, service_audit_hash, validate_service_audit_operation_ref,
    validate_service_audit_record, validate_service_quota_policy,
};
pub use sync::{
    MAX_PARTIAL_SYNC_CONVERSATIONS, MAX_SYNC_RESUME_TOKEN_LEN, SyncError, can_transition_sync,
    canonical_sync_session, is_terminal_sync_state, validate_sync_checkpoint,
    validate_sync_transition,
};
pub use transport_failover::{
    MAX_TRANSPORT_FAILOVER_ROUTE_ATTEMPTS, TRANSPORT_FAILOVER_CAPABILITY,
    TransportFailoverProtocolError, phase25_transport_failover_capabilities,
    validate_transport_failover_policy,
};
pub use transport_orchestrator::{
    MAX_TRANSPORT_BANDWIDTH_BPS, MAX_TRANSPORT_HINTS, MAX_TRANSPORT_LATENCY_MS,
    MAX_TRANSPORT_PRIORITY_CLASS, MAX_TRANSPORT_ROUTE_CANDIDATES,
    TRANSPORT_ORCHESTRATOR_CAPABILITY, TransportOrchestratorProtocolError,
    canonical_transport_routing_hints, phase24_transport_orchestrator_capabilities,
    validate_transport_priority_class, validate_transport_resource_snapshot,
    validate_transport_route_candidate_count, validate_transport_route_telemetry,
};
pub use trusted_key::{TrustedSigningKeyError, validate_trusted_signing_key_descriptor};
pub use version::{
    ProtocolVersion, RUNTIME_ENVELOPE_SCHEMA_V1, VersionNegotiationError, VersionPolicy,
    VersionRange, negotiate_version, negotiate_version_sets,
};
pub use video::{
    H264_LEVEL_4_0_MAX_DPB_MACROBLOCKS, H264_MAX_REFERENCE_FRAMES, H264_VIDEO_CODEC_CAPABILITY,
    MANDATORY_VIDEO_FRAME_RATE, MANDATORY_VIDEO_HEIGHT, MANDATORY_VIDEO_WIDTH,
    MAX_ENCODED_VIDEO_FRAME_BYTES, MAX_VIDEO_BITRATE_BPS, MAX_VIDEO_FRAME_RATE, MAX_VIDEO_HEIGHT,
    MAX_VIDEO_WIDTH, MIN_VIDEO_BITRATE_BPS, SCREEN_SHARE_VIDEO_CAPABILITY, VIDEO_MEDIA_CAPABILITY,
    VideoProtocolError, canonical_video_codec_config, canonical_video_stream_descriptor,
    h264_reference_coded_dimensions, h264_reference_max_dpb_frames, phase21_video_capabilities,
    required_video_capability_for_source, validate_video_frame_for_stream, video_rgb8_len,
};
