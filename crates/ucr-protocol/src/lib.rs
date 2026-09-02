#![forbid(unsafe_code)]

mod addressing;
mod authorization;
mod capability;
mod commands;
mod crypto_contract;
mod crypto_negotiation;
mod delivery;
mod error;
mod extension;
mod framing;
mod handshake;
mod message;
mod provenance;
mod recovery;
mod scope;
mod version;

pub use addressing::{
    AddressingError, MAX_ADDRESS_VALUE_LEN, MAX_ENDPOINT_ADDRESSES, MAX_ENDPOINT_CAPABILITIES,
    MAX_EXTERNAL_ENTITY_ID_LEN, validate_endpoint_address, validate_endpoint_descriptor,
    validate_external_identity_binding,
};
pub use authorization::{
    AuthorizationError, GrantValidationError, authorize, is_service_principal,
    validate_permission_grant,
};
pub use capability::{
    CapabilityDescriptor, CapabilityError, CapabilityMaturity, CapabilityRequirement,
    negotiate_capabilities,
};
pub use commands::{
    CommandError, CommandReceipt, CommandReceiptStatus, EventError, IdempotencyDecision,
    ReceiptError, compare_command_idempotency, validate_command, validate_command_receipt,
    validate_event,
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
pub use error::{CanonicalError, CanonicalErrorCode};
pub use extension::{
    ExtensionDescriptor, ExtensionError, require_supported_extensions, validate_extension_name,
    validate_namespaced_identifier,
};
pub use framing::{
    CURRENT_FRAMING_VERSION, DEFAULT_MAX_PAYLOAD_LEN, FRAME_HEADER_LEN, FRAME_MAGIC, FrameError,
    FrameHeader, FrameKind, FramePolicy, decode_frame_prefix, decode_header,
};
pub use handshake::{
    HandshakeError, NegotiatedSession, NegotiationPolicy, PeerHello, negotiate_session,
};
pub use message::{
    ConversationError, EXTERNAL_MESSAGE_ID_LIMIT, EXTERNAL_MESSAGE_MAPPING_LIMIT,
    MESSAGE_ATTACHMENT_LIMIT, MESSAGE_CRYPTO_METADATA_LIMIT, MESSAGE_RELATION_LIMIT, MessageError,
    canonical_message, validate_conversation, validate_conversation_parent_kind, validate_message,
};
pub use provenance::{ProvenanceError, validate_origin_ref};
pub use recovery::{
    MAX_RECOVERY_AUTHORITIES, RecoveryError, canonical_recovery_plan, recovery_plan_aad,
    validate_recovery_plan, validate_recovery_request,
};
pub use scope::{ScopeError, ScopeRelation, require_exact_scope, scope_relation};
pub use version::{
    ProtocolVersion, VersionNegotiationError, VersionPolicy, VersionRange, negotiate_version,
    negotiate_version_sets,
};
