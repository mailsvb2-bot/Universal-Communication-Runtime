#![forbid(unsafe_code)]

mod addressing;
mod capability;
mod error;
mod extension;
mod framing;
mod handshake;
mod provenance;
mod version;

pub use addressing::{
    AddressingError, MAX_ADDRESS_VALUE_LEN, MAX_ENDPOINT_ADDRESSES, MAX_ENDPOINT_CAPABILITIES,
    MAX_EXTERNAL_ENTITY_ID_LEN, validate_endpoint_address, validate_endpoint_descriptor,
    validate_external_identity_binding,
};
pub use capability::{
    CapabilityDescriptor, CapabilityError, CapabilityMaturity, CapabilityRequirement,
    negotiate_capabilities,
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
pub use provenance::{ProvenanceError, validate_origin_ref};
pub use version::{
    ProtocolVersion, VersionNegotiationError, VersionPolicy, VersionRange, negotiate_version,
    negotiate_version_sets,
};
