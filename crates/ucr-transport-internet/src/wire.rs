use std::io::{Read, Write};
use std::net::TcpStream;

use prost::Message;
use sha2::{Digest, Sha256};
use ucr_crypto::{AgreementPublicKey, ConfirmationTag, SignatureBytes, TranscriptBinding};
use ucr_model::{
    CapabilityMaturity, CryptoSuite, DeviceId, HandshakeNonce, KeyId, KeyPurpose, OpaqueId,
    ProtocolExtension, ProtocolVersion, PublicKeyDescriptor, TenantScope,
};
use ucr_protocol::{
    CURRENT_FRAMING_VERSION, DEFAULT_MAX_PAYLOAD_LEN, FrameHeader, FrameKind, FramePolicy,
    NegotiatedSession, NegotiationResultEnvelope, PeerHello, VersionRange, decode_header,
    negotiation_result_for_session,
};

#[allow(clippy::all, clippy::pedantic, dead_code)]
pub(crate) mod pb {
    include!(concat!(env!("OUT_DIR"), "/ucr.v1.rs"));
}

pub(crate) const INTERNET_CONTEXT_EXTENSION: &str = "ucr.transport.internet.context.v1";
pub(crate) const HANDSHAKE_AAD_DOMAIN: &[u8] = b"UCR-INTERNET-TRANSPORT-V1\0";
pub(crate) const INTERNET_RECEIPT_AAD_DOMAIN: &[u8] = b"UCR-INTERNET-RECEIPT-V1\0";
pub(crate) const INTERNET_CHUNK_PLAINTEXT_MIN: usize = 64 * 1024;
pub(crate) const INTERNET_CHUNK_PLAINTEXT_MAX: usize = 1024 * 1024;
pub(crate) const INTERNET_ENVELOPE_MAX: usize = DEFAULT_MAX_PAYLOAD_LEN as usize;
pub(crate) const INTERNET_NONCE_LEN: usize = 24;
pub(crate) const INTERNET_RECEIPT_ACCEPTED: i32 = 1;
pub(crate) const INTERNET_RECEIPT_DUPLICATE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    Io(std::io::ErrorKind),
    Frame,
    Encode,
    Decode,
    UnexpectedFrameKind,
    InvalidValue,
    PayloadTooLarge,
}

impl From<std::io::Error> for WireError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub(crate) fn encode_message_frame<M: Message>(
    kind: FrameKind,
    message: &M,
) -> Result<Vec<u8>, WireError> {
    let payload_len = message.encoded_len();
    let payload_len = u32::try_from(payload_len).map_err(|_| WireError::PayloadTooLarge)?;
    if payload_len > DEFAULT_MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLarge);
    }
    let header = FrameHeader {
        framing_version: CURRENT_FRAMING_VERSION,
        kind,
        flags: 0,
        payload_len,
    };
    let mut frame = Vec::with_capacity(12 + payload_len as usize);
    frame.extend_from_slice(&header.encode());
    message.encode(&mut frame).map_err(|_| WireError::Encode)?;
    Ok(frame)
}

pub(crate) fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<(), WireError> {
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

pub(crate) fn read_message_frame<M: Message + Default>(
    stream: &mut TcpStream,
    expected: FrameKind,
) -> Result<(Vec<u8>, M), WireError> {
    let mut header_bytes = [0_u8; 12];
    stream.read_exact(&mut header_bytes)?;
    let header =
        decode_header(&header_bytes, FramePolicy::default()).map_err(|_| WireError::Frame)?;
    if header.kind != expected {
        return Err(WireError::UnexpectedFrameKind);
    }
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| WireError::PayloadTooLarge)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    let message = M::decode(payload.as_slice()).map_err(|_| WireError::Decode)?;
    let mut frame = Vec::with_capacity(header_bytes.len() + payload.len());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(&payload);
    Ok((frame, message))
}

pub(crate) fn encode_hello(hello: &PeerHello) -> Result<Vec<u8>, WireError> {
    encode_message_frame(FrameKind::Hello, &pb_hello(hello))
}

pub(crate) fn decode_hello(value: pb::NegotiationHello) -> Result<PeerHello, WireError> {
    let nonce: [u8; 32] = value
        .nonce
        .try_into()
        .map_err(|_| WireError::InvalidValue)?;
    Ok(PeerHello {
        supported_versions: value
            .supported_versions
            .into_iter()
            .map(decode_version_range)
            .collect::<Result<Vec<_>, _>>()?,
        supported_crypto_suites: value
            .supported_crypto_suites
            .into_iter()
            .map(decode_crypto_suite)
            .collect::<Result<Vec<_>, _>>()?,
        nonce: HandshakeNonce::new(nonce),
        capabilities: value
            .capabilities
            .into_iter()
            .map(decode_capability)
            .collect::<Result<Vec<_>, _>>()?,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
    })
}

fn pb_hello(value: &PeerHello) -> pb::NegotiationHello {
    pb::NegotiationHello {
        supported_versions: value
            .supported_versions
            .iter()
            .copied()
            .map(pb_version_range)
            .collect(),
        capabilities: value.capabilities.iter().map(pb_capability).collect(),
        extensions: value.extensions.iter().map(pb_extension).collect(),
        nonce: value.nonce.as_bytes().to_vec(),
        supported_crypto_suites: value
            .supported_crypto_suites
            .iter()
            .map(|suite| pb_crypto_suite(*suite))
            .collect(),
    }
}

pub(crate) fn encode_negotiation_result(
    session: &NegotiatedSession,
) -> Result<(Vec<u8>, NegotiationResultEnvelope), WireError> {
    let result = negotiation_result_for_session(session);
    let frame = encode_message_frame(
        FrameKind::NegotiationResult,
        &pb_negotiation_result(&result),
    )?;
    Ok((frame, result))
}

#[allow(deprecated)]
pub(crate) fn decode_negotiation_result(
    value: pb::NegotiationResult,
) -> Result<NegotiationResultEnvelope, WireError> {
    Ok(NegotiationResultEnvelope {
        version: decode_protocol_version(value.version.ok_or(WireError::InvalidValue)?)?,
        capabilities: value
            .capabilities
            .into_iter()
            .map(decode_capability)
            .collect::<Result<Vec<_>, _>>()?,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
        transcript_binding: value.transcript_binding,
        crypto_suite: decode_crypto_suite(value.crypto_suite)?,
    })
}

#[allow(deprecated)]
fn pb_negotiation_result(value: &NegotiationResultEnvelope) -> pb::NegotiationResult {
    pb::NegotiationResult {
        version: Some(pb_protocol_version(value.version)),
        capabilities: value.capabilities.iter().map(pb_capability).collect(),
        extensions: value.extensions.iter().map(pb_extension).collect(),
        transcript_binding: value.transcript_binding.clone(),
        crypto_suite: pb_crypto_suite(value.crypto_suite),
    }
}

pub(crate) fn context_extension(
    endpoint_id: &ucr_model::EndpointId,
    scope: &TenantScope,
) -> ProtocolExtension {
    let context = pb::InternetTransportContext {
        endpoint_id: Some(pb_opaque(endpoint_id.as_opaque())),
        scope_binding: scope_binding(scope).to_vec(),
    };
    ProtocolExtension {
        name: INTERNET_CONTEXT_EXTENSION.to_owned(),
        critical: true,
        payload: context.encode_to_vec(),
    }
}

pub(crate) fn endpoint_from_context(
    hello: &PeerHello,
    scope: &TenantScope,
) -> Result<ucr_model::EndpointId, WireError> {
    let mut matches = hello
        .extensions
        .iter()
        .filter(|extension| extension.name == INTERNET_CONTEXT_EXTENSION);
    let extension = matches.next().ok_or(WireError::InvalidValue)?;
    if matches.next().is_some() || !extension.critical {
        return Err(WireError::InvalidValue);
    }
    let context = pb::InternetTransportContext::decode(extension.payload.as_slice())
        .map_err(|_| WireError::Decode)?;
    if context.scope_binding.as_slice() != scope_binding(scope) {
        return Err(WireError::InvalidValue);
    }
    let endpoint = decode_opaque(&context.endpoint_id.ok_or(WireError::InvalidValue)?)?;
    Ok(ucr_model::EndpointId::from_opaque(endpoint))
}

fn scope_binding(scope: &TenantScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"UCR-INTERNET-SCOPE-V1\0");
    hash_len_prefixed(&mut hasher, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hasher.update([1]);
            hash_len_prefixed(&mut hasher, namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub(crate) fn key_exchange_frame(public: AgreementPublicKey) -> Result<Vec<u8>, WireError> {
    encode_message_frame(
        FrameKind::HandshakeKeyExchange,
        &pb::HandshakeKeyExchange {
            ephemeral_key: public.0.to_vec(),
        },
    )
}

pub(crate) fn decode_agreement(
    value: pb::HandshakeKeyExchange,
) -> Result<AgreementPublicKey, WireError> {
    let bytes: [u8; 32] = value
        .ephemeral_key
        .try_into()
        .map_err(|_| WireError::InvalidValue)?;
    Ok(AgreementPublicKey(bytes))
}

pub(crate) fn auth_frame(
    binding: &TranscriptBinding,
    descriptor: &PublicKeyDescriptor,
    signature: SignatureBytes,
) -> Result<Vec<u8>, WireError> {
    encode_message_frame(
        FrameKind::HandshakeAuthentication,
        &pb::HandshakeAuthentication {
            transcript_binding: binding.as_bytes().to_vec(),
            signing_key: Some(pb_public_key_descriptor(descriptor)),
            signature: signature.0.to_vec(),
        },
    )
}

pub(crate) fn decode_auth(
    value: pb::HandshakeAuthentication,
    expected_binding: &TranscriptBinding,
) -> Result<(PublicKeyDescriptor, SignatureBytes), WireError> {
    if value.transcript_binding.as_slice() != expected_binding.as_bytes() {
        return Err(WireError::InvalidValue);
    }
    let signature: [u8; 64] = value
        .signature
        .try_into()
        .map_err(|_| WireError::InvalidValue)?;
    let descriptor =
        decode_public_key_descriptor(value.signing_key.ok_or(WireError::InvalidValue)?)?;
    Ok((descriptor, SignatureBytes(signature)))
}

pub(crate) fn confirmation_frame(
    binding: &TranscriptBinding,
    tag: ConfirmationTag,
) -> Result<Vec<u8>, WireError> {
    encode_message_frame(
        FrameKind::KeyConfirmation,
        &pb::KeyConfirmation {
            transcript_binding: binding.as_bytes().to_vec(),
            tag: tag.0.to_vec(),
        },
    )
}

pub(crate) fn decode_confirmation(
    value: pb::KeyConfirmation,
    expected_binding: &TranscriptBinding,
) -> Result<ConfirmationTag, WireError> {
    if value.transcript_binding.as_slice() != expected_binding.as_bytes() {
        return Err(WireError::InvalidValue);
    }
    let tag: [u8; 32] = value.tag.try_into().map_err(|_| WireError::InvalidValue)?;
    Ok(ConfirmationTag(tag))
}

pub(crate) fn data_frame(message: &pb::InternetTransportData) -> Result<Vec<u8>, WireError> {
    encode_message_frame(FrameKind::InternetData, message)
}

pub(crate) fn receipt_frame(message: &pb::InternetTransportReceipt) -> Result<Vec<u8>, WireError> {
    encode_message_frame(FrameKind::InternetReceipt, message)
}

pub(crate) fn pb_opaque(value: &OpaqueId) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_wire_bytes().to_vec(),
    }
}

pub(crate) fn decode_opaque(value: &pb::OpaqueId) -> Result<OpaqueId, WireError> {
    OpaqueId::from_wire_bytes(&value.value).map_err(|_| WireError::InvalidValue)
}

fn pb_protocol_version(value: ProtocolVersion) -> pb::ProtocolVersion {
    pb::ProtocolVersion {
        major: value.major,
        minor: value.minor,
    }
}

fn decode_protocol_version(value: pb::ProtocolVersion) -> Result<ProtocolVersion, WireError> {
    if value.major == 0 {
        return Err(WireError::InvalidValue);
    }
    Ok(ProtocolVersion::new(value.major, value.minor))
}

fn pb_version_range(value: VersionRange) -> pb::VersionRange {
    pb::VersionRange {
        min: Some(pb_protocol_version(value.min)),
        max: Some(pb_protocol_version(value.max)),
    }
}

fn decode_version_range(value: pb::VersionRange) -> Result<VersionRange, WireError> {
    VersionRange::new(
        decode_protocol_version(value.min.ok_or(WireError::InvalidValue)?)?,
        decode_protocol_version(value.max.ok_or(WireError::InvalidValue)?)?,
    )
    .map_err(|_| WireError::InvalidValue)
}

fn pb_extension(value: &ProtocolExtension) -> pb::Extension {
    pb::Extension {
        name: value.name.clone(),
        critical: value.critical,
        payload: value.payload.clone(),
    }
}

fn decode_extension(value: pb::Extension) -> ProtocolExtension {
    ProtocolExtension {
        name: value.name,
        critical: value.critical,
        payload: value.payload,
    }
}

fn pb_capability(value: &ucr_model::CapabilityDescriptor) -> pb::Capability {
    pb::Capability {
        id: value.id.clone(),
        maturity: pb_maturity(value.maturity),
        extensions: value.extensions.iter().map(pb_extension).collect(),
    }
}

fn decode_capability(value: pb::Capability) -> Result<ucr_model::CapabilityDescriptor, WireError> {
    Ok(ucr_model::CapabilityDescriptor {
        id: value.id,
        maturity: decode_maturity(value.maturity)?,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
    })
}

const fn pb_maturity(value: CapabilityMaturity) -> i32 {
    match value {
        CapabilityMaturity::Experimental => 1,
        CapabilityMaturity::Prepared => 2,
        CapabilityMaturity::Beta => 3,
        CapabilityMaturity::Production => 4,
        CapabilityMaturity::Deprecated => 5,
        CapabilityMaturity::Disabled => 6,
    }
}

fn decode_maturity(value: i32) -> Result<CapabilityMaturity, WireError> {
    match value {
        1 => Ok(CapabilityMaturity::Experimental),
        2 => Ok(CapabilityMaturity::Prepared),
        3 => Ok(CapabilityMaturity::Beta),
        4 => Ok(CapabilityMaturity::Production),
        5 => Ok(CapabilityMaturity::Deprecated),
        6 => Ok(CapabilityMaturity::Disabled),
        _ => Err(WireError::InvalidValue),
    }
}

const fn pb_crypto_suite(value: CryptoSuite) -> i32 {
    match value {
        CryptoSuite::UcrV1 => 1,
    }
}

fn decode_crypto_suite(value: i32) -> Result<CryptoSuite, WireError> {
    match value {
        1 => Ok(CryptoSuite::UcrV1),
        _ => Err(WireError::InvalidValue),
    }
}

fn pb_public_key_descriptor(value: &PublicKeyDescriptor) -> pb::PublicKeyDescriptor {
    pb::PublicKeyDescriptor {
        key_id: Some(pb_opaque(value.key_id.as_opaque())),
        device_id: Some(pb_opaque(value.device_id.as_opaque())),
        purpose: match value.purpose {
            KeyPurpose::Signing => 1,
            KeyPurpose::KeyAgreement => 2,
        },
        algorithm_id: value.algorithm_id.clone(),
        algorithm_version: value.algorithm_version,
        key_format_version: value.key_format_version,
        public_key: value.public_key.clone(),
    }
}

fn decode_public_key_descriptor(
    value: pb::PublicKeyDescriptor,
) -> Result<PublicKeyDescriptor, WireError> {
    let purpose = match value.purpose {
        1 => KeyPurpose::Signing,
        2 => KeyPurpose::KeyAgreement,
        _ => return Err(WireError::InvalidValue),
    };
    Ok(PublicKeyDescriptor {
        key_id: KeyId::from_opaque(decode_opaque(
            &value.key_id.ok_or(WireError::InvalidValue)?,
        )?),
        device_id: DeviceId::from_opaque(decode_opaque(
            &value.device_id.ok_or(WireError::InvalidValue)?,
        )?),
        purpose,
        algorithm_id: value.algorithm_id,
        algorithm_version: value.algorithm_version,
        key_format_version: value.key_format_version,
        public_key: value.public_key,
    })
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_untrusted_internet_frame(bytes: &[u8]) {
    let Ok((header, payload, remainder)) =
        ucr_protocol::decode_frame_prefix(bytes, FramePolicy::default())
    else {
        return;
    };
    if !remainder.is_empty() {
        return;
    }
    match header.kind {
        FrameKind::Hello => {
            if let Ok(value) = pb::NegotiationHello::decode(payload) {
                let _ = decode_hello(value);
            }
        }
        FrameKind::NegotiationResult => {
            if let Ok(value) = pb::NegotiationResult::decode(payload) {
                let _ = decode_negotiation_result(value);
            }
        }
        FrameKind::HandshakeKeyExchange => {
            if let Ok(value) = pb::HandshakeKeyExchange::decode(payload) {
                let _ = decode_agreement(value);
            }
        }
        FrameKind::HandshakeAuthentication => {
            if let Ok(value) = pb::HandshakeAuthentication::decode(payload) {
                let _ = fuzz_validate_auth(&value);
            }
        }
        FrameKind::KeyConfirmation => {
            if let Ok(value) = pb::KeyConfirmation::decode(payload) {
                let _ = fuzz_validate_confirmation(&value);
            }
        }
        FrameKind::InternetData => {
            if let Ok(value) = pb::InternetTransportData::decode(payload) {
                let _ = fuzz_validate_data(&value);
            }
        }
        FrameKind::InternetReceipt => {
            if let Ok(value) = pb::InternetTransportReceipt::decode(payload) {
                let _ = fuzz_validate_receipt(&value);
            }
        }
        FrameKind::Command | FrameKind::Event | FrameKind::Error | FrameKind::Acknowledgement => {}
    }
}

#[cfg(feature = "fuzzing")]
fn fuzz_validate_auth(value: &pb::HandshakeAuthentication) -> Result<(), WireError> {
    if value.transcript_binding.len() != 32 || value.signature.len() != 64 {
        return Err(WireError::InvalidValue);
    }
    let descriptor = value.signing_key.clone().ok_or(WireError::InvalidValue)?;
    decode_public_key_descriptor(descriptor).map(|_| ())
}

#[cfg(feature = "fuzzing")]
fn fuzz_validate_confirmation(value: &pb::KeyConfirmation) -> Result<(), WireError> {
    if value.transcript_binding.len() != 32 || value.tag.len() != 32 {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}

#[cfg(feature = "fuzzing")]
fn fuzz_validate_data(value: &pb::InternetTransportData) -> Result<(), WireError> {
    let attempt = value.attempt_id.as_ref().ok_or(WireError::InvalidValue)?;
    decode_opaque(attempt)?;
    if value.chunk_count == 0
        || value.chunk_index >= value.chunk_count
        || value.nonce.len() != INTERNET_NONCE_LEN
        || value.ciphertext.is_empty()
        || value.ciphertext.len() > INTERNET_CHUNK_PLAINTEXT_MAX + 16
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}

#[cfg(feature = "fuzzing")]
fn fuzz_validate_receipt(value: &pb::InternetTransportReceipt) -> Result<(), WireError> {
    let attempt = value.attempt_id.as_ref().ok_or(WireError::InvalidValue)?;
    decode_opaque(attempt)?;
    if value.nonce.len() != INTERNET_NONCE_LEN
        || value.ciphertext.is_empty()
        || value.ciphertext.len() > 1024
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
