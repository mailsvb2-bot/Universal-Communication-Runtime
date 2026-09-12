use sha2::{Digest, Sha256};
use ucr_model::{
    CryptoSuite, DeviceId, EncryptedGroupMediaFrame, GroupMediaE2eeContext, GroupMediaFrameHeader,
    MediaKind, OpaqueId, PrincipalKind, PrincipalRef, TenantScope,
};

pub const GROUP_MEDIA_E2EE_CAPABILITY: &str = "ucr.media.e2ee.group.mls";
pub const GROUP_MEDIA_CONTEXT_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-CONTEXT-V1\0";
pub const GROUP_MEDIA_FRAME_AAD_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-FRAME-AAD-V1\0";
pub const GROUP_MEDIA_KEY_CONTEXT_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-KEY-CONTEXT-V1\0";
pub const GROUP_MEDIA_SOURCE_SIGNATURE_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-SOURCE-SIGNATURE-V1\0";
pub const MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES: usize = 2 * 1024 * 1024 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaE2eeProtocolError {
    InvalidNegotiation,
    InvalidEpoch,
    UnsupportedCryptoSuite,
    ContextMismatch,
    DeviceParticipantMismatch,
    EmptyCiphertext,
    CiphertextTooLarge,
    InvalidAudioHeader,
    InvalidSourceSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMediaSigningBinding([u8; 32]);

impl GroupMediaSigningBinding {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hashes exact authenticated frame metadata, nonce and ciphertext for the source Device signature.
///
/// # Errors
/// Rejects malformed header/ciphertext shape before any signature operation.
pub fn group_media_source_signing_binding(
    header: &GroupMediaFrameHeader,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<GroupMediaSigningBinding, GroupMediaE2eeProtocolError> {
    let aad = group_media_frame_aad(header)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES {
        return Err(if ciphertext.is_empty() {
            GroupMediaE2eeProtocolError::EmptyCiphertext
        } else {
            GroupMediaE2eeProtocolError::CiphertextTooLarge
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(GROUP_MEDIA_SOURCE_SIGNATURE_V1_DOMAIN);
    hasher.update((aad.len() as u64).to_be_bytes());
    hasher.update(&aad);
    hasher.update(nonce);
    hasher.update((ciphertext.len() as u64).to_be_bytes());
    hasher.update(ciphertext);
    Ok(GroupMediaSigningBinding(hasher.finalize().into()))
}

/// Validates one MLS-backed group-media security context.
///
/// # Errors
/// Rejects missing negotiation/epoch state or an unsupported crypto suite.
pub fn canonical_group_media_e2ee_context(
    context: &GroupMediaE2eeContext,
) -> Result<GroupMediaE2eeContext, GroupMediaE2eeProtocolError> {
    if context.negotiation_generation == 0 {
        return Err(GroupMediaE2eeProtocolError::InvalidNegotiation);
    }
    if context.crypto_suite != CryptoSuite::UcrV1 {
        return Err(GroupMediaE2eeProtocolError::UnsupportedCryptoSuite);
    }
    Ok(context.clone())
}

/// Stable domain-separated binding for one canonical group-media epoch context.
///
/// # Errors
/// Returns context validation failures.
pub fn group_media_context_binding(
    context: &GroupMediaE2eeContext,
) -> Result<[u8; 32], GroupMediaE2eeProtocolError> {
    let context = canonical_group_media_e2ee_context(context)?;
    let mut bytes = Vec::new();
    push_scope(&mut bytes, &context.scope);
    push_bytes(&mut bytes, context.call_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, context.group_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, context.negotiation_ref.as_wire_bytes());
    bytes.extend_from_slice(&context.negotiation_generation.to_be_bytes());
    bytes.extend_from_slice(&context.crypto_epoch.to_be_bytes());
    push_bytes(&mut bytes, context.crypto_state_ref.as_wire_bytes());
    bytes.extend_from_slice(&(context.crypto_suite as u32).to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(GROUP_MEDIA_CONTEXT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

/// Canonical per-source/stream key-derivation context. This contains no key material.
///
/// # Errors
/// Rejects an invalid group-media context. Principal→Device association is a runtime trust check, not a wire-level equality rule.
pub fn group_media_key_context(
    context: &GroupMediaE2eeContext,
    source: &PrincipalRef,
    source_device_id: &DeviceId,
    stream_id: &OpaqueId,
    media_kind: MediaKind,
) -> Result<Vec<u8>, GroupMediaE2eeProtocolError> {
    canonical_group_media_e2ee_context(context)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(GROUP_MEDIA_KEY_CONTEXT_V1_DOMAIN);
    bytes.extend_from_slice(&group_media_context_binding(context)?);
    push_principal(&mut bytes, source);
    push_bytes(&mut bytes, source_device_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, stream_id.as_wire_bytes());
    bytes.push(media_kind as u8);
    Ok(bytes)
}

/// Canonical AEAD associated data for one encrypted group-media frame.
///
/// # Errors
/// Rejects invalid group epoch metadata or impossible audio keyframe state. Principal→Device association is revalidated by the runtime trust boundary.
pub fn group_media_frame_aad(
    header: &GroupMediaFrameHeader,
) -> Result<Vec<u8>, GroupMediaE2eeProtocolError> {
    if header.negotiation_generation == 0 {
        return Err(GroupMediaE2eeProtocolError::InvalidNegotiation);
    }
    if header.crypto_suite != CryptoSuite::UcrV1 {
        return Err(GroupMediaE2eeProtocolError::UnsupportedCryptoSuite);
    }
    if header.media_kind == MediaKind::Audio && header.keyframe {
        return Err(GroupMediaE2eeProtocolError::InvalidAudioHeader);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(GROUP_MEDIA_FRAME_AAD_V1_DOMAIN);
    push_scope(&mut bytes, &header.scope);
    push_bytes(&mut bytes, header.call_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, header.group_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, header.stream_id.as_wire_bytes());
    push_principal(&mut bytes, &header.source);
    push_bytes(
        &mut bytes,
        header.source_device_id.as_opaque().as_wire_bytes(),
    );
    push_bytes(&mut bytes, header.negotiation_ref.as_wire_bytes());
    bytes.extend_from_slice(&header.negotiation_generation.to_be_bytes());
    bytes.extend_from_slice(&header.crypto_epoch.to_be_bytes());
    push_bytes(&mut bytes, header.crypto_state_ref.as_wire_bytes());
    bytes.extend_from_slice(&(header.crypto_suite as u32).to_be_bytes());
    bytes.push(header.media_kind as u8);
    bytes.extend_from_slice(&header.sequence.to_be_bytes());
    bytes.extend_from_slice(&header.media_timestamp.to_be_bytes());
    bytes.push(u8::from(header.keyframe));
    Ok(bytes)
}

/// Reconstructs the exact public group-media epoch context authenticated by a frame header.
///
/// # Errors
/// Rejects malformed context fields before returning the canonical value.
pub fn group_media_context_from_frame(
    frame: &EncryptedGroupMediaFrame,
) -> Result<GroupMediaE2eeContext, GroupMediaE2eeProtocolError> {
    canonical_group_media_e2ee_context(&GroupMediaE2eeContext {
        scope: frame.header.scope.clone(),
        call_id: frame.header.call_id.clone(),
        group_id: frame.header.group_id.clone(),
        negotiation_ref: frame.header.negotiation_ref.clone(),
        negotiation_generation: frame.header.negotiation_generation,
        crypto_epoch: frame.header.crypto_epoch,
        crypto_state_ref: frame.header.crypto_state_ref.clone(),
        crypto_suite: frame.header.crypto_suite,
    })
}

/// Validates an encrypted group-media frame against an exact MLS epoch context.
///
/// # Errors
/// Rejects malformed, oversized or cross-context ciphertext before endpoint AEAD open or SFU route.
pub fn validate_encrypted_group_media_frame(
    context: &GroupMediaE2eeContext,
    frame: &EncryptedGroupMediaFrame,
) -> Result<(), GroupMediaE2eeProtocolError> {
    let context = canonical_group_media_e2ee_context(context)?;
    let header = &frame.header;
    group_media_frame_aad(header)?;
    if frame.ciphertext.is_empty() {
        return Err(GroupMediaE2eeProtocolError::EmptyCiphertext);
    }
    if frame.ciphertext.len() > MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES {
        return Err(GroupMediaE2eeProtocolError::CiphertextTooLarge);
    }
    if frame.source_signature.algorithm_id != crate::SIGNATURE_ALGORITHM_ID
        || frame.source_signature.algorithm_version != crate::ALGORITHM_VERSION
        || frame.source_signature.signature.len() != 64
    {
        return Err(GroupMediaE2eeProtocolError::InvalidSourceSignature);
    }
    group_media_source_signing_binding(header, &frame.nonce, &frame.ciphertext)?;
    if header.scope != context.scope
        || header.call_id != context.call_id
        || header.group_id != context.group_id
        || header.negotiation_ref != context.negotiation_ref
        || header.negotiation_generation != context.negotiation_generation
        || header.crypto_epoch != context.crypto_epoch
        || header.crypto_state_ref != context.crypto_state_ref
        || header.crypto_suite != context.crypto_suite
    {
        return Err(GroupMediaE2eeProtocolError::ContextMismatch);
    }
    Ok(())
}

fn push_scope(bytes: &mut Vec<u8>, scope: &TenantScope) {
    push_bytes(bytes, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            bytes.push(1);
            push_bytes(bytes, namespace.as_opaque().as_wire_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_principal(bytes: &mut Vec<u8>, principal: &PrincipalRef) {
    bytes.push(principal_kind_code(principal.kind));
    push_bytes(bytes, principal.principal_id.as_opaque().as_wire_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("canonical identifier budget fits u32");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}
