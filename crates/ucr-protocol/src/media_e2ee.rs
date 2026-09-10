use sha2::{Digest, Sha256};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CryptoSuite, EncryptedMediaFrame, MediaE2eeContext,
    MediaE2eeFrameHeader, MediaKind, PrincipalKind, PrincipalRef, TenantScope,
};

pub const MEDIA_E2EE_CAPABILITY: &str = "ucr.media.e2ee";
pub const MEDIA_E2EE_CONTEXT_V1_DOMAIN: &[u8] = b"UCR-MEDIA-E2EE-CONTEXT-V1\0";
pub const MEDIA_E2EE_FRAME_AAD_V1_DOMAIN: &[u8] = b"UCR-MEDIA-E2EE-FRAME-AAD-V1\0";
pub const MEDIA_E2EE_SESSION_BINDING_LEN: usize = 32;
pub const MEDIA_E2EE_NONCE_LEN: usize = 24;
pub const MEDIA_E2EE_AEAD_TAG_LEN: usize = 16;
pub const MAX_ENCRYPTED_MEDIA_PAYLOAD_BYTES: usize = 2 * 1024 * 1024 + MEDIA_E2EE_AEAD_TAG_LEN;
pub const MAX_MEDIA_STREAMS_PER_EPOCH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaE2eeProtocolError {
    InvalidParticipants,
    InvalidDevices,
    InvalidNegotiation,
    InvalidEpoch,
    UnsupportedCryptoSuite,
    InvalidSessionBinding,
    EmptyCiphertext,
    CiphertextTooLarge,
    ContextMismatch,
    InvalidAudioHeader,
}

#[must_use]
pub fn phase22_media_e2ee_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: MEDIA_E2EE_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Validates the immutable security context for one direct-call media key epoch.
///
/// # Errors
/// Rejects self-peering, reused device identities, missing negotiation/epoch, or an unsupported suite.
pub fn canonical_media_e2ee_context(
    context: &MediaE2eeContext,
) -> Result<MediaE2eeContext, MediaE2eeProtocolError> {
    if context.initiator == context.responder {
        return Err(MediaE2eeProtocolError::InvalidParticipants);
    }
    if context.initiator_device_id == context.responder_device_id {
        return Err(MediaE2eeProtocolError::InvalidDevices);
    }
    if context.negotiation_generation == 0 {
        return Err(MediaE2eeProtocolError::InvalidNegotiation);
    }
    if context.key_epoch == 0 {
        return Err(MediaE2eeProtocolError::InvalidEpoch);
    }
    if context.crypto_suite != CryptoSuite::UcrV1 {
        return Err(MediaE2eeProtocolError::UnsupportedCryptoSuite);
    }
    Ok(context.clone())
}

/// Stable domain-separated fingerprint of the exact Phase-22 media security context.
///
/// # Errors
/// Returns context validation failures.
pub fn media_e2ee_context_binding(
    context: &MediaE2eeContext,
) -> Result<[u8; 32], MediaE2eeProtocolError> {
    let context = canonical_media_e2ee_context(context)?;
    let mut bytes = Vec::new();
    push_scope(&mut bytes, &context.scope);
    push_bytes(&mut bytes, context.call_id.as_opaque().as_wire_bytes());
    push_principal(&mut bytes, &context.initiator);
    push_principal(&mut bytes, &context.responder);
    push_bytes(
        &mut bytes,
        context.initiator_device_id.as_opaque().as_wire_bytes(),
    );
    push_bytes(
        &mut bytes,
        context.responder_device_id.as_opaque().as_wire_bytes(),
    );
    push_bytes(&mut bytes, context.negotiation_ref.as_wire_bytes());
    bytes.extend_from_slice(&context.negotiation_generation.to_be_bytes());
    bytes.extend_from_slice(&context.key_epoch.to_be_bytes());
    bytes.extend_from_slice(&(context.crypto_suite as u32).to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(MEDIA_E2EE_CONTEXT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

/// Canonical AEAD associated data for one encrypted media frame.
///
/// # Errors
/// Rejects malformed header fields before cryptographic processing.
pub fn media_e2ee_frame_aad(
    header: &MediaE2eeFrameHeader,
) -> Result<Vec<u8>, MediaE2eeProtocolError> {
    if header.session_binding.iter().all(|byte| *byte == 0) {
        return Err(MediaE2eeProtocolError::InvalidSessionBinding);
    }
    if header.key_epoch == 0 || header.negotiation_generation == 0 {
        return Err(MediaE2eeProtocolError::InvalidEpoch);
    }
    if header.crypto_suite != CryptoSuite::UcrV1 {
        return Err(MediaE2eeProtocolError::UnsupportedCryptoSuite);
    }
    if header.media_kind == MediaKind::Audio && header.keyframe {
        return Err(MediaE2eeProtocolError::InvalidAudioHeader);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MEDIA_E2EE_FRAME_AAD_V1_DOMAIN);
    push_scope(&mut bytes, &header.scope);
    push_bytes(&mut bytes, header.call_id.as_opaque().as_wire_bytes());
    push_bytes(&mut bytes, header.stream_id.as_wire_bytes());
    push_principal(&mut bytes, &header.source);
    push_principal(&mut bytes, &header.recipient);
    push_bytes(&mut bytes, header.negotiation_ref.as_wire_bytes());
    bytes.extend_from_slice(&header.negotiation_generation.to_be_bytes());
    bytes.extend_from_slice(&header.key_epoch.to_be_bytes());
    bytes.extend_from_slice(&(header.crypto_suite as u32).to_be_bytes());
    bytes.extend_from_slice(&header.session_binding);
    bytes.push(header.media_kind as u8);
    bytes.extend_from_slice(&header.sequence.to_be_bytes());
    bytes.extend_from_slice(&header.media_timestamp.to_be_bytes());
    bytes.push(u8::from(header.keyframe));
    Ok(bytes)
}

/// Validates the public encrypted frame envelope and exact key-epoch context binding.
///
/// # Errors
/// Rejects malformed, oversized, or cross-context encrypted media before AEAD open.
pub fn validate_encrypted_media_frame(
    context: &MediaE2eeContext,
    frame: &EncryptedMediaFrame,
) -> Result<(), MediaE2eeProtocolError> {
    let context = canonical_media_e2ee_context(context)?;
    let header = &frame.header;
    media_e2ee_frame_aad(header)?;
    if frame.ciphertext.is_empty() {
        return Err(MediaE2eeProtocolError::EmptyCiphertext);
    }
    if frame.ciphertext.len() > MAX_ENCRYPTED_MEDIA_PAYLOAD_BYTES {
        return Err(MediaE2eeProtocolError::CiphertextTooLarge);
    }
    if header.scope != context.scope
        || header.call_id != context.call_id
        || header.negotiation_ref != context.negotiation_ref
        || header.negotiation_generation != context.negotiation_generation
        || header.key_epoch != context.key_epoch
        || header.crypto_suite != context.crypto_suite
    {
        return Err(MediaE2eeProtocolError::ContextMismatch);
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

#[cfg(test)]
mod tests {
    use ucr_model::{CallId, DeviceId, OpaqueId, PrincipalId, PrincipalKind, TenantId};

    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn context() -> MediaE2eeContext {
        MediaE2eeContext {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-media-e2ee")),
                namespace_id: None,
            },
            call_id: CallId::from_opaque(oid("call-media-e2ee")),
            initiator: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("alice")),
                kind: PrincipalKind::Person,
            },
            responder: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("bob")),
                kind: PrincipalKind::Person,
            },
            initiator_device_id: DeviceId::from_opaque(oid("device-alice")),
            responder_device_id: DeviceId::from_opaque(oid("device-bob")),
            negotiation_ref: oid("negotiation-media-e2ee"),
            negotiation_generation: 1,
            key_epoch: 1,
            crypto_suite: CryptoSuite::UcrV1,
        }
    }

    #[test]
    fn context_binding_is_role_epoch_and_negotiation_sensitive() {
        let base = context();
        let fingerprint = media_e2ee_context_binding(&base).expect("binding");
        let mut changed = base.clone();
        changed.key_epoch = 2;
        assert_ne!(
            fingerprint,
            media_e2ee_context_binding(&changed).expect("binding")
        );
        changed = base.clone();
        core::mem::swap(&mut changed.initiator, &mut changed.responder);
        assert_ne!(
            fingerprint,
            media_e2ee_context_binding(&changed).expect("binding")
        );
        changed = base;
        changed.negotiation_generation = 2;
        assert_ne!(
            fingerprint,
            media_e2ee_context_binding(&changed).expect("binding")
        );
    }
}
