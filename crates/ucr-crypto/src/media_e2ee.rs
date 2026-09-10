use sha2::{Digest, Sha256};
use ucr_model::MediaE2eeContext;
use ucr_protocol::media_e2ee_context_binding;

use crate::{AgreementPublicKey, TranscriptBinding};

pub const MEDIA_E2EE_HANDSHAKE_V1_DOMAIN: &[u8] = b"UCR-MEDIA-E2EE-HANDSHAKE-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaE2eeBindingError {
    InvalidContext,
    ReusedEphemeralKey,
}

/// Binds one exact Phase-22 direct-call media key epoch and both fresh X25519 ephemerals.
///
/// This composes the existing UCR cryptographic suite; it does not define a new cipher,
/// signature, key-agreement, or KDF primitive.
///
/// # Errors
/// Rejects an invalid canonical media context or identical initiator/responder ephemeral keys.
pub fn bind_media_e2ee_transcript(
    context: &MediaE2eeContext,
    initiator_ephemeral: AgreementPublicKey,
    responder_ephemeral: AgreementPublicKey,
) -> Result<TranscriptBinding, MediaE2eeBindingError> {
    if initiator_ephemeral == responder_ephemeral {
        return Err(MediaE2eeBindingError::ReusedEphemeralKey);
    }
    let context_binding =
        media_e2ee_context_binding(context).map_err(|_| MediaE2eeBindingError::InvalidContext)?;
    let mut hasher = Sha256::new();
    hasher.update(MEDIA_E2EE_HANDSHAKE_V1_DOMAIN);
    hasher.update(context_binding);
    hasher.update(initiator_ephemeral.0);
    hasher.update(responder_ephemeral.0);
    Ok(TranscriptBinding::from_bytes(hasher.finalize().into()))
}
