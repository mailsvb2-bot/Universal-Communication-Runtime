use sha2::{Digest, Sha256};

use crate::AgreementPublicKey;

const TRANSCRIPT_DOMAIN: &[u8] = b"UCR-TRANSCRIPT-V1\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranscriptBinding([u8; 32]);

impl core::fmt::Debug for TranscriptBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("TranscriptBinding")
            .field(&"<sha256>")
            .finish()
    }
}

impl TranscriptBinding {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptError {
    EmptyInitiatorHello,
    EmptyResponderHello,
    EmptyNegotiationResult,
}

fn hash_transcript(parts: &[&[u8]]) -> TranscriptBinding {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update((parts.len() as u64).to_be_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    TranscriptBinding(hasher.finalize().into())
}

/// Binds the exact negotiated wire transcript and both ephemeral agreement keys.
///
/// Callers must pass the raw canonical UCR handshake frame bytes in initiator/
/// responder order. This preserves unknown fields and prevents reconstruction drift.
///
/// # Errors
/// Rejects an omitted hello or negotiation result.
pub fn bind_handshake_transcript(
    initiator_hello_frame: &[u8],
    responder_hello_frame: &[u8],
    negotiation_result_frame: &[u8],
    initiator_ephemeral: AgreementPublicKey,
    responder_ephemeral: AgreementPublicKey,
) -> Result<TranscriptBinding, TranscriptError> {
    if initiator_hello_frame.is_empty() {
        return Err(TranscriptError::EmptyInitiatorHello);
    }
    if responder_hello_frame.is_empty() {
        return Err(TranscriptError::EmptyResponderHello);
    }
    if negotiation_result_frame.is_empty() {
        return Err(TranscriptError::EmptyNegotiationResult);
    }
    Ok(hash_transcript(&[
        initiator_hello_frame,
        responder_hello_frame,
        negotiation_result_frame,
        &initiator_ephemeral.0,
        &responder_ephemeral.0,
    ]))
}

#[cfg(test)]
mod tests {
    use super::hash_transcript;

    #[test]
    fn transcript_is_order_and_boundary_sensitive() {
        let first = hash_transcript(&[b"ab", b"c"]);
        let second = hash_transcript(&[b"a", b"bc"]);
        let reversed = hash_transcript(&[b"c", b"ab"]);
        assert_ne!(first, second);
        assert_ne!(first, reversed);
    }
}
