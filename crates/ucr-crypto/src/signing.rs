use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::{SigningKeyHandle, TranscriptBinding};

const SIGNATURE_DOMAIN: &[u8] = b"UCR-HANDSHAKE-SIGNATURE-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    OsRandomUnavailable,
    InvalidPublicKey,
    InvalidSignature,
}

pub struct SigningKeyMaterial(SigningKey);

impl core::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("SigningKeyMaterial")
            .field(&"<secret>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKeyBytes(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);
impl SigningKeyMaterial {
    /// Generates a signing key from the operating-system CSPRNG.
    ///
    /// # Errors
    /// Returns an explicit error if the OS random source is unavailable.
    pub fn generate() -> Result<Self, SignatureError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| SignatureError::OsRandomUnavailable)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKeyBytes {
        VerifyingKeyBytes(self.0.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign_transcript(&self, binding: &TranscriptBinding) -> SignatureBytes {
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(binding.as_bytes());
        SignatureBytes(self.0.sign(&message).to_bytes())
    }
}

/// Verifies a transcript signature against a public Ed25519 key.
///
/// # Errors
/// Returns explicit invalid-key or invalid-signature failures.
pub fn verify_transcript_signature(
    public_key: VerifyingKeyBytes,
    binding: &TranscriptBinding,
    signature: SignatureBytes,
) -> Result<(), SignatureError> {
    let verifying_key =
        VerifyingKey::from_bytes(&public_key.0).map_err(|_| SignatureError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature.0);
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(binding.as_bytes());
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

impl SigningKeyHandle for SigningKeyMaterial {
    fn verifying_key(&self) -> VerifyingKeyBytes {
        SigningKeyMaterial::verifying_key(self)
    }

    fn sign_transcript(
        &self,
        binding: &TranscriptBinding,
    ) -> Result<SignatureBytes, SignatureError> {
        Ok(SigningKeyMaterial::sign_transcript(self, binding))
    }
}
