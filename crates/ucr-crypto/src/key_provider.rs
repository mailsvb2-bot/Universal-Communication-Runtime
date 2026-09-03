use crate::{SignatureBytes, SignatureError, TranscriptBinding, VerifyingKeyBytes};
use ucr_protocol::MessageSigningBinding;

/// Non-exporting signing operation boundary for OS/hardware-backed keys.
pub trait SigningKeyHandle: core::fmt::Debug + Send + Sync {
    fn verifying_key(&self) -> VerifyingKeyBytes;

    /// Signs the already domain-separated UCR transcript binding.
    ///
    /// # Errors
    /// Returns an explicit provider/signature failure; private key bytes are
    /// never part of this interface.
    fn sign_transcript(
        &self,
        binding: &TranscriptBinding,
    ) -> Result<SignatureBytes, SignatureError>;

    /// Signs an already domain-separated canonical authored-Message binding.
    ///
    /// # Errors
    /// Returns an explicit provider/signature failure without exporting private key bytes.
    fn sign_message_binding(
        &self,
        binding: &MessageSigningBinding,
    ) -> Result<SignatureBytes, SignatureError>;
}
