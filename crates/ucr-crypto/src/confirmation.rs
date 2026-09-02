use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::TranscriptBinding;

const CONFIRMATION_DOMAIN: &[u8] = b"UCR-KEY-CONFIRMATION-V1\0";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationError {
    InitializationFailed,
    InvalidTag,
}

pub struct ConfirmationKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for ConfirmationKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ConfirmationKey")
            .field(&"<secret>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationTag(pub [u8; 32]);
impl ConfirmationKey {
    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Computes a key-confirmation tag for the transcript.
    ///
    /// # Errors
    /// Returns an explicit initialization failure if the MAC cannot be created.
    pub fn tag(&self, binding: &TranscriptBinding) -> Result<ConfirmationTag, ConfirmationError> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .map_err(|_| ConfirmationError::InitializationFailed)?;
        mac.update(CONFIRMATION_DOMAIN);
        mac.update(binding.as_bytes());
        Ok(ConfirmationTag(mac.finalize().into_bytes().into()))
    }

    /// Verifies the peer's key-confirmation tag in constant time.
    ///
    /// # Errors
    /// Returns [`ConfirmationError::InvalidTag`] when confirmation fails.
    pub fn verify(
        &self,
        binding: &TranscriptBinding,
        tag: ConfirmationTag,
    ) -> Result<(), ConfirmationError> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .map_err(|_| ConfirmationError::InitializationFailed)?;
        mac.update(CONFIRMATION_DOMAIN);
        mac.update(binding.as_bytes());
        mac.verify_slice(&tag.0)
            .map_err(|_| ConfirmationError::InvalidTag)
    }
}
