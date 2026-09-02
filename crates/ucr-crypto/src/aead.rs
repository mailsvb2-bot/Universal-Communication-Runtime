use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use ucr_protocol::DEFAULT_MAX_PAYLOAD_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    OsRandomUnavailable,
    EmptyAssociatedData,
    PayloadTooLarge,
    AssociatedDataTooLarge,
    EncryptionFailed,
    DecryptionFailed,
}

pub struct TrafficKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for TrafficKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("TrafficKey")
            .field(&"<secret>")
            .finish()
    }
}

pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_AAD_LEN: usize = 64 * 1024;
pub const MAX_CIPHERTEXT_LEN: usize = DEFAULT_MAX_PAYLOAD_LEN as usize;
pub const MAX_PLAINTEXT_LEN: usize = MAX_CIPHERTEXT_LEN - AEAD_TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub nonce: [u8; 24],
    pub bytes: Vec<u8>,
}
impl TrafficKey {
    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Encrypts plaintext with mandatory associated data and a fresh random nonce.
    ///
    /// # Errors
    /// Returns an explicit failure if nonce generation or AEAD encryption fails.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext, AeadError> {
        validate_aead_inputs(plaintext.len(), aad)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| AeadError::OsRandomUnavailable)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_ref())
            .map_err(|_| AeadError::EncryptionFailed)?;
        let bytes = cipher
            .encrypt(
                &XNonce::try_from(&nonce[..]).map_err(|_| AeadError::EncryptionFailed)?,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AeadError::EncryptionFailed)?;
        Ok(Ciphertext { nonce, bytes })
    }

    /// Decrypts and authenticates ciphertext against the supplied associated data.
    ///
    /// # Errors
    /// Returns an explicit integrity/decryption failure for tampering or wrong AAD.
    pub fn decrypt(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        if aad.is_empty() {
            return Err(AeadError::EmptyAssociatedData);
        }
        if aad.len() > MAX_AAD_LEN {
            return Err(AeadError::AssociatedDataTooLarge);
        }
        if ciphertext.bytes.len() > MAX_CIPHERTEXT_LEN {
            return Err(AeadError::PayloadTooLarge);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_ref())
            .map_err(|_| AeadError::DecryptionFailed)?;
        cipher
            .decrypt(
                &XNonce::try_from(&ciphertext.nonce[..])
                    .map_err(|_| AeadError::DecryptionFailed)?,
                Payload {
                    msg: &ciphertext.bytes,
                    aad,
                },
            )
            .map_err(|_| AeadError::DecryptionFailed)
    }
}

fn validate_aead_inputs(plaintext_len: usize, aad: &[u8]) -> Result<(), AeadError> {
    if aad.is_empty() {
        return Err(AeadError::EmptyAssociatedData);
    }
    if aad.len() > MAX_AAD_LEN {
        return Err(AeadError::AssociatedDataTooLarge);
    }
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(AeadError::PayloadTooLarge);
    }
    Ok(())
}
