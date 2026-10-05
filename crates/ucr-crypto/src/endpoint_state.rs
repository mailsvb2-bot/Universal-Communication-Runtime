use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use ucr_protocol::DEFAULT_MAX_PAYLOAD_LEN;

const ENDPOINT_STATE_AAD_MAX_LEN: usize = 64 * 1024;
pub const ENDPOINT_STATE_KEY_LEN: usize = 32;
pub const ENDPOINT_STATE_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
pub const MAX_ENDPOINT_STATE_PLAINTEXT_LEN: usize =
    DEFAULT_MAX_PAYLOAD_LEN as usize - AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointStateError {
    InvalidWrappingKey,
    EmptyAssociatedData,
    AssociatedDataTooLarge,
    StateTooLarge,
    OsRandomUnavailable,
    EncryptionFailed,
    DecryptionFailed,
}

pub struct EndpointStateWrappingKey(Zeroizing<[u8; ENDPOINT_STATE_KEY_LEN]>);

impl core::fmt::Debug for EndpointStateWrappingKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("EndpointStateWrappingKey")
            .field(&"<secret>")
            .finish()
    }
}

impl EndpointStateWrappingKey {
    /// Imports endpoint-local wrapping key material.
    ///
    /// # Errors
    /// Rejects the all-zero sentinel rather than silently accepting an unusable key.
    pub fn import(bytes: [u8; ENDPOINT_STATE_KEY_LEN]) -> Result<Self, EndpointStateError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(EndpointStateError::InvalidWrappingKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEndpointState {
    pub nonce: [u8; ENDPOINT_STATE_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypts browser endpoint state with mandatory binding data and a fresh nonce.
///
/// # Errors
/// Fails closed for invalid AAD, oversized state, randomness failure, or AEAD failure.
pub fn seal_endpoint_state(
    key: &EndpointStateWrappingKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedEndpointState, EndpointStateError> {
    validate_inputs(aad, plaintext.len())?;
    let mut nonce = [0_u8; ENDPOINT_STATE_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| EndpointStateError::OsRandomUnavailable)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| EndpointStateError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).map_err(|_| EndpointStateError::EncryptionFailed)?,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EndpointStateError::EncryptionFailed)?;
    Ok(SealedEndpointState { nonce, ciphertext })
}

/// Opens and authenticates one endpoint-state package against exact binding data.
///
/// # Errors
/// Wrong key, wrong binding data, tampering, or oversized ciphertext fail closed.
pub fn open_endpoint_state(
    key: &EndpointStateWrappingKey,
    aad: &[u8],
    sealed: &SealedEndpointState,
) -> Result<Zeroizing<Vec<u8>>, EndpointStateError> {
    if aad.is_empty() {
        return Err(EndpointStateError::EmptyAssociatedData);
    }
    if aad.len() > ENDPOINT_STATE_AAD_MAX_LEN {
        return Err(EndpointStateError::AssociatedDataTooLarge);
    }
    if sealed.ciphertext.len() > DEFAULT_MAX_PAYLOAD_LEN as usize {
        return Err(EndpointStateError::StateTooLarge);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| EndpointStateError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            &XNonce::try_from(&sealed.nonce[..])
                .map_err(|_| EndpointStateError::DecryptionFailed)?,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| EndpointStateError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

fn validate_inputs(aad: &[u8], plaintext_len: usize) -> Result<(), EndpointStateError> {
    if aad.is_empty() {
        return Err(EndpointStateError::EmptyAssociatedData);
    }
    if aad.len() > ENDPOINT_STATE_AAD_MAX_LEN {
        return Err(EndpointStateError::AssociatedDataTooLarge);
    }
    if plaintext_len > MAX_ENDPOINT_STATE_PLAINTEXT_LEN {
        return Err(EndpointStateError::StateTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_state_round_trip_is_bound_to_aad() {
        let key = EndpointStateWrappingKey::import([7_u8; ENDPOINT_STATE_KEY_LEN]).unwrap();
        let sealed = seal_endpoint_state(&key, b"scope-a", b"private-mls-state").unwrap();
        assert_eq!(
            open_endpoint_state(&key, b"scope-a", &sealed)
                .unwrap()
                .as_slice(),
            b"private-mls-state"
        );
        assert_eq!(
            open_endpoint_state(&key, b"scope-b", &sealed),
            Err(EndpointStateError::DecryptionFailed)
        );
    }

    #[test]
    fn endpoint_state_tampering_and_zero_key_fail_closed() {
        assert!(matches!(
            EndpointStateWrappingKey::import([0_u8; ENDPOINT_STATE_KEY_LEN]),
            Err(EndpointStateError::InvalidWrappingKey)
        ));

        let key = EndpointStateWrappingKey::import([9_u8; ENDPOINT_STATE_KEY_LEN]).unwrap();
        let mut sealed = seal_endpoint_state(&key, b"bound", b"state").unwrap();
        sealed.ciphertext[0] ^= 1;
        assert_eq!(
            open_endpoint_state(&key, b"bound", &sealed),
            Err(EndpointStateError::DecryptionFailed)
        );
    }
}
