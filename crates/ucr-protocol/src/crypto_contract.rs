pub use ucr_model::{CryptoSuite, KeyPurpose, PublicKeyDescriptor};

pub const CRYPTO_SUITE_ID: &str = "ucr.crypto.v1";
pub const SIGNATURE_ALGORITHM_ID: &str = "ed25519";
pub const AGREEMENT_ALGORITHM_ID: &str = "x25519";
pub const KDF_ALGORITHM_ID: &str = "hkdf-sha256";
pub const AEAD_ALGORITHM_ID: &str = "xchacha20-poly1305";
pub const ALGORITHM_VERSION: u32 = 1;
pub const KEY_FORMAT_VERSION: u32 = 1;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const HANDSHAKE_NONCE_LEN: usize = 32;
pub const TRANSCRIPT_BINDING_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const KEY_CONFIRMATION_TAG_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoContractError {
    WrongAlgorithm,
    WrongAlgorithmVersion,
    WrongKeyFormatVersion,
    WrongPublicKeyLength,
}

/// Validates a public-key descriptor against the negotiated crypto suite.
///
/// # Errors
/// Rejects algorithm, version, key-format, or key-length mismatches. The
/// descriptor is metadata only and never establishes trust by itself.
pub fn validate_public_key_descriptor(
    suite: CryptoSuite,
    descriptor: &PublicKeyDescriptor,
) -> Result<(), CryptoContractError> {
    let (algorithm, key_len) = match (suite, descriptor.purpose) {
        (CryptoSuite::UcrV1, KeyPurpose::Signing) => {
            (SIGNATURE_ALGORITHM_ID, ED25519_PUBLIC_KEY_LEN)
        }
        (CryptoSuite::UcrV1, KeyPurpose::KeyAgreement) => {
            (AGREEMENT_ALGORITHM_ID, X25519_PUBLIC_KEY_LEN)
        }
    };
    if descriptor.algorithm_id != algorithm {
        return Err(CryptoContractError::WrongAlgorithm);
    }
    if descriptor.algorithm_version != ALGORITHM_VERSION {
        return Err(CryptoContractError::WrongAlgorithmVersion);
    }
    if descriptor.key_format_version != KEY_FORMAT_VERSION {
        return Err(CryptoContractError::WrongKeyFormatVersion);
    }
    if descriptor.public_key.len() != key_len {
        return Err(CryptoContractError::WrongPublicKeyLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{DeviceId, KeyId, OpaqueId};

    use super::*;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn descriptor(purpose: KeyPurpose) -> PublicKeyDescriptor {
        let algorithm_id = match purpose {
            KeyPurpose::Signing => SIGNATURE_ALGORITHM_ID,
            KeyPurpose::KeyAgreement => AGREEMENT_ALGORITHM_ID,
        };
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(id("key-a")),
            device_id: DeviceId::from_opaque(id("device-a")),
            purpose,
            algorithm_id: algorithm_id.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![7_u8; 32],
        }
    }
    #[test]
    fn suite_v1_accepts_expected_signing_and_agreement_keys() {
        assert_eq!(
            validate_public_key_descriptor(CryptoSuite::UcrV1, &descriptor(KeyPurpose::Signing)),
            Ok(())
        );
        assert_eq!(
            validate_public_key_descriptor(
                CryptoSuite::UcrV1,
                &descriptor(KeyPurpose::KeyAgreement)
            ),
            Ok(())
        );
    }

    #[test]
    fn descriptor_mismatches_fail_closed() {
        let mut wrong_algorithm = descriptor(KeyPurpose::Signing);
        wrong_algorithm.algorithm_id = AGREEMENT_ALGORITHM_ID.to_owned();
        assert_eq!(
            validate_public_key_descriptor(CryptoSuite::UcrV1, &wrong_algorithm),
            Err(CryptoContractError::WrongAlgorithm)
        );

        let mut wrong_length = descriptor(KeyPurpose::KeyAgreement);
        wrong_length.public_key.pop();
        assert_eq!(
            validate_public_key_descriptor(CryptoSuite::UcrV1, &wrong_length),
            Err(CryptoContractError::WrongPublicKeyLength)
        );
    }
}
