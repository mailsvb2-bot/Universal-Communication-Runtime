use ucr_model::{CryptoSuite, KeyPurpose, PublicKeyDescriptor};

use crate::{CryptoContractError, validate_public_key_descriptor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedSigningKeyError {
    WrongPurpose,
    InvalidDescriptor(CryptoContractError),
}

/// Validates one descriptor for admission into trusted signing-key state.
///
/// # Errors
/// Rejects non-Signing purpose and any suite-v1 algorithm/version/format/length mismatch.
pub fn validate_trusted_signing_key_descriptor(
    descriptor: &PublicKeyDescriptor,
) -> Result<(), TrustedSigningKeyError> {
    if descriptor.purpose != KeyPurpose::Signing {
        return Err(TrustedSigningKeyError::WrongPurpose);
    }
    validate_public_key_descriptor(CryptoSuite::UcrV1, descriptor)
        .map_err(TrustedSigningKeyError::InvalidDescriptor)
}

#[cfg(test)]
mod tests {
    use ucr_model::{DeviceId, KeyId, OpaqueId};

    use super::*;
    use crate::{ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn descriptor() -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid("trusted-key")),
            device_id: DeviceId::from_opaque(oid("device-a")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![7_u8; 32],
        }
    }

    #[test]
    fn trusted_key_admission_requires_signing_suite_v1_descriptor() {
        assert_eq!(
            validate_trusted_signing_key_descriptor(&descriptor()),
            Ok(())
        );

        let mut agreement = descriptor();
        agreement.purpose = KeyPurpose::KeyAgreement;
        assert_eq!(
            validate_trusted_signing_key_descriptor(&agreement),
            Err(TrustedSigningKeyError::WrongPurpose)
        );

        let mut malformed = descriptor();
        malformed.public_key.pop();
        assert!(matches!(
            validate_trusted_signing_key_descriptor(&malformed),
            Err(TrustedSigningKeyError::InvalidDescriptor(_))
        ));
    }
}
