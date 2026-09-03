use ucr_model::OpaqueId;
use ucr_protocol::{
    CANONICAL_ID_RANDOM_BYTES, CanonicalError, CanonicalErrorCode, NativeIdEncodingError,
    encode_native_opaque_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdGenerationError {
    OsRandomUnavailable,
    InternalEncoding,
}

impl From<IdGenerationError> for CanonicalError {
    fn from(_error: IdGenerationError) -> Self {
        Self::new(CanonicalErrorCode::Internal)
    }
}

/// Generates one native canonical UCR ID without network, clock, or server
/// coordination.
///
/// The runtime obtains exactly 128 bits from the operating-system CSPRNG and
/// delegates the stable random-hex-v1 encoding to `ucr-protocol`. There is no
/// fallback to time, counters, host metadata, provider IDs, or server state.
///
/// # Errors
/// Returns an explicit internal failure when OS randomness is unavailable or
/// the protocol encoding invariant fails.
pub fn generate_opaque_id() -> Result<OpaqueId, IdGenerationError> {
    generate_opaque_id_with(|bytes| {
        getrandom::fill(bytes).map_err(|_| IdGenerationError::OsRandomUnavailable)
    })
}

fn generate_opaque_id_with<F>(mut fill: F) -> Result<OpaqueId, IdGenerationError>
where
    F: FnMut(&mut [u8]) -> Result<(), IdGenerationError>,
{
    let mut random = [0_u8; CANONICAL_ID_RANDOM_BYTES];
    fill(&mut random)?;
    encode_native_opaque_id(random)
        .map_err(|NativeIdEncodingError::InvariantViolation| IdGenerationError::InternalEncoding)
}

#[cfg(test)]
mod tests {
    use super::{IdGenerationError, generate_opaque_id, generate_opaque_id_with};
    use ucr_protocol::{CANONICAL_ID_TEXT_LEN, CanonicalError, CanonicalErrorCode};

    #[test]
    fn generator_fails_closed_when_os_randomness_is_unavailable() {
        let error = generate_opaque_id_with(|_| Err(IdGenerationError::OsRandomUnavailable))
            .expect_err("random failure must not fall back");
        assert_eq!(error, IdGenerationError::OsRandomUnavailable);
        assert_eq!(
            CanonicalError::from(error).code,
            CanonicalErrorCode::Internal
        );
    }

    #[test]
    fn production_generator_emits_semantically_valid_lower_hex_tokens() {
        let id = generate_opaque_id().expect("OS CSPRNG available in test environment");
        assert_eq!(id.as_wire_bytes().len(), CANONICAL_ID_TEXT_LEN);
        assert!(
            id.as_wire_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        );
    }
}
