use ucr_model::OpaqueId;

pub const CANONICAL_ID_GENERATION_ALGORITHM_ID: &str = "ucr.id.random_hex.v1";
pub const CANONICAL_ID_RANDOM_BYTES: usize = 16;
pub const CANONICAL_ID_TEXT_LEN: usize = CANONICAL_ID_RANDOM_BYTES * 2;

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeIdEncodingError {
    InvariantViolation,
}

/// Deterministically encodes 128 bits of caller-supplied CSPRNG entropy as a
/// native `ucr.id.random_hex.v1` opaque ID.
///
/// This function owns only the language-independent encoding. Runtime callers
/// must obtain the input from a cryptographically secure random source; the
/// protocol layer deliberately does not depend on an operating-system RNG.
///
/// # Errors
/// Returns an internal invariant failure if the fixed encoding ever stops
/// satisfying the canonical [`OpaqueId`] representation contract.
pub fn encode_native_opaque_id(
    random: [u8; CANONICAL_ID_RANDOM_BYTES],
) -> Result<OpaqueId, NativeIdEncodingError> {
    let mut token = String::with_capacity(CANONICAL_ID_TEXT_LEN);
    for byte in random {
        token.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        token.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    OpaqueId::new(token).map_err(|_| NativeIdEncodingError::InvariantViolation)
}

#[cfg(test)]
mod tests {
    use super::{
        CANONICAL_ID_GENERATION_ALGORITHM_ID, CANONICAL_ID_RANDOM_BYTES, CANONICAL_ID_TEXT_LEN,
        encode_native_opaque_id,
    };

    #[test]
    fn generation_contract_has_stable_algorithm_and_golden_encoding() {
        assert_eq!(CANONICAL_ID_GENERATION_ALGORITHM_ID, "ucr.id.random_hex.v1");
        assert_eq!(CANONICAL_ID_RANDOM_BYTES, 16);
        assert_eq!(CANONICAL_ID_TEXT_LEN, 32);
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x7f, 0x80, 0x9a, 0xbc, 0xde, 0xff, 0x42, 0x55,
            0xaa, 0xf0,
        ];
        let id = encode_native_opaque_id(bytes).expect("encode fixed random bytes");
        assert_eq!(id.as_str(), "0001020310117f809abcdeff4255aaf0");
        assert_eq!(id.as_wire_bytes(), id.as_str().as_bytes());
    }
}
