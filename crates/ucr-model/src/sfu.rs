use core::fmt;

use crate::{EncryptedGroupMediaFrame, PrincipalRef};

/// One already-encrypted group-media frame offered to a Phase-29 SFU routing boundary.
///
/// The SFU never owns plaintext media, MLS exporter secrets, Call state, Group membership state,
/// Delivery state, or Conference state.
#[derive(Clone, PartialEq, Eq)]
pub struct SfuForwardEnvelope {
    pub frame: EncryptedGroupMediaFrame,
}

impl fmt::Debug for SfuForwardEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SfuForwardEnvelope")
            .field("frame_header", &self.frame.header)
            .field("ciphertext_len", &self.frame.ciphertext.len())
            .field("source_signature", &self.frame.source_signature)
            .finish_non_exhaustive()
    }
}

/// Ephemeral SFU fan-out target derived from the current canonical Call participant set.
///
/// This is not durable membership, a subscription owner or Conference state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuForwardTarget {
    pub recipient: PrincipalRef,
}
