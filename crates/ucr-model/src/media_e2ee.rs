use core::fmt;

use crate::{CallId, CryptoSuite, DeviceId, OpaqueId, PrincipalRef, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MediaKind {
    Audio = 1,
    Video = 2,
}

/// Exact direct-call security context for one Phase-22 media key epoch.
///
/// This is ephemeral security metadata. It is not a second Call, Identity, Group, transport,
/// durable media store, or adaptive-media policy owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaE2eeContext {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub initiator: PrincipalRef,
    pub responder: PrincipalRef,
    pub initiator_device_id: DeviceId,
    pub responder_device_id: DeviceId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub key_epoch: u64,
    pub crypto_suite: CryptoSuite,
}

/// Authenticated cleartext header for one encrypted realtime media payload.
/// Every field is covered by AEAD associated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaE2eeFrameHeader {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub stream_id: OpaqueId,
    pub source: PrincipalRef,
    pub recipient: PrincipalRef,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub key_epoch: u64,
    pub crypto_suite: CryptoSuite,
    pub session_binding: [u8; 32],
    pub media_kind: MediaKind,
    pub sequence: u64,
    pub media_timestamp: u64,
    pub keyframe: bool,
}

/// Ciphertext wrapper around one encoded Audio or Video payload.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedMediaFrame {
    pub header: MediaE2eeFrameHeader,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedMediaFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedMediaFrame")
            .field("header", &self.header)
            .field("nonce", &"<nonce>")
            .field("ciphertext", &"<encrypted-media>")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}
