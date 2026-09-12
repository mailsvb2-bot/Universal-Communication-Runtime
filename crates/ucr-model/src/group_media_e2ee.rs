use core::fmt;

use crate::{
    CallId, CryptoSuite, DeviceId, GroupId, KeyId, MediaKind, OpaqueId, PrincipalRef, TenantScope,
};

/// Immutable security context for one MLS-backed group-media epoch.
///
/// The context binds realtime media to the canonical Group, Call negotiation and exact group-crypto
/// epoch. It contains no key material and is safe to expose to an SFU as bounded routing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMediaE2eeContext {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub group_id: GroupId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub crypto_epoch: u64,
    pub crypto_state_ref: OpaqueId,
    pub crypto_suite: CryptoSuite,
}

/// Clear group-media routing metadata authenticated as AEAD associated data.
///
/// `source_device_id` is explicit because MLS membership and revocation are device-sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMediaFrameHeader {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub group_id: GroupId,
    pub stream_id: OpaqueId,
    pub source: PrincipalRef,
    pub source_device_id: DeviceId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub crypto_epoch: u64,
    pub crypto_state_ref: OpaqueId,
    pub crypto_suite: CryptoSuite,
    pub media_kind: MediaKind,
    pub sequence: u64,
    pub media_timestamp: u64,
    pub keyframe: bool,
}

/// Device signature proving which active endpoint produced one encrypted group-media frame.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupMediaSourceSignature {
    pub key_id: KeyId,
    pub algorithm_id: String,
    pub algorithm_version: u32,
    pub signature: Vec<u8>,
}

impl fmt::Debug for GroupMediaSourceSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupMediaSourceSignature")
            .field("key_id", &self.key_id)
            .field("algorithm_id", &self.algorithm_id)
            .field("algorithm_version", &self.algorithm_version)
            .field("signature", &"<opaque>")
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// One endpoint-encrypted and source-authenticated group-media frame.
///
/// The SFU is allowed to observe the authenticated header, signature metadata and ciphertext length,
/// but never plaintext or the MLS exporter secret used to derive the stream traffic key.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedGroupMediaFrame {
    pub header: GroupMediaFrameHeader,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub source_signature: GroupMediaSourceSignature,
}

impl fmt::Debug for EncryptedGroupMediaFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedGroupMediaFrame")
            .field("header", &self.header)
            .field("nonce", &"<redacted>")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("source_signature", &self.source_signature)
            .finish()
    }
}
