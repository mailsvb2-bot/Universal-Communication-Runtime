use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use ucr_model::{DeviceId, GroupMediaE2eeContext, MediaKind, OpaqueId, PrincipalRef};
use ucr_protocol::{
    GroupMediaE2eeProtocolError, group_media_context_binding, group_media_key_context,
};

use crate::{SignatureBytes, SignatureError, SigningKeyMaterial, TrafficKey, VerifyingKeyBytes};
use ucr_protocol::GroupMediaSigningBinding;

const GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-TRAFFIC-KDF-V1\0";

/// Non-exporting signing boundary for source-authenticated group media.
pub trait GroupMediaSigningKeyHandle: core::fmt::Debug + Send + Sync {
    fn verifying_key(&self) -> VerifyingKeyBytes;

    /// Signs one already domain-separated canonical group-media frame binding.
    ///
    /// # Errors
    /// Returns an explicit provider/signature failure without exporting private key bytes.
    fn sign_group_media_binding(
        &self,
        binding: &GroupMediaSigningBinding,
    ) -> Result<SignatureBytes, SignatureError>;
}

impl GroupMediaSigningKeyHandle for SigningKeyMaterial {
    fn verifying_key(&self) -> VerifyingKeyBytes {
        SigningKeyMaterial::verifying_key(self)
    }

    fn sign_group_media_binding(
        &self,
        binding: &GroupMediaSigningBinding,
    ) -> Result<SignatureBytes, SignatureError> {
        Ok(SigningKeyMaterial::sign_group_media_binding(self, binding))
    }
}

/// MLS exporter material for one exact group epoch.
///
/// This value is endpoint-only key material. It must never cross the SFU boundary, appear in logs,
/// or be persisted by UCR outside the standardized MLS provider's own protected state.
pub struct GroupMediaEpochSecret(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for GroupMediaEpochSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("GroupMediaEpochSecret")
            .field(&"<secret>")
            .finish()
    }
}

impl GroupMediaEpochSecret {
    /// Wraps exactly 32 bytes exported by the standardized MLS provider.
    #[must_use]
    pub fn from_exporter_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaKeyError {
    Protocol(GroupMediaE2eeProtocolError),
    ExpandFailed,
}

impl From<GroupMediaE2eeProtocolError> for GroupMediaKeyError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Derives a source/stream-specific AEAD key from one MLS epoch exporter secret.
///
/// The exact UCR group-media context is used as HKDF salt and the source Device, stream and media
/// kind are included in HKDF info. This prevents key reuse between independent senders/streams while
/// preserving one MLS group epoch as the membership/key-lifecycle authority.
///
/// # Errors
/// Rejects malformed context/source bindings or HKDF expansion failure.
pub fn derive_group_media_traffic_key(
    epoch_secret: &GroupMediaEpochSecret,
    context: &GroupMediaE2eeContext,
    source: &PrincipalRef,
    source_device_id: &DeviceId,
    stream_id: &OpaqueId,
    media_kind: MediaKind,
) -> Result<TrafficKey, GroupMediaKeyError> {
    let binding = group_media_context_binding(context)?;
    let key_context =
        group_media_key_context(context, source, source_device_id, stream_id, media_kind)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&binding), epoch_secret.0.as_ref());
    let mut info = Vec::with_capacity(GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN.len() + key_context.len());
    info.extend_from_slice(GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN);
    info.extend_from_slice(&key_context);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| GroupMediaKeyError::ExpandFailed)?;
    Ok(TrafficKey::from_bytes(output))
}
