use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, GroupMediaE2eeContext, SfuForwardEnvelope,
};

use crate::{
    GroupMediaE2eeProtocolError, group_media_context_from_frame,
    validate_encrypted_group_media_frame,
};

pub const SFU_MEDIA_CAPABILITY: &str = "ucr.media.sfu";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuProtocolError {
    GroupMedia(GroupMediaE2eeProtocolError),
}

impl From<GroupMediaE2eeProtocolError> for SfuProtocolError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::GroupMedia(error)
    }
}

#[must_use]
pub fn phase29_sfu_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: SFU_MEDIA_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Validates the public encrypted group-media shape an SFU may route without decrypting it and
/// returns the exact authenticated epoch context reconstructed from the frame header.
///
/// # Errors
/// Rejects malformed MLS-backed group media before any infrastructure side effect.
pub fn canonical_sfu_forward_envelope(
    envelope: &SfuForwardEnvelope,
) -> Result<(GroupMediaE2eeContext, SfuForwardEnvelope), SfuProtocolError> {
    let context = group_media_context_from_frame(&envelope.frame)?;
    validate_encrypted_group_media_frame(&context, &envelope.frame)?;
    Ok((context, envelope.clone()))
}
