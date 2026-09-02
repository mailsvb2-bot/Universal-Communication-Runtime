use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{AgreementPublicKey, ConfirmationKey, TrafficKey, TranscriptBinding};

const KDF_DOMAIN: &[u8] = b"UCR-SESSION-KDF-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationError {
    ExpandFailed,
}

pub(crate) struct SessionSecrets {
    pub initiator_to_responder: TrafficKey,
    pub responder_to_initiator: TrafficKey,
    pub initiator_confirmation: ConfirmationKey,
    pub responder_confirmation: ConfirmationKey,
}

impl core::fmt::Debug for SessionSecrets {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SessionSecrets")
            .field("initiator_to_responder", &"<secret>")
            .field("responder_to_initiator", &"<secret>")
            .field("initiator_confirmation", &"<secret>")
            .field("responder_confirmation", &"<secret>")
            .finish()
    }
}
/// Derives direction-specific traffic and key-confirmation secrets.
///
/// The ordered public keys bind initiator/responder roles. The transcript hash
/// is used as HKDF salt so negotiated parameters and nonces affect all keys.
///
/// # Errors
/// Returns an explicit derivation failure if HKDF expansion fails.
pub(crate) fn derive_session_secrets(
    shared_secret: &Zeroizing<[u8; 32]>,
    binding: &TranscriptBinding,
    initiator_public: AgreementPublicKey,
    responder_public: AgreementPublicKey,
) -> Result<SessionSecrets, DerivationError> {
    let hkdf = Hkdf::<Sha256>::new(Some(binding.as_bytes()), shared_secret.as_ref());
    let mut context = Vec::with_capacity(KDF_DOMAIN.len() + 64);
    context.extend_from_slice(KDF_DOMAIN);
    context.extend_from_slice(&initiator_public.0);
    context.extend_from_slice(&responder_public.0);

    let i2r = expand_key(&hkdf, &context, b"traffic:i2r")?;
    let r2i = expand_key(&hkdf, &context, b"traffic:r2i")?;
    let iconfirm = expand_key(&hkdf, &context, b"confirm:initiator")?;
    let rconfirm = expand_key(&hkdf, &context, b"confirm:responder")?;

    Ok(SessionSecrets {
        initiator_to_responder: TrafficKey::from_bytes(i2r),
        responder_to_initiator: TrafficKey::from_bytes(r2i),
        initiator_confirmation: ConfirmationKey::from_bytes(iconfirm),
        responder_confirmation: ConfirmationKey::from_bytes(rconfirm),
    })
}
fn expand_key(
    hkdf: &Hkdf<Sha256>,
    context: &[u8],
    label: &[u8],
) -> Result<Zeroizing<[u8; 32]>, DerivationError> {
    let mut info = Vec::with_capacity(context.len() + label.len() + 8);
    info.extend_from_slice(context);
    info.extend_from_slice(&(label.len() as u64).to_be_bytes());
    info.extend_from_slice(label);

    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| DerivationError::ExpandFailed)?;
    info.zeroize();
    Ok(output)
}
