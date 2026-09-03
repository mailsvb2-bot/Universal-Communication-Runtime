#![forbid(unsafe_code)]

mod aead;
mod agreement;
mod confirmation;
mod kdf;
mod key_provider;
mod message_signature;
mod recovery;
mod rng;
mod session;
mod signing;
mod transcript;
mod trusted_key;

pub use aead::{AeadError, Ciphertext, TrafficKey};
pub use agreement::{AgreementError, AgreementKeyPair, AgreementPublicKey};
pub use confirmation::{ConfirmationError, ConfirmationKey, ConfirmationTag};
pub use kdf::DerivationError;
pub use key_provider::SigningKeyHandle;
pub use message_signature::{
    MessageSignatureVerificationError, TrustedMessageSignatureError, verify_message_signature,
    verify_message_signature_with_trust,
};
pub use recovery::{
    MAX_RECOVERY_MATERIAL_LEN, RECOVERY_NONCE_LEN, RECOVERY_PACKAGE_FORMAT_VERSION,
    RECOVERY_SECRET_LEN, RecoveryPackageError, RecoverySecret, open_recovery_material,
    seal_recovery_material,
};
pub use rng::{RandomError, generate_handshake_nonce};
pub use session::{
    EstablishedSession, PendingSession, ReplayError, ReplayProtector, SessionError,
    SessionHandshakeInput, SessionRole, TrustedSessionError, TrustedSessionHandshakeInput,
    begin_session, begin_session_with_trusted_peer,
};
pub use signing::{
    MESSAGE_SIGNATURE_V1_DOMAIN, SignatureBytes, SignatureError, SigningKeyMaterial,
    VerifyingKeyBytes, verify_message_binding_signature, verify_transcript_signature,
};
pub use transcript::{TranscriptBinding, TranscriptError, bind_handshake_transcript};
pub use trusted_key::{TrustedKeyResolutionError, TrustedSigningKeyResolver};

pub use ucr_protocol::{
    AEAD_ALGORITHM_ID, AGREEMENT_ALGORITHM_ID, ALGORITHM_VERSION, CRYPTO_SUITE_ID,
    KDF_ALGORITHM_ID, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID,
};

#[cfg(test)]
mod tests;
