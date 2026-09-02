#![forbid(unsafe_code)]

mod aead;
mod agreement;
mod confirmation;
mod kdf;
mod key_provider;
mod rng;
mod session;
mod signing;
mod transcript;

pub use aead::{AeadError, Ciphertext, TrafficKey};
pub use agreement::{AgreementError, AgreementKeyPair, AgreementPublicKey};
pub use confirmation::{ConfirmationError, ConfirmationKey, ConfirmationTag};
pub use kdf::DerivationError;
pub use key_provider::SigningKeyHandle;
pub use rng::{RandomError, generate_handshake_nonce};
pub use session::{
    EstablishedSession, PendingSession, ReplayError, ReplayProtector, SessionError,
    SessionHandshakeInput, SessionRole, begin_session,
};
pub use signing::{
    SignatureBytes, SignatureError, SigningKeyMaterial, VerifyingKeyBytes,
    verify_transcript_signature,
};
pub use transcript::{TranscriptBinding, TranscriptError, bind_handshake_transcript};

pub use ucr_protocol::{
    AEAD_ALGORITHM_ID, AGREEMENT_ALGORITHM_ID, ALGORITHM_VERSION, CRYPTO_SUITE_ID,
    KDF_ALGORITHM_ID, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID,
};

#[cfg(test)]
mod tests;
