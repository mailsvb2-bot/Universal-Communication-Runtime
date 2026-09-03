use crate::kdf::derive_session_secrets;
use crate::{
    AgreementError, AgreementKeyPair, AgreementPublicKey, ConfirmationError, ConfirmationKey,
    ConfirmationTag, DerivationError, SignatureBytes, SignatureError, TrafficKey,
    TranscriptBinding, TrustedKeyResolutionError, TrustedSigningKeyResolver, VerifyingKeyBytes,
    verify_transcript_signature,
};
use ucr_model::{CryptoSuite, PublicKeyDescriptor, TenantScope};
use ucr_protocol::validate_trusted_signing_key_descriptor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHandshakeInput {
    pub suite: CryptoSuite,
    pub role: SessionRole,
    pub peer_agreement: AgreementPublicKey,
    pub initiator_public: AgreementPublicKey,
    pub responder_public: AgreementPublicKey,
    pub trusted_peer_verifying_key: VerifyingKeyBytes,
    pub peer_signature: SignatureBytes,
    pub binding: TranscriptBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSessionHandshakeInput {
    pub scope: TenantScope,
    pub suite: CryptoSuite,
    pub role: SessionRole,
    pub peer_agreement: AgreementPublicKey,
    pub initiator_public: AgreementPublicKey,
    pub responder_public: AgreementPublicKey,
    pub peer_signing_descriptor: PublicKeyDescriptor,
    pub peer_signature: SignatureBytes,
    pub binding: TranscriptBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedSessionError {
    Trust(TrustedKeyResolutionError),
    Session(SessionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    Replayed,
    StorageFull,
    CorruptState,
    Unavailable,
    PermissionDenied,
    Internal,
}

pub trait ReplayProtector: core::fmt::Debug + Send + Sync {
    /// Atomically records a peer+transcript binding once.
    ///
    /// # Errors
    /// Returns `Replayed` when the binding was already accepted or an explicit
    /// availability/internal failure when replay state cannot be trusted.
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Signature(SignatureError),
    Replay(ReplayError),
    Agreement(AgreementError),
    Derivation(DerivationError),
    Confirmation(ConfirmationError),
    LocalAgreementKeyMismatch,
    PeerAgreementKeyMismatch,
}

pub struct PendingSession {
    binding: TranscriptBinding,
    outbound: TrafficKey,
    inbound: TrafficKey,
    local_confirmation: ConfirmationKey,
    peer_confirmation: ConfirmationKey,
}

impl core::fmt::Debug for PendingSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingSession")
            .field("binding", &self.binding)
            .field("outbound", &"<secret>")
            .field("inbound", &"<secret>")
            .field("local_confirmation", &"<secret>")
            .field("peer_confirmation", &"<secret>")
            .finish()
    }
}

pub struct EstablishedSession {
    binding: TranscriptBinding,
    outbound: TrafficKey,
    inbound: TrafficKey,
}
impl core::fmt::Debug for EstablishedSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EstablishedSession")
            .field("binding", &self.binding)
            .field("outbound", &"<secret>")
            .field("inbound", &"<secret>")
            .finish()
    }
}

/// Verifies peer authentication and replay state, then derives pending session keys.
///
/// # Errors
/// Fails closed on invalid signature, replay-state failure, non-contributory key
/// agreement, or key derivation failure.
pub fn begin_session<R: ReplayProtector>(
    local_agreement: AgreementKeyPair,
    input: SessionHandshakeInput,
    replay: &R,
) -> Result<PendingSession, SessionError> {
    match input.suite {
        CryptoSuite::UcrV1 => {}
    }
    let (expected_local_public, expected_peer_public) = match input.role {
        SessionRole::Initiator => (input.initiator_public, input.responder_public),
        SessionRole::Responder => (input.responder_public, input.initiator_public),
    };
    if local_agreement.public_key() != expected_local_public {
        return Err(SessionError::LocalAgreementKeyMismatch);
    }
    if input.peer_agreement != expected_peer_public {
        return Err(SessionError::PeerAgreementKeyMismatch);
    }
    verify_transcript_signature(
        input.trusted_peer_verifying_key,
        &input.binding,
        input.peer_signature,
    )
    .map_err(SessionError::Signature)?;
    replay
        .record_once(&input.trusted_peer_verifying_key, &input.binding)
        .map_err(SessionError::Replay)?;
    let shared = local_agreement
        .agree(input.peer_agreement)
        .map_err(SessionError::Agreement)?;
    let secrets = derive_session_secrets(
        &shared,
        &input.binding,
        input.initiator_public,
        input.responder_public,
    )
    .map_err(SessionError::Derivation)?;
    let (outbound, inbound, local_confirmation, peer_confirmation) = match input.role {
        SessionRole::Initiator => (
            secrets.initiator_to_responder,
            secrets.responder_to_initiator,
            secrets.initiator_confirmation,
            secrets.responder_confirmation,
        ),
        SessionRole::Responder => (
            secrets.responder_to_initiator,
            secrets.initiator_to_responder,
            secrets.responder_confirmation,
            secrets.initiator_confirmation,
        ),
    };

    Ok(PendingSession {
        binding: input.binding,
        outbound,
        inbound,
        local_confirmation,
        peer_confirmation,
    })
}

/// Resolves an active trusted peer signing descriptor before beginning a secure session.
///
/// The peer-supplied descriptor is a claim, not a trust source. It must exactly equal
/// the independently resolved active descriptor for the requested scope/device/key.
///
/// # Errors
/// Returns a non-disclosing trust failure or the underlying session failure.
pub fn begin_session_with_trusted_peer<R, T>(
    local_agreement: AgreementKeyPair,
    input: &TrustedSessionHandshakeInput,
    replay: &R,
    trust: &T,
) -> Result<PendingSession, TrustedSessionError>
where
    R: ReplayProtector,
    T: TrustedSigningKeyResolver,
{
    let claim = &input.peer_signing_descriptor;
    let trusted = trust
        .resolve_active_signing_key(&input.scope, &claim.device_id, None, &claim.key_id)
        .map_err(TrustedSessionError::Trust)?;
    if trusted != *claim {
        return Err(TrustedSessionError::Trust(
            TrustedKeyResolutionError::NotTrusted,
        ));
    }
    validate_trusted_signing_key_descriptor(&trusted)
        .map_err(|_| TrustedSessionError::Trust(TrustedKeyResolutionError::Corrupt))?;
    let public_key: [u8; 32] = trusted
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| TrustedSessionError::Trust(TrustedKeyResolutionError::Corrupt))?;

    begin_session(
        local_agreement,
        SessionHandshakeInput {
            suite: input.suite,
            role: input.role,
            peer_agreement: input.peer_agreement,
            initiator_public: input.initiator_public,
            responder_public: input.responder_public,
            trusted_peer_verifying_key: VerifyingKeyBytes(public_key),
            peer_signature: input.peer_signature,
            binding: input.binding,
        },
        replay,
    )
    .map_err(TrustedSessionError::Session)
}

impl PendingSession {
    /// Computes this side's key-confirmation tag.
    ///
    /// # Errors
    /// Returns an explicit MAC initialization failure.
    pub fn local_confirmation_tag(&self) -> Result<ConfirmationTag, SessionError> {
        self.local_confirmation
            .tag(&self.binding)
            .map_err(SessionError::Confirmation)
    }
    /// Verifies peer key confirmation and transitions to an established session.
    ///
    /// # Errors
    /// Returns an explicit confirmation failure; traffic keys are not exposed
    /// through an established-session API when verification fails.
    pub fn confirm_peer(self, tag: ConfirmationTag) -> Result<EstablishedSession, SessionError> {
        self.peer_confirmation
            .verify(&self.binding, tag)
            .map_err(SessionError::Confirmation)?;
        Ok(EstablishedSession {
            binding: self.binding,
            outbound: self.outbound,
            inbound: self.inbound,
        })
    }
}

impl EstablishedSession {
    #[must_use]
    pub const fn transcript_binding(&self) -> &TranscriptBinding {
        &self.binding
    }

    /// Encrypts outbound application data using the direction-specific key.
    ///
    /// # Errors
    /// Returns explicit randomness/encryption failures.
    pub fn encrypt_outbound(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<crate::Ciphertext, crate::AeadError> {
        self.outbound.encrypt(plaintext, aad)
    }

    /// Authenticates and decrypts inbound application data.
    ///
    /// # Errors
    /// Returns an explicit integrity/decryption failure.
    pub fn decrypt_inbound(
        &self,
        ciphertext: &crate::Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, crate::AeadError> {
        self.inbound.decrypt(ciphertext, aad)
    }
}
