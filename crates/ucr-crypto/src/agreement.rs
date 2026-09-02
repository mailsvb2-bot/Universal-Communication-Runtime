use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgreementError {
    OsRandomUnavailable,
    NonContributoryPeerKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgreementPublicKey(pub [u8; 32]);

pub struct AgreementKeyPair {
    secret: StaticSecret,
    public: AgreementPublicKey,
}

impl core::fmt::Debug for AgreementKeyPair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgreementKeyPair")
            .field("secret", &"<secret>")
            .field("public", &self.public)
            .finish()
    }
}
impl AgreementKeyPair {
    /// Generates an ephemeral/static X25519 key pair from the OS CSPRNG.
    ///
    /// # Errors
    /// Returns an explicit failure if the OS random source is unavailable.
    pub fn generate() -> Result<Self, AgreementError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| AgreementError::OsRandomUnavailable)?;
        let secret = StaticSecret::from(*bytes);
        let public = AgreementPublicKey(PublicKey::from(&secret).to_bytes());
        Ok(Self { secret, public })
    }

    #[must_use]
    pub const fn public_key(&self) -> AgreementPublicKey {
        self.public
    }

    /// Computes a contributory X25519 shared secret.
    ///
    /// # Errors
    /// Rejects low-order/non-contributory peer keys which produce the all-zero
    /// shared secret class described by RFC 7748.
    pub fn agree(self, peer: AgreementPublicKey) -> Result<Zeroizing<[u8; 32]>, AgreementError> {
        let peer = PublicKey::from(peer.0);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(AgreementError::NonContributoryPeerKey);
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}
