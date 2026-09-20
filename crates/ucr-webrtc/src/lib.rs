#![forbid(unsafe_code)]

use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use ucr_model::{
    IceServerConfig, IceTransportPolicy, SessionId, WebRtcIceCandidate, WebRtcSessionDescription,
};
use ucr_protocol::{
    CapabilityDescriptor, WebRtcProtocolError, canonical_ice_server, canonical_webrtc_candidate,
    canonical_webrtc_description, phase46_webrtc_capabilities,
};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcProviderError {
    InvalidProtocol(WebRtcProtocolError),
    SessionUnavailable,
    Conflict,
    CapacityExceeded,
    TemporarilyUnavailable,
    Internal,
}

impl From<WebRtcProtocolError> for WebRtcProviderError {
    fn from(error: WebRtcProtocolError) -> Self {
        Self::InvalidProtocol(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebRtcSessionConfig {
    pub session_id: SessionId,
    pub ice_servers: Vec<IceServerConfig>,
    pub ice_transport_policy: IceTransportPolicy,
}

impl fmt::Debug for WebRtcSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcSessionConfig")
            .field("session_id", &self.session_id)
            .field("ice_server_count", &self.ice_servers.len())
            .field("ice_transport_policy", &self.ice_transport_policy)
            .finish()
    }
}

pub trait WebRtcProvider: fmt::Debug + Send + Sync {
    /// Returns truthful runtime capability maturity for this provider.
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;

    /// Creates one ephemeral peer-connection session. Canonical Call/Conference state stays
    /// outside this provider.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn create_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError>;

    /// Applies the remote offer/answer for an existing provider session.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError>;

    /// Applies one trickle-ICE candidate.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn add_remote_candidate(
        &self,
        candidate: &WebRtcIceCandidate,
    ) -> Result<(), WebRtcProviderError>;

    /// Closes ephemeral provider state. It does not end the canonical Call by itself.
    ///
    /// # Errors
    /// Returns bounded provider failures.
    fn close_session(&self, session_id: &SessionId) -> Result<(), WebRtcProviderError>;
}

pub const MIN_TURN_CREDENTIAL_TTL_SECONDS: u32 = 30;
pub const MAX_TURN_CREDENTIAL_TTL_SECONDS: u32 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnCredentialError {
    InvalidTtl,
    ClockOverflow,
    CryptoUnavailable,
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TurnRestSecret([u8; 32]);

impl TurnRestSecret {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TurnRestSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TurnRestSecret")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IssuedTurnCredential {
    pub username: String,
    pub credential: String,
    pub expires_at_unix_seconds: u64,
}

impl fmt::Debug for IssuedTurnCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTurnCredential")
            .field("username", &self.username)
            .field("credential", &"<redacted>")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

#[derive(Clone)]
pub struct TurnRestCredentialIssuer {
    secret: TurnRestSecret,
}

impl fmt::Debug for TurnRestCredentialIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnRestCredentialIssuer")
            .finish_non_exhaustive()
    }
}

impl TurnRestCredentialIssuer {
    #[must_use]
    pub const fn new(secret: TurnRestSecret) -> Self {
        Self { secret }
    }

    /// Issues coturn TURN REST API compatible time-limited credentials for one realtime session.
    ///
    /// The username embeds the expiry timestamp and canonical session identifier. The credential
    /// is HMAC-SHA1 as required by coturn shared-secret mode. The shared secret never leaves this
    /// issuer and is not persisted by the WebRTC provider.
    ///
    /// # Errors
    /// Returns InvalidTtl outside the bounded lifetime, ClockOverflow on expiry overflow, or
    /// CryptoUnavailable if the platform crypto provider fails.
    pub fn issue(
        &self,
        session_id: &SessionId,
        ttl_seconds: u32,
        now_unix_seconds: u64,
    ) -> Result<IssuedTurnCredential, TurnCredentialError> {
        if !(MIN_TURN_CREDENTIAL_TTL_SECONDS..=MAX_TURN_CREDENTIAL_TTL_SECONDS)
            .contains(&ttl_seconds)
        {
            return Err(TurnCredentialError::InvalidTtl);
        }
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(u64::from(ttl_seconds))
            .ok_or(TurnCredentialError::ClockOverflow)?;
        let username = format!(
            "{expires_at_unix_seconds}:{}",
            session_id.as_opaque().as_str()
        );
        let key = PKey::hmac(&self.secret.0).map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        let mut signer = Signer::new(MessageDigest::sha1(), &key)
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        signer
            .update(username.as_bytes())
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        let mac = signer
            .sign_to_vec()
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        Ok(IssuedTurnCredential {
            username,
            credential: STANDARD.encode(mac),
            expires_at_unix_seconds,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedWebRtcProvider;

impl WebRtcProvider for PreparedWebRtcProvider {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase46_webrtc_capabilities()
    }

    fn create_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
        if config.ice_servers.len() > ucr_protocol::MAX_ICE_SERVERS {
            return Err(WebRtcProviderError::InvalidProtocol(
                WebRtcProtocolError::TooManyIceServers,
            ));
        }
        for server in &config.ice_servers {
            canonical_ice_server(server)?;
        }
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError> {
        canonical_webrtc_description(description)?;
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn add_remote_candidate(
        &self,
        candidate: &WebRtcIceCandidate,
    ) -> Result<(), WebRtcProviderError> {
        canonical_webrtc_candidate(candidate)?;
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn close_session(&self, _session_id: &SessionId) -> Result<(), WebRtcProviderError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{IceCredentialType, OpaqueId};
    use ucr_protocol::{CapabilityMaturity, WEBRTC_BROWSER_CAPABILITY};

    #[test]
    fn turn_rest_credentials_are_short_lived_session_bound_and_redacted() {
        let session_id = SessionId::from_opaque(OpaqueId::new("session").expect("id"));
        let issuer = TurnRestCredentialIssuer::new(TurnRestSecret::from_bytes([7_u8; 32]));
        let first = issuer.issue(&session_id, 300, 1_000).expect("issue");
        let second = issuer.issue(&session_id, 300, 1_000).expect("issue");
        assert_eq!(first, second);
        assert_eq!(first.expires_at_unix_seconds, 1_300);
        assert_eq!(first.username, "1300:session");
        assert!(!first.credential.is_empty());
        assert!(!format!("{first:?}").contains(&first.credential));
        assert!(!format!("{issuer:?}").contains("07070707"));
        assert_eq!(
            issuer.issue(&session_id, MIN_TURN_CREDENTIAL_TTL_SECONDS - 1, 1_000),
            Err(TurnCredentialError::InvalidTtl)
        );
        assert_eq!(
            issuer.issue(&session_id, MAX_TURN_CREDENTIAL_TTL_SECONDS + 1, 1_000),
            Err(TurnCredentialError::InvalidTtl)
        );
    }

    #[test]
    fn prepared_provider_is_truthful_and_never_claims_live_transport() {
        let provider = PreparedWebRtcProvider;
        let capabilities = provider.current_capabilities();
        assert!(capabilities.iter().any(|capability| {
            capability.id == WEBRTC_BROWSER_CAPABILITY
                && capability.maturity == CapabilityMaturity::Prepared
        }));
        let config = WebRtcSessionConfig {
            session_id: SessionId::from_opaque(OpaqueId::new("session").expect("id")),
            ice_servers: vec![IceServerConfig {
                urls: vec!["stun:stun.example.test:3478".to_owned()],
                username: None,
                credential: None,
                credential_type: IceCredentialType::Password,
            }],
            ice_transport_policy: IceTransportPolicy::All,
        };
        assert_eq!(
            provider.create_session(&config),
            Err(WebRtcProviderError::TemporarilyUnavailable)
        );
    }
}
