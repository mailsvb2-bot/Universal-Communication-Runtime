#![forbid(unsafe_code)]

use core::fmt;

use ucr_model::{
    IceServerConfig, IceTransportPolicy, SessionId, WebRtcIceCandidate, WebRtcSessionDescription,
};
use ucr_protocol::{
    CapabilityDescriptor, WebRtcProtocolError, canonical_ice_server, canonical_webrtc_candidate,
    canonical_webrtc_description, phase46_webrtc_capabilities,
};

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
