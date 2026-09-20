use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, IceServerConfig, WebRtcIceCandidate,
    WebRtcSessionDescription,
};

pub const WEBRTC_BROWSER_CAPABILITY: &str = "ucr.realtime.webrtc.browser";
pub const WEBRTC_ICE_CAPABILITY: &str = "ucr.realtime.webrtc.ice";
pub const WEBRTC_TURN_CAPABILITY: &str = "ucr.realtime.webrtc.turn";

pub const MAX_ICE_SERVERS: usize = 8;
pub const MAX_ICE_URLS_PER_SERVER: usize = 4;
pub const MAX_ICE_URL_LEN: usize = 512;
pub const MAX_ICE_USERNAME_LEN: usize = 256;
pub const MAX_ICE_CREDENTIAL_LEN: usize = 512;
pub const MAX_SDP_LEN: usize = 256 * 1024;
pub const MAX_ICE_CANDIDATE_LEN: usize = 4096;
pub const MAX_SDP_MID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcProtocolError {
    TooManyIceServers,
    TooManyIceUrls,
    InvalidIceUrl,
    InvalidIceCredential,
    InvalidSdp,
    InvalidCandidate,
}

#[must_use]
pub fn phase46_webrtc_capabilities() -> Vec<CapabilityDescriptor> {
    [
        WEBRTC_BROWSER_CAPABILITY,
        WEBRTC_ICE_CAPABILITY,
        WEBRTC_TURN_CAPABILITY,
    ]
    .into_iter()
    .map(|id| CapabilityDescriptor {
        id: id.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    })
    .collect()
}

/// Validates one deployment-supplied STUN/TURN server descriptor without persisting credentials.
///
/// # Errors
/// Rejects unsupported schemes, excessive sizes, credentials on STUN entries, or missing TURN
/// credentials.
pub fn canonical_ice_server(
    server: &IceServerConfig,
) -> Result<IceServerConfig, WebRtcProtocolError> {
    if server.urls.is_empty() || server.urls.len() > MAX_ICE_URLS_PER_SERVER {
        return Err(WebRtcProtocolError::TooManyIceUrls);
    }
    let mut has_turn = false;
    for url in &server.urls {
        if url.is_empty()
            || url.len() > MAX_ICE_URL_LEN
            || url.chars().any(char::is_whitespace)
        {
            return Err(WebRtcProtocolError::InvalidIceUrl);
        }
        if url.starts_with("turn:") || url.starts_with("turns:") {
            has_turn = true;
        } else if !url.starts_with("stun:") {
            return Err(WebRtcProtocolError::InvalidIceUrl);
        }
    }
    if server
        .username
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_ICE_USERNAME_LEN)
        || server
            .credential
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_ICE_CREDENTIAL_LEN)
    {
        return Err(WebRtcProtocolError::InvalidIceCredential);
    }
    if has_turn && (server.username.is_none() || server.credential.is_none()) {
        return Err(WebRtcProtocolError::InvalidIceCredential);
    }
    if !has_turn && (server.username.is_some() || server.credential.is_some()) {
        return Err(WebRtcProtocolError::InvalidIceCredential);
    }
    Ok(server.clone())
}

/// Validates a bounded SDP offer/answer owned by the transport provider.
///
/// # Errors
/// Rejects empty or excessively large SDP or embedded NUL bytes.
pub fn canonical_webrtc_description(
    description: &WebRtcSessionDescription,
) -> Result<WebRtcSessionDescription, WebRtcProtocolError> {
    if description.sdp.is_empty()
        || description.sdp.len() > MAX_SDP_LEN
        || description.sdp.as_bytes().contains(&0)
    {
        return Err(WebRtcProtocolError::InvalidSdp);
    }
    Ok(description.clone())
}

/// Validates one trickle-ICE candidate.
///
/// # Errors
/// Rejects empty/oversized candidates, embedded NUL bytes or oversized media IDs.
pub fn canonical_webrtc_candidate(
    candidate: &WebRtcIceCandidate,
) -> Result<WebRtcIceCandidate, WebRtcProtocolError> {
    if candidate.candidate.is_empty()
        || candidate.candidate.len() > MAX_ICE_CANDIDATE_LEN
        || candidate.candidate.as_bytes().contains(&0)
        || candidate
            .sdp_mid
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SDP_MID_LEN)
    {
        return Err(WebRtcProtocolError::InvalidCandidate);
    }
    Ok(candidate.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{IceCredentialType, OpaqueId, SessionId, WebRtcSdpType};

    fn sid() -> SessionId {
        SessionId::from_opaque(OpaqueId::new("webrtc-session").expect("id"))
    }

    #[test]
    fn turn_requires_credentials_and_stun_rejects_them() {
        let turn = IceServerConfig {
            urls: vec!["turns:turn.example.test:5349?transport=tcp".to_owned()],
            username: Some("ephemeral-user".to_owned()),
            credential: Some("ephemeral-secret".to_owned()),
            credential_type: IceCredentialType::Password,
        };
        assert_eq!(canonical_ice_server(&turn), Ok(turn.clone()));

        let missing = IceServerConfig {
            credential: None,
            ..turn
        };
        assert_eq!(
            canonical_ice_server(&missing),
            Err(WebRtcProtocolError::InvalidIceCredential)
        );

        let stun = IceServerConfig {
            urls: vec!["stun:stun.example.test:3478".to_owned()],
            username: Some("unexpected".to_owned()),
            credential: None,
            credential_type: IceCredentialType::Password,
        };
        assert_eq!(
            canonical_ice_server(&stun),
            Err(WebRtcProtocolError::InvalidIceCredential)
        );
    }

    #[test]
    fn description_and_candidate_are_bounded() {
        let description = WebRtcSessionDescription {
            session_id: sid(),
            sdp_type: WebRtcSdpType::Offer,
            sdp: "v=0\r\n".to_owned(),
        };
        assert_eq!(
            canonical_webrtc_description(&description),
            Ok(description.clone())
        );
        let candidate = WebRtcIceCandidate {
            session_id: sid(),
            candidate: "candidate:1 1 UDP 1 203.0.113.10 50000 typ host".to_owned(),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
        };
        assert_eq!(
            canonical_webrtc_candidate(&candidate),
            Ok(candidate)
        );
    }
}
