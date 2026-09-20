use crate::SessionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceCredentialType {
    Password,
}

#[derive(Clone, PartialEq, Eq)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
    pub credential_type: IceCredentialType,
}

impl core::fmt::Debug for IceServerConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IceServerConfig")
            .field("urls", &self.urls)
            .field("has_username", &self.username.is_some())
            .field("has_credential", &self.credential.is_some())
            .field("credential_type", &self.credential_type)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceTransportPolicy {
    All,
    RelayOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcSdpType {
    Offer,
    Answer,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebRtcSessionDescription {
    pub session_id: SessionId,
    pub sdp_type: WebRtcSdpType,
    pub sdp: String,
}

impl core::fmt::Debug for WebRtcSessionDescription {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WebRtcSessionDescription")
            .field("session_id", &self.session_id)
            .field("sdp_type", &self.sdp_type)
            .field("sdp", &"<redacted>")
            .field("sdp_len", &self.sdp.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebRtcIceCandidate {
    pub session_id: SessionId,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
}

impl core::fmt::Debug for WebRtcIceCandidate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WebRtcIceCandidate")
            .field("session_id", &self.session_id)
            .field("candidate", &"<redacted>")
            .field("candidate_len", &self.candidate.len())
            .field("sdp_mid", &self.sdp_mid)
            .field("sdp_mline_index", &self.sdp_mline_index)
            .finish()
    }
}
