use core::fmt;

use crate::{CallId, OpaqueId, PrincipalRef, TenantScope, VideoStreamId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoSourceKind {
    Camera,
    ScreenShare,
}

/// Negotiated codec parameters for one Phase-21 video stream.
///
/// `codec_capability_id` remains capability based so future codecs do not require a parallel media
/// model. Width/height/frame-rate/bitrate are fixed negotiated parameters here; adaptive policy is
/// owned by Phase 23, not by this config type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoCodecConfig {
    pub codec_capability_id: String,
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub target_bitrate_bps: u32,
}

/// Ephemeral video stream identity bound to one canonical `CallSession` and source principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoStreamDescriptor {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub stream_id: VideoStreamId,
    pub source: PrincipalRef,
    pub source_kind: VideoSourceKind,
    pub codec: VideoCodecConfig,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
}

/// One encoded realtime video frame. Payload is codec data, not ciphertext or durable Message data.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedVideoFrame {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub stream_id: VideoStreamId,
    pub source: PrincipalRef,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub sequence: u64,
    pub media_timestamp_us: u64,
    pub keyframe: bool,
    pub payload: Vec<u8>,
}

impl fmt::Debug for EncodedVideoFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedVideoFrame")
            .field("scope", &self.scope)
            .field("call_id", &self.call_id)
            .field("stream_id", &self.stream_id)
            .field("source", &self.source)
            .field("negotiation_ref", &self.negotiation_ref)
            .field("negotiation_generation", &self.negotiation_generation)
            .field("sequence", &self.sequence)
            .field("media_timestamp_us", &self.media_timestamp_us)
            .field("keyframe", &self.keyframe)
            .field("payload", &"<encoded-video>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
