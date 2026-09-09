use core::fmt;

use crate::{AudioStreamId, CallId, OpaqueId, PrincipalRef, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioChannelLayout {
    Mono,
    Stereo,
}

impl AudioChannelLayout {
    #[must_use]
    pub const fn channels(self) -> usize {
        match self {
            Self::Mono => 1,
            Self::Stereo => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFrameDuration {
    Ms2_5,
    Ms5,
    Ms10,
    Ms20,
    Ms40,
    Ms60,
}

/// Negotiated codec parameters for one Phase-20 audio stream.
///
/// `codec_capability_id` is a canonical capability identifier rather than an enum so later codecs
/// can be added through capability negotiation without changing the fundamental model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioCodecConfig {
    pub codec_capability_id: String,
    pub sample_rate_hz: u32,
    pub channel_layout: AudioChannelLayout,
    pub frame_duration: AudioFrameDuration,
}

/// Ephemeral media stream identity bound to one canonical `CallSession` and exact source principal.
///
/// The descriptor is not a second Call, Group, Identity, transport route, or durable media store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioStreamDescriptor {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub stream_id: AudioStreamId,
    pub source: PrincipalRef,
    pub codec: AudioCodecConfig,
    /// Exact canonical media-negotiation result referenced by the owning `CallSession`.
    pub negotiation_ref: OpaqueId,
    /// Must equal the canonical `CallSession` media-negotiation generation when the stream is used.
    pub negotiation_generation: u64,
}

/// One encoded realtime audio frame. Payload is codec data, not ciphertext or durable message data.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedAudioFrame {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub stream_id: AudioStreamId,
    pub source: PrincipalRef,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub sequence: u64,
    pub media_timestamp_samples: u64,
    pub payload: Vec<u8>,
}

impl fmt::Debug for EncodedAudioFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedAudioFrame")
            .field("scope", &self.scope)
            .field("call_id", &self.call_id)
            .field("stream_id", &self.stream_id)
            .field("source", &self.source)
            .field("negotiation_ref", &self.negotiation_ref)
            .field("negotiation_generation", &self.negotiation_generation)
            .field("sequence", &self.sequence)
            .field("media_timestamp_samples", &self.media_timestamp_samples)
            .field("payload", &"<encoded-audio>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
