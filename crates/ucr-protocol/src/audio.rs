use ucr_model::{
    AudioCodecConfig, AudioFrameDuration, AudioStreamDescriptor, CapabilityDescriptor,
    CapabilityMaturity, EncodedAudioFrame,
};

use crate::validate_namespaced_identifier;

pub const AUDIO_MEDIA_CAPABILITY: &str = "ucr.media.audio";
pub const OPUS_AUDIO_CODEC_CAPABILITY: &str = "ucr.media.audio.opus";
pub const MANDATORY_AUDIO_SAMPLE_RATE_HZ: u32 = 48_000;
pub const MAX_ENCODED_AUDIO_FRAME_BYTES: usize = 1_275;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioProtocolError {
    InvalidCapability,
    UnsupportedCodec,
    UnsupportedSampleRate,
    EmptyPayload,
    PayloadTooLarge,
    FrameBindingMismatch,
}

/// Returns the Phase-20 capability advertisements. Both are Prepared, never Production claims.
#[must_use]
pub fn phase20_audio_capabilities() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            id: AUDIO_MEDIA_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: OPUS_AUDIO_CODEC_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
    ]
}

/// Canonicalizes one Phase-20 audio codec profile.
///
/// Phase 20 makes Opus the mandatory interoperable codec while keeping the model capability-ID
/// based so later codecs do not require a parallel media model.
///
/// # Errors
/// Rejects malformed/unsupported codec IDs or sample rates unsupported by Opus.
pub fn canonical_audio_codec_config(
    config: &AudioCodecConfig,
) -> Result<AudioCodecConfig, AudioProtocolError> {
    validate_namespaced_identifier(&config.codec_capability_id)
        .map_err(|_| AudioProtocolError::InvalidCapability)?;
    if config.codec_capability_id != OPUS_AUDIO_CODEC_CAPABILITY {
        return Err(AudioProtocolError::UnsupportedCodec);
    }
    if !matches!(
        config.sample_rate_hz,
        8_000 | 12_000 | 16_000 | 24_000 | 48_000
    ) {
        return Err(AudioProtocolError::UnsupportedSampleRate);
    }
    Ok(config.clone())
}

/// Validates one ephemeral audio stream descriptor without inventing durable Call/media state.
///
/// # Errors
/// Returns codec-profile validation failures.
pub fn canonical_audio_stream_descriptor(
    descriptor: &AudioStreamDescriptor,
) -> Result<AudioStreamDescriptor, AudioProtocolError> {
    let mut canonical = descriptor.clone();
    canonical.codec = canonical_audio_codec_config(&descriptor.codec)?;
    Ok(canonical)
}

/// Returns the exact PCM sample count per channel for one configured Opus frame.
///
/// # Errors
/// Returns codec-profile validation failures.
pub fn audio_samples_per_channel(config: &AudioCodecConfig) -> Result<usize, AudioProtocolError> {
    let canonical = canonical_audio_codec_config(config)?;
    let rate = canonical.sample_rate_hz as usize;
    Ok(match canonical.frame_duration {
        AudioFrameDuration::Ms2_5 => rate / 400,
        AudioFrameDuration::Ms5 => rate / 200,
        AudioFrameDuration::Ms10 => rate / 100,
        AudioFrameDuration::Ms20 => rate / 50,
        AudioFrameDuration::Ms40 => rate / 25,
        AudioFrameDuration::Ms60 => (rate * 3) / 50,
    })
}

/// Validates an encoded frame against the exact stream identity and negotiation generation.
///
/// # Errors
/// Rejects empty/oversized payloads or any cross-stream/cross-call/source/generation mismatch.
pub fn validate_audio_frame_for_stream(
    stream: &AudioStreamDescriptor,
    frame: &EncodedAudioFrame,
) -> Result<(), AudioProtocolError> {
    canonical_audio_stream_descriptor(stream)?;
    if frame.payload.is_empty() {
        return Err(AudioProtocolError::EmptyPayload);
    }
    if frame.payload.len() > MAX_ENCODED_AUDIO_FRAME_BYTES {
        return Err(AudioProtocolError::PayloadTooLarge);
    }
    if frame.scope != stream.scope
        || frame.call_id != stream.call_id
        || frame.stream_id != stream.stream_id
        || frame.source != stream.source
        || frame.negotiation_generation != stream.negotiation_generation
    {
        return Err(AudioProtocolError::FrameBindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{AudioChannelLayout, AudioCodecConfig, AudioFrameDuration, CapabilityMaturity};

    use super::{
        AudioProtocolError, MANDATORY_AUDIO_SAMPLE_RATE_HZ, OPUS_AUDIO_CODEC_CAPABILITY,
        audio_samples_per_channel, canonical_audio_codec_config, phase20_audio_capabilities,
    };

    fn opus_config() -> AudioCodecConfig {
        AudioCodecConfig {
            codec_capability_id: OPUS_AUDIO_CODEC_CAPABILITY.to_owned(),
            sample_rate_hz: MANDATORY_AUDIO_SAMPLE_RATE_HZ,
            channel_layout: AudioChannelLayout::Mono,
            frame_duration: AudioFrameDuration::Ms20,
        }
    }

    #[test]
    fn opus_is_mandatory_prepared_profile_with_exact_20ms_sample_count() {
        let config = canonical_audio_codec_config(&opus_config()).expect("opus");
        assert_eq!(audio_samples_per_channel(&config), Ok(960));
        let capabilities = phase20_audio_capabilities();
        assert!(
            capabilities
                .iter()
                .all(|value| value.maturity == CapabilityMaturity::Prepared)
        );
        assert!(
            capabilities
                .iter()
                .any(|value| value.id == OPUS_AUDIO_CODEC_CAPABILITY)
        );
    }

    #[test]
    fn unsupported_codec_or_sample_rate_fails_closed() {
        let mut config = opus_config();
        config.codec_capability_id = "ucr.media.audio.other".to_owned();
        assert_eq!(
            canonical_audio_codec_config(&config),
            Err(AudioProtocolError::UnsupportedCodec)
        );
        config = opus_config();
        config.sample_rate_hz = 44_100;
        assert_eq!(
            canonical_audio_codec_config(&config),
            Err(AudioProtocolError::UnsupportedSampleRate)
        );
    }
}
