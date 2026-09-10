use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, EncodedVideoFrame, VideoCodecConfig, VideoSourceKind,
    VideoStreamDescriptor,
};

use crate::validate_namespaced_identifier;

pub const VIDEO_MEDIA_CAPABILITY: &str = "ucr.media.video";
pub const H264_VIDEO_CODEC_CAPABILITY: &str = "ucr.media.video.h264";
pub const SCREEN_SHARE_VIDEO_CAPABILITY: &str = "ucr.media.video.screen_share";
pub const MANDATORY_VIDEO_WIDTH: u32 = 320;
pub const MANDATORY_VIDEO_HEIGHT: u32 = 240;
pub const MANDATORY_VIDEO_FRAME_RATE: u32 = 20;
pub const MAX_VIDEO_WIDTH: u32 = 1_920;
pub const MAX_VIDEO_HEIGHT: u32 = 1_080;
pub const MAX_VIDEO_FRAME_RATE: u32 = 60;
pub const H264_LEVEL_4_0_MAX_FRAME_MACROBLOCKS: u32 = 8_192;
pub const H264_LEVEL_4_0_MAX_MACROBLOCKS_PER_SECOND: u32 = 245_760;
pub const H264_LEVEL_4_0_MAX_DPB_MACROBLOCKS: u32 = 32_768;
pub const H264_MAX_REFERENCE_FRAMES: u32 = 16;
pub const MIN_VIDEO_BITRATE_BPS: u32 = 64_000;
pub const MAX_VIDEO_BITRATE_BPS: u32 = 20_000_000;
pub const MAX_ENCODED_VIDEO_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoProtocolError {
    InvalidCapability,
    UnsupportedCodec,
    InvalidDimensions,
    UnsupportedFrameRate,
    UnsupportedBitrate,
    EmptyPayload,
    PayloadTooLarge,
    FrameBindingMismatch,
}

#[must_use]
pub fn phase21_video_capabilities() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            id: VIDEO_MEDIA_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: SCREEN_SHARE_VIDEO_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
    ]
}

/// Canonicalizes the bounded Phase-21 H.264 reference profile.
///
/// # Errors
/// Rejects malformed/unsupported codec identifiers and any unbounded or unsupported profile.
pub fn canonical_video_codec_config(
    config: &VideoCodecConfig,
) -> Result<VideoCodecConfig, VideoProtocolError> {
    validate_namespaced_identifier(&config.codec_capability_id)
        .map_err(|_| VideoProtocolError::InvalidCapability)?;
    if config.codec_capability_id != H264_VIDEO_CODEC_CAPABILITY {
        return Err(VideoProtocolError::UnsupportedCodec);
    }
    if config.width < 16
        || config.height < 16
        || config.width > MAX_VIDEO_WIDTH
        || config.height > MAX_VIDEO_HEIGHT
        || !config.width.is_multiple_of(2)
        || !config.height.is_multiple_of(2)
    {
        return Err(VideoProtocolError::InvalidDimensions);
    }
    if config.frame_rate == 0 || config.frame_rate > MAX_VIDEO_FRAME_RATE {
        return Err(VideoProtocolError::UnsupportedFrameRate);
    }
    let (_, _, frame_macroblocks) = h264_level_4_0_coded_shape(config.width, config.height)?;
    let macroblocks_per_second = frame_macroblocks
        .checked_mul(config.frame_rate)
        .ok_or(VideoProtocolError::UnsupportedFrameRate)?;
    if macroblocks_per_second > H264_LEVEL_4_0_MAX_MACROBLOCKS_PER_SECOND {
        return Err(VideoProtocolError::UnsupportedFrameRate);
    }
    if !(MIN_VIDEO_BITRATE_BPS..=MAX_VIDEO_BITRATE_BPS).contains(&config.target_bitrate_bps) {
        return Err(VideoProtocolError::UnsupportedBitrate);
    }
    Ok(config.clone())
}

/// Returns the exact uncropped coded canvas expected by the fixed H.264 Level 4.0 profile.
///
/// # Errors
/// Returns profile validation failures.
pub fn h264_reference_coded_dimensions(
    config: &VideoCodecConfig,
) -> Result<(u32, u32), VideoProtocolError> {
    let canonical = canonical_video_codec_config(config)?;
    let (width, height, _) = h264_level_4_0_coded_shape(canonical.width, canonical.height)?;
    Ok((width, height))
}

/// Returns the maximum decoded-picture-buffer frame count allowed by H.264 Level 4.0
/// for the canonical coded picture size.
///
/// # Errors
/// Returns profile validation failures.
pub fn h264_reference_max_dpb_frames(config: &VideoCodecConfig) -> Result<u32, VideoProtocolError> {
    let canonical = canonical_video_codec_config(config)?;
    let (_, _, frame_macroblocks) = h264_level_4_0_coded_shape(canonical.width, canonical.height)?;
    let by_dpb = H264_LEVEL_4_0_MAX_DPB_MACROBLOCKS
        .checked_div(frame_macroblocks)
        .ok_or(VideoProtocolError::InvalidDimensions)?;
    Ok(by_dpb.min(H264_MAX_REFERENCE_FRAMES))
}

fn h264_level_4_0_coded_shape(
    width: u32,
    height: u32,
) -> Result<(u32, u32, u32), VideoProtocolError> {
    let width_macroblocks = width.div_ceil(16);
    let height_macroblocks = height.div_ceil(16);
    let frame_macroblocks = width_macroblocks
        .checked_mul(height_macroblocks)
        .ok_or(VideoProtocolError::InvalidDimensions)?;
    if frame_macroblocks > H264_LEVEL_4_0_MAX_FRAME_MACROBLOCKS {
        return Err(VideoProtocolError::InvalidDimensions);
    }
    let coded_width = width_macroblocks
        .checked_mul(16)
        .ok_or(VideoProtocolError::InvalidDimensions)?;
    let coded_height = height_macroblocks
        .checked_mul(16)
        .ok_or(VideoProtocolError::InvalidDimensions)?;
    Ok((coded_width, coded_height, frame_macroblocks))
}

/// # Errors
/// Returns codec-profile validation failures.
pub fn canonical_video_stream_descriptor(
    descriptor: &VideoStreamDescriptor,
) -> Result<VideoStreamDescriptor, VideoProtocolError> {
    let mut canonical = descriptor.clone();
    canonical.codec = canonical_video_codec_config(&descriptor.codec)?;
    Ok(canonical)
}

/// Exact contiguous RGB8 byte count expected by the reference encoder.
///
/// # Errors
/// Returns profile validation failures or size overflow.
pub fn video_rgb8_len(config: &VideoCodecConfig) -> Result<usize, VideoProtocolError> {
    let canonical = canonical_video_codec_config(config)?;
    let pixels = usize::try_from(canonical.width)
        .ok()
        .and_then(|width| {
            usize::try_from(canonical.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .ok_or(VideoProtocolError::InvalidDimensions)?;
    pixels
        .checked_mul(3)
        .ok_or(VideoProtocolError::InvalidDimensions)
}

/// # Errors
/// Rejects empty/oversized encoded payloads or cross-stream/call/source/negotiation mismatches.
pub fn validate_video_frame_for_stream(
    stream: &VideoStreamDescriptor,
    frame: &EncodedVideoFrame,
) -> Result<(), VideoProtocolError> {
    canonical_video_stream_descriptor(stream)?;
    if frame.payload.is_empty() {
        return Err(VideoProtocolError::EmptyPayload);
    }
    if frame.payload.len() > MAX_ENCODED_VIDEO_FRAME_BYTES {
        return Err(VideoProtocolError::PayloadTooLarge);
    }
    if frame.scope != stream.scope
        || frame.call_id != stream.call_id
        || frame.stream_id != stream.stream_id
        || frame.source != stream.source
        || frame.negotiation_ref != stream.negotiation_ref
        || frame.negotiation_generation != stream.negotiation_generation
    {
        return Err(VideoProtocolError::FrameBindingMismatch);
    }
    Ok(())
}

#[must_use]
pub const fn required_video_capability_for_source(source: VideoSourceKind) -> Option<&'static str> {
    match source {
        VideoSourceKind::Camera => None,
        VideoSourceKind::ScreenShare => Some(SCREEN_SHARE_VIDEO_CAPABILITY),
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{CapabilityMaturity, VideoCodecConfig};

    use super::{
        H264_VIDEO_CODEC_CAPABILITY, MANDATORY_VIDEO_FRAME_RATE, MANDATORY_VIDEO_HEIGHT,
        MANDATORY_VIDEO_WIDTH, VideoProtocolError, canonical_video_codec_config,
        h264_reference_coded_dimensions, h264_reference_max_dpb_frames, phase21_video_capabilities,
        video_rgb8_len,
    };

    fn h264() -> VideoCodecConfig {
        VideoCodecConfig {
            codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
            width: MANDATORY_VIDEO_WIDTH,
            height: MANDATORY_VIDEO_HEIGHT,
            frame_rate: MANDATORY_VIDEO_FRAME_RATE,
            target_bitrate_bps: 384_000,
        }
    }

    #[test]
    fn h264_prepared_profile_has_bounded_reference_shape() {
        let config = canonical_video_codec_config(&h264()).expect("h264");
        assert_eq!(video_rgb8_len(&config), Ok(320 * 240 * 3));
        assert_eq!(h264_reference_coded_dimensions(&config), Ok((320, 240)));
        assert_eq!(h264_reference_max_dpb_frames(&config), Ok(16));
        let capabilities = phase21_video_capabilities();
        assert!(
            capabilities
                .iter()
                .all(|value| value.maturity == CapabilityMaturity::Prepared)
        );
        assert!(
            capabilities
                .iter()
                .any(|value| value.id == H264_VIDEO_CODEC_CAPABILITY)
        );
    }

    #[test]
    fn invalid_codec_dimensions_rate_or_bitrate_fail_closed() {
        let mut config = h264();
        config.codec_capability_id = "ucr.media.video.other".to_owned();
        assert_eq!(
            canonical_video_codec_config(&config),
            Err(VideoProtocolError::UnsupportedCodec)
        );
        config = h264();
        config.width = 321;
        assert_eq!(
            canonical_video_codec_config(&config),
            Err(VideoProtocolError::InvalidDimensions)
        );
        config = h264();
        config.frame_rate = 61;
        assert_eq!(
            canonical_video_codec_config(&config),
            Err(VideoProtocolError::UnsupportedFrameRate)
        );
        config = h264();
        config.width = 1_920;
        config.height = 1_080;
        config.frame_rate = 60;
        assert_eq!(
            canonical_video_codec_config(&config),
            Err(VideoProtocolError::UnsupportedFrameRate)
        );
        config.frame_rate = 30;
        assert!(canonical_video_codec_config(&config).is_ok());
        assert_eq!(h264_reference_coded_dimensions(&config), Ok((1_920, 1_088)));
        assert_eq!(h264_reference_max_dpb_frames(&config), Ok(4));
        config = h264();
        config.target_bitrate_bps = 1;
        assert_eq!(
            canonical_video_codec_config(&config),
            Err(VideoProtocolError::UnsupportedBitrate)
        );
    }
}
