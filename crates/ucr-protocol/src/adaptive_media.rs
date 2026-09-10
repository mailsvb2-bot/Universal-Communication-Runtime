use ucr_model::{
    AdaptiveMediaPressure, AdaptiveMediaStage, AdaptiveMediaTelemetry, CapabilityDescriptor,
    CapabilityMaturity, DeferredMediaFallback, MediaThermalState, VideoCodecConfig,
};

use crate::{H264_VIDEO_CODEC_CAPABILITY, canonical_video_codec_config};

pub const ADAPTIVE_MEDIA_CAPABILITY: &str = "ucr.media.adaptive";
pub const MAX_ADAPTIVE_BANDWIDTH_BPS: u64 = 10_000_000_000;
pub const MAX_ADAPTIVE_LATENCY_MS: u32 = 120_000;
pub const OPUS_NORMAL_TARGET_BITRATE_BPS: u32 = 48_000;
pub const OPUS_LOW_TARGET_BITRATE_BPS: u32 = 16_000;
pub const ADAPTIVE_DEGRADE_CONFIRM_SAMPLES: u8 = 2;
pub const ADAPTIVE_RECOVERY_CONFIRM_SAMPLES: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMediaProtocolError {
    BandwidthOutOfRange,
    PacketLossOutOfRange,
    LatencyOutOfRange,
    CpuOutOfRange,
    GpuOutOfRange,
    BatteryOutOfRange,
    VideoProfileInvalid,
}

#[must_use]
pub fn phase23_adaptive_media_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: ADAPTIVE_MEDIA_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Canonicalizes one bounded telemetry observation used only for media adaptation.
///
/// # Errors
/// Rejects impossible percentages/loss values and intentionally bounded network measurements.
pub fn canonical_adaptive_media_telemetry(
    telemetry: &AdaptiveMediaTelemetry,
) -> Result<AdaptiveMediaTelemetry, AdaptiveMediaProtocolError> {
    if telemetry.estimated_bandwidth_bps > MAX_ADAPTIVE_BANDWIDTH_BPS {
        return Err(AdaptiveMediaProtocolError::BandwidthOutOfRange);
    }
    if telemetry.packet_loss_basis_points > 10_000 {
        return Err(AdaptiveMediaProtocolError::PacketLossOutOfRange);
    }
    if telemetry.jitter_ms > MAX_ADAPTIVE_LATENCY_MS || telemetry.rtt_ms > MAX_ADAPTIVE_LATENCY_MS {
        return Err(AdaptiveMediaProtocolError::LatencyOutOfRange);
    }
    if telemetry.cpu_utilization_percent > 100 {
        return Err(AdaptiveMediaProtocolError::CpuOutOfRange);
    }
    if telemetry
        .gpu_utilization_percent
        .is_some_and(|value| value > 100)
    {
        return Err(AdaptiveMediaProtocolError::GpuOutOfRange);
    }
    if telemetry.battery_percent > 100 {
        return Err(AdaptiveMediaProtocolError::BatteryOutOfRange);
    }
    Ok(telemetry.clone())
}

/// Produces the reference quality ceiling from all Canon-required media signals.
///
/// Thresholds are a Prepared reference policy, not a universal production tuning claim.
///
/// # Errors
/// Returns bounded telemetry validation failures.
pub fn reference_stage_for_telemetry(
    telemetry: &AdaptiveMediaTelemetry,
) -> Result<AdaptiveMediaStage, AdaptiveMediaProtocolError> {
    let telemetry = canonical_adaptive_media_telemetry(telemetry)?;
    let mut stage = bandwidth_stage(telemetry.estimated_bandwidth_bps);
    stage = worse(stage, loss_stage(telemetry.packet_loss_basis_points));
    stage = worse(stage, jitter_stage(telemetry.jitter_ms));
    stage = worse(stage, rtt_stage(telemetry.rtt_ms));
    stage = worse(stage, cpu_stage(telemetry.cpu_utilization_percent));
    if let Some(gpu) = telemetry.gpu_utilization_percent {
        stage = worse(stage, gpu_stage(gpu));
    }
    stage = worse(
        stage,
        battery_stage(telemetry.battery_percent, telemetry.external_power),
    );
    stage = worse(stage, thermal_stage(telemetry.thermal_state));
    Ok(stage)
}

/// Returns a bounded, stable-order explanation of the signals currently limiting 1080p operation.
///
/// # Errors
/// Returns bounded telemetry validation failures.
pub fn adaptive_media_pressures(
    telemetry: &AdaptiveMediaTelemetry,
) -> Result<Vec<AdaptiveMediaPressure>, AdaptiveMediaProtocolError> {
    let telemetry = canonical_adaptive_media_telemetry(telemetry)?;
    let mut pressures = Vec::with_capacity(8);
    if bandwidth_stage(telemetry.estimated_bandwidth_bps) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::Bandwidth);
    }
    if loss_stage(telemetry.packet_loss_basis_points) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::PacketLoss);
    }
    if jitter_stage(telemetry.jitter_ms) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::Jitter);
    }
    if rtt_stage(telemetry.rtt_ms) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::Rtt);
    }
    if cpu_stage(telemetry.cpu_utilization_percent) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::Cpu);
    }
    if telemetry
        .gpu_utilization_percent
        .is_some_and(|gpu| gpu_stage(gpu) > AdaptiveMediaStage::Video1080p)
    {
        pressures.push(AdaptiveMediaPressure::Gpu);
    }
    if battery_stage(telemetry.battery_percent, telemetry.external_power)
        > AdaptiveMediaStage::Video1080p
    {
        pressures.push(AdaptiveMediaPressure::Battery);
    }
    if thermal_stage(telemetry.thermal_state) > AdaptiveMediaStage::Video1080p {
        pressures.push(AdaptiveMediaPressure::Thermal);
    }
    Ok(pressures)
}

/// Canonical reference H.264 operating point for one video stage.
///
/// # Errors
/// Returns an error if a reference point ever drifts outside the Phase-21 H.264 contract.
pub fn reference_video_config(
    stage: AdaptiveMediaStage,
) -> Result<Option<VideoCodecConfig>, AdaptiveMediaProtocolError> {
    let config = match stage {
        AdaptiveMediaStage::Video1080p => Some(video_config(1_920, 1_080, 30, 4_000_000)),
        AdaptiveMediaStage::Video720p => Some(video_config(1_280, 720, 30, 2_000_000)),
        AdaptiveMediaStage::Video480p => Some(video_config(854, 480, 30, 1_000_000)),
        AdaptiveMediaStage::VideoLowFps => Some(video_config(640, 360, 12, 384_000)),
        AdaptiveMediaStage::Audio
        | AdaptiveMediaStage::AudioLowBitrate
        | AdaptiveMediaStage::EventualFallbackRequired => None,
    };
    config
        .map(|value| {
            canonical_video_codec_config(&value)
                .map_err(|_| AdaptiveMediaProtocolError::VideoProfileInvalid)
        })
        .transpose()
}

#[must_use]
pub const fn reference_opus_target_bitrate(stage: AdaptiveMediaStage) -> Option<u32> {
    match stage {
        AdaptiveMediaStage::Audio => Some(OPUS_NORMAL_TARGET_BITRATE_BPS),
        AdaptiveMediaStage::AudioLowBitrate => Some(OPUS_LOW_TARGET_BITRATE_BPS),
        AdaptiveMediaStage::Video1080p
        | AdaptiveMediaStage::Video720p
        | AdaptiveMediaStage::Video480p
        | AdaptiveMediaStage::VideoLowFps
        | AdaptiveMediaStage::EventualFallbackRequired => None,
    }
}

#[must_use]
pub fn reference_deferred_fallbacks(stage: AdaptiveMediaStage) -> Vec<DeferredMediaFallback> {
    if stage == AdaptiveMediaStage::EventualFallbackRequired {
        vec![
            DeferredMediaFallback::VoiceMessage,
            DeferredMediaFallback::Text,
            DeferredMediaFallback::StoreAndForward,
        ]
    } else {
        Vec::new()
    }
}

#[must_use]
pub fn stage_requires_media_renegotiation(
    previous: AdaptiveMediaStage,
    next: AdaptiveMediaStage,
) -> bool {
    previous != next && (is_video_stage(previous) || is_video_stage(next))
}

#[must_use]
pub const fn is_video_stage(stage: AdaptiveMediaStage) -> bool {
    matches!(
        stage,
        AdaptiveMediaStage::Video1080p
            | AdaptiveMediaStage::Video720p
            | AdaptiveMediaStage::Video480p
            | AdaptiveMediaStage::VideoLowFps
    )
}

#[must_use]
pub const fn one_step_better(stage: AdaptiveMediaStage) -> AdaptiveMediaStage {
    match stage {
        AdaptiveMediaStage::Video1080p | AdaptiveMediaStage::Video720p => {
            AdaptiveMediaStage::Video1080p
        }
        AdaptiveMediaStage::Video480p => AdaptiveMediaStage::Video720p,
        AdaptiveMediaStage::VideoLowFps => AdaptiveMediaStage::Video480p,
        AdaptiveMediaStage::Audio => AdaptiveMediaStage::VideoLowFps,
        AdaptiveMediaStage::AudioLowBitrate => AdaptiveMediaStage::Audio,
        AdaptiveMediaStage::EventualFallbackRequired => AdaptiveMediaStage::AudioLowBitrate,
    }
}

const fn worse(left: AdaptiveMediaStage, right: AdaptiveMediaStage) -> AdaptiveMediaStage {
    if (left as u8) >= (right as u8) {
        left
    } else {
        right
    }
}

fn video_config(width: u32, height: u32, frame_rate: u32, bitrate: u32) -> VideoCodecConfig {
    VideoCodecConfig {
        codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
        width,
        height,
        frame_rate,
        target_bitrate_bps: bitrate,
    }
}

fn bandwidth_stage(value: u64) -> AdaptiveMediaStage {
    match value {
        5_000_000.. => AdaptiveMediaStage::Video1080p,
        2_500_000.. => AdaptiveMediaStage::Video720p,
        1_250_000.. => AdaptiveMediaStage::Video480p,
        500_000.. => AdaptiveMediaStage::VideoLowFps,
        80_000.. => AdaptiveMediaStage::Audio,
        24_000.. => AdaptiveMediaStage::AudioLowBitrate,
        _ => AdaptiveMediaStage::EventualFallbackRequired,
    }
}

fn loss_stage(value: u16) -> AdaptiveMediaStage {
    match value {
        0..=100 => AdaptiveMediaStage::Video1080p,
        101..=200 => AdaptiveMediaStage::Video720p,
        201..=400 => AdaptiveMediaStage::Video480p,
        401..=800 => AdaptiveMediaStage::VideoLowFps,
        801..=1_500 => AdaptiveMediaStage::Audio,
        1_501..=2_500 => AdaptiveMediaStage::AudioLowBitrate,
        _ => AdaptiveMediaStage::EventualFallbackRequired,
    }
}

fn jitter_stage(value: u32) -> AdaptiveMediaStage {
    match value {
        0..=30 => AdaptiveMediaStage::Video1080p,
        31..=45 => AdaptiveMediaStage::Video720p,
        46..=75 => AdaptiveMediaStage::Video480p,
        76..=120 => AdaptiveMediaStage::VideoLowFps,
        121..=200 => AdaptiveMediaStage::Audio,
        201..=350 => AdaptiveMediaStage::AudioLowBitrate,
        _ => AdaptiveMediaStage::EventualFallbackRequired,
    }
}

fn rtt_stage(value: u32) -> AdaptiveMediaStage {
    match value {
        0..=180 => AdaptiveMediaStage::Video1080p,
        181..=250 => AdaptiveMediaStage::Video720p,
        251..=400 => AdaptiveMediaStage::Video480p,
        401..=650 => AdaptiveMediaStage::VideoLowFps,
        651..=1_000 => AdaptiveMediaStage::Audio,
        1_001..=1_800 => AdaptiveMediaStage::AudioLowBitrate,
        _ => AdaptiveMediaStage::EventualFallbackRequired,
    }
}

fn cpu_stage(value: u8) -> AdaptiveMediaStage {
    match value {
        0..=70 => AdaptiveMediaStage::Video1080p,
        71..=80 => AdaptiveMediaStage::Video720p,
        81..=88 => AdaptiveMediaStage::Video480p,
        89..=94 => AdaptiveMediaStage::VideoLowFps,
        95..=98 => AdaptiveMediaStage::Audio,
        _ => AdaptiveMediaStage::AudioLowBitrate,
    }
}

fn gpu_stage(value: u8) -> AdaptiveMediaStage {
    match value {
        0..=80 => AdaptiveMediaStage::Video1080p,
        81..=90 => AdaptiveMediaStage::Video720p,
        91..=95 => AdaptiveMediaStage::Video480p,
        96..=98 => AdaptiveMediaStage::VideoLowFps,
        _ => AdaptiveMediaStage::Audio,
    }
}

fn battery_stage(value: u8, external_power: bool) -> AdaptiveMediaStage {
    if external_power {
        return AdaptiveMediaStage::Video1080p;
    }
    match value {
        30..=100 => AdaptiveMediaStage::Video1080p,
        20..=29 => AdaptiveMediaStage::Video720p,
        12..=19 => AdaptiveMediaStage::Video480p,
        8..=11 => AdaptiveMediaStage::VideoLowFps,
        4..=7 => AdaptiveMediaStage::Audio,
        _ => AdaptiveMediaStage::AudioLowBitrate,
    }
}

const fn thermal_stage(value: MediaThermalState) -> AdaptiveMediaStage {
    match value {
        MediaThermalState::Nominal => AdaptiveMediaStage::Video1080p,
        MediaThermalState::Elevated => AdaptiveMediaStage::Video720p,
        MediaThermalState::Serious => AdaptiveMediaStage::Audio,
        MediaThermalState::Critical => AdaptiveMediaStage::AudioLowBitrate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ideal() -> AdaptiveMediaTelemetry {
        AdaptiveMediaTelemetry {
            estimated_bandwidth_bps: 8_000_000,
            packet_loss_basis_points: 20,
            jitter_ms: 10,
            rtt_ms: 40,
            cpu_utilization_percent: 30,
            gpu_utilization_percent: Some(25),
            battery_percent: 90,
            external_power: false,
            thermal_state: MediaThermalState::Nominal,
        }
    }

    #[test]
    fn all_canon_signals_can_independently_limit_quality() {
        assert_eq!(
            reference_stage_for_telemetry(&ideal()),
            Ok(AdaptiveMediaStage::Video1080p)
        );
        let mut cases = Vec::new();
        let mut t = ideal();
        t.estimated_bandwidth_bps = 1_300_000;
        cases.push(t);
        let mut t = ideal();
        t.packet_loss_basis_points = 350;
        cases.push(t);
        let mut t = ideal();
        t.jitter_ms = 70;
        cases.push(t);
        let mut t = ideal();
        t.rtt_ms = 350;
        cases.push(t);
        let mut t = ideal();
        t.cpu_utilization_percent = 86;
        cases.push(t);
        let mut t = ideal();
        t.gpu_utilization_percent = Some(94);
        cases.push(t);
        let mut t = ideal();
        t.battery_percent = 15;
        cases.push(t);
        let mut t = ideal();
        t.thermal_state = MediaThermalState::Serious;
        cases.push(t);
        assert!(cases.iter().all(|value| {
            reference_stage_for_telemetry(value)
                .is_ok_and(|stage| stage > AdaptiveMediaStage::Video1080p)
        }));
    }

    #[test]
    fn reference_profiles_remain_inside_existing_media_contracts() {
        for stage in [
            AdaptiveMediaStage::Video1080p,
            AdaptiveMediaStage::Video720p,
            AdaptiveMediaStage::Video480p,
            AdaptiveMediaStage::VideoLowFps,
        ] {
            let config = reference_video_config(stage)
                .expect("profile")
                .expect("video");
            assert_eq!(config.codec_capability_id, H264_VIDEO_CODEC_CAPABILITY);
        }
        assert_eq!(
            reference_opus_target_bitrate(AdaptiveMediaStage::Audio),
            Some(48_000)
        );
        assert_eq!(
            reference_opus_target_bitrate(AdaptiveMediaStage::AudioLowBitrate),
            Some(16_000)
        );
    }

    #[test]
    fn eventual_boundary_preserves_canon_fallback_order_without_executing_it() {
        assert_eq!(
            reference_deferred_fallbacks(AdaptiveMediaStage::EventualFallbackRequired),
            vec![
                DeferredMediaFallback::VoiceMessage,
                DeferredMediaFallback::Text,
                DeferredMediaFallback::StoreAndForward,
            ]
        );
    }
}
