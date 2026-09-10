use crate::VideoCodecConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaThermalState {
    Nominal,
    Elevated,
    Serious,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveMediaTelemetry {
    pub estimated_bandwidth_bps: u64,
    pub packet_loss_basis_points: u16,
    pub jitter_ms: u32,
    pub rtt_ms: u32,
    pub cpu_utilization_percent: u8,
    pub gpu_utilization_percent: Option<u8>,
    pub battery_percent: u8,
    pub external_power: bool,
    pub thermal_state: MediaThermalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdaptiveMediaStage {
    Video1080p,
    Video720p,
    Video480p,
    VideoLowFps,
    Audio,
    AudioLowBitrate,
    EventualFallbackRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMediaPressure {
    Bandwidth,
    PacketLoss,
    Jitter,
    Rtt,
    Cpu,
    Gpu,
    Battery,
    Thermal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredMediaFallback {
    VoiceMessage,
    Text,
    StoreAndForward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveMediaDecision {
    pub stage: AdaptiveMediaStage,
    pub changed: bool,
    pub requires_media_renegotiation: bool,
    pub video: Option<VideoCodecConfig>,
    pub opus_target_bitrate_bps: Option<u32>,
    pub deferred_fallbacks: Vec<DeferredMediaFallback>,
    pub pressures: Vec<AdaptiveMediaPressure>,
}
