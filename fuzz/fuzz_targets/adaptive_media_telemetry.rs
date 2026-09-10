#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_media_adaptive::AdaptiveMediaController;
use ucr_model::{AdaptiveMediaStage, AdaptiveMediaTelemetry, MediaThermalState};
use ucr_protocol::{
    adaptive_media_pressures, canonical_adaptive_media_telemetry, reference_stage_for_telemetry,
    reference_video_config,
};

fn u16_at(data: &[u8], offset: usize) -> u16 {
    let mut bytes = [0_u8; 2];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u16::from_le_bytes(bytes)
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u32::from_le_bytes(bytes)
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u64::from_le_bytes(bytes)
}

fuzz_target!(|data: &[u8]| {
    let thermal = match data.get(23).copied().unwrap_or_default() & 3 {
        0 => MediaThermalState::Nominal,
        1 => MediaThermalState::Elevated,
        2 => MediaThermalState::Serious,
        _ => MediaThermalState::Critical,
    };
    let telemetry = AdaptiveMediaTelemetry {
        estimated_bandwidth_bps: u64_at(data, 0),
        packet_loss_basis_points: u16_at(data, 8),
        jitter_ms: u32_at(data, 10),
        rtt_ms: u32_at(data, 14),
        cpu_utilization_percent: data.get(18).copied().unwrap_or_default(),
        gpu_utilization_percent: data
            .get(19)
            .copied()
            .filter(|_| data.get(24).copied().unwrap_or_default() & 1 == 1),
        battery_percent: data.get(20).copied().unwrap_or_default(),
        external_power: data.get(21).copied().unwrap_or_default() & 1 == 1,
        thermal_state: thermal,
    };

    if canonical_adaptive_media_telemetry(&telemetry).is_ok() {
        let stage = reference_stage_for_telemetry(&telemetry).expect("validated telemetry");
        let _ = adaptive_media_pressures(&telemetry);
        let _ = reference_video_config(stage);
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video1080p);
        for _ in 0..5 {
            let _ = controller.observe(&telemetry);
        }
    }
});
