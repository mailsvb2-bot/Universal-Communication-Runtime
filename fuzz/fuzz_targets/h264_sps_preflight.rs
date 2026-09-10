#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::VideoCodecConfig;
use ucr_protocol::H264_VIDEO_CODEC_CAPABILITY;
use ucr_video::preflight_h264_parameter_sets;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let codec = VideoCodecConfig {
        codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
        width: 320,
        height: 240,
        frame_rate: 20,
        target_bitrate_bps: 384_000,
    };
    let _ = preflight_h264_parameter_sets(data, &codec, false);
    let _ = preflight_h264_parameter_sets(data, &codec, true);
});
