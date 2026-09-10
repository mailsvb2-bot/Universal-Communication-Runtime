#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_video::preflight_h264_parameter_sets;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let _ = preflight_h264_parameter_sets(data, 320, 240, false);
    let _ = preflight_h264_parameter_sets(data, 320, 240, true);
});
