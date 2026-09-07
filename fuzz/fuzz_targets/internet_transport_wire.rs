#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ucr_transport_internet::fuzz_decode_untrusted_internet_frame(data);
});
