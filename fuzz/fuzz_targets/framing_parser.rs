#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_protocol::{FramePolicy, decode_frame_prefix, decode_header};

fuzz_target!(|data: &[u8]| {
    let policy = FramePolicy::default();
    let header = decode_header(data, policy);
    let frame = decode_frame_prefix(data, policy);

    if let Ok((decoded, payload, remainder)) = frame {
        assert_eq!(header, Ok(decoded));
        assert_eq!(payload.len(), decoded.payload_len as usize);
        assert_eq!(data.len(), 12 + payload.len() + remainder.len());
    }
});
