#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::OpaqueId;

fuzz_target!(|data: &[u8]| {
    if let Ok(id) = OpaqueId::from_wire_bytes(data) {
        assert_eq!(id.as_wire_bytes(), data);
        let reparsed = OpaqueId::from_wire_bytes(id.as_wire_bytes()).expect("valid round trip");
        assert_eq!(reparsed, id);
    }
});
