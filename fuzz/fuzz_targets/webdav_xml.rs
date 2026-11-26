#![no_main]

use libfuzzer_sys::fuzz_target;
use rship_backends::webdav::xml::{parse_dav_timestamp_ns, parse_multistatus};

fuzz_target!(|data: &[u8]| {
    let _ = parse_multistatus(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_dav_timestamp_ns(s);
    }
});
