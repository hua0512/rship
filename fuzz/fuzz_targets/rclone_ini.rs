#![no_main]

use libfuzzer_sys::fuzz_target;
use rship_core::rclone_ini::{
    obscure_rclone_secret_with_iv, parse_rclone_ini, reveal_or_passthrough_rclone_secret,
    reveal_rclone_obscured,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(sections) = parse_rclone_ini(text) {
        for section in &sections {
            let _ = section.kind();
            let _ = section.get_non_empty("type");
            let _ = section.get_non_empty("pass");
            let _ = section.get_bool("env_auth");
            // Exercise Debug redaction to ensure arbitrary keys/values never panic.
            let _ = format!("{section:?}");
        }
    }

    let _ = reveal_rclone_obscured(text);
    let _ = reveal_or_passthrough_rclone_secret(text);

    // Round-trip invariant: obscuring arbitrary UTF-8 with an arbitrary 16-byte IV
    // must always reveal back to the exact original string.
    if data.len() >= 16
        && let Ok(plain) = std::str::from_utf8(&data[16..])
    {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[..16]);
        let obscured = obscure_rclone_secret_with_iv(plain, iv);
        let revealed = reveal_rclone_obscured(&obscured)
            .expect("obscured valid UTF-8 secret must always reveal");
        assert_eq!(revealed, plain);
    }
});
