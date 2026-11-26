#![no_main]

use libfuzzer_sys::fuzz_target;
use rship_backends::azureblob::xml::{
    normalize_azure_etag, parse_azure_error_xml, parse_block_list, parse_list_blobs,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_list_blobs(data);
    let _ = parse_block_list(data);
    let _ = parse_azure_error_xml(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = normalize_azure_etag(s);
    }
});
