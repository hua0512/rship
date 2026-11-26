#![no_main]

use libfuzzer_sys::fuzz_target;
use rship_backends::s3::xml::{
    parse_complete_multipart_response, parse_copy_result, parse_delete_objects_response,
    parse_initiate_multipart_upload, parse_list_multipart_uploads, parse_list_objects_v2,
    parse_list_parts, parse_s3_error_xml,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_list_objects_v2(data);
    let _ = parse_list_parts(data);
    let _ = parse_initiate_multipart_upload(data);
    let _ = parse_complete_multipart_response(data);
    let _ = parse_copy_result(data);
    let _ = parse_delete_objects_response(data);
    let _ = parse_list_multipart_uploads(data);
    let _ = parse_s3_error_xml(data);
});
