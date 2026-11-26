//! Pure-Rust AWS Signature Version 4 (`AWS4-HMAC-SHA256`) signer and strict
//! S3 URI encoding/decoding (`TestMergeDeleteMarkersWithURLEncodedKeys`).

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rship_core::{Error, Result};
use sha2::{Digest, Sha256};

use crate::common::http::sensitive_header_value;
use crate::s3::config::S3Credentials;

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Compute lowercase hex SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// RFC 2104 HMAC-SHA256 delegated to shared `crate::common::crypto::hmac_sha256`.
pub use crate::common::crypto::hmac_sha256;

/// Strict RFC 3986 / AWS SigV4 URI percent-encoding.
///
/// Unreserved characters `A-Z a-z 0-9 - _ . ~` pass through verbatim; everything
/// else (including space -> `%20`, `+` -> `%2B`, `%` -> `%25`, `&` -> `%26`,
/// `#` -> `%23`, `/` -> `%2F`, and multi-byte UTF-8) is uppercase percent-encoded.
pub fn aws_uri_encode(input: &str) -> String {
    crate::common::http::percent_encode_segment(input)
}

/// Strict AWS SigV4 canonical path encoding (preserves `/` separators while
/// encoding every other non-unreserved byte strictly per RFC 3986).
pub fn aws_uri_encode_path(path: &str) -> String {
    crate::common::http::percent_encode_path(path)
}

/// Decode an S3 XML key/prefix returned when `encoding-type=url` was requested.
///
/// Per AWS S3 specification, `encoding-type=url` encodes spaces as `+`, literal `+`
/// as `%2B`, `%` as `%25`, and non-ASCII/control bytes as `%XX`.
pub fn decode_s3_url_encoded_key(encoded: &str) -> Result<String> {
    let bytes = encoded.as_bytes();
    if !bytes.iter().any(|&b| b == b'+' || b == b'%') {
        return Ok(encoded.to_owned());
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(Error::protocol(format!(
                        "truncated percent-escape in S3 encoded key `{encoded}`"
                    )));
                }
                let hi = hex_val(bytes[i + 1]).ok_or_else(|| {
                    Error::protocol(format!("invalid hex escape in S3 key `{encoded}`"))
                })?;
                let lo = hex_val(bytes[i + 2]).ok_or_else(|| {
                    Error::protocol(format!("invalid hex escape in S3 key `{encoded}`"))
                })?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out)
        .map_err(|e| Error::protocol(format!("S3 URL-decoded key is not valid UTF-8: {e}")))
}

/// Zero-allocation fast-path variant of [`decode_s3_url_encoded_key`] for owned keys:
/// returns `encoded` untouched when it contains no `+` or `%` bytes.
pub fn decode_s3_url_encoded_key_owned(encoded: String) -> Result<String> {
    if !encoded.as_bytes().iter().any(|&b| b == b'+' || b == b'%') {
        return Ok(encoded);
    }
    decode_s3_url_encoded_key(&encoded)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Build the AWS SigV4 canonical query string from raw `(name, value)` pairs.
/// Sorts strictly by `(encoded_name, encoded_value)` and emits `k=v` (even when `v` is empty).
pub fn build_canonical_query(query_pairs: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = query_pairs
        .iter()
        .map(|(k, v)| (aws_uri_encode(k), aws_uri_encode(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sign an S3 HTTP request in place using AWS Signature Version 4 (`AWS4-HMAC-SHA256`).
///
/// Injects `host`, `x-amz-date`, `x-amz-content-sha256`, optional `x-amz-security-token`,
/// and `authorization` headers into `headers`.
#[allow(clippy::too_many_arguments)]
pub fn sign_v4_request(
    method: &Method,
    canonical_uri: &str,
    query_pairs: &[(String, String)],
    host_header: &str,
    headers: &mut HeaderMap,
    payload_sha256: &str,
    creds: &S3Credentials,
    region: &str,
    now_unix_secs: i64,
) -> Result<()> {
    sign_v4_service_request(
        method,
        canonical_uri,
        query_pairs,
        host_header,
        headers,
        payload_sha256,
        creds,
        region,
        "s3",
        now_unix_secs,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4_service_request(
    method: &Method,
    canonical_uri: &str,
    query_pairs: &[(String, String)],
    host_header: &str,
    headers: &mut HeaderMap,
    payload_sha256: &str,
    creds: &S3Credentials,
    region: &str,
    service: &str,
    now_unix_secs: i64,
) -> Result<()> {
    // `YYYYMMDDTHHMMSSZ`; the credential-scope date is its `YYYYMMDD` prefix.
    let amz_date = rship_core::time::format_iso8601_basic(now_unix_secs);
    let date_stamp = amz_date[..8].to_string();

    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host_header)
            .map_err(|e| Error::protocol(format!("invalid Host header `{host_header}`: {e}")))?,
    );
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        HeaderValue::from_str(&amz_date).expect("valid amz date"),
    );
    headers.insert(
        HeaderName::from_static("x-amz-content-sha256"),
        HeaderValue::from_str(payload_sha256)
            .map_err(|e| Error::protocol(format!("invalid x-amz-content-sha256: {e}")))?,
    );
    if let Some(ref st) = creds.session_token
        && !st.is_empty()
    {
        headers.insert(
            HeaderName::from_static("x-amz-security-token"),
            sensitive_header_value(st, "x-amz-security-token")?,
        );
    }

    // Collect and sort all headers to sign (excluding `authorization` itself).
    let mut header_entries: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization" || lower == "user-agent" {
            continue;
        }
        let val_s = value
            .to_str()
            .map_err(|_| Error::protocol(format!("non-ASCII header `{lower}`")))?;
        // SigV4 trims leading/trailing whitespace and collapses internal runs of spaces.
        let collapsed = collapse_spaces(val_s.trim());
        header_entries.push((lower, collapsed));
    }
    header_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Merge duplicate header keys with commas per SigV4 spec.
    let mut merged: Vec<(String, String)> = Vec::with_capacity(header_entries.len());
    for (k, v) in header_entries {
        if let Some(last) = merged.last_mut()
            && last.0 == k
        {
            last.1.push(',');
            last.1.push_str(&v);
        } else {
            merged.push((k, v));
        }
    }

    let mut canonical_headers = String::new();
    let mut signed_headers_list = Vec::with_capacity(merged.len());
    for (k, v) in &merged {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
        signed_headers_list.push(k.as_str());
    }
    let signed_headers = signed_headers_list.join(";");
    let canonical_query = build_canonical_query(query_pairs);

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_sha256
    );
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );
    headers.insert(
        http::header::AUTHORIZATION,
        sensitive_header_value(&auth_header, "Authorization")?,
    );
    Ok(())
}

fn collapse_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch == ' ' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encoding_and_s3_url_key_decoding_preserve_special_chars_and_utf8() {
        let raw = "dir/a + b %20 & # café 中文.txt";
        let encoded_path = aws_uri_encode_path(&format!("/{raw}"));
        assert_eq!(
            encoded_path,
            "/dir/a%20%2B%20b%20%2520%20%26%20%23%20caf%C3%A9%20%E4%B8%AD%E6%96%87.txt"
        );

        // S3 `encoding-type=url` emits `+` for spaces and `%2B` for literal `+`!
        let s3_xml_key = "dir/a+%2B+b+%2520+%26+%23+caf%C3%A9+%E4%B8%AD%E6%96%87.txt";
        assert_eq!(decode_s3_url_encoded_key(s3_xml_key).unwrap(), raw);
    }

    #[test]
    fn sigv4_matches_official_aws_s3_get_object_test_vector() {
        // Official AWS S3 SigV4 documentation example:
        // GET /test.txt, Host: examplebucket.s3.amazonaws.com, Range: bytes=0-9
        // Date: 20130524T000000Z (1369353600), Region: us-east-1
        let creds = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RANGE, HeaderValue::from_static("bytes=0-9"));

        sign_v4_request(
            &Method::GET,
            "/test.txt",
            &[],
            "examplebucket.s3.amazonaws.com",
            &mut headers,
            EMPTY_SHA256_HEX,
            &creds,
            "us-east-1",
            1_369_353_600,
        )
        .unwrap();

        assert_eq!(
            headers.get("x-amz-date").unwrap().to_str().unwrap(),
            "20130524T000000Z"
        );
        let auth = headers
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn sigv4_matches_official_aws_s3_put_object_test_vector() {
        // Official AWS S3 SigV4 documentation PutObject example:
        // PUT /test%24file.text, Date: 20130524T000000Z, payload = "Welcome to Amazon S3."
        let creds = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let payload_hash = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            payload_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::DATE,
            HeaderValue::from_static("Fri, 24 May 2013 00:00:00 GMT"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-storage-class"),
            HeaderValue::from_static("REDUCED_REDUNDANCY"),
        );

        let uri = aws_uri_encode_path("/test$file.text");
        assert_eq!(uri, "/test%24file.text");

        sign_v4_request(
            &Method::PUT,
            &uri,
            &[],
            "examplebucket.s3.amazonaws.com",
            &mut headers,
            &payload_hash,
            &creds,
            "us-east-1",
            1_369_353_600,
        )
        .unwrap();

        let auth = headers
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn sigv4_marks_authorization_and_security_token_headers_sensitive() {
        let creds = S3Credentials::new("ASIA_TEMP_KEY", "SECRET_TEMP_KEY")
            .with_session_token(Some("FwoGZXIvYXdzE_SUPER_SECRET_TOKEN".to_string()));
        let mut headers = HeaderMap::new();
        sign_v4_request(
            &Method::GET,
            "/bucket/key",
            &[],
            "s3.us-east-1.amazonaws.com",
            &mut headers,
            EMPTY_SHA256_HEX,
            &creds,
            "us-east-1",
            1_700_000_000,
        )
        .unwrap();

        let auth_val = headers.get(http::header::AUTHORIZATION).unwrap();
        assert!(auth_val.is_sensitive(), "Authorization must be sensitive");
        assert!(
            !format!("{auth_val:?}").contains("Signature="),
            "Debug formatting must hide sensitive Authorization header"
        );

        let token_val = headers.get("x-amz-security-token").unwrap();
        assert!(
            token_val.is_sensitive(),
            "x-amz-security-token must be sensitive"
        );
        assert!(
            !format!("{token_val:?}").contains("SUPER_SECRET_TOKEN"),
            "Debug formatting must hide sensitive x-amz-security-token header"
        );
    }
}
