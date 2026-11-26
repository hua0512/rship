use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::s3::{
    S3Backend, S3Config, S3Credentials, S3Provider, UNSIGNED_PAYLOAD, crc64_nvme_base64,
    sha256_hex, sign_v4_request,
};
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::types::ByteRange;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

use crate::common::{self, FaultInjector, InjectedFault};

#[derive(Debug, Clone)]
pub(crate) struct MockS3Object {
    pub(crate) data: Vec<u8>,
    pub(crate) etag: String,
    pub(crate) last_modified: String,
    pub(crate) metadata: HashMap<String, String>,
    pub(crate) checksum_crc64nvme: Option<String>,
    pub(crate) checksum_crc32c: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockMultipartSession {
    pub(crate) key: String,
    pub(crate) upload_id: String,
    pub(crate) metadata: HashMap<String, String>,
    /// Upper-case `x-amz-checksum-algorithm` from `CreateMultipartUpload` (e.g. `CRC32C`).
    pub(crate) checksum_algorithm: Option<String>,
    /// `COMPOSITE` or `FULL_OBJECT` (defaulted per algorithm like AWS).
    pub(crate) checksum_type: Option<String>,
    pub(crate) parts: BTreeMap<u32, (Vec<u8>, String)>,
    pub(crate) part_checksums: BTreeMap<u32, String>,
}

/// Checksum algorithms S3 accepts, with their request header and XML element names.
const S3_CHECKSUM_ALGORITHMS: [(&str, &str, &str); 5] = [
    ("CRC32", "x-amz-checksum-crc32", "ChecksumCRC32"),
    ("CRC32C", "x-amz-checksum-crc32c", "ChecksumCRC32C"),
    ("CRC64NVME", "x-amz-checksum-crc64nvme", "ChecksumCRC64NVME"),
    ("SHA1", "x-amz-checksum-sha1", "ChecksumSHA1"),
    ("SHA256", "x-amz-checksum-sha256", "ChecksumSHA256"),
];

fn checksum_xml_tag(alg: &str) -> Option<&'static str> {
    S3_CHECKSUM_ALGORITHMS
        .iter()
        .find(|(a, _, _)| *a == alg)
        .map(|(_, _, tag)| *tag)
}

/// Compute the base64 checksum S3 would calculate for `data` (algorithms the mock can verify).
fn compute_s3_checksum_b64(alg: &str, data: &[u8]) -> Option<String> {
    match alg {
        "CRC32C" => Some(rship_backends::s3::crc32c_base64(data)),
        "CRC64NVME" => Some(crc64_nvme_base64(data)),
        _ => None,
    }
}

/// One `<Part>` of a `CompleteMultipartUpload` request body.
struct CompletePartEntry {
    part_number: u32,
    etag: String,
    /// `(algorithm, value)` for each `Checksum<ALG>` element supplied for this part.
    checksums: Vec<(&'static str, String)>,
}

fn xml_element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

fn parse_complete_parts(body: &str) -> Option<Vec<CompletePartEntry>> {
    let mut out = Vec::new();
    for chunk in body.split("<Part>").skip(1) {
        let part_xml = chunk.split("</Part>").next()?;
        let part_number = xml_element_text(part_xml, "PartNumber")?
            .trim()
            .parse()
            .ok()?;
        let etag = xml_element_text(part_xml, "ETag")?
            .trim()
            .replace("&quot;", "\"");
        let checksums = S3_CHECKSUM_ALGORITHMS
            .iter()
            .filter_map(|(alg, _, tag)| {
                xml_element_text(part_xml, tag).map(|v| (*alg, v.trim().to_string()))
            })
            .collect();
        out.push(CompletePartEntry {
            part_number,
            etag,
            checksums,
        });
    }
    Some(out)
}

#[derive(Debug, Default)]
pub(crate) struct MockS3Counters {
    pub(crate) put_object_calls: usize,
    pub(crate) create_multipart_calls: usize,
    pub(crate) upload_part_calls: usize,
    pub(crate) list_parts_calls: usize,
    pub(crate) complete_multipart_calls: usize,
    pub(crate) abort_multipart_calls: usize,
    pub(crate) copy_object_calls: usize,
    pub(crate) upload_part_copy_calls: usize,
    pub(crate) delete_object_calls: usize,
    pub(crate) delete_objects_calls: usize,
    pub(crate) get_object_calls: usize,
    pub(crate) head_object_calls: usize,
    pub(crate) list_objects_calls: usize,
    pub(crate) seen_start_afters: Vec<String>,
    pub(crate) seen_payload_hashes: Vec<String>,
    pub(crate) seen_crc64nvme_headers: Vec<String>,
    pub(crate) seen_crc32c_headers: Vec<String>,
    pub(crate) seen_content_md5_headers: Vec<String>,
    pub(crate) verified_sigv4_count: usize,
    pub(crate) seen_if_none_match_count: usize,
    pub(crate) seen_cf_copy_headers: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub(crate) struct MockS3Faults {
    /// If set, `ListParts` returns at most this many parts per page (testing pagination!).
    pub(crate) list_parts_page_limit: Option<usize>,
    /// Enforce equal non-final part sizes (Cloudflare R2 rule).
    pub(crate) enforce_r2_equal_non_final: bool,
    /// Keys that should return `<Error><Code>AccessDenied</Code>` inside `POST ?delete` `<DeleteResult>`.
    pub(crate) delete_batch_error_keys: std::collections::HashSet<String>,
    /// Queued per-key error codes returned in `<DeleteResult>` `<Error>` (popped front on each batch).
    pub(crate) delete_batch_transient_errors: HashMap<String, Vec<String>>,
    /// Corrupt the returned `ETag` on the next `PutObject` to simulate in-transit corruption.
    pub(crate) corrupt_put_etag_once: bool,
    /// Corrupt the returned `x-amz-checksum-crc32c` on the next `PutObject`.
    pub(crate) corrupt_put_crc32c_once: bool,
    /// Always compute & echo `x-amz-checksum-crc32c` on `PutObject` even if client omitted the header.
    pub(crate) always_return_crc32c_on_put: bool,
    /// Corrupt the returned `ETag` on the next `UploadPart`.
    pub(crate) corrupt_upload_part_etag_once: bool,
    /// Flip a byte in the next `GetObject` response body while keeping original checksum headers.
    pub(crate) corrupt_get_body_once: bool,
    /// Reject single-part `PutObject` containing `x-amz-checksum-crc32c` (R2 behavior).
    pub(crate) reject_r2_single_part_crc32c: bool,
    /// Enforce R2 `cf-copy-destination-if-*` headers and reject standard `If-Match`/`If-None-Match` on `CopyObject`.
    pub(crate) r2_copy_headers_only: bool,
    /// Reject `If-None-Match` on `PutObject` / `CopyObject` (Wasabi behavior).
    pub(crate) forbid_if_none_match: bool,
    /// Simulate server clock skewed by `skew_server_offset_secs` seconds from wall clock.
    pub(crate) skew_server_offset_secs: i64,
    /// Return `403 InvalidObjectState` on `GetObject` (Glacier/Deep Archive archived object).
    pub(crate) force_invalid_object_state_on_get: bool,
    /// Return `x-amz-server-side-encryption: aws:kms` and an opaque non-MD5 ETag on reads/puts.
    pub(crate) sse_kms_mode: bool,
    /// Require SSE-C headers on Put/Head/Get/Copy/UploadPart and return `x-amz-server-side-encryption-customer-algorithm: AES256` with non-MD5 ETag.
    pub(crate) sse_c_mode: bool,
}

pub(crate) struct MockS3State {
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) creds: S3Credentials,
    pub(crate) next_seq: u64,
    pub(crate) objects: BTreeMap<String, MockS3Object>,
    pub(crate) uploads: HashMap<String, MockMultipartSession>,
    pub(crate) counters: MockS3Counters,
    pub(crate) faults: MockS3Faults,
    pub(crate) fault_injector: FaultInjector,
}

impl MockS3State {
    fn new(
        bucket: &str,
        region: &str,
        creds: S3Credentials,
        fault_injector: FaultInjector,
    ) -> Self {
        Self {
            bucket: bucket.to_string(),
            region: region.to_string(),
            creds,
            next_seq: 1,
            objects: BTreeMap::new(),
            uploads: HashMap::new(),
            counters: MockS3Counters::default(),
            faults: MockS3Faults::default(),
            fault_injector,
        }
    }

    fn alloc_upload_id(&mut self) -> String {
        let id = format!("uid-{}", self.next_seq);
        self.next_seq += 1;
        id
    }
}

pub(crate) struct MockS3Server {
    pub(crate) addr: String,
    pub(crate) state: Arc<Mutex<MockS3State>>,
}

impl MockS3Server {
    pub(crate) async fn start(bucket: &str, region: &str) -> Self {
        Self::start_with_faults(bucket, region, FaultInjector::new()).await
    }

    pub(crate) async fn start_with_faults(
        bucket: &str,
        region: &str,
        fault_injector: FaultInjector,
    ) -> Self {
        let creds = S3Credentials::new("AKIA_TEST_KEY", "SECRET_TEST_KEY_12345");
        let state = Arc::new(Mutex::new(MockS3State::new(
            bucket,
            region,
            creds,
            fault_injector,
        )));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let app = Router::new()
            .fallback(handle_s3_request)
            .layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024))
            .with_state(state.clone());

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { addr, state }
    }

    pub(crate) fn fault_injector(&self) -> FaultInjector {
        self.state.lock().unwrap().fault_injector.clone()
    }

    pub(crate) fn config(&self, provider: S3Provider, bucket: &str, region: &str) -> S3Config {
        let creds = S3Credentials::new("AKIA_TEST_KEY", "SECRET_TEST_KEY_12345");
        let mut cfg = S3Config::new("test-s3", provider, bucket, creds);
        cfg.region = region.to_string();
        cfg.endpoint = Some(format!("http://{}", self.addr));
        cfg.force_path_style = Some(true);
        cfg.base_retry_delay = Duration::from_millis(10);
        cfg.max_retry_delay = Duration::from_millis(40);
        cfg
    }
}

/// Cryptographically verify incoming AWS SigV4 signature against server credentials,
/// ensuring canonical URI encoding, canonical query sorting, and payload hash match!
fn verify_incoming_sigv4(
    method: &Method,
    raw_uri: &http::Uri,
    headers: &HeaderMap,
    body: &[u8],
    creds: &S3Credentials,
    region: &str,
) -> Result<(), String> {
    let auth = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing Authorization header".to_string())?;
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing x-amz-date".to_string())?;
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing x-amz-content-sha256".to_string())?;
    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing Host header".to_string())?;

    if payload_hash != UNSIGNED_PAYLOAD {
        let actual_sha = sha256_hex(body);
        if actual_sha != payload_hash {
            return Err(format!(
                "x-amz-content-sha256 mismatch: header={payload_hash}, actual={actual_sha}"
            ));
        }
    }

    // `YYYYMMDDTHHMMSSZ` -> `YYYY-MM-DDTHH:MM:SSZ`.
    let b = amz_date.as_bytes();
    let dt = (b.len() == 16 && amz_date.is_ascii() && b[8] == b'T' && b[15] == b'Z')
        .then(|| {
            let d = amz_date;
            format!(
                "{}-{}-{}T{}:{}:{}Z",
                &d[0..4],
                &d[4..6],
                &d[6..8],
                &d[9..11],
                &d[11..13],
                &d[13..15]
            )
        })
        .and_then(|s| rship_core::time::parse_rfc3339_to_secs(&s))
        .ok_or_else(|| format!("bad x-amz-date: {amz_date}"))?;

    // Parse raw query pairs preserving percent-decoded values to feed back into canonical signer.
    let mut query_pairs: Vec<(String, String)> = Vec::new();
    if let Some(q) = raw_uri.query() {
        for pair in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query_pairs.push((percent_decode_strict(k), percent_decode_strict(v)));
        }
    }

    // Reconstruct signed header subset from `SignedHeaders=...`.
    let signed_hdrs_str = auth
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .ok_or_else(|| "missing SignedHeaders".to_string())?;
    let mut to_sign = HeaderMap::new();
    for hname in signed_hdrs_str.split(';') {
        if let Some(val) = headers.get(hname) {
            to_sign.insert(
                http::header::HeaderName::from_bytes(hname.as_bytes()).unwrap(),
                val.clone(),
            );
        }
    }

    sign_v4_request(
        method,
        raw_uri.path(),
        &query_pairs,
        host,
        &mut to_sign,
        payload_hash,
        creds,
        region,
        dt,
    )
    .map_err(|e| e.to_string())?;

    let expected_auth = to_sign
        .get(http::header::AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap();
    if expected_auth != auth {
        return Err(format!(
            "SigV4 signature mismatch!\n  expected: {expected_auth}\n  actual:   {auth}"
        ));
    }
    Ok(())
}

fn percent_decode_strict(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Encode key using S3 `encoding-type=url` convention (spaces -> `+`, `+` -> `%2B`, etc.).
fn encode_s3_url_key(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in raw.as_bytes() {
        match b {
            b' ' => out.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}

fn xml_error(status: StatusCode, code: &str, message: &str) -> Response {
    common::build_http_error_response(
        status,
        None,
        "application/xml",
        common::format_s3_error_xml(code, message),
    )
}

fn check_ssec_headers(headers: &HeaderMap, op: &str) -> Option<Response> {
    let alg = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key = headers.get("x-amz-server-side-encryption-customer-key");
    let md5 = headers.get("x-amz-server-side-encryption-customer-key-md5");
    if alg != Some("AES256") || key.is_none() || md5.is_none() {
        return Some(xml_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("missing x-amz-server-side-encryption-customer-* headers on {op}"),
        ));
    }
    None
}

fn check_ssec_copy_source_headers(headers: &HeaderMap, op: &str) -> Option<Response> {
    let alg = headers
        .get("x-amz-copy-source-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key = headers.get("x-amz-copy-source-server-side-encryption-customer-key");
    let md5 = headers.get("x-amz-copy-source-server-side-encryption-customer-key-md5");
    if alg != Some("AES256") || key.is_none() || md5.is_none() {
        return Some(xml_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("missing x-amz-copy-source-server-side-encryption-customer-* headers on {op}"),
        ));
    }
    None
}

fn classify_s3_op(
    method: &Method,
    key: &str,
    qmap: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Option<&'static str> {
    if key.is_empty() {
        if *method == Method::POST && qmap.contains_key("delete") {
            return Some("DeleteObjects");
        }
        if *method == Method::GET {
            if qmap.contains_key("uploads") {
                return Some("ListMultipartUploads");
            }
            return Some("ListObjectsV2");
        }
        return None;
    }
    if *method == Method::POST && qmap.contains_key("uploads") {
        return Some("CreateMultipartUpload");
    }
    if qmap.contains_key("uploadId") {
        return match *method {
            Method::PUT if headers.contains_key("x-amz-copy-source") => Some("UploadPartCopy"),
            Method::PUT => Some("UploadPart"),
            Method::GET => Some("ListParts"),
            Method::POST => Some("CompleteMultipartUpload"),
            Method::DELETE => Some("AbortMultipartUpload"),
            _ => None,
        };
    }
    match *method {
        Method::HEAD => Some("HeadObject"),
        Method::GET => Some("GetObject"),
        Method::PUT if headers.contains_key("x-amz-copy-source") => Some("CopyObject"),
        Method::PUT => Some("PutObject"),
        Method::DELETE => Some("DeleteObject"),
        _ => None,
    }
}

fn increment_s3_counter(counters: &mut MockS3Counters, op: &str) {
    match op {
        "DeleteObjects" => counters.delete_objects_calls += 1,
        "ListObjectsV2" => counters.list_objects_calls += 1,
        "CreateMultipartUpload" => counters.create_multipart_calls += 1,
        "UploadPartCopy" => counters.upload_part_copy_calls += 1,
        "UploadPart" => counters.upload_part_calls += 1,
        "ListParts" => counters.list_parts_calls += 1,
        "CompleteMultipartUpload" => counters.complete_multipart_calls += 1,
        "AbortMultipartUpload" => counters.abort_multipart_calls += 1,
        "HeadObject" => counters.head_object_calls += 1,
        "GetObject" => counters.get_object_calls += 1,
        "CopyObject" => counters.copy_object_calls += 1,
        "PutObject" => counters.put_object_calls += 1,
        "DeleteObject" => counters.delete_object_calls += 1,
        _ => {}
    }
}

fn is_partial_subrange_get(headers: &HeaderMap, obj_len: usize) -> bool {
    let Some(range_val) = headers
        .get(http::header::RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(spec) = range_val.strip_prefix("bytes=") else {
        return false;
    };
    let Some((s, e)) = spec.split_once('-') else {
        return false;
    };
    let (Ok(start), Ok(end)) = (s.parse::<usize>(), e.parse::<usize>()) else {
        return false;
    };
    start <= end && end < obj_len && (start > 0 || end + 1 < obj_len)
}

enum S3PreFlight {
    Immediate(Response),
    Proceed {
        slow_delay: Option<Duration>,
        post_commit_fault: Option<InjectedFault>,
        is_list_buckets: bool,
        key: String,
        qmap: HashMap<String, String>,
    },
}

fn preflight_s3_request(
    st: &Arc<Mutex<MockS3State>>,
    method: &Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> S3PreFlight {
    let mut g = st.lock().unwrap();

    if let Err(msg) = verify_incoming_sigv4(method, uri, headers, body, &g.creds, &g.region) {
        return S3PreFlight::Immediate(xml_error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            &msg,
        ));
    }
    g.counters.verified_sigv4_count += 1;

    if g.faults.skew_server_offset_secs != 0 {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let server_secs = now_secs + g.faults.skew_server_offset_secs;
        let amz_date = headers
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let req_secs = (amz_date.len() == 16 && amz_date.is_ascii())
            .then(|| {
                let d = amz_date;
                format!(
                    "{}-{}-{}T{}:{}:{}Z",
                    &d[0..4],
                    &d[4..6],
                    &d[6..8],
                    &d[9..11],
                    &d[11..13],
                    &d[13..15]
                )
            })
            .and_then(|s| rship_core::time::parse_rfc3339_to_secs(&s))
            .unwrap_or(now_secs);
        if (req_secs - server_secs).abs() > 300 {
            let server_rfc = rship_core::time::Timestamp::from_second(server_secs)
                .unwrap()
                .to_string();
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>RequestTimeTooSkewed</Code><Message>The difference between the request time and the current time is too large.</Message><ServerTime>{server_rfc}</ServerTime></Error>"
            );
            return S3PreFlight::Immediate(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "application/xml")
                    .body(Body::from(xml))
                    .unwrap(),
            );
        }
    }

    // Enforce RFC 9110 / strict S3 `411 MissingContentLength` on PUT and POST!
    if matches!(*method, Method::PUT | Method::POST)
        && !headers.contains_key(axum::http::header::CONTENT_LENGTH)
    {
        return S3PreFlight::Immediate(xml_error(
            StatusCode::LENGTH_REQUIRED,
            "MissingContentLength",
            "You must provide the Content-Length HTTP header.",
        ));
    }

    // Service-level `GET /` (`ListBuckets` probe for bucketless remotes).
    let path_trimmed = uri.path().trim_start_matches('/');
    if path_trimmed.is_empty() && *method == Method::GET {
        let mut slow_delay = None;
        let mut post_commit_fault = None;
        if let Some(fault) = g.fault_injector.next_fault("ListBuckets") {
            match fault {
                InjectedFault::SlowFinalize { delay } => slow_delay = Some(delay),
                other => match other.into_pre_commit_response() {
                    Ok(resp) => return S3PreFlight::Immediate(resp),
                    Err(post) => post_commit_fault = Some(post),
                },
            }
        }
        return S3PreFlight::Proceed {
            slow_delay,
            post_commit_fault,
            is_list_buckets: true,
            key: String::new(),
            qmap: HashMap::new(),
        };
    }

    // Parse path-style `/{bucket}` or `/{bucket}/{encoded_key}`.
    let (bucket_enc, key_enc) = match path_trimmed.split_once('/') {
        Some((b, k)) => (b, k),
        None => (path_trimmed, ""),
    };
    let bucket = percent_decode_strict(bucket_enc);
    if bucket != g.bucket {
        return S3PreFlight::Immediate(xml_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "bucket not found",
        ));
    }
    let key = percent_decode_strict(key_enc);

    let mut qmap: HashMap<String, String> = HashMap::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            qmap.insert(percent_decode_strict(k), percent_decode_strict(v));
        }
    }

    let op_name = classify_s3_op(method, &key, &qmap, headers);
    if let Some(op) = op_name {
        increment_s3_counter(&mut g.counters, op);
    }

    let mut slow_delay = None;
    let mut post_commit_fault = None;
    if let Some(op) = op_name
        && let Some(fault) = g.fault_injector.next_fault(op)
    {
        match fault {
            InjectedFault::SlowFinalize { delay } => slow_delay = Some(delay),
            InjectedFault::MidBodyReset { prefix } => {
                if op == "GetObject"
                    && g.objects
                        .get(&key)
                        .is_some_and(|obj| is_partial_subrange_get(headers, obj.data.len()))
                {
                    return S3PreFlight::Immediate(
                        common::build_mid_body_reset_response_with_status(
                            StatusCode::PARTIAL_CONTENT,
                            prefix,
                        ),
                    );
                }
                return S3PreFlight::Immediate(common::build_mid_body_reset_response(prefix));
            }
            other => match other.into_pre_commit_response() {
                Ok(resp) => return S3PreFlight::Immediate(resp),
                Err(post) => post_commit_fault = Some(post),
            },
        }
    }

    S3PreFlight::Proceed {
        slow_delay,
        post_commit_fault,
        is_list_buckets: false,
        key,
        qmap,
    }
}

async fn handle_s3_request(
    State(st): State<Arc<Mutex<MockS3State>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (slow_delay, post_commit_fault, is_list_buckets, key, qmap) =
        match preflight_s3_request(&st, &method, &uri, &headers, &body) {
            S3PreFlight::Immediate(resp) => return resp,
            S3PreFlight::Proceed {
                slow_delay,
                post_commit_fault,
                is_list_buckets,
                key,
                qmap,
            } => (slow_delay, post_commit_fault, is_list_buckets, key, qmap),
        };

    // Request body has already been drained by the `Bytes` extractor; sleep with no mutex held.
    if let Some(delay) = slow_delay {
        tokio::time::sleep(delay).await;
    }

    execute_s3_request(
        &st,
        method,
        headers,
        body,
        is_list_buckets,
        key,
        qmap,
        post_commit_fault,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_s3_request(
    st: &Arc<Mutex<MockS3State>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    is_list_buckets: bool,
    key: String,
    qmap: HashMap<String, String>,
    post_commit_fault: Option<InjectedFault>,
) -> Response {
    let mut g = st.lock().unwrap();

    if is_list_buckets {
        if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response) {
            return resp;
        }
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets><Bucket><Name>{}</Name></Bucket></Buckets></ListAllMyBucketsResult>",
            g.bucket
        );
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    // 1. Bucket-level operations (`key.is_empty()`).
    if key.is_empty() && method == Method::POST && qmap.contains_key("delete") {
        use base64::Engine as _;
        let expected_md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(&body));
        let got_md5 = headers
            .get("content-md5")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if got_md5 != expected_md5 {
            return xml_error(
                StatusCode::BAD_REQUEST,
                "BadDigest",
                "Content-MD5 did not match DeleteObjects payload",
            );
        }

        // Validate XML 1.0 legal character rules on raw body just like real S3.
        if let Ok(body_str) = std::str::from_utf8(&body)
            && !body_str.chars().all(|c| {
                matches!(
                    c,
                    '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
                )
            })
        {
            return xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            );
        }

        // Parse `<Key>...</Key>` items from `<Delete>` XML.
        let mut reader = quick_xml::Reader::from_reader(body.as_ref());
        reader.config_mut().trim_text(false);
        let mut in_key = false;
        let mut cur = String::new();
        let mut keys = Vec::new();
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == "Key" => {
                    in_key = true;
                    cur.clear();
                }
                Ok(
                    ev @ (quick_xml::events::Event::Text(_)
                    | quick_xml::events::Event::GeneralRef(_)),
                ) if in_key => {
                    if let Some(text) = rship_backends::common::xml::event_text(&ev).unwrap() {
                        cur.push_str(&text);
                    }
                }
                Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == "Key" => {
                    in_key = false;
                    keys.push(std::mem::take(&mut cur));
                }
                Ok(quick_xml::events::Event::Eof) => break,
                _ => {}
            }
        }
        if keys.len() > 1000 {
            return xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "DeleteObjects allows at most 1000 keys per request",
            );
        }

        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        for k in keys {
            if let Some(queue) = g.faults.delete_batch_transient_errors.get_mut(&k)
                && !queue.is_empty()
            {
                let code = queue.remove(0);
                xml.push_str(&format!(
                    "<Error><Key>{k}</Key><Code>{code}</Code><Message>injected transient</Message></Error>"
                ));
            } else if g.faults.delete_batch_error_keys.contains(&k) {
                xml.push_str(&format!(
                    "<Error><Key>{k}</Key><Code>AccessDenied</Code><Message>injected denied</Message></Error>"
                ));
            } else {
                g.objects.remove(&k);
            }
        }
        xml.push_str("</DeleteResult>");
        if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response) {
            return resp;
        }
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    if key.is_empty() && method == Method::GET {
        if qmap.contains_key("uploads") {
            let prefix = qmap.get("prefix").cloned().unwrap_or_default();
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>",
            );
            for u in g.uploads.values() {
                if u.key.starts_with(&prefix) {
                    xml.push_str(&format!(
                        "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>2026-11-24T00:00:00.000Z</Initiated></Upload>",
                        encode_s3_url_key(&u.key),
                        u.upload_id
                    ));
                }
            }
            xml.push_str("</ListMultipartUploadsResult>");
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
        }

        // ListObjectsV2
        let prefix = qmap.get("prefix").cloned().unwrap_or_default();
        let delimiter = qmap.get("delimiter").cloned();
        let max_keys: usize = qmap
            .get("max-keys")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        let cont = qmap.get("continuation-token").cloned();
        let start_after = qmap.get("start-after").cloned();
        if let Some(ref sa) = start_after {
            g.counters.seen_start_afters.push(sa.clone());
        }
        let lower_bound = cont.as_deref().or(start_after.as_deref());

        let mut matching_keys: Vec<String> = g
            .objects
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .filter(|k| lower_bound.is_none_or(|lb| k.as_str() > lb))
            .cloned()
            .collect();
        matching_keys.sort();

        let mut contents_xml = String::new();
        let mut common_prefixes: Vec<String> = Vec::new();
        let mut emitted = 0usize;
        let mut last_key = None;
        let mut truncated = false;

        for k in matching_keys {
            if emitted >= max_keys {
                truncated = true;
                break;
            }
            if let Some(ref d) = delimiter {
                let rest = &k[prefix.len()..];
                if let Some(pos) = rest.find(d.as_str()) {
                    let cp = format!("{prefix}{}", &rest[..pos + d.len()]);
                    if !common_prefixes.contains(&cp) {
                        common_prefixes.push(cp);
                        emitted += 1;
                    }
                    last_key = Some(k);
                    continue;
                }
            }
            let obj = &g.objects[&k];
            contents_xml.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>",
                encode_s3_url_key(&k),
                obj.last_modified,
                obj.etag.replace('"', "&quot;"),
                obj.data.len()
            ));
            emitted += 1;
            last_key = Some(k);
        }

        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><EncodingType>url</EncodingType>",
        );
        xml.push_str(&format!(
            "<IsTruncated>{}</IsTruncated>",
            if truncated { "true" } else { "false" }
        ));
        if truncated && let Some(lk) = last_key {
            xml.push_str(&format!(
                "<NextContinuationToken>{lk}</NextContinuationToken>"
            ));
        }
        xml.push_str(&contents_xml);
        for cp in common_prefixes {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                encode_s3_url_key(&cp)
            ));
        }
        xml.push_str("</ListBucketResult>");
        if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response) {
            return resp;
        }
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    // 2. Multipart operations on object key.
    if method == Method::POST && qmap.contains_key("uploads") {
        // AWS CreateMultipartUpload: `x-amz-checksum-algorithm` must be a known algorithm;
        // `x-amz-checksum-type` defaults to FULL_OBJECT for CRC64NVME and COMPOSITE otherwise.
        // CRC64NVME only supports FULL_OBJECT, SHA1/SHA256 only support COMPOSITE, and a type
        // without an algorithm is rejected.
        // https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
        let checksum_algorithm = headers
            .get("x-amz-checksum-algorithm")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_uppercase());
        let requested_type = headers
            .get("x-amz-checksum-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string());
        let checksum_type = match (checksum_algorithm.as_deref(), requested_type.as_deref()) {
            (None, None) => None,
            (None, Some(_)) => {
                return xml_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "x-amz-checksum-type requires x-amz-checksum-algorithm",
                );
            }
            (Some(alg), _) if checksum_xml_tag(alg).is_none() => {
                return xml_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Value for x-amz-checksum-algorithm header is invalid.",
                );
            }
            (Some("CRC64NVME"), None) => Some("FULL_OBJECT".to_string()),
            (Some(_), None) => Some("COMPOSITE".to_string()),
            (Some("CRC64NVME"), Some("FULL_OBJECT"))
            | (Some("CRC32" | "CRC32C"), Some("FULL_OBJECT")) => Some("FULL_OBJECT".to_string()),
            (Some("CRC32" | "CRC32C" | "SHA1" | "SHA256"), Some("COMPOSITE")) => {
                Some("COMPOSITE".to_string())
            }
            (Some(_), Some("COMPOSITE" | "FULL_OBJECT")) => {
                return xml_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "The checksum type is not supported for this checksum algorithm.",
                );
            }
            (Some(_), Some(_)) => {
                return xml_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Value for x-amz-checksum-type header is invalid.",
                );
            }
        };
        if g.faults.sse_c_mode
            && let Some(resp) = check_ssec_headers(&headers, "CreateMultipartUpload")
        {
            return resp;
        }
        let uid = g.alloc_upload_id();
        let meta = extract_user_meta(&headers);
        g.uploads.insert(
            uid.clone(),
            MockMultipartSession {
                key: key.clone(),
                upload_id: uid.clone(),
                metadata: meta,
                checksum_algorithm,
                checksum_type,
                parts: BTreeMap::new(),
                part_checksums: BTreeMap::new(),
            },
        );
        if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response) {
            return resp;
        }
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult><UploadId>{uid}</UploadId></InitiateMultipartUploadResult>"
        );
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/xml");
        if g.faults.sse_c_mode {
            resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
        }
        return resp.body(Body::from(xml)).unwrap();
    }

    if let Some(uid) = qmap.get("uploadId").cloned() {
        match method {
            Method::PUT => {
                // UploadPartCopy vs UploadPart
                let pn: u32 = qmap
                    .get("partNumber")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if let Some(copy_src) = headers
                    .get("x-amz-copy-source")
                    .and_then(|v| v.to_str().ok())
                {
                    if g.faults.sse_c_mode {
                        if let Some(resp) = check_ssec_headers(&headers, "UploadPartCopy") {
                            return resp;
                        }
                        if let Some(resp) =
                            check_ssec_copy_source_headers(&headers, "UploadPartCopy")
                        {
                            return resp;
                        }
                    }
                    let trimmed = copy_src.trim_start_matches('/');
                    let (_, src_key_enc) = trimmed.split_once('/').unwrap_or(("", trimmed));
                    let src_key = percent_decode_strict(src_key_enc);
                    let Some(src_obj) = g.objects.get(&src_key) else {
                        return xml_error(
                            StatusCode::NOT_FOUND,
                            "NoSuchKey",
                            "copy source not found",
                        );
                    };
                    if let Some(expected_etag) = headers
                        .get("x-amz-copy-source-if-match")
                        .and_then(|v| v.to_str().ok())
                        && expected_etag != src_obj.etag
                    {
                        return xml_error(
                            StatusCode::PRECONDITION_FAILED,
                            "PreconditionFailed",
                            "x-amz-copy-source-if-match mismatch",
                        );
                    }
                    let src_data = src_obj.data.clone();
                    let slice = if let Some(rng) = headers
                        .get("x-amz-copy-source-range")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.strip_prefix("bytes="))
                    {
                        let (a, b) = rng.split_once('-').unwrap();
                        let start: usize = a.parse().unwrap();
                        let end: usize = b.parse().unwrap();
                        src_data[start..=end].to_vec()
                    } else {
                        src_data
                    };
                    let etag = if g.faults.sse_c_mode {
                        format!("\"ssec-part-{pn}\"")
                    } else {
                        format!("\"{}\"", hex::encode(Md5::digest(&slice)))
                    };
                    let Some(sess) = g.uploads.get_mut(&uid) else {
                        return xml_error(
                            StatusCode::NOT_FOUND,
                            "NoSuchUpload",
                            "upload not found",
                        );
                    };
                    sess.parts.insert(pn, (slice, etag.clone()));
                    if let Some(resp) =
                        post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                    {
                        return resp;
                    }
                    let xml = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyPartResult><ETag>{}</ETag></CopyPartResult>",
                        etag.replace('"', "&quot;")
                    );
                    let mut resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/xml");
                    if g.faults.sse_c_mode {
                        resp = resp
                            .header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                    }
                    return resp.body(Body::from(xml)).unwrap();
                }

                // UploadPart
                if g.faults.sse_c_mode
                    && let Some(resp) = check_ssec_headers(&headers, "UploadPart")
                {
                    return resp;
                }
                if let Some(ph) = headers
                    .get("x-amz-content-sha256")
                    .and_then(|v| v.to_str().ok())
                {
                    g.counters.seen_payload_hashes.push(ph.to_string());
                }
                let ck64 = headers
                    .get("x-amz-checksum-crc64nvme")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(ref ck) = ck64 {
                    g.counters.seen_crc64nvme_headers.push(ck.clone());
                }
                let ck32 = headers
                    .get("x-amz-checksum-crc32c")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let sent_checksums: Vec<(&'static str, String)> = S3_CHECKSUM_ALGORITHMS
                    .iter()
                    .filter_map(|(alg, hdr, _)| {
                        headers
                            .get(*hdr)
                            .and_then(|v| v.to_str().ok())
                            .map(|v| (*alg, v.trim().to_string()))
                    })
                    .collect();
                let mut etag = if g.faults.sse_c_mode {
                    format!("\"ssec-part-{pn}\"")
                } else {
                    format!("\"{}\"", hex::encode(Md5::digest(&body)))
                };
                if g.faults.corrupt_upload_part_etag_once {
                    g.faults.corrupt_upload_part_etag_once = false;
                    etag = "\"ffffffffffffffffffffffffffffffff\"".to_string();
                }
                let Some(sess) = g.uploads.get_mut(&uid) else {
                    return xml_error(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found");
                };
                // AWS UploadPart: at most one `x-amz-checksum-*` header; its algorithm must be
                // the one the upload was created with ("Checksum Type mismatch occurred"); its
                // value must match the part bytes (`BadDigest`).
                if sent_checksums.len() > 1 {
                    return xml_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",
                    );
                }
                if let (Some((sent_alg, _)), Some(sess_alg)) =
                    (sent_checksums.first(), sess.checksum_algorithm.as_deref())
                    && *sent_alg != sess_alg
                {
                    return xml_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        &format!(
                            "Checksum Type mismatch occurred, expected checksum Type: {}, actual checksum Type: {}",
                            sess_alg.to_ascii_lowercase(),
                            sent_alg.to_ascii_lowercase()
                        ),
                    );
                }
                if let Some((sent_alg, sent_val)) = sent_checksums.first()
                    && let Some(actual) = compute_s3_checksum_b64(sent_alg, &body)
                    && actual != *sent_val
                {
                    return xml_error(
                        StatusCode::BAD_REQUEST,
                        "BadDigest",
                        &format!(
                            "The {sent_alg} you specified did not match the calculated checksum."
                        ),
                    );
                }
                // A part only carries a checksum when the client sent one: a part uploaded
                // without the header into a COMPOSITE-checksum upload can never be completed
                // (the strict reading of the AWS contract).
                if let Some((_, ck)) = sent_checksums.first() {
                    sess.part_checksums.insert(pn, ck.clone());
                } else {
                    sess.part_checksums.remove(&pn);
                }
                sess.parts.insert(pn, (body.to_vec(), etag.clone()));
                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::ETAG, etag);
                if g.faults.sse_c_mode {
                    resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                }
                if let Some(ref ck) = ck64 {
                    resp = resp.header("x-amz-checksum-crc64nvme", ck.as_str());
                }
                if let Some(ref ck) = ck32 {
                    resp = resp.header("x-amz-checksum-crc32c", ck.as_str());
                }
                return resp.body(Body::empty()).unwrap();
            }
            Method::GET => {
                // ListParts (supports forced small pagination!)
                let Some(sess) = g.uploads.get(&uid) else {
                    return xml_error(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found");
                };
                let marker: u32 = qmap
                    .get("part-number-marker")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let limit = g.faults.list_parts_page_limit.unwrap_or(1000);
                let remaining: Vec<_> = sess.parts.iter().filter(|(pn, _)| **pn > marker).collect();
                let is_truncated = remaining.len() > limit;
                let slice = &remaining[..remaining.len().min(limit)];
                let next_marker = slice.last().map(|(pn, _)| **pn);

                let mut xml =
                    String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult>");
                xml.push_str(&format!(
                    "<IsTruncated>{}</IsTruncated>",
                    if is_truncated { "true" } else { "false" }
                ));
                if is_truncated && let Some(nm) = next_marker {
                    xml.push_str(&format!(
                        "<NextPartNumberMarker>{nm}</NextPartNumberMarker>"
                    ));
                }
                for (pn, (data, etag)) in slice {
                    xml.push_str(&format!(
                        "<Part><PartNumber>{pn}</PartNumber><ETag>{}</ETag><Size>{}</Size>",
                        etag.replace('"', "&quot;"),
                        data.len()
                    ));
                    if let Some(ck) = sess.part_checksums.get(pn) {
                        match sess.checksum_algorithm.as_deref() {
                            Some("CRC64NVME") => {
                                xml.push_str(&format!(
                                    "<ChecksumCRC64NVME>{ck}</ChecksumCRC64NVME>"
                                ));
                            }
                            Some("CRC32C") => {
                                xml.push_str(&format!("<ChecksumCRC32C>{ck}</ChecksumCRC32C>"));
                            }
                            _ => {}
                        }
                    }
                    xml.push_str("</Part>");
                }
                xml.push_str("</ListPartsResult>");
                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }
                return (StatusCode::OK, [("content-type", "application/xml")], xml)
                    .into_response();
            }
            Method::POST => {
                // CompleteMultipartUpload
                if g.faults.sse_c_mode
                    && headers.keys().any(|k| {
                        let s = k.as_str();
                        s.starts_with("x-amz-server-side-encryption-customer-")
                            || s.starts_with("x-amz-copy-source-server-side-encryption-customer-")
                    })
                {
                    return xml_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "CompleteMultipartUpload must not send SSE-C request headers",
                    );
                }
                if headers
                    .get(http::header::IF_NONE_MATCH)
                    .and_then(|v| v.to_str().ok())
                    == Some("*")
                    && g.objects.contains_key(&key)
                {
                    return xml_error(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "object already exists",
                    );
                }
                if let Some(if_match) = headers
                    .get(http::header::IF_MATCH)
                    .and_then(|v| v.to_str().ok())
                {
                    match g.objects.get(&key) {
                        Some(existing) if existing.etag == if_match => {}
                        _ => {
                            return xml_error(
                                StatusCode::PRECONDITION_FAILED,
                                "PreconditionFailed",
                                "CompleteMultipartUpload If-Match failed",
                            );
                        }
                    }
                }
                let Some(sess) = g.uploads.remove(&uid) else {
                    return xml_error(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found");
                };
                if g.faults.enforce_r2_equal_non_final && sess.parts.len() >= 2 {
                    let lens: Vec<usize> = sess.parts.values().map(|(d, _)| d.len()).collect();
                    let first = lens[0];
                    if lens[..lens.len() - 1].iter().any(|&l| l != first) {
                        return xml_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidPart",
                            "R2 requires equal non-final part sizes",
                        );
                    }
                }
                let body_str = std::str::from_utf8(&body).unwrap_or("");
                if let Err(resp) = validate_complete_manifest(&sess, body_str) {
                    // A rejected Complete leaves the upload in place, like S3.
                    g.uploads.insert(uid.clone(), sess);
                    return *resp;
                }
                let listed = parse_complete_parts(body_str).expect("validated manifest");
                let mut combined = Vec::new();
                let mut part_md5s = Vec::new();
                for entry in &listed {
                    let (data, _) = &sess.parts[&entry.part_number];
                    part_md5s.extend_from_slice(&Md5::digest(data));
                    combined.extend_from_slice(data);
                }
                let mp_etag = if g.faults.sse_c_mode {
                    format!("\"ssec-mp-{}-{}\"", g.objects.len() + 1, listed.len())
                } else {
                    format!(
                        "\"{}-{}\"",
                        hex::encode(Md5::digest(&part_md5s)),
                        listed.len()
                    )
                };
                let full_crc64 = (sess.checksum_algorithm.as_deref() == Some("CRC64NVME"))
                    .then(|| crc64_nvme_base64(&combined));
                let composite_crc32c = (sess.checksum_algorithm.as_deref() == Some("CRC32C"))
                    .then(|| format!("4waSgw==-{}", listed.len()));
                let obj = MockS3Object {
                    data: combined,
                    etag: mp_etag.clone(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                    metadata: sess.metadata,
                    checksum_crc64nvme: full_crc64.clone(),
                    checksum_crc32c: composite_crc32c.clone(),
                };
                g.objects.insert(sess.key, obj);

                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }

                let mut ck_xml = String::new();
                if let Some(ref c64) = full_crc64 {
                    ck_xml.push_str(&format!("<ChecksumCRC64NVME>{c64}</ChecksumCRC64NVME>"));
                }
                if let Some(ref c32) = composite_crc32c {
                    ck_xml.push_str(&format!("<ChecksumCRC32C>{c32}</ChecksumCRC32C>"));
                }
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult><ETag>{}</ETag>{ck_xml}</CompleteMultipartUploadResult>",
                    mp_etag.replace('"', "&quot;")
                );
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/xml");
                if g.faults.sse_c_mode {
                    resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                }
                return resp.body(Body::from(xml)).unwrap();
            }
            Method::DELETE => {
                // AbortMultipartUpload
                if g.uploads.remove(&uid).is_some() {
                    if let Some(resp) =
                        post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                    {
                        return resp;
                    }
                    return StatusCode::NO_CONTENT.into_response();
                }
                return xml_error(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found");
            }
            _ => {}
        }
    }

    // 3. Single-object operations: HEAD / GET / PUT / DELETE.
    match method {
        Method::HEAD => {
            let Some(obj) = g.objects.get(&key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_LENGTH, obj.data.len())
                .header(http::header::ETAG, &obj.etag)
                .header(http::header::LAST_MODIFIED, &obj.last_modified);
            if g.faults.sse_kms_mode {
                resp = resp.header("x-amz-server-side-encryption", "aws:kms");
            }
            if g.faults.sse_c_mode {
                if let Some(resp) = check_ssec_headers(&headers, "HeadObject") {
                    return resp;
                }
                resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
            }
            for (mk, mv) in &obj.metadata {
                resp = resp.header(mk.as_str(), mv.as_str());
            }
            if let Some(ref c64) = obj.checksum_crc64nvme {
                resp = resp.header("x-amz-checksum-crc64nvme", c64.as_str());
            }
            if let Some(ref c32) = obj.checksum_crc32c {
                resp = resp.header("x-amz-checksum-crc32c", c32.as_str());
            }
            resp.body(Body::empty()).unwrap()
        }
        Method::GET => {
            if g.faults.force_invalid_object_state_on_get {
                return xml_error(
                    StatusCode::FORBIDDEN,
                    "InvalidObjectState",
                    "The operation is not valid for the object's storage class",
                );
            }
            if g.faults.sse_c_mode
                && let Some(resp) = check_ssec_headers(&headers, "GetObject")
            {
                return resp;
            }
            let corrupt_body = if g.faults.corrupt_get_body_once {
                g.faults.corrupt_get_body_once = false;
                true
            } else {
                false
            };
            let Some(obj) = g.objects.get(&key) else {
                return xml_error(StatusCode::NOT_FOUND, "NoSuchKey", "key not found");
            };
            if let Some(if_match) = headers
                .get(http::header::IF_MATCH)
                .and_then(|v| v.to_str().ok())
                && if_match != obj.etag
            {
                return xml_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "ETag mismatch on version-pinned Range read",
                );
            }
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            let send_ck_mode = headers
                .get("x-amz-checksum-mode")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("ENABLED"));
            let total = obj.data.len();
            if let Some(range_val) = headers
                .get(http::header::RANGE)
                .and_then(|v| v.to_str().ok())
                && let Some(spec) = range_val.strip_prefix("bytes=")
                && let Some((s, e)) = spec.split_once('-')
                && let (Ok(start), Ok(end)) = (s.parse::<usize>(), e.parse::<usize>())
                && start <= end
                && end < total
            {
                let mut slice = obj.data[start..=end].to_vec();
                if corrupt_body && let Some(last) = slice.last_mut() {
                    *last ^= 0xFF;
                }
                let mut resp = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(http::header::ETAG, &obj.etag)
                    .header(
                        http::header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{total}"),
                    )
                    .header(http::header::CONTENT_LENGTH, slice.len());
                if g.faults.sse_kms_mode {
                    resp = resp.header("x-amz-server-side-encryption", "aws:kms");
                }
                if g.faults.sse_c_mode {
                    resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                }
                if send_ck_mode {
                    if let Some(ref c64) = obj.checksum_crc64nvme {
                        resp = resp.header("x-amz-checksum-crc64nvme", c64.as_str());
                    }
                    if let Some(ref c32) = obj.checksum_crc32c {
                        resp = resp.header("x-amz-checksum-crc32c", c32.as_str());
                    }
                }
                return resp.body(Body::from(slice)).unwrap();
            }
            let mut full_body = obj.data.clone();
            if corrupt_body && let Some(last) = full_body.last_mut() {
                *last ^= 0xFF;
            }
            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::ETAG, &obj.etag)
                .header(http::header::CONTENT_LENGTH, total);
            if g.faults.sse_kms_mode {
                resp = resp.header("x-amz-server-side-encryption", "aws:kms");
            }
            if g.faults.sse_c_mode {
                resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
            }
            if send_ck_mode {
                if let Some(ref c64) = obj.checksum_crc64nvme {
                    resp = resp.header("x-amz-checksum-crc64nvme", c64.as_str());
                }
                if let Some(ref c32) = obj.checksum_crc32c {
                    resp = resp.header("x-amz-checksum-crc32c", c32.as_str());
                }
            }
            resp.body(Body::from(full_body)).unwrap()
        }
        Method::PUT => {
            if let Some(copy_src) = headers
                .get("x-amz-copy-source")
                .and_then(|v| v.to_str().ok())
            {
                if g.faults.sse_c_mode {
                    if let Some(resp) = check_ssec_headers(&headers, "CopyObject") {
                        return resp;
                    }
                    if let Some(resp) = check_ssec_copy_source_headers(&headers, "CopyObject") {
                        return resp;
                    }
                }
                let trimmed = copy_src.trim_start_matches('/');
                let (_, src_key_enc) = trimmed.split_once('/').unwrap_or(("", trimmed));
                let src_key = percent_decode_strict(src_key_enc);
                let Some(src_obj) = g.objects.get(&src_key).cloned() else {
                    return xml_error(StatusCode::NOT_FOUND, "NoSuchKey", "copy source not found");
                };
                if let Some(expected_etag) = headers
                    .get("x-amz-copy-source-if-match")
                    .and_then(|v| v.to_str().ok())
                    && expected_etag != src_obj.etag
                {
                    return xml_error(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "x-amz-copy-source-if-match mismatch",
                    );
                }
                if g.faults.r2_copy_headers_only {
                    if headers.contains_key(http::header::IF_NONE_MATCH)
                        || headers.contains_key(http::header::IF_MATCH)
                    {
                        return xml_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidRequest",
                            "R2 CopyObject rejects standard If-Match / If-None-Match",
                        );
                    }
                    if let Some(cf_inm) = headers
                        .get("cf-copy-destination-if-none-match")
                        .and_then(|v| v.to_str().ok())
                    {
                        g.counters.seen_cf_copy_headers.push((
                            "cf-copy-destination-if-none-match".to_string(),
                            cf_inm.to_string(),
                        ));
                        if cf_inm == "*" && g.objects.contains_key(&key) {
                            return xml_error(
                                StatusCode::PRECONDITION_FAILED,
                                "PreconditionFailed",
                                "cf-copy-destination-if-none-match: * failed",
                            );
                        }
                    }
                    if let Some(cf_im) = headers
                        .get("cf-copy-destination-if-match")
                        .and_then(|v| v.to_str().ok())
                    {
                        g.counters.seen_cf_copy_headers.push((
                            "cf-copy-destination-if-match".to_string(),
                            cf_im.to_string(),
                        ));
                        match g.objects.get(&key) {
                            Some(existing) if existing.etag == cf_im => {}
                            _ => {
                                return xml_error(
                                    StatusCode::PRECONDITION_FAILED,
                                    "PreconditionFailed",
                                    "cf-copy-destination-if-match failed",
                                );
                            }
                        }
                    }
                } else {
                    if headers
                        .get(http::header::IF_NONE_MATCH)
                        .and_then(|v| v.to_str().ok())
                        == Some("*")
                        && g.objects.contains_key(&key)
                    {
                        return xml_error(
                            StatusCode::PRECONDITION_FAILED,
                            "PreconditionFailed",
                            "CopyObject If-None-Match: * failed (object already exists)",
                        );
                    }
                    if let Some(if_match) = headers
                        .get(http::header::IF_MATCH)
                        .and_then(|v| v.to_str().ok())
                    {
                        match g.objects.get(&key) {
                            Some(existing) if existing.etag == if_match => {}
                            _ => {
                                return xml_error(
                                    StatusCode::PRECONDITION_FAILED,
                                    "PreconditionFailed",
                                    "CopyObject If-Match failed",
                                );
                            }
                        }
                    }
                }
                let dst_etag = if g.faults.sse_c_mode {
                    format!("\"ssec-opaque-copy-{}\"", g.objects.len() + 1)
                } else {
                    src_obj.etag.clone()
                };
                let new_obj = MockS3Object {
                    data: src_obj.data,
                    etag: dst_etag.clone(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                    metadata: extract_user_meta(&headers),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                };
                g.objects.insert(key, new_obj);
                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult><ETag>{}</ETag></CopyObjectResult>",
                    dst_etag.replace('"', "&quot;")
                );
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/xml");
                if g.faults.sse_c_mode {
                    resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                }
                return resp.body(Body::from(xml)).unwrap();
            }

            if let Some(ph) = headers
                .get("x-amz-content-sha256")
                .and_then(|v| v.to_str().ok())
            {
                g.counters.seen_payload_hashes.push(ph.to_string());
            }
            let ck64 = headers
                .get("x-amz-checksum-crc64nvme")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(ref c) = ck64 {
                g.counters.seen_crc64nvme_headers.push(c.clone());
            }
            let ck32 = headers
                .get("x-amz-checksum-crc32c")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(ref c) = ck32 {
                if g.faults.reject_r2_single_part_crc32c {
                    return xml_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "R2 single-part PutObject does not support x-amz-checksum-crc32c",
                    );
                }
                g.counters.seen_crc32c_headers.push(c.clone());
            }
            if let Some(cm) = headers
                .get("content-md5")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                g.counters.seen_content_md5_headers.push(cm);
            }
            if headers.contains_key(http::header::IF_NONE_MATCH) {
                g.counters.seen_if_none_match_count += 1;
                if g.faults.forbid_if_none_match {
                    return xml_error(
                        StatusCode::NOT_IMPLEMENTED,
                        "NotImplemented",
                        "If-None-Match is not supported",
                    );
                }
            }
            if headers
                .get(http::header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                == Some("*")
                && g.objects.contains_key(&key)
            {
                return xml_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "If-None-Match: * failed (object already exists)",
                );
            }
            if let Some(if_match) = headers
                .get(http::header::IF_MATCH)
                .and_then(|v| v.to_str().ok())
            {
                match g.objects.get(&key) {
                    Some(existing) if existing.etag == if_match => {}
                    _ => {
                        return xml_error(
                            StatusCode::PRECONDITION_FAILED,
                            "PreconditionFailed",
                            "If-Match failed",
                        );
                    }
                }
            }
            let mut etag = if g.faults.sse_kms_mode {
                format!("\"kms-opaque-{}\"", g.objects.len() + 1)
            } else if g.faults.sse_c_mode {
                if let Some(resp) = check_ssec_headers(&headers, "PutObject") {
                    return resp;
                }
                format!("\"ssec-opaque-{}\"", g.objects.len() + 1)
            } else {
                format!("\"{}\"", hex::encode(Md5::digest(&body)))
            };
            if g.faults.corrupt_put_etag_once {
                g.faults.corrupt_put_etag_once = false;
                etag = "\"00000000000000000000000000000000\"".to_string();
            }
            let resp_ck32 = if g.faults.corrupt_put_crc32c_once {
                g.faults.corrupt_put_crc32c_once = false;
                Some("AAAAAA==".to_string())
            } else if ck32.is_some() {
                ck32.clone()
            } else if g.faults.always_return_crc32c_on_put {
                Some(rship_backends::s3::crc32c_base64(&body))
            } else {
                None
            };
            let obj = MockS3Object {
                data: body.to_vec(),
                etag: etag.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                metadata: extract_user_meta(&headers),
                checksum_crc64nvme: ck64.clone(),
                checksum_crc32c: resp_ck32.clone(),
            };
            g.objects.insert(key, obj);
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::ETAG, etag);
            if g.faults.sse_kms_mode {
                resp = resp.header("x-amz-server-side-encryption", "aws:kms");
            }
            if g.faults.sse_c_mode {
                resp = resp.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
            }
            if let Some(c) = ck64 {
                resp = resp.header("x-amz-checksum-crc64nvme", c);
            }
            if let Some(c) = resp_ck32 {
                resp = resp.header("x-amz-checksum-crc32c", c);
            }
            resp.body(Body::empty()).unwrap()
        }
        Method::DELETE => {
            g.objects.remove(&key);
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Validate a `CompleteMultipartUpload` part manifest the way AWS does:
/// - parts must be listed in ascending order (`InvalidPartOrder`), and each must exist with a
///   matching ETag (`InvalidPart`); only the listed parts are assembled;
/// - for a COMPOSITE-checksum upload, EVERY part must carry its `Checksum<ALG>` element
///   ("The upload was created using a crc32c checksum. The complete request must include the
///   checksum for each part. It was missing for part 1 in the request.");
/// - FULL_OBJECT uploads may omit part checksums, but any supplied one must match the part;
/// - a part checksum of another algorithm, or one on a non-checksummed upload, is rejected.
///
/// <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>
fn validate_complete_manifest(
    sess: &MockMultipartSession,
    body_str: &str,
) -> std::result::Result<(), Box<Response>> {
    let reject = |code: &str, msg: String| Box::new(xml_error(StatusCode::BAD_REQUEST, code, &msg));
    let Some(listed) = parse_complete_parts(body_str).filter(|p| !p.is_empty()) else {
        return Err(reject(
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema.".to_string(),
        ));
    };
    for (i, entry) in listed.iter().enumerate() {
        let pn = entry.part_number;
        if i > 0 && pn <= listed[i - 1].part_number {
            return Err(reject(
                "InvalidPartOrder",
                "The list of parts was not in ascending order.".to_string(),
            ));
        }
        let Some((_, stored_etag)) = sess.parts.get(&pn) else {
            return Err(reject(
                "InvalidPart",
                format!("One or more of the specified parts could not be found (part {pn})."),
            ));
        };
        if stored_etag.trim_matches('"') != entry.etag.trim_matches('"') {
            return Err(reject(
                "InvalidPart",
                format!("The entity tag of part {pn} did not match."),
            ));
        }
        let stored_ck = sess.part_checksums.get(&pn);
        let Some(alg) = sess.checksum_algorithm.as_deref() else {
            if !entry.checksums.is_empty() {
                return Err(reject(
                    "InvalidRequest",
                    format!("The upload was not created with a checksum, but part {pn} has one."),
                ));
            }
            continue;
        };
        if entry.checksums.iter().any(|(a, _)| *a != alg) {
            return Err(reject(
                "InvalidRequest",
                format!(
                    "The upload was created using a {} checksum; part {pn} has another algorithm.",
                    alg.to_ascii_lowercase()
                ),
            ));
        }
        let composite = sess.checksum_type.as_deref() == Some("COMPOSITE");
        match entry.checksums.iter().find(|(a, _)| *a == alg) {
            None if composite => {
                return Err(reject(
                    "InvalidRequest",
                    format!(
                        "The upload was created using a {} checksum. The complete request must include the checksum for each part. It was missing for part {pn} in the request.",
                        alg.to_ascii_lowercase()
                    ),
                ));
            }
            Some((_, val)) if Some(val) != stored_ck => {
                return Err(reject(
                    "InvalidPart",
                    format!("The checksum of part {pn} did not match the uploaded part."),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn extract_user_meta(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        if lower.starts_with("x-amz-meta-")
            && let Ok(s) = v.to_str()
        {
            out.insert(lower, s.to_string());
        }
    }
    out
}

pub(crate) async fn read_s3_all(backend: &S3Backend, path: &RelPath) -> Vec<u8> {
    match backend
        .open_read(&BackendPath::from_rel(path.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => {
            let mut s = r
                .open_range(ByteRange {
                    offset: 0,
                    len: r.total_len(),
                })
                .await
                .unwrap();
            let mut out = Vec::new();
            while let Some(c) = s.next().await {
                out.extend_from_slice(&c.unwrap());
            }
            out
        }
        _ => panic!("expected RemoteRangeReadable"),
    }
}
