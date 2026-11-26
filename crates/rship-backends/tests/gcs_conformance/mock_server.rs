use crate::common::{FaultInjector, InjectedFault, build_mid_body_reset_response_with_status};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use md5::{Digest as _, Md5};
use rship_backends::gcs::{GCS_CHUNK_ALIGN_BYTES, GcsBackend, GcsConfig};
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
pub(crate) struct MockGcsObject {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) generation: u64,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) cache_control: Option<String>,
    pub(crate) content_disposition: Option<String>,
    pub(crate) content_language: Option<String>,
    pub(crate) custom_time: Option<String>,
    /// Optional uncompressed body used to simulate GCS decompressive transcoding when
    /// `content_encoding == Some("gzip")` and client omits `Accept-Encoding: gzip`.
    pub(crate) gzip_uncompressed: Option<Vec<u8>>,
}

pub(crate) struct MockResumableSession {
    pub(crate) name: String,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) if_gen_match: Option<u64>,
    pub(crate) buf: Vec<u8>,
    pub(crate) completed: Option<MockGcsObject>,
    /// Base64 `crc32c` / `md5Hash` from the initiation metadata, validated on finalize.
    pub(crate) expected_crc32c: Option<String>,
    pub(crate) expected_md5: Option<String>,
}

pub(crate) struct MockRewriteState {
    pub(crate) src_name: String,
    pub(crate) dst_name: String,
    pub(crate) template: MockGcsObject,
    pub(crate) steps_remaining: usize,
}

pub(crate) struct MockGcsState {
    pub(crate) base_url: String,
    pub(crate) expected_token: String,
    pub(crate) faults: FaultInjector,
    pub(crate) next_gen: u64,
    pub(crate) objects: BTreeMap<String, MockGcsObject>,
    pub(crate) sessions: HashMap<String, MockResumableSession>,
    pub(crate) rewrite_tokens: HashMap<String, MockRewriteState>,
    pub(crate) rewrite_steps: usize,
    pub(crate) rewrite_force_duplicate_token: bool,
    pub(crate) rewrite_calls: usize,
    pub(crate) delete_calls: usize,
    pub(crate) abort_499_calls: usize,
    pub(crate) seen_upload_metadata: Vec<serde_json::Value>,
    pub(crate) seen_multipart_boundaries: Vec<String>,
    pub(crate) seen_rewrite_bodies: Vec<(String, Vec<u8>)>,
    pub(crate) seen_rewrite_queries: Vec<HashMap<String, String>>,
    pub(crate) seen_user_projects: Vec<(String, String, Option<String>)>,
    pub(crate) seen_download_accept_encoding: Vec<Option<String>>,
    /// When `Some(obj_name)`, queued `GetObjectMeta` faults only fire for `obj_name` (so a
    /// pre-rewrite source GET does not consume a reconcile-lag fault queued for the dst).
    pub(crate) get_meta_fault_only_for: Option<String>,
    pub(crate) corrupt_upload_crc32c_once: bool,
    pub(crate) corrupt_get_meta_crc32c_once: bool,
    pub(crate) corrupt_download_body_once: bool,
    /// Flip one byte of the next resumable chunk as it is stored (in-transit corruption).
    pub(crate) corrupt_next_resumable_chunk: bool,
    /// Return a wrong `crc32c` in the next resumable finalize response (data stored intact).
    pub(crate) corrupt_resumable_final_crc32c_once: bool,
    /// Persist nothing from the next resumable chunk and answer with the session's current
    /// `308`, which carries no `Range` header while nothing has been persisted yet.
    pub(crate) drop_next_resumable_chunk: bool,
    /// `(Content-Range, x-goog-hash)` of every resumable chunk `PUT`, in order.
    pub(crate) resumable_puts: Vec<(String, Option<String>)>,
}

impl MockGcsState {
    fn new(base_url: String) -> Self {
        Self {
            base_url,
            expected_token: "gcs-test-token".to_string(),
            faults: FaultInjector::new(),
            next_gen: 100,
            objects: BTreeMap::new(),
            sessions: HashMap::new(),
            rewrite_tokens: HashMap::new(),
            rewrite_steps: 2,
            rewrite_force_duplicate_token: false,
            rewrite_calls: 0,
            delete_calls: 0,
            abort_499_calls: 0,
            seen_upload_metadata: Vec::new(),
            seen_multipart_boundaries: Vec::new(),
            seen_rewrite_bodies: Vec::new(),
            seen_rewrite_queries: Vec::new(),
            seen_user_projects: Vec::new(),
            seen_download_accept_encoding: Vec::new(),
            get_meta_fault_only_for: None,
            corrupt_upload_crc32c_once: false,
            corrupt_get_meta_crc32c_once: false,
            corrupt_download_body_once: false,
            corrupt_next_resumable_chunk: false,
            corrupt_resumable_final_crc32c_once: false,
            drop_next_resumable_chunk: false,
            resumable_puts: Vec::new(),
        }
    }

    pub(crate) fn alloc_gen(&mut self) -> u64 {
        let g = self.next_gen;
        self.next_gen += 1;
        g
    }

    pub(crate) fn seed_object(&mut self, name: impl Into<String>, data: Vec<u8>) {
        let name = name.into();
        let generation = self.alloc_gen();
        self.objects.insert(
            name.clone(),
            MockGcsObject {
                name,
                data,
                generation,
                ..Default::default()
            },
        );
    }

    fn object_json(obj: &MockGcsObject) -> serde_json::Value {
        let md5_b64 = B64.encode(Md5::digest(&obj.data));
        let crc_bytes = simple_crc32c(&obj.data).to_be_bytes();
        let crc_b64 = B64.encode(crc_bytes);
        let mut val = serde_json::json!({
            "name": obj.name,
            "size": obj.data.len().to_string(),
            "generation": obj.generation.to_string(),
            "etag": format!("\"gen-{}\"", obj.generation),
            "updated": "2026-11-25T02:00:00Z",
            "md5Hash": md5_b64,
            "crc32c": crc_b64,
            "metadata": obj.metadata,
        });
        if let Some(v) = &obj.content_type {
            val["contentType"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = &obj.content_encoding {
            val["contentEncoding"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = &obj.cache_control {
            val["cacheControl"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = &obj.content_disposition {
            val["contentDisposition"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = &obj.content_language {
            val["contentLanguage"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = &obj.custom_time {
            val["customTime"] = serde_json::Value::String(v.clone());
        }
        val
    }
}

pub(crate) fn simple_crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// Real GCS resumable uploads accept non-final chunks only in 256 KiB multiples.
const GCS_MIN_CHUNK: usize = 256 * 1024;

/// Extract the base64 `crc32c=` value from an `x-goog-hash` header.
fn x_goog_hash_crc32c(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-goog-hash")?.to_str().ok()?;
    raw.split(',').find_map(|item| {
        let (k, v) = item.trim().split_once('=')?;
        k.eq_ignore_ascii_case("crc32c")
            .then(|| v.trim().to_string())
    })
}

/// HTTP 400 in the shape GCS uses when an integrity check fails.
fn integrity_mismatch_resp(kind: &str, provided: &str, calculated: &str) -> Response {
    let message =
        format!("Provided {kind} \"{provided}\" doesn't match calculated {kind} \"{calculated}\".");
    json_resp(
        StatusCode::BAD_REQUEST,
        serde_json::json!({
            "error": {
                "code": 400,
                "message": message,
                "errors": [{"message": message, "domain": "global", "reason": "invalid"}],
            }
        }),
    )
}

fn precondition_failed_resp() -> Response {
    json_resp(
        StatusCode::PRECONDITION_FAILED,
        serde_json::json!({"error": {
            "code": 412,
            "message": "At least one of the pre-conditions you specified did not hold.",
            "errors": [{"reason": "conditionNotMet"}]
        }}),
    )
}

fn parse_if_gen_match(query: &HashMap<String, String>, key: &str) -> Option<u64> {
    query.get(key).and_then(|s| s.parse::<u64>().ok())
}

fn check_generation_match(expected: Option<u64>, actual: Option<u64>) -> bool {
    match expected {
        None => true,
        Some(0) => actual.is_none(),
        Some(n) => actual == Some(n),
    }
}

/// Validate `x-goog-hash` and the object-resource `crc32c` / `md5Hash` against `data`, like
/// GCS does when an upload is finalized.
fn check_upload_integrity(
    data: &[u8],
    header_crc32c: Option<&str>,
    meta_crc32c: Option<&str>,
    meta_md5: Option<&str>,
) -> Option<Response> {
    let crc_b64 = B64.encode(simple_crc32c(data).to_be_bytes());
    for provided in [header_crc32c, meta_crc32c].into_iter().flatten() {
        if provided != crc_b64 {
            return Some(integrity_mismatch_resp("CRC32C", provided, &crc_b64));
        }
    }
    if let Some(provided) = meta_md5 {
        let md5_b64 = B64.encode(Md5::digest(data));
        if provided != md5_b64 {
            return Some(integrity_mismatch_resp("MD5 hash", provided, &md5_b64));
        }
    }
    None
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn parse_query(uri: &axum::http::Uri) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(pct_decode(k), pct_decode(v));
            }
        }
    }
    map
}

fn json_resp(status: StatusCode, val: serde_json::Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        serde_json::to_vec(&val).unwrap(),
    )
        .into_response()
}

fn parse_multipart_related(body: &[u8], ct: &str) -> (String, serde_json::Value, Vec<u8>) {
    let boundary = ct
        .split("boundary=")
        .nth(1)
        .unwrap()
        .trim()
        .trim_matches('"')
        .to_string();
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let mut positions = Vec::new();
    let mut i = 0;
    while i + delim_bytes.len() <= body.len() {
        if &body[i..i + delim_bytes.len()] == delim_bytes {
            positions.push(i);
            i += delim_bytes.len();
        } else {
            i += 1;
        }
    }
    assert!(positions.len() >= 3, "invalid multipart/related body");
    let part1 = &body[positions[0] + delim_bytes.len()..positions[1]];
    let p1_hdr_end = part1.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let json_slice = &part1[p1_hdr_end + 4..part1.len().saturating_sub(2)];
    let meta: serde_json::Value = serde_json::from_slice(json_slice).unwrap();

    let part2 = &body[positions[1] + delim_bytes.len()..positions[2]];
    let p2_hdr_end = part2.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let data = part2[p2_hdr_end + 4..part2.len().saturating_sub(2)].to_vec();
    (boundary, meta, data)
}

fn classify_gcs_op(
    method: &Method,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> &'static str {
    if path.starts_with("/upload/session/") {
        if *method == Method::DELETE {
            return "AbortUpload";
        }
        if *method == Method::PUT {
            let cr = headers
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            return if cr == "bytes */*" {
                "QueryUpload"
            } else {
                "UploadChunk"
            };
        }
        return "UploadSession";
    }
    if path == "/upload/storage/v1/b/test-bucket/o" && *method == Method::POST {
        return match query.get("uploadType").map(String::as_str).unwrap_or("") {
            "media" => "UploadMedia",
            "multipart" => "UploadMultipart",
            "resumable" => "BeginResumable",
            _ => "UploadUnknown",
        };
    }
    if let Some(rest) = path.strip_prefix("/storage/v1/b/test-bucket/o/")
        && rest.contains("/rewriteTo/b/test-bucket/o/")
        && *method == Method::POST
    {
        return "RewriteObject";
    }
    if path == "/storage/v1/b/test-bucket/o" && *method == Method::GET {
        return "ListObjects";
    }
    if path.starts_with("/storage/v1/b/test-bucket/o/") {
        if *method == Method::DELETE {
            return "DeleteObject";
        }
        if *method == Method::GET {
            return if query.get("alt").map(String::as_str) == Some("media") {
                "DownloadObject"
            } else {
                "GetObjectMeta"
            };
        }
    }
    "Unknown"
}

async fn handle_gcs(
    State(st): State<Arc<Mutex<MockGcsState>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    let query = parse_query(&uri);
    let op_name = classify_gcs_op(&method, path, &query, &headers);

    let (expected_token, faults, skip_get_meta_fault) = {
        let g = st.lock().unwrap();
        let skip = if op_name == "GetObjectMeta"
            && let Some(ref target) = g.get_meta_fault_only_for
        {
            let obj_name = path
                .strip_prefix("/storage/v1/b/test-bucket/o/")
                .map(pct_decode)
                .unwrap_or_default();
            obj_name != *target
        } else {
            false
        };
        (g.expected_token.clone(), g.faults.clone(), skip)
    };
    let expected_auth = format!("Bearer {expected_token}");
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected_auth.as_str()) {
        return json_resp(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "unauthorized"}),
        );
    }

    if !path.starts_with("/upload/session/") {
        st.lock().unwrap().seen_user_projects.push((
            method.to_string(),
            path.to_string(),
            query.get("userProject").cloned(),
        ));
    }

    let post_commit_fault = if skip_get_meta_fault {
        None
    } else if let Some(fault) = faults.next_fault(op_name) {
        match fault {
            InjectedFault::SlowFinalize { delay } => {
                tokio::time::sleep(delay).await;
                None
            }
            InjectedFault::MidBodyReset { prefix }
                if op_name == "DownloadObject" && headers.contains_key(http::header::RANGE) =>
            {
                return build_mid_body_reset_response_with_status(
                    StatusCode::PARTIAL_CONTENT,
                    prefix,
                );
            }
            other => match other.into_pre_commit_response() {
                Ok(resp) => return resp,
                Err(post) => Some(post),
            },
        }
    } else {
        None
    };

    let resp = execute_gcs_request(&st, method, path, &query, &headers, body);
    if let Some(post) = post_commit_fault
        && resp.status().is_success()
        && let Some(fault_resp) = post.into_post_commit_response()
    {
        return fault_resp;
    }
    resp
}

fn execute_gcs_request(
    st: &Arc<Mutex<MockGcsState>>,
    method: Method,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Resumable upload session PUT / DELETE
    if let Some(sid) = path.strip_prefix("/upload/session/") {
        let mut g = st.lock().unwrap();
        if method == Method::DELETE {
            g.sessions.remove(sid);
            g.abort_499_calls += 1;
            return StatusCode::from_u16(499).unwrap().into_response();
        }
        if method == Method::PUT {
            let cr = headers
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let Some(sess) = g.sessions.get_mut(sid) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if let Some(done_obj) = &sess.completed {
                return json_resp(StatusCode::OK, MockGcsState::object_json(done_obj));
            }
            if cr == "bytes */*" {
                if sess.buf.is_empty() {
                    return StatusCode::from_u16(308).unwrap().into_response();
                }
                let rng = format!("bytes=0-{}", sess.buf.len() - 1);
                return (
                    StatusCode::from_u16(308).unwrap(),
                    [("range", rng)],
                    Vec::<u8>::new(),
                )
                    .into_response();
            }

            let header_crc32c = x_goog_hash_crc32c(headers);
            let (start, total, is_zero_finalize) =
                if let Some(total_part) = cr.strip_prefix("bytes */") {
                    let total: u64 = total_part.parse().unwrap();
                    assert_eq!(
                        total, 0,
                        "bytes */{total} is only valid for 0-byte finalize"
                    );
                    (0usize, 0u64, true)
                } else {
                    // Parse `bytes start-end/total`
                    let spec = cr.strip_prefix("bytes ").unwrap();
                    let (range_part, total_part) = spec.split_once('/').unwrap();
                    let (start_s, _end_s) = range_part.split_once('-').unwrap();
                    let start: usize = start_s.parse().unwrap();
                    let total: u64 = total_part.parse().unwrap();
                    (start, total, false)
                };

            let dropped = std::mem::take(&mut g.drop_next_resumable_chunk);
            let sess = g.sessions.get_mut(sid).unwrap();
            if dropped || (!is_zero_finalize && start != sess.buf.len()) {
                if sess.buf.is_empty() {
                    return StatusCode::from_u16(308).unwrap().into_response();
                }
                let rng = format!("bytes=0-{}", sess.buf.len() - 1);
                return (
                    StatusCode::from_u16(308).unwrap(),
                    [("range", rng)],
                    Vec::<u8>::new(),
                )
                    .into_response();
            }

            let is_final = is_zero_finalize || (start + body.len()) as u64 >= total;
            let mut data = body.to_vec();
            if !is_final {
                // GCS rejects short non-final chunks and persists only whole 256 KiB units.
                if data.len() < GCS_MIN_CHUNK {
                    return json_resp(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": {"code": 400, "message": "Invalid request. The number of bytes uploaded is required to be equal or greater than 262144, except for the final request (it's recommended to be the exact multiple of 262144)."}}),
                    );
                }
                data.truncate(data.len() / GCS_MIN_CHUNK * GCS_MIN_CHUNK);
            }
            let corrupt = std::mem::take(&mut g.corrupt_next_resumable_chunk);
            g.resumable_puts
                .push((cr.to_string(), header_crc32c.clone()));
            let sess = g.sessions.get_mut(sid).unwrap();
            if corrupt && let Some(b) = data.first_mut() {
                *b ^= 0xFF;
            }
            sess.buf.extend_from_slice(&data);
            if is_zero_finalize || sess.buf.len() as u64 >= total {
                if let Some(resp) = check_upload_integrity(
                    &sess.buf,
                    header_crc32c.as_deref(),
                    sess.expected_crc32c.as_deref(),
                    sess.expected_md5.as_deref(),
                ) {
                    // A failed integrity check ends the session; the client must start over.
                    g.sessions.remove(sid);
                    return resp;
                }
                let name = sess.name.clone();
                let meta = sess.metadata.clone();
                let data = sess.buf.clone();
                let if_gen_match = sess.if_gen_match;
                let existing_gen = g.objects.get(&name).map(|o| o.generation);
                if !check_generation_match(if_gen_match, existing_gen) {
                    return precondition_failed_resp();
                }
                let gen_id = g.alloc_gen();
                let obj = MockGcsObject {
                    name: name.clone(),
                    data,
                    generation: gen_id,
                    metadata: meta,
                    ..Default::default()
                };
                g.objects.insert(name, obj.clone());
                g.sessions.get_mut(sid).unwrap().completed = Some(obj.clone());
                let mut obj_json = MockGcsState::object_json(&obj);
                if std::mem::take(&mut g.corrupt_resumable_final_crc32c_once) {
                    obj_json["crc32c"] =
                        serde_json::Value::String(B64.encode([0xDE, 0xAD, 0xBE, 0xEF]));
                }
                return json_resp(StatusCode::OK, obj_json);
            }
            let rng = format!("bytes=0-{}", sess.buf.len() - 1);
            return (
                StatusCode::from_u16(308).unwrap(),
                [("range", rng)],
                Vec::<u8>::new(),
            )
                .into_response();
        }
    }

    // 2. Upload endpoints (`/upload/storage/v1/b/{bucket}/o`)
    if path == "/upload/storage/v1/b/test-bucket/o" && method == Method::POST {
        let upload_type = query.get("uploadType").map(String::as_str).unwrap_or("");
        let if_gen_match = parse_if_gen_match(query, "ifGenerationMatch");
        let mut g = st.lock().unwrap();

        match upload_type {
            "media" => {
                let name = query.get("name").cloned().unwrap();
                let existing_gen = g.objects.get(&name).map(|o| o.generation);
                if !check_generation_match(if_gen_match, existing_gen) {
                    return precondition_failed_resp();
                }
                let gen_id = g.alloc_gen();
                let obj = MockGcsObject {
                    name: name.clone(),
                    data: body.to_vec(),
                    generation: gen_id,
                    ..Default::default()
                };
                g.objects.insert(name, obj.clone());
                return json_resp(StatusCode::OK, MockGcsState::object_json(&obj));
            }
            "multipart" => {
                let ct = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let (boundary, meta_json, data) = parse_multipart_related(&body, ct);
                g.seen_multipart_boundaries.push(boundary);
                g.seen_upload_metadata.push(meta_json.clone());
                if let Some(resp) = check_upload_integrity(
                    &data,
                    None,
                    meta_json["crc32c"].as_str(),
                    meta_json["md5Hash"].as_str(),
                ) {
                    return resp;
                }
                let name = meta_json["name"].as_str().unwrap().to_string();
                let existing_gen = g.objects.get(&name).map(|o| o.generation);
                if !check_generation_match(if_gen_match, existing_gen) {
                    return precondition_failed_resp();
                }
                let metadata: BTreeMap<String, String> = meta_json
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default();
                let gen_id = g.alloc_gen();
                let obj = MockGcsObject {
                    name: name.clone(),
                    data,
                    generation: gen_id,
                    metadata,
                    ..Default::default()
                };
                g.objects.insert(name, obj.clone());
                let mut obj_json = MockGcsState::object_json(&obj);
                if g.corrupt_upload_crc32c_once {
                    g.corrupt_upload_crc32c_once = false;
                    obj_json["crc32c"] =
                        serde_json::Value::String(B64.encode([0xDE, 0xAD, 0xBE, 0xEF]));
                }
                return json_resp(StatusCode::OK, obj_json);
            }
            "resumable" => {
                let meta_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                g.seen_upload_metadata.push(meta_json.clone());
                let name = meta_json["name"].as_str().unwrap().to_string();
                let existing_gen = g.objects.get(&name).map(|o| o.generation);
                if !check_generation_match(if_gen_match, existing_gen) {
                    return precondition_failed_resp();
                }
                let metadata: BTreeMap<String, String> = meta_json
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default();
                let sid = format!("sess-{}", g.alloc_gen());
                let loc = format!("{}/upload/session/{sid}", g.base_url);
                g.sessions.insert(
                    sid,
                    MockResumableSession {
                        name,
                        metadata,
                        if_gen_match,
                        buf: Vec::new(),
                        completed: None,
                        expected_crc32c: meta_json["crc32c"].as_str().map(str::to_string),
                        expected_md5: meta_json["md5Hash"].as_str().map(str::to_string),
                    },
                );
                return (StatusCode::OK, [("location", loc)], Vec::<u8>::new()).into_response();
            }
            _ => return StatusCode::BAD_REQUEST.into_response(),
        }
    }

    // 3. RewriteTo server-side copy (`/storage/v1/b/{src_b}/o/{src_o}/rewriteTo/b/{dst_b}/o/{dst_o}`)
    if let Some(rest) = path.strip_prefix("/storage/v1/b/test-bucket/o/")
        && let Some((src_enc, dst_part)) = rest.split_once("/rewriteTo/b/test-bucket/o/")
        && method == Method::POST
    {
        // Enforce single-segment encoding (no unencoded `/` in either object name)!
        assert!(!src_enc.contains('/'), "unencoded slash in rewrite src");
        assert!(!dst_part.contains('/'), "unencoded slash in rewrite dst");
        let src_name = pct_decode(src_enc);
        let dst_name = pct_decode(dst_part);
        let mut g = st.lock().unwrap();
        g.rewrite_calls += 1;
        g.seen_rewrite_bodies
            .push((path.to_string(), body.to_vec()));
        g.seen_rewrite_queries.push(query.clone());

        // Preconditions are evaluated against destination and source on every rewrite call.
        let if_gen_match = parse_if_gen_match(query, "ifGenerationMatch");
        let dst_gen = g.objects.get(&dst_name).map(|o| o.generation);
        if !check_generation_match(if_gen_match, dst_gen) {
            return precondition_failed_resp();
        }
        let if_src_gen_match = parse_if_gen_match(query, "ifSourceGenerationMatch");
        let src_gen = g.objects.get(&src_name).map(|o| o.generation);
        if !check_generation_match(if_src_gen_match, src_gen) {
            return precondition_failed_resp();
        }

        if let Some(tok) = query.get("rewriteToken") {
            let Some(mut rw_state) = g.rewrite_tokens.remove(tok) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(src_obj) = g.objects.get(&rw_state.src_name).cloned() else {
                return StatusCode::NOT_FOUND.into_response();
            };
            rw_state.steps_remaining = rw_state.steps_remaining.saturating_sub(1);
            if rw_state.steps_remaining > 0 {
                let next_tok = if g.rewrite_force_duplicate_token {
                    tok.clone()
                } else {
                    format!("rw-tok-{}", g.alloc_gen())
                };
                g.rewrite_tokens.insert(next_tok.clone(), rw_state);
                return json_resp(
                    StatusCode::OK,
                    serde_json::json!({"done": false, "rewriteToken": next_tok}),
                );
            }
            let gen_id = g.alloc_gen();
            let mut copied = rw_state.template;
            copied.name = rw_state.dst_name.clone();
            copied.data = src_obj.data;
            copied.generation = gen_id;
            g.objects.insert(rw_state.dst_name, copied.clone());
            return json_resp(
                StatusCode::OK,
                serde_json::json!({
                    "done": true,
                    "resource": MockGcsState::object_json(&copied)
                }),
            );
        }

        let Some(src_obj) = g.objects.get(&src_name).cloned() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let mut template = src_obj.clone();
        if !body.is_empty() {
            let meta_json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if let Some(m) = meta_json.get("metadata") {
                template.metadata = serde_json::from_value(m.clone()).unwrap_or_default();
            }
            template.content_type = meta_json
                .get("contentType")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.content_type);
            template.content_encoding = meta_json
                .get("contentEncoding")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.content_encoding);
            template.cache_control = meta_json
                .get("cacheControl")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.cache_control);
            template.content_disposition = meta_json
                .get("contentDisposition")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.content_disposition);
            template.content_language = meta_json
                .get("contentLanguage")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.content_language);
            template.custom_time = meta_json
                .get("customTime")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or(template.custom_time);
        }

        let steps = g.rewrite_steps.max(1);
        if steps == 1 {
            let gen_id = g.alloc_gen();
            let mut copied = template;
            copied.name = dst_name.clone();
            copied.generation = gen_id;
            g.objects.insert(dst_name, copied.clone());
            return json_resp(
                StatusCode::OK,
                serde_json::json!({
                    "done": true,
                    "resource": MockGcsState::object_json(&copied)
                }),
            );
        }

        let tok = format!("rw-tok-{}", g.alloc_gen());
        g.rewrite_tokens.insert(
            tok.clone(),
            MockRewriteState {
                src_name,
                dst_name,
                template,
                steps_remaining: steps - 1,
            },
        );
        return json_resp(
            StatusCode::OK,
            serde_json::json!({"done": false, "rewriteToken": tok}),
        );
    }

    // 4. List objects (`/storage/v1/b/test-bucket/o`)
    if path == "/storage/v1/b/test-bucket/o" && method == Method::GET {
        let pfx = query.get("prefix").cloned().unwrap_or_default();
        let delim = query.get("delimiter").cloned();
        let start_offset = query.get("startOffset").cloned();
        let max_results = query
            .get("maxResults")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1000);
        let start_idx = query
            .get("pageToken")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let g = st.lock().unwrap();
        let mut all_items = Vec::new();
        let mut prefixes_set = std::collections::BTreeSet::new();

        for obj in g.objects.values() {
            if !obj.name.starts_with(&pfx) {
                continue;
            }
            if let Some(ref so) = start_offset
                && obj.name.as_str() < so.as_str()
            {
                continue;
            }
            let rest = &obj.name[pfx.len()..];
            if let Some(ref d) = delim
                && let Some(pos) = rest.find(d.as_str())
            {
                prefixes_set.insert(format!("{}{}", pfx, &rest[..=pos]));
                continue;
            }
            all_items.push(MockGcsState::object_json(obj));
        }

        // Page with size 2 when maxResults > 1 to exercise `nextPageToken`!
        let page_sz = if max_results == 1 { 1 } else { 2 };
        let end = (start_idx + page_sz).min(all_items.len());
        let page_items = if start_idx < all_items.len() {
            all_items[start_idx..end].to_vec()
        } else {
            Vec::new()
        };
        let next_tok = (end < all_items.len()).then(|| end.to_string());
        let mut resp = serde_json::json!({
            "items": page_items,
            "prefixes": if start_idx == 0 { prefixes_set.into_iter().collect::<Vec<_>>() } else { vec![] },
        });
        if let Some(nt) = next_tok {
            resp["nextPageToken"] = serde_json::Value::String(nt);
        }
        return json_resp(StatusCode::OK, resp);
    }

    // 5. Object metadata / download / delete (`/storage/v1/b/test-bucket/o/{encoded}`)
    if let Some(enc) = path.strip_prefix("/storage/v1/b/test-bucket/o/") {
        assert!(
            !enc.contains('/'),
            "GCS object segment must percent-encode `/`: got `{enc}`"
        );
        let name = pct_decode(enc);
        let mut g = st.lock().unwrap();

        if method == Method::DELETE {
            g.delete_calls += 1;
            return if g.objects.remove(&name).is_some() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            };
        }
        if method == Method::GET {
            let Some(obj) = g.objects.get(&name).cloned() else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if let Some(req_gen) = query.get("generation")
                && req_gen != &obj.generation.to_string()
            {
                return StatusCode::NOT_FOUND.into_response();
            }
            if query.get("alt").map(String::as_str) == Some("media") {
                let accept_enc = headers
                    .get("accept-encoding")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                g.seen_download_accept_encoding.push(accept_enc.clone());

                if obj.content_encoding.as_deref() == Some("gzip")
                    && !accept_enc
                        .as_deref()
                        .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"))
                {
                    // Simulate GCS decompressive transcoding when Accept-Encoding: gzip is omitted.
                    let plain = obj
                        .gzip_uncompressed
                        .clone()
                        .unwrap_or_else(|| b"decompressed".to_vec());
                    return (StatusCode::OK, plain).into_response();
                }

                let corrupt_body = std::mem::take(&mut g.corrupt_download_body_once);
                let crc_b64 = B64.encode(simple_crc32c(&obj.data).to_be_bytes());
                let md5_b64 = B64.encode(Md5::digest(&obj.data));
                let goog_hash = format!("crc32c={crc_b64}, md5={md5_b64}");
                if let Some(range_hdr) = headers.get("range").and_then(|v| v.to_str().ok())
                    && let Some(spec) = range_hdr.strip_prefix("bytes=")
                    && let Some((s, e)) = spec.split_once('-')
                {
                    let start: usize = s.parse().unwrap_or(0);
                    let end: usize = e.parse().unwrap_or(obj.data.len().saturating_sub(1));
                    let mut slice = obj.data[start..=end.min(obj.data.len() - 1)].to_vec();
                    if corrupt_body && let Some(last) = slice.last_mut() {
                        *last ^= 0xFF;
                    }
                    let mut resp_hdrs = HeaderMap::new();
                    resp_hdrs.insert("x-goog-hash", goog_hash.parse().unwrap());
                    if let Some(ce) = &obj.content_encoding {
                        resp_hdrs.insert("content-encoding", ce.parse().unwrap());
                    }
                    return (StatusCode::PARTIAL_CONTENT, resp_hdrs, slice).into_response();
                }
                let mut full = obj.data.clone();
                if corrupt_body && let Some(last) = full.last_mut() {
                    *last ^= 0xFF;
                }
                return (StatusCode::OK, [("x-goog-hash", goog_hash)], full).into_response();
            }
            let mut obj_json = MockGcsState::object_json(&obj);
            if std::mem::take(&mut g.corrupt_get_meta_crc32c_once) {
                obj_json["crc32c"] =
                    serde_json::Value::String(B64.encode([0xDE, 0xAD, 0xBE, 0xEF]));
            }
            return json_resp(StatusCode::OK, obj_json);
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

pub(crate) async fn spawn_mock_gcs() -> (String, Arc<Mutex<MockGcsState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(Mutex::new(MockGcsState::new(base_url.clone())));
    let app = Router::new().fallback(handle_gcs).with_state(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, state)
}

pub(crate) fn make_backend(base_url: &str) -> Arc<GcsBackend> {
    make_backend_with_config(base_url, |_| {})
}

pub(crate) fn make_backend_with_config(
    base_url: &str,
    configure: impl FnOnce(&mut GcsConfig),
) -> Arc<GcsBackend> {
    let mut cfg = GcsConfig::new("gcs-test", "test-bucket");
    cfg.api_base_url = format!("{base_url}/storage/v1");
    cfg.upload_base_url = format!("{base_url}/upload/storage/v1");
    cfg.chunk_size = GCS_CHUNK_ALIGN_BYTES;
    configure(&mut cfg);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    Arc::new(GcsBackend::new(cfg, auth, transport).unwrap())
}
