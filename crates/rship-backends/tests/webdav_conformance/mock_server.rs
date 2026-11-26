use crate::common::{FaultInjector, InjectedFault, build_mid_body_reset_response_with_status};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

pub(crate) type ScriptedResponse = (String, StatusCode, Vec<(String, String)>, String);

#[derive(Default)]
pub(crate) struct MockDavState {
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    pub(crate) mtimes: BTreeMap<String, i64>,
    pub(crate) dirs: BTreeSet<String>,
    pub(crate) copy_calls: usize,
    pub(crate) get_calls: usize,
    pub(crate) put_calls: usize,
    pub(crate) faults: FaultInjector,
    /// `OC-Checksum` stored per file. A `PUT` without the header clears it (Nextcloud).
    pub(crate) checksums: BTreeMap<String, String>,
    /// Answer `X-Hash: md5` on `PUT` with `X-Hash-MD5` computed over the stored bytes
    /// (Nextcloud). Off emulates ownCloud and older Nextcloud releases.
    pub(crate) x_hash_supported: bool,
    /// Reject a `PUT`/`MOVE .file` whose `OC-Checksum` MD5/SHA1 does not match (ownCloud).
    pub(crate) validate_oc_checksum: bool,
    /// Flip one byte of the next `PUT` body before it is stored (in-transit corruption).
    pub(crate) corrupt_next_put: bool,
    /// Flip one byte of the next `GET` response body.
    pub(crate) corrupt_download_body_once: bool,
    /// `(path, X-Hash, OC-Checksum)` request headers of every `PUT` and `MOVE .file`.
    pub(crate) checksum_headers_seen: Vec<(String, Option<String>, Option<String>)>,
    /// Full request telemetry `(method, raw_uri_path, headers)` for protocol assertions.
    pub(crate) requests_seen: Vec<(String, String, HeaderMap)>,
    /// Per-file write version. Real servers change `getetag` on EVERY write (Nextcloud uses a
    /// random id, Apache inode-size-mtime), so two same-size files never share an ETag.
    pub(crate) etag_versions: BTreeMap<String, u64>,
    pub(crate) next_etag_version: u64,
    /// Strict Nginx-style trailing-slash check for `MKCOL`, dir `PROPFIND`, and dir `DELETE`.
    pub(crate) require_trailing_slash: bool,
    /// When true, `PUT` fails with `409 Conflict` if the parent directory is missing.
    pub(crate) enforce_parent_dir_on_put: bool,
    /// When true, `PUT`/`MOVE .file` ignore `X-OC-Mtime` and do not emit `X-OC-Mtime: accepted`.
    pub(crate) ignore_x_oc_mtime: bool,
    /// When true, `PROPFIND` omits `<d:getetag>` so mtime-tolerance reconciliation paths can be tested.
    pub(crate) omit_etag: bool,
    /// One-shot scripted responses keyed by `op_name`: `(op_name, status, headers, body)`.
    pub(crate) scripted_responses: VecDeque<ScriptedResponse>,
    /// Extra `<response>` entries injected into `PROPFIND` Depth:1 for a directory path.
    pub(crate) extra_propfind_entries: BTreeMap<String, Vec<(String, bool, usize)>>,
}

fn format_http_date(secs: i64) -> String {
    rship_core::time::format_http_date(secs)
}

impl MockDavState {
    /// Strong ETag of `path`: a fresh value per write. Files seeded directly into `files` by
    /// a test (never written through the mock) get a content-derived ETag.
    pub(crate) fn etag_of(&self, path: &str) -> String {
        match self.etag_versions.get(path) {
            Some(v) => format!("\"w{v}\""),
            None => {
                use md5::{Digest as _, Md5};
                let data = self.files.get(path).map(Vec::as_slice).unwrap_or_default();
                format!("\"seed-{}\"", hex::encode(Md5::digest(data)))
            }
        }
    }

    /// Record a write to `path` (PUT, COPY/MOVE destination, chunk assembly).
    pub(crate) fn bump_etag(&mut self, path: &str) {
        self.next_etag_version += 1;
        self.etag_versions
            .insert(path.to_string(), self.next_etag_version);
    }

    pub(crate) fn new() -> Self {
        let mut s = Self::default();
        s.dirs.insert("/remote.php/dav/files/alice".to_string());
        s.dirs.insert("/remote.php/dav/uploads/alice".to_string());
        s.x_hash_supported = true;
        s
    }
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest as _, Md5};
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sha1_hex(data: &[u8]) -> String {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    state.iter().map(|w| format!("{w:08x}")).collect()
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// ownCloud's response to an `OC-Checksum` that does not match the received bytes.
fn checksum_mismatch_resp() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/xml; charset=utf-8")],
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:error xmlns:d=\"DAV:\" xmlns:s=\"http://sabredav.org/ns\"><s:exception>Sabre\\DAV\\Exception\\BadRequest</s:exception><s:message>The computed checksum does not match the one received from the client.</s:message></d:error>",
    )
        .into_response()
}

/// Whether `oc_checksum` (`MD5:<hex>` or `SHA1:<hex>`) disagrees with `data`.
fn oc_checksum_mismatch(oc_checksum: Option<&str>, data: &[u8]) -> bool {
    let Some(raw) = oc_checksum else {
        return false;
    };
    for item in raw.split([' ', ',']) {
        let Some((kind, hex)) = item.trim().split_once(':') else {
            continue;
        };
        let hex = hex.trim().to_ascii_lowercase();
        if kind.eq_ignore_ascii_case("MD5") && hex != md5_hex(data) {
            return true;
        }
        if kind.eq_ignore_ascii_case("SHA1") && hex != sha1_hex(data) {
            return true;
        }
    }
    false
}

fn decode_path(p: &str) -> String {
    let bytes = p.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&p[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| p.to_string())
}

fn encode_href(p: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in p.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
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

fn classify_dav_op(method: &Method, path: &str) -> &'static str {
    match method.as_str() {
        "PROPFIND" => "PROPFIND",
        "MKCOL" => "MKCOL",
        "PUT" => "PUT",
        "GET" => "GET",
        "DELETE" => "DELETE",
        "COPY" => "COPY",
        "MOVE" if path.ends_with("/.file") => "MOVE_ASSEMBLE",
        "MOVE" => "MOVE",
        _ => "OTHER",
    }
}

pub(crate) async fn handle_dav(
    State(st): State<Arc<Mutex<MockDavState>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw_uri_path = uri.path().to_string();
    let has_trailing_slash = raw_uri_path.ends_with('/');
    let path = decode_path(&raw_uri_path).trim_end_matches('/').to_string();
    let op_name = classify_dav_op(&method, &path);
    let faults = {
        let mut g = st.lock().unwrap();
        g.requests_seen
            .push((method.as_str().to_string(), raw_uri_path, headers.clone()));
        if let Some(pos) = g
            .scripted_responses
            .iter()
            .position(|(op, _, _, _)| op == op_name)
        {
            let (_, status, hdrs, resp_body) = g.scripted_responses.remove(pos).unwrap();
            let mut resp = (status, resp_body).into_response();
            for (k, v) in hdrs {
                if let (Ok(hn), Ok(hv)) = (
                    axum::http::HeaderName::from_bytes(k.as_bytes()),
                    axum::http::HeaderValue::from_str(&v),
                ) {
                    resp.headers_mut().insert(hn, hv);
                }
            }
            return resp;
        }
        g.faults.clone()
    };

    let post_commit_fault = if let Some(fault) = faults.next_fault(op_name) {
        match fault {
            InjectedFault::SlowFinalize { delay } => {
                tokio::time::sleep(delay).await;
                None
            }
            InjectedFault::MidBodyReset { prefix }
                if op_name == "GET" && headers.contains_key(axum::http::header::RANGE) =>
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

    let normal_resp = {
        let mut g = st.lock().unwrap();

        match method.as_str() {
            "PROPFIND" => {
                let depth = headers
                    .get("depth")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("0");
                let is_file = g.files.contains_key(&path);
                let is_dir = g.dirs.contains(&path);
                if g.require_trailing_slash && is_dir && !has_trailing_slash {
                    return StatusCode::CONFLICT.into_response();
                }
                if !is_file && !is_dir {
                    StatusCode::NOT_FOUND.into_response()
                } else {
                    let mut xml = String::from(
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
                    );
                    let push_item = |xml: &mut String,
                                     href: &str,
                                     dir: bool,
                                     len: usize,
                                     mtime_s: Option<i64>,
                                     etag: Option<&str>| {
                        let rt = if dir { "<d:collection/>" } else { "" };
                        let lm = mtime_s
                            .map(format_http_date)
                            .unwrap_or_else(|| "Tue, 24 Nov 2026 12:00:00 GMT".to_string());
                        let etag_tag = etag
                            .map(|e| format!("<d:getetag>{e}</d:getetag>"))
                            .unwrap_or_default();
                        xml.push_str(&format!(
                            "<d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype>{rt}</d:resourcetype><d:getcontentlength>{len}</d:getcontentlength><d:getlastmodified>{lm}</d:getlastmodified>{etag_tag}<d:quota-available-bytes>8000000</d:quota-available-bytes><d:quota-used-bytes>2000000</d:quota-used-bytes></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                            encode_href(href)
                        ));
                    };

                    if is_file {
                        let etag = (!g.omit_etag).then(|| g.etag_of(&path));
                        push_item(
                            &mut xml,
                            &path,
                            false,
                            g.files[&path].len(),
                            g.mtimes.get(&path).copied(),
                            etag.as_deref(),
                        );
                    } else {
                        let dir_etag = (!g.omit_etag).then_some("\"dir\"");
                        push_item(&mut xml, &format!("{path}/"), true, 0, None, dir_etag);
                        if depth == "1" {
                            let prefix = format!("{path}/");
                            for d in g.dirs.iter() {
                                if let Some(rest) = d.strip_prefix(&prefix)
                                    && !rest.is_empty()
                                    && !rest.contains('/')
                                {
                                    push_item(&mut xml, &format!("{d}/"), true, 0, None, dir_etag);
                                }
                            }
                            for (f, data) in g.files.iter() {
                                if let Some(rest) = f.strip_prefix(&prefix)
                                    && !rest.is_empty()
                                    && !rest.contains('/')
                                {
                                    let etag = (!g.omit_etag).then(|| g.etag_of(f));
                                    push_item(
                                        &mut xml,
                                        f,
                                        false,
                                        data.len(),
                                        g.mtimes.get(f).copied(),
                                        etag.as_deref(),
                                    );
                                }
                            }
                            if let Some(extras) = g.extra_propfind_entries.get(&path) {
                                for (href, is_col, len) in extras {
                                    let etag = (!g.omit_etag).then_some("\"extra\"");
                                    push_item(&mut xml, href, *is_col, *len, None, etag);
                                }
                            }
                        }
                    }
                    xml.push_str("</d:multistatus>");
                    (
                        StatusCode::MULTI_STATUS,
                        [("content-type", "application/xml")],
                        xml,
                    )
                        .into_response()
                }
            }
            "MKCOL" => {
                if g.require_trailing_slash && !has_trailing_slash {
                    StatusCode::CONFLICT.into_response()
                } else if g.dirs.contains(&path) || g.files.contains_key(&path) {
                    StatusCode::METHOD_NOT_ALLOWED.into_response()
                } else {
                    g.dirs.insert(path);
                    StatusCode::CREATED.into_response()
                }
            }
            "PUT" => {
                g.put_calls += 1;
                if let Some(cl) = headers
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<usize>().ok())
                    && body.len() != cl
                {
                    StatusCode::BAD_REQUEST.into_response()
                } else if g.enforce_parent_dir_on_put
                    && let Some((parent, _)) = path.rsplit_once('/')
                    && !parent.is_empty()
                    && !g.dirs.contains(parent)
                {
                    StatusCode::CONFLICT.into_response()
                } else {
                    // Auto-register parent dir if missing unless `enforce_parent_dir_on_put` is enabled.
                    if let Some((parent, _)) = path.rsplit_once('/') {
                        g.dirs.insert(parent.to_string());
                    }
                    let x_hash = header_str(&headers, "x-hash");
                    let oc_checksum = header_str(&headers, "oc-checksum");
                    g.checksum_headers_seen.push((
                        path.clone(),
                        x_hash.clone(),
                        oc_checksum.clone(),
                    ));
                    let mut data = body.to_vec();
                    if std::mem::take(&mut g.corrupt_next_put)
                        && let Some(b) = data.first_mut()
                    {
                        *b ^= 0xFF;
                    }
                    if g.validate_oc_checksum && oc_checksum_mismatch(oc_checksum.as_deref(), &data)
                    {
                        return checksum_mismatch_resp();
                    }
                    let mut accepted_oc_mtime = false;
                    if !g.ignore_x_oc_mtime
                        && let Some(mtime_s) = headers
                            .get("x-oc-mtime")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<i64>().ok())
                    {
                        g.mtimes.insert(path.clone(), mtime_s);
                        accepted_oc_mtime = true;
                    }
                    match oc_checksum {
                        Some(ck) => g.checksums.insert(path.clone(), ck),
                        None => g.checksums.remove(&path),
                    };
                    let hash_md5 = (g.x_hash_supported
                        && x_hash.is_some_and(|h| h.eq_ignore_ascii_case("md5")))
                    .then(|| md5_hex(&data));
                    g.files.insert(path.clone(), data);
                    g.bump_etag(&path);
                    let etag = g.etag_of(&path);
                    let mut resp = (StatusCode::CREATED, [("etag", etag)]).into_response();
                    if accepted_oc_mtime {
                        resp.headers_mut()
                            .insert("x-oc-mtime", "accepted".parse().unwrap());
                    }
                    if let Some(md5) = hash_md5 {
                        resp.headers_mut()
                            .insert("x-hash-md5", md5.parse().unwrap());
                    }
                    resp
                }
            }
            "GET" => {
                g.get_calls += 1;
                let corrupt = std::mem::take(&mut g.corrupt_download_body_once);
                let oc_checksum = g.checksums.get(&path).cloned();
                if let Some(data) = g.files.get(&path) {
                    let (status, mut out) = if let Some(rng) = headers
                        .get(axum::http::header::RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.strip_prefix("bytes="))
                        && let Some((a, b)) = rng.split_once('-')
                    {
                        let start: usize = a.parse().unwrap_or(0);
                        let end: usize = b.parse().unwrap_or(data.len().saturating_sub(1));
                        let slice = data[start..=end.min(data.len().saturating_sub(1))].to_vec();
                        (StatusCode::PARTIAL_CONTENT, slice)
                    } else {
                        (StatusCode::OK, data.clone())
                    };
                    if corrupt && let Some(b) = out.last_mut() {
                        *b ^= 0xFF;
                    }
                    let mut resp = if out.len() > 65_536 {
                        let total_len = out.len();
                        let chunks: Vec<std::result::Result<Bytes, std::io::Error>> = out
                            .chunks(32_768)
                            .map(|c| Ok(Bytes::copy_from_slice(c)))
                            .collect();
                        let mut r = Response::new(axum::body::Body::from_stream(
                            futures::stream::iter(chunks),
                        ));
                        *r.status_mut() = status;
                        r.headers_mut().insert(
                            axum::http::header::CONTENT_LENGTH,
                            total_len.to_string().parse().unwrap(),
                        );
                        r
                    } else {
                        (status, out).into_response()
                    };
                    // Nextcloud/ownCloud report the stored checksum on every GET.
                    if let Some(ck) = oc_checksum {
                        resp.headers_mut()
                            .insert("oc-checksum", ck.parse().unwrap());
                    }
                    resp
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
            "DELETE" => {
                if g.require_trailing_slash && g.dirs.contains(&path) && !has_trailing_slash {
                    return StatusCode::CONFLICT.into_response();
                }
                let removed_file = g.files.remove(&path).is_some();
                let removed_dir = g.dirs.remove(&path);
                g.mtimes.remove(&path);
                g.checksums.remove(&path);
                g.etag_versions.remove(&path);
                let prefix = format!("{path}/");
                g.files.retain(|k, _| !k.starts_with(&prefix));
                g.dirs.retain(|k| !k.starts_with(&prefix));
                g.mtimes.retain(|k, _| !k.starts_with(&prefix));
                if removed_file || removed_dir {
                    StatusCode::NO_CONTENT.into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
            "COPY" => {
                g.copy_calls += 1;
                let Some(dst_hdr) = headers.get("destination").and_then(|v| v.to_str().ok()) else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let dst_url = url::Url::parse(dst_hdr).unwrap();
                let dst_path = decode_path(dst_url.path())
                    .trim_end_matches('/')
                    .to_string();
                // RFC 4918 9.8: `Overwrite: F` with an existing destination is 412; otherwise
                // 201 Created for a new resource and 204 No Content when one was replaced.
                let overwrite = headers
                    .get("overwrite")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("T");
                let dst_exists = g.files.contains_key(&dst_path) || g.dirs.contains(&dst_path);
                if overwrite.eq_ignore_ascii_case("F") && dst_exists {
                    StatusCode::PRECONDITION_FAILED.into_response()
                } else if let Some(data) = g.files.get(&path).cloned() {
                    if let Some((parent, _)) = dst_path.rsplit_once('/') {
                        g.dirs.insert(parent.to_string());
                    }
                    if let Some(&mt) = g.mtimes.get(&path) {
                        g.mtimes.insert(dst_path.clone(), mt);
                    }
                    g.files.insert(dst_path.clone(), data);
                    g.bump_etag(&dst_path);
                    if dst_exists {
                        StatusCode::NO_CONTENT.into_response()
                    } else {
                        StatusCode::CREATED.into_response()
                    }
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
            "MOVE" => {
                let Some(dst_hdr) = headers.get("destination").and_then(|v| v.to_str().ok()) else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let dst_url = url::Url::parse(dst_hdr).unwrap();
                let dst_path = decode_path(dst_url.path())
                    .trim_end_matches('/')
                    .to_string();
                let overwrite = headers
                    .get("overwrite")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("T");
                // Nextcloud Chunked Upload v2 assembly: `MOVE /uploads/<user>/<op_id>/.file`!
                if let Some(staging_dir) = path.strip_suffix("/.file") {
                    if !g.dirs.contains(staging_dir) {
                        StatusCode::NOT_FOUND.into_response()
                    } else if overwrite.eq_ignore_ascii_case("F")
                        && (g.files.contains_key(&dst_path) || g.dirs.contains(&dst_path))
                    {
                        StatusCode::PRECONDITION_FAILED.into_response()
                    } else {
                        let prefix = format!("{staging_dir}/");
                        let mut chunks: Vec<(String, Vec<u8>)> = g
                            .files
                            .iter()
                            .filter(|(k, _)| k.starts_with(&prefix))
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        chunks.sort_by(|a, b| {
                            let na = a.0.rsplit('/').next().and_then(|s| s.parse::<u64>().ok());
                            let nb = b.0.rsplit('/').next().and_then(|s| s.parse::<u64>().ok());
                            match (na, nb) {
                                (Some(x), Some(y)) => x.cmp(&y),
                                _ => a.0.cmp(&b.0),
                            }
                        });
                        let mut assembled = Vec::new();
                        for (_, data) in chunks {
                            assembled.extend_from_slice(&data);
                        }
                        let oc_checksum = header_str(&headers, "oc-checksum");
                        g.checksum_headers_seen
                            .push((path.clone(), None, oc_checksum.clone()));
                        if g.validate_oc_checksum
                            && oc_checksum_mismatch(oc_checksum.as_deref(), &assembled)
                        {
                            return checksum_mismatch_resp();
                        }
                        match oc_checksum {
                            Some(ck) => g.checksums.insert(dst_path.clone(), ck),
                            None => g.checksums.remove(&dst_path),
                        };
                        g.files.retain(|k, _| !k.starts_with(&prefix));
                        g.dirs.remove(staging_dir);
                        if let Some((parent, _)) = dst_path.rsplit_once('/') {
                            g.dirs.insert(parent.to_string());
                        }
                        let mut accepted_oc_mtime = false;
                        if !g.ignore_x_oc_mtime
                            && let Some(mtime_s) = headers
                                .get("x-oc-mtime")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<i64>().ok())
                        {
                            g.mtimes.insert(dst_path.clone(), mtime_s);
                            accepted_oc_mtime = true;
                        }
                        g.files.insert(dst_path.clone(), assembled);
                        g.bump_etag(&dst_path);
                        let etag = g.etag_of(&dst_path);
                        let mut resp = (StatusCode::CREATED, [("etag", etag)]).into_response();
                        if accepted_oc_mtime {
                            resp.headers_mut()
                                .insert("x-oc-mtime", "accepted".parse().unwrap());
                        }
                        resp
                    }
                } else if overwrite.eq_ignore_ascii_case("F")
                    && (g.files.contains_key(&dst_path) || g.dirs.contains(&dst_path))
                {
                    StatusCode::PRECONDITION_FAILED.into_response()
                } else if let Some(data) = g.files.remove(&path) {
                    let existed = g.files.contains_key(&dst_path);
                    if let Some((parent, _)) = dst_path.rsplit_once('/') {
                        g.dirs.insert(parent.to_string());
                    }
                    if let Some(mt) = g.mtimes.remove(&path) {
                        g.mtimes.insert(dst_path.clone(), mt);
                    }
                    // A rename keeps the resource's ETag (seeded ETags are content-derived).
                    match g.etag_versions.remove(&path) {
                        Some(v) => g.etag_versions.insert(dst_path.clone(), v),
                        None => g.etag_versions.remove(&dst_path),
                    };
                    g.files.insert(dst_path, data);
                    if existed {
                        StatusCode::NO_CONTENT.into_response()
                    } else {
                        StatusCode::CREATED.into_response()
                    }
                } else if g.dirs.remove(&path) {
                    let src_prefix = format!("{path}/");
                    let dst_prefix = format!("{dst_path}/");
                    let moved_dirs: Vec<String> = g
                        .dirs
                        .iter()
                        .filter(|k| k.starts_with(&src_prefix))
                        .cloned()
                        .collect();
                    for d in moved_dirs {
                        g.dirs.remove(&d);
                        g.dirs
                            .insert(format!("{dst_prefix}{}", &d[src_prefix.len()..]));
                    }
                    let moved_files: Vec<(String, Vec<u8>)> = g
                        .files
                        .iter()
                        .filter(|(k, _)| k.starts_with(&src_prefix))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    for (f, data) in moved_files {
                        g.files.remove(&f);
                        let new_f = format!("{dst_prefix}{}", &f[src_prefix.len()..]);
                        if let Some(mt) = g.mtimes.remove(&f) {
                            g.mtimes.insert(new_f.clone(), mt);
                        }
                        g.files.insert(new_f, data);
                    }
                    g.dirs.insert(dst_path);
                    StatusCode::CREATED.into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
    };

    if let Some(post) = post_commit_fault
        && normal_resp.status().is_success()
        && let Some(fault_resp) = post.into_post_commit_response()
    {
        return fault_resp;
    }

    normal_resp
}

pub(crate) async fn start_mock_dav() -> (String, Arc<Mutex<MockDavState>>) {
    let state = Arc::new(Mutex::new(MockDavState::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let app = Router::new()
        .fallback(handle_dav)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, state)
}
