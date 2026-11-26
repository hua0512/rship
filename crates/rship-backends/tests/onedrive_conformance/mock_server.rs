use crate::common::{FaultInjector, InjectedFault, build_mid_body_reset_response_with_status};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rship_backends::onedrive::ONEDRIVE_CHUNK_ALIGN_BYTES;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub(crate) enum MockMonitorMode {
    Completed,
    InProgressThenCompleted { remaining_in_progress: usize },
    InProgressThenSeeOther { remaining_in_progress: usize },
    DeleteFailed,
    AlwaysInProgress,
}

#[derive(Clone)]
pub(crate) struct MockItem {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) is_folder: bool,
    pub(crate) data: Vec<u8>,
    pub(crate) last_modified: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OmitRanges {
    pub(crate) drop_fragment: bool,
}

pub(crate) struct MockUploadSess {
    pub(crate) dst_path: String,
    pub(crate) buf: Vec<u8>,
    pub(crate) last_modified: String,
}

pub(crate) struct MockGraphState {
    pub(crate) base_url: String,
    pub(crate) next_id: u64,
    pub(crate) items_by_path: BTreeMap<String, MockItem>,
    pub(crate) sessions: HashMap<String, MockUploadSess>,
    pub(crate) monitors: HashMap<String, String>, // monitor_id -> resource_id
    pub(crate) copy_calls: usize,
    pub(crate) get_content_calls: usize,
    pub(crate) put_simple_calls: usize,
    pub(crate) faults: FaultInjector,
    pub(crate) valid_token: Option<String>,
    pub(crate) next_refreshed_token: Option<String>,
    pub(crate) token_refreshes: usize,
    pub(crate) corrupt_upload_sha256_once: bool,
    pub(crate) corrupt_download_body_once: bool,
    /// Report only `quickXorHash` (no `sha256Hash`/`sha1Hash`), like OneDrive for Business,
    /// SharePoint and current OneDrive Personal accounts.
    pub(crate) business_hashes_only: bool,
    /// Return a wrong `quickXorHash` in the next simple-upload response (data stored intact).
    pub(crate) corrupt_upload_quickxor_once: bool,
    /// Flip one byte of the next upload-session fragment as it is stored.
    pub(crate) corrupt_next_session_fragment: bool,
    /// Corrupt the first fragment of EVERY upload session (a persistently bad path).
    pub(crate) corrupt_every_first_fragment: bool,
    /// Answer the next non-final fragment with a `202` whose body has no
    /// `nextExpectedRanges`. With `drop_fragment` the bytes are not kept either.
    pub(crate) omit_next_expected_ranges: Option<OmitRanges>,
    /// Write version per item id. Graph changes an item's `eTag` on every write.
    pub(crate) etag_versions: HashMap<String, u64>,
    pub(crate) package_paths: HashSet<String>,
    pub(crate) remote_items: HashMap<String, (String, String)>,
    pub(crate) remote_drives: HashMap<String, BTreeMap<String, MockItem>>,
    pub(crate) omit_download_url: bool,
    pub(crate) download_url_version: u64,
    pub(crate) download_url_calls: usize,
    pub(crate) require_sec_precision_z: bool,
    pub(crate) captured_copy_drive_ids: Vec<Option<String>>,
    pub(crate) next_monitor_mode: Option<MockMonitorMode>,
    pub(crate) monitor_modes: HashMap<String, MockMonitorMode>,
    pub(crate) force_empty_next_expected_ranges_on_status: bool,
    pub(crate) fragment_overlap_once: Option<usize>,
    pub(crate) quota_override: Option<(i64, i64, i64, i64)>,
    pub(crate) list_page_size: Option<usize>,
    pub(crate) observed_list_urls: Vec<String>,
    pub(crate) retry_after_zero_on_in_progress: bool,
    pub(crate) malformed_patch_once: bool,
}

impl MockGraphState {
    fn new(base_url: String) -> Self {
        let mut s = Self {
            base_url,
            next_id: 2,
            items_by_path: BTreeMap::new(),
            sessions: HashMap::new(),
            monitors: HashMap::new(),
            copy_calls: 0,
            get_content_calls: 0,
            put_simple_calls: 0,
            faults: FaultInjector::new(),
            valid_token: None,
            next_refreshed_token: None,
            token_refreshes: 0,
            corrupt_upload_sha256_once: false,
            corrupt_download_body_once: false,
            business_hashes_only: false,
            corrupt_upload_quickxor_once: false,
            corrupt_next_session_fragment: false,
            corrupt_every_first_fragment: false,
            omit_next_expected_ranges: None,
            etag_versions: HashMap::new(),
            package_paths: HashSet::new(),
            remote_items: HashMap::new(),
            remote_drives: HashMap::new(),
            omit_download_url: false,
            download_url_version: 1,
            download_url_calls: 0,
            require_sec_precision_z: false,
            captured_copy_drive_ids: Vec::new(),
            next_monitor_mode: None,
            monitor_modes: HashMap::new(),
            force_empty_next_expected_ranges_on_status: false,
            fragment_overlap_once: None,
            quota_override: None,
            list_page_size: None,
            observed_list_urls: Vec::new(),
            retry_after_zero_on_in_progress: false,
            malformed_patch_once: false,
        };
        s.items_by_path.insert(
            String::new(),
            MockItem {
                id: "root-id".into(),
                path: String::new(),
                is_folder: true,
                data: vec![],
                last_modified: "2026-11-24T12:00:00Z".into(),
            },
        );
        s
    }

    pub(crate) fn fault_injector(&self) -> FaultInjector {
        self.faults.clone()
    }

    fn check_auth(&self, headers: &HeaderMap) -> bool {
        match self.valid_token.as_deref() {
            None => true,
            Some(expected) => headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == format!("Bearer {expected}")),
        }
    }

    fn alloc_id(&mut self) -> String {
        let id = format!("od-{}", self.next_id);
        self.next_id += 1;
        id
    }

    fn item_json(&self, item: &MockItem) -> serde_json::Value {
        self.item_json_in_drive(None, item)
    }

    fn item_json_in_drive(&self, drive_id: Option<&str>, item: &MockItem) -> serde_json::Value {
        let name = item.path.rsplit('/').next().unwrap_or("root");
        let mut obj = serde_json::json!({
            "id": item.id,
            "name": name,
            "size": item.data.len(),
            "eTag": format!(
                "\"{{{}}},{}\"",
                item.id,
                self.etag_versions.get(&item.id).copied().unwrap_or(0)
            ),
            "lastModifiedDateTime": item.last_modified,
        });
        if let Some(did) = drive_id {
            obj["parentReference"] = serde_json::json!({ "driveId": did });
        }
        if drive_id.is_none() && self.package_paths.contains(&item.path) {
            obj["package"] = serde_json::json!({ "type": "oneNote" });
            return obj;
        }
        if drive_id.is_none()
            && let Some((remote_drive_id, remote_item_id)) = self.remote_items.get(&item.path)
        {
            let mut remote_obj = serde_json::json!({
                "id": remote_item_id,
                "name": name,
                "parentReference": {
                    "driveId": remote_drive_id
                }
            });
            if item.is_folder {
                remote_obj["folder"] = serde_json::json!({ "childCount": 0 });
            } else {
                remote_obj["size"] = serde_json::json!(item.data.len());
                remote_obj["file"] = serde_json::json!({
                    "hashes": { "quickXorHash": B64.encode(mock_quickxor(&item.data)) }
                });
                if !self.omit_download_url {
                    remote_obj["@microsoft.graph.downloadUrl"] = serde_json::json!(format!(
                        "{}/download/{}?v={}",
                        self.base_url, remote_item_id, self.download_url_version
                    ));
                }
            }
            obj["remoteItem"] = remote_obj;
            return obj;
        }
        if item.is_folder {
            obj["folder"] = serde_json::json!({ "childCount": 0 });
        } else {
            let quickxor = B64.encode(mock_quickxor(&item.data));
            obj["file"] = if self.business_hashes_only {
                serde_json::json!({ "hashes": { "quickXorHash": quickxor } })
            } else {
                // Graph reports SHA hashes as uppercase hex.
                let sha256 = hex_encode(&Sha256::digest(&item.data)).to_ascii_uppercase();
                serde_json::json!({
                    "hashes": { "sha256Hash": sha256, "quickXorHash": quickxor }
                })
            };
            if !self.omit_download_url {
                obj["@microsoft.graph.downloadUrl"] = serde_json::json!(format!(
                    "{}/download/{}?v={}",
                    self.base_url, item.id, self.download_url_version
                ));
            }
        }
        obj
    }

    /// Record a write to item `id`, changing its `eTag`.
    pub(crate) fn bump_etag(&mut self, id: &str) {
        *self.etag_versions.entry(id.to_string()).or_insert(0) += 1;
    }

    fn find_by_id(&self, id: &str) -> Option<MockItem> {
        if let Some(it) = self.items_by_path.values().find(|it| it.id == id) {
            return Some(it.clone());
        }
        for map in self.remote_drives.values() {
            if let Some(it) = map.values().find(|it| it.id == id) {
                return Some(it.clone());
            }
        }
        None
    }

    fn find_in_drive_by_id(&self, drive_id: Option<&str>, id: &str) -> Option<MockItem> {
        match drive_id {
            Some(did) => self
                .remote_drives
                .get(did)
                .and_then(|map| map.values().find(|it| it.id == id).cloned()),
            None => self.items_by_path.values().find(|it| it.id == id).cloned(),
        }
    }

    fn drive_map_mut(&mut self, drive_id: Option<&str>) -> Option<&mut BTreeMap<String, MockItem>> {
        match drive_id {
            Some(did) => self.remote_drives.get_mut(did),
            None => Some(&mut self.items_by_path),
        }
    }
}

/// Bit-by-bit QuickXorHash, independent of the backend's implementation: byte `i` is XORed
/// into a circular 160-bit register at bit `(i * 11) % 160`, then the length (LE `u64`) is
/// XORed into the last 8 bytes.
pub(crate) fn mock_quickxor(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, &byte) in data.iter().enumerate() {
        for b in 0..8 {
            if byte & (1 << b) != 0 {
                let pos = (i * 11 + b) % 160;
                out[pos / 8] ^= 1 << (pos % 8);
            }
        }
    }
    for (dst, l) in out[12..].iter_mut().zip((data.len() as u64).to_le_bytes()) {
        *dst ^= l;
    }
    out
}

fn name_already_exists() -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": {
                "code": "nameAlreadyExists",
                "message": "The specified item name already exists."
            }
        })),
    )
        .into_response()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_pct(s: &str) -> String {
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

fn is_final_content_range(headers: &HeaderMap) -> bool {
    let Some(cr) = headers
        .get(axum::http::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(rest) = cr.strip_prefix("bytes ") else {
        return false;
    };
    let Some((range_s, total_s)) = rest.split_once('/') else {
        return false;
    };
    let Some((_, end_s)) = range_s.split_once('-') else {
        return false;
    };
    match (end_s.parse::<usize>(), total_s.parse::<usize>()) {
        (Ok(end), Ok(total)) => end + 1 == total,
        _ => false,
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(decode_pct(v)) } else { None }
    })
}

fn is_valid_sec_precision_z(ts: &str) -> bool {
    ts.len() == 20 && ts.ends_with('Z') && !ts.contains('.') && !ts.contains('+')
}

fn strip_drive_prefix(raw_path: &str) -> Option<(Option<&str>, &str)> {
    if let Some(rest) = raw_path.strip_prefix("/v1.0/me/drive") {
        return Some((None, rest));
    }
    if let Some(after_drives) = raw_path.strip_prefix("/v1.0/drives/") {
        return match after_drives.split_once('/') {
            Some((drive_id, rest)) => Some((Some(drive_id), rest)),
            None => Some((Some(after_drives), "")),
        };
    }
    None
}

fn classify_graph_op(method: &Method, raw_path: &str, headers: &HeaderMap) -> (&'static str, bool) {
    if raw_path.starts_with("/upload/") {
        let op = match *method {
            Method::GET => "upload.status",
            Method::DELETE => "upload.abort",
            Method::PUT => {
                if is_final_content_range(headers) {
                    "upload.chunk_final"
                } else {
                    "upload.chunk"
                }
            }
            _ => "upload.other",
        };
        return (op, false);
    }
    if raw_path.starts_with("/download/") {
        return ("items.content", false);
    }
    if raw_path.starts_with("/monitor/") {
        return ("copy.monitor", false);
    }
    if let Some((_, drive_sub)) = strip_drive_prefix(raw_path) {
        if drive_sub.is_empty() && *method == Method::GET {
            return ("drive.get", true);
        }
        let sub = drive_sub.strip_prefix('/').unwrap_or(drive_sub);
        if let Some(rest) = sub.strip_prefix("items/") {
            if rest.ends_with("/children") {
                let op = match *method {
                    Method::GET => "items.list",
                    Method::POST => "items.mkdir",
                    _ => "items.other",
                };
                return (op, true);
            }
            if rest.ends_with("/content") {
                return ("items.content", true);
            }
            if rest.ends_with("/copy") {
                return ("items.copy", true);
            }
            let op = match *method {
                Method::GET => "items.get",
                Method::PATCH => "items.patch",
                Method::DELETE => "items.delete",
                _ => "items.other",
            };
            return (op, true);
        }
        if let Some(rest) = sub.strip_prefix("root") {
            let action = if rest.is_empty() {
                ""
            } else if let Some(act) = rest.strip_prefix('/') {
                act
            } else if let Some(after_colon) = rest.strip_prefix(":/") {
                if let Some((_, act)) = after_colon.rsplit_once(":/") {
                    act
                } else {
                    ""
                }
            } else {
                return ("root.other", true);
            };
            let op = match (method.clone(), action) {
                (Method::GET, "") => "items.get",
                (Method::GET, "children") => "items.list",
                (Method::POST, "children") => "items.mkdir",
                (Method::PUT, "content") => "upload.simple",
                (Method::POST, "createUploadSession") => "upload.create_session",
                (Method::DELETE, "") => "items.delete",
                _ => "root.other",
            };
            return (op, true);
        }
    }
    ("unknown", false)
}

async fn handle_graph(
    State(st): State<Arc<Mutex<MockGraphState>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw_path = uri.path();
    let raw_query = uri.query().unwrap_or("");

    // 0. Mock Microsoft Entra OAuth2 token refresh endpoint (`/oauth2/v2.0/token`).
    if raw_path == "/oauth2/v2.0/token" && method == Method::POST {
        // Brief async yield so concurrent callers actually serialize on single-flight refresh lock.
        tokio::time::sleep(Duration::from_millis(15)).await;
        let mut g = st.lock().unwrap();
        g.token_refreshes += 1;
        let next = g
            .next_refreshed_token
            .clone()
            .unwrap_or_else(|| format!("tok-refreshed-{}", g.token_refreshes));
        g.valid_token = Some(next.clone());
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "access_token": next,
                "refresh_token": format!("refresh-tok-{}", g.token_refreshes),
                "token_type": "Bearer",
                "expires_in": 3600
            })),
        )
            .into_response();
    }

    let (op, requires_auth) = classify_graph_op(&method, raw_path, &headers);
    let fault = {
        let g = st.lock().unwrap();
        if requires_auth && !g.check_auth(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "Access token has expired."
                    }
                })),
            )
                .into_response();
        }
        g.faults.next_fault(op)
    };

    let post_fault = match fault {
        None => None,
        Some(InjectedFault::SlowFinalize { delay }) => {
            tokio::time::sleep(delay).await;
            None
        }
        Some(InjectedFault::MidBodyReset { prefix })
            if op == "items.content" && headers.contains_key(axum::http::header::RANGE) =>
        {
            return build_mid_body_reset_response_with_status(StatusCode::PARTIAL_CONTENT, prefix);
        }
        Some(f) => match f.into_pre_commit_response() {
            Ok(resp) => return resp,
            Err(post) => Some(post),
        },
    };

    let resp = handle_graph_inner(&st, method, raw_path, raw_query, &headers, body);
    if let Some(post) = post_fault
        && let Some(err_resp) = post.into_post_commit_response()
    {
        return err_resp;
    }
    resp
}

fn serve_item_content(g: &mut MockGraphState, it: &MockItem, headers: &HeaderMap) -> Response {
    g.get_content_calls += 1;
    let corrupt = std::mem::take(&mut g.corrupt_download_body_once);
    if let Some(rng) = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("bytes="))
        && let Some((a, b)) = rng.split_once('-')
    {
        let start: usize = a.parse().unwrap_or(0);
        let end: usize = b.parse().unwrap_or(it.data.len().saturating_sub(1));
        if start >= it.data.len() && !it.data.is_empty() {
            return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        }
        let mut slice = if it.data.is_empty() {
            Vec::new()
        } else {
            it.data[start..=end.min(it.data.len().saturating_sub(1))].to_vec()
        };
        if corrupt && !slice.is_empty() {
            slice[0] ^= 0xFF;
        }
        return (StatusCode::PARTIAL_CONTENT, slice).into_response();
    }
    let mut data = it.data.clone();
    if corrupt && !data.is_empty() {
        data[0] ^= 0xFF;
    }
    (StatusCode::OK, data).into_response()
}

fn list_children_response(
    g: &mut MockGraphState,
    drive_id: Option<&str>,
    target_path: &str,
    raw_path: &str,
    raw_query: &str,
) -> Response {
    let full_url = if raw_query.is_empty() {
        raw_path.to_string()
    } else {
        format!("{raw_path}?{raw_query}")
    };
    g.observed_list_urls.push(full_url);

    let items_map = match drive_id.and_then(|did| g.remote_drives.get(did)) {
        Some(m) => m,
        None => &g.items_by_path,
    };
    if !items_map.contains_key(target_path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let prefix = if target_path.is_empty() {
        String::new()
    } else {
        format!("{target_path}/")
    };
    let children: Vec<serde_json::Value> = items_map
        .values()
        .filter(|it| !it.path.is_empty())
        .filter(|it| {
            if prefix.is_empty() {
                !it.path.contains('/')
            } else if let Some(r) = it.path.strip_prefix(&prefix) {
                !r.is_empty() && !r.contains('/')
            } else {
                false
            }
        })
        .map(|it| g.item_json_in_drive(drive_id, it))
        .collect();

    let top = query_param(raw_query, "$top").and_then(|s| s.parse::<usize>().ok());
    let skiptoken = query_param(raw_query, "$skiptoken")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let page_limit = g.list_page_size.or(top).unwrap_or(usize::MAX).max(1);
    let start = skiptoken.min(children.len());
    let end = start.saturating_add(page_limit).min(children.len());
    let page_items = children[start..end].to_vec();
    let mut resp = serde_json::json!({ "value": page_items });
    if end < children.len() {
        let next_top = top.unwrap_or(999);
        resp["@odata.nextLink"] = serde_json::json!(format!(
            "{}{raw_path}?$top={next_top}&$skiptoken={end}",
            g.base_url
        ));
    }
    (StatusCode::OK, axum::Json(resp)).into_response()
}

fn handle_graph_inner(
    st: &Arc<Mutex<MockGraphState>>,
    method: Method,
    raw_path: &str,
    raw_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let mut g = st.lock().unwrap();

    // 0. Pre-authenticated `@microsoft.graph.downloadUrl` endpoint (`/download/{id}`)
    if let Some(id) = raw_path.strip_prefix("/download/")
        && method == Method::GET
    {
        if headers.contains_key(axum::http::header::AUTHORIZATION) {
            return (
                StatusCode::UNAUTHORIZED,
                "pre-authenticated downloadUrl must not include Authorization header",
            )
                .into_response();
        }
        g.download_url_calls += 1;
        let ver_ok = query_param(raw_query, "v")
            .and_then(|v| v.parse::<u64>().ok())
            .is_none_or(|v| v == g.download_url_version);
        if !ver_ok {
            return (
                StatusCode::GONE,
                axum::Json(serde_json::json!({
                    "error": { "code": "itemNotFound", "message": "downloadUrl expired" }
                })),
            )
                .into_response();
        }
        let decoded_id = decode_pct(id);
        let Some(it) = g.find_by_id(&decoded_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        return serve_item_content(&mut g, &it, headers);
    }

    // 1. Pre-authenticated upload session endpoints (`/upload/{sess_id}`) — MUST NOT receive Bearer!
    if let Some(sess_id) = raw_path.strip_prefix("/upload/") {
        if headers.contains_key(axum::http::header::AUTHORIZATION) {
            return (
                StatusCode::UNAUTHORIZED,
                "pre-authenticated uploadUrl must not include Authorization header",
            )
                .into_response();
        }
        match method {
            Method::GET => {
                let Some(sess) = g.sessions.get(sess_id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let ranges = if g.force_empty_next_expected_ranges_on_status {
                    Vec::<String>::new()
                } else {
                    vec![format!("{}-", sess.buf.len())]
                };
                let resp = serde_json::json!({
                    "nextExpectedRanges": ranges
                });
                return (StatusCode::OK, axum::Json(resp)).into_response();
            }
            Method::DELETE => {
                g.sessions.remove(sess_id);
                return StatusCode::NO_CONTENT.into_response();
            }
            Method::PUT => {
                let Some(cr) = headers
                    .get(axum::http::header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let rest = cr.strip_prefix("bytes ").unwrap();
                let (range_s, total_s) = rest.split_once('/').unwrap();
                let (start_s, end_s) = range_s.split_once('-').unwrap();
                let start: usize = start_s.parse().unwrap();
                let end: usize = end_s.parse().unwrap();
                let total: usize = total_s.parse().unwrap();
                let expected_len = end - start + 1;
                if body.len() != expected_len {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                let is_final = end + 1 == total;
                if !is_final && !(expected_len as u64).is_multiple_of(ONEDRIVE_CHUNK_ALIGN_BYTES) {
                    return (StatusCode::BAD_REQUEST, "chunk not 320 KiB aligned").into_response();
                }

                if let Some(advance_to) = g.fragment_overlap_once.take() {
                    if let Some(sess) = g.sessions.get_mut(sess_id)
                        && sess.buf.len() < advance_to
                        && start <= sess.buf.len()
                    {
                        let missing = advance_to - sess.buf.len();
                        let take_n = missing.min(body.len());
                        sess.buf.extend_from_slice(&body[..take_n]);
                    }
                    return (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        axum::Json(serde_json::json!({
                            "error": {
                                "code": "fragmentOverlap",
                                "message": "Uploaded fragment overlaps with existing bytes."
                            }
                        })),
                    )
                        .into_response();
                }

                let corrupt = std::mem::take(&mut g.corrupt_next_session_fragment)
                    || (g.corrupt_every_first_fragment && start == 0);
                let omit = if is_final {
                    None
                } else {
                    g.omit_next_expected_ranges.take()
                };
                let Some(sess) = g.sessions.get_mut(sess_id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if start != sess.buf.len() {
                    return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                }
                if let Some(omit) = omit {
                    if !omit.drop_fragment {
                        sess.buf.extend_from_slice(&body);
                    }
                    return (StatusCode::ACCEPTED, axum::Json(serde_json::json!({})))
                        .into_response();
                }
                sess.buf.extend_from_slice(&body);
                if corrupt && let Some(b) = sess.buf.get_mut(start) {
                    *b ^= 0xFF;
                }
                if is_final {
                    let finished = g.sessions.remove(sess_id).unwrap();
                    let id = g
                        .items_by_path
                        .get(&finished.dst_path)
                        .map(|i| i.id.clone())
                        .unwrap_or_else(|| g.alloc_id());
                    let item = MockItem {
                        id,
                        path: finished.dst_path.clone(),
                        is_folder: false,
                        data: finished.buf,
                        last_modified: finished.last_modified,
                    };
                    g.bump_etag(&item.id);
                    let json = g.item_json(&item);
                    g.items_by_path.insert(finished.dst_path, item);
                    return (StatusCode::CREATED, axum::Json(json)).into_response();
                } else {
                    let next = sess.buf.len();
                    return (
                        StatusCode::ACCEPTED,
                        axum::Json(serde_json::json!({
                            "nextExpectedRanges": [format!("{next}-")]
                        })),
                    )
                        .into_response();
                }
            }
            _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
    }

    // 2. Copy monitor endpoint (`/monitor/{id}`)
    if let Some(mon_id) = raw_path.strip_prefix("/monitor/") {
        let Some(res_id) = g.monitors.get(mon_id).cloned() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let mode = g
            .monitor_modes
            .get_mut(mon_id)
            .cloned()
            .unwrap_or(MockMonitorMode::Completed);
        match mode {
            MockMonitorMode::Completed => {
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "status": "completed",
                        "resourceId": res_id
                    })),
                )
                    .into_response();
            }
            MockMonitorMode::InProgressThenCompleted {
                remaining_in_progress,
            } => {
                if remaining_in_progress > 0 {
                    g.monitor_modes.insert(
                        mon_id.to_string(),
                        MockMonitorMode::InProgressThenCompleted {
                            remaining_in_progress: remaining_in_progress - 1,
                        },
                    );
                    let mut resp = (
                        StatusCode::OK,
                        axum::Json(serde_json::json!({ "status": "inProgress" })),
                    )
                        .into_response();
                    if g.retry_after_zero_on_in_progress {
                        resp.headers_mut().insert(
                            axum::http::header::RETRY_AFTER,
                            axum::http::HeaderValue::from_static("0"),
                        );
                    }
                    return resp;
                }
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "status": "completed",
                        "resourceId": res_id
                    })),
                )
                    .into_response();
            }
            MockMonitorMode::InProgressThenSeeOther {
                remaining_in_progress,
            } => {
                if remaining_in_progress > 0 {
                    g.monitor_modes.insert(
                        mon_id.to_string(),
                        MockMonitorMode::InProgressThenSeeOther {
                            remaining_in_progress: remaining_in_progress - 1,
                        },
                    );
                    return (
                        StatusCode::OK,
                        axum::Json(serde_json::json!({ "status": "inProgress" })),
                    )
                        .into_response();
                }
                let loc = format!("{}/v1.0/me/drive/items/{res_id}", g.base_url);
                return (StatusCode::SEE_OTHER, [("location", loc)]).into_response();
            }
            MockMonitorMode::DeleteFailed => {
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({ "status": "deleteFailed" })),
                )
                    .into_response();
            }
            MockMonitorMode::AlwaysInProgress => {
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({ "status": "inProgress" })),
                )
                    .into_response();
            }
        }
    }

    // 3. Drive quota & items/root under `/v1.0/me/drive` or `/v1.0/drives/{drive_id}`
    if let Some((drive_id_raw, drive_sub)) = strip_drive_prefix(raw_path) {
        let drive_id_owned = drive_id_raw.map(decode_pct);
        let drive_id_opt = drive_id_owned.as_deref();
        if drive_sub.is_empty() && method == Method::GET {
            let (total, used, remaining, deleted) =
                g.quota_override
                    .unwrap_or((100_000_000, 25_000_000, 75_000_000, 1_000_000));
            return (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "id": drive_id_opt.unwrap_or("drive-1"),
                    "quota": {
                        "total": total,
                        "used": used,
                        "remaining": remaining,
                        "deleted": deleted
                    }
                })),
            )
                .into_response();
        }
        let sub = drive_sub.strip_prefix('/').unwrap_or(drive_sub);

        // 4. `.../items/{id}...`
        if let Some(rest) = sub.strip_prefix("items/") {
            if let Some(id_raw) = rest.strip_suffix("/children") {
                let id = decode_pct(id_raw);
                let Some(folder) = g.find_in_drive_by_id(drive_id_opt, &id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if !folder.is_folder {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                if method == Method::GET {
                    return list_children_response(
                        &mut g,
                        drive_id_opt,
                        &folder.path,
                        raw_path,
                        raw_query,
                    );
                }
            }
            if let Some(id_raw) = rest.strip_suffix("/content") {
                let id = decode_pct(id_raw);
                let Some(it) = g.find_in_drive_by_id(drive_id_opt, &id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                return serve_item_content(&mut g, &it, headers);
            }
            if let Some(id_raw) = rest.strip_suffix("/copy") {
                g.copy_calls += 1;
                let id = decode_pct(id_raw);
                let Some(src) = g.find_in_drive_by_id(drive_id_opt, &id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let copy_drive_id = v["parentReference"]["driveId"].as_str().map(str::to_string);
                g.captured_copy_drive_ids.push(copy_drive_id);
                let parent_id = v["parentReference"]["id"].as_str().unwrap();
                let dst_name = v["name"].as_str().unwrap();
                let parent = g.find_by_id(parent_id).unwrap();
                let dst_path = if parent.path.is_empty() {
                    dst_name.to_string()
                } else {
                    format!("{}/{dst_name}", parent.path)
                };
                // `POST /items/{id}/copy` defaults to `@microsoft.graph.conflictBehavior=fail`:
                // an existing target name is a 409 nameAlreadyExists, never an overwrite.
                if g.items_by_path.contains_key(&dst_path) {
                    return name_already_exists();
                }
                let new_id = g.alloc_id();
                g.bump_etag(&new_id);
                let mode = g
                    .next_monitor_mode
                    .take()
                    .unwrap_or(MockMonitorMode::Completed);
                if !matches!(
                    mode,
                    MockMonitorMode::DeleteFailed | MockMonitorMode::AlwaysInProgress
                ) {
                    g.items_by_path.insert(
                        dst_path.clone(),
                        MockItem {
                            id: new_id.clone(),
                            path: dst_path,
                            is_folder: false,
                            data: src.data,
                            last_modified: src.last_modified,
                        },
                    );
                }
                let mon_id = format!("mon-{new_id}");
                g.monitors.insert(mon_id.clone(), new_id);
                g.monitor_modes.insert(mon_id.clone(), mode);
                let loc = format!("{}/monitor/{mon_id}", g.base_url);
                return (StatusCode::ACCEPTED, [("location", loc)]).into_response();
            }
            let item_id = decode_pct(rest);
            match method {
                Method::GET => {
                    let Some(it) = g.find_in_drive_by_id(drive_id_opt, &item_id) else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    return (
                        StatusCode::OK,
                        axum::Json(g.item_json_in_drive(drive_id_opt, &it)),
                    )
                        .into_response();
                }
                Method::PATCH => {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let new_lm = v["fileSystemInfo"]["lastModifiedDateTime"]
                        .as_str()
                        .map(str::to_string);
                    if let Some(ref lm) = new_lm
                        && g.require_sec_precision_z
                        && !is_valid_sec_precision_z(lm)
                    {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": {
                                    "code": "invalidRequest",
                                    "message": format!("lastModifiedDateTime must be YYYY-MM-DDTHH:MM:SSZ, got {lm}")
                                }
                            })),
                        )
                            .into_response();
                    }
                    let new_name = v["name"].as_str().map(str::to_string);
                    let key = g.drive_map_mut(drive_id_opt).and_then(|map| {
                        map.iter()
                            .find(|(_, it)| it.id == item_id)
                            .map(|(k, _)| k.clone())
                    });
                    if let Some(mut k) = key {
                        if let Some(ref name) = new_name {
                            let new_path = match k.rsplit_once('/') {
                                Some((parent, _)) if !parent.is_empty() => {
                                    format!("{parent}/{name}")
                                }
                                _ => name.clone(),
                            };
                            if new_path != k {
                                let map = g.drive_map_mut(drive_id_opt).unwrap();
                                if map.contains_key(&new_path) {
                                    return name_already_exists();
                                }
                                let mut moved = map.remove(&k).unwrap();
                                moved.path = new_path.clone();
                                let old_prefix = format!("{k}/");
                                let child_keys: Vec<String> = map
                                    .keys()
                                    .filter(|p| p.starts_with(&old_prefix))
                                    .cloned()
                                    .collect();
                                for ck in child_keys {
                                    if let Some(mut child) = map.remove(&ck) {
                                        let suffix = &ck[k.len()..];
                                        let np = format!("{new_path}{suffix}");
                                        child.path = np.clone();
                                        map.insert(np, child);
                                    }
                                }
                                map.insert(new_path.clone(), moved);
                                k = new_path;
                            }
                        }
                        if let Some(lm) = new_lm
                            && let Some(map) = g.drive_map_mut(drive_id_opt)
                            && let Some(it) = map.get_mut(&k)
                        {
                            it.last_modified = lm;
                        }
                        let it = g
                            .drive_map_mut(drive_id_opt)
                            .unwrap()
                            .get(&k)
                            .unwrap()
                            .clone();
                        g.bump_etag(&it.id);
                        if std::mem::take(&mut g.malformed_patch_once) {
                            return (StatusCode::OK, "{not-valid-graph-item-json").into_response();
                        }
                        return (
                            StatusCode::OK,
                            axum::Json(g.item_json_in_drive(drive_id_opt, &it)),
                        )
                            .into_response();
                    }
                    return StatusCode::NOT_FOUND.into_response();
                }
                Method::DELETE => {
                    let key = g.drive_map_mut(drive_id_opt).and_then(|map| {
                        map.iter()
                            .find(|(_, v)| v.id == item_id)
                            .map(|(k, _)| k.clone())
                    });
                    if let Some(k) = key {
                        let map = g.drive_map_mut(drive_id_opt).unwrap();
                        map.remove(&k);
                        let prefix = format!("{k}/");
                        map.retain(|p, _| !p.starts_with(&prefix));
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    return StatusCode::NOT_FOUND.into_response();
                }
                _ => {}
            }
        }

        // 5. Root & path-addressed Graph endpoints (`.../root...`)
        if let Some(rest) = sub.strip_prefix("root") {
            let (target_path, action) = if rest.is_empty() {
                (String::new(), "")
            } else if let Some(act) = rest.strip_prefix('/') {
                (String::new(), act)
            } else if let Some(after_colon) = rest.strip_prefix(":/") {
                if let Some((p, act)) = after_colon.rsplit_once(":/") {
                    (decode_pct(p), act)
                } else if let Some(p) = after_colon.strip_suffix(':') {
                    (decode_pct(p), "")
                } else {
                    (decode_pct(after_colon), "")
                }
            } else {
                return StatusCode::NOT_FOUND.into_response();
            };

            match (method, action) {
                (Method::GET, "") => {
                    let Some(it) = g.items_by_path.get(&target_path).cloned() else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    return (StatusCode::OK, axum::Json(g.item_json(&it))).into_response();
                }
                (Method::GET, "children") => {
                    return list_children_response(
                        &mut g,
                        drive_id_opt,
                        &target_path,
                        raw_path,
                        raw_query,
                    );
                }
                (Method::POST, "children") => {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let name = v["name"].as_str().unwrap();
                    let full = if target_path.is_empty() {
                        name.to_string()
                    } else {
                        format!("{target_path}/{name}")
                    };
                    if g.items_by_path.contains_key(&full) {
                        // conflictBehavior=fail on createFolder.
                        return name_already_exists();
                    }
                    let id = g.alloc_id();
                    let item = MockItem {
                        id,
                        path: full.clone(),
                        is_folder: true,
                        data: vec![],
                        last_modified: "2026-11-24T12:00:00Z".into(),
                    };
                    let json = g.item_json(&item);
                    g.items_by_path.insert(full, item);
                    return (StatusCode::CREATED, axum::Json(json)).into_response();
                }
                (Method::PUT, "content") => {
                    g.put_simple_calls += 1;
                    if let Some(cl) = headers
                        .get(axum::http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<usize>().ok())
                        && body.len() != cl
                    {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    let id = g
                        .items_by_path
                        .get(&target_path)
                        .map(|i| i.id.clone())
                        .unwrap_or_else(|| g.alloc_id());
                    let item = MockItem {
                        id,
                        path: target_path.clone(),
                        is_folder: false,
                        data: body.to_vec(),
                        last_modified: "2026-11-24T12:00:00Z".into(),
                    };
                    g.bump_etag(&item.id);
                    let mut json = g.item_json(&item);
                    if std::mem::take(&mut g.corrupt_upload_sha256_once) {
                        json["file"]["hashes"]["sha256Hash"] = serde_json::json!(
                            "0000000000000000000000000000000000000000000000000000000000000000"
                        );
                    }
                    if std::mem::take(&mut g.corrupt_upload_quickxor_once) {
                        json["file"]["hashes"]["quickXorHash"] =
                            serde_json::json!(B64.encode([0xA5u8; 20]));
                    }
                    g.items_by_path.insert(target_path, item);
                    return (StatusCode::CREATED, axum::Json(json)).into_response();
                }
                (Method::POST, "createUploadSession") => {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let lm_opt = v["item"]["fileSystemInfo"]["lastModifiedDateTime"]
                        .as_str()
                        .map(str::to_string);
                    if let Some(ref lm) = lm_opt
                        && g.require_sec_precision_z
                        && !is_valid_sec_precision_z(lm)
                    {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": {
                                    "code": "invalidRequest",
                                    "message": format!("lastModifiedDateTime must be YYYY-MM-DDTHH:MM:SSZ, got {lm}")
                                }
                            })),
                        )
                            .into_response();
                    }
                    let last_modified = lm_opt.unwrap_or_else(|| "2026-11-24T12:00:00Z".into());
                    let sid = g.alloc_id();
                    g.sessions.insert(
                        sid.clone(),
                        MockUploadSess {
                            dst_path: target_path,
                            buf: Vec::new(),
                            last_modified,
                        },
                    );
                    let upload_url = format!("{}/upload/{sid}", g.base_url);
                    return (
                        StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "uploadUrl": upload_url,
                            "expirationDateTime": "2026-12-01T00:00:00Z"
                        })),
                    )
                        .into_response();
                }
                (Method::DELETE, "") => {
                    if g.items_by_path.remove(&target_path).is_some() {
                        let prefix = format!("{target_path}/");
                        g.items_by_path.retain(|p, _| !p.starts_with(&prefix));
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    return StatusCode::NOT_FOUND.into_response();
                }
                _ => {}
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

pub(crate) async fn start_mock_graph() -> (String, Arc<Mutex<MockGraphState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let base_url = format!("http://{addr}");
    let state = Arc::new(Mutex::new(MockGraphState::new(base_url.clone())));
    let app = Router::new()
        .fallback(handle_graph)
        .with_state(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base_url, state)
}
