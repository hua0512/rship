use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Form, Json, Router};
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::gdrive::{
    FOLDER_MIME, GdriveBackend, GdriveConfig, SHORTCUT_MIME, StaticBearerAuth,
};
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_transport::{HttpTransport, TransportConfig};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

use crate::common::{FaultInjector, InjectedFault};

#[derive(Debug, Clone)]
pub(crate) struct MockFile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) mime_type: String,
    pub(crate) parents: Vec<String>,
    pub(crate) modified_time: String,
    pub(crate) data: Vec<u8>,
    pub(crate) trashed: bool,
    pub(crate) shortcut_target: Option<(String, String)>,
    pub(crate) app_properties: HashMap<String, String>,
}

impl MockFile {
    fn to_json(&self) -> Value {
        let mut obj = json!({
            "id": self.id,
            "name": self.name,
            "mimeType": self.mime_type,
            "parents": self.parents,
            "modifiedTime": self.modified_time,
            "trashed": self.trashed,
        });
        if self.mime_type != FOLDER_MIME && self.mime_type != SHORTCUT_MIME {
            let md5 = hex::encode(Md5::digest(&self.data));
            let sha1 = sha1_hex(&self.data);
            let sha256 = hex::encode(Sha256::digest(&self.data));
            obj["size"] = json!(self.data.len().to_string());
            obj["md5Checksum"] = json!(md5);
            obj["sha1Checksum"] = json!(sha1);
            obj["sha256Checksum"] = json!(sha256);
        }
        if let Some((tid, tmime)) = &self.shortcut_target {
            obj["shortcutDetails"] = json!({
                "targetId": tid,
                "targetMimeType": tmime,
            });
        }
        if !self.app_properties.is_empty() {
            obj["appProperties"] = json!(self.app_properties);
        }
        obj
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MockSession {
    pub(crate) file_id: String,
    pub(crate) name: String,
    pub(crate) parents: Vec<String>,
    pub(crate) modified_time: String,
    pub(crate) app_properties: HashMap<String, String>,
    pub(crate) is_update: bool,
    pub(crate) total_size: u64,
    pub(crate) buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockChangeItem {
    pub(crate) file_id: String,
    pub(crate) removed: bool,
    pub(crate) file: Option<MockFile>,
}

#[derive(Debug, Default)]
pub(crate) struct MockCounters {
    pub(crate) generate_ids: usize,
    pub(crate) resumable_begin_post: usize,
    pub(crate) resumable_begin_patch: usize,
    pub(crate) multipart_post: usize,
    pub(crate) multipart_patch: usize,
    pub(crate) copy_calls: usize,
    pub(crate) query_upload_calls: usize,
    pub(crate) chunk_put_calls: usize,
    pub(crate) token_refreshes: usize,
    pub(crate) folder_creates: usize,
    pub(crate) list_queries: Vec<String>,
    pub(crate) list_params: Vec<HashMap<String, String>>,
    pub(crate) change_params: Vec<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub(crate) struct MockFaults {
    /// If set, every request must carry `Authorization: Bearer <valid_token>`.
    pub(crate) valid_token: Option<String>,
    /// Rotate `valid_token` to this value on the next `/oauth2/token` refresh call.
    pub(crate) next_refreshed_token: Option<String>,
    /// Expire the token (trigger 401) right before the N-th `chunk_put_calls` (1-based).
    pub(crate) expire_token_on_chunk_call: Option<usize>,
    /// On final resumable chunk: commit the file, delete the session (so `query_upload`
    /// returns 404), and respond 503 to simulate a dropped final HTTP response!
    pub(crate) drop_final_chunk_response_after_commit: bool,
    /// Always respond `308` with NO `Range` header (offset 0) to simulate a stuck server.
    pub(crate) always_return_308_no_progress: bool,
    /// Queue of injected `(StatusCode, body)` responses for `files.list` / `files.create` / etc.
    pub(crate) queued_control_errors: VecDeque<(StatusCode, String)>,
    /// Return `incompleteSearch: true` when listing this specific parent ID.
    pub(crate) incomplete_search_for_parent: Option<String>,
    /// Return HTTP `500 Internal Server Error` when listing this specific parent ID.
    pub(crate) fail_500_for_parent: Option<String>,
    /// Corrupt the returned `md5Checksum` on the next single-shot multipart upload response.
    pub(crate) corrupt_upload_md5_once: bool,
    /// Flip one byte in the returned `alt=media` body on the next download while keeping metadata intact.
    pub(crate) corrupt_download_body_once: bool,
    /// File/folder IDs that return HTTP `403 insufficientFilePermissions` on `files.get` / `files.list`.
    pub(crate) forbidden_file_ids: HashSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockChangePage {
    pub(crate) items: Vec<MockChangeItem>,
    pub(crate) next_page_token: Option<String>,
    pub(crate) new_start_page_token: Option<String>,
}

pub(crate) struct MockDriveState {
    pub(crate) base_url: String,
    pub(crate) next_seq: u64,
    pub(crate) files: HashMap<String, MockFile>,
    pub(crate) shared_with_me_times: HashMap<String, String>,
    pub(crate) sessions: HashMap<String, MockSession>,
    pub(crate) start_page_token: String,
    pub(crate) changes_by_token: HashMap<String, MockChangePage>,
    pub(crate) counters: MockCounters,
    pub(crate) faults: MockFaults,
    pub(crate) fault_injector: FaultInjector,
}

impl MockDriveState {
    fn new(base_url: String) -> Self {
        Self {
            base_url,
            next_seq: 1,
            files: HashMap::new(),
            shared_with_me_times: HashMap::new(),
            sessions: HashMap::new(),
            start_page_token: "100".to_string(),
            changes_by_token: HashMap::new(),
            counters: MockCounters::default(),
            faults: MockFaults::default(),
            fault_injector: FaultInjector::new(),
        }
    }

    fn file_to_json(&self, f: &MockFile) -> Value {
        let mut obj = f.to_json();
        if let Some(ts) = self.shared_with_me_times.get(&f.id) {
            obj["sharedWithMeTime"] = json!(ts);
        } else if f.parents.iter().any(|p| p == "sharedWithMe") {
            obj["sharedWithMeTime"] = json!("2026-11-24T00:00:00.000Z");
        }
        obj
    }

    fn alloc_id(&mut self, prefix: &str) -> String {
        let id = format!("{prefix}-{}", self.next_seq);
        self.next_seq += 1;
        id
    }

    fn check_auth(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.faults.valid_token else {
            return true;
        };
        headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {expected}"))
    }
}

pub(crate) struct MockGdriveServer {
    pub(crate) addr: String,
    pub(crate) state: Arc<Mutex<MockDriveState>>,
}

impl MockGdriveServer {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let base_url = format!("http://{addr}");
        let state = Arc::new(Mutex::new(MockDriveState::new(base_url)));

        let app = Router::new()
            .route("/drive/v3/files/generateIds", get(handle_generate_ids))
            .route(
                "/drive/v3/files",
                get(handle_list_files).post(handle_create_metadata),
            )
            .route(
                "/drive/v3/files/{id}",
                get(handle_get_file)
                    .patch(handle_patch_file)
                    .delete(handle_delete_file),
            )
            .route("/drive/v3/files/{id}/copy", post(handle_copy_file))
            .route("/drive/v3/about", get(handle_about))
            .route(
                "/drive/v3/changes/startPageToken",
                get(handle_start_page_token),
            )
            .route("/drive/v3/changes", get(handle_list_changes))
            .route("/upload/drive/v3/files", post(handle_upload_post))
            .route("/upload/drive/v3/files/{id}", patch(handle_upload_patch))
            .route(
                "/upload/session/{sid}",
                put(handle_session_put).delete(handle_session_delete),
            )
            .route("/oauth2/token", post(handle_oauth_token))
            .with_state(state.clone());

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { addr, state }
    }

    pub(crate) fn config(&self, remote_name: &str) -> GdriveConfig {
        let mut cfg = GdriveConfig::new(remote_name);
        cfg.api_base_url = format!("http://{}/drive/v3", self.addr);
        cfg.upload_base_url = format!("http://{}/upload/drive/v3", self.addr);
        cfg.token_url = format!("http://{}/oauth2/token", self.addr);
        cfg.write_qps = None; // Keep conformance tests fast unless specifically testing pacing.
        cfg.base_retry_delay = Duration::from_millis(10);
        cfg.max_retry_delay = Duration::from_millis(50);
        cfg
    }

    pub(crate) fn fault_injector(&self) -> FaultInjector {
        self.state.lock().unwrap().fault_injector.clone()
    }

    pub(crate) fn backend(&self, remote_name: &str) -> GdriveBackend {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("test-user", "test-token"));
        GdriveBackend::new(self.config(remote_name), transport, auth, None, None)
    }
}

fn unauthorized_resp() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "code": 401,
                "message": "Invalid Credentials",
                "errors": [{ "domain": "global", "reason": "authError" }]
            }
        })),
    )
        .into_response()
}

fn conflict_id_resp(id: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": {
                "code": 409,
                "message": format!("A file already exists with the provided ID: {id}"),
                "errors": [{ "domain": "global", "reason": "duplicate", "message": "Duplicate ID" }]
            }
        })),
    )
        .into_response()
}

async fn apply_fault_before_commit(
    fault: Option<InjectedFault>,
) -> Result<Option<InjectedFault>, Box<Response>> {
    match fault {
        Some(InjectedFault::SlowFinalize { delay }) => {
            tokio::time::sleep(delay).await;
            Ok(None)
        }
        Some(f) => match f.into_pre_commit_response() {
            Ok(resp) => Err(Box::new(resp)),
            Err(post) => Ok(Some(post)),
        },
        None => Ok(None),
    }
}

/// Unescape Google Drive single-quoted string literals (`\'` -> `'`, `\\` -> `\`).
fn parse_drive_q_clause(q: &str, key_prefix: &str) -> Option<String> {
    let idx = q.find(key_prefix)?;
    let rest = &q[idx + key_prefix.len()..];
    let mut chars = rest.chars();
    if chars.next()? != '\'' {
        return None;
    }
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            }
            '\'' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

fn parse_parent_in_q(q: &str) -> Option<String> {
    let idx = q.find(" in parents")?;
    let prefix = &q[..idx];
    // Extract the quoted literal immediately before ` in parents`.
    let start_quote = prefix.find('\'')?;
    let rest = &prefix[start_quote..];
    parse_drive_q_clause(rest, "")
}

fn parse_app_property_in_q(q: &str) -> Option<(String, String)> {
    let idx = q.find("appProperties has")?;
    let rest = &q[idx..];
    let key = parse_drive_q_clause(rest, "key=")?;
    let val = parse_drive_q_clause(rest, "value=")?;
    Some((key, val))
}

fn parse_all_mime_filters(q: &str) -> (Vec<String>, Vec<String>) {
    let mut allowed = Vec::new();
    let mut excluded = Vec::new();
    let mut rest = q;
    while let Some(idx) = rest.find("mimeType ") {
        let after = &rest[idx + "mimeType ".len()..];
        if let Some(val_rest) = after.strip_prefix("= ") {
            if let Some(lit) = parse_drive_q_clause(val_rest, "") {
                allowed.push(lit);
            }
            rest = val_rest;
        } else if let Some(val_rest) = after.strip_prefix("!= ") {
            if let Some(lit) = parse_drive_q_clause(val_rest, "") {
                excluded.push(lit);
            }
            rest = val_rest;
        } else {
            rest = after;
        }
    }
    (allowed, excluded)
}

async fn handle_generate_ids(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.fault_injector.next_fault("files.generateIds")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let count = params
        .get("count")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 1000);
    let space = params
        .get("space")
        .map(String::as_str)
        .unwrap_or("drive")
        .to_string();
    let resp = {
        let mut g = st.lock().unwrap();
        g.counters.generate_ids += 1;
        let ids: Vec<String> = (0..count).map(|_| g.alloc_id("pregen")).collect();
        Json(json!({ "ids": ids, "space": space })).into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_list_files(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let fault = {
        let mut g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        if let Some((status, body)) = g.faults.queued_control_errors.pop_front() {
            return (status, body).into_response();
        }
        g.fault_injector.next_fault("files.list")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        // Verify explicit `fields` and Shared Drive params are always sent!
        assert!(
            params.contains_key("fields"),
            "files.list must always send explicit fields mask"
        );
        assert_eq!(
            params.get("supportsAllDrives").map(String::as_str),
            Some("true")
        );
        if params.get("spaces").map(String::as_str) != Some("appDataFolder") {
            assert_eq!(
                params.get("includeItemsFromAllDrives").map(String::as_str),
                Some("true")
            );
        }

        let q = params.get("q").cloned().unwrap_or_default();
        g.counters.list_queries.push(q.clone());
        g.counters.list_params.push(params.clone());

        let parent_filter = parse_parent_in_q(&q);
        if let Some(ref p) = parent_filter
            && g.faults.forbidden_file_ids.contains(p)
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "code": 403,
                        "message": "Insufficient File Permissions",
                        "errors": [{ "domain": "global", "reason": "insufficientFilePermissions" }]
                    }
                })),
            )
                .into_response();
        }
        if let Some(ref p) = parent_filter
            && g.faults.fail_500_for_parent.as_deref() == Some(p.as_str())
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {
                        "code": 500,
                        "message": "Backend Error",
                        "errors": [{ "domain": "global", "reason": "backendError" }]
                    }
                })),
            )
                .into_response();
        }
        let shared_with_me_filter = q.contains("sharedWithMe = true");
        let name_filter = parse_drive_q_clause(&q, "name = ");
        let (allowed_mimes, excluded_mimes) = parse_all_mime_filters(&q);
        let app_prop_filter = parse_app_property_in_q(&q);
        let trashed_filter = if q.contains("trashed = true") {
            Some(true)
        } else if q.contains("trashed = false") {
            Some(false)
        } else {
            None
        };

        let incomplete = parent_filter
            .as_ref()
            .is_some_and(|p| g.faults.incomplete_search_for_parent.as_deref() == Some(p.as_str()));

        let mut matched: Vec<Value> = g
            .files
            .values()
            .filter(|f| {
                if let Some(want_trashed) = trashed_filter
                    && f.trashed != want_trashed
                {
                    return false;
                }
                if shared_with_me_filter
                    && !f.parents.iter().any(|p| p == "sharedWithMe")
                    && !g.shared_with_me_times.contains_key(&f.id)
                {
                    return false;
                }
                if let Some(ref p) = parent_filter
                    && !f.parents.contains(p)
                {
                    return false;
                }
                if let Some(ref n) = name_filter
                    && f.name != *n
                {
                    return false;
                }
                if !allowed_mimes.is_empty() && !allowed_mimes.contains(&f.mime_type) {
                    return false;
                }
                if excluded_mimes.contains(&f.mime_type) {
                    return false;
                }
                if let Some((ref ak, ref av)) = app_prop_filter
                    && f.app_properties.get(ak) != Some(av)
                {
                    return false;
                }
                true
            })
            .map(|f| g.file_to_json(f))
            .collect();
        matched.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

        Json(json!({
            "incompleteSearch": incomplete,
            "files": matched,
        }))
        .into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_create_metadata(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fault = {
        let mut g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        if let Some((status, err_body)) = g.faults.queued_control_errors.pop_front() {
            return (status, err_body).into_response();
        }
        g.fault_injector.next_fault("files.create")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        let id = if let Some(client_id) = body["id"].as_str().filter(|s| !s.is_empty()) {
            if g.files.contains_key(client_id) {
                return conflict_id_resp(client_id);
            }
            client_id.to_string()
        } else {
            g.alloc_id("node")
        };
        let mime_type = body["mimeType"]
            .as_str()
            .unwrap_or("application/octet-stream")
            .to_string();
        if mime_type == FOLDER_MIME {
            g.counters.folder_creates += 1;
        }
        let parents: Vec<String> = body["parents"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| vec!["root".to_string()]);
        let file = MockFile {
            id: id.clone(),
            name: body["name"].as_str().unwrap_or("").to_string(),
            mime_type,
            parents,
            modified_time: body["modifiedTime"]
                .as_str()
                .unwrap_or("2026-11-24T00:00:00.000Z")
                .to_string(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: parse_app_props(&body),
        };
        let resp_json = file.to_json();
        g.files.insert(id, file);
        (StatusCode::OK, Json(resp_json)).into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_get_file(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let is_media = params.get("alt").map(String::as_str) == Some("media");
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        let op = if is_media {
            "files.get_media"
        } else {
            "files.get"
        };
        g.fault_injector.next_fault(op)
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        if g.faults.forbidden_file_ids.contains(&id) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "code": 403,
                        "message": "Insufficient File Permissions",
                        "errors": [{ "domain": "global", "reason": "insufficientFilePermissions" }]
                    }
                })),
            )
                .into_response();
        }
        let corrupt_dl = is_media && std::mem::take(&mut g.faults.corrupt_download_body_once);
        let Some(file) = g.files.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": { "code": 404, "message": "File not found" } })),
            )
                .into_response();
        };

        if is_media {
            if file.mime_type == SHORTCUT_MIME || file.mime_type == FOLDER_MIME {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": {
                            "code": 403,
                            "message": "Only files with binary content can be downloaded.",
                            "errors": [{ "domain": "global", "reason": "fileNotDownloadable" }]
                        }
                    })),
                )
                    .into_response();
            }
            let total = file.data.len();
            if let Some(range_val) = headers
                .get(http::header::RANGE)
                .and_then(|v| v.to_str().ok())
                && let Some(spec) = range_val.strip_prefix("bytes=")
                && let Some((s, e)) = spec.split_once('-')
                && let (Ok(start), Ok(end)) = (s.parse::<usize>(), e.parse::<usize>())
                && start <= end
                && end < total
            {
                let mut slice = file.data[start..=end].to_vec();
                if corrupt_dl && !slice.is_empty() {
                    slice[0] ^= 0xFF;
                }
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(
                        http::header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{total}"),
                    )
                    .header(http::header::CONTENT_LENGTH, slice.len())
                    .body(Body::from(slice))
                    .unwrap()
            } else {
                let mut full = file.data.clone();
                if corrupt_dl && !full.is_empty() {
                    full[0] ^= 0xFF;
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_LENGTH, total)
                    .body(Body::from(full))
                    .unwrap()
            }
        } else {
            Json(file.to_json()).into_response()
        }
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_patch_file(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.fault_injector.next_fault("files.patch")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        let Some(file) = g.files.get_mut(&id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if let Some(name) = body["name"].as_str() {
            file.name = name.to_string();
        }
        if let Some(t) = body["trashed"].as_bool() {
            file.trashed = t;
        }
        if let Some(mt) = body["modifiedTime"].as_str() {
            file.modified_time = mt.to_string();
        }
        Json(file.to_json()).into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_delete_file(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.fault_injector.next_fault("files.delete")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        if g.files.remove(&id).is_some() {
            StatusCode::NO_CONTENT.into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_upload_post(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    handle_upload_init_or_multipart(st, None, headers, params, body).await
}

async fn handle_upload_patch(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    handle_upload_init_or_multipart(st, Some(id), headers, params, body).await
}

async fn handle_upload_init_or_multipart(
    st: Arc<Mutex<MockDriveState>>,
    existing_id: Option<String>,
    headers: HeaderMap,
    params: HashMap<String, String>,
    body: Bytes,
) -> Response {
    let upload_type = params.get("uploadType").map(String::as_str).unwrap_or("");
    let op_name = match upload_type {
        "multipart" => "upload.multipart",
        "resumable" => "upload.resumable_begin",
        _ => "upload.unknown",
    };

    let fault = {
        let mut g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        if let Some((status, err_body)) = g.faults.queued_control_errors.pop_front() {
            return (status, err_body).into_response();
        }
        g.fault_injector.next_fault(op_name)
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let normal_resp = {
        let mut g = st.lock().unwrap();

        if upload_type == "multipart" {
            let ct = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let Some(boundary) = ct.split("boundary=").nth(1) else {
                return (StatusCode::BAD_REQUEST, "missing multipart boundary").into_response();
            };
            let Some((meta, media)) = parse_multipart_related(&body, boundary.trim()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    "malformed or truncated multipart/related body",
                )
                    .into_response();
            };

            if let Some(fid) = existing_id {
                g.counters.multipart_patch += 1;
                let corrupt_md5 = std::mem::take(&mut g.faults.corrupt_upload_md5_once);
                let Some(file) = g.files.get_mut(&fid) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if file.mime_type == SHORTCUT_MIME || file.mime_type == FOLDER_MIME {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": {
                                "code": 400,
                                "message": "Cannot upload content directly onto a shortcut or folder"
                            }
                        })),
                    )
                        .into_response();
                }
                file.data = media;
                if let Some(mt) = meta["modifiedTime"].as_str() {
                    file.modified_time = mt.to_string();
                }
                let props = parse_app_props(&meta);
                if !props.is_empty() {
                    file.app_properties = props;
                }
                let mut out = file.to_json();
                if corrupt_md5 {
                    out["md5Checksum"] = json!("00000000000000000000000000000000");
                }
                Json(out).into_response()
            } else {
                let id = if let Some(client_id) = meta["id"].as_str().filter(|s| !s.is_empty()) {
                    if g.files.contains_key(client_id) {
                        return conflict_id_resp(client_id);
                    }
                    client_id.to_string()
                } else {
                    g.alloc_id("file")
                };
                g.counters.multipart_post += 1;
                let parents: Vec<String> = meta["parents"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["root".to_string()]);
                let file = MockFile {
                    id: id.clone(),
                    name: meta["name"].as_str().unwrap_or("").to_string(),
                    mime_type: "application/octet-stream".to_string(),
                    parents,
                    modified_time: meta["modifiedTime"]
                        .as_str()
                        .unwrap_or("2026-11-24T00:00:00.000Z")
                        .to_string(),
                    data: media,
                    trashed: false,
                    shortcut_target: None,
                    app_properties: parse_app_props(&meta),
                };
                let mut out = file.to_json();
                if std::mem::take(&mut g.faults.corrupt_upload_md5_once) {
                    out["md5Checksum"] = json!("00000000000000000000000000000000");
                }
                g.files.insert(id, file);
                Json(out).into_response()
            }
        } else if upload_type == "resumable" {
            let meta: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
            let total_size: u64 = headers
                .get("x-upload-content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let (file_id, name, parents, is_update) = if let Some(fid) = existing_id {
                g.counters.resumable_begin_patch += 1;
                let Some(existing) = g.files.get(&fid) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if existing.mime_type == SHORTCUT_MIME || existing.mime_type == FOLDER_MIME {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": {
                                "code": 400,
                                "message": "Cannot upload content directly onto a shortcut or folder"
                            }
                        })),
                    )
                        .into_response();
                }
                (fid, existing.name.clone(), existing.parents.clone(), true)
            } else {
                let fid = if let Some(client_id) = meta["id"].as_str().filter(|s| !s.is_empty()) {
                    if g.files.contains_key(client_id) {
                        return conflict_id_resp(client_id);
                    }
                    client_id.to_string()
                } else {
                    g.alloc_id("file")
                };
                g.counters.resumable_begin_post += 1;
                let name = meta["name"].as_str().unwrap_or("").to_string();
                let parents: Vec<String> = meta["parents"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["root".to_string()]);
                (fid, name, parents, false)
            };

            let sid = g.alloc_id("sess");
            let location = format!("{}/upload/session/{sid}", g.base_url);
            g.sessions.insert(
                sid,
                MockSession {
                    file_id,
                    name,
                    parents,
                    modified_time: meta["modifiedTime"]
                        .as_str()
                        .unwrap_or("2026-11-24T00:00:00.000Z")
                        .to_string(),
                    app_properties: parse_app_props(&meta),
                    is_update,
                    total_size,
                    buffer: Vec::new(),
                },
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::LOCATION, location)
                .body(Body::empty())
                .unwrap()
        } else {
            return (StatusCode::BAD_REQUEST, "unsupported uploadType").into_response();
        }
    };

    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    normal_resp
}

async fn handle_session_put(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // Enforce `CONFORMANCE_TESTS.md` §4: `query_upload` and chunk PUTs MUST pass
    // `?fields=...&supportsAllDrives=true`!
    assert!(
        params.contains_key("fields"),
        "resumable session PUT/query MUST include `fields`"
    );
    assert_eq!(
        params.get("supportsAllDrives").map(String::as_str),
        Some("true"),
        "resumable session PUT/query MUST include `supportsAllDrives=true`"
    );

    let cr = headers
        .get(http::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Status query: `Content-Range: bytes */TOTAL`
    if cr.starts_with("bytes */") {
        let fault = {
            let g = st.lock().unwrap();
            if !g.check_auth(&headers) {
                return unauthorized_resp();
            }
            g.fault_injector.next_fault("upload.query")
        };
        let post = match apply_fault_before_commit(fault).await {
            Ok(p) => p,
            Err(resp) => return *resp,
        };
        let resp = {
            let mut g = st.lock().unwrap();
            g.counters.query_upload_calls += 1;
            let Some(sess) = g.sessions.get(&sid) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let mut resp = Response::builder().status(StatusCode::from_u16(308).unwrap());
            // Missing `Range` header when 0 bytes received (real Google Drive behavior!).
            if !sess.buffer.is_empty() {
                resp = resp.header(
                    http::header::RANGE,
                    format!("bytes=0-{}", sess.buffer.len() - 1),
                );
            }
            resp.body(Body::empty()).unwrap()
        };
        if let Some(f) = post
            && let Some(r) = f.into_post_commit_response()
        {
            return r;
        }
        return resp;
    }

    // Parse `Content-Range: bytes START-END/TOTAL` before fault draw so we know `is_final`.
    let Some(spec) = cr.strip_prefix("bytes ") else {
        return (StatusCode::BAD_REQUEST, "missing Content-Range").into_response();
    };
    let Some((range_part, total_part)) = spec.split_once('/') else {
        return (StatusCode::BAD_REQUEST, "bad Content-Range").into_response();
    };
    let Some((start_s, end_s)) = range_part.split_once('-') else {
        return (StatusCode::BAD_REQUEST, "bad Content-Range range").into_response();
    };
    let (Ok(start), Ok(end), Ok(total)) = (
        start_s.parse::<u64>(),
        end_s.parse::<u64>(),
        total_part.parse::<u64>(),
    ) else {
        return (StatusCode::BAD_REQUEST, "non-numeric Content-Range").into_response();
    };
    let expected_len = end - start + 1;
    let is_final = end + 1 == total;

    // Chunk upload PUT.
    let fault = {
        let mut g = st.lock().unwrap();
        g.counters.chunk_put_calls += 1;
        let call_num = g.counters.chunk_put_calls;
        if g.faults.expire_token_on_chunk_call == Some(call_num) {
            g.faults.expire_token_on_chunk_call = None;
            // Expire token right before this chunk to force a mid-upload 401 refresh!
            g.faults.valid_token = Some("expired-now-must-refresh".to_string());
        }
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        let op = if is_final {
            "upload.chunk_final"
        } else {
            "upload.chunk"
        };
        g.fault_injector.next_fault(op)
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let normal_resp = {
        let mut g = st.lock().unwrap();
        let Some(sess) = g.sessions.get(&sid).cloned() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if body.len() as u64 != expected_len || total != sess.total_size {
            return (StatusCode::BAD_REQUEST, "Content-Range length mismatch").into_response();
        }
        if !is_final && !expected_len.is_multiple_of(256 * 1024) {
            return (
                StatusCode::BAD_REQUEST,
                "non-final chunk is not a multiple of 256 KiB",
            )
                .into_response();
        }

        if g.faults.always_return_308_no_progress {
            return Response::builder()
                .status(StatusCode::from_u16(308).unwrap())
                .body(Body::empty())
                .unwrap();
        }

        let sess_mut = g.sessions.get_mut(&sid).unwrap();
        if start as usize > sess_mut.buffer.len() {
            return (
                StatusCode::BAD_REQUEST,
                "chunk offset ahead of received bytes",
            )
                .into_response();
        }
        // Truncate any overlapping retransmit cleanly and append new bytes.
        sess_mut.buffer.truncate(start as usize);
        sess_mut.buffer.extend_from_slice(&body);
        let received = sess_mut.buffer.len() as u64;

        if received < total {
            Response::builder()
                .status(StatusCode::from_u16(308).unwrap())
                .header(http::header::RANGE, format!("bytes=0-{}", received - 1))
                .body(Body::empty())
                .unwrap()
        } else {
            // Final byte received -> commit file atomically and close session!
            let completed = g.sessions.remove(&sid).unwrap();
            if completed.is_update {
                assert!(
                    g.files.contains_key(&completed.file_id),
                    "PATCH resumable session must target existing fileId"
                );
            }
            let file = MockFile {
                id: completed.file_id.clone(),
                name: completed.name,
                mime_type: "application/octet-stream".to_string(),
                parents: completed.parents,
                modified_time: completed.modified_time,
                data: completed.buffer,
                trashed: false,
                shortcut_target: None,
                app_properties: completed.app_properties,
            };
            let file_json = file.to_json();
            g.files.insert(completed.file_id, file);

            if g.faults.drop_final_chunk_response_after_commit {
                g.faults.drop_final_chunk_response_after_commit = false;
                // File IS committed and session IS gone (subsequent query_upload -> 404),
                // but simulate a lost HTTP response with 503!
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "simulated lost final response",
                )
                    .into_response();
            }

            (StatusCode::OK, Json(file_json)).into_response()
        }
    };

    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    normal_resp
}

async fn handle_session_delete(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Path(sid): Path<String>,
) -> Response {
    let mut g = st.lock().unwrap();
    g.sessions.remove(&sid);
    StatusCode::from_u16(499).unwrap().into_response()
}

async fn handle_about(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
) -> Response {
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.fault_injector.next_fault("about.get")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = Json(json!({
        "storageQuota": {
            "limit": "107374182400",
            "usage": "1024",
            "usageInDriveTrash": "256"
        }
    }))
    .into_response();
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_start_page_token(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
) -> Response {
    let g = st.lock().unwrap();
    if !g.check_auth(&headers) {
        return unauthorized_resp();
    }
    Json(json!({ "startPageToken": g.start_page_token })).into_response()
}

async fn handle_list_changes(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let fault = {
        let mut g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.counters.change_params.push(params.clone());
        g.fault_injector.next_fault("changes.list")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let g = st.lock().unwrap();
        let tok = params.get("pageToken").cloned().unwrap_or_default();
        let Some(page) = g.changes_by_token.get(&tok) else {
            return Json(json!({
                "newStartPageToken": tok,
                "changes": [],
            }))
            .into_response();
        };
        let changes_json: Vec<Value> = page
            .items
            .iter()
            .map(|c| {
                let mut obj = json!({
                    "fileId": c.file_id,
                    "removed": c.removed,
                });
                if let Some(f) = &c.file {
                    obj["file"] = g.file_to_json(f);
                }
                obj
            })
            .collect();
        let mut out = json!({ "changes": changes_json });
        if let Some(np) = &page.next_page_token {
            out["nextPageToken"] = json!(np);
        }
        if let Some(ns) = &page.new_start_page_token {
            out["newStartPageToken"] = json!(ns);
        }
        Json(out).into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

async fn handle_oauth_token(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    Form(_params): Form<HashMap<String, String>>,
) -> Response {
    let mut g = st.lock().unwrap();
    g.counters.token_refreshes += 1;
    let new_tok = g
        .faults
        .next_refreshed_token
        .take()
        .unwrap_or_else(|| format!("refreshed-token-{}", g.counters.token_refreshes));
    g.faults.valid_token = Some(new_tok.clone());
    Json(json!({
        "access_token": new_tok,
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .into_response()
}

fn parse_app_props(meta: &Value) -> HashMap<String, String> {
    meta["appProperties"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_multipart_related(body: &[u8], boundary: &str) -> Option<(Value, Vec<u8>)> {
    let delim = format!("--{boundary}");
    let closing = format!("\r\n--{boundary}--\r\n");
    if !body.ends_with(closing.as_bytes()) {
        return None;
    }
    let without_closing = &body[..body.len() - closing.len()];
    let first_sep = format!("{delim}\r\n");
    let rest = without_closing.strip_prefix(first_sep.as_bytes())?;
    let part_sep = format!("\r\n{delim}\r\n");
    let sep_pos = find_subslice(rest, part_sep.as_bytes())?;
    let part1 = &rest[..sep_pos];
    let part2 = &rest[sep_pos + part_sep.len()..];

    let p1_body_idx = find_subslice(part1, b"\r\n\r\n")? + 4;
    let p2_body_idx = find_subslice(part2, b"\r\n\r\n")? + 4;

    let meta: Value = serde_json::from_slice(&part1[p1_body_idx..]).ok()?;
    let media = part2[p2_body_idx..].to_vec();
    Some((meta, media))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(crate) async fn read_gdrive_bytes(backend: &GdriveBackend, path: &RelPath) -> Vec<u8> {
    match backend
        .open_read(&BackendPath::from_rel(path.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => {
            let mut s = r
                .open_range(rship_core::types::ByteRange {
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

async fn handle_copy_file(
    State(st): State<Arc<Mutex<MockDriveState>>>,
    axum::extract::Path(src_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fault = {
        let g = st.lock().unwrap();
        if !g.check_auth(&headers) {
            return unauthorized_resp();
        }
        g.fault_injector.next_fault("files.copy")
    };
    let post = match apply_fault_before_commit(fault).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let resp = {
        let mut g = st.lock().unwrap();
        let Some(src) = g.files.get(&src_id).cloned() else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": {"code": 404, "message": "source file not found"}})),
            )
                .into_response();
        };
        if src.mime_type == FOLDER_MIME || src.mime_type == SHORTCUT_MIME {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "code": 400,
                        "message": "This file cannot be copied.",
                        "errors": [{ "domain": "global", "reason": "cannotCopyFile" }]
                    }
                })),
            )
                .into_response();
        }
        let new_id = if let Some(client_id) = body["id"].as_str().filter(|s| !s.is_empty()) {
            if g.files.contains_key(client_id) {
                return conflict_id_resp(client_id);
            }
            client_id.to_string()
        } else {
            g.alloc_id("copy")
        };
        g.counters.copy_calls += 1;
        let name = body["name"].as_str().unwrap_or(&src.name).to_string();
        let parents: Vec<String> = body["parents"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| src.parents.clone());
        let modified_time = body["modifiedTime"]
            .as_str()
            .unwrap_or(&src.modified_time)
            .to_string();
        let mut app_properties = HashMap::new();
        if let Some(obj) = body["appProperties"].as_object() {
            for (k, v) in obj {
                if let Some(sv) = v.as_str() {
                    app_properties.insert(k.clone(), sv.to_string());
                }
            }
        }
        let copied = MockFile {
            id: new_id.clone(),
            name,
            mime_type: src.mime_type,
            parents,
            modified_time,
            data: src.data,
            trashed: false,
            shortcut_target: None,
            app_properties,
        };
        let json_val = copied.to_json();
        g.files.insert(new_id, copied);
        (StatusCode::OK, Json(json_val)).into_response()
    };
    if let Some(f) = post
        && let Some(r) = f.into_post_commit_response()
    {
        return r;
    }
    resp
}

fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let o = i * 4;
            *word = u32::from_be_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
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
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4]
    )
}
