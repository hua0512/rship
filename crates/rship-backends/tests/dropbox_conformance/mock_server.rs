use crate::common::{self, FaultInjector, InjectedFault};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rship_backends::dropbox::{DropboxBackend, DropboxConfig, dropbox_content_hash};
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone)]
pub(crate) struct MockEntry {
    pub(crate) id: String,
    pub(crate) path: String, // leading `/`, e.g. `/dir/file.txt`
    pub(crate) is_folder: bool,
    pub(crate) data: Vec<u8>,
    pub(crate) rev: String,
    pub(crate) client_modified: String,
}

pub(crate) struct MockUploadSession {
    pub(crate) data: Vec<u8>,
}

pub(crate) struct MockDropboxState {
    pub(crate) next_id: u64,
    pub(crate) entries: BTreeMap<String, MockEntry>, // key = lowercased path (Dropbox is case-insensitive!)
    pub(crate) non_downloadable_paths: HashSet<String>,
    pub(crate) sessions: HashMap<String, MockUploadSession>,
    pub(crate) cursors: HashMap<String, Vec<MockEntry>>,
    pub(crate) async_delete_jobs: HashMap<String, (usize, serde_json::Value)>,
    pub(crate) delete_batch_async_polls: usize,
    pub(crate) delete_batch_fail_keys: HashSet<String>,
    pub(crate) delete_batch_check_calls: usize,
    pub(crate) inject_429_remaining: usize,
    pub(crate) inject_content_hash_mismatch_once: bool,
    pub(crate) copy_calls: usize,
    pub(crate) move_calls: usize,
    pub(crate) batch_delete_calls: usize,
    pub(crate) valid_token: String,
    pub(crate) refreshed_token: String,
    pub(crate) oauth_refresh_calls: usize,
    pub(crate) oauth_refresh_delay: Option<Duration>,
    pub(crate) reject_refreshed_token: bool,
    pub(crate) fault_injector: FaultInjector,
    pub(crate) seen_upload_content_hashes: Vec<String>,
    pub(crate) seen_upload_args: Vec<serde_json::Value>,
    pub(crate) seen_list_folder_args: Vec<serde_json::Value>,
    pub(crate) seen_headers: Vec<(String, Option<String>, Option<String>)>,
    pub(crate) space_usage_override: Option<serde_json::Value>,
    pub(crate) team_members_by_email: HashMap<String, String>,
    pub(crate) corrupt_upload_content_hash_once: bool,
    pub(crate) corrupt_download_body_once: bool,
}

impl MockDropboxState {
    fn new() -> Self {
        Self {
            next_id: 1,
            entries: BTreeMap::new(),
            non_downloadable_paths: HashSet::new(),
            sessions: HashMap::new(),
            cursors: HashMap::new(),
            async_delete_jobs: HashMap::new(),
            delete_batch_async_polls: 0,
            delete_batch_fail_keys: HashSet::new(),
            delete_batch_check_calls: 0,
            inject_429_remaining: 0,
            inject_content_hash_mismatch_once: false,
            copy_calls: 0,
            move_calls: 0,
            batch_delete_calls: 0,
            valid_token: "dbx-test-token".to_string(),
            refreshed_token: "dbx-refreshed-token".to_string(),
            oauth_refresh_calls: 0,
            oauth_refresh_delay: None,
            reject_refreshed_token: false,
            fault_injector: FaultInjector::new(),
            seen_upload_content_hashes: Vec::new(),
            seen_upload_args: Vec::new(),
            seen_list_folder_args: Vec::new(),
            seen_headers: Vec::new(),
            space_usage_override: None,
            team_members_by_email: HashMap::new(),
            corrupt_upload_content_hash_once: false,
            corrupt_download_body_once: false,
        }
    }

    pub(crate) fn fault_injector(&self) -> FaultInjector {
        self.fault_injector.clone()
    }

    pub(crate) fn alloc_id(&mut self, prefix: &str) -> String {
        let id = format!("{prefix}{}", self.next_id);
        self.next_id += 1;
        id
    }

    pub(crate) fn key(path: &str) -> String {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("/{}", trimmed.to_lowercase())
        }
    }

    pub(crate) fn ensure_parents(&mut self, full_path: &str) {
        let trimmed = full_path.trim_start_matches('/');
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() <= 1 {
            return;
        }
        let mut cur = String::new();
        for seg in &parts[..parts.len() - 1] {
            cur.push('/');
            cur.push_str(seg);
            let k = Self::key(&cur);
            if !self.entries.contains_key(&k) {
                let id = self.alloc_id("id:dir");
                self.entries.insert(
                    k,
                    MockEntry {
                        id,
                        path: cur.clone(),
                        is_folder: true,
                        data: Vec::new(),
                        rev: "0100000000000001".into(),
                        client_modified: "2026-11-25T02:00:00Z".into(),
                    },
                );
            }
        }
    }

    fn entry_json(e: &MockEntry) -> serde_json::Value {
        let name = e.path.rsplit('/').next().unwrap_or("");
        if e.is_folder {
            serde_json::json!({
                ".tag": "folder",
                "id": e.id,
                "name": name,
                "path_lower": e.path.to_lowercase(),
                "path_display": e.path,
            })
        } else {
            serde_json::json!({
                ".tag": "file",
                "id": e.id,
                "name": name,
                "path_lower": e.path.to_lowercase(),
                "path_display": e.path,
                "size": e.data.len(),
                "server_modified": "2026-11-25T02:00:00Z",
                "client_modified": e.client_modified,
                "rev": e.rev,
                "content_hash": dropbox_content_hash(&e.data),
            })
        }
    }
}

fn to_conflict_resp() -> Response {
    json_resp(
        StatusCode::CONFLICT,
        serde_json::json!({
            "error_summary": "to/conflict/file/..",
            "error": {".tag": "to", "to": {".tag": "conflict", "conflict": {".tag": "file"}}}
        }),
    )
}

fn json_resp(status: StatusCode, val: serde_json::Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        serde_json::to_vec(&val).unwrap(),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn parse_api_arg(headers: &HeaderMap) -> Result<serde_json::Value, Response> {
    let raw = headers.get("dropbox-api-arg").ok_or_else(|| {
        json_resp(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error_summary": "missing Dropbox-API-Arg"}),
        )
    })?;
    // Enforce real Dropbox's strict ASCII-only header rule!
    if !raw.as_bytes().iter().all(|b| b.is_ascii()) {
        return Err(json_resp(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error_summary": "non-ASCII bytes in Dropbox-API-Arg header"}),
        ));
    }
    let s = raw.to_str().map_err(|_| {
        json_resp(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error_summary": "invalid header string"}),
        )
    })?;
    serde_json::from_str(s).map_err(|e| {
        json_resp(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error_summary": format!("invalid JSON in Dropbox-API-Arg: {e}")}),
        )
    })
}

fn classify_dropbox_op(path: &str) -> Option<&'static str> {
    match path {
        "/2/files/get_metadata" => Some("get_metadata"),
        "/2/files/list_folder" => Some("list_folder"),
        "/2/files/list_folder/continue" => Some("list_folder_continue"),
        "/2/files/create_folder_v2" => Some("create_folder_v2"),
        "/2/files/delete_v2" => Some("delete_v2"),
        "/2/files/delete_batch" => Some("delete_batch"),
        "/2/files/delete_batch/check" => Some("delete_batch_check"),
        "/2/files/copy_v2" => Some("copy_v2"),
        "/2/files/move_v2" => Some("move_v2"),
        "/2/users/get_space_usage" => Some("get_space_usage"),
        "/2/team/members/get_info" => Some("team_members_get_info"),
        "/2/files/upload" => Some("upload"),
        "/2/files/download" => Some("download"),
        "/2/files/upload_session/start" => Some("upload_session_start"),
        "/2/files/upload_session/append_v2" => Some("upload_session_append_v2"),
        "/2/files/upload_session/finish" => Some("upload_session_finish"),
        _ => None,
    }
}

enum DropboxPreFlight {
    Immediate(Response),
    Proceed {
        slow_delay: Option<Duration>,
        post_commit_fault: Option<InjectedFault>,
    },
}

fn preflight_dropbox_request(
    st: &Arc<Mutex<MockDropboxState>>,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> DropboxPreFlight {
    let g = st.lock().unwrap();
    let expected_auth = format!("Bearer {}", g.valid_token);
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected_auth.as_str()) {
        return DropboxPreFlight::Immediate(json_resp(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error_summary": "invalid_access_token"}),
        ));
    }

    let mut slow_delay = None;
    let mut post_commit_fault = None;
    if let Some(op) = classify_dropbox_op(uri.path())
        && let Some(fault) = g.fault_injector.next_fault(op)
    {
        match fault {
            InjectedFault::SlowFinalize { delay } => slow_delay = Some(delay),
            InjectedFault::MidBodyReset { prefix } => {
                if op == "download" && headers.contains_key("range") {
                    return DropboxPreFlight::Immediate(
                        common::build_mid_body_reset_response_with_status(
                            StatusCode::PARTIAL_CONTENT,
                            prefix,
                        ),
                    );
                }
                return DropboxPreFlight::Immediate(common::build_mid_body_reset_response(prefix));
            }
            other => match other.into_pre_commit_response() {
                Ok(resp) => return DropboxPreFlight::Immediate(resp),
                Err(post) => post_commit_fault = Some(post),
            },
        }
    }

    DropboxPreFlight::Proceed {
        slow_delay,
        post_commit_fault,
    }
}

async fn handle_dropbox(
    State(st): State<Arc<Mutex<MockDropboxState>>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if uri.path() == "/oauth2/token" {
        let delay = st.lock().unwrap().oauth_refresh_delay;
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let mut g = st.lock().unwrap();
        g.oauth_refresh_calls += 1;
        let next_tok = g.refreshed_token.clone();
        if !g.reject_refreshed_token {
            g.valid_token = next_tok.clone();
        }
        return json_resp(
            StatusCode::OK,
            serde_json::json!({
                "access_token": next_tok,
                "token_type": "bearer",
                "expires_in": 14400
            }),
        );
    }

    let (slow_delay, post_commit_fault) = match preflight_dropbox_request(&st, &uri, &headers) {
        DropboxPreFlight::Immediate(resp) => return resp,
        DropboxPreFlight::Proceed {
            slow_delay,
            post_commit_fault,
        } => (slow_delay, post_commit_fault),
    };

    // Request body has already been drained by the `Bytes` extractor; sleep with no mutex held.
    if let Some(delay) = slow_delay {
        tokio::time::sleep(delay).await;
    }

    let resp = execute_dropbox_request(&st, &uri, &headers, body);
    if let Some(post) = post_commit_fault
        && resp.status().is_success()
    {
        return post.into_post_commit_response().unwrap_or(resp);
    }
    resp
}

fn execute_dropbox_request(
    st: &Arc<Mutex<MockDropboxState>>,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    {
        let mut g = st.lock().unwrap();
        let path_root = headers
            .get("dropbox-api-path-root")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let select_user = headers
            .get("dropbox-api-select-user")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        g.seen_headers
            .push((uri.path().to_string(), path_root, select_user));
    }
    match uri.path() {
        "/2/files/get_metadata" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let path = req["path"].as_str().unwrap_or("");
            let g = st.lock().unwrap();
            if let Some(e) = g.entries.get(&MockDropboxState::key(path)) {
                json_resp(StatusCode::OK, MockDropboxState::entry_json(e))
            } else {
                json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "path/not_found/...", "error": {".tag": "path", "path": {".tag": "not_found"}}}),
                )
            }
        }
        "/2/files/list_folder" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let path = req["path"].as_str().unwrap_or("");
            let recursive = req["recursive"].as_bool().unwrap_or(false);
            let include_non_downloadable = req["include_non_downloadable_files"]
                .as_bool()
                .unwrap_or(true);
            let mut g = st.lock().unwrap();
            g.seen_list_folder_args.push(req.clone());
            if !path.is_empty() && !g.entries.contains_key(&MockDropboxState::key(path)) {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "path/not_found/.", "error": {".tag": "path", "path": {".tag": "not_found"}}}),
                );
            }
            let pfx_segs: Vec<String> = path
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_lowercase())
                .collect();
            let mut matched: Vec<MockEntry> = g
                .entries
                .values()
                .filter(|e| {
                    let key = MockDropboxState::key(&e.path);
                    if !include_non_downloadable && g.non_downloadable_paths.contains(&key) {
                        return false;
                    }
                    let e_segs: Vec<String> = e
                        .path
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_lowercase())
                        .collect();
                    if e_segs.len() <= pfx_segs.len() || e_segs[..pfx_segs.len()] != pfx_segs[..] {
                        return false;
                    }
                    let rest_len = e_segs.len() - pfx_segs.len();
                    recursive || rest_len == 1
                })
                .cloned()
                .collect();
            matched.sort_by(|a, b| a.path.cmp(&b.path));
            // Force pagination when > 2 entries!
            let (first, rest) = if matched.len() > 2 {
                let tail = matched.split_off(2);
                (matched, Some(tail))
            } else {
                (matched, None)
            };
            let entries: Vec<_> = first
                .iter()
                .map(|e| {
                    let mut v = MockDropboxState::entry_json(e);
                    if g.non_downloadable_paths
                        .contains(&MockDropboxState::key(&e.path))
                    {
                        v["is_downloadable"] = serde_json::Value::Bool(false);
                    }
                    v
                })
                .collect();
            if let Some(tail) = rest {
                let cursor = g.alloc_id("cur-");
                g.cursors.insert(cursor.clone(), tail);
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({"entries": entries, "cursor": cursor, "has_more": true}),
                )
            } else {
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({"entries": entries, "cursor": "done", "has_more": false}),
                )
            }
        }
        "/2/files/list_folder/continue" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let cursor = req["cursor"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            let mut remaining = g.cursors.remove(cursor).unwrap_or_default();
            let (page, tail) = if remaining.len() > 2 {
                let t = remaining.split_off(2);
                (remaining, Some(t))
            } else {
                (remaining, None)
            };
            let entries: Vec<_> = page.iter().map(MockDropboxState::entry_json).collect();
            if let Some(t) = tail {
                let next = g.alloc_id("cur-");
                g.cursors.insert(next.clone(), t);
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({"entries": entries, "cursor": next, "has_more": true}),
                )
            } else {
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({"entries": entries, "cursor": "done", "has_more": false}),
                )
            }
        }
        "/2/files/create_folder_v2" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let path = req["path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            let k = MockDropboxState::key(path);
            if g.entries.contains_key(&k) {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "path/conflict/folder/.", "error": {".tag": "path", "path": {".tag": "conflict"}}}),
                );
            }
            g.ensure_parents(path);
            let id = g.alloc_id("id:dir");
            let entry = MockEntry {
                id,
                path: path.to_string(),
                is_folder: true,
                data: Vec::new(),
                rev: "0100000000000001".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            };
            g.entries.insert(k, entry.clone());
            json_resp(
                StatusCode::OK,
                serde_json::json!({"metadata": MockDropboxState::entry_json(&entry)}),
            )
        }
        "/2/files/delete_v2" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let path = req["path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            let k = MockDropboxState::key(path);
            let Some(removed) = g.entries.remove(&k) else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "path_lookup/not_found/."}),
                );
            };
            let prefix = format!("{k}/");
            g.entries.retain(|ek, _| !ek.starts_with(&prefix));
            json_resp(
                StatusCode::OK,
                serde_json::json!({"metadata": MockDropboxState::entry_json(&removed)}),
            )
        }
        "/2/files/delete_batch" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let mut g = st.lock().unwrap();
            g.batch_delete_calls += 1;
            let mut results = Vec::new();
            for item in req["entries"].as_array().cloned().unwrap_or_default() {
                let p = item["path"].as_str().unwrap_or("");
                let k = MockDropboxState::key(p);
                if g.delete_batch_fail_keys.contains(&k) {
                    results.push(serde_json::json!({
                        ".tag": "failure",
                        "failure": {".tag": "cant_transfer_ownership"}
                    }));
                } else if let Some(rem) = g.entries.remove(&k) {
                    let prefix = format!("{k}/");
                    g.entries.retain(|ek, _| !ek.starts_with(&prefix));
                    results.push(serde_json::json!({".tag": "success", "metadata": MockDropboxState::entry_json(&rem)}));
                } else {
                    results.push(serde_json::json!({".tag": "failure", "failure": {".tag": "path_lookup", "path_lookup": {".tag": "not_found"}}}));
                }
            }
            let complete_payload = serde_json::json!({".tag": "complete", "entries": results});
            if g.delete_batch_async_polls > 0 {
                let job_id = g.alloc_id("dbx-del-job-");
                let polls = g.delete_batch_async_polls;
                g.async_delete_jobs
                    .insert(job_id.clone(), (polls, complete_payload));
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({".tag": "async_job_id", "async_job_id": job_id}),
                )
            } else {
                json_resp(StatusCode::OK, complete_payload)
            }
        }
        "/2/files/delete_batch/check" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let job_id = req["async_job_id"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            g.delete_batch_check_calls += 1;
            let Some((remaining, payload)) = g.async_delete_jobs.get_mut(job_id) else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "invalid_async_job_id/.", "error": {".tag": "invalid_async_job_id"}}),
                );
            };
            if *remaining > 0 {
                *remaining -= 1;
                json_resp(StatusCode::OK, serde_json::json!({".tag": "in_progress"}))
            } else {
                let done = payload.clone();
                g.async_delete_jobs.remove(job_id);
                json_resp(StatusCode::OK, done)
            }
        }
        "/2/files/copy_v2" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let from = req["from_path"].as_str().unwrap_or("");
            let to = req["to_path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            if g.inject_429_remaining > 0 {
                g.inject_429_remaining -= 1;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "0"), ("content-type", "application/json")],
                    br#"{"error_summary":"too_many_write_operations/."}"#.to_vec(),
                )
                    .into_response();
            }
            g.copy_calls += 1;
            let Some(src) = g.entries.get(&MockDropboxState::key(from)).cloned() else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "from_lookup/not_found/."}),
                );
            };
            // copy_v2/move_v2 never overwrite: an existing destination is 409 `to/conflict`
            // (https://www.dropbox.com/developers/documentation/http/documentation#files-copy).
            if g.entries.contains_key(&MockDropboxState::key(to)) {
                return to_conflict_resp();
            }
            g.ensure_parents(to);
            let id = g.alloc_id("id:copy");
            let copied = MockEntry {
                id,
                path: to.to_string(),
                is_folder: src.is_folder,
                data: src.data,
                rev: g.alloc_id("rev"),
                client_modified: src.client_modified,
            };
            g.entries.insert(MockDropboxState::key(to), copied.clone());
            json_resp(
                StatusCode::OK,
                serde_json::json!({"metadata": MockDropboxState::entry_json(&copied)}),
            )
        }
        "/2/files/move_v2" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let from = req["from_path"].as_str().unwrap_or("");
            let to = req["to_path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            g.move_calls += 1;
            if !g.entries.contains_key(&MockDropboxState::key(from)) {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "from_lookup/not_found/.", "error": {".tag": "from_lookup", "from_lookup": {".tag": "not_found"}}}),
                );
            }
            if MockDropboxState::key(from) != MockDropboxState::key(to)
                && g.entries.contains_key(&MockDropboxState::key(to))
            {
                return to_conflict_resp();
            }
            let mut src = g.entries.remove(&MockDropboxState::key(from)).unwrap();
            g.ensure_parents(to);
            src.path = to.to_string();
            src.rev = g.alloc_id("rev");
            g.entries.insert(MockDropboxState::key(to), src.clone());
            json_resp(
                StatusCode::OK,
                serde_json::json!({"metadata": MockDropboxState::entry_json(&src)}),
            )
        }
        "/2/users/get_space_usage" => {
            let g = st.lock().unwrap();
            let val = g.space_usage_override.clone().unwrap_or_else(|| {
                serde_json::json!({
                    "used": 100_000_000u64,
                    "allocation": { ".tag": "individual", "allocated": 2_000_000_000u64 }
                })
            });
            json_resp(StatusCode::OK, val)
        }
        "/2/team/members/get_info" => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let g = st.lock().unwrap();
            let email = req["members"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|m| m.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(member_id) = g.team_members_by_email.get(email) {
                json_resp(
                    StatusCode::OK,
                    serde_json::json!([{
                        ".tag": "member_info",
                        "profile": {
                            "team_member_id": member_id,
                            "email": email
                        }
                    }]),
                )
            } else {
                json_resp(
                    StatusCode::OK,
                    serde_json::json!([{ ".tag": "email_not_found", "email_not_found": email }]),
                )
            }
        }
        "/2/files/upload" => {
            let arg = match parse_api_arg(headers) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let path = arg["path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            g.seen_upload_args.push(arg.clone());
            if g.inject_429_remaining > 0 {
                g.inject_429_remaining -= 1;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "0"), ("content-type", "application/json")],
                    br#"{"error_summary":"too_many_write_operations/."}"#.to_vec(),
                )
                    .into_response();
            }
            if g.inject_content_hash_mismatch_once {
                g.inject_content_hash_mismatch_once = false;
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "error_summary": "content_hash_mismatch/.",
                        "error": {".tag": "content_hash_mismatch"}
                    }),
                );
            }
            if let Some(ch) = arg.get("content_hash").and_then(|v| v.as_str()) {
                g.seen_upload_content_hashes.push(ch.to_string());
            }
            g.ensure_parents(path);
            let id = g.alloc_id("id:file");
            let rev = g.alloc_id("rev");
            let client_modified = arg["client_modified"]
                .as_str()
                .unwrap_or("2026-11-25T02:00:00Z")
                .to_string();
            let entry = MockEntry {
                id,
                path: path.to_string(),
                is_folder: false,
                data: body.to_vec(),
                rev,
                client_modified,
            };
            g.entries.insert(MockDropboxState::key(path), entry.clone());
            let mut resp_json = MockDropboxState::entry_json(&entry);
            if g.corrupt_upload_content_hash_once {
                g.corrupt_upload_content_hash_once = false;
                resp_json["content_hash"] = serde_json::Value::String("0".repeat(64));
            }
            json_resp(StatusCode::OK, resp_json)
        }
        "/2/files/download" => {
            let arg = match parse_api_arg(headers) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let path = arg["path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            let corrupt_body = if g.corrupt_download_body_once {
                g.corrupt_download_body_once = false;
                true
            } else {
                false
            };
            let Some(entry) = g.entries.get(&MockDropboxState::key(path)) else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "path/not_found/."}),
                );
            };
            let api_result = rship_backends::dropbox::encode_dropbox_api_arg(
                &MockDropboxState::entry_json(entry),
            );
            if let Some(range_hdr) = headers.get("range").and_then(|v| v.to_str().ok())
                && let Some(spec) = range_hdr.strip_prefix("bytes=")
                && let Some((s, e)) = spec.split_once('-')
            {
                let start: usize = s.parse().unwrap_or(0);
                let end: usize = e.parse().unwrap_or(entry.data.len().saturating_sub(1));
                let mut slice = entry.data[start..=end.min(entry.data.len() - 1)].to_vec();
                if corrupt_body && let Some(last) = slice.last_mut() {
                    *last ^= 0xFF;
                }
                return (
                    StatusCode::PARTIAL_CONTENT,
                    [("dropbox-api-result", api_result)],
                    slice,
                )
                    .into_response();
            }
            let mut full = entry.data.clone();
            if corrupt_body && let Some(last) = full.last_mut() {
                *last ^= 0xFF;
            }
            (StatusCode::OK, [("dropbox-api-result", api_result)], full).into_response()
        }
        "/2/files/upload_session/start" => {
            let _ = match parse_api_arg(headers) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let mut g = st.lock().unwrap();
            let sid = g.alloc_id("dbx-sess-");
            g.sessions.insert(
                sid.clone(),
                MockUploadSession {
                    data: body.to_vec(),
                },
            );
            json_resp(StatusCode::OK, serde_json::json!({"session_id": sid}))
        }
        "/2/files/upload_session/append_v2" => {
            let arg = match parse_api_arg(headers) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
            let offset = arg["cursor"]["offset"].as_u64().unwrap_or(0) as usize;
            let mut g = st.lock().unwrap();
            let Some(sess) = g.sessions.get_mut(sid) else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "not_found/.", "error": {".tag": "not_found"}}),
                );
            };
            if sess.data.len() != offset {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "error_summary": "incorrect_offset/.",
                        "error": { ".tag": "incorrect_offset", "correct_offset": sess.data.len() }
                    }),
                );
            }
            sess.data.extend_from_slice(&body);
            (StatusCode::OK, b"null".to_vec()).into_response()
        }
        "/2/files/upload_session/finish" => {
            let arg = match parse_api_arg(headers) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
            let offset = arg["cursor"]["offset"].as_u64().unwrap_or(0) as usize;
            let dst_path = arg["commit"]["path"].as_str().unwrap_or("");
            let mut g = st.lock().unwrap();
            g.seen_upload_args.push(arg.clone());
            if g.inject_content_hash_mismatch_once {
                g.inject_content_hash_mismatch_once = false;
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "error_summary": "content_hash_mismatch/.",
                        "error": {".tag": "content_hash_mismatch"}
                    }),
                );
            }
            let Some(sess) = g.sessions.get_mut(sid) else {
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({"error_summary": "lookup_failed/not_found/."}),
                );
            };
            if sess.data.len() != offset {
                let correct = sess.data.len();
                return json_resp(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "error_summary": "lookup_failed/incorrect_offset/.",
                        "error": { ".tag": "lookup_failed", "lookup_failed": { ".tag": "incorrect_offset", "correct_offset": correct } }
                    }),
                );
            }
            sess.data.extend_from_slice(&body);
            let final_data = g.sessions.remove(sid).unwrap().data;
            g.ensure_parents(dst_path);
            let id = g.alloc_id("id:file");
            let rev = g.alloc_id("rev");
            let client_modified = arg["commit"]["client_modified"]
                .as_str()
                .unwrap_or("2026-11-25T02:00:00Z")
                .to_string();
            let entry = MockEntry {
                id,
                path: dst_path.to_string(),
                is_folder: false,
                data: final_data,
                rev,
                client_modified,
            };
            g.entries
                .insert(MockDropboxState::key(dst_path), entry.clone());
            json_resp(StatusCode::OK, MockDropboxState::entry_json(&entry))
        }
        other => json_resp(
            StatusCode::NOT_FOUND,
            serde_json::json!({"error_summary": format!("unknown mock path {other}")}),
        ),
    }
}

pub(crate) async fn spawn_mock_dropbox() -> (String, Arc<Mutex<MockDropboxState>>) {
    let state = Arc::new(Mutex::new(MockDropboxState::new()));
    let app = Router::new()
        .fallback(handle_dropbox)
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

pub(crate) fn make_backend(base_url: &str) -> Arc<DropboxBackend> {
    let mut cfg = DropboxConfig::new("dropbox-test");
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    cfg.chunk_align_override = Some(64 * 1024);
    cfg.default_chunk_size = 64 * 1024;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("dropbox-test", "dbx-test-token"));
    Arc::new(DropboxBackend::new(cfg, auth, transport).unwrap())
}
