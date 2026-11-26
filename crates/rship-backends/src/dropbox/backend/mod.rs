//! Dropbox v2 API [`StorageBackend`] implementation with streaming uploads/downloads,
//! `incorrect_offset` crash-resume recovery, `too_many_write_operations` 429 retry,
//! server-side copy, batch delete, in-place rename, and storage quota.

mod ops;
mod transfer;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, StorageQuota,
    UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter, parse_retry_after};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::common::http::{
    HttpResponse, Idempotency, PolicyDecision, ReconcileAction, bearer_header_value,
    execute_with_policy_full,
};
use crate::dropbox::auth::DropboxAuthProvider;
use crate::dropbox::config::{DROPBOX_CHUNK_ALIGN_BYTES, DropboxConfig, MAX_DROPBOX_CHUNK_BYTES};
use crate::dropbox::hash::encode_dropbox_api_arg;

const HDR_DROPBOX_API_ARG: &str = "dropbox-api-arg";
const HDR_DROPBOX_API_PATH_ROOT: &str = "dropbox-api-path-root";
const HDR_DROPBOX_API_SELECT_USER: &str = "dropbox-api-select-user";

/// Build authenticated headers for a Dropbox JSON RPC request (`/2/...`), marking
/// `Authorization` as sensitive so credentials are never printed in debug logs.
pub fn build_rpc_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, bearer_header_value(token)?);
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(headers)
}

/// Build authenticated headers for a Dropbox Content API upload or 0-byte content RPC
/// (`/2/files/upload`, `/2/files/upload_session/*`), marking `Authorization` as sensitive.
pub fn build_content_upload_headers(
    token: &str,
    api_arg: &str,
    expected_len: u64,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, bearer_header_value(token)?);
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        HeaderName::from_static(HDR_DROPBOX_API_ARG),
        HeaderValue::from_str(api_arg)
            .map_err(|e| Error::protocol(format!("invalid Dropbox-API-Arg: {e}")))?,
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&expected_len.to_string()).expect("valid content-length"),
    );
    Ok(headers)
}

/// Build authenticated headers for a Dropbox Content API ranged download (`/2/files/download`),
/// marking `Authorization` as sensitive.
pub fn build_download_headers(
    token: &str,
    api_arg: &str,
    range_start: u64,
    range_end_inclusive: u64,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, bearer_header_value(token)?);
    headers.insert(
        HeaderName::from_static(HDR_DROPBOX_API_ARG),
        HeaderValue::from_str(api_arg)
            .map_err(|e| Error::protocol(format!("invalid Dropbox-API-Arg: {e}")))?,
    );
    headers.insert(
        http::header::RANGE,
        HeaderValue::from_str(&format!("bytes={range_start}-{range_end_inclusive}"))
            .expect("valid range header"),
    );
    Ok(headers)
}

struct DropboxInner {
    cfg: DropboxConfig,
    auth: Arc<dyn DropboxAuthProvider>,
    transport: HttpTransport,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    resolved_select_user: tokio::sync::OnceCell<Option<String>>,
}

#[derive(Clone)]
pub struct DropboxBackend {
    inner: Arc<DropboxInner>,
}

impl DropboxBackend {
    pub fn new(
        cfg: DropboxConfig,
        auth: Arc<dyn DropboxAuthProvider>,
        transport: HttpTransport,
    ) -> Result<Self> {
        let scope = LimiterScope::new(&cfg.remote_name, auth.principal().to_string());
        let rate_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), rate_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, rate_cfg);
        Ok(Self {
            inner: Arc::new(DropboxInner {
                cfg,
                auth,
                transport,
                control_limiter,
                data_limiter,
                resolved_select_user: tokio::sync::OnceCell::new(),
            }),
        })
    }

    pub fn control_limiter(&self) -> Arc<ScopedLimiter> {
        self.inner.control_limiter.clone()
    }

    pub fn data_limiter(&self) -> Arc<ScopedLimiter> {
        self.inner.data_limiter.clone()
    }

    fn rpc_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn content_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.inner.cfg.content_base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    async fn resolve_select_user(&self) -> Result<Option<String>> {
        let Some(raw) = self
            .inner
            .cfg
            .impersonate
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        if !raw.contains('@') || raw.starts_with("dbmid:") {
            return Ok(Some(raw.to_string()));
        }
        let cached = self
            .inner
            .resolved_select_user
            .get_or_try_init(|| async {
                let payload = Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "members": [{ ".tag": "email", "email": raw }]
                    }))
                    .map_err(|e| {
                        Error::protocol(format!("encode Dropbox team/members/get_info: {e}"))
                    })?,
                );
                let url = self.rpc_url("team/members/get_info");
                let policy_cfg = self.inner.cfg.retry_policy();
                let (status, headers, body) = execute_with_policy_full(
                    &self.inner.transport,
                    &self.inner.control_limiter,
                    "Dropbox team/members/get_info",
                    &policy_cfg,
                    Idempotency::Idempotent,
                    || {
                        let url = url.clone();
                        let payload = payload.clone();
                        async move {
                            let token = self.inner.auth.access_token().await?;
                            let headers = build_rpc_headers(&token)?;
                            let req = self
                                .inner
                                .transport
                                .control_client()
                                .post(&url)
                                .headers(headers)
                                .body(payload);
                            Ok((req, token))
                        }
                    },
                    |failed_token| async move {
                        let _ = self.inner.auth.force_refresh(&failed_token).await?;
                        Ok(true)
                    },
                    |resp| classify_dropbox_rpc_response("Dropbox team/members/get_info", resp),
                    |err| async move { Ok(ReconcileAction::Fail(err)) },
                )
                .await?;
                if !status.is_success() {
                    return Err(classify_dropbox_error(
                        "Dropbox team/members/get_info",
                        status,
                        &headers,
                        &body,
                    ));
                }
                let entries: Vec<serde_json::Value> =
                    serde_json::from_slice(&body).map_err(|e| {
                        Error::protocol(format!("parse Dropbox team/members/get_info: {e}"))
                    })?;
                let first = entries.first().ok_or_else(|| {
                    Error::not_found(format!("Dropbox team member `{raw}` not found"))
                })?;
                if first.get(".tag").and_then(|t| t.as_str()) != Some("member_info") {
                    return Err(Error::not_found(format!(
                        "Dropbox team member `{raw}` lookup failed: {first}"
                    )));
                }
                let member_id = first
                    .get("profile")
                    .and_then(|p| p.get("team_member_id"))
                    .and_then(|id| id.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        Error::protocol(format!(
                            "Dropbox team/members/get_info missing profile.team_member_id for `{raw}`"
                        ))
                    })?;
                Ok(Some(member_id.to_string()))
            })
            .await?;
        Ok(cached.clone())
    }

    fn apply_team_headers(
        &self,
        headers: &mut HeaderMap,
        include_path_root: bool,
        select_user: Option<&str>,
    ) -> Result<()> {
        if include_path_root
            && let Some(raw_ns) = self.inner.cfg.root_namespace.as_deref()
            && let Some(val) = format_path_root_header(raw_ns)
        {
            headers.insert(
                HeaderName::from_static(HDR_DROPBOX_API_PATH_ROOT),
                HeaderValue::from_str(&val)
                    .map_err(|e| Error::config(format!("invalid Dropbox-API-Path-Root: {e}")))?,
            );
        }
        if let Some(uid) = select_user {
            headers.insert(
                HeaderName::from_static(HDR_DROPBOX_API_SELECT_USER),
                HeaderValue::from_str(uid)
                    .map_err(|e| Error::config(format!("invalid Dropbox-API-Select-User: {e}")))?,
            );
        }
        Ok(())
    }

    /// Execute an authenticated Dropbox JSON RPC POST (`/2/...`) through the shared
    /// retry/rate-limit policy engine with single-flight `401` refresh, transport-error
    /// retries, `429`/`503`/`5xx` backoff, and exact retry-quota accounting.
    async fn rpc_post(
        &self,
        context: &str,
        endpoint: &str,
        body_json: serde_json::Value,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.execute_rpc_post(context, endpoint, body_json, None)
            .await
    }

    async fn execute_rpc_post(
        &self,
        context: &str,
        endpoint: &str,
        body_json: serde_json::Value,
        request_timeout: Option<Duration>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.dropbox_request(
            context,
            DropboxCall::rpc(endpoint, &body_json)?,
            request_timeout,
            Idempotency::Idempotent,
            |resp| classify_dropbox_rpc_response(context, resp).map_ok(DbxOutcome::Response),
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
        .and_then(DbxOutcome::into_response)
    }

    /// Execute a 0-byte Dropbox Content API control RPC (`upload_session/start`,
    /// `upload_session/append_v2` probe, or `upload_session/finish` commit) through the
    /// shared control-plane retry/auth policy engine.
    async fn content_rpc_post(
        &self,
        context: &str,
        endpoint: &str,
        api_arg: &serde_json::Value,
        request_timeout: Option<Duration>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.dropbox_request(
            context,
            DropboxCall::content(endpoint, api_arg),
            request_timeout,
            Idempotency::Idempotent,
            |resp| classify_dropbox_rpc_response(context, resp).map_ok(DbxOutcome::Response),
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
        .and_then(DbxOutcome::into_response)
    }

    /// Run one Dropbox RPC (`/2/...` JSON or 0-byte Content API call) under the shared
    /// retry policy with single-flight `401` refresh. NON-idempotent commits pass
    /// [`Idempotency::NonIdempotent`] and a `reconcile` hook that must prove the commit is
    /// ours before resolving.
    async fn dropbox_request<ClassifyFn, RecFn, RecFut>(
        &self,
        context: &str,
        call: DropboxCall,
        request_timeout: Option<Duration>,
        idempotency: Idempotency,
        mut classify: ClassifyFn,
        reconcile: RecFn,
    ) -> Result<DbxOutcome>
    where
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<DbxOutcome>,
        RecFn: FnMut(Error) -> RecFut,
        RecFut: std::future::Future<Output = Result<ReconcileAction<DbxOutcome>>>,
    {
        let mut policy_cfg = self.inner.cfg.retry_policy();
        if let Some(timeout) = request_timeout {
            policy_cfg = policy_cfg.with_request_timeout(timeout);
        }
        let url = match &call {
            DropboxCall::Rpc { endpoint, .. } => self.rpc_url(endpoint),
            DropboxCall::Content { endpoint, .. } => self.content_url(endpoint),
        };
        let include_path_root = call.include_path_root();
        let select_user = self.resolve_select_user().await?;

        execute_with_policy_full(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            idempotency,
            || {
                let url = url.clone();
                let call = &call;
                let select_user = select_user.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let (mut headers, body) = match call {
                        DropboxCall::Rpc { payload, .. } => {
                            (build_rpc_headers(&token)?, payload.clone())
                        }
                        DropboxCall::Content { arg_header, .. } => (
                            build_content_upload_headers(&token, arg_header, 0)?,
                            Bytes::new(),
                        ),
                    };
                    self.apply_team_headers(
                        &mut headers,
                        include_path_root,
                        select_user.as_deref(),
                    )?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .post(&url)
                        .headers(headers)
                        .body(body);
                    Ok((req, token))
                }
            },
            |failed_token| async move {
                let _ = self.inner.auth.force_refresh(&failed_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                classify(resp)
            },
            reconcile,
        )
        .await
    }

    /// Raw `get_metadata` of an API path (`None` when it does not exist).
    async fn get_meta(&self, api_path: &str) -> Result<Option<DropboxMeta>> {
        let (status, headers, body) = self
            .rpc_post(
                "Dropbox get_metadata",
                "files/get_metadata",
                serde_json::json!({ "path": api_path }),
            )
            .await?;
        if status == StatusCode::CONFLICT {
            if DropboxApiError::parse(&body).is_not_found() {
                return Ok(None);
            }
            return Err(classify_dropbox_error(
                "Dropbox get_metadata",
                status,
                &headers,
                &body,
            ));
        }
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| Error::protocol(format!("parse Dropbox get_metadata: {e}")))
    }

    fn entry_from_meta(&self, meta: DropboxMeta) -> Option<Entry> {
        if meta.is_downloadable == Some(false) {
            return None;
        }
        let kind = match meta.tag.as_str() {
            "file" => EntryKind::File,
            "folder" => EntryKind::Directory,
            _ => return None,
        };
        let mtime_ns = parse_meta_mtime_ns(&meta);
        let raw_full = meta.path_display.unwrap_or(meta.path_lower);
        let stripped = strip_root_path(&raw_full, &self.inner.cfg.root_path)?;
        if stripped.is_empty() {
            return None;
        }
        let nfc_path = RelPath::parse(&stripped).ok()?;
        Some(Entry {
            node_id: meta.id.map(rship_core::types::NodeId),
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&nfc_path, &stripped),
            nfc_path,
            kind,
            size: if kind == EntryKind::File {
                meta.size.unwrap_or(0)
            } else {
                0
            },
            mtime_ns,
            ctime_ns: None,
            etag: meta.rev,
            // Note: Dropbox's native `content_hash` is a 4 MiB SHA-256 block tree, NOT flat SHA-256.
            checksum: None,
        })
    }
}

/// One Dropbox RPC: a `/2/...` JSON call or a 0-byte Content API call (`Dropbox-API-Arg`).
enum DropboxCall {
    Rpc {
        endpoint: String,
        payload: Bytes,
    },
    Content {
        endpoint: String,
        arg_header: String,
    },
}

impl DropboxCall {
    fn rpc(endpoint: &str, body_json: &serde_json::Value) -> Result<Self> {
        let payload = serde_json::to_vec(body_json)
            .map_err(|e| Error::protocol(format!("encode Dropbox RPC `{endpoint}`: {e}")))?;
        Ok(Self::Rpc {
            endpoint: endpoint.to_string(),
            payload: Bytes::from(payload),
        })
    }

    fn content(endpoint: &str, api_arg: &serde_json::Value) -> Self {
        Self::Content {
            endpoint: endpoint.to_string(),
            arg_header: encode_dropbox_api_arg(api_arg),
        }
    }

    fn include_path_root(&self) -> bool {
        let endpoint = match self {
            Self::Rpc { endpoint, .. } | Self::Content { endpoint, .. } => endpoint.as_str(),
        };
        endpoint.starts_with("files/") || endpoint.starts_with("sharing/")
    }
}

/// A Dropbox RPC reply, or the metadata a reconcile proved to be this commit's result.
enum DbxOutcome {
    Response((StatusCode, HeaderMap, Bytes)),
    Reconciled(DropboxMeta),
}

impl DbxOutcome {
    fn into_response(self) -> Result<(StatusCode, HeaderMap, Bytes)> {
        match self {
            Self::Response(r) => Ok(r),
            // Only non-idempotent commits (which pass a real reconcile hook) can resolve.
            Self::Reconciled(_) => Err(Error::protocol(
                "Dropbox RPC unexpectedly resolved through reconcile",
            )),
        }
    }
}

/// Typed representation of structured Dropbox API v2 error payloads (`.tag` tree +
/// slash-separated `error_summary` segments), replacing ad-hoc substring checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DropboxApiError {
    NotFound {
        summary: String,
    },
    FromNotFound {
        summary: String,
    },
    ToConflict {
        summary: String,
    },
    FolderConflict {
        summary: String,
    },
    ContentHashMismatch {
        summary: String,
    },
    InsufficientSpace {
        summary: String,
    },
    RateLimited {
        retry_after: Option<Duration>,
        summary: String,
    },
    IncorrectOffset {
        correct_offset: u64,
        summary: String,
    },
    SessionExpired {
        summary: String,
    },
    InvalidAsyncJobId {
        summary: String,
    },
    Other {
        summary: String,
    },
}

impl DropboxApiError {
    pub(super) fn parse(body: &[u8]) -> Self {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Self::Other {
                summary: String::from_utf8_lossy(body).trim().to_string(),
            };
        };
        let summary = v
            .get("error_summary")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        let top_retry = parse_json_retry_after(&v);
        if let Some(err_val) = v.get("error") {
            let mut parsed = Self::from_error_value_with_top_retry(err_val, &summary, top_retry);
            if !matches!(parsed, Self::Other { .. }) {
                if let Self::RateLimited { retry_after, .. } = &mut parsed
                    && retry_after.is_none()
                {
                    *retry_after = top_retry;
                }
                return parsed;
            }
        }
        Self::from_summary(&summary, top_retry)
    }

    pub(super) fn from_error_value(err_val: &serde_json::Value, summary: &str) -> Self {
        Self::from_error_value_with_top_retry(err_val, summary, None)
    }

    fn from_error_value_with_top_retry(
        err_val: &serde_json::Value,
        summary: &str,
        top_retry: Option<Duration>,
    ) -> Self {
        let mut tags = Vec::new();
        let mut retry_after = parse_json_retry_after(err_val).or(top_retry);
        let mut correct_offset = None;
        let mut cur = err_val;
        for _ in 0..8 {
            if let Some(r) = parse_json_retry_after(cur) {
                retry_after = Some(r);
            }
            if let Some(off) = cur.get("correct_offset").and_then(|n| n.as_u64()) {
                correct_offset = Some(off);
            }
            let Some(tag) = cur.get(".tag").and_then(|t| t.as_str()) else {
                break;
            };
            tags.push(tag);
            if let Some(next) = cur.get(tag) {
                cur = next;
            } else {
                break;
            }
        }
        let summary_owned = if summary.is_empty() {
            tags.join("/")
        } else {
            summary.to_string()
        };
        let summary_segs = summary_segments(summary);

        if tags.last() == Some(&"incorrect_offset")
            && let Some(off) = correct_offset
        {
            return Self::IncorrectOffset {
                correct_offset: off,
                summary: summary_owned,
            };
        }
        if tags.contains(&"too_many_write_operations") || tags.contains(&"too_many_requests") {
            return Self::RateLimited {
                retry_after,
                summary: summary_owned,
            };
        }
        if tags.contains(&"content_hash_mismatch") {
            return Self::ContentHashMismatch {
                summary: summary_owned,
            };
        }
        if tags.contains(&"insufficient_space") {
            return Self::InsufficientSpace {
                summary: summary_owned,
            };
        }
        if tags.first() == Some(&"invalid_async_job_id") {
            return Self::InvalidAsyncJobId {
                summary: summary_owned,
            };
        }
        if tags.as_slice() == ["path", "conflict", "folder"]
            || (tags.as_slice() == ["path", "conflict"]
                && summary_segs.starts_with(&["path", "conflict", "folder"]))
        {
            return Self::FolderConflict {
                summary: summary_owned,
            };
        }
        if tags.starts_with(&["to", "conflict"]) {
            return Self::ToConflict {
                summary: summary_owned,
            };
        }
        if tags.starts_with(&["from_lookup", "not_found"]) {
            return Self::FromNotFound {
                summary: summary_owned,
            };
        }
        if matches!(
            tags.as_slice(),
            ["not_found"]
                | ["closed"]
                | ["not_closed"]
                | ["lookup_failed", "not_found"]
                | ["lookup_failed", "closed"]
                | ["lookup_failed", "not_closed"]
        ) {
            return Self::SessionExpired {
                summary: summary_owned,
            };
        }
        if matches!(
            tags.as_slice(),
            ["path", "not_found"] | ["path_lookup", "not_found"]
        ) {
            return Self::NotFound {
                summary: summary_owned,
            };
        }
        Self::from_summary(&summary_owned, retry_after)
    }

    fn from_summary(summary: &str, top_retry: Option<Duration>) -> Self {
        let segs = summary_segments(summary);
        let summary_owned = summary.to_string();
        if matches!(
            segs.first().copied(),
            Some("too_many_write_operations" | "too_many_requests")
        ) {
            return Self::RateLimited {
                retry_after: top_retry,
                summary: summary_owned,
            };
        }
        if segs.contains(&"content_hash_mismatch") {
            return Self::ContentHashMismatch {
                summary: summary_owned,
            };
        }
        if segs.contains(&"insufficient_space") {
            return Self::InsufficientSpace {
                summary: summary_owned,
            };
        }
        if segs.first() == Some(&"invalid_async_job_id") {
            return Self::InvalidAsyncJobId {
                summary: summary_owned,
            };
        }
        if segs.starts_with(&["path", "conflict", "folder"]) {
            return Self::FolderConflict {
                summary: summary_owned,
            };
        }
        if segs.starts_with(&["to", "conflict"]) {
            return Self::ToConflict {
                summary: summary_owned,
            };
        }
        if segs.starts_with(&["from_lookup", "not_found"]) {
            return Self::FromNotFound {
                summary: summary_owned,
            };
        }
        if matches!(
            segs.as_slice(),
            ["not_found"]
                | ["closed"]
                | ["not_closed"]
                | ["lookup_failed", "not_found"]
                | ["lookup_failed", "closed"]
                | ["lookup_failed", "not_closed"]
        ) {
            return Self::SessionExpired {
                summary: summary_owned,
            };
        }
        if matches!(
            segs.as_slice(),
            ["path", "not_found"] | ["path_lookup", "not_found"]
        ) {
            return Self::NotFound {
                summary: summary_owned,
            };
        }
        Self::Other {
            summary: summary_owned,
        }
    }

    pub(super) fn summary(&self) -> &str {
        match self {
            Self::NotFound { summary }
            | Self::FromNotFound { summary }
            | Self::ToConflict { summary }
            | Self::FolderConflict { summary }
            | Self::ContentHashMismatch { summary }
            | Self::InsufficientSpace { summary }
            | Self::RateLimited { summary, .. }
            | Self::IncorrectOffset { summary, .. }
            | Self::SessionExpired { summary }
            | Self::InvalidAsyncJobId { summary }
            | Self::Other { summary } => summary,
        }
    }

    pub(super) fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. } | Self::FromNotFound { .. })
    }

    pub(super) fn is_session_expired(&self) -> bool {
        matches!(self, Self::SessionExpired { .. })
    }

    pub(super) fn is_throttled(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    pub(super) fn incorrect_offset(&self) -> Option<u64> {
        match self {
            Self::IncorrectOffset { correct_offset, .. } => Some(*correct_offset),
            _ => None,
        }
    }
}

fn summary_segments(summary: &str) -> Vec<&str> {
    summary
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.chars().all(|c| c == '.'))
        .collect()
}

fn parse_json_retry_after(v: &serde_json::Value) -> Option<Duration> {
    let field = v.get("retry_after")?;
    if let Some(secs) = field.as_u64() {
        return Some(Duration::from_secs(secs));
    }
    if let Some(secs) = field.as_f64()
        && secs.is_finite()
        && secs >= 0.0
    {
        return Some(Duration::from_secs_f64(secs));
    }
    None
}

fn nonzero_retry_floor() -> Duration {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hash = std::hash::BuildHasher::hash_one(&std::collections::hash_map::RandomState::new(), n);
    Duration::from_millis(50 + (hash % 201))
}

fn apply_nonzero_retry_floor(retry_after: Option<Duration>) -> Option<Duration> {
    match retry_after {
        Some(d) if d.is_zero() => Some(nonzero_retry_floor()),
        other => other,
    }
}

fn format_path_root_header(raw: &str) -> Option<String> {
    let ns = raw.trim();
    if ns.is_empty() {
        return None;
    }
    if ns.starts_with('{') {
        return Some(ns.to_string());
    }
    if ns.eq_ignore_ascii_case("home") {
        return Some(r#"{".tag":"home"}"#.to_string());
    }
    if let Some(root_id) = ns.strip_prefix("root:") {
        return Some(serde_json::json!({ ".tag": "root", "root": root_id }).to_string());
    }
    let nsid = ns
        .strip_prefix("ns:")
        .or_else(|| ns.strip_prefix("namespace_id:"))
        .unwrap_or(ns);
    Some(serde_json::json!({ ".tag": "namespace_id", "namespace_id": nsid }).to_string())
}

#[derive(Debug, Clone, Deserialize)]
struct DropboxMeta {
    #[serde(rename = ".tag")]
    tag: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path_lower: String,
    #[serde(default)]
    path_display: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    rev: Option<String>,
    #[serde(default)]
    client_modified: Option<String>,
    #[serde(default)]
    server_modified: Option<String>,
    #[serde(default)]
    content_hash: Option<String>,
    #[serde(default)]
    is_downloadable: Option<bool>,
}

fn parse_meta_mtime_ns(meta: &DropboxMeta) -> i64 {
    meta.client_modified
        .as_deref()
        .or(meta.server_modified.as_deref())
        .and_then(rship_core::time::parse_rfc3339_to_nanos)
        .unwrap_or(0)
}

pub(super) fn unicode_fold_segment(seg: &str) -> String {
    RelPath::parse(seg)
        .map(|r| r.fold_key())
        .unwrap_or_else(|_| seg.to_lowercase())
}

pub(super) fn unicode_eq_ignore_case(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let a_segs: Vec<&str> = a
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let b_segs: Vec<&str> = b
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if a_segs.len() != b_segs.len() {
        return false;
    }
    a_segs
        .iter()
        .zip(b_segs.iter())
        .all(|(sa, sb)| sa == sb || unicode_fold_segment(sa) == unicode_fold_segment(sb))
}

fn strip_root_path(api_path: &str, root_path: &str) -> Option<String> {
    let clean = api_path.trim_matches('/');
    let root = root_path.trim_matches('/');
    if root.is_empty() {
        return Some(clean.to_string());
    }
    let clean_segs: Vec<&str> = clean.split('/').collect();
    let root_segs: Vec<&str> = root.split('/').collect();
    if clean_segs.len() < root_segs.len() {
        return None;
    }
    for (cs, rs) in clean_segs.iter().zip(root_segs.iter()) {
        if cs != rs && unicode_fold_segment(cs) != unicode_fold_segment(rs) {
            return None;
        }
    }
    Some(clean_segs[root_segs.len()..].join("/"))
}

fn classify_dropbox_rpc_response(
    context: &str,
    resp: HttpResponse,
) -> PolicyDecision<(StatusCode, HeaderMap, Bytes)> {
    if resp.status == StatusCode::UNAUTHORIZED {
        return PolicyDecision::AuthRefresh;
    }
    if resp.status.is_success()
        || (resp.status == StatusCode::CONFLICT
            && !DropboxApiError::parse(&resp.body).is_throttled())
    {
        return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
    }
    PolicyDecision::from_error(classify_dropbox_error(
        context,
        resp.status,
        &resp.headers,
        &resp.body,
    ))
}

fn classify_dropbox_error(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Error {
    let text = String::from_utf8_lossy(body);
    let api_err = DropboxApiError::parse(body);
    let json_retry_after = match &api_err {
        DropboxApiError::RateLimited { retry_after, .. } => *retry_after,
        _ => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(parse_json_retry_after)
                    .or_else(|| parse_json_retry_after(&v))
            }),
    };
    let retry_after =
        apply_nonzero_retry_floor(json_retry_after.or_else(|| parse_retry_after(headers)));

    if status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::SERVICE_UNAVAILABLE
        || api_err.is_throttled()
    {
        return Error::rate_limited(
            format!(
                "{context}: Dropbox rate limited (HTTP {}): {}",
                status.as_u16(),
                text.trim()
            ),
            retry_after,
        );
    }
    if matches!(api_err, DropboxApiError::ContentHashMismatch { .. }) {
        let msg = if api_err.summary().is_empty() {
            text.trim()
        } else {
            api_err.summary()
        };
        return Error::integrity(format!(
            "{context}: Dropbox content_hash mismatch (HTTP {}): {msg}",
            status.as_u16()
        ));
    }
    if status == StatusCode::REQUEST_TIMEOUT {
        let mut e = Error::new(
            ErrorKind::Timeout,
            RetryClass::Retryable,
            format!("{context}: HTTP {}: {}", status.as_u16(), text.trim()),
        );
        if let Some(ra) = retry_after {
            e = e.with_retry_after(ra);
        }
        return e;
    }
    if matches!(api_err, DropboxApiError::InsufficientSpace { .. }) {
        return Error::new(
            ErrorKind::QuotaExceeded,
            RetryClass::Permanent,
            format!("{context}: Dropbox storage quota exceeded"),
        );
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Error::new(
            ErrorKind::PermissionDenied,
            RetryClass::Permanent,
            format!("{context}: HTTP {}: {}", status.as_u16(), text.trim()),
        );
    }
    if status.is_server_error() {
        let mut e = Error::new(
            ErrorKind::Network,
            RetryClass::Retryable,
            format!("{context}: HTTP {}: {}", status.as_u16(), text.trim()),
        );
        if let Some(ra) = retry_after {
            e = e.with_retry_after(ra);
        }
        return e;
    }
    Error::protocol(format!(
        "{context}: HTTP {}: {}",
        status.as_u16(),
        text.trim()
    ))
}

#[async_trait]
impl StorageBackend for DropboxBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "dropbox"
    }

    fn endpoint_identity(&self) -> String {
        let base = format!(
            "dropbox://{}/{}",
            self.inner.auth.principal(),
            self.inner.cfg.root_path.trim_matches('/')
        );
        let ns = self
            .inner
            .cfg
            .root_namespace
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let imp = self
            .inner
            .cfg
            .impersonate
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (ns, imp) {
            (None, None) => base,
            (Some(n), None) => format!("{base}?ns={n}"),
            (None, Some(u)) => format!("{base}?user={u}"),
            (Some(n), Some(u)) => format!("{base}?ns={n}&user={u}"),
        }
    }

    fn capabilities(&self) -> Capabilities {
        let align = self
            .inner
            .cfg
            .chunk_align_override
            .unwrap_or(DROPBOX_CHUNK_ALIGN_BYTES);
        Capabilities {
            hashes: vec![],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: align,
                max_chunk_bytes: Some(MAX_DROPBOX_CHUNK_BYTES),
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self.inner.cfg.default_chunk_size,
            allows_duplicate_names: false,
            case_sensitive: false,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        self.stat_impl(path).await
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_stream_impl(prefix, recursive).await
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        self.mkdir_impl(path).await
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.delete_impl(path).await
    }

    async fn delete_batch(&self, paths: &[BackendPath]) -> Result<Vec<(BackendPath, Error)>> {
        self.delete_batch_impl(paths).await
    }

    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
    }

    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.open_read_impl(path, range).await
    }

    async fn open_read_entry(
        &self,
        entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        self.open_read_entry_impl(entry, path, range).await
    }

    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.put_single_shot_impl(init, body).await
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.begin_upload_impl(init).await
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        self.query_upload_impl(op).await
    }

    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
        self.upload_chunk_impl(op, chunk).await
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        self.finish_upload_impl(op, parts).await
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.abort_upload_impl(op).await
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.reconcile_operation_impl(op).await
    }

    fn can_server_side_copy_from(&self, src_endpoint: &str) -> bool {
        self.can_server_side_copy_from_impl(src_endpoint)
    }

    async fn server_side_copy(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        self.server_side_copy_impl(src_endpoint, src_path, init)
            .await
    }

    async fn rename(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        self.rename_impl(path, new_name).await
    }

    async fn about(&self) -> Result<Option<StorageQuota>> {
        self.about_impl().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropbox_request_authorization_headers_are_marked_sensitive() {
        let secret = "sl.dropbox-super-secret-bearer-token";

        let rpc_hdrs = build_rpc_headers(secret).expect("rpc headers");
        let rpc_auth = rpc_hdrs
            .get(http::header::AUTHORIZATION)
            .expect("rpc Authorization");
        assert!(rpc_auth.is_sensitive());
        assert_eq!(rpc_auth.to_str().unwrap(), format!("Bearer {secret}"));
        assert!(!format!("{rpc_auth:?}").contains(secret));

        let upload_hdrs =
            build_content_upload_headers(secret, r#"{"path":"/a.bin"}"#, 128).expect("upload hdrs");
        let upload_auth = upload_hdrs
            .get(http::header::AUTHORIZATION)
            .expect("upload Authorization");
        assert!(upload_auth.is_sensitive());
        assert_eq!(upload_auth.to_str().unwrap(), format!("Bearer {secret}"));
        assert!(!format!("{upload_auth:?}").contains(secret));

        let dl_hdrs =
            build_download_headers(secret, r#"{"path":"/a.bin"}"#, 0, 127).expect("download hdrs");
        let dl_auth = dl_hdrs
            .get(http::header::AUTHORIZATION)
            .expect("download Authorization");
        assert!(dl_auth.is_sensitive());
        assert_eq!(dl_auth.to_str().unwrap(), format!("Bearer {secret}"));
        assert!(!format!("{dl_auth:?}").contains(secret));

        let bad_err = build_rpc_headers("leaked-secret\r\nX-Injected: 1").unwrap_err();
        assert_eq!(bad_err.kind, ErrorKind::Protocol);
        assert!(!bad_err.message().contains("leaked-secret"));
    }

    #[test]
    fn classifies_429_503_408_and_non_throttled_5xx() {
        let mut hdrs_429 = HeaderMap::new();
        hdrs_429.insert(http::header::RETRY_AFTER, HeaderValue::from_static("9"));
        let e429 = classify_dropbox_error(
            "ctx",
            StatusCode::TOO_MANY_REQUESTS,
            &hdrs_429,
            br#"{"error_summary":"too_many_write_operations/."}"#,
        );
        assert_eq!(e429.kind, ErrorKind::RateLimited);
        assert_eq!(e429.retry, RetryClass::Throttled);
        assert!(e429.is_throttled());
        assert_eq!(e429.retry_after, Some(Duration::from_secs(9)));

        // JSON `error.retry_after` takes precedence over header.
        let e429_json = classify_dropbox_error(
            "ctx",
            StatusCode::TOO_MANY_REQUESTS,
            &hdrs_429,
            br#"{"error_summary":"too_many_requests/.","error":{"retry_after":42}}"#,
        );
        assert_eq!(e429_json.retry_after, Some(Duration::from_secs(42)));
        assert!(e429_json.is_throttled());

        // 503 is classified as Throttled (RateLimited) and preserves Retry-After.
        let e503 = classify_dropbox_error("ctx", StatusCode::SERVICE_UNAVAILABLE, &hdrs_429, b"");
        assert_eq!(e503.kind, ErrorKind::RateLimited);
        assert_eq!(e503.retry, RetryClass::Throttled);
        assert!(e503.is_throttled());
        assert_eq!(e503.retry_after, Some(Duration::from_secs(9)));

        // 500/502/504 are Retryable Network errors without tripping CUBIC throttle.
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = classify_dropbox_error("ctx", status, &HeaderMap::new(), b"server error");
            assert_eq!(err.kind, ErrorKind::Network);
            assert_eq!(err.retry, RetryClass::Retryable);
            assert!(!err.is_throttled());
        }

        // 408 is Retryable Timeout without tripping CUBIC throttle.
        let e408 =
            classify_dropbox_error("ctx", StatusCode::REQUEST_TIMEOUT, &HeaderMap::new(), b"");
        assert_eq!(e408.kind, ErrorKind::Timeout);
        assert_eq!(e408.retry, RetryClass::Retryable);
        assert!(!e408.is_throttled());

        // 409 domain errors pass through `classify_dropbox_rpc_response` as `Ok`, whereas
        // 409 lock-contention (`too_many_write_operations`) retries.
        let not_found_decision = classify_dropbox_rpc_response(
            "ctx",
            HttpResponse {
                status: StatusCode::CONFLICT,
                headers: HeaderMap::new(),
                body: Bytes::from_static(br#"{"error_summary":"path/not_found/."}"#),
            },
        );
        assert!(matches!(
            not_found_decision,
            PolicyDecision::Ok((StatusCode::CONFLICT, _, _))
        ));

        let lock_decision = classify_dropbox_rpc_response(
            "ctx",
            HttpResponse {
                status: StatusCode::CONFLICT,
                headers: HeaderMap::new(),
                body: Bytes::from_static(br#"{"error_summary":"too_many_write_operations/."}"#),
            },
        );
        assert!(matches!(lock_decision, PolicyDecision::Retry(ref e) if e.is_throttled()));

        let unauth_decision = classify_dropbox_rpc_response(
            "ctx",
            HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: HeaderMap::new(),
                body: Bytes::from_static(br#"{"error_summary":"expired_access_token/."}"#),
            },
        );
        assert!(matches!(unauth_decision, PolicyDecision::AuthRefresh));
    }

    #[test]
    fn dropbox_api_error_parses_structured_variants_and_maps_integrity() {
        let hash_err = classify_dropbox_error(
            "upload",
            StatusCode::CONFLICT,
            &HeaderMap::new(),
            br#"{"error_summary":"content_hash_mismatch/.","error":{".tag":"content_hash_mismatch"}}"#,
        );
        assert_eq!(hash_err.kind, ErrorKind::Integrity);
        assert_eq!(hash_err.retry, RetryClass::Integrity);

        let nested_off = DropboxApiError::parse(
            br#"{"error_summary":"lookup_failed/incorrect_offset/.","error":{".tag":"lookup_failed","lookup_failed":{".tag":"incorrect_offset","correct_offset":131072}}}"#,
        );
        assert_eq!(nested_off.incorrect_offset(), Some(131_072));

        let folder_conflict = DropboxApiError::parse(
            br#"{"error_summary":"path/conflict/folder/.","error":{".tag":"path","path":{".tag":"conflict"}}}"#,
        );
        assert!(matches!(
            folder_conflict,
            DropboxApiError::FolderConflict { .. }
        ));

        // Filenames containing "not_found" or "closed" inside unrelated errors must not false-positive.
        let false_pos =
            DropboxApiError::parse(br#"{"error_summary":"other_error/not_found_closed.txt"}"#);
        assert!(!false_pos.is_not_found());
        assert!(!false_pos.is_session_expired());
        assert!(!false_pos.is_throttled());
    }

    #[test]
    fn dropbox_api_error_from_summary_handles_dot_truncation_tails() {
        for payload in [
            br#"{"error_summary":"path/not_found/."}"#.as_slice(),
            br#"{"error_summary":"path/not_found/.."}"#.as_slice(),
            br#"{"error_summary":"path/not_found/..."}"#.as_slice(),
            br#"{"error_summary":"path_lookup/not_found/..."}"#.as_slice(),
        ] {
            let parsed = DropboxApiError::parse(payload);
            assert!(
                parsed.is_not_found(),
                "expected NotFound for {}: got {parsed:?}",
                String::from_utf8_lossy(payload)
            );
        }

        let expired = DropboxApiError::parse(br#"{"error_summary":"lookup_failed/not_found/..."}"#);
        assert!(
            expired.is_session_expired(),
            "expected SessionExpired for lookup_failed/not_found/..., got {expired:?}"
        );

        let filename_false_pos = DropboxApiError::parse(
            br#"{"error_summary":"other_error/not_found_closed_incorrect_offset.txt"}"#,
        );
        assert!(!filename_false_pos.is_not_found());
        assert!(!filename_false_pos.is_session_expired());
        assert!(!filename_false_pos.is_throttled());
        assert_eq!(filename_false_pos.incorrect_offset(), None);
    }

    #[test]
    fn retry_after_zero_applies_nonzero_jitter_floor() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("0"));
        let e_hdr = classify_dropbox_error("ctx", StatusCode::TOO_MANY_REQUESTS, &hdrs, b"");
        let ra_hdr = e_hdr.retry_after.expect("retry_after must stay Some");
        assert!(
            ra_hdr >= Duration::from_millis(50) && ra_hdr <= Duration::from_millis(250),
            "expected nonzero jitter floor, got {ra_hdr:?}"
        );

        let e_json = classify_dropbox_error(
            "ctx",
            StatusCode::TOO_MANY_REQUESTS,
            &HeaderMap::new(),
            br#"{"error_summary":"too_many_write_operations/.","error":{".tag":"too_many_write_operations","retry_after":0}}"#,
        );
        let ra_json = e_json.retry_after.expect("retry_after must stay Some");
        assert!(
            ra_json >= Duration::from_millis(50) && ra_json <= Duration::from_millis(250),
            "expected nonzero jitter floor, got {ra_json:?}"
        );
    }

    #[test]
    fn strip_root_path_handles_unicode_case_folding_and_expanding_chars() {
        assert_eq!(
            strip_root_path("/Café/ sub /a.txt", "/café"),
            Some(" sub /a.txt".to_string())
        );
        // Expanding ('İ' 2 bytes -> "i\u{307}" 3 bytes) and shrinking ('ẞ' 3 bytes -> "ß" 2 bytes)
        // case-folds must never panic or corrupt remainder.
        assert_eq!(
            strip_root_path("/İstanbul/Nested/file.txt", "/i\u{307}stanbul"),
            Some("Nested/file.txt".to_string())
        );
        assert_eq!(
            strip_root_path("/ẞ/file.txt", "/ß"),
            Some("file.txt".to_string())
        );
        assert_eq!(
            strip_root_path("/Straße/file.txt", "/straße"),
            Some("file.txt".to_string())
        );
        assert_eq!(strip_root_path("/café", "/Café"), Some(String::new()));
        assert_eq!(strip_root_path("/other/file.txt", "/café"), None);
    }

    #[test]
    fn format_path_root_header_handles_ns_home_root_and_json() {
        let parsed: serde_json::Value =
            serde_json::from_str(&format_path_root_header("ns:12345").unwrap()).unwrap();
        assert_eq!(parsed[".tag"], "namespace_id");
        assert_eq!(parsed["namespace_id"], "12345");

        let plain: serde_json::Value =
            serde_json::from_str(&format_path_root_header("98765").unwrap()).unwrap();
        assert_eq!(plain[".tag"], "namespace_id");
        assert_eq!(plain["namespace_id"], "98765");

        assert_eq!(
            format_path_root_header("home").as_deref(),
            Some(r#"{".tag":"home"}"#)
        );
        let root_tag: serde_json::Value =
            serde_json::from_str(&format_path_root_header("root:7").unwrap()).unwrap();
        assert_eq!(root_tag[".tag"], "root");
        assert_eq!(root_tag["root"], "7");
        assert_eq!(
            format_path_root_header(r#"{".tag":"root","root":"9"}"#).as_deref(),
            Some(r#"{".tag":"root","root":"9"}"#)
        );
    }
}
