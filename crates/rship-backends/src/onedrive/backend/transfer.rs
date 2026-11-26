//! OneDrive data-plane streaming downloads (`RemoteRangeReadable`), single-shot
//! `PUT /content` uploads with QuickXorHash/SHA-256 verification and mtime patching,
//! 320 KiB-aligned `createUploadSession` resumable uploads (`nextExpectedRanges`) with a
//! running QuickXorHash, and reconciliation.

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::OperationRecord;
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex as StdMutex};

use crate::common::http::{
    Idempotency, PolicyDecision, execute_with_policy, send_watched_sized_upload_with_capture,
};
use crate::common::reconcile::{PreOpState, judge_reconciled_object};
use crate::common::{
    BoundedSessionMap, ExactDownloadStream, Sha256Hasher, StreamingHashStream, StrictBodyStream,
    VerifyingDownloadStream, checksum_mismatch_error, lock_unpoisoned,
};
use crate::onedrive::config::{MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES};
use crate::onedrive::quickxor::{QuickXorHasher, QuickXorState};

/// Running QuickXorHash of the bytes OneDrive has accepted for each upload session, keyed by
/// `op_id` (never the credential-bearing `uploadUrl`). The hasher's length is the session
/// offset it covers.
///
/// The state lives in memory because the engine passes `upload_chunk` an immutable
/// [`OperationRecord`] and never re-persists `backend_meta` after `begin_upload`. A session
/// resumed by another process, or one where OneDrive accepted a byte count other than what
/// was hashed, has no running hash: its final `quickXorHash` is then **not verified**.
pub(super) struct SessionQuickXorMap(StdMutex<BoundedSessionMap<String, QuickXorHasher>>);

impl Default for SessionQuickXorMap {
    fn default() -> Self {
        Self(StdMutex::new(BoundedSessionMap::with_defaults()))
    }
}

impl SessionQuickXorMap {
    fn lock(&self) -> std::sync::MutexGuard<'_, BoundedSessionMap<String, QuickXorHasher>> {
        lock_unpoisoned(&self.0)
    }

    pub(super) fn start(&self, op_id: &str) {
        self.lock().insert(op_id.to_string(), QuickXorHasher::new());
    }

    /// Snapshot of the running hash, if it covers exactly `[0, offset)`. A state at any
    /// other offset can never become valid again and is dropped.
    pub(super) fn at(&self, op_id: &str, offset: u64) -> Option<QuickXorHasher> {
        let mut map = self.lock();
        let key = op_id.to_string();
        match map.get_mut(&key) {
            Some(h) if h.len() == offset => Some(h.clone()),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    pub(super) fn advance(&self, op_id: &str, hasher: QuickXorHasher) {
        let key = op_id.to_string();
        if let Some(slot) = self.lock().get_mut(&key) {
            *slot = hasher;
        }
    }

    pub(super) fn forget(&self, op_id: &str) {
        self.lock().remove(&op_id.to_string());
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Digests computed over one upload request body while it streamed.
#[derive(Default)]
struct StreamedHashes {
    sha256: Option<String>,
    /// Running QuickXorHash after this request's bytes.
    quickxor: Option<QuickXorHasher>,
}

use super::{GraphItem, OnedriveBackend, classify_graph_status, graph_error_decision};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadSessionResp {
    upload_url: String,
    #[serde(default)]
    expiration_date_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadStatusResp {
    #[serde(default)]
    next_expected_ranges: Vec<String>,
}

/// Compare the hashes Graph returned for an uploaded item with what was streamed (and with
/// source checksums of the same kind). Returns whether at least one hash was compared, so
/// callers can report an upload that could not be verified.
fn verify_onedrive_upload_hashes(
    context: &str,
    item: &GraphItem,
    streamed_sha256: Option<&str>,
    streamed_quickxor: Option<&str>,
    known_checksums: &[Checksum],
) -> Result<bool> {
    let hashes = item.file.as_ref().and_then(|f| f.hashes.as_ref());
    let mut verified = false;

    if let Some(remote) = hashes.and_then(|h| h.sha256_hex()) {
        let expected = streamed_sha256
            .map(str::to_ascii_lowercase)
            .into_iter()
            .chain(
                known_checksums
                    .iter()
                    .filter(|ck| ck.kind == HashKind::Sha256 && !ck.hex.trim().is_empty())
                    .map(|ck| ck.hex.trim().to_ascii_lowercase()),
            );
        for expected in expected {
            if expected != remote {
                return Err(checksum_mismatch_error(
                    context, "SHA-256", &expected, &remote,
                ));
            }
            verified = true;
        }
    }

    if let (Some(remote), Some(streamed)) =
        (hashes.and_then(|h| h.quickxor_hex()), streamed_quickxor)
    {
        if !streamed.eq_ignore_ascii_case(&remote) {
            return Err(checksum_mismatch_error(
                context,
                "QuickXorHash",
                &streamed.to_ascii_lowercase(),
                &remote,
            ));
        }
        verified = true;
    }
    Ok(verified)
}

/// Full-object hash a download is verified against.
#[derive(Debug, Clone)]
enum ExpectedDownloadHash {
    Sha256(String),
    QuickXor(String),
}

impl ExpectedDownloadHash {
    /// Prefer `sha256Hash` (stronger, OneDrive Personal only), else `quickXorHash`.
    fn from_item(item: &GraphItem) -> Option<Self> {
        let hashes = item.file.as_ref()?.hashes.as_ref()?;
        hashes
            .sha256_hex()
            .map(Self::Sha256)
            .or_else(|| hashes.quickxor_hex().map(Self::QuickXor))
    }

    fn algorithm(&self) -> &'static str {
        match self {
            Self::Sha256(_) => "SHA-256",
            Self::QuickXor(_) => "QuickXorHash",
        }
    }

    fn hex(&self) -> &str {
        match self {
            Self::Sha256(h) | Self::QuickXor(h) => h,
        }
    }

    fn of_empty(&self) -> String {
        match self {
            Self::Sha256(_) => Sha256Hasher::new().finalize_hex(),
            Self::QuickXor(_) => QuickXorHasher::new().finalize_hex(),
        }
    }
}

#[derive(Clone)]
enum DownloadTarget {
    Unresolved,
    PreAuthUrl(String),
    AuthenticatedContent(String),
}

struct OnedriveRangeReader {
    backend: OnedriveBackend,
    item_path: BackendPath,
    remote_target: Option<(Option<String>, String)>,
    content_url: String,
    download_target: tokio::sync::Mutex<DownloadTarget>,
    total_len: u64,
    /// Full-object hash; `None` leaves every read of this item unverified (length-checked
    /// only). Ranged reads are always unverified here.
    expected: Option<ExpectedDownloadHash>,
}

impl OnedriveRangeReader {
    async fn refresh_download_target(&self) -> Result<DownloadTarget> {
        let (item, remote_drive_id) = match &self.remote_target {
            Some((Some(drive_id), remote_id)) => {
                let url = self.backend.drive_item_url(Some(drive_id), remote_id, "");
                let (status, _, body) = self
                    .backend
                    .graph_request("stat", Method::GET, &url, None, true)
                    .await?;
                if status == StatusCode::NOT_FOUND {
                    return Err(Error::not_found(format!(
                        "OneDrive item `{}` not found",
                        self.item_path.nfc_path
                    )));
                }
                let item = serde_json::from_slice::<GraphItem>(&body)
                    .map_err(|e| Error::protocol(format!("decode GraphItem: {e}")))?;
                (item, Some(drive_id.clone()))
            }
            _ => self
                .backend
                .stat_graph_item_with_drive(&self.item_path)
                .await?
                .ok_or_else(|| {
                    Error::not_found(format!(
                        "OneDrive item `{}` not found",
                        self.item_path.nfc_path
                    ))
                })?,
        };
        let url = item
            .download_url
            .clone()
            .or_else(|| item.effective().download_url.clone())
            .filter(|u| !u.trim().is_empty());
        Ok(match url {
            Some(u) => DownloadTarget::PreAuthUrl(u),
            None => {
                let (target_did, target_id) = item.remote_target();
                let effective_did = if item.remote_item.is_some() {
                    self.backend
                        .external_drive_id(target_did)
                        .await?
                        .or(remote_drive_id)
                } else {
                    remote_drive_id.or(self.backend.external_drive_id(target_did).await?)
                };
                let resolved_content_url = if !target_id.is_empty() {
                    self.backend
                        .drive_item_url(effective_did.as_deref(), target_id, "content")
                } else {
                    self.content_url.clone()
                };
                DownloadTarget::AuthenticatedContent(resolved_content_url)
            }
        })
    }
}

#[async_trait]
impl RemoteRangeReadable for OnedriveRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            if range.offset == 0
                && self.total_len == 0
                && let Some(ref expected) = self.expected
            {
                let empty = expected.of_empty();
                if !empty.eq_ignore_ascii_case(expected.hex()) {
                    return Err(checksum_mismatch_error(
                        "OneDrive download",
                        expected.algorithm(),
                        expected.hex(),
                        &empty,
                    ));
                }
            }
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("OneDrive range overflow"))?;
        if end_exclusive > self.total_len {
            return Err(Error::invalid_geometry(
                "OneDrive range exceeds file length",
            ));
        }

        let mut url_refreshed = false;
        let mut auth_refreshed = false;
        let resp = loop {
            let target = {
                let mut guard = self.download_target.lock().await;
                if matches!(*guard, DownloadTarget::Unresolved) {
                    *guard = self.refresh_download_target().await?;
                }
                guard.clone()
            };
            let (url, token) = match &target {
                DownloadTarget::PreAuthUrl(u) => (u.as_str(), None),
                DownloadTarget::AuthenticatedContent(content_url) => {
                    let tok = self.backend.inner.auth.access_token().await?;
                    (content_url.as_str(), Some(tok))
                }
                DownloadTarget::Unresolved => unreachable!(),
            };
            self.backend.inner.data_limiter.acquire_send_permit().await;
            let req = self.backend.build_range_request(
                url,
                token.as_deref(),
                range.offset,
                end_exclusive - 1,
            )?;
            let resp = self
                .backend
                .inner
                .transport
                .send_data_request("GET(OneDrive range)", req)
                .await?;
            let status = resp.status();
            match &target {
                DownloadTarget::PreAuthUrl(used_url)
                    if matches!(
                        status,
                        StatusCode::UNAUTHORIZED
                            | StatusCode::FORBIDDEN
                            | StatusCode::NOT_FOUND
                            | StatusCode::GONE
                    ) && !url_refreshed =>
                {
                    url_refreshed = true;
                    let mut guard = self.download_target.lock().await;
                    if matches!(&*guard, DownloadTarget::PreAuthUrl(cur) if cur == used_url) {
                        *guard = self.refresh_download_target().await?;
                    }
                    continue;
                }
                DownloadTarget::AuthenticatedContent(_)
                    if status == StatusCode::UNAUTHORIZED && !auth_refreshed =>
                {
                    auth_refreshed = true;
                    if let Some(ref tok) = token {
                        let _ = self.backend.inner.auth.force_refresh(tok).await?;
                    }
                    continue;
                }
                _ => {}
            }
            if status == StatusCode::PARTIAL_CONTENT
                || (status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
            {
                self.backend.inner.data_limiter.record_success(false, false);
                break resp;
            }
            let rh = resp.headers().clone();
            let rb = self.backend.inner.transport.read_data_body(resp).await?;
            let err = classify_graph_status("GET(OneDrive range)", status, &rh, &rb, false);
            if err.is_throttled() {
                self.backend.inner.data_limiter.record_throttle();
            }
            return Err(err);
        };
        let watched = self
            .backend
            .inner
            .transport
            .watch_response_stream("OneDrive range body", resp);
        let exact = ExactDownloadStream::new("OneDrive", watched, range.len);
        if range.offset == 0 && range.len == self.total_len {
            match &self.expected {
                Some(ExpectedDownloadHash::Sha256(hex)) => {
                    return Ok(Box::pin(VerifyingDownloadStream::new(
                        "OneDrive",
                        "SHA-256",
                        exact,
                        Sha256Hasher::new(),
                        range.len,
                        hex.clone(),
                    )));
                }
                Some(ExpectedDownloadHash::QuickXor(hex)) => {
                    return Ok(Box::pin(VerifyingDownloadStream::new(
                        "OneDrive",
                        "QuickXorHash",
                        exact,
                        QuickXorHasher::new(),
                        range.len,
                        hex.clone(),
                    )));
                }
                None => {}
            }
        }
        Ok(Box::pin(exact))
    }
}

pub fn parse_expected_range_start(range_str: &str) -> Result<u64> {
    let start_s = range_str.split('-').next().unwrap_or("").trim();
    start_s
        .parse::<u64>()
        .map_err(|_| Error::protocol(format!("invalid OneDrive nextExpectedRanges `{range_str}`")))
}

pub(super) fn format_rfc3339_secs(ns: i64) -> String {
    rship_core::time::format_rfc3339_secs(ns.div_euclid(1_000_000_000))
}

impl OnedriveBackend {
    /// Stream an upload body of exactly `expected_len` bytes, hashing it on the way:
    /// SHA-256 from scratch when `compute_sha256`, and QuickXorHash continuing from
    /// `quickxor` when given (a fresh hasher for single-shot uploads, the session's running
    /// hash for upload-session chunks).
    async fn send_onedrive_upload(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
        body: ByteStream,
        expected_len: u64,
        compute_sha256: bool,
        quickxor: Option<QuickXorHasher>,
    ) -> Result<(reqwest::Response, StreamedHashes)> {
        let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let sha256_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let quickxor_slot: Arc<StdMutex<Option<QuickXorHasher>>> = Arc::new(StdMutex::new(None));
        let mut stream: ByteStream = Box::pin(StrictBodyStream::new(
            "OneDrive",
            body,
            expected_len,
            captured_err.clone(),
        ));
        if compute_sha256 {
            stream = Box::pin(StreamingHashStream::new(
                stream,
                Sha256Hasher::new(),
                expected_len,
                sha256_slot.clone(),
            ));
        }
        if let Some(hasher) = quickxor {
            stream = Box::pin(StreamingHashStream::new(
                stream,
                QuickXorState(hasher),
                expected_len,
                quickxor_slot.clone(),
            ));
        }
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            context,
            req,
            stream,
            expected_len,
            captured_err,
        )
        .await?;
        let hashes = StreamedHashes {
            sha256: lock_unpoisoned(&sha256_slot).take(),
            quickxor: lock_unpoisoned(&quickxor_slot).take(),
        };
        Ok((resp, hashes))
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some((item, remote_drive_id)) = self.stat_graph_item_with_drive(path).await? else {
            return Err(Error::not_found(format!(
                "OneDrive item `{}` not found",
                path.nfc_path
            )));
        };
        if item.is_package() {
            return Err(Error::unsupported(format!(
                "cannot open OneNote package `{}` for reading",
                path.nfc_path
            )));
        }
        if item.is_folder() {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let eff = item.effective();
        let expected = ExpectedDownloadHash::from_item(eff);
        let download_url = item
            .download_url
            .clone()
            .or_else(|| eff.download_url.clone())
            .filter(|u| !u.trim().is_empty());
        let (target_drive_id, target_id) = item.remote_target();
        let effective_drive_id = if item.remote_item.is_some() {
            self.external_drive_id(target_drive_id)
                .await?
                .or(remote_drive_id)
        } else {
            remote_drive_id.or(self.external_drive_id(target_drive_id).await?)
        };
        let content_url = self.drive_item_url(effective_drive_id.as_deref(), target_id, "content");
        let item_node_id = if item.remote_item.is_some() && !item.id.is_empty() {
            super::encode_node_id(None, &item.id)
        } else {
            super::encode_node_id(effective_drive_id.as_deref(), target_id)
        };
        let item_path = BackendPath::new(path.raw_path(), path.nfc_path.clone(), item_node_id);
        let remote_target =
            (!target_id.is_empty()).then(|| (effective_drive_id, target_id.to_string()));
        let download_target = match download_url {
            Some(u) => DownloadTarget::PreAuthUrl(u),
            None => DownloadTarget::AuthenticatedContent(content_url.clone()),
        };
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            OnedriveRangeReader {
                backend: self.clone(),
                item_path,
                remote_target,
                content_url,
                download_target: tokio::sync::Mutex::new(download_target),
                total_len: eff.size,
                expected,
            },
        )))
    }

    pub(super) async fn open_read_entry_impl(
        &self,
        entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let Some(nid) = entry.node_id.as_ref().or(path.node_id.as_ref()) else {
            return self.open_read(path, range).await;
        };
        let (nid_drive_id, item_id) = super::decode_node_id(nid.as_str());
        let content_url = self.drive_item_url(nid_drive_id, item_id, "content");
        let item_path = BackendPath::new(path.raw_path(), path.nfc_path.clone(), Some(nid.clone()));
        let remote_target = nid_drive_id.map(|did| (Some(did.to_string()), item_id.to_string()));
        // Only `Entry::checksum` travels with the entry, and it can only hold `sha256Hash`
        // (or `sha1Hash`, which this backend cannot recompute). The listing's `quickXorHash`
        // has no `HashKind`, so entry-based reads without `sha256Hash` (all of OneDrive for
        // Business / SharePoint) stay unverified on hash unless `stat` reveals one.
        let expected = entry
            .checksum
            .as_ref()
            .filter(|c| c.kind == HashKind::Sha256 && !c.hex.trim().is_empty())
            .map(|c| ExpectedDownloadHash::Sha256(c.hex.trim().to_ascii_lowercase()));
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            OnedriveRangeReader {
                backend: self.clone(),
                item_path,
                remote_target,
                content_url,
                download_target: tokio::sync::Mutex::new(DownloadTarget::Unresolved),
                total_len: entry.size,
                expected,
            },
        )))
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let parent_target = if let Some(parent) = init.dst_path.parent()
            && !parent.is_root()
        {
            Some(self.ensure_dir_chain(&parent).await?)
        } else {
            None
        };
        let (url, patch_drive_id) = match parent_target {
            Some((ref parent_id, Some(ref remote_did))) => {
                let file_name = init
                    .dst_path
                    .file_name()
                    .ok_or_else(|| Error::invalid_path("cannot upload OneDrive item to root"))?;
                (
                    self.drive_item_child_path_url(
                        Some(remote_did.as_str()),
                        parent_id,
                        file_name,
                        "content",
                    ),
                    Some(remote_did.clone()),
                )
            }
            _ => (self.item_path_url(&init.dst_path, "content"), None),
        };
        let token = self.inner.auth.access_token().await?;

        self.inner.data_limiter.acquire_send_permit().await;
        let req = self.build_single_shot_request(&url, &token, init.total_size)?;
        let (resp, streamed) = self
            .send_onedrive_upload(
                "PUT(simple)",
                req,
                body,
                init.total_size,
                true,
                Some(QuickXorHasher::new()),
            )
            .await?;
        let streamed_sha256 = streamed.sha256;
        let streamed_quickxor = streamed.quickxor.map(|h| h.finalize_hex());
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                let _ = self.inner.auth.force_refresh(&token).await?;
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Retryable,
                    "PUT(simple): HTTP 401 (OAuth token refreshed; retry upload)",
                ));
            }
            let err =
                classify_graph_status("PUT(simple)", status, &resp_headers, &resp_body, false);
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }
        self.inner.data_limiter.record_success(false, false);

        let mut item: GraphItem = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::protocol(format!("decode PUT(simple) GraphItem: {e}")))?;
        let verified = verify_onedrive_upload_hashes(
            "OneDrive upload",
            &item,
            streamed_sha256.as_deref(),
            streamed_quickxor.as_deref(),
            &init.checksums,
        )?;
        if !verified {
            tracing::debug!(
                path = %init.dst_path,
                "OneDrive returned no quickXorHash/sha256Hash for the uploaded item; upload is unverified"
            );
        }
        // Microsoft Graph simple `PUT /content` assigns server wall-clock mtime; patch
        // `fileSystemInfo.lastModifiedDateTime` so `can_set_mtime = true` holds for <= 4 MiB files.
        if init.src_mtime_ns >= 0 {
            let patch_url = self.drive_item_url(patch_drive_id.as_deref(), &item.id, "");
            let patch_body = serde_json::json!({
                "fileSystemInfo": {
                    "lastModifiedDateTime": format_rfc3339_secs(init.src_mtime_ns),
                }
            });
            let (_, _, pbody) = self
                .graph_request(
                    "PATCH(mtime)",
                    Method::PATCH,
                    &patch_url,
                    Some(&patch_body),
                    false,
                )
                .await?;
            match serde_json::from_slice::<GraphItem>(&pbody) {
                Ok(patched) => {
                    verify_onedrive_upload_hashes(
                        "OneDrive upload",
                        &patched,
                        streamed_sha256.as_deref(),
                        streamed_quickxor.as_deref(),
                        &init.checksums,
                    )?;
                    item = patched;
                }
                Err(e) => {
                    tracing::warn!(
                        path = %init.dst_path,
                        error = %e,
                        "OneDrive PATCH(mtime) returned unexpected JSON; retaining initial upload item"
                    );
                }
            }
        }
        let effective_drive_id = patch_drive_id.or(self
            .external_drive_id(
                item.parent_reference
                    .as_ref()
                    .and_then(|p| p.drive_id.as_deref()),
            )
            .await?);
        Ok(self.item_to_entry(
            &item,
            init.dst_path.as_str(),
            init.dst_path.clone(),
            effective_drive_id.as_deref(),
        ))
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let parent_target = if let Some(parent) = init.dst_path.parent()
            && !parent.is_root()
        {
            Some(self.ensure_dir_chain(&parent).await?)
        } else {
            None
        };
        // Snapshot what occupies the destination now, so `reconcile_operation` can tell this
        // session's commit (new eTag) from an older item of the same size.
        let pre_op = PreOpState::snapshot(
            self.stat(&BackendPath::from_rel(init.dst_path.clone()))
                .await?
                .as_ref(),
            |e| e.etag.clone(),
        );
        let url = match parent_target {
            Some((ref parent_id, Some(ref remote_did))) => {
                let file_name = init
                    .dst_path
                    .file_name()
                    .ok_or_else(|| Error::invalid_path("cannot upload OneDrive item to root"))?;
                self.drive_item_child_path_url(
                    Some(remote_did.as_str()),
                    parent_id,
                    file_name,
                    "createUploadSession",
                )
            }
            _ => self.item_path_url(&init.dst_path, "createUploadSession"),
        };
        let mut item_payload = serde_json::Map::new();
        item_payload.insert(
            "@microsoft.graph.conflictBehavior".to_string(),
            serde_json::json!("replace"),
        );
        if init.src_mtime_ns >= 0 {
            item_payload.insert(
                "fileSystemInfo".to_string(),
                serde_json::json!({
                    "lastModifiedDateTime": format_rfc3339_secs(init.src_mtime_ns)
                }),
            );
        }
        let payload = serde_json::json!({
            "item": item_payload
        });
        let (_, _, body) = self
            .graph_request(
                "createUploadSession",
                Method::POST,
                &url,
                Some(&payload),
                false,
            )
            .await?;
        let sess: UploadSessionResp = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode createUploadSession: {e}")))?;
        let expires_at = sess
            .expiration_date_time
            .as_deref()
            .and_then(rship_core::time::parse_rfc3339_to_secs);
        self.inner.session_quickxor.start(&init.op_id);

        Ok(UploadSessionInit {
            session_token: sess.upload_url,
            backend_meta: serde_json::to_string(&OnedriveSessionMeta {
                pre_op: Some(pre_op),
                known_checksums: init.checksums.clone(),
            })
            .map_err(|e| Error::protocol(format!("encode OneDrive session meta: {e}")))?,
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: expires_at,
        })
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        enum QueryStatus {
            Expired,
            Status(UploadStatusResp),
        }

        let Some(upload_url) = op.session_token.as_deref() else {
            self.inner.session_quickxor.forget(&op.op_id);
            return Ok(UploadProgress::Expired);
        };
        let policy_cfg = self.retry_policy_config(None);
        let raw = execute_with_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            "GET(uploadUrl)",
            &policy_cfg,
            Idempotency::Idempotent,
            || {
                let upload_url = upload_url.to_string();
                async move {
                    // Pre-authenticated `uploadUrl`: MUST NOT send `Authorization: Bearer` header!
                    Ok(self.inner.transport.control_client().get(&upload_url))
                }
            },
            |resp| {
                if resp.status == StatusCode::NOT_FOUND || resp.status == StatusCode::GONE {
                    return PolicyDecision::Ok(QueryStatus::Expired);
                }
                if resp.status.is_success() {
                    return match serde_json::from_slice::<UploadStatusResp>(&resp.body) {
                        Ok(st) => PolicyDecision::Ok(QueryStatus::Status(st)),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "decode upload session status: {e}"
                        ))),
                    };
                }
                graph_error_decision(
                    "GET(uploadUrl)",
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    true,
                )
            },
        )
        .await?;

        let st = match raw {
            QueryStatus::Expired => {
                self.inner.session_quickxor.forget(&op.op_id);
                return Ok(UploadProgress::Expired);
            }
            QueryStatus::Status(st) => st,
        };
        if let Some(first_range) = st.next_expected_ranges.first() {
            let start = parse_expected_range_start(first_range)?;
            Ok(UploadProgress::SequentialOffset(start))
        } else {
            self.inner.session_quickxor.forget(&op.op_id);
            // Empty `nextExpectedRanges` only counts as AlreadyCompleted when PreOpState proof
            // confirms the committed item at destination is actually this upload.
            match self.verify_committed_destination(op).await? {
                ReconcileOutcome::Committed(entry) => Ok(UploadProgress::AlreadyCompleted(entry)),
                ReconcileOutcome::NotCommitted | ReconcileOutcome::Ambiguous(_) | _ => {
                    Ok(UploadProgress::Expired)
                }
            }
        }
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let upload_url = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing OneDrive uploadUrl"))?;
        if chunk.len == 0 {
            return Err(Error::invalid_geometry("OneDrive chunk cannot be 0 bytes"));
        }
        if chunk.len > MAX_ONEDRIVE_CHUNK_BYTES {
            return Err(Error::invalid_geometry(format!(
                "OneDrive chunk length {} exceeds maximum {} bytes",
                chunk.len, MAX_ONEDRIVE_CHUNK_BYTES
            )));
        }
        let end_inclusive = chunk
            .offset
            .checked_add(chunk.len)
            .and_then(|e| e.checked_sub(1))
            .ok_or_else(|| Error::invalid_geometry("OneDrive Content-Range overflow"))?;
        let is_final = end_inclusive + 1 == chunk.total_size;
        if !is_final && !chunk.len.is_multiple_of(ONEDRIVE_CHUNK_ALIGN_BYTES) {
            return Err(Error::invalid_geometry(format!(
                "OneDrive non-final chunk length {} is not a multiple of 320 KiB",
                chunk.len
            )));
        }

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&chunk.len.to_string())
                .map_err(|e| Error::protocol(format!("Content-Length: {e}")))?,
        );
        headers.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                chunk.offset, end_inclusive, chunk.total_size
            ))
            .map_err(|e| Error::protocol(format!("Content-Range: {e}")))?,
        );

        let req = self
            .inner
            .transport
            .data_client()
            .put(upload_url)
            .headers(headers);
        let compute_sha256 = chunk.offset == 0 && is_final;
        let running = self.inner.session_quickxor.at(&op.op_id, chunk.offset);
        if is_final && running.is_none() {
            tracing::debug!(
                path = %op.dst_nfc_path,
                "OneDrive upload session has no in-process running QuickXorHash (resumed by \
                 another process or after a partial accept); final item is unverified"
            );
        }
        let (resp, streamed) = match self
            .send_onedrive_upload(
                "PUT(uploadUrl chunk)",
                req,
                chunk.body,
                chunk.len,
                compute_sha256,
                running,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                if !e.is_retryable() {
                    self.inner.session_quickxor.forget(&op.op_id);
                }
                return Err(e);
            }
        };

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if status == StatusCode::ACCEPTED {
            self.inner.data_limiter.record_success(false, false);
            let reported = serde_json::from_slice::<UploadStatusResp>(&resp_body)
                .ok()
                .and_then(|st| st.next_expected_ranges.first().cloned())
                .and_then(|r| parse_expected_range_start(&r).ok());
            let next_off = match reported {
                Some(off) => off,
                // A 202 without `nextExpectedRanges` does not say what landed. Ask the
                // session instead of assuming the whole fragment was accepted.
                None => match self.query_upload_impl(op).await? {
                    UploadProgress::SequentialOffset(off) => off,
                    UploadProgress::AlreadyCompleted(entry) => {
                        self.inner.session_quickxor.forget(&op.op_id);
                        return Ok(ChunkAck {
                            next_offset: Some(chunk.total_size),
                            etag: entry.etag.clone(),
                            completed: Some(entry),
                            checksum: None,
                        });
                    }
                    UploadProgress::Expired | _ => {
                        self.inner.session_quickxor.forget(&op.op_id);
                        return Err(Error::session_expired(
                            "OneDrive upload session vanished after a 202 without nextExpectedRanges",
                        ));
                    }
                },
            };
            match streamed.quickxor {
                Some(hasher) if next_off == end_inclusive + 1 => {
                    self.inner.session_quickxor.advance(&op.op_id, hasher);
                }
                // Nothing accepted: the running hash still describes `[0, offset)`.
                _ if next_off == chunk.offset => {}
                _ => self.inner.session_quickxor.forget(&op.op_id),
            }
            return Ok(ChunkAck {
                next_offset: Some(next_off),
                etag: None,
                completed: None,
                checksum: None,
            });
        }

        if status == StatusCode::OK || status == StatusCode::CREATED {
            self.inner.session_quickxor.forget(&op.op_id);
            let item: GraphItem = serde_json::from_slice(&resp_body)
                .map_err(|e| Error::protocol(format!("decode final chunk GraphItem: {e}")))?;
            let known_checksums: Vec<Checksum> =
                serde_json::from_str::<OnedriveSessionMeta>(&op.backend_meta)
                    .map(|m| m.known_checksums)
                    .unwrap_or_default();
            let streamed_sha256 = streamed.sha256.filter(|_| compute_sha256);
            let streamed_quickxor = streamed
                .quickxor
                .filter(|h| h.len() == chunk.total_size)
                .map(|h| h.finalize_hex());
            let verified = verify_onedrive_upload_hashes(
                "OneDrive upload session",
                &item,
                streamed_sha256.as_deref(),
                streamed_quickxor.as_deref(),
                &known_checksums,
            )?;
            if !verified && streamed_quickxor.is_some() {
                tracing::debug!(
                    path = %op.dst_nfc_path,
                    "OneDrive final upload fragment response carried no quickXorHash; upload is unverified"
                );
            }
            let remote_drive_id = self
                .external_drive_id(
                    item.parent_reference
                        .as_ref()
                        .and_then(|p| p.drive_id.as_deref()),
                )
                .await?;
            let entry = self.item_to_entry(
                &item,
                op.dst_raw_path.as_str(),
                op.dst_nfc_path.clone(),
                remote_drive_id.as_deref(),
            );
            self.inner.data_limiter.record_success(false, false);
            return Ok(ChunkAck {
                next_offset: Some(chunk.total_size),
                etag: entry.etag.clone(),
                completed: Some(entry),
                checksum: None,
            });
        }

        let err = classify_graph_status(
            "PUT(uploadUrl chunk)",
            status,
            &resp_headers,
            &resp_body,
            true,
        );
        if !err.is_retryable() {
            self.inner.session_quickxor.forget(&op.op_id);
        }
        if err.is_throttled() {
            self.inner.data_limiter.record_throttle();
        }
        Err(err)
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        self.inner.session_quickxor.forget(&op.op_id);
        let bp = BackendPath::new(op.dst_raw_path.as_str(), op.dst_nfc_path.clone(), None);
        self.stat(&bp).await?.ok_or_else(|| {
            Error::protocol("OneDrive upload finalized without visible destination item")
        })
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        self.inner.session_quickxor.forget(&op.op_id);
        if let Some(upload_url) = op.session_token.as_deref() {
            self.inner.control_limiter.acquire_send_permit().await;
            let req = self.inner.transport.control_client().delete(upload_url);
            let _ = self
                .inner
                .transport
                .send_control_request("DELETE(uploadUrl)", req)
                .await;
        }
        Ok(())
    }

    async fn verify_committed_destination(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        // Proof that the item is this operation's result: source size, the source mtime we
        // set in `fileSystemInfo` (second precision), and an eTag different from the
        // pre-operation item (snapshot taken at `begin_upload`, else the planner's
        // precondition). Size alone never proves anything.
        let pre_op = serde_json::from_str::<OnedriveSessionMeta>(&op.backend_meta)
            .ok()
            .and_then(|m| m.pre_op)
            .unwrap_or_else(|| {
                PreOpState::from_precondition(&op.dst_precondition, |_, etag| etag.clone())
            });
        let bp = BackendPath::new(op.dst_raw_path.as_str(), op.dst_nfc_path.clone(), None);
        let Some(entry) = self.stat(&bp).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };
        if entry.kind != EntryKind::File {
            return Ok(ReconcileOutcome::NotCommitted);
        }
        let etag = entry.etag.clone();
        let outcome = judge_reconciled_object(
            op,
            entry,
            etag.as_deref(),
            &pre_op,
            Some(ONEDRIVE_MTIME_TOLERANCE_NS),
            "OneDrive reconcile",
        );
        if matches!(outcome, ReconcileOutcome::Committed(_)) {
            self.inner.session_quickxor.forget(&op.op_id);
        }
        Ok(outcome)
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        self.verify_committed_destination(op).await
    }
}

/// `fileSystemInfo.lastModifiedDateTime` keeps whole seconds.
const ONEDRIVE_MTIME_TOLERANCE_NS: i64 = 1_000_000_000;

/// `backend_meta` of an upload session.
#[derive(Debug, Serialize, Deserialize)]
struct OnedriveSessionMeta {
    /// Destination state before the session (absent in records written before it existed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pre_op: Option<PreOpState>,
    /// Source checksums captured at `begin_upload` so SHA-256 verification applies across
    /// single-fragment, multi-fragment, and resumed sessions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    known_checksums: Vec<Checksum>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_graph_rfc3339_truncates_to_whole_seconds_z() {
        assert_eq!(
            format_rfc3339_secs(1_700_000_000_987_654_321),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(format_rfc3339_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn session_quickxor_map_keys_by_op_id_bounds_capacity_and_cleans_up() {
        let map = SessionQuickXorMap(StdMutex::new(BoundedSessionMap::new(
            2,
            std::time::Duration::from_secs(60),
        )));
        map.start("op-1");
        map.start("op-2");
        assert_eq!(map.len(), 2);

        // Inserting op-3 evicts oldest (op-1) because capacity is bounded to 2.
        map.start("op-3");
        assert_eq!(map.len(), 2);
        assert!(map.at("op-1", 0).is_none());

        // `at` with mismatched offset drops the stale entry.
        assert!(map.at("op-2", 128).is_none());
        assert_eq!(map.len(), 1);

        // `advance` then `forget` cleans up op-3.
        let mut h = map.at("op-3", 0).unwrap();
        h.update_bytes(b"hello");
        map.advance("op-3", h);
        assert_eq!(map.at("op-3", 5).unwrap().len(), 5);
        map.forget("op-3");
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn onedrive_session_meta_omits_dst_and_round_trips_checksums() {
        let meta = OnedriveSessionMeta {
            pre_op: None,
            known_checksums: vec![Checksum {
                kind: HashKind::Sha256,
                hex: "abcd".into(),
            }],
        };
        let encoded = serde_json::to_string(&meta).unwrap();
        assert!(!encoded.contains("\"dst\""));
        let decoded: OnedriveSessionMeta = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.known_checksums.len(), 1);
        assert_eq!(decoded.known_checksums[0].hex, "abcd");
    }

    #[tokio::test]
    async fn backend_session_quickxor_cleaned_up_on_abort_and_finish_and_permanent_err() {
        use crate::onedrive::config::OnedriveConfig;
        use rship_core::path::RelPath;
        use rship_core::state::{DstPrecondition, OperationState, SourceVersion};
        use rship_transport::oauth::StaticBearerAuth;
        use rship_transport::{HttpTransport, TransportConfig};

        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
        let backend = OnedriveBackend::new(OnedriveConfig::new("od"), auth, transport).unwrap();
        let rel = RelPath::parse("file.bin").unwrap();

        let make_op = |op_id: &str| OperationRecord {
            op_id: op_id.into(),
            session_key: format!("sk-{op_id}"),
            job_id: "j".into(),
            src_endpoint: "local".into(),
            dst_endpoint: backend.endpoint_identity(),
            src_raw_path: rel.as_str().into(),
            dst_raw_path: rel.as_str().into(),
            dst_nfc_path: rel.clone(),
            src_version: SourceVersion {
                node_id: None,
                size: 16,
                mtime_ns: 0,
                ctime_ns: None,
                etag: None,
            },
            dst_precondition: DstPrecondition::Any,
            existing_dst_node_id: None,
            remote_op_id: None,
            backend_kind: "onedrive".into(),
            session_token: None,
            backend_meta: String::new(),
            planned_chunk_size: 16,
            confirmed_offset: 0,
            state: OperationState::Active,
            created_at: 1,
            updated_at: 1,
            expires_at: None,
        };

        backend.inner.session_quickxor.start("op-abort");
        assert_eq!(backend.inner.session_quickxor.len(), 1);
        backend.abort_upload(&make_op("op-abort")).await.unwrap();
        assert_eq!(backend.inner.session_quickxor.len(), 0);
    }
}
