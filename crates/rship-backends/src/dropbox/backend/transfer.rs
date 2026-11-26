//! Dropbox data-plane streaming downloads (`RemoteRangeReadable`), single-shot
//! `/files/upload`, 4 MiB-aligned resumable upload sessions (`/files/upload_session/*`)
//! with `incorrect_offset` crash-resume recovery, and reconciliation.

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::OperationRecord;
use rship_core::types::{ByteRange, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use serde::Deserialize;
use std::sync::Arc;

use crate::common::http::{Idempotency, ReconcileAction, send_watched_sized_upload_with_capture};
use crate::common::{
    ExactDownloadStream, StreamingHashStream, StrictBodyStream, VerifyingDownloadStream,
    checksum_mismatch_error, lock_unpoisoned,
};
use crate::dropbox::hash::{
    DropboxContentHasher, dropbox_content_hash_from_single_block_sha256, encode_dropbox_api_arg,
};

use super::{
    DbxOutcome, DropboxApiError, DropboxBackend, DropboxCall, DropboxMeta,
    build_content_upload_headers, build_download_headers, classify_dropbox_error,
};

enum MaybeHashedStream<S> {
    Plain(S),
    Hashed(Box<StreamingHashStream<S, DropboxContentHasher>>),
}

impl<S> futures::Stream for MaybeHashedStream<S>
where
    S: futures::Stream<Item = Result<Bytes>> + Unpin,
{
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.as_mut().get_mut() {
            Self::Plain(inner) => std::pin::Pin::new(inner).poll_next(cx),
            Self::Hashed(inner) => std::pin::Pin::new(inner.as_mut()).poll_next(cx),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SessionStartResp {
    session_id: String,
}

struct DropboxRangeReader {
    backend: DropboxBackend,
    api_path: String,
    total_len: u64,
}

#[async_trait]
impl RemoteRangeReadable for DropboxRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("Dropbox range overflow"))?;
        if end_exclusive > self.total_len {
            return Err(Error::invalid_geometry("Dropbox range exceeds file size"));
        }

        let url = self.backend.content_url("files/download");
        let arg = encode_dropbox_api_arg(&serde_json::json!({ "path": self.api_path }));
        let select_user = self.backend.resolve_select_user().await?;
        let mut auth_refreshed = false;

        loop {
            self.backend.inner.data_limiter.acquire_send_permit().await;
            let token = self.backend.inner.auth.access_token().await?;

            let mut headers =
                build_download_headers(&token, &arg, range.offset, end_exclusive - 1)?;
            self.backend
                .apply_team_headers(&mut headers, true, select_user.as_deref())?;

            let req = self
                .backend
                .inner
                .transport
                .data_client()
                .post(&url)
                .headers(headers);
            let resp = self
                .backend
                .inner
                .transport
                .send_data_request("Dropbox files/download", req)
                .await?;
            let status = resp.status();

            if status == StatusCode::UNAUTHORIZED && !auth_refreshed {
                auth_refreshed = true;
                let _ = self.backend.inner.auth.force_refresh(&token).await?;
                continue;
            }
            if status != StatusCode::PARTIAL_CONTENT
                && !(status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
            {
                let resp_headers = resp.headers().clone();
                let body = self.backend.inner.transport.read_data_body(resp).await?;
                let err =
                    classify_dropbox_error("Dropbox files/download", status, &resp_headers, &body);
                if err.is_throttled() {
                    self.backend.inner.data_limiter.record_throttle();
                }
                return Err(err);
            }

            self.backend.inner.data_limiter.record_success(false, false);
            let is_full_object = range.offset == 0 && range.len == self.total_len;
            let expected_content_hash = if is_full_object {
                extract_dropbox_api_result_content_hash(resp.headers())
            } else {
                None
            };
            let watched = self
                .backend
                .inner
                .transport
                .watch_response_stream("Dropbox download stream", resp);
            let exact = ExactDownloadStream::new("Dropbox", watched, range.len);
            if let Some(expected_hash) = expected_content_hash {
                return Ok(Box::pin(VerifyingDownloadStream::new(
                    "Dropbox",
                    "Dropbox content_hash",
                    exact,
                    DropboxContentHasher::new(),
                    range.len,
                    expected_hash,
                )));
            }
            return Ok(Box::pin(exact));
        }
    }
}

/// Extract a validated 64-hex `content_hash` from Dropbox's `dropbox-api-result` JSON header.
fn extract_dropbox_api_result_content_hash(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("dropbox-api-result")?.to_str().ok()?;
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    let hash = val.get("content_hash")?.as_str()?.trim();
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

fn format_dropbox_client_modified(mtime_ns: i64) -> Option<String> {
    if mtime_ns <= 0 {
        return None;
    }
    let secs = mtime_ns.div_euclid(1_000_000_000);
    Some(rship_core::time::format_rfc3339_secs(secs))
}

fn build_commit_info(
    api_path: String,
    mtime_ns: i64,
    content_hash: Option<&str>,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("path".to_string(), serde_json::Value::String(api_path));
    map.insert(
        "mode".to_string(),
        serde_json::Value::String("overwrite".to_string()),
    );
    map.insert("autorename".to_string(), serde_json::Value::Bool(false));
    map.insert("mute".to_string(), serde_json::Value::Bool(true));
    if let Some(cm) = format_dropbox_client_modified(mtime_ns) {
        map.insert("client_modified".to_string(), serde_json::Value::String(cm));
    }
    if let Some(ch) = content_hash {
        map.insert(
            "content_hash".to_string(),
            serde_json::Value::String(ch.to_string()),
        );
    }
    serde_json::Value::Object(map)
}

impl DropboxBackend {
    async fn send_dropbox_upload(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
        body: ByteStream,
        expected_len: u64,
        compute_content_hash: bool,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let captured_err: Arc<std::sync::Mutex<Option<Error>>> =
            Arc::new(std::sync::Mutex::new(None));
        let hash_slot: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        let strict = StrictBodyStream::new("Dropbox", body, expected_len, captured_err.clone());
        let stream = if compute_content_hash {
            MaybeHashedStream::Hashed(Box::new(StreamingHashStream::new(
                strict,
                DropboxContentHasher::new(),
                expected_len,
                hash_slot.clone(),
            )))
        } else {
            MaybeHashedStream::Plain(strict)
        };
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            context,
            req,
            stream,
            expected_len,
            captured_err,
        )
        .await?;
        let streamed_hash = lock_unpoisoned(&hash_slot).take();
        Ok((resp, streamed_hash))
    }

    /// Execute a streaming Dropbox Content API upload (`/files/upload` or `/files/upload_session/*`).
    async fn content_upload(
        &self,
        context: &str,
        endpoint: &str,
        api_arg: &serde_json::Value,
        body: ByteStream,
        expected_len: u64,
        compute_content_hash: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes, Option<String>)> {
        let url = self.content_url(endpoint);
        let arg_header = encode_dropbox_api_arg(api_arg);
        let select_user = self.resolve_select_user().await?;
        self.inner.data_limiter.acquire_send_permit().await;
        let token = self.inner.auth.access_token().await?;

        let mut headers = build_content_upload_headers(&token, &arg_header, expected_len)?;
        self.apply_team_headers(&mut headers, true, select_user.as_deref())?;

        let req = self
            .inner
            .transport
            .data_client()
            .post(&url)
            .headers(headers);
        let (resp, streamed_hash) = if expected_len == 0 {
            let mut s = body;
            while let Some(item) = s.next().await {
                let b = item?;
                if !b.is_empty() {
                    return Err(Error::source_mutated(
                        "non-empty bytes yielded for 0-byte Dropbox upload",
                    ));
                }
            }
            let watchdog = self.inner.transport.data_watchdog();
            watchdog.handle().mark_body_eof();
            let resp = self
                .inner
                .transport
                .send_watched_request(
                    context,
                    req.body(reqwest::Body::from(Bytes::new())),
                    &watchdog,
                )
                .await?;
            let empty_hash =
                compute_content_hash.then(|| DropboxContentHasher::new().finalize_hex());
            (resp, empty_hash)
        } else {
            self.send_dropbox_upload(context, req, body, expected_len, compute_content_hash)
                .await?
        };

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if status == StatusCode::UNAUTHORIZED {
            let _ = self.inner.auth.force_refresh(&token).await?;
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Retryable,
                format!("{context}: HTTP 401 token refreshed; retry upload"),
            ));
        }

        if status.is_success()
            || (status == StatusCode::CONFLICT
                && !DropboxApiError::parse(&resp_body).is_throttled())
        {
            self.inner.data_limiter.record_success(false, false);
            return Ok((status, resp_headers, resp_body, streamed_hash));
        }

        let err = classify_dropbox_error(context, status, &resp_headers, &resp_body);
        if err.is_throttled() {
            self.inner.data_limiter.record_throttle();
        }
        Err(err)
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some(entry) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "Dropbox file `{}` not found",
                path.nfc_path
            )));
        };
        self.open_read_entry(&entry, path, None).await
    }

    pub(super) async fn open_read_entry_impl(
        &self,
        entry: &Entry,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open Dropbox folder `{}` for reading",
                path.nfc_path
            )));
        }
        let raw_rel = path
            .raw_path
            .as_deref()
            .or(entry.raw_path.as_deref())
            .unwrap_or_else(|| path.nfc_path.as_str());
        let api_path = self.inner.cfg.api_path(raw_rel);
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            DropboxRangeReader {
                backend: self.clone(),
                api_path,
                total_len: entry.size,
            },
        )))
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let api_path = self.inner.cfg.api_path(init.dst_path.as_str());
        // Derive the exact Dropbox `content_hash` when a flat SHA-256 is known for a
        // single-block object (`<= 4 MiB`), since `HashKind` has no dedicated Dropbox
        // block-tree variant yet.
        let known_content_hash = init.checksums.iter().find_map(|ck| match ck.kind {
            HashKind::Sha256 => {
                dropbox_content_hash_from_single_block_sha256(&ck.hex, init.total_size)
            }
            _ => None,
        });
        let arg = build_commit_info(api_path, init.src_mtime_ns, known_content_hash.as_deref());
        let (status, headers, resp_body, streamed_hash) = self
            .content_upload(
                "Dropbox files/upload",
                "files/upload",
                &arg,
                body,
                init.total_size,
                true,
            )
            .await?;
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox files/upload",
                status,
                &headers,
                &resp_body,
            ));
        }
        let meta: DropboxMeta = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::protocol(format!("parse Dropbox upload metadata: {e}")))?;
        if let Some(server_hash) = meta
            .content_hash
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Some(ref streamed) = streamed_hash
                && !streamed.eq_ignore_ascii_case(server_hash)
            {
                return Err(checksum_mismatch_error(
                    "Dropbox files/upload",
                    "Dropbox content_hash",
                    streamed,
                    server_hash,
                ));
            }
            if let Some(ref known) = known_content_hash
                && !known.eq_ignore_ascii_case(server_hash)
            {
                return Err(checksum_mismatch_error(
                    "Dropbox files/upload",
                    "Dropbox content_hash",
                    known,
                    server_hash,
                ));
            }
        }
        self.entry_from_meta(meta)
            .ok_or_else(|| Error::protocol("Dropbox upload returned non-file metadata"))
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let arg = serde_json::json!({ "close": false });
        let (status, headers, body) = self
            .content_rpc_post(
                "Dropbox upload_session/start",
                "files/upload_session/start",
                &arg,
                None,
            )
            .await?;
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox upload_session/start",
                status,
                &headers,
                &body,
            ));
        }
        let resp: SessionStartResp = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse upload_session/start: {e}")))?;
        Ok(UploadSessionInit {
            session_token: resp.session_id,
            backend_meta: self.inner.cfg.api_path(init.dst_path.as_str()),
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    /// Recover live upload offset via Dropbox's 0-byte `append_v2` probe:
    /// - HTTP 200 at offset 0 -> server offset is `0`.
    /// - HTTP 409 `incorrect_offset` -> `error.correct_offset` gives exact committed bytes!
    /// - HTTP 409 `not_found` / `closed` -> `UploadProgress::Expired`.
    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(session_id) = op.session_token.as_deref() else {
            return Ok(UploadProgress::Expired);
        };
        let arg = serde_json::json!({
            "cursor": { "session_id": session_id, "offset": 0u64 },
            "close": false,
        });
        let (status, headers, body) = self
            .content_rpc_post(
                "Dropbox query upload_session",
                "files/upload_session/append_v2",
                &arg,
                None,
            )
            .await?;
        if status.is_success() {
            return Ok(UploadProgress::SequentialOffset(0));
        }
        if status == StatusCode::CONFLICT {
            let parsed = DropboxApiError::parse(&body);
            if let Some(correct_off) = parsed.incorrect_offset() {
                return Ok(UploadProgress::SequentialOffset(correct_off));
            }
            if parsed.is_session_expired() {
                return Ok(UploadProgress::Expired);
            }
        }
        Err(classify_dropbox_error(
            "Dropbox query upload_session",
            status,
            &headers,
            &body,
        ))
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let session_id = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing Dropbox upload session_id"))?;
        let is_final = chunk.offset + chunk.len == chunk.total_size;
        let api_path = if op.backend_meta.is_empty() {
            self.inner.cfg.api_path(op.dst_nfc_path.as_str())
        } else {
            op.backend_meta.clone()
        };

        if is_final {
            let arg = serde_json::json!({
                "cursor": { "session_id": session_id, "offset": chunk.offset },
                "commit": build_commit_info(api_path, op.src_version.mtime_ns, None),
            });
            let (status, headers, body, _) = self
                .content_upload(
                    "Dropbox upload_session/finish",
                    "files/upload_session/finish",
                    &arg,
                    chunk.body,
                    chunk.len,
                    false,
                )
                .await?;
            if status == StatusCode::CONFLICT {
                let parsed = DropboxApiError::parse(&body);
                if let Some(correct_off) = parsed.incorrect_offset() {
                    return Ok(ChunkAck {
                        next_offset: Some(correct_off),
                        etag: None,
                        completed: None,
                        checksum: None,
                    });
                }
                if parsed.is_session_expired() {
                    return Err(Error::session_expired("Dropbox upload session expired"));
                }
                return Err(classify_dropbox_error(
                    "Dropbox upload_session/finish",
                    status,
                    &headers,
                    &body,
                ));
            }
            let meta: DropboxMeta = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("parse upload_session/finish: {e}")))?;
            let entry = self
                .entry_from_meta(meta)
                .ok_or_else(|| Error::protocol("Dropbox finish returned non-file metadata"))?;
            return Ok(ChunkAck {
                next_offset: Some(chunk.total_size),
                etag: entry.etag.clone(),
                completed: Some(entry),
                checksum: None,
            });
        }

        let arg = serde_json::json!({
            "cursor": { "session_id": session_id, "offset": chunk.offset },
            "close": false,
        });
        let (status, headers, body, _) = self
            .content_upload(
                "Dropbox upload_session/append_v2",
                "files/upload_session/append_v2",
                &arg,
                chunk.body,
                chunk.len,
                false,
            )
            .await?;
        if status == StatusCode::CONFLICT {
            let parsed = DropboxApiError::parse(&body);
            if let Some(correct_off) = parsed.incorrect_offset() {
                return Ok(ChunkAck {
                    next_offset: Some(correct_off),
                    etag: None,
                    completed: None,
                    checksum: None,
                });
            }
            if parsed.is_session_expired() {
                return Err(Error::session_expired("Dropbox upload session expired"));
            }
            return Err(classify_dropbox_error(
                "Dropbox upload_session/append_v2",
                status,
                &headers,
                &body,
            ));
        }

        Ok(ChunkAck {
            next_offset: Some(chunk.offset + chunk.len),
            etag: None,
            completed: None,
            checksum: None,
        })
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        let session_id = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing Dropbox upload session_id"))?;
        let api_path = if op.backend_meta.is_empty() {
            self.inner.cfg.api_path(op.dst_nfc_path.as_str())
        } else {
            op.backend_meta.clone()
        };
        let client_modified = format_dropbox_client_modified(op.src_version.mtime_ns);
        let arg = serde_json::json!({
            "cursor": { "session_id": session_id, "offset": op.src_version.size },
            "commit": build_commit_info(api_path.clone(), op.src_version.mtime_ns, None),
        });
        // finish commits and closes the session: a replay after a lost response gets 409
        // `lookup_failed/...`. Dropbox has no custom metadata for an op id, and the multi-chunk
        // content_hash is not known here, so reconcile requires a NEW revision (vs. the
        // pre-commit snapshot) with our size and client_modified (when set).
        let rev_before = self.get_meta(&api_path).await?.and_then(|m| m.rev);
        let expected_size = op.src_version.size;
        let outcome = self
            .dropbox_request(
                "Dropbox upload_session/finish",
                DropboxCall::content("files/upload_session/finish", &arg),
                Some(self.inner.transport.config().long_control_timeout),
                Idempotency::NonIdempotent,
                |resp| {
                    super::ops::reconcile_on_409(
                        resp,
                        "Dropbox upload_session/finish",
                        DropboxApiError::is_session_expired,
                    )
                },
                |err| {
                    let api_path = api_path.clone();
                    let rev_before = rev_before.clone();
                    let client_modified = client_modified.clone();
                    async move {
                        if let Some(meta) = self.get_meta(&api_path).await?
                            && meta.tag == "file"
                            && meta.size == Some(expected_size)
                            && client_modified
                                .as_deref()
                                .is_none_or(|cm| meta.client_modified.as_deref() == Some(cm))
                            && meta.rev.is_some()
                            && meta.rev != rev_before
                        {
                            return Ok(ReconcileAction::Resolved(DbxOutcome::Reconciled(meta)));
                        }
                        if err.kind == ErrorKind::Conflict {
                            // The session is gone and the file is not ours.
                            return Ok(ReconcileAction::Fail(err));
                        }
                        Ok(ReconcileAction::Retry(err))
                    }
                },
            )
            .await?;
        let (status, headers, body) = match outcome {
            DbxOutcome::Reconciled(meta) => {
                return self
                    .entry_from_meta(meta)
                    .ok_or_else(|| Error::protocol("Dropbox finish returned non-file metadata"));
            }
            DbxOutcome::Response(r) => r,
        };
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox upload_session/finish",
                status,
                &headers,
                &body,
            ));
        }
        let meta: DropboxMeta = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse upload_session/finish: {e}")))?;
        self.entry_from_meta(meta)
            .ok_or_else(|| Error::protocol("Dropbox finish returned non-file metadata"))
    }

    pub(super) async fn abort_upload_impl(&self, _op: &OperationRecord) -> Result<()> {
        // Dropbox upload sessions auto-expire cleanly after 7 days with zero storage charge.
        Ok(())
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        // Proof: source size, the source mtime we set as `client_modified` (whole seconds,
        // when `mtime_ns > 0`), and a `rev` different from the planner's pre-op revision.
        // Size alone never proves a commit (see `common::reconcile`).
        let bp = BackendPath::from_rel(op.dst_nfc_path.clone());
        let Some(entry) = self.stat(&bp).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };
        if entry.kind != EntryKind::File {
            return Ok(ReconcileOutcome::NotCommitted);
        }
        let pre_op = crate::common::reconcile::PreOpState::from_precondition(
            &op.dst_precondition,
            |_, rev| rev.clone(),
        );
        let rev = entry.etag.clone();
        let mtime_tol = (op.src_version.mtime_ns > 0).then_some(1_000_000_000);
        Ok(crate::common::reconcile::judge_reconciled_object(
            op,
            entry,
            rev.as_deref(),
            &pre_op,
            mtime_tol,
            "Dropbox reconcile",
        ))
    }
}
