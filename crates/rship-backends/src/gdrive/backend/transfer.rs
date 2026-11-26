//! Google Drive data-plane reads (`open_read`), single-shot multipart upload,
//! resumable `308` sessions (`begin/query/upload/finish/abort`), ambiguous-commit
//! reconciliation, and zero-bandwidth server-side copy (`files.copy`).

use bytes::Bytes;
use futures::StreamExt;
use http::{Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, Result, RetryClass};
use std::sync::{Arc, Mutex as StdMutex};
use tracing::debug;

use crate::common::http::{
    Idempotency, PolicyDecision, bearer_header_value, execute_with_auth_policy, send_strict_upload,
    send_watched_sized_upload_with_capture,
};
use crate::common::{
    StreamingHashStream, StreamingMd5, StrictBodyStream, checksum_mismatch_error, lock_unpoisoned,
};
use crate::gdrive::changes::{ShortcutTargetKind, decode_shortcut_ref};
use crate::gdrive::config::GDRIVE_CHUNK_ALIGN_BYTES;
use crate::gdrive::error::{classify_gdrive_error, classify_gdrive_upload_error};
use crate::gdrive::query::{
    FILE_FIELDS, FOLDER_MIME, SHORTCUT_MIME, ensure_session_uri_params, format_rfc3339_millis,
    parse_content_range_308,
};

use super::streams::GdriveRangeReader;
use super::tree::ProbeFileOutcome;
use super::{DriveFile, GdriveBackend, GdriveSessionMeta};

impl GdriveBackend {
    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some(entry) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "gdrive object `{}` not found",
                path.nfc_path
            )));
        };
        self.open_read_entry_impl(&entry, path, None).await
    }

    pub(super) async fn open_read_entry_impl(
        &self,
        entry: &Entry,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let mut expected_md5 = entry
            .checksum
            .as_ref()
            .filter(|c| c.kind == HashKind::Md5 && !c.hex.trim().is_empty())
            .map(|c| c.hex.trim().to_ascii_lowercase());
        let mut expected_sha256 = entry
            .checksum
            .as_ref()
            .filter(|c| c.kind == HashKind::Sha256 && !c.hex.trim().is_empty())
            .map(|c| c.hex.trim().to_ascii_lowercase());

        let (file_id, total_len) = match entry.node_id.as_ref().or(path.node_id.as_ref()) {
            Some(nid) => {
                let mut resolved_id = nid.0.clone();
                let mut visited = std::collections::HashSet::new();
                visited.insert(resolved_id.clone());
                let mut resolved_to_non_shortcut = false;

                for _ in 0..8 {
                    if let Some((tid, tmime)) = self.lookup_shortcut_target(&resolved_id) {
                        if tmime == FOLDER_MIME {
                            return Err(Error::invalid_path(format!(
                                "cannot open directory `{}` for reading",
                                path.nfc_path
                            )));
                        }
                        if !visited.insert(tid.clone()) {
                            break;
                        }
                        resolved_id = tid;
                        if tmime != SHORTCUT_MIME {
                            resolved_to_non_shortcut = true;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if !resolved_to_non_shortcut && self.inner.cfg.use_changes_feed {
                    let scope = self.scope();
                    for _ in 0..8 {
                        let Ok(Some(rec)) = self
                            .inner
                            .inventory
                            .get_node(&scope.remote_name, &scope.corpus_id, &resolved_id)
                            .await
                        else {
                            break;
                        };
                        if rec.kind == EntryKind::Directory {
                            return Err(Error::invalid_path(format!(
                                "cannot open directory `{}` for reading",
                                path.nfc_path
                            )));
                        }
                        if let Some((tk, tid)) = decode_shortcut_ref(&rec) {
                            if tk == ShortcutTargetKind::Folder {
                                return Err(Error::invalid_path(format!(
                                    "cannot open directory `{}` for reading",
                                    path.nfc_path
                                )));
                            }
                            if !visited.insert(tid.to_string()) {
                                break;
                            }
                            resolved_id = tid.to_string();
                            if tk == ShortcutTargetKind::File {
                                // Check next iteration only if target happens to be in inventory;
                                // if external, `get_node` returns `None` and breaks with `tid`.
                                continue;
                            }
                        } else {
                            break;
                        }
                    }
                }
                (resolved_id, entry.size)
            }
            None => {
                let Some(resolved) = self.resolve_backend_path(path, true).await? else {
                    return Err(Error::not_found(format!(
                        "gdrive object `{}` not found",
                        path.nfc_path
                    )));
                };
                if resolved.effective_mime() == FOLDER_MIME {
                    return Err(Error::invalid_path(format!(
                        "cannot open directory `{}` for reading",
                        path.nfc_path
                    )));
                }
                let f = resolved.target.unwrap_or(resolved.node);
                if expected_md5.is_none() {
                    expected_md5 = f.checksum_for(HashKind::Md5).map(|c| c.hex);
                }
                if expected_sha256.is_none() {
                    expected_sha256 = f.checksum_for(HashKind::Sha256).map(|c| c.hex);
                }
                (f.id, f.size)
            }
        };
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            GdriveRangeReader {
                backend: self.clone(),
                file_id: tokio::sync::RwLock::new(file_id),
                shortcut_resolve_lock: tokio::sync::Mutex::new(()),
                resolved_shortcut: std::sync::atomic::AtomicBool::new(false),
                total_len: std::sync::atomic::AtomicU64::new(total_len),
                expected_md5: StdMutex::new(expected_md5),
                expected_sha256: StdMutex::new(expected_sha256),
            },
        )))
    }

    async fn prepare_upload_target(
        &self,
        init: &UploadInit,
    ) -> Result<(String, String, Option<String>)> {
        let file_name = init
            .dst_path
            .file_name()
            .ok_or_else(|| Error::invalid_path("cannot upload to root path"))?
            .to_string();
        let parent_rel = init.dst_path.parent().unwrap_or_else(RelPath::root);
        let parent_id = self.ensure_dir_chain(&parent_rel).await?;
        let existing_id = self
            .resolve_existing_file_id_for_upload(init, &parent_id, &file_name)
            .await?;
        Ok((file_name, parent_id, existing_id))
    }

    /// Single-shot `uploadType=multipart` (`multipart/related`) for small files (`<= 5 MiB`).
    /// Streams directly from `body` via [`StrictBodyStream`] without buffering the
    /// entire file in RAM, and strictly aborts the HTTP transfer on short EOF or stream
    /// error so any pre-existing file at destination is preserved intact.
    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let (file_name, parent_id, existing_id) = self.prepare_upload_target(init).await?;

        let mtime_rfc3339 = format_rfc3339_millis(init.src_mtime_ns);
        let (method, url, meta_json, new_file_id) = if let Some(fid) = existing_id {
            let url = self.upload_url(
                &["files", &fid],
                &[
                    ("uploadType", "multipart"),
                    ("fields", FILE_FIELDS),
                    ("supportsAllDrives", "true"),
                ],
            )?;
            let meta = serde_json::json!({
                "modifiedTime": mtime_rfc3339,
                "appProperties": {
                    "rship_op_id": init.op_id,
                }
            });
            (Method::PATCH, url, meta, None)
        } else {
            let file_id = match &init.pregenerated_id {
                Some(id) => id.0.clone(),
                None => self.generate_file_id().await?,
            };
            let url = self.upload_url(
                &["files"],
                &[
                    ("uploadType", "multipart"),
                    ("fields", FILE_FIELDS),
                    ("supportsAllDrives", "true"),
                ],
            )?;
            let meta = serde_json::json!({
                "id": file_id,
                "name": file_name,
                "parents": [parent_id],
                "modifiedTime": mtime_rfc3339,
                "appProperties": {
                    "rship_op_id": init.op_id,
                }
            });
            (Method::POST, url, meta, Some(file_id))
        };

        let meta_bytes = serde_json::to_vec(&meta_json)
            .map_err(|e| Error::protocol(format!("encode multipart metadata JSON: {e}")))?;
        let boundary = format!(
            "rship_mp_{}",
            init.op_id
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(32)
                .collect::<String>()
        );
        let preamble = format!(
            "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n",
            String::from_utf8_lossy(&meta_bytes)
        );
        let epilogue = format!("\r\n--{boundary}--\r\n");

        let total_content_len = (preamble.len() as u64)
            .checked_add(init.total_size)
            .and_then(|v| v.checked_add(epilogue.len() as u64))
            .ok_or_else(|| Error::invalid_geometry("multipart content length overflow"))?;

        let stream_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let md5_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let strict = StrictBodyStream::new("GDrive", body, init.total_size, stream_err.clone());
        let hashed = StreamingHashStream::new(
            strict,
            StreamingMd5::new(),
            init.total_size,
            md5_slot.clone(),
        );
        let pre_bytes = Bytes::from(preamble);
        let epi_bytes = Bytes::from(epilogue);
        let combined = futures::stream::once(async move { Ok(pre_bytes) })
            .chain(hashed)
            .chain(futures::stream::once(async move { Ok(epi_bytes) }));

        self.inner.data_limiter.acquire_send_permit().await;
        self.inner.data_limiter.acquire_write_permit().await;
        let token = self.inner.auth.access_token().await?;
        let auth_hdr = bearer_header_value(&token)?;

        let req = self
            .inner
            .transport
            .data_client()
            .request(method, &url)
            .header(http::header::AUTHORIZATION, auth_hdr)
            .header(
                http::header::CONTENT_TYPE,
                format!("multipart/related; boundary={boundary}"),
            )
            .header(http::header::CONTENT_LENGTH, total_content_len);

        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            "gdrive multipart upload",
            req,
            Box::pin(combined),
            total_content_len,
            stream_err,
        )
        .await?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if status == StatusCode::UNAUTHORIZED {
            let _ = self.inner.auth.force_refresh(&token).await?;
            return Err(Error::network(
                "OAuth token refreshed after 401 during multipart upload; retry single-shot",
            ));
        }

        if status == StatusCode::CONFLICT
            && let Some(ref pre_id) = new_file_id
            && let Ok(Some(existing)) = self.get_file_by_id(pre_id).await
            && !existing.trashed
            && existing.size == init.total_size
            && existing
                .app_properties
                .get("rship_op_id")
                .is_none_or(|v| v == &init.op_id)
        {
            let streamed_md5 = lock_unpoisoned(&md5_slot).take();
            verify_gdrive_md5(
                "GDrive upload MD5",
                existing.md5_checksum.as_deref(),
                streamed_md5.as_deref(),
                &init.checksums,
            )?;
            self.inner.data_limiter.record_success(false, false);
            self.cache_node(&existing, Some(&parent_id)).await;
            return Ok(self.drive_file_to_entry(
                &existing,
                init.dst_path.as_str(),
                init.dst_path.clone(),
            ));
        }

        if !status.is_success() {
            let err = classify_gdrive_upload_error(
                "gdrive multipart upload",
                status,
                &headers,
                &resp_body,
                false,
                self.inner.cfg.stop_on_upload_limit,
            );
            if err.retry == RetryClass::Throttled {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }

        self.inner.data_limiter.record_success(false, false);
        let created: DriveFile = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::protocol(format!("decode multipart upload JSON: {e}")))?;
        let streamed_md5 = lock_unpoisoned(&md5_slot).take();
        verify_gdrive_md5(
            "GDrive upload MD5",
            created.md5_checksum.as_deref(),
            streamed_md5.as_deref(),
            &init.checksums,
        )?;
        self.cache_node(&created, Some(&parent_id)).await;

        Ok(self.drive_file_to_entry(&created, init.dst_path.as_str(), init.dst_path.clone()))
    }

    /// Initiate a Google Drive resumable upload session:
    /// - Existing destination object -> `PATCH /upload/drive/v3/files/{fileId}?uploadType=resumable`
    /// - New destination object -> pre-generates `fileId` (`files.generateIds`) and issues
    ///   `POST /upload/drive/v3/files?uploadType=resumable` with `id` + `appProperties.rship_op_id`.
    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let (file_name, parent_id, existing_id) = self.prepare_upload_target(init).await?;

        let mtime_rfc3339 = format_rfc3339_millis(init.src_mtime_ns);
        let (method, url, meta_json, file_id, is_update) = if let Some(fid) = existing_id {
            let url = self.upload_url(
                &["files", &fid],
                &[
                    ("uploadType", "resumable"),
                    ("fields", FILE_FIELDS),
                    ("supportsAllDrives", "true"),
                ],
            )?;
            let meta = serde_json::json!({
                "modifiedTime": mtime_rfc3339,
                "appProperties": {
                    "rship_op_id": init.op_id,
                }
            });
            (Method::PATCH, url, meta, fid, true)
        } else {
            let pre_id = match &init.pregenerated_id {
                Some(id) => id.0.clone(),
                None => self.generate_file_id().await?,
            };
            let url = self.upload_url(
                &["files"],
                &[
                    ("uploadType", "resumable"),
                    ("fields", FILE_FIELDS),
                    ("supportsAllDrives", "true"),
                ],
            )?;
            let meta = serde_json::json!({
                "id": pre_id,
                "name": file_name,
                "parents": [parent_id],
                "modifiedTime": mtime_rfc3339,
                "appProperties": {
                    "rship_op_id": init.op_id,
                }
            });
            (Method::POST, url, meta, pre_id, false)
        };

        let meta_bytes = serde_json::to_vec(&meta_json)
            .map_err(|e| Error::protocol(format!("encode resumable init JSON: {e}")))?;
        let total_size_hdr = init.total_size.to_string();
        let policy_cfg = self.retry_policy_config(true);
        let stop_on_upload_limit = self.inner.cfg.stop_on_upload_limit;

        let session_uri = execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            "gdrive begin_upload",
            &policy_cfg,
            Idempotency::Idempotent,
            || {
                let method = method.clone();
                let url = url.clone();
                let meta_bytes = meta_bytes.clone();
                let total_size_hdr = total_size_hdr.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .request(method, &url)
                        .header(http::header::AUTHORIZATION, auth_hdr)
                        .header(
                            http::header::CONTENT_TYPE,
                            "application/json; charset=UTF-8",
                        )
                        .header("X-Upload-Content-Type", "application/octet-stream")
                        .header("X-Upload-Content-Length", total_size_hdr)
                        .body(meta_bytes);
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                if resp.status.is_success() {
                    let loc = match resp
                        .headers
                        .get(http::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .filter(|s| !s.is_empty())
                    {
                        Some(l) => l,
                        None => {
                            return PolicyDecision::Fail(Error::protocol(
                                "gdrive begin_upload succeeded without Location header",
                            ));
                        }
                    };
                    return match ensure_session_uri_params(loc) {
                        Ok(uri) => PolicyDecision::Ok(uri),
                        Err(e) => PolicyDecision::Fail(e),
                    };
                }
                let err = classify_gdrive_upload_error(
                    "gdrive begin_upload",
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    false,
                    stop_on_upload_limit,
                );
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
        )
        .await?;

        let backend_meta = serde_json::to_string(&GdriveSessionMeta {
            file_id: file_id.clone(),
            parent_id,
            is_update,
            total_size: init.total_size,
        })
        .unwrap_or_default();

        Ok(UploadSessionInit {
            session_token: session_uri,
            backend_meta,
            remote_op_id: Some(file_id),
            expires_at_unix_secs: Some(self.inner.clock.now_unix_secs() + 7 * 86_400),
        })
    }

    /// Query resumable upload progress using empty `PUT <session_uri>` with
    /// `Content-Range: bytes */<total_size>` and `?fields=...&supportsAllDrives=true`.
    /// Preserves `session_uri` across `401` refreshes!
    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        enum QueryUploadRaw {
            SequentialOffset(u64),
            Completed(Box<DriveFile>),
            Expired,
        }

        let raw_uri = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("query_upload called without session_token"))?;
        let session_uri = ensure_session_uri_params(raw_uri)?;
        let content_range = format!("bytes */{}", op.src_version.size);
        let policy_cfg = self.retry_policy_config(false);

        let raw = execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            "gdrive query_upload",
            &policy_cfg,
            Idempotency::Idempotent,
            || {
                let session_uri = session_uri.clone();
                let content_range = content_range.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .put(&session_uri)
                        .header(http::header::AUTHORIZATION, auth_hdr)
                        .header(http::header::CONTENT_LENGTH, "0")
                        .header(http::header::CONTENT_RANGE, content_range);
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                // Refresh token WITHOUT invalidating `session_uri`!
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                if resp.status.as_u16() == 308 {
                    return match parse_content_range_308(&resp.headers) {
                        Ok(next_offset) => {
                            PolicyDecision::Ok(QueryUploadRaw::SequentialOffset(next_offset))
                        }
                        Err(e) => PolicyDecision::Fail(e),
                    };
                }
                if resp.status == StatusCode::OK || resp.status == StatusCode::CREATED {
                    return match serde_json::from_slice::<DriveFile>(&resp.body) {
                        Ok(file) => PolicyDecision::Ok(QueryUploadRaw::Completed(Box::new(file))),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "decode query_upload completed JSON: {e}"
                        ))),
                    };
                }
                if resp.status == StatusCode::NOT_FOUND || resp.status == StatusCode::GONE {
                    return PolicyDecision::Ok(QueryUploadRaw::Expired);
                }
                let err = classify_gdrive_error(
                    "gdrive query_upload",
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    true,
                );
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
        )
        .await?;

        match raw {
            QueryUploadRaw::SequentialOffset(off) => Ok(UploadProgress::SequentialOffset(off)),
            QueryUploadRaw::Expired => Ok(UploadProgress::Expired),
            QueryUploadRaw::Completed(file) => {
                let fallback_parent = serde_json::from_str::<GdriveSessionMeta>(&op.backend_meta)
                    .ok()
                    .map(|m| m.parent_id);
                self.cache_node(&file, fallback_parent.as_deref()).await;
                let entry = self.drive_file_to_entry(
                    &file,
                    op.dst_raw_path.clone(),
                    op.dst_nfc_path.clone(),
                );
                Ok(UploadProgress::AlreadyCompleted(entry))
            }
        }
    }

    /// Stream one 256 KiB-aligned protocol chunk (or final unaligned chunk) onto
    /// `session_uri` over the HTTP/1.1 Data Plane with byte-progress stall watchdog.
    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        if chunk.len == 0 {
            return Err(Error::invalid_geometry("upload_chunk len must be > 0"));
        }
        let end_exclusive = chunk
            .offset
            .checked_add(chunk.len)
            .ok_or_else(|| Error::invalid_geometry("chunk offset + len overflow"))?;
        if end_exclusive > chunk.total_size {
            return Err(Error::invalid_geometry(format!(
                "chunk end ({end_exclusive}) exceeds total_size ({})",
                chunk.total_size
            )));
        }
        let is_final = end_exclusive == chunk.total_size;
        if !is_final && !chunk.len.is_multiple_of(GDRIVE_CHUNK_ALIGN_BYTES) {
            return Err(Error::invalid_geometry(format!(
                "non-final Google Drive chunk length ({}) must be a multiple of {} bytes",
                chunk.len, GDRIVE_CHUNK_ALIGN_BYTES
            )));
        }

        let raw_uri = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("upload_chunk called without session_token"))?;
        let session_uri = ensure_session_uri_params(raw_uri)?;
        let content_range = format!(
            "bytes {}-{}/{}",
            chunk.offset,
            end_exclusive - 1,
            chunk.total_size
        );

        self.inner.data_limiter.acquire_send_permit().await;
        let token = self.inner.auth.access_token().await?;
        let auth_hdr = bearer_header_value(&token)?;

        let req = self
            .inner
            .transport
            .data_client()
            .put(&session_uri)
            .header(http::header::AUTHORIZATION, auth_hdr)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(http::header::CONTENT_LENGTH, chunk.len)
            .header(http::header::CONTENT_RANGE, &content_range);

        let resp = send_strict_upload(
            &self.inner.transport,
            "gdrive upload_chunk",
            "GDrive",
            req,
            chunk.body,
            chunk.len,
        )
        .await?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if status == StatusCode::UNAUTHORIZED {
            // Refresh OAuth token immediately WITHOUT invalidating `session_uri`,
            // then signal retryable so the engine queries `308` and re-sends on the
            // exact same `session_uri`!
            let _ = self.inner.auth.force_refresh(&token).await?;
            return Err(Error::network(
                "OAuth token refreshed after 401 on upload_chunk; retry on same session_uri",
            ));
        }

        if status.as_u16() == 308 {
            let next_offset = parse_content_range_308(&headers)?;
            self.inner.data_limiter.record_success(false, false);
            return Ok(ChunkAck {
                next_offset: Some(next_offset),
                etag: None,
                completed: None,
                checksum: None,
            });
        }

        if status == StatusCode::OK || status == StatusCode::CREATED {
            self.inner.data_limiter.record_success(false, false);
            let file: DriveFile = serde_json::from_slice(&resp_body)
                .map_err(|e| Error::protocol(format!("decode upload_chunk final JSON: {e}")))?;
            let fallback_parent = serde_json::from_str::<GdriveSessionMeta>(&op.backend_meta)
                .ok()
                .map(|m| m.parent_id);
            self.cache_node(&file, fallback_parent.as_deref()).await;
            let entry =
                self.drive_file_to_entry(&file, op.dst_raw_path.clone(), op.dst_nfc_path.clone());
            return Ok(ChunkAck {
                next_offset: Some(chunk.total_size),
                etag: entry.etag.clone(),
                completed: Some(entry),
                checksum: None,
            });
        }

        let err = classify_gdrive_upload_error(
            "gdrive upload_chunk",
            status,
            &headers,
            &resp_body,
            true,
            self.inner.cfg.stop_on_upload_limit,
        );
        if err.retry == RetryClass::Throttled {
            self.inner.data_limiter.record_throttle();
        }
        Err(err)
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        match self.query_upload(op).await? {
            UploadProgress::AlreadyCompleted(entry) => Ok(entry),
            UploadProgress::Expired => match self.reconcile_operation(op).await? {
                ReconcileOutcome::Committed(entry) => Ok(entry),
                ReconcileOutcome::NotCommitted => Err(Error::session_expired(
                    "upload session expired before completion",
                )),
                ReconcileOutcome::Ambiguous(msg) => Err(Error::conflict(msg)),
                _ => Err(Error::protocol("unexpected reconcile outcome")),
            },
            UploadProgress::SequentialOffset(off) => Err(Error::protocol(format!(
                "finish_upload called while Google Drive only received {off}/{} bytes",
                op.src_version.size
            ))),
            UploadProgress::CompletedParts(_) => Err(Error::protocol("unexpected CompletedParts")),
            _ => Err(Error::protocol("unexpected upload progress variant")),
        }
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        let Some(raw_uri) = op.session_token.as_deref() else {
            return Ok(());
        };
        let token = self.inner.auth.access_token().await?;
        let auth_hdr = bearer_header_value(&token)?;
        let req = self
            .inner
            .transport
            .control_client()
            .delete(raw_uri)
            .header(http::header::AUTHORIZATION, auth_hdr)
            .header(http::header::CONTENT_LENGTH, "0");
        let resp = self
            .inner
            .transport
            .send_control_request("gdrive abort_upload", req)
            .await;

        match resp {
            Ok(r) => {
                let code = r.status().as_u16();
                // Drive returns 499 ("Client Closed Request") or 404/410 on session cancel.
                if r.status().is_success() || code == 404 || code == 410 || code == 499 {
                    Ok(())
                } else {
                    debug!(
                        status = code,
                        "abort_upload returned non-2xx; treating session as closed"
                    );
                    Ok(())
                }
            }
            Err(e) => {
                debug!(error = %e, "abort_upload network error ignored during cleanup");
                Ok(())
            }
        }
    }

    /// Reconcile an ambiguous commit (e.g. lost final `200`/`201` followed by `404`/`410`
    /// on `query_upload` or crash during `Completing`) using the pre-generated `fileId`
    /// (`op.remote_op_id`, checked first), `existing_dst_node_id`, session metadata, or
    /// falling back to searching the parent folder by `appProperties.rship_op_id`.
    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let meta = serde_json::from_str::<GdriveSessionMeta>(&op.backend_meta).ok();
        let meta_file_id = meta.as_ref().map(|m| m.file_id.clone());
        let is_update = meta
            .as_ref()
            .map(|m| m.is_update)
            .unwrap_or_else(|| op.existing_dst_node_id.is_some());

        let mut probed: Option<(DriveFile, Option<String>)> = None;

        // 1. Check `remote_op_id` first (exact pregenerated ID for creates/copies/resumable).
        if let Some(ref rem_id) = op.remote_op_id
            && let Some(file) = self.get_file_by_id(rem_id).await?
        {
            probed = Some((file, None));
        }

        // 2. Check `meta_file_id` (if distinct from `remote_op_id`).
        if probed.is_none()
            && let Some(ref mid) = meta_file_id
            && op.remote_op_id.as_deref() != Some(mid.as_str())
            && let Some(file) = self.get_file_by_id(mid).await?
        {
            probed = Some((file, None));
        }

        // 3. Check `existing_dst_node_id` (in-place PATCH overwrites). Note: if the existing
        //    node was a shortcut that got replaced by a new file, `existing_dst_node_id`
        //    will be missing or trashed as `SHORTCUT_MIME` — fall through to `find_child_by_op_id`!
        let mut replaced_shortcut = false;
        if probed.is_none()
            && let Some(ref existing_id) = op.existing_dst_node_id
            && op.remote_op_id.as_deref() != Some(existing_id.0.as_str())
        {
            match self.get_file_by_id(&existing_id.0).await? {
                Some(f) if f.mime_type == SHORTCUT_MIME => {
                    replaced_shortcut = true;
                }
                Some(f) => {
                    probed = Some((f, None));
                }
                None => {
                    if self.lookup_shortcut_target(&existing_id.0).is_some() {
                        replaced_shortcut = true;
                    } else {
                        // Could be a shortcut deleted before reconcile or disappeared target.
                        replaced_shortcut = true;
                    }
                }
            }
        }

        // 4. Fallback: search parent folder by `appProperties.rship_op_id` (covers single-shot
        //    overwrites where `prepare_operation_id` pre-generated an unused `remote_op_id`
        //    before `put_single_shot` chose `PATCH existing_id`, as well as shortcut replacements).
        if probed.is_none() {
            let parent_resolved = if op.dst_raw_path != op.dst_nfc_path.as_str() {
                let mut raw_segs: Vec<&str> = op
                    .dst_raw_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if !raw_segs.is_empty() {
                    raw_segs.pop();
                }
                let root_id = self.inner.cfg.effective_root_id().to_string();
                match self
                    .resolve_rel_path_from_id(&root_id, &raw_segs, true)
                    .await?
                {
                    Some(r) => Some(r),
                    None => {
                        let parent_rel = op.dst_nfc_path.parent().unwrap_or_else(RelPath::root);
                        self.resolve_rel_path_raw(&parent_rel, true).await?
                    }
                }
            } else {
                let parent_rel = op.dst_nfc_path.parent().unwrap_or_else(RelPath::root);
                self.resolve_rel_path_raw(&parent_rel, true).await?
            };
            if let Some(parent_resolved) = parent_resolved
                && let Some(found) = self
                    .find_child_by_op_id(parent_resolved.content_id(), &op.op_id)
                    .await?
            {
                probed = Some((found, Some(parent_resolved.content_id().to_string())));
            }
        }

        let Some((file, fallback_parent)) = probed else {
            return if op.existing_dst_node_id.is_none() || replaced_shortcut {
                Ok(ReconcileOutcome::NotCommitted)
            } else {
                Ok(ReconcileOutcome::Ambiguous(format!(
                    "target fileId `{}` disappeared during overwrite",
                    op.existing_dst_node_id
                        .as_ref()
                        .map_or("", |n| n.0.as_str())
                )))
            };
        };

        if file.trashed {
            return if op.existing_dst_node_id.is_none() || replaced_shortcut {
                Ok(ReconcileOutcome::NotCommitted)
            } else {
                Ok(ReconcileOutcome::Ambiguous(format!(
                    "target fileId `{}` was trashed during overwrite",
                    file.id
                )))
            };
        }

        let entry =
            self.drive_file_to_entry(&file, op.dst_raw_path.clone(), op.dst_nfc_path.clone());
        let op_id_matches = file
            .app_properties
            .get("rship_op_id")
            .is_some_and(|v| v == &op.op_id);

        // 1. Exact `rship_op_id` + size match proves our exact operation committed!
        if op_id_matches && entry.size == op.src_version.size {
            self.cache_node(&file, fallback_parent.as_deref()).await;
            return Ok(ReconcileOutcome::Committed(entry));
        }

        // 2. For a new object created with a pre-generated unique `fileId`, finding
        //    the live object with matching size proves commitment even if the server
        //    stripped or did not return `appProperties` (as long as no different op_id is set).
        if (!is_update || replaced_shortcut)
            && entry.size == op.src_version.size
            && !file
                .app_properties
                .get("rship_op_id")
                .is_some_and(|v| v != &op.op_id)
        {
            self.cache_node(&file, fallback_parent.as_deref()).await;
            return Ok(ReconcileOutcome::Committed(entry));
        }

        // 3. For an overwrite, if the destination still matches the pre-upload
        //    precondition (old size & mtime) and does NOT carry our `rship_op_id`,
        //    then our overwrite clearly never committed -> safe to restart!
        if let DstPrecondition::Existing {
            size: old_size,
            mtime_ns: old_mtime,
            ..
        } = &op.dst_precondition
            && !op_id_matches
            && entry.size == *old_size
            && (entry.mtime_ns - *old_mtime).abs() <= 1_000_000
        {
            return Ok(ReconcileOutcome::NotCommitted);
        }

        Ok(ReconcileOutcome::Ambiguous(format!(
            "destination fileId `{}` has unexpected state (size={}, expected={}, op_id_match={op_id_matches})",
            file.id, entry.size, op.src_version.size
        )))
    }

    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        let Some(rest) = src_endpoint.strip_prefix("gdrive://") else {
            return false;
        };
        let mut parts = rest.splitn(3, '/');
        let Some(src_principal) = parts.next() else {
            return false;
        };
        let Some(src_corpus) = parts.next() else {
            return false;
        };
        src_principal == self.inner.auth.principal() && !src_corpus.is_empty()
    }

    /// Zero-local-bandwidth server-side copy via `POST /drive/v3/files/{fileId}/copy`.
    ///
    /// Supports cross-drive copies (My Drive <-> Shared Drive, Shared Drive A <-> B) under
    /// the same principal, resolves shortcut sources to their target file ID, guards
    /// against resolving cross-root `None` `node_id` paths on `self`, and falls back to
    /// `Ok(None)` when overwriting an existing destination file so `PATCH /upload/...`
    /// preserves existing `fileId`, ACLs, and revision history.
    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        if !self.can_server_side_copy_from(src_endpoint) {
            return Ok(None);
        }
        let src_file_id = match &src_path.node_id {
            Some(nid) => {
                let mut cur_id = nid.0.clone();
                let mut visited = std::collections::HashSet::new();
                visited.insert(cur_id.clone());
                let mut resolved_file_id: Option<String> = None;

                for _ in 0..8 {
                    if let Some((tid, tmime)) = self.lookup_shortcut_target(&cur_id) {
                        if tmime == FOLDER_MIME {
                            return Ok(None);
                        }
                        if !visited.insert(tid.clone()) {
                            return Ok(None);
                        }
                        cur_id = tid;
                        if tmime != SHORTCUT_MIME {
                            resolved_file_id = Some(cur_id.clone());
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if resolved_file_id.is_none() {
                    let scope = self.scope();
                    let mut last_sc_kind: Option<ShortcutTargetKind> = None;
                    let mut hopped_in_inventory = false;
                    for _ in 0..8 {
                        if let Ok(Some(rec)) = self
                            .inner
                            .inventory
                            .get_node(&scope.remote_name, &scope.corpus_id, &cur_id)
                            .await
                        {
                            if (!self.inner.cfg.trashed_only && rec.trashed)
                                || rec.kind == EntryKind::Directory
                            {
                                return Ok(None);
                            }
                            if let Some((tk, tid)) = decode_shortcut_ref(&rec) {
                                if tk == ShortcutTargetKind::Folder {
                                    return Ok(None);
                                }
                                if !visited.insert(tid.to_string()) {
                                    return Ok(None);
                                }
                                cur_id = tid.to_string();
                                last_sc_kind = Some(tk);
                                hopped_in_inventory = true;
                                continue;
                            }
                            resolved_file_id = Some(rec.file_id);
                            break;
                        } else {
                            if hopped_in_inventory && last_sc_kind == Some(ShortcutTargetKind::File)
                            {
                                resolved_file_id = Some(cur_id.clone());
                            }
                            break;
                        }
                    }
                }

                if let Some(fid) = resolved_file_id {
                    fid
                } else {
                    let ProbeFileOutcome::Found(f) =
                        self.get_file_by_id_tolerating_403(&cur_id).await?
                    else {
                        return Ok(None);
                    };
                    let f = *f;
                    if (!self.inner.cfg.trashed_only && f.trashed)
                        || crate::gdrive::query::is_exportable_workspace_doc(&f.mime_type)
                        || f.mime_type == FOLDER_MIME
                    {
                        return Ok(None);
                    }
                    if f.mime_type == SHORTCUT_MIME {
                        let Some(target) = self.resolve_shortcut_target(f).await? else {
                            return Ok(None);
                        };
                        if target.mime_type == FOLDER_MIME || visited.contains(&target.id) {
                            return Ok(None);
                        }
                        target.id
                    } else {
                        f.id
                    }
                }
            }
            None => {
                // Only resolve `src_path` locally when source & destination share the
                // exact same Drive root/corpus (`endpoint_identity`). Cross-root copies without
                // `src_path.node_id` fall back to streaming copy (`Ok(None)`).
                if src_endpoint != self.endpoint_identity() {
                    return Ok(None);
                }
                match self.resolve_backend_path(src_path, true).await? {
                    Some(resolved) if resolved.effective_mime() != FOLDER_MIME => {
                        resolved.content_id().to_string()
                    }
                    _ => return Ok(None),
                }
            }
        };

        let (file_name, parent_id, existing_id) = self.prepare_upload_target(init).await?;

        // Preserve fileId & revision history on overwrite by falling back to PATCH upload.
        if existing_id.is_some() {
            return Ok(None);
        }

        let copy_id = match &init.pregenerated_id {
            Some(id) => id.0.clone(),
            None => self.generate_file_id().await?,
        };

        let url = self.api_url(
            &["files", &src_file_id, "copy"],
            &[("fields", FILE_FIELDS), ("supportsAllDrives", "true")],
        )?;

        let mtime_rfc3339 = format_rfc3339_millis(init.src_mtime_ns);
        let meta = serde_json::json!({
            "id": copy_id,
            "name": file_name,
            "parents": [parent_id],
            "modifiedTime": mtime_rfc3339,
            "appProperties": {
                "rship_op_id": init.op_id,
            }
        });

        let copied = self
            .control_create_with_id(
                "files.copy",
                url,
                &meta,
                &copy_id,
                Some(&init.op_id),
                false,
                self.inner.cfg.stop_on_upload_limit,
                Some(self.inner.transport.config().long_control_timeout),
            )
            .await?;
        self.cache_node(&copied, Some(&parent_id)).await;

        Ok(Some(self.drive_file_to_entry(
            &copied,
            init.dst_path.as_str(),
            init.dst_path.clone(),
        )))
    }
}

fn verify_gdrive_md5(
    context: &str,
    remote_md5: Option<&str>,
    streamed_md5: Option<&str>,
    known_checksums: &[Checksum],
) -> Result<()> {
    let Some(remote) = remote_md5.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    if let Some(streamed) = streamed_md5
        && !streamed.eq_ignore_ascii_case(remote)
    {
        return Err(checksum_mismatch_error(
            context,
            "MD5",
            &streamed.to_ascii_lowercase(),
            &remote.to_ascii_lowercase(),
        ));
    }
    for ck in known_checksums {
        if ck.kind == HashKind::Md5 {
            let expected = ck.hex.trim();
            if !expected.is_empty() && !expected.eq_ignore_ascii_case(remote) {
                return Err(checksum_mismatch_error(
                    context,
                    "MD5",
                    &expected.to_ascii_lowercase(),
                    &remote.to_ascii_lowercase(),
                ));
            }
        }
    }
    Ok(())
}
