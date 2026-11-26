//! GCS data-plane streaming downloads (`RemoteRangeReadable`), single-shot
//! `uploadType=multipart` uploads, 256 KiB-aligned resumable `308` upload sessions (with a
//! running CRC32C sent as `x-goog-hash` on the final request),
//! and ambiguous-commit reconciliation.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, UploadInit,
    UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::OperationRecord;
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use sha2::{Digest as _, Sha256};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::common::http::{Idempotency, PolicyDecision, send_watched_sized_upload_with_capture};
use crate::common::{
    BoundedSessionMap, Crc32cHasher, ExactDownloadStream, StreamingDigest, StreamingHashStream,
    StreamingMd5, StrictBodyStream, VerifyingDownloadStream, checksum_mismatch_error,
    crc32c_update, lock_unpoisoned,
};
use crate::gcs::config::{GCS_CHUNK_ALIGN_BYTES, gcs_encode_object_name};

use super::{
    GcsBackend, GcsInner, GcsObject, META_OP_ID, append_dst_precondition_query,
    append_user_project_cfg, map_gcs_http_error_with_headers,
};

static MULTIPART_BOUNDARY_SEQ: AtomicU64 = AtomicU64::new(1);

fn generate_multipart_boundary(op_id: &str, full_key: &str) -> String {
    let mut h1 = RandomState::new().build_hasher();
    h1.write_u64(MULTIPART_BOUNDARY_SEQ.fetch_add(1, Ordering::Relaxed));
    let r1 = h1.finish();
    let r2 = RandomState::new().build_hasher().finish();
    let now_ns = rship_core::time::now_unix_nanos();
    let mut hasher = Sha256::new();
    hasher.update(r1.to_le_bytes());
    hasher.update(r2.to_le_bytes());
    hasher.update(now_ns.to_le_bytes());
    hasher.update(op_id.as_bytes());
    hasher.update(b":");
    hasher.update(full_key.as_bytes());
    let digest = hasher.finalize();
    format!("rship_gcs_mp_{}", hex::encode(&digest[..16]))
}

/// Parse GCS `x-goog-hash` headers (either multiple headers or comma-separated
/// `crc32c=<b64>, md5=<b64>`) into lowercase hex `(crc32c_hex, md5_hex)`.
fn parse_x_goog_hash(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let mut crc32c_hex = None;
    let mut md5_hex = None;
    for val in headers.get_all("x-goog-hash") {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for item in raw.split(',') {
            let Some((kind, b64)) = item.trim().split_once('=') else {
                continue;
            };
            match kind.trim().to_ascii_lowercase().as_str() {
                "crc32c" if crc32c_hex.is_none() => {
                    if let Ok(bytes) = B64.decode(b64.trim())
                        && bytes.len() == 4
                    {
                        crc32c_hex = Some(hex::encode(bytes));
                    }
                }
                "md5" if md5_hex.is_none() => {
                    if let Ok(bytes) = B64.decode(b64.trim())
                        && bytes.len() == 16
                    {
                        md5_hex = Some(hex::encode(bytes));
                    }
                }
                _ => {}
            }
        }
    }
    (crc32c_hex, md5_hex)
}

/// Verify server-returned GCS object hashes (`crc32c` / `md5Hash`) against the on-the-fly
/// streamed CRC32C digest and any known source checksums whose kind matches.
fn verify_gcs_object_checksums(
    context: &str,
    obj: &GcsObject,
    streamed_crc32c: Option<&str>,
    source_checksums: &[Checksum],
) -> Result<()> {
    let server_crc = obj.crc32c_hex();
    let server_md5 = obj.md5_hex();

    if let (Some(streamed), Some(server)) = (streamed_crc32c, &server_crc)
        && !streamed.eq_ignore_ascii_case(server)
    {
        return Err(checksum_mismatch_error(context, "CRC32C", streamed, server));
    }

    for src_ck in source_checksums {
        match src_ck.kind {
            HashKind::Crc32c => {
                if let Some(server) = &server_crc
                    && !src_ck.hex.eq_ignore_ascii_case(server)
                {
                    return Err(checksum_mismatch_error(
                        context,
                        "CRC32C",
                        &src_ck.hex.to_ascii_lowercase(),
                        server,
                    ));
                }
            }
            HashKind::Md5 => {
                if let Some(server) = &server_md5
                    && !src_ck.hex.eq_ignore_ascii_case(server)
                {
                    return Err(checksum_mismatch_error(
                        context,
                        "MD5",
                        &src_ck.hex.to_ascii_lowercase(),
                        server,
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_gcs_session_expected_checksums(backend_meta: &str) -> Vec<Checksum> {
    serde_json::from_str::<serde_json::Value>(backend_meta)
        .ok()
        .and_then(|v| v.get("checksums").cloned())
        .and_then(|c| serde_json::from_value::<Vec<Checksum>>(c).ok())
        .unwrap_or_default()
}

/// Running CRC32C of the bytes GCS has confirmed for one resumable session.
///
/// GCS checks a resumable upload end to end only when the final request carries
/// `x-goog-hash: crc32c=<CRC of the whole object>`, so the CRC is accumulated chunk by chunk
/// while the data streams. The state lives in memory, keyed by session URI, because the
/// engine passes `upload_chunk` an immutable [`OperationRecord`] and never re-persists
/// `backend_meta` after `begin_upload`. That has two deliberate consequences:
/// - A session resumed by a new process has no running CRC. Its final request goes out
///   without `x-goog-hash`, so the object is checked only against source checksums known up
///   front (`crc32c`/`md5Hash` in the initiation metadata). Without those, the upload is
///   **unverified**.
/// - If GCS confirms an offset other than the end of the bytes just hashed (a partial
///   persist), the state is dropped and the upload falls back to unverified in the same way.
#[derive(Debug, Clone, Copy)]
struct RunningCrc32c {
    /// Session offset up to which `register` covers the uploaded bytes.
    next_offset: u64,
    /// Raw reflected CRC32C register (starts at `u32::MAX`, not yet complemented).
    register: u32,
}

/// Per-process bounded table of [`RunningCrc32c`] states, keyed by resumable session URI.
#[derive(Debug)]
pub(super) struct ResumableCrcMap(StdMutex<BoundedSessionMap<String, RunningCrc32c>>);

impl Default for ResumableCrcMap {
    fn default() -> Self {
        Self(StdMutex::new(BoundedSessionMap::with_defaults()))
    }
}

impl ResumableCrcMap {
    #[cfg(test)]
    fn with_limits(max_entries: usize, ttl: std::time::Duration) -> Self {
        Self(StdMutex::new(BoundedSessionMap::new(max_entries, ttl)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BoundedSessionMap<String, RunningCrc32c>> {
        lock_unpoisoned(&self.0)
    }

    fn start(&self, session_uri: &str) {
        self.lock().insert(
            session_uri.to_string(),
            RunningCrc32c {
                next_offset: 0,
                register: u32::MAX,
            },
        );
    }

    /// Register covering `[0, offset)`, if the tracked state ends exactly at `offset`.
    /// A state at any other offset can never become valid again and is dropped.
    fn at(&self, session_uri: &str, offset: u64) -> Option<u32> {
        let mut map = self.lock();
        let key = session_uri.to_string();
        match map.get_mut(&key) {
            Some(st) if st.next_offset == offset => Some(st.register),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    fn advance(&self, session_uri: &str, next_offset: u64, register: u32) {
        let key = session_uri.to_string();
        if let Some(st) = self.lock().get_mut(&key) {
            *st = RunningCrc32c {
                next_offset,
                register,
            };
        }
    }

    fn forget(&self, session_uri: &str) {
        self.lock().remove(&session_uri.to_string());
    }
}

/// [`StreamingDigest`] that continues a raw CRC32C register and yields the raw register, so
/// the result can seed the next chunk of the same resumable session.
struct Crc32cRegister(u32);

impl StreamingDigest for Crc32cRegister {
    type Output = u32;

    fn update(&mut self, chunk: &[u8]) {
        self.0 = crc32c_update(self.0, chunk);
    }

    fn finalize(self) -> u32 {
        self.0
    }
}

/// `x-goog-hash` value for a finalized CRC32C: base64 of its 4 big-endian bytes.
fn crc32c_x_goog_hash(crc: u32) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("crc32c={}", B64.encode(crc.to_be_bytes())))
        .map_err(|e| Error::protocol(format!("x-goog-hash header: {e}")))
}

/// Recognize the HTTP 400 GCS returns when an integrity check fails, e.g.
/// `Provided CRC32C "…" doesn't match calculated CRC32C "…".` (or the `MD5 hash` variant).
/// Returns the algorithm and, when parseable, the server-calculated value as lowercase hex.
fn parse_gcs_integrity_rejection(body: &[u8]) -> Option<(&'static str, Option<String>)> {
    let parsed_msg = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    let text: std::borrow::Cow<'_, str> = match parsed_msg {
        Some(m) => std::borrow::Cow::Owned(m),
        None => String::from_utf8_lossy(body),
    };
    for (algorithm, marker) in [
        ("CRC32C", "calculated CRC32C \""),
        ("CRC32C", "calculated CRC32C \\\""),
        ("MD5", "calculated MD5 hash \""),
        ("MD5", "calculated MD5 hash \\\""),
    ] {
        let Some(pos) = text.find(marker) else {
            continue;
        };
        let calculated = text[pos + marker.len()..]
            .split(['"', '\\'])
            .next()
            .and_then(|b64| B64.decode(b64.trim()).ok())
            .map(hex::encode);
        return Some((algorithm, calculated));
    }
    None
}

/// Yields exactly the first `remaining` bytes of `inner`, then parks `inner`, together with
/// the unread part of the item that straddled the boundary, in `rest`. The caller can then
/// keep reading the same source after the request that carried the head has completed.
struct SplitHeadStream {
    inner: Option<ByteStream>,
    remaining: u64,
    rest: Arc<StdMutex<Option<(ByteStream, Bytes)>>>,
}

impl futures::Stream for SplitHeadStream {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let this = self.as_mut().get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(mut chunk))) => {
                let len = chunk.len() as u64;
                if len < this.remaining {
                    this.remaining -= len;
                    return Poll::Ready(Some(Ok(chunk)));
                }
                // `remaining <= chunk.len()`, so the cast is lossless.
                let head = chunk.split_to(this.remaining as usize);
                this.remaining = 0;
                if let Some(inner) = this.inner.take() {
                    *lock_unpoisoned(&this.rest) = Some((inner, chunk));
                }
                Poll::Ready(Some(Ok(head)))
            }
            other => other,
        }
    }
}

/// Read exactly `len` bytes (`leftover` first, then `stream`) into one buffer, verifying clean EOF.
///
/// The read is not covered by the HTTP data-plane watchdog, so it applies the same
/// `stall_timeout`: a source that yields no bytes for that long fails with a retryable
/// timeout instead of hanging the upload.
async fn read_exact_bytes(
    mut stream: ByteStream,
    leftover: Bytes,
    len: u64,
    stall_timeout: std::time::Duration,
) -> Result<Bytes> {
    let len = usize::try_from(len)
        .map_err(|_| Error::invalid_geometry("GCS final chunk tail exceeds usize"))?;
    let exceeded = || Error::source_mutated("GCS upload stream exceeded declared chunk length");
    if leftover.len() > len {
        return Err(exceeded());
    }
    let mut buf = BytesMut::with_capacity(len);
    buf.extend_from_slice(&leftover);
    let mut deadline = tokio::time::Instant::now() + stall_timeout;
    while buf.len() < len {
        let Ok(item) = tokio::time::timeout_at(deadline, stream.next()).await else {
            return Err(Error::timeout(format!(
                "GCS upload source stalled for {stall_timeout:?} with no byte progress \
                 (at {} of {len} final-chunk bytes)",
                buf.len()
            )));
        };
        match item {
            Some(Ok(bytes)) => {
                if buf.len() + bytes.len() > len {
                    return Err(exceeded());
                }
                if !bytes.is_empty() {
                    deadline = tokio::time::Instant::now() + stall_timeout;
                }
                buf.extend_from_slice(&bytes);
            }
            Some(Err(e)) => return Err(e),
            None => {
                return Err(Error::source_mutated(format!(
                    "short EOF during GCS upload: received {} of {len} final-chunk bytes",
                    buf.len()
                )));
            }
        }
    }
    loop {
        let Ok(item) = tokio::time::timeout_at(deadline, stream.next()).await else {
            return Err(Error::timeout(format!(
                "GCS upload source stalled waiting for EOF after {len} final-chunk bytes"
            )));
        };
        match item {
            None => break,
            Some(Ok(bytes)) if bytes.is_empty() => continue,
            Some(Ok(_)) => return Err(exceeded()),
            Some(Err(e)) => return Err(e),
        }
    }
    Ok(buf.freeze())
}

/// What one resumable `PUT` carried, so its response can be checked and the session's
/// running CRC advanced.
struct ResumablePutSent {
    offset: u64,
    len: u64,
    /// CRC32C register after this request's bytes, when the session's CRC is tracked.
    register_after: Option<u32>,
    /// Whole-object CRC32C (lowercase hex) sent in `x-goog-hash` on a final request.
    final_crc32c_hex: Option<String>,
}

/// Raw response of one resumable `PUT`: status, headers, body, and the bearer token used.
type ResumablePutResponse = (StatusCode, HeaderMap, Bytes, Option<String>);

/// Parse GCS `308 Resume Incomplete` `Range: bytes=0-N` header into next byte offset (`N + 1`).
fn parse_gcs_resume_range(headers: &HeaderMap) -> Option<u64> {
    let raw = headers.get(http::header::RANGE)?.to_str().ok()?.trim();
    let rest = raw.strip_prefix("bytes=")?;
    let (_, end_str) = rest.split_once('-')?;
    let end_inclusive = end_str.trim().parse::<u64>().ok()?;
    end_inclusive.checked_add(1)
}

struct GcsRangeReader {
    inner: Arc<GcsInner>,
    full_key: String,
    generation: Option<String>,
    total_len: u64,
}

#[async_trait]
impl RemoteRangeReadable for GcsRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            if range.offset > self.total_len {
                return Err(Error::invalid_geometry(format!(
                    "GCS empty read range offset {} exceeds object size {}",
                    range.offset, self.total_len
                )));
            }
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_inclusive = range
            .offset
            .checked_add(range.len - 1)
            .ok_or_else(|| Error::invalid_geometry("GCS read range overflow"))?;
        if end_inclusive >= self.total_len {
            return Err(Error::invalid_geometry(format!(
                "GCS read range {}..{} exceeds object size {}",
                range.offset,
                range.offset.saturating_add(range.len),
                self.total_len
            )));
        }

        let base = format!(
            "{}/b/{}/o/{}",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            gcs_encode_object_name(&self.inner.cfg.bucket),
            gcs_encode_object_name(&self.full_key)
        );
        let mut url = url::Url::parse(&base)
            .map_err(|e| Error::protocol(format!("parse GCS download URL: {e}")))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("alt", "media");
            if let Some(gen_id) = &self.generation
                && !gen_id.is_empty()
            {
                qp.append_pair("generation", gen_id);
            }
            append_user_project_cfg(&self.inner.cfg, &mut qp);
        }

        let mut refreshed_token = false;
        let resp = loop {
            self.inner.data_limiter.acquire_send_permit().await;
            let mut headers = HeaderMap::new();
            let used_tok = self.inner.apply_auth(&mut headers).await?;
            // Ask GCS to serve stored gzip objects verbatim (preventing decompressive transcoding);
            // `data_client()` configures `.no_gzip()` so reqwest does not decompress on the client.
            headers.insert(
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            headers.insert(
                http::header::RANGE,
                HeaderValue::from_str(&format!("bytes={}-{}", range.offset, end_inclusive))
                    .map_err(|e| Error::protocol(format!("invalid Range header: {e}")))?,
            );

            let req = self
                .inner
                .transport
                .data_client()
                .get(url.as_str())
                .headers(headers);
            let resp = self
                .inner
                .transport
                .send_data_request("GCS range download", req)
                .await?;
            let status = resp.status();

            if status == StatusCode::PARTIAL_CONTENT
                || (status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
            {
                break resp;
            }

            let resp_headers = resp.headers().clone();
            let body = self.inner.transport.read_data_body(resp).await?;

            if status == StatusCode::UNAUTHORIZED
                && !refreshed_token
                && let (Some(auth), Some(tok)) = (&self.inner.auth, used_tok.as_deref())
            {
                refreshed_token = true;
                auth.force_refresh(tok).await?;
                continue;
            }

            if self.generation.as_deref().is_some_and(|g| !g.is_empty())
                && matches!(
                    status,
                    StatusCode::NOT_FOUND | StatusCode::PRECONDITION_FAILED
                )
            {
                return Err(Error::source_mutated(format!(
                    "GCS object `{}` generation `{}` mutated or deleted (HTTP {})",
                    self.full_key,
                    self.generation.as_deref().unwrap_or(""),
                    status.as_u16()
                )));
            }

            let err = map_gcs_http_error_with_headers(
                "GCS range download",
                status,
                Some(&resp_headers),
                &body,
            );
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        };

        self.inner.data_limiter.record_success(false, false);

        let is_full_object = range.offset == 0 && range.len == self.total_len;
        let resp_headers = resp.headers().clone();
        let watched = self
            .inner
            .transport
            .watch_response_stream("GCS download stream", resp);
        let exact = ExactDownloadStream::new("GCS", watched, range.len);
        if is_full_object {
            let (crc32c_hex, md5_hex) = parse_x_goog_hash(&resp_headers);
            if let Some(expected_crc) = crc32c_hex {
                return Ok(Box::pin(VerifyingDownloadStream::new(
                    "GCS",
                    "CRC32C",
                    exact,
                    Crc32cHasher::new(),
                    range.len,
                    expected_crc,
                )));
            }
            if let Some(expected_md5) = md5_hex {
                return Ok(Box::pin(VerifyingDownloadStream::new(
                    "GCS",
                    "MD5",
                    exact,
                    StreamingMd5::new(),
                    range.len,
                    expected_md5,
                )));
            }
        }
        Ok(Box::pin(exact))
    }
}

impl GcsBackend {
    async fn finish_open_read(
        &self,
        full_key: String,
        generation: Option<String>,
        total_len: u64,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let reader = Arc::new(GcsRangeReader {
            inner: self.inner.clone(),
            full_key,
            generation,
            total_len,
        });
        if let Some(r) = range {
            let stream = reader.open_range(r).await?;
            return Ok(DataSource::SequentialStream {
                stream,
                total_len: Some(r.len),
            });
        }
        Ok(DataSource::RemoteRangeReadable(reader))
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let full_key = self.inner.cfg.full_key(path.raw_path());
        let pinned_gen = path
            .node_id
            .as_ref()
            .map(|n| n.0.trim())
            .filter(|s| !s.is_empty());
        let Some(obj) = self.get_object_meta(&full_key).await? else {
            if let Some(expected_gen) = pinned_gen {
                return Err(Error::source_mutated(format!(
                    "GCS object `{full_key}` (pinned generation `{expected_gen}`) not found"
                )));
            }
            return Err(Error::not_found(format!(
                "GCS object `{full_key}` not found"
            )));
        };
        if let Some(expected_gen) = pinned_gen
            && obj.generation.as_deref() != Some(expected_gen)
        {
            return Err(Error::source_mutated(format!(
                "GCS object `{full_key}` generation changed (expected `{expected_gen}`, got `{}`)",
                obj.generation.as_deref().unwrap_or("<none>")
            )));
        }
        let total_len = obj.parsed_size();
        self.finish_open_read(full_key, obj.generation, total_len, range)
            .await
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
        let raw_rel = path
            .raw_path
            .as_deref()
            .or(entry.raw_path.as_deref())
            .unwrap_or_else(|| path.nfc_path.as_str());
        let full_key = self.inner.cfg.full_key(raw_rel);
        let generation = entry
            .node_id
            .as_ref()
            .or(path.node_id.as_ref())
            .map(|n| n.0.as_str())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_string);
        self.finish_open_read(full_key, generation, entry.size, range)
            .await
    }

    fn clear_upload_401_guard(&self, op_id: &str) {
        lock_unpoisoned(&self.inner.refreshed_401_tokens).remove(&op_id.to_string());
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_upload_error_response(
        &self,
        context: &str,
        op_id: &str,
        status: StatusCode,
        resp_headers: &HeaderMap,
        resp_body: &[u8],
        used_tok: Option<&str>,
        provided_crc32c_hex: Option<&str>,
    ) -> Error {
        if status == StatusCode::UNAUTHORIZED
            && let (Some(auth), Some(tok)) = (&self.inner.auth, used_tok)
        {
            let key = op_id.to_string();
            let already_refreshed_this_tok = lock_unpoisoned(&self.inner.refreshed_401_tokens)
                .get_mut(&key)
                .is_some_and(|prev| prev == tok);
            if already_refreshed_this_tok {
                return Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!("{context}: HTTP 401 after OAuth token refresh"),
                );
            }
            match auth.force_refresh(tok).await {
                Ok(new_tok) if new_tok != tok => {
                    lock_unpoisoned(&self.inner.refreshed_401_tokens).insert(key, new_tok);
                    return Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Retryable,
                        format!("{context}: HTTP 401 (OAuth token refreshed; retry upload)"),
                    );
                }
                Ok(_) => {
                    return Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        format!("{context}: HTTP 401 (token refresh returned unchanged token)"),
                    );
                }
                Err(refresh_err) => return refresh_err,
            }
        }
        if status == StatusCode::BAD_REQUEST
            && let Some((algorithm, calculated)) = parse_gcs_integrity_rejection(resp_body)
        {
            let provided = match (algorithm, provided_crc32c_hex) {
                ("CRC32C", Some(hex)) => hex.to_string(),
                _ => "source checksum".to_string(),
            };
            return checksum_mismatch_error(
                &format!("{context} (rejected by server)"),
                algorithm,
                &provided,
                calculated.as_deref().unwrap_or("server-calculated value"),
            );
        }
        let err = map_gcs_http_error_with_headers(context, status, Some(resp_headers), resp_body);
        if err.is_throttled() {
            self.inner.data_limiter.record_throttle();
        }
        err
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let full_key = self.inner.cfg.full_key(init.dst_path.as_str());
        let meta_json = serde_json::to_vec(&self.build_upload_metadata_json(init, &full_key))
            .map_err(|e| Error::protocol(format!("encode GCS multipart metadata: {e}")))?;

        let boundary = generate_multipart_boundary(&init.op_id, &full_key);
        let mut prefix_bytes = Vec::with_capacity(meta_json.len() + 192);
        prefix_bytes.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
                .as_bytes(),
        );
        prefix_bytes.extend_from_slice(&meta_json);
        prefix_bytes.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n")
                .as_bytes(),
        );
        let suffix_bytes = Bytes::from(format!("\r\n--{boundary}--\r\n"));
        let total_http_len =
            prefix_bytes.len() as u64 + init.total_size + suffix_bytes.len() as u64;

        let mut url = self.bucket_upload_url()?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("uploadType", "multipart");
            append_dst_precondition_query(
                &mut qp,
                &init.precondition,
                init.existing_node_id.as_ref(),
            );
            self.append_user_project_pair(&mut qp);
        }

        let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let crc_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let strict = StrictBodyStream::new("GCS", body, init.total_size, captured_err.clone());
        let hashed = StreamingHashStream::new(
            strict,
            Crc32cHasher::new(),
            init.total_size,
            crc_slot.clone(),
        );
        let combined = futures::stream::once(async move { Ok(Bytes::from(prefix_bytes)) })
            .chain(hashed)
            .chain(futures::stream::once(async move { Ok(suffix_bytes) }));

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        let used_tok = self.apply_auth(&mut headers).await?;
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/related; boundary={boundary}"))
                .map_err(|e| Error::protocol(format!("multipart header: {e}")))?,
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&total_http_len.to_string())
                .map_err(|e| Error::protocol(format!("content-length header: {e}")))?,
        );

        let req = self
            .inner
            .transport
            .data_client()
            .post(url.as_str())
            .headers(headers);
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            "GCS single-shot upload",
            req,
            Box::pin(combined),
            total_http_len,
            captured_err,
        )
        .await?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;
        if !status.is_success() {
            return Err(self
                .handle_upload_error_response(
                    "GCS single-shot upload",
                    &init.op_id,
                    status,
                    &resp_headers,
                    &resp_body,
                    used_tok.as_deref(),
                    None,
                )
                .await);
        }
        self.clear_upload_401_guard(&init.op_id);
        self.inner.data_limiter.record_success(false, false);
        let obj: GcsObject = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::protocol(format!("parse GCS upload response JSON: {e}")))?;
        let streamed_crc = lock_unpoisoned(&crc_slot).take();
        verify_gcs_object_checksums(
            "GCS single-shot upload",
            &obj,
            streamed_crc.as_deref(),
            &init.checksums,
        )?;
        self.object_to_entry(&obj)?
            .ok_or_else(|| Error::protocol("GCS upload response outside configured prefix"))
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let full_key = self.inner.cfg.full_key(init.dst_path.as_str());
        let meta_bytes = Bytes::from(
            serde_json::to_vec(&self.build_upload_metadata_json(init, &full_key))
                .map_err(|e| Error::protocol(format!("encode GCS resumable init JSON: {e}")))?,
        );

        let mut url = self.bucket_upload_url()?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("uploadType", "resumable");
            append_dst_precondition_query(
                &mut qp,
                &init.precondition,
                init.existing_node_id.as_ref(),
            );
            self.append_user_project_pair(&mut qp);
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=UTF-8"),
        );
        headers.insert(
            HeaderName::from_static("x-upload-content-type"),
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            HeaderName::from_static("x-upload-content-length"),
            HeaderValue::from_str(&init.total_size.to_string())
                .map_err(|e| Error::protocol(format!("x-upload-content-length: {e}")))?,
        );

        let (_, resp_headers, _) = self
            .control_request(
                "GCS begin resumable upload",
                Method::POST,
                url.as_str(),
                headers,
                Some(meta_bytes),
                false,
            )
            .await?;

        let session_uri = resp_headers
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::protocol("GCS resumable initiation missing Location header"))?
            .to_string();
        self.inner.resumable_crc.start(&session_uri);

        Ok(UploadSessionInit {
            session_token: session_uri,
            backend_meta: serde_json::json!({
                "full_key": full_key,
                "checksums": init.checksums,
            })
            .to_string(),
            remote_op_id: None,
            expires_at_unix_secs: None,
        })
    }

    async fn query_upload_inner(
        &self,
        op: &OperationRecord,
    ) -> Result<(UploadProgress, Option<GcsObject>)> {
        let Some(session_uri) = op.session_token.as_deref() else {
            return Ok((UploadProgress::Expired, None));
        };
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        headers.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_static("bytes */*"),
        );

        let (status, resp_headers, resp_body) = self
            .control_request_with_policy(
                "GCS query resumable upload",
                Method::PUT,
                session_uri,
                headers,
                Some(Bytes::new()),
                false,
                Idempotency::Idempotent,
                |resp| {
                    if resp.status.is_success() || matches!(resp.status.as_u16(), 308 | 404 | 410) {
                        return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                    }
                    PolicyDecision::from_error(map_gcs_http_error_with_headers(
                        "GCS query resumable upload",
                        resp.status,
                        Some(&resp.headers),
                        &resp.body,
                    ))
                },
            )
            .await?;

        if status.as_u16() == 308 {
            let confirmed = parse_gcs_resume_range(&resp_headers).unwrap_or(0);
            return Ok((UploadProgress::SequentialOffset(confirmed), None));
        }
        // The session is finished (or gone): its running CRC can never be used again.
        self.inner.resumable_crc.forget(session_uri);
        if status.is_success() {
            let obj: GcsObject = serde_json::from_slice(&resp_body)
                .map_err(|e| Error::protocol(format!("parse GCS completed JSON: {e}")))?;
            let entry = self
                .object_to_entry(&obj)?
                .ok_or_else(|| Error::protocol("GCS completed object outside prefix"))?;
            return Ok((UploadProgress::AlreadyCompleted(entry), Some(obj)));
        }
        Ok((UploadProgress::Expired, None))
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        Ok(self.query_upload_inner(op).await?.0)
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let session_uri = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("GCS upload_chunk missing session_token"))?;
        let is_final = chunk.offset.checked_add(chunk.len) == Some(chunk.total_size);
        let running = self.inner.resumable_crc.at(session_uri, chunk.offset);

        if chunk.len == 0 {
            let mut body = chunk.body;
            while let Some(item) = body.next().await {
                let bytes = item?;
                if !bytes.is_empty() {
                    return Err(Error::source_mutated(
                        "GCS upload chunk yielded non-empty bytes for 0-byte chunk",
                    ));
                }
            }
            let final_crc = running.filter(|_| is_final).map(|register| !register);
            let x_goog_hash = final_crc.map(crc32c_x_goog_hash).transpose()?;
            let resp = self
                .send_resumable_put(
                    session_uri,
                    chunk.offset,
                    0,
                    chunk.total_size,
                    futures::stream::empty(),
                    Arc::new(StdMutex::new(None)),
                    x_goog_hash,
                )
                .await?;
            let sent = ResumablePutSent {
                offset: chunk.offset,
                len: 0,
                register_after: running,
                final_crc32c_hex: final_crc.map(|crc| format!("{crc:08x}")),
            };
            return self
                .finish_resumable_put(op, session_uri, chunk.total_size, sent, resp)
                .await;
        }

        if is_final && let Some(register) = running {
            return self
                .upload_final_chunk_with_crc32c(op, session_uri, chunk, register)
                .await;
        }
        if is_final {
            tracing::debug!(
                path = %op.dst_nfc_path,
                "GCS resumable session has no in-process running CRC32C (resumed by another \
                 process or after a partial persist); final chunk is sent without x-goog-hash, \
                 so only source checksums known at initiation are verified"
            );
        }

        let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let register_slot: Arc<StdMutex<Option<u32>>> = Arc::new(StdMutex::new(None));
        let strict = StrictBodyStream::new("GCS", chunk.body, chunk.len, captured_err.clone());
        let resp = if let Some(register) = running {
            let hashed = StreamingHashStream::new(
                strict,
                Crc32cRegister(register),
                chunk.len,
                register_slot.clone(),
            );
            self.send_resumable_put(
                session_uri,
                chunk.offset,
                chunk.len,
                chunk.total_size,
                hashed,
                captured_err,
                None,
            )
            .await?
        } else {
            self.send_resumable_put(
                session_uri,
                chunk.offset,
                chunk.len,
                chunk.total_size,
                strict,
                captured_err,
                None,
            )
            .await?
        };
        let sent = ResumablePutSent {
            offset: chunk.offset,
            len: chunk.len,
            register_after: lock_unpoisoned(&register_slot).take(),
            final_crc32c_hex: None,
        };
        self.finish_resumable_put(op, session_uri, chunk.total_size, sent, resp)
            .await
    }

    /// Upload the final chunk of a session whose running CRC32C is known, sending
    /// `x-goog-hash: crc32c=<whole object>` so GCS rejects corrupted data before it commits.
    ///
    /// The header has to be sent before the body, but the CRC is only known after the last
    /// byte. So the chunk is split: everything except the last `1..=256 KiB` streams as a
    /// normal non-final request (a multiple of 256 KiB, as GCS requires), and only that short
    /// tail is buffered, hashed, and sent as the final request with the header.
    async fn upload_final_chunk_with_crc32c(
        &self,
        op: &OperationRecord,
        session_uri: &str,
        chunk: ChunkUpload,
        mut register: u32,
    ) -> Result<ChunkAck> {
        let tail_len = (chunk.len - 1) % GCS_CHUNK_ALIGN_BYTES + 1;
        let head_len = chunk.len - tail_len;
        let mut offset = chunk.offset;
        let mut body = chunk.body;
        let mut leftover = Bytes::new();

        if head_len > 0 {
            let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
            let register_slot: Arc<StdMutex<Option<u32>>> = Arc::new(StdMutex::new(None));
            let rest_slot: Arc<StdMutex<Option<(ByteStream, Bytes)>>> =
                Arc::new(StdMutex::new(None));
            let head = SplitHeadStream {
                inner: Some(body),
                remaining: head_len,
                rest: rest_slot.clone(),
            };
            let strict =
                StrictBodyStream::new("GCS", Box::pin(head), head_len, captured_err.clone());
            let hashed = StreamingHashStream::new(
                strict,
                Crc32cRegister(register),
                head_len,
                register_slot.clone(),
            );
            let resp = self
                .send_resumable_put(
                    session_uri,
                    offset,
                    head_len,
                    chunk.total_size,
                    hashed,
                    captured_err,
                    None,
                )
                .await?;
            let sent = ResumablePutSent {
                offset,
                len: head_len,
                register_after: lock_unpoisoned(&register_slot).take(),
                final_crc32c_hex: None,
            };
            let ack = self
                .finish_resumable_put(op, session_uri, chunk.total_size, sent, resp)
                .await?;
            offset += head_len;
            // A partial persist (or an unexpected completion) hands control back to the
            // engine, which re-sends from the server's confirmed offset.
            if ack.completed.is_some() || ack.next_offset != Some(offset) {
                return Ok(ack);
            }
            let Some(advanced) = self.inner.resumable_crc.at(session_uri, offset) else {
                return Ok(ack);
            };
            register = advanced;
            let Some((rest, tail_start)) = lock_unpoisoned(&rest_slot).take() else {
                return Err(Error::protocol(
                    "GCS final chunk split lost the remaining body stream",
                ));
            };
            body = rest;
            leftover = tail_start;
        }

        let stall_timeout = self.inner.transport.config().data_stall_timeout;
        let tail = read_exact_bytes(body, leftover, tail_len, stall_timeout).await?;
        let register = crc32c_update(register, &tail);
        let crc = !register;
        let resp = self
            .send_resumable_put(
                session_uri,
                offset,
                tail_len,
                chunk.total_size,
                futures::stream::iter([Ok(tail)]),
                Arc::new(StdMutex::new(None)),
                Some(crc32c_x_goog_hash(crc)?),
            )
            .await?;
        let sent = ResumablePutSent {
            offset,
            len: tail_len,
            register_after: Some(register),
            final_crc32c_hex: Some(format!("{crc:08x}")),
        };
        self.finish_resumable_put(op, session_uri, chunk.total_size, sent, resp)
            .await
    }

    /// Send one resumable-session `PUT` of `len` bytes at `offset`.
    #[allow(clippy::too_many_arguments)]
    async fn send_resumable_put<S>(
        &self,
        session_uri: &str,
        offset: u64,
        len: u64,
        total_size: u64,
        body: S,
        captured_err: Arc<StdMutex<Option<Error>>>,
        x_goog_hash: Option<HeaderValue>,
    ) -> Result<ResumablePutResponse>
    where
        S: futures::Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
    {
        let content_range = if len == 0 {
            format!("bytes */{total_size}")
        } else {
            let end_inclusive = offset
                .checked_add(len - 1)
                .ok_or_else(|| Error::protocol("GCS chunk offset overflow"))?;
            format!("bytes {offset}-{end_inclusive}/{total_size}")
        };

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        let used_tok = self.apply_auth(&mut headers).await?;
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string())
                .map_err(|e| Error::protocol(format!("content-length: {e}")))?,
        );
        headers.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_str(&content_range)
                .map_err(|e| Error::protocol(format!("content-range: {e}")))?,
        );
        if let Some(hash) = x_goog_hash {
            headers.insert(HeaderName::from_static("x-goog-hash"), hash);
        }

        let req = self
            .inner
            .transport
            .data_client()
            .put(session_uri)
            .headers(headers);
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            "GCS upload chunk",
            req,
            body,
            len,
            captured_err,
        )
        .await?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;
        Ok((status, resp_headers, resp_body, used_tok))
    }

    /// Interpret the response to a resumable `PUT`: advance (or drop) the session's running
    /// CRC32C, and on completion verify the object's `crc32c` against what was streamed.
    async fn finish_resumable_put(
        &self,
        op: &OperationRecord,
        session_uri: &str,
        total_size: u64,
        sent: ResumablePutSent,
        resp: ResumablePutResponse,
    ) -> Result<ChunkAck> {
        let (status, resp_headers, resp_body, used_tok) = resp;

        if status.as_u16() == 308 {
            self.clear_upload_401_guard(&op.op_id);
            self.inner.data_limiter.record_success(false, false);
            let sent_end = sent.offset + sent.len;
            // A `308` without `Range` means GCS has persisted nothing at all; never assume
            // the chunk just sent landed.
            let next = parse_gcs_resume_range(&resp_headers).unwrap_or(0);
            match sent.register_after {
                Some(register) if next == sent_end => {
                    self.inner
                        .resumable_crc
                        .advance(session_uri, next, register);
                }
                // Nothing persisted: the state still describes `[0, offset)`.
                _ if next == sent.offset => {}
                _ => self.inner.resumable_crc.forget(session_uri),
            }
            return Ok(ChunkAck {
                next_offset: Some(next),
                etag: None,
                completed: None,
                checksum: None,
            });
        }
        if status.is_success() {
            self.clear_upload_401_guard(&op.op_id);
            self.inner.resumable_crc.forget(session_uri);
            self.inner.data_limiter.record_success(false, false);
            let obj: GcsObject = serde_json::from_slice(&resp_body)
                .map_err(|e| Error::protocol(format!("parse GCS final chunk JSON: {e}")))?;
            let expected_checksums = parse_gcs_session_expected_checksums(&op.backend_meta);
            verify_gcs_object_checksums(
                "GCS resumable upload",
                &obj,
                sent.final_crc32c_hex.as_deref(),
                &expected_checksums,
            )?;
            let etag = obj.etag.clone();
            let entry = self
                .object_to_entry(&obj)?
                .ok_or_else(|| Error::protocol("GCS finalized object outside prefix"))?;
            return Ok(ChunkAck {
                next_offset: Some(total_size),
                etag,
                completed: Some(entry),
                checksum: None,
            });
        }
        if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            self.inner.resumable_crc.forget(session_uri);
            return Err(Error::session_expired(format!(
                "GCS resumable session expired (HTTP {})",
                status.as_u16()
            )));
        }
        let err = self
            .handle_upload_error_response(
                "GCS upload chunk",
                &op.op_id,
                status,
                &resp_headers,
                &resp_body,
                used_tok.as_deref(),
                sent.final_crc32c_hex.as_deref(),
            )
            .await;
        if err.kind == ErrorKind::Integrity {
            self.inner.resumable_crc.forget(session_uri);
        }
        Err(err)
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        let expected_checksums = parse_gcs_session_expected_checksums(&op.backend_meta);
        let obj = match self.query_upload_inner(op).await? {
            (UploadProgress::AlreadyCompleted(_), Some(obj)) => obj,
            _ => {
                let dst_raw = if op.dst_raw_path.is_empty() {
                    op.dst_nfc_path.as_str()
                } else {
                    op.dst_raw_path.as_str()
                };
                let dst_bp = BackendPath::new(
                    dst_raw,
                    op.dst_nfc_path.clone(),
                    op.existing_dst_node_id.clone(),
                );
                let full_key = self.inner.cfg.full_key(dst_bp.raw_path());
                self.get_object_meta(&full_key).await?.ok_or_else(|| {
                    Error::protocol("GCS finish_upload: object not found on server")
                })?
            }
        };
        verify_gcs_object_checksums("GCS finish_upload", &obj, None, &expected_checksums)?;
        self.object_to_entry(&obj)?
            .ok_or_else(|| Error::protocol("GCS finish_upload: object outside configured prefix"))
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        let Some(session_uri) = op.session_token.as_deref() else {
            return Ok(());
        };
        self.inner.resumable_crc.forget(session_uri);
        // GCS returns 499 Client Closed Request (or 404/410) when cancelling a resumable session;
        // abort is best-effort cleanup.
        self.control_request_with_policy(
            "GCS abort resumable upload",
            Method::DELETE,
            session_uri,
            HeaderMap::new(),
            None,
            false,
            Idempotency::Idempotent,
            |resp| {
                if resp.status.is_success() || matches!(resp.status.as_u16(), 404 | 410 | 499) {
                    return PolicyDecision::Ok(());
                }
                PolicyDecision::from_error(map_gcs_http_error_with_headers(
                    "GCS abort resumable upload",
                    resp.status,
                    Some(&resp.headers),
                    &resp.body,
                ))
            },
        )
        .await
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let dst_raw = if op.dst_raw_path.is_empty() {
            op.dst_nfc_path.as_str()
        } else {
            op.dst_raw_path.as_str()
        };
        let full_key = self.inner.cfg.full_key(dst_raw);
        let Some(obj) = self.get_object_meta(&full_key).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };
        let op_matches = obj
            .metadata
            .as_ref()
            .and_then(|m| m.get(META_OP_ID))
            .is_some_and(|id| id == &op.op_id);
        if op_matches
            && obj.parsed_size() == op.src_version.size
            && let Some(entry) = self.object_to_entry(&obj)?
        {
            return Ok(ReconcileOutcome::Committed(entry));
        }
        Ok(ReconcileOutcome::Ambiguous(format!(
            "GCS object `{full_key}` exists with different op-id or size"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_boundary_is_unique_and_rfc2046_valid() {
        let b1 = generate_multipart_boundary("op-1", "a/b.bin");
        let b2 = generate_multipart_boundary("op-1", "a/b.bin");
        assert_ne!(b1, b2);
        assert!(b1.len() <= 70);
        assert!(b1.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        assert!(b2.len() <= 70);
        assert!(b2.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }

    #[test]
    fn resumable_crc_map_evicts_lru_and_expires_ttl() {
        let map = ResumableCrcMap::with_limits(2, std::time::Duration::from_secs(60));
        map.start("https://example.test/s1");
        map.start("https://example.test/s2");
        // Touch s1 so s2 becomes LRU
        assert_eq!(map.at("https://example.test/s1", 0), Some(u32::MAX));
        map.start("https://example.test/s3");
        assert_eq!(map.at("https://example.test/s2", 0), None);
        assert_eq!(map.at("https://example.test/s1", 0), Some(u32::MAX));
        assert_eq!(map.at("https://example.test/s3", 0), Some(u32::MAX));

        // Zero TTL expires immediately
        let expired_map = ResumableCrcMap::with_limits(4, std::time::Duration::ZERO);
        expired_map.start("https://example.test/exp");
        assert_eq!(expired_map.at("https://example.test/exp", 0), None);
    }

    #[test]
    fn parse_gcs_integrity_rejection_parses_json_error_message() {
        let crc_b64 = B64.encode([0x12, 0x34, 0x56, 0x78]);
        let body = serde_json::json!({
            "error": {
                "code": 400,
                "message": format!("Provided CRC32C \"AAAAAA==\" doesn't match calculated CRC32C \"{crc_b64}\".")
            }
        });
        let parsed = parse_gcs_integrity_rejection(&serde_json::to_vec(&body).unwrap());
        assert_eq!(parsed, Some(("CRC32C", Some("12345678".to_string()))));

        let md5_b64 = B64.encode([0xABu8; 16]);
        let body_md5 = serde_json::json!({
            "error": {
                "code": 400,
                "message": format!("Provided MD5 hash \"AA==\" doesn't match calculated MD5 hash \"{md5_b64}\".")
            }
        });
        let parsed_md5 = parse_gcs_integrity_rejection(&serde_json::to_vec(&body_md5).unwrap());
        assert_eq!(
            parsed_md5,
            Some(("MD5", Some("abababababababababababababababab".to_string())))
        );
    }

    #[tokio::test]
    async fn read_exact_bytes_rejects_trailing_non_empty_bytes_as_source_mutated() {
        let stream: ByteStream = Box::pin(futures::stream::iter([
            Ok(Bytes::from_static(b"abcd")),
            Ok(Bytes::from_static(b"extra")),
        ]));
        let err = read_exact_bytes(stream, Bytes::new(), 4, std::time::Duration::from_secs(5))
            .await
            .expect_err("trailing bytes after declared length must fail");
        assert_eq!(err.kind, ErrorKind::SourceMutated);
    }
}
