//! Version-pinned S3 `Range` reader, strict-SigV4 spool/hash preparation,
//! upload/download byte-length enforcement streams, and header checksum helpers.

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::source::{ByteStream, RemoteRangeReadable};
use rship_core::types::{ByteRange, Checksum, HashKind};
use rship_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::common::{
    Crc32cHasher, Crc64NvmeHasher, ExactDownloadStream, Sha256Hasher, StreamingDigest,
    StreamingMd5, VerifyingDownloadStream, checksum_mismatch_error,
};
#[cfg(test)]
use crate::s3::checksum::{crc32c_base64, crc64_nvme_base64};
use crate::s3::checksum::{crc32c_update, crc64_nvme_update};
use crate::s3::error::{classify_s3_error, is_expired_token_error};
use crate::s3::sigv4::{EMPTY_SHA256_HEX, sign_v4_request};

use super::{IN_MEM_STRICT_HASH_CAP, META_SHA256, S3Backend, STRICT_HASH_MEM_UNIT};

/// Version-pinned (`If-Match: <etag>`) HTTP `Range` reader for zero-RAM S3 downloads
/// and cloud-to-cloud relays.
pub(super) struct S3RangeReader {
    pub(super) backend: S3Backend,
    pub(super) full_key: String,
    pub(super) total_len: u64,
    pub(super) pinned_etag: Option<String>,
}

#[async_trait]
impl RemoteRangeReadable for S3RangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("S3 download ByteRange overflow"))?;
        if end_exclusive > self.total_len {
            return Err(Error::invalid_geometry(format!(
                "S3 download range [{}..{}) exceeds object size {}",
                range.offset, end_exclusive, self.total_len
            )));
        }

        let is_full_object = range.offset == 0 && range.len == self.total_len;
        let (url, canonical_uri, host_header) =
            self.backend.build_request_target(&self.full_key, &[])?;
        let mut base_headers = HeaderMap::new();
        base_headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={}-{}", range.offset, end_exclusive - 1))
                .expect("valid range"),
        );
        if is_full_object
            && (self.backend.inner.profile.supports_crc64nvme
                || self.backend.inner.profile.supports_crc32c)
        {
            base_headers.insert(
                HeaderName::from_static("x-amz-checksum-mode"),
                HeaderValue::from_static("ENABLED"),
            );
        }
        // Version-pinned read: fails with 412 PreconditionFailed if object mutates mid-download!
        // Respects `pin_read_etag` so legacy Swift/S3 gateways with buggy SLO If-Match can opt out.
        if self.backend.inner.cfg.pin_read_etag
            && let Some(ref etag) = self.pinned_etag
        {
            base_headers.insert(
                http::header::IF_MATCH,
                HeaderValue::from_str(etag)
                    .map_err(|e| Error::protocol(format!("invalid If-Match ETag: {e}")))?,
            );
        }
        self.backend
            .apply_sse_c_headers_if_needed(&mut base_headers)?;

        let mut refreshed_token = false;
        let mut skew_retries = 0u8;
        let resp = loop {
            self.backend.inner.data_limiter.acquire_send_permit().await;

            let creds = self.backend.inner.creds.credentials().await?;
            let mut headers = base_headers.clone();
            sign_v4_request(
                &Method::GET,
                &canonical_uri,
                &[],
                &host_header,
                &mut headers,
                EMPTY_SHA256_HEX,
                &creds,
                self.backend.inner.cfg.signing_region(),
                self.backend.effective_unix_secs(),
            )?;

            let req = self
                .backend
                .inner
                .transport
                .data_client()
                .get(&url)
                .headers(headers);
            let resp = self
                .backend
                .inner
                .transport
                .send_data_request("S3 GetObject(range)", req)
                .await?;
            let status = resp.status();

            if status == StatusCode::PARTIAL_CONTENT
                || (status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
            {
                break resp;
            }

            let resp_headers = resp.headers().clone();
            let body = self.backend.inner.transport.read_data_body(resp).await?;
            if !refreshed_token
                && self.backend.inner.creds.is_dynamic()
                && is_expired_token_error(&Method::GET, status, &body)
            {
                refreshed_token = true;
                if self
                    .backend
                    .inner
                    .creds
                    .force_refresh(&creds.access_key_id, creds.session_token.as_deref())
                    .await?
                    .is_some()
                {
                    continue;
                }
            }
            if skew_retries < 2 && self.backend.maybe_adjust_clock_skew(&resp_headers, &body) {
                skew_retries += 1;
                continue;
            }
            let err = classify_s3_error("S3 GetObject", status, &resp_headers, &body, false);
            if err.is_throttled() {
                self.backend.inner.data_limiter.record_throttle();
            }
            return Err(err);
        };

        self.backend.inner.data_limiter.record_success(false, false);
        let resp_headers = resp.headers().clone();
        let watched = self
            .backend
            .inner
            .transport
            .watch_response_stream("S3 download stream", resp);
        let exact = ExactDownloadStream::new("S3", watched, range.len);
        if is_full_object
            && let Some(expected) =
                extract_download_checksum_from_headers(&resp_headers, self.backend.is_non_md5_sse())
        {
            return Ok(match expected.kind {
                HashKind::Crc64Nvme => Box::pin(VerifyingDownloadStream::new(
                    "S3",
                    "CRC64NVME",
                    exact,
                    Crc64NvmeHasher::new(),
                    range.len,
                    expected.hex,
                )),
                HashKind::Crc32c => Box::pin(VerifyingDownloadStream::new(
                    "S3",
                    "CRC32C",
                    exact,
                    Crc32cHasher::new(),
                    range.len,
                    expected.hex,
                )),
                HashKind::Sha256 => Box::pin(VerifyingDownloadStream::new(
                    "S3",
                    "SHA-256",
                    exact,
                    Sha256Hasher::new(),
                    range.len,
                    expected.hex,
                )),
                HashKind::Md5 => Box::pin(VerifyingDownloadStream::new(
                    "S3",
                    "MD5/ETag",
                    exact,
                    StreamingMd5::new(),
                    range.len,
                    expected.hex,
                )),
                _ => Box::pin(exact),
            });
        }
        Ok(Box::pin(exact))
    }
}

/// Digests computed on-the-fly while streaming an S3 `PutObject` or `UploadPart` body,
/// verified against server-returned checksum / `ETag` headers immediately upon HTTP 2xx.
#[derive(Debug, Clone)]
pub(super) struct S3StreamUploadDigests {
    pub(super) crc64nvme_val: Option<u64>,
    pub(super) crc64nvme_hex: Option<String>,
    pub(super) crc32c_val: Option<u32>,
    pub(super) crc32c_hex: Option<String>,
    pub(super) md5_hex: String,
}

impl S3StreamUploadDigests {
    pub(super) fn for_empty(compute_crc64: bool, compute_crc32c: bool) -> Self {
        let empty_crc64 = compute_crc64.then_some(0u64);
        let empty_crc32c = compute_crc32c.then_some(0u32);
        Self {
            crc64nvme_val: empty_crc64,
            crc64nvme_hex: empty_crc64.map(|v| format!("{v:016x}")),
            crc32c_val: empty_crc32c,
            crc32c_hex: empty_crc32c.map(|v| format!("{v:08x}")),
            md5_hex: StreamingMd5::new().finalize_hex(),
        }
    }

    /// Build `(HeaderName, HeaderValue, tagged_checksum)` directly from the already-computed
    /// CRC digest without a second pass over the payload buffer.
    pub(super) fn checksum_header_and_tag(
        &self,
        kind: HashKind,
    ) -> Option<(HeaderName, HeaderValue, String)> {
        match kind {
            HashKind::Crc64Nvme => {
                let val = self.crc64nvme_val?;
                let b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    val.to_be_bytes(),
                );
                let hv = HeaderValue::from_str(&b64).ok()?;
                Some((
                    HeaderName::from_static("x-amz-checksum-crc64nvme"),
                    hv,
                    format!("crc64nvme:{b64}"),
                ))
            }
            HashKind::Crc32c => {
                let val = self.crc32c_val?;
                let b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    val.to_be_bytes(),
                );
                let hv = HeaderValue::from_str(&b64).ok()?;
                Some((
                    HeaderName::from_static("x-amz-checksum-crc32c"),
                    hv,
                    format!("crc32c:{b64}"),
                ))
            }
            _ => None,
        }
    }
}

pub(super) struct S3StreamUploadHasher {
    crc64_state: Option<u64>,
    crc32c_state: Option<u32>,
    md5: StreamingMd5,
}

impl S3StreamUploadHasher {
    pub(super) fn new(compute_crc64: bool, compute_crc32c: bool) -> Self {
        Self {
            crc64_state: compute_crc64.then_some(u64::MAX),
            crc32c_state: compute_crc32c.then_some(u32::MAX),
            md5: StreamingMd5::new(),
        }
    }
}

impl StreamingDigest for S3StreamUploadHasher {
    type Output = S3StreamUploadDigests;

    fn update(&mut self, chunk: &[u8]) {
        if let Some(ref mut state) = self.crc64_state {
            *state = crc64_nvme_update(*state, chunk);
        }
        if let Some(ref mut state) = self.crc32c_state {
            *state = crc32c_update(*state, chunk);
        }
        self.md5.update_bytes(chunk);
    }

    fn finalize(self) -> S3StreamUploadDigests {
        let crc64nvme_val = self.crc64_state.map(|s| !s);
        let crc32c_val = self.crc32c_state.map(|s| !s);
        S3StreamUploadDigests {
            crc64nvme_val,
            crc64nvme_hex: crc64nvme_val.map(|v| format!("{v:016x}")),
            crc32c_val,
            crc32c_hex: crc32c_val.map(|v| format!("{v:08x}")),
            md5_hex: self.md5.finalize_hex(),
        }
    }
}

pub(super) struct PreparedUpload {
    pub(super) sha256_hex: Option<String>,
    pub(super) checksum_header: Option<(HeaderName, HeaderValue)>,
    pub(super) part_checksum: Option<String>,
    pub(super) digests: S3StreamUploadDigests,
    pub(super) backing: PreparedBacking,
}

pub(super) enum PreparedBacking {
    Memory {
        data: Bytes,
        _permit: OwnedSemaphorePermit,
    },
    SpoolFile(std::fs::File),
}

impl PreparedBacking {
    pub(super) fn into_stream(self) -> ByteStream {
        match self {
            PreparedBacking::Memory { data, _permit } => {
                // Keep `_permit` alive until the stream yields and drops its state.
                Box::pin(futures::stream::once(async move {
                    let _keep = _permit;
                    Ok(data)
                }))
            }
            PreparedBacking::SpoolFile(file) => {
                // Own `std::fs::File` directly by value across `spawn_blocking` turns (no Mutex).
                let s = futures::stream::try_unfold(file, |mut f| async move {
                    let (f, chunk) = tokio::task::spawn_blocking(
                        move || -> (std::fs::File, Result<Option<Bytes>>) {
                            let mut buf = vec![0u8; 256 * 1024];
                            match f.read(&mut buf) {
                                Ok(0) => (f, Ok(None)),
                                Ok(n) => {
                                    buf.truncate(n);
                                    (f, Ok(Some(Bytes::from(buf))))
                                }
                                Err(e) => (f, Err(Error::io("read strict-sigv4 spool file", e))),
                            }
                        },
                    )
                    .await
                    .map_err(|e| Error::protocol(format!("spool read task panicked: {e}")))?;
                    Ok(chunk?.map(|b| (b, f)))
                });
                Box::pin(s)
            }
        }
    }
}

/// Shared single-pass in-memory buffering & hashing helper for `<= 4 MiB` uploads.
async fn prepare_in_memory_upload_inner(
    mut body: ByteStream,
    expected_len: u64,
    compute_sha256: bool,
    checksum_kind: Option<HashKind>,
    compute_crc64: bool,
    compute_crc32c: bool,
    permit: OwnedSemaphorePermit,
) -> Result<PreparedUpload> {
    let mut seen = 0u64;
    let mut sha = compute_sha256.then(Sha256::new);
    let mut buf = Vec::with_capacity(expected_len as usize);
    let mut hasher = S3StreamUploadHasher::new(
        compute_crc64 || checksum_kind == Some(HashKind::Crc64Nvme),
        compute_crc32c || checksum_kind == Some(HashKind::Crc32c),
    );
    while let Some(item) = body.next().await {
        let chunk = item?;
        seen = seen.saturating_add(chunk.len() as u64);
        if seen > expected_len {
            return Err(Error::source_mutated(format!(
                "upload stream exceeded declared length ({seen} > {expected_len})"
            )));
        }
        if let Some(ref mut s) = sha {
            s.update(&chunk);
        }
        hasher.update(&chunk);
        buf.extend_from_slice(&chunk);
    }
    if seen != expected_len {
        return Err(Error::source_mutated(format!(
            "short EOF during S3 upload: received {seen} of {expected_len} bytes"
        )));
    }
    let digests = hasher.finalize();
    let (checksum_header, part_checksum) =
        match checksum_kind.and_then(|ck| digests.checksum_header_and_tag(ck)) {
            Some((name, val, tagged)) => (Some((name, val)), Some(tagged)),
            None => (None, None),
        };
    Ok(PreparedUpload {
        sha256_hex: sha.map(|s| hex::encode(s.finalize())),
        checksum_header,
        part_checksum,
        digests,
        backing: PreparedBacking::Memory {
            data: Bytes::from(buf),
            _permit: permit,
        },
    })
}

/// Budgeted in-memory checksum preparation for `UNSIGNED-PAYLOAD` uploads `<= 4 MiB`
/// when `send_upload_checksum = true`: NEVER spills to disk (`tempfile`).
///
/// If the 16 MiB concurrent RAM budget is saturated, returns `Ok(Err(body))` immediately so
/// the caller falls back (zero-buffer streaming hashing for optional checksums, or
/// [`prepare_required_checksum_upload`]'s disk spool for mandatory ones). It never waits on
/// the budget: the body's producer may already hold a pooled slab, and waiting would hold one
/// pooled buffer while acquiring another.
pub(super) async fn prepare_in_memory_checksum_upload(
    body: ByteStream,
    expected_len: u64,
    checksum_kind: HashKind,
    compute_crc64: bool,
    compute_crc32c: bool,
    mem_budget: &Arc<Semaphore>,
) -> Result<std::result::Result<PreparedUpload, ByteStream>> {
    if expected_len > IN_MEM_STRICT_HASH_CAP {
        return Ok(Err(body));
    }
    let units = expected_len.div_ceil(STRICT_HASH_MEM_UNIT).max(1) as u32;
    let Ok(permit) = mem_budget.clone().try_acquire_many_owned(units) else {
        return Ok(Err(body));
    };
    let prepared = prepare_in_memory_upload_inner(
        body,
        expected_len,
        false,
        Some(checksum_kind),
        compute_crc64,
        compute_crc32c,
        permit,
    )
    .await?;
    Ok(Ok(prepared))
}

/// Prepare a body that MUST be sent with an `x-amz-checksum-*` header (an `UploadPart` into
/// a multipart upload created with `x-amz-checksum-algorithm`).
///
/// Deadlock-free by construction: the engine's prefetch may already hold a pooled slab for
/// this body, so we never *wait* on the RAM budget (that would hold one pooled buffer while
/// acquiring another; see `rship_core::buffer`). If the budget is free we hash in RAM;
/// otherwise the body is spooled to disk (which drains it and releases its slabs) and hashed
/// on the way.
#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_required_checksum_upload(
    body: ByteStream,
    expected_len: u64,
    checksum_kind: HashKind,
    compute_crc64: bool,
    compute_crc32c: bool,
    mem_budget: &Arc<Semaphore>,
    spool_dir: Option<&Path>,
) -> Result<PreparedUpload> {
    match prepare_in_memory_checksum_upload(
        body,
        expected_len,
        checksum_kind,
        compute_crc64,
        compute_crc32c,
        mem_budget,
    )
    .await?
    {
        Ok(prepared) => Ok(prepared),
        Err(body) => {
            prepare_hashed_upload(
                body,
                expected_len,
                false,
                Some(checksum_kind),
                compute_crc64,
                compute_crc32c,
                mem_budget,
                spool_dir,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_hashed_upload(
    mut body: ByteStream,
    expected_len: u64,
    compute_sha256: bool,
    checksum_kind: Option<HashKind>,
    compute_crc64: bool,
    compute_crc32c: bool,
    mem_budget: &Arc<Semaphore>,
    spool_dir: Option<&Path>,
) -> Result<PreparedUpload> {
    let mut seen = 0u64;
    let track_crc64 = compute_crc64 || checksum_kind == Some(HashKind::Crc64Nvme);
    let track_crc32c = compute_crc32c || checksum_kind == Some(HashKind::Crc32c);

    // Try budgeted in-memory fast path for `<= 4 MiB` uploads; if concurrent strict-hashed
    // uploads saturate the 16 MiB budget, transparently spill to an anonymous temp spool file.
    if expected_len <= IN_MEM_STRICT_HASH_CAP {
        let units = expected_len.div_ceil(STRICT_HASH_MEM_UNIT).max(1) as u32;
        if let Ok(permit) = mem_budget.clone().try_acquire_many_owned(units) {
            return prepare_in_memory_upload_inner(
                body,
                expected_len,
                compute_sha256,
                checksum_kind,
                track_crc64,
                track_crc32c,
                permit,
            )
            .await;
        }
    }

    // Spool asynchronously to an anonymous temp file under `spool_dir` (avoiding Linux `/tmp`
    // `tmpfs`) via ONE dedicated blocking writer with a 256 KiB `BufWriter` over a bounded
    // channel (avoiding per-16KiB-frame `spawn_blocking` scheduling overhead), computing
    // optional SHA-256, MD5, and CRC64NVME / CRC32C in ONE pass.
    let spool_dir_owned = spool_dir.map(Path::to_path_buf);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let writer_handle = tokio::task::spawn_blocking(
        move || -> Result<(std::fs::File, Option<Sha256>, u64, u32, StreamingMd5)> {
            let tmp = if let Some(dir) = spool_dir_owned {
                std::fs::create_dir_all(&dir)
                    .map_err(|e| Error::io("create strict-sigv4 spool dir", e))?;
                tempfile::tempfile_in(dir)
                    .map_err(|e| Error::io("create strict-sigv4 temporary spool file", e))?
            } else {
                tempfile::tempfile()
                    .map_err(|e| Error::io("create strict-sigv4 temporary spool file", e))?
            };
            let mut writer = BufWriter::with_capacity(256 * 1024, tmp);
            let mut sha = compute_sha256.then(Sha256::new);
            let mut crc64_state = 0xFFFF_FFFF_FFFF_FFFFu64;
            let mut crc32c_state = 0xFFFF_FFFFu32;
            let mut md5 = StreamingMd5::new();

            while let Some(chunk) = rx.blocking_recv() {
                if let Some(ref mut s) = sha {
                    s.update(&chunk);
                }
                if track_crc64 {
                    crc64_state = crc64_nvme_update(crc64_state, &chunk);
                }
                if track_crc32c {
                    crc32c_state = crc32c_update(crc32c_state, &chunk);
                }
                md5.update_bytes(&chunk);
                writer
                    .write_all(&chunk)
                    .map_err(|e| Error::io("write strict-sigv4 spool file", e))?;
            }
            writer
                .flush()
                .map_err(|e| Error::io("flush strict-sigv4 spool file", e))?;
            let mut tmp_file = writer
                .into_inner()
                .map_err(|e| Error::io("finish strict-sigv4 spool file", e.into_error()))?;
            tmp_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| Error::io("rewind strict-sigv4 spool file", e))?;
            Ok((tmp_file, sha, crc64_state, crc32c_state, md5))
        },
    );

    let mut producer_err: Option<Error> = None;
    while let Some(item) = body.next().await {
        let chunk = match item {
            Ok(c) => c,
            Err(e) => {
                producer_err = Some(e);
                break;
            }
        };
        if chunk.is_empty() {
            continue;
        }
        seen = seen.saturating_add(chunk.len() as u64);
        if seen > expected_len {
            producer_err = Some(Error::source_mutated(format!(
                "upload stream exceeded declared length ({seen} > {expected_len})"
            )));
            break;
        }
        if tx.send(chunk).await.is_err() {
            break;
        }
    }
    drop(tx);

    let writer_res = writer_handle
        .await
        .map_err(|e| Error::protocol(format!("spool writer task panicked: {e}")))?;
    if let Some(e) = producer_err {
        return Err(e);
    }
    let (tmp_file, sha, crc64_state, crc32c_state, md5) = writer_res?;
    if seen != expected_len {
        return Err(Error::source_mutated(format!(
            "short EOF during S3 upload: received {seen} of {expected_len} bytes"
        )));
    }

    let crc64_val = !crc64_state;
    let crc32c_val = !crc32c_state;
    let digests = S3StreamUploadDigests {
        crc64nvme_val: track_crc64.then_some(crc64_val),
        crc64nvme_hex: track_crc64.then(|| format!("{crc64_val:016x}")),
        crc32c_val: track_crc32c.then_some(crc32c_val),
        crc32c_hex: track_crc32c.then(|| format!("{crc32c_val:08x}")),
        md5_hex: md5.finalize_hex(),
    };
    let (checksum_header, part_checksum) =
        match checksum_kind.and_then(|ck| digests.checksum_header_and_tag(ck)) {
            Some((name, val, tagged)) => (Some((name, val)), Some(tagged)),
            None => (None, None),
        };

    Ok(PreparedUpload {
        sha256_hex: sha.map(|s| hex::encode(s.finalize())),
        checksum_header,
        part_checksum,
        digests,
        backing: PreparedBacking::SpoolFile(tmp_file),
    })
}

pub(super) fn insert_upload_checksum_header(
    headers: &mut HeaderMap,
    kind: HashKind,
    data: &[u8],
) -> Option<String> {
    let mut hasher =
        S3StreamUploadHasher::new(kind == HashKind::Crc64Nvme, kind == HashKind::Crc32c);
    hasher.update(data);
    let (k, v, tagged) = hasher.finalize().checksum_header_and_tag(kind)?;
    headers.insert(k, v);
    Some(tagged)
}

/// Extract a tagged raw-base64 S3 part checksum (`"crc64nvme:<b64>"` / `"crc32c:<b64>"` /
/// `"sha256:<b64>"`) from `UploadPart` / `UploadPartCopy` response headers.
pub(super) fn extract_tagged_part_checksum_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers
        .get("x-amz-checksum-crc64nvme")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(format!("crc64nvme:{v}"));
    }
    if let Some(v) = headers
        .get("x-amz-checksum-crc32c")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(format!("crc32c:{v}"));
    }
    if let Some(v) = headers
        .get("x-amz-checksum-sha256")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(format!("sha256:{v}"));
    }
    None
}

/// Decode an S3 base64 checksum header/XML value into lowercase hex ONLY if it represents
/// a single full-object digest of exact byte length `expected_bytes` (rejecting composite
/// multipart digests like `<base64>-<part_count>` which contain `-`).
pub(super) fn decode_s3_base64_checksum_hex(raw: &str, expected_bytes: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('-') {
        return None;
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed).ok()?;
    if bytes.len() != expected_bytes {
        return None;
    }
    Some(hex::encode(bytes))
}

fn parse_hex_sha256(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

/// Return `true` when S3 headers indicate SSE-KMS or SSE-C encryption, where `ETag`
/// is NOT the plaintext MD5 digest of the object body.
pub(super) fn is_kms_or_customer_encrypted(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().to_ascii_lowercase().starts_with("aws:kms"))
        || headers.contains_key("x-amz-server-side-encryption-customer-algorithm")
}

/// Insert the strongest provider-supported S3 wire checksum header (`x-amz-checksum-crc64nvme`,
/// `x-amz-checksum-crc32c`, or `Content-MD5`) directly from known source `checksums` without
/// spooling or buffering the upload stream.
pub(super) fn try_insert_known_s3_checksum_header(
    headers: &mut HeaderMap,
    checksums: &[Checksum],
    supports_crc64nvme: bool,
    supports_crc32c: bool,
) -> Result<bool> {
    if supports_crc64nvme
        && let Some(ck) = checksums.iter().find(|c| c.kind == HashKind::Crc64Nvme)
        && let Ok(bytes) = hex::decode(ck.hex.trim())
        && bytes.len() == 8
    {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        headers.insert(
            HeaderName::from_static("x-amz-checksum-crc64nvme"),
            HeaderValue::from_str(&b64)
                .map_err(|e| Error::protocol(format!("invalid crc64nvme header: {e}")))?,
        );
        return Ok(true);
    }
    if supports_crc32c
        && let Some(ck) = checksums.iter().find(|c| c.kind == HashKind::Crc32c)
        && let Ok(bytes) = hex::decode(ck.hex.trim())
        && bytes.len() == 4
    {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        headers.insert(
            HeaderName::from_static("x-amz-checksum-crc32c"),
            HeaderValue::from_str(&b64)
                .map_err(|e| Error::protocol(format!("invalid crc32c header: {e}")))?,
        );
        return Ok(true);
    }
    if let Some(ck) = checksums.iter().find(|c| c.kind == HashKind::Md5)
        && let Ok(bytes) = hex::decode(ck.hex.trim())
        && bytes.len() == 16
    {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        headers.insert(
            HeaderName::from_static("content-md5"),
            HeaderValue::from_str(&b64)
                .map_err(|e| Error::protocol(format!("invalid content-md5 header: {e}")))?,
        );
        return Ok(true);
    }
    Ok(false)
}

/// Verify server-returned checksum / `ETag` headers on `PutObject` or `UploadPart` against
/// digests computed on-the-fly while streaming the request body.
pub(super) fn verify_s3_upload_response_checksums(
    context: &str,
    resp_headers: &HeaderMap,
    streamed: &S3StreamUploadDigests,
    suppress_etag_md5: bool,
) -> Result<()> {
    if let Some(ref expected) = streamed.crc64nvme_hex
        && let Some(server_hex) = resp_headers
            .get("x-amz-checksum-crc64nvme")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| decode_s3_base64_checksum_hex(v, 8))
        && !server_hex.eq_ignore_ascii_case(expected)
    {
        return Err(checksum_mismatch_error(
            context,
            "CRC64NVME",
            expected,
            &server_hex,
        ));
    }
    if let Some(ref expected) = streamed.crc32c_hex
        && let Some(server_hex) = resp_headers
            .get("x-amz-checksum-crc32c")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| decode_s3_base64_checksum_hex(v, 4))
        && !server_hex.eq_ignore_ascii_case(expected)
    {
        return Err(checksum_mismatch_error(
            context,
            "CRC32C",
            expected,
            &server_hex,
        ));
    }
    if !suppress_etag_md5
        && !is_kms_or_customer_encrypted(resp_headers)
        && let Some(server_md5) = resp_headers
            .get(http::header::ETAG)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_single_part_md5_from_etag)
        && !server_md5.eq_ignore_ascii_case(&streamed.md5_hex)
    {
        return Err(checksum_mismatch_error(
            context,
            "MD5/ETag",
            &streamed.md5_hex,
            &server_md5,
        ));
    }
    Ok(())
}

/// Compare known source checksums against the server-returned object checksum whenever
/// their [`HashKind`] matches.
pub(super) fn verify_known_source_checksums_against_entry(
    context: &str,
    source_checksums: &[Checksum],
    committed: Option<&Checksum>,
) -> Result<()> {
    let Some(dst_ck) = committed else {
        return Ok(());
    };
    for src_ck in source_checksums {
        if src_ck.kind == dst_ck.kind && !src_ck.hex.eq_ignore_ascii_case(&dst_ck.hex) {
            return Err(checksum_mismatch_error(
                context,
                dst_ck.kind.as_str(),
                &src_ck.hex.to_ascii_lowercase(),
                &dst_ck.hex.to_ascii_lowercase(),
            ));
        }
    }
    Ok(())
}

/// Extract a native full-object checksum from `GetObject` response headers for full-object
/// streaming download verification (skipping user metadata and SSE-KMS/SSE-C ETags).
fn extract_download_checksum_from_headers(
    headers: &HeaderMap,
    suppress_etag_md5: bool,
) -> Option<Checksum> {
    if let Some(hex) = headers
        .get("x-amz-checksum-crc64nvme")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| decode_s3_base64_checksum_hex(v, 8))
    {
        return Some(Checksum {
            kind: HashKind::Crc64Nvme,
            hex,
        });
    }
    if let Some(hex) = headers
        .get("x-amz-checksum-crc32c")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| decode_s3_base64_checksum_hex(v, 4))
    {
        return Some(Checksum {
            kind: HashKind::Crc32c,
            hex,
        });
    }
    if let Some(hex) = headers
        .get("x-amz-checksum-sha256")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| decode_s3_base64_checksum_hex(v, 32))
    {
        return Some(Checksum {
            kind: HashKind::Sha256,
            hex,
        });
    }
    if !suppress_etag_md5 && !is_kms_or_customer_encrypted(headers) {
        return headers
            .get(http::header::ETAG)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_single_part_md5_from_etag)
            .map(|hex| Checksum {
                kind: HashKind::Md5,
                hex,
            });
    }
    None
}

/// Extract a specific [`HashKind`] from S3 `HeadObject` headers (so requesting `Sha256` or
/// `Md5` still succeeds when an object also carries a higher-priority `CRC64NVME` header).
pub(super) fn extract_checksum_of_kind_from_headers(
    headers: &HeaderMap,
    etag: Option<&str>,
    kind: HashKind,
    suppress_etag_md5: bool,
) -> Option<Checksum> {
    match kind {
        HashKind::Crc64Nvme => headers
            .get("x-amz-checksum-crc64nvme")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| decode_s3_base64_checksum_hex(v, 8))
            .map(|hex| Checksum { kind, hex }),
        HashKind::Crc32c => headers
            .get("x-amz-checksum-crc32c")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| decode_s3_base64_checksum_hex(v, 4))
            .map(|hex| Checksum { kind, hex }),
        HashKind::Sha256 => headers
            .get(META_SHA256)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_hex_sha256)
            .or_else(|| {
                headers
                    .get("x-amz-checksum-sha256")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|v| decode_s3_base64_checksum_hex(v, 32))
            })
            .map(|hex| Checksum { kind, hex }),
        HashKind::Md5 if !suppress_etag_md5 && !is_kms_or_customer_encrypted(headers) => etag
            .and_then(parse_single_part_md5_from_etag)
            .map(|hex| Checksum { kind, hex }),
        _ => None,
    }
}

pub(super) fn extract_verified_checksum_from_headers(
    headers: &HeaderMap,
    etag: Option<&str>,
    suppress_etag_md5: bool,
) -> Option<Checksum> {
    if let Some(hex) = headers
        .get("x-amz-checksum-crc64nvme")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| decode_s3_base64_checksum_hex(v, 8))
    {
        return Some(Checksum {
            kind: HashKind::Crc64Nvme,
            hex,
        });
    }
    if let Some(hex) = headers
        .get("x-amz-checksum-crc32c")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| decode_s3_base64_checksum_hex(v, 4))
    {
        return Some(Checksum {
            kind: HashKind::Crc32c,
            hex,
        });
    }
    if let Some(hex) = headers
        .get(META_SHA256)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_hex_sha256)
        .or_else(|| {
            headers
                .get("x-amz-checksum-sha256")
                .and_then(|h| h.to_str().ok())
                .and_then(|v| decode_s3_base64_checksum_hex(v, 32))
        })
    {
        return Some(Checksum {
            kind: HashKind::Sha256,
            hex,
        });
    }
    if suppress_etag_md5 || is_kms_or_customer_encrypted(headers) {
        return None;
    }
    etag.and_then(parse_single_part_md5_from_etag)
        .map(|hex| Checksum {
            kind: HashKind::Md5,
            hex,
        })
}

/// Extract MD5 hex from an S3 ETag ONLY if it is a single-part 32-hex MD5
/// (multipart ETags like `"abcd...-4"` contain `-` and are NEVER file MD5!).
pub(super) fn parse_single_part_md5_from_etag(etag: &str) -> Option<String> {
    let trimmed = etag.trim().trim_matches('"');
    if trimmed.len() == 32 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

pub(super) fn parse_http_date_nanos(raw: &str) -> Option<i64> {
    rship_core::time::parse_http_date_to_nanos(raw)
}

pub(super) use crate::s3::xml::parse_rfc3339_or_http_nanos;
#[cfg(test)]
use crate::s3::xml::parse_utc_rfc3339_fast_nanos;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_s3_base64_checksums_to_lowercase_hex_and_rejects_composite() {
        // CRC64NVME of b"123456789" -> 0xae8b14860a799888 ("rosUhgp5mIg=").
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-amz-checksum-crc64nvme"),
            HeaderValue::from_static("rosUhgp5mIg="),
        );
        let ck = extract_verified_checksum_from_headers(&h, None, false).unwrap();
        assert_eq!(ck.kind, HashKind::Crc64Nvme);
        assert_eq!(ck.hex, "ae8b14860a799888");

        // CRC32C of b"123456789" -> 0xe3069283 ("4waSgw==").
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-amz-checksum-crc32c"),
            HeaderValue::from_static("4waSgw=="),
        );
        let ck = extract_verified_checksum_from_headers(&h, None, false).unwrap();
        assert_eq!(ck.kind, HashKind::Crc32c);
        assert_eq!(ck.hex, "e3069283");

        // Composite multipart CRC32C (`<b64>-2`) must be rejected, falling through to META_SHA256!
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-amz-checksum-crc32c"),
            HeaderValue::from_static("4waSgw==-2"),
        );
        let meta_sha = "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225";
        h.insert(
            HeaderName::from_static(META_SHA256),
            HeaderValue::from_static(meta_sha),
        );
        let ck = extract_verified_checksum_from_headers(&h, Some("\"deadbeef-2\""), false).unwrap();
        assert_eq!(ck.kind, HashKind::Sha256);
        assert_eq!(ck.hex, meta_sha);

        // Native base64 `x-amz-checksum-sha256` decodes to 64-char lowercase hex.
        let mut h = HeaderMap::new();
        let sha_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hex::decode(meta_sha).unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-amz-checksum-sha256"),
            HeaderValue::from_str(&sha_b64).unwrap(),
        );
        let ck = extract_verified_checksum_from_headers(&h, None, false).unwrap();
        assert_eq!(ck.kind, HashKind::Sha256);
        assert_eq!(ck.hex, meta_sha);

        // Composite multipart SHA256 (`<b64>-4`) must also be rejected!
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-amz-checksum-sha256"),
            HeaderValue::from_str(&format!("{sha_b64}-4")).unwrap(),
        );
        assert!(
            extract_verified_checksum_from_headers(&h, Some("\"deadbeef-4\""), false).is_none()
        );

        // SSE-KMS / SSE-C suppression: 32-hex ETag must NOT be treated as MD5 when `suppress_etag_md5` is true.
        let empty_hdrs = HeaderMap::new();
        let hex32 = "\"d41d8cd98f00b204e9800998ecf8427e\"";
        assert_eq!(
            extract_verified_checksum_from_headers(&empty_hdrs, Some(hex32), false).map(|c| c.kind),
            Some(HashKind::Md5)
        );
        assert!(extract_verified_checksum_from_headers(&empty_hdrs, Some(hex32), true).is_none());
        assert!(
            extract_download_checksum_from_headers(
                &{
                    let mut m = HeaderMap::new();
                    m.insert(http::header::ETAG, HeaderValue::from_static(hex32));
                    m
                },
                true
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn single_pass_in_memory_and_hashed_upload_match_reference_crcs() {
        let data = b"123456789".to_vec();
        let budget = Arc::new(Semaphore::new(8));

        let body1: ByteStream = Box::pin(futures::stream::once({
            let d = data.clone();
            async move { Ok(Bytes::from(d)) }
        }));
        let p1 = prepare_in_memory_checksum_upload(
            body1,
            data.len() as u64,
            HashKind::Crc64Nvme,
            true,
            true,
            &budget,
        )
        .await
        .unwrap()
        .unwrap_or_else(|_| panic!("expected in-memory prepared upload"));
        assert_eq!(
            p1.part_checksum.as_deref(),
            Some(format!("crc64nvme:{}", crc64_nvme_base64(&data)).as_str())
        );

        let body2: ByteStream = Box::pin(futures::stream::once({
            let d = data.clone();
            async move { Ok(Bytes::from(d)) }
        }));
        let p2 = prepare_hashed_upload(
            body2,
            data.len() as u64,
            true,
            Some(HashKind::Crc32c),
            false,
            true,
            &budget,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            p2.part_checksum.as_deref(),
            Some(format!("crc32c:{}", crc32c_base64(&data)).as_str())
        );
        assert_eq!(
            p2.sha256_hex.as_deref(),
            Some(crate::s3::sigv4::sha256_hex(&data).as_str())
        );
    }

    #[test]
    fn fast_utc_rfc3339_matches_general_parser_across_leap_years_fractions_and_fallbacks() {
        let valid = [
            "1970-01-01T00:00:00Z",
            "1970-01-01T00:00:00.000Z",
            "2000-02-29T23:59:59.999999999Z",
            "2024-02-29T12:34:56.1Z",
            "2024-02-29T12:34:56.123456Z",
            "2026-11-25T21:05:09.042z",
            "1969-12-31T23:59:59Z",
            "2100-03-01T00:00:00Z",
        ];
        for ts in valid {
            let expected = rship_core::time::parse_rfc3339_to_nanos(ts).unwrap();
            assert_eq!(
                parse_utc_rfc3339_fast_nanos(ts),
                Some(expected),
                "fast parser mismatch on {ts}"
            );
            assert_eq!(parse_rfc3339_or_http_nanos(ts), Some(expected));
        }

        // Invalid leap-year and malformed dates must return None from fast path.
        for bad in [
            "2025-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-11-25T24:00:00Z",
            "2026-11-25T00:00:00.Z",
            "2026-11-25T00:00:00.1234567890Z",
        ] {
            assert_eq!(
                parse_utc_rfc3339_fast_nanos(bad),
                None,
                "should reject {bad}"
            );
        }

        // Non-Z offset and RFC 2822 HTTP-date fall back to the general parsers cleanly.
        let tz = "2026-11-25T23:05:09+02:00";
        assert_eq!(parse_utc_rfc3339_fast_nanos(tz), None);
        assert_eq!(
            parse_rfc3339_or_http_nanos(tz),
            Some(1_795_640_709_000_000_000)
        );
        let http = "Wed, 25 Nov 2026 21:05:09 GMT";
        assert_eq!(
            parse_rfc3339_or_http_nanos(http),
            Some(1_795_640_709_000_000_000)
        );
    }

    /// C2 residue: a part that MUST carry a checksum header must never wait on the 16 MiB
    /// RAM budget while its body (prefetched by the engine) already holds a pool slab.
    ///
    /// Tight pool: exactly one slab, held by our body. Another upload holds the whole RAM
    /// budget and only releases it once its own body producer gets that slab. Waiting on
    /// the budget here would deadlock both uploads.
    #[tokio::test]
    async fn required_part_checksum_never_waits_on_ram_budget_while_holding_a_pool_slab() {
        use rship_core::buffer::BufferPool;
        const SLAB: usize = 64 * 1024;
        let pool = BufferPool::new(SLAB, SLAB).unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let held_by_other_upload = budget.clone().acquire_many_owned(4).await.unwrap();

        let mut slab = pool.try_acquire_slab().expect("the only slab");
        slab.spare_mut()[..SLAB].fill(0x42);
        slab.set_len(SLAB);
        let body: ByteStream = Box::pin(futures::stream::iter(vec![Ok(slab.into_bytes())]));

        let other_pool = pool.clone();
        let other_upload = tokio::spawn(async move {
            let _next_chunk = other_pool.acquire_slab().await.unwrap();
            drop(held_by_other_upload);
        });

        let tmp = tempfile::TempDir::new().unwrap();
        let prepared = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            prepare_required_checksum_upload(
                body,
                SLAB as u64,
                HashKind::Crc32c,
                false,
                true,
                &budget,
                Some(tmp.path()),
            ),
        )
        .await
        .expect("must not deadlock on the RAM budget while holding a pool slab")
        .unwrap();
        let expected = crc32c_base64(&vec![0x42u8; SLAB]);
        assert_eq!(
            prepared.part_checksum.as_deref(),
            Some(format!("crc32c:{expected}").as_str())
        );
        let (name, val) = prepared.checksum_header.expect("checksum header");
        assert_eq!(name.as_str(), "x-amz-checksum-crc32c");
        assert_eq!(val.to_str().unwrap(), expected);
        other_upload.await.unwrap();

        let mut out = Vec::new();
        let mut s = prepared.backing.into_stream();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        assert_eq!(out, vec![0x42u8; SLAB]);
        assert_eq!(pool.stats().in_use_units, 0);
    }
}
