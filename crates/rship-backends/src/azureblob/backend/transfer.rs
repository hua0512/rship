//! Azure Blob data-plane streaming downloads (`RemoteRangeReadable`), single-shot
//! `PutBlob`, parallel `PutBlock` / `GetBlockList` / `PutBlockList` uploads, block ID
//! encoding, and ambiguous-commit reconciliation.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::OperationRecord;
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};

use crate::azureblob::config::append_rfc3986_query;
use crate::azureblob::xml::{build_block_list_xml, normalize_azure_etag, parse_block_list};
use crate::common::http::send_watched_sized_upload_with_capture;
use crate::common::{
    ExactDownloadStream, StreamingHashStream, StreamingMd5, StrictBodyStream,
    VerifyingDownloadStream, checksum_mismatch_error, lock_unpoisoned,
};

use super::{
    AzureBlobBackend, AzureInner, BLOCK_MD5_UNIT_BYTES, HDR_META_MTIME, HDR_META_OP_ID,
    MAX_BLOCK_MD5_BYTES, decode_md5_b64, format_azure_mtime, insert_write_precondition_header,
    map_azure_http_error_with_headers,
};

const MAX_REORDER_PARTS: usize = 8;

#[inline]
fn op_dst_raw_path(op: &OperationRecord) -> &str {
    if op.dst_raw_path.is_empty() {
        op.dst_nfc_path.as_str()
    } else {
        op.dst_raw_path.as_str()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct AzureSessionMeta {
    #[serde(default)]
    checksums: Vec<Checksum>,
}

/// Whole-blob MD5 of a block upload, accumulated in exact part/offset order using a bounded
/// reorder window (`MAX_REORDER_PARTS` blocks) so `UploadTopology::ParallelParts` uploads
/// reliably compute the whole-blob MD5 when concurrent parts finish slightly out of order.
///
/// If parts arrive beyond the reorder window, are duplicated, missing (e.g. crash-resume), or
/// exceed the bounded memory budget, the state transitions to `broken` and releases all
/// buffered bytes so no corrupted/false MD5 is ever claimed.
pub(super) struct OrderedBlobMd5 {
    next_part: u32,
    next_offset: u64,
    hasher: StreamingMd5,
    pending: BTreeMap<u32, (u64, Bytes, tokio::sync::OwnedSemaphorePermit)>,
    broken: bool,
}

impl OrderedBlobMd5 {
    fn new() -> Self {
        Self {
            next_part: 1,
            next_offset: 0,
            hasher: StreamingMd5::new(),
            pending: BTreeMap::new(),
            broken: false,
        }
    }

    fn mark_broken(&mut self) {
        self.broken = true;
        self.pending.clear();
    }

    fn submit(
        &mut self,
        part_number: u32,
        offset: u64,
        len: u64,
        data: Option<(Bytes, tokio::sync::OwnedSemaphorePermit)>,
    ) {
        if self.broken {
            return;
        }
        if part_number < self.next_part || self.pending.contains_key(&part_number) {
            self.mark_broken();
            return;
        }
        let Some((bytes, permit)) = data else {
            self.mark_broken();
            return;
        };
        if bytes.len() as u64 != len {
            self.mark_broken();
            return;
        }
        if part_number == self.next_part {
            if offset != self.next_offset {
                self.mark_broken();
                return;
            }
            self.hasher.update_bytes(&bytes);
            drop(permit);
            let (Some(np), Some(no)) = (
                self.next_part.checked_add(1),
                self.next_offset.checked_add(len),
            ) else {
                self.mark_broken();
                return;
            };
            self.next_part = np;
            self.next_offset = no;
            while let Some((p_off, p_bytes, p_permit)) = self.pending.remove(&self.next_part) {
                if p_off != self.next_offset {
                    self.mark_broken();
                    return;
                }
                self.hasher.update_bytes(&p_bytes);
                let p_len = p_bytes.len() as u64;
                drop(p_permit);
                let (Some(np), Some(no)) = (
                    self.next_part.checked_add(1),
                    self.next_offset.checked_add(p_len),
                ) else {
                    self.mark_broken();
                    return;
                };
                self.next_part = np;
                self.next_offset = no;
            }
        } else {
            if self.pending.len() >= MAX_REORDER_PARTS {
                self.mark_broken();
                return;
            }
            self.pending.insert(part_number, (offset, bytes, permit));
        }
    }
}

/// Deterministic, fixed-length (16 raw bytes -> 24 Base64 chars) Azure Block ID encoding a
/// 12-byte SHA-256 hash of the full `op_tag` plus the 4-byte big-endian `part_number`.
///
/// Azure requires all block IDs in a single blob's `Put Block List` to have identical byte length
/// (`<= 64` raw bytes) and distinct operation tags must never collide.
pub fn make_block_id_b64(op_tag: &str, part_number: u32) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(op_tag.as_bytes());
    let mut raw = [0u8; 16];
    raw[..12].copy_from_slice(&digest[..12]);
    raw[12..16].copy_from_slice(&part_number.to_be_bytes());
    B64.encode(raw)
}

/// Parse a `part_number` back from a base64 block ID if it belongs to `op_tag`.
pub fn parse_block_id_part(block_id_b64: &str, op_tag: &str) -> Option<u32> {
    use sha2::Digest as _;
    let decoded = B64.decode(block_id_b64.trim()).ok()?;
    if decoded.len() != 16 {
        return None;
    }
    let digest = sha2::Sha256::digest(op_tag.as_bytes());
    if decoded[..12] != digest[..12] {
        return None;
    }
    Some(u32::from_be_bytes([
        decoded[12],
        decoded[13],
        decoded[14],
        decoded[15],
    ]))
}

struct AzureBlobRangeReader {
    inner: Arc<AzureInner>,
    full_key: String,
    etag: Option<String>,
    total_len: u64,
}

#[async_trait]
impl RemoteRangeReadable for AzureBlobRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_inclusive = range
            .offset
            .checked_add(range.len - 1)
            .ok_or_else(|| Error::protocol("Azure Blob range overflow"))?;
        let raw_url = self.inner.cfg.blob_url(&self.full_key);
        let final_url = self.inner.auth.apply_url(&raw_url);

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={}-{}", range.offset, end_inclusive))
                .map_err(|e| Error::protocol(format!("Range header: {e}")))?,
        );
        if let Some(etag) = &self.etag
            && !etag.is_empty()
        {
            headers.insert(
                http::header::IF_MATCH,
                HeaderValue::from_str(etag)
                    .map_err(|e| Error::protocol(format!("If-Match header: {e}")))?,
            );
        }
        let now = self.inner.now_utc();
        self.inner
            .auth
            .sign_headers(&Method::GET, &final_url, &mut headers, now)?;

        let req = self
            .inner
            .transport
            .data_client()
            .get(&final_url)
            .headers(headers);
        let resp = self
            .inner
            .transport
            .send_data_request("Azure Blob range download", req)
            .await?;
        let status = resp.status();

        if status != StatusCode::PARTIAL_CONTENT
            && !(status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
        {
            let resp_headers = resp.headers().clone();
            let body = self.inner.transport.read_data_body(resp).await?;
            let err = map_azure_http_error_with_headers(
                "Azure Blob range download",
                status,
                Some(&resp_headers),
                &body,
            );
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }
        self.inner.data_limiter.record_success(false, false);

        let is_full_object = range.offset == 0 && range.len == self.total_len;
        let resp_headers = resp.headers().clone();
        let watched = self
            .inner
            .transport
            .watch_response_stream("Azure download stream", resp);
        let exact = ExactDownloadStream::new("AzureBlob", watched, range.len);
        if is_full_object
            && let Some(expected_md5) = resp_headers
                .get("content-md5")
                .or_else(|| resp_headers.get("x-ms-blob-content-md5"))
                .and_then(|v| v.to_str().ok())
                .and_then(decode_md5_b64)
        {
            return Ok(Box::pin(VerifyingDownloadStream::new(
                "AzureBlob",
                "MD5",
                exact,
                StreamingMd5::new(),
                range.len,
                expected_md5.hex,
            )));
        }
        Ok(Box::pin(exact))
    }
}

impl AzureBlobBackend {
    async fn send_azure_upload(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
        body: ByteStream,
        expected_len: u64,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let md5_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let strict = StrictBodyStream::new("AzureBlob", body, expected_len, captured_err.clone());
        let hashed =
            StreamingHashStream::new(strict, StreamingMd5::new(), expected_len, md5_slot.clone());
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            context,
            req,
            hashed,
            expected_len,
            captured_err,
        )
        .await?;
        let streamed_md5 = lock_unpoisoned(&md5_slot).take();
        Ok((resp, streamed_md5))
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let raw_rel = path.raw_path();
        let full_key = self.inner.cfg.full_key(raw_rel);
        let headers = self
            .head_blob(&full_key)
            .await?
            .ok_or_else(|| Error::not_found(format!("Azure blob `{full_key}` not found")))?;
        if headers
            .get("x-ms-access-tier")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("Archive"))
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                RetryClass::Permanent,
                format!(
                    "Azure blob `{full_key}` is in Archive tier and must be rehydrated before reading"
                ),
            ));
        }
        let entry = self.headers_to_entry(raw_rel, &headers)?;
        self.open_read_entry(&entry, path, range).await
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
        let reader = Arc::new(AzureBlobRangeReader {
            inner: self.inner.clone(),
            full_key,
            etag: entry.etag.clone(),
            total_len: entry.size,
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

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let full_key = self.inner.cfg.full_key(init.dst_path.as_str());
        let raw_url = self.inner.cfg.blob_url(&full_key);
        let final_url = self.inner.auth.apply_url(&raw_url);

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("BlockBlob"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&init.total_size.to_string())
                .map_err(|e| Error::protocol(format!("content-length: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static(HDR_META_MTIME),
            HeaderValue::from_str(&format_azure_mtime(init.src_mtime_ns))
                .map_err(|e| Error::protocol(format!("mtime header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static(HDR_META_OP_ID),
            HeaderValue::from_str(&init.op_id)
                .map_err(|e| Error::protocol(format!("op-id header: {e}")))?,
        );
        self.insert_access_tier_header(&mut headers)?;
        insert_write_precondition_header(&init.precondition, &mut headers)?;
        let known_md5_hex = init
            .checksums
            .iter()
            .find(|c| c.kind == HashKind::Md5)
            .and_then(|c| {
                let bytes = hex::decode(c.hex.trim()).ok()?;
                (bytes.len() == 16).then(|| (c.hex.trim().to_ascii_lowercase(), B64.encode(bytes)))
            });
        if let Some((_, ref md5_b64)) = known_md5_hex {
            headers.insert(
                HeaderName::from_static("content-md5"),
                HeaderValue::from_str(md5_b64)
                    .map_err(|e| Error::protocol(format!("content-md5 header: {e}")))?,
            );
        }
        self.inner
            .auth
            .sign_headers(&Method::PUT, &final_url, &mut headers, self.now_utc())?;

        let req = self
            .inner
            .transport
            .data_client()
            .put(&final_url)
            .headers(headers);
        let (resp, streamed_md5) = self
            .send_azure_upload("Azure PutBlob", req, body, init.total_size)
            .await?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;
        if !status.is_success() {
            let err = map_azure_http_error_with_headers(
                "Azure PutBlob",
                status,
                Some(&resp_headers),
                &resp_body,
            );
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }
        self.inner.data_limiter.record_success(false, false);

        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_azure_etag);
        let checksum = resp_headers
            .get("content-md5")
            .and_then(|v| v.to_str().ok())
            .and_then(decode_md5_b64);

        if let Some(ref server_ck) = checksum {
            if let Some(ref streamed) = streamed_md5
                && !streamed.eq_ignore_ascii_case(&server_ck.hex)
            {
                return Err(checksum_mismatch_error(
                    "Azure PutBlob",
                    "MD5",
                    streamed,
                    &server_ck.hex,
                ));
            }
            if let Some((ref known_hex, _)) = known_md5_hex
                && !known_hex.eq_ignore_ascii_case(&server_ck.hex)
            {
                return Err(checksum_mismatch_error(
                    "Azure PutBlob",
                    "MD5",
                    known_hex,
                    &server_ck.hex,
                ));
            }
        }

        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        })
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let meta = AzureSessionMeta {
            checksums: init.checksums.clone(),
        };
        let backend_meta = serde_json::to_string(&meta)
            .map_err(|e| Error::protocol(format!("serialize Azure session meta: {e}")))?;
        Ok(UploadSessionInit {
            session_token: init.op_id.clone(),
            backend_meta,
            remote_op_id: None,
            expires_at_unix_secs: None,
        })
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(op_tag) = op.session_token.as_deref() else {
            return Ok(UploadProgress::Expired);
        };
        let full_key = self.inner.cfg.full_key(op_dst_raw_path(op));
        let raw_url = append_rfc3986_query(
            &self.inner.cfg.blob_url(&full_key),
            &[("comp", "blocklist"), ("blocklisttype", "uncommitted")],
        );
        let (status, _, body) = self
            .control_request(
                "Azure GetBlockList",
                Method::GET,
                &raw_url,
                HeaderMap::new(),
                None,
                true,
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(UploadProgress::CompletedParts(Vec::new()));
        }

        let bl = parse_block_list(&body)?;
        let chunk_size = op.planned_chunk_size.max(1);
        let mut parts = Vec::new();
        for blk in bl.uncommitted {
            if let Some(part_number) = parse_block_id_part(&blk.name_b64, op_tag) {
                let offset = u64::from(part_number.saturating_sub(1)) * chunk_size;
                parts.push(CompletedPart {
                    part_number,
                    offset,
                    length: blk.size,
                    etag: blk.name_b64,
                    checksum: None,
                });
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok(UploadProgress::CompletedParts(parts))
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let op_tag = op.session_token.as_deref().unwrap_or(op.op_id.as_str());
        let block_id_b64 = make_block_id_b64(op_tag, chunk.part_number);
        let full_key = self.inner.cfg.full_key(op_dst_raw_path(op));

        let raw_url = append_rfc3986_query(
            &self.inner.cfg.blob_url(&full_key),
            &[("comp", "block"), ("blockid", &block_id_b64)],
        );
        let final_url = self.inner.auth.apply_url(&raw_url);

        self.inner.data_limiter.acquire_send_permit().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&chunk.len.to_string())
                .map_err(|e| Error::protocol(format!("content-length: {e}")))?,
        );

        let mut body_stream = chunk.body;
        let buffered = if chunk.len <= MAX_BLOCK_MD5_BYTES {
            let units = (chunk.len.max(1).div_ceil(BLOCK_MD5_UNIT_BYTES)) as u32;
            if let Ok(permit) = self
                .inner
                .block_md5_mem_budget
                .clone()
                .try_acquire_many_owned(units)
            {
                let mut buf = Vec::with_capacity(chunk.len as usize);
                let mut hasher = StreamingMd5::new();
                while let Some(item) = body_stream.next().await {
                    let bytes = item?;
                    if (buf.len() as u64).saturating_add(bytes.len() as u64) > chunk.len {
                        return Err(Error::source_mutated(format!(
                            "AzureBlob PutBlock stream exceeded declared length (> {})",
                            chunk.len
                        )));
                    }
                    hasher.update_bytes(&bytes);
                    buf.extend_from_slice(&bytes);
                }
                if buf.len() as u64 != chunk.len {
                    return Err(Error::source_mutated(format!(
                        "short EOF during AzureBlob PutBlock: received {} of {} bytes",
                        buf.len(),
                        chunk.len
                    )));
                }
                let md5_b64 = B64.encode(hasher.finalize_bytes());
                headers.insert(
                    HeaderName::from_static("content-md5"),
                    HeaderValue::from_str(&md5_b64)
                        .map_err(|e| Error::protocol(format!("content-md5 header: {e}")))?,
                );
                let bytes = Bytes::from(buf);
                let for_req = bytes.clone();
                let req_stream: ByteStream = if for_req.is_empty() {
                    Box::pin(futures::stream::empty())
                } else {
                    Box::pin(futures::stream::once(async move { Ok(for_req) }))
                };
                Some((req_stream, (bytes, permit)))
            } else {
                None
            }
        } else {
            None
        };

        self.inner
            .auth
            .sign_headers(&Method::PUT, &final_url, &mut headers, self.now_utc())?;

        let req = self
            .inner
            .transport
            .data_client()
            .put(&final_url)
            .headers(headers);

        match buffered {
            Some((req_stream, reorder_data)) => {
                self.put_block_checked(req, req_stream, chunk.len).await?;
                self.submit_ordered_md5(
                    &op.op_id,
                    chunk.part_number,
                    chunk.offset,
                    chunk.len,
                    Some(reorder_data),
                );
            }
            None => {
                self.put_block_checked(req, body_stream, chunk.len).await?;
                self.submit_ordered_md5(
                    &op.op_id,
                    chunk.part_number,
                    chunk.offset,
                    chunk.len,
                    None,
                );
            }
        }

        Ok(ChunkAck {
            next_offset: None,
            etag: Some(block_id_b64),
            completed: None,
            checksum: None,
        })
    }

    /// Send one `Put Block` and verify the service's MD5 of the block against the streamed one.
    async fn put_block_checked(
        &self,
        req: reqwest::RequestBuilder,
        body: ByteStream,
        len: u64,
    ) -> Result<()> {
        let (resp, streamed_md5) = self
            .send_azure_upload("Azure PutBlock", req, body, len)
            .await?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;
        if !status.is_success() {
            let err = map_azure_http_error_with_headers(
                "Azure PutBlock",
                status,
                Some(&resp_headers),
                &resp_body,
            );
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }
        if let Some(ref streamed) = streamed_md5
            && let Some(server_ck) = resp_headers
                .get("content-md5")
                .and_then(|v| v.to_str().ok())
                .and_then(decode_md5_b64)
            && !streamed.eq_ignore_ascii_case(&server_ck.hex)
        {
            return Err(checksum_mismatch_error(
                "Azure PutBlock",
                "MD5",
                streamed,
                &server_ck.hex,
            ));
        }
        self.inner.data_limiter.record_success(false, false);
        Ok(())
    }

    fn submit_ordered_md5(
        &self,
        op_id: &str,
        part_number: u32,
        offset: u64,
        len: u64,
        data: Option<(Bytes, tokio::sync::OwnedSemaphorePermit)>,
    ) {
        let mut map = lock_unpoisoned(&self.inner.blob_md5);
        let key = op_id.to_string();
        if let Some(st) = map.get_mut(&key) {
            st.submit(part_number, offset, len, data);
        } else {
            let mut st = OrderedBlobMd5::new();
            st.submit(part_number, offset, len, data);
            map.insert(key, st);
        }
    }

    /// Take the finished whole-blob MD5 (lowercase hex) if every block of `sorted` was hashed
    /// in order and the bytes cover the whole source.
    fn take_ordered_md5(&self, op: &OperationRecord, sorted: &[&CompletedPart]) -> Option<String> {
        let st = lock_unpoisoned(&self.inner.blob_md5).remove(&op.op_id)?;
        let in_order = sorted
            .iter()
            .enumerate()
            .all(|(i, p)| p.part_number as usize == i + 1);
        if st.broken
            || !st.pending.is_empty()
            || !in_order
            || st.next_part as usize != sorted.len() + 1
            || st.next_offset != op.src_version.size
        {
            return None;
        }
        Some(st.hasher.finalize_hex())
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        parts: &[CompletedPart],
    ) -> Result<Entry> {
        let mut sorted: Vec<&CompletedPart> = parts.iter().collect();
        sorted.sort_by_key(|p| p.part_number);
        let ids: Vec<&str> = sorted.iter().map(|p| p.etag.as_str()).collect();
        let xml_body = Bytes::from(build_block_list_xml(&ids));

        let full_key = self.inner.cfg.full_key(op_dst_raw_path(op));
        let raw_url = append_rfc3986_query(
            &self.inner.cfg.blob_url(&full_key),
            &[("comp", "blocklist")],
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            HeaderName::from_static(HDR_META_MTIME),
            HeaderValue::from_str(&format_azure_mtime(op.src_version.mtime_ns))
                .map_err(|e| Error::protocol(format!("mtime header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static(HDR_META_OP_ID),
            HeaderValue::from_str(&op.op_id)
                .map_err(|e| Error::protocol(format!("op-id header: {e}")))?,
        );
        self.insert_access_tier_header(&mut headers)?;
        insert_write_precondition_header(&op.dst_precondition, &mut headers)?;

        let session_meta =
            serde_json::from_str::<AzureSessionMeta>(&op.backend_meta).unwrap_or_default();
        let expected_md5 = session_meta
            .checksums
            .into_iter()
            .find(|ck| ck.kind == HashKind::Md5)
            .and_then(|ck| {
                let bytes = hex::decode(ck.hex.trim()).ok()?;
                (bytes.len() == 16).then(|| (ck.hex.trim().to_ascii_lowercase(), B64.encode(bytes)))
            });
        // The real whole-blob MD5, if every block was streamed through it in order. It is
        // checked against a known source MD5 BEFORE committing, and stored as the blob's
        // Content-MD5 (the service does not validate `x-ms-blob-content-md5`).
        let streamed_md5 = self.take_ordered_md5(op, &sorted);
        if let (Some(computed), Some((expected_hex, _))) = (&streamed_md5, &expected_md5)
            && !computed.eq_ignore_ascii_case(expected_hex)
        {
            return Err(checksum_mismatch_error(
                "Azure PutBlockList",
                "MD5",
                expected_hex,
                computed,
            ));
        }
        let blob_md5_b64 = match &streamed_md5 {
            Some(hex_md5) => Some(
                B64.encode(
                    hex::decode(hex_md5)
                        .map_err(|e| Error::protocol(format!("streamed MD5 hex: {e}")))?,
                ),
            ),
            // Unverified source MD5: stored as the blob property (rclone-compatible) but NOT
            // claimed as the committed checksum below.
            None => expected_md5.as_ref().map(|(_, b64)| b64.clone()),
        };
        if let Some(md5_b64) = &blob_md5_b64 {
            headers.insert(
                HeaderName::from_static("x-ms-blob-content-md5"),
                HeaderValue::from_str(md5_b64)
                    .map_err(|e| Error::protocol(format!("x-ms-blob-content-md5 header: {e}")))?,
            );
        }

        // NOTE: the response `Content-MD5` is the MD5 of the block-list XML request body,
        // never the blob's, so it is not used as the committed checksum.
        let expected_size = op.src_version.size;
        let (_, resp_headers, _) = self
            .long_control_commit(
                "Azure PutBlockList",
                &raw_url,
                headers,
                xml_body,
                false,
                |err| {
                    let full_key = full_key.clone();
                    async move {
                        self.reconcile_commit_by_op_id(
                            &full_key,
                            &op.op_id,
                            Some(expected_size),
                            false,
                            err,
                        )
                        .await
                    }
                },
            )
            .await?;

        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_azure_etag);
        let checksum = streamed_md5.map(|hex| Checksum {
            kind: HashKind::Md5,
            hex,
        });

        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&op.dst_nfc_path, op_dst_raw_path(op)),
            nfc_path: op.dst_nfc_path.clone(),
            kind: EntryKind::File,
            size: op.src_version.size,
            mtime_ns: op.src_version.mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        })
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        lock_unpoisoned(&self.inner.blob_md5).remove(&op.op_id);
        // Uncommitted Azure blocks are never visible to readers and are garbage-collected
        // automatically by Azure Storage after 7 days (or overwritten on the next PutBlockList).
        Ok(())
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let full_key = self.inner.cfg.full_key(op_dst_raw_path(op));
        let Some(headers) = self.head_blob(&full_key).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };
        let op_matches = headers
            .get(HDR_META_OP_ID)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == op.op_id);
        if !op_matches {
            return Ok(ReconcileOutcome::Ambiguous(format!(
                "Azure blob `{full_key}` exists with different op-id"
            )));
        }
        let copy_status = headers
            .get("x-ms-copy-status")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase());
        match copy_status.as_deref() {
            Some("pending") => {
                return Ok(ReconcileOutcome::Ambiguous(format!(
                    "Azure CopyBlob `{full_key}` for op `{}` is still pending",
                    op.op_id
                )));
            }
            Some("failed") | Some("aborted") => {
                return Ok(ReconcileOutcome::NotCommitted);
            }
            None | Some("success") => {}
            Some(other) => {
                return Ok(ReconcileOutcome::Ambiguous(format!(
                    "Azure blob `{full_key}` has unexpected x-ms-copy-status `{other}`"
                )));
            }
        }
        let entry = self.headers_to_entry(op_dst_raw_path(op), &headers)?;
        if entry.size == op.src_version.size {
            return Ok(ReconcileOutcome::Committed(entry));
        }
        Ok(ReconcileOutcome::Ambiguous(format!(
            "Azure blob `{full_key}` exists with different size ({} != {})",
            entry.size, op.src_version.size
        )))
    }
}
