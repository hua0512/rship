//! WebDAV data-plane streaming downloads (`RemoteRangeReadable`), single-shot `PUT`,
//! Nextcloud/OwnCloud Chunked Upload v2 (`MKCOL` -> `PUT` chunks -> `PROPFIND` recovery
//! -> reconciled `MOVE .file` assembly), and ambiguous-commit reconciliation.
//!
//! # Checksums
//!
//! WebDAV itself has no content hash. Only Nextcloud/ownCloud vendors
//! ([`WebdavVendor::supports_oc_checksums`](crate::webdav::WebdavVendor::supports_oc_checksums))
//! get verification, and only through these headers:
//! - Every `PUT` (single-shot and chunk) sends `X-Hash: md5`. Nextcloud hashes the bytes as it
//!   writes them and returns `X-Hash-MD5`, which is compared with the MD5 streamed here.
//!   ownCloud and older Nextcloud omit the header; that `PUT` is then unverified.
//! - When the source MD5 or SHA-1 is known up front, single-shot `PUT` and the chunked `MOVE` send
//!   `OC-Checksum: MD5:<hex>` or `SHA1:<hex>`. ownCloud validates it (HTTP 400 on mismatch).
//!   Nextcloud stores it and returns it as `OC-Checksum` on later `GET`s.
//! - A full-object `GET` whose response carries an `OC-Checksum` `MD5` or `SHA1` is verified while
//!   it streams. Ranged reads, and `ADLER32`-only checksums, are unverified.
//!
//! These checksums are client-supplied metadata on Nextcloud, so they are never surfaced as
//! `Entry::checksum` and the backend advertises no hash capability. Every other vendor
//! (generic, Alist, Synology, Infinicloud) is unverified, length checks aside.

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind, raw_path_override};
use rship_core::{Error, ErrorKind, Result};
use rship_transport::{HttpDumpMode, map_reqwest_error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use crate::common::http::{
    HttpResponse, PolicyDecision, ReconcileAction, percent_encode_segment,
    send_watched_sized_upload_with_capture, watch_sized_upload_stream,
};
use crate::common::reconcile::{PreOpState, judge_reconciled_object};
use crate::common::{
    StreamingDigest, StreamingHashStream, StreamingMd5, StrictBodyStream, VerifyingDownloadStream,
    checksum_mismatch_error, lock_unpoisoned,
};
use crate::webdav::config::WebdavChunkNaming;
use crate::webdav::xml::PROPFIND_ALL_BODY;

use super::{
    MAX_WEBDAV_REDIRECTS, METHOD_MOVE, WebdavBackend, classify_dav_status,
    dav_mutation_policy_decision, dump_webdav_error, dump_webdav_request, dump_webdav_response,
    is_method_preserving_redirect, resolve_same_origin_redirect,
};

const X_HASH: &str = "x-hash";
const X_HASH_MD5: &str = "x-hash-md5";
const OC_CHECKSUM: &str = "oc-checksum";
const X_OC_MTIME: &str = "x-oc-mtime";
const MAX_NEXTCLOUD_PARTS: u32 = 10_000;

/// Pure-Rust RFC 3174 streaming SHA-1 hasher returning 40-char lowercase hex.
#[derive(Clone)]
struct StreamingSha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

impl StreamingSha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
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

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    fn update_bytes(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let block: &[u8; 64] = block.try_into().expect("64-byte slice");
            Self::compress(&mut self.state, block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.state, &self.buf);

        let mut out = String::with_capacity(40);
        for word in self.state {
            for b in word.to_be_bytes() {
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
        out
    }
}

impl StreamingDigest for StreamingSha1 {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

fn known_source_hash(
    checksums: &[Checksum],
    target: HashKind,
    expected_len: usize,
) -> Option<String> {
    checksums
        .iter()
        .find(|ck| ck.kind == target)
        .map(|ck| ck.hex.trim().to_ascii_lowercase())
        .filter(|hex| hex.len() == expected_len && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Prefer MD5 (matches `X-Hash: md5` synergy), falling back to SHA-1 for `OC-Checksum`.
fn known_source_oc_checksum(checksums: &[Checksum]) -> Option<(HashKind, String)> {
    if let Some(md5) = known_source_hash(checksums, HashKind::Md5, 32) {
        return Some((HashKind::Md5, md5));
    }
    known_source_hash(checksums, HashKind::Sha1, 40).map(|sha1| (HashKind::Sha1, sha1))
}

fn format_oc_checksum_header(kind: HashKind, hex: &str) -> (&'static str, String) {
    match kind {
        HashKind::Md5 => ("MD5", format!("MD5:{hex}")),
        HashKind::Sha1 => ("SHA1", format!("SHA1:{hex}")),
        _ => ("UNKNOWN", hex.to_string()),
    }
}

/// Extract `MD5` or `SHA1` (lowercase hex) from an `OC-Checksum` header such as
/// `SHA1:… MD5:… ADLER32:…`, preferring `MD5` when both are present.
fn parse_oc_checksum(headers: &HeaderMap) -> Option<(HashKind, String)> {
    let mut sha1_fallback: Option<String> = None;
    for raw in headers
        .get_all(OC_CHECKSUM)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for item in raw.split([' ', ',']) {
            let Some((kind, hex)) = item.trim().split_once(':') else {
                continue;
            };
            let hex = hex.trim().to_ascii_lowercase();
            if kind.eq_ignore_ascii_case("MD5")
                && hex.len() == 32
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Some((HashKind::Md5, hex));
            }
            if sha1_fallback.is_none()
                && kind.eq_ignore_ascii_case("SHA1")
                && hex.len() == 40
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                sha1_fallback = Some(hex);
            }
        }
    }
    sha1_fallback.map(|hex| (HashKind::Sha1, hex))
}

/// Whether an HTTP 400 body is ownCloud's checksum rejection
/// ("The computed checksum does not match the one received from the client.").
fn is_checksum_rejection(status: StatusCode, body: &[u8]) -> bool {
    status == StatusCode::BAD_REQUEST
        && String::from_utf8_lossy(body)
            .to_ascii_lowercase()
            .contains("checksum")
}

fn default_unknown_pre_op() -> PreOpState {
    PreOpState::Unknown
}

fn normalize_oc_mtime_ns(ns: i64) -> i64 {
    let secs = ns.div_euclid(1_000_000_000);
    if secs > 0 {
        secs.saturating_mul(1_000_000_000)
    } else {
        ns
    }
}

enum MoveAssembleOutcome {
    Completed(HeaderMap),
    Reconciled(Entry),
}

#[derive(Debug, Serialize, Deserialize)]
struct WebdavSessionMeta {
    staging_url: String,
    dst_url: String,
    total_size: u64,
    src_mtime_ns: i64,
    /// Source MD5 known at `begin_upload`, sent as `OC-Checksum` on the assembling `MOVE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_md5: Option<String>,
    /// Source SHA-1 known at `begin_upload`, used as fallback `OC-Checksum` when MD5 is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_sha1: Option<String>,
    /// Pre-operation destination state captured at `begin_upload` for safe C6 reconciliation.
    #[serde(default = "default_unknown_pre_op")]
    pre_op: PreOpState,
}

struct StreamPutParams<'a> {
    context: &'static str,
    url: &'a str,
    expected_len: u64,
    mtime_ns: Option<i64>,
    dst_path: Option<&'a RelPath>,
    is_upload_session: bool,
    source_checksum: Option<(HashKind, &'a str)>,
    extra_headers: Option<&'a HeaderMap>,
}

struct WebdavRangeReader {
    backend: WebdavBackend,
    url: String,
    total_len: u64,
}

#[async_trait]
impl RemoteRangeReadable for WebdavRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("WebDAV range overflow"))?;
        if end_exclusive > self.total_len {
            return Err(Error::invalid_geometry(format!(
                "WebDAV download range [{}..{}) exceeds size {}",
                range.offset, end_exclusive, self.total_len
            )));
        }

        let mut headers = HeaderMap::new();
        self.backend.apply_request_headers(&mut headers);
        headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={}-{}", range.offset, end_exclusive - 1))
                .map_err(|e| Error::protocol(format!("Range header: {e}")))?,
        );

        let mut active_url = self.url.clone();
        let mut resp_opt = None;
        for hop in 0..=MAX_WEBDAV_REDIRECTS {
            self.backend.inner.data_limiter.acquire_send_permit().await;
            let req = self
                .backend
                .inner
                .no_redirect_data
                .get(&active_url)
                .headers(headers.clone());
            let resp = self
                .backend
                .send_no_redirect_data_request("GET(Range)", req)
                .await?;
            if is_method_preserving_redirect(resp.status()) {
                if hop == MAX_WEBDAV_REDIRECTS {
                    return Err(Error::protocol(format!(
                        "GET(Range): exceeded {MAX_WEBDAV_REDIRECTS} redirects"
                    )));
                }
                active_url =
                    resolve_same_origin_redirect("GET(Range)", &active_url, resp.headers())?;
                continue;
            }
            resp_opt = Some(resp);
            break;
        }
        let resp = resp_opt.expect("redirect loop returns or breaks with response");
        let status = resp.status();
        if status != StatusCode::PARTIAL_CONTENT
            && !(status == StatusCode::OK && range.offset == 0 && range.len == self.total_len)
        {
            let rh = resp.headers().clone();
            let rb = self.backend.inner.transport.read_data_body(resp).await?;
            let err = classify_dav_status("GET(Range)", status, &rh, &rb, false);
            if err.is_throttled() {
                self.backend.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }
        self.backend.inner.data_limiter.record_success(false, false);

        let is_full_object = range.offset == 0 && range.len == self.total_len;
        let expected_oc = (is_full_object && self.backend.inner.cfg.vendor.supports_oc_checksums())
            .then(|| parse_oc_checksum(resp.headers()))
            .flatten();
        let watched = self
            .backend
            .inner
            .transport
            .watch_response_stream("GET(Range) body", resp);
        let exact = crate::common::ExactDownloadStream::new("WebDAV", watched, range.len);
        match expected_oc {
            Some((HashKind::Md5, expected_md5)) => Ok(Box::pin(VerifyingDownloadStream::new(
                "WebDAV",
                "MD5",
                exact,
                StreamingMd5::new(),
                range.len,
                expected_md5,
            ))),
            Some((HashKind::Sha1, expected_sha1)) => Ok(Box::pin(VerifyingDownloadStream::new(
                "WebDAV",
                "SHA1",
                exact,
                StreamingSha1::new(),
                range.len,
                expected_sha1,
            ))),
            _ => Ok(Box::pin(exact)),
        }
    }
}

impl WebdavBackend {
    /// Stream one `PUT` of exactly `expected_len` bytes.
    ///
    /// For Nextcloud/ownCloud vendors the body is MD5-hashed while it streams and the
    /// request asks for `X-Hash: md5`; a returned `X-Hash-MD5` that differs fails the call.
    /// `source_checksum` (single-shot only) is sent as `OC-Checksum` for ownCloud to validate.
    async fn stream_put_data(
        &self,
        params: StreamPutParams<'_>,
        body: ByteStream,
    ) -> Result<HeaderMap> {
        self.inner.data_limiter.acquire_send_permit().await;
        let oc_checksums = self.inner.cfg.vendor.supports_oc_checksums();
        let oc_mtime = self.inner.cfg.vendor.supports_oc_mtime();

        let mut headers = params.extra_headers.cloned().unwrap_or_default();
        self.apply_request_headers(&mut headers);
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&params.expected_len.to_string())
                .map_err(|e| Error::protocol(format!("invalid Content-Length: {e}")))?,
        );
        if oc_mtime && let Some(ns) = params.mtime_ns {
            let secs = ns.div_euclid(1_000_000_000);
            if secs > 0
                && let Ok(val) = HeaderValue::from_str(&secs.to_string())
            {
                headers.insert(HeaderName::from_static(X_OC_MTIME), val);
            }
        }
        let source_checksum = params.source_checksum.filter(|_| oc_checksums);
        if oc_checksums {
            headers.insert(
                HeaderName::from_static(X_HASH),
                HeaderValue::from_static("md5"),
            );
        }
        if let Some((kind, hex)) = source_checksum {
            let (_, header_val) = format_oc_checksum_header(kind, hex);
            headers.insert(
                HeaderName::from_static(OC_CHECKSUM),
                HeaderValue::from_str(&header_val)
                    .map_err(|e| Error::protocol(format!("invalid OC-Checksum: {e}")))?,
            );
        }

        // Enforce exact byte count during streaming so short EOF or source read errors
        // abort the HTTP body cleanly before the server commits a truncated object, and
        // signal body EOF on exact byte completion via `watch_sized_upload_stream`.
        let req = self.inner.no_redirect_data.put(params.url).headers(headers);
        let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let md5_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let mut strict: ByteStream = Box::pin(StrictBodyStream::new(
            "WebDAV",
            body,
            params.expected_len,
            captured_err.clone(),
        ));
        if oc_checksums {
            strict = Box::pin(StreamingHashStream::new(
                strict,
                StreamingMd5::new(),
                params.expected_len,
                md5_slot.clone(),
            ));
        }
        let resp = if self.inner.transport.config().dump_mode == HttpDumpMode::None {
            send_watched_sized_upload_with_capture(
                &self.inner.transport,
                params.context,
                req,
                strict,
                params.expected_len,
                captured_err,
            )
            .await?
        } else {
            let watchdog = self.inner.transport.data_watchdog();
            let watched = watch_sized_upload_stream(&watchdog, strict, params.expected_len);
            let built = req
                .body(reqwest::Body::wrap_stream(watched))
                .build()
                .map_err(|e| map_reqwest_error(params.context, e))?;
            dump_webdav_request(params.context, &built);
            let started = std::time::Instant::now();
            let res = watchdog
                .run(async {
                    self.inner
                        .no_redirect_data
                        .execute(built)
                        .await
                        .map_err(|e| map_reqwest_error(params.context, e))
                })
                .await;
            let resp = match res {
                Ok(r) => {
                    dump_webdav_response(params.context, &r, started.elapsed());
                    r
                }
                Err(e) => {
                    dump_webdav_error(params.context, &e, started.elapsed());
                    if let Some(root) = lock_unpoisoned(&captured_err).take() {
                        return Err(root);
                    }
                    return Err(e);
                }
            };
            if let Some(root) = lock_unpoisoned(&captured_err).take() {
                return Err(root);
            }
            resp
        };

        let status = resp.status();
        if status.is_redirection() {
            return Err(Error::protocol(format!(
                "{}: refusing HTTP {} redirect on streaming PUT",
                params.context,
                status.as_u16()
            )));
        }
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if !status.is_success() {
            if status == StatusCode::CONFLICT
                && let Some(dst) = params.dst_path
                && let Some(parent) = dst.parent()
            {
                self.evict_known_dir_chain(&parent);
            }
            if let Some((kind, expected_hex)) = source_checksum
                && is_checksum_rejection(status, &resp_body)
            {
                let (algo, _) = format_oc_checksum_header(kind, expected_hex);
                return Err(checksum_mismatch_error(
                    &format!("{} (rejected by server)", params.context),
                    algo,
                    expected_hex,
                    "server-computed value",
                ));
            }
            let err = classify_dav_status(
                params.context,
                status,
                &resp_headers,
                &resp_body,
                params.is_upload_session,
            );
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }

        self.inner.data_limiter.record_success(false, false);
        let streamed_md5 = lock_unpoisoned(&md5_slot).take();
        let server_md5 = resp_headers
            .get(X_HASH_MD5)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase());
        match (streamed_md5, server_md5) {
            (Some(streamed), Some(server)) if streamed != server => {
                if params.is_upload_session {
                    // A corrupted chunk would still count toward the confirmed prefix that
                    // `query_upload` derives from chunk names and sizes, so remove it.
                    let _ = self
                        .delete_reconciled("DELETE(corrupt chunked-v2 chunk)", params.url)
                        .await;
                }
                return Err(checksum_mismatch_error(
                    params.context,
                    "MD5",
                    &streamed,
                    &server,
                ));
            }
            (Some(_), None) => {
                tracing::debug!(
                    context = params.context,
                    "WebDAV server returned no X-Hash-MD5 for the PUT; it is unverified"
                );
            }
            _ => {}
        }
        Ok(resp_headers)
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some(entry) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "WebDAV object `{}` not found",
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
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let raw_rel = path
            .raw_path
            .as_deref()
            .or(entry.raw_path.as_deref())
            .unwrap_or_else(|| path.nfc_path.as_str());
        let url = self.url_for_rel(raw_rel);
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            WebdavRangeReader {
                backend: self.clone(),
                url,
                total_len: entry.size,
            },
        )))
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        self.ensure_parent_dirs(&init.dst_path).await?;
        let url = self.url_for_rel(init.dst_path.as_str());
        let source_checksum = known_source_oc_checksum(&init.checksums);
        let resp_headers = self
            .stream_put_data(
                StreamPutParams {
                    context: "PUT(single-shot)",
                    url: &url,
                    expected_len: init.total_size,
                    mtime_ns: Some(init.src_mtime_ns),
                    dst_path: Some(&init.dst_path),
                    is_upload_session: false,
                    source_checksum: source_checksum.as_ref().map(|(k, hex)| (*k, hex.as_str())),
                    extra_headers: None,
                },
                body,
            )
            .await?;
        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let sent_oc_mtime = self.inner.cfg.vendor.supports_oc_mtime()
            && init.src_mtime_ns.div_euclid(1_000_000_000) > 0;
        let x_oc_mtime_accepted = resp_headers
            .get(X_OC_MTIME)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("accepted"));

        // Generic WebDAV servers (and Nextcloud/ownCloud proxies that strip `X-OC-Mtime`) assign
        // their own server `getlastmodified` and `getetag`. Query `stat` when `X-OC-Mtime` was not
        // explicitly accepted so `sync_baseline` records exact server attributes.
        if !sent_oc_mtime || !x_oc_mtime_accepted {
            let bp = BackendPath::from_rel(init.dst_path.clone());
            if let Ok(Some(mut actual)) = self.stat(&bp).await {
                if actual.etag.is_none() {
                    actual.etag = etag.clone();
                }
                return Ok(actual);
            }
        }
        let mtime_ns = if sent_oc_mtime {
            normalize_oc_mtime_ns(init.src_mtime_ns)
        } else {
            init.src_mtime_ns
        };
        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: init.total_size,
            mtime_ns,
            ctime_ns: None,
            etag,
            checksum: None,
        })
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let Some(uploads_root) = &self.inner.chunked_root else {
            return Err(Error::protocol(
                "WebDAV remote does not support Nextcloud/OwnCloud chunked v2 uploads",
            ));
        };
        let encoded_op_id = percent_encode_segment(&init.op_id);
        let staging_url = format!("{}/{}", uploads_root.trim_end_matches('/'), encoded_op_id);
        let dst_url = self.url_for_rel(init.dst_path.as_str());

        let pre_op = match PreOpState::from_precondition(&init.precondition, |_, etag| etag.clone())
        {
            PreOpState::Unknown => {
                let dst_bp = BackendPath::from_rel(init.dst_path.clone());
                let existing = self.stat(&dst_bp).await?;
                PreOpState::snapshot(existing.as_ref(), |e| e.etag.clone())
            }
            known => known,
        };

        let mut mkcol_headers = HeaderMap::new();
        mkcol_headers.insert(
            HeaderName::from_static("destination"),
            HeaderValue::from_str(&dst_url)
                .map_err(|e| Error::protocol(format!("invalid Destination header: {e}")))?,
        );
        mkcol_headers.insert(
            HeaderName::from_static("oc-total-length"),
            HeaderValue::from_str(&init.total_size.to_string())
                .map_err(|e| Error::protocol(format!("invalid OC-Total-Length: {e}")))?,
        );
        self.mkcol_reconciled_with_headers(
            "MKCOL(chunked-v2)",
            &Self::ensure_trailing_slash(&staging_url),
            &mkcol_headers,
        )
        .await?;

        let meta = WebdavSessionMeta {
            staging_url: staging_url.clone(),
            dst_url,
            total_size: init.total_size,
            src_mtime_ns: init.src_mtime_ns,
            source_md5: known_source_hash(&init.checksums, HashKind::Md5, 32),
            source_sha1: known_source_hash(&init.checksums, HashKind::Sha1, 40),
            pre_op,
        };
        let backend_meta = serde_json::to_string(&meta)
            .map_err(|e| Error::protocol(format!("encode WebDAV session meta: {e}")))?;

        Ok(UploadSessionInit {
            session_token: staging_url,
            backend_meta,
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(staging_url) = op.session_token.as_deref() else {
            return Ok(UploadProgress::Expired);
        };
        let Some(items) = self
            .propfind(
                &Self::ensure_trailing_slash(staging_url),
                "1",
                PROPFIND_ALL_BODY,
                true,
            )
            .await?
        else {
            return Ok(UploadProgress::Expired);
        };

        let meta_total_size = serde_json::from_str::<WebdavSessionMeta>(&op.backend_meta)
            .map(|m| m.total_size)
            .unwrap_or(op.src_version.size);
        let total_size = meta_total_size.max(op.src_version.size);

        // Support both Nextcloud Chunking v2 numeric part names (`1..=10000`) and
        // ownCloud byte-range names (`{start:016}-{end_exclusive:016}`). Zero-byte chunk
        // files (`content_length == 0`) are always rejected.
        let mut ranges: HashMap<u64, u64> = HashMap::new();
        for item in items {
            if item.is_collection || item.content_length == 0 {
                continue;
            }
            let name = item
                .href
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("");
            if let Some((start_s, end_s)) = name.split_once('-')
                && let (Ok(start), Ok(end)) = (start_s.parse::<u64>(), end_s.parse::<u64>())
                && end > start
                && item.content_length == end - start
            {
                ranges.insert(start, end);
            } else if let Ok(part_num) = name.parse::<u32>()
                && (1..=MAX_NEXTCLOUD_PARTS).contains(&part_num)
                && op.planned_chunk_size > 0
                && total_size > 0
            {
                let start = u64::from(part_num - 1).saturating_mul(op.planned_chunk_size);
                if start < total_size {
                    let expected_len = op.planned_chunk_size.min(total_size - start);
                    if item.content_length == expected_len
                        || start.saturating_add(item.content_length) == total_size
                    {
                        ranges.insert(start, start.saturating_add(item.content_length));
                    }
                }
            }
        }

        let mut confirmed = 0u64;
        while let Some(&next_end) = ranges.get(&confirmed) {
            if next_end <= confirmed {
                break;
            }
            confirmed = next_end;
        }
        Ok(UploadProgress::SequentialOffset(confirmed))
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let staging_url = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing WebDAV chunked staging URL"))?;
        let end_exclusive = chunk.offset.saturating_add(chunk.len);
        let staging_trimmed = staging_url.trim_end_matches('/');

        let chunk_url = match self.inner.cfg.vendor.chunk_naming() {
            WebdavChunkNaming::NumericPart => {
                if !(1..=MAX_NEXTCLOUD_PARTS).contains(&chunk.part_number) {
                    return Err(Error::invalid_geometry(format!(
                        "Nextcloud chunked v2 part_number {} out of supported range 1..={MAX_NEXTCLOUD_PARTS}",
                        chunk.part_number
                    )));
                }
                format!("{staging_trimmed}/{}", chunk.part_number)
            }
            WebdavChunkNaming::ByteRange => {
                format!(
                    "{staging_trimmed}/{:016}-{:016}",
                    chunk.offset, end_exclusive
                )
            }
        };

        let (dst_url, total_size) =
            match serde_json::from_str::<WebdavSessionMeta>(&op.backend_meta) {
                Ok(meta) => (meta.dst_url, meta.total_size),
                Err(_) => (
                    self.url_for_rel(&op.dst_raw_path),
                    chunk.total_size.max(op.src_version.size),
                ),
            };
        let mut extra_headers = HeaderMap::new();
        extra_headers.insert(
            HeaderName::from_static("destination"),
            HeaderValue::from_str(&dst_url)
                .map_err(|e| Error::protocol(format!("invalid Destination header: {e}")))?,
        );
        extra_headers.insert(
            HeaderName::from_static("oc-total-length"),
            HeaderValue::from_str(&total_size.to_string())
                .map_err(|e| Error::protocol(format!("invalid OC-Total-Length: {e}")))?,
        );

        let resp_headers = self
            .stream_put_data(
                StreamPutParams {
                    context: "PUT(chunked-v2)",
                    url: &chunk_url,
                    expected_len: chunk.len,
                    mtime_ns: None,
                    dst_path: None,
                    is_upload_session: true,
                    source_checksum: None,
                    extra_headers: Some(&extra_headers),
                },
                chunk.body,
            )
            .await?;
        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        Ok(ChunkAck {
            next_offset: Some(end_exclusive),
            etag,
            completed: None,
            checksum: None,
        })
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        let meta: WebdavSessionMeta = serde_json::from_str(&op.backend_meta)
            .map_err(|e| Error::protocol(format!("decode WebDAV session meta: {e}")))?;
        self.ensure_parent_dirs(&op.dst_nfc_path).await?;

        let assemble_url = format!("{}/.file", meta.staging_url.trim_end_matches('/'));
        let overwrite = if matches!(op.dst_precondition, DstPrecondition::Absent) {
            "F"
        } else {
            "T"
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("destination"),
            HeaderValue::from_str(&meta.dst_url)
                .map_err(|e| Error::protocol(format!("invalid Destination header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static("overwrite"),
            HeaderValue::from_static(overwrite),
        );
        headers.insert(
            HeaderName::from_static("oc-total-length"),
            HeaderValue::from_str(&meta.total_size.to_string())
                .map_err(|e| Error::protocol(format!("invalid OC-Total-Length: {e}")))?,
        );
        let mtime_secs = meta.src_mtime_ns.div_euclid(1_000_000_000);
        let sent_oc_mtime = self.inner.cfg.vendor.supports_oc_mtime() && mtime_secs > 0;
        if sent_oc_mtime && let Ok(val) = HeaderValue::from_str(&mtime_secs.to_string()) {
            headers.insert(HeaderName::from_static(X_OC_MTIME), val);
        }
        // ownCloud validates the assembled file against `OC-Checksum`; Nextcloud stores it
        // (and returns it on later `GET`s). Each chunk was already checked via `X-Hash`.
        let source_oc = if self.inner.cfg.vendor.supports_oc_checksums() {
            meta.source_md5
                .as_deref()
                .map(|h| (HashKind::Md5, h))
                .or_else(|| meta.source_sha1.as_deref().map(|h| (HashKind::Sha1, h)))
        } else {
            None
        };
        if let Some((kind, hex)) = source_oc {
            let (_, val) = format_oc_checksum_header(kind, hex);
            headers.insert(
                HeaderName::from_static(OC_CHECKSUM),
                HeaderValue::from_str(&val)
                    .map_err(|e| Error::protocol(format!("invalid OC-Checksum: {e}")))?,
            );
        }

        let policy_cfg = self.control_retry_config(true);
        let dst_bp = BackendPath::new(&op.dst_raw_path, op.dst_nfc_path.clone(), None);
        let pre_op = Self::resolve_pre_op(op, Some(&meta));

        let outcome_res = self
            .execute_reconcile_control(
                "MOVE(chunked-v2-assemble)",
                &assemble_url,
                &policy_cfg,
                |active_assemble_url| {
                    self.build_control_request(
                        METHOD_MOVE.clone(),
                        active_assemble_url,
                        &headers,
                        Bytes::new(),
                    )
                },
                |resp: HttpResponse| {
                    if !resp.status.is_success()
                        && let Some((kind, expected_hex)) = source_oc
                        && is_checksum_rejection(resp.status, &resp.body)
                    {
                        let (algo, _) = format_oc_checksum_header(kind, expected_hex);
                        return PolicyDecision::Fail(checksum_mismatch_error(
                            "MOVE(chunked-v2-assemble) (rejected by server)",
                            algo,
                            expected_hex,
                            "server-computed value",
                        ));
                    }
                    dav_mutation_policy_decision("MOVE(chunked-v2-assemble)", resp, true, |r| {
                        MoveAssembleOutcome::Completed(r.headers)
                    })
                },
                |err, _| {
                    let staging_url = Self::ensure_trailing_slash(&meta.staging_url);
                    let dst_bp = dst_bp.clone();
                    let pre_op = pre_op.clone();
                    async move {
                        let src_exists = self
                            .propfind(&staging_url, "0", PROPFIND_ALL_BODY, true)
                            .await?
                            .is_some_and(|items| !items.is_empty());
                        if src_exists {
                            // Staging collection is still present -> assembly MOVE did not commit.
                            return Ok(ReconcileAction::Retry(err));
                        }
                        let Some(dst_entry) = self.stat(&dst_bp).await? else {
                            return Ok(ReconcileAction::Fail(err));
                        };
                        if dst_entry.kind != EntryKind::File {
                            return Ok(ReconcileAction::Fail(err));
                        }
                        let etag = dst_entry.etag.clone();
                        let mtime_tol = self.reconcile_mtime_tol(op, etag.as_deref());
                        match judge_reconciled_object(
                            op,
                            dst_entry,
                            etag.as_deref(),
                            &pre_op,
                            mtime_tol,
                            "WebDAV finish_upload",
                        ) {
                            ReconcileOutcome::Committed(committed) => {
                                Ok(ReconcileAction::Resolved(MoveAssembleOutcome::Reconciled(
                                    committed,
                                )))
                            }
                            _ => Ok(ReconcileAction::Fail(err)),
                        }
                    }
                },
            )
            .await;

        let outcome = match outcome_res {
            Ok(v) => v,
            Err(err) => {
                if err.kind == ErrorKind::PreconditionFailed
                    && err.message().contains("HTTP 409")
                    && let Some(parent) = op.dst_nfc_path.parent()
                {
                    self.evict_known_dir_chain(&parent);
                }
                return Err(err);
            }
        };

        match outcome {
            MoveAssembleOutcome::Reconciled(entry) => Ok(entry),
            MoveAssembleOutcome::Completed(resp_headers) => {
                let etag = resp_headers
                    .get(http::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(ToOwned::to_owned);
                let x_oc_mtime_accepted = resp_headers
                    .get(X_OC_MTIME)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.eq_ignore_ascii_case("accepted"));

                if (!sent_oc_mtime || !x_oc_mtime_accepted)
                    && let Ok(Some(mut actual)) = self.stat(&dst_bp).await
                {
                    if actual.etag.is_none() {
                        actual.etag = etag.clone();
                    }
                    return Ok(actual);
                }
                let mtime_ns = if sent_oc_mtime {
                    normalize_oc_mtime_ns(meta.src_mtime_ns)
                } else {
                    meta.src_mtime_ns
                };

                Ok(Entry {
                    node_id: None,
                    parent_id: None,
                    raw_path: raw_path_override(&op.dst_nfc_path, &op.dst_raw_path),
                    nfc_path: op.dst_nfc_path.clone(),
                    kind: EntryKind::File,
                    size: meta.total_size,
                    mtime_ns,
                    ctime_ns: None,
                    etag,
                    checksum: None,
                })
            }
        }
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        if let Some(staging_url) = op.session_token.as_deref() {
            let _ = self
                .delete_reconciled(
                    "DELETE(abort-chunked-v2)",
                    &Self::ensure_trailing_slash(staging_url),
                )
                .await;
        }
        Ok(())
    }

    fn resolve_pre_op(op: &OperationRecord, meta: Option<&WebdavSessionMeta>) -> PreOpState {
        match meta.map(|m| &m.pre_op) {
            Some(p) if !matches!(p, PreOpState::Unknown) => p.clone(),
            _ => PreOpState::from_precondition(&op.dst_precondition, |_, etag| etag.clone()),
        }
    }

    fn reconcile_mtime_tol(&self, op: &OperationRecord, etag: Option<&str>) -> Option<i64> {
        (etag.is_none() && self.inner.cfg.vendor.supports_oc_mtime() && op.src_version.mtime_ns > 0)
            .then_some(1_000_000_000)
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        // Proof: source size, a chunked-upload staging folder that is gone (the final MOVE
        // ran), and an ETag different from the planner's pre-op ETag (or a pre-op absence).
        // Size alone never proves a commit (see `common::reconcile`).
        let meta: Option<WebdavSessionMeta> = (!op.backend_meta.is_empty())
            .then(|| serde_json::from_str(&op.backend_meta).ok())
            .flatten();
        let staging_url = op
            .session_token
            .as_deref()
            .or_else(|| meta.as_ref().map(|m| m.staging_url.as_str()));
        if let Some(staging_url) = staging_url
            && self
                .propfind(
                    &Self::ensure_trailing_slash(staging_url),
                    "0",
                    PROPFIND_ALL_BODY,
                    true,
                )
                .await?
                .is_some_and(|items| !items.is_empty())
        {
            return Ok(ReconcileOutcome::NotCommitted);
        }
        let dst_raw = if op.dst_raw_path.is_empty() {
            op.dst_nfc_path.as_str()
        } else {
            op.dst_raw_path.as_str()
        };
        let bp = BackendPath::new(dst_raw, op.dst_nfc_path.clone(), None);
        let Some(entry) = self.stat(&bp).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };
        if entry.kind != EntryKind::File {
            return Ok(ReconcileOutcome::NotCommitted);
        }
        let pre_op = Self::resolve_pre_op(op, meta.as_ref());
        let etag = entry.etag.clone();
        let mtime_tol = self.reconcile_mtime_tol(op, etag.as_deref());
        Ok(judge_reconciled_object(
            op,
            entry,
            etag.as_deref(),
            &pre_op,
            mtime_tol,
            "WebDAV reconcile",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_sha1_matches_rfc3174_vectors() {
        let h_empty = StreamingSha1::new();
        assert_eq!(
            h_empty.finalize(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        let mut h_abc = StreamingSha1::new();
        h_abc.update(b"abc");
        assert_eq!(h_abc.finalize(), "a9993e364706816aba3e25717850c26c9cd0d89d");

        let mut h_multi = StreamingSha1::new();
        h_multi.update(b"abcdbcdecdefdefg");
        h_multi.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            h_multi.finalize(),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn parse_oc_checksum_supports_md5_and_sha1() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            OC_CHECKSUM,
            HeaderValue::from_static("SHA1:a9993e364706816aba3e25717850c26c9cd0d89d"),
        );
        assert_eq!(
            parse_oc_checksum(&hdrs),
            Some((
                HashKind::Sha1,
                "a9993e364706816aba3e25717850c26c9cd0d89d".to_string()
            ))
        );

        hdrs.insert(
            OC_CHECKSUM,
            HeaderValue::from_static(
                "SHA1:a9993e364706816aba3e25717850c26c9cd0d89d MD5:900150983cd24fb0d6963f7d28e17f72",
            ),
        );
        assert_eq!(
            parse_oc_checksum(&hdrs),
            Some((
                HashKind::Md5,
                "900150983cd24fb0d6963f7d28e17f72".to_string()
            ))
        );
    }

    #[test]
    fn streaming_sha1_nist_million_a_and_irregular_splits_and_512mib_bit_len() {
        // NIST / RFC 3174 1,000,000-byte `'a'` vector:
        const EXPECTED_MILLION_A: &str = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
        let million_a = vec![b'a'; 1_000_000];

        let mut single = StreamingSha1::new();
        single.update(&million_a);
        assert_eq!(single.finalize(), EXPECTED_MILLION_A);

        // Irregular chunk splits across buf_len boundaries (including empty slices).
        let split_pattern = [0usize, 1, 7, 63, 64, 65, 137, 4099, 65537];
        let mut split_hasher = StreamingSha1::new();
        let mut pos = 0usize;
        let mut step = 0usize;
        while pos < million_a.len() {
            let chunk_len = split_pattern[step % split_pattern.len()].min(million_a.len() - pos);
            split_hasher.update(&million_a[pos..pos + chunk_len]);
            pos += chunk_len;
            step += 1;
        }
        assert_eq!(split_hasher.finalize(), EXPECTED_MILLION_A);

        // Boundary sweep across 55/56/63/64/65/128/1MiB+13 comparing one-shot vs odd-split.
        for total in [
            0usize,
            1,
            54,
            55,
            56,
            57,
            63,
            64,
            65,
            119,
            120,
            127,
            128,
            129,
            1024 * 1024 + 13,
        ] {
            let payload: Vec<u8> = (0..total).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
            let mut h1 = StreamingSha1::new();
            h1.update(&payload);
            let d1 = h1.finalize();

            let mut h2 = StreamingSha1::new();
            let mut off = 0usize;
            let mut idx = 0usize;
            let chunks = [1usize, 3, 17, 64, 61, 131, 4093];
            while off < payload.len() {
                let n = chunks[idx % chunks.len()].min(payload.len() - off);
                h2.update(&payload[off..off + n]);
                off += n;
                idx += 1;
            }
            assert_eq!(h2.finalize(), d1, "split mismatch at len={total}");
        }

        // 512 MiB (2^32 bits) bit-length arithmetic: verify u64 bit_len encodes
        // `0x0000_0001_0000_0000` without 32-bit truncation.
        let mut h_512mib = StreamingSha1::new();
        h_512mib.total_bytes = 512 * 1024 * 1024;
        let digest_512mib = h_512mib.finalize();

        let mut expected_state = StreamingSha1::new().state;
        let mut block = [0u8; 64];
        block[0] = 0x80;
        block[56..64].copy_from_slice(&(512u64 * 1024 * 1024 * 8).to_be_bytes());
        StreamingSha1::compress(&mut expected_state, &block);
        let expected_hex: String = expected_state.iter().map(|w| format!("{w:08x}")).collect();
        assert_eq!(digest_512mib, expected_hex);
        assert_ne!(
            digest_512mib,
            StreamingSha1::new().finalize(),
            "512 MiB bit-length must not wrap to 0"
        );
    }

    #[tokio::test]
    async fn streaming_sha1_multi_mb_verifying_download_and_hash_stream() {
        use futures::StreamExt;

        let total_len = 1_048_593usize; // > 1 MiB, non-block-aligned
        let payload: Vec<u8> = (0..total_len)
            .map(|i| ((i * 17 + 3) & 0xff) as u8)
            .collect();
        let mut ref_sha1 = StreamingSha1::new();
        ref_sha1.update(&payload);
        let expected_hex = ref_sha1.finalize();

        let make_chunk_stream = |data: Vec<u8>| -> ByteStream {
            let chunk_sizes = [31usize, 4095, 65537, 17, 16384];
            let mut slices = Vec::new();
            let mut off = 0usize;
            let mut idx = 0usize;
            while off < data.len() {
                let n = chunk_sizes[idx % chunk_sizes.len()].min(data.len() - off);
                slices.push(Ok(Bytes::copy_from_slice(&data[off..off + n])));
                off += n;
                idx += 1;
            }
            Box::pin(futures::stream::iter(slices))
        };

        // 1. StreamingHashStream computes identical >1 MiB SHA-1 digest.
        let hash_slot = Arc::new(StdMutex::new(None));
        let mut hs = StreamingHashStream::new(
            make_chunk_stream(payload.clone()),
            StreamingSha1::new(),
            total_len as u64,
            hash_slot.clone(),
        );
        let mut collected = Vec::with_capacity(total_len);
        while let Some(item) = hs.next().await {
            collected.extend_from_slice(&item.unwrap());
        }
        assert_eq!(collected, payload);
        assert_eq!(
            lock_unpoisoned(&hash_slot).as_deref(),
            Some(expected_hex.as_str())
        );

        // 2. VerifyingDownloadStream passes on valid >1 MiB stream.
        let exact_ok = crate::common::ExactDownloadStream::new(
            "WebDAV",
            make_chunk_stream(payload.clone()),
            total_len as u64,
        );
        let mut vs_ok = VerifyingDownloadStream::new(
            "WebDAV",
            "SHA1",
            exact_ok,
            StreamingSha1::new(),
            total_len as u64,
            expected_hex.clone(),
        );
        let mut out_ok = Vec::with_capacity(total_len);
        while let Some(item) = vs_ok.next().await {
            out_ok.extend_from_slice(&item.unwrap());
        }
        assert_eq!(out_ok, payload);

        // 3. Single-bit flip mid-stream fails with ErrorKind::Integrity.
        let mut bad_payload = payload;
        bad_payload[total_len / 2] ^= 0x01;
        let exact_bad = crate::common::ExactDownloadStream::new(
            "WebDAV",
            make_chunk_stream(bad_payload),
            total_len as u64,
        );
        let mut vs_bad = VerifyingDownloadStream::new(
            "WebDAV",
            "SHA1",
            exact_bad,
            StreamingSha1::new(),
            total_len as u64,
            expected_hex,
        );
        let mut got_err = None;
        while let Some(item) = vs_bad.next().await {
            if let Err(e) = item {
                got_err = Some(e);
                break;
            }
        }
        let err = got_err.expect("1-bit corruption in >1 MiB SHA1 stream must fail");
        assert_eq!(err.kind, ErrorKind::Integrity);
    }
}
