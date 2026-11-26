//! Zero-RAM HTTP `Range` reader for Google Drive downloads and cloud-to-cloud relays.

use crate::common::http::bearer_header_value;
use crate::common::{
    ExactDownloadStream, StreamingDigest, StreamingMd5, VerifyingDownloadStream,
    checksum_mismatch_error, lock_unpoisoned,
};
use async_trait::async_trait;
use http::StatusCode;
use rship_core::source::{ByteStream, RemoteRangeReadable};
use rship_core::types::ByteRange;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use sha2::{Digest as _, Sha256};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex as TokioMutex, RwLock};

use crate::gdrive::error::classify_gdrive_error;
use crate::gdrive::query::SHORTCUT_MIME;

use super::GdriveBackend;

pub(super) struct GdriveSha256Hasher(Sha256);

impl GdriveSha256Hasher {
    pub(super) fn new() -> Self {
        Self(Sha256::new())
    }
}

impl StreamingDigest for GdriveSha256Hasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    fn finalize(self) -> String {
        let digest = self.0.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// Zero-RAM HTTP `Range` reader implementing [`RemoteRangeReadable`] for Google Drive
/// downloads and cloud-to-cloud relays.
pub(super) struct GdriveRangeReader {
    pub(super) backend: GdriveBackend,
    pub(super) file_id: RwLock<String>,
    pub(super) shortcut_resolve_lock: TokioMutex<()>,
    pub(super) resolved_shortcut: AtomicBool,
    pub(super) total_len: AtomicU64,
    pub(super) expected_md5: StdMutex<Option<String>>,
    pub(super) expected_sha256: StdMutex<Option<String>>,
}

#[async_trait]
impl RemoteRangeReadable for GdriveRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len.load(Ordering::Acquire)
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        let total_len = self.total_len.load(Ordering::Acquire);
        if range.len == 0 {
            if range.offset == 0 && total_len == 0 {
                if let Some(ref expected_sha256) = *lock_unpoisoned(&self.expected_sha256) {
                    let empty_sha256 = GdriveSha256Hasher::new().finalize();
                    if !empty_sha256.eq_ignore_ascii_case(expected_sha256) {
                        return Err(checksum_mismatch_error(
                            "GDrive download",
                            "SHA-256",
                            expected_sha256,
                            &empty_sha256,
                        ));
                    }
                } else if let Some(ref expected_md5) = *lock_unpoisoned(&self.expected_md5) {
                    let empty_md5 = StreamingMd5::new().finalize_hex();
                    if !empty_md5.eq_ignore_ascii_case(expected_md5) {
                        return Err(checksum_mismatch_error(
                            "GDrive download",
                            "MD5",
                            expected_md5,
                            &empty_md5,
                        ));
                    }
                }
            }
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("download ByteRange overflow"))?;
        if end_exclusive > total_len {
            return Err(Error::invalid_geometry(format!(
                "download range [{}..{}) exceeds file size {}",
                range.offset, end_exclusive, total_len
            )));
        }

        let range_hdr = format!("bytes={}-{}", range.offset, end_exclusive - 1);

        let mut auth_refreshed = false;
        let resp = loop {
            let cur_id = self.file_id.read().await.clone();
            let url_s = self.backend.api_url(
                &["files", &cur_id],
                &[("alt", "media"), ("supportsAllDrives", "true")],
            )?;

            self.backend.inner.data_limiter.acquire_send_permit().await;
            let token = self.backend.inner.auth.access_token().await?;
            let auth_hdr = bearer_header_value(&token)?;

            let watchdog = self.backend.inner.transport.data_watchdog();
            let req = self
                .backend
                .inner
                .transport
                .data_client()
                .get(&url_s)
                .header(http::header::AUTHORIZATION, auth_hdr)
                .header(http::header::RANGE, &range_hdr);
            let resp = self
                .backend
                .inner
                .transport
                .send_watched_request("gdrive open_range", req, &watchdog)
                .await?;

            if resp.status() == StatusCode::UNAUTHORIZED && !auth_refreshed {
                auth_refreshed = true;
                let _ = self.backend.inner.auth.force_refresh(&token).await?;
                continue;
            }
            let cur_total_len = self.total_len.load(Ordering::Acquire);
            if resp.status() == StatusCode::PARTIAL_CONTENT
                || (resp.status() == StatusCode::OK
                    && range.offset == 0
                    && range.len == cur_total_len)
            {
                self.backend.inner.data_limiter.record_success(false, false);
                break resp;
            }

            let status = resp.status();
            let headers = resp.headers().clone();
            let body = self.backend.inner.transport.read_data_body(resp).await?;

            if status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN {
                let _resolve_guard = self.shortcut_resolve_lock.lock().await;
                if *self.file_id.read().await != cur_id {
                    continue;
                }
                if !self.resolved_shortcut.load(Ordering::Acquire) {
                    if let Some(file) = self.backend.get_file_by_id(&cur_id).await? {
                        self.resolved_shortcut.store(true, Ordering::Release);
                        if file.mime_type == SHORTCUT_MIME {
                            let Some(target) = self.backend.resolve_shortcut_target(file).await?
                            else {
                                return Err(Error::new(
                                    ErrorKind::PermissionDenied,
                                    RetryClass::Permanent,
                                    format!(
                                        "gdrive shortcut `{cur_id}` target is inaccessible or broken"
                                    ),
                                ));
                            };
                            *self.file_id.write().await = target.id.clone();
                            if self.total_len.load(Ordering::Acquire) == 0 && target.size > 0 {
                                self.total_len.store(target.size, Ordering::Release);
                            }
                            if let Some(md5) = target
                                .md5_checksum
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                            {
                                let mut slot = lock_unpoisoned(&self.expected_md5);
                                if slot.is_none() {
                                    *slot = Some(md5.to_ascii_lowercase());
                                }
                            }
                            if let Some(sha256) = target
                                .sha256_checksum
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                            {
                                let mut slot = lock_unpoisoned(&self.expected_sha256);
                                if slot.is_none() {
                                    *slot = Some(sha256.to_ascii_lowercase());
                                }
                            }
                            continue;
                        }
                    } else {
                        self.resolved_shortcut.store(true, Ordering::Release);
                    }
                }
            }

            let err = classify_gdrive_error("gdrive open_range", status, &headers, &body, false);
            if err.retry == RetryClass::Throttled {
                self.backend.inner.data_limiter.record_throttle();
            }
            return Err(err);
        };

        let watched = self
            .backend
            .inner
            .transport
            .watch_response_stream("gdrive download stream", resp);
        let exact = ExactDownloadStream::new("GDrive", watched, range.len);
        let cur_total_len = self.total_len.load(Ordering::Acquire);
        if range.offset == 0 && range.len == cur_total_len {
            if let Some(expected_sha256) = lock_unpoisoned(&self.expected_sha256).clone() {
                return Ok(Box::pin(VerifyingDownloadStream::new(
                    "GDrive",
                    "SHA-256",
                    exact,
                    GdriveSha256Hasher::new(),
                    range.len,
                    expected_sha256,
                )));
            }
            if let Some(expected_md5) = lock_unpoisoned(&self.expected_md5).clone() {
                return Ok(Box::pin(VerifyingDownloadStream::new(
                    "GDrive",
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
