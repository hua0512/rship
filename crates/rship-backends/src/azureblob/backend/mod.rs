//! Azure Blob Storage REST API (`2023-11-03`) [`StorageBackend`] implementation.

mod ops;
mod transfer;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, OrderedListPage,
    ReconcileOutcome, StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::clock::{Clock, SystemClock};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter, parse_retry_after};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crate::azureblob::auth::AzureAuth;
use crate::azureblob::config::{
    AZURE_MAX_BLOCK_BYTES, AZURE_MAX_BLOCKS, AZURE_MAX_OBJECT_BYTES, AZURE_MIN_BLOCK_BYTES,
    AzureBlobConfig, append_rfc3986_query,
};
use crate::azureblob::xml::{normalize_azure_etag, parse_azure_error_xml, parse_list_blobs};
use crate::common::BoundedSessionMap;
use crate::common::http::{
    Idempotency, PolicyDecision, ReconcileAction, classify_common_http_status,
    execute_with_reconcile_policy,
};

pub use transfer::{make_block_id_b64, parse_block_id_part};

const HDR_META_MTIME: &str = "x-ms-meta-mtime";
const HDR_META_MTIME_LEGACY: &str = "x-ms-meta-rship_mtime_ns";
const META_KEY_MTIME: &str = "mtime";
const META_KEY_MTIME_LEGACY: &str = "rship_mtime_ns";
const HDR_META_OP_ID: &str = "x-ms-meta-rship_op_id";
/// 256 KiB per semaphore unit => 256 units = 64 MiB bounded RAM budget for `PutBlock` MD5 & reorder window.
const BLOCK_MD5_UNIT_BYTES: u64 = 256 * 1024;
const BLOCK_MD5_BUDGET_UNITS: usize = 256;
const MAX_BLOCK_MD5_BYTES: u64 = 16 * 1024 * 1024;

struct ControlRequestOpts {
    request_timeout: Option<Duration>,
    allow_not_found: bool,
}

type ControlResponse = (StatusCode, HeaderMap, Bytes);

struct AzureInner {
    cfg: AzureBlobConfig,
    auth: AzureAuth,
    transport: HttpTransport,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    clock: Arc<dyn Clock>,
    /// Whole-blob MD5 of in-progress block uploads, keyed by op id (see
    /// [`transfer::OrderedBlobMd5`]), bounded by capacity and TTL.
    blob_md5: StdMutex<BoundedSessionMap<String, transfer::OrderedBlobMd5>>,
    /// Global bounded memory budget for `PutBlock` request `Content-MD5` computation and
    /// bounded out-of-order block buffering (`BLOCK_MD5_BUDGET_UNITS * 256 KiB = 64 MiB`).
    block_md5_mem_budget: Arc<tokio::sync::Semaphore>,
}

impl AzureInner {
    fn now_utc(&self) -> rship_core::time::Timestamp {
        rship_core::time::Timestamp::from_second(self.clock.now_unix_secs())
            .unwrap_or_else(|_| rship_core::time::Timestamp::now())
    }
}

#[derive(Clone)]
pub struct AzureBlobBackend {
    inner: Arc<AzureInner>,
}

impl AzureBlobBackend {
    pub fn new(
        cfg: AzureBlobConfig,
        auth: AzureAuth,
        transport: HttpTransport,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<Self> {
        if cfg.container.trim().is_empty() {
            return Err(Error::protocol(
                "Azure Blob container name must not be empty",
            ));
        }
        let scope = LimiterScope::new(&cfg.remote_name, auth.principal(&cfg.account));
        let rate_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), rate_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, rate_cfg);
        Ok(Self {
            inner: Arc::new(AzureInner {
                cfg,
                auth,
                transport,
                control_limiter,
                data_limiter,
                clock: clock.unwrap_or_else(SystemClock::shared),
                blob_md5: StdMutex::new(BoundedSessionMap::new(
                    1024,
                    Duration::from_secs(6 * 3600),
                )),
                block_md5_mem_budget: Arc::new(tokio::sync::Semaphore::new(BLOCK_MD5_BUDGET_UNITS)),
            }),
        })
    }

    pub fn control_limiter(&self) -> Arc<ScopedLimiter> {
        self.inner.control_limiter.clone()
    }

    pub fn data_limiter(&self) -> Arc<ScopedLimiter> {
        self.inner.data_limiter.clone()
    }

    fn now_utc(&self) -> rship_core::time::Timestamp {
        self.inner.now_utc()
    }

    /// Execute an authenticated Azure Blob control-plane request through the shared
    /// retry/rate-limit policy engine.
    async fn control_request(
        &self,
        context: &str,
        method: Method,
        raw_url: &str,
        base_headers: HeaderMap,
        body: Option<Bytes>,
        allow_not_found: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.execute_control_request(
            context,
            method,
            raw_url,
            base_headers,
            body,
            ControlRequestOpts {
                request_timeout: None,
                allow_not_found,
            },
        )
        .await
    }

    async fn execute_control_request(
        &self,
        context: &str,
        method: Method,
        raw_url: &str,
        base_headers: HeaderMap,
        body: Option<Bytes>,
        opts: ControlRequestOpts,
    ) -> Result<ControlResponse> {
        self.execute_control_request_with(
            context,
            method,
            raw_url,
            base_headers,
            body,
            opts,
            Idempotency::Idempotent,
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
    }

    /// Execute a NON-idempotent commit (`Put Block List` / `Copy Blob` with
    /// `If-None-Match: *`) on the long control timeout. Ambiguous failures and the
    /// `409 BlobAlreadyExists` / `412` a replay gets after a lost response go through
    /// `reconcile`, which must prove the blob is ours (op-id metadata) before resolving.
    async fn long_control_commit<RecFn, RecFut>(
        &self,
        context: &str,
        raw_url: &str,
        base_headers: HeaderMap,
        body: Bytes,
        allow_not_found: bool,
        reconcile: RecFn,
    ) -> Result<ControlResponse>
    where
        RecFn: FnMut(Error) -> RecFut,
        RecFut: Future<Output = Result<ReconcileAction<ControlResponse>>>,
    {
        self.execute_control_request_with(
            context,
            Method::PUT,
            raw_url,
            base_headers,
            Some(body),
            ControlRequestOpts {
                request_timeout: Some(self.inner.transport.config().long_control_timeout),
                allow_not_found,
            },
            Idempotency::NonIdempotent,
            reconcile,
        )
        .await
    }

    /// `HEAD` the blob and resolve a reconcile when its `rship_op_id` metadata proves the
    /// committed blob was written by `op_id` (and, when given, has `expected_size` bytes).
    async fn reconcile_commit_by_op_id(
        &self,
        full_key: &str,
        op_id: &str,
        expected_size: Option<u64>,
        allow_pending_copy: bool,
        err: Error,
    ) -> Result<ReconcileAction<ControlResponse>> {
        let Some(headers) = self.head_blob(full_key).await? else {
            if matches!(
                err.kind,
                ErrorKind::PreconditionFailed | ErrorKind::Unsupported | ErrorKind::SourceMutated
            ) {
                return Ok(ReconcileAction::Fail(err));
            }
            return Ok(ReconcileAction::Retry(err));
        };
        let ours = headers
            .get(HDR_META_OP_ID)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == op_id);
        let size = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let copy_status = headers
            .get("x-ms-copy-status")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase());
        if ours && matches!(copy_status.as_deref(), Some("failed") | Some("aborted")) {
            return Ok(ReconcileAction::Fail(Error::protocol(format!(
                "Azure CopyBlob for op `{op_id}` ended in status `{}`",
                copy_status.as_deref().unwrap_or("unknown")
            ))));
        }
        let pending_copy = copy_status.as_deref() == Some("pending");
        let copy_ok = allow_pending_copy || !pending_copy;
        let size_ok = expected_size
            .is_none_or(|want| (allow_pending_copy && pending_copy) || size == Some(want));
        if ours && copy_ok && size_ok {
            return Ok(ReconcileAction::Resolved((
                StatusCode::OK,
                headers,
                Bytes::new(),
            )));
        }
        if matches!(
            err.kind,
            ErrorKind::Conflict
                | ErrorKind::PreconditionFailed
                | ErrorKind::Unsupported
                | ErrorKind::SourceMutated
        ) {
            // Another writer's blob or a permanent precondition/type/source mismatch.
            return Ok(ReconcileAction::Fail(err));
        }
        Ok(ReconcileAction::Retry(err))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_control_request_with<RecFn, RecFut>(
        &self,
        context: &str,
        method: Method,
        raw_url: &str,
        base_headers: HeaderMap,
        body: Option<Bytes>,
        opts: ControlRequestOpts,
        idempotency: Idempotency,
        reconcile: RecFn,
    ) -> Result<ControlResponse>
    where
        RecFn: FnMut(Error) -> RecFut,
        RecFut: Future<Output = Result<ReconcileAction<ControlResponse>>>,
    {
        let final_url = self.inner.auth.apply_url(raw_url);
        let mut policy_cfg = self
            .inner
            .cfg
            .retry_policy()
            .with_skip_response_body(method == Method::HEAD);
        if let Some(timeout) = opts.request_timeout {
            policy_cfg = policy_cfg.with_request_timeout(timeout);
        }

        execute_with_reconcile_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            idempotency,
            || {
                let mut headers = base_headers.clone();
                let method = method.clone();
                let final_url = final_url.clone();
                let body = body.clone();
                let auth = &self.inner.auth;
                let client = self.inner.transport.control_client();
                let now = self.now_utc();
                let built = (|| -> Result<reqwest::RequestBuilder> {
                    if let Some(b) = &body {
                        headers.insert(
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&b.len().to_string())
                                .map_err(|e| Error::protocol(format!("content-length: {e}")))?,
                        );
                    }
                    auth.sign_headers(&method, &final_url, &mut headers, now)?;
                    let mut req = client.request(method, &final_url).headers(headers);
                    if let Some(b) = body {
                        req = req.body(b);
                    }
                    Ok(req)
                })();
                async move { built }
            },
            |resp| {
                if resp.status.is_success()
                    || (opts.allow_not_found && resp.status == StatusCode::NOT_FOUND)
                {
                    return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                }
                let err = map_azure_http_error_with_headers(
                    context,
                    resp.status,
                    Some(&resp.headers),
                    &resp.body,
                );
                if idempotency == Idempotency::NonIdempotent
                    && matches!(
                        resp.status,
                        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED
                    )
                    && matches!(
                        err.kind,
                        ErrorKind::Conflict | ErrorKind::PreconditionFailed
                    )
                {
                    // A replay after a lost response sees our own blob: reconcile.
                    return PolicyDecision::Reconcile(err);
                }
                PolicyDecision::from_error(err)
            },
            reconcile,
        )
        .await
    }

    async fn head_blob(&self, full_key: &str) -> Result<Option<HeaderMap>> {
        let url = self.inner.cfg.blob_url(full_key);
        let (status, headers, _) = self
            .control_request(
                "Azure HEAD blob",
                Method::HEAD,
                &url,
                HeaderMap::new(),
                None,
                true,
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(headers))
    }

    async fn has_prefix(&self, dir_prefix: &str) -> Result<bool> {
        let url = append_rfc3986_query(
            &self.inner.cfg.container_url(),
            &[
                ("restype", "container"),
                ("comp", "list"),
                ("prefix", dir_prefix),
                ("maxresults", "1"),
            ],
        );
        let (status, _, body) = self
            .control_request(
                "Azure stat prefix",
                Method::GET,
                &url,
                HeaderMap::new(),
                None,
                true,
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let page = parse_list_blobs(&body)?;
        Ok(!page.blobs.is_empty() || !page.prefixes.is_empty())
    }

    fn insert_access_tier_header(&self, headers: &mut HeaderMap) -> Result<()> {
        if let Some(tier) = &self.inner.cfg.access_tier
            && !tier.trim().is_empty()
        {
            headers.insert(
                http::header::HeaderName::from_static("x-ms-access-tier"),
                HeaderValue::from_str(tier.trim())
                    .map_err(|e| Error::protocol(format!("access-tier header: {e}")))?,
            );
        }
        Ok(())
    }

    fn headers_to_entry(&self, raw_rel: &str, headers: &HeaderMap) -> Result<Entry> {
        let is_dir = raw_rel.ends_with('/')
            || headers
                .get("x-ms-resource-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("directory"))
            || headers
                .get("x-ms-meta-hdi_isfolder")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
        let normalized_raw = if is_dir {
            raw_rel.trim_end_matches('/')
        } else {
            raw_rel
        };
        let nfc_path = RelPath::parse(normalized_raw)?;
        let size = if is_dir {
            0
        } else {
            headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        let mtime_ns = parse_azure_mtime_ns(
            headers.get(HDR_META_MTIME).and_then(|v| v.to_str().ok()),
            headers
                .get(HDR_META_MTIME_LEGACY)
                .and_then(|v| v.to_str().ok()),
            headers
                .get(http::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok()),
        );
        let etag = headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_azure_etag);
        let checksum = if is_dir {
            None
        } else {
            headers
                .get("content-md5")
                .and_then(|v| v.to_str().ok())
                .and_then(decode_md5_b64)
        };

        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&nfc_path, normalized_raw),
            nfc_path,
            kind: if is_dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            size,
            mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        })
    }

    fn parse_src_container_and_prefix<'a>(
        &self,
        src_endpoint: &'a str,
    ) -> Option<(&'a str, &'a str)> {
        let expected = format!("azureblob://{}/", self.inner.cfg.effective_endpoint());
        let rest = src_endpoint.strip_prefix(&expected)?;
        match rest.split_once('/') {
            Some((container, pfx)) if !container.is_empty() => Some((container, pfx)),
            None if !rest.is_empty() => Some((rest, "")),
            _ => None,
        }
    }
}

/// Format Unix nanoseconds in rclone `azureblob` RFC3339Nano UTC (`YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`).
pub(super) fn format_azure_mtime(ns: i64) -> String {
    let base = rship_core::time::format_rfc3339(ns);
    let stem = base.strip_suffix("+00:00").unwrap_or(&base);
    if let Some((sec_part, frac)) = stem.split_once('.') {
        format!("{sec_part}.{frac:0<9}Z")
    } else {
        format!("{stem}.000000000Z")
    }
}

/// Parse an `x-ms-meta-mtime` value (rclone RFC3339/RFC3339Nano, or Unix epoch seconds float/int).
pub(super) fn parse_azure_mtime_value(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(ns) = rship_core::time::parse_rfc3339_to_nanos(trimmed) {
        return Some(ns);
    }
    // Fallback: Unix epoch seconds as integer or decimal float (e.g. "1700000000.123456789").
    let (neg, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let (sec_str, frac_str) = body.split_once('.').unwrap_or((body, ""));
    if sec_str.is_empty() || !sec_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !frac_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs: i64 = sec_str.parse().ok()?;
    let mut frac_buf = [b'0'; 9];
    for (dst, &src) in frac_buf.iter_mut().zip(frac_str.as_bytes()) {
        *dst = src;
    }
    let frac_ns: i64 = std::str::from_utf8(&frac_buf).ok()?.parse().ok()?;
    let mag = secs.checked_mul(1_000_000_000)?.checked_add(frac_ns)?;
    if neg { mag.checked_neg() } else { Some(mag) }
}

/// Resolve blob mtime with dual-read precedence:
/// `x-ms-meta-mtime` -> legacy `x-ms-meta-rship_mtime_ns` -> `Last-Modified` -> `0`.
pub(super) fn parse_azure_mtime_ns(
    mtime: Option<&str>,
    legacy_ns: Option<&str>,
    last_modified: Option<&str>,
) -> i64 {
    mtime
        .and_then(parse_azure_mtime_value)
        .or_else(|| legacy_ns.and_then(|s| s.trim().parse::<i64>().ok()))
        .or_else(|| last_modified.and_then(parse_http_date_ns))
        .unwrap_or(0)
}

pub(super) fn insert_write_precondition_header(
    precondition: &DstPrecondition,
    headers: &mut HeaderMap,
) -> Result<()> {
    match precondition {
        DstPrecondition::Any => Ok(()),
        DstPrecondition::Absent => {
            headers.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("*"));
            Ok(())
        }
        DstPrecondition::Existing { etag, .. } => {
            if let Some(etag) = etag
                && !etag.trim().is_empty()
            {
                headers.insert(
                    http::header::IF_MATCH,
                    HeaderValue::from_str(etag.trim())
                        .map_err(|e| Error::protocol(format!("If-Match header: {e}")))?,
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn decode_md5_b64(raw: &str) -> Option<Checksum> {
    let bytes = B64.decode(raw.trim()).ok()?;
    (bytes.len() == 16).then(|| Checksum {
        kind: HashKind::Md5,
        hex: hex::encode(bytes),
    })
}

fn parse_http_date_ns(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    rship_core::time::parse_http_date_to_nanos(raw)
        .or_else(|| rship_core::time::parse_rfc3339_to_nanos(raw))
}

fn map_azure_http_error_with_headers(
    context: &str,
    status: StatusCode,
    headers: Option<&HeaderMap>,
    body: &[u8],
) -> Error {
    let xml_err = parse_azure_error_xml(body);
    let header_code = headers
        .and_then(|h| h.get("x-ms-error-code"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let error_code = xml_err.as_ref().map(|(c, _)| c.as_str()).or(header_code);
    let detail = if let Some((ref code, ref msg)) = xml_err {
        format!("{code}: {msg}")
    } else if let Some(code) = header_code {
        code.to_string()
    } else {
        let s = String::from_utf8_lossy(body);
        s.trim().chars().take(240).collect()
    };
    let msg = if detail.is_empty() {
        format!("{context} failed with HTTP {}", status.as_u16())
    } else {
        format!("{context} failed with HTTP {}: {detail}", status.as_u16())
    };
    let retry_after = headers.and_then(parse_retry_after);
    let is_throttle_code = matches!(
        error_code,
        Some(
            "ServerBusy"
                | "TooManyRequests"
                | "IngressLimitExceeded"
                | "EgressLimitExceeded"
                | "OperationsPerSecondLimitExceeded"
        )
    );
    let empty_headers = HeaderMap::new();
    let mut err = match status.as_u16() {
        401 | 403 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg),
        404 => Error::new(ErrorKind::NotFound, RetryClass::Permanent, msg),
        429 | 503 => Error::rate_limited(msg, retry_after),
        _ if is_throttle_code => Error::rate_limited(msg, retry_after),
        400 if error_code == Some("Md5Mismatch") => Error::integrity(msg),
        409 => match error_code {
            Some("BlobArchived") => Error::new(
                ErrorKind::Unsupported,
                RetryClass::Permanent,
                format!("{msg} (blob is in Archive tier; rehydrate before reading/copying)"),
            ),
            Some("InvalidBlobType") => Error::new(
                ErrorKind::Conflict,
                RetryClass::Permanent,
                format!("{msg} (destination blob type is incompatible with BlockBlob operation)"),
            ),
            _ => Error::new(ErrorKind::Conflict, RetryClass::Permanent, msg),
        },
        412 => match error_code {
            Some("SourceConditionNotMet") => Error::source_mutated(msg),
            _ => Error::precondition_failed(msg),
        },
        408 | 500..=599 => {
            if let Some(common_err) = classify_common_http_status(
                context,
                status,
                headers.unwrap_or(&empty_headers),
                &detail,
            ) {
                common_err
            } else {
                Error::new(ErrorKind::Network, RetryClass::Retryable, msg)
            }
        }
        400..=499 => Error::new(ErrorKind::Protocol, RetryClass::Permanent, msg),
        _ => Error::new(ErrorKind::Protocol, RetryClass::Permanent, msg),
    };
    if let Some(ra) = retry_after
        && err.retry_after.is_none()
    {
        err = err.with_retry_after(ra);
    }
    err
}

#[async_trait]
impl StorageBackend for AzureBlobBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "azureblob"
    }

    fn endpoint_identity(&self) -> String {
        let pfx = self.inner.cfg.prefix.trim_matches('/');
        if pfx.is_empty() {
            format!(
                "azureblob://{}/{}",
                self.inner.cfg.effective_endpoint(),
                self.inner.cfg.container
            )
        } else {
            format!(
                "azureblob://{}/{}/{}",
                self.inner.cfg.effective_endpoint(),
                self.inner.cfg.container,
                pfx
            )
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![HashKind::Md5],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                min_bytes: AZURE_MIN_BLOCK_BYTES,
                max_bytes: AZURE_MAX_BLOCK_BYTES,
                max_parts: AZURE_MAX_BLOCKS,
                max_object_bytes: AZURE_MAX_OBJECT_BYTES,
                require_equal_non_final_parts: false,
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self
                .inner
                .cfg
                .block_size
                .clamp(AZURE_MIN_BLOCK_BYTES, AZURE_MAX_BLOCK_BYTES),
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: true,
            supports_ordered_utf8_list: false,
            supports_conditional_write: true,
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

    async fn list_ordered_page(
        &self,
        prefix: &RelPath,
        start_after: Option<&str>,
        continuation: Option<&str>,
        max_keys: u32,
    ) -> Result<OrderedListPage> {
        self.list_ordered_page_impl(prefix, start_after, continuation, max_keys)
            .await
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        self.mkdir_impl(path).await
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.delete_impl(path).await
    }

    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.compute_hash_impl(path, kind).await
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderName;

    #[test]
    fn golden_last_modified_parses_rfc1123_and_rfc3339() {
        let want = Some(1_795_640_709_000_000_000);
        assert_eq!(parse_http_date_ns("Wed, 25 Nov 2026 21:05:09 GMT"), want);
        assert_eq!(
            parse_http_date_ns("  Wed, 25 Nov 2026 21:05:09 GMT \n"),
            want
        );
        assert_eq!(parse_http_date_ns("2026-11-25T21:05:09Z"), want);
        assert_eq!(
            parse_http_date_ns("2026-11-25T21:05:09.1234567Z"),
            Some(1_795_640_709_123_456_700)
        );
        assert_eq!(parse_http_date_ns("nope"), None);
    }

    #[test]
    fn block_ids_are_equal_length_and_roundtrip_part_number() {
        let id1 = make_block_id_b64("op-abc-12345", 1);
        let id99 = make_block_id_b64("op-abc-12345", 9999);
        assert_eq!(id1.len(), id99.len());
        assert_eq!(parse_block_id_part(&id1, "op-abc-12345"), Some(1));
        assert_eq!(parse_block_id_part(&id99, "op-abc-12345"), Some(9999));
        assert_eq!(parse_block_id_part(&id1, "other-op"), None);
    }

    #[test]
    fn classifies_429_and_503_as_throttled_and_other_5xx_as_retryable_only() {
        let mut hdrs_429 = HeaderMap::new();
        hdrs_429.insert(http::header::RETRY_AFTER, HeaderValue::from_static("7"));
        let e429 = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::TOO_MANY_REQUESTS,
            Some(&hdrs_429),
            b"",
        );
        assert_eq!(e429.kind, ErrorKind::RateLimited);
        assert_eq!(e429.retry, RetryClass::Throttled);
        assert!(e429.is_throttled());
        assert_eq!(e429.retry_after, Some(Duration::from_secs(7)));

        let e503 = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            b"<Error><Code>ServerBusy</Code><Message>busy</Message></Error>",
        );
        assert_eq!(e503.kind, ErrorKind::RateLimited);
        assert_eq!(e503.retry, RetryClass::Throttled);
        assert!(e503.is_throttled());

        let mut head_503 = HeaderMap::new();
        head_503.insert(
            HeaderName::from_static("x-ms-error-code"),
            HeaderValue::from_static("ServerBusy"),
        );
        let e503_head = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::SERVICE_UNAVAILABLE,
            Some(&head_503),
            b"",
        );
        assert!(e503_head.is_throttled());
        assert!(e503_head.message().contains("ServerBusy"));

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = map_azure_http_error_with_headers(
                "ctx",
                status,
                None,
                b"<Error><Code>InternalError</Code><Message>transient</Message></Error>",
            );
            assert_eq!(err.kind, ErrorKind::Network, "status={status}");
            assert_eq!(err.retry, RetryClass::Retryable, "status={status}");
            assert!(!err.is_throttled(), "status={status} must NOT trip CUBIC");
        }

        let e408 = map_azure_http_error_with_headers("ctx", StatusCode::REQUEST_TIMEOUT, None, b"");
        assert_eq!(e408.kind, ErrorKind::Timeout);
        assert_eq!(e408.retry, RetryClass::Retryable);
        assert!(!e408.is_throttled());
    }

    #[test]
    fn block_ids_resist_long_prefix_collisions_and_have_fixed_length() {
        let a = make_block_id_b64("op-20261127080000-fileA", 1);
        let b = make_block_id_b64("op-20261127080000-fileB", 1);
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
        assert_eq!(
            make_block_id_b64("op-20261127080000-fileA", 50_000).len(),
            a.len()
        );
        assert_eq!(parse_block_id_part(&a, "op-20261127080000-fileA"), Some(1));
        assert_eq!(parse_block_id_part(&a, "op-20261127080000-fileB"), None);
    }

    #[test]
    fn mtime_formats_rfc3339_nano_and_dual_reads_rclone_legacy_and_last_modified() {
        let ns = 1_700_000_000_123_456_789_i64;
        let formatted = format_azure_mtime(ns);
        assert_eq!(formatted, "2023-11-14T22:13:20.123456789Z");
        assert_eq!(format_azure_mtime(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            format_azure_mtime(1_700_000_000_120_000_000),
            "2023-11-14T22:13:20.120000000Z"
        );

        assert_eq!(
            parse_azure_mtime_ns(
                Some(&formatted),
                Some("1700000005000000000"),
                Some("Wed, 25 Nov 2026 21:05:09 GMT")
            ),
            ns
        );
        // Unix float fallback in x-ms-meta-mtime
        assert_eq!(
            parse_azure_mtime_ns(Some("1700000000.123456789"), None, None),
            1_700_000_000_123_456_789
        );
        assert_eq!(
            parse_azure_mtime_ns(Some("1700000000"), None, None),
            1_700_000_000_000_000_000
        );
        // Legacy fallback
        assert_eq!(
            parse_azure_mtime_ns(
                None,
                Some("1700000005000000000"),
                Some("Wed, 25 Nov 2026 21:05:09 GMT")
            ),
            1_700_000_005_000_000_000
        );
        // Last-Modified fallback
        assert_eq!(
            parse_azure_mtime_ns(None, None, Some("Wed, 25 Nov 2026 21:05:09 GMT")),
            1_795_640_709_000_000_000
        );
    }

    #[test]
    fn maps_412_409_and_md5_mismatch_and_reports_capabilities() {
        let e412 = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::PRECONDITION_FAILED,
            None,
            b"<Error><Code>ConditionNotMet</Code><Message>mismatch</Message></Error>",
        );
        assert_eq!(e412.kind, ErrorKind::PreconditionFailed);

        let e_src_412 = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::PRECONDITION_FAILED,
            None,
            b"<Error><Code>SourceConditionNotMet</Code><Message>src changed</Message></Error>",
        );
        assert_eq!(e_src_412.kind, ErrorKind::SourceMutated);

        let e_arch = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::CONFLICT,
            None,
            b"<Error><Code>BlobArchived</Code><Message>archived</Message></Error>",
        );
        assert_eq!(e_arch.kind, ErrorKind::Unsupported);

        let e_type = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::CONFLICT,
            None,
            b"<Error><Code>InvalidBlobType</Code><Message>page blob</Message></Error>",
        );
        assert_eq!(e_type.kind, ErrorKind::Conflict);
        assert!(e_type.message().contains("BlockBlob"));

        let e_md5 = map_azure_http_error_with_headers(
            "ctx",
            StatusCode::BAD_REQUEST,
            None,
            b"<Error><Code>Md5Mismatch</Code><Message>bad md5</Message></Error>",
        );
        assert_eq!(e_md5.kind, ErrorKind::Integrity);

        let cfg = AzureBlobConfig::new("az", "acct", "cont");
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let backend = AzureBlobBackend::new(cfg, AzureAuth::Anonymous, transport, None).unwrap();
        let caps = backend.capabilities();
        assert!(!caps.supports_ordered_utf8_list);
        match caps.chunk_alignment {
            ChunkAlignment::MinSizeWithMaxParts {
                max_bytes,
                max_object_bytes,
                ..
            } => {
                assert_eq!(max_bytes, AZURE_MAX_BLOCK_BYTES);
                assert_eq!(max_object_bytes, AZURE_MAX_OBJECT_BYTES);
            }
            other => panic!("unexpected alignment: {other:?}"),
        }
    }
}
