//! Production S3-compatible [`StorageBackend`] implementation covering AWS S3,
//! Cloudflare R2, MinIO, Alibaba OSS, Backblaze B2, and generic S3 endpoints.

mod copy;
mod listing;
mod streams;
mod upload;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::clock::{Clock, SystemClock};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{ByteRange, Capabilities, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use url::Url;

use crate::common::http::{
    HttpResponse, Idempotency, PolicyDecision, ReconcileAction, RetryPolicyConfig,
    execute_with_auth_policy, execute_with_policy_full, send_watched_sized_upload_with_capture,
    sensitive_header_value,
};
use crate::common::{StreamingHashStream, StrictBodyStream, lock_unpoisoned};
use crate::s3::config::{S3Config, S3ServerSideEncryption, infer_content_type};
use crate::s3::credentials::{S3CredentialProvider, S3CredentialSource};
use crate::s3::error::{classify_s3_error, is_expired_token_error};
use crate::s3::provider::ProviderProfile;
use crate::s3::sigv4::{
    EMPTY_SHA256_HEX, UNSIGNED_PAYLOAD, aws_uri_encode, aws_uri_encode_path, build_canonical_query,
    sha256_hex, sign_v4_request,
};
use crate::s3::xml::{parse_list_objects_v2, parse_s3_error_xml, parse_s3_server_time_xml};
use base64::Engine as _;
use md5::{Digest as _, Md5};
use std::sync::atomic::{AtomicI64, Ordering};

use streams::{
    PreparedUpload, S3StreamUploadDigests, S3StreamUploadHasher,
    extract_verified_checksum_from_headers, insert_upload_checksum_header, parse_http_date_nanos,
    prepare_hashed_upload, prepare_in_memory_checksum_upload, prepare_required_checksum_upload,
    verify_s3_upload_response_checksums,
};

pub(super) const IN_MEM_STRICT_HASH_CAP: u64 = 4 * 1024 * 1024;
/// Total concurrent in-memory strict-SigV4 buffer budget (16 MiB in 64 KiB units)
/// so high concurrency spills excess strict-hashed uploads to disk instead of blowing RSS.
pub(super) const STRICT_HASH_MEM_UNIT: u64 = 64 * 1024;
const STRICT_HASH_MEM_BUDGET_UNITS: usize = (16 * 1024 * 1024 / STRICT_HASH_MEM_UNIT) as usize;
pub(super) const META_OP_ID: &str = "x-amz-meta-rship-op-id";
pub(super) const META_MTIME_NS: &str = "x-amz-meta-rship-mtime-ns";
pub(super) const META_SHA256: &str = "x-amz-meta-rship-sha256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartUploadInfo {
    pub key: String,
    pub upload_id: String,
    pub initiated: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct S3SessionMeta {
    key: String,
    total_size: u64,
    planned_chunk_size: u64,
    op_id: String,
    src_mtime_ns: i64,
    #[serde(default)]
    send_part_checksum_header: bool,
    /// Algorithm passed as `x-amz-checksum-algorithm` on `CreateMultipartUpload`. Every
    /// `UploadPart` must send this algorithm's checksum (S3 rejects any other with "Checksum
    /// Type mismatch"), and `CompleteMultipartUpload` must list it for each part when the
    /// checksum type is COMPOSITE (CRC32C). `None` in journals written before this field
    /// existed; see [`S3Backend::session_part_checksum_kind`].
    #[serde(default)]
    part_checksum_algorithm: Option<HashKind>,
    #[serde(default)]
    expected_checksums: Vec<Checksum>,
}

/// S3-compatible storage backend.
#[derive(Clone)]
pub struct S3Backend {
    inner: Arc<S3Inner>,
}

struct S3Inner {
    cfg: S3Config,
    profile: ProviderProfile,
    transport: HttpTransport,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    clock: Arc<dyn Clock>,
    clock_offset_secs: AtomicI64,
    bucket_prefix_with_slash: String,
    creds: Arc<S3CredentialProvider>,
    strict_hash_mem_budget: Arc<tokio::sync::Semaphore>,
}

impl S3Backend {
    pub fn new(
        cfg: S3Config,
        transport: HttpTransport,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<Self> {
        if cfg.bucket.trim().is_empty() {
            return Err(Error::invalid_path("S3 bucket name cannot be empty"));
        }
        let profile = cfg.provider.profile();
        let clock = clock.unwrap_or_else(SystemClock::shared);
        let cred_source = cfg
            .credential_source
            .clone()
            .unwrap_or_else(|| S3CredentialSource::Static(cfg.credentials.clone()));
        let creds = Arc::new(S3CredentialProvider::new(
            cred_source,
            transport.clone(),
            clock.clone(),
        ));
        let scope = LimiterScope::new(
            &cfg.remote_name,
            format!("{}:{}", creds.scope_label(), cfg.bucket),
        );
        let limiter_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), limiter_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, limiter_cfg);
        let norm_prefix = cfg.normalized_prefix();
        let bucket_prefix_with_slash = if norm_prefix.is_empty() {
            String::new()
        } else {
            format!("{norm_prefix}/")
        };

        Ok(Self {
            inner: Arc::new(S3Inner {
                cfg,
                profile,
                transport,
                control_limiter,
                data_limiter,
                clock,
                clock_offset_secs: AtomicI64::new(0),
                bucket_prefix_with_slash,
                creds,
                strict_hash_mem_budget: Arc::new(tokio::sync::Semaphore::new(
                    STRICT_HASH_MEM_BUDGET_UNITS,
                )),
            }),
        })
    }

    pub(super) fn is_non_md5_sse(&self) -> bool {
        self.inner.cfg.is_non_md5_sse()
    }

    pub(super) fn effective_unix_secs(&self) -> i64 {
        self.inner
            .clock
            .now_unix_secs()
            .saturating_add(self.inner.clock_offset_secs.load(Ordering::Relaxed))
    }

    pub(super) fn maybe_adjust_clock_skew(&self, headers: &HeaderMap, body: &[u8]) -> bool {
        let Some(xml_err) = parse_s3_error_xml(body) else {
            return false;
        };
        if xml_err.code != "RequestTimeTooSkewed" {
            return false;
        }
        let server_secs = parse_s3_server_time_xml(body).or_else(|| {
            headers
                .get(http::header::DATE)
                .and_then(|v| v.to_str().ok())
                .and_then(rship_core::time::parse_http_date_to_secs)
        });
        if let Some(secs) = server_secs {
            let offset = secs.saturating_sub(self.inner.clock.now_unix_secs());
            self.inner
                .clock_offset_secs
                .store(offset, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn sse_c_key_and_md5(&self) -> Result<Option<(&str, String)>> {
        let Some(S3ServerSideEncryption::SseC { customer_key_b64 }) =
            &self.inner.cfg.server_side_encryption
        else {
            return Ok(None);
        };
        let trimmed = customer_key_b64.trim();
        let raw_key = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| Error::config(format!("invalid base64 SSE-C key: {e}")))?;
        if raw_key.len() != 32 {
            return Err(Error::config(format!(
                "SSE-C requires a 32-byte AES key, got {} bytes",
                raw_key.len()
            )));
        }
        let md5_b64 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(&raw_key));
        Ok(Some((trimmed, md5_b64)))
    }

    pub(super) fn apply_sse_c_headers_if_needed(&self, headers: &mut HeaderMap) -> Result<()> {
        if let Some((trimmed, md5_b64)) = self.sse_c_key_and_md5()? {
            headers.insert(
                HeaderName::from_static("x-amz-server-side-encryption-customer-algorithm"),
                HeaderValue::from_static("AES256"),
            );
            headers.insert(
                HeaderName::from_static("x-amz-server-side-encryption-customer-key"),
                sensitive_header_value(trimmed, "SSE-C key")?,
            );
            headers.insert(
                HeaderName::from_static("x-amz-server-side-encryption-customer-key-md5"),
                HeaderValue::from_str(&md5_b64)
                    .map_err(|e| Error::protocol(format!("invalid SSE-C key MD5 header: {e}")))?,
            );
        }
        Ok(())
    }

    pub(super) fn apply_sse_c_copy_source_headers_if_needed(
        &self,
        headers: &mut HeaderMap,
    ) -> Result<()> {
        if let Some((trimmed, md5_b64)) = self.sse_c_key_and_md5()? {
            headers.insert(
                HeaderName::from_static(
                    "x-amz-copy-source-server-side-encryption-customer-algorithm",
                ),
                HeaderValue::from_static("AES256"),
            );
            headers.insert(
                HeaderName::from_static("x-amz-copy-source-server-side-encryption-customer-key"),
                sensitive_header_value(trimmed, "SSE-C copy-source key")?,
            );
            headers.insert(
                HeaderName::from_static(
                    "x-amz-copy-source-server-side-encryption-customer-key-md5",
                ),
                HeaderValue::from_str(&md5_b64).map_err(|e| {
                    Error::protocol(format!("invalid SSE-C copy-source key MD5 header: {e}"))
                })?,
            );
        }
        Ok(())
    }

    pub(super) fn apply_sse_headers(&self, headers: &mut HeaderMap) -> Result<()> {
        match &self.inner.cfg.server_side_encryption {
            Some(S3ServerSideEncryption::SseC { .. }) => {
                self.apply_sse_c_headers_if_needed(headers)?;
            }
            Some(sse) => {
                headers.insert(
                    HeaderName::from_static("x-amz-server-side-encryption"),
                    HeaderValue::from_static(sse.as_header_value()),
                );
                if let S3ServerSideEncryption::AwsKms { key_id: Some(kid) } = sse {
                    headers.insert(
                        HeaderName::from_static("x-amz-server-side-encryption-aws-kms-key-id"),
                        HeaderValue::from_str(kid).map_err(|e| {
                            Error::protocol(format!("invalid kms_key_id header: {e}"))
                        })?,
                    );
                }
            }
            None => {}
        }
        Ok(())
    }

    pub(super) fn insert_common_object_headers(
        &self,
        headers: &mut HeaderMap,
        dst_path: &RelPath,
        op_id: &str,
        src_mtime_ns: i64,
        checksums: &[Checksum],
    ) -> Result<Option<String>> {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(infer_content_type(dst_path.as_str())),
        );
        self.apply_sse_headers(headers)?;
        headers.insert(
            HeaderName::from_static(META_OP_ID),
            HeaderValue::from_str(op_id)
                .map_err(|e| Error::protocol(format!("invalid op_id header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static(META_MTIME_NS),
            HeaderValue::from_str(&src_mtime_ns.to_string()).expect("valid i64"),
        );
        let mut precomputed_sha256: Option<String> = None;
        for ck in checksums {
            if ck.kind == HashKind::Sha256 {
                precomputed_sha256 = Some(ck.hex.clone());
                headers.insert(
                    HeaderName::from_static(META_SHA256),
                    HeaderValue::from_str(&ck.hex)
                        .map_err(|e| Error::protocol(format!("invalid sha256 header: {e}")))?,
                );
            }
        }
        if let Some(ref sc) = self.inner.cfg.storage_class {
            headers.insert(
                HeaderName::from_static("x-amz-storage-class"),
                HeaderValue::from_str(sc)
                    .map_err(|e| Error::protocol(format!("invalid storage_class: {e}")))?,
            );
        }
        Ok(precomputed_sha256)
    }

    pub fn config(&self) -> &S3Config {
        &self.inner.cfg
    }

    pub fn profile(&self) -> &ProviderProfile {
        &self.inner.profile
    }

    /// Perform an authenticated service-level `ListBuckets` (`GET /`) connectivity probe for
    /// bucketless S3 remotes (`rship config test <remote>` when no default bucket is set).
    pub async fn probe_service(
        cfg: &S3Config,
        transport: &HttpTransport,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<String> {
        let ep_str = cfg.effective_endpoint();
        let parsed = Url::parse(&ep_str)
            .map_err(|e| Error::protocol(format!("invalid S3 endpoint `{ep_str}`: {e}")))?;
        let scheme = parsed.scheme();
        let base_host = parsed
            .host_str()
            .ok_or_else(|| Error::protocol(format!("S3 endpoint `{ep_str}` missing host")))?;
        let port_suffix = match (scheme, parsed.port()) {
            ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
            (_, Some(p)) => format!(":{p}"),
        };
        let host_header = format!("{base_host}{port_suffix}");
        let ep_path = parsed.path().trim_end_matches('/');
        let canonical_uri = if ep_path.is_empty() {
            "/".to_string()
        } else {
            ep_path.to_string()
        };
        let url = format!("{scheme}://{host_header}{canonical_uri}");

        let clock = clock.unwrap_or_else(SystemClock::shared);
        let cred_source = cfg
            .credential_source
            .clone()
            .unwrap_or_else(|| S3CredentialSource::Static(cfg.credentials.clone()));
        let provider = S3CredentialProvider::new(cred_source, transport.clone(), clock.clone());
        let scope = LimiterScope::new(&cfg.remote_name, format!("{}:*", provider.scope_label()));
        let limiter = transport
            .control_limiter_for_with_config(scope, transport.config().default_rate_limit.clone());
        let policy_cfg = RetryPolicyConfig::new()
            .with_max_retries(cfg.max_retries)
            .with_delays(cfg.base_retry_delay, cfg.max_retry_delay);
        let is_dynamic_creds = provider.is_dynamic();
        let provider_ref = &provider;
        let url_ref = &url;
        let canonical_uri_ref = &canonical_uri;
        let host_header_ref = &host_header;
        let clock_ref = &clock;

        execute_with_auth_policy(
            transport,
            &limiter,
            "ListBuckets",
            &policy_cfg,
            Idempotency::Idempotent,
            || async move {
                let creds = provider_ref.credentials().await?;
                let mut headers = HeaderMap::new();
                sign_v4_request(
                    &Method::GET,
                    canonical_uri_ref,
                    &[],
                    host_header_ref,
                    &mut headers,
                    EMPTY_SHA256_HEX,
                    &creds,
                    cfg.signing_region(),
                    clock_ref.now_unix_secs(),
                )?;
                let req = transport.control_client().get(url_ref).headers(headers);
                Ok((req, creds))
            },
            |creds| async move {
                Ok(provider_ref
                    .force_refresh(&creds.access_key_id, creds.session_token.as_deref())
                    .await?
                    .is_some())
            },
            |resp| {
                if resp.status.is_success() {
                    return PolicyDecision::Ok(());
                }
                if is_dynamic_creds && is_expired_token_error(&Method::GET, resp.status, &resp.body)
                {
                    return PolicyDecision::AuthRefresh;
                }
                let err =
                    classify_s3_error("ListBuckets", resp.status, &resp.headers, &resp.body, false);
                PolicyDecision::from_error(err)
            },
        )
        .await?;
        Ok(format!("s3://{ep_str}"))
    }

    fn bucket_prefix_with_slash(&self) -> &str {
        &self.inner.bucket_prefix_with_slash
    }

    /// Map a relative key (either raw or NFC) into the full S3 object key inside `bucket`,
    /// preserving any literal leading `/` on `rel` (since `"/foo"` and `"foo"` are distinct S3 keys).
    fn full_key(&self, rel: &str) -> String {
        let base = self.inner.cfg.normalized_prefix();
        match (base.is_empty(), rel.is_empty()) {
            (true, true) => String::new(),
            (true, false) => rel.to_string(),
            (false, true) => base.to_string(),
            (false, false) => format!("{base}/{rel}"),
        }
    }

    /// Strip configured bucket `prefix/` from a full S3 object key (zero-alloc).
    fn strip_bucket_prefix<'a>(&self, full_key: &'a str) -> Option<&'a str> {
        let base = self.inner.cfg.normalized_prefix();
        if base.is_empty() {
            return Some(full_key);
        }
        full_key.strip_prefix(base)?.strip_prefix('/')
    }

    /// Construct `(full_url, canonical_uri, host_header)` strictly matching SigV4 canonical rules.
    fn build_request_target(
        &self,
        full_key: &str,
        query_pairs: &[(String, String)],
    ) -> Result<(String, String, String)> {
        let ep_str = self.inner.cfg.effective_endpoint();
        let parsed = Url::parse(&ep_str)
            .map_err(|e| Error::protocol(format!("invalid S3 endpoint `{ep_str}`: {e}")))?;
        let scheme = parsed.scheme();
        let base_host = parsed
            .host_str()
            .ok_or_else(|| Error::protocol(format!("S3 endpoint `{ep_str}` missing host")))?;
        let port_suffix = match (scheme, parsed.port()) {
            ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
            (_, Some(p)) => format!(":{p}"),
        };
        let ep_path = parsed.path().trim_end_matches('/');

        let (host_header, canonical_uri) = if self.inner.cfg.use_path_style() {
            let host = format!("{base_host}{port_suffix}");
            let enc_bucket = aws_uri_encode(&self.inner.cfg.bucket);
            let uri = if full_key.is_empty() {
                format!("{ep_path}/{enc_bucket}")
            } else {
                let enc_key = aws_uri_encode_path(full_key);
                format!("{ep_path}/{enc_bucket}/{enc_key}")
            };
            (host, uri)
        } else {
            let host = format!("{}.{base_host}{port_suffix}", self.inner.cfg.bucket);
            let uri = if full_key.is_empty() {
                if ep_path.is_empty() {
                    "/".to_string()
                } else {
                    ep_path.to_string()
                }
            } else {
                let enc_key = aws_uri_encode_path(full_key);
                format!("{ep_path}/{enc_key}")
            };
            (host, uri)
        };

        let canonical_query = build_canonical_query(query_pairs);
        let full_url = if canonical_query.is_empty() {
            format!("{scheme}://{host_header}{canonical_uri}")
        } else {
            format!("{scheme}://{host_header}{canonical_uri}?{canonical_query}")
        };

        Ok((full_url, canonical_uri, host_header))
    }

    pub(super) fn control_retry_config(
        &self,
        method: &Method,
        long_timeout: bool,
    ) -> RetryPolicyConfig {
        let mut cfg = RetryPolicyConfig::new()
            .with_max_retries(self.inner.cfg.max_retries)
            .with_delays(
                self.inner.cfg.base_retry_delay,
                self.inner.cfg.max_retry_delay,
            )
            .with_skip_response_body(*method == Method::HEAD);
        if long_timeout {
            cfg = cfg.with_request_timeout(self.inner.transport.config().long_control_timeout);
        }
        cfg
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn control_signed_request_with_policy<
        T,
        ClassifyFn,
        ReconcileFn,
        ReconcileFut,
    >(
        &self,
        context: &str,
        method: Method,
        full_key: &str,
        query_pairs: &[(String, String)],
        extra_headers: HeaderMap,
        body: Bytes,
        long_timeout: bool,
        idempotency: Idempotency,
        mut classify: ClassifyFn,
        reconcile: ReconcileFn,
    ) -> Result<T>
    where
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
        ReconcileFn: FnMut(Error) -> ReconcileFut,
        ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
    {
        let (url, canonical_uri, host_header) = self.build_request_target(full_key, query_pairs)?;
        let payload_hash = if body.is_empty() {
            EMPTY_SHA256_HEX.to_string()
        } else {
            sha256_hex(&body)
        };
        let policy_cfg = self.control_retry_config(&method, long_timeout);
        let method_for_build = method.clone();
        let method_for_classify = method;
        let is_dynamic_creds = self.inner.creds.is_dynamic();

        execute_with_policy_full(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            idempotency,
            || {
                let method = method_for_build.clone();
                let url = url.clone();
                let canonical_uri = canonical_uri.clone();
                let host_header = host_header.clone();
                let extra_headers = extra_headers.clone();
                let body = body.clone();
                let payload_hash = payload_hash.clone();
                async move {
                    let creds = self.inner.creds.credentials().await?;
                    let mut headers = extra_headers;
                    let needs_empty_body =
                        body.is_empty() && matches!(method, Method::PUT | Method::POST);
                    if needs_empty_body {
                        headers
                            .entry(http::header::CONTENT_LENGTH)
                            .or_insert_with(|| HeaderValue::from_static("0"));
                    }
                    sign_v4_request(
                        &method,
                        &canonical_uri,
                        query_pairs,
                        &host_header,
                        &mut headers,
                        &payload_hash,
                        &creds,
                        self.inner.cfg.signing_region(),
                        self.effective_unix_secs(),
                    )?;

                    let mut req = self
                        .inner
                        .transport
                        .control_client()
                        .request(method, &url)
                        .headers(headers);
                    if !body.is_empty() || needs_empty_body {
                        req = req.body(body);
                    }
                    Ok((req, creds))
                }
            },
            |creds| async move {
                Ok(self
                    .inner
                    .creds
                    .force_refresh(&creds.access_key_id, creds.session_token.as_deref())
                    .await?
                    .is_some())
            },
            |resp| {
                if !resp.status.is_success() {
                    if is_dynamic_creds
                        && is_expired_token_error(&method_for_classify, resp.status, &resp.body)
                    {
                        return PolicyDecision::AuthRefresh;
                    }
                    self.maybe_adjust_clock_skew(&resp.headers, &resp.body);
                }
                classify(resp)
            },
            reconcile,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn control_signed_request(
        &self,
        context: &str,
        method: Method,
        full_key: &str,
        query_pairs: &[(String, String)],
        extra_headers: HeaderMap,
        body: Bytes,
        allow_404: bool,
        is_multipart_op: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.control_signed_request_with_policy(
            context,
            method,
            full_key,
            query_pairs,
            extra_headers,
            body,
            false,
            Idempotency::Idempotent,
            |resp| {
                if resp.status.is_success() || (allow_404 && resp.status == StatusCode::NOT_FOUND) {
                    return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                }
                let err = classify_s3_error(
                    context,
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    is_multipart_op,
                );
                PolicyDecision::from_error(err)
            },
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
    }

    async fn head_object_raw(&self, full_key: &str) -> Result<Option<HeaderMap>> {
        let mut headers = HeaderMap::new();
        if self.inner.profile.supports_crc64nvme || self.inner.profile.supports_crc32c {
            headers.insert(
                HeaderName::from_static("x-amz-checksum-mode"),
                HeaderValue::from_static("ENABLED"),
            );
        }
        self.apply_sse_c_headers_if_needed(&mut headers)?;
        let (status, resp_headers, _) = self
            .control_signed_request(
                "HeadObject",
                Method::HEAD,
                full_key,
                &[],
                headers,
                Bytes::new(),
                true,
                false,
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp_headers))
    }

    async fn list_v2_page(
        &self,
        full_prefix: &str,
        delimiter: Option<&str>,
        continuation_token: Option<&str>,
        v1_marker: Option<&str>,
        max_keys: Option<u32>,
    ) -> Result<crate::s3::xml::ListObjectsV2Page> {
        self.list_v2_page_with_start_after(
            full_prefix,
            delimiter,
            continuation_token,
            v1_marker,
            None,
            max_keys,
        )
        .await
    }

    async fn list_v2_page_with_start_after(
        &self,
        full_prefix: &str,
        delimiter: Option<&str>,
        continuation_token: Option<&str>,
        v1_marker: Option<&str>,
        start_after: Option<&str>,
        max_keys: Option<u32>,
    ) -> Result<crate::s3::xml::ListObjectsV2Page> {
        let mut query = Vec::with_capacity(7);
        if let Some(m) = v1_marker {
            query.push(("marker".to_string(), m.to_string()));
        } else {
            query.push(("list-type".to_string(), "2".to_string()));
            if let Some(ct) = continuation_token {
                query.push(("continuation-token".to_string(), ct.to_string()));
            } else if let Some(sa) = start_after {
                query.push(("start-after".to_string(), sa.to_string()));
            }
        }
        query.push(("encoding-type".to_string(), "url".to_string()));
        if !full_prefix.is_empty() {
            query.push(("prefix".to_string(), full_prefix.to_string()));
        }
        if let Some(d) = delimiter {
            query.push(("delimiter".to_string(), d.to_string()));
        }
        if let Some(mk) = max_keys {
            query.push(("max-keys".to_string(), mk.to_string()));
        }

        let op_name = if v1_marker.is_some() {
            "ListObjects"
        } else {
            "ListObjectsV2"
        };
        let (_, _, body) = self
            .control_signed_request(
                op_name,
                Method::GET,
                "",
                &query,
                HeaderMap::new(),
                Bytes::new(),
                false,
                false,
            )
            .await?;
        parse_list_objects_v2(&body)
    }

    fn headers_to_entry(
        &self,
        headers: &HeaderMap,
        raw_path: &str,
        nfc_path: RelPath,
        kind: EntryKind,
    ) -> Entry {
        let size = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let etag = headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // Always use S3's own server `Last-Modified` so `HeadObject` and `ListObjectsV2`
        // agree bit-for-bit on `Entry.mtime_ns` (dual-side `sync_baseline` tracks source
        // vs destination mtime separately!).
        let mtime_ns = headers
            .get(http::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date_nanos)
            .unwrap_or(0);

        let checksum =
            extract_verified_checksum_from_headers(headers, etag.as_deref(), self.is_non_md5_sse());

        Entry {
            node_id: None,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path),
            nfc_path,
            kind,
            size: if kind == EntryKind::Directory {
                0
            } else {
                size
            },
            mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        }
    }

    /// Checksum algorithm a NEW multipart upload with `planned_chunk_size` parts is created
    /// with (`x-amz-checksum-algorithm`), or `None` when parts are sent without checksums.
    ///
    /// Parts must carry the checksum header, so this is only enabled when every part can be
    /// hashed before it is sent: in RAM (`<= IN_MEM_STRICT_HASH_CAP`) or while computing the
    /// SigV4 payload hash (plain HTTP / strict SigV4).
    fn multipart_part_checksum_kind(&self, planned_chunk_size: u64) -> Option<HashKind> {
        if !self.inner.cfg.send_upload_checksum
            || !(self.inner.cfg.requires_payload_sha256()
                || planned_chunk_size <= IN_MEM_STRICT_HASH_CAP)
        {
            return None;
        }
        if self.inner.profile.supports_crc64nvme {
            Some(HashKind::Crc64Nvme)
        } else if self.inner.profile.supports_crc32c {
            Some(HashKind::Crc32c)
        } else {
            None
        }
    }

    /// Checksum algorithm an EXISTING multipart upload was created with, read from its
    /// session metadata so `UploadPart`/`CompleteMultipartUpload` can never disagree with
    /// `CreateMultipartUpload`.
    ///
    /// Journals written before `part_checksum_algorithm` existed only recorded
    /// `send_part_checksum_header`; the algorithm then followed the profile preference, which
    /// is reproduced here. Unparsable metadata falls back to the same rule
    /// `CreateMultipartUpload` applies ([`Self::multipart_part_checksum_kind`]).
    fn session_part_checksum_kind(
        &self,
        meta: Option<&S3SessionMeta>,
        planned_chunk_size: u64,
    ) -> Option<HashKind> {
        match meta {
            Some(m) => m.part_checksum_algorithm.or_else(|| {
                if !m.send_part_checksum_header {
                    None
                } else if self.inner.profile.supports_crc64nvme {
                    Some(HashKind::Crc64Nvme)
                } else if self.inner.profile.supports_crc32c {
                    Some(HashKind::Crc32c)
                } else {
                    None
                }
            }),
            None => self.multipart_part_checksum_kind(planned_chunk_size),
        }
    }

    fn resolve_upload_checksum_kind(
        &self,
        is_multipart_op: bool,
        has_preknown_checksum_header: bool,
        multipart_checksum: Option<HashKind>,
    ) -> Option<HashKind> {
        if is_multipart_op {
            // `UploadPart` must use exactly the algorithm the upload was created with.
            multipart_checksum
        } else if self.inner.cfg.send_upload_checksum && !has_preknown_checksum_header {
            if self.inner.profile.supports_crc64nvme {
                Some(HashKind::Crc64Nvme)
            } else if self.inner.profile.supports_single_part_crc32c {
                Some(HashKind::Crc32c)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_put_payload(
        &self,
        headers: &mut HeaderMap,
        body: ByteStream,
        expected_len: u64,
        precomputed_sha256: Option<&str>,
        upload_ck_kind: Option<HashKind>,
        is_multipart_op: bool,
        stream_err: &Arc<StdMutex<Option<Error>>>,
        digest_slot: &Arc<StdMutex<Option<S3StreamUploadDigests>>>,
    ) -> Result<(String, ByteStream, Option<String>)> {
        let need_sha256 = self.inner.cfg.requires_payload_sha256();
        let compute_crc64 = self.inner.profile.supports_crc64nvme;
        let compute_crc32c = self.inner.profile.supports_crc32c;

        if expected_len == 0 {
            let mut s = body;
            while let Some(item) = s.next().await {
                let b = item?;
                if !b.is_empty() {
                    return Err(Error::source_mutated(
                        "non-empty bytes yielded for 0-byte S3 upload",
                    ));
                }
            }
            let sent_ck =
                upload_ck_kind.and_then(|ck| insert_upload_checksum_header(headers, ck, &[]));
            if need_sha256 && !is_multipart_op && !headers.contains_key(META_SHA256) {
                headers.insert(
                    HeaderName::from_static(META_SHA256),
                    HeaderValue::from_static(EMPTY_SHA256_HEX),
                );
            }
            *lock_unpoisoned(digest_slot) = Some(S3StreamUploadDigests::for_empty(
                compute_crc64,
                compute_crc32c,
            ));
            let ph = if need_sha256 {
                EMPTY_SHA256_HEX.to_string()
            } else {
                UNSIGNED_PAYLOAD.to_string()
            };
            return Ok((ph, Box::pin(futures::stream::empty()), sent_ck));
        }

        if !need_sha256 {
            let in_mem_prepared = match upload_ck_kind {
                Some(ck_kind) if is_multipart_op => Ok(prepare_required_checksum_upload(
                    body,
                    expected_len,
                    ck_kind,
                    compute_crc64,
                    compute_crc32c,
                    &self.inner.strict_hash_mem_budget,
                    self.inner.cfg.spool_dir.as_deref(),
                )
                .await?),
                Some(ck_kind) if expected_len <= IN_MEM_STRICT_HASH_CAP => {
                    prepare_in_memory_checksum_upload(
                        body,
                        expected_len,
                        ck_kind,
                        compute_crc64,
                        compute_crc32c,
                        &self.inner.strict_hash_mem_budget,
                    )
                    .await?
                }
                _ => Err(body),
            };

            return Ok(match in_mem_prepared {
                Ok(PreparedUpload {
                    checksum_header,
                    part_checksum,
                    digests,
                    backing,
                    ..
                }) => {
                    if let Some((hdr_name, hdr_val)) = checksum_header {
                        headers.insert(hdr_name, hdr_val);
                    }
                    *lock_unpoisoned(digest_slot) = Some(digests);
                    (
                        UNSIGNED_PAYLOAD.to_string(),
                        backing.into_stream(),
                        part_checksum,
                    )
                }
                Err(streaming_body) => {
                    let strict = StrictBodyStream::new(
                        "S3",
                        streaming_body,
                        expected_len,
                        stream_err.clone(),
                    );
                    let hashed = StreamingHashStream::new(
                        strict,
                        S3StreamUploadHasher::new(compute_crc64, compute_crc32c),
                        expected_len,
                        digest_slot.clone(),
                    );
                    (UNSIGNED_PAYLOAD.to_string(), Box::pin(hashed), None)
                }
            });
        }

        if upload_ck_kind.is_none()
            && let Some(hex_sha) = precomputed_sha256
        {
            let strict = StrictBodyStream::new("S3", body, expected_len, stream_err.clone());
            let hashed = StreamingHashStream::new(
                strict,
                S3StreamUploadHasher::new(compute_crc64, compute_crc32c),
                expected_len,
                digest_slot.clone(),
            );
            return Ok((hex_sha.to_string(), Box::pin(hashed), None));
        }

        let compute_sha256 = precomputed_sha256.is_none();
        let PreparedUpload {
            sha256_hex,
            checksum_header,
            part_checksum,
            digests,
            backing,
        } = prepare_hashed_upload(
            body,
            expected_len,
            compute_sha256,
            upload_ck_kind,
            compute_crc64,
            compute_crc32c,
            &self.inner.strict_hash_mem_budget,
            self.inner.cfg.spool_dir.as_deref(),
        )
        .await?;
        if let Some((hdr_name, hdr_val)) = checksum_header {
            headers.insert(hdr_name, hdr_val);
        }
        if !is_multipart_op
            && !headers.contains_key(META_SHA256)
            && let Some(ref hex_sha) = sha256_hex
        {
            headers.insert(
                HeaderName::from_static(META_SHA256),
                HeaderValue::from_str(hex_sha).expect("valid sha256 hex"),
            );
        }
        *lock_unpoisoned(digest_slot) = Some(digests);
        let ph = sha256_hex
            .or_else(|| precomputed_sha256.map(str::to_string))
            .expect("sha256 computed when need_sha256 is true");
        Ok((ph, backing.into_stream(), part_checksum))
    }

    /// Stream an upload body (`PutObject` or `UploadPart`) over the `.http1_only()`
    /// Data Plane, enforcing payload signing, streaming checksums, and strict length.
    #[allow(clippy::too_many_arguments)]
    async fn send_data_put(
        &self,
        context: &str,
        full_key: &str,
        query_pairs: &[(String, String)],
        mut headers: HeaderMap,
        body: ByteStream,
        expected_len: u64,
        precomputed_sha256: Option<&str>,
        has_preknown_checksum_header: bool,
        multipart_checksum: Option<HashKind>,
        is_multipart_op: bool,
    ) -> Result<(HeaderMap, Option<String>)> {
        let (url, canonical_uri, host_header) = self.build_request_target(full_key, query_pairs)?;
        let upload_ck_kind = self.resolve_upload_checksum_kind(
            is_multipart_op,
            has_preknown_checksum_header,
            multipart_checksum,
        );
        let stream_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
        let digest_slot: Arc<StdMutex<Option<S3StreamUploadDigests>>> =
            Arc::new(StdMutex::new(None));

        let (payload_hash, req_body_stream, sent_part_checksum) = self
            .prepare_put_payload(
                &mut headers,
                body,
                expected_len,
                precomputed_sha256,
                upload_ck_kind,
                is_multipart_op,
                &stream_err,
                &digest_slot,
            )
            .await?;

        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&expected_len.to_string()).expect("valid content-length"),
        );

        self.inner.data_limiter.acquire_send_permit().await;

        let creds = self.inner.creds.credentials().await?;
        sign_v4_request(
            &Method::PUT,
            &canonical_uri,
            query_pairs,
            &host_header,
            &mut headers,
            &payload_hash,
            &creds,
            self.inner.cfg.signing_region(),
            self.effective_unix_secs(),
        )?;

        let req = self
            .inner
            .transport
            .data_client()
            .put(&url)
            .headers(headers);
        let resp = send_watched_sized_upload_with_capture(
            &self.inner.transport,
            context,
            req,
            req_body_stream,
            expected_len,
            stream_err,
        )
        .await?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = self.inner.transport.read_data_body(resp).await?;

        if !status.is_success() {
            self.maybe_adjust_clock_skew(&resp_headers, &resp_body);
            let mut err =
                classify_s3_error(context, status, &resp_headers, &resp_body, is_multipart_op);
            if self.inner.creds.is_dynamic()
                && is_expired_token_error(&Method::PUT, status, &resp_body)
                && matches!(
                    self.inner
                        .creds
                        .force_refresh(&creds.access_key_id, creds.session_token.as_deref())
                        .await,
                    Ok(Some(_))
                )
            {
                err = Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Retryable,
                    err.message,
                );
            }
            if err.is_throttled() {
                self.inner.data_limiter.record_throttle();
            }
            return Err(err);
        }

        if let Some(streamed) = lock_unpoisoned(&digest_slot).take() {
            verify_s3_upload_response_checksums(
                context,
                &resp_headers,
                &streamed,
                self.is_non_md5_sse(),
            )?;
        }

        self.inner.data_limiter.record_success(false, false);
        Ok((resp_headers, sent_part_checksum))
    }
}

#[async_trait]
impl StorageBackend for S3Backend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "s3"
    }

    fn endpoint_identity(&self) -> String {
        let p = self.inner.cfg.normalized_prefix();
        if p.is_empty() {
            format!(
                "s3://{}/{}",
                self.inner.cfg.effective_endpoint(),
                self.inner.cfg.bucket
            )
        } else {
            format!(
                "s3://{}/{}/{}",
                self.inner.cfg.effective_endpoint(),
                self.inner.cfg.bucket,
                p
            )
        }
    }

    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.profile.to_capabilities(
            self.inner.cfg.single_shot_max_bytes,
            self.inner.cfg.default_chunk_size,
            self.inner.cfg.min_part_bytes_override,
        );
        caps.supports_version_pinned_read = self.inner.cfg.pin_read_etag;
        // Only advertise checksum algorithms that this configured endpoint actually populates:
        // over production `https://` with default `UNSIGNED-PAYLOAD`, single-part `MD5` ETag is
        // universally available whereas `x-amz-meta-rship-sha256` is only written when payload
        // SHA-256 is enabled, and `CRC64NVME`/`CRC32C` only when `send_upload_checksum` is on.
        let has_sha256 = self.inner.cfg.requires_payload_sha256();
        let has_upload_ck = self.inner.cfg.send_upload_checksum;
        let crc_active = has_upload_ck
            && (has_sha256
                || (caps.single_shot_max_bytes <= IN_MEM_STRICT_HASH_CAP
                    && caps.default_chunk_size <= IN_MEM_STRICT_HASH_CAP));
        let allow_md5 = !self.is_non_md5_sse();
        caps.hashes.retain(|hk| match hk {
            HashKind::Md5 => allow_md5,
            HashKind::Sha256 => has_sha256,
            HashKind::Crc64Nvme => crc_active && self.inner.profile.supports_crc64nvme,
            // AWS exclusively sends CRC64NVME when `supports_crc64nvme` is enabled (never
            // CRC32C), and providers like R2 only support COMPOSITE multipart CRC32C (never
            // single-part FULL_OBJECT CRC32C), so advertise CRC32C only when single-part
            // CRC32C is supported and active across configured size thresholds.
            HashKind::Crc32c => {
                crc_active
                    && self.inner.profile.supports_single_part_crc32c
                    && !self.inner.profile.supports_crc64nvme
            }
            _ => false,
        });
        caps
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
    ) -> Result<rship_core::backend::OrderedListPage> {
        self.list_ordered_page_impl(prefix, start_after, continuation, max_keys)
            .await
    }

    fn ordered_list_concurrency(&self) -> usize {
        // Two-Gear `OrderedRangeStream` always uses 1 single RPC on <= 1,000 objects
        // (zero small-bucket penalty), so default Gear 2 range parallelism to 16 shards
        // out of the box while honoring any larger user-configured concurrency.
        if self.inner.cfg.list_prefix_concurrency > 1 {
            self.inner.cfg.list_prefix_concurrency
        } else {
            16
        }
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
        self.open_read_entry_impl(entry, path, range)
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

    async fn list_incomplete_uploads(
        &self,
        prefix: &RelPath,
    ) -> Result<Vec<rship_core::backend::IncompleteUpload>> {
        let uploads = self.list_multipart_uploads_under(prefix).await?;
        Ok(uploads
            .into_iter()
            .map(|u| {
                let initiated_unix_secs = u
                    .initiated
                    .as_deref()
                    .and_then(rship_core::time::parse_rfc3339_to_secs);
                rship_core::backend::IncompleteUpload {
                    key: u.key,
                    upload_id: u.upload_id,
                    initiated_unix_secs,
                }
            })
            .collect())
    }

    async fn abort_incomplete_upload(
        &self,
        upload: &rship_core::backend::IncompleteUpload,
    ) -> Result<()> {
        self.abort_multipart_by_id(&upload.key, &upload.upload_id)
            .await
    }
}
