//! Google Cloud Storage (GCS) JSON API v1 [`StorageBackend`] implementation.

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
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter, parse_retry_after};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::common::http::{
    HttpResponse, Idempotency, PolicyDecision, ReconcileAction, RetryPolicyConfig,
    bearer_header_value, execute_with_policy_full, policy_decision_from_http,
};
use crate::gcs::auth::GcsAuthProvider;
use crate::gcs::config::{GCS_CHUNK_ALIGN_BYTES, GcsConfig, gcs_encode_object_name};

const META_RCLONE_MTIME_RESERVED: &str = "goog-reserved-file-mtime";
const META_RCLONE_MTIME: &str = "mtime";
const META_LEGACY_MTIME_NS: &str = "rship-mtime-ns";
const META_OP_ID: &str = "rship-op-id";

struct GcsInner {
    cfg: GcsConfig,
    auth: Option<Arc<dyn GcsAuthProvider>>,
    transport: HttpTransport,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    /// Running CRC32C state of every resumable session this process opened, keyed by session
    /// URI. See [`transfer::RunningCrc32c`] for why this lives in memory only.
    resumable_crc: transfer::ResumableCrcMap,
    /// Per-operation guard tracking a newly refreshed bearer token that has not yet succeeded,
    /// preventing unbounded 401 refresh loops across outer retries when IAM/scope denies access.
    refreshed_401_tokens: std::sync::Mutex<crate::common::BoundedSessionMap<String, String>>,
}

impl GcsInner {
    async fn apply_auth(&self, headers: &mut HeaderMap) -> Result<Option<String>> {
        if let Some(auth) = &self.auth {
            let tok = auth.access_token().await?;
            headers.insert(http::header::AUTHORIZATION, bearer_header_value(&tok)?);
            Ok(Some(tok))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone)]
pub struct GcsBackend {
    inner: Arc<GcsInner>,
}

impl GcsBackend {
    pub fn new(
        cfg: GcsConfig,
        auth: Option<Arc<dyn GcsAuthProvider>>,
        transport: HttpTransport,
    ) -> Result<Self> {
        if cfg.bucket.trim().is_empty() {
            return Err(Error::protocol("GCS bucket name must not be empty"));
        }
        let principal = auth
            .as_ref()
            .map(|a| a.principal().to_string())
            .unwrap_or_else(|| "anonymous".to_string());
        let scope = LimiterScope::new(&cfg.remote_name, principal);
        let limiter_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), limiter_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, limiter_cfg);
        Ok(Self {
            inner: Arc::new(GcsInner {
                cfg,
                auth,
                transport,
                control_limiter,
                data_limiter,
                resumable_crc: transfer::ResumableCrcMap::default(),
                refreshed_401_tokens: std::sync::Mutex::new(
                    crate::common::BoundedSessionMap::with_defaults(),
                ),
            }),
        })
    }

    fn encoded_bucket(&self) -> String {
        gcs_encode_object_name(&self.inner.cfg.bucket)
    }

    fn append_user_project_pair(
        &self,
        qp: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    ) {
        append_user_project_cfg(&self.inner.cfg, qp);
    }

    fn object_api_url_in(&self, bucket: &str, full_key: &str) -> Result<url::Url> {
        let raw = format!(
            "{}/b/{}/o/{}",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            gcs_encode_object_name(bucket),
            gcs_encode_object_name(full_key)
        );
        let mut url = url::Url::parse(&raw)
            .map_err(|e| Error::protocol(format!("parse GCS object URL: {e}")))?;
        if self.inner.cfg.effective_user_project().is_some() {
            let mut qp = url.query_pairs_mut();
            self.append_user_project_pair(&mut qp);
        }
        Ok(url)
    }

    fn object_api_url(&self, full_key: &str) -> Result<url::Url> {
        self.object_api_url_in(&self.inner.cfg.bucket, full_key)
    }

    fn bucket_objects_api_url(&self) -> Result<url::Url> {
        let raw = format!(
            "{}/b/{}/o",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            self.encoded_bucket()
        );
        url::Url::parse(&raw).map_err(|e| Error::protocol(format!("parse GCS list URL: {e}")))
    }

    fn bucket_upload_url(&self) -> Result<url::Url> {
        let raw = format!(
            "{}/b/{}/o",
            self.inner.cfg.upload_base_url.trim_end_matches('/'),
            self.encoded_bucket()
        );
        url::Url::parse(&raw).map_err(|e| Error::protocol(format!("parse GCS upload URL: {e}")))
    }

    async fn apply_auth(&self, headers: &mut HeaderMap) -> Result<Option<String>> {
        self.inner.apply_auth(headers).await
    }

    #[doc(hidden)]
    pub async fn apply_auth_header(&self, headers: &mut HeaderMap) -> Result<Option<String>> {
        self.apply_auth(headers).await
    }

    fn control_retry_config(&self, long_timeout: bool) -> RetryPolicyConfig {
        let mut cfg = RetryPolicyConfig::new()
            .with_max_retries(self.inner.cfg.max_retries)
            .with_delays(
                self.inner.cfg.base_retry_delay,
                self.inner.cfg.max_retry_delay,
            );
        if long_timeout {
            cfg = cfg.with_request_timeout(self.inner.transport.config().long_control_timeout);
        }
        cfg
    }

    /// Execute an authenticated control-plane HTTP request through the shared policy engine
    /// with single-flight `401` refresh, retry-quota accounting, and plane-isolated CUBIC
    /// throttling (`429`/`503` only).
    #[allow(clippy::too_many_arguments)]
    async fn control_request_with_policy<T, ClassifyFn>(
        &self,
        context: &str,
        method: Method,
        url: &str,
        extra_headers: HeaderMap,
        body: Option<Bytes>,
        long_timeout: bool,
        idempotency: Idempotency,
        classify: ClassifyFn,
    ) -> Result<T>
    where
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
    {
        self.control_request_with_reconcile(
            context,
            method,
            url,
            extra_headers,
            body,
            long_timeout,
            idempotency,
            classify,
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
    }

    /// [`Self::control_request_with_policy`] with a caller-supplied `reconcile` hook, run on
    /// ambiguous failures of a [`Idempotency::NonIdempotent`] request and on
    /// [`PolicyDecision::Reconcile`].
    #[allow(clippy::too_many_arguments)]
    async fn control_request_with_reconcile<T, ClassifyFn, RecFn, RecFut>(
        &self,
        context: &str,
        method: Method,
        url: &str,
        extra_headers: HeaderMap,
        body: Option<Bytes>,
        long_timeout: bool,
        idempotency: Idempotency,
        mut classify: ClassifyFn,
        reconcile: RecFn,
    ) -> Result<T>
    where
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
        RecFn: FnMut(Error) -> RecFut,
        RecFut: std::future::Future<Output = Result<ReconcileAction<T>>>,
    {
        let policy_cfg = self.control_retry_config(long_timeout);
        let has_auth = self.inner.auth.is_some();

        execute_with_policy_full(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            idempotency,
            || {
                let method = method.clone();
                let extra_headers = extra_headers.clone();
                let body = body.clone();
                async move {
                    let mut headers = extra_headers;
                    if let Some(b) = &body
                        && b.is_empty()
                        && matches!(method, Method::POST | Method::PUT)
                    {
                        headers
                            .entry(http::header::CONTENT_LENGTH)
                            .or_insert_with(|| HeaderValue::from_static("0"));
                    }
                    let used_token = self.apply_auth(&mut headers).await?;
                    let mut req = self
                        .inner
                        .transport
                        .control_client()
                        .request(method, url)
                        .headers(headers);
                    if let Some(b) = body {
                        req = req.body(b);
                    }
                    Ok((req, used_token))
                }
            },
            |used_token: Option<String>| async move {
                if let (Some(auth), Some(tok)) = (&self.inner.auth, used_token.as_deref()) {
                    auth.force_refresh(tok).await?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED && has_auth {
                    return PolicyDecision::AuthRefresh;
                }
                classify(resp)
            },
            reconcile,
        )
        .await
    }

    async fn control_request(
        &self,
        context: &str,
        method: Method,
        url: &str,
        extra_headers: HeaderMap,
        body: Option<Bytes>,
        allow_404: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.control_request_with_policy(
            context,
            method,
            url,
            extra_headers,
            body,
            false,
            Idempotency::Idempotent,
            |resp| {
                policy_decision_from_http(resp, allow_404, false, |status, headers, body| {
                    map_gcs_http_error_with_headers(context, status, Some(headers), body)
                })
            },
        )
        .await
    }

    async fn get_object_meta_in_optional(
        &self,
        bucket: &str,
        full_key: &str,
        allow_403: bool,
    ) -> Result<Option<GcsObject>> {
        let url = self.object_api_url_in(bucket, full_key)?;
        let (status, _, body) = self
            .control_request_with_policy(
                "GCS stat object",
                Method::GET,
                url.as_str(),
                HeaderMap::new(),
                None,
                false,
                Idempotency::Idempotent,
                |resp| {
                    if allow_403 && resp.status == StatusCode::FORBIDDEN {
                        return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                    }
                    policy_decision_from_http(resp, true, false, |status, headers, body| {
                        map_gcs_http_error_with_headers(
                            "GCS stat object",
                            status,
                            Some(headers),
                            body,
                        )
                    })
                },
            )
            .await?;
        if status == StatusCode::NOT_FOUND || (allow_403 && status == StatusCode::FORBIDDEN) {
            return Ok(None);
        }
        let obj: GcsObject = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse GCS object JSON: {e}")))?;
        Ok(Some(obj))
    }

    async fn get_object_meta(&self, full_key: &str) -> Result<Option<GcsObject>> {
        self.get_object_meta_in_optional(&self.inner.cfg.bucket, full_key, false)
            .await
    }

    async fn has_prefix(&self, dir_prefix: &str) -> Result<bool> {
        let mut url = self.bucket_objects_api_url()?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("prefix", dir_prefix);
            qp.append_pair("maxResults", "1");
            self.append_user_project_pair(&mut qp);
        }
        let (status, _, body) = self
            .control_request(
                "GCS stat prefix",
                Method::GET,
                url.as_str(),
                HeaderMap::new(),
                None,
                true,
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let page: GcsListResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse GCS list JSON: {e}")))?;
        Ok(!page.items.is_empty() || !page.prefixes.is_empty())
    }

    fn object_to_entry_rel(&self, obj: &GcsObject, rel_raw: &str) -> Result<Option<Entry>> {
        if rel_raw.is_empty() {
            return Ok(None);
        }
        let node_id = obj
            .generation
            .as_ref()
            .map(|g| rship_core::types::NodeId(g.clone()));
        let mtime_ns = obj.parsed_mtime_ns();
        if rel_raw.ends_with('/') {
            let trimmed = rel_raw.trim_end_matches('/');
            if trimmed.is_empty() {
                return Ok(None);
            }
            let nfc_path = RelPath::parse(trimmed)?;
            return Ok(Some(Entry {
                node_id,
                parent_id: None,
                raw_path: rship_core::types::raw_path_override(&nfc_path, trimmed),
                nfc_path,
                kind: EntryKind::Directory,
                size: 0,
                mtime_ns,
                ctime_ns: None,
                etag: obj.etag.clone(),
                checksum: None,
            }));
        }
        let nfc_path = RelPath::parse(rel_raw)?;
        Ok(Some(Entry {
            node_id,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&nfc_path, rel_raw),
            nfc_path,
            kind: EntryKind::File,
            size: obj.parsed_size(),
            mtime_ns,
            ctime_ns: None,
            etag: obj.etag.clone(),
            checksum: obj.preferred_checksum(),
        }))
    }

    fn object_to_entry(&self, obj: &GcsObject) -> Result<Option<Entry>> {
        let Some(rel_raw) = self.inner.cfg.strip_prefix(&obj.name) else {
            return Ok(None);
        };
        self.object_to_entry_rel(obj, rel_raw)
    }

    fn insert_rship_write_metadata(
        custom: &mut serde_json::Map<String, serde_json::Value>,
        init: &UploadInit,
    ) {
        let secs = init.src_mtime_ns.div_euclid(1_000_000_000);
        custom.insert(
            META_RCLONE_MTIME_RESERVED.to_string(),
            serde_json::Value::String(secs.to_string()),
        );
        custom.insert(
            META_RCLONE_MTIME.to_string(),
            serde_json::Value::String(rship_core::time::format_rfc3339(init.src_mtime_ns)),
        );
        custom.insert(
            META_OP_ID.to_string(),
            serde_json::Value::String(init.op_id.clone()),
        );
    }

    fn build_upload_metadata_json(&self, init: &UploadInit, full_key: &str) -> serde_json::Value {
        let mut custom = serde_json::Map::new();
        Self::insert_rship_write_metadata(&mut custom, init);
        let mut root = serde_json::Map::new();
        root.insert(
            "name".to_string(),
            serde_json::Value::String(full_key.to_string()),
        );
        root.insert("metadata".to_string(), serde_json::Value::Object(custom));
        if let Some(sc) = &self.inner.cfg.storage_class
            && !sc.trim().is_empty()
        {
            root.insert(
                "storageClass".to_string(),
                serde_json::Value::String(sc.clone()),
            );
        }
        for ck in &init.checksums {
            match ck.kind {
                HashKind::Crc32c => {
                    if let Ok(bytes) = hex::decode(ck.hex.trim())
                        && bytes.len() == 4
                    {
                        root.insert(
                            "crc32c".to_string(),
                            serde_json::Value::String(B64.encode(bytes)),
                        );
                    }
                }
                HashKind::Md5 => {
                    if let Ok(bytes) = hex::decode(ck.hex.trim())
                        && bytes.len() == 16
                    {
                        root.insert(
                            "md5Hash".to_string(),
                            serde_json::Value::String(B64.encode(bytes)),
                        );
                    }
                }
                _ => {}
            }
        }
        serde_json::Value::Object(root)
    }

    fn build_rewrite_metadata_json(
        &self,
        src_obj: Option<&GcsObject>,
        init: &UploadInit,
    ) -> Option<serde_json::Value> {
        let configured_sc = self
            .inner
            .cfg
            .storage_class
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let Some(src) = src_obj else {
            return configured_sc.map(|sc| serde_json::json!({ "storageClass": sc }));
        };

        let mut root = serde_json::Map::new();
        if let Some(v) = &src.content_type {
            root.insert(
                "contentType".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(v) = &src.content_encoding {
            root.insert(
                "contentEncoding".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(v) = &src.cache_control {
            root.insert(
                "cacheControl".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(v) = &src.content_disposition {
            root.insert(
                "contentDisposition".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(v) = &src.content_language {
            root.insert(
                "contentLanguage".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(v) = &src.custom_time {
            root.insert(
                "customTime".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(sc) = configured_sc {
            root.insert(
                "storageClass".to_string(),
                serde_json::Value::String(sc.to_string()),
            );
        } else if let Some(sc) = &src.storage_class {
            root.insert(
                "storageClass".to_string(),
                serde_json::Value::String(sc.clone()),
            );
        }

        let mut custom = serde_json::Map::new();
        if let Some(existing) = &src.metadata {
            for (k, v) in existing {
                if k != META_LEGACY_MTIME_NS {
                    custom.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
            }
        }
        Self::insert_rship_write_metadata(&mut custom, init);
        root.insert("metadata".to_string(), serde_json::Value::Object(custom));
        Some(serde_json::Value::Object(root))
    }

    /// Parse another GCS endpoint identity (`gcs://<api_base>/<bucket>[/<prefix>]`) to allow
    /// same-provider server-side `rewriteTo` copy (same bucket or cross-bucket on same endpoint).
    fn parse_src_bucket_and_prefix<'a>(&self, src_endpoint: &'a str) -> Option<(&'a str, &'a str)> {
        let expected_prefix = format!(
            "gcs://{}/",
            self.inner.cfg.api_base_url.trim_end_matches('/')
        );
        let rest = src_endpoint.strip_prefix(&expected_prefix)?;
        match rest.split_once('/') {
            Some((bucket, pfx)) if !bucket.is_empty() => Some((bucket, pfx)),
            None if !rest.is_empty() => Some((rest, "")),
            _ => None,
        }
    }
}

fn append_user_project_cfg(
    cfg: &GcsConfig,
    qp: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
) {
    if let Some(up) = cfg.effective_user_project() {
        qp.append_pair("userProject", up);
    }
}

fn append_dst_precondition_query(
    qp: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    precondition: &rship_core::state::DstPrecondition,
    existing_node_id: Option<&rship_core::types::NodeId>,
) {
    match precondition {
        rship_core::state::DstPrecondition::Absent => {
            qp.append_pair("ifGenerationMatch", "0");
        }
        rship_core::state::DstPrecondition::Existing { node_id, .. } => {
            if let Some(gen_id) = node_id
                .as_ref()
                .or(existing_node_id)
                .map(|n| n.0.trim())
                .filter(|s| !s.is_empty())
            {
                qp.append_pair("ifGenerationMatch", gen_id);
            }
        }
        rship_core::state::DstPrecondition::Any | _ => {}
    }
}

fn parse_decimal_unix_secs_to_nanos(raw: &str) -> Option<i64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, unsigned) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    if unsigned.is_empty() {
        return None;
    }
    let (secs_str, frac_str) = match unsigned.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (unsigned, None),
    };
    if secs_str.is_empty() || !secs_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs: i128 = secs_str.parse().ok()?;
    let mut frac_ns: i128 = 0;
    if let Some(frac) = frac_str {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut weight = 100_000_000_i128;
        for b in frac.bytes().take(9) {
            frac_ns += i128::from(b - b'0') * weight;
            weight /= 10;
        }
    }
    let total_abs = secs.checked_mul(1_000_000_000)?.checked_add(frac_ns)?;
    let signed = if neg { -total_abs } else { total_abs };
    i64::try_from(signed).ok()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcsObject {
    name: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    updated: Option<String>,
    #[serde(default)]
    time_created: Option<String>,
    #[serde(default)]
    generation: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    md5_hash: Option<String>,
    #[serde(default)]
    crc32c: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    content_encoding: Option<String>,
    #[serde(default)]
    cache_control: Option<String>,
    #[serde(default)]
    content_disposition: Option<String>,
    #[serde(default)]
    content_language: Option<String>,
    #[serde(default)]
    custom_time: Option<String>,
    #[serde(default)]
    storage_class: Option<String>,
    #[serde(default)]
    metadata: Option<BTreeMap<String, String>>,
}

impl GcsObject {
    fn parsed_size(&self) -> u64 {
        self.size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn parsed_mtime_ns(&self) -> i64 {
        if let Some(meta) = &self.metadata {
            if let Some(raw) = meta.get(META_RCLONE_MTIME)
                && let Some(ns) = rship_core::time::parse_rfc3339_to_nanos(raw.trim())
                    .or_else(|| parse_decimal_unix_secs_to_nanos(raw))
            {
                return ns;
            }
            if let Some(raw) = meta.get(META_RCLONE_MTIME_RESERVED)
                && let Some(ns) = parse_decimal_unix_secs_to_nanos(raw)
                    .or_else(|| rship_core::time::parse_rfc3339_to_nanos(raw.trim()))
            {
                return ns;
            }
            if let Some(raw) = meta.get(META_LEGACY_MTIME_NS)
                && let Ok(ns) = raw.trim().parse::<i64>()
            {
                return ns;
            }
        }
        let ts = self.updated.as_deref().or(self.time_created.as_deref());
        ts.and_then(rship_core::time::parse_rfc3339_to_nanos)
            .unwrap_or(0)
    }

    fn md5_hex(&self) -> Option<String> {
        let raw = self.md5_hash.as_deref()?;
        let decoded = B64.decode(raw.trim()).ok()?;
        (decoded.len() == 16).then(|| hex::encode(decoded))
    }

    fn crc32c_hex(&self) -> Option<String> {
        let raw = self.crc32c.as_deref()?;
        let decoded = B64.decode(raw.trim()).ok()?;
        (decoded.len() == 4).then(|| hex::encode(decoded))
    }

    fn preferred_checksum(&self) -> Option<Checksum> {
        if let Some(hex) = self.md5_hex() {
            return Some(Checksum {
                kind: HashKind::Md5,
                hex,
            });
        }
        self.crc32c_hex().map(|hex| Checksum {
            kind: HashKind::Crc32c,
            hex,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcsListResponse {
    #[serde(default)]
    items: Vec<GcsObject>,
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    next_page_token: Option<String>,
}

fn map_gcs_http_error_with_headers(
    context: &str,
    status: StatusCode,
    headers: Option<&HeaderMap>,
    body: &[u8],
) -> Error {
    let text = String::from_utf8_lossy(body);
    let snippet = text.trim();
    let msg = if snippet.is_empty() {
        format!("{context} failed with HTTP {}", status.as_u16())
    } else {
        format!(
            "{context} failed with HTTP {}: {}",
            status.as_u16(),
            &snippet[..snippet.floor_char_boundary(300)]
        )
    };
    let retry_after = headers.and_then(parse_retry_after);
    let mut err = match status.as_u16() {
        401 | 403 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg),
        404 => Error::new(ErrorKind::NotFound, RetryClass::Permanent, msg),
        408 => Error::new(ErrorKind::Timeout, RetryClass::Retryable, msg),
        409 => Error::new(ErrorKind::Conflict, RetryClass::Permanent, msg),
        412 => Error::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg),
        429 | 503 => Error::rate_limited(msg, retry_after),
        400..=499 => Error::new(ErrorKind::Protocol, RetryClass::Permanent, msg),
        500..=599 => Error::new(ErrorKind::Network, RetryClass::Retryable, msg),
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
impl StorageBackend for GcsBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "gcs"
    }

    fn endpoint_identity(&self) -> String {
        let pfx = self.inner.cfg.prefix.trim_matches('/');
        if pfx.is_empty() {
            format!(
                "gcs://{}/{}",
                self.inner.cfg.api_base_url.trim_end_matches('/'),
                self.inner.cfg.bucket
            )
        } else {
            format!(
                "gcs://{}/{}/{}",
                self.inner.cfg.api_base_url.trim_end_matches('/'),
                self.inner.cfg.bucket,
                pfx
            )
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![HashKind::Md5, HashKind::Crc32c],
            mtime_granularity: Duration::from_millis(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: GCS_CHUNK_ALIGN_BYTES,
                max_chunk_bytes: None,
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self.inner.cfg.aligned_chunk_size(),
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: true,
            supports_ordered_utf8_list: true,
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

    fn ordered_list_concurrency(&self) -> usize {
        16
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
    use rship_transport::TransportConfig;
    use rship_transport::oauth::StaticBearerAuth;

    #[test]
    fn map_gcs_http_error_truncates_multibyte_utf8_safely() {
        let body = "错误".repeat(200);
        let err = map_gcs_http_error_with_headers(
            "upload",
            StatusCode::BAD_REQUEST,
            None,
            body.as_bytes(),
        );
        assert_eq!(err.kind, ErrorKind::Protocol);
        assert!(err.message.contains("HTTP 400"));
    }

    #[test]
    fn map_gcs_http_error_classifies_only_429_and_503_as_throttled() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("7"));

        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let err = map_gcs_http_error_with_headers("op", status, Some(&hdrs), b"slow");
            assert_eq!(err.kind, ErrorKind::RateLimited, "status {status}");
            assert_eq!(err.retry, RetryClass::Throttled, "status {status}");
            assert!(err.is_throttled(), "status {status}");
            assert_eq!(err.retry_after, Some(Duration::from_secs(7)));
        }

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = map_gcs_http_error_with_headers("op", status, None, b"transient");
            assert_eq!(err.kind, ErrorKind::Network, "status {status}");
            assert_eq!(err.retry, RetryClass::Retryable, "status {status}");
            assert!(!err.is_throttled(), "status {status} must not trip CUBIC");
        }

        let timeout_408 =
            map_gcs_http_error_with_headers("op", StatusCode::REQUEST_TIMEOUT, None, b"timeout");
        assert_eq!(timeout_408.kind, ErrorKind::Timeout);
        assert_eq!(timeout_408.retry, RetryClass::Retryable);
        assert!(!timeout_408.is_throttled());

        let precond_412 = map_gcs_http_error_with_headers(
            "op",
            StatusCode::PRECONDITION_FAILED,
            None,
            b"conditionNotMet",
        );
        assert_eq!(precond_412.kind, ErrorKind::PreconditionFailed);
        assert_eq!(precond_412.retry, RetryClass::Permanent);

        let conflict_409 =
            map_gcs_http_error_with_headers("op", StatusCode::CONFLICT, None, b"conflict");
        assert_eq!(conflict_409.kind, ErrorKind::Conflict);
        assert_eq!(conflict_409.retry, RetryClass::Permanent);
    }

    #[test]
    fn gcs_object_parsed_mtime_ns_precedence_and_lossless_decimals() {
        let mut meta = BTreeMap::new();
        meta.insert(
            META_RCLONE_MTIME.to_string(),
            "2023-11-14T22:13:20.123456789Z".to_string(),
        );
        meta.insert(
            META_RCLONE_MTIME_RESERVED.to_string(),
            "1700000000".to_string(),
        );
        meta.insert(
            META_LEGACY_MTIME_NS.to_string(),
            "1600000000000000000".to_string(),
        );
        let obj = GcsObject {
            name: "a.txt".into(),
            updated: Some("2020-01-01T00:00:00Z".into()),
            metadata: Some(meta.clone()),
            ..Default::default()
        };
        assert_eq!(obj.parsed_mtime_ns(), 1_700_000_000_123_456_789);

        // Priority 2: goog-reserved-file-mtime fractional decimal without f64 truncation
        meta.remove(META_RCLONE_MTIME);
        meta.insert(
            META_RCLONE_MTIME_RESERVED.to_string(),
            "1700000005.123456789".to_string(),
        );
        let obj2 = GcsObject {
            metadata: Some(meta.clone()),
            ..obj.clone()
        };
        assert_eq!(obj2.parsed_mtime_ns(), 1_700_000_005_123_456_789);

        // Negative pre-1970 timestamp
        meta.insert(META_RCLONE_MTIME_RESERVED.to_string(), "-1.5".to_string());
        let obj_neg = GcsObject {
            metadata: Some(meta.clone()),
            ..obj.clone()
        };
        assert_eq!(obj_neg.parsed_mtime_ns(), -1_500_000_000);

        // Priority 3: legacy rship-mtime-ns
        meta.remove(META_RCLONE_MTIME_RESERVED);
        let obj3 = GcsObject {
            metadata: Some(meta),
            ..obj.clone()
        };
        assert_eq!(obj3.parsed_mtime_ns(), 1_600_000_000_000_000_000);

        // Priority 4: updated fallback
        let obj4 = GcsObject {
            metadata: None,
            ..obj
        };
        assert_eq!(obj4.parsed_mtime_ns(), 1_577_836_800_000_000_000);
    }

    #[test]
    fn upload_and_rewrite_metadata_builders_are_isolated() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let mut cfg = GcsConfig::new("gcs-unit", "bkt");
        cfg.storage_class = Some("NEARLINE".to_string());
        let backend = GcsBackend::new(cfg, None, transport).unwrap();
        let init = UploadInit {
            op_id: "op-meta-1".to_string(),
            dst_path: RelPath::parse("dir/f.bin").unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 4,
            src_mtime_ns: 1_700_000_000_123_456_789,
            planned_chunk_size: 4,
            checksums: vec![
                Checksum {
                    kind: HashKind::Crc32c,
                    hex: "01020304".to_string(),
                },
                Checksum {
                    kind: HashKind::Md5,
                    hex: "00112233445566778899aabbccddeeff".to_string(),
                },
            ],
            precondition: rship_core::state::DstPrecondition::Absent,
            src_etag: None,
        };

        let up_json = backend.build_upload_metadata_json(&init, "dir/f.bin");
        assert_eq!(up_json["name"], "dir/f.bin");
        assert_eq!(up_json["storageClass"], "NEARLINE");
        assert!(up_json.get("crc32c").is_some());
        assert!(up_json.get("md5Hash").is_some());
        assert_eq!(
            up_json["metadata"][META_RCLONE_MTIME_RESERVED],
            "1700000000"
        );
        assert_eq!(
            up_json["metadata"][META_RCLONE_MTIME],
            "2023-11-14T22:13:20.123456789+00:00"
        );
        assert!(up_json["metadata"].get(META_LEGACY_MTIME_NS).is_none());

        let mut src_meta = BTreeMap::new();
        src_meta.insert("x-custom".to_string(), "keep-me".to_string());
        src_meta.insert(META_LEGACY_MTIME_NS.to_string(), "12345".to_string());
        let src_obj = GcsObject {
            name: "src.bin".into(),
            content_type: Some("text/plain".into()),
            content_encoding: Some("gzip".into()),
            cache_control: Some("max-age=3600".into()),
            content_disposition: Some("inline".into()),
            content_language: Some("en".into()),
            custom_time: Some("2025-01-01T00:00:00Z".into()),
            metadata: Some(src_meta),
            ..Default::default()
        };
        let rw_json = backend
            .build_rewrite_metadata_json(Some(&src_obj), &init)
            .expect("Some rewrite JSON");
        assert!(rw_json.get("name").is_none());
        assert!(rw_json.get("crc32c").is_none());
        assert!(rw_json.get("md5Hash").is_none());
        assert_eq!(rw_json["contentType"], "text/plain");
        assert_eq!(rw_json["contentEncoding"], "gzip");
        assert_eq!(rw_json["cacheControl"], "max-age=3600");
        assert_eq!(rw_json["contentDisposition"], "inline");
        assert_eq!(rw_json["contentLanguage"], "en");
        assert_eq!(rw_json["customTime"], "2025-01-01T00:00:00Z");
        assert_eq!(rw_json["storageClass"], "NEARLINE");
        assert_eq!(rw_json["metadata"]["x-custom"], "keep-me");
        assert_eq!(rw_json["metadata"][META_OP_ID], "op-meta-1");
        assert!(rw_json["metadata"].get(META_LEGACY_MTIME_NS).is_none());

        // When source object metadata could not be fetched (None), only storageClass is sent.
        let rw_none = backend
            .build_rewrite_metadata_json(None, &init)
            .expect("storageClass-only body");
        assert_eq!(rw_none, serde_json::json!({ "storageClass": "NEARLINE" }));

        let no_sc_backend = GcsBackend::new(
            GcsConfig::new("gcs-unit", "bkt"),
            None,
            HttpTransport::new(TransportConfig::default()).unwrap(),
        )
        .unwrap();
        assert!(
            no_sc_backend
                .build_rewrite_metadata_json(None, &init)
                .is_none()
        );
    }

    #[tokio::test]
    async fn gcs_apply_auth_marks_bearer_header_sensitive() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Some(Arc::new(StaticBearerAuth::new("unit", "gcs-unit-secret-token")) as _);
        let backend = GcsBackend::new(GcsConfig::new("gcs-unit", "bkt"), auth, transport).unwrap();
        let mut headers = HeaderMap::new();
        let tok = backend.apply_auth(&mut headers).await.unwrap();
        assert_eq!(tok.as_deref(), Some("gcs-unit-secret-token"));
        let val = headers
            .get(http::header::AUTHORIZATION)
            .expect("Authorization header inserted");
        assert!(
            val.is_sensitive(),
            "GCS Bearer header must be marked sensitive"
        );
        assert_eq!(val.as_bytes(), b"Bearer gcs-unit-secret-token");
        assert!(
            !format!("{val:?}").contains("gcs-unit-secret-token"),
            "Debug formatting must redact sensitive bearer token"
        );
    }
}
