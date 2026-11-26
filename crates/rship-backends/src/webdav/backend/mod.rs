//! Production constant-memory WebDAV [`StorageBackend`] with Nextcloud/OwnCloud
//! Chunked Upload v2 crash-resume, server-side `COPY`, and zero-RAM `Range` streaming.

mod ops;
mod transfer;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, HashKind, StorageQuota,
    UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{
    HttpDumpMode, HttpTransport, LimiterScope, ScopedLimiter, format_redacted_headers,
    map_reqwest_error, parse_retry_after, redact_url_for_dump,
};
use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;

use crate::common::http::{
    HttpResponse, Idempotency, PolicyDecision, ReconcileAction, RetryPolicyConfig,
    execute_with_policy, execute_with_reconcile_policy, sensitive_header_value,
};
use crate::common::lock_unpoisoned;
use crate::webdav::config::{
    DEFAULT_WEBDAV_CHUNK_SIZE, DEFAULT_WEBDAV_SINGLE_SHOT_MAX, MAX_NEXTCLOUD_CHUNK_BYTES,
    WebdavAuth, WebdavConfig,
};
use crate::webdav::xml::{
    DavPropItem, PROPFIND_ALL_BODY, parse_multistatus, parse_multistatus_statuses,
};

pub(super) const MAX_WEBDAV_REDIRECTS: usize = 5;

pub(super) static METHOD_PROPFIND: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"PROPFIND").expect("valid PROPFIND method"));
pub(super) static METHOD_MKCOL: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"MKCOL").expect("valid MKCOL method"));
pub(super) static METHOD_COPY: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"COPY").expect("valid COPY method"));
pub(super) static METHOD_MOVE: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"MOVE").expect("valid MOVE method"));

struct WebdavInner {
    cfg: WebdavConfig,
    base_url: String,
    base_path: String,
    chunked_root: Option<String>,
    transport: HttpTransport,
    no_redirect_control: reqwest::Client,
    no_redirect_data: reqwest::Client,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    auth_header: Option<HeaderValue>,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    mkdir_lock: Mutex<()>,
    known_dirs: StdMutex<HashSet<String>>,
}

#[derive(Clone)]
pub struct WebdavBackend {
    inner: Arc<WebdavInner>,
}

impl WebdavBackend {
    pub fn new(cfg: WebdavConfig, transport: HttpTransport) -> Result<Self> {
        let raw_base = cfg.normalized_base_url();
        let mut parsed = Url::parse(&raw_base)
            .map_err(|e| Error::protocol(format!("invalid WebDAV URL `{raw_base}`: {e}")))?;
        parsed.set_query(None);
        parsed.set_fragment(None);
        let base_url = parsed.as_str().trim_end_matches('/').to_string();
        let base_path = parsed.path().trim_end_matches('/').to_string();
        let chunked_root = cfg.resolve_chunked_upload_root();

        let auth_header = match &cfg.auth {
            WebdavAuth::None => None,
            WebdavAuth::Basic { username, password } => {
                let raw = format!("{username}:{password}");
                let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                Some(sensitive_header_value(
                    &format!("Basic {b64}"),
                    "WebDAV Basic Authorization",
                )?)
            }
            WebdavAuth::Bearer { token } => Some(sensitive_header_value(
                &format!("Bearer {token}"),
                "WebDAV Bearer Authorization",
            )?),
        };

        let mut custom_headers = Vec::with_capacity(cfg.headers.len());
        for (k, v) in &cfg.headers {
            let name = HeaderName::from_bytes(k.trim().as_bytes())
                .map_err(|e| Error::config(format!("invalid WebDAV header name `{k}`: {e}")))?;
            let val = sensitive_header_value(v.trim(), &format!("WebDAV header `{k}`"))?;
            custom_headers.push((name, val));
        }

        let no_redirect_control = build_no_redirect_control_client(transport.config())?;
        let no_redirect_data = build_no_redirect_data_client(transport.config())?;

        let principal = match &cfg.auth {
            WebdavAuth::Basic { username, .. } => username.clone(),
            WebdavAuth::Bearer { .. } => "bearer".to_string(),
            WebdavAuth::None => "anonymous".to_string(),
        };
        let scope = LimiterScope::new(&cfg.remote_name, principal);
        let limiter_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), limiter_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, limiter_cfg);

        Ok(Self {
            inner: Arc::new(WebdavInner {
                cfg,
                base_url,
                base_path,
                chunked_root,
                transport,
                no_redirect_control,
                no_redirect_data,
                control_limiter,
                data_limiter,
                auth_header,
                custom_headers,
                mkdir_lock: Mutex::new(()),
                known_dirs: StdMutex::new(HashSet::new()),
            }),
        })
    }

    fn url_for_rel(&self, rel: &str) -> String {
        let trimmed = rel.trim_matches('/');
        if trimmed.is_empty() {
            self.inner.base_url.clone()
        } else {
            format!("{}/{}", self.inner.base_url, encode_url_path(trimmed))
        }
    }

    fn dir_url_for_rel(&self, rel: &str) -> String {
        let trimmed = rel.trim_matches('/');
        if trimmed.is_empty() {
            format!("{}/", self.inner.base_url)
        } else {
            format!("{}/{}/", self.inner.base_url, encode_url_path(trimmed))
        }
    }

    fn ensure_trailing_slash(url: &str) -> String {
        if url.ends_with('/') {
            url.to_string()
        } else {
            format!("{url}/")
        }
    }

    fn evict_known_dir_chain(&self, rel: &RelPath) {
        let mut dirs = lock_unpoisoned(&self.inner.known_dirs);
        let target = rel.as_str();
        if target.is_empty() {
            return;
        }
        let prefix = format!("{target}/");
        dirs.retain(|d| d != target && !d.starts_with(&prefix));
        let mut cur = target;
        while let Some((parent, _)) = cur.rsplit_once('/') {
            dirs.remove(parent);
            cur = parent;
        }
    }

    fn href_to_rel(&self, href: &str) -> Option<(String, RelPath)> {
        let is_http = href
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
            || href
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
        let path_part = if is_http {
            Url::parse(href).ok()?.path().to_string()
        } else {
            href.to_string()
        };
        let decoded = percent_decode_path(&path_part);
        let decoded_trimmed = decoded.trim_end_matches('/');
        let base_decoded = percent_decode_path(&self.inner.base_path);
        let base_trimmed = base_decoded.trim_end_matches('/');

        let rel_raw = if base_trimmed.is_empty() {
            decoded_trimmed.trim_start_matches('/')
        } else if decoded_trimmed == base_trimmed {
            ""
        } else {
            decoded_trimmed
                .strip_prefix(base_trimmed)?
                .strip_prefix('/')?
        };

        if rel_raw.is_empty() {
            return Some((String::new(), RelPath::root()));
        }
        let rel = RelPath::parse(rel_raw).ok()?;
        Some((rel_raw.to_string(), rel))
    }

    fn apply_auth(&self, headers: &mut HeaderMap) {
        if let Some(auth) = &self.inner.auth_header {
            headers.insert(http::header::AUTHORIZATION, auth.clone());
        }
    }

    fn apply_request_headers(&self, headers: &mut HeaderMap) {
        for (name, val) in &self.inner.custom_headers {
            if !headers.contains_key(name) {
                headers.insert(name.clone(), val.clone());
            }
        }
        self.apply_auth(headers);
    }

    #[doc(hidden)]
    pub fn apply_auth_header(&self, headers: &mut HeaderMap) {
        self.apply_auth(headers);
    }

    fn control_retry_config(&self, long_timeout: bool) -> RetryPolicyConfig {
        let mut cfg = self.inner.cfg.retry_policy();
        if long_timeout {
            cfg = cfg.with_request_timeout(self.inner.transport.config().long_control_timeout);
        }
        cfg
    }

    fn build_control_request(
        &self,
        method: Method,
        url: &str,
        extra_headers: &HeaderMap,
        body: Bytes,
    ) -> reqwest::RequestBuilder {
        let mut headers = extra_headers.clone();
        self.apply_request_headers(&mut headers);
        self.inner
            .no_redirect_control
            .request(method, url)
            .headers(headers)
            .body(body)
    }

    pub(super) async fn send_no_redirect_data_request(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        if self.inner.transport.config().dump_mode == HttpDumpMode::None {
            return self.inner.transport.send_data_request(context, req).await;
        }
        let watchdog = self.inner.transport.data_watchdog();
        let built = req.build().map_err(|e| map_reqwest_error(context, e))?;
        dump_webdav_request(context, &built);
        let started = std::time::Instant::now();
        let res = watchdog
            .run(async {
                self.inner
                    .no_redirect_data
                    .execute(built)
                    .await
                    .map_err(|e| map_reqwest_error(context, e))
            })
            .await;
        match res {
            Ok(resp) => {
                dump_webdav_response(context, &resp, started.elapsed());
                Ok(resp)
            }
            Err(err) => {
                dump_webdav_error(context, &err, started.elapsed());
                Err(err)
            }
        }
    }

    async fn execute_no_redirect_control_with_dump<
        T,
        BuildFn,
        ClassifyFn,
        ReconcileFn,
        ReconcileFut,
    >(
        &self,
        context: &str,
        policy_cfg: &RetryPolicyConfig,
        idempotency: Idempotency,
        mut build_req: BuildFn,
        mut classify: ClassifyFn,
        mut reconcile: ReconcileFn,
    ) -> Result<T>
    where
        BuildFn: FnMut() -> reqwest::RequestBuilder,
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
        ReconcileFn: FnMut(Error) -> ReconcileFut,
        ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
    {
        let limiter = &self.inner.control_limiter;
        let mut attempt = 0u32;
        let mut had_timeout = false;

        loop {
            limiter.acquire_send_permit().await;
            if policy_cfg.is_write {
                limiter.acquire_write_permit().await;
            }

            let mut req = build_req();
            if let Some(t) = policy_cfg.request_timeout {
                req = req.timeout(t);
            }
            let step_res: Result<HttpResponse> = match req.build() {
                Ok(built) => {
                    dump_webdav_request(context, &built);
                    let started = std::time::Instant::now();
                    match self.inner.no_redirect_control.execute(built).await {
                        Ok(resp) => {
                            dump_webdav_response(context, &resp, started.elapsed());
                            let status = resp.status();
                            let headers = resp.headers().clone();
                            let body = if policy_cfg.skip_response_body {
                                Ok(Bytes::new())
                            } else {
                                self.inner.transport.read_control_body(resp).await
                            };
                            body.map(|b| HttpResponse {
                                status,
                                headers,
                                body: b,
                            })
                        }
                        Err(e) => {
                            let mapped = map_reqwest_error(context, e);
                            dump_webdav_error(context, &mapped, started.elapsed());
                            Err(mapped)
                        }
                    }
                }
                Err(e) => Err(map_reqwest_error(context, e)),
            };

            let (err, must_reconcile, retry_after) = match step_res {
                Ok(response) => {
                    let status = response.status;
                    let header_retry_after = parse_retry_after(&response.headers);
                    match classify(response) {
                        PolicyDecision::Ok(val) => {
                            limiter.record_success(attempt > 0, had_timeout);
                            return Ok(val);
                        }
                        PolicyDecision::AuthRefresh => {
                            return Err(Error::permission_denied(format!(
                                "{context}: HTTP {} authentication failed",
                                status.as_u16()
                            )));
                        }
                        PolicyDecision::Fail(err) => return Err(err),
                        PolicyDecision::Reconcile(err) => {
                            if err.is_throttled() {
                                limiter.record_throttle();
                            }
                            let ra = err.retry_after.or(header_retry_after);
                            (err, true, ra)
                        }
                        PolicyDecision::Retry(err) => {
                            if err.is_throttled() {
                                limiter.record_throttle();
                            }
                            let ra = err.retry_after.or(header_retry_after);
                            let rejected_unprocessed = status == StatusCode::TOO_MANY_REQUESTS;
                            (
                                err,
                                idempotency == Idempotency::NonIdempotent && !rejected_unprocessed,
                                ra,
                            )
                        }
                    }
                }
                Err(err) => {
                    if !err.is_retryable() {
                        return Err(err);
                    }
                    if err.is_throttled() {
                        limiter.record_throttle();
                    }
                    let ra = err.retry_after;
                    (err, idempotency == Idempotency::NonIdempotent, ra)
                }
            };

            let is_timeout = err.kind == ErrorKind::Timeout;
            let err_for_exhausted = if must_reconcile {
                match reconcile(err).await {
                    Ok(ReconcileAction::Resolved(val)) => {
                        limiter.record_success(attempt > 0, had_timeout);
                        return Ok(val);
                    }
                    Ok(ReconcileAction::Fail(e)) => return Err(e.with_retries_exhausted()),
                    Err(e) => return Err(e.with_retries_exhausted()),
                    Ok(ReconcileAction::Retry(e)) => match (e.retry_after, retry_after) {
                        (None, Some(ra)) => e.with_retry_after(ra),
                        _ => e,
                    },
                }
            } else {
                err
            };

            if attempt < policy_cfg.max_retries && limiter.try_acquire_retry_quota(is_timeout) {
                if is_timeout {
                    had_timeout = true;
                }
                attempt += 1;
                let delay = limiter.backoff_delay(
                    attempt,
                    policy_cfg.base_delay,
                    policy_cfg.max_delay,
                    retry_after,
                );
                limiter.sleep(delay).await;
                continue;
            }

            return Err(err_for_exhausted.with_retries_exhausted());
        }
    }

    async fn control_idempotent_request(
        &self,
        context: &str,
        method: Method,
        url: &str,
        extra_headers: HeaderMap,
        body: Bytes,
        allowed_status: Option<StatusCode>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let policy_cfg = self.control_retry_config(false);
        let use_dump_path = self.inner.transport.config().dump_mode != HttpDumpMode::None;
        let mut active_url = url.to_string();
        for hop in 0..=MAX_WEBDAV_REDIRECTS {
            let redirect_slot: Arc<StdMutex<Option<Result<String>>>> =
                Arc::new(StdMutex::new(None));
            let res = if use_dump_path {
                self.execute_no_redirect_control_with_dump(
                    context,
                    &policy_cfg,
                    Idempotency::Idempotent,
                    || {
                        self.build_control_request(
                            method.clone(),
                            &active_url,
                            &extra_headers,
                            body.clone(),
                        )
                    },
                    |resp: HttpResponse| {
                        if is_method_preserving_redirect(resp.status) {
                            let redir =
                                resolve_same_origin_redirect(context, &active_url, &resp.headers);
                            *lock_unpoisoned(&redirect_slot) = Some(redir);
                            return PolicyDecision::Fail(Error::protocol("WebDAV redirect"));
                        }
                        if resp.status.is_success() || allowed_status == Some(resp.status) {
                            return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                        }
                        dav_error_decision(context, resp.status, &resp.headers, &resp.body, false)
                    },
                    |err| async move { Ok(ReconcileAction::Retry(err)) },
                )
                .await
            } else {
                execute_with_policy(
                    &self.inner.transport,
                    &self.inner.control_limiter,
                    context,
                    &policy_cfg,
                    Idempotency::Idempotent,
                    || {
                        let req = self.build_control_request(
                            method.clone(),
                            &active_url,
                            &extra_headers,
                            body.clone(),
                        );
                        async move { Ok(req) }
                    },
                    |resp: HttpResponse| {
                        if is_method_preserving_redirect(resp.status) {
                            let redir =
                                resolve_same_origin_redirect(context, &active_url, &resp.headers);
                            *lock_unpoisoned(&redirect_slot) = Some(redir);
                            return PolicyDecision::Fail(Error::protocol("WebDAV redirect"));
                        }
                        if resp.status.is_success() || allowed_status == Some(resp.status) {
                            return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                        }
                        dav_error_decision(context, resp.status, &resp.headers, &resp.body, false)
                    },
                )
                .await
            };

            if let Some(redir) = lock_unpoisoned(&redirect_slot).take() {
                if hop == MAX_WEBDAV_REDIRECTS {
                    return Err(Error::protocol(format!(
                        "{context}: exceeded {MAX_WEBDAV_REDIRECTS} redirects"
                    )));
                }
                active_url = redir?;
                continue;
            }
            return res;
        }
        unreachable!("loop returns on final hop or success/error")
    }

    async fn execute_reconcile_control<T, BuildFn, ClassifyFn, ReconcileFn, ReconcileFut>(
        &self,
        context: &str,
        url: &str,
        policy_cfg: &RetryPolicyConfig,
        mut build_req: BuildFn,
        mut classify: ClassifyFn,
        mut reconcile: ReconcileFn,
    ) -> Result<T>
    where
        BuildFn: FnMut(&str) -> reqwest::RequestBuilder,
        ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
        ReconcileFn: FnMut(Error, String) -> ReconcileFut,
        ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
    {
        let use_dump_path = self.inner.transport.config().dump_mode != HttpDumpMode::None;
        let mut active_url = url.to_string();
        for hop in 0..=MAX_WEBDAV_REDIRECTS {
            let redirect_slot: Arc<StdMutex<Option<Result<String>>>> =
                Arc::new(StdMutex::new(None));
            let res = if use_dump_path {
                self.execute_no_redirect_control_with_dump(
                    context,
                    policy_cfg,
                    Idempotency::NonIdempotent,
                    || build_req(&active_url),
                    |resp: HttpResponse| {
                        if is_method_preserving_redirect(resp.status) {
                            let redir =
                                resolve_same_origin_redirect(context, &active_url, &resp.headers);
                            *lock_unpoisoned(&redirect_slot) = Some(redir);
                            return PolicyDecision::Fail(Error::protocol("WebDAV redirect"));
                        }
                        classify(resp)
                    },
                    |err| reconcile(err, active_url.clone()),
                )
                .await
            } else {
                execute_with_reconcile_policy(
                    &self.inner.transport,
                    &self.inner.control_limiter,
                    context,
                    policy_cfg,
                    Idempotency::NonIdempotent,
                    || {
                        let req = build_req(&active_url);
                        async move { Ok(req) }
                    },
                    |resp: HttpResponse| {
                        if is_method_preserving_redirect(resp.status) {
                            let redir =
                                resolve_same_origin_redirect(context, &active_url, &resp.headers);
                            *lock_unpoisoned(&redirect_slot) = Some(redir);
                            return PolicyDecision::Fail(Error::protocol("WebDAV redirect"));
                        }
                        classify(resp)
                    },
                    |err| reconcile(err, active_url.clone()),
                )
                .await
            };

            if let Some(redir) = lock_unpoisoned(&redirect_slot).take() {
                if hop == MAX_WEBDAV_REDIRECTS {
                    return Err(Error::protocol(format!(
                        "{context}: exceeded {MAX_WEBDAV_REDIRECTS} redirects"
                    )));
                }
                active_url = redir?;
                continue;
            }
            return res;
        }
        unreachable!("loop returns on final hop or success/error")
    }

    async fn mkcol_reconciled(&self, context: &str, url: &str) -> Result<()> {
        let empty = HeaderMap::new();
        self.mkcol_reconciled_with_headers(context, url, &empty)
            .await
    }

    async fn mkcol_reconciled_with_headers(
        &self,
        context: &str,
        url: &str,
        extra_headers: &HeaderMap,
    ) -> Result<()> {
        let policy_cfg = self.control_retry_config(false);
        let mkcol_url = Self::ensure_trailing_slash(url);

        self.execute_reconcile_control(
            context,
            &mkcol_url,
            &policy_cfg,
            |active_url| {
                self.build_control_request(
                    METHOD_MKCOL.clone(),
                    active_url,
                    extra_headers,
                    Bytes::new(),
                )
            },
            |resp: HttpResponse| {
                if resp.status.is_success() {
                    return PolicyDecision::Ok(());
                }
                let err =
                    classify_dav_status(context, resp.status, &resp.headers, &resp.body, false);
                // RFC 4918: HTTP 405 Method Not Allowed on MKCOL signals a resource already exists
                // at `url` (either an existing collection or a conflicting non-collection). Reconcile
                // via PROPFIND depth 0 to verify it is a collection rather than blindly succeeding.
                if resp.status == StatusCode::METHOD_NOT_ALLOWED {
                    return PolicyDecision::Reconcile(err);
                }
                PolicyDecision::from_error(err)
            },
            |err, active_url| async move {
                let is_ambiguous = err.is_retryable();
                let probe_url = Self::ensure_trailing_slash(&active_url);
                let items = self
                    .propfind(&probe_url, "0", PROPFIND_ALL_BODY, true)
                    .await?;
                match items.and_then(|v| v.into_iter().next()) {
                    Some(item) if item.is_collection => Ok(ReconcileAction::Resolved(())),
                    Some(_) => Ok(ReconcileAction::Fail(err)),
                    None if is_ambiguous => Ok(ReconcileAction::Retry(err)),
                    None => Ok(ReconcileAction::Fail(err)),
                }
            },
        )
        .await
    }

    async fn delete_reconciled(&self, context: &str, url: &str) -> Result<()> {
        let policy_cfg = self.control_retry_config(false);
        let empty_headers = HeaderMap::new();

        self.execute_reconcile_control(
            context,
            url,
            &policy_cfg,
            |active_url| {
                self.build_control_request(Method::DELETE, active_url, &empty_headers, Bytes::new())
            },
            |resp: HttpResponse| {
                if resp.status == StatusCode::NOT_FOUND || resp.status == StatusCode::GONE {
                    return PolicyDecision::Ok(());
                }
                dav_mutation_policy_decision(context, resp, false, |_| ())
            },
            |err, active_url| async move {
                let items = self
                    .propfind(&active_url, "0", PROPFIND_ALL_BODY, true)
                    .await?;
                if items.is_none_or(|v| v.is_empty()) {
                    Ok(ReconcileAction::Resolved(()))
                } else {
                    Ok(ReconcileAction::Retry(err))
                }
            },
        )
        .await
    }

    async fn ensure_parent_dirs(&self, rel: &RelPath) -> Result<()> {
        let Some(parent) = rel.parent() else {
            return Ok(());
        };
        if parent.is_root() {
            return Ok(());
        }
        self.mkdir(&parent).await
    }

    async fn propfind(
        &self,
        url: &str,
        depth: &str,
        body: &'static str,
        allow_404: bool,
    ) -> Result<Option<Vec<DavPropItem>>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("depth"),
            HeaderValue::from_str(depth)
                .map_err(|e| Error::protocol(format!("Depth header: {e}")))?,
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );

        let (status, _, resp_body) = self
            .control_idempotent_request(
                "PROPFIND",
                METHOD_PROPFIND.clone(),
                url,
                headers,
                Bytes::from_static(body.as_bytes()),
                allow_404.then_some(StatusCode::NOT_FOUND),
            )
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let items = parse_multistatus(&resp_body)?;
        Ok(Some(items))
    }
}

pub(super) fn dump_webdav_request(context: &str, req: &reqwest::Request) {
    let safe_url = redact_url_for_dump(req.url().as_str());
    let hdrs = format_redacted_headers(req.headers());
    tracing::info!(
        target: "rship::http_dump",
        ">>> HTTP REQUEST [{context}] {} {safe_url}\n{hdrs}",
        req.method()
    );
}

pub(super) fn dump_webdav_response(context: &str, resp: &reqwest::Response, elapsed: Duration) {
    let hdrs = format_redacted_headers(resp.headers());
    tracing::info!(
        target: "rship::http_dump",
        "<<< HTTP RESPONSE [{context}] {:?} {} ({}ms)\n{hdrs}",
        resp.version(),
        resp.status(),
        elapsed.as_millis()
    );
}

pub(super) fn dump_webdav_error(context: &str, err: &Error, elapsed: Duration) {
    tracing::info!(
        target: "rship::http_dump",
        "<<< HTTP ERROR [{context}] ({}ms): {err}",
        elapsed.as_millis()
    );
}

fn apply_proxy_and_ca(
    mut builder: reqwest::ClientBuilder,
    tcfg: &rship_transport::TransportConfig,
) -> Result<reqwest::ClientBuilder> {
    if let Some(proxy_url) = tcfg
        .proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| Error::config(format!("invalid proxy URL in WebDAV client: {e}")))?;
        builder = builder.proxy(proxy);
    }

    if let Some(ca_path) = tcfg.ca_cert_path.as_deref() {
        let pem = std::fs::read(ca_path).map_err(|e| {
            Error::config(format!("read custom CA cert `{}`: {e}", ca_path.display()))
                .with_source(e)
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            Error::config(format!(
                "parse custom CA PEM bundle `{}`: {e}",
                ca_path.display()
            ))
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    Ok(builder)
}

fn build_no_redirect_control_client(
    tcfg: &rship_transport::TransportConfig,
) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .user_agent(&tcfg.user_agent)
        .connect_timeout(tcfg.connect_timeout)
        .timeout(tcfg.control_timeout)
        .pool_max_idle_per_host(tcfg.pool_max_idle_per_host)
        .tcp_nodelay(true)
        .redirect(reqwest::redirect::Policy::none());
    apply_proxy_and_ca(builder, tcfg)?
        .build()
        .map_err(|e| Error::protocol(format!("build WebDAV no-redirect control client: {e}")))
}

fn build_no_redirect_data_client(
    tcfg: &rship_transport::TransportConfig,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(&tcfg.user_agent)
        .connect_timeout(tcfg.connect_timeout)
        .pool_max_idle_per_host(tcfg.pool_max_idle_per_host)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(reqwest::redirect::Policy::none());
    if tcfg.data_http1_only {
        builder = builder.http1_only();
    }
    apply_proxy_and_ca(builder, tcfg)?
        .build()
        .map_err(|e| Error::protocol(format!("build WebDAV no-redirect data client: {e}")))
}

#[inline]
pub(super) fn is_method_preserving_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 307 | 308)
}

pub(super) fn resolve_same_origin_redirect(
    context: &str,
    current_url: &str,
    headers: &HeaderMap,
) -> Result<String> {
    let location = headers
        .get(http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::protocol(format!(
                "{context}: HTTP redirect without valid Location header"
            ))
        })?;
    let current = Url::parse(current_url).map_err(|e| {
        Error::protocol(format!(
            "{context}: invalid current URL `{current_url}`: {e}"
        ))
    })?;
    let target = current.join(location).map_err(|e| {
        Error::protocol(format!(
            "{context}: invalid redirect Location `{location}`: {e}"
        ))
    })?;
    if target.scheme() != current.scheme()
        || target.host_str() != current.host_str()
        || target.port_or_known_default() != current.port_or_known_default()
    {
        return Err(Error::protocol(format!(
            "{context}: refusing cross-origin WebDAV redirect from `{}` to `{}`",
            current.origin().ascii_serialization(),
            target.origin().ascii_serialization(),
        )));
    }
    Ok(target.to_string())
}

pub(super) fn dav_error_decision<T>(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
) -> PolicyDecision<T> {
    PolicyDecision::from_error(classify_dav_status(
        context,
        status,
        headers,
        body,
        is_upload_session,
    ))
}

pub(super) fn dav_mutation_policy_decision<T>(
    context: &str,
    resp: HttpResponse,
    is_upload_session: bool,
    on_ok: impl FnOnce(HttpResponse) -> T,
) -> PolicyDecision<T> {
    if resp.status == StatusCode::MULTI_STATUS {
        let statuses = match parse_multistatus_statuses(&resp.body) {
            Ok(s) => s,
            Err(e) => return PolicyDecision::Fail(e),
        };
        if statuses.is_empty() {
            return PolicyDecision::Fail(Error::protocol(format!(
                "{context}: HTTP 207 Multi-Status contained no response statuses"
            )));
        }
        let failures: Vec<(StatusCode, String)> = statuses
            .iter()
            .filter_map(|item| match item.status_code {
                Some(code) if (200..300).contains(&code) => None,
                Some(code) => StatusCode::from_u16(code)
                    .ok()
                    .map(|sc| (sc, item.href.clone())),
                None => Some((StatusCode::BAD_GATEWAY, item.href.clone())),
            })
            .collect();
        if !failures.is_empty() {
            let mut first_retryable: Option<Error> = None;
            for (sc, href) in failures {
                let sub_ctx = if href.is_empty() {
                    context.to_string()
                } else {
                    format!("{context} ({href})")
                };
                let err =
                    classify_dav_status(&sub_ctx, sc, &resp.headers, &resp.body, is_upload_session);
                if !err.is_retryable() {
                    return PolicyDecision::Fail(err);
                }
                if first_retryable.is_none() {
                    first_retryable = Some(err);
                }
            }
            if let Some(err) = first_retryable {
                return PolicyDecision::from_error(err);
            }
        }
        return PolicyDecision::Ok(on_ok(resp));
    }
    if resp.status.is_success() {
        return PolicyDecision::Ok(on_ok(resp));
    }
    dav_error_decision(
        context,
        resp.status,
        &resp.headers,
        &resp.body,
        is_upload_session,
    )
}

fn classify_dav_status(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
) -> Error {
    let retry_after = parse_retry_after(headers);
    let snippet = String::from_utf8_lossy(&body[..body.len().min(200)]);
    let msg = format!("{context}: HTTP {} ({snippet})", status.as_u16());
    let mut err = match status.as_u16() {
        401 | 403 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg),
        404 | 410 if is_upload_session => {
            Error::new(ErrorKind::NotFound, RetryClass::SessionExpired, msg)
        }
        404 | 410 => Error::new(ErrorKind::NotFound, RetryClass::Permanent, msg),
        408 => Error::new(ErrorKind::Timeout, RetryClass::Retryable, msg),
        409 | 412 => Error::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg),
        423 => Error::new(ErrorKind::LockBusy, RetryClass::Retryable, msg),
        429 | 503 => Error::new(ErrorKind::RateLimited, RetryClass::Throttled, msg),
        507 => Error::new(ErrorKind::QuotaExceeded, RetryClass::Permanent, msg),
        500..=599 => Error::new(ErrorKind::Network, RetryClass::Retryable, msg),
        _ => Error::new(ErrorKind::Protocol, RetryClass::Permanent, msg),
    };
    if let Some(ra) = retry_after {
        err = err.with_retry_after(ra);
    }
    err
}

fn encode_url_path(path: &str) -> String {
    crate::common::http::percent_encode_path(path)
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                decode_hex_nibble(bytes[i + 1]),
                decode_hex_nibble(bytes[i + 2]),
            )
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

#[async_trait]
impl StorageBackend for WebdavBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "webdav"
    }

    fn endpoint_identity(&self) -> String {
        format!("webdav://{}", self.inner.base_url)
    }

    fn capabilities(&self) -> Capabilities {
        let supports_chunked = self.inner.chunked_root.is_some();
        let single_shot_max = if supports_chunked {
            self.inner
                .cfg
                .single_shot_max_bytes
                .unwrap_or(DEFAULT_WEBDAV_SINGLE_SHOT_MAX)
        } else {
            u64::MAX
        };
        let default_chunk = self
            .inner
            .cfg
            .default_chunk_size
            .unwrap_or(DEFAULT_WEBDAV_CHUNK_SIZE);

        Capabilities {
            // No server-guaranteed content hash. Nextcloud/ownCloud `OC-Checksum` values are
            // client-supplied metadata (Nextcloud never validates them), so they are only
            // used inside this backend (see `transfer.rs`) and never reported as
            // `Entry::checksum`.
            hashes: vec![],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: self.inner.cfg.vendor.supports_oc_mtime(),
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: 1,
                max_chunk_bytes: supports_chunked.then_some(MAX_NEXTCLOUD_CHUNK_BYTES),
            },
            single_shot_max_bytes: single_shot_max,
            default_chunk_size: default_chunk,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        self.stat_impl(path).await
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_with_options(prefix, &ListOptions::new().with_recursive(recursive))
            .await
    }

    async fn list_with_options(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        self.list_with_options_impl(prefix, options).await
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        self.mkdir_impl(path).await
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.delete_impl(path).await
    }

    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
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

    async fn about(&self) -> Result<Option<StorageQuota>> {
        self.about_impl().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_transport::TransportConfig;

    #[test]
    fn percent_decode_path_handles_malformed_multibyte_percent_without_panic() {
        assert_eq!(
            percent_decode_path("dir/hello%20world.txt"),
            "dir/hello world.txt"
        );
        assert_eq!(percent_decode_path("dir/%aé.txt"), "dir/%aé.txt");
        assert_eq!(percent_decode_path("dir/%中.txt"), "dir/%中.txt");
    }

    #[test]
    fn basic_and_bearer_auth_headers_are_marked_sensitive() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();

        let mut basic_cfg = WebdavConfig::new("dav-basic", "https://dav.example.com/files");
        basic_cfg.auth = WebdavAuth::Basic {
            username: "alice".into(),
            password: "super-secret-dav-password".into(),
        };
        let basic_backend = WebdavBackend::new(basic_cfg, transport.clone()).unwrap();
        let mut basic_hdrs = HeaderMap::new();
        basic_backend.apply_auth(&mut basic_hdrs);
        let basic_val = basic_hdrs
            .get(http::header::AUTHORIZATION)
            .expect("Basic Authorization header must be present");
        assert!(basic_val.is_sensitive());
        assert!(!format!("{basic_val:?}").contains("Basic "));

        let mut bearer_cfg = WebdavConfig::new("dav-bearer", "https://dav.example.com/files");
        bearer_cfg.auth = WebdavAuth::Bearer {
            token: "super-secret-dav-token-12345".into(),
        };
        let bearer_backend = WebdavBackend::new(bearer_cfg, transport.clone()).unwrap();
        let mut bearer_hdrs = HeaderMap::new();
        bearer_backend.apply_auth(&mut bearer_hdrs);
        let bearer_val = bearer_hdrs
            .get(http::header::AUTHORIZATION)
            .expect("Bearer Authorization header must be present");
        assert!(bearer_val.is_sensitive());
        assert!(!format!("{bearer_val:?}").contains("super-secret-dav-token-12345"));

        let anon_backend = WebdavBackend::new(
            WebdavConfig::new("dav-anon", "https://dav.example.com/files"),
            transport,
        )
        .unwrap();
        let mut anon_hdrs = HeaderMap::new();
        anon_backend.apply_auth(&mut anon_hdrs);
        assert!(anon_hdrs.get(http::header::AUTHORIZATION).is_none());
    }

    #[test]
    fn classify_dav_status_distinguishes_throttled_timeout_retryable_and_permanent() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("7"));

        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let err = classify_dav_status("op", status, &hdrs, b"busy", false);
            assert_eq!(err.kind, ErrorKind::RateLimited);
            assert_eq!(err.retry, RetryClass::Throttled);
            assert!(err.is_throttled());
            assert_eq!(err.retry_after, Some(Duration::from_secs(7)));
        }

        let timeout = classify_dav_status(
            "op",
            StatusCode::REQUEST_TIMEOUT,
            &HeaderMap::new(),
            b"",
            false,
        );
        assert_eq!(timeout.kind, ErrorKind::Timeout);
        assert_eq!(timeout.retry, RetryClass::Retryable);
        assert!(!timeout.is_throttled());

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = classify_dav_status("op", status, &HeaderMap::new(), b"err", false);
            assert_eq!(err.kind, ErrorKind::Network);
            assert_eq!(err.retry, RetryClass::Retryable);
            assert!(!err.is_throttled());
        }

        let quota = classify_dav_status(
            "op",
            StatusCode::INSUFFICIENT_STORAGE,
            &HeaderMap::new(),
            b"",
            false,
        );
        assert_eq!(quota.kind, ErrorKind::QuotaExceeded);
        assert_eq!(quota.retry, RetryClass::Permanent);

        let expired =
            classify_dav_status("op", StatusCode::NOT_FOUND, &HeaderMap::new(), b"", true);
        assert_eq!(expired.kind, ErrorKind::NotFound);
        assert_eq!(expired.retry, RetryClass::SessionExpired);

        let locked = classify_dav_status(
            "op",
            StatusCode::LOCKED,
            &HeaderMap::new(),
            b"locked",
            false,
        );
        assert_eq!(locked.kind, ErrorKind::LockBusy);
        assert_eq!(locked.retry, RetryClass::Retryable);
        assert!(locked.is_retryable());
    }

    #[test]
    fn href_to_rel_handles_case_insensitive_scheme_and_encoded_base_url() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let cfg = WebdavConfig::new("dav-enc", "https://dav.example.com/my files/café");
        let backend = WebdavBackend::new(cfg, transport).unwrap();
        assert_eq!(
            backend.url_for_rel("sub dir/a b.txt"),
            "https://dav.example.com/my%20files/caf%C3%A9/sub%20dir/a%20b.txt"
        );
        assert_eq!(
            backend.dir_url_for_rel("sub dir"),
            "https://dav.example.com/my%20files/caf%C3%A9/sub%20dir/"
        );
        assert_eq!(
            backend.dir_url_for_rel(""),
            "https://dav.example.com/my%20files/caf%C3%A9/"
        );
        let (raw, rel) = backend
            .href_to_rel("HTTPS://dav.example.com/my%20files/caf%C3%A9/sub%20dir/a%20b.txt")
            .expect("uppercase HTTPS scheme must match");
        assert_eq!(raw, "sub dir/a b.txt");
        assert_eq!(rel.as_str(), "sub dir/a b.txt");

        let (raw2, rel2) = backend
            .href_to_rel("HTTP://dav.example.com/my%20files/caf%C3%A9/note.txt")
            .expect("uppercase HTTP scheme must match");
        assert_eq!(raw2, "note.txt");
        assert_eq!(rel2.as_str(), "note.txt");
    }
}
