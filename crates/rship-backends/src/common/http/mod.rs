//! Shared HTTP backend helpers: policy-driven retry/reconciliation engine, sensitive
//! auth header builders, watched strict-length uploads, RFC 3986 URI percent-encoding,
//! `mpsc -> EntryStream` conversion, and rclone OAuth token parsing.

#![forbid(unsafe_code)]

use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, HeaderValue, StatusCode};
use rship_core::source::ByteStream;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{
    HttpTransport, ProgressHandle, ProgressWatchdog, ScopedLimiter, WatchedByteStream,
    parse_retry_after,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use super::StrictBodyStream;
pub use super::rx_to_entry_stream;

#[cfg(test)]
mod tests;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Build an HTTP [`HeaderValue`] marked sensitive (`set_sensitive(true)`) so
/// hyper/reqwest/tracing debug formatting never prints credential material.
pub fn sensitive_header_value(raw: &str, context: &str) -> Result<HeaderValue> {
    let mut val = HeaderValue::from_str(raw)
        .map_err(|e| Error::protocol(format!("{context}: invalid header value: {e}")))?;
    val.set_sensitive(true);
    Ok(val)
}

/// Build a `"Bearer <token>"` HTTP [`HeaderValue`] marked sensitive (`set_sensitive(true)`).
pub fn bearer_header_value(token: &str) -> Result<HeaderValue> {
    sensitive_header_value(&format!("Bearer {token}"), "Authorization Bearer")
}

/// Configuration for [`execute_with_policy`] and its full/auth/reconcile variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicyConfig {
    /// Maximum number of retry attempts after the initial request (default: `5`).
    pub max_retries: u32,
    /// Base delay for full-jitter exponential backoff (default: `200ms`).
    pub base_delay: Duration,
    /// Single configurable ceiling applied to BOTH exponential backoff AND server
    /// `Retry-After` hints (default: [`rship_core::engine::DEFAULT_MAX_RETRY_DELAY`], 30 s).
    pub max_delay: Duration,
    /// Optional per-request timeout override; when `Some(d)`, sends via
    /// [`HttpTransport::send_control_request_with_timeout`].
    pub request_timeout: Option<Duration>,
    /// When `true`, acquires [`ScopedLimiter::acquire_write_permit`] before sending.
    pub is_write: bool,
    /// When `true` (e.g. for `HEAD`), skips [`HttpTransport::read_control_body`] and
    /// supplies `Bytes::new()` to the response classifier.
    pub skip_response_body: bool,
}

impl Default for RetryPolicyConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay: Duration::from_millis(200),
            max_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
            request_timeout: None,
            is_write: false,
            skip_response_body: false,
        }
    }
}

impl RetryPolicyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_delays(mut self, base_delay: Duration, max_delay: Duration) -> Self {
        self.base_delay = base_delay;
        self.max_delay = max_delay;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    pub fn with_write_permit(mut self, is_write: bool) -> Self {
        self.is_write = is_write;
        self
    }

    pub fn with_skip_response_body(mut self, skip: bool) -> Self {
        self.skip_response_body = skip;
        self
    }
}

/// Retry safety classification for an HTTP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    /// Safe to retry directly on retryable transport/timeout errors and retryable HTTP responses.
    Idempotent,
    /// Mutation (e.g. WebDAV `MOVE`/`COPY`/`MKCOL`/`DELETE`, S3 `CopyObject` with
    /// `If-None-Match`, GDrive create) that MUST NOT be blindly retried on ambiguous failure
    /// without a caller-supplied reconcile step.
    NonIdempotent,
}

/// Buffered control-plane HTTP response passed to a policy classifier.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Outcome returned by a caller's HTTP response classifier.
#[derive(Debug)]
pub enum PolicyDecision<T> {
    /// Request succeeded; refunds retry quota accurately and records CUBIC success.
    Ok(T),
    /// Credentials expired (e.g. HTTP `401` or S3 `ExpiredToken`); invokes the caller's
    /// auth-refresh hook at most once per execution without burning retry attempts or quota.
    AuthRefresh,
    /// Transient or throttled HTTP error.
    Retry(Error),
    /// Explicit reconciliation trigger (e.g. HTTP `412 PreconditionFailed` after an ambiguous
    /// prior attempt) regardless of [`Idempotency`].
    Reconcile(Error),
    /// Permanent / non-retryable error; returned immediately without touching retry quota
    /// or throttle state.
    Fail(Error),
}

impl<T> PolicyDecision<T> {
    /// Classify an [`Error`] as [`PolicyDecision::Retry`] when retryable or
    /// [`PolicyDecision::Fail`] when permanent/exhausted.
    pub fn from_error(err: Error) -> Self {
        if err.is_retryable() {
            Self::Retry(err)
        } else {
            Self::Fail(err)
        }
    }

    /// Transform a [`PolicyDecision::Ok`] payload while preserving all non-`Ok` decisions.
    pub fn map_ok<U>(self, f: impl FnOnce(T) -> U) -> PolicyDecision<U> {
        match self {
            Self::Ok(val) => PolicyDecision::Ok(f(val)),
            Self::AuthRefresh => PolicyDecision::AuthRefresh,
            Self::Retry(e) => PolicyDecision::Retry(e),
            Self::Reconcile(e) => PolicyDecision::Reconcile(e),
            Self::Fail(e) => PolicyDecision::Fail(e),
        }
    }
}

/// Classify standard transient HTTP status codes (`408`, `429`, `500..=599`) into
/// retryable/throttled [`Error`] values preserving `Retry-After` headers.
pub fn classify_common_http_status(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body_snippet: &str,
) -> Option<Error> {
    let retry_after = parse_retry_after(headers);
    let trimmed = body_snippet.trim();
    let suffix = if trimmed.is_empty() {
        String::new()
    } else {
        format!(": {trimmed}")
    };
    if status == StatusCode::REQUEST_TIMEOUT {
        let mut err = Error::timeout(format!("{context}: HTTP 408 Request Timeout{suffix}"));
        if let Some(ra) = retry_after {
            err = err.with_retry_after(ra);
        }
        return Some(err);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Some(Error::rate_limited(
            format!("{context}: HTTP 429 Too Many Requests{suffix}"),
            retry_after,
        ));
    }
    if status.is_server_error() {
        let retry = if status == StatusCode::SERVICE_UNAVAILABLE {
            RetryClass::Throttled
        } else {
            RetryClass::Retryable
        };
        let mut err = Error::new(
            ErrorKind::Network,
            retry,
            format!("{context}: HTTP {}{suffix}", status.as_u16()),
        );
        if let Some(ra) = retry_after {
            err = err.with_retry_after(ra);
        }
        return Some(err);
    }
    None
}

/// Standard HTTP response -> [`PolicyDecision`] adapter supporting optional `404`
/// pass-through and `401` credential refresh.
pub fn policy_decision_from_http(
    resp: HttpResponse,
    allow_not_found: bool,
    auth_refresh_on_401: bool,
    map_err: impl FnOnce(StatusCode, &HeaderMap, &[u8]) -> Error,
) -> PolicyDecision<(StatusCode, HeaderMap, Bytes)> {
    if resp.status.is_success() || (allow_not_found && resp.status == StatusCode::NOT_FOUND) {
        return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
    }
    if auth_refresh_on_401 && resp.status == StatusCode::UNAUTHORIZED {
        return PolicyDecision::AuthRefresh;
    }
    PolicyDecision::from_error(map_err(resp.status, &resp.headers, &resp.body))
}

/// Action returned by a caller-supplied reconciliation hook after an ambiguous failure
/// or explicit [`PolicyDecision::Reconcile`].
#[derive(Debug)]
pub enum ReconcileAction<T> {
    /// Reconciliation confirmed the operation already committed; record success and return `Ok(val)`.
    Resolved(T),
    /// Reconciliation confirmed the operation did NOT commit; proceed to charge retry quota,
    /// sleep backoff, and retry.
    ///
    /// Carries the error to surface if the retry budget is exhausted. Hooks should hand back
    /// the error they were given so its `source` chain (e.g. the underlying I/O or TLS error)
    /// survives into the final report.
    Retry(Error),
    /// Reconciliation failed or determined the operation cannot be retried; return `Err(err)`.
    Fail(Error),
}

enum SendStepError {
    Build(Error),
    Transport(Error),
}

/// Execute a control-plane HTTP request under the shared retry/rate-limit policy
/// without auth-refresh or reconciliation hooks.
///
/// When `idempotency == Idempotency::NonIdempotent`, ambiguous transport/HTTP failures
/// fail fast with `retries_exhausted() == true` instead of blindly retrying.
pub async fn execute_with_policy<T, BuildFn, BuildFut, ClassifyFn>(
    transport: &HttpTransport,
    limiter: &ScopedLimiter,
    context: &str,
    cfg: &RetryPolicyConfig,
    idempotency: Idempotency,
    mut build_req: BuildFn,
    classify: ClassifyFn,
) -> Result<T>
where
    BuildFn: FnMut() -> BuildFut,
    BuildFut: Future<Output = Result<reqwest::RequestBuilder>>,
    ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
{
    execute_with_policy_full(
        transport,
        limiter,
        context,
        cfg,
        idempotency,
        || {
            let fut = build_req();
            async move { fut.await.map(|req| (req, ())) }
        },
        |()| async { Ok(false) },
        classify,
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
}

/// Execute a control-plane HTTP request under the shared retry/rate-limit policy
/// with single-shot credential refresh (`on_auth_refresh`) and no reconciliation hook.
#[allow(clippy::too_many_arguments)]
pub async fn execute_with_auth_policy<
    T,
    AuthCtx,
    BuildFn,
    BuildFut,
    RefreshFn,
    RefreshFut,
    ClassifyFn,
>(
    transport: &HttpTransport,
    limiter: &ScopedLimiter,
    context: &str,
    cfg: &RetryPolicyConfig,
    idempotency: Idempotency,
    build_req: BuildFn,
    on_auth_refresh: RefreshFn,
    classify: ClassifyFn,
) -> Result<T>
where
    BuildFn: FnMut() -> BuildFut,
    BuildFut: Future<Output = Result<(reqwest::RequestBuilder, AuthCtx)>>,
    RefreshFn: FnMut(AuthCtx) -> RefreshFut,
    RefreshFut: Future<Output = Result<bool>>,
    ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
{
    execute_with_policy_full(
        transport,
        limiter,
        context,
        cfg,
        idempotency,
        build_req,
        on_auth_refresh,
        classify,
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
}

/// Execute a control-plane HTTP request under the shared retry/rate-limit policy
/// with caller-supplied reconciliation (`reconcile`) and no auth-refresh hook.
#[allow(clippy::too_many_arguments)]
pub async fn execute_with_reconcile_policy<
    T,
    BuildFn,
    BuildFut,
    ClassifyFn,
    ReconcileFn,
    ReconcileFut,
>(
    transport: &HttpTransport,
    limiter: &ScopedLimiter,
    context: &str,
    cfg: &RetryPolicyConfig,
    idempotency: Idempotency,
    mut build_req: BuildFn,
    classify: ClassifyFn,
    reconcile: ReconcileFn,
) -> Result<T>
where
    BuildFn: FnMut() -> BuildFut,
    BuildFut: Future<Output = Result<reqwest::RequestBuilder>>,
    ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
    ReconcileFn: FnMut(Error) -> ReconcileFut,
    ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
{
    execute_with_policy_full(
        transport,
        limiter,
        context,
        cfg,
        idempotency,
        || {
            let fut = build_req();
            async move { fut.await.map(|req| (req, ())) }
        },
        |()| async { Ok(false) },
        classify,
        reconcile,
    )
    .await
}

/// Full shared control-plane HTTP execution engine supporting:
/// - Scoped send + optional write-QPS permit acquisition
/// - Optional per-request timeout override and `HEAD`/body-skip mode
/// - At-most-once credential refresh (`PolicyDecision::AuthRefresh`) without burning
///   retry attempts or retry quota
/// - Exact retry-quota charging & refunding (distinguishing timeout vs standard retries)
/// - Full-jitter exponential backoff and `Retry-After` strictly capped at `cfg.max_delay`
/// - Non-idempotent safety & explicit reconciliation (`Idempotency::NonIdempotent` and
///   `PolicyDecision::Reconcile`)
/// - `retries_exhausted` marking on exhausted/unreconciled errors to prevent stacked retries
#[allow(clippy::too_many_arguments)]
pub async fn execute_with_policy_full<
    T,
    AuthCtx,
    BuildFn,
    BuildFut,
    RefreshFn,
    RefreshFut,
    ClassifyFn,
    ReconcileFn,
    ReconcileFut,
>(
    transport: &HttpTransport,
    limiter: &ScopedLimiter,
    context: &str,
    cfg: &RetryPolicyConfig,
    idempotency: Idempotency,
    mut build_req: BuildFn,
    on_auth_refresh: RefreshFn,
    classify: ClassifyFn,
    reconcile: ReconcileFn,
) -> Result<T>
where
    BuildFn: FnMut() -> BuildFut,
    BuildFut: Future<Output = Result<(reqwest::RequestBuilder, AuthCtx)>>,
    RefreshFn: FnMut(AuthCtx) -> RefreshFut,
    RefreshFut: Future<Output = Result<bool>>,
    ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
    ReconcileFn: FnMut(Error) -> ReconcileFut,
    ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
{
    execute_policy_loop(
        limiter,
        context,
        cfg,
        idempotency,
        || {
            let req_fut = build_req();
            async move {
                let (req, auth_ctx) = req_fut.await.map_err(SendStepError::Build)?;
                let resp = match cfg.request_timeout {
                    Some(timeout) => {
                        transport
                            .send_control_request_with_timeout(context, req, timeout)
                            .await
                    }
                    None => transport.send_control_request(context, req).await,
                }
                .map_err(SendStepError::Transport)?;

                let status = resp.status();
                let headers = resp.headers().clone();
                let body = if cfg.skip_response_body {
                    Bytes::new()
                } else {
                    transport
                        .read_control_body(resp)
                        .await
                        .map_err(SendStepError::Transport)?
                };
                Ok((
                    HttpResponse {
                        status,
                        headers,
                        body,
                    },
                    auth_ctx,
                ))
            }
        },
        on_auth_refresh,
        classify,
        reconcile,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_policy_loop<
    T,
    AuthCtx,
    SendFn,
    SendFut,
    RefreshFn,
    RefreshFut,
    ClassifyFn,
    ReconcileFn,
    ReconcileFut,
>(
    limiter: &ScopedLimiter,
    context: &str,
    cfg: &RetryPolicyConfig,
    idempotency: Idempotency,
    mut send_once: SendFn,
    mut on_auth_refresh: RefreshFn,
    mut classify: ClassifyFn,
    mut reconcile: ReconcileFn,
) -> Result<T>
where
    SendFn: FnMut() -> SendFut,
    SendFut: Future<Output = std::result::Result<(HttpResponse, AuthCtx), SendStepError>>,
    RefreshFn: FnMut(AuthCtx) -> RefreshFut,
    RefreshFut: Future<Output = Result<bool>>,
    ClassifyFn: FnMut(HttpResponse) -> PolicyDecision<T>,
    ReconcileFn: FnMut(Error) -> ReconcileFut,
    ReconcileFut: Future<Output = Result<ReconcileAction<T>>>,
{
    let mut attempt = 0u32;
    let mut had_timeout = false;
    let mut auth_refreshed = false;

    loop {
        limiter.acquire_send_permit().await;
        if cfg.is_write {
            limiter.acquire_write_permit().await;
        }

        let (err, must_reconcile, retry_after) = match send_once().await {
            Ok((response, auth_ctx)) => {
                let status = response.status;
                let header_retry_after = parse_retry_after(&response.headers);
                match classify(response) {
                    PolicyDecision::Ok(val) => {
                        limiter.record_success(attempt > 0, had_timeout);
                        return Ok(val);
                    }
                    PolicyDecision::AuthRefresh => {
                        if !auth_refreshed {
                            match on_auth_refresh(auth_ctx).await {
                                Ok(true) => {
                                    auth_refreshed = true;
                                    continue;
                                }
                                Ok(false) => {
                                    return Err(Error::permission_denied(format!(
                                        "{context}: HTTP {} authentication failed (credentials could not be refreshed)",
                                        status.as_u16()
                                    )));
                                }
                                Err(err) => {
                                    if !err.is_retryable() {
                                        return Err(err);
                                    }
                                    if err.is_throttled() {
                                        limiter.record_throttle();
                                    }
                                    let ra = err.retry_after;
                                    (err, false, ra)
                                }
                            }
                        } else {
                            return Err(Error::permission_denied(format!(
                                "{context}: HTTP {} authentication failed after credential refresh",
                                status.as_u16()
                            )));
                        }
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
                        // RFC 6585: a `429` means the request was NOT processed, so even a
                        // non-idempotent request can be resent without reconciling first
                        // (a reconcile probe would just add another throttled request).
                        let rejected_unprocessed = status == StatusCode::TOO_MANY_REQUESTS;
                        (
                            err,
                            idempotency == Idempotency::NonIdempotent && !rejected_unprocessed,
                            ra,
                        )
                    }
                }
            }
            Err(SendStepError::Build(err)) => {
                if !err.is_retryable() {
                    return Err(err);
                }
                if err.is_throttled() {
                    limiter.record_throttle();
                }
                let ra = err.retry_after;
                (err, false, ra)
            }
            Err(SendStepError::Transport(err)) => {
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
                // Keep the hook's error intact (kind, message AND `source` chain).
                Ok(ReconcileAction::Retry(e)) => match (e.retry_after, retry_after) {
                    (None, Some(ra)) => e.with_retry_after(ra),
                    _ => e,
                },
            }
        } else {
            err
        };

        if attempt < cfg.max_retries && limiter.try_acquire_retry_quota(is_timeout) {
            if is_timeout {
                had_timeout = true;
            }
            attempt += 1;
            let delay = limiter.backoff_delay(attempt, cfg.base_delay, cfg.max_delay, retry_after);
            // Sleep through the limiter's injectable clock (identical to `tokio::time::sleep`
            // in production; virtualised under DST).
            limiter.sleep(delay).await;
            continue;
        }

        return Err(err_for_exhausted.with_retries_exhausted());
    }
}

/// Percent-encode a single URI path segment per RFC 3986 (leaving `[A-Za-z0-9._~-]` unescaped;
/// encodes `/` as `%2F`).
pub fn percent_encode_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}

/// Percent-encode a URI path per RFC 3986 while preserving `/` path separators.
pub fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}

/// Wraps a fixed-length upload body stream and signals [`ProgressHandle::mark_body_eof`]
/// as soon as `expected_len` bytes have been yielded (or immediately on creation when
/// `expected_len == 0`).
///
/// Hyper's HTTP/1.1 sized `Content-Length` encoder stops polling the request body stream
/// as soon as `expected_len` bytes are yielded — without polling for a trailing
/// `Poll::Ready(None)` (and never polls the stream at all for `Content-Length: 0`).
/// Signaling body EOF at exact byte completion ensures [`ProgressWatchdog`] transitions
/// from `data_stall_timeout` to `data_finalize_timeout` while waiting for server-side
/// commit/assembly.
///
/// "Yielded to hyper" is not "on the wire": a blackhole during the final buffered bytes (or
/// during a whole single-chunk body) is only caught by the finalize timeout. See the
/// "Known limitation" section of [`rship_transport::watchdog`].
pub struct SizedEofStream<S> {
    inner: S,
    expected_len: u64,
    seen_len: u64,
    progress: ProgressHandle,
    eof_signaled: bool,
}

impl<S> SizedEofStream<S> {
    pub fn new(inner: S, expected_len: u64, progress: ProgressHandle) -> Self {
        let eof_signaled = expected_len == 0;
        if eof_signaled {
            progress.mark_body_eof();
        }
        Self {
            inner,
            expected_len,
            seen_len: 0,
            progress,
            eof_signaled,
        }
    }
}

impl<S> Stream for SizedEofStream<S>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.seen_len = this.seen_len.saturating_add(chunk.len() as u64);
                if !this.eof_signaled && this.seen_len >= this.expected_len {
                    this.eof_signaled = true;
                    this.progress.mark_body_eof();
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                if !this.eof_signaled {
                    this.eof_signaled = true;
                    this.progress.mark_body_eof();
                }
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Wrap an outbound fixed-length upload stream with both [`ProgressWatchdog::watch_upload_stream`]
/// (byte-progress tracking) and [`SizedEofStream`] (exact-length EOF signaling).
///
/// Wrapping [`WatchedByteStream`] inside [`SizedEofStream`] ensures byte progress is recorded
/// before `mark_body_eof` wakes the watchdog on the final chunk.
pub fn watch_sized_upload_stream<S>(
    watchdog: &ProgressWatchdog,
    stream: S,
    expected_len: u64,
) -> SizedEofStream<WatchedByteStream<S>>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    let progress = watchdog.handle();
    SizedEofStream::new(watchdog.watch_upload_stream(stream), expected_len, progress)
}

pub async fn send_watched_body_with_capture<S>(
    transport: &HttpTransport,
    context: &str,
    req: reqwest::RequestBuilder,
    watched_stream: S,
    captured_err: Arc<StdMutex<Option<Error>>>,
    watchdog: &ProgressWatchdog,
) -> Result<reqwest::Response>
where
    S: Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
{
    let req = req.body(reqwest::Body::wrap_stream(watched_stream));
    let resp = match transport.send_watched_request(context, req, watchdog).await {
        Ok(r) => r,
        Err(e) => {
            if let Some(root) = super::lock_unpoisoned(&captured_err).take() {
                return Err(root);
            }
            return Err(e);
        }
    };
    if let Some(root) = super::lock_unpoisoned(&captured_err).take() {
        return Err(root);
    }
    Ok(resp)
}

/// Send a fixed-length upload stream wrapped with [`watch_sized_upload_stream`]
/// ([`WatchedByteStream`] strictly inside [`SizedEofStream`]) and capture root-cause
/// stream errors into `captured_err`.
///
/// Handles 0-byte uploads immediately via [`SizedEofStream`] EOF signaling so HTTP/1.1
/// `Content-Length: 0` requests transition directly to `data_finalize_timeout`.
pub async fn send_watched_sized_upload_with_capture<S>(
    transport: &HttpTransport,
    context: &str,
    req: reqwest::RequestBuilder,
    stream: S,
    expected_len: u64,
    captured_err: Arc<StdMutex<Option<Error>>>,
) -> Result<reqwest::Response>
where
    S: Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
{
    let watchdog = transport.data_watchdog();
    let watched = watch_sized_upload_stream(&watchdog, stream, expected_len);
    send_watched_body_with_capture(transport, context, req, watched, captured_err, &watchdog).await
}

/// Send an upload request whose body stream is wrapped with [`ProgressWatchdog`] and
/// captures root-cause stream errors into `captured_err` so reqwest never masks
/// `SourceMutated` / short-EOF failures behind a generic transport error.
pub async fn send_watched_stream_with_capture<S>(
    transport: &HttpTransport,
    context: &str,
    req: reqwest::RequestBuilder,
    stream: S,
    captured_err: Arc<StdMutex<Option<Error>>>,
    watchdog: ProgressWatchdog,
) -> Result<reqwest::Response>
where
    S: Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
{
    let watched = watchdog.watch_upload_stream(stream);
    send_watched_body_with_capture(transport, context, req, watched, captured_err, &watchdog).await
}

/// Send a streaming HTTP upload enforcing exact `expected_len` bytes via [`StrictBodyStream`],
/// byte-progress idle stall protection via [`ProgressWatchdog`], and exact-length body-EOF
/// signaling via [`SizedEofStream`] so HTTP/1.1 `Content-Length` uploads transition cleanly
/// to `data_finalize_timeout` (including 0-byte uploads).
pub async fn send_strict_upload(
    transport: &HttpTransport,
    context: &str,
    label: &'static str,
    req: reqwest::RequestBuilder,
    body: ByteStream,
    expected_len: u64,
) -> Result<reqwest::Response> {
    let captured_err: Arc<StdMutex<Option<Error>>> = Arc::new(StdMutex::new(None));
    let strict = StrictBodyStream::new(label, body, expected_len, captured_err.clone());
    send_watched_sized_upload_with_capture(
        transport,
        context,
        req,
        strict,
        expected_len,
        captured_err,
    )
    .await
}

/// Parse an `rclone.conf` OAuth2 `token = {...}` JSON blob (which stores RFC 3339 `"expiry"`)
/// into a normalized [`rship_transport::oauth::OAuthToken`].
#[cfg(any(
    feature = "dropbox",
    feature = "gcs",
    feature = "gdrive",
    feature = "onedrive"
))]
pub fn parse_rclone_oauth_token(
    raw_json: &str,
) -> std::result::Result<rship_transport::oauth::OAuthToken, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct RcloneTokenJson {
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        refresh_token: Option<String>,
        #[serde(default)]
        token_type: Option<String>,
        #[serde(default)]
        expiry: Option<String>,
        #[serde(default)]
        expires_at_unix_secs: Option<i64>,
        #[serde(default)]
        scope: Option<String>,
    }

    let parsed: RcloneTokenJson = serde_json::from_str(raw_json)?;
    let expires_at_unix_secs = parsed
        .expiry
        .as_deref()
        .and_then(rship_core::time::parse_rfc3339_to_secs)
        .or(parsed.expires_at_unix_secs)
        .unwrap_or(0);
    Ok(rship_transport::oauth::OAuthToken {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token.filter(|s| !s.is_empty()),
        token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
        expires_at_unix_secs,
        scope: parsed.scope,
    })
}
