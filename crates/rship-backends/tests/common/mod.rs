#![allow(dead_code)]
//! Shared HTTP mock fault-injection harness reused across provider conformance suites
//! (`s3`, `gdrive`, `azureblob`, `gcs`, `dropbox`, `onedrive`, `webdav`).
//!
//! Deliberately avoids importing any feature-gated backend symbols so every integration
//! test binary can `mod common;` regardless of which single backend feature is enabled.

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, HeaderName, HeaderValue, RETRY_AFTER};
use axum::response::Response;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Wildcard operation key matching any operation when no operation-specific fault is queued.
pub const WILDCARD_OP: &str = "*";

/// A single fault injected into a mock HTTP backend handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectedFault {
    /// Return an immediate HTTP error response before executing the handler mutation.
    HttpStatus {
        status: StatusCode,
        retry_after: Option<String>,
        content_type: &'static str,
        body: String,
    },
    /// Return HTTP `200 OK` containing an embedded S3 `<Error>` XML document (including
    /// leading keep-alive whitespace as AWS S3 emits on `CompleteMultipartUpload` / `CopyObject`).
    Ok200XmlError { code: String, message: String },
    /// Return HTTP `200 OK` streaming `prefix` bytes and then aborting the body stream
    /// with `std::io::ErrorKind::ConnectionReset`.
    MidBodyReset { prefix: Bytes },
    /// Signal the handler to commit the mutation to mock state first, then return the
    /// specified HTTP failure response (simulating a lost response after server-side commit).
    CommitThenError {
        status: StatusCode,
        retry_after: Option<String>,
        content_type: &'static str,
        body: String,
    },
    /// Signal the handler to commit the mutation to mock state first, then stream a
    /// mid-body connection reset / abrupt stream drop.
    CommitThenReset,
    /// Signal the handler to drain the request body, sleep for `delay`, and then proceed
    /// with normal request execution (for testing slow finalize / stall watchdog handling).
    SlowFinalize { delay: Duration },
}

impl InjectedFault {
    /// Construct an HTTP `429 Too Many Requests` fault with an optional `Retry-After` header.
    pub fn too_many_requests(retry_after: Option<&str>) -> Self {
        Self::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: retry_after.map(str::to_string),
            content_type: "text/plain; charset=utf-8",
            body: "Too Many Requests".to_string(),
        }
    }

    /// Construct an HTTP `503 Service Unavailable` fault with an optional `Retry-After` header.
    pub fn service_unavailable(retry_after: Option<&str>) -> Self {
        Self::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: retry_after.map(str::to_string),
            content_type: "text/plain; charset=utf-8",
            body: "Service Unavailable".to_string(),
        }
    }

    /// Construct an AWS S3 HTTP `503 Service Unavailable` `<Code>SlowDown</Code>` XML fault
    /// with an optional `Retry-After` header.
    pub fn s3_slow_down(retry_after: Option<&str>) -> Self {
        Self::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: retry_after.map(str::to_string),
            content_type: "application/xml",
            body: format_s3_error_xml("SlowDown", "Please reduce your request rate."),
        }
    }

    /// Construct a JSON HTTP error fault (without `Retry-After`; chain [`Self::with_retry_after`]
    /// if needed).
    pub fn json_error(status: StatusCode, body: impl Into<String>) -> Self {
        Self::HttpStatus {
            status,
            retry_after: None,
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// Construct an S3-style XML HTTP error fault (without `Retry-After`; chain
    /// [`Self::with_retry_after`] if needed).
    pub fn xml_error(status: StatusCode, code: &str, message: &str) -> Self {
        Self::HttpStatus {
            status,
            retry_after: None,
            content_type: "application/xml",
            body: format_s3_error_xml(code, message),
        }
    }

    /// Construct an HTTP `200 OK` embedded XML `<Error>` fault.
    pub fn ok_200_xml_error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Ok200XmlError {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Construct a mid-body connection-reset fault streaming `prefix` bytes first.
    pub fn mid_body_reset(prefix: impl Into<Bytes>) -> Self {
        Self::MidBodyReset {
            prefix: prefix.into(),
        }
    }

    /// Construct a post-commit HTTP error fault with custom content type and body.
    pub fn commit_then_error(
        status: StatusCode,
        content_type: &'static str,
        body: impl Into<String>,
    ) -> Self {
        Self::CommitThenError {
            status,
            retry_after: None,
            content_type,
            body: body.into(),
        }
    }

    /// Construct a post-commit S3-style XML HTTP error fault.
    pub fn commit_then_xml_error(status: StatusCode, code: &str, message: &str) -> Self {
        Self::CommitThenError {
            status,
            retry_after: None,
            content_type: "application/xml",
            body: format_s3_error_xml(code, message),
        }
    }

    /// Construct a post-commit JSON HTTP error fault.
    pub fn commit_then_json_error(status: StatusCode, body: impl Into<String>) -> Self {
        Self::CommitThenError {
            status,
            retry_after: None,
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// Construct a post-commit mid-body reset fault.
    pub fn commit_then_reset() -> Self {
        Self::CommitThenReset
    }

    /// Construct a slow-finalize delay fault.
    pub fn slow_finalize(delay: Duration) -> Self {
        Self::SlowFinalize { delay }
    }

    /// Attach or override the `Retry-After` header value on `HttpStatus` or `CommitThenError`.
    pub fn with_retry_after(mut self, value: impl Into<String>) -> Self {
        let ra = Some(value.into());
        match &mut self {
            Self::HttpStatus { retry_after, .. } | Self::CommitThenError { retry_after, .. } => {
                *retry_after = ra;
            }
            _ => {}
        }
        self
    }

    /// Returns `true` if this fault must be applied *after* the handler commits its mutation.
    pub fn is_post_commit(&self) -> bool {
        matches!(self, Self::CommitThenError { .. } | Self::CommitThenReset)
    }

    /// Convert an immediate pre-commit fault (`HttpStatus`, `Ok200XmlError`, `MidBodyReset`)
    /// into an Axum [`Response`]; returns `Err(self)` for post-commit or `SlowFinalize` faults.
    pub fn into_pre_commit_response(self) -> Result<Response, Self> {
        match self {
            Self::HttpStatus {
                status,
                retry_after,
                content_type,
                body,
            } => Ok(build_http_error_response(
                status,
                retry_after.as_deref(),
                content_type,
                body,
            )),
            Self::Ok200XmlError { code, message } => {
                Ok(build_ok200_xml_error_response(&code, &message))
            }
            Self::MidBodyReset { prefix } => Ok(build_mid_body_reset_response(prefix)),
            other => Err(other),
        }
    }

    /// Convert a post-commit fault (`CommitThenError`, `CommitThenReset`) into an Axum
    /// [`Response`]; returns `None` for other variants.
    pub fn into_post_commit_response(self) -> Option<Response> {
        match self {
            Self::CommitThenError {
                status,
                retry_after,
                content_type,
                body,
            } => Some(build_http_error_response(
                status,
                retry_after.as_deref(),
                content_type,
                body,
            )),
            Self::CommitThenReset => Some(build_commit_then_reset_response()),
            _ => None,
        }
    }
}

/// Per-request probabilities (each in `0.0..=1.0`) for [`FaultInjector::seeded`].
///
/// On each intercepted request where no scripted fault is queued, a single uniform draw
/// `u in [0.0, 1.0)` is tested against the cumulative intervals in fixed order:
/// 1. `throttle_429` -> HTTP `429 Too Many Requests`
/// 2. `service_unavailable_503` -> HTTP `503 Service Unavailable` (`SlowDown` XML)
/// 3. `ok_200_xml_error` -> HTTP `200 OK` embedded `<Error><Code>InternalError</Code>` XML
/// 4. `mid_body_reset` -> HTTP `200 OK` streaming `reset_prefix` then `ConnectionReset`
/// 5. `commit_then_503` -> commit first, then HTTP `503 Service Unavailable` XML
/// 6. `commit_then_reset` -> commit first, then mid-body reset
/// 7. `slow_finalize` -> sleep `slow_finalize_delay`, then succeed normally
#[derive(Debug, Clone, PartialEq)]
pub struct FaultRates {
    pub throttle_429: f64,
    pub service_unavailable_503: f64,
    pub ok_200_xml_error: f64,
    pub mid_body_reset: f64,
    pub commit_then_503: f64,
    pub commit_then_reset: f64,
    pub slow_finalize: f64,
    /// Delay used when `slow_finalize` triggers.
    pub slow_finalize_delay: Duration,
    /// Optional `Retry-After` header attached to randomly generated 429/503 responses.
    pub retry_after: Option<String>,
    /// Prefix bytes streamed before `ConnectionReset` when `mid_body_reset` triggers.
    pub reset_prefix: Bytes,
}

impl Default for FaultRates {
    fn default() -> Self {
        Self {
            throttle_429: 0.0,
            service_unavailable_503: 0.0,
            ok_200_xml_error: 0.0,
            mid_body_reset: 0.0,
            commit_then_503: 0.0,
            commit_then_reset: 0.0,
            slow_finalize: 0.0,
            slow_finalize_delay: Duration::from_millis(50),
            retry_after: Some("0".to_string()),
            reset_prefix: Bytes::from_static(b"partial-chunk"),
        }
    }
}

impl FaultRates {
    /// Zero probabilities across all fault categories.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with_throttle_429(mut self, rate: f64) -> Self {
        self.throttle_429 = rate;
        self
    }

    pub fn with_service_unavailable_503(mut self, rate: f64) -> Self {
        self.service_unavailable_503 = rate;
        self
    }

    pub fn with_ok_200_xml_error(mut self, rate: f64) -> Self {
        self.ok_200_xml_error = rate;
        self
    }

    pub fn with_mid_body_reset(mut self, rate: f64) -> Self {
        self.mid_body_reset = rate;
        self
    }

    pub fn with_commit_then_503(mut self, rate: f64) -> Self {
        self.commit_then_503 = rate;
        self
    }

    pub fn with_commit_then_reset(mut self, rate: f64) -> Self {
        self.commit_then_reset = rate;
        self
    }

    pub fn with_slow_finalize(mut self, rate: f64, delay: Duration) -> Self {
        self.slow_finalize = rate;
        self.slow_finalize_delay = delay;
        self
    }

    pub fn with_retry_after(mut self, retry_after: Option<impl Into<String>>) -> Self {
        self.retry_after = retry_after.map(Into::into);
        self
    }

    pub fn with_reset_prefix(mut self, prefix: impl Into<Bytes>) -> Self {
        self.reset_prefix = prefix.into();
        self
    }

    fn is_active(&self) -> bool {
        self.throttle_429 > 0.0
            || self.service_unavailable_503 > 0.0
            || self.ok_200_xml_error > 0.0
            || self.mid_body_reset > 0.0
            || self.commit_then_503 > 0.0
            || self.commit_then_reset > 0.0
            || self.slow_finalize > 0.0
    }

    fn select(&self, u: f64) -> Option<InjectedFault> {
        let mut cursor = 0.0;
        let ra = self.retry_after.as_deref();

        if self.throttle_429 > 0.0 {
            cursor += self.throttle_429;
            if u < cursor {
                return Some(InjectedFault::too_many_requests(ra));
            }
        }
        if self.service_unavailable_503 > 0.0 {
            cursor += self.service_unavailable_503;
            if u < cursor {
                return Some(InjectedFault::s3_slow_down(ra));
            }
        }
        if self.ok_200_xml_error > 0.0 {
            cursor += self.ok_200_xml_error;
            if u < cursor {
                return Some(InjectedFault::ok_200_xml_error(
                    "InternalError",
                    "seeded 200 OK XML error",
                ));
            }
        }
        if self.mid_body_reset > 0.0 {
            cursor += self.mid_body_reset;
            if u < cursor {
                return Some(InjectedFault::mid_body_reset(self.reset_prefix.clone()));
            }
        }
        if self.commit_then_503 > 0.0 {
            cursor += self.commit_then_503;
            if u < cursor {
                let mut fault = InjectedFault::commit_then_xml_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    "seeded lost response after commit",
                );
                if let Some(val) = ra {
                    fault = fault.with_retry_after(val);
                }
                return Some(fault);
            }
        }
        if self.commit_then_reset > 0.0 {
            cursor += self.commit_then_reset;
            if u < cursor {
                return Some(InjectedFault::commit_then_reset());
            }
        }
        if self.slow_finalize > 0.0 {
            cursor += self.slow_finalize;
            if u < cursor {
                return Some(InjectedFault::slow_finalize(self.slow_finalize_delay));
            }
        }
        None
    }
}

/// Deterministic SplitMix64 PRNG (platform- and crate-version-independent so any logged
/// seed reproduces the exact same fault sequence forever).
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0.0, 1.0)`.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }
}

/// Snapshot of request and fault-injection counts observed by a [`FaultInjector`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultTelemetry {
    pub requests_seen: usize,
    pub faults_injected: usize,
    pub per_op_requests: BTreeMap<String, usize>,
    pub per_op_faults: BTreeMap<String, usize>,
}

#[derive(Debug)]
struct SeededState {
    seed: u64,
    rng: SplitMix64,
    rates: FaultRates,
    allowed_ops: Option<HashSet<String>>,
}

#[derive(Debug, Default)]
struct FaultInjectorInner {
    queues: HashMap<String, VecDeque<InjectedFault>>,
    seeded: Option<SeededState>,
    telemetry: FaultTelemetry,
}

impl FaultInjectorInner {
    fn draw_seeded_fault(&mut self, op: &str) -> Option<InjectedFault> {
        let seeded = self.seeded.as_mut()?;
        if !seeded.rates.is_active() {
            return None;
        }
        if let Some(ref allowed) = seeded.allowed_ops
            && !allowed.contains(op)
        {
            return None;
        }
        let u = seeded.rng.next_f64();
        seeded.rates.select(u)
    }
}

/// Thread-safe, cloneable fault injector supporting both scripted per-operation fault queues
/// (including the `"*"` wildcard) and deterministic seeded pseudo-random fault injection.
#[derive(Debug, Clone, Default)]
pub struct FaultInjector {
    inner: Arc<Mutex<FaultInjectorInner>>,
}

impl FaultInjector {
    /// Create a scripted-only fault injector with empty queues and zeroed telemetry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fault injector configured with a deterministic seeded PRNG and [`FaultRates`].
    ///
    /// Scripted faults pushed via [`Self::push`] / [`Self::push_many`] still take precedence
    /// over seeded draws when present.
    pub fn seeded(seed: u64, rates: FaultRates) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FaultInjectorInner {
                queues: HashMap::new(),
                seeded: Some(SeededState {
                    seed,
                    rng: SplitMix64::new(seed),
                    rates,
                    allowed_ops: None,
                }),
                telemetry: FaultTelemetry::default(),
            })),
        }
    }

    /// Restrict seeded pseudo-random fault draws to only the given operation names.
    /// Scripted faults pushed via [`Self::push`] still apply to any operation.
    pub fn with_seeded_ops<I, S>(self, ops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(ref mut seeded) = self.inner.lock().expect("FaultInjector mutex").seeded {
            seeded.allowed_ops = Some(ops.into_iter().map(Into::into).collect());
        }
        self
    }

    /// Return the configured seed if this injector was constructed via [`Self::seeded`].
    pub fn seed(&self) -> Option<u64> {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .seeded
            .as_ref()
            .map(|s| s.seed)
    }

    /// Enqueue a single scripted fault for `op` (or [`WILDCARD_OP`] `"*"` for any operation).
    pub fn push(&self, op: impl Into<String>, fault: InjectedFault) {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .queues
            .entry(op.into())
            .or_default()
            .push_back(fault);
    }

    /// Enqueue multiple scripted faults in FIFO order for `op` (or [`WILDCARD_OP`] `"*"`).
    pub fn push_many<I>(&self, op: impl Into<String>, faults: I)
    where
        I: IntoIterator<Item = InjectedFault>,
    {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .queues
            .entry(op.into())
            .or_default()
            .extend(faults);
    }

    /// Record an observed request for `op` and return the next fault to inject, if any.
    ///
    /// Lookup precedence:
    /// 1. Exact operation queue (`op`)
    /// 2. Wildcard queue (`"*"`)
    /// 3. Seeded PRNG draw (if configured)
    pub fn next_fault(&self, op: &str) -> Option<InjectedFault> {
        let mut guard = self.inner.lock().expect("FaultInjector mutex");
        guard.telemetry.requests_seen += 1;
        *guard
            .telemetry
            .per_op_requests
            .entry(op.to_string())
            .or_insert(0) += 1;

        let fault = guard
            .queues
            .get_mut(op)
            .and_then(VecDeque::pop_front)
            .or_else(|| {
                guard
                    .queues
                    .get_mut(WILDCARD_OP)
                    .and_then(VecDeque::pop_front)
            })
            .or_else(|| guard.draw_seeded_fault(op));

        if fault.is_some() {
            guard.telemetry.faults_injected += 1;
            *guard
                .telemetry
                .per_op_faults
                .entry(op.to_string())
                .or_insert(0) += 1;
        }
        fault
    }

    /// Remove all pending scripted faults across all operations.
    pub fn clear_queues(&self) {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .queues
            .clear();
    }

    /// Reset all telemetry counters back to zero.
    pub fn reset_telemetry(&self) {
        self.inner.lock().expect("FaultInjector mutex").telemetry = FaultTelemetry::default();
    }

    /// Return a full snapshot of observed request and fault-injection counts.
    pub fn telemetry(&self) -> FaultTelemetry {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .telemetry
            .clone()
    }

    pub fn requests_seen(&self) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .telemetry
            .requests_seen
    }

    pub fn faults_injected(&self) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .telemetry
            .faults_injected
    }

    pub fn op_requests(&self, op: &str) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .telemetry
            .per_op_requests
            .get(op)
            .copied()
            .unwrap_or(0)
    }

    pub fn op_faults(&self, op: &str) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .telemetry
            .per_op_faults
            .get(op)
            .copied()
            .unwrap_or(0)
    }

    pub fn remaining_scripted(&self, op: &str) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .queues
            .get(op)
            .map_or(0, VecDeque::len)
    }

    pub fn total_remaining_scripted(&self) -> usize {
        self.inner
            .lock()
            .expect("FaultInjector mutex")
            .queues
            .values()
            .map(VecDeque::len)
            .sum()
    }
}

/// Format an S3-compatible `<Error>` XML body.
pub fn format_s3_error_xml(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
    )
}

/// Build an Axum HTTP error [`Response`] with `status`, `Content-Type`, optional `Retry-After`,
/// and body text.
pub fn build_http_error_response(
    status: StatusCode,
    retry_after: Option<&str>,
    content_type: &str,
    body: impl Into<String>,
) -> Response {
    let mut builder = Response::builder().status(status);
    if let Ok(val) = HeaderValue::from_str(content_type) {
        builder = builder.header(CONTENT_TYPE, val);
    }
    if let Some(ra) = retry_after
        && let Ok(val) = HeaderValue::from_str(ra)
    {
        builder = builder.header(RETRY_AFTER, val);
    }
    builder
        .body(Body::from(body.into()))
        .expect("valid HTTP error response")
}

/// Build an Axum HTTP error [`Response`] with additional custom headers (e.g. `x-ms-error-code`
/// or `x-amz-request-id`).
pub fn build_http_error_response_with_headers(
    status: StatusCode,
    retry_after: Option<&str>,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: impl Into<String>,
) -> Response {
    let mut builder = Response::builder().status(status);
    if let Ok(val) = HeaderValue::from_str(content_type) {
        builder = builder.header(CONTENT_TYPE, val);
    }
    if let Some(ra) = retry_after
        && let Ok(val) = HeaderValue::from_str(ra)
    {
        builder = builder.header(RETRY_AFTER, val);
    }
    for &(name, value) in extra_headers {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(hn, hv);
        }
    }
    builder
        .body(Body::from(body.into()))
        .expect("valid HTTP error response")
}

/// Build an Axum HTTP `200 OK` response containing an embedded S3 `<Error>` XML document
/// preceded by keep-alive whitespace (simulating AWS S3's `CompleteMultipartUpload` /
/// `CopyObject` 200-OK failure mode).
pub fn build_ok200_xml_error_response(code: &str, message: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n    \n<Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    build_http_error_response(StatusCode::OK, None, "application/xml", body)
}

/// Build an Axum HTTP `200 OK` streaming response that writes `prefix` bytes and then aborts
/// mid-body with `std::io::ErrorKind::ConnectionReset`.
pub fn build_mid_body_reset_response(prefix: Bytes) -> Response {
    build_mid_body_reset_response_with_status(StatusCode::OK, prefix)
}

/// Build an Axum streaming response with `status` (e.g. `200 OK` or `206 Partial Content`)
/// that writes `prefix` bytes and then aborts mid-body with `std::io::ErrorKind::ConnectionReset`.
pub fn build_mid_body_reset_response_with_status(status: StatusCode, prefix: Bytes) -> Response {
    enum Stage {
        EmitPrefix(Bytes),
        Reset,
        Done,
    }

    let initial = if prefix.is_empty() {
        Stage::Reset
    } else {
        Stage::EmitPrefix(prefix)
    };

    let stream = futures::stream::unfold(initial, |stage| async move {
        match stage {
            Stage::EmitPrefix(chunk) => Some((Ok(chunk), Stage::Reset)),
            Stage::Reset => {
                // Yield once so hyper flushes the HTTP headers and any prefix chunk before
                // aborting the stream with a connection reset.
                tokio::task::yield_now().await;
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "injected mid-body connection reset",
                    )),
                    Stage::Done,
                ))
            }
            Stage::Done => None,
        }
    });

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(stream))
        .expect("valid mid-body reset response")
}

/// Build a response that immediately aborts the response stream with `ConnectionReset`,
/// simulating a dropped response after the server has already committed a mutation.
pub fn build_commit_then_reset_response() -> Response {
    build_mid_body_reset_response(Bytes::new())
}

/// Spawn a raw-TCP HTTP/1.1 server that drains each request (headers + `Content-Length`
/// body), replies with `status_line` + `extra_headers` and a `Content-Length: 64` header,
/// writes only `prefix` of the body, then stalls forever without closing the socket.
///
/// Models a server (or middlebox) that commits an upload, sends response headers, and then
/// blackholes the response body. Returns `http://127.0.0.1:<port>`.
pub async fn spawn_headers_then_stall_server(
    status_line: &'static str,
    extra_headers: &'static str,
    prefix: &'static [u8],
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stall server");
    let addr = listener.local_addr().expect("stall server addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 64 * 1024];
                // Read headers.
                let header_end = loop {
                    let Ok(n) = sock.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                let content_len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut have = buf.len() - header_end;
                while have < content_len {
                    let Ok(n) = sock.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    have += n;
                }
                let resp =
                    format!("HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: 64\r\n\r\n");
                if sock.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                let _ = sock.write_all(prefix).await;
                let _ = sock.flush().await;
                // Blackhole: never send the rest of the body, never close.
                std::future::pending::<()>().await;
                drop(sock);
            });
        }
    });
    format!("http://{addr}")
}
