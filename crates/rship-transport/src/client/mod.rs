//! Split Control Plane (HTTP/2 multiplexed) and Data Plane (HTTP/1.1 bulk streaming)
//! HTTP clients with native root TLS, optional custom CA certificates, and bounded
//! response body reading.

mod redact;
#[cfg(test)]
mod tests;

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::HeaderMap;
use reqwest::{Certificate, Client, Response};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::limiter::{
    LimiterPlane, LimiterRegistry, LimiterScope, RateLimiterConfig, ScopedLimiter,
};
pub use crate::watchdog::DEFAULT_DATA_FINALIZE_TIMEOUT;
use crate::watchdog::ProgressWatchdog;
use redact::{dump_http_request, dump_http_response, redact_single_url_credentials};

pub use redact::{
    format_redacted_headers, redact_url_credentials, redact_url_for_dump, redact_urls_in_text,
};

pub const DEFAULT_MAX_CONTROL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_LONG_CONTROL_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_DATA_STALL_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);

/// Optional redacted HTTP wire diagnostics mode (`--dump headers`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpDumpMode {
    /// Disabled (default): zero formatting or allocation overhead on the hot path.
    #[default]
    None,
    /// Log redacted HTTP request & response lines and headers via `tracing` (`rship::http_dump`).
    Headers,
}

impl HttpDumpMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "off" => Some(Self::None),
            "headers" => Some(Self::Headers),
            _ => None,
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct TransportConfig {
    /// Optional custom PEM CA certificate bundle (`--ca-cert`).
    pub ca_cert_path: Option<PathBuf>,
    /// Optional explicit proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`) via `--proxy`.
    pub proxy_url: Option<String>,
    /// TCP + TLS handshake connect timeout (shared across both planes).
    pub connect_timeout: Duration,
    /// Total per-RPC timeout for Control Plane metadata/auth requests.
    pub control_timeout: Duration,
    /// Extended per-RPC timeout for slow Control Plane operations (e.g. server-side
    /// copy, complete-multipart, or folder deletion) via `send_long_control_request`.
    pub long_control_timeout: Duration,
    /// Byte-progress idle stall timeout for Data Plane uploads/downloads.
    pub data_stall_timeout: Duration,
    /// Post-body-EOF finalize timeout for Data Plane uploads waiting on server-side
    /// assembly/commit after the final payload chunk has been transmitted.
    pub data_finalize_timeout: Duration,
    /// Optional overall ceiling per Data Plane request (independent of stall timeout).
    pub data_total_timeout: Option<Duration>,
    /// Hard memory ceiling when reading Control Plane JSON/error bodies.
    pub max_control_response_bytes: usize,
    /// Data Plane defaults to `.http1_only()` to avoid ALPN `h2` upload coalescing
    /// and unbounded `h2` receive-window buffer bloat.
    pub data_http1_only: bool,
    pub pool_max_idle_per_host: usize,
    pub user_agent: String,
    pub default_rate_limit: RateLimiterConfig,
    /// Optional redacted HTTP wire diagnostic dump mode (`--dump headers`).
    pub dump_mode: HttpDumpMode,
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_proxy = self.proxy_url.as_deref().map(redact_url_credentials);
        f.debug_struct("TransportConfig")
            .field("ca_cert_path", &self.ca_cert_path)
            .field("proxy_url", &redacted_proxy)
            .field("connect_timeout", &self.connect_timeout)
            .field("control_timeout", &self.control_timeout)
            .field("long_control_timeout", &self.long_control_timeout)
            .field("data_stall_timeout", &self.data_stall_timeout)
            .field("data_finalize_timeout", &self.data_finalize_timeout)
            .field("data_total_timeout", &self.data_total_timeout)
            .field(
                "max_control_response_bytes",
                &self.max_control_response_bytes,
            )
            .field("data_http1_only", &self.data_http1_only)
            .field("pool_max_idle_per_host", &self.pool_max_idle_per_host)
            .field("user_agent", &self.user_agent)
            .field("default_rate_limit", &self.default_rate_limit)
            .field("dump_mode", &self.dump_mode)
            .finish()
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            proxy_url: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            control_timeout: DEFAULT_CONTROL_TIMEOUT,
            long_control_timeout: DEFAULT_LONG_CONTROL_TIMEOUT,
            data_stall_timeout: DEFAULT_DATA_STALL_TIMEOUT,
            data_finalize_timeout: DEFAULT_DATA_FINALIZE_TIMEOUT,
            data_total_timeout: Some(DEFAULT_DATA_TOTAL_TIMEOUT),
            max_control_response_bytes: DEFAULT_MAX_CONTROL_RESPONSE_BYTES,
            data_http1_only: true,
            pool_max_idle_per_host: 32,
            user_agent: format!("rship/{}", env!("CARGO_PKG_VERSION")),
            default_rate_limit: RateLimiterConfig::default(),
            dump_mode: HttpDumpMode::None,
        }
    }
}

impl TransportConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    pub fn with_proxy_url(mut self, url: impl Into<String>) -> Self {
        self.proxy_url = Some(url.into());
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_control_timeout(mut self, timeout: Duration) -> Self {
        self.control_timeout = timeout;
        self
    }

    pub fn with_long_control_timeout(mut self, timeout: Duration) -> Self {
        self.long_control_timeout = timeout;
        self
    }

    pub fn with_data_stall_timeout(mut self, timeout: Duration) -> Self {
        self.data_stall_timeout = timeout;
        self
    }

    pub fn with_data_finalize_timeout(mut self, timeout: Duration) -> Self {
        self.data_finalize_timeout = timeout;
        self
    }

    pub fn with_data_total_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.data_total_timeout = timeout;
        self
    }

    pub fn with_max_control_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_control_response_bytes = max_bytes;
        self
    }

    pub fn with_data_http1_only(mut self, http1_only: bool) -> Self {
        self.data_http1_only = http1_only;
        self
    }

    pub fn with_pool_max_idle_per_host(mut self, max_idle: usize) -> Self {
        self.pool_max_idle_per_host = max_idle;
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    pub fn with_default_rate_limit(mut self, cfg: RateLimiterConfig) -> Self {
        self.default_rate_limit = cfg;
        self
    }

    pub fn with_tps_limit(mut self, tps: f64) -> Self {
        self.default_rate_limit.tps_limit = (tps.is_finite() && tps > 0.0).then_some(tps);
        self
    }

    pub fn with_tps_burst(mut self, burst: f64) -> Self {
        self.default_rate_limit.tps_burst = Some(burst);
        self
    }

    pub fn with_dump_mode(mut self, mode: HttpDumpMode) -> Self {
        self.dump_mode = mode;
        self
    }
}

/// Validate an explicit proxy URL (`--proxy`) without constructing full HTTP clients.
///
/// Returns `Ok(())` for empty/whitespace-only inputs (treated as no proxy) or valid proxy
/// URLs accepted by `reqwest::Proxy::all`, and `Error::config` (with redacted credentials)
/// on malformed URLs.
pub fn validate_proxy_url(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    reqwest::Proxy::all(trimmed).map(|_| ()).map_err(|e| {
        let safe_url = redact_single_url_credentials(trimmed);
        let raw_err = e.to_string().replace(trimmed, &safe_url);
        let safe_err = redact_urls_in_text(&raw_err);
        Error::config(format!("invalid proxy URL `{safe_url}`: {safe_err}"))
    })
}

/// Split-plane HTTP transport shared across cloud backends.
#[derive(Clone)]
pub struct HttpTransport {
    control: Client,
    data: Client,
    config: Arc<TransportConfig>,
    limiters: LimiterRegistry,
}

impl HttpTransport {
    pub fn new(config: TransportConfig) -> Result<Self> {
        Self::new_with_clock(config, rship_core::clock::SystemClock::shared())
    }

    /// Build a transport whose rate limiters (token buckets, pacing waits and backend retry
    /// backoff via [`ScopedLimiter::sleep`]) run on `clock`, so deterministic simulation tests
    /// can virtualise every retry sleep. [`HttpTransport::new`] uses the system clock.
    pub fn new_with_clock(
        config: TransportConfig,
        clock: Arc<dyn rship_core::clock::Clock>,
    ) -> Result<Self> {
        let custom_certs = load_custom_ca_certs(config.ca_cert_path.as_deref())?;
        let proxy = match config.proxy_url.as_deref() {
            Some(url) if !url.trim().is_empty() => {
                let trimmed = url.trim();
                Some(reqwest::Proxy::all(trimmed).map_err(|e| {
                    let safe_url = redact_single_url_credentials(trimmed);
                    let raw_err = e.to_string().replace(trimmed, &safe_url);
                    let safe_err = redact_urls_in_text(&raw_err);
                    Error::config(format!("invalid proxy URL `{safe_url}`: {safe_err}"))
                })?)
            }
            _ => None,
        };

        // Control Plane: HTTP/2 multiplexed (with HTTP/1.1 fallback via ALPN) +
        // explicit RPC deadline + native system root CAs.
        let mut ctrl_builder = Client::builder()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .timeout(config.control_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .tcp_nodelay(true)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .tcp_keepalive(Some(Duration::from_secs(30)));

        if let Some(ref p) = proxy {
            ctrl_builder = ctrl_builder.proxy(p.clone());
        }
        for cert in &custom_certs {
            ctrl_builder = ctrl_builder.add_root_certificate(cert.clone());
        }
        let control = ctrl_builder
            .build()
            .map_err(|e| Error::protocol(format!("build control-plane HTTP client: {e}")))?;

        // Data Plane: `.http1_only()` by default (dedicated keep-alive socket per
        // concurrent transfer), NO short total `.timeout()` (guarded instead by
        // `ProgressWatchdog` byte-progress stall + finalize + optional `data_total_timeout`),
        // and NO transparent response decompression so wire bytes, `Content-Length`,
        // `Content-Encoding`, and checksums/range offsets are preserved verbatim.
        let mut data_builder = Client::builder()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .tcp_nodelay(true)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();

        if config.data_http1_only {
            data_builder = data_builder.http1_only();
        }
        if let Some(p) = proxy {
            data_builder = data_builder.proxy(p);
        }
        for cert in &custom_certs {
            data_builder = data_builder.add_root_certificate(cert.clone());
        }
        let data = data_builder
            .build()
            .map_err(|e| Error::protocol(format!("build data-plane HTTP client: {e}")))?;

        let limiters = LimiterRegistry::with_clock(config.default_rate_limit.clone(), clock);

        Ok(Self {
            control,
            data,
            config: Arc::new(config),
            limiters,
        })
    }

    /// Multiplexed HTTP/2 client for metadata, directory listing, auth, and small control RPCs.
    pub fn control_client(&self) -> &Client {
        &self.control
    }

    /// Dedicated-connection HTTP/1.1 client for streaming bulk uploads and downloads.
    pub fn data_client(&self) -> &Client {
        &self.data
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn limiters(&self) -> &LimiterRegistry {
        &self.limiters
    }

    /// Obtain or initialize the isolated rate limiter for `(remote, principal)`.
    pub fn limiter_for(&self, scope: LimiterScope) -> Arc<ScopedLimiter> {
        self.limiters.get_or_create(scope)
    }

    /// Obtain or initialize an isolated limiter with custom per-backend defaults
    /// (e.g. GDrive write QPS cap).
    pub fn limiter_for_with_config(
        &self,
        scope: LimiterScope,
        cfg: RateLimiterConfig,
    ) -> Arc<ScopedLimiter> {
        self.limiters.get_or_create_with_config(scope, cfg)
    }

    /// Obtain or initialize the Control Plane isolated rate limiter for `scope`.
    pub fn control_limiter_for(&self, scope: LimiterScope) -> Arc<ScopedLimiter> {
        self.limiters
            .get_or_create(scope.for_plane(LimiterPlane::Control))
    }

    /// Obtain or initialize the Data Plane isolated rate limiter for `scope`.
    pub fn data_limiter_for(&self, scope: LimiterScope) -> Arc<ScopedLimiter> {
        self.limiters
            .get_or_create(scope.for_plane(LimiterPlane::Data))
    }

    /// Obtain or initialize a Control Plane isolated limiter with custom per-backend defaults.
    pub fn control_limiter_for_with_config(
        &self,
        scope: LimiterScope,
        cfg: RateLimiterConfig,
    ) -> Arc<ScopedLimiter> {
        self.limiters
            .get_or_create_with_config(scope.for_plane(LimiterPlane::Control), cfg)
    }

    /// Obtain or initialize a Data Plane isolated limiter with custom per-backend defaults.
    pub fn data_limiter_for_with_config(
        &self,
        scope: LimiterScope,
        cfg: RateLimiterConfig,
    ) -> Arc<ScopedLimiter> {
        self.limiters
            .get_or_create_with_config(scope.for_plane(LimiterPlane::Data), cfg)
    }

    /// Create a fresh Data Plane stall + finalize + total-deadline watchdog using configured durations.
    pub fn data_watchdog(&self) -> ProgressWatchdog {
        ProgressWatchdog::new(
            self.config.data_stall_timeout,
            self.config.data_total_timeout,
        )
        .with_finalize_timeout(self.config.data_finalize_timeout)
    }

    /// Execute a Control Plane HTTP request with an explicit per-request timeout override.
    pub async fn send_control_request_with_timeout(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
        timeout: Duration,
    ) -> Result<Response> {
        self.send_control_request(context, req.timeout(timeout))
            .await
    }

    /// Execute a slow Control Plane HTTP request using `config.long_control_timeout`.
    pub async fn send_long_control_request(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
    ) -> Result<Response> {
        self.send_control_request_with_timeout(context, req, self.config.long_control_timeout)
            .await
    }

    /// Execute a Control Plane HTTP request with optional redacted `--dump headers` diagnostics.
    ///
    /// When `dump_mode == HttpDumpMode::None` (default), executes `req.send()` directly with
    /// zero extra allocations or formatting overhead.
    pub async fn send_control_request(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
    ) -> Result<Response> {
        if self.config.dump_mode == HttpDumpMode::None {
            return req.send().await.map_err(|e| map_reqwest_error(context, e));
        }
        let built = req.build().map_err(|e| map_reqwest_error(context, e))?;
        dump_http_request(context, &built);
        let started = Instant::now();
        match self.control.execute(built).await {
            Ok(resp) => {
                dump_http_response(context, &resp, started.elapsed());
                Ok(resp)
            }
            Err(e) => {
                let mapped = map_reqwest_error(context, e);
                tracing::info!(
                    target: "rship::http_dump",
                    "<<< HTTP ERROR [{context}] ({}ms): {mapped}",
                    started.elapsed().as_millis()
                );
                Err(mapped)
            }
        }
    }

    /// Execute a Data Plane request whose upload body was wrapped with `watchdog.watch_upload_stream(...)`,
    /// enforcing byte-progress stall detection, optional `data_total_timeout`, and optional redacted
    /// `--dump headers` wire logging.
    pub async fn send_watched_request(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
        watchdog: &ProgressWatchdog,
    ) -> Result<Response> {
        if self.config.dump_mode == HttpDumpMode::None {
            return watchdog
                .run(async { req.send().await.map_err(|e| map_reqwest_error(context, e)) })
                .await;
        }
        let built = req.build().map_err(|e| map_reqwest_error(context, e))?;
        dump_http_request(context, &built);
        let started = Instant::now();
        let res = watchdog
            .run(async {
                self.data
                    .execute(built)
                    .await
                    .map_err(|e| map_reqwest_error(context, e))
            })
            .await;
        match res {
            Ok(resp) => {
                dump_http_response(context, &resp, started.elapsed());
                Ok(resp)
            }
            Err(err) => {
                tracing::info!(
                    target: "rship::http_dump",
                    "<<< HTTP ERROR [{context}] ({}ms): {err}",
                    started.elapsed().as_millis()
                );
                Err(err)
            }
        }
    }

    /// Execute a Data Plane request without an upload stream (e.g. `Range` download `GET`),
    /// guarding response-header latency with the configured Data Plane watchdog.
    pub async fn send_data_request(
        &self,
        context: &str,
        req: reqwest::RequestBuilder,
    ) -> Result<Response> {
        let watchdog = self.data_watchdog();
        self.send_watched_request(context, req, &watchdog).await
    }

    /// Wrap a Data Plane download `Response` body stream with byte-progress stall detection
    /// and optional overall transfer deadline.
    pub fn watch_response_stream(
        &self,
        context: &'static str,
        resp: Response,
    ) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes>> + Send>> {
        let watchdog = self.data_watchdog();
        let raw = resp
            .bytes_stream()
            .map(move |r| r.map_err(|e| map_reqwest_error(context, e)));
        Box::pin(watchdog.watch_download_stream(Box::pin(raw)))
    }

    /// Read a Control Plane response body enforcing `max_control_response_bytes`.
    pub async fn read_control_body(&self, resp: Response) -> Result<Bytes> {
        read_bounded_body(resp, self.config.max_control_response_bytes).await
    }

    /// Read the (small) body of a **Data Plane** response, e.g. an upload's commit reply or a
    /// failed range GET's error document, enforcing `max_control_response_bytes`.
    ///
    /// The data-plane client deliberately has no total `.timeout()`, and the upload stall
    /// watchdog stops guarding once the response headers arrive, so a server that sends
    /// headers and then stalls the body would otherwise hang the transfer forever. The read
    /// fails with a retryable [`ErrorKind::Timeout`] when no body bytes arrive for
    /// `data_stall_timeout`, or when the whole read exceeds `data_finalize_timeout`.
    pub async fn read_data_body(&self, resp: Response) -> Result<Bytes> {
        read_bounded_body_with_deadlines(
            resp,
            self.config.max_control_response_bytes,
            Some(self.config.data_stall_timeout),
            Some(self.config.data_finalize_timeout),
        )
        .await
    }

    /// Read and deserialize a Control Plane JSON body enforcing `max_control_response_bytes`.
    pub async fn read_control_json<T: DeserializeOwned>(&self, resp: Response) -> Result<T> {
        read_bounded_json(resp, self.config.max_control_response_bytes).await
    }
}

/// Validate that a custom CA PEM certificate file exists, is readable, and contains valid PEM
/// certificates without constructing full HTTP clients.
pub fn validate_ca_cert_path(path: &std::path::Path) -> Result<()> {
    load_custom_ca_certs(Some(path)).map(|_| ())
}

fn load_custom_ca_certs(path: Option<&std::path::Path>) -> Result<Vec<Certificate>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let pem = std::fs::read(path).map_err(|e| {
        Error::config(format!("read custom CA cert `{}`: {e}", path.display())).with_source(e)
    })?;
    Certificate::from_pem_bundle(&pem).map_err(|e| {
        Error::config(format!(
            "parse custom CA PEM bundle `{}`: {e}",
            path.display()
        ))
    })
}

/// Stream a `reqwest::Response` into `Bytes` with a strict hard memory cap so a
/// runaway or malformed control-plane response can never blow past our RSS ceiling.
pub async fn read_bounded_body(resp: Response, max_bytes: usize) -> Result<Bytes> {
    read_bounded_body_with_deadlines(resp, max_bytes, None, None).await
}

/// [`read_bounded_body`] that additionally fails with a retryable [`ErrorKind::Timeout`]
/// when no body bytes arrive for `idle_timeout`, or when the whole read takes longer than
/// `total_timeout`.
pub async fn read_bounded_body_with_deadlines(
    resp: Response,
    max_bytes: usize,
    idle_timeout: Option<Duration>,
    total_timeout: Option<Duration>,
) -> Result<Bytes> {
    let read = read_bounded_body_idle(resp, max_bytes, idle_timeout);
    match total_timeout {
        Some(total) => tokio::time::timeout(total, read).await.unwrap_or_else(|_| {
            Err(Error::new(
                ErrorKind::Timeout,
                RetryClass::Retryable,
                format!("read response body: not complete after {total:?}"),
            ))
        }),
        None => read.await,
    }
}

async fn read_bounded_body_idle(
    resp: Response,
    max_bytes: usize,
    idle_timeout: Option<Duration>,
) -> Result<Bytes> {
    if let Some(cl) = resp.content_length()
        && cl > max_bytes as u64
    {
        return Err(Error::protocol(format!(
            "control-plane response Content-Length ({cl} bytes) exceeds cap ({max_bytes} bytes)"
        )));
    }

    let initial_cap = resp
        .content_length()
        .and_then(|cl| usize::try_from(cl).ok())
        .map(|n| n.min(max_bytes).min(64 * 1024))
        .unwrap_or(0);
    let mut buf = BytesMut::with_capacity(initial_cap);
    let mut stream = resp.bytes_stream();

    loop {
        let next = match idle_timeout {
            Some(idle) => tokio::time::timeout(idle, stream.next())
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        RetryClass::Retryable,
                        format!(
                            "read response body: stalled (no bytes for {idle:?}, {} received)",
                            buf.len()
                        ),
                    )
                })?,
            None => stream.next().await,
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|e| map_reqwest_error("read response body", e))?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(Error::protocol(format!(
                "control-plane response body exceeded cap ({max_bytes} bytes)"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf.freeze())
}

/// Read a bounded response body and deserialize JSON.
pub async fn read_bounded_json<T: DeserializeOwned>(resp: Response, max_bytes: usize) -> Result<T> {
    let body = read_bounded_body(resp, max_bytes).await?;
    serde_json::from_slice(&body).map_err(|e| Error::protocol(format!("decode JSON response: {e}")))
}

/// Convert a `reqwest::Error` into an `rship_core::Error` with accurate `ErrorKind`
/// and `RetryClass` (scrubbing any embedded proxy/URL credentials and sensitive query
/// parameters from the message).
pub fn map_reqwest_error(context: &str, err: reqwest::Error) -> Error {
    let safe = redact_urls_in_text(&err.to_string());
    if err.is_timeout() {
        return Error::new(
            ErrorKind::Timeout,
            RetryClass::Retryable,
            format!("{context}: request timed out: {safe}"),
        );
    }
    if err.is_connect() || err.is_request() || err.is_body() || err.is_decode() {
        return Error::new(
            ErrorKind::Network,
            RetryClass::Retryable,
            format!("{context}: network error: {safe}"),
        );
    }
    if err.is_builder() || err.is_redirect() {
        return Error::new(
            ErrorKind::Protocol,
            RetryClass::Permanent,
            format!("{context}: invalid HTTP request/redirect: {safe}"),
        );
    }
    Error::new(
        ErrorKind::Network,
        RetryClass::Retryable,
        format!("{context}: HTTP error: {safe}"),
    )
}

/// Parse an HTTP `Retry-After` header (delta-seconds or IMF-fixdate / RFC 2822).
pub fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers
        .get(http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    if let Some(target_secs) = rship_core::time::parse_http_date_to_secs(raw) {
        let now_ns = i128::from(rship_core::time::now_unix_nanos());
        // Whole seconds until the date, truncated toward zero.
        let delta_secs = (i128::from(target_secs) * 1_000_000_000 - now_ns) / 1_000_000_000;
        if delta_secs > 0 {
            return Some(Duration::from_secs(
                u64::try_from(delta_secs).unwrap_or(u64::MAX),
            ));
        }
        return Some(Duration::ZERO);
    }
    None
}
