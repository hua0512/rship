//! Split-plane HTTP transport, byte-progress stall watchdog, and per-scope
//! adaptive CUBIC rate limiting for `rship` cloud backends.
//!
//! Architectural invariants:
//! - **Control Plane**: multiplexed HTTP/2 client using `rustls-tls-native-roots`
//!   (+ optional `--ca-cert`), bounded response bodies, and explicit request timeout.
//! - **Data Plane**: defaults to `.http1_only()` so concurrent bulk uploads/downloads
//!   each use dedicated keep-alive TCP connections without TLS ALPN `h2` stream
//!   coalescing or unbounded `h2` receive-window slab bloat.
//! - **Stall Watchdog**: byte-progress idle deadline + separate connect & total
//!   deadlines catching stalled sources, blackholed TCP sockets, and hung responses.
//! - **Scoped Limiters**: isolated per `(remote, principal)` with AWS-SDK-style
//!   CUBIC send rate limiting, retry-quota token bucket, and write-QPS pacer.

#![forbid(unsafe_code)]

pub mod client;
pub mod limiter;
pub mod oauth;
pub mod watchdog;

pub use client::{
    HttpDumpMode, HttpTransport, TransportConfig, format_redacted_headers, map_reqwest_error,
    parse_retry_after, read_bounded_body, read_bounded_body_with_deadlines, read_bounded_json,
    redact_url_credentials, redact_url_for_dump, redact_urls_in_text, validate_ca_cert_path,
    validate_proxy_url,
};
pub use limiter::{
    CubicConfig, LimiterPlane, LimiterRegistry, LimiterScope, RateLimiterConfig, RetryQuotaConfig,
    ScopedLimiter,
};
pub use watchdog::{ProgressHandle, ProgressWatchdog, StallWatchdogStream, WatchedByteStream};
