use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Coarse retry classification used by protocol state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RetryClass {
    /// Safe to retry with backoff.
    Retryable,
    /// Explicitly throttled (HTTP 429 / 503 / GDrive userRateLimitExceeded).
    Throttled,
    /// Permanent or non-retryable failure (e.g. 400, 403 storageQuotaExceeded, invalid geometry).
    Permanent,
    /// Remote session expired / missing (e.g. GDrive 404/410, S3 NoSuchUpload).
    /// Must trigger destination reconciliation before deciding whether to restart.
    SessionExpired,
    /// Source file mutated while being read/uploaded; must abort and re-plan.
    SourceMutated,
    /// Interrupted by user signal (e.g. SIGINT); preserve resumable state!
    Cancelled,
    /// Data-integrity failure (checksum mismatch between source and destination bytes).
    ///
    /// Never retried in place, never reconciled into a committed result, and never treated
    /// as a congestion signal; the engine discards any object it wrote for the failed attempt
    /// and restarts the transfer from scratch a bounded number of times.
    Integrity,
}

impl RetryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Throttled => "throttled",
            Self::Permanent => "permanent",
            Self::SessionExpired => "session_expired",
            Self::SourceMutated => "source_mutated",
            Self::Cancelled => "cancelled",
            Self::Integrity => "integrity",
        }
    }
}

impl fmt::Display for RetryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorKind {
    Config,
    InvalidPath,
    InvalidGeometry,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    QuotaExceeded,
    RateLimited,
    LockBusy,
    Network,
    Timeout,
    SessionExpired,
    SourceMutated,
    PreconditionFailed,
    Conflict,
    Unsupported,
    StateStore,
    Io,
    Cancelled,
    Protocol,
    /// Checksum mismatch between the bytes read from the source and the bytes the
    /// destination committed (or between a download and its advertised hash).
    Integrity,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::InvalidPath => "invalid_path",
            Self::InvalidGeometry => "invalid_geometry",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::PermissionDenied => "permission_denied",
            Self::QuotaExceeded => "quota_exceeded",
            Self::RateLimited => "rate_limited",
            Self::LockBusy => "lock_busy",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::SessionExpired => "session_expired",
            Self::SourceMutated => "source_mutated",
            Self::PreconditionFailed => "precondition_failed",
            Self::Conflict => "conflict",
            Self::Unsupported => "unsupported",
            Self::StateStore => "state_store",
            Self::Io => "io",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
            Self::Integrity => "integrity",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// High-level, machine-readable error category designed for programmatic CLI
/// (`--json`) and SDK callers (eliminating fragile error-string matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCategory {
    /// Invalid configuration, CLI options, proxy/CA setup, or unconfigured remote.
    Config,
    /// Authentication, authorization, expired OAuth refresh token, or permission failure.
    Auth,
    /// Missing source/destination file, directory, bucket, or object.
    NotFound,
    /// Storage quota or daily upload limit exhausted (e.g. Google Drive 750 GiB/day cap).
    QuotaExceeded,
    /// Remote rate limit or throttling (HTTP 429 / 503 / QPS cap).
    RateLimited,
    /// Destination advisory process lock is held by another `rship` process.
    LockBusy,
    /// Transient network, timeout, session, source-mutation, or retryable I/O failure.
    Transient,
    /// Namespace/data conflict, type-flip, precondition mismatch, or already-exists error.
    Conflict,
    /// Operation interrupted by signal or caller cancellation.
    Cancelled,
    /// Non-retryable local I/O or state-store failure.
    Io,
    /// Unclassified permanent protocol or internal failure.
    #[default]
    Other,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Auth => "auth",
            Self::NotFound => "not_found",
            Self::QuotaExceeded => "quota_exceeded",
            Self::RateLimited => "rate_limited",
            Self::LockBusy => "lock_busy",
            Self::Transient => "transient",
            Self::Conflict => "conflict",
            Self::Cancelled => "cancelled",
            Self::Io => "io",
            Self::Other => "other",
        }
    }

    /// Map a fine-grained [`ErrorKind`] and [`RetryClass`] to a stable [`ErrorCategory`].
    pub fn from_kind_and_retry(kind: ErrorKind, retry: RetryClass) -> Self {
        if kind == ErrorKind::Cancelled || retry == RetryClass::Cancelled {
            return Self::Cancelled;
        }
        match kind {
            ErrorKind::Config
            | ErrorKind::InvalidPath
            | ErrorKind::InvalidGeometry
            | ErrorKind::Unsupported => Self::Config,
            ErrorKind::PermissionDenied => Self::Auth,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::QuotaExceeded => Self::QuotaExceeded,
            ErrorKind::RateLimited => Self::RateLimited,
            ErrorKind::LockBusy => Self::LockBusy,
            ErrorKind::Network
            | ErrorKind::Timeout
            | ErrorKind::SessionExpired
            | ErrorKind::SourceMutated
            | ErrorKind::Integrity => Self::Transient,
            ErrorKind::Conflict | ErrorKind::PreconditionFailed | ErrorKind::AlreadyExists => {
                Self::Conflict
            }
            ErrorKind::Io | ErrorKind::StateStore => match retry {
                RetryClass::Retryable => Self::Transient,
                RetryClass::Throttled => Self::RateLimited,
                _ => Self::Io,
            },
            ErrorKind::Protocol => match retry {
                RetryClass::Retryable => Self::Transient,
                RetryClass::Throttled => Self::RateLimited,
                _ => Self::Other,
            },
            ErrorKind::Cancelled => Self::Cancelled,
        }
    }

    /// Relative precedence when summarizing multiple errors in a single batch report
    /// (higher priority wins so account-fatal conditions like quota/auth surface over transient noise).
    pub fn priority(self) -> u8 {
        match self {
            Self::Cancelled => 100,
            Self::QuotaExceeded => 90,
            Self::Auth => 80,
            Self::Config => 70,
            Self::LockBusy => 60,
            Self::RateLimited => 50,
            Self::NotFound => 40,
            Self::Transient => 30,
            Self::Conflict => 20,
            Self::Io => 10,
            Self::Other => 5,
        }
    }

    /// Pick the highest-priority category from a sequence of error categories.
    pub fn primary<I: IntoIterator<Item = Self>>(categories: I) -> Option<Self> {
        categories.into_iter().max_by_key(|c| c.priority())
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("{kind:?}: {message}")]
#[non_exhaustive]
pub struct Error {
    pub kind: ErrorKind,
    pub retry: RetryClass,
    pub retry_after: Option<Duration>,
    /// True when a lower layer (e.g. a backend HTTP client) already ran and exhausted
    /// its own retry loop for this error, preventing outer layers from stacking retries.
    pub retries_exhausted: bool,
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind, retry: RetryClass, message: impl Into<String>) -> Self {
        Self {
            kind,
            retry,
            retry_after: None,
            retries_exhausted: false,
            message: message.into(),
            source: None,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn category(&self) -> ErrorCategory {
        ErrorCategory::from_kind_and_retry(self.kind, self.retry)
    }

    pub fn retry_class(&self) -> RetryClass {
        self.retry
    }

    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    pub fn retries_exhausted(&self) -> bool {
        self.retries_exhausted
    }

    pub fn is_config(&self) -> bool {
        self.kind == ErrorKind::Config
    }

    pub fn is_lock_busy(&self) -> bool {
        self.kind == ErrorKind::LockBusy
    }

    pub fn is_retryable(&self) -> bool {
        !self.retries_exhausted
            && matches!(self.retry, RetryClass::Retryable | RetryClass::Throttled)
    }

    pub fn is_throttled(&self) -> bool {
        self.kind == ErrorKind::RateLimited || self.retry == RetryClass::Throttled
    }

    pub fn is_quota_exceeded(&self) -> bool {
        self.kind == ErrorKind::QuotaExceeded
    }

    pub fn is_not_found(&self) -> bool {
        self.kind == ErrorKind::NotFound
    }

    pub fn is_permission_denied(&self) -> bool {
        self.kind == ErrorKind::PermissionDenied
    }

    pub fn is_cancelled(&self) -> bool {
        self.kind == ErrorKind::Cancelled || self.retry == RetryClass::Cancelled
    }

    pub fn is_permanent(&self) -> bool {
        self.retry == RetryClass::Permanent
    }

    pub fn is_conflict(&self) -> bool {
        self.kind == ErrorKind::Conflict
    }

    pub fn is_session_expired(&self) -> bool {
        self.kind == ErrorKind::SessionExpired || self.retry == RetryClass::SessionExpired
    }

    /// Returns `true` for data-integrity failures (checksum mismatches).
    ///
    /// Such errors must never be reconciled into success: the destination may hold a
    /// committed object whose bytes differ from the source.
    pub fn is_integrity(&self) -> bool {
        self.kind == ErrorKind::Integrity || self.retry == RetryClass::Integrity
    }

    pub fn is_source_mutated(&self) -> bool {
        self.kind == ErrorKind::SourceMutated || self.retry == RetryClass::SourceMutated
    }

    pub fn with_source(mut self, src: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(src));
        self
    }

    pub fn with_retry_after(mut self, delay: Duration) -> Self {
        self.retry_after = Some(delay);
        self
    }

    pub fn with_retries_exhausted(mut self) -> Self {
        self.retries_exhausted = true;
        self
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, RetryClass::Permanent, msg)
    }

    pub fn lock_busy(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::LockBusy, RetryClass::Retryable, msg)
    }

    pub fn invalid_path(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidPath, RetryClass::Permanent, msg)
    }

    pub fn invalid_geometry(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidGeometry, RetryClass::Permanent, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, RetryClass::Permanent, msg)
    }

    pub fn already_exists(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::AlreadyExists, RetryClass::Permanent, msg)
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg)
    }

    pub fn quota_exceeded(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::QuotaExceeded, RetryClass::Permanent, msg)
    }

    pub fn precondition_failed(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg)
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, RetryClass::Permanent, msg)
    }

    pub fn session_expired(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::SessionExpired, RetryClass::SessionExpired, msg)
    }

    pub fn source_mutated(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::SourceMutated, RetryClass::SourceMutated, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, RetryClass::Permanent, msg)
    }

    /// Data-integrity failure (checksum mismatch). See [`RetryClass::Integrity`].
    pub fn integrity(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Integrity, RetryClass::Integrity, msg)
    }

    pub fn cancelled(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Cancelled, RetryClass::Cancelled, msg)
    }

    pub fn rate_limited(msg: impl Into<String>, retry_after: Option<Duration>) -> Self {
        let mut e = Self::new(ErrorKind::RateLimited, RetryClass::Throttled, msg);
        e.retry_after = retry_after;
        e
    }

    pub fn network(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, RetryClass::Retryable, msg)
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, RetryClass::Retryable, msg)
    }

    pub fn short_eof(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, RetryClass::Permanent, msg)
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, RetryClass::Permanent, msg)
    }

    pub fn state_store(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::StateStore, RetryClass::Permanent, msg)
    }

    pub fn io(msg: impl Into<String>, err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            std::io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
            std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
            _ => ErrorKind::Io,
        };
        let retry = match err.kind() {
            std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe => RetryClass::Retryable,
            _ => RetryClass::Permanent,
        };
        Self::new(kind, retry, msg).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_categories_and_priority_cover_all_classes() {
        assert_eq!(Error::config("bad cfg").category(), ErrorCategory::Config);
        assert!(Error::config("bad cfg").is_config());
        assert_eq!(Error::lock_busy("busy").category(), ErrorCategory::LockBusy);
        assert!(Error::lock_busy("busy").is_lock_busy());
        assert_eq!(
            Error::permission_denied("401").category(),
            ErrorCategory::Auth
        );
        assert_eq!(Error::not_found("x").category(), ErrorCategory::NotFound);
        assert_eq!(
            Error::quota_exceeded("limit").category(),
            ErrorCategory::QuotaExceeded
        );
        assert_eq!(
            Error::rate_limited("429", Some(Duration::from_secs(1))).category(),
            ErrorCategory::RateLimited
        );
        assert_eq!(Error::network("reset").category(), ErrorCategory::Transient);
        assert_eq!(Error::timeout("stall").category(), ErrorCategory::Transient);
        assert_eq!(
            Error::session_expired("expired").category(),
            ErrorCategory::Transient
        );
        assert_eq!(
            Error::source_mutated("changed").category(),
            ErrorCategory::Transient
        );
        assert_eq!(Error::conflict("flip").category(), ErrorCategory::Conflict);
        let integrity = Error::integrity("crc mismatch");
        assert_eq!(integrity.category(), ErrorCategory::Transient);
        assert!(integrity.is_integrity());
        assert!(!integrity.is_retryable());
        assert!(!integrity.is_throttled());
        assert_eq!(
            Error::cancelled("sigint").category(),
            ErrorCategory::Cancelled
        );

        // Priority ordering: permanent/actionable categories beat generic transient/other.
        assert_eq!(
            ErrorCategory::primary([ErrorCategory::Transient, ErrorCategory::QuotaExceeded]),
            Some(ErrorCategory::QuotaExceeded)
        );
        assert_eq!(
            ErrorCategory::primary([ErrorCategory::Other, ErrorCategory::RateLimited]),
            Some(ErrorCategory::RateLimited)
        );
        assert_eq!(
            ErrorCategory::primary([ErrorCategory::Io, ErrorCategory::Auth]),
            Some(ErrorCategory::Auth)
        );
        assert_eq!(ErrorCategory::primary([]), None);
    }

    #[test]
    fn retries_exhausted_defaults_false_and_suppresses_is_retryable() {
        let raw = Error::rate_limited("429", Some(Duration::from_secs(2)));
        assert!(!raw.retries_exhausted());
        assert!(raw.is_retryable());
        assert!(raw.is_throttled());

        let exhausted = raw.with_retries_exhausted();
        assert!(exhausted.retries_exhausted());
        assert!(!exhausted.is_retryable());
        assert!(exhausted.is_throttled());
        assert_eq!(exhausted.retry_class(), RetryClass::Throttled);
    }
}
