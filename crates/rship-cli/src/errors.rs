//! Machine-readable error classification, distinct process exit codes, fatal `--json`
//! formatting, and `--json-progress` JSONL error event serialization for `rship-cli`.

use rship_core::{Error, ErrorCategory, ErrorKind, RetryClass};
use std::io::{self, Write};

/// Success.
pub const EXIT_OK: u8 = 0;

/// Construct a strongly-typed configuration/CLI-argument error (`EXIT_CONFIG = 7`).
pub fn config_err(msg: impl Into<String>) -> anyhow::Error {
    Error::config(msg).into()
}

/// Construct a strongly-typed user-cancellation error (`EXIT_CANCELLED = 130`).
pub fn cancelled_err(msg: impl Into<String>) -> anyhow::Error {
    Error::cancelled(msg).into()
}

/// Construct a strongly-typed unsupported-feature error (`EXIT_CONFIG = 7`).
pub fn unsupported_err(msg: impl Into<String>) -> anyhow::Error {
    Error::unsupported(msg).into()
}
/// Unclassified / local I/O / permanent protocol error (or `rship check` differences).
pub const EXIT_ERROR: u8 = 1;
/// Unresolved sync/bisync conflicts (also `clap` CLI syntax/argument error).
pub const EXIT_CONFLICT: u8 = 2;
/// Missing source/destination file, directory, bucket, or object.
pub const EXIT_NOT_FOUND: u8 = 3;
/// Authentication, authorization, expired OAuth token, or permission failure.
pub const EXIT_AUTH: u8 = 4;
/// Transient network, timeout, session, source-mutation, or retryable failure.
pub const EXIT_TRANSIENT: u8 = 5;
/// Remote rate limit or throttling (HTTP 429 / 503).
pub const EXIT_RATE_LIMITED: u8 = 6;
/// Invalid configuration, CLI flag, proxy/CA setup, or unconfigured remote.
pub const EXIT_CONFIG: u8 = 7;
/// Storage quota or daily upload limit exhausted (e.g. Google Drive 750 GiB/day cap).
pub const EXIT_QUOTA_EXCEEDED: u8 = 8;
/// Exclusive destination advisory process lock is held by another `rship` process.
pub const EXIT_LOCK_BUSY: u8 = 9;
/// Interrupted / cancelled by signal (`SIGINT` / `SIGTERM`).
pub const EXIT_CANCELLED: u8 = 130;

/// Map a machine-readable [`ErrorCategory`] to its deterministic process exit code.
pub fn exit_code_for_category(category: ErrorCategory) -> u8 {
    match category {
        ErrorCategory::Config => EXIT_CONFIG,
        ErrorCategory::Auth => EXIT_AUTH,
        ErrorCategory::NotFound => EXIT_NOT_FOUND,
        ErrorCategory::QuotaExceeded => EXIT_QUOTA_EXCEEDED,
        ErrorCategory::RateLimited => EXIT_RATE_LIMITED,
        ErrorCategory::LockBusy => EXIT_LOCK_BUSY,
        ErrorCategory::Transient => EXIT_TRANSIENT,
        ErrorCategory::Conflict => EXIT_CONFLICT,
        ErrorCategory::Cancelled => EXIT_CANCELLED,
        ErrorCategory::Io | ErrorCategory::Other => EXIT_ERROR,
        _ => EXIT_ERROR,
    }
}

/// Structured classification of a fatal `anyhow::Error` surfaced to `main`.
#[derive(Debug, Clone)]
pub struct ClassifiedError {
    pub kind: ErrorKind,
    pub category: ErrorCategory,
    pub retry_class: RetryClass,
    pub retry_after_ms: Option<u64>,
    pub exit_code: u8,
    pub message: String,
    pub detail_message: String,
    pub causes: Vec<String>,
    pub hint: Option<&'static str>,
}

/// Classify an `anyhow::Error` by downcasting its causal chain (`rship_core::Error` first,
/// then `std::io::Error` / `toml::de::Error`) with a minimal fallback for unstructured errors.
pub fn classify_anyhow_error(err: &anyhow::Error) -> ClassifiedError {
    let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
    let message = chain
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown error".to_string());
    let causes = if chain.len() > 1 {
        chain[1..].to_vec()
    } else {
        Vec::new()
    };
    let full_msg = chain.join(" | ");
    let hint = crate::ui::infer_error_hint(&full_msg);

    for cause in err.chain() {
        if let Some(core_err) = cause.downcast_ref::<Error>() {
            let category = core_err.category();
            let retry_after_ms = core_err
                .retry_after
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return ClassifiedError {
                kind: core_err.kind,
                category,
                retry_class: core_err.retry,
                retry_after_ms,
                exit_code: exit_code_for_category(category),
                message,
                detail_message: core_err.to_string(),
                causes,
                hint,
            };
        }
    }

    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            let mapped = Error::io("", io::Error::from(io_err.kind()));
            let category = mapped.category();
            return ClassifiedError {
                kind: mapped.kind,
                category,
                retry_class: mapped.retry,
                retry_after_ms: None,
                exit_code: exit_code_for_category(category),
                detail_message: io_err.to_string(),
                message,
                causes,
                hint,
            };
        }
        if cause.downcast_ref::<toml::de::Error>().is_some() {
            let category = ErrorCategory::Config;
            return ClassifiedError {
                kind: ErrorKind::Config,
                category,
                retry_class: RetryClass::Permanent,
                retry_after_ms: None,
                exit_code: exit_code_for_category(category),
                detail_message: cause.to_string(),
                message,
                causes,
                hint,
            };
        }
    }

    let lower = full_msg.to_ascii_lowercase();
    let (kind, retry_class) = if lower.contains("cancelled") || lower.contains("canceled") {
        (ErrorKind::Cancelled, RetryClass::Cancelled)
    } else if lower.contains("not configured")
        || lower.contains("invalid ")
        || lower.contains("unknown ")
        || lower.contains("missing ")
        || lower.contains("must be")
        || lower.contains("not enabled in this build")
    {
        (ErrorKind::Config, RetryClass::Permanent)
    } else if lower.contains("not found") || lower.contains("does not exist") {
        (ErrorKind::NotFound, RetryClass::Permanent)
    } else {
        (ErrorKind::Protocol, RetryClass::Permanent)
    };
    let category = ErrorCategory::from_kind_and_retry(kind, retry_class);

    ClassifiedError {
        kind,
        category,
        retry_class,
        retry_after_ms: None,
        exit_code: exit_code_for_category(category),
        detail_message: message.clone(),
        message,
        causes,
        hint,
    }
}

/// Format a fatal startup/runtime CLI error as a machine-readable JSON object for `stdout`
/// when `--json` is passed.
pub fn format_fatal_error_json(command: &str, classified: &ClassifiedError) -> serde_json::Value {
    let mut detail = serde_json::json!({
        "kind": classified.kind.as_str(),
        "category": classified.category.as_str(),
        "retry_class": classified.retry_class.as_str(),
        "message": classified.detail_message,
    });
    if let Some(ms) = classified.retry_after_ms {
        detail["retry_after_ms"] = serde_json::json!(ms);
    }

    let mut out = serde_json::json!({
        "ok": false,
        "fatal": true,
        "command": command,
        "exit_code": classified.exit_code,
        "error": classified.message,
        "error_category": classified.category.as_str(),
        "error_kind": classified.kind.as_str(),
        "retry_class": classified.retry_class.as_str(),
        "causes": classified.causes,
        "errors": [&classified.message],
        "error_details": [detail],
    });
    if let Some(ms) = classified.retry_after_ms {
        out["retry_after_ms"] = serde_json::json!(ms);
    }
    if let Some(hint) = classified.hint {
        out["hint"] = serde_json::json!(hint);
    }
    out
}

/// Format one structured newline-delimited JSON (`"event": "error"`) line for `stderr`
/// under `--json-progress`.
#[allow(clippy::too_many_arguments)]
pub fn format_error_jsonl(
    mode: &str,
    job_id: Option<&str>,
    path: Option<&str>,
    kind: ErrorKind,
    category: ErrorCategory,
    retry_class: RetryClass,
    retry_after_ms: Option<u64>,
    message: &str,
    fatal: bool,
) -> String {
    let ts_unix_ms = rship_core::time::now_unix_ms();
    serde_json::json!({
        "event": "error",
        "ts_unix_ms": ts_unix_ms,
        "mode": mode.to_ascii_lowercase(),
        "job_id": job_id,
        "path": path,
        "error": message,
        "error_kind": kind.as_str(),
        "error_category": category.as_str(),
        "retry_class": retry_class.as_str(),
        "retry_after_ms": retry_after_ms,
        "fatal": fatal,
    })
    .to_string()
}

/// Atomically write one complete JSONL line to `stderr` under the global stderr lock so
/// concurrent progress ticks and real-time error events never interleave mid-line.
pub fn write_jsonl_stderr(line: &str) {
    let stderr = io::stderr();
    let mut guard = stderr.lock();
    let _ = guard.write_all(line.as_bytes());
    let _ = guard.write_all(b"\n");
    let _ = guard.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn classifies_all_core_error_categories_and_exit_codes() {
        let cases = [
            (
                Error::config("bad proxy"),
                ErrorCategory::Config,
                EXIT_CONFIG,
            ),
            (
                Error::permission_denied("401 revoked"),
                ErrorCategory::Auth,
                EXIT_AUTH,
            ),
            (
                Error::not_found("missing.mp4"),
                ErrorCategory::NotFound,
                EXIT_NOT_FOUND,
            ),
            (
                Error::quota_exceeded("750 GiB/day"),
                ErrorCategory::QuotaExceeded,
                EXIT_QUOTA_EXCEEDED,
            ),
            (
                Error::rate_limited("429", Some(Duration::from_secs(5))),
                ErrorCategory::RateLimited,
                EXIT_RATE_LIMITED,
            ),
            (
                Error::lock_busy("lock held"),
                ErrorCategory::LockBusy,
                EXIT_LOCK_BUSY,
            ),
            (
                Error::network("connection reset"),
                ErrorCategory::Transient,
                EXIT_TRANSIENT,
            ),
            (
                Error::timeout("stall"),
                ErrorCategory::Transient,
                EXIT_TRANSIENT,
            ),
            (
                Error::conflict("type flip"),
                ErrorCategory::Conflict,
                EXIT_CONFLICT,
            ),
            (
                Error::cancelled("SIGINT"),
                ErrorCategory::Cancelled,
                EXIT_CANCELLED,
            ),
        ];

        for (core_err, expected_cat, expected_exit) in cases {
            let wrapped = anyhow::Error::new(core_err).context("operation failed");
            let classified = classify_anyhow_error(&wrapped);
            assert_eq!(classified.category, expected_cat);
            assert_eq!(classified.exit_code, expected_exit);
            let json = format_fatal_error_json("moveto", &classified);
            assert_eq!(json["ok"], false);
            assert_eq!(json["fatal"], true);
            assert_eq!(json["error_category"], expected_cat.as_str());
            assert_eq!(json["exit_code"], expected_exit);
        }
    }
}
