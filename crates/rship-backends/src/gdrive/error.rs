//! Google Drive v3 HTTP status and JSON `error.errors[].reason` classifier.
//!
//! Carefully distinguishes retryable rate-limit `403`s (`userRateLimitExceeded`,
//! `rateLimitExceeded`, `sharingRateLimitExceeded`) from fatal quota exhaustion
//! (`storageQuotaExceeded`, `teamDriveFileLimitExceeded`) so transfers never
//! spin futilely on an out-of-space Drive or a 0-GB Service Account personal Drive.

use http::{HeaderMap, StatusCode};
use rship_core::{Error, ErrorKind, RetryClass};
use rship_transport::parse_retry_after;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GdriveErrorReason {
    UserRateLimitExceeded,
    RateLimitExceeded,
    SharingRateLimitExceeded,
    QuotaExceeded,
    StorageQuotaExceeded,
    TeamDriveFileLimitExceeded,
    DailyLimitExceeded,
    DownloadQuotaExceeded,
    BackendError,
    InsufficientPermissions,
    NotFound,
    Other(String),
}

impl GdriveErrorReason {
    pub fn parse(reason: &str) -> Self {
        match reason {
            "userRateLimitExceeded" => Self::UserRateLimitExceeded,
            "rateLimitExceeded" => Self::RateLimitExceeded,
            "sharingRateLimitExceeded" => Self::SharingRateLimitExceeded,
            "quotaExceeded" => Self::QuotaExceeded,
            "storageQuotaExceeded" => Self::StorageQuotaExceeded,
            "teamDriveFileLimitExceeded" | "numChildrenInNonRootLimitExceeded" => {
                Self::TeamDriveFileLimitExceeded
            }
            "dailyLimitExceeded" => Self::DailyLimitExceeded,
            "downloadQuotaExceeded" => Self::DownloadQuotaExceeded,
            "backendError" | "internalError" => Self::BackendError,
            "insufficientFilePermissions"
            | "appNotAuthorizedToFile"
            | "domainPolicy"
            | "forbidden"
            | "cannotDeleteFileWithDescendant"
            | "teamDriveMembershipRequired" => Self::InsufficientPermissions,
            "notFound" => Self::NotFound,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn is_throttle(&self) -> bool {
        matches!(
            self,
            Self::UserRateLimitExceeded
                | Self::RateLimitExceeded
                | Self::SharingRateLimitExceeded
                | Self::QuotaExceeded
                | Self::BackendError
        )
    }

    pub fn is_fatal_quota(&self) -> bool {
        matches!(
            self,
            Self::StorageQuotaExceeded
                | Self::TeamDriveFileLimitExceeded
                | Self::DailyLimitExceeded
                | Self::DownloadQuotaExceeded
        )
    }
}

#[derive(Debug, Deserialize)]
struct GdriveErrorEnvelope {
    error: GdriveErrorBody,
}

#[derive(Debug, Deserialize)]
struct GdriveErrorBody {
    #[serde(default)]
    message: String,
    #[serde(default)]
    errors: Vec<GdriveErrorDetail>,
}

#[derive(Debug, Deserialize)]
struct GdriveErrorDetail {
    #[serde(default)]
    reason: String,
    #[serde(default)]
    message: String,
}

/// Extract primary `error.errors[].reason` and message from a Drive error payload.
pub fn parse_gdrive_error_body(body: &[u8]) -> (Option<GdriveErrorReason>, String) {
    if let Ok(env) = serde_json::from_slice::<GdriveErrorEnvelope>(body) {
        let primary = env
            .error
            .errors
            .first()
            .filter(|d| !d.reason.is_empty())
            .map(|d| GdriveErrorReason::parse(&d.reason));
        let msg = if !env.error.message.is_empty() {
            env.error.message
        } else {
            env.error
                .errors
                .first()
                .map(|d| d.message.clone())
                .unwrap_or_default()
        };
        return (primary, msg);
    }
    let fallback = String::from_utf8_lossy(body);
    let trimmed = fallback.trim();
    let snippet: String = trimmed.chars().take(256).collect();
    (None, snippet)
}

const UPLOAD_LIMIT_EXACT_MSG: &str = "User rate limit exceeded.";

fn is_exact_upload_limit_403(body: &[u8]) -> Option<String> {
    let env = serde_json::from_slice::<GdriveErrorEnvelope>(body).ok()?;
    let env_msg = env.error.message.trim();
    for detail in &env.error.errors {
        if detail.reason == "userRateLimitExceeded" {
            let detail_msg = detail.message.trim();
            if detail_msg == UPLOAD_LIMIT_EXACT_MSG || env_msg == UPLOAD_LIMIT_EXACT_MSG {
                let msg = if !env_msg.is_empty() {
                    env_msg.to_string()
                } else {
                    detail_msg.to_string()
                };
                return Some(msg);
            }
        }
    }
    None
}

/// Map a Google Drive upload HTTP error into `rship_core::Error`.
///
/// When `stop_on_upload_limit == true` (`--drive-stop-on-upload-limit`), HTTP `403`
/// with reason `userRateLimitExceeded` AND exact message `"User rate limit exceeded."`
/// (Google Drive's 750 GiB/day per-user upload cap) is immediately promoted to
/// permanent `ErrorKind::QuotaExceeded` so transfers fail fast, while short-term QPS
/// bursts (`"User Rate Limit Exceeded"`, `rateLimitExceeded`) still retry with backoff.
pub fn classify_gdrive_upload_error(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
    stop_on_upload_limit: bool,
) -> Error {
    if stop_on_upload_limit
        && status == StatusCode::FORBIDDEN
        && let Some(detail) = is_exact_upload_limit_403(body)
    {
        return Error::new(
            ErrorKind::QuotaExceeded,
            RetryClass::Permanent,
            format!("{context}: HTTP 403 [UserRateLimitExceeded] (upload limit reached): {detail}"),
        );
    }
    classify_gdrive_error(context, status, headers, body, is_upload_session)
}

/// Map a Google Drive HTTP error status, headers, and body into `rship_core::Error`.
///
/// When `is_upload_session == true`, `404` and `410` map to `RetryClass::SessionExpired`
/// so the resumable state machine triggers destination reconciliation.
pub fn classify_gdrive_error(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
) -> Error {
    let retry_after = parse_retry_after(headers);
    let (reason, detail) = parse_gdrive_error_body(body);
    let reason_tag = reason
        .as_ref()
        .map(|r| format!(" [{r:?}]"))
        .unwrap_or_default();
    let full_msg = format!("{context}: HTTP {}{reason_tag}: {detail}", status.as_u16());

    match status.as_u16() {
        401 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, full_msg),
        403 => match reason {
            Some(ref r) if r.is_throttle() => Error::rate_limited(full_msg, retry_after),
            Some(ref r) if r.is_fatal_quota() => {
                Error::new(ErrorKind::QuotaExceeded, RetryClass::Permanent, full_msg)
            }
            _ => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, full_msg),
        },
        404 | 410 if is_upload_session => Error::session_expired(full_msg),
        404 => Error::not_found(full_msg),
        409 => Error::conflict(full_msg),
        412 => Error::new(
            ErrorKind::PreconditionFailed,
            RetryClass::Permanent,
            full_msg,
        ),
        429 => Error::rate_limited(full_msg, retry_after),
        503 => {
            let mut e = Error::new(ErrorKind::RateLimited, RetryClass::Throttled, full_msg);
            if let Some(ra) = retry_after {
                e = e.with_retry_after(ra);
            }
            e
        }
        500 | 502 | 504 => {
            let mut e = Error::new(ErrorKind::Network, RetryClass::Retryable, full_msg);
            if let Some(ra) = retry_after {
                e = e.with_retry_after(ra);
            }
            e
        }
        400 => Error::protocol(full_msg),
        _ if status.is_server_error() => {
            Error::new(ErrorKind::Network, RetryClass::Retryable, full_msg)
        }
        _ => Error::protocol(full_msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};

    #[test]
    fn classifies_403_throttle_vs_fatal_quota_accurately() {
        let headers = HeaderMap::new();

        let rate_limit = br#"{
            "error": {
                "code": 403,
                "message": "User rate limit exceeded.",
                "errors": [{ "domain": "usageLimits", "reason": "userRateLimitExceeded", "message": "User rate limit exceeded." }]
            }
        }"#;
        let err =
            classify_gdrive_error("upload", StatusCode::FORBIDDEN, &headers, rate_limit, false);
        assert_eq!(err.kind, ErrorKind::RateLimited);
        assert_eq!(err.retry, RetryClass::Throttled);

        let storage_quota = br#"{
            "error": {
                "code": 403,
                "message": "The user's Drive storage quota has been exceeded.",
                "errors": [{ "domain": "usageLimits", "reason": "storageQuotaExceeded", "message": "Quota exceeded." }]
            }
        }"#;
        let err2 = classify_gdrive_error(
            "upload",
            StatusCode::FORBIDDEN,
            &headers,
            storage_quota,
            false,
        );
        assert_eq!(err2.kind, ErrorKind::QuotaExceeded);
        assert_eq!(err2.retry, RetryClass::Permanent);

        let team_limit = br#"{
            "error": {
                "code": 403,
                "message": "Shared drive item limit reached",
                "errors": [{ "domain": "global", "reason": "teamDriveFileLimitExceeded" }]
            }
        }"#;
        let err3 =
            classify_gdrive_error("create", StatusCode::FORBIDDEN, &headers, team_limit, false);
        assert_eq!(err3.kind, ErrorKind::QuotaExceeded);
        assert_eq!(err3.retry, RetryClass::Permanent);
    }

    #[test]
    fn classifies_404_and_410_as_session_expired_for_uploads() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("3"),
        );

        let e404 = classify_gdrive_error("chunk", StatusCode::NOT_FOUND, &headers, b"", true);
        assert_eq!(e404.kind, ErrorKind::SessionExpired);
        assert_eq!(e404.retry, RetryClass::SessionExpired);

        let e410 = classify_gdrive_error("chunk", StatusCode::GONE, &headers, b"", true);
        assert_eq!(e410.kind, ErrorKind::SessionExpired);
        assert_eq!(e410.retry, RetryClass::SessionExpired);

        let e429 =
            classify_gdrive_error("list", StatusCode::TOO_MANY_REQUESTS, &headers, b"", false);
        assert_eq!(e429.kind, ErrorKind::RateLimited);
        assert_eq!(e429.retry, RetryClass::Throttled);
        assert_eq!(e429.retry_after, Some(std::time::Duration::from_secs(3)));

        let e409 = classify_gdrive_error("create", StatusCode::CONFLICT, &headers, b"", false);
        assert_eq!(e409.kind, ErrorKind::Conflict);
        assert_eq!(e409.retry, RetryClass::Permanent);
    }

    #[test]
    fn upload_limit_fast_fails_only_user_rate_limit_exceeded() {
        let headers = HeaderMap::new();
        let user_limit = br#"{
            "error": {
                "code": 403,
                "message": "User rate limit exceeded.",
                "errors": [{ "domain": "usageLimits", "reason": "userRateLimitExceeded" }]
            }
        }"#;
        let qps_limit = br#"{
            "error": {
                "code": 403,
                "message": "Rate Limit Exceeded",
                "errors": [{ "domain": "usageLimits", "reason": "rateLimitExceeded" }]
            }
        }"#;

        // With stop_on_upload_limit=true, 750 GiB/day userRateLimitExceeded fails fast as QuotaExceeded.
        let e1 = classify_gdrive_upload_error(
            "upload_chunk",
            StatusCode::FORBIDDEN,
            &headers,
            user_limit,
            true,
            true,
        );
        assert_eq!(e1.kind, ErrorKind::QuotaExceeded);
        assert_eq!(e1.retry, RetryClass::Permanent);

        // Generic QPS rateLimitExceeded STILL retries with CUBIC backoff!
        let e2 = classify_gdrive_upload_error(
            "upload_chunk",
            StatusCode::FORBIDDEN,
            &headers,
            qps_limit,
            true,
            true,
        );
        assert_eq!(e2.kind, ErrorKind::RateLimited);
        assert_eq!(e2.retry, RetryClass::Throttled);

        // With stop_on_upload_limit=false, userRateLimitExceeded stays retryable.
        let e3 = classify_gdrive_upload_error(
            "upload_chunk",
            StatusCode::FORBIDDEN,
            &headers,
            user_limit,
            true,
            false,
        );
        assert_eq!(e3.kind, ErrorKind::RateLimited);
        assert_eq!(e3.retry, RetryClass::Throttled);

        // Short-term burst `"User Rate Limit Exceeded"` (without exact sentence-case
        // `"User rate limit exceeded."`) MUST still retry even when stop_on_upload_limit=true!
        let burst_limit = br#"{
            "error": {
                "code": 403,
                "message": "User Rate Limit Exceeded",
                "errors": [{ "domain": "usageLimits", "reason": "userRateLimitExceeded" }]
            }
        }"#;
        let e4 = classify_gdrive_upload_error(
            "upload_chunk",
            StatusCode::FORBIDDEN,
            &headers,
            burst_limit,
            true,
            true,
        );
        assert_eq!(e4.kind, ErrorKind::RateLimited);
        assert_eq!(e4.retry, RetryClass::Throttled);
    }

    #[test]
    fn classifies_quota_exceeded_vs_daily_and_download_quota_reasons() {
        let headers = HeaderMap::new();
        let quota_throttle = br#"{
            "error": {
                "code": 403,
                "message": "Quota exceeded for quota metric",
                "errors": [{ "domain": "usageLimits", "reason": "quotaExceeded" }]
            }
        }"#;
        let e1 = classify_gdrive_error(
            "list",
            StatusCode::FORBIDDEN,
            &headers,
            quota_throttle,
            false,
        );
        assert_eq!(e1.kind, ErrorKind::RateLimited);
        assert_eq!(e1.retry, RetryClass::Throttled);

        for reason in ["dailyLimitExceeded", "downloadQuotaExceeded"] {
            let body = format!(
                r#"{{"error":{{"code":403,"message":"limit","errors":[{{"reason":"{reason}"}}]}}}}"#
            );
            let err = classify_gdrive_error(
                "download",
                StatusCode::FORBIDDEN,
                &headers,
                body.as_bytes(),
                false,
            );
            assert_eq!(err.kind, ErrorKind::QuotaExceeded, "reason={reason}");
            assert_eq!(err.retry, RetryClass::Permanent, "reason={reason}");
        }
    }
}
