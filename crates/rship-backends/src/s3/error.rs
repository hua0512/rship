//! S3 HTTP status and `<Error><Code>` XML error classifier.

use http::{HeaderMap, StatusCode};
use rship_core::{Error, ErrorKind, RetryClass};
use rship_transport::parse_retry_after;

use crate::s3::xml::{S3ErrorXml, parse_s3_error_xml};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3ErrorCode {
    SlowDown,
    RequestLimitExceeded,
    ServiceUnavailable,
    InternalError,
    RequestTimeout,
    NoSuchUpload,
    NoSuchKey,
    NoSuchBucket,
    PreconditionFailed,
    AccessDenied,
    RequestTimeTooSkewed,
    InvalidObjectState,
    InvalidPart,
    InvalidPartOrder,
    EntityTooSmall,
    EntityTooLarge,
    Other(String),
}

impl S3ErrorCode {
    pub fn parse(code: &str) -> Self {
        match code {
            "SlowDown" | "Throttling" | "ThrottlingException" | "TooManyRequests" => Self::SlowDown,
            "RequestLimitExceeded" => Self::RequestLimitExceeded,
            "ServiceUnavailable" => Self::ServiceUnavailable,
            "InternalError" => Self::InternalError,
            "RequestTimeout" => Self::RequestTimeout,
            "NoSuchUpload" => Self::NoSuchUpload,
            "NoSuchKey" => Self::NoSuchKey,
            "NoSuchBucket" => Self::NoSuchBucket,
            "PreconditionFailed" | "ConditionalRequestConflict" => Self::PreconditionFailed,
            "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" | "ExpiredToken" => {
                Self::AccessDenied
            }
            "RequestTimeTooSkewed" => Self::RequestTimeTooSkewed,
            "InvalidObjectState" => Self::InvalidObjectState,
            "InvalidPart" => Self::InvalidPart,
            "InvalidPartOrder" => Self::InvalidPartOrder,
            "EntityTooSmall" => Self::EntityTooSmall,
            "EntityTooLarge" => Self::EntityTooLarge,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Returns `true` when an S3 error response indicates expired/invalid temporary STS credentials
/// that warrant a single forced credential refresh and retry.
///
/// Note: HTTP `HEAD` (`HeadObject`) responses never carry an XML body, so AWS S3 returns an
/// empty-body `400` or `403` when an STS token expires; callers gate refresh to once per request.
pub fn is_expired_token_error(method: &http::Method, status: StatusCode, body: &[u8]) -> bool {
    if !matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
    ) {
        return false;
    }
    if let Some(xml_err) = parse_s3_error_xml(body) {
        return matches!(
            xml_err.code.as_str(),
            "ExpiredToken" | "ExpiredTokenException" | "InvalidToken" | "TokenRefreshRequired"
        );
    }
    status == StatusCode::UNAUTHORIZED
        || (*method == http::Method::HEAD
            && body.is_empty()
            && matches!(status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN))
}

/// Classify a parsed `<Error>` XML body (including one returned inside HTTP `200 OK`
/// on `CompleteMultipartUpload`!).
pub fn classify_s3_xml_error(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    xml_err: &S3ErrorXml,
) -> Error {
    let retry_after = parse_retry_after(headers);
    let code = S3ErrorCode::parse(&xml_err.code);
    let msg = format!(
        "{context}: HTTP {} [{}]: {}",
        status.as_u16(),
        xml_err.code,
        xml_err.message
    );

    match code {
        S3ErrorCode::SlowDown
        | S3ErrorCode::RequestLimitExceeded
        | S3ErrorCode::ServiceUnavailable => Error::rate_limited(msg, retry_after),
        S3ErrorCode::NoSuchUpload => Error::session_expired(msg),
        S3ErrorCode::NoSuchKey | S3ErrorCode::NoSuchBucket => Error::not_found(msg),
        S3ErrorCode::PreconditionFailed => {
            Error::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg)
        }
        S3ErrorCode::AccessDenied => {
            Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg)
        }
        S3ErrorCode::InvalidObjectState => Error::new(
            ErrorKind::Unsupported,
            RetryClass::Permanent,
            format!(
                "{msg} (object is archived in Glacier/Deep Archive and must be restored via RestoreObject before reading or copying)"
            ),
        ),
        S3ErrorCode::InternalError
        | S3ErrorCode::RequestTimeout
        | S3ErrorCode::RequestTimeTooSkewed => {
            let mut e = Error::new(ErrorKind::Network, RetryClass::Retryable, msg);
            if let Some(ra) = retry_after {
                e = e.with_retry_after(ra);
            }
            e
        }
        S3ErrorCode::InvalidPart
        | S3ErrorCode::InvalidPartOrder
        | S3ErrorCode::EntityTooSmall
        | S3ErrorCode::EntityTooLarge => {
            Error::new(ErrorKind::InvalidGeometry, RetryClass::Permanent, msg)
        }
        S3ErrorCode::Other(_) => classify_by_status(context, status, headers, &msg),
    }
}

/// Classify an S3 HTTP error response (inspecting XML `<Code>` first, falling back
/// to HTTP status code).
pub fn classify_s3_error(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_multipart_op: bool,
) -> Error {
    if let Some(xml_err) = parse_s3_error_xml(body) {
        return classify_s3_xml_error(context, status, headers, &xml_err);
    }

    let snippet: String = String::from_utf8_lossy(body)
        .trim()
        .chars()
        .take(256)
        .collect();
    let msg = format!("{context}: HTTP {}: {snippet}", status.as_u16());

    if is_multipart_op && status == StatusCode::NOT_FOUND {
        return Error::session_expired(msg);
    }
    classify_by_status(context, status, headers, &msg)
}

fn classify_by_status(_context: &str, status: StatusCode, headers: &HeaderMap, msg: &str) -> Error {
    let retry_after = parse_retry_after(headers);
    match status.as_u16() {
        401 | 403 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg),
        404 => Error::not_found(msg),
        409 | 412 => Error::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg),
        429 | 503 => Error::rate_limited(msg, retry_after),
        500 | 502 | 504 => {
            let mut e = Error::new(ErrorKind::Network, RetryClass::Retryable, msg);
            if let Some(ra) = retry_after {
                e = e.with_retry_after(ra);
            }
            e
        }
        400 => Error::protocol(msg),
        _ if status.is_server_error() => Error::new(ErrorKind::Network, RetryClass::Retryable, msg),
        _ => Error::protocol(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_request_time_too_skewed_and_invalid_object_state() {
        let skewed_body = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>RequestTimeTooSkewed</Code>
  <Message>The difference between the request time and the current time is too large.</Message>
  <ServerTime>2026-11-27T10:30:00Z</ServerTime>
</Error>"#;
        let err = classify_s3_error(
            "HeadObject",
            StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            skewed_body,
            false,
        );
        assert_eq!(err.kind, ErrorKind::Network);
        assert_eq!(err.retry, RetryClass::Retryable);

        let glacier_body = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidObjectState</Code>
  <Message>The operation is not valid for the object's storage class</Message>
</Error>"#;
        let err = classify_s3_error(
            "GetObject",
            StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            glacier_body,
            false,
        );
        assert_eq!(err.kind, ErrorKind::Unsupported);
        assert_eq!(err.retry, RetryClass::Permanent);
        assert!(err.message.contains("RestoreObject"));
    }
}
