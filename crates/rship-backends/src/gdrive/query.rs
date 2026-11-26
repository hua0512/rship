//! Google Drive v3 query escaping, explicit `fields` masks, timestamp helpers,
//! MIME classification, and `308 Resume Incomplete` `Range` parsing.

use http::HeaderMap;
use rship_core::{Error, Result};
use url::Url;

pub const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
pub const SHORTCUT_MIME: &str = "application/vnd.google-apps.shortcut";
pub const WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";

/// Explicit minimal `fields` mask for single-file responses (`files.get`, `files.create`,
/// `files.update`, and resumable upload completion).
pub const FILE_FIELDS: &str = "id,name,mimeType,size,modifiedTime,md5Checksum,sha1Checksum,sha256Checksum,parents,trashed,sharedWithMeTime,shortcutDetails(targetId,targetMimeType),appProperties";

/// Explicit `fields` mask for `files.list` (includes `incompleteSearch` for Observation
/// Completeness Gate!).
pub const FILE_LIST_FIELDS: &str = "nextPageToken,incompleteSearch,files(id,name,mimeType,size,modifiedTime,md5Checksum,sha1Checksum,sha256Checksum,parents,trashed,sharedWithMeTime,shortcutDetails(targetId,targetMimeType),appProperties)";

/// Explicit `fields` mask for `changes.list`.
pub const CHANGES_LIST_FIELDS: &str = "nextPageToken,newStartPageToken,changes(fileId,removed,file(id,name,mimeType,size,modifiedTime,md5Checksum,sha1Checksum,sha256Checksum,parents,trashed,sharedWithMeTime,shortcutDetails(targetId,targetMimeType),appProperties))";

/// Escape a string literal for Google Drive `q` expressions (`name = '<escaped>'`).
///
/// Escapes backslashes (`\` -> `\\`) BEFORE single quotes (`'` -> `\'`), matching
/// Google Drive API query grammar and passing rclone's `SingleQuoteFolder` suite.
pub fn escape_query_literal(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '\'' => out.push_str(r"\'"),
            other => out.push(other),
        }
    }
    out
}

/// Returns `true` for export-only Google Workspace native documents (Docs, Sheets,
/// Slides, Forms, Drawings, etc.) that have no downloadable binary blob via `alt=media`.
/// Folders and shortcuts return `false`.
pub fn is_exportable_workspace_doc(mime_type: &str) -> bool {
    mime_type.starts_with(WORKSPACE_MIME_PREFIX)
        && mime_type != FOLDER_MIME
        && mime_type != SHORTCUT_MIME
}

/// Parse Google Drive's `308 Resume Incomplete` `Range` header into the exact next
/// byte offset (`confirmed_offset`).
///
/// Rules (`CONFORMANCE_TESTS.md` §4 & Google Drive v3 resumable upload spec):
/// - Missing `Range` header -> `0` bytes acknowledged so far.
/// - `Range: bytes=0-N` -> `N + 1` bytes acknowledged (next byte to transmit).
pub fn parse_content_range_308(headers: &HeaderMap) -> Result<u64> {
    let Some(val) = headers.get(http::header::RANGE) else {
        return Ok(0);
    };
    let s = val
        .to_str()
        .map_err(|_| Error::protocol("non-ASCII Range header in 308 response"))?
        .trim();
    if s.is_empty() {
        return Ok(0);
    }
    let rest = s
        .strip_prefix("bytes=")
        .ok_or_else(|| Error::protocol(format!("malformed 308 Range header `{s}`")))?;
    let (start_s, end_s) = rest
        .split_once('-')
        .ok_or_else(|| Error::protocol(format!("malformed 308 Range header `{s}`")))?;
    let start: u64 = start_s
        .parse()
        .map_err(|_| Error::protocol(format!("invalid Range start in `{s}`")))?;
    let end: u64 = end_s
        .parse()
        .map_err(|_| Error::protocol(format!("invalid Range end in `{s}`")))?;
    if start != 0 || end < start {
        return Err(Error::protocol(format!(
            "unexpected non-zero-based 308 Range header `{s}`"
        )));
    }
    end.checked_add(1)
        .ok_or_else(|| Error::protocol("308 Range end overflows u64"))
}

/// Ensure a resumable `session_uri` includes `fields={FILE_FIELDS}` and
/// `supportsAllDrives=true` so both `query_upload` and final chunk `200`/`201`
/// responses return full metadata (including `md5Checksum` and `appProperties`).
pub fn ensure_session_uri_params(session_uri: &str) -> Result<String> {
    let mut url = Url::parse(session_uri).map_err(|e| {
        Error::protocol(format!(
            "invalid resumable session_uri `{session_uri}`: {e}"
        ))
    })?;
    let mut has_fields = false;
    let mut has_all_drives = false;
    for (k, _) in url.query_pairs() {
        if k == "fields" {
            has_fields = true;
        } else if k == "supportsAllDrives" {
            has_all_drives = true;
        }
    }
    {
        let mut qp = url.query_pairs_mut();
        if !has_fields {
            qp.append_pair("fields", FILE_FIELDS);
        }
        if !has_all_drives {
            qp.append_pair("supportsAllDrives", "true");
        }
    }
    Ok(url.into())
}

/// Format Unix nanoseconds as RFC 3339 with millisecond precision (Google Drive `modifiedTime`).
pub fn format_rfc3339_millis(mtime_ns: i64) -> String {
    rship_core::time::format_rfc3339_millis(mtime_ns)
}

/// Parse an RFC 3339 timestamp string into Unix nanoseconds.
pub fn parse_rfc3339_nanos(s: &str) -> i64 {
    rship_core::time::parse_rfc3339_to_nanos(s).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};

    #[test]
    fn golden_modified_time_formats_and_parses() {
        assert_eq!(
            format_rfc3339_millis(1_737_000_000_123_456_789),
            "2025-01-16T04:00:00.123Z"
        );
        assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            parse_rfc3339_nanos("2025-01-16T04:00:00.123Z"),
            1_737_000_000_123_000_000
        );
        assert_eq!(
            parse_rfc3339_nanos("2025-01-16T05:00:00.5+01:00"),
            1_737_000_000_500_000_000
        );
        assert_eq!(parse_rfc3339_nanos("garbage"), 0);
    }

    #[test]
    fn escapes_single_quotes_and_backslashes_in_drive_queries() {
        assert_eq!(escape_query_literal("O'Reilly"), r"O\'Reilly");
        assert_eq!(escape_query_literal(r"a\b'c\'d"), r"a\\b\'c\\\'d");
        assert_eq!(escape_query_literal("plain-name_1.txt"), "plain-name_1.txt");
    }

    #[test]
    fn classifies_workspace_docs_vs_folders_and_shortcuts() {
        assert!(is_exportable_workspace_doc(
            "application/vnd.google-apps.document"
        ));
        assert!(is_exportable_workspace_doc(
            "application/vnd.google-apps.spreadsheet"
        ));
        assert!(!is_exportable_workspace_doc(FOLDER_MIME));
        assert!(!is_exportable_workspace_doc(SHORTCUT_MIME));
        assert!(!is_exportable_workspace_doc("application/octet-stream"));
    }

    #[test]
    fn parses_308_range_headers_including_missing_range_as_zero() {
        let empty = HeaderMap::new();
        assert_eq!(parse_content_range_308(&empty).unwrap(), 0);

        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("range"),
            HeaderValue::from_static("bytes=0-262143"),
        );
        assert_eq!(parse_content_range_308(&h).unwrap(), 262_144);

        h.insert(
            HeaderName::from_static("range"),
            HeaderValue::from_static("bytes=0-0"),
        );
        assert_eq!(parse_content_range_308(&h).unwrap(), 1);

        h.insert(
            HeaderName::from_static("range"),
            HeaderValue::from_static("bytes=10-20"),
        );
        assert!(parse_content_range_308(&h).is_err());
    }

    #[test]
    fn session_uri_appends_fields_and_supports_all_drives_idempotently() {
        let raw =
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc";
        let enriched = ensure_session_uri_params(raw).unwrap();
        assert!(enriched.contains("fields="));
        assert!(enriched.contains("supportsAllDrives=true"));
        assert!(enriched.contains("upload_id=abc"));

        // Second call must not duplicate query params.
        let enriched2 = ensure_session_uri_params(&enriched).unwrap();
        assert_eq!(enriched, enriched2);
    }
}
