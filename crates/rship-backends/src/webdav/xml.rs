//! RFC 4918 / RFC 4331 WebDAV XML `PROPFIND` multistatus parser.

use quick_xml::Reader;
use quick_xml::events::Event;
use rship_core::{Error, Result};

use crate::common::xml::{event_text, local_name};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DavPropItem {
    pub href: String,
    pub is_collection: bool,
    pub content_length: u64,
    pub last_modified_ns: i64,
    pub etag: Option<String>,
    pub quota_available_bytes: Option<u64>,
    pub quota_used_bytes: Option<u64>,
}

pub const PROPFIND_ALL_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <d:getetag/>
  </d:prop>
</d:propfind>"#;

pub const PROPFIND_QUOTA_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:quota-available-bytes/>
    <d:quota-used-bytes/>
  </d:prop>
</d:propfind>"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DavTag {
    Response,
    Href,
    Propstat,
    Status,
    Resourcetype,
    Collection,
    GetContentLength,
    GetLastModified,
    GetEtag,
    QuotaAvailableBytes,
    QuotaUsedBytes,
    Other,
}

impl DavTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        if name.eq_ignore_ascii_case("response") {
            Self::Response
        } else if name.eq_ignore_ascii_case("href") {
            Self::Href
        } else if name.eq_ignore_ascii_case("propstat") {
            Self::Propstat
        } else if name.eq_ignore_ascii_case("status") {
            Self::Status
        } else if name.eq_ignore_ascii_case("resourcetype") {
            Self::Resourcetype
        } else if name.eq_ignore_ascii_case("collection") {
            Self::Collection
        } else if name.eq_ignore_ascii_case("getcontentlength") {
            Self::GetContentLength
        } else if name.eq_ignore_ascii_case("getlastmodified") {
            Self::GetLastModified
        } else if name.eq_ignore_ascii_case("getetag") {
            Self::GetEtag
        } else if name.eq_ignore_ascii_case("quota-available-bytes") {
            Self::QuotaAvailableBytes
        } else if name.eq_ignore_ascii_case("quota-used-bytes") {
            Self::QuotaUsedBytes
        } else {
            Self::Other
        }
    }
}

fn parse_http_status_code(raw: &str) -> Option<u16> {
    raw.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
}

#[derive(Default)]
struct PropStatBuilder {
    status: String,
    is_collection: bool,
    len: String,
    lm: String,
    etag: String,
    quota_avail: String,
    quota_used: String,
}

impl PropStatBuilder {
    fn reset(&mut self) {
        self.status.clear();
        self.is_collection = false;
        self.len.clear();
        self.lm.clear();
        self.etag.clear();
        self.quota_avail.clear();
        self.quota_used.clear();
    }

    fn text_target(&mut self, tag: DavTag, parent: Option<DavTag>) -> Option<&mut String> {
        match tag {
            DavTag::Status if parent == Some(DavTag::Propstat) => Some(&mut self.status),
            DavTag::GetContentLength => Some(&mut self.len),
            DavTag::GetLastModified => Some(&mut self.lm),
            DavTag::GetEtag => Some(&mut self.etag),
            DavTag::QuotaAvailableBytes => Some(&mut self.quota_avail),
            DavTag::QuotaUsedBytes => Some(&mut self.quota_used),
            _ => None,
        }
    }

    /// Apply properties to `cur` when `<status>` is absent or has a 2xx HTTP status code.
    fn apply_if_ok(&self, cur: &mut DavPropItem) -> bool {
        let trimmed = self.status.trim();
        let status_ok = trimmed.is_empty()
            || parse_http_status_code(trimmed).is_some_and(|code| (200..300).contains(&code));
        if !status_ok {
            return false;
        }
        if self.is_collection {
            cur.is_collection = true;
        }
        if let Ok(len) = self.len.trim().parse::<u64>() {
            cur.content_length = len;
        }
        if !self.lm.trim().is_empty()
            && let Some(ns) = parse_dav_timestamp_ns(self.lm.trim())
        {
            cur.last_modified_ns = ns;
        }
        if !self.etag.trim().is_empty() {
            cur.etag = Some(self.etag.trim().to_string());
        }
        if let Ok(v) = self.quota_avail.trim().parse::<u64>() {
            cur.quota_available_bytes = Some(v);
        }
        if let Ok(v) = self.quota_used.trim().parse::<u64>() {
            cur.quota_used_bytes = Some(v);
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavResponseStatus {
    pub href: String,
    pub status_code: Option<u16>,
    pub status_line: String,
}

/// Parse an RFC 4918 `207 Multi-Status` XML response into per-`<response>` HTTP status
/// items (for `DELETE`/`COPY`/`MOVE` partial-failure inspection).
pub fn parse_multistatus_statuses(body: &[u8]) -> Result<Vec<DavResponseStatus>> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut statuses = Vec::new();
    let mut stack: Vec<DavTag> = Vec::with_capacity(8);
    let mut saw_multistatus = false;

    let mut in_response = false;
    let mut in_propstat = false;
    let mut href = String::new();
    let mut direct_status = String::new();
    let mut propstat_status = String::new();
    let mut propstat_statuses: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let lname = local_name(e.name());
                if lname.eq_ignore_ascii_case("multistatus") {
                    saw_multistatus = true;
                }
                let tag = DavTag::from_name(lname);
                match tag {
                    DavTag::Response => {
                        in_response = true;
                        in_propstat = false;
                        href.clear();
                        direct_status.clear();
                        propstat_statuses.clear();
                    }
                    DavTag::Propstat if in_response => {
                        in_propstat = true;
                        propstat_status.clear();
                    }
                    _ => {}
                }
                stack.push(tag);
            }
            Ok(Event::Empty(e)) => {
                if local_name(e.name()).eq_ignore_ascii_case("multistatus") {
                    saw_multistatus = true;
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if in_response => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = if !in_propstat
                    && top == DavTag::Href
                    && parent == Some(DavTag::Response)
                {
                    Some(&mut href)
                } else if !in_propstat && top == DavTag::Status && parent == Some(DavTag::Response)
                {
                    Some(&mut direct_status)
                } else if in_propstat && top == DavTag::Status && parent == Some(DavTag::Propstat) {
                    Some(&mut propstat_status)
                } else {
                    None
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop();
                if popped == Some(DavTag::Propstat) && in_propstat {
                    in_propstat = false;
                    let s = propstat_status.trim();
                    if !s.is_empty() {
                        propstat_statuses.push(s.to_string());
                    }
                } else if popped == Some(DavTag::Response) && in_response {
                    in_response = false;
                    let href_trimmed = href.trim().to_string();
                    let direct = direct_status.trim();
                    if !direct.is_empty() {
                        statuses.push(DavResponseStatus {
                            href: href_trimmed,
                            status_code: parse_http_status_code(direct),
                            status_line: direct.to_string(),
                        });
                    } else if !propstat_statuses.is_empty() {
                        for ps_line in propstat_statuses.drain(..) {
                            statuses.push(DavResponseStatus {
                                href: href_trimmed.clone(),
                                status_code: parse_http_status_code(&ps_line),
                                status_line: ps_line,
                            });
                        }
                    } else if !href_trimmed.is_empty() {
                        statuses.push(DavResponseStatus {
                            href: href_trimmed,
                            status_code: None,
                            status_line: String::new(),
                        });
                    }
                }
            }
            Ok(Event::Eof) => {
                if !stack.is_empty() {
                    return Err(Error::protocol(
                        "parse WebDAV 207 Multi-Status XML: unexpected EOF with unclosed elements",
                    ));
                }
                if !saw_multistatus {
                    return Err(Error::protocol(
                        "parse WebDAV 207 Multi-Status XML: missing multistatus root element",
                    ));
                }
                break;
            }
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse WebDAV 207 Multi-Status XML: {e}"
                )));
            }
            _ => {}
        }
    }

    Ok(statuses)
}

/// Parse a WebDAV `207 Multi-Status` XML response into [`DavPropItem`] entries.
/// Only properties inside `2xx` `<propstat>` blocks are applied, and `<response>`
/// elements without any `2xx` status/propstat are omitted.
pub fn parse_multistatus(body: &[u8]) -> Result<Vec<DavPropItem>> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut items = Vec::new();
    let mut stack: Vec<DavTag> = Vec::with_capacity(8);
    let mut saw_multistatus = false;

    let mut in_response = false;
    let mut cur = DavPropItem::default();
    let mut has_ok_propstat = false;
    let mut response_status = String::new();

    // Track per-`<propstat>` buffer so 404 `<propstat>` blocks don't overwrite 200 values.
    let mut in_propstat = false;
    let mut ps = PropStatBuilder::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let lname = local_name(e.name());
                if lname.eq_ignore_ascii_case("multistatus") {
                    saw_multistatus = true;
                }
                let tag = DavTag::from_name(lname);
                match tag {
                    DavTag::Response => {
                        in_response = true;
                        in_propstat = false;
                        cur = DavPropItem::default();
                        has_ok_propstat = false;
                        response_status.clear();
                    }
                    DavTag::Propstat if in_response => {
                        in_propstat = true;
                        ps.reset();
                    }
                    DavTag::Collection
                        if in_propstat && stack.last().copied() == Some(DavTag::Resourcetype) =>
                    {
                        ps.is_collection = true;
                    }
                    _ => {}
                }
                stack.push(tag);
            }
            Ok(Event::Empty(e)) => {
                let lname = local_name(e.name());
                if lname.eq_ignore_ascii_case("multistatus") {
                    saw_multistatus = true;
                } else if in_propstat
                    && stack.last().copied() == Some(DavTag::Resourcetype)
                    && DavTag::from_name(lname) == DavTag::Collection
                {
                    ps.is_collection = true;
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if in_response => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == DavTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = if !in_propstat
                    && top == DavTag::Href
                    && parent == Some(DavTag::Response)
                {
                    Some(&mut cur.href)
                } else if !in_propstat && top == DavTag::Status && parent == Some(DavTag::Response)
                {
                    Some(&mut response_status)
                } else if in_propstat {
                    ps.text_target(top, parent)
                } else {
                    None
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop();
                if popped == Some(DavTag::Propstat) && in_propstat {
                    in_propstat = false;
                    if ps.apply_if_ok(&mut cur) {
                        has_ok_propstat = true;
                    }
                } else if popped == Some(DavTag::Response) && in_response {
                    in_response = false;
                    let trimmed = cur.href.trim();
                    if trimmed.len() != cur.href.len() {
                        cur.href = trimmed.to_string();
                    }
                    let resp_status_trimmed = response_status.trim();
                    let resp_status_ok = if resp_status_trimmed.is_empty() {
                        None
                    } else {
                        Some(
                            parse_http_status_code(resp_status_trimmed)
                                .is_some_and(|code| (200..300).contains(&code)),
                        )
                    };
                    if !cur.href.is_empty()
                        && resp_status_ok != Some(false)
                        && (has_ok_propstat || resp_status_ok == Some(true))
                    {
                        items.push(std::mem::take(&mut cur));
                    }
                }
            }
            Ok(Event::Eof) => {
                if !stack.is_empty() {
                    return Err(Error::protocol(
                        "parse WebDAV PROPFIND XML: unexpected EOF with unclosed elements",
                    ));
                }
                if !saw_multistatus {
                    return Err(Error::protocol(
                        "parse WebDAV PROPFIND XML: missing multistatus root element",
                    ));
                }
                break;
            }
            Err(e) => return Err(Error::protocol(format!("parse WebDAV PROPFIND XML: {e}"))),
            _ => {}
        }
    }

    Ok(items)
}

pub fn parse_dav_timestamp_ns(raw: &str) -> Option<i64> {
    rship_core::time::parse_http_date_to_nanos(raw)
        .or_else(|| rship_core::time::parse_rfc3339_to_nanos(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_dav_timestamps_accept_http_date_and_rfc3339() {
        let want = Some(784_111_777_000_000_000);
        assert_eq!(
            parse_dav_timestamp_ns("Sun, 06 Nov 1994 08:49:37 GMT"),
            want
        );
        assert_eq!(
            parse_dav_timestamp_ns("Sun, 06 Nov 1994 08:49:37 +0000"),
            want
        );
        assert_eq!(parse_dav_timestamp_ns("1994-11-06T08:49:37Z"), want);
        assert_eq!(
            parse_dav_timestamp_ns("1994-11-06T09:49:37.25+01:00"),
            Some(784_111_777_250_000_000)
        );
        assert_eq!(parse_dav_timestamp_ns("yesterday"), None);
    }

    #[test]
    fn parses_multistatus_files_dirs_and_quotas() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/docs/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
        <d:quota-available-bytes>900000</d:quota-available-bytes>
        <d:quota-used-bytes>100000</d:quota-used-bytes>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/docs/hello%20world.txt</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>42</d:getcontentlength>
        <d:getlastmodified>Tue, 24 Nov 2026 12:00:00 GMT</d:getlastmodified>
        <d:getetag>"abc123"</d:getetag>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
    <d:propstat>
      <d:prop><d:quota-used-bytes/></d:prop>
      <d:status>HTTP/1.1 404 Not Found</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

        let items = parse_multistatus(xml).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_collection);
        assert_eq!(items[0].quota_available_bytes, Some(900_000));
        assert_eq!(items[0].quota_used_bytes, Some(100_000));

        assert!(!items[1].is_collection);
        assert_eq!(items[1].content_length, 42);
        assert_eq!(items[1].etag.as_deref(), Some("\"abc123\""));
        assert!(items[1].last_modified_ns > 0);
    }

    #[test]
    fn filters_non_2xx_propstat_and_response_without_emitting_phantom_zero_byte_files() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/docs/missing.txt</d:href>
    <d:propstat>
      <d:prop><d:getcontentlength/><d:resourcetype/></d:prop>
      <d:status>HTTP/1.1 404 Not Found</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/docs/denied.txt</d:href>
    <d:status>HTTP/1.1 403 Forbidden</d:status>
  </d:response>
  <d:response>
    <d:href>/dav/docs/valid.txt</d:href>
    <d:propstat>
      <d:prop><d:getcontentlength>17</d:getcontentlength></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
    <d:propstat>
      <d:prop><d:quota-used-bytes/></d:prop>
      <d:status>HTTP/1.1 404 Not Found</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

        let items = parse_multistatus(xml).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].href, "/dav/docs/valid.txt");
        assert_eq!(items[0].content_length, 17);
    }

    #[test]
    fn parses_multistatus_mutation_statuses_for_delete_copy_move() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/dir/ok.txt</d:href>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:response>
  <d:response>
    <d:href>/dav/dir/locked.txt</d:href>
    <d:status>HTTP/1.1 423 Locked</d:status>
  </d:response>
  <d:response>
    <d:href>/dav/dir/forbidden.txt</d:href>
    <d:propstat>
      <d:prop><d:resourcetype/></d:prop>
      <d:status>HTTP/1.1 403 Forbidden</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

        let statuses = parse_multistatus_statuses(xml).unwrap();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[0].href, "/dav/dir/ok.txt");
        assert_eq!(statuses[0].status_code, Some(200));
        assert_eq!(statuses[1].href, "/dav/dir/locked.txt");
        assert_eq!(statuses[1].status_code, Some(423));
        assert_eq!(statuses[2].href, "/dav/dir/forbidden.txt");
        assert_eq!(statuses[2].status_code, Some(403));
    }

    #[test]
    fn rejects_truncated_empty_and_non_multistatus_xml_while_accepting_self_closing_elements() {
        // Truncated 207 statuses: closed 200 followed by unclosed 403 at EOF.
        let truncated_207_inner = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/ok.txt</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>
  <d:response><d:href>/dav/bad.txt</d:href><d:status>HTTP/1.1 403 Forbidden"#;
        let err = parse_multistatus_statuses(truncated_207_inner)
            .expect_err("truncated 207 response must fail");
        assert_eq!(err.kind, rship_core::ErrorKind::Protocol, "got: {err:?}");

        // Truncated between </d:response> and </d:multistatus>.
        let truncated_207_root = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/ok.txt</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>"#;
        assert!(parse_multistatus_statuses(truncated_207_root).is_err());

        // Truncated PROPFIND response.
        let truncated_propfind = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/real.txt</d:href>
    <d:propstat><d:prop><d:getcontentlength>9</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/cut.txt</d:href>"#;
        let err = parse_multistatus(truncated_propfind).expect_err("truncated PROPFIND must fail");
        assert_eq!(err.kind, rship_core::ErrorKind::Protocol, "got: {err:?}");

        let truncated_propfind_root = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/real.txt</d:href>
    <d:propstat><d:prop><d:getcontentlength>9</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>"#;
        assert!(parse_multistatus(truncated_propfind_root).is_err());

        // Empty / declaration-only / non-multistatus root must all error.
        for bad in [
            b"".as_slice(),
            b"<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            b"<html><body>error</body></html>",
            b"<html/>",
        ] {
            assert!(
                parse_multistatus_statuses(bad).is_err(),
                "statuses should reject {:?}",
                String::from_utf8_lossy(bad)
            );
            assert!(
                parse_multistatus(bad).is_err(),
                "propfind should reject {:?}",
                String::from_utf8_lossy(bad)
            );
        }

        // Valid self-closing <d:multistatus/>, <d:response/>, and <d:resourcetype><d:collection/></d:resourcetype>.
        let self_closing_root =
            br#"<?xml version="1.0" encoding="utf-8"?><D:MultiStatus xmlns:D="DAV:"/>"#;
        assert!(
            parse_multistatus_statuses(self_closing_root)
                .unwrap()
                .is_empty()
        );
        assert!(parse_multistatus(self_closing_root).unwrap().is_empty());

        let empty_pair_root = br#"<d:multistatus xmlns:d="DAV:"></d:multistatus>"#;
        assert!(
            parse_multistatus_statuses(empty_pair_root)
                .unwrap()
                .is_empty()
        );
        assert!(parse_multistatus(empty_pair_root).unwrap().is_empty());

        let self_closing_resp = br#"<d:multistatus xmlns:d="DAV:">
  <d:response/>
  <d:response>
    <d:href>/dav/col/</d:href>
    <d:propstat>
      <d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
        assert!(parse_multistatus_statuses(self_closing_resp).unwrap().len() == 1);
        let parsed = parse_multistatus(self_closing_resp).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_collection);
        assert_eq!(parsed[0].href, "/dav/col/");
    }
}
