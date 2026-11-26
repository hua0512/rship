//! S3 XML serialization and parsing, including mandatory HTTP `200 OK` `<Error>`
//! body inspection for `CompleteMultipartUpload` (`PLAN.md` P0-5).

use quick_xml::Reader;
use quick_xml::events::Event;
use rship_core::{Error, Result};

use crate::common::xml::{escape_xml_text, event_text, local_name};
use crate::s3::sigv4::{decode_s3_url_encoded_key, decode_s3_url_encoded_key_owned};

/// Fast-path ASCII parser for canonical S3 UTC ISO-8601 timestamps
/// (`YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.fffffffffZ`), avoiding
/// general RFC 3339 parsing and per-object `String` allocations during XML parsing.
pub(crate) fn parse_utc_rfc3339_fast_nanos(raw: &str) -> Option<i64> {
    let b = raw.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
        || !matches!(b[b.len() - 1], b'Z' | b'z')
    {
        return None;
    }
    let d2 = |i: usize| -> Option<u32> {
        let a = b[i].wrapping_sub(b'0');
        let c = b[i + 1].wrapping_sub(b'0');
        (a < 10 && c < 10).then(|| u32::from(a) * 10 + u32::from(c))
    };
    let year = (d2(0)? * 100 + d2(2)?) as i64;
    let month = d2(5)?;
    let day = d2(8)?;
    let hour = d2(11)?;
    let min = d2(14)?;
    let sec = d2(17)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        2 if is_leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > max_day {
        return None;
    }
    let nanos: i64 = if b.len() == 20 {
        0
    } else if b[19] == b'.' {
        let frac = &b[20..b.len() - 1];
        if frac.is_empty() || frac.len() > 9 {
            return None;
        }
        let mut n = 0i64;
        for &ch in frac {
            let dig = ch.wrapping_sub(b'0');
            if dig >= 10 {
                return None;
            }
            n = n * 10 + i64::from(dig);
        }
        for _ in frac.len()..9 {
            n *= 10;
        }
        n
    } else {
        return None;
    };
    // Howard Hinnant's civil-to-days algorithm (days since 1970-01-01).
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

pub(crate) fn parse_rfc3339_or_http_nanos(raw: &str) -> Option<i64> {
    if let Some(ns) = parse_utc_rfc3339_fast_nanos(raw) {
        return Some(ns);
    }
    rship_core::time::parse_rfc3339_to_nanos(raw)
        .or_else(|| rship_core::time::parse_http_date_to_nanos(raw))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ErrorXml {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedObject {
    pub key: String,
    pub size: u64,
    pub last_modified_ns: Option<i64>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListObjectsV2Page {
    pub objects: Vec<ListedObject>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
    /// Legacy ListObjects v1 pagination marker (`<NextMarker>`), populated by older
    /// OpenStack Swift `swift3` and S3-compatible gateways that ignore `list-type=2`.
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedPart {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    /// Optional tagged S3 part checksum (`"crc64nvme:<b64>"`, `"crc32c:<b64>"`, `"sha256:<b64>"`).
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListPartsPage {
    pub parts: Vec<ListedPart>,
    pub is_truncated: bool,
    pub next_part_number_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedMultipartUpload {
    pub key: String,
    pub upload_id: String,
    pub initiated: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListMultipartUploadsPage {
    pub uploads: Vec<ListedMultipartUpload>,
    pub is_truncated: bool,
    pub next_key_marker: Option<String>,
    pub next_upload_id_marker: Option<String>,
}

/// Outcome of parsing a `CopyObject` or `UploadPartCopy` HTTP `200 OK` XML body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyResultBody {
    Completed {
        etag: Option<String>,
        last_modified: Option<String>,
        checksum: Option<String>,
    },
    /// AWS S3 & clones can return an `<Error>` XML document inside HTTP `200 OK`
    /// during `CopyObject` and `UploadPartCopy`!
    Error(S3ErrorXml),
}

/// Parse `<CopyObjectResult>` or `<CopyPartResult>`, detecting `<Error>` XML inside `200 OK`.
pub fn parse_copy_result(body: &[u8]) -> Result<CopyResultBody> {
    if let Some(err) = parse_s3_error_xml(body) {
        return Ok(CopyResultBody::Error(err));
    }

    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut saw_root = false;
    let mut current = String::new();
    let mut etag = String::new();
    let mut last_modified = String::new();
    let mut crc64 = String::new();
    let mut crc32c = String::new();
    let mut sha256 = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if !saw_root {
                    if name == "CopyObjectResult" || name == "CopyPartResult" {
                        saw_root = true;
                    } else if name == "Error" {
                        return Err(Error::network(
                            "S3 copy 200 OK returned malformed <Error> body",
                        ));
                    }
                } else {
                    current.clear();
                    current.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if saw_root => {
                if let Some(text) = event_text(&ev)? {
                    match current.as_str() {
                        "ETag" => etag.push_str(&text),
                        "LastModified" => last_modified.push_str(&text),
                        "ChecksumCRC64NVME" => crc64.push_str(&text),
                        "ChecksumCRC32C" => crc32c.push_str(&text),
                        "ChecksumSHA256" => sha256.push_str(&text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(_)) => current.clear(),
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::network(format!(
                    "truncated or invalid S3 CopyResult XML body: {e}"
                )));
            }
            _ => {}
        }
    }

    if !saw_root {
        return Err(Error::network(
            "S3 copy 200 OK missing <CopyObjectResult>/<CopyPartResult> body",
        ));
    }
    let checksum = tagged_part_checksum(crc64.trim(), crc32c.trim(), sha256.trim());
    Ok(CopyResultBody::Completed {
        etag: (!etag.trim().is_empty()).then(|| etag.trim().to_string()),
        last_modified: (!last_modified.trim().is_empty()).then(|| last_modified.trim().to_string()),
        checksum,
    })
}

fn tagged_part_checksum(crc64: &str, crc32c: &str, sha256: &str) -> Option<String> {
    if !crc64.is_empty() {
        Some(format!("crc64nvme:{crc64}"))
    } else if !crc32c.is_empty() {
        Some(format!("crc32c:{crc32c}"))
    } else if !sha256.is_empty() {
        Some(format!("sha256:{sha256}"))
    } else {
        None
    }
}

/// Outcome of parsing a `CompleteMultipartUpload` HTTP `200 OK` XML body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteMultipartBody {
    Completed {
        etag: Option<String>,
        checksum_crc64nvme: Option<String>,
        checksum_crc32c: Option<String>,
        checksum_sha256: Option<String>,
    },
    /// AWS S3 & clones can return an `<Error>` XML document inside HTTP `200 OK`!
    Error(S3ErrorXml),
}

/// Try to parse an S3 `<Error>` XML payload.
pub fn parse_s3_error_xml(body: &[u8]) -> Option<S3ErrorXml> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut in_error = false;
    let mut current_tag = String::new();
    let mut code = String::new();
    let mut message = String::new();
    let mut request_id = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if !in_error {
                    if name == "Error" {
                        in_error = true;
                    } else {
                        return None;
                    }
                } else {
                    current_tag.clear();
                    current_tag.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if in_error => {
                // Preserve `<Code>` even if `<Message>`/`<RequestId>` contains an unusual entity.
                let text = match event_text(&ev) {
                    Ok(Some(t)) => t,
                    _ => continue,
                };
                match current_tag.as_str() {
                    "Code" => code.push_str(&text),
                    "Message" => message.push_str(&text),
                    "RequestId" => request_id.push_str(&text),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name());
                if name == "Error" {
                    break;
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    if !in_error || code.is_empty() {
        return None;
    }
    Some(S3ErrorXml {
        code,
        message,
        request_id: (!request_id.is_empty()).then_some(request_id),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListV2Tag {
    ListBucketResult,
    EncodingType,
    IsTruncated,
    NextContinuationToken,
    NextMarker,
    Contents,
    Key,
    Size,
    LastModified,
    ETag,
    CommonPrefixes,
    Prefix,
    Other,
}

impl ListV2Tag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "ListBucketResult" => Self::ListBucketResult,
            "EncodingType" => Self::EncodingType,
            "IsTruncated" => Self::IsTruncated,
            "NextContinuationToken" => Self::NextContinuationToken,
            "NextMarker" => Self::NextMarker,
            "Contents" => Self::Contents,
            "Key" => Self::Key,
            "Size" => Self::Size,
            "LastModified" => Self::LastModified,
            "ETag" => Self::ETag,
            "CommonPrefixes" => Self::CommonPrefixes,
            "Prefix" => Self::Prefix,
            _ => Self::Other,
        }
    }
}

/// Parse `ListObjectsV2` (and legacy v1 fallback) XML response, decoding URL-encoded
/// keys/prefixes whenever `<EncodingType>url</EncodingType>` is present.
pub fn parse_list_objects_v2(body: &[u8]) -> Result<ListObjectsV2Page> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut page = ListObjectsV2Page {
        objects: Vec::with_capacity((body.len() / 220).min(1024)),
        ..Default::default()
    };
    let mut encoding_url = false;
    let mut stack: Vec<ListV2Tag> = Vec::with_capacity(8);

    let mut cur_key = String::new();
    let mut cur_size = String::new();
    let mut cur_lm = String::new();
    let mut cur_etag = String::with_capacity(64);
    let mut cur_prefix = String::new();
    let mut raw_next_token = String::new();
    let mut raw_next_marker = String::new();
    let mut raw_truncated = String::new();
    let mut raw_encoding = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = ListV2Tag::from_name(local_name(e.name()));
                let parent = stack.last().copied();
                if parent == Some(ListV2Tag::ListBucketResult) {
                    if tag == ListV2Tag::Contents {
                        cur_key.clear();
                        cur_size.clear();
                        cur_lm.clear();
                        cur_etag.clear();
                    } else if tag == ListV2Tag::CommonPrefixes {
                        cur_prefix.clear();
                    }
                }
                stack.push(tag);
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == ListV2Tag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = match (parent, top) {
                    (Some(ListV2Tag::Contents), ListV2Tag::Key) => Some(&mut cur_key),
                    (Some(ListV2Tag::Contents), ListV2Tag::Size) => Some(&mut cur_size),
                    (Some(ListV2Tag::Contents), ListV2Tag::LastModified) => Some(&mut cur_lm),
                    (Some(ListV2Tag::Contents), ListV2Tag::ETag) => Some(&mut cur_etag),
                    (Some(ListV2Tag::CommonPrefixes), ListV2Tag::Prefix) => Some(&mut cur_prefix),
                    (Some(ListV2Tag::ListBucketResult), ListV2Tag::EncodingType) => {
                        Some(&mut raw_encoding)
                    }
                    (Some(ListV2Tag::ListBucketResult), ListV2Tag::IsTruncated) => {
                        Some(&mut raw_truncated)
                    }
                    (Some(ListV2Tag::ListBucketResult), ListV2Tag::NextContinuationToken) => {
                        Some(&mut raw_next_token)
                    }
                    (Some(ListV2Tag::ListBucketResult), ListV2Tag::NextMarker) => {
                        Some(&mut raw_next_marker)
                    }
                    _ => None,
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop();
                let parent = stack.last().copied();
                match (parent, popped) {
                    (Some(ListV2Tag::ListBucketResult), Some(ListV2Tag::EncodingType)) => {
                        encoding_url = raw_encoding.trim().eq_ignore_ascii_case("url");
                    }
                    (Some(ListV2Tag::ListBucketResult), Some(ListV2Tag::Contents)) => {
                        let size = cur_size.trim().parse::<u64>().unwrap_or(0);
                        let lm_trimmed = cur_lm.trim();
                        let last_modified_ns = if lm_trimmed.is_empty() {
                            None
                        } else {
                            parse_rfc3339_or_http_nanos(lm_trimmed)
                        };
                        let etag_trimmed = cur_etag.trim();
                        let etag = (!etag_trimmed.is_empty()).then(|| etag_trimmed.to_owned());
                        page.objects.push(ListedObject {
                            key: std::mem::take(&mut cur_key),
                            size,
                            last_modified_ns,
                            etag,
                        });
                    }
                    (Some(ListV2Tag::ListBucketResult), Some(ListV2Tag::CommonPrefixes))
                        if !cur_prefix.is_empty() =>
                    {
                        page.common_prefixes.push(std::mem::take(&mut cur_prefix));
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse ListObjectsV2 XML failed: {e}"
                )));
            }
            _ => {}
        }
    }

    // Decode URL-encoded keys/prefixes AFTER parsing the full document so servers that
    // emit `<EncodingType>url</EncodingType>` after `<Contents>` are handled identically.
    if encoding_url {
        for obj in &mut page.objects {
            let owned = std::mem::take(&mut obj.key);
            obj.key = decode_s3_url_encoded_key_owned(owned)?;
        }
        for p in &mut page.common_prefixes {
            let owned = std::mem::take(p);
            *p = decode_s3_url_encoded_key_owned(owned)?;
        }
    }

    page.is_truncated = raw_truncated.trim().eq_ignore_ascii_case("true");
    if !raw_next_token.trim().is_empty() {
        page.next_continuation_token = Some(raw_next_token.trim().to_string());
    }
    if !raw_next_marker.trim().is_empty() {
        let marker = raw_next_marker.trim();
        page.next_marker = Some(if encoding_url {
            decode_s3_url_encoded_key(marker)?
        } else {
            marker.to_string()
        });
    }
    Ok(page)
}

/// Parse `<InitiateMultipartUploadResult><UploadId>...</UploadId></InitiateMultipartUploadResult>`.
pub fn parse_initiate_multipart_upload(body: &[u8]) -> Result<String> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut current = String::new();
    let mut upload_id = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                current.clear();
                current.push_str(local_name(e.name()));
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)))
                if current == "UploadId" =>
            {
                if let Some(text) = event_text(&ev)? {
                    upload_id.push_str(&text);
                }
            }
            Ok(Event::End(_)) => current.clear(),
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse InitiateMultipartUploadResult XML: {e}"
                )));
            }
            _ => {}
        }
    }
    let id = upload_id.trim().to_string();
    if id.is_empty() {
        return Err(Error::protocol(
            "InitiateMultipartUploadResult missing <UploadId>",
        ));
    }
    Ok(id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListPartsTag {
    ListPartsResult,
    IsTruncated,
    NextPartNumberMarker,
    Part,
    PartNumber,
    ETag,
    Size,
    ChecksumCrc64Nvme,
    ChecksumCrc32c,
    ChecksumSha256,
    Other,
}

impl ListPartsTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "ListPartsResult" => Self::ListPartsResult,
            "IsTruncated" => Self::IsTruncated,
            "NextPartNumberMarker" => Self::NextPartNumberMarker,
            "Part" => Self::Part,
            "PartNumber" => Self::PartNumber,
            "ETag" => Self::ETag,
            "Size" => Self::Size,
            "ChecksumCRC64NVME" => Self::ChecksumCrc64Nvme,
            "ChecksumCRC32C" => Self::ChecksumCrc32c,
            "ChecksumSHA256" => Self::ChecksumSha256,
            _ => Self::Other,
        }
    }
}

/// Parse paginated `ListPartsResult` XML.
pub fn parse_list_parts(body: &[u8]) -> Result<ListPartsPage> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut page = ListPartsPage::default();
    let mut stack: Vec<ListPartsTag> = Vec::with_capacity(8);
    let mut raw_truncated = String::new();
    let mut raw_next_marker = String::new();
    let mut p_num = String::new();
    let mut p_etag = String::new();
    let mut p_size = String::new();
    let mut p_crc64 = String::new();
    let mut p_crc32c = String::new();
    let mut p_sha256 = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = ListPartsTag::from_name(local_name(e.name()));
                if tag == ListPartsTag::Part
                    && stack.last().copied() == Some(ListPartsTag::ListPartsResult)
                {
                    p_num.clear();
                    p_etag.clear();
                    p_size.clear();
                    p_crc64.clear();
                    p_crc32c.clear();
                    p_sha256.clear();
                }
                stack.push(tag);
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == ListPartsTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = match (parent, top) {
                    (Some(ListPartsTag::ListPartsResult), ListPartsTag::IsTruncated) => {
                        Some(&mut raw_truncated)
                    }
                    (Some(ListPartsTag::ListPartsResult), ListPartsTag::NextPartNumberMarker) => {
                        Some(&mut raw_next_marker)
                    }
                    (Some(ListPartsTag::Part), ListPartsTag::PartNumber) => Some(&mut p_num),
                    (Some(ListPartsTag::Part), ListPartsTag::ETag) => Some(&mut p_etag),
                    (Some(ListPartsTag::Part), ListPartsTag::Size) => Some(&mut p_size),
                    (Some(ListPartsTag::Part), ListPartsTag::ChecksumCrc64Nvme) => {
                        Some(&mut p_crc64)
                    }
                    (Some(ListPartsTag::Part), ListPartsTag::ChecksumCrc32c) => Some(&mut p_crc32c),
                    (Some(ListPartsTag::Part), ListPartsTag::ChecksumSha256) => Some(&mut p_sha256),
                    _ => None,
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop();
                let parent = stack.last().copied();
                if parent == Some(ListPartsTag::ListPartsResult)
                    && popped == Some(ListPartsTag::Part)
                {
                    let part_number = p_num.trim().parse::<u32>().map_err(|_| {
                        Error::protocol(format!(
                            "invalid PartNumber `{}` in ListParts",
                            p_num.trim()
                        ))
                    })?;
                    let size = p_size.trim().parse::<u64>().map_err(|_| {
                        Error::protocol(format!("invalid Size `{}` in ListParts", p_size.trim()))
                    })?;
                    let checksum =
                        tagged_part_checksum(p_crc64.trim(), p_crc32c.trim(), p_sha256.trim());
                    page.parts.push(ListedPart {
                        part_number,
                        etag: p_etag.trim().to_string(),
                        size,
                        checksum,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!("parse ListParts XML: {e}")));
            }
            _ => {}
        }
    }

    page.is_truncated = raw_truncated.trim().eq_ignore_ascii_case("true");
    if !raw_next_marker.trim().is_empty() {
        page.next_part_number_marker = Some(raw_next_marker.trim().to_string());
    }
    Ok(page)
}

/// Build `<CompleteMultipartUpload>` XML body from sorted `(part_number, etag, optional_tagged_checksum)` entries.
pub fn build_complete_multipart_xml(parts: &[(u32, &str, Option<&str>)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (num, etag, checksum) in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&num.to_string());
        xml.push_str("</PartNumber><ETag>");
        xml.push_str(&escape_xml_text(etag));
        xml.push_str("</ETag>");
        if let Some(tagged) = checksum {
            if let Some(val) = tagged.strip_prefix("crc64nvme:") {
                xml.push_str("<ChecksumCRC64NVME>");
                xml.push_str(&escape_xml_text(val));
                xml.push_str("</ChecksumCRC64NVME>");
            } else if let Some(val) = tagged.strip_prefix("crc32c:") {
                xml.push_str("<ChecksumCRC32C>");
                xml.push_str(&escape_xml_text(val));
                xml.push_str("</ChecksumCRC32C>");
            } else if let Some(val) = tagged.strip_prefix("sha256:") {
                xml.push_str("<ChecksumSHA256>");
                xml.push_str(&escape_xml_text(val));
                xml.push_str("</ChecksumSHA256>");
            }
        }
        xml.push_str("</Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

/// Parse a `CompleteMultipartUpload` HTTP `200 OK` response body.
///
/// Crucially detects `<Error>` XML bodies returned inside HTTP `200 OK` (with
/// optional leading keep-alive whitespace) as well as `<CompleteMultipartUploadResult>`.
pub fn parse_complete_multipart_response(body: &[u8]) -> Result<CompleteMultipartBody> {
    if let Some(err) = parse_s3_error_xml(body) {
        return Ok(CompleteMultipartBody::Error(err));
    }

    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut saw_result_root = false;
    let mut current = String::new();
    let mut etag = String::new();
    let mut crc64 = String::new();
    let mut crc32c = String::new();
    let mut sha256 = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if !saw_result_root {
                    if name == "CompleteMultipartUploadResult" {
                        saw_result_root = true;
                    } else if name == "Error" {
                        return Err(Error::network(
                            "CompleteMultipartUpload 200 OK returned malformed <Error> body",
                        ));
                    }
                } else {
                    current.clear();
                    current.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)))
                if saw_result_root =>
            {
                if let Some(text) = event_text(&ev)? {
                    match current.as_str() {
                        "ETag" => etag.push_str(&text),
                        "ChecksumCRC64NVME" => crc64.push_str(&text),
                        "ChecksumCRC32C" => crc32c.push_str(&text),
                        "ChecksumSHA256" => sha256.push_str(&text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(_)) => current.clear(),
            Ok(Event::Eof) => break,
            Err(e) => {
                // Truncated/corrupt 200 OK XML body must be treated as retryable/reconcilable!
                return Err(Error::network(format!(
                    "truncated or invalid CompleteMultipartUpload XML body: {e}"
                )));
            }
            _ => {}
        }
    }

    if !saw_result_root {
        return Err(Error::network(
            "CompleteMultipartUpload 200 OK missing <CompleteMultipartUploadResult> body",
        ));
    }

    Ok(CompleteMultipartBody::Completed {
        etag: (!etag.trim().is_empty()).then(|| etag.trim().to_string()),
        checksum_crc64nvme: (!crc64.trim().is_empty()).then(|| crc64.trim().to_string()),
        checksum_crc32c: (!crc32c.trim().is_empty()).then(|| crc32c.trim().to_string()),
        checksum_sha256: (!sha256.trim().is_empty()).then(|| sha256.trim().to_string()),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListUploadsTag {
    ListMultipartUploadsResult,
    EncodingType,
    IsTruncated,
    NextKeyMarker,
    NextUploadIdMarker,
    Upload,
    Key,
    UploadId,
    Initiated,
    Other,
}

impl ListUploadsTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "ListMultipartUploadsResult" => Self::ListMultipartUploadsResult,
            "EncodingType" => Self::EncodingType,
            "IsTruncated" => Self::IsTruncated,
            "NextKeyMarker" => Self::NextKeyMarker,
            "NextUploadIdMarker" => Self::NextUploadIdMarker,
            "Upload" => Self::Upload,
            "Key" => Self::Key,
            "UploadId" => Self::UploadId,
            "Initiated" => Self::Initiated,
            _ => Self::Other,
        }
    }
}

/// Parse `ListMultipartUploadsResult` XML for bucket multipart GC.
pub fn parse_list_multipart_uploads(body: &[u8]) -> Result<ListMultipartUploadsPage> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut page = ListMultipartUploadsPage::default();
    let mut stack: Vec<ListUploadsTag> = Vec::with_capacity(8);
    let mut encoding_url = false;
    let mut raw_encoding = String::new();
    let mut raw_truncated = String::new();
    let mut next_key = String::new();
    let mut next_uid = String::new();
    let mut cur_key = String::new();
    let mut cur_uid = String::new();
    let mut cur_init = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = ListUploadsTag::from_name(local_name(e.name()));
                if tag == ListUploadsTag::Upload
                    && stack.last().copied() == Some(ListUploadsTag::ListMultipartUploadsResult)
                {
                    cur_key.clear();
                    cur_uid.clear();
                    cur_init.clear();
                }
                stack.push(tag);
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == ListUploadsTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = match (parent, top) {
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        ListUploadsTag::EncodingType,
                    ) => Some(&mut raw_encoding),
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        ListUploadsTag::IsTruncated,
                    ) => Some(&mut raw_truncated),
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        ListUploadsTag::NextKeyMarker,
                    ) => Some(&mut next_key),
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        ListUploadsTag::NextUploadIdMarker,
                    ) => Some(&mut next_uid),
                    (Some(ListUploadsTag::Upload), ListUploadsTag::Key) => Some(&mut cur_key),
                    (Some(ListUploadsTag::Upload), ListUploadsTag::UploadId) => Some(&mut cur_uid),
                    (Some(ListUploadsTag::Upload), ListUploadsTag::Initiated) => {
                        Some(&mut cur_init)
                    }
                    _ => None,
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let popped = stack.pop();
                let parent = stack.last().copied();
                match (parent, popped) {
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        Some(ListUploadsTag::EncodingType),
                    ) => {
                        encoding_url = raw_encoding.trim().eq_ignore_ascii_case("url");
                    }
                    (
                        Some(ListUploadsTag::ListMultipartUploadsResult),
                        Some(ListUploadsTag::Upload),
                    ) => {
                        page.uploads.push(ListedMultipartUpload {
                            key: std::mem::take(&mut cur_key),
                            upload_id: cur_uid.trim().to_string(),
                            initiated: (!cur_init.trim().is_empty())
                                .then(|| cur_init.trim().to_string()),
                        });
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse ListMultipartUploads XML: {e}"
                )));
            }
            _ => {}
        }
    }

    if encoding_url {
        for up in &mut page.uploads {
            let owned = std::mem::take(&mut up.key);
            up.key = decode_s3_url_encoded_key_owned(owned)?;
        }
    }

    page.is_truncated = raw_truncated.trim().eq_ignore_ascii_case("true");
    if !next_key.trim().is_empty() {
        page.next_key_marker = Some(if encoding_url {
            decode_s3_url_encoded_key(next_key.trim())?
        } else {
            next_key.trim().to_string()
        });
    }
    if !next_uid.trim().is_empty() {
        page.next_upload_id_marker = Some(next_uid.trim().to_string());
    }
    Ok(page)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3DeleteError {
    pub key: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteObjectsBody {
    Result { errors: Vec<S3DeleteError> },
    TopLevelError(S3ErrorXml),
}

pub(crate) fn is_xml10_safe(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(
            c as u32,
            0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
        )
    })
}

/// Extract `<ServerTime>` from an S3 `<Error>` response body as Unix seconds.
pub(crate) fn parse_s3_server_time_xml(body: &[u8]) -> Option<i64> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut in_error = false;
    let mut current_tag = String::new();
    let mut server_time = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if !in_error {
                    if name == "Error" {
                        in_error = true;
                    } else {
                        return None;
                    }
                } else {
                    current_tag.clear();
                    current_tag.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if in_error => {
                if current_tag == "ServerTime"
                    && let Ok(Some(text)) = event_text(&ev)
                {
                    server_time.push_str(&text);
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name()) == "Error" {
                    break;
                }
                current_tag.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    let trimmed = server_time.trim();
    if trimmed.is_empty() {
        return None;
    }
    parse_rfc3339_or_http_nanos(trimmed).map(|ns| ns.div_euclid(1_000_000_000))
}

/// Parse AWS STS `<AssumeRoleResponse>` / `<AssumeRoleWithWebIdentityResponse>` XML
/// returning `(access_key_id, secret_access_key, session_token, expires_at_unix_secs)`.
pub(crate) fn parse_sts_credentials_xml(
    body: &[u8],
) -> Result<(String, String, Option<String>, Option<i64>)> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut in_credentials = false;
    let mut current_tag = String::new();
    let mut access_key_id = String::new();
    let mut secret_access_key = String::new();
    let mut session_token = String::new();
    let mut expiration = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if name == "Credentials" {
                    in_credentials = true;
                } else if in_credentials {
                    current_tag.clear();
                    current_tag.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)))
                if in_credentials =>
            {
                if let Some(text) = event_text(&ev)? {
                    match current_tag.as_str() {
                        "AccessKeyId" => access_key_id.push_str(&text),
                        "SecretAccessKey" => secret_access_key.push_str(&text),
                        "SessionToken" => session_token.push_str(&text),
                        "Expiration" => expiration.push_str(&text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name());
                if name == "Credentials" {
                    break;
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse AWS STS credentials XML failed: {e}"
                )));
            }
            _ => {}
        }
    }

    let ak = access_key_id.trim().to_string();
    let sk = secret_access_key.trim().to_string();
    if ak.is_empty() || sk.is_empty() {
        return Err(Error::protocol(
            "AWS STS credentials XML missing AccessKeyId or SecretAccessKey",
        ));
    }
    let st = (!session_token.trim().is_empty()).then(|| session_token.trim().to_string());
    let exp = (!expiration.trim().is_empty())
        .then(|| rship_core::time::parse_rfc3339_to_secs(expiration.trim()))
        .flatten();
    Ok((ak, sk, st, exp))
}

/// Build an S3 `DeleteObjects` (`POST /?delete`) XML request payload (quiet mode).
pub fn build_delete_objects_xml(keys: &[&str]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Quiet>true</Quiet>",
    );
    for key in keys {
        xml.push_str("<Object><Key>");
        xml.push_str(&escape_xml_text(key));
        xml.push_str("</Key></Object>");
    }
    xml.push_str("</Delete>");
    xml
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeleteTag {
    DeleteResult,
    Error,
    Key,
    Code,
    Message,
    RequestId,
    Other,
}

impl DeleteTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "DeleteResult" => Self::DeleteResult,
            "Error" => Self::Error,
            "Key" => Self::Key,
            "Code" => Self::Code,
            "Message" => Self::Message,
            "RequestId" => Self::RequestId,
            _ => Self::Other,
        }
    }
}

/// Parse an S3 `DeleteObjects` (`POST /?delete`) HTTP 200 response body, returning
/// any per-object `<Error>` entries inside `<DeleteResult>` or a top-level `<Error>`.
pub fn parse_delete_objects_response(body: &[u8]) -> Result<DeleteObjectsBody> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<DeleteTag> = Vec::with_capacity(8);
    let mut saw_root = false;
    let mut is_top_error = false;
    let mut top_code = String::new();
    let mut top_msg = String::new();
    let mut top_req = String::new();

    let mut errors: Vec<S3DeleteError> = Vec::new();
    let mut cur_key = String::new();
    let mut cur_code = String::new();
    let mut cur_msg = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = DeleteTag::from_name(local_name(e.name()));
                if !saw_root {
                    saw_root = true;
                    if tag == DeleteTag::Error {
                        is_top_error = true;
                    }
                } else if !is_top_error
                    && tag == DeleteTag::Error
                    && stack.last().copied() == Some(DeleteTag::DeleteResult)
                {
                    cur_key.clear();
                    cur_code.clear();
                    cur_msg.clear();
                }
                stack.push(tag);
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == DeleteTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = if is_top_error {
                    match top {
                        DeleteTag::Code => Some(&mut top_code),
                        DeleteTag::Message => Some(&mut top_msg),
                        DeleteTag::RequestId => Some(&mut top_req),
                        _ => None,
                    }
                } else if parent == Some(DeleteTag::Error) {
                    match top {
                        DeleteTag::Key => Some(&mut cur_key),
                        DeleteTag::Code => Some(&mut cur_code),
                        DeleteTag::Message => Some(&mut cur_msg),
                        _ => None,
                    }
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
                let parent = stack.last().copied();
                if !is_top_error
                    && parent == Some(DeleteTag::DeleteResult)
                    && popped == Some(DeleteTag::Error)
                {
                    errors.push(S3DeleteError {
                        key: std::mem::take(&mut cur_key),
                        code: std::mem::take(&mut cur_code),
                        message: std::mem::take(&mut cur_msg),
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::network(format!("parse DeleteResult XML: {e}")));
            }
            _ => {}
        }
    }

    if is_top_error {
        return Ok(DeleteObjectsBody::TopLevelError(S3ErrorXml {
            code: top_code.trim().to_string(),
            message: top_msg.trim().to_string(),
            request_id: (!top_req.trim().is_empty()).then(|| top_req.trim().to_string()),
        }));
    }

    Ok(DeleteObjectsBody::Result { errors })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_error_xml_inside_200_ok_complete_multipart_response() {
        let keepalive_and_err = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n   \n<Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message><RequestId>REQ123</RequestId></Error>";
        match parse_complete_multipart_response(keepalive_and_err).unwrap() {
            CompleteMultipartBody::Error(e) => {
                assert_eq!(e.code, "InternalError");
                assert_eq!(e.request_id.as_deref(), Some("REQ123"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let ok_xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult><ETag>&quot;abc-2&quot;</ETag></CompleteMultipartUploadResult>";
        match parse_complete_multipart_response(ok_xml).unwrap() {
            CompleteMultipartBody::Completed { etag, .. } => {
                assert_eq!(etag.as_deref(), Some("\"abc-2\""));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn parses_url_encoded_list_objects_v2_keys_and_paginated_list_parts() {
        let list_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok-2</NextContinuationToken>
  <Contents>
    <Key>dir/a+%2B+b+%2520+%26+%23+%E4%B8%AD%E6%96%87.txt</Key>
    <LastModified>2026-11-24T12:00:00.000Z</LastModified>
    <ETag>&quot;deadbeef&quot;</ETag>
    <Size>42</Size>
  </Contents>
  <CommonPrefixes>
    <Prefix>sub+dir/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;
        let page = parse_list_objects_v2(list_xml).unwrap();
        assert!(page.is_truncated);
        assert_eq!(page.next_continuation_token.as_deref(), Some("tok-2"));
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "dir/a + b %20 & # 中文.txt");
        assert_eq!(page.objects[0].etag.as_deref(), Some("\"deadbeef\""));
        assert_eq!(page.common_prefixes, vec!["sub dir/"]);

        let parts_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult>
  <IsTruncated>true</IsTruncated>
  <NextPartNumberMarker>2</NextPartNumberMarker>
  <Part><PartNumber>1</PartNumber><ETag>&quot;e1&quot;</ETag><Size>5242880</Size><ChecksumCRC64NVME>rosUhgp5mIg=</ChecksumCRC64NVME></Part>
  <Part><PartNumber>2</PartNumber><ETag>&quot;e2&quot;</ETag><Size>5242880</Size><ChecksumCRC32C>4waSgw==</ChecksumCRC32C></Part>
</ListPartsResult>"#;
        let lp = parse_list_parts(parts_xml).unwrap();
        assert!(lp.is_truncated);
        assert_eq!(lp.next_part_number_marker.as_deref(), Some("2"));
        assert_eq!(lp.parts.len(), 2);
        assert_eq!(
            lp.parts[0].checksum.as_deref(),
            Some("crc64nvme:rosUhgp5mIg=")
        );
        assert_eq!(lp.parts[1].etag, "\"e2\"");
        assert_eq!(lp.parts[1].checksum.as_deref(), Some("crc32c:4waSgw=="));

        let complete_xml = build_complete_multipart_xml(&[
            (1, "\"e1\"", lp.parts[0].checksum.as_deref()),
            (2, "\"e2\"", lp.parts[1].checksum.as_deref()),
            (3, "\"e3\"", None),
        ]);
        assert!(complete_xml.contains("<ChecksumCRC64NVME>rosUhgp5mIg=</ChecksumCRC64NVME>"));
        assert!(complete_xml.contains("<ChecksumCRC32C>4waSgw==</ChecksumCRC32C>"));
        assert!(
            complete_xml.contains("<PartNumber>3</PartNumber><ETag>&quot;e3&quot;</ETag></Part>")
        );

        let copy_part_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult><ETag>&quot;cp1&quot;</ETag><LastModified>2026-11-24T12:00:00.000Z</LastModified><ChecksumCRC64NVME>rosUhgp5mIg=</ChecksumCRC64NVME></CopyPartResult>"#;
        match parse_copy_result(copy_part_xml).unwrap() {
            CopyResultBody::Completed {
                etag,
                last_modified,
                checksum,
            } => {
                assert_eq!(etag.as_deref(), Some("\"cp1\""));
                assert_eq!(last_modified.as_deref(), Some("2026-11-24T12:00:00.000Z"));
                assert_eq!(checksum.as_deref(), Some("crc64nvme:rosUhgp5mIg="));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn builds_and_parses_delete_objects_xml_with_partial_errors() {
        let req = build_delete_objects_xml(&["a/1.txt", "b/x & y <z>.txt"]);
        assert!(req.contains("<Quiet>true</Quiet>"));
        assert!(req.contains("<Key>a/1.txt</Key>"));
        assert!(req.contains("<Key>b/x &amp; y &lt;z&gt;.txt</Key>"));

        let ok_resp = br#"<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>"#;
        assert_eq!(
            parse_delete_objects_response(ok_resp).unwrap(),
            DeleteObjectsBody::Result { errors: vec![] }
        );

        let partial = br#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Error>
    <Key>b/locked.txt</Key>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
  </Error>
</DeleteResult>"#;
        match parse_delete_objects_response(partial).unwrap() {
            DeleteObjectsBody::Result { errors } => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].key, "b/locked.txt");
                assert_eq!(errors[0].code, "AccessDenied");
            }
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[test]
    fn decodes_trailing_encoding_type_and_cdata_sections() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Contents>
    <Key><![CDATA[dir/my+file%20name.txt]]></Key>
    <ETag><![CDATA["0123456789abcdef0123456789abcdef"]]></ETag>
    <Size>99</Size>
  </Contents>
  <CommonPrefixes>
    <Prefix>folder+one/</Prefix>
  </CommonPrefixes>
  <EncodingType>url</EncodingType>
</ListBucketResult>"#;
        let page = parse_list_objects_v2(xml).unwrap();
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "dir/my file name.txt");
        assert_eq!(
            page.objects[0].etag.as_deref(),
            Some("\"0123456789abcdef0123456789abcdef\"")
        );
        assert_eq!(page.common_prefixes, vec!["folder one/"]);
    }

    #[test]
    fn validates_xml10_chars_and_parses_sts_and_server_time_xml() {
        assert!(is_xml10_safe("normal/path \t\n\r 中文.txt"));
        for bad in [
            "\x00", "\x07", "\x08", "\x0B", "\x0C", "\x1F", "\u{FFFE}", "\u{FFFF}",
        ] {
            assert!(
                !is_xml10_safe(bad),
                "must reject illegal XML 1.0 char {bad:?}"
            );
        }

        let skewed = br#"<Error><Code>RequestTimeTooSkewed</Code><ServerTime>2026-11-27T10:30:00Z</ServerTime></Error>"#;
        assert_eq!(parse_s3_server_time_xml(skewed), Some(1_795_775_400));

        let sts = br#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIA_STS_1</AccessKeyId>
      <SecretAccessKey>SECRET_STS_1</SecretAccessKey>
      <SessionToken>TOKEN_STS_1</SessionToken>
      <Expiration>2026-11-27T12:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#;
        let (ak, sk, st, exp) = parse_sts_credentials_xml(sts).unwrap();
        assert_eq!(ak, "ASIA_STS_1");
        assert_eq!(sk, "SECRET_STS_1");
        assert_eq!(st.as_deref(), Some("TOKEN_STS_1"));
        assert_eq!(exp, Some(1_795_780_800));
    }
}
