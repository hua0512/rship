//! Azure Blob Storage XML parsing and serialization (`ListBlobs`, `GetBlockList`, `PutBlockList`, `<Error>`).

use quick_xml::Reader;
use quick_xml::events::Event;
use rship_core::{Error, Result};
use std::collections::BTreeMap;

use crate::common::xml::{escape_xml_text, event_text, local_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedBlob {
    pub name: String,
    pub size: u64,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub content_md5_b64: Option<String>,
    pub resource_type: Option<String>,
    pub blob_type: Option<String>,
    pub access_tier: Option<String>,
    pub archive_status: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

impl ListedBlob {
    /// Whether this listed blob represents a directory marker or ADLS Gen2 / HNS directory.
    pub fn is_directory(&self) -> bool {
        self.name.ends_with('/')
            || self
                .resource_type
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case("directory"))
            || self
                .metadata
                .get("hdi_isfolder")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListBlobsPage {
    pub blobs: Vec<ListedBlob>,
    pub prefixes: Vec<String>,
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedBlock {
    pub name_b64: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BlockListResult {
    pub committed: Vec<ListedBlock>,
    pub uncommitted: Vec<ListedBlock>,
}

/// Normalize Azure Blob ETags so unquoted `<Etag>0x8DC...</Etag>` in `ListBlobs` XML
/// and RFC 9110 quoted `ETag: "0x8DC..."` HTTP response headers compare identically.
pub fn normalize_azure_etag(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        Some(trimmed.to_string())
    } else {
        Some(format!("\"{trimmed}\""))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AzBlobTag {
    EnumerationResults,
    NextMarker,
    Blob,
    BlobPrefix,
    Name,
    Properties,
    ContentLength,
    LastModified,
    Etag,
    ContentMd5,
    ResourceType,
    BlobType,
    AccessTier,
    ArchiveStatus,
    Metadata,
    MetaEntry,
    Other,
}

impl AzBlobTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "EnumerationResults" => Self::EnumerationResults,
            "NextMarker" => Self::NextMarker,
            "Blob" => Self::Blob,
            "BlobPrefix" => Self::BlobPrefix,
            "Name" => Self::Name,
            "Properties" => Self::Properties,
            "Content-Length" => Self::ContentLength,
            "Last-Modified" => Self::LastModified,
            "Etag" | "ETag" => Self::Etag,
            "Content-MD5" => Self::ContentMd5,
            "ResourceType" => Self::ResourceType,
            "BlobType" => Self::BlobType,
            "AccessTier" => Self::AccessTier,
            "ArchiveStatus" => Self::ArchiveStatus,
            "Metadata" => Self::Metadata,
            _ => Self::Other,
        }
    }
}

fn has_encoded_true(e: &quick_xml::events::BytesStart<'_>) -> bool {
    e.attributes().flatten().any(|attr| {
        local_name(attr.key).eq_ignore_ascii_case("Encoded")
            && attr.value.trim().eq_ignore_ascii_case("true")
    })
}

/// Parse `<EnumerationResults>` XML from `GET /{container}?restype=container&comp=list`.
pub fn parse_list_blobs(body: &[u8]) -> Result<ListBlobsPage> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut page = ListBlobsPage::default();
    let mut stack: Vec<AzBlobTag> = Vec::with_capacity(8);

    let mut cur_name = String::new();
    let mut cur_name_encoded = false;
    let mut cur_size = String::new();
    let mut cur_lm = String::new();
    let mut cur_etag = String::new();
    let mut cur_md5 = String::new();
    let mut cur_resource_type = String::new();
    let mut cur_blob_type = String::new();
    let mut cur_access_tier = String::new();
    let mut cur_archive_status = String::new();
    let mut cur_meta: BTreeMap<String, String> = BTreeMap::new();
    let mut cur_meta_val = String::new();
    let mut cur_prefix = String::new();
    let mut cur_prefix_encoded = false;
    let mut next_marker = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let parent = stack.last().copied();
                // Check `parent == Metadata` FIRST so a user metadata key named `<Blob>`
                // never clobbers the enclosing `<Blob>` buffers.
                if parent == Some(AzBlobTag::Metadata) {
                    cur_meta_val.clear();
                    stack.push(AzBlobTag::MetaEntry);
                } else {
                    let tag = AzBlobTag::from_name(local_name(e.name()));
                    if tag == AzBlobTag::Blob {
                        cur_name.clear();
                        cur_name_encoded = false;
                        cur_size.clear();
                        cur_lm.clear();
                        cur_etag.clear();
                        cur_md5.clear();
                        cur_resource_type.clear();
                        cur_blob_type.clear();
                        cur_access_tier.clear();
                        cur_archive_status.clear();
                        cur_meta.clear();
                    } else if tag == AzBlobTag::BlobPrefix {
                        cur_prefix.clear();
                        cur_prefix_encoded = false;
                    } else if tag == AzBlobTag::Name && has_encoded_true(&e) {
                        if parent == Some(AzBlobTag::Blob) {
                            cur_name_encoded = true;
                        } else if parent == Some(AzBlobTag::BlobPrefix) {
                            cur_prefix_encoded = true;
                        }
                    }
                    stack.push(tag);
                }
            }
            Ok(Event::Empty(e)) => {
                if stack.last().copied() == Some(AzBlobTag::Metadata) {
                    cur_meta.insert(local_name(e.name()).to_ascii_lowercase(), String::new());
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == AzBlobTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = match (parent, top) {
                    (Some(AzBlobTag::Metadata), AzBlobTag::MetaEntry) => Some(&mut cur_meta_val),
                    (Some(AzBlobTag::EnumerationResults), AzBlobTag::NextMarker) => {
                        Some(&mut next_marker)
                    }
                    (Some(AzBlobTag::Blob), AzBlobTag::Name) => Some(&mut cur_name),
                    (Some(AzBlobTag::BlobPrefix), AzBlobTag::Name) => Some(&mut cur_prefix),
                    (Some(AzBlobTag::Properties), AzBlobTag::ContentLength) => Some(&mut cur_size),
                    (Some(AzBlobTag::Properties), AzBlobTag::LastModified) => Some(&mut cur_lm),
                    (Some(AzBlobTag::Properties), AzBlobTag::Etag) => Some(&mut cur_etag),
                    (Some(AzBlobTag::Properties), AzBlobTag::ContentMd5) => Some(&mut cur_md5),
                    (Some(AzBlobTag::Properties), AzBlobTag::ResourceType) => {
                        Some(&mut cur_resource_type)
                    }
                    (Some(AzBlobTag::Properties), AzBlobTag::BlobType) => Some(&mut cur_blob_type),
                    (Some(AzBlobTag::Properties), AzBlobTag::AccessTier) => {
                        Some(&mut cur_access_tier)
                    }
                    (Some(AzBlobTag::Properties), AzBlobTag::ArchiveStatus) => {
                        Some(&mut cur_archive_status)
                    }
                    _ => None,
                };
                if let Some(dst) = target
                    && let Some(text) = event_text(&ev)?
                {
                    dst.push_str(&text);
                }
            }
            Ok(Event::End(e)) => {
                let popped = stack.pop();
                let parent = stack.last().copied();
                match (parent, popped) {
                    (Some(AzBlobTag::Metadata), Some(AzBlobTag::MetaEntry)) => {
                        cur_meta.insert(
                            local_name(e.name()).to_ascii_lowercase(),
                            cur_meta_val.trim().to_string(),
                        );
                        cur_meta_val.clear();
                    }
                    (_, Some(AzBlobTag::Blob)) => {
                        let raw_name = std::mem::take(&mut cur_name);
                        let name = if cur_name_encoded {
                            crate::azureblob::config::percent_decode_rfc3986(&raw_name)
                        } else {
                            raw_name
                        };
                        let opt = |s: &mut String| {
                            let t = s.trim();
                            let res = (!t.is_empty()).then(|| t.to_string());
                            s.clear();
                            res
                        };
                        page.blobs.push(ListedBlob {
                            name,
                            size: cur_size.trim().parse::<u64>().unwrap_or(0),
                            last_modified: opt(&mut cur_lm),
                            etag: normalize_azure_etag(&cur_etag),
                            content_md5_b64: opt(&mut cur_md5),
                            resource_type: opt(&mut cur_resource_type),
                            blob_type: opt(&mut cur_blob_type),
                            access_tier: opt(&mut cur_access_tier),
                            archive_status: opt(&mut cur_archive_status),
                            metadata: std::mem::take(&mut cur_meta),
                        });
                    }
                    (_, Some(AzBlobTag::BlobPrefix)) if !cur_prefix.is_empty() => {
                        let raw_prefix = std::mem::take(&mut cur_prefix);
                        let prefix = if cur_prefix_encoded {
                            crate::azureblob::config::percent_decode_rfc3986(&raw_prefix)
                        } else {
                            raw_prefix
                        };
                        if !prefix.is_empty() {
                            page.prefixes.push(prefix);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse Azure ListBlobs XML failed: {e}"
                )));
            }
            _ => {}
        }
    }

    if !next_marker.trim().is_empty() {
        page.next_marker = Some(next_marker.trim().to_string());
    }
    Ok(page)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AzBlockTag {
    CommittedBlocks,
    UncommittedBlocks,
    Block,
    Name,
    Size,
    Other,
}

impl AzBlockTag {
    #[inline]
    fn from_name(name: &str) -> Self {
        match name {
            "CommittedBlocks" => Self::CommittedBlocks,
            "UncommittedBlocks" => Self::UncommittedBlocks,
            "Block" => Self::Block,
            "Name" => Self::Name,
            "Size" => Self::Size,
            _ => Self::Other,
        }
    }
}

/// Parse `<BlockList>` XML from `GET /{container}/{blob}?comp=blocklist`.
pub fn parse_block_list(body: &[u8]) -> Result<BlockListResult> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut result = BlockListResult::default();
    let mut stack: Vec<AzBlockTag> = Vec::with_capacity(8);
    let mut cur_name = String::new();
    let mut cur_size = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = AzBlockTag::from_name(local_name(e.name()));
                if tag == AzBlockTag::Block {
                    cur_name.clear();
                    cur_size.clear();
                }
                stack.push(tag);
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) => {
                let Some(&top) = stack.last() else {
                    continue;
                };
                if top == AzBlockTag::Other {
                    continue;
                }
                let parent = stack
                    .len()
                    .checked_sub(2)
                    .and_then(|i| stack.get(i).copied());
                let target = match (parent, top) {
                    (Some(AzBlockTag::Block), AzBlockTag::Name) => Some(&mut cur_name),
                    (Some(AzBlockTag::Block), AzBlockTag::Size) => Some(&mut cur_size),
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
                if popped == Some(AzBlockTag::Block) {
                    let block = ListedBlock {
                        name_b64: cur_name.trim().to_string(),
                        size: cur_size.trim().parse::<u64>().unwrap_or(0),
                    };
                    match parent {
                        Some(AzBlockTag::CommittedBlocks) => result.committed.push(block),
                        Some(AzBlockTag::UncommittedBlocks) => result.uncommitted.push(block),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(Error::protocol(format!(
                    "parse Azure BlockList XML failed: {e}"
                )));
            }
            _ => {}
        }
    }
    Ok(result)
}

/// Build `<BlockList>` XML body for `PUT /{container}/{blob}?comp=blocklist`.
pub fn build_block_list_xml(block_ids_b64: &[&str]) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
    for id in block_ids_b64 {
        xml.push_str("<Latest>");
        xml.push_str(&escape_xml_text(id));
        xml.push_str("</Latest>");
    }
    xml.push_str("</BlockList>");
    xml
}

/// Parse `<Error><Code>...</Code><Message>...</Message></Error>` returned by Azure Blob Storage.
pub fn parse_azure_error_xml(body: &[u8]) -> Option<(String, String)> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut in_error = false;
    let mut current = String::new();
    let mut code = String::new();
    let mut msg = String::new();

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
                    current.clear();
                    current.push_str(name);
                }
            }
            Ok(ev @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))) if in_error => {
                if let Ok(Some(t)) = event_text(&ev) {
                    match current.as_str() {
                        "Code" => code.push_str(&t),
                        "Message" => msg.push_str(&t),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name()) == "Error" {
                    break;
                }
                current.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }
    if !in_error || code.trim().is_empty() {
        return None;
    }
    Some((code.trim().to_string(), msg.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_blobs_with_metadata_entities_and_marker() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="data">
  <Blobs>
    <Blob>
      <Name>dir/a &amp; b &lt;1&gt;.txt</Name>
      <Properties>
        <Last-Modified>Wed, 25 Nov 2026 01:02:03 GMT</Last-Modified>
        <Etag>0x8DC123</Etag>
        <Content-Length>1234</Content-Length>
        <Content-MD5>1B2M2Y8AsgTpgAmY7PhCfg==</Content-MD5>
      </Properties>
      <Metadata>
        <rship_mtime_ns>1700000000000000000</rship_mtime_ns>
      </Metadata>
    </Blob>
    <BlobPrefix><Name>sub/</Name></BlobPrefix>
  </Blobs>
  <NextMarker>2!84!MDAw</NextMarker>
</EnumerationResults>"#;

        let page = parse_list_blobs(xml).unwrap();
        assert_eq!(page.next_marker.as_deref(), Some("2!84!MDAw"));
        assert_eq!(page.prefixes, vec!["sub/"]);
        assert_eq!(page.blobs.len(), 1);
        assert_eq!(page.blobs[0].name, "dir/a & b <1>.txt");
        assert_eq!(page.blobs[0].size, 1234);
        assert_eq!(page.blobs[0].etag.as_deref(), Some("\"0x8DC123\""));
        assert_eq!(
            page.blobs[0]
                .metadata
                .get("rship_mtime_ns")
                .map(String::as_str),
            Some("1700000000000000000")
        );
    }

    #[test]
    fn metadata_tag_named_blob_and_empty_metadata_tag_do_not_corrupt_blob() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob>
      <Name>photos/img.jpg</Name>
      <Properties>
        <Content-Length>42</Content-Length>
      </Properties>
      <Metadata>
        <Blob>nested-meta-value</Blob>
        <EmptyKey/>
      </Metadata>
    </Blob>
  </Blobs>
</EnumerationResults>"#;

        let page = parse_list_blobs(xml).unwrap();
        assert_eq!(page.blobs.len(), 1);
        assert_eq!(page.blobs[0].name, "photos/img.jpg");
        assert_eq!(page.blobs[0].size, 42);
        assert_eq!(
            page.blobs[0].metadata.get("blob").map(String::as_str),
            Some("nested-meta-value")
        );
        assert_eq!(
            page.blobs[0].metadata.get("emptykey").map(String::as_str),
            Some("")
        );
    }

    #[test]
    fn builds_and_parses_block_list_xml() {
        let req = build_block_list_xml(&["YmxvY2sx", "YmxvY2sy"]);
        assert!(req.contains("<Latest>YmxvY2sx</Latest><Latest>YmxvY2sy</Latest>"));

        let resp = br#"<?xml version="1.0" encoding="utf-8"?>
<BlockList>
  <CommittedBlocks><Block><Name>Y29tMQ==</Name><Size>1024</Size></Block></CommittedBlocks>
  <UncommittedBlocks><Block><Name>dW5jMQ==</Name><Size>4194304</Size></Block></UncommittedBlocks>
</BlockList>"#;
        let parsed = parse_block_list(resp).unwrap();
        assert_eq!(parsed.committed.len(), 1);
        assert_eq!(parsed.uncommitted.len(), 1);
        assert_eq!(parsed.uncommitted[0].name_b64, "dW5jMQ==");
        assert_eq!(parsed.uncommitted[0].size, 4_194_304);
    }

    #[test]
    fn parses_encoded_names_hns_directories_and_tier_properties() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob>
      <Name Encoded="true">a%20b%09c+1%2B2.txt</Name>
      <Properties>
        <Content-Length>9</Content-Length>
        <BlobType>BlockBlob</BlobType>
        <AccessTier>Archive</AccessTier>
        <ArchiveStatus>rehydrate-pending-to-hot</ArchiveStatus>
      </Properties>
    </Blob>
    <Blob>
      <Name>hns-by-resource</Name>
      <Properties>
        <Content-Length>0</Content-Length>
        <ResourceType>directory</ResourceType>
      </Properties>
    </Blob>
    <Blob>
      <Name>hns-by-meta</Name>
      <Properties>
        <Content-Length>0</Content-Length>
      </Properties>
      <Metadata>
        <hdi_isfolder>true</hdi_isfolder>
      </Metadata>
    </Blob>
    <BlobPrefix><Name Encoded="true">sub%09dir/</Name></BlobPrefix>
  </Blobs>
</EnumerationResults>"#;

        let page = parse_list_blobs(xml).unwrap();
        assert_eq!(page.prefixes, vec!["sub\tdir/"]);
        assert_eq!(page.blobs.len(), 3);
        assert_eq!(page.blobs[0].name, "a b\tc+1+2.txt");
        assert!(!page.blobs[0].is_directory());
        assert_eq!(page.blobs[0].blob_type.as_deref(), Some("BlockBlob"));
        assert_eq!(page.blobs[0].access_tier.as_deref(), Some("Archive"));
        assert_eq!(
            page.blobs[0].archive_status.as_deref(),
            Some("rehydrate-pending-to-hot")
        );
        assert!(page.blobs[1].is_directory());
        assert!(page.blobs[2].is_directory());
    }
}
