#![cfg(any(feature = "gdrive", feature = "onedrive", feature = "dropbox"))]

use crate::mock_http::{CapturedRequest, MockAction, MockHttpServer, MockResponse};
use futures::StreamExt;
#[cfg(feature = "dropbox")]
use rship::backends::dropbox::{DropboxPkceFlow, dropbox_content_hash};
#[cfg(feature = "onedrive")]
use rship::backends::onedrive::quickxor::QuickXorHasher;
use rship::core::ErrorKind;
#[cfg(any(feature = "onedrive", feature = "dropbox"))]
use rship::core::backend::BackendPath;
#[cfg(any(feature = "gdrive", all(feature = "onedrive", feature = "local")))]
use rship::core::backend::UploadProgress;
use rship::core::backend::{EntryStream, ListOptions};
use rship::core::path::RelPath;
use rship::core::source::DataSource;
#[cfg(any(feature = "gdrive", all(feature = "onedrive", feature = "local")))]
use rship::core::state::DstPrecondition;
#[cfg(any(feature = "gdrive", feature = "dropbox"))]
use rship::core::types::EntryKind;
#[cfg(feature = "gdrive")]
use rship::core::types::NodeId;
use rship::core::types::{ByteRange, Entry};
use rship::prelude::*;
#[cfg(feature = "onedrive")]
use rship::transport::TransportConfig;
use std::collections::HashMap;
#[cfg(feature = "onedrive")]
use std::sync::atomic::AtomicBool;
#[cfg(any(feature = "onedrive", feature = "dropbox"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(any(feature = "onedrive", feature = "dropbox"))]
use std::time::Duration;
#[cfg(feature = "local")]
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared Pure-Rust Helpers
// ---------------------------------------------------------------------------

async fn collect_entries(mut stream: EntryStream) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item?);
    }
    Ok(out)
}

async fn read_all_from_source(src: DataSource) -> Result<Vec<u8>> {
    match src {
        DataSource::RemoteRangeReadable(r) => {
            let total = r.total_len();
            let mut stream = r
                .open_range(ByteRange {
                    offset: 0,
                    len: total,
                })
                .await?;
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
        DataSource::SequentialStream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
        DataSource::LocalSeekable(seekable) => {
            let total = seekable.total_len() as usize;
            let mut out = vec![0u8; total];
            let mut off = 0usize;
            while off < total {
                let n = seekable.read_at(off as u64, &mut out[off..]).await?;
                if n == 0 {
                    break;
                }
                off += n;
            }
            out.truncate(off);
            Ok(out)
        }
    }
}

#[cfg(any(
    all(feature = "gdrive", feature = "local"),
    feature = "onedrive",
    feature = "dropbox"
))]
async fn read_range_from_source(src: DataSource, range: ByteRange) -> Result<Vec<u8>> {
    match src {
        DataSource::RemoteRangeReadable(r) => {
            let mut stream = r.open_range(range).await?;
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
        other => read_all_from_source(other).await,
    }
}

#[cfg(feature = "onedrive")]
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(any(feature = "gdrive", feature = "onedrive"))]
fn percent_decode_strict(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_byte_range_header(req: &CapturedRequest, total: usize) -> Option<(usize, usize)> {
    let hdr = req.header("range")?;
    let spec = hdr.strip_prefix("bytes=")?;
    let (s_str, e_str) = spec.split_once('-')?;
    let start: usize = s_str.parse().ok()?;
    let end: usize = if e_str.is_empty() {
        total.checked_sub(1)?
    } else {
        e_str.parse::<usize>().ok()?.min(total.saturating_sub(1))
    };
    if start > end || start >= total {
        return None;
    }
    Some((start, end))
}

#[cfg(feature = "onedrive")]
fn parse_content_range_upload(req: &CapturedRequest) -> Option<(usize, usize, usize)> {
    let hdr = req.header("content-range")?;
    let spec = hdr.strip_prefix("bytes ")?;
    let (range_part, total_str) = spec.split_once('/')?;
    let total: usize = total_str.parse().ok()?;
    let (start_str, end_str) = range_part.split_once('-')?;
    let start: usize = start_str.parse().ok()?;
    let end: usize = end_str.parse().ok()?;
    Some((start, end, total))
}

#[cfg(any(feature = "gdrive", all(feature = "onedrive", feature = "local")))]
fn make_op_record(
    backend_kind: &str,
    init: &rship::core::backend::UploadInit,
    session_token: Option<String>,
    backend_meta: String,
    remote_op_id: Option<String>,
) -> rship::core::state::OperationRecord {
    use rship::core::state::{OperationRecord, OperationState, SourceVersion};
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sess-{}", init.op_id),
        job_id: "job-test".to_string(),
        src_endpoint: "mem://src".to_string(),
        dst_endpoint: format!("{backend_kind}://dst"),
        src_raw_path: init.dst_path.as_str().to_string(),
        dst_raw_path: init.dst_path.as_str().to_string(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: init.src_etag.clone(),
        },
        dst_precondition: init.precondition.clone(),
        existing_dst_node_id: init.existing_node_id.clone(),
        remote_op_id,
        backend_kind: backend_kind.to_string(),
        session_token,
        backend_meta,
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        expires_at: None,
    }
}

#[cfg(any(feature = "gdrive", feature = "onedrive", feature = "dropbox"))]
fn make_upload_init(
    dst_path: RelPath,
    total_size: u64,
    src_mtime_ns: i64,
    planned_chunk_size: u64,
) -> rship::core::backend::UploadInit {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static OP_SEQ: AtomicUsize = AtomicUsize::new(1);
    let seq = OP_SEQ.fetch_add(1, Ordering::Relaxed);
    rship::core::backend::UploadInit {
        op_id: format!("test-op-{seq}"),
        dst_path,
        existing_node_id: None,
        pregenerated_id: None,
        total_size,
        src_mtime_ns,
        planned_chunk_size,
        checksums: Vec::new(),
        precondition: rship::core::state::DstPrecondition::Any,
        src_etag: None,
    }
}

#[cfg(any(feature = "gdrive", feature = "onedrive", feature = "dropbox"))]
fn make_byte_stream(data: Vec<u8>) -> rship::core::source::ByteStream {
    use rship::core::buffer::BufferPool;
    use rship::core::source::{MemorySource, bounded_range_stream};
    let len = data.len() as u64;
    if len == 0 {
        return Box::pin(futures::stream::empty());
    }
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).expect("buffer pool");
    let src = Arc::new(MemorySource::new(data));
    bounded_range_stream(src, 0, len, pool)
}

// ===========================================================================
// Feature Area #8: Google Drive (`gdrive`)
// ===========================================================================

#[cfg(feature = "gdrive")]
use gdrive_mock::*;

#[cfg(feature = "gdrive")]
mod gdrive_mock {
    use super::*;

    pub(super) const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
    pub(super) const SHORTCUT_MIME: &str = "application/vnd.google-apps.shortcut";

    pub(super) const TEST_SA_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkEYEt8W1qR3Sp
iRmZKbkq3CRZUgvAC3M2nFEGL62wdrjvwQ6GpZi8MwETTCvikAF6Q1qr2zpuy1P/
IVF1zJT0X2XXG/fiVUFUVEpf9FmVPjHkP6tlMWzb1WH1bnYPabwmJJ9eN/lJ3PrU
wLv4MY695GvE2ByQg1xoE3BfWWzFwMbFpaZAvWKzcZCx3EbrWAMEcN39bvcVeT5c
3oHRYmhjFPFtVIrc1g9n4HKKxKyByNSRDdUhfc/fTOXE3vpqtuD1vEAqAu8AVM0E
KG2L1RnLiVglY+eO/SCnxqxtzoR1QjZ75215SgL4tpjQXhNQLkL88Z/Cx7HN9gbc
VzpdlA4TAgMBAAECggEADl25gmUonD8GCHJCmSHf436pREsYj5W12zHIVMugdQyP
CuMuGnZh6ZdY5DGyVGIrBajEFGE9DAkyY4OVkWyinix7Y/jQcE+O5VRhHvkFKSzl
9z4felwjqRe6EbvnvRubwD28U2YGBb+t7F4VORJ+FSFHVi3t/RhmALqz8GQLDjKM
NarYigojkk0IWUlrfbIhN+I8Y+4sJ38+dUVXDKNYzqOmKt+Uyg2lRiDTLOwLZL41
MoyT6yW0OwNdDh62bc0ChagJcZa4+dR29sCNiDAWfuInn+o9vsvIAcURmtQriqNl
bnytlnD7GB0irGjKmRu50xPvKuJLKKSgZNzJckLKSQKBgQD7Gv/DRBDYafXcFi3P
ONJLLPLdNcKHCGay1zT8fG9U5KSGXa6DiJQqV9F/bZ2bZhDIpJ7qXhi37sV5Kh4F
vDPE5H5MQVSMu5EFcbRGNkQv582lexwtU1spEej+v8QDhC+rbrZcvDQJPQCQiUHO
6L8v/3FaUB/pvOGl4aOMSE4EHwKBgQDog41Hmmqh8tOi2k296cMEQLMBuYMh0v3c
RIY9nAp25pqvfZM4+WT/lLWbp5zlVAa0+OlmYjUfPMR9ashpsTanK3BJzpnPcDh5
nw9Q7GqcCnaMGfkXhbFL42Om3WU0etGGYg4fdyNADK9l1VA+4PVSsHJnCF/k21pW
ypTUCCMXjQKBgQCHc5DzrAvKMZ5GElCzr1sA4kY/vXgpjwaXAi+64wTLLmrxcCdr
HImQLb78lgymfvAey25NzmRXE53CNk3rmhHy666VQ8hwAd3Aqg0ssqkljk0ILtiM
OqK6DMc6ZAdAPlXYi+gjLgKD2Twsu12cV0CKi6iBpycP1quB561pRreO0QKBgCQj
XjAE1hH5td8X4wFjdcYRcEESXklBi+dSVzL4L8AvM1eXQuyWBpaavGdG8+HI34n9
LfmVxf/m5/s+P4v92Sq+W6N9Evbk0EJG8JB5TlCWZ7p6xvZa9yV+YBytSG+Rr0Md
tmg5kicAUbqYHvLG8Bo8BmvxJ0ZguXfH4L3bzeh5AoGAV0VffYO++qwvqljZYWM4
lz5fhHD/Of5fQ9o4DByZqwNnOWsmWMnd7h/wHNcFh3FMfGMo90T+LZpToIgm1G8H
3gtNqdk2T/SWfg+VuTDWAJLQF8XHkvVyUpGx6/PFKVUlvqZrNksrnJiLQRd8tGdV
iEP0Q2gYfn8kNNw/KekT9Tg=
-----END PRIVATE KEY-----
";

    #[derive(Clone, Debug)]
    pub(super) struct MockDriveNode {
        pub(super) id: String,
        pub(super) name: String,
        pub(super) mime_type: String,
        pub(super) parents: Vec<String>,
        pub(super) data: Vec<u8>,
        pub(super) modified_time: String,
        pub(super) trashed: bool,
        pub(super) shortcut_target: Option<(String, String)>,
        pub(super) app_properties: HashMap<String, String>,
    }

    impl MockDriveNode {
        pub(super) fn folder(id: &str, name: &str, parent: &str) -> Self {
            Self {
                id: id.to_string(),
                name: name.to_string(),
                mime_type: FOLDER_MIME.to_string(),
                parents: vec![parent.to_string()],
                data: Vec::new(),
                modified_time: "2026-01-01T00:00:00.000Z".to_string(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            }
        }

        pub(super) fn file(id: &str, name: &str, parent: &str, data: Vec<u8>) -> Self {
            Self {
                id: id.to_string(),
                name: name.to_string(),
                mime_type: "application/octet-stream".to_string(),
                parents: vec![parent.to_string()],
                data,
                modified_time: "2026-01-01T00:00:00.000Z".to_string(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            }
        }

        pub(super) fn shortcut(
            id: &str,
            name: &str,
            parent: &str,
            target_id: &str,
            target_mime: &str,
        ) -> Self {
            Self {
                id: id.to_string(),
                name: name.to_string(),
                mime_type: SHORTCUT_MIME.to_string(),
                parents: vec![parent.to_string()],
                data: Vec::new(),
                modified_time: "2026-01-01T00:00:00.000Z".to_string(),
                trashed: false,
                shortcut_target: Some((target_id.to_string(), target_mime.to_string())),
                app_properties: HashMap::new(),
            }
        }

        pub(super) fn to_json(&self) -> serde_json::Value {
            let mut obj = serde_json::json!({
                "id": self.id,
                "name": self.name,
                "mimeType": self.mime_type,
                "size": self.data.len().to_string(),
                "modifiedTime": self.modified_time,
                "parents": self.parents,
                "trashed": self.trashed,
                "appProperties": self.app_properties,
            });
            if let Some((tid, tmime)) = &self.shortcut_target {
                obj["shortcutDetails"] = serde_json::json!({
                    "targetId": tid,
                    "targetMimeType": tmime,
                });
            }
            obj
        }
    }

    #[derive(Clone, Debug)]
    struct MockResumableSession {
        file_id: String,
        name: Option<String>,
        parents: Vec<String>,
        is_update: bool,
        modified_time: String,
        app_properties: HashMap<String, String>,
        buf: Vec<u8>,
        committed: bool,
    }

    pub(super) struct MockDriveState {
        pub(super) nodes: HashMap<String, MockDriveNode>,
        order: Vec<String>,
        sessions: HashMap<String, MockResumableSession>,
        next_id: usize,
        next_session: usize,
        pub(super) forbidden_ids: HashMap<String, u16>,
        about_quota: serde_json::Value,
        pub(super) start_page_token: String,
        pub(super) changes_pages: Vec<(u16, serde_json::Value)>,
        pub(super) page_size_override: Option<usize>,
        pub(super) omit_308_range_once: bool,
        pub(super) require_token: Option<String>,
        pub(super) list_incomplete_dirs: HashMap<String, bool>,
        pub(super) dir_page_500_on_call: Option<(String, usize)>,
        pub(super) dir_list_calls: HashMap<String, usize>,
        pub(super) upload_faults: std::collections::VecDeque<(u16, serde_json::Value)>,
    }

    impl MockDriveState {
        pub(super) fn new() -> Self {
            Self {
                nodes: HashMap::new(),
                order: Vec::new(),
                sessions: HashMap::new(),
                next_id: 1,
                next_session: 1,
                forbidden_ids: HashMap::new(),
                about_quota: serde_json::json!({
                    "storageQuota": {
                        "limit": "16106127360",
                        "usage": "4294967296",
                        "usageInDriveTrash": "1048576"
                    }
                }),
                start_page_token: "tok-1".to_string(),
                changes_pages: Vec::new(),
                page_size_override: None,
                omit_308_range_once: false,
                require_token: None,
                list_incomplete_dirs: HashMap::new(),
                dir_page_500_on_call: None,
                dir_list_calls: HashMap::new(),
                upload_faults: std::collections::VecDeque::new(),
            }
        }

        pub(super) fn insert(&mut self, node: MockDriveNode) {
            let id = node.id.clone();
            if !self.nodes.contains_key(&id) {
                self.order.push(id.clone());
            }
            self.nodes.insert(id, node);
        }

        fn gen_id(&mut self) -> String {
            let id = format!("gd-id-{}", self.next_id);
            self.next_id += 1;
            id
        }
    }

    fn unescape_drive_literal(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn extract_single_quoted_after(haystack: &str, marker: &str) -> Option<String> {
        let idx = haystack.find(marker)?;
        let rest = &haystack[idx + marker.len()..];
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push('\\');
                    out.push(next);
                }
            } else if c == '\'' {
                return Some(unescape_drive_literal(&out));
            } else {
                out.push(c);
            }
        }
        None
    }

    fn extract_parent_clause(q: &str) -> Option<String> {
        let idx = q.find("' in parents")?;
        let prefix = &q[..idx];
        // Walk backwards to the unescaped opening single quote.
        let bytes = prefix.as_bytes();
        let mut i = bytes.len();
        while i > 0 {
            i -= 1;
            if bytes[i] == b'\'' {
                let mut backslashes = 0usize;
                let mut j = i;
                while j > 0 && bytes[j - 1] == b'\\' {
                    backslashes += 1;
                    j -= 1;
                }
                if backslashes.is_multiple_of(2) {
                    return Some(unescape_drive_literal(&prefix[i + 1..]));
                }
            }
        }
        None
    }

    fn parse_multipart_related(req: &CapturedRequest) -> Option<(serde_json::Value, Vec<u8>)> {
        let ct = req.header("content-type")?;
        let boundary = ct.split("boundary=").nth(1)?.trim().trim_matches('"');
        let sep = format!("--{boundary}").into_bytes();
        let body = &req.body;
        let first = body.windows(sep.len()).position(|w| w == sep.as_slice())?;
        let after_first = &body[first + sep.len()..];
        let hdr1_end = after_first.windows(4).position(|w| w == b"\r\n\r\n")?;
        let part1_body_start = &after_first[hdr1_end + 4..];
        let second = part1_body_start
            .windows(sep.len())
            .position(|w| w == sep.as_slice())?;
        let meta_slice = part1_body_start[..second]
            .strip_suffix(b"\r\n")
            .unwrap_or(&part1_body_start[..second]);
        let meta: serde_json::Value = serde_json::from_slice(meta_slice).ok()?;
        let after_second = &part1_body_start[second + sep.len()..];
        let hdr2_end = after_second.windows(4).position(|w| w == b"\r\n\r\n")?;
        let data_start = &after_second[hdr2_end + 4..];
        let end_sep = format!("\r\n--{boundary}--").into_bytes();
        let end_pos = data_start
            .windows(end_sep.len())
            .position(|w| w == end_sep.as_slice())?;
        Some((meta, data_start[..end_pos].to_vec()))
    }

    pub(super) async fn start_mock_drive(state: Arc<Mutex<MockDriveState>>) -> MockHttpServer {
        let srv = MockHttpServer::start().await;
        let base_url = srv.base_url();
        srv.set_fallback(move |req| {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());

            if req.method == "POST" && req.path == "/token" {
                let access_tok = st
                    .require_token
                    .clone()
                    .unwrap_or_else(|| "sa-access-token".to_string());
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "access_token": access_tok,
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }),
                ));
            }

            if let Some(expected_tok) = st.require_token.clone()
                && req.header("authorization") != Some(&format!("Bearer {expected_tok}"))
            {
                return MockAction::Respond(MockResponse::json(
                    401,
                    &serde_json::json!({
                        "error": {
                            "code": 401,
                            "message": "Invalid Credentials",
                            "errors": [{ "reason": "authError", "message": "Invalid Credentials" }]
                        }
                    }),
                ));
            }

            if req.method == "GET" && req.path == "/about" {
                return MockAction::Respond(MockResponse::json(200, &st.about_quota));
            }

            if req.method == "GET" && req.path == "/files/generateIds" {
                let count: usize = req
                    .query_get("count")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10)
                    .min(100);
                let ids: Vec<String> = (0..count).map(|_| st.gen_id()).collect();
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "ids": ids }),
                ));
            }

            if req.method == "GET" && req.path == "/changes/startPageToken" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "startPageToken": st.start_page_token }),
                ));
            }

            if req.method == "GET" && req.path == "/changes" {
                if !st.changes_pages.is_empty() {
                    let (status, val) = st.changes_pages.remove(0);
                    return MockAction::Respond(MockResponse::json(status, &val));
                }
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "changes": [],
                        "newStartPageToken": st.start_page_token
                    }),
                ));
            }

            if req.method == "GET" && req.path == "/files" {
                let q = req.query_get("q").unwrap_or_default();
                let parent_opt = extract_parent_clause(&q);
                if let Some(parent_id) = &parent_opt {
                    if let Some(&code) = st.forbidden_ids.get(parent_id) {
                        return MockAction::Respond(MockResponse::json(
                            code,
                            &serde_json::json!({
                                "error": {
                                    "code": code,
                                    "message": "Forbidden",
                                    "errors": [{ "reason": "forbidden", "message": "Forbidden" }]
                                }
                            }),
                        ));
                    }
                    let count = {
                        let c = st.dir_list_calls.entry(parent_id.clone()).or_insert(0);
                        *c += 1;
                        *c
                    };
                    if let Some((ref err_dir, err_call)) = st.dir_page_500_on_call
                        && err_dir == parent_id
                        && count == err_call
                    {
                        return MockAction::Respond(MockResponse::json(
                            500,
                            &serde_json::json!({
                                "error": {
                                    "code": 500,
                                    "message": "Backend Error",
                                    "errors": [{ "reason": "backendError", "message": "Backend Error" }]
                                }
                            }),
                        ));
                    }
                }

                let name_filter = extract_single_quoted_after(&q, "name = '");
                let op_id_filter = extract_single_quoted_after(&q, "value='");
                let want_trashed = q.contains("trashed = true");
                let want_dir_or_shortcut = q.contains("mimeType = 'application/vnd.google-apps.folder' or mimeType = 'application/vnd.google-apps.shortcut'");
                let want_dir_only = q.contains("mimeType = 'application/vnd.google-apps.folder'")
                    && !q.contains("mimeType = 'application/vnd.google-apps.shortcut'");
                let want_not_folder = q.contains("mimeType != 'application/vnd.google-apps.folder'");

                let mut matched = Vec::new();
                for id in &st.order {
                    let Some(node) = st.nodes.get(id) else {
                        continue;
                    };
                    if node.trashed != want_trashed {
                        continue;
                    }
                    if let Some(pid) = &parent_opt
                        && !node.parents.iter().any(|p| p == pid)
                    {
                        continue;
                    }
                    if let Some(nf) = &name_filter
                        && &node.name != nf
                    {
                        continue;
                    }
                    if let Some(oid) = &op_id_filter
                        && node.app_properties.get("rship_op_id") != Some(oid)
                    {
                        continue;
                    }
                    if want_dir_or_shortcut
                        && node.mime_type != FOLDER_MIME
                        && node.mime_type != SHORTCUT_MIME
                    {
                        continue;
                    }
                    if want_dir_only && node.mime_type != FOLDER_MIME {
                        continue;
                    }
                    if want_not_folder && node.mime_type == FOLDER_MIME {
                        continue;
                    }
                    matched.push(node.to_json());
                }

                let page_size = st.page_size_override.unwrap_or(1000);
                let start_idx: usize = req
                    .query_get("pageToken")
                    .and_then(|t| t.strip_prefix("off:").and_then(|n| n.parse().ok()))
                    .unwrap_or(0);
                let end_idx = (start_idx + page_size).min(matched.len());
                let slice = matched[start_idx..end_idx].to_vec();
                let next_page = (end_idx < matched.len()).then(|| format!("off:{end_idx}"));
                let incomplete = parent_opt
                    .as_deref()
                    .and_then(|pid| st.list_incomplete_dirs.get(pid).copied())
                    .unwrap_or(false);

                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "files": slice,
                        "nextPageToken": next_page,
                        "incompleteSearch": incomplete,
                    }),
                ));
            }

            if req.method == "POST" && req.path == "/files" {
                let upload_type = req.query_get("uploadType").unwrap_or_default();
                if (upload_type == "multipart" || upload_type == "resumable")
                    && let Some((status, err_json)) = st.upload_faults.pop_front()
                {
                    return MockAction::Respond(MockResponse::json(status, &err_json));
                }
                if upload_type == "multipart" {
                    let Some((meta, data)) = parse_multipart_related(req) else {
                        return MockAction::Respond(MockResponse::text(400, "bad multipart"));
                    };
                    let id = meta
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| st.gen_id());
                    let name = meta
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed")
                        .to_string();
                    let parents: Vec<String> = meta
                        .get("parents")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_else(|| vec!["root".to_string()]);
                    let modified_time = meta
                        .get("modifiedTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("2026-01-01T00:00:00.000Z")
                        .to_string();
                    let mut app_properties = HashMap::new();
                    if let Some(obj) = meta.get("appProperties").and_then(|v| v.as_object()) {
                        for (k, v) in obj {
                            if let Some(s) = v.as_str() {
                                app_properties.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    let node = MockDriveNode {
                        id: id.clone(),
                        name,
                        mime_type: "application/octet-stream".to_string(),
                        parents,
                        data,
                        modified_time,
                        trashed: false,
                        shortcut_target: None,
                        app_properties,
                    };
                    let resp = node.to_json();
                    st.insert(node);
                    return MockAction::Respond(MockResponse::json(200, &resp));
                }
                if upload_type == "resumable" {
                    let meta = req.body_json().unwrap_or_default();
                    let file_id = meta
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| st.gen_id());
                    let name = meta
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let parents: Vec<String> = meta
                        .get("parents")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_else(|| vec!["root".to_string()]);
                    let modified_time = meta
                        .get("modifiedTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("2026-01-01T00:00:00.000Z")
                        .to_string();
                    let mut app_properties = HashMap::new();
                    if let Some(obj) = meta.get("appProperties").and_then(|v| v.as_object()) {
                        for (k, v) in obj {
                            if let Some(s) = v.as_str() {
                                app_properties.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    let sess_id = format!("sess-{}", st.next_session);
                    st.next_session += 1;
                    st.sessions.insert(
                        sess_id.clone(),
                        MockResumableSession {
                            file_id,
                            name,
                            parents,
                            is_update: false,
                            modified_time,
                            app_properties,
                            buf: Vec::new(),
                            committed: false,
                        },
                    );
                    let loc = format!("{base_url}/upload/session/{sess_id}");
                    return MockAction::Respond(
                        MockResponse::empty(200).with_header("Location", loc),
                    );
                }

                // JSON create (mkdir or shortcut)
                let meta = req.body_json().unwrap_or_default();
                let id = meta
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| st.gen_id());
                let name = meta
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string();
                let mime_type = meta
                    .get("mimeType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let parents: Vec<String> = meta
                    .get("parents")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["root".to_string()]);
                let node = MockDriveNode {
                    id,
                    name,
                    mime_type,
                    parents,
                    data: Vec::new(),
                    modified_time: "2026-01-01T00:00:00.000Z".to_string(),
                    trashed: false,
                    shortcut_target: None,
                    app_properties: HashMap::new(),
                };
                let resp = node.to_json();
                st.insert(node);
                return MockAction::Respond(MockResponse::json(200, &resp));
            }

            if let Some(sess_id) = req.path.strip_prefix("/upload/session/") {
                let Some(mut sess) = st.sessions.get(sess_id).cloned() else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if req.method == "DELETE" {
                    st.sessions.remove(sess_id);
                    return MockAction::Respond(MockResponse::empty(204));
                }
                if req.method == "PUT" {
                    let cr = req.header("content-range").unwrap_or("");
                    if let Some(rest) = cr.strip_prefix("bytes */") {
                        let _total: usize = rest.parse().unwrap_or(0);
                        if sess.committed
                            && let Some(node) = st.nodes.get(&sess.file_id)
                        {
                            return MockAction::Respond(MockResponse::json(200, &node.to_json()));
                        }
                        let mut resp = MockResponse::empty(308);
                        if st.omit_308_range_once {
                            st.omit_308_range_once = false;
                        } else if !sess.buf.is_empty() {
                            resp = resp.with_header(
                                "Range",
                                format!("bytes=0-{}", sess.buf.len() - 1),
                            );
                        }
                        return MockAction::Respond(resp);
                    }

                    if let Some(spec) = cr.strip_prefix("bytes ")
                        && let Some((range_part, total_str)) = spec.split_once('/')
                        && let Some((s_str, e_str)) = range_part.split_once('-')
                        && let (Ok(start), Ok(end), Ok(total)) = (
                            s_str.parse::<usize>(),
                            e_str.parse::<usize>(),
                            total_str.parse::<usize>(),
                        )
                    {
                        if sess.buf.len() < start {
                            sess.buf.resize(start, 0);
                        }
                        if sess.buf.len() == start {
                            sess.buf.extend_from_slice(&req.body);
                        } else {
                            let needed = start + req.body.len();
                            if sess.buf.len() < needed {
                                sess.buf.resize(needed, 0);
                            }
                            sess.buf[start..needed].copy_from_slice(&req.body);
                        }
                        if end + 1 < total {
                            st.sessions.insert(sess_id.to_string(), sess.clone());
                            let mut resp = MockResponse::empty(308);
                            if st.omit_308_range_once {
                                st.omit_308_range_once = false;
                            } else {
                                resp = resp.with_header("Range", format!("bytes=0-{end}"));
                            }
                            return MockAction::Respond(resp);
                        }

                        // Final chunk committed.
                        sess.committed = true;
                        let node = if sess.is_update
                            && let Some(mut existing) = st.nodes.get(&sess.file_id).cloned()
                        {
                            existing.data = sess.buf.clone();
                            existing.modified_time = sess.modified_time.clone();
                            existing.app_properties = sess.app_properties.clone();
                            existing
                        } else {
                            MockDriveNode {
                                id: sess.file_id.clone(),
                                name: sess.name.clone().unwrap_or_else(|| "file.bin".to_string()),
                                mime_type: "application/octet-stream".to_string(),
                                parents: sess.parents.clone(),
                                data: sess.buf.clone(),
                                modified_time: sess.modified_time.clone(),
                                trashed: false,
                                shortcut_target: None,
                                app_properties: sess.app_properties.clone(),
                            }
                        };
                        let resp_json = node.to_json();
                        st.insert(node);
                        st.sessions.insert(sess_id.to_string(), sess);
                        return MockAction::Respond(MockResponse::json(200, &resp_json));
                    }
                }
            }

            if let Some(rest) = req.path.strip_prefix("/files/") {
                if let Some(raw_id) = rest.strip_suffix("/copy")
                    && req.method == "POST"
                {
                    let src_id = percent_decode_strict(raw_id);
                    let Some(src_node) = st.nodes.get(&src_id).cloned() else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    let meta = req.body_json().unwrap_or_default();
                    let new_id = meta
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| st.gen_id());
                    let new_name = meta
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&src_node.name)
                        .to_string();
                    let parents: Vec<String> = meta
                        .get("parents")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_else(|| src_node.parents.clone());
                    let modified_time = meta
                        .get("modifiedTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&src_node.modified_time)
                        .to_string();
                    let copied = MockDriveNode {
                        id: new_id,
                        name: new_name,
                        mime_type: src_node.mime_type,
                        parents,
                        data: src_node.data,
                        modified_time,
                        trashed: false,
                        shortcut_target: None,
                        app_properties: HashMap::new(),
                    };
                    let resp_json = copied.to_json();
                    st.insert(copied);
                    return MockAction::Respond(MockResponse::json(200, &resp_json));
                }

                let file_id = percent_decode_strict(rest);
                if let Some(&code) = st.forbidden_ids.get(&file_id) {
                    return MockAction::Respond(MockResponse::json(
                        code,
                        &serde_json::json!({
                            "error": {
                                "code": code,
                                "message": "Forbidden",
                                "errors": [{ "reason": "forbidden", "message": "Forbidden" }]
                            }
                        }),
                    ));
                }

                if req.method == "GET" {
                    if file_id == "root" {
                        return MockAction::Respond(MockResponse::json(
                            200,
                            &serde_json::json!({
                                "id": "actual-root-id",
                                "name": "My Drive",
                                "mimeType": FOLDER_MIME,
                                "parents": [],
                            }),
                        ));
                    }
                    let Some(node) = st.nodes.get(&file_id) else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    if req.query_get("alt").as_deref() == Some("media") {
                        if node.data.is_empty() {
                            return MockAction::Respond(MockResponse::empty(200));
                        }
                        if let Some((start, end)) = parse_byte_range_header(req, node.data.len()) {
                            return MockAction::Respond(
                                MockResponse::new(206, node.data[start..=end].to_vec())
                                    .with_header(
                                        "Content-Range",
                                        format!("bytes {start}-{end}/{}", node.data.len()),
                                    ),
                            );
                        }
                        return MockAction::Respond(MockResponse::ok(node.data.clone()));
                    }
                    return MockAction::Respond(MockResponse::json(200, &node.to_json()));
                }

                if req.method == "PATCH" {
                    let upload_type = req.query_get("uploadType").unwrap_or_default();
                    if upload_type == "multipart" {
                        let Some((meta, data)) = parse_multipart_related(req) else {
                            return MockAction::Respond(MockResponse::text(400, "bad multipart"));
                        };
                        let Some(mut node) = st.nodes.get(&file_id).cloned() else {
                            return MockAction::Respond(MockResponse::empty(404));
                        };
                        if node.mime_type == SHORTCUT_MIME {
                            return MockAction::Respond(MockResponse::json(
                                400,
                                &serde_json::json!({
                                    "error": {
                                        "code": 400,
                                        "message": "Invalid request: cannot upload content to shortcut",
                                        "errors": [{ "reason": "badRequest", "message": "Invalid request: cannot upload content to shortcut" }]
                                    }
                                }),
                            ));
                        }
                        node.data = data;
                        if let Some(mt) = meta.get("modifiedTime").and_then(|v| v.as_str()) {
                            node.modified_time = mt.to_string();
                        }
                        let resp_json = node.to_json();
                        st.insert(node);
                        return MockAction::Respond(MockResponse::json(200, &resp_json));
                    }
                    if upload_type == "resumable" {
                        if st
                            .nodes
                            .get(&file_id)
                            .is_some_and(|n| n.mime_type == SHORTCUT_MIME)
                        {
                            return MockAction::Respond(MockResponse::json(
                                400,
                                &serde_json::json!({
                                    "error": {
                                        "code": 400,
                                        "message": "Invalid request: cannot upload content to shortcut",
                                        "errors": [{ "reason": "badRequest", "message": "Invalid request: cannot upload content to shortcut" }]
                                    }
                                }),
                            ));
                        }
                        let meta = req.body_json().unwrap_or_default();
                        let sess_id = format!("sess-{}", st.next_session);
                        st.next_session += 1;
                        st.sessions.insert(
                            sess_id.clone(),
                            MockResumableSession {
                                file_id: file_id.clone(),
                                name: None,
                                parents: Vec::new(),
                                is_update: true,
                                modified_time: meta
                                    .get("modifiedTime")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("2026-01-01T00:00:00.000Z")
                                    .to_string(),
                                app_properties: HashMap::new(),
                                buf: Vec::new(),
                                committed: false,
                            },
                        );
                        let loc = format!("{base_url}/upload/session/{sess_id}");
                        return MockAction::Respond(
                            MockResponse::empty(200).with_header("Location", loc),
                        );
                    }

                    let Some(mut node) = st.nodes.get(&file_id).cloned() else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    let patch = req.body_json().unwrap_or_default();
                    if let Some(n) = patch.get("name").and_then(|v| v.as_str()) {
                        node.name = n.to_string();
                    }
                    if let Some(t) = patch.get("trashed").and_then(|v| v.as_bool()) {
                        node.trashed = t;
                    }
                    if let Some(mt) = patch.get("modifiedTime").and_then(|v| v.as_str()) {
                        node.modified_time = mt.to_string();
                    }
                    let resp_json = node.to_json();
                    st.insert(node);
                    return MockAction::Respond(MockResponse::json(200, &resp_json));
                }

                if req.method == "DELETE" {
                    st.nodes.remove(&file_id);
                    return MockAction::Respond(MockResponse::empty(204));
                }
            }

            MockAction::Respond(MockResponse::empty(404))
        });
        srv
    }

    pub(super) fn gdrive_client_for(srv: &MockHttpServer) -> RshipClient {
        let gcfg = GdriveRemoteConfig::new()
            .with_api_base_url(srv.base_url())
            .with_upload_base_url(srv.base_url())
            .with_access_token("gd-tok");
        RshipClient::builder()
            .ephemeral()
            .allow_changes_feed(false)
            .remote("gd", gcfg)
            .build()
            .unwrap()
    }

    pub(super) async fn put_via_backend(
        client: &RshipClient,
        remote_target: &str,
        data: &[u8],
    ) -> Result<Entry> {
        let (backend, rel) = client.resolve(remote_target)?;
        let mut init = make_upload_init(
            rel,
            data.len() as u64,
            1_700_000_000_000_000_000,
            256 * 1024,
        );
        init.precondition = DstPrecondition::Any;
        backend
            .put_single_shot(&init, make_byte_stream(data.to_vec()))
            .await
    }

    pub(super) async fn put_via_backend_with_existing(
        client: &RshipClient,
        remote_target: &str,
        existing_node_id: NodeId,
        data: &[u8],
    ) -> Result<Entry> {
        let (backend, rel) = client.resolve(remote_target)?;
        let mut init = make_upload_init(
            rel,
            data.len() as u64,
            1_700_000_000_000_000_000,
            256 * 1024,
        );
        init.existing_node_id = Some(existing_node_id);
        init.precondition = DstPrecondition::Any;
        backend
            .put_single_shot(&init, make_byte_stream(data.to_vec()))
            .await
    }
}

// ---------------------------------------------------------------------------
// GDrive Tier 1 (Happy Path >= 5)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "gdrive", feature = "local"))]
#[tokio::test]
async fn tier1_gdrive_mkdir_put_multipart_stat_list_and_get() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    let srv = start_mock_drive(state.clone()).await;
    let client = gdrive_client_for(&srv);

    client.mkdir("gd:docs/nested").await.unwrap();
    // Idempotent second mkdir must succeed cleanly.
    client.mkdir("gd:docs/nested").await.unwrap();

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("hello.txt");
    let payload = b"hello google drive multipart".to_vec();
    std::fs::write(&src_path, &payload).unwrap();

    client
        .copy_file(
            src_path.to_string_lossy().as_ref(),
            "gd:docs/nested/hello.txt",
        )
        .run()
        .await
        .unwrap();

    let entry = client
        .stat("gd:docs/nested/hello.txt")
        .await
        .unwrap()
        .expect("stat must find uploaded file");
    assert_eq!(entry.kind, EntryKind::File);
    assert_eq!(entry.size, payload.len() as u64);

    let listed = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "docs/nested/hello.txt")
    );

    let ds = client
        .open_read("gd:docs/nested/hello.txt", None)
        .await
        .unwrap();
    assert_eq!(read_all_from_source(ds).await.unwrap(), payload);

    let dst_path = tmp.path().join("downloaded.txt");
    client
        .copy_file(
            "gd:docs/nested/hello.txt",
            dst_path.to_string_lossy().as_ref(),
        )
        .run()
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dst_path).unwrap(), payload);

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| r.method == "POST"
        && r.path == "/files"
        && r.query_get("uploadType").as_deref() == Some("multipart")));
}

#[cfg(all(feature = "gdrive", feature = "local"))]
#[tokio::test]
async fn tier1_gdrive_resumable_308_upload_over_5mib_and_range_get() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    let srv = start_mock_drive(state.clone()).await;
    let client = gdrive_client_for(&srv);

    let total = 5 * 1024 * 1024 + 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("big.bin");
    std::fs::write(&src_path, &payload).unwrap();

    client
        .copy_file(src_path.to_string_lossy().as_ref(), "gd:big.bin")
        .chunk_size(2 * 1024 * 1024)
        .run()
        .await
        .unwrap();

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.method == "POST"
            && r.path == "/files"
            && r.query_get("uploadType").as_deref() == Some("resumable")
    }));
    let put_ranges: Vec<String> = reqs
        .iter()
        .filter(|r| r.method == "PUT" && r.path.starts_with("/upload/session/"))
        .filter_map(|r| r.header("content-range").map(str::to_string))
        .collect();
    assert_eq!(
        put_ranges,
        vec![
            format!("bytes 0-2097151/{total}"),
            format!("bytes 2097152-4194303/{total}"),
            format!("bytes 4194304-{}/{total}", total - 1),
        ]
    );

    let full = read_all_from_source(client.open_read("gd:big.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(full, payload);

    let range = ByteRange {
        offset: 2_000_000,
        len: 4096,
    };
    let partial = read_range_from_source(
        client.open_read("gd:big.bin", Some(range)).await.unwrap(),
        range,
    )
    .await
    .unwrap();
    assert_eq!(partial, payload[2_000_000..2_004_096]);
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier1_gdrive_rename_and_delete() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    state.lock().unwrap().insert(MockDriveNode::file(
        "f-1",
        "old.txt",
        "root",
        b"data".to_vec(),
    ));
    let srv = start_mock_drive(state.clone()).await;
    let client = gdrive_client_for(&srv);

    let renamed = client.rename("gd:old.txt", "new.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "new.txt");
    assert!(client.stat("gd:old.txt").await.unwrap().is_none());
    assert!(client.stat("gd:new.txt").await.unwrap().is_some());

    client.delete("gd:new.txt").await.unwrap();
    assert!(client.stat("gd:new.txt").await.unwrap().is_none());
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier1_gdrive_server_side_copy_same_remote_and_cross_drive_sa() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file(
            "f-src",
            "src.bin",
            "root",
            b"payload-copy".to_vec(),
        ));
        st.insert(MockDriveNode::file(
            "f-sa",
            "sa_src.bin",
            "root",
            b"sa-payload".to_vec(),
        ));
    }
    let srv = start_mock_drive(state.clone()).await;

    // (a) Same-remote server-side copy
    let client = gdrive_client_for(&srv);
    let report = client
        .copy_file("gd:src.bin", "gd:copied.bin")
        .run()
        .await
        .unwrap();
    assert_eq!(report.files_transferred, 1);
    let reqs_a = srv.take_requests();
    assert!(
        reqs_a
            .iter()
            .any(|r| r.method == "POST" && r.path == "/files/f-src/copy")
    );
    assert!(
        !reqs_a
            .iter()
            .any(|r| r.method == "GET" && r.query_get("alt").as_deref() == Some("media")),
        "same-remote server-side copy must not download alt=media"
    );
    let ds = client.open_read("gd:copied.bin", None).await.unwrap();
    assert_eq!(read_all_from_source(ds).await.unwrap(), b"payload-copy");
    srv.take_requests();

    // (b) Cross-drive Service Account server-side copy (My Drive -> Shared Drive)
    let dir = tempfile::tempdir().unwrap();
    let sa_path = dir.path().join("sa.json");
    let sa_json = serde_json::json!({
        "type": "service_account",
        "project_id": "proj-1",
        "private_key_id": "kid-1",
        "private_key": TEST_SA_PRIVATE_KEY_PEM,
        "client_email": "rship-sa@proj-1.iam.gserviceaccount.com",
        "client_id": "123456",
        "token_uri": srv.url("/token"),
    });
    std::fs::write(&sa_path, serde_json::to_vec(&sa_json).unwrap()).unwrap();

    let gd_my = GdriveRemoteConfig::new()
        .with_api_base_url(srv.base_url())
        .with_upload_base_url(srv.base_url())
        .with_token_url(srv.url("/token"))
        .with_service_account_file(&sa_path);
    let gd_team = GdriveRemoteConfig::new()
        .with_api_base_url(srv.base_url())
        .with_upload_base_url(srv.base_url())
        .with_token_url(srv.url("/token"))
        .with_service_account_file(&sa_path)
        .with_shared_drive_id("drv-team-1");

    let sa_client = RshipClient::builder()
        .ephemeral()
        .allow_changes_feed(false)
        .remote("gd_my", gd_my)
        .remote("gd_team", gd_team)
        .build()
        .unwrap();

    let copy_report = sa_client.copy("gd_my:", "gd_team:").run().await.unwrap();
    assert!(copy_report.files_transferred >= 1);

    let reqs_b = srv.requests();
    assert!(
        reqs_b
            .iter()
            .any(|r| r.method == "POST" && r.path == "/token")
    );
    assert!(reqs_b.iter().any(|r| {
        r.method == "POST"
            && r.path == "/files/f-sa/copy"
            && r.query_get("supportsAllDrives").as_deref() == Some("true")
    }));
    assert!(
        !reqs_b
            .iter()
            .any(|r| r.method == "GET" && r.query_get("alt").as_deref() == Some("media")),
        "cross-drive SA copy must use server-side copy without downloading"
    );
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier1_gdrive_about_personal_drive_quota() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    let srv = start_mock_drive(state).await;
    let client = gdrive_client_for(&srv);

    let quota = client
        .about("gd:")
        .await
        .unwrap()
        .expect("personal drive must return quota");
    assert_eq!(quota.total_bytes, Some(16_106_127_360));
    assert_eq!(quota.used_bytes, Some(4_294_967_296));
    assert_eq!(quota.free_bytes, Some(16_106_127_360 - 4_294_967_296));
    assert_eq!(quota.trashed_bytes, Some(1_048_576));
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier1_gdrive_zero_byte_file_and_single_quote_escaping() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    let srv = start_mock_drive(state).await;
    let client = gdrive_client_for(&srv);

    client.mkdir("gd:O'Reilly").await.unwrap();
    put_via_backend(&client, "gd:O'Reilly/it's.txt", b"")
        .await
        .unwrap();

    let st = client
        .stat("gd:O'Reilly/it's.txt")
        .await
        .unwrap()
        .expect("0-byte file with quotes must stat");
    assert_eq!(st.size, 0);

    let bytes = read_all_from_source(
        client
            .open_read("gd:O'Reilly/it's.txt", None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(bytes.is_empty());

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.method == "GET"
            && r.path == "/files"
            && r.query_get("q").is_some_and(|q| q.contains(r"O\'Reilly"))
    }));
    assert!(reqs.iter().any(|r| {
        r.method == "GET"
            && r.path == "/files"
            && r.query_get("q").is_some_and(|q| q.contains(r"it\'s.txt"))
    }));
}

// -----------------------------------------------------------------------
// Tier 2 (Audit §III.2 & R2)
// -----------------------------------------------------------------------

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_shortcut_id_isolation_delete_rename_and_overwrite() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file(
            "target-1",
            "real_target.txt",
            "outside-folder",
            b"SACRED_TARGET_DATA".to_vec(),
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-del",
            "del_link.txt",
            "root",
            "target-1",
            "application/octet-stream",
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-ren",
            "ren_link.txt",
            "root",
            "target-1",
            "application/octet-stream",
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-ow",
            "ow_link.txt",
            "root",
            "target-1",
            "application/octet-stream",
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-ow-2",
            "ow_link_2.txt",
            "root",
            "target-1",
            "application/octet-stream",
        ));
        #[cfg(feature = "local")]
        st.insert(MockDriveNode::shortcut(
            "sc-ow-3",
            "ow_link_3.txt",
            "root",
            "target-1",
            "application/octet-stream",
        ));
    }
    let srv = start_mock_drive(state.clone()).await;
    let client = gdrive_client_for(&srv);

    // 1. Delete shortcut -> only sc-del trashed, target-1 untouched.
    client.delete("gd:del_link.txt").await.unwrap();
    {
        let st = state.lock().unwrap();
        assert!(
            st.nodes["sc-del"].trashed,
            "shortcut sc-del must be trashed"
        );
        assert!(
            !st.nodes["target-1"].trashed,
            "target-1 MUST NOT be trashed"
        );
        assert_eq!(st.nodes["target-1"].data, b"SACRED_TARGET_DATA");
    }

    // 2. Rename shortcut -> only sc-ren renamed, target-1 untouched.
    let ren_entry = client
        .rename("gd:ren_link.txt", "ren_link_v2.txt")
        .await
        .unwrap();
    assert_eq!(ren_entry.nfc_path.as_str(), "ren_link_v2.txt");
    {
        let st = state.lock().unwrap();
        assert_eq!(st.nodes["sc-ren"].name, "ren_link_v2.txt");
        assert_eq!(st.nodes["target-1"].name, "real_target.txt");
    }

    // 3a. Overwrite shortcut with existing_node_id: None -> trashes sc-ow and creates new regular file.
    let ow_entry = put_via_backend(&client, "gd:ow_link.txt", b"NEW_REGULAR_FILE")
        .await
        .unwrap();
    assert_eq!(ow_entry.kind, EntryKind::File);
    assert_ne!(
        ow_entry.node_id.as_ref().map(|n| n.0.as_str()),
        Some("sc-ow")
    );

    // 3b. Overwrite shortcut with existing_node_id: Some(NodeId("sc-ow-2")) -> trashes sc-ow-2 and creates new regular file.
    let ow_entry_2 = put_via_backend_with_existing(
        &client,
        "gd:ow_link_2.txt",
        NodeId("sc-ow-2".into()),
        b"NEW_REGULAR_FILE_2",
    )
    .await
    .unwrap();
    assert_eq!(ow_entry_2.kind, EntryKind::File);
    assert_ne!(
        ow_entry_2.node_id.as_ref().map(|n| n.0.as_str()),
        Some("sc-ow-2")
    );

    // 3c. Overwrite shortcut via RshipClient::copy_file (engine populates existing_node_id = Some("sc-ow-3")).
    #[cfg(feature = "local")]
    {
        let tmp = TempDir::new().unwrap();
        let src_file = tmp.path().join("ow_src.txt");
        std::fs::write(&src_file, b"NEW_REGULAR_FILE_3").unwrap();
        client
            .copy_file(src_file.to_string_lossy().as_ref(), "gd:ow_link_3.txt")
            .run()
            .await
            .unwrap();
    }

    {
        let st = state.lock().unwrap();
        assert!(
            st.nodes["sc-ow"].trashed,
            "shortcut sc-ow must be trashed on overwrite"
        );
        assert!(
            st.nodes["sc-ow-2"].trashed,
            "shortcut sc-ow-2 must be trashed on overwrite"
        );
        #[cfg(feature = "local")]
        assert!(
            st.nodes["sc-ow-3"].trashed,
            "shortcut sc-ow-3 must be trashed on copy_file overwrite"
        );
        assert!(
            !st.nodes["target-1"].trashed,
            "target-1 must remain untrashed"
        );
        assert_eq!(st.nodes["target-1"].name, "real_target.txt");
        assert_eq!(st.nodes["target-1"].data, b"SACRED_TARGET_DATA");
    }

    let read_1 = read_all_from_source(client.open_read("gd:ow_link.txt", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(read_1, b"NEW_REGULAR_FILE");
    let read_2 = read_all_from_source(client.open_read("gd:ow_link_2.txt", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(read_2, b"NEW_REGULAR_FILE_2");
    #[cfg(feature = "local")]
    {
        let read_3 =
            read_all_from_source(client.open_read("gd:ow_link_3.txt", None).await.unwrap())
                .await
                .unwrap();
        assert_eq!(read_3, b"NEW_REGULAR_FILE_3");
    }

    let reqs = srv.requests();
    assert!(
        !reqs.iter().any(|r| {
            r.method == "PATCH"
                && (r.path == "/files/sc-ow"
                    || r.path == "/files/sc-ow-2"
                    || r.path == "/files/sc-ow-3")
                && r.query_get("uploadType").is_some()
        }),
        "must never PATCH upload content directly onto a shortcut node ID"
    );
    assert!(
        !reqs.iter().any(|r| {
            (r.method == "PATCH" || r.method == "DELETE") && r.path == "/files/target-1"
        }),
        "must never PATCH or DELETE target-1 when operating on shortcuts"
    );
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_use_trash_on_delete_default_true_and_explicit_false() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file(
            "f-def",
            "def.txt",
            "root",
            b"1".to_vec(),
        ));
        st.insert(MockDriveNode::file("f-rc", "rc.txt", "root", b"2".to_vec()));
        st.insert(MockDriveNode::file(
            "f-perm",
            "perm.txt",
            "root",
            b"3".to_vec(),
        ));
    }
    let srv = start_mock_drive(state.clone()).await;

    // Default GdriveRemoteConfig::new() -> use_trash_on_delete = true -> PATCH trashed:true
    let client_def = gdrive_client_for(&srv);
    client_def.delete("gd:def.txt").await.unwrap();
    let reqs_def = srv.take_requests();
    assert!(reqs_def.iter().any(|r| {
        r.method == "PATCH"
            && r.path == "/files/f-def"
            && r.body_json()
                .is_ok_and(|j| j.get("trashed") == Some(&serde_json::json!(true)))
    }));
    assert!(
        !reqs_def
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/files/f-def")
    );

    // rclone_conf_str omitting use_trash -> defaults to true -> PATCH trashed:true
    let rclone_raw = "[gd_rc]\ntype = drive\nscope = drive\nclient_id = cid\n\n[gd_rc_perm]\ntype = drive\nscope = drive\nuse_trash = false\nclient_id = cid\n";
    let mut cfg = AppConfig::new();
    let dummy_tmp = tempfile::tempdir().unwrap();
    let dummy_paths = AppPaths::new(
        dummy_tmp.path().join("rship_unused_cfg.toml"),
        dummy_tmp.path().join("rship_unused_state"),
    );
    rship::factory::import_rclone_conf(&mut cfg, rclone_raw, &dummy_paths, true, false).unwrap();
    for name in ["gd_rc", "gd_rc_perm"] {
        if let Some(RemoteConfig::Gdrive(g)) = cfg.remotes.get_mut(name) {
            g.api_base_url = Some(srv.base_url());
            g.upload_base_url = Some(srv.base_url());
            g.client_id = None;
            g.access_token = Some("tok".to_string());
        }
    }
    let client_rc = RshipClient::builder()
        .ephemeral()
        .allow_changes_feed(false)
        .config(cfg)
        .build()
        .unwrap();
    client_rc.delete("gd_rc:rc.txt").await.unwrap();
    client_rc.delete("gd_rc_perm:perm.txt").await.unwrap();

    let reqs_rc = srv.take_requests();
    assert!(reqs_rc.iter().any(|r| {
        r.method == "PATCH"
            && r.path == "/files/f-rc"
            && r.body_json()
                .is_ok_and(|j| j.get("trashed") == Some(&serde_json::json!(true)))
    }));
    assert!(
        reqs_rc
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/files/f-perm")
    );

    // Explicit GdriveRemoteConfig::new().with_use_trash(false)
    state.lock().unwrap().insert(MockDriveNode::file(
        "f-exp",
        "exp.txt",
        "root",
        b"4".to_vec(),
    ));
    let client_exp = RshipClient::builder()
        .ephemeral()
        .allow_changes_feed(false)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_use_trash(false),
        )
        .build()
        .unwrap();
    client_exp.delete("gd:exp.txt").await.unwrap();
    let reqs_exp = srv.requests();
    assert!(
        reqs_exp
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/files/f-exp")
    );
}

#[cfg(all(feature = "gdrive", feature = "sqlite"))]
#[tokio::test]
async fn tier2_gdrive_sync_changes_atomic_completeness_gate_mid_crawl_500() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file(
            "f-init",
            "init.txt",
            "root",
            b"init".to_vec(),
        ));
        st.page_size_override = Some(1000);
    }
    let srv = start_mock_drive(state.clone()).await;

    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let client = RshipClient::builder()
        .paths(paths)
        .allow_changes_feed(true)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_use_changes_feed(true)
                .with_max_retries(0),
        )
        .build()
        .unwrap();

    // 1. Initial bootstrap succeeds with tok-1.
    let initial = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert_eq!(initial.len(), 1);
    srv.take_requests();

    // 2. Moved-in directory with 2,150 children (>2000 INVENTORY_FLUSH_BATCH); page 3 returns HTTP 500.
    {
        let mut st = state.lock().unwrap();
        let moved_dir = MockDriveNode::folder("moved-dir", "moved_dir", "root");
        st.insert(moved_dir.clone());
        for i in 0..2150 {
            st.insert(MockDriveNode::file(
                &format!("m-file-{i}"),
                &format!("item_{i:04}.txt"),
                "moved-dir",
                vec![b'x'],
            ));
        }
        st.changes_pages = vec![(
            200,
            serde_json::json!({
                "changes": [{
                    "fileId": "moved-dir",
                    "removed": false,
                    "file": moved_dir.to_json()
                }],
                "newStartPageToken": "tok-2"
            }),
        )];
        st.dir_page_500_on_call = Some(("moved-dir".to_string(), 3));
    }

    let failed_res = client.list("gd:", &ListOptions::recursive()).await;
    assert!(
        failed_res.is_err(),
        "mid-crawl HTTP 500 must fail list/sync_changes"
    );
    srv.take_requests();

    // 3. Clear 500 fault and supply changes from preserved tok-1 -> must recover all 2,150 items.
    {
        let mut st = state.lock().unwrap();
        st.dir_page_500_on_call = None;
        st.dir_list_calls.clear();
        let moved_json = st.nodes["moved-dir"].to_json();
        st.changes_pages = vec![(
            200,
            serde_json::json!({
                "changes": [{
                    "fileId": "moved-dir",
                    "removed": false,
                    "file": moved_json
                }],
                "newStartPageToken": "tok-2"
            }),
        )];
    }

    let recovered = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    let reqs_recover = srv.take_requests();
    assert!(
        reqs_recover.iter().any(|r| {
            r.path == "/changes" && r.query_get("pageToken").as_deref() == Some("tok-1")
        }),
        "startPageToken MUST remain tok-1 after failed mid-crawl"
    );
    assert_eq!(
        recovered
            .iter()
            .filter(|e| e.nfc_path.as_str().starts_with("moved_dir/"))
            .count(),
        2150,
        "all 2,150 moved-in items must be present after recovery"
    );

    // 4. incompleteSearch=true during moved-in crawl aborts mutation and errors list.
    {
        let mut st = state.lock().unwrap();
        let inc_dir = MockDriveNode::folder("inc-dir", "inc_dir", "root");
        st.insert(inc_dir.clone());
        st.insert(MockDriveNode::file(
            "inc-f1",
            "a.txt",
            "inc-dir",
            b"a".to_vec(),
        ));
        st.list_incomplete_dirs.insert("inc-dir".to_string(), true);
        st.changes_pages = vec![(
            200,
            serde_json::json!({
                "changes": [{
                    "fileId": "inc-dir",
                    "removed": false,
                    "file": inc_dir.to_json()
                }],
                "newStartPageToken": "tok-3"
            }),
        )];
    }
    let inc_err = client.list("gd:", &ListOptions::recursive()).await;
    assert!(
        inc_err.is_err(),
        "incompleteSearch=true must abort and fail list"
    );

    // Clear incompleteSearch fault -> next list recovers inc_dir/a.txt cleanly.
    {
        let mut st = state.lock().unwrap();
        st.list_incomplete_dirs.remove("inc-dir");
        let inc_json = st.nodes["inc-dir"].to_json();
        st.changes_pages = vec![(
            200,
            serde_json::json!({
                "changes": [{
                    "fileId": "inc-dir",
                    "removed": false,
                    "file": inc_json
                }],
                "newStartPageToken": "tok-3"
            }),
        )];
    }
    let inc_recovered =
        collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
            .await
            .unwrap();
    assert!(
        inc_recovered
            .iter()
            .any(|e| e.nfc_path.as_str() == "inc_dir/a.txt"),
        "after clearing incompleteSearch, next list must recover inc_dir/a.txt"
    );
}

#[cfg(all(feature = "gdrive", feature = "sqlite"))]
#[tokio::test]
async fn tier2_gdrive_changes_list_410_and_400_expired_token_auto_reset_recovery() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    state
        .lock()
        .unwrap()
        .insert(MockDriveNode::file("f-1", "a.txt", "root", b"a".to_vec()));
    let srv = start_mock_drive(state.clone()).await;

    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let client = RshipClient::builder()
        .paths(paths)
        .allow_changes_feed(true)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_use_changes_feed(true),
        )
        .build()
        .unwrap();

    let _ = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();

    // 410 Gone -> clears inventory and auto-bootstraps with new startPageToken.
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file("f-2", "b.txt", "root", b"b".to_vec()));
        st.start_page_token = "tok-reset-410".to_string();
        st.changes_pages = vec![(
            410,
            serde_json::json!({
                "error": { "code": 410, "message": "Token expired" }
            }),
        )];
    }
    let after_410 = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(after_410.iter().any(|e| e.nfc_path.as_str() == "b.txt"));

    // 400 Bad Request -> also clears inventory and auto-bootstraps.
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file("f-3", "c.txt", "root", b"c".to_vec()));
        st.start_page_token = "tok-reset-400".to_string();
        st.changes_pages = vec![(
            400,
            serde_json::json!({
                "error": { "code": 400, "message": "Invalid pageToken" }
            }),
        )];
    }
    let after_400 = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(after_400.iter().any(|e| e.nfc_path.as_str() == "c.txt"));
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_folder_shortcut_traversal_broken_403_diamond_and_changes_feed() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        // Shared target subtree outside root
        st.insert(MockDriveNode::folder("ext-dir", "ext_dir", "ext-parent"));
        st.insert(MockDriveNode::folder("ext-sub", "sub", "ext-dir"));
        st.insert(MockDriveNode::file(
            "ext-deep",
            "deep.txt",
            "ext-sub",
            b"DEEP".to_vec(),
        ));
        st.insert(MockDriveNode::file(
            "ext-file",
            "ext.txt",
            "ext-parent",
            b"EXT".to_vec(),
        ));

        // Folder shortcut in root -> ext-dir
        st.insert(MockDriveNode::shortcut(
            "sc-dir",
            "sc_dir",
            "root",
            "ext-dir",
            FOLDER_MIME,
        ));
        // Diamond folder shortcuts -> shared-dir
        st.insert(MockDriveNode::folder(
            "shared-dir",
            "shared_real",
            "ext-parent",
        ));
        st.insert(MockDriveNode::file(
            "shared-f",
            "leaf.txt",
            "shared-dir",
            b"LEAF".to_vec(),
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-diamond-a",
            "branch_a",
            "root",
            "shared-dir",
            FOLDER_MIME,
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-diamond-b",
            "branch_b",
            "root",
            "shared-dir",
            FOLDER_MIME,
        ));
        // File shortcut in root
        st.insert(MockDriveNode::shortcut(
            "sc-file",
            "sc_file.txt",
            "root",
            "ext-file",
            "application/octet-stream",
        ));
        // Broken shortcuts (403 on target)
        st.insert(MockDriveNode::shortcut(
            "sc-broken-f",
            "broken_f.txt",
            "root",
            "forbidden-file",
            "application/octet-stream",
        ));
        st.insert(MockDriveNode::shortcut(
            "sc-broken-d",
            "broken_d",
            "root",
            "forbidden-dir",
            FOLDER_MIME,
        ));
        st.forbidden_ids.insert("forbidden-file".to_string(), 403);
        st.forbidden_ids.insert("forbidden-dir".to_string(), 403);
    }
    let srv = start_mock_drive(state.clone()).await;
    let client = gdrive_client_for(&srv);

    // Direct traversal through folder shortcut
    let st_deep = client
        .stat("gd:sc_dir/sub/deep.txt")
        .await
        .unwrap()
        .expect("stat through folder shortcut must succeed");
    assert_eq!(st_deep.size, 4);
    let deep_bytes = read_all_from_source(
        client
            .open_read("gd:sc_dir/sub/deep.txt", None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(deep_bytes, b"DEEP");

    // Verify GET /files query resolving sc_dir includes application/vnd.google-apps.shortcut
    let sc_reqs = srv.requests();
    assert!(
        sc_reqs.iter().any(|r| {
            r.method == "GET"
                && r.path == "/files"
                && r.query_get("q").is_some_and(|q| {
                    q.contains("name = 'sc_dir'")
                        && q.contains("application/vnd.google-apps.shortcut")
                })
        }),
        "GET /files query resolving sc_dir must include application/vnd.google-apps.shortcut"
    );

    // Recursive list tolerates broken 403 shortcuts and emits both diamond branches
    let listed = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "sc_dir/sub/deep.txt")
    );
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == "sc_file.txt"));
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "branch_a/leaf.txt")
    );
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "branch_b/leaf.txt")
    );
    assert!(!listed.iter().any(|e| e.nfc_path.as_str() == "broken_f.txt"));

    // Changes-feed mode also emits shortcuts on bootstrap + incremental sync
    #[cfg(feature = "sqlite")]
    {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
        let cf_client = RshipClient::builder()
            .paths(paths)
            .allow_changes_feed(true)
            .remote(
                "gd",
                GdriveRemoteConfig::new()
                    .with_api_base_url(srv.base_url())
                    .with_upload_base_url(srv.base_url())
                    .with_access_token("tok")
                    .with_use_changes_feed(true),
            )
            .build()
            .unwrap();
        let cf_entries = collect_entries(
            cf_client
                .list("gd:", &ListOptions::recursive())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            cf_entries
                .iter()
                .any(|e| e.nfc_path.as_str() == "sc_dir/sub/deep.txt")
        );
        assert!(
            cf_entries
                .iter()
                .any(|e| e.nfc_path.as_str() == "sc_file.txt")
        );

        // Incremental /changes page introducing a new shortcut after bootstrap
        {
            let mut st = state.lock().unwrap();
            let inc_sc = MockDriveNode::shortcut(
                "sc-inc-file",
                "inc_sc_file.txt",
                "root",
                "ext-file",
                "application/octet-stream",
            );
            st.insert(inc_sc.clone());
            st.changes_pages = vec![(
                200,
                serde_json::json!({
                    "changes": [{
                        "fileId": "sc-inc-file",
                        "removed": false,
                        "file": inc_sc.to_json()
                    }],
                    "newStartPageToken": "tok-inc-2"
                }),
            )];
        }
        let cf_entries_inc = collect_entries(
            cf_client
                .list("gd:", &ListOptions::recursive())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            cf_entries_inc
                .iter()
                .any(|e| e.nfc_path.as_str() == "inc_sc_file.txt"),
            "incremental /changes sync must ingest and emit new shortcut"
        );
    }
}

#[cfg(all(feature = "gdrive", feature = "sqlite"))]
#[tokio::test]
async fn tier2_gdrive_changes_403_unrelated_parent_tolerance_and_restrict_to_my_drive() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::file(
            "f-root",
            "mine.txt",
            "root",
            b"mine".to_vec(),
        ));
        st.forbidden_ids
            .insert("foreign-parent-403".to_string(), 403);
    }
    let srv = start_mock_drive(state.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let client = RshipClient::builder()
        .paths(paths)
        .allow_changes_feed(true)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_use_changes_feed(true),
        )
        .build()
        .unwrap();

    let _ = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();

    {
        let mut st = state.lock().unwrap();
        let foreign = MockDriveNode::file(
            "foreign-file",
            "other.txt",
            "foreign-parent-403",
            b"other".to_vec(),
        );
        let added = MockDriveNode::file("f-new", "new_mine.txt", "root", b"new".to_vec());
        st.insert(added.clone());
        st.changes_pages = vec![(
            200,
            serde_json::json!({
                "changes": [
                    { "fileId": "foreign-file", "removed": false, "file": foreign.to_json() },
                    { "fileId": "f-new", "removed": false, "file": added.to_json() }
                ],
                "newStartPageToken": "tok-2"
            }),
        )];
    }

    let listed = collect_entries(client.list("gd:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == "new_mine.txt"));
    assert!(!listed.iter().any(|e| e.nfc_path.as_str() == "other.txt"));

    let reqs = srv.requests();
    let ch_req = reqs
        .iter()
        .find(|r| r.method == "GET" && r.path == "/changes")
        .expect("changes.list must be called");
    assert_eq!(
        ch_req.query_get("restrictToMyDrive").as_deref(),
        Some("true")
    );
    assert!(ch_req.query_get("includeItemsFromAllDrives").is_none());
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_max_depth_zero_returns_empty_and_depth_one_shallow() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert(MockDriveNode::folder("d-1", "dir", "root"));
        st.insert(MockDriveNode::file(
            "f-top",
            "top.txt",
            "root",
            b"1".to_vec(),
        ));
        st.insert(MockDriveNode::file(
            "f-sub",
            "sub.txt",
            "d-1",
            b"2".to_vec(),
        ));
    }
    let srv = start_mock_drive(state).await;
    let client = gdrive_client_for(&srv);

    let depth0 = collect_entries(
        client
            .list("gd:", &ListOptions::new().with_max_depth(0))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(depth0.is_empty(), "max_depth(0) must return empty stream");

    let depth1 = collect_entries(
        client
            .list("gd:", &ListOptions::new().with_max_depth(1))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(depth1.iter().any(|e| e.nfc_path.as_str() == "top.txt"));
    assert!(depth1.iter().any(|e| e.nfc_path.as_str() == "dir"));
    assert!(!depth1.iter().any(|e| e.nfc_path.as_str() == "dir/sub.txt"));

    #[cfg(feature = "sqlite")]
    {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
        let cf_client = RshipClient::builder()
            .paths(paths)
            .allow_changes_feed(true)
            .remote(
                "gd",
                GdriveRemoteConfig::new()
                    .with_api_base_url(srv.base_url())
                    .with_upload_base_url(srv.base_url())
                    .with_access_token("tok")
                    .with_use_changes_feed(true),
            )
            .build()
            .unwrap();
        let cf_depth0 = collect_entries(
            cf_client
                .list("gd:", &ListOptions::new().with_max_depth(0))
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            cf_depth0.is_empty(),
            "changes-feed max_depth(0) must return empty"
        );
    }
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_stop_on_upload_limit_vs_transient_burst_and_403_reasons() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    let srv = start_mock_drive(state.clone()).await;
    let client = RshipClient::builder()
        .ephemeral()
        .allow_changes_feed(false)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_stop_on_upload_limit(true)
                .with_max_retries(2),
        )
        .build()
        .unwrap();

    let (backend, _) = client.resolve("gd:").unwrap();
    let _ = srv.take_requests();

    // 1. Exact "User rate limit exceeded." with stop_on_upload_limit=true -> fast-fail QuotaExceeded in 1 upload attempt
    state.lock().unwrap().upload_faults.push_back((
            403,
            serde_json::json!({
                "error": {
                    "code": 403,
                    "message": "User rate limit exceeded.",
                    "errors": [{ "reason": "userRateLimitExceeded", "message": "User rate limit exceeded." }]
                }
            }),
        ));
    let mut init1 = make_upload_init(
        RelPath::parse("limit.bin").unwrap(),
        4,
        1_700_000_000_000_000_000,
        256 * 1024,
    );
    init1.precondition = DstPrecondition::Absent;
    let err1 = backend
        .put_single_shot(&init1, make_byte_stream(b"1234".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(err1.kind, ErrorKind::QuotaExceeded);
    let reqs1 = srv.take_requests();
    assert_eq!(
        reqs1
            .iter()
            .filter(
                |r| r.method == "POST" && r.query_get("uploadType").as_deref() == Some("multipart")
            )
            .count(),
        1,
        "stop_on_upload_limit must fast-fail without retrying exact 750GiB message"
    );

    // 2. Transient burst "User Rate Limit Exceeded" -> retries and succeeds via begin_upload
    state.lock().unwrap().upload_faults.push_back((
            403,
            serde_json::json!({
                "error": {
                    "code": 403,
                    "message": "User Rate Limit Exceeded",
                    "errors": [{ "reason": "userRateLimitExceeded", "message": "User Rate Limit Exceeded" }]
                }
            }),
        ));
    let mut init2 = make_upload_init(
        RelPath::parse("burst.bin").unwrap(),
        256 * 1024 + 1,
        1_700_000_000_000_000_000,
        256 * 1024,
    );
    init2.precondition = DstPrecondition::Absent;
    let session = backend.begin_upload(&init2).await.unwrap();
    assert!(session.session_token.contains("/upload/session/"));

    // 3. dailyLimitExceeded -> permanent QuotaExceeded
    state.lock().unwrap().upload_faults.push_back((
        403,
        serde_json::json!({
            "error": {
                "code": 403,
                "message": "Daily Limit Exceeded",
                "errors": [{ "reason": "dailyLimitExceeded", "message": "Daily Limit Exceeded" }]
            }
        }),
    ));
    let err3 = backend
        .put_single_shot(&init1, make_byte_stream(b"1234".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(err3.kind, ErrorKind::QuotaExceeded);
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_about_shared_drive_none_and_app_data_folder_spaces() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    state.lock().unwrap().insert(MockDriveNode::file(
        "app-1",
        "cfg.json",
        "appDataFolder",
        b"{}".to_vec(),
    ));
    let srv = start_mock_drive(state).await;

    let client = RshipClient::builder()
        .ephemeral()
        .allow_changes_feed(false)
        .remote(
            "gd_team",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_shared_drive_id("drv-team-99"),
        )
        .remote(
            "gd_app",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_access_token("tok")
                .with_scope("drive.appfolder"),
        )
        .build()
        .unwrap();

    let team_about = client.about("gd_team:").await.unwrap();
    assert!(
        team_about.is_none(),
        "Shared Drive about() must return Ok(None)"
    );
    assert!(
        !srv.requests().iter().any(|r| r.path == "/about"),
        "Shared Drive about() must make 0 /about requests"
    );

    let app_files = collect_entries(
        client
            .list("gd_app:", &ListOptions::shallow())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(app_files.len(), 1);
    assert_eq!(app_files[0].nfc_path.as_str(), "cfg.json");

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.method == "GET"
            && r.path == "/files"
            && r.query_get("spaces").as_deref() == Some("appDataFolder")
            && r.query_get("q")
                .is_some_and(|q| q.contains("'appDataFolder' in parents"))
    }));
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier2_gdrive_resumable_308_missing_range_and_401_preserves_session_uri() {
    let state = Arc::new(Mutex::new(MockDriveState::new()));
    {
        let mut st = state.lock().unwrap();
        st.omit_308_range_once = true;
        st.require_token = Some("tok-v1".to_string());
    }
    let srv = start_mock_drive(state.clone()).await;

    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    std::fs::create_dir_all(paths.token_file_for("gd").parent().unwrap()).unwrap();
    let tok_json = serde_json::json!({
        "access_token": "tok-v1",
        "refresh_token": "ref-1",
        "token_type": "Bearer",
        "expires_at_unix_secs": 4_102_444_800u64,
        "scope": null
    });
    std::fs::write(
        paths.token_file_for("gd"),
        serde_json::to_vec(&tok_json).unwrap(),
    )
    .unwrap();

    let client = RshipClient::builder()
        .paths(paths)
        .allow_changes_feed(false)
        .remote(
            "gd",
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_upload_base_url(srv.base_url())
                .with_token_url(srv.url("/token"))
                .with_client_id("cid-oauth")
                .with_client_secret("csec-oauth"),
        )
        .build()
        .unwrap();

    let (backend, _) = client.resolve("gd:").unwrap();
    let total_size = 300_000u64;
    let init = make_upload_init(
        RelPath::parse("resume.bin").unwrap(),
        total_size,
        1_700_000_000_000_000_000,
        262_144,
    );
    let sess = backend.begin_upload(&init).await.unwrap();
    let session_uri = sess.session_token.clone();
    let op = make_op_record(
        "gdrive",
        &init,
        Some(session_uri.clone()),
        sess.backend_meta,
        sess.remote_op_id,
    );

    // 1. 308 missing Range -> SequentialOffset(0)
    let p0 = backend.query_upload(&op).await.unwrap();
    assert_eq!(p0, UploadProgress::SequentialOffset(0));

    // 2. Chunk 1 (256 KiB) -> 308 with Range: bytes=0-262143
    let chunk1 = vec![b'A'; 262_144];
    let ack1 = backend
        .upload_chunk(
            &op,
            rship::core::backend::ChunkUpload::new(
                1,
                0,
                262_144,
                total_size,
                make_byte_stream(chunk1),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack1.next_offset, Some(262_144));
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(262_144)
    );

    // 3. Rotate required token so chunk 2 hits 401 -> refreshes via /token and succeeds on SAME session_uri
    state.lock().unwrap().require_token = Some("tok-v2".to_string());
    let chunk2 = vec![b'B'; (total_size - 262_144) as usize];
    let err_401 = backend
        .upload_chunk(
            &op,
            rship::core::backend::ChunkUpload::new(
                2,
                262_144,
                chunk2.len() as u64,
                total_size,
                make_byte_stream(chunk2.clone()),
            ),
        )
        .await
        .unwrap_err();
    assert!(err_401.is_retryable());

    // Retry on exact same session_uri with newly refreshed tok-v2
    let ack2 = backend
        .upload_chunk(
            &op,
            rship::core::backend::ChunkUpload::new(
                2,
                262_144,
                chunk2.len() as u64,
                total_size,
                make_byte_stream(chunk2),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack2.next_offset, Some(total_size));
    let done = backend.finish_upload(&op, &[]).await.unwrap();
    assert_eq!(done.size, total_size);

    let reqs = srv.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "POST" && r.path == "/token")
    );
    let sess_path = session_uri
        .strip_prefix(&srv.base_url())
        .unwrap()
        .split('?')
        .next()
        .unwrap()
        .to_string();
    assert!(
        reqs.iter().any(|r| {
            r.method == "PUT"
                && r.path == sess_path
                && r.header("authorization") == Some("Bearer tok-v2")
        }),
        "retry must reuse exact same session_uri with refreshed Bearer tok-v2"
    );
}

// ===========================================================================
// Feature Area #9: Microsoft OneDrive (`onedrive`)
// ===========================================================================

#[cfg(feature = "onedrive")]
use onedrive_mock::*;

#[cfg(feature = "onedrive")]
mod onedrive_mock {
    use super::*;

    pub(super) fn quickxor_b64(data: &[u8]) -> String {
        let mut h = QuickXorHasher::new();
        h.update_bytes(data);
        base64_encode(&h.finalize_bytes())
    }

    pub(super) fn make_graph_file(
        id: &str,
        name: &str,
        data: &[u8],
        etag: &str,
        mtime: &str,
        download_url: Option<&str>,
    ) -> serde_json::Value {
        let mut val = serde_json::json!({
            "id": id,
            "name": name,
            "size": data.len(),
            "eTag": etag,
            "lastModifiedDateTime": mtime,
            "fileSystemInfo": { "lastModifiedDateTime": mtime },
            "file": {
                "hashes": {
                    "quickXorHash": quickxor_b64(data)
                }
            }
        });
        if let Some(u) = download_url {
            val["@microsoft.graph.downloadUrl"] = serde_json::json!(u);
        }
        val
    }

    pub(super) fn make_graph_folder(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "size": 0,
            "folder": { "childCount": 0 }
        })
    }

    pub(super) fn onedrive_client_for(srv: &MockHttpServer) -> RshipClient {
        RshipClient::builder()
            .ephemeral()
            .remote(
                "od",
                OnedriveRemoteConfig::new()
                    .with_api_base_url(srv.base_url())
                    .with_access_token("od-tok"),
            )
            .build()
            .unwrap()
    }

    #[derive(Clone)]
    pub(super) struct MockOdItem {
        id: String,
        path: String,
        name: String,
        is_folder: bool,
        data: Vec<u8>,
        etag: String,
        mtime: String,
    }

    pub(super) struct MockOdState {
        items_by_path: HashMap<String, MockOdItem>,
        sessions: HashMap<String, (String, Vec<u8>)>,
        next_id: usize,
        next_sess: usize,
    }

    impl MockOdState {
        pub(super) fn new() -> Self {
            Self {
                items_by_path: HashMap::new(),
                sessions: HashMap::new(),
                next_id: 1,
                next_sess: 1,
            }
        }

        pub(super) fn insert_folder(&mut self, path: &str) -> MockOdItem {
            let trimmed = path.trim_matches('/');
            if let Some(ex) = self.items_by_path.get(trimmed) {
                return ex.clone();
            }
            let id = format!("od-dir-{}", self.next_id);
            self.next_id += 1;
            let name = trimmed.rsplit('/').next().unwrap_or("root").to_string();
            let item = MockOdItem {
                id,
                path: trimmed.to_string(),
                name,
                is_folder: true,
                data: Vec::new(),
                etag: "\"dir-etag\"".to_string(),
                mtime: "2026-01-01T00:00:00Z".to_string(),
            };
            self.items_by_path.insert(trimmed.to_string(), item.clone());
            item
        }

        pub(super) fn insert_file(&mut self, path: &str, data: Vec<u8>) -> MockOdItem {
            let trimmed = path.trim_matches('/');
            let id = format!("od-file-{}", self.next_id);
            self.next_id += 1;
            let name = trimmed.rsplit('/').next().unwrap_or("file").to_string();
            let item = MockOdItem {
                id: id.clone(),
                path: trimmed.to_string(),
                name,
                is_folder: false,
                data,
                etag: format!("\"etag-{id}\""),
                mtime: "2026-01-01T00:00:00Z".to_string(),
            };
            self.items_by_path.insert(trimmed.to_string(), item.clone());
            item
        }

        fn by_id(&self, id: &str) -> Option<MockOdItem> {
            self.items_by_path.values().find(|i| i.id == id).cloned()
        }

        fn to_graph_json(&self, item: &MockOdItem, base_url: &str) -> serde_json::Value {
            if item.is_folder {
                make_graph_folder(&item.id, &item.name)
            } else {
                let dl = format!("{base_url}/cdn/{}", item.id);
                make_graph_file(
                    &item.id,
                    &item.name,
                    &item.data,
                    &item.etag,
                    &item.mtime,
                    Some(&dl),
                )
            }
        }
    }

    pub(super) async fn start_mock_od(state: Arc<Mutex<MockOdState>>) -> MockHttpServer {
        let srv = MockHttpServer::start().await;
        let base_url = srv.base_url();
        srv.set_fallback(move |req| {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());

            if req.method == "GET" && req.path == "/me/drive" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "id": "drv-me",
                        "quota": {
                            "total": 1099511627776_i64,
                            "used": 1048576_i64,
                            "remaining": 1099510579200_i64,
                            "deleted": 0_i64
                        }
                    }),
                ));
            }

            if let Some(id) = req.path.strip_prefix("/cdn/")
                && req.method == "GET"
            {
                let Some(item) = st.by_id(id) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if let Some((s, e)) = parse_byte_range_header(req, item.data.len()) {
                    return MockAction::Respond(
                        MockResponse::new(206, item.data[s..=e].to_vec()).with_header(
                            "Content-Range",
                            format!("bytes {s}-{e}/{}", item.data.len()),
                        ),
                    );
                }
                return MockAction::Respond(MockResponse::ok(item.data));
            }

            if let Some(sess_id) = req.path.strip_prefix("/upload_sess/") {
                let Some((target_path, mut buf)) = st.sessions.get(sess_id).cloned() else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if req.method == "GET" {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({ "nextExpectedRanges": [format!("{}-", buf.len())] }),
                    ));
                }
                if req.method == "PUT"
                    && let Some((start, end, total)) = parse_content_range_upload(req)
                {
                    if buf.len() < start {
                        buf.resize(start, 0);
                    }
                    let needed = start + req.body.len();
                    if buf.len() < needed {
                        buf.resize(needed, 0);
                    }
                    buf[start..needed].copy_from_slice(&req.body);
                    if end + 1 < total {
                        st.sessions
                            .insert(sess_id.to_string(), (target_path, buf.clone()));
                        return MockAction::Respond(MockResponse::json(
                            202,
                            &serde_json::json!({ "nextExpectedRanges": [format!("{}-", end + 1)] }),
                        ));
                    }
                    let item = st.insert_file(&target_path, buf);
                    let json = st.to_graph_json(&item, &base_url);
                    return MockAction::Respond(MockResponse::json(201, &json));
                }
            }

            if req.method == "GET" && req.path == "/me/drive/root/children" {
                let children: Vec<serde_json::Value> = st
                    .items_by_path
                    .values()
                    .filter(|it| !it.path.is_empty() && !it.path.contains('/'))
                    .map(|it| st.to_graph_json(it, &base_url))
                    .collect();
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "value": children }),
                ));
            }

            if req.method == "POST" && req.path == "/me/drive/root/children" {
                let body = req.body_json().unwrap_or_default();
                let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("dir");
                let item = st.insert_folder(name);
                let json = st.to_graph_json(&item, &base_url);
                return MockAction::Respond(MockResponse::json(201, &json));
            }

            if let Some(rest) = req.path.strip_prefix("/me/drive/items/") {
                if let Some(id) = rest.strip_suffix("/children") {
                    let parent_path = st.by_id(id).map(|i| i.path).unwrap_or_default();
                    let prefix = format!("{parent_path}/");
                    if req.method == "GET" {
                        let children: Vec<serde_json::Value> = st
                            .items_by_path
                            .values()
                            .filter(|it| {
                                it.path
                                    .strip_prefix(&prefix)
                                    .is_some_and(|rem| !rem.is_empty() && !rem.contains('/'))
                            })
                            .map(|it| st.to_graph_json(it, &base_url))
                            .collect();
                        return MockAction::Respond(MockResponse::json(
                            200,
                            &serde_json::json!({ "value": children }),
                        ));
                    }
                    if req.method == "POST" {
                        let body = req.body_json().unwrap_or_default();
                        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("dir");
                        let full = if parent_path.is_empty() {
                            name.to_string()
                        } else {
                            format!("{parent_path}/{name}")
                        };
                        let item = st.insert_folder(&full);
                        let json = st.to_graph_json(&item, &base_url);
                        return MockAction::Respond(MockResponse::json(201, &json));
                    }
                }
                let id = percent_decode_strict(rest);
                if req.method == "PATCH" {
                    let Some(mut item) = st.by_id(&id) else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    let patch = req.body_json().unwrap_or_default();
                    if let Some(new_name) = patch.get("name").and_then(|v| v.as_str()) {
                        let old_path = item.path.clone();
                        let new_path = match old_path.rsplit_once('/') {
                            Some((p, _)) => format!("{p}/{new_name}"),
                            None => new_name.to_string(),
                        };
                        st.items_by_path.remove(&old_path);
                        item.name = new_name.to_string();
                        item.path = new_path.clone();
                        st.items_by_path.insert(new_path, item.clone());
                    }
                    if let Some(mtime) = patch
                        .get("fileSystemInfo")
                        .and_then(|f| f.get("lastModifiedDateTime"))
                        .and_then(|v| v.as_str())
                    {
                        item.mtime = mtime.to_string();
                        st.items_by_path.insert(item.path.clone(), item.clone());
                    }
                    let json = st.to_graph_json(&item, &base_url);
                    return MockAction::Respond(MockResponse::json(200, &json));
                }
            }

            if let Some(raw_rest) = req.path.strip_prefix("/me/drive/root:/") {
                if let Some(enc_path) = raw_rest.strip_suffix(":/children") {
                    let parent_rel = percent_decode_strict(enc_path);
                    if req.method == "POST" {
                        let body = req.body_json().unwrap_or_default();
                        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("dir");
                        let full = if parent_rel.is_empty() {
                            name.to_string()
                        } else {
                            format!("{parent_rel}/{name}")
                        };
                        let item = st.insert_folder(&full);
                        let json = st.to_graph_json(&item, &base_url);
                        return MockAction::Respond(MockResponse::json(201, &json));
                    }
                    if req.method == "GET" {
                        let prefix = format!("{parent_rel}/");
                        let children: Vec<serde_json::Value> = st
                            .items_by_path
                            .values()
                            .filter(|it| {
                                it.path
                                    .strip_prefix(&prefix)
                                    .is_some_and(|rem| !rem.is_empty() && !rem.contains('/'))
                            })
                            .map(|it| st.to_graph_json(it, &base_url))
                            .collect();
                        return MockAction::Respond(MockResponse::json(
                            200,
                            &serde_json::json!({ "value": children }),
                        ));
                    }
                }
                if let Some(enc_path) = raw_rest.strip_suffix(":/content")
                    && req.method == "PUT"
                {
                    let rel = percent_decode_strict(enc_path);
                    let item = st.insert_file(&rel, req.body.clone());
                    let json = st.to_graph_json(&item, &base_url);
                    return MockAction::Respond(MockResponse::json(201, &json));
                }
                if let Some(enc_path) = raw_rest.strip_suffix(":/createUploadSession")
                    && req.method == "POST"
                {
                    let rel = percent_decode_strict(enc_path);
                    let sid = format!("s-{}", st.next_sess);
                    st.next_sess += 1;
                    st.sessions.insert(sid.clone(), (rel, Vec::new()));
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "uploadUrl": format!("{base_url}/upload_sess/{sid}"),
                            "expirationDateTime": "2099-01-01T00:00:00Z"
                        }),
                    ));
                }
                if let Some(enc_path) = raw_rest.strip_suffix(':') {
                    let rel = percent_decode_strict(enc_path);
                    if req.method == "GET" {
                        if let Some(item) = st.items_by_path.get(&rel).cloned() {
                            let json = st.to_graph_json(&item, &base_url);
                            return MockAction::Respond(MockResponse::json(200, &json));
                        }
                        return MockAction::Respond(MockResponse::empty(404));
                    }
                    if req.method == "DELETE" {
                        st.items_by_path.remove(&rel);
                        return MockAction::Respond(MockResponse::empty(204));
                    }
                }
            }

            MockAction::Respond(MockResponse::empty(404))
        });
        srv
    }
}

// ---------------------------------------------------------------------------
// OneDrive Tier 1 (Happy Path >= 5)
// ---------------------------------------------------------------------------

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier1_onedrive_stat_and_list_shallow_recursive_paginated() {
    let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/me/drive/root:/missing.txt:" {
                return MockAction::Respond(MockResponse::empty(404));
            }
            if req.method == "GET" && req.path == "/me/drive/root:/docs/readme.txt:" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &make_graph_file(
                        "f-readme",
                        "readme.txt",
                        b"hello",
                        "\"e1\"",
                        "2026-01-01T00:00:00Z",
                        None,
                    ),
                ));
            }
            if req.method == "GET" && req.path == "/me/drive/root/children" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [make_graph_folder("d-docs", "docs")],
                        "@odata.nextLink": format!("http://{}/page2", req.header("host").unwrap_or("127.0.0.1"))
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/page2" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [make_graph_file("f-top", "top.txt", b"top", "\"e0\"", "2026-01-01T00:00:00Z", None)]
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/me/drive/items/d-docs/children" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [make_graph_file("f-readme", "readme.txt", b"hello", "\"e1\"", "2026-01-01T00:00:00Z", None)]
                    }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;
    let client = onedrive_client_for(&srv);

    assert!(client.stat("od:missing.txt").await.unwrap().is_none());
    let st = client.stat("od:docs/readme.txt").await.unwrap().unwrap();
    assert_eq!(st.size, 5);

    let shallow = collect_entries(client.list("od:", &ListOptions::shallow()).await.unwrap())
        .await
        .unwrap();
    assert_eq!(shallow.len(), 2);

    let recursive = collect_entries(client.list("od:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    assert!(
        recursive
            .iter()
            .any(|e| e.nfc_path.as_str() == "docs/readme.txt")
    );
    assert!(recursive.iter().any(|e| e.nfc_path.as_str() == "top.txt"));
}

#[cfg(all(feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier1_onedrive_put_single_shot_and_mtime_patch() {
    let state = Arc::new(Mutex::new(MockOdState::new()));
    let srv = start_mock_od(state.clone()).await;
    let client = onedrive_client_for(&srv);

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("small.bin");
    let payload = b"onedrive small upload".to_vec();
    std::fs::write(&src, &payload).unwrap();

    client
        .copy_file(src.to_string_lossy().as_ref(), "od:sub/small.bin")
        .run()
        .await
        .unwrap();

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.method == "PUT"
            && r.path == "/me/drive/root:/sub/small.bin:/content"
            && r.header("authorization") == Some("Bearer od-tok")
            && r.body == payload
    }));
    assert!(reqs.iter().any(|r| {
        r.method == "PATCH"
            && r.path.starts_with("/me/drive/items/")
            && r.body_json().is_ok_and(|j| {
                j["fileSystemInfo"]["lastModifiedDateTime"]
                    .as_str()
                    .is_some_and(|s| s.len() == 20 && s.ends_with('Z'))
            })
    }));
}

#[cfg(all(feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier1_onedrive_upload_session_multi_chunk() {
    let state = Arc::new(Mutex::new(MockOdState::new()));
    let srv = start_mock_od(state.clone()).await;
    let client = onedrive_client_for(&srv);

    let total = 4_500_000usize;
    let payload: Vec<u8> = (0..total).map(|i| (i % 241) as u8).collect();
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("large.bin");
    std::fs::write(&src, &payload).unwrap();

    client
        .copy_file(src.to_string_lossy().as_ref(), "od:large.bin")
        .chunk_size(13 * 320 * 1024)
        .run()
        .await
        .unwrap();

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.method == "POST" && r.path == "/me/drive/root:/large.bin:/createUploadSession"
    }));
    let sess_puts: Vec<_> = reqs
        .iter()
        .filter(|r| r.method == "PUT" && r.path.starts_with("/upload_sess/"))
        .collect();
    assert_eq!(sess_puts.len(), 2);
    assert!(
        sess_puts
            .iter()
            .all(|r| r.header("authorization").is_none()),
        "pre-authenticated uploadUrl PUTs must omit Authorization"
    );
    assert_eq!(
        sess_puts[0].header("content-range"),
        Some("bytes 0-4259839/4500000")
    );
    assert_eq!(
        sess_puts[1].header("content-range"),
        Some("bytes 4259840-4499999/4500000")
    );

    let ds = client.open_read("od:large.bin", None).await.unwrap();
    assert_eq!(read_all_from_source(ds).await.unwrap(), payload);
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier1_onedrive_open_read_full_and_range() {
    let state = Arc::new(Mutex::new(MockOdState::new()));
    let payload: Vec<u8> = (0..512).map(|i| (i % 199) as u8).collect();
    state
        .lock()
        .unwrap()
        .insert_file("file.bin", payload.clone());
    let srv = start_mock_od(state).await;
    let client = onedrive_client_for(&srv);

    let full = read_all_from_source(client.open_read("od:file.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(full, payload);

    let range = ByteRange {
        offset: 100,
        len: 64,
    };
    let partial = read_range_from_source(
        client.open_read("od:file.bin", Some(range)).await.unwrap(),
        range,
    )
    .await
    .unwrap();
    assert_eq!(partial, payload[100..164]);
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier1_onedrive_mkdir_rename_and_delete() {
    let state = Arc::new(Mutex::new(MockOdState::new()));
    {
        let mut st = state.lock().unwrap();
        st.insert_folder("a");
        st.insert_folder("a/b");
        st.insert_file("a/b/old.txt", b"rename me".to_vec());
    }
    let srv = start_mock_od(state).await;
    let client = onedrive_client_for(&srv);

    client.mkdir("od:a/b/c").await.unwrap();
    assert!(client.stat("od:a/b/c").await.unwrap().is_some());

    let renamed = client.rename("od:a/b/old.txt", "new.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "a/b/new.txt");
    assert!(client.stat("od:a/b/new.txt").await.unwrap().is_some());

    client.delete("od:a/b/new.txt").await.unwrap();
    assert!(client.stat("od:a/b/new.txt").await.unwrap().is_none());
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier1_onedrive_about_quota_and_negative_overquota() {
    let srv = MockHttpServer::start().await;
    srv.enqueue_response(MockResponse::json(
        200,
        &serde_json::json!({
            "id": "drv-1",
            "quota": { "total": 1000_i64, "used": 250_i64, "remaining": 750_i64, "deleted": 10_i64 }
        }),
    ));
    srv.enqueue_response(MockResponse::json(
        200,
        &serde_json::json!({
            "id": "drv-1",
            "quota": { "total": -1_i64, "used": 2050_i64, "remaining": -50_i64, "deleted": 0_i64 }
        }),
    ));
    let client = onedrive_client_for(&srv);

    let q1 = client.about("od:").await.unwrap().unwrap();
    assert_eq!(q1.total_bytes, Some(1000));
    assert_eq!(q1.used_bytes, Some(250));
    assert_eq!(q1.free_bytes, Some(750));
    assert_eq!(q1.trashed_bytes, Some(10));

    let q2 = client.about("od:").await.unwrap().unwrap();
    assert_eq!(q2.total_bytes, None);
    assert_eq!(q2.used_bytes, Some(2050));
    assert_eq!(q2.free_bytes, Some(0));
}

// -----------------------------------------------------------------------
// Tier 2 (Audit §III.5)
// -----------------------------------------------------------------------

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier2_onedrive_server_side_copy_drive_id_polls_past_3s_303_delete_failed_and_mtime() {
    let monitor_srv = MockHttpServer::start().await;
    let monitor_url = monitor_srv.url("/monitor/job-1");
    let mon_hits = Arc::new(AtomicUsize::new(0));
    let mon_hits_c = mon_hits.clone();
    let mode = Arc::new(Mutex::new("poll_past_3s"));
    let mode_c = mode.clone();

    let api_srv = MockHttpServer::start().await;
    let api_base = api_srv.base_url();
    monitor_srv.set_fallback(move |_req| {
        let n = mon_hits_c.fetch_add(1, Ordering::SeqCst);
        let m = *mode_c.lock().unwrap();
        match m {
            "poll_past_3s" => {
                if n < 4 {
                    MockAction::Respond(
                        MockResponse::json(200, &serde_json::json!({ "status": "inProgress" }))
                            .with_header("Retry-After", "1"),
                    )
                } else {
                    MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({ "status": "completed", "resourceId": "dst-id-1" }),
                    ))
                }
            }
            "redirect_303" => MockAction::Respond(
                MockResponse::empty(303)
                    .with_header("Location", format!("{api_base}/me/drive/items/dst-id-2")),
            ),
            _ => MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "status": "deleteFailed" }),
            )),
        }
    });

    let dst_present = Arc::new(AtomicBool::new(false));
    let dst_present_c = dst_present.clone();
    let mon_url_c = monitor_url.clone();
    let src_data = b"server-side-copy-data".to_vec();
    let src_data_c = src_data.clone();
    api_srv.set_fallback(move |req| {
        if req.method == "GET" && req.path == "/me/drive" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "id": "drv-me-9" }),
            ));
        }
        if req.method == "GET" && req.path == "/me/drive/root:/src.bin:" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "src-id-1",
                    "src.bin",
                    &src_data_c,
                    "\"se1\"",
                    "2026-01-01T00:00:00Z",
                    None,
                ),
            ));
        }
        if req.method == "GET" && req.path == "/me/drive/root:/dst.bin:" {
            if dst_present_c.load(Ordering::SeqCst) {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &make_graph_file(
                        "dst-id-1",
                        "dst.bin",
                        &src_data_c,
                        "\"de1\"",
                        "2026-01-01T00:00:05Z",
                        None,
                    ),
                ));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "GET" && req.path == "/me/drive/items/dst-id-1" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "dst-id-1",
                    "dst.bin",
                    &src_data_c,
                    "\"de1\"",
                    "2026-01-01T00:00:05Z",
                    None,
                ),
            ));
        }
        if req.method == "GET" && req.path == "/me/drive/items/dst-id-2" {
            if req.header("authorization") != Some("Bearer od-tok") {
                return MockAction::Respond(MockResponse::empty(401));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "dst-id-2",
                    "dst2.bin",
                    &src_data_c,
                    "\"de2\"",
                    "2026-01-01T00:00:00Z",
                    None,
                ),
            ));
        }
        if req.method == "GET" && req.path == "/me/drive/root" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_folder("root-id-1", "root"),
            ));
        }
        if req.method == "POST" && req.path == "/me/drive/items/src-id-1/copy" {
            dst_present_c.store(true, Ordering::SeqCst);
            return MockAction::Respond(
                MockResponse::empty(202).with_header("Location", &mon_url_c),
            );
        }
        if req.method == "PATCH" && req.path.starts_with("/me/drive/items/dst-id-") {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "dst-id-1",
                    "dst.bin",
                    &src_data_c,
                    "\"de1\"",
                    "2026-01-02T03:04:05Z",
                    None,
                ),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    });

    let client = RshipClient::builder()
        .ephemeral()
        .transport_config(TransportConfig::new().with_long_control_timeout(Duration::from_secs(7)))
        .remote(
            "od",
            OnedriveRemoteConfig::new()
                .with_api_base_url(api_srv.base_url())
                .with_access_token("od-tok"),
        )
        .build()
        .unwrap();

    // Sub-case A: polls past 3s (4 x Retry-After: 1s >= 3.5s) without aborting
    let start = std::time::Instant::now();
    let report = client
        .copy_file("od:src.bin", "od:dst.bin")
        .run()
        .await
        .unwrap();
    assert_eq!(report.files_transferred, 1);
    assert!(
        start.elapsed() >= Duration::from_secs(3),
        "must poll past 3s instead of aborting prematurely"
    );
    let api_reqs = api_srv.take_requests();
    assert!(
        !api_reqs.iter().any(|r| r.path.contains("/content")),
        "must NOT fall back to streaming /content transfer"
    );
    let copy_req = api_reqs
        .iter()
        .find(|r| r.method == "POST" && r.path == "/me/drive/items/src-id-1/copy")
        .unwrap();
    let copy_json = copy_req.body_json().unwrap();
    assert_eq!(copy_json["parentReference"]["driveId"], "drv-me-9");
    let patch_req = api_reqs
        .iter()
        .find(|r| r.method == "PATCH" && r.path == "/me/drive/items/dst-id-1")
        .unwrap();
    let mtime_str = patch_req.body_json().unwrap()["fileSystemInfo"]["lastModifiedDateTime"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        mtime_str.len() == 20 && mtime_str.ends_with('Z') && !mtime_str.contains('.'),
        "mtime must be second-precision YYYY-MM-DDTHH:MM:SSZ, got {mtime_str}"
    );
    assert!(
        monitor_srv
            .requests()
            .iter()
            .all(|r| r.header("authorization").is_none()),
        "monitor URL requests must NOT send Authorization"
    );

    // Sub-case B: 303 See Other & Sub-case C: deleteFailed -> Ok(None)
    let (backend, _) = client.resolve("od:").unwrap();
    *mode.lock().unwrap() = "redirect_303";
    dst_present.store(false, Ordering::SeqCst);
    let init_b = make_upload_init(
        RelPath::parse("dst.bin").unwrap(),
        src_data.len() as u64,
        1_700_000_000_000_000_000,
        13 * 320 * 1024,
    );
    let res_b = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &init_b,
        )
        .await
        .unwrap();
    assert!(res_b.is_some(), "303 See Other monitor must succeed");

    *mode.lock().unwrap() = "delete_failed";
    dst_present.store(false, Ordering::SeqCst);
    let res_c = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &init_b,
        )
        .await
        .unwrap();
    assert!(
        res_c.is_none(),
        "deleteFailed monitor status must return Ok(None)"
    );
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier2_onedrive_open_read_uses_download_url_without_authorization_and_refreshes_on_403() {
    let cdn_srv = MockHttpServer::start().await;
    let payload = b"0123456789abcdefghijklmnopqrstuvwxyz".to_vec();
    let payload_c = payload.clone();
    let cdn_hits = Arc::new(AtomicUsize::new(0));
    let cdn_hits_c = cdn_hits.clone();
    cdn_srv.set_fallback(move |req| {
        assert!(
            req.header("authorization").is_none(),
            "CDN downloadUrl request MUST NOT carry Authorization header"
        );
        let n = cdn_hits_c.fetch_add(1, Ordering::SeqCst);
        if req.path == "/cdn/v1" && n >= 2 {
            return MockAction::Respond(MockResponse::empty(403));
        }
        if let Some((s, e)) = parse_byte_range_header(req, payload_c.len()) {
            return MockAction::Respond(
                MockResponse::new(206, payload_c[s..=e].to_vec()).with_header(
                    "Content-Range",
                    format!("bytes {s}-{e}/{}", payload_c.len()),
                ),
            );
        }
        MockAction::Respond(MockResponse::ok(payload_c.clone()))
    });

    let api_srv = MockHttpServer::start().await;
    let stat_calls = Arc::new(AtomicUsize::new(0));
    let stat_calls_c = stat_calls.clone();
    let cdn_v1 = cdn_srv.url("/cdn/v1");
    let cdn_v2 = cdn_srv.url("/cdn/v2");
    let payload_a = payload.clone();
    api_srv.set_fallback(move |req| {
        if req.method == "GET"
            && (req.path == "/me/drive/root:/doc.bin:" || req.path == "/me/drive/items/doc-1")
        {
            let c = stat_calls_c.fetch_add(1, Ordering::SeqCst);
            let url = if c == 0 { &cdn_v1 } else { &cdn_v2 };
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "doc-1",
                    "doc.bin",
                    &payload_a,
                    "\"e1\"",
                    "2026-01-01T00:00:00Z",
                    Some(url),
                ),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    });

    let client = onedrive_client_for(&api_srv);
    let DataSource::RemoteRangeReadable(reader) =
        client.open_read("od:doc.bin", None).await.unwrap()
    else {
        panic!("expected RemoteRangeReadable");
    };

    // Read 1 & 2 hit /cdn/v1; Read 3 gets 403 on v1, refreshes via stat -> /cdn/v2
    let mut s1 = reader
        .open_range(ByteRange { offset: 0, len: 10 })
        .await
        .unwrap();
    let mut got1 = Vec::new();
    while let Some(chunk) = s1.next().await {
        got1.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got1, payload[0..10]);

    let mut s2 = reader
        .open_range(ByteRange {
            offset: 10,
            len: 10,
        })
        .await
        .unwrap();
    let mut got2 = Vec::new();
    while let Some(chunk) = s2.next().await {
        got2.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got2, payload[10..20]);

    let mut s3 = reader
        .open_range(ByteRange {
            offset: 20,
            len: 10,
        })
        .await
        .unwrap();
    let mut got3 = Vec::new();
    while let Some(chunk) = s3.next().await {
        got3.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got3, payload[20..30]);

    assert!(
        !api_srv
            .requests()
            .iter()
            .any(|r| r.path.contains("/content")),
        "Graph /content must NOT be called when @microsoft.graph.downloadUrl is present"
    );
    assert!(
        cdn_srv.requests().iter().any(|r| r.path == "/cdn/v2"),
        "403 on expired downloadUrl must refresh to /cdn/v2"
    );
}

#[cfg(all(feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier2_onedrive_chunk_416_fragment_overlap_and_423_locked_resume_via_query_upload() {
    let srv = MockHttpServer::start().await;
    let base_url = srv.base_url();
    let buf_slot: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let buf_c = buf_slot.clone();
    let chunk2_calls = Arc::new(AtomicUsize::new(0));
    let chunk2_c = chunk2_calls.clone();

    srv.set_fallback(move |req| {
        if req.method == "GET" && req.path == "/me/drive/root:/resumed.bin:" {
            let b = buf_c.lock().unwrap();
            if b.len() == 4_500_000 {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &make_graph_file(
                        "od-res-1",
                        "resumed.bin",
                        &b,
                        "\"e-res\"",
                        "2026-01-01T00:00:00Z",
                        None,
                    ),
                ));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "POST" && req.path == "/me/drive/root:/resumed.bin:/createUploadSession" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "uploadUrl": format!("{base_url}/upload_sess/s-416"),
                    "expirationDateTime": "2099-01-01T00:00:00Z"
                }),
            ));
        }
        if req.path == "/upload_sess/s-416" && req.method == "GET" {
            let len = buf_c.lock().unwrap().len();
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "nextExpectedRanges": [format!("{len}-")] }),
            ));
        }
        if req.path == "/upload_sess/s-416"
            && req.method == "PUT"
            && let Some((start, end, total)) = parse_content_range_upload(req)
        {
            if start == 0 {
                let mut b = buf_c.lock().unwrap();
                *b = req.body.clone();
                return MockAction::Respond(MockResponse::json(
                    202,
                    &serde_json::json!({ "nextExpectedRanges": [format!("{}-", end + 1)] }),
                ));
            }
            let attempt = chunk2_c.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                return MockAction::Respond(MockResponse::json(
                    416,
                    &serde_json::json!({ "error": { "code": "fragmentOverlap" } }),
                ));
            }
            if attempt == 1 {
                return MockAction::Respond(MockResponse::json(
                    423,
                    &serde_json::json!({ "error": { "code": "resourceLocked" } }),
                ));
            }
            let mut b = buf_c.lock().unwrap();
            if b.len() < total {
                b.resize(total, 0);
            }
            b[start..=end].copy_from_slice(&req.body);
            let json = make_graph_file(
                "od-res-1",
                "resumed.bin",
                &b,
                "\"e-res\"",
                "2026-01-01T00:00:00Z",
                None,
            );
            return MockAction::Respond(MockResponse::json(201, &json));
        }
        MockAction::Respond(MockResponse::empty(404))
    });

    let client = onedrive_client_for(&srv);
    let total = 4_500_000usize;
    let payload: Vec<u8> = (0..total).map(|i| (i % 239) as u8).collect();
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("resumed.bin");
    std::fs::write(&src, &payload).unwrap();

    client
        .copy_file(src.to_string_lossy().as_ref(), "od:resumed.bin")
        .chunk_size(13 * 320 * 1024)
        .retries(3)
        .base_retry_delay(Duration::from_millis(5))
        .run()
        .await
        .unwrap();

    assert_eq!(*buf_slot.lock().unwrap(), payload);
    let query_gets = srv
        .requests()
        .iter()
        .filter(|r| r.method == "GET" && r.path == "/upload_sess/s-416")
        .count();
    assert!(
        query_gets >= 2,
        "416 fragmentOverlap and 423 Locked must both trigger GET uploadUrl query_upload"
    );
}

#[cfg(all(feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier2_onedrive_query_upload_empty_next_expected_ranges_requires_pre_op_proof_move_safe() {
    let srv = MockHttpServer::start().await;
    let base_url = srv.base_url();
    let old_data = vec![b'O'; 4_500_000];
    let new_data = vec![b'N'; 4_500_000];
    let old_etag = Arc::new(Mutex::new("\"old-etag\"".to_string()));
    let old_etag_c = old_etag.clone();
    let old_data_c = old_data.clone();

    srv.set_fallback(move |req| {
        if req.method == "GET" && req.path == "/me/drive/root:/target.bin:" {
            let et = old_etag_c.lock().unwrap().clone();
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "od-target-1",
                    "target.bin",
                    &old_data_c,
                    &et,
                    "2026-01-01T00:00:00Z",
                    None,
                ),
            ));
        }
        if req.method == "POST" && req.path == "/me/drive/root:/target.bin:/createUploadSession" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "uploadUrl": format!("{base_url}/upload_sess/s-empty"),
                    "expirationDateTime": "2099-01-01T00:00:00Z"
                }),
            ));
        }
        if req.path == "/upload_sess/s-empty" && req.method == "GET" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "nextExpectedRanges": [] }),
            ));
        }
        if req.path == "/upload_sess/s-empty" && req.method == "PUT" {
            return MockAction::Respond(MockResponse::empty(503));
        }
        if req.path == "/upload_sess/s-empty" && req.method == "DELETE" {
            return MockAction::Respond(MockResponse::empty(204));
        }
        MockAction::Respond(MockResponse::empty(404))
    });

    let client = onedrive_client_for(&srv);
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("source.bin");
    std::fs::write(&src, &new_data).unwrap();

    let res = client
        .move_file(src.to_string_lossy().as_ref(), "od:target.bin")
        .chunk_size(13 * 320 * 1024)
        .retries(1)
        .base_retry_delay(Duration::from_millis(5))
        .run()
        .await;
    if let Ok(report) = res {
        assert_eq!(report.files_transferred, 0);
        assert_eq!(report.sources_deleted, 0);
        assert!(!report.errors.is_empty());
    }
    assert!(
        src.exists(),
        "CRITICAL: local source file MUST remain intact when destination eTag is unchanged"
    );
    assert_eq!(std::fs::read(&src).unwrap(), new_data);

    // Also check StorageBackend::query_upload PreOpState proof directly:
    let (backend, _) = client.resolve("od:").unwrap();
    let mut init = make_upload_init(
        RelPath::parse("target.bin").unwrap(),
        4_500_000,
        1_767_225_600_000_000_000, // 2026-01-01T00:00:00Z
        13 * 320 * 1024,
    );
    init.precondition = DstPrecondition::Existing {
        node_id: None,
        size: 4_500_000,
        mtime_ns: 1_767_225_600_000_000_000,
        etag: Some("\"old-etag\"".to_string()),
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op_record(
        "onedrive",
        &init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );
    // Same eTag -> Expired (NOT AlreadyCompleted)
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::Expired
    );
    // Changed eTag -> AlreadyCompleted
    *old_etag.lock().unwrap() = "\"new-etag-committed\"".to_string();
    assert!(matches!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::AlreadyCompleted(_)
    ));
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier2_onedrive_ensure_dir_chain_rejects_regular_file_as_parent() {
    let state = Arc::new(Mutex::new(MockOdState::new()));
    state
        .lock()
        .unwrap()
        .insert_file("not_a_dir", b"i am a file".to_vec());
    let srv = start_mock_od(state).await;
    let client = onedrive_client_for(&srv);

    let err = client.mkdir("od:not_a_dir/sub").await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);

    let (backend, _) = client.resolve("od:").unwrap();
    let init = make_upload_init(
        RelPath::parse("not_a_dir/child.txt").unwrap(),
        4,
        1_700_000_000_000_000_000,
        13 * 320 * 1024,
    );
    let up_err = backend
        .put_single_shot(&init, make_byte_stream(b"abcd".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(up_err.kind, ErrorKind::Conflict);
    assert!(
        !srv.requests()
            .iter()
            .any(|r| r.method == "PUT" && r.path.contains("/content")),
        "must reject regular file parent before issuing PUT /content"
    );
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier2_onedrive_max_depth_zero_nfd_bfs_and_package_remote_item_facets() {
    let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/me/drive" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "id": "drv-me" }),
                ));
            }
            if req.method == "GET" && req.path == "/me/drive/root/children" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [
                            make_graph_folder("nfd-dir-1", "Cafe\u{301}"),
                            {
                                "id": "mount-1",
                                "name": "SharedMount",
                                "remoteItem": {
                                    "id": "rem-dir-1",
                                    "parentReference": { "driveId": "drv-rem-9" },
                                    "folder": { "childCount": 1 }
                                }
                            },
                            {
                                "id": "pkg-1",
                                "name": "Notebook",
                                "size": 0,
                                "package": { "type": "oneNote" }
                            }
                        ]
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/me/drive/items/nfd-dir-1/children" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [make_graph_file("f-nfd", "inside.txt", b"nfd", "\"e1\"", "2026-01-01T00:00:00Z", None)]
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/drives/drv-rem-9/items/rem-dir-1/children" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "value": [make_graph_file("f-rem", "doc.txt", b"rem", "\"e2\"", "2026-01-01T00:00:00Z", None)]
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/me/drive/root:/Notebook:" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "id": "pkg-1",
                        "name": "Notebook",
                        "size": 0,
                        "package": { "type": "oneNote" }
                    }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;
    let client = onedrive_client_for(&srv);

    // 1. max_depth(0) -> empty and 0 /children requests
    let d0 = collect_entries(
        client
            .list("od:", &ListOptions::new().with_max_depth(0))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(d0.is_empty());
    assert!(
        srv.requests().is_empty(),
        "max_depth(0) must issue 0 HTTP calls"
    );

    // 2. Recursive NFD + remoteItem + package exclusion
    let entries = collect_entries(client.list("od:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    let nfd_file = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "Café/inside.txt")
        .expect("NFD folder subtree must not be dropped");
    assert_eq!(nfd_file.raw_path.as_deref(), Some("Cafe\u{301}/inside.txt"));
    assert!(
        entries
            .iter()
            .any(|e| e.nfc_path.as_str() == "SharedMount/doc.txt"),
        "remoteItem folder must traverse via /drives/drv-rem-9/items/rem-dir-1/children"
    );
    assert!(
        !entries.iter().any(|e| e.nfc_path.as_str() == "Notebook"),
        "package facet must be excluded from listing"
    );

    let pkg_err = client.open_read("od:Notebook", None).await.err().unwrap();
    assert_eq!(pkg_err.kind, ErrorKind::Unsupported);
}

#[cfg(feature = "onedrive")]
#[tokio::test]
async fn tier2_onedrive_quickxor_integrity_check_and_nfd_parent_rename() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "GET" && req.path == "/me/drive/root:/bad_qxh.bin:" {
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "PUT" && req.path == "/me/drive/root:/bad_qxh.bin:/content" {
            return MockAction::Respond(MockResponse::json(
                201,
                &serde_json::json!({
                    "id": "od-bad-1",
                    "name": "bad_qxh.bin",
                    "size": 4,
                    "file": {
                        "hashes": {
                            "quickXorHash": base64_encode(&[0u8; 20])
                        }
                    }
                }),
            ));
        }
        if req.method == "GET" && req.path == "/me/drive/root:/Cafe%CC%81/old.txt:" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "od-nfd-f",
                    "old.txt",
                    b"abc",
                    "\"e1\"",
                    "2026-01-01T00:00:00Z",
                    None,
                ),
            ));
        }
        if req.method == "PATCH" && req.path == "/me/drive/items/od-nfd-f" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_graph_file(
                    "od-nfd-f",
                    "new.txt",
                    b"abc",
                    "\"e1\"",
                    "2026-01-01T00:00:00Z",
                    None,
                ),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    let client = onedrive_client_for(&srv);
    let (backend, _) = client.resolve("od:").unwrap();

    // Business/SharePoint quickXorHash mismatch -> ErrorKind::Integrity
    let init = make_upload_init(
        RelPath::parse("bad_qxh.bin").unwrap(),
        4,
        1_700_000_000_000_000_000,
        13 * 320 * 1024,
    );
    let err = backend
        .put_single_shot(&init, make_byte_stream(b"abcd".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Integrity);

    // NFD parent rename preserves NFD raw_path and sends Cafe%CC%81 on wire
    let bp = BackendPath::new(
        "Cafe\u{301}/old.txt",
        RelPath::parse("Café/old.txt").unwrap(),
        None,
    );
    let renamed = backend.rename(&bp, "new.txt").await.unwrap();
    assert_eq!(renamed.raw_path.as_deref(), Some("Cafe\u{301}/new.txt"));
    assert_eq!(renamed.nfc_path.as_str(), "Café/new.txt");
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "GET"
                && r.path == "/me/drive/root:/Cafe%CC%81/old.txt:"
                && !r.path.contains("Caf%C3%A9")
        }),
        "OneDrive rename must send NFD Cafe%CC%81 on the wire (not NFC Caf%C3%A9)"
    );
}

// ===========================================================================
// Feature Area #10: Dropbox (`dropbox`)
// ===========================================================================

#[cfg(feature = "dropbox")]
use dropbox_mock::*;

#[cfg(feature = "dropbox")]
mod dropbox_mock {
    use super::*;

    pub(super) fn dropbox_api_arg_json(req: &CapturedRequest) -> Option<serde_json::Value> {
        let raw = req.header("dropbox-api-arg")?;
        serde_json::from_str(raw).ok()
    }

    pub(super) fn make_dbx_file(path_display: &str, data: &[u8], rev: &str) -> serde_json::Value {
        let name = path_display.rsplit('/').next().unwrap_or(path_display);
        serde_json::json!({
            ".tag": "file",
            "id": format!("id:{rev}"),
            "name": name,
            "path_lower": path_display.to_ascii_lowercase(),
            "path_display": path_display,
            "size": data.len(),
            "rev": rev,
            "client_modified": "2026-01-01T00:00:00Z",
            "server_modified": "2026-01-01T00:00:00Z",
            "content_hash": dropbox_content_hash(data),
            "is_downloadable": true,
        })
    }

    pub(super) fn make_dbx_folder(path_display: &str) -> serde_json::Value {
        let name = path_display.rsplit('/').next().unwrap_or(path_display);
        serde_json::json!({
            ".tag": "folder",
            "id": format!("id:dir:{path_display}"),
            "name": name,
            "path_lower": path_display.to_ascii_lowercase(),
            "path_display": path_display,
        })
    }

    pub(super) fn dropbox_client_for(srv: &MockHttpServer, root_path: Option<&str>) -> RshipClient {
        let mut cfg = DropboxRemoteConfig::new()
            .with_api_base_url(srv.url("/api/2"))
            .with_content_base_url(srv.url("/content/2"))
            .with_access_token("dbx-tok");
        if let Some(rp) = root_path {
            cfg = cfg.with_root_path(rp);
        }
        RshipClient::builder()
            .ephemeral()
            .remote("dbx", cfg)
            .build()
            .unwrap()
    }

    #[derive(Clone)]
    pub(super) struct MockDbxItem {
        is_folder: bool,
        path_display: String,
        data: Vec<u8>,
        rev: String,
    }

    pub(super) struct MockDbxState {
        items: HashMap<String, MockDbxItem>,
        sessions: HashMap<String, Vec<u8>>,
        next_rev: usize,
        next_sess: usize,
    }

    impl MockDbxState {
        pub(super) fn new() -> Self {
            Self {
                items: HashMap::new(),
                sessions: HashMap::new(),
                next_rev: 1,
                next_sess: 1,
            }
        }

        pub(super) fn put_file(&mut self, path_display: &str, data: Vec<u8>) -> MockDbxItem {
            let rev = format!("rev{:x}", self.next_rev);
            self.next_rev += 1;
            let item = MockDbxItem {
                is_folder: false,
                path_display: path_display.to_string(),
                data,
                rev,
            };
            self.items.insert(path_display.to_string(), item.clone());
            item
        }

        pub(super) fn put_folder(&mut self, path_display: &str) -> MockDbxItem {
            let item = MockDbxItem {
                is_folder: true,
                path_display: path_display.to_string(),
                data: Vec::new(),
                rev: String::new(),
            };
            self.items.insert(path_display.to_string(), item.clone());
            item
        }

        fn to_json(item: &MockDbxItem) -> serde_json::Value {
            if item.is_folder {
                make_dbx_folder(&item.path_display)
            } else {
                make_dbx_file(&item.path_display, &item.data, &item.rev)
            }
        }
    }

    pub(super) async fn start_mock_dbx(state: Arc<Mutex<MockDbxState>>) -> MockHttpServer {
        let srv = MockHttpServer::start().await;
        srv.set_fallback(move |req| {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            if req.path == "/api/2/files/get_metadata" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(item) = st.items.get(path) {
                    return MockAction::Respond(MockResponse::json(200, &MockDbxState::to_json(item)));
                }
                return MockAction::Respond(MockResponse::json(
                    409,
                    &serde_json::json!({
                        "error_summary": "path/not_found/..",
                        "error": { ".tag": "path", "path": { ".tag": "not_found" } }
                    }),
                ));
            }
            if req.path == "/api/2/files/create_folder_v2" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if st.items.contains_key(path) {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({
                            "error_summary": "path/conflict/folder/.",
                            "error": { ".tag": "path", "path": { ".tag": "conflict", "conflict": { ".tag": "folder" } } }
                        }),
                    ));
                }
                let item = st.put_folder(path);
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "metadata": MockDbxState::to_json(&item) }),
                ));
            }
            if req.path == "/api/2/files/list_folder" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let recursive = body.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
                let entries: Vec<serde_json::Value> = st
                    .items
                    .values()
                    .filter(|it| {
                        let rel = if path.is_empty() {
                            it.path_display.strip_prefix('/')
                        } else {
                            it.path_display.strip_prefix(&format!("{path}/"))
                        };
                        match rel {
                            Some(r) if !r.is_empty() => recursive || !r.contains('/'),
                            _ => false,
                        }
                    })
                    .map(MockDbxState::to_json)
                    .collect();
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "entries": entries,
                        "cursor": "cur-1",
                        "has_more": false
                    }),
                ));
            }
            if req.path == "/api/2/files/delete_v2" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(removed) = st.items.remove(path) {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({ "metadata": MockDbxState::to_json(&removed) }),
                    ));
                }
                return MockAction::Respond(MockResponse::json(
                    409,
                    &serde_json::json!({
                        "error_summary": "path_lookup/not_found/.",
                        "error": { ".tag": "path_lookup", "path_lookup": { ".tag": "not_found" } }
                    }),
                ));
            }
            if req.path == "/api/2/files/move_v2" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let from = body.get("from_path").and_then(|v| v.as_str()).unwrap_or("");
                let to = body.get("to_path").and_then(|v| v.as_str()).unwrap_or("");
                let Some(mut item) = st.items.remove(from) else {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({ "error_summary": "from_lookup/not_found/." }),
                    ));
                };
                item.path_display = to.to_string();
                st.items.insert(to.to_string(), item.clone());
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "metadata": MockDbxState::to_json(&item) }),
                ));
            }
            if req.path == "/api/2/files/copy_v2" && req.method == "POST" {
                let body = req.body_json().unwrap_or_default();
                let from = body.get("from_path").and_then(|v| v.as_str()).unwrap_or("");
                let to = body.get("to_path").and_then(|v| v.as_str()).unwrap_or("");
                if st.items.contains_key(to) {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({
                            "error_summary": "to/conflict/file/.",
                            "error": { ".tag": "to", "to": { ".tag": "conflict", "conflict": { ".tag": "file" } } }
                        }),
                    ));
                }
                let Some(src) = st.items.get(from).cloned() else {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({ "error_summary": "from_lookup/not_found/." }),
                    ));
                };
                let dst = st.put_file(to, src.data);
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "metadata": MockDbxState::to_json(&dst) }),
                ));
            }
            if req.path == "/api/2/users/get_space_usage" && req.method == "POST" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "used": 1000,
                        "allocation": { ".tag": "individual", "allocated": 4000 }
                    }),
                ));
            }
            if req.path == "/content/2/files/upload" && req.method == "POST" {
                let Some(arg) = dropbox_api_arg_json(req) else {
                    return MockAction::Respond(MockResponse::empty(400));
                };
                let path = arg.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let item = st.put_file(path, req.body.clone());
                return MockAction::Respond(MockResponse::json(200, &MockDbxState::to_json(&item)));
            }
            if req.path == "/content/2/files/upload_session/start" && req.method == "POST" {
                let sid = format!("dbx-sess-{}", st.next_sess);
                st.next_sess += 1;
                st.sessions.insert(sid.clone(), req.body.clone());
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "session_id": sid }),
                ));
            }
            if req.path == "/content/2/files/upload_session/append_v2" && req.method == "POST" {
                let Some(arg) = dropbox_api_arg_json(req) else {
                    return MockAction::Respond(MockResponse::empty(400));
                };
                let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
                let off = arg["cursor"]["offset"].as_u64().unwrap_or(0) as usize;
                let Some(buf) = st.sessions.get_mut(sid) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if buf.len() != off {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({
                            "error_summary": "incorrect_offset/.",
                            "error": { ".tag": "incorrect_offset", "correct_offset": buf.len() }
                        }),
                    ));
                }
                buf.extend_from_slice(&req.body);
                return MockAction::Respond(MockResponse::json(200, &serde_json::json!({})));
            }
            if req.path == "/content/2/files/upload_session/finish" && req.method == "POST" {
                let Some(arg) = dropbox_api_arg_json(req) else {
                    return MockAction::Respond(MockResponse::empty(400));
                };
                let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
                let off = arg["cursor"]["offset"].as_u64().unwrap_or(0) as usize;
                let path = arg["commit"]["path"].as_str().unwrap_or("");
                let Some(mut buf) = st.sessions.remove(sid) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if buf.len() != off {
                    return MockAction::Respond(MockResponse::json(
                        409,
                        &serde_json::json!({
                            "error_summary": "incorrect_offset/.",
                            "error": { ".tag": "incorrect_offset", "correct_offset": buf.len() }
                        }),
                    ));
                }
                buf.extend_from_slice(&req.body);
                let item = st.put_file(path, buf);
                return MockAction::Respond(MockResponse::json(200, &MockDbxState::to_json(&item)));
            }
            if req.path == "/content/2/files/download" && req.method == "POST" {
                let Some(arg) = dropbox_api_arg_json(req) else {
                    return MockAction::Respond(MockResponse::empty(400));
                };
                let path = arg.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let Some(item) = st.items.get(path) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                let meta_hdr = serde_json::to_string(&MockDbxState::to_json(item)).unwrap();
                if let Some((s, e)) = parse_byte_range_header(req, item.data.len()) {
                    return MockAction::Respond(
                        MockResponse::new(206, item.data[s..=e].to_vec())
                            .with_header("Content-Range", format!("bytes {s}-{e}/{}", item.data.len()))
                            .with_header("dropbox-api-result", meta_hdr),
                    );
                }
                return MockAction::Respond(
                    MockResponse::ok(item.data.clone()).with_header("dropbox-api-result", meta_hdr),
                );
            }
            MockAction::Respond(MockResponse::empty(404))
        });
        srv
    }
}

// ---------------------------------------------------------------------------
// Dropbox Tier 1 (Happy Path >= 5)
// ---------------------------------------------------------------------------

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier1_dropbox_stat_and_list_paginated() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.path == "/api/2/files/get_metadata" {
            let path = req.body_json().unwrap()["path"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if path == "/a/b.txt" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &make_dbx_file("/a/b.txt", b"hello", "rev1"),
                ));
            }
            return MockAction::Respond(MockResponse::json(
                409,
                &serde_json::json!({
                    "error_summary": "path/not_found/..",
                    "error": { ".tag": "path", "path": { ".tag": "not_found" } }
                }),
            ));
        }
        if req.path == "/api/2/files/list_folder" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "entries": [make_dbx_folder("/a")],
                    "cursor": "cur-page-1",
                    "has_more": true
                }),
            ));
        }
        if req.path == "/api/2/files/list_folder/continue" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "entries": [make_dbx_file("/a/b.txt", b"hello", "rev1")],
                    "cursor": "cur-page-2",
                    "has_more": false
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    let client = dropbox_client_for(&srv, None);

    assert!(client.stat("dbx:missing.txt").await.unwrap().is_none());
    let st = client.stat("dbx:a/b.txt").await.unwrap().unwrap();
    assert_eq!(st.size, 5);

    let listed = collect_entries(
        client
            .list("dbx:", &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == "a"));
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == "a/b.txt"));
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.path == "/api/2/files/list_folder/continue")
    );
}

#[cfg(all(feature = "dropbox", feature = "local"))]
#[tokio::test]
async fn tier1_dropbox_put_single_shot_and_content_hash_verification() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("small.bin");
    let payload = b"dropbox single shot payload".to_vec();
    std::fs::write(&src, &payload).unwrap();

    client
        .copy_file(src.to_string_lossy().as_ref(), "dbx:small.bin")
        .run()
        .await
        .unwrap();

    let req = srv
        .requests()
        .into_iter()
        .find(|r| r.path == "/content/2/files/upload")
        .expect("POST /files/upload expected");
    assert_eq!(req.body, payload);
    let arg = dropbox_api_arg_json(&req).unwrap();
    assert_eq!(arg["path"], "/small.bin");
    assert_eq!(arg["mode"], "overwrite");
    assert_eq!(arg["mute"], true);
    let st = client.stat("dbx:small.bin").await.unwrap().unwrap();
    assert_eq!(st.size, payload.len() as u64);

    // Also verify single-shot response content_hash mismatch is caught with ErrorKind::Integrity
    let bad_srv = MockHttpServer::start_with_handler(|req| {
            if req.path == "/content/2/files/upload" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        ".tag": "file",
                        "id": "id:bad",
                        "name": "bad.bin",
                        "path_lower": "/bad.bin",
                        "path_display": "/bad.bin",
                        "size": 4,
                        "rev": "rev1",
                        "client_modified": "2026-01-01T00:00:00Z",
                        "server_modified": "2026-01-01T00:00:00Z",
                        "content_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "is_downloadable": true
                    }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;
    let bad_client = dropbox_client_for(&bad_srv, None);
    let (bad_backend, _) = bad_client.resolve("dbx:").unwrap();
    let bad_init = make_upload_init(
        RelPath::parse("bad.bin").unwrap(),
        4,
        1_700_000_000_000_000_000,
        4 * 1024 * 1024,
    );
    let err = bad_backend
        .put_single_shot(&bad_init, make_byte_stream(b"abcd".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Integrity);
}

#[cfg(all(feature = "dropbox", feature = "local"))]
#[tokio::test]
async fn tier1_dropbox_upload_session_multi_chunk() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    let total = 4_500_000usize;
    let payload: Vec<u8> = (0..total).map(|i| (i % 233) as u8).collect();
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("big.bin");
    std::fs::write(&src, &payload).unwrap();

    client
        .copy_file(src.to_string_lossy().as_ref(), "dbx:big.bin")
        .chunk_size(4 * 1024 * 1024)
        .run()
        .await
        .unwrap();

    let reqs = srv.requests();
    assert!(
        reqs.iter()
            .any(|r| r.path == "/content/2/files/upload_session/start")
    );
    assert!(
        reqs.iter()
            .any(|r| r.path == "/content/2/files/upload_session/append_v2")
    );
    assert!(
        reqs.iter()
            .any(|r| r.path == "/content/2/files/upload_session/finish")
    );

    let ds = client.open_read("dbx:big.bin", None).await.unwrap();
    assert_eq!(read_all_from_source(ds).await.unwrap(), payload);
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier1_dropbox_open_read_full_and_range() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    let payload: Vec<u8> = (0..512).map(|i| (i % 197) as u8).collect();
    state.lock().unwrap().put_file("/file.bin", payload.clone());
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    let full = read_all_from_source(client.open_read("dbx:file.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(full, payload);

    let range = ByteRange {
        offset: 50,
        len: 100,
    };
    let partial = read_range_from_source(
        client.open_read("dbx:file.bin", Some(range)).await.unwrap(),
        range,
    )
    .await
    .unwrap();
    assert_eq!(partial, payload[50..150]);
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier1_dropbox_mkdir_rename_and_delete() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    {
        let mut st = state.lock().unwrap();
        st.put_folder("/dir");
        st.put_file("/dir/old.txt", b"hello".to_vec());
    }
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    client.mkdir("dbx:dir/sub").await.unwrap();
    client.mkdir("dbx:dir/sub").await.unwrap();

    let renamed = client.rename("dbx:dir/old.txt", "new.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "dir/new.txt");
    assert!(client.stat("dbx:dir/new.txt").await.unwrap().is_some());

    client.delete("dbx:dir/new.txt").await.unwrap();
    assert!(client.stat("dbx:dir/new.txt").await.unwrap().is_none());
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier1_dropbox_about_individual_quota() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    let q = client.about("dbx:").await.unwrap().unwrap();
    assert_eq!(q.total_bytes, Some(4000));
    assert_eq!(q.used_bytes, Some(1000));
    assert_eq!(q.free_bytes, Some(3000));
    assert_eq!(q.trashed_bytes, None);
}

// -----------------------------------------------------------------------
// Tier 2 (Audit §III.6)
// -----------------------------------------------------------------------

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_pkce_omits_empty_scope() {
    let pkce = DropboxPkceFlow::start(
        "dbx-cid",
        None,
        "https://www.dropbox.com/oauth2/authorize",
        "https://api.dropboxapi.com/oauth2/token",
    )
    .await
    .unwrap();
    assert!(pkce.authorize_url.contains("token_access_type=offline"));
    assert!(pkce.authorize_url.contains("code_challenge_method=S256"));
    assert!(
        !pkce.authorize_url.contains("scope="),
        "Dropbox PKCE authorize_url must omit empty scope=, got: {}",
        pkce.authorize_url
    );
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_delete_batch_async_job_polling_and_root_delete_blocked() {
    let check_calls = Arc::new(AtomicUsize::new(0));
    let check_c = check_calls.clone();
    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.path == "/api/2/files/delete_batch" && req.method == "POST" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    ".tag": "async_job_id",
                    "async_job_id": "job-42"
                }),
            ));
        }
        if req.path == "/api/2/files/delete_batch/check" && req.method == "POST" {
            let n = check_c.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ ".tag": "in_progress" }),
                ));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    ".tag": "complete",
                    "entries": [
                        { ".tag": "success" },
                        { ".tag": "failure", "failure": { ".tag": "insufficient_space" } }
                    ]
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    let client = dropbox_client_for(&srv, None);

    // Root delete via client.delete must issue 0 delete_v2 calls
    client.delete("dbx:").await.unwrap();
    assert!(
        !srv.requests()
            .iter()
            .any(|r| r.path == "/api/2/files/delete_v2")
    );

    let (backend, _) = client.resolve("dbx:").unwrap();
    let failures = backend
        .delete_batch(&[
            BackendPath::from_rel(RelPath::root()),
            BackendPath::from_rel(RelPath::parse("ok.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("fail.txt").unwrap()),
        ])
        .await
        .unwrap();

    assert_eq!(failures.len(), 2);
    assert!(failures[0].0.nfc_path.is_root());
    assert_eq!(failures[0].1.kind, ErrorKind::InvalidPath);
    assert_eq!(failures[1].0.nfc_path.as_str(), "fail.txt");
    assert_eq!(failures[1].1.kind, ErrorKind::QuotaExceeded);

    let reqs = srv.requests();
    let batch_req = reqs
        .iter()
        .find(|r| r.path == "/api/2/files/delete_batch")
        .unwrap();
    assert_eq!(
        batch_req.body_json().unwrap()["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(check_calls.load(Ordering::SeqCst), 3);
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_server_side_copy_overwrite_existing_destination() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    {
        let mut st = state.lock().unwrap();
        st.put_file("/src.bin", b"NEW_SRC_CONTENT_LONGER".to_vec());
        st.put_file("/existing.bin", b"OLD_DST".to_vec());
    }
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, None);

    let report = client
        .copy_file("dbx:src.bin", "dbx:existing.bin")
        .run()
        .await
        .unwrap();
    assert_eq!(report.files_transferred, 1);

    let reqs = srv.take_requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.path == "/content/2/files/download" || r.path == "/content/2/files/upload"),
        "server-side copy overwrite must NOT fall back to download+upload"
    );
    assert!(reqs.iter().any(|r| r.path == "/api/2/files/copy_v2"));
    assert!(reqs.iter().any(|r| r.path == "/api/2/files/move_v2"));
    assert!(reqs.iter().any(|r| r.path == "/api/2/files/delete_v2"));

    let data = read_all_from_source(client.open_read("dbx:existing.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(data, b"NEW_SRC_CONTENT_LONGER");
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_stat_root_with_non_empty_root_path() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    state.lock().unwrap().put_folder("/sub");
    let srv = start_mock_dbx(state.clone()).await;
    let client = dropbox_client_for(&srv, Some("/sub"));

    let root_dir = client
        .stat("dbx:")
        .await
        .unwrap()
        .expect("stat(root) with folder root_path must be Some");
    assert_eq!(root_dir.kind, EntryKind::Directory);
    assert!(root_dir.nfc_path.is_root());

    // When /sub is a file instead of a folder, stat(root) returns None
    state
        .lock()
        .unwrap()
        .put_file("/sub", b"not a dir".to_vec());
    assert!(client.stat("dbx:").await.unwrap().is_none());
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_api_path_preserves_leading_and_trailing_spaces() {
    let state = Arc::new(Mutex::new(MockDbxState::new()));
    {
        let mut st = state.lock().unwrap();
        st.put_folder("/ root ");
        st.put_file("/ root / lead ", b"spaced".to_vec());
    }
    let srv = start_mock_dbx(state).await;
    let client = dropbox_client_for(&srv, Some("/ root "));

    let entry = client
        .stat("dbx: lead ")
        .await
        .unwrap()
        .expect("spaced filename must stat");
    assert_eq!(entry.size, 6);

    let bytes = read_all_from_source(client.open_read("dbx: lead ", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(bytes, b"spaced");

    let reqs = srv.requests();
    assert!(reqs.iter().any(|r| {
        r.path == "/api/2/files/get_metadata"
            && r.body_json().is_ok_and(|j| j["path"] == "/ root / lead ")
    }));
    assert!(reqs.iter().any(|r| {
        r.path == "/content/2/files/download"
            && dropbox_api_arg_json(r).is_some_and(|j| j["path"] == "/ root / lead ")
    }));
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_409_content_hash_mismatch_integrity_and_retry_after_zero_floor() {
    let srv = MockHttpServer::start().await;
    let client = dropbox_client_for(&srv, None);
    let (backend, _) = client.resolve("dbx:").unwrap();

    // Part A: 409 content_hash_mismatch -> ErrorKind::Integrity (not Protocol)
    srv.enqueue_response(MockResponse::json(
        409,
        &serde_json::json!({
            "error_summary": "content_hash_mismatch/.",
            "error": { ".tag": "content_hash_mismatch" }
        }),
    ));
    let init = make_upload_init(
        RelPath::parse("hash_err.bin").unwrap(),
        4,
        1_700_000_000_000_000_000,
        4 * 1024 * 1024,
    );
    let err = backend
        .put_single_shot(&init, make_byte_stream(b"abcd".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Integrity,
        "409 content_hash_mismatch must map to ErrorKind::Integrity"
    );
    assert!(err.is_integrity());

    // Part B: Retry-After: 0 (header and JSON retry_after: 0) enforces non-zero backoff (>=50ms each)
    srv.enqueue_response(
        MockResponse::json(
            429,
            &serde_json::json!({ "error_summary": "too_many_requests/." }),
        )
        .with_header("Retry-After", "0"),
    );
    srv.enqueue_response(MockResponse::json(
        429,
        &serde_json::json!({
            "error_summary": "too_many_write_operations/.",
            "error": { ".tag": "too_many_write_operations", "retry_after": 0 }
        }),
    ));
    srv.enqueue_response(MockResponse::json(
        200,
        &make_dbx_file("/ok.txt", b"ok", "rev1"),
    ));

    let t0 = std::time::Instant::now();
    let found = client.stat("dbx:ok.txt").await.unwrap();
    let elapsed = t0.elapsed();
    assert!(found.is_some());
    assert!(
        elapsed >= Duration::from_millis(100),
        "two Retry-After: 0 responses must enforce >= 100ms total backoff floor, got {elapsed:?}"
    );
}

#[cfg(feature = "dropbox")]
#[tokio::test]
async fn tier2_dropbox_list_non_downloadable_nfd_rename_and_team_about() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.path == "/api/2/files/list_folder" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "entries": [
                        make_dbx_file("/real.txt", b"hi", "rev1"),
                        {
                            ".tag": "file",
                            "id": "id:paper",
                            "name": "Doc.paper",
                            "path_lower": "/doc.paper",
                            "path_display": "/Doc.paper",
                            "size": 0,
                            "rev": "rev2",
                            "is_downloadable": false
                        }
                    ],
                    "cursor": "c1",
                    "has_more": false
                }),
            ));
        }
        if req.path == "/api/2/files/get_metadata" {
            return MockAction::Respond(MockResponse::json(
                200,
                &make_dbx_file("/Cafe\u{301}/old.txt", b"nfd", "rev3"),
            ));
        }
        if req.path == "/api/2/files/move_v2" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "metadata": make_dbx_file("/Cafe\u{301}/new.txt", b"nfd", "rev4")
                }),
            ));
        }
        if req.path == "/api/2/users/get_space_usage" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "used": 200,
                    "allocation": {
                        ".tag": "team",
                        "used": 200,
                        "allocated": 1000,
                        "user_within_team_space_allocated": 500,
                        "user_within_team_space_used_cached": 120
                    }
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    let client = dropbox_client_for(&srv, None);

    // 1. list_folder sends include_non_downloadable_files: false and skips is_downloadable: false
    let entries = collect_entries(client.list("dbx:", &ListOptions::shallow()).await.unwrap())
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].nfc_path.as_str(), "real.txt");
    let list_req = srv
        .requests()
        .into_iter()
        .find(|r| r.path == "/api/2/files/list_folder")
        .unwrap();
    assert_eq!(
        list_req.body_json().unwrap()["include_non_downloadable_files"],
        false
    );

    // 2. NFD parent directory rename preserves NFD raw path
    let (backend, _) = client.resolve("dbx:").unwrap();
    let bp = BackendPath::new(
        "Cafe\u{301}/old.txt",
        RelPath::parse("Café/old.txt").unwrap(),
        None,
    );
    let renamed = backend.rename(&bp, "new.txt").await.unwrap();
    assert_eq!(renamed.raw_path.as_deref(), Some("Cafe\u{301}/new.txt"));
    let move_req = srv
        .requests()
        .into_iter()
        .find(|r| r.path == "/api/2/files/move_v2")
        .unwrap();
    let move_json = move_req.body_json().unwrap();
    assert_eq!(move_json["from_path"], "/Cafe\u{301}/old.txt");
    assert_eq!(move_json["to_path"], "/Cafe\u{301}/new.txt");

    // 3. Team about() quota uses user_within_team_space_*
    let team_q = client.about("dbx:").await.unwrap().unwrap();
    assert_eq!(team_q.total_bytes, Some(500));
    assert_eq!(team_q.used_bytes, Some(120));
    assert_eq!(team_q.free_bytes, Some(380));
}
