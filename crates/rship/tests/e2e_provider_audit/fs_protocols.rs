//! M4 E2E tests for filesystem & protocol backends: `webdav` (#11) and `sftp` (#12).
//! All `#[tokio::test]` functions live at module top level for clean `-- tier1_` /
//! `-- tier2_` / `-- fs_protocols::` test filtering, with zero `#![allow(...)]`.

#[cfg(feature = "webdav")]
mod webdav_helpers {
    use crate::mock_http::{CapturedRequest, MockAction, MockHttpServer, MockResponse};
    use futures::StreamExt;
    use rship::backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};
    use rship::core::backend::{EntryStream, UploadInit};
    use rship::core::buffer::BufferPool;
    use rship::core::path::RelPath;
    use rship::core::source::{ByteStream, DataSource, MemorySource, bounded_range_stream};
    use rship::core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
    use rship::core::types::{ByteRange, Entry};
    use rship::prelude::*;
    use rship::transport::{HttpTransport, TransportConfig};
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    pub(super) fn make_webdav_backend(cfg: WebdavConfig) -> WebdavBackend {
        let transport = HttpTransport::new(TransportConfig::new()).expect("HttpTransport::new");
        WebdavBackend::new(cfg, transport).expect("WebdavBackend::new")
    }

    pub(super) fn make_byte_stream(data: Vec<u8>) -> ByteStream {
        let len = data.len() as u64;
        if len == 0 {
            return Box::pin(futures::stream::empty());
        }
        let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).expect("BufferPool::new");
        let src = Arc::new(MemorySource::new(data));
        bounded_range_stream(src, 0, len, pool)
    }

    pub(super) async fn collect_entries(mut stream: EntryStream) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            out.push(item?);
        }
        Ok(out)
    }

    pub(super) async fn read_all_from_source(src: DataSource) -> Result<Vec<u8>> {
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

    pub(super) async fn read_range_from_source(
        src: DataSource,
        range: ByteRange,
    ) -> Result<Vec<u8>> {
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

    pub(super) fn make_upload_init(
        op_id: &str,
        dst_path: RelPath,
        total_size: u64,
        planned_chunk_size: u64,
        precondition: DstPrecondition,
    ) -> UploadInit {
        UploadInit {
            op_id: op_id.to_string(),
            dst_path,
            existing_node_id: None,
            pregenerated_id: None,
            total_size,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size,
            checksums: Vec::new(),
            precondition,
            src_etag: None,
        }
    }

    pub(super) fn make_op_record(
        init: &UploadInit,
        session_token: Option<String>,
        backend_meta: String,
        remote_op_id: Option<String>,
    ) -> OperationRecord {
        OperationRecord {
            op_id: init.op_id.clone(),
            session_key: format!("sess-{}", init.op_id),
            job_id: "job-webdav".to_string(),
            src_endpoint: "mem://src".to_string(),
            dst_endpoint: "webdav://dst".to_string(),
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
            backend_kind: "webdav".to_string(),
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

    pub(super) fn percent_decode_strict(raw: &str) -> String {
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

    pub(super) fn percent_encode_path(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for b in raw.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    pub(super) fn base64_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

    pub(super) fn md5_hex(data: &[u8]) -> String {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const K: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());

        let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476);
        for block in msg.as_chunks::<64>().0 {
            let mut m = [0u32; 16];
            for (i, w) in m.iter_mut().enumerate() {
                *w = u32::from_le_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
            for i in 0..64 {
                let (f, g) = match i {
                    0..=15 => ((b & c) | ((!b) & d), i),
                    16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | (!d)), (7 * i) % 16),
                };
                let temp = d;
                d = c;
                c = b;
                let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
                b = b.wrapping_add(sum.rotate_left(S[i]));
                a = temp;
            }
            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }
        let mut hex = String::with_capacity(32);
        for w in [a0, b0, c0, d0] {
            for b in w.to_le_bytes() {
                hex.push_str(&format!("{b:02x}"));
            }
        }
        hex
    }

    pub(super) fn sha1_hex(data: &[u8]) -> String {
        let mut state: [u32; 5] = [
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0xc3d2_e1f0,
        ];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for block in msg.as_chunks::<64>().0 {
            let mut w = [0u32; 80];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                let o = i * 4;
                *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = state;
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                    _ => (b ^ c ^ d, 0xca62_c1d6u32),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
        }
        let mut hex = String::with_capacity(40);
        for w in state {
            for b in w.to_be_bytes() {
                hex.push_str(&format!("{b:02x}"));
            }
        }
        hex
    }

    pub(super) fn parse_byte_range(req: &CapturedRequest, total: usize) -> Option<(usize, usize)> {
        let hdr = req.header("range")?;
        let spec = hdr.strip_prefix("bytes=")?;
        let (s_str, e_str) = spec.split_once('-')?;
        let start: usize = s_str.parse().ok()?;
        let end = if e_str.is_empty() {
            total.checked_sub(1)?
        } else {
            e_str.parse::<usize>().ok()?.min(total.saturating_sub(1))
        };
        (start <= end && start < total).then_some((start, end))
    }

    #[derive(Clone, Debug)]
    pub(super) struct DavMockFile {
        pub(super) data: Vec<u8>,
        pub(super) etag: String,
        pub(super) mtime_secs: i64,
        pub(super) oc_checksum: Option<String>,
    }

    #[derive(Clone, Debug)]
    pub(super) struct DavUploadSession {
        pub(super) chunks: BTreeMap<String, Vec<u8>>,
        pub(super) total_size: u64,
    }

    #[derive(Clone, Debug)]
    pub(super) struct ExtraPropResponse {
        pub(super) href: String,
        pub(super) is_dir: bool,
        pub(super) len: u64,
        pub(super) status_line: String,
        pub(super) add_404_propstat: bool,
    }

    pub(super) struct DavMockState {
        pub(super) base_path: String,
        pub(super) uploads_path: String,
        pub(super) files: BTreeMap<String, DavMockFile>,
        pub(super) dirs: BTreeSet<String>,
        pub(super) uploads: HashMap<String, DavUploadSession>,
        pub(super) quota: Option<(u64, u64)>,
        pub(super) require_trailing_slash: bool,
        pub(super) enforce_parent_dir_on_put: bool,
        pub(super) omit_etag: bool,
        pub(super) accept_oc_mtime: bool,
        pub(super) next_etag: usize,
        pub(super) corrupt_next_get_bytes: bool,
        pub(super) extra_propfind: HashMap<String, Vec<ExtraPropResponse>>,
        pub(super) scripted_by_method: HashMap<String, VecDeque<MockAction>>,
    }

    impl DavMockState {
        pub(super) fn new(base_path: &str, uploads_path: &str) -> Self {
            Self {
                base_path: base_path.trim_end_matches('/').to_string(),
                uploads_path: uploads_path.trim_end_matches('/').to_string(),
                files: BTreeMap::new(),
                dirs: BTreeSet::new(),
                uploads: HashMap::new(),
                quota: Some((900_000, 100_000)),
                require_trailing_slash: false,
                enforce_parent_dir_on_put: false,
                omit_etag: false,
                accept_oc_mtime: true,
                next_etag: 1,
                corrupt_next_get_bytes: false,
                extra_propfind: HashMap::new(),
                scripted_by_method: HashMap::new(),
            }
        }

        pub(super) fn next_etag(&mut self) -> String {
            let id = self.next_etag;
            self.next_etag += 1;
            format!("\"dav-etag-{id}\"")
        }

        pub(super) fn script_method(&mut self, method: &str, action: MockAction) {
            self.scripted_by_method
                .entry(method.to_string())
                .or_default()
                .push_back(action);
        }

        fn strip_base_rel(&self, raw_path: &str) -> Option<(String, bool)> {
            let has_slash = raw_path.ends_with('/');
            let decoded_path = percent_decode_strict(raw_path);
            let decoded_base = percent_decode_strict(&self.base_path);
            let trimmed_path = decoded_path.trim_end_matches('/');
            let trimmed_base = decoded_base.trim_end_matches('/');
            if trimmed_path == trimmed_base {
                return Some((String::new(), has_slash));
            }
            let rest = trimmed_path.strip_prefix(trimmed_base)?.strip_prefix('/')?;
            Some((rest.to_string(), has_slash))
        }

        fn strip_uploads_rel(&self, raw_path: &str) -> Option<String> {
            let decoded_path = percent_decode_strict(raw_path);
            let decoded_up = percent_decode_strict(&self.uploads_path);
            let trimmed_path = decoded_path.trim_end_matches('/');
            let trimmed_up = decoded_up.trim_end_matches('/');
            if trimmed_path == trimmed_up {
                return Some(String::new());
            }
            trimmed_path
                .strip_prefix(trimmed_up)?
                .strip_prefix('/')
                .map(ToOwned::to_owned)
        }

        fn destination_rel(&self, req: &CapturedRequest) -> Option<String> {
            let dest = req.header("destination")?;
            let path_part = if let Some(rest) = dest
                .strip_prefix("http://")
                .or_else(|| dest.strip_prefix("https://"))
            {
                rest.find('/').map(|i| &rest[i..])?
            } else {
                dest
            };
            self.strip_base_rel(path_part).map(|(rel, _)| rel)
        }

        fn href_for_rel(&self, rel: &str, is_dir: bool) -> String {
            let base = &self.base_path;
            if rel.is_empty() {
                format!("{base}/")
            } else if is_dir {
                format!("{base}/{}/", percent_encode_path(rel))
            } else {
                format!("{base}/{}", percent_encode_path(rel))
            }
        }

        fn render_prop_response(
            &self,
            href: &str,
            is_dir: bool,
            size: u64,
            etag: Option<&str>,
            quota: Option<(u64, u64)>,
        ) -> String {
            let rt = if is_dir {
                "<d:resourcetype><d:collection/></d:resourcetype>"
            } else {
                "<d:resourcetype/>"
            };
            let len_xml = if is_dir {
                String::new()
            } else {
                format!("<d:getcontentlength>{size}</d:getcontentlength>")
            };
            let etag_xml = if let Some(e) = etag
                && !self.omit_etag
            {
                format!("<d:getetag>{}</d:getetag>", xml_escape(e))
            } else {
                String::new()
            };
            let quota_xml = if let Some((avail, used)) = quota {
                format!(
                    "<d:quota-available-bytes>{avail}</d:quota-available-bytes>\
                     <d:quota-used-bytes>{used}</d:quota-used-bytes>"
                )
            } else {
                String::new()
            };
            format!(
                "<d:response><d:href>{}</d:href><d:propstat><d:prop>\
                 {rt}{len_xml}<d:getlastmodified>Wed, 25 Nov 2026 12:00:00 GMT</d:getlastmodified>\
                 {etag_xml}{quota_xml}\
                 </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                xml_escape(href)
            )
        }

        fn ensure_parents(&mut self, rel: &str) {
            let mut acc = String::new();
            let parts: Vec<&str> = rel.split('/').collect();
            for seg in parts.iter().take(parts.len().saturating_sub(1)) {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(seg);
                self.dirs.insert(acc.clone());
            }
        }
    }

    pub(super) async fn start_dav_mock(
        base_path: &str,
        uploads_path: &str,
    ) -> (MockHttpServer, Arc<Mutex<DavMockState>>) {
        let state = Arc::new(Mutex::new(DavMockState::new(base_path, uploads_path)));
        let st_c = state.clone();
        let srv = MockHttpServer::start_with_handler(move |req| {
            let mut st = st_c.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(q) = st.scripted_by_method.get_mut(&req.method)
                && let Some(action) = q.pop_front()
            {
                return action;
            }

            // Uploads tree (`/remote.php/dav/uploads/<user>/...` or `/dav/uploads/<user>/...`)
            if let Some(up_rel) = st.strip_uploads_rel(&req.path) {
                return handle_uploads(&mut st, req, &up_rel);
            }

            // Files tree
            let Some((rel, has_slash)) = st.strip_base_rel(&req.path) else {
                return MockAction::Respond(MockResponse::empty(404));
            };

            match req.method.as_str() {
                "PROPFIND" => handle_propfind(&st, req, &rel, has_slash),
                "MKCOL" => {
                    if st.require_trailing_slash && !has_slash {
                        return MockAction::Respond(MockResponse::empty(409));
                    }
                    if st.files.contains_key(&rel) {
                        return MockAction::Respond(MockResponse::empty(405));
                    }
                    if st.dirs.contains(&rel) {
                        return MockAction::Respond(MockResponse::empty(405));
                    }
                    st.ensure_parents(&rel);
                    st.dirs.insert(rel);
                    MockAction::Respond(MockResponse::empty(201))
                }
                "PUT" => {
                    if rel.is_empty() || st.dirs.contains(&rel) {
                        return MockAction::Respond(MockResponse::empty(409));
                    }
                    if st.enforce_parent_dir_on_put
                        && let Some((parent, _)) = rel.rsplit_once('/')
                        && !st.dirs.contains(parent)
                    {
                        return MockAction::Respond(MockResponse::empty(409));
                    }
                    let etag = st.next_etag();
                    let mtime_secs = req
                        .header("x-oc-mtime")
                        .and_then(|v| v.parse::<i64>().ok())
                        .unwrap_or(1_700_000_000);
                    let oc_checksum = req.header("oc-checksum").map(ToOwned::to_owned);
                    let x_hash_md5 =
                        (req.header("x-hash") == Some("md5")).then(|| md5_hex(&req.body));
                    st.files.insert(
                        rel,
                        DavMockFile {
                            data: req.body.clone(),
                            etag: etag.clone(),
                            mtime_secs,
                            oc_checksum,
                        },
                    );
                    let mut resp = MockResponse::empty(201);
                    if !st.omit_etag {
                        resp = resp.with_header("ETag", etag);
                    }
                    if let Some(md5) = x_hash_md5 {
                        resp = resp.with_header("X-Hash-MD5", md5);
                    }
                    if st.accept_oc_mtime && req.header("x-oc-mtime").is_some() {
                        resp = resp.with_header("X-OC-Mtime", "accepted");
                    }
                    MockAction::Respond(resp)
                }
                "GET" => {
                    let Some(file) = st.files.get(&rel).cloned() else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    let mut payload = file.data.clone();
                    if st.corrupt_next_get_bytes {
                        st.corrupt_next_get_bytes = false;
                        if let Some(first) = payload.first_mut() {
                            *first ^= 0xff;
                        }
                    }
                    if let Some(_rh) = req.header("range") {
                        let Some((s, e)) = parse_byte_range(req, file.data.len()) else {
                            return MockAction::Respond(MockResponse::empty(416));
                        };
                        let is_full = s == 0 && e + 1 == file.data.len();
                        let slice = payload[s..=e].to_vec();
                        let mut resp = MockResponse::new(206, slice)
                            .with_header("ETag", file.etag)
                            .with_header(
                                "Content-Range",
                                format!("bytes {s}-{e}/{}", file.data.len()),
                            );
                        if is_full && let Some(ck) = file.oc_checksum {
                            resp = resp.with_header("OC-Checksum", ck);
                        }
                        return MockAction::Respond(resp);
                    }
                    let _ = req.header("range");
                    let mut resp = MockResponse::ok(payload).with_header("ETag", file.etag);
                    if let Some(ck) = file.oc_checksum {
                        resp = resp.with_header("OC-Checksum", ck);
                    }
                    MockAction::Respond(resp)
                }
                "DELETE" => {
                    if st.files.remove(&rel).is_some() {
                        return MockAction::Respond(MockResponse::empty(204));
                    }
                    if st.dirs.contains(&rel) {
                        if st.require_trailing_slash && !has_slash {
                            return MockAction::Respond(MockResponse::empty(409));
                        }
                        st.dirs.remove(&rel);
                        let prefix = format!("{rel}/");
                        st.dirs.retain(|d| !d.starts_with(&prefix));
                        st.files.retain(|k, _| !k.starts_with(&prefix));
                        return MockAction::Respond(MockResponse::empty(204));
                    }
                    MockAction::Respond(MockResponse::empty(404))
                }
                "COPY" => {
                    let Some(dst_rel) = st.destination_rel(req) else {
                        return MockAction::Respond(MockResponse::empty(400));
                    };
                    if st.enforce_parent_dir_on_put
                        && let Some((parent, _)) = dst_rel.rsplit_once('/')
                        && !st.dirs.contains(parent)
                    {
                        return MockAction::Respond(MockResponse::empty(409));
                    }
                    if req.header("overwrite") == Some("F") && st.files.contains_key(&dst_rel) {
                        return MockAction::Respond(MockResponse::empty(412));
                    }
                    let Some(src) = st.files.get(&rel).cloned() else {
                        return MockAction::Respond(MockResponse::empty(404));
                    };
                    let etag = st.next_etag();
                    st.files.insert(
                        dst_rel,
                        DavMockFile {
                            data: src.data,
                            etag: etag.clone(),
                            mtime_secs: src.mtime_secs,
                            oc_checksum: src.oc_checksum,
                        },
                    );
                    let mut resp = MockResponse::empty(201);
                    if !st.omit_etag {
                        resp = resp.with_header("ETag", etag);
                    }
                    MockAction::Respond(resp)
                }
                "MOVE" => {
                    let Some(dst_rel) = st.destination_rel(req) else {
                        return MockAction::Respond(MockResponse::empty(400));
                    };
                    if req.header("overwrite") == Some("F") && st.files.contains_key(&dst_rel) {
                        return MockAction::Respond(MockResponse::empty(412));
                    }
                    if let Some(mut src) = st.files.remove(&rel) {
                        src.etag = st.next_etag();
                        let etag = src.etag.clone();
                        st.files.insert(dst_rel, src);
                        let mut resp = MockResponse::empty(201);
                        if !st.omit_etag {
                            resp = resp.with_header("ETag", etag);
                        }
                        return MockAction::Respond(resp);
                    }
                    if st.dirs.remove(&rel) {
                        let old_prefix = format!("{rel}/");
                        let new_prefix = format!("{dst_rel}/");
                        st.dirs.insert(dst_rel);
                        let moved_dirs: Vec<String> = st
                            .dirs
                            .iter()
                            .filter(|d| d.starts_with(&old_prefix))
                            .cloned()
                            .collect();
                        for d in moved_dirs {
                            st.dirs.remove(&d);
                            if let Some(tail) = d.strip_prefix(&old_prefix) {
                                st.dirs.insert(format!("{new_prefix}{tail}"));
                            }
                        }
                        let moved_files: Vec<(String, DavMockFile)> = st
                            .files
                            .iter()
                            .filter(|(k, _)| k.starts_with(&old_prefix))
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        for (k, v) in moved_files {
                            st.files.remove(&k);
                            if let Some(tail) = k.strip_prefix(&old_prefix) {
                                st.files.insert(format!("{new_prefix}{tail}"), v);
                            }
                        }
                        return MockAction::Respond(MockResponse::empty(201));
                    }
                    MockAction::Respond(MockResponse::empty(404))
                }
                _ => MockAction::Respond(MockResponse::empty(405)),
            }
        })
        .await;
        (srv, state)
    }

    fn handle_propfind(
        st: &DavMockState,
        req: &CapturedRequest,
        rel: &str,
        has_slash: bool,
    ) -> MockAction {
        let depth = req.header("depth").unwrap_or("0");
        let is_dir = rel.is_empty() || st.dirs.contains(rel);
        if is_dir && st.require_trailing_slash && !has_slash {
            return MockAction::Respond(MockResponse::empty(409));
        }
        if !is_dir && !st.files.contains_key(rel) {
            return MockAction::Respond(MockResponse::empty(404));
        }

        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
        );
        if is_dir {
            let quota = if rel.is_empty() && req.body_text().contains("quota-available-bytes") {
                st.quota
            } else {
                None
            };
            body.push_str(&st.render_prop_response(
                &st.href_for_rel(rel, true),
                true,
                0,
                None,
                quota,
            ));
            if depth == "1" {
                let prefix = if rel.is_empty() {
                    String::new()
                } else {
                    format!("{rel}/")
                };
                for d in &st.dirs {
                    if let Some(rest) = d.strip_prefix(&prefix)
                        && !rest.is_empty()
                        && !rest.contains('/')
                    {
                        body.push_str(&st.render_prop_response(
                            &st.href_for_rel(d, true),
                            true,
                            0,
                            None,
                            None,
                        ));
                    }
                }
                for (k, f) in &st.files {
                    if let Some(rest) = k.strip_prefix(&prefix)
                        && !rest.is_empty()
                        && !rest.contains('/')
                    {
                        body.push_str(&st.render_prop_response(
                            &st.href_for_rel(k, false),
                            false,
                            f.data.len() as u64,
                            Some(&f.etag),
                            None,
                        ));
                    }
                }
                if let Some(extras) = st.extra_propfind.get(rel) {
                    for ex in extras {
                        let rt = if ex.is_dir {
                            "<d:resourcetype><d:collection/></d:resourcetype>"
                        } else {
                            "<d:resourcetype/>"
                        };
                        let extra_ps = if ex.add_404_propstat {
                            "<d:propstat><d:prop><d:getcontentlength/></d:prop>\
                             <d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
                        } else {
                            ""
                        };
                        body.push_str(&format!(
                            "<d:response><d:href>{}</d:href><d:propstat><d:prop>\
                             {rt}<d:getcontentlength>{}</d:getcontentlength>\
                             </d:prop><d:status>{}</d:status></d:propstat>{extra_ps}</d:response>",
                            xml_escape(&ex.href),
                            ex.len,
                            xml_escape(&ex.status_line)
                        ));
                    }
                }
            }
        } else if let Some(f) = st.files.get(rel) {
            body.push_str(&st.render_prop_response(
                &st.href_for_rel(rel, false),
                false,
                f.data.len() as u64,
                Some(&f.etag),
                None,
            ));
        }
        body.push_str("</d:multistatus>");
        MockAction::Respond(
            MockResponse::new(207, body.into_bytes())
                .with_header("Content-Type", "application/xml; charset=utf-8"),
        )
    }

    fn handle_uploads(st: &mut DavMockState, req: &CapturedRequest, up_rel: &str) -> MockAction {
        let has_slash = req.path.ends_with('/');
        let parts: Vec<&str> = up_rel.split('/').filter(|s| !s.is_empty()).collect();
        match (req.method.as_str(), parts.as_slice()) {
            ("MKCOL", [op_id]) => {
                if st.require_trailing_slash && !has_slash {
                    return MockAction::Respond(MockResponse::empty(409));
                }
                let total_size = req
                    .header("oc-total-length")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                st.uploads.insert(
                    (*op_id).to_string(),
                    DavUploadSession {
                        chunks: BTreeMap::new(),
                        total_size,
                    },
                );
                MockAction::Respond(MockResponse::empty(201))
            }
            ("PROPFIND", [op_id]) => {
                let Some(sess) = st.uploads.get(*op_id) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                let depth = req.header("depth").unwrap_or("0");
                let mut body = String::from(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
                );
                let dir_href = format!("{}/{op_id}/", st.uploads_path);
                body.push_str(&st.render_prop_response(&dir_href, true, 0, None, None));
                if depth == "1" {
                    for (name, bytes) in &sess.chunks {
                        let ch_href = format!("{}/{op_id}/{name}", st.uploads_path);
                        body.push_str(&st.render_prop_response(
                            &ch_href,
                            false,
                            bytes.len() as u64,
                            None,
                            None,
                        ));
                    }
                }
                body.push_str("</d:multistatus>");
                MockAction::Respond(
                    MockResponse::new(207, body.into_bytes())
                        .with_header("Content-Type", "application/xml; charset=utf-8"),
                )
            }
            ("PUT", [op_id, chunk_name]) => {
                let Some(sess) = st.uploads.get_mut(*op_id) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                sess.chunks
                    .insert((*chunk_name).to_string(), req.body.clone());
                let etag = format!("\"chunk-{chunk_name}\"");
                let mut resp = MockResponse::empty(201).with_header("ETag", etag);
                if req.header("x-hash") == Some("md5") {
                    resp = resp.with_header("X-Hash-MD5", md5_hex(&req.body));
                }
                MockAction::Respond(resp)
            }
            ("MOVE", [op_id, ".file"]) => {
                let Some(dst_rel) = st.destination_rel(req) else {
                    return MockAction::Respond(MockResponse::empty(400));
                };
                if st.enforce_parent_dir_on_put
                    && let Some((parent, _)) = dst_rel.rsplit_once('/')
                    && !st.dirs.contains(parent)
                {
                    return MockAction::Respond(MockResponse::empty(409));
                }
                if req.header("overwrite") == Some("F") && st.files.contains_key(&dst_rel) {
                    return MockAction::Respond(MockResponse::empty(412));
                }
                let Some(sess) = st.uploads.remove(*op_id) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                let mut entries: Vec<(String, Vec<u8>)> = sess.chunks.into_iter().collect();
                entries.sort_by(
                    |(a, _), (b, _)| match (a.parse::<u32>(), b.parse::<u32>()) {
                        (Ok(na), Ok(nb)) => na.cmp(&nb),
                        _ => a.cmp(b),
                    },
                );
                let mut assembled = Vec::new();
                for (_, bytes) in entries {
                    assembled.extend_from_slice(&bytes);
                }
                if sess.total_size > 0 && assembled.len() as u64 != sess.total_size {
                    return MockAction::Respond(MockResponse::empty(400));
                }
                let etag = st.next_etag();
                let mtime_secs = req
                    .header("x-oc-mtime")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(1_700_000_000);
                let oc_checksum = req.header("oc-checksum").map(ToOwned::to_owned);
                st.files.insert(
                    dst_rel,
                    DavMockFile {
                        data: assembled,
                        etag: etag.clone(),
                        mtime_secs,
                        oc_checksum,
                    },
                );
                let mut resp = MockResponse::empty(201);
                if !st.omit_etag {
                    resp = resp.with_header("ETag", etag);
                }
                if st.accept_oc_mtime && req.header("x-oc-mtime").is_some() {
                    resp = resp.with_header("X-OC-Mtime", "accepted");
                }
                MockAction::Respond(resp)
            }
            ("DELETE", [op_id]) => {
                if st.require_trailing_slash && !has_slash {
                    return MockAction::Respond(MockResponse::empty(409));
                }
                st.uploads.remove(*op_id);
                MockAction::Respond(MockResponse::empty(204))
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        }
    }

    pub(super) fn nextcloud_client(srv: &MockHttpServer, user: &str, pass: &str) -> RshipClient {
        RshipClient::builder()
            .ephemeral()
            .remote(
                "dav",
                WebdavRemoteConfig::new(srv.url(&format!("/remote.php/dav/files/{user}")))
                    .with_vendor("nextcloud")
                    .with_basic_auth(user, pass),
            )
            .build()
            .expect("build nextcloud RshipClient")
    }

    pub(super) fn nextcloud_cfg(srv: &MockHttpServer, user: &str, pass: &str) -> WebdavConfig {
        let mut cfg = WebdavConfig::new("dav", srv.url(&format!("/remote.php/dav/files/{user}")));
        cfg.vendor = WebdavVendor::Nextcloud;
        cfg.auth = WebdavAuth::Basic {
            username: user.to_string(),
            password: pass.to_string(),
        };
        cfg.base_retry_delay = std::time::Duration::from_millis(5);
        cfg.max_retry_delay = std::time::Duration::from_millis(20);
        cfg
    }
}

#[cfg(feature = "sftp")]
mod sftp_helpers {
    use futures::StreamExt;
    use rship::backends::sftp::{SftpAuth, SftpBackend, SftpConfig};
    use rship::core::backend::EntryStream;
    use rship::core::types::Entry;
    use rship::prelude::*;

    pub(super) async fn collect_entries(mut stream: EntryStream) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            out.push(item?);
        }
        Ok(out)
    }

    pub(super) fn sftp_backend_with_root(host: &str, port: u16, root_path: &str) -> SftpBackend {
        let mut cfg = SftpConfig::new("sf", host, "alice", SftpAuth::Password("pw".to_string()));
        cfg.port = port;
        cfg.root_path = root_path.to_string();
        SftpBackend::new(cfg).expect("SftpBackend::new")
    }
}

// ===========================================================================
// Feature Area #11: WebDAV (`#[cfg(feature = "webdav")]`) — 6 Tier 1 + 8 Tier 2
// ===========================================================================

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_single_shot_put_stat_list_open_read_range_and_delete() {
    use rship::core::backend::{BackendPath, ListOptions};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use rship::core::types::{ByteRange, EntryKind};
    use webdav_helpers::*;

    let (srv, _state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let client = nextcloud_client(&srv, "alice", "secret");
    let (backend, _) = client.resolve("dav:").expect("resolve root");

    client.mkdir("dav:docs/sub").await.expect("mkdir");
    let payload = b"webdav tier1 payload 0123456789abcdef".to_vec();
    let init = make_upload_init(
        "op-wd-t1-1",
        RelPath::parse("docs/sub/hello.txt").unwrap(),
        payload.len() as u64,
        64 * 1024,
        DstPrecondition::Absent,
    );
    let committed = backend
        .put_single_shot(&init, make_byte_stream(payload.clone()))
        .await
        .expect("put_single_shot");
    assert_eq!(committed.size, payload.len() as u64);

    let st = client
        .stat("dav:docs/sub/hello.txt")
        .await
        .expect("stat")
        .expect("exists");
    assert_eq!(st.kind, EntryKind::File);
    assert_eq!(st.size, payload.len() as u64);

    let shallow = collect_entries(
        client
            .list("dav:", &ListOptions::shallow())
            .await
            .expect("list shallow"),
    )
    .await
    .expect("collect shallow");
    assert_eq!(shallow.len(), 1);
    assert_eq!(shallow[0].nfc_path.as_str(), "docs");

    let recursive = collect_entries(
        client
            .list("dav:", &ListOptions::recursive())
            .await
            .expect("list recursive"),
    )
    .await
    .expect("collect recursive");
    assert!(
        recursive
            .iter()
            .any(|e| e.nfc_path.as_str() == "docs/sub/hello.txt" && e.kind == EntryKind::File)
    );

    let full = read_all_from_source(
        client
            .open_read("dav:docs/sub/hello.txt", None)
            .await
            .expect("open_read full"),
    )
    .await
    .expect("read full");
    assert_eq!(full, payload);

    let partial = read_range_from_source(
        backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("docs/sub/hello.txt").unwrap()),
                None,
            )
            .await
            .expect("open_read range"),
        ByteRange { offset: 7, len: 12 },
    )
    .await
    .expect("read partial");
    assert_eq!(partial, &payload[7..19]);

    client
        .delete("dav:docs/sub/hello.txt")
        .await
        .expect("delete");
    assert!(
        client
            .stat("dav:docs/sub/hello.txt")
            .await
            .expect("stat after delete")
            .is_none()
    );

    let expected_auth = format!("Basic {}", base64_encode(b"alice:secret"));
    let reqs = srv.requests();
    assert!(!reqs.is_empty());
    assert!(
        reqs.iter()
            .all(|r| r.header("authorization") == Some(expected_auth.as_str()))
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_server_side_copy_and_rename_roundtrip() {
    use rship::core::backend::BackendPath;
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, _state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let client = nextcloud_client(&srv, "alice", "secret");
    let (backend, _) = client.resolve("dav:").expect("resolve");

    let data = b"copy-and-rename-bytes".to_vec();
    let init_src = make_upload_init(
        "op-wd-t1-cp-src",
        RelPath::parse("src.txt").unwrap(),
        data.len() as u64,
        64 * 1024,
        DstPrecondition::Absent,
    );
    backend
        .put_single_shot(&init_src, make_byte_stream(data.clone()))
        .await
        .expect("put src");

    let cp_init = make_upload_init(
        "op-wd-t1-cp",
        RelPath::parse("copied.txt").unwrap(),
        data.len() as u64,
        64 * 1024,
        DstPrecondition::Absent,
    );
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
            &cp_init,
        )
        .await
        .expect("server_side_copy")
        .expect("Some(entry)");
    assert_eq!(copied.nfc_path.as_str(), "copied.txt");
    assert_eq!(copied.size, data.len() as u64);

    let renamed = client
        .rename("dav:copied.txt", "renamed.txt")
        .await
        .expect("rename");
    assert_eq!(renamed.nfc_path.as_str(), "renamed.txt");
    assert!(client.stat("dav:copied.txt").await.unwrap().is_none());

    let got = read_all_from_source(client.open_read("dav:renamed.txt", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, data);

    let reqs = srv.requests();
    let copy_req = reqs.iter().find(|r| r.method == "COPY").expect("COPY");
    assert!(
        copy_req
            .header("destination")
            .unwrap()
            .ends_with("/copied.txt")
    );
    let move_req = reqs.iter().find(|r| r.method == "MOVE").expect("MOVE");
    assert!(
        move_req
            .header("destination")
            .unwrap()
            .ends_with("/renamed.txt")
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_nextcloud_chunked_v2_upload_and_query_resume() {
    use rship::core::backend::{ChunkUpload, CompletedPart, StorageBackend, UploadProgress};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use rship::prelude::*;
    use webdav_helpers::*;

    let (srv, _state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let mut cfg = nextcloud_cfg(&srv, "alice", "secret");
    cfg.single_shot_max_bytes = Some(64 * 1024);
    cfg.default_chunk_size = Some(64 * 1024);
    let backend = make_webdav_backend(cfg);

    let c1 = vec![0x11u8; 64 * 1024];
    let c2 = vec![0x22u8; 10 * 1024];
    let mut full = Vec::new();
    full.extend_from_slice(&c1);
    full.extend_from_slice(&c2);

    let init = make_upload_init(
        "op-nc-t1-chunked",
        RelPath::parse("big/archive.bin").unwrap(),
        full.len() as u64,
        64 * 1024,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    let mut op = make_op_record(
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        sess.remote_op_id.clone(),
    );

    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                c1.len() as u64,
                full.len() as u64,
                make_byte_stream(c1.clone()),
            ),
        )
        .await
        .expect("upload chunk 1");
    assert_eq!(ack1.next_offset, Some(c1.len() as u64));

    let prog = backend.query_upload(&op).await.expect("query_upload");
    assert_eq!(prog, UploadProgress::SequentialOffset(c1.len() as u64));
    op.confirmed_offset = c1.len() as u64;

    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                c1.len() as u64,
                c2.len() as u64,
                full.len() as u64,
                make_byte_stream(c2.clone()),
            ),
        )
        .await
        .expect("upload chunk 2");
    assert_eq!(ack2.next_offset, Some(full.len() as u64));

    let entry = backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: c1.len() as u64,
                    etag: ack1.etag.unwrap_or_default(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 2,
                    offset: c1.len() as u64,
                    length: c2.len() as u64,
                    etag: ack2.etag.unwrap_or_default(),
                    checksum: None,
                },
            ],
        )
        .await
        .expect("finish_upload");
    assert_eq!(entry.size, full.len() as u64);

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend("dav", backend)
        .build()
        .unwrap();
    let got = read_all_from_source(client.open_read("dav:big/archive.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, full);

    let reqs = srv.requests();
    assert!(reqs.iter().any(
        |r| r.method == "MKCOL" && r.path == "/remote.php/dav/uploads/alice/op-nc-t1-chunked/"
    ));
    assert!(
        reqs.iter().any(|r| r.method == "MOVE"
            && r.path == "/remote.php/dav/uploads/alice/op-nc-t1-chunked/.file")
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_about_quota_and_capabilities() {
    use rship::backends::webdav::{WebdavConfig, WebdavVendor};
    use rship::core::backend::StorageBackend;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    state.lock().unwrap().quota = Some((750_000, 250_000));

    let nc = make_webdav_backend(nextcloud_cfg(&srv, "alice", "secret"));
    let quota = nc.about().await.expect("about").expect("Some(quota)");
    assert_eq!(quota.free_bytes, Some(750_000));
    assert_eq!(quota.used_bytes, Some(250_000));
    assert_eq!(quota.total_bytes, Some(1_000_000));

    let nc_caps = nc.capabilities();
    assert!(nc_caps.can_set_mtime);
    assert!(nc_caps.supports_range_read);
    assert!(nc_caps.supports_server_side_copy);
    assert!(nc_caps.hashes.is_empty());

    let mut gen_cfg = WebdavConfig::new("generic", srv.url("/remote.php/dav/files/alice"));
    gen_cfg.vendor = WebdavVendor::Generic;
    let generic_backend = make_webdav_backend(gen_cfg);
    let gen_caps = generic_backend.capabilities();
    assert!(!gen_caps.can_set_mtime);
    assert!(gen_caps.hashes.is_empty());
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_abort_upload_and_missing_object_not_found() {
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let backend = make_webdav_backend(nextcloud_cfg(&srv, "alice", "secret"));

    let init = make_upload_init(
        "op-abort-1",
        RelPath::parse("aborted.bin").unwrap(),
        1024,
        512,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    assert!(state.lock().unwrap().uploads.contains_key("op-abort-1"));
    let op = make_op_record(
        &init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );
    backend.abort_upload(&op).await.expect("abort_upload");
    assert!(!state.lock().unwrap().uploads.contains_key("op-abort-1"));
    assert!(srv.requests().iter().any(|r| {
        r.method == "DELETE" && r.path == "/remote.php/dav/uploads/alice/op-abort-1/"
    }));

    let missing = BackendPath::from_rel(RelPath::parse("does/not/exist.txt").unwrap());
    assert!(backend.stat(&missing).await.expect("stat").is_none());
    let Err(read_err) = backend.open_read(&missing, None).await else {
        panic!("expected NotFound");
    };
    assert_eq!(read_err.kind(), ErrorKind::NotFound);

    for bad_name in ["a/b", "..", ".", ""] {
        let ren_err = backend
            .rename(
                &BackendPath::from_rel(RelPath::parse("file.txt").unwrap()),
                bad_name,
            )
            .await
            .expect_err("invalid rename name");
        assert_eq!(ren_err.kind(), ErrorKind::InvalidPath);
    }
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier1_webdav_rclone_import_and_obscured_pass_via_factory() {
    use rship::core::rclone_ini::obscure_rclone_secret_with_iv;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;
    use webdav_helpers::*;

    let (srv, _state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let iv = [0x11u8; 16];
    let obscured = obscure_rclone_secret_with_iv("s3cr3t-p@ss", iv);
    let conf = format!(
        "[nc_basic]\n\
         type = webdav\n\
         url = {url}\n\
         vendor = nextcloud\n\
         user = alice\n\
         pass = {obscured}\n\
         \n\
         [nc_bearer]\n\
         type = webdav\n\
         url = {url}\n\
         vendor = nextcloud\n\
         bearer_token = tok-bearer-99\n",
        url = srv.url("/remote.php/dav/files/alice"),
    );

    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let mut app_cfg = AppConfig::new();
    let rep = import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).expect("import");
    assert_eq!(rep.imported.len(), 2);

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .expect("build client");

    assert!(client.stat("nc_basic:missing").await.unwrap().is_none());
    assert!(client.stat("nc_bearer:missing").await.unwrap().is_none());

    let reqs = srv.requests();
    let expected_basic = format!("Basic {}", base64_encode(b"alice:s3cr3t-p@ss"));
    assert!(
        reqs.iter()
            .any(|r| r.header("authorization") == Some(expected_basic.as_str()))
    );
    assert!(
        reqs.iter()
            .any(|r| r.header("authorization") == Some("Bearer tok-bearer-99"))
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_207_multistatus_partial_failure_and_423_locked_retry() {
    use crate::mock_http::{MockAction, MockResponse};
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, ChunkUpload, CompletedPart, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let mut cfg = nextcloud_cfg(&srv, "alice", "secret");
    cfg.max_retries = 2;
    let backend = make_webdav_backend(cfg.clone());

    let init = make_upload_init(
        "op-207-src",
        RelPath::parse("src.txt").unwrap(),
        5,
        1024,
        DstPrecondition::Absent,
    );
    backend
        .put_single_shot(&init, make_byte_stream(b"hello".to_vec()))
        .await
        .expect("seed src.txt");

    let ms_403 = |href: &str| {
        MockAction::Respond(
            MockResponse::new(
                207,
                format!(
                    "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                     <d:response><d:href>{href}</d:href>\
                     <d:status>HTTP/1.1 403 Forbidden</d:status></d:response></d:multistatus>"
                )
                .into_bytes(),
            )
            .with_header("Content-Type", "application/xml"),
        )
    };
    let ms_423 = |href: &str| {
        MockAction::Respond(
            MockResponse::new(
                207,
                format!(
                    "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                     <d:response><d:href>{href}</d:href>\
                     <d:status>HTTP/1.1 423 Locked</d:status></d:response></d:multistatus>"
                )
                .into_bytes(),
            )
            .with_header("Content-Type", "application/xml"),
        )
    };

    // 207 with 403 Forbidden must fail with PermissionDenied across COPY, MOVE(rename), DELETE, MOVE(.file)
    state
        .lock()
        .unwrap()
        .script_method("COPY", ms_403("/remote.php/dav/files/alice/cp.txt"));
    let cp_init = make_upload_init(
        "op-207-cp",
        RelPath::parse("cp.txt").unwrap(),
        5,
        1024,
        DstPrecondition::Any,
    );
    let err_cp = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
            &cp_init,
        )
        .await
        .expect_err("COPY 207 403 must fail");
    assert_eq!(err_cp.kind(), ErrorKind::PermissionDenied);

    state
        .lock()
        .unwrap()
        .script_method("MOVE", ms_403("/remote.php/dav/files/alice/ren.txt"));
    let err_mv = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
            "ren.txt",
        )
        .await
        .expect_err("MOVE rename 207 403 must fail");
    assert_eq!(err_mv.kind(), ErrorKind::PermissionDenied);

    state
        .lock()
        .unwrap()
        .script_method("DELETE", ms_403("/remote.php/dav/files/alice/src.txt"));
    let err_del = backend
        .delete(&BackendPath::from_rel(RelPath::parse("src.txt").unwrap()))
        .await
        .expect_err("DELETE 207 403 must fail");
    assert_eq!(err_del.kind(), ErrorKind::PermissionDenied);

    // Chunked MOVE .file 207 with 403 -> PermissionDenied
    let up_init = make_upload_init(
        "op-207-up",
        RelPath::parse("chunked.bin").unwrap(),
        10,
        10,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&up_init).await.unwrap();
    let op = make_op_record(
        &up_init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, 10, 10, make_byte_stream(vec![9u8; 10])),
        )
        .await
        .unwrap();
    state
        .lock()
        .unwrap()
        .script_method("MOVE", ms_403("/remote.php/dav/files/alice/chunked.bin"));
    let err_fin = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 10,
                etag: ack.etag.clone().unwrap_or_default(),
                checksum: None,
            }],
        )
        .await
        .expect_err("MOVE .file 207 403 must fail");
    assert_eq!(err_fin.kind(), ErrorKind::PermissionDenied);

    // 207 with 423 Locked and HTTP 423 retry and succeed; max_retries=0 surfaces LockBusy
    state
        .lock()
        .unwrap()
        .script_method("MOVE", ms_423("/remote.php/dav/files/alice/chunked.bin"));
    let finished = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 10,
                etag: ack.etag.unwrap_or_default(),
                checksum: None,
            }],
        )
        .await
        .expect("207 423 must retry and succeed");
    assert_eq!(finished.size, 10);

    state
        .lock()
        .unwrap()
        .script_method("DELETE", MockAction::Respond(MockResponse::empty(423)));
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("chunked.bin").unwrap(),
        ))
        .await
        .expect("HTTP 423 must retry and succeed");

    let mut no_retry_cfg = cfg;
    no_retry_cfg.max_retries = 0;
    let no_retry_backend = make_webdav_backend(no_retry_cfg);
    state
        .lock()
        .unwrap()
        .script_method("DELETE", MockAction::Respond(MockResponse::empty(423)));
    let lock_err = no_retry_backend
        .delete(&BackendPath::from_rel(RelPath::parse("src.txt").unwrap()))
        .await
        .expect_err("max_retries=0 423 must fail with LockBusy");
    assert_eq!(lock_err.kind(), ErrorKind::LockBusy);
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_finish_upload_reconcile_rejects_stale_same_size_and_retries_precommit() {
    use crate::mock_http::{MockAction, MockResponse};
    use rship::core::backend::{ChunkUpload, CompletedPart, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let mut cfg = nextcloud_cfg(&srv, "alice", "secret");
    cfg.max_retries = 2;
    let backend = make_webdav_backend(cfg);

    // Seed pre-existing same-size file at destination.
    let old_data = b"OLD_PAYLOAD_16BB".to_vec();
    let new_data = b"NEW_PAYLOAD_16BB".to_vec();
    let seed_init = make_upload_init(
        "op-seed-stale",
        RelPath::parse("target.bin").unwrap(),
        old_data.len() as u64,
        1024,
        DstPrecondition::Absent,
    );
    let old_entry = backend
        .put_single_shot(&seed_init, make_byte_stream(old_data.clone()))
        .await
        .expect("seed target.bin");

    // Case A: staging disappears while MOVE .file returns 503 AND destination still holds stale ETag -> MUST fail.
    let init_a = make_upload_init(
        "op-stale-fail",
        RelPath::parse("target.bin").unwrap(),
        new_data.len() as u64,
        new_data.len() as u64,
        DstPrecondition::Existing {
            size: old_entry.size,
            mtime_ns: old_entry.mtime_ns,
            etag: old_entry.etag.clone(),
            node_id: None,
        },
    );
    let sess_a = backend.begin_upload(&init_a).await.unwrap();
    let op_a = make_op_record(
        &init_a,
        Some(sess_a.session_token),
        sess_a.backend_meta,
        sess_a.remote_op_id,
    );
    let ack_a = backend
        .upload_chunk(
            &op_a,
            ChunkUpload::new(
                1,
                0,
                new_data.len() as u64,
                new_data.len() as u64,
                make_byte_stream(new_data.clone()),
            ),
        )
        .await
        .unwrap();
    {
        let mut st = state.lock().unwrap();
        st.uploads.remove("op-stale-fail");
        st.script_method("MOVE", MockAction::Respond(MockResponse::empty(503)));
    }
    let stale_err = backend
        .finish_upload(
            &op_a,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: new_data.len() as u64,
                etag: ack_a.etag.unwrap_or_default(),
                checksum: None,
            }],
        )
        .await
        .expect_err("stale same-size destination must NOT be falsely reconciled as committed");
    assert!(!stale_err.message().is_empty());

    // Case B: pre-commit 503 while staging STILL exists -> MUST retry and succeed with new data.
    let init_b = make_upload_init(
        "op-precommit-ok",
        RelPath::parse("target.bin").unwrap(),
        new_data.len() as u64,
        new_data.len() as u64,
        DstPrecondition::Any,
    );
    let sess_b = backend.begin_upload(&init_b).await.unwrap();
    let op_b = make_op_record(
        &init_b,
        Some(sess_b.session_token),
        sess_b.backend_meta,
        sess_b.remote_op_id,
    );
    let ack_b = backend
        .upload_chunk(
            &op_b,
            ChunkUpload::new(
                1,
                0,
                new_data.len() as u64,
                new_data.len() as u64,
                make_byte_stream(new_data.clone()),
            ),
        )
        .await
        .unwrap();
    state
        .lock()
        .unwrap()
        .script_method("MOVE", MockAction::Respond(MockResponse::empty(503)));
    let committed = backend
        .finish_upload(
            &op_b,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: new_data.len() as u64,
                etag: ack_b.etag.unwrap_or_default(),
                checksum: None,
            }],
        )
        .await
        .expect("pre-commit 503 with staging intact must retry and succeed");
    assert_eq!(committed.size, new_data.len() as u64);
    assert_eq!(
        state.lock().unwrap().files.get("target.bin").unwrap().data,
        new_data
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_query_upload_ignores_zero_byte_chunks() {
    use rship::backends::webdav::WebdavVendor;
    use rship::core::backend::{StorageBackend, UploadProgress};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;

    // Nextcloud numeric part `1` with 0 bytes
    let nc = make_webdav_backend(nextcloud_cfg(&srv, "alice", "secret"));
    let init_nc = make_upload_init(
        "op-zero-nc",
        RelPath::parse("zero-nc.bin").unwrap(),
        16_384,
        8_192,
        DstPrecondition::Absent,
    );
    let sess_nc = nc.begin_upload(&init_nc).await.unwrap();
    state
        .lock()
        .unwrap()
        .uploads
        .get_mut("op-zero-nc")
        .unwrap()
        .chunks
        .insert("1".to_string(), Vec::new());
    let op_nc = make_op_record(
        &init_nc,
        Some(sess_nc.session_token),
        sess_nc.backend_meta,
        sess_nc.remote_op_id,
    );
    assert_eq!(
        nc.query_upload(&op_nc).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );

    // ownCloud byte-range `0000000000000000-0000000000008192` with 0 bytes
    let mut oc_cfg = nextcloud_cfg(&srv, "alice", "secret");
    oc_cfg.vendor = WebdavVendor::Owncloud;
    let oc = make_webdav_backend(oc_cfg);
    let init_oc = make_upload_init(
        "op-zero-oc",
        RelPath::parse("zero-oc.bin").unwrap(),
        16_384,
        8_192,
        DstPrecondition::Absent,
    );
    let sess_oc = oc.begin_upload(&init_oc).await.unwrap();
    state
        .lock()
        .unwrap()
        .uploads
        .get_mut("op-zero-oc")
        .unwrap()
        .chunks
        .insert("0000000000000000-0000000000008192".to_string(), Vec::new());
    let op_oc = make_op_record(
        &init_oc,
        Some(sess_oc.session_token),
        sess_oc.backend_meta,
        sess_oc.remote_op_id,
    );
    assert_eq!(
        oc.query_upload(&op_oc).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_trailing_slash_and_no_redirect_downgrade_or_cross_origin_leak() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, ListOptions, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    state.lock().unwrap().require_trailing_slash = true;

    let mut cfg = nextcloud_cfg(&srv, "alice", "secret");
    cfg.max_retries = 1;
    let backend = make_webdav_backend(cfg.clone());

    // Strict trailing slash on MKCOL, dir PROPFIND, PUT, and DELETE (with fresh backend having empty known_dirs & kind==None)
    backend
        .mkdir(&RelPath::parse("strictdir/nested").unwrap())
        .await
        .expect("mkdir trailing /");
    let items = collect_entries(
        backend
            .list_with_options(
                &RelPath::parse("strictdir").unwrap(),
                &ListOptions::shallow(),
            )
            .await
            .expect("list strictdir"),
    )
    .await
    .unwrap();
    assert_eq!(items.len(), 1);
    let fresh_backend = make_webdav_backend(cfg.clone());
    fresh_backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("strictdir/nested").unwrap(),
        ))
        .await
        .expect("fresh delete with kind==None must recover trailing /");

    // 301 / 302 same-origin redirect on MKCOL stays MKCOL (never downgraded to GET)
    let redir_target = srv.url("/remote.php/dav/files/alice/redir_final/");
    state.lock().unwrap().script_method(
        "MKCOL",
        MockAction::Respond(MockResponse::empty(301).with_header("Location", redir_target.clone())),
    );
    backend
        .mkdir(&RelPath::parse("redir_dir").unwrap())
        .await
        .expect("301 MKCOL");
    let mkcols: Vec<_> = srv
        .requests()
        .into_iter()
        .filter(|r| r.method == "MKCOL" && r.path.contains("redir_final"))
        .collect();
    assert_eq!(mkcols.len(), 1, "301 redirect must preserve MKCOL method");

    // 302 same-origin redirect on GET(Range) succeeds
    let data = b"redirect-range-payload".to_vec();
    backend
        .put_single_shot(
            &make_upload_init(
                "op-redir-get",
                RelPath::parse("rfile.txt").unwrap(),
                data.len() as u64,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(data.clone()),
        )
        .await
        .unwrap();
    state.lock().unwrap().script_method(
        "GET",
        MockAction::Respond(
            MockResponse::empty(302)
                .with_header("Location", srv.url("/remote.php/dav/files/alice/rfile.txt")),
        ),
    );
    let got = read_all_from_source(
        backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("rfile.txt").unwrap()),
                None,
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(got, data);

    // 302 cross-origin redirect -> ErrorKind::Protocol and 0 hits on foreign server
    let foreign =
        MockHttpServer::start_with_handler(|_| MockAction::Respond(MockResponse::empty(200))).await;
    state.lock().unwrap().script_method(
        "MKCOL",
        MockAction::Respond(
            MockResponse::empty(302).with_header("Location", foreign.url("/steal-creds")),
        ),
    );
    let cross_err = backend
        .mkdir(&RelPath::parse("xorigin").unwrap())
        .await
        .expect_err("cross-origin redirect must fail");
    assert_eq!(cross_err.kind(), ErrorKind::Protocol);
    assert_eq!(foreign.hit_count(), 0);

    // 303 See Other same-origin -> ErrorKind::Protocol
    state.lock().unwrap().script_method(
        "MKCOL",
        MockAction::Respond(MockResponse::empty(303).with_header("Location", redir_target)),
    );
    let see_other_err = backend
        .mkdir(&RelPath::parse("seeother").unwrap())
        .await
        .expect_err("303 See Other must fail");
    assert_eq!(see_other_err.kind(), ErrorKind::Protocol);
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_percent_encoded_destination_nfd_bfs_and_nfd_rename() {
    use rship::core::backend::{BackendPath, ListOptions, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice smith",
        "/remote.php/dav/uploads/alice%20smith",
    )
    .await;
    let mut cfg = nextcloud_cfg(&srv, "alice smith", "secret");
    cfg.url = srv.url("/remote.php/dav/files/alice%20smith");
    let backend = make_webdav_backend(cfg);

    let nfd_dir = "cafe\u{0301}/sub\u{0301}";
    let nfd_file = format!("{nfd_dir}/note file.txt");
    {
        let mut st = state.lock().unwrap();
        st.dirs.insert("cafe\u{0301}".to_string());
        st.dirs.insert(nfd_dir.to_string());
        st.files.insert(
            nfd_file.clone(),
            DavMockFile {
                data: b"nfd-content".to_vec(),
                etag: "\"e-nfd\"".to_string(),
                mtime_secs: 1_700_000_000,
                oc_checksum: None,
            },
        );
    }

    let entries = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &ListOptions::recursive())
            .await
            .expect("recursive list"),
    )
    .await
    .expect("collect");
    let leaf = entries
        .iter()
        .find(|e| e.nfc_path.as_str().ends_with("note file.txt"))
        .expect("NFD leaf must be listed");
    assert_eq!(leaf.raw_path.as_deref(), Some(nfd_file.as_str()));

    let leaf_bp = BackendPath::from_entry(leaf);
    let renamed = backend
        .rename(&leaf_bp, "renamed file.txt")
        .await
        .expect("NFD rename must succeed");
    assert!(renamed.nfc_path.as_str().ends_with("renamed file.txt"));

    let cp_init = make_upload_init(
        "op-enc-cp",
        RelPath::parse("copied file.txt").unwrap(),
        11,
        1024,
        DstPrecondition::Absent,
    );
    backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_entry(&renamed),
            &cp_init,
        )
        .await
        .expect("COPY with spaces");

    let reqs = srv.requests();
    let copy_dest = reqs
        .iter()
        .find(|r| r.method == "COPY")
        .and_then(|r| r.header("destination"))
        .expect("COPY Destination header");
    assert!(copy_dest.contains("alice%20smith"));
    assert!(copy_dest.contains("copied%20file.txt"));
    assert!(!copy_dest.contains(' '));
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_nextcloud_v2_numeric_parts_11_headers_and_ocis_root() {
    use rship::backends::webdav::{WebdavAuth, WebdavConfig, WebdavVendor};
    use rship::core::ErrorKind;
    use rship::core::backend::{
        BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadProgress,
    };
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    // Verify oCIS URL `/dav/files/<user>` auto-derives `/dav/uploads/<user>`
    let ocis_cfg = WebdavConfig {
        vendor: WebdavVendor::Nextcloud,
        ..WebdavConfig::new("ocis", "https://ocis.example/dav/files/alice%20smith/docs")
    };
    assert_eq!(
        ocis_cfg.resolve_chunked_upload_root().as_deref(),
        Some("https://ocis.example/dav/uploads/alice%20smith")
    );

    let (srv, _state) = start_dav_mock("/dav/files/alice", "/dav/uploads/alice").await;
    let mut cfg = WebdavConfig::new("ocis", srv.url("/dav/files/alice"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Bearer {
        token: "ocis-tok".to_string(),
    };
    cfg.single_shot_max_bytes = Some(1024);
    cfg.default_chunk_size = Some(1024);
    let backend = make_webdav_backend(cfg);

    let chunk_size = 1024usize;
    let total_size = 10 * chunk_size + 300;
    let payload: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();

    let init = make_upload_init(
        "op-nc-11",
        RelPath::parse("large/11parts.bin").unwrap(),
        total_size as u64,
        chunk_size as u64,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    assert!(sess.session_token.contains("/dav/uploads/alice/op-nc-11"));
    let op = make_op_record(
        &init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );

    // Part 0 must fail InvalidGeometry
    let bad_part = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(0, 0, 10, total_size as u64, make_byte_stream(vec![0u8; 10])),
        )
        .await
        .expect_err("part 0 must fail");
    assert_eq!(bad_part.kind(), ErrorKind::InvalidGeometry);

    let mut completed = Vec::new();
    for part_num in 1..=11u32 {
        let start = (part_num as usize - 1) * chunk_size;
        let end = (start + chunk_size).min(total_size);
        let slice = payload[start..end].to_vec();
        let ack = backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    part_num,
                    start as u64,
                    slice.len() as u64,
                    total_size as u64,
                    make_byte_stream(slice.clone()),
                ),
            )
            .await
            .expect("upload chunk");
        completed.push(CompletedPart {
            part_number: part_num,
            offset: start as u64,
            length: slice.len() as u64,
            etag: ack.etag.unwrap_or_default(),
            checksum: None,
        });
        if part_num == 10 {
            assert_eq!(
                backend.query_upload(&op).await.unwrap(),
                UploadProgress::SequentialOffset((10 * chunk_size) as u64)
            );
        }
    }
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(total_size as u64)
    );

    let entry = backend
        .finish_upload(&op, &completed)
        .await
        .expect("finish 11-part");
    assert_eq!(entry.size, total_size as u64);

    let got = read_all_from_source(
        backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("large/11parts.bin").unwrap()),
                None,
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(got, payload);

    let reqs = srv.requests();
    let mkcol = reqs
        .iter()
        .find(|r| r.method == "MKCOL" && r.path == "/dav/uploads/alice/op-nc-11/")
        .unwrap();
    assert!(mkcol.header("destination").is_some());
    assert_eq!(
        mkcol.header("oc-total-length"),
        Some(total_size.to_string().as_str())
    );
    for p in 1..=11 {
        let put = reqs
            .iter()
            .find(|r| r.method == "PUT" && r.path == format!("/dav/uploads/alice/op-nc-11/{p}"))
            .unwrap_or_else(|| panic!("missing numeric chunk PUT /{p}"));
        assert!(put.header("destination").is_some());
        assert_eq!(
            put.header("oc-total-length"),
            Some(total_size.to_string().as_str())
        );
    }
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_xml_filters_non_2xx_propstat_max_depth_0_and_cycle_guard() {
    use rship::core::backend::{ListOptions, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    let backend = make_webdav_backend(nextcloud_cfg(&srv, "alice", "secret"));

    backend
        .mkdir(&RelPath::parse("tree/sub/deep").unwrap())
        .await
        .unwrap();
    backend
        .put_single_shot(
            &make_upload_init(
                "op-xml-1",
                RelPath::parse("tree/a.txt").unwrap(),
                3,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"aaa".to_vec()),
        )
        .await
        .unwrap();
    backend
        .put_single_shot(
            &make_upload_init(
                "op-xml-2",
                RelPath::parse("tree/sub/b.txt").unwrap(),
                3,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"bbb".to_vec()),
        )
        .await
        .unwrap();
    backend
        .put_single_shot(
            &make_upload_init(
                "op-xml-3",
                RelPath::parse("tree/sub/deep/c.txt").unwrap(),
                3,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"ccc".to_vec()),
        )
        .await
        .unwrap();

    // Inject non-2xx phantom responses, a mixed 200+404 propstat entry, and an ancestor/sibling cycle!
    {
        let mut st = state.lock().unwrap();
        st.extra_propfind.insert(
            "tree".to_string(),
            vec![
                ExtraPropResponse {
                    href: "/remote.php/dav/files/alice/tree/phantom_404.txt".to_string(),
                    is_dir: false,
                    len: 999,
                    status_line: "HTTP/1.1 404 Not Found".to_string(),
                    add_404_propstat: false,
                },
                ExtraPropResponse {
                    href: "/remote.php/dav/files/alice/tree/phantom_403.txt".to_string(),
                    is_dir: false,
                    len: 777,
                    status_line: "HTTP/1.1 403 Forbidden".to_string(),
                    add_404_propstat: false,
                },
                ExtraPropResponse {
                    href: "/remote.php/dav/files/alice/tree/mixed_ok.txt".to_string(),
                    is_dir: false,
                    len: 42,
                    status_line: "HTTP/1.1 200 OK".to_string(),
                    add_404_propstat: true,
                },
            ],
        );
        st.extra_propfind.insert(
            "tree/sub".to_string(),
            vec![
                // Ancestor cycle pointing back to `tree/`
                ExtraPropResponse {
                    href: "/remote.php/dav/files/alice/tree/".to_string(),
                    is_dir: true,
                    len: 0,
                    status_line: "HTTP/1.1 200 OK".to_string(),
                    add_404_propstat: false,
                },
                // Out-of-subtree entry
                ExtraPropResponse {
                    href: "/remote.php/dav/files/alice/other/escape.txt".to_string(),
                    is_dir: false,
                    len: 10,
                    status_line: "HTTP/1.1 200 OK".to_string(),
                    add_404_propstat: false,
                },
            ],
        );
    }

    // max_depth(0) returns 0 entries without PROPFIND
    let hits_before = srv.hit_count();
    let d0 = collect_entries(
        backend
            .list_with_options(
                &RelPath::parse("tree").unwrap(),
                &ListOptions::new().with_max_depth(0),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(d0.is_empty());
    assert_eq!(srv.hit_count(), hits_before);

    // max_depth(2) + recursive(false) returns depth 2 and respects cycle/non-2xx filtering
    let d2 = collect_entries(
        backend
            .list_with_options(
                &RelPath::parse("tree").unwrap(),
                &ListOptions::new().with_max_depth(2).with_recursive(false),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let names: Vec<&str> = d2.iter().map(|e| e.nfc_path.as_str()).collect();
    assert!(names.contains(&"tree/a.txt"));
    assert!(names.contains(&"tree/sub"));
    assert!(names.contains(&"tree/sub/b.txt"));
    assert!(names.contains(&"tree/sub/deep"));
    assert!(names.contains(&"tree/mixed_ok.txt"));
    assert!(
        !names.contains(&"tree/sub/deep/c.txt"),
        "depth 3 must be excluded"
    );
    assert!(!names.contains(&"tree/phantom_404.txt"));
    assert!(!names.contains(&"tree/phantom_403.txt"));
    assert!(!names.contains(&"other/escape.txt"));
}

#[cfg(feature = "webdav")]
#[tokio::test]
async fn tier2_webdav_overwrite_false_409_known_dirs_eviction_sha1_checksum_and_rclone_strict_import()
 {
    use rship::backends::webdav::{WebdavVendor, try_parse_rclone_webdav_conf};
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use rship::core::types::{Checksum, HashKind};
    use webdav_helpers::*;

    let (srv, state) = start_dav_mock(
        "/remote.php/dav/files/alice",
        "/remote.php/dav/uploads/alice",
    )
    .await;
    state.lock().unwrap().enforce_parent_dir_on_put = true;

    let mut cfg = nextcloud_cfg(&srv, "alice", "secret")
        .with_headers(vec![("X-Custom-Audit".to_string(), "m4-val".to_string())]);
    cfg.vendor = WebdavVendor::Owncloud;
    let backend = make_webdav_backend(cfg);

    // Create parent dir -> PUT succeeds -> server deletes parent dir -> 409 evicts known_dirs -> retry recreates parent
    backend
        .mkdir(&RelPath::parse("pdir").unwrap())
        .await
        .unwrap();
    let mut init1 = make_upload_init(
        "op-sha1-1",
        RelPath::parse("pdir/item.bin").unwrap(),
        9,
        1024,
        DstPrecondition::Absent,
    );
    let data = b"sha1-body".to_vec();
    let sha1 = sha1_hex(&data);
    init1.checksums.push(Checksum {
        kind: HashKind::Sha1,
        hex: sha1.clone(),
    });
    backend
        .put_single_shot(&init1, make_byte_stream(data.clone()))
        .await
        .expect("initial SHA1 PUT");

    // Full-object GET verifies OC-Checksum SHA1; corrupted bytes trigger ErrorKind::Integrity
    let ok_read = read_all_from_source(
        backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("pdir/item.bin").unwrap()),
                None,
            )
            .await
            .unwrap(),
    )
    .await
    .expect("valid SHA1 GET");
    assert_eq!(ok_read, data);

    state.lock().unwrap().corrupt_next_get_bytes = true;
    let bad_read = read_all_from_source(
        backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("pdir/item.bin").unwrap()),
                None,
            )
            .await
            .unwrap(),
    )
    .await
    .expect_err("corrupted SHA1 GET must fail Integrity");
    assert_eq!(bad_read.kind(), ErrorKind::Integrity);

    // Custom header verified on wire
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.header("x-custom-audit") == Some("m4-val"))
    );

    // Overwrite: F on COPY with Absent precondition -> 412 PreconditionFailed when target exists
    let cp_err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("pdir/item.bin").unwrap()),
            &make_upload_init(
                "op-ov-f",
                RelPath::parse("pdir/item.bin").unwrap(),
                9,
                1024,
                DstPrecondition::Absent,
            ),
        )
        .await
        .expect_err("Overwrite: F against existing target must fail");
    assert_eq!(cp_err.kind(), ErrorKind::PreconditionFailed);

    // Evict known_dirs on 409 when server drops `pdir`
    state.lock().unwrap().dirs.remove("pdir");
    let err_409 = backend
        .put_single_shot(
            &make_upload_init(
                "op-409-evict",
                RelPath::parse("pdir/second.bin").unwrap(),
                3,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"abc".to_vec()),
        )
        .await
        .expect_err("409 expected when server lost pdir");
    assert_eq!(err_409.kind(), ErrorKind::PreconditionFailed);

    // Next PUT must recreate `pdir` via MKCOL because known_dirs was evicted!
    backend
        .put_single_shot(
            &make_upload_init(
                "op-409-retry",
                RelPath::parse("pdir/second.bin").unwrap(),
                3,
                1024,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"abc".to_vec()),
        )
        .await
        .expect("retry after 409 eviction must recreate parent dir and succeed");

    // Strict rclone WebDAV import checks
    let enc_err = try_parse_rclone_webdav_conf("RCLONE_ENCRYPT_V0:\nYWJj\n")
        .expect_err("encrypted rclone.conf must error");
    assert!(enc_err.is_config());

    let parsed = try_parse_rclone_webdav_conf(
        "[wd_strict]\n\
         type = webdav\n\
         url = https://dav.example/remote.php/dav/files/u\n\
         vendor = mysterious_vendor\n\
         bearer_token_command = /usr/bin/get-tok\n\
         headers = X-One,\"val,1\",X-Two,val2\n",
    )
    .expect("strict parse");
    assert_eq!(parsed.remotes.len(), 1);
    assert_eq!(parsed.remotes[0].vendor, WebdavVendor::Generic);
    assert_eq!(
        parsed.remotes[0].headers,
        vec![
            ("X-One".to_string(), "val,1".to_string()),
            ("X-Two".to_string(), "val2".to_string()),
        ]
    );
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.contains("mysterious_vendor"))
    );
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.contains("bearer_token_command"))
    );
}

// ===========================================================================
// Feature Area #12: SFTP (`#[cfg(feature = "sftp")]`) — 5 Tier 1 + 6 Tier 2
// ===========================================================================

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier1_sftp_config_builder_resolve_and_capabilities() {
    use rship::SftpRemoteConfig;
    use rship::backends::sftp::{DEFAULT_SFTP_CHUNK_SIZE, DEFAULT_SFTP_SINGLE_SHOT_MAX};
    use rship::prelude::*;

    let client = RshipClient::builder()
        .ephemeral()
        .remote(
            "sf",
            SftpRemoteConfig::new("127.0.0.1", "alice")
                .with_port(2222)
                .with_password("pw")
                .with_root_path("/backups")
                .with_host_key_policy("strict"),
        )
        .build()
        .expect("build client");

    let (backend, rel) = client.resolve("sf:dir/item.bin").expect("resolve");
    assert_eq!(rel.as_str(), "dir/item.bin");
    assert_eq!(backend.kind(), "sftp");
    assert_eq!(
        backend.endpoint_identity(),
        "sftp://alice@127.0.0.1:2222//backups"
    );

    let caps = backend.capabilities();
    assert!(caps.hashes.is_empty());
    assert!(caps.can_set_mtime);
    assert!(caps.supports_range_read);
    assert!(!caps.supports_server_side_copy);
    assert_eq!(caps.single_shot_max_bytes, DEFAULT_SFTP_SINGLE_SHOT_MAX);
    assert_eq!(caps.default_chunk_size, DEFAULT_SFTP_CHUNK_SIZE);
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier1_sftp_sdk_resolve_missing_credentials_and_invalid_policy_fail_config() {
    use rship::SftpRemoteConfig;
    use rship::backends::sftp::{SftpAuth, SftpBackend, SftpConfig};
    use rship::core::ErrorKind;
    use rship::prelude::*;

    let client = RshipClient::builder()
        .ephemeral()
        .remote("no_creds", SftpRemoteConfig::new("127.0.0.1", "alice"))
        .remote(
            "bad_policy",
            SftpRemoteConfig::new("127.0.0.1", "alice")
                .with_password("pw")
                .with_host_key_policy("bogus-policy"),
        )
        .build()
        .expect("build");

    let Err(err_creds) = client.resolve("no_creds:f") else {
        panic!("missing creds must fail");
    };
    assert_eq!(err_creds.kind(), ErrorKind::PermissionDenied);

    let Err(err_pol) = client.resolve("bad_policy:f") else {
        panic!("invalid policy must fail");
    };
    assert_eq!(err_pol.kind(), ErrorKind::InvalidPath);

    let Err(empty_host_err) = SftpBackend::new(SftpConfig::new(
        "r",
        "   ",
        "alice",
        SftpAuth::Password("pw".to_string()),
    )) else {
        panic!("empty host must fail");
    };
    assert_eq!(empty_host_err.kind(), ErrorKind::Protocol);
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier1_sftp_secret_redaction_in_debug_for_remote_and_backend_config() {
    use rship::SftpRemoteConfig;
    use rship::backends::sftp::{ImportedSftpRemote, SftpAuth, SftpConfig};
    use std::path::PathBuf;

    let remote_cfg = SftpRemoteConfig::new("example.org", "alice")
        .with_password("top-secret-pw")
        .with_key_passphrase("top-secret-passphrase");
    let dbg_remote = format!("{remote_cfg:?}");
    assert!(!dbg_remote.contains("top-secret-pw"));
    assert!(!dbg_remote.contains("top-secret-passphrase"));
    assert!(dbg_remote.contains("REDACTED"));

    let auth_pw = format!("{:?}", SftpAuth::Password("pw-123".into()));
    let auth_kf = format!(
        "{:?}",
        SftpAuth::KeyFile {
            path: PathBuf::from("/id"),
            passphrase: Some("kf-pass".into()),
        }
    );
    let auth_pem = format!(
        "{:?}",
        SftpAuth::KeyPem {
            pem: "PEM-PRIVATE-BODY".into(),
            passphrase: Some("pem-pass".into()),
        }
    );
    assert!(!auth_pw.contains("pw-123"));
    assert!(!auth_kf.contains("kf-pass"));
    assert!(!auth_pem.contains("PEM-PRIVATE-BODY"));
    assert!(!auth_pem.contains("pem-pass"));

    let backend_cfg = SftpConfig::new(
        "r",
        "example.org",
        "alice",
        SftpAuth::Password("cfg-secret".into()),
    );
    assert!(!format!("{backend_cfg:?}").contains("cfg-secret"));

    let imported = ImportedSftpRemote {
        name: "sf".into(),
        host: "example.org".into(),
        port: 22,
        user: "alice".into(),
        pass: Some("imp-pass".into()),
        key_file: None,
        key_file_pass: Some("imp-kf".into()),
        known_hosts_file: None,
        key_pem: Some("imp-pem".into()),
    };
    let dbg_imp = format!("{imported:?}");
    assert!(!dbg_imp.contains("imp-pass"));
    assert!(!dbg_imp.contains("imp-kf"));
    assert!(!dbg_imp.contains("imp-pem"));
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier1_sftp_list_max_depth_0_short_circuits_without_network() {
    use rship::core::backend::{BackendPath, ListOptions, StorageBackend};
    use rship::core::path::RelPath;
    use rship::core::types::HashKind;
    use sftp_helpers::*;

    // Point at a closed/unbound port — max_depth(0), compute_hash, and delete(root) must not connect
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let backend = sftp_backend_with_root("127.0.0.1", closed_port, "/");
    let entries = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
            .await
            .expect("max_depth(0) must short-circuit"),
    )
    .await
    .unwrap();
    assert!(entries.is_empty());

    assert!(
        backend
            .compute_hash(
                &BackendPath::from_rel(RelPath::parse("a.txt").unwrap()),
                HashKind::Sha256
            )
            .await
            .unwrap()
            .is_none()
    );
    backend
        .delete(&BackendPath::from_rel(RelPath::root()))
        .await
        .unwrap();
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier1_sftp_rclone_import_and_obscured_secrets_via_factory() {
    use rship::core::rclone_ini::obscure_rclone_secret_with_iv;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;

    let iv = [0x22u8; 16];
    let obs_pw = obscure_rclone_secret_with_iv("sftp-pw-secret", iv);
    let obs_kp = obscure_rclone_secret_with_iv("sftp-key-pass", iv);

    let tmp = TempDir::new().unwrap();
    let key_path = tmp.path().join("id_ed25519");
    let conf = format!(
        "[sf_pw]\n\
         type = sftp\n\
         host = 10.0.0.10\n\
         port = 2222\n\
         user = bob\n\
         pass = {obs_pw}\n\
         \n\
         [sf_key]\n\
         type = sftp\n\
         host = 10.0.0.11\n\
         user = carol\n\
         key_file = {}\n\
         key_file_pass = {obs_kp}\n",
        key_path.display()
    );

    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let mut app_cfg = AppConfig::new();
    let rep = import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).expect("import");
    assert_eq!(rep.imported.len(), 2);

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .expect("build");
    let (b_pw, _) = client.resolve("sf_pw:").expect("resolve sf_pw");
    assert_eq!(b_pw.endpoint_identity(), "sftp://bob@10.0.0.10:2222/");
    let (b_key, _) = client.resolve("sf_key:").expect("resolve sf_key");
    assert_eq!(b_key.endpoint_identity(), "sftp://carol@10.0.0.11:22/");
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_root_path_slash_and_tilde_distinct_endpoint_identities() {
    use rship::core::backend::StorageBackend;
    use sftp_helpers::*;
    use std::collections::BTreeSet;

    let id_empty = sftp_backend_with_root("10.0.0.5", 22, "").endpoint_identity();
    let id_rel = sftp_backend_with_root("10.0.0.5", 22, "data").endpoint_identity();
    let id_slash = sftp_backend_with_root("10.0.0.5", 22, "/").endpoint_identity();
    let id_slashes = sftp_backend_with_root("10.0.0.5", 22, "///").endpoint_identity();
    let id_abs = sftp_backend_with_root("10.0.0.5", 22, "/data/").endpoint_identity();
    let id_tilde = sftp_backend_with_root("10.0.0.5", 22, "~").endpoint_identity();
    let id_tilde_slash = sftp_backend_with_root("10.0.0.5", 22, "~/").endpoint_identity();
    let id_tilde_sub = sftp_backend_with_root("10.0.0.5", 22, "~/backups/").endpoint_identity();

    assert_eq!(id_slash, "sftp://alice@10.0.0.5:22//");
    assert_eq!(id_slashes, "sftp://alice@10.0.0.5:22//");
    assert_eq!(id_empty, "sftp://alice@10.0.0.5:22/");
    assert_eq!(id_tilde, "sftp://alice@10.0.0.5:22/");
    assert_eq!(id_tilde_slash, "sftp://alice@10.0.0.5:22/");
    assert_eq!(id_tilde_sub, "sftp://alice@10.0.0.5:22/backups");

    let distinct: BTreeSet<String> = [id_empty, id_rel, id_slash, id_abs].into_iter().collect();
    assert_eq!(distinct.len(), 4);
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_connect_timeout_bounds_banner_stall_via_runtime_options() {
    use rship::SftpRemoteConfig;
    use rship::config::RuntimeOptions;
    use rship::core::ErrorKind;
    use rship::prelude::*;
    use std::time::{Duration, Instant};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(sock);
        }
    });

    let client = RshipClient::builder()
        .ephemeral()
        .runtime_options(
            RuntimeOptions::new()
                .with_sftp_connect_timeout(Some(Duration::from_millis(200)))
                .with_sftp_io_timeout(Some(Duration::from_millis(200))),
        )
        .remote(
            "sf",
            SftpRemoteConfig::new("127.0.0.1", "alice")
                .with_port(port)
                .with_password("pw")
                .with_host_key_policy("insecure"),
        )
        .build()
        .expect("build client");

    let started = Instant::now();
    let err = client
        .stat("sf:file.txt")
        .await
        .expect_err("stalled banner must time out");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "timeout took {elapsed:?}");
    assert_eq!(err.kind(), ErrorKind::Timeout);
    assert!(err.is_retryable());
    server_task.abort();
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_abrupt_tcp_disconnect_after_banner_classified_retryable() {
    use rship::backends::sftp::{HostKeyPolicy, SftpAuth, SftpBackend, SftpConfig};
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, StorageBackend};
    use rship::core::path::RelPath;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(b"SSH-2.0-MockSSH_1.0\r\n").await;
            let _ = sock.flush().await;
            drop(sock);
        }
    });

    let mut cfg = SftpConfig::new("sf", "127.0.0.1", "alice", SftpAuth::Password("pw".into()));
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.connect_timeout = Duration::from_secs(2);
    let backend = SftpBackend::new(cfg).unwrap();

    let err = backend
        .stat(&BackendPath::from_rel(RelPath::parse("a.txt").unwrap()))
        .await
        .expect_err("abrupt EOF after banner must fail");
    assert!(
        matches!(err.kind(), ErrorKind::Network | ErrorKind::Timeout),
        "expected Network or Timeout, got {:?}: {err}",
        err.kind()
    );
    assert!(
        err.is_retryable(),
        "abrupt disconnect must be retryable: {err}"
    );
    let _ = server_task.await;
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_missing_key_file_and_bad_pem_fail_permanent_permission_denied() {
    use rship::SftpRemoteConfig;
    use rship::backends::sftp::{SftpAuth, SftpBackend, SftpConfig};
    use rship::core::ErrorKind;
    use rship::core::backend::{BackendPath, StorageBackend};
    use rship::core::path::RelPath;
    use rship::prelude::*;
    use std::time::Duration;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let missing_key = tmp.path().join("does_not_exist_ed25519");

    let client = RshipClient::builder()
        .ephemeral()
        .remote(
            "sf_kf",
            SftpRemoteConfig::new("127.0.0.1", "alice")
                .with_port(2222)
                .with_key_file(&missing_key),
        )
        .build()
        .unwrap();
    let err_kf = client
        .stat("sf_kf:file.txt")
        .await
        .expect_err("missing key_file must fail");
    assert_eq!(err_kf.kind(), ErrorKind::PermissionDenied);
    assert!(err_kf.is_permanent());

    let mut bad_pem_cfg = SftpConfig::new(
        "sf_pem",
        "127.0.0.1",
        "alice",
        SftpAuth::KeyPem {
            pem: "NOT A VALID PRIVATE KEY".to_string(),
            passphrase: None,
        },
    );
    bad_pem_cfg.connect_timeout = Duration::from_secs(5);
    let pem_backend = SftpBackend::new(bad_pem_cfg).unwrap();
    let err_pem = pem_backend
        .stat(&BackendPath::from_rel(RelPath::parse("a.txt").unwrap()))
        .await
        .expect_err("invalid KeyPem must fail");
    assert_eq!(err_pem.kind(), ErrorKind::PermissionDenied);
    assert!(err_pem.is_permanent());
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_rclone_import_os_user_tilde_known_hosts_key_pem_and_encrypted_reject() {
    use rship::backends::sftp::try_parse_rclone_sftp_conf;
    use std::path::PathBuf;

    let enc_err = try_parse_rclone_sftp_conf("RCLONE_ENCRYPT_V0:\nYWJj\n")
        .expect_err("encrypted rclone.conf must fail");
    assert!(enc_err.is_config());

    let conf = r#"
[sf_opts]
type = sftp
host = 10.1.2.3
key_file = ~/.ssh/id_ed25519
known_hosts_file = ~/.ssh/known_hosts
key_pem = -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----
"#;
    let rep = try_parse_rclone_sftp_conf(conf).expect("parse sftp conf");
    assert_eq!(rep.remotes.len(), 1);
    let r = &rep.remotes[0];

    let expected_user = ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .find_map(|v| {
            std::env::var(v)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "user".to_string());
    assert_eq!(r.user, expected_user);

    let has_home = ["HOME", "USERPROFILE"]
        .into_iter()
        .any(|v| std::env::var_os(v).is_some_and(|val| !val.is_empty()));
    if has_home {
        let kf = r.key_file.as_ref().expect("key_file");
        let kh = r.known_hosts_file.as_ref().expect("known_hosts_file");
        assert!(!kf.starts_with("~"), "key_file tilde must expand: {kf:?}");
        assert!(
            !kh.starts_with("~"),
            "known_hosts tilde must expand: {kh:?}"
        );
        assert!(kf.ends_with(PathBuf::from(".ssh").join("id_ed25519")));
        assert!(kh.ends_with(PathBuf::from(".ssh").join("known_hosts")));
    }

    let pem = r.key_pem.as_deref().expect("key_pem");
    assert!(pem.contains('\n'));
    assert!(!pem.contains("\\n"));
    assert!(!format!("{r:?}").contains("AAAA"));
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier2_sftp_env_gated_live_roundtrip_if_configured() {
    use rship::SftpRemoteConfig;
    use rship::core::backend::ListOptions;
    use rship::core::path::RelPath;
    use rship::core::state::DstPrecondition;
    use rship::prelude::*;
    use sftp_helpers::*;

    let Ok(host) = std::env::var("RSHIP_E2E_SFTP_HOST") else {
        return;
    };
    if host.trim().is_empty() {
        return;
    }
    let user = std::env::var("RSHIP_E2E_SFTP_USER").unwrap_or_else(|_| "user".to_string());
    let mut cfg = SftpRemoteConfig::new(host, user);
    if let Ok(port) = std::env::var("RSHIP_E2E_SFTP_PORT")
        && let Ok(p) = port.parse::<u16>()
    {
        cfg = cfg.with_port(p);
    }
    if let Ok(root) = std::env::var("RSHIP_E2E_SFTP_ROOT") {
        cfg = cfg.with_root_path(root);
    }
    if let Ok(pass) = std::env::var("RSHIP_E2E_SFTP_PASS") {
        cfg = cfg.with_password(pass);
    }
    if let Ok(kf) = std::env::var("RSHIP_E2E_SFTP_KEY_FILE") {
        cfg = cfg.with_key_file(kf);
    }

    let client = RshipClient::builder()
        .ephemeral()
        .remote("live_sf", cfg)
        .build()
        .expect("build live SFTP client");
    let (backend, _) = client.resolve("live_sf:").expect("resolve");

    let rel_dir = format!("rship_e2e_{}", std::process::id());
    let rel_file = format!("{rel_dir}/hello.txt");
    client
        .mkdir(&format!("live_sf:{rel_dir}"))
        .await
        .expect("mkdir");
    let data = b"live sftp roundtrip".to_vec();
    let pool = rship::core::buffer::BufferPool::new(64 * 1024, 64 * 1024).unwrap();
    let src = std::sync::Arc::new(rship::core::source::MemorySource::new(data.clone()));
    let stream = rship::core::source::bounded_range_stream(src, 0, data.len() as u64, pool);
    backend
        .put_single_shot(
            &rship::core::backend::UploadInit {
                op_id: "op-live-sf".to_string(),
                dst_path: RelPath::parse(&rel_file).unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: data.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 64 * 1024,
                checksums: Vec::new(),
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            stream,
        )
        .await
        .expect("put_single_shot");
    let st = client
        .stat(&format!("live_sf:{rel_file}"))
        .await
        .unwrap()
        .expect("stat");
    assert_eq!(st.size, data.len() as u64);
    let listed = collect_entries(
        client
            .list(&format!("live_sf:{rel_dir}"), &ListOptions::shallow())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == rel_file));
    client.delete(&format!("live_sf:{rel_file}")).await.unwrap();
    client.delete(&format!("live_sf:{rel_dir}")).await.unwrap();
}
