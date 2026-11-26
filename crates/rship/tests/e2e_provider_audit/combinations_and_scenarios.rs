//! M4 E2E Tier 3 (pairwise cross-feature combinations, 14 tests) and Tier 4
//! (real-world SDK application scenarios, 4 tests).
//! All `#[tokio::test]` functions live at module top level for clean `-- tier3_` /
//! `-- tier4_` / `-- combinations_and_scenarios::` filtering, with zero `#![allow(...)]`.

#[cfg(feature = "local")]
mod local_helpers {
    use futures::StreamExt;
    use rship::core::backend::EntryStream;
    use rship::core::source::DataSource;
    use rship::core::types::{ByteRange, Entry};
    use rship::prelude::*;

    pub(super) async fn collect_entries(mut stream: EntryStream) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            out.push(item?);
        }
        Ok(out)
    }

    pub(super) async fn read_all_from_source(src: DataSource) -> Result<Vec<u8>> {
        match src {
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
        }
    }
}

#[cfg(all(
    feature = "local",
    any(
        feature = "crypt",
        feature = "webdav",
        feature = "gcs",
        feature = "azureblob"
    )
))]
mod binary_helpers {
    use rship::core::buffer::BufferPool;
    use rship::core::source::{ByteStream, MemorySource, bounded_range_stream};
    use std::sync::Arc;

    #[cfg(any(feature = "crypt", feature = "webdav"))]
    pub(super) fn make_byte_stream(data: Vec<u8>) -> ByteStream {
        let len = data.len() as u64;
        if len == 0 {
            return Box::pin(futures::stream::empty());
        }
        let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).expect("BufferPool::new");
        let src = Arc::new(MemorySource::new(data));
        bounded_range_stream(src, 0, len, pool)
    }

    #[cfg(any(feature = "webdav", feature = "azureblob"))]
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

    #[cfg(any(feature = "webdav", feature = "azureblob"))]
    pub(super) fn md5_digest(data: &[u8]) -> [u8; 16] {
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
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&a0.to_le_bytes());
        out[4..8].copy_from_slice(&b0.to_le_bytes());
        out[8..12].copy_from_slice(&c0.to_le_bytes());
        out[12..16].copy_from_slice(&d0.to_le_bytes());
        out
    }

    #[cfg(feature = "webdav")]
    pub(super) fn md5_hex(data: &[u8]) -> String {
        let mut s = String::with_capacity(32);
        for b in md5_digest(data) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[cfg(any(feature = "webdav", feature = "gcs", feature = "azureblob"))]
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

    #[cfg(feature = "webdav")]
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
}

#[cfg(all(feature = "local", feature = "crypt", feature = "s3"))]
mod s3_mock_helpers {
    use crate::mock_http::{CapturedRequest, MockAction, MockHttpServer, MockResponse};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub(super) struct MockS3Object {
        pub(super) data: Vec<u8>,
        pub(super) etag: String,
    }

    pub(super) type S3PartsMap = BTreeMap<u32, (Vec<u8>, String)>;

    pub(super) struct MockS3State {
        pub(super) bucket: String,
        pub(super) objects: BTreeMap<String, MockS3Object>,
        pub(super) uploads: HashMap<String, (String, S3PartsMap)>,
        pub(super) next_etag: usize,
        pub(super) next_upload: usize,
        pub(super) enforce_if_match: bool,
    }

    impl MockS3State {
        pub(super) fn new(bucket: &str, enforce_if_match: bool) -> Self {
            Self {
                bucket: bucket.to_string(),
                objects: BTreeMap::new(),
                uploads: HashMap::new(),
                next_etag: 1,
                next_upload: 1,
                enforce_if_match,
            }
        }

        fn gen_etag(&mut self) -> String {
            let id = self.next_etag;
            self.next_etag += 1;
            format!("\"s3-etag-{id}\"")
        }
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    fn url_encode_s3(raw: &str) -> String {
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

    fn extract_xml_tag_values(xml: &str, tag: &str) -> Vec<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut out = Vec::new();
        let mut rest = xml;
        while let Some(s) = rest.find(&open) {
            let after = &rest[s + open.len()..];
            let Some(e) = after.find(&close) else {
                break;
            };
            out.push(after[..e].to_string());
            rest = &after[e + close.len()..];
        }
        out
    }

    fn parse_byte_range(req: &CapturedRequest, total: usize) -> Option<(usize, usize)> {
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

    pub(super) async fn start_mock_s3(
        bucket: &str,
        enforce_if_match: bool,
    ) -> (MockHttpServer, Arc<Mutex<MockS3State>>) {
        let state = Arc::new(Mutex::new(MockS3State::new(bucket, enforce_if_match)));
        let st_c = state.clone();
        let srv = MockHttpServer::start_with_handler(move |req| {
            let mut st = st_c.lock().unwrap_or_else(|e| e.into_inner());
            let bkt_prefix = format!("/{}/", st.bucket);
            let bkt_root = format!("/{}", st.bucket);

            // ListObjectsV2 & DeleteObjects on `/{bucket}`
            if req.path == bkt_root {
                if req.method == "GET" {
                    let prefix = req.query_get("prefix").unwrap_or_default();
                    let delim = req.query_get("delimiter");
                    let mut contents = String::new();
                    let mut common = std::collections::BTreeSet::new();
                    for (k, obj) in &st.objects {
                        if !k.starts_with(&prefix) {
                            continue;
                        }
                        let rest = &k[prefix.len()..];
                        if delim.as_deref() == Some("/")
                            && let Some((dir, _)) = rest.split_once('/')
                        {
                            common.insert(format!("{prefix}{dir}/"));
                            continue;
                        }
                        contents.push_str(&format!(
                            "<Contents><Key>{}</Key><Size>{}</Size><ETag>{}</ETag>\
                             <LastModified>2026-11-25T12:00:00.000Z</LastModified></Contents>",
                            xml_escape(&url_encode_s3(k)),
                            obj.data.len(),
                            xml_escape(&obj.etag)
                        ));
                    }
                    let mut cp_xml = String::new();
                    for p in common {
                        cp_xml.push_str(&format!(
                            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                            xml_escape(&url_encode_s3(&p))
                        ));
                    }
                    let xml = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <ListBucketResult><IsTruncated>false</IsTruncated>\
                         <EncodingType>url</EncodingType>{contents}{cp_xml}</ListBucketResult>"
                    );
                    return MockAction::Respond(
                        MockResponse::ok(xml.into_bytes())
                            .with_header("Content-Type", "application/xml"),
                    );
                }
                if req.method == "POST" && req.query_get("delete").is_some() {
                    let keys = extract_xml_tag_values(&req.body_text(), "Key");
                    let mut deleted = String::new();
                    for k in keys {
                        st.objects.remove(&k);
                        deleted.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", xml_escape(&k)));
                    }
                    let xml = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult>{deleted}</DeleteResult>"
                    );
                    return MockAction::Respond(MockResponse::ok(xml.into_bytes()));
                }
            }

            let Some(raw_key) = req.path.strip_prefix(&bkt_prefix) else {
                return MockAction::Respond(MockResponse::empty(404));
            };
            let key = percent_decode_strict(raw_key);

            if req.method == "POST" && req.query_get("uploads").is_some() {
                let uid = format!("up-{}", st.next_upload);
                st.next_upload += 1;
                st.uploads.insert(uid.clone(), (key.clone(), BTreeMap::new()));
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key>\
                     <UploadId>{uid}</UploadId></InitiateMultipartUploadResult>",
                    xml_escape(&st.bucket),
                    xml_escape(&key)
                );
                return MockAction::Respond(MockResponse::ok(xml.into_bytes()));
            }

            if req.method == "PUT"
                && let Some(uid) = req.query_get("uploadId")
                && let Some(pn_str) = req.query_get("partNumber")
                && let Ok(pn) = pn_str.parse::<u32>()
            {
                let etag = st.gen_etag();
                let Some((_, parts)) = st.uploads.get_mut(&uid) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                parts.insert(pn, (req.body.clone(), etag.clone()));
                return MockAction::Respond(MockResponse::empty(200).with_header("ETag", etag));
            }

            if req.method == "POST"
                && let Some(uid) = req.query_get("uploadId")
            {
                if st.enforce_if_match
                    && let Some(expected) = req.header("if-match")
                {
                    let cur = st.objects.get(&key).map(|o| o.etag.as_str());
                    if cur != Some(expected) {
                        return MockAction::Respond(MockResponse::text(
                            412,
                            "<Error><Code>PreconditionFailed</Code></Error>",
                        ));
                    }
                }
                let Some((_, parts)) = st.uploads.remove(&uid) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                let mut assembled = Vec::new();
                for (_, (bytes, _)) in parts {
                    assembled.extend_from_slice(&bytes);
                }
                let etag = st.gen_etag();
                st.objects.insert(
                    key.clone(),
                    MockS3Object {
                        data: assembled,
                        etag: etag.clone(),
                    },
                );
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key>\
                     <ETag>{}</ETag></CompleteMultipartUploadResult>",
                    xml_escape(&st.bucket),
                    xml_escape(&key),
                    xml_escape(&etag)
                );
                return MockAction::Respond(
                    MockResponse::ok(xml.into_bytes()).with_header("ETag", etag),
                );
            }

            match req.method.as_str() {
                "PUT" => {
                    if st.enforce_if_match
                        && let Some(expected) = req.header("if-match")
                    {
                        let cur = st.objects.get(&key).map(|o| o.etag.as_str());
                        if cur != Some(expected) {
                            return MockAction::Respond(MockResponse::text(
                                412,
                                "<Error><Code>PreconditionFailed</Code></Error>",
                            ));
                        }
                    }
                    let etag = st.gen_etag();
                    st.objects.insert(
                        key,
                        MockS3Object {
                            data: req.body.clone(),
                            etag: etag.clone(),
                        },
                    );
                    MockAction::Respond(
                        MockResponse::empty(200)
                            .with_header("ETag", etag)
                            .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                    )
                }
                "HEAD" => {
                    if let Some(obj) = st.objects.get(&key) {
                        MockAction::Respond(
                            MockResponse::empty(200)
                                .with_header("Content-Length", obj.data.len().to_string())
                                .with_header("ETag", obj.etag.clone())
                                .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                        )
                    } else {
                        MockAction::Respond(MockResponse::empty(404))
                    }
                }
                "GET" => {
                    if let Some(obj) = st.objects.get(&key) {
                        if let Some(rh) = req.header("range")
                            && let Some((s, e)) = parse_byte_range(req, obj.data.len())
                        {
                            let _ = rh;
                            return MockAction::Respond(
                                MockResponse::new(206, obj.data[s..=e].to_vec())
                                    .with_header("ETag", obj.etag.clone())
                                    .with_header(
                                        "Content-Range",
                                        format!("bytes {s}-{e}/{}", obj.data.len()),
                                    ),
                            );
                        }
                        MockAction::Respond(
                            MockResponse::ok(obj.data.clone()).with_header("ETag", obj.etag.clone()),
                        )
                    } else {
                        MockAction::Respond(MockResponse::empty(404))
                    }
                }
                "DELETE" => {
                    st.objects.remove(&key);
                    MockAction::Respond(MockResponse::empty(204))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;
        (srv, state)
    }
}

#[cfg(all(feature = "local", feature = "gcs"))]
const TEST_SA_KEY_PEM: &str = "\
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

// ===========================================================================
// Tier 3 — Pairwise Cross-Feature Combinations (14 tests, 0 #[ignore])
// ===========================================================================

#[cfg(feature = "local")]
#[tokio::test]
async fn tier3_local_windows_safe_and_max_depth_zero() {
    use local_helpers::*;
    use rship::backends::local::LocalBackend;
    use rship::core::backend::ListOptions;
    use rship::core::encoding::EncodingMode;
    use rship::core::path::RelPath;
    use rship::core::types::HashKind;
    use rship::prelude::*;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let d1 = tmp.path().join("ws1");
    let d2 = tmp.path().join("ws2");
    std::fs::create_dir_all(d1.join("sub")).unwrap();
    std::fs::create_dir_all(&d2).unwrap();

    // Seed WindowsSafe-encoded segments directly on disk: `CON`, `a:b`, `foo `, `sub/deep.txt`
    std::fs::write(d1.join("^43ON"), b"con-data").unwrap();
    std::fs::write(d1.join("a^3Ab"), b"colon-data").unwrap();
    std::fs::write(d1.join("foo^20"), b"space-data").unwrap();
    std::fs::write(d1.join("sub/deep.txt"), b"deep-data").unwrap();

    let b1 = LocalBackend::new("ws1", &d1)
        .unwrap()
        .with_encoding(EncodingMode::WindowsSafe);
    let b2 = LocalBackend::new("ws2", &d2)
        .unwrap()
        .with_encoding(EncodingMode::WindowsSafe);

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend("ws1", b1)
        .register_backend("ws2", b2)
        .build()
        .unwrap();

    // max_depth(0) returns 0 entries (never overwritten to 1)
    let depth0 = collect_entries(
        client
            .list("ws1:", &ListOptions::new().with_max_depth(0))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(depth0.is_empty());

    // Shallow list decodes WindowsSafe segments cleanly
    let shallow = collect_entries(client.list("ws1:", &ListOptions::shallow()).await.unwrap())
        .await
        .unwrap();
    let shallow_names: BTreeSet<String> = shallow
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert_eq!(
        shallow_names,
        ["CON", "a:b", "foo ", "sub"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    );

    let rep = client.sync("ws1:", "ws2:").run().await.unwrap();
    assert_eq!(rep.files_transferred, 4);
    assert!(d2.join("^43ON").exists());
    assert!(d2.join("a^3Ab").exists());
    assert!(d2.join("foo^20").exists());

    // Parity verification: list(recursive) + stat + open_read + compute_hash(Sha256) + checksum sync
    let (dst_backend, _) = client.resolve("ws2:").unwrap();
    let (src_backend, _) = client.resolve("ws1:").unwrap();
    let rec = collect_entries(
        client
            .list("ws2:", &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    for entry in rec.iter().filter(|e| e.kind == EntryKind::File) {
        let bp = BackendPath::from_entry(entry);
        let st = dst_backend.stat(&bp).await.unwrap().expect("stat");
        assert_eq!(st.size, entry.size);
        let bytes1 = read_all_from_source(
            client
                .open_read(&format!("ws1:{}", entry.nfc_path), None)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        let bytes2 = read_all_from_source(
            client
                .open_read(&format!("ws2:{}", entry.nfc_path), None)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(bytes1, bytes2);
        let h1 = src_backend
            .compute_hash(
                &BackendPath::from_rel(RelPath::parse(entry.nfc_path.as_str()).unwrap()),
                HashKind::Sha256,
            )
            .await
            .unwrap();
        let h2 = dst_backend
            .compute_hash(&bp, HashKind::Sha256)
            .await
            .unwrap();
        assert_eq!(h1, h2);
    }

    let check_rep = client
        .sync("ws1:", "ws2:")
        .checksum(true)
        .run()
        .await
        .unwrap();
    assert_eq!(check_rep.files_transferred, 0);
    assert_eq!(check_rep.files_skipped, 4);
    assert_eq!(check_rep.items_deleted, 0);
}

#[cfg(feature = "local")]
#[tokio::test]
async fn tier3_local_nfd_sync_rename_and_parity_check() {
    use local_helpers::*;
    use rship::core::backend::ListOptions;
    use rship::prelude::*;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let nfd_dir = src.join("cafe\u{0301}").join("sub");
    std::fs::create_dir_all(&nfd_dir).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(nfd_dir.join("old.txt"), b"nfd-data").unwrap();
    std::fs::write(nfd_dir.join("keep.txt"), b"keep").unwrap();

    let client = RshipClient::ephemeral().unwrap();
    let rep = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .run()
        .await
        .unwrap();
    assert_eq!(rep.files_transferred, 2);

    let dst_s = dst.to_string_lossy().to_string();
    let entries = collect_entries(
        client
            .list(dst_s.as_str(), &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let old_entry = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "caf\u{00e9}/sub/old.txt")
        .expect("NFC normalized path in list")
        .clone();
    assert!(
        entries
            .iter()
            .any(|e| e.nfc_path.as_str() == "caf\u{00e9}/sub/keep.txt")
    );

    let (dst_backend, _) = client.resolve(dst_s.as_str()).unwrap();
    let renamed = dst_backend
        .rename(&BackendPath::from_entry(&old_entry), "new.txt")
        .await
        .expect("rename inside NFD parent");
    assert_eq!(renamed.nfc_path.as_str(), "caf\u{00e9}/sub/new.txt");

    let read_back = read_all_from_source(
        dst_backend
            .open_read(&BackendPath::from_entry(&renamed), None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(read_back, b"nfd-data");

    // Re-sync with delete=true aligns src->dst cleanly, and checksum sync confirms 0 diffs
    let rep2 = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .delete(true)
        .run()
        .await
        .unwrap();
    assert!(rep2.is_success());
    let check_rep = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .checksum(true)
        .run()
        .await
        .unwrap();
    assert_eq!(check_rep.files_transferred, 0);
    assert_eq!(check_rep.files_skipped, 2);
}

#[cfg(all(feature = "local", feature = "crypt"))]
#[tokio::test]
async fn tier3_local_crypt_existing_precondition_and_chunked_overwrite() {
    use binary_helpers::*;
    use local_helpers::*;
    use rship::backends::local::LocalBackend;
    use rship::core::backend::{
        BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit,
    };
    use rship::core::path::RelPath;
    use rship::core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
    use rship::crypto::{CryptoBackend, CryptoConfig, MasterKey};
    use rship::prelude::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let vault = tmp.path().join("vault");
    let src_dir = tmp.path().join("plain_src");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::create_dir_all(&src_dir).unwrap();

    let inner = Arc::new(
        LocalBackend::new("vault", &vault)
            .unwrap()
            .with_chunking(64 * 1024, 64 * 1024),
    );
    let crypt = CryptoBackend::new(
        inner.clone(),
        CryptoConfig::new("crypt_vault"),
        MasterKey::from_bytes([0x5au8; 32]).derive_subkeys(),
    )
    .unwrap();

    let v1 = vec![0x33u8; 128 * 1024];
    let init1 = UploadInit {
        op_id: "op-lc-1".to_string(),
        dst_path: RelPath::parse("blob.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: v1.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let s1 = crypt.begin_upload(&init1).await.unwrap();
    let op1 = OperationRecord {
        op_id: init1.op_id.clone(),
        session_key: "sk-1".into(),
        job_id: "j-1".into(),
        src_endpoint: "local://s".into(),
        dst_endpoint: crypt.endpoint_identity(),
        src_raw_path: "blob.bin".into(),
        dst_raw_path: "blob.bin".into(),
        dst_nfc_path: init1.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init1.total_size,
            mtime_ns: init1.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: s1.remote_op_id.clone(),
        backend_kind: "crypt".into(),
        session_token: Some(s1.session_token.clone()),
        backend_meta: s1.backend_meta.clone(),
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        expires_at: None,
    };
    let mut parts1 = Vec::new();
    for (idx, chunk) in v1.chunks(64 * 1024).enumerate() {
        let off = (idx * 64 * 1024) as u64;
        let ack = crypt
            .upload_chunk(
                &op1,
                ChunkUpload::new(
                    idx as u32 + 1,
                    off,
                    chunk.len() as u64,
                    v1.len() as u64,
                    make_byte_stream(chunk.to_vec()),
                ),
            )
            .await
            .unwrap();
        parts1.push(CompletedPart {
            part_number: idx as u32 + 1,
            offset: off,
            length: chunk.len() as u64,
            etag: ack.etag.unwrap_or_default(),
            checksum: ack.checksum,
        });
    }
    let e1 = crypt.finish_upload(&op1, &parts1).await.unwrap();
    assert_eq!(e1.size, v1.len() as u64);

    // Overwrite 128 KiB -> 192 KiB with DstPrecondition::Existing { size: 128 KiB, .. }
    let v2 = vec![0x77u8; 192 * 1024];
    let pre = DstPrecondition::Existing {
        size: e1.size,
        mtime_ns: e1.mtime_ns,
        etag: e1.etag.clone(),
        node_id: e1.node_id.clone(),
    };
    let init2 = UploadInit {
        op_id: "op-lc-2".to_string(),
        dst_path: RelPath::parse("blob.bin").unwrap(),
        existing_node_id: e1.node_id.clone(),
        pregenerated_id: None,
        total_size: v2.len() as u64,
        src_mtime_ns: 1_700_000_010_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: pre.clone(),
        src_etag: None,
    };
    let s2 = crypt.begin_upload(&init2).await.unwrap();
    let op2 = OperationRecord {
        op_id: init2.op_id.clone(),
        session_key: "sk-2".into(),
        job_id: "j-2".into(),
        src_endpoint: "local://s".into(),
        dst_endpoint: crypt.endpoint_identity(),
        src_raw_path: "blob.bin".into(),
        dst_raw_path: "blob.bin".into(),
        dst_nfc_path: init2.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init2.total_size,
            mtime_ns: init2.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: pre,
        existing_dst_node_id: e1.node_id.clone(),
        remote_op_id: s2.remote_op_id.clone(),
        backend_kind: "crypt".into(),
        session_token: Some(s2.session_token.clone()),
        backend_meta: s2.backend_meta.clone(),
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1_700_000_010,
        updated_at: 1_700_000_010,
        expires_at: None,
    };
    let mut parts2 = Vec::new();
    for (idx, chunk) in v2.chunks(64 * 1024).enumerate() {
        let off = (idx * 64 * 1024) as u64;
        let ack = crypt
            .upload_chunk(
                &op2,
                ChunkUpload::new(
                    idx as u32 + 1,
                    off,
                    chunk.len() as u64,
                    v2.len() as u64,
                    make_byte_stream(chunk.to_vec()),
                ),
            )
            .await
            .unwrap();
        parts2.push(CompletedPart {
            part_number: idx as u32 + 1,
            offset: off,
            length: chunk.len() as u64,
            etag: ack.etag.unwrap_or_default(),
            checksum: ack.checksum,
        });
    }
    let e2 = crypt.finish_upload(&op2, &parts2).await.unwrap();
    assert_eq!(e2.size, v2.len() as u64);

    let dec = read_all_from_source(
        crypt
            .open_read(
                &BackendPath::from_rel(RelPath::parse("blob.bin").unwrap()),
                None,
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(dec, v2);

    // Tampered precondition: using plaintext size (`v2.len()`) when inner size differs, OR stale wrong size -> PreconditionFailed
    let wrong_pre = DstPrecondition::Existing {
        size: 128 * 1024,
        mtime_ns: e2.mtime_ns,
        etag: e2.etag.clone(),
        node_id: e2.node_id.clone(),
    };
    let err_pre = crypt
        .put_single_shot(
            &UploadInit {
                op_id: "op-lc-bad-pre".to_string(),
                dst_path: RelPath::parse("blob.bin").unwrap(),
                existing_node_id: e2.node_id.clone(),
                pregenerated_id: None,
                total_size: 100,
                src_mtime_ns: 1_700_000_020_000_000_000,
                planned_chunk_size: 64 * 1024,
                checksums: Vec::new(),
                precondition: wrong_pre,
                src_etag: None,
            },
            make_byte_stream(vec![1u8; 100]),
        )
        .await
        .expect_err("wrong Existing size must fail PreconditionFailed");
    assert_eq!(err_pre.kind(), ErrorKind::PreconditionFailed);

    // Also wire RshipClient with CryptRemoteConfig over local
    let vault2 = tmp.path().join("vault2");
    std::fs::create_dir_all(&vault2).unwrap();
    std::fs::write(src_dir.join("hello.txt"), b"client-crypt-sync").unwrap();
    let client = RshipClient::builder()
        .ephemeral()
        .remote(
            "crypt_loc",
            CryptRemoteConfig::new(vault2.to_string_lossy().as_ref())
                .with_password("test-passphrase-m4"),
        )
        .build()
        .unwrap();
    let rep = client
        .sync(src_dir.to_string_lossy().as_ref(), "crypt_loc:")
        .run()
        .await
        .unwrap();
    assert_eq!(rep.files_transferred, 1);
    let got = read_all_from_source(client.open_read("crypt_loc:hello.txt", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, b"client-crypt-sync");
}

#[cfg(all(feature = "crypt", feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier3_crypt_onedrive_single_shot_4mib_boundary() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use local_helpers::*;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Default)]
    struct Od4MiBState {
        files: HashMap<String, (Vec<u8>, String)>,
        sessions: HashMap<String, (String, Vec<u8>)>,
        next_sess: usize,
    }
    let state = Arc::new(Mutex::new(Od4MiBState::default()));
    let st_c = state.clone();

    let srv = MockHttpServer::start().await;
    let base_url = srv.base_url();
    srv.set_fallback(move |req| {
        let mut st = st_c.lock().unwrap_or_else(|e| e.into_inner());
        if req.method == "PUT" && req.path.ends_with(":/content") {
            if req.body.len() > 4 * 1024 * 1024 {
                return MockAction::Respond(MockResponse::empty(413));
            }
            let rel = req
                .path
                .strip_prefix("/me/drive/root:/")
                .and_then(|s| s.strip_suffix(":/content"))
                .unwrap_or("")
                .to_string();
            st.files
                .insert(rel.clone(), (req.body.clone(), format!("id-{rel}")));
            return MockAction::Respond(MockResponse::json(
                201,
                &serde_json::json!({
                    "id": format!("id-{rel}"),
                    "name": rel,
                    "size": req.body.len(),
                    "eTag": "\"od-ss\"",
                    "file": {},
                    "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" }
                }),
            ));
        }
        if req.method == "POST" && req.path.ends_with(":/createUploadSession") {
            let rel = req
                .path
                .strip_prefix("/me/drive/root:/")
                .and_then(|s| s.strip_suffix(":/createUploadSession"))
                .unwrap_or("")
                .to_string();
            st.next_sess += 1;
            let sid = format!("s-{}", st.next_sess);
            st.sessions.insert(sid.clone(), (rel, Vec::new()));
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "uploadUrl": format!("{base_url}/upload_sess/{sid}"),
                    "expirationDateTime": "2099-01-01T00:00:00Z"
                }),
            ));
        }
        if let Some(sid) = req.path.strip_prefix("/upload_sess/")
            && req.method == "PUT"
        {
            let hdr = req.header("content-range").unwrap_or("");
            let spec = hdr.strip_prefix("bytes ").unwrap_or("0-0/0");
            let (range_part, total_s) = spec.split_once('/').unwrap_or(("0-0", "0"));
            let (s_s, e_s) = range_part.split_once('-').unwrap_or(("0", "0"));
            let start: usize = s_s.parse().unwrap_or(0);
            let end: usize = e_s.parse().unwrap_or(0);
            let total: usize = total_s.parse().unwrap_or(0);

            let (rel, finished_data) = {
                let Some((rel, buf)) = st.sessions.get_mut(sid) else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                if buf.len() < total {
                    buf.resize(total, 0);
                }
                buf[start..=end].copy_from_slice(&req.body);
                if end + 1 >= total {
                    (Some(rel.clone()), Some(buf.clone()))
                } else {
                    (None, None)
                }
            };
            if let (Some(rel), Some(data)) = (rel, finished_data) {
                st.sessions.remove(sid);
                let id = format!("id-{}", st.files.len() + 1);
                st.files.insert(rel.clone(), (data.clone(), id.clone()));
                return MockAction::Respond(MockResponse::json(
                    201,
                    &serde_json::json!({
                        "id": id,
                        "name": rel,
                        "size": data.len(),
                        "eTag": "\"od-chunk\"",
                        "file": {},
                        "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" }
                    }),
                ));
            }
            return MockAction::Respond(MockResponse::json(
                202,
                &serde_json::json!({ "nextExpectedRanges": [format!("{}-", end + 1)] }),
            ));
        }
        if let Some(rel) = req
            .path
            .strip_prefix("/me/drive/root:/")
            .and_then(|s| s.strip_suffix(':'))
            && req.method == "GET"
        {
            if let Some((data, id)) = st.files.get(rel) {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "id": id,
                        "name": rel,
                        "size": data.len(),
                        "eTag": "\"od-chunk\"",
                        "file": {},
                        "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" },
                        "@microsoft.graph.downloadUrl": format!("{base_url}/cdn/{id}")
                    }),
                ));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if let Some(id) = req.path.strip_prefix("/cdn/")
            && req.method == "GET"
        {
            if let Some((data, _)) = st.files.values().find(|(_, fid)| fid == id) {
                if let Some(rh) = req.header("range")
                    && let Some(spec) = rh.strip_prefix("bytes=")
                    && let Some((ss, es)) = spec.split_once('-')
                {
                    let s: usize = ss.parse().unwrap_or(0);
                    let e: usize = es
                        .parse()
                        .unwrap_or(data.len().saturating_sub(1))
                        .min(data.len() - 1);
                    return MockAction::Respond(
                        MockResponse::new(206, data[s..=e].to_vec())
                            .with_header("Content-Range", format!("bytes {s}-{e}/{}", data.len())),
                    );
                }
                return MockAction::Respond(MockResponse::ok(data.clone()));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "GET" && req.path.starts_with("/me/drive/root/children") {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "value": [] }),
            ));
        }
        if req.method == "GET" && req.path.starts_with("/me/drive/items/") {
            let id = req.path.strip_prefix("/me/drive/items/").unwrap_or("");
            if let Some((rel, (data, _))) = st.files.iter().find(|(_, (_, fid))| fid == id) {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "id": id,
                        "name": rel,
                        "size": data.len(),
                        "eTag": "\"od-chunk\"",
                        "file": {},
                        "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" },
                        "@microsoft.graph.downloadUrl": format!("{base_url}/cdn/{id}")
                    }),
                ));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "PATCH" && req.path.starts_with("/me/drive/items/") {
            let id = req.path.strip_prefix("/me/drive/items/").unwrap_or("");
            if let Some((rel, (data, _))) = st.files.iter().find(|(_, (_, fid))| fid == id) {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "id": id,
                        "name": rel,
                        "size": data.len(),
                        "eTag": "\"od-chunk\"",
                        "file": {},
                        "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" }
                    }),
                ));
            }
        }
        MockAction::Respond(MockResponse::empty(404))
    });

    let tmp = TempDir::new().unwrap();
    let plain_path = tmp.path().join("four.bin");
    let plain: Vec<u8> = (0..(4 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&plain_path, &plain).unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .remote(
            "od",
            OnedriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_access_token("od-tok"),
        )
        .remote(
            "crypt_od",
            CryptRemoteConfig::new("od:")
                .with_key_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        )
        .build()
        .unwrap();

    let rep = client
        .copy_file(plain_path.to_string_lossy().as_ref(), "crypt_od:four.bin")
        .run()
        .await
        .expect("4 MiB plaintext through crypt->onedrive must switch to createUploadSession");
    assert_eq!(rep.files_transferred, 1);

    let reqs = srv.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "POST" && r.path.ends_with(":/createUploadSession")),
        "ciphertext > 4 MiB must use createUploadSession"
    );
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "PUT" && r.path.ends_with(":/content")),
        "ciphertext > 4 MiB must NOT attempt single-shot :/content"
    );

    let got = read_all_from_source(client.open_read("crypt_od:four.bin", None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, plain);
}

#[cfg(all(feature = "crypt", feature = "s3", feature = "local"))]
#[tokio::test]
async fn tier3_crypt_s3_if_match_precondition_and_412() {
    use binary_helpers::*;
    use rship::backends::s3::{S3Backend, S3Config, S3Credentials, S3Provider};
    use rship::core::backend::{
        BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit,
    };
    use rship::core::path::RelPath;
    use rship::core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
    use rship::crypto::{CryptoBackend, CryptoConfig, MasterKey};
    use rship::prelude::*;
    use rship::transport::{HttpTransport, TransportConfig};
    use s3_mock_helpers::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    let (srv, s3_state) = start_mock_s3("crypt-bkt", true).await;

    let mut s3_cfg = S3Config::new(
        "s3_fast",
        S3Provider::Aws,
        "crypt-bkt",
        S3Credentials {
            access_key_id: "AKIA".into(),
            secret_access_key: "SECRET".into(),
            session_token: None,
        },
    );
    s3_cfg.endpoint = Some(srv.base_url());
    s3_cfg.region = "us-east-1".to_string();
    s3_cfg.force_path_style = Some(true);
    s3_cfg.single_shot_max_bytes = Some(128 * 1024);
    s3_cfg.default_chunk_size = Some(128 * 1024);
    s3_cfg.min_part_bytes_override = Some(64 * 1024);

    let transport = HttpTransport::new(TransportConfig::new()).unwrap();
    let s3_backend = Arc::new(S3Backend::new(s3_cfg, transport, None).unwrap());
    let crypt_backend = CryptoBackend::new(
        s3_backend.clone(),
        CryptoConfig::new("crypt_s3"),
        MasterKey::from_bytes([0x7bu8; 32]).derive_subkeys(),
    )
    .unwrap();

    // (a) Initial sync via RshipClient with 200 KiB file -> triggers S3 multipart
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let v1 = vec![0x41u8; 200 * 1024];
    std::fs::write(src_dir.join("data.bin"), &v1).unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend_arc("s3_fast", s3_backend.clone())
        .remote(
            "crypt_s3",
            CryptRemoteConfig::new("s3_fast:")
                .with_key_hex("7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b"),
        )
        .build()
        .unwrap();
    let rep = client
        .sync(src_dir.to_string_lossy().as_ref(), "crypt_s3:")
        .run()
        .await
        .unwrap();
    assert_eq!(rep.files_transferred, 1);

    let cur_etag = {
        let st = s3_state.lock().unwrap();
        assert_eq!(st.objects.len(), 1);
        st.objects.values().next().unwrap().etag.clone()
    };
    let existing = crypt_backend
        .stat(&BackendPath::from_rel(RelPath::parse("data.bin").unwrap()))
        .await
        .unwrap()
        .expect("stat after initial sync");

    // (b) Overwrite via CryptoBackend chunked upload with matching Existing ETag -> CompleteMultipartUpload sends If-Match
    let v2 = vec![0x42u8; 200 * 1024];
    let pre_ok = DstPrecondition::Existing {
        size: existing.size,
        mtime_ns: existing.mtime_ns,
        etag: Some(cur_etag.clone()),
        node_id: existing.node_id.clone(),
    };
    let init2 = UploadInit {
        op_id: "op-cs3-2".to_string(),
        dst_path: RelPath::parse("data.bin").unwrap(),
        existing_node_id: existing.node_id.clone(),
        pregenerated_id: None,
        total_size: v2.len() as u64,
        src_mtime_ns: 1_700_000_050_000_000_000,
        planned_chunk_size: 128 * 1024,
        checksums: Vec::new(),
        precondition: pre_ok.clone(),
        src_etag: None,
    };
    let s2 = crypt_backend.begin_upload(&init2).await.unwrap();
    let op2 = OperationRecord {
        op_id: init2.op_id.clone(),
        session_key: "sk-cs3-2".into(),
        job_id: "j-cs3".into(),
        src_endpoint: "local://s".into(),
        dst_endpoint: crypt_backend.endpoint_identity(),
        src_raw_path: "data.bin".into(),
        dst_raw_path: "data.bin".into(),
        dst_nfc_path: init2.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init2.total_size,
            mtime_ns: init2.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: pre_ok,
        existing_dst_node_id: existing.node_id.clone(),
        remote_op_id: s2.remote_op_id.clone(),
        backend_kind: "crypt".into(),
        session_token: Some(s2.session_token.clone()),
        backend_meta: s2.backend_meta.clone(),
        planned_chunk_size: 128 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1_700_000_050,
        updated_at: 1_700_000_050,
        expires_at: None,
    };
    let mut parts = Vec::new();
    for (idx, chunk) in v2.chunks(128 * 1024).enumerate() {
        let off = (idx * 128 * 1024) as u64;
        let ack = crypt_backend
            .upload_chunk(
                &op2,
                ChunkUpload::new(
                    idx as u32 + 1,
                    off,
                    chunk.len() as u64,
                    v2.len() as u64,
                    make_byte_stream(chunk.to_vec()),
                ),
            )
            .await
            .unwrap();
        parts.push(CompletedPart {
            part_number: idx as u32 + 1,
            offset: off,
            length: chunk.len() as u64,
            etag: ack.etag.unwrap_or_default(),
            checksum: ack.checksum,
        });
    }
    let committed = crypt_backend.finish_upload(&op2, &parts).await.unwrap();
    assert_eq!(committed.size, v2.len() as u64);
    assert!(
        srv.requests().iter().any(|r| {
            r.method == "POST"
                && r.query_get("uploadId").is_some()
                && r.header("if-match") == Some(cur_etag.as_str())
        }),
        "CompleteMultipartUpload must carry If-Match: {cur_etag}"
    );

    // (c) Stale ETag -> 412 -> ErrorKind::PreconditionFailed
    let stale_pre = DstPrecondition::Existing {
        size: committed.size,
        mtime_ns: committed.mtime_ns,
        etag: Some("\"stale-etag\"".to_string()),
        node_id: committed.node_id.clone(),
    };
    let err_stale = crypt_backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-cs3-stale".to_string(),
                dst_path: RelPath::parse("data.bin").unwrap(),
                existing_node_id: committed.node_id,
                pregenerated_id: None,
                total_size: 16,
                src_mtime_ns: 1_700_000_060_000_000_000,
                planned_chunk_size: 128 * 1024,
                checksums: Vec::new(),
                precondition: stale_pre,
                src_etag: None,
            },
            make_byte_stream(vec![9u8; 16]),
        )
        .await
        .expect_err("stale If-Match must fail 412");
    assert_eq!(err_stale.kind(), ErrorKind::PreconditionFailed);
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn tier3_rclone_import_gdrive_use_trash_default_and_delete() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;

    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "GET" && req.path == "/files" {
            let q = req.query_get("q").unwrap_or_default();
            if q.contains("name = 'doc.txt'") {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "files": [{
                            "id": "f1",
                            "name": "doc.txt",
                            "mimeType": "application/octet-stream",
                            "size": "4",
                            "modifiedTime": "2026-01-01T00:00:00.000Z",
                            "parents": ["root"],
                            "trashed": false
                        }]
                    }),
                ));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "files": [] }),
            ));
        }
        if req.method == "PATCH" && req.path == "/files/f1" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "id": "f1",
                    "name": "doc.txt",
                    "mimeType": "application/octet-stream",
                    "size": "4",
                    "trashed": true
                }),
            ));
        }
        if req.method == "DELETE" && req.path == "/files/f1" {
            return MockAction::Respond(MockResponse::empty(204));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let conf = r#"
[gd_def]
type = drive
client_id = cid-1

[gd_perm]
type = drive
client_id = cid-1
use_trash = false
"#;
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, conf, &paths, true, false).unwrap();

    if let Some(RemoteConfig::Gdrive(gd)) = app_cfg.remotes.get_mut("gd_def") {
        assert_eq!(
            gd.use_trash,
            Some(true),
            "omitted use_trash must default to true"
        );
        gd.client_id = None;
        gd.api_base_url = Some(srv.base_url());
        gd.access_token = Some("tok-1".to_string());
    }
    if let Some(RemoteConfig::Gdrive(gd)) = app_cfg.remotes.get_mut("gd_perm") {
        assert_eq!(gd.use_trash, Some(false));
        gd.client_id = None;
        gd.api_base_url = Some(srv.base_url());
        gd.access_token = Some("tok-1".to_string());
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();

    client.delete("gd_def:doc.txt").await.unwrap();
    let reqs_def = srv.take_requests();
    assert!(reqs_def.iter().any(|r| {
        r.method == "PATCH"
            && r.path == "/files/f1"
            && r.body_json().is_ok_and(|j| j["trashed"] == true)
    }));
    assert!(!reqs_def.iter().any(|r| r.method == "DELETE"));

    client.delete("gd_perm:doc.txt").await.unwrap();
    let reqs_perm = srv.take_requests();
    assert!(
        reqs_perm
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/files/f1")
    );
}

#[cfg(all(feature = "s3", feature = "local"))]
#[tokio::test]
async fn tier3_rclone_import_s3_sse_and_disable_checksum() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;

    let srv = MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/b") => MockAction::Respond(
            MockResponse::ok(
                br#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"#.to_vec(),
            )
            .with_header("Content-Type", "application/xml"),
        ),
        ("HEAD", "/b/obj.bin") => MockAction::Respond(MockResponse::empty(404)),
        ("PUT", "/b/obj.bin") => MockAction::Respond(
            MockResponse::empty(200)
                .with_header("ETag", "\"etag-kms\"")
                .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
        ),
        _ => MockAction::Respond(MockResponse::empty(404)),
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("obj.bin");
    std::fs::write(&src_file, b"kms-payload").unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));

    let conf = format!(
        "[s3_kms]\n\
         type = s3\n\
         provider = AWS\n\
         access_key_id = AKIAEXAMPLE\n\
         secret_access_key = SECRETKEY\n\
         region = us-east-1\n\
         endpoint = {}\n\
         force_path_style = true\n\
         server_side_encryption = aws:kms\n\
         sse_kms_key_id = arn:aws:kms:us-east-1:123456789012:key/test-key\n\
         disable_checksum = true\n",
        srv.base_url()
    );
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).unwrap();
    if let Some(RemoteConfig::S3(s3)) = app_cfg.remotes.get_mut("s3_kms") {
        s3.bucket = Some("b".to_string());
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();
    let rep = client
        .copy_file(src_file.to_string_lossy().as_ref(), "s3_kms:obj.bin")
        .run()
        .await
        .unwrap();
    assert!(rep.is_success(), "s3 copy_file failed: {:?}", rep.errors);

    let reqs = srv.requests();
    let put = reqs
        .iter()
        .find(|r| r.method == "PUT" && r.path == "/b/obj.bin")
        .expect("PUT /b/obj.bin");
    assert_eq!(put.header("x-amz-server-side-encryption"), Some("aws:kms"));
    assert_eq!(
        put.header("x-amz-server-side-encryption-aws-kms-key-id"),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-key")
    );
    assert!(put.header("x-amz-checksum-crc32c").is_none());
    assert!(put.header("x-amz-checksum-crc64nvme").is_none());
}

#[cfg(all(feature = "gcs", feature = "local"))]
#[tokio::test]
async fn tier3_rclone_import_gcs_user_project_and_rclone_mtime() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    let objects: Arc<Mutex<HashMap<String, serde_json::Value>>> =
        Arc::new(Mutex::new(HashMap::new()));
    {
        objects.lock().unwrap().insert(
            "legacy.txt".to_string(),
            serde_json::json!({
                "name": "legacy.txt",
                "size": "6",
                "generation": "1",
                "metadata": { "rship-mtime-ns": "1700000123000000000" }
            }),
        );
    }
    let obj_c = objects.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.method == "POST" && req.path == "/token" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "sa-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ));
        }
        if req.method == "POST" && req.path == "/upload/storage/v1/b/b/o" {
            let ct = req.header("content-type").unwrap_or("");
            let boundary = ct
                .split("boundary=")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            let sep = format!("--{boundary}").into_bytes();
            let body = &req.body;
            let meta: serde_json::Value =
                if let Some(p1) = body.windows(sep.len()).position(|w| w == sep.as_slice()) {
                    let after1 = &body[p1 + sep.len()..];
                    let h_end = after1
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .unwrap_or(0);
                    let p1_body = &after1[h_end + 4..];
                    let p2 = p1_body
                        .windows(sep.len())
                        .position(|w| w == sep.as_slice())
                        .unwrap_or(p1_body.len());
                    serde_json::from_slice(
                        p1_body[..p2]
                            .strip_suffix(b"\r\n")
                            .unwrap_or(&p1_body[..p2]),
                    )
                    .unwrap_or_default()
                } else {
                    serde_json::Value::Null
                };
            let res = serde_json::json!({
                "name": "f.txt",
                "size": "7",
                "generation": "2",
                "metadata": meta.get("metadata").cloned().unwrap_or_default()
            });
            obj_c
                .lock()
                .unwrap()
                .insert("f.txt".to_string(), res.clone());
            return MockAction::Respond(MockResponse::json(200, &res));
        }
        if req.method == "GET" && req.path == "/storage/v1/b/b/o/f.txt" {
            if let Some(obj) = obj_c.lock().unwrap().get("f.txt").cloned() {
                return MockAction::Respond(MockResponse::json(200, &obj));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "GET" && req.path == "/storage/v1/b/b/o/legacy.txt" {
            if let Some(obj) = obj_c.lock().unwrap().get("legacy.txt").cloned() {
                return MockAction::Respond(MockResponse::json(200, &obj));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let sa_path = tmp.path().join("sa.json");
    std::fs::write(
        &sa_path,
        serde_json::to_vec(&serde_json::json!({
            "type": "service_account",
            "client_email": "sa@proj.iam.gserviceaccount.com",
            "private_key": TEST_SA_KEY_PEM,
            "token_uri": srv.url("/token")
        }))
        .unwrap(),
    )
    .unwrap();
    let src_file = tmp.path().join("f.txt");
    std::fs::write(&src_file, b"gcs-m5!").unwrap();

    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let conf = format!(
        "[gcs_up]\n\
         type = google cloud storage\n\
         endpoint = {}\n\
         user_project = billing-proj\n\
         service_account_file = {}\n",
        srv.base_url(),
        sa_path.display()
    );
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).unwrap();
    if let Some(RemoteConfig::Gcs(gcs)) = app_cfg.remotes.get_mut("gcs_up") {
        gcs.bucket = Some("b".to_string());
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();
    let rep = client
        .copy_file(src_file.to_string_lossy().as_ref(), "gcs_up:f.txt")
        .run()
        .await
        .unwrap();
    assert!(rep.is_success(), "gcs copy_file failed: {:?}", rep.errors);

    let st_new = client
        .stat("gcs_up:f.txt")
        .await
        .unwrap()
        .expect("stat f.txt");
    let st_old = client
        .stat("gcs_up:legacy.txt")
        .await
        .unwrap()
        .expect("stat legacy.txt");
    assert_eq!(st_old.mtime_ns, 1_700_000_123_000_000_000);
    assert!(st_new.mtime_ns > 0);

    let reqs = srv.requests();
    let gcs_api_reqs: Vec<_> = reqs
        .iter()
        .filter(|r| r.path.starts_with("/storage/") || r.path.starts_with("/upload/"))
        .collect();
    assert!(!gcs_api_reqs.is_empty());
    for r in gcs_api_reqs {
        assert_eq!(
            r.query_get("userProject").as_deref(),
            Some("billing-proj"),
            "missing userProject on {} {}",
            r.method,
            r.path
        );
    }
    let stored = objects.lock().unwrap().get("f.txt").cloned().unwrap();
    assert!(
        stored["metadata"]["goog-reserved-file-mtime"].is_string(),
        "GCS upload metadata must write rclone standard goog-reserved-file-mtime: {stored}"
    );
}

#[cfg(all(feature = "azureblob", feature = "local"))]
#[tokio::test]
async fn tier3_rclone_import_azureblob_container_sas_and_rclone_mtime() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use binary_helpers::*;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    type BlobMap = HashMap<String, (Vec<u8>, Option<String>)>;
    let blobs: Arc<Mutex<BlobMap>> = Arc::new(Mutex::new(HashMap::new()));
    {
        blobs
            .lock()
            .unwrap()
            .insert("legacy.bin".to_string(), (b"old".to_vec(), None));
    }
    let blobs_c = blobs.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.path == "/devstoreaccount1/mycont/up.bin" {
            match req.method.as_str() {
                "HEAD" => {
                    if let Some((data, mtime)) = blobs_c.lock().unwrap().get("up.bin").cloned() {
                        let mut resp = MockResponse::empty(200)
                            .with_header("Content-Length", data.len().to_string())
                            .with_header("ETag", "\"0x1\"");
                        if let Some(mt) = mtime {
                            resp = resp.with_header("x-ms-meta-mtime", mt);
                        }
                        return MockAction::Respond(resp);
                    }
                    return MockAction::Respond(MockResponse::empty(404));
                }
                "PUT" => {
                    let mtime = req.header("x-ms-meta-mtime").map(ToOwned::to_owned);
                    let md5_b64 = base64_encode(&md5_digest(&req.body));
                    blobs_c
                        .lock()
                        .unwrap()
                        .insert("up.bin".to_string(), (req.body.clone(), mtime));
                    return MockAction::Respond(
                        MockResponse::empty(201)
                            .with_header("ETag", "\"0x1\"")
                            .with_header("Content-MD5", md5_b64),
                    );
                }
                _ => {}
            }
        }
        if req.path == "/devstoreaccount1/mycont/legacy.bin" && req.method == "HEAD" {
            return MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Content-Length", "3")
                    .with_header("ETag", "\"0x2\"")
                    .with_header("x-ms-meta-rship_mtime_ns", "1700000456000000000"),
            );
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("up.bin");
    std::fs::write(&src_file, b"azure-sas-m5").unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));

    let conf = format!(
        "[az_sas]\n\
         type = azureblob\n\
         sas_url = {}/devstoreaccount1/mycont?sv=2023-11-03&sig=abc\n",
        srv.base_url()
    );
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).unwrap();

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();
    let rep = client
        .copy_file(src_file.to_string_lossy().as_ref(), "az_sas:up.bin")
        .run()
        .await
        .unwrap();
    assert!(
        rep.is_success(),
        "az_sas copy_file failed: {:?}",
        rep.errors
    );

    let st_up = client
        .stat("az_sas:up.bin")
        .await
        .unwrap()
        .expect("stat up.bin");
    let st_legacy = client
        .stat("az_sas:legacy.bin")
        .await
        .unwrap()
        .expect("stat legacy.bin");
    assert_eq!(st_legacy.mtime_ns, 1_700_000_456_000_000_000);
    assert!(st_up.mtime_ns > 0);

    let reqs = srv.requests();
    let put = reqs
        .iter()
        .find(|r| r.method == "PUT" && r.path == "/devstoreaccount1/mycont/up.bin")
        .expect("PUT /devstoreaccount1/mycont/up.bin");
    assert_eq!(put.query_get("sv").as_deref(), Some("2023-11-03"));
    assert!(put.header("x-ms-meta-mtime").is_some());
}

#[cfg(all(feature = "webdav", feature = "local"))]
#[tokio::test]
async fn tier3_rclone_import_webdav_local_move_207_source_preservation() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use binary_helpers::*;
    use rship::core::rclone_ini::obscure_rclone_secret_with_iv;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    let files: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let files_c = files.clone();
    let fail_put_207 = Arc::new(AtomicBool::new(true));
    let fail_c = fail_put_207.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let rel = percent_decode_strict(
            req.path
                .strip_prefix("/remote.php/dav/files/alice")
                .unwrap_or("")
                .trim_matches('/'),
        );
        match req.method.as_str() {
            "PROPFIND" => {
                if rel.is_empty() {
                    let mut items = String::from(
                        "<d:response><d:href>/remote.php/dav/files/alice/</d:href>\
                         <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>\
                         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                    );
                    if req.header("depth") == Some("1") {
                        for (k, v) in files_c.lock().unwrap().iter() {
                            items.push_str(&format!(
                                "<d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                                 <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength></d:prop>\
                                 <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                                percent_encode_path(k),
                                v.len()
                            ));
                        }
                    }
                    return MockAction::Respond(MockResponse::new(
                        207,
                        format!("<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">{items}</d:multistatus>")
                            .into_bytes(),
                    ));
                }
                if let Some(v) = files_c.lock().unwrap().get(&rel) {
                    let body = format!(
                        "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                         <d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                         <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength></d:prop>\
                         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
                        percent_encode_path(&rel),
                        v.len()
                    );
                    return MockAction::Respond(MockResponse::new(207, body.into_bytes()));
                }
                MockAction::Respond(MockResponse::empty(404))
            }
            "PUT" => {
                if fail_c.load(Ordering::SeqCst) {
                    return MockAction::Respond(MockResponse::empty(403));
                }
                let md5 = md5_hex(&req.body);
                files_c.lock().unwrap().insert(rel, req.body.clone());
                MockAction::Respond(
                    MockResponse::empty(201)
                        .with_header("ETag", "\"wd-1\"")
                        .with_header("X-Hash-MD5", md5)
                        .with_header("X-OC-Mtime", "accepted"),
                )
            }
            "DELETE" => {
                let body = format!(
                    "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                     <d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                     <d:status>HTTP/1.1 403 Forbidden</d:status></d:response></d:multistatus>",
                    percent_encode_path(&rel)
                );
                MockAction::Respond(MockResponse::new(207, body.into_bytes()))
            }
            "MKCOL" => MockAction::Respond(MockResponse::empty(201)),
            _ => MockAction::Respond(MockResponse::empty(404)),
        }
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let local_file = src_dir.join("keep_safe.txt");
    std::fs::write(&local_file, b"precious-local-bytes").unwrap();

    let obs = obscure_rclone_secret_with_iv("pw-nc", [0x33u8; 16]);
    let conf = format!(
        "[nc]\n\
         type = webdav\n\
         url = {}\n\
         vendor = nextcloud\n\
         user = alice\n\
         pass = {obs}\n",
        srv.url("/remote.php/dav/files/alice")
    );
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).unwrap();

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();

    let rep_fail = client
        .move_path(src_dir.to_string_lossy().as_ref(), "nc:")
        .run()
        .await
        .unwrap();
    assert!(!rep_fail.is_success());
    assert!(!rep_fail.errors.is_empty());
    assert!(local_file.exists(), "local source MUST survive failed move");
    assert_eq!(std::fs::read(&local_file).unwrap(), b"precious-local-bytes");

    fail_put_207.store(false, Ordering::SeqCst);
    let rep_ok = client
        .move_path(src_dir.to_string_lossy().as_ref(), "nc:")
        .run()
        .await
        .unwrap();
    assert!(rep_ok.is_success());
    assert!(
        !local_file.exists(),
        "local source deleted only after verified commit"
    );
    assert_eq!(
        files
            .lock()
            .unwrap()
            .get("keep_safe.txt")
            .map(Vec::as_slice),
        Some(b"precious-local-bytes".as_slice())
    );

    // Also verify 207 Multi-Status 403 Forbidden fails PermissionDenied via imported WebDAV client
    let del_err = client
        .delete("nc:keep_safe.txt")
        .await
        .expect_err("207 403 Forbidden on DELETE must fail");
    assert_eq!(del_err.kind(), ErrorKind::PermissionDenied);
}

#[cfg(all(feature = "dropbox", feature = "onedrive", feature = "local"))]
#[tokio::test]
async fn tier3_oauth2_429_503_retry_with_dropbox_and_onedrive_sync() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use rship::backends::dropbox::dropbox_content_hash;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    let token_hits = Arc::new(AtomicUsize::new(0));
    let tok_c = token_hits.clone();
    let dbx_files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let dbx_c = dbx_files.clone();
    let od_files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let od_c = od_files.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.method == "POST" && req.path == "/token" {
            let n = tok_c.fetch_add(1, Ordering::SeqCst);
            return match n % 3 {
                0 => MockAction::Respond(MockResponse::empty(503)),
                1 => MockAction::Respond(MockResponse::empty(429).with_header("Retry-After", "0")),
                _ => MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "access_token": "fresh-tok",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }),
                )),
            };
        }
        // Require refreshed token on all provider calls
        if req.header("authorization") != Some("Bearer fresh-tok") {
            return MockAction::Respond(MockResponse::empty(401));
        }

        // Dropbox endpoints
        if req.path == "/api/2/files/list_folder" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "entries": [], "cursor": "c1", "has_more": false }),
            ));
        }
        if req.path == "/api/2/files/get_metadata" {
            return MockAction::Respond(MockResponse::json(
                409,
                &serde_json::json!({
                    "error_summary": "path/not_found/.",
                    "error": { ".tag": "path", "path": { ".tag": "not_found" } }
                }),
            ));
        }
        if req.path == "/content/2/files/upload" {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let path = arg["path"].as_str().unwrap_or("/up.txt").to_string();
            let hash = dropbox_content_hash(&req.body);
            dbx_c.lock().unwrap().insert(path.clone(), req.body.clone());
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    ".tag": "file",
                    "name": path.trim_start_matches('/'),
                    "path_lower": path.to_ascii_lowercase(),
                    "path_display": path,
                    "id": "id:dbx-1",
                    "client_modified": "2026-01-01T00:00:00Z",
                    "server_modified": "2026-01-01T00:00:00Z",
                    "rev": "015a",
                    "size": req.body.len(),
                    "is_downloadable": true,
                    "content_hash": hash
                }),
            ));
        }

        // OneDrive endpoints
        if req.method == "GET" && req.path == "/me/drive/root/children" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "value": [] }),
            ));
        }
        if req.method == "GET"
            && req.path.starts_with("/me/drive/root:/")
            && req.path.ends_with(':')
        {
            return MockAction::Respond(MockResponse::empty(404));
        }
        if req.method == "PUT"
            && let Some(rel) = req
                .path
                .strip_prefix("/me/drive/root:/")
                .and_then(|s| s.strip_suffix(":/content"))
        {
            od_c.lock()
                .unwrap()
                .insert(rel.to_string(), req.body.clone());
            return MockAction::Respond(MockResponse::json(
                201,
                &serde_json::json!({
                    "id": "od-item-1",
                    "name": rel,
                    "size": req.body.len(),
                    "eTag": "\"od-e1\"",
                    "file": {},
                    "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" }
                }),
            ));
        }
        if req.method == "PATCH" && req.path == "/me/drive/items/od-item-1" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "id": "od-item-1",
                    "name": "od.txt",
                    "size": 7,
                    "eTag": "\"od-e1\"",
                    "file": {},
                    "fileSystemInfo": { "lastModifiedDateTime": "2026-01-01T00:00:00Z" }
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_a = tmp.path().join("src_a");
    let src_b = tmp.path().join("src_b");
    std::fs::create_dir_all(&src_a).unwrap();
    std::fs::create_dir_all(&src_b).unwrap();
    std::fs::write(src_a.join("dbx.txt"), b"dbx-body").unwrap();
    std::fs::write(src_b.join("od.txt"), b"od-body").unwrap();

    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let conf = r#"
[dbx]
type = dropbox
client_id = cid-dbx
client_secret = csec-dbx
token = {"access_token":"expired-dbx","token_type":"Bearer","refresh_token":"ref-dbx","expiry":"2020-01-01T00:00:00Z"}

[od]
type = onedrive
client_id = cid-od
client_secret = csec-od
token = {"access_token":"expired-od","token_type":"Bearer","refresh_token":"ref-od","expiry":"2020-01-01T00:00:00Z"}
"#;
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, conf, &paths, true, false).unwrap();
    if let Some(RemoteConfig::Dropbox(dbx)) = app_cfg.remotes.get_mut("dbx") {
        dbx.api_base_url = Some(srv.url("/api/2"));
        dbx.content_base_url = Some(srv.url("/content/2"));
        dbx.token_url = Some(srv.url("/token"));
    }
    if let Some(RemoteConfig::Onedrive(od)) = app_cfg.remotes.get_mut("od") {
        od.api_base_url = Some(srv.base_url());
        od.token_url = Some(srv.url("/token"));
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();

    let r_dbx = client
        .sync(src_a.to_string_lossy().as_ref(), "dbx:")
        .run()
        .await
        .unwrap();
    assert!(r_dbx.is_success());
    let r_od = client
        .sync(src_b.to_string_lossy().as_ref(), "od:")
        .run()
        .await
        .unwrap();
    assert!(r_od.is_success());

    assert_eq!(
        dbx_files.lock().unwrap().get("/dbx.txt").map(Vec::as_slice),
        Some(b"dbx-body".as_slice())
    );
    assert_eq!(
        od_files.lock().unwrap().get("od.txt").map(Vec::as_slice),
        Some(b"od-body".as_slice())
    );
    assert!(
        token_hits.load(Ordering::SeqCst) >= 6,
        "expected >= 6 /token hits across 503+429+200 for both remotes"
    );
}

#[cfg(all(feature = "local", feature = "sqlite"))]
#[tokio::test]
async fn tier3_local_sqlite_persistent_journal_sync_and_baseline_skip() {
    use rship::prelude::*;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    let cfg_path = tmp.path().join("config.toml");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("b.txt"), b"beta").unwrap();

    let client = RshipClient::builder()
        .paths(AppPaths::new(cfg_path, &state_dir))
        .build()
        .unwrap();
    assert!(client.state_actor().unwrap().is_some());

    let rep1 = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .baseline_mode(BaselineMode::All)
        .job_id("j-sqlite-1")
        .run()
        .await
        .unwrap();
    assert_eq!(rep1.files_transferred, 2);
    assert!(state_dir.join("journal.db").exists());
    assert!(state_dir.join("baselines").exists());

    let jobs = client.journal().unwrap().list_jobs(10).await.unwrap();
    let job = jobs
        .iter()
        .find(|j| j.job_id == "j-sqlite-1")
        .expect("j-sqlite-1 recorded in SQLite journal");
    assert_eq!(job.status, JobStatus::Completed);

    let rep2 = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .baseline_mode(BaselineMode::All)
        .run()
        .await
        .unwrap();
    assert_eq!(rep2.files_transferred, 0);
    assert_eq!(rep2.files_skipped, 2);

    client.flush().await.unwrap();
    client.shutdown().await.unwrap();

    let post_shutdown = client
        .sync(
            src.to_string_lossy().as_ref(),
            dst.to_string_lossy().as_ref(),
        )
        .run()
        .await
        .expect_err("sync after shutdown must fail");
    assert!(post_shutdown.is_cancelled());
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn tier3_rclone_import_sftp_endpoint_identity_and_encrypted_conf_rejection() {
    use rship::backends::sftp::{SftpAuth, SftpBackend, SftpConfig, try_parse_rclone_sftp_conf};
    use rship::core::backend::StorageBackend;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;

    let enc_err = try_parse_rclone_sftp_conf("RCLONE_ENCRYPT_V0:\nYWJj\n")
        .expect_err("try_parse_rclone_sftp_conf must reject RCLONE_ENCRYPT_V0:");
    assert!(enc_err.is_config());

    let parsed = try_parse_rclone_sftp_conf(
        "[sf_opts]\n\
         type = sftp\n\
         host = 10.0.0.5\n\
         known_hosts_file = ~/.ssh/known_hosts\n\
         key_pem = -----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    assert_eq!(parsed.remotes.len(), 1);
    assert!(!parsed.remotes[0].user.is_empty());
    assert!(parsed.remotes[0].key_pem.as_deref().unwrap().contains('\n'));

    let mut cfg_slash = SftpConfig::new(
        "sf_slash",
        "10.0.0.5",
        "alice",
        SftpAuth::Password("pw".into()),
    );
    cfg_slash.root_path = "/".to_string();
    let b_slash = SftpBackend::new(cfg_slash).unwrap();

    let mut cfg_rel = SftpConfig::new(
        "sf_rel",
        "10.0.0.5",
        "alice",
        SftpAuth::Password("pw".into()),
    );
    cfg_rel.root_path = "data".to_string();
    let b_rel = SftpBackend::new(cfg_rel).unwrap();

    assert_eq!(b_slash.endpoint_identity(), "sftp://alice@10.0.0.5:22//");
    assert_ne!(b_slash.endpoint_identity(), b_rel.endpoint_identity());

    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(
        &mut app_cfg,
        "[sf_root]\ntype = sftp\nhost = 10.0.0.5\nuser = alice\npass = pw\n",
        &paths,
        true,
        false,
    )
    .unwrap();
    if let Some(RemoteConfig::Sftp(sf)) = app_cfg.remotes.get_mut("sf_root") {
        sf.root_path = Some("/".to_string());
    }
    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();
    let (resolved, _) = client.resolve("sf_root:").unwrap();
    assert_eq!(resolved.endpoint_identity(), "sftp://alice@10.0.0.5:22//");
}

#[cfg(feature = "local")]
#[tokio::test]
async fn tier3_local_rclone_import_encrypted_conf_rejects_and_clean_state() {
    use rship::core::rclone_ini::parse_rclone_ini;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use tempfile::TempDir;

    let raw = "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
    let ini_err = parse_rclone_ini(raw).expect_err("parse_rclone_ini rejects encrypted conf");
    assert!(ini_err.is_config());

    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), &state_dir);

    let mut app_cfg = AppConfig::new();
    let imp_err = import_rclone_conf(&mut app_cfg, raw, &paths, true, false)
        .expect_err("import_rclone_conf must reject RCLONE_ENCRYPT_V0:");
    assert!(imp_err.is_config());

    let b_err = RshipClient::builder()
        .state_dir(&state_dir)
        .rclone_conf_str(raw)
        .build()
        .expect_err("ClientBuilder::rclone_conf_str must fail fast on encrypted conf");
    assert!(b_err.is_config());
    assert!(
        !state_dir.exists() || std::fs::read_dir(&state_dir).unwrap().next().is_none(),
        "failed encrypted rclone_conf_str must leave zero files in state_dir"
    );
}

// ===========================================================================
// Tier 4 — Real-World SDK Application Scenarios (4 scenarios, 0 #[ignore])
// ===========================================================================

#[cfg(all(feature = "local", feature = "crypt", feature = "s3"))]
#[tokio::test]
async fn tier4_scenario_encrypted_nfd_sync_check_overwrite_and_delete() {
    use local_helpers::*;
    use rship::backends::s3::{S3Backend, S3Config, S3Credentials, S3Provider};
    use rship::core::backend::ListOptions;
    use rship::prelude::*;
    use rship::transport::{HttpTransport, TransportConfig};
    use s3_mock_helpers::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    let (srv, s3_state) = start_mock_s3("t4-bkt", true).await;

    let mut s3_cfg = S3Config::new(
        "s3_t4",
        S3Provider::Aws,
        "t4-bkt",
        S3Credentials {
            access_key_id: "AKIA".into(),
            secret_access_key: "SECRET".into(),
            session_token: None,
        },
    );
    s3_cfg.endpoint = Some(srv.base_url());
    s3_cfg.region = "us-east-1".to_string();
    s3_cfg.force_path_style = Some(true);
    s3_cfg.single_shot_max_bytes = Some(64 * 1024);
    s3_cfg.default_chunk_size = Some(64 * 1024);
    s3_cfg.min_part_bytes_override = Some(64 * 1024);

    let transport = HttpTransport::new(TransportConfig::new()).unwrap();
    let s3_backend = Arc::new(S3Backend::new(s3_cfg, transport, None).unwrap());

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("cafe\u{0301}").join("sub")).unwrap();
    std::fs::create_dir_all(src.join("docs")).unwrap();

    let note_v1 = vec![0x61u8; 1024];
    let readme_v1 = vec![0x62u8; 512];
    let big_v1 = vec![0x63u8; 160 * 1024];
    std::fs::write(
        src.join("cafe\u{0301}").join("sub").join("note.txt"),
        &note_v1,
    )
    .unwrap();
    std::fs::write(src.join("docs").join("readme.md"), &readme_v1).unwrap();
    std::fs::write(src.join("big.bin"), &big_v1).unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend_arc("s3_t4", s3_backend)
        .remote(
            "crypt_s3",
            CryptRemoteConfig::new("s3_t4:")
                .with_key_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        )
        .build()
        .unwrap();

    // 1. Initial sync -> 3 files, big.bin uses S3 multipart, raw S3 keys are encrypted
    let r1 = client
        .sync(src.to_string_lossy().as_ref(), "crypt_s3:")
        .run()
        .await
        .unwrap();
    assert_eq!(r1.files_transferred, 3);
    {
        let st = s3_state.lock().unwrap();
        let file_objs: Vec<_> = st.objects.keys().filter(|k| !k.ends_with('/')).collect();
        assert_eq!(file_objs.len(), 3);
        assert!(
            file_objs
                .iter()
                .all(|k| !k.contains("note.txt") && !k.contains("big.bin"))
        );
    }
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.method == "POST" && r.query_get("uploads").is_some())
    );

    // 2. Parity check (list recursive -> NFC paths, stat + open_read decrypt, checksum sync -> 0 transfers)
    let listed = collect_entries(
        client
            .list("crypt_s3:", &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let file_paths: Vec<&str> = listed
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.nfc_path.as_str())
        .collect();
    assert!(file_paths.contains(&"caf\u{00e9}/sub/note.txt"));
    assert!(file_paths.contains(&"docs/readme.md"));
    assert!(file_paths.contains(&"big.bin"));
    assert_eq!(
        read_all_from_source(
            client
                .open_read("crypt_s3:caf\u{00e9}/sub/note.txt", None)
                .await
                .unwrap()
        )
        .await
        .unwrap(),
        note_v1
    );
    assert_eq!(
        read_all_from_source(
            client
                .open_read("crypt_s3:docs/readme.md", None)
                .await
                .unwrap()
        )
        .await
        .unwrap(),
        readme_v1
    );
    assert_eq!(
        read_all_from_source(client.open_read("crypt_s3:big.bin", None).await.unwrap())
            .await
            .unwrap(),
        big_v1
    );
    let check_rep = client
        .sync(src.to_string_lossy().as_ref(), "crypt_s3:")
        .run()
        .await
        .unwrap();
    assert_eq!(check_rep.files_transferred, 0);
    assert_eq!(check_rep.files_skipped, 3);

    // 3. Overwrite big.bin -> 200 KiB + newer mtime -> multipart CompleteMultipartUpload with If-Match
    let big_v2 = vec![0x64u8; 200 * 1024];
    std::fs::write(src.join("big.bin"), &big_v2).unwrap();
    let _ = srv.take_requests();
    let r2 = client
        .sync(src.to_string_lossy().as_ref(), "crypt_s3:")
        .run()
        .await
        .unwrap();
    assert_eq!(r2.files_transferred, 1);
    assert!(srv.requests().iter().any(|r| r.method == "POST"
        && r.query_get("uploadId").is_some()
        && r.header("if-match").is_some()));
    assert_eq!(
        read_all_from_source(client.open_read("crypt_s3:big.bin", None).await.unwrap())
            .await
            .unwrap(),
        big_v2
    );

    // 4. Delete readme.md via sync(delete=true) and explicit delete big.bin
    std::fs::remove_file(src.join("docs").join("readme.md")).unwrap();
    let r3 = client
        .sync(src.to_string_lossy().as_ref(), "crypt_s3:")
        .delete(true)
        .run()
        .await
        .unwrap();
    assert!(r3.items_deleted >= 1);
    assert!(
        client
            .stat("crypt_s3:docs/readme.md")
            .await
            .unwrap()
            .is_none()
    );

    client.delete("crypt_s3:big.bin").await.unwrap();
    assert!(client.stat("crypt_s3:big.bin").await.unwrap().is_none());
}

#[cfg(all(
    feature = "local",
    feature = "sqlite",
    feature = "gdrive",
    feature = "dropbox"
))]
#[tokio::test]
async fn tier4_scenario_rclone_import_multi_provider_oauth_recovery_and_sqlite_journal() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use local_helpers::*;
    use rship::backends::dropbox::dropbox_content_hash;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    let token_hits = Arc::new(AtomicUsize::new(0));
    let tok_c = token_hits.clone();
    let gd_upload_503_once = Arc::new(AtomicBool::new(true));
    let gd_503_c = gd_upload_503_once.clone();
    type GdriveFileMap = HashMap<String, (String, Vec<u8>)>;
    let gd_files: Arc<Mutex<GdriveFileMap>> = Arc::new(Mutex::new(HashMap::new()));
    let gd_c = gd_files.clone();
    let dbx_files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let dbx_c = dbx_files.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.method == "POST" && req.path == "/token" {
            let n = tok_c.fetch_add(1, Ordering::SeqCst);
            return match n % 3 {
                0 => MockAction::Respond(MockResponse::empty(503)),
                1 => MockAction::Respond(MockResponse::empty(429).with_header("Retry-After", "0")),
                _ => MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "access_token": "tok-v2",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }),
                )),
            };
        }
        if req.header("authorization") != Some("Bearer tok-v2") {
            return MockAction::Respond(MockResponse::empty(401));
        }

        // GDrive
        if req.method == "GET" && req.path == "/files/generateIds" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "ids": ["gd-id-1", "gd-id-2"] }),
            ));
        }
        if req.method == "GET" && req.path == "/files" {
            let q = req.query_get("q").unwrap_or_default();
            let list: Vec<serde_json::Value> = gd_c
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| {
                    !q.contains("name = ") || q.contains(&format!("name = '{name}'"))
                })
                .map(|(name, (id, data))| {
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "mimeType": "application/octet-stream",
                        "size": data.len().to_string(),
                        "modifiedTime": "2026-01-01T00:00:00.000Z",
                        "parents": ["root"],
                        "trashed": false
                    })
                })
                .collect();
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "files": list }),
            ));
        }
        if req.method == "POST" && req.path == "/files" {
            if gd_503_c.swap(false, Ordering::SeqCst) {
                return MockAction::Respond(MockResponse::json(
                    503,
                    &serde_json::json!({ "error": { "code": 503, "message": "Backend Error" } }),
                ));
            }
            let ct = req.header("content-type").unwrap_or("");
            let boundary = ct
                .split("boundary=")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            let sep = format!("--{boundary}").into_bytes();
            let body = &req.body;
            let p1 = body
                .windows(sep.len())
                .position(|w| w == sep.as_slice())
                .unwrap();
            let a1 = &body[p1 + sep.len()..];
            let h1 = a1.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let p1b = &a1[h1 + 4..];
            let p2 = p1b
                .windows(sep.len())
                .position(|w| w == sep.as_slice())
                .unwrap();
            let meta: serde_json::Value =
                serde_json::from_slice(p1b[..p2].strip_suffix(b"\r\n").unwrap_or(&p1b[..p2]))
                    .unwrap();
            let a2 = &p1b[p2 + sep.len()..];
            let h2 = a2.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let data_start = &a2[h2 + 4..];
            let end_sep = format!("\r\n--{boundary}--").into_bytes();
            let end_pos = data_start
                .windows(end_sep.len())
                .position(|w| w == end_sep.as_slice())
                .unwrap();
            let data = data_start[..end_pos].to_vec();
            let name = meta["name"].as_str().unwrap_or("file").to_string();
            let id = meta["id"].as_str().unwrap_or("gd-id-auto").to_string();
            gd_c.lock()
                .unwrap()
                .insert(name.clone(), (id.clone(), data.clone()));
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "id": id,
                    "name": name,
                    "mimeType": "application/octet-stream",
                    "size": data.len().to_string(),
                    "modifiedTime": "2026-01-01T00:00:00.000Z",
                    "parents": ["root"],
                    "trashed": false
                }),
            ));
        }
        if let Some(id) = req.path.strip_prefix("/files/")
            && req.method == "GET"
            && req.query_get("alt").as_deref() == Some("media")
        {
            if let Some((_, (_, data))) =
                gd_c.lock().unwrap().iter().find(|(_, (fid, _))| fid == id)
            {
                return MockAction::Respond(MockResponse::ok(data.clone()));
            }
            return MockAction::Respond(MockResponse::empty(404));
        }

        // Dropbox
        if req.path == "/api/2/files/list_folder" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "entries": [], "cursor": "c1", "has_more": false }),
            ));
        }
        if req.path == "/api/2/files/get_metadata" {
            return MockAction::Respond(MockResponse::json(
                409,
                &serde_json::json!({
                    "error_summary": "path/not_found/.",
                    "error": { ".tag": "path", "path": { ".tag": "not_found" } }
                }),
            ));
        }
        if req.path == "/content/2/files/upload" {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let path = arg["path"].as_str().unwrap_or("/up").to_string();
            let hash = dropbox_content_hash(&req.body);
            dbx_c.lock().unwrap().insert(path.clone(), req.body.clone());
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    ".tag": "file",
                    "name": path.trim_start_matches('/'),
                    "path_lower": path.to_ascii_lowercase(),
                    "path_display": path,
                    "id": "id:dbx-r4",
                    "client_modified": "2026-01-01T00:00:00Z",
                    "server_modified": "2026-01-01T00:00:00Z",
                    "rev": "016b",
                    "size": req.body.len(),
                    "is_downloadable": true,
                    "content_hash": hash
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_a = tmp.path().join("src_a");
    let src_b = tmp.path().join("src_b");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_a).unwrap();
    std::fs::create_dir_all(&src_b).unwrap();
    std::fs::write(src_a.join("report.txt"), b"gdrive-data").unwrap();
    std::fs::write(src_b.join("bundle.bin"), b"dropbox-move-data").unwrap();

    let paths = AppPaths::new(tmp.path().join("cfg.toml"), &state_dir);
    let conf = r#"
[gd]
type = drive
client_id = cid-gd
client_secret = csec-gd
token = {"access_token":"old-gd","token_type":"Bearer","refresh_token":"ref-gd","expiry":"2020-01-01T00:00:00Z"}

[dbx]
type = dropbox
client_id = cid-dbx
client_secret = csec-dbx
token = {"access_token":"old-dbx","token_type":"Bearer","refresh_token":"ref-dbx","expiry":"2020-01-01T00:00:00Z"}
"#;
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, conf, &paths, true, false).unwrap();
    if let Some(RemoteConfig::Gdrive(gd)) = app_cfg.remotes.get_mut("gd") {
        gd.api_base_url = Some(srv.base_url());
        gd.upload_base_url = Some(srv.base_url());
        gd.token_url = Some(srv.url("/token"));
    }
    if let Some(RemoteConfig::Dropbox(dbx)) = app_cfg.remotes.get_mut("dbx") {
        dbx.api_base_url = Some(srv.url("/api/2"));
        dbx.content_base_url = Some(srv.url("/content/2"));
        dbx.token_url = Some(srv.url("/token"));
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .allow_changes_feed(false)
        .build()
        .unwrap();

    let rep_gd = client
        .copy(src_a.to_string_lossy().as_ref(), "gd:")
        .job_id("job-gd-copy")
        .run()
        .await
        .unwrap();
    assert!(rep_gd.is_success());
    assert_eq!(
        read_all_from_source(client.open_read("gd:report.txt", None).await.unwrap())
            .await
            .unwrap(),
        b"gdrive-data"
    );

    let rep_dbx = client
        .move_path(src_b.to_string_lossy().as_ref(), "dbx:")
        .job_id("job-dbx-move")
        .run()
        .await
        .unwrap();
    assert!(rep_dbx.is_success());
    assert!(!src_b.join("bundle.bin").exists());
    assert_eq!(
        dbx_files
            .lock()
            .unwrap()
            .get("/bundle.bin")
            .map(Vec::as_slice),
        Some(b"dropbox-move-data".as_slice())
    );

    assert!(state_dir.join("journal.db").exists());
    let jobs = client.journal().unwrap().list_jobs(10).await.unwrap();
    assert!(
        jobs.iter()
            .any(|j| j.job_id == "job-gd-copy" && j.status == JobStatus::Completed)
    );
    assert!(
        jobs.iter()
            .any(|j| j.job_id == "job-dbx-move" && j.status == JobStatus::Completed)
    );
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();
}

#[cfg(all(feature = "local", feature = "webdav"))]
#[tokio::test]
async fn tier4_scenario_webdav_nextcloud_chunked_upload_and_207_move_safety() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use binary_helpers::*;
    use rship::backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};
    use rship::prelude::*;
    use rship::transport::{HttpTransport, TransportConfig};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct NcState {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeSet<String>,
        uploads: HashMap<String, BTreeMap<u32, Vec<u8>>>,
        inject_207_on_assemble: AtomicBool,
    }
    let state = Arc::new(Mutex::new(NcState {
        files: BTreeMap::new(),
        dirs: BTreeSet::new(),
        uploads: HashMap::new(),
        inject_207_on_assemble: AtomicBool::new(true),
    }));
    let st_c = state.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let mut st = st_c.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(up_rest) = req
            .path
            .strip_prefix("/remote.php/dav/uploads/alice/")
            .map(|s| s.trim_matches('/'))
        {
            let parts: Vec<&str> = up_rest.split('/').filter(|s| !s.is_empty()).collect();
            return match (req.method.as_str(), parts.as_slice()) {
                ("MKCOL", [op_id]) => {
                    st.uploads.insert((*op_id).to_string(), BTreeMap::new());
                    MockAction::Respond(MockResponse::empty(201))
                }
                ("PUT", [op_id, pn_str]) => {
                    let pn = pn_str.parse::<u32>().unwrap_or(0);
                    let md5 = md5_hex(&req.body);
                    if let Some(m) = st.uploads.get_mut(*op_id) {
                        m.insert(pn, req.body.clone());
                    }
                    MockAction::Respond(MockResponse::empty(201).with_header("X-Hash-MD5", md5))
                }
                ("PROPFIND", [op_id]) => {
                    let mut items = format!(
                        "<d:response><d:href>/remote.php/dav/uploads/alice/{op_id}/</d:href>\
                         <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>\
                         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
                    );
                    if req.header("depth") == Some("1")
                        && let Some(m) = st.uploads.get(*op_id)
                    {
                        for (pn, bytes) in m {
                            items.push_str(&format!(
                                "<d:response><d:href>/remote.php/dav/uploads/alice/{op_id}/{pn}</d:href>\
                                 <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength></d:prop>\
                                 <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                                bytes.len()
                            ));
                        }
                    }
                    MockAction::Respond(MockResponse::new(
                        207,
                        format!("<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">{items}</d:multistatus>")
                            .into_bytes(),
                    ))
                }
                ("MOVE", [op_id, ".file"]) => {
                    let dest = req.header("destination").unwrap_or("");
                    assert!(
                        dest.contains("space%20dir/archive.bin"),
                        "Destination must be percent-encoded: {dest}"
                    );
                    if st.inject_207_on_assemble.swap(false, Ordering::SeqCst) {
                        let xml = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                                   <d:response><d:href>/remote.php/dav/files/alice/space%20dir/archive.bin</d:href>\
                                   <d:status>HTTP/1.1 403 Forbidden</d:status></d:response></d:multistatus>";
                        return MockAction::Respond(MockResponse::new(207, xml.as_bytes().to_vec()));
                    }
                    let chunks = st.uploads.remove(*op_id).unwrap_or_default();
                    let mut assembled = Vec::new();
                    for (_, bytes) in chunks {
                        assembled.extend_from_slice(&bytes);
                    }
                    st.files.insert("space dir/archive.bin".to_string(), assembled);
                    MockAction::Respond(
                        MockResponse::empty(201)
                            .with_header("ETag", "\"nc-t4\"")
                            .with_header("X-OC-Mtime", "accepted"),
                    )
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            };
        }

        let rel = percent_decode_strict(
            req.path
                .strip_prefix("/remote.php/dav/files/alice")
                .unwrap_or("")
                .trim_matches('/'),
        );
        match req.method.as_str() {
            "PROPFIND" => {
                if rel.is_empty() || st.dirs.contains(&rel) {
                    let mut items = format!(
                        "<d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                         <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>\
                         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                        if rel.is_empty() {
                            String::new()
                        } else {
                            format!("{}/", percent_encode_path(&rel))
                        }
                    );
                    if req.header("depth") == Some("1") {
                        let pfx = if rel.is_empty() { String::new() } else { format!("{rel}/") };
                        for d in &st.dirs {
                            if let Some(tail) = d.strip_prefix(&pfx)
                                && !tail.is_empty()
                                && !tail.contains('/')
                            {
                                items.push_str(&format!(
                                    "<d:response><d:href>/remote.php/dav/files/alice/{}/</d:href>\
                                     <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>\
                                     <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                                    percent_encode_path(d)
                                ));
                            }
                        }
                        for (k, v) in &st.files {
                            if let Some(tail) = k.strip_prefix(&pfx)
                                && !tail.is_empty()
                                && !tail.contains('/')
                            {
                                items.push_str(&format!(
                                    "<d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                                     <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength></d:prop>\
                                     <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                                    percent_encode_path(k),
                                    v.len()
                                ));
                            }
                        }
                    }
                    return MockAction::Respond(MockResponse::new(
                        207,
                        format!("<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">{items}</d:multistatus>")
                            .into_bytes(),
                    ));
                }
                if let Some(v) = st.files.get(&rel) {
                    let body = format!(
                        "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">\
                         <d:response><d:href>/remote.php/dav/files/alice/{}</d:href>\
                         <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength></d:prop>\
                         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
                        percent_encode_path(&rel),
                        v.len()
                    );
                    return MockAction::Respond(MockResponse::new(207, body.into_bytes()));
                }
                MockAction::Respond(MockResponse::empty(404))
            }
            "MKCOL" => {
                st.dirs.insert(rel);
                MockAction::Respond(MockResponse::empty(201))
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        }
    })
    .await;

    let mut cfg = WebdavConfig::new("nc", srv.url("/remote.php/dav/files/alice"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "pw".into(),
    };
    cfg.single_shot_max_bytes = Some(64 * 1024);
    cfg.default_chunk_size = Some(64 * 1024);
    let transport = HttpTransport::new(TransportConfig::new()).unwrap();
    let nc_backend = WebdavBackend::new(cfg, transport).unwrap();

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("space dir")).unwrap();
    let payload: Vec<u8> = (0..(160 * 1024)).map(|i| (i % 251) as u8).collect();
    let src_file = src.join("space dir").join("archive.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend("nc", nc_backend)
        .build()
        .unwrap();

    let r_fail = client
        .move_path(src.to_string_lossy().as_ref(), "nc:")
        .run()
        .await
        .unwrap();
    assert!(!r_fail.is_success());
    assert!(
        src_file.exists(),
        "207 Multi-Status assembly failure must preserve local source"
    );

    let r_ok = client
        .move_path(src.to_string_lossy().as_ref(), "nc:")
        .run()
        .await
        .unwrap();
    assert!(r_ok.is_success());
    assert_eq!(r_ok.sources_deleted, 1);
    assert!(!src_file.exists());
    assert_eq!(
        state
            .lock()
            .unwrap()
            .files
            .get("space dir/archive.bin")
            .map(Vec::as_slice),
        Some(payload.as_slice())
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "PUT" && r.path.ends_with("/1"))
    );
    assert!(
        reqs.iter()
            .any(|r| r.method == "PUT" && r.path.ends_with("/2"))
    );
    assert!(
        reqs.iter()
            .any(|r| r.method == "PUT" && r.path.ends_with("/3"))
    );
    let mv = reqs
        .iter()
        .find(|r| r.method == "MOVE" && r.path.ends_with("/.file"))
        .expect("MOVE .file");
    assert_eq!(mv.header("oc-total-length"), Some("163840"));
}

#[cfg(all(feature = "local", feature = "gcs", feature = "azureblob"))]
#[tokio::test]
async fn tier4_scenario_rclone_import_object_storage_mtime_and_safe_rename_parity() {
    use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
    use binary_helpers::*;
    use rship::factory::import_rclone_conf;
    use rship::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Default)]
    struct ObjParityState {
        gcs_objs: HashMap<String, (Vec<u8>, serde_json::Value)>,
        az_blobs: HashMap<String, (Vec<u8>, HashMap<String, String>)>,
    }
    let state = Arc::new(Mutex::new(ObjParityState::default()));
    {
        let mut st = state.lock().unwrap();
        st.gcs_objs.insert(
            "legacy.txt".to_string(),
            (
                b"old-gcs".to_vec(),
                serde_json::json!({
                    "name": "legacy.txt",
                    "size": "7",
                    "generation": "1",
                    "metadata": { "rship-mtime-ns": "1700000777000000000" }
                }),
            ),
        );
        let mut az_meta = HashMap::new();
        az_meta.insert(
            "x-ms-meta-rship_mtime_ns".to_string(),
            "1700000888000000000".to_string(),
        );
        st.az_blobs
            .insert("legacy.txt".to_string(), (b"old-az".to_vec(), az_meta));
    }
    let st_c = state.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let mut st = st_c.lock().unwrap_or_else(|e| e.into_inner());
        // GCS endpoints
        if req.method == "POST" && req.path == "/upload/storage/v1/b/bkt/o" {
            let ct = req.header("content-type").unwrap_or("");
            let boundary = ct
                .split("boundary=")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            let sep = format!("--{boundary}").into_bytes();
            let body = &req.body;
            let p1 = body
                .windows(sep.len())
                .position(|w| w == sep.as_slice())
                .unwrap();
            let a1 = &body[p1 + sep.len()..];
            let h1 = a1.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let p1b = &a1[h1 + 4..];
            let p2 = p1b
                .windows(sep.len())
                .position(|w| w == sep.as_slice())
                .unwrap();
            let meta: serde_json::Value =
                serde_json::from_slice(p1b[..p2].strip_suffix(b"\r\n").unwrap_or(&p1b[..p2]))
                    .unwrap();
            let a2 = &p1b[p2 + sep.len()..];
            let h2 = a2.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let data_start = &a2[h2 + 4..];
            let end_sep = format!("\r\n--{boundary}--").into_bytes();
            let end_pos = data_start
                .windows(end_sep.len())
                .position(|w| w == end_sep.as_slice())
                .unwrap();
            let data = data_start[..end_pos].to_vec();
            let name = meta["name"].as_str().unwrap_or("item").to_string();
            let obj = serde_json::json!({
                "name": name,
                "size": data.len().to_string(),
                "generation": "10",
                "metadata": meta.get("metadata").cloned().unwrap_or_default()
            });
            st.gcs_objs.insert(name, (data, obj.clone()));
            return MockAction::Respond(MockResponse::json(200, &obj));
        }
        if req.method == "POST"
            && req.path.starts_with("/storage/v1/b/bkt/o/")
            && req.path.contains("/rewriteTo/b/bkt/o/")
        {
            let rest = req.path.strip_prefix("/storage/v1/b/bkt/o/").unwrap();
            let (src_enc, dst_enc) = rest.split_once("/rewriteTo/b/bkt/o/").unwrap();
            let src_name = percent_decode_strict(src_enc);
            let dst_name = percent_decode_strict(dst_enc);
            let Some((data, mut obj)) = st.gcs_objs.get(&src_name).cloned() else {
                return MockAction::Respond(MockResponse::empty(404));
            };
            obj["name"] = serde_json::json!(dst_name);
            obj["generation"] = serde_json::json!("11");
            st.gcs_objs.insert(dst_name, (data, obj.clone()));
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({ "done": true, "resource": obj }),
            ));
        }
        if let Some(enc) = req.path.strip_prefix("/storage/v1/b/bkt/o/") {
            let name = percent_decode_strict(enc);
            if req.method == "GET" {
                if let Some((_, obj)) = st.gcs_objs.get(&name) {
                    return MockAction::Respond(MockResponse::json(200, obj));
                }
                return MockAction::Respond(MockResponse::empty(404));
            }
            if req.method == "DELETE" {
                st.gcs_objs.remove(&name);
                return MockAction::Respond(MockResponse::empty(204));
            }
        }

        // Azure endpoints
        if let Some(enc) = req.path.strip_prefix("/devstoreaccount1/cont/") {
            let name = percent_decode_strict(enc);
            match req.method.as_str() {
                "PUT" => {
                    if let Some(copy_src) = req.header("x-ms-copy-source") {
                        let src_name = percent_decode_strict(
                            copy_src
                                .split("/devstoreaccount1/cont/")
                                .nth(1)
                                .unwrap_or("")
                                .split('?')
                                .next()
                                .unwrap_or(""),
                        );
                        let Some((data, meta)) = st.az_blobs.get(&src_name).cloned() else {
                            return MockAction::Respond(MockResponse::empty(404));
                        };
                        st.az_blobs.insert(name, (data, meta));
                        return MockAction::Respond(
                            MockResponse::empty(202)
                                .with_header("x-ms-copy-status", "success")
                                .with_header("ETag", "\"0x22\""),
                        );
                    }
                    let mut meta = HashMap::new();
                    for (k, vals) in &req.headers {
                        if k.starts_with("x-ms-meta-")
                            && let Some(v) = vals.first()
                        {
                            meta.insert(k.clone(), v.clone());
                        }
                    }
                    let md5_b64 = base64_encode(&md5_digest(&req.body));
                    st.az_blobs.insert(name, (req.body.clone(), meta));
                    return MockAction::Respond(
                        MockResponse::empty(201)
                            .with_header("ETag", "\"0x21\"")
                            .with_header("Content-MD5", md5_b64),
                    );
                }
                "HEAD" => {
                    if let Some((data, meta)) = st.az_blobs.get(&name) {
                        let mut resp = MockResponse::empty(200)
                            .with_header("Content-Length", data.len().to_string())
                            .with_header("ETag", "\"0x21\"");
                        for (k, v) in meta {
                            resp = resp.with_header(k.clone(), v.clone());
                        }
                        return MockAction::Respond(resp);
                    }
                    return MockAction::Respond(MockResponse::empty(404));
                }
                "DELETE" => {
                    st.az_blobs.remove(&name);
                    return MockAction::Respond(MockResponse::empty(202));
                }
                _ => {}
            }
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("item.txt");
    std::fs::write(&src_file, b"parity-item").unwrap();
    let paths = AppPaths::new(tmp.path().join("cfg.toml"), tmp.path().join("state"));

    let conf = format!(
        "[gcs_r4]\n\
         type = google cloud storage\n\
         endpoint = {base}\n\
         user_project = proj-r4\n\
         anonymous = true\n\
         \n\
         [az_r4]\n\
         type = azureblob\n\
         sas_url = {base}/devstoreaccount1/cont?sv=2023-11-03&sig=abc\n",
        base = srv.base_url()
    );
    let mut app_cfg = AppConfig::new();
    import_rclone_conf(&mut app_cfg, &conf, &paths, true, false).unwrap();
    if let Some(RemoteConfig::Gcs(gcs)) = app_cfg.remotes.get_mut("gcs_r4") {
        gcs.bucket = Some("bkt".to_string());
    }

    let client = RshipClient::builder()
        .paths(paths)
        .config(app_cfg)
        .build()
        .unwrap();

    let r_gcs = client
        .copy_file(
            src_file.to_string_lossy().as_ref(),
            "gcs_r4:cafe\u{0301}/item.txt",
        )
        .run()
        .await
        .unwrap();
    assert!(
        r_gcs.is_success(),
        "gcs_r4 copy_file failed: {:?}",
        r_gcs.errors
    );
    let r_az = client
        .copy_file(
            src_file.to_string_lossy().as_ref(),
            "az_r4:cafe\u{0301}/item.txt",
        )
        .run()
        .await
        .unwrap();
    assert!(
        r_az.is_success(),
        "az_r4 copy_file failed: {:?}",
        r_az.errors
    );

    // Same-name rename must NEVER send DELETE
    let _ = srv.take_requests();
    let _ = client
        .rename("gcs_r4:caf\u{00e9}/item.txt", "item.txt")
        .await;
    let _ = client
        .rename("az_r4:caf\u{00e9}/item.txt", "item.txt")
        .await;
    let same_reqs = srv.take_requests();
    assert!(same_reqs.iter().all(|r| r.method != "DELETE"));

    // Rename inside NFD parent
    let gcs_ren = client
        .rename("gcs_r4:caf\u{00e9}/item.txt", "renamed.txt")
        .await
        .unwrap();
    let az_ren = client
        .rename("az_r4:caf\u{00e9}/item.txt", "renamed.txt")
        .await
        .unwrap();
    assert_eq!(gcs_ren.nfc_path.as_str(), "caf\u{00e9}/renamed.txt");
    assert_eq!(az_ren.nfc_path.as_str(), "caf\u{00e9}/renamed.txt");

    // Dual-read mtime parity: standard rclone keys + legacy rship keys
    let gcs_leg = client.stat("gcs_r4:legacy.txt").await.unwrap().unwrap();
    let az_leg = client.stat("az_r4:legacy.txt").await.unwrap().unwrap();
    assert_eq!(gcs_leg.mtime_ns, 1_700_000_777_000_000_000);
    assert_eq!(az_leg.mtime_ns, 1_700_000_888_000_000_000);
    assert!(
        client
            .stat("gcs_r4:caf\u{00e9}/renamed.txt")
            .await
            .unwrap()
            .unwrap()
            .mtime_ns
            > 0
    );
    assert!(
        client
            .stat("az_r4:caf\u{00e9}/renamed.txt")
            .await
            .unwrap()
            .unwrap()
            .mtime_ns
            > 0
    );
}
