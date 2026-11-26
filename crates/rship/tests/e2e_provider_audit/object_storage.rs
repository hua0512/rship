#![cfg(any(feature = "s3", feature = "gcs", feature = "azureblob"))]

#[cfg(feature = "azureblob")]
use crate::mock_http::CapturedRequest;
use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
use futures::StreamExt;
#[cfg(feature = "azureblob")]
use rship::backends::azureblob::{
    AZURE_MIN_BLOCK_BYTES, AzureAuth, AzureBlobBackend, AzureBlobConfig,
    config::{AZURITE_ACCOUNT, AZURITE_KEY},
    extract_sas_account_and_endpoint,
};
#[cfg(feature = "gcs")]
use rship::backends::gcs::{GCS_CHUNK_ALIGN_BYTES, GcsBackend, GcsConfig, gcs_encode_object_name};
#[cfg(feature = "s3")]
use rship::backends::s3::{
    S3Backend, S3Config, S3Credentials, S3Provider, S3ServerSideEncryption,
    provider::{GIB, TIB},
};
#[cfg(any(feature = "s3", feature = "azureblob"))]
use rship::core::backend::CompletedPart;
use rship::core::backend::{
    BackendPath, ChunkUpload, EntryStream, ListOptions, StorageBackend, UploadInit, UploadProgress,
};
use rship::core::buffer::BufferPool;
use rship::core::path::RelPath;
use rship::core::source::{ByteStream, DataSource, MemorySource, bounded_range_stream};
use rship::core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
#[cfg(any(feature = "s3", feature = "gcs"))]
use rship::core::types::HashKind;
use rship::core::types::{ByteRange, Entry, EntryKind};
#[cfg(feature = "gcs")]
use rship::core::types::{Checksum, NodeId};
use rship::prelude::*;
use rship::transport::{HttpTransport, TransportConfig};
#[cfg(any(feature = "s3", feature = "azureblob"))]
use std::collections::BTreeMap;
#[cfg(any(feature = "gcs", feature = "azureblob"))]
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

// ---------------------------------------------------------------------------
// Shared Pure-Rust Helpers (dev-deps do not include base64/md-5/sha2/hex/url)
// ---------------------------------------------------------------------------

fn make_byte_stream(data: Vec<u8>) -> ByteStream {
    let len = data.len() as u64;
    if len == 0 {
        return Box::pin(futures::stream::empty());
    }
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).expect("buffer pool");
    let src = Arc::new(MemorySource::new(data));
    bounded_range_stream(src, 0, len, pool)
}

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

fn make_op_record(
    backend_kind: &str,
    init: &UploadInit,
    session_token: Option<String>,
    backend_meta: String,
    remote_op_id: Option<String>,
) -> OperationRecord {
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

#[cfg(feature = "azureblob")]
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.as_chunks::<4>().0 {
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return None;
        }
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            vals[i] = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 2 => {
                    pad += 1;
                    0
                }
                _ => return None,
            };
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if pad < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if pad == 0 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

/// Strict percent-decoder that leaves `+` literal (unlike `application/x-www-form-urlencoded`).
#[cfg(any(feature = "gcs", feature = "azureblob"))]
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

#[cfg(any(feature = "s3", feature = "azureblob"))]
fn md5_digest(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
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

#[cfg(feature = "gcs")]
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

#[cfg(feature = "azureblob")]
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(feature = "azureblob")]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256_digest(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Vec::with_capacity(64 + data.len());
    let mut opad = Vec::with_capacity(64 + 32);
    for &b in &k_block {
        ipad.push(b ^ 0x36);
        opad.push(b ^ 0x5c);
    }
    ipad.extend_from_slice(data);
    let inner = sha256_digest(&ipad);
    opad.extend_from_slice(&inner);
    sha256_digest(&opad)
}

#[cfg(any(feature = "s3", feature = "azureblob"))]
fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(any(feature = "s3", feature = "azureblob"))]
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

fn parse_byte_range_header(hdr: &str, total: usize) -> Option<(usize, usize)> {
    let spec = hdr.strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    let start: usize = start_s.parse().ok()?;
    let end = if end_s.is_empty() {
        total.saturating_sub(1)
    } else {
        end_s.parse::<usize>().ok()?.min(total.saturating_sub(1))
    };
    (start <= end && start < total).then_some((start, end))
}

// ===========================================================================
// Feature Area #5: Amazon S3 & S3-Compatible (`#[cfg(feature = "s3")]`)
// ===========================================================================

#[cfg(feature = "s3")]
fn make_s3_backend(cfg: S3Config) -> S3Backend {
    let transport = HttpTransport::new(TransportConfig::new()).expect("transport");
    S3Backend::new(cfg, transport, None).expect("S3Backend::new")
}

#[cfg(feature = "s3")]
fn s3_url_encode_key(raw: &str) -> String {
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

// -----------------------------------------------------------------------
// S3 Tier 1 (5 happy-path tests; MUST pass 100% on baseline `af414db`)
// -----------------------------------------------------------------------

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier1_s3_put_stat_get_and_delete_via_rship_client() {
    #[derive(Default)]
    struct Store {
        objects: BTreeMap<String, (Vec<u8>, String)>,
    }
    let store = Arc::new(Mutex::new(Store::default()));
    let store_c = store.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
            let mut st = store_c.lock().unwrap_or_else(|e| e.into_inner());
            let key = req.path.strip_prefix("/test-bkt/").unwrap_or("");
            match req.method.as_str() {
                "PUT" if !key.is_empty() => {
                    let etag = format!("\"mock-etag-{}\"", st.objects.len() + 1);
                    st.objects.insert(key.to_string(), (req.body.clone(), etag.clone()));
                    MockAction::Respond(
                        MockResponse::empty(200)
                            .with_header("ETag", etag)
                            .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                    )
                }
                "HEAD" if !key.is_empty() => {
                    if let Some((data, etag)) = st.objects.get(key) {
                        MockAction::Respond(
                            MockResponse::empty(200)
                                .with_header("Content-Length", data.len().to_string())
                                .with_header("ETag", etag.clone())
                                .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                        )
                    } else {
                        MockAction::Respond(MockResponse::empty(404))
                    }
                }
                "GET" if req.path == "/test-bkt" => {
                    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                "GET" if !key.is_empty() => {
                    if let Some((data, etag)) = st.objects.get(key) {
                        if let Some(rh) = req.header("range")
                            && let Some((s, e)) = parse_byte_range_header(rh, data.len())
                        {
                            let slice = data[s..=e].to_vec();
                            return MockAction::Respond(
                                MockResponse::new(206, slice)
                                    .with_header("ETag", etag.clone())
                                    .with_header(
                                        "Content-Range",
                                        format!("bytes {s}-{e}/{}", data.len()),
                                    ),
                            );
                        }
                        MockAction::Respond(
                            MockResponse::ok(data.clone()).with_header("ETag", etag.clone()),
                        )
                    } else {
                        MockAction::Respond(MockResponse::empty(404))
                    }
                }
                "DELETE" if !key.is_empty() => {
                    st.objects.remove(key);
                    MockAction::Respond(MockResponse::empty(204))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let cfg = S3RemoteConfig::new("minio")
        .with_bucket("test-bkt")
        .with_endpoint(srv.base_url())
        .with_credentials("AKIAEXAMPLE", "SECRETKEY")
        .with_force_path_style(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("s3", cfg)
        .build()
        .expect("build client");

    let payload = b"hello s3 tier1 object storage!".to_vec();
    let (backend, rel) = client.resolve("s3:hello.txt").expect("resolve");
    let init = UploadInit {
        op_id: "op-s3-t1-put".to_string(),
        dst_path: rel,
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let committed = backend
        .put_single_shot(&init, make_byte_stream(payload.clone()))
        .await
        .expect("put_single_shot");
    assert_eq!(committed.size, payload.len() as u64);

    let entry = client
        .stat("s3:hello.txt")
        .await
        .expect("stat")
        .expect("must exist");
    assert_eq!(entry.kind, EntryKind::File);
    assert_eq!(entry.size, payload.len() as u64);

    let src = client
        .open_read("s3:hello.txt", None)
        .await
        .expect("open_read");
    let got = read_all_from_source(src).await.expect("read_all");
    assert_eq!(got, payload);

    client.delete("s3:hello.txt").await.expect("delete");
    assert!(
        client
            .stat("s3:hello.txt")
            .await
            .expect("stat after del")
            .is_none()
    );

    let reqs = srv.requests();
    let put_req = reqs
        .iter()
        .find(|r| r.method == "PUT")
        .expect("PUT captured");
    assert!(put_req.header("x-amz-content-sha256").is_some());
    assert!(put_req.header("x-amz-meta-rship-sha256").is_some());
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier1_s3_list_shallow_recursive_and_ordered_page() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method != "GET" || req.path != "/list-bkt" {
            return MockAction::Respond(MockResponse::empty(404));
        }
        let delim = req.query_get("delimiter");
        let ct = req.query_get("continuation-token");
        let xml = match (delim.as_deref(), ct.as_deref()) {
            (Some("/"), None) => format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>true</IsTruncated>
                      <NextContinuationToken>tok-2</NextContinuationToken>
                      <EncodingType>url</EncodingType>
                      <Contents><Key>{}</Key><Size>12</Size><ETag>\"e1\"</ETag></Contents>
                      <CommonPrefixes><Prefix>sub/</Prefix></CommonPrefixes>
                    </ListBucketResult>",
                s3_url_encode_key("a 1.txt")
            ),
            (Some("/"), Some("tok-2")) => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>false</IsTruncated>
                      <EncodingType>url</EncodingType>
                      <Contents><Key>b.txt</Key><Size>5</Size><ETag>\"e2\"</ETag></Contents>
                    </ListBucketResult>"
                .to_string(),
            (None, None) => format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>true</IsTruncated>
                      <NextContinuationToken>ord-2</NextContinuationToken>
                      <EncodingType>url</EncodingType>
                      <Contents><Key>{}</Key><Size>12</Size><ETag>\"e1\"</ETag></Contents>
                      <Contents><Key>sub/c.txt</Key><Size>9</Size><ETag>\"e3\"</ETag></Contents>
                    </ListBucketResult>",
                s3_url_encode_key("a 1.txt")
            ),
            (None, Some("ord-2")) => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>false</IsTruncated>
                      <EncodingType>url</EncodingType>
                      <Contents><Key>b.txt</Key><Size>5</Size><ETag>\"e2\"</ETag></Contents>
                    </ListBucketResult>"
                .to_string(),
            _ => {
                "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".to_string()
            }
        };
        MockAction::Respond(MockResponse::ok(xml.into_bytes()))
    })
    .await;

    let cfg = S3RemoteConfig::new("minio")
        .with_bucket("list-bkt")
        .with_endpoint(srv.base_url())
        .with_credentials("AK", "SK")
        .with_force_path_style(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("s3", cfg)
        .build()
        .expect("build client");

    let shallow = collect_entries(
        client
            .list("s3:", &ListOptions::shallow())
            .await
            .expect("shallow list"),
    )
    .await
    .expect("collect shallow");
    let shallow_paths: Vec<(&str, EntryKind)> = shallow
        .iter()
        .map(|e| (e.nfc_path.as_str(), e.kind))
        .collect();
    assert!(shallow_paths.contains(&("a 1.txt", EntryKind::File)));
    assert!(shallow_paths.contains(&("sub", EntryKind::Directory)));
    assert!(shallow_paths.contains(&("b.txt", EntryKind::File)));

    let rec = collect_entries(
        client
            .list("s3:", &ListOptions::recursive())
            .await
            .expect("recursive list"),
    )
    .await
    .expect("collect recursive");
    let rec_names: Vec<&str> = rec.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(rec_names, vec!["a 1.txt", "sub/c.txt", "b.txt"]);

    let (backend, root) = client.resolve("s3:").expect("resolve");
    let page1 = backend
        .list_ordered_page(&root, None, None, 10)
        .await
        .expect("page1");
    assert!(page1.is_truncated);
    assert_eq!(page1.next_cursor.as_deref(), Some("v2:ord-2"));
    let page2 = backend
        .list_ordered_page(&root, None, page1.next_cursor.as_deref(), 10)
        .await
        .expect("page2");
    assert!(!page2.is_truncated);
    assert_eq!(page2.entries[0].nfc_path.as_str(), "b.txt");
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier1_s3_multipart_upload_and_resume_list_parts() {
    type PartsMap = BTreeMap<u32, (Vec<u8>, String)>;
    let parts_store: Arc<Mutex<PartsMap>> = Arc::new(Mutex::new(BTreeMap::new()));
    let parts_c = parts_store.clone();
    let completed_body: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let completed_c = completed_body.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
            if req.path != "/mp-bkt/big.bin" {
                return MockAction::Respond(MockResponse::empty(404));
            }
            match req.method.as_str() {
                "POST" if req.query.as_deref() == Some("uploads=") => {
                    let xml = "<InitiateMultipartUploadResult><UploadId>up-s3-1</UploadId></InitiateMultipartUploadResult>";
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                "PUT" if req.query_get("uploadId").as_deref() == Some("up-s3-1") => {
                    let pnum: u32 = req.query_get("partNumber").unwrap().parse().unwrap();
                    let etag = format!("\"mp-part-{pnum}\"");
                    parts_c
                        .lock()
                        .unwrap()
                        .insert(pnum, (req.body.clone(), etag.clone()));
                    MockAction::Respond(MockResponse::empty(200).with_header("ETag", etag))
                }
                "GET" if req.query_get("uploadId").as_deref() == Some("up-s3-1") => {
                    let guard = parts_c.lock().unwrap();
                    let mut items = String::new();
                    for (pn, (data, etag)) in guard.iter() {
                        items.push_str(&format!(
                            "<Part><PartNumber>{pn}</PartNumber><ETag>{}</ETag><Size>{}</Size></Part>",
                            xml_escape(etag),
                            data.len()
                        ));
                    }
                    let xml = format!(
                        "<ListPartsResult><IsTruncated>false</IsTruncated>{items}</ListPartsResult>"
                    );
                    MockAction::Respond(MockResponse::ok(xml.into_bytes()))
                }
                "POST" if req.query_get("uploadId").as_deref() == Some("up-s3-1") => {
                    let guard = parts_c.lock().unwrap();
                    let mut buf = Vec::new();
                    for (data, _) in guard.values() {
                        buf.extend_from_slice(data);
                    }
                    *completed_c.lock().unwrap() = Some(buf);
                    let xml = "<CompleteMultipartUploadResult><ETag>\"final-mp-etag\"</ETag></CompleteMultipartUploadResult>";
                    MockAction::Respond(
                        MockResponse::ok(xml.as_bytes().to_vec())
                            .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                    )
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let mut cfg = S3Config::new(
        "s3",
        S3Provider::Minio,
        "mp-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    cfg.single_shot_max_bytes = Some(64);
    cfg.default_chunk_size = Some(64);
    cfg.min_part_bytes_override = Some(64);
    let backend = make_s3_backend(cfg);

    let p1 = vec![b'A'; 64];
    let p2 = vec![b'B'; 25];
    let total = (p1.len() + p2.len()) as u64;
    let init = UploadInit {
        op_id: "op-s3-mp-1".to_string(),
        dst_path: RelPath::parse("big.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };

    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    assert_eq!(sess.session_token, "up-s3-1");
    let op = make_op_record(
        "s3",
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        sess.remote_op_id.clone(),
    );

    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, p1.len() as u64, total, make_byte_stream(p1.clone())),
        )
        .await
        .expect("upload part 1");

    let progress = backend.query_upload(&op).await.expect("query_upload");
    match progress {
        UploadProgress::CompletedParts(listed) => {
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].part_number, 1);
            assert_eq!(listed[0].length, 64);
        }
        other => panic!("expected CompletedParts, got {other:?}"),
    }

    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(2, 64, p2.len() as u64, total, make_byte_stream(p2.clone())),
        )
        .await
        .expect("upload part 2");

    let entry = backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: p1.len() as u64,
                    etag: ack1.etag.unwrap(),
                    checksum: ack1.checksum,
                },
                CompletedPart {
                    part_number: 2,
                    offset: 64,
                    length: p2.len() as u64,
                    etag: ack2.etag.unwrap(),
                    checksum: ack2.checksum,
                },
            ],
        )
        .await
        .expect("finish_upload");
    assert_eq!(entry.size, total);
    let mut expected = p1;
    expected.extend_from_slice(&p2);
    assert_eq!(
        completed_body.lock().unwrap().as_deref(),
        Some(expected.as_slice())
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier1_s3_server_side_copy_and_range_read() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("HEAD", "/src-bkt/src.bin") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "10")
                        .with_header("ETag", "\"src-etag-1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                ),
                ("PUT", "/dst-bkt/dst.bin") => {
                    let xml = "<CopyObjectResult><ETag>\"dst-etag-1\"</ETag><LastModified>2026-11-25T12:00:00Z</LastModified></CopyObjectResult>";
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                ("HEAD", "/dst-bkt/dst.bin") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "10")
                        .with_header("ETag", "\"dst-etag-1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                ),
                ("GET", "/dst-bkt/dst.bin") => {
                    let full = b"0123456789";
                    if let Some(rh) = req.header("range")
                        && let Some((s, e)) = parse_byte_range_header(rh, full.len())
                    {
                        return MockAction::Respond(
                            MockResponse::new(206, full[s..=e].to_vec())
                                .with_header("ETag", "\"dst-etag-1\"")
                                .with_header("Content-Range", format!("bytes {s}-{e}/10")),
                        );
                    }
                    MockAction::Respond(MockResponse::ok(full.to_vec()).with_header("ETag", "\"dst-etag-1\""))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let cfg_a = S3RemoteConfig::new("minio")
        .with_bucket("src-bkt")
        .with_endpoint(srv.base_url())
        .with_credentials("AK", "SK")
        .with_force_path_style(true);
    let cfg_b = S3RemoteConfig::new("minio")
        .with_bucket("dst-bkt")
        .with_endpoint(srv.base_url())
        .with_credentials("AK", "SK")
        .with_force_path_style(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("s3a", cfg_a)
        .remote("s3b", cfg_b)
        .build()
        .expect("build client");

    let report = client
        .copy_file("s3a:src.bin", "s3b:dst.bin")
        .run()
        .await
        .expect("copy_file");
    assert_eq!(report.server_side_copies, 1);

    let src = client
        .open_read("s3b:dst.bin", None)
        .await
        .expect("open_read");
    match src {
        DataSource::RemoteRangeReadable(r) => {
            let mut stream = r
                .open_range(ByteRange { offset: 2, len: 4 })
                .await
                .expect("open_range");
            let mut out = Vec::new();
            while let Some(c) = stream.next().await {
                out.extend_from_slice(&c.unwrap());
            }
            assert_eq!(out, b"2345");
        }
        _ => panic!("expected RemoteRangeReadable"),
    }

    let reqs = srv.requests();
    let copy_req = reqs
        .iter()
        .find(|r| r.method == "PUT" && r.path == "/dst-bkt/dst.bin")
        .expect("CopyObject PUT");
    assert_eq!(
        copy_req.header("x-amz-copy-source"),
        Some("/src-bkt/src.bin")
    );
    assert_eq!(
        copy_req.header("x-amz-copy-source-if-match"),
        Some("\"src-etag-1\"")
    );
    let range_req = reqs
        .iter()
        .find(|r| r.method == "GET" && r.path == "/dst-bkt/dst.bin")
        .expect("Range GET");
    assert_eq!(range_req.header("range"), Some("bytes=2-5"));
    assert_eq!(range_req.header("if-match"), Some("\"dst-etag-1\""));
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier1_s3_delete_batch_and_mkdir() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str(), req.query.as_deref()) {
                ("PUT", "/del-bkt/sub/dir/", _) => {
                    assert_eq!(req.header("content-type"), Some("application/x-directory"));
                    assert!(req.body.is_empty());
                    MockAction::Respond(MockResponse::empty(200))
                }
                ("POST", "/del-bkt", Some("delete=")) => {
                    let expected_md5 = base64_encode(&md5_digest(&req.body));
                    assert_eq!(req.header("content-md5"), Some(expected_md5.as_str()));
                    let keys = extract_xml_tag_values(&req.body_text(), "Key");
                    assert_eq!(keys, vec!["a.txt", "sub/dir/"]);
                    let xml = "<DeleteResult><Deleted><Key>a.txt</Key></Deleted><Deleted><Key>sub/dir/</Key></Deleted></DeleteResult>";
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let cfg = S3Config::new(
        "s3",
        S3Provider::Minio,
        "del-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(cfg);

    backend
        .mkdir(&RelPath::parse("sub/dir").unwrap())
        .await
        .expect("mkdir");
    let p_file = BackendPath::from_rel(RelPath::parse("a.txt").unwrap());
    let p_dir = BackendPath::from_rel(RelPath::parse("sub/dir").unwrap())
        .with_kind(Some(EntryKind::Directory));
    let failures = backend
        .delete_batch(&[p_file, p_dir])
        .await
        .expect("delete_batch");
    assert!(failures.is_empty());
}

// -----------------------------------------------------------------------
// S3 Tier 2 (10 tests covering Audit §III.1 items)
// -----------------------------------------------------------------------

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_sse_kms_and_ssec_etag_not_treated_as_md5() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "GET" && req.path == "/kms-bkt" {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>false</IsTruncated>
                      <EncodingType>url</EncodingType>
                      <Contents>
                        <Key>secret.bin</Key>
                        <Size>10</Size>
                        <ETag>\"0123456789abcdef0123456789abcdef\"</ETag>
                      </Contents>
                    </ListBucketResult>";
            return MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()));
        }
        if req.method == "HEAD" && req.path == "/kms-bkt/ssec.bin" {
            return MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Content-Length", "5")
                    .with_header("ETag", "\"0123456789abcdef0123456789abcdef\"")
                    .with_header("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            );
        }
        if req.method == "GET" && req.path == "/kms-bkt/ssec.bin" {
            return MockAction::Respond(
                MockResponse::new(206, b"hello".to_vec())
                    .with_header("ETag", "\"0123456789abcdef0123456789abcdef\"")
                    .with_header("Content-Range", "bytes 0-4/5")
                    .with_header("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            );
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let kms_cfg = S3Config::new(
        "kms",
        S3Provider::Aws,
        "kms-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true)
    .with_server_side_encryption(S3ServerSideEncryption::AwsKms {
        key_id: Some("arn:aws:kms:us-east-1:123:key/abc".into()),
    });
    let kms_backend = make_s3_backend(kms_cfg);
    assert!(
        !kms_backend.capabilities().hashes.contains(&HashKind::Md5),
        "SSE-KMS backend must NOT advertise HashKind::Md5 because KMS ETags are not plaintext MD5"
    );

    let aes_cfg = S3Config::new(
        "aes",
        S3Provider::Aws,
        "kms-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true)
    .with_server_side_encryption(S3ServerSideEncryption::Aes256);
    let aes_backend = make_s3_backend(aes_cfg);
    assert!(aes_backend.capabilities().hashes.contains(&HashKind::Md5));

    let listed = collect_entries(
        kms_backend
            .list_stream(&RelPath::root(), false)
            .await
            .expect("list_stream"),
    )
    .await
    .expect("collect");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].checksum, None,
        "SSE-KMS list_stream must NOT treat 32-hex ETag as MD5"
    );

    let page = kms_backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect("list_ordered_page");
    assert_eq!(
        page.entries[0].checksum, None,
        "SSE-KMS list_ordered_page must NOT treat 32-hex ETag as MD5"
    );

    let ssec_bp = BackendPath::from_rel(RelPath::parse("ssec.bin").unwrap());
    let ssec_entry = aes_backend
        .stat(&ssec_bp)
        .await
        .expect("stat")
        .expect("exists");
    assert_eq!(ssec_entry.checksum, None);
    let src = aes_backend
        .open_read_entry(&ssec_entry, &ssec_bp, None)
        .await
        .expect("open_read_entry");
    assert_eq!(
        read_all_from_source(src).await.expect("read ssec"),
        b"hello"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_oss_default_region_endpoint_and_sigv4_scope() {
    let default_oss = S3Config::new(
        "oss",
        S3Provider::Oss,
        "oss-bkt",
        S3Credentials::new("AK", "SK"),
    );
    assert_eq!(default_oss.region, "cn-hangzhou");
    let ep = default_oss.effective_endpoint();
    assert!(
        ep.contains("oss-cn-hangzhou.aliyuncs.com"),
        "OSS effective_endpoint `{ep}` must target oss-cn-hangzhou.aliyuncs.com"
    );

    let srv = MockHttpServer::start_with_handler(|_| {
        MockAction::Respond(MockResponse::empty(200).with_header("Content-Length", "3"))
    })
    .await;
    let wire_oss = S3Config::new(
        "oss",
        S3Provider::Oss,
        "oss-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(wire_oss);
    let _ = backend
        .stat(&BackendPath::from_rel(RelPath::parse("obj.txt").unwrap()))
        .await
        .expect("stat");

    let reqs = srv.requests();
    let auth = reqs[0]
        .header("authorization")
        .expect("SigV4 Authorization");
    assert!(
        auth.contains("/cn-hangzhou/s3/aws4_request"),
        "OSS SigV4 credential scope must use `cn-hangzhou`, got: {auth}"
    );
    assert!(
        !auth.contains("/oss-cn-hangzhou/"),
        "OSS SigV4 credential scope must not include `oss-` prefix: {auth}"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_r2_single_part_omits_crc32c_conditional_copy_headers_and_limits() {
    let prof = S3Provider::R2.profile();
    assert!(
        prof.max_part_bytes >= 4_500_000_000 && prof.max_part_bytes < 5 * GIB,
        "R2 max_part_bytes ({}) must reflect 4.995 GiB limit (< 5 GiB)",
        prof.max_part_bytes
    );
    assert!(
        prof.max_object_bytes >= 4_500_000_000_000 && prof.max_object_bytes < 5 * TIB,
        "R2 max_object_bytes ({}) must reflect 4.995 TiB limit (< 5 TiB)",
        prof.max_object_bytes
    );

    let srv = MockHttpServer::start_with_handler(|req| match req.method.as_str() {
            "PUT" if req.header("x-amz-copy-source").is_some() => MockAction::Respond(
                MockResponse::ok(
                    b"<CopyObjectResult><ETag>\"cp-e1\"</ETag><LastModified>2026-11-25T12:00:00Z</LastModified></CopyObjectResult>".to_vec(),
                ),
            ),
            "PUT" => MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("ETag", "\"put-e1\"")
                    .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
            ),
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let cfg = S3Config::new(
        "r2",
        S3Provider::R2,
        "r2-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(cfg);

    let payload = vec![0x42u8; 128];
    let init_put = UploadInit {
        op_id: "op-r2-put".to_string(),
        dst_path: RelPath::parse("item.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .put_single_shot(&init_put, make_byte_stream(payload))
        .await
        .expect("R2 put_single_shot");

    let ep = backend.endpoint_identity();
    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap());

    let copy_absent = UploadInit {
        op_id: "op-r2-cp-absent".to_string(),
        dst_path: RelPath::parse("dst1.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 10,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .server_side_copy(&ep, &src_bp, &copy_absent)
        .await
        .expect("R2 copy absent");

    let copy_existing = UploadInit {
        op_id: "op-r2-cp-exist".to_string(),
        dst_path: RelPath::parse("dst2.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 10,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: Some("\"old-e1\"".to_string()),
            mtime_ns: 0,
            size: 10,
        },
        src_etag: None,
    };
    backend
        .server_side_copy(&ep, &src_bp, &copy_existing)
        .await
        .expect("R2 copy existing");

    let reqs = srv.requests();
    let put_req = reqs.iter().find(|r| r.path == "/r2-bkt/item.bin").unwrap();
    assert!(
        put_req.header("x-amz-checksum-crc32c").is_none(),
        "R2 single-part PutObject must NOT send x-amz-checksum-crc32c"
    );

    let cp1 = reqs.iter().find(|r| r.path == "/r2-bkt/dst1.bin").unwrap();
    assert_eq!(cp1.header("cf-copy-destination-if-none-match"), Some("*"));
    assert!(cp1.header("if-none-match").is_none());

    let cp2 = reqs.iter().find(|r| r.path == "/r2-bkt/dst2.bin").unwrap();
    assert_eq!(
        cp2.header("cf-copy-destination-if-match"),
        Some("\"old-e1\"")
    );
    assert!(cp2.header("if-match").is_none());
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_wasabi_disables_if_none_match() {
    let srv = MockHttpServer::start_with_handler(|_| {
        MockAction::Respond(
            MockResponse::empty(200)
                .with_header("ETag", "\"wasabi-e1\"")
                .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
        )
    })
    .await;

    let cfg = S3Config::new(
        "wasabi",
        S3Provider::Wasabi,
        "w-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(cfg);

    assert!(
        !backend.capabilities().supports_conditional_write,
        "Wasabi must report supports_conditional_write == false"
    );

    let payload = b"wasabi-data".to_vec();
    let init = UploadInit {
        op_id: "op-wasabi-1".to_string(),
        dst_path: RelPath::parse("w.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .put_single_shot(&init, make_byte_stream(payload))
        .await
        .expect("put_single_shot");

    let reqs = srv.requests();
    assert!(
        reqs[0].header("if-none-match").is_none(),
        "Wasabi must NOT send If-None-Match: *"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_dot_in_bucket_and_ip_endpoint_force_path_style() {
    let dot_cfg = S3Config::new(
        "aws-dot",
        S3Provider::Aws,
        "my.dotted.bucket",
        S3Credentials::new("AK", "SK"),
    );
    assert!(
        dot_cfg.use_path_style(),
        "buckets containing `.` must force path-style addressing"
    );

    let v6_cfg = S3Config::new(
        "aws-v6",
        S3Provider::Aws,
        "plainbucket",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint("http://[::1]:9000");
    assert!(
        v6_cfg.use_path_style(),
        "IPv6 literal endpoints must force path-style addressing"
    );

    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "HEAD" && req.path == "/plainbucket/k.txt" {
            MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Content-Length", "4")
                    .with_header("ETag", "\"ip-e1\""),
            )
        } else {
            MockAction::Respond(MockResponse::empty(404))
        }
    })
    .await;

    let ip_cfg = S3Config::new(
        "aws-ip",
        S3Provider::Aws,
        "plainbucket",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url());
    assert!(
        ip_cfg.use_path_style(),
        "IPv4 literal endpoints must force path-style addressing"
    );

    let backend = make_s3_backend(ip_cfg);
    let entry = backend
        .stat(&BackendPath::from_rel(RelPath::parse("k.txt").unwrap()))
        .await
        .expect("stat on IP endpoint must succeed with path-style")
        .expect("k.txt exists");
    assert_eq!(entry.size, 4);

    let reqs = srv.requests();
    assert_eq!(reqs[0].path, "/plainbucket/k.txt");
    let host = reqs[0].header("host").expect("Host header");
    assert!(
        host.starts_with("127.0.0.1:"),
        "IP endpoint Host header must not prepend bucket, got: {host}"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_complete_multipart_if_match_and_412_precondition_failed() {
    let srv = MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.query.as_deref()) {
            ("POST", Some("uploads=")) => MockAction::Respond(MockResponse::ok(
                b"<InitiateMultipartUploadResult><UploadId>up-cond-1</UploadId></InitiateMultipartUploadResult>".to_vec(),
            )),
            ("PUT", _) if req.query_get("uploadId").as_deref() == Some("up-cond-1") => {
                MockAction::Respond(MockResponse::empty(200).with_header("ETag", "\"p1\""))
            }
            ("POST", _) if req.query_get("uploadId").as_deref() == Some("up-cond-1") => {
                let xml = "<Error><Code>PreconditionFailed</Code><Message>If-Match did not match</Message></Error>";
                MockAction::Respond(MockResponse::new(412, xml.as_bytes().to_vec()))
            }
            ("HEAD", _) => MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Content-Length", "64")
                    .with_header("ETag", "\"someone-elses-etag\"")
                    .with_header("x-amz-meta-rship-op-id", "other-writer-op"),
            ),
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let mut cfg = S3Config::new(
        "s3",
        S3Provider::Aws,
        "cond-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true)
    .with_send_upload_checksum(false);
    cfg.single_shot_max_bytes = Some(64);
    cfg.min_part_bytes_override = Some(64);
    let backend = make_s3_backend(cfg);

    let init = UploadInit {
        op_id: "op-cond-ours".to_string(),
        dst_path: RelPath::parse("obj.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64,
        checksums: Vec::new(),
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: Some("\"expected-old-etag\"".to_string()),
            mtime_ns: 0,
            size: 64,
        },
        src_etag: None,
    };

    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    let op = make_op_record(
        "s3",
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        sess.remote_op_id.clone(),
    );
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, 64, 64, make_byte_stream(vec![b'X'; 64])),
        )
        .await
        .expect("upload_chunk");

    let err = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 64,
                etag: ack.etag.unwrap(),
                checksum: ack.checksum,
            }],
        )
        .await
        .expect_err("412 on CompleteMultipartUpload must fail");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);

    let reqs = srv.requests();
    let complete_req = reqs
        .iter()
        .find(|r| r.method == "POST" && r.query_get("uploadId").as_deref() == Some("up-cond-1"))
        .expect("CompleteMultipartUpload POST");
    assert_eq!(
        complete_req.header("if-match"),
        Some("\"expected-old-etag\""),
        "CompleteMultipartUpload must send If-Match for DstPrecondition::Existing"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_leading_slash_key_preserved_across_stat_read_delete_copy() {
    let srv = MockHttpServer::start_with_handler(|req| {
            let is_leading_slash_target =
                req.path == "/ls-bkt//foo" || req.path == "/ls-bkt/%2Ffoo";
            match req.method.as_str() {
                "HEAD" if is_leading_slash_target => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "5")
                        .with_header("ETag", "\"ls-e1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                ),
                "GET" if is_leading_slash_target => MockAction::Respond(
                    MockResponse::new(206, b"slash".to_vec())
                        .with_header("ETag", "\"ls-e1\"")
                        .with_header("Content-Range", "bytes 0-4/5"),
                ),
                "PUT" if req.path == "/ls-bkt/dst.bin" => MockAction::Respond(MockResponse::ok(
                    b"<CopyObjectResult><ETag>\"ls-cp\"</ETag><LastModified>2026-11-25T12:00:00Z</LastModified></CopyObjectResult>".to_vec(),
                )),
                "DELETE" if is_leading_slash_target => {
                    MockAction::Respond(MockResponse::empty(204))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let cfg = S3Config::new(
        "s3",
        S3Provider::Minio,
        "ls-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(cfg);

    let bp = BackendPath::new("/foo", RelPath::parse("foo").unwrap(), None);
    let entry = backend
        .stat(&bp)
        .await
        .expect("stat")
        .expect("leading-slash object /foo must be found");
    assert_eq!(entry.size, 5);

    let src = backend.open_read(&bp, None).await.expect("open_read");
    assert_eq!(read_all_from_source(src).await.expect("read"), b"slash");

    let cp_init = UploadInit {
        op_id: "op-ls-cp".to_string(),
        dst_path: RelPath::parse("dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    backend
        .server_side_copy(&backend.endpoint_identity(), &bp, &cp_init)
        .await
        .expect("server_side_copy");

    backend.delete(&bp).await.expect("delete");

    let reqs = srv.requests();
    let copy_req = reqs
        .iter()
        .find(|r| r.method == "PUT" && r.path == "/ls-bkt/dst.bin")
        .expect("CopyObject");
    let copy_src = copy_req
        .header("x-amz-copy-source")
        .expect("x-amz-copy-source");
    assert!(
        copy_src == "/ls-bkt//foo" || copy_src == "/ls-bkt/%2Ffoo",
        "x-amz-copy-source must preserve leading slash, got: {copy_src}"
    );
    assert!(
        reqs.iter()
            .any(|r| r.method == "DELETE"
                && (r.path == "/ls-bkt//foo" || r.path == "/ls-bkt/%2Ffoo")),
        "DELETE must preserve leading slash in path"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_trailing_slash_nonzero_object_not_treated_as_directory() {
    let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/ts-bkt" {
                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
                    <ListBucketResult>
                      <IsTruncated>false</IsTruncated>
                      <EncodingType>url</EncodingType>
                      <Contents><Key>data/</Key><Size>128</Size><ETag>\"nz-1\"</ETag></Contents>
                      <Contents><Key>empty_dir/</Key><Size>0</Size><ETag>\"d41d8cd98f00b204e9800998ecf8427e\"</ETag></Contents>
                    </ListBucketResult>";
                MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
            } else {
                MockAction::Respond(MockResponse::empty(404))
            }
        })
        .await;

    let cfg = S3Config::new(
        "s3",
        S3Provider::Minio,
        "ts-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true);
    let backend = make_s3_backend(cfg);

    for recursive in [false, true] {
        let entries = collect_entries(
            backend
                .list_stream(&RelPath::root(), recursive)
                .await
                .expect("list_stream"),
        )
        .await
        .expect("collect");
        let data_entry = entries
            .iter()
            .find(|e| e.nfc_path.as_str() == "data")
            .expect("data/ entry");
        assert_eq!(data_entry.kind, EntryKind::File);
        assert_eq!(data_entry.size, 128);
        assert_eq!(data_entry.raw_path(), "data/");

        let dir_entry = entries
            .iter()
            .find(|e| e.nfc_path.as_str() == "empty_dir")
            .expect("empty_dir/ entry");
        assert_eq!(dir_entry.kind, EntryKind::Directory);
        assert_eq!(dir_entry.size, 0);
    }

    let page = backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect("list_ordered_page");
    let data_page = page
        .entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "data")
        .expect("data/ in ordered page");
    assert_eq!(data_page.kind, EntryKind::File);
    assert_eq!(data_page.size, 128);
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_delete_objects_partial_retryable_error_retries_only_failed_keys() {
    let attempt = Arc::new(AtomicUsize::new(0));
    let attempt_c = attempt.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
            if req.method == "POST" && req.path == "/db-bkt" && req.query.as_deref() == Some("delete=")
            {
                let n = attempt_c.fetch_add(1, Ordering::SeqCst);
                let xml = if n == 0 {
                    "<DeleteResult>
                       <Deleted><Key>b.txt</Key></Deleted>
                       <Error><Key>a.txt</Key><Code>SlowDown</Code><Message>Slow down</Message></Error>
                     </DeleteResult>"
                } else {
                    "<DeleteResult>
                       <Deleted><Key>a.txt</Key></Deleted>
                     </DeleteResult>"
                };
                return MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

    let mut cfg = S3Config::new(
        "s3",
        S3Provider::Minio,
        "db-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true)
    .with_max_retries(3);
    cfg.base_retry_delay = std::time::Duration::from_millis(5);
    cfg.max_retry_delay = std::time::Duration::from_millis(20);
    let backend = make_s3_backend(cfg);

    let failures = backend
        .delete_batch(&[
            BackendPath::from_rel(RelPath::parse("a.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("b.txt").unwrap()),
        ])
        .await
        .expect("delete_batch must retry retryable partial SlowDown");
    assert!(
        failures.is_empty(),
        "expected 0 failures after retry, got {failures:?}"
    );

    let reqs = srv.requests();
    assert_eq!(reqs.len(), 2);
    let second_keys = extract_xml_tag_values(&reqs[1].body_text(), "Key");
    assert_eq!(second_keys, vec!["a.txt"]);
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn tier2_s3_request_time_too_skewed_retries_and_invalid_object_state_not_permission_denied() {
    let list_attempt = Arc::new(AtomicUsize::new(0));
    let list_c = list_attempt.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
            if req.method == "GET" && req.path == "/err-bkt" {
                let n = list_c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    let xml = "<Error><Code>RequestTimeTooSkewed</Code><Message>Difference too large</Message></Error>";
                    return MockAction::Respond(MockResponse::new(403, xml.as_bytes().to_vec()));
                }
                return MockAction::Respond(MockResponse::ok(
                    b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".to_vec(),
                ));
            }
            if req.method == "GET" && req.path == "/err-bkt/archived.bin" {
                let xml = "<Error><Code>InvalidObjectState</Code><Message>Object is in GLACIER storage class</Message></Error>";
                return MockAction::Respond(MockResponse::new(403, xml.as_bytes().to_vec()));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

    let mut cfg = S3Config::new(
        "s3",
        S3Provider::Aws,
        "err-bkt",
        S3Credentials::new("AK", "SK"),
    )
    .with_endpoint(srv.base_url())
    .with_force_path_style(true)
    .with_max_retries(2);
    cfg.base_retry_delay = std::time::Duration::from_millis(5);
    cfg.max_retry_delay = std::time::Duration::from_millis(20);
    let backend = make_s3_backend(cfg);

    let entries = collect_entries(
        backend
            .list_stream(&RelPath::root(), false)
            .await
            .expect("RequestTimeTooSkewed must retry and succeed"),
    )
    .await
    .expect("collect");
    assert!(entries.is_empty());
    assert_eq!(list_attempt.load(Ordering::SeqCst), 2);

    let archived = Entry {
        node_id: None,
        parent_id: None,
        raw_path: None,
        nfc_path: RelPath::parse("archived.bin").unwrap(),
        kind: EntryKind::File,
        size: 16,
        mtime_ns: 0,
        ctime_ns: None,
        etag: Some("\"glacier-1\"".to_string()),
        checksum: None,
    };
    let bp = BackendPath::from_entry(&archived);
    let src = backend
        .open_read_entry(&archived, &bp, None)
        .await
        .expect("open_read_entry");
    let err = read_all_from_source(src)
        .await
        .expect_err("InvalidObjectState must fail read");
    assert!(
        !err.is_retryable(),
        "InvalidObjectState must be permanent: {err:?}"
    );
    assert_ne!(
        err.kind,
        ErrorKind::PermissionDenied,
        "InvalidObjectState must NOT be misclassified as PermissionDenied: {err:?}"
    );
}

// ===========================================================================
// Feature Area #6: Google Cloud Storage (`#[cfg(feature = "gcs")]`)
// ===========================================================================

#[cfg(feature = "gcs")]
fn make_gcs_backend(cfg: GcsConfig) -> GcsBackend {
    let transport = HttpTransport::new(TransportConfig::new()).expect("transport");
    GcsBackend::new(cfg, None, transport).expect("GcsBackend::new")
}

#[cfg(feature = "gcs")]
fn parse_gcs_multipart_related(
    content_type: &str,
    body: &[u8],
) -> Option<(String, serde_json::Value, Vec<u8>)> {
    let boundary = content_type.split(';').find_map(|p| {
        let t = p.trim();
        t.strip_prefix("boundary=")
            .map(|b| b.trim_matches('"').to_string())
    })?;
    let delim = format!("--{boundary}\r\n");
    let mid = format!("\r\n--{boundary}\r\n");
    let end = format!("\r\n--{boundary}--");

    let after_first = body
        .windows(delim.len())
        .position(|w| w == delim.as_bytes())
        .map(|p| &body[p + delim.len()..])?;
    let json_hdr_end = after_first.windows(4).position(|w| w == b"\r\n\r\n")?;
    let after_json_hdr = &after_first[json_hdr_end + 4..];
    let mid_pos = after_json_hdr
        .windows(mid.len())
        .position(|w| w == mid.as_bytes())?;
    let json_val: serde_json::Value = serde_json::from_slice(&after_json_hdr[..mid_pos]).ok()?;

    let part2 = &after_json_hdr[mid_pos + mid.len()..];
    let part2_hdr_end = part2.windows(4).position(|w| w == b"\r\n\r\n")?;
    let after_p2_hdr = &part2[part2_hdr_end + 4..];
    let end_pos = after_p2_hdr
        .windows(end.len())
        .position(|w| w == end.as_bytes())?;
    Some((boundary, json_val, after_p2_hdr[..end_pos].to_vec()))
}

// -----------------------------------------------------------------------
// GCS Tier 1 (5 happy-path tests; MUST pass 100% on baseline `af414db`)
// -----------------------------------------------------------------------

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier1_gcs_list_and_stat() {
    let srv =
        MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/storage/v1/b/gcs-bkt/o/file.txt") => MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "file.txt",
                    "size": "5",
                    "updated": "2026-01-01T00:00:00Z",
                    "generation": "101",
                    "etag": "g-e1",
                    "crc32c": base64_encode(&crc32c(b"hello").to_be_bytes())
                }),
            )),
            ("GET", "/storage/v1/b/gcs-bkt/o/vdir") => {
                MockAction::Respond(MockResponse::empty(404))
            }
            ("GET", "/storage/v1/b/gcs-bkt/o/missing.txt") => {
                MockAction::Respond(MockResponse::empty(404))
            }
            ("GET", "/storage/v1/b/gcs-bkt/o") => {
                let pfx = req.query_get("prefix");
                let delim = req.query_get("delimiter");
                let tok = req.query_get("pageToken");
                if pfx.as_deref() == Some("vdir/")
                    && req.query_get("maxResults").as_deref() == Some("1")
                {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({"items": [{"name": "vdir/inner.txt", "size": "2"}]}),
                    ));
                }
                if pfx.as_deref() == Some("missing.txt/") {
                    return MockAction::Respond(MockResponse::json(200, &serde_json::json!({})));
                }
                match (delim.as_deref(), tok.as_deref()) {
                    (Some("/"), None) => MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "items": [{"name": "file.txt", "size": "5", "generation": "101"}],
                            "prefixes": ["vdir/"],
                            "nextPageToken": "p2"
                        }),
                    )),
                    (Some("/"), Some("p2")) => MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "items": [{"name": "z.txt", "size": "3", "generation": "102"}]
                        }),
                    )),
                    (None, None) => MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "items": [
                                {"name": "file.txt", "size": "5"},
                                {"name": "vdir/inner.txt", "size": "2"}
                            ]
                        }),
                    )),
                    _ => MockAction::Respond(MockResponse::json(200, &serde_json::json!({}))),
                }
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let cfg = GcsRemoteConfig::new()
        .with_bucket("gcs-bkt")
        .with_api_base_url(srv.url("/storage/v1"))
        .with_upload_base_url(srv.url("/upload/storage/v1"))
        .with_anonymous(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("gcs", cfg)
        .build()
        .expect("build client");

    let file_entry = client
        .stat("gcs:file.txt")
        .await
        .unwrap()
        .expect("file.txt");
    assert_eq!(file_entry.size, 5);
    assert_eq!(file_entry.node_id, Some(NodeId("101".to_string())));

    let dir_entry = client.stat("gcs:vdir").await.unwrap().expect("vdir");
    assert_eq!(dir_entry.kind, EntryKind::Directory);
    assert!(client.stat("gcs:missing.txt").await.unwrap().is_none());

    let shallow = collect_entries(client.list("gcs:", &ListOptions::shallow()).await.unwrap())
        .await
        .unwrap();
    assert!(shallow.iter().any(|e| e.nfc_path.as_str() == "file.txt"));
    assert!(
        shallow
            .iter()
            .any(|e| e.nfc_path.as_str() == "vdir" && e.kind == EntryKind::Directory)
    );
    assert!(shallow.iter().any(|e| e.nfc_path.as_str() == "z.txt"));

    let rec = collect_entries(
        client
            .list("gcs:", &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let rec_paths: Vec<&str> = rec.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(rec_paths, vec!["file.txt", "vdir/inner.txt"]);
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier1_gcs_put_single_shot_and_get() {
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let store_c = store.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let mut st = store_c.lock().unwrap_or_else(|e| e.into_inner());
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("multipart")
        {
            let ct = req.header("content-type").unwrap_or("");
            let (_, meta, payload) =
                parse_gcs_multipart_related(ct, &req.body).expect("valid multipart/related");
            let name = meta["name"].as_str().unwrap().to_string();
            let crc_b64 = base64_encode(&crc32c(&payload).to_be_bytes());
            let size_s = payload.len().to_string();
            st.insert(name.clone(), payload);
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": name,
                    "size": size_s,
                    "generation": "201",
                    "etag": "etag-gcs-1",
                    "crc32c": crc_b64,
                    "updated": "2026-01-01T00:00:00Z"
                }),
            ));
        }
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/hello.txt" {
            let Some(data) = st.get("hello.txt") else {
                return MockAction::Respond(MockResponse::empty(404));
            };
            let crc_b64 = base64_encode(&crc32c(data).to_be_bytes());
            if req.query_get("alt").as_deref() == Some("media") {
                if let Some(rh) = req.header("range")
                    && let Some((s, e)) = parse_byte_range_header(rh, data.len())
                {
                    return MockAction::Respond(
                        MockResponse::new(206, data[s..=e].to_vec())
                            .with_header("x-goog-hash", format!("crc32c={crc_b64}"))
                            .with_header("Content-Range", format!("bytes {s}-{e}/{}", data.len())),
                    );
                }
                return MockAction::Respond(
                    MockResponse::ok(data.clone())
                        .with_header("x-goog-hash", format!("crc32c={crc_b64}")),
                );
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "hello.txt",
                    "size": data.len().to_string(),
                    "generation": "201",
                    "etag": "etag-gcs-1",
                    "crc32c": crc_b64
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = Arc::new(make_gcs_backend(cfg));
    let client = RshipClient::builder()
        .ephemeral()
        .register_backend_arc("gcs", backend.clone())
        .build()
        .expect("build client");

    let payload = b"gcs single shot payload!".to_vec();
    let init = UploadInit {
        op_id: "op-gcs-ss-1".to_string(),
        dst_path: RelPath::parse("hello.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let committed = backend
        .put_single_shot(&init, make_byte_stream(payload.clone()))
        .await
        .expect("put_single_shot");
    assert_eq!(committed.size, payload.len() as u64);

    let src = client
        .open_read("gcs:hello.txt", None)
        .await
        .expect("open_read");
    assert_eq!(read_all_from_source(src).await.expect("read_all"), payload);
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier1_gcs_resumable_upload_308_and_get() {
    let session_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let buf_c = session_buf.clone();
    let srv_url_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let url_slot_c = srv_url_slot.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let mut buf = buf_c.lock().unwrap_or_else(|e| e.into_inner());
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("resumable")
        {
            let base = url_slot_c.lock().unwrap().clone();
            return MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Location", format!("{base}/upload/session/sess-1")),
            );
        }
        if req.method == "PUT" && req.path == "/upload/session/sess-1" {
            let cr = req.header("content-range").unwrap_or("");
            if cr.starts_with("bytes */") {
                let end = buf.len().saturating_sub(1);
                return MockAction::Respond(
                    MockResponse::empty(308).with_header("Range", format!("bytes=0-{end}")),
                );
            }
            buf.extend_from_slice(&req.body);
            if buf.len() < (GCS_CHUNK_ALIGN_BYTES as usize + 100) {
                let end = buf.len() - 1;
                return MockAction::Respond(
                    MockResponse::empty(308).with_header("Range", format!("bytes=0-{end}")),
                );
            }
            let crc_b64 = base64_encode(&crc32c(&buf).to_be_bytes());
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "resumable.bin",
                    "size": buf.len().to_string(),
                    "generation": "301",
                    "crc32c": crc_b64
                }),
            ));
        }
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/resumable.bin" {
            if req.query_get("alt").as_deref() == Some("media") {
                return MockAction::Respond(MockResponse::new(206, buf.clone()));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "resumable.bin",
                    "size": buf.len().to_string(),
                    "generation": "301"
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    *srv_url_slot.lock().unwrap() = srv.base_url();

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    cfg.single_shot_max_bytes = 64;
    cfg.chunk_size = GCS_CHUNK_ALIGN_BYTES;
    let backend = make_gcs_backend(cfg);

    let chunk1 = vec![0x11u8; GCS_CHUNK_ALIGN_BYTES as usize];
    let chunk2 = vec![0x22u8; 100];
    let total = (chunk1.len() + chunk2.len()) as u64;
    let init = UploadInit {
        op_id: "op-gcs-res-1".to_string(),
        dst_path: RelPath::parse("resumable.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    let op = make_op_record(
        "gcs",
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        None,
    );

    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk1.len() as u64,
                total,
                make_byte_stream(chunk1.clone()),
            ),
        )
        .await
        .expect("chunk1");
    assert_eq!(ack1.next_offset, Some(chunk1.len() as u64));

    assert_eq!(
        backend.query_upload(&op).await.expect("query_upload"),
        UploadProgress::SequentialOffset(chunk1.len() as u64)
    );

    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk1.len() as u64,
                chunk2.len() as u64,
                total,
                make_byte_stream(chunk2.clone()),
            ),
        )
        .await
        .expect("chunk2");
    let entry = ack2.completed.expect("final chunk commits");
    assert_eq!(entry.size, total);

    let src = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("resumable.bin").unwrap()),
            None,
        )
        .await
        .expect("open_read");
    let mut expected = chunk1;
    expected.extend_from_slice(&chunk2);
    assert_eq!(read_all_from_source(src).await.expect("read_all"), expected);
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier1_gcs_mkdir_and_delete() {
    let srv =
        MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/upload/storage/v1/b/gcs-bkt/o")
                if req.query_get("uploadType").as_deref() == Some("media")
                    && req.query_get("name").as_deref() == Some("dir/sub/") =>
            {
                assert_eq!(req.header("content-type"), Some("application/x-directory"));
                MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({"name": "dir/sub/", "size": "0"}),
                ))
            }
            ("DELETE", "/storage/v1/b/gcs-bkt/o/file.txt") => {
                MockAction::Respond(MockResponse::empty(204))
            }
            ("DELETE", "/storage/v1/b/gcs-bkt/o/dir%2Fsub") => {
                MockAction::Respond(MockResponse::empty(404))
            }
            ("DELETE", "/storage/v1/b/gcs-bkt/o/dir%2Fsub%2F") => {
                MockAction::Respond(MockResponse::empty(204))
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let cfg = GcsRemoteConfig::new()
        .with_bucket("gcs-bkt")
        .with_api_base_url(srv.url("/storage/v1"))
        .with_upload_base_url(srv.url("/upload/storage/v1"))
        .with_anonymous(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("gcs", cfg)
        .build()
        .expect("build client");

    client.mkdir("gcs:dir/sub").await.expect("mkdir");
    client.delete("gcs:file.txt").await.expect("delete file");
    client.delete("gcs:dir/sub").await.expect("delete dir");
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier1_gcs_rename_and_server_side_copy() {
    let srv =
        MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/storage/v1/b/gcs-bkt/o/old.txt") => MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({"name": "old.txt", "size": "7", "generation": "11"}),
            )),
            ("POST", "/storage/v1/b/gcs-bkt/o/old.txt/rewriteTo/b/gcs-bkt/o/new.txt") => {
                MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "done": true,
                        "resource": {"name": "new.txt", "size": "7", "generation": "12"}
                    }),
                ))
            }
            ("DELETE", "/storage/v1/b/gcs-bkt/o/old.txt") => {
                MockAction::Respond(MockResponse::empty(204))
            }
            ("POST", "/storage/v1/b/gcs-bkt/o/a.bin/rewriteTo/b/gcs-bkt/o/b.bin") => {
                if req.query_get("rewriteToken").is_none() {
                    MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({"done": false, "rewriteToken": "rw-tok-1"}),
                    ))
                } else {
                    assert_eq!(req.query_get("rewriteToken").as_deref(), Some("rw-tok-1"));
                    MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "done": true,
                            "resource": {"name": "b.bin", "size": "20", "generation": "13"}
                        }),
                    ))
                }
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = Arc::new(make_gcs_backend(cfg));
    let client = RshipClient::builder()
        .ephemeral()
        .register_backend_arc("gcs", backend.clone())
        .build()
        .expect("build client");

    let renamed = client
        .rename("gcs:old.txt", "new.txt")
        .await
        .expect("rename");
    assert_eq!(renamed.nfc_path.as_str(), "new.txt");

    let ep = backend.endpoint_identity();
    let cp_init = UploadInit {
        op_id: "op-gcs-rw".to_string(),
        dst_path: RelPath::parse("b.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 20,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("a.bin").unwrap()),
            &cp_init,
        )
        .await
        .expect("server_side_copy")
        .expect("Some(entry)");
    assert_eq!(copied.nfc_path.as_str(), "b.bin");
}

// -----------------------------------------------------------------------
// GCS Tier 2 (8 tests covering Audit §III.3 & R2)
// -----------------------------------------------------------------------

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_list_stream_suppresses_self_marker() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "items": [
                        {"name": "sub/", "size": "0", "generation": "1"},
                        {"name": "sub/a.txt", "size": "4", "generation": "2"}
                    ]
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    for recursive in [false, true] {
        let entries = collect_entries(
            backend
                .list_stream(&RelPath::parse("sub").unwrap(), recursive)
                .await
                .expect("list_stream"),
        )
        .await
        .expect("collect");
        let paths: Vec<&str> = entries.iter().map(|e| e.nfc_path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["sub/a.txt"],
            "GCS list_stream(sub, recursive={recursive}) must suppress `sub/` self-marker"
        );
    }
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_rename_same_name_guard_nfd_parent_and_unique_op_id() {
    let nfd_parent = "caf\u{0065}\u{0301}";
    let nfd_old = format!("{nfd_parent}/old.txt");
    let nfd_new = format!("{nfd_parent}/new.txt");
    let enc_nfd_old = gcs_encode_object_name(&nfd_old);
    let enc_nfd_new = gcs_encode_object_name(&nfd_new);

    let srv = MockHttpServer::start_with_handler(move |req| {
            if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/same.txt" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({"name": "same.txt", "size": "5", "generation": "10", "metadata": {"rship-mtime-ns": "1700000000000000000"}}),
                ));
            }
            if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/x1.txt" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({"name": "x1.txt", "size": "5", "generation": "11", "metadata": {"rship-mtime-ns": "1700000000000000000"}}),
                ));
            }
            if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/x2.txt" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({"name": "x2.txt", "size": "5", "generation": "12", "metadata": {"rship-mtime-ns": "1700000000000000000"}}),
                ));
            }
            if req.method == "GET" && req.path == format!("/storage/v1/b/gcs-bkt/o/{enc_nfd_old}") {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({"name": nfd_old, "size": "6", "generation": "20"}),
                ));
            }
            if req.method == "POST" && req.path.contains("/rewriteTo/") {
                let dst_name = req.path.rsplit("/o/").next().unwrap_or("");
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "done": true,
                        "resource": {"name": percent_decode_strict(dst_name), "size": "5", "generation": "99"}
                    }),
                ));
            }
            if req.method == "DELETE" {
                return MockAction::Respond(MockResponse::empty(204));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    // Case A: Same-name rename must NEVER send DELETE.
    let _ = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("same.txt").unwrap()),
            "same.txt",
        )
        .await;
    let reqs_a = srv.take_requests();
    assert!(
        reqs_a.iter().all(|r| r.method != "DELETE"),
        "rename(same.txt, same.txt) must NOT DELETE the source object"
    );

    // Case B: NFD parent path preserved in rewriteTo destination URL.
    let nfd_bp = BackendPath::new(
        format!("{nfd_parent}/old.txt"),
        RelPath::parse(&format!("{nfd_parent}/old.txt")).unwrap(),
        None,
    );
    let _ = backend
        .rename(&nfd_bp, "new.txt")
        .await
        .expect("NFD parent rename");
    let reqs_b = srv.take_requests();
    let rw_b = reqs_b
        .iter()
        .find(|r| r.method == "POST" && r.path.contains("/rewriteTo/"))
        .expect("rewriteTo request");
    assert!(
        rw_b.path.ends_with(&format!("/o/{enc_nfd_new}")),
        "rewriteTo dst path must preserve NFD parent bytes (`{enc_nfd_new}`), got: {}",
        rw_b.path
    );

    // Case C: Two renames with identical mtime_ns must produce unique op_ids.
    backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("x1.txt").unwrap()),
            "y1.txt",
        )
        .await
        .expect("rename x1");
    backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("x2.txt").unwrap()),
            "y2.txt",
        )
        .await
        .expect("rename x2");
    let reqs_c = srv.take_requests();
    let op_ids: Vec<String> = reqs_c
        .iter()
        .filter(|r| r.method == "POST" && r.path.contains("/rewriteTo/"))
        .filter_map(|r| {
            r.body_json()
                .ok()
                .and_then(|v| v["metadata"]["rship-op-id"].as_str().map(str::to_string))
        })
        .collect();
    assert_eq!(
        op_ids.len(),
        2,
        "both rename rewriteTo requests must carry metadata.rship-op-id"
    );
    assert_ne!(
        op_ids[0], op_ids[1],
        "rename op_id must be unique across identical mtime_ns"
    );
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_get_sends_accept_encoding_gzip_and_preserves_raw_bytes() {
    // Minimal valid gzip stream for "hello":
    let raw_gzip: Vec<u8> = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
    ];
    let raw_c = raw_gzip.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/archive.gz" {
            if req.query_get("alt").as_deref() == Some("media") {
                let accepts_gzip = req
                    .header("accept-encoding")
                    .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"));
                if accepts_gzip {
                    return MockAction::Respond(
                        MockResponse::new(206, raw_c.clone())
                            .with_header("Content-Encoding", "gzip")
                            .with_header(
                                "Content-Range",
                                format!("bytes 0-{}/{}", raw_c.len() - 1, raw_c.len()),
                            ),
                    );
                }
                // Simulate GCS decompressive transcoding when Accept-Encoding: gzip is omitted.
                return MockAction::Respond(MockResponse::ok(b"hello".to_vec()));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "archive.gz",
                    "size": raw_c.len().to_string(),
                    "generation": "55"
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    let src = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("archive.gz").unwrap()),
            None,
        )
        .await
        .expect("open_read");
    let got = read_all_from_source(src)
        .await
        .expect("GCS GET with Accept-Encoding: gzip must return raw gzip bytes");
    assert_eq!(got, raw_gzip);

    let reqs = srv.requests();
    let media_req = reqs
        .iter()
        .find(|r| r.query_get("alt").as_deref() == Some("media"))
        .expect("alt=media GET");
    assert!(
        media_req
            .header("accept-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("gzip")),
        "GcsRangeReader must send Accept-Encoding: gzip"
    );
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_dst_precondition_existing_if_generation_match_and_412_409_generation_404() {
    let mode = Arc::new(AtomicUsize::new(0));
    let mode_c = mode.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let m = mode_c.load(Ordering::SeqCst);
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/doc.txt" {
            if req.query_get("alt").as_deref() == Some("media")
                && req.query_get("generation").as_deref() == Some("42")
            {
                return MockAction::Respond(MockResponse::text(404, "No such object generation"));
            }
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "doc.txt",
                    "size": "5",
                    "generation": "99",
                    "metadata": {"rship-op-id": "other-op"}
                }),
            ));
        }
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("multipart")
        {
            let status = if m == 1 { 409 } else { 412 };
            return MockAction::Respond(MockResponse::text(status, "precondition or conflict"));
        }
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("resumable")
        {
            return MockAction::Respond(MockResponse::text(412, "generation mismatch"));
        }
        if req.method == "POST" && req.path.contains("/rewriteTo/") {
            return MockAction::Respond(MockResponse::text(412, "generation mismatch"));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    let existing_pre = DstPrecondition::Existing {
        node_id: Some(NodeId("42".to_string())),
        etag: None,
        mtime_ns: 0,
        size: 5,
    };

    let put_init = UploadInit {
        op_id: "op-gcs-pre-put".to_string(),
        dst_path: RelPath::parse("doc.txt").unwrap(),
        existing_node_id: Some(NodeId("42".to_string())),
        pregenerated_id: None,
        total_size: 3,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: existing_pre.clone(),
        src_etag: None,
    };
    let err_put = backend
        .put_single_shot(&put_init, make_byte_stream(b"abc".to_vec()))
        .await
        .expect_err("412 must fail");
    assert_eq!(err_put.kind, ErrorKind::PreconditionFailed);

    let err_res = backend
        .begin_upload(&put_init)
        .await
        .expect_err("412 on begin_upload must fail");
    assert_eq!(err_res.kind, ErrorKind::PreconditionFailed);

    let ep = backend.endpoint_identity();
    let err_rw = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
            &put_init,
        )
        .await
        .expect_err("412 on rewriteTo must fail");
    assert_eq!(err_rw.kind, ErrorKind::PreconditionFailed);

    let reqs = srv.take_requests();
    for ctx in ["multipart", "resumable"] {
        let r = reqs
            .iter()
            .find(|r| r.query_get("uploadType").as_deref() == Some(ctx))
            .unwrap();
        assert_eq!(
            r.query_get("ifGenerationMatch").as_deref(),
            Some("42"),
            "GCS {ctx} upload must send ifGenerationMatch=42"
        );
    }
    let rw_req = reqs
        .iter()
        .find(|r| r.path.contains("/rewriteTo/"))
        .expect("rewriteTo");
    assert_eq!(
        rw_req.query_get("ifGenerationMatch").as_deref(),
        Some("42"),
        "GCS rewriteTo must send ifGenerationMatch=42"
    );

    mode.store(1, Ordering::SeqCst);
    let err_409 = backend
        .put_single_shot(&put_init, make_byte_stream(b"abc".to_vec()))
        .await
        .expect_err("409 must fail");
    assert_eq!(err_409.kind, ErrorKind::Conflict);

    let pinned = Entry {
        node_id: Some(NodeId("42".to_string())),
        parent_id: None,
        raw_path: None,
        nfc_path: RelPath::parse("doc.txt").unwrap(),
        kind: EntryKind::File,
        size: 5,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    };
    let bp = BackendPath::from_entry(&pinned);
    let src = backend.open_read_entry(&pinned, &bp, None).await.unwrap();
    let err_gen_404 = read_all_from_source(src)
        .await
        .expect_err("404 with ?generation= must fail");
    assert_eq!(err_gen_404.kind, ErrorKind::SourceMutated);
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_multipart_boundary_is_randomized_and_payload_safe() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("multipart")
        {
            let ct = req.header("content-type").unwrap_or("");
            let Some((_, meta, payload)) = parse_gcs_multipart_related(ct, &req.body) else {
                return MockAction::Respond(MockResponse::text(400, "corrupt multipart"));
            };
            let crc_b64 = base64_encode(&crc32c(&payload).to_be_bytes());
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": meta["name"],
                    "size": payload.len().to_string(),
                    "generation": "501",
                    "crc32c": crc_b64
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    let tricky_payload = b"prefix\r\n--rship_gcs_mp_boundary_9f3c7e2b\r\nmiddle\r\n--rship_gcs_mp_boundary_9f3c7e2b\r\nsuffix".to_vec();
    for i in 0..2 {
        let init = UploadInit {
            op_id: format!("op-gcs-bnd-{i}"),
            dst_path: RelPath::parse(&format!("bnd-{i}.bin")).unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: tricky_payload.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
            checksums: Vec::new(),
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        let entry = backend
            .put_single_shot(&init, make_byte_stream(tricky_payload.clone()))
            .await
            .expect("multipart upload with tricky payload");
        assert_eq!(entry.size, tricky_payload.len() as u64);
    }

    let reqs = srv.requests();
    let boundaries: Vec<String> = reqs
        .iter()
        .filter_map(|r| {
            let ct = r.header("content-type")?;
            let (b, _, payload) = parse_gcs_multipart_related(ct, &r.body)?;
            assert_eq!(payload, tricky_payload);
            Some(b)
        })
        .collect();
    assert_eq!(boundaries.len(), 2);
    assert_ne!(boundaries[0], "rship_gcs_mp_boundary_9f3c7e2b");
    assert_ne!(boundaries[0], boundaries[1]);
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_rewrite_isolates_metadata_patch_and_if_source_generation_match() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "GET" && req.path == "/storage/v1/b/gcs-bkt/o/src.bin" {
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "name": "src.bin",
                    "size": "16",
                    "generation": "777",
                    "cacheControl": "public, max-age=3600",
                    "metadata": {"x-custom": "keep-me"}
                }),
            ));
        }
        if req.method == "POST"
            && req.path == "/storage/v1/b/gcs-bkt/o/src.bin/rewriteTo/b/gcs-bkt/o/dst.bin"
        {
            // GCS objects.rewrite semantics: source has {"x-custom": "keep-me"} + cacheControl.
            // If request body specifies "metadata", it replaces source's metadata map.
            let body_val = if req.body.is_empty() {
                serde_json::json!({})
            } else {
                req.body_json().unwrap_or_else(|_| serde_json::json!({}))
            };
            let dst_meta = if let Some(m) = body_val.get("metadata") {
                m.clone()
            } else {
                serde_json::json!({"x-custom": "keep-me"})
            };
            let cache_ctl = body_val
                .get("cacheControl")
                .and_then(|v| v.as_str())
                .unwrap_or("public, max-age=3600");
            return MockAction::Respond(MockResponse::json(
                200,
                &serde_json::json!({
                    "done": true,
                    "resource": {
                        "name": "dst.bin",
                        "size": "16",
                        "generation": "888",
                        "cacheControl": cache_ctl,
                        "metadata": dst_meta
                    }
                }),
            ));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap())
        .with_node_id(Some(NodeId("777".to_string())));
    let init = UploadInit {
        op_id: "op-gcs-rw-iso".to_string(),
        dst_path: RelPath::parse("dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: vec![Checksum {
            kind: HashKind::Crc32c,
            hex: "01020304".to_string(),
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .server_side_copy(&backend.endpoint_identity(), &src_bp, &init)
        .await
        .expect("server_side_copy");

    let reqs = srv.requests();
    let rw = reqs
        .iter()
        .find(|r| r.path.contains("/rewriteTo/"))
        .expect("rewriteTo");
    assert_eq!(
        rw.query_get("ifSourceGenerationMatch").as_deref(),
        Some("777"),
        "rewriteTo must pass ifSourceGenerationMatch when src_path.node_id is set"
    );
    assert!(
        !rw.body.is_empty(),
        "rewriteTo must send metadata JSON body to preserve source custom metadata"
    );
    let json = rw.body_json().expect("rewrite JSON body");
    assert!(
        json.get("crc32c").is_none() && json.get("md5Hash").is_none(),
        "rewriteTo body must NOT inject upload checksum fields: {json}"
    );
    let meta = json
        .get("metadata")
        .expect("rewriteTo body must preserve source metadata map");
    assert_eq!(
        meta.get("x-custom").and_then(|v| v.as_str()),
        Some("keep-me"),
        "rewriteTo must not wipe existing source custom metadata: {json}"
    );
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_zero_byte_resumable_query_upload_sends_wildcard_range() {
    let srv_url_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let url_c = srv_url_slot.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if req.method == "POST"
            && req.path == "/upload/storage/v1/b/gcs-bkt/o"
            && req.query_get("uploadType").as_deref() == Some("resumable")
        {
            let base = url_c.lock().unwrap().clone();
            return MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Location", format!("{base}/upload/session/zero-1")),
            );
        }
        if req.method == "PUT" && req.path == "/upload/session/zero-1" {
            return MockAction::Respond(MockResponse::empty(308));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;
    *srv_url_slot.lock().unwrap() = srv.base_url();

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    let backend = make_gcs_backend(cfg);

    let init = UploadInit {
        op_id: "op-gcs-zero".to_string(),
        dst_path: RelPath::parse("empty.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 0,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    let op = make_op_record(
        "gcs",
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        None,
    );
    let _ = backend.query_upload(&op).await.expect("query_upload");

    let reqs = srv.requests();
    let q_req = reqs
        .iter()
        .find(|r| r.method == "PUT" && r.path == "/upload/session/zero-1")
        .expect("query_upload PUT");
    assert_eq!(
        q_req.header("content-range"),
        Some("bytes */*"),
        "0-byte resumable query_upload must send Content-Range: bytes */*"
    );
}

#[cfg(feature = "gcs")]
#[tokio::test]
async fn tier2_gcs_r2_mtime_and_user_project() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("POST", "/upload/storage/v1/b/gcs-bkt/o")
                    if req.query_get("uploadType").as_deref() == Some("multipart") =>
                {
                    let ct = req.header("content-type").unwrap_or("");
                    let (_, meta, payload) =
                        parse_gcs_multipart_related(ct, &req.body).expect("multipart");
                    let crc_b64 = base64_encode(&crc32c(&payload).to_be_bytes());
                    MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "name": meta["name"],
                            "size": payload.len().to_string(),
                            "generation": "701",
                            "crc32c": crc_b64,
                            "metadata": meta["metadata"]
                        }),
                    ))
                }
                ("POST", "/upload/storage/v1/b/gcs-bkt/o")
                    if req.query_get("uploadType").as_deref() == Some("resumable") =>
                {
                    MockAction::Respond(
                        MockResponse::empty(200)
                            .with_header("Location", "http://127.0.0.1:1/upload/session/u1"),
                    )
                }
                ("GET", "/storage/v1/b/gcs-bkt/o/rclone-reserved.txt") => MockAction::Respond(
                    MockResponse::json(
                        200,
                        &serde_json::json!({
                            "name": "rclone-reserved.txt",
                            "size": "3",
                            "generation": "1",
                            "metadata": {"goog-reserved-file-mtime": "1700000000"}
                        }),
                    ),
                ),
                ("GET", "/storage/v1/b/gcs-bkt/o/rclone-rfc.txt") => MockAction::Respond(
                    MockResponse::json(
                        200,
                        &serde_json::json!({
                            "name": "rclone-rfc.txt",
                            "size": "3",
                            "generation": "2",
                            "metadata": {"mtime": "2023-11-14T22:13:20.123456789Z"}
                        }),
                    ),
                ),
                ("GET", "/storage/v1/b/gcs-bkt/o/legacy-rship.txt") => MockAction::Respond(
                    MockResponse::json(
                        200,
                        &serde_json::json!({
                            "name": "legacy-rship.txt",
                            "size": "3",
                            "generation": "3",
                            "metadata": {"rship-mtime-ns": "1700000005000000000"}
                        }),
                    ),
                ),
                ("GET", "/storage/v1/b/gcs-bkt/o") => MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "items": [
                            {"name": "rclone-reserved.txt", "size": "3", "metadata": {"goog-reserved-file-mtime": "1700000000"}},
                            {"name": "rclone-rfc.txt", "size": "3", "metadata": {"mtime": "2023-11-14T22:13:20.123456789Z"}},
                            {"name": "legacy-rship.txt", "size": "3", "metadata": {"rship-mtime-ns": "1700000005000000000"}}
                        ]
                    }),
                )),
                ("DELETE", "/storage/v1/b/gcs-bkt/o/rclone-reserved.txt") => {
                    MockAction::Respond(MockResponse::empty(204))
                }
                ("POST", p) if p.contains("/rewriteTo/") => MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "done": true,
                        "resource": {"name": "copied.txt", "size": "3", "generation": "9"}
                    }),
                )),
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let mut cfg = GcsConfig::new("gcs", "gcs-bkt").with_endpoint(&srv.base_url());
    cfg.anonymous = true;
    cfg.project_number = Some("pay-proj-123".to_string());
    let backend = make_gcs_backend(cfg);

    // 1. Write mtime via put_single_shot & begin_upload
    let init = UploadInit {
        op_id: "op-gcs-r2-1".to_string(),
        dst_path: RelPath::parse("up.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_123_456_789,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .put_single_shot(&init, make_byte_stream(b"data".to_vec()))
        .await
        .expect("put_single_shot");
    backend.begin_upload(&init).await.expect("begin_upload");

    // 2. Dual-read via stat + list_stream
    let e_res = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("rclone-reserved.txt").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_res.mtime_ns, 1_700_000_000_000_000_000);

    let e_rfc = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("rclone-rfc.txt").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_rfc.mtime_ns, 1_700_000_000_123_456_789);

    let e_leg = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("legacy-rship.txt").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_leg.mtime_ns, 1_700_000_005_000_000_000);

    let listed = collect_entries(
        backend
            .list_stream(&RelPath::root(), false)
            .await
            .expect("list_stream"),
    )
    .await
    .unwrap();
    assert_eq!(listed[0].mtime_ns, 1_700_000_000_000_000_000);
    assert_eq!(listed[1].mtime_ns, 1_700_000_000_123_456_789);
    assert_eq!(listed[2].mtime_ns, 1_700_000_005_000_000_000);

    // 3. Delete & rewriteTo also carry userProject
    backend
        .delete(
            &BackendPath::from_rel(RelPath::parse("rclone-reserved.txt").unwrap())
                .with_kind(Some(EntryKind::File)),
        )
        .await
        .expect("delete");
    backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("rclone-reserved.txt").unwrap()),
            &init,
        )
        .await
        .expect("rewriteTo");

    let reqs = srv.requests();
    let mp_req = reqs
        .iter()
        .find(|r| r.query_get("uploadType").as_deref() == Some("multipart"))
        .unwrap();
    let (_, mp_meta, _) =
        parse_gcs_multipart_related(mp_req.header("content-type").unwrap(), &mp_req.body).unwrap();
    let is_valid_gcs_epoch = |val: Option<&serde_json::Value>| -> bool {
        val.and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|s| {
                s.parse::<f64>()
                    .is_ok_and(|secs| secs.is_finite() && secs > 0.0)
            })
    };
    assert!(
        is_valid_gcs_epoch(mp_meta["metadata"].get("goog-reserved-file-mtime")),
        "GCS upload must write valid non-zero `goog-reserved-file-mtime` metadata key, got: {mp_meta}"
    );

    let res_req = reqs
        .iter()
        .find(|r| r.query_get("uploadType").as_deref() == Some("resumable"))
        .unwrap();
    let res_meta = res_req.body_json().unwrap();
    assert!(
        is_valid_gcs_epoch(res_meta["metadata"].get("goog-reserved-file-mtime")),
        "GCS resumable init must write valid non-zero `goog-reserved-file-mtime`: {res_meta}"
    );

    for r in &reqs {
        assert_eq!(
            r.query_get("userProject").as_deref(),
            Some("pay-proj-123"),
            "GCS request `{} {}` missing `userProject=pay-proj-123`",
            r.method,
            r.path
        );
    }
}

// ===========================================================================
// Feature Area #7: Azure Blob Storage (`#[cfg(feature = "azureblob")]`)
// ===========================================================================

#[cfg(feature = "azureblob")]
fn make_azure_backend(cfg: AzureBlobConfig, auth: AzureAuth) -> AzureBlobBackend {
    let transport = HttpTransport::new(TransportConfig::new()).expect("transport");
    AzureBlobBackend::new(cfg, auth, transport, None).expect("AzureBlobBackend::new")
}

/// Independent Azure Storage SharedKey HMAC-SHA256 verifier (REST API 2023-11-03).
/// Decodes query parameters strictly (`%20` -> `' '`, `+` remains literal `+`) so
/// `+` vs `%20` mismatches on wire fail verification just as real Azure Storage rejects them.
#[cfg(feature = "azureblob")]
fn verify_azure_shared_key(
    req: &CapturedRequest,
    account: &str,
    key_b64: &str,
) -> std::result::Result<(), String> {
    let auth_hdr = req
        .header("authorization")
        .ok_or_else(|| "missing Authorization header".to_string())?;
    let sig_part = auth_hdr
        .strip_prefix(&format!("SharedKey {account}:"))
        .ok_or_else(|| format!("unexpected Authorization prefix: {auth_hdr}"))?;
    let key_bytes = base64_decode(key_b64).ok_or_else(|| "bad key b64".to_string())?;

    let content_encoding = req.header("content-encoding").unwrap_or("");
    let content_language = req.header("content-language").unwrap_or("");
    let raw_cl = req.header("content-length").unwrap_or("");
    let content_length = if raw_cl.is_empty() || raw_cl == "0" {
        ""
    } else {
        raw_cl
    };
    let content_md5 = req.header("content-md5").unwrap_or("");
    let content_type = req.header("content-type").unwrap_or("");
    let date = if req.header("x-ms-date").is_some() {
        ""
    } else {
        req.header("date").unwrap_or("")
    };
    let if_modified_since = req.header("if-modified-since").unwrap_or("");
    let if_match = req.header("if-match").unwrap_or("");
    let if_none_match = req.header("if-none-match").unwrap_or("");
    let if_unmodified_since = req.header("if-unmodified-since").unwrap_or("");
    let range = req.header("range").unwrap_or("");

    let mut xms: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, vals) in &req.headers {
        if k.starts_with("x-ms-") {
            let collapsed: Vec<String> = vals
                .iter()
                .map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect();
            xms.entry(k.clone()).or_default().extend(collapsed);
        }
    }
    let mut canon_headers = String::new();
    for (k, vals) in xms {
        canon_headers.push_str(&k);
        canon_headers.push(':');
        canon_headers.push_str(&vals.join(","));
        canon_headers.push('\n');
    }

    let mut canon_resource = format!("/{account}{}", req.path);
    if let Some(q) = &req.query {
        let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pair in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            params
                .entry(percent_decode_strict(k).to_ascii_lowercase())
                .or_default()
                .push(percent_decode_strict(v));
        }
        for (k, mut vals) in params {
            vals.sort();
            canon_resource.push('\n');
            canon_resource.push_str(&k);
            canon_resource.push(':');
            canon_resource.push_str(&vals.join(","));
        }
    }

    let sts = format!(
        "{}\n{content_encoding}\n{content_language}\n{content_length}\n{content_md5}\n{content_type}\n{date}\n{if_modified_since}\n{if_match}\n{if_none_match}\n{if_unmodified_since}\n{range}\n{canon_headers}{canon_resource}",
        req.method
    );
    let expected_sig = base64_encode(&hmac_sha256(&key_bytes, sts.as_bytes()));
    if expected_sig == sig_part {
        Ok(())
    } else {
        Err(format!(
            "SharedKey mismatch: expected `{expected_sig}`, got `{sig_part}`; sts={sts:?}"
        ))
    }
}

// -----------------------------------------------------------------------
// Azure Blob Tier 1 (5 happy-path tests; MUST pass 100% on baseline)
// -----------------------------------------------------------------------

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier1_azureblob_list_and_stat() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("HEAD", "/mycont/hello.txt") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "5")
                        .with_header("ETag", "\"0x8DC1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT")
                        .with_header("Content-MD5", base64_encode(&md5_digest(b"hello"))),
                ),
                ("HEAD", "/mycont/vdir") | ("HEAD", "/mycont/missing.txt") => {
                    MockAction::Respond(MockResponse::empty(404))
                }
                ("GET", "/mycont") if req.query_get("comp").as_deref() == Some("list") => {
                    let pfx = req.query_get("prefix");
                    let delim = req.query_get("delimiter");
                    let marker = req.query_get("marker");
                    if pfx.as_deref() == Some("vdir/") && req.query_get("maxresults").as_deref() == Some("1") {
                        let xml = "<EnumerationResults><Blobs><Blob><Name>vdir/in.txt</Name><Properties><Content-Length>2</Content-Length></Properties></Blob></Blobs></EnumerationResults>";
                        return MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()));
                    }
                    if pfx.as_deref() == Some("missing.txt/") {
                        return MockAction::Respond(MockResponse::ok(
                            b"<EnumerationResults><Blobs/></EnumerationResults>".to_vec(),
                        ));
                    }
                    let xml = match (delim.as_deref(), marker.as_deref()) {
                        (Some("/"), None) => "<EnumerationResults><Blobs>
                            <Blob><Name>hello.txt</Name><Properties><Content-Length>5</Content-Length><Etag>\"0x8DC1\"</Etag></Properties></Blob>
                            <BlobPrefix><Name>vdir/</Name></BlobPrefix>
                          </Blobs><NextMarker>m2</NextMarker></EnumerationResults>",
                        (Some("/"), Some("m2")) => "<EnumerationResults><Blobs>
                            <Blob><Name>z.txt</Name><Properties><Content-Length>3</Content-Length></Properties></Blob>
                          </Blobs><NextMarker/></EnumerationResults>",
                        (None, None) => "<EnumerationResults><Blobs>
                            <Blob><Name>hello.txt</Name><Properties><Content-Length>5</Content-Length></Properties></Blob>
                            <Blob><Name>vdir/in.txt</Name><Properties><Content-Length>2</Content-Length></Properties></Blob>
                          </Blobs></EnumerationResults>",
                        _ => "<EnumerationResults><Blobs/></EnumerationResults>",
                    };
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let cfg = AzureblobRemoteConfig::new()
        .with_account("myacct")
        .with_container("mycont")
        .with_endpoint(srv.base_url())
        .with_anonymous(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("az", cfg)
        .build()
        .expect("build client");

    let e = client
        .stat("az:hello.txt")
        .await
        .unwrap()
        .expect("hello.txt");
    assert_eq!(e.size, 5);
    assert!(e.checksum.is_some());

    let vdir = client.stat("az:vdir").await.unwrap().expect("vdir");
    assert_eq!(vdir.kind, EntryKind::Directory);
    assert!(client.stat("az:missing.txt").await.unwrap().is_none());

    let shallow = collect_entries(client.list("az:", &ListOptions::shallow()).await.unwrap())
        .await
        .unwrap();
    assert!(shallow.iter().any(|x| x.nfc_path.as_str() == "hello.txt"));
    assert!(
        shallow
            .iter()
            .any(|x| x.nfc_path.as_str() == "vdir" && x.kind == EntryKind::Directory)
    );
    assert!(shallow.iter().any(|x| x.nfc_path.as_str() == "z.txt"));

    let rec = collect_entries(client.list("az:", &ListOptions::recursive()).await.unwrap())
        .await
        .unwrap();
    let names: Vec<&str> = rec.iter().map(|x| x.nfc_path.as_str()).collect();
    assert_eq!(names, vec!["hello.txt", "vdir/in.txt"]);
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier1_azureblob_put_single_shot_and_get() {
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let store_c = store.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        let mut st = store_c.lock().unwrap_or_else(|e| e.into_inner());
        if req.path != "/mycont/single.bin" {
            return MockAction::Respond(MockResponse::empty(404));
        }
        match req.method.as_str() {
            "PUT" => {
                assert_eq!(req.header("x-ms-blob-type"), Some("BlockBlob"));
                let md5_b64 = base64_encode(&md5_digest(&req.body));
                st.insert("single.bin".to_string(), req.body.clone());
                MockAction::Respond(
                    MockResponse::empty(201)
                        .with_header("ETag", "\"0x8DC1\"")
                        .with_header("Content-MD5", md5_b64)
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                )
            }
            "HEAD" => {
                let Some(data) = st.get("single.bin") else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", data.len().to_string())
                        .with_header("ETag", "\"0x8DC1\"")
                        .with_header("Content-MD5", base64_encode(&md5_digest(data))),
                )
            }
            "GET" => {
                let Some(data) = st.get("single.bin") else {
                    return MockAction::Respond(MockResponse::empty(404));
                };
                assert_eq!(req.header("if-match"), Some("\"0x8DC1\""));
                let md5_b64 = base64_encode(&md5_digest(data));
                if let Some(rh) = req.header("range")
                    && let Some((s, e)) = parse_byte_range_header(rh, data.len())
                {
                    return MockAction::Respond(
                        MockResponse::new(206, data[s..=e].to_vec())
                            .with_header("ETag", "\"0x8DC1\"")
                            .with_header("Content-MD5", md5_b64)
                            .with_header("Content-Range", format!("bytes {s}-{e}/{}", data.len())),
                    );
                }
                MockAction::Respond(
                    MockResponse::ok(data.clone()).with_header("ETag", "\"0x8DC1\""),
                )
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        }
    })
    .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = Arc::new(make_azure_backend(cfg, AzureAuth::Anonymous));
    let client = RshipClient::builder()
        .ephemeral()
        .register_backend_arc("az", backend.clone())
        .build()
        .expect("build client");

    let payload = b"azure single-shot blob payload".to_vec();
    let init = UploadInit {
        op_id: "op-az-ss-1".to_string(),
        dst_path: RelPath::parse("single.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let committed = backend
        .put_single_shot(&init, make_byte_stream(payload.clone()))
        .await
        .expect("put_single_shot");
    assert_eq!(committed.size, payload.len() as u64);

    let src = client
        .open_read("az:single.bin", None)
        .await
        .expect("open_read");
    assert_eq!(read_all_from_source(src).await.expect("read_all"), payload);
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier1_azureblob_block_upload_put_block_get_block_list_and_commit() {
    let blocks: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let blocks_c = blocks.clone();
    let committed_blob: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let committed_c = committed_blob.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
            if req.path != "/mycont/blocks.bin" {
                return MockAction::Respond(MockResponse::empty(404));
            }
            match (req.method.as_str(), req.query_get("comp").as_deref()) {
                ("PUT", Some("block")) => {
                    let bid = req.query_get("blockid").expect("blockid");
                    blocks_c.lock().unwrap().insert(bid, req.body.clone());
                    MockAction::Respond(MockResponse::empty(201))
                }
                ("GET", Some("blocklist")) => {
                    let guard = blocks_c.lock().unwrap();
                    let mut uncomm = String::new();
                    for (bid, data) in guard.iter() {
                        uncomm.push_str(&format!(
                            "<Block><Name>{}</Name><Size>{}</Size></Block>",
                            xml_escape(bid),
                            data.len()
                        ));
                    }
                    let xml = format!(
                        "<BlockList><CommittedBlocks/><UncommittedBlocks>{uncomm}</UncommittedBlocks></BlockList>"
                    );
                    MockAction::Respond(MockResponse::ok(xml.into_bytes()))
                }
                ("PUT", Some("blocklist")) => {
                    let guard = blocks_c.lock().unwrap();
                    let latest = extract_xml_tag_values(&req.body_text(), "Latest");
                    let mut buf = Vec::new();
                    for id in latest {
                        let data = guard.get(&id).expect("staged block present");
                        buf.extend_from_slice(data);
                    }
                    *committed_c.lock().unwrap() = Some(buf);
                    MockAction::Respond(
                        MockResponse::empty(201)
                            .with_header("ETag", "\"0x8DC-BLK\"")
                            .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                    )
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    cfg.single_shot_max_bytes = 64;
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    let b1 = vec![0x31u8; AZURE_MIN_BLOCK_BYTES as usize];
    let b2 = vec![0x32u8; 77];
    let total = (b1.len() + b2.len()) as u64;
    let init = UploadInit {
        op_id: "op-az-blk-1".to_string(),
        dst_path: RelPath::parse("blocks.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.expect("begin_upload");
    let op = make_op_record(
        "azureblob",
        &init,
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
        None,
    );

    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, b1.len() as u64, total, make_byte_stream(b1.clone())),
        )
        .await
        .expect("PutBlock 1");

    match backend.query_upload(&op).await.expect("GetBlockList") {
        UploadProgress::CompletedParts(parts) => {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].part_number, 1);
            assert_eq!(parts[0].length, b1.len() as u64);
        }
        other => panic!("expected CompletedParts, got {other:?}"),
    }

    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                b1.len() as u64,
                b2.len() as u64,
                total,
                make_byte_stream(b2.clone()),
            ),
        )
        .await
        .expect("PutBlock 2");

    let entry = backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: b1.len() as u64,
                    etag: ack1.etag.unwrap(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 2,
                    offset: b1.len() as u64,
                    length: b2.len() as u64,
                    etag: ack2.etag.unwrap(),
                    checksum: None,
                },
            ],
        )
        .await
        .expect("PutBlockList");
    assert_eq!(entry.size, total);
    let mut expected = b1;
    expected.extend_from_slice(&b2);
    assert_eq!(
        committed_blob.lock().unwrap().as_deref(),
        Some(expected.as_slice())
    );
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier1_azureblob_mkdir_and_delete() {
    let srv =
        MockHttpServer::start_with_handler(|req| match (req.method.as_str(), req.path.as_str()) {
            ("PUT", "/mycont/dir/sub/") => {
                assert_eq!(req.header("x-ms-blob-type"), Some("BlockBlob"));
                assert_eq!(req.header("content-type"), Some("application/x-directory"));
                MockAction::Respond(MockResponse::empty(201))
            }
            ("DELETE", "/mycont/file.txt") => MockAction::Respond(MockResponse::empty(202)),
            ("DELETE", "/mycont/dir/sub") => MockAction::Respond(MockResponse::empty(404)),
            ("DELETE", "/mycont/dir/sub/") => MockAction::Respond(MockResponse::empty(202)),
            _ => MockAction::Respond(MockResponse::empty(404)),
        })
        .await;

    let cfg = AzureblobRemoteConfig::new()
        .with_account("myacct")
        .with_container("mycont")
        .with_endpoint(srv.base_url())
        .with_anonymous(true);
    let client = RshipClient::builder()
        .ephemeral()
        .remote("az", cfg)
        .build()
        .expect("build client");

    client.mkdir("az:dir/sub").await.expect("mkdir");
    client.delete("az:file.txt").await.expect("delete file");
    client.delete("az:dir/sub").await.expect("delete dir");
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier1_azureblob_server_side_copy_async_poll_and_shared_key_signing() {
    let head_calls = Arc::new(AtomicUsize::new(0));
    let head_c = head_calls.clone();

    let srv = MockHttpServer::start_with_handler(move |req| {
        if let Err(reason) = verify_azure_shared_key(req, AZURITE_ACCOUNT, AZURITE_KEY) {
            return MockAction::Respond(MockResponse::text(403, reason));
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("PUT", "/devstoreaccount1/mycont/dst.bin") => {
                assert!(req.header("x-ms-copy-source").is_some());
                MockAction::Respond(
                    MockResponse::empty(202)
                        .with_header("x-ms-copy-status", "pending")
                        .with_header("x-ms-copy-id", "cp-1"),
                )
            }
            ("HEAD", "/devstoreaccount1/mycont/dst.bin") => {
                let n = head_c.fetch_add(1, Ordering::SeqCst);
                let status = if n == 0 { "pending" } else { "success" };
                MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "12")
                        .with_header("ETag", "\"0x8DC-CP\"")
                        .with_header("x-ms-copy-status", status),
                )
            }
            _ => MockAction::Respond(MockResponse::empty(404)),
        }
    })
    .await;

    let mut cfg = AzureBlobConfig::new("az", AZURITE_ACCOUNT, "mycont");
    cfg.endpoint = Some(format!("{}/{AZURITE_ACCOUNT}", srv.base_url()));
    let auth = AzureAuth::shared_key(AZURITE_ACCOUNT, AZURITE_KEY).expect("shared_key");
    let backend = make_azure_backend(cfg, auth);

    let ep = backend.endpoint_identity();
    let init = UploadInit {
        op_id: "op-az-cp-1".to_string(),
        dst_path: RelPath::parse("dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 12,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &init,
        )
        .await
        .expect("server_side_copy with SharedKey + async poll")
        .expect("Some(entry)");
    assert_eq!(entry.size, 12);
    assert!(head_calls.load(Ordering::SeqCst) >= 2);
}

// -----------------------------------------------------------------------
// Azure Blob Tier 2 (8 tests covering Audit §III.4 & R2)
// -----------------------------------------------------------------------

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_percent20_query_encoding_and_shared_key_with_spaces() {
    let srv = MockHttpServer::start_with_handler(|req| {
            if let Err(reason) = verify_azure_shared_key(req, "myacct", AZURITE_KEY) {
                return MockAction::Respond(MockResponse::text(403, reason));
            }
            if req.method == "HEAD" {
                return MockAction::Respond(MockResponse::empty(404));
            }
            if req.method == "GET" && req.path == "/mycont" {
                let raw_q = req.query.as_deref().unwrap_or("");
                if raw_q.contains('+') {
                    return MockAction::Respond(MockResponse::text(400, "plus sign in query"));
                }
                let q_params: HashMap<String, String> = raw_q
                    .split('&')
                    .filter(|part| !part.is_empty())
                    .map(|part| match part.split_once('=') {
                        Some((k, v)) => (percent_decode_strict(k), percent_decode_strict(v)),
                        None => (percent_decode_strict(part), String::new()),
                    })
                    .collect();
                if q_params.get("marker").map(String::as_str) == Some("2!mark with space") {
                    return MockAction::Respond(MockResponse::ok(
                        b"<EnumerationResults><Blobs><Blob><Name>my dir/sub dir/b.txt</Name><Properties><Content-Length>2</Content-Length></Properties></Blob></Blobs><NextMarker/></EnumerationResults>".to_vec(),
                    ));
                }
                if q_params.get("prefix").map(String::as_str) == Some("my dir/sub dir/") {
                    return MockAction::Respond(MockResponse::ok(
                        b"<EnumerationResults><Blobs><Blob><Name>my dir/sub dir/a.txt</Name><Properties><Content-Length>1</Content-Length></Properties></Blob></Blobs><NextMarker>2!mark with space</NextMarker></EnumerationResults>".to_vec(),
                    ));
                }
                if q_params.get("prefix").map(String::as_str) == Some("my dir/") {
                    return MockAction::Respond(MockResponse::ok(
                        b"<EnumerationResults><Blobs><Blob><Name>my dir/sub dir/a.txt</Name><Properties><Content-Length>1</Content-Length></Properties></Blob></Blobs></EnumerationResults>".to_vec(),
                    ));
                }
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let auth = AzureAuth::shared_key("myacct", AZURITE_KEY).expect("shared_key");
    let backend = make_azure_backend(cfg, auth);

    let entries = collect_entries(
        backend
            .list_stream(&RelPath::parse("my dir/sub dir").unwrap(), false)
            .await
            .expect("list_stream with spaces"),
    )
    .await
    .expect("collect");
    assert_eq!(entries.len(), 2);

    let dir_stat = backend
        .stat(&BackendPath::from_rel(RelPath::parse("my dir").unwrap()))
        .await
        .expect("stat virtual dir with space")
        .expect("dir exists");
    assert_eq!(dir_stat.kind, EntryKind::Directory);

    let reqs = srv.requests();
    for r in reqs.iter().filter(|r| r.method == "GET") {
        let q = r.query.as_deref().unwrap_or("");
        assert!(
            !q.contains('+'),
            "Azure query string MUST use %20, NEVER `+`, got: {q}"
        );
    }
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_block_ids_no_collision_and_equal_length() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "PUT" && req.query_get("comp").as_deref() == Some("block") {
            MockAction::Respond(MockResponse::empty(201))
        } else {
            MockAction::Respond(MockResponse::empty(404))
        }
    })
    .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    let make_op = |op_id: &str| -> OperationRecord {
        let init = UploadInit {
            op_id: op_id.to_string(),
            dst_path: RelPath::parse("shared.bin").unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 1_000_000,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
            checksums: Vec::new(),
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        make_op_record(
            "azureblob",
            &init,
            Some(op_id.to_string()),
            "{}".to_string(),
            None,
        )
    };

    let op_a = make_op("op-20261127080000-fileA");
    let op_b = make_op("op-20261127080000-fileB");

    let ack_a1 = backend
        .upload_chunk(
            &op_a,
            ChunkUpload::new(1, 0, 8, 1_000_000, make_byte_stream(vec![1; 8])),
        )
        .await
        .unwrap();
    let ack_a10 = backend
        .upload_chunk(
            &op_a,
            ChunkUpload::new(10, 8, 8, 1_000_000, make_byte_stream(vec![2; 8])),
        )
        .await
        .unwrap();
    let ack_a9999 = backend
        .upload_chunk(
            &op_a,
            ChunkUpload::new(9999, 16, 8, 1_000_000, make_byte_stream(vec![3; 8])),
        )
        .await
        .unwrap();
    let ack_b1 = backend
        .upload_chunk(
            &op_b,
            ChunkUpload::new(1, 0, 8, 1_000_000, make_byte_stream(vec![4; 8])),
        )
        .await
        .unwrap();

    let id_a1 = ack_a1.etag.unwrap();
    let id_a10 = ack_a10.etag.unwrap();
    let id_a9999 = ack_a9999.etag.unwrap();
    let id_b1 = ack_b1.etag.unwrap();

    assert_ne!(
        id_a1, id_b1,
        "distinct op_ids sharing >16-char prefix must NOT collide in Azure block IDs"
    );
    let raw_len_a1 = base64_decode(&id_a1).expect("valid b64").len();
    let raw_len_a10 = base64_decode(&id_a10).expect("valid b64").len();
    let raw_len_a9999 = base64_decode(&id_a9999).expect("valid b64").len();
    let raw_len_b1 = base64_decode(&id_b1).expect("valid b64").len();
    assert_eq!(raw_len_a1, raw_len_a10);
    assert_eq!(raw_len_a1, raw_len_a9999);
    assert_eq!(raw_len_a1, raw_len_b1);
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_reconcile_operation_checks_x_ms_copy_status_for_move_safety() {
    let srv = MockHttpServer::start().await;
    for status in ["pending", "failed", "success"] {
        srv.enqueue_response(
            MockResponse::empty(200)
                .with_header("Content-Length", "100")
                .with_header("ETag", "\"0x8DC-REC\"")
                .with_header("x-ms-meta-rship_op_id", "op-move-1")
                .with_header("x-ms-copy-status", status),
        );
    }

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    let init = UploadInit {
        op_id: "op-move-1".to_string(),
        dst_path: RelPath::parse("dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 100,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let op = make_op_record("azureblob", &init, None, "{}".to_string(), None);

    let r_pending = backend
        .reconcile_operation(&op)
        .await
        .expect("reconcile pending");
    assert!(
        !matches!(
            r_pending,
            rship::core::backend::ReconcileOutcome::Committed(_)
        ),
        "reconcile_operation MUST NOT return Committed while x-ms-copy-status is `pending`: {r_pending:?}"
    );

    let r_failed = backend
        .reconcile_operation(&op)
        .await
        .expect("reconcile failed");
    assert!(
        !matches!(
            r_failed,
            rship::core::backend::ReconcileOutcome::Committed(_)
        ),
        "reconcile_operation MUST NOT return Committed when x-ms-copy-status is `failed`: {r_failed:?}"
    );

    let r_success = backend
        .reconcile_operation(&op)
        .await
        .expect("reconcile success");
    assert!(
        matches!(
            r_success,
            rship::core::backend::ReconcileOutcome::Committed(_)
        ),
        "reconcile_operation should return Committed when x-ms-copy-status is `success`: {r_success:?}"
    );
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_rename_same_name_and_directory_guard() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("HEAD", "/mycont/same.txt") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "5")
                        .with_header("ETag", "\"0x8DC-S\""),
                ),
                ("HEAD", "/mycont/mydir") => MockAction::Respond(MockResponse::empty(404)),
                ("GET", "/mycont") if req.query_get("prefix").as_deref() == Some("mydir/") => {
                    MockAction::Respond(MockResponse::ok(
                        b"<EnumerationResults><Blobs><Blob><Name>mydir/child.txt</Name><Properties><Content-Length>3</Content-Length></Properties></Blob></Blobs></EnumerationResults>".to_vec(),
                    ))
                }
                ("PUT", "/mycont/same.txt") => MockAction::Respond(MockResponse::empty(202)),
                ("DELETE", _) => MockAction::Respond(MockResponse::empty(202)),
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    let _ = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("same.txt").unwrap()),
            "same.txt",
        )
        .await;
    let reqs_same = srv.take_requests();
    assert!(
        reqs_same.iter().all(|r| r.method != "DELETE"),
        "rename(same.txt, same.txt) must NOT send DELETE"
    );

    let err_dir = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("mydir").unwrap()),
            "mydir2",
        )
        .await
        .expect_err("renaming a directory on Azure Blob must be rejected");
    assert!(
        matches!(
            err_dir.kind,
            ErrorKind::Unsupported | ErrorKind::InvalidPath
        ),
        "directory rename must return Unsupported or InvalidPath, got: {err_dir:?}"
    );
    let reqs_dir = srv.take_requests();
    assert!(
        reqs_dir
            .iter()
            .all(|r| r.method != "PUT" && r.method != "DELETE"),
        "directory rename must guard before sending CopyBlob PUT or DELETE"
    );
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_put_block_sends_content_md5_request_header() {
    let srv = MockHttpServer::start_with_handler(|req| {
        if let Err(reason) = verify_azure_shared_key(req, "myacct", AZURITE_KEY) {
            return MockAction::Respond(MockResponse::text(403, reason));
        }
        if req.method == "PUT" && req.query_get("comp").as_deref() == Some("block") {
            return MockAction::Respond(MockResponse::empty(201));
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let auth = AzureAuth::shared_key("myacct", AZURITE_KEY).expect("shared_key");
    let backend = make_azure_backend(cfg, auth);

    let init = UploadInit {
        op_id: "op-az-md5-blk".to_string(),
        dst_path: RelPath::parse("blk.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let op = make_op_record(
        "azureblob",
        &init,
        Some("op-az-md5-blk".into()),
        "{}".into(),
        None,
    );

    let body_bytes = b"block-md5-verify".to_vec();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                body_bytes.len() as u64,
                16,
                make_byte_stream(body_bytes.clone()),
            ),
        )
        .await
        .expect("PutBlock with SharedKey + Content-MD5");

    let reqs = srv.requests();
    let expected_md5 = base64_encode(&md5_digest(&body_bytes));
    assert_eq!(
        reqs[0].header("content-md5"),
        Some(expected_md5.as_str()),
        "PutBlock request MUST include Content-MD5 header matching block digest"
    );
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_azurite_and_container_sas_url_end_to_end() {
    let (az_acct, az_ep) = extract_sas_account_and_endpoint(
        "http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sig=abc",
    );
    assert_eq!(az_acct.as_deref(), Some("devstoreaccount1"));
    assert_eq!(
        az_ep.as_deref(),
        Some("http://127.0.0.1:10000/devstoreaccount1")
    );

    let srv = MockHttpServer::start_with_handler(|req| {
        if req.method == "HEAD" && req.path == "/devstoreaccount1/mycont/hello.txt" {
            assert_eq!(req.query_get("sv").as_deref(), Some("2023-11-03"));
            assert_eq!(req.query_get("sig").as_deref(), Some("abc"));
            return MockAction::Respond(
                MockResponse::empty(200)
                    .with_header("Content-Length", "9")
                    .with_header("ETag", "\"0x8DC-SAS\""),
            );
        }
        MockAction::Respond(MockResponse::empty(404))
    })
    .await;

    let cfg = AzureblobRemoteConfig::new()
        .with_sas_url(srv.url("/devstoreaccount1/mycont?sv=2023-11-03&sr=c&sig=abc"))
        .with_container("mycont");
    let client = RshipClient::builder()
        .ephemeral()
        .remote("az", cfg)
        .build()
        .expect("AzureblobRemoteConfig with sas_url and container must build");
    let entry = client
        .stat("az:hello.txt")
        .await
        .expect("stat via Azurite container SAS URL")
        .expect("hello.txt exists");
    assert_eq!(entry.size, 9);
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_preconditions_capabilities_and_listing_edge_cases() {
    let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/mycont" {
                let xml = if req.query_get("prefix").as_deref() == Some("sub/") {
                    "<EnumerationResults><Blobs>
                       <Blob><Name>sub/</Name><Properties><Content-Length>0</Content-Length></Properties></Blob>
                       <Blob><Name>sub/file.txt</Name><Properties><Content-Length>4</Content-Length></Properties></Blob>
                     </Blobs></EnumerationResults>"
                } else {
                    "<EnumerationResults><Blobs>
                       <Blob><Name Encoded=\"true\">a%20b%09c.txt</Name><Properties><Content-Length>7</Content-Length></Properties></Blob>
                       <Blob><Name>hnsdir</Name><Properties><Content-Length>0</Content-Length><ResourceType>directory</ResourceType></Properties><Metadata><hdi_isfolder>true</hdi_isfolder></Metadata></Blob>
                     </Blobs></EnumerationResults>"
                };
                return MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()));
            }
            if req.method == "HEAD" && req.path == "/mycont/pre.bin" {
                return MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "4")
                        .with_header("ETag", "\"0x8DC-OTHER\"")
                        .with_header("x-ms-meta-rship_op_id", "other-op"),
                );
            }
            if req.method == "PUT" && req.path == "/mycont/pre.bin" {
                return MockAction::Respond(MockResponse::text(412, "ConditionNotMet"));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    assert!(
        !backend.capabilities().supports_ordered_utf8_list,
        "Azure Blob sorts UTF-16 code units, not UTF-8 bytes"
    );

    let sub_entries = collect_entries(
        backend
            .list_stream(&RelPath::parse("sub").unwrap(), false)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let sub_names: Vec<&str> = sub_entries.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(
        sub_names,
        vec!["sub/file.txt"],
        "Azure list_stream must suppress `sub/` self-marker"
    );

    let root_entries = collect_entries(backend.list_stream(&RelPath::root(), false).await.unwrap())
        .await
        .unwrap();
    assert!(
        root_entries
            .iter()
            .any(|e| e.nfc_path.as_str() == "a b\tc.txt"),
        "Azure list_stream must decode <Name Encoded=\"true\">, got: {root_entries:?}"
    );
    let hns = root_entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "hnsdir")
        .expect("hnsdir");
    assert_eq!(
        hns.kind,
        EntryKind::Directory,
        "ADLS HNS hdi_isfolder / ResourceType=directory must map to EntryKind::Directory"
    );

    let pre_init = UploadInit {
        op_id: "op-az-pre-1".to_string(),
        dst_path: RelPath::parse("pre.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: Some("\"0x8DC1\"".to_string()),
            mtime_ns: 0,
            size: 4,
        },
        src_etag: None,
    };
    let err_put = backend
        .put_single_shot(&pre_init, make_byte_stream(b"abcd".to_vec()))
        .await
        .expect_err("412 on PutBlob");
    assert_eq!(err_put.kind, ErrorKind::PreconditionFailed);

    let op = make_op_record(
        "azureblob",
        &pre_init,
        Some("op-az-pre-1".into()),
        "{}".into(),
        None,
    );
    let err_blk = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 4,
                etag: base64_encode(b"b1"),
                checksum: None,
            }],
        )
        .await
        .expect_err("412 on PutBlockList");
    assert_eq!(err_blk.kind, ErrorKind::PreconditionFailed);

    let err_cp = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &pre_init,
        )
        .await
        .expect_err("412 on CopyBlob");
    assert_eq!(err_cp.kind, ErrorKind::PreconditionFailed);

    let reqs = srv.requests();
    let put_reqs: Vec<&CapturedRequest> = reqs
        .iter()
        .filter(|r| r.method == "PUT" && r.path == "/mycont/pre.bin")
        .collect();
    assert_eq!(put_reqs.len(), 3);
    for r in put_reqs {
        assert_eq!(
            r.header("if-match"),
            Some("\"0x8DC1\""),
            "Azure write with DstPrecondition::Existing must send If-Match"
        );
    }
}

#[cfg(feature = "azureblob")]
#[tokio::test]
async fn tier2_azureblob_r2_mtime_write_and_dual_read() {
    let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("PUT", "/mycont/up.bin") => MockAction::Respond(
                    MockResponse::empty(201)
                        .with_header("ETag", "\"0x8DC-M1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                ),
                ("PUT", "/mycont/cp.bin") => MockAction::Respond(
                    MockResponse::empty(202).with_header("x-ms-copy-status", "success"),
                ),
                ("HEAD", "/mycont/cp.bin") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "4")
                        .with_header("ETag", "\"0x8DC-CP\"")
                        .with_header("x-ms-meta-mtime", "2023-11-14T22:13:20.123456789Z"),
                ),
                ("HEAD", "/mycont/rclone.txt") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "3")
                        .with_header("ETag", "\"0x8DC-R\"")
                        .with_header("x-ms-meta-mtime", "2023-11-14T22:13:20.123456789Z"),
                ),
                ("HEAD", "/mycont/legacy.txt") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("Content-Length", "3")
                        .with_header("ETag", "\"0x8DC-L\"")
                        .with_header("x-ms-meta-rship_mtime_ns", "1700000005000000000"),
                ),
                ("GET", "/mycont") if req.query_get("comp").as_deref() == Some("list") => {
                    let xml = "<EnumerationResults><Blobs>
                        <Blob><Name>rclone.txt</Name><Properties><Content-Length>3</Content-Length></Properties><Metadata><mtime>2023-11-14T22:13:20.123456789Z</mtime></Metadata></Blob>
                        <Blob><Name>legacy.txt</Name><Properties><Content-Length>3</Content-Length></Properties><Metadata><rship_mtime_ns>1700000005000000000</rship_mtime_ns></Metadata></Blob>
                    </Blobs></EnumerationResults>";
                    MockAction::Respond(MockResponse::ok(xml.as_bytes().to_vec()))
                }
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

    let mut cfg = AzureBlobConfig::new("az", "myacct", "mycont");
    cfg.endpoint = Some(srv.base_url());
    let backend = make_azure_backend(cfg, AzureAuth::Anonymous);

    let init = UploadInit {
        op_id: "op-az-r2-1".to_string(),
        dst_path: RelPath::parse("up.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_123_456_789,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: Vec::new(),
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .put_single_shot(&init, make_byte_stream(b"data".to_vec()))
        .await
        .expect("put_single_shot");
    let op = make_op_record(
        "azureblob",
        &init,
        Some("op-az-r2-1".into()),
        "{}".into(),
        None,
    );
    backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 4,
                etag: base64_encode(b"b1"),
                checksum: None,
            }],
        )
        .await
        .expect("PutBlockList");

    let mut cp_init = init.clone();
    cp_init.dst_path = RelPath::parse("cp.bin").unwrap();
    backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &cp_init,
        )
        .await
        .expect("CopyBlob");

    let e_rclone = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("rclone.txt").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_rclone.mtime_ns, 1_700_000_000_123_456_789);

    let e_legacy = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("legacy.txt").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_legacy.mtime_ns, 1_700_000_005_000_000_000);

    let listed = collect_entries(backend.list_stream(&RelPath::root(), false).await.unwrap())
        .await
        .unwrap();
    assert_eq!(listed[0].mtime_ns, 1_700_000_000_123_456_789);
    assert_eq!(listed[1].mtime_ns, 1_700_000_005_000_000_000);

    let reqs = srv.requests();
    for r in reqs.iter().filter(|r| r.method == "PUT") {
        let mtime_raw = r
            .header("x-ms-meta-mtime")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let valid_mtime = mtime_raw.is_some_and(|s| {
            rship::core::time::parse_rfc3339_to_nanos(s).is_some_and(|ns| ns > 0)
                || s.parse::<f64>()
                    .is_ok_and(|secs| secs.is_finite() && secs > 0.0)
        });
        assert!(
            valid_mtime,
            "Azure write `{} {}` must set valid non-zero `x-ms-meta-mtime` (RFC3339 or numeric epoch), got: {:?}",
            r.method,
            r.path,
            r.header("x-ms-meta-mtime")
        );
    }
}
