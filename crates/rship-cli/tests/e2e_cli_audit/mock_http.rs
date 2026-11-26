#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Pure-Rust Hash & Encoding Helpers (zero extra crate dependencies)
// ---------------------------------------------------------------------------

pub(crate) fn md5_digest(data: &[u8]) -> [u8; 16] {
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
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
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
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
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

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn md5_hex(data: &[u8]) -> String {
    hex_lower(&md5_digest(data))
}

pub(crate) fn md5_b64(data: &[u8]) -> String {
    B64.encode(md5_digest(data))
}

pub(crate) fn sha256_digest(data: &[u8]) -> [u8; 32] {
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
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
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
        for (hv, add) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *hv = hv.wrapping_add(add);
        }
    }
    let mut out = [0u8; 32];
    for (i, hv) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&hv.to_be_bytes());
    }
    out
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&sha256_digest(data))
}

pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0x82f63b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub(crate) fn crc32c_b64(data: &[u8]) -> String {
    B64.encode(crc32c(data).to_be_bytes())
}

pub(crate) fn dropbox_content_hash(data: &[u8]) -> String {
    const BLOCK: usize = 4 * 1024 * 1024;
    if data.is_empty() {
        return sha256_hex(&[]);
    }
    let mut combined = Vec::new();
    for chunk in data.chunks(BLOCK) {
        combined.extend_from_slice(&sha256_digest(chunk));
    }
    sha256_hex(&combined)
}

pub(crate) fn quickxor_b64(data: &[u8]) -> String {
    let mut out = [0u8; 20];
    for (i, &byte) in data.iter().enumerate() {
        for b in 0..8 {
            if byte & (1 << b) != 0 {
                let pos = (i * 11 + b) % 160;
                out[pos / 8] ^= 1 << (pos % 8);
            }
        }
    }
    for (dst, l) in out[12..].iter_mut().zip((data.len() as u64).to_le_bytes()) {
        *dst ^= l;
    }
    B64.encode(out)
}

pub(crate) fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

pub(crate) fn form_decode(s: &str) -> String {
    let replaced = s.replace('+', " ");
    pct_decode(&replaced)
}

pub(crate) fn pct_encode_path(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}

pub(crate) fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn parse_query(raw_query: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(q) = raw_query else {
        return out;
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(form_decode(k), form_decode(v));
    }
    out
}

pub(crate) fn encode_dropbox_api_arg(v: &serde_json::Value) -> String {
    let json = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        if (ch as u32) < 0x7f {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for code in ch.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{code:04x}"));
            }
        }
    }
    out
}

fn slice_byte_range(data: &[u8], rng: &str) -> Result<(usize, usize, Vec<u8>), MockResponse> {
    let Some((a, b)) = rng.split_once('-') else {
        return Err(MockResponse::empty(416)
            .with_header("content-range", format!("bytes */{}", data.len())));
    };
    if data.is_empty() {
        return Err(MockResponse::empty(416).with_header("content-range", "bytes */0"));
    }
    let (start, end) = if a.is_empty() {
        let Ok(suffix) = b.parse::<usize>() else {
            return Err(MockResponse::empty(416)
                .with_header("content-range", format!("bytes */{}", data.len())));
        };
        if suffix == 0 {
            return Err(MockResponse::empty(416)
                .with_header("content-range", format!("bytes */{}", data.len())));
        }
        (data.len().saturating_sub(suffix), data.len() - 1)
    } else {
        let Ok(start) = a.parse::<usize>() else {
            return Err(MockResponse::empty(416)
                .with_header("content-range", format!("bytes */{}", data.len())));
        };
        let end = if b.is_empty() {
            data.len() - 1
        } else {
            let Ok(parsed_end) = b.parse::<usize>() else {
                return Err(MockResponse::empty(416)
                    .with_header("content-range", format!("bytes */{}", data.len())));
            };
            parsed_end.min(data.len() - 1)
        };
        (start, end)
    };
    if start >= data.len() || start > end {
        return Err(MockResponse::empty(416)
            .with_header("content-range", format!("bytes */{}", data.len())));
    }
    Ok((start, end, data[start..=end].to_vec()))
}

// ---------------------------------------------------------------------------
// Generic HTTP/1.1 Mock Server (`tokio::net::TcpListener`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct RecordedRequest {
    pub(crate) method: String,
    pub(crate) raw_target: String,
    pub(crate) path: String,
    pub(crate) raw_query: Option<String>,
    pub(crate) query: HashMap<String, String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl RecordedRequest {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl MockResponse {
    pub(crate) fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason: status_reason(status),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub(crate) fn json(status: u16, val: &serde_json::Value) -> Self {
        Self::new(status, serde_json::to_vec(val).unwrap())
            .with_header("content-type", "application/json")
    }

    pub(crate) fn xml(status: u16, xml: impl Into<Vec<u8>>) -> Self {
        Self::new(status, xml).with_header("content-type", "application/xml; charset=utf-8")
    }

    pub(crate) fn empty(status: u16) -> Self {
        Self::new(status, Vec::new())
    }

    pub(crate) fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        302 => "Found",
        308 => "Resume Incomplete",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[derive(Debug, Clone)]
pub(crate) enum FaultAction {
    Status(MockResponse),
    Delay {
        delay: Duration,
        resp: MockResponse,
    },
    MidBodyReset {
        status: u16,
        headers: Vec<(String, String)>,
        prefix: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct FaultRule {
    pub(crate) method: Option<String>,
    pub(crate) path_contains: String,
    pub(crate) action: FaultAction,
}

type HandlerFn = Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>;

pub(crate) struct MockHttpServer {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    faults: Arc<Mutex<VecDeque<FaultRule>>>,
    shutdown_tx: watch::Sender<bool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl MockHttpServer {
    pub(crate) fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let faults = Arc::new(Mutex::new(VecDeque::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (port_tx, port_rx) = std::sync::mpsc::sync_channel(1);

        let handler: HandlerFn = Arc::new(handler);
        let reqs_c = requests.clone();
        let faults_c = faults.clone();

        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build mock tokio runtime");

            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind mock tcp listener");
                let port = listener.local_addr().unwrap().port();
                let _ = port_tx.send(port);

                let mut rx = shutdown_rx;
                loop {
                    tokio::select! {
                        biased;
                        changed = rx.changed() => {
                            if changed.is_err() || *rx.borrow() {
                                break;
                            }
                        }
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break; };
                            let h = handler.clone();
                            let r = reqs_c.clone();
                            let f = faults_c.clone();
                            let mut conn_rx = rx.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = handle_conn(stream, h, r, f) => {}
                                    _ = conn_rx.changed() => {}
                                }
                            });
                        }
                    }
                }
            });
        });

        let port = port_rx.recv().expect("receive mock port");
        Self {
            port,
            requests,
            faults,
            shutdown_tx,
            join: Some(join),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn clear_requests(&self) {
        self.requests.lock().unwrap().clear();
    }

    pub(crate) fn push_fault(
        &self,
        method: Option<&str>,
        path_contains: &str,
        action: FaultAction,
    ) {
        self.faults.lock().unwrap().push_back(FaultRule {
            method: method.map(|m| m.to_ascii_uppercase()),
            path_contains: path_contains.to_string(),
            action,
        });
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

async fn handle_conn(
    stream: TcpStream,
    handler: HandlerFn,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    faults: Arc<Mutex<VecDeque<FaultRule>>>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    loop {
        let mut req_line = String::new();
        match reader.read_line(&mut req_line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        while req_line == "\r\n" || req_line == "\n" {
            req_line.clear();
            match reader.read_line(&mut req_line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
        let parts: Vec<&str> = req_line.trim_end_matches(['\r', '\n']).split(' ').collect();
        if parts.len() < 2 {
            break;
        }
        let method = parts[0].to_ascii_uppercase();
        let raw_target = parts[1].to_string();
        let (path_only, raw_query) = match raw_target.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (raw_target.clone(), None),
        };

        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        let mut expect_100 = false;
        let mut close_conn = false;

        loop {
            let mut hline = String::new();
            match reader.read_line(&mut hline).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let trimmed = hline.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse::<usize>().ok();
                } else if key.eq_ignore_ascii_case("transfer-encoding")
                    && val.to_ascii_lowercase().contains("chunked")
                {
                    is_chunked = true;
                } else if key.eq_ignore_ascii_case("expect")
                    && val.to_ascii_lowercase().contains("100-continue")
                {
                    expect_100 = true;
                } else if key.eq_ignore_ascii_case("connection")
                    && val.eq_ignore_ascii_case("close")
                {
                    close_conn = true;
                }
                headers.push((key, val));
            }
        }

        if expect_100 {
            if write_half
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
            {
                break;
            }
            let _ = write_half.flush().await;
        }

        let mut body = Vec::new();
        if is_chunked {
            loop {
                let mut sz_line = String::new();
                if reader.read_line(&mut sz_line).await.unwrap_or(0) == 0 {
                    return;
                }
                let hex_part = sz_line
                    .trim_end_matches(['\r', '\n'])
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                let Ok(sz) = usize::from_str_radix(hex_part, 16) else {
                    return;
                };
                if sz == 0 {
                    // Consume trailing CRLF / optional trailers.
                    loop {
                        let mut tr = String::new();
                        if reader.read_line(&mut tr).await.unwrap_or(0) == 0 {
                            break;
                        }
                        if tr.trim_end_matches(['\r', '\n']).is_empty() {
                            break;
                        }
                    }
                    break;
                }
                let mut chunk = vec![0u8; sz];
                if reader.read_exact(&mut chunk).await.is_err() {
                    return;
                }
                body.extend_from_slice(&chunk);
                let mut crlf = [0u8; 2];
                if reader.read_exact(&mut crlf).await.is_err() {
                    return;
                }
            }
        } else if let Some(cl) = content_length
            && cl > 0
        {
            body.resize(cl, 0);
            if reader.read_exact(&mut body).await.is_err() {
                return;
            }
        }

        let rec = RecordedRequest {
            method: method.clone(),
            raw_target: raw_target.clone(),
            path: path_only,
            query: parse_query(raw_query.as_deref()),
            raw_query,
            headers,
            body,
        };
        requests.lock().unwrap().push(rec.clone());

        // Check queued faults first.
        let matched_fault = {
            let mut fg = faults.lock().unwrap();
            let pos = fg.iter().position(|r| {
                r.method.as_deref().is_none_or(|m| m == rec.method.as_str())
                    && rec.raw_target.contains(&r.path_contains)
            });
            pos.and_then(|idx| fg.remove(idx))
        };

        let resp = if let Some(rule) = matched_fault {
            match rule.action {
                FaultAction::Status(r) => r,
                FaultAction::Delay { delay, resp } => {
                    tokio::time::sleep(delay).await;
                    resp
                }
                FaultAction::MidBodyReset {
                    status,
                    headers,
                    prefix,
                } => {
                    let mut raw = format!(
                        "HTTP/1.1 {status} {}\r\nContent-Length: 999999\r\nConnection: close\r\n",
                        status_reason(status)
                    );
                    for (k, v) in headers {
                        raw.push_str(&format!("{k}: {v}\r\n"));
                    }
                    raw.push_str("\r\n");
                    let _ = write_half.write_all(raw.as_bytes()).await;
                    let _ = write_half.write_all(&prefix).await;
                    let _ = write_half.flush().await;
                    drop(write_half);
                    return;
                }
            }
        } else {
            handler(&rec)
        };

        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            resp.status,
            if resp.reason.is_empty() {
                status_reason(resp.status)
            } else {
                resp.reason
            }
        );
        let has_cl = resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        for (k, v) in &resp.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if !has_cl && resp.status != 204 {
            head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
        }
        if close_conn {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");

        if write_half.write_all(head.as_bytes()).await.is_err() {
            break;
        }
        if rec.method != "HEAD"
            && !resp.body.is_empty()
            && write_half.write_all(&resp.body).await.is_err()
        {
            break;
        }
        if write_half.flush().await.is_err() {
            break;
        }
        if close_conn {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Mock S3 Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockS3Object {
    pub(crate) data: Vec<u8>,
    pub(crate) etag: String,
    pub(crate) last_modified: String,
    pub(crate) metadata: HashMap<String, String>,
    pub(crate) sse: Option<String>,
    pub(crate) kms_key_id: Option<String>,
    pub(crate) checksum_crc32c: Option<String>,
    pub(crate) checksum_crc64nvme: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockS3IncompleteUpload {
    pub(crate) key: String,
    pub(crate) upload_id: String,
    pub(crate) initiated: String,
    pub(crate) parts: BTreeMap<u32, (Vec<u8>, String)>,
}

#[derive(Debug, Default)]
pub(crate) struct MockS3State {
    pub(crate) bucket: String,
    pub(crate) objects: BTreeMap<String, MockS3Object>,
    pub(crate) uploads: HashMap<String, MockS3IncompleteUpload>,
    pub(crate) next_seq: u64,
    pub(crate) sse_kms_mode: bool,
    pub(crate) aborted_uploads: Vec<(String, String)>,
}

impl MockS3State {
    pub(crate) fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            ..Self::default()
        }
    }

    pub(crate) fn seed_object(&mut self, key: &str, data: Vec<u8>) {
        let etag = if self.sse_kms_mode {
            // Non-MD5 32-hex ETag simulating SSE-KMS encrypted object!
            "deadbeef00112233445566778899aabb".to_string()
        } else {
            md5_hex(&data)
        };
        self.objects.insert(
            key.to_string(),
            MockS3Object {
                data,
                etag: format!("\"{etag}\""),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                metadata: HashMap::new(),
                sse: self.sse_kms_mode.then(|| "aws:kms".to_string()),
                kms_key_id: self.sse_kms_mode.then(|| "alias/test-key".to_string()),
                checksum_crc32c: None,
                checksum_crc64nvme: None,
            },
        );
    }

    pub(crate) fn seed_incomplete_upload(&mut self, key: &str, upload_id: &str, initiated: &str) {
        self.uploads.insert(
            upload_id.to_string(),
            MockS3IncompleteUpload {
                key: key.to_string(),
                upload_id: upload_id.to_string(),
                initiated: initiated.to_string(),
                parts: BTreeMap::new(),
            },
        );
    }
}

pub(crate) fn start_s3_mock(bucket: &str) -> (MockHttpServer, Arc<Mutex<MockS3State>>) {
    let state = Arc::new(Mutex::new(MockS3State::new(bucket)));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_s3(&st, req));
    (srv, state)
}

fn xml_tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

fn handle_s3(st: &Arc<Mutex<MockS3State>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    let path = pct_decode(&req.path);

    // ListBuckets: `GET /`
    if req.method == "GET" && path == "/" && req.raw_query.is_none() {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Owner><ID>owner</ID></Owner><Buckets><Bucket><Name>{}</Name><CreationDate>2026-11-24T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>",
            escape_xml(&g.bucket)
        );
        return MockResponse::xml(200, xml);
    }

    let bucket_prefix = format!("/{}", g.bucket);
    let Some(rest) = path.strip_prefix(&bucket_prefix) else {
        return MockResponse::xml(404, "<Error><Code>NoSuchBucket</Code></Error>");
    };

    // Bucket-level operations: `/{bucket}` or `/{bucket}/`
    if rest.is_empty() || rest == "/" {
        if req.method == "GET" && req.query.get("list-type").map(String::as_str) == Some("2") {
            let pfx = req.query.get("prefix").cloned().unwrap_or_default();
            let delim = req.query.get("delimiter").cloned();
            let encode_url = req.query.get("encoding-type").map(String::as_str) == Some("url");
            let mut common_prefixes = BTreeSet::new();
            let mut contents = Vec::new();
            for (k, obj) in &g.objects {
                if !k.starts_with(&pfx) {
                    continue;
                }
                let tail = &k[pfx.len()..];
                if let Some(ref d) = delim
                    && let Some(pos) = tail.find(d.as_str())
                {
                    common_prefixes.insert(format!("{pfx}{}", &tail[..=pos]));
                    continue;
                }
                contents.push((k.clone(), obj.clone()));
            }
            let enc_val = |v: &str| {
                if encode_url {
                    pct_encode_path(v)
                } else {
                    v.to_string()
                }
            };
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><KeyCount>{}</KeyCount><IsTruncated>false</IsTruncated>{}",
                escape_xml(&g.bucket),
                contents.len(),
                if encode_url {
                    "<EncodingType>url</EncodingType>"
                } else {
                    ""
                }
            );
            for (k, obj) in contents {
                xml.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>",
                    escape_xml(&enc_val(&k)),
                    escape_xml(&obj.last_modified),
                    escape_xml(&obj.etag),
                    obj.data.len()
                ));
            }
            for cp in common_prefixes {
                xml.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    escape_xml(&enc_val(&cp))
                ));
            }
            xml.push_str("</ListBucketResult>");
            return MockResponse::xml(200, xml);
        }

        if req.method == "GET"
            && req
                .raw_query
                .as_deref()
                .is_some_and(|q| q.contains("uploads"))
        {
            let pfx = req.query.get("prefix").cloned().unwrap_or_default();
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult><Bucket>{}</Bucket><IsTruncated>false</IsTruncated>",
                escape_xml(&g.bucket)
            );
            for u in g.uploads.values() {
                if u.key.starts_with(&pfx) {
                    xml.push_str(&format!(
                        "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>{}</Initiated></Upload>",
                        escape_xml(&u.key),
                        escape_xml(&u.upload_id),
                        escape_xml(&u.initiated)
                    ));
                }
            }
            xml.push_str("</ListMultipartUploadsResult>");
            return MockResponse::xml(200, xml);
        }

        if req.method == "POST"
            && req
                .raw_query
                .as_deref()
                .is_some_and(|q| q.contains("delete"))
        {
            let body_str = String::from_utf8_lossy(&req.body);
            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult>");
            for chunk in body_str.split("<Object>").skip(1) {
                if let Some(key) = xml_tag_text(chunk, "Key") {
                    g.objects.remove(key);
                    xml.push_str(&format!(
                        "<Deleted><Key>{}</Key></Deleted>",
                        escape_xml(key)
                    ));
                }
            }
            xml.push_str("</DeleteResult>");
            return MockResponse::xml(200, xml);
        }

        return MockResponse::empty(400);
    }

    let key = rest.strip_prefix('/').unwrap_or(rest).to_string();

    // Multipart operations
    if req.method == "POST" && req.query.contains_key("uploads") {
        g.next_seq += 1;
        let uid = format!("uid-{}", g.next_seq);
        g.uploads.insert(
            uid.clone(),
            MockS3IncompleteUpload {
                key: key.clone(),
                upload_id: uid.clone(),
                initiated: "2026-11-24T00:00:00.000Z".to_string(),
                parts: BTreeMap::new(),
            },
        );
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
            escape_xml(&g.bucket),
            escape_xml(&key),
            escape_xml(&uid)
        );
        return MockResponse::xml(200, xml);
    }

    if let Some(uid) = req.query.get("uploadId").cloned() {
        if req.method == "PUT" {
            let part_num: u32 = req
                .query
                .get("partNumber")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let etag = format!("\"{}\"", md5_hex(&req.body));
            let Some(up) = g.uploads.get_mut(&uid) else {
                return MockResponse::xml(404, "<Error><Code>NoSuchUpload</Code></Error>");
            };
            up.parts.insert(part_num, (req.body.clone(), etag.clone()));
            let mut resp = MockResponse::empty(200).with_header("ETag", etag);
            if let Some(ck) = req.header("x-amz-checksum-crc32c") {
                resp = resp.with_header("x-amz-checksum-crc32c", ck);
            }
            if let Some(ck) = req.header("x-amz-checksum-crc64nvme") {
                resp = resp.with_header("x-amz-checksum-crc64nvme", ck);
            }
            return resp;
        }
        if req.method == "GET" {
            let Some(up) = g.uploads.get(&uid) else {
                return MockResponse::xml(404, "<Error><Code>NoSuchUpload</Code></Error>");
            };
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><IsTruncated>false</IsTruncated>",
                escape_xml(&g.bucket),
                escape_xml(&up.key),
                escape_xml(&uid)
            );
            for (pn, (data, etag)) in &up.parts {
                xml.push_str(&format!(
                    "<Part><PartNumber>{pn}</PartNumber><ETag>{}</ETag><Size>{}</Size></Part>",
                    escape_xml(etag),
                    data.len()
                ));
            }
            xml.push_str("</ListPartsResult>");
            return MockResponse::xml(200, xml);
        }
        if req.method == "POST" {
            if let Some(if_match) = req.header("if-match") {
                match g.objects.get(&key) {
                    Some(existing) if existing.etag == if_match => {}
                    _ => {
                        return MockResponse::xml(
                            412,
                            "<Error><Code>PreconditionFailed</Code></Error>",
                        );
                    }
                }
            }
            if req.header("if-none-match") == Some("*") && g.objects.contains_key(&key) {
                return MockResponse::xml(412, "<Error><Code>PreconditionFailed</Code></Error>");
            }
            let Some(up) = g.uploads.remove(&uid) else {
                return MockResponse::xml(404, "<Error><Code>NoSuchUpload</Code></Error>");
            };
            let mut full = Vec::new();
            let count = up.parts.len();
            for (_, (data, _)) in up.parts {
                full.extend_from_slice(&data);
            }
            let etag = format!("\"{}-{count}\"", md5_hex(&full));
            let sse = g.sse_kms_mode.then(|| "aws:kms".to_string());
            let kms_key_id = g.sse_kms_mode.then(|| "alias/test-key".to_string());
            g.objects.insert(
                key.clone(),
                MockS3Object {
                    data: full,
                    etag: etag.clone(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                    metadata: HashMap::new(),
                    sse,
                    kms_key_id,
                    checksum_crc32c: None,
                    checksum_crc64nvme: None,
                },
            );
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
                escape_xml(&g.bucket),
                escape_xml(&key),
                escape_xml(&etag)
            );
            return MockResponse::xml(200, xml);
        }
        if req.method == "DELETE" {
            g.aborted_uploads.push((key, uid.clone()));
            if g.uploads.remove(&uid).is_some() {
                return MockResponse::empty(204);
            }
            return MockResponse::xml(404, "<Error><Code>NoSuchUpload</Code></Error>");
        }
    }

    match req.method.as_str() {
        "HEAD" | "GET" => {
            let Some(obj) = g.objects.get(&key) else {
                return MockResponse::xml(404, "<Error><Code>NoSuchKey</Code></Error>");
            };
            if let Some(if_match) = req.header("if-match")
                && obj.etag != if_match
            {
                return MockResponse::xml(412, "<Error><Code>PreconditionFailed</Code></Error>");
            }
            let mut resp = if req.method == "HEAD" {
                MockResponse::empty(200).with_header("content-length", obj.data.len().to_string())
            } else if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                match slice_byte_range(&obj.data, rng) {
                    Ok((start, end, slice)) => MockResponse::new(206, slice).with_header(
                        "content-range",
                        format!("bytes {start}-{end}/{}", obj.data.len()),
                    ),
                    Err(r) => return r,
                }
            } else {
                MockResponse::new(200, obj.data.clone())
            };
            resp = resp
                .with_header("etag", &obj.etag)
                .with_header("last-modified", &obj.last_modified);
            if let Some(sse) = &obj.sse {
                resp = resp.with_header("x-amz-server-side-encryption", sse);
            }
            if let Some(kid) = &obj.kms_key_id {
                resp = resp.with_header("x-amz-server-side-encryption-aws-kms-key-id", kid);
            }
            if let Some(c) = &obj.checksum_crc32c {
                resp = resp.with_header("x-amz-checksum-crc32c", c);
            }
            if let Some(c) = &obj.checksum_crc64nvme {
                resp = resp.with_header("x-amz-checksum-crc64nvme", c);
            }
            for (mk, mv) in &obj.metadata {
                resp = resp.with_header(mk, mv);
            }
            resp
        }
        "PUT" => {
            if let Some(if_match) = req.header("if-match") {
                match g.objects.get(&key) {
                    Some(existing) if existing.etag == if_match => {}
                    _ => {
                        return MockResponse::xml(
                            412,
                            "<Error><Code>PreconditionFailed</Code></Error>",
                        );
                    }
                }
            }
            if req.header("if-none-match") == Some("*") && g.objects.contains_key(&key) {
                return MockResponse::xml(412, "<Error><Code>PreconditionFailed</Code></Error>");
            }
            let sse = req
                .header("x-amz-server-side-encryption")
                .map(str::to_string)
                .or_else(|| g.sse_kms_mode.then(|| "aws:kms".to_string()));
            let kms_key_id = req
                .header("x-amz-server-side-encryption-aws-kms-key-id")
                .map(str::to_string);
            let etag = if sse.as_deref() == Some("aws:kms") {
                format!("\"cafe0000{:024x}\"", req.body.len())
            } else {
                format!("\"{}\"", md5_hex(&req.body))
            };
            let mut meta = HashMap::new();
            for (hk, hv) in &req.headers {
                if hk.to_ascii_lowercase().starts_with("x-amz-meta-") {
                    meta.insert(hk.to_ascii_lowercase(), hv.clone());
                }
            }
            let crc32c_hdr = req.header("x-amz-checksum-crc32c").map(str::to_string);
            let crc64_hdr = req.header("x-amz-checksum-crc64nvme").map(str::to_string);
            g.objects.insert(
                key,
                MockS3Object {
                    data: req.body.clone(),
                    etag: etag.clone(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                    metadata: meta,
                    sse: sse.clone(),
                    kms_key_id,
                    checksum_crc32c: crc32c_hdr.clone(),
                    checksum_crc64nvme: crc64_hdr.clone(),
                },
            );
            let mut resp = MockResponse::empty(200).with_header("ETag", etag);
            if let Some(s) = sse {
                resp = resp.with_header("x-amz-server-side-encryption", s);
            }
            if let Some(c) = crc32c_hdr {
                resp = resp.with_header("x-amz-checksum-crc32c", c);
            }
            if let Some(c) = crc64_hdr {
                resp = resp.with_header("x-amz-checksum-crc64nvme", c);
            }
            resp
        }
        "DELETE" => {
            g.objects.remove(&key);
            MockResponse::empty(204)
        }
        _ => MockResponse::empty(405),
    }
}

// ---------------------------------------------------------------------------
// 2. Mock GCS Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockGcsObject {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) generation: u64,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) content_encoding: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct MockGcsSession {
    pub(crate) name: String,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) buf: Vec<u8>,
}

pub(crate) struct MockGcsState {
    pub(crate) bucket: String,
    pub(crate) base_url: String,
    pub(crate) objects: BTreeMap<String, MockGcsObject>,
    pub(crate) sessions: HashMap<String, MockGcsSession>,
    pub(crate) next_gen: u64,
}

impl MockGcsState {
    pub(crate) fn new(bucket: &str, base_url: String) -> Self {
        Self {
            bucket: bucket.to_string(),
            base_url,
            objects: BTreeMap::new(),
            sessions: HashMap::new(),
            next_gen: 1,
        }
    }

    pub(crate) fn seed_object(
        &mut self,
        name: &str,
        data: Vec<u8>,
        metadata: BTreeMap<String, String>,
    ) {
        self.next_gen += 1;
        let gen_id = self.next_gen;
        self.objects.insert(
            name.to_string(),
            MockGcsObject {
                name: name.to_string(),
                data,
                generation: gen_id,
                metadata,
                content_encoding: None,
            },
        );
    }

    fn obj_json(&self, obj: &MockGcsObject) -> serde_json::Value {
        serde_json::json!({
            "name": obj.name,
            "size": obj.data.len().to_string(),
            "generation": obj.generation.to_string(),
            "etag": format!("gen-{}", obj.generation),
            "updated": "2026-11-24T12:00:00Z",
            "md5Hash": md5_b64(&obj.data),
            "crc32c": crc32c_b64(&obj.data),
            "metadata": obj.metadata,
        })
    }
}

pub(crate) fn start_gcs_mock(bucket: &str) -> (MockHttpServer, Arc<Mutex<MockGcsState>>) {
    let state = Arc::new(Mutex::new(MockGcsState::new(bucket, String::new())));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_gcs(&st, req));
    state.lock().unwrap().base_url = srv.base_url();
    (srv, state)
}

fn parse_multipart_related(body: &[u8], content_type: &str) -> (serde_json::Value, Vec<u8>) {
    let boundary = content_type
        .split(';')
        .find_map(|p| p.trim().strip_prefix("boundary="))
        .unwrap_or("rship_gcs_multipart_boundary")
        .trim_matches('"');
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let first = body
        .windows(delim_bytes.len())
        .position(|w| w == delim_bytes)
        .unwrap();
    let after_first = &body[first + delim_bytes.len()..];
    let second = after_first
        .windows(delim_bytes.len())
        .position(|w| w == delim_bytes)
        .unwrap();
    let part1 = &after_first[..second];
    let p1_hdr_end = part1.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let meta: serde_json::Value =
        serde_json::from_slice(&part1[p1_hdr_end + 4..part1.len().saturating_sub(2)]).unwrap();
    let after_second = &after_first[second + delim_bytes.len()..];
    let end_marker = format!("--{boundary}--");
    let third = after_second
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_bytes())
        .unwrap();
    let part2 = &after_second[..third];
    let p2_hdr_end = part2.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let data = part2[p2_hdr_end + 4..part2.len().saturating_sub(2)].to_vec();
    (meta, data)
}

fn handle_gcs(st: &Arc<Mutex<MockGcsState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    if req.path == "/oauth2/token" && req.method == "POST" {
        return MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "gcs-refreshed-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        );
    }

    if let Some(sid) = req.path.strip_prefix("/upload/session/") {
        if req.method == "DELETE" {
            g.sessions.remove(sid);
            return MockResponse::empty(499);
        }
        if req.method == "PUT" {
            let cr = req.header("content-range").unwrap_or("");
            if cr == "bytes */0" {
                // Simulate GCS finalizing a 0-byte object if client sent `bytes */0`!
                let Some(sess) = g.sessions.remove(sid) else {
                    return MockResponse::empty(404);
                };
                g.next_gen += 1;
                let obj = MockGcsObject {
                    name: sess.name.clone(),
                    data: Vec::new(),
                    generation: g.next_gen,
                    metadata: sess.metadata,
                    content_encoding: None,
                };
                g.objects.insert(sess.name, obj.clone());
                return MockResponse::json(200, &g.obj_json(&obj));
            }
            if cr.starts_with("bytes */") {
                let Some(sess) = g.sessions.get(sid) else {
                    return MockResponse::empty(404);
                };
                if sess.buf.is_empty() {
                    return MockResponse::empty(308);
                }
                return MockResponse::empty(308)
                    .with_header("range", format!("bytes=0-{}", sess.buf.len() - 1));
            }
            let spec = cr.strip_prefix("bytes ").unwrap_or("0-0/0");
            let (rng_part, total_part) = spec.split_once('/').unwrap_or(("0-0", "0"));
            let (s_part, _) = rng_part.split_once('-').unwrap_or(("0", "0"));
            let start: usize = s_part.parse().unwrap_or(0);
            let total: u64 = total_part.parse().unwrap_or(0);
            {
                let Some(sess) = g.sessions.get_mut(sid) else {
                    return MockResponse::empty(404);
                };
                if start == sess.buf.len() {
                    sess.buf.extend_from_slice(&req.body);
                }
            }
            let done = g
                .sessions
                .get(sid)
                .is_some_and(|s| s.buf.len() as u64 >= total);
            if done {
                let sess = g.sessions.remove(sid).unwrap();
                g.next_gen += 1;
                let obj = MockGcsObject {
                    name: sess.name.clone(),
                    data: sess.buf,
                    generation: g.next_gen,
                    metadata: sess.metadata,
                    content_encoding: None,
                };
                g.objects.insert(sess.name, obj.clone());
                return MockResponse::json(200, &g.obj_json(&obj));
            }
            let len = g.sessions.get(sid).map(|s| s.buf.len()).unwrap_or(0);
            return MockResponse::empty(308).with_header("range", format!("bytes=0-{}", len - 1));
        }
    }

    let up_path = format!("/upload/storage/v1/b/{}/o", g.bucket);
    if req.path == up_path && req.method == "POST" {
        let ut = req
            .query
            .get("uploadType")
            .map(String::as_str)
            .unwrap_or("");
        match ut {
            "multipart" => {
                let ct = req.header("content-type").unwrap_or("");
                let (meta_json, data) = parse_multipart_related(&req.body, ct);
                let name = meta_json["name"].as_str().unwrap_or("").to_string();
                let metadata: BTreeMap<String, String> = meta_json
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default();
                g.next_gen += 1;
                let obj = MockGcsObject {
                    name: name.clone(),
                    data,
                    generation: g.next_gen,
                    metadata,
                    content_encoding: None,
                };
                g.objects.insert(name, obj.clone());
                return MockResponse::json(200, &g.obj_json(&obj));
            }
            "resumable" => {
                let meta_json: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let name = meta_json["name"].as_str().unwrap_or("").to_string();
                let metadata: BTreeMap<String, String> = meta_json
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default();
                g.next_gen += 1;
                let sid = format!("gcs-sess-{}", g.next_gen);
                let loc = format!("{}/upload/session/{sid}", g.base_url);
                g.sessions.insert(
                    sid,
                    MockGcsSession {
                        name,
                        metadata,
                        buf: Vec::new(),
                    },
                );
                return MockResponse::empty(200).with_header("location", loc);
            }
            "media" => {
                let name = req.query.get("name").cloned().unwrap_or_default();
                g.next_gen += 1;
                let obj = MockGcsObject {
                    name: name.clone(),
                    data: req.body.clone(),
                    generation: g.next_gen,
                    metadata: BTreeMap::new(),
                    content_encoding: None,
                };
                g.objects.insert(name, obj.clone());
                return MockResponse::json(200, &g.obj_json(&obj));
            }
            _ => return MockResponse::empty(400),
        }
    }

    let list_path = format!("/storage/v1/b/{}/o", g.bucket);
    if req.path == list_path && req.method == "GET" {
        let pfx = req.query.get("prefix").cloned().unwrap_or_default();
        let delim = req.query.get("delimiter").cloned();
        let mut items = Vec::new();
        let mut prefixes = BTreeSet::new();
        for obj in g.objects.values() {
            if !obj.name.starts_with(&pfx) {
                continue;
            }
            let rest = &obj.name[pfx.len()..];
            if let Some(ref d) = delim
                && let Some(pos) = rest.find(d.as_str())
            {
                prefixes.insert(format!("{pfx}{}", &rest[..=pos]));
                continue;
            }
            items.push(g.obj_json(obj));
        }
        return MockResponse::json(
            200,
            &serde_json::json!({
                "items": items,
                "prefixes": prefixes.into_iter().collect::<Vec<_>>(),
            }),
        );
    }

    let obj_prefix = format!("/storage/v1/b/{}/o/", g.bucket);
    if let Some(rest) = req.path.strip_prefix(&obj_prefix) {
        let rewrite_marker = format!("/rewriteTo/b/{}/o/", g.bucket);
        if let Some((src_enc, dst_enc)) = rest.split_once(&rewrite_marker)
            && req.method == "POST"
        {
            let src_name = pct_decode(src_enc);
            let dst_name = pct_decode(dst_enc);
            let Some(src_obj) = g.objects.get(&src_name).cloned() else {
                return MockResponse::empty(404);
            };
            let meta_json: serde_json::Value =
                serde_json::from_slice(&req.body).unwrap_or_default();
            let metadata: BTreeMap<String, String> = meta_json
                .get("metadata")
                .and_then(|m| serde_json::from_value(m.clone()).ok())
                .unwrap_or_else(|| src_obj.metadata.clone());
            g.next_gen += 1;
            let copied = MockGcsObject {
                name: dst_name.clone(),
                data: src_obj.data,
                generation: g.next_gen,
                metadata,
                content_encoding: src_obj.content_encoding,
            };
            g.objects.insert(dst_name, copied.clone());
            return MockResponse::json(
                200,
                &serde_json::json!({ "done": true, "resource": g.obj_json(&copied) }),
            );
        }

        let name = pct_decode(rest);
        match req.method.as_str() {
            "DELETE" => {
                if g.objects.remove(&name).is_some() {
                    return MockResponse::empty(204);
                }
                return MockResponse::empty(404);
            }
            "PATCH" => {
                let patch_json: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or_default();
                let Some(obj) = g.objects.get_mut(&name) else {
                    return MockResponse::empty(404);
                };
                if let Some(m) = patch_json.get("metadata").and_then(|v| v.as_object()) {
                    for (k, v) in m {
                        if let Some(vs) = v.as_str() {
                            obj.metadata.insert(k.clone(), vs.to_string());
                        }
                    }
                }
                let cloned = obj.clone();
                return MockResponse::json(200, &g.obj_json(&cloned));
            }
            "GET" => {
                let Some(obj) = g.objects.get(&name).cloned() else {
                    return MockResponse::empty(404);
                };
                if req.query.get("alt").map(String::as_str) == Some("media") {
                    let goog_hash = format!(
                        "crc32c={}, md5={}",
                        crc32c_b64(&obj.data),
                        md5_b64(&obj.data)
                    );
                    if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                        match slice_byte_range(&obj.data, rng) {
                            Ok((start, end, slice)) => {
                                return MockResponse::new(206, slice)
                                    .with_header(
                                        "content-range",
                                        format!("bytes {start}-{end}/{}", obj.data.len()),
                                    )
                                    .with_header("x-goog-hash", goog_hash);
                            }
                            Err(r) => return r,
                        }
                    }
                    return MockResponse::new(200, obj.data).with_header("x-goog-hash", goog_hash);
                }
                return MockResponse::json(200, &g.obj_json(&obj));
            }
            _ => {}
        }
    }

    MockResponse::empty(404)
}

// ---------------------------------------------------------------------------
// 3. Mock Azure Blob Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockAzureBlob {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) etag: String,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) copy_status: Option<String>,
}

pub(crate) struct MockAzureState {
    pub(crate) container: String,
    pub(crate) blobs: BTreeMap<String, MockAzureBlob>,
    pub(crate) uncommitted: HashMap<String, BTreeMap<String, Vec<u8>>>,
    pub(crate) next_seq: u64,
    pub(crate) copy_status_override: Option<String>,
}

impl MockAzureState {
    pub(crate) fn new(container: &str) -> Self {
        Self {
            container: container.to_string(),
            blobs: BTreeMap::new(),
            uncommitted: HashMap::new(),
            next_seq: 1,
            copy_status_override: None,
        }
    }

    pub(crate) fn seed_blob(
        &mut self,
        name: &str,
        data: Vec<u8>,
        metadata: BTreeMap<String, String>,
    ) {
        self.next_seq += 1;
        self.blobs.insert(
            name.to_string(),
            MockAzureBlob {
                name: name.to_string(),
                data,
                etag: format!("\"0x8DC{:04X}\"", self.next_seq),
                metadata,
                copy_status: None,
            },
        );
    }
}

pub(crate) fn start_azure_mock(container: &str) -> (MockHttpServer, Arc<Mutex<MockAzureState>>) {
    let state = Arc::new(Mutex::new(MockAzureState::new(container)));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_azure(&st, req));
    (srv, state)
}

fn handle_azure(st: &Arc<Mutex<MockAzureState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    let container_path = format!("/{}", g.container);
    if req.path == container_path
        && req.method == "GET"
        && req.query.get("restype").map(String::as_str) == Some("container")
        && req.query.get("comp").map(String::as_str) == Some("list")
    {
        let pfx = req.query.get("prefix").cloned().unwrap_or_default();
        let delim = req.query.get("delimiter").cloned();
        let mut blobs = Vec::new();
        let mut prefixes = BTreeSet::new();
        for b in g.blobs.values() {
            if !b.name.starts_with(&pfx) {
                continue;
            }
            let rest = &b.name[pfx.len()..];
            if let Some(ref d) = delim
                && let Some(pos) = rest.find(d.as_str())
            {
                prefixes.insert(format!("{pfx}{}", &rest[..=pos]));
                continue;
            }
            blobs.push(b.clone());
        }
        let mut xml =
            String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults><Blobs>");
        for b in blobs {
            xml.push_str("<Blob><Name>");
            xml.push_str(&escape_xml(&b.name));
            xml.push_str("</Name><Properties>");
            xml.push_str("<Last-Modified>Wed, 25 Nov 2026 02:00:00 GMT</Last-Modified>");
            xml.push_str(&format!("<Etag>{}</Etag>", escape_xml(&b.etag)));
            xml.push_str(&format!(
                "<Content-Length>{}</Content-Length>",
                b.data.len()
            ));
            xml.push_str(&format!("<Content-MD5>{}</Content-MD5>", md5_b64(&b.data)));
            xml.push_str("</Properties><Metadata>");
            for (mk, mv) in &b.metadata {
                xml.push_str(&format!("<{mk}>{}</{mk}>", escape_xml(mv)));
            }
            xml.push_str("</Metadata></Blob>");
        }
        for p in prefixes {
            xml.push_str(&format!(
                "<BlobPrefix><Name>{}</Name></BlobPrefix>",
                escape_xml(&p)
            ));
        }
        xml.push_str("</Blobs></EnumerationResults>");
        return MockResponse::xml(200, xml);
    }

    let blob_prefix = format!("/{}/", g.container);
    let Some(raw_blob) = req.path.strip_prefix(&blob_prefix) else {
        return MockResponse::empty(404);
    };
    let blob_name = raw_blob
        .split('/')
        .map(pct_decode)
        .collect::<Vec<_>>()
        .join("/");
    let comp = req.query.get("comp").map(String::as_str);

    match (req.method.as_str(), comp) {
        ("PUT", Some("block")) => {
            let block_id = req.query.get("blockid").cloned().unwrap_or_default();
            g.uncommitted
                .entry(blob_name)
                .or_default()
                .insert(block_id, req.body.clone());
            MockResponse::empty(201).with_header("content-md5", md5_b64(&req.body))
        }
        ("PUT", Some("blocklist")) => {
            let body_str = String::from_utf8_lossy(&req.body);
            let mut full = Vec::new();
            let parts_map = g.uncommitted.remove(&blob_name).unwrap_or_default();
            for seg in body_str.split("<Latest>").skip(1) {
                if let Some(bid) = seg.split("</Latest>").next()
                    && let Some(bytes) = parts_map.get(bid)
                {
                    full.extend_from_slice(bytes);
                }
            }
            let mut meta = BTreeMap::new();
            for (hk, hv) in &req.headers {
                if let Some(mk) = hk.to_ascii_lowercase().strip_prefix("x-ms-meta-") {
                    meta.insert(mk.to_string(), hv.clone());
                }
            }
            g.next_seq += 1;
            let etag = format!("\"0x8DC{:04X}\"", g.next_seq);
            let md5 = md5_b64(&full);
            g.blobs.insert(
                blob_name.clone(),
                MockAzureBlob {
                    name: blob_name,
                    data: full,
                    etag: etag.clone(),
                    metadata: meta,
                    copy_status: None,
                },
            );
            MockResponse::empty(201)
                .with_header("etag", etag)
                .with_header("content-md5", md5)
        }
        ("PUT", None) => {
            if let Some(copy_src) = req.header("x-ms-copy-source") {
                let src_path = copy_src
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .split(&format!("/{}/", g.container))
                    .nth(1)
                    .map(pct_decode)
                    .unwrap_or_default();
                let Some(src) = g.blobs.get(&src_path).cloned() else {
                    return MockResponse::empty(404);
                };
                g.next_seq += 1;
                let etag = format!("\"0x8DC{:04X}\"", g.next_seq);
                let mut meta = src.metadata.clone();
                for (hk, hv) in &req.headers {
                    if let Some(mk) = hk.to_ascii_lowercase().strip_prefix("x-ms-meta-") {
                        meta.insert(mk.to_string(), hv.clone());
                    }
                }
                let copy_status = g
                    .copy_status_override
                    .clone()
                    .unwrap_or_else(|| "success".to_string());
                g.blobs.insert(
                    blob_name.clone(),
                    MockAzureBlob {
                        name: blob_name,
                        data: src.data,
                        etag: etag.clone(),
                        metadata: meta,
                        copy_status: Some(copy_status.clone()),
                    },
                );
                return MockResponse::empty(202)
                    .with_header("etag", etag)
                    .with_header("x-ms-copy-status", copy_status);
            }
            let mut meta = BTreeMap::new();
            for (hk, hv) in &req.headers {
                if let Some(mk) = hk.to_ascii_lowercase().strip_prefix("x-ms-meta-") {
                    meta.insert(mk.to_string(), hv.clone());
                }
            }
            g.next_seq += 1;
            let etag = format!("\"0x8DC{:04X}\"", g.next_seq);
            let md5 = md5_b64(&req.body);
            g.blobs.insert(
                blob_name.clone(),
                MockAzureBlob {
                    name: blob_name,
                    data: req.body.clone(),
                    etag: etag.clone(),
                    metadata: meta,
                    copy_status: None,
                },
            );
            MockResponse::empty(201)
                .with_header("etag", etag)
                .with_header("content-md5", md5)
        }
        ("HEAD" | "GET", None) => {
            let Some(blob) = g.blobs.get(&blob_name) else {
                return MockResponse::empty(404);
            };
            let mut resp = if req.method == "HEAD" {
                MockResponse::empty(200).with_header("content-length", blob.data.len().to_string())
            } else if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                match slice_byte_range(&blob.data, rng) {
                    Ok((start, end, slice)) => MockResponse::new(206, slice).with_header(
                        "content-range",
                        format!("bytes {start}-{end}/{}", blob.data.len()),
                    ),
                    Err(r) => return r,
                }
            } else {
                MockResponse::new(200, blob.data.clone())
            };
            resp = resp
                .with_header("etag", &blob.etag)
                .with_header("last-modified", "Wed, 25 Nov 2026 02:00:00 GMT")
                .with_header("content-md5", md5_b64(&blob.data));
            if let Some(cs) = &blob.copy_status {
                resp = resp.with_header("x-ms-copy-status", cs);
            }
            for (mk, mv) in &blob.metadata {
                resp = resp.with_header(format!("x-ms-meta-{mk}"), mv);
            }
            resp
        }
        ("DELETE", None) => {
            if g.blobs.remove(&blob_name).is_some() {
                MockResponse::empty(202)
            } else {
                MockResponse::empty(404)
            }
        }
        _ => MockResponse::empty(404),
    }
}

// ---------------------------------------------------------------------------
// 4. Mock Google Drive Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockDriveFile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) mime_type: String,
    pub(crate) parents: Vec<String>,
    pub(crate) modified_time: String,
    pub(crate) data: Vec<u8>,
    pub(crate) trashed: bool,
    pub(crate) shortcut_target: Option<(String, String)>,
}

impl MockDriveFile {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "id": self.id,
            "name": self.name,
            "mimeType": self.mime_type,
            "parents": self.parents,
            "modifiedTime": self.modified_time,
            "trashed": self.trashed,
        });
        if self.mime_type != "application/vnd.google-apps.folder" && self.shortcut_target.is_none()
        {
            obj["size"] = serde_json::Value::String(self.data.len().to_string());
            obj["md5Checksum"] = serde_json::Value::String(md5_hex(&self.data));
        }
        if let Some((ref tid, ref tmime)) = self.shortcut_target {
            obj["shortcutDetails"] = serde_json::json!({
                "targetId": tid,
                "targetMimeType": tmime,
            });
        }
        obj
    }
}

pub(crate) struct MockDriveUploadSess {
    pub(crate) file_id: Option<String>,
    pub(crate) name: String,
    pub(crate) parents: Vec<String>,
    pub(crate) buf: Vec<u8>,
}

pub(crate) struct MockGdriveState {
    pub(crate) base_url: String,
    pub(crate) expected_token: Option<String>,
    pub(crate) files: BTreeMap<String, MockDriveFile>,
    pub(crate) sessions: HashMap<String, MockDriveUploadSess>,
    pub(crate) next_seq: u64,
    pub(crate) token_refreshes: usize,
}

impl MockGdriveState {
    pub(crate) fn new(base_url: String) -> Self {
        Self {
            base_url,
            expected_token: None,
            files: BTreeMap::new(),
            sessions: HashMap::new(),
            next_seq: 1,
            token_refreshes: 0,
        }
    }

    pub(crate) fn seed_file(
        &mut self,
        id: &str,
        name: &str,
        parent: &str,
        data: Vec<u8>,
        modified_time: &str,
    ) {
        self.files.insert(
            id.to_string(),
            MockDriveFile {
                id: id.to_string(),
                name: name.to_string(),
                mime_type: "application/octet-stream".to_string(),
                parents: vec![parent.to_string()],
                modified_time: modified_time.to_string(),
                data,
                trashed: false,
                shortcut_target: None,
            },
        );
    }

    pub(crate) fn seed_shortcut(
        &mut self,
        id: &str,
        name: &str,
        parent: &str,
        target_id: &str,
        target_mime: &str,
    ) {
        self.files.insert(
            id.to_string(),
            MockDriveFile {
                id: id.to_string(),
                name: name.to_string(),
                mime_type: "application/vnd.google-apps.shortcut".to_string(),
                parents: vec![parent.to_string()],
                modified_time: "2026-11-24T12:00:00Z".to_string(),
                data: Vec::new(),
                trashed: false,
                shortcut_target: Some((target_id.to_string(), target_mime.to_string())),
            },
        );
    }
}

pub(crate) fn start_gdrive_mock() -> (MockHttpServer, Arc<Mutex<MockGdriveState>>) {
    let state = Arc::new(Mutex::new(MockGdriveState::new(String::new())));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_gdrive(&st, req));
    state.lock().unwrap().base_url = srv.base_url();
    (srv, state)
}

fn parse_drive_q_clause(q: &str, prefix: &str) -> Option<String> {
    let idx = q.find(prefix)?;
    let rest = &q[idx + prefix.len()..];
    let mut chars = rest.chars();
    if chars.next()? != '\'' {
        return None;
    }
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            }
            '\'' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

fn handle_gdrive(st: &Arc<Mutex<MockGdriveState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    if req.path == "/oauth2/token" && req.method == "POST" {
        g.token_refreshes += 1;
        let fresh = format!("gd-fresh-tok-{}", g.token_refreshes);
        g.expected_token = Some(fresh.clone());
        return MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": fresh,
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        );
    }

    if let Some(ref exp) = g.expected_token {
        let want = format!("Bearer {exp}");
        if req.header("authorization") != Some(want.as_str()) {
            return MockResponse::json(
                401,
                &serde_json::json!({
                    "error": { "code": 401, "message": "Invalid Credentials" }
                }),
            );
        }
    }

    if req.path == "/drive/v3/about" && req.method == "GET" {
        return MockResponse::json(
            200,
            &serde_json::json!({
                "storageQuota": {
                    "limit": "10737418240",
                    "usage": "1048576",
                    "usageInDriveTrash": "1024"
                }
            }),
        );
    }

    if req.path == "/drive/v3/files/generateIds" && req.method == "GET" {
        let count = req
            .query
            .get("count")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 100);
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            g.next_seq += 1;
            ids.push(format!("pregen-{}", g.next_seq));
        }
        return MockResponse::json(200, &serde_json::json!({ "ids": ids, "space": "drive" }));
    }

    if req.path == "/drive/v3/files" && req.method == "GET" {
        let q = req.query.get("q").cloned().unwrap_or_default();
        let parent_filter = q
            .find(" in parents")
            .and_then(|idx| q[..idx].rfind('\'').map(|s| &q[s..idx]))
            .and_then(|lit| parse_drive_q_clause(lit, ""));
        let name_filter = parse_drive_q_clause(&q, "name = ");
        let mime_filter = parse_drive_q_clause(&q, "mimeType = ");
        let excl_trashed = q.contains("trashed = false");
        let files: Vec<_> = g
            .files
            .values()
            .filter(|f| {
                if excl_trashed && f.trashed {
                    return false;
                }
                if let Some(ref p) = parent_filter
                    && !f.parents.contains(p)
                {
                    return false;
                }
                if let Some(ref n) = name_filter
                    && f.name != *n
                {
                    return false;
                }
                if let Some(ref m) = mime_filter
                    && f.mime_type != *m
                {
                    return false;
                }
                true
            })
            .map(MockDriveFile::to_json)
            .collect();
        return MockResponse::json(
            200,
            &serde_json::json!({ "incompleteSearch": false, "files": files }),
        );
    }

    if req.path == "/drive/v3/files" && req.method == "POST" {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let id = v["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                g.next_seq += 1;
                format!("node-{}", g.next_seq)
            });
        let parents = v["parents"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| vec!["root".to_string()]);
        let f = MockDriveFile {
            id: id.clone(),
            name: v["name"].as_str().unwrap_or("").to_string(),
            mime_type: v["mimeType"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string(),
            parents,
            modified_time: v["modifiedTime"]
                .as_str()
                .unwrap_or("2026-11-24T12:00:00Z")
                .to_string(),
            data: Vec::new(),
            trashed: false,
            shortcut_target: None,
        };
        let j = f.to_json();
        g.files.insert(id, f);
        return MockResponse::json(200, &j);
    }

    if let Some(sid) = req.path.strip_prefix("/upload/session/") {
        if req.method == "DELETE" {
            g.sessions.remove(sid);
            return MockResponse::empty(499);
        }
        if req.method == "PUT" {
            let cr = req.header("content-range").unwrap_or("");
            if cr.starts_with("bytes */") {
                let Some(sess) = g.sessions.get(sid) else {
                    return MockResponse::empty(404);
                };
                if sess.buf.is_empty() {
                    return MockResponse::empty(308);
                }
                return MockResponse::empty(308)
                    .with_header("range", format!("bytes=0-{}", sess.buf.len() - 1));
            }
            let spec = cr.strip_prefix("bytes ").unwrap_or("0-0/0");
            let (rng_part, total_part) = spec.split_once('/').unwrap_or(("0-0", "0"));
            let (s_part, _) = rng_part.split_once('-').unwrap_or(("0", "0"));
            let start: usize = s_part.parse().unwrap_or(0);
            let total: u64 = total_part.parse().unwrap_or(0);
            {
                let Some(sess) = g.sessions.get_mut(sid) else {
                    return MockResponse::empty(404);
                };
                if start == sess.buf.len() {
                    sess.buf.extend_from_slice(&req.body);
                }
            }
            let done = g
                .sessions
                .get(sid)
                .is_some_and(|s| s.buf.len() as u64 >= total);
            if done {
                let sess = g.sessions.remove(sid).unwrap();
                let id = sess.file_id.unwrap_or_else(|| {
                    g.next_seq += 1;
                    format!("node-{}", g.next_seq)
                });
                let f = MockDriveFile {
                    id: id.clone(),
                    name: sess.name,
                    mime_type: "application/octet-stream".to_string(),
                    parents: sess.parents,
                    modified_time: "2026-11-24T12:00:00Z".to_string(),
                    data: sess.buf,
                    trashed: false,
                    shortcut_target: None,
                };
                let j = f.to_json();
                g.files.insert(id, f);
                return MockResponse::json(200, &j);
            }
            let len = g.sessions.get(sid).map(|s| s.buf.len()).unwrap_or(0);
            return MockResponse::empty(308).with_header("range", format!("bytes=0-{}", len - 1));
        }
    }

    if req.path == "/upload/drive/v3/files" || req.path.starts_with("/upload/drive/v3/files/") {
        let existing_id = req
            .path
            .strip_prefix("/upload/drive/v3/files/")
            .map(str::to_string);
        let ut = req
            .query
            .get("uploadType")
            .map(String::as_str)
            .unwrap_or("");
        if ut == "multipart" {
            let ct = req.header("content-type").unwrap_or("");
            let (meta, data) = parse_multipart_related(&req.body, ct);
            let id = existing_id
                .or_else(|| {
                    meta["id"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| {
                    g.next_seq += 1;
                    format!("node-{}", g.next_seq)
                });
            let parents = meta["parents"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_else(|| vec!["root".to_string()]);
            let name = meta["name"]
                .as_str()
                .map(str::to_string)
                .or_else(|| g.files.get(&id).map(|f| f.name.clone()))
                .unwrap_or_default();
            let f = MockDriveFile {
                id: id.clone(),
                name,
                mime_type: "application/octet-stream".to_string(),
                parents,
                modified_time: meta["modifiedTime"]
                    .as_str()
                    .unwrap_or("2026-11-24T12:00:00Z")
                    .to_string(),
                data,
                trashed: false,
                shortcut_target: None,
            };
            let j = f.to_json();
            g.files.insert(id, f);
            return MockResponse::json(200, &j);
        }
        if ut == "resumable" {
            let meta: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let id = existing_id.or_else(|| {
                meta["id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            });
            let parents = meta["parents"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_else(|| vec!["root".to_string()]);
            g.next_seq += 1;
            let sid = format!("gd-sess-{}", g.next_seq);
            let loc = format!("{}/upload/session/{sid}", g.base_url);
            g.sessions.insert(
                sid,
                MockDriveUploadSess {
                    file_id: id,
                    name: meta["name"].as_str().unwrap_or("").to_string(),
                    parents,
                    buf: Vec::new(),
                },
            );
            return MockResponse::empty(200).with_header("location", loc);
        }
    }

    if let Some(rest) = req.path.strip_prefix("/drive/v3/files/") {
        if let Some(id) = rest.strip_suffix("/copy")
            && req.method == "POST"
        {
            let Some(src) = g.files.get(id).cloned() else {
                return MockResponse::empty(404);
            };
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let new_id = body["id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    g.next_seq += 1;
                    format!("node-{}", g.next_seq)
                });
            let copied = MockDriveFile {
                id: new_id.clone(),
                name: body["name"].as_str().unwrap_or(&src.name).to_string(),
                mime_type: src.mime_type,
                parents: body["parents"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or(src.parents),
                modified_time: src.modified_time,
                data: src.data,
                trashed: false,
                shortcut_target: None,
            };
            let j = copied.to_json();
            g.files.insert(new_id, copied);
            return MockResponse::json(200, &j);
        }

        let id = pct_decode(rest);
        match req.method.as_str() {
            "GET" => {
                let Some(f) = g.files.get(&id) else {
                    return MockResponse::empty(404);
                };
                if req.query.get("alt").map(String::as_str) == Some("media") {
                    if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                        match slice_byte_range(&f.data, rng) {
                            Ok((start, end, slice)) => {
                                return MockResponse::new(206, slice).with_header(
                                    "content-range",
                                    format!("bytes {start}-{end}/{}", f.data.len()),
                                );
                            }
                            Err(r) => return r,
                        }
                    }
                    return MockResponse::new(200, f.data.clone());
                }
                return MockResponse::json(200, &f.to_json());
            }
            "PATCH" => {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let Some(f) = g.files.get_mut(&id) else {
                    return MockResponse::empty(404);
                };
                if let Some(t) = body["trashed"].as_bool() {
                    f.trashed = t;
                }
                if let Some(n) = body["name"].as_str() {
                    f.name = n.to_string();
                }
                if let Some(mt) = body["modifiedTime"].as_str() {
                    f.modified_time = mt.to_string();
                }
                return MockResponse::json(200, &f.to_json());
            }
            "DELETE" => {
                if g.files.remove(&id).is_some() {
                    return MockResponse::empty(204);
                }
                return MockResponse::empty(404);
            }
            _ => {}
        }
    }

    MockResponse::empty(404)
}

// ---------------------------------------------------------------------------
// 5. Mock OneDrive Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockOnedriveItem {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) is_folder: bool,
    pub(crate) data: Vec<u8>,
    pub(crate) last_modified: String,
    pub(crate) etag_ver: u64,
}

pub(crate) struct MockOnedriveUploadSess {
    pub(crate) dst_path: String,
    pub(crate) buf: Vec<u8>,
    pub(crate) last_modified: String,
}

pub(crate) struct MockOnedriveState {
    pub(crate) base_url: String,
    pub(crate) items: BTreeMap<String, MockOnedriveItem>,
    pub(crate) sessions: HashMap<String, MockOnedriveUploadSess>,
    pub(crate) next_seq: u64,
}

impl MockOnedriveState {
    pub(crate) fn new(base_url: String) -> Self {
        let mut items = BTreeMap::new();
        items.insert(
            String::new(),
            MockOnedriveItem {
                id: "root".to_string(),
                path: String::new(),
                is_folder: true,
                data: Vec::new(),
                last_modified: "2026-11-24T12:00:00Z".to_string(),
                etag_ver: 1,
            },
        );
        Self {
            base_url,
            items,
            sessions: HashMap::new(),
            next_seq: 1,
        }
    }

    pub(crate) fn seed_file(&mut self, path: &str, data: Vec<u8>) {
        self.next_seq += 1;
        let id = format!("od-{}", self.next_seq);
        self.items.insert(
            path.to_string(),
            MockOnedriveItem {
                id,
                path: path.to_string(),
                is_folder: false,
                data,
                last_modified: "2026-11-24T12:00:00Z".to_string(),
                etag_ver: 1,
            },
        );
    }

    fn item_json(&self, item: &MockOnedriveItem) -> serde_json::Value {
        let name = if item.path.is_empty() {
            "root"
        } else {
            item.path.rsplit('/').next().unwrap_or(&item.path)
        };
        let mut obj = serde_json::json!({
            "id": item.id,
            "name": name,
            "size": item.data.len(),
            "eTag": format!("\"{}:{}\"", item.id, item.etag_ver),
            "lastModifiedDateTime": item.last_modified,
            "fileSystemInfo": { "lastModifiedDateTime": item.last_modified },
        });
        if item.is_folder {
            obj["folder"] = serde_json::json!({ "childCount": 0 });
        } else {
            obj["@microsoft.graph.downloadUrl"] =
                serde_json::json!(format!("{}/download/{}", self.base_url, item.id));
            obj["file"] = serde_json::json!({
                "hashes": {
                    "sha256Hash": sha256_hex(&item.data).to_ascii_uppercase(),
                    "quickXorHash": quickxor_b64(&item.data),
                }
            });
        }
        obj
    }
}

pub(crate) fn start_onedrive_mock() -> (MockHttpServer, Arc<Mutex<MockOnedriveState>>) {
    let state = Arc::new(Mutex::new(MockOnedriveState::new(String::new())));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_onedrive(&st, req));
    state.lock().unwrap().base_url = srv.base_url();
    (srv, state)
}

fn handle_onedrive(st: &Arc<Mutex<MockOnedriveState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    if req.path == "/oauth2/v2.0/token" && req.method == "POST" {
        return MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "od-refreshed-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        );
    }

    if let Some(id) = req.path.strip_prefix("/download/")
        && req.method == "GET"
    {
        let Some(it) = g.items.values().find(|i| i.id == id) else {
            return MockResponse::empty(404);
        };
        if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
            match slice_byte_range(&it.data, rng) {
                Ok((start, end, slice)) => {
                    return MockResponse::new(206, slice).with_header(
                        "content-range",
                        format!("bytes {start}-{end}/{}", it.data.len()),
                    );
                }
                Err(r) => return r,
            }
        }
        return MockResponse::new(200, it.data.clone());
    }

    if let Some(sid) = req.path.strip_prefix("/upload/") {
        match req.method.as_str() {
            "GET" => {
                let Some(sess) = g.sessions.get(sid) else {
                    return MockResponse::empty(404);
                };
                return MockResponse::json(
                    200,
                    &serde_json::json!({ "nextExpectedRanges": [format!("{}-", sess.buf.len())] }),
                );
            }
            "DELETE" => {
                g.sessions.remove(sid);
                return MockResponse::empty(204);
            }
            "PUT" => {
                let cr = req.header("content-range").unwrap_or("");
                let rest = cr.strip_prefix("bytes ").unwrap_or("0-0/0");
                let (rng, total_s) = rest.split_once('/').unwrap_or(("0-0", "0"));
                let (s_s, e_s) = rng.split_once('-').unwrap_or(("0", "0"));
                let start: usize = s_s.parse().unwrap_or(0);
                let end: usize = e_s.parse().unwrap_or(0);
                let total: usize = total_s.parse().unwrap_or(0);
                let is_final = end + 1 >= total;
                {
                    let Some(sess) = g.sessions.get_mut(sid) else {
                        return MockResponse::empty(404);
                    };
                    if start != sess.buf.len() {
                        return MockResponse::json(
                            416,
                            &serde_json::json!({ "error": { "code": "fragmentOverlap" } }),
                        );
                    }
                    sess.buf.extend_from_slice(&req.body);
                }
                if is_final {
                    let sess = g.sessions.remove(sid).unwrap();
                    g.next_seq += 1;
                    let id = format!("od-{}", g.next_seq);
                    let item = MockOnedriveItem {
                        id,
                        path: sess.dst_path.clone(),
                        is_folder: false,
                        data: sess.buf,
                        last_modified: sess.last_modified,
                        etag_ver: g.next_seq,
                    };
                    let j = g.item_json(&item);
                    g.items.insert(sess.dst_path, item);
                    return MockResponse::json(201, &j);
                }
                let next = g.sessions.get(sid).map(|s| s.buf.len()).unwrap_or(0);
                return MockResponse::json(
                    202,
                    &serde_json::json!({ "nextExpectedRanges": [format!("{next}-")] }),
                );
            }
            _ => {}
        }
    }

    if req.path == "/v1.0/me/drive" && req.method == "GET" {
        return MockResponse::json(
            200,
            &serde_json::json!({
                "id": "drive-1",
                "quota": {
                    "total": 100_000_000u64,
                    "used": 25_000_000u64,
                    "remaining": 75_000_000u64,
                    "deleted": 1_000_000u64
                }
            }),
        );
    }

    if let Some(rest) = req.path.strip_prefix("/v1.0/me/drive/items/") {
        if let Some(id) = rest.strip_suffix("/content") {
            let Some(it) = g.items.values().find(|i| i.id == id) else {
                return MockResponse::empty(404);
            };
            if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                match slice_byte_range(&it.data, rng) {
                    Ok((start, end, slice)) => {
                        return MockResponse::new(206, slice).with_header(
                            "content-range",
                            format!("bytes {start}-{end}/{}", it.data.len()),
                        );
                    }
                    Err(r) => return r,
                }
            }
            return MockResponse::new(200, it.data.clone());
        }
        match req.method.as_str() {
            "GET" => {
                let Some(it) = g.items.values().find(|i| i.id == rest) else {
                    return MockResponse::empty(404);
                };
                return MockResponse::json(200, &g.item_json(it));
            }
            "PATCH" => {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let key = g
                    .items
                    .iter()
                    .find(|(_, i)| i.id == rest)
                    .map(|(k, _)| k.clone());
                let Some(k) = key else {
                    return MockResponse::empty(404);
                };
                if let Some(lm) = body["fileSystemInfo"]["lastModifiedDateTime"].as_str() {
                    g.items.get_mut(&k).unwrap().last_modified = lm.to_string();
                }
                let it = g.items.get(&k).unwrap().clone();
                return MockResponse::json(200, &g.item_json(&it));
            }
            "DELETE" => {
                let key = g
                    .items
                    .iter()
                    .find(|(_, i)| i.id == rest)
                    .map(|(k, _)| k.clone());
                if let Some(k) = key {
                    g.items.remove(&k);
                    return MockResponse::empty(204);
                }
                return MockResponse::empty(404);
            }
            _ => {}
        }
    }

    if let Some(rest) = req.path.strip_prefix("/v1.0/me/drive/root") {
        let (target_path, action) = if rest.is_empty() {
            (String::new(), "")
        } else if let Some(act) = rest.strip_prefix('/') {
            (String::new(), act)
        } else if let Some(after_colon) = rest.strip_prefix(":/") {
            if let Some((p, act)) = after_colon.rsplit_once(":/") {
                (pct_decode(p), act)
            } else if let Some(p) = after_colon.strip_suffix(':') {
                (pct_decode(p), "")
            } else {
                (pct_decode(after_colon), "")
            }
        } else {
            return MockResponse::empty(404);
        };

        match (req.method.as_str(), action) {
            ("GET", "") => {
                let Some(it) = g.items.get(&target_path) else {
                    return MockResponse::empty(404);
                };
                return MockResponse::json(200, &g.item_json(it));
            }
            ("GET", "children") => {
                if !g.items.contains_key(&target_path) {
                    return MockResponse::empty(404);
                }
                let pfx = if target_path.is_empty() {
                    String::new()
                } else {
                    format!("{target_path}/")
                };
                let vals: Vec<_> = g
                    .items
                    .values()
                    .filter(|it| !it.path.is_empty())
                    .filter(|it| {
                        if pfx.is_empty() {
                            !it.path.contains('/')
                        } else if let Some(r) = it.path.strip_prefix(&pfx) {
                            !r.is_empty() && !r.contains('/')
                        } else {
                            false
                        }
                    })
                    .map(|it| g.item_json(it))
                    .collect();
                return MockResponse::json(200, &serde_json::json!({ "value": vals }));
            }
            ("POST", "children") => {
                let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let name = v["name"].as_str().unwrap_or("");
                let full = if target_path.is_empty() {
                    name.to_string()
                } else {
                    format!("{target_path}/{name}")
                };
                g.next_seq += 1;
                let item = MockOnedriveItem {
                    id: format!("od-{}", g.next_seq),
                    path: full.clone(),
                    is_folder: true,
                    data: Vec::new(),
                    last_modified: "2026-11-24T12:00:00Z".to_string(),
                    etag_ver: g.next_seq,
                };
                let j = g.item_json(&item);
                g.items.insert(full, item);
                return MockResponse::json(201, &j);
            }
            ("PUT", "content") => {
                g.next_seq += 1;
                let id = g
                    .items
                    .get(&target_path)
                    .map(|i| i.id.clone())
                    .unwrap_or_else(|| format!("od-{}", g.next_seq));
                let item = MockOnedriveItem {
                    id,
                    path: target_path.clone(),
                    is_folder: false,
                    data: req.body.clone(),
                    last_modified: "2026-11-24T12:00:00Z".to_string(),
                    etag_ver: g.next_seq,
                };
                let j = g.item_json(&item);
                g.items.insert(target_path, item);
                return MockResponse::json(201, &j);
            }
            ("POST", "createUploadSession") => {
                let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let last_modified = v["item"]["fileSystemInfo"]["lastModifiedDateTime"]
                    .as_str()
                    .unwrap_or("2026-11-24T12:00:00Z")
                    .to_string();
                g.next_seq += 1;
                let sid = format!("od-sess-{}", g.next_seq);
                g.sessions.insert(
                    sid.clone(),
                    MockOnedriveUploadSess {
                        dst_path: target_path,
                        buf: Vec::new(),
                        last_modified,
                    },
                );
                return MockResponse::json(
                    200,
                    &serde_json::json!({
                        "uploadUrl": format!("{}/upload/{sid}", g.base_url),
                        "expirationDateTime": "2026-12-01T00:00:00Z"
                    }),
                );
            }
            ("DELETE", "") => {
                if g.items.remove(&target_path).is_some() {
                    return MockResponse::empty(204);
                }
                return MockResponse::empty(404);
            }
            _ => {}
        }
    }

    MockResponse::empty(404)
}

// ---------------------------------------------------------------------------
// 6. Mock Dropbox Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MockDropboxEntry {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) is_folder: bool,
    pub(crate) data: Vec<u8>,
    pub(crate) rev: String,
    pub(crate) client_modified: String,
}

pub(crate) struct MockDropboxState {
    pub(crate) entries: BTreeMap<String, MockDropboxEntry>,
    pub(crate) sessions: HashMap<String, Vec<u8>>,
    pub(crate) next_seq: u64,
}

impl MockDropboxState {
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            sessions: HashMap::new(),
            next_seq: 1,
        }
    }

    fn key(p: &str) -> String {
        p.trim_end_matches('/').to_ascii_lowercase()
    }

    fn ensure_parents(&mut self, path: &str) {
        let trimmed = path.trim_matches('/');
        let parts: Vec<&str> = trimmed.split('/').collect();
        for i in 1..parts.len() {
            let sub = format!("/{}", parts[..i].join("/"));
            let k = Self::key(&sub);
            if !self.entries.contains_key(&k) {
                self.next_seq += 1;
                self.entries.insert(
                    k,
                    MockDropboxEntry {
                        id: format!("id:dir-{}", self.next_seq),
                        path: sub,
                        is_folder: true,
                        data: Vec::new(),
                        rev: "0100000000000001".to_string(),
                        client_modified: "2026-11-25T02:00:00Z".to_string(),
                    },
                );
            }
        }
    }

    pub(crate) fn seed_file(&mut self, path: &str, data: Vec<u8>) {
        self.ensure_parents(path);
        self.next_seq += 1;
        let id = format!("id:file-{}", self.next_seq);
        let rev = format!("{:016x}", self.next_seq);
        self.entries.insert(
            Self::key(path),
            MockDropboxEntry {
                id,
                path: path.to_string(),
                is_folder: false,
                data,
                rev,
                client_modified: "2026-11-25T02:00:00Z".to_string(),
            },
        );
    }

    fn entry_json(e: &MockDropboxEntry) -> serde_json::Value {
        let name = e.path.rsplit('/').next().unwrap_or("");
        if e.is_folder {
            serde_json::json!({
                ".tag": "folder",
                "name": name,
                "path_lower": e.path.to_ascii_lowercase(),
                "path_display": e.path,
                "id": e.id,
            })
        } else {
            serde_json::json!({
                ".tag": "file",
                "name": name,
                "path_lower": e.path.to_ascii_lowercase(),
                "path_display": e.path,
                "id": e.id,
                "client_modified": e.client_modified,
                "server_modified": e.client_modified,
                "rev": e.rev,
                "size": e.data.len(),
                "is_downloadable": true,
                "content_hash": dropbox_content_hash(&e.data),
            })
        }
    }
}

pub(crate) fn start_dropbox_mock() -> (MockHttpServer, Arc<Mutex<MockDropboxState>>) {
    let state = Arc::new(Mutex::new(MockDropboxState::new()));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_dropbox(&st, req));
    (srv, state)
}

fn handle_dropbox(st: &Arc<Mutex<MockDropboxState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    if req.path == "/oauth2/token" && req.method == "POST" {
        return MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "dbx-refreshed-tok",
                "token_type": "bearer",
                "expires_in": 14400
            }),
        );
    }

    match req.path.as_str() {
        "/2/users/get_space_usage" => MockResponse::json(
            200,
            &serde_json::json!({
                "used": 100_000_000u64,
                "allocation": { ".tag": "individual", "allocated": 2_000_000_000u64 }
            }),
        ),
        "/2/files/get_metadata" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let p = v["path"].as_str().unwrap_or("");
            if let Some(e) = g.entries.get(&MockDropboxState::key(p)) {
                MockResponse::json(200, &MockDropboxState::entry_json(e))
            } else {
                MockResponse::json(
                    409,
                    &serde_json::json!({
                        "error_summary": "path/not_found/.",
                        "error": { ".tag": "path", "path": { ".tag": "not_found" } }
                    }),
                )
            }
        }
        "/2/files/list_folder" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let p = v["path"].as_str().unwrap_or("");
            let recursive = v["recursive"].as_bool().unwrap_or(false);
            let pfx_lower = if p.is_empty() {
                "/".to_string()
            } else {
                format!("{}/", p.trim_end_matches('/').to_ascii_lowercase())
            };
            let entries: Vec<_> = g
                .entries
                .values()
                .filter(|e| {
                    let lower = e.path.to_ascii_lowercase();
                    if !lower.starts_with(&pfx_lower) {
                        return false;
                    }
                    let rest = &lower[pfx_lower.len()..];
                    !rest.is_empty() && (recursive || !rest.contains('/'))
                })
                .map(MockDropboxState::entry_json)
                .collect();
            MockResponse::json(
                200,
                &serde_json::json!({ "entries": entries, "cursor": "done", "has_more": false }),
            )
        }
        "/2/files/create_folder_v2" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let p = v["path"].as_str().unwrap_or("");
            g.ensure_parents(p);
            g.next_seq += 1;
            let entry = MockDropboxEntry {
                id: format!("id:dir-{}", g.next_seq),
                path: p.to_string(),
                is_folder: true,
                data: Vec::new(),
                rev: "0100000000000001".to_string(),
                client_modified: "2026-11-25T02:00:00Z".to_string(),
            };
            g.entries.insert(MockDropboxState::key(p), entry.clone());
            MockResponse::json(
                200,
                &serde_json::json!({ "metadata": MockDropboxState::entry_json(&entry) }),
            )
        }
        "/2/files/delete_v2" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let p = v["path"].as_str().unwrap_or("");
            let Some(rem) = g.entries.remove(&MockDropboxState::key(p)) else {
                return MockResponse::json(
                    409,
                    &serde_json::json!({ "error_summary": "path_lookup/not_found/." }),
                );
            };
            MockResponse::json(
                200,
                &serde_json::json!({ "metadata": MockDropboxState::entry_json(&rem) }),
            )
        }
        "/2/files/delete_batch" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let mut results = Vec::new();
            for item in v["entries"].as_array().cloned().unwrap_or_default() {
                let p = item["path"].as_str().unwrap_or("");
                if let Some(rem) = g.entries.remove(&MockDropboxState::key(p)) {
                    results.push(serde_json::json!({
                        ".tag": "success",
                        "metadata": MockDropboxState::entry_json(&rem)
                    }));
                } else {
                    results.push(serde_json::json!({
                        ".tag": "failure",
                        "failure": { ".tag": "path_lookup", "path_lookup": { ".tag": "not_found" } }
                    }));
                }
            }
            MockResponse::json(
                200,
                &serde_json::json!({ ".tag": "complete", "entries": results }),
            )
        }
        "/2/files/copy_v2" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let from = v["from_path"].as_str().unwrap_or("");
            let to = v["to_path"].as_str().unwrap_or("");
            let Some(src) = g.entries.get(&MockDropboxState::key(from)).cloned() else {
                return MockResponse::json(
                    409,
                    &serde_json::json!({ "error_summary": "from_lookup/not_found/." }),
                );
            };
            if g.entries.contains_key(&MockDropboxState::key(to)) {
                return MockResponse::json(
                    409,
                    &serde_json::json!({
                        "error_summary": "to/conflict/file/.",
                        "error": { ".tag": "to", "to": { ".tag": "conflict" } }
                    }),
                );
            }
            g.ensure_parents(to);
            g.next_seq += 1;
            let copied = MockDropboxEntry {
                id: format!("id:copy-{}", g.next_seq),
                path: to.to_string(),
                is_folder: src.is_folder,
                data: src.data,
                rev: format!("{:016x}", g.next_seq),
                client_modified: src.client_modified,
            };
            g.entries.insert(MockDropboxState::key(to), copied.clone());
            MockResponse::json(
                200,
                &serde_json::json!({ "metadata": MockDropboxState::entry_json(&copied) }),
            )
        }
        "/2/files/move_v2" => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let from = v["from_path"].as_str().unwrap_or("");
            let to = v["to_path"].as_str().unwrap_or("");
            let Some(mut src) = g.entries.remove(&MockDropboxState::key(from)) else {
                return MockResponse::json(
                    409,
                    &serde_json::json!({ "error_summary": "from_lookup/not_found/." }),
                );
            };
            g.ensure_parents(to);
            src.path = to.to_string();
            g.entries.insert(MockDropboxState::key(to), src.clone());
            MockResponse::json(
                200,
                &serde_json::json!({ "metadata": MockDropboxState::entry_json(&src) }),
            )
        }
        "/2/files/upload" => {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let p = arg["path"].as_str().unwrap_or("");
            g.ensure_parents(p);
            g.next_seq += 1;
            let entry = MockDropboxEntry {
                id: format!("id:file-{}", g.next_seq),
                path: p.to_string(),
                is_folder: false,
                data: req.body.clone(),
                rev: format!("{:016x}", g.next_seq),
                client_modified: arg["client_modified"]
                    .as_str()
                    .unwrap_or("2026-11-25T02:00:00Z")
                    .to_string(),
            };
            g.entries.insert(MockDropboxState::key(p), entry.clone());
            MockResponse::json(200, &MockDropboxState::entry_json(&entry))
        }
        "/2/files/download" => {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let p = arg["path"].as_str().unwrap_or("");
            let Some(entry) = g.entries.get(&MockDropboxState::key(p)) else {
                return MockResponse::json(
                    409,
                    &serde_json::json!({ "error_summary": "path/not_found/." }),
                );
            };
            let api_res = encode_dropbox_api_arg(&MockDropboxState::entry_json(entry));
            MockResponse::new(200, entry.data.clone()).with_header("dropbox-api-result", api_res)
        }
        "/2/files/upload_session/start" => {
            g.next_seq += 1;
            let sid = format!("dbx-sess-{}", g.next_seq);
            g.sessions.insert(sid.clone(), req.body.clone());
            MockResponse::json(200, &serde_json::json!({ "session_id": sid }))
        }
        "/2/files/upload_session/append_v2" => {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
            if let Some(buf) = g.sessions.get_mut(sid) {
                buf.extend_from_slice(&req.body);
            }
            MockResponse::json(200, &serde_json::json!(null))
        }
        "/2/files/upload_session/finish" => {
            let arg: serde_json::Value = req
                .header("dropbox-api-arg")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let sid = arg["cursor"]["session_id"].as_str().unwrap_or("");
            let dst = arg["commit"]["path"].as_str().unwrap_or("");
            let mut data = g.sessions.remove(sid).unwrap_or_default();
            data.extend_from_slice(&req.body);
            g.ensure_parents(dst);
            g.next_seq += 1;
            let entry = MockDropboxEntry {
                id: format!("id:file-{}", g.next_seq),
                path: dst.to_string(),
                is_folder: false,
                data,
                rev: format!("{:016x}", g.next_seq),
                client_modified: "2026-11-25T02:00:00Z".to_string(),
            };
            g.entries.insert(MockDropboxState::key(dst), entry.clone());
            MockResponse::json(200, &MockDropboxState::entry_json(&entry))
        }
        _ => MockResponse::empty(404),
    }
}

// ---------------------------------------------------------------------------
// 7. Mock WebDAV (Nextcloud) Store
// ---------------------------------------------------------------------------

pub(crate) struct MockWebdavState {
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    pub(crate) dirs: BTreeSet<String>,
    pub(crate) etags: BTreeMap<String, String>,
    pub(crate) next_seq: u64,
    pub(crate) move_207_failure: Option<(String, String)>,
}

impl MockWebdavState {
    pub(crate) fn new() -> Self {
        let mut dirs = BTreeSet::new();
        dirs.insert("/remote.php/dav/files/alice".to_string());
        dirs.insert("/remote.php/dav/uploads/alice".to_string());
        Self {
            files: BTreeMap::new(),
            dirs,
            etags: BTreeMap::new(),
            next_seq: 1,
            move_207_failure: None,
        }
    }

    pub(crate) fn seed_file(&mut self, rel: &str, data: Vec<u8>) {
        let full = format!(
            "/remote.php/dav/files/alice/{}",
            rel.trim_start_matches('/')
        );
        if let Some((parent, _)) = full.rsplit_once('/') {
            let mut cur = String::new();
            for seg in parent.trim_start_matches('/').split('/') {
                cur.push('/');
                cur.push_str(seg);
                self.dirs.insert(cur.clone());
            }
        }
        self.next_seq += 1;
        self.etags
            .insert(full.clone(), format!("\"w{}\"", self.next_seq));
        self.files.insert(full, data);
    }
}

pub(crate) fn start_webdav_mock() -> (MockHttpServer, Arc<Mutex<MockWebdavState>>) {
    let state = Arc::new(Mutex::new(MockWebdavState::new()));
    let st = state.clone();
    let srv = MockHttpServer::start(move |req| handle_webdav(&st, req));
    (srv, state)
}

fn destination_path(hdr: &str) -> String {
    let without_scheme = if let Some((_, rest)) = hdr.split_once("://") {
        rest.split_once('/')
            .map(|(_, p)| format!("/{p}"))
            .unwrap_or_else(|| "/".to_string())
    } else {
        hdr.to_string()
    };
    pct_decode(&without_scheme)
        .trim_end_matches('/')
        .to_string()
}

fn webdav_207_failure_response(
    failure: &Option<(String, String)>,
    src_path: &str,
    dst_path: &str,
) -> Option<MockResponse> {
    let (fail_href, fail_status_line) = failure.as_ref()?;
    let target = fail_href.trim_end_matches('/');
    if dst_path != target && src_path != target {
        return None;
    }
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>{}</d:href><d:status>{fail_status_line}</d:status></d:response></d:multistatus>",
        pct_encode_path(fail_href)
    );
    Some(MockResponse::xml(207, xml))
}

fn handle_webdav(st: &Arc<Mutex<MockWebdavState>>, req: &RecordedRequest) -> MockResponse {
    let mut g = st.lock().unwrap();
    let path = pct_decode(&req.path).trim_end_matches('/').to_string();

    match req.method.as_str() {
        "PROPFIND" => {
            let depth = req.header("depth").unwrap_or("0");
            let is_file = g.files.contains_key(&path);
            let is_dir = g.dirs.contains(&path);
            if !is_file && !is_dir {
                return MockResponse::empty(404);
            }
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
            );
            let push_item = |xml: &mut String, href: &str, dir: bool, len: usize, etag: &str| {
                let rt = if dir { "<d:collection/>" } else { "" };
                xml.push_str(&format!(
                    "<d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype>{rt}</d:resourcetype><d:getcontentlength>{len}</d:getcontentlength><d:getlastmodified>Tue, 24 Nov 2026 12:00:00 GMT</d:getlastmodified><d:getetag>{etag}</d:getetag><d:quota-available-bytes>8000000</d:quota-available-bytes><d:quota-used-bytes>2000000</d:quota-used-bytes></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                    pct_encode_path(href)
                ));
            };
            if is_file {
                let et = g
                    .etags
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| "\"w0\"".to_string());
                push_item(&mut xml, &path, false, g.files[&path].len(), &et);
            } else {
                push_item(&mut xml, &format!("{path}/"), true, 0, "\"dir\"");
                if depth == "1" {
                    let pfx = format!("{path}/");
                    for d in &g.dirs {
                        if let Some(rest) = d.strip_prefix(&pfx)
                            && !rest.is_empty()
                            && !rest.contains('/')
                        {
                            push_item(&mut xml, &format!("{d}/"), true, 0, "\"dir\"");
                        }
                    }
                    for (f, data) in &g.files {
                        if let Some(rest) = f.strip_prefix(&pfx)
                            && !rest.is_empty()
                            && !rest.contains('/')
                        {
                            let et = g
                                .etags
                                .get(f)
                                .cloned()
                                .unwrap_or_else(|| "\"w0\"".to_string());
                            push_item(&mut xml, f, false, data.len(), &et);
                        }
                    }
                }
            }
            xml.push_str("</d:multistatus>");
            MockResponse::xml(207, xml)
        }
        "MKCOL" => {
            if g.dirs.contains(&path) || g.files.contains_key(&path) {
                MockResponse::empty(405)
            } else {
                g.dirs.insert(path);
                MockResponse::empty(201)
            }
        }
        "PUT" => {
            if let Some((parent, _)) = path.rsplit_once('/') {
                g.dirs.insert(parent.to_string());
            }
            g.next_seq += 1;
            let etag = format!("\"w{}\"", g.next_seq);
            g.etags.insert(path.clone(), etag.clone());
            let md5 = md5_hex(&req.body);
            let want_x_hash = req
                .header("x-hash")
                .is_some_and(|h| h.eq_ignore_ascii_case("md5"));
            g.files.insert(path, req.body.clone());
            let mut resp = MockResponse::empty(201).with_header("etag", etag);
            if want_x_hash {
                resp = resp.with_header("x-hash-md5", md5);
            }
            resp
        }
        "GET" => {
            let Some(data) = g.files.get(&path) else {
                return MockResponse::empty(404);
            };
            if let Some(rng) = req.header("range").and_then(|s| s.strip_prefix("bytes=")) {
                match slice_byte_range(data, rng) {
                    Ok((start, end, slice)) => {
                        return MockResponse::new(206, slice).with_header(
                            "content-range",
                            format!("bytes {start}-{end}/{}", data.len()),
                        );
                    }
                    Err(r) => return r,
                }
            }
            MockResponse::new(200, data.clone())
        }
        "DELETE" => {
            let rf = g.files.remove(&path).is_some();
            let rd = g.dirs.remove(&path);
            let pfx = format!("{path}/");
            g.files.retain(|k, _| !k.starts_with(&pfx));
            g.dirs.retain(|k| !k.starts_with(&pfx));
            if rf || rd {
                MockResponse::empty(204)
            } else {
                MockResponse::empty(404)
            }
        }
        "COPY" => {
            let Some(dst_hdr) = req.header("destination") else {
                return MockResponse::empty(400);
            };
            let dst_path = destination_path(dst_hdr);
            if let Some(resp) = webdav_207_failure_response(&g.move_207_failure, &path, &dst_path) {
                return resp;
            }
            let Some(data) = g.files.get(&path).cloned() else {
                return MockResponse::empty(404);
            };
            if let Some((parent, _)) = dst_path.rsplit_once('/') {
                g.dirs.insert(parent.to_string());
            }
            let existed = g.files.contains_key(&dst_path);
            g.next_seq += 1;
            let seq = g.next_seq;
            g.etags.insert(dst_path.clone(), format!("\"w{seq}\""));
            g.files.insert(dst_path, data);
            MockResponse::empty(if existed { 204 } else { 201 })
        }
        "MOVE" => {
            let Some(dst_hdr) = req.header("destination") else {
                return MockResponse::empty(400);
            };
            let dst_path = destination_path(dst_hdr);
            if let Some(resp) = webdav_207_failure_response(&g.move_207_failure, &path, &dst_path) {
                return resp;
            }
            if let Some(staging_dir) = path.strip_suffix("/.file") {
                if !g.dirs.contains(staging_dir) {
                    return MockResponse::empty(404);
                }
                let pfx = format!("{staging_dir}/");
                let mut chunks: Vec<(String, Vec<u8>)> = g
                    .files
                    .iter()
                    .filter(|(k, _)| k.starts_with(&pfx))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                chunks.sort_by(|a, b| {
                    let na = a.0.rsplit('/').next().unwrap_or(&a.0).parse::<u64>();
                    let nb = b.0.rsplit('/').next().unwrap_or(&b.0).parse::<u64>();
                    match (na, nb) {
                        (Ok(ia), Ok(ib)) => ia.cmp(&ib),
                        _ => a.0.cmp(&b.0),
                    }
                });
                let mut assembled = Vec::new();
                for (_, data) in chunks {
                    assembled.extend_from_slice(&data);
                }
                g.files.retain(|k, _| !k.starts_with(&pfx));
                g.dirs.remove(staging_dir);
                if let Some((parent, _)) = dst_path.rsplit_once('/') {
                    g.dirs.insert(parent.to_string());
                }
                g.next_seq += 1;
                let etag = format!("\"w{}\"", g.next_seq);
                g.etags.insert(dst_path.clone(), etag.clone());
                g.files.insert(dst_path, assembled);
                return MockResponse::empty(201).with_header("etag", etag);
            }
            if let Some(data) = g.files.remove(&path) {
                let existed = g.files.contains_key(&dst_path);
                if let Some((parent, _)) = dst_path.rsplit_once('/') {
                    g.dirs.insert(parent.to_string());
                }
                g.next_seq += 1;
                let seq = g.next_seq;
                g.etags.insert(dst_path.clone(), format!("\"w{seq}\""));
                g.files.insert(dst_path, data);
                return MockResponse::empty(if existed { 204 } else { 201 });
            }
            MockResponse::empty(404)
        }
        _ => MockResponse::empty(405),
    }
}
