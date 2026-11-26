#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};

#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub raw_target: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|vals| vals.first())
            .map(String::as_str)
    }

    pub fn header_values(&self, name: &str) -> &[String] {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn body_text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    pub fn body_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::from_slice(&self.body)
    }

    pub fn form_pairs(&self) -> Vec<(String, String)> {
        let text = String::from_utf8_lossy(&self.body);
        if text.is_empty() {
            return Vec::new();
        }
        text.split('&')
            .filter(|part| !part.is_empty())
            .map(|part| match part.split_once('=') {
                Some((k, v)) => (percent_decode_form(k), percent_decode_form(v)),
                None => (percent_decode_form(part), String::new()),
            })
            .collect()
    }

    pub fn form_get(&self, key: &str) -> Option<String> {
        self.form_pairs()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn query_pairs(&self) -> Vec<(String, String)> {
        let Some(q) = &self.query else {
            return Vec::new();
        };
        q.split('&')
            .filter(|part| !part.is_empty())
            .map(|part| match part.split_once('=') {
                Some((k, v)) => (percent_decode_form(k), percent_decode_form(v)),
                None => (percent_decode_form(part), String::new()),
            })
            .collect()
    }

    pub fn query_get(&self, key: &str) -> Option<String> {
        self.query_pairs()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

fn percent_decode_form(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay_before_headers: Duration,
    pub close_after: bool,
}

impl MockResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason: None,
            headers: Vec::new(),
            body: body.into(),
            delay_before_headers: Duration::ZERO,
            close_after: false,
        }
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, body)
    }

    pub fn empty(status: u16) -> Self {
        Self::new(status, Vec::new())
    }

    pub fn text(status: u16, text: impl Into<String>) -> Self {
        Self::new(status, text.into().into_bytes())
            .with_header("Content-Type", "text/plain; charset=utf-8")
    }

    pub fn json(status: u16, val: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(val).unwrap_or_default();
        Self::new(status, body).with_header("Content-Type", "application/json")
    }

    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay_before_headers = delay;
        self
    }

    pub fn with_close(mut self) -> Self {
        self.close_after = true;
        self
    }
}

#[derive(Debug, Clone)]
pub enum MockAction {
    Respond(MockResponse),
    /// Drain request, write status+headers+Content-Length: declared_len + prefix, then hang open.
    HeadersThenStall {
        status: u16,
        headers: Vec<(String, String)>,
        declared_len: usize,
        prefix: Vec<u8>,
    },
    /// Drain request, write headers+Content-Length: declared_len + prefix (< declared_len), then close.
    TruncatedBody {
        status: u16,
        headers: Vec<(String, String)>,
        declared_len: usize,
        prefix: Vec<u8>,
    },
    /// Drop/close TCP socket immediately after reading request without sending headers.
    AbruptReset,
    /// Drain request and hold socket open without sending headers.
    StallBeforeHeaders,
}

pub type DynamicHandler = Arc<dyn Fn(&CapturedRequest) -> MockAction + Send + Sync>;

pub struct MockHttpServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    queue: Arc<Mutex<VecDeque<MockAction>>>,
    fallback: Arc<Mutex<Option<DynamicHandler>>>,
    req_notify: Arc<Notify>,
    shutdown: watch::Sender<bool>,
    hits: Arc<AtomicUsize>,
}

impl MockHttpServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind MockHttpServer on 127.0.0.1:0");
        let addr = listener.local_addr().expect("MockHttpServer local_addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let fallback: Arc<Mutex<Option<DynamicHandler>>> = Arc::new(Mutex::new(None));
        let req_notify = Arc::new(Notify::new());
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let hits = Arc::new(AtomicUsize::new(0));

        let requests_c = requests.clone();
        let queue_c = queue.clone();
        let fallback_c = fallback.clone();
        let notify_c = req_notify.clone();
        let hits_c = hits.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let _ = stream.set_nodelay(true);
                        let reqs = requests_c.clone();
                        let q = queue_c.clone();
                        let fb = fallback_c.clone();
                        let n = notify_c.clone();
                        let h = hits_c.clone();
                        let mut conn_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, reqs, q, fb, n, h, &mut conn_shutdown).await;
                        });
                    }
                }
            }
        });

        Self {
            addr,
            requests,
            queue,
            fallback,
            req_notify,
            shutdown,
            hits,
        }
    }

    pub async fn start_with_handler<F>(handler: F) -> Self
    where
        F: Fn(&CapturedRequest) -> MockAction + Send + Sync + 'static,
    {
        let srv = Self::start().await;
        srv.set_fallback(handler);
        srv
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("http://{}{path}", self.addr)
        } else {
            format!("http://{}/{path}", self.addr)
        }
    }

    pub fn enqueue(&self, action: MockAction) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(action);
    }

    pub fn enqueue_response(&self, resp: MockResponse) {
        self.enqueue(MockAction::Respond(resp));
    }

    pub fn set_fallback<F>(&self, handler: F)
    where
        F: Fn(&CapturedRequest) -> MockAction + Send + Sync + 'static,
    {
        *self.fallback.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(handler));
    }

    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn take_requests(&self) -> Vec<CapturedRequest> {
        let mut guard = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }

    pub fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub async fn wait_for_requests(&self, count: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.req_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.hits.load(Ordering::SeqCst) >= count {
                return true;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn handle_connection(
    stream: TcpStream,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    queue: Arc<Mutex<VecDeque<MockAction>>>,
    fallback: Arc<Mutex<Option<DynamicHandler>>>,
    notify: Arc<Notify>,
    hits: Arc<AtomicUsize>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut reader = BufReader::new(stream);
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        let req_opt = tokio::select! {
            _ = shutdown_rx.changed() => return,
            r = read_http_request(&mut reader) => r,
        };
        let Some((req, client_wants_close)) = (match req_opt {
            Ok(v) => v,
            Err(_) => return,
        }) else {
            return;
        };

        let is_head = req.method.eq_ignore_ascii_case("HEAD");
        let action = {
            let queued = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
            match queued {
                Some(a) => a,
                None => {
                    let fb = fallback.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    match fb {
                        Some(handler) => handler(&req),
                        None => MockAction::Respond(MockResponse::empty(404)),
                    }
                }
            }
        };

        requests.lock().unwrap_or_else(|e| e.into_inner()).push(req);
        hits.fetch_add(1, Ordering::SeqCst);
        notify.notify_waiters();

        match action {
            MockAction::Respond(resp) => {
                if !resp.delay_before_headers.is_zero() {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return,
                        _ = tokio::time::sleep(resp.delay_before_headers) => {}
                    }
                }
                let close = client_wants_close || resp.close_after;
                if write_mock_response(reader.get_mut(), &resp, is_head, close)
                    .await
                    .is_err()
                {
                    return;
                }
                if close {
                    let _ = reader.get_mut().shutdown().await;
                    return;
                }
            }
            MockAction::HeadersThenStall {
                status,
                headers,
                declared_len,
                prefix,
            } => {
                let mut head = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Length: {declared_len}\r\nConnection: close\r\n",
                    default_reason(status)
                );
                for (k, v) in &headers {
                    if !k.eq_ignore_ascii_case("content-length")
                        && !k.eq_ignore_ascii_case("connection")
                    {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                }
                head.push_str("\r\n");
                let sock = reader.get_mut();
                if sock.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                if !is_head && !prefix.is_empty() && sock.write_all(&prefix).await.is_err() {
                    return;
                }
                let _ = sock.flush().await;
                let _ = shutdown_rx.changed().await;
                return;
            }
            MockAction::TruncatedBody {
                status,
                headers,
                declared_len,
                prefix,
            } => {
                let mut head = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Length: {declared_len}\r\nConnection: close\r\n",
                    default_reason(status)
                );
                for (k, v) in &headers {
                    if !k.eq_ignore_ascii_case("content-length")
                        && !k.eq_ignore_ascii_case("connection")
                    {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                }
                head.push_str("\r\n");
                let sock = reader.get_mut();
                let _ = sock.write_all(head.as_bytes()).await;
                if !is_head && !prefix.is_empty() {
                    let _ = sock.write_all(&prefix).await;
                }
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
                return;
            }
            MockAction::AbruptReset => {
                drop(reader);
                return;
            }
            MockAction::StallBeforeHeaders => {
                let _ = shutdown_rx.changed().await;
                return;
            }
        }
    }
}

async fn read_http_request(
    reader: &mut BufReader<TcpStream>,
) -> std::io::Result<Option<(CapturedRequest, bool)>> {
    let mut request_line = String::new();
    loop {
        request_line.clear();
        let n = reader.read_line(&mut request_line).await?;
        if n == 0 {
            return Ok(None);
        }
        if request_line != "\r\n" && request_line != "\n" {
            break;
        }
    }

    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let raw_target = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing target"))?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1");

    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw_target.clone(), None),
    };

    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in headers",
            ));
        }
        let header_line = line.trim_end_matches(['\r', '\n']);
        if header_line.is_empty() {
            break;
        }
        if let Some((k, v)) = header_line.split_once(':') {
            headers
                .entry(k.trim().to_ascii_lowercase())
                .or_default()
                .push(v.trim().to_string());
        }
    }

    // Eagerly accept `Expect: 100-continue` before queue/fallback dispatch so clients proceed
    // with sending their request body; early 401/412 pre-body rejections cannot be mocked via `MockResponse`.
    let has_100_continue = headers
        .get("expect")
        .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case("100-continue")));
    if has_100_continue {
        let sock = reader.get_mut();
        sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        sock.flush().await?;
    }

    let is_chunked = headers.get("transfer-encoding").is_some_and(|vals| {
        vals.iter()
            .any(|v| v.to_ascii_lowercase().contains("chunked"))
    });

    let body = if is_chunked {
        read_chunked_body(reader).await?
    } else if let Some(cl_val) = headers.get("content-length").and_then(|v| v.first()) {
        let len: usize = cl_val.trim().parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid content-length")
        })?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        buf
    } else {
        Vec::new()
    };

    let client_wants_close = headers
        .get("connection")
        .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case("close")))
        || version.eq_ignore_ascii_case("HTTP/1.0");

    Ok(Some((
        CapturedRequest {
            method,
            raw_target,
            path,
            query,
            headers,
            body,
        },
        client_wants_close,
    )))
}

async fn read_chunked_body(reader: &mut BufReader<TcpStream>) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF reading chunk size",
            ));
        }
        let size_hex = line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk hex len")
        })?;
        if chunk_len == 0 {
            // Drain optional trailer headers until empty line.
            loop {
                line.clear();
                let tn = reader.read_line(&mut line).await?;
                if tn == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
            }
            break;
        }
        let start = out.len();
        out.resize(start + chunk_len, 0);
        reader.read_exact(&mut out[start..]).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
    }
    Ok(out)
}

async fn write_mock_response(
    sock: &mut TcpStream,
    resp: &MockResponse,
    is_head: bool,
    close: bool,
) -> std::io::Result<()> {
    let reason = resp
        .reason
        .as_deref()
        .unwrap_or_else(|| default_reason(resp.status));
    let status_forbids_body = matches!(resp.status, 204 | 304) || resp.status < 200;
    let no_body = is_head || status_forbids_body;
    let has_te = resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let has_te_chunked = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });

    let mut head = format!("HTTP/1.1 {} {reason}\r\n", resp.status);
    let mut has_cl = false;
    let mut has_conn = false;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            if has_te || status_forbids_body {
                continue;
            }
            has_cl = true;
        }
        if k.eq_ignore_ascii_case("connection") {
            has_conn = true;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_cl && !has_te && !status_forbids_body {
        head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    if !has_conn {
        if close {
            head.push_str("Connection: close\r\n");
        } else {
            head.push_str("Connection: keep-alive\r\n");
        }
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes()).await?;
    if !no_body {
        if has_te_chunked {
            if !resp.body.is_empty() {
                let chunk_hdr = format!("{:x}\r\n", resp.body.len());
                sock.write_all(chunk_hdr.as_bytes()).await?;
                sock.write_all(&resp.body).await?;
                sock.write_all(b"\r\n").await?;
            }
            sock.write_all(b"0\r\n\r\n").await?;
        } else if !resp.body.is_empty() {
            sock.write_all(&resp.body).await?;
        }
    }
    sock.flush().await
}

fn default_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        308 => "Resume Incomplete",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        423 => "Locked",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}
