use crate::common::{self, FaultInjector, InjectedFault};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use md5::{Digest as _, Md5};
use rship_backends::azureblob::auth::sign_shared_key_request;
use rship_backends::azureblob::xml::parse_block_list;
use rship_backends::azureblob::{
    AZURE_MIN_BLOCK_BYTES, AzureAuth, AzureBlobBackend, AzureBlobConfig,
};
use rship_core::clock::SystemClock;
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

pub(crate) const TEST_ACCOUNT: &str = "rshiptestacct";
pub(crate) const TEST_SAS_TOKEN: &str = "sv=2023-11-03&ss=b&srt=co&sp=rwdlac&sig=valid-mock-sas";

#[derive(Clone, Default)]
pub(crate) struct MockBlob {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) etag: String,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) pending_copy_polls: usize,
    /// The blob's `Content-MD5` property (base64), if any. Put Blob stores the MD5 the service
    /// computes; Put Block List stores `x-ms-blob-content-md5` UNVALIDATED (or nothing);
    /// Copy Blob copies the source's property.
    pub(crate) content_md5: Option<String>,
    pub(crate) encoded_name: bool,
    pub(crate) resource_type: Option<String>,
    pub(crate) blob_type: Option<String>,
    pub(crate) access_tier: Option<String>,
    pub(crate) archive_status: Option<String>,
    pub(crate) copy_id: Option<String>,
    pub(crate) copy_status_override: Option<String>,
    pub(crate) copy_status_description: Option<String>,
    pub(crate) copy_terminal_status: Option<(String, Option<String>)>,
}

pub(crate) struct MockAzureState {
    pub(crate) base_url: String,
    pub(crate) account_key: Vec<u8>,
    pub(crate) next_etag: u64,
    pub(crate) next_copy_id: u64,
    pub(crate) blobs: BTreeMap<String, MockBlob>,
    pub(crate) uncommitted: HashMap<String, HashMap<String, Vec<u8>>>, // blob_name -> (block_id_b64 -> bytes)
    /// Committed block list of each block blob (`<Latest>` resolves uncommitted, then these).
    pub(crate) committed: HashMap<String, HashMap<String, Vec<u8>>>,
    pub(crate) put_block_list_calls: usize,
    pub(crate) copy_calls: usize,
    pub(crate) pending_polls_served: usize,
    pub(crate) fault_injector: FaultInjector,
    pub(crate) seen_put_blob_content_md5: Vec<String>,
    pub(crate) seen_put_block_content_md5: Vec<String>,
    pub(crate) seen_delete_snapshots: Vec<(String, Option<String>)>,
    pub(crate) aborted_copies: Vec<(String, String)>,
    pub(crate) blobs_with_snapshots: HashSet<String>,
    pub(crate) force_stuck_pending_copies: bool,
    pub(crate) copy_pending_polls_override: Option<(usize, String, Option<String>)>,
    pub(crate) page_size_override: Option<usize>,
    pub(crate) reject_plus_in_query: bool,
    pub(crate) corrupt_put_blob_md5_once: bool,
    pub(crate) corrupt_put_block_md5_once: bool,
    pub(crate) corrupt_get_body_once: bool,
}

impl MockAzureState {
    fn new(base_url: String, account_key: Vec<u8>) -> Self {
        Self {
            base_url,
            account_key,
            next_etag: 1,
            next_copy_id: 1,
            blobs: BTreeMap::new(),
            uncommitted: HashMap::new(),
            committed: HashMap::new(),
            put_block_list_calls: 0,
            copy_calls: 0,
            pending_polls_served: 0,
            fault_injector: FaultInjector::new(),
            seen_put_blob_content_md5: Vec::new(),
            seen_put_block_content_md5: Vec::new(),
            seen_delete_snapshots: Vec::new(),
            aborted_copies: Vec::new(),
            blobs_with_snapshots: HashSet::new(),
            force_stuck_pending_copies: false,
            copy_pending_polls_override: None,
            page_size_override: None,
            reject_plus_in_query: true,
            corrupt_put_blob_md5_once: false,
            corrupt_put_block_md5_once: false,
            corrupt_get_body_once: false,
        }
    }

    pub(crate) fn fault_injector(&self) -> FaultInjector {
        self.fault_injector.clone()
    }

    pub(crate) fn alloc_etag(&mut self) -> String {
        let e = format!("\"0x8DC{:08X}\"", self.next_etag);
        self.next_etag += 1;
        e
    }
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn parse_query(uri: &axum::http::Uri) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(pct_decode(k), pct_decode(v));
            }
        }
    }
    map
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn azure_err(status: StatusCode, code: &str, msg: &str) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>{code}</Code><Message>{msg}</Message></Error>"
    );
    (status, [("content-type", "application/xml")], xml).into_response()
}

#[allow(clippy::result_large_err)]
fn verify_auth(
    st: &MockAzureState,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Result<(), Response> {
    // Allow valid SAS query token
    let query = parse_query(uri);
    if query.get("sig").map(String::as_str) == Some("valid-mock-sas") {
        return Ok(());
    }
    // Otherwise cryptographically verify `Authorization: SharedKey ...`!
    let Some(got_auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Err(azure_err(
            StatusCode::FORBIDDEN,
            "AuthenticationFailed",
            "Missing Authorization header or SAS token",
        ));
    };
    let full_url = format!("{}{}", st.base_url, uri);
    let expected =
        sign_shared_key_request(method, &full_url, headers, TEST_ACCOUNT, &st.account_key)
            .map_err(|e| azure_err(StatusCode::INTERNAL_SERVER_ERROR, "SignErr", &e.to_string()))?;
    if got_auth != expected {
        return Err(azure_err(
            StatusCode::FORBIDDEN,
            "AuthenticationFailed",
            &format!("SharedKey signature mismatch: got `{got_auth}`, expected `{expected}`"),
        ));
    }
    Ok(())
}

fn extract_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        if let Some(mk) = lower.strip_prefix("x-ms-meta-")
            && let Ok(val) = v.to_str()
        {
            out.insert(mk.to_string(), val.trim().to_string());
        }
    }
    out
}

fn parse_put_block_list_ids(body: &[u8]) -> Vec<String> {
    let s = std::str::from_utf8(body).unwrap();
    let mut ids = Vec::new();
    let mut rest = s;
    while let Some(pos) = rest.find("<Latest>") {
        rest = &rest[pos + 8..];
        let end = rest.find("</Latest>").unwrap();
        ids.push(rest[..end].to_string());
        rest = &rest[end + 9..];
    }
    ids
}

fn classify_azure_op(
    method: &Method,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Option<&'static str> {
    if path == "/test-container"
        && *method == Method::GET
        && query.get("restype").map(String::as_str) == Some("container")
        && query.get("comp").map(String::as_str) == Some("list")
    {
        return Some("ListBlobs");
    }
    path.strip_prefix("/test-container/")?;
    let comp = query.get("comp").map(String::as_str);
    match (method, comp) {
        (&Method::PUT, Some("block")) => Some("PutBlock"),
        (&Method::GET, Some("blocklist")) => Some("GetBlockList"),
        (&Method::PUT, Some("blocklist")) => Some("PutBlockList"),
        (&Method::PUT, Some("copy")) => Some("AbortCopyBlob"),
        (&Method::PUT, None) => {
            if headers.contains_key("x-ms-copy-source") {
                Some("CopyBlob")
            } else {
                Some("PutBlob")
            }
        }
        (&Method::HEAD, None) => Some("HeadBlob"),
        (&Method::GET, None) => Some("GetBlob"),
        (&Method::DELETE, None) => Some("DeleteBlob"),
        _ => None,
    }
}

enum AzurePreFlight {
    Immediate(Response),
    Proceed {
        slow_delay: Option<Duration>,
        post_commit_fault: Option<InjectedFault>,
        query: HashMap<String, String>,
    },
}

fn preflight_azure_request(
    st: &Arc<Mutex<MockAzureState>>,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> AzurePreFlight {
    let query = parse_query(uri);
    let g = st.lock().unwrap();
    if g.reject_plus_in_query && uri.query().is_some_and(|q| q.contains('+')) {
        return AzurePreFlight::Immediate(azure_err(
            StatusCode::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "Raw '+' is not allowed in query strings; use RFC 3986 %20 or %2B",
        ));
    }
    if let Err(resp) = verify_auth(&g, method, uri, headers) {
        return AzurePreFlight::Immediate(resp);
    }

    let mut slow_delay = None;
    let mut post_commit_fault = None;
    if let Some(op) = classify_azure_op(method, uri.path(), &query, headers)
        && let Some(fault) = g.fault_injector.next_fault(op)
    {
        match fault {
            InjectedFault::SlowFinalize { delay } => slow_delay = Some(delay),
            InjectedFault::MidBodyReset { prefix } => {
                if op == "GetBlob" && headers.contains_key("range") {
                    return AzurePreFlight::Immediate(
                        common::build_mid_body_reset_response_with_status(
                            StatusCode::PARTIAL_CONTENT,
                            prefix,
                        ),
                    );
                }
                return AzurePreFlight::Immediate(common::build_mid_body_reset_response(prefix));
            }
            other => match other.into_pre_commit_response() {
                Ok(resp) => return AzurePreFlight::Immediate(resp),
                Err(post) => post_commit_fault = Some(post),
            },
        }
    }

    AzurePreFlight::Proceed {
        slow_delay,
        post_commit_fault,
        query,
    }
}

async fn handle_azure(
    State(st): State<Arc<Mutex<MockAzureState>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (slow_delay, post_commit_fault, query) =
        match preflight_azure_request(&st, &method, &uri, &headers) {
            AzurePreFlight::Immediate(resp) => return resp,
            AzurePreFlight::Proceed {
                slow_delay,
                post_commit_fault,
                query,
            } => (slow_delay, post_commit_fault, query),
        };

    // Request body has already been drained by the `Bytes` extractor; sleep with no mutex held.
    if let Some(delay) = slow_delay {
        tokio::time::sleep(delay).await;
    }

    execute_azure_request(&st, method, uri, headers, body, query, post_commit_fault)
}

fn check_write_preconditions(headers: &HeaderMap, existing: Option<&MockBlob>) -> Option<Response> {
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some("*") && existing.is_some()
    {
        return Some(azure_err(
            StatusCode::CONFLICT,
            "BlobAlreadyExists",
            "The specified blob already exists.",
        ));
    }
    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        let matched = existing.is_some_and(|b| if_match == "*" || b.etag == if_match);
        if !matched {
            return Some(azure_err(
                StatusCode::PRECONDITION_FAILED,
                "ConditionNotMet",
                "The condition specified using HTTP conditional header(s) is not met.",
            ));
        }
    }
    None
}

fn execute_azure_request(
    st: &Arc<Mutex<MockAzureState>>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
    query: HashMap<String, String>,
    post_commit_fault: Option<InjectedFault>,
) -> Response {
    let path = uri.path();

    // 1. Container listing (`GET /test-container?restype=container&comp=list`)
    if path == "/test-container"
        && method == Method::GET
        && query.get("restype").map(String::as_str) == Some("container")
        && query.get("comp").map(String::as_str) == Some("list")
    {
        let pfx = query.get("prefix").cloned().unwrap_or_default();
        let delim = query.get("delimiter").cloned();
        let max_res = query
            .get("maxresults")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5000);
        let start_idx = query
            .get("marker")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let g = st.lock().unwrap();
        let mut all_blobs = Vec::new();
        let mut prefixes = std::collections::BTreeSet::new();

        for blob in g.blobs.values() {
            if !blob.name.starts_with(&pfx) {
                continue;
            }
            let rest = &blob.name[pfx.len()..];
            if let Some(ref d) = delim
                && let Some(pos) = rest.find(d.as_str())
            {
                prefixes.insert(format!("{}{}", pfx, &rest[..=pos]));
                continue;
            }
            all_blobs.push(blob.clone());
        }

        let page_sz = g
            .page_size_override
            .unwrap_or(if max_res == 1 { 1 } else { 2 });
        let end = (start_idx + page_sz).min(all_blobs.len());
        let slice = if start_idx < all_blobs.len() {
            &all_blobs[start_idx..end]
        } else {
            &[]
        };

        let mut xml =
            String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults><Blobs>");
        for b in slice {
            if b.encoded_name {
                xml.push_str("<Blob><Name Encoded=\"true\">");
                xml.push_str(&escape_xml(
                    &rship_backends::azureblob::azure_encode_blob_path(&b.name),
                ));
                xml.push_str("</Name><Properties>");
            } else {
                xml.push_str("<Blob><Name>");
                xml.push_str(&escape_xml(&b.name));
                xml.push_str("</Name><Properties>");
            }
            xml.push_str("<Last-Modified>Wed, 25 Nov 2026 02:00:00 GMT</Last-Modified>");
            xml.push_str(&format!("<Etag>{}</Etag>", escape_xml(&b.etag)));
            xml.push_str(&format!(
                "<Content-Length>{}</Content-Length>",
                b.data.len()
            ));
            if let Some(md5_b64) = &b.content_md5 {
                xml.push_str(&format!("<Content-MD5>{md5_b64}</Content-MD5>"));
            }
            if let Some(rt) = &b.resource_type {
                xml.push_str(&format!("<ResourceType>{}</ResourceType>", escape_xml(rt)));
            }
            if let Some(bt) = &b.blob_type {
                xml.push_str(&format!("<BlobType>{}</BlobType>", escape_xml(bt)));
            }
            if let Some(tier) = &b.access_tier {
                xml.push_str(&format!("<AccessTier>{}</AccessTier>", escape_xml(tier)));
            }
            if let Some(arch) = &b.archive_status {
                xml.push_str(&format!(
                    "<ArchiveStatus>{}</ArchiveStatus>",
                    escape_xml(arch)
                ));
            }
            xml.push_str("</Properties><Metadata>");
            for (mk, mv) in &b.metadata {
                xml.push_str(&format!("<{mk}>{}</{mk}>", escape_xml(mv)));
            }
            xml.push_str("</Metadata></Blob>");
        }
        if start_idx == 0 {
            for p in prefixes {
                xml.push_str(&format!(
                    "<BlobPrefix><Name>{}</Name></BlobPrefix>",
                    escape_xml(&p)
                ));
            }
        }
        xml.push_str("</Blobs>");
        if end < all_blobs.len() {
            xml.push_str(&format!("<NextMarker>{end}</NextMarker>"));
        }
        xml.push_str("</EnumerationResults>");
        if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response) {
            return resp;
        }
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    // 2. Blob endpoints (`/test-container/{blob_path}`)
    let Some(raw_blob_path) = path.strip_prefix("/test-container/") else {
        return azure_err(
            StatusCode::NOT_FOUND,
            "ContainerNotFound",
            "unknown container",
        );
    };
    let blob_name = raw_blob_path
        .split('/')
        .map(pct_decode)
        .collect::<Vec<_>>()
        .join("/");

    let comp = query.get("comp").map(String::as_str);
    let mut g = st.lock().unwrap();

    match (method, comp) {
        (Method::PUT, Some("block")) => {
            let block_id = query.get("blockid").cloned().unwrap();
            let decoded = B64.decode(&block_id).expect("valid base64 blockid");
            if let Some(req_md5) = headers.get("content-md5").and_then(|v| v.to_str().ok()) {
                let actual_md5 = B64.encode(Md5::digest(&body));
                if req_md5.trim() != actual_md5 {
                    return azure_err(
                        StatusCode::BAD_REQUEST,
                        "Md5Mismatch",
                        "The MD5 value specified in the request did not match with the MD5 value calculated by the server.",
                    );
                }
                g.seen_put_block_content_md5
                    .push(req_md5.trim().to_string());
            }
            let map = g.uncommitted.entry(blob_name).or_default();
            // Enforce Azure's equal block ID length constraint!
            if let Some(first_id) = map.keys().next() {
                let first_len = B64.decode(first_id).unwrap().len();
                if first_len != decoded.len() {
                    return azure_err(
                        StatusCode::BAD_REQUEST,
                        "InvalidBlockId",
                        "block ID lengths must be equal",
                    );
                }
            }
            map.insert(block_id, body.to_vec());
            let req_had_md5 = headers.contains_key("content-md5");
            let corrupt = if g.corrupt_put_block_md5_once {
                g.corrupt_put_block_md5_once = false;
                true
            } else {
                false
            };
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            if req_had_md5 {
                let md5_b64 = if corrupt {
                    B64.encode([0xAAu8; 16])
                } else {
                    B64.encode(Md5::digest(&body))
                };
                (
                    StatusCode::CREATED,
                    [("content-md5", md5_b64)],
                    Vec::<u8>::new(),
                )
                    .into_response()
            } else {
                // Azure API 2019-02-02+ omits Content-MD5 unless request sent Content-MD5.
                (
                    StatusCode::CREATED,
                    [("x-ms-content-crc64", "AAAAAAAAAAA=")],
                    Vec::<u8>::new(),
                )
                    .into_response()
            }
        }
        (Method::GET, Some("blocklist")) => {
            let map = g.uncommitted.get(&blob_name);
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><UncommittedBlocks>",
            );
            if let Some(m) = map {
                for (id, bytes) in m {
                    xml.push_str(&format!(
                        "<Block><Name>{}</Name><Size>{}</Size></Block>",
                        escape_xml(id),
                        bytes.len()
                    ));
                }
            }
            xml.push_str("</UncommittedBlocks></BlockList>");
            // Sanity-check our own XML with parse_block_list
            let _ = parse_block_list(xml.as_bytes()).unwrap();
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        (Method::PUT, Some("blocklist")) => {
            g.put_block_list_calls += 1;
            if let Some(resp) = check_write_preconditions(&headers, g.blobs.get(&blob_name)) {
                return resp;
            }
            // `<Latest>` resolves the uncommitted list first, then the committed one, so a
            // replayed Put Block List re-commits the same blocks.
            // https://learn.microsoft.com/rest/api/storageservices/put-block-list
            let ids = parse_put_block_list_ids(&body);
            let staged = g.uncommitted.get(&blob_name).cloned().unwrap_or_default();
            let committed = g.committed.get(&blob_name).cloned().unwrap_or_default();
            let mut assembled = Vec::new();
            let mut new_committed = HashMap::new();
            for id in ids {
                let Some(blk) = staged.get(&id).or_else(|| committed.get(&id)) else {
                    return azure_err(
                        StatusCode::BAD_REQUEST,
                        "InvalidBlockList",
                        "The specified block list is invalid.",
                    );
                };
                assembled.extend_from_slice(blk);
                new_committed.insert(id, blk.clone());
            }
            g.uncommitted.remove(&blob_name);
            g.committed.insert(blob_name.clone(), new_committed);
            let etag = g.alloc_etag();
            // The response `Content-MD5` is the MD5 of the REQUEST BODY (the block list XML),
            // not of the blob. The blob's own Content-MD5 property is whatever the client sent
            // in `x-ms-blob-content-md5`, NOT validated by the service.
            let md5_b64 = B64.encode(Md5::digest(&body));
            let content_md5 = headers
                .get("x-ms-blob-content-md5")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let access_tier = headers
                .get("x-ms-access-tier")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string());
            let metadata = extract_metadata(&headers);
            g.blobs.insert(
                blob_name.clone(),
                MockBlob {
                    name: blob_name,
                    data: assembled,
                    etag: etag.clone(),
                    metadata,
                    content_md5,
                    access_tier,
                    blob_type: Some("BlockBlob".to_string()),
                    ..Default::default()
                },
            );
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            (
                StatusCode::CREATED,
                [("etag", etag), ("content-md5", md5_b64)],
                Vec::<u8>::new(),
            )
                .into_response()
        }
        (Method::PUT, Some("copy")) => {
            if headers
                .get("x-ms-copy-action")
                .and_then(|v| v.to_str().ok())
                == Some("abort")
            {
                let copy_id = query.get("copyid").cloned().unwrap_or_default();
                g.aborted_copies.push((blob_name.clone(), copy_id));
                if let Some(blob) = g.blobs.get_mut(&blob_name) {
                    blob.pending_copy_polls = 0;
                    blob.copy_status_override = Some("aborted".to_string());
                }
                return StatusCode::NO_CONTENT.into_response();
            }
            azure_err(StatusCode::BAD_REQUEST, "InvalidOperation", "bad copy comp")
        }
        (Method::PUT, None) => {
            // Check server-side `x-ms-copy-source` first!
            if let Some(copy_src) = headers
                .get("x-ms-copy-source")
                .and_then(|v| v.to_str().ok())
            {
                g.copy_calls += 1;
                let parsed = url::Url::parse(copy_src).unwrap();
                let Some(src_raw) = parsed.path().strip_prefix("/test-container/") else {
                    return azure_err(
                        StatusCode::FORBIDDEN,
                        "CannotVerifyCopySource",
                        "cross-container copy unauthorized",
                    );
                };
                let src_name = src_raw
                    .split('/')
                    .map(pct_decode)
                    .collect::<Vec<_>>()
                    .join("/");
                let Some(src_blob) = g.blobs.get(&src_name).cloned() else {
                    return azure_err(
                        StatusCode::NOT_FOUND,
                        "CannotVerifyCopySource",
                        "src missing",
                    );
                };
                if let Some(src_if_match) = headers
                    .get("x-ms-source-if-match")
                    .and_then(|v| v.to_str().ok())
                    && src_blob.etag != src_if_match
                {
                    return azure_err(
                        StatusCode::PRECONDITION_FAILED,
                        "SourceConditionNotMet",
                        "The source condition specified using HTTP conditional header(s) is not met.",
                    );
                }
                if let Some(resp) = check_write_preconditions(&headers, g.blobs.get(&blob_name)) {
                    return resp;
                }
                let etag = g.alloc_etag();
                let copy_id = format!("copy-{}", g.next_copy_id);
                g.next_copy_id += 1;
                let metadata = extract_metadata(&headers);
                let access_tier = headers
                    .get("x-ms-access-tier")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().to_string())
                    .or_else(|| src_blob.access_tier.clone());
                let src_committed = g.committed.get(&src_name).cloned();
                match src_committed {
                    Some(c) => g.committed.insert(blob_name.clone(), c),
                    None => g.committed.remove(&blob_name),
                };
                let (pending_polls, copy_terminal_status) = if g.force_stuck_pending_copies {
                    (usize::MAX, None)
                } else if let Some((polls, ref st, ref desc)) = g.copy_pending_polls_override {
                    (polls, Some((st.clone(), desc.clone())))
                } else {
                    (1, None)
                };
                g.blobs.insert(
                    blob_name.clone(),
                    MockBlob {
                        name: blob_name,
                        data: src_blob.data,
                        etag: etag.clone(),
                        metadata,
                        pending_copy_polls: pending_polls, // Force async pending->success polling!
                        content_md5: src_blob.content_md5,
                        access_tier,
                        blob_type: Some("BlockBlob".to_string()),
                        copy_id: Some(copy_id.clone()),
                        copy_terminal_status,
                        ..Default::default()
                    },
                );
                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }
                return (
                    StatusCode::ACCEPTED,
                    [
                        ("etag", etag),
                        ("x-ms-copy-status", "pending".to_string()),
                        ("x-ms-copy-id", copy_id),
                    ],
                    Vec::<u8>::new(),
                )
                    .into_response();
            }

            if let Some(resp) = check_write_preconditions(&headers, g.blobs.get(&blob_name)) {
                return resp;
            }
            if let Some(cm) = headers
                .get("content-md5")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                g.seen_put_blob_content_md5.push(cm);
            }
            let etag = g.alloc_etag();
            let md5_b64 = if g.corrupt_put_blob_md5_once {
                g.corrupt_put_blob_md5_once = false;
                B64.encode([0xBBu8; 16])
            } else {
                B64.encode(Md5::digest(&body))
            };
            let metadata = extract_metadata(&headers);
            let access_tier = headers
                .get("x-ms-access-tier")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string());
            g.committed.remove(&blob_name);
            g.blobs.insert(
                blob_name.clone(),
                MockBlob {
                    name: blob_name,
                    data: body.to_vec(),
                    etag: etag.clone(),
                    metadata,
                    // Put Blob stores the MD5 the service computed for the body.
                    content_md5: Some(B64.encode(Md5::digest(&body))),
                    access_tier,
                    blob_type: Some("BlockBlob".to_string()),
                    ..Default::default()
                },
            );
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            (
                StatusCode::CREATED,
                [("etag", etag), ("content-md5", md5_b64)],
                Vec::<u8>::new(),
            )
                .into_response()
        }
        (Method::HEAD, None) => {
            let Some(blob) = g.blobs.get_mut(&blob_name) else {
                return azure_err(StatusCode::NOT_FOUND, "BlobNotFound", "not found");
            };
            let copy_status = if let Some(ref ov) = blob.copy_status_override {
                ov.clone()
            } else if blob.pending_copy_polls > 0 {
                blob.pending_copy_polls -= 1;
                g.pending_polls_served += 1;
                "pending".to_string()
            } else if let Some((ref term_status, ref term_desc)) = blob.copy_terminal_status {
                if let Some(d) = term_desc {
                    blob.copy_status_description = Some(d.clone());
                }
                term_status.clone()
            } else {
                "success".to_string()
            };
            let blob = g.blobs.get(&blob_name).unwrap();
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header("content-length", blob.data.len().to_string())
                .header("etag", &blob.etag)
                .header("last-modified", "Wed, 25 Nov 2026 02:00:00 GMT")
                .header("x-ms-copy-status", copy_status);
            if let Some(cid) = &blob.copy_id {
                resp = resp.header("x-ms-copy-id", cid);
            }
            if let Some(desc) = &blob.copy_status_description {
                resp = resp.header("x-ms-copy-status-description", desc);
            }
            if let Some(tier) = &blob.access_tier {
                resp = resp.header("x-ms-access-tier", tier);
            }
            if let Some(arch) = &blob.archive_status {
                resp = resp.header("x-ms-archive-status", arch);
            }
            if let Some(rt) = &blob.resource_type {
                resp = resp.header("x-ms-resource-type", rt);
            }
            if let Some(md5_b64) = &blob.content_md5 {
                resp = resp.header("content-md5", md5_b64);
            }
            for (mk, mv) in &blob.metadata {
                resp = resp.header(format!("x-ms-meta-{mk}"), mv);
            }
            resp.body(axum::body::Body::empty()).unwrap()
        }
        (Method::GET, None) => {
            let corrupt_body = if g.corrupt_get_body_once {
                g.corrupt_get_body_once = false;
                true
            } else {
                false
            };
            let Some(blob) = g.blobs.get(&blob_name) else {
                return azure_err(StatusCode::NOT_FOUND, "BlobNotFound", "not found");
            };
            if blob
                .access_tier
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("Archive"))
            {
                return azure_err(
                    StatusCode::CONFLICT,
                    "BlobArchived",
                    "This operation is not permitted on an archived blob.",
                );
            }
            if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok())
                && if_match != blob.etag
            {
                return azure_err(
                    StatusCode::PRECONDITION_FAILED,
                    "ConditionNotMet",
                    "etag changed",
                );
            }
            if let Some(resp) = post_commit_fault.and_then(InjectedFault::into_post_commit_response)
            {
                return resp;
            }
            let md5_hdr: Vec<(&str, String)> = blob
                .content_md5
                .iter()
                .map(|m| ("content-md5", m.clone()))
                .collect();
            if let Some(range_hdr) = headers.get("range").and_then(|v| v.to_str().ok())
                && let Some(spec) = range_hdr.strip_prefix("bytes=")
                && let Some((s, e)) = spec.split_once('-')
            {
                let start: usize = s.parse().unwrap_or(0);
                let end: usize = e.parse().unwrap_or(blob.data.len().saturating_sub(1));
                let mut slice = blob.data[start..=end.min(blob.data.len() - 1)].to_vec();
                if corrupt_body && let Some(last) = slice.last_mut() {
                    *last ^= 0xFF;
                }
                let mut resp = Response::builder().status(StatusCode::PARTIAL_CONTENT);
                for (k, v) in &md5_hdr {
                    resp = resp.header(*k, v);
                }
                return resp.body(axum::body::Body::from(slice)).unwrap();
            }
            let mut full = blob.data.clone();
            if corrupt_body && let Some(last) = full.last_mut() {
                *last ^= 0xFF;
            }
            let mut resp = Response::builder().status(StatusCode::OK);
            for (k, v) in &md5_hdr {
                resp = resp.header(*k, v);
            }
            resp.body(axum::body::Body::from(full)).unwrap()
        }
        (Method::DELETE, None) => {
            let del_snap = headers
                .get("x-ms-delete-snapshots")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string());
            g.seen_delete_snapshots
                .push((blob_name.clone(), del_snap.clone()));
            if g.blobs_with_snapshots.contains(&blob_name) && del_snap.as_deref() != Some("include")
            {
                return azure_err(
                    StatusCode::CONFLICT,
                    "SnapshotsPresent",
                    "This operation is not permitted because the blob has snapshots.",
                );
            }
            if g.blobs.remove(&blob_name).is_some() {
                g.blobs_with_snapshots.remove(&blob_name);
                if let Some(resp) =
                    post_commit_fault.and_then(InjectedFault::into_post_commit_response)
                {
                    return resp;
                }
                StatusCode::ACCEPTED.into_response()
            } else {
                azure_err(StatusCode::NOT_FOUND, "BlobNotFound", "not found")
            }
        }
        _ => azure_err(StatusCode::BAD_REQUEST, "InvalidOperation", "unsupported"),
    }
}

pub(crate) async fn spawn_mock_azure() -> (String, String, Arc<Mutex<MockAzureState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let raw_key = vec![0x33u8; 64];
    let key_b64 = B64.encode(&raw_key);
    let state = Arc::new(Mutex::new(MockAzureState::new(base_url.clone(), raw_key)));
    let app = Router::new()
        .fallback(handle_azure)
        .with_state(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, key_b64, state)
}

pub(crate) fn make_backend(base_url: &str, auth: AzureAuth) -> Arc<AzureBlobBackend> {
    let mut cfg = AzureBlobConfig::new("azure-test", TEST_ACCOUNT, "test-container");
    cfg.endpoint = Some(base_url.to_string());
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    Arc::new(AzureBlobBackend::new(cfg, auth, transport, Some(SystemClock::shared())).unwrap())
}
