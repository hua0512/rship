//! Production constant-memory Microsoft OneDrive / SharePoint [`StorageBackend`]
//! on Microsoft Graph API v1.0.

mod ops;
mod transfer;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, NodeId,
    StorageQuota, UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter, parse_retry_after};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::common::http::{
    Idempotency, PolicyDecision, ReconcileAction, RetryPolicyConfig, bearer_header_value,
    execute_with_auth_policy, execute_with_policy_full, percent_encode_segment,
    policy_decision_from_http,
};
use crate::onedrive::auth::OnedriveAuthProvider;
use crate::onedrive::config::{
    MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveConfig,
};

pub use transfer::parse_expected_range_start;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    e_tag: Option<String>,
    #[serde(default)]
    last_modified_date_time: Option<String>,
    #[serde(default)]
    file_system_info: Option<GraphFsInfo>,
    #[serde(default)]
    folder: Option<serde_json::Value>,
    #[serde(default)]
    file: Option<GraphFileFacet>,
    #[serde(default)]
    package: Option<serde_json::Value>,
    #[serde(default)]
    remote_item: Option<Box<GraphItem>>,
    #[serde(default)]
    parent_reference: Option<GraphParentRef>,
    #[serde(rename = "@microsoft.graph.downloadUrl", default)]
    download_url: Option<String>,
}

impl GraphItem {
    fn effective(&self) -> &GraphItem {
        self.remote_item.as_deref().unwrap_or(self)
    }

    fn is_package(&self) -> bool {
        self.package.is_some()
            || self
                .remote_item
                .as_deref()
                .is_some_and(|r| r.package.is_some())
    }

    fn is_folder(&self) -> bool {
        !self.is_package() && self.effective().folder.is_some()
    }

    /// Resolve `(drive_id, item_id)` for Graph item/children/content URLs.
    fn remote_target(&self) -> (Option<&str>, &str) {
        if let Some(remote) = self.remote_item.as_deref() {
            let drive_id = remote
                .parent_reference
                .as_ref()
                .and_then(|p| p.drive_id.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let id = if !remote.id.is_empty() {
                remote.id.as_str()
            } else {
                self.id.as_str()
            };
            (drive_id, id)
        } else {
            let drive_id = self
                .parent_reference
                .as_ref()
                .and_then(|p| p.drive_id.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            (drive_id, self.id.as_str())
        }
    }
}

/// Unambiguous prefix for cross-drive `NodeId` values (`rship-drive:{drive_id}/{item_id}`).
/// OneDrive Personal item IDs commonly contain `!` (e.g. `1234567890ABCDEF!101`), so `!`
/// must never be used as a separator.
const REMOTE_NODE_PREFIX: &str = "rship-drive:";

pub(super) fn encode_node_id(drive_id: Option<&str>, item_id: &str) -> Option<NodeId> {
    let id = item_id.trim();
    if id.is_empty() {
        return None;
    }
    match drive_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(did) => Some(NodeId(format!("{REMOTE_NODE_PREFIX}{did}/{id}"))),
        None => Some(NodeId(id.to_string())),
    }
}

pub(super) fn decode_node_id(raw: &str) -> (Option<&str>, &str) {
    if let Some(rest) = raw.strip_prefix(REMOTE_NODE_PREFIX)
        && let Some((did, iid)) = rest.split_once('/')
        && !did.is_empty()
        && !iid.is_empty()
    {
        return (Some(did), iid);
    }
    (None, raw)
}

/// A Graph commit's reply, or the item a reconcile proved to be its result.
enum GraphOutcome {
    Response(StatusCode, HeaderMap, Bytes),
    Item(Box<GraphItem>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphFsInfo {
    last_modified_date_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphFileFacet {
    hashes: Option<GraphHashes>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphHashes {
    sha256_hash: Option<String>,
    sha1_hash: Option<String>,
    /// Base64 QuickXorHash. Unlike `sha1Hash`/`sha256Hash`, which OneDrive for Business and
    /// SharePoint never return and OneDrive Personal is phasing out, this is present on every
    /// drive type. There is no `HashKind` for it, so it is verified inside this backend
    /// (uploads and full downloads) and never surfaced in `Entry::checksum`.
    #[serde(default)]
    quick_xor_hash: Option<String>,
}

impl GraphHashes {
    fn normalize_hex(raw: Option<&str>) -> Option<String> {
        raw.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
    }

    /// `sha256Hash` as lowercase hex, if present.
    fn sha256_hex(&self) -> Option<String> {
        Self::normalize_hex(self.sha256_hash.as_deref())
    }

    /// `sha1Hash` as lowercase hex, if present.
    fn sha1_hex(&self) -> Option<String> {
        Self::normalize_hex(self.sha1_hash.as_deref())
    }

    /// `quickXorHash` decoded to lowercase hex, if present and well-formed.
    fn quickxor_hex(&self) -> Option<String> {
        self.quick_xor_hash
            .as_deref()
            .and_then(crate::onedrive::quickxor::quickxor_base64_to_hex)
    }

    /// Preferred [`Checksum`] exposed on [`Entry`] (`sha256Hash` over `sha1Hash`).
    fn preferred_entry_checksum(&self) -> Option<Checksum> {
        self.sha256_hex()
            .map(|hex| Checksum {
                kind: HashKind::Sha256,
                hex,
            })
            .or_else(|| {
                self.sha1_hex().map(|hex| Checksum {
                    kind: HashKind::Sha1,
                    hex,
                })
            })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphParentRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    drive_id: Option<String>,
}

struct OnedriveInner {
    cfg: OnedriveConfig,
    drive_base: String,
    resolved_drive_id: tokio::sync::OnceCell<String>,
    auth: Arc<dyn OnedriveAuthProvider>,
    transport: HttpTransport,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    mkdir_lock: Mutex<()>,
    /// Running QuickXorHash of every upload session this process opened, keyed by
    /// `op_id`. See [`transfer::SessionQuickXorMap`].
    session_quickxor: transfer::SessionQuickXorMap,
}

#[derive(Clone)]
pub struct OnedriveBackend {
    inner: Arc<OnedriveInner>,
}

impl OnedriveBackend {
    pub fn new(
        cfg: OnedriveConfig,
        auth: Arc<dyn OnedriveAuthProvider>,
        transport: HttpTransport,
    ) -> Result<Self> {
        let cfg = cfg.with_resolved_region_endpoints();
        let drive_base = cfg.drive_base_url();
        let scope = LimiterScope::new(&cfg.remote_name, auth.principal());
        let rate_cfg = transport.config().default_rate_limit.clone();
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), rate_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, rate_cfg);
        Ok(Self {
            inner: Arc::new(OnedriveInner {
                cfg,
                drive_base,
                resolved_drive_id: tokio::sync::OnceCell::new(),
                auth,
                transport,
                control_limiter,
                data_limiter,
                mkdir_lock: Mutex::new(()),
                session_quickxor: transfer::SessionQuickXorMap::default(),
            }),
        })
    }

    pub fn control_limiter(&self) -> &Arc<ScopedLimiter> {
        &self.inner.control_limiter
    }

    pub fn data_limiter(&self) -> &Arc<ScopedLimiter> {
        &self.inner.data_limiter
    }

    /// Build a sensitive `Authorization: Bearer <token>` header value (`is_sensitive() == true`).
    pub fn bearer_header(token: &str) -> Result<HeaderValue> {
        bearer_header_value(token)
    }

    fn retry_policy_config(&self, request_timeout: Option<Duration>) -> RetryPolicyConfig {
        let mut cfg = self.inner.cfg.retry_policy();
        if let Some(timeout) = request_timeout {
            cfg = cfg.with_request_timeout(timeout);
        }
        cfg
    }

    fn build_graph_request(
        &self,
        method: Method,
        url: &str,
        token: &str,
        body_bytes: Option<Bytes>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, Self::bearer_header(token)?);
        let mut req = self.inner.transport.control_client().request(method, url);
        if let Some(payload) = body_bytes {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            req = req.body(payload);
        }
        Ok(req.headers(headers))
    }

    fn build_single_shot_request(
        &self,
        url: &str,
        token: &str,
        total_size: u64,
    ) -> Result<reqwest::RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, Self::bearer_header(token)?);
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&total_size.to_string())
                .map_err(|e| Error::protocol(format!("Content-Length: {e}")))?,
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        Ok(self.inner.transport.data_client().put(url).headers(headers))
    }

    fn build_range_request(
        &self,
        url: &str,
        token: Option<&str>,
        start: u64,
        end_inclusive: u64,
    ) -> Result<reqwest::RequestBuilder> {
        let mut headers = HeaderMap::new();
        if let Some(tok) = token {
            headers.insert(http::header::AUTHORIZATION, Self::bearer_header(tok)?);
        }
        headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={start}-{end_inclusive}"))
                .map_err(|e| Error::protocol(format!("Range header: {e}")))?,
        );
        Ok(self.inner.transport.data_client().get(url).headers(headers))
    }

    fn raw_item_path_url(&self, raw_rel: &str, suffix: &str) -> String {
        if raw_rel.is_empty() {
            if suffix.is_empty() {
                format!("{}/root", self.inner.drive_base)
            } else {
                format!(
                    "{}/root/{}",
                    self.inner.drive_base,
                    suffix.trim_start_matches('/')
                )
            }
        } else {
            let enc = encode_graph_path(raw_rel);
            if suffix.is_empty() {
                format!("{}/root:/{enc}:", self.inner.drive_base)
            } else {
                format!(
                    "{}/root:/{enc}:/{}",
                    self.inner.drive_base,
                    suffix.trim_start_matches('/')
                )
            }
        }
    }

    fn item_path_url(&self, rel: &RelPath, suffix: &str) -> String {
        self.raw_item_path_url(rel.as_str(), suffix)
    }

    fn drive_item_url(&self, drive_id: Option<&str>, item_id: &str, suffix: &str) -> String {
        let enc_id = percent_encode_segment(item_id);
        let base = match drive_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(did) => format!(
                "{}/drives/{}/items/{enc_id}",
                self.inner.cfg.api_base_url.trim_end_matches('/'),
                percent_encode_segment(did),
            ),
            None => format!("{}/items/{enc_id}", self.inner.drive_base),
        };
        let sfx = suffix.trim_start_matches('/');
        if sfx.is_empty() {
            base
        } else {
            format!("{base}/{sfx}")
        }
    }

    fn drive_item_child_path_url(
        &self,
        drive_id: Option<&str>,
        parent_id: &str,
        child_path: &str,
        suffix: &str,
    ) -> String {
        let item_base = self.drive_item_url(drive_id, parent_id, "");
        let enc_child = encode_graph_path(child_path);
        let sfx = suffix.trim_start_matches('/');
        if sfx.is_empty() {
            format!("{item_base}:/{enc_child}:")
        } else {
            format!("{item_base}:/{enc_child}:/{sfx}")
        }
    }

    /// Return `Some(drive_id)` when `candidate` is non-empty and refers to a drive other
    /// than this backend's own drive.
    async fn external_drive_id(&self, candidate: Option<&str>) -> Result<Option<String>> {
        let Some(did) = candidate.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        if let Some(cfg_did) = self
            .inner
            .cfg
            .drive_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok((did != cfg_did).then(|| did.to_string()));
        }
        let own = self.resolve_drive_id().await?;
        Ok((did != own).then(|| did.to_string()))
    }

    async fn graph_request(
        &self,
        context: &str,
        method: Method,
        url: &str,
        json_body: Option<&serde_json::Value>,
        allow_404: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        self.graph_request_with_timeout(context, method, url, json_body, allow_404, None)
            .await
    }

    async fn graph_request_with_timeout(
        &self,
        context: &str,
        method: Method,
        url: &str,
        json_body: Option<&serde_json::Value>,
        allow_404: bool,
        request_timeout: Option<Duration>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let body_bytes = match json_body {
            Some(v) => {
                Some(Bytes::from(serde_json::to_vec(v).map_err(|e| {
                    Error::protocol(format!("encode Graph JSON: {e}"))
                })?))
            }
            None => None,
        };
        let policy_cfg = self.retry_policy_config(request_timeout);

        execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            Idempotency::Idempotent,
            || {
                let method = method.clone();
                let url = url.to_string();
                let body_bytes = body_bytes.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let req = self.build_graph_request(method, &url, &token, body_bytes)?;
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                policy_decision_from_http(resp, allow_404, true, |status, headers, body| {
                    classify_graph_status(context, status, headers, body, false)
                })
            },
        )
        .await
    }

    /// Run a NON-idempotent Graph commit (`conflictBehavior=fail` copy / createFolder).
    /// Ambiguous failures and the `409 nameAlreadyExists` a replay gets after a lost
    /// response go through `reconcile`, which must prove the item is this commit's result.
    async fn graph_commit<RecFn, RecFut>(
        &self,
        context: &str,
        url: &str,
        json_body: &serde_json::Value,
        request_timeout: Option<Duration>,
        reconcile: RecFn,
    ) -> Result<GraphOutcome>
    where
        RecFn: FnMut(Error) -> RecFut,
        RecFut: std::future::Future<Output = Result<ReconcileAction<GraphOutcome>>>,
    {
        let body_bytes = Bytes::from(
            serde_json::to_vec(json_body)
                .map_err(|e| Error::protocol(format!("encode Graph JSON: {e}")))?,
        );
        let policy_cfg = self.retry_policy_config(request_timeout);
        execute_with_policy_full(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &policy_cfg,
            Idempotency::NonIdempotent,
            || {
                let body_bytes = body_bytes.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let req =
                        self.build_graph_request(Method::POST, url, &token, Some(body_bytes))?;
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                if resp.status.is_success() {
                    return PolicyDecision::Ok(GraphOutcome::Response(
                        resp.status,
                        resp.headers,
                        resp.body,
                    ));
                }
                if resp.status == StatusCode::CONFLICT {
                    let err = classify_graph_status(
                        context,
                        resp.status,
                        &resp.headers,
                        &resp.body,
                        false,
                    );
                    return PolicyDecision::Reconcile(err);
                }
                graph_error_decision(context, resp.status, &resp.headers, &resp.body, false)
            },
            reconcile,
        )
        .await
    }

    fn item_to_entry(
        &self,
        item: &GraphItem,
        raw_path: impl AsRef<str>,
        nfc_path: RelPath,
        remote_drive_id: Option<&str>,
    ) -> Entry {
        let eff = item.effective();
        let is_dir = item.is_folder();
        let mtime_str = eff
            .file_system_info
            .as_ref()
            .and_then(|fs| fs.last_modified_date_time.as_deref())
            .or(eff.last_modified_date_time.as_deref())
            .or_else(|| {
                item.file_system_info
                    .as_ref()
                    .and_then(|fs| fs.last_modified_date_time.as_deref())
            })
            .or(item.last_modified_date_time.as_deref());
        let mtime_ns = mtime_str
            .and_then(rship_core::time::parse_rfc3339_to_nanos)
            .unwrap_or(0);
        let checksum = eff
            .file
            .as_ref()
            .and_then(|f| f.hashes.as_ref())
            .and_then(GraphHashes::preferred_entry_checksum);
        let node_id = if item.remote_item.is_some() {
            if !item.id.is_empty() {
                encode_node_id(remote_drive_id, &item.id)
            } else {
                let (eff_did, eff_id) = item.remote_target();
                encode_node_id(eff_did.or(remote_drive_id), eff_id)
            }
        } else {
            encode_node_id(remote_drive_id, &item.id)
        };
        Entry {
            node_id,
            parent_id: item
                .parent_reference
                .as_ref()
                .and_then(|p| p.id.as_deref())
                .and_then(|pid| encode_node_id(remote_drive_id, pid)),
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
            nfc_path,
            kind: if is_dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            size: if is_dir { 0 } else { eff.size },
            mtime_ns,
            ctime_ns: None,
            etag: eff.e_tag.clone().or_else(|| item.e_tag.clone()),
            checksum,
        }
    }

    async fn find_child_in_drive_folder(
        &self,
        drive_id: Option<&str>,
        parent_id: &str,
        segment: &str,
    ) -> Result<Option<GraphItem>> {
        let seg_nfc = RelPath::parse(segment).ok();
        let mut next_url = Some(format!(
            "{}?$top=999",
            self.drive_item_url(drive_id, parent_id, "children")
        ));
        while let Some(url) = next_url.take() {
            let (status, _, body) = self
                .graph_request("list(children)", Method::GET, &url, None, true)
                .await?;
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let page: ops::GraphChildrenPage = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode children page: {e}")))?;
            next_url = page.next_link;
            for item in page.value {
                if item.is_package() {
                    continue;
                }
                let item_name = if !item.name.is_empty() {
                    item.name.as_str()
                } else {
                    item.effective().name.as_str()
                };
                if item_name == segment
                    || (seg_nfc.is_some() && RelPath::parse(item_name).ok() == seg_nfc)
                {
                    return Ok(Some(item));
                }
            }
        }
        Ok(None)
    }

    async fn stat_through_remote_mount(
        &self,
        raw_path: &str,
    ) -> Result<Option<(GraphItem, Option<String>)>> {
        let segs: Vec<&str> = raw_path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() < 2 {
            return Ok(None);
        }
        let mut prefix_raw = String::new();
        for i in 0..(segs.len() - 1) {
            if !prefix_raw.is_empty() {
                prefix_raw.push('/');
            }
            prefix_raw.push_str(segs[i]);
            let url = self.raw_item_path_url(&prefix_raw, "");
            let (status, _, body) = self
                .graph_request("stat", Method::GET, &url, None, true)
                .await?;
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let item: GraphItem = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode GraphItem: {e}")))?;
            if item.remote_item.is_some() {
                let (did_opt, rid) = item.remote_target();
                if rid.is_empty() {
                    return Ok(None);
                }
                let mut cur_drive_id = self.external_drive_id(did_opt).await?;
                let mut cur_item_id = rid.to_string();
                let remaining = &segs[i + 1..];
                if let Some(ref did) = cur_drive_id {
                    let rest_path = remaining.join("/");
                    let direct_url = self.drive_item_child_path_url(
                        Some(did.as_str()),
                        &cur_item_id,
                        &rest_path,
                        "",
                    );
                    let (dstatus, _, dbody) = self
                        .graph_request("stat", Method::GET, &direct_url, None, true)
                        .await?;
                    if dstatus != StatusCode::NOT_FOUND {
                        let found: GraphItem = serde_json::from_slice(&dbody)
                            .map_err(|e| Error::protocol(format!("decode GraphItem: {e}")))?;
                        let remote_did = if found.remote_item.is_some() {
                            cur_drive_id.clone()
                        } else {
                            let cand = found
                                .parent_reference
                                .as_ref()
                                .and_then(|p| p.drive_id.as_deref());
                            self.external_drive_id(cand).await?.or(cur_drive_id)
                        };
                        return Ok(Some((found, remote_did)));
                    }
                }
                for (idx, seg) in remaining.iter().enumerate() {
                    let Some(child) = self
                        .find_child_in_drive_folder(cur_drive_id.as_deref(), &cur_item_id, seg)
                        .await?
                    else {
                        return Ok(None);
                    };
                    if idx + 1 == remaining.len() {
                        return Ok(Some((child, cur_drive_id)));
                    }
                    if !child.is_folder() {
                        return Ok(None);
                    }
                    if child.remote_item.is_some() {
                        let (next_did, next_id) = child.remote_target();
                        if next_id.is_empty() {
                            return Ok(None);
                        }
                        if next_did.is_some() {
                            cur_drive_id = self.external_drive_id(next_did).await?;
                        }
                        cur_item_id = next_id.to_string();
                    } else {
                        cur_item_id = child.id;
                    }
                }
                return Ok(None);
            }
            if !item.is_folder() {
                return Ok(None);
            }
        }
        Ok(None)
    }

    async fn stat_graph_item_with_drive(
        &self,
        path: &BackendPath,
    ) -> Result<Option<(GraphItem, Option<String>)>> {
        if let Some(nid) = &path.node_id {
            let (nid_drive_id, item_id) = decode_node_id(nid.as_str());
            let url = self.drive_item_url(nid_drive_id, item_id, "");
            let (status, _, body) = self
                .graph_request("stat", Method::GET, &url, None, true)
                .await?;
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let item: GraphItem = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode GraphItem: {e}")))?;
            let remote_drive_id = if item.remote_item.is_some() {
                nid_drive_id.map(str::to_string)
            } else if let Some(did) = nid_drive_id {
                Some(did.to_string())
            } else {
                let candidate = item
                    .parent_reference
                    .as_ref()
                    .and_then(|p| p.drive_id.as_deref());
                self.external_drive_id(candidate).await?
            };
            return Ok(Some((item, remote_drive_id)));
        }

        let raw_path = path.raw_path();
        let url = self.raw_item_path_url(raw_path, "");
        let (status, _, body) = self
            .graph_request("stat", Method::GET, &url, None, true)
            .await?;
        if status != StatusCode::NOT_FOUND {
            let item: GraphItem = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode GraphItem: {e}")))?;
            let remote_drive_id = if item.remote_item.is_some() {
                None
            } else {
                let candidate = item
                    .parent_reference
                    .as_ref()
                    .and_then(|p| p.drive_id.as_deref());
                self.external_drive_id(candidate).await?
            };
            return Ok(Some((item, remote_drive_id)));
        }

        if raw_path.contains('/') {
            return self.stat_through_remote_mount(raw_path).await;
        }
        Ok(None)
    }

    async fn stat_graph_item(&self, path: &BackendPath) -> Result<Option<GraphItem>> {
        Ok(self
            .stat_graph_item_with_drive(path)
            .await?
            .map(|(it, _)| it))
    }
}

fn graph_error_decision<T>(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
) -> PolicyDecision<T> {
    PolicyDecision::from_error(classify_graph_status(
        context,
        status,
        headers,
        body,
        is_upload_session,
    ))
}

fn classify_graph_status(
    context: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    is_upload_session: bool,
) -> Error {
    let retry_after = parse_retry_after(headers);
    let snippet = String::from_utf8_lossy(&body[..body.len().min(240)]);
    let msg = format!("{context}: HTTP {} ({snippet})", status.as_u16());
    let mut err = match status.as_u16() {
        401 | 403 => Error::new(ErrorKind::PermissionDenied, RetryClass::Permanent, msg),
        404 | 410 if is_upload_session => {
            Error::new(ErrorKind::NotFound, RetryClass::SessionExpired, msg)
        }
        404 | 410 => Error::new(ErrorKind::NotFound, RetryClass::Permanent, msg),
        408 => Error::new(ErrorKind::Timeout, RetryClass::Retryable, msg),
        409 => Error::new(ErrorKind::Conflict, RetryClass::Permanent, msg),
        412 => Error::new(ErrorKind::PreconditionFailed, RetryClass::Permanent, msg),
        416 if is_upload_session => Error::new(ErrorKind::Conflict, RetryClass::Retryable, msg),
        423 => Error::lock_busy(msg),
        429 | 503 | 509 => Error::rate_limited(msg, retry_after),
        507 => Error::new(ErrorKind::QuotaExceeded, RetryClass::Permanent, msg),
        500..=599 => Error::new(ErrorKind::Network, RetryClass::Retryable, msg),
        _ => Error::new(ErrorKind::Protocol, RetryClass::Permanent, msg),
    };
    if let Some(ra) = retry_after
        && err.retry_after.is_none()
    {
        err = err.with_retry_after(ra);
    }
    err
}

fn encode_graph_path(path: &str) -> String {
    crate::common::http::percent_encode_path(path)
}

#[async_trait]
impl StorageBackend for OnedriveBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "onedrive"
    }

    fn endpoint_identity(&self) -> String {
        format!(
            "onedrive://{}/{}",
            self.inner.auth.principal(),
            self.inner.drive_base
        )
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Only kinds Graph may report verbatim in `file.hashes`: `Entry::checksum` carries
            // `sha256Hash` or `sha1Hash` when the drive returns them (OneDrive Personal only).
            // Business & SharePoint drives never report SHA-1/SHA-256 (only `quickXorHash`), so
            // `hashes` is empty there; uploads and full downloads still verify `quickXorHash`
            // internally.
            hashes: if self.inner.cfg.is_business_or_sharepoint() {
                Vec::new()
            } else {
                vec![HashKind::Sha256, HashKind::Sha1]
            },
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: ONEDRIVE_CHUNK_ALIGN_BYTES,
                max_chunk_bytes: Some(MAX_ONEDRIVE_CHUNK_BYTES),
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self.inner.cfg.default_chunk_size,
            allows_duplicate_names: false,
            case_sensitive: false,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        self.stat_impl(path).await
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_with_options(prefix, &ListOptions::new().with_recursive(recursive))
            .await
    }

    async fn list_with_options(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        self.list_with_options_impl(prefix, options).await
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        self.mkdir_impl(path).await
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.delete_impl(path).await
    }

    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.compute_hash_impl(path, kind).await
    }

    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.open_read_impl(path, range).await
    }

    async fn open_read_entry(
        &self,
        entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        self.open_read_entry_impl(entry, path, range).await
    }

    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.put_single_shot_impl(init, body).await
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.begin_upload_impl(init).await
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        self.query_upload_impl(op).await
    }

    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
        self.upload_chunk_impl(op, chunk).await
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        self.finish_upload_impl(op, parts).await
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.abort_upload_impl(op).await
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.reconcile_operation_impl(op).await
    }

    fn can_server_side_copy_from(&self, src_endpoint: &str) -> bool {
        self.can_server_side_copy_from_impl(src_endpoint)
    }

    async fn server_side_copy(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        self.server_side_copy_impl(src_endpoint, src_path, init)
            .await
    }

    async fn about(&self) -> Result<Option<StorageQuota>> {
        self.about_impl().await
    }

    async fn rename(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        self.rename_impl(path, new_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_transport::oauth::StaticBearerAuth;
    use rship_transport::{LimiterPlane, TransportConfig};

    #[test]
    fn control_and_data_limiters_are_plane_isolated() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok"));
        let backend = OnedriveBackend::new(OnedriveConfig::new("od"), auth, transport).unwrap();

        assert!(!Arc::ptr_eq(
            backend.control_limiter(),
            backend.data_limiter()
        ));
        assert_eq!(
            backend.control_limiter().scope().plane,
            Some(LimiterPlane::Control)
        );
        assert_eq!(
            backend.data_limiter().scope().plane,
            Some(LimiterPlane::Data)
        );

        backend.control_limiter().record_throttle();
        assert!(backend.control_limiter().snapshot().cubic_enabled);
        assert!(
            !backend.data_limiter().snapshot().cubic_enabled,
            "control-plane throttle must not affect isolated data-plane limiter"
        );
    }

    #[test]
    fn bearer_authorization_headers_are_marked_sensitive_at_all_request_sites() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let secret = "super-secret-onedrive-access-token";
        let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", secret));
        let backend = OnedriveBackend::new(OnedriveConfig::new("od"), auth, transport).unwrap();

        let requests = [
            backend
                .build_graph_request(
                    Method::GET,
                    "https://graph.microsoft.com/v1.0/me/drive",
                    secret,
                    None,
                )
                .unwrap()
                .build()
                .unwrap(),
            backend
                .build_single_shot_request(
                    "https://graph.microsoft.com/v1.0/me/drive/root:/a.bin:/content",
                    secret,
                    128,
                )
                .unwrap()
                .build()
                .unwrap(),
            backend
                .build_range_request(
                    "https://graph.microsoft.com/v1.0/me/drive/items/id-1/content",
                    Some(secret),
                    0,
                    63,
                )
                .unwrap()
                .build()
                .unwrap(),
        ];

        let pre_auth_req = backend
            .build_range_request(
                "https://download.example.com/preauth/blob?sig=xyz",
                None,
                0,
                63,
            )
            .unwrap()
            .build()
            .unwrap();
        assert!(
            pre_auth_req
                .headers()
                .get(http::header::AUTHORIZATION)
                .is_none(),
            "pre-authenticated downloadUrl range request must not include Authorization header"
        );

        for req in requests {
            let hdr = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .expect("request must include Authorization header");
            assert!(
                hdr.is_sensitive(),
                "Bearer Authorization header must be marked sensitive (is_sensitive() == true)"
            );
            assert_eq!(hdr.as_bytes(), format!("Bearer {secret}").as_bytes());
            assert!(
                !format!("{hdr:?}").contains(secret),
                "Debug formatting must redact sensitive Bearer token"
            );
        }
    }

    #[test]
    fn classifies_graph_429_503_509_as_throttled_and_other_5xx_as_retryable_only() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("9"));

        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::from_u16(509).unwrap(),
        ] {
            let err = classify_graph_status("test", status, &hdrs, b"busy", false);
            assert_eq!(err.kind, ErrorKind::RateLimited, "status={status}");
            assert_eq!(err.retry, RetryClass::Throttled, "status={status}");
            assert!(err.is_throttled(), "status={status}");
            assert_eq!(err.retry_after, Some(Duration::from_secs(9)));
        }

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = classify_graph_status("test", status, &HeaderMap::new(), b"err", false);
            assert_eq!(err.kind, ErrorKind::Network, "status={status}");
            assert_eq!(err.retry, RetryClass::Retryable, "status={status}");
            assert!(!err.is_throttled(), "status={status} must not trip CUBIC");
        }

        let err_408 = classify_graph_status(
            "test",
            StatusCode::REQUEST_TIMEOUT,
            &HeaderMap::new(),
            b"timeout",
            false,
        );
        assert_eq!(err_408.kind, ErrorKind::Timeout);
        assert_eq!(err_408.retry, RetryClass::Retryable);
        assert!(!err_408.is_throttled());

        let err_507 = classify_graph_status(
            "test",
            StatusCode::INSUFFICIENT_STORAGE,
            &HeaderMap::new(),
            b"quota",
            false,
        );
        assert_eq!(err_507.kind, ErrorKind::QuotaExceeded);
        assert_eq!(err_507.retry, RetryClass::Permanent);

        let err_410_sess =
            classify_graph_status("test", StatusCode::GONE, &HeaderMap::new(), b"gone", true);
        assert_eq!(err_410_sess.kind, ErrorKind::NotFound);
        assert_eq!(err_410_sess.retry, RetryClass::SessionExpired);
    }

    #[test]
    fn classifies_416_upload_session_and_423_locked_as_retryable() {
        let err_416_sess = classify_graph_status(
            "PUT(uploadUrl chunk)",
            StatusCode::RANGE_NOT_SATISFIABLE,
            &HeaderMap::new(),
            br#"{"error":{"code":"fragmentOverlap"}}"#,
            true,
        );
        assert_eq!(err_416_sess.retry, RetryClass::Retryable);
        assert!(err_416_sess.is_retryable());

        let err_416_read = classify_graph_status(
            "GET(OneDrive range)",
            StatusCode::RANGE_NOT_SATISFIABLE,
            &HeaderMap::new(),
            b"range not satisfiable",
            false,
        );
        assert_eq!(err_416_read.retry, RetryClass::Permanent);
        assert!(!err_416_read.is_retryable());

        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("4"));
        let err_423 = classify_graph_status("PATCH", StatusCode::LOCKED, &hdrs, b"locked", false);
        assert_eq!(err_423.kind, ErrorKind::LockBusy);
        assert_eq!(err_423.retry, RetryClass::Retryable);
        assert_eq!(err_423.retry_after, Some(Duration::from_secs(4)));
    }

    #[test]
    fn capabilities_hashes_empty_for_business_and_sharepoint_drive_types() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("alice@contoso.com", "tok"));

        for dt_str in ["business", "documentLibrary", "sharepoint"] {
            let dt = crate::onedrive::config::OnedriveDriveType::parse(dt_str).unwrap();
            let cfg = OnedriveConfig::new("od").with_drive_type(dt);
            let backend = OnedriveBackend::new(cfg, auth.clone(), transport.clone()).unwrap();
            assert!(
                backend.capabilities().hashes.is_empty(),
                "drive_type={dt_str} must report empty capabilities().hashes"
            );
        }

        let personal = OnedriveBackend::new(
            OnedriveConfig::new("od-p")
                .with_drive_type(crate::onedrive::config::OnedriveDriveType::Personal),
            auth,
            transport,
        )
        .unwrap();
        assert_eq!(
            personal.capabilities().hashes,
            vec![HashKind::Sha256, HashKind::Sha1]
        );
    }

    #[test]
    fn graph_hashes_normalizes_hex_and_prefers_sha256() {
        let h = GraphHashes {
            sha256_hash: Some("  AABBCC  ".into()),
            sha1_hash: Some(" 112233 ".into()),
            quick_xor_hash: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()),
        };
        assert_eq!(h.sha256_hex().as_deref(), Some("aabbcc"));
        assert_eq!(h.sha1_hex().as_deref(), Some("112233"));
        assert_eq!(h.quickxor_hex(), Some("0".repeat(40)));
        assert_eq!(
            h.preferred_entry_checksum(),
            Some(Checksum {
                kind: HashKind::Sha256,
                hex: "aabbcc".into(),
            })
        );
    }

    #[test]
    fn node_id_encode_decode_preserves_personal_bang_ids_and_remote_drive_prefix() {
        // OneDrive Personal item IDs commonly contain `!`; `!` must NOT split drive_id/item_id.
        let personal_id = "1234567890ABCDEF!101";
        let local_nid = encode_node_id(None, personal_id).unwrap();
        assert_eq!(local_nid.as_str(), personal_id);
        assert_eq!(decode_node_id(local_nid.as_str()), (None, personal_id));

        let remote_nid = encode_node_id(Some("b!drv-shared"), "ABCDEF!202").unwrap();
        assert_eq!(remote_nid.as_str(), "rship-drive:b!drv-shared/ABCDEF!202");
        assert_eq!(
            decode_node_id(remote_nid.as_str()),
            (Some("b!drv-shared"), "ABCDEF!202")
        );

        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok"));
        let backend = OnedriveBackend::new(OnedriveConfig::new("od"), auth, transport).unwrap();
        assert_eq!(
            backend.drive_item_url(None, personal_id, ""),
            "https://graph.microsoft.com/v1.0/me/drive/items/1234567890ABCDEF%21101"
        );
        assert_eq!(
            backend.drive_item_url(Some("b!drv-shared"), "ABCDEF!202", "content"),
            "https://graph.microsoft.com/v1.0/drives/b%21drv-shared/items/ABCDEF%21202/content"
        );
    }
}
