//! Production Google Drive v3 [`StorageBackend`] implementation.

mod inventory;
mod streams;
mod transfer;
mod tree;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::clock::{Clock, SystemClock};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DeltaInventoryStore, DeltaScope, OperationRecord};
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, HashKind, NodeId, UploadTopology,
};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::{HttpTransport, LimiterScope, RateLimiterConfig, ScopedLimiter};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;

use crate::common::http::{
    Idempotency, PolicyDecision, ReconcileAction, RetryPolicyConfig, bearer_header_value,
    execute_with_auth_policy, execute_with_policy_full, percent_encode_segment,
};
use crate::common::lock_unpoisoned;
use crate::gdrive::auth::AuthProvider;
use crate::gdrive::changes::InMemoryGdriveStore;
use crate::gdrive::config::{GDRIVE_CHUNK_ALIGN_BYTES, GdriveConfig};
use crate::gdrive::error::{classify_gdrive_error, classify_gdrive_upload_error};
use crate::gdrive::query::{FOLDER_MIME, SHORTCUT_MIME};

pub(super) const MAX_ANCESTOR_HOPS: usize = 64;
const MAX_MKDIR_LOCKS_SOFT_CAP: usize = 1024;
const MAX_SHORTCUT_CACHE_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DriveFile {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default, deserialize_with = "de_u64_lenient")]
    pub size: u64,
    #[serde(default)]
    pub modified_time: Option<String>,
    #[serde(default)]
    pub md5_checksum: Option<String>,
    #[serde(default)]
    pub sha1_checksum: Option<String>,
    #[serde(default)]
    pub sha256_checksum: Option<String>,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub trashed: bool,
    #[serde(default)]
    pub shared_with_me_time: Option<String>,
    #[serde(default)]
    pub shortcut_details: Option<ShortcutDetails>,
    #[serde(default)]
    pub app_properties: HashMap<String, String>,
}

impl DriveFile {
    pub(crate) fn checksum_for(&self, kind: HashKind) -> Option<Checksum> {
        let raw = match kind {
            HashKind::Md5 => self.md5_checksum.as_deref(),
            HashKind::Sha1 => self.sha1_checksum.as_deref(),
            HashKind::Sha256 => self.sha256_checksum.as_deref(),
            _ => None,
        }?;
        let hex = raw.trim();
        if hex.is_empty() {
            return None;
        }
        Some(Checksum {
            kind,
            hex: hex.to_ascii_lowercase(),
        })
    }

    pub(crate) fn best_checksum(&self) -> Option<Checksum> {
        self.checksum_for(HashKind::Md5)
            .or_else(|| self.checksum_for(HashKind::Sha256))
            .or_else(|| self.checksum_for(HashKind::Sha1))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShortcutDetails {
    pub target_id: String,
    #[serde(default)]
    pub target_mime_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileListResponse {
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    incomplete_search: bool,
    #[serde(default)]
    files: Vec<DriveFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateIdsResponse {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartPageTokenResponse {
    start_page_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeListResponse {
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    new_start_page_token: Option<String>,
    #[serde(default)]
    changes: Vec<DriveChange>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveChange {
    file_id: String,
    #[serde(default)]
    removed: bool,
    #[serde(default)]
    file: Option<DriveFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GdriveSessionMeta {
    file_id: String,
    parent_id: String,
    is_update: bool,
    total_size: u64,
}

fn de_u64_lenient<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        Str(String),
        Num(u64),
        Null,
    }
    match Option::<StringOrNum>::deserialize(deserializer)? {
        Some(StringOrNum::Str(s)) => Ok(s.parse::<u64>().unwrap_or(0)),
        Some(StringOrNum::Num(n)) => Ok(n),
        Some(StringOrNum::Null) | None => Ok(0),
    }
}

/// Google Drive v3 storage backend.
#[derive(Clone)]
pub struct GdriveBackend {
    inner: Arc<GdriveInner>,
}

struct GdriveInner {
    cfg: GdriveConfig,
    transport: HttpTransport,
    auth: Arc<dyn AuthProvider>,
    control_limiter: Arc<ScopedLimiter>,
    data_limiter: Arc<ScopedLimiter>,
    inventory: Arc<dyn DeltaInventoryStore>,
    clock: Arc<dyn Clock>,
    /// Per-path-prefix async mutexes preventing duplicate sibling directory creation
    /// under concurrent `mkdir` / upload workers, stored as `Weak` references so idle
    /// locks do not accumulate unboundedly.
    mkdir_locks: StdMutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    /// Bounded in-memory `(parent_id, folder_name) -> folder_id` cache eliminating
    /// redundant SQLite / HTTP lookups on hot nested uploads and path resolution.
    dir_id_cache: StdMutex<HashMap<(String, String), String>>,
    /// Bounded in-memory `shortcut_id -> (target_id, target_mime_type)` cache so
    /// node-id-based reads/copies/overwrites avoid extra `files.get` probes when hot.
    shortcut_targets: StdMutex<HashMap<String, (String, String)>>,
    /// Pooled `files.generateIds` IDs keyed by space (`"drive"` or `"appDataFolder"`).
    generated_id_pool: Mutex<(String, Vec<String>)>,
    /// Lazily discovered canonical folder ID for Google Drive's `"root"` alias
    /// (e.g. `"0AI...PVA"`), learned at zero cost from top-level listings/uploads or
    /// queried once via `files.get("root")` when needed by `changes.list`.
    actual_root_id: tokio::sync::OnceCell<String>,
}

impl GdriveBackend {
    pub fn new(
        cfg: GdriveConfig,
        transport: HttpTransport,
        auth: Arc<dyn AuthProvider>,
        inventory: Option<Arc<dyn DeltaInventoryStore>>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let mut lim_cfg = RateLimiterConfig::default();
        lim_cfg.write_qps = cfg.write_qps;
        let scope = LimiterScope::new(&cfg.remote_name, auth.principal());
        let control_limiter =
            transport.control_limiter_for_with_config(scope.clone(), lim_cfg.clone());
        let data_limiter = transport.data_limiter_for_with_config(scope, lim_cfg);
        let inventory = inventory.unwrap_or_else(|| Arc::new(InMemoryGdriveStore::new()));
        let clock = clock.unwrap_or_else(SystemClock::shared);

        Self {
            inner: Arc::new(GdriveInner {
                cfg,
                transport,
                auth,
                control_limiter,
                data_limiter,
                inventory,
                clock,
                mkdir_locks: StdMutex::new(HashMap::new()),
                dir_id_cache: StdMutex::new(HashMap::new()),
                shortcut_targets: StdMutex::new(HashMap::new()),
                generated_id_pool: Mutex::new((String::new(), Vec::new())),
                actual_root_id: tokio::sync::OnceCell::new(),
            }),
        }
    }

    pub fn config(&self) -> &GdriveConfig {
        &self.inner.cfg
    }

    pub fn inventory(&self) -> &Arc<dyn DeltaInventoryStore> {
        &self.inner.inventory
    }

    pub fn control_limiter(&self) -> &Arc<ScopedLimiter> {
        &self.inner.control_limiter
    }

    pub fn data_limiter(&self) -> &Arc<ScopedLimiter> {
        &self.inner.data_limiter
    }

    pub(super) fn build_url(
        &self,
        base: &str,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<String> {
        let mut raw = base.trim_end_matches('/').to_string();
        for seg in segments {
            raw.push('/');
            raw.push_str(&percent_encode_segment(seg));
        }
        let mut url = Url::parse(&raw)
            .map_err(|e| Error::protocol(format!("invalid Google Drive url `{raw}`: {e}")))?;
        if !query.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
        }
        Ok(url.into())
    }

    pub(super) fn api_url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<String> {
        self.build_url(&self.inner.cfg.api_base_url, segments, query)
    }

    pub(super) fn upload_url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<String> {
        self.build_url(&self.inner.cfg.upload_base_url, segments, query)
    }

    pub(super) fn retry_policy_config(&self, is_write: bool) -> RetryPolicyConfig {
        RetryPolicyConfig::new()
            .with_max_retries(self.inner.cfg.max_retries)
            .with_delays(
                self.inner.cfg.base_retry_delay,
                self.inner.cfg.max_retry_delay,
            )
            .with_write_permit(is_write)
    }

    pub fn scope(&self) -> DeltaScope {
        DeltaScope {
            remote_name: self.inner.cfg.remote_name.clone(),
            principal: self.inner.auth.principal().to_string(),
            corpus_id: self.inner.cfg.corpus_id().to_string(),
            root_id: self.inner.cfg.effective_root_id().to_string(),
        }
    }

    fn mkdir_lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        let mut map = lock_unpoisoned(&self.inner.mkdir_locks);
        if let Some(existing) = map.get(key).and_then(std::sync::Weak::upgrade) {
            return existing;
        }
        if map.len() >= MAX_MKDIR_LOCKS_SOFT_CAP {
            map.retain(|_, weak| weak.strong_count() > 0);
        }
        let lock = Arc::new(Mutex::new(()));
        map.insert(key.to_string(), Arc::downgrade(&lock));
        lock
    }

    pub(super) fn lookup_dir_cache(&self, parent_id: &str, name: &str) -> Option<String> {
        lock_unpoisoned(&self.inner.dir_id_cache)
            .get(&(parent_id.to_string(), name.to_string()))
            .cloned()
    }

    pub(super) fn insert_dir_cache(&self, parent_id: &str, name: &str, folder_id: &str) {
        let mut map = lock_unpoisoned(&self.inner.dir_id_cache);
        if map.len() >= 16_384 {
            map.clear();
        }
        map.insert(
            (parent_id.to_string(), name.to_string()),
            folder_id.to_string(),
        );
    }

    pub(super) fn invalidate_dir_cache_for_id(&self, file_id: &str) {
        let mut map = lock_unpoisoned(&self.inner.dir_id_cache);
        let mut to_evict: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        queue.push_back(file_id.to_string());
        while let Some(cur) = queue.pop_front() {
            if !to_evict.insert(cur.clone()) {
                continue;
            }
            for ((parent, _), child) in map.iter() {
                if parent == &cur && !to_evict.contains(child) {
                    queue.push_back(child.clone());
                }
            }
        }
        map.retain(|(parent, _), child| !to_evict.contains(parent) && !to_evict.contains(child));
        drop(map);
        self.invalidate_shortcut_target(file_id);
    }

    pub(super) async fn evict_cached_dir(&self, dir_id: &str) {
        self.invalidate_dir_cache_for_id(dir_id);
        if !self.inner.cfg.use_changes_feed {
            let scope = self.scope();
            let _ = self
                .inner
                .inventory
                .apply_change_batch(
                    &scope,
                    rship_core::state::DeltaChangeBatch {
                        evict_subtree_root_ids: vec![dir_id.to_string()],
                        updated_at: self.inner.clock.now_unix_secs(),
                        ..Default::default()
                    },
                )
                .await;
        }
    }

    pub(super) fn record_shortcut_target(
        &self,
        shortcut_id: &str,
        target_id: &str,
        target_mime_type: &str,
    ) {
        let mut map = lock_unpoisoned(&self.inner.shortcut_targets);
        if map.len() >= MAX_SHORTCUT_CACHE_ENTRIES {
            map.clear();
        }
        map.insert(
            shortcut_id.to_string(),
            (target_id.to_string(), target_mime_type.to_string()),
        );
    }

    pub(super) fn lookup_shortcut_target(&self, shortcut_id: &str) -> Option<(String, String)> {
        lock_unpoisoned(&self.inner.shortcut_targets)
            .get(shortcut_id)
            .cloned()
    }

    pub(super) fn invalidate_shortcut_target(&self, shortcut_id: &str) {
        lock_unpoisoned(&self.inner.shortcut_targets).remove(shortcut_id);
    }

    pub(super) fn record_root_alias_id(&self, candidate: &str) {
        if !self.inner.cfg.shared_with_me
            && self.inner.cfg.effective_root_id() == "root"
            && !candidate.is_empty()
            && candidate != "root"
        {
            let _ = self.inner.actual_root_id.set(candidate.to_string());
        }
    }

    pub(super) async fn ensure_actual_root_id(&self) -> Result<Option<&str>> {
        if self.inner.cfg.shared_with_me || self.inner.cfg.effective_root_id() != "root" {
            return Ok(None);
        }
        let id = self
            .inner
            .actual_root_id
            .get_or_try_init(|| async {
                match self.get_file_by_id("root").await? {
                    Some(f) if !f.id.is_empty() => Ok(f.id),
                    _ => Ok("root".to_string()),
                }
            })
            .await?;
        Ok(Some(id.as_str()))
    }

    /// Normalize a Drive `parents[0]` ID so My Drive's alphanumeric root folder ID
    /// (e.g. `"0AI...PVA"`) maps canonically to `"root"` whenever `effective_root_id() == "root"`
    /// and `shared_with_me` is disabled.
    pub(super) fn normalize_parent_id(
        &self,
        raw_parent: Option<String>,
        fallback_parent: Option<&str>,
    ) -> Option<String> {
        let pid = raw_parent.or_else(|| fallback_parent.map(str::to_string))?;
        if self.inner.cfg.shared_with_me {
            if fallback_parent == Some("root") {
                return Some("root".to_string());
            }
            return Some(pid);
        }
        if self.inner.cfg.effective_root_id() == "root" {
            if fallback_parent == Some("root") {
                self.record_root_alias_id(&pid);
                return Some("root".to_string());
            }
            if self
                .inner
                .actual_root_id
                .get()
                .is_some_and(|actual| actual == &pid)
            {
                return Some("root".to_string());
            }
        }
        Some(pid)
    }

    pub(super) async fn control_request(
        &self,
        context: &str,
        method: Method,
        url: String,
        json_body: Option<&serde_json::Value>,
        is_write: bool,
        allow_404: bool,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let body_bytes = match json_body {
            Some(v) => Some(
                serde_json::to_vec(v)
                    .map_err(|e| Error::protocol(format!("{context}: encode JSON body: {e}")))?,
            ),
            None => None,
        };
        let cfg = self.retry_policy_config(is_write);

        execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &cfg,
            Idempotency::Idempotent,
            || {
                let method = method.clone();
                let url = url.clone();
                let body_bytes = body_bytes.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let mut req = self
                        .inner
                        .transport
                        .control_client()
                        .request(method, &url)
                        .header(http::header::AUTHORIZATION, auth_hdr);
                    if let Some(payload) = body_bytes {
                        req = req
                            .header(
                                http::header::CONTENT_TYPE,
                                "application/json; charset=UTF-8",
                            )
                            .body(payload);
                    }
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
                if resp.status.is_success() || (allow_404 && resp.status == StatusCode::NOT_FOUND) {
                    return PolicyDecision::Ok((resp.status, resp.headers, resp.body));
                }
                let err =
                    classify_gdrive_error(context, resp.status, &resp.headers, &resp.body, false);
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
        )
        .await
    }

    /// Execute a non-idempotent Drive `POST` mutation (`files.create` folder or `files.copy`)
    /// carrying a pre-generated `"id"` under `execute_with_policy_full` (`NonIdempotent`),
    /// reconciling ambiguous failures and `409 Conflict` via `files.get(pregenerated_id)`
    /// so lost responses after server-side commit never create duplicate nodes.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn control_create_with_id(
        &self,
        context: &str,
        url: String,
        json_body: &serde_json::Value,
        pregenerated_id: &str,
        expected_op_id: Option<&str>,
        expected_folder: bool,
        apply_upload_limit: bool,
        request_timeout: Option<Duration>,
    ) -> Result<DriveFile> {
        let body_bytes = serde_json::to_vec(json_body)
            .map_err(|e| Error::protocol(format!("{context}: encode JSON body: {e}")))?;
        let mut cfg = self.retry_policy_config(true);
        if let Some(timeout) = request_timeout {
            cfg = cfg.with_request_timeout(timeout);
        }

        execute_with_policy_full(
            &self.inner.transport,
            &self.inner.control_limiter,
            context,
            &cfg,
            Idempotency::NonIdempotent,
            || {
                let url = url.clone();
                let body_bytes = body_bytes.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .post(&url)
                        .header(http::header::AUTHORIZATION, auth_hdr)
                        .header(
                            http::header::CONTENT_TYPE,
                            "application/json; charset=UTF-8",
                        )
                        .body(body_bytes);
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
                    return match serde_json::from_slice::<DriveFile>(&resp.body) {
                        Ok(file) => PolicyDecision::Ok(file),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "{context}: decode response JSON: {e}"
                        ))),
                    };
                }
                let err = classify_gdrive_upload_error(
                    context,
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    false,
                    apply_upload_limit,
                );
                if resp.status == StatusCode::CONFLICT {
                    return PolicyDecision::Reconcile(err);
                }
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
            |err| {
                let pregenerated_id = pregenerated_id.to_string();
                let expected_op_id = expected_op_id.map(str::to_string);
                async move {
                    match self.get_file_by_id(&pregenerated_id).await {
                        Ok(Some(existing)) if !existing.trashed => {
                            if expected_folder
                                && existing.mime_type != crate::gdrive::query::FOLDER_MIME
                            {
                                return Ok(ReconcileAction::Fail(Error::conflict(format!(
                                    "{context}: pre-generated id `{pregenerated_id}` resolved to non-folder mimeType `{}`",
                                    existing.mime_type
                                ))));
                            }
                            if let Some(ref op_id) = expected_op_id
                                && let Some(found_op) = existing.app_properties.get("rship_op_id")
                                && found_op != op_id
                            {
                                return Ok(ReconcileAction::Fail(Error::conflict(format!(
                                    "{context}: pre-generated id `{pregenerated_id}` belongs to different operation `{found_op}`"
                                ))));
                            }
                            Ok(ReconcileAction::Resolved(existing))
                        }
                        Ok(Some(_trashed)) => Ok(ReconcileAction::Fail(err)),
                        Ok(None) => {
                            if err.kind == ErrorKind::Conflict {
                                Ok(ReconcileAction::Fail(err))
                            } else {
                                Ok(ReconcileAction::Retry(err))
                            }
                        }
                        Err(probe_err) => Ok(ReconcileAction::Fail(probe_err)),
                    }
                }
            },
        )
        .await
    }

    /// Rename an existing Drive file, folder, or shortcut in place by `file_id`.
    pub(crate) async fn rename_node(&self, file_id: &str, new_name: &str) -> Result<DriveFile> {
        let url = self.api_url(
            &["files", file_id],
            &[
                ("fields", crate::gdrive::query::FILE_FIELDS),
                ("supportsAllDrives", "true"),
            ],
        )?;
        let body = serde_json::json!({ "name": new_name });
        let (_, _, resp_body) = self
            .control_request(
                "files.update(rename)",
                Method::PATCH,
                url,
                Some(&body),
                true,
                false,
            )
            .await?;
        let updated: DriveFile = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::protocol(format!("decode files.update(rename) JSON: {e}")))?;
        self.invalidate_dir_cache_for_id(file_id);
        if updated.mime_type == FOLDER_MIME
            && let Some(pid) = updated.parents.first()
        {
            self.insert_dir_cache(pid, &updated.name, &updated.id);
        }
        // Only update `gdrive_nodes` for directories that are ALREADY tracked so an
        // un-crawled directory never appears as `was_known.is_some()` in `sync_changes`.
        if updated.mime_type != FOLDER_MIME {
            self.cache_node(&updated, None).await;
        } else if self.inner.cfg.use_changes_feed {
            let scope = self.scope();
            if self
                .inner
                .inventory
                .get_node(&scope.remote_name, &scope.corpus_id, &updated.id)
                .await
                .ok()
                .flatten()
                .is_some()
            {
                self.cache_node(&updated, None).await;
            }
        }
        Ok(updated)
    }
}

#[async_trait]
impl StorageBackend for GdriveBackend {
    /// Engine transfer retries share this account's control-plane retry bucket with the
    /// backend's own HTTP retries, so the two layers cannot each spend a full budget.
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::RetryQuota>> {
        Some(self.inner.control_limiter.clone())
    }

    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "gdrive"
    }

    fn endpoint_identity(&self) -> String {
        format!(
            "gdrive://{}/{}/{}",
            self.inner.auth.principal(),
            self.inner.cfg.corpus_id(),
            self.inner.cfg.effective_root_id()
        )
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![HashKind::Sha256, HashKind::Sha1, HashKind::Md5],
            mtime_granularity: Duration::from_millis(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: GDRIVE_CHUNK_ALIGN_BYTES,
                max_chunk_bytes: None,
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self.inner.cfg.default_chunk_size,
            allows_duplicate_names: true,
            case_sensitive: true,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: true,
            supports_server_side_copy: true,
            default_write_qps: self.inner.cfg.write_qps.map(|q| q.ceil().max(1.0) as u32),
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        self.stat_impl(path).await
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_with_options_impl(prefix, &ListOptions::new().with_recursive(recursive))
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

    async fn prepare_operation_id(&self, init: &UploadInit) -> Result<Option<NodeId>> {
        if init.existing_node_id.is_some() {
            return Ok(None);
        }
        let id = self.generate_file_id().await?;
        Ok(Some(NodeId(id)))
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

    async fn about(&self) -> Result<Option<rship_core::types::StorageQuota>> {
        if self.inner.cfg.shared_drive_id.is_some() {
            // Shared Drives have no per-drive `about.storageQuota`; `GET /about`
            // returns the caller's personal/Service Account quota instead.
            return Ok(None);
        }
        let url = self.api_url(&["about"], &[("fields", "storageQuota")])?;

        let (_, _, body) = self
            .control_request("about.get", Method::GET, url, None, false, false)
            .await?;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AboutResp {
            storage_quota: Option<QuotaJson>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct QuotaJson {
            limit: Option<String>,
            usage: Option<String>,
            usage_in_drive_trash: Option<String>,
        }

        let parsed: AboutResp = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode about.get JSON: {e}")))?;
        let Some(q) = parsed.storage_quota else {
            return Ok(None);
        };
        let total = q.limit.as_deref().and_then(|s| s.parse::<u64>().ok());
        let used = q.usage.as_deref().and_then(|s| s.parse::<u64>().ok());
        let trashed = q
            .usage_in_drive_trash
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok());
        let free = match (total, used) {
            (Some(t), Some(u)) => Some(t.saturating_sub(u)),
            _ => None,
        };
        Ok(Some(rship_core::types::StorageQuota {
            total_bytes: total,
            used_bytes: used,
            free_bytes: free,
            trashed_bytes: trashed,
        }))
    }

    async fn rename(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
            return Err(Error::invalid_path(format!(
                "invalid rename target name `{new_name}`"
            )));
        }
        let file_id = if let Some(id) = &path.node_id {
            id.0.clone()
        } else {
            let Some(found) = self.resolve_backend_path(path, false).await? else {
                return Err(Error::not_found(format!(
                    "gdrive object `{}` not found",
                    path.nfc_path
                )));
            };
            found.own_id().to_string()
        };
        let updated = self.rename_node(&file_id, new_name).await?;
        let new_rel = match path.nfc_path.parent() {
            Some(parent) => parent.join(new_name)?,
            None => RelPath::parse(new_name)?,
        };
        let raw_trimmed = path.raw_path().trim_matches('/');
        let new_raw = match raw_trimmed.rsplit_once('/') {
            Some((parent_raw, _)) if !parent_raw.is_empty() => format!("{parent_raw}/{new_name}"),
            _ => new_name.to_string(),
        };
        if updated.mime_type == SHORTCUT_MIME {
            let target = self.resolve_shortcut_target(updated.clone()).await?;
            return Ok(tree::ResolvedDriveNode {
                node: updated,
                target,
            }
            .into_entry(self, new_raw, new_rel));
        }
        Ok(self.drive_file_to_entry(&updated, new_raw, new_rel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdrive::auth::StaticBearerAuth;

    #[test]
    fn root_alias_normalizes_alphanumeric_drive_root_parent_id() {
        let transport = HttpTransport::new(Default::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("test-user", "tok"));
        let backend = GdriveBackend::new(GdriveConfig::new("gdrive"), transport, auth, None, None);

        // First top-level listing/mkdir under `"root"` teaches the real My Drive ID (`0AI_REAL_ROOT`).
        let p1 = backend.normalize_parent_id(Some("0AI_REAL_ROOT".to_string()), Some("root"));
        assert_eq!(p1.as_deref(), Some("root"));

        // Subsequent changes/uploads without `fallback_parent` also map `0AI_REAL_ROOT` -> `"root"`.
        let p2 = backend.normalize_parent_id(Some("0AI_REAL_ROOT".to_string()), None);
        assert_eq!(p2.as_deref(), Some("root"));

        // Non-root subfolders retain their exact Drive folder ID.
        let p3 = backend.normalize_parent_id(Some("1SubFolderId".to_string()), None);
        assert_eq!(p3.as_deref(), Some("1SubFolderId"));
    }

    #[test]
    fn control_and_data_limiters_are_plane_isolated() {
        let transport = HttpTransport::new(Default::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
        let backend = GdriveBackend::new(GdriveConfig::new("gdrive"), transport, auth, None, None);

        assert!(!Arc::ptr_eq(
            backend.control_limiter(),
            backend.data_limiter()
        ));
        assert_eq!(
            backend.control_limiter().scope().plane,
            Some(rship_transport::LimiterPlane::Control)
        );
        assert_eq!(
            backend.data_limiter().scope().plane,
            Some(rship_transport::LimiterPlane::Data)
        );

        // Throttling control plane must not activate CUBIC on data plane.
        backend.control_limiter().record_throttle();
        assert!(backend.control_limiter().snapshot().cubic_enabled);
        assert!(!backend.data_limiter().snapshot().cubic_enabled);
    }

    #[test]
    fn mkdir_locks_prune_idle_entries_and_invalidate_dir_cache_is_recursive() {
        let transport = HttpTransport::new(Default::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("test-user", "tok"));
        let backend = GdriveBackend::new(GdriveConfig::new("gdrive"), transport, auth, None, None);

        // Create and drop > 1024 transient locks; weak pruning keeps map bounded!
        for i in 0..1100 {
            let _lock = backend.mkdir_lock_for(&format!("dir/{i}"));
        }
        let retained_len = lock_unpoisoned(&backend.inner.mkdir_locks).len();
        assert!(
            retained_len < 100,
            "idle weak mkdir_locks must be pruned (got {retained_len})"
        );

        // Live lock is shared by concurrent callers.
        let l1 = backend.mkdir_lock_for("shared/key");
        let l2 = backend.mkdir_lock_for("shared/key");
        assert!(Arc::ptr_eq(&l1, &l2));

        // Recursive dir cache invalidation removes descendants too.
        backend.insert_dir_cache("root", "a", "dir-a");
        backend.insert_dir_cache("dir-a", "b", "dir-b");
        backend.insert_dir_cache("dir-b", "c", "dir-c");
        backend.insert_dir_cache("root", "other", "dir-other");
        backend.invalidate_dir_cache_for_id("dir-a");

        assert!(backend.lookup_dir_cache("root", "a").is_none());
        assert!(backend.lookup_dir_cache("dir-a", "b").is_none());
        assert!(backend.lookup_dir_cache("dir-b", "c").is_none());
        assert_eq!(
            backend.lookup_dir_cache("root", "other").as_deref(),
            Some("dir-other")
        );
    }

    #[tokio::test]
    async fn shared_drive_about_returns_none() {
        let transport = HttpTransport::new(Default::default()).unwrap();
        let auth = Arc::new(StaticBearerAuth::new("test-user", "tok"));
        let cfg = GdriveConfig::new("gd-shared").with_shared_drive_id("0ASharedDrive");
        let backend = GdriveBackend::new(cfg, transport, auth, None, None);
        assert!(backend.about().await.unwrap().is_none());
    }
}
