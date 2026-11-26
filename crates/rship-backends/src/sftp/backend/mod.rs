//! SSH/SFTP [`StorageBackend`] built on `russh` + `russh-sftp`.

mod known_hosts;
mod ops;
mod pool;
mod transfer;

use async_trait::async_trait;
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, HashKind, StorageQuota,
    UploadTopology,
};
use rship_core::{Error, Result};
use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Mutex;

use crate::sftp::config::SftpConfig;

use pool::{PooledSftpConn, SftpPool};

const PART_PREFIX: &str = ".rship.part.";
const BAK_PREFIX: &str = ".rship.bak.";

struct SftpInner {
    cfg: SftpConfig,
    root_norm: String,
    pool: Arc<SftpPool>,
    known_dirs: StdMutex<HashSet<String>>,
    mkdir_lock: Mutex<()>,
}

#[derive(Clone)]
pub struct SftpBackend {
    inner: Arc<SftpInner>,
}

fn normalize_root_path(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s == "~" || s == "~/" {
        return String::new();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return rest.trim_matches('/').to_string();
    }
    if s.chars().all(|c| c == '/') {
        return "/".to_string();
    }
    s.trim_end_matches('/').to_string()
}

impl SftpBackend {
    pub fn new(cfg: SftpConfig) -> Result<Self> {
        if cfg.host.trim().is_empty() {
            return Err(Error::protocol("SFTP config missing `host`"));
        }
        let root_norm = normalize_root_path(&cfg.root_path);
        Ok(Self {
            inner: Arc::new(SftpInner {
                cfg,
                root_norm,
                pool: SftpPool::new(),
                known_dirs: StdMutex::new(HashSet::new()),
                mkdir_lock: Mutex::new(()),
            }),
        })
    }

    fn remote_path(&self, rel: &str) -> String {
        let trimmed = rel.trim_matches('/');
        match (self.inner.root_norm.as_str(), trimmed.is_empty()) {
            ("", true) => ".".to_string(),
            ("", false) => trimmed.to_string(),
            ("/", true) => "/".to_string(),
            ("/", false) => format!("/{trimmed}"),
            (root, true) => root.to_string(),
            (root, false) => format!("{root}/{trimmed}"),
        }
    }

    fn sibling_temp_path(&self, final_remote: &str, prefix: &str, op_id: &str) -> String {
        match final_remote.rsplit_once('/') {
            Some((parent, fname)) => {
                if parent.is_empty() {
                    format!("/{prefix}{op_id}.{fname}")
                } else {
                    format!("{parent}/{prefix}{op_id}.{fname}")
                }
            }
            None => format!("{prefix}{op_id}.{final_remote}"),
        }
    }

    fn staging_remote_path(&self, final_remote: &str, op_id: &str) -> String {
        self.sibling_temp_path(final_remote, PART_PREFIX, op_id)
    }

    fn backup_remote_path(&self, final_remote: &str, op_id: &str) -> String {
        self.sibling_temp_path(final_remote, BAK_PREFIX, op_id)
    }

    async fn acquire_conn(&self) -> Result<PooledSftpConn> {
        self.inner.pool.acquire(&self.inner.cfg).await
    }

    async fn ensure_parent_dirs(&self, rel: &RelPath) -> Result<()> {
        let Some(parent) = rel.parent() else {
            return Ok(());
        };
        if parent.is_root() {
            return Ok(());
        }
        self.mkdir(&parent).await
    }
}

#[async_trait]
impl StorageBackend for SftpBackend {
    fn name(&self) -> &str {
        &self.inner.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "sftp"
    }

    fn endpoint_identity(&self) -> String {
        format!(
            "sftp://{}@{}:{}/{}",
            self.inner.cfg.user, self.inner.cfg.host, self.inner.cfg.port, self.inner.root_norm
        )
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // SFTP v3 has no content-hash request (the `check-file` extension is rarely
            // implemented, and running `sha256sum` over the SSH channel would be a separate
            // exec privilege). So no hash is advertised, `compute_hash` returns `None`,
            // `Entry::checksum` is always `None`, and uploads and downloads are UNVERIFIED end
            // to end: only byte counts are enforced (strict upload length, exact download
            // length, staging-file size on resume). Nothing here may claim otherwise.
            hashes: vec![],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: 64 * 1024,
                max_chunk_bytes: None,
            },
            single_shot_max_bytes: self.inner.cfg.single_shot_max_bytes,
            default_chunk_size: self.inner.cfg.default_chunk_size,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
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

    /// SFTP exposes no remote content hash; see [`Self::capabilities`].
    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
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

    async fn about(&self) -> Result<Option<StorageQuota>> {
        self.about_impl().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::config::SftpAuth;
    use std::collections::HashSet;

    fn make_backend_with_root(root_path: &str) -> SftpBackend {
        let mut cfg = SftpConfig::new("r", "host.test", "alice", SftpAuth::Password("pw".into()));
        cfg.root_path = root_path.to_string();
        SftpBackend::new(cfg).unwrap()
    }

    #[test]
    fn preserves_root_slash_and_expands_tilde_root_paths() {
        let b_slash = make_backend_with_root("/");
        assert_eq!(b_slash.remote_path(""), "/");
        assert_eq!(b_slash.remote_path("etc/hosts"), "/etc/hosts");

        let b_tilde = make_backend_with_root("~");
        assert_eq!(b_tilde.remote_path(""), ".");
        assert_eq!(b_tilde.remote_path("a/b"), "a/b");

        let b_tilde_slash = make_backend_with_root("~/");
        assert_eq!(b_tilde_slash.remote_path(""), ".");
        assert_eq!(b_tilde_slash.remote_path("a"), "a");

        let b_tilde_sub = make_backend_with_root("~/backups/");
        assert_eq!(b_tilde_sub.remote_path(""), "backups");
        assert_eq!(b_tilde_sub.remote_path("file.tar"), "backups/file.tar");
    }

    #[test]
    fn endpoint_identity_is_pairwise_distinct_across_root_forms() {
        let ids: HashSet<String> = ["", "data", "/", "/data"]
            .into_iter()
            .map(|r| make_backend_with_root(r).endpoint_identity())
            .collect();
        assert_eq!(
            ids.len(),
            4,
            "expected 4 distinct endpoint identities: {ids:?}"
        );
    }
}
