//! Core `StorageBackend` trait and protocol-faithful resumable upload contracts.

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::filter::FilterSet;
use crate::path::RelPath;
use crate::source::{ByteStream, DataSource};
use crate::state::{DstPrecondition, OperationRecord};
use crate::types::{
    BackendKind, ByteRange, Capabilities, Checksum, Entry, EntryKind, HashKind, NodeId,
    StorageQuota, raw_path_override,
};

pub type EntryStream = Pin<Box<dyn Stream<Item = Result<Entry>> + Send>>;

/// One lexicographically ascending UTF-8 page returned by
/// [`StorageBackend::list_ordered_page`] for zero-disk streaming merge-join.
#[derive(Debug, Clone, Default)]
pub struct OrderedListPage {
    /// Entries under the requested `prefix`, with paths already stripped relative to `prefix`,
    /// in ascending raw UTF-8 wire order.
    pub entries: Vec<Entry>,
    /// True when more entries exist after this page under `prefix`.
    pub is_truncated: bool,
    /// Opaque continuation cursor for the next sequential page in this range scan.
    pub next_cursor: Option<String>,
    /// Raw UTF-8 key of the last object returned by the server (relative to `prefix`, retaining
    /// any trailing `'/'` on directory markers), used for Gear-2 midpoint bisection and
    /// `StartAfter` crash-resume watermarks.
    pub last_wire_key: Option<String>,
    /// True when the backend supports arbitrary client-supplied `start_after` keys (enabling
    /// Gear-2 parallel key-range bisection and `dir_pruner` fast-forward jumps).
    pub supports_start_after: bool,
}

/// Predicate invoked with a backend-relative directory [`RelPath`]; returning `true`
/// skips descending into that directory subtree entirely.
pub type DirPruner = Arc<dyn Fn(&RelPath) -> bool + Send + Sync>;

#[derive(Clone)]
struct PrunerSlot(DirPruner);

impl fmt::Debug for PrunerSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<dir_pruner>")
    }
}

impl PartialEq for PrunerSlot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for PrunerSlot {}

/// Extensible options controlling [`StorageBackend::list_with_options`].
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListOptions {
    /// Traverse nested subdirectories recursively (default: `true`).
    pub recursive: bool,
    /// Optional maximum directory depth relative to `prefix` (`Some(1)` = immediate children only).
    pub max_depth: Option<usize>,
    dir_pruner: Option<PrunerSlot>,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            max_depth: None,
            dir_pruner: None,
        }
    }
}

impl ListOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recursive() -> Self {
        Self {
            recursive: true,
            max_depth: None,
            dir_pruner: None,
        }
    }

    pub fn shallow() -> Self {
        Self {
            recursive: false,
            max_depth: Some(1),
            dir_pruner: None,
        }
    }

    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self.recursive = max_depth > 1;
        self
    }

    /// Effective maximum traversal depth relative to `prefix`.
    ///
    /// Explicit `max_depth` (including `Some(0)`) always takes precedence over `recursive`;
    /// when `max_depth` is `None`, non-recursive listings default to `Some(1)`.
    pub fn effective_max_depth(&self) -> Option<usize> {
        self.max_depth.or_else(|| (!self.recursive).then_some(1))
    }

    pub fn with_dir_pruner<F>(mut self, pruner: F) -> Self
    where
        F: Fn(&RelPath) -> bool + Send + Sync + 'static,
    {
        self.dir_pruner = Some(PrunerSlot(Arc::new(pruner)));
        self
    }

    pub fn with_shared_dir_pruner(mut self, pruner: Option<DirPruner>) -> Self {
        self.dir_pruner = pruner.map(PrunerSlot);
        self
    }

    /// Attach a prefix-aware directory pruner derived from `filter` when `filter` contains
    /// directory-prunable rules (`--exclude dir/`, `--files-from`, or leading `- dir/` rules).
    pub fn with_filter_pruning(mut self, filter: &FilterSet, prefix: &RelPath) -> Self {
        if !filter.has_dir_pruning() {
            return self;
        }
        let filter = filter.clone();
        let prefix_str = prefix.as_str().to_string();
        self.dir_pruner = Some(PrunerSlot(Arc::new(move |backend_dir: &RelPath| {
            let s = backend_dir.as_str();
            let rel_str = if prefix_str.is_empty() {
                s
            } else if s == prefix_str {
                return false;
            } else {
                let Some(rest) = s
                    .strip_prefix(prefix_str.as_str())
                    .and_then(|r| r.strip_prefix('/'))
                else {
                    return false;
                };
                rest
            };
            filter.should_prune_dir_str(rel_str)
        })));
        self
    }

    pub fn dir_pruner(&self) -> Option<&DirPruner> {
        self.dir_pruner.as_ref().map(|p| &p.0)
    }

    pub fn has_dir_pruner(&self) -> bool {
        self.dir_pruner.is_some()
    }

    #[inline]
    pub fn should_prune_dir(&self, backend_dir_path: &RelPath) -> bool {
        self.dir_pruner
            .as_ref()
            .is_some_and(|p| (p.0)(backend_dir_path))
    }
}

/// Address of an existing backend item: carries both exact `raw_path` (so reads
/// and deletes never fail on NFD keys) and canonical `nfc_path`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackendPath {
    /// Native backend key ONLY when it differs from `nfc_path` (zero allocation on NFC paths).
    /// Prefer [`BackendPath::raw_path()`] to read the effective raw path.
    pub raw_path: Option<Box<str>>,
    pub nfc_path: RelPath,
    pub node_id: Option<NodeId>,
    /// Optional known entry kind (`File`/`Directory`/`Symlink`), allowing object-store
    /// backends like S3 to skip redundant directory-marker probes during file deletes.
    pub kind: Option<EntryKind>,
}

impl BackendPath {
    pub fn new(raw_path: impl AsRef<str>, nfc_path: RelPath, node_id: Option<NodeId>) -> Self {
        let raw_path = raw_path_override(&nfc_path, raw_path.as_ref());
        Self {
            raw_path,
            nfc_path,
            node_id,
            kind: None,
        }
    }

    pub fn from_rel(nfc_path: RelPath) -> Self {
        Self {
            raw_path: None,
            nfc_path,
            node_id: None,
            kind: None,
        }
    }

    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            raw_path: entry.raw_path.clone(),
            nfc_path: entry.nfc_path.clone(),
            node_id: entry.node_id.clone(),
            kind: Some(entry.kind),
        }
    }

    /// Effective backend-native path (`raw_path` override if distinct, else `nfc_path`).
    #[inline]
    pub fn raw_path(&self) -> &str {
        self.raw_path.as_deref().unwrap_or(self.nfc_path.as_str())
    }

    /// Join a sync `prefix` with a relative `(raw_rel, nfc_rel)` pair with zero extra
    /// `raw_path` allocation whenever `raw_rel == nfc_rel.as_str()`.
    pub fn join_prefixed(
        prefix: &RelPath,
        raw_rel: &str,
        nfc_rel: &RelPath,
        node_id: Option<NodeId>,
        kind: Option<EntryKind>,
    ) -> Result<Self> {
        let full_nfc = if prefix.is_root() {
            nfc_rel.clone()
        } else if nfc_rel.is_root() {
            prefix.clone()
        } else {
            RelPath::parse(&format!("{}/{}", prefix.as_str(), nfc_rel.as_str()))?
        };
        let raw_path = if raw_rel == nfc_rel.as_str() {
            None
        } else if prefix.is_root() {
            raw_path_override(&full_nfc, raw_rel)
        } else if raw_rel.is_empty() {
            raw_path_override(&full_nfc, prefix.as_str())
        } else {
            let joined = format!("{}/{}", prefix.as_str(), raw_rel);
            raw_path_override(&full_nfc, &joined)
        };
        Ok(Self {
            raw_path,
            nfc_path: full_nfc,
            node_id,
            kind,
        })
    }

    pub fn with_node_id(mut self, node_id: Option<NodeId>) -> Self {
        self.node_id = node_id;
        self
    }

    pub fn with_kind(mut self, kind: Option<EntryKind>) -> Self {
        self.kind = kind;
        self
    }
}

impl From<RelPath> for BackendPath {
    fn from(rel: RelPath) -> Self {
        Self::from_rel(rel)
    }
}

impl From<&Entry> for BackendPath {
    fn from(entry: &Entry) -> Self {
        Self::from_entry(entry)
    }
}

impl fmt::Display for BackendPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.nfc_path.as_str())
    }
}

/// Parameters for initiating a single-shot or resumable upload.
#[derive(Debug, Clone)]
pub struct UploadInit {
    /// Unique operation ID generated BEFORE remote side effects (used for
    /// `.rship.part.<op_id>`, S3 `x-amz-meta-rship-op-id`, or idempotency).
    pub op_id: String,
    pub dst_path: RelPath,
    /// Existing destination node ID when overwriting an existing object
    /// (CRITICAL for Google Drive `PATCH /upload/drive/v3/files/{fileId}` so
    /// overwrites do not create duplicate sibling files).
    pub existing_node_id: Option<NodeId>,
    /// Optional pre-generated remote ID (e.g. GDrive `files.generateIds`).
    pub pregenerated_id: Option<NodeId>,
    pub total_size: u64,
    pub src_mtime_ns: i64,
    pub planned_chunk_size: u64,
    pub checksums: Vec<Checksum>,
    pub precondition: DstPrecondition,
    /// Optional source ETag / version tag for conditional server-side copies
    /// (e.g. S3 `x-amz-copy-source-if-match` preventing torn multipart copies).
    pub src_etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionInit {
    /// Backend-opaque resumable token (GDrive `session_uri`, S3 `UploadId`, Local part path).
    pub session_token: String,
    /// Backend-specific JSON metadata persisted verbatim in SQLite.
    pub backend_meta: String,
    /// Resolved remote identity when allocated at init time (e.g. GDrive fileId).
    pub remote_op_id: Option<String>,
    pub expires_at_unix_secs: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedPart {
    pub part_number: u32,
    pub offset: u64,
    pub length: u64,
    pub etag: String,
    pub checksum: Option<String>,
}

/// Live server upload progress queried during resume or error recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadProgress {
    /// Sequential backend (GDrive `308`, Local partial file) confirmed exact bytes `[0..offset)`.
    SequentialOffset(u64),
    /// Parallel-parts backend (S3 `ListParts`) confirmed completed parts.
    CompletedParts(Vec<CompletedPart>),
    /// Upload already finalized on server (e.g., lost final `200`/`201` response).
    AlreadyCompleted(Entry),
    /// Session expired / not found (`404`/`410`/`NoSuchUpload`) -> reconcile destination!
    Expired,
}

#[non_exhaustive]
pub struct ChunkUpload {
    pub part_number: u32,
    pub offset: u64,
    pub len: u64,
    pub total_size: u64,
    pub body: ByteStream,
}

impl ChunkUpload {
    pub fn new(part_number: u32, offset: u64, len: u64, total_size: u64, body: ByteStream) -> Self {
        Self {
            part_number,
            offset,
            len,
            total_size,
            body,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChunkAck {
    /// For sequential backends: next confirmed byte offset (`N + 1` from `308`).
    pub next_offset: Option<u64>,
    /// For parallel-parts backends: opaque part ETag.
    pub etag: Option<String>,
    /// Populated if this final chunk directly committed the object (e.g. GDrive `200`/`201`).
    pub completed: Option<Entry>,
    /// Optional backend-specific part checksum (e.g., S3 `"crc64nvme:<b64>"` or `"crc32c:<b64>"`)
    /// persisted on [`CompletedPart`] and echoed when finalizing multipart uploads.
    pub checksum: Option<String>,
}

/// Result of reconciling an ambiguous completion (crash or `404`/`NoSuchUpload`
/// after `completing` intent was recorded).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReconcileOutcome {
    /// Verified that this operation's object committed cleanly on destination.
    Committed(Entry),
    /// Confirmed object did NOT commit (safe to restart from scratch).
    NotCommitted,
    /// Destination contains conflicting or unverifiable state -> human/manual intervention.
    Ambiguous(String),
}

/// An incomplete remote multipart/resumable upload discovered during bucket/prefix GC
/// (e.g., S3 `ListMultipartUploads`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncompleteUpload {
    /// Backend-native full object key (e.g. `"prefix/file.bin"`).
    pub key: String,
    /// Backend-native upload session identifier (e.g. S3 `UploadId`).
    pub upload_id: String,
    /// Optional initiation timestamp in Unix seconds (used for `--older-than` filtering).
    pub initiated_unix_secs: Option<i64>,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Logical remote name (e.g. `"local"`, `"gdrive"`, `"r2"`).
    fn name(&self) -> &str;

    /// Driver type identifier (`"local"`, `"gdrive"`, `"s3"`, `"chaos"`).
    fn kind(&self) -> &'static str;

    /// Strongly-typed backend driver kind derived from [`Self::kind`].
    fn backend_kind(&self) -> BackendKind {
        BackendKind::parse(self.kind())
    }

    /// Stable identity string (endpoint + root/bucket/drive) scoped into journal keys.
    fn endpoint_identity(&self) -> String;

    fn capabilities(&self) -> Capabilities;

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>>;

    /// Stream entries under `prefix`. Implementations must respect `filter`
    /// directory pruning where applicable and never collect full trees in RAM.
    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream>;

    /// Stream entries under `prefix` using extensible [`ListOptions`] (recursive, max_depth, dir_pruner).
    async fn list_with_options(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let base_depth = prefix.segments().count();
        let max_depth = options.effective_max_depth();
        let pruner = options.dir_pruner().cloned();
        let stream = self.list_stream(prefix, options.recursive).await?;
        if max_depth.is_none() && pruner.is_none() {
            return Ok(stream);
        }
        let filtered = stream.filter(move |item| {
            let keep = match item {
                Ok(entry) => {
                    if let Some(limit) = max_depth {
                        let depth = entry.nfc_path.segments().count().saturating_sub(base_depth);
                        if depth > limit {
                            return std::future::ready(false);
                        }
                    }
                    if let Some(ref p) = pruner {
                        if entry.kind == EntryKind::Directory && p(&entry.nfc_path) {
                            return std::future::ready(false);
                        }
                        let mut anc = entry.nfc_path.parent();
                        while let Some(dir) = anc {
                            if dir.is_root() {
                                break;
                            }
                            if p(&dir) {
                                return std::future::ready(false);
                            }
                            anc = dir.parent();
                        }
                    }
                    true
                }
                Err(_) => true,
            };
            std::future::ready(keep)
        });
        Ok(Box::pin(filtered))
    }

    /// Fetch one lexicographically ascending UTF-8 page of entries strictly relative to `prefix`
    /// (with `delimiter = None`) for zero-disk streaming merge-join (`StreamingMergeDiffSource`).
    ///
    /// - `start_after`: optional exclusive lower-bound key relative to `prefix` (ignored when
    ///   `continuation` is `Some`).
    /// - `continuation`: opaque cursor returned in [`OrderedListPage::next_cursor`].
    async fn list_ordered_page(
        &self,
        prefix: &RelPath,
        start_after: Option<&str>,
        continuation: Option<&str>,
        max_keys: u32,
    ) -> Result<OrderedListPage> {
        let _ = (prefix, start_after, continuation, max_keys);
        Err(Error::unsupported(format!(
            "backend `{}` does not support ordered UTF-8 range listing",
            self.kind()
        )))
    }

    /// Preferred Gear-2 parallel key-range listing concurrency for this backend (default: `1`).
    fn ordered_list_concurrency(&self) -> usize {
        1
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()>;

    async fn delete(&self, path: &BackendPath) -> Result<()>;

    /// Delete a batch of paths (files or directory markers).
    ///
    /// Backends with native bulk-delete APIs (e.g., S3 `DeleteObjects`, up to 1,000 keys/request)
    /// override this method. The default executes bounded concurrent `delete()` calls (16 in flight).
    /// Returns `(path, error)` entries ONLY for items that failed to delete.
    async fn delete_batch(&self, paths: &[BackendPath]) -> Result<Vec<(BackendPath, Error)>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let failures = futures::stream::iter(paths.iter().cloned())
            .map(|bp| async move {
                match self.delete(&bp).await {
                    Ok(()) => None,
                    Err(e) => Some((bp, e)),
                }
            })
            .buffer_unordered(16)
            .filter_map(|opt| async move { opt })
            .collect::<Vec<_>>()
            .await;
        Ok(failures)
    }

    /// Compute or fetch a file's checksum when supported.
    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>>;

    /// Open a file for reading. `range` enables resumable downloads and zero-RAM
    /// cloud-to-cloud `RemoteRangeReadable` relays.
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource>;

    /// Open an already-observed file entry for reading, allowing backends to construct
    /// range readers directly from `entry.size`, `entry.etag`, and `entry.node_id` without
    /// issuing a redundant `HEAD` / `stat` RPC.
    async fn open_read_entry(
        &self,
        _entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        self.open_read(path, range).await
    }

    /// Single-shot fast-path write for small files (`<= single_shot_max_bytes`).
    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry>;

    /// Optionally pre-generate and return a backend-native destination node/operation ID
    /// BEFORE executing an upload or server-side copy.
    ///
    /// Backends with duplicate-name semantics (e.g. Google Drive `files.generateIds`)
    /// implement this so the engine can persist `OperationRecord::remote_op_id` into the
    /// write-ahead journal BEFORE the first remote side effect — allowing crash recovery
    /// to reconcile via deterministic ID lookup (`files.get(id)`) with zero duplicates.
    async fn prepare_operation_id(&self, _init: &UploadInit) -> Result<Option<NodeId>> {
        Ok(None)
    }

    /// Whether a committed write can become visible (listed, `stat`-able, returned as an
    /// [`Entry`]) before its data is durable, until [`Self::flush_durable_writes`] runs.
    ///
    /// `true` for `LocalBackend` in [`crate::types::FsyncMode::Batch`] mode. The engine then
    /// holds back every journal record that would let a later run trust such a file
    /// (baseline rows, operation retirement, a finished job status) until the flush has
    /// succeeded. Wrappers must forward this to the backend they wrap.
    fn defers_durable_writes(&self) -> bool {
        false
    }

    /// Shared retry budget for this backend's `(remote, principal)` scope, if it keeps one.
    ///
    /// The engine draws its own transfer-level retries from this quota when the run has
    /// no explicit [`crate::engine::EngineConfig::retry_quota`], so engine retries and the
    /// backend's HTTP-level retries share one budget per remote account instead of each
    /// run (or each file) starting with a fresh bucket. `None` (the default) makes the
    /// engine fall back to one token bucket per run.
    fn retry_quota(&self) -> Option<std::sync::Arc<dyn crate::engine::RetryQuota>> {
        None
    }

    /// Flush any deferred non-fsynced writes on this backend so committed files become
    /// durable on stable storage (e.g. `LocalBackend` in [`crate::types::FsyncMode::Batch`]
    /// mode calls `syncfs` on Linux, `FlushFileBuffers` on Windows, and file/dir `fsync` on
    /// macOS). No-op for cloud backends and for `LocalBackend` in `Always` or `Never` mode.
    async fn flush_durable_writes(&self) -> Result<()> {
        Ok(())
    }

    /// Force a single committed file (and its parent directory on POSIX) to be durably
    /// synced to stable storage BEFORE any source deletion (`move` / `bisync`), regardless
    /// of the backend's configured `--fsync` batching mode.
    async fn sync_durable_file(&self, _path: &BackendPath) -> Result<()> {
        Ok(())
    }

    /// Resumable upload primitive 1: initiate remote upload session.
    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit>;

    /// Resumable upload primitive 2: query live server state on resume/recovery.
    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress>;

    /// Resumable upload primitive 3: stream one protocol chunk / part.
    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck>;

    /// Resumable upload primitive 4: finalize multipart/staged upload.
    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry>;

    /// Resumable upload primitive 5: clean up an aborted or superseded session.
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()>;

    /// Reconcile an ambiguous commit (e.g. crash during `completing` state or
    /// `404`/`NoSuchUpload` after final chunk).
    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome>;

    /// Whether this backend can execute a zero-local-bandwidth server-side copy
    /// from an object residing on `src_endpoint`.
    fn can_server_side_copy_from(&self, _src_endpoint: &str) -> bool {
        false
    }

    /// Attempt a zero-local-bandwidth server-side copy from `(src_endpoint, src_path)`
    /// into `init.dst_path`.
    ///
    /// Returns `Ok(Some(entry))` if the server-side copy committed, or `Ok(None)`
    /// if the transfer should fall back transparently to streaming relay.
    async fn server_side_copy(
        &self,
        _src_endpoint: &str,
        _src_path: &BackendPath,
        _init: &UploadInit,
    ) -> Result<Option<Entry>> {
        Ok(None)
    }

    /// Optional storage capacity & quota inquiry (`rship about`).
    async fn about(&self) -> Result<Option<StorageQuota>> {
        Ok(None)
    }

    /// Optional server-side in-place rename within the same parent directory
    /// (zero data transfer; used by `rship dedupe --mode rename` and fast local/cloud renames).
    ///
    /// Backends that do not support in-place rename return `ErrorKind::Unsupported`.
    async fn rename(&self, _path: &BackendPath, _new_name: &str) -> Result<Entry> {
        Err(Error::new(
            crate::ErrorKind::Unsupported,
            crate::RetryClass::Permanent,
            format!(
                "backend `{}` does not support server-side rename",
                self.kind()
            ),
        ))
    }

    /// List incomplete remote multipart/resumable uploads under `prefix` for `rship gc --remote-multipart`.
    async fn list_incomplete_uploads(&self, _prefix: &RelPath) -> Result<Vec<IncompleteUpload>> {
        Err(Error::unsupported(format!(
            "backend `{}` does not support remote multipart upload GC",
            self.kind()
        )))
    }

    /// Abort one incomplete remote multipart/resumable upload returned by [`Self::list_incomplete_uploads`].
    async fn abort_incomplete_upload(&self, _upload: &IncompleteUpload) -> Result<()> {
        Err(Error::unsupported(format!(
            "backend `{}` does not support remote multipart upload GC",
            self.kind()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListBackend {
        entries: Vec<Entry>,
    }

    #[async_trait]
    impl StorageBackend for MockListBackend {
        fn name(&self) -> &str {
            "mock"
        }

        fn kind(&self) -> &'static str {
            "mock"
        }

        fn endpoint_identity(&self) -> String {
            "mock://test".to_string()
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }

        async fn stat(&self, _path: &BackendPath) -> Result<Option<Entry>> {
            Ok(None)
        }

        async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
            let prefix_str = prefix.as_str();
            let prefix_depth = prefix.segments().count();
            let items: Vec<Result<Entry>> = self
                .entries
                .iter()
                .filter(|e| {
                    let s = e.nfc_path.as_str();
                    let under = if prefix_str.is_empty() {
                        !s.is_empty()
                    } else {
                        s.strip_prefix(prefix_str)
                            .is_some_and(|rest| rest.starts_with('/'))
                    };
                    if !under {
                        return false;
                    }
                    if recursive {
                        true
                    } else {
                        e.nfc_path.segments().count().saturating_sub(prefix_depth) <= 1
                    }
                })
                .cloned()
                .map(Ok)
                .collect();
            Ok(Box::pin(futures::stream::iter(items)))
        }

        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }

        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }

        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }

        async fn open_read(
            &self,
            _path: &BackendPath,
            _range: Option<ByteRange>,
        ) -> Result<DataSource> {
            Err(Error::unsupported("mock"))
        }

        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            Err(Error::unsupported("mock"))
        }

        async fn begin_upload(&self, _init: &UploadInit) -> Result<UploadSessionInit> {
            Err(Error::unsupported("mock"))
        }

        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Err(Error::unsupported("mock"))
        }

        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            _chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            Err(Error::unsupported("mock"))
        }

        async fn finish_upload(
            &self,
            _op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            Err(Error::unsupported("mock"))
        }

        async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
            Ok(())
        }

        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Err(Error::unsupported("mock"))
        }
    }

    fn mk_entry(path: &str, kind: EntryKind) -> Entry {
        let rel = RelPath::parse(path).unwrap();
        match kind {
            EntryKind::Directory => Entry::dir(rel, 0),
            _ => Entry::file(rel, 0, 0),
        }
    }

    #[test]
    fn list_options_effective_max_depth_handles_all_combinations() {
        let def = ListOptions::default();
        assert!(def.recursive);
        assert_eq!(def.effective_max_depth(), None);

        let rec = ListOptions::recursive();
        assert!(rec.recursive);
        assert_eq!(rec.effective_max_depth(), None);

        let shallow = ListOptions::shallow();
        assert!(!shallow.recursive);
        assert_eq!(shallow.effective_max_depth(), Some(1));

        let non_rec = ListOptions::new().with_recursive(false);
        assert!(!non_rec.recursive);
        assert_eq!(non_rec.effective_max_depth(), Some(1));

        let d0 = ListOptions::new().with_max_depth(0);
        assert!(!d0.recursive);
        assert_eq!(d0.effective_max_depth(), Some(0));

        let d0_after_rec = ListOptions::new().with_recursive(true).with_max_depth(0);
        assert!(!d0_after_rec.recursive);
        assert_eq!(d0_after_rec.effective_max_depth(), Some(0));

        let rec_after_d0 = ListOptions::new().with_max_depth(0).with_recursive(true);
        assert!(rec_after_d0.recursive);
        assert_eq!(rec_after_d0.effective_max_depth(), Some(0));

        let d1 = ListOptions::new().with_max_depth(1);
        assert!(!d1.recursive);
        assert_eq!(d1.effective_max_depth(), Some(1));

        let d2 = ListOptions::new().with_max_depth(2);
        assert!(d2.recursive);
        assert_eq!(d2.effective_max_depth(), Some(2));

        let shallow_then_d2 = ListOptions::shallow().with_max_depth(2);
        assert!(shallow_then_d2.recursive);
        assert_eq!(shallow_then_d2.effective_max_depth(), Some(2));
    }

    #[tokio::test]
    async fn default_list_with_options_enforces_max_depth_zero_one_two_and_shallow() {
        let backend = MockListBackend {
            entries: vec![
                mk_entry("a.txt", EntryKind::File),
                mk_entry("sub", EntryKind::Directory),
                mk_entry("sub/b.txt", EntryKind::File),
                mk_entry("sub/deep", EntryKind::Directory),
                mk_entry("sub/deep/c.txt", EntryKind::File),
            ],
        };

        async fn collect_paths(
            backend: &MockListBackend,
            opts: ListOptions,
            prefix: RelPath,
        ) -> Vec<String> {
            let mut stream = backend.list_with_options(&prefix, &opts).await.unwrap();
            let mut out = Vec::new();
            while let Some(item) = stream.next().await {
                out.push(item.unwrap().nfc_path.as_str().to_string());
            }
            out
        }

        assert!(
            collect_paths(
                &backend,
                ListOptions::new().with_max_depth(0),
                RelPath::root()
            )
            .await
            .is_empty()
        );
        assert!(
            collect_paths(
                &backend,
                ListOptions::new().with_max_depth(0),
                RelPath::parse("sub").unwrap(),
            )
            .await
            .is_empty()
        );
        assert_eq!(
            collect_paths(
                &backend,
                ListOptions::new().with_recursive(false),
                RelPath::root()
            )
            .await,
            vec!["a.txt", "sub"]
        );
        assert_eq!(
            collect_paths(
                &backend,
                ListOptions::new().with_max_depth(1),
                RelPath::root()
            )
            .await,
            vec!["a.txt", "sub"]
        );
        assert_eq!(
            collect_paths(
                &backend,
                ListOptions::shallow().with_max_depth(2),
                RelPath::root()
            )
            .await,
            vec!["a.txt", "sub", "sub/b.txt", "sub/deep"]
        );
    }
}
