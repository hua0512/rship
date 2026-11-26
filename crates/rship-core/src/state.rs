//! Durable write-ahead operation journal, dual-side baseline, and disk-backed
//! sync diff index trait contracts (implemented by `rship-state` on SQLite).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

/// Lazily-materialized per-job ephemeral scratch directory provider (implemented by
/// `rship_state::LazyRunDir`) so engine subsystems (`--strict-source`, `DeleteSpillLog`)
/// never touch the filesystem on small/normal runs while still cleaning up atomically
/// on `Drop` and `SIGKILL` crash sweeps.
#[async_trait]
pub trait RunScratchDir: fmt::Debug + Send + Sync {
    /// Lazily create and return the scratch subdirectory `name`.
    ///
    /// Async so implementations can wait for contended locks without blocking the executor
    /// thread (which would stall a `current_thread` runtime entirely).
    async fn ensure_subdir(&self, name: &str) -> Result<PathBuf>;
}

use crate::backend::CompletedPart;
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::types::{Entry, EntryKind, HashKind, NodeId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationState {
    /// Persisted BEFORE the first remote side effect.
    Intent,
    /// Remote session opened (`session_token` persisted).
    Active,
    /// Persisted BEFORE issuing the final commit request (single-shot, final GDrive PUT, or S3 Complete).
    Completing,
    /// Verified destination commit; ready for retirement.
    Verified,
    Aborted,
    Expired,
    NeedsReconciliation,
    /// Journal marker (not a transfer session): the destination object at this
    /// `(source, destination)` pair failed checksum verification and could not be removed
    /// (delete failed, or the corrupt upload replaced a pre-existing version). Until a
    /// verified transfer clears it, planned skips of this path become fresh transfers,
    /// so neither a baseline nor a `move` source delete can trust the corrupt object.
    /// Stored under [`integrity_marker_key`]`(session_key)`.
    IntegrityFailed,
}

/// Session key of the [`OperationState::IntegrityFailed`] marker for `session_key`.
pub fn integrity_marker_key(session_key: &str) -> String {
    format!("integrity:{session_key}")
}

/// Whether `entry` (observed on the marker's destination side) may still be the corrupt
/// object recorded by an [`OperationState::IntegrityFailed`] `marker`. Unknown identity
/// counts as a match (conservative).
pub fn integrity_marker_matches(marker: &OperationRecord, entry: &crate::types::Entry) -> bool {
    match &marker.dst_precondition {
        DstPrecondition::Existing {
            etag,
            size,
            mtime_ns,
            ..
        } => match (etag, &entry.etag) {
            (Some(recorded), Some(current)) => recorded == current,
            _ => *size == entry.size && *mtime_ns == entry.mtime_ns,
        },
        _ => true,
    }
}

impl OperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Active => "active",
            Self::Completing => "completing",
            Self::Verified => "verified",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
            Self::NeedsReconciliation => "needs_reconciliation",
            Self::IntegrityFailed => "integrity_failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "intent" => Some(Self::Intent),
            "active" => Some(Self::Active),
            "completing" => Some(Self::Completing),
            "verified" => Some(Self::Verified),
            "aborted" => Some(Self::Aborted),
            "expired" => Some(Self::Expired),
            "needs_reconciliation" => Some(Self::NeedsReconciliation),
            "integrity_failed" => Some(Self::IntegrityFailed),
            _ => None,
        }
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OperationState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown operation state `{s}`")))
    }
}

/// Source version tuple bound across retries and checked before final commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVersion {
    pub node_id: Option<NodeId>,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: Option<i64>,
    pub etag: Option<String>,
}

impl SourceVersion {
    pub fn from_entry(e: &Entry) -> Self {
        Self {
            node_id: e.node_id.clone(),
            size: e.size,
            mtime_ns: e.mtime_ns,
            ctime_ns: e.ctime_ns,
            etag: e.etag.clone(),
        }
    }
}

/// Expected destination state authorizing an upload/overwrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DstPrecondition {
    Any,
    Absent,
    Existing {
        node_id: Option<NodeId>,
        etag: Option<String>,
        mtime_ns: i64,
        size: u64,
    },
}

impl DstPrecondition {
    /// Whether the destination may already exist under this precondition (anything but
    /// [`Self::Absent`]).
    pub fn may_exist(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// Durable write-ahead journal entry for one file transfer operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub op_id: String,
    pub session_key: String,
    pub job_id: String,
    pub src_endpoint: String,
    pub dst_endpoint: String,
    pub src_raw_path: String,
    pub dst_raw_path: String,
    pub dst_nfc_path: RelPath,
    pub src_version: SourceVersion,
    pub dst_precondition: DstPrecondition,
    pub existing_dst_node_id: Option<NodeId>,
    pub remote_op_id: Option<String>,
    pub backend_kind: String,
    pub session_token: Option<String>,
    pub backend_meta: String,
    pub planned_chunk_size: u64,
    pub confirmed_offset: u64,
    pub state: OperationState,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

/// Dual-side verified baseline record (`sync_baseline`) storing BOTH source and
/// destination metadata so S3 server-assigned `LastModified`/`ETag` never cause
/// false diffs and future `bisync` has a complete merge-base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub pair_key: String,
    pub nfc_path: RelPath,
    pub kind: EntryKind,
    pub src_node_id: Option<NodeId>,
    pub dst_node_id: Option<NodeId>,
    pub size: u64,
    pub src_mtime_ns: i64,
    pub dst_mtime_ns: i64,
    pub dst_etag: Option<String>,
    pub hash_kind: Option<HashKind>,
    pub hash_hex: Option<String>,
    pub updated_at: i64,
}

/// Durable per-pair bisync guard metadata (`bisync_state` in `journal.db`) tracking
/// the last committed filter fingerprint and post-sync file counts so filter drift
/// or an unmounted/empty side cannot silently wipe the peer tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisyncPairState {
    pub pair_key: String,
    pub filter_hash: String,
    pub last_a_files: u64,
    pub last_b_files: u64,
    pub updated_at: i64,
}

/// Controls when verified transfers write durable `sync_baseline` rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BaselineMode {
    /// Persist baseline rows only when incremental re-runs need them:
    /// never on `move`, skipped when destination preserves mtime or both sides
    /// expose matching full-object non-multipart checksums, persisted otherwise
    /// (e.g. `local -> S3`, multipart S3 objects with composite ETags).
    #[default]
    Auto,
    /// Always persist a `sync_baseline` row for every verified transfer.
    All,
    /// Never read or write `sync_baseline` rows (stateless / one-shot migration).
    None,
}

impl BaselineMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::All => "all",
            Self::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "all" => Some(Self::All),
            "none" | "off" => Some(Self::None),
            _ => None,
        }
    }
}

impl fmt::Display for BaselineMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BaselineMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown baseline mode `{s}`")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobMode {
    Copy,
    Sync,
    Move,
}

impl JobMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Sync => "sync",
            Self::Move => "move",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "copy" => Some(Self::Copy),
            "sync" => Some(Self::Sync),
            "move" => Some(Self::Move),
            _ => None,
        }
    }
}

impl fmt::Display for JobMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown job mode `{s}`")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobStatus {
    Running,
    Paused,
    Completed,
    CompletedWithConflicts,
    Failed,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::CompletedWithConflicts => "completed_with_conflicts",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "running" => Some(Self::Running),
            "paused" => Some(Self::Paused),
            "completed" => Some(Self::Completed),
            "completed_with_conflicts" => Some(Self::CompletedWithConflicts),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown job status `{s}`")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: String,
    pub mode: JobMode,
    pub src_spec: String,
    pub dst_spec: String,
    pub status: JobStatus,
    pub files_total: u64,
    pub files_done: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub created_at: i64,
    pub updated_at: i64,
    /// Optional serialized JSON of CLI/engine run options so `rship resume <job_id>`
    /// restores original filters, chunking, strict-source, and move flags faithfully.
    #[serde(default)]
    pub options_json: Option<String>,
    /// Safe `StartAfter` watermark key strictly preceding all in-flight or failed keys in
    /// streaming object-store transfers, enabling O(1) crash-resume skipping millions of keys.
    #[serde(default)]
    pub resume_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConflictKind {
    DuplicateSourceName,
    DuplicateDestinationName,
    UnicodeNfcCollision,
    CaseInsensitiveCollision,
    TypeFlipFileOverDir,
    TypeFlipDirOverFile,
    ConcurrentBisyncEdit,
    ModifyDeleteConflict,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateSourceName => "duplicate_source_name",
            Self::DuplicateDestinationName => "duplicate_destination_name",
            Self::UnicodeNfcCollision => "unicode_nfc_collision",
            Self::CaseInsensitiveCollision => "case_insensitive_collision",
            Self::TypeFlipFileOverDir => "type_flip_file_over_dir",
            Self::TypeFlipDirOverFile => "type_flip_dir_over_file",
            Self::ConcurrentBisyncEdit => "concurrent_bisync_edit",
            Self::ModifyDeleteConflict => "modify_delete_conflict",
        }
    }
}

impl fmt::Display for ConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflict {
    pub nfc_path: RelPath,
    pub kind: ConflictKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DiffRow {
    pub row_id: i64,
    pub src: Option<Entry>,
    pub dst: Option<Entry>,
}

/// Deterministic key identifying a `(src_endpoint, src_path, dst_endpoint, dst_path)` pair.
pub fn compute_session_key(
    src_endpoint: &str,
    src_raw_path: &str,
    dst_endpoint: &str,
    dst_nfc_path: &RelPath,
) -> String {
    let mut h = Sha256::new();
    h.update(src_endpoint.as_bytes());
    h.update([0u8]);
    h.update(src_raw_path.as_bytes());
    h.update([0u8]);
    h.update(dst_endpoint.as_bytes());
    h.update([0u8]);
    h.update(dst_nfc_path.as_str().as_bytes());
    hex::encode(h.finalize())
}

pub fn compute_pair_key(src_endpoint: &str, dst_endpoint: &str) -> String {
    let mut h = Sha256::new();
    h.update(src_endpoint.as_bytes());
    h.update([0u8]);
    h.update(dst_endpoint.as_bytes());
    hex::encode(h.finalize())
}

/// Durable journal & baseline contract implemented by `rship-state::StateActor`.
#[async_trait]
pub trait JournalStore: Send + Sync {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()>;
    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>>;
    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>>;

    /// Persist write-ahead intent BEFORE any remote mutation.
    async fn put_operation(&self, op: &OperationRecord) -> Result<()>;
    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>>;
    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>>;
    async fn delete_operation(&self, op_id: &str) -> Result<()>;

    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()>;
    async fn list_parts(&self, op_id: &str) -> Result<Vec<CompletedPart>>;

    /// Atomically commit verified transfer result: optionally upsert `sync_baseline`,
    /// optionally delete retired operation (cascading parts), and increment job counters.
    async fn commit_verified_transfer(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()>;

    /// Same as [`Self::commit_verified_transfer`], for a destination file whose data the
    /// caller has already made durable (e.g. `StorageBackend::sync_durable_file` before a
    /// `move` deletes its source).
    ///
    /// Durability-fencing wrappers (the engine's `DurabilityFence`) hold ordinary commits
    /// back until the next destination flush; this variant is written immediately, so it is
    /// durable before the caller goes on to delete the source.
    async fn commit_verified_transfer_durable(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()> {
        self.commit_verified_transfer(op_id, baseline, job_id, bytes_transferred)
            .await
    }

    async fn get_baseline(
        &self,
        pair_key: &str,
        nfc_path: &RelPath,
    ) -> Result<Option<BaselineRecord>>;

    /// Fetch multiple baseline records for `pair_key` in a single round-trip.
    async fn get_baselines_batch(
        &self,
        pair_key: &str,
        nfc_paths: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        let mut out = HashMap::with_capacity(nfc_paths.len());
        for p in nfc_paths {
            if let Some(b) = self.get_baseline(pair_key, p).await? {
                out.insert(p.clone(), b);
            }
        }
        Ok(out)
    }

    async fn delete_baseline(&self, pair_key: &str, nfc_path: &RelPath) -> Result<()>;

    /// Delete multiple baseline records for `pair_key` in a single batched transaction.
    async fn delete_baselines_batch(&self, pair_key: &str, nfc_paths: &[RelPath]) -> Result<()> {
        for p in nfc_paths {
            self.delete_baseline(pair_key, p).await?;
        }
        Ok(())
    }

    /// Delete all baseline rows for `pair_key` (used by `bisync --resync` to reset a pair's merge-base).
    async fn delete_pair_baselines(&self, pair_key: &str) -> Result<()> {
        let _ = pair_key;
        Err(crate::error::Error::unsupported(
            "JournalStore::delete_pair_baselines is not implemented for this store",
        ))
    }

    /// Forward cursor pagination over `sync_baseline` rows for `pair_key` in ascending
    /// `nfc_path` order (`WHERE nfc_path > after_nfc_path ORDER BY nfc_path LIMIT limit`).
    async fn next_baseline_page(
        &self,
        pair_key: &str,
        after_nfc_path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        let _ = (pair_key, after_nfc_path, limit);
        Err(crate::error::Error::unsupported(
            "JournalStore::next_baseline_page is not implemented for this store",
        ))
    }

    /// Read durable bisync safety metadata (last filter fingerprint + file counts) for `pair_key`.
    async fn get_bisync_state(&self, pair_key: &str) -> Result<Option<BisyncPairState>> {
        let _ = pair_key;
        Err(crate::error::Error::unsupported(
            "JournalStore::get_bisync_state is not implemented for this store",
        ))
    }

    /// Persist durable bisync safety metadata for `pair_key` after a completed run.
    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        let _ = state;
        Err(crate::error::Error::unsupported(
            "JournalStore::upsert_bisync_state is not implemented for this store",
        ))
    }
}

/// Disk-backed ephemeral per-run observation & diff index.
///
/// Crucially stores entries by surrogate row ID (NOT unique `rel_path PRIMARY KEY`)
/// with non-unique `nfc_path` and `fold_path` indexes built after bulk load.
#[async_trait]
pub trait SyncDiffIndex: Send + Sync {
    async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()>;
    async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()>;

    /// Build post-load non-unique indexes and compute duplicate/NFC/case collisions.
    async fn finalize_and_detect_conflicts(
        &self,
        dst_case_sensitive: bool,
    ) -> Result<Vec<SyncConflict>>;

    async fn list_conflicts(&self) -> Result<Vec<SyncConflict>>;

    /// Keyset-paginated source pass (`WHERE s.id > after_id ORDER BY s.id LIMIT limit`).
    async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>>;

    /// Keyset-paginated destination-only pass (`WHERE d.id > after_id AND no matching src`).
    async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>>;
}

/// Scope key isolating incremental delta change tokens and ID-keyed node graphs by
/// `(remote_name, principal, corpus_id, root_id)` (e.g. Google Drive `changes.list`,
/// OneDrive `/delta`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeltaScope {
    pub remote_name: String,
    pub principal: String,
    pub corpus_id: String,
    pub root_id: String,
}

/// Durable ID-keyed cloud node record persisted in the local delta inventory cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaNodeRecord {
    pub file_id: String,
    pub parent_id: Option<String>,
    pub raw_name: String,
    pub nfc_name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_ns: i64,
    pub md5: Option<String>,
    pub trashed: bool,
    pub generation: i64,
    pub updated_at: i64,
}

/// Atomic mutation batch applied to the delta node graph and change token in a
/// single durable SQLite transaction.
#[derive(Debug, Clone, Default)]
pub struct DeltaChangeBatch {
    pub upserts: Vec<DeltaNodeRecord>,
    /// Individual `file_id`s to delete from the node graph.
    pub remove_file_ids: Vec<String>,
    /// Root `file_id`s whose entire descendant subtrees (and themselves) must be evicted.
    pub evict_subtree_root_ids: Vec<String>,
    /// If `Some`, atomically publishes `new_start_page_token`.
    pub new_start_page_token: Option<String>,
    pub updated_at: i64,
}

/// Provider-agnostic durable ID-keyed delta inventory & change-feed token persistence contract.
#[async_trait]
pub trait DeltaInventoryStore: Send + Sync {
    async fn get_change_token(&self, scope: &DeltaScope) -> Result<Option<String>>;

    /// Atomically apply node upserts, removals, recursive subtree evictions, and
    /// optional change-token update in ONE durable transaction.
    async fn apply_change_batch(&self, scope: &DeltaScope, batch: DeltaChangeBatch) -> Result<()>;

    async fn get_node(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_id: &str,
    ) -> Result<Option<DeltaNodeRecord>>;

    /// Fetch multiple live delta node records by `file_id` in a single round-trip.
    async fn get_nodes_batch(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_ids: &[String],
    ) -> Result<HashMap<String, DeltaNodeRecord>> {
        let mut out = HashMap::with_capacity(file_ids.len());
        for fid in file_ids {
            if let Some(node) = self.get_node(remote_name, corpus_id, fid).await?
                && !node.trashed
            {
                out.insert(fid.clone(), node);
            }
        }
        Ok(out)
    }

    async fn list_children(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>>;

    async fn find_children_by_name(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
        name: &str,
    ) -> Result<Vec<DeltaNodeRecord>>;

    async fn list_all_nodes(
        &self,
        remote_name: &str,
        corpus_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>>;

    async fn clear_inventory(&self, scope: &DeltaScope) -> Result<()>;
}

#[derive(Debug, Default)]
struct MemoryJournalInner {
    jobs: HashMap<String, JobRecord>,
    ops: HashMap<String, OperationRecord>,
    parts: HashMap<String, Vec<CompletedPart>>,
    baselines: HashMap<(String, RelPath), BaselineRecord>,
    bisync_states: HashMap<String, BisyncPairState>,
}

/// Ephemeral, SQLite-free in-memory [`JournalStore`] for stateless transfers,
/// minimal SDK builds (`--no-default-features`), and deterministic tests.
#[derive(Debug, Default)]
pub struct MemoryJournalStore {
    inner: Mutex<MemoryJournalInner>,
}

impl MemoryJournalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl JournalStore for MemoryJournalStore {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        g.jobs.insert(job.job_id.clone(), job.clone());
        Ok(())
    }

    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        Ok(g.jobs.get(job_id).cloned())
    }

    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        let mut jobs: Vec<JobRecord> = g.jobs.values().cloned().collect();
        jobs.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| b.created_at.cmp(&a.created_at))
        });
        jobs.truncate(limit);
        Ok(jobs)
    }

    async fn put_operation(&self, op: &OperationRecord) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        if op.session_token.is_none() && op.state == OperationState::Intent {
            g.parts.remove(&op.op_id);
        }
        g.ops.insert(op.op_id.clone(), op.clone());
        Ok(())
    }

    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        Ok(g.ops
            .values()
            .filter(|op| op.session_key == session_key)
            .max_by_key(|op| op.updated_at)
            .cloned())
    }

    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        let mut ops: Vec<OperationRecord> = g.ops.values().cloned().collect();
        ops.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
        Ok(ops)
    }

    async fn delete_operation(&self, op_id: &str) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        g.ops.remove(op_id);
        g.parts.remove(op_id);
        Ok(())
    }

    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        let list = g.parts.entry(op_id.to_string()).or_default();
        if let Some(existing) = list.iter_mut().find(|p| p.part_number == part.part_number) {
            *existing = part.clone();
        } else {
            list.push(part.clone());
            list.sort_by_key(|p| p.part_number);
        }
        Ok(())
    }

    async fn list_parts(&self, op_id: &str) -> Result<Vec<CompletedPart>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        Ok(g.parts.get(op_id).cloned().unwrap_or_default())
    }

    async fn commit_verified_transfer(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        if let Some(base) = baseline {
            g.baselines
                .insert((base.pair_key.clone(), base.nfc_path.clone()), base.clone());
        }
        if let Some(id) = op_id {
            g.ops.remove(id);
            g.parts.remove(id);
        }
        if let Some(job) = g.jobs.get_mut(job_id) {
            job.files_done = job.files_done.saturating_add(1);
            job.bytes_done = job.bytes_done.saturating_add(bytes_transferred);
            if let Some(base) = baseline {
                job.updated_at = job.updated_at.max(base.updated_at);
            }
        }
        Ok(())
    }

    async fn get_baseline(
        &self,
        pair_key: &str,
        nfc_path: &RelPath,
    ) -> Result<Option<BaselineRecord>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        Ok(g.baselines
            .get(&(pair_key.to_string(), nfc_path.clone()))
            .cloned())
    }

    async fn get_baselines_batch(
        &self,
        pair_key: &str,
        nfc_paths: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        if nfc_paths.is_empty() {
            return Ok(HashMap::new());
        }
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        let mut out = HashMap::with_capacity(nfc_paths.len());
        let pk = pair_key.to_string();
        for p in nfc_paths {
            if let Some(rec) = g.baselines.get(&(pk.clone(), p.clone())) {
                out.insert(p.clone(), rec.clone());
            }
        }
        Ok(out)
    }

    async fn delete_baseline(&self, pair_key: &str, nfc_path: &RelPath) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        g.baselines
            .remove(&(pair_key.to_string(), nfc_path.clone()));
        Ok(())
    }

    async fn delete_baselines_batch(&self, pair_key: &str, nfc_paths: &[RelPath]) -> Result<()> {
        if nfc_paths.is_empty() {
            return Ok(());
        }
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        let pk = pair_key.to_string();
        for p in nfc_paths {
            g.baselines.remove(&(pk.clone(), p.clone()));
        }
        Ok(())
    }

    async fn delete_pair_baselines(&self, pair_key: &str) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        g.baselines.retain(|(pk, _), _| pk != pair_key);
        Ok(())
    }

    async fn next_baseline_page(
        &self,
        pair_key: &str,
        after_nfc_path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        let mut rows: Vec<BaselineRecord> = g
            .baselines
            .iter()
            .filter(|((pk, nfc), _)| {
                pk == pair_key && after_nfc_path.is_none_or(|after| nfc.as_str() > after)
            })
            .map(|(_, rec)| rec.clone())
            .collect();
        rows.sort_by(|a, b| a.nfc_path.as_str().cmp(b.nfc_path.as_str()));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn get_bisync_state(&self, pair_key: &str) -> Result<Option<BisyncPairState>> {
        let g = self.inner.lock().expect("memory journal mutex poisoned");
        Ok(g.bisync_states.get(pair_key).cloned())
    }

    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        let mut g = self.inner.lock().expect("memory journal mutex poisoned");
        g.bisync_states
            .insert(state.pair_key.clone(), state.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemorySyncIndexInner {
    src: Vec<(i64, Entry)>,
    dst: Vec<(i64, Entry)>,
    src_nfc: HashSet<RelPath>,
    dst_by_nfc: HashMap<RelPath, Entry>,
    conflicts: Vec<SyncConflict>,
}

/// Ephemeral, SQLite-free in-memory [`SyncDiffIndex`] with full duplicate, Unicode
/// NFC, and case-insensitive collision detection for lightweight SDK builds and tests.
///
/// For large trees (hundreds of thousands of files), prefer `rship_state::SqliteSyncIndex`
/// to keep peak RSS strictly bounded.
#[derive(Debug, Default)]
pub struct MemorySyncIndex {
    inner: Mutex<MemorySyncIndexInner>,
}

impl MemorySyncIndex {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SyncDiffIndex for MemorySyncIndex {
    async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
        let mut g = self.inner.lock().expect("memory sync index mutex poisoned");
        for e in entries {
            let id = g.src.len() as i64 + 1;
            g.src.push((id, e));
        }
        Ok(())
    }

    async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
        let mut g = self.inner.lock().expect("memory sync index mutex poisoned");
        for e in entries {
            let id = g.dst.len() as i64 + 1;
            g.dst.push((id, e));
        }
        Ok(())
    }

    async fn finalize_and_detect_conflicts(
        &self,
        dst_case_sensitive: bool,
    ) -> Result<Vec<SyncConflict>> {
        let mut g = self.inner.lock().expect("memory sync index mutex poisoned");
        let inner = &mut *g;
        inner.src_nfc.clear();
        inner.dst_by_nfc.clear();
        inner.conflicts.clear();

        let mut src_counts: HashMap<RelPath, (usize, HashSet<String>)> = HashMap::new();
        for (_, e) in &inner.src {
            inner.src_nfc.insert(e.nfc_path.clone());
            let entry = src_counts
                .entry(e.nfc_path.clone())
                .or_insert_with(|| (0, HashSet::new()));
            entry.0 += 1;
            entry.1.insert(e.raw_path().to_string());
        }
        for (nfc, (cnt, raws)) in src_counts {
            if cnt > 1 {
                let kind = if raws.len() > 1 {
                    ConflictKind::UnicodeNfcCollision
                } else {
                    ConflictKind::DuplicateSourceName
                };
                inner.conflicts.push(SyncConflict {
                    detail: format!("{cnt} source entries map to NFC path `{nfc}`"),
                    nfc_path: nfc,
                    kind,
                });
            }
        }

        let mut dst_counts: HashMap<RelPath, usize> = HashMap::new();
        for (_, e) in &inner.dst {
            inner
                .dst_by_nfc
                .entry(e.nfc_path.clone())
                .or_insert_with(|| e.clone());
            *dst_counts.entry(e.nfc_path.clone()).or_insert(0) += 1;
        }
        for (nfc, cnt) in dst_counts {
            if cnt > 1 {
                inner.conflicts.push(SyncConflict {
                    detail: format!("{cnt} destination entries share path `{nfc}`"),
                    nfc_path: nfc,
                    kind: ConflictKind::DuplicateDestinationName,
                });
            }
        }

        if !dst_case_sensitive {
            let mut fold_groups: HashMap<String, HashSet<RelPath>> = HashMap::new();
            for (_, e) in &inner.src {
                fold_groups
                    .entry(e.nfc_path.fold_key())
                    .or_default()
                    .insert(e.nfc_path.clone());
            }
            for (_, e) in &inner.dst {
                fold_groups
                    .entry(e.nfc_path.fold_key())
                    .or_default()
                    .insert(e.nfc_path.clone());
            }
            for (fold, paths) in fold_groups {
                if paths.len() > 1 {
                    let mut sorted: Vec<RelPath> = paths.into_iter().collect();
                    sorted.sort();
                    for nfc in sorted {
                        inner.conflicts.push(SyncConflict {
                            detail: format!("`{nfc}` collides case-insensitively on `{fold}`"),
                            nfc_path: nfc,
                            kind: ConflictKind::CaseInsensitiveCollision,
                        });
                    }
                }
            }
        }

        Ok(inner.conflicts.clone())
    }

    async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
        let g = self.inner.lock().expect("memory sync index mutex poisoned");
        Ok(g.conflicts.clone())
    }

    async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        let g = self.inner.lock().expect("memory sync index mutex poisoned");
        let start = usize::try_from(after_id.max(0)).unwrap_or(usize::MAX);
        if start >= g.src.len() {
            return Ok(Vec::new());
        }
        Ok(g.src[start..]
            .iter()
            .take(limit)
            .map(|(id, src)| DiffRow {
                row_id: *id,
                dst: g.dst_by_nfc.get(&src.nfc_path).cloned(),
                src: Some(src.clone()),
            })
            .collect())
    }

    async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        let g = self.inner.lock().expect("memory sync index mutex poisoned");
        let start = usize::try_from(after_id.max(0)).unwrap_or(usize::MAX);
        if start >= g.dst.len() {
            return Ok(Vec::new());
        }
        Ok(g.dst[start..]
            .iter()
            .filter(|(_, dst)| !g.src_nfc.contains(&dst.nfc_path))
            .take(limit)
            .map(|(id, dst)| DiffRow {
                row_id: *id,
                src: None,
                dst: Some(dst.clone()),
            })
            .collect())
    }
}
