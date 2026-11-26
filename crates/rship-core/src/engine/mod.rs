//! Bounded-memory, write-ahead-journaled Transfer & Sync Engine.
//!
//! Enforces every P0 invariant from `PLAN.md` v2:
//! - Pull-driven bounded work admission (`mpsc::channel(256)` -> fixed workers).
//! - Write-ahead `Intent` persisted BEFORE first remote mutation.
//! - Resumed sessions locked strictly to persisted `planned_chunk_size`.
//! - Pre-commit source freshness re-verification (detects live TOCTOU mutations).
//! - Ambiguous commit reconciliation before restarting on `SessionExpired` or `Completing`.
//! - Observation Completeness Gate + `--delete-after` + `--max-delete` circuit breaker.
//! - Clean `SIGINT` cancellation preserving resumable sessions.

mod config;
pub mod diff;
mod fence;
mod move_skips;
mod pool;
mod protocols;
mod report;
mod run;
mod single_file;
pub(crate) mod task;
mod verify;

use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::backend::{BackendPath, ListOptions, StorageBackend};
use crate::buffer::BufferPool;
use crate::clock::Clock;
use crate::error::{Error, ErrorKind, Result, RetryClass};
use crate::filter::FilterSet;
use crate::path::RelPath;
use crate::progress::{EventSink, JobEventEmitter, TransferPhase, TransferProgress};
use crate::state::{
    BaselineMode, BaselineRecord, JobMode, JobRecord, JobStatus, JournalStore, SourceVersion,
    SyncDiffIndex,
};
use crate::types::{Capabilities, Entry, EntryKind};

pub use config::{
    BackoffJitter, BackupTarget, DEFAULT_MAX_RETRY_DELAY, DeleteMode, EngineConfig, RetryQuota,
    TokenBucketRetryQuota,
};
pub(crate) use config::{ProtectedDirs, validate_backup_dir_overlap};
pub use fence::DurabilityFence;
use report::push_file_result;
pub use report::{
    CancelFlag, FileTransferResult, FileTransferStatus, MAX_REPORT_CONFLICTS, MAX_REPORT_ERRORS,
    MAX_REPORT_FILE_RESULTS, RunReport, TransferErrorInfo,
};

const DIFF_PAGE_SIZE: usize = 512;
const OBSERVE_BATCH_SIZE: usize = 2000;
const WORK_QUEUE_CAPACITY: usize = 256;
const MAX_NO_PROGRESS_LOOPS: u32 = 3;
/// Upper bound on tracked source directories for `move --delete-empty-src-dirs`.
pub const MAX_OBSERVED_SRC_DIRS: usize = 65_536;

pub struct TransferEngine {
    src: Arc<dyn StorageBackend>,
    dst: Arc<dyn StorageBackend>,
    /// The caller's journal wrapped in [`DurabilityFence`] over `dst`.
    journal: Arc<dyn JournalStore>,
    fence: Arc<DurabilityFence>,
    pool: BufferPool,
    clock: Arc<dyn Clock>,
    cancel: CancelFlag,
    progress: Option<Arc<TransferProgress>>,
    events: Option<Arc<dyn EventSink>>,
}

impl TransferEngine {
    /// Build an engine copying `src` to `dst`.
    ///
    /// `journal` is wrapped in a [`DurabilityFence`] over `dst`, so when `dst` defers
    /// durability (`LocalBackend` with `FsyncMode::Batch`) no baseline row, operation
    /// retirement or finished job status is committed before the destination data it
    /// vouches for has been flushed.
    pub fn new(
        src: Arc<dyn StorageBackend>,
        dst: Arc<dyn StorageBackend>,
        journal: Arc<dyn JournalStore>,
        pool: BufferPool,
        clock: Arc<dyn Clock>,
        cancel: CancelFlag,
    ) -> Self {
        let fence = DurabilityFence::new(journal, vec![dst.clone()], clock.clone());
        Self {
            src,
            dst,
            journal: fence.clone(),
            fence,
            pool,
            clock,
            cancel,
            progress: None,
            events: None,
        }
    }

    pub fn with_progress(mut self, progress: Arc<TransferProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.events = Some(sink);
        self
    }

    pub(super) fn set_phase(&self, emitter: &JobEventEmitter, phase: TransferPhase) {
        if let Some(p) = &self.progress {
            p.set_phase(phase);
        }
        emitter.emit_phase(phase);
    }

    async fn finish_job(
        &self,
        job: &mut JobRecord,
        status: JobStatus,
        dry_run: bool,
    ) -> Result<()> {
        if !dry_run {
            job.status = status;
            job.updated_at = self.clock.now_unix_secs();
            self.journal.upsert_job(job).await?;
        }
        Ok(())
    }

    /// Preload any active operations belonging to `(self.src, self.dst)` so files that
    /// already converged on destination (e.g. crash between remote commit and
    /// `commit_verified_transfer`) retire their dangling journal entry cleanly on skip.
    ///
    /// Returns an empty map in `O(1)` when `dry_run` is set or no crashed operations exist,
    /// adding zero per-file overhead on normal runs.
    pub(super) async fn load_active_ops_for_pair(
        &self,
        cfg: &EngineConfig,
    ) -> Result<std::collections::HashMap<String, crate::state::OperationRecord>> {
        if cfg.dry_run {
            return Ok(std::collections::HashMap::new());
        }
        let ops = self.journal.list_active_operations().await?;
        if ops.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let src_ep = self.src.endpoint_identity();
        let dst_ep = self.dst.endpoint_identity();
        let mut map = std::collections::HashMap::new();
        for op in ops {
            if op.src_endpoint == src_ep && op.dst_endpoint == dst_ep {
                map.entry(op.session_key.clone()).or_insert(op);
            }
        }
        Ok(map)
    }

    /// Retire a dangling journal [`crate::state::OperationRecord`] for a file that the
    /// planner already verified as converged (`PlannedAction::Skip`).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn retire_skipped_operation(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        active_ops: &mut std::collections::HashMap<String, crate::state::OperationRecord>,
        src_entry: &Entry,
        src_full_raw: &str,
        dst_rel: &RelPath,
        dst_full_rel: &RelPath,
        dst_entry: Option<&Entry>,
    ) -> Result<()> {
        if active_ops.is_empty() || cfg.dry_run {
            return Ok(());
        }
        let session_key = crate::state::compute_session_key(
            &self.src.endpoint_identity(),
            src_full_raw,
            &self.dst.endpoint_identity(),
            dst_full_rel,
        );
        let Some(op) = active_ops.remove(&session_key) else {
            return Ok(());
        };
        if op.session_token.is_some()
            && !matches!(
                op.state,
                crate::state::OperationState::Completing
                    | crate::state::OperationState::NeedsReconciliation
            )
        {
            let _ = self.dst.abort_upload(&op).await;
        }
        if let Some(dst_e) = dst_entry
            && should_persist_baseline(cfg, src_entry, dst_e, src_caps, dst_caps)
        {
            let baseline = make_baseline(pair_key, dst_rel, src_entry, dst_e, &self.clock);
            self.journal
                .commit_verified_transfer(Some(&op.op_id), Some(&baseline), &cfg.job_id, 0)
                .await?;
        } else {
            self.journal.delete_operation(&op.op_id).await?;
        }
        Ok(())
    }

    /// Turn a planned skip into a fresh transfer when an
    /// [`crate::state::OperationState::IntegrityFailed`] marker flags the path: the
    /// destination holds bytes that failed checksum verification, so a size/mtime match
    /// proves nothing, and neither a baseline nor a `move` source delete may trust it.
    pub(super) fn force_transfer_if_integrity_marked(
        &self,
        cfg: &EngineConfig,
        active_ops: &std::collections::HashMap<String, crate::state::OperationRecord>,
        src_entry: &Entry,
        dst_entry: Option<&Entry>,
        dst_rel: &RelPath,
        action: crate::planner::PlannedAction,
    ) -> Result<crate::planner::PlannedAction> {
        use crate::planner::{PlannedAction, PlannedTransfer};
        if !matches!(action, PlannedAction::Skip)
            || src_entry.kind != EntryKind::File
            || active_ops.is_empty()
        {
            return Ok(action);
        }
        let src_bp = BackendPath::join_prefixed(
            &cfg.src_prefix,
            src_entry.raw_path(),
            &src_entry.nfc_path,
            src_entry.node_id.clone(),
            Some(EntryKind::File),
        )?;
        let dst_full_rel = join_prefix(&cfg.dst_prefix, dst_rel)?;
        let session_key = crate::state::compute_session_key(
            &self.src.endpoint_identity(),
            src_bp.raw_path(),
            &self.dst.endpoint_identity(),
            &dst_full_rel,
        );
        let marked = active_ops
            .get(&crate::state::integrity_marker_key(&session_key))
            .is_some_and(|m| m.state == crate::state::OperationState::IntegrityFailed);
        if !marked {
            return Ok(action);
        }
        tracing::warn!(path = %dst_rel, "destination failed checksum verification earlier; re-transferring instead of skipping");
        let precondition = match dst_entry {
            Some(d) => crate::state::DstPrecondition::Existing {
                node_id: d.node_id.clone(),
                etag: d.etag.clone(),
                mtime_ns: d.mtime_ns,
                size: d.size,
            },
            None => crate::state::DstPrecondition::Any,
        };
        Ok(PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src_entry.clone(),
            dst_path: dst_rel.clone(),
            existing_dst_node_id: dst_entry.and_then(|d| d.node_id.clone()),
            precondition,
            needs_checksum_verify: false,
            replace_dst_dir: None,
        })))
    }

    /// Crash-recovery guard for destinations that defer durability (`LocalBackend` with
    /// `FsyncMode::Batch`): never trust a listing match for a file that still has a
    /// `Completing` operation left over from an earlier run.
    ///
    /// The durability fence only retires an operation after the destination flush that
    /// covered the file's data, so a leftover `Completing` operation means the file may have
    /// been renamed into place without its data reaching stable storage. After a power loss
    /// some filesystems keep the size and mtime but not the contents, which the planner's
    /// size + mtime comparison cannot see. Such a `Skip` is only kept when a content hash
    /// common to both sides matches; otherwise the operation is dropped and the file is
    /// transferred again over the existing destination. Hashing runs at most once per
    /// leftover operation, i.e. only after a crash.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn distrust_unflushed_skip(
        &self,
        cfg: &EngineConfig,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        active_ops: &mut std::collections::HashMap<String, crate::state::OperationRecord>,
        src_entry: &Entry,
        dst_rel: &RelPath,
        dst_entry: Option<&Entry>,
        action: crate::planner::PlannedAction,
    ) -> Result<crate::planner::PlannedAction> {
        use crate::planner::{PlannedAction, PlannedTransfer};
        if !matches!(action, PlannedAction::Skip)
            || active_ops.is_empty()
            || cfg.dry_run
            || src_entry.kind != EntryKind::File
            || !self.dst.defers_durable_writes()
        {
            return Ok(action);
        }
        let Some(dst_e) = dst_entry.filter(|d| d.kind == EntryKind::File) else {
            return Ok(action);
        };
        let src_bp = BackendPath::join_prefixed(
            &cfg.src_prefix,
            src_entry.raw_path(),
            &src_entry.nfc_path,
            src_entry.node_id.clone(),
            Some(EntryKind::File),
        )?;
        let dst_full_rel = join_prefix(&cfg.dst_prefix, dst_rel)?;
        let session_key = crate::state::compute_session_key(
            &self.src.endpoint_identity(),
            src_bp.raw_path(),
            &self.dst.endpoint_identity(),
            &dst_full_rel,
        );
        let leftover_completing = active_ops.get(&session_key).is_some_and(|op| {
            matches!(
                op.state,
                crate::state::OperationState::Completing
                    | crate::state::OperationState::NeedsReconciliation
            )
        });
        if !leftover_completing {
            return Ok(action);
        }
        let dst_bp = BackendPath::join_prefixed(
            &cfg.dst_prefix,
            dst_e.raw_path(),
            &dst_e.nfc_path,
            dst_e.node_id.clone(),
            Some(EntryKind::File),
        )?;
        let content_matches = match src_caps.best_common_hash(dst_caps) {
            Some(kind) => {
                let (s, d) = tokio::join!(
                    self.src.compute_hash(&src_bp, kind),
                    self.dst.compute_hash(&dst_bp, kind)
                );
                matches!((s, d), (Ok(Some(a)), Ok(Some(b))) if a.hex.eq_ignore_ascii_case(&b.hex))
            }
            None => false,
        };
        if content_matches {
            return Ok(action);
        }
        tracing::warn!(
            path = %src_entry.nfc_path,
            "destination file from an interrupted run is not verifiably intact; transferring it again"
        );
        if let Some(op) = active_ops.remove(&session_key) {
            self.journal.delete_operation(&op.op_id).await?;
        }
        Ok(PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src_entry.clone(),
            dst_path: dst_rel.clone(),
            existing_dst_node_id: dst_e.node_id.clone(),
            precondition: crate::state::DstPrecondition::Existing {
                node_id: dst_e.node_id.clone(),
                etag: dst_e.etag.clone(),
                mtime_ns: dst_e.mtime_ns,
                size: dst_e.size,
            },
            needs_checksum_verify: false,
            replace_dst_dir: None,
        })))
    }

    /// Handle a planning-level `PlannedAction::Skip` for a regular file across `run`,
    /// `run_single_file`, and `run_file_list`, keeping `files_skipped`, `sources_deleted`,
    /// `errors`, `error_details`, `file_results`, `TransferProgress`, and `EventSink`
    /// consistent with worker-level skips.
    pub(super) async fn handle_planned_file_skip(
        &self,
        cfg: &EngineConfig,
        src_entry: &Entry,
        src_bp: &BackendPath,
        result_path: &str,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) {
        if cfg.delete_source_after_transfer {
            if cfg.dry_run {
                report.files_skipped += 1;
                report.sources_deleted += 1;
                if let Some(p) = &self.progress {
                    p.add_planned_skip();
                    p.inc_sources_deleted();
                }
                push_file_result(
                    &mut report.file_results,
                    &mut report.file_results_truncated,
                    Some(emitter),
                    FileTransferResult::skipped(result_path, true),
                );
                return;
            }

            let expected_ver = SourceVersion::from_entry(src_entry);
            let del_res = verify_and_delete_skipped_move_source(
                &self.src,
                &self.dst,
                &cfg.dst_prefix,
                src_bp,
                result_path,
                &expected_ver,
            )
            .await;
            record_move_skip_outcome(
                self.progress.as_ref(),
                result_path,
                src_bp,
                del_res,
                emitter,
                report,
            );
        } else {
            report.files_skipped += 1;
            if let Some(p) = &self.progress {
                p.add_planned_skip();
            }
            push_file_result(
                &mut report.file_results,
                &mut report.file_results_truncated,
                Some(emitter),
                FileTransferResult::skipped(result_path, false),
            );
        }
    }

    async fn observe_side(
        &self,
        backend: &Arc<dyn StorageBackend>,
        prefix: &RelPath,
        filter: &FilterSet,
        scan_started_ns: i64,
        is_src: bool,
        index: &Arc<dyn SyncDiffIndex>,
    ) -> (bool, u64, Vec<TransferErrorInfo>, ProtectedDirs) {
        let mut errors = Vec::new();
        let mut complete = true;
        let mut files_observed = 0u64;
        let mut protected_dirs = ProtectedDirs::default();
        let list_opts = ListOptions::recursive().with_filter_pruning(filter, prefix);
        let stream = match backend.list_with_options(prefix, &list_opts).await {
            Ok(s) => s,
            Err(e) if !is_src && backend.kind() == "local" && e.kind == ErrorKind::NotFound => {
                // Brand-new local destination directory (e.g. `rship copy ./src ./new_dst`):
                // treat as empty so planned mkdirs/transfers materialize it cleanly.
                // Missing local sources and missing cloud buckets ALWAYS remain hard errors.
                return (true, 0, errors, protected_dirs);
            }
            Err(e) => {
                errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &e,
                    format!("list `{}` failed: {e}", backend.name()),
                ));
                return (false, 0, errors, protected_dirs);
            }
        };

        let mut stream = stream;
        let mut batch = Vec::with_capacity(OBSERVE_BATCH_SIZE);
        while let Some(item) = stream.next().await {
            if self.cancel.is_cancelled() {
                complete = false;
                break;
            }
            match item {
                Ok(mut entry) => {
                    // Strip prefix so `nfc_path` and `raw_path` are relative to the sync root.
                    if !prefix.is_root() {
                        let old_raw = entry.raw_path.take();
                        if let Some(rel) = strip_rel_prefix(&entry.nfc_path, prefix) {
                            entry.nfc_path = rel;
                        } else {
                            continue;
                        }
                        if let Some(raw_full) = old_raw
                            && let Some(raw_rel) = strip_raw_prefix(&raw_full, prefix.as_str())
                        {
                            entry.set_raw_path(&raw_rel);
                        }
                    }
                    if entry.nfc_path.is_root() {
                        continue;
                    }
                    if !filter.matches_entry(&entry, scan_started_ns) {
                        if !is_src {
                            protected_dirs.protect_ancestors(&entry.nfc_path);
                        }
                        continue;
                    }
                    if entry.kind == EntryKind::File {
                        files_observed += 1;
                    }
                    batch.push(entry);
                    if batch.len() >= OBSERVE_BATCH_SIZE {
                        let to_flush =
                            std::mem::replace(&mut batch, Vec::with_capacity(OBSERVE_BATCH_SIZE));
                        if let Err(e) = flush_batch(index, is_src, to_flush).await {
                            errors.push(TransferErrorInfo::from_error_with_message(
                                None,
                                &e,
                                format!("sync index insert failed: {e}"),
                            ));
                            complete = false;
                            break;
                        }
                    }
                }
                Err(e) => {
                    complete = false;
                    if errors.len() < MAX_REPORT_ERRORS {
                        errors.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("observe `{}` error: {e}", backend.name()),
                        ));
                    }
                }
            }
        }
        if !batch.is_empty()
            && let Err(e) = flush_batch(index, is_src, batch).await
        {
            errors.push(TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("sync index flush failed: {e}"),
            ));
            complete = false;
        }
        (complete, files_observed, errors, protected_dirs)
    }

    /// D3 for `--files-from`: listed paths are `stat`ed one by one, and a missing source root
    /// makes every `stat` report "not found", which would otherwise look like a run with
    /// nothing to do. Called once a listed path turns out to be missing; returns the error
    /// when the source root itself does not exist.
    pub(super) async fn missing_source_root(&self, src_prefix: &RelPath) -> Option<Error> {
        let err = match self.src.list_stream(src_prefix, false).await {
            Err(e) => e,
            Ok(mut entries) => match entries.next().await {
                Some(Err(e)) => e,
                _ => return None,
            },
        };
        (err.kind == ErrorKind::NotFound).then(|| {
            Error::not_found(format!(
                "source root `{}` on `{}` does not exist: {err}",
                src_prefix,
                self.src.name()
            ))
        })
    }

    /// Direct-stat (`--no-traverse`) observation for `--files-from` lists: stats ONLY
    /// the explicitly listed relative paths on source & destination without crawling
    /// either directory tree (avoiding in-progress sibling files like `.flv` locally
    /// and avoiding remote `files.list` / `changes.list` calls on Google Drive).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn observe_files_from(
        &self,
        listed: &[RelPath],
        src_prefix: &RelPath,
        dst_prefix: &RelPath,
        filter: &FilterSet,
        scan_started_ns: i64,
        concurrency: usize,
        index: &Arc<dyn SyncDiffIndex>,
    ) -> (
        (bool, Vec<TransferErrorInfo>),
        (bool, Vec<TransferErrorInfo>),
        u64,
    ) {
        let mut src_ok = true;
        let mut dst_ok = true;
        let mut dst_files_observed = 0u64;
        let mut src_errs = Vec::new();
        let mut dst_errs = Vec::new();
        let mut src_batch = Vec::with_capacity(listed.len().min(OBSERVE_BATCH_SIZE));
        let mut dst_batch = Vec::with_capacity(listed.len().min(OBSERVE_BATCH_SIZE));

        let max_stat = if self.src.kind() == "local" && self.dst.kind() == "local" {
            16
        } else {
            64
        };
        let conc = concurrency.clamp(1, max_stat);
        let src_backend = self.src.clone();
        let dst_backend = self.dst.clone();
        let src_pre = src_prefix.clone();
        let dst_pre = dst_prefix.clone();
        let cancel = self.cancel.clone();

        let mut stream = futures::stream::iter(listed.iter().cloned())
            .map(move |rel| {
                let src = src_backend.clone();
                let dst = dst_backend.clone();
                let sp = src_pre.clone();
                let dp = dst_pre.clone();
                let c = cancel.clone();
                async move {
                    if c.is_cancelled() {
                        return (rel, None, None, None, None, false);
                    }
                    let rel_str = rel.as_str().to_string();
                    let src_full = match join_prefix(&sp, &rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let info = TransferErrorInfo::from_error(Some(rel_str), &e);
                            return (rel, None, None, Some(info), None, false);
                        }
                    };
                    let src_bp = BackendPath::from_rel(src_full);
                    let src_entry = match src.stat(&src_bp).await {
                        Ok(Some(mut e)) => {
                            let old_raw = e.raw_path.take();
                            e.nfc_path = rel.clone();
                            if let Some(raw_full) = old_raw {
                                if sp.is_root() {
                                    e.set_raw_path(&raw_full);
                                } else if let Some(raw_rel) =
                                    strip_raw_prefix(&raw_full, sp.as_str())
                                {
                                    e.set_raw_path(&raw_rel);
                                }
                            }
                            e
                        }
                        Ok(None) => {
                            // Missing source file (e.g. already moved & deleted on an earlier
                            // partial-failure run): skip cleanly, unless the whole source root
                            // is missing (checked once after the scan).
                            return (rel, None, None, None, None, true);
                        }
                        Err(e) => {
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(rel_str),
                                &e,
                                format!("stat source `{}` failed: {e}", src_bp.nfc_path),
                            );
                            return (rel, None, None, Some(info), None, false);
                        }
                    };

                    if c.is_cancelled() {
                        return (rel, Some(src_entry), None, None, None, false);
                    }

                    let dst_full = match join_prefix(&dp, &rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let info = TransferErrorInfo::from_error(Some(rel_str), &e);
                            return (rel, Some(src_entry), None, None, Some(info), false);
                        }
                    };
                    let dst_bp = BackendPath::from_rel(dst_full);
                    match dst.stat(&dst_bp).await {
                        Ok(Some(mut de)) => {
                            let old_raw = de.raw_path.take();
                            de.nfc_path = rel.clone();
                            if let Some(raw_full) = old_raw {
                                if dp.is_root() {
                                    de.set_raw_path(&raw_full);
                                } else if let Some(raw_rel) =
                                    strip_raw_prefix(&raw_full, dp.as_str())
                                {
                                    de.set_raw_path(&raw_rel);
                                }
                            }
                            (rel, Some(src_entry), Some(de), None, None, false)
                        }
                        Ok(None) => (rel, Some(src_entry), None, None, None, false),
                        Err(e) => {
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(rel_str),
                                &e,
                                format!("stat destination `{}` failed: {e}", dst_bp.nfc_path),
                            );
                            (rel, Some(src_entry), None, None, Some(info), false)
                        }
                    }
                }
            })
            .buffer_unordered(conc);

        let mut any_src_missing = false;
        while let Some((_rel, src_opt, dst_opt, s_err, d_err, src_missing)) = stream.next().await {
            any_src_missing |= src_missing;
            if self.cancel.is_cancelled() {
                src_ok = false;
                dst_ok = false;
                break;
            }
            if let Some(e) = s_err {
                src_ok = false;
                if src_errs.len() < MAX_REPORT_ERRORS {
                    src_errs.push(e);
                }
                continue;
            }
            if let Some(e) = d_err {
                dst_ok = false;
                if dst_errs.len() < MAX_REPORT_ERRORS {
                    dst_errs.push(e);
                }
                continue;
            }
            if let Some(se) = src_opt
                && filter.matches_entry(&se, scan_started_ns)
            {
                src_batch.push(se);
                if let Some(de) = dst_opt {
                    if de.kind == EntryKind::File {
                        dst_files_observed += 1;
                    }
                    dst_batch.push(de);
                }
                if src_batch.len() >= OBSERVE_BATCH_SIZE {
                    let sb =
                        std::mem::replace(&mut src_batch, Vec::with_capacity(OBSERVE_BATCH_SIZE));
                    if let Err(e) = index.insert_src_batch(sb).await {
                        src_ok = false;
                        src_errs.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("sync index insert failed: {e}"),
                        ));
                        break;
                    }
                }
                if dst_batch.len() >= OBSERVE_BATCH_SIZE {
                    let db =
                        std::mem::replace(&mut dst_batch, Vec::with_capacity(OBSERVE_BATCH_SIZE));
                    if let Err(e) = index.insert_dst_batch(db).await {
                        dst_ok = false;
                        dst_errs.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("sync index insert failed: {e}"),
                        ));
                        break;
                    }
                }
            }
        }

        if !src_batch.is_empty()
            && let Err(e) = index.insert_src_batch(src_batch).await
        {
            src_ok = false;
            src_errs.push(TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("sync index flush failed: {e}"),
            ));
        }
        if !dst_batch.is_empty()
            && let Err(e) = index.insert_dst_batch(dst_batch).await
        {
            dst_ok = false;
            dst_errs.push(TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("sync index flush failed: {e}"),
            ));
        }
        if any_src_missing
            && src_ok
            && let Some(e) = self.missing_source_root(src_prefix).await
        {
            src_ok = false;
            src_errs.push(TransferErrorInfo::from_error(None, &e));
        }

        ((src_ok, src_errs), (dst_ok, dst_errs), dst_files_observed)
    }
}

pub(crate) fn validate_max_delete_percent(pct: Option<f64>) -> Result<()> {
    if let Some(p) = pct
        && (!p.is_finite() || !(0.0..=100.0).contains(&p))
    {
        return Err(Error::config(format!(
            "max_delete_percent must be between 0.0 and 100.0 (got {p})"
        )));
    }
    Ok(())
}

async fn flush_batch(
    index: &Arc<dyn SyncDiffIndex>,
    is_src: bool,
    batch: Vec<Entry>,
) -> Result<()> {
    if is_src {
        index.insert_src_batch(batch).await
    } else {
        index.insert_dst_batch(batch).await
    }
}

async fn verify_source_unchanged(
    src: &Arc<dyn StorageBackend>,
    src_path: &BackendPath,
    expected: &SourceVersion,
) -> Result<()> {
    let Some(now) = src.stat(src_path).await? else {
        return Err(Error::source_mutated(format!(
            "source `{}` disappeared during transfer",
            src_path.raw_path()
        )));
    };
    let cur = SourceVersion::from_entry(&now);
    if cur != *expected {
        return Err(Error::source_mutated(format!(
            "source `{}` mutated during transfer (expected {:?}, observed {:?})",
            src_path.raw_path(),
            expected,
            cur
        )));
    }
    Ok(())
}

pub(crate) fn is_retryable(e: &Error) -> bool {
    !e.retries_exhausted && matches!(e.retry, RetryClass::Retryable | RetryClass::Throttled)
}

pub(crate) fn compute_backoff_delay(
    err: &Error,
    attempt: u32,
    base_delay: Duration,
    max_retry_delay: Duration,
    jitter: &BackoffJitter,
) -> Duration {
    if let Some(ra) = err.retry_after {
        return ra.min(max_retry_delay);
    }
    let shift = attempt.saturating_sub(1);
    let mult = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    let ceiling = base_delay.saturating_mul(mult).min(max_retry_delay);
    let max_ns = ceiling.as_nanos().min(u128::from(u64::MAX)) as u64;
    if max_ns == 0 {
        return Duration::ZERO;
    }
    let sample_ns = if max_ns == u64::MAX {
        jitter.next_u64()
    } else {
        let span = u128::from(max_ns) + 1;
        ((u128::from(jitter.next_u64()) * span) >> 64) as u64
    };
    Duration::from_nanos(sample_ns)
}

async fn backoff_sleep(
    err: &Error,
    attempt: u32,
    base_delay: Duration,
    max_retry_delay: Duration,
    jitter: &BackoffJitter,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
) -> Result<()> {
    let delay = compute_backoff_delay(err, attempt, base_delay, max_retry_delay, jitter);
    if cancel.is_cancelled() {
        return Err(Error::cancelled("cancelled during retry backoff"));
    }
    if !delay.is_zero() {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::cancelled("cancelled during retry backoff"));
            }
            () = clock.sleep(delay) => {}
        }
    }
    if cancel.is_cancelled() {
        return Err(Error::cancelled("cancelled during retry backoff"));
    }
    Ok(())
}

pub(super) struct PlannedMoveSkip {
    pub(super) src_bp: BackendPath,
    pub(super) result_path: String,
    pub(super) expected_ver: SourceVersion,
    pub(super) wire_key: Option<String>,
}

/// Record the outcome of one planned `move` skip (verify + delete of the source).
/// Returns `true` when the source was deleted.
pub(super) fn record_move_skip_outcome(
    progress: Option<&Arc<TransferProgress>>,
    result_path: &str,
    src_bp: &BackendPath,
    del_res: Result<()>,
    emitter: &JobEventEmitter,
    report: &mut RunReport,
) -> bool {
    match del_res {
        Ok(()) => {
            report.files_skipped += 1;
            report.sources_deleted += 1;
            if let Some(p) = progress {
                p.add_planned_skip();
                p.inc_sources_deleted();
            }
            push_file_result(
                &mut report.file_results,
                &mut report.file_results_truncated,
                Some(emitter),
                FileTransferResult::skipped(result_path, true),
            );
            true
        }
        Err(e) => {
            if let Some(p) = progress {
                p.add_planned_error();
            }
            let msg = format!("delete moved source `{}`: {e}", src_bp.nfc_path);
            let info = TransferErrorInfo::from_error_with_message(
                Some(result_path.to_string()),
                &e,
                msg.clone(),
            );
            report.push_error(info);
            push_file_result(
                &mut report.file_results,
                &mut report.file_results_truncated,
                Some(emitter),
                FileTransferResult::failed_with_message(result_path, &e, msg),
            );
            false
        }
    }
}

async fn verify_and_delete_skipped_move_source(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    dst_prefix: &RelPath,
    src_bp: &BackendPath,
    result_path: &str,
    expected_ver: &SourceVersion,
) -> Result<()> {
    let dst_full = RelPath::parse(result_path).and_then(|rel| join_prefix(dst_prefix, &rel))?;
    let dst_sync_bp = BackendPath::from_rel(dst_full);
    dst.sync_durable_file(&dst_sync_bp).await?;
    verify_source_unchanged(src, src_bp, expected_ver).await?;
    src.delete(src_bp).await
}

pub(super) fn has_comparable_full_checksums(src: &Entry, dst: &Entry) -> bool {
    matches!(
        (&src.checksum, &dst.checksum),
        (Some(sh), Some(dh))
            if sh.kind == dh.kind
                && !sh.hex.contains('-')
                && !dh.hex.contains('-')
    )
}

/// End-to-end post-commit checksum verification (C3): whenever both the source entry and
/// the provider's committed destination entry carry comparable full-object (non-multipart)
/// checksums of the same [`crate::types::HashKind`], reject any mismatch loudly before
/// persisting a baseline or deleting a moved source. Mismatches are reported as
/// [`Error::integrity`] so they are never reconciled into success.
pub(super) fn verify_committed_checksum(src: &Entry, dst: &Entry) -> Result<()> {
    if let (Some(sh), Some(dh)) = (&src.checksum, &dst.checksum)
        && has_comparable_full_checksums(src, dst)
        && !sh.hex.eq_ignore_ascii_case(&dh.hex)
    {
        return Err(Error::integrity(format!(
            "end-to-end checksum mismatch for `{}` ({:?}: source {} != destination {})",
            src.nfc_path, sh.kind, sh.hex, dh.hex
        )));
    }
    Ok(())
}

/// Decide whether a verified transfer needs a durable `sync_baseline` row.
///
/// In `BaselineMode::Auto` (default):
/// - `move` NEVER writes a baseline (the source is deleted after verification).
/// - Transfers whose destination preserves mtime (`dst_caps.can_set_mtime`) skip baselines.
/// - Transfers where both source and committed destination already carry matching
///   non-multipart full-object checksums (e.g., single-part S3 -> S3 MD5 ETags) skip
///   baselines because incremental re-runs compare live hashes directly in O(1).
/// - All other transfers (e.g., `local -> S3`, or multipart S3 objects whose composite
///   ETag cannot be matched without re-hashing) persist a baseline row.
pub(super) fn should_persist_baseline(
    cfg: &EngineConfig,
    src: &Entry,
    committed_dst: &Entry,
    _src_caps: &Capabilities,
    dst_caps: &Capabilities,
) -> bool {
    if cfg.delete_source_after_transfer || matches!(cfg.mode, JobMode::Move) {
        return false;
    }
    match cfg.baseline_mode {
        BaselineMode::None => false,
        BaselineMode::All => true,
        BaselineMode::Auto => {
            if dst_caps.can_set_mtime {
                return false;
            }
            if let (Some(sh), Some(dh)) = (&src.checksum, &committed_dst.checksum)
                && sh.kind == dh.kind
                && !sh.hex.contains('-')
                && !dh.hex.contains('-')
                && sh.hex.eq_ignore_ascii_case(&dh.hex)
            {
                return false;
            }
            true
        }
    }
}

/// Decide whether planning a `(src, dst)` file pair requires querying `sync_baseline`.
pub(super) fn needs_baseline_lookup(
    cfg: &EngineConfig,
    src: &Entry,
    dst: &Entry,
    dst_caps: &Capabilities,
    mtime_tolerance_ns: i64,
    scan_started_ns: i64,
) -> bool {
    if cfg.checksum || cfg.baseline_mode == BaselineMode::None {
        return false;
    }
    if src.kind != EntryKind::File || dst.kind != EntryKind::File || src.size != dst.size {
        return false;
    }
    if has_comparable_full_checksums(src, dst) {
        return false;
    }
    let tol = u64::try_from(mtime_tolerance_ns).unwrap_or(0);
    let src_racily_clean = scan_started_ns.abs_diff(src.mtime_ns) <= tol;
    !(dst_caps.can_set_mtime && !src_racily_clean && src.mtime_ns.abs_diff(dst.mtime_ns) <= tol)
}

fn make_baseline(
    pair_key: &str,
    rel: &RelPath,
    src: &Entry,
    dst: &Entry,
    clock: &Arc<dyn Clock>,
) -> BaselineRecord {
    let (hash_kind, hash_hex) = match (&dst.checksum, &src.checksum) {
        (Some(c), _) | (None, Some(c)) => (Some(c.kind), Some(c.hex.clone())),
        (None, None) => (None, None),
    };
    BaselineRecord {
        pair_key: pair_key.to_string(),
        nfc_path: rel.clone(),
        kind: EntryKind::File,
        src_node_id: src.node_id.clone(),
        dst_node_id: dst.node_id.clone(),
        size: dst.size,
        src_mtime_ns: src.mtime_ns,
        dst_mtime_ns: dst.mtime_ns,
        dst_etag: dst.etag.clone(),
        hash_kind,
        hash_hex,
        updated_at: clock.now_unix_secs(),
    }
}

fn generate_op_id(clock: &Arc<dyn Clock>, session_key: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let ts = clock.now_unix_nanos();
    let short_key = &session_key[..12.min(session_key.len())];
    format!("op-{ts:x}-{seq:x}-{short_key}")
}

pub(crate) fn join_prefix(prefix: &RelPath, rel: &RelPath) -> Result<RelPath> {
    Ok(prefix.join_path(rel))
}

pub(crate) fn strip_rel_prefix(path: &RelPath, prefix: &RelPath) -> Option<RelPath> {
    path.strip_prefix(prefix)
}

pub(crate) fn strip_raw_prefix(raw: &str, prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return Some(raw.to_string());
    }
    if raw == prefix {
        return Some(String::new());
    }
    raw.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('/'))
        .map(str::to_string)
}

/// Compute a deterministic pair key from two backend identities and their active sub-prefixes.
pub(crate) fn make_prefixed_pair_key(
    src_endpoint: &str,
    src_prefix: &RelPath,
    dst_endpoint: &str,
    dst_prefix: &RelPath,
) -> String {
    let format_ep = |ep: &str, prefix: &RelPath| -> String {
        if prefix.is_root() {
            ep.to_string()
        } else {
            format!("{}/{}", ep.trim_end_matches('/'), prefix)
        }
    };
    crate::state::compute_pair_key(
        &format_ep(src_endpoint, src_prefix),
        &format_ep(dst_endpoint, dst_prefix),
    )
}

/// Prevent catastrophic self-overwrites, infinite recursion (`sync /a /a/b`),
/// and destructive parent wipes (`sync /a/b /a`) on overlapping roots
/// (inspired by rclone `TestSyncOverlap` & `TestSyncOverlapWithFilter`).
pub fn check_overlapping_roots(
    src_endpoint: &str,
    src_prefix: &RelPath,
    dst_endpoint: &str,
    dst_prefix: &RelPath,
    filter: &FilterSet,
) -> Result<()> {
    let src_full = normalize_endpoint_path(src_endpoint, src_prefix);
    let dst_full = normalize_endpoint_path(dst_endpoint, dst_prefix);

    let Some((src_scheme, src_path)) = src_full else {
        return Ok(());
    };
    let Some((dst_scheme, dst_path)) = dst_full else {
        return Ok(());
    };
    if src_scheme != dst_scheme {
        return Ok(());
    }

    // Identical root is always fatal overlap.
    if src_path == dst_path {
        return Err(Error::conflict(format!(
            "overlapping source and destination roots: `{src_endpoint}` == `{dst_endpoint}`"
        )));
    }

    // Case 1: destination is nested inside source (e.g. `src=/a`, `dst=/a/sub`).
    // Allowed ONLY if `filter` explicitly prunes that relative subdir in `src`!
    if let Some(rel_in_src) = nested_subpath(&src_path, &dst_path) {
        if let Ok(rel) = RelPath::parse(&rel_in_src)
            && filter.should_prune_dir(&rel)
        {
            return Ok(());
        }
        return Err(Error::conflict(format!(
            "overlapping roots: destination `{dst_endpoint}` is inside source `{src_endpoint}` (exclude `{rel_in_src}/` to allow)"
        )));
    }

    // Case 2: source is nested inside destination (e.g. `src=/a/sub`, `dst=/a`).
    if nested_subpath(&dst_path, &src_path).is_some() {
        return Err(Error::conflict(format!(
            "overlapping roots: source `{src_endpoint}` is inside destination `{dst_endpoint}`"
        )));
    }

    Ok(())
}

fn normalize_endpoint_path(endpoint: &str, prefix: &RelPath) -> Option<(String, String)> {
    let (scheme, rest) = endpoint.split_once("://")?;
    let mut path = rest.replace('\\', "/");
    // Strip Windows verbatim prefix `//?/` if canonicalized.
    if let Some(stripped) = path.strip_prefix("//?/") {
        path = stripped.to_string();
    }
    let path = path.trim_end_matches('/');
    let joined = if prefix.is_root() {
        path.to_string()
    } else if path.is_empty() {
        prefix.as_str().to_string()
    } else {
        format!("{path}/{}", prefix.as_str())
    };
    // On Windows local endpoints, compare paths case-insensitively.
    let norm = if cfg!(windows) && scheme == "local" {
        joined.to_lowercase()
    } else {
        joined
    };
    Some((scheme.to_string(), norm))
}

fn nested_subpath(parent: &str, child: &str) -> Option<String> {
    if parent.is_empty() {
        return if child.is_empty() {
            None
        } else {
            Some(child.to_string())
        };
    }
    child
        .strip_prefix(parent)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests;
