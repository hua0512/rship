//! Pipelined unordered transfer loop (P8) for non-ordered backends (`Local`, `SFTP`,
//! `WebDAV`, `Local -> S3`, `Local -> GDrive`, etc.): observes a bounded destination
//! snapshot first, then streams source entries directly into `TransferWorkerPool` as
//! listing progresses without waiting for full source materialization in `SyncDiffIndex`.
//!
//! Safety invariants preserved identically to the indexed path:
//! - Only activates when `!src_caps.allows_duplicate_names && dst_caps.case_sensitive`
//!   (and `--delete-after` or no deletes) so duplicate/case collisions are impossible mid-stream.
//! - Pure-ASCII source entries stream immediately into workers; any non-ASCII or NFD-distinct
//!   entries are deferred until source listing EOF for exact `UnicodeNfcCollision` checking
//!   (including singleton contractions such as Kelvin `U+212A` -> `'K'`). Deferred entries
//!   are flushed in bounded batches into the run's `SyncDiffIndex` (which spills to disk on
//!   large trees), so their memory is bounded by the index, not by the tree size.
//! - Destination snapshots exceeding `PIPELINE_MAX_DST_ENTRIES` transparently spill into
//!   `SyncDiffIndex` without re-listing, keeping RAM strictly `O(1)` bounded on huge trees.
//! - Phase 3 `--delete-after` strictly enforces the Observation Completeness Gate,
//!   conflict exclusion, protected dirs, and `--max-delete` circuit breakers.

use futures::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

use crate::backend::{BackendPath, ListOptions};
use crate::error::{ErrorKind, Result};
use crate::path::RelPath;
use crate::planner::{PlanOptions, PlannedAction, plan_dst_only_item, plan_source_item};
use crate::progress::{JobEventEmitter, TransferPhase};
use crate::state::{
    ConflictKind, JobRecord, JobStatus, SourceVersion, SyncConflict, SyncDiffIndex,
};
use crate::types::{Capabilities, Entry, EntryKind};

use super::super::diff::{DeleteSpillLog, DeleteTarget};
use super::super::move_skips::{MoveSkipRunner, submit_move_skips};
use super::super::pool::TransferWorkerPool;
use super::super::task::TransferTask;
use super::super::{
    EngineConfig, MAX_OBSERVED_SRC_DIRS, MAX_REPORT_ERRORS, OBSERVE_BATCH_SIZE, PlannedMoveSkip,
    ProtectedDirs, RunReport, TransferEngine, TransferErrorInfo, join_prefix,
    needs_baseline_lookup, strip_raw_prefix, strip_rel_prefix,
};
use super::{PageMkdirItem, resolve_final_status};

/// Upper bound on in-memory destination entries held by the unordered pipelined fast path
/// (~10-15 MiB worst case). Larger destinations seamlessly spill into `SyncDiffIndex`.
const PIPELINE_MAX_DST_ENTRIES: usize = 65_536;
/// Maximum immediately-ready source entries coalesced into one baseline/mkdir/transfer batch.
const PIPELINE_BATCH_SIZE: usize = 128;

pub(super) enum DstPipelineLoad {
    InMemory {
        dst_map: HashMap<RelPath, Entry>,
        dst_conflicts: Vec<SyncConflict>,
        dst_ok: bool,
        dst_errs: Vec<TransferErrorInfo>,
        observed_dst_files: u64,
        protected_dst_dirs: ProtectedDirs,
    },
    SpilledToIndex {
        src_ok: bool,
        src_errs: Vec<TransferErrorInfo>,
        dst_ok: bool,
        dst_errs: Vec<TransferErrorInfo>,
        observed_dst_files: u64,
        protected_dst_dirs: ProtectedDirs,
    },
}

impl TransferEngine {
    /// Load destination entries into a bounded in-memory map for unordered pipelining.
    /// If destination exceeds `PIPELINE_MAX_DST_ENTRIES`, flushes what was read so far into
    /// `index` and finishes observing both sides concurrently into `index` with zero wasted RPCs.
    pub(super) async fn observe_dst_for_pipeline(
        &self,
        cfg: &EngineConfig,
        scan_started_ns: i64,
        index: &Arc<dyn SyncDiffIndex>,
    ) -> DstPipelineLoad {
        let mut dst_errs = Vec::new();
        let mut dst_ok = true;
        let mut observed_dst_files = 0u64;
        let mut protected_dst_dirs = ProtectedDirs::default();
        let list_opts = ListOptions::recursive().with_filter_pruning(&cfg.filter, &cfg.dst_prefix);
        let mut stream = match self
            .dst
            .list_with_options(&cfg.dst_prefix, &list_opts)
            .await
        {
            Ok(s) => s,
            Err(e) if self.dst.kind() == "local" && e.kind == ErrorKind::NotFound => {
                return DstPipelineLoad::InMemory {
                    dst_map: HashMap::new(),
                    dst_conflicts: Vec::new(),
                    dst_ok: true,
                    dst_errs,
                    observed_dst_files: 0,
                    protected_dst_dirs,
                };
            }
            Err(e) => {
                dst_errs.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &e,
                    format!("list `{}` failed: {e}", self.dst.name()),
                ));
                return DstPipelineLoad::InMemory {
                    dst_map: HashMap::new(),
                    dst_conflicts: Vec::new(),
                    dst_ok: false,
                    dst_errs,
                    observed_dst_files: 0,
                    protected_dst_dirs,
                };
            }
        };

        let mut dst_map: HashMap<RelPath, Entry> = HashMap::new();
        let mut dst_dup_counts: HashMap<RelPath, usize> = HashMap::new();
        let mut dst_extra_dups: Vec<Entry> = Vec::new();

        while let Some(item) = stream.next().await {
            if self.cancel.is_cancelled() {
                dst_ok = false;
                break;
            }
            match item {
                Ok(mut entry) => {
                    if !cfg.dst_prefix.is_root() {
                        let old_raw = entry.raw_path.take();
                        if let Some(rel) = strip_rel_prefix(&entry.nfc_path, &cfg.dst_prefix) {
                            entry.nfc_path = rel;
                        } else {
                            continue;
                        }
                        if let Some(raw_full) = old_raw
                            && let Some(raw_rel) =
                                strip_raw_prefix(&raw_full, cfg.dst_prefix.as_str())
                        {
                            entry.set_raw_path(&raw_rel);
                        }
                    }
                    if entry.nfc_path.is_root() {
                        continue;
                    }
                    if !cfg.filter.matches_entry(&entry, scan_started_ns) {
                        protected_dst_dirs.protect_ancestors(&entry.nfc_path);
                        continue;
                    }
                    if entry.kind == EntryKind::File {
                        observed_dst_files += 1;
                    }
                    if dst_map.len() >= PIPELINE_MAX_DST_ENTRIES {
                        // Destination is large: spill buffered entries + remaining stream into
                        // `SyncDiffIndex` while concurrently observing `src` into `index`!
                        let mut initial_spill =
                            Vec::with_capacity(dst_map.len() + dst_extra_dups.len() + 1);
                        initial_spill.extend(dst_map.into_values());
                        initial_spill.extend(dst_extra_dups);
                        initial_spill.push(entry);

                        let dst_prefix = cfg.dst_prefix.clone();
                        let filter = cfg.filter.clone();
                        let index_dst = index.clone();
                        let dst_name = self.dst.name().to_string();
                        let cancel_dst = self.cancel.clone();

                        let finish_dst = async move {
                            let mut batch = Vec::with_capacity(OBSERVE_BATCH_SIZE);
                            for e in initial_spill {
                                batch.push(e);
                                if batch.len() >= OBSERVE_BATCH_SIZE {
                                    let flush = std::mem::replace(
                                        &mut batch,
                                        Vec::with_capacity(OBSERVE_BATCH_SIZE),
                                    );
                                    if let Err(err) = index_dst.insert_dst_batch(flush).await {
                                        dst_errs.push(TransferErrorInfo::from_error_with_message(
                                            None,
                                            &err,
                                            format!("sync index insert failed: {err}"),
                                        ));
                                        dst_ok = false;
                                        return (
                                            dst_ok,
                                            observed_dst_files,
                                            dst_errs,
                                            protected_dst_dirs,
                                        );
                                    }
                                }
                            }
                            while let Some(it) = stream.next().await {
                                if cancel_dst.is_cancelled() {
                                    dst_ok = false;
                                    break;
                                }
                                match it {
                                    Ok(mut e) => {
                                        if !dst_prefix.is_root() {
                                            let old_raw = e.raw_path.take();
                                            if let Some(rel) =
                                                strip_rel_prefix(&e.nfc_path, &dst_prefix)
                                            {
                                                e.nfc_path = rel;
                                            } else {
                                                continue;
                                            }
                                            if let Some(raw_full) = old_raw
                                                && let Some(raw_rel) =
                                                    strip_raw_prefix(&raw_full, dst_prefix.as_str())
                                            {
                                                e.set_raw_path(&raw_rel);
                                            }
                                        }
                                        if e.nfc_path.is_root() {
                                            continue;
                                        }
                                        if !filter.matches_entry(&e, scan_started_ns) {
                                            protected_dst_dirs.protect_ancestors(&e.nfc_path);
                                            continue;
                                        }
                                        if e.kind == EntryKind::File {
                                            observed_dst_files += 1;
                                        }
                                        batch.push(e);
                                        if batch.len() >= OBSERVE_BATCH_SIZE {
                                            let flush = std::mem::replace(
                                                &mut batch,
                                                Vec::with_capacity(OBSERVE_BATCH_SIZE),
                                            );
                                            if let Err(err) =
                                                index_dst.insert_dst_batch(flush).await
                                            {
                                                dst_errs.push(
                                                    TransferErrorInfo::from_error_with_message(
                                                        None,
                                                        &err,
                                                        format!("sync index insert failed: {err}"),
                                                    ),
                                                );
                                                dst_ok = false;
                                                break;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        dst_ok = false;
                                        if dst_errs.len() < MAX_REPORT_ERRORS {
                                            dst_errs.push(
                                                TransferErrorInfo::from_error_with_message(
                                                    None,
                                                    &err,
                                                    format!("observe `{dst_name}` error: {err}"),
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                            if !batch.is_empty()
                                && let Err(err) = index_dst.insert_dst_batch(batch).await
                            {
                                dst_errs.push(TransferErrorInfo::from_error_with_message(
                                    None,
                                    &err,
                                    format!("sync index flush failed: {err}"),
                                ));
                                dst_ok = false;
                            }
                            (dst_ok, observed_dst_files, dst_errs, protected_dst_dirs)
                        };

                        let ((src_ok, _, src_errs, _), (d_ok, d_files, d_errs, prot_d)) = tokio::join!(
                            self.observe_side(
                                &self.src,
                                &cfg.src_prefix,
                                &cfg.filter,
                                scan_started_ns,
                                true,
                                index,
                            ),
                            finish_dst,
                        );
                        return DstPipelineLoad::SpilledToIndex {
                            src_ok,
                            src_errs,
                            dst_ok: d_ok,
                            dst_errs: d_errs,
                            observed_dst_files: d_files,
                            protected_dst_dirs: prot_d,
                        };
                    }

                    if dst_map.contains_key(&entry.nfc_path) {
                        *dst_dup_counts.entry(entry.nfc_path.clone()).or_insert(1) += 1;
                        dst_extra_dups.push(entry);
                    } else {
                        dst_map.insert(entry.nfc_path.clone(), entry);
                    }
                }
                Err(e) => {
                    dst_ok = false;
                    if dst_errs.len() < MAX_REPORT_ERRORS {
                        dst_errs.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("observe `{}` error: {e}", self.dst.name()),
                        ));
                    }
                }
            }
        }

        let dst_conflicts = dst_dup_counts
            .into_iter()
            .map(|(nfc, cnt)| SyncConflict {
                detail: format!("{cnt} destination entries share path `{nfc}`"),
                nfc_path: nfc,
                kind: ConflictKind::DuplicateDestinationName,
            })
            .collect();

        DstPipelineLoad::InMemory {
            dst_map,
            dst_conflicts,
            dst_ok,
            dst_errs,
            observed_dst_files,
            protected_dst_dirs,
        }
    }

    /// Pipelined unordered transfer execution: streams source entries directly into
    /// `TransferWorkerPool` against an in-memory destination snapshot so transfers begin
    /// immediately while `src` listing is still running.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_pipelined_unordered(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        scan_started_ns: i64,
        will_delete: bool,
        base_files_done: u64,
        base_bytes_done: u64,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        mut dst_map: HashMap<RelPath, Entry>,
        dst_conflicts: Vec<SyncConflict>,
        dst_ok: bool,
        dst_errs: Vec<TransferErrorInfo>,
        observed_dst_files: u64,
        protected_dst_dirs: ProtectedDirs,
        index: &Arc<dyn SyncDiffIndex>,
        emitter: &JobEventEmitter,
        job: &mut JobRecord,
        report: &mut RunReport,
    ) -> Result<RunReport> {
        report.dst_observation_complete = dst_ok;
        for info in dst_errs {
            if let Some(p) = &self.progress {
                p.inc_errors();
            }
            emitter.emit_error(info.clone());
            report.push_error(info);
        }

        if self.cancel.is_cancelled() {
            report.cancelled = true;
            self.finish_job(job, JobStatus::Paused, cfg.dry_run).await?;
            return Ok(std::mem::take(report));
        }

        let mut conflict_paths: HashSet<RelPath> =
            dst_conflicts.iter().map(|c| c.nfc_path.clone()).collect();
        for c in dst_conflicts {
            emitter.emit_conflict(c.clone());
            report.push_conflict(c);
        }

        let bwlimit = cfg.build_bwlimit(&self.clock)?;
        let mut active_ops = self.load_active_ops_for_pair(cfg).await?;
        let worker_pool = TransferWorkerPool::spawn(
            self,
            cfg,
            pair_key,
            src_caps,
            dst_caps,
            emitter,
            bwlimit.clone(),
            None,
            None,
        )?;

        let mut move_skips = MoveSkipRunner::spawn_for(self, cfg, None, emitter);
        let planned_files_total = Arc::new(AtomicU64::new(base_files_done));
        let planned_bytes_total = Arc::new(AtomicU64::new(base_bytes_done));
        let mut heartbeat_handle = Some(self.spawn_job_heartbeat(
            job,
            &worker_pool,
            planned_files_total.clone(),
            planned_bytes_total.clone(),
            base_files_done,
            base_bytes_done,
            None,
        ));

        if let Some(p) = &self.progress {
            p.set_totals_discovered(false);
        }

        let plan_opts = PlanOptions {
            delete: will_delete,
            max_delete: cfg.max_delete,
            checksum_mode: cfg.checksum,
            force_type_replace: cfg.force_type_replace,
            scan_started_unix_ns: scan_started_ns,
            // Completeness is strictly checked before Phase 3 deletions below.
            src_observation_complete: true,
            dst_observation_complete: dst_ok,
        };

        let mtime_tolerance_ns =
            i64::try_from(src_caps.effective_mtime_tolerance(dst_caps).as_nanos())
                .unwrap_or(i64::MAX);
        let mkdir_conc = cfg.transfers.clamp(1, 8);
        let mut observed_src_dirs: BTreeMap<usize, Vec<BackendPath>> = BTreeMap::new();
        let mut observed_src_dirs_count = 0usize;
        let mut src_ok = true;
        let mut src_err_count = 0usize;
        // Set when the worker pool stops accepting tasks (every worker exited): listing stops
        // early, so the source was NOT fully observed and Phase 3 deletes must not run.
        let mut producer_closed = false;

        let producer_res: Result<()> = async {
            let list_opts =
                ListOptions::recursive().with_filter_pruning(&cfg.filter, &cfg.src_prefix);
            let mut src_stream = match self
                .src
                .list_with_options(&cfg.src_prefix, &list_opts)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    src_ok = false;
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    let info = TransferErrorInfo::from_error_with_message(
                        None,
                        &e,
                        format!("list `{}` failed: {e}", self.src.name()),
                    );
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                    return Ok(());
                }
            };

            // Non-ASCII / NFD entries wait for listing EOF (exact NFC collision detection).
            // They are buffered in at most `OBSERVE_BATCH_SIZE` entries and then flushed into
            // the run's `SyncDiffIndex`, which spills to disk on large trees, so a tree of
            // millions of CJK names never sits in RAM.
            let mut deferred_non_ascii: Vec<Entry> = Vec::new();
            let mut deferred_total = 0usize;
            let mut deferred_ok = true;
            let mut batch: Vec<Entry> = Vec::with_capacity(PIPELINE_BATCH_SIZE);
            let mut src_eof = false;

            while !self.cancel.is_cancelled() && !producer_closed && !src_eof {
                batch.clear();
                let first = tokio::select! {
                    biased;
                    () = self.cancel.cancelled() => {
                        src_ok = false;
                        break;
                    }
                    item = src_stream.next() => item,
                };
                let Some(first_item) = first else {
                    break;
                };

                self.ingest_pipelined_src_item(
                    first_item,
                    cfg,
                    scan_started_ns,
                    &mut batch,
                    &mut deferred_non_ascii,
                    &mut src_ok,
                    &mut src_err_count,
                    emitter,
                    report,
                );

                // Drain additional immediately-ready source entries without blocking when the
                // underlying listing stream is waiting on network/disk I/O, so transfers begin
                // immediately while slow listings continue in the background.
                while batch.len() < PIPELINE_BATCH_SIZE
                    && deferred_non_ascii.len() < OBSERVE_BATCH_SIZE
                {
                    if self.cancel.is_cancelled() {
                        src_ok = false;
                        break;
                    }
                    tokio::select! {
                        biased;
                        item = src_stream.next() => {
                            match item {
                                Some(it) => {
                                    self.ingest_pipelined_src_item(
                                        it,
                                        cfg,
                                        scan_started_ns,
                                        &mut batch,
                                        &mut deferred_non_ascii,
                                        &mut src_ok,
                                        &mut src_err_count,
                                        emitter,
                                        report,
                                    );
                                }
                                None => {
                                    src_eof = true;
                                    break;
                                }
                            }
                        }
                        () = std::future::ready(()) => {
                            break;
                        }
                    }
                }

                if !batch.is_empty() {
                    producer_closed = self
                        .dispatch_pipelined_batch(
                            &mut batch,
                            cfg,
                            pair_key,
                            scan_started_ns,
                            mtime_tolerance_ns,
                            mkdir_conc,
                            src_caps,
                            dst_caps,
                            &plan_opts,
                            &mut dst_map,
                            &mut active_ops,
                            &conflict_paths,
                            &mut observed_src_dirs,
                            &mut observed_src_dirs_count,
                            &worker_pool,
                            move_skips.as_ref(),
                            bwlimit.as_ref(),
                            &planned_files_total,
                            &planned_bytes_total,
                            emitter,
                            job,
                            report,
                        )
                        .await?;
                }
                if deferred_non_ascii.len() >= OBSERVE_BATCH_SIZE {
                    deferred_total += deferred_non_ascii.len();
                    self.flush_deferred_to_index(
                        index,
                        &mut deferred_non_ascii,
                        &mut deferred_ok,
                        &mut src_ok,
                        emitter,
                        report,
                    )
                    .await;
                }
            }

            // Reconcile any deferred non-ASCII / NFD entries once source listing has reached EOF,
            // guaranteeing exact Unicode NFC collision detection before uploading them.
            deferred_total += deferred_non_ascii.len();
            if deferred_total > 0 {
                self.flush_deferred_to_index(
                    index,
                    &mut deferred_non_ascii,
                    &mut deferred_ok,
                    &mut src_ok,
                    emitter,
                    report,
                )
                .await;
            }
            if deferred_total > 0 && deferred_ok && !self.cancel.is_cancelled() && !producer_closed
            {
                // The index only holds deferred source entries (the destination snapshot is
                // in `dst_map`), so its conflicts are exactly the source NFC/duplicate
                // collisions among deferred names.
                for conflict in index
                    .finalize_and_detect_conflicts(dst_caps.case_sensitive)
                    .await?
                {
                    conflict_paths.insert(conflict.nfc_path.clone());
                    emitter.emit_conflict(conflict.clone());
                    report.push_conflict(conflict);
                }

                let mut after_id = 0i64;
                loop {
                    if self.cancel.is_cancelled() || producer_closed {
                        break;
                    }
                    let page = index.next_src_page(after_id, PIPELINE_BATCH_SIZE).await?;
                    if page.is_empty() {
                        break;
                    }
                    let mut ready: Vec<Entry> = Vec::with_capacity(page.len());
                    for row in page {
                        after_id = row.row_id;
                        let Some(e) = row.src else { continue };
                        if conflict_paths.contains(&e.nfc_path) {
                            continue;
                        }
                        // Rare singleton contraction to ASCII (e.g., Kelvin `U+212A` -> `'K'`):
                        // verify no distinct ASCII sibling exists on source before transferring.
                        if e.has_distinct_raw_path() && e.nfc_path.as_str().is_ascii() {
                            let ascii_bp =
                                BackendPath::from_rel(join_prefix(&cfg.src_prefix, &e.nfc_path)?);
                            if let Ok(Some(live)) = self.src.stat(&ascii_bp).await
                                && live.raw_path() != e.raw_path()
                            {
                                let conflict = SyncConflict {
                                    detail: format!(
                                        "source entry `{}` collides under Unicode NFC with `{}`",
                                        e.raw_path(),
                                        e.nfc_path
                                    ),
                                    nfc_path: e.nfc_path.clone(),
                                    kind: ConflictKind::UnicodeNfcCollision,
                                };
                                conflict_paths.insert(e.nfc_path);
                                emitter.emit_conflict(conflict.clone());
                                report.push_conflict(conflict);
                                continue;
                            }
                        }
                        ready.push(e);
                    }
                    if ready.is_empty() {
                        continue;
                    }
                    producer_closed = self
                        .dispatch_pipelined_batch(
                            &mut ready,
                            cfg,
                            pair_key,
                            scan_started_ns,
                            mtime_tolerance_ns,
                            mkdir_conc,
                            src_caps,
                            dst_caps,
                            &plan_opts,
                            &mut dst_map,
                            &mut active_ops,
                            &conflict_paths,
                            &mut observed_src_dirs,
                            &mut observed_src_dirs_count,
                            &worker_pool,
                            move_skips.as_ref(),
                            bwlimit.as_ref(),
                            &planned_files_total,
                            &planned_bytes_total,
                            emitter,
                            job,
                            report,
                        )
                        .await?;
                }
            }

            Ok(())
        }
        .await;

        if let Err(err) = producer_res {
            if let Some(runner) = move_skips.take() {
                runner.abort().await;
            }
            if let Some(hb) = heartbeat_handle.take() {
                hb.abort_and_await().await;
            }
            let (done_files, done_bytes) = worker_pool.progress_counters();
            worker_pool.abort_and_join().await;
            job.files_done = base_files_done.saturating_add(done_files.load(Ordering::Relaxed));
            job.bytes_done = base_bytes_done.saturating_add(done_bytes.load(Ordering::Relaxed));
            return Err(err);
        }

        if let Some(p) = &self.progress {
            p.set_totals_discovered(true);
        }
        report.src_observation_complete = src_ok && !producer_closed && !self.cancel.is_cancelled();

        worker_pool.finish(report).await;
        if let Some(runner) = move_skips.take() {
            runner.finish(report).await;
        }
        if let Some(hb) = heartbeat_handle.take() {
            hb.abort_and_await().await;
        }
        job.files_done = base_files_done.saturating_add(report.files_transferred);
        job.bytes_done = base_bytes_done.saturating_add(report.bytes_transferred);
        self.set_phase(emitter, TransferPhase::Finalizing);

        if !cfg.dry_run {
            self.fence.drain().await?;
        }

        self.cleanup_empty_src_dirs(cfg, observed_src_dirs, mkdir_conc, report)
            .await;

        if self.cancel.is_cancelled() {
            report.cancelled = true;
            self.finish_job(job, JobStatus::Paused, cfg.dry_run).await?;
            return Ok(std::mem::take(report));
        }

        // Phase 3: `--delete-after` over remaining unmatched destination entries (STRICTLY gated
        // on complete observation on BOTH sides + zero transfer errors + `--max-delete`).
        if will_delete
            && report.src_observation_complete
            && report.dst_observation_complete
            && report.errors.is_empty()
        {
            let mut delete_files_log = DeleteSpillLog::new(cfg.scratch_dir.clone());
            let mut delete_dirs_logs: BTreeMap<usize, DeleteSpillLog> = BTreeMap::new();
            let mut planned_deletes: u64 = 0;
            let mut planned_file_deletes: u64 = 0;
            let delete_plan_opts = PlanOptions {
                delete: true,
                max_delete: cfg.max_delete,
                checksum_mode: cfg.checksum,
                force_type_replace: cfg.force_type_replace,
                scan_started_unix_ns: scan_started_ns,
                src_observation_complete: report.src_observation_complete,
                dst_observation_complete: report.dst_observation_complete,
            };

            for (_, dst_entry) in dst_map {
                if conflict_paths.contains(&dst_entry.nfc_path) {
                    continue;
                }
                if dst_entry.kind == EntryKind::Directory
                    && protected_dst_dirs.is_protected(&dst_entry.nfc_path)
                {
                    continue;
                }
                if let PlannedAction::Delete { dst, kind } =
                    plan_dst_only_item(&dst_entry, &delete_plan_opts)
                {
                    planned_deletes += 1;
                    if kind != EntryKind::Directory {
                        planned_file_deletes += 1;
                    }
                    if cfg.max_delete.is_none_or(|limit| planned_deletes <= limit) {
                        match kind {
                            EntryKind::Directory => {
                                let depth = dst_entry.nfc_path.segments().count();
                                delete_dirs_logs
                                    .entry(depth)
                                    .or_insert_with(|| DeleteSpillLog::new(cfg.scratch_dir.clone()))
                                    .push_async(DeleteTarget {
                                        nfc_path: dst_entry.nfc_path,
                                        backend_path: dst,
                                        kind,
                                        expected_version: None,
                                    })
                                    .await?;
                            }
                            _ => {
                                delete_files_log
                                    .push_async(DeleteTarget {
                                        nfc_path: dst_entry.nfc_path,
                                        backend_path: dst,
                                        kind,
                                        expected_version: None,
                                    })
                                    .await?;
                            }
                        }
                    }
                }
            }

            self.execute_delete_spill_logs(
                cfg,
                pair_key,
                delete_files_log,
                delete_dirs_logs,
                &protected_dst_dirs,
                planned_deletes,
                planned_file_deletes,
                observed_dst_files,
                0,
                bwlimit.as_ref(),
                emitter,
                report,
            )
            .await?;
        } else if will_delete
            && (!report.src_observation_complete
                || !report.dst_observation_complete
                || !report.errors.is_empty())
        {
            warn!("skipping destination deletions because source scan or transfers had errors");
        }

        let final_status = resolve_final_status(report);
        if !matches!(final_status, JobStatus::Paused | JobStatus::Failed) {
            job.resume_cursor = None;
        }
        job.files_done = base_files_done.saturating_add(report.files_transferred);
        job.bytes_done = base_bytes_done.saturating_add(report.bytes_transferred);
        self.finish_job(job, final_status, cfg.dry_run).await?;
        self.set_phase(emitter, TransferPhase::Completed);

        Ok(std::mem::take(report))
    }

    /// Move the buffered deferred (non-ASCII / NFD) source entries into `index`. On an
    /// index failure the remaining deferred entries are dropped and the source observation
    /// is marked incomplete so Phase 3 deletes cannot run.
    async fn flush_deferred_to_index(
        &self,
        index: &Arc<dyn SyncDiffIndex>,
        deferred: &mut Vec<Entry>,
        deferred_ok: &mut bool,
        src_ok: &mut bool,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) {
        let entries = std::mem::take(deferred);
        if entries.is_empty() || !*deferred_ok {
            return;
        }
        if let Err(e) = index.insert_src_batch(entries).await {
            *deferred_ok = false;
            *src_ok = false;
            if let Some(p) = &self.progress {
                p.inc_errors();
            }
            let info = TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("sync index insert failed: {e}"),
            );
            emitter.emit_error(info.clone());
            report.push_error(info);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_pipelined_src_item(
        &self,
        item: Result<Entry>,
        cfg: &EngineConfig,
        scan_started_ns: i64,
        batch: &mut Vec<Entry>,
        deferred_non_ascii: &mut Vec<Entry>,
        src_ok: &mut bool,
        src_err_count: &mut usize,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) {
        match item {
            Ok(mut entry) => {
                if !cfg.src_prefix.is_root() {
                    let old_raw = entry.raw_path.take();
                    if let Some(rel) = strip_rel_prefix(&entry.nfc_path, &cfg.src_prefix) {
                        entry.nfc_path = rel;
                    } else {
                        return;
                    }
                    if let Some(raw_full) = old_raw
                        && let Some(raw_rel) = strip_raw_prefix(&raw_full, cfg.src_prefix.as_str())
                    {
                        entry.set_raw_path(&raw_rel);
                    }
                }
                if entry.nfc_path.is_root() {
                    return;
                }
                if !cfg.filter.matches_entry(&entry, scan_started_ns) {
                    return;
                }
                if !entry.nfc_path.as_str().is_ascii() || entry.has_distinct_raw_path() {
                    deferred_non_ascii.push(entry);
                } else {
                    batch.push(entry);
                }
            }
            Err(e) => {
                *src_ok = false;
                if *src_err_count < MAX_REPORT_ERRORS {
                    *src_err_count += 1;
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    let info = TransferErrorInfo::from_error_with_message(
                        None,
                        &e,
                        format!("observe `{}` error: {e}", self.src.name()),
                    );
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_pipelined_batch(
        &self,
        batch: &mut Vec<Entry>,
        cfg: &EngineConfig,
        pair_key: &str,
        scan_started_ns: i64,
        mtime_tolerance_ns: i64,
        mkdir_conc: usize,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        plan_opts: &PlanOptions,
        dst_map: &mut HashMap<RelPath, Entry>,
        active_ops: &mut HashMap<String, crate::state::OperationRecord>,
        conflict_paths: &HashSet<RelPath>,
        observed_src_dirs: &mut BTreeMap<usize, Vec<BackendPath>>,
        observed_src_dirs_count: &mut usize,
        worker_pool: &TransferWorkerPool,
        move_skips: Option<&MoveSkipRunner>,
        bwlimit: Option<&Arc<crate::bandwidth::BandwidthLimiter>>,
        planned_files_total: &Arc<AtomicU64>,
        planned_bytes_total: &Arc<AtomicU64>,
        emitter: &JobEventEmitter,
        job: &mut JobRecord,
        report: &mut RunReport,
    ) -> Result<bool> {
        let mut pairs: Vec<(Entry, Option<Entry>)> = Vec::with_capacity(batch.len());
        for src_entry in batch.drain(..) {
            if conflict_paths.contains(&src_entry.nfc_path) {
                continue;
            }
            let dst_opt = dst_map.remove(&src_entry.nfc_path);
            pairs.push((src_entry, dst_opt));
        }
        if pairs.is_empty() {
            return Ok(false);
        }

        let baseline_paths: Vec<RelPath> = pairs
            .iter()
            .filter_map(|(src_entry, dst_opt)| {
                let d = dst_opt.as_ref()?;
                needs_baseline_lookup(
                    cfg,
                    src_entry,
                    d,
                    dst_caps,
                    mtime_tolerance_ns,
                    scan_started_ns,
                )
                .then(|| src_entry.nfc_path.clone())
            })
            .collect();
        let mut page_baselines = if baseline_paths.is_empty() {
            HashMap::new()
        } else {
            self.journal
                .get_baselines_batch(pair_key, &baseline_paths)
                .await?
        };

        let mut page_mkdirs: BTreeMap<usize, Vec<PageMkdirItem>> = BTreeMap::new();
        let mut page_transfers: Vec<TransferTask> = Vec::new();
        let mut page_move_skips: Vec<PlannedMoveSkip> = Vec::new();

        for (src_entry, dst_opt) in pairs {
            if src_entry.kind == EntryKind::Directory
                && cfg.delete_empty_src_dirs
                && *observed_src_dirs_count < MAX_OBSERVED_SRC_DIRS
            {
                let bp = BackendPath::join_prefixed(
                    &cfg.src_prefix,
                    src_entry.raw_path(),
                    &src_entry.nfc_path,
                    src_entry.node_id.clone(),
                    Some(EntryKind::Directory),
                )?;
                let depth = src_entry.nfc_path.segments().count();
                observed_src_dirs.entry(depth).or_default().push(bp);
                *observed_src_dirs_count += 1;
            }
            let baseline = page_baselines.remove(&src_entry.nfc_path);
            let action = plan_source_item(
                &src_entry,
                dst_opt.as_ref(),
                baseline.as_ref(),
                src_caps,
                dst_caps,
                plan_opts,
            );
            let action = self.force_transfer_if_integrity_marked(
                cfg,
                active_ops,
                &src_entry,
                dst_opt.as_ref(),
                &src_entry.nfc_path,
                action,
            )?;
            let action = self
                .distrust_unflushed_skip(
                    cfg,
                    src_caps,
                    dst_caps,
                    active_ops,
                    &src_entry,
                    &src_entry.nfc_path,
                    dst_opt.as_ref(),
                    action,
                )
                .await?;
            match action {
                PlannedAction::Skip => {
                    if src_entry.kind == EntryKind::File {
                        let src_bp = BackendPath::join_prefixed(
                            &cfg.src_prefix,
                            src_entry.raw_path(),
                            &src_entry.nfc_path,
                            src_entry.node_id.clone(),
                            Some(EntryKind::File),
                        )?;
                        let dst_full_rel = join_prefix(&cfg.dst_prefix, &src_entry.nfc_path)?;
                        self.retire_skipped_operation(
                            cfg,
                            pair_key,
                            src_caps,
                            dst_caps,
                            active_ops,
                            &src_entry,
                            src_bp.raw_path(),
                            &src_entry.nfc_path,
                            &dst_full_rel,
                            dst_opt.as_ref(),
                        )
                        .await?;
                        if cfg.delete_source_after_transfer && !cfg.dry_run {
                            page_move_skips.push(PlannedMoveSkip {
                                src_bp,
                                result_path: src_entry.nfc_path.as_str().to_string(),
                                expected_ver: SourceVersion::from_entry(&src_entry),
                                wire_key: None,
                            });
                        } else {
                            self.handle_planned_file_skip(
                                cfg,
                                &src_entry,
                                &src_bp,
                                src_entry.nfc_path.as_str(),
                                emitter,
                                report,
                            )
                            .await;
                        }
                    } else if src_entry.kind != EntryKind::Directory {
                        report.files_skipped += 1;
                        if let Some(p) = &self.progress {
                            p.add_planned_skip();
                        }
                    }
                }
                PlannedAction::Mkdir { path } => {
                    let target = join_prefix(&cfg.dst_prefix, &path)?;
                    let depth = target.segments().count();
                    page_mkdirs
                        .entry(depth)
                        .or_default()
                        .push((target, None, None));
                }
                PlannedAction::ReplaceWithDir {
                    path,
                    dst_to_delete,
                } => {
                    let target = join_prefix(&cfg.dst_prefix, &path)?;
                    let full_del = BackendPath::join_prefixed(
                        &cfg.dst_prefix,
                        dst_to_delete.raw_path(),
                        &dst_to_delete.nfc_path,
                        dst_to_delete.node_id.clone(),
                        Some(EntryKind::File),
                    )?;
                    let depth = target.segments().count();
                    page_mkdirs.entry(depth).or_default().push((
                        target,
                        Some((path, full_del)),
                        None,
                    ));
                }
                PlannedAction::Transfer(pt) => {
                    let crate::planner::PlannedTransfer {
                        src,
                        dst_path,
                        existing_dst_node_id,
                        precondition,
                        needs_checksum_verify,
                        replace_dst_dir,
                    } = *pt;
                    let size = src.size;
                    job.files_total += 1;
                    job.bytes_total = job.bytes_total.saturating_add(size);
                    planned_files_total.store(job.files_total, Ordering::Relaxed);
                    planned_bytes_total.store(job.bytes_total, Ordering::Relaxed);
                    if let Some(p) = &self.progress {
                        p.add_planned_file(size);
                    }
                    page_transfers.push(TransferTask {
                        src,
                        dst_rel: dst_path,
                        existing_dst_node_id,
                        precondition,
                        needs_checksum_verify,
                        dst_existing: dst_opt,
                        wire_key: None,
                        replace_dst_dir,
                        defer_op_commit: false,
                    });
                }
                PlannedAction::Conflict(c) => {
                    emitter.emit_conflict(c.clone());
                    report.push_conflict(c);
                }
                PlannedAction::Delete { .. } => {}
            }
        }

        self.execute_page_mkdirs(
            cfg,
            pair_key,
            page_mkdirs,
            mkdir_conc,
            bwlimit,
            None,
            emitter,
            report,
        )
        .await;

        let mut producer_closed = false;
        if !page_transfers.is_empty() {
            self.set_phase(emitter, TransferPhase::Transferring);
            for task in page_transfers {
                if self.cancel.is_cancelled() {
                    break;
                }
                if !worker_pool.send(task).await {
                    producer_closed = true;
                    break;
                }
            }
        }
        submit_move_skips(move_skips, page_move_skips).await;
        Ok(producer_closed)
    }
}
