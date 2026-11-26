//! Zero-disk two-pointer streaming merge-join loop for ordered UTF-8 object stores
//! (`S3`, `GCS`, `Azure`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

use crate::backend::{BackendPath, ListOptions};
use crate::error::Result;
use crate::path::RelPath;
use crate::planner::{PlanOptions, PlannedAction, plan_dst_only_item, plan_source_item};
use crate::progress::{JobEventEmitter, TransferPhase};
use crate::state::{JobRecord, JobStatus, SourceVersion};
use crate::types::{Capabilities, Entry, EntryKind};

use super::super::diff::{
    DeleteSpillLog, DeleteTarget, DiffItem, SafeWatermarkTracker, StreamingMergeDiffSource,
    entry_wire_key,
};
use super::super::move_skips::{MoveSkipRunner, submit_move_skips};
use super::super::pool::TransferWorkerPool;
use super::super::task::TransferTask;
use super::super::{
    EngineConfig, FileTransferResult, MAX_OBSERVED_SRC_DIRS, PlannedMoveSkip, ProtectedDirs,
    RunReport, TransferEngine, join_prefix, needs_baseline_lookup, push_file_result,
};
use super::{PageMkdirItem, STREAM_MERGE_BATCH_SIZE, resolve_final_status};

impl TransferEngine {
    /// Zero-disk two-pointer streaming merge-join loop for ordered UTF-8 object stores
    /// (`S3`, `GCS`, `Azure`).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_streaming_merge(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        scan_started_ns: i64,
        will_delete: bool,
        base_files_done: u64,
        base_bytes_done: u64,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        emitter: &JobEventEmitter,
        job: &mut JobRecord,
        report: &mut RunReport,
    ) -> Result<RunReport> {
        self.set_phase(emitter, TransferPhase::Observing);

        let dir_pruner = ListOptions::recursive()
            .with_filter_pruning(&cfg.filter, &RelPath::root())
            .dir_pruner()
            .cloned();
        let initial_cursor = if !will_delete {
            cfg.resume_cursor.clone()
        } else {
            None
        };

        let mut diff = StreamingMergeDiffSource::start(
            self.src.clone(),
            cfg.src_prefix.clone(),
            self.dst.clone(),
            cfg.dst_prefix.clone(),
            initial_cursor,
            dir_pruner.clone(),
            dir_pruner,
            self.cancel.clone(),
        )
        .await?;

        if let Some(p) = &self.progress {
            p.set_totals_discovered(diff.totals_known_immediately());
        }

        let watermark = if diff.supports_resume_cursor() && !will_delete && !cfg.dry_run {
            Some(SafeWatermarkTracker::new())
        } else {
            None
        };

        let bwlimit = cfg.build_bwlimit(&self.clock)?;
        let mut active_ops = self.load_active_ops_for_pair(cfg).await?;
        let mut worker_pool = if !cfg.dry_run {
            Some(TransferWorkerPool::spawn(
                self,
                cfg,
                pair_key,
                src_caps,
                dst_caps,
                emitter,
                bwlimit.clone(),
                None,
                watermark.clone(),
            )?)
        } else {
            None
        };

        let mut move_skips = MoveSkipRunner::spawn_for(self, cfg, watermark.clone(), emitter);

        let planned_files_total = Arc::new(AtomicU64::new(base_files_done));
        let planned_bytes_total = Arc::new(AtomicU64::new(base_bytes_done));
        let mut heartbeat_handle = worker_pool.as_ref().map(|pool| {
            self.spawn_job_heartbeat(
                job,
                pool,
                planned_files_total.clone(),
                planned_bytes_total.clone(),
                base_files_done,
                base_bytes_done,
                watermark.clone(),
            )
        });

        let plan_opts = PlanOptions {
            delete: will_delete,
            max_delete: cfg.max_delete,
            checksum_mode: cfg.checksum,
            force_type_replace: cfg.force_type_replace,
            scan_started_unix_ns: scan_started_ns,
            // Completeness is checked strictly before executing Phase 3 deletes below.
            src_observation_complete: true,
            dst_observation_complete: true,
        };

        let mtime_tolerance_ns =
            i64::try_from(src_caps.effective_mtime_tolerance(dst_caps).as_nanos())
                .unwrap_or(i64::MAX);
        let mkdir_conc = cfg.transfers.clamp(1, 8);

        let mut observed_src_dirs: BTreeMap<usize, Vec<BackendPath>> = BTreeMap::new();
        let mut observed_src_dirs_count = 0usize;
        let mut delete_files_log = DeleteSpillLog::new(cfg.scratch_dir.clone());
        let mut delete_dirs_logs: BTreeMap<usize, DeleteSpillLog> = BTreeMap::new();
        let mut protected_dst_dirs = ProtectedDirs::default();
        let mut observed_dst_files: u64 = 0;
        let mut planned_deletes: u64 = 0;
        let mut planned_file_deletes: u64 = 0;
        let mut producer_closed = false;

        let mut batch_src_rows: Vec<(Entry, Option<Entry>)> =
            Vec::with_capacity(STREAM_MERGE_BATCH_SIZE);

        let stream_res: Result<()> = async {
            loop {
                if self.cancel.is_cancelled() || producer_closed {
                    break;
                }
                batch_src_rows.clear();
                let mut hit_eof = false;

                while batch_src_rows.len() < STREAM_MERGE_BATCH_SIZE {
                    if self.cancel.is_cancelled() {
                        break;
                    }
                    let Some(item) = diff.next_item().await else {
                        if let Some(ref wm) = watermark {
                            wm.set_buffered_floor(None);
                        }
                        hit_eof = true;
                        break;
                    };
                    if let Some(ref wm) = watermark {
                        wm.set_buffered_floor(diff.min_buffered_src_wire_key());
                    }
                    match item {
                        DiffItem::Conflict(c) => {
                            if let Some(ref wm) = watermark {
                                wm.mark_completed(c.nfc_path.as_str(), false);
                            }
                            emitter.emit_conflict(c.clone());
                            report.push_conflict(c);
                        }
                        DiffItem::DstOnly(dst_entry) => {
                            let matched = cfg.filter.matches_entry(&dst_entry, scan_started_ns);
                            if !matched {
                                protected_dst_dirs.protect_ancestors(&dst_entry.nfc_path);
                            } else if dst_entry.kind == EntryKind::File {
                                observed_dst_files += 1;
                            }
                            if will_delete
                                && matched
                                && let PlannedAction::Delete { dst, kind } =
                                    plan_dst_only_item(&dst_entry, &plan_opts)
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
                                                .or_insert_with(|| {
                                                    DeleteSpillLog::new(cfg.scratch_dir.clone())
                                                })
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
                            } else if let Some(ref wm) = watermark {
                                wm.mark_skipped(&entry_wire_key(&dst_entry));
                            }
                        }
                        DiffItem::SrcOnly(src_entry) => {
                            let wk = entry_wire_key(&src_entry);
                            if !cfg.filter.matches_entry(&src_entry, scan_started_ns) {
                                if let Some(ref wm) = watermark {
                                    wm.mark_skipped(&wk);
                                }
                                continue;
                            }
                            // Register immediately in `in_flight` BEFORE batch staging so no
                            // later skipped key in the 1,000-row batch can leapfrog `resume_cursor`!
                            if let Some(ref wm) = watermark {
                                wm.mark_dispatched(wk);
                            }
                            batch_src_rows.push((src_entry, None));
                        }
                        DiffItem::Both { src, dst } => {
                            if dst.kind == EntryKind::File
                                && cfg.filter.matches_entry(&dst, scan_started_ns)
                            {
                                observed_dst_files += 1;
                            }
                            let wk = entry_wire_key(&src);
                            // Post-merge filtering: if `src` is excluded by `--min-size`/`--max-age`/
                            // `--exclude`, we neither transfer `src` nor falsely delete `dst`!
                            if !cfg.filter.matches_entry(&src, scan_started_ns) {
                                protected_dst_dirs.protect_ancestors(&dst.nfc_path);
                                if let Some(ref wm) = watermark {
                                    wm.mark_skipped(&wk);
                                }
                                continue;
                            }
                            if let Some(ref wm) = watermark {
                                wm.mark_dispatched(wk);
                            }
                            batch_src_rows.push((src, Some(dst)));
                        }
                    }
                }

                if !batch_src_rows.is_empty() {
                    let baseline_paths: Vec<RelPath> = batch_src_rows
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

                    for (src_entry, dst_opt) in batch_src_rows.drain(..) {
                        if src_entry.kind == EntryKind::Directory
                            && cfg.delete_empty_src_dirs
                            && observed_src_dirs_count < MAX_OBSERVED_SRC_DIRS
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
                            observed_src_dirs_count += 1;
                        }
                        let wk = entry_wire_key(&src_entry);
                        let baseline = page_baselines.remove(&src_entry.nfc_path);
                        let action = plan_source_item(
                            &src_entry,
                            dst_opt.as_ref(),
                            baseline.as_ref(),
                            src_caps,
                            dst_caps,
                            &plan_opts,
                        );
                        let action = self.force_transfer_if_integrity_marked(
                            cfg,
                            &active_ops,
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
                                &mut active_ops,
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
                                    let dst_full_rel =
                                        join_prefix(&cfg.dst_prefix, &src_entry.nfc_path)?;
                                    self.retire_skipped_operation(
                                        cfg,
                                        pair_key,
                                        src_caps,
                                        dst_caps,
                                        &mut active_ops,
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
                                            wire_key: Some(wk),
                                        });
                                    } else {
                                        let errs_before = report.errors.len();
                                        self.handle_planned_file_skip(
                                            cfg,
                                            &src_entry,
                                            &src_bp,
                                            src_entry.nfc_path.as_str(),
                                            emitter,
                                            report,
                                        )
                                        .await;
                                        if let Some(ref wm) = watermark {
                                            wm.mark_completed(
                                                &wk,
                                                report.errors.len() == errs_before,
                                            );
                                        }
                                    }
                                } else {
                                    if src_entry.kind != EntryKind::Directory {
                                        report.files_skipped += 1;
                                        if let Some(p) = &self.progress {
                                            p.add_planned_skip();
                                        }
                                    }
                                    if let Some(ref wm) = watermark {
                                        wm.mark_completed(&wk, true);
                                    }
                                }
                            }
                            PlannedAction::Mkdir { path } => {
                                let target = join_prefix(&cfg.dst_prefix, &path)?;
                                if cfg.dry_run {
                                    report.dirs_created += 1;
                                    if let Some(p) = &self.progress {
                                        p.inc_dirs_created();
                                    }
                                    if let Some(ref wm) = watermark {
                                        wm.mark_completed(&wk, true);
                                    }
                                } else {
                                    let depth = target.segments().count();
                                    page_mkdirs.entry(depth).or_default().push((
                                        target,
                                        None,
                                        Some(wk),
                                    ));
                                }
                            }
                            PlannedAction::ReplaceWithDir {
                                path,
                                dst_to_delete,
                            } => {
                                let target = join_prefix(&cfg.dst_prefix, &path)?;
                                if cfg.dry_run {
                                    report.items_deleted += 1;
                                    report.dirs_created += 1;
                                    if let Some(p) = &self.progress {
                                        p.inc_dirs_created();
                                    }
                                    if let Some(ref wm) = watermark {
                                        wm.mark_completed(&wk, true);
                                    }
                                } else {
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
                                        Some(wk),
                                    ));
                                }
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
                                if cfg.dry_run {
                                    report.files_transferred += 1;
                                    report.bytes_transferred =
                                        report.bytes_transferred.saturating_add(size);
                                    if cfg.delete_source_after_transfer {
                                        report.sources_deleted += 1;
                                    }
                                    if let Some(p) = &self.progress {
                                        p.inc_files_done();
                                        p.add_bytes_done(size);
                                        if cfg.delete_source_after_transfer {
                                            p.inc_sources_deleted();
                                        }
                                    }
                                    push_file_result(
                                        &mut report.file_results,
                                        &mut report.file_results_truncated,
                                        Some(emitter),
                                        FileTransferResult::transferred(
                                            dst_path.as_str(),
                                            size,
                                            cfg.delete_source_after_transfer,
                                        ),
                                    );
                                    if let Some(ref wm) = watermark {
                                        wm.mark_completed(&wk, true);
                                    }
                                    continue;
                                }
                                page_transfers.push(TransferTask {
                                    src,
                                    dst_rel: dst_path,
                                    existing_dst_node_id,
                                    precondition,
                                    needs_checksum_verify,
                                    dst_existing: dst_opt,
                                    wire_key: Some(wk),
                                    replace_dst_dir,
                                    defer_op_commit: false,
                                });
                            }
                            PlannedAction::Conflict(c) => {
                                if let Some(ref wm) = watermark {
                                    wm.mark_completed(&wk, false);
                                }
                                emitter.emit_conflict(c.clone());
                                report.push_conflict(c);
                            }
                            PlannedAction::Delete { .. } => {
                                if let Some(ref wm) = watermark {
                                    wm.mark_completed(&wk, true);
                                }
                            }
                        }
                    }

                    self.execute_page_mkdirs(
                        cfg,
                        pair_key,
                        page_mkdirs,
                        mkdir_conc,
                        bwlimit.as_ref(),
                        watermark.as_ref(),
                        emitter,
                        report,
                    )
                    .await;

                    if !page_transfers.is_empty() {
                        self.set_phase(emitter, TransferPhase::Transferring);
                    }
                    if let Some(ref pool) = worker_pool {
                        for task in page_transfers {
                            if self.cancel.is_cancelled() {
                                break;
                            }
                            if !pool.send(task).await {
                                producer_closed = true;
                                break;
                            }
                        }
                    }
                    submit_move_skips(move_skips.as_ref(), page_move_skips).await;
                }

                if hit_eof {
                    break;
                }
            }
            Ok(())
        }
        .await;

        if let Err(err) = stream_res {
            if let Some(runner) = move_skips.take() {
                runner.abort().await;
            }
            if let Some(hb) = heartbeat_handle.take() {
                hb.abort_and_await().await;
            }
            if let Some(pool) = worker_pool.take() {
                let (done_files, done_bytes) = pool.progress_counters();
                pool.abort_and_join().await;
                job.files_done = base_files_done.saturating_add(done_files.load(Ordering::Relaxed));
                job.bytes_done = base_bytes_done.saturating_add(done_bytes.load(Ordering::Relaxed));
            }
            return Err(err);
        }

        if let Some(p) = &self.progress {
            p.set_totals_discovered(true);
        }

        for info in diff.drain_errors() {
            if let Some(p) = &self.progress {
                p.inc_errors();
            }
            emitter.emit_error(info.clone());
            report.push_error(info);
        }
        // A closed producer (every transfer worker exited) stopped the merge early, so the
        // source was not fully observed and planned deletes must not run.
        report.src_observation_complete =
            diff.src_complete() && !producer_closed && !self.cancel.is_cancelled();
        report.dst_observation_complete = diff.dst_complete() && !self.cancel.is_cancelled();

        if let Some(pool) = worker_pool.take() {
            pool.finish(report).await;
        }
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
            if let Some(cur) = watermark
                .as_ref()
                .and_then(SafeWatermarkTracker::current_watermark)
            {
                job.resume_cursor = Some(cur);
            }
            self.finish_job(job, JobStatus::Paused, cfg.dry_run).await?;
            return Ok(std::mem::take(report));
        }

        // Phase 3: `--delete-after` from `DeleteSpillLog` (STRICTLY gated on complete
        // observation + zero transfer errors + `--max-delete` circuit breaker).
        if will_delete
            && report.src_observation_complete
            && report.dst_observation_complete
            && report.errors.is_empty()
        {
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
        if matches!(final_status, JobStatus::Paused | JobStatus::Failed) {
            if let Some(cur) = watermark
                .as_ref()
                .and_then(SafeWatermarkTracker::current_watermark)
            {
                job.resume_cursor = Some(cur);
            }
        } else {
            job.resume_cursor = None;
        }
        job.files_done = base_files_done.saturating_add(report.files_transferred);
        job.bytes_done = base_bytes_done.saturating_add(report.bytes_transferred);
        self.finish_job(job, final_status, cfg.dry_run).await?;
        self.set_phase(emitter, TransferPhase::Completed);

        Ok(std::mem::take(report))
    }
}
