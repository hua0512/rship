//! Full directory Observation -> Planning -> Transfer -> (`--delete-after`) engine loop.

mod delete;
mod pipelined;
mod streaming;

use futures::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

use crate::backend::BackendPath;
use crate::error::Result;
use crate::path::RelPath;
use crate::planner::{PlanOptions, PlannedAction, plan_source_item};
use crate::progress::{JobEventEmitter, JobEventGuard, TransferPhase};
use crate::state::{BaselineMode, JobMode, JobRecord, JobStatus, SourceVersion, SyncDiffIndex};
use crate::types::EntryKind;

use super::diff::SafeWatermarkTracker;
use super::move_skips::{MoveSkipRunner, submit_move_skips};
use super::pool::TransferWorkerPool;
use super::task::{TransferTask, archive_dst_file_to_backup};
use super::{
    DIFF_PAGE_SIZE, DeleteMode, EngineConfig, FileTransferResult, MAX_OBSERVED_SRC_DIRS,
    PlannedMoveSkip, ProtectedDirs, RunReport, TransferEngine, TransferErrorInfo,
    check_overlapping_roots, join_prefix, make_prefixed_pair_key, needs_baseline_lookup,
    push_file_result, validate_backup_dir_overlap, validate_max_delete_percent,
};

pub(super) const STREAM_MERGE_BATCH_SIZE: usize = 1000;
pub(super) const DELETE_FILE_CHUNK: usize = 1000;

pub(super) type PageMkdirItem = (RelPath, Option<(RelPath, BackendPath)>, Option<String>);

pub(super) fn resolve_final_status(report: &RunReport) -> JobStatus {
    if report.cancelled {
        JobStatus::Paused
    } else if !report.errors.is_empty() {
        JobStatus::Failed
    } else if !report.conflicts.is_empty() {
        JobStatus::CompletedWithConflicts
    } else {
        JobStatus::Completed
    }
}

impl TransferEngine {
    /// Execute a full Observation -> Planning -> Transfer -> (--delete-after) run.
    pub async fn run(
        &self,
        cfg: &EngineConfig,
        index: Arc<dyn SyncDiffIndex>,
    ) -> Result<RunReport> {
        let mut run_cfg = cfg.clone();
        run_cfg.pin_run_retry_quota(self.dst.as_ref());
        let cfg = &run_cfg;
        validate_max_delete_percent(cfg.max_delete_percent)?;
        let will_delete = cfg.delete && matches!(cfg.mode, JobMode::Sync);
        // Rclone `TestSyncOverlap` / `TestSyncOverlapWithFilter` safety guard:
        // reject overlapping src/dst trees BEFORE scanning or mutating anything!
        check_overlapping_roots(
            &self.src.endpoint_identity(),
            &cfg.src_prefix,
            &self.dst.endpoint_identity(),
            &cfg.dst_prefix,
            &cfg.filter,
        )?;
        // Rclone `TestSyncBackupDir` safety guard: `--backup-dir` MUST NOT overlap `src` or `dst`!
        if let Some(ref bk) = cfg.backup_dir {
            validate_backup_dir_overlap(
                &self.src.endpoint_identity(),
                &cfg.src_prefix,
                &self.dst.endpoint_identity(),
                &cfg.dst_prefix,
                bk,
            )?;
        }

        // Streaming direct-stat fast path for `--files-from` without `--delete`:
        // bypasses `SyncDiffIndex` completely so 500k-line manifests stream in 512-file
        // chunks with `O(1)` memory and zero disk index amplification.
        if !will_delete && let Some(listed) = cfg.filter.files_from_paths() {
            return self.run_file_list(cfg, listed).await;
        }

        let now_s = self.clock.now_unix_secs();
        let scan_started_ns = self.clock.now_unix_nanos();
        let pair_key = make_prefixed_pair_key(
            &self.src.endpoint_identity(),
            &cfg.src_prefix,
            &self.dst.endpoint_identity(),
            &cfg.dst_prefix,
        );

        let prev_job = if !cfg.dry_run {
            self.journal.get_job(&cfg.job_id).await?
        } else {
            None
        };
        let base_files_done = prev_job.as_ref().map_or(0, |j| j.files_done);
        let base_bytes_done = prev_job.as_ref().map_or(0, |j| j.bytes_done);
        let created_at = prev_job.as_ref().map_or(now_s, |j| j.created_at);

        let mut job = JobRecord {
            job_id: cfg.job_id.clone(),
            mode: cfg.mode,
            src_spec: cfg.src_spec.clone(),
            dst_spec: cfg.dst_spec.clone(),
            status: JobStatus::Running,
            files_total: base_files_done,
            files_done: base_files_done,
            bytes_total: base_bytes_done,
            bytes_done: base_bytes_done,
            created_at,
            updated_at: now_s,
            options_json: cfg.options_json.clone(),
            resume_cursor: cfg.resume_cursor.clone(),
        };
        if !cfg.dry_run {
            self.journal.upsert_job(&job).await?;
        }

        let mut report = RunReport {
            job_id: cfg.job_id.clone(),
            ..Default::default()
        };

        let (event_guard, emitter) =
            JobEventGuard::start(&cfg.job_id, cfg.mode, self.events.clone());

        let run_res: Result<RunReport> = async {
            let src_caps = self.src.capabilities();
            let dst_caps = self.dst.capabilities();

            // Zero-disk streaming merge-join fast path for ordered UTF-8 case-sensitive object
            // stores (S3, GCS, Azure):
            // - Small buckets (<= 1,000 objects/side): Gear 1 executes 1 RPC/side, knows exact
            //   totals immediately, creates 0 disk files, and starts transferring on Page 1.
            // - Massive buckets (40M+ objects): Gear 2 dynamic midpoint work-stealing bisection
            //   streams in O(1) RAM with zero SQLite index and zero local disk amplification.
            let can_stream_merge = src_caps.supports_ordered_utf8_list
                && dst_caps.supports_ordered_utf8_list
                && src_caps.case_sensitive
                && dst_caps.case_sensitive
                && cfg.filter.files_from_paths().is_none()
                && !cfg.no_traverse
                && !(will_delete && cfg.delete_mode != DeleteMode::After);
            if can_stream_merge {
                return self
                    .run_streaming_merge(
                        cfg,
                        &pair_key,
                        scan_started_ns,
                        will_delete,
                        base_files_done,
                        base_bytes_done,
                        &src_caps,
                        &dst_caps,
                        &emitter,
                        &mut job,
                        &mut report,
                    )
                    .await;
            }

            // Phase 1: Observation — either pipelined unordered streaming (`!allows_duplicate_names`
            // on `src` + case-sensitive `dst`), direct-stat (`--no-traverse` / `--files-from` without
            // `--delete`), or concurrent full-tree observation into adaptive hybrid SyncIndex.
            self.set_phase(&emitter, TransferPhase::Observing);
            let can_pipeline_unordered = !cfg.dry_run
                && !src_caps.allows_duplicate_names
                && dst_caps.case_sensitive
                && cfg.filter.files_from_paths().is_none()
                && !cfg.no_traverse
                && !(will_delete && cfg.delete_mode != DeleteMode::After);

            let ((src_ok, src_errs), (dst_ok, dst_errs), observed_dst_files, protected_dst_dirs) =
                if can_pipeline_unordered {
                    match self
                        .observe_dst_for_pipeline(cfg, scan_started_ns, &index)
                        .await
                    {
                        pipelined::DstPipelineLoad::InMemory {
                            dst_map,
                            dst_conflicts,
                            dst_ok,
                            dst_errs,
                            observed_dst_files,
                            protected_dst_dirs,
                        } => {
                            return self
                                .run_pipelined_unordered(
                                    cfg,
                                    &pair_key,
                                    scan_started_ns,
                                    will_delete,
                                    base_files_done,
                                    base_bytes_done,
                                    &src_caps,
                                    &dst_caps,
                                    dst_map,
                                    dst_conflicts,
                                    dst_ok,
                                    dst_errs,
                                    observed_dst_files,
                                    protected_dst_dirs,
                                    &index,
                                    &emitter,
                                    &mut job,
                                    &mut report,
                                )
                                .await;
                        }
                        pipelined::DstPipelineLoad::SpilledToIndex {
                            src_ok,
                            src_errs,
                            dst_ok,
                            dst_errs,
                            observed_dst_files,
                            protected_dst_dirs,
                        } => (
                            (src_ok, src_errs),
                            (dst_ok, dst_errs),
                            observed_dst_files,
                            protected_dst_dirs,
                        ),
                    }
                } else if let Some(listed) = cfg.filter.files_from_paths()
                    && (cfg.no_traverse || !will_delete)
                {
                    let (s, d, dst_files) = self
                        .observe_files_from(
                            listed,
                            &cfg.src_prefix,
                            &cfg.dst_prefix,
                            &cfg.filter,
                            scan_started_ns,
                            cfg.transfers,
                            &index,
                        )
                        .await;
                    (s, d, dst_files, ProtectedDirs::default())
                } else {
                    let ((so, _, se, _), (do_, dst_files, de, prot_dst)) = tokio::join!(
                        self.observe_side(
                            &self.src,
                            &cfg.src_prefix,
                            &cfg.filter,
                            scan_started_ns,
                            true,
                            &index
                        ),
                        self.observe_side(
                            &self.dst,
                            &cfg.dst_prefix,
                            &cfg.filter,
                            scan_started_ns,
                            false,
                            &index
                        ),
                    );
                    ((so, se), (do_, de), dst_files, prot_dst)
                };
            report.src_observation_complete = src_ok;
            report.dst_observation_complete = dst_ok;
            for info in src_errs.into_iter().chain(dst_errs) {
                if let Some(path) = info.path.clone() {
                    if let Some(p) = &self.progress {
                        p.add_planned_error();
                    }
                    let result = FileTransferResult::from_error_info(path, &info);
                    report.push_error(info);
                    push_file_result(
                        &mut report.file_results,
                        &mut report.file_results_truncated,
                        Some(&emitter),
                        result,
                    );
                } else {
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                }
            }

            if self.cancel.is_cancelled() {
                report.cancelled = true;
                self.finish_job(&mut job, JobStatus::Paused, cfg.dry_run)
                    .await?;
                return Ok(report);
            }

            let conflicts = index
                .finalize_and_detect_conflicts(dst_caps.case_sensitive)
                .await?;
            let conflict_paths: HashSet<RelPath> =
                conflicts.iter().map(|c| c.nfc_path.clone()).collect();
            for c in conflicts {
                emitter.emit_conflict(c.clone());
                report.push_conflict(c);
            }

            let plan_opts = PlanOptions {
                delete: cfg.delete && matches!(cfg.mode, JobMode::Sync),
                max_delete: cfg.max_delete,
                checksum_mode: cfg.checksum,
                force_type_replace: cfg.force_type_replace,
                scan_started_unix_ns: scan_started_ns,
                src_observation_complete: src_ok,
                dst_observation_complete: dst_ok,
            };

            let bwlimit = cfg.build_bwlimit(&self.clock)?;

            // `--delete-before`: remove extraneous destination items BEFORE starting Phase 2 transfers
            // (strictly gated on Observation Completeness Gate + `--max-delete` circuit breaker!).
            let mut deletes_executed = false;
            if plan_opts.delete && cfg.delete_mode == DeleteMode::Before {
                deletes_executed = true;
                if plan_opts.src_observation_complete
                    && plan_opts.dst_observation_complete
                    && report.errors.is_empty()
                {
                    self.execute_indexed_delete_pass(
                        cfg,
                        &pair_key,
                        scan_started_ns,
                        &index,
                        &conflict_paths,
                        &protected_dst_dirs,
                        &plan_opts,
                        observed_dst_files,
                        bwlimit.as_ref(),
                        &emitter,
                        &mut report,
                    )
                    .await?;
                } else {
                    warn!("skipping --delete-before deletions because observation had errors");
                }
                if report.cancelled {
                    self.finish_job(&mut job, JobStatus::Paused, cfg.dry_run)
                        .await?;
                    return Ok(report);
                }
                if !report.errors.is_empty() {
                    self.finish_job(&mut job, JobStatus::Failed, cfg.dry_run)
                        .await?;
                    self.set_phase(&emitter, TransferPhase::Completed);
                    return Ok(report);
                }
            }

            // Phase 2: Pull-driven bounded worker pool for source pass (Mkdir + Transfers).
            let mut worker_pool = if !cfg.dry_run {
                Some(TransferWorkerPool::spawn(
                    self,
                    cfg,
                    &pair_key,
                    &src_caps,
                    &dst_caps,
                    &emitter,
                    bwlimit.clone(),
                    None,
                    None,
                )?)
            } else {
                None
            };

            // 2-second debounced progress heartbeat for `journal.db`:
            // - Runs < 2s pay 0 extra SQLite writes.
            // - Hour-long jobs (even with zero-WAL single-shot + `--baseline=auto`) flush live
            //   `(files_total, files_done, bytes_total, bytes_done)` every 2s so `rship status`
            //   reflects real progress and hard crashes preserve recent counters.
            let planned_files_total = Arc::new(AtomicU64::new(base_files_done));
            let planned_bytes_total = Arc::new(AtomicU64::new(base_bytes_done));
            let mut heartbeat_handle = worker_pool.as_ref().map(|pool| {
                self.spawn_job_heartbeat(
                    &job,
                    pool,
                    planned_files_total.clone(),
                    planned_bytes_total.clone(),
                    base_files_done,
                    base_bytes_done,
                    None,
                )
            });

            // Track observed source directories by depth for optional `--delete-empty-src-dirs` in `move`.
            let mut observed_src_dirs: BTreeMap<usize, Vec<BackendPath>> = BTreeMap::new();
            let mut observed_src_dirs_count = 0usize;

            // Producer: stream keyset-paginated source diff rows into bounded channel(s).
            // Wrapped in an inner async block so ANY early `?` deterministically aborts and joins
            // both the worker pool and heartbeat task before returning!
            let mtime_tolerance_ns =
                i64::try_from(src_caps.effective_mtime_tolerance(&dst_caps).as_nanos())
                    .unwrap_or(i64::MAX);
            let mkdir_conc = cfg.transfers.clamp(1, 8);
            let mut active_ops = self.load_active_ops_for_pair(cfg).await?;
            let mut move_skips = MoveSkipRunner::spawn_for(self, cfg, None, &emitter);
            let producer_res: Result<()> = async {
                let mut after_id = 0i64;
                let mut producer_closed = false;
                loop {
                    if self.cancel.is_cancelled() || producer_closed {
                        break;
                    }
                    let page = index.next_src_page(after_id, DIFF_PAGE_SIZE).await?;
                    if page.is_empty() {
                        break;
                    }
                    let mut page_mkdirs: BTreeMap<usize, Vec<PageMkdirItem>> = BTreeMap::new();
                    let mut page_transfers: Vec<TransferTask> = Vec::new();
                    let mut page_move_skips: Vec<PlannedMoveSkip> = Vec::new();

                    // Batch-fetch durable `sync_baseline` rows only for ambiguous same-size files
                    // that cannot be decided directly from live checksums or destination mtimes.
                    let baseline_paths: Vec<RelPath> = page
                        .iter()
                        .filter_map(|row| {
                            let src_entry = row.src.as_ref()?;
                            if conflict_paths.contains(&src_entry.nfc_path) {
                                return None;
                            }
                            let d = row.dst.as_ref()?;
                            needs_baseline_lookup(
                                cfg,
                                src_entry,
                                d,
                                &dst_caps,
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
                            .get_baselines_batch(&pair_key, &baseline_paths)
                            .await?
                    };

                    for row in page {
                        after_id = row.row_id;
                        let Some(src_entry) = row.src else { continue };
                        if conflict_paths.contains(&src_entry.nfc_path) {
                            continue;
                        }
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
                        let baseline = page_baselines.remove(&src_entry.nfc_path);
                        let action = plan_source_item(
                            &src_entry,
                            row.dst.as_ref(),
                            baseline.as_ref(),
                            &src_caps,
                            &dst_caps,
                            &plan_opts,
                        );
                        let action = self.force_transfer_if_integrity_marked(
                            cfg,
                            &active_ops,
                            &src_entry,
                            row.dst.as_ref(),
                            &src_entry.nfc_path,
                            action,
                        )?;
                        let action = self
                            .distrust_unflushed_skip(
                                cfg,
                                &src_caps,
                                &dst_caps,
                                &mut active_ops,
                                &src_entry,
                                &src_entry.nfc_path,
                                row.dst.as_ref(),
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
                                        &pair_key,
                                        &src_caps,
                                        &dst_caps,
                                        &mut active_ops,
                                        &src_entry,
                                        src_bp.raw_path(),
                                        &src_entry.nfc_path,
                                        &dst_full_rel,
                                        row.dst.as_ref(),
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
                                            &emitter,
                                            &mut report,
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
                                if cfg.dry_run {
                                    report.dirs_created += 1;
                                    if let Some(p) = &self.progress {
                                        p.inc_dirs_created();
                                    }
                                } else {
                                    let depth = target.segments().count();
                                    page_mkdirs
                                        .entry(depth)
                                        .or_default()
                                        .push((target, None, None));
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
                                        None,
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
                                        Some(&emitter),
                                        FileTransferResult::transferred(
                                            dst_path.as_str(),
                                            size,
                                            cfg.delete_source_after_transfer,
                                        ),
                                    );
                                    continue;
                                }
                                page_transfers.push(TransferTask {
                                    src,
                                    dst_rel: dst_path,
                                    existing_dst_node_id,
                                    precondition,
                                    needs_checksum_verify,
                                    dst_existing: row.dst,
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

                    // Create missing directories depth-by-depth concurrently so parent folders
                    // exist before children and remote APIs aren't serialized 1-by-1.
                    self.execute_page_mkdirs(
                        cfg,
                        &pair_key,
                        page_mkdirs,
                        mkdir_conc,
                        bwlimit.as_ref(),
                        None,
                        &emitter,
                        &mut report,
                    )
                    .await;

                    if !page_transfers.is_empty() {
                        self.set_phase(&emitter, TransferPhase::Transferring);
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

                // `--delete-during`: execute destination deletions while transfer workers are actively running
                // (still strictly gated on complete Phase 1 observation + `--max-delete`!).
                if plan_opts.delete && cfg.delete_mode == DeleteMode::During && !deletes_executed {
                    deletes_executed = true;
                    if plan_opts.src_observation_complete
                        && plan_opts.dst_observation_complete
                        && report.errors.is_empty()
                    {
                        self.execute_indexed_delete_pass(
                            cfg,
                            &pair_key,
                            scan_started_ns,
                            &index,
                            &conflict_paths,
                            &protected_dst_dirs,
                            &plan_opts,
                            observed_dst_files,
                            bwlimit.as_ref(),
                            &emitter,
                            &mut report,
                        )
                        .await?;
                    } else {
                        warn!("skipping --delete-during deletions because observation had errors");
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
                if let Some(pool) = worker_pool.take() {
                    let (done_files, done_bytes) = pool.progress_counters();
                    pool.abort_and_join().await;
                    job.files_done =
                        base_files_done.saturating_add(done_files.load(Ordering::Relaxed));
                    job.bytes_done =
                        base_bytes_done.saturating_add(done_bytes.load(Ordering::Relaxed));
                }
                return Err(err);
            }

            if let Some(pool) = worker_pool.take() {
                pool.finish(&mut report).await;
            }
            if let Some(runner) = move_skips.take() {
                runner.finish(&mut report).await;
            }
            if let Some(hb) = heartbeat_handle.take() {
                hb.abort_and_await().await;
            }
            // Always sync `job` progress counters from `report` immediately after workers finish
            // so even an early `Paused` (Ctrl+C) `finish_job` never overwrites progress back to 0.
            job.files_done = base_files_done.saturating_add(report.files_transferred);
            job.bytes_done = base_bytes_done.saturating_add(report.bytes_transferred);
            self.set_phase(&emitter, TransferPhase::Finalizing);

            if !cfg.dry_run {
                self.fence.drain().await?;
            }

            // Optional empty source directory cleanup after `move` (strictly gated on zero errors),
            // executed deepest-depth-first with bounded sibling concurrency.
            self.cleanup_empty_src_dirs(cfg, observed_src_dirs, mkdir_conc, &report)
                .await;

            if self.cancel.is_cancelled() {
                report.cancelled = true;
                self.finish_job(&mut job, JobStatus::Paused, cfg.dry_run)
                    .await?;
                return Ok(report);
            }

            // Phase 3: `--delete-after` destination-only pass (STRICTLY gated on observation
            // completeness + zero transfer errors + `--max-delete` circuit breaker).
            if plan_opts.delete
                && !deletes_executed
                && plan_opts.src_observation_complete
                && plan_opts.dst_observation_complete
                && report.errors.is_empty()
            {
                self.execute_indexed_delete_pass(
                    cfg,
                    &pair_key,
                    scan_started_ns,
                    &index,
                    &conflict_paths,
                    &protected_dst_dirs,
                    &plan_opts,
                    observed_dst_files,
                    bwlimit.as_ref(),
                    &emitter,
                    &mut report,
                )
                .await?;
            } else if cfg.delete
                && !deletes_executed
                && matches!(cfg.mode, JobMode::Sync)
                && (!plan_opts.src_observation_complete || !report.errors.is_empty())
            {
                warn!("skipping destination deletions because source scan or transfers had errors");
            }

            let final_status = resolve_final_status(&report);
            if !matches!(final_status, JobStatus::Paused | JobStatus::Failed) {
                job.resume_cursor = None;
            }
            job.files_done = base_files_done.saturating_add(report.files_transferred);
            job.bytes_done = base_bytes_done.saturating_add(report.bytes_transferred);
            self.finish_job(&mut job, final_status, cfg.dry_run).await?;
            self.set_phase(&emitter, TransferPhase::Completed);

            Ok(report)
        }
        .await;

        match run_res {
            Ok(report) => {
                event_guard.finish(
                    report.files_transferred,
                    report.files_skipped,
                    report.bytes_transferred,
                    report.errors.len(),
                    report.conflicts.len(),
                    report.cancelled,
                );
                Ok(report)
            }
            Err(err) => {
                if job.status == JobStatus::Running {
                    let fail_status = if err.retry == crate::error::RetryClass::Cancelled
                        || self.cancel.is_cancelled()
                    {
                        JobStatus::Paused
                    } else {
                        JobStatus::Failed
                    };
                    let _ = self.finish_job(&mut job, fail_status, cfg.dry_run).await;
                }
                event_guard.finish_err(&err);
                Err(err)
            }
        }
    }

    /// Spawn a 2-second debounced progress heartbeat task flushing live counters (and
    /// optional streaming resume watermark) to `journal.db`. Runs < 2s pay 0 extra writes.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_job_heartbeat(
        &self,
        job: &JobRecord,
        pool: &TransferWorkerPool,
        planned_files_total: Arc<AtomicU64>,
        planned_bytes_total: Arc<AtomicU64>,
        base_files_done: u64,
        base_bytes_done: u64,
        watermark: Option<SafeWatermarkTracker>,
    ) -> AbortOnDrop {
        let (done_files, done_bytes) = pool.progress_counters();
        let journal = self.journal.clone();
        let clock = self.clock.clone();
        let cancel = self.cancel.clone();
        let mut hb_job = job.clone();
        AbortOnDrop::new(tokio::spawn(async move {
            // Instant-sleep virtual clocks (DST) advance time on every `sleep`, so a
            // wall-clock debounce loop would spin virtual time; skip background ticks
            // and let finalization persist exact counters deterministically.
            if clock.is_instant_sleep() {
                return;
            }
            let mut last = (
                base_files_done,
                base_files_done,
                base_bytes_done,
                base_bytes_done,
            );
            let mut last_cursor: Option<String> = hb_job.resume_cursor.clone();
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = clock.sleep(Duration::from_secs(2)) => {
                        let cur = (
                            planned_files_total.load(Ordering::Relaxed),
                            base_files_done.saturating_add(done_files.load(Ordering::Relaxed)),
                            planned_bytes_total.load(Ordering::Relaxed),
                            base_bytes_done.saturating_add(done_bytes.load(Ordering::Relaxed)),
                        );
                        let cur_cursor = watermark
                            .as_ref()
                            .and_then(SafeWatermarkTracker::current_watermark)
                            .or_else(|| hb_job.resume_cursor.clone());
                        if cur != last || cur_cursor != last_cursor {
                            last = cur;
                            last_cursor = cur_cursor.clone();
                            hb_job.files_total = cur.0;
                            hb_job.files_done = cur.1;
                            hb_job.bytes_total = cur.2;
                            hb_job.bytes_done = cur.3;
                            hb_job.resume_cursor = cur_cursor;
                            hb_job.updated_at = clock.now_unix_secs();
                            let _ = journal.upsert_job(&hb_job).await;
                        }
                    }
                }
            }
        }))
    }

    /// Create missing destination directories depth-by-depth concurrently (handling
    /// optional `--force-type-replace` file backup + deletion before `mkdir`).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_page_mkdirs(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        page_mkdirs: BTreeMap<usize, Vec<PageMkdirItem>>,
        mkdir_conc: usize,
        bwlimit: Option<&Arc<crate::bandwidth::BandwidthLimiter>>,
        watermark: Option<&SafeWatermarkTracker>,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) {
        if !page_mkdirs.is_empty() {
            self.set_phase(emitter, TransferPhase::CreatingDirs);
        }
        let mut replaced_file_baselines: Vec<RelPath> = Vec::new();
        for (_depth, dirs) in page_mkdirs {
            if self.cancel.is_cancelled() {
                break;
            }
            let dst = self.dst.clone();
            let journal = self.journal.clone();
            let pool = self.pool.clone();
            let clock = self.clock.clone();
            let cancel = self.cancel.clone();
            let mut results = futures::stream::iter(dirs)
                .map(move |(target, replace_file, wk)| {
                    let dst = dst.clone();
                    let journal = journal.clone();
                    let pool = pool.clone();
                    let clock = clock.clone();
                    let cancel = cancel.clone();
                    async move {
                        let mut replaced_nfc = None;
                        if let Some((nfc, full_del)) = replace_file {
                            if let Some(ref bk) = cfg.backup_dir
                                && !cfg.dry_run
                                && let Err(e) = archive_dst_file_to_backup(
                                    &dst,
                                    &cfg.dst_prefix,
                                    bk,
                                    &nfc,
                                    full_del.raw_path.as_deref(),
                                    None,
                                    &full_del,
                                    &journal,
                                    &pool,
                                    &clock,
                                    &cancel,
                                    bwlimit,
                                    cfg,
                                )
                                .await
                            {
                                return (target, None, wk, Err(e));
                            }
                            if let Err(e) = dst.delete(&full_del).await {
                                return (target, None, wk, Err(e));
                            }
                            replaced_nfc = Some(nfc);
                        }
                        let res = dst.mkdir(&target).await;
                        (target, replaced_nfc, wk, res)
                    }
                })
                .buffer_unordered(mkdir_conc);
            while let Some((target, replaced_nfc, wk, res)) = results.next().await {
                if let Some(nfc) = replaced_nfc {
                    report.items_deleted += 1;
                    if cfg.baseline_mode != BaselineMode::None {
                        replaced_file_baselines.push(nfc);
                    }
                }
                if let Err(e) = res {
                    if let (Some(wm), Some(wk)) = (watermark, wk.as_deref()) {
                        wm.mark_completed(wk, false);
                    }
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    let msg = format!("mkdir `{target}`: {e}");
                    let info = TransferErrorInfo::from_error_with_message(
                        Some(target.as_str().to_string()),
                        &e,
                        msg,
                    );
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                } else {
                    if let (Some(wm), Some(wk)) = (watermark, wk.as_deref()) {
                        wm.mark_completed(wk, true);
                    }
                    report.dirs_created += 1;
                    if let Some(p) = &self.progress {
                        p.inc_dirs_created();
                    }
                }
            }
        }
        if !replaced_file_baselines.is_empty() {
            let _ = self
                .journal
                .delete_baselines_batch(pair_key, &replaced_file_baselines)
                .await;
        }
    }

    pub(super) async fn cleanup_empty_src_dirs(
        &self,
        cfg: &EngineConfig,
        observed_src_dirs: BTreeMap<usize, Vec<BackendPath>>,
        mkdir_conc: usize,
        report: &RunReport,
    ) {
        if !(cfg.delete_source_after_transfer
            && cfg.delete_empty_src_dirs
            && !cfg.dry_run
            && !self.cancel.is_cancelled()
            && report.errors.is_empty()
            && report.conflicts.is_empty())
        {
            return;
        }
        for (_depth, dirs) in observed_src_dirs.into_iter().rev() {
            if self.cancel.is_cancelled() {
                break;
            }
            let src = self.src.clone();
            let mut stream = futures::stream::iter(dirs)
                .map(move |bp| {
                    let src = src.clone();
                    async move {
                        if let Ok(mut ls) = src.list_stream(&bp.nfc_path, false).await
                            && ls.next().await.is_none()
                        {
                            let _ = src.delete(&bp).await;
                        }
                    }
                })
                .buffer_unordered(mkdir_conc);
            while stream.next().await.is_some() {}
        }
    }
}

/// RAII guard that aborts a spawned background task whenever dropped (e.g. on early `?` return).
pub(super) struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }

    pub(super) async fn abort_and_await(mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
            let _ = h.await;
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}
