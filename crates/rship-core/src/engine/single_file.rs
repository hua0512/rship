//! Direct single-file (`run_single_file`) and explicit file-list (`run_file_list`)
//! fast paths without directory tree crawling or `SqliteSyncIndex` overhead.

use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;

use crate::adaptive::{FalconConfig, FalconController, TransferLane};
use crate::backend::BackendPath;
use crate::error::{Error, Result, RetryClass};
use crate::path::RelPath;
use crate::planner::{PlanOptions, PlannedAction, plan_source_item};
use crate::progress::{JobEventGuard, TransferPhase};
use crate::state::{JobRecord, JobStatus, SourceVersion, compute_pair_key};
use crate::types::EntryKind;

use super::move_skips::{MoveSkipRunner, submit_move_skips};
use super::pool::TransferWorkerPool;
use super::task::{TransferOutcome, TransferTask, execute_transfer_task};
use super::{
    DIFF_PAGE_SIZE, EngineConfig, FileTransferResult, PlannedMoveSkip, RunReport, TransferEngine,
    TransferErrorInfo, check_overlapping_roots, join_prefix, needs_baseline_lookup,
    push_file_result, strip_raw_prefix,
};

impl TransferEngine {
    /// Execute a single-file `copy` / `move` / `copyto` / `moveto` transfer directly
    /// from `src_path` on `self.src` to `dst_rel` on `self.dst` with full write-ahead
    /// journaling, resumable chunks, server-side copy fast path, `--strict-source`,
    /// `--bwlimit`, `--checksum`, and `move` source-deletion guarantees.
    pub async fn run_single_file(
        &self,
        cfg: &EngineConfig,
        src_path: &BackendPath,
        dst_rel: &RelPath,
    ) -> Result<RunReport> {
        if dst_rel.is_root() {
            return Err(Error::invalid_path(
                "single-file destination path cannot be root",
            ));
        }
        let src_endpoint = self.src.endpoint_identity();
        let dst_endpoint = self.dst.endpoint_identity();
        if src_endpoint == dst_endpoint && src_path.nfc_path == *dst_rel {
            return Err(Error::invalid_path(format!(
                "source and destination refer to the same file `{dst_rel}`"
            )));
        }
        if let Some(ref bk) = cfg.backup_dir {
            super::validate_backup_dir_overlap(
                &src_endpoint,
                &src_path.nfc_path,
                &dst_endpoint,
                dst_rel,
                bk,
            )?;
        }

        let (event_guard, emitter) =
            JobEventGuard::start(&cfg.job_id, cfg.mode, self.events.clone());

        let mut started_job: Option<JobRecord> = None;
        let run_res: Result<RunReport> = async {
            self.set_phase(&emitter, TransferPhase::Observing);
            let Some(mut src_entry) = self.src.stat(src_path).await? else {
                return Err(Error::not_found(format!(
                    "source file `{}` not found",
                    src_path.nfc_path
                )));
            };
            if src_entry.kind != EntryKind::File {
                return Err(Error::invalid_path(format!(
                    "source `{}` is a directory, not a file",
                    src_path.nfc_path
                )));
            }
            if src_entry.raw_path().is_empty() {
                src_entry.set_raw_path(src_path.raw_path());
            }
            if src_entry.node_id.is_none() {
                src_entry.node_id = src_path.node_id.clone();
            }

            let dst_bp = BackendPath::from_rel(dst_rel.clone());
            let dst_existing = self.dst.stat(&dst_bp).await?;
            if let Some(ref de) = dst_existing
                && de.kind == EntryKind::Directory
            {
                return Err(Error::invalid_path(format!(
                    "destination `{dst_rel}` is an existing directory"
                )));
            }

            let now_s = self.clock.now_unix_secs();
            let scan_started_ns = self.clock.now_unix_nanos();
            let pair_key = compute_pair_key(&src_endpoint, &dst_endpoint);

            let job_rec = JobRecord {
                job_id: cfg.job_id.clone(),
                mode: cfg.mode,
                src_spec: cfg.src_spec.clone(),
                dst_spec: cfg.dst_spec.clone(),
                status: JobStatus::Running,
                files_total: 0,
                files_done: 0,
                bytes_total: 0,
                bytes_done: 0,
                created_at: now_s,
                updated_at: now_s,
                options_json: cfg.options_json.clone(),
                resume_cursor: None,
            };
            if !cfg.dry_run {
                self.journal.upsert_job(&job_rec).await?;
            }
            let job = started_job.insert(job_rec);

            let mut report = RunReport {
                job_id: cfg.job_id.clone(),
                src_observation_complete: true,
                dst_observation_complete: true,
                ..Default::default()
            };

            let src_caps = self.src.capabilities();
            let dst_caps = self.dst.capabilities();
            let plan_opts = PlanOptions {
                delete: false,
                max_delete: None,
                checksum_mode: cfg.checksum,
                force_type_replace: cfg.force_type_replace,
                scan_started_unix_ns: scan_started_ns,
                src_observation_complete: true,
                dst_observation_complete: true,
            };
            let mtime_tolerance_ns =
                i64::try_from(src_caps.effective_mtime_tolerance(&dst_caps).as_nanos())
                    .unwrap_or(i64::MAX);
            let baseline = match dst_existing.as_ref() {
                Some(d)
                    if needs_baseline_lookup(
                        cfg,
                        &src_entry,
                        d,
                        &dst_caps,
                        mtime_tolerance_ns,
                        scan_started_ns,
                    ) =>
                {
                    self.journal.get_baseline(&pair_key, dst_rel).await?
                }
                _ => None,
            };

            // Use an internal config with root prefixes because `src_entry` and `dst_rel`
            // already carry full backend-relative paths.
            let mut eff_cfg = cfg.clone();
            eff_cfg.src_prefix = RelPath::root();
            eff_cfg.dst_prefix = RelPath::root();
            eff_cfg.pin_run_retry_quota(self.dst.as_ref());

            let mut active_ops = self.load_active_ops_for_pair(cfg).await?;
            let action = plan_source_item(
                &src_entry,
                dst_existing.as_ref(),
                baseline.as_ref(),
                &src_caps,
                &dst_caps,
                &plan_opts,
            );
            let action = self.force_transfer_if_integrity_marked(
                &eff_cfg,
                &active_ops,
                &src_entry,
                dst_existing.as_ref(),
                dst_rel,
                action,
            )?;
            let action = self
                .distrust_unflushed_skip(
                    &eff_cfg,
                    &src_caps,
                    &dst_caps,
                    &mut active_ops,
                    &src_entry,
                    dst_rel,
                    dst_existing.as_ref(),
                    action,
                )
                .await?;
            match action {
                PlannedAction::Skip => {
                    self.retire_skipped_operation(
                        cfg,
                        &pair_key,
                        &src_caps,
                        &dst_caps,
                        &mut active_ops,
                        &src_entry,
                        src_path.raw_path(),
                        dst_rel,
                        dst_rel,
                        dst_existing.as_ref(),
                    )
                    .await?;
                    self.handle_planned_file_skip(
                        cfg,
                        &src_entry,
                        src_path,
                        dst_rel.as_str(),
                        &emitter,
                        &mut report,
                    )
                    .await;
                }
                PlannedAction::Transfer(pt) => {
                    let size = pt.src.size;
                    job.files_total = 1;
                    job.bytes_total = size;
                    if let Some(p) = &self.progress {
                        p.add_planned_file(size);
                    }
                    self.set_phase(&emitter, TransferPhase::Transferring);
                    emitter.emit_file_started(dst_rel.as_str(), size);
                    if cfg.dry_run {
                        report.files_transferred = 1;
                        report.bytes_transferred = size;
                        if cfg.delete_source_after_transfer {
                            report.sources_deleted = 1;
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
                                dst_rel.as_str(),
                                size,
                                cfg.delete_source_after_transfer,
                            ),
                        );
                    } else {
                        let bwlimit = cfg.build_bwlimit(&self.clock)?;
                        let falcon = if eff_cfg.adaptive_concurrency {
                            let fcfg = eff_cfg.falcon_config.clone().unwrap_or_else(|| {
                                FalconConfig::from_max_transfers(eff_cfg.transfers)
                            });
                            let ctrl =
                                Arc::new(FalconController::with_clock(fcfg, self.clock.clone()));
                            let lane = ctrl.classify(size);
                            if let Some(p) = &self.progress {
                                p.set_falcon_concurrency(
                                    ctrl.concurrency(TransferLane::SmallPipelined),
                                    ctrl.concurrency(TransferLane::LargeStreaming),
                                );
                            }
                            Some((ctrl, lane))
                        } else {
                            None
                        };
                        let _lane_permit = match falcon.as_ref() {
                            Some((ctrl, lane)) => Some(ctrl.acquire_permit(*lane).await),
                            None => None,
                        };
                        let slot_guard = self
                            .progress
                            .as_ref()
                            .map(|p| p.start_transfer(dst_rel.as_str(), size, ""));
                        let task = TransferTask {
                            src: pt.src,
                            dst_rel: dst_rel.clone(),
                            existing_dst_node_id: pt.existing_dst_node_id,
                            precondition: pt.precondition,
                            needs_checksum_verify: pt.needs_checksum_verify,
                            dst_existing,
                            wire_key: None,
                            replace_dst_dir: pt.replace_dst_dir,
                            defer_op_commit: false,
                        };
                        let res = execute_transfer_task(
                            &self.src,
                            &self.dst,
                            &self.journal,
                            &self.pool,
                            &self.clock,
                            &self.cancel,
                            bwlimit.as_ref(),
                            self.progress.as_ref(),
                            slot_guard.as_ref(),
                            falcon.as_ref().map(|(c, l)| (c, *l)),
                            &eff_cfg,
                            &pair_key,
                            &src_caps,
                            &dst_caps,
                            task,
                        )
                        .await;
                        drop(slot_guard);
                        if let Some((ref fctrl, lane)) = falcon {
                            match &res {
                                Ok(
                                    TransferOutcome::Transferred { .. }
                                    | TransferOutcome::ServerSideCopied { .. },
                                ) => {
                                    fctrl.record_transfer(lane, 0, 0, 0);
                                }
                                Err(e)
                                    if matches!(
                                        e.retry,
                                        RetryClass::Throttled | RetryClass::Retryable
                                    ) =>
                                {
                                    let is_throttle = u32::from(e.retry == RetryClass::Throttled);
                                    let is_transient = u32::from(e.retry == RetryClass::Retryable);
                                    fctrl.record_transfer(lane, 0, is_throttle, is_transient);
                                }
                                _ => {}
                            }
                            report.final_small_concurrency =
                                Some(fctrl.concurrency(TransferLane::SmallPipelined));
                            report.final_large_concurrency =
                                Some(fctrl.concurrency(TransferLane::LargeStreaming));
                            if let Some(p) = &self.progress {
                                p.set_falcon_concurrency(
                                    fctrl.concurrency(TransferLane::SmallPipelined),
                                    fctrl.concurrency(TransferLane::LargeStreaming),
                                );
                            }
                        }
                        match res {
                            Ok(TransferOutcome::Transferred {
                                bytes,
                                source_deleted,
                                ..
                            }) => {
                                report.files_transferred = 1;
                                report.bytes_transferred = bytes;
                                if source_deleted {
                                    report.sources_deleted = 1;
                                }
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    if source_deleted {
                                        p.inc_sources_deleted();
                                    }
                                }
                                push_file_result(
                                    &mut report.file_results,
                                    &mut report.file_results_truncated,
                                    Some(&emitter),
                                    FileTransferResult::transferred(
                                        dst_rel.as_str(),
                                        bytes,
                                        source_deleted,
                                    ),
                                );
                            }
                            Ok(TransferOutcome::ServerSideCopied {
                                bytes,
                                source_deleted,
                                ..
                            }) => {
                                report.files_transferred = 1;
                                report.server_side_copies = 1;
                                report.bytes_transferred = bytes;
                                if source_deleted {
                                    report.sources_deleted = 1;
                                }
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.inc_server_side_copies();
                                    if source_deleted {
                                        p.inc_sources_deleted();
                                    }
                                }
                                push_file_result(
                                    &mut report.file_results,
                                    &mut report.file_results_truncated,
                                    Some(&emitter),
                                    FileTransferResult::server_side_copied(
                                        dst_rel.as_str(),
                                        bytes,
                                        source_deleted,
                                    ),
                                );
                            }
                            Ok(TransferOutcome::Skipped { source_deleted }) => {
                                report.files_skipped = 1;
                                if source_deleted {
                                    report.sources_deleted = 1;
                                }
                                if let Some(p) = &self.progress {
                                    p.record_worker_skip(size);
                                    if source_deleted {
                                        p.inc_sources_deleted();
                                    }
                                }
                                push_file_result(
                                    &mut report.file_results,
                                    &mut report.file_results_truncated,
                                    Some(&emitter),
                                    FileTransferResult::skipped(dst_rel.as_str(), source_deleted),
                                );
                            }
                            Err(e) if e.retry == RetryClass::Cancelled => {
                                report.cancelled = true;
                            }
                            Err(e) => {
                                if let Some(p) = &self.progress {
                                    p.inc_errors();
                                }
                                let info = TransferErrorInfo::from_error(
                                    Some(dst_rel.as_str().to_string()),
                                    &e,
                                );
                                report.push_error(info);
                                push_file_result(
                                    &mut report.file_results,
                                    &mut report.file_results_truncated,
                                    Some(&emitter),
                                    FileTransferResult::failed(dst_rel.as_str(), &e),
                                );
                            }
                        }
                    }
                }
                PlannedAction::Conflict(c) => {
                    emitter.emit_conflict(c.clone());
                    report.push_conflict(c);
                }
                PlannedAction::Mkdir { .. }
                | PlannedAction::ReplaceWithDir { .. }
                | PlannedAction::Delete { .. } => {}
            }

            self.set_phase(&emitter, TransferPhase::Finalizing);
            if !cfg.dry_run {
                self.fence.drain().await?;
            }
            let final_status = if report.cancelled || self.cancel.is_cancelled() {
                report.cancelled = true;
                JobStatus::Paused
            } else if !report.errors.is_empty() {
                JobStatus::Failed
            } else if !report.conflicts.is_empty() {
                JobStatus::CompletedWithConflicts
            } else {
                JobStatus::Completed
            };
            job.files_done = report.files_transferred;
            job.bytes_done = report.bytes_transferred;
            self.finish_job(job, final_status, cfg.dry_run).await?;
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
                if let Some(mut job) = started_job
                    && job.status == JobStatus::Running
                {
                    let fail_status =
                        if err.retry == RetryClass::Cancelled || self.cancel.is_cancelled() {
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

    /// Ergonomic direct-stat batch transfer (`copy` / `move`) over an explicit list of
    /// relative file paths — requires NO `SqliteSyncIndex` and performs ZERO directory
    /// tree listing on either `src` or `dst` (ideal for Rust crate embedders like `rust-srec`
    /// uploading explicit `[.jpg, .mp4]` batches from directories containing live `.flv` files).
    pub async fn run_file_list(&self, cfg: &EngineConfig, files: &[RelPath]) -> Result<RunReport> {
        let mut run_cfg = cfg.clone();
        run_cfg.pin_run_retry_quota(self.dst.as_ref());
        let cfg = &run_cfg;
        check_overlapping_roots(
            &self.src.endpoint_identity(),
            &cfg.src_prefix,
            &self.dst.endpoint_identity(),
            &cfg.dst_prefix,
            &cfg.filter,
        )?;
        if let Some(ref bk) = cfg.backup_dir {
            super::validate_backup_dir_overlap(
                &self.src.endpoint_identity(),
                &cfg.src_prefix,
                &self.dst.endpoint_identity(),
                &cfg.dst_prefix,
                bk,
            )?;
        }

        let now_s = self.clock.now_unix_secs();
        let scan_started_ns = self.clock.now_unix_nanos();
        let pair_key = super::make_prefixed_pair_key(
            &self.src.endpoint_identity(),
            &cfg.src_prefix,
            &self.dst.endpoint_identity(),
            &cfg.dst_prefix,
        );

        let mut job = JobRecord {
            job_id: cfg.job_id.clone(),
            mode: cfg.mode,
            src_spec: cfg.src_spec.clone(),
            dst_spec: cfg.dst_spec.clone(),
            status: JobStatus::Running,
            files_total: 0,
            files_done: 0,
            bytes_total: 0,
            bytes_done: 0,
            created_at: now_s,
            updated_at: now_s,
            options_json: cfg.options_json.clone(),
            resume_cursor: None,
        };
        if !cfg.dry_run {
            self.journal.upsert_job(&job).await?;
        }

        let mut report = RunReport {
            job_id: cfg.job_id.clone(),
            src_observation_complete: true,
            dst_observation_complete: true,
            ..Default::default()
        };

        let (event_guard, emitter) =
            JobEventGuard::start(&cfg.job_id, cfg.mode, self.events.clone());

        let run_res: Result<RunReport> = async {
            self.set_phase(&emitter, TransferPhase::Observing);

            let src_caps = self.src.capabilities();
            let dst_caps = self.dst.capabilities();
            let plan_opts = PlanOptions {
                delete: false,
                max_delete: None,
                checksum_mode: cfg.checksum,
                force_type_replace: cfg.force_type_replace,
                scan_started_unix_ns: scan_started_ns,
                src_observation_complete: true,
                dst_observation_complete: true,
            };

            let max_stat = if self.src.kind() == "local" && self.dst.kind() == "local" {
                16
            } else {
                64
            };
            let conc = cfg.transfers.clamp(1, max_stat);
            let mut worker_pool: Option<TransferWorkerPool> = None;
            let mut producer_closed = false;
            let mut active_ops = self.load_active_ops_for_pair(cfg).await?;
            let mut move_skips = MoveSkipRunner::spawn_for(self, cfg, None, &emitter);

            let list_res: Result<()> = async {
                let mut root_checked = false;
                for file_chunk in files.chunks(DIFF_PAGE_SIZE) {
                    if self.cancel.is_cancelled() || producer_closed {
                        report.cancelled = self.cancel.is_cancelled();
                        break;
                    }
                    let src_b = self.src.clone();
                    let dst_b = self.dst.clone();
                    let src_pre = cfg.src_prefix.clone();
                    let dst_pre = cfg.dst_prefix.clone();
                    let cancel_obs = self.cancel.clone();

                    let chunk_items: Vec<_> = futures::stream::iter(file_chunk.iter().cloned())
                        .map(move |rel| {
                            let src = src_b.clone();
                            let dst = dst_b.clone();
                            let sp = src_pre.clone();
                            let dp = dst_pre.clone();
                            let c = cancel_obs.clone();
                            async move {
                                if c.is_cancelled() || rel.is_root() {
                                    return (rel, None, None, None);
                                }
                                let src_full = match join_prefix(&sp, &rel) {
                                    Ok(p) => p,
                                    Err(e) => return (rel, None, None, Some(e)),
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
                                    Ok(None) => return (rel, None, None, None),
                                    Err(e) => return (rel, None, None, Some(e)),
                                };
                                if src_entry.kind != EntryKind::File {
                                    return (rel, None, None, None);
                                }
                                let dst_full = match join_prefix(&dp, &rel) {
                                    Ok(p) => p,
                                    Err(e) => return (rel, Some(src_entry), None, Some(e)),
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
                                        (rel, Some(src_entry), Some(de), None)
                                    }
                                    Ok(None) => (rel, Some(src_entry), None, None),
                                    Err(e) => (rel, Some(src_entry), None, Some(e)),
                                }
                            }
                        })
                        .buffer_unordered(conc)
                        .collect()
                        .await;

                    // D3: a missing source root makes every listed `stat` say "not found".
                    if !root_checked
                        && chunk_items
                            .iter()
                            .any(|(_, src_opt, _, err_opt)| src_opt.is_none() && err_opt.is_none())
                    {
                        root_checked = true;
                        if let Some(e) = self.missing_source_root(&cfg.src_prefix).await {
                            report.src_observation_complete = false;
                            if let Some(p) = &self.progress {
                                p.inc_errors();
                            }
                            let info = TransferErrorInfo::from_error(None, &e);
                            emitter.emit_error(info.clone());
                            report.push_error(info);
                            break;
                        }
                    }

                    let mtime_tolerance_ns =
                        i64::try_from(src_caps.effective_mtime_tolerance(&dst_caps).as_nanos())
                            .unwrap_or(i64::MAX);
                    let baseline_paths: Vec<RelPath> = chunk_items
                        .iter()
                        .filter_map(|(_, src_opt, dst_opt, err_opt)| {
                            if err_opt.is_some() {
                                return None;
                            }
                            let se = src_opt.as_ref()?;
                            let de = dst_opt.as_ref()?;
                            (cfg.filter.matches_entry(se, scan_started_ns)
                                && needs_baseline_lookup(
                                    cfg,
                                    se,
                                    de,
                                    &dst_caps,
                                    mtime_tolerance_ns,
                                    scan_started_ns,
                                ))
                            .then(|| se.nfc_path.clone())
                        })
                        .collect();
                    let mut baselines = if baseline_paths.is_empty() {
                        HashMap::new()
                    } else {
                        self.journal
                            .get_baselines_batch(&pair_key, &baseline_paths)
                            .await?
                    };

                    let mut page_move_skips: Vec<PlannedMoveSkip> = Vec::new();
                    for (rel, src_opt, dst_opt, err_opt) in chunk_items {
                        if self.cancel.is_cancelled() {
                            report.cancelled = true;
                            break;
                        }
                        if let Some(e) = err_opt {
                            report.src_observation_complete = false;
                            if let Some(p) = &self.progress {
                                p.add_planned_error();
                            }
                            let info =
                                TransferErrorInfo::from_error(Some(rel.as_str().to_string()), &e);
                            report.push_error(info);
                            push_file_result(
                                &mut report.file_results,
                                &mut report.file_results_truncated,
                                Some(&emitter),
                                FileTransferResult::failed(rel.as_str(), &e),
                            );
                            continue;
                        }
                        let Some(src_entry) = src_opt else {
                            continue;
                        };
                        if !cfg.filter.matches_entry(&src_entry, scan_started_ns) {
                            continue;
                        }
                        let baseline = baselines.remove(&src_entry.nfc_path);
                        let action = plan_source_item(
                            &src_entry,
                            dst_opt.as_ref(),
                            baseline.as_ref(),
                            &src_caps,
                            &dst_caps,
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
                                &src_caps,
                                &dst_caps,
                                &mut active_ops,
                                &src_entry,
                                &src_entry.nfc_path,
                                dst_opt.as_ref(),
                                action,
                            )
                            .await?;
                        match action {
                            PlannedAction::Skip => {
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
                                        &emitter,
                                        &mut report,
                                    )
                                    .await;
                                }
                            }
                            PlannedAction::Transfer(pt) => {
                                let size = pt.src.size;
                                job.files_total += 1;
                                job.bytes_total = job.bytes_total.saturating_add(size);
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
                                            pt.dst_path.as_str(),
                                            size,
                                            cfg.delete_source_after_transfer,
                                        ),
                                    );
                                } else {
                                    if worker_pool.is_none() {
                                        self.set_phase(&emitter, TransferPhase::Transferring);
                                        worker_pool = Some(TransferWorkerPool::spawn(
                                            self,
                                            cfg,
                                            &pair_key,
                                            &src_caps,
                                            &dst_caps,
                                            &emitter,
                                            cfg.build_bwlimit(&self.clock)?,
                                            Some(files.len()),
                                            None,
                                        )?);
                                    }
                                    let task = TransferTask {
                                        src: pt.src,
                                        dst_rel: pt.dst_path,
                                        existing_dst_node_id: pt.existing_dst_node_id,
                                        precondition: pt.precondition,
                                        needs_checksum_verify: pt.needs_checksum_verify,
                                        dst_existing: dst_opt,
                                        wire_key: None,
                                        replace_dst_dir: pt.replace_dst_dir,
                                        defer_op_commit: false,
                                    };
                                    if let Some(ref pool) = worker_pool
                                        && !pool.send(task).await
                                    {
                                        producer_closed = true;
                                        break;
                                    }
                                }
                            }
                            PlannedAction::Conflict(c) => {
                                emitter.emit_conflict(c.clone());
                                report.push_conflict(c);
                            }
                            PlannedAction::Mkdir { .. }
                            | PlannedAction::ReplaceWithDir { .. }
                            | PlannedAction::Delete { .. } => {}
                        }
                    }
                    submit_move_skips(move_skips.as_ref(), page_move_skips).await;
                }
                Ok(())
            }
            .await;

            if let Err(err) = list_res {
                if let Some(runner) = move_skips.take() {
                    runner.abort().await;
                }
                if let Some(pool) = worker_pool.take() {
                    let (done_files, done_bytes) = pool.progress_counters();
                    pool.abort_and_join().await;
                    job.files_done = done_files.load(std::sync::atomic::Ordering::Relaxed);
                    job.bytes_done = done_bytes.load(std::sync::atomic::Ordering::Relaxed);
                }
                return Err(err);
            }

            if let Some(pool) = worker_pool.take() {
                pool.finish(&mut report).await;
            }
            if let Some(runner) = move_skips.take() {
                runner.finish(&mut report).await;
            }

            self.set_phase(&emitter, TransferPhase::Finalizing);
            if !cfg.dry_run {
                self.fence.drain().await?;
            }
            let final_status = if report.cancelled || self.cancel.is_cancelled() {
                report.cancelled = true;
                JobStatus::Paused
            } else if !report.errors.is_empty() {
                JobStatus::Failed
            } else if !report.conflicts.is_empty() {
                JobStatus::CompletedWithConflicts
            } else {
                JobStatus::Completed
            };
            job.files_done = report.files_transferred;
            job.bytes_done = report.bytes_transferred;
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
                    let fail_status =
                        if err.retry == RetryClass::Cancelled || self.cancel.is_cancelled() {
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
}
