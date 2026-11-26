//! Destination-only deletion passes (`--delete-before`, `--delete-during`, `--delete-after`),
//! `--backup-dir` archival before delete, `--max-delete` circuit breaker, and `DeleteSpillLog` replay.

use futures::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::warn;

use crate::backend::BackendPath;
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::planner::{PlanOptions, PlannedAction, plan_dst_only_item};
use crate::progress::JobEventEmitter;
use crate::state::{BaselineMode, SyncDiffIndex};
use crate::types::EntryKind;

use super::super::diff::{DeleteSpillLog, DeleteTarget};
use super::super::task::archive_dst_file_to_backup;
use super::super::{
    DIFF_PAGE_SIZE, EngineConfig, ProtectedDirs, RunReport, TransferEngine, TransferErrorInfo,
};
use super::DELETE_FILE_CHUNK;

impl TransferEngine {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_indexed_delete_pass(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        scan_started_ns: i64,
        index: &Arc<dyn SyncDiffIndex>,
        conflict_paths: &HashSet<RelPath>,
        protected_dst_dirs: &ProtectedDirs,
        plan_opts: &PlanOptions,
        observed_dst_files: u64,
        bwlimit: Option<&Arc<crate::bandwidth::BandwidthLimiter>>,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) -> Result<()> {
        let mut inline_files: Vec<(RelPath, BackendPath)> = Vec::new();
        let mut delete_files_log = DeleteSpillLog::new(cfg.scratch_dir.clone());
        let mut delete_dirs_logs: BTreeMap<usize, DeleteSpillLog> = BTreeMap::new();
        let mut planned_deletes: u64 = 0;
        let mut planned_file_deletes: u64 = 0;
        let mut inline_deleted_files: u64 = 0;
        let has_delete_limit = cfg.max_delete.is_some() || cfg.max_delete_percent.is_some();
        let mut dst_after_id = 0i64;

        loop {
            if self.cancel.is_cancelled() {
                report.cancelled = true;
                break;
            }
            let page = index
                .next_dst_only_page(dst_after_id, DIFF_PAGE_SIZE)
                .await?;
            if page.is_empty() {
                break;
            }
            for row in page {
                dst_after_id = row.row_id;
                let Some(dst_entry) = row.dst else { continue };
                if conflict_paths.contains(&dst_entry.nfc_path) {
                    continue;
                }
                if !cfg.filter.matches_entry(&dst_entry, scan_started_ns) {
                    continue;
                }
                if dst_entry.kind == EntryKind::Directory
                    && protected_dst_dirs.is_protected(&dst_entry.nfc_path)
                {
                    continue;
                }
                if let PlannedAction::Delete { dst, kind } =
                    plan_dst_only_item(&dst_entry, plan_opts)
                {
                    planned_deletes += 1;
                    if kind != EntryKind::Directory {
                        planned_file_deletes += 1;
                    }
                    if let Some(limit) = cfg.max_delete
                        && planned_deletes > limit
                    {
                        continue;
                    }
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
                            if !has_delete_limit && cfg.dry_run {
                                report.items_deleted += 1;
                                inline_deleted_files += 1;
                            } else if !has_delete_limit {
                                inline_files.push((dst_entry.nfc_path, dst));
                                if inline_files.len() >= DELETE_FILE_CHUNK {
                                    let chunk = std::mem::replace(
                                        &mut inline_files,
                                        Vec::with_capacity(DELETE_FILE_CHUNK),
                                    );
                                    inline_deleted_files += self
                                        .delete_dst_file_chunk(
                                            cfg, pair_key, &chunk, bwlimit, emitter, report,
                                        )
                                        .await?;
                                }
                            } else {
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
        }

        if !inline_files.is_empty() && !report.cancelled {
            inline_deleted_files += self
                .delete_dst_file_chunk(cfg, pair_key, &inline_files, bwlimit, emitter, report)
                .await?;
        }
        self.execute_delete_spill_logs(
            cfg,
            pair_key,
            delete_files_log,
            delete_dirs_logs,
            protected_dst_dirs,
            planned_deletes,
            planned_file_deletes,
            observed_dst_files,
            inline_deleted_files,
            bwlimit,
            emitter,
            report,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn delete_dst_file_chunk(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        chunk: &[(RelPath, BackendPath)],
        bwlimit: Option<&Arc<crate::bandwidth::BandwidthLimiter>>,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) -> Result<u64> {
        let mut full_targets = Vec::with_capacity(chunk.len());
        let mut nfc_by_full = HashMap::with_capacity(chunk.len());
        for (nfc, target) in chunk {
            let full_bp = BackendPath::join_prefixed(
                &cfg.dst_prefix,
                target.raw_path(),
                &target.nfc_path,
                target.node_id.clone(),
                target.kind.or(Some(EntryKind::File)),
            )?;
            if let Some(ref bk) = cfg.backup_dir
                && !cfg.dry_run
                && let Err(err) = archive_dst_file_to_backup(
                    &self.dst,
                    &cfg.dst_prefix,
                    bk,
                    nfc,
                    target.raw_path.as_deref(),
                    None,
                    &full_bp,
                    &self.journal,
                    &self.pool,
                    &self.clock,
                    &self.cancel,
                    bwlimit,
                    cfg,
                )
                .await
            {
                if let Some(p) = &self.progress {
                    p.inc_errors();
                }
                let msg = format!("backup before delete `{nfc}`: {err}");
                let info = TransferErrorInfo::from_error_with_message(
                    Some(nfc.as_str().to_string()),
                    &err,
                    msg,
                );
                emitter.emit_error(info.clone());
                report.push_error(info);
                continue;
            }
            nfc_by_full.insert(full_bp.nfc_path.as_str().to_string(), nfc.clone());
            full_targets.push(full_bp);
        }
        if full_targets.is_empty() {
            return Ok(0);
        }
        let mut deleted_in_chunk = 0u64;
        match self.dst.delete_batch(&full_targets).await {
            Ok(failures) => {
                let mut failed_keys = HashSet::with_capacity(failures.len());
                for (fbp, err) in failures {
                    let key = fbp.nfc_path.as_str().to_string();
                    let label = nfc_by_full
                        .get(&key)
                        .map(|r| r.as_str())
                        .unwrap_or(fbp.nfc_path.as_str());
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    let msg = format!("delete `{label}`: {err}");
                    let info = TransferErrorInfo::from_error_with_message(
                        Some(label.to_string()),
                        &err,
                        msg.clone(),
                    );
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                    failed_keys.insert(key);
                }
                let mut deleted_nfcs = Vec::new();
                for bp in &full_targets {
                    let key = bp.nfc_path.as_str();
                    if !failed_keys.contains(key) {
                        if cfg.baseline_mode != BaselineMode::None
                            && let Some(nfc) = nfc_by_full.get(key)
                        {
                            deleted_nfcs.push(nfc.clone());
                        }
                        report.items_deleted += 1;
                        deleted_in_chunk += 1;
                        if let Some(p) = &self.progress {
                            p.inc_items_deleted();
                        }
                    }
                }
                if !deleted_nfcs.is_empty() {
                    let _ = self
                        .journal
                        .delete_baselines_batch(pair_key, &deleted_nfcs)
                        .await;
                }
            }
            Err(e) => {
                if let Some(p) = &self.progress {
                    p.inc_errors();
                }
                let msg = format!("batch delete failed: {e}");
                let info = TransferErrorInfo::from_error_with_message(None, &e, msg.clone());
                emitter.emit_error(info.clone());
                report.push_error(info);
            }
        }
        Ok(deleted_in_chunk)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_delete_spill_logs(
        &self,
        cfg: &EngineConfig,
        pair_key: &str,
        delete_files_log: DeleteSpillLog,
        delete_dirs_logs: BTreeMap<usize, DeleteSpillLog>,
        protected_dst_dirs: &ProtectedDirs,
        planned_deletes: u64,
        planned_file_deletes: u64,
        observed_dst_files: u64,
        already_deleted_files: u64,
        bwlimit: Option<&Arc<crate::bandwidth::BandwidthLimiter>>,
        emitter: &JobEventEmitter,
        report: &mut RunReport,
    ) -> Result<()> {
        if let Some(limit) = cfg.max_delete {
            if planned_deletes > limit {
                let msg = format!(
                    "delete circuit breaker tripped: planned {planned_deletes} deletions exceeds --max-delete={limit}"
                );
                let err = Error::precondition_failed(msg.clone());
                let info = TransferErrorInfo::from_error_with_message(None, &err, msg.clone());
                if let Some(p) = &self.progress {
                    p.inc_errors();
                }
                emitter.emit_error(info.clone());
                report.push_error(info);
                return Ok(());
            }
        } else if let Some(pct) = cfg.max_delete_percent
            && observed_dst_files > 0
        {
            let limit = ((observed_dst_files as f64) * pct / 100.0).floor() as u64;
            if planned_file_deletes > limit {
                let msg = format!(
                    "delete circuit breaker tripped: planned {planned_file_deletes} file deletions exceeds --max-delete={pct}% ({limit} of {observed_dst_files} observed destination files)"
                );
                let err = Error::precondition_failed(msg.clone());
                let info = TransferErrorInfo::from_error_with_message(None, &err, msg);
                if let Some(p) = &self.progress {
                    p.inc_errors();
                }
                emitter.emit_error(info.clone());
                report.push_error(info);
                return Ok(());
            }
        }
        if report.cancelled {
            return Ok(());
        }

        let mut deleted_files = already_deleted_files;
        if !delete_files_log.is_empty() {
            if cfg.dry_run {
                let n = delete_files_log.len();
                report.items_deleted += n;
                deleted_files += n;
            } else {
                let mut reader = delete_files_log.into_reader_async().await?;
                let mut raw_chunk = Vec::with_capacity(DELETE_FILE_CHUNK);
                let mut pair_chunk = Vec::with_capacity(DELETE_FILE_CHUNK);
                while reader
                    .next_chunk_async(DELETE_FILE_CHUNK, &mut raw_chunk)
                    .await?
                    > 0
                {
                    if self.cancel.is_cancelled() {
                        report.cancelled = true;
                        break;
                    }
                    pair_chunk.clear();
                    for item in raw_chunk.drain(..) {
                        pair_chunk.push((item.nfc_path, item.backend_path));
                    }
                    deleted_files += self
                        .delete_dst_file_chunk(cfg, pair_key, &pair_chunk, bwlimit, emitter, report)
                        .await?;
                }
            }
        }

        if !report.cancelled
            && observed_dst_files > 0
            && deleted_files.saturating_mul(2) > observed_dst_files
        {
            let pct = (deleted_files as f64 / observed_dst_files as f64) * 100.0;
            let msg = format!(
                "sync deleted {deleted_files} of {observed_dst_files} observed destination files ({pct:.1}% > 50%)"
            );
            warn!("{msg}");
            report.high_delete_warning = Some(msg);
        }

        let delete_dir_conc = cfg.transfers.clamp(1, 16);
        for (_depth, dir_log) in delete_dirs_logs.into_iter().rev() {
            if self.cancel.is_cancelled() || report.cancelled {
                report.cancelled = true;
                break;
            }
            if cfg.dry_run {
                let mut reader = dir_log.into_reader_async().await?;
                let mut raw_chunk = Vec::with_capacity(DELETE_FILE_CHUNK);
                while reader
                    .next_chunk_async(DELETE_FILE_CHUNK, &mut raw_chunk)
                    .await?
                    > 0
                {
                    for item in raw_chunk.drain(..) {
                        if !protected_dst_dirs.is_protected(&item.nfc_path) {
                            report.items_deleted += 1;
                        }
                    }
                }
                continue;
            }
            let mut reader = dir_log.into_reader_async().await?;
            let mut raw_chunk = Vec::with_capacity(DELETE_FILE_CHUNK);
            while reader
                .next_chunk_async(DELETE_FILE_CHUNK, &mut raw_chunk)
                .await?
                > 0
            {
                if self.cancel.is_cancelled() {
                    report.cancelled = true;
                    break;
                }
                let mut targets = Vec::with_capacity(raw_chunk.len());
                for item in raw_chunk.drain(..) {
                    if protected_dst_dirs.is_protected(&item.nfc_path) {
                        continue;
                    }
                    let node_id = item.backend_path.node_id.clone();
                    let full_target = BackendPath::join_prefixed(
                        &cfg.dst_prefix,
                        item.backend_path.raw_path(),
                        &item.backend_path.nfc_path,
                        node_id,
                        Some(EntryKind::Directory),
                    )?;
                    targets.push((item.nfc_path, full_target));
                }
                if targets.is_empty() {
                    continue;
                }
                let dst = self.dst.clone();
                let cancel = self.cancel.clone();
                let clear_base = cfg.baseline_mode != BaselineMode::None;
                let mut stream = futures::stream::iter(targets)
                    .map(move |(nfc, full_target)| {
                        let dst = dst.clone();
                        let cancel = cancel.clone();
                        async move {
                            if cancel.is_cancelled() {
                                return None;
                            }
                            match dst.delete(&full_target).await {
                                Ok(()) => Some(Ok(nfc)),
                                Err(e) => Some(Err((nfc, e))),
                            }
                        }
                    })
                    .buffer_unordered(delete_dir_conc);

                let mut deleted_dir_nfcs = Vec::new();
                while let Some(item) = stream.next().await {
                    match item {
                        Some(Ok(nfc)) => {
                            if clear_base {
                                deleted_dir_nfcs.push(nfc);
                            }
                            report.items_deleted += 1;
                            if let Some(p) = &self.progress {
                                p.inc_items_deleted();
                            }
                        }
                        Some(Err((nfc, e))) => {
                            if let Some(p) = &self.progress {
                                p.inc_errors();
                            }
                            let msg = format!("delete `{nfc}`: {e}");
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(nfc.as_str().to_string()),
                                &e,
                                msg.clone(),
                            );
                            emitter.emit_error(info.clone());
                            report.push_error(info);
                        }
                        None => report.cancelled = true,
                    }
                }
                if !deleted_dir_nfcs.is_empty() {
                    let _ = self
                        .journal
                        .delete_baselines_batch(pair_key, &deleted_dir_nfcs)
                        .await;
                }
            }
        }
        Ok(())
    }
}
