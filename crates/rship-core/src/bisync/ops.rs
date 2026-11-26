//! Execution helpers for [`BisyncEngine`]: file transfers, conflict strategies
//! (`KeepBoth`, `PreferA`, `PreferB`, `Abort`), and ordered batch/reverse-depth deletions.

use futures::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::info;

use super::{
    BisyncAction, BisyncConfig, BisyncEngine, BisyncReport, BisyncWorkOutcome, ConflictStrategy,
    make_bisync_baseline, make_conflict_path,
};
use crate::backend::{BackendPath, StorageBackend};
use crate::bandwidth::BandwidthLimiter;
use crate::engine::diff::{DeleteSpillLog, DeleteTarget};
use crate::engine::task::{TransferOutcome, TransferTask, execute_transfer_task};
use crate::engine::{EngineConfig, FileTransferResult, TransferErrorInfo};
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::progress::JobEventEmitter;
use crate::state::{
    BaselineMode, ConflictKind, DstPrecondition, JobMode, SourceVersion, SyncConflict,
};
use crate::types::{Capabilities, Entry, EntryKind};

impl BisyncEngine {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_work_action(
        &self,
        action: BisyncAction,
        cfg: &BisyncConfig,
        pair_key: &str,
        a_caps: &Capabilities,
        b_caps: &Capabilities,
        emitter: &JobEventEmitter,
        bwlimit: Option<&Arc<BandwidthLimiter>>,
    ) -> Result<BisyncWorkOutcome> {
        let mut out = BisyncWorkOutcome::default();
        if self.cancel.is_cancelled() {
            out.cancelled = true;
            return Ok(out);
        }
        match action {
            BisyncAction::CopyAToB { a, b_existing } => {
                emitter.emit_file_started(a.nfc_path.as_str(), a.size);
                if cfg.dry_run {
                    out.copied_a_to_b = 1;
                    out.files_done = 1;
                    out.bytes_transferred = a.size;
                    if let Some(p) = &self.progress {
                        p.inc_files_done();
                        p.add_bytes_done(a.size);
                    }
                    emitter.emit_file_completed(FileTransferResult::transferred(
                        a.nfc_path.as_str(),
                        a.size,
                        false,
                    ));
                    return Ok(out);
                }
                match self
                    .copy_one(
                        cfg,
                        pair_key,
                        &self.side_a,
                        &cfg.a_prefix,
                        a_caps,
                        &self.side_b,
                        &cfg.b_prefix,
                        b_caps,
                        &a,
                        b_existing.as_ref(),
                        &a.nfc_path,
                        bwlimit,
                    )
                    .await
                {
                    Ok((b_written, op_id)) => {
                        let base = make_bisync_baseline(pair_key, &a, &b_written, &self.clock);
                        self.journal
                            .commit_verified_transfer(
                                op_id.as_deref(),
                                Some(&base),
                                &cfg.job_id,
                                a.size,
                            )
                            .await?;
                        out.copied_a_to_b = 1;
                        if b_existing.is_none() {
                            out.created_on_b = 1;
                        }
                        out.files_done = 1;
                        out.bytes_transferred = a.size;
                        if let Some(p) = &self.progress {
                            p.inc_files_done();
                        }
                        emitter.emit_file_completed(FileTransferResult::transferred(
                            a.nfc_path.as_str(),
                            a.size,
                            false,
                        ));
                    }
                    Err(e) => {
                        if let Some(p) = &self.progress {
                            p.inc_errors();
                        }
                        let msg = format!("copy A->B `{}`: {e}", a.nfc_path);
                        out.errors.push(TransferErrorInfo::from_error_with_message(
                            Some(a.nfc_path.as_str().to_string()),
                            &e,
                            msg.clone(),
                        ));
                        emitter.emit_file_completed(FileTransferResult::failed_with_message(
                            a.nfc_path.as_str(),
                            &e,
                            msg,
                        ));
                    }
                }
            }
            BisyncAction::CopyBToA { b, a_existing } => {
                emitter.emit_file_started(b.nfc_path.as_str(), b.size);
                if cfg.dry_run {
                    out.copied_b_to_a = 1;
                    out.files_done = 1;
                    out.bytes_transferred = b.size;
                    if let Some(p) = &self.progress {
                        p.inc_files_done();
                        p.add_bytes_done(b.size);
                    }
                    emitter.emit_file_completed(FileTransferResult::transferred(
                        b.nfc_path.as_str(),
                        b.size,
                        false,
                    ));
                    return Ok(out);
                }
                match self
                    .copy_one(
                        cfg,
                        pair_key,
                        &self.side_b,
                        &cfg.b_prefix,
                        b_caps,
                        &self.side_a,
                        &cfg.a_prefix,
                        a_caps,
                        &b,
                        a_existing.as_ref(),
                        &b.nfc_path,
                        bwlimit,
                    )
                    .await
                {
                    Ok((a_written, op_id)) => {
                        let base = make_bisync_baseline(pair_key, &a_written, &b, &self.clock);
                        self.journal
                            .commit_verified_transfer(
                                op_id.as_deref(),
                                Some(&base),
                                &cfg.job_id,
                                b.size,
                            )
                            .await?;
                        out.copied_b_to_a = 1;
                        if a_existing.is_none() {
                            out.created_on_a = 1;
                        }
                        out.files_done = 1;
                        out.bytes_transferred = b.size;
                        if let Some(p) = &self.progress {
                            p.inc_files_done();
                        }
                        emitter.emit_file_completed(FileTransferResult::transferred(
                            b.nfc_path.as_str(),
                            b.size,
                            false,
                        ));
                    }
                    Err(e) => {
                        if let Some(p) = &self.progress {
                            p.inc_errors();
                        }
                        let msg = format!("copy B->A `{}`: {e}", b.nfc_path);
                        out.errors.push(TransferErrorInfo::from_error_with_message(
                            Some(b.nfc_path.as_str().to_string()),
                            &e,
                            msg.clone(),
                        ));
                        emitter.emit_file_completed(FileTransferResult::failed_with_message(
                            b.nfc_path.as_str(),
                            &e,
                            msg,
                        ));
                    }
                }
            }
            BisyncAction::Conflict {
                nfc_path,
                kind,
                a,
                b,
                detail,
            } => {
                let conflict = SyncConflict {
                    nfc_path: nfc_path.clone(),
                    kind,
                    detail,
                };
                emitter.emit_conflict(conflict.clone());
                let is_type_flip = matches!(
                    kind,
                    ConflictKind::TypeFlipFileOverDir | ConflictKind::TypeFlipDirOverFile
                );
                if is_type_flip || cfg.conflict_strategy == ConflictStrategy::Abort {
                    out.conflict = Some(conflict);
                    return Ok(out);
                }
                match cfg.conflict_strategy {
                    ConflictStrategy::PreferA => {
                        if let Some(ae) = a {
                            if !cfg.dry_run {
                                match self
                                    .copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_a,
                                        &cfg.a_prefix,
                                        a_caps,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &ae,
                                        b.as_ref(),
                                        &nfc_path,
                                        bwlimit,
                                    )
                                    .await
                                {
                                    Ok((bw, op_id)) => {
                                        let base =
                                            make_bisync_baseline(pair_key, &ae, &bw, &self.clock);
                                        self.journal
                                            .commit_verified_transfer(
                                                op_id.as_deref(),
                                                Some(&base),
                                                &cfg.job_id,
                                                ae.size,
                                            )
                                            .await?;
                                        out.copied_a_to_b = 1;
                                        if b.is_none() {
                                            out.created_on_b = 1;
                                        }
                                        out.files_done = 1;
                                        out.bytes_transferred = ae.size;
                                        out.conflicts_resolved = 1;
                                        if let Some(p) = &self.progress {
                                            p.inc_files_done();
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_errors();
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(nfc_path.as_str().to_string()),
                                            &e,
                                            format!("conflict prefer-a `{nfc_path}`: {e}"),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                }
                            } else {
                                out.files_done = 1;
                                out.bytes_transferred = ae.size;
                                out.conflicts_resolved = 1;
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.add_bytes_done(ae.size);
                                }
                            }
                        } else if let Some(be) = b {
                            out.extra_delete_b = Some(be);
                            out.conflicts_resolved = 1;
                        }
                    }
                    ConflictStrategy::PreferB => {
                        if let Some(be) = b {
                            if !cfg.dry_run {
                                match self
                                    .copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &self.side_a,
                                        &cfg.a_prefix,
                                        a_caps,
                                        &be,
                                        a.as_ref(),
                                        &nfc_path,
                                        bwlimit,
                                    )
                                    .await
                                {
                                    Ok((aw, op_id)) => {
                                        let base =
                                            make_bisync_baseline(pair_key, &aw, &be, &self.clock);
                                        self.journal
                                            .commit_verified_transfer(
                                                op_id.as_deref(),
                                                Some(&base),
                                                &cfg.job_id,
                                                be.size,
                                            )
                                            .await?;
                                        out.copied_b_to_a = 1;
                                        if a.is_none() {
                                            out.created_on_a = 1;
                                        }
                                        out.files_done = 1;
                                        out.bytes_transferred = be.size;
                                        out.conflicts_resolved = 1;
                                        if let Some(p) = &self.progress {
                                            p.inc_files_done();
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_errors();
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(nfc_path.as_str().to_string()),
                                            &e,
                                            format!("conflict prefer-b `{nfc_path}`: {e}"),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                }
                            } else {
                                out.files_done = 1;
                                out.bytes_transferred = be.size;
                                out.conflicts_resolved = 1;
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.add_bytes_done(be.size);
                                }
                            }
                        } else if let Some(ae) = a {
                            out.extra_delete_a = Some(ae);
                            out.conflicts_resolved = 1;
                        }
                    }
                    ConflictStrategy::KeepBoth => match (a, b) {
                        (Some(ae), Some(be)) => {
                            let conflict_rel =
                                make_conflict_path(&nfc_path, self.clock.now_unix_secs())?;
                            info!(
                                path = %nfc_path,
                                conflict_copy = %conflict_rel,
                                "preserving concurrent bisync conflict copy (keep-both)"
                            );
                            if !cfg.dry_run {
                                let (ca, cb) = tokio::join!(
                                    self.copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &self.side_a,
                                        &cfg.a_prefix,
                                        a_caps,
                                        &be,
                                        None,
                                        &conflict_rel,
                                        bwlimit,
                                    ),
                                    self.copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &be,
                                        None,
                                        &conflict_rel,
                                        bwlimit,
                                    ),
                                );
                                match (ca, cb) {
                                    (Ok((ca_e, ca_op)), Ok((cb_e, cb_op))) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_files_done();
                                            p.inc_files_done();
                                        }
                                        if let Some(id) = ca_op {
                                            self.journal.delete_operation(&id).await?;
                                        }
                                        let cbase = make_bisync_baseline(
                                            pair_key,
                                            &ca_e,
                                            &cb_e,
                                            &self.clock,
                                        );
                                        self.journal
                                            .commit_verified_transfer(
                                                cb_op.as_deref(),
                                                Some(&cbase),
                                                &cfg.job_id,
                                                be.size.saturating_add(be.size),
                                            )
                                            .await?;
                                        match self
                                            .copy_one(
                                                cfg,
                                                pair_key,
                                                &self.side_a,
                                                &cfg.a_prefix,
                                                a_caps,
                                                &self.side_b,
                                                &cfg.b_prefix,
                                                b_caps,
                                                &ae,
                                                Some(&be),
                                                &nfc_path,
                                                bwlimit,
                                            )
                                            .await
                                        {
                                            Ok((bw, op_id)) => {
                                                let base = make_bisync_baseline(
                                                    pair_key,
                                                    &ae,
                                                    &bw,
                                                    &self.clock,
                                                );
                                                self.journal
                                                    .commit_verified_transfer(
                                                        op_id.as_deref(),
                                                        Some(&base),
                                                        &cfg.job_id,
                                                        ae.size,
                                                    )
                                                    .await?;
                                                out.copied_a_to_b = 1;
                                                out.copied_b_to_a = 1;
                                                out.created_on_a = 1;
                                                out.created_on_b = 1;
                                                out.files_done = 3;
                                                out.bytes_transferred = ae
                                                    .size
                                                    .saturating_add(be.size)
                                                    .saturating_add(be.size);
                                                out.conflicts_resolved = 1;
                                                if let Some(p) = &self.progress {
                                                    p.inc_files_done();
                                                }
                                            }
                                            Err(e) => {
                                                if let Some(p) = &self.progress {
                                                    p.inc_errors();
                                                }
                                                let info =
                                                    TransferErrorInfo::from_error_with_message(
                                                        Some(nfc_path.as_str().to_string()),
                                                        &e,
                                                        format!(
                                                            "keep-both canonical copy `{nfc_path}`: {e}"
                                                        ),
                                                    );
                                                emitter.emit_error(info.clone());
                                                out.errors.push(info);
                                            }
                                        }
                                    }
                                    (Err(e1), Err(e2)) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_errors();
                                            p.inc_errors();
                                            p.record_worker_skip(ae.size);
                                        }
                                        for e in [e1, e2] {
                                            let info = TransferErrorInfo::from_error_with_message(
                                                Some(conflict_rel.as_str().to_string()),
                                                &e,
                                                format!(
                                                    "keep-both conflict copy `{conflict_rel}`: {e}"
                                                ),
                                            );
                                            emitter.emit_error(info.clone());
                                            out.errors.push(info);
                                        }
                                    }
                                    (Ok((ca_e, ca_op)), Err(e)) => {
                                        // Best-effort cleanup of the orphan conflict copy on Side A so
                                        // the next bisync run does not propagate a half-written twin.
                                        if let Ok(full_a) = BackendPath::join_prefixed(
                                            &cfg.a_prefix,
                                            conflict_rel.as_str(),
                                            &conflict_rel,
                                            ca_e.node_id.clone(),
                                            Some(EntryKind::File),
                                        ) {
                                            let _ = self.side_a.delete(&full_a).await;
                                        }
                                        if let Some(id) = ca_op {
                                            let _ = self.journal.delete_operation(&id).await;
                                        }
                                        if let Some(p) = &self.progress {
                                            p.record_worker_skip(be.size);
                                            p.inc_errors();
                                            p.record_worker_skip(ae.size);
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(conflict_rel.as_str().to_string()),
                                            &e,
                                            format!(
                                                "keep-both conflict copy `{conflict_rel}`: {e}"
                                            ),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                    (Err(e), Ok((cb_e, cb_op))) => {
                                        // Best-effort cleanup of the orphan conflict copy on Side B.
                                        if let Ok(full_b) = BackendPath::join_prefixed(
                                            &cfg.b_prefix,
                                            conflict_rel.as_str(),
                                            &conflict_rel,
                                            cb_e.node_id.clone(),
                                            Some(EntryKind::File),
                                        ) {
                                            let _ = self.side_b.delete(&full_b).await;
                                        }
                                        if let Some(id) = cb_op {
                                            let _ = self.journal.delete_operation(&id).await;
                                        }
                                        if let Some(p) = &self.progress {
                                            p.record_worker_skip(be.size);
                                            p.inc_errors();
                                            p.record_worker_skip(ae.size);
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(conflict_rel.as_str().to_string()),
                                            &e,
                                            format!(
                                                "keep-both conflict copy `{conflict_rel}`: {e}"
                                            ),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                }
                            } else {
                                out.files_done = 3;
                                out.bytes_transferred =
                                    be.size.saturating_add(be.size).saturating_add(ae.size);
                                out.conflicts_resolved = 1;
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.inc_files_done();
                                    p.inc_files_done();
                                    p.add_bytes_done(
                                        be.size.saturating_add(be.size).saturating_add(ae.size),
                                    );
                                }
                            }
                        }
                        (Some(ae), None) => {
                            if !cfg.dry_run {
                                match self
                                    .copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_a,
                                        &cfg.a_prefix,
                                        a_caps,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &ae,
                                        None,
                                        &nfc_path,
                                        bwlimit,
                                    )
                                    .await
                                {
                                    Ok((bw, op_id)) => {
                                        let base =
                                            make_bisync_baseline(pair_key, &ae, &bw, &self.clock);
                                        self.journal
                                            .commit_verified_transfer(
                                                op_id.as_deref(),
                                                Some(&base),
                                                &cfg.job_id,
                                                ae.size,
                                            )
                                            .await?;
                                        out.copied_a_to_b = 1;
                                        out.created_on_b = 1;
                                        out.files_done = 1;
                                        out.bytes_transferred = ae.size;
                                        out.conflicts_resolved = 1;
                                        if let Some(p) = &self.progress {
                                            p.inc_files_done();
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_errors();
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(nfc_path.as_str().to_string()),
                                            &e,
                                            format!("keep-both revive `{nfc_path}`: {e}"),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                }
                            } else {
                                out.files_done = 1;
                                out.bytes_transferred = ae.size;
                                out.conflicts_resolved = 1;
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.add_bytes_done(ae.size);
                                }
                            }
                        }
                        (None, Some(be)) => {
                            if !cfg.dry_run {
                                match self
                                    .copy_one(
                                        cfg,
                                        pair_key,
                                        &self.side_b,
                                        &cfg.b_prefix,
                                        b_caps,
                                        &self.side_a,
                                        &cfg.a_prefix,
                                        a_caps,
                                        &be,
                                        None,
                                        &nfc_path,
                                        bwlimit,
                                    )
                                    .await
                                {
                                    Ok((aw, op_id)) => {
                                        let base =
                                            make_bisync_baseline(pair_key, &aw, &be, &self.clock);
                                        self.journal
                                            .commit_verified_transfer(
                                                op_id.as_deref(),
                                                Some(&base),
                                                &cfg.job_id,
                                                be.size,
                                            )
                                            .await?;
                                        out.copied_b_to_a = 1;
                                        out.created_on_a = 1;
                                        out.files_done = 1;
                                        out.bytes_transferred = be.size;
                                        out.conflicts_resolved = 1;
                                        if let Some(p) = &self.progress {
                                            p.inc_files_done();
                                        }
                                    }
                                    Err(e) => {
                                        if let Some(p) = &self.progress {
                                            p.inc_errors();
                                        }
                                        let info = TransferErrorInfo::from_error_with_message(
                                            Some(nfc_path.as_str().to_string()),
                                            &e,
                                            format!("keep-both revive `{nfc_path}`: {e}"),
                                        );
                                        emitter.emit_error(info.clone());
                                        out.errors.push(info);
                                    }
                                }
                            } else {
                                out.files_done = 1;
                                out.bytes_transferred = be.size;
                                out.conflicts_resolved = 1;
                                if let Some(p) = &self.progress {
                                    p.inc_files_done();
                                    p.add_bytes_done(be.size);
                                }
                            }
                        }
                        (None, None) => {}
                    },
                    ConflictStrategy::Abort => {}
                }
            }
            _ => {}
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_side_delete_logs(
        &self,
        backend: &Arc<dyn StorageBackend>,
        prefix: &RelPath,
        side_label: &str,
        files_log: DeleteSpillLog,
        dirs_logs: BTreeMap<usize, DeleteSpillLog>,
        protected_dirs: &crate::engine::ProtectedDirs,
        pair_key: &str,
        conc: usize,
        dry_run: bool,
        emitter: &JobEventEmitter,
        report: &mut BisyncReport,
    ) -> Result<(u64, u64)> {
        const DELETE_CHUNK: usize = 1000;
        let file_items = files_log.len();
        let total_items = file_items + dirs_logs.values().map(DeleteSpillLog::len).sum::<u64>();
        if total_items == 0 {
            return Ok((0, 0));
        }
        if dry_run {
            let mut dir_items = 0u64;
            for (_depth, dir_log) in dirs_logs {
                let mut reader = dir_log.into_reader_async().await?;
                let mut chunk = Vec::with_capacity(DELETE_CHUNK);
                while reader.next_chunk_async(DELETE_CHUNK, &mut chunk).await? > 0 {
                    for item in chunk.drain(..) {
                        if !protected_dirs.is_protected(&item.nfc_path) {
                            dir_items += 1;
                        }
                    }
                }
            }
            return Ok((file_items + dir_items, file_items));
        }

        let mut deleted = 0u64;
        let mut deleted_files = 0u64;
        if !files_log.is_empty() {
            enum VerifyDeleteOutcome {
                Cancelled,
                ReadyToDelete(RelPath, BackendPath),
                AlreadyGone(RelPath),
                ModifiedConcurrently(RelPath),
                StatFailed(RelPath, Error),
            }

            let mut reader = files_log.into_reader_async().await?;
            let mut chunk: Vec<DeleteTarget> = Vec::with_capacity(DELETE_CHUNK);
            while reader.next_chunk_async(DELETE_CHUNK, &mut chunk).await? > 0 {
                if self.cancel.is_cancelled() {
                    report.cancelled = true;
                    return Ok((deleted, deleted_files));
                }
                let mut candidates = Vec::with_capacity(chunk.len());
                for item in chunk.drain(..) {
                    let node_id = item.backend_path.node_id.clone();
                    let full_bp = BackendPath::join_prefixed(
                        prefix,
                        item.backend_path.raw_path(),
                        &item.backend_path.nfc_path,
                        node_id,
                        Some(item.kind),
                    )?;
                    candidates.push((item, full_bp));
                }

                // Re-stat each candidate concurrently (bounded by `conc`) and verify its live
                // version still matches Phase-1 observation before issuing `delete_batch`.
                let b_verify = backend.clone();
                let cancel_verify = self.cancel.clone();
                let mut verify_stream = futures::stream::iter(candidates)
                    .map(move |(item, full_bp)| {
                        let b = b_verify.clone();
                        let cancel = cancel_verify.clone();
                        async move {
                            if cancel.is_cancelled() {
                                return VerifyDeleteOutcome::Cancelled;
                            }
                            let Some(expected) = item.expected_version else {
                                return VerifyDeleteOutcome::ReadyToDelete(item.nfc_path, full_bp);
                            };
                            match b.stat(&full_bp).await {
                                Ok(None) => VerifyDeleteOutcome::AlreadyGone(item.nfc_path),
                                Ok(Some(live))
                                    if live.kind == item.kind
                                        && SourceVersion::from_entry(&live) == expected =>
                                {
                                    VerifyDeleteOutcome::ReadyToDelete(item.nfc_path, full_bp)
                                }
                                Ok(Some(_)) => {
                                    VerifyDeleteOutcome::ModifiedConcurrently(item.nfc_path)
                                }
                                Err(err) => VerifyDeleteOutcome::StatFailed(item.nfc_path, err),
                            }
                        }
                    })
                    .buffer_unordered(conc);

                let mut full_targets = Vec::new();
                let mut nfc_by_full = HashMap::new();
                let mut already_gone_nfcs = Vec::new();
                while let Some(res) = verify_stream.next().await {
                    match res {
                        VerifyDeleteOutcome::Cancelled => {
                            report.cancelled = true;
                        }
                        VerifyDeleteOutcome::ReadyToDelete(nfc, full_bp) => {
                            nfc_by_full.insert(full_bp.nfc_path.as_str().to_string(), nfc);
                            full_targets.push(full_bp);
                        }
                        VerifyDeleteOutcome::AlreadyGone(nfc) => {
                            already_gone_nfcs.push(nfc);
                            deleted += 1;
                            deleted_files += 1;
                            if let Some(p) = &self.progress {
                                p.inc_items_deleted();
                            }
                        }
                        VerifyDeleteOutcome::ModifiedConcurrently(nfc) => {
                            let err = Error::precondition_failed(format!(
                                "delete {side_label} `{nfc}`: target modified concurrently since observation; skipping delete"
                            ));
                            let info =
                                TransferErrorInfo::from_error(Some(nfc.as_str().to_string()), &err);
                            if let Some(p) = &self.progress {
                                p.inc_errors();
                            }
                            emitter.emit_error(info.clone());
                            report.push_error(info);
                        }
                        VerifyDeleteOutcome::StatFailed(nfc, err) => {
                            let msg = format!("re-stat before delete {side_label} `{nfc}`: {err}");
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(nfc.as_str().to_string()),
                                &err,
                                msg,
                            );
                            if let Some(p) = &self.progress {
                                p.inc_errors();
                            }
                            emitter.emit_error(info.clone());
                            report.push_error(info);
                        }
                    }
                }
                if !already_gone_nfcs.is_empty() {
                    let _ = self
                        .journal
                        .delete_baselines_batch(pair_key, &already_gone_nfcs)
                        .await;
                }
                if report.cancelled {
                    return Ok((deleted, deleted_files));
                }
                if full_targets.is_empty() {
                    continue;
                }
                match backend.delete_batch(&full_targets).await {
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
                            let msg = format!("delete {side_label} `{label}`: {err}");
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(label.to_string()),
                                &err,
                                msg,
                            );
                            emitter.emit_error(info.clone());
                            report.push_error(info);
                            failed_keys.insert(key);
                        }
                        let mut deleted_nfcs = Vec::new();
                        for bp in &full_targets {
                            let key = bp.nfc_path.as_str();
                            if !failed_keys.contains(key) {
                                if let Some(nfc) = nfc_by_full.get(key) {
                                    deleted_nfcs.push(nfc.clone());
                                }
                                deleted += 1;
                                deleted_files += 1;
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
                    Err(err) => {
                        if let Some(p) = &self.progress {
                            p.inc_errors();
                        }
                        let msg = format!("batch delete {side_label} failed: {err}");
                        let info = TransferErrorInfo::from_error_with_message(None, &err, msg);
                        emitter.emit_error(info.clone());
                        report.push_error(info);
                    }
                }
            }
        }

        for (_depth, dir_log) in dirs_logs.into_iter().rev() {
            if self.cancel.is_cancelled() || report.cancelled {
                report.cancelled = true;
                break;
            }
            let mut reader = dir_log.into_reader_async().await?;
            let mut chunk: Vec<DeleteTarget> = Vec::with_capacity(DELETE_CHUNK);
            while reader.next_chunk_async(DELETE_CHUNK, &mut chunk).await? > 0 {
                if self.cancel.is_cancelled() {
                    report.cancelled = true;
                    break;
                }
                let mut targets = Vec::with_capacity(chunk.len());
                for item in chunk.drain(..) {
                    if protected_dirs.is_protected(&item.nfc_path) {
                        continue;
                    }
                    let node_id = item.backend_path.node_id.clone();
                    let bp = BackendPath::join_prefixed(
                        prefix,
                        item.backend_path.raw_path(),
                        &item.backend_path.nfc_path,
                        node_id,
                        Some(item.kind),
                    )?;
                    targets.push((item.nfc_path, bp));
                }
                if targets.is_empty() {
                    continue;
                }
                let b = backend.clone();
                let cancel = self.cancel.clone();
                let mut stream = futures::stream::iter(targets)
                    .map(move |(nfc, bp)| {
                        let b = b.clone();
                        let cancel = cancel.clone();
                        async move {
                            if cancel.is_cancelled() {
                                return None;
                            }
                            match b.delete(&bp).await {
                                Ok(()) => Some(Ok(nfc)),
                                Err(err) => Some(Err((nfc, err))),
                            }
                        }
                    })
                    .buffer_unordered(conc);

                let mut deleted_dir_nfcs = Vec::new();
                while let Some(res) = stream.next().await {
                    match res {
                        Some(Ok(nfc)) => {
                            deleted_dir_nfcs.push(nfc);
                            deleted += 1;
                            if let Some(p) = &self.progress {
                                p.inc_items_deleted();
                            }
                        }
                        Some(Err((nfc, err))) => {
                            if let Some(p) = &self.progress {
                                p.inc_errors();
                            }
                            let msg = format!("delete {side_label} `{nfc}`: {err}");
                            let info = TransferErrorInfo::from_error_with_message(
                                Some(nfc.as_str().to_string()),
                                &err,
                                msg,
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

        Ok((deleted, deleted_files))
    }

    /// Execute one bisync file transfer via the unified [`execute_transfer_task`] pipeline:
    /// automatically unlocks `> 5 GiB` parallel multipart / resumable sequential uploads,
    /// write-ahead crash recovery, retries, and zero-bandwidth server-side copy while letting
    /// bisync commit its own dual-side baseline record on verification.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn copy_one(
        &self,
        cfg: &BisyncConfig,
        pair_key: &str,
        src: &Arc<dyn StorageBackend>,
        src_prefix: &RelPath,
        src_caps: &Capabilities,
        dst: &Arc<dyn StorageBackend>,
        dst_prefix: &RelPath,
        dst_caps: &Capabilities,
        src_entry: &Entry,
        dst_existing: Option<&Entry>,
        dst_rel: &RelPath,
        bwlimit: Option<&Arc<BandwidthLimiter>>,
    ) -> Result<(Entry, Option<String>)> {
        let mut tcfg = EngineConfig::new(&cfg.job_id, JobMode::Copy, &cfg.a_spec, &cfg.b_spec);
        tcfg.src_prefix = src_prefix.clone();
        tcfg.dst_prefix = dst_prefix.clone();
        tcfg.delete = false;
        tcfg.delete_source_after_transfer = false;
        tcfg.baseline_mode = BaselineMode::None;
        tcfg.allow_server_side_copy = true;
        tcfg.scratch_dir = cfg.scratch_dir.clone();
        tcfg.retry_quota = cfg.transfer_retry_quota(dst.as_ref());
        tcfg.retry_jitter = cfg.retry_jitter.clone();

        let precondition = match dst_existing {
            Some(d) => DstPrecondition::Existing {
                node_id: d.node_id.clone(),
                etag: d.etag.clone(),
                mtime_ns: d.mtime_ns,
                size: d.size,
            },
            None => DstPrecondition::Absent,
        };
        if !dst_caps.supports_conditional_write
            && let Some(obs) = dst_existing
        {
            let dst_bp = BackendPath::join_prefixed(
                dst_prefix,
                obs.raw_path(),
                dst_rel,
                obs.node_id.clone(),
                Some(obs.kind),
            )?;
            let expected = SourceVersion::from_entry(obs);
            match dst.stat(&dst_bp).await? {
                Some(live)
                    if live.kind == obs.kind && SourceVersion::from_entry(&live) == expected => {}
                Some(live) => {
                    return Err(Error::precondition_failed(format!(
                        "destination `{dst_rel}` modified concurrently since observation (expected {:?}, observed {:?}); refusing overwrite",
                        expected,
                        SourceVersion::from_entry(&live),
                    )));
                }
                None => {
                    return Err(Error::precondition_failed(format!(
                        "destination `{dst_rel}` disappeared concurrently since observation; refusing overwrite"
                    )));
                }
            }
        }
        let task = TransferTask {
            src: src_entry.clone(),
            dst_rel: dst_rel.clone(),
            existing_dst_node_id: dst_existing.and_then(|e| e.node_id.clone()),
            precondition,
            needs_checksum_verify: false,
            dst_existing: dst_existing.cloned(),
            wire_key: None,
            replace_dst_dir: None,
            defer_op_commit: true,
        };

        let slot_guard = self
            .progress
            .as_ref()
            .map(|prog| prog.start_transfer(dst_rel.as_str(), src_entry.size, ""));
        let outcome = execute_transfer_task(
            src,
            dst,
            &self.journal,
            &self.pool,
            &self.clock,
            &self.cancel,
            bwlimit,
            self.progress.as_ref(),
            slot_guard.as_ref(),
            None,
            &tcfg,
            pair_key,
            src_caps,
            dst_caps,
            task,
        )
        .await?;
        drop(slot_guard);

        match outcome {
            TransferOutcome::Transferred {
                mut entry,
                op_id_to_retire,
                ..
            }
            | TransferOutcome::ServerSideCopied {
                mut entry,
                op_id_to_retire,
                ..
            } => {
                // Normalize `nfc_path` to sync-root-relative path for `make_bisync_baseline`.
                entry.nfc_path = dst_rel.clone();
                Ok((entry, op_id_to_retire))
            }
            TransferOutcome::Skipped { .. } => Err(Error::protocol(
                "unexpected Skipped outcome during bisync copy_one",
            )),
        }
    }
}
