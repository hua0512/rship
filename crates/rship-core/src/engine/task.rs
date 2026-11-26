//! Per-file transfer task execution: server-side copy, `--strict-source` snapshots,
//! checksum verification, upload protocol dispatch, and `move` source cleanup.

use std::sync::Arc;
use tracing::{info, warn};

use crate::adaptive::{FalconController, TransferLane};
use crate::backend::{BackendPath, ReconcileOutcome, StorageBackend, UploadInit};
use crate::bandwidth::BandwidthLimiter;
use crate::buffer::BufferPool;
use crate::chunking::{UploadPlan, plan_upload};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::progress::{ActiveTransferGuard, TransferProgress};
use crate::source::{SeekableSource, SpoolSeekableSource};
use crate::state::{
    DstPrecondition, JournalStore, OperationRecord, OperationState, SourceVersion,
    compute_session_key, integrity_marker_key,
};
use crate::types::{Entry, UploadTopology};

use super::protocols::{
    open_range_body, run_parallel_multipart, run_sequential_resumable, run_single_shot,
};
use super::{
    CancelFlag, EngineConfig, generate_op_id, join_prefix, make_baseline, should_persist_baseline,
    verify_committed_checksum, verify_source_unchanged,
};

/// Upper bound on fresh whole-file retries after a data-integrity failure (also capped by
/// [`EngineConfig::max_retries`]).
const MAX_INTEGRITY_RETRIES: u32 = 2;

pub(crate) struct TransferTask {
    pub(crate) src: Entry,
    pub(crate) dst_rel: RelPath,
    pub(crate) existing_dst_node_id: Option<crate::types::NodeId>,
    pub(crate) precondition: DstPrecondition,
    pub(crate) needs_checksum_verify: bool,
    pub(crate) dst_existing: Option<Entry>,
    pub(crate) wire_key: Option<String>,
    /// Set under `--force-type-replace` when replacing a destination directory with a file.
    pub(crate) replace_dst_dir: Option<BackendPath>,
    /// When `true` (used by `BisyncEngine`), skip calling `commit_verified_transfer` inside
    /// `execute_transfer_task` and return `op_id_to_retire` so the caller fuses operation
    /// retirement and dual-side baseline upsert into a single transaction.
    pub(crate) defer_op_commit: bool,
}

pub(crate) enum TransferOutcome {
    Transferred {
        bytes: u64,
        source_deleted: bool,
        entry: Entry,
        op_id_to_retire: Option<String>,
    },
    ServerSideCopied {
        bytes: u64,
        source_deleted: bool,
        entry: Entry,
        op_id_to_retire: Option<String>,
    },
    Skipped {
        source_deleted: bool,
    },
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_transfer_task(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
    cfg: &EngineConfig,
    pair_key: &str,
    src_caps: &crate::types::Capabilities,
    dst_caps: &crate::types::Capabilities,
    mut task: TransferTask,
) -> Result<TransferOutcome> {
    let src_full_path = BackendPath::join_prefixed(
        &cfg.src_prefix,
        task.src.raw_path(),
        &task.src.nfc_path,
        task.src.node_id.clone(),
        Some(task.src.kind),
    )?;
    let dst_full_rel = join_prefix(&cfg.dst_prefix, &task.dst_rel)?;

    // `--force-type-replace`: remove the conflicting destination directory (or object-store
    // `<dir>/` marker) BEFORE uploading the replacement file with `DstPrecondition::Absent`.
    if let Some(ref dir_bp) = task.replace_dst_dir {
        let full_dir_bp = BackendPath::join_prefixed(
            &cfg.dst_prefix,
            dir_bp.raw_path(),
            &dir_bp.nfc_path,
            dir_bp.node_id.clone(),
            Some(crate::types::EntryKind::Directory),
        )?;
        dst.delete(&full_dir_bp).await?;
    }

    // Optional checksum fast-skip when sizes match & comparable hash exists.
    // Prefer any hash already present on destination or source metadata (e.g. S3 single-part
    // MD5 ETag) before falling back to `best_common_hash`, and query any remote backend BEFORE
    // reading potentially multi-GiB local files.
    if task.needs_checksum_verify
        && let Some(dst_e) = &task.dst_existing
    {
        let chosen_hash = dst_e
            .checksum
            .as_ref()
            .filter(|ck| src_caps.hashes.contains(&ck.kind))
            .map(|ck| {
                let src_cached = task
                    .src
                    .checksum
                    .as_ref()
                    .filter(|s| s.kind == ck.kind)
                    .map(|s| s.hex.as_str());
                (ck.kind, src_cached, Some(ck.hex.as_str()))
            })
            .or_else(|| {
                task.src
                    .checksum
                    .as_ref()
                    .filter(|ck| dst_caps.hashes.contains(&ck.kind))
                    .map(|ck| (ck.kind, Some(ck.hex.as_str()), None))
            })
            .or_else(|| {
                src_caps
                    .best_common_hash(dst_caps)
                    .map(|hk| (hk, None, None))
            });

        if let Some((hash_kind, cached_src_hex, cached_dst_hex)) = chosen_hash {
            let fetch_src_first = cached_src_hex.is_none()
                && cached_dst_hex.is_none()
                && dst.kind() == "local"
                && src.kind() != "local";

            let (src_hex, dst_hex) = if fetch_src_first {
                let sh = src
                    .compute_hash(&src_full_path, hash_kind)
                    .await
                    .ok()
                    .flatten()
                    .map(|c| c.hex);
                let dh = if sh.is_some() {
                    let dst_bp = BackendPath::join_prefixed(
                        &cfg.dst_prefix,
                        dst_e.raw_path(),
                        &dst_e.nfc_path,
                        dst_e.node_id.clone(),
                        Some(dst_e.kind),
                    )?;
                    dst.compute_hash(&dst_bp, hash_kind)
                        .await
                        .ok()
                        .flatten()
                        .map(|c| c.hex)
                } else {
                    None
                };
                (sh, dh)
            } else {
                let dh = match cached_dst_hex {
                    Some(h) => Some(h.to_owned()),
                    None => {
                        let dst_bp = BackendPath::join_prefixed(
                            &cfg.dst_prefix,
                            dst_e.raw_path(),
                            &dst_e.nfc_path,
                            dst_e.node_id.clone(),
                            Some(dst_e.kind),
                        )?;
                        dst.compute_hash(&dst_bp, hash_kind)
                            .await
                            .ok()
                            .flatten()
                            .map(|c| c.hex)
                    }
                };
                let sh = if dh.is_some() {
                    match cached_src_hex {
                        Some(h) => Some(h.to_owned()),
                        None => src
                            .compute_hash(&src_full_path, hash_kind)
                            .await
                            .ok()
                            .flatten()
                            .map(|c| c.hex),
                    }
                } else {
                    None
                };
                (sh, dh)
            };

            if let (Some(sh), Some(dh)) = (src_hex, dst_hex)
                && sh.eq_ignore_ascii_case(&dh)
            {
                let source_deleted = if cfg.delete_source_after_transfer && !cfg.dry_run {
                    let dst_sync_bp = BackendPath::join_prefixed(
                        &cfg.dst_prefix,
                        dst_e.raw_path(),
                        &dst_e.nfc_path,
                        dst_e.node_id.clone(),
                        Some(dst_e.kind),
                    )?;
                    dst.sync_durable_file(&dst_sync_bp).await?;
                    let ver = SourceVersion::from_entry(&task.src);
                    verify_source_unchanged(src, &src_full_path, &ver).await?;
                    src.delete(&src_full_path).await?;
                    true
                } else {
                    false
                };
                return Ok(TransferOutcome::Skipped { source_deleted });
            }
        }
    }

    // Optional `--backup-dir`: archive existing destination file BEFORE overwriting it!
    // Placed strictly after checksum fast-skip so identical skipped files are NOT backed up.
    if let Some(ref bk) = cfg.backup_dir
        && let Some(ref dst_e) = task.dst_existing
        && dst_e.kind == crate::types::EntryKind::File
        && !cfg.dry_run
    {
        let dst_full_bp = BackendPath::join_prefixed(
            &cfg.dst_prefix,
            dst_e.raw_path(),
            &dst_e.nfc_path,
            dst_e.node_id.clone(),
            Some(crate::types::EntryKind::File),
        )?;
        archive_dst_file_to_backup(
            dst,
            &cfg.dst_prefix,
            bk,
            &task.dst_rel,
            dst_e.raw_path.as_deref(),
            Some(dst_e),
            &dst_full_bp,
            journal,
            pool,
            clock,
            cancel,
            bwlimit,
            cfg,
        )
        .await?;
    }

    let retry_quota = cfg.resolve_retry_quota();
    let max_fresh_attempts = cfg.max_retries.min(MAX_INTEGRITY_RETRIES);
    let mut fresh_attempts = 0u32;
    loop {
        let res = transfer_attempt(
            src,
            dst,
            journal,
            pool,
            clock,
            cancel,
            bwlimit,
            progress,
            slot_guard,
            falcon,
            cfg,
            pair_key,
            src_caps,
            dst_caps,
            &retry_quota,
            &src_full_path,
            &dst_full_rel,
            &mut task,
        )
        .await;
        match res {
            Err(err)
                if err.is_integrity()
                    && fresh_attempts < max_fresh_attempts
                    && !cancel.is_cancelled()
                    && retry_quota.try_acquire(false) =>
            {
                fresh_attempts += 1;
                warn!(
                    path = %task.dst_rel,
                    attempt = fresh_attempts,
                    error = %err,
                    "checksum mismatch; restarting transfer from scratch"
                );
            }
            Ok(outcome) => {
                // A completed, verified transfer replaced any corrupt object recorded by an
                // integrity marker for this path.
                clear_integrity_marker(journal, src, dst, &src_full_path, &dst_full_rel).await?;
                return Ok(outcome);
            }
            Err(err) => return Err(err),
        }
    }
}

fn pair_session_key(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    src_full_path: &BackendPath,
    dst_full_rel: &RelPath,
) -> String {
    compute_session_key(
        &src.endpoint_identity(),
        src_full_path.raw_path(),
        &dst.endpoint_identity(),
        dst_full_rel,
    )
}

async fn clear_integrity_marker(
    journal: &Arc<dyn JournalStore>,
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    src_full_path: &BackendPath,
    dst_full_rel: &RelPath,
) -> Result<()> {
    let key = integrity_marker_key(&pair_session_key(src, dst, src_full_path, dst_full_rel));
    if let Some(marker) = journal.get_operation_by_key(&key).await?
        && marker.state == OperationState::IntegrityFailed
    {
        journal.delete_operation(&marker.op_id).await?;
    }
    Ok(())
}

/// One end-to-end transfer attempt (journal lookup/reconcile, write-ahead intent, upload,
/// post-commit verification, commit, and `move` source cleanup).
#[allow(clippy::too_many_arguments)]
async fn transfer_attempt(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
    cfg: &EngineConfig,
    pair_key: &str,
    src_caps: &crate::types::Capabilities,
    dst_caps: &crate::types::Capabilities,
    retry_quota: &Arc<dyn super::RetryQuota>,
    src_full_path: &BackendPath,
    dst_full_rel: &RelPath,
    task: &mut TransferTask,
) -> Result<TransferOutcome> {
    let src_full_path = src_full_path.clone();
    let dst_full_rel = dst_full_rel.clone();
    let src_endpoint = src.endpoint_identity();
    let dst_endpoint = dst.endpoint_identity();
    let session_key = compute_session_key(
        &src_endpoint,
        src_full_path.raw_path(),
        &dst_endpoint,
        &dst_full_rel,
    );
    let current_src_ver = SourceVersion::from_entry(&task.src);
    // A destination flagged by an integrity marker holds bytes that failed verification:
    // never accept a reconciled commit for it without a fresh, verified transfer.
    let integrity_marked = journal
        .get_operation_by_key(&integrity_marker_key(&session_key))
        .await?
        .is_some_and(|m| m.state == OperationState::IntegrityFailed);

    let plan = plan_upload(task.src.size, dst_caps, cfg.chunk_size_override)?;

    // Check for an existing durable journal entry (resume or reconcile!).
    let mut active_op: Option<OperationRecord> = None;
    if let Some(existing) = journal.get_operation_by_key(&session_key).await? {
        if existing.state == OperationState::Completing
            || existing.state == OperationState::NeedsReconciliation
        {
            match dst.reconcile_operation(&existing).await? {
                ReconcileOutcome::Committed(committed_entry) => {
                    let checksum_check = verify_committed_checksum(&task.src, &committed_entry);
                    if existing.src_version == current_src_ver
                        && checksum_check.is_ok()
                        && !integrity_marked
                    {
                        info!(path = %task.dst_rel, op_id = %existing.op_id, "reconciled previously committed upload");
                        let dst_sync_bp = BackendPath::from_rel(dst_full_rel.clone());
                        let baseline = (!task.defer_op_commit
                            && should_persist_baseline(
                                cfg,
                                &task.src,
                                &committed_entry,
                                src_caps,
                                dst_caps,
                            ))
                        .then(|| {
                            make_baseline(
                                pair_key,
                                &task.dst_rel,
                                &task.src,
                                &committed_entry,
                                clock,
                            )
                        });
                        let (op_id_to_retire, source_deleted) = finish_committed_transfer(
                            cfg,
                            src,
                            dst,
                            journal,
                            task.defer_op_commit,
                            Some(existing.op_id.as_str()),
                            baseline.as_ref(),
                            task.src.size,
                            &src_full_path,
                            &dst_sync_bp,
                            &current_src_ver,
                            false,
                        )
                        .await?;
                        return Ok(TransferOutcome::Transferred {
                            bytes: 0,
                            source_deleted,
                            entry: committed_entry,
                            op_id_to_retire,
                        });
                    }
                    if let Err(err) = checksum_check
                        && existing.src_version == current_src_ver
                    {
                        // A crashed earlier run committed bytes that do not match the source:
                        // never accept them. Discard the object if that run created it and
                        // fall through to a fresh transfer.
                        warn!(path = %task.dst_rel, op_id = %existing.op_id, error = %err, "discarding reconciled commit that fails checksum verification");
                        discard_corrupt_commit(
                            dst,
                            journal,
                            clock,
                            &existing,
                            true,
                            &dst_full_rel,
                            Some(committed_entry),
                            task,
                        )
                        .await?;
                    } else {
                        // Stale op committed an older source version: retire it, update overwrite
                        // target metadata if this task assumed `Absent`, and fall through to a fresh
                        // transfer of the updated source.
                        info!(
                            path = %task.dst_rel,
                            op_id = %existing.op_id,
                            "retired stale committed operation after source changed; re-uploading updated source"
                        );
                        journal.delete_operation(&existing.op_id).await?;
                        if committed_entry.node_id.is_some() {
                            task.existing_dst_node_id = committed_entry.node_id.clone();
                        }
                        if matches!(task.precondition, DstPrecondition::Absent) {
                            task.precondition = DstPrecondition::Existing {
                                node_id: committed_entry.node_id.clone(),
                                etag: committed_entry.etag.clone(),
                                mtime_ns: committed_entry.mtime_ns,
                                size: committed_entry.size,
                            };
                        }
                    }
                }
                ReconcileOutcome::NotCommitted => {
                    if existing.src_version == current_src_ver && existing.session_token.is_some() {
                        // Resumable/multipart session has not committed yet (e.g. crashed after
                        // persisting `Completing` but before the final chunk / `finish_upload`
                        // reached the server). Preserve the live session so the protocol machine
                        // queries server progress and uploads at most the remaining chunk instead
                        // of discarding all previously completed parts.
                        active_op = Some(existing);
                    } else {
                        let _ = dst.abort_upload(&existing).await;
                        journal.delete_operation(&existing.op_id).await?;
                    }
                }
                ReconcileOutcome::Ambiguous(msg) => {
                    return Err(Error::conflict(format!(
                        "operation `{}` requires manual reconciliation: {msg}",
                        existing.op_id
                    )));
                }
            }
        } else if existing.src_version == current_src_ver
            && existing.state == OperationState::Active
        {
            // Valid resumable session — lock strictly to `existing.planned_chunk_size`!
            active_op = Some(existing);
        } else {
            // Source changed or stale Intent -> abort remote/staging session and start clean.
            let _ = dst.abort_upload(&existing).await;
            journal.delete_operation(&existing.op_id).await?;
        }
    }

    let planned_chunk_size = match (&active_op, plan) {
        (Some(op), _) => op.planned_chunk_size,
        (None, UploadPlan::SingleShot { total_size }) => total_size.max(1),
        (None, UploadPlan::Resumable { chunk_size, .. }) => chunk_size,
    };

    // WRITE-AHEAD INTENT: persist operation BEFORE the first remote side effect!
    // When dispatching directly into single-shot or native fast/server-side copy,
    // persist `Completing` directly in one write instead of writing `Intent`
    // followed microseconds later by `Completing`.
    let will_try_ssc = cfg.allow_server_side_copy
        && dst_caps.supports_server_side_copy
        && dst.can_server_side_copy_from(&src_endpoint)
        && !(dst.kind() == "local" && (bwlimit.is_some() || cfg.strict_source));
    let is_single_shot_plan = matches!(plan, UploadPlan::SingleShot { .. });
    // Atomic single-shot PUTs and small SSCs on duplicate-free backends have no
    // multi-part session state to resume or orphan on crash. Skipping the `operations`
    // WAL write + immediate delete eliminates 2 SQLite transactions per object while
    // preserving crash idempotence.
    // Destinations that defer durability always journal the operation: a leftover
    // `Completing` op is how the next run knows a file may not have reached stable storage.
    let skip_op_journal = active_op.is_none()
        && !cfg.strict_source
        && !dst_caps.allows_duplicate_names
        && !dst.defers_durable_writes()
        && ((is_single_shot_plan && dst.kind() != "local")
            || (will_try_ssc && task.src.size <= dst_caps.single_shot_max_bytes));
    let mut op_persisted = !skip_op_journal;
    let direct_completing = (will_try_ssc && active_op.is_none())
        || (is_single_shot_plan && !will_try_ssc && !cfg.strict_source);

    let mut op = match active_op {
        Some(op) => op,
        None => {
            let op_id = generate_op_id(clock, &session_key);
            let now_s = clock.now_unix_secs();
            let initial_state = if direct_completing {
                OperationState::Completing
            } else {
                OperationState::Intent
            };
            let rec = OperationRecord {
                op_id,
                session_key: session_key.clone(),
                job_id: cfg.job_id.clone(),
                src_endpoint: src_endpoint.clone(),
                dst_endpoint,
                src_raw_path: src_full_path.raw_path().to_string(),
                dst_raw_path: dst_full_rel.as_str().to_string(),
                dst_nfc_path: dst_full_rel.clone(),
                src_version: current_src_ver.clone(),
                dst_precondition: task.precondition.clone(),
                existing_dst_node_id: task.existing_dst_node_id.clone(),
                remote_op_id: None,
                backend_kind: dst.kind().to_string(),
                session_token: None,
                backend_meta: String::new(),
                planned_chunk_size,
                confirmed_offset: 0,
                state: initial_state,
                created_at: now_s,
                updated_at: now_s,
                expires_at: None,
            };
            if op_persisted {
                journal.put_operation(&rec).await?;
            }
            rec
        }
    };

    let mut init = UploadInit {
        op_id: op.op_id.clone(),
        dst_path: dst_full_rel.clone(),
        existing_node_id: op.existing_dst_node_id.clone(),
        pregenerated_id: op.remote_op_id.clone().map(crate::types::NodeId),
        total_size: task.src.size,
        src_mtime_ns: task.src.mtime_ns,
        planned_chunk_size: op.planned_chunk_size,
        checksums: task.src.checksum.clone().into_iter().collect(),
        precondition: op.dst_precondition.clone(),
        src_etag: task.src.etag.clone(),
    };

    // D5 write-ahead ID pre-generation: for backends allowing duplicate sibling names
    // (e.g. Google Drive), pre-generate the destination node ID and persist it into
    // `op.remote_op_id` BEFORE executing `server_side_copy`, `put_single_shot`, or
    // `begin_upload` so crash reconciliation looks up the exact ID with zero duplicates.
    if op.remote_op_id.is_none()
        && op.existing_dst_node_id.is_none()
        && dst_caps.allows_duplicate_names
        && op.session_token.is_none()
        && let Some(pre_id) = dst.prepare_operation_id(&init).await?
    {
        op.remote_op_id = Some(pre_id.0.clone());
        op.updated_at = clock.now_unix_secs();
        if op_persisted {
            journal.put_operation(&op).await?;
        }
        init.pregenerated_id = Some(pre_id);
    }

    let dst_sync_bp = BackendPath::from_rel(dst_full_rel.clone());

    // Zero-local-bandwidth Server-Side Copy (GDrive / S3 / etc.) and OS-native
    // kernel fast-copy (`CopyFileExW` / `copy_file_range` / `fclonefileat` on Local).
    if will_try_ssc && op.session_token.is_none() {
        if op_persisted && op.state != OperationState::Completing {
            op.state = OperationState::Completing;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(&op).await?;
        }

        let ssc_res = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::cancelled("transfer cancelled by user"));
            }
            res = dst.server_side_copy(&src_endpoint, &src_full_path, &init) => res?,
        };
        if let Some(entry) = ssc_res {
            if let Err(err) = verify_committed_checksum(&task.src, &entry) {
                discard_corrupt_commit(
                    dst,
                    journal,
                    clock,
                    &op,
                    op_persisted,
                    &dst_full_rel,
                    Some(entry),
                    task,
                )
                .await?;
                return Err(err);
            }
            if let Some((fc, lane)) = falcon {
                fc.record_bytes(lane, task.src.size);
            }
            if let Some(g) = slot_guard {
                g.add_bytes(task.src.size);
            } else if let Some(p) = progress {
                p.add_bytes_done(task.src.size);
            }
            let baseline = (!task.defer_op_commit
                && should_persist_baseline(cfg, &task.src, &entry, src_caps, dst_caps))
            .then(|| make_baseline(pair_key, &task.dst_rel, &task.src, &entry, clock));
            let (op_id_to_retire, source_deleted) = finish_committed_transfer(
                cfg,
                src,
                dst,
                journal,
                task.defer_op_commit,
                op_persisted.then_some(op.op_id.as_str()),
                baseline.as_ref(),
                task.src.size,
                &src_full_path,
                &dst_sync_bp,
                &current_src_ver,
                false,
            )
            .await?;
            if dst.kind() == "local" {
                return Ok(TransferOutcome::Transferred {
                    bytes: task.src.size,
                    source_deleted,
                    entry,
                    op_id_to_retire,
                });
            }
            return Ok(TransferOutcome::ServerSideCopied {
                bytes: task.src.size,
                source_deleted,
                entry,
                op_id_to_retire,
            });
        }
        // Fallback to streaming relay cleanly: ensure resumable/strict-source uploads are journaled.
        if !is_single_shot_plan || cfg.strict_source || dst_caps.allows_duplicate_names {
            op.state = OperationState::Intent;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(&op).await?;
            op_persisted = true;
        }
    }

    // Optional `--strict-source`: freeze source into a private quota-bounded local snapshot
    // BEFORE uploading so live writers cannot cause mid-upload `SourceMutated` loops!
    let strict_spool: Option<Arc<SpoolSeekableSource>> = if cfg.strict_source {
        if task.src.size > cfg.strict_source_max_bytes {
            return Err(Error::invalid_geometry(format!(
                "--strict-source snapshot refused for `{}`: size {} exceeds quota {}",
                task.src.nfc_path, task.src.size, cfg.strict_source_max_bytes
            )));
        }
        let spool_dir = match &cfg.strict_source_dir {
            Some(dir) => dir.clone(),
            None => match &cfg.scratch_dir {
                Some(scratch) => scratch.ensure_subdir("strict-source").await?,
                None => std::env::temp_dir().join("rship-strict-source"),
            },
        };
        let raw_stream = open_range_body(
            src,
            Some(&task.src),
            &src_full_path,
            None,
            0,
            task.src.size,
            pool,
            cancel,
            None,
            None,
            None,
            None,
        )
        .await?;
        let snap =
            SpoolSeekableSource::from_stream(raw_stream, &spool_dir, cfg.strict_source_max_bytes)
                .await?;
        if snap.total_len() != task.src.size {
            snap.cleanup_async().await;
            return Err(Error::source_mutated(format!(
                "--strict-source snapshot length mismatch for `{}` (expected {}, got {})",
                task.src.nfc_path,
                task.src.size,
                snap.total_len()
            )));
        }
        if let Err(err) = verify_source_unchanged(src, &src_full_path, &current_src_ver).await {
            snap.cleanup_async().await;
            return Err(err);
        }
        Some(snap)
    } else {
        None
    };
    let strict_snapshot: Option<Arc<dyn SeekableSource>> = strict_spool
        .as_ref()
        .map(|s| s.clone() as Arc<dyn SeekableSource>);

    let upload_outcome: Result<TransferOutcome> = async {
        // Single-shot fast path (unless resuming an already-opened resumable session).
        if is_single_shot_plan && op.session_token.is_none() {
            let (entry, verified_fresh) = run_single_shot(
                src,
                dst,
                journal,
                pool,
                clock,
                cancel,
                bwlimit,
                progress,
                slot_guard,
                strict_snapshot.as_ref(),
                falcon,
                retry_quota,
                cfg,
                src_caps,
                op_persisted,
                &task.src,
                &src_full_path,
                &mut op,
                &init,
                &current_src_ver,
            )
            .await?;

            verify_committed_checksum(&task.src, &entry)?;

            let baseline = (!task.defer_op_commit
                && should_persist_baseline(cfg, &task.src, &entry, src_caps, dst_caps))
            .then(|| make_baseline(pair_key, &task.dst_rel, &task.src, &entry, clock));
            let (op_id_to_retire, source_deleted) = finish_committed_transfer(
                cfg,
                src,
                dst,
                journal,
                task.defer_op_commit,
                op_persisted.then_some(op.op_id.as_str()),
                baseline.as_ref(),
                task.src.size,
                &src_full_path,
                &dst_sync_bp,
                &current_src_ver,
                verified_fresh,
            )
            .await?;
            return Ok(TransferOutcome::Transferred {
                bytes: task.src.size,
                source_deleted,
                entry,
                op_id_to_retire,
            });
        }

        // Ensure resumable / multipart sessions are always write-ahead journaled before beginning.
        if !op_persisted {
            op.state = OperationState::Intent;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(&op).await?;
            op_persisted = true;
        }

        // Resumable chunked / multipart path!
        let topology = match plan {
            UploadPlan::Resumable { topology, .. } => topology,
            UploadPlan::SingleShot { .. } => dst_caps.upload_topology,
        };

        let (committed_entry, verified_fresh) = match topology {
            UploadTopology::Sequential => {
                run_sequential_resumable(
                    src,
                    dst,
                    journal,
                    pool,
                    clock,
                    cancel,
                    bwlimit,
                    progress,
                    slot_guard,
                    strict_snapshot.as_ref(),
                    falcon,
                    retry_quota,
                    cfg,
                    src_caps,
                    &task.src,
                    &src_full_path,
                    &mut op,
                    &init,
                    &current_src_ver,
                )
                .await?
            }
            UploadTopology::ParallelParts => {
                run_parallel_multipart(
                    src,
                    dst,
                    journal,
                    pool,
                    clock,
                    cancel,
                    bwlimit,
                    progress,
                    slot_guard,
                    strict_snapshot.as_ref(),
                    falcon,
                    retry_quota,
                    cfg,
                    src_caps,
                    &task.src,
                    &src_full_path,
                    &mut op,
                    &init,
                    &current_src_ver,
                )
                .await?
            }
        };

        verify_committed_checksum(&task.src, &committed_entry)?;

        let baseline = (!task.defer_op_commit
            && should_persist_baseline(cfg, &task.src, &committed_entry, src_caps, dst_caps))
        .then(|| make_baseline(pair_key, &task.dst_rel, &task.src, &committed_entry, clock));
        let (op_id_to_retire, source_deleted) = finish_committed_transfer(
            cfg,
            src,
            dst,
            journal,
            task.defer_op_commit,
            op_persisted.then_some(op.op_id.as_str()),
            baseline.as_ref(),
            task.src.size,
            &src_full_path,
            &dst_sync_bp,
            &current_src_ver,
            verified_fresh,
        )
        .await?;
        Ok(TransferOutcome::Transferred {
            bytes: task.src.size,
            source_deleted,
            entry: committed_entry,
            op_id_to_retire,
        })
    }
    .await;

    drop(strict_snapshot);
    if let Some(spool) = strict_spool {
        spool.cleanup_async().await;
    }
    if let Err(err) = &upload_outcome
        && err.is_integrity()
    {
        // The upload committed (or may have committed) bytes that do not match the
        // source. Never reconcile them into success: discard the object if this attempt
        // created it and retire the journal entry so no later run accepts it either.
        discard_corrupt_commit(
            dst,
            journal,
            clock,
            &op,
            op_persisted,
            &dst_full_rel,
            None,
            task,
        )
        .await?;
    }
    upload_outcome
}

/// Discard the outcome of a transfer attempt whose committed bytes failed checksum
/// verification (or whose backend reported a checksum mismatch).
///
/// - Aborts any open resumable/multipart session.
/// - If reconcile proves the object at the destination was written by `op` AND the path
///   had no object before the transfer (`DstPrecondition::Absent`), deletes it. A
///   pre-existing destination version is never deleted.
/// - If a corrupt (or possibly corrupt) object is left in place, persists an
///   [`OperationState::IntegrityFailed`] marker so later runs re-transfer the path instead
///   of planning a skip (no baseline, no `move` source delete) until a verified transfer.
/// - Retires the journal entry so no later run reconciles the corrupt object into success.
/// - Updates `task` so a fresh attempt targets whatever now exists at the destination.
#[allow(clippy::too_many_arguments)]
async fn discard_corrupt_commit(
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    clock: &Arc<dyn Clock>,
    op: &OperationRecord,
    op_persisted: bool,
    dst_full_rel: &RelPath,
    committed: Option<Entry>,
    task: &mut TransferTask,
) -> Result<()> {
    if op.session_token.is_some() {
        let _ = dst.abort_upload(op).await;
    }
    // `Some(true)`: a corrupt object written by `op` is still in place; `Some(false)`: none
    // is (never committed, or deleted); `None`: unknown (reconcile failed).
    let mut corrupt_left: Option<bool> = Some(false);
    let committed = match committed {
        Some(entry) => Some(entry),
        None => match dst.reconcile_operation(op).await {
            Ok(ReconcileOutcome::Committed(entry)) => Some(entry),
            Ok(ReconcileOutcome::NotCommitted) => None,
            Ok(ReconcileOutcome::Ambiguous(_)) | Err(_) => {
                corrupt_left = None;
                None
            }
        },
    };
    if let Some(entry) = committed {
        let mut deleted = false;
        if matches!(op.dst_precondition, DstPrecondition::Absent) {
            let bp = BackendPath {
                raw_path: None,
                nfc_path: dst_full_rel.clone(),
                node_id: entry.node_id.clone(),
                kind: Some(crate::types::EntryKind::File),
            };
            match dst.delete(&bp).await {
                Ok(()) => deleted = true,
                Err(e) => {
                    warn!(path = %dst_full_rel, error = %e, "failed to delete corrupt destination object");
                }
            }
        }
        if deleted {
            task.existing_dst_node_id = None;
            task.precondition = DstPrecondition::Absent;
        } else {
            corrupt_left = Some(true);
            if entry.node_id.is_some() {
                task.existing_dst_node_id = entry.node_id.clone();
            }
            task.precondition = DstPrecondition::Existing {
                node_id: entry.node_id.clone(),
                etag: entry.etag.clone(),
                mtime_ns: entry.mtime_ns,
                size: entry.size,
            };
        }
    }
    if corrupt_left != Some(false) {
        // Persist the marker BEFORE retiring the op: a crash in between leaves both, and
        // either one keeps the corrupt object from being trusted.
        let marker_key = integrity_marker_key(&op.session_key);
        let now = clock.now_unix_secs();
        let marker = OperationRecord {
            op_id: format!("{marker_key}:marker"),
            session_key: marker_key,
            state: OperationState::IntegrityFailed,
            // Identity of the corrupt object left in place (`Any` when unknown), so later
            // runs can tell whether the path still holds it.
            dst_precondition: if corrupt_left == Some(true) {
                task.precondition.clone()
            } else {
                DstPrecondition::Any
            },
            session_token: None,
            remote_op_id: None,
            backend_meta: String::new(),
            confirmed_offset: 0,
            created_at: now,
            updated_at: now,
            expires_at: None,
            ..op.clone()
        };
        journal.put_operation(&marker).await?;
    }
    if op_persisted {
        journal.delete_operation(&op.op_id).await?;
    }
    Ok(())
}

/// Record a verified, committed destination file in the journal and, for `move`, delete
/// its source. Returns `(op_id_to_retire, source_deleted)`.
///
/// - `defer_op_commit` (bisync): nothing is written; the op id is handed back so the caller
///   commits it together with its dual-side baseline.
/// - `move`: the destination file is synced durably first, then the record is committed
///   with [`JournalStore::commit_verified_transfer_durable`] (not held back for a batch
///   flush), and only then is the source verified unchanged and deleted. So both the data
///   and the record are durable before the only other copy goes away.
/// - otherwise the record goes through [`JournalStore::commit_verified_transfer`], which the
///   engine's durability fence holds back until the destination's next batch flush.
#[allow(clippy::too_many_arguments)]
async fn finish_committed_transfer(
    cfg: &EngineConfig,
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    defer_op_commit: bool,
    op_id: Option<&str>,
    baseline: Option<&crate::state::BaselineRecord>,
    bytes: u64,
    src_path: &BackendPath,
    dst_path: &BackendPath,
    expected_ver: &SourceVersion,
    already_verified_fresh: bool,
) -> Result<(Option<String>, bool)> {
    let moving = cfg.delete_source_after_transfer && !cfg.dry_run;
    if moving {
        dst.sync_durable_file(dst_path).await?;
    }
    let op_id_to_retire = if defer_op_commit {
        op_id.map(str::to_string)
    } else {
        if op_id.is_some() || baseline.is_some() {
            if moving {
                journal
                    .commit_verified_transfer_durable(op_id, baseline, &cfg.job_id, bytes)
                    .await?;
            } else {
                journal
                    .commit_verified_transfer(op_id, baseline, &cfg.job_id, bytes)
                    .await?;
            }
        }
        None
    };
    if !moving {
        return Ok((op_id_to_retire, false));
    }
    if !already_verified_fresh {
        verify_source_unchanged(src, src_path, expected_ver).await?;
    }
    src.delete(src_path).await?;
    Ok((op_id_to_retire, true))
}

/// Archive an existing destination file into `cfg.backup_dir` before overwriting or deleting it.
/// Prefers zero-bandwidth server-side copy when possible, falling back seamlessly to streaming
/// single-shot / resumable / parallel multipart copy via `execute_transfer_task`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn archive_dst_file_to_backup(
    dst: &Arc<dyn StorageBackend>,
    dst_prefix: &RelPath,
    backup: &super::BackupTarget,
    dst_rel: &RelPath,
    dst_rel_raw: Option<&str>,
    dst_entry_opt: Option<&Entry>,
    dst_full_bp: &BackendPath,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    cfg: &EngineConfig,
) -> Result<()> {
    let mut src_entry = match dst_entry_opt {
        Some(e) if e.kind == crate::types::EntryKind::File => e.clone(),
        Some(_) => return Ok(()),
        None => match dst.stat(dst_full_bp).await? {
            Some(mut e) if e.kind == crate::types::EntryKind::File => {
                // `stat` returns paths relative to backend root, whereas `bcfg.src_prefix`
                // holds `dst_prefix`; reset to `dst_rel` while preserving any NFD `dst_rel_raw`
                // so `join_prefixed` addresses the exact wire key without double-prefixing.
                e.nfc_path = dst_rel.clone();
                e.raw_path = dst_rel_raw.and_then(|r| crate::types::raw_path_override(dst_rel, r));
                e
            }
            _ => return Ok(()),
        },
    };
    src_entry.nfc_path = dst_rel.clone();

    let bk_full_rel = join_prefix(&backup.prefix, dst_rel)?;
    if let Some(parent) = bk_full_rel.parent()
        && !parent.is_root()
        && backup.mark_dir_if_new(&parent)
    {
        let _ = backup.backend.mkdir(&parent).await;
    }

    let bk_caps = backup.backend.capabilities();
    let existing_bk_node_id = if bk_caps.allows_duplicate_names {
        backup
            .backend
            .stat(&BackendPath::from_rel(bk_full_rel))
            .await
            .ok()
            .flatten()
            .and_then(|e| e.node_id)
    } else {
        None
    };

    let mut bcfg = EngineConfig::new(
        format!("{}-backup", cfg.job_id),
        crate::state::JobMode::Copy,
        &cfg.dst_spec,
        "backup-dir",
    );
    bcfg.src_prefix = dst_prefix.clone();
    bcfg.dst_prefix = backup.prefix.clone();
    bcfg.delete = false;
    bcfg.delete_source_after_transfer = false;
    bcfg.baseline_mode = crate::state::BaselineMode::None;
    bcfg.allow_server_side_copy = cfg.allow_server_side_copy;
    bcfg.max_retries = cfg.max_retries;
    bcfg.base_retry_delay = cfg.base_retry_delay;
    bcfg.max_retry_delay = cfg.max_retry_delay;
    bcfg.retry_quota = cfg.retry_quota.clone();
    bcfg.retry_jitter = cfg.retry_jitter.clone();
    bcfg.part_concurrency = cfg.part_concurrency;
    bcfg.chunk_size_override = cfg.chunk_size_override;
    bcfg.scratch_dir = cfg.scratch_dir.clone();

    let dst_caps = dst.capabilities();
    let bk_pair = crate::state::compute_pair_key(
        &dst.endpoint_identity(),
        &backup.backend.endpoint_identity(),
    );
    let task = TransferTask {
        src: src_entry,
        dst_rel: dst_rel.clone(),
        existing_dst_node_id: existing_bk_node_id,
        precondition: DstPrecondition::Any,
        needs_checksum_verify: false,
        dst_existing: None,
        wire_key: None,
        replace_dst_dir: None,
        defer_op_commit: false,
    };
    let bk_sync_path = BackendPath::from_rel(join_prefix(&backup.prefix, dst_rel)?);
    let _ = Box::pin(execute_transfer_task(
        dst,
        &backup.backend,
        journal,
        pool,
        clock,
        cancel,
        bwlimit,
        None,
        None,
        None,
        &bcfg,
        &bk_pair,
        &dst_caps,
        &bk_caps,
        task,
    ))
    .await?;
    // The caller overwrites or deletes the original right after this returns, so the
    // archived copy must not be one whose data a power loss can still drop.
    if backup.backend.defers_durable_writes() {
        backup.backend.sync_durable_file(&bk_sync_path).await?;
    }
    Ok(())
}
