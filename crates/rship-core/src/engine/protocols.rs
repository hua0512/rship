//! Single-shot, sequential resumable, and parallel multipart upload state machines.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

use crate::adaptive::{FalconController, TransferLane};
use crate::backend::{
    BackendPath, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend, UploadInit,
    UploadProgress,
};
use crate::bandwidth::BandwidthLimiter;
use crate::buffer::BufferPool;
use crate::chunking::part_byte_range;
use crate::clock::Clock;
use crate::error::{Error, ErrorKind, Result, RetryClass};
use crate::progress::{ActiveTransferGuard, TransferProgress};
use crate::source::{DataSource, SeekableSource, bounded_range_stream};
use crate::state::{JournalStore, OperationRecord, OperationState, SourceVersion};
use crate::types::{ByteRange, Capabilities, Entry};

use super::verify::{PartCrcs, SequentialVerifier, new_failure_slot, take_failure};
use super::{
    CancelFlag, EngineConfig, MAX_NO_PROGRESS_LOOPS, RetryQuota, backoff_sleep, is_retryable,
    verify_source_unchanged,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_single_shot(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    strict_snapshot: Option<&Arc<dyn SeekableSource>>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
    retry_quota: &Arc<dyn RetryQuota>,
    cfg: &EngineConfig,
    src_caps: &Capabilities,
    persist_op: bool,
    src_entry: &Entry,
    src_path: &BackendPath,
    op: &mut OperationRecord,
    init: &UploadInit,
    expected_src: &SourceVersion,
) -> Result<(Entry, bool)> {
    let atomic_single = src_caps.supports_atomic_single_read;
    let version_pinned = src_caps.supports_version_pinned_read && src_entry.etag.is_some();
    let skip_pre_read_first = atomic_single
        || version_pinned
        || matches!(init.precondition, crate::state::DstPrecondition::Absent);
    let mut attempt = 0u32;
    let mut last_retry_was_timeout = false;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::cancelled("transfer cancelled by user"));
        }
        // On attempt 0, skip the redundant pre-read `stat` when creating a new file (`Absent`),
        // when the source returns an atomic single-GET snapshot (S3/Swift/GCS/Azure/GDrive/
        // OneDrive/Dropbox), or when reads are ETag-pinned (`If-Match`).
        if strict_snapshot.is_none() && (attempt > 0 || !skip_pre_read_first) {
            verify_source_unchanged(src, src_path, expected_src).await?;
        }

        // Record `Completing` intent BEFORE issuing single-shot write when journaling is active.
        if persist_op && (op.state != OperationState::Completing || attempt > 0) {
            op.state = OperationState::Completing;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(op).await?;
        }

        let stream = open_range_body(
            src,
            Some(src_entry),
            src_path,
            strict_snapshot,
            0,
            init.total_size,
            pool,
            cancel,
            bwlimit,
            progress,
            slot_guard,
            falcon,
        )
        .await?;
        let put_res = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::cancelled("transfer cancelled by user"));
            }
            res = dst.put_single_shot(init, stream) => res,
        };
        match put_res {
            Ok(entry) => {
                retry_quota.record_success(attempt > 0, last_retry_was_timeout);
                // Post-read freshness verification: skip when reading a frozen `--strict-source`
                // snapshot OR when the single-GET source read is an atomic snapshot (or ETag-
                // pinned). For `move` (`delete_source_after_transfer`), returning
                // `verified_fresh = false` ensures `finish_committed_transfer` still runs
                // `verify_source_unchanged` right before `src.delete()`.
                let verified_fresh =
                    if strict_snapshot.is_none() && !(atomic_single || version_pinned) {
                        verify_source_unchanged(src, src_path, expected_src).await?;
                        true
                    } else {
                        false
                    };
                return Ok((entry, verified_fresh));
            }
            // `RetryClass::Integrity` (checksum mismatch) is deliberately NOT retryable here:
            // the object may be committed with wrong bytes, and reconcile only matches op id
            // and size. The caller discards the attempt and restarts from scratch.
            Err(e) if is_retryable(&e) && attempt < cfg.max_retries => {
                if e.retry == RetryClass::Throttled
                    && let Some((fc, lane)) = falcon
                {
                    fc.record_throttle(lane);
                }
                // Check if write actually committed before retrying!
                if let Ok(ReconcileOutcome::Committed(entry)) = dst.reconcile_operation(op).await {
                    retry_quota.record_success(attempt > 0, last_retry_was_timeout);
                    return Ok((entry, false));
                }
                let is_timeout = e.kind == ErrorKind::Timeout;
                if !retry_quota.try_acquire(is_timeout) {
                    return Err(e);
                }
                last_retry_was_timeout = is_timeout;
                attempt += 1;
                backoff_sleep(
                    &e,
                    attempt,
                    cfg.base_retry_delay,
                    cfg.max_retry_delay,
                    &cfg.jitter(),
                    clock,
                    cancel,
                )
                .await?;
            }
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_sequential_resumable(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    strict_snapshot: Option<&Arc<dyn SeekableSource>>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
    retry_quota: &Arc<dyn RetryQuota>,
    cfg: &EngineConfig,
    src_caps: &Capabilities,
    src_entry: &Entry,
    src_path: &BackendPath,
    op: &mut OperationRecord,
    init: &UploadInit,
    expected_src: &SourceVersion,
) -> Result<(Entry, bool)> {
    let version_pinned = src_caps.supports_version_pinned_read && src_entry.etag.is_some();
    let skip_freshness =
        strict_snapshot.is_some() || (version_pinned && !cfg.delete_source_after_transfer);
    let mut session_restarts = 0u32;

    'session: loop {
        if cancel.is_cancelled() {
            return Err(Error::cancelled("transfer cancelled by user"));
        }

        // Open session if needed, or query existing session progress.
        let mut offset = if op.session_token.is_none() {
            let opened = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(Error::cancelled("transfer cancelled by user"));
                }
                res = dst.begin_upload(init) => res?,
            };
            op.session_token = Some(opened.session_token);
            op.backend_meta = opened.backend_meta;
            op.remote_op_id = opened.remote_op_id;
            op.expires_at = opened.expires_at_unix_secs;
            op.confirmed_offset = 0;
            op.state = OperationState::Active;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(op).await?;
            0u64
        } else {
            let progress_res = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(Error::cancelled("transfer cancelled by user"));
                }
                res = dst.query_upload(op) => res?,
            };
            match progress_res {
                UploadProgress::AlreadyCompleted(entry) => return Ok((entry, false)),
                UploadProgress::SequentialOffset(off) => {
                    if off > init.total_size {
                        return Err(Error::protocol(format!(
                            "server reported offset {off} > total_size {}",
                            init.total_size
                        )));
                    }
                    op.confirmed_offset = off;
                    if off < init.total_size {
                        op.state = OperationState::Active;
                    }
                    op.updated_at = clock.now_unix_secs();
                    journal.put_operation(op).await?;
                    off
                }
                UploadProgress::Expired => {
                    if let ReconcileOutcome::Committed(entry) = dst.reconcile_operation(op).await? {
                        return Ok((entry, false));
                    }
                    session_restarts += 1;
                    if session_restarts > cfg.max_retries {
                        return Err(Error::session_expired(
                            "resumable session expired repeatedly",
                        ));
                    }
                    op.session_token = None;
                    op.confirmed_offset = 0;
                    op.state = OperationState::Intent;
                    journal.put_operation(op).await?;
                    continue 'session;
                }
                UploadProgress::CompletedParts(_) => {
                    return Err(Error::protocol(
                        "sequential backend returned CompletedParts progress",
                    ));
                }
            }
        };

        let mut no_progress_count = 0u32;
        let mut attempt = 0u32;
        let mut last_retry_was_timeout = false;
        // Whole-object verification of the ranged chunk reads (see `engine::verify`).
        let verifier = if strict_snapshot.is_none() && offset == 0 {
            SequentialVerifier::for_entry(src_entry, init.total_size)
        } else {
            None
        };
        let verify_failure = new_failure_slot();

        // Reuse `RemoteRangeReadable` handles (e.g. cloud-to-cloud or `crypt` sources) across
        // sequential chunks to avoid repeating remote `stat`/header RPCs per chunk, while
        // re-opening `LocalSeekable` paths per 256 MiB chunk (~3 µs) to detect live path swaps.
        let shared_remote = if strict_snapshot.is_none()
            && offset < init.total_size
            && src.capabilities().supports_range_read
            && src.kind() != "local"
            && src.kind() != "chaos"
        {
            match src.open_read_entry(src_entry, src_path, None).await {
                Ok(DataSource::RemoteRangeReadable(r)) => Some(r),
                _ => None,
            }
        } else {
            None
        };

        while offset < init.total_size {
            if cancel.is_cancelled() {
                return Err(Error::cancelled("transfer cancelled by user"));
            }

            let remaining = init.total_size - offset;
            let len = remaining.min(op.planned_chunk_size);
            let is_final = offset + len == init.total_size;
            let part_number = (offset / op.planned_chunk_size) as u32 + 1;

            // Pre-final-commit source freshness re-check + `Completing` intent!
            if is_final {
                if !skip_freshness {
                    verify_source_unchanged(src, src_path, expected_src)
                        .await
                        .inspect_err(|_| {
                            debug!(path = %op.dst_nfc_path, "source mutated before final chunk; aborting session");
                        })?;
                }
                op.state = OperationState::Completing;
                op.updated_at = clock.now_unix_secs();
                journal.put_operation(op).await?;
            }

            let body = if let Some(ref remote) = shared_remote {
                let mut s = remote.open_range(ByteRange { offset, len }).await?;
                if let Some(lim) = bwlimit {
                    s = lim.wrap_stream(s, cancel.clone());
                }
                if let Some(guard) = slot_guard {
                    s = guard.track_stream(s);
                } else if let Some(prog) = progress {
                    s = prog.track_stream(s);
                }
                if let Some((fc, lane)) = falcon {
                    s = fc.track_stream(lane, s);
                }
                s
            } else {
                open_range_body(
                    src,
                    Some(src_entry),
                    src_path,
                    strict_snapshot,
                    offset,
                    len,
                    pool,
                    cancel,
                    bwlimit,
                    progress,
                    slot_guard,
                    falcon,
                )
                .await?
            };
            let body = match &verifier {
                Some(v) => v.wrap(offset, len, body, verify_failure.clone()),
                None => body,
            };
            let chunk = ChunkUpload {
                part_number,
                offset,
                len,
                total_size: init.total_size,
                body,
            };

            let chunk_res = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(Error::cancelled("transfer cancelled by user"));
                }
                res = dst.upload_chunk(op, chunk) => res,
            };
            if let Some(e) = take_failure(&verify_failure) {
                return Err(e);
            }
            match chunk_res {
                Ok(ack) => {
                    retry_quota.record_success(attempt > 0, last_retry_was_timeout);
                    attempt = 0;
                    last_retry_was_timeout = false;
                    if let Some(entry) = ack.completed {
                        // Final check that source didn't mutate during the final chunk read!
                        let verified_fresh = if !skip_freshness {
                            verify_source_unchanged(src, src_path, expected_src).await?;
                            true
                        } else {
                            false
                        };
                        return Ok((entry, verified_fresh));
                    }
                    let next = ack.next_offset.unwrap_or(offset + len);
                    if next <= offset {
                        no_progress_count += 1;
                        if no_progress_count >= MAX_NO_PROGRESS_LOOPS {
                            return Err(Error::protocol(format!(
                                "no upload progress after {no_progress_count} consecutive chunks at offset {offset}"
                            )));
                        }
                    } else {
                        no_progress_count = 0;
                    }
                    offset = next;
                    op.confirmed_offset = offset;
                    op.updated_at = clock.now_unix_secs();
                    journal.put_operation(op).await?;
                }
                Err(e) if e.retry == RetryClass::SourceMutated => {
                    let _ = dst.abort_upload(op).await;
                    journal.delete_operation(&op.op_id).await?;
                    return Err(e);
                }
                Err(e) if e.retry == RetryClass::SessionExpired => {
                    if let ReconcileOutcome::Committed(entry) = dst.reconcile_operation(op).await? {
                        return Ok((entry, false));
                    }
                    session_restarts += 1;
                    if session_restarts > cfg.max_retries {
                        return Err(e);
                    }
                    op.session_token = None;
                    op.confirmed_offset = 0;
                    op.state = OperationState::Intent;
                    journal.put_operation(op).await?;
                    continue 'session;
                }
                Err(e) if is_retryable(&e) && attempt < cfg.max_retries => {
                    if e.retry == RetryClass::Throttled
                        && let Some((fc, lane)) = falcon
                    {
                        fc.record_throttle(lane);
                    }
                    let is_timeout = e.kind == ErrorKind::Timeout;
                    if !retry_quota.try_acquire(is_timeout) {
                        return Err(e);
                    }
                    last_retry_was_timeout = is_timeout;
                    attempt += 1;
                    backoff_sleep(
                        &e,
                        attempt,
                        cfg.base_retry_delay,
                        cfg.max_retry_delay,
                        &cfg.jitter(),
                        clock,
                        cancel,
                    )
                    .await?;
                    // Query exact server offset before re-issuing chunk (GDrive `308` rule!).
                    match dst.query_upload(op).await {
                        Ok(UploadProgress::AlreadyCompleted(entry)) => {
                            retry_quota.record_success(true, last_retry_was_timeout);
                            return Ok((entry, false));
                        }
                        Ok(UploadProgress::SequentialOffset(server_off)) => {
                            if server_off > init.total_size {
                                return Err(Error::protocol("server offset exceeds file size"));
                            }
                            offset = server_off;
                            op.confirmed_offset = server_off;
                            op.state = OperationState::Active;
                            op.updated_at = clock.now_unix_secs();
                            journal.put_operation(op).await?;
                        }
                        Ok(UploadProgress::Expired) => {
                            if let ReconcileOutcome::Committed(entry) =
                                dst.reconcile_operation(op).await?
                            {
                                retry_quota.record_success(true, last_retry_was_timeout);
                                return Ok((entry, false));
                            }
                            session_restarts += 1;
                            if session_restarts > cfg.max_retries {
                                return Err(Error::session_expired(
                                    "session expired during recovery",
                                ));
                            }
                            op.session_token = None;
                            op.confirmed_offset = 0;
                            op.state = OperationState::Intent;
                            journal.put_operation(op).await?;
                            continue 'session;
                        }
                        Ok(UploadProgress::CompletedParts(_)) => {
                            return Err(Error::protocol("unexpected CompletedParts response"));
                        }
                        Err(_) => {
                            // Keep current offset and let retry loop try again.
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }

        // All bytes uploaded; verify source unchanged before calling `finish_upload`.
        let verified_fresh = if !skip_freshness {
            if let Err(e) = verify_source_unchanged(src, src_path, expected_src).await {
                let _ = dst.abort_upload(op).await;
                journal.delete_operation(&op.op_id).await?;
                return Err(e);
            }
            true
        } else {
            false
        };
        op.state = OperationState::Completing;
        op.updated_at = clock.now_unix_secs();
        journal.put_operation(op).await?;
        let entry = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::cancelled("transfer cancelled by user"));
            }
            res = dst.finish_upload(op, &[]) => res?,
        };
        return Ok((entry, verified_fresh));
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_parallel_multipart(
    src: &Arc<dyn StorageBackend>,
    dst: &Arc<dyn StorageBackend>,
    journal: &Arc<dyn JournalStore>,
    pool: &BufferPool,
    clock: &Arc<dyn Clock>,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    strict_snapshot: Option<&Arc<dyn SeekableSource>>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
    retry_quota: &Arc<dyn RetryQuota>,
    cfg: &EngineConfig,
    src_caps: &Capabilities,
    src_entry: &Entry,
    src_path: &BackendPath,
    op: &mut OperationRecord,
    init: &UploadInit,
    expected_src: &SourceVersion,
) -> Result<(Entry, bool)> {
    let version_pinned = src_caps.supports_version_pinned_read && src_entry.etag.is_some();
    let skip_freshness =
        strict_snapshot.is_some() || (version_pinned && !cfg.delete_source_after_transfer);
    let chunk_size = op.planned_chunk_size;
    let total_parts = init.total_size.div_ceil(chunk_size) as u32;

    let mut session_restarts = 0u32;
    'session: loop {
        if cancel.is_cancelled() {
            return Err(Error::cancelled("transfer cancelled by user"));
        }

        let mut verified_parts: HashMap<u32, CompletedPart> = HashMap::new();

        if op.session_token.is_none() {
            let opened = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(Error::cancelled("transfer cancelled by user"));
                }
                res = dst.begin_upload(init) => res?,
            };
            op.session_token = Some(opened.session_token);
            op.backend_meta = opened.backend_meta;
            op.remote_op_id = opened.remote_op_id;
            op.expires_at = opened.expires_at_unix_secs;
            op.state = OperationState::Active;
            op.updated_at = clock.now_unix_secs();
            journal.put_operation(op).await?;
        } else {
            // Reconcile local durable manifest against server `ListParts`!
            let local_parts: HashMap<u32, CompletedPart> = journal
                .list_parts(&op.op_id)
                .await?
                .into_iter()
                .map(|p| (p.part_number, p))
                .collect();

            let progress_res = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(Error::cancelled("transfer cancelled by user"));
                }
                res = dst.query_upload(op) => res?,
            };
            match progress_res {
                UploadProgress::AlreadyCompleted(entry) => return Ok((entry, false)),
                UploadProgress::CompletedParts(server_parts) => {
                    for sp in server_parts {
                        let Ok((_, expected_len)) =
                            part_byte_range(init.total_size, chunk_size, sp.part_number)
                        else {
                            // Server has geometry incompatible with locked `chunk_size` -> restart!
                            let _ = dst.abort_upload(op).await;
                            op.session_token = None;
                            op.state = OperationState::Intent;
                            journal.put_operation(op).await?;
                            continue 'session;
                        };
                        // Only trust a server part if its size matches expected geometry AND
                        // our local durable manifest proves we uploaded that exact ETag from this source version.
                        if sp.length == expected_len
                            && local_parts
                                .get(&sp.part_number)
                                .is_some_and(|lp| lp.etag == sp.etag && lp.length == expected_len)
                        {
                            verified_parts.insert(sp.part_number, sp);
                        }
                    }
                }
                UploadProgress::Expired => {
                    if let ReconcileOutcome::Committed(entry) = dst.reconcile_operation(op).await? {
                        return Ok((entry, false));
                    }
                    session_restarts += 1;
                    if session_restarts > cfg.max_retries {
                        return Err(Error::session_expired(
                            "multipart session expired repeatedly",
                        ));
                    }
                    op.session_token = None;
                    op.state = OperationState::Intent;
                    journal.put_operation(op).await?;
                    continue 'session;
                }
                UploadProgress::SequentialOffset(_) => {
                    return Err(Error::protocol(
                        "parallel backend returned SequentialOffset",
                    ));
                }
            }
        }

        // Upload missing parts with bounded `part_concurrency` and fail-fast cancellation.
        let missing: Vec<u32> = (1..=total_parts)
            .filter(|pn| !verified_parts.contains_key(pn))
            .collect();
        // Whole-object CRC-32C over per-part CRCs, only when this process streams every part.
        let part_crcs = if strict_snapshot.is_none() && verified_parts.is_empty() {
            PartCrcs::for_entry(src_entry)
        } else {
            None
        };

        // Open the source handle ONCE before fanning out parallel parts:
        // - Remote range-readable sources avoid repeating `stat` or encrypted header fetches.
        // - Local seekable sources share ONE `LocalSeekableFile` across all parts (zero per-part open/stat).
        let (shared_remote, shared_local) = if strict_snapshot.is_none()
            && !missing.is_empty()
            && src.capabilities().supports_range_read
        {
            match src.open_read_entry(src_entry, src_path, None).await {
                Ok(DataSource::RemoteRangeReadable(r)) => (Some(r), None),
                Ok(DataSource::LocalSeekable(s)) => (None, Some(s)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        let is_local_dst = dst.kind() == "local"
            || (dst.kind() == "crypt" && dst.endpoint_identity().contains("inner=local://"));
        let is_local_crypt_pair = is_local_dst
            && (dst.kind() == "crypt"
                || (src.kind() == "crypt" && src.endpoint_identity().contains("inner=local://")));
        let max_conc = if !is_local_dst
            && cfg.part_concurrency == 4
            && total_parts >= 6
            && pool.available_bytes() >= 8 * 1024 * 1024
        {
            // High-BDP cloud object stores (S3/R2/GCS/Azure) benefit from 8 parallel
            // parts to saturate 1-10 Gbps links on large single files.
            8usize.min(total_parts as usize)
        } else if is_local_crypt_pair && cfg.part_concurrency == 4 {
            // Local NVMe + STREAM OAE2 encrypt/decrypt saturates >1 GiB/s at 2 parallel
            // parts while halving off-pool AEAD pipeline & writer memory (explicit user
            // `--part-concurrency` overrides are still honored).
            2usize.min(total_parts as usize)
        } else {
            cfg.part_concurrency.max(1)
        };
        let completed_map = Arc::new(Mutex::new(verified_parts));
        let op_snapshot = op.clone();
        let mut join_set: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();
        let mut first_err: Option<Error> = None;

        // When Falcon is active, dynamically bound multipart part concurrency to Falcon's live
        // lane concurrency (divided across active files in the lane, floored at 1 so an already-
        // admitted file can never deadlock even when `current_c == 1`).
        let effective_max_conc = || -> usize {
            match falcon {
                Some((fc, lane)) => {
                    let c = fc.concurrency(lane);
                    let active_files = fc.in_flight(lane).max(1);
                    (c / active_files).min(max_conc).max(1)
                }
                None => max_conc,
            }
        };

        for pn in missing {
            while join_set.len() >= effective_max_conc() {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        first_err = Some(Error::cancelled("transfer cancelled by user"));
                        join_set.abort_all();
                        break;
                    }
                    maybe_res = join_set.join_next() => {
                        if let Some(res) = maybe_res {
                            match res {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    first_err = Some(e);
                                    join_set.abort_all();
                                    break;
                                }
                                Err(e) => {
                                    first_err = Some(Error::protocol(format!("part task panicked: {e}")));
                                    join_set.abort_all();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if first_err.is_some() {
                break;
            }
            if cancel.is_cancelled() {
                first_err = Some(Error::cancelled("transfer cancelled by user"));
                join_set.abort_all();
                break;
            }
            let src = src.clone();
            let dst = dst.clone();
            let journal = journal.clone();
            let pool = pool.clone();
            let clock = clock.clone();
            let cancel = cancel.clone();
            let bw_c = bwlimit.cloned();
            let prog_c = progress.cloned();
            let slot_counter_c = slot_guard.map(ActiveTransferGuard::slot_counter);
            let snap_c = strict_snapshot.cloned().or_else(|| shared_local.clone());
            let remote_c = shared_remote.clone();
            let falcon_c = falcon.map(|(fc, lane)| (fc.clone(), lane));
            let retry_quota_c = retry_quota.clone();
            let part_crcs_c = part_crcs.clone();
            let src_entry_c = src_entry.clone();
            let src_path = src_path.clone();
            let op_c = op_snapshot.clone();
            let completed_map = completed_map.clone();
            let max_retries = cfg.max_retries;
            let base_delay = cfg.base_retry_delay;
            let max_retry_delay = cfg.max_retry_delay;
            let jitter = cfg.jitter();
            let total_size = init.total_size;

            join_set.spawn(async move {
                let (offset, len) = part_byte_range(total_size, chunk_size, pn)?;
                let mut attempt = 0u32;
                let mut last_retry_was_timeout = false;
                loop {
                    if cancel.is_cancelled() {
                        return Err(Error::cancelled("cancelled"));
                    }
                    let mut body = if let Some(ref remote) = remote_c {
                        let mut s = remote.open_range(ByteRange { offset, len }).await?;
                        if let Some(ref lim) = bw_c {
                            s = lim.wrap_stream(s, cancel.clone());
                        }
                        s
                    } else {
                        open_range_body(
                            &src,
                            Some(&src_entry_c),
                            &src_path,
                            snap_c.as_ref(),
                            offset,
                            len,
                            &pool,
                            &cancel,
                            bw_c.as_ref(),
                            None,
                            None,
                            None,
                        )
                        .await?
                    };
                    if let Some(ref pc) = part_crcs_c {
                        body = pc.wrap(pn, len, body);
                    }
                    if let Some(ref prog) = prog_c {
                        body = match &slot_counter_c {
                            Some(ctr) => prog.track_stream_with_slot(body, ctr.clone()),
                            None => prog.track_stream(body),
                        };
                    }
                    if let Some((ref fc, lane)) = falcon_c {
                        body = fc.track_stream(lane, body);
                    }
                    let chunk = ChunkUpload {
                        part_number: pn,
                        offset,
                        len,
                        total_size,
                        body,
                    };
                    let chunk_res = tokio::select! {
                        biased;
                        () = cancel.cancelled() => {
                            return Err(Error::cancelled("transfer cancelled by user"));
                        }
                        res = dst.upload_chunk(&op_c, chunk) => res,
                    };
                    match chunk_res {
                        Ok(ack) => {
                            retry_quota_c.record_success(attempt > 0, last_retry_was_timeout);
                            let etag = ack.etag.ok_or_else(|| {
                                Error::protocol(format!("missing ETag for part {pn}"))
                            })?;
                            let cp = CompletedPart {
                                part_number: pn,
                                offset,
                                length: len,
                                etag,
                                checksum: ack.checksum,
                            };
                            journal.upsert_part(&op_c.op_id, &cp).await?;
                            completed_map.lock().await.insert(pn, cp);
                            return Ok(());
                        }
                        Err(e) if is_retryable(&e) && attempt < max_retries => {
                            if e.retry == RetryClass::Throttled
                                && let Some((ref fc, lane)) = falcon_c
                            {
                                fc.record_throttle(lane);
                            }
                            let is_timeout = e.kind == ErrorKind::Timeout;
                            if !retry_quota_c.try_acquire(is_timeout) {
                                return Err(e);
                            }
                            last_retry_was_timeout = is_timeout;
                            attempt += 1;
                            backoff_sleep(
                                &e,
                                attempt,
                                base_delay,
                                max_retry_delay,
                                &jitter,
                                &clock,
                                &cancel,
                            )
                            .await?;
                        }
                        Err(e) => return Err(e),
                    }
                }
            });
        }

        while !join_set.is_empty() {
            if first_err.is_some() {
                let _ = join_set.join_next().await;
                continue;
            }
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    first_err = Some(Error::cancelled("transfer cancelled by user"));
                    join_set.abort_all();
                }
                maybe_res = join_set.join_next() => {
                    let Some(res) = maybe_res else { break };
                    match res {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            first_err = Some(e);
                            join_set.abort_all();
                        }
                        Err(e) => {
                            if !e.is_cancelled() {
                                first_err = Some(Error::protocol(format!("part task panicked: {e}")));
                                join_set.abort_all();
                            }
                        }
                    }
                }
            }
        }
        if let Some(e) = first_err {
            if e.retry == RetryClass::SessionExpired && session_restarts < cfg.max_retries {
                session_restarts += 1;
                op.session_token = None;
                op.state = OperationState::Intent;
                journal.put_operation(op).await?;
                continue 'session;
            }
            if e.retry == RetryClass::SourceMutated {
                let _ = dst.abort_upload(op).await;
                journal.delete_operation(&op.op_id).await?;
            }
            return Err(e);
        }

        // Pre-commit whole-object check of the ranged part reads (integrity errors make the
        // caller abort this session and restart the transfer from scratch).
        if let Some(pc) = &part_crcs {
            pc.verify(total_parts)?;
        }

        // Pre-commit source freshness re-check!
        let verified_fresh = if !skip_freshness {
            if let Err(e) = verify_source_unchanged(src, src_path, expected_src).await {
                let _ = dst.abort_upload(op).await;
                journal.delete_operation(&op.op_id).await?;
                return Err(e);
            }
            true
        } else {
            false
        };

        let mut parts: Vec<CompletedPart> = completed_map.lock().await.values().cloned().collect();
        parts.sort_by_key(|p| p.part_number);

        op.state = OperationState::Completing;
        op.updated_at = clock.now_unix_secs();
        journal.put_operation(op).await?;

        let finish_res = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::cancelled("transfer cancelled by user"));
            }
            res = dst.finish_upload(op, &parts) => res,
        };
        match finish_res {
            Ok(entry) => return Ok((entry, verified_fresh)),
            Err(e) if e.retry == RetryClass::SessionExpired => {
                if let ReconcileOutcome::Committed(entry) = dst.reconcile_operation(op).await? {
                    return Ok((entry, false));
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open_range_body(
    src: &Arc<dyn StorageBackend>,
    src_entry: Option<&Entry>,
    src_path: &BackendPath,
    strict_snapshot: Option<&Arc<dyn SeekableSource>>,
    offset: u64,
    len: u64,
    pool: &BufferPool,
    cancel: &CancelFlag,
    bwlimit: Option<&Arc<BandwidthLimiter>>,
    progress: Option<&Arc<TransferProgress>>,
    slot_guard: Option<&ActiveTransferGuard>,
    falcon: Option<(&Arc<FalconController>, TransferLane)>,
) -> Result<crate::source::ByteStream> {
    if len == 0 {
        return Ok(Box::pin(futures::stream::empty()));
    }
    let range = ByteRange { offset, len };
    let mut stream = if let Some(snap) = strict_snapshot {
        bounded_range_stream(snap.clone(), offset, len, pool.clone())
    } else {
        let ds = match src_entry {
            Some(entry) => src.open_read_entry(entry, src_path, Some(range)).await?,
            None => src.open_read(src_path, Some(range)).await?,
        };
        match ds {
            DataSource::LocalSeekable(seekable) => {
                bounded_range_stream(seekable, offset, len, pool.clone())
            }
            DataSource::RemoteRangeReadable(remote) => remote.open_range(range).await?,
            DataSource::SequentialStream { stream, .. } => stream,
        }
    };
    if let Some(lim) = bwlimit {
        stream = lim.wrap_stream(stream, cancel.clone());
    }
    if let Some(guard) = slot_guard {
        stream = guard.track_stream(stream);
    } else if let Some(prog) = progress {
        stream = prog.track_stream(stream);
    }
    if let Some((fc, lane)) = falcon {
        stream = fc.track_stream(lane, stream);
    }
    Ok(stream)
}
