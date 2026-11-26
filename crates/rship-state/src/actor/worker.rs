//! Background SQLite actor loop, group-commit batching, and `journal.db` queries/writes.

use rship_core::backend::CompletedPart;
use rship_core::path::RelPath;
use rship_core::state::{
    BaselineRecord, BisyncPairState, DstPrecondition, JobMode, JobRecord, JobStatus,
    OperationRecord, OperationState, SourceVersion,
};
use rship_core::types::NodeId;
use rship_core::{Error, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, mpsc as std_mpsc};
use tokio::sync::oneshot;

use super::baselines::{
    flush_pending_baseline_deletes_for_pair, flush_pending_baselines_for_pair, query_baseline,
    query_baselines_batch, query_next_baseline_page,
};
use super::delta::{
    apply_inventory_write, query_all_gdrive_nodes, query_change_token, query_gdrive_children,
    query_gdrive_children_by_name, query_gdrive_node, query_gdrive_nodes_batch,
};
use super::{ActiveOpIndex, ActorState, Cmd, MAX_GROUP_COMMIT_BATCH, OpIndexDelta, WriteCmd};

enum JournalWrite {
    UpsertJob(Box<JobRecord>),
    PutOperation(Box<OperationRecord>),
    DeleteOperation(String),
    UpsertPart(String, CompletedPart),
    UpsertBisyncState(Box<BisyncPairState>),
}

pub(super) fn actor_loop(
    mut state: ActorState,
    rx: std_mpsc::Receiver<Cmd>,
    active_ops: Arc<RwLock<ActiveOpIndex>>,
) {
    let mut pending_cmd: Option<Cmd> = None;

    loop {
        let first = match pending_cmd.take() {
            Some(c) => c,
            None => match rx.recv() {
                Ok(c) => c,
                Err(_) => break,
            },
        };

        match first {
            Cmd::Write(w, reply) => {
                let mut batch = Vec::with_capacity(16);
                batch.push((w, reply));
                while batch.len() < MAX_GROUP_COMMIT_BATCH {
                    match rx.try_recv() {
                        Ok(Cmd::Write(w2, r2)) => batch.push((w2, r2)),
                        Ok(other) => {
                            pending_cmd = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                execute_write_batch(&mut state, batch, &active_ops);
            }
            Cmd::GetJob(id, reply) => {
                let _ = reply.send(query_job(&state.journal, &id));
            }
            Cmd::ListJobs(limit, reply) => {
                let _ = reply.send(query_jobs(&state.journal, limit));
            }
            Cmd::GetOpByKey(key, reply) => {
                let _ = reply.send(query_op_by_key(&state.journal, &key));
            }
            Cmd::ListActiveOps(reply) => {
                let _ = reply.send(query_active_ops(&state.journal));
            }
            Cmd::ListParts(op_id, reply) => {
                let _ = reply.send(query_parts(&state.journal, &op_id));
            }
            Cmd::GetBaseline(pair_key, nfc_path, reply) => {
                let res = match state.get_baseline_conn_existing(&pair_key) {
                    Ok(Some(conn)) => query_baseline(conn, &pair_key, &nfc_path),
                    Ok(None) => Ok(None),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::GetBaselinesBatch(pair_key, paths, reply) => {
                let res = match state.get_baseline_conn_existing(&pair_key) {
                    Ok(Some(conn)) => query_baselines_batch(conn, &pair_key, &paths),
                    Ok(None) => Ok(HashMap::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::NextBaselinePage(pair_key, after_nfc, limit, reply) => {
                let res = match state.get_baseline_conn_existing(&pair_key) {
                    Ok(Some(conn)) => {
                        query_next_baseline_page(conn, &pair_key, after_nfc.as_deref(), limit)
                    }
                    Ok(None) => Ok(Vec::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::GetBisyncState(pair_key, reply) => {
                let _ = reply.send(query_bisync_state(&state.journal, &pair_key));
            }
            Cmd::GetChangeToken(scope, reply) => {
                let res =
                    match state.get_inventory_conn_existing(&scope.remote_name, &scope.corpus_id) {
                        Ok(Some(conn)) => query_change_token(conn, &scope),
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    };
                let _ = reply.send(res);
            }
            Cmd::GetGdriveNode(remote, corpus, file_id, reply) => {
                let res = match state.get_inventory_conn_existing(&remote, &corpus) {
                    Ok(Some(conn)) => query_gdrive_node(conn, &remote, &corpus, &file_id),
                    Ok(None) => Ok(None),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::GetGdriveNodesBatch(remote, corpus, file_ids, reply) => {
                let res = match state.get_inventory_conn_existing(&remote, &corpus) {
                    Ok(Some(conn)) => query_gdrive_nodes_batch(conn, &remote, &corpus, &file_ids),
                    Ok(None) => Ok(HashMap::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::ListGdriveChildren(remote, corpus, parent_id, reply) => {
                let res = match state.get_inventory_conn_existing(&remote, &corpus) {
                    Ok(Some(conn)) => query_gdrive_children(conn, &remote, &corpus, &parent_id),
                    Ok(None) => Ok(Vec::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::FindGdriveChildrenByName(remote, corpus, parent_id, name, reply) => {
                let res = match state.get_inventory_conn_existing(&remote, &corpus) {
                    Ok(Some(conn)) => {
                        query_gdrive_children_by_name(conn, &remote, &corpus, &parent_id, &name)
                    }
                    Ok(None) => Ok(Vec::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::ListAllGdriveNodes(remote, corpus, reply) => {
                let res = match state.get_inventory_conn_existing(&remote, &corpus) {
                    Ok(Some(conn)) => query_all_gdrive_nodes(conn, &remote, &corpus),
                    Ok(None) => Ok(Vec::new()),
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Cmd::Flush(reply) => {
                let _ = reply.send(state.checkpoint_all());
            }
            #[cfg(test)]
            Cmd::JournalSynchronousMode(reply) => {
                let res = state
                    .journal
                    .query_row("PRAGMA synchronous;", [], |r| r.get::<_, i64>(0))
                    .map_err(|e| Error::state_store(format!("read journal synchronous: {e}")));
                let _ = reply.send(res);
            }
            Cmd::Shutdown(reply) => {
                let _ = reply.send(state.checkpoint_all());
                return;
            }
        }
    }

    let _ = state.checkpoint_all();
}

fn execute_write_batch(
    state: &mut ActorState,
    batch: Vec<(Box<WriteCmd>, oneshot::Sender<Result<()>>)>,
    active_ops: &RwLock<ActiveOpIndex>,
) {
    let n = batch.len();
    let mut replies = Vec::with_capacity(n);
    let mut results: Vec<Result<()>> = (0..n).map(|_| Ok(())).collect();

    let mut pending_baselines: HashMap<String, Vec<(usize, Box<BaselineRecord>)>> = HashMap::new();
    let mut pending_baseline_deletes: HashMap<String, Vec<(usize, RelPath)>> = HashMap::new();
    let mut journal_writes: Vec<(usize, JournalWrite)> = Vec::new();
    let mut job_deltas: HashMap<String, (i64, i64, i64)> = HashMap::new();
    let mut job_delta_indices: Vec<usize> = Vec::new();
    let mut inventory_cmds: Vec<(usize, WriteCmd)> = Vec::new();

    for (idx, (cmd, reply)) in batch.into_iter().enumerate() {
        replies.push(reply);
        match *cmd {
            WriteCmd::UpsertJob(j) => journal_writes.push((idx, JournalWrite::UpsertJob(j))),
            WriteCmd::PutOperation(op) => {
                journal_writes.push((idx, JournalWrite::PutOperation(op)))
            }
            WriteCmd::DeleteOperation(op_id) => {
                journal_writes.push((idx, JournalWrite::DeleteOperation(op_id)))
            }
            WriteCmd::UpsertPart(op_id, part) => {
                journal_writes.push((idx, JournalWrite::UpsertPart(op_id, part)))
            }
            WriteCmd::CommitVerifiedTransfer {
                op_id,
                baseline,
                job_id,
                bytes_transferred,
            } => {
                let ts = baseline.as_ref().map(|b| b.updated_at).unwrap_or(0);
                if let Some(b) = baseline {
                    if let Some(dels) = pending_baseline_deletes.remove(&b.pair_key) {
                        flush_pending_baseline_deletes_for_pair(
                            state,
                            &b.pair_key,
                            dels,
                            &mut results,
                        );
                    }
                    pending_baselines
                        .entry(b.pair_key.clone())
                        .or_default()
                        .push((idx, b));
                }
                if let Some(id) = op_id {
                    journal_writes.push((idx, JournalWrite::DeleteOperation(id)));
                }
                let entry = job_deltas.entry(job_id).or_insert((0, 0, ts));
                entry.0 += 1;
                entry.1 = entry.1.saturating_add(bytes_transferred as i64);
                entry.2 = entry.2.max(ts);
                job_delta_indices.push(idx);
            }
            WriteCmd::DeleteBaseline(pair_key, nfc_path) => {
                if let Some(rows) = pending_baselines.remove(&pair_key) {
                    flush_pending_baselines_for_pair(state, &pair_key, rows, &mut results);
                }
                pending_baseline_deletes
                    .entry(pair_key)
                    .or_default()
                    .push((idx, nfc_path));
            }
            WriteCmd::DeleteBaselinesBatch(pair_key, nfc_paths) => {
                if let Some(rows) = pending_baselines.remove(&pair_key) {
                    flush_pending_baselines_for_pair(state, &pair_key, rows, &mut results);
                }
                let entry = pending_baseline_deletes.entry(pair_key).or_default();
                entry.reserve(nfc_paths.len());
                for p in nfc_paths {
                    entry.push((idx, p));
                }
            }
            WriteCmd::DeletePairBaselines(pair_key) => {
                pending_baselines.remove(&pair_key);
                pending_baseline_deletes.remove(&pair_key);
                if let Err(e) = state.delete_baseline_shard(&pair_key) {
                    results[idx] = Err(e);
                }
            }
            WriteCmd::UpsertBisyncState(bs) => {
                journal_writes.push((idx, JournalWrite::UpsertBisyncState(bs)));
            }
            inv @ (WriteCmd::ApplyGdriveChangeBatch(_, _) | WriteCmd::ClearGdriveInventory(_)) => {
                inventory_cmds.push((idx, inv));
            }
        }
    }

    // 1. Flush baseline shard upserts & deletes FIRST (sorted by PK) before retiring operations in `journal.db`.
    for (pair_key, rows) in pending_baselines {
        flush_pending_baselines_for_pair(state, &pair_key, rows, &mut results);
    }
    for (pair_key, dels) in pending_baseline_deletes {
        flush_pending_baseline_deletes_for_pair(state, &pair_key, dels, &mut results);
    }

    // 2. Commit `journal.db` mutations + aggregated `jobs` counters in ONE transaction.
    if !journal_writes.is_empty() || !job_deltas.is_empty() {
        apply_journal_batch(
            &mut state.journal,
            journal_writes,
            job_deltas,
            &job_delta_indices,
            active_ops,
            &mut results,
        );
    }

    // 3. Apply any delta inventory mutations to their per-scope shard DBs.
    for (idx, cmd) in inventory_cmds {
        if let Err(e) = apply_inventory_write(state, cmd) {
            results[idx] = Err(e);
        }
    }

    for (res, reply) in results.into_iter().zip(replies) {
        let _ = reply.send(res);
    }
}

fn mark_batch_indices_failed(
    results: &mut [Result<()>],
    touched_indices: &[usize],
    job_delta_indices: &[usize],
    msg: &str,
) {
    for &idx in touched_indices {
        if results[idx].is_ok() {
            results[idx] = Err(Error::state_store(msg.to_string()));
        }
    }
    for &idx in job_delta_indices {
        if results[idx].is_ok() {
            results[idx] = Err(Error::state_store(msg.to_string()));
        }
    }
}

fn apply_journal_batch(
    conn: &mut Connection,
    writes: Vec<(usize, JournalWrite)>,
    job_deltas: HashMap<String, (i64, i64, i64)>,
    job_delta_indices: &[usize],
    active_ops: &RwLock<ActiveOpIndex>,
    results: &mut [Result<()>],
) {
    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(e) => {
            let msg = format!("begin immediate journal tx: {e}");
            for (idx, _) in writes {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            for &idx in job_delta_indices {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            return;
        }
    };

    let mut op_deltas = Vec::new();
    let mut touched_indices = Vec::with_capacity(writes.len());
    for (idx, w) in writes {
        touched_indices.push(idx);
        if results[idx].is_err() {
            continue;
        }
        let maybe_delta = match &w {
            JournalWrite::PutOperation(op) => {
                Some(OpIndexDelta::Put(op.op_id.clone(), op.session_key.clone()))
            }
            JournalWrite::DeleteOperation(op_id) => Some(OpIndexDelta::Remove(op_id.clone())),
            _ => None,
        };
        let res = apply_journal_write(&tx, w);
        match res {
            Ok(()) => {
                if let Some(d) = maybe_delta {
                    op_deltas.push(d);
                }
            }
            Err(e) => results[idx] = Err(e),
        }
    }

    if !job_deltas.is_empty() {
        match tx.prepare_cached(
            "UPDATE jobs SET files_done = files_done + ?1, bytes_done = bytes_done + ?2, updated_at = MAX(updated_at, ?3) WHERE job_id = ?4",
        ) {
            Ok(mut stmt) => {
                for (job_id, (files_delta, bytes_delta, updated_at)) in job_deltas {
                    if let Err(e) = stmt.execute(params![files_delta, bytes_delta, updated_at, job_id]) {
                        let msg = format!("update batch job counters: {e}");
                        // Returning early drops `tx` and rolls back the entire transaction,
                        // so every index touched by this batch MUST be reported as failed.
                        mark_batch_indices_failed(
                            results,
                            &touched_indices,
                            job_delta_indices,
                            &msg,
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                let msg = format!("prepare batch job counters: {e}");
                // Returning early drops `tx` and rolls back the entire transaction,
                // so every index touched by this batch MUST be reported as failed.
                mark_batch_indices_failed(results, &touched_indices, job_delta_indices, &msg);
                return;
            }
        }
    }

    match tx.commit() {
        Ok(()) => {
            if !op_deltas.is_empty()
                && let Ok(mut idx_map) = active_ops.write()
            {
                for delta in op_deltas {
                    match delta {
                        OpIndexDelta::Put(op_id, key) => idx_map.insert(op_id, key),
                        OpIndexDelta::Remove(op_id) => idx_map.remove(&op_id),
                    }
                }
            }
        }
        Err(e) => {
            let msg = format!("commit journal batch tx: {e}");
            mark_batch_indices_failed(results, &touched_indices, job_delta_indices, &msg);
        }
    }
}

fn apply_journal_write(tx: &rusqlite::Transaction<'_>, cmd: JournalWrite) -> Result<()> {
    match cmd {
        JournalWrite::UpsertJob(j) => {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO jobs (job_id, mode, src_spec, dst_spec, status, files_total, files_done, bytes_total, bytes_done, created_at, updated_at, options_json, resume_cursor)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                     ON CONFLICT(job_id) DO UPDATE SET
                       status = excluded.status,
                       files_total = excluded.files_total,
                       files_done = excluded.files_done,
                       bytes_total = excluded.bytes_total,
                       bytes_done = excluded.bytes_done,
                       updated_at = excluded.updated_at,
                       options_json = COALESCE(excluded.options_json, jobs.options_json),
                       resume_cursor = excluded.resume_cursor",
                )
                .map_err(|e| Error::state_store(format!("prepare upsert job: {e}")))?;
            stmt.execute(params![
                j.job_id,
                j.mode.as_str(),
                j.src_spec,
                j.dst_spec,
                j.status.as_str(),
                j.files_total as i64,
                j.files_done as i64,
                j.bytes_total as i64,
                j.bytes_done as i64,
                j.created_at,
                j.updated_at,
                j.options_json.as_deref(),
                j.resume_cursor.as_deref(),
            ])
            .map_err(|e| Error::state_store(format!("upsert job: {e}")))?;
            Ok(())
        }
        JournalWrite::PutOperation(op) => {
            let src_ver = serde_json::to_string(&op.src_version)
                .map_err(|e| Error::state_store(format!("encode src_version: {e}")))?;
            let dst_pre = serde_json::to_string(&op.dst_precondition)
                .map_err(|e| Error::state_store(format!("encode dst_precondition: {e}")))?;
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO operations (
                        op_id, session_key, job_id, src_endpoint, dst_endpoint,
                        src_raw_path, dst_raw_path, dst_nfc_path,
                        src_version_json, dst_precondition_json,
                        existing_dst_node_id, remote_op_id, backend_kind,
                        session_token, backend_meta, planned_chunk_size,
                        confirmed_offset, state, created_at, updated_at, expires_at
                    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
                    ON CONFLICT(op_id) DO UPDATE SET
                        remote_op_id = excluded.remote_op_id,
                        session_token = excluded.session_token,
                        backend_meta = excluded.backend_meta,
                        confirmed_offset = excluded.confirmed_offset,
                        state = excluded.state,
                        updated_at = excluded.updated_at,
                        expires_at = excluded.expires_at",
                )
                .map_err(|e| Error::state_store(format!("prepare put operation: {e}")))?;
            stmt.execute(params![
                op.op_id,
                op.session_key,
                op.job_id,
                op.src_endpoint,
                op.dst_endpoint,
                op.src_raw_path,
                op.dst_raw_path,
                op.dst_nfc_path.as_str(),
                src_ver,
                dst_pre,
                op.existing_dst_node_id.as_ref().map(NodeId::as_str),
                op.remote_op_id.as_deref(),
                op.backend_kind,
                op.session_token.as_deref(),
                op.backend_meta,
                op.planned_chunk_size as i64,
                op.confirmed_offset as i64,
                op.state.as_str(),
                op.created_at,
                op.updated_at,
                op.expires_at,
            ])
            .map_err(|e| Error::state_store(format!("put operation: {e}")))?;
            if op.session_token.is_none() && op.state == OperationState::Intent {
                let mut del_stmt = tx
                    .prepare_cached("DELETE FROM operation_parts WHERE op_id = ?1")
                    .map_err(|e| {
                        Error::state_store(format!("prepare clear stale operation parts: {e}"))
                    })?;
                del_stmt
                    .execute([&op.op_id])
                    .map_err(|e| Error::state_store(format!("clear stale operation parts: {e}")))?;
            }
            Ok(())
        }
        JournalWrite::DeleteOperation(op_id) => {
            let mut stmt = tx
                .prepare_cached("DELETE FROM operations WHERE op_id = ?1")
                .map_err(|e| Error::state_store(format!("prepare delete operation: {e}")))?;
            stmt.execute([op_id])
                .map_err(|e| Error::state_store(format!("delete operation: {e}")))?;
            Ok(())
        }
        JournalWrite::UpsertPart(op_id, part) => {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO operation_parts (op_id, part_number, offset, length, etag, checksum)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(op_id, part_number) DO UPDATE SET
                       offset = excluded.offset,
                       length = excluded.length,
                       etag = excluded.etag,
                       checksum = excluded.checksum",
                )
                .map_err(|e| Error::state_store(format!("prepare upsert part: {e}")))?;
            stmt.execute(params![
                op_id,
                i64::from(part.part_number),
                part.offset as i64,
                part.length as i64,
                part.etag,
                part.checksum.as_deref(),
            ])
            .map_err(|e| Error::state_store(format!("upsert part: {e}")))?;
            Ok(())
        }
        JournalWrite::UpsertBisyncState(bs) => {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO bisync_state (pair_key, filter_hash, last_a_files, last_b_files, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(pair_key) DO UPDATE SET
                       filter_hash = excluded.filter_hash,
                       last_a_files = excluded.last_a_files,
                       last_b_files = excluded.last_b_files,
                       updated_at = excluded.updated_at",
                )
                .map_err(|e| Error::state_store(format!("prepare upsert bisync_state: {e}")))?;
            stmt.execute(params![
                bs.pair_key,
                bs.filter_hash,
                bs.last_a_files as i64,
                bs.last_b_files as i64,
                bs.updated_at,
            ])
            .map_err(|e| Error::state_store(format!("upsert bisync_state: {e}")))?;
            Ok(())
        }
    }
}

fn map_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    let mode_s: String = row.get(1)?;
    let status_s: String = row.get(4)?;
    Ok(JobRecord {
        job_id: row.get(0)?,
        mode: JobMode::parse(&mode_s).unwrap_or(JobMode::Copy),
        src_spec: row.get(2)?,
        dst_spec: row.get(3)?,
        status: JobStatus::parse(&status_s).unwrap_or(JobStatus::Failed),
        files_total: row.get::<_, i64>(5)? as u64,
        files_done: row.get::<_, i64>(6)? as u64,
        bytes_total: row.get::<_, i64>(7)? as u64,
        bytes_done: row.get::<_, i64>(8)? as u64,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        options_json: row.get(11)?,
        resume_cursor: row.get(12)?,
    })
}

fn query_job(conn: &Connection, job_id: &str) -> Result<Option<JobRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT job_id, mode, src_spec, dst_spec, status, files_total, files_done, bytes_total, bytes_done, created_at, updated_at, options_json, resume_cursor
             FROM jobs WHERE job_id = ?1",
        )
        .map_err(|e| Error::state_store(format!("prepare get job: {e}")))?;
    stmt.query_row([job_id], map_job)
        .optional()
        .map_err(|e| Error::state_store(format!("get job: {e}")))
}

fn query_bisync_state(conn: &Connection, pair_key: &str) -> Result<Option<BisyncPairState>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT pair_key, filter_hash, last_a_files, last_b_files, updated_at
             FROM bisync_state WHERE pair_key = ?1",
        )
        .map_err(|e| Error::state_store(format!("prepare get bisync_state: {e}")))?;
    stmt.query_row([pair_key], |row| {
        Ok(BisyncPairState {
            pair_key: row.get(0)?,
            filter_hash: row.get(1)?,
            last_a_files: row.get::<_, i64>(2)?.max(0) as u64,
            last_b_files: row.get::<_, i64>(3)?.max(0) as u64,
            updated_at: row.get(4)?,
        })
    })
    .optional()
    .map_err(|e| Error::state_store(format!("get bisync_state: {e}")))
}

fn query_jobs(conn: &Connection, limit: usize) -> Result<Vec<JobRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT job_id, mode, src_spec, dst_spec, status, files_total, files_done, bytes_total, bytes_done, created_at, updated_at, options_json, resume_cursor
             FROM jobs ORDER BY updated_at DESC, created_at DESC, rowid DESC LIMIT ?1",
        )
        .map_err(|e| Error::state_store(format!("prepare list jobs: {e}")))?;
    let rows = stmt
        .query_map([limit as i64], map_job)
        .map_err(|e| Error::state_store(format!("query jobs: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read job row: {e}")))?);
    }
    Ok(out)
}

fn map_op(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRecord> {
    let nfc_s: String = row.get(7)?;
    let src_ver_s: String = row.get(8)?;
    let dst_pre_s: String = row.get(9)?;
    let state_s: String = row.get(17)?;
    let src_version: SourceVersion = serde_json::from_str(&src_ver_s)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let dst_precondition: DstPrecondition = serde_json::from_str(&dst_pre_s)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let dst_nfc_path = RelPath::from_normalized_unchecked(nfc_s);
    Ok(OperationRecord {
        op_id: row.get(0)?,
        session_key: row.get(1)?,
        job_id: row.get(2)?,
        src_endpoint: row.get(3)?,
        dst_endpoint: row.get(4)?,
        src_raw_path: row.get(5)?,
        dst_raw_path: row.get(6)?,
        dst_nfc_path,
        src_version,
        dst_precondition,
        existing_dst_node_id: row.get::<_, Option<String>>(10)?.map(NodeId),
        remote_op_id: row.get(11)?,
        backend_kind: row.get(12)?,
        session_token: row.get(13)?,
        backend_meta: row.get(14)?,
        planned_chunk_size: row.get::<_, i64>(15)? as u64,
        confirmed_offset: row.get::<_, i64>(16)? as u64,
        state: OperationState::parse(&state_s).unwrap_or(OperationState::NeedsReconciliation),
        created_at: row.get(18)?,
        updated_at: row.get(19)?,
        expires_at: row.get(20)?,
    })
}

fn query_op_by_key(conn: &Connection, session_key: &str) -> Result<Option<OperationRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT op_id, session_key, job_id, src_endpoint, dst_endpoint,
                    src_raw_path, dst_raw_path, dst_nfc_path,
                    src_version_json, dst_precondition_json,
                    existing_dst_node_id, remote_op_id, backend_kind,
                    session_token, backend_meta, planned_chunk_size,
                    confirmed_offset, state, created_at, updated_at, expires_at
             FROM operations WHERE session_key = ?1 ORDER BY updated_at DESC LIMIT 1",
        )
        .map_err(|e| Error::state_store(format!("prepare get op by key: {e}")))?;
    stmt.query_row([session_key], map_op)
        .optional()
        .map_err(|e| Error::state_store(format!("get op by key: {e}")))
}

fn query_active_ops(conn: &Connection) -> Result<Vec<OperationRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT op_id, session_key, job_id, src_endpoint, dst_endpoint,
                    src_raw_path, dst_raw_path, dst_nfc_path,
                    src_version_json, dst_precondition_json,
                    existing_dst_node_id, remote_op_id, backend_kind,
                    session_token, backend_meta, planned_chunk_size,
                    confirmed_offset, state, created_at, updated_at, expires_at
             FROM operations ORDER BY updated_at DESC",
        )
        .map_err(|e| Error::state_store(format!("prepare list ops: {e}")))?;
    let rows = stmt
        .query_map([], map_op)
        .map_err(|e| Error::state_store(format!("query ops: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read op row: {e}")))?);
    }
    Ok(out)
}

fn query_parts(conn: &Connection, op_id: &str) -> Result<Vec<CompletedPart>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT part_number, offset, length, etag, checksum
             FROM operation_parts WHERE op_id = ?1 ORDER BY part_number ASC",
        )
        .map_err(|e| Error::state_store(format!("prepare list parts: {e}")))?;
    let rows = stmt
        .query_map([op_id], |row| {
            Ok(CompletedPart {
                part_number: row.get::<_, i64>(0)? as u32,
                offset: row.get::<_, i64>(1)? as u64,
                length: row.get::<_, i64>(2)? as u64,
                etag: row.get(3)?,
                checksum: row.get(4)?,
            })
        })
        .map_err(|e| Error::state_store(format!("query parts: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read part row: {e}")))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::StorageMode;
    use crate::schema::configure_journal_db;
    use rship_core::ErrorKind;
    use std::collections::HashSet;

    fn make_test_op(op_id: &str, session_key: &str, job_id: &str) -> OperationRecord {
        OperationRecord {
            op_id: op_id.into(),
            session_key: session_key.into(),
            job_id: job_id.into(),
            src_endpoint: "local://a".into(),
            dst_endpoint: "local://b".into(),
            src_raw_path: "file.bin".into(),
            dst_raw_path: "file.bin".into(),
            dst_nfc_path: RelPath::parse("file.bin").unwrap(),
            src_version: SourceVersion {
                node_id: None,
                size: 100,
                mtime_ns: 10,
                ctime_ns: None,
                etag: None,
            },
            dst_precondition: DstPrecondition::Absent,
            existing_dst_node_id: None,
            remote_op_id: None,
            backend_kind: "local".into(),
            session_token: Some("tok".into()),
            backend_meta: "{}".into(),
            planned_chunk_size: 64,
            confirmed_offset: 0,
            state: OperationState::Active,
            created_at: 1,
            updated_at: 1,
            expires_at: None,
        }
    }

    #[test]
    fn d6_failed_job_counter_update_fails_every_touched_write_and_rolls_back() {
        let conn = Connection::open_in_memory().unwrap();
        configure_journal_db(&conn).unwrap();

        // Seed a job row so `UPDATE jobs ... WHERE job_id = 'j1'` matches and fires our trigger.
        conn.execute(
            "INSERT INTO jobs (job_id, mode, src_spec, dst_spec, status, created_at, updated_at)
             VALUES ('j1', 'copy', 'a', 'b', 'running', 1, 1)",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_jobs_counter_update
             BEFORE UPDATE ON jobs
             BEGIN
                 SELECT RAISE(ABORT, 'injected job counter update failure');
             END;",
        )
        .unwrap();

        let mut state = ActorState {
            storage: StorageMode::Memory,
            journal: conn,
            baselines: HashMap::new(),
            inventories: HashMap::new(),
            known_baseline_pairs: Arc::new(RwLock::new(HashSet::new())),
            tick: 0,
        };
        let active_ops = RwLock::new(ActiveOpIndex::default());

        let (tx_op, mut rx_op) = oneshot::channel();
        let (tx_bisync, mut rx_bisync) = oneshot::channel();
        let (tx_commit, mut rx_commit) = oneshot::channel();

        let batch = vec![
            (
                Box::new(WriteCmd::PutOperation(Box::new(make_test_op(
                    "op-rollback",
                    "skey-rollback",
                    "j1",
                )))),
                tx_op,
            ),
            (
                Box::new(WriteCmd::UpsertBisyncState(Box::new(BisyncPairState {
                    pair_key: "pair-rollback".into(),
                    filter_hash: "h".into(),
                    last_a_files: 1,
                    last_b_files: 1,
                    updated_at: 5,
                }))),
                tx_bisync,
            ),
            (
                Box::new(WriteCmd::CommitVerifiedTransfer {
                    op_id: None,
                    baseline: None,
                    job_id: "j1".into(),
                    bytes_transferred: 100,
                }),
                tx_commit,
            ),
        ];

        execute_write_batch(&mut state, batch, &active_ops);

        let op_res = rx_op.try_recv().unwrap();
        let bisync_res = rx_bisync.try_recv().unwrap();
        let commit_res = rx_commit.try_recv().unwrap();

        assert!(
            commit_res.is_err(),
            "CommitVerifiedTransfer must fail when UPDATE jobs fails"
        );
        assert_eq!(commit_res.unwrap_err().kind(), ErrorKind::StateStore);
        assert!(
            op_res.is_err(),
            "PutOperation in the same rolled-back batch MUST return Err, not Ok"
        );
        assert_eq!(op_res.unwrap_err().kind(), ErrorKind::StateStore);
        assert!(
            bisync_res.is_err(),
            "UpsertBisyncState in the same rolled-back batch MUST return Err, not Ok"
        );
        assert_eq!(bisync_res.unwrap_err().kind(), ErrorKind::StateStore);

        // Verify the transaction was rolled back in SQLite and `active_ops` was NOT mutated.
        assert!(
            query_op_by_key(&state.journal, "skey-rollback")
                .unwrap()
                .is_none()
        );
        assert!(
            query_bisync_state(&state.journal, "pair-rollback")
                .unwrap()
                .is_none()
        );
        assert!(
            !active_ops.read().unwrap().contains_key("skey-rollback"),
            "active_ops must not contain a rolled-back operation"
        );
    }

    #[test]
    fn d6_failed_job_counter_prepare_fails_every_touched_write_and_rolls_back() {
        let conn = Connection::open_in_memory().unwrap();
        configure_journal_db(&conn).unwrap();
        // Drop `jobs` so `prepare_cached("UPDATE jobs ...")` fails after `PutOperation` runs.
        conn.execute_batch("DROP TABLE jobs;").unwrap();

        let mut state = ActorState {
            storage: StorageMode::Memory,
            journal: conn,
            baselines: HashMap::new(),
            inventories: HashMap::new(),
            known_baseline_pairs: Arc::new(RwLock::new(HashSet::new())),
            tick: 0,
        };
        let active_ops = RwLock::new(ActiveOpIndex::default());

        let (tx_op, mut rx_op) = oneshot::channel();
        let (tx_commit, mut rx_commit) = oneshot::channel();
        let batch = vec![
            (
                Box::new(WriteCmd::PutOperation(Box::new(make_test_op(
                    "op-prep-fail",
                    "skey-prep-fail",
                    "j1",
                )))),
                tx_op,
            ),
            (
                Box::new(WriteCmd::CommitVerifiedTransfer {
                    op_id: None,
                    baseline: None,
                    job_id: "j1".into(),
                    bytes_transferred: 50,
                }),
                tx_commit,
            ),
        ];

        execute_write_batch(&mut state, batch, &active_ops);

        let op_res = rx_op.try_recv().unwrap();
        let commit_res = rx_commit.try_recv().unwrap();
        assert!(commit_res.is_err());
        assert!(
            op_res.is_err(),
            "PutOperation in a batch where prepare_cached(UPDATE jobs) fails MUST return Err"
        );
        assert!(
            query_op_by_key(&state.journal, "skey-prep-fail")
                .unwrap()
                .is_none()
        );
        assert!(!active_ops.read().unwrap().contains_key("skey-prep-fail"));
    }
}
