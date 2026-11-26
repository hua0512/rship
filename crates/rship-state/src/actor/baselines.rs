//! Per-pair `WITHOUT ROWID` `sync_baseline` shard batch writes and keyset-paginated queries.

use rship_core::path::RelPath;
use rship_core::state::BaselineRecord;
use rship_core::types::NodeId;
use rship_core::{Error, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;

use crate::schema::{decode_entry_meta, encode_entry_meta};

use super::ActorState;

pub(super) fn flush_pending_baselines_for_pair(
    state: &mut ActorState,
    pair_key: &str,
    mut rows: Vec<(usize, Box<BaselineRecord>)>,
    results: &mut [Result<()>],
) {
    if rows.is_empty() {
        return;
    }
    // Sort by `nfc_path` (stable, so later updates to the same path win) to turn
    // random B-tree page splits into sequential clustered inserts on `WITHOUT ROWID`.
    rows.sort_by(|a, b| a.1.nfc_path.as_str().cmp(b.1.nfc_path.as_str()));

    let conn = match state.open_baseline_conn(pair_key) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            for (idx, _) in rows {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            return;
        }
    };

    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(e) => {
            let msg = format!("begin baseline tx: {e}");
            for (idx, _) in rows {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            return;
        }
    };

    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO sync_baseline (
                nfc_path, flags, src_node_id, dst_node_id,
                size, src_mtime_ns, dst_mtime_ns, dst_etag, hash_blob, updated_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
            ON CONFLICT(nfc_path) DO UPDATE SET
                flags = excluded.flags,
                src_node_id = excluded.src_node_id,
                dst_node_id = excluded.dst_node_id,
                size = excluded.size,
                src_mtime_ns = excluded.src_mtime_ns,
                dst_mtime_ns = excluded.dst_mtime_ns,
                dst_etag = excluded.dst_etag,
                hash_blob = excluded.hash_blob,
                updated_at = excluded.updated_at",
        ) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("prepare upsert baseline: {e}");
                for (idx, _) in rows {
                    if results[idx].is_ok() {
                        results[idx] = Err(Error::state_store(msg.clone()));
                    }
                }
                return;
            }
        };

        for (idx, b) in &rows {
            let (flags, stored_etag, hash_blob) = encode_entry_meta(
                b.kind,
                b.dst_etag.as_deref(),
                b.hash_kind,
                b.hash_hex.as_deref(),
            );
            if let Err(e) = stmt.execute(params![
                b.nfc_path.as_str(),
                flags,
                b.src_node_id.as_ref().map(NodeId::as_str),
                b.dst_node_id.as_ref().map(NodeId::as_str),
                b.size as i64,
                b.src_mtime_ns,
                b.dst_mtime_ns,
                stored_etag,
                hash_blob.as_deref(),
                b.updated_at,
            ]) && results[*idx].is_ok()
            {
                results[*idx] = Err(Error::state_store(format!("commit baseline: {e}")));
            }
        }
    }

    if let Err(e) = tx.commit() {
        let msg = format!("commit baseline batch tx: {e}");
        for (idx, _) in rows {
            if results[idx].is_ok() {
                results[idx] = Err(Error::state_store(msg.clone()));
            }
        }
    }
}

pub(super) fn flush_pending_baseline_deletes_for_pair(
    state: &mut ActorState,
    pair_key: &str,
    mut items: Vec<(usize, RelPath)>,
    results: &mut [Result<()>],
) {
    if items.is_empty() {
        return;
    }
    let conn = match state.get_baseline_conn_existing(pair_key) {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(e) => {
            let msg = format!("{e}");
            for (idx, _) in items {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            return;
        }
    };

    // Sort by primary key (`nfc_path`) so B-tree deletions stay localized in minimal pages.
    items.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()));

    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(e) => {
            let msg = format!("begin immediate baseline delete batch tx: {e}");
            for (idx, _) in items {
                if results[idx].is_ok() {
                    results[idx] = Err(Error::state_store(msg.clone()));
                }
            }
            return;
        }
    };

    {
        let mut stmt = match tx.prepare_cached("DELETE FROM sync_baseline WHERE nfc_path = ?1") {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("prepare delete baseline: {e}");
                for (idx, _) in items {
                    if results[idx].is_ok() {
                        results[idx] = Err(Error::state_store(msg.clone()));
                    }
                }
                return;
            }
        };
        for (idx, nfc_path) in &items {
            if let Err(e) = stmt.execute([nfc_path.as_str()])
                && results[*idx].is_ok()
            {
                results[*idx] = Err(Error::state_store(format!("delete baseline: {e}")));
            }
        }
    }

    if let Err(e) = tx.commit() {
        let msg = format!("commit baseline delete batch tx: {e}");
        for (idx, _) in items {
            if results[idx].is_ok() {
                results[idx] = Err(Error::state_store(msg.clone()));
            }
        }
    }
}

fn map_baseline_row(pair_key: &str, row: &rusqlite::Row<'_>) -> rusqlite::Result<BaselineRecord> {
    let nfc_s: String = row.get(0)?;
    let flags: i64 = row.get(1)?;
    let src_node_id = row.get::<_, Option<String>>(2)?.map(NodeId);
    let dst_node_id = row.get::<_, Option<String>>(3)?.map(NodeId);
    let size = row.get::<_, i64>(4)? as u64;
    let src_mtime_ns: i64 = row.get(5)?;
    let dst_mtime_ns: i64 = row.get(6)?;
    let stored_etag: Option<String> = row.get(7)?;
    let hash_blob: Option<Vec<u8>> = row.get(8)?;
    let updated_at: i64 = row.get(9)?;

    let (kind, dst_etag, checksum) = decode_entry_meta(flags, stored_etag, hash_blob);
    let (hash_kind, hash_hex) = match checksum {
        Some(c) => (Some(c.kind), Some(c.hex)),
        None => (None, None),
    };
    Ok(BaselineRecord {
        pair_key: pair_key.to_string(),
        nfc_path: RelPath::from_normalized_unchecked(nfc_s),
        kind,
        src_node_id,
        dst_node_id,
        size,
        src_mtime_ns,
        dst_mtime_ns,
        dst_etag,
        hash_kind,
        hash_hex,
        updated_at,
    })
}

pub(super) fn query_baseline(
    conn: &Connection,
    pair_key: &str,
    nfc_path: &RelPath,
) -> Result<Option<BaselineRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT nfc_path, flags, src_node_id, dst_node_id, size,
                    src_mtime_ns, dst_mtime_ns, dst_etag, hash_blob, updated_at
             FROM sync_baseline WHERE nfc_path = ?1",
        )
        .map_err(|e| Error::state_store(format!("prepare query baseline: {e}")))?;
    stmt.query_row([nfc_path.as_str()], |row| map_baseline_row(pair_key, row))
        .optional()
        .map_err(|e| Error::state_store(format!("query baseline: {e}")))
}

pub(super) fn query_baselines_batch(
    conn: &Connection,
    pair_key: &str,
    nfc_paths: &[RelPath],
) -> Result<HashMap<RelPath, BaselineRecord>> {
    if nfc_paths.is_empty() {
        return Ok(HashMap::new());
    }
    let mut stmt = conn
        .prepare_cached(
            "SELECT nfc_path, flags, src_node_id, dst_node_id, size,
                    src_mtime_ns, dst_mtime_ns, dst_etag, hash_blob, updated_at
             FROM sync_baseline WHERE nfc_path = ?1",
        )
        .map_err(|e| Error::state_store(format!("prepare query baselines batch: {e}")))?;
    let mut out = HashMap::with_capacity(nfc_paths.len());
    for p in nfc_paths {
        if let Some(rec) = stmt
            .query_row([p.as_str()], |row| map_baseline_row(pair_key, row))
            .optional()
            .map_err(|e| Error::state_store(format!("query baseline batch row: {e}")))?
        {
            out.insert(p.clone(), rec);
        }
    }
    Ok(out)
}

pub(super) fn query_next_baseline_page(
    conn: &Connection,
    pair_key: &str,
    after_nfc_path: Option<&str>,
    limit: usize,
) -> Result<Vec<BaselineRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(limit.min(512));
    if let Some(after) = after_nfc_path {
        let mut stmt = conn
            .prepare_cached(
                "SELECT nfc_path, flags, src_node_id, dst_node_id, size,
                        src_mtime_ns, dst_mtime_ns, dst_etag, hash_blob, updated_at
                 FROM sync_baseline
                 WHERE nfc_path > ?1
                 ORDER BY nfc_path ASC
                 LIMIT ?2",
            )
            .map_err(|e| Error::state_store(format!("prepare next baseline page: {e}")))?;
        let rows = stmt
            .query_map(params![after, limit as i64], |row| {
                map_baseline_row(pair_key, row)
            })
            .map_err(|e| Error::state_store(format!("query next baseline page: {e}")))?;
        for r in rows {
            out.push(r.map_err(|e| Error::state_store(format!("read baseline page row: {e}")))?);
        }
    } else {
        let mut stmt = conn
            .prepare_cached(
                "SELECT nfc_path, flags, src_node_id, dst_node_id, size,
                        src_mtime_ns, dst_mtime_ns, dst_etag, hash_blob, updated_at
                 FROM sync_baseline
                 ORDER BY nfc_path ASC
                 LIMIT ?1",
            )
            .map_err(|e| Error::state_store(format!("prepare first baseline page: {e}")))?;
        let rows = stmt
            .query_map(params![limit as i64], |row| map_baseline_row(pair_key, row))
            .map_err(|e| Error::state_store(format!("query first baseline page: {e}")))?;
        for r in rows {
            out.push(r.map_err(|e| Error::state_store(format!("read baseline page row: {e}")))?);
        }
    }
    Ok(out)
}
