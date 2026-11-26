//! Per-scope delta inventory shard writes (including recursive CTE subtree eviction) and queries.

use rship_core::state::{DeltaNodeRecord, DeltaScope};
use rship_core::types::EntryKind;
use rship_core::{Error, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;

use super::{ActorState, WriteCmd};

pub(super) fn apply_inventory_write(state: &mut ActorState, cmd: WriteCmd) -> Result<()> {
    match cmd {
        WriteCmd::ApplyGdriveChangeBatch(scope, batch) => {
            let conn = state.open_inventory_conn(&scope.remote_name, &scope.corpus_id)?;
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| Error::state_store(format!("begin inventory tx: {e}")))?;
            for root_id in &batch.evict_subtree_root_ids {
                tx.execute(
                    "WITH RECURSIVE sub(fid) AS (
                        VALUES (?3)
                        UNION
                        SELECT n.file_id FROM gdrive_nodes n
                        JOIN sub s ON n.parent_id = s.fid
                        WHERE n.remote_name = ?1 AND n.corpus_id = ?2
                    )
                    DELETE FROM gdrive_nodes
                    WHERE remote_name = ?1 AND corpus_id = ?2 AND file_id IN (SELECT fid FROM sub)",
                    params![scope.remote_name, scope.corpus_id, root_id],
                )
                .map_err(|e| {
                    Error::state_store(format!("evict gdrive subtree `{root_id}`: {e}"))
                })?;
            }
            for fid in &batch.remove_file_ids {
                tx.execute(
                    "DELETE FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2 AND file_id = ?3",
                    params![scope.remote_name, scope.corpus_id, fid],
                )
                .map_err(|e| Error::state_store(format!("delete gdrive node `{fid}`: {e}")))?;
            }
            if !batch.upserts.is_empty() {
                let mut stmt = tx
                    .prepare_cached(
                        "INSERT INTO gdrive_nodes (
                            remote_name, corpus_id, file_id, parent_id, raw_name, nfc_name,
                            kind, size, mtime_ns, md5, trashed, generation, updated_at
                        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                        ON CONFLICT(remote_name, corpus_id, file_id) DO UPDATE SET
                            parent_id = excluded.parent_id,
                            raw_name = excluded.raw_name,
                            nfc_name = excluded.nfc_name,
                            kind = excluded.kind,
                            size = excluded.size,
                            mtime_ns = excluded.mtime_ns,
                            md5 = excluded.md5,
                            trashed = excluded.trashed,
                            generation = excluded.generation,
                            updated_at = excluded.updated_at",
                    )
                    .map_err(|e| Error::state_store(format!("prepare upsert gdrive node: {e}")))?;
                for n in &batch.upserts {
                    stmt.execute(params![
                        scope.remote_name,
                        scope.corpus_id,
                        n.file_id,
                        n.parent_id.as_deref(),
                        n.raw_name,
                        n.nfc_name,
                        n.kind.as_str(),
                        n.size as i64,
                        n.mtime_ns,
                        n.md5.as_deref(),
                        if n.trashed { 1i64 } else { 0i64 },
                        n.generation,
                        n.updated_at,
                    ])
                    .map_err(|e| Error::state_store(format!("upsert gdrive node: {e}")))?;
                }
            }
            if let Some(tok) = &batch.new_start_page_token {
                tx.execute(
                    "INSERT INTO change_tokens (remote_name, principal, corpus_id, root_id, token, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(remote_name, principal, corpus_id, root_id) DO UPDATE SET
                       token = excluded.token,
                       updated_at = excluded.updated_at",
                    params![
                        scope.remote_name,
                        scope.principal,
                        scope.corpus_id,
                        scope.root_id,
                        tok,
                        batch.updated_at,
                    ],
                )
                .map_err(|e| Error::state_store(format!("upsert change token: {e}")))?;
            }
            tx.commit()
                .map_err(|e| Error::state_store(format!("commit inventory tx: {e}")))?;
            Ok(())
        }
        WriteCmd::ClearGdriveInventory(scope) => {
            if let Some(conn) =
                state.get_inventory_conn_existing(&scope.remote_name, &scope.corpus_id)?
            {
                let tx = conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| Error::state_store(format!("begin clear inventory tx: {e}")))?;
                tx.execute(
                    "DELETE FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2",
                    params![scope.remote_name, scope.corpus_id],
                )
                .map_err(|e| Error::state_store(format!("clear gdrive nodes: {e}")))?;
                tx.execute(
                    "DELETE FROM change_tokens
                     WHERE remote_name = ?1 AND principal = ?2 AND corpus_id = ?3 AND root_id = ?4",
                    params![
                        scope.remote_name,
                        scope.principal,
                        scope.corpus_id,
                        scope.root_id
                    ],
                )
                .map_err(|e| Error::state_store(format!("clear change token: {e}")))?;
                tx.commit()
                    .map_err(|e| Error::state_store(format!("commit clear inventory tx: {e}")))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn map_gdrive_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeltaNodeRecord> {
    let kind_s: String = row.get(4)?;
    Ok(DeltaNodeRecord {
        file_id: row.get(0)?,
        parent_id: row.get(1)?,
        raw_name: row.get(2)?,
        nfc_name: row.get(3)?,
        kind: EntryKind::parse(&kind_s).unwrap_or(EntryKind::File),
        size: row.get::<_, i64>(5)? as u64,
        mtime_ns: row.get(6)?,
        md5: row.get(7)?,
        trashed: row.get::<_, i64>(8)? != 0,
        generation: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

pub(super) fn query_change_token(conn: &Connection, scope: &DeltaScope) -> Result<Option<String>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT token FROM change_tokens
             WHERE remote_name = ?1 AND principal = ?2 AND corpus_id = ?3 AND root_id = ?4",
        )
        .map_err(|e| Error::state_store(format!("prepare get change token: {e}")))?;
    stmt.query_row(
        params![
            scope.remote_name,
            scope.principal,
            scope.corpus_id,
            scope.root_id
        ],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| Error::state_store(format!("get change token: {e}")))
}

pub(super) fn query_gdrive_node(
    conn: &Connection,
    remote_name: &str,
    corpus_id: &str,
    file_id: &str,
) -> Result<Option<DeltaNodeRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT file_id, parent_id, raw_name, nfc_name, kind, size, mtime_ns, md5, trashed, generation, updated_at
             FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2 AND file_id = ?3",
        )
        .map_err(|e| Error::state_store(format!("prepare get delta node: {e}")))?;
    stmt.query_row(params![remote_name, corpus_id, file_id], map_gdrive_node)
        .optional()
        .map_err(|e| Error::state_store(format!("get delta node: {e}")))
}

pub(super) fn query_gdrive_nodes_batch(
    conn: &Connection,
    remote_name: &str,
    corpus_id: &str,
    file_ids: &[String],
) -> Result<HashMap<String, DeltaNodeRecord>> {
    if file_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut stmt = conn
        .prepare_cached(
            "SELECT file_id, parent_id, raw_name, nfc_name, kind, size, mtime_ns, md5, trashed, generation, updated_at
             FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2 AND file_id = ?3 AND trashed = 0",
        )
        .map_err(|e| Error::state_store(format!("prepare get delta nodes batch: {e}")))?;
    let mut out = HashMap::with_capacity(file_ids.len());
    for fid in file_ids {
        if let Some(rec) = stmt
            .query_row(params![remote_name, corpus_id, fid], map_gdrive_node)
            .optional()
            .map_err(|e| Error::state_store(format!("get delta node batch row: {e}")))?
        {
            out.insert(fid.clone(), rec);
        }
    }
    Ok(out)
}

pub(super) fn query_gdrive_children(
    conn: &Connection,
    remote_name: &str,
    corpus_id: &str,
    parent_id: &str,
) -> Result<Vec<DeltaNodeRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT file_id, parent_id, raw_name, nfc_name, kind, size, mtime_ns, md5, trashed, generation, updated_at
             FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2 AND parent_id = ?3 AND trashed = 0",
        )
        .map_err(|e| Error::state_store(format!("prepare list delta children: {e}")))?;
    let rows = stmt
        .query_map(params![remote_name, corpus_id, parent_id], map_gdrive_node)
        .map_err(|e| Error::state_store(format!("query delta children: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read delta child: {e}")))?);
    }
    Ok(out)
}

pub(super) fn query_gdrive_children_by_name(
    conn: &Connection,
    remote_name: &str,
    corpus_id: &str,
    parent_id: &str,
    name: &str,
) -> Result<Vec<DeltaNodeRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT file_id, parent_id, raw_name, nfc_name, kind, size, mtime_ns, md5, trashed, generation, updated_at
             FROM gdrive_nodes
             WHERE remote_name = ?1 AND corpus_id = ?2 AND parent_id = ?3
               AND trashed = 0 AND (raw_name = ?4 OR nfc_name = ?4)",
        )
        .map_err(|e| Error::state_store(format!("prepare find delta child: {e}")))?;
    let rows = stmt
        .query_map(
            params![remote_name, corpus_id, parent_id, name],
            map_gdrive_node,
        )
        .map_err(|e| Error::state_store(format!("query find delta child: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read delta child: {e}")))?);
    }
    Ok(out)
}

pub(super) fn query_all_gdrive_nodes(
    conn: &Connection,
    remote_name: &str,
    corpus_id: &str,
) -> Result<Vec<DeltaNodeRecord>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT file_id, parent_id, raw_name, nfc_name, kind, size, mtime_ns, md5, trashed, generation, updated_at
             FROM gdrive_nodes WHERE remote_name = ?1 AND corpus_id = ?2 AND trashed = 0",
        )
        .map_err(|e| Error::state_store(format!("prepare list all delta nodes: {e}")))?;
    let rows = stmt
        .query_map(params![remote_name, corpus_id], map_gdrive_node)
        .map_err(|e| Error::state_store(format!("query all delta nodes: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| Error::state_store(format!("read delta node: {e}")))?);
    }
    Ok(out)
}
