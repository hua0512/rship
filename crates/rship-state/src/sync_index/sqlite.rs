//! Disk-backed spilled SQLite ingest (`src_raw.db` / `dst_raw.db`), external sort
//! into `WITHOUT ROWID` `sorted.db`, conflict detection, and dual forward-cursor merge.

use rship_core::path::RelPath;
use rship_core::state::{ConflictKind, DiffRow, SyncConflict};
use rship_core::types::{Entry, NodeId};
use rship_core::{Error, Result};
use rusqlite::{Connection, params};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use crate::schema::{
    EPHEMERAL_BUILD_DST_SORTED_FROM_ATTACH, EPHEMERAL_BUILD_SRC_SORTED_FROM_ATTACH,
    EPHEMERAL_DST_RAW_SCHEMA, EPHEMERAL_SRC_RAW_SCHEMA, configure_raw_ephemeral_db,
    configure_sorted_ephemeral_db, decode_entry_meta, encode_entry_meta,
};

use super::SideIngest;
use super::run_dir::{LazyRunDir, ensure_sqlite_tmpdir_exists};

const MERGE_FETCH_CHUNK: usize = 2048;
const DST_ONLY_SRC_NFC_CHUNK: usize = 4096;

const SQL_INSERT_SRC_RAW: &str = "INSERT INTO src_raw (
    nfc_path, raw_path, node_id, parent_id, flags,
    size, mtime_ns, ctime_ns, etag, hash_blob
) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)";

const SQL_INSERT_DST_RAW: &str = "INSERT INTO dst_raw (
    nfc_path, raw_path, node_id, parent_id, flags,
    size, mtime_ns, ctime_ns, etag, hash_blob
) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)";

const SQL_CREATE_SRC_SORTED: &str = r#"
CREATE TABLE src_sorted (
    nfc_path  TEXT NOT NULL,
    id        INTEGER NOT NULL,
    raw_path  TEXT,
    node_id   TEXT,
    parent_id TEXT,
    flags     INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    ctime_ns  INTEGER,
    etag      TEXT,
    hash_blob BLOB,
    PRIMARY KEY (nfc_path, id)
) WITHOUT ROWID;
"#;

const SQL_INSERT_SRC_SORTED: &str = "INSERT INTO src_sorted (
    nfc_path, id, raw_path, node_id, parent_id, flags,
    size, mtime_ns, ctime_ns, etag, hash_blob
) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";

const SQL_CREATE_DST_SORTED: &str = r#"
CREATE TABLE dst_sorted (
    nfc_path  TEXT NOT NULL,
    id        INTEGER NOT NULL,
    raw_path  TEXT,
    node_id   TEXT,
    parent_id TEXT,
    flags     INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    ctime_ns  INTEGER,
    etag      TEXT,
    hash_blob BLOB,
    PRIMARY KEY (nfc_path, id)
) WITHOUT ROWID;
"#;

const SQL_INSERT_DST_SORTED: &str = "INSERT INTO dst_sorted (
    nfc_path, id, raw_path, node_id, parent_id, flags,
    size, mtime_ns, ctime_ns, etag, hash_blob
) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";

pub(super) struct SpilledSide {
    /// Open SQLite connection to `src_raw.db` or `dst_raw.db`.
    /// Declared BEFORE `_run_dir` so the connection is always closed before
    /// `LazyRunDir` drops and deletes the scratch directory (Windows requirement).
    conn: Option<Connection>,
    path: PathBuf,
    _run_dir: LazyRunDir,
}

impl SpilledSide {
    pub(super) fn create_and_spill(
        run_dir: LazyRunDir,
        dir: PathBuf,
        is_src: bool,
        buffered: &[Entry],
        incoming: &[Entry],
        #[cfg(test)] on_raw_write: impl FnOnce(),
    ) -> Result<Self> {
        ensure_sqlite_tmpdir_exists();

        let (file_name, schema, sql) = if is_src {
            ("src_raw.db", EPHEMERAL_SRC_RAW_SCHEMA, SQL_INSERT_SRC_RAW)
        } else {
            ("dst_raw.db", EPHEMERAL_DST_RAW_SCHEMA, SQL_INSERT_DST_RAW)
        };
        let raw_path = dir.join(file_name);
        if raw_path.exists() {
            let _ = std::fs::remove_file(&raw_path);
        }

        let mut conn = Connection::open(&raw_path)
            .map_err(|e| Error::state_store(format!("open {file_name}: {e}")))?;
        configure_raw_ephemeral_db(&conn, schema)?;

        #[cfg(test)]
        on_raw_write();

        write_entry_slices_to_raw_conn(&mut conn, sql, &[buffered, incoming])?;

        Ok(Self {
            conn: Some(conn),
            path: raw_path,
            _run_dir: run_dir,
        })
    }

    pub(super) fn write_batch(
        &mut self,
        is_src: bool,
        entries: &[Entry],
        #[cfg(test)] on_raw_write: impl FnOnce(),
    ) -> Result<()> {
        let sql = if is_src {
            SQL_INSERT_SRC_RAW
        } else {
            SQL_INSERT_DST_RAW
        };
        let conn = self.conn.as_mut().ok_or_else(|| {
            Error::state_store(if is_src {
                "src_raw connection already finalized"
            } else {
                "dst_raw connection already finalized"
            })
        })?;

        #[cfg(test)]
        on_raw_write();

        write_entry_slices_to_raw_conn(conn, sql, &[entries])
    }

    #[cfg(test)]
    pub(super) fn raw_conn(&self) -> Option<&Connection> {
        self.conn.as_ref()
    }
}

#[derive(Default)]
struct SrcMergeCursor {
    initialized: bool,
    last_emitted_seq: i64,
    src_buf: VecDeque<Entry>,
    src_last_key: Option<(String, i64)>,
    src_eof: bool,
    dst_buf: VecDeque<Entry>,
    dst_last_key: Option<(String, i64)>,
    dst_eof: bool,
}

impl SrcMergeCursor {
    fn reset(&mut self) {
        self.initialized = true;
        self.last_emitted_seq = 0;
        self.src_buf.clear();
        self.src_last_key = None;
        self.src_eof = false;
        self.dst_buf.clear();
        self.dst_last_key = None;
        self.dst_eof = false;
    }
}

#[derive(Default)]
struct DstOnlyMergeCursor {
    initialized: bool,
    last_emitted_seq: i64,
    dst_buf: VecDeque<Entry>,
    dst_last_key: Option<(String, i64)>,
    dst_eof: bool,
    src_nfc_buf: VecDeque<String>,
    src_last_key: Option<(String, i64)>,
    src_eof: bool,
}

impl DstOnlyMergeCursor {
    fn reset(&mut self) {
        self.initialized = true;
        self.last_emitted_seq = 0;
        self.dst_buf.clear();
        self.dst_last_key = None;
        self.dst_eof = false;
        self.src_nfc_buf.clear();
        self.src_last_key = None;
        self.src_eof = false;
    }
}

pub(super) struct SpilledReadState {
    /// Open SQLite connection to `sorted.db`.
    /// Declared BEFORE `_run_dir` so the connection closes before `LazyRunDir` cleanup.
    sorted_conn: Option<Connection>,
    src_merge: SrcMergeCursor,
    dst_only_merge: DstOnlyMergeCursor,
    _run_dir: LazyRunDir,
}

pub(super) struct SpilledFinalizeOutcome {
    pub(super) state: SpilledReadState,
    pub(super) conflicts: Vec<SyncConflict>,
    pub(super) total_bytes: u64,
    pub(super) freelist_bytes: u64,
    pub(super) auto_vacuum: i64,
}

impl SpilledReadState {
    pub(super) fn finalize(
        run_dir: LazyRunDir,
        src: &mut SideIngest,
        dst: &mut SideIngest,
        dst_case_sensitive: bool,
    ) -> Result<SpilledFinalizeOutcome> {
        let dir = run_dir.planned_path();
        ensure_sqlite_tmpdir_exists();

        let sorted_path = dir.join("sorted.db");
        let fold_path = dir.join("fold.db");
        for p in [&sorted_path, &fold_path] {
            if p.exists() {
                let _ = std::fs::remove_file(p);
            }
        }

        let mut conn = Connection::open(&sorted_path)
            .map_err(|e| Error::state_store(format!("open sorted.db: {e}")))?;
        configure_sorted_ephemeral_db(&conn)?;

        // 1. External-sort `src_raw.db` -> `src_sorted` WITHOUT ROWID (and O(1) unlink `src_raw.db`),
        //    or directly bulk-insert if `src` remained small in RAM.
        build_sorted_table_from_side(&mut conn, src, true)?;

        // 2. External-sort `dst_raw.db` -> `dst_sorted` WITHOUT ROWID (and O(1) unlink `dst_raw.db`),
        //    or directly bulk-insert if `dst` remained small in RAM.
        build_sorted_table_from_side(&mut conn, dst, false)?;

        let mut conflicts = Vec::new();

        // 3. Intra-source duplicate / NFC collisions (sequential PK scan on `src_sorted`).
        {
            let dup_nfcs: Vec<String> = {
                let mut stmt = conn
                    .prepare(
                        "SELECT nfc_path FROM src_sorted GROUP BY nfc_path HAVING COUNT(*) > 1",
                    )
                    .map_err(|e| Error::state_store(format!("query src dupes: {e}")))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| Error::state_store(format!("run src dupes: {e}")))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| Error::state_store(format!("read src dupe: {e}")))?
            };
            if !dup_nfcs.is_empty() {
                let mut detail_stmt = conn
                    .prepare(
                        "SELECT COUNT(*), COUNT(DISTINCT COALESCE(raw_path, nfc_path))
                         FROM src_sorted WHERE nfc_path = ?1",
                    )
                    .map_err(|e| Error::state_store(format!("query src dupe detail: {e}")))?;
                for nfc in dup_nfcs {
                    let (cnt, distinct_raw): (i64, i64) = detail_stmt
                        .query_row(params![&nfc], |r| Ok((r.get(0)?, r.get(1)?)))
                        .map_err(|e| Error::state_store(format!("read src dupe detail: {e}")))?;
                    let kind = if distinct_raw > 1 {
                        ConflictKind::UnicodeNfcCollision
                    } else {
                        ConflictKind::DuplicateSourceName
                    };
                    let detail = format!("{cnt} source entries map to NFC path `{nfc}`");
                    conflicts.push(SyncConflict {
                        nfc_path: RelPath::from_normalized_unchecked(nfc),
                        kind,
                        detail,
                    });
                }
            }
        }

        // 4. Intra-destination duplicate / NFC collisions (sequential PK scan on `dst_sorted`).
        {
            let mut stmt = conn
                .prepare(
                    "SELECT nfc_path, COUNT(*) FROM dst_sorted GROUP BY nfc_path HAVING COUNT(*) > 1",
                )
                .map_err(|e| Error::state_store(format!("query dst dupes: {e}")))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| Error::state_store(format!("run dst dupes: {e}")))?;
            for r in rows {
                let (nfc, cnt) =
                    r.map_err(|e| Error::state_store(format!("read dst dupe: {e}")))?;
                let detail = format!("{cnt} destination entries share path `{nfc}`");
                conflicts.push(SyncConflict {
                    nfc_path: RelPath::from_normalized_unchecked(nfc),
                    kind: ConflictKind::DuplicateDestinationName,
                    detail,
                });
            }
        }

        // 5. Case-insensitive collisions: use a separate ephemeral `fold.db` and unlink it
        //    afterward so `sorted.db` stays compact with zero freelist pages.
        if !dst_case_sensitive {
            detect_case_insensitive_collisions(&conn, &fold_path, &mut conflicts)?;
        }

        let tx = conn
            .transaction()
            .map_err(|e| Error::state_store(format!("begin conflicts tx: {e}")))?;
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT INTO sync_conflicts (nfc_path, kind, detail) VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| Error::state_store(format!("prepare insert conflict: {e}")))?;
            for c in &conflicts {
                ins.execute(params![c.nfc_path.as_str(), c.kind.as_str(), c.detail,])
                    .map_err(|e| Error::state_store(format!("insert conflict: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| Error::state_store(format!("commit conflicts: {e}")))?;

        let (total_bytes, freelist_bytes, auto_vacuum) = query_db_diagnostics(&conn);

        let mut src_merge = SrcMergeCursor::default();
        src_merge.reset();
        let mut dst_only_merge = DstOnlyMergeCursor::default();
        dst_only_merge.reset();

        let state = Self {
            sorted_conn: Some(conn),
            src_merge,
            dst_only_merge,
            _run_dir: run_dir,
        };
        Ok(SpilledFinalizeOutcome {
            state,
            conflicts,
            total_bytes,
            freelist_bytes,
            auto_vacuum,
        })
    }

    pub(super) fn load_conflicts(&self) -> Result<Vec<SyncConflict>> {
        let conn = self
            .sorted_conn
            .as_ref()
            .ok_or_else(|| Error::state_store("sync index not finalized"))?;
        load_conflicts_conn(conn)
    }

    pub(super) fn next_src_page(&mut self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self
            .sorted_conn
            .as_ref()
            .ok_or_else(|| Error::state_store("sync index not finalized"))?;
        let cur = &mut self.src_merge;

        let mut skip_count = 0i64;
        if after_id <= 0 {
            cur.reset();
        } else if !cur.initialized || cur.last_emitted_seq != after_id {
            cur.reset();
            skip_count = after_id;
        }

        let mut out = Vec::with_capacity(limit.min(512));
        while out.len() < limit {
            if cur.src_buf.is_empty() && !cur.src_eof {
                refill_sorted_entries(
                    conn,
                    true,
                    &mut cur.src_last_key,
                    &mut cur.src_buf,
                    &mut cur.src_eof,
                )?;
            }
            let Some(src_entry) = cur.src_buf.pop_front() else {
                break;
            };

            let matched_dst = loop {
                if cur.dst_buf.is_empty() && !cur.dst_eof {
                    refill_sorted_entries(
                        conn,
                        false,
                        &mut cur.dst_last_key,
                        &mut cur.dst_buf,
                        &mut cur.dst_eof,
                    )?;
                }
                match cur.dst_buf.front() {
                    Some(d) if d.nfc_path.as_str() < src_entry.nfc_path.as_str() => {
                        cur.dst_buf.pop_front();
                    }
                    Some(d) if d.nfc_path.as_str() == src_entry.nfc_path.as_str() => {
                        break Some(d.clone());
                    }
                    _ => break None,
                }
            };

            cur.last_emitted_seq += 1;
            if skip_count > 0 {
                skip_count -= 1;
                continue;
            }
            out.push(DiffRow {
                row_id: cur.last_emitted_seq,
                src: Some(src_entry),
                dst: matched_dst,
            });
        }
        Ok(out)
    }

    pub(super) fn next_dst_only_page(
        &mut self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<DiffRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self
            .sorted_conn
            .as_ref()
            .ok_or_else(|| Error::state_store("sync index not finalized"))?;
        let cur = &mut self.dst_only_merge;

        let mut skip_count = 0i64;
        if after_id <= 0 {
            cur.reset();
        } else if !cur.initialized || cur.last_emitted_seq != after_id {
            cur.reset();
            skip_count = after_id;
        }

        let mut out = Vec::with_capacity(limit.min(512));
        while out.len() < limit {
            if cur.dst_buf.is_empty() && !cur.dst_eof {
                refill_sorted_entries(
                    conn,
                    false,
                    &mut cur.dst_last_key,
                    &mut cur.dst_buf,
                    &mut cur.dst_eof,
                )?;
            }
            let Some(dst_entry) = cur.dst_buf.pop_front() else {
                break;
            };

            let exists_on_src = loop {
                if cur.src_nfc_buf.is_empty() && !cur.src_eof {
                    refill_src_nfc_keys(
                        conn,
                        &mut cur.src_last_key,
                        &mut cur.src_nfc_buf,
                        &mut cur.src_eof,
                    )?;
                }
                match cur.src_nfc_buf.front() {
                    Some(s) if s.as_str() < dst_entry.nfc_path.as_str() => {
                        cur.src_nfc_buf.pop_front();
                    }
                    Some(s) if s.as_str() == dst_entry.nfc_path.as_str() => break true,
                    _ => break false,
                }
            };

            if exists_on_src {
                continue;
            }

            cur.last_emitted_seq += 1;
            if skip_count > 0 {
                skip_count -= 1;
                continue;
            }
            out.push(DiffRow {
                row_id: cur.last_emitted_seq,
                src: None,
                dst: Some(dst_entry),
            });
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(super) fn sorted_conn(&self) -> Option<&Connection> {
        self.sorted_conn.as_ref()
    }
}

fn query_db_diagnostics(conn: &Connection) -> (u64, u64, i64) {
    let pages: i64 = conn
        .query_row("PRAGMA page_count;", [], |r| r.get(0))
        .unwrap_or(0);
    let free: i64 = conn
        .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
        .unwrap_or(0);
    let ps: i64 = conn
        .query_row("PRAGMA page_size;", [], |r| r.get(0))
        .unwrap_or(0);
    let av: i64 = conn
        .query_row("PRAGMA auto_vacuum;", [], |r| r.get(0))
        .unwrap_or(0);
    (
        (pages.max(0) as u64).saturating_mul(ps.max(0) as u64),
        (free.max(0) as u64).saturating_mul(ps.max(0) as u64),
        av,
    )
}

fn write_entry_slices_to_raw_conn(
    conn: &mut Connection,
    sql: &'static str,
    slices: &[&[Entry]],
) -> Result<()> {
    if slices.iter().all(|s| s.is_empty()) {
        return Ok(());
    }
    let tx = conn
        .transaction()
        .map_err(|e| Error::state_store(format!("begin insert tx: {e}")))?;
    {
        let mut stmt = tx
            .prepare_cached(sql)
            .map_err(|e| Error::state_store(format!("prepare insert: {e}")))?;
        for slice in slices {
            for e in *slice {
                let nfc = e.nfc_path.as_str();
                let raw_opt = e.raw_path.as_deref();
                let (flags, stored_etag, hash_blob) = encode_entry_meta(
                    e.kind,
                    e.etag.as_deref(),
                    e.checksum.as_ref().map(|c| c.kind),
                    e.checksum.as_ref().map(|c| c.hex.as_str()),
                );
                stmt.execute(params![
                    nfc,
                    raw_opt,
                    e.node_id.as_ref().map(NodeId::as_str),
                    e.parent_id.as_ref().map(NodeId::as_str),
                    flags,
                    e.size as i64,
                    e.mtime_ns,
                    e.ctime_ns,
                    stored_etag,
                    hash_blob.as_deref(),
                ])
                .map_err(|err| Error::state_store(format!("insert entry: {err}")))?;
            }
        }
    }
    tx.commit()
        .map_err(|e| Error::state_store(format!("commit insert batch: {e}")))?;
    Ok(())
}

fn build_sorted_table_from_side(
    sorted_conn: &mut Connection,
    side: &mut SideIngest,
    is_src: bool,
) -> Result<()> {
    let prev = std::mem::replace(side, SideIngest::Finalized);
    match prev {
        SideIngest::Spilled(mut sp) => {
            // Close raw connection BEFORE attaching so `locking_mode = EXCLUSIVE` is released cleanly.
            let _ = sp.conn.take();
            let (alias, attach_sql, label) = if is_src {
                ("raw_src", EPHEMERAL_BUILD_SRC_SORTED_FROM_ATTACH, "src")
            } else {
                ("raw_dst", EPHEMERAL_BUILD_DST_SORTED_FROM_ATTACH, "dst")
            };
            let raw_str = sp.path.to_string_lossy().into_owned();
            sorted_conn
                .execute(&format!("ATTACH DATABASE ?1 AS {alias}"), params![raw_str])
                .map_err(|e| Error::state_store(format!("attach {label}_raw.db: {e}")))?;
            sorted_conn
                .execute_batch(attach_sql)
                .map_err(|e| Error::state_store(format!("build {label}_sorted: {e}")))?;
            sorted_conn
                .execute_batch(&format!("DETACH DATABASE {alias};"))
                .map_err(|e| Error::state_store(format!("detach {label}_raw.db: {e}")))?;
            let _ = std::fs::remove_file(&sp.path);
            Ok(())
        }
        SideIngest::InMemory(entries) => {
            let (create_sql, insert_sql, label) = if is_src {
                (SQL_CREATE_SRC_SORTED, SQL_INSERT_SRC_SORTED, "src")
            } else {
                (SQL_CREATE_DST_SORTED, SQL_INSERT_DST_SORTED, "dst")
            };
            sorted_conn
                .execute_batch(create_sql)
                .map_err(|e| Error::state_store(format!("create {label}_sorted: {e}")))?;
            if entries.is_empty() {
                return Ok(());
            }
            // Preserve 1-based insertion order (`id`) for equal `nfc_path` keys, matching
            // `ORDER BY nfc_path ASC, id ASC` from the raw table.
            let mut indexed: Vec<(i64, Entry)> = entries
                .into_iter()
                .enumerate()
                .map(|(i, e)| ((i + 1) as i64, e))
                .collect();
            indexed.sort_by(|a, b| {
                a.1.nfc_path
                    .as_str()
                    .cmp(b.1.nfc_path.as_str())
                    .then_with(|| a.0.cmp(&b.0))
            });
            let tx = sorted_conn
                .transaction()
                .map_err(|e| Error::state_store(format!("begin {label}_sorted tx: {e}")))?;
            {
                let mut stmt = tx.prepare_cached(insert_sql).map_err(|e| {
                    Error::state_store(format!("prepare {label}_sorted insert: {e}"))
                })?;
                for (id, e) in indexed {
                    let nfc = e.nfc_path.as_str();
                    let raw_opt = e.raw_path.as_deref();
                    let (flags, stored_etag, hash_blob) = encode_entry_meta(
                        e.kind,
                        e.etag.as_deref(),
                        e.checksum.as_ref().map(|c| c.kind),
                        e.checksum.as_ref().map(|c| c.hex.as_str()),
                    );
                    stmt.execute(params![
                        nfc,
                        id,
                        raw_opt,
                        e.node_id.as_ref().map(NodeId::as_str),
                        e.parent_id.as_ref().map(NodeId::as_str),
                        flags,
                        e.size as i64,
                        e.mtime_ns,
                        e.ctime_ns,
                        stored_etag,
                        hash_blob.as_deref(),
                    ])
                    .map_err(|err| {
                        Error::state_store(format!("insert {label}_sorted entry: {err}"))
                    })?;
                }
            }
            tx.commit()
                .map_err(|e| Error::state_store(format!("commit {label}_sorted: {e}")))?;
            Ok(())
        }
        SideIngest::Finalized => Err(Error::state_store(format!(
            "{}_raw connection already finalized",
            if is_src { "src" } else { "dst" }
        ))),
    }
}

fn detect_case_insensitive_collisions(
    sorted_conn: &Connection,
    fold_path: &Path,
    conflicts: &mut Vec<SyncConflict>,
) -> Result<()> {
    if fold_path.exists() {
        let _ = std::fs::remove_file(fold_path);
    }
    let mut fold_conn = Connection::open(fold_path)
        .map_err(|e| Error::state_store(format!("open fold.db: {e}")))?;
    fold_conn
        .execute_batch(
            "PRAGMA page_size = 8192;
             PRAGMA auto_vacuum = NONE;
             PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA locking_mode = EXCLUSIVE;
             PRAGMA cache_size = -4096;
             PRAGMA temp_store = FILE;
             PRAGMA mmap_size = 0;
             CREATE TABLE fold_check (
                 fold_path TEXT NOT NULL,
                 nfc_path  TEXT NOT NULL
             );",
        )
        .map_err(|e| Error::state_store(format!("create fold_check: {e}")))?;

    for table in ["src_sorted", "dst_sorted"] {
        let mut last_key: Option<(String, i64)> = None;
        let mut prev_nfc: Option<String> = None;
        let mut batch: Vec<String> = Vec::with_capacity(MERGE_FETCH_CHUNK);
        loop {
            batch.clear();
            let mut fetched = 0usize;
            {
                let mut stmt = match &last_key {
                    None => sorted_conn
                        .prepare(&format!(
                            "SELECT nfc_path, id FROM {table} ORDER BY nfc_path ASC, id ASC LIMIT ?1"
                        ))
                        .map_err(|e| Error::state_store(format!("prepare fold scan: {e}")))?,
                    Some(_) => sorted_conn
                        .prepare(&format!(
                            "SELECT nfc_path, id FROM {table}
                             WHERE (nfc_path, id) > (?1, ?2)
                             ORDER BY nfc_path ASC, id ASC LIMIT ?3"
                        ))
                        .map_err(|e| Error::state_store(format!("prepare fold scan: {e}")))?,
                };
                let mut rows = match &last_key {
                    None => stmt
                        .query(params![MERGE_FETCH_CHUNK as i64])
                        .map_err(|e| Error::state_store(format!("run fold scan: {e}")))?,
                    Some((ln, lid)) => stmt
                        .query(params![ln, lid, MERGE_FETCH_CHUNK as i64])
                        .map_err(|e| Error::state_store(format!("run fold scan: {e}")))?,
                };
                while let Some(row) = rows
                    .next()
                    .map_err(|e| Error::state_store(format!("read fold scan row: {e}")))?
                {
                    let nfc: String = row
                        .get(0)
                        .map_err(|e| Error::state_store(format!("read fold nfc: {e}")))?;
                    let id: i64 = row
                        .get(1)
                        .map_err(|e| Error::state_store(format!("read fold id: {e}")))?;
                    fetched += 1;
                    if prev_nfc.as_deref() != Some(nfc.as_str()) {
                        batch.push(nfc.clone());
                        prev_nfc = Some(nfc.clone());
                    }
                    last_key = Some((nfc, id));
                }
            }
            if !batch.is_empty() {
                let tx = fold_conn
                    .transaction()
                    .map_err(|e| Error::state_store(format!("begin fold insert tx: {e}")))?;
                {
                    let mut ins = tx
                        .prepare_cached(
                            "INSERT INTO fold_check (fold_path, nfc_path) VALUES (?1, ?2)",
                        )
                        .map_err(|e| Error::state_store(format!("prepare fold insert: {e}")))?;
                    for nfc in &batch {
                        let rel = RelPath::from_normalized_unchecked(nfc.clone());
                        let fold = rel.fold_key_cow();
                        ins.execute(params![fold.as_ref(), nfc.as_str()])
                            .map_err(|e| Error::state_store(format!("insert fold_check: {e}")))?;
                    }
                }
                tx.commit()
                    .map_err(|e| Error::state_store(format!("commit fold insert tx: {e}")))?;
            }
            if fetched < MERGE_FETCH_CHUNK {
                break;
            }
        }
    }

    fold_conn
        .execute_batch("CREATE INDEX idx_fold_check ON fold_check(fold_path, nfc_path);")
        .map_err(|e| Error::state_store(format!("build idx_fold_check: {e}")))?;

    let colliding_folds: Vec<String> = {
        let mut stmt = fold_conn
            .prepare(
                "SELECT fold_path FROM fold_check
                 GROUP BY fold_path
                 HAVING MIN(nfc_path) <> MAX(nfc_path)
                 ORDER BY fold_path ASC",
            )
            .map_err(|e| Error::state_store(format!("query case collisions: {e}")))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Error::state_store(format!("run case collisions: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::state_store(format!("read case collision fold: {e}")))?
    };

    if !colliding_folds.is_empty() {
        let mut members_stmt = fold_conn
            .prepare(
                "SELECT DISTINCT nfc_path FROM fold_check
                 WHERE fold_path = ?1
                 ORDER BY nfc_path ASC",
            )
            .map_err(|e| Error::state_store(format!("query case collision members: {e}")))?;
        for fold in colliding_folds {
            let rows = members_stmt
                .query_map(params![&fold], |r| r.get::<_, String>(0))
                .map_err(|e| Error::state_store(format!("run case collision members: {e}")))?;
            for r in rows {
                let nfc =
                    r.map_err(|e| Error::state_store(format!("read case collision member: {e}")))?;
                let detail = format!("`{nfc}` collides case-insensitively on `{fold}`");
                conflicts.push(SyncConflict {
                    nfc_path: RelPath::from_normalized_unchecked(nfc),
                    kind: ConflictKind::CaseInsensitiveCollision,
                    detail,
                });
            }
        }
    }

    drop(fold_conn);
    let _ = std::fs::remove_file(fold_path);
    Ok(())
}

fn load_conflicts_conn(conn: &Connection) -> Result<Vec<SyncConflict>> {
    let mut stmt = conn
        .prepare_cached("SELECT nfc_path, kind, detail FROM sync_conflicts ORDER BY id ASC")
        .map_err(|e| Error::state_store(format!("prepare load conflicts: {e}")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| Error::state_store(format!("query load conflicts: {e}")))?;
    let mut out = Vec::new();
    for r in rows {
        let (nfc, k, detail) =
            r.map_err(|e| Error::state_store(format!("read conflict row: {e}")))?;
        out.push(SyncConflict {
            nfc_path: RelPath::from_normalized_unchecked(nfc),
            kind: parse_conflict_kind(&k)?,
            detail,
        });
    }
    Ok(out)
}

fn refill_sorted_entries(
    conn: &Connection,
    is_src: bool,
    last_key: &mut Option<(String, i64)>,
    buf: &mut VecDeque<Entry>,
    eof: &mut bool,
) -> Result<()> {
    if *eof {
        return Ok(());
    }
    let (sql_first, sql_next) = if is_src {
        (
            "SELECT id, nfc_path, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
             FROM src_sorted
             ORDER BY nfc_path ASC, id ASC
             LIMIT ?1",
            "SELECT id, nfc_path, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
             FROM src_sorted
             WHERE (nfc_path, id) > (?1, ?2)
             ORDER BY nfc_path ASC, id ASC
             LIMIT ?3",
        )
    } else {
        (
            "SELECT id, nfc_path, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
             FROM dst_sorted
             ORDER BY nfc_path ASC, id ASC
             LIMIT ?1",
            "SELECT id, nfc_path, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
             FROM dst_sorted
             WHERE (nfc_path, id) > (?1, ?2)
             ORDER BY nfc_path ASC, id ASC
             LIMIT ?3",
        )
    };

    let mut fetched = 0usize;
    let mut new_last: Option<(String, i64)> = None;
    match last_key {
        None => {
            let mut stmt = conn
                .prepare_cached(sql_first)
                .map_err(|e| Error::state_store(format!("prepare sorted scan: {e}")))?;
            let rows = stmt
                .query_map(params![MERGE_FETCH_CHUNK as i64], read_sorted_row)
                .map_err(|e| Error::state_store(format!("query sorted scan: {e}")))?;
            for r in rows {
                let (id, entry) =
                    r.map_err(|e| Error::state_store(format!("read sorted row: {e}")))?;
                new_last = Some((entry.nfc_path.as_str().to_string(), id));
                buf.push_back(entry);
                fetched += 1;
            }
        }
        Some((last_nfc, last_id)) => {
            let mut stmt = conn
                .prepare_cached(sql_next)
                .map_err(|e| Error::state_store(format!("prepare sorted next scan: {e}")))?;
            let rows = stmt
                .query_map(
                    params![last_nfc.as_str(), *last_id, MERGE_FETCH_CHUNK as i64],
                    read_sorted_row,
                )
                .map_err(|e| Error::state_store(format!("query sorted next scan: {e}")))?;
            for r in rows {
                let (id, entry) =
                    r.map_err(|e| Error::state_store(format!("read sorted next row: {e}")))?;
                new_last = Some((entry.nfc_path.as_str().to_string(), id));
                buf.push_back(entry);
                fetched += 1;
            }
        }
    }

    if let Some(lk) = new_last {
        *last_key = Some(lk);
    }
    if fetched < MERGE_FETCH_CHUNK {
        *eof = true;
    }
    Ok(())
}

fn refill_src_nfc_keys(
    conn: &Connection,
    last_key: &mut Option<(String, i64)>,
    buf: &mut VecDeque<String>,
    eof: &mut bool,
) -> Result<()> {
    if *eof {
        return Ok(());
    }
    let mut fetched = 0usize;
    let mut new_last: Option<(String, i64)> = None;
    match last_key {
        None => {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT nfc_path, id FROM src_sorted ORDER BY nfc_path ASC, id ASC LIMIT ?1",
                )
                .map_err(|e| Error::state_store(format!("prepare src nfc scan: {e}")))?;
            let rows = stmt
                .query_map(params![DST_ONLY_SRC_NFC_CHUNK as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .map_err(|e| Error::state_store(format!("query src nfc scan: {e}")))?;
            for r in rows {
                let (nfc, id) =
                    r.map_err(|e| Error::state_store(format!("read src nfc row: {e}")))?;
                if buf.back().map(String::as_str) != Some(nfc.as_str()) {
                    buf.push_back(nfc.clone());
                }
                new_last = Some((nfc, id));
                fetched += 1;
            }
        }
        Some((last_nfc, last_id)) => {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT nfc_path, id FROM src_sorted
                     WHERE (nfc_path, id) > (?1, ?2)
                     ORDER BY nfc_path ASC, id ASC
                     LIMIT ?3",
                )
                .map_err(|e| Error::state_store(format!("prepare src nfc next scan: {e}")))?;
            let rows = stmt
                .query_map(
                    params![last_nfc.as_str(), *last_id, DST_ONLY_SRC_NFC_CHUNK as i64],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )
                .map_err(|e| Error::state_store(format!("query src nfc next scan: {e}")))?;
            for r in rows {
                let (nfc, id) =
                    r.map_err(|e| Error::state_store(format!("read src nfc next row: {e}")))?;
                if buf.back().map(String::as_str) != Some(nfc.as_str()) {
                    buf.push_back(nfc.clone());
                }
                new_last = Some((nfc, id));
                fetched += 1;
            }
        }
    }

    if let Some(lk) = new_last {
        *last_key = Some(lk);
    }
    if fetched < DST_ONLY_SRC_NFC_CHUNK {
        *eof = true;
    }
    Ok(())
}

fn read_sorted_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Entry)> {
    let id: i64 = r.get(0)?;
    let nfc_s: String = r.get(1)?;
    let raw_opt: Option<String> = r.get(2)?;
    let node_id = r.get::<_, Option<String>>(3)?.map(NodeId);
    let parent_id = r.get::<_, Option<String>>(4)?.map(NodeId);
    let flags: i64 = r.get(5)?;
    let size = r.get::<_, i64>(6)? as u64;
    let mtime_ns: i64 = r.get(7)?;
    let ctime_ns: Option<i64> = r.get(8)?;
    let stored_etag: Option<String> = r.get(9)?;
    let hash_blob: Option<Vec<u8>> = r.get(10)?;

    let (kind, etag, checksum) = decode_entry_meta(flags, stored_etag, hash_blob);
    let raw_path = raw_opt.map(String::into_boxed_str);
    let nfc_path = RelPath::from_normalized_unchecked(nfc_s);
    Ok((
        id,
        Entry {
            node_id,
            parent_id,
            raw_path,
            nfc_path,
            kind,
            size,
            mtime_ns,
            ctime_ns,
            etag,
            checksum,
        },
    ))
}

fn parse_conflict_kind(s: &str) -> Result<ConflictKind> {
    match s {
        "duplicate_source_name" => Ok(ConflictKind::DuplicateSourceName),
        "duplicate_destination_name" => Ok(ConflictKind::DuplicateDestinationName),
        "unicode_nfc_collision" => Ok(ConflictKind::UnicodeNfcCollision),
        "case_insensitive_collision" => Ok(ConflictKind::CaseInsensitiveCollision),
        "type_flip_file_over_dir" => Ok(ConflictKind::TypeFlipFileOverDir),
        "type_flip_dir_over_file" => Ok(ConflictKind::TypeFlipDirOverFile),
        "concurrent_bisync_edit" => Ok(ConflictKind::ConcurrentBisyncEdit),
        "modify_delete_conflict" => Ok(ConflictKind::ModifyDeleteConflict),
        other => Err(Error::state_store(format!(
            "unknown conflict kind `{other}` in sync index"
        ))),
    }
}
