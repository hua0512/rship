//! Greenfield split SQLite schemas, compact bitpacked metadata encoding,
//! and dual durability profiles.
//!
//! Persistent state directory layout (`<state_dir>`):
//! - `journal.db`: tiny WAL-mode DB for `jobs`, active `operations`, and `operation_parts`.
//! - `baselines/<pair_key>.db`: lazily created per-pair `WITHOUT ROWID` DB storing
//!   compact binary `sync_baseline` rows (zero secondary indexes; O(1) file unlink on reset).
//! - `inventory/<scope>.db`: lazily created per-remote/corpus delta inventory (`change_tokens`,
//!   `gdrive_nodes`).
//!
//! Ephemeral per-run directory layout (`<state_dir>/runs/run-<job_id>/`):
//! - `.run.lock`: exclusive advisory process lock enabling crash-safe stale-run GC.
//! - `sync.db`: `journal_mode = OFF; synchronous = OFF; locking_mode = EXCLUSIVE; mmap_size = 0;`
//!   append-only `src_raw`/`dst_raw` -> external sort into `WITHOUT ROWID` `src_sorted`/`dst_sorted`
//!   (dropping raw tables sequentially) -> dual forward-cursor merge scan.

use rship_core::types::{Checksum, EntryKind, HashKind};
use rship_core::{Error, Result};
use rusqlite::{Connection, ErrorCode};
use std::time::Duration;

pub const STATE_DB_BUSY_TIMEOUT: Duration = Duration::from_secs(15);

/// Current `PRAGMA user_version` for persistent `journal.db`.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;
/// Current `PRAGMA user_version` for persistent `baselines/<pair>.db` shards.
pub const BASELINE_SCHEMA_VERSION: u32 = 1;
/// Current `PRAGMA user_version` for persistent `inventory/<scope>.db` shards.
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

const FLAG_HASH_RAW_BYTES: i64 = 1 << 5;
const FLAG_ETAG_QUOTED_HASH: i64 = 1 << 6;
const FLAG_ETAG_UNQUOTED_HASH: i64 = 1 << 7;

/// Bitpack `(kind, hash_kind, binary-hash encoding, etag-dedup)` and encode compact
/// `(flags, stored_etag, hash_blob)` for lossless storage in SQLite.
///
/// For typical single-part S3 objects (`etag = "\"<32-hex-md5>\""`, `checksum = MD5`),
/// this packs `kind + hash_kind + etag` into a 1-byte SQLite integer + 16-byte raw BLOB
/// with `stored_etag = None`, saving ~50 bytes per row over UTF-8 text columns.
pub(crate) fn encode_entry_meta<'a>(
    kind: EntryKind,
    etag: Option<&'a str>,
    hash_kind: Option<HashKind>,
    hash_hex: Option<&str>,
) -> (i64, Option<&'a str>, Option<Vec<u8>>) {
    let mut flags: i64 = match kind {
        EntryKind::File => 0,
        EntryKind::Directory => 1,
        EntryKind::Symlink => 2,
        _ => 0,
    };

    let mut stored_etag = etag;
    let hash_blob = if let (Some(hk), Some(hex_str)) = (hash_kind, hash_hex) {
        let hk_bits: i64 = match hk {
            HashKind::Md5 => 1,
            HashKind::Sha1 => 2,
            HashKind::Sha256 => 3,
            HashKind::Crc32c => 4,
            HashKind::Crc64Nvme => 5,
            HashKind::Blake3 => 6,
            _ => 0,
        };
        if hk_bits != 0 {
            flags |= hk_bits << 2;
            if let Some(et) = etag {
                if et.len() == hex_str.len() + 2
                    && et.starts_with('"')
                    && et.ends_with('"')
                    && &et[1..et.len() - 1] == hex_str
                {
                    flags |= FLAG_ETAG_QUOTED_HASH;
                    stored_etag = None;
                } else if et == hex_str {
                    flags |= FLAG_ETAG_UNQUOTED_HASH;
                    stored_etag = None;
                }
            }
            // Only decode to raw bytes when the string is exact lowercase even-length hex so
            // `hex::encode` reproduces the exact original string losslessly.
            if !hex_str.is_empty()
                && hex_str.len().is_multiple_of(2)
                && hex_str
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                && let Ok(raw) = hex::decode(hex_str)
            {
                flags |= FLAG_HASH_RAW_BYTES;
                Some(raw)
            } else {
                Some(hex_str.as_bytes().to_vec())
            }
        } else {
            None
        }
    } else {
        None
    };

    (flags, stored_etag, hash_blob)
}

/// Losslessly decode `(EntryKind, Option<String> /* etag */, Option<Checksum>)` from
/// `(flags, stored_etag, hash_blob)`.
pub(crate) fn decode_entry_meta(
    flags: i64,
    stored_etag: Option<String>,
    hash_blob: Option<Vec<u8>>,
) -> (EntryKind, Option<String>, Option<Checksum>) {
    let kind = match flags & 0b11 {
        1 => EntryKind::Directory,
        2 => EntryKind::Symlink,
        _ => EntryKind::File,
    };
    let hash_kind = match (flags >> 2) & 0b111 {
        1 => Some(HashKind::Md5),
        2 => Some(HashKind::Sha1),
        3 => Some(HashKind::Sha256),
        4 => Some(HashKind::Crc32c),
        5 => Some(HashKind::Crc64Nvme),
        6 => Some(HashKind::Blake3),
        _ => None,
    };

    let checksum = match (hash_kind, hash_blob) {
        (Some(hk), Some(blob)) => {
            let hex = if (flags & FLAG_HASH_RAW_BYTES) != 0 {
                hex::encode(&blob)
            } else {
                String::from_utf8(blob).unwrap_or_default()
            };
            Some(Checksum { kind: hk, hex })
        }
        _ => None,
    };

    let etag = if stored_etag.is_some() {
        stored_etag
    } else if let Some(ref ck) = checksum {
        if (flags & FLAG_ETAG_QUOTED_HASH) != 0 {
            let mut s = String::with_capacity(ck.hex.len() + 2);
            s.push('"');
            s.push_str(&ck.hex);
            s.push('"');
            Some(s)
        } else if (flags & FLAG_ETAG_UNQUOTED_HASH) != 0 {
            Some(ck.hex.clone())
        } else {
            None
        }
    } else {
        None
    };

    (kind, etag, checksum)
}

const JOURNAL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    mode         TEXT NOT NULL,
    src_spec     TEXT NOT NULL,
    dst_spec     TEXT NOT NULL,
    status       TEXT NOT NULL,
    files_total  INTEGER NOT NULL DEFAULT 0,
    files_done   INTEGER NOT NULL DEFAULT 0,
    bytes_total  INTEGER NOT NULL DEFAULT 0,
    bytes_done   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    options_json  TEXT,
    resume_cursor TEXT
);

CREATE TABLE IF NOT EXISTS operations (
    op_id                 TEXT PRIMARY KEY,
    session_key           TEXT NOT NULL,
    job_id                TEXT NOT NULL,
    src_endpoint          TEXT NOT NULL,
    dst_endpoint          TEXT NOT NULL,
    src_raw_path          TEXT NOT NULL,
    dst_raw_path          TEXT NOT NULL,
    dst_nfc_path          TEXT NOT NULL,
    src_version_json      TEXT NOT NULL,
    dst_precondition_json TEXT NOT NULL,
    existing_dst_node_id  TEXT,
    remote_op_id          TEXT,
    backend_kind          TEXT NOT NULL,
    session_token         TEXT,
    backend_meta          TEXT NOT NULL DEFAULT '',
    planned_chunk_size    INTEGER NOT NULL,
    confirmed_offset      INTEGER NOT NULL DEFAULT 0,
    state                 TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    expires_at            INTEGER
);
CREATE INDEX IF NOT EXISTS idx_operations_session_key ON operations(session_key);
CREATE INDEX IF NOT EXISTS idx_operations_job_id ON operations(job_id);

CREATE TABLE IF NOT EXISTS operation_parts (
    op_id       TEXT NOT NULL REFERENCES operations(op_id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL,
    offset      INTEGER NOT NULL,
    length      INTEGER NOT NULL,
    etag        TEXT NOT NULL,
    checksum    TEXT,
    PRIMARY KEY (op_id, part_number)
);

CREATE TABLE IF NOT EXISTS bisync_state (
    pair_key     TEXT PRIMARY KEY,
    filter_hash  TEXT NOT NULL,
    last_a_files INTEGER NOT NULL DEFAULT 0,
    last_b_files INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);
"#;

const BASELINE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sync_baseline (
    nfc_path     TEXT PRIMARY KEY,
    flags        INTEGER NOT NULL,
    src_node_id  TEXT,
    dst_node_id  TEXT,
    size         INTEGER NOT NULL,
    src_mtime_ns INTEGER NOT NULL,
    dst_mtime_ns INTEGER NOT NULL,
    dst_etag     TEXT,
    hash_blob    BLOB,
    updated_at   INTEGER NOT NULL
) WITHOUT ROWID;
"#;

const INVENTORY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS change_tokens (
    remote_name  TEXT NOT NULL,
    principal    TEXT NOT NULL,
    corpus_id    TEXT NOT NULL,
    root_id      TEXT NOT NULL,
    token        TEXT NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (remote_name, principal, corpus_id, root_id)
);

CREATE TABLE IF NOT EXISTS gdrive_nodes (
    remote_name  TEXT NOT NULL,
    corpus_id    TEXT NOT NULL,
    file_id      TEXT NOT NULL,
    parent_id    TEXT,
    raw_name     TEXT NOT NULL,
    nfc_name     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    size         INTEGER NOT NULL DEFAULT 0,
    mtime_ns     INTEGER NOT NULL DEFAULT 0,
    md5          TEXT,
    trashed      INTEGER NOT NULL DEFAULT 0,
    generation   INTEGER NOT NULL DEFAULT 1,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (remote_name, corpus_id, file_id)
);
CREATE INDEX IF NOT EXISTS idx_gdrive_nodes_parent ON gdrive_nodes(remote_name, corpus_id, parent_id);
"#;

pub const EPHEMERAL_SRC_RAW_SCHEMA: &str = r#"
CREATE TABLE src_raw (
    id        INTEGER PRIMARY KEY,
    nfc_path  TEXT NOT NULL,
    raw_path  TEXT,
    node_id   TEXT,
    parent_id TEXT,
    flags     INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    ctime_ns  INTEGER,
    etag      TEXT,
    hash_blob BLOB
);
"#;

pub const EPHEMERAL_DST_RAW_SCHEMA: &str = r#"
CREATE TABLE dst_raw (
    id        INTEGER PRIMARY KEY,
    nfc_path  TEXT NOT NULL,
    raw_path  TEXT,
    node_id   TEXT,
    parent_id TEXT,
    flags     INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    ctime_ns  INTEGER,
    etag      TEXT,
    hash_blob BLOB
);
"#;

pub const EPHEMERAL_SORTED_BASE_SCHEMA: &str = r#"
CREATE TABLE sync_conflicts (
    id        INTEGER PRIMARY KEY,
    nfc_path  TEXT NOT NULL,
    kind      TEXT NOT NULL,
    detail    TEXT NOT NULL
);
"#;

pub const EPHEMERAL_BUILD_SRC_SORTED_FROM_ATTACH: &str = r#"
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

INSERT INTO src_sorted (
    nfc_path, id, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
)
SELECT
    nfc_path, id, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
FROM raw_src.src_raw
ORDER BY nfc_path ASC, id ASC;
"#;

pub const EPHEMERAL_BUILD_DST_SORTED_FROM_ATTACH: &str = r#"
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

INSERT INTO dst_sorted (
    nfc_path, id, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
)
SELECT
    nfc_path, id, raw_path, node_id, parent_id, flags, size, mtime_ns, ctime_ns, etag, hash_blob
FROM raw_dst.dst_raw
ORDER BY nfc_path ASC, id ASC;
"#;

pub(crate) fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if matches!(e.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn retry_on_busy<T, F>(mut op: F) -> rusqlite::Result<T>
where
    F: FnMut() -> rusqlite::Result<T>,
{
    const MAX_ATTEMPTS: u32 = 25;
    for attempt in 0..MAX_ATTEMPTS {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if is_sqlite_busy(&e) && attempt + 1 < MAX_ATTEMPTS => {
                let backoff_ms = 10u64.saturating_mul(u64::from(attempt + 1).min(20));
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop always returns before terminating")
}

struct ImmediateTxGuard<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> ImmediateTxGuard<'a> {
    fn begin(conn: &'a Connection) -> rusqlite::Result<Self> {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    fn commit(mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch("COMMIT;")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for ImmediateTxGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK;");
        }
    }
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )?;
    Ok(exists > 0)
}

fn any_table_exists(conn: &Connection, tables: &[&str]) -> rusqlite::Result<bool> {
    for &table in tables {
        if table_exists(conn, table)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table});"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version;", [], |r| r.get(0))
}

fn set_user_version(conn: &Connection, version: u32) -> rusqlite::Result<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {version};"))
}

fn version_too_new_error(label: &str, found: u32, supported: u32) -> Error {
    Error::state_store(format!(
        "cannot open {label}: database schema version {found} is newer than supported version {supported}; upgrade rship to open this state store"
    ))
}

enum SchemaTxErr {
    Sqlite(rusqlite::Error),
    Fatal(Error),
}

fn retry_schema_tx<F>(label: &str, mut op: F) -> Result<()>
where
    F: FnMut() -> std::result::Result<(), SchemaTxErr>,
{
    const MAX_ATTEMPTS: u32 = 25;
    for attempt in 0..MAX_ATTEMPTS {
        match op() {
            Ok(()) => return Ok(()),
            Err(SchemaTxErr::Sqlite(e)) if is_sqlite_busy(&e) && attempt + 1 < MAX_ATTEMPTS => {
                let backoff_ms = 10u64.saturating_mul(u64::from(attempt + 1).min(20));
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
            Err(SchemaTxErr::Sqlite(e)) => {
                return Err(Error::state_store(format!(
                    "init/migrate {label} schema: {e}"
                )));
            }
            Err(SchemaTxErr::Fatal(e)) => return Err(e),
        }
    }
    unreachable!("loop always returns before terminating")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SynchronousMode {
    Normal,
    Full,
}

impl SynchronousMode {
    const fn as_pragma(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Full => "FULL",
        }
    }
}

pub(crate) struct SchemaMigration {
    pub(crate) from_version: u32,
    pub(crate) to_version: u32,
    pub(crate) apply: fn(&Connection) -> rusqlite::Result<()>,
}

pub(crate) struct SchemaSpec<'a> {
    pub(crate) label: &'a str,
    pub(crate) current_version: u32,
    pub(crate) synchronous: SynchronousMode,
    pub(crate) page_size: Option<u32>,
    /// Tables whose presence indicates an existing unversioned v0.1.0 DB when `user_version == 0`.
    pub(crate) legacy_tables: &'a [&'a str],
    /// Full DDL for initializing a brand-new database directly at `current_version`.
    pub(crate) ddl: &'a str,
    /// Optional idempotent hook to bring an unversioned v0.1.0 DB (`user_version == 0` with
    /// existing tables) to a complete v1 schema before running `v1 -> current_version` migrations.
    pub(crate) ensure_v1: Option<fn(&Connection) -> rusqlite::Result<()>>,
    /// Ordered step-by-step migrations `(v -> v + 1)` from v1 up to `current_version`.
    pub(crate) migrations: &'a [SchemaMigration],
}

fn ensure_journal_v1_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(JOURNAL_SCHEMA)?;
    if table_exists(conn, "jobs")? {
        if !table_has_column(conn, "jobs", "options_json")? {
            conn.execute_batch("ALTER TABLE jobs ADD COLUMN options_json TEXT;")?;
        }
        if !table_has_column(conn, "jobs", "resume_cursor")? {
            conn.execute_batch("ALTER TABLE jobs ADD COLUMN resume_cursor TEXT;")?;
        }
    }
    Ok(())
}

fn configure_wal_db(conn: &Connection, spec: &SchemaSpec<'_>) -> Result<()> {
    let label = spec.label;
    conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
        .map_err(|e| Error::state_store(format!("configure {label} busy_timeout: {e}")))?;

    if let Some(ps) = spec.page_size {
        let _ = conn.execute_batch(&format!("PRAGMA page_size = {ps};"));
    }

    let pragmas = format!(
        "PRAGMA synchronous = {};
         PRAGMA wal_autocheckpoint = 2048;
         PRAGMA journal_size_limit = 16777216;
         PRAGMA foreign_keys = ON;
         PRAGMA cache_size = -4096;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;",
        spec.synchronous.as_pragma()
    );
    conn.execute_batch(&pragmas)
        .map_err(|e| Error::state_store(format!("configure {label} pragmas: {e}")))?;

    retry_on_busy(|| {
        let mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
            let _: String = conn.query_row("PRAGMA journal_mode = WAL;", [], |r| r.get(0))?;
        }
        Ok(())
    })
    .map_err(|e| Error::state_store(format!("configure {label} WAL mode: {e}")))?;

    // Fast path: read `PRAGMA user_version` without taking a write lock.
    let raw_version = retry_on_busy(|| read_user_version(conn))
        .map_err(|e| Error::state_store(format!("read {label} schema version: {e}")))?;
    if raw_version < 0 {
        return Err(Error::state_store(format!(
            "cannot open {label}: invalid negative database schema version {raw_version}"
        )));
    }
    let version = u32::try_from(raw_version).map_err(|_| {
        Error::state_store(format!(
            "cannot open {label}: out-of-range database schema version {raw_version}"
        ))
    })?;
    if version == spec.current_version {
        return Ok(());
    }
    if version > spec.current_version {
        return Err(version_too_new_error(label, version, spec.current_version));
    }

    retry_schema_tx(label, || {
        let tx = ImmediateTxGuard::begin(conn).map_err(SchemaTxErr::Sqlite)?;
        let raw = read_user_version(conn).map_err(SchemaTxErr::Sqlite)?;
        if raw < 0 {
            return Err(SchemaTxErr::Fatal(Error::state_store(format!(
                "cannot open {label}: invalid negative database schema version {raw}"
            ))));
        }
        let current = u32::try_from(raw).map_err(|_| {
            SchemaTxErr::Fatal(Error::state_store(format!(
                "cannot open {label}: out-of-range database schema version {raw}"
            )))
        })?;
        if current == spec.current_version {
            tx.commit().map_err(SchemaTxErr::Sqlite)?;
            return Ok(());
        }
        if current > spec.current_version {
            return Err(SchemaTxErr::Fatal(version_too_new_error(
                label,
                current,
                spec.current_version,
            )));
        }

        let mut ver = current;
        if ver == 0 {
            let has_existing =
                any_table_exists(conn, spec.legacy_tables).map_err(SchemaTxErr::Sqlite)?;
            if !has_existing {
                // Brand-new database: apply full DDL at `current_version` and stamp version.
                conn.execute_batch(spec.ddl).map_err(SchemaTxErr::Sqlite)?;
                set_user_version(conn, spec.current_version).map_err(SchemaTxErr::Sqlite)?;
                tx.commit().map_err(SchemaTxErr::Sqlite)?;
                return Ok(());
            }
            // Unversioned v0.1.0 database (`user_version == 0` with existing tables):
            // treat as version 1, ensure all v1 tables/columns exist, stamp v1, then run
            // any ordered migrations up to `current_version`.
            if let Some(ensure_v1) = spec.ensure_v1 {
                ensure_v1(conn).map_err(SchemaTxErr::Sqlite)?;
            } else {
                conn.execute_batch(spec.ddl).map_err(SchemaTxErr::Sqlite)?;
            }
            set_user_version(conn, 1).map_err(SchemaTxErr::Sqlite)?;
            ver = 1;
        }

        while ver < spec.current_version {
            let next = ver + 1;
            let migration = spec
                .migrations
                .iter()
                .find(|m| m.from_version == ver && m.to_version == next)
                .ok_or_else(|| {
                    SchemaTxErr::Fatal(Error::state_store(format!(
                        "missing schema migration for {label} from v{ver} to v{next}"
                    )))
                })?;
            (migration.apply)(conn).map_err(SchemaTxErr::Sqlite)?;
            set_user_version(conn, next).map_err(SchemaTxErr::Sqlite)?;
            ver = next;
        }

        tx.commit().map_err(SchemaTxErr::Sqlite)?;
        Ok(())
    })?;

    Ok(())
}

const JOURNAL_SPEC: SchemaSpec<'static> = SchemaSpec {
    label: "journal.db",
    current_version: JOURNAL_SCHEMA_VERSION,
    synchronous: SynchronousMode::Full,
    page_size: None,
    legacy_tables: &["jobs", "operations", "operation_parts", "bisync_state"],
    ddl: JOURNAL_SCHEMA,
    ensure_v1: Some(ensure_journal_v1_schema),
    migrations: &[],
};

const BASELINE_SPEC: SchemaSpec<'static> = SchemaSpec {
    label: "baseline.db",
    current_version: BASELINE_SCHEMA_VERSION,
    synchronous: SynchronousMode::Normal,
    page_size: Some(8192),
    legacy_tables: &["sync_baseline"],
    ddl: BASELINE_SCHEMA,
    ensure_v1: None,
    migrations: &[],
};

const INVENTORY_SPEC: SchemaSpec<'static> = SchemaSpec {
    label: "inventory.db",
    current_version: INVENTORY_SCHEMA_VERSION,
    synchronous: SynchronousMode::Normal,
    page_size: Some(8192),
    legacy_tables: &["gdrive_nodes", "change_tokens"],
    ddl: INVENTORY_SCHEMA,
    ensure_v1: None,
    migrations: &[],
};

pub fn configure_journal_db(conn: &Connection) -> Result<()> {
    configure_wal_db(conn, &JOURNAL_SPEC)
}

pub fn configure_baseline_db(conn: &Connection) -> Result<()> {
    configure_wal_db(conn, &BASELINE_SPEC)
}

pub fn configure_inventory_db(conn: &Connection) -> Result<()> {
    configure_wal_db(conn, &INVENTORY_SPEC)
}

pub fn configure_raw_ephemeral_db(conn: &Connection, ddl: &str) -> Result<()> {
    // Separate append-only raw ingest DB (`auto_vacuum = NONE`): zero pointer-map
    // overhead during inserts, and unlinked in O(1) via `remove_file` right after
    // external-sorting into `sorted.db`.
    conn.execute_batch(
        "PRAGMA page_size = 8192;
         PRAGMA auto_vacuum = NONE;
         PRAGMA journal_mode = OFF;
         PRAGMA synchronous = OFF;
         PRAGMA locking_mode = EXCLUSIVE;
         PRAGMA cache_size = -4096;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;",
    )
    .map_err(|e| Error::state_store(format!("configure raw ephemeral db pragmas: {e}")))?;
    conn.execute_batch(ddl)
        .map_err(|e| Error::state_store(format!("create raw ephemeral schema: {e}")))?;
    Ok(())
}

pub fn configure_sorted_ephemeral_db(conn: &Connection) -> Result<()> {
    // 8 KiB pages halve B-tree page splits on path-heavy trees while capping
    // SQLite's page cache at 8 MiB (`cache_size = -8192`). `auto_vacuum = NONE`
    // avoids pointer-map maintenance and backward page-shuffling because raw
    // ingest lives in separate files that are unlinked in O(1).
    conn.execute_batch(
        "PRAGMA page_size = 8192;
         PRAGMA auto_vacuum = NONE;
         PRAGMA journal_mode = OFF;
         PRAGMA synchronous = OFF;
         PRAGMA locking_mode = EXCLUSIVE;
         PRAGMA cache_size = -8192;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;",
    )
    .map_err(|e| Error::state_store(format!("configure sorted ephemeral db pragmas: {e}")))?;
    conn.execute_batch(EPHEMERAL_SORTED_BASE_SCHEMA)
        .map_err(|e| Error::state_store(format!("create sorted ephemeral schema: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::ErrorKind;
    use tempfile::TempDir;

    fn get_user_version(conn: &Connection) -> u32 {
        conn.query_row("PRAGMA user_version;", [], |r| r.get::<_, u32>(0))
            .unwrap()
    }

    #[test]
    fn d11_unversioned_v010_dbs_upgrade_and_stamp_user_version() {
        let dir = TempDir::new().unwrap();

        // 1. Unversioned v0.1.0 journal.db (`user_version = 0` with existing tables).
        let journal_path = dir.path().join("journal.db");
        {
            let conn = Connection::open(&journal_path).unwrap();
            conn.execute_batch(JOURNAL_SCHEMA).unwrap();
            assert_eq!(get_user_version(&conn), 0);
        }
        {
            let conn = Connection::open(&journal_path).unwrap();
            configure_journal_db(&conn).unwrap();
            assert_eq!(get_user_version(&conn), 1);
        }

        // 2. Unversioned v0.1.0 journal.db missing optional legacy column `options_json` & `resume_cursor`.
        let legacy_cols_path = dir.path().join("journal_legacy_cols.db");
        {
            let conn = Connection::open(&legacy_cols_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE jobs (
                    job_id      TEXT PRIMARY KEY,
                    mode        TEXT NOT NULL,
                    src_spec    TEXT NOT NULL,
                    dst_spec    TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    files_total INTEGER NOT NULL DEFAULT 0,
                    files_done  INTEGER NOT NULL DEFAULT 0,
                    bytes_total INTEGER NOT NULL DEFAULT 0,
                    bytes_done  INTEGER NOT NULL DEFAULT 0,
                    created_at  INTEGER NOT NULL,
                    updated_at  INTEGER NOT NULL
                 );
                 CREATE TABLE bisync_state (
                    pair_key     TEXT PRIMARY KEY,
                    filter_hash  TEXT NOT NULL,
                    last_a_files INTEGER NOT NULL DEFAULT 0,
                    last_b_files INTEGER NOT NULL DEFAULT 0,
                    updated_at   INTEGER NOT NULL
                 );",
            )
            .unwrap();
            assert_eq!(get_user_version(&conn), 0);
            configure_journal_db(&conn).unwrap();
            assert_eq!(get_user_version(&conn), 1);
            // Must be able to select newly ensured v1 columns without error.
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE options_json IS NULL AND resume_cursor IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }

        // 3. Unversioned baseline & inventory shards also stamp `user_version = 1`.
        let baseline_path = dir.path().join("baseline.db");
        {
            let conn = Connection::open(&baseline_path).unwrap();
            conn.execute_batch(BASELINE_SCHEMA).unwrap();
            assert_eq!(get_user_version(&conn), 0);
            configure_baseline_db(&conn).unwrap();
            assert_eq!(get_user_version(&conn), 1);
        }
        let inv_path = dir.path().join("inventory.db");
        {
            let conn = Connection::open(&inv_path).unwrap();
            conn.execute_batch(INVENTORY_SCHEMA).unwrap();
            assert_eq!(get_user_version(&conn), 0);
            configure_inventory_db(&conn).unwrap();
            assert_eq!(get_user_version(&conn), 1);
        }
    }

    #[test]
    fn d11_newer_schema_version_refuses_to_open() {
        let dir = TempDir::new().unwrap();

        let journal_path = dir.path().join("future_journal.db");
        {
            let conn = Connection::open(&journal_path).unwrap();
            conn.execute_batch(JOURNAL_SCHEMA).unwrap();
            conn.execute_batch("PRAGMA user_version = 999;").unwrap();
        }
        {
            let conn = Connection::open(&journal_path).unwrap();
            let err = configure_journal_db(&conn).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StateStore);
            assert!(
                err.message().contains("999"),
                "error should mention DB version 999: {}",
                err.message()
            );
        }

        let baseline_path = dir.path().join("future_baseline.db");
        {
            let conn = Connection::open(&baseline_path).unwrap();
            conn.execute_batch(BASELINE_SCHEMA).unwrap();
            conn.execute_batch("PRAGMA user_version = 999;").unwrap();
            let err = configure_baseline_db(&conn).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StateStore);
        }

        let inv_path = dir.path().join("future_inventory.db");
        {
            let conn = Connection::open(&inv_path).unwrap();
            conn.execute_batch(INVENTORY_SCHEMA).unwrap();
            conn.execute_batch("PRAGMA user_version = 999;").unwrap();
            let err = configure_inventory_db(&conn).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StateStore);
        }
    }

    #[test]
    fn d11_ordered_migration_runner_executes_step_by_step_and_updates_user_version() {
        const V1_DDL: &str = "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                              CREATE TABLE IF NOT EXISTS mig_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, step TEXT NOT NULL);";
        const V3_DDL: &str = "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, v2_tag TEXT, v3_tag TEXT);
                              CREATE TABLE IF NOT EXISTS mig_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, step TEXT NOT NULL);";

        fn ensure_v1(conn: &Connection) -> rusqlite::Result<()> {
            conn.execute_batch(V1_DDL)
        }
        fn migrate_1_to_2(conn: &Connection) -> rusqlite::Result<()> {
            conn.execute_batch(
                "ALTER TABLE items ADD COLUMN v2_tag TEXT;
                 UPDATE items SET v2_tag = name || ':v2';
                 INSERT INTO mig_log (step) VALUES ('1->2');",
            )
        }
        fn migrate_2_to_3(conn: &Connection) -> rusqlite::Result<()> {
            conn.execute_batch(
                "ALTER TABLE items ADD COLUMN v3_tag TEXT;
                 UPDATE items SET v3_tag = v2_tag || ':v3';
                 INSERT INTO mig_log (step) VALUES ('2->3');",
            )
        }

        const SPEC_V3: SchemaSpec<'static> = SchemaSpec {
            label: "test_mig.db",
            current_version: 3,
            synchronous: SynchronousMode::Full,
            page_size: None,
            legacy_tables: &["items"],
            ddl: V3_DDL,
            ensure_v1: Some(ensure_v1),
            migrations: &[
                SchemaMigration {
                    from_version: 1,
                    to_version: 2,
                    apply: migrate_1_to_2,
                },
                SchemaMigration {
                    from_version: 2,
                    to_version: 3,
                    apply: migrate_2_to_3,
                },
            ],
        };

        let read_steps = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn
                .prepare("SELECT step FROM mig_log ORDER BY seq ASC")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };

        // Case 1: Unversioned v0.1.0 DB (`user_version = 0` with existing `items`) upgrades 1 -> 2 -> 3 in order.
        {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(V1_DDL).unwrap();
            conn.execute("INSERT INTO items (id, name) VALUES (1, 'alpha')", [])
                .unwrap();
            assert_eq!(read_user_version(&conn).unwrap(), 0);

            configure_wal_db(&conn, &SPEC_V3).unwrap();

            assert_eq!(read_user_version(&conn).unwrap(), 3);
            assert_eq!(read_steps(&conn), vec!["1->2", "2->3"]);
            let v3_tag: String = conn
                .query_row("SELECT v3_tag FROM items WHERE id = 1", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v3_tag, "alpha:v2:v3");

            // Case 3: Re-opening at current version takes the fast path (no duplicate migrations).
            configure_wal_db(&conn, &SPEC_V3).unwrap();
            assert_eq!(read_user_version(&conn).unwrap(), 3);
            assert_eq!(read_steps(&conn), vec!["1->2", "2->3"]);
        }

        // Case 2: DB already at v2 executes only `2->3`.
        {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(V1_DDL).unwrap();
            conn.execute("INSERT INTO items (id, name) VALUES (1, 'beta')", [])
                .unwrap();
            conn.execute_batch(
                "ALTER TABLE items ADD COLUMN v2_tag TEXT;
                 UPDATE items SET v2_tag = 'beta:v2';
                 PRAGMA user_version = 2;",
            )
            .unwrap();

            configure_wal_db(&conn, &SPEC_V3).unwrap();

            assert_eq!(read_user_version(&conn).unwrap(), 3);
            assert_eq!(read_steps(&conn), vec!["2->3"]);
            let v3_tag: String = conn
                .query_row("SELECT v3_tag FROM items WHERE id = 1", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v3_tag, "beta:v2:v3");
        }

        // Case 4: Brand-new DB applies full V3 DDL directly without running incremental migrations.
        {
            let conn = Connection::open_in_memory().unwrap();
            configure_wal_db(&conn, &SPEC_V3).unwrap();
            assert_eq!(read_user_version(&conn).unwrap(), 3);
            assert!(read_steps(&conn).is_empty());
            assert!(table_has_column(&conn, "items", "v3_tag").unwrap());
        }

        // Case 5: Failure mid-migration rolls back both earlier migration steps and `user_version`.
        {
            fn failing_2_to_3(conn: &Connection) -> rusqlite::Result<()> {
                conn.execute_batch("THIS IS INVALID SQL;")
            }
            const SPEC_FAIL: SchemaSpec<'static> = SchemaSpec {
                label: "test_mig_fail.db",
                current_version: 3,
                synchronous: SynchronousMode::Full,
                page_size: None,
                legacy_tables: &["items"],
                ddl: V3_DDL,
                ensure_v1: Some(ensure_v1),
                migrations: &[
                    SchemaMigration {
                        from_version: 1,
                        to_version: 2,
                        apply: migrate_1_to_2,
                    },
                    SchemaMigration {
                        from_version: 2,
                        to_version: 3,
                        apply: failing_2_to_3,
                    },
                ],
            };
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(V1_DDL).unwrap();
            conn.execute_batch("PRAGMA user_version = 1;").unwrap();

            let err = configure_wal_db(&conn, &SPEC_FAIL).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StateStore);
            assert_eq!(
                read_user_version(&conn).unwrap(),
                1,
                "failed migration must roll back user_version atomically"
            );
            assert!(
                !table_has_column(&conn, "items", "v2_tag").unwrap(),
                "failed migration must roll back earlier migration DDL atomically"
            );
        }
    }
}
