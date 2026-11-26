//! Dedicated `std::thread` split-database SQLite `StateActor` with group-commit coalescing.
//!
//! Layout under `<state_dir>`:
//! - `journal.db`: tiny WAL-mode DB for `jobs`, active `operations`, and `operation_parts`.
//! - `baselines/<pair_key>.db`: lazily created per-pair `WITHOUT ROWID` DB storing compact
//!   binary `sync_baseline` rows (sorted by `nfc_path` on every group-commit batch, zero
//!   secondary indexes, O(1) unlink on `delete_pair_baselines`).
//! - `inventory/<scope>.db`: lazily created per-`(remote_name, corpus_id)` delta inventory DB.

mod baselines;
mod delta;
#[cfg(test)]
mod tests;
mod worker;

use async_trait::async_trait;
use rship_core::backend::CompletedPart;
use rship_core::path::RelPath;
use rship_core::state::{
    BaselineRecord, BisyncPairState, DeltaChangeBatch, DeltaInventoryStore, DeltaNodeRecord,
    DeltaScope, JobRecord, JournalStore, OperationRecord,
};
use rship_core::{Error, Result};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, mpsc as std_mpsc};
use tokio::sync::oneshot;

use crate::schema::{configure_baseline_db, configure_inventory_db, configure_journal_db};

pub(super) const MAX_GROUP_COMMIT_BATCH: usize = 2048;
const ACTOR_CHANNEL_CAPACITY: usize = 4096;
const MAX_OPEN_SHARD_CONNS: usize = 8;

pub(super) enum Cmd {
    Write(Box<WriteCmd>, oneshot::Sender<Result<()>>),
    GetJob(String, oneshot::Sender<Result<Option<JobRecord>>>),
    ListJobs(usize, oneshot::Sender<Result<Vec<JobRecord>>>),
    GetOpByKey(String, oneshot::Sender<Result<Option<OperationRecord>>>),
    ListActiveOps(oneshot::Sender<Result<Vec<OperationRecord>>>),
    ListParts(String, oneshot::Sender<Result<Vec<CompletedPart>>>),
    GetBaseline(
        String,
        RelPath,
        oneshot::Sender<Result<Option<BaselineRecord>>>,
    ),
    GetBaselinesBatch(
        String,
        Vec<RelPath>,
        oneshot::Sender<Result<HashMap<RelPath, BaselineRecord>>>,
    ),
    NextBaselinePage(
        String,
        Option<String>,
        usize,
        oneshot::Sender<Result<Vec<BaselineRecord>>>,
    ),
    GetBisyncState(String, oneshot::Sender<Result<Option<BisyncPairState>>>),
    GetChangeToken(DeltaScope, oneshot::Sender<Result<Option<String>>>),
    GetGdriveNode(
        String,
        String,
        String,
        oneshot::Sender<Result<Option<DeltaNodeRecord>>>,
    ),
    GetGdriveNodesBatch(
        String,
        String,
        Vec<String>,
        oneshot::Sender<Result<HashMap<String, DeltaNodeRecord>>>,
    ),
    ListGdriveChildren(
        String,
        String,
        String,
        oneshot::Sender<Result<Vec<DeltaNodeRecord>>>,
    ),
    FindGdriveChildrenByName(
        String,
        String,
        String,
        String,
        oneshot::Sender<Result<Vec<DeltaNodeRecord>>>,
    ),
    ListAllGdriveNodes(
        String,
        String,
        oneshot::Sender<Result<Vec<DeltaNodeRecord>>>,
    ),
    Flush(oneshot::Sender<Result<()>>),
    #[cfg(test)]
    JournalSynchronousMode(oneshot::Sender<Result<i64>>),
    Shutdown(oneshot::Sender<Result<()>>),
}

pub(super) enum WriteCmd {
    UpsertJob(Box<JobRecord>),
    PutOperation(Box<OperationRecord>),
    DeleteOperation(String),
    UpsertPart(String, CompletedPart),
    CommitVerifiedTransfer {
        op_id: Option<String>,
        baseline: Option<Box<BaselineRecord>>,
        job_id: String,
        bytes_transferred: u64,
    },
    DeleteBaseline(String, RelPath),
    DeleteBaselinesBatch(String, Vec<RelPath>),
    DeletePairBaselines(String),
    UpsertBisyncState(Box<BisyncPairState>),
    ApplyGdriveChangeBatch(DeltaScope, DeltaChangeBatch),
    ClearGdriveInventory(DeltaScope),
}

#[derive(Default)]
pub(super) struct ActiveOpIndex {
    op_to_key: HashMap<String, String>,
    key_counts: HashMap<String, usize>,
}

impl ActiveOpIndex {
    fn from_conn(conn: &Connection) -> Result<Self> {
        let mut idx = Self::default();
        let mut stmt = conn
            .prepare("SELECT op_id, session_key FROM operations")
            .map_err(|e| Error::state_store(format!("preload active ops: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| Error::state_store(format!("query active ops: {e}")))?;
        for r in rows {
            let (op_id, key) = r.map_err(|e| Error::state_store(format!("read active op: {e}")))?;
            idx.insert(op_id, key);
        }
        Ok(idx)
    }

    pub(super) fn insert(&mut self, op_id: String, session_key: String) {
        if let Some(old_key) = self.op_to_key.insert(op_id, session_key.clone()) {
            if old_key == session_key {
                return;
            }
            self.dec_key(&old_key);
        }
        *self.key_counts.entry(session_key).or_insert(0) += 1;
    }

    pub(super) fn remove(&mut self, op_id: &str) {
        if let Some(old_key) = self.op_to_key.remove(op_id) {
            self.dec_key(&old_key);
        }
    }

    fn dec_key(&mut self, key: &str) {
        if let Some(cnt) = self.key_counts.get_mut(key) {
            if *cnt <= 1 {
                self.key_counts.remove(key);
            } else {
                *cnt -= 1;
            }
        }
    }

    fn contains_key(&self, session_key: &str) -> bool {
        self.key_counts.contains_key(session_key)
    }
}

pub(super) enum OpIndexDelta {
    Put(String, String),
    Remove(String),
}

pub(super) enum StorageMode {
    Disk(PathBuf),
    Memory,
}

pub(super) struct ShardEntry {
    pub(super) conn: Connection,
    pub(super) last_used: u64,
}

pub(super) struct ActorState {
    pub(super) storage: StorageMode,
    pub(super) journal: Connection,
    pub(super) baselines: HashMap<String, ShardEntry>,
    pub(super) inventories: HashMap<String, ShardEntry>,
    pub(super) known_baseline_pairs: Arc<RwLock<HashSet<String>>>,
    pub(super) tick: u64,
}

impl ActorState {
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn baseline_path(&self, pair_key: &str) -> Option<PathBuf> {
        match &self.storage {
            StorageMode::Disk(root) => Some(root.join("baselines").join(shard_filename(pair_key))),
            StorageMode::Memory => None,
        }
    }

    fn inventory_path(&self, inv_key: &str) -> Option<PathBuf> {
        match &self.storage {
            StorageMode::Disk(root) => Some(root.join("inventory").join(shard_filename(inv_key))),
            StorageMode::Memory => None,
        }
    }

    pub(super) fn get_baseline_conn_existing(
        &mut self,
        pair_key: &str,
    ) -> Result<Option<&mut Connection>> {
        if self.baselines.contains_key(pair_key) {
            let t = self.next_tick();
            let entry = self.baselines.get_mut(pair_key).unwrap();
            entry.last_used = t;
            return Ok(Some(&mut entry.conn));
        }
        let Some(path) = self.baseline_path(pair_key) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        self.open_baseline_conn(pair_key).map(Some)
    }

    pub(super) fn open_baseline_conn(&mut self, pair_key: &str) -> Result<&mut Connection> {
        if self.baselines.contains_key(pair_key) {
            let t = self.next_tick();
            let entry = self.baselines.get_mut(pair_key).unwrap();
            entry.last_used = t;
            return Ok(&mut entry.conn);
        }

        if matches!(self.storage, StorageMode::Disk(_))
            && self.baselines.len() >= MAX_OPEN_SHARD_CONNS
        {
            evict_oldest_shard(&mut self.baselines);
        }

        let conn = match self.baseline_path(pair_key) {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        Error::io(format!("create baselines dir `{}`", parent.display()), e)
                    })?;
                }
                let c = Connection::open(&path).map_err(|e| {
                    Error::state_store(format!("open baseline db `{}`: {e}", path.display()))
                })?;
                configure_baseline_db(&c)?;
                c
            }
            None => {
                let c = Connection::open_in_memory()
                    .map_err(|e| Error::state_store(format!("open mem baseline db: {e}")))?;
                configure_baseline_db(&c)?;
                c
            }
        };

        let t = self.next_tick();
        self.baselines
            .insert(pair_key.to_string(), ShardEntry { conn, last_used: t });
        if let Ok(mut known) = self.known_baseline_pairs.write() {
            known.insert(shard_stem(pair_key));
        }
        Ok(&mut self.baselines.get_mut(pair_key).unwrap().conn)
    }

    pub(super) fn delete_baseline_shard(&mut self, pair_key: &str) -> Result<()> {
        // Close handle first (required on Windows before unlinking files).
        self.baselines.remove(pair_key);
        if let Some(path) = self.baseline_path(pair_key) {
            remove_sqlite_files(&path)?;
        }
        if let Ok(mut known) = self.known_baseline_pairs.write() {
            known.remove(&shard_stem(pair_key));
        }
        Ok(())
    }

    pub(super) fn get_inventory_conn_existing(
        &mut self,
        remote_name: &str,
        corpus_id: &str,
    ) -> Result<Option<&mut Connection>> {
        let key = inventory_shard_key(remote_name, corpus_id);
        if self.inventories.contains_key(&key) {
            let t = self.next_tick();
            let entry = self.inventories.get_mut(&key).unwrap();
            entry.last_used = t;
            return Ok(Some(&mut entry.conn));
        }
        let Some(path) = self.inventory_path(&key) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        self.open_inventory_conn(remote_name, corpus_id).map(Some)
    }

    pub(super) fn open_inventory_conn(
        &mut self,
        remote_name: &str,
        corpus_id: &str,
    ) -> Result<&mut Connection> {
        let key = inventory_shard_key(remote_name, corpus_id);
        if self.inventories.contains_key(&key) {
            let t = self.next_tick();
            let entry = self.inventories.get_mut(&key).unwrap();
            entry.last_used = t;
            return Ok(&mut entry.conn);
        }

        if matches!(self.storage, StorageMode::Disk(_))
            && self.inventories.len() >= MAX_OPEN_SHARD_CONNS
        {
            evict_oldest_shard(&mut self.inventories);
        }

        let conn = match self.inventory_path(&key) {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        Error::io(format!("create inventory dir `{}`", parent.display()), e)
                    })?;
                }
                let c = Connection::open(&path).map_err(|e| {
                    Error::state_store(format!("open inventory db `{}`: {e}", path.display()))
                })?;
                configure_inventory_db(&c)?;
                c
            }
            None => {
                let c = Connection::open_in_memory()
                    .map_err(|e| Error::state_store(format!("open mem inventory db: {e}")))?;
                configure_inventory_db(&c)?;
                c
            }
        };

        let t = self.next_tick();
        self.inventories
            .insert(key.clone(), ShardEntry { conn, last_used: t });
        Ok(&mut self.inventories.get_mut(&key).unwrap().conn)
    }

    pub(super) fn checkpoint_all(&mut self) -> Result<()> {
        let mut first_err: Option<Error> = None;
        if let Err(e) = checkpoint_wal(&self.journal) {
            first_err = Some(e);
        }
        for shard in self.baselines.values() {
            if let Err(e) = checkpoint_wal(&shard.conn)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        for shard in self.inventories.values() {
            if let Err(e) = checkpoint_wal(&shard.conn)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

pub(super) fn checkpoint_wal(conn: &Connection) -> Result<()> {
    let busy: i64 = match conn.query_row("PRAGMA wal_checkpoint(PASSIVE);", [], |r| r.get(0)) {
        Ok(b) => b,
        Err(e) if crate::schema::is_sqlite_busy(&e) => return Ok(()),
        Err(e) => return Err(Error::state_store(format!("wal passive checkpoint: {e}"))),
    };
    if busy == 0 {
        let _ = conn.busy_timeout(std::time::Duration::from_millis(50));
        let truncate_res = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |r| {
            r.get::<_, i64>(0)
        });
        let _ = conn.busy_timeout(crate::schema::STATE_DB_BUSY_TIMEOUT);
        if let Err(e) = truncate_res
            && !crate::schema::is_sqlite_busy(&e)
        {
            return Err(Error::state_store(format!("wal truncate checkpoint: {e}")));
        }
    }
    Ok(())
}

fn evict_oldest_shard(map: &mut HashMap<String, ShardEntry>) {
    let oldest_key = map
        .iter()
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(k, _)| k.clone());
    if let Some(k) = oldest_key
        && let Some(entry) = map.remove(&k)
    {
        let _ = checkpoint_wal(&entry.conn);
    }
}

fn remove_sqlite_files(db_path: &Path) -> Result<()> {
    // Delete companion `-wal` and `-shm` files BEFORE the main `.db` file so a
    // partial failure or concurrent reopen can never replay an orphaned WAL onto
    // a newly created database at the same path.
    for suffix in ["-wal", "-shm", ""] {
        let p = if suffix.is_empty() {
            db_path.to_path_buf()
        } else {
            let mut os = db_path.as_os_str().to_os_string();
            os.push(suffix);
            PathBuf::from(os)
        };
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::io(
                    format!("remove sqlite file `{}`", p.display()),
                    e,
                ));
            }
        }
    }
    Ok(())
}

fn shard_stem(key: &str) -> String {
    if !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        key.to_string()
    } else {
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        hex::encode(h.finalize())
    }
}

fn shard_filename(key: &str) -> String {
    format!("{}.db", shard_stem(key))
}

fn scan_existing_baseline_stems(state_dir: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    let dir = state_dir.join("baselines");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return set;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path.extension().and_then(|e| e.to_str()) == Some("db")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            set.insert(stem.to_string());
        }
    }
    set
}

fn inventory_shard_key(remote_name: &str, corpus_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(remote_name.as_bytes());
    h.update([0u8]);
    h.update(corpus_id.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Clone)]
pub struct StateActor {
    tx: std_mpsc::SyncSender<Cmd>,
    active_ops: Arc<RwLock<ActiveOpIndex>>,
    known_baseline_pairs: Arc<RwLock<HashSet<String>>>,
    join_handle: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl StateActor {
    /// Open (or initialize) the split SQLite state store under `state_dir`:
    /// `<state_dir>/journal.db`, `<state_dir>/baselines/<pair_key>.db`, and
    /// `<state_dir>/inventory/<scope>.db`.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| Error::io(format!("create state dir `{}`", state_dir.display()), e))?;
        let journal_path = state_dir.join("journal.db");
        let journal = Connection::open(&journal_path)
            .map_err(|e| Error::state_store(format!("open `{}`: {e}", journal_path.display())))?;
        configure_journal_db(&journal)?;
        let active_ops = Arc::new(RwLock::new(ActiveOpIndex::from_conn(&journal)?));
        let active_ops_thread = active_ops.clone();
        let known_baseline_pairs = Arc::new(RwLock::new(scan_existing_baseline_stems(state_dir)));

        let state = ActorState {
            storage: StorageMode::Disk(state_dir.to_path_buf()),
            journal,
            baselines: HashMap::new(),
            inventories: HashMap::new(),
            known_baseline_pairs: known_baseline_pairs.clone(),
            tick: 0,
        };

        let (tx, rx) = std_mpsc::sync_channel::<Cmd>(ACTOR_CHANNEL_CAPACITY);
        let handle = std::thread::Builder::new()
            .name("rship-state-actor".into())
            .spawn(move || worker::actor_loop(state, rx, active_ops_thread))
            .map_err(|e| Error::io("spawn state actor thread", e))?;

        Ok(Self {
            tx,
            active_ops,
            known_baseline_pairs,
            join_handle: Arc::new(std::sync::Mutex::new(Some(handle))),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let journal = Connection::open_in_memory()
            .map_err(|e| Error::state_store(format!("open in-memory journal sqlite: {e}")))?;
        configure_journal_db(&journal)?;
        let active_ops = Arc::new(RwLock::new(ActiveOpIndex::default()));
        let active_ops_thread = active_ops.clone();
        let known_baseline_pairs = Arc::new(RwLock::new(HashSet::new()));

        let state = ActorState {
            storage: StorageMode::Memory,
            journal,
            baselines: HashMap::new(),
            inventories: HashMap::new(),
            known_baseline_pairs: known_baseline_pairs.clone(),
            tick: 0,
        };

        let (tx, rx) = std_mpsc::sync_channel::<Cmd>(ACTOR_CHANNEL_CAPACITY);
        let handle = std::thread::Builder::new()
            .name("rship-state-actor-mem".into())
            .spawn(move || worker::actor_loop(state, rx, active_ops_thread))
            .map_err(|e| Error::io("spawn mem state actor thread", e))?;
        Ok(Self {
            tx,
            active_ops,
            known_baseline_pairs,
            join_handle: Arc::new(std::sync::Mutex::new(Some(handle))),
        })
    }

    fn has_baseline_shard(&self, pair_key: &str) -> bool {
        let stem = shard_stem(pair_key);
        self.known_baseline_pairs
            .read()
            .map(|set| set.contains(&stem))
            .unwrap_or(true)
    }

    /// Wait until all preceding queued writes have been committed to SQLite and
    /// checkpoint open WAL files (`PRAGMA wal_checkpoint(TRUNCATE)`).
    pub async fn flush(&self) -> Result<()> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::Flush(otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    #[cfg(test)]
    pub(crate) async fn journal_synchronous_mode(&self) -> Result<i64> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::JournalSynchronousMode(otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    /// Gracefully flush WAL checkpoints and join the background SQLite thread.
    pub async fn shutdown(&self) -> Result<()> {
        let (otx, orx) = oneshot::channel();
        let mut flush_res = Ok(());
        if self.tx.send(Cmd::Shutdown(otx)).is_ok()
            && let Ok(res) = orx.await
        {
            flush_res = res;
        }
        let handle = self
            .join_handle
            .lock()
            .expect("state actor join mutex poisoned")
            .take();
        if let Some(h) = handle {
            let join_res = tokio::task::spawn_blocking(move || h.join())
                .await
                .map_err(|e| Error::state_store(format!("join state actor task: {e}")))?;
            if let Err(payload) = join_res {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic payload".to_string()
                };
                return Err(Error::state_store(format!(
                    "state actor thread panicked: {msg}"
                )));
            }
        }
        flush_res
    }

    async fn send_write(&self, w: WriteCmd) -> Result<()> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::Write(Box::new(w), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }
}

#[async_trait]
impl JournalStore for StateActor {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()> {
        self.send_write(WriteCmd::UpsertJob(Box::new(job.clone())))
            .await
    }

    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetJob(job_id.to_string(), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::ListJobs(limit, otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn put_operation(&self, op: &OperationRecord) -> Result<()> {
        self.send_write(WriteCmd::PutOperation(Box::new(op.clone())))
            .await
    }

    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>> {
        if let Ok(idx) = self.active_ops.read()
            && !idx.contains_key(session_key)
        {
            return Ok(None);
        }
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetOpByKey(session_key.to_string(), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::ListActiveOps(otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn delete_operation(&self, op_id: &str) -> Result<()> {
        self.send_write(WriteCmd::DeleteOperation(op_id.to_string()))
            .await
    }

    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()> {
        self.send_write(WriteCmd::UpsertPart(op_id.to_string(), part.clone()))
            .await
    }

    async fn list_parts(&self, op_id: &str) -> Result<Vec<CompletedPart>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::ListParts(op_id.to_string(), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn commit_verified_transfer(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()> {
        self.send_write(WriteCmd::CommitVerifiedTransfer {
            op_id: op_id.map(str::to_string),
            baseline: baseline.map(|b| Box::new(b.clone())),
            job_id: job_id.to_string(),
            bytes_transferred,
        })
        .await
    }

    async fn get_baseline(
        &self,
        pair_key: &str,
        nfc_path: &RelPath,
    ) -> Result<Option<BaselineRecord>> {
        if !self.has_baseline_shard(pair_key) {
            return Ok(None);
        }
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetBaseline(
                pair_key.to_string(),
                nfc_path.clone(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn get_baselines_batch(
        &self,
        pair_key: &str,
        nfc_paths: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        if nfc_paths.is_empty() || !self.has_baseline_shard(pair_key) {
            return Ok(HashMap::new());
        }
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetBaselinesBatch(
                pair_key.to_string(),
                nfc_paths.to_vec(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn delete_baseline(&self, pair_key: &str, nfc_path: &RelPath) -> Result<()> {
        if !self.has_baseline_shard(pair_key) {
            return Ok(());
        }
        self.send_write(WriteCmd::DeleteBaseline(
            pair_key.to_string(),
            nfc_path.clone(),
        ))
        .await
    }

    async fn delete_baselines_batch(&self, pair_key: &str, nfc_paths: &[RelPath]) -> Result<()> {
        if nfc_paths.is_empty() || !self.has_baseline_shard(pair_key) {
            return Ok(());
        }
        self.send_write(WriteCmd::DeleteBaselinesBatch(
            pair_key.to_string(),
            nfc_paths.to_vec(),
        ))
        .await
    }

    async fn delete_pair_baselines(&self, pair_key: &str) -> Result<()> {
        self.send_write(WriteCmd::DeletePairBaselines(pair_key.to_string()))
            .await
    }

    async fn next_baseline_page(
        &self,
        pair_key: &str,
        after_nfc_path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        if limit == 0 || !self.has_baseline_shard(pair_key) {
            return Ok(Vec::new());
        }
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::NextBaselinePage(
                pair_key.to_string(),
                after_nfc_path.map(str::to_string),
                limit,
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn get_bisync_state(&self, pair_key: &str) -> Result<Option<BisyncPairState>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetBisyncState(pair_key.to_string(), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        self.send_write(WriteCmd::UpsertBisyncState(Box::new(state.clone())))
            .await
    }
}

#[async_trait]
impl DeltaInventoryStore for StateActor {
    async fn get_change_token(&self, scope: &DeltaScope) -> Result<Option<String>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetChangeToken(scope.clone(), otx))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn apply_change_batch(&self, scope: &DeltaScope, batch: DeltaChangeBatch) -> Result<()> {
        self.send_write(WriteCmd::ApplyGdriveChangeBatch(scope.clone(), batch))
            .await
    }

    async fn get_node(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_id: &str,
    ) -> Result<Option<DeltaNodeRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetGdriveNode(
                remote_name.to_string(),
                corpus_id.to_string(),
                file_id.to_string(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn get_nodes_batch(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_ids: &[String],
    ) -> Result<HashMap<String, DeltaNodeRecord>> {
        if file_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::GetGdriveNodesBatch(
                remote_name.to_string(),
                corpus_id.to_string(),
                file_ids.to_vec(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn list_children(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::ListGdriveChildren(
                remote_name.to_string(),
                corpus_id.to_string(),
                parent_id.to_string(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn find_children_by_name(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
        name: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::FindGdriveChildrenByName(
                remote_name.to_string(),
                corpus_id.to_string(),
                parent_id.to_string(),
                name.to_string(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn list_all_nodes(
        &self,
        remote_name: &str,
        corpus_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Cmd::ListAllGdriveNodes(
                remote_name.to_string(),
                corpus_id.to_string(),
                otx,
            ))
            .map_err(|_| Error::state_store("state actor stopped"))?;
        orx.await
            .map_err(|_| Error::state_store("state actor dropped reply"))?
    }

    async fn clear_inventory(&self, scope: &DeltaScope) -> Result<()> {
        self.send_write(WriteCmd::ClearGdriveInventory(scope.clone()))
            .await
    }
}
