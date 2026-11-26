//! D2 batch durability: no journal record that lets a later run trust a destination file
//! (baseline row, operation retirement, finished job / bisync state) may be committed before
//! that file's data was flushed by `flush_durable_writes` (or synced by `sync_durable_file`).
//!
//! The destination wrapper defers durability like `LocalBackend` in `FsyncMode::Batch` and
//! logs every write and flush; the journal wrapper logs every trust record. The checker
//! replays the shared log in order.

use super::super::*;
use crate::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
    UploadProgress, UploadSessionInit,
};
use crate::bisync::{BisyncConfig, BisyncEngine};
use crate::chaos::ChaosBackend;
use crate::clock::VirtualClock;
use crate::path::RelPath;
use crate::source::{ByteStream, DataSource};
use crate::state::{
    BisyncPairState, DiffRow, JobMode, JobStatus, MemoryJournalStore, MemorySyncIndex,
    OperationRecord, SyncConflict,
};
use crate::types::{ByteRange, Capabilities, Checksum, Entry, HashKind};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Log = Arc<StdMutex<Vec<String>>>;

fn push(log: &Log, ev: String) {
    log.lock().unwrap().push(ev);
}

/// Destination that defers durability until `flush_durable_writes`.
struct DeferringDst {
    inner: Arc<ChaosBackend>,
    log: Log,
    fail_flush: AtomicBool,
    /// Cancel `cancel` once this many files were written (0 = never).
    cancel_after_writes: usize,
    writes: AtomicUsize,
    cancel: CancelFlag,
}

impl DeferringDst {
    fn new(name: &str, log: &Log) -> Self {
        Self {
            inner: Arc::new(ChaosBackend::parallel_s3_like(name, 64 * 1024)),
            log: log.clone(),
            fail_flush: AtomicBool::new(false),
            cancel_after_writes: 0,
            writes: AtomicUsize::new(0),
            cancel: CancelFlag::new(),
        }
    }

    fn wrote(&self, path: &RelPath) {
        push(&self.log, format!("write:{path}"));
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.cancel_after_writes > 0 && n == self.cancel_after_writes {
            self.cancel.cancel();
        }
    }
}

#[async_trait]
impl StorageBackend for DeferringDst {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn kind(&self) -> &'static str {
        "local"
    }
    fn endpoint_identity(&self) -> String {
        format!("deferring://{}", self.inner.name())
    }
    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.capabilities();
        caps.supports_ordered_utf8_list = false;
        caps.supports_server_side_copy = false;
        caps
    }
    fn defers_durable_writes(&self) -> bool {
        true
    }
    async fn flush_durable_writes(&self) -> Result<()> {
        if self.fail_flush.load(Ordering::SeqCst) {
            push(&self.log, "flush-failed".into());
            return Err(Error::new(
                ErrorKind::Io,
                RetryClass::Permanent,
                "injected EIO from syncfs",
            ));
        }
        push(&self.log, "flush".into());
        Ok(())
    }
    async fn sync_durable_file(&self, path: &BackendPath) -> Result<()> {
        push(&self.log, format!("sync:{}", path.nfc_path));
        Ok(())
    }
    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        self.inner.stat(path).await
    }
    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.inner.list_stream(prefix, recursive).await
    }
    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        self.inner.mkdir(path).await
    }
    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.inner.delete(path).await
    }
    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.inner.compute_hash(path, kind).await
    }
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.inner.open_read(path, range).await
    }
    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        let e = self.inner.put_single_shot(init, body).await?;
        self.wrote(&init.dst_path);
        Ok(e)
    }
    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.inner.begin_upload(init).await
    }
    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        self.inner.query_upload(op).await
    }
    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
        self.inner.upload_chunk(op, chunk).await
    }
    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        let e = self.inner.finish_upload(op, parts).await?;
        self.wrote(&op.dst_nfc_path);
        Ok(e)
    }
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.inner.abort_upload(op).await
    }
    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.inner.reconcile_operation(op).await
    }
}

/// Journal that logs every record a later run would trust.
struct RecordingJournal {
    inner: MemoryJournalStore,
    log: Log,
    op_paths: StdMutex<HashMap<String, RelPath>>,
}

impl RecordingJournal {
    fn new(log: &Log) -> Self {
        Self {
            inner: MemoryJournalStore::new(),
            log: log.clone(),
            op_paths: StdMutex::new(HashMap::new()),
        }
    }

    fn log_commit(&self, tag: &str, op_id: Option<&str>, baseline: Option<&BaselineRecord>) {
        if let Some(b) = baseline {
            push(&self.log, format!("{tag}:{}", b.nfc_path));
        } else if let Some(id) = op_id
            && let Some(p) = self.op_paths.lock().unwrap().get(id)
        {
            push(&self.log, format!("{tag}:{p}"));
        }
    }
}

#[async_trait]
impl JournalStore for RecordingJournal {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()> {
        if job.status != JobStatus::Running {
            push(&self.log, format!("job:{}", job.status.as_str()));
        }
        self.inner.upsert_job(job).await
    }
    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>> {
        self.inner.get_job(job_id).await
    }
    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        self.inner.list_jobs(limit).await
    }
    async fn put_operation(&self, op: &OperationRecord) -> Result<()> {
        // Session keys are scoped by endpoint; strip the job prefix down to the dst path.
        self.op_paths
            .lock()
            .unwrap()
            .insert(op.op_id.clone(), op.dst_nfc_path.clone());
        self.inner.put_operation(op).await
    }
    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>> {
        self.inner.get_operation_by_key(session_key).await
    }
    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>> {
        self.inner.list_active_operations().await
    }
    async fn delete_operation(&self, op_id: &str) -> Result<()> {
        self.inner.delete_operation(op_id).await
    }
    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()> {
        self.inner.upsert_part(op_id, part).await
    }
    async fn list_parts(&self, op_id: &str) -> Result<Vec<CompletedPart>> {
        self.inner.list_parts(op_id).await
    }
    async fn commit_verified_transfer(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes: u64,
    ) -> Result<()> {
        self.log_commit("commit", op_id, baseline);
        self.inner
            .commit_verified_transfer(op_id, baseline, job_id, bytes)
            .await
    }
    async fn get_baseline(&self, pair: &str, p: &RelPath) -> Result<Option<BaselineRecord>> {
        self.inner.get_baseline(pair, p).await
    }
    async fn get_baselines_batch(
        &self,
        pair: &str,
        ps: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        self.inner.get_baselines_batch(pair, ps).await
    }
    async fn delete_baseline(&self, pair: &str, p: &RelPath) -> Result<()> {
        self.inner.delete_baseline(pair, p).await
    }
    async fn delete_baselines_batch(&self, pair: &str, ps: &[RelPath]) -> Result<()> {
        self.inner.delete_baselines_batch(pair, ps).await
    }
    async fn delete_pair_baselines(&self, pair: &str) -> Result<()> {
        self.inner.delete_pair_baselines(pair).await
    }
    async fn next_baseline_page(
        &self,
        pair: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        self.inner.next_baseline_page(pair, after, limit).await
    }
    async fn get_bisync_state(&self, pair: &str) -> Result<Option<BisyncPairState>> {
        self.inner.get_bisync_state(pair).await
    }
    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        push(&self.log, "bisync-state".into());
        self.inner.upsert_bisync_state(state).await
    }
}

/// Replay the log: every trust record must come after a flush (or durable sync) that
/// followed the write of the file it vouches for. Returns the number of committed records.
fn assert_flush_before_trust(log: &Log) -> usize {
    let events = log.lock().unwrap().clone();
    let mut unflushed: HashSet<String> = HashSet::new();
    let mut commits = 0;
    for (i, ev) in events.iter().enumerate() {
        if let Some(p) = ev.strip_prefix("write:") {
            unflushed.insert(p.to_string());
        } else if ev == "flush" {
            unflushed.clear();
        } else if let Some(p) = ev.strip_prefix("sync:") {
            unflushed.remove(p);
        } else if let Some(p) = ev.strip_prefix("commit:") {
            commits += 1;
            assert!(
                !unflushed.contains(p),
                "event #{i}: journal record for `{p}` committed before its data was flushed:\n{events:#?}"
            );
        } else if ev == "job:completed"
            || ev == "job:completed_with_conflicts"
            || ev == "job:paused"
            || ev == "bisync-state"
        {
            assert!(
                unflushed.is_empty(),
                "event #{i}: `{ev}` written while {unflushed:?} were not flushed:\n{events:#?}"
            );
        }
    }
    commits
}

fn written(log: &Log) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|e| e.starts_with("write:"))
        .count()
}

fn count(log: &Log, ev: &str) -> usize {
    log.lock().unwrap().iter().filter(|e| *e == ev).count()
}

const MTIME: i64 = 1_700_000_000_000_000_000;

fn seeded_src(name: &str, files: usize, big: bool) -> Arc<ChaosBackend> {
    // Duplicate-name sources take the indexed (SyncDiffIndex) observation path.
    let src = Arc::new(ChaosBackend::sequential_gdrive_like(name, 256 * 1024));
    for i in 0..files {
        src.insert_file(
            &format!("f{i:04}.txt"),
            format!("data-{i}").into_bytes(),
            MTIME,
        );
    }
    if big {
        src.insert_file("big.bin", vec![9u8; 200 * 1024], MTIME);
    }
    src
}

fn engine_with(
    src: Arc<ChaosBackend>,
    dst: Arc<DeferringDst>,
    journal: Arc<RecordingJournal>,
    cancel: CancelFlag,
) -> TransferEngine {
    TransferEngine::new(
        src,
        dst,
        journal,
        BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_100)),
        cancel,
    )
}

#[tokio::test]
async fn d2_baselines_and_retirements_commit_only_after_destination_flush() {
    let log: Log = Arc::default();
    let src = seeded_src("fence-src", 20, true);
    let dst = Arc::new(DeferringDst::new("fence-dst", &log));
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src, dst.clone(), journal.clone(), CancelFlag::new());
    let mut cfg = EngineConfig::new("j-fence", JobMode::Copy, "src", "dst").with_transfers(4);
    cfg.baseline_mode = BaselineMode::All;
    cfg.chunk_size_override = Some(64 * 1024);
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 21);
    assert_eq!(written(&log), 21);
    let commits = assert_flush_before_trust(&log);
    assert_eq!(
        commits, 21,
        "every transferred file gets exactly one record"
    );
    assert_eq!(count(&log, "job:completed"), 1);
}

#[tokio::test]
async fn d2_fence_flushes_in_bounded_batches() {
    let log: Log = Arc::default();
    let files = fence::MAX_PENDING_COMMITS + 200;
    let src = seeded_src("fence-wide-src", files, false);
    let dst = Arc::new(DeferringDst::new("fence-wide-dst", &log));
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src, dst, journal, CancelFlag::new());
    let mut cfg = EngineConfig::new("j-fence-wide", JobMode::Copy, "src", "dst").with_transfers(8);
    cfg.baseline_mode = BaselineMode::All;
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(assert_flush_before_trust(&log), files);
    // The queue may not outgrow the bound: at least one flush happens before the end.
    let events = log.lock().unwrap().clone();
    let first_flush = events.iter().position(|e| e == "flush").unwrap();
    let last_write = events
        .iter()
        .rposition(|e| e.starts_with("write:"))
        .unwrap();
    assert!(
        first_flush < last_write,
        "a full batch of {} commits must flush mid-run",
        fence::MAX_PENDING_COMMITS
    );
}

#[tokio::test]
async fn d2_cancelled_run_flushes_before_committing_and_pausing() {
    let log: Log = Arc::default();
    let src = seeded_src("fence-cancel-src", 40, false);
    let cancel = CancelFlag::new();
    let mut dst = DeferringDst::new("fence-cancel-dst", &log);
    dst.cancel_after_writes = 5;
    dst.cancel = cancel.clone();
    let dst = Arc::new(dst);
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src, dst, journal, cancel);
    let mut cfg =
        EngineConfig::new("j-fence-cancel", JobMode::Copy, "src", "dst").with_transfers(2);
    cfg.baseline_mode = BaselineMode::All;
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.cancelled);
    assert!(written(&log) >= 5);
    let commits = assert_flush_before_trust(&log);
    assert!(
        commits >= 1,
        "files finished before the cancel are still recorded"
    );
    assert_eq!(count(&log, "job:paused"), 1);
}

/// Index whose second source page fails, so the producer errors after the first page of
/// transfers has been handed to the workers.
struct FailingSecondPageIndex {
    inner: MemorySyncIndex,
}

#[async_trait]
impl SyncDiffIndex for FailingSecondPageIndex {
    async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
        self.inner.insert_src_batch(entries).await
    }
    async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
        self.inner.insert_dst_batch(entries).await
    }
    async fn finalize_and_detect_conflicts(&self, cs: bool) -> Result<Vec<SyncConflict>> {
        self.inner.finalize_and_detect_conflicts(cs).await
    }
    async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
        self.inner.list_conflicts().await
    }
    async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        if after_id > 0 {
            return Err(Error::state_store("injected index failure on page 2"));
        }
        self.inner.next_src_page(after_id, limit).await
    }
    async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        self.inner.next_dst_only_page(after_id, limit).await
    }
}

#[tokio::test]
async fn d2_producer_error_still_flushes_before_committing_finished_files() {
    let log: Log = Arc::default();
    let src = seeded_src("fence-err-src", DIFF_PAGE_SIZE + 20, false);
    let dst = Arc::new(DeferringDst::new("fence-err-dst", &log));
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src, dst, journal.clone(), CancelFlag::new());
    let mut cfg = EngineConfig::new("j-fence-err", JobMode::Copy, "src", "dst").with_transfers(4);
    cfg.baseline_mode = BaselineMode::All;
    let err = engine
        .run(
            &cfg,
            Arc::new(FailingSecondPageIndex {
                inner: MemorySyncIndex::new(),
            }),
        )
        .await
        .expect_err("page-2 index failure aborts the run");
    assert!(err.to_string().contains("page 2"), "{err}");
    assert_flush_before_trust(&log);
    assert!(
        count(&log, "flush") >= 1,
        "the error path must flush what the workers finished"
    );
    assert_eq!(count(&log, "job:failed"), 1);
}

#[tokio::test]
async fn d2_failed_flush_drops_the_batch_and_fails_the_job() {
    let log: Log = Arc::default();
    let src = seeded_src("fence-eio-src", 10, false);
    let dst = Arc::new(DeferringDst::new("fence-eio-dst", &log));
    dst.fail_flush.store(true, Ordering::SeqCst);
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src, dst, journal.clone(), CancelFlag::new());
    let mut cfg = EngineConfig::new("j-fence-eio", JobMode::Copy, "src", "dst");
    cfg.baseline_mode = BaselineMode::All;
    let res = engine.run(&cfg, Arc::new(MemorySyncIndex::new())).await;
    assert!(
        res.is_err(),
        "an EIO from the batch flush must fail the run"
    );
    assert_eq!(
        assert_flush_before_trust(&log),
        0,
        "no record may be committed for files whose flush failed"
    );
    assert_eq!(count(&log, "job:completed"), 0);
    let job = journal.get_job("j-fence-eio").await.unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Failed);
    assert!(
        journal.list_active_operations().await.unwrap().len() <= 10,
        "unretired operations keep the files untrusted for the next run"
    );
}

#[tokio::test]
async fn d2_move_syncs_and_commits_before_each_source_delete() {
    let log: Log = Arc::default();
    let src = seeded_src("fence-move-src", 6, false);
    let dst = Arc::new(DeferringDst::new("fence-move-dst", &log));
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = engine_with(src.clone(), dst, journal, CancelFlag::new());
    let cfg = EngineConfig::new("j-fence-move", JobMode::Move, "src", "dst");
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.sources_deleted, 6);
    assert_eq!(src.file_count(), 0);
    assert_eq!(assert_flush_before_trust(&log), 6);
    // Each record follows its own durable sync rather than waiting for a batch flush.
    let events = log.lock().unwrap().clone();
    for (i, ev) in events.iter().enumerate() {
        if let Some(p) = ev.strip_prefix("commit:") {
            assert!(
                events[..i].iter().any(|e| e == &format!("sync:{p}")),
                "move record for `{p}` must follow its sync_durable_file"
            );
        }
    }
}

#[tokio::test]
async fn d2_bisync_cancel_flushes_before_committing_and_pausing() {
    let log: Log = Arc::default();
    let side_a = seeded_src("fence-bisync-a", 30, false);
    let cancel = CancelFlag::new();
    let mut side_b = DeferringDst::new("fence-bisync-b", &log);
    side_b.cancel_after_writes = 4;
    side_b.cancel = cancel.clone();
    let side_b = Arc::new(side_b);
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = BisyncEngine::new(
        side_a,
        side_b,
        journal,
        BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_100)),
        cancel,
    );
    let cfg = BisyncConfig::new("j-fence-bisync", "a", "b").with_resync(true);
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.cancelled, "{rep:?}");
    assert!(written(&log) >= 4);
    assert!(assert_flush_before_trust(&log) >= 1);
    assert_eq!(count(&log, "job:paused"), 1);
}

#[tokio::test]
async fn d2_bisync_completed_run_flushes_before_baselines() {
    let log: Log = Arc::default();
    let side_a = seeded_src("fence-bisync-ok-a", 12, true);
    let side_b = Arc::new(DeferringDst::new("fence-bisync-ok-b", &log));
    let journal = Arc::new(RecordingJournal::new(&log));
    let engine = BisyncEngine::new(
        side_a,
        side_b,
        journal,
        BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_100)),
        CancelFlag::new(),
    );
    let cfg = BisyncConfig::new("j-fence-bisync-ok", "a", "b").with_resync(true);
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(assert_flush_before_trust(&log), 13);
    assert_eq!(count(&log, "job:completed"), 1);
}
