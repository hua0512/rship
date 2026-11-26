use super::super::*;
use crate::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::source::{ByteStream, DataSource};
use crate::state::{JobMode, OperationRecord};
use crate::types::{ByteRange, Capabilities, Checksum, Entry, HashKind};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

struct FailDeleteBackend {
    inner: Arc<ChaosBackend>,
}

#[async_trait]
impl StorageBackend for FailDeleteBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn endpoint_identity(&self) -> String {
        self.inner.endpoint_identity()
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
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
        Err(Error::permission_denied(format!(
            "source delete refused for `{}`",
            path.nfc_path
        )))
    }
    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.inner.compute_hash(path, kind).await
    }
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.inner.open_read(path, range).await
    }
    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.inner.put_single_shot(init, body).await
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
        self.inner.finish_upload(op, parts).await
    }
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.inner.abort_upload(op).await
    }
    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.inner.reconcile_operation(op).await
    }
}

#[tokio::test]
async fn dst_planning_skips_recorded_in_file_results_and_progress_totals() {
    use crate::engine::FileTransferStatus;
    use crate::progress::{ChannelEventSink, TransferEvent, TransferProgress};

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    let t1 = 1_700_000_000_000_000_000i64;

    // 10 files total: 8 already identical on dst (planning skips) + 2 new transfers.
    for i in 0..8 {
        let name = format!("skip_{i}.txt");
        let data = format!("same-content-{i}").into_bytes();
        src.insert_file(&name, data.clone(), t1);
        dst.insert_file(&name, data, t1);
    }
    src.insert_file("new_0.txt", b"fresh-0".to_vec(), t1);
    src.insert_file("new_1.txt", b"fresh-1".to_vec(), t1);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_900));
    let progress = TransferProgress::new();
    let (sink, mut rx) = ChannelEventSink::bounded(64);

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal,
        pool,
        clock,
        CancelFlag::new(),
    )
    .with_progress(progress.clone())
    .with_event_sink(sink);

    let cfg = EngineConfig::new("job-plan-skip-copy", JobMode::Copy, "src:", "dst:");
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();

    assert!(rep.is_success(), "errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(rep.files_skipped, 8);
    assert_eq!(rep.file_results.len(), 10);
    assert_eq!(
        rep.file_results
            .iter()
            .filter(|r| r.status == FileTransferStatus::Skipped && !r.source_deleted)
            .count(),
        8
    );
    assert_eq!(
        rep.file_results
            .iter()
            .filter(|r| r.status == FileTransferStatus::Transferred && !r.source_deleted)
            .count(),
        2
    );

    let snap = progress.snapshot(None);
    assert_eq!(snap.files_total, 10);
    assert_eq!(snap.files_planned, 2);
    assert_eq!(snap.files_done, 2);
    assert_eq!(snap.files_skipped, 8);
    assert_eq!(snap.errors, 0);

    let mut completed_events = 0usize;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, TransferEvent::FileCompleted { .. }) {
            completed_events += 1;
        }
    }
    assert_eq!(completed_events, 10);
}

#[tokio::test]
async fn dst_planning_skip_move_delete_failure_records_failed_not_skipped() {
    use crate::engine::FileTransferStatus;
    use crate::error::{ErrorCategory, ErrorKind};
    use crate::progress::{ChannelEventSink, TransferEvent, TransferProgress};

    let t1 = 1_700_000_000_000_000_000i64;

    // Verify identical semantics across ALL 3 entry points: `run`, `run_single_file`, `run_file_list`.
    for mode_label in ["run", "single", "file_list"] {
        let src_inner = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
        let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
        src_inner.insert_file("already.bin", b"identical-bytes".to_vec(), t1);
        dst.insert_file("already.bin", b"identical-bytes".to_vec(), t1);

        let src: Arc<dyn StorageBackend> = Arc::new(FailDeleteBackend { inner: src_inner });
        let journal = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new(1_700_000_900));
        let progress = TransferProgress::new();
        let (sink, mut rx) = ChannelEventSink::bounded(32);

        let engine = TransferEngine::new(src, dst, journal, pool, clock, CancelFlag::new())
            .with_progress(progress.clone())
            .with_event_sink(sink);
        let cfg = EngineConfig::new(
            format!("job-skip-del-fail-{mode_label}"),
            JobMode::Move,
            "src:",
            "dst:",
        );

        let rep = match mode_label {
            "run" => engine
                .run(&cfg, Arc::new(InMemorySyncIndex::default()))
                .await
                .unwrap(),
            "single" => {
                let rel = RelPath::parse("already.bin").unwrap();
                engine
                    .run_single_file(&cfg, &BackendPath::from_rel(rel.clone()), &rel)
                    .await
                    .unwrap()
            }
            _ => engine
                .run_file_list(&cfg, &[RelPath::parse("already.bin").unwrap()])
                .await
                .unwrap(),
        };

        assert_eq!(
            rep.files_skipped, 0,
            "{mode_label}: must not count failed delete as skipped"
        );
        assert_eq!(rep.sources_deleted, 0, "{mode_label}");
        assert_eq!(rep.errors.len(), 1, "{mode_label}");
        assert_eq!(rep.error_details.len(), 1, "{mode_label}");
        assert_eq!(
            rep.error_details[0].kind,
            ErrorKind::PermissionDenied,
            "{mode_label}"
        );
        assert_eq!(
            rep.error_details[0].category,
            ErrorCategory::Auth,
            "{mode_label}"
        );
        assert_eq!(
            rep.primary_error_category(),
            Some(ErrorCategory::Auth),
            "{mode_label}"
        );
        assert_eq!(rep.file_results.len(), 1, "{mode_label}");
        assert_eq!(
            rep.file_results[0].status,
            FileTransferStatus::Failed,
            "{mode_label}"
        );
        assert_eq!(
            rep.file_results[0].error_kind,
            Some(ErrorKind::PermissionDenied),
            "{mode_label}"
        );
        assert_eq!(
            rep.file_results[0].error_category,
            Some(ErrorCategory::Auth),
            "{mode_label}"
        );
        assert!(!rep.file_results[0].source_deleted, "{mode_label}");

        let snap = progress.snapshot(None);
        assert_eq!(snap.files_total, 1, "{mode_label}");
        assert_eq!(snap.files_planned, 0, "{mode_label}");
        assert_eq!(snap.files_skipped, 0, "{mode_label}");
        assert_eq!(snap.errors, 1, "{mode_label}");

        let mut saw_failed_event = false;
        while let Ok(ev) = rx.try_recv() {
            if let TransferEvent::FileCompleted { result, .. } = ev
                && result.status == FileTransferStatus::Failed
            {
                saw_failed_event = true;
            }
        }
        assert!(
            saw_failed_event,
            "{mode_label}: must emit FileCompleted(Failed)"
        );
    }
}

#[tokio::test]
async fn dst_observation_error_emits_error_occurred_event_and_error_details() {
    use crate::error::ErrorCategory;
    use crate::progress::{ChannelEventSink, TransferEvent};

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    src.insert_file("a.txt", b"hello".to_vec(), 100);
    src.set_faults(FaultSchedule {
        inject_list_error: true,
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(200));
    let (sink, mut rx) = ChannelEventSink::bounded(32);

    let engine = TransferEngine::new(src, dst, journal, pool, clock, CancelFlag::new())
        .with_event_sink(sink);
    let cfg = EngineConfig::new("job-obs-err", JobMode::Copy, "src:", "dst:");
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();

    assert!(!rep.errors.is_empty());
    assert_eq!(rep.error_details.len(), rep.errors.len());
    assert_eq!(rep.primary_error_category(), Some(ErrorCategory::Transient));

    let mut saw_error_event = false;
    while let Ok(ev) = rx.try_recv() {
        if let TransferEvent::ErrorOccurred { error, .. } = ev
            && error.category == ErrorCategory::Transient
        {
            saw_error_event = true;
        }
    }
    assert!(
        saw_error_event,
        "must emit TransferEvent::ErrorOccurred on observation error"
    );
}

struct FailStatOnPathBackend {
    inner: Arc<ChaosBackend>,
    fail_path: String,
}

#[async_trait]
impl StorageBackend for FailStatOnPathBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn endpoint_identity(&self) -> String {
        self.inner.endpoint_identity()
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        if path.nfc_path.as_str() == self.fail_path {
            return Err(Error::rate_limited("429 stat throttled", None));
        }
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
        self.inner.put_single_shot(init, body).await
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
        self.inner.finish_upload(op, parts).await
    }
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.inner.abort_upload(op).await
    }
    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.inner.reconcile_operation(op).await
    }
}

struct RecordingDeleteBackend {
    inner: Arc<ChaosBackend>,
    deleted: Arc<Mutex<Vec<BackendPath>>>,
}

#[async_trait]
impl StorageBackend for RecordingDeleteBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn endpoint_identity(&self) -> String {
        self.inner.endpoint_identity()
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
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
        self.deleted.lock().unwrap().push(path.clone());
        self.inner.delete(path).await
    }
    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.inner.compute_hash(path, kind).await
    }
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.inner.open_read(path, range).await
    }
    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.inner.put_single_shot(init, body).await
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
        self.inner.finish_upload(op, parts).await
    }
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.inner.abort_upload(op).await
    }
    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.inner.reconcile_operation(op).await
    }
}

#[tokio::test]
async fn dst_files_from_dst_stat_error_skips_upload_and_emits_single_failure() {
    use crate::engine::FileTransferStatus;
    use crate::error::ErrorCategory;
    use crate::filter::{FilterOptions, FilterSet};
    use crate::progress::{ChannelEventSink, TransferEvent, TransferProgress};

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst_inner = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    src.insert_file("a.txt", b"alpha".to_vec(), 100);
    src.insert_file("b.txt", b"beta".to_vec(), 100);

    let dst: Arc<dyn StorageBackend> = Arc::new(FailStatOnPathBackend {
        inner: dst_inner.clone(),
        fail_path: "a.txt".into(),
    });
    let progress = TransferProgress::new();
    let (sink, mut rx) = ChannelEventSink::bounded(64);
    let engine = TransferEngine::new(
        src,
        dst,
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 256 * 1024).unwrap(),
        Arc::new(VirtualClock::new(200)),
        CancelFlag::new(),
    )
    .with_progress(progress.clone())
    .with_event_sink(sink);

    let mut cfg = EngineConfig::new("job-ff-dstat", JobMode::Copy, "src:", "dst:");
    cfg.no_traverse = true;
    cfg.filter = FilterSet::from_options(&FilterOptions {
        files_from: Some(vec!["a.txt".into(), "b.txt".into()]),
        ..Default::default()
    })
    .unwrap();

    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();

    // `a.txt` must NOT have been uploaded despite `src.stat` succeeding!
    assert!(dst_inner.get_file_bytes("a.txt").is_none());
    assert_eq!(
        dst_inner.get_file_bytes("b.txt").as_deref(),
        Some(b"beta".as_slice())
    );
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(rep.errors.len(), 1);
    assert_eq!(rep.error_details.len(), 1);
    assert_eq!(
        rep.primary_error_category(),
        Some(ErrorCategory::RateLimited)
    );
    assert_eq!(rep.file_results.len(), 2);
    assert!(rep.file_results.iter().any(|r| {
        r.path == "a.txt"
            && r.status == FileTransferStatus::Failed
            && r.error_category == Some(ErrorCategory::RateLimited)
    }));

    let snap = progress.snapshot(None);
    assert_eq!(snap.files_total, 2);
    assert_eq!(snap.files_planned, 1);
    assert_eq!(snap.files_done, 1);
    assert_eq!(snap.errors, 1);

    // Exactly ONE failure notification for `a.txt` (via FileCompleted(Failed), no duplicate ErrorOccurred).
    let mut failed_events = 0usize;
    let mut err_occurred = 0usize;
    while let Ok(ev) = rx.try_recv() {
        match ev {
            TransferEvent::FileCompleted { result, .. }
                if result.status == FileTransferStatus::Failed =>
            {
                failed_events += 1;
            }
            TransferEvent::ErrorOccurred { .. } => err_occurred += 1,
            _ => {}
        }
    }
    assert_eq!(failed_events, 1);
    assert_eq!(err_occurred, 0);
}

#[tokio::test]
async fn dst_warm_dirs_dry_run_worker_skip_and_file_list_node_id_invariants() {
    use crate::bisync::{BisyncConfig, BisyncEngine};
    use crate::progress::TransferProgress;

    let t1 = 1_700_000_000_000_000_000i64;
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    for d in ["sub1", "sub1/deep", "sub2"] {
        src.mkdir(&RelPath::parse(d).unwrap()).await.unwrap();
        dst.mkdir(&RelPath::parse(d).unwrap()).await.unwrap();
    }
    src.insert_file("sub1/a.txt", b"same-a".to_vec(), t1);
    dst.insert_file("sub1/a.txt", b"same-a".to_vec(), t1);
    src.insert_file("sub1/deep/b.txt", b"same-b".to_vec(), t1);
    dst.insert_file("sub1/deep/b.txt", b"same-b".to_vec(), t1);
    src.insert_file("sub2/new.txt", b"fresh-data".to_vec(), t1);

    // 1. Warm re-run with 3 existing directories + 2 unchanged files + 1 new file.
    let p_warm = TransferProgress::new();
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 256 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_900)),
        CancelFlag::new(),
    )
    .with_progress(p_warm.clone());

    // Dry-run first: verifies H2 (existing dirs ignored) + H3 (dry-run progress counters).
    let mut dry_cfg = EngineConfig::new("job-dry-inv", JobMode::Copy, "src:", "dst:");
    dry_cfg.dry_run = true;
    let dry_rep = engine
        .run(&dry_cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(dry_rep.files_transferred, 1);
    assert_eq!(dry_rep.files_skipped, 2);
    assert_eq!(dry_rep.file_results.len(), 3);
    let dry_snap = p_warm.snapshot(None);
    assert_eq!(dry_snap.files_total, 3);
    assert_eq!(dry_snap.files_planned, 1);
    assert_eq!(dry_snap.files_done, 1);
    assert_eq!(dry_snap.files_skipped, 2);
    assert_eq!(dry_snap.bytes_done, dry_snap.bytes_total);

    // 2. Worker-level `--checksum` skip subtracts skipped bytes from `bytes_total` (L2).
    let src_ck = Arc::new(ChaosBackend::sequential_gdrive_like("src-ck", 256 * 1024));
    let dst_ck = Arc::new(ChaosBackend::sequential_gdrive_like("dst-ck", 256 * 1024));
    src_ck.insert_file("ck.bin", b"identical-16byte".to_vec(), t1);
    dst_ck.insert_file("ck.bin", b"identical-16byte".to_vec(), t1 + 5_000_000_000);
    let p_ck = TransferProgress::new();
    let eng_ck = TransferEngine::new(
        src_ck,
        dst_ck,
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 256 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_900)),
        CancelFlag::new(),
    )
    .with_progress(p_ck.clone());
    let mut ck_cfg = EngineConfig::new("job-ck-skip", JobMode::Copy, "src-ck:", "dst-ck:");
    ck_cfg.checksum = true;
    let ck_rep = eng_ck
        .run(&ck_cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(ck_rep.files_skipped, 1);
    let ck_snap = p_ck.snapshot(None);
    assert_eq!(ck_snap.files_total, 1);
    assert_eq!(ck_snap.files_skipped, 1);
    assert_eq!(ck_snap.bytes_total, 0);
    assert_eq!(ck_snap.bytes_done, 0);

    // 3. `run_file_list` preserves `src_entry.node_id` on planning-skip move delete (M5).
    let deleted_log = Arc::new(Mutex::new(Vec::new()));
    let rec_src: Arc<dyn StorageBackend> = Arc::new(RecordingDeleteBackend {
        inner: src.clone(),
        deleted: deleted_log.clone(),
    });
    let move_eng = TransferEngine::new(
        rec_src,
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 256 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_900)),
        CancelFlag::new(),
    );
    let mv_cfg = EngineConfig::new("job-fl-nid", JobMode::Move, "src:", "dst:");
    let mv_rep = move_eng
        .run_file_list(&mv_cfg, &[RelPath::parse("sub1/a.txt").unwrap()])
        .await
        .unwrap();
    assert_eq!(mv_rep.files_skipped, 1);
    assert_eq!(mv_rep.sources_deleted, 1);
    {
        let dels = deleted_log.lock().unwrap();
        assert_eq!(dels.len(), 1);
        assert!(
            dels[0].node_id.is_some(),
            "must preserve node_id on planning-skip delete"
        );
    }

    // 4. BisyncEngine warm re-run with shared directories + dry-run progress invariant (H2 + H3).
    let a = Arc::new(ChaosBackend::sequential_gdrive_like("bi-a", 256 * 1024));
    let b = Arc::new(ChaosBackend::sequential_gdrive_like("bi-b", 256 * 1024));
    a.mkdir(&RelPath::parse("dir1").unwrap()).await.unwrap();
    b.mkdir(&RelPath::parse("dir1").unwrap()).await.unwrap();
    a.insert_file("dir1/same.txt", b"same".to_vec(), t1);
    b.insert_file("dir1/same.txt", b"same".to_vec(), t1);
    a.insert_file("dir1/only_a.txt", b"only-a".to_vec(), t1);
    let p_bi = TransferProgress::new();
    let bi_eng = BisyncEngine::new(
        a,
        b,
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 256 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_900)),
        CancelFlag::new(),
    )
    .with_progress(p_bi.clone());
    let mut bi_cfg = BisyncConfig::new("job-bi-dry", "bi-a:", "bi-b:");
    bi_cfg.resync = true;
    bi_cfg.dry_run = true;
    let bi_rep = bi_eng
        .run(&bi_cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(
        bi_rep.converged_skipped, 1,
        "shared dir1 must not inflate converged_skipped"
    );
    assert_eq!(bi_rep.copied_a_to_b, 1);
    let bi_snap = p_bi.snapshot(None);
    assert_eq!(bi_snap.files_total, 2);
    assert_eq!(bi_snap.files_planned, 1);
    assert_eq!(bi_snap.files_done, 1);
    assert_eq!(bi_snap.files_skipped, 1);
    assert_eq!(bi_snap.bytes_done, bi_snap.bytes_total);
}
