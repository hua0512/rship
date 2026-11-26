use super::super::*;
use crate::backend::BackendPath;
use crate::clock::VirtualClock;
use crate::error::{ErrorKind, RetryClass};
use crate::path::RelPath;
use crate::state::JobMode;
use crate::types::{Capabilities, Entry};
use futures::StreamExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[tokio::test]
async fn p9_cancel_aborts_hanging_single_shot_and_upload_chunk_and_preserves_journal() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{DstPrecondition, MemoryJournalStore, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind, UploadTopology};
    use async_trait::async_trait;
    use std::time::Instant;
    use tokio::sync::Notify;

    struct HangingUploadDst {
        inner: Arc<ChaosBackend>,
        entered: Arc<Notify>,
    }

    #[async_trait]
    impl StorageBackend for HangingUploadDst {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "hanging-dst"
        }
        fn endpoint_identity(&self) -> String {
            format!("hanging-dst://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.supports_server_side_copy = false;
            caps
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
        async fn compute_hash(
            &self,
            path: &BackendPath,
            kind: HashKind,
        ) -> Result<Option<Checksum>> {
            self.inner.compute_hash(path, kind).await
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            self.inner.open_read(path, range).await
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            self.entered.notify_one();
            futures::future::pending::<()>().await;
            unreachable!()
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            self.inner.begin_upload(init).await
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            self.inner.query_upload(op).await
        }
        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            _chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            self.entered.notify_one();
            futures::future::pending::<()>().await;
            unreachable!()
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.inner.finish_upload(op, parts).await
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.inner.abort_upload(op).await
        }
        async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
            self.inner.reconcile_operation(op).await
        }
    }

    let mtime = 1_700_000_000_000_000_000i64;
    // Exercise all 3 upload paths:
    // 1. Single-shot (with `allows_duplicate_names: true` so op is journaled)
    // 2. Sequential resumable (`upload_chunk`)
    // 3. Parallel multipart (`upload_chunk`)
    let cases = [
        ("single-shot", UploadTopology::Sequential, 1024usize),
        ("seq-chunk", UploadTopology::Sequential, 64 * 1024usize),
        ("par-chunk", UploadTopology::ParallelParts, 64 * 1024usize),
    ];

    for (label, topology, size) in cases {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("p9-src", 256 * 1024));
        src.insert_file("hang.bin", vec![0x55u8; size], mtime);
        let src_entry = src
            .stat(&BackendPath::from_rel(RelPath::parse("hang.bin").unwrap()))
            .await
            .unwrap()
            .unwrap();

        let raw_dst = match topology {
            UploadTopology::Sequential => {
                ChaosBackend::sequential_gdrive_like("p9-dst", 256 * 1024)
            }
            UploadTopology::ParallelParts => ChaosBackend::parallel_s3_like("p9-dst", 32 * 1024),
        };
        let entered = Arc::new(Notify::new());
        let dst: Arc<dyn StorageBackend> = Arc::new(HangingUploadDst {
            inner: Arc::new(raw_dst),
            entered: entered.clone(),
        });
        let src_dyn: Arc<dyn StorageBackend> = src;
        let journal = Arc::new(MemoryJournalStore::new());
        let journal_dyn: Arc<dyn JournalStore> = journal.clone();
        let pool = BufferPool::new(512 * 1024, 32 * 1024).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let cancel = CancelFlag::new();
        let cfg = EngineConfig::new(format!("job-p9-{label}"), JobMode::Copy, "src", "dst")
            .with_allow_server_side_copy(false);
        let src_caps = src_dyn.capabilities();
        let dst_caps = dst.capabilities();
        let t = task::TransferTask {
            src: src_entry,
            dst_rel: RelPath::parse("hang.bin").unwrap(),
            existing_dst_node_id: None,
            precondition: DstPrecondition::Absent,
            needs_checksum_verify: false,
            dst_existing: None,
            wire_key: None,
            replace_dst_dir: None,
            defer_op_commit: false,
        };

        let cancel_c = cancel.clone();
        let handle = tokio::spawn(async move {
            task::execute_transfer_task(
                &src_dyn,
                &dst,
                &journal_dyn,
                &pool,
                &clock,
                &cancel_c,
                None,
                None,
                None,
                None,
                &cfg,
                "pair-p9",
                &src_caps,
                &dst_caps,
                t,
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap_or_else(|_| panic!("{label}: never entered hanging backend call"));

        let t0 = Instant::now();
        cancel.cancel();
        let outcome = tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .unwrap_or_else(|_| panic!("{label}: cancel did not abort hanging transfer"))
            .unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(200),
            "{label}: cancel took too long: {elapsed:?}"
        );
        let err = match outcome {
            Ok(_) => panic!("{label}: expected Cancelled error, got Ok"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ErrorKind::Cancelled, "{label}: {err}");
        assert_eq!(err.retry, RetryClass::Cancelled, "{label}: {err}");

        let ops = journal.list_active_operations().await.unwrap();
        assert_eq!(
            ops.len(),
            1,
            "{label}: durable OperationRecord MUST be preserved in journal after Ctrl-C"
        );
    }
}

#[tokio::test]
async fn p8_unordered_pipelining_starts_transfers_before_source_listing_finishes() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{ConflictKind, MemoryJournalStore, MemorySyncIndex, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind};
    use async_trait::async_trait;
    use tokio::sync::Notify;

    struct GatedListingSrc {
        inner: Arc<ChaosBackend>,
        first_batch: Vec<Entry>,
        second_batch: Vec<Entry>,
        resume_listing: Arc<Notify>,
        listing_finished: Arc<AtomicBool>,
    }

    #[async_trait]
    impl StorageBackend for GatedListingSrc {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "gated-list-src"
        }
        fn endpoint_identity(&self) -> String {
            format!("gated-list-src://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.supports_ordered_utf8_list = false;
            caps.allows_duplicate_names = false;
            caps.case_sensitive = true;
            caps
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            self.inner.stat(path).await
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            let first = self.first_batch.clone();
            let second = self.second_batch.clone();
            let resume = self.resume_listing.clone();
            let finished = self.listing_finished.clone();
            let s = futures::stream::unfold(
                (0usize, first, second, resume, finished),
                |(stage, mut first, mut second, resume, finished)| async move {
                    if stage == 0 {
                        if !first.is_empty() {
                            let e = first.remove(0);
                            return Some((Ok(e), (0, first, second, resume, finished)));
                        }
                        // Wait for a transfer to start BEFORE finishing source listing!
                        resume.notified().await;
                        if !second.is_empty() {
                            let e = second.remove(0);
                            return Some((Ok(e), (1, first, second, resume, finished)));
                        }
                        finished.store(true, Ordering::SeqCst);
                        None
                    } else if !second.is_empty() {
                        let e = second.remove(0);
                        Some((Ok(e), (1, first, second, resume, finished)))
                    } else {
                        finished.store(true, Ordering::SeqCst);
                        None
                    }
                },
            );
            Ok(Box::pin(s))
        }
        async fn mkdir(&self, path: &RelPath) -> Result<()> {
            self.inner.mkdir(path).await
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            self.inner.delete(path).await
        }
        async fn compute_hash(
            &self,
            path: &BackendPath,
            kind: HashKind,
        ) -> Result<Option<Checksum>> {
            self.inner.compute_hash(path, kind).await
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
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
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.inner.finish_upload(op, parts).await
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.inner.abort_upload(op).await
        }
        async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
            self.inner.reconcile_operation(op).await
        }
    }

    struct NotifyOnPutDst {
        inner: Arc<ChaosBackend>,
        resume_listing: Arc<Notify>,
        listing_finished: Arc<AtomicBool>,
        started_before_list_end: Arc<AtomicBool>,
    }

    #[async_trait]
    impl StorageBackend for NotifyOnPutDst {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "notify-put-dst"
        }
        fn endpoint_identity(&self) -> String {
            format!("notify-put-dst://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.supports_ordered_utf8_list = false;
            caps.case_sensitive = true;
            caps.supports_server_side_copy = false;
            caps
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
        async fn compute_hash(
            &self,
            path: &BackendPath,
            kind: HashKind,
        ) -> Result<Option<Checksum>> {
            self.inner.compute_hash(path, kind).await
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            self.inner.open_read(path, range).await
        }
        async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
            if !self.listing_finished.load(Ordering::SeqCst) {
                self.started_before_list_end.store(true, Ordering::SeqCst);
            }
            self.resume_listing.notify_waiters();
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
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.inner.finish_upload(op, parts).await
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.inner.abort_upload(op).await
        }
        async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
            self.inner.reconcile_operation(op).await
        }
    }

    let mtime = 1_700_000_000_000_000_000i64;
    let raw_src = Arc::new(ChaosBackend::parallel_s3_like("p8-src", 64 * 1024));
    let mut first_batch = Vec::new();
    let mut second_batch = Vec::new();
    for i in 0..8 {
        let name = format!("file-{i}.txt");
        raw_src.insert_file(&name, format!("data-{i}").into_bytes(), mtime);
        let entry = raw_src
            .stat(&BackendPath::from_rel(RelPath::parse(&name).unwrap()))
            .await
            .unwrap()
            .unwrap();
        if i < 4 {
            first_batch.push(entry);
        } else {
            second_batch.push(entry);
        }
    }
    // Also include an NFC + NFD colliding pair to prove deferred non-ASCII collision safety!
    raw_src.insert_file("caf\u{00e9}.txt", b"nfc-v".to_vec(), mtime);
    raw_src.insert_file("cafe\u{0301}.txt", b"nfd-v".to_vec(), mtime);
    let mut raw_list = raw_src.list_stream(&RelPath::root(), true).await.unwrap();
    while let Some(Ok(e)) = raw_list.next().await {
        if e.nfc_path.as_str() == "caf\u{00e9}.txt" {
            second_batch.push(e);
        }
    }

    let raw_dst = Arc::new(ChaosBackend::parallel_s3_like("p8-dst", 64 * 1024));
    raw_dst.insert_file("stale.txt", b"old-extra".to_vec(), mtime);

    let resume_listing = Arc::new(Notify::new());
    let listing_finished = Arc::new(AtomicBool::new(false));
    let started_before_list_end = Arc::new(AtomicBool::new(false));

    let src = Arc::new(GatedListingSrc {
        inner: raw_src,
        first_batch,
        second_batch,
        resume_listing: resume_listing.clone(),
        listing_finished: listing_finished.clone(),
    });
    let dst = Arc::new(NotifyOnPutDst {
        inner: raw_dst.clone(),
        resume_listing,
        listing_finished,
        started_before_list_end: started_before_list_end.clone(),
    });

    let engine = TransferEngine::new(
        src,
        dst,
        Arc::new(MemoryJournalStore::new()),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_000)),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("job-p8", JobMode::Sync, "src", "dst")
        .with_delete(true)
        .with_transfers(4)
        .with_allow_server_side_copy(false);

    let rep = tokio::time::timeout(
        Duration::from_secs(3),
        engine.run(&cfg, Arc::new(MemorySyncIndex::new())),
    )
    .await
    .expect("P8 pipelining deadlocked: transfers did not start before src listing finished")
    .unwrap();

    assert!(
        started_before_list_end.load(Ordering::SeqCst),
        "at least one transfer MUST start before src listing finishes"
    );
    assert_eq!(rep.files_transferred, 8);
    assert_eq!(rep.items_deleted, 1);
    assert!(raw_dst.get_file_bytes("stale.txt").is_none());
    assert!(
        rep.conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::UnicodeNfcCollision),
        "deferred non-ASCII NFC/NFD collision must still be detected: {:?}",
        rep.conflicts
    );
    assert!(
        raw_dst.get_file_bytes("caf\u{00e9}.txt").is_none(),
        "colliding NFC/NFD source entries must NOT be uploaded"
    );
}

#[tokio::test]
async fn p12_spool_seekable_source_drop_unlinks_off_async_thread() {
    use crate::source::SpoolSeekableSource;
    use bytes::Bytes;

    let dir = std::env::temp_dir().join(format!("rship-p12-spool-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let stream: crate::source::ByteStream = Box::pin(futures::stream::iter([Ok(
        Bytes::from_static(b"hello-p12-spool"),
    )]));
    let spool = SpoolSeekableSource::from_stream(stream, &dir, 1024 * 1024)
        .await
        .unwrap();
    let spool_path = spool.path().to_path_buf();
    assert!(spool_path.exists());
    drop(spool);

    for _ in 0..100 {
        if !spool_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !spool_path.exists(),
        "SpoolSeekableSource::drop must unlink `{}` via spawn_blocking",
        spool_path.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A spool owned by a task that the runtime drops while shutting down must still be
/// unlinked: `spawn_blocking` is no longer serviced at that point, so a cleanup that only
/// lives inside a spawned closure would never run.
#[test]
fn p12_spool_dropped_during_runtime_shutdown_is_still_unlinked() {
    use crate::source::SpoolSeekableSource;
    use bytes::Bytes;

    let dir = std::env::temp_dir().join(format!("rship-p12-spool-shutdown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (path_tx, path_rx) = std::sync::mpsc::channel();
    let dir_c = dir.clone();
    rt.spawn(async move {
        let stream: crate::source::ByteStream = Box::pin(futures::stream::iter([Ok(
            Bytes::from_static(b"spool held across shutdown"),
        )]));
        let spool = SpoolSeekableSource::from_stream(stream, &dir_c, 1024 * 1024)
            .await
            .unwrap();
        path_tx.send(spool.path().to_path_buf()).unwrap();
        // Hold the spool until the runtime drops this task at shutdown.
        std::future::pending::<()>().await;
        drop(spool);
    });
    let path = path_rx.recv().unwrap();
    assert!(path.exists());
    drop(rt);
    assert!(
        !path.exists(),
        "spool `{}` leaked when its owner was dropped during runtime shutdown",
        path.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
