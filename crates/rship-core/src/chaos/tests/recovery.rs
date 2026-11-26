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
use crate::state::{JobMode, JournalStore, OperationRecord};
use crate::types::{ByteRange, Capabilities, Checksum, Entry, HashKind};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
async fn d1_stale_completing_op_after_source_edit_uploads_v2_in_sync_and_move() {
    use crate::clock::Clock;
    use crate::state::{DstPrecondition, OperationState};

    // 1. JobMode::Sync — stale Completing op for v1 MUST NOT skip uploading v2!
    {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like(
            "d1-sync-src",
            256 * 1024,
        ));
        let dst = Arc::new(ChaosBackend::sequential_gdrive_like(
            "d1-sync-dst",
            256 * 1024,
        ));
        let journal = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new(1_700_000_000));

        let t1 = clock.now_unix_nanos();
        src.insert_file("doc.txt", b"version-one".to_vec(), t1);
        dst.set_faults(FaultSchedule {
            drop_final_commit_response_remaining: 1,
            ..Default::default()
        });

        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let mut cfg = EngineConfig::new("d1-sync-1", JobMode::Sync, "src:", "dst:")
            .with_max_retries(0)
            .with_allow_server_side_copy(false);
        cfg.base_retry_delay = Duration::from_millis(1);

        let r1 = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(
            !r1.errors.is_empty(),
            "run 1 must observe dropped commit response"
        );
        assert_eq!(
            dst.get_file_bytes("doc.txt").as_deref(),
            Some(b"version-one".as_slice())
        );
        let ops = journal.list_active_operations().await.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].state, OperationState::Completing);

        // User edits `doc.txt` on source before re-running sync!
        clock.advance(Duration::from_secs(10));
        let t2 = clock.now_unix_nanos();
        src.delete(&BackendPath::from_rel(RelPath::parse("doc.txt").unwrap()))
            .await
            .unwrap();
        src.insert_file("doc.txt", b"version-two-edited".to_vec(), t2);

        let mut cfg2 = cfg.clone();
        cfg2.job_id = "d1-sync-2".into();
        let r2 = engine
            .run(&cfg2, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(r2.is_success(), "run 2 errors: {:?}", r2.errors);
        assert_eq!(r2.files_transferred, 1);
        assert_eq!(
            dst.get_file_bytes("doc.txt").as_deref(),
            Some(b"version-two-edited".as_slice()),
            "sync must upload v2 instead of falsely reconciling stale v1 Completing op"
        );
        assert!(journal.list_active_operations().await.unwrap().is_empty());
    }

    // 2. JobMode::Move — stale Completing op for v1 MUST upload v2 before deleting src!
    {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like(
            "d1-move-src",
            256 * 1024,
        ));
        let dst = Arc::new(ChaosBackend::sequential_gdrive_like(
            "d1-move-dst",
            256 * 1024,
        ));
        let journal = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new(1_700_000_000));

        let t1 = clock.now_unix_nanos();
        src.insert_file("precious.txt", b"v1-old".to_vec(), t1);
        dst.set_faults(FaultSchedule {
            drop_final_commit_response_remaining: 1,
            ..Default::default()
        });

        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let mut cfg = EngineConfig::new("d1-move-1", JobMode::Move, "src:", "dst:")
            .with_max_retries(0)
            .with_allow_server_side_copy(false);
        cfg.base_retry_delay = Duration::from_millis(1);

        let r1 = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(!r1.errors.is_empty());
        assert_eq!(
            src.get_file_bytes("precious.txt").as_deref(),
            Some(b"v1-old".as_slice()),
            "source must remain intact when run 1 fails ambiguously"
        );
        assert_eq!(
            dst.get_file_bytes("precious.txt").as_deref(),
            Some(b"v1-old".as_slice())
        );

        // User edits `precious.txt` on source to v2 before re-running move!
        clock.advance(Duration::from_secs(10));
        let t2 = clock.now_unix_nanos();
        src.delete(&BackendPath::from_rel(
            RelPath::parse("precious.txt").unwrap(),
        ))
        .await
        .unwrap();
        src.insert_file("precious.txt", b"v2-only-copy-must-survive".to_vec(), t2);

        let mut cfg2 = cfg.clone();
        cfg2.job_id = "d1-move-2".into();
        let r2 = engine
            .run(&cfg2, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(r2.is_success(), "run 2 errors: {:?}", r2.errors);
        assert_eq!(
            dst.get_file_bytes("precious.txt").as_deref(),
            Some(b"v2-only-copy-must-survive".as_slice()),
            "move MUST upload v2 before deleting source; dst must NEVER retain stale v1"
        );
        assert!(
            src.get_file_bytes("precious.txt").is_none(),
            "source should be deleted only after v2 is committed"
        );
        assert!(journal.list_active_operations().await.unwrap().is_empty());
    }

    // 3. Stale committed op with `DstPrecondition::Absent` upgrades precondition to `Existing`.
    {
        struct PreconditionCaptureBackend {
            inner: ChaosBackend,
            seen_preconditions: Mutex<Vec<DstPrecondition>>,
        }

        #[async_trait]
        impl StorageBackend for PreconditionCaptureBackend {
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
                self.seen_preconditions
                    .lock()
                    .unwrap()
                    .push(init.precondition.clone());
                self.inner.put_single_shot(init, body).await
            }
            async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
                self.inner.begin_upload(init).await
            }
            async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
                self.inner.query_upload(op).await
            }
            async fn upload_chunk(
                &self,
                op: &OperationRecord,
                chunk: ChunkUpload,
            ) -> Result<ChunkAck> {
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

        let src = Arc::new(ChaosBackend::sequential_gdrive_like(
            "d1-pre-src",
            256 * 1024,
        ));
        let dst_raw = ChaosBackend::sequential_gdrive_like("d1-pre-dst", 256 * 1024);
        dst_raw.set_faults(FaultSchedule {
            drop_final_commit_response_remaining: 1,
            ..Default::default()
        });
        let dst = Arc::new(PreconditionCaptureBackend {
            inner: dst_raw,
            seen_preconditions: Mutex::new(Vec::new()),
        });
        let journal: Arc<dyn JournalStore> = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let cancel = CancelFlag::new();

        let t1 = clock.now_unix_nanos();
        src.insert_file("cond.txt", b"v1".to_vec(), t1);
        let cfg = EngineConfig::new("d1-pre-1", JobMode::Copy, "src:", "dst:")
            .with_max_retries(0)
            .with_allow_server_side_copy(false);
        let src_dyn: Arc<dyn StorageBackend> = src.clone();
        let dst_dyn: Arc<dyn StorageBackend> = dst.clone();
        let src_e1 = src
            .stat(&BackendPath::from_rel(RelPath::parse("cond.txt").unwrap()))
            .await
            .unwrap()
            .unwrap();
        let first_res = crate::engine::task::execute_transfer_task(
            &src_dyn,
            &dst_dyn,
            &journal,
            &pool,
            &clock,
            &cancel,
            None,
            None,
            None,
            None,
            &cfg,
            "pk",
            &src.capabilities(),
            &dst.capabilities(),
            crate::engine::task::TransferTask {
                src: src_e1,
                dst_rel: RelPath::parse("cond.txt").unwrap(),
                existing_dst_node_id: None,
                precondition: DstPrecondition::Absent,
                needs_checksum_verify: false,
                dst_existing: None,
                wire_key: None,
                replace_dst_dir: None,
                defer_op_commit: false,
            },
        )
        .await;
        assert!(first_res.is_err());

        // Source changes to v2 while task still holds `DstPrecondition::Absent`
        src.delete(&BackendPath::from_rel(RelPath::parse("cond.txt").unwrap()))
            .await
            .unwrap();
        src.insert_file("cond.txt", b"v2-newer".to_vec(), t1 + 5_000_000_000);
        let src_e2 = src
            .stat(&BackendPath::from_rel(RelPath::parse("cond.txt").unwrap()))
            .await
            .unwrap()
            .unwrap();
        let old_dst = dst
            .stat(&BackendPath::from_rel(RelPath::parse("cond.txt").unwrap()))
            .await
            .unwrap()
            .unwrap();
        dst.seen_preconditions.lock().unwrap().clear();

        crate::engine::task::execute_transfer_task(
            &src_dyn,
            &dst_dyn,
            &journal,
            &pool,
            &clock,
            &cancel,
            None,
            None,
            None,
            None,
            &cfg,
            "pk",
            &src.capabilities(),
            &dst.capabilities(),
            crate::engine::task::TransferTask {
                src: src_e2,
                dst_rel: RelPath::parse("cond.txt").unwrap(),
                existing_dst_node_id: None,
                precondition: DstPrecondition::Absent,
                needs_checksum_verify: false,
                dst_existing: None,
                wire_key: None,
                replace_dst_dir: None,
                defer_op_commit: false,
            },
        )
        .await
        .unwrap();

        let seen = dst.seen_preconditions.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            DstPrecondition::Existing {
                node_id: old_dst.node_id,
                etag: old_dst.etag,
                mtime_ns: old_dst.mtime_ns,
                size: old_dst.size,
            }
        );
        assert_eq!(
            dst.inner.get_file_bytes("cond.txt").as_deref(),
            Some(b"v2-newer".as_slice())
        );
    }
}

#[tokio::test]
async fn d12_early_producer_error_marks_job_failed_and_joins_aborted_workers() {
    use crate::state::{DiffRow, JobStatus, SyncConflict, SyncDiffIndex};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct ActiveWorkerGuard(Arc<AtomicUsize>);
    impl Drop for ActiveWorkerGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct BlockingPutBackend {
        inner: ChaosBackend,
        active_workers: Arc<AtomicUsize>,
        worker_started: Arc<Notify>,
    }

    #[async_trait]
    impl StorageBackend for BlockingPutBackend {
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
            self.active_workers.fetch_add(1, Ordering::SeqCst);
            let _guard = ActiveWorkerGuard(self.active_workers.clone());
            self.worker_started.notify_one();
            futures::future::pending::<()>().await;
            unreachable!()
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

    struct FailingPage2Index {
        inner: InMemorySyncIndex,
        worker_started: Arc<Notify>,
    }

    #[async_trait]
    impl SyncDiffIndex for FailingPage2Index {
        async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.inner.insert_src_batch(entries).await
        }
        async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.inner.insert_dst_batch(entries).await
        }
        async fn finalize_and_detect_conflicts(
            &self,
            dst_case_sensitive: bool,
        ) -> Result<Vec<SyncConflict>> {
            self.inner
                .finalize_and_detect_conflicts(dst_case_sensitive)
                .await
        }
        async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
            self.inner.list_conflicts().await
        }
        async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            if after_id == 0 {
                // Return only the first row so page 2 triggers while worker 1 is active!
                return self.inner.next_src_page(0, limit.min(1)).await;
            }
            self.worker_started.notified().await;
            Err(Error::state_store("injected producer page 2 failure"))
        }
        async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            self.inner.next_dst_only_page(after_id, limit).await
        }
    }

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("d12-src", 256 * 1024));
    src.insert_file("a.txt", b"aaa".to_vec(), 1_700_000_000_000_000_000);
    src.insert_file("b.txt", b"bbb".to_vec(), 1_700_000_000_000_000_000);

    let active_workers = Arc::new(AtomicUsize::new(0));
    let worker_started = Arc::new(Notify::new());
    let dst = Arc::new(BlockingPutBackend {
        inner: ChaosBackend::sequential_gdrive_like("d12-dst", 256 * 1024),
        active_workers: active_workers.clone(),
        worker_started: worker_started.clone(),
    });
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let engine = TransferEngine::new(src, dst, journal.clone(), pool, clock, CancelFlag::new());

    let cfg = EngineConfig::new("d12-job-1", JobMode::Copy, "src:", "dst:")
        .with_transfers(2)
        .with_allow_server_side_copy(false);
    let index = Arc::new(FailingPage2Index {
        inner: InMemorySyncIndex::default(),
        worker_started,
    });

    let err = engine.run(&cfg, index).await.unwrap_err();
    assert!(err.message.contains("injected producer page 2 failure"));
    assert_eq!(
        active_workers.load(Ordering::SeqCst),
        0,
        "all worker tasks MUST have exited before TransferEngine::run returns on early error"
    );
    let job = journal.get_job("d12-job-1").await.unwrap().unwrap();
    assert_eq!(
        job.status,
        JobStatus::Failed,
        "job status MUST transition to Failed on early producer error (not stay Running)"
    );
}
