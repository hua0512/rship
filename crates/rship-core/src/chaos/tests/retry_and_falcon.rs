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
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn dst_falcon_permanent_errors_do_not_cut_concurrency() {
    use crate::adaptive::FalconConfig;

    struct PermanentErrorBackend {
        inner: ChaosBackend,
    }

    #[async_trait]
    impl StorageBackend for PermanentErrorBackend {
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
        async fn put_single_shot(&self, init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            if init.dst_path.as_str().starts_with("missing/") {
                Err(Error::not_found(format!(
                    "injected NotFound for `{}`",
                    init.dst_path
                )))
            } else {
                Err(Error::permission_denied(format!(
                    "injected PermissionDenied for `{}`",
                    init.dst_path
                )))
            }
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

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(PermanentErrorBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst", 256 * 1024),
    });
    for i in 0..3 {
        src.insert_file(
            &format!("denied/f{i}.txt"),
            b"secret".to_vec(),
            1_700_000_000_000_000_000,
        );
        src.insert_file(
            &format!("missing/m{i}.txt"),
            b"gone".to_vec(),
            1_700_000_000_000_000_000,
        );
    }

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_100));
    let engine = TransferEngine::new(src, dst, journal, pool, clock, CancelFlag::new());

    let mut cfg = EngineConfig::new("job-perm-falcon", JobMode::Copy, "src:", "dst:");
    cfg.adaptive_concurrency = true;
    cfg.falcon_config = Some(FalconConfig {
        small_file_threshold_bytes: 64 * 1024,
        small_min: 1,
        small_max: 16,
        small_initial: 8,
        large_min: 1,
        large_max: 8,
        large_initial: 4,
        ..Default::default()
    });

    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep.errors.len(), 6);
    assert_eq!(
        rep.final_small_concurrency,
        Some(8),
        "permanent PermissionDenied/NotFound errors must NEVER cut Falcon concurrency"
    );
}

#[tokio::test]
async fn dst_retries_exhausted_prevents_engine_retry_stacking() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ExhaustedErrorBackend {
        inner: ChaosBackend,
        mark_exhausted: bool,
        put_calls: AtomicUsize,
        chunk_calls: AtomicUsize,
    }

    #[async_trait]
    impl StorageBackend for ExhaustedErrorBackend {
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
        async fn put_single_shot(&self, _init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
            while body.next().await.is_some() {}
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            let mut e = Error::rate_limited("429 from backend", Some(Duration::from_secs(1)));
            if self.mark_exhausted {
                e = e.with_retries_exhausted();
            }
            Err(e)
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
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            while chunk.body.next().await.is_some() {}
            self.chunk_calls.fetch_add(1, Ordering::SeqCst);
            let mut e = Error::rate_limited("429 chunk", Some(Duration::from_secs(1)));
            if self.mark_exhausted {
                e = e.with_retries_exhausted();
            }
            Err(e)
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

    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));

    // 1. Single-shot: backend-exhausted 429 -> strictly 1 call total (no 5x5 stacking!).
    let src_ss = Arc::new(ChaosBackend::sequential_gdrive_like("src-ss", 256 * 1024));
    src_ss.insert_file("small.txt", b"hello".to_vec(), 1_700_000_000_000_000_000);
    let dst_ss = Arc::new(ExhaustedErrorBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst-ss", 256 * 1024),
        mark_exhausted: true,
        put_calls: AtomicUsize::new(0),
        chunk_calls: AtomicUsize::new(0),
    });
    let eng_ss = TransferEngine::new(
        src_ss.clone(),
        dst_ss.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("job-ex-ss", JobMode::Copy, "src:", "dst:")
        .with_max_retries(5)
        .with_base_retry_delay(Duration::from_millis(10));
    let rep_ss = eng_ss
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep_ss.errors.len(), 1);
    assert_eq!(
        dst_ss.put_calls.load(Ordering::SeqCst),
        1,
        "retries_exhausted single-shot error MUST NOT be retried by engine"
    );

    // 2. Sequential resumable: backend-exhausted 429 -> strictly 1 chunk call total!
    let src_seq = Arc::new(ChaosBackend::sequential_gdrive_like("src-seq", 256 * 1024));
    src_seq.insert_file("big.bin", vec![42u8; 300 * 1024], 1_700_000_000_000_000_000);
    let dst_seq = Arc::new(ExhaustedErrorBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst-seq", 256 * 1024),
        mark_exhausted: true,
        put_calls: AtomicUsize::new(0),
        chunk_calls: AtomicUsize::new(0),
    });
    let eng_seq = TransferEngine::new(
        src_seq,
        dst_seq.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let rep_seq = eng_seq
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep_seq.errors.len(), 1);
    assert_eq!(
        dst_seq.chunk_calls.load(Ordering::SeqCst),
        1,
        "retries_exhausted sequential chunk error MUST NOT be retried by engine"
    );

    // 3. Parallel multipart (part_concurrency = 1): backend-exhausted 429 -> strictly 1 call!
    let src_mp = Arc::new(ChaosBackend::parallel_s3_like("src-mp", 64 * 1024));
    src_mp.insert_file("mp.bin", vec![7u8; 192 * 1024], 1_700_000_000_000_000_000);
    let dst_mp = Arc::new(ExhaustedErrorBackend {
        inner: ChaosBackend::parallel_s3_like("dst-mp", 64 * 1024),
        mark_exhausted: true,
        put_calls: AtomicUsize::new(0),
        chunk_calls: AtomicUsize::new(0),
    });
    let eng_mp = TransferEngine::new(
        src_mp,
        dst_mp.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let cfg_mp = cfg
        .clone()
        .with_part_concurrency(1)
        .with_chunk_size(Some(64 * 1024));
    let rep_mp = eng_mp
        .run(&cfg_mp, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep_mp.errors.len(), 1);
    assert_eq!(
        dst_mp.chunk_calls.load(Ordering::SeqCst),
        1,
        "retries_exhausted multipart chunk error MUST NOT be retried by engine"
    );

    // 4. Control: non-exhausted 429 DOES retry up to max_retries + 1 = 6 calls.
    let dst_ctrl = Arc::new(ExhaustedErrorBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst-ctrl", 256 * 1024),
        mark_exhausted: false,
        put_calls: AtomicUsize::new(0),
        chunk_calls: AtomicUsize::new(0),
    });
    let eng_ctrl = TransferEngine::new(
        src_ss,
        dst_ctrl.clone(),
        Arc::new(InMemoryJournal::default()),
        pool,
        clock,
        CancelFlag::new(),
    );
    let rep_ctrl = eng_ctrl
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep_ctrl.errors.len(), 1);
    assert_eq!(dst_ctrl.put_calls.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn dst_engine_retry_quota_fails_fast_and_refunds_on_success() {
    use crate::engine::TokenBucketRetryQuota;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FlakyPutBackend {
        inner: ChaosBackend,
        fail_count: usize,
        timeout_errors: bool,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl StorageBackend for FlakyPutBackend {
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
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= self.fail_count {
                let mut body = body;
                while body.next().await.is_some() {}
                if self.timeout_errors {
                    return Err(Error::timeout("injected request timeout"));
                }
                return Err(Error::network("injected transient network reset"));
            }
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

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src-q", 256 * 1024));
    src.insert_file("doc.txt", b"payload".to_vec(), 1_700_000_000_000_000_000);
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));

    // 1. Quota exhausted -> fail fast after only 2 retries (3 total calls) despite max_retries = 5!
    let quota_exhaust = Arc::new(TokenBucketRetryQuota::new(10, 5, 10, 1));
    let dst_exhaust = Arc::new(FlakyPutBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst-q1", 256 * 1024),
        fail_count: 100,
        timeout_errors: false,
        calls: AtomicUsize::new(0),
    });
    let eng1 = TransferEngine::new(
        src.clone(),
        dst_exhaust.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let cfg1 = EngineConfig::new("job-quota-exhaust", JobMode::Copy, "src:", "dst:")
        .with_max_retries(5)
        .with_base_retry_delay(Duration::from_millis(10))
        .with_retry_quota(Some(quota_exhaust.clone()));
    let rep1 = eng1
        .run(&cfg1, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep1.errors.len(), 1);
    assert_eq!(
        dst_exhaust.calls.load(Ordering::SeqCst),
        3,
        "10-token quota with retry_cost=5 allows 2 retries (3 total calls), then fails fast"
    );
    assert_eq!(quota_exhaust.available(), 0);

    // 2. Timeout retry (cost 10) succeeds on retry -> full timeout cost refunded (0 -> 10)!
    let quota_refund = Arc::new(TokenBucketRetryQuota::new(10, 5, 10, 1));
    let dst_refund = Arc::new(FlakyPutBackend {
        inner: ChaosBackend::sequential_gdrive_like("dst-q2", 256 * 1024),
        fail_count: 1,
        timeout_errors: true,
        calls: AtomicUsize::new(0),
    });
    let eng2 = TransferEngine::new(
        src,
        dst_refund.clone(),
        Arc::new(InMemoryJournal::default()),
        pool,
        clock,
        CancelFlag::new(),
    );
    let cfg2 = EngineConfig::new("job-quota-refund", JobMode::Copy, "src:", "dst:")
        .with_max_retries(5)
        .with_base_retry_delay(Duration::from_millis(10))
        .with_retry_quota(Some(quota_refund.clone()));
    let rep2 = eng2
        .run(&cfg2, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep2.is_success(), "errors: {:?}", rep2.errors);
    assert_eq!(dst_refund.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        quota_refund.available(),
        10,
        "successful timeout retry MUST refund timeout_retry_cost back to bucket"
    );
}

#[tokio::test]
async fn dst_falcon_bounds_multipart_part_concurrency_and_never_deadlocks_at_one() {
    use crate::adaptive::FalconConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MultipartProbeBackend {
        inner: ChaosBackend,
        clock: Arc<VirtualClock>,
        advance_per_part: Duration,
        in_flight_parts: AtomicUsize,
        peak_parts: AtomicUsize,
        parts_uploaded: AtomicUsize,
    }

    #[async_trait]
    impl StorageBackend for MultipartProbeBackend {
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
            self.inner.put_single_shot(init, body).await
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            self.inner.begin_upload(init).await
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            self.inner.query_upload(op).await
        }
        async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
            let cur = self.in_flight_parts.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_parts.fetch_max(cur, Ordering::SeqCst);
            self.parts_uploaded.fetch_add(1, Ordering::SeqCst);
            // Yield several times so all concurrently spawned parts in this wave overlap in flight.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            let active = self.in_flight_parts.load(Ordering::SeqCst).max(1);
            // Yield again so sibling parts sample `active` before any part decrements `in_flight_parts`.
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            if !self.advance_per_part.is_zero() {
                // Parallel parts overlap in wall time: `active` concurrent parts divide virtual time.
                let scaled = self.advance_per_part / (active as u32);
                self.clock.advance(scaled);
            }
            let res = self.inner.upload_chunk(op, chunk).await;
            self.in_flight_parts.fetch_sub(1, Ordering::SeqCst);
            res
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

    // 9 parts of 64 KiB each = 576 KiB (> 32 KiB small_file_threshold -> LargeStreaming).
    // 9 parts aligns cleanly to waves 2 + 3 + 4 during Falcon upward probing.
    let payload: Vec<u8> = (0..(576 * 1024)).map(|i| ((i * 19) % 251) as u8).collect();
    let src = Arc::new(ChaosBackend::parallel_s3_like("src-mp-f", 64 * 1024));
    src.insert_file("movie.mkv", payload.clone(), 1_700_000_000_000_000_000);
    let pool = BufferPool::new(4 * 1024 * 1024, 256 * 1024).unwrap();

    // 1. Falcon capped at c = 2 bounds multipart part concurrency == 2 even when part_concurrency = 8!
    let clock_c2 = Arc::new(VirtualClock::new(1_700_000_000));
    let dst_c2 = Arc::new(MultipartProbeBackend {
        inner: ChaosBackend::parallel_s3_like("dst-mp-c2", 64 * 1024),
        clock: clock_c2.clone(),
        advance_per_part: Duration::ZERO,
        in_flight_parts: AtomicUsize::new(0),
        peak_parts: AtomicUsize::new(0),
        parts_uploaded: AtomicUsize::new(0),
    });
    let eng_c2 = TransferEngine::new(
        src.clone(),
        dst_c2.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock_c2,
        CancelFlag::new(),
    );
    let cfg_c2 = EngineConfig::new("job-mp-c2", JobMode::Copy, "src:", "dst:")
        .with_part_concurrency(8)
        .with_chunk_size(Some(64 * 1024))
        .with_adaptive_concurrency(true)
        .with_falcon_config(Some(FalconConfig {
            small_file_threshold_bytes: 32 * 1024,
            large_min: 1,
            large_max: 2,
            large_initial: 2,
            ..Default::default()
        }));
    let rep_c2 = eng_c2
        .run(&cfg_c2, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_c2.is_success(), "errors: {:?}", rep_c2.errors);
    assert_eq!(dst_c2.parts_uploaded.load(Ordering::SeqCst), 9);
    assert_eq!(
        dst_c2.inner.get_file_bytes("movie.mkv").as_deref(),
        Some(payload.as_slice())
    );
    assert_eq!(
        dst_c2.peak_parts.load(Ordering::SeqCst),
        2,
        "Falcon c=2 must bound multipart parts to 2 (not part_concurrency=8), observed peak {}",
        dst_c2.peak_parts.load(Ordering::SeqCst)
    );

    // 2. Falcon at c = 1 MUST NOT deadlock and runs strictly 1 part at a time!
    let clock_c1 = Arc::new(VirtualClock::new(1_700_000_000));
    let dst_c1 = Arc::new(MultipartProbeBackend {
        inner: ChaosBackend::parallel_s3_like("dst-mp-c1", 64 * 1024),
        clock: clock_c1.clone(),
        advance_per_part: Duration::ZERO,
        in_flight_parts: AtomicUsize::new(0),
        peak_parts: AtomicUsize::new(0),
        parts_uploaded: AtomicUsize::new(0),
    });
    let eng_c1 = TransferEngine::new(
        src.clone(),
        dst_c1.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock_c1,
        CancelFlag::new(),
    );
    let cfg_c1 = EngineConfig::new("job-mp-c1", JobMode::Copy, "src:", "dst:")
        .with_part_concurrency(8)
        .with_chunk_size(Some(64 * 1024))
        .with_adaptive_concurrency(true)
        .with_falcon_config(Some(FalconConfig {
            small_file_threshold_bytes: 32 * 1024,
            large_min: 1,
            large_max: 1,
            large_initial: 1,
            ..Default::default()
        }));
    let rep_c1 = eng_c1
        .run(&cfg_c1, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_c1.is_success(), "errors: {:?}", rep_c1.errors);
    assert_eq!(dst_c1.parts_uploaded.load(Ordering::SeqCst), 9);
    assert_eq!(
        dst_c1.inner.get_file_bytes("movie.mkv").as_deref(),
        Some(payload.as_slice())
    );
    assert_eq!(dst_c1.peak_parts.load(Ordering::SeqCst), 1);

    // 3. Live `record_bytes` during multipart stream probes Falcon upward mid-file (2 -> >2)!
    let clock_grow = Arc::new(VirtualClock::new(1_700_000_000));
    let dst_grow = Arc::new(MultipartProbeBackend {
        inner: ChaosBackend::parallel_s3_like("dst-mp-grow", 64 * 1024),
        clock: clock_grow.clone(),
        advance_per_part: Duration::from_millis(1200),
        in_flight_parts: AtomicUsize::new(0),
        peak_parts: AtomicUsize::new(0),
        parts_uploaded: AtomicUsize::new(0),
    });
    let eng_grow = TransferEngine::new(
        src,
        dst_grow.clone(),
        Arc::new(InMemoryJournal::default()),
        pool,
        clock_grow,
        CancelFlag::new(),
    );
    let cfg_grow = EngineConfig::new("job-mp-grow", JobMode::Copy, "src:", "dst:")
        .with_part_concurrency(8)
        .with_chunk_size(Some(64 * 1024))
        .with_adaptive_concurrency(true)
        .with_falcon_config(Some(FalconConfig {
            small_file_threshold_bytes: 32 * 1024,
            large_min: 1,
            large_max: 8,
            large_initial: 2,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        }));
    let rep_grow = eng_grow
        .run(&cfg_grow, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_grow.is_success(), "errors: {:?}", rep_grow.errors);
    assert_eq!(dst_grow.parts_uploaded.load(Ordering::SeqCst), 9);
    assert_eq!(
        dst_grow.inner.get_file_bytes("movie.mkv").as_deref(),
        Some(payload.as_slice())
    );
    assert!(
        rep_grow.final_large_concurrency.unwrap_or(0) > 2,
        "live streamed bytes must probe Falcon upward mid-file from initial 2, got {:?}",
        rep_grow.final_large_concurrency
    );
    assert!(
        dst_grow.peak_parts.load(Ordering::SeqCst) > 2,
        "dynamic Falcon multipart ceiling must unlock >2 concurrent parts once Falcon probes up, peak={}",
        dst_grow.peak_parts.load(Ordering::SeqCst)
    );
}

/// Engine retries draw from the destination backend's shared `(remote, principal)` quota
/// when the run has no explicit quota, so separate runs against one remote share one
/// budget instead of each starting with a fresh bucket.
#[tokio::test]
async fn engine_runs_share_the_destination_backend_retry_quota() {
    use crate::engine::{RetryQuota, TokenBucketRetryQuota};

    let src = Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024));
    let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
    src.insert_file("a.bin", vec![7; 64], 1_700_000_000_000_000_000);
    dst.set_faults(FaultSchedule {
        fail_put_transient_paths: std::iter::once("a.bin".to_string()).collect(),
        ..Default::default()
    });
    // 10 tokens, 5 per retry, nothing refunded: two retries in total across all runs.
    let quota = Arc::new(TokenBucketRetryQuota::new(10, 5, 10, 0));
    dst.set_retry_quota(Some(quota.clone() as Arc<dyn RetryQuota>));

    let cfg = EngineConfig::new("shared-quota", JobMode::Copy, "src:", "dst:")
        .with_transfers(1)
        .with_allow_server_side_copy(false)
        .with_max_retries(5)
        .with_base_retry_delay(Duration::from_millis(1));
    for _ in 0..2 {
        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            Arc::new(InMemoryJournal::default()),
            BufferPool::new(256 * 1024, 64 * 1024).unwrap(),
            Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
            CancelFlag::new(),
        );
        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(!rep.errors.is_empty());
    }
    assert_eq!(quota.available(), 0);
    // Run 1: 1 attempt + 2 retries (quota exhausted). Run 2: 1 attempt, no retry budget.
    assert_eq!(dst.put_single_shot_calls(), 4);
}
