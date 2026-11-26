use super::super::*;
use crate::backend::BackendPath;
use crate::clock::VirtualClock;
use crate::path::RelPath;
use crate::state::JobMode;
use crate::types::{Capabilities, Entry};
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn p4_falcon_saturated_large_lane_does_not_starve_idle_small_lane() {
    use crate::adaptive::FalconConfig;
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{MemoryJournalStore, MemorySyncIndex, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind};
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::{Notify, watch};

    struct GatedLargeDst {
        inner: Arc<ChaosBackend>,
        small_threshold: u64,
        release_large: watch::Receiver<bool>,
        small_done: Arc<AtomicUsize>,
        large_done: Arc<AtomicUsize>,
        expected_small: usize,
        all_small_done: Arc<Notify>,
    }

    #[async_trait]
    impl StorageBackend for GatedLargeDst {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "gated-large"
        }
        fn endpoint_identity(&self) -> String {
            format!("gated-large://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.single_shot_max_bytes = 64 * 1024;
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
            if init.total_size > self.small_threshold {
                let mut rx = self.release_large.clone();
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                let res = self.inner.put_single_shot(init, body).await;
                if res.is_ok() {
                    self.large_done.fetch_add(1, Ordering::SeqCst);
                }
                res
            } else {
                let res = self.inner.put_single_shot(init, body).await;
                if res.is_ok()
                    && self.small_done.fetch_add(1, Ordering::SeqCst) + 1 == self.expected_small
                {
                    self.all_small_done.notify_one();
                }
                res
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

    let small_threshold = 1024u64;
    // 160 large files exceed `lane_cap = 128` + `large_max = 1`, which previously caused
    // `large_tx.send().await` to head-of-line block the producer before reaching small files.
    let large_count = 160usize;
    let small_count = 8usize;
    let mtime = 1_700_000_000_000_000_000i64;

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("p4-src", 256 * 1024));
    for i in 0..large_count {
        src.insert_file(&format!("a_large_{i:03}.bin"), vec![0xAA; 2048], mtime);
    }
    for i in 0..small_count {
        src.insert_file(&format!("z_small_{i:03}.bin"), vec![0xBB; 128], mtime);
    }

    let (release_tx, release_rx) = watch::channel(false);
    let small_done = Arc::new(AtomicUsize::new(0));
    let large_done = Arc::new(AtomicUsize::new(0));
    let all_small_done = Arc::new(Notify::new());
    let dst = Arc::new(GatedLargeDst {
        inner: Arc::new(ChaosBackend::parallel_s3_like("p4-dst", 256 * 1024)),
        small_threshold,
        release_large: release_rx,
        small_done: small_done.clone(),
        large_done: large_done.clone(),
        expected_small: small_count,
        all_small_done: all_small_done.clone(),
    });

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).unwrap();
    let engine = Arc::new(TransferEngine::new(
        src,
        dst,
        Arc::new(MemoryJournalStore::new()),
        pool,
        clock,
        CancelFlag::new(),
    ));

    let fcfg = FalconConfig {
        small_file_threshold_bytes: small_threshold,
        small_min: 2,
        small_max: 4,
        small_initial: 4,
        large_min: 1,
        large_max: 1,
        large_initial: 1,
        ..Default::default()
    };
    let cfg = EngineConfig::new("job-p4", JobMode::Copy, "src", "dst")
        .with_adaptive_concurrency(true)
        .with_falcon_config(Some(fcfg))
        .with_allow_server_side_copy(false);

    let eng_c = engine.clone();
    let run_handle = tokio::spawn(async move {
        eng_c
            .run(&cfg, Arc::new(MemorySyncIndex::new()))
            .await
            .unwrap()
    });

    // All 8 small files MUST complete promptly while every large file is still blocked!
    tokio::time::timeout(Duration::from_secs(3), all_small_done.notified())
        .await
        .expect("small files were head-of-line blocked by saturated large lane");
    assert_eq!(small_done.load(Ordering::SeqCst), small_count);
    assert_eq!(
        large_done.load(Ordering::SeqCst),
        0,
        "large files must still be blocked when small files finish"
    );

    let _ = release_tx.send(true);
    let rep = tokio::time::timeout(Duration::from_secs(5), run_handle)
        .await
        .expect("engine.run timed out after releasing large lane")
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, (large_count + small_count) as u64);
}

#[tokio::test]
async fn p5_move_planned_skips_execute_concurrently_and_preserve_mutated_source() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{MemoryJournalStore, MemorySyncIndex, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind};
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;

    struct ConcurrentStatDeleteSrc {
        inner: Arc<ChaosBackend>,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
        mutate_target: String,
    }

    #[async_trait]
    impl StorageBackend for ConcurrentStatDeleteSrc {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "p5-src"
        }
        fn endpoint_identity(&self) -> String {
            format!("p5-src://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            self.inner.capabilities()
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut res = self.inner.stat(path).await;
            if path.nfc_path.as_str() == self.mutate_target
                && let Ok(Some(ref mut e)) = res
            {
                e.mtime_ns += 5_000_000_000;
                e.size += 1;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            res
        }
        async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
            self.inner.list_stream(prefix, recursive).await
        }
        async fn list_ordered_page(
            &self,
            prefix: &RelPath,
            start_after: Option<&str>,
            continuation: Option<&str>,
            max_keys: u32,
        ) -> Result<crate::backend::OrderedListPage> {
            self.inner
                .list_ordered_page(prefix, start_after, continuation, max_keys)
                .await
        }
        async fn mkdir(&self, path: &RelPath) -> Result<()> {
            self.inner.mkdir(path).await
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let res = self.inner.delete(path).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            res
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

    let mtime = 1_700_000_000_000_000_000i64;
    for ordered in [false, true] {
        let raw_src = Arc::new(
            ChaosBackend::parallel_s3_like("p5-src", 64 * 1024)
                .with_caps(|c| c.supports_ordered_utf8_list = ordered),
        );
        let dst = Arc::new(
            ChaosBackend::parallel_s3_like("p5-dst", 64 * 1024)
                .with_caps(|c| c.supports_ordered_utf8_list = ordered),
        );
        for i in 0..16 {
            let name = format!("synced_{i:02}.txt");
            let data = format!("payload-{i:02}").into_bytes();
            raw_src.insert_file(&name, data.clone(), mtime);
            dst.insert_file(&name, data, mtime);
        }
        // 17th skipped file mutates on `stat` -> must NOT be deleted!
        raw_src.insert_file("mutated.txt", b"original".to_vec(), mtime);
        dst.insert_file("mutated.txt", b"original".to_vec(), mtime);

        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let src = Arc::new(ConcurrentStatDeleteSrc {
            inner: raw_src.clone(),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: max_in_flight.clone(),
            mutate_target: "mutated.txt".into(),
        });

        let engine = TransferEngine::new(
            src,
            dst,
            Arc::new(MemoryJournalStore::new()),
            BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
            Arc::new(VirtualClock::new(1_700_000_500)),
            CancelFlag::new(),
        );
        let cfg = EngineConfig::new("job-p5", JobMode::Move, "src", "dst").with_transfers(8);
        let rep = engine
            .run(&cfg, Arc::new(MemorySyncIndex::new()))
            .await
            .unwrap();

        assert!(
            max_in_flight.load(Ordering::SeqCst) >= 2,
            "planned move skips must run concurrently (ordered={ordered}, max_in_flight={})",
            max_in_flight.load(Ordering::SeqCst)
        );
        assert_eq!(rep.files_skipped, 16);
        assert_eq!(rep.sources_deleted, 16);
        assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
        for i in 0..16 {
            assert!(
                raw_src
                    .get_file_bytes(&format!("synced_{i:02}.txt"))
                    .is_none()
            );
        }
        assert!(
            raw_src.get_file_bytes("mutated.txt").is_some(),
            "mutated source MUST NOT be deleted"
        );
    }
}
