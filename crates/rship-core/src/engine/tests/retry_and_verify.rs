use super::super::*;
use crate::backend::BackendPath;
use crate::clock::VirtualClock;
use crate::error::{Error, ErrorKind};
use crate::path::RelPath;
use crate::state::{BaselineMode, JobMode};
use crate::types::{Capabilities, Entry, EntryKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[test]
fn is_retryable_returns_false_when_retries_exhausted() {
    let net = Error::network("reset");
    assert!(is_retryable(&net));
    assert!(!is_retryable(&net.with_retries_exhausted()));

    let throttled = Error::rate_limited("429", Some(Duration::from_secs(1)));
    assert!(is_retryable(&throttled));
    assert!(!is_retryable(&throttled.with_retries_exhausted()));

    assert!(!is_retryable(&Error::permission_denied("403")));
}

#[test]
fn token_bucket_retry_quota_charges_exhausts_and_refunds() {
    let q = TokenBucketRetryQuota::new(20, 5, 10, 1);
    assert_eq!(q.available(), 20);
    assert!(q.try_acquire(false)); // 20 -> 15
    assert_eq!(q.available(), 15);
    assert!(q.try_acquire(true)); // 15 -> 5
    assert_eq!(q.available(), 5);
    assert!(!q.try_acquire(true)); // needs 10, only 5 -> fail fast!
    assert_eq!(q.available(), 5);
    assert!(q.try_acquire(false)); // 5 -> 0
    assert!(!q.try_acquire(false)); // exhausted -> fail fast!

    // Refund on retry success & non-retry success, capped at max_tokens.
    q.record_success(true, true); // 0 -> 10
    assert_eq!(q.available(), 10);
    q.record_success(true, false); // 10 -> 15
    assert_eq!(q.available(), 15);
    q.record_success(false, false); // 15 -> 16
    assert_eq!(q.available(), 16);
    q.record_success(true, true); // 16 -> min(26, 20) = 20
    assert_eq!(q.available(), 20);
}

#[tokio::test]
async fn backoff_sleep_caps_huge_retry_after_and_uses_full_jitter() {
    let vclock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let clock: Arc<dyn Clock> = vclock.clone();
    let cancel = CancelFlag::new();
    let max_delay = Duration::from_secs(60);

    // Huge Retry-After (3600s) MUST be capped to max_retry_delay (60s) and use clock.sleep().
    let err_ra = Error::rate_limited("429", Some(Duration::from_secs(3600)));
    let t0 = vclock.now_unix_nanos();
    backoff_sleep(
        &err_ra,
        1,
        Duration::from_millis(50),
        max_delay,
        &BackoffJitter::seeded(1),
        &clock,
        &cancel,
    )
    .await
    .unwrap();
    let elapsed_ra_ns = vclock.now_unix_nanos() - t0;
    assert_eq!(
        elapsed_ra_ns,
        max_delay.as_nanos() as i64,
        "Retry-After 3600s must cap strictly at max_retry_delay (60s)"
    );

    // Full jitter without Retry-After: [0, min(max_delay, base_delay * 2^(attempt-1))].
    // For base_delay = 1s, attempt = 3 -> ceiling = 4s.
    let err_net = Error::network("transient");
    let base = Duration::from_secs(1);
    let ceiling = Duration::from_secs(4);
    let jitter = BackoffJitter::seeded(0x5eed);
    let mut saw_lower_half = false;
    let mut saw_upper_half = false;
    let mut min_seen = Duration::MAX;
    let mut max_seen = Duration::ZERO;
    for _ in 0..200 {
        let before = vclock.now_unix_nanos();
        backoff_sleep(&err_net, 3, base, max_delay, &jitter, &clock, &cancel)
            .await
            .unwrap();
        let slept = Duration::from_nanos((vclock.now_unix_nanos() - before) as u64);
        assert!(
            slept <= ceiling,
            "full jitter sample {slept:?} exceeded ceiling {ceiling:?}"
        );
        if slept < ceiling / 2 {
            saw_lower_half = true;
        }
        if slept > ceiling / 2 {
            saw_upper_half = true;
        }
        min_seen = min_seen.min(slept);
        max_seen = max_seen.max(slept);
    }
    assert!(
        saw_lower_half && saw_upper_half && max_seen > min_seen,
        "expected full-jitter spread across [0, {ceiling:?}], saw [{min_seen:?}, {max_seen:?}]"
    );

    // High attempt exponent must also cap at max_retry_delay without overflowing.
    for _ in 0..32 {
        let d = compute_backoff_delay(&err_net, 40, base, max_delay, &jitter);
        assert!(d <= max_delay);
    }
}

#[tokio::test]
async fn d5_prepare_operation_id_persists_remote_op_id_before_single_shot_and_ssc() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{MemoryJournalStore, MemorySyncIndex, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind, NodeId};
    use async_trait::async_trait;
    use std::sync::Mutex;

    type ObservedOpIds = Arc<Mutex<Vec<(Option<NodeId>, Option<String>)>>>;

    #[derive(Clone)]
    struct DupNameSpyBackend {
        inner: Arc<ChaosBackend>,
        journal: Arc<MemoryJournalStore>,
        next_id: Arc<AtomicU64>,
        ssc_enabled: bool,
        observed_in_put: ObservedOpIds,
        observed_in_ssc: ObservedOpIds,
    }

    #[async_trait]
    impl StorageBackend for DupNameSpyBackend {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "dup-spy"
        }
        fn endpoint_identity(&self) -> String {
            format!("dup-spy://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.allows_duplicate_names = true;
            caps.supports_server_side_copy = self.ssc_enabled;
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
        async fn prepare_operation_id(&self, init: &UploadInit) -> Result<Option<NodeId>> {
            if init.existing_node_id.is_some() {
                return Ok(None);
            }
            let seq = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(Some(NodeId(format!("pregen-d5-{seq}"))))
        }
        async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
            let ops = self.journal.list_active_operations().await?;
            let persisted = ops
                .into_iter()
                .find(|o| o.op_id == init.op_id)
                .and_then(|o| o.remote_op_id);
            self.observed_in_put
                .lock()
                .unwrap()
                .push((init.pregenerated_id.clone(), persisted));
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
        fn can_server_side_copy_from(&self, _src_endpoint: &str) -> bool {
            self.ssc_enabled
        }
        async fn server_side_copy(
            &self,
            _src_endpoint: &str,
            src_path: &BackendPath,
            init: &UploadInit,
        ) -> Result<Option<Entry>> {
            let ops = self.journal.list_active_operations().await?;
            let persisted = ops
                .into_iter()
                .find(|o| o.op_id == init.op_id)
                .and_then(|o| o.remote_op_id);
            self.observed_in_ssc
                .lock()
                .unwrap()
                .push((init.pregenerated_id.clone(), persisted));
            let entry = Entry::file(init.dst_path.clone(), init.total_size, init.src_mtime_ns)
                .with_node_id(
                    init.pregenerated_id
                        .clone()
                        .unwrap_or_else(|| NodeId("fallback".into())),
                );
            let _ = src_path;
            Ok(Some(entry))
        }
    }

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();

    // 1. Single-shot upload: journal MUST already contain `remote_op_id` BEFORE `put_single_shot`.
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    src.insert_file(
        "doc.txt",
        b"d5-single-shot".to_vec(),
        1_700_000_000_000_000_000,
    );
    let journal = Arc::new(MemoryJournalStore::new());
    let dst_put = Arc::new(DupNameSpyBackend {
        inner: Arc::new(ChaosBackend::sequential_gdrive_like("dst-put", 256 * 1024)),
        journal: journal.clone(),
        next_id: Arc::new(AtomicU64::new(0)),
        ssc_enabled: false,
        observed_in_put: Arc::new(Mutex::new(Vec::new())),
        observed_in_ssc: Arc::new(Mutex::new(Vec::new())),
    });
    let engine = TransferEngine::new(
        src.clone(),
        dst_put.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("job-d5-put", JobMode::Copy, "src", "dst-put");
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    let put_obs = dst_put.observed_in_put.lock().unwrap().clone();
    assert_eq!(
        put_obs,
        vec![(
            Some(NodeId("pregen-d5-1".into())),
            Some("pregen-d5-1".to_string())
        )],
        "op.remote_op_id MUST be persisted in JournalStore BEFORE put_single_shot runs"
    );

    // 2. Server-side copy: journal MUST already contain `remote_op_id` BEFORE `server_side_copy`.
    let journal_ssc = Arc::new(MemoryJournalStore::new());
    let dst_ssc = Arc::new(DupNameSpyBackend {
        inner: Arc::new(ChaosBackend::sequential_gdrive_like("dst-ssc", 256 * 1024)),
        journal: journal_ssc.clone(),
        next_id: Arc::new(AtomicU64::new(0)),
        ssc_enabled: true,
        observed_in_put: Arc::new(Mutex::new(Vec::new())),
        observed_in_ssc: Arc::new(Mutex::new(Vec::new())),
    });
    let engine_ssc = TransferEngine::new(
        src,
        dst_ssc.clone(),
        journal_ssc,
        pool,
        clock,
        CancelFlag::new(),
    );
    let cfg_ssc = EngineConfig::new("job-d5-ssc", JobMode::Copy, "src", "dst-ssc");
    let rep_ssc = engine_ssc
        .run(&cfg_ssc, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep_ssc.is_success(), "{:?}", rep_ssc.errors);
    let ssc_obs = dst_ssc.observed_in_ssc.lock().unwrap().clone();
    assert_eq!(
        ssc_obs,
        vec![(
            Some(NodeId("pregen-d5-1".into())),
            Some("pregen-d5-1".to_string())
        )],
        "op.remote_op_id MUST be persisted in JournalStore BEFORE server_side_copy runs"
    );
}

#[test]
fn c3_verify_committed_checksum_unit_cases() {
    use crate::types::{Checksum, HashKind};

    let make_entry = |ck: Option<Checksum>| Entry {
        node_id: None,
        parent_id: None,
        raw_path: None,
        nfc_path: RelPath::parse("doc.bin").unwrap(),
        kind: EntryKind::File,
        size: 16,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: ck,
    };

    let src_sha = make_entry(Some(Checksum {
        kind: HashKind::Sha256,
        hex: "aabbccdd".into(),
    }));
    let dst_same_upper = make_entry(Some(Checksum {
        kind: HashKind::Sha256,
        hex: "AABBCCDD".into(),
    }));
    assert!(verify_committed_checksum(&src_sha, &dst_same_upper).is_ok());

    let dst_mismatch = make_entry(Some(Checksum {
        kind: HashKind::Sha256,
        hex: "deadbeef".into(),
    }));
    let err = verify_committed_checksum(&src_sha, &dst_mismatch).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Integrity);
    assert!(err.message.contains("end-to-end checksum mismatch"));

    // Different hash kinds or composite multipart ETags (containing '-') are skipped cleanly.
    let dst_md5 = make_entry(Some(Checksum {
        kind: HashKind::Md5,
        hex: "deadbeef".into(),
    }));
    assert!(verify_committed_checksum(&src_sha, &dst_md5).is_ok());

    let src_md5 = make_entry(Some(Checksum {
        kind: HashKind::Md5,
        hex: "aabbccdd".into(),
    }));
    let dst_multipart = make_entry(Some(Checksum {
        kind: HashKind::Md5,
        hex: "deadbeef-4".into(),
    }));
    assert!(verify_committed_checksum(&src_md5, &dst_multipart).is_ok());

    let dst_none = make_entry(None);
    assert!(verify_committed_checksum(&src_sha, &dst_none).is_ok());
}

#[tokio::test]
async fn c3_checksum_mismatch_fails_without_baseline_or_move_source_delete() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::chaos::ChaosBackend;
    use crate::source::{ByteStream, DataSource};
    use crate::state::{MemoryJournalStore, MemorySyncIndex, OperationRecord};
    use crate::types::{ByteRange, Checksum, HashKind};
    use async_trait::async_trait;

    struct CorruptChecksumDst {
        inner: Arc<ChaosBackend>,
        ssc_enabled: bool,
    }

    impl CorruptChecksumDst {
        fn corrupt(mut e: Entry) -> Entry {
            e.checksum = Some(Checksum {
                kind: HashKind::Sha256,
                hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            });
            e
        }
    }

    #[async_trait]
    impl StorageBackend for CorruptChecksumDst {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            "corrupt-dst"
        }
        fn endpoint_identity(&self) -> String {
            format!("corrupt-dst://{}", self.inner.name())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.supports_server_side_copy = self.ssc_enabled;
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
            self.inner
                .put_single_shot(init, body)
                .await
                .map(Self::corrupt)
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            self.inner.begin_upload(init).await
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            self.inner.query_upload(op).await
        }
        async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
            let mut ack = self.inner.upload_chunk(op, chunk).await?;
            ack.completed = ack.completed.map(Self::corrupt);
            Ok(ack)
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.inner.finish_upload(op, parts).await.map(Self::corrupt)
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.inner.abort_upload(op).await
        }
        async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
            match self.inner.reconcile_operation(op).await? {
                ReconcileOutcome::Committed(e) => Ok(ReconcileOutcome::Committed(Self::corrupt(e))),
                other => Ok(other),
            }
        }
        fn can_server_side_copy_from(&self, _src_endpoint: &str) -> bool {
            self.ssc_enabled
        }
        async fn server_side_copy(
            &self,
            _src_endpoint: &str,
            _src_path: &BackendPath,
            init: &UploadInit,
        ) -> Result<Option<Entry>> {
            let entry = Entry::file(init.dst_path.clone(), init.total_size, init.src_mtime_ns);
            Ok(Some(Self::corrupt(entry)))
        }
    }

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let pool = BufferPool::new(1024 * 1024, 64 * 1024).unwrap();
    let mtime = 1_700_000_000_000_000_000i64;

    // 1. Copy (single-shot + multipart) MUST fail and persist ZERO baselines.
    let src = Arc::new(ChaosBackend::parallel_s3_like("c3-src", 32 * 1024));
    src.insert_file("small.bin", b"hello-c3-small".to_vec(), mtime);
    src.insert_file("large.bin", vec![0x42u8; 80 * 1024], mtime);
    let dst = Arc::new(CorruptChecksumDst {
        inner: Arc::new(ChaosBackend::parallel_s3_like("c3-dst", 32 * 1024)),
        ssc_enabled: false,
    });
    let journal = Arc::new(MemoryJournalStore::new());
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("job-c3-copy", JobMode::Copy, "src", "dst")
        .with_baseline_mode(BaselineMode::All)
        .with_allow_server_side_copy(false);
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(!rep.is_success());
    assert_eq!(rep.files_transferred, 0);
    assert_eq!(rep.errors.len(), 2, "{:?}", rep.errors);
    assert!(
        rep.errors
            .iter()
            .all(|e| e.contains("end-to-end checksum mismatch")),
        "{:?}",
        rep.errors
    );
    let pair_key = make_prefixed_pair_key(
        &src.endpoint_identity(),
        &RelPath::root(),
        &dst.endpoint_identity(),
        &RelPath::root(),
    );
    assert!(
        journal
            .get_baseline(&pair_key, &RelPath::parse("small.bin").unwrap())
            .await
            .unwrap()
            .is_none(),
        "must NOT persist baseline on single-shot checksum mismatch"
    );
    assert!(
        journal
            .get_baseline(&pair_key, &RelPath::parse("large.bin").unwrap())
            .await
            .unwrap()
            .is_none(),
        "must NOT persist baseline on multipart finish_upload checksum mismatch"
    );

    // 2. Move mode MUST NOT delete source on single-shot, multipart, or server-side copy mismatch!
    for ssc in [false, true] {
        let msrc = Arc::new(ChaosBackend::parallel_s3_like("c3-msrc", 32 * 1024));
        msrc.insert_file("precious.bin", b"do-not-delete".to_vec(), mtime);
        let mdst = Arc::new(CorruptChecksumDst {
            inner: Arc::new(ChaosBackend::parallel_s3_like("c3-mdst", 32 * 1024)),
            ssc_enabled: ssc,
        });
        let mjournal = Arc::new(MemoryJournalStore::new());
        let mengine = TransferEngine::new(
            msrc.clone(),
            mdst,
            mjournal,
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let mcfg = EngineConfig::new("job-c3-move", JobMode::Move, "msrc", "mdst")
            .with_allow_server_side_copy(ssc);
        let mrep = mengine
            .run(&mcfg, Arc::new(MemorySyncIndex::new()))
            .await
            .unwrap();
        assert!(!mrep.is_success());
        assert_eq!(mrep.sources_deleted, 0);
        assert!(
            msrc.get_file_bytes("precious.bin").is_some(),
            "move MUST NOT delete source on checksum mismatch (ssc={ssc})"
        );
    }
}

#[test]
fn retry_after_is_capped_at_the_single_default_ceiling() {
    // One cap for both layers: the engine default matches the backend HTTP policy (30 s).
    let cfg = EngineConfig::new("cap", JobMode::Copy, "a:", "b:");
    assert_eq!(cfg.max_retry_delay, Duration::from_secs(30));
    let err = Error::rate_limited("429", Some(Duration::from_secs(45)));
    let d = compute_backoff_delay(
        &err,
        1,
        cfg.base_retry_delay,
        cfg.max_retry_delay,
        &cfg.jitter(),
    );
    assert_eq!(d, Duration::from_secs(30));
}
