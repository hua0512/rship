//! `CryptoBackend` must forward every durability and write-ahead hook of the backend it
//! wraps (`prepare_operation_id`, `defers_durable_writes`, `flush_durable_writes`,
//! `sync_durable_file`), mapping plaintext paths to their encrypted inner paths.

use super::super::*;
use crate::keys::MasterKey;
use rship_backends::local::LocalBackend;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_core::types::{FsyncMode, NodeId};
use rship_state::{SqliteSyncIndex, StateActor};
use tempfile::TempDir;

fn keys() -> CryptoKeys {
    MasterKey::from_bytes([0x5Au8; 32]).derive_subkeys()
}

fn crypt_over(inner: Arc<dyn StorageBackend>) -> Arc<CryptoBackend> {
    Arc::new(CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys()).unwrap())
}

async fn run_job(
    src: Arc<dyn StorageBackend>,
    dst: Arc<dyn StorageBackend>,
    mode: JobMode,
    job: &str,
    state: &std::path::Path,
) -> rship_core::engine::RunReport {
    let engine = TransferEngine::new(
        src,
        dst,
        Arc::new(StateActor::open(state).unwrap()),
        BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new(job, mode, "src", "crypt");
    engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(state, job).unwrap()),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn crypt_move_fsyncs_inner_local_file_before_deleting_source() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();
    std::fs::write(src_dir.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src_dir.join("b.bin"), vec![7u8; 300 * 1024]).unwrap();

    // `Never` keeps every other fsync out of the count: only the pre-delete sync remains.
    let inner = Arc::new(
        LocalBackend::new("enc", &enc_dir)
            .unwrap()
            .with_fsync_mode(FsyncMode::Never),
    );
    let crypt = crypt_over(inner.clone());
    let rep = run_job(
        Arc::new(LocalBackend::new("src", &src_dir).unwrap()),
        crypt,
        JobMode::Move,
        "j-crypt-move",
        &tmp.path().join("state"),
    )
    .await;
    assert!(rep.is_success(), "crypt move errors: {:?}", rep.errors);
    assert_eq!(rep.sources_deleted, 2);
    assert_eq!(
        inner.fsync_count(),
        2,
        "crypt must forward sync_durable_file to the inner local backend before each source delete"
    );
}

#[tokio::test]
async fn crypt_forwards_batch_flush_and_deferred_durability_to_inner() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();
    std::fs::write(src_dir.join("a.txt"), b"alpha").unwrap();

    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    assert_eq!(inner.fsync_mode(), FsyncMode::Batch);
    let crypt = crypt_over(inner.clone());
    assert!(
        crypt.defers_durable_writes(),
        "crypt over a Batch-mode local backend defers durability like the inner backend"
    );
    let rep = run_job(
        Arc::new(LocalBackend::new("src", &src_dir).unwrap()),
        crypt,
        JobMode::Copy,
        "j-crypt-batch",
        &tmp.path().join("state"),
    )
    .await;
    assert!(rep.is_success(), "crypt copy errors: {:?}", rep.errors);
    assert_eq!(
        inner.batch_flush_count(),
        1,
        "crypt must forward flush_durable_writes to the inner local backend"
    );

    let always = crypt_over(Arc::new(
        LocalBackend::new("enc2", tmp.path().join("enc2"))
            .unwrap()
            .with_fsync_mode(FsyncMode::Always),
    ));
    assert!(!always.defers_durable_writes());
}

#[tokio::test]
async fn crypt_sync_overwrites_existing_small_file_on_local() {
    // The inner backend checks `DstPrecondition::Existing` against the ciphertext size, so
    // crypt must translate the plaintext size it plans with for single-shot uploads too.
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();
    std::fs::write(src_dir.join("note.txt"), b"version one").unwrap();
    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let src: Arc<dyn StorageBackend> = Arc::new(LocalBackend::new("src", &src_dir).unwrap());

    let rep = run_job(
        src.clone(),
        crypt_over(inner.clone()),
        JobMode::Sync,
        "j-crypt-ow-1",
        &state,
    )
    .await;
    assert!(rep.is_success(), "first sync errors: {:?}", rep.errors);
    std::fs::write(src_dir.join("note.txt"), b"version two is longer").unwrap();
    let rep = run_job(
        src,
        crypt_over(inner.clone()),
        JobMode::Sync,
        "j-crypt-ow-2",
        &state,
    )
    .await;
    assert!(rep.is_success(), "overwrite sync errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);

    let crypt = crypt_over(inner);
    let entry = crypt
        .stat(&BackendPath::from_rel(RelPath::parse("note.txt").unwrap()))
        .await
        .unwrap()
        .unwrap();
    let DataSource::RemoteRangeReadable(reader) = crypt
        .open_read_entry(
            &entry,
            &BackendPath::from_rel(RelPath::parse("note.txt").unwrap()),
            None,
        )
        .await
        .unwrap()
    else {
        panic!("expected a range reader");
    };
    let body = super::drain_byte_stream(
        reader
            .open_range(ByteRange {
                offset: 0,
                len: entry.size,
            })
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(body, b"version two is longer");
}

/// Delegating wrapper that behaves like a duplicate-name backend (Google Drive) and hands out
/// pre-generated IDs, recording which inner path each was requested for.
struct PregenIdBackend {
    inner: Arc<LocalBackend>,
    requested: StdMutex<Vec<String>>,
    quota: Arc<dyn rship_core::engine::RetryQuota>,
}

#[async_trait]
impl StorageBackend for PregenIdBackend {
    fn name(&self) -> &str {
        "pregen"
    }
    fn kind(&self) -> &'static str {
        "pregen"
    }
    fn endpoint_identity(&self) -> String {
        format!("pregen://{}", self.inner.endpoint_identity())
    }
    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.capabilities();
        caps.allows_duplicate_names = true;
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
    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        self.inner.compute_hash(path, kind).await
    }
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        self.inner.open_read(path, range).await
    }
    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.inner.put_single_shot(init, body).await
    }
    fn retry_quota(&self) -> Option<Arc<dyn rship_core::engine::RetryQuota>> {
        Some(self.quota.clone())
    }
    async fn prepare_operation_id(&self, init: &UploadInit) -> Result<Option<NodeId>> {
        self.requested
            .lock()
            .unwrap()
            .push(init.dst_path.as_str().to_string());
        Ok(Some(NodeId(format!("pregen-{}", init.op_id))))
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
async fn crypt_forwards_prepare_operation_id_with_encrypted_path() {
    let tmp = TempDir::new().unwrap();
    let inner = Arc::new(PregenIdBackend {
        inner: Arc::new(LocalBackend::new("enc", tmp.path()).unwrap()),
        requested: StdMutex::new(Vec::new()),
        quota: Arc::new(rship_core::engine::TokenBucketRetryQuota::default()),
    });
    let crypt = crypt_over(inner.clone());
    assert!(
        crypt.capabilities().allows_duplicate_names,
        "crypt keeps the inner duplicate-name semantics, so the engine asks for an ID"
    );
    let plain = RelPath::parse("dir/secret.txt").unwrap();
    let init = UploadInit {
        op_id: "op-pregen".into(),
        dst_path: plain.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let id = crypt.prepare_operation_id(&init).await.unwrap();
    assert_eq!(id, Some(NodeId("pregen-op-pregen".into())));
    let requested = inner.requested.lock().unwrap().clone();
    let expected = encrypt_rel_path(&keys(), FilenameEncryption::Standard, &plain).unwrap();
    assert_eq!(requested, vec![expected.as_str().to_string()]);

    // The inner account's shared retry budget is the crypt remote's budget too.
    let quota = crypt
        .retry_quota()
        .expect("crypt must forward the inner retry quota");
    assert!(Arc::ptr_eq(&quota, &inner.quota));
}

#[tokio::test]
async fn crypt_reconciles_single_shot_operation_without_session_metadata() {
    // Single-shot uploads never open a session, so their journaled operation has empty
    // `backend_meta`. Crash recovery must still reconcile it against the encrypted object.
    let tmp = TempDir::new().unwrap();
    let crypt = crypt_over(Arc::new(LocalBackend::new("enc", tmp.path()).unwrap()));
    let rel = RelPath::parse("ss/file.txt").unwrap();
    let payload: &'static [u8] = b"single shot payload";
    let mtime_ns = 1_700_000_000_000_000_000;
    let init = UploadInit {
        op_id: "op-ss".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: mtime_ns,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    crypt
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move {
                Ok(Bytes::from_static(payload))
            })),
        )
        .await
        .unwrap();

    let op = OperationRecord {
        op_id: "op-ss".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: crypt.endpoint_identity(),
        src_raw_path: "ss/file.txt".into(),
        dst_raw_path: "ss/file.txt".into(),
        dst_nfc_path: rel,
        src_version: rship_core::state::SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "crypt".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: payload.len() as u64,
        confirmed_offset: 0,
        state: rship_core::state::OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    match crypt.reconcile_operation(&op).await.unwrap() {
        ReconcileOutcome::Committed(entry) => {
            assert_eq!(entry.size, payload.len() as u64);
            assert_eq!(entry.nfc_path.as_str(), "ss/file.txt");
        }
        other => panic!("expected Committed, got {other:?}"),
    }
    crypt.abort_upload(&op).await.unwrap();
}

#[tokio::test]
async fn crypt_sync_overwrites_existing_resumable_file_with_dst_precondition_on_local() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();

    let v1: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 251) as u8).collect();
    let v2: Vec<u8> = (0..(250 * 1024))
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect();
    std::fs::write(src_dir.join("big.bin"), &v1).unwrap();

    let inner = Arc::new(
        LocalBackend::new("enc", &enc_dir)
            .unwrap()
            .with_chunking(64 * 1024, 128 * 1024),
    );
    let src: Arc<dyn StorageBackend> = Arc::new(LocalBackend::new("src", &src_dir).unwrap());

    let rep1 = run_job(
        src.clone(),
        crypt_over(inner.clone()),
        JobMode::Sync,
        "j-crypt-res-1",
        &state,
    )
    .await;
    assert!(
        rep1.is_success(),
        "first resumable sync errors: {:?}",
        rep1.errors
    );

    std::fs::write(src_dir.join("big.bin"), &v2).unwrap();
    let rep2 = run_job(
        src.clone(),
        crypt_over(inner.clone()),
        JobMode::Sync,
        "j-crypt-res-2",
        &state,
    )
    .await;
    assert!(
        rep2.is_success(),
        "overwrite resumable sync with DstPrecondition::Existing failed: {:?}",
        rep2.errors
    );
    assert_eq!(rep2.files_transferred, 1);

    let crypt = crypt_over(inner.clone());
    let rel = RelPath::parse("big.bin").unwrap();
    let entry = crypt
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.size, v2.len() as u64);
    let DataSource::RemoteRangeReadable(reader) = crypt
        .open_read_entry(&entry, &BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap()
    else {
        panic!("expected range reader");
    };
    let got = super::drain_byte_stream(
        reader
            .open_range(ByteRange {
                offset: 0,
                len: entry.size,
            })
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(got, v2);

    // Concurrent destination mutation: a stale DstPrecondition::Existing plaintext size
    // must be mapped to ciphertext_size and fail with PreconditionFailed in finish_upload.
    let stale_init = UploadInit {
        op_id: "op-stale-resumable".into(),
        dst_path: rel.clone(),
        existing_node_id: entry.node_id.clone(),
        pregenerated_id: None,
        total_size: 150 * 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 128 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Existing {
            node_id: entry.node_id.clone(),
            etag: entry.etag.clone(),
            mtime_ns: entry.mtime_ns,
            size: v1.len() as u64, // stale plaintext size (200 KiB != current 250 KiB)
        },
        src_etag: None,
    };
    let sess = crypt.begin_upload(&stale_init).await.unwrap();
    let stale_op = OperationRecord {
        op_id: "op-stale-resumable".into(),
        session_key: "sk-res".into(),
        job_id: "j-res".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: crypt.endpoint_identity(),
        src_raw_path: "big.bin".into(),
        dst_raw_path: "big.bin".into(),
        dst_nfc_path: rel.clone(),
        src_version: rship_core::state::SourceVersion {
            node_id: None,
            size: 150 * 1024,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: stale_init.precondition.clone(),
        existing_dst_node_id: entry.node_id.clone(),
        remote_op_id: sess.remote_op_id.clone(),
        backend_kind: "crypt".into(),
        session_token: Some(sess.session_token.clone()),
        backend_meta: sess.backend_meta.clone(),
        planned_chunk_size: 128 * 1024,
        confirmed_offset: 0,
        state: rship_core::state::OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let p1 = vec![0x11u8; 128 * 1024];
    let p2 = vec![0x22u8; 22 * 1024];
    let ack1 = crypt
        .upload_chunk(
            &stale_op,
            ChunkUpload::new(
                1,
                0,
                p1.len() as u64,
                150 * 1024,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1)) })),
            ),
        )
        .await
        .unwrap();
    let ack2 = crypt
        .upload_chunk(
            &stale_op,
            ChunkUpload::new(
                2,
                128 * 1024,
                p2.len() as u64,
                150 * 1024,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .unwrap();
    let parts = vec![
        CompletedPart {
            part_number: 1,
            offset: 0,
            length: 128 * 1024,
            etag: ack1.etag.unwrap_or_default(),
            checksum: ack1.checksum,
        },
        CompletedPart {
            part_number: 2,
            offset: 128 * 1024,
            length: 22 * 1024,
            etag: ack2.etag.unwrap_or_default(),
            checksum: ack2.checksum,
        },
    ];
    let finish_err = crypt.finish_upload(&stale_op, &parts).await.unwrap_err();
    assert_eq!(finish_err.kind, rship_core::ErrorKind::PreconditionFailed);

    // Reconcile on a resumable OperationRecord with DstPrecondition::Existing.
    let rec_init = UploadInit {
        op_id: "op-match-resumable".into(),
        dst_path: rel.clone(),
        existing_node_id: Some(NodeId("prior-inode".into())),
        pregenerated_id: None,
        total_size: v2.len() as u64,
        src_mtime_ns: entry.mtime_ns,
        planned_chunk_size: 128 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Existing {
            node_id: Some(NodeId("prior-inode".into())),
            etag: None,
            mtime_ns: 0,
            size: v1.len() as u64,
        },
        src_etag: None,
    };
    let match_sess = crypt.begin_upload(&rec_init).await.unwrap();
    let matching_op = OperationRecord {
        op_id: "op-match-resumable".into(),
        session_key: "sk-res2".into(),
        job_id: "j-res2".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: crypt.endpoint_identity(),
        src_raw_path: "big.bin".into(),
        dst_raw_path: "big.bin".into(),
        dst_nfc_path: rel,
        src_version: rship_core::state::SourceVersion {
            node_id: None,
            size: v2.len() as u64,
            mtime_ns: entry.mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: rec_init.precondition.clone(),
        existing_dst_node_id: Some(NodeId("prior-inode".into())),
        remote_op_id: match_sess.remote_op_id,
        backend_kind: "crypt".into(),
        session_token: Some(match_sess.session_token),
        backend_meta: match_sess.backend_meta,
        planned_chunk_size: 128 * 1024,
        confirmed_offset: 0,
        state: rship_core::state::OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    crypt.abort_upload(&matching_op).await.unwrap();
    match crypt.reconcile_operation(&matching_op).await.unwrap() {
        ReconcileOutcome::Committed(e) => assert_eq!(e.size, v2.len() as u64),
        other => panic!("expected Committed on reconcile, got {other:?}"),
    }
}

#[tokio::test]
async fn crypt_single_shot_max_bytes_clamps_4mib_and_routes_4mib_to_resumable() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FourMibCappedBackend {
        inner: Arc<LocalBackend>,
        single_shot_calls: AtomicUsize,
        begin_upload_calls: AtomicUsize,
        last_single_shot_ct_len: StdMutex<Option<u64>>,
    }

    #[async_trait]
    impl StorageBackend for FourMibCappedBackend {
        fn name(&self) -> &str {
            "capped4m"
        }
        fn kind(&self) -> &'static str {
            "capped4m"
        }
        fn endpoint_identity(&self) -> String {
            format!("capped4m://{}", self.inner.endpoint_identity())
        }
        fn capabilities(&self) -> Capabilities {
            let mut caps = self.inner.capabilities();
            caps.single_shot_max_bytes = 4 * 1024 * 1024;
            caps.default_chunk_size = 512 * 1024;
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
            if init.total_size > 4 * 1024 * 1024 {
                return Err(Error::protocol(format!(
                    "inner backend rejected oversized single-shot payload: {} > 4 MiB",
                    init.total_size
                )));
            }
            self.single_shot_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_single_shot_ct_len.lock().unwrap() = Some(init.total_size);
            self.inner.put_single_shot(init, body).await
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            self.begin_upload_calls.fetch_add(1, Ordering::SeqCst);
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

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();

    let inner = Arc::new(FourMibCappedBackend {
        inner: Arc::new(
            LocalBackend::new("enc", &enc_dir)
                .unwrap()
                .with_chunking(4 * 1024 * 1024, 512 * 1024),
        ),
        single_shot_calls: AtomicUsize::new(0),
        begin_upload_calls: AtomicUsize::new(0),
        last_single_shot_ct_len: StdMutex::new(None),
    });
    let crypt = crypt_over(inner.clone());
    assert_eq!(crypt.capabilities().single_shot_max_bytes, 4_193_248);

    // Exactly 4 MiB plaintext -> must route through resumable chunked upload, NOT single_shot.
    std::fs::write(
        src_dir.join("exact-4mib.bin"),
        vec![0x33u8; 4 * 1024 * 1024],
    )
    .unwrap();
    let src: Arc<dyn StorageBackend> = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let rep1 = run_job(
        src.clone(),
        crypt.clone(),
        JobMode::Copy,
        "j-4mib-resumable",
        &state,
    )
    .await;
    assert!(rep1.is_success(), "4 MiB copy errors: {:?}", rep1.errors);
    assert_eq!(inner.single_shot_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.begin_upload_calls.load(Ordering::SeqCst), 1);

    // Exactly 4_193_248 plaintext bytes -> fits in single_shot with ciphertext == 4 MiB.
    std::fs::remove_file(src_dir.join("exact-4mib.bin")).unwrap();
    std::fs::write(src_dir.join("max-ss.bin"), vec![0x44u8; 4_193_248]).unwrap();
    let rep2 = run_job(src, crypt, JobMode::Copy, "j-max-ss", &state).await;
    assert!(
        rep2.is_success(),
        "max single-shot errors: {:?}",
        rep2.errors
    );
    assert_eq!(inner.single_shot_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *inner.last_single_shot_ct_len.lock().unwrap(),
        Some(4 * 1024 * 1024)
    );
}
