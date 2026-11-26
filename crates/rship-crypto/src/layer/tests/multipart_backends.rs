use super::super::*;
use crate::keys::MasterKey;
use rship_backends::local::LocalBackend;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use tempfile::TempDir;

#[tokio::test]
async fn crypto_over_equal_non_final_parts_backend_succeeds_and_decrypts_bit_exact() {
    use rship_core::types::{ChunkAlignment, UploadTopology};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    type MockUploadEntry = (String, u64, HashMap<u32, Vec<u8>>);

    #[derive(Clone, Default)]
    struct R2StrictMock {
        objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
        uploads: Arc<StdMutex<HashMap<String, MockUploadEntry>>>,
    }

    #[async_trait]
    impl StorageBackend for R2StrictMock {
        fn name(&self) -> &str {
            "r2-mock"
        }
        fn kind(&self) -> &'static str {
            "s3"
        }
        fn endpoint_identity(&self) -> String {
            "s3://mock/r2".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: 64 * 1024,
                    max_bytes: 5 * 1024 * 1024,
                    max_parts: 10_000,
                    max_object_bytes: 100 * 1024 * 1024,
                    require_equal_non_final_parts: true,
                },
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 128 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let map = self.objects.lock().unwrap();
            Ok(map.get(path.nfc_path.as_str()).map(|b| Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: b.len() as u64,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: None,
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            self.objects.lock().unwrap().remove(path.nfc_path.as_str());
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            let data = self
                .objects
                .lock()
                .unwrap()
                .get(path.nfc_path.as_str())
                .cloned()
                .ok_or_else(|| Error::not_found("missing"))?;
            let slice = match range {
                Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
                None => data,
            };
            let len = slice.len() as u64;
            Ok(DataSource::SequentialStream {
                stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                total_len: Some(len),
            })
        }
        async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(&c?);
            }
            let len = buf.len() as u64;
            self.objects
                .lock()
                .unwrap()
                .insert(init.dst_path.as_str().to_string(), buf);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: init.dst_path.clone(),
                kind: EntryKind::File,
                size: len,
                mtime_ns: init.src_mtime_ns,
                ctime_ns: None,
                etag: Some("\"single\"".into()),
                checksum: None,
            })
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            let uid = format!("uid-{}", init.op_id);
            self.uploads.lock().unwrap().insert(
                uid.clone(),
                (
                    init.dst_path.as_str().to_string(),
                    init.planned_chunk_size,
                    HashMap::new(),
                ),
            );
            Ok(UploadSessionInit {
                session_token: uid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Ok(UploadProgress::CompletedParts(vec![]))
        }
        async fn upload_chunk(
            &self,
            op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            let uid = op.session_token.as_deref().unwrap();
            let is_final = chunk.offset + chunk.len == chunk.total_size;
            if !is_final && chunk.len != op.planned_chunk_size {
                return Err(Error::invalid_geometry(format!(
                    "R2 strict mock rejected unequal non-final part {}: got {}, expected {}",
                    chunk.part_number, chunk.len, op.planned_chunk_size
                )));
            }
            if is_final && chunk.len > op.planned_chunk_size {
                return Err(Error::invalid_geometry(format!(
                    "R2 strict mock rejected oversized final part {}: {} > {}",
                    chunk.part_number, chunk.len, op.planned_chunk_size
                )));
            }
            let mut buf = Vec::new();
            while let Some(c) = chunk.body.next().await {
                buf.extend_from_slice(&c?);
            }
            assert_eq!(buf.len() as u64, chunk.len);
            self.uploads
                .lock()
                .unwrap()
                .get_mut(uid)
                .unwrap()
                .2
                .insert(chunk.part_number, buf);
            Ok(ChunkAck {
                next_offset: None,
                etag: Some(format!("\"etag-{}\"", chunk.part_number)),
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            let uid = op.session_token.as_deref().unwrap();
            let (key, planned, mut stored) = self.uploads.lock().unwrap().remove(uid).unwrap();
            assert!(!parts.is_empty());
            for p in &parts[..parts.len().saturating_sub(1)] {
                assert_eq!(
                    p.length, planned,
                    "non-final part {} length mismatch",
                    p.part_number
                );
            }
            assert!(
                parts.last().unwrap().length <= planned,
                "final part > planned"
            );
            let mut full = Vec::new();
            for p in parts {
                full.extend_from_slice(&stored.remove(&p.part_number).unwrap());
            }
            let len = full.len() as u64;
            self.objects.lock().unwrap().insert(key.clone(), full);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::parse(&key)?,
                kind: EntryKind::File,
                size: len,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            })
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            if let Some(uid) = op.session_token.as_deref() {
                self.uploads.lock().unwrap().remove(uid);
            }
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let exact_payload: Vec<u8> = (0..(384 * 1024))
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect();
    let partial_payload: Vec<u8> = (0..(320 * 1024))
        .map(|i| ((i * 13 + 9) % 251) as u8)
        .collect();
    std::fs::write(src_dir.join("exact.bin"), &exact_payload).unwrap();
    std::fs::write(src_dir.join("partial.bin"), &partial_payload).unwrap();

    let local_src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let r2 = Arc::new(R2StrictMock::default());
    let keys = MasterKey::from_bytes([0x42u8; 32]).derive_subkeys();
    let crypto = Arc::new(CryptoBackend::new(r2, CryptoConfig::new("r2-crypt"), keys).unwrap());

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        local_src,
        crypto.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg = EngineConfig::new("job-r2-crypt", JobMode::Copy, "src", "r2-crypt");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(
        rep.errors.is_empty(),
        "R2 crypt transfer errors: {:?}",
        rep.errors
    );
    assert_eq!(rep.files_transferred, 2);

    for (name, expected) in [
        ("exact.bin", &exact_payload),
        ("partial.bin", &partial_payload),
    ] {
        let reader = match crypto
            .open_read(&BackendPath::from_rel(RelPath::parse(name).unwrap()), None)
            .await
            .unwrap()
        {
            DataSource::RemoteRangeReadable(r) => r,
            _ => panic!("expected RemoteRangeReadable"),
        };
        assert_eq!(reader.total_len(), expected.len() as u64);
        let mut s = reader
            .open_range(ByteRange {
                offset: 0,
                len: expected.len() as u64,
            })
            .await
            .unwrap();
        let mut got = Vec::new();
        while let Some(c) = s.next().await {
            got.extend_from_slice(&c.unwrap());
        }
        assert_eq!(
            got, *expected,
            "decrypted `{name}` mismatch over R2 strict mock"
        );
    }
}

#[tokio::test]
async fn crypto_over_gdrive_256k_aligned_sequential_backend_streams_and_resumes_bit_exact() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct GdriveStrictAlignMock {
        objects: StdMutex<HashMap<String, Vec<u8>>>,
        sessions: StdMutex<HashMap<String, (String, Vec<u8>)>>,
        injected_partial_drop: AtomicBool,
    }

    #[async_trait]
    impl StorageBackend for GdriveStrictAlignMock {
        fn name(&self) -> &str {
            "gd-mock"
        }
        fn kind(&self) -> &'static str {
            "gdrive"
        }
        fn endpoint_identity(&self) -> String {
            "gdrive://strict-align-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_millis(1),
                can_set_mtime: true,
                upload_topology: UploadTopology::Sequential,
                chunk_alignment: ChunkAlignment::MultipleOf {
                    align_bytes: 256 * 1024,
                    max_chunk_bytes: None,
                },
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 512 * 1024,
                allows_duplicate_names: true,
                case_sensitive: true,
                supports_node_id: true,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let objs = self.objects.lock().unwrap();
            Ok(objs.get(path.nfc_path.as_str()).map(|b| Entry {
                node_id: None,
                parent_id: None,
                raw_path: path.raw_path.clone(),
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: b.len() as u64,
                mtime_ns: 0,
                ctime_ns: None,
                etag: Some("\"gd\"".into()),
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            let objs = self.objects.lock().unwrap();
            let items: Vec<Result<Entry>> = objs
                .iter()
                .map(|(k, b)| {
                    Ok(Entry {
                        node_id: None,
                        parent_id: None,
                        raw_path: None,
                        nfc_path: RelPath::parse(k).unwrap(),
                        kind: EntryKind::File,
                        size: b.len() as u64,
                        mtime_ns: 0,
                        ctime_ns: None,
                        etag: Some("\"gd\"".into()),
                        checksum: None,
                    })
                })
                .collect();
            Ok(Box::pin(futures::stream::iter(items)))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            self.objects.lock().unwrap().remove(path.nfc_path.as_str());
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            let objs = self.objects.lock().unwrap();
            let data = objs
                .get(path.nfc_path.as_str())
                .ok_or_else(|| Error::not_found("missing"))?;
            let slice = match range {
                Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
                None => data.clone(),
            };
            let len = slice.len() as u64;
            Ok(DataSource::SequentialStream {
                stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                total_len: Some(len),
            })
        }
        async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(&c?);
            }
            let len = buf.len() as u64;
            self.objects
                .lock()
                .unwrap()
                .insert(init.dst_path.as_str().to_string(), buf);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: init.dst_path.clone(),
                kind: EntryKind::File,
                size: len,
                mtime_ns: init.src_mtime_ns,
                ctime_ns: None,
                etag: Some("\"single\"".into()),
                checksum: None,
            })
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            let sid = format!("gd-sid-{}", init.op_id);
            self.sessions.lock().unwrap().insert(
                sid.clone(),
                (init.dst_path.as_str().to_string(), Vec::new()),
            );
            Ok(UploadSessionInit {
                session_token: sid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            let sid = op.session_token.as_deref().unwrap();
            let sessions = self.sessions.lock().unwrap();
            let Some((_, buf)) = sessions.get(sid) else {
                return Ok(UploadProgress::Expired);
            };
            Ok(UploadProgress::SequentialOffset(buf.len() as u64))
        }
        async fn upload_chunk(
            &self,
            op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            let sid = op.session_token.as_deref().unwrap();
            let is_final = chunk.offset + chunk.len == chunk.total_size;
            if !is_final && !chunk.len.is_multiple_of(256 * 1024) {
                return Err(Error::invalid_geometry(format!(
                    "GDrive strict mock rejected non-256KiB-aligned chunk {}: len={}",
                    chunk.part_number, chunk.len
                )));
            }
            let mut incoming = Vec::new();
            while let Some(c) = chunk.body.next().await {
                incoming.extend_from_slice(&c?);
            }
            assert_eq!(incoming.len() as u64, chunk.len);

            let mut sessions = self.sessions.lock().unwrap();
            let (key, stored) = sessions.get_mut(sid).unwrap();
            assert_eq!(
                stored.len() as u64,
                chunk.offset,
                "non-contiguous GDrive offset"
            );

            if chunk.part_number == 2
                && incoming.len() >= 256 * 1024
                && !self.injected_partial_drop.swap(true, Ordering::SeqCst)
            {
                stored.extend_from_slice(&incoming[..256 * 1024]);
                return Err(Error::network(
                    "simulated mid-chunk TCP reset after 256 KiB",
                ));
            }

            stored.extend_from_slice(&incoming);
            if is_final {
                let key_done = key.clone();
                let full = std::mem::take(stored);
                sessions.remove(sid);
                drop(sessions);
                let len = full.len() as u64;
                self.objects.lock().unwrap().insert(key_done.clone(), full);
                let entry = Entry {
                    node_id: None,
                    parent_id: None,
                    raw_path: None,
                    nfc_path: RelPath::parse(&key_done)?,
                    kind: EntryKind::File,
                    size: len,
                    mtime_ns: op.src_version.mtime_ns,
                    ctime_ns: None,
                    etag: Some("\"gd-done\"".into()),
                    checksum: None,
                };
                return Ok(ChunkAck {
                    next_offset: Some(len),
                    etag: entry.etag.clone(),
                    completed: Some(entry),
                    checksum: None,
                });
            }

            Ok(ChunkAck {
                next_offset: Some(stored.len() as u64),
                etag: None,
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            _op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            unreachable!("GDrive sequential upload completes inside final upload_chunk")
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            if let Some(sid) = op.session_token.as_deref() {
                self.sessions.lock().unwrap().remove(sid);
            }
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let payload: Vec<u8> = (0..1_475_794).map(|i| ((i * 19 + 5) % 251) as u8).collect();
    std::fs::write(src_dir.join("multi_chunk_gdrive.bin"), &payload).unwrap();

    let local_src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let gd = Arc::new(GdriveStrictAlignMock::default());
    let keys = MasterKey::from_bytes([0xABu8; 32]).derive_subkeys();
    let crypto =
        Arc::new(CryptoBackend::new(gd.clone(), CryptoConfig::new("gd-crypt"), keys).unwrap());

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(4 * 1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local_src,
        crypto.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg = EngineConfig::new("job-gd-crypt", JobMode::Copy, "src", "gd-crypt");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(
        rep.errors.is_empty(),
        "GDrive crypt multi-chunk errors: {:?}",
        rep.errors
    );
    assert_eq!(rep.files_transferred, 1);
    assert!(gd.injected_partial_drop.load(Ordering::SeqCst));

    let reader = match crypto
        .open_read(
            &BackendPath::from_rel(RelPath::parse("multi_chunk_gdrive.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    assert_eq!(reader.total_len(), payload.len() as u64);
    let mut s = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(c) = s.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(
        got, payload,
        "decrypted multi-chunk GDrive payload mismatch"
    );
}

#[test]
fn map_sequential_ct_offset_handles_header_and_block0_boundaries() {
    use crate::layer::framing::map_sequential_ct_offset;
    use crate::stream::{CIPHERTEXT_CHUNK_LEN, HEADER_LEN, PLAINTEXT_CHUNK_LEN, ciphertext_size};

    let total_pt = 2 * PLAINTEXT_CHUNK_LEN as u64; // 131_072
    let ct_total = ciphertext_size(total_pt).unwrap(); // 32 + 2 * 65_552 = 131_136
    let block0_end = (HEADER_LEN + CIPHERTEXT_CHUNK_LEN) as u64; // 65_584

    assert_eq!(map_sequential_ct_offset(0, total_pt), (0, 0));
    assert_eq!(map_sequential_ct_offset(1, total_pt), (0, 1));
    assert_eq!(map_sequential_ct_offset(16, total_pt), (0, 16));
    assert_eq!(map_sequential_ct_offset(31, total_pt), (0, 31));
    assert_eq!(map_sequential_ct_offset(32, total_pt), (0, 32));
    assert_eq!(map_sequential_ct_offset(32_768, total_pt), (0, 32_768));
    assert_eq!(
        map_sequential_ct_offset(block0_end - 1, total_pt),
        (0, block0_end - 1)
    );
    assert_eq!(
        map_sequential_ct_offset(block0_end, total_pt),
        (PLAINTEXT_CHUNK_LEN as u64, 0)
    );
    assert_eq!(
        map_sequential_ct_offset(block0_end + 123, total_pt),
        (PLAINTEXT_CHUNK_LEN as u64, 123)
    );
    assert_eq!(map_sequential_ct_offset(ct_total, total_pt), (total_pt, 0));
    assert_eq!(
        map_sequential_ct_offset(ct_total + 50, total_pt),
        (total_pt, 0)
    );

    // Sub-block object (`total_pt < 65_536`)
    let small_pt = 40_000u64;
    let small_ct = ciphertext_size(small_pt).unwrap(); // 40_048
    assert_eq!(map_sequential_ct_offset(16, small_pt), (0, 16));
    assert_eq!(map_sequential_ct_offset(32, small_pt), (0, 32));
    assert_eq!(map_sequential_ct_offset(32_768, small_pt), (0, 32_768));
    assert_eq!(map_sequential_ct_offset(small_ct, small_pt), (small_pt, 0));
}

type SeqSessionMap = HashMap<String, (String, Vec<u8>)>;

#[derive(Clone)]
struct ConfigurableSeqAlignMock {
    align_bytes: u64,
    default_chunk_size: u64,
    objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    sessions: Arc<StdMutex<SeqSessionMap>>,
}

impl ConfigurableSeqAlignMock {
    fn new(align_bytes: u64, default_chunk_size: u64) -> Self {
        Self {
            align_bytes,
            default_chunk_size,
            objects: Arc::new(StdMutex::new(HashMap::new())),
            sessions: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageBackend for ConfigurableSeqAlignMock {
    fn name(&self) -> &str {
        "seq-align-mock"
    }
    fn kind(&self) -> &'static str {
        "gdrive"
    }
    fn endpoint_identity(&self) -> String {
        format!("gdrive://seq-align-{}", self.align_bytes)
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: std::time::Duration::from_millis(1),
            can_set_mtime: true,
            upload_topology: rship_core::types::UploadTopology::Sequential,
            chunk_alignment: rship_core::types::ChunkAlignment::MultipleOf {
                align_bytes: self.align_bytes,
                max_chunk_bytes: None,
            },
            single_shot_max_bytes: 64 * 1024,
            default_chunk_size: self.default_chunk_size,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
            default_write_qps: None,
        }
    }
    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let objs = self.objects.lock().unwrap();
        Ok(objs.get(path.nfc_path.as_str()).map(|b| Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: path.nfc_path.clone(),
            kind: EntryKind::File,
            size: b.len() as u64,
            mtime_ns: 0,
            ctime_ns: None,
            etag: Some("\"seq\"".into()),
            checksum: None,
        }))
    }
    async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
        Ok(Box::pin(futures::stream::empty()))
    }
    async fn mkdir(&self, _path: &RelPath) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.objects.lock().unwrap().remove(path.nfc_path.as_str());
        Ok(())
    }
    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
    }
    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        let objs = self.objects.lock().unwrap();
        let data = objs
            .get(path.nfc_path.as_str())
            .ok_or_else(|| Error::not_found("missing"))?;
        let slice = match range {
            Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
            None => data.clone(),
        };
        let len = slice.len() as u64;
        Ok(DataSource::SequentialStream {
            stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
            total_len: Some(len),
        })
    }
    async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
        let mut buf = Vec::new();
        while let Some(c) = body.next().await {
            buf.extend_from_slice(&c?);
        }
        let len = buf.len() as u64;
        self.objects
            .lock()
            .unwrap()
            .insert(init.dst_path.as_str().to_string(), buf);
        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: len,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: Some("\"single\"".into()),
            checksum: None,
        })
    }
    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let sid = format!("seq-sid-{}", init.op_id);
        self.sessions.lock().unwrap().insert(
            sid.clone(),
            (init.dst_path.as_str().to_string(), Vec::new()),
        );
        Ok(UploadSessionInit {
            session_token: sid,
            backend_meta: String::new(),
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }
    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let sid = op.session_token.as_deref().unwrap();
        let sessions = self.sessions.lock().unwrap();
        let Some((_, buf)) = sessions.get(sid) else {
            return Ok(UploadProgress::Expired);
        };
        Ok(UploadProgress::SequentialOffset(buf.len() as u64))
    }
    async fn upload_chunk(&self, op: &OperationRecord, mut chunk: ChunkUpload) -> Result<ChunkAck> {
        let sid = op.session_token.as_deref().unwrap();
        let is_final = chunk.offset + chunk.len == chunk.total_size;
        if !is_final && !chunk.len.is_multiple_of(self.align_bytes) {
            return Err(Error::invalid_geometry(format!(
                "non-final len {} not aligned to {}",
                chunk.len, self.align_bytes
            )));
        }
        let mut incoming = Vec::new();
        while let Some(c) = chunk.body.next().await {
            incoming.extend_from_slice(&c?);
        }
        assert_eq!(incoming.len() as u64, chunk.len);

        let mut sessions = self.sessions.lock().unwrap();
        let (key, stored) = sessions.get_mut(sid).unwrap();
        assert_eq!(
            stored.len() as u64,
            chunk.offset,
            "non-contiguous offset: stored={}, chunk.offset={}",
            stored.len(),
            chunk.offset
        );
        stored.extend_from_slice(&incoming);
        if is_final {
            assert_eq!(
                stored.len() as u64,
                chunk.total_size,
                "final ciphertext size mismatch"
            );
            let key_done = key.clone();
            let full = std::mem::take(stored);
            sessions.remove(sid);
            drop(sessions);
            let len = full.len() as u64;
            self.objects.lock().unwrap().insert(key_done.clone(), full);
            let entry = Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::parse(&key_done)?,
                kind: EntryKind::File,
                size: len,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"seq-done\"".into()),
                checksum: None,
            };
            return Ok(ChunkAck {
                next_offset: Some(len),
                etag: entry.etag.clone(),
                completed: Some(entry),
                checksum: None,
            });
        }
        Ok(ChunkAck {
            next_offset: Some(stored.len() as u64),
            etag: None,
            completed: None,
            checksum: None,
        })
    }
    async fn finish_upload(
        &self,
        _op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        unreachable!("sequential upload completes inside final upload_chunk")
    }
    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        if let Some(sid) = op.session_token.as_deref() {
            self.sessions.lock().unwrap().remove(sid);
        }
        Ok(())
    }
    async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
        Ok(ReconcileOutcome::NotCommitted)
    }
}

fn make_op_record(
    op_id: &str,
    rel: RelPath,
    total_size: u64,
    planned_chunk_size: u64,
    sess: &UploadSessionInit,
    endpoint: String,
) -> OperationRecord {
    OperationRecord {
        op_id: op_id.into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: endpoint,
        src_raw_path: rel.as_str().to_string(),
        dst_raw_path: rel.as_str().to_string(),
        dst_nfc_path: rel,
        src_version: rship_core::state::SourceVersion {
            node_id: None,
            size: total_size,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id.clone(),
        backend_kind: "crypt".into(),
        session_token: Some(sess.session_token.clone()),
        backend_meta: sess.backend_meta.clone(),
        planned_chunk_size,
        confirmed_offset: 0,
        state: rship_core::state::OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    }
}

async fn read_full_crypt(crypto: &CryptoBackend, rel: &RelPath, expected: &[u8]) {
    let DataSource::RemoteRangeReadable(reader) = crypto
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap()
    else {
        panic!("expected RemoteRangeReadable");
    };
    assert_eq!(reader.total_len(), expected.len() as u64);
    let mut s = reader
        .open_range(ByteRange {
            offset: 0,
            len: expected.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(c) = s.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got, expected, "decrypted payload mismatch for {rel}");
}

#[tokio::test]
async fn crypto_seq_align_resume_resets_skip_leading_ct_when_avail_lt_align() {
    for (align_bytes, chunk_size) in [(262_144u64, 262_144u64), (524_288u64, 131_072u64)] {
        let total_size = 1_000_000u64;
        let payload: Vec<u8> = (0..total_size as usize)
            .map(|i| ((i * 31 + 7) % 251) as u8)
            .collect();
        let inner = Arc::new(ConfigurableSeqAlignMock::new(align_bytes, chunk_size));
        let keys = MasterKey::from_bytes([0x33u8; 32]).derive_subkeys();
        let crypto = Arc::new(
            CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys.clone()).unwrap(),
        );
        let rel = RelPath::parse(&format!("resume_{align_bytes}_{chunk_size}.bin")).unwrap();
        let op_id = format!("op-seq-{align_bytes}-{chunk_size}");
        let sess = crypto
            .begin_upload(&UploadInit {
                op_id: op_id.clone(),
                dst_path: rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: chunk_size,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            })
            .await
            .unwrap();
        let op = make_op_record(
            &op_id,
            rel.clone(),
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );

        // Upload enough initial chunks to flush at least `align_bytes` to the inner mock.
        let mut off = 0u64;
        let mut pn = 1u32;
        while off < align_bytes {
            let len = (total_size - off).min(chunk_size);
            let slice = Bytes::copy_from_slice(&payload[off as usize..(off + len) as usize]);
            crypto
                .upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn,
                        off,
                        len,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(slice) })),
                    ),
                )
                .await
                .unwrap();
            off += len;
            pn += 1;
        }

        // Simulate process restart with a fresh `CryptoBackend` instance (empty in-memory
        // `seq_align_state`), querying the inner session and resuming across `avail < align`.
        let resumed_crypto =
            Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys).unwrap());
        let UploadProgress::SequentialOffset(mut resume_off) =
            resumed_crypto.query_upload(&op).await.unwrap()
        else {
            panic!("expected SequentialOffset from query_upload");
        };
        assert!(resume_off < off, "expected partial block rewind on resume");

        while resume_off < total_size {
            let len = (total_size - resume_off).min(chunk_size);
            let slice =
                Bytes::copy_from_slice(&payload[resume_off as usize..(resume_off + len) as usize]);
            let ack = resumed_crypto
                .upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn,
                        resume_off,
                        len,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(slice) })),
                    ),
                )
                .await
                .unwrap();
            resume_off = ack.next_offset.unwrap();
            pn += 1;
        }

        read_full_crypt(&resumed_crypto, &rel, &payload).await;
    }
}

#[tokio::test]
async fn crypto_seq_align_resume_inside_block0_preserves_header_skip_bit_exact() {
    for (align_bytes, resume_ct_off) in [
        (32_768u64, 32_768u64), // 32 <= ct_off < 65_584
        (32_768u64, 32u64),     // exact header boundary
        (16u64, 16u64),         // 0 < ct_off < 32
        (65_536u64, 32_768u64), // block-0 resume + avail < align combined
    ] {
        let total_size = 131_072u64; // 2 * 64 KiB plaintext blocks
        let chunk_size = 65_536u64;
        let payload: Vec<u8> = (0..total_size as usize)
            .map(|i| ((i * 17 + 11) % 251) as u8)
            .collect();
        let inner = Arc::new(ConfigurableSeqAlignMock::new(align_bytes, chunk_size));
        let keys = MasterKey::from_bytes([0x77u8; 32]).derive_subkeys();
        let crypto = Arc::new(
            CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys.clone()).unwrap(),
        );
        let rel = RelPath::parse(&format!("block0_{align_bytes}_{resume_ct_off}.bin")).unwrap();
        let op_id = format!("op-b0-{align_bytes}-{resume_ct_off}");
        let sess = crypto
            .begin_upload(&UploadInit {
                op_id: op_id.clone(),
                dst_path: rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: chunk_size,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            })
            .await
            .unwrap();
        let op = make_op_record(
            &op_id,
            rel.clone(),
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );

        // Encrypt the exact stream prefix locally into the mock's inner session buffer up to
        // `resume_ct_off` to simulate a mid-block-0 server commit before interruption.
        let meta_val: serde_json::Value = serde_json::from_str(&sess.backend_meta).unwrap();
        let nonce_bytes = hex::decode(meta_val["nonce_prefix_hex"].as_str().unwrap()).unwrap();
        let mut nonce_prefix = [0u8; 16];
        nonce_prefix.copy_from_slice(&nonce_bytes);
        let header = crate::stream::StreamHeader::from_nonce_prefix(nonce_prefix);
        let payload_bytes = Bytes::from(payload.clone());
        let mut enc_stream = crate::stream::StreamEncryptor::new(
            Box::pin(futures::stream::once(async move { Ok(payload_bytes) })),
            &keys.data_key,
            header,
            0,
            total_size,
            true,
            true,
        );
        let mut full_ct = Vec::new();
        while let Some(c) = enc_stream.next().await {
            full_ct.extend_from_slice(&c.unwrap());
        }
        {
            let mut sessions = inner.sessions.lock().unwrap();
            let (_, buf) = sessions.get_mut(&sess.session_token).unwrap();
            buf.extend_from_slice(&full_ct[..resume_ct_off as usize]);
        }

        let resumed_crypto =
            Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys).unwrap());
        let UploadProgress::SequentialOffset(resume_off) =
            resumed_crypto.query_upload(&op).await.unwrap()
        else {
            panic!("expected SequentialOffset from query_upload");
        };
        assert_eq!(resume_off, 0, "block-0 resume must restart at pt_off 0");

        let mut off = resume_off;
        let mut pn = 1u32;
        while off < total_size {
            let len = (total_size - off).min(chunk_size);
            let slice = Bytes::copy_from_slice(&payload[off as usize..(off + len) as usize]);
            let ack = resumed_crypto
                .upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn,
                        off,
                        len,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(slice) })),
                    ),
                )
                .await
                .unwrap();
            off = ack.next_offset.unwrap();
            pn += 1;
        }

        read_full_crypt(&resumed_crypto, &rel, &payload).await;
    }
}

#[tokio::test]
async fn crypto_equal_non_final_parts_query_upload_aligns_and_clamps_confirmed_offset() {
    use rship_core::types::{ChunkAlignment, UploadTopology};
    use std::time::Duration;

    type EqualUploadEntry = (String, u64, HashMap<u32, Vec<u8>>);

    #[derive(Clone, Default)]
    struct EqualPartsMock {
        objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
        uploads: Arc<StdMutex<HashMap<String, EqualUploadEntry>>>,
    }

    #[async_trait]
    impl StorageBackend for EqualPartsMock {
        fn name(&self) -> &str {
            "eq-mock"
        }
        fn kind(&self) -> &'static str {
            "s3"
        }
        fn endpoint_identity(&self) -> String {
            "s3://eq-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: 64 * 1024,
                    max_bytes: 5 * 1024 * 1024,
                    max_parts: 10_000,
                    max_object_bytes: 100 * 1024 * 1024,
                    require_equal_non_final_parts: true,
                },
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 128 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let map = self.objects.lock().unwrap();
            Ok(map.get(path.nfc_path.as_str()).map(|b| Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: b.len() as u64,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            let data = self
                .objects
                .lock()
                .unwrap()
                .get(path.nfc_path.as_str())
                .cloned()
                .ok_or_else(|| Error::not_found("missing"))?;
            let slice = match range {
                Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
                None => data,
            };
            let len = slice.len() as u64;
            Ok(DataSource::SequentialStream {
                stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                total_len: Some(len),
            })
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            unreachable!()
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            let uid = format!("eq-uid-{}", init.op_id);
            self.uploads.lock().unwrap().insert(
                uid.clone(),
                (
                    init.dst_path.as_str().to_string(),
                    init.planned_chunk_size,
                    HashMap::new(),
                ),
            );
            Ok(UploadSessionInit {
                session_token: uid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Ok(UploadProgress::CompletedParts(vec![]))
        }
        async fn upload_chunk(
            &self,
            op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            let uid = op.session_token.as_deref().unwrap();
            let mut buf = Vec::new();
            while let Some(c) = chunk.body.next().await {
                buf.extend_from_slice(&c?);
            }
            self.uploads
                .lock()
                .unwrap()
                .get_mut(uid)
                .unwrap()
                .2
                .insert(chunk.part_number, buf);
            Ok(ChunkAck {
                next_offset: None,
                etag: Some(format!("\"etag-{}\"", chunk.part_number)),
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            let uid = op.session_token.as_deref().unwrap();
            let (key, _planned, mut stored) = self.uploads.lock().unwrap().remove(uid).unwrap();
            let mut full = Vec::new();
            for p in parts {
                full.extend_from_slice(&stored.remove(&p.part_number).unwrap());
            }
            let len = full.len() as u64;
            self.objects.lock().unwrap().insert(key.clone(), full);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::parse(&key)?,
                kind: EntryKind::File,
                size: len,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            })
        }
        async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let total_size = 200_000u64;
    let chunk_size = 131_072u64;
    let inner = Arc::new(EqualPartsMock::default());
    let keys = MasterKey::from_bytes([0x55u8; 32]).derive_subkeys();
    let crypto = Arc::new(CryptoBackend::new(inner, CryptoConfig::new("eq"), keys).unwrap());
    let rel = RelPath::parse("eq_align.bin").unwrap();
    let sess = crypto
        .begin_upload(&UploadInit {
            op_id: "op-eq-align".into(),
            dst_path: rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: chunk_size,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        })
        .await
        .unwrap();
    let mut op = make_op_record(
        "op-eq-align",
        rel.clone(),
        total_size,
        chunk_size,
        &sess,
        crypto.endpoint_identity(),
    );

    // Unaligned confirmed_offset < PLAINTEXT_CHUNK_LEN -> aligns down to 0
    op.confirmed_offset = 12_345;
    assert_eq!(
        crypto.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );

    // Unaligned confirmed_offset > PLAINTEXT_CHUNK_LEN -> aligns down to 65_536
    op.confirmed_offset = 100_000;
    assert_eq!(
        crypto.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(65_536)
    );

    // Confirmed offset >= total_size -> clamped to total_size
    op.confirmed_offset = total_size + 999;
    assert_eq!(
        crypto.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(total_size)
    );

    // Offset returned by query_upload(12_345) is accepted by upload_chunk and finishes cleanly
    op.confirmed_offset = 12_345;
    let UploadProgress::SequentialOffset(start_off) = crypto.query_upload(&op).await.unwrap()
    else {
        panic!("expected SequentialOffset");
    };
    assert_eq!(start_off, 0);
    let payload: Vec<u8> = (0..total_size as usize).map(|i| (i % 251) as u8).collect();
    let p1 = Bytes::copy_from_slice(&payload[0..chunk_size as usize]);
    crypto
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk_size,
                total_size,
                Box::pin(futures::stream::once(async move { Ok(p1) })),
            ),
        )
        .await
        .unwrap();
    let p2 = Bytes::copy_from_slice(&payload[chunk_size as usize..]);
    crypto
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk_size,
                total_size - chunk_size,
                total_size,
                Box::pin(futures::stream::once(async move { Ok(p2) })),
            ),
        )
        .await
        .unwrap();
    crypto.finish_upload(&op, &[]).await.unwrap();
    read_full_crypt(&crypto, &rel, &payload).await;
}

#[tokio::test]
async fn crypto_equal_non_final_parts_finish_upload_retains_manifest_on_retryable_error() {
    use rship_core::types::{ChunkAlignment, UploadTopology};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    type EqualUploadEntry = (String, u64, HashMap<u32, Vec<u8>>);

    #[derive(Default)]
    struct EqualPartsRetryMock {
        objects: StdMutex<HashMap<String, Vec<u8>>>,
        uploads: StdMutex<HashMap<String, EqualUploadEntry>>,
        fail_first_finish: AtomicBool,
        finish_attempts: AtomicUsize,
        aborted_uploads: AtomicUsize,
    }

    impl EqualPartsRetryMock {
        fn new() -> Self {
            Self {
                objects: StdMutex::new(HashMap::new()),
                uploads: StdMutex::new(HashMap::new()),
                fail_first_finish: AtomicBool::new(true),
                finish_attempts: AtomicUsize::new(0),
                aborted_uploads: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for EqualPartsRetryMock {
        fn name(&self) -> &str {
            "eq-retry-mock"
        }
        fn kind(&self) -> &'static str {
            "s3"
        }
        fn endpoint_identity(&self) -> String {
            "s3://eq-retry-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: 64 * 1024,
                    max_bytes: 5 * 1024 * 1024,
                    max_parts: 10_000,
                    max_object_bytes: 100 * 1024 * 1024,
                    require_equal_non_final_parts: true,
                },
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 128 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let map = self.objects.lock().unwrap();
            Ok(map.get(path.nfc_path.as_str()).map(|b| Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: b.len() as u64,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            let data = self
                .objects
                .lock()
                .unwrap()
                .get(path.nfc_path.as_str())
                .cloned()
                .ok_or_else(|| Error::not_found("missing"))?;
            let slice = match range {
                Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
                None => data,
            };
            let len = slice.len() as u64;
            Ok(DataSource::SequentialStream {
                stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                total_len: Some(len),
            })
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            unreachable!()
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            let uid = format!("eq-retry-uid-{}", init.op_id);
            self.uploads.lock().unwrap().insert(
                uid.clone(),
                (
                    init.dst_path.as_str().to_string(),
                    init.planned_chunk_size,
                    HashMap::new(),
                ),
            );
            Ok(UploadSessionInit {
                session_token: uid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Ok(UploadProgress::CompletedParts(vec![]))
        }
        async fn upload_chunk(
            &self,
            op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            let uid = op.session_token.as_deref().unwrap();
            let mut buf = Vec::new();
            while let Some(c) = chunk.body.next().await {
                buf.extend_from_slice(&c?);
            }
            self.uploads
                .lock()
                .unwrap()
                .get_mut(uid)
                .unwrap()
                .2
                .insert(chunk.part_number, buf);
            Ok(ChunkAck {
                next_offset: None,
                etag: Some(format!("\"etag-{}\"", chunk.part_number)),
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.finish_attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail_first_finish.swap(false, Ordering::SeqCst) {
                return Err(Error::network(
                    "simulated 503 Service Unavailable during finish_upload",
                ));
            }
            let uid = op.session_token.as_deref().unwrap();
            let (key, _planned, mut stored) = self.uploads.lock().unwrap().remove(uid).unwrap();
            let mut full = Vec::new();
            for p in parts {
                full.extend_from_slice(&stored.remove(&p.part_number).unwrap());
            }
            let len = full.len() as u64;
            self.objects.lock().unwrap().insert(key.clone(), full);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::parse(&key)?,
                kind: EntryKind::File,
                size: len,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            })
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.aborted_uploads.fetch_add(1, Ordering::SeqCst);
            if let Some(uid) = op.session_token.as_deref() {
                self.uploads.lock().unwrap().remove(uid);
            }
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let total_size = 200_000u64;
    let chunk_size = 131_072u64;
    let payload: Vec<u8> = (0..total_size as usize)
        .map(|i| ((i * 7 + 1) % 251) as u8)
        .collect();
    let inner = Arc::new(EqualPartsRetryMock::new());
    let keys = MasterKey::from_bytes([0x61u8; 32]).derive_subkeys();
    let crypto =
        Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("eq"), keys.clone()).unwrap());
    let rel = RelPath::parse("finish_retry.bin").unwrap();
    let sess = crypto
        .begin_upload(&UploadInit {
            op_id: "op-eq-finish-retry".into(),
            dst_path: rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: chunk_size,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        })
        .await
        .unwrap();
    let mut op = make_op_record(
        "op-eq-finish-retry",
        rel.clone(),
        total_size,
        chunk_size,
        &sess,
        crypto.endpoint_identity(),
    );

    let p1 = Bytes::copy_from_slice(&payload[0..chunk_size as usize]);
    crypto
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk_size,
                total_size,
                Box::pin(futures::stream::once(async move { Ok(p1) })),
            ),
        )
        .await
        .unwrap();
    let p2 = Bytes::copy_from_slice(&payload[chunk_size as usize..]);
    crypto
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk_size,
                total_size - chunk_size,
                total_size,
                Box::pin(futures::stream::once(async move { Ok(p2) })),
            ),
        )
        .await
        .unwrap();

    // Attempt 1 fails with retryable network/503 error: manifest MUST be retained.
    let err = crypto.finish_upload(&op, &[]).await.unwrap_err();
    assert!(err.is_retryable(), "expected retryable error, got {err:?}");
    assert!(
        lock_unpoisoned(&crypto.equal_parts_state).contains_key(&op.op_id),
        "equal_parts_state must retain manifest after retryable finish_upload failure"
    );

    // Recovery query_upload must NOT abort inner session and must report full offset.
    op.confirmed_offset = total_size;
    assert_eq!(
        crypto.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(total_size)
    );
    assert_eq!(inner.aborted_uploads.load(Ordering::SeqCst), 0);

    // Attempt 2 succeeds, cleans up equal_parts_state, and decrypts bit-exact.
    crypto.finish_upload(&op, &[]).await.unwrap();
    assert_eq!(inner.finish_attempts.load(Ordering::SeqCst), 2);
    assert!(
        lock_unpoisoned(&crypto.equal_parts_state).is_empty(),
        "equal_parts_state must be cleaned up after finish_upload succeeds"
    );
    read_full_crypt(&crypto, &rel, &payload).await;

    // Also verify `seq_align_state` is cleaned up when `query_upload` sees `ct_off >= ct_total`
    // and `finish_upload` is invoked directly without a final `upload_chunk`.
    struct SeqAlignFinishMock {
        ct_total: u64,
    }

    #[async_trait]
    impl StorageBackend for SeqAlignFinishMock {
        fn name(&self) -> &str {
            "seq-finish-mock"
        }
        fn kind(&self) -> &'static str {
            "gdrive"
        }
        fn endpoint_identity(&self) -> String {
            "gdrive://seq-finish-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_millis(1),
                can_set_mtime: true,
                upload_topology: UploadTopology::Sequential,
                chunk_alignment: ChunkAlignment::MultipleOf {
                    align_bytes: 256 * 1024,
                    max_chunk_bytes: None,
                },
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 256 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, _path: &BackendPath) -> Result<Option<Entry>> {
            Ok(None)
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            _path: &BackendPath,
            _range: Option<ByteRange>,
        ) -> Result<DataSource> {
            unreachable!()
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            unreachable!()
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            Ok(UploadSessionInit {
                session_token: format!("seq-fin-{}", init.op_id),
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Ok(UploadProgress::SequentialOffset(self.ct_total))
        }
        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            _chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            unreachable!()
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: op.dst_nfc_path.clone(),
                kind: EntryKind::File,
                size: self.ct_total,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"done\"".into()),
                checksum: None,
            })
        }
        async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let seq_pt_total = 131_072u64;
    let seq_ct_total = ciphertext_size(seq_pt_total).unwrap();
    let seq_inner = Arc::new(SeqAlignFinishMock {
        ct_total: seq_ct_total,
    });
    let seq_crypto =
        Arc::new(CryptoBackend::new(seq_inner, CryptoConfig::new("gd"), keys).unwrap());
    let seq_rel = RelPath::parse("seq_query_finish.bin").unwrap();
    let seq_sess = seq_crypto
        .begin_upload(&UploadInit {
            op_id: "op-seq-query-finish".into(),
            dst_path: seq_rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: seq_pt_total,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 65_536,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        })
        .await
        .unwrap();
    let seq_op = make_op_record(
        "op-seq-query-finish",
        seq_rel,
        seq_pt_total,
        65_536,
        &seq_sess,
        seq_crypto.endpoint_identity(),
    );
    assert_eq!(
        seq_crypto.query_upload(&seq_op).await.unwrap(),
        UploadProgress::SequentialOffset(seq_pt_total)
    );
    assert!(lock_unpoisoned(&seq_crypto.seq_align_state).contains_key(&seq_op.op_id));
    seq_crypto.finish_upload(&seq_op, &[]).await.unwrap();
    assert!(
        lock_unpoisoned(&seq_crypto.seq_align_state).is_empty(),
        "seq_align_state must be removed after finish_upload succeeds"
    );
}

#[tokio::test]
async fn crypto_abort_upload_prevents_inflight_upload_chunk_zombie_state() {
    use rship_core::ErrorKind;
    use rship_core::types::{ChunkAlignment, UploadTopology};
    use std::time::Duration;
    use tokio::sync::Notify;

    struct PausedChunkMock {
        equal_parts: bool,
        align_bytes: u64,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        sessions: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl PausedChunkMock {
        fn new_equal() -> Self {
            Self {
                equal_parts: true,
                align_bytes: 0,
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                sessions: StdMutex::new(HashMap::new()),
            }
        }
        fn new_seq(align_bytes: u64) -> Self {
            Self {
                equal_parts: false,
                align_bytes,
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                sessions: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for PausedChunkMock {
        fn name(&self) -> &str {
            "paused-mock"
        }
        fn kind(&self) -> &'static str {
            if self.equal_parts { "s3" } else { "gdrive" }
        }
        fn endpoint_identity(&self) -> String {
            "mock://paused".into()
        }
        fn capabilities(&self) -> Capabilities {
            let (upload_topology, chunk_alignment) = if self.equal_parts {
                (
                    UploadTopology::ParallelParts,
                    ChunkAlignment::MinSizeWithMaxParts {
                        min_bytes: 64 * 1024,
                        max_bytes: 5 * 1024 * 1024,
                        max_parts: 10_000,
                        max_object_bytes: 100 * 1024 * 1024,
                        require_equal_non_final_parts: true,
                    },
                )
            } else {
                (
                    UploadTopology::Sequential,
                    ChunkAlignment::MultipleOf {
                        align_bytes: self.align_bytes,
                        max_chunk_bytes: None,
                    },
                )
            };
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology,
                chunk_alignment,
                single_shot_max_bytes: 64 * 1024,
                default_chunk_size: 128 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, _path: &BackendPath) -> Result<Option<Entry>> {
            Ok(None)
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            _path: &BackendPath,
            _range: Option<ByteRange>,
        ) -> Result<DataSource> {
            unreachable!()
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            unreachable!()
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            let sid = format!("paused-sid-{}", init.op_id);
            self.sessions
                .lock()
                .unwrap()
                .insert(sid.clone(), Vec::new());
            Ok(UploadSessionInit {
                session_token: sid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            let sid = op.session_token.as_deref().unwrap();
            let sessions = self.sessions.lock().unwrap();
            match sessions.get(sid) {
                Some(buf) => Ok(UploadProgress::SequentialOffset(buf.len() as u64)),
                None => Ok(UploadProgress::Expired),
            }
        }
        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            while let Some(c) = chunk.body.next().await {
                let _ = c?;
            }
            self.entered.notify_one();
            self.release.notified().await;
            Ok(ChunkAck {
                next_offset: Some(chunk.offset + chunk.len),
                etag: Some("\"etag-1\"".into()),
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            _op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            unreachable!()
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            if let Some(sid) = op.session_token.as_deref() {
                self.sessions.lock().unwrap().remove(sid);
            }
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    // 1. equal_non_final_parts: pause upload_chunk across .await, abort concurrently, resume.
    {
        let inner = Arc::new(PausedChunkMock::new_equal());
        let keys = MasterKey::from_bytes([0x88u8; 32]).derive_subkeys();
        let crypto =
            Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("eq"), keys).unwrap());
        let rel = RelPath::parse("abort_eq.bin").unwrap();
        let total_size = 262_144u64;
        let chunk_size = 131_072u64;
        let sess = crypto
            .begin_upload(&UploadInit {
                op_id: "op-abort-eq".into(),
                dst_path: rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: chunk_size,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            })
            .await
            .unwrap();
        let op = make_op_record(
            "op-abort-eq",
            rel,
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );
        let payload = Bytes::from(vec![0x11u8; chunk_size as usize]);
        let crypto_task = crypto.clone();
        let op_task = op.clone();
        let entered_wait = inner.entered.notified();
        let handle = tokio::spawn(async move {
            crypto_task
                .upload_chunk(
                    &op_task,
                    ChunkUpload::new(
                        1,
                        0,
                        chunk_size,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(payload) })),
                    ),
                )
                .await
        });

        entered_wait.await;
        crypto.abort_upload(&op).await.unwrap();
        inner.release.notify_one();

        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::SessionExpired);
        assert!(lock_unpoisoned(&crypto.equal_parts_state).is_empty());
        assert_eq!(
            crypto.query_upload(&op).await.unwrap(),
            UploadProgress::Expired
        );
    }

    // 2. seq_align_bytes (with begin_upload): pause upload_chunk across inner .await.
    {
        let align_bytes = 65_536u64;
        let inner = Arc::new(PausedChunkMock::new_seq(align_bytes));
        let keys = MasterKey::from_bytes([0x89u8; 32]).derive_subkeys();
        let crypto =
            Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys).unwrap());
        let rel = RelPath::parse("abort_seq_begin.bin").unwrap();
        let total_size = 262_144u64;
        let chunk_size = 131_072u64;
        let sess = crypto
            .begin_upload(&UploadInit {
                op_id: "op-abort-seq-begin".into(),
                dst_path: rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: chunk_size,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            })
            .await
            .unwrap();
        let op = make_op_record(
            "op-abort-seq-begin",
            rel,
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );
        let payload = Bytes::from(vec![0x22u8; chunk_size as usize]);
        let crypto_task = crypto.clone();
        let op_task = op.clone();
        let entered_wait = inner.entered.notified();
        let handle = tokio::spawn(async move {
            crypto_task
                .upload_chunk(
                    &op_task,
                    ChunkUpload::new(
                        1,
                        0,
                        chunk_size,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(payload) })),
                    ),
                )
                .await
        });

        entered_wait.await;
        crypto.abort_upload(&op).await.unwrap();
        inner.release.notify_one();

        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::SessionExpired);
        assert!(lock_unpoisoned(&crypto.seq_align_state).is_empty());
        assert_eq!(
            crypto.query_upload(&op).await.unwrap(),
            UploadProgress::Expired
        );
    }

    // 3. seq_align_bytes WITHOUT prior begin_upload on this CryptoBackend (chunk 1 before
    //    `seq_align_state` had an entry), testing both `avail >= align` and `avail < align`.
    for (op_id, align_bytes, chunk_size, pause_in_stream) in [
        ("op-abort-seq-direct-ge", 65_536u64, 131_072u64, false),
        ("op-abort-seq-direct-lt", 262_144u64, 65_536u64, true),
    ] {
        let inner = Arc::new(PausedChunkMock::new_seq(align_bytes));
        let keys = MasterKey::from_bytes([0x8Au8; 32]).derive_subkeys();
        let crypto =
            Arc::new(CryptoBackend::new(inner.clone(), CryptoConfig::new("gd"), keys).unwrap());
        let rel = RelPath::parse(&format!("{op_id}.bin")).unwrap();
        let total_size = 524_288u64;
        let meta = CryptoSessionMeta {
            nonce_prefix_hex: hex::encode([0x44u8; 16]),
            plaintext_total_size: total_size,
            plaintext_chunk_size: chunk_size,
            inner_meta: String::new(),
            inner_dst_path: crypto.to_inner_rel(&rel).unwrap().as_str().to_string(),
            equal_non_final_parts: false,
            seq_align_bytes: Some(align_bytes),
        };
        let sess = UploadSessionInit {
            session_token: format!("direct-sid-{op_id}"),
            backend_meta: serde_json::to_string(&meta).unwrap(),
            remote_op_id: Some(op_id.into()),
            expires_at_unix_secs: None,
        };
        let op = make_op_record(
            op_id,
            rel,
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );
        assert!(lock_unpoisoned(&crypto.seq_align_state).is_empty());

        let payload = Bytes::from(vec![0x33u8; chunk_size as usize]);
        let stream_entered = Arc::new(Notify::new());
        let stream_release = Arc::new(Notify::new());
        let body: ByteStream = if pause_in_stream {
            let e = stream_entered.clone();
            let r = stream_release.clone();
            Box::pin(futures::stream::once(async move {
                e.notify_one();
                r.notified().await;
                Ok(payload)
            }))
        } else {
            Box::pin(futures::stream::once(async move { Ok(payload) }))
        };

        let crypto_task = crypto.clone();
        let op_task = op.clone();
        let entered_wait = if pause_in_stream {
            stream_entered.notified()
        } else {
            inner.entered.notified()
        };
        let handle = tokio::spawn(async move {
            crypto_task
                .upload_chunk(
                    &op_task,
                    ChunkUpload::new(1, 0, chunk_size, total_size, body),
                )
                .await
        });

        entered_wait.await;
        crypto.abort_upload(&op).await.unwrap();
        if pause_in_stream {
            stream_release.notify_one();
        } else {
            inner.release.notify_one();
        }

        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::SessionExpired);
        assert!(
            lock_unpoisoned(&crypto.seq_align_state).is_empty(),
            "zombie seq_align_state re-inserted for {op_id}"
        );
        assert_eq!(
            crypto.query_upload(&op).await.unwrap(),
            UploadProgress::Expired
        );
    }
}

#[tokio::test]
async fn crypto_minmax_parts_capabilities_and_roundtrip_respect_ciphertext_expansion() {
    use rship_core::chunking::{UploadPlan, plan_upload};
    use rship_core::types::{ChunkAlignment, UploadTopology};
    use std::time::Duration;

    type StrictUploadState = (String, u64, u64, HashMap<u32, Vec<u8>>);

    #[derive(Clone)]
    struct StrictBoundsMinMaxMock {
        min_bytes: u64,
        max_bytes: u64,
        max_parts: u32,
        max_object_bytes: u64,
        single_shot_max_bytes: u64,
        default_chunk_size: u64,
        require_equal_non_final_parts: bool,
        objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
        uploads: Arc<StdMutex<HashMap<String, StrictUploadState>>>,
    }

    #[async_trait]
    impl StorageBackend for StrictBoundsMinMaxMock {
        fn name(&self) -> &str {
            "strict-minmax-mock"
        }
        fn kind(&self) -> &'static str {
            "s3"
        }
        fn endpoint_identity(&self) -> String {
            "s3://strict-minmax-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: self.min_bytes,
                    max_bytes: self.max_bytes,
                    max_parts: self.max_parts,
                    max_object_bytes: self.max_object_bytes,
                    require_equal_non_final_parts: self.require_equal_non_final_parts,
                },
                single_shot_max_bytes: self.single_shot_max_bytes,
                default_chunk_size: self.default_chunk_size,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let map = self.objects.lock().unwrap();
            Ok(map.get(path.nfc_path.as_str()).map(|b| Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: b.len() as u64,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: None,
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            self.objects.lock().unwrap().remove(path.nfc_path.as_str());
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            let data = self
                .objects
                .lock()
                .unwrap()
                .get(path.nfc_path.as_str())
                .cloned()
                .ok_or_else(|| Error::not_found("missing"))?;
            let slice = match range {
                Some(r) => data[r.offset as usize..(r.offset + r.len) as usize].to_vec(),
                None => data,
            };
            let len = slice.len() as u64;
            Ok(DataSource::SequentialStream {
                stream: Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                total_len: Some(len),
            })
        }
        async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
            if init.total_size > self.single_shot_max_bytes {
                return Err(Error::invalid_geometry(format!(
                    "single_shot {} exceeds {}",
                    init.total_size, self.single_shot_max_bytes
                )));
            }
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(&c?);
            }
            let len = buf.len() as u64;
            self.objects
                .lock()
                .unwrap()
                .insert(init.dst_path.as_str().to_string(), buf);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: init.dst_path.clone(),
                kind: EntryKind::File,
                size: len,
                mtime_ns: init.src_mtime_ns,
                ctime_ns: None,
                etag: Some("\"single\"".into()),
                checksum: None,
            })
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            if init.total_size > self.max_object_bytes {
                return Err(Error::invalid_geometry(format!(
                    "ct total {} exceeds inner max_object_bytes {}",
                    init.total_size, self.max_object_bytes
                )));
            }
            if init.planned_chunk_size < self.min_bytes || init.planned_chunk_size > self.max_bytes
            {
                return Err(Error::invalid_geometry(format!(
                    "ct planned_chunk_size {} outside [{}, {}]",
                    init.planned_chunk_size, self.min_bytes, self.max_bytes
                )));
            }
            let uid = format!("strict-uid-{}", init.op_id);
            self.uploads.lock().unwrap().insert(
                uid.clone(),
                (
                    init.dst_path.as_str().to_string(),
                    init.planned_chunk_size,
                    init.total_size,
                    HashMap::new(),
                ),
            );
            Ok(UploadSessionInit {
                session_token: uid,
                backend_meta: String::new(),
                remote_op_id: Some(init.op_id.clone()),
                expires_at_unix_secs: None,
            })
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Ok(UploadProgress::CompletedParts(vec![]))
        }
        async fn upload_chunk(
            &self,
            op: &OperationRecord,
            mut chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            if chunk.total_size > self.max_object_bytes {
                return Err(Error::invalid_geometry(format!(
                    "ct total {} exceeds inner max_object_bytes {}",
                    chunk.total_size, self.max_object_bytes
                )));
            }
            if chunk.part_number == 0 || chunk.part_number > self.max_parts {
                return Err(Error::invalid_geometry(format!(
                    "ct part_number {} exceeds max_parts {}",
                    chunk.part_number, self.max_parts
                )));
            }
            if chunk.len > self.max_bytes {
                return Err(Error::invalid_geometry(format!(
                    "ct part {} len {} exceeds inner max_bytes {}",
                    chunk.part_number, chunk.len, self.max_bytes
                )));
            }
            let is_final = chunk.offset + chunk.len == chunk.total_size;
            if self.require_equal_non_final_parts {
                if !is_final && chunk.len != op.planned_chunk_size {
                    return Err(Error::invalid_geometry(format!(
                        "unequal non-final part {}: {} != {}",
                        chunk.part_number, chunk.len, op.planned_chunk_size
                    )));
                }
                if is_final && chunk.len > op.planned_chunk_size {
                    return Err(Error::invalid_geometry(format!(
                        "final part {} {} > planned {}",
                        chunk.part_number, chunk.len, op.planned_chunk_size
                    )));
                }
            } else if !is_final && chunk.len < self.min_bytes {
                return Err(Error::invalid_geometry(format!(
                    "non-final part {} len {} < min_bytes {}",
                    chunk.part_number, chunk.len, self.min_bytes
                )));
            }
            let uid = op.session_token.as_deref().unwrap();
            let mut buf = Vec::new();
            while let Some(c) = chunk.body.next().await {
                buf.extend_from_slice(&c?);
            }
            assert_eq!(buf.len() as u64, chunk.len);
            self.uploads
                .lock()
                .unwrap()
                .get_mut(uid)
                .unwrap()
                .3
                .insert(chunk.part_number, buf);
            Ok(ChunkAck {
                next_offset: None,
                etag: Some(format!("\"etag-{}\"", chunk.part_number)),
                completed: None,
                checksum: None,
            })
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            let uid = op.session_token.as_deref().unwrap();
            let (key, _planned, expected_total, mut stored) =
                self.uploads.lock().unwrap().remove(uid).unwrap();
            assert!(!parts.is_empty());
            assert!(parts.len() <= self.max_parts as usize);
            let mut full = Vec::new();
            for p in parts {
                full.extend_from_slice(&stored.remove(&p.part_number).unwrap());
            }
            assert_eq!(full.len() as u64, expected_total);
            self.objects.lock().unwrap().insert(key.clone(), full);
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::parse(&key)?,
                kind: EntryKind::File,
                size: expected_total,
                mtime_ns: op.src_version.mtime_ns,
                ctime_ns: None,
                etag: Some("\"mp\"".into()),
                checksum: None,
            })
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            if let Some(sid) = op.session_token.as_deref() {
                self.uploads.lock().unwrap().remove(sid);
            }
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    async fn run_manual_multipart(
        crypto: &CryptoBackend,
        name: &str,
        payload: &[u8],
        chunk_size: u64,
    ) {
        let rel = RelPath::parse(name).unwrap();
        let total_size = payload.len() as u64;
        let op_id = format!("op-{name}");
        let sess = crypto
            .begin_upload(&UploadInit {
                op_id: op_id.clone(),
                dst_path: rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: chunk_size,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            })
            .await
            .unwrap();
        let op = make_op_record(
            &op_id,
            rel.clone(),
            total_size,
            chunk_size,
            &sess,
            crypto.endpoint_identity(),
        );
        let mut completed = Vec::new();
        let mut offset = 0u64;
        let mut pn = 1u32;
        while offset < total_size {
            let len = (total_size - offset).min(chunk_size);
            let slice = Bytes::copy_from_slice(&payload[offset as usize..(offset + len) as usize]);
            let ack = crypto
                .upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn,
                        offset,
                        len,
                        total_size,
                        Box::pin(futures::stream::once(async move { Ok(slice) })),
                    ),
                )
                .await
                .unwrap();
            completed.push(CompletedPart {
                part_number: pn,
                offset,
                length: len,
                etag: ack.etag.unwrap_or_default(),
                checksum: ack.checksum,
            });
            offset += len;
            pn += 1;
        }
        crypto.finish_upload(&op, &completed).await.unwrap();
        read_full_crypt(crypto, &rel, payload).await;
    }

    let keys = MasterKey::from_bytes([0x55u8; 32]).derive_subkeys();

    // 1. require_equal_non_final_parts = true (128 KiB..512 KiB, max_parts=4, max_object_bytes=2 MiB)
    {
        let inner_max_bytes = 512 * 1024u64;
        let inner_max_obj = 2 * 1024 * 1024u64;
        let inner = Arc::new(StrictBoundsMinMaxMock {
            min_bytes: 128 * 1024,
            max_bytes: inner_max_bytes,
            max_parts: 4,
            max_object_bytes: inner_max_obj,
            single_shot_max_bytes: 64 * 1024,
            default_chunk_size: inner_max_bytes,
            require_equal_non_final_parts: true,
            objects: Arc::new(StdMutex::new(HashMap::new())),
            uploads: Arc::new(StdMutex::new(HashMap::new())),
        });
        let crypto = Arc::new(
            CryptoBackend::new(inner, CryptoConfig::new("eq-caps"), keys.clone()).unwrap(),
        );
        let caps = crypto.capabilities();
        let ChunkAlignment::MinSizeWithMaxParts {
            min_bytes,
            max_bytes,
            max_parts,
            max_object_bytes,
            require_equal_non_final_parts,
        } = caps.chunk_alignment
        else {
            panic!("expected MinSizeWithMaxParts");
        };
        assert!(require_equal_non_final_parts);
        assert_eq!(min_bytes, 128 * 1024);
        assert_eq!(max_bytes, 458_752); // 7 * 64 KiB
        assert!(min_bytes <= max_bytes);
        assert!(caps.default_chunk_size <= max_bytes);
        assert_eq!(max_parts, 3);
        assert_eq!(
            max_object_bytes,
            max_plaintext_for_ciphertext(inner_max_obj)
        );
        assert!(ciphertext_size(max_object_bytes).unwrap() <= inner_max_obj);
        assert!(ciphertext_size(max_object_bytes + 1).unwrap() > inner_max_obj);
        assert!(equal_ct_part_size(max_bytes).unwrap() <= inner_max_bytes);
        assert!(
            equal_ct_part_size(max_bytes + PLAINTEXT_CHUNK_LEN as u64).unwrap() > inner_max_bytes
        );

        // Automatic chunk planner with None override
        let auto_size = 1_300_000u64;
        let plan = plan_upload(auto_size, &caps, None).unwrap();
        let UploadPlan::Resumable {
            chunk_size,
            total_parts,
            ..
        } = plan
        else {
            panic!("expected Resumable plan");
        };
        assert_eq!(chunk_size, max_bytes);
        assert_eq!(total_parts, 3);
        let auto_payload: Vec<u8> = (0..auto_size as usize)
            .map(|i| ((i * 31 + 7) % 251) as u8)
            .collect();
        run_manual_multipart(&crypto, "eq_auto.bin", &auto_payload, chunk_size).await;

        // Exact 3 * max_bytes triggers the 32-byte carry tail part (inner part 4 == max_parts)
        let exact_max_size = 3 * max_bytes;
        let plan_exact = plan_upload(exact_max_size, &caps, Some(max_bytes)).unwrap();
        assert!(matches!(
            plan_exact,
            UploadPlan::Resumable {
                chunk_size: c,
                total_parts: 3,
                ..
            } if c == max_bytes
        ));
        let exact_payload: Vec<u8> = (0..exact_max_size as usize)
            .map(|i| ((i * 17 + 11) % 251) as u8)
            .collect();
        run_manual_multipart(&crypto, "eq_exact_max.bin", &exact_payload, max_bytes).await;
    }

    // 2. S3 5 MiB..5 GiB capability math (require_equal_non_final_parts = true)
    {
        const MIB: u64 = 1024 * 1024;
        const GIB: u64 = 1024 * MIB;
        let inner_max_bytes = 5 * GIB;
        let inner_max_obj = 5 * 1024 * GIB;
        let inner = Arc::new(StrictBoundsMinMaxMock {
            min_bytes: 5 * MIB,
            max_bytes: inner_max_bytes,
            max_parts: 10_000,
            max_object_bytes: inner_max_obj,
            single_shot_max_bytes: 64 * MIB,
            default_chunk_size: 16 * MIB,
            require_equal_non_final_parts: true,
            objects: Arc::new(StdMutex::new(HashMap::new())),
            uploads: Arc::new(StdMutex::new(HashMap::new())),
        });
        let crypto = Arc::new(
            CryptoBackend::new(inner, CryptoConfig::new("s3-caps"), keys.clone()).unwrap(),
        );
        let caps = crypto.capabilities();
        let ChunkAlignment::MinSizeWithMaxParts {
            min_bytes,
            max_bytes,
            max_parts,
            max_object_bytes,
            ..
        } = caps.chunk_alignment
        else {
            panic!("expected MinSizeWithMaxParts");
        };
        assert_eq!(min_bytes, 5 * MIB);
        assert_eq!(
            max_bytes,
            (inner_max_bytes / CIPHERTEXT_CHUNK_LEN as u64) * PLAINTEXT_CHUNK_LEN as u64
        );
        assert_eq!(max_parts, 9_999);
        assert_eq!(
            max_object_bytes,
            max_plaintext_for_ciphertext(inner_max_obj)
        );
        assert!(equal_ct_part_size(max_bytes).unwrap() <= inner_max_bytes);
        assert!(
            equal_ct_part_size(max_bytes + PLAINTEXT_CHUNK_LEN as u64).unwrap() > inner_max_bytes
        );
        assert!(ciphertext_size(max_object_bytes).unwrap() <= inner_max_obj);
        assert!(ciphertext_size(max_object_bytes + 1).unwrap() > inner_max_obj);
        assert!(plan_upload(max_object_bytes, &caps, Some(max_bytes)).is_ok());
    }

    // 3. require_equal_non_final_parts = false at chunk_size = crypt_caps.max_bytes and
    //    file_size = crypt_caps.max_object_bytes (including tight max_object_bytes boundary)
    for (label, inner_max_obj) in [("tight", 327_760u64), ("multi", 1_048_656u64)] {
        let inner_max_bytes = 512 * 1024u64;
        let inner = Arc::new(StrictBoundsMinMaxMock {
            min_bytes: 64 * 1024,
            max_bytes: inner_max_bytes,
            max_parts: 10,
            max_object_bytes: inner_max_obj,
            single_shot_max_bytes: 64 * 1024,
            default_chunk_size: inner_max_bytes,
            require_equal_non_final_parts: false,
            objects: Arc::new(StdMutex::new(HashMap::new())),
            uploads: Arc::new(StdMutex::new(HashMap::new())),
        });
        let crypto = Arc::new(
            CryptoBackend::new(
                inner,
                CryptoConfig::new(format!("neq-{label}")),
                keys.clone(),
            )
            .unwrap(),
        );
        let caps = crypto.capabilities();
        let ChunkAlignment::MinSizeWithMaxParts {
            min_bytes,
            max_bytes,
            max_parts,
            max_object_bytes,
            require_equal_non_final_parts,
        } = caps.chunk_alignment
        else {
            panic!("expected MinSizeWithMaxParts");
        };
        assert!(!require_equal_non_final_parts);
        assert_eq!(min_bytes, 64 * 1024);
        assert_eq!(max_bytes, 458_752); // HEADER_LEN (32) + 7 * 65552 = 458896 <= 512 KiB
        assert!(min_bytes <= max_bytes);
        assert_eq!(max_parts, 10);
        assert_eq!(
            max_object_bytes,
            max_plaintext_for_ciphertext(inner_max_obj)
        );
        assert!(ciphertext_size(max_object_bytes).unwrap() <= inner_max_obj);
        assert!(ciphertext_size(max_object_bytes + 1).unwrap() > inner_max_obj);
        assert!(HEADER_LEN as u64 + equal_ct_part_size(max_bytes).unwrap() <= inner_max_bytes);
        assert!(
            HEADER_LEN as u64 + equal_ct_part_size(max_bytes + PLAINTEXT_CHUNK_LEN as u64).unwrap()
                > inner_max_bytes
        );

        let plan = plan_upload(max_object_bytes, &caps, Some(max_bytes)).unwrap();
        let UploadPlan::Resumable { chunk_size, .. } = plan else {
            panic!("expected Resumable plan for {label}");
        };
        assert_eq!(chunk_size, max_bytes);
        let payload: Vec<u8> = (0..max_object_bytes as usize)
            .map(|i| ((i * 23 + 1) % 251) as u8)
            .collect();
        run_manual_multipart(&crypto, &format!("neq_{label}.bin"), &payload, max_bytes).await;
    }
}
