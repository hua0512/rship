use super::super::*;
use super::pipeline_slot_test_lock;
use crate::keys::MasterKey;
use rship_backends::local::LocalBackend;
use rship_core::clock::{Clock, SystemClock, VirtualClock};
use rship_core::conformance::run_backend_conformance;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use tempfile::TempDir;

#[tokio::test]
async fn crypto_backend_passes_full_conformance_suite_with_encrypted_filenames() {
    let dir = TempDir::new().unwrap();
    let inner = Arc::new(LocalBackend::new("local-enc", dir.path()).unwrap());
    let keys = MasterKey::from_bytes([0xABu8; 32]).derive_subkeys();
    let crypto: Arc<dyn StorageBackend> =
        Arc::new(CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys).unwrap());
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    run_backend_conformance(crypto, clock).await;
}

#[tokio::test]
async fn crypto_seekable_range_read_and_tamper_detection_across_multi_chunk_file() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();

    // 200 KiB file spans 4 × 64 KiB STREAM AEAD blocks (3 full + 1 partial)!
    let payload: Vec<u8> = (0..200_000).map(|i| ((i * 31) % 251) as u8).collect();
    std::fs::write(src_dir.join("secret.bin"), &payload).unwrap();

    let local_src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let local_enc = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let keys = MasterKey::from_passphrase("correct-horse-battery-staple", None)
        .unwrap()
        .derive_subkeys();
    let crypto = Arc::new(
        CryptoBackend::new(local_enc.clone(), CryptoConfig::new("crypt"), keys.clone()).unwrap(),
    );

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local_src,
        crypto.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg = EngineConfig::new("job-crypt", JobMode::Copy, "src", "crypt");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);

    assert!(!enc_dir.join("secret.bin").exists());
    let enc_rel = encrypt_rel_path(
        &keys,
        FilenameEncryption::Standard,
        &RelPath::parse("secret.bin").unwrap(),
    )
    .unwrap();
    let ct_path = enc_dir.join(enc_rel.as_str());
    let ct_bytes = std::fs::read(&ct_path).unwrap();
    assert_eq!(ct_bytes.len() as u64, ciphertext_size(200_000).unwrap());
    assert_eq!(&ct_bytes[0..8], b"RSHIPCR1");

    let reader = match crypto
        .open_read(
            &BackendPath::from_rel(RelPath::parse("secret.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut s = reader
        .open_range(ByteRange {
            offset: 65_436,
            len: 66_136,
        })
        .await
        .unwrap();
    let mut slice_out = Vec::new();
    while let Some(c) = s.next().await {
        slice_out.extend_from_slice(&c.unwrap());
    }
    assert_eq!(slice_out, payload[65_436..65_436 + 66_136]);

    // Flip 1 byte in chunk 1 on disk -> Range read MUST fail AEAD verification!
    let mut tampered = ct_bytes.clone();
    tampered[HEADER_LEN + CIPHERTEXT_CHUNK_LEN + 42] ^= 0xFF;
    std::fs::write(&ct_path, &tampered).unwrap();

    let mut s_bad = reader
        .open_range(ByteRange {
            offset: 65_436,
            len: 66_136,
        })
        .await
        .unwrap();
    let mut saw_err = false;
    while let Some(item) = s_bad.next().await {
        if item.is_err() {
            saw_err = true;
            break;
        }
    }
    assert!(
        saw_err,
        "tampered ciphertext must fail Poly1305 AEAD verification"
    );
}

#[tokio::test]
async fn concurrent_large_encrypted_uploads_bound_pipeline_slots_and_release_cleanly() {
    let _pipeline_guard = pipeline_slot_test_lock().lock().await;
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&enc_dir).unwrap();

    // 16 files × 1.25 MiB (> 1 MiB pipeline threshold) uploaded at `-t 16`!
    // Exercises simultaneous pipelined slots (first 6) AND zero-queue inline fallback (remaining 10).
    let file_len = 1_310_720usize;
    for idx in 0..16u8 {
        let data: Vec<u8> = (0..file_len)
            .map(|i| ((i.wrapping_mul(17).wrapping_add(idx as usize)) % 251) as u8)
            .collect();
        std::fs::write(src_dir.join(format!("blob_{idx:02}.bin")), &data).unwrap();
    }

    let local_src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let local_enc = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let keys = MasterKey::from_bytes([0x77u8; 32]).derive_subkeys();
    let pool = BufferPool::new(8 * 1024 * 1024, 256 * 1024).unwrap();
    let crypto = Arc::new(
        CryptoBackend::new(local_enc, CryptoConfig::new("crypt"), keys)
            .unwrap()
            .with_buffer_pool(pool.clone()),
    );

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let engine = TransferEngine::new(
        local_src,
        crypto.clone(),
        state_actor,
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg = EngineConfig::new("job-crypt-16", JobMode::Copy, "src", "crypt").with_transfers(16);
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 16);
    assert_eq!(
        encrypt_pipeline_slots().available_permits(),
        MAX_GLOBAL_ENCRYPT_PIPELINES
    );

    // Spot-check first and last files decrypt bit-exact.
    for idx in [0u8, 15u8] {
        let name = format!("blob_{idx:02}.bin");
        let expected = std::fs::read(src_dir.join(&name)).unwrap();
        let reader = match crypto
            .open_read(&BackendPath::from_rel(RelPath::parse(&name).unwrap()), None)
            .await
            .unwrap()
        {
            DataSource::RemoteRangeReadable(r) => r,
            _ => panic!("expected RemoteRangeReadable"),
        };
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
        assert_eq!(got, expected);
    }
}

#[tokio::test]
async fn crypto_single_get_full_decrypt_preserves_etag_and_disables_ordered_list() {
    use rship_core::source::RemoteRangeReadable;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct CountingOrderedMock {
        objects: StdMutex<HashMap<String, (Vec<u8>, String)>>,
        range_calls: Arc<AtomicUsize>,
        seen_etags: Arc<StdMutex<Vec<Option<String>>>>,
    }

    struct CountingReader {
        data: Vec<u8>,
        range_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RemoteRangeReadable for CountingReader {
        fn total_len(&self) -> u64 {
            self.data.len() as u64
        }
        async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
            self.range_calls.fetch_add(1, Ordering::SeqCst);
            let start = range.offset as usize;
            let end = (range.offset + range.len) as usize;
            let slice = Bytes::copy_from_slice(&self.data[start..end]);
            Ok(Box::pin(futures::stream::once(async move { Ok(slice) })))
        }
    }

    #[async_trait]
    impl StorageBackend for CountingOrderedMock {
        fn name(&self) -> &str {
            "ordered-mock"
        }
        fn kind(&self) -> &'static str {
            "s3"
        }
        fn endpoint_identity(&self) -> String {
            "s3://counting-mock".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hashes: vec![],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: true,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::Arbitrary,
                single_shot_max_bytes: 16 * 1024 * 1024,
                default_chunk_size: 5 * 1024 * 1024,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: true,
                supports_ordered_utf8_list: true,
                supports_conditional_write: false,
                supports_change_feed: false,
                supports_server_side_copy: false,
                default_write_qps: None,
            }
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            let g = self.objects.lock().unwrap();
            Ok(g.get(path.nfc_path.as_str()).map(|(d, etag)| Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::File,
                size: d.len() as u64,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: Some(etag.clone()),
                checksum: None,
            }))
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            let items: Vec<Result<Entry>> = self
                .objects
                .lock()
                .unwrap()
                .iter()
                .map(|(k, (d, etag))| {
                    Ok(Entry {
                        node_id: None,
                        parent_id: None,
                        raw_path: None,
                        nfc_path: RelPath::parse(k).unwrap(),
                        kind: EntryKind::File,
                        size: d.len() as u64,
                        mtime_ns: 1_700_000_000_000_000_000,
                        ctime_ns: None,
                        etag: Some(etag.clone()),
                        checksum: None,
                    })
                })
                .collect();
            Ok(Box::pin(futures::stream::iter(items)))
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
            let e = self.stat(path).await?.unwrap();
            self.open_read_entry(&e, path, range).await
        }
        async fn open_read_entry(
            &self,
            entry: &Entry,
            path: &BackendPath,
            _range: Option<ByteRange>,
        ) -> Result<DataSource> {
            self.seen_etags.lock().unwrap().push(entry.etag.clone());
            let data = self
                .objects
                .lock()
                .unwrap()
                .get(path.nfc_path.as_str())
                .unwrap()
                .0
                .clone();
            Ok(DataSource::RemoteRangeReadable(Arc::new(CountingReader {
                data,
                range_calls: self.range_calls.clone(),
            })))
        }
        async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(&c?);
            }
            let etag = "\"ct-etag-v1\"".to_string();
            self.objects.lock().unwrap().insert(
                init.dst_path.as_str().to_string(),
                (buf.clone(), etag.clone()),
            );
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: init.dst_path.clone(),
                kind: EntryKind::File,
                size: buf.len() as u64,
                mtime_ns: init.src_mtime_ns,
                ctime_ns: None,
                etag: Some(etag),
                checksum: None,
            })
        }
        async fn begin_upload(&self, _init: &UploadInit) -> Result<UploadSessionInit> {
            Err(Error::unsupported(
                "begin_upload unused in CountingOrderedMock",
            ))
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Err(Error::unsupported(
                "query_upload unused in CountingOrderedMock",
            ))
        }
        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            _chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            Err(Error::unsupported(
                "upload_chunk unused in CountingOrderedMock",
            ))
        }
        async fn finish_upload(
            &self,
            _op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            Err(Error::unsupported(
                "finish_upload unused in CountingOrderedMock",
            ))
        }
        async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    let range_calls = Arc::new(AtomicUsize::new(0));
    let seen_etags = Arc::new(StdMutex::new(Vec::new()));
    let inner = Arc::new(CountingOrderedMock {
        objects: StdMutex::new(HashMap::new()),
        range_calls: range_calls.clone(),
        seen_etags: seen_etags.clone(),
    });
    let keys = MasterKey::from_bytes([0x99u8; 32]).derive_subkeys();
    let crypto = Arc::new(CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys).unwrap());

    // 1. Ciphertext filename encryption breaks plaintext UTF-8 order -> MUST report false!
    assert!(!crypto.capabilities().supports_ordered_utf8_list);
    assert!(crypto.capabilities().supports_atomic_single_read);

    // 2. Upload a 260 KiB (> 4 OAE2 blocks) plaintext file, then decrypt-download via TransferEngine.
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    let payload: Vec<u8> = (0..(260 * 1024))
        .map(|i| ((i * 31 + 11) % 251) as u8)
        .collect();
    std::fs::write(src_dir.join("multi_block.bin"), &payload).unwrap();

    let local_src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let local_dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let state = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap();

    let up = TransferEngine::new(
        local_src,
        crypto.clone(),
        state.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let r_up = up
        .run(
            &EngineConfig::new("crypt-up", JobMode::Copy, "src", "crypt"),
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_up.is_success(), "{:?}", r_up.errors);

    // Download from `crypto` -> `local_dst` must perform ONE single full-object ciphertext GET
    // (1-GET fast path) and preserve `ct_entry.etag` on `open_read_entry`!
    let dn = TransferEngine::new(
        crypto,
        local_dst,
        state,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let r_dn = dn
        .run(
            &EngineConfig::new("crypt-dn", JobMode::Copy, "crypt", "dst"),
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_dn.is_success(), "{:?}", r_dn.errors);
    assert_eq!(
        std::fs::read(dst_dir.join("multi_block.bin")).unwrap(),
        payload
    );
    assert_eq!(
        range_calls.load(Ordering::SeqCst),
        1,
        "full decrypt download must use 1 single GET rather than per-64KiB range GETs"
    );
    assert_eq!(
        seen_etags.lock().unwrap().as_slice(),
        &[Some("\"ct-etag-v1\"".to_string())]
    );
}

#[tokio::test]
async fn rclone_crypt_filename_255b_boundary_and_exact_64kib_block_range_reads() {
    use crate::filename::{decrypt_segment, encrypt_segment};

    let keys = MasterKey::from_bytes([0x42u8; 32]).derive_subkeys();

    // 1. Filename length boundary: base32((16 SIV + len + 16 TAG)) = ceil((len + 32) * 8 / 5).
    // Maximum plaintext segment whose base32 ciphertext fits inside 255-byte POSIX/NTFS NAME_MAX is 127 bytes:
    // (127 + 32) * 8 / 5 = 254.4 -> 255 bytes! Verify every length near the boundary round-trips losslessly.
    for len in [1usize, 64, 126, 127, 128, 200] {
        let seg: String = (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        let enc = encrypt_segment(&keys, &seg).unwrap();
        if len <= 127 {
            assert!(
                enc.len() <= 255,
                "plaintext len {len} produced encrypted len {} > 255",
                enc.len()
            );
        }
        assert_eq!(decrypt_segment(&keys, &enc).unwrap(), seg);
    }

    // 2. Exact 64 KiB OAE2 block boundaries: 0, 1, 65535, 65536, 65537, 131072, 131073 bytes
    // + Range reads straddling exact 65535 / 65536 / 65537 offsets!
    let tmp = TempDir::new().unwrap();
    let inner = Arc::new(LocalBackend::new("local-crypt", tmp.path()).unwrap());
    let crypto = Arc::new(CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys).unwrap());

    for &size in &[0usize, 1, 65_535, 65_536, 65_537, 131_072, 131_073] {
        let name = format!("boundary_{size}.bin");
        let rel = RelPath::parse(&name).unwrap();
        let payload: Vec<u8> = (0..size).map(|i| ((i * 37 + 13) % 251) as u8).collect();
        let body = Box::pin(futures::stream::once({
            let p = payload.clone();
            async move { Ok(Bytes::from(p)) }
        }));
        let init = UploadInit {
            op_id: format!("op-{size}"),
            dst_path: rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: size as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 64 * 1024,
            precondition: DstPrecondition::Any,
            checksums: Vec::new(),
            src_etag: None,
        };
        let entry = crypto.put_single_shot(&init, body).await.unwrap();
        assert_eq!(
            entry.size, size as u64,
            "decrypted stat size mismatch for {size}"
        );

        // Full read
        let bp = BackendPath::from_rel(rel);
        let src = crypto.open_read(&bp, None).await.unwrap();
        let full_out = match src {
            DataSource::RemoteRangeReadable(r) => {
                let mut s = r
                    .open_range(ByteRange {
                        offset: 0,
                        len: size as u64,
                    })
                    .await
                    .unwrap();
                let mut out = Vec::new();
                while let Some(c) = s.next().await {
                    out.extend_from_slice(&c.unwrap());
                }
                out
            }
            DataSource::SequentialStream { mut stream, .. } => {
                let mut out = Vec::new();
                while let Some(c) = stream.next().await {
                    out.extend_from_slice(&c.unwrap());
                }
                out
            }
            DataSource::LocalSeekable { .. } => unreachable!(),
        };
        assert_eq!(full_out, payload, "full decrypt mismatch for size {size}");

        // Straddling block-boundary range reads for multi-block sizes
        if size >= 65_537 {
            let reader = match crypto.open_read(&bp, None).await.unwrap() {
                DataSource::RemoteRangeReadable(r) => r,
                _ => panic!("expected RemoteRangeReadable"),
            };
            for (off, len) in [
                (65_535usize, 1usize),
                (65_535, 2),
                (65_536, 1),
                (65_535, (size - 65_535).min(65_539)),
                (size - 1, 1),
            ] {
                let mut s = reader
                    .open_range(ByteRange {
                        offset: off as u64,
                        len: len as u64,
                    })
                    .await
                    .unwrap();
                let mut out = Vec::new();
                while let Some(c) = s.next().await {
                    out.extend_from_slice(&c.unwrap());
                }
                assert_eq!(
                    out,
                    payload[off..off + len],
                    "range [{off}..+{len}] mismatch on size {size}"
                );
            }
        }
    }
}
