use super::super::*;
use super::{assert_pool_clean, drain_byte_stream};
use crate::keys::MasterKey;
use crate::stream::StreamEncryptor;

/// Fast in-memory `StorageBackend` + `RemoteRangeReadable` that yields requested byte
/// ranges split across arbitrary seeded chunk boundaries (including empty chunks and
/// tiny 1-byte fragments) to stress `open_full_decrypt_stream` and `CryptoRangeReader`.
struct ChunkedMemoryBackend {
    objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    split_seed: u64,
}

struct ChunkedMemoryReader {
    data: Vec<u8>,
    split_seed: u64,
}

#[async_trait]
impl rship_core::source::RemoteRangeReadable for ChunkedMemoryReader {
    fn total_len(&self) -> u64 {
        self.data.len() as u64
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        use crate::prop_test::{mix_seed, random_split_chunks, rng_for};
        let end = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("range overflow"))?;
        let avail_start = (range.offset as usize).min(self.data.len());
        let avail_end = (end as usize).min(self.data.len());
        let slice = &self.data[avail_start..avail_end];
        let mut rng = rng_for(mix_seed(
            self.split_seed ^ range.offset.rotate_left(13),
            range.len as usize,
        ));
        let chunks = random_split_chunks(slice, &mut rng);
        Ok(Box::pin(futures::stream::iter(chunks.into_iter().map(Ok))))
    }
}

#[async_trait]
impl StorageBackend for ChunkedMemoryBackend {
    fn name(&self) -> &str {
        "chunked-mem"
    }
    fn kind(&self) -> &'static str {
        "mem"
    }
    fn endpoint_identity(&self) -> String {
        "mem://chunked-prop".into()
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: std::time::Duration::from_secs(1),
            can_set_mtime: false,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: 16 * 1024 * 1024,
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
    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let map = self.objects.lock().unwrap();
        Ok(map.get(path.nfc_path.as_str()).map(|d| Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: path.nfc_path.clone(),
            kind: EntryKind::File,
            size: d.len() as u64,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: Some("\"mem-etag\"".into()),
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
    async fn open_read(&self, path: &BackendPath, _range: Option<ByteRange>) -> Result<DataSource> {
        let data = self
            .objects
            .lock()
            .unwrap()
            .get(path.nfc_path.as_str())
            .cloned()
            .ok_or_else(|| Error::not_found("missing object"))?;
        Ok(DataSource::RemoteRangeReadable(Arc::new(
            ChunkedMemoryReader {
                data,
                split_seed: self.split_seed,
            },
        )))
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
            etag: Some("\"mem-etag\"".into()),
            checksum: None,
        })
    }
    async fn begin_upload(&self, _init: &UploadInit) -> Result<UploadSessionInit> {
        Err(Error::unsupported("unused in ChunkedMemoryBackend"))
    }
    async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
        Err(Error::unsupported("unused in ChunkedMemoryBackend"))
    }
    async fn upload_chunk(&self, _op: &OperationRecord, _chunk: ChunkUpload) -> Result<ChunkAck> {
        Err(Error::unsupported("unused in ChunkedMemoryBackend"))
    }
    async fn finish_upload(
        &self,
        _op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        Err(Error::unsupported("unused in ChunkedMemoryBackend"))
    }
    async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
        Ok(())
    }
    async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
        Ok(ReconcileOutcome::NotCommitted)
    }
}

fn sample_layer_pt_len(case_idx: usize, rng: &mut rand::rngs::StdRng) -> usize {
    use rand::RngExt;
    const BOUNDARIES: &[usize] = &[
        0,
        1,
        15,
        16,
        65_535,
        65_536,
        65_537,
        2 * PLAINTEXT_CHUNK_LEN - 1,
        2 * PLAINTEXT_CHUNK_LEN,
        2 * PLAINTEXT_CHUNK_LEN + 1,
        3 * PLAINTEXT_CHUNK_LEN - 1,
        3 * PLAINTEXT_CHUNK_LEN,
        3 * PLAINTEXT_CHUNK_LEN + 1,
        200_000,
    ];
    if case_idx < BOUNDARIES.len() {
        return BOUNDARIES[case_idx];
    }
    match rng.random_range(0u8..5) {
        0 => rng.random_range(0..=64),
        1 => rng.random_range((PLAINTEXT_CHUNK_LEN - 32)..=(PLAINTEXT_CHUNK_LEN + 32)),
        2 => rng.random_range((2 * PLAINTEXT_CHUNK_LEN - 32)..=(2 * PLAINTEXT_CHUNK_LEN + 32)),
        3 => rng.random_range(1..=3) * PLAINTEXT_CHUNK_LEN,
        _ => rng.random_range(0..=200_000),
    }
}

#[tokio::test]
async fn prop_stream_encrypt_full_decrypt_and_range_reader_roundtrip() {
    use crate::prop_test::{SeedGuard, random_split_chunks, rng_for, seeds_for};
    use rand::{Rng, RngExt};
    use rship_core::source::RemoteRangeReadable;

    const MAX_BLOCKS_CHOICES: &[usize] = &[1, 2, 4, 8];
    const SLAB_CHOICES: &[usize] = &[64 * 1024, 100 * 1024, 256 * 1024];

    let seeds = seeds_for(0x5253_4849_4C59_0001, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "stream_encrypt_full_decrypt_and_range_reader_roundtrip",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_layer_pt_len(case_idx, &mut rng);

        let mut master_raw = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut master_raw);
        rng.fill_bytes(&mut nonce_prefix);
        let keys = Arc::new(MasterKey::from_bytes(master_raw).derive_subkeys());
        let header = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);

        // 1. Encrypt via StreamEncryptor with arbitrary split pattern & random max_blocks.
        let in_chunks = random_split_chunks(&plaintext, &mut rng);
        let max_blocks = MAX_BLOCKS_CHOICES[rng.random_range(0..MAX_BLOCKS_CHOICES.len())];
        let in_stream: ByteStream = Box::pin(futures::stream::iter(in_chunks.into_iter().map(Ok)));
        let mut enc = StreamEncryptor::with_coalesced_blocks(
            in_stream,
            &keys.data_key,
            header,
            0,
            pt_len as u64,
            true,
            true,
            max_blocks,
        );
        let mut ct = Vec::new();
        while let Some(item) = enc.next().await {
            ct.extend_from_slice(&item.unwrap());
        }
        let expected_ct_len = ciphertext_size(pt_len as u64).unwrap();
        assert_eq!(
            ct.len() as u64,
            expected_ct_len,
            "ciphertext_size mismatch (pt_len={pt_len}, max_blocks={max_blocks}, seed={seed:#018x})"
        );

        // Store ciphertext in ChunkedMemoryBackend with seeded downstream chunk fragmentation.
        let rel = RelPath::parse("blob.enc").unwrap();
        let bp = BackendPath::from_rel(rel.clone());
        let objects = Arc::new(StdMutex::new(HashMap::from([(
            rel.as_str().to_string(),
            ct.clone(),
        )])));
        let inner: Arc<dyn StorageBackend> = Arc::new(ChunkedMemoryBackend {
            objects,
            split_seed: rng.random(),
        });
        let ct_entry = Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: rel,
            kind: EntryKind::File,
            size: expected_ct_len,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: Some("\"mem-etag\"".into()),
            checksum: None,
        };
        let slab = SLAB_CHOICES[rng.random_range(0..SLAB_CHOICES.len())];
        let pool = BufferPool::new(slab * 2, slab).unwrap();

        // 2. Full decrypt via `open_full_decrypt_stream` must match plaintext bit-for-bit.
        let full_stream = reader::open_full_decrypt_stream(
            &inner,
            &ct_entry,
            &bp,
            pt_len as u64,
            expected_ct_len,
            keys.data_key,
            &pool,
        )
        .await
        .unwrap();
        let full_pt = drain_byte_stream(full_stream).await.unwrap_or_else(|e| {
            panic!("open_full_decrypt_stream failed (pt_len={pt_len}, seed={seed:#018x}): {e}")
        });
        assert_eq!(
            full_pt, plaintext,
            "open_full_decrypt_stream mismatch (pt_len={pt_len}, seed={seed:#018x})"
        );
        assert_pool_clean(&pool);

        // 3. Random unaligned sub-range reads via `CryptoRangeReader::open_range`.
        let range_reader = CryptoRangeReader {
            inner: inner.clone(),
            enc_path: bp.clone(),
            ct_entry: Some(ct_entry),
            ct_len: expected_ct_len,
            pt_len: pt_len as u64,
            keys: keys.clone(),
            header: OnceCell::new(),
            pool: pool.clone(),
        };
        assert_eq!(range_reader.total_len(), pt_len as u64);

        let mut test_ranges: Vec<(usize, usize)> = vec![(0, 0), (0, pt_len)];
        if pt_len > 0 {
            test_ranges.push((0, 1));
            test_ranges.push((pt_len - 1, 1));
            if pt_len > PLAINTEXT_CHUNK_LEN {
                test_ranges.push((PLAINTEXT_CHUNK_LEN - 1, 2));
                test_ranges.push((PLAINTEXT_CHUNK_LEN, 1));
            }
            if pt_len > 2 * PLAINTEXT_CHUNK_LEN {
                test_ranges.push((2 * PLAINTEXT_CHUNK_LEN - 1, 2));
            }
            for _ in 0..6 {
                let offset = rng.random_range(0..=pt_len);
                let max_len = pt_len - offset;
                let len = if max_len == 0 {
                    0
                } else {
                    rng.random_range(0..=max_len)
                };
                test_ranges.push((offset, len));
            }
        }

        for (offset, len) in test_ranges {
            let s = range_reader
                .open_range(ByteRange {
                    offset: offset as u64,
                    len: len as u64,
                })
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "open_range([{offset}..+{len}]) failed (pt_len={pt_len}, seed={seed:#018x}): {e}"
                    )
                });
            let got = drain_byte_stream(s).await.unwrap_or_else(|e| {
                panic!(
                    "draining range [{offset}..+{len}] failed (pt_len={pt_len}, seed={seed:#018x}): {e}"
                )
            });
            assert_eq!(
                got,
                &plaintext[offset..offset + len],
                "range [{offset}..+{len}] mismatch (pt_len={pt_len}, seed={seed:#018x})"
            );
            assert_pool_clean(&pool);
        }

        // Out-of-bounds range must return Err cleanly.
        assert!(
            range_reader
                .open_range(ByteRange {
                    offset: pt_len as u64,
                    len: 1,
                })
                .await
                .is_err(),
            "out-of-bounds range accepted (pt_len={pt_len}, seed={seed:#018x})"
        );
        assert_pool_clean(&pool);
    }
}

#[tokio::test]
async fn prop_layer_range_and_full_decrypt_reject_tampered_ciphertext() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use rand::{Rng, RngExt};
    use rship_core::source::RemoteRangeReadable;

    let seeds = seeds_for(0x5253_4849_4C59_0002, 128);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "layer_range_and_full_decrypt_reject_tampered_ciphertext",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_layer_pt_len(case_idx, &mut rng);

        let mut master_raw = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut master_raw);
        rng.fill_bytes(&mut nonce_prefix);
        let keys = Arc::new(MasterKey::from_bytes(master_raw).derive_subkeys());
        let header = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);
        let in_stream: ByteStream = if plaintext.is_empty() {
            Box::pin(futures::stream::empty())
        } else {
            Box::pin(futures::stream::once({
                let p = plaintext.clone();
                async move { Ok(Bytes::from(p)) }
            }))
        };
        let mut enc = StreamEncryptor::with_coalesced_blocks(
            in_stream,
            &keys.data_key,
            header,
            0,
            pt_len as u64,
            true,
            true,
            4,
        );
        let mut ct = Vec::new();
        while let Some(item) = enc.next().await {
            ct.extend_from_slice(&item.unwrap());
        }
        let ct_len = ct.len() as u64;
        let rel = RelPath::parse("tamper.enc").unwrap();
        let bp = BackendPath::from_rel(rel.clone());
        let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

        // 1. Tamper 1 random bit anywhere in header, nonce, body, or tag.
        let flip_pos = rng.random_range(0..ct.len());
        let flip_bit = rng.random_range(0u8..8);
        let mut bad_ct = ct.clone();
        bad_ct[flip_pos] ^= 1u8 << flip_bit;

        let objects = Arc::new(StdMutex::new(HashMap::from([(
            rel.as_str().to_string(),
            bad_ct,
        )])));
        let inner: Arc<dyn StorageBackend> = Arc::new(ChunkedMemoryBackend {
            objects,
            split_seed: rng.random(),
        });
        let ct_entry = Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: rel.clone(),
            kind: EntryKind::File,
            size: ct_len,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: Some("\"mem-etag\"".into()),
            checksum: None,
        };

        let full_res = async {
            let s = reader::open_full_decrypt_stream(
                &inner,
                &ct_entry,
                &bp,
                pt_len as u64,
                ct_len,
                keys.data_key,
                &pool,
            )
            .await?;
            drain_byte_stream(s).await
        }
        .await;
        assert!(
            full_res.is_err(),
            "open_full_decrypt_stream accepted bit flip at pos={flip_pos}/{} (pt_len={pt_len}, seed={seed:#018x})",
            ct.len()
        );
        assert_pool_clean(&pool);

        let range_reader = CryptoRangeReader {
            inner: inner.clone(),
            enc_path: bp.clone(),
            ct_entry: Some(ct_entry.clone()),
            ct_len,
            pt_len: pt_len as u64,
            keys: keys.clone(),
            header: OnceCell::new(),
            pool: pool.clone(),
        };
        let (range_off, range_len) = if pt_len == 0 || flip_pos < HEADER_LEN {
            (0usize, pt_len.min(1))
        } else {
            let chunk_idx = (flip_pos - HEADER_LEN) / CIPHERTEXT_CHUNK_LEN;
            let off = (chunk_idx * PLAINTEXT_CHUNK_LEN).min(pt_len - 1);
            (off, 1usize)
        };
        let range_res = async {
            let s = range_reader
                .open_range(ByteRange {
                    offset: range_off as u64,
                    len: range_len as u64,
                })
                .await?;
            drain_byte_stream(s).await
        }
        .await;
        assert!(
            range_res.is_err(),
            "CryptoRangeReader accepted bit flip at pos={flip_pos}/{} (pt_len={pt_len}, range=[{range_off}..+{range_len}], seed={seed:#018x})",
            ct.len()
        );
        assert_pool_clean(&pool);

        // 2. Truncated underlying ciphertext stream must be rejected by both readers.
        let cut = rng.random_range(0..ct.len());
        let trunc_objects = Arc::new(StdMutex::new(HashMap::from([(
            rel.as_str().to_string(),
            ct[..cut].to_vec(),
        )])));
        let trunc_inner: Arc<dyn StorageBackend> = Arc::new(ChunkedMemoryBackend {
            objects: trunc_objects,
            split_seed: rng.random(),
        });
        let trunc_full = async {
            let s = reader::open_full_decrypt_stream(
                &trunc_inner,
                &ct_entry,
                &bp,
                pt_len as u64,
                ct_len,
                keys.data_key,
                &pool,
            )
            .await?;
            drain_byte_stream(s).await
        }
        .await;
        assert!(
            trunc_full.is_err(),
            "open_full_decrypt_stream accepted truncated stream {cut}/{} (pt_len={pt_len}, seed={seed:#018x})",
            ct.len()
        );
        assert_pool_clean(&pool);

        let trunc_reader = CryptoRangeReader {
            inner: trunc_inner,
            enc_path: bp.clone(),
            ct_entry: Some(ct_entry),
            ct_len,
            pt_len: pt_len as u64,
            keys: keys.clone(),
            header: OnceCell::new(),
            pool: pool.clone(),
        };
        let trunc_range = async {
            let s = trunc_reader
                .open_range(ByteRange {
                    offset: 0,
                    len: pt_len as u64,
                })
                .await?;
            drain_byte_stream(s).await
        }
        .await;
        assert!(
            trunc_range.is_err(),
            "CryptoRangeReader accepted truncated stream {cut}/{} (pt_len={pt_len}, seed={seed:#018x})",
            ct.len()
        );
        assert_pool_clean(&pool);
    }
}
