use super::super::*;
use super::{
    assert_pool_clean, drain_byte_stream, pipeline_slot_test_lock,
    upload_test_blob_via_bounded_stream,
};
use crate::keys::MasterKey;
use rship_backends::local::LocalBackend;
use tempfile::TempDir;

#[tokio::test]
async fn tight_pool_1slab_full_decrypt_and_range_reader_no_deadlock() {
    use std::time::Duration;

    let tmp = TempDir::new().unwrap();
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&enc_dir).unwrap();

    // > 512 KiB payload (11 OAE2 blocks, ciphertext spans 3 x 256 KiB slabs).
    let payload: Vec<u8> = (0..700_137).map(|i| ((i * 29 + 17) % 251) as u8).collect();
    let keys = MasterKey::from_bytes([0x31u8; 32]).derive_subkeys();

    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let setup_pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();
    let setup_crypto = CryptoBackend::new(inner.clone(), CryptoConfig::new("crypt"), keys.clone())
        .unwrap()
        .with_buffer_pool(setup_pool.clone());
    let entry =
        upload_test_blob_via_bounded_stream(&setup_crypto, "big.bin", &payload, &setup_pool)
            .await
            .unwrap();
    assert_pool_clean(&setup_pool);

    // 1-slab tight BufferPool (256 KiB total, 256 KiB slab).
    let pool = BufferPool::new(256 * 1024, 256 * 1024).unwrap();
    let crypto = CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys)
        .unwrap()
        .with_buffer_pool(pool.clone());
    let bp = BackendPath::from_rel(RelPath::parse("big.bin").unwrap());

    // 1. open_full_decrypt_stream path (open_read_entry with full range 0..pt_len).
    let full_dec = tokio::time::timeout(Duration::from_secs(5), async {
        let ds = crypto
            .open_read_entry(
                &entry,
                &bp,
                Some(ByteRange {
                    offset: 0,
                    len: entry.size,
                }),
            )
            .await?;
        match ds {
            DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
            _ => panic!("expected SequentialStream from open_full_decrypt_stream"),
        }
    })
    .await
    .expect("open_full_decrypt_stream deadlocked under 1-slab BufferPool")
    .unwrap();
    assert_eq!(full_dec, payload);
    assert_pool_clean(&pool);

    // 2. CryptoRangeReader::open_range full-file read.
    let reader = match crypto.open_read(&bp, None).await.unwrap() {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let range_full = tokio::time::timeout(Duration::from_secs(5), async {
        let s = reader
            .open_range(ByteRange {
                offset: 0,
                len: payload.len() as u64,
            })
            .await?;
        drain_byte_stream(s).await
    })
    .await
    .expect("CryptoRangeReader::open_range (full) deadlocked under 1-slab BufferPool")
    .unwrap();
    assert_eq!(range_full, payload);
    assert_pool_clean(&pool);

    // 3. CryptoRangeReader::open_range partial unaligned & aligned multi-slab ranges.
    for (off, len) in [
        (73_123usize, 560_000usize),
        (65_536, 524_288),
        (1, payload.len() - 2),
        (payload.len() - 10_000, 10_000),
    ] {
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let s = reader
                .open_range(ByteRange {
                    offset: off as u64,
                    len: len as u64,
                })
                .await?;
            drain_byte_stream(s).await
        })
        .await
        .unwrap_or_else(|_| {
            panic!("CryptoRangeReader::open_range [{off}..+{len}] deadlocked under 1-slab pool")
        })
        .unwrap();
        assert_eq!(
            got,
            payload[off..off + len],
            "range [{off}..+{len}] mismatch"
        );
        assert_pool_clean(&pool);
    }
}

#[tokio::test]
async fn tight_pool_2slab_concurrent_decrypt_streams_no_deadlock() {
    use std::time::Duration;

    let tmp = TempDir::new().unwrap();
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&enc_dir).unwrap();

    let payload_a: Vec<u8> = (0..680_111).map(|i| ((i * 13 + 5) % 251) as u8).collect();
    let payload_b: Vec<u8> = (0..720_222).map(|i| ((i * 23 + 11) % 251) as u8).collect();
    let keys = MasterKey::from_bytes([0x32u8; 32]).derive_subkeys();

    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let setup_pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();
    let setup_crypto = CryptoBackend::new(inner.clone(), CryptoConfig::new("crypt"), keys.clone())
        .unwrap()
        .with_buffer_pool(setup_pool.clone());
    let entry_a =
        upload_test_blob_via_bounded_stream(&setup_crypto, "a.bin", &payload_a, &setup_pool)
            .await
            .unwrap();
    let entry_b =
        upload_test_blob_via_bounded_stream(&setup_crypto, "b.bin", &payload_b, &setup_pool)
            .await
            .unwrap();
    assert_pool_clean(&setup_pool);

    // 2-slab tight BufferPool shared across 2 concurrent decrypt streams.
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let crypto = CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys)
        .unwrap()
        .with_buffer_pool(pool.clone());
    let bp_a = BackendPath::from_rel(RelPath::parse("a.bin").unwrap());
    let bp_b = BackendPath::from_rel(RelPath::parse("b.bin").unwrap());

    // 1. Two concurrent open_full_decrypt_stream consumers.
    let (dec_a, dec_b) = tokio::time::timeout(Duration::from_secs(5), async {
        let f_a = async {
            let ds = crypto
                .open_read_entry(
                    &entry_a,
                    &bp_a,
                    Some(ByteRange {
                        offset: 0,
                        len: entry_a.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        };
        let f_b = async {
            let ds = crypto
                .open_read_entry(
                    &entry_b,
                    &bp_b,
                    Some(ByteRange {
                        offset: 0,
                        len: entry_b.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        };
        tokio::try_join!(f_a, f_b)
    })
    .await
    .expect("2 concurrent open_full_decrypt_stream calls deadlocked under 2-slab BufferPool")
    .unwrap();
    assert_eq!(dec_a, payload_a);
    assert_eq!(dec_b, payload_b);
    assert_pool_clean(&pool);

    // 2. Two concurrent CryptoRangeReader::open_range calls (full + partial unaligned).
    let reader_a = match crypto.open_read(&bp_a, None).await.unwrap() {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let reader_b = match crypto.open_read(&bp_b, None).await.unwrap() {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let (range_a, range_b) = tokio::time::timeout(Duration::from_secs(5), async {
        let f_a = async {
            let s = reader_a
                .open_range(ByteRange {
                    offset: 0,
                    len: payload_a.len() as u64,
                })
                .await?;
            drain_byte_stream(s).await
        };
        let f_b = async {
            let s = reader_b
                .open_range(ByteRange {
                    offset: 71_234,
                    len: 590_000,
                })
                .await?;
            drain_byte_stream(s).await
        };
        tokio::try_join!(f_a, f_b)
    })
    .await
    .expect("2 concurrent CryptoRangeReader::open_range calls deadlocked under 2-slab BufferPool")
    .unwrap();
    assert_eq!(range_a, payload_a);
    assert_eq!(range_b, payload_b[71_234..71_234 + 590_000]);
    assert_pool_clean(&pool);

    // 3. Mixed concurrent open_full_decrypt_stream + CryptoRangeReader::open_range partial unaligned.
    let (mixed_a, mixed_b) = tokio::time::timeout(Duration::from_secs(5), async {
        let f_a = async {
            let ds = crypto
                .open_read_entry(
                    &entry_a,
                    &bp_a,
                    Some(ByteRange {
                        offset: 0,
                        len: entry_a.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        };
        let f_b = async {
            let s = reader_b
                .open_range(ByteRange {
                    offset: 65_535,
                    len: 590_001,
                })
                .await?;
            drain_byte_stream(s).await
        };
        tokio::try_join!(f_a, f_b)
    })
    .await
    .expect("mixed concurrent decrypt streams deadlocked under 2-slab BufferPool")
    .unwrap();
    assert_eq!(mixed_a, payload_a);
    assert_eq!(mixed_b, payload_b[65_535..65_535 + 590_001]);
    assert_pool_clean(&pool);

    // 4. Mid-stream cancellation/drop must immediately release held slabs.
    {
        let mut s = reader_a
            .open_range(ByteRange {
                offset: 0,
                len: payload_a.len() as u64,
            })
            .await
            .unwrap();
        let first = s.next().await.unwrap().unwrap();
        assert_eq!(first.len(), PLAINTEXT_CHUNK_LEN);
    }
    assert_pool_clean(&pool);
}

#[tokio::test]
async fn tight_pool_1slab_and_2slab_single_shot_encrypt_no_deadlock() {
    use std::time::Duration;

    let _pipeline_guard = pipeline_slot_test_lock().lock().await;
    let tmp = TempDir::new().unwrap();
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&enc_dir).unwrap();

    // Inline encryptor (< 1 MiB, multi-slab > 512 KiB) and pipelined encryptor (>= 1 MiB).
    let inline_payload: Vec<u8> = (0..615_137).map(|i| ((i * 37 + 3) % 251) as u8).collect();
    let pipelined_payload_a: Vec<u8> = (0..1_150_321).map(|i| ((i * 41 + 7) % 251) as u8).collect();
    let pipelined_payload_b: Vec<u8> = (0..1_120_777)
        .map(|i| ((i * 43 + 13) % 251) as u8)
        .collect();

    let keys = MasterKey::from_bytes([0x33u8; 32]).derive_subkeys();
    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());

    // 1-slab pool: single-shot inline AND pipelined uploads + decrypt verification.
    let pool1 = BufferPool::new(256 * 1024, 256 * 1024).unwrap();
    let crypto1 = CryptoBackend::new(inner.clone(), CryptoConfig::new("crypt"), keys.clone())
        .unwrap()
        .with_buffer_pool(pool1.clone());

    for (name, payload) in [
        ("inline_1slab.bin", &inline_payload),
        ("pipe_1slab.bin", &pipelined_payload_a),
    ] {
        let entry = tokio::time::timeout(
            Duration::from_secs(5),
            upload_test_blob_via_bounded_stream(&crypto1, name, payload, &pool1),
        )
        .await
        .unwrap_or_else(|_| panic!("put_single_shot `{name}` deadlocked under 1-slab BufferPool"))
        .unwrap();
        assert_eq!(entry.size, payload.len() as u64);
        assert_pool_clean(&pool1);

        let bp = BackendPath::from_rel(RelPath::parse(name).unwrap());
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let ds = crypto1
                .open_read_entry(
                    &entry,
                    &bp,
                    Some(ByteRange {
                        offset: 0,
                        len: entry.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        })
        .await
        .unwrap_or_else(|_| panic!("decrypt `{name}` deadlocked under 1-slab BufferPool"))
        .unwrap();
        assert_eq!(got, *payload);
        assert_pool_clean(&pool1);
    }

    // 2-slab pool: 2 concurrent put_single_shot uploads (both pipelined >= 1 MiB).
    let pool2 = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let crypto2 = CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys)
        .unwrap()
        .with_buffer_pool(pool2.clone());

    let (e1, e2) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            upload_test_blob_via_bounded_stream(
                &crypto2,
                "pipe_2slab_a.bin",
                &pipelined_payload_a,
                &pool2,
            ),
            upload_test_blob_via_bounded_stream(
                &crypto2,
                "pipe_2slab_b.bin",
                &pipelined_payload_b,
                &pool2,
            ),
        )
    })
    .await
    .expect("2 concurrent put_single_shot uploads deadlocked under 2-slab BufferPool")
    .unwrap();
    assert_eq!(e1.size, pipelined_payload_a.len() as u64);
    assert_eq!(e2.size, pipelined_payload_b.len() as u64);
    assert_pool_clean(&pool2);

    // Concurrent decrypt verification under the same 2-slab pool.
    let bp1 = BackendPath::from_rel(RelPath::parse("pipe_2slab_a.bin").unwrap());
    let bp2 = BackendPath::from_rel(RelPath::parse("pipe_2slab_b.bin").unwrap());
    let (dec1, dec2) = tokio::time::timeout(Duration::from_secs(5), async {
        let f1 = async {
            let ds = crypto2
                .open_read_entry(
                    &e1,
                    &bp1,
                    Some(ByteRange {
                        offset: 0,
                        len: e1.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        };
        let f2 = async {
            let ds = crypto2
                .open_read_entry(
                    &e2,
                    &bp2,
                    Some(ByteRange {
                        offset: 0,
                        len: e2.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        };
        tokio::try_join!(f1, f2)
    })
    .await
    .expect("2 concurrent decrypts deadlocked under 2-slab BufferPool")
    .unwrap();
    assert_eq!(dec1, pipelined_payload_a);
    assert_eq!(dec2, pipelined_payload_b);
    assert_pool_clean(&pool2);
    assert_eq!(
        encrypt_pipeline_slots().available_permits(),
        MAX_GLOBAL_ENCRYPT_PIPELINES
    );
}

#[tokio::test]
async fn tight_pool_1slab_and_2slab_parallel_multipart_encrypt_decrypt_no_deadlock() {
    use rship_core::source::{MemorySource, SeekableSource, bounded_range_stream};
    use rship_core::state::{OperationState, SourceVersion};
    use std::time::Duration;

    let _pipeline_guard = pipeline_slot_test_lock().lock().await;

    async fn run_multipart_case(
        crypto: &CryptoBackend,
        pool: &BufferPool,
        name: &str,
        payload: &[u8],
        part_size: u64,
        parallel: bool,
    ) -> Entry {
        let rel = RelPath::parse(name).unwrap();
        let total_size = payload.len() as u64;
        let op_id = format!("mp-{name}");
        let init = UploadInit {
            op_id: op_id.clone(),
            dst_path: rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: part_size,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        };
        let session = crypto.begin_upload(&init).await.unwrap();
        let op = OperationRecord {
            op_id,
            session_key: format!("key-{name}"),
            job_id: "tight-pool-mp".into(),
            src_endpoint: "mem://src".into(),
            dst_endpoint: crypto.endpoint_identity(),
            src_raw_path: name.into(),
            dst_raw_path: rel.as_str().into(),
            dst_nfc_path: rel,
            src_version: SourceVersion {
                size: total_size,
                mtime_ns: init.src_mtime_ns,
                ctime_ns: None,
                etag: None,
                node_id: None,
            },
            dst_precondition: DstPrecondition::Any,
            existing_dst_node_id: None,
            remote_op_id: session.remote_op_id,
            backend_kind: crypto.kind().into(),
            session_token: Some(session.session_token),
            backend_meta: session.backend_meta,
            planned_chunk_size: part_size,
            confirmed_offset: 0,
            state: OperationState::Active,
            created_at: 0,
            updated_at: 0,
            expires_at: session.expires_at_unix_secs,
        };

        let src: Arc<dyn SeekableSource> = Arc::new(MemorySource::new(payload.to_vec()));
        let mut ranges = Vec::new();
        let mut off = 0u64;
        let mut pn = 1u32;
        while off < total_size {
            let len = part_size.min(total_size - off);
            ranges.push((pn, off, len));
            off += len;
            pn += 1;
        }
        assert!(ranges.len() >= 3, "test requires >= 3 multipart chunks");

        let mut completed = Vec::with_capacity(ranges.len());
        if parallel {
            // Upload part 1 and part 2 concurrently under the 2-slab pool, then remaining parts.
            let (pn1, off1, len1) = ranges[0];
            let (pn2, off2, len2) = ranges[1];
            let (ack1, ack2) = tokio::try_join!(
                crypto.upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn1,
                        off1,
                        len1,
                        total_size,
                        bounded_range_stream(src.clone(), off1, len1, pool.clone()),
                    ),
                ),
                crypto.upload_chunk(
                    &op,
                    ChunkUpload::new(
                        pn2,
                        off2,
                        len2,
                        total_size,
                        bounded_range_stream(src.clone(), off2, len2, pool.clone()),
                    ),
                ),
            )
            .unwrap();
            completed.push(CompletedPart {
                part_number: pn1,
                offset: off1,
                length: len1,
                etag: ack1.etag.unwrap_or_default(),
                checksum: ack1.checksum,
            });
            completed.push(CompletedPart {
                part_number: pn2,
                offset: off2,
                length: len2,
                etag: ack2.etag.unwrap_or_default(),
                checksum: ack2.checksum,
            });
            for &(p, o, l) in &ranges[2..] {
                let ack = crypto
                    .upload_chunk(
                        &op,
                        ChunkUpload::new(
                            p,
                            o,
                            l,
                            total_size,
                            bounded_range_stream(src.clone(), o, l, pool.clone()),
                        ),
                    )
                    .await
                    .unwrap();
                completed.push(CompletedPart {
                    part_number: p,
                    offset: o,
                    length: l,
                    etag: ack.etag.unwrap_or_default(),
                    checksum: ack.checksum,
                });
            }
        } else {
            for &(p, o, l) in &ranges {
                let ack = crypto
                    .upload_chunk(
                        &op,
                        ChunkUpload::new(
                            p,
                            o,
                            l,
                            total_size,
                            bounded_range_stream(src.clone(), o, l, pool.clone()),
                        ),
                    )
                    .await
                    .unwrap();
                completed.push(CompletedPart {
                    part_number: p,
                    offset: o,
                    length: l,
                    etag: ack.etag.unwrap_or_default(),
                    checksum: ack.checksum,
                });
            }
        }

        crypto.finish_upload(&op, &completed).await.unwrap()
    }

    let tmp = TempDir::new().unwrap();
    let enc_dir = tmp.path().join("enc");
    std::fs::create_dir_all(&enc_dir).unwrap();
    let inner = Arc::new(LocalBackend::new("enc", &enc_dir).unwrap());
    let keys = MasterKey::from_bytes([0x34u8; 32]).derive_subkeys();

    // 2.2 MiB payload split into 1 MiB parts (exercises pipelined encryptor) + trailing partial part.
    let payload_pipe: Vec<u8> = (0..2_220_608)
        .map(|i| ((i * 19 + 23) % 251) as u8)
        .collect();
    // 1.6 MiB payload split into 640 KiB parts (exercises inline multi-slab encryptor).
    let payload_inline: Vec<u8> = (0..1_650_123)
        .map(|i| ((i * 29 + 31) % 251) as u8)
        .collect();

    // 1. 1-slab tight BufferPool: sequential multipart upload + decrypt (both inline & pipelined parts).
    let pool1 = BufferPool::new(256 * 1024, 256 * 1024).unwrap();
    let crypto1 = CryptoBackend::new(inner.clone(), CryptoConfig::new("crypt"), keys.clone())
        .unwrap()
        .with_buffer_pool(pool1.clone());

    for (name, payload, part_sz) in [
        ("mp_1slab_inline.bin", &payload_inline, 640 * 1024u64),
        ("mp_1slab_pipe.bin", &payload_pipe, 1024 * 1024u64),
    ] {
        let entry = tokio::time::timeout(
            Duration::from_secs(5),
            run_multipart_case(&crypto1, &pool1, name, payload, part_sz, false),
        )
        .await
        .unwrap_or_else(|_| panic!("multipart upload `{name}` deadlocked under 1-slab BufferPool"));
        assert_eq!(entry.size, payload.len() as u64);
        assert_pool_clean(&pool1);

        let bp = BackendPath::from_rel(RelPath::parse(name).unwrap());
        let dec = tokio::time::timeout(Duration::from_secs(5), async {
            let ds = crypto1
                .open_read_entry(
                    &entry,
                    &bp,
                    Some(ByteRange {
                        offset: 0,
                        len: entry.size,
                    }),
                )
                .await?;
            match ds {
                DataSource::SequentialStream { stream, .. } => drain_byte_stream(stream).await,
                _ => panic!("expected SequentialStream"),
            }
        })
        .await
        .unwrap_or_else(|_| panic!("multipart decrypt `{name}` deadlocked under 1-slab BufferPool"))
        .unwrap();
        assert_eq!(dec, *payload);
        assert_pool_clean(&pool1);
    }

    // 2. 2-slab tight BufferPool: parallel multipart upload + concurrent range decrypt.
    let pool2 = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let crypto2 = CryptoBackend::new(inner, CryptoConfig::new("crypt"), keys)
        .unwrap()
        .with_buffer_pool(pool2.clone());

    for (name, payload, part_sz) in [
        ("mp_2slab_inline.bin", &payload_inline, 640 * 1024u64),
        ("mp_2slab_pipe.bin", &payload_pipe, 1024 * 1024u64),
    ] {
        let entry = tokio::time::timeout(
            Duration::from_secs(5),
            run_multipart_case(&crypto2, &pool2, name, payload, part_sz, true),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("parallel multipart upload `{name}` deadlocked under 2-slab BufferPool")
        });
        assert_eq!(entry.size, payload.len() as u64);
        assert_pool_clean(&pool2);

        let bp = BackendPath::from_rel(RelPath::parse(name).unwrap());
        let reader = match crypto2.open_read(&bp, None).await.unwrap() {
            DataSource::RemoteRangeReadable(r) => r,
            _ => panic!("expected RemoteRangeReadable"),
        };
        let mid = (payload.len() / 2) + 123;
        let (left, right) = tokio::time::timeout(Duration::from_secs(5), async {
            let f_left = async {
                let s = reader
                    .open_range(ByteRange {
                        offset: 0,
                        len: mid as u64,
                    })
                    .await?;
                drain_byte_stream(s).await
            };
            let f_right = async {
                let s = reader
                    .open_range(ByteRange {
                        offset: mid as u64,
                        len: (payload.len() - mid) as u64,
                    })
                    .await?;
                drain_byte_stream(s).await
            };
            tokio::try_join!(f_left, f_right)
        })
        .await
        .unwrap_or_else(|_| {
            panic!("concurrent range decrypt `{name}` deadlocked under 2-slab BufferPool")
        })
        .unwrap();
        assert_eq!(left, payload[..mid]);
        assert_eq!(right, payload[mid..]);
        assert_pool_clean(&pool2);
    }
    assert_eq!(
        encrypt_pipeline_slots().available_permits(),
        MAX_GLOBAL_ENCRYPT_PIPELINES
    );
}
