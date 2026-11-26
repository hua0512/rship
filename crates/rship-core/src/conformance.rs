//! Reusable rclone-inspired backend conformance & corner-case test suite.
//!
//! Every `StorageBackend` implementation (`ChaosBackend`, `LocalBackend`, and
//! future M2 `GdriveBackend` & M3 `S3Backend`) should invoke
//! [`run_backend_conformance`] in its test suite to verify uniform protocol
//! compliance across all corner cases.

use bytes::Bytes;
use futures::StreamExt;
use std::sync::Arc;

use crate::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit};
use crate::buffer::BufferPool;
use crate::clock::Clock;
use crate::error::Error;
use crate::path::RelPath;
use crate::source::{ByteStream, DataSource, MemorySource, bounded_range_stream};
use crate::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use crate::types::{ByteRange, HashKind};

/// Run the full backend conformance matrix against a fresh empty `backend`.
pub async fn run_backend_conformance(backend: Arc<dyn StorageBackend>, clock: Arc<dyn Clock>) {
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).expect("pool");

    test_list_not_found_and_empty(&backend).await;
    test_delete_not_found_idempotent(&backend).await;
    test_mkdir_nested_and_idempotent(&backend).await;
    test_put_zero_length(&backend, &clock).await;
    test_overwrite_shorter_and_longer(&backend, &clock, &pool).await;
    test_put_short_eof_preserves_existing(&backend, &clock).await;
    test_put_stream_error_preserves_existing(&backend, &clock).await;
    test_open_range_and_partial_read(&backend, &clock, &pool).await;
    test_early_list_drop_no_leak(&backend, &clock).await;
    test_chunked_short_eof_aborts_cleanly(&backend, &clock).await;
    test_special_filenames_roundtrip(&backend, &clock, &pool).await;
    test_boundary_range_and_extreme_timestamps(&backend, &clock, &pool).await;

    assert_eq!(
        pool.stats().in_use_units,
        0,
        "buffer pool leaked permits during conformance suite"
    );
}

async fn read_all(
    backend: &Arc<dyn StorageBackend>,
    path: &RelPath,
    range: Option<ByteRange>,
    pool: &BufferPool,
) -> Vec<u8> {
    let bp = BackendPath::from_rel(path.clone());
    match backend.open_read(&bp, range).await.expect("open_read") {
        DataSource::LocalSeekable(src) => {
            let (off, len) = match range {
                Some(r) => (r.offset, r.len),
                None => (0, src.total_len()),
            };
            let mut stream = bounded_range_stream(src, off, len, pool.clone());
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("chunk"));
            }
            out
        }
        DataSource::RemoteRangeReadable(remote) => {
            let r = range.unwrap_or(ByteRange {
                offset: 0,
                len: remote.total_len(),
            });
            let mut stream = remote.open_range(r).await.expect("open_range");
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("chunk"));
            }
            out
        }
        DataSource::SequentialStream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("chunk"));
            }
            out
        }
    }
}

fn single_shot_init(op_id: &str, path: &RelPath, total_size: u64, mtime_ns: i64) -> UploadInit {
    UploadInit {
        op_id: op_id.to_string(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size,
        src_mtime_ns: mtime_ns,
        planned_chunk_size: total_size.max(1),
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

async fn test_list_not_found_and_empty(backend: &Arc<dyn StorageBackend>) {
    let missing = RelPath::parse("definitely/does/not/exist").unwrap();
    let mut s = backend
        .list_stream(&missing, true)
        .await
        .expect("list missing dir must succeed");
    assert!(s.next().await.is_none());

    let mut root_s = backend
        .list_stream(&RelPath::root(), true)
        .await
        .expect("list empty root");
    assert!(root_s.next().await.is_none());
}

async fn test_delete_not_found_idempotent(backend: &Arc<dyn StorageBackend>) {
    let missing = BackendPath::from_rel(RelPath::parse("ghost/file.txt").unwrap());
    backend
        .delete(&missing)
        .await
        .expect("delete missing path must be idempotent");
}

async fn test_mkdir_nested_and_idempotent(backend: &Arc<dyn StorageBackend>) {
    let dir = RelPath::parse("conformance/nested/empty_dir").unwrap();
    backend.mkdir(&dir).await.expect("mkdir nested");
    backend.mkdir(&dir).await.expect("mkdir idempotent");
    let st = backend
        .stat(&BackendPath::from_rel(dir))
        .await
        .expect("stat dir");
    assert!(st.is_some(), "created directory should be observable");
}

async fn test_put_zero_length(backend: &Arc<dyn StorageBackend>, clock: &Arc<dyn Clock>) {
    let path = RelPath::parse("conformance/zero.bin").unwrap();
    let init = single_shot_init("op-zero", &path, 0, clock.now_unix_nanos());
    let body: ByteStream = Box::pin(futures::stream::empty());
    let entry = backend
        .put_single_shot(&init, body)
        .await
        .expect("put 0-byte file");
    assert_eq!(entry.size, 0);

    let st = backend
        .stat(&BackendPath::from_rel(path.clone()))
        .await
        .expect("stat 0-byte")
        .expect("0-byte exists");
    assert_eq!(st.size, 0);

    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    assert!(read_all(backend, &path, None, &pool).await.is_empty());
}

async fn test_overwrite_shorter_and_longer(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
    pool: &BufferPool,
) {
    let path = RelPath::parse("conformance/overwrite.dat").unwrap();
    let mtime = clock.now_unix_nanos();

    // 1. Write 4 KiB
    let v1 = vec![0xABu8; 4096];
    let init1 = single_shot_init("op-ow-1", &path, v1.len() as u64, mtime);
    let b1: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(v1)) }));
    backend.put_single_shot(&init1, b1).await.expect("put v1");

    // 2. Overwrite with shorter 13 bytes -> NO trailing garbage bytes!
    let v2 = b"short payload".to_vec();
    let init2 = single_shot_init("op-ow-2", &path, v2.len() as u64, mtime + 1_000_000_000);
    let b2: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(v2)) }));
    backend.put_single_shot(&init2, b2).await.expect("put v2");
    assert_eq!(read_all(backend, &path, None, pool).await, b"short payload");

    // 3. Overwrite with longer 12 KiB
    let v3: Vec<u8> = (0..12288).map(|i| (i % 251) as u8).collect();
    let init3 = single_shot_init("op-ow-3", &path, v3.len() as u64, mtime + 2_000_000_000);
    let v3_clone = v3.clone();
    let b3: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(v3_clone)) },
    ));
    backend.put_single_shot(&init3, b3).await.expect("put v3");
    assert_eq!(read_all(backend, &path, None, pool).await, v3);

    // Check hash if supported.
    if backend.capabilities().hashes.contains(&HashKind::Sha256) {
        let h = backend
            .compute_hash(&BackendPath::from_rel(path), HashKind::Sha256)
            .await
            .expect("compute_hash");
        assert!(h.is_some());
    }
}

async fn test_put_short_eof_preserves_existing(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
) {
    let path = RelPath::parse("conformance/preserve_eof.bin").unwrap();
    let mtime = clock.now_unix_nanos();
    let original = b"original-good-data-do-not-corrupt".to_vec();

    // Seed original good file.
    let init0 = single_shot_init("op-pre-eof", &path, original.len() as u64, mtime);
    let orig_c = original.clone();
    let b0: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(orig_c)) },
    ));
    backend
        .put_single_shot(&init0, b0)
        .await
        .expect("seed file");

    // Attempt overwrite declaring 1000 bytes but yielding only 10 bytes (Short EOF)!
    let init_bad = single_shot_init("op-short-eof", &path, 1000, mtime + 1_000_000_000);
    let bad_stream: ByteStream = Box::pin(futures::stream::once(async {
        Ok(Bytes::from_static(b"0123456789"))
    }));
    let res = backend.put_single_shot(&init_bad, bad_stream).await;
    assert!(res.is_err(), "short EOF single-shot must fail");

    // Original file MUST remain 100% intact!
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    assert_eq!(read_all(backend, &path, None, &pool).await, original);
}

async fn test_put_stream_error_preserves_existing(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
) {
    let path = RelPath::parse("conformance/preserve_err.bin").unwrap();
    let mtime = clock.now_unix_nanos();
    let original = b"intact-before-error".to_vec();

    let init0 = single_shot_init("op-pre-err", &path, original.len() as u64, mtime);
    let orig_c = original.clone();
    let b0: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(orig_c)) },
    ));
    backend
        .put_single_shot(&init0, b0)
        .await
        .expect("seed file");

    let init_err = single_shot_init("op-stream-err", &path, 100, mtime + 1_000_000_000);
    let err_stream: ByteStream = Box::pin(futures::stream::iter(vec![
        Ok(Bytes::from_static(b"partial")),
        Err(Error::network("injected mid-stream failure")),
    ]));
    let res = backend.put_single_shot(&init_err, err_stream).await;
    assert!(res.is_err(), "stream error must fail put");

    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    assert_eq!(read_all(backend, &path, None, &pool).await, original);
}

async fn test_open_range_and_partial_read(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
    pool: &BufferPool,
) {
    let path = RelPath::parse("conformance/range.bin").unwrap();
    let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let init = single_shot_init("op-range", &path, data.len() as u64, clock.now_unix_nanos());
    let data_c = data.clone();
    let body: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(data_c)) },
    ));
    backend
        .put_single_shot(&init, body)
        .await
        .expect("put range.bin");

    // Prefix slice
    assert_eq!(
        read_all(
            backend,
            &path,
            Some(ByteRange {
                offset: 0,
                len: 500
            }),
            pool
        )
        .await,
        data[..500]
    );
    // Middle slice
    assert_eq!(
        read_all(
            backend,
            &path,
            Some(ByteRange {
                offset: 3333,
                len: 1234
            }),
            pool
        )
        .await,
        data[3333..3333 + 1234]
    );
    // Tail slice
    assert_eq!(
        read_all(
            backend,
            &path,
            Some(ByteRange {
                offset: 9500,
                len: 500
            }),
            pool
        )
        .await,
        data[9500..]
    );
}

async fn test_early_list_drop_no_leak(backend: &Arc<dyn StorageBackend>, clock: &Arc<dyn Clock>) {
    let mtime = clock.now_unix_nanos();
    for i in 0..20 {
        let p = RelPath::parse(&format!("conformance/drop_list/f{i}.txt")).unwrap();
        let init = single_shot_init(&format!("op-dl-{i}"), &p, 3, mtime);
        let body: ByteStream = Box::pin(futures::stream::once(async {
            Ok(Bytes::from_static(b"abc"))
        }));
        backend.put_single_shot(&init, body).await.expect("seed");
    }
    let dir = RelPath::parse("conformance/drop_list").unwrap();
    let mut stream = backend.list_stream(&dir, true).await.expect("list");
    let first = stream.next().await;
    assert!(first.is_some());
    // Drop stream immediately without draining remaining 19 items -> must not deadlock/leak!
    drop(stream);
}

async fn test_chunked_short_eof_aborts_cleanly(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
) {
    let path = RelPath::parse("conformance/chunked_short.bin").unwrap();
    let mtime = clock.now_unix_nanos();
    let caps = backend.capabilities();
    let chunk_size = match caps.chunk_alignment {
        crate::types::ChunkAlignment::Arbitrary => caps.default_chunk_size.clamp(1024, 256 * 1024),
        crate::types::ChunkAlignment::MultipleOf { align_bytes, .. } => {
            let align = align_bytes.max(1);
            let target = caps.default_chunk_size.clamp(1024, 256 * 1024);
            target.div_ceil(align) * align
        }
        crate::types::ChunkAlignment::MinSizeWithMaxParts { min_bytes, .. } => caps
            .default_chunk_size
            .min(256 * 1024)
            .max(min_bytes)
            .max(1024),
    };
    let init = UploadInit {
        op_id: "op-chunk-short".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: chunk_size * 2,
        src_mtime_ns: mtime,
        planned_chunk_size: chunk_size,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = backend.begin_upload(&init).await.expect("begin_upload");
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "test://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: path.as_str().into(),
        dst_raw_path: path.as_str().into(),
        dst_nfc_path: path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: mtime,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: backend.kind().into(),
        session_token: Some(opened.session_token),
        backend_meta: opened.backend_meta,
        planned_chunk_size: chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Feed a short MemorySource into bounded_range_stream declaring chunk_size bytes.
    let short_src = Arc::new(MemorySource::new(Bytes::from(vec![1u8; 64])));
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let short_body = bounded_range_stream(short_src, 0, chunk_size, pool.clone());
    let chunk = ChunkUpload {
        part_number: 1,
        offset: 0,
        len: chunk_size,
        total_size: init.total_size,
        body: short_body,
    };
    let res = backend.upload_chunk(&op, chunk).await;
    assert!(res.is_err(), "chunked short EOF must fail");

    backend.abort_upload(&op).await.expect("abort_upload");
    assert!(
        backend
            .stat(&BackendPath::from_rel(path))
            .await
            .expect("stat")
            .is_none(),
        "aborted chunked upload must not publish partial object"
    );
    assert_eq!(pool.stats().in_use_units, 0);
}

/// rclone `TestFsEncoding`-inspired special filename round-trip: verifies spaces, `+`,
/// `%20`, `#`, `&`, `;`, quotes, Unicode, and 4-byte Emoji survive put -> stat -> list ->
/// read -> delete cleanly without URL double-encoding, XML escaping bugs, or truncation.
async fn test_special_filenames_roundtrip(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
    pool: &BufferPool,
) {
    let kind = backend.kind();
    let is_windows_fs = (kind == "local" || kind == "sftp") && cfg!(windows);
    let forbids_xml_angles = is_windows_fs || kind == "onedrive" || kind == "dropbox";

    let mut names: Vec<&str> = vec![
        "hello world+plus%20pct.txt",
        "hash#1&amp;semi'quote[1].txt",
        "café_中文_🚀_emoji.bin",
    ];
    if !forbids_xml_angles {
        names.push("query?a=1&b=2<tag>.txt");
    }

    let mtime = clock.now_unix_nanos();
    let mut created = Vec::new();
    for (idx, name) in names.iter().enumerate() {
        let rel = RelPath::parse(&format!("conformance/enc/{name}")).expect("parse special rel");
        let payload = format!("payload-{idx}-{name}").into_bytes();
        let init = single_shot_init(&format!("op-enc-{idx}"), &rel, payload.len() as u64, mtime);
        let body_bytes = payload.clone();
        let body: ByteStream =
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(body_bytes)) },
            ));
        let put_entry = backend
            .put_single_shot(&init, body)
            .await
            .unwrap_or_else(|e| panic!("put special filename `{name}` on `{kind}` failed: {e}"));
        assert_eq!(put_entry.size, payload.len() as u64);

        let st = backend
            .stat(&BackendPath::from_rel(rel.clone()))
            .await
            .unwrap_or_else(|e| panic!("stat special filename `{name}` on `{kind}` failed: {e}"))
            .unwrap_or_else(|| panic!("stat missing special filename `{name}` on `{kind}`"));
        assert_eq!(st.size, payload.len() as u64);

        let got = read_all(backend, &rel, None, pool).await;
        assert_eq!(
            got, payload,
            "round-trip payload mismatch for `{name}` on `{kind}`"
        );
        created.push((rel, st));
    }

    // List directory and verify every special filename appears with matching NFC path.
    let dir = RelPath::parse("conformance/enc").unwrap();
    let mut stream = backend
        .list_stream(&dir, true)
        .await
        .unwrap_or_else(|e| panic!("list special dir on `{kind}` failed: {e}"));
    let mut listed = std::collections::HashSet::new();
    while let Some(item) = stream.next().await {
        let e = item.unwrap_or_else(|e| panic!("list item error on `{kind}`: {e}"));
        listed.insert(e.nfc_path);
    }
    for (rel, _) in &created {
        assert!(
            listed.contains(rel),
            "listed entries on `{kind}` missing special filename `{rel}` (saw: {listed:?})"
        );
    }

    // Delete every created special file and confirm disappearance.
    for (rel, st) in created {
        let bp = BackendPath::from_entry(&st);
        backend
            .delete(&bp)
            .await
            .unwrap_or_else(|e| panic!("delete special filename `{rel}` on `{kind}` failed: {e}"));
        assert!(
            backend
                .stat(&BackendPath::from_rel(rel.clone()))
                .await
                .expect("stat after delete")
                .is_none(),
            "special filename `{rel}` still exists after delete on `{kind}`"
        );
    }
}

/// rclone `TestFsOpenOption` & `TestFsSetModTime` boundary tests:
/// - 0-byte empty range read, 1-byte file & last-byte range read, `offset == size` empty range.
/// - Extreme timestamps (near Unix epoch 1970 and future 2040-01-01).
async fn test_boundary_range_and_extreme_timestamps(
    backend: &Arc<dyn StorageBackend>,
    clock: &Arc<dyn Clock>,
    pool: &BufferPool,
) {
    let kind = backend.kind();

    // 1. 0-byte file with explicit zero-length range [0..0).
    let zero_path = RelPath::parse("conformance/bounds/empty.bin").unwrap();
    let init0 = single_shot_init("op-bnd-0", &zero_path, 0, clock.now_unix_nanos());
    backend
        .put_single_shot(&init0, Box::pin(futures::stream::empty()))
        .await
        .expect("put empty bounds file");
    assert!(
        read_all(
            backend,
            &zero_path,
            Some(ByteRange { offset: 0, len: 0 }),
            pool
        )
        .await
        .is_empty()
    );

    // 2. 1-byte file: read full, read single last byte, read zero-length tail at offset == size.
    let one_path = RelPath::parse("conformance/bounds/one.bin").unwrap();
    let init1 = single_shot_init("op-bnd-1", &one_path, 1, clock.now_unix_nanos());
    backend
        .put_single_shot(
            &init1,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"Z"))
            })),
        )
        .await
        .expect("put 1-byte file");
    assert_eq!(
        read_all(
            backend,
            &one_path,
            Some(ByteRange { offset: 0, len: 1 }),
            pool
        )
        .await,
        b"Z"
    );
    assert!(
        read_all(
            backend,
            &one_path,
            Some(ByteRange { offset: 1, len: 0 }),
            pool
        )
        .await
        .is_empty()
    );

    // 3. Extreme timestamps: 1970-01-02 (86400s) and 2040-01-01 (2_208_988_800s).
    for (tag, ts_secs) in [("epoch1970", 86_400i64), ("future2040", 2_208_988_800i64)] {
        let p = RelPath::parse(&format!("conformance/bounds/ts_{tag}.bin")).unwrap();
        let ts_ns = ts_secs * 1_000_000_000;
        let init = single_shot_init(&format!("op-ts-{tag}"), &p, 4, ts_ns);
        backend
            .put_single_shot(
                &init,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"time"))
                })),
            )
            .await
            .unwrap_or_else(|e| panic!("put with {tag} timestamp on `{kind}` failed: {e}"));
        let st = backend
            .stat(&BackendPath::from_rel(p.clone()))
            .await
            .expect("stat ts file")
            .expect("ts file exists");
        assert_eq!(st.size, 4);
        if backend.capabilities().can_set_mtime {
            let tol = i64::try_from(backend.capabilities().mtime_granularity.as_nanos())
                .unwrap_or(1_000_000_000)
                .max(2_000_000_000);
            assert!(
                (st.mtime_ns - ts_ns).abs() <= tol,
                "backend `{kind}` failed to preserve {tag} mtime (expected {ts_ns}, got {}, tol {tol})",
                st.mtime_ns
            );
        }
    }
}
