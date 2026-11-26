use super::super::fs_util::staging_manifest_path;
use super::super::*;
use bytes::Bytes;
use futures::StreamExt;
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use tempfile::TempDir;

#[tokio::test]
async fn local_to_local_resumable_copy_and_sync_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(src_dir.join("nested")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let big_payload: Vec<u8> = (0..(900 * 1024)).map(|i| (i % 239) as u8).collect();
    std::fs::write(src_dir.join("small.txt"), b"hello rship").unwrap();
    std::fs::write(src_dir.join("nested/big.bin"), &big_payload).unwrap();
    // Pre-existing orphan in dst that should be deleted by sync.
    std::fs::write(dst_dir.join("stale.txt"), b"old").unwrap();

    // Force resumable chunked local write on `big.bin` (single_shot_max = 64 KiB, chunk = 256 KiB).
    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let dst = Arc::new(
        LocalBackend::new("dst", &dst_dir)
            .unwrap()
            .with_chunking(64 * 1024, 256 * 1024),
    );
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-e2e").unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut cfg = EngineConfig::new("j-e2e", JobMode::Sync, "src", "dst");
    // Exercise the resumable ParallelParts chunked path explicitly in this test.
    cfg.allow_server_side_copy = false;
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(rep.items_deleted, 1);
    assert_eq!(
        std::fs::read(dst_dir.join("small.txt")).unwrap(),
        b"hello rship"
    );
    assert_eq!(
        std::fs::read(dst_dir.join("nested/big.bin")).unwrap(),
        big_payload
    );
    assert!(!dst_dir.join("stale.txt").exists());
    assert_eq!(pool.stats().in_use_units, 0);

    // Second sync run must skip everything cleanly (0 transfers, 0 deletes).
    let idx2 = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-e2e-2").unwrap());
    let cfg2 = EngineConfig::new("j-e2e-2", JobMode::Sync, "src", "dst");
    let rep2 = engine.run(&cfg2, idx2).await.unwrap();
    assert!(rep2.errors.is_empty());
    assert_eq!(rep2.files_transferred, 0);
    assert_eq!(rep2.files_skipped, 2); // 2 files (directories are excluded from files_skipped)
}

#[tokio::test]
async fn readonly_target_overwrite_succeeds_cross_platform() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(src_dir.join("doc.txt"), b"updated content v2").unwrap();
    let dst_file = dst_dir.join("doc.txt");
    std::fs::write(&dst_file, b"v1").unwrap();
    let mut perms = std::fs::metadata(&dst_file).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&dst_file, perms).unwrap();

    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-ro").unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

    let engine = TransferEngine::new(
        src,
        dst,
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-ro", JobMode::Copy, "src", "dst");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(std::fs::read(&dst_file).unwrap(), b"updated content v2");
}

#[tokio::test]
async fn local_backend_passes_rclone_conformance_suite() {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(
        LocalBackend::new("local-conf", tmp.path())
            .unwrap()
            .with_chunking(64 * 1024, 256 * 1024),
    );
    rship_core::conformance::run_backend_conformance(backend, SystemClock::shared()).await;
}

#[tokio::test]
async fn local_parallel_parts_crash_resume_and_power_loss_crc_detection() {
    let tmp = TempDir::new().unwrap();
    let dst = LocalBackend::new("dst", tmp.path())
        .unwrap()
        .with_chunking(64 * 1024, 128 * 1024);

    let total = 512 * 1024u64; // 4 × 128 KiB parts
    let full_data: Vec<u8> = (0..total as usize)
        .map(|i| ((i * 29 + 7) % 251) as u8)
        .collect();
    let rel = RelPath::parse("resume/large.bin").unwrap();
    let init = UploadInit {
        op_id: "op-crc-resume".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 128 * 1024,
        checksums: vec![],
        precondition: rship_core::state::DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = dst.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-crc".into(),
        job_id: "j-crc".into(),
        src_endpoint: "test://src".into(),
        dst_endpoint: dst.endpoint_identity(),
        src_raw_path: "large.bin".into(),
        dst_raw_path: rel.as_str().into(),
        dst_nfc_path: rel.clone(),
        src_version: rship_core::state::SourceVersion {
            node_id: None,
            size: total,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: rship_core::state::DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "local".into(),
        session_token: Some(opened.session_token.clone()),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 128 * 1024,
        confirmed_offset: 0,
        state: rship_core::state::OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    for pn in [1u32, 3u32] {
        let off = u64::from(pn - 1) * 128 * 1024;
        let slice = Bytes::copy_from_slice(&full_data[off as usize..(off + 128 * 1024) as usize]);
        let ack = dst
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    pn,
                    off,
                    128 * 1024,
                    total,
                    Box::pin(futures::stream::once(async move { Ok(slice) })),
                ),
            )
            .await
            .unwrap();
        assert!(ack.etag.as_deref().unwrap().starts_with("crc32c:"));
    }

    let part_file = PathBuf::from(&opened.session_token);
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&part_file)
            .unwrap();
        f.seek(SeekFrom::Start(4096)).unwrap();
        f.write_all(&[full_data[4096] ^ 0xFF]).unwrap();
    }

    let prog = dst.query_upload(&op).await.unwrap();
    let mut completed_parts = match prog {
        UploadProgress::CompletedParts(parts) => {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].part_number, 3);
            parts
        }
        other => panic!("expected CompletedParts([3]), got {other:?}"),
    };

    for pn in [1u32, 2u32, 4u32] {
        let off = u64::from(pn - 1) * 128 * 1024;
        let slice = Bytes::copy_from_slice(&full_data[off as usize..(off + 128 * 1024) as usize]);
        let ack = dst
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    pn,
                    off,
                    128 * 1024,
                    total,
                    Box::pin(futures::stream::once(async move { Ok(slice) })),
                ),
            )
            .await
            .unwrap();
        completed_parts.push(rship_core::backend::CompletedPart {
            part_number: pn,
            offset: off,
            length: 128 * 1024,
            etag: ack.etag.unwrap_or_default(),
            checksum: ack.checksum,
        });
    }

    let entry = dst.finish_upload(&op, &completed_parts).await.unwrap();
    assert_eq!(entry.size, total);
    assert_eq!(
        std::fs::read(tmp.path().join("resume/large.bin")).unwrap(),
        full_data
    );
    assert!(!part_file.exists());
    assert!(!staging_manifest_path(&part_file).exists());
}

#[tokio::test]
async fn local_native_fast_copy_handles_small_large_and_readonly_files() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(src_dir.join("sub")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let small = b"small native copy payload".to_vec();
    let large: Vec<u8> = (0..(600 * 1024))
        .map(|i| ((i * 37 + 13) % 251) as u8)
        .collect();
    std::fs::write(src_dir.join("small.txt"), &small).unwrap();
    std::fs::write(src_dir.join("sub/large.bin"), &large).unwrap();

    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-fast").unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-fast", JobMode::Copy, "src", "dst");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(rep.server_side_copies, 0);
    assert_eq!(std::fs::read(dst_dir.join("small.txt")).unwrap(), small);
    assert_eq!(std::fs::read(dst_dir.join("sub/large.bin")).unwrap(), large);
    assert_eq!(pool.stats().peak_units, 0);

    let idx2 = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-fast-sync").unwrap());
    let cfg2 = EngineConfig::new("j-fast-sync", JobMode::Sync, "src", "dst");
    let rep2 = engine.run(&cfg2, idx2).await.unwrap();
    assert!(rep2.errors.is_empty(), "{:?}", rep2.errors);
    assert_eq!(rep2.files_transferred, 0);
    assert_eq!(rep2.files_skipped, 2);

    let updated = b"updated small payload with different length!".to_vec();
    std::fs::write(src_dir.join("small.txt"), &updated).unwrap();
    #[cfg(windows)]
    {
        let mut perms = std::fs::metadata(dst_dir.join("small.txt"))
            .unwrap()
            .permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(dst_dir.join("small.txt"), perms).unwrap();
    }
    let idx3 = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-fast-over").unwrap());
    let cfg3 = EngineConfig::new("j-fast-over", JobMode::Copy, "src", "dst");
    let rep3 = engine.run(&cfg3, idx3).await.unwrap();
    assert!(rep3.errors.is_empty(), "{:?}", rep3.errors);
    assert_eq!(rep3.files_transferred, 1);
    assert_eq!(std::fs::read(dst_dir.join("small.txt")).unwrap(), updated);
}

#[tokio::test]
async fn local_compute_hash_supports_crc32c_and_crc64nvme_and_matches_standard_vectors() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("check.bin"), b"123456789").unwrap();
    let big: Vec<u8> = (0..(400 * 1024))
        .map(|i| ((i * 53 + 7) & 0xFF) as u8)
        .collect();
    std::fs::write(tmp.path().join("big.bin"), &big).unwrap();

    let backend = LocalBackend::new("local", tmp.path()).unwrap();
    let bp = BackendPath::from_rel(RelPath::parse("check.bin").unwrap());
    let ck32 = backend
        .compute_hash(&bp, HashKind::Crc32c)
        .await
        .unwrap()
        .expect("crc32c supported");
    assert_eq!(ck32.kind, HashKind::Crc32c);
    assert_eq!(ck32.hex, "e3069283");

    let ck64 = backend
        .compute_hash(&bp, HashKind::Crc64Nvme)
        .await
        .unwrap()
        .expect("crc64nvme supported");
    assert_eq!(ck64.kind, HashKind::Crc64Nvme);
    assert_eq!(ck64.hex, "ae8b14860a799888");

    let bp_big = BackendPath::from_rel(RelPath::parse("big.bin").unwrap());
    let ck64_big = backend
        .compute_hash(&bp_big, HashKind::Crc64Nvme)
        .await
        .unwrap()
        .expect("crc64nvme supported on multi-block file");
    assert_eq!(
        ck64_big.hex,
        format!("{:016x}", crate::common::crc64_nvme(&big))
    );
}

#[tokio::test]
async fn sync_file_level_exclude_preserves_dst_subdirectory_containing_excluded_files() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(dst_dir.join("secrets")).unwrap();
    std::fs::create_dir_all(dst_dir.join("orphan_empty")).unwrap();

    std::fs::write(src_dir.join("app.txt"), b"app-v1").unwrap();
    std::fs::write(dst_dir.join("app.txt"), b"app-v1").unwrap();
    std::fs::write(dst_dir.join("secrets/prod.env"), b"API_KEY=keep-me").unwrap();
    std::fs::write(dst_dir.join("secrets/stale.txt"), b"delete-me").unwrap();

    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-prot-dir").unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

    let engine = TransferEngine::new(
        src,
        dst,
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut cfg = EngineConfig::new("j-prot-dir", JobMode::Sync, "src", "dst");
    cfg.filter = rship_core::filter::FilterSet::new(&[], &["*.env".into()]).unwrap();
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "unexpected errors: {:?}", rep.errors);
    assert_eq!(
        std::fs::read(dst_dir.join("secrets/prod.env")).unwrap(),
        b"API_KEY=keep-me",
        "excluded file in destination subdirectory MUST be preserved!"
    );
    assert!(
        !dst_dir.join("secrets/stale.txt").exists(),
        "non-excluded orphan file inside protected directory MUST still be deleted"
    );
    assert!(
        !dst_dir.join("orphan_empty").exists(),
        "truly unprotected empty orphan directory MUST still be deleted"
    );
}

/// A destination file whose name is NFD on a normalization-sensitive filesystem (e.g. copied
/// there from macOS) matches an NFC source by `nfc_path`. Overwriting it must replace the
/// existing NFD file in place, not fail the `Existing` precondition against the NFC spelling
/// (which does not exist) or create an NFC sibling next to it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn sync_overwrites_existing_nfd_destination_in_place() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    let nfc_dir = "r\u{e9}sum\u{e9}";
    let nfd_dir = "re\u{301}sume\u{301}";
    let nfc_name = "caf\u{e9}.txt";
    let nfd_name = "cafe\u{301}.txt";
    std::fs::create_dir_all(src_dir.join(nfc_dir)).unwrap();
    std::fs::create_dir_all(dst_dir.join(nfd_dir)).unwrap();
    std::fs::write(src_dir.join(nfc_name), b"new source content").unwrap();
    std::fs::write(src_dir.join(nfc_dir).join(nfc_name), b"nested new content").unwrap();
    std::fs::write(src_dir.join(nfc_dir).join("fresh.txt"), b"fresh").unwrap();
    std::fs::write(dst_dir.join(nfd_name), b"old").unwrap();
    std::fs::write(dst_dir.join(nfd_dir).join(nfd_name), b"old nested").unwrap();

    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();
    for (round, allow_ssc) in [(0, true), (1, false)] {
        if round == 1 {
            std::fs::write(src_dir.join(nfc_name), b"second round, streamed").unwrap();
            std::fs::write(src_dir.join(nfc_dir).join(nfc_name), b"second nested round").unwrap();
        }
        let engine = TransferEngine::new(
            Arc::new(LocalBackend::new("src", &src_dir).unwrap()),
            Arc::new(LocalBackend::new("dst", &dst_dir).unwrap()),
            journal.clone(),
            pool.clone(),
            SystemClock::shared(),
            CancelFlag::new(),
        );
        let job = format!("j-nfd-{round}");
        let mut cfg = EngineConfig::new(&job, JobMode::Sync, "src", "dst");
        cfg.allow_server_side_copy = allow_ssc;
        let rep = engine
            .run(
                &cfg,
                Arc::new(SqliteSyncIndex::open_temp(&state_dir, &job).unwrap()),
            )
            .await
            .unwrap();
        assert!(
            rep.is_success(),
            "round {round}: NFD overwrite errors: {:?}",
            rep.errors
        );
    }

    let mut top: Vec<String> = std::fs::read_dir(&dst_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    top.sort();
    let mut expected_top = vec![nfd_dir.to_string(), nfd_name.to_string()];
    expected_top.sort();
    assert_eq!(
        top, expected_top,
        "no NFC siblings may appear next to NFD entries"
    );
    assert_eq!(
        std::fs::read(dst_dir.join(nfd_name)).unwrap(),
        b"second round, streamed"
    );
    let mut nested: Vec<String> = std::fs::read_dir(dst_dir.join(nfd_dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    nested.sort();
    let mut expected_nested = vec![nfd_name.to_string(), "fresh.txt".to_string()];
    expected_nested.sort();
    assert_eq!(nested, expected_nested);
    assert_eq!(
        std::fs::read(dst_dir.join(nfd_dir).join(nfd_name)).unwrap(),
        b"second nested round"
    );
}

#[tokio::test]
async fn windows_safe_bidirectional_and_reserved_names_roundtrip() {
    use super::super::fs_util::{decode_local_rel_path, encode_local_segment};
    use rship_core::encoding::EncodingMode;

    for reserved in [
        "CON",
        "CON .txt",
        "NUL   .tar.gz",
        "COM\u{00B9}",
        "LPT\u{00B3}",
        "what?file:name*.log",
        "trailing.",
        "trailing ",
        "literal^5E",
    ] {
        let enc = encode_local_segment(EncodingMode::WindowsSafe, reserved);
        let dec = decode_local_rel_path(EncodingMode::WindowsSafe, &enc).unwrap();
        assert_eq!(
            dec, reserved,
            "roundtrip failed for {reserved:?} -> {enc:?}"
        );
        assert_ne!(enc, reserved, "expected escaping for {reserved:?}");
    }

    let tmp = TempDir::new().unwrap();
    let d1 = tmp.path().join("ws1");
    let d2 = tmp.path().join("ws2");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();

    std::fs::write(d1.join("^43ON"), b"con").unwrap();
    std::fs::write(d1.join("^43ON .txt"), b"con-space").unwrap();
    std::fs::write(d1.join("a^3Ab"), b"colon").unwrap();

    let ws1 = Arc::new(
        LocalBackend::new("ws1", &d1)
            .unwrap()
            .with_encoding(EncodingMode::WindowsSafe),
    );
    let ws2 = Arc::new(
        LocalBackend::new("ws2", &d2)
            .unwrap()
            .with_encoding(EncodingMode::WindowsSafe),
    );

    let listed: Vec<Entry> = ws1
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
        .await;
    for e in &listed {
        assert!(
            e.raw_path.is_none(),
            "ASCII decoded WindowsSafe entry `{}` must have raw_path=None, got {:?}",
            e.nfc_path,
            e.raw_path
        );
    }

    let bp_space = BackendPath::from_rel(RelPath::parse("CON .txt").unwrap());
    assert!(ws1.stat(&bp_space).await.unwrap().is_some());
    assert!(
        ws1.compute_hash(&bp_space, HashKind::Sha256)
            .await
            .unwrap()
            .is_some()
    );

    let engine = TransferEngine::new(
        ws1.clone(),
        ws2.clone(),
        Arc::new(StateActor::open(&state_dir).unwrap()),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let rep1 = engine
        .run(
            &EngineConfig::new("j-ws-1", JobMode::Sync, "ws1", "ws2"),
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-ws-1").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep1.is_success(), "{:?}", rep1.errors);
    assert_eq!(rep1.files_transferred, 3);

    // Second sync must skip all 3 files cleanly (no false UnicodeNfcCollision).
    let rep2 = engine
        .run(
            &EngineConfig::new("j-ws-2", JobMode::Sync, "ws1", "ws2"),
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-ws-2").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep2.is_success(), "{:?}", rep2.errors);
    assert_eq!(rep2.files_transferred, 0);
    assert_eq!(rep2.files_skipped, 3);

    // Cross-encoding fallback: WindowsSafe src -> Identity dst must fall back cleanly in copy.rs
    // (using a filename valid on both Windows and Unix `Identity`, e.g. `literal^5E` stored as
    // `literal^5E5E` on WindowsSafe).
    let ws_cross_dir = tmp.path().join("ws_cross");
    let id_dir = tmp.path().join("id");
    std::fs::create_dir_all(&ws_cross_dir).unwrap();
    std::fs::create_dir_all(&id_dir).unwrap();
    std::fs::write(ws_cross_dir.join("literal^5E5E"), b"caret-body").unwrap();
    let ws_cross = Arc::new(
        LocalBackend::new("ws_cross", &ws_cross_dir)
            .unwrap()
            .with_encoding(EncodingMode::WindowsSafe),
    );
    let id_dst = Arc::new(LocalBackend::new("id", &id_dir).unwrap());
    let engine_cross = TransferEngine::new(
        ws_cross,
        id_dst,
        Arc::new(StateActor::open(&state_dir).unwrap()),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let rep_cross = engine_cross
        .run(
            &EngineConfig::new("j-ws-cross", JobMode::Copy, "ws_cross", "id"),
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-ws-cross").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep_cross.is_success(), "{:?}", rep_cross.errors);
    assert_eq!(rep_cross.files_transferred, 1);
    assert_eq!(
        std::fs::read(id_dir.join("literal^5E")).unwrap(),
        b"caret-body"
    );

    let renamed = ws1.rename(&bp_space, "AUX .txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "AUX .txt");
    assert!(d1.join("^41UX .txt").exists());
    ws1.delete(&BackendPath::from_entry(&renamed))
        .await
        .unwrap();
    assert!(!d1.join("^41UX .txt").exists());
}

#[tokio::test]
async fn finish_upload_rejects_incomplete_or_forged_parts_and_guard_cleans_failures() {
    use rship_core::error::ErrorKind;
    use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};

    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let dst = LocalBackend::new("dst", &root)
        .unwrap()
        .with_chunking(32 * 1024, 64 * 1024);

    let total = 128 * 1024u64;
    let rel = RelPath::parse("sparse.bin").unwrap();
    let init = UploadInit {
        op_id: "op-sparse-guard".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = dst.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: dst.endpoint_identity(),
        src_raw_path: "sparse.bin".into(),
        dst_raw_path: "sparse.bin".into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "local".into(),
        session_token: Some(opened.session_token.clone()),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    let ack1 = dst
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                total,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0xAB; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap();
    let p1 = rship_core::backend::CompletedPart {
        part_number: 1,
        offset: 0,
        length: 64 * 1024,
        etag: ack1.etag.clone().unwrap(),
        checksum: None,
    };

    // Empty parts, partial parts, gapped parts, and forged part 2 must all fail and preserve staging!
    assert_eq!(
        dst.finish_upload(&op, &[]).await.unwrap_err().kind,
        ErrorKind::InvalidGeometry
    );
    assert_eq!(
        dst.finish_upload(&op, std::slice::from_ref(&p1))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidGeometry
    );
    let forged_p2 = rship_core::backend::CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: String::new(),
        checksum: None,
    };
    assert_eq!(
        dst.finish_upload(&op, &[p1.clone(), forged_p2])
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidGeometry
    );
    let part_file = PathBuf::from(&opened.session_token);
    assert!(
        part_file.exists(),
        "incomplete finish_upload must keep resumable staging"
    );
    assert!(!root.join("sparse.bin").exists());

    // Upload part 2, verify wrong etag fails Integrity, then commit succeeds.
    let ack2 = dst
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                64 * 1024,
                64 * 1024,
                total,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0xCD; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap();
    let p2_empty_etag = rship_core::backend::CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: String::new(),
        checksum: None,
    };
    assert_eq!(
        dst.finish_upload(&op, &[p1.clone(), p2_empty_etag])
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Integrity
    );
    let p2_bad = rship_core::backend::CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: "crc32c:00000000".into(),
        checksum: None,
    };
    assert_eq!(
        dst.finish_upload(&op, &[p1.clone(), p2_bad])
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Integrity
    );
    let p2 = rship_core::backend::CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: ack2.etag.unwrap(),
        checksum: None,
    };
    dst.finish_upload(&op, &[p1.clone(), p2.clone()])
        .await
        .unwrap();
    assert!(!part_file.exists());
    assert!(!staging_manifest_path(&part_file).exists());

    // PreconditionFailed in finish_upload must trigger StagingGuard cleanup of part + .parts.
    let init2 = UploadInit {
        op_id: "op-guard-clean".into(),
        dst_path: rel,
        ..init
    };
    let opened2 = dst.begin_upload(&init2).await.unwrap();
    let op2 = OperationRecord {
        op_id: init2.op_id,
        session_token: Some(opened2.session_token.clone()),
        backend_meta: opened2.backend_meta,
        ..op
    };
    let a1 = dst
        .upload_chunk(
            &op2,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                total,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![1u8; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap();
    let a2 = dst
        .upload_chunk(
            &op2,
            ChunkUpload::new(
                2,
                64 * 1024,
                64 * 1024,
                total,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![2u8; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap();
    let c1 = rship_core::backend::CompletedPart {
        part_number: 1,
        offset: 0,
        length: 64 * 1024,
        etag: a1.etag.unwrap(),
        checksum: None,
    };
    let c2 = rship_core::backend::CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: a2.etag.unwrap(),
        checksum: None,
    };
    assert_eq!(
        dst.finish_upload(&op2, &[c1, c2]).await.unwrap_err().kind,
        ErrorKind::PreconditionFailed
    );
    let pf2 = PathBuf::from(&opened2.session_token);
    assert!(
        !pf2.exists(),
        "StagingGuard must remove staging on PreconditionFailed"
    );
    assert!(
        !staging_manifest_path(&pf2).exists(),
        "StagingGuard must remove .parts on PreconditionFailed"
    );
}

#[tokio::test]
async fn upload_chunk_and_finish_return_session_expired_on_missing_staging_and_validate_bounds() {
    use rship_core::error::ErrorKind;
    use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};

    let tmp = TempDir::new().unwrap();
    let dst = LocalBackend::new("dst", tmp.path()).unwrap();
    let rel = RelPath::parse("bounds.bin").unwrap();
    let init = UploadInit {
        op_id: "op-bounds".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16,
        src_mtime_ns: 100,
        planned_chunk_size: 8,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = dst.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id,
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: dst.endpoint_identity(),
        src_raw_path: "bounds.bin".into(),
        dst_raw_path: "bounds.bin".into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: 16,
            mtime_ns: 100,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "local".into(),
        session_token: Some(opened.session_token.clone()),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 8,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Bounds violations return InvalidGeometry.
    let bad_total = ChunkUpload::new(
        1,
        0,
        8,
        32,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from(vec![0u8; 8]))
        })),
    );
    assert_eq!(
        dst.upload_chunk(&op, bad_total).await.unwrap_err().kind,
        ErrorKind::InvalidGeometry
    );
    let oob_range = ChunkUpload::new(
        1,
        12,
        8,
        16,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from(vec![0u8; 8]))
        })),
    );
    assert_eq!(
        dst.upload_chunk(&op, oob_range).await.unwrap_err().kind,
        ErrorKind::InvalidGeometry
    );

    // Delete staging file -> both upload_chunk and finish_upload return SessionExpired.
    std::fs::remove_file(&opened.session_token).unwrap();
    let valid_chunk = ChunkUpload::new(
        1,
        0,
        16,
        16,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from(vec![1u8; 16]))
        })),
    );
    let err = dst.upload_chunk(&op, valid_chunk).await.unwrap_err();
    assert!(
        err.is_session_expired(),
        "expected SessionExpired, got {err:?}"
    );

    let p1 = rship_core::backend::CompletedPart {
        part_number: 1,
        offset: 0,
        length: 16,
        etag: String::new(),
        checksum: None,
    };
    let err2 = dst.finish_upload(&op, &[p1]).await.unwrap_err();
    assert!(
        err2.is_session_expired(),
        "expected SessionExpired, got {err2:?}"
    );
}

#[tokio::test]
async fn nfd_parent_dir_writes_and_rename_preserve_raw_path() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let nfd_dir = "cafe\u{0301}";
    std::fs::create_dir_all(src_dir.join(nfd_dir)).unwrap();
    std::fs::create_dir_all(dst_dir.join(nfd_dir)).unwrap();
    std::fs::write(src_dir.join(nfd_dir).join("src.txt"), b"from-src").unwrap();

    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();

    let put_rel = RelPath::parse("caf\u{00e9}/written.txt").unwrap();
    let written = dst
        .put_single_shot(
            &UploadInit {
                op_id: "op-nfd-put".into(),
                dst_path: put_rel,
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 3,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 3,
                checksums: vec![],
                precondition: rship_core::state::DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abc"))
            })),
        )
        .await
        .unwrap();
    assert_eq!(written.nfc_path.as_str(), "caf\u{00e9}/written.txt");
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(written.raw_path(), "cafe\u{0301}/written.txt");

    let renamed = dst
        .rename(&BackendPath::from_entry(&written), "renamed.txt")
        .await
        .unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "caf\u{00e9}/renamed.txt");
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(renamed.raw_path(), "cafe\u{0301}/renamed.txt");
    assert!(dst_dir.join(nfd_dir).join("renamed.txt").exists());

    let src_entry = src
        .stat(&BackendPath::new(
            "cafe\u{0301}/src.txt",
            RelPath::parse("caf\u{00e9}/src.txt").unwrap(),
            None,
        ))
        .await
        .unwrap()
        .unwrap();
    let copied = dst
        .server_side_copy(
            &src.endpoint_identity(),
            &BackendPath::from_entry(&src_entry),
            &UploadInit {
                op_id: "op-nfd-ssc".into(),
                dst_path: RelPath::parse("caf\u{00e9}/copied.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: src_entry.size,
                src_mtime_ns: src_entry.mtime_ns,
                planned_chunk_size: src_entry.size,
                checksums: vec![],
                precondition: rship_core::state::DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(copied.nfc_path.as_str(), "caf\u{00e9}/copied.txt");
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(copied.raw_path(), "cafe\u{0301}/copied.txt");
}

#[tokio::test]
async fn server_side_copy_large_file_preserves_content_and_accurate_mtime() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..(400 * 1024)).map(|i| (i % 251) as u8).collect();
    let src_file = src_dir.join("big.bin");
    std::fs::write(&src_file, &payload).unwrap();
    let mut perms = std::fs::metadata(&src_file).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&src_file, perms).unwrap();

    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    let bp = BackendPath::from_rel(RelPath::parse("big.bin").unwrap());
    let src_entry = src.stat(&bp).await.unwrap().unwrap();
    let copied = dst
        .server_side_copy(
            &src.endpoint_identity(),
            &bp,
            &UploadInit {
                op_id: "op-ssc-big".into(),
                dst_path: RelPath::parse("big.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: src_entry.size,
                src_mtime_ns: src_entry.mtime_ns,
                planned_chunk_size: src_entry.size,
                checksums: vec![],
                precondition: rship_core::state::DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    let dst_stat = dst.stat(&bp).await.unwrap().unwrap();
    assert_eq!(copied.mtime_ns, dst_stat.mtime_ns);
    assert_eq!(std::fs::read(dst_dir.join("big.bin")).unwrap(), payload);

    // Clear readonly so TempDir cleans up cleanly.
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut p = std::fs::metadata(&src_file).unwrap().permissions();
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&src_file, p);
    }
}

#[tokio::test]
async fn seekable_source_concurrent_reads_and_open_read_bounded_small_path() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("concurrent.bin");
    let data: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 199) as u8).collect();
    std::fs::write(&path, &data).unwrap();

    let backend = Arc::new(LocalBackend::new("conc", tmp.path()).unwrap());
    let bp = BackendPath::from_rel(RelPath::parse("concurrent.bin").unwrap());
    let DataSource::LocalSeekable(seek) = backend.open_read(&bp, None).await.unwrap() else {
        panic!("expected LocalSeekable");
    };

    let mut handles = Vec::new();
    for t in 0..8usize {
        let s = seek.clone();
        let expected = data[t * 32 * 1024..(t + 1) * 32 * 1024].to_vec();
        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let n = s.read_at((t * 32 * 1024) as u64, &mut buf).await.unwrap();
            assert_eq!(n, expected.len());
            assert_eq!(buf, expected);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Small-file bounded inline path (`range <= 64 KiB`).
    let small_path = tmp.path().join("small.bin");
    std::fs::write(&small_path, b"hello-small").unwrap();
    let small_bp = BackendPath::from_rel(RelPath::parse("small.bin").unwrap());
    let DataSource::LocalSeekable(mem) = backend
        .open_read(
            &small_bp,
            Some(rship_core::types::ByteRange { offset: 0, len: 11 }),
        )
        .await
        .unwrap()
    else {
        panic!("expected LocalSeekable");
    };
    let mut out = vec![0u8; 11];
    assert_eq!(mem.read_at(0, &mut out).await.unwrap(), 11);
    assert_eq!(&out, b"hello-small");

    // Replacing/truncating the file on disk must be detected on Windows `PlatformReadHandle`.
    #[cfg(windows)]
    {
        std::fs::write(&path, b"mutated").unwrap();
        let mut buf = vec![0u8; 16];
        let err = seek.read_at(0, &mut buf).await.unwrap_err();
        assert!(
            err.is_source_mutated(),
            "expected SourceMutated, got {err:?}"
        );
    }
}

#[tokio::test]
async fn compute_hash_supports_sha1_ignores_blake3_and_rejects_fifo_nonblocking() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("empty.bin"), b"").unwrap();
    std::fs::write(tmp.path().join("hw.bin"), b"hello world").unwrap();
    let big: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 131) as u8).collect();
    std::fs::write(tmp.path().join("big.bin"), &big).unwrap();

    let backend = LocalBackend::new("hash", tmp.path()).unwrap();
    assert!(backend.capabilities().hashes.contains(&HashKind::Sha1));

    let h_empty = backend
        .compute_hash(
            &BackendPath::from_rel(RelPath::parse("empty.bin").unwrap()),
            HashKind::Sha1,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_empty.hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let h_hw = backend
        .compute_hash(
            &BackendPath::from_rel(RelPath::parse("hw.bin").unwrap()),
            HashKind::Sha1,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_hw.hex, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");

    assert!(
        backend
            .compute_hash(
                &BackendPath::from_rel(RelPath::parse("big.bin").unwrap()),
                HashKind::Sha1
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        backend
            .compute_hash(
                &BackendPath::from_rel(RelPath::parse("hw.bin").unwrap()),
                HashKind::Blake3
            )
            .await
            .unwrap()
            .is_none()
    );

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let fifo = tmp.path().join("pipe.fifo");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_fifo` is a valid NUL-terminated path string.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            backend.compute_hash(
                &BackendPath::from_rel(RelPath::parse("pipe.fifo").unwrap()),
                HashKind::Sha256,
            ),
        )
        .await
        .expect("compute_hash on FIFO must not hang");
        assert_eq!(
            res.unwrap_err().kind,
            rship_core::error::ErrorKind::InvalidPath
        );
    }
}
