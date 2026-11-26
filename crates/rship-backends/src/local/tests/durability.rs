use super::super::*;
use futures::StreamExt;
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use tempfile::TempDir;

#[tokio::test]
async fn d3_missing_local_root_returns_not_found_and_blocks_deletes() {
    use rship_core::bisync::{BisyncConfig, BisyncEngine};
    use rship_core::error::ErrorKind;

    let tmp = TempDir::new().unwrap();
    let missing_root = tmp.path().join("unmounted_drive");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(dst_dir.join("precious.txt"), b"do-not-delete").unwrap();

    // 1. Direct `list_stream` on a missing local root MUST fail with NotFound.
    let missing_backend = Arc::new(LocalBackend::new("missing", &missing_root).unwrap());
    let list_res = missing_backend.list_stream(&RelPath::root(), true).await;
    let err = match list_res {
        Err(e) => e,
        Ok(mut stream) => {
            let mut found_err = None;
            while let Some(item) = stream.next().await {
                if let Err(e) = item {
                    found_err = Some(e);
                    break;
                }
            }
            found_err.expect("listing a missing local root MUST return NotFound error, not empty")
        }
    };
    assert_eq!(
        err.kind,
        ErrorKind::NotFound,
        "expected ErrorKind::NotFound for missing local root, got {err:?}"
    );

    // 2. `TransferEngine` sync with missing local source MUST fail and delete ZERO files in dst.
    let dst_backend = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d3-sync").unwrap());
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        missing_backend.clone(),
        dst_backend.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-d3-sync", JobMode::Sync, "missing", "dst");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(
        !rep.src_observation_complete,
        "missing local source root must mark src observation incomplete"
    );
    assert!(
        !rep.errors.is_empty(),
        "missing local source root must record an error"
    );
    assert_eq!(rep.items_deleted, 0);
    assert_eq!(
        std::fs::read(dst_dir.join("precious.txt")).unwrap(),
        b"do-not-delete",
        "sync from missing local root must NEVER delete destination files"
    );

    // 3. `BisyncEngine` with a missing local root on either side MUST fail and delete nothing.
    let bidx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d3-bisync").unwrap());
    let bisync = BisyncEngine::new(
        missing_backend,
        dst_backend,
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let bcfg = BisyncConfig::new("j-d3-bisync", "missing", "dst").with_resync(true);
    let brep = bisync.run(&bcfg, bidx).await.unwrap();
    assert!(
        !brep.a_observation_complete || !brep.errors.is_empty(),
        "bisync with missing local root must fail observation: {brep:?}"
    );
    assert_eq!(brep.deleted_on_a, 0);
    assert_eq!(brep.deleted_on_b, 0);
    assert!(dst_dir.join("precious.txt").exists());
}

#[tokio::test]
async fn d4_local_put_single_shot_and_server_side_copy_honor_precondition() {
    use rship_core::error::ErrorKind;
    use rship_core::state::DstPrecondition;

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    let rel = RelPath::parse("target.bin").unwrap();

    // Seed destination with initial content.
    let init_seed = UploadInit {
        op_id: "op-seed".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 8,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let seeded = dst
        .put_single_shot(
            &init_seed,
            Box::pin(futures::stream::once(async {
                Ok(bytes::Bytes::from_static(b"original"))
            })),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(dst_dir.join("target.bin")).unwrap(),
        b"original"
    );

    // 1. Small `put_single_shot` with `Absent` when file exists -> PreconditionFailed.
    let absent_small = UploadInit {
        op_id: "op-absent-small".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 7,
        src_mtime_ns: 1_700_000_001_000_000_000,
        planned_chunk_size: 7,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err = dst
        .put_single_shot(
            &absent_small,
            Box::pin(futures::stream::once(async {
                Ok(bytes::Bytes::from_static(b"clobber"))
            })),
        )
        .await
        .expect_err("put_single_shot(Absent) must reject existing file");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(
        std::fs::read(dst_dir.join("target.bin")).unwrap(),
        b"original"
    );

    // 2. Large (> 256 KiB) `put_single_shot` with `Absent` when file exists -> PreconditionFailed.
    let big_payload = vec![b'X'; 300 * 1024];
    let absent_large = UploadInit {
        op_id: "op-absent-large".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big_payload.len() as u64,
        src_mtime_ns: 1_700_000_002_000_000_000,
        planned_chunk_size: big_payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let big_c = big_payload.clone();
    let err = dst
        .put_single_shot(
            &absent_large,
            Box::pin(futures::stream::once(async move {
                Ok(bytes::Bytes::from(big_c))
            })),
        )
        .await
        .expect_err("large put_single_shot(Absent) must reject existing file");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(
        std::fs::read(dst_dir.join("target.bin")).unwrap(),
        b"original"
    );

    // 3. `put_single_shot` with stale `Existing { size, mtime_ns }` after concurrent edit -> PreconditionFailed.
    let stale_precond = DstPrecondition::Existing {
        node_id: seeded.node_id.clone(),
        etag: None,
        mtime_ns: seeded.mtime_ns,
        size: seeded.size,
    };
    std::fs::write(dst_dir.join("target.bin"), b"concurrently-edited-content").unwrap();
    let stale_put = UploadInit {
        op_id: "op-stale-existing".into(),
        dst_path: rel.clone(),
        existing_node_id: seeded.node_id.clone(),
        pregenerated_id: None,
        total_size: 9,
        src_mtime_ns: 1_700_000_003_000_000_000,
        planned_chunk_size: 9,
        checksums: vec![],
        precondition: stale_precond.clone(),
        src_etag: None,
    };
    let err = dst
        .put_single_shot(
            &stale_put,
            Box::pin(futures::stream::once(async {
                Ok(bytes::Bytes::from_static(b"overwrite"))
            })),
        )
        .await
        .expect_err("put_single_shot(Existing) must reject concurrently modified file");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(
        std::fs::read(dst_dir.join("target.bin")).unwrap(),
        b"concurrently-edited-content"
    );

    // 4. `server_side_copy` (small & large) must also honor `Absent` and stale `Existing`.
    std::fs::write(src_dir.join("small.bin"), b"from-ssc-small").unwrap();
    let small_meta = src
        .stat(&BackendPath::from_rel(RelPath::parse("small.bin").unwrap()))
        .await
        .unwrap()
        .unwrap();
    let ssc_absent = UploadInit {
        op_id: "op-ssc-absent".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: small_meta.size,
        src_mtime_ns: small_meta.mtime_ns,
        planned_chunk_size: small_meta.size,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err = dst
        .server_side_copy(
            &src.endpoint_identity(),
            &BackendPath::from_entry(&small_meta),
            &ssc_absent,
        )
        .await
        .expect_err("small server_side_copy(Absent) must reject existing file");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);

    std::fs::write(src_dir.join("large.bin"), &big_payload).unwrap();
    let large_meta = src
        .stat(&BackendPath::from_rel(RelPath::parse("large.bin").unwrap()))
        .await
        .unwrap()
        .unwrap();
    let ssc_stale = UploadInit {
        op_id: "op-ssc-stale".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: large_meta.size,
        src_mtime_ns: large_meta.mtime_ns,
        planned_chunk_size: large_meta.size,
        checksums: vec![],
        precondition: stale_precond,
        src_etag: None,
    };
    let err = dst
        .server_side_copy(
            &src.endpoint_identity(),
            &BackendPath::from_entry(&large_meta),
            &ssc_stale,
        )
        .await
        .expect_err("large server_side_copy(Existing) must reject concurrently modified file");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(
        std::fs::read(dst_dir.join("target.bin")).unwrap(),
        b"concurrently-edited-content"
    );

    // 5. Verify no leaked `.rship.part.*` staging files remain in dst_dir.
    for entry in std::fs::read_dir(&dst_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".rship.part."),
            "staging file `{name}` leaked after PreconditionFailed"
        );
    }
}

#[tokio::test]
async fn d8_mtime_granularity_and_racily_clean_guard() {
    use rship_core::planner::{PlanOptions, PlannedAction, plan_source_item};

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();

    // 1. Capabilities must report >= 10ms mtime granularity to guard coarse kernel ticks.
    let src_caps = src.capabilities();
    let dst_caps = dst.capabilities();
    assert!(
        src_caps.mtime_granularity >= Duration::from_millis(10),
        "local mtime_granularity must be >= 10ms, got {:?}",
        src_caps.mtime_granularity
    );
    // Windows timestamps tick at the ~15.6 ms system timer, so 10 ms is not enough there.
    #[cfg(windows)]
    assert!(
        src_caps.mtime_granularity >= Duration::from_millis(20),
        "Windows local mtime_granularity must be >= 20ms, got {:?}",
        src_caps.mtime_granularity
    );

    // 2. Two writes within the same 10ms tick (e.g. 2ms apart from scan start) with identical
    //    size and mtime MUST be treated as racily-clean (`needs_checksum_verify == true`).
    let rel = RelPath::parse("tick.txt").unwrap();
    let scan_started_ns = 1_700_000_000_005_000_000i64;
    let src_entry = Entry::file(rel.clone(), 16, 1_700_000_000_000_000_000);
    let dst_entry = Entry::file(rel.clone(), 16, 1_700_000_000_000_000_000);
    let opts = PlanOptions {
        delete: false,
        max_delete: None,
        checksum_mode: false,
        force_type_replace: false,
        scan_started_unix_ns: scan_started_ns,
        src_observation_complete: true,
        dst_observation_complete: true,
    };
    let action = plan_source_item(
        &src_entry,
        Some(&dst_entry),
        None,
        &src_caps,
        &dst_caps,
        &opts,
    );
    match action {
        PlannedAction::Transfer(pt) => {
            assert!(
                pt.needs_checksum_verify,
                "same-tick (5ms) write must trigger racily-clean checksum verification"
            );
        }
        other => panic!("expected racily-clean Transfer with checksum verify, got {other:?}"),
    }
}

#[tokio::test]
async fn d2_fsync_modes_always_batch_never_and_move_durability() {
    use rship_core::bisync::{BisyncConfig, BisyncEngine};
    use rship_core::types::FsyncMode;

    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    // Include both small (<= 256 KiB) and large (> 256 KiB) files to cover all local commit paths.
    std::fs::write(src_dir.join("small_a.txt"), b"hello-small-a").unwrap();
    std::fs::write(src_dir.join("small_b.txt"), b"hello-small-b").unwrap();
    std::fs::write(src_dir.join("large.bin"), vec![b'L'; 300 * 1024]).unwrap();

    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();

    // 1. Default mode is `FsyncMode::Batch`: deferred during writes, flushed once at end of run.
    let dst_batch_dir = tmp.path().join("dst_batch");
    let dst_batch = Arc::new(LocalBackend::new("dst-batch", &dst_batch_dir).unwrap());
    assert_eq!(dst_batch.fsync_mode(), FsyncMode::Batch);
    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let engine = TransferEngine::new(
        src.clone(),
        dst_batch.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-d2-batch", JobMode::Copy, "src", "dst-batch");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-batch").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "batch copy errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, 3);
    assert_eq!(
        dst_batch.batch_flush_count(),
        1,
        "Batch mode must run one flush_durable_writes() batch at run end"
    );
    assert!(
        dst_batch.fsync_count() >= 1,
        "Batch flush must execute at least one fsync/syncfs/FlushFileBuffers"
    );

    // 2. `FsyncMode::Always`: every committed file fsyncs immediately, no batch flush needed.
    let dst_always_dir = tmp.path().join("dst_always");
    let dst_always = Arc::new(
        LocalBackend::new("dst-always", &dst_always_dir)
            .unwrap()
            .with_fsync_mode(FsyncMode::Always),
    );
    assert_eq!(dst_always.fsync_mode(), FsyncMode::Always);
    let engine = TransferEngine::new(
        src.clone(),
        dst_always.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-d2-always", JobMode::Copy, "src", "dst-always");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-always").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "always copy errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, 3);
    assert_eq!(
        dst_always.fsync_count(),
        3,
        "Always mode must fsync every committed file (small + large)"
    );
    assert_eq!(dst_always.batch_flush_count(), 0);

    // Also verify `put_single_shot` (non-SSC streaming) & `finish_upload` honor Always vs Never.
    let dst_stream_dir = tmp.path().join("dst_stream");
    let dst_stream = Arc::new(
        LocalBackend::new("dst-stream", &dst_stream_dir)
            .unwrap()
            .with_fsync_mode(FsyncMode::Always)
            .with_chunking(64 * 1024, 32 * 1024),
    );
    let mut cfg_stream = EngineConfig::new("j-d2-stream", JobMode::Copy, "src", "dst-stream");
    cfg_stream.allow_server_side_copy = false;
    let engine = TransferEngine::new(
        src.clone(),
        dst_stream.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let rep = engine
        .run(
            &cfg_stream,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-stream").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "stream copy errors: {:?}", rep.errors);
    assert_eq!(
        dst_stream.fsync_count(),
        3,
        "Always mode must fsync put_single_shot AND multipart finish_upload"
    );

    // 3. `FsyncMode::Never` on `copy` performs ZERO fsyncs...
    let dst_never_dir = tmp.path().join("dst_never");
    let dst_never = Arc::new(
        LocalBackend::new("dst-never", &dst_never_dir)
            .unwrap()
            .with_fsync_mode(FsyncMode::Never),
    );
    let engine = TransferEngine::new(
        src.clone(),
        dst_never.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg_never = EngineConfig::new("j-d2-never", JobMode::Copy, "src", "dst-never");
    let rep = engine
        .run(
            &cfg_never,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-never").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success());
    assert_eq!(dst_never.fsync_count(), 0);
    assert_eq!(dst_never.batch_flush_count(), 0);

    // 4. ...HOWEVER, `move` MUST STILL durably sync the destination file BEFORE deleting source,
    //    even when destination is configured with `FsyncMode::Never`!
    let move_src_dir = tmp.path().join("move_src");
    let move_dst_dir = tmp.path().join("move_dst");
    std::fs::create_dir_all(&move_src_dir).unwrap();
    std::fs::write(move_src_dir.join("m1.txt"), b"move-payload-1").unwrap();
    std::fs::write(move_src_dir.join("m2.txt"), b"move-payload-2").unwrap();
    let move_src = Arc::new(LocalBackend::new("move-src", &move_src_dir).unwrap());
    let move_dst = Arc::new(
        LocalBackend::new("move-dst", &move_dst_dir)
            .unwrap()
            .with_fsync_mode(FsyncMode::Never),
    );
    let engine = TransferEngine::new(
        move_src,
        move_dst.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg_move = EngineConfig::new("j-d2-move", JobMode::Move, "move-src", "move-dst");
    let rep = engine
        .run(
            &cfg_move,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-move").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "move errors: {:?}", rep.errors);
    assert_eq!(rep.sources_deleted, 2);
    assert!(!move_src_dir.join("m1.txt").exists());
    assert!(!move_src_dir.join("m2.txt").exists());
    assert_eq!(
        move_dst.fsync_count(),
        2,
        "move MUST call sync_durable_file before deleting every source even in FsyncMode::Never"
    );

    // 5. `BisyncEngine` in `Batch` mode flushes pending writes on both sides before Phase 3 / baseline commit.
    let side_a_dir = tmp.path().join("bisync_a");
    let side_b_dir = tmp.path().join("bisync_b");
    std::fs::create_dir_all(&side_a_dir).unwrap();
    std::fs::create_dir_all(&side_b_dir).unwrap();
    std::fs::write(side_a_dir.join("from_a.txt"), b"a-data").unwrap();
    std::fs::write(side_b_dir.join("from_b.txt"), b"b-data").unwrap();
    let side_a = Arc::new(LocalBackend::new("a", &side_a_dir).unwrap());
    let side_b = Arc::new(LocalBackend::new("b", &side_b_dir).unwrap());
    let bisync = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let bcfg = BisyncConfig::new("j-d2-bisync", "a", "b").with_resync(true);
    let brep = bisync
        .run(
            &bcfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-bisync").unwrap()),
        )
        .await
        .unwrap();
    assert!(brep.is_success(), "bisync errors: {:?}", brep.errors);
    assert_eq!(side_a.batch_flush_count(), 1);
    assert_eq!(side_b.batch_flush_count(), 1);
    assert!(side_a.fsync_count() >= 1);
    assert!(side_b.fsync_count() >= 1);
}

#[cfg(unix)]
fn small_init(op_id: &str, rel: &str, len: u64) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: RelPath::parse(rel).unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: len,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: len.max(1),
        checksums: vec![],
        precondition: rship_core::state::DstPrecondition::Absent,
        src_etag: None,
    }
}

#[cfg(unix)]
async fn put_small(dst: &LocalBackend, op_id: &str, rel: &str, payload: &'static [u8]) {
    dst.put_single_shot(
        &small_init(op_id, rel, payload.len() as u64),
        Box::pin(futures::stream::once(async move {
            Ok(bytes::Bytes::from_static(payload))
        })),
    )
    .await
    .unwrap();
}

/// Per-path batch fallback (the macOS / BSD path) as a Linux test can force it.
fn per_path_flush() -> fs_util::BatchFlushOptions {
    fs_util::BatchFlushOptions {
        allow_syncfs: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn d2_batch_fsync_flushes_wide_file_batch_cleanly() {
    use rship_core::types::FsyncMode;

    const COUNT: usize = 64;
    const DIRS: usize = 4;
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    for d in 0..DIRS {
        std::fs::create_dir_all(src_dir.join(format!("d{d}"))).unwrap();
    }
    for i in 0..COUNT {
        std::fs::write(
            src_dir.join(format!("d{}/file_{i:03}.bin", i % DIRS)),
            format!("payload-{i:03}").as_bytes(),
        )
        .unwrap();
    }

    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    // Force the per-path fallback so Linux exercises the parallel file + directory pass.
    let dst = Arc::new(
        LocalBackend::new("dst", &dst_dir)
            .unwrap()
            .with_batch_flush_options(per_path_flush()),
    );
    assert_eq!(dst.fsync_mode(), FsyncMode::Batch);
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        src,
        dst.clone(),
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-d2-wide-batch", JobMode::Copy, "src", "dst");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-d2-wide-batch").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "wide batch copy errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, COUNT as u64);
    assert_eq!(dst.batch_flush_count(), 1);
    assert_eq!(
        dst.fsync_count(),
        COUNT as u64,
        "the per-path fallback must fsync every written file exactly once"
    );
    #[cfg(unix)]
    assert!(
        dst.dir_fsync_count() >= DIRS as u64,
        "the per-path fallback must also fsync every parent directory, got {}",
        dst.dir_fsync_count()
    );
    for i in 0..COUNT {
        assert_eq!(
            std::fs::read(dst_dir.join(format!("d{}/file_{i:03}.bin", i % DIRS))).unwrap(),
            format!("payload-{i:03}").as_bytes()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn d2_batch_flush_failure_keeps_every_pending_path() {
    let tmp = TempDir::new().unwrap();
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir)
        .unwrap()
        .with_batch_flush_options(per_path_flush());
    put_small(&dst, "op-x", "a/x.bin", b"x-data").await;
    put_small(&dst, "op-y", "a/y.bin", b"y-data").await;
    put_small(&dst, "op-z", "b/z.bin", b"z-data").await;

    // Make `a/x.bin` and `a/y.bin` unopenable (`ENOTDIR`) so the batch fails part-way.
    std::fs::rename(dst_dir.join("a"), dst_dir.join("a_moved")).unwrap();
    std::fs::write(dst_dir.join("a"), b"not a directory").unwrap();
    dst.flush_durable_writes()
        .await
        .expect_err("a batch with an unopenable path must fail");
    let after_failure = dst.fsync_count();

    // Repair the tree: the retry must sync all three files again, not just what was left.
    std::fs::remove_file(dst_dir.join("a")).unwrap();
    std::fs::rename(dst_dir.join("a_moved"), dst_dir.join("a")).unwrap();
    dst.flush_durable_writes().await.unwrap();
    assert_eq!(
        dst.fsync_count() - after_failure,
        3,
        "a failed batch must keep every pending path for the next flush"
    );
    assert_eq!(dst.batch_flush_count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn d2_syncfs_eio_propagates_and_only_unsupported_errors_fall_back() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("f.bin");
    std::fs::write(&file, b"data").unwrap();
    let files: HashSet<PathBuf> = [file].into_iter().collect();
    let dirs: HashSet<PathBuf> = [tmp.path().to_path_buf()].into_iter().collect();
    let with_errno = |errno| fs_util::BatchFlushOptions {
        allow_syncfs: true,
        syncfs_errno: Some(errno),
    };

    let err = fs_util::flush_pending_batch(tmp.path(), &files, &dirs, &with_errno(libc::EIO))
        .expect_err("syncfs EIO is a write-back failure and must not fall back");
    assert!(
        err.to_string().contains("syncfs"),
        "unexpected error: {err}"
    );

    for errno in [libc::ENOSYS, libc::EPERM, libc::EOPNOTSUPP] {
        let stats = fs_util::flush_pending_batch(tmp.path(), &files, &dirs, &with_errno(errno))
            .unwrap_or_else(|e| panic!("errno {errno} must fall back to per-path fsync: {e}"));
        assert!(!stats.syncfs);
        assert_eq!(stats.files, 1);
        assert_eq!(stats.dirs, 1);
    }

    let stats = fs_util::flush_pending_batch(
        tmp.path(),
        &files,
        &dirs,
        &fs_util::BatchFlushOptions::default(),
    )
    .unwrap();
    assert!(stats.syncfs, "a working syncfs covers the whole batch");
}

#[cfg(unix)]
#[test]
fn d2_parent_directory_fsync_errors_propagate() {
    use std::os::unix::fs::PermissionsExt;
    // Root can open any directory, so the permission trick below needs an unprivileged user.
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("wx_only");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("f.bin");
    std::fs::write(&file, b"data").unwrap();
    // `-wx`: the file inside stays reachable but the directory cannot be opened for fsync.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    let res = fs_util::sync_file_and_parent(&file, &[]);
    let part = tmp.path().join("wx_only/part");
    std::fs::write(&part, b"p").unwrap();
    let replace = fs_util::atomic_replace(&part, &file, true, true);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    res.expect_err("an unopenable parent directory must fail the durable sync");
    replace.expect_err("an unopenable parent directory must fail a durable atomic_replace");
}

#[cfg(unix)]
#[tokio::test]
async fn d2_durable_sync_fsyncs_newly_created_intermediate_dirs() {
    let tmp = TempDir::new().unwrap();
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    put_small(&dst, "op-deep", "n1/n2/f.bin", b"deep").await;

    let before = dst.dir_fsync_count();
    dst.sync_durable_file(&BackendPath::from_rel(
        RelPath::parse("n1/n2/f.bin").unwrap(),
    ))
    .await
    .unwrap();
    // `n1/n2` (holds `f.bin`), `n1` (holds the new `n2`), and the root (holds the new `n1`).
    assert_eq!(dst.dir_fsync_count() - before, 3);

    // A second file in the same, now durable, directories only needs its own parent.
    put_small(&dst, "op-deep2", "n1/n2/g.bin", b"deep2").await;
    let before = dst.dir_fsync_count();
    dst.sync_durable_file(&BackendPath::from_rel(
        RelPath::parse("n1/n2/g.bin").unwrap(),
    ))
    .await
    .unwrap();
    assert_eq!(dst.dir_fsync_count() - before, 1);
}

/// Seed the state a power loss can leave behind in `FsyncMode::Batch`: the destination file
/// was renamed into place with the right size and mtime, but its data never reached disk
/// (zeros), and its operation is still `Completing` because the durability fence retires it
/// only after the batch flush that never happened.
async fn seed_power_loss_leftover(
    journal: &Arc<StateActor>,
    src: &LocalBackend,
    src_dir: &std::path::Path,
    dst: &LocalBackend,
    dst_dir: &std::path::Path,
    name: &str,
    payload: &[u8],
) {
    use rship_core::state::{
        DstPrecondition, JournalStore, OperationRecord, OperationState, SourceVersion,
        compute_session_key,
    };
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    std::fs::write(src_dir.join(name), payload).unwrap();
    std::fs::File::options()
        .write(true)
        .open(src_dir.join(name))
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    std::fs::write(dst_dir.join(name), vec![0u8; payload.len()]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(dst_dir.join(name))
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let rel = RelPath::parse(name).unwrap();
    let src_entry = src
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let op = OperationRecord {
        op_id: format!("op-leftover-{name}"),
        session_key: compute_session_key(
            &src.endpoint_identity(),
            name,
            &dst.endpoint_identity(),
            &rel,
        ),
        job_id: "j-crashed".into(),
        src_endpoint: src.endpoint_identity(),
        dst_endpoint: dst.endpoint_identity(),
        src_raw_path: name.into(),
        dst_raw_path: name.into(),
        dst_nfc_path: rel,
        src_version: SourceVersion::from_entry(&src_entry),
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "local".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: payload.len() as u64,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        expires_at: None,
    };
    journal.put_operation(&op).await.unwrap();
}

#[tokio::test]
async fn d2_leftover_unflushed_file_with_matching_metadata_is_retransferred() {
    use rship_core::state::JournalStore;
    for mode in [JobMode::Sync, JobMode::Move] {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();
        let src = LocalBackend::new("src", &src_dir).unwrap();
        let dst = LocalBackend::new("dst", &dst_dir).unwrap();
        let journal = Arc::new(StateActor::open(&state_dir).unwrap());
        let payload = b"precious data that never reached the disk";
        seed_power_loss_leftover(&journal, &src, &src_dir, &dst, &dst_dir, "doc.txt", payload)
            .await;

        let engine = TransferEngine::new(
            Arc::new(src),
            Arc::new(dst),
            journal.clone(),
            BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap(),
            SystemClock::shared(),
            CancelFlag::new(),
        );
        let job = format!("j-leftover-{}", mode.as_str());
        let cfg = EngineConfig::new(&job, mode, "src", "dst");
        let rep = engine
            .run(
                &cfg,
                Arc::new(SqliteSyncIndex::open_temp(&state_dir, &job).unwrap()),
            )
            .await
            .unwrap();
        assert!(rep.is_success(), "{mode:?}: {:?}", rep.errors);
        assert_eq!(
            std::fs::read(dst_dir.join("doc.txt")).unwrap(),
            payload,
            "{mode:?}: a size+mtime match must not vouch for a file left by an unflushed batch"
        );
        assert!(
            journal.list_active_operations().await.unwrap().is_empty(),
            "{mode:?}: the leftover operation must be retired"
        );
        if mode == JobMode::Move {
            assert!(!src_dir.join("doc.txt").exists());
        }
    }
}

#[tokio::test]
async fn d2_leftover_intact_file_is_trusted_after_hash_check() {
    use rship_core::state::JournalStore;
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let payload = b"intact after a process crash";
    seed_power_loss_leftover(&journal, &src, &src_dir, &dst, &dst_dir, "ok.txt", payload).await;
    // A process crash (not a power loss) leaves the data intact in the page cache.
    let mtime = std::fs::metadata(dst_dir.join("ok.txt"))
        .unwrap()
        .modified()
        .unwrap();
    std::fs::write(dst_dir.join("ok.txt"), payload).unwrap();
    std::fs::File::options()
        .write(true)
        .open(dst_dir.join("ok.txt"))
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let engine = TransferEngine::new(
        Arc::new(src),
        Arc::new(dst),
        journal.clone(),
        BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-leftover-ok", JobMode::Sync, "src", "dst");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-leftover-ok").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(
        rep.files_transferred, 0,
        "a verified intact file is not copied again"
    );
    assert_eq!(rep.files_skipped, 1);
    assert!(journal.list_active_operations().await.unwrap().is_empty());
}

#[tokio::test]
async fn d2_bisync_leftover_unflushed_copy_is_redone_not_baselined() {
    use rship_core::bisync::{BisyncConfig, BisyncEngine};
    use rship_core::state::JournalStore;
    let tmp = TempDir::new().unwrap();
    let a_dir = tmp.path().join("a");
    let b_dir = tmp.path().join("b");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();
    let side_a = LocalBackend::new("a", &a_dir).unwrap();
    let side_b = LocalBackend::new("b", &b_dir).unwrap();
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let payload = b"bisync payload lost by the power cut";
    seed_power_loss_leftover(&journal, &side_a, &a_dir, &side_b, &b_dir, "x.txt", payload).await;

    let engine = BisyncEngine::new(
        Arc::new(side_a),
        Arc::new(side_b),
        journal.clone(),
        BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = BisyncConfig::new("j-bisync-leftover", "a", "b");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-bisync-leftover").unwrap()),
        )
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(std::fs::read(b_dir.join("x.txt")).unwrap(), payload);
    assert_eq!(std::fs::read(a_dir.join("x.txt")).unwrap(), payload);
    assert!(journal.list_active_operations().await.unwrap().is_empty());
}

#[tokio::test]
async fn d3_files_from_with_missing_source_root_is_an_error() {
    use rship_core::filter::{FilterOptions, FilterSet};

    let tmp = TempDir::new().unwrap();
    let missing_root = tmp.path().join("unmounted");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(dst_dir.join("keep.txt"), b"keep").unwrap();
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let filter = FilterSet::from_options(&FilterOptions {
        files_from: Some(vec!["a.txt".into(), "keep.txt".into()]),
        ..Default::default()
    })
    .unwrap();

    // (copy, streaming `run_file_list`) and (sync --delete --no-traverse, indexed observation).
    for (job, mode, delete) in [
        ("j-ff-copy", JobMode::Copy, false),
        ("j-ff-sync", JobMode::Sync, true),
    ] {
        let engine = TransferEngine::new(
            Arc::new(LocalBackend::new("missing", &missing_root).unwrap()),
            Arc::new(LocalBackend::new("dst", &dst_dir).unwrap()),
            journal.clone(),
            BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
            SystemClock::shared(),
            CancelFlag::new(),
        );
        let mut cfg = EngineConfig::new(job, mode, "missing", "dst");
        cfg.filter = filter.clone();
        cfg.delete = delete;
        cfg.no_traverse = delete;
        let rep = engine
            .run(
                &cfg,
                Arc::new(SqliteSyncIndex::open_temp(&state_dir, job).unwrap()),
            )
            .await
            .unwrap();
        assert!(
            !rep.is_success() && !rep.src_observation_complete,
            "{job}: --files-from from a missing source root must fail, got {rep:?}"
        );
        assert!(
            rep.errors.iter().any(|e| e.contains("does not exist")),
            "{job}: {:?}",
            rep.errors
        );
        assert_eq!(rep.items_deleted, 0);
        assert!(dst_dir.join("keep.txt").exists());
    }
}

/// `reconcile_operation` must never accept a pre-existing file just because its size and
/// mtime match the source: on Unix the publication rename installs a new inode, so an
/// unchanged inode proves the operation never committed.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_never_accepts_an_older_same_size_same_mtime_file() {
    use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
    let tmp = TempDir::new().unwrap();
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let old = dst_dir.join("f.bin");
    std::fs::write(&old, b"old content!").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let rel = RelPath::parse("f.bin").unwrap();
    let old_entry = dst
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let mut op = OperationRecord {
        op_id: "op-reconcile-local".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: dst.endpoint_identity(),
        src_raw_path: "f.bin".into(),
        dst_raw_path: "f.bin".into(),
        dst_nfc_path: rel.clone(),
        // The new source has the same size and mtime but different bytes.
        src_version: SourceVersion {
            node_id: None,
            size: old_entry.size,
            mtime_ns: old_entry.mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Existing {
            node_id: old_entry.node_id.clone(),
            etag: old_entry.etag.clone(),
            mtime_ns: old_entry.mtime_ns,
            size: old_entry.size,
        },
        existing_dst_node_id: old_entry.node_id.clone(),
        remote_op_id: None,
        backend_kind: "local".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: old_entry.size,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let outcome = dst.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "unchanged inode must not be accepted: {outcome:?}"
    );

    // No recorded pre-op file: cannot be proven ours either.
    op.dst_precondition = DstPrecondition::Any;
    let outcome = dst.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "{outcome:?}"
    );

    // A rename that installed a new inode with the source size and mtime is ours.
    op.dst_precondition = DstPrecondition::Existing {
        node_id: old_entry.node_id.clone(),
        etag: None,
        mtime_ns: old_entry.mtime_ns,
        size: old_entry.size,
    };
    let staged = dst_dir.join("f.bin.staged");
    std::fs::write(&staged, b"new content!").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&staged)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    std::fs::rename(&staged, &old).unwrap();
    let outcome = dst.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "{outcome:?}"
    );
}

/// Engine-level guard: a crashed `move` left a `Completing` op whose destination still holds
/// the OLDER file, with exactly the new source's size and mtime. The next `move` must copy
/// the new content before deleting the source, never trusting the old file.
#[cfg(unix)]
#[tokio::test]
async fn move_never_trusts_an_older_same_size_destination_left_by_a_crash() {
    use rship_core::state::{
        DstPrecondition, JournalStore, OperationRecord, OperationState, SourceVersion,
        compute_session_key,
    };
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for (dir, body) in [
        (&src_dir, &b"NEW precious bytes"[..]),
        (&dst_dir, &b"old stale  bytes!!"[..]),
    ] {
        std::fs::write(dir.join("doc.txt"), body).unwrap();
        std::fs::File::options()
            .write(true)
            .open(dir.join("doc.txt"))
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }
    let src = LocalBackend::new("src", &src_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir).unwrap();
    let rel = RelPath::parse("doc.txt").unwrap();
    let src_entry = src
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let dst_entry = dst
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    journal
        .put_operation(&OperationRecord {
            op_id: "op-crashed-move".into(),
            session_key: compute_session_key(
                &src.endpoint_identity(),
                "doc.txt",
                &dst.endpoint_identity(),
                &rel,
            ),
            job_id: "j-crashed".into(),
            src_endpoint: src.endpoint_identity(),
            dst_endpoint: dst.endpoint_identity(),
            src_raw_path: "doc.txt".into(),
            dst_raw_path: "doc.txt".into(),
            dst_nfc_path: rel.clone(),
            src_version: SourceVersion::from_entry(&src_entry),
            dst_precondition: DstPrecondition::Existing {
                node_id: dst_entry.node_id.clone(),
                etag: dst_entry.etag.clone(),
                mtime_ns: dst_entry.mtime_ns,
                size: dst_entry.size,
            },
            existing_dst_node_id: dst_entry.node_id.clone(),
            remote_op_id: None,
            backend_kind: "local".into(),
            session_token: None,
            backend_meta: String::new(),
            planned_chunk_size: src_entry.size,
            confirmed_offset: 0,
            state: OperationState::Completing,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            expires_at: None,
        })
        .await
        .unwrap();

    let engine = TransferEngine::new(
        Arc::new(src),
        Arc::new(dst),
        journal.clone(),
        BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-move-after-crash", JobMode::Move, "src", "dst");
    let rep = engine
        .run(
            &cfg,
            Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-move-after-crash").unwrap()),
        )
        .await
        .unwrap();
    let dst_now = std::fs::read(dst_dir.join("doc.txt")).unwrap();
    let src_left = src_dir.join("doc.txt").exists();
    assert!(
        dst_now == b"NEW precious bytes" || src_left,
        "data loss: source deleted while destination holds the old bytes ({:?})",
        rep.errors
    );
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(dst_now, b"NEW precious bytes");
    assert!(!src_left, "a verified move removes the source");
}

#[tokio::test]
async fn durability_tracker_prunes_created_dirs_after_per_path_batch_flush() {
    let tmp = TempDir::new().unwrap();
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&dst_dir).unwrap();
    let dst = LocalBackend::new("dst", &dst_dir)
        .unwrap()
        .with_batch_flush_options(per_path_flush());

    let rel_a = RelPath::parse("n1/n2/a.bin").unwrap();
    dst.put_single_shot(
        &UploadInit {
            op_id: "op-prune-a".into(),
            dst_path: rel_a.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 4,
            src_mtime_ns: 100,
            planned_chunk_size: 4,
            checksums: vec![],
            precondition: rship_core::state::DstPrecondition::Absent,
            src_etag: None,
        },
        Box::pin(futures::stream::once(async {
            Ok(bytes::Bytes::from_static(b"aaaa"))
        })),
    )
    .await
    .unwrap();
    dst.flush_durable_writes().await.unwrap();

    // Now write a sibling in `n1/n2` and call `sync_durable_file`: because `created_dirs`
    // was pruned during the per-path batch flush, only `n1/n2` (1 dir on Unix, 0 on Windows)
    // needs to be synced, NOT `n1` or `root` again.
    let rel_b = RelPath::parse("n1/n2/b.bin").unwrap();
    dst.put_single_shot(
        &UploadInit {
            op_id: "op-prune-b".into(),
            dst_path: rel_b.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 4,
            src_mtime_ns: 100,
            planned_chunk_size: 4,
            checksums: vec![],
            precondition: rship_core::state::DstPrecondition::Absent,
            src_etag: None,
        },
        Box::pin(futures::stream::once(async {
            Ok(bytes::Bytes::from_static(b"bbbb"))
        })),
    )
    .await
    .unwrap();
    let before = dst.dir_fsync_count();
    dst.sync_durable_file(&BackendPath::from_rel(rel_b))
        .await
        .unwrap();
    #[cfg(unix)]
    assert_eq!(dst.dir_fsync_count() - before, 1);
    #[cfg(windows)]
    assert_eq!(dst.dir_fsync_count() - before, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn precondition_existing_checks_unix_inode_and_absent_is_atomic() {
    use rship_core::error::ErrorKind;
    use rship_core::state::DstPrecondition;

    let tmp = TempDir::new().unwrap();
    let dst = LocalBackend::new("dst", tmp.path()).unwrap();
    let rel = RelPath::parse("inode.bin").unwrap();
    let path = tmp.path().join("inode.bin");
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    std::fs::write(&path, b"12345678").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let st1 = dst
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();

    // Replace with a brand-new inode having identical size & mtime.
    let replacement = tmp.path().join("inode.new");
    std::fs::write(&replacement, b"abcdefgh").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    std::fs::rename(&replacement, &path).unwrap();

    let err = dst
        .put_single_shot(
            &UploadInit {
                op_id: "op-inode-pre".into(),
                dst_path: rel,
                existing_node_id: st1.node_id.clone(),
                pregenerated_id: None,
                total_size: 4,
                src_mtime_ns: 100,
                planned_chunk_size: 4,
                checksums: vec![],
                precondition: DstPrecondition::Existing {
                    node_id: st1.node_id,
                    etag: None,
                    mtime_ns: st1.mtime_ns,
                    size: st1.size,
                },
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(bytes::Bytes::from_static(b"xxxx"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
}

#[cfg(unix)]
#[test]
fn is_fullfsync_unsupported_matches_only_expected_errnos() {
    use super::super::fs_util::is_fullfsync_unsupported;
    for errno in [libc::ENOTSUP, libc::EINVAL, libc::EOPNOTSUPP, libc::ENOTTY] {
        assert!(is_fullfsync_unsupported(
            &std::io::Error::from_raw_os_error(errno)
        ));
    }
    for errno in [libc::EIO, libc::EBADF] {
        assert!(!is_fullfsync_unsupported(
            &std::io::Error::from_raw_os_error(errno)
        ));
    }
}

#[test]
fn fs_name_mtime_granularity_returns_2s_for_fat_variants() {
    use super::super::fs_util::fs_name_mtime_granularity;
    for fat in ["FAT", "FAT32", "fat32", "vfat", "msdos", "FAT16"] {
        assert_eq!(fs_name_mtime_granularity(fat), Duration::from_secs(2));
    }
    #[cfg(windows)]
    assert_eq!(fs_name_mtime_granularity("NTFS"), Duration::from_millis(20));
    #[cfg(not(windows))]
    assert_eq!(fs_name_mtime_granularity("ext4"), Duration::from_millis(10));
}
