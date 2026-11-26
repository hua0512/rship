use super::super::*;
use crate::backend::StorageBackend;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::path::RelPath;
use crate::state::{JobMode, JournalStore};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn dst_sequential_resumes_through_429_partial_drop_expiry_and_ambiguous_commit() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    let payload: Vec<u8> = (0..(700 * 1024)).map(|i| (i % 251) as u8).collect();
    src.insert_file("big.bin", payload.clone(), 1_700_000_000_000_000_000);

    // Inject ALL major faults in one run: 429, mid-chunk partial drop (308 recovery),
    // session expiry, AND lost final 200 OK response!
    dst.set_faults(FaultSchedule {
        fail_chunk_rate_limit_remaining: 2,
        drop_after_partial_chunk_remaining: 1,
        expire_session_remaining: 1,
        drop_final_commit_response_remaining: 1,
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_100));
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-1", JobMode::Copy, "src:", "dst:");
    cfg.base_retry_delay = Duration::from_millis(1);
    cfg.max_retries = 5;

    // First run triggers lost final commit response (ambiguous commit!).
    let r1 = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(
        r1.errors.is_empty()
            || dst.get_file_bytes("big.bin").as_deref() == Some(payload.as_slice())
    );

    // Re-running MUST reconcile the ambiguous commit via `reconcile_operation`
    // without corrupting or re-uploading, and retire the operation cleanly!
    let r2 = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(r2.errors.is_empty(), "errors: {:?}", r2.errors);
    assert_eq!(
        dst.get_file_bytes("big.bin").as_deref(),
        Some(payload.as_slice())
    );
    assert!(journal.list_active_operations().await.unwrap().is_empty());
    assert_eq!(pool.stats().in_use_units, 0);
    assert!(pool.stats().peak_units <= pool.stats().max_units);
}

#[tokio::test]
async fn dst_parallel_multipart_s3_converges_bit_exact() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::parallel_s3_like("s3", 128 * 1024));
    let payload: Vec<u8> = (0..(600 * 1024)).map(|i| ((i * 31) % 256) as u8).collect();
    src.insert_file("archive.tar", payload.clone(), 1_700_000_000_000_000_000);

    dst.set_faults(FaultSchedule {
        fail_chunk_rate_limit_remaining: 2,
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_200));
    let engine = TransferEngine::new(
        src,
        dst.clone(),
        journal.clone(),
        pool.clone(),
        clock,
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-s3", JobMode::Copy, "src:", "s3:");
    cfg.base_retry_delay = Duration::from_millis(1);
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(
        dst.get_file_bytes("archive.tar").as_deref(),
        Some(payload.as_slice())
    );
    assert_eq!(dst.active_session_count(), 0);
    assert_eq!(pool.stats().in_use_units, 0);
}

#[tokio::test]
async fn dst_same_length_middle_edit_aborts_and_never_pollutes_baseline() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    let payload = vec![0xAAu8; 600 * 1024];
    src.insert_file("live.db", payload, 1_700_000_000_000_000_000);

    // Mutate the middle byte of `live.db` right on chunk #2!
    src.set_faults(FaultSchedule {
        mutate_source_after_reads: Some(("live.db".into(), 2)),
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_300));
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool,
        clock,
        CancelFlag::new(),
    );

    let cfg = EngineConfig::new("job-live", JobMode::Copy, "src:", "dst:");
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep.errors.is_empty(), "expected SourceMutated error");
    assert!(
        dst.get_file_bytes("live.db").is_none(),
        "mutated hybrid file must NEVER commit"
    );
    let pair_key =
        crate::state::compute_pair_key(&src.endpoint_identity(), &dst.endpoint_identity());
    assert!(
        journal
            .get_baseline(&pair_key, &RelPath::parse("live.db").unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn dst_partial_source_listing_blocks_all_deletes() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    dst.insert_file(
        "precious.txt",
        b"do not wipe".to_vec(),
        1_700_000_000_000_000_000,
    );
    src.set_faults(FaultSchedule {
        inject_list_error: true,
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_400));
    let engine = TransferEngine::new(src, dst.clone(), journal, pool, clock, CancelFlag::new());

    let cfg = EngineConfig::new("job-sync", JobMode::Sync, "src:", "dst:");
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep.src_observation_complete);
    assert_eq!(rep.items_deleted, 0);
    assert!(dst.get_file_bytes("precious.txt").is_some());
}

#[tokio::test]
async fn dst_duplicate_nfc_names_emit_conflict_and_protect_destination() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    // Insert both NFC and NFD variants in source!
    src.insert_file("caf\u{00e9}.txt", b"nfc".to_vec(), 100);
    src.insert_file("cafe\u{0301}.txt", b"nfd".to_vec(), 200);
    dst.insert_file("caf\u{00e9}.txt", b"existing".to_vec(), 50);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_500));
    let engine = TransferEngine::new(src, dst.clone(), journal, pool, clock, CancelFlag::new());

    let cfg = EngineConfig::new("job-dup", JobMode::Sync, "src:", "dst:");
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep.conflicts.is_empty());
    // Conflicted file on dst must remain untouched!
    assert_eq!(
        dst.get_file_bytes("caf\u{00e9}.txt").as_deref(),
        Some(b"existing".as_slice())
    );
}

#[tokio::test]
async fn conformance_suite_passes_on_chaos_sequential_and_parallel() {
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let seq = Arc::new(ChaosBackend::sequential_gdrive_like("seq", 256 * 1024));
    crate::conformance::run_backend_conformance(seq, clock.clone()).await;

    let par = Arc::new(ChaosBackend::parallel_s3_like("par", 128 * 1024));
    crate::conformance::run_backend_conformance(par, clock).await;
}

#[tokio::test]
async fn dst_overlap_detection_blocks_nested_and_allows_excluded() {
    let same = Arc::new(ChaosBackend::sequential_gdrive_like("bucket", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_600));
    let engine = TransferEngine::new(
        same.clone(),
        same.clone(),
        journal,
        pool,
        clock,
        CancelFlag::new(),
    );

    // 1. Same root -> fatal overlap error.
    let cfg_same = EngineConfig::new("ov-1", JobMode::Sync, "b:", "b:");
    assert!(
        engine
            .run(&cfg_same, Arc::new(InMemorySyncIndex::default()))
            .await
            .is_err()
    );

    // 2. dst inside src without exclude -> fatal overlap error.
    let mut cfg_nested = EngineConfig::new("ov-2", JobMode::Sync, "b:", "b:sub");
    cfg_nested.dst_prefix = RelPath::parse("sub").unwrap();
    assert!(
        engine
            .run(&cfg_nested, Arc::new(InMemorySyncIndex::default()))
            .await
            .is_err()
    );

    // 3. src inside dst -> fatal overlap error.
    let mut cfg_parent = EngineConfig::new("ov-3", JobMode::Sync, "b:sub", "b:");
    cfg_parent.src_prefix = RelPath::parse("sub").unwrap();
    assert!(
        engine
            .run(&cfg_parent, Arc::new(InMemorySyncIndex::default()))
            .await
            .is_err()
    );

    // 4. dst inside src WITH `--exclude sub/` -> allowed (rclone TestSyncOverlapWithFilter)!
    let mut cfg_filtered = EngineConfig::new("ov-4", JobMode::Copy, "b:", "b:sub");
    cfg_filtered.dst_prefix = RelPath::parse("sub").unwrap();
    cfg_filtered.filter = crate::filter::FilterSet::new(&[], &["sub/".into()]).unwrap();
    assert!(
        engine
            .run(&cfg_filtered, Arc::new(InMemorySyncIndex::default()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn dst_concurrent_20_files_truncate_and_delete_and_checksum() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    let t1 = 1_700_000_000_000_000_000i64;
    for i in 0..20 {
        src.insert_file(&format!("both{i}.txt"), b"potato".to_vec(), t1);
        dst.insert_file(&format!("both{i}.txt"), b"potato".to_vec(), t1);
        // Truncate to empty on src (rclone TestSyncConcurrentTruncate).
        src.insert_file(&format!("trunc{i}.txt"), Vec::new(), t1);
        dst.insert_file(&format!("trunc{i}.txt"), b"potato".to_vec(), t1);
        // Delete on src (rclone TestSyncConcurrentDelete).
        dst.insert_file(&format!("only{i}.txt"), b"remove".to_vec(), t1);
    }
    // Same size + same mtime, DIFFERENT content -> caught by --checksum!
    src.insert_file("silent_edit.txt", b"BBBBBB".to_vec(), t1);
    dst.insert_file("silent_edit.txt", b"AAAAAA".to_vec(), t1);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_900));
    let engine = TransferEngine::new(
        src,
        dst.clone(),
        journal,
        pool.clone(),
        clock,
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-conc", JobMode::Sync, "src:", "dst:");
    cfg.transfers = 4;
    cfg.checksum = true;
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.items_deleted, 20);
    assert_eq!(
        dst.get_file_bytes("silent_edit.txt").as_deref(),
        Some(b"BBBBBB".as_slice())
    );
    for i in 0..20 {
        assert_eq!(
            dst.get_file_bytes(&format!("trunc{i}.txt")).as_deref(),
            Some(&[][..])
        );
        assert!(dst.get_file_bytes(&format!("only{i}.txt")).is_none());
    }
    assert_eq!(pool.stats().in_use_units, 0);
}

#[tokio::test]
async fn dst_dry_run_makes_zero_mutations_and_zero_journal_writes() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    src.insert_file("new.txt", b"hello".to_vec(), 100);
    dst.insert_file("old.txt", b"keep".to_vec(), 100);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(200));
    let engine = TransferEngine::new(
        src,
        dst.clone(),
        journal.clone(),
        pool,
        clock,
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-dry", JobMode::Sync, "src:", "dst:");
    cfg.dry_run = true;
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(rep.items_deleted, 1);
    // Destination and journal must be 100% untouched!
    assert!(dst.get_file_bytes("new.txt").is_none());
    assert_eq!(
        dst.get_file_bytes("old.txt").as_deref(),
        Some(b"keep".as_slice())
    );
    assert!(journal.list_jobs(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn dst_falcon_dual_lane_adaptive_concurrency_backs_off_and_converges() {
    use crate::adaptive::FalconConfig;

    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));

    // 8 small files (<= 64 KiB threshold) + 2 large files (> 64 KiB threshold).
    for i in 0..8 {
        src.insert_file(
            &format!("small/s{i}.txt"),
            format!("small-payload-{i}").into_bytes(),
            1_700_000_000_000_000_000,
        );
    }
    let big_a: Vec<u8> = (0..(300 * 1024)).map(|i| (i % 251) as u8).collect();
    let big_b: Vec<u8> = (0..(300 * 1024)).map(|i| ((i * 7) % 251) as u8).collect();
    src.insert_file("large/a.bin", big_a.clone(), 1_700_000_000_000_000_000);
    src.insert_file("large/b.bin", big_b.clone(), 1_700_000_000_000_000_000);

    // Inject 2 rate-limit (`429`) faults so Falcon backs off multiplicatively on retries!
    dst.set_faults(FaultSchedule {
        fail_chunk_rate_limit_remaining: 2,
        ..Default::default()
    });

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_100));
    let engine = TransferEngine::new(
        src,
        dst.clone(),
        journal,
        pool.clone(),
        clock,
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-falcon", JobMode::Copy, "src:", "dst:");
    cfg.base_retry_delay = Duration::from_millis(1);
    cfg.adaptive_concurrency = true;
    cfg.falcon_config = Some(FalconConfig {
        small_file_threshold_bytes: 64 * 1024,
        small_min: 1,
        small_max: 6,
        small_initial: 4,
        large_min: 1,
        large_max: 4,
        large_initial: 4,
        ..Default::default()
    });

    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "errors: {:?}", rep.errors);
    assert_eq!(rep.files_transferred, 10);
    assert!(rep.final_small_concurrency.is_some());
    // Large lane hit 429 on chunk uploads so concurrency backed off below initial 4!
    assert!(
        rep.final_large_concurrency.unwrap() < 4,
        "expected large lane backoff after 429, got {:?}",
        rep.final_large_concurrency
    );
    assert_eq!(
        dst.get_file_bytes("large/a.bin").as_deref(),
        Some(big_a.as_slice())
    );
    assert_eq!(
        dst.get_file_bytes("large/b.bin").as_deref(),
        Some(big_b.as_slice())
    );
    for i in 0..8 {
        assert_eq!(
            dst.get_file_bytes(&format!("small/s{i}.txt")).as_deref(),
            Some(format!("small-payload-{i}").as_bytes())
        );
    }
    assert_eq!(pool.stats().in_use_units, 0);
}

#[tokio::test]
async fn dst_move_deletes_source_only_after_commit_and_strict_source_snapshots() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 256 * 1024));
    let payload: Vec<u8> = (0..(120 * 1024)).map(|i| (i % 251) as u8).collect();
    src.insert_file("move_me.bin", payload.clone(), 1_700_000_000_000_000_000);

    let spool_dir = std::env::temp_dir().join(format!("rship-strict-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spool_dir);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_100));
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal,
        pool.clone(),
        clock,
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-move", JobMode::Move, "src:", "dst:");
    cfg.strict_source = true;
    cfg.strict_source_dir = Some(spool_dir.clone());
    let rep = engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(rep.sources_deleted, 1);
    assert_eq!(
        dst.get_file_bytes("move_me.bin").as_deref(),
        Some(payload.as_slice())
    );
    assert!(
        src.get_file_bytes("move_me.bin").is_none(),
        "moved source must be deleted"
    );
    assert_eq!(pool.stats().in_use_units, 0);

    // Verify `--strict-source` spool file was cleaned up automatically on Drop!
    let remaining: Vec<_> = std::fs::read_dir(&spool_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    assert!(remaining.is_empty(), "spool file leaked: {remaining:?}");
    let _ = std::fs::remove_dir_all(&spool_dir);
}

/// The 2-second progress heartbeat is skipped under instant-sleep clocks, so exercise it
/// with a non-instant `VirtualClock` on paused Tokio time: while one transfer is blocked,
/// the heartbeat must persist the progress of the transfer that already finished.
#[tokio::test(start_paused = true)]
async fn heartbeat_persists_live_progress_under_virtual_clock() {
    let src = Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024));
    let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
    src.insert_file("a.bin", vec![1; 64], 1_700_000_000_000_000_000);
    src.insert_file("b.bin", vec![2; 64], 1_700_000_000_000_000_000);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    dst.set_put_gate(Some(("b.bin".to_string(), gate.clone())));

    let journal = Arc::new(InMemoryJournal::default());
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        BufferPool::new(256 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new(1_700_000_100)),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("heartbeat", JobMode::Copy, "src:", "dst:")
        .with_transfers(2)
        .with_allow_server_side_copy(false);
    let run = tokio::spawn(async move {
        engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
    });

    let mut persisted_mid_run = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(job) = journal.get_job("heartbeat").await.unwrap()
            && job.status == crate::state::JobStatus::Running
            && job.files_done == 1
            && job.files_total == 2
        {
            persisted_mid_run = true;
            break;
        }
    }
    assert!(
        persisted_mid_run,
        "heartbeat must flush live counters while the run is in progress"
    );
    gate.add_permits(1);
    let rep = run.await.unwrap().unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(
        journal
            .get_job("heartbeat")
            .await
            .unwrap()
            .unwrap()
            .files_done,
        2
    );
}
