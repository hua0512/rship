use super::super::*;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::state::{JobMode, JournalStore};
use crate::types::ChunkAlignment;
use std::sync::Arc;

// =========================================================================
// Step 4 (B.3): FailingJournalStore + Crash-at-Every-Step `k` Sweep tests
// =========================================================================

#[tokio::test]
async fn b3_failing_journal_put_operation_intent_prevents_all_remote_side_effects() {
    use crate::state::JobStatus;

    for (label, is_parallel) in [("sequential", false), ("parallel", true)] {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        let dst = if is_parallel {
            Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024))
        } else {
            Arc::new(
                ChaosBackend::sequential_gdrive_like("dst", 64 * 1024).with_caps(|c| {
                    c.chunk_alignment = ChunkAlignment::MultipleOf {
                        align_bytes: 64 * 1024,
                        max_chunk_bytes: None,
                    };
                    c.default_chunk_size = 64 * 1024;
                }),
            )
        };
        let payload = vec![0x42u8; 192 * 1024]; // 3 chunks
        src.insert_file("wal.bin", payload, 1_700_000_000_000_000_000);

        let mem_journal = Arc::new(InMemoryJournal::default());
        let failing_journal = Arc::new(FailingJournalStore::new(mem_journal.clone()));
        failing_journal.inject_fault(
            JournalBoundary::PutOperation,
            JournalFault::StateStoreError("SQLITE_FULL: database or disk is full".into()),
        );

        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_100));
        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            failing_journal.clone(),
            pool.clone(),
            clock,
            CancelFlag::new(),
        );
        let mut cfg = EngineConfig::new(format!("b3-wal-{label}"), JobMode::Copy, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_allow_server_side_copy(false)
            .with_max_retries(0);
        if is_parallel {
            cfg.chunk_size_override = Some(64 * 1024);
        }

        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(
            !rep.errors.is_empty(),
            "{label}: PutOperation SQLITE_FULL must report an error"
        );
        assert!(
            rep.error_details
                .iter()
                .any(|e| e.kind == crate::error::ErrorKind::StateStore),
            "{label}: expected StateStore error kind, got {:?}",
            rep.error_details
        );
        assert_eq!(
            dst.put_single_shot_calls(),
            0,
            "{label}: write-ahead intent failure must prevent put_single_shot"
        );
        assert_eq!(
            dst.begin_upload_calls(),
            0,
            "{label}: write-ahead intent failure must prevent begin_upload"
        );
        assert_eq!(
            dst.upload_chunk_calls(),
            0,
            "{label}: write-ahead intent failure must prevent upload_chunk"
        );
        assert_eq!(
            dst.finish_upload_calls(),
            0,
            "{label}: write-ahead intent failure must prevent finish_upload"
        );
        assert_eq!(dst.file_count(), 0);
        assert_eq!(dst.active_session_count(), 0);
        assert_eq!(pool.available_bytes(), pool.max_bytes());
        let job = mem_journal
            .get_job(&format!("b3-wal-{label}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.status, JobStatus::Failed);
    }
}

#[tokio::test]
async fn b3_failing_journal_upsert_part_and_commit_verified_transfer_report_clean_failure() {
    use crate::state::JobStatus;

    // 1. StateStore error on UpsertPart (parallel multipart)
    {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
        let payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
        src.insert_file("parts.bin", payload.clone(), 1_700_000_000_000_000_000);

        let mem_journal = Arc::new(InMemoryJournal::default());
        let failing_journal = Arc::new(FailingJournalStore::new(mem_journal.clone()));
        failing_journal.inject_fault_on_call(
            JournalBoundary::UpsertPart,
            2,
            JournalFault::StateStoreError("SQLITE_FULL during upsert_part".into()),
        );

        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_100));
        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            failing_journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let cfg = EngineConfig::new("b3-part-err", JobMode::Copy, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_chunk_size(Some(64 * 1024))
            .with_allow_server_side_copy(false)
            .with_max_retries(0);

        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(!rep.errors.is_empty());
        assert!(
            rep.error_details
                .iter()
                .any(|e| e.kind == crate::error::ErrorKind::StateStore)
        );
        assert_eq!(pool.available_bytes(), pool.max_bytes());
        let job = mem_journal.get_job("b3-part-err").await.unwrap().unwrap();
        assert_eq!(job.status, JobStatus::Failed);

        // Clearing the fault and resuming converges cleanly with bit-exact output!
        failing_journal.clear_faults();
        let rep2 = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(rep2.is_success(), "resume errors: {:?}", rep2.errors);
        assert_eq!(
            dst.get_file_bytes("parts.bin").as_deref(),
            Some(payload.as_slice())
        );
        assert!(
            mem_journal
                .list_active_operations()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(pool.available_bytes(), pool.max_bytes());
    }

    // 2. StateStore error on CommitVerifiedTransfer
    {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
        let payload: Vec<u8> = (0..(192 * 1024)).map(|i| ((i * 7) % 253) as u8).collect();
        src.insert_file("commit.bin", payload.clone(), 1_700_000_000_000_000_000);

        let mem_journal = Arc::new(InMemoryJournal::default());
        let failing_journal = Arc::new(FailingJournalStore::new(mem_journal.clone()));
        failing_journal.inject_fault(
            JournalBoundary::CommitVerifiedTransfer,
            JournalFault::StateStoreError("SQLITE_IOERR during commit_verified_transfer".into()),
        );

        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_100));
        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            failing_journal.clone(),
            pool.clone(),
            clock,
            CancelFlag::new(),
        );
        let cfg = EngineConfig::new("b3-commit-err", JobMode::Copy, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_chunk_size(Some(64 * 1024))
            .with_allow_server_side_copy(false)
            .with_max_retries(0);

        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(!rep.errors.is_empty());
        assert!(
            rep.error_details
                .iter()
                .any(|e| e.kind == crate::error::ErrorKind::StateStore)
        );
        assert_eq!(pool.available_bytes(), pool.max_bytes());
        let job = mem_journal.get_job("b3-commit-err").await.unwrap().unwrap();
        assert_eq!(job.status, JobStatus::Failed);

        // Resuming after clearing the fault retires the dangling Completing op with 0 re-uploaded bytes!
        failing_journal.clear_faults();
        let uploaded_before = dst.bytes_uploaded();
        let rep2 = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(rep2.is_success(), "resume errors: {:?}", rep2.errors);
        assert_eq!(
            dst.bytes_uploaded(),
            uploaded_before,
            "resuming after post-commit journal error must upload 0 extra bytes"
        );
        assert_eq!(
            dst.get_file_bytes("commit.bin").as_deref(),
            Some(payload.as_slice())
        );
        assert!(
            mem_journal
                .list_active_operations()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(pool.available_bytes(), pool.max_bytes());
    }
}

async fn run_crash_at_every_step_sweep(
    label: &str,
    file_size: usize,
    chunk_size: u64,
    make_dst: impl Fn() -> ChaosBackend,
    chunk_override: Option<u64>,
) {
    let payload: Vec<u8> = (0..file_size)
        .map(|i| ((i * 29 + 13) % 251) as u8)
        .collect();
    let make_cfg = || {
        let mut c = EngineConfig::new(format!("sweep-{label}"), JobMode::Copy, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_allow_server_side_copy(false)
            .with_max_retries(0);
        c.chunk_size_override = chunk_override;
        c
    };

    // 0. Dry-counting baseline run to record exact crash boundary steps 1..=total_steps.
    let (total_steps, baseline_trace) = {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        src.insert_file("payload.bin", payload.clone(), 1_700_000_000_000_000_000);
        let dst = Arc::new(make_dst());
        let mem_journal = Arc::new(InMemoryJournal::default());
        let coord = FailpointCoordinator::new(None);
        let failing_journal = Arc::new(FailingJournalStore::with_coordinator(
            mem_journal.clone(),
            coord.clone(),
        ));
        dst.set_failpoints(Some(coord.clone()));
        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_100));
        let engine = TransferEngine::new(
            src,
            dst.clone(),
            failing_journal,
            pool.clone(),
            clock,
            CancelFlag::new(),
        );
        let rep = engine
            .run(&make_cfg(), Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();
        assert!(
            rep.is_success(),
            "{label} baseline failed: {:?}",
            rep.errors
        );
        assert_eq!(
            dst.get_file_bytes("payload.bin").as_deref(),
            Some(payload.as_slice())
        );
        assert!(
            mem_journal
                .list_active_operations()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(pool.available_bytes(), pool.max_bytes());
        (coord.steps_reached(), coord.trace())
    };

    assert!(
        total_steps >= 6,
        "{label}: expected >= 6 observable crash boundaries, got {total_steps}: {baseline_trace:?}"
    );

    // 1. Sweep EVERY single crash boundary k in 1..=total_steps!
    for k in 1..=total_steps {
        let step_label = baseline_trace.get(k - 1).map_or("unknown", |(_, lbl)| *lbl);
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        src.insert_file("payload.bin", payload.clone(), 1_700_000_000_000_000_000);
        let dst = Arc::new(make_dst());
        let mem_journal = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_100));

        // Run 1: crash at exact boundary `k`.
        let cancel1 = CancelFlag::new();
        let coord = FailpointCoordinator::new(Some(cancel1.clone()));
        coord.arm_crash_at(k);
        let failing_journal = Arc::new(FailingJournalStore::with_coordinator(
            mem_journal.clone(),
            coord.clone(),
        ));
        dst.set_failpoints(Some(coord.clone()));

        let engine1 = TransferEngine::new(
            src.clone(),
            dst.clone(),
            failing_journal,
            pool.clone(),
            clock.clone(),
            cancel1,
        );
        let _ = engine1
            .run(&make_cfg(), Arc::new(InMemorySyncIndex::default()))
            .await;
        assert!(
            coord.is_crashed(),
            "{label} step {k}/{total_steps} ({step_label}): expected crash failpoint to fire"
        );
        let bytes_run1 = dst.bytes_uploaded();
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "{label} step {k} ({step_label}): leaked buffer permits after crash"
        );

        // Run 2: disable failpoints, keep SAME MemoryJournalStore + ChaosBackend, and resume!
        dst.set_failpoints(None);
        let engine2 = TransferEngine::new(
            src.clone(),
            dst.clone(),
            mem_journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let r2 = engine2
            .run(&make_cfg(), Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap_or_else(|e| {
                panic!("{label} step {k}/{total_steps} ({step_label}): resume error: {e}")
            });
        let bytes_total = dst.bytes_uploaded();
        let bytes_run2 = bytes_total.saturating_sub(bytes_run1);

        assert!(
            r2.is_success(),
            "{label} step {k}/{total_steps} ({step_label}): resume had errors {:?} / conflicts {:?}",
            r2.errors,
            r2.conflicts
        );
        assert_eq!(
            dst.get_file_bytes("payload.bin").as_deref(),
            Some(payload.as_slice()),
            "{label} step {k}/{total_steps} ({step_label}): destination bytes not bit-exact"
        );
        assert!(
            mem_journal
                .list_active_operations()
                .await
                .unwrap()
                .is_empty(),
            "{label} step {k}/{total_steps} ({step_label}): active operations not empty after resume: {:?}",
            mem_journal.list_active_operations().await.unwrap()
        );
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "{label} step {k}/{total_steps} ({step_label}): leaked buffer permits after resume"
        );
        let max_allowed = (file_size as u64) + chunk_size;
        assert!(
            bytes_total <= max_allowed,
            "{label} step {k}/{total_steps} ({step_label}): resume re-sent > 1 chunk! run1={bytes_run1}, run2={bytes_run2}, total={bytes_total}, limit={max_allowed}"
        );
    }
}

#[tokio::test]
async fn b3_crash_at_every_step_k_sweep_parallel_sequential_and_single_shot() {
    // 1. ParallelParts: 5 parts x 64 KiB = 320 KiB
    run_crash_at_every_step_sweep(
        "parallel-5x64k",
        5 * 64 * 1024,
        64 * 1024,
        || ChaosBackend::parallel_s3_like("dst", 64 * 1024),
        Some(64 * 1024),
    )
    .await;

    // 2. SequentialResumable: 5 chunks x 64 KiB = 320 KiB
    run_crash_at_every_step_sweep(
        "sequential-5x64k",
        5 * 64 * 1024,
        64 * 1024,
        || {
            ChaosBackend::sequential_gdrive_like("dst", 64 * 1024).with_caps(|c| {
                c.chunk_alignment = ChunkAlignment::MultipleOf {
                    align_bytes: 64 * 1024,
                    max_chunk_bytes: None,
                };
                c.default_chunk_size = 64 * 1024;
                c.single_shot_max_bytes = 16 * 1024;
            })
        },
        None,
    )
    .await;

    // 3. SingleShot: 8 KiB (with write-ahead journal enabled via allows_duplicate_names = true)
    run_crash_at_every_step_sweep(
        "single-shot-8k",
        8 * 1024,
        8 * 1024,
        || ChaosBackend::sequential_gdrive_like("dst", 64 * 1024),
        None,
    )
    .await;
}

// -------------------------------------------------------------------------
// Multi-file Move / Sync(+baselines, delete phase) crash sweeps
// -------------------------------------------------------------------------

#[tokio::test]
async fn crash_sweep_move_sync_multi_file_in_memory_journal() {
    for scenario in standard_crash_sweep_scenarios() {
        let steps = run_crash_sweep(&scenario, &InMemoryJournalHarness).await;
        assert!(steps > 0, "{}", scenario.label);
    }
}
