use super::super::faults::SplitMix64;
use super::super::*;
use crate::backend::{BackendPath, StorageBackend};
use crate::buffer::BufferPool;
use crate::clock::{Clock, VirtualClock};
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::path::RelPath;
use crate::state::{JobMode, JournalStore};
use crate::types::ChunkAlignment;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

// =========================================================================
// Step 5 (B.2): Real Seeded DST + Determinism + Multi-Thread Runtime DST
// =========================================================================

fn dst_seed_list(default_count: u64) -> Vec<u64> {
    if let Ok(raw) = std::env::var("RSHIP_DST_SEED")
        && let Ok(single) = raw.trim().parse::<u64>()
    {
        return vec![single];
    }
    let count = std::env::var("RSHIP_DST_SEEDS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default_count);
    (1..=count).collect()
}

#[test]
fn fault_schedule_random_is_deterministic_for_same_seed_and_covers_all_faults() {
    let ops = [
        ChaosOp::List,
        ChaosOp::Stat,
        ChaosOp::BeginUpload,
        ChaosOp::UploadChunk,
        ChaosOp::QueryUpload,
        ChaosOp::FinishUpload,
        ChaosOp::PutSingleShot,
        ChaosOp::ReconcileOperation,
        ChaosOp::Delete,
    ];
    let profile = RandomFaultProfile::heavy();
    let mut s1 = FaultSchedule::random(0xDEAD_BEEF_1234_5678, profile);
    let mut s2 = FaultSchedule::random(0xDEAD_BEEF_1234_5678, profile);
    let mut s3 = FaultSchedule::random(0xCAFE_BABE_8765_4321, profile);

    let mut seq1 = Vec::new();
    let mut seq2 = Vec::new();
    let mut seq3 = Vec::new();
    for round in 0..40 {
        let op = ops[round % ops.len()];
        seq1.push(s1.next_fault(op));
        seq2.push(s2.next_fault(op));
        seq3.push(s3.next_fault(op));
    }
    assert_eq!(
        seq1, seq2,
        "identical seeds must produce identical fault sequences"
    );
    assert_ne!(
        seq1, seq3,
        "distinct seeds must produce distinct fault sequences"
    );

    // Verify all 5 fault categories are generated across a small batch of seeds.
    let (mut saw_429, mut saw_503, mut saw_exp, mut saw_partial, mut saw_lost) =
        (false, false, false, false, false);
    for seed in 1..=16u64 {
        let mut sched = FaultSchedule::random(seed, RandomFaultProfile::heavy());
        for i in 0..80 {
            if let Some(f) = sched.next_fault(ops[i % ops.len()]) {
                match f {
                    InjectedFault::RateLimited { retry_after } => {
                        assert!(retry_after >= Duration::from_millis(1));
                        saw_429 = true;
                    }
                    InjectedFault::Network503(_) => saw_503 = true,
                    InjectedFault::SessionExpired => saw_exp = true,
                    InjectedFault::PartialChunkDrop => saw_partial = true,
                    InjectedFault::LostCommitResponse => saw_lost = true,
                }
            }
        }
    }
    assert!(
        saw_429 && saw_503 && saw_exp && saw_partial && saw_lost,
        "seeded random faults must exercise all fault kinds: 429={saw_429} 503={saw_503} exp={saw_exp} partial={saw_partial} lost={saw_lost}"
    );
}

/// Which engine planning path a DST scenario drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DstTopology {
    /// Source allows duplicate names (GDrive-like): full observation into the SyncDiffIndex.
    Indexed,
    /// Unordered source without duplicate names: pipelined unordered streaming.
    Pipelined,
    /// Both sides list in ordered UTF-8: zero-index streaming merge-join.
    StreamingMerge,
}

/// Prefix for assertion messages. A single-thread run is fully determined by its seed,
/// so the message tells how to replay it; a multi-thread run is not (OS scheduling
/// decides interleavings), so the message says the seed only replays the fault schedule.
fn seed_tag(seed: u64, reproducible: bool) -> String {
    if reproducible {
        format!("RSHIP_DST_SEED={seed}")
    } else {
        format!(
            "seed={seed} (multi-thread runtime: RSHIP_DST_SEED={seed} replays the fault schedule but not the thread interleaving)"
        )
    }
}

/// Observable outcome of one seeded scenario, compared across replays of the same seed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DstFingerprint {
    /// Final virtual clock (sum of every instant-sleep backoff).
    clock_ns: i64,
    runs_needed: usize,
    dst_upload_requests: u64,
    dst_bytes_uploaded: u64,
    dst_faults_injected: u32,
}

fn make_seeded_bytes(seed: u64, file_idx: usize, len: usize) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed.wrapping_mul(0x9E37_79B9) ^ (file_idx as u64 + 1));
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let word = rng.next_u64().to_le_bytes();
        let take = (len - out.len()).min(8);
        out.extend_from_slice(&word[..take]);
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn run_seeded_engine_scenario(
    report_seed: u64,
    fault_seed: u64,
    mode: JobMode,
    parallel_dst: bool,
    adaptive_falcon: bool,
    topology: DstTopology,
    reproducible: bool,
) -> DstFingerprint {
    let tag = seed_tag(report_seed, reproducible);
    let mut rng = SplitMix64::new(fault_seed ^ 0xA5A5_5A5A_1234_5678);
    let parallel_dst = parallel_dst || topology == DstTopology::StreamingMerge;
    let src = Arc::new(match topology {
        DstTopology::Indexed => ChaosBackend::sequential_gdrive_like("src", 64 * 1024),
        DstTopology::Pipelined => ChaosBackend::parallel_s3_like("src", 64 * 1024),
        DstTopology::StreamingMerge => ChaosBackend::parallel_s3_like("src", 64 * 1024)
            .with_caps(|c| c.supports_ordered_utf8_list = true),
    });
    let dst = if topology == DstTopology::StreamingMerge {
        Arc::new(
            ChaosBackend::parallel_s3_like("dst", 64 * 1024)
                .with_caps(|c| c.supports_ordered_utf8_list = true),
        )
    } else if parallel_dst {
        Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024))
    } else {
        Arc::new(
            ChaosBackend::sequential_gdrive_like("dst", 64 * 1024).with_caps(|c| {
                c.chunk_alignment = ChunkAlignment::MultipleOf {
                    align_bytes: 64 * 1024,
                    max_chunk_bytes: None,
                };
                c.default_chunk_size = 64 * 1024;
                c.single_shot_max_bytes = 16 * 1024;
            }),
        )
    };

    let base_mtime = 1_700_000_000_000_000_000i64;
    // Mix of empty, single-shot, and multi-chunk files across nested directories.
    let file_specs = [
        ("empty.bin", 0usize),
        ("small/a.txt", 512),
        ("small/b.txt", 12 * 1024),
        ("medium/c.bin", 96 * 1024),
        ("large/d.bin", 210 * 1024),
        ("large/nested/e.bin", 260 * 1024),
    ];
    let mut expected_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (idx, (path, size)) in file_specs.iter().enumerate() {
        let data = make_seeded_bytes(fault_seed, idx, *size);
        src.insert_file(
            path,
            data.clone(),
            base_mtime + (idx as i64) * 1_000_000_000,
        );
        expected_files.insert((*path).to_string(), data);
    }

    if matches!(mode, JobMode::Sync) {
        // Seed stale/extraneous files on destination so sync exercises overwrite + delete.
        dst.insert_file(
            "extra/old1.txt",
            b"stale-1".to_vec(),
            base_mtime - 5_000_000_000,
        );
        dst.insert_file(
            "extra/old2.txt",
            b"stale-2".to_vec(),
            base_mtime - 5_000_000_000,
        );
        dst.insert_file(
            "small/a.txt",
            b"outdated-content".to_vec(),
            base_mtime - 1_000_000_000,
        );
    }

    let profile = RandomFaultProfile {
        max_total_faults: 20 + (rng.next_u64() % 16) as u32,
        ..RandomFaultProfile::moderate()
    };
    dst.set_faults(FaultSchedule::random(fault_seed, profile));
    if matches!(mode, JobMode::Move) {
        src.set_faults(FaultSchedule::random(
            fault_seed.wrapping_mul(31) ^ 0x55AA,
            RandomFaultProfile {
                list_error_pct: 10,
                stat_error_pct: 8,
                delete_error_pct: 20,
                max_total_faults: 10,
                ..RandomFaultProfile::moderate()
            },
        ));
    }

    let journal = Arc::new(InMemoryJournal::default());
    // Tight buffer pool (4 x 64 KiB slabs = 256 KiB total) shared across concurrent workers!
    let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_500));

    let mut cfg = EngineConfig::new(format!("dst-{mode}-{fault_seed}"), mode, "src:", "dst:")
        .with_transfers(4)
        .with_part_concurrency(2)
        .with_delete(matches!(mode, JobMode::Sync))
        .with_delete_source_after_transfer(matches!(mode, JobMode::Move))
        .with_allow_server_side_copy(false)
        .with_adaptive_concurrency(adaptive_falcon)
        .with_max_retries(6)
        .with_base_retry_delay(Duration::from_millis(5))
        .with_max_retry_delay(Duration::from_secs(2))
        .with_retry_jitter_seed(fault_seed);
    if parallel_dst {
        cfg.chunk_size_override = Some(64 * 1024);
    }

    let mut converged = false;
    let mut runs_needed = 0usize;
    let mut last_errors = Vec::new();
    for run_idx in 0..24 {
        runs_needed = run_idx + 1;
        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{tag} mode={mode} parallel={parallel_dst} falcon={adaptive_falcon} run={run_idx}: engine error: {e}"
                )
            });
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "{tag} mode={mode} parallel={parallel_dst} run={run_idx}: leaked buffer permits"
        );
        let st = pool.stats();
        assert!(
            st.peak_units <= st.max_units,
            "{tag} mode={mode} parallel={parallel_dst}: peak_units {} > max_units {}",
            st.peak_units,
            st.max_units
        );
        if rep.is_success() {
            converged = true;
            break;
        }
        last_errors = rep.errors;
    }

    assert!(
        converged,
        "{tag} mode={mode} parallel={parallel_dst} falcon={adaptive_falcon}: failed to converge within 24 runs, last errors: {last_errors:?}"
    );
    assert_eq!(
        dst.all_files(),
        expected_files,
        "{tag} mode={mode} parallel={parallel_dst}: destination bytes diverged from source"
    );
    if matches!(mode, JobMode::Move) {
        assert_eq!(
            src.file_count(),
            0,
            "{tag} mode=move parallel={parallel_dst}: source files remained after move"
        );
    }
    assert!(
        journal.list_active_operations().await.unwrap().is_empty(),
        "{tag} mode={mode} parallel={parallel_dst}: active journal operations leaked: {:?}",
        journal.list_active_operations().await.unwrap()
    );
    assert_eq!(
        pool.available_bytes(),
        pool.max_bytes(),
        "{tag} mode={mode} parallel={parallel_dst}: final buffer pool leak"
    );
    DstFingerprint {
        clock_ns: clock.now_unix_nanos(),
        runs_needed,
        dst_upload_requests: dst.upload_request_count(),
        dst_bytes_uploaded: dst.bytes_uploaded(),
        dst_faults_injected: dst.random_faults_injected(),
    }
}

#[tokio::test]
async fn dst_seeded_random_fault_sweep_converges_bit_exact() {
    let seeds = dst_seed_list(16);
    let wall_start = std::time::Instant::now();
    for &seed in &seeds {
        let parallel_dst = seed % 2 == 0;
        let mode = match seed % 3 {
            0 => JobMode::Sync,
            1 => JobMode::Copy,
            _ => JobMode::Move,
        };
        run_seeded_engine_scenario(
            seed,
            seed,
            mode,
            parallel_dst,
            false,
            DstTopology::Indexed,
            true,
        )
        .await;
    }
    // Instant-sleep virtual time keeps a seed well under a second; the budget scales with
    // the seed count (nightly runs 64) so it only catches accidental wall-clock sleeps.
    let budget = Duration::from_secs(2) * u32::try_from(seeds.len()).unwrap_or(u32::MAX);
    let budget = budget.max(Duration::from_secs(30));
    assert!(
        wall_start.elapsed() < budget,
        "seeded DST sweep ({} seeds) unexpectedly slow: {:?} (budget {budget:?})",
        seeds.len(),
        wall_start.elapsed()
    );
}

/// The pipelined unordered and streaming merge-join planning paths under seeded faults
/// (the indexed path is covered by `dst_seeded_random_fault_sweep_converges_bit_exact`).
#[tokio::test]
async fn dst_seeded_pipelined_and_streaming_merge_converge_bit_exact() {
    for seed in dst_seed_list(8) {
        let mode = match seed % 3 {
            0 => JobMode::Sync,
            1 => JobMode::Copy,
            _ => JobMode::Move,
        };
        run_seeded_engine_scenario(
            seed,
            seed ^ 0x5151,
            mode,
            seed % 2 == 0,
            false,
            DstTopology::Pipelined,
            true,
        )
        .await;
        run_seeded_engine_scenario(
            seed,
            seed ^ 0x7373,
            mode,
            true,
            seed % 2 == 1,
            DstTopology::StreamingMerge,
            true,
        )
        .await;
    }
}

/// On the single-thread runtime a seed fully determines a run, including backoff jitter
/// (which advances the instant-sleep clock that Falcon reads): replaying a seed must
/// reproduce the same virtual time, retries, and fault sequence.
#[tokio::test]
async fn dst_same_seed_replays_exactly() {
    for seed in dst_seed_list(4) {
        for (topology, mode, falcon) in [
            (DstTopology::Indexed, JobMode::Sync, true),
            (DstTopology::Pipelined, JobMode::Move, false),
            (DstTopology::StreamingMerge, JobMode::Copy, true),
        ] {
            let first =
                run_seeded_engine_scenario(seed, seed, mode, seed % 2 == 0, falcon, topology, true)
                    .await;
            let second =
                run_seeded_engine_scenario(seed, seed, mode, seed % 2 == 0, falcon, topology, true)
                    .await;
            assert_eq!(
                first, second,
                "RSHIP_DST_SEED={seed} {topology:?} {mode}: replay diverged"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dst_seeded_multithread_parallel_and_falcon_converge() {
    let seeds = dst_seed_list(8);
    for &seed in &seeds {
        // Exercise real OS-thread interleavings with parallel multipart AND Falcon dual-lane!
        run_seeded_engine_scenario(
            seed,
            seed,
            JobMode::Sync,
            true,
            true,
            DstTopology::Indexed,
            false,
        )
        .await;
        run_seeded_engine_scenario(
            seed,
            seed.wrapping_add(10_000),
            JobMode::Copy,
            false,
            true,
            DstTopology::Pipelined,
            false,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dst_seeded_multithread_move_and_bisync_converge() {
    use crate::bisync::{BisyncConfig, BisyncEngine, ConflictStrategy};

    let seeds = dst_seed_list(8);
    for &seed in &seeds {
        let tag = seed_tag(seed, false);
        // 1. Multi-thread concurrent Move under seeded faults on BOTH src and dst.
        run_seeded_engine_scenario(
            seed,
            seed.wrapping_add(20_000),
            JobMode::Move,
            seed % 2 == 0,
            true,
            DstTopology::StreamingMerge,
            false,
        )
        .await;

        // 2. Multi-thread concurrent Bisync under seeded faults on BOTH sides!
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let side_a = Arc::new(ChaosBackend::parallel_s3_like("a", 64 * 1024));
        let side_b = Arc::new(
            ChaosBackend::sequential_gdrive_like("b", 64 * 1024).with_caps(|c| {
                c.chunk_alignment = ChunkAlignment::MultipleOf {
                    align_bytes: 64 * 1024,
                    max_chunk_bytes: None,
                };
                c.default_chunk_size = 64 * 1024;
                c.single_shot_max_bytes = 16 * 1024;
            }),
        );
        let journal = Arc::new(InMemoryJournal::default());
        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();

        let t0 = clock.now_unix_nanos();
        side_a.insert_file("shared/doc.bin", make_seeded_bytes(seed, 1, 80 * 1024), t0);
        side_a.insert_file("only_a/file.txt", make_seeded_bytes(seed, 2, 4 * 1024), t0);
        side_b.insert_file("only_b/big.bin", make_seeded_bytes(seed, 3, 140 * 1024), t0);

        // Initial healthy convergence to establish merge-base baseline.
        let bisync = BisyncEngine::new(
            side_a.clone(),
            side_b.clone(),
            journal.clone(),
            pool.clone(),
            clock.clone(),
            CancelFlag::new(),
        );
        let r_init = bisync
            .run(
                &BisyncConfig::new(format!("bs-init-{seed}"), "a", "b")
                    .with_transfers(4)
                    .with_resync(true),
                Arc::new(InMemorySyncIndex::default()),
            )
            .await
            .unwrap();
        assert!(
            r_init.is_success(),
            "{tag}: bisync init errors: {:?}",
            r_init.errors
        );
        assert_eq!(side_a.all_files(), side_b.all_files());

        // Round 2: diverge both sides + arm randomized faults on BOTH sides!
        clock.advance(Duration::from_secs(30));
        let t1 = clock.now_unix_nanos();
        side_a
            .delete(&BackendPath::from_rel(
                RelPath::parse("shared/doc.bin").unwrap(),
            ))
            .await
            .unwrap();
        side_a.insert_file(
            "shared/doc.bin",
            make_seeded_bytes(seed, 11, 150 * 1024),
            t1,
        );
        side_a.insert_file("new_from_a.bin", make_seeded_bytes(seed, 12, 90 * 1024), t1);
        side_b
            .delete(&BackendPath::from_rel(
                RelPath::parse("only_a/file.txt").unwrap(),
            ))
            .await
            .unwrap();
        side_b.insert_file(
            "new_from_b.bin",
            make_seeded_bytes(seed, 13, 130 * 1024),
            t1,
        );

        let profile = RandomFaultProfile {
            max_total_faults: 16,
            ..RandomFaultProfile::moderate()
        };
        side_a.set_faults(FaultSchedule::random(seed ^ 0x1111, profile));
        side_b.set_faults(FaultSchedule::random(seed ^ 0x2222, profile));

        let mut bs_ok = false;
        let mut last_bs_errs = Vec::new();
        for attempt in 0..24 {
            let bs = BisyncEngine::new(
                side_a.clone(),
                side_b.clone(),
                journal.clone(),
                pool.clone(),
                clock.clone(),
                CancelFlag::new(),
            );
            let cfg = BisyncConfig::new(format!("bs-chaos-{seed}-{attempt}"), "a", "b")
                .with_transfers(4)
                .with_conflict_strategy(ConflictStrategy::KeepBoth)
                .with_max_delete_percent(None);
            let rep = bs
                .run(&cfg, Arc::new(InMemorySyncIndex::default()))
                .await
                .unwrap_or_else(|e| panic!("{tag} bisync attempt={attempt}: error: {e}"));
            assert_eq!(
                pool.available_bytes(),
                pool.max_bytes(),
                "{tag} bisync attempt={attempt}: leaked buffer permits"
            );
            if rep.is_success() {
                bs_ok = true;
                break;
            }
            last_bs_errs = rep.errors;
        }
        assert!(
            bs_ok,
            "{tag}: bisync failed to converge under faults: {last_bs_errs:?}"
        );
        assert_eq!(
            side_a.all_files(),
            side_b.all_files(),
            "{tag}: bisync sides did not converge bit-exact"
        );
        assert!(
            side_a.get_file_bytes("only_a/file.txt").is_none(),
            "{tag}: deletion on B must propagate to A"
        );
        assert_eq!(
            side_b.get_file_bytes("shared/doc.bin").as_deref(),
            Some(make_seeded_bytes(seed, 11, 150 * 1024).as_slice())
        );
        assert_eq!(
            side_a.get_file_bytes("new_from_b.bin").as_deref(),
            Some(make_seeded_bytes(seed, 13, 130 * 1024).as_slice())
        );
        assert_eq!(
            side_b.get_file_bytes("new_from_a.bin").as_deref(),
            Some(make_seeded_bytes(seed, 12, 90 * 1024).as_slice())
        );
        assert!(
            journal.list_active_operations().await.unwrap().is_empty(),
            "{tag}: bisync leaked active operations: {:?}",
            journal.list_active_operations().await.unwrap()
        );
        let st = pool.stats();
        assert_eq!(st.in_use_units, 0);
        assert!(st.peak_units <= st.max_units);
    }
}
