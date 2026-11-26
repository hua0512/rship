//! Crash-at-every-step sweep harness shared by the in-memory journal tests in
//! `rship-core` and the SQLite `StateActor` tests in `rship-state`.
//!
//! A dry run numbers every journal write boundary (via [`FailingJournalStore`]) and every
//! remote commit/delete boundary on BOTH backends (via [`ChaosBackend::set_failpoints`])
//! with one shared [`FailpointCoordinator`]. The sweep then re-runs the scenario once per
//! boundary `k`, crashes at `k`, reopens the journal the way a restarted process would,
//! resumes without failpoints, and checks the invariants:
//!
//! - after the crash, every source file's bytes still exist on at least one side, and no
//!   destination file holds bytes other than its pre-existing or its new content;
//! - the resumed run succeeds and the destination is bit-exact (`sync` also deletes the
//!   extraneous files, `move` also empties the source);
//! - crash + resume upload at most one chunk more than a clean run;
//! - no journal operation is left active, and a further run uploads nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{ChaosBackend, FailingJournalStore, FailpointCoordinator, InMemorySyncIndex};
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, RunReport, TransferEngine};
use crate::state::{BaselineMode, JobMode, JournalStore};
use crate::types::ChunkAlignment;

const MTIME: i64 = 1_700_000_000_000_000_000;

/// One crash-sweep scenario.
#[derive(Clone)]
pub struct CrashSweepScenario {
    pub label: String,
    pub mode: JobMode,
    /// Files created on the source (path, bytes).
    pub src_files: Vec<(String, Vec<u8>)>,
    /// Files already present on the destination before the run (older mtime).
    pub dst_files: Vec<(String, Vec<u8>)>,
    pub make_src: fn() -> ChaosBackend,
    pub make_dst: fn() -> ChaosBackend,
    /// Largest number of bytes one resumed transfer may re-send (one chunk/part).
    pub chunk_size: u64,
    pub chunk_override: Option<u64>,
    pub baseline_mode: BaselineMode,
}

impl CrashSweepScenario {
    fn config(&self) -> EngineConfig {
        let mut cfg = EngineConfig::new(format!("sweep-{}", self.label), self.mode, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_allow_server_side_copy(false)
            .with_baseline_mode(self.baseline_mode)
            .with_max_retries(0)
            .with_retry_jitter_seed(7);
        cfg.chunk_size_override = self.chunk_override;
        cfg
    }

    fn backends(&self) -> (Arc<ChaosBackend>, Arc<ChaosBackend>) {
        let src = Arc::new((self.make_src)());
        for (path, data) in &self.src_files {
            src.insert_file(path, data.clone(), MTIME);
        }
        let dst = Arc::new((self.make_dst)());
        for (path, data) in &self.dst_files {
            dst.insert_file(path, data.clone(), MTIME - 60_000_000_000);
        }
        (src, dst)
    }

    fn expected_dst(&self) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        if self.mode != JobMode::Sync {
            for (p, d) in &self.dst_files {
                out.insert(p.clone(), d.clone());
            }
        }
        for (p, d) in &self.src_files {
            out.insert(p.clone(), d.clone());
        }
        out
    }

    fn uploaded_bytes_clean(&self) -> u64 {
        self.src_files.iter().map(|(_, d)| d.len() as u64).sum()
    }
}

/// How the sweep obtains and "reopens" journals around a simulated crash.
pub trait CrashJournalHarness {
    /// Fresh, empty durable state for crash point `k` (`0` is the dry counting run).
    fn open(&self, k: usize) -> impl Future<Output = Arc<dyn JournalStore>>;
    /// Simulate a process restart after a crash: release `crashed` and reopen whatever
    /// state was durably committed before the crash.
    fn reopen(
        &self,
        k: usize,
        crashed: Arc<dyn JournalStore>,
    ) -> impl Future<Output = Arc<dyn JournalStore>>;
}

/// [`CrashJournalHarness`] over the in-memory journal (the same object survives the crash).
pub struct InMemoryJournalHarness;

impl CrashJournalHarness for InMemoryJournalHarness {
    async fn open(&self, _k: usize) -> Arc<dyn JournalStore> {
        Arc::new(super::InMemoryJournal::default())
    }

    async fn reopen(&self, _k: usize, crashed: Arc<dyn JournalStore>) -> Arc<dyn JournalStore> {
        crashed
    }
}

async fn run_engine(
    src: &Arc<ChaosBackend>,
    dst: &Arc<ChaosBackend>,
    journal: Arc<dyn JournalStore>,
    pool: &BufferPool,
    cancel: CancelFlag,
    cfg: &EngineConfig,
) -> crate::error::Result<RunReport> {
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal,
        pool.clone(),
        Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
        cancel,
    );
    engine
        .run(cfg, Arc::new(InMemorySyncIndex::default()))
        .await
}

/// Run `scenario` crashing at every boundary. Returns the number of boundaries swept.
pub async fn run_crash_sweep(
    scenario: &CrashSweepScenario,
    harness: &impl CrashJournalHarness,
) -> usize {
    let label = &scenario.label;
    let cfg = scenario.config();
    let expected = scenario.expected_dst();

    // 0. Dry counting run.
    let (total_steps, trace) = {
        let (src, dst) = scenario.backends();
        let coord = FailpointCoordinator::new(None);
        let inner = harness.open(0).await;
        let journal = Arc::new(FailingJournalStore::with_coordinator(
            inner.clone(),
            coord.clone(),
        ));
        src.set_failpoints(Some(coord.clone()));
        dst.set_failpoints(Some(coord.clone()));
        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();
        let rep = run_engine(&src, &dst, journal, &pool, CancelFlag::new(), &cfg)
            .await
            .unwrap();
        assert!(rep.is_success(), "{label} dry run failed: {:?}", rep.errors);
        assert_eq!(dst.all_files(), expected, "{label}: dry run output");
        (coord.steps_reached(), coord.trace())
    };
    assert!(
        total_steps >= 6,
        "{label}: expected >= 6 crash boundaries, got {total_steps}: {trace:?}"
    );

    for k in 1..=total_steps {
        let step = trace.get(k - 1).map_or("unknown", |(_, l)| *l);
        let ctx = format!("{label} step {k}/{total_steps} ({step})");
        let (src, dst) = scenario.backends();
        let pool = BufferPool::new(256 * 1024, 64 * 1024).unwrap();

        // Run 1: crash at boundary k.
        let cancel = CancelFlag::new();
        let coord = FailpointCoordinator::new(Some(cancel.clone()));
        coord.arm_crash_at(k);
        let inner = harness.open(k).await;
        let journal = Arc::new(FailingJournalStore::with_coordinator(
            inner.clone(),
            coord.clone(),
        ));
        src.set_failpoints(Some(coord.clone()));
        dst.set_failpoints(Some(coord.clone()));
        let _ = run_engine(&src, &dst, journal, &pool, cancel, &cfg).await;
        assert!(coord.is_crashed(), "{ctx}: crash failpoint did not fire");
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "{ctx}: leaked buffer permits after crash"
        );
        src.set_failpoints(None);
        dst.set_failpoints(None);

        // No data loss at the crash point.
        let src_now = src.all_files();
        let dst_now = dst.all_files();
        for (path, data) in &scenario.src_files {
            let on_src = src_now.get(path) == Some(data);
            let on_dst = dst_now.get(path) == Some(data);
            assert!(
                on_src || on_dst,
                "{ctx}: `{path}` exists on neither side after the crash"
            );
        }
        for (path, got) in &dst_now {
            let new = scenario.src_files.iter().find(|(p, _)| p == path);
            let old = scenario.dst_files.iter().find(|(p, _)| p == path);
            assert!(
                new.is_some_and(|(_, d)| d == got) || old.is_some_and(|(_, d)| d == got),
                "{ctx}: destination `{path}` holds bytes that are neither its old nor its new content"
            );
        }
        let bytes_run1 = dst.bytes_uploaded();

        // Run 2: restart and resume.
        let journal2 = harness.reopen(k, inner).await;
        let rep = run_engine(&src, &dst, journal2.clone(), &pool, CancelFlag::new(), &cfg)
            .await
            .unwrap_or_else(|e| panic!("{ctx}: resume error: {e}"));
        assert!(
            rep.is_success(),
            "{ctx}: resume errors {:?} conflicts {:?}",
            rep.errors,
            rep.conflicts
        );
        assert_eq!(
            dst.all_files(),
            expected,
            "{ctx}: destination not bit-exact"
        );
        if scenario.mode == JobMode::Move {
            assert_eq!(src.file_count(), 0, "{ctx}: sources left after move resume");
        }
        let active = journal2.list_active_operations().await.unwrap();
        assert!(
            active.is_empty(),
            "{ctx}: active operations left: {active:?}"
        );
        let total = dst.bytes_uploaded();
        let limit = scenario.uploaded_bytes_clean() + scenario.chunk_size;
        assert!(
            total <= limit,
            "{ctx}: re-sent more than one chunk (run1={bytes_run1}, total={total}, limit={limit})"
        );

        // Run 3: converged state is stable (baselines / skips are consistent).
        let rep3 = run_engine(&src, &dst, journal2, &pool, CancelFlag::new(), &cfg)
            .await
            .unwrap();
        assert!(rep3.is_success(), "{ctx}: re-run errors {:?}", rep3.errors);
        assert_eq!(
            dst.bytes_uploaded(),
            total,
            "{ctx}: a converged re-run uploaded bytes"
        );
        assert_eq!(
            dst.all_files(),
            expected,
            "{ctx}: re-run changed the destination"
        );
    }
    total_steps
}

fn sweep_bytes(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + usize::from(salt) * 7) % 251) as u8)
        .collect()
}

fn sweep_seq_dst() -> ChaosBackend {
    ChaosBackend::sequential_gdrive_like("dst", 64 * 1024).with_caps(|c| {
        c.chunk_alignment = ChunkAlignment::MultipleOf {
            align_bytes: 64 * 1024,
            max_chunk_bytes: None,
        };
        c.default_chunk_size = 64 * 1024;
        c.single_shot_max_bytes = 16 * 1024;
    })
}

fn sweep_s3_dst() -> ChaosBackend {
    ChaosBackend::parallel_s3_like("dst", 64 * 1024)
}

fn sweep_gdrive_src() -> ChaosBackend {
    // Duplicate-name source: indexed planning path.
    ChaosBackend::sequential_gdrive_like("src", 64 * 1024)
}

fn sweep_s3_src() -> ChaosBackend {
    // No duplicate names, unordered: pipelined planning path.
    ChaosBackend::parallel_s3_like("src", 64 * 1024)
}

fn sweep_src_files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("a/small.txt".to_string(), sweep_bytes(6 * 1024, 1)),
        (
            "b/multi.bin".to_string(),
            sweep_bytes(3 * 64 * 1024 + 100, 2),
        ),
        ("c/empty.bin".to_string(), Vec::new()),
    ]
}

fn sweep_stale_dst_files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("b/multi.bin".to_string(), sweep_bytes(10 * 1024, 9)),
        ("z/extra.txt".to_string(), b"extraneous".to_vec()),
        ("z/deep/extra2.txt".to_string(), b"extraneous 2".to_vec()),
    ]
}

/// Multi-file `copy`, `move` and `sync` (with baselines and an extraneous-file delete
/// phase) scenarios over both the indexed (duplicate-name source) and the pipelined
/// (unordered source) planning paths, on sequential and parallel-part destinations.
pub fn standard_crash_sweep_scenarios() -> Vec<CrashSweepScenario> {
    let base = |label: &str,
                mode: JobMode,
                make_src: fn() -> ChaosBackend,
                make_dst: fn() -> ChaosBackend,
                chunk_override: Option<u64>| CrashSweepScenario {
        label: label.to_string(),
        mode,
        src_files: sweep_src_files(),
        dst_files: Vec::new(),
        make_src,
        make_dst,
        chunk_size: 64 * 1024,
        chunk_override,
        baseline_mode: BaselineMode::Auto,
    };
    vec![
        base(
            "copy-multi-seq",
            JobMode::Copy,
            sweep_gdrive_src,
            sweep_seq_dst,
            None,
        ),
        base(
            "move-multi-seq",
            JobMode::Move,
            sweep_gdrive_src,
            sweep_seq_dst,
            None,
        ),
        base(
            "move-multi-s3-pipelined",
            JobMode::Move,
            sweep_s3_src,
            sweep_s3_dst,
            Some(64 * 1024),
        ),
        CrashSweepScenario {
            dst_files: sweep_stale_dst_files(),
            baseline_mode: BaselineMode::All,
            ..base(
                "sync-baselines-seq",
                JobMode::Sync,
                sweep_gdrive_src,
                sweep_seq_dst,
                None,
            )
        },
        CrashSweepScenario {
            dst_files: sweep_stale_dst_files(),
            baseline_mode: BaselineMode::All,
            ..base(
                "sync-baselines-s3-pipelined",
                JobMode::Sync,
                sweep_s3_src,
                sweep_s3_dst,
                Some(64 * 1024),
            )
        },
    ]
}
