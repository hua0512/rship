//! `TransferEngine` runs against the real SQLite-backed state: the adaptive
//! `SqliteSyncIndex` (spill to disk) and the `StateActor` journal.

use std::sync::Arc;

use rship_core::buffer::BufferPool;
use rship_core::chaos::{ChaosBackend, InMemoryJournal};
use rship_core::clock::VirtualClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::{ConflictKind, JobMode};
use rship_state::SqliteSyncIndex;

const MTIME: i64 = 1_700_000_000_000_000_000;

/// The pipelined path defers non-ASCII names until listing EOF. Those entries must go
/// through the run's `SyncDiffIndex`, so a large CJK tree spills to disk instead of being
/// held in an unbounded in-memory `Vec`.
#[tokio::test]
async fn pipelined_non_ascii_tree_spills_deferred_entries_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let src = Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024));
    let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
    for i in 0..600 {
        src.insert_file(
            &format!("照片/图{i:04}.jpg"),
            vec![(i % 251) as u8; 16],
            MTIME,
        );
    }
    src.insert_file("caf\u{e9}.txt", b"nfc".to_vec(), MTIME);
    src.insert_file("cafe\u{301}.txt", b"nfd".to_vec(), MTIME);

    // Spill threshold far below the number of deferred entries.
    let index = Arc::new(SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "cjk", 64).unwrap());
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(1024 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("cjk", JobMode::Copy, "src:", "dst:")
        .with_transfers(4)
        .with_allow_server_side_copy(false);
    let rep = engine.run(&cfg, index.clone()).await.unwrap();

    assert!(rep.errors.is_empty(), "errors: {:?}", rep.errors);
    assert!(
        index.is_spilled(),
        "deferred non-ASCII entries must spill to disk above the index threshold"
    );
    assert_eq!(dst.file_count(), 600);
    assert!(
        rep.conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::UnicodeNfcCollision),
        "{:?}",
        rep.conflicts
    );
}

/// Crash sweep on the real SQLite `StateActor` journal. A crash at boundary `k` means
/// every journal write not yet acknowledged is lost, exactly like a crash between two
/// group commits; the restarted process reopens `journal.db` from disk.
struct SqliteJournalHarness {
    root: tempfile::TempDir,
    actors: std::sync::Mutex<std::collections::HashMap<usize, rship_state::StateActor>>,
}

impl SqliteJournalHarness {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            actors: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn open_actor(&self, k: usize) -> Arc<dyn rship_core::state::JournalStore> {
        let actor = rship_state::StateActor::open(&self.root.path().join(format!("k{k}"))).unwrap();
        self.actors.lock().unwrap().insert(k, actor.clone());
        Arc::new(actor)
    }
}

impl rship_core::chaos::CrashJournalHarness for SqliteJournalHarness {
    async fn open(&self, k: usize) -> Arc<dyn rship_core::state::JournalStore> {
        self.open_actor(k)
    }

    async fn reopen(
        &self,
        k: usize,
        crashed: Arc<dyn rship_core::state::JournalStore>,
    ) -> Arc<dyn rship_core::state::JournalStore> {
        drop(crashed);
        let old = self.actors.lock().unwrap().remove(&k);
        if let Some(actor) = old {
            actor.shutdown().await.unwrap();
        }
        self.open_actor(k)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_sweep_on_sqlite_state_actor_journal() {
    let harness = SqliteJournalHarness::new();
    for scenario in rship_core::chaos::standard_crash_sweep_scenarios() {
        let steps = rship_core::chaos::run_crash_sweep(&scenario, &harness).await;
        assert!(steps > 0, "{}", scenario.label);
    }
}

/// The integrity marker survives a restart on the SQLite journal: after a `move` leaves a
/// corrupt object in place (its delete failed), a new process reopening `journal.db`
/// re-transfers the file instead of skipping it and deleting the only good copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integrity_marker_survives_restart_on_sqlite_journal() {
    use rship_core::chaos::FaultSchedule;
    use rship_core::state::{JournalStore, OperationState};

    let state_dir = tempfile::tempdir().unwrap();
    let src =
        Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).without_listing_checksums());
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("dst", 64 * 1024));
    let data: Vec<u8> = (0..8 * 1024).map(|i| (i % 251) as u8).collect();
    src.insert_file("photo.jpg", data.clone(), MTIME);
    let mut faults = FaultSchedule {
        corrupt_commit_remaining: u32::MAX,
        corrupt_commit_reports_mismatch: true,
        ..Default::default()
    };
    faults.fail_delete_paths.insert("photo.jpg".to_string());
    dst.set_faults(faults);

    let cfg = EngineConfig::new("marker-restart", JobMode::Move, "src:", "dst:")
        .with_transfers(1)
        .with_allow_server_side_copy(false)
        .with_max_retries(2)
        .with_base_retry_delay(std::time::Duration::from_millis(1));
    let run = |journal: Arc<dyn JournalStore>| {
        let src = src.clone();
        let dst = dst.clone();
        let cfg = cfg.clone();
        async move {
            TransferEngine::new(
                src,
                dst,
                journal,
                BufferPool::new(256 * 1024, 64 * 1024).unwrap(),
                Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
                CancelFlag::new(),
            )
            .run(
                &cfg,
                Arc::new(rship_core::chaos::InMemorySyncIndex::default()),
            )
            .await
            .unwrap()
        }
    };

    let actor = rship_state::StateActor::open(state_dir.path()).unwrap();
    let rep1 = run(Arc::new(actor.clone())).await;
    assert!(!rep1.errors.is_empty());
    assert!(dst.get_file_bytes("photo.jpg").is_some_and(|b| b != data));
    actor.shutdown().await.unwrap();

    // Restart: a new process opens the same state directory; the destination is healthy.
    dst.set_faults(FaultSchedule::default());
    let actor = rship_state::StateActor::open(state_dir.path()).unwrap();
    let markers = actor
        .list_active_operations()
        .await
        .unwrap()
        .into_iter()
        .filter(|o| o.state == OperationState::IntegrityFailed)
        .count();
    assert_eq!(markers, 1, "the marker must be durable");
    let rep2 = run(Arc::new(actor.clone())).await;
    assert!(rep2.is_success(), "{:?}", rep2.errors);
    assert_eq!(rep2.files_transferred, 1, "must re-transfer, not skip");
    assert_eq!(
        dst.get_file_bytes("photo.jpg").as_deref(),
        Some(data.as_slice())
    );
    assert!(src.get_file_bytes("photo.jpg").is_none());
    assert!(actor.list_active_operations().await.unwrap().is_empty());
    actor.shutdown().await.unwrap();
}
