use super::*;
use crate::backend::{BackendPath, StorageBackend};
use crate::buffer::BufferPool;
use crate::chaos::{ChaosBackend, InMemoryJournal, InMemorySyncIndex};
use crate::clock::VirtualClock;
use crate::engine::CancelFlag;
use std::time::Duration;

async fn upsert_chaos(b: &ChaosBackend, path: &str, data: &[u8], mtime_ns: i64) {
    let rel = RelPath::parse(path).unwrap();
    b.delete(&BackendPath::from_rel(rel)).await.unwrap();
    b.insert_file(path, data.to_vec(), mtime_ns);
}

#[tokio::test]
async fn three_tree_bisync_propagates_both_directions_deletes_and_preserves_conflicts() {
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("a", 256 * 1024));
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("b", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    // Initial seed: `only_a.txt` on A, `only_b.txt` on B, `shared.txt` on A.
    side_a.insert_file("only_a.txt", b"from-a".to_vec(), 1_700_000_000_000_000_000);
    side_a.insert_file("shared.txt", b"v1".to_vec(), 1_700_000_000_000_000_000);
    side_b.insert_file("only_b.txt", b"from-b".to_vec(), 1_700_000_000_000_000_000);

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // Round 1: initial convergence!
    let r1 = engine
        .run(
            &BisyncConfig::new("bs-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.errors.is_empty(), "{:?}", r1.errors);
    assert_eq!(r1.copied_a_to_b, 2);
    assert_eq!(r1.copied_b_to_a, 1);
    assert_eq!(side_b.get_file_bytes("only_a.txt").unwrap(), b"from-a");
    assert_eq!(side_a.get_file_bytes("only_b.txt").unwrap(), b"from-b");
    assert_eq!(side_b.get_file_bytes("shared.txt").unwrap(), b"v1");

    // Round 2:
    // - Delete `only_a.txt` on A -> must delete on B!
    // - Edit `only_b.txt` on B -> must propagate B -> A!
    // - Edit `shared.txt` concurrently on BOTH A ("v2-from-a") and B ("v2-from-b-longer")!
    clock.advance(Duration::from_secs(10));
    let t2 = clock.now_unix_nanos();
    side_a
        .delete(&BackendPath::from_rel(
            RelPath::parse("only_a.txt").unwrap(),
        ))
        .await
        .unwrap();
    upsert_chaos(&side_b, "only_b.txt", b"from-b-edited", t2).await;
    upsert_chaos(&side_a, "shared.txt", b"v2-from-a", t2).await;
    upsert_chaos(
        &side_b,
        "shared.txt",
        b"v2-from-b-longer",
        t2 + 1_000_000_000,
    )
    .await;

    let r2 = engine
        .run(
            &BisyncConfig::new("bs-2", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r2.errors.is_empty(), "{:?}", r2.errors);
    assert_eq!(r2.deleted_on_b, 1);
    assert_eq!(r2.conflicts_resolved, 1);

    assert!(side_b.get_file_bytes("only_a.txt").is_none());
    assert_eq!(
        side_a.get_file_bytes("only_b.txt").unwrap(),
        b"from-b-edited"
    );
    assert_eq!(side_a.get_file_bytes("shared.txt").unwrap(), b"v2-from-a");
    assert_eq!(side_b.get_file_bytes("shared.txt").unwrap(), b"v2-from-a");
    let conflict_name = format!("shared.conflict-{}.txt", clock.now_unix_secs());
    assert_eq!(
        side_a.get_file_bytes(&conflict_name).unwrap(),
        b"v2-from-b-longer"
    );
    assert_eq!(
        side_b.get_file_bytes(&conflict_name).unwrap(),
        b"v2-from-b-longer"
    );

    // Round 3: Modify-vs-Delete conflict under `ConflictStrategy::Abort` MUST preserve modified side!
    clock.advance(Duration::from_secs(10));
    let t3 = clock.now_unix_nanos();
    side_a
        .delete(&BackendPath::from_rel(
            RelPath::parse("only_b.txt").unwrap(),
        ))
        .await
        .unwrap();
    upsert_chaos(&side_b, "only_b.txt", b"important-edit-dont-lose", t3).await;

    let mut cfg3 = BisyncConfig::new("bs-3", "a", "b");
    cfg3.conflict_strategy = ConflictStrategy::Abort;
    let r3 = engine
        .run(&cfg3, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert_eq!(r3.conflicts.len(), 1);
    assert_eq!(r3.conflicts[0].kind, ConflictKind::ModifyDeleteConflict);
    assert_eq!(
        side_b.get_file_bytes("only_b.txt").unwrap(),
        b"important-edit-dont-lose"
    );

    // Round 4: `--resync` resets prior baselines and merges the union of A & B without
    // inferring deletions from stale baseline rows!
    clock.advance(Duration::from_secs(10));
    side_a
        .delete(&BackendPath::from_rel(
            RelPath::parse("shared.txt").unwrap(),
        ))
        .await
        .unwrap();
    let cfg4 = BisyncConfig::new("bs-4", "a", "b").with_resync(true);
    let r4 = engine
        .run(&cfg4, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(r4.errors.is_empty(), "{:?}", r4.errors);
    assert_eq!(r4.deleted_on_a, 0);
    assert_eq!(r4.deleted_on_b, 0);
    assert_eq!(side_a.get_file_bytes("shared.txt").unwrap(), b"v2-from-a");
    assert_eq!(
        side_a.get_file_bytes("only_b.txt").unwrap(),
        b"important-edit-dont-lose"
    );
}

#[tokio::test]
async fn bisync_multipart_large_file_keepboth_counters_and_baseline_pagination() {
    use crate::state::{JournalStore, compute_pair_key};

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    // `parallel_s3_like` has `single_shot_max_bytes = 16 KiB`, `part_size = 64 KiB`,
    // forcing multi-part uploads via `execute_transfer_task` for files > 16 KiB!
    let side_a = Arc::new(ChaosBackend::parallel_s3_like("a", 64 * 1024));
    let side_b = Arc::new(ChaosBackend::parallel_s3_like("b", 64 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).unwrap();

    let big_payload: Vec<u8> = (0..(192 * 1024 + 321))
        .map(|i| ((i * 29 + 7) % 251) as u8)
        .collect();
    side_a.insert_file("big.bin", big_payload.clone(), 1_700_000_000_000_000_000);
    for i in 0..4 {
        side_a.insert_file(
            &format!("small_{i}.txt"),
            format!("data-{i}").into_bytes(),
            1_700_000_000_000_000_000,
        );
    }

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // Round 1: initial convergence exercises parallel multipart upload for `big.bin`.
    let r1 = engine
        .run(
            &BisyncConfig::new("bs-mp-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.errors.is_empty(), "{:?}", r1.errors);
    assert_eq!(r1.copied_a_to_b, 5);
    assert_eq!(side_b.get_file_bytes("big.bin").unwrap(), big_payload);
    assert!(
        side_b.upload_request_count() >= 4,
        "big.bin must be uploaded via multipart chunks (saw {} upload requests)",
        side_b.upload_request_count()
    );

    // Verify `next_baseline_page` cursor pagination over the 5 baselines in strict ascending order.
    let pair_key = compute_pair_key(&side_a.endpoint_identity(), &side_b.endpoint_identity());
    let mut after: Option<String> = None;
    let mut seen = Vec::new();
    loop {
        let page = journal
            .next_baseline_page(&pair_key, after.as_deref(), 2)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        after = Some(page.last().unwrap().nfc_path.as_str().to_string());
        seen.extend(page.into_iter().map(|b| b.nfc_path.as_str().to_string()));
    }
    assert_eq!(
        seen,
        vec![
            "big.bin",
            "small_0.txt",
            "small_1.txt",
            "small_2.txt",
            "small_3.txt"
        ]
    );

    // Round 2: trigger a `KeepBoth` conflict and check job counter parity (`files_done` / `bytes_done`).
    clock.advance(Duration::from_secs(10));
    let t2 = clock.now_unix_nanos();
    upsert_chaos(&side_a, "small_0.txt", b"edit-from-a", t2).await;
    upsert_chaos(
        &side_b,
        "small_0.txt",
        b"edit-from-b-longer",
        t2 + 1_000_000_000,
    )
    .await;

    let r2 = engine
        .run(
            &BisyncConfig::new("bs-mp-2", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r2.errors.is_empty(), "{:?}", r2.errors);
    assert_eq!(r2.conflicts_resolved, 1);
    let job2 = journal.get_job("bs-mp-2").await.unwrap().unwrap();
    // KeepBoth writes B's conflict copy on B, copies it to A, and copies A's winner to B = 2 cross-side copies + 1 local conflict copy.
    assert!(
        job2.files_done >= 2,
        "KeepBoth job.files_done must reflect resolved conflict transfers (got {})",
        job2.files_done
    );
    assert!(
        job2.bytes_done >= (b"edit-from-a".len() + b"edit-from-b-longer".len()) as u64,
        "KeepBoth job.bytes_done must include transferred bytes (got {})",
        job2.bytes_done
    );
}

#[tokio::test]
async fn rclone_bisync_filter_drift_empty_side_guard_modtime_precision_and_conflict_convergence() {
    use crate::error::ErrorKind;
    use crate::filter::FilterSet;

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    // Side A: 100ns precision (NTFS/APFS); Side B: 2s precision (FAT32/older WebDAV)
    let side_a = Arc::new(
        ChaosBackend::sequential_gdrive_like("prec-a", 256 * 1024)
            .with_caps(|c| c.mtime_granularity = Duration::from_nanos(100)),
    );
    let side_b = Arc::new(
        ChaosBackend::sequential_gdrive_like("prec-b", 256 * 1024)
            .with_caps(|c| c.mtime_granularity = Duration::from_secs(2)),
    );
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    side_a.insert_file("doc.txt", b"hello-v1".to_vec(), 1_700_000_000_123_456_700);
    side_a.insert_file("keep.log", b"log-v1".to_vec(), 1_700_000_000_000_000_000);
    side_b.insert_file("other.txt", b"from-b".to_vec(), 1_700_000_000_000_000_000);

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // 1. Initial sync with filter `--exclude *.log`
    let f1 = FilterSet::new(&[], &["*.log".into()]).unwrap();
    let r1 = engine
        .run(
            &BisyncConfig::new("g-1", "a", "b").with_filter(f1.clone()),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);
    assert_eq!(r1.copied_a_to_b, 1); // doc.txt only (keep.log excluded)
    assert_eq!(r1.copied_b_to_a, 1); // other.txt
    assert!(side_b.get_file_bytes("keep.log").is_none());

    // 2. Cross-precision modtime convergence: truncate Side B's mtime to 2s boundary (+1.2s drift)
    // and run 2 more rounds -> MUST produce 0 transfers & 0 errors!
    upsert_chaos(&side_b, "doc.txt", b"hello-v1", 1_700_000_000_000_000_000).await;
    for round in 2..=3 {
        let r = engine
            .run(
                &BisyncConfig::new(format!("g-conv-{round}"), "a", "b").with_filter(f1.clone()),
                Arc::new(InMemorySyncIndex::default()),
            )
            .await
            .unwrap();
        assert!(r.is_success(), "round {round} errors: {:?}", r.errors);
        assert_eq!(r.copied_a_to_b, 0, "round {round} must not re-copy A->B");
        assert_eq!(r.copied_b_to_a, 0, "round {round} must not re-copy B->A");
        assert_eq!(r.deleted_on_a, 0);
        assert_eq!(r.deleted_on_b, 0);
    }

    // 3. Filter drift guard: changing filters WITHOUT `--resync` MUST fail PreconditionFailed
    // BEFORE mutating either side!
    let f2 = FilterSet::new(&[], &["*.tmp".into()]).unwrap();
    let err = engine
        .run(
            &BisyncConfig::new("g-drift", "a", "b").with_filter(f2.clone()),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert!(
        err.message.contains("filter rules changed"),
        "unexpected error: {err}"
    );
    // Side B must remain completely untouched (`keep.log` was NOT copied).
    assert!(side_b.get_file_bytes("keep.log").is_none());

    // 4. Re-running with `--resync` adopts the new filter cleanly and converges `keep.log`!
    let r_resync = engine
        .run(
            &BisyncConfig::new("g-resync", "a", "b")
                .with_filter(f2.clone())
                .with_resync(true),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r_resync.is_success(), "{:?}", r_resync.errors);
    assert_eq!(side_b.get_file_bytes("keep.log").unwrap(), b"log-v1");

    // 5. Conflict-copy convergence: create a KeepBoth conflict, then run a subsequent bisync
    // round and confirm zero transfers and NO `.conflict.conflict` recursion!
    clock.advance(Duration::from_secs(30));
    let t_conf = clock.now_unix_nanos();
    upsert_chaos(&side_a, "doc.txt", b"hello-v2-a", t_conf).await;
    upsert_chaos(
        &side_b,
        "doc.txt",
        b"hello-v2-b-diff",
        t_conf + 5_000_000_000,
    )
    .await;
    let r_conf = engine
        .run(
            &BisyncConfig::new("g-conf-1", "a", "b").with_filter(f2.clone()),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r_conf.is_success(), "{:?}", r_conf.errors);
    assert_eq!(r_conf.conflicts_resolved, 1);

    let r_after_conf = engine
        .run(
            &BisyncConfig::new("g-conf-2", "a", "b").with_filter(f2.clone()),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r_after_conf.is_success(), "{:?}", r_after_conf.errors);
    assert_eq!(r_after_conf.copied_a_to_b, 0);
    assert_eq!(r_after_conf.copied_b_to_a, 0);
    assert_eq!(r_after_conf.conflicts_resolved, 0);

    // 6. Empty-side disaster guard: simulate Side A mount disappearing (all files gone on A).
    // Bisync MUST refuse and preserve ALL files on Side B!
    for name in [
        "doc.txt",
        "keep.log",
        "other.txt",
        &format!("doc.conflict-{}.txt", clock.now_unix_secs()),
    ] {
        side_a
            .delete(&BackendPath::from_rel(RelPath::parse(name).unwrap()))
            .await
            .unwrap();
    }
    assert_eq!(side_a.file_count(), 0);
    let b_before = side_b.file_count();
    assert!(b_before >= 4);

    let err_empty = engine
        .run(
            &BisyncConfig::new("g-empty", "a", "b").with_filter(f2.clone()),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap_err();
    assert_eq!(err_empty.kind, ErrorKind::PreconditionFailed);
    assert!(
        err_empty.message.contains("empty-side safety guard"),
        "unexpected error: {err_empty}"
    );
    assert_eq!(
        side_b.file_count(),
        b_before,
        "empty-side guard MUST protect every file on Side B"
    );

    // Explicit `--force-empty-side` allows intentional full wipe propagation when user overrides.
    let r_forced = engine
        .run(
            &BisyncConfig::new("g-force-empty", "a", "b")
                .with_filter(f2)
                .with_force_empty_side(true),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r_forced.is_success(), "{:?}", r_forced.errors);
    assert_eq!(side_b.file_count(), 0);
}

#[tokio::test]
async fn bisync_streaming_merge_ordered_s3_enforces_empty_side_guard_and_converges() {
    use crate::error::ErrorKind;

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(
        ChaosBackend::parallel_s3_like("s3-a", 64 * 1024)
            .with_caps(|c| c.supports_ordered_utf8_list = true),
    );
    let side_b = Arc::new(
        ChaosBackend::parallel_s3_like("s3-b", 64 * 1024)
            .with_caps(|c| c.supports_ordered_utf8_list = true),
    );
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 64 * 1024).unwrap();

    side_a.insert_file("alpha.txt", b"a1".to_vec(), 1_700_000_000_000_000_000);
    side_b.insert_file("beta.txt", b"b1".to_vec(), 1_700_000_000_000_000_000);

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    let r1 = engine
        .run(
            &BisyncConfig::new("s3-bs-1", "s3a", "s3b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);
    assert_eq!(side_a.file_count(), 2);
    assert_eq!(side_b.file_count(), 2);

    // Wipe side B (simulating misconfigured empty bucket/prefix) AND add a brand-new file on A:
    // streaming merge MUST abort BEFORE copying `gamma.txt` into empty Side B OR deleting on A!
    side_a.insert_file("gamma.txt", b"new-a".to_vec(), 1_700_000_005_000_000_000);
    side_b
        .delete(&BackendPath::from_rel(RelPath::parse("alpha.txt").unwrap()))
        .await
        .unwrap();
    side_b
        .delete(&BackendPath::from_rel(RelPath::parse("beta.txt").unwrap()))
        .await
        .unwrap();
    assert_eq!(side_b.file_count(), 0);

    let err = engine
        .run(
            &BisyncConfig::new("s3-bs-empty", "s3a", "s3b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert_eq!(
        side_a.file_count(),
        3,
        "streaming-merge empty-side guard must block all deletions on Side A"
    );
    assert_eq!(
        side_b.file_count(),
        0,
        "streaming-merge empty-side guard must abort BEFORE uploading new files to empty Side B"
    );
}

#[tokio::test]
async fn d3_interrupted_first_bisync_arms_empty_side_guard() {
    use crate::chaos::FaultSchedule;
    use crate::error::ErrorKind;
    use crate::state::{JournalStore, compute_pair_key};

    // Part A: Run 1 copies 3 files A->B and fails on file 4 (so end-of-run `bisync_state`
    // is never reached). Side A then disappears -> Run 2 MUST refuse to mass-delete Side B!
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("d3-a", 256 * 1024));
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("d3-b", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    for i in 0..4 {
        side_a.insert_file(
            &format!("file_{i}.txt"),
            format!("content-{i}").into_bytes(),
            1_700_000_000_000_000_000,
        );
    }
    let mut faults = FaultSchedule::default();
    faults.fail_put_paths.insert("file_3.txt".into());
    side_b.set_faults(faults);

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    let r1 = engine
        .run(
            &BisyncConfig::new("d3-bs-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(!r1.is_success(), "run 1 should fail on file_3.txt");
    assert_eq!(side_b.file_count(), 3, "run 1 copied 3 files before error");

    // Clear fault, then simulate Side A mount disappearing!
    side_b.set_faults(FaultSchedule::default());
    for i in 0..4 {
        side_a
            .delete(&BackendPath::from_rel(
                RelPath::parse(&format!("file_{i}.txt")).unwrap(),
            ))
            .await
            .unwrap();
    }
    assert_eq!(side_a.file_count(), 0);

    let err = engine
        .run(
            &BisyncConfig::new("d3-bs-2", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);
    assert!(
        err.message.contains("empty-side safety guard"),
        "unexpected error: {err}"
    );
    assert_eq!(
        side_b.file_count(),
        3,
        "empty-side guard MUST protect Side B after interrupted first bisync run"
    );

    // Part B: Simulate upgraded v0.1.0 journal where `bisync_state` is `None` while
    // `sync_baseline` rows exist from an interrupted run -> guard MUST STILL refuse!
    let legacy_journal = Arc::new(InMemoryJournal::default());
    let pair_key = compute_pair_key(&side_a.endpoint_identity(), &side_b.endpoint_identity());
    for i in 0..3 {
        let b_entry = side_b
            .stat(&BackendPath::from_rel(
                RelPath::parse(&format!("file_{i}.txt")).unwrap(),
            ))
            .await
            .unwrap()
            .unwrap();
        let base = make_bisync_baseline(
            &pair_key,
            &b_entry,
            &b_entry,
            &(clock.clone() as Arc<dyn crate::clock::Clock>),
        );
        legacy_journal
            .commit_verified_transfer(None, Some(&base), "legacy-job", b_entry.size)
            .await
            .unwrap();
    }
    assert!(
        legacy_journal
            .get_bisync_state(&pair_key)
            .await
            .unwrap()
            .is_none()
    );

    let legacy_engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        legacy_journal,
        pool,
        clock,
        CancelFlag::new(),
    );
    let err_legacy = legacy_engine
        .run(
            &BisyncConfig::new("d3-bs-legacy", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap_err();
    assert_eq!(err_legacy.kind, ErrorKind::PreconditionFailed);
    assert!(
        err_legacy.message.contains("empty-side safety guard"),
        "unexpected legacy error: {err_legacy}"
    );
    assert_eq!(side_b.file_count(), 3);
}

#[tokio::test]
async fn d3_bisync_default_max_delete_percent_aborts_over_50_and_allows_override() {
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("d3-pct-a", 256 * 1024));
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("d3-pct-b", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    for i in 0..4 {
        side_a.insert_file(
            &format!("f{i}.txt"),
            format!("data-{i}").into_bytes(),
            1_700_000_000_000_000_000,
        );
    }

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    let r1 = engine
        .run(
            &BisyncConfig::new("d3-pct-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);
    assert_eq!(side_b.file_count(), 4);

    // Delete 3 of 4 files (75% > default 50%) on Side A!
    for i in 0..3 {
        side_a
            .delete(&BackendPath::from_rel(
                RelPath::parse(&format!("f{i}.txt")).unwrap(),
            ))
            .await
            .unwrap();
    }

    // Default `BisyncConfig` (`max_delete_percent: Some(50.0)`) MUST abort deletions!
    let cfg_default = BisyncConfig::new("d3-pct-2", "a", "b");
    assert_eq!(cfg_default.max_delete_percent, Some(50.0));
    let r2 = engine
        .run(&cfg_default, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(
        !r2.is_success(),
        "default 50% max-delete guard must abort deleting 3 of 4 files"
    );
    assert_eq!(r2.deleted_on_b, 0);
    assert_eq!(side_b.file_count(), 4);

    // Explicit `max_delete_percent: None` overrides and permits the 75% delete!
    let r3 = engine
        .run(
            &BisyncConfig::new("d3-pct-3", "a", "b").with_max_delete_percent(None),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r3.is_success(), "{:?}", r3.errors);
    assert_eq!(r3.deleted_on_b, 3);
    assert_eq!(side_b.file_count(), 1);

    // Explicit `max_delete: Some(10)` overrides default `max_delete_percent: Some(50.0)`.
    for i in 1..4 {
        side_a.insert_file(
            &format!("g{i}.txt"),
            format!("g-{i}").into_bytes(),
            1_700_000_010_000_000_000,
        );
    }
    let r4 = engine
        .run(
            &BisyncConfig::new("d3-pct-4", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r4.is_success(), "{:?}", r4.errors);
    assert_eq!(side_b.file_count(), 4);

    for i in 1..4 {
        side_a
            .delete(&BackendPath::from_rel(
                RelPath::parse(&format!("g{i}.txt")).unwrap(),
            ))
            .await
            .unwrap();
    }
    let r5 = engine
        .run(
            &BisyncConfig::new("d3-pct-5", "a", "b").with_max_delete(Some(10)),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r5.is_success(), "{:?}", r5.errors);
    assert_eq!(r5.deleted_on_b, 3);
    assert_eq!(side_b.file_count(), 1);
}

#[tokio::test]
async fn d4_bisync_phase3_delete_restats_and_preserves_concurrently_modified_file() {
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::error::ErrorKind;
    use crate::source::{ByteStream, DataSource};
    use crate::state::OperationRecord;
    use crate::types::{ByteRange, Checksum, HashKind};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MutateAOnPutBackend {
        inner: Arc<ChaosBackend>,
        side_a: Arc<ChaosBackend>,
        mutate_time_ns: i64,
        fired: AtomicBool,
    }

    #[async_trait]
    impl StorageBackend for MutateAOnPutBackend {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn kind(&self) -> &'static str {
            self.inner.kind()
        }
        fn endpoint_identity(&self) -> String {
            self.inner.endpoint_identity()
        }
        fn capabilities(&self) -> Capabilities {
            self.inner.capabilities()
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            self.inner.stat(path).await
        }
        async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
            self.inner.list_stream(prefix, recursive).await
        }
        async fn mkdir(&self, path: &RelPath) -> Result<()> {
            self.inner.mkdir(path).await
        }
        async fn delete(&self, path: &BackendPath) -> Result<()> {
            self.inner.delete(path).await
        }
        async fn compute_hash(
            &self,
            path: &BackendPath,
            kind: HashKind,
        ) -> Result<Option<Checksum>> {
            self.inner.compute_hash(path, kind).await
        }
        async fn open_read(
            &self,
            path: &BackendPath,
            range: Option<ByteRange>,
        ) -> Result<DataSource> {
            self.inner.open_read(path, range).await
        }
        async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
            let res = self.inner.put_single_shot(init, body).await;
            if init.dst_path.as_str() == "trigger.txt" && !self.fired.swap(true, Ordering::SeqCst) {
                upsert_chaos(
                    &self.side_a,
                    "victim.txt",
                    b"concurrent-edit-during-phase2",
                    self.mutate_time_ns,
                )
                .await;
            }
            res
        }
        async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
            self.inner.begin_upload(init).await
        }
        async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
            self.inner.query_upload(op).await
        }
        async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
            self.inner.upload_chunk(op, chunk).await
        }
        async fn finish_upload(
            &self,
            op: &OperationRecord,
            parts: &[CompletedPart],
        ) -> Result<Entry> {
            self.inner.finish_upload(op, parts).await
        }
        async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
            self.inner.abort_upload(op).await
        }
        async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
            self.inner.reconcile_operation(op).await
        }
    }

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("d4-del-a", 256 * 1024));
    let side_b_raw = Arc::new(ChaosBackend::sequential_gdrive_like("d4-del-b", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    let t1 = clock.now_unix_nanos();
    side_a.insert_file("trigger.txt", b"v1".to_vec(), t1);
    side_a.insert_file("victim.txt", b"original-v1".to_vec(), t1);
    side_a.insert_file("stay.txt", b"stay".to_vec(), t1);

    let init_engine = BisyncEngine::new(
        side_a.clone(),
        side_b_raw.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let r1 = init_engine
        .run(
            &BisyncConfig::new("d4-del-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);

    // Between runs: modify `trigger.txt` on A (so Phase 2 copies A->B) and delete `victim.txt`
    // on B (so Phase 3 plans DeleteOnA(victim.txt)). During Phase 2, `victim.txt` on A is edited!
    clock.advance(Duration::from_secs(10));
    let t2 = clock.now_unix_nanos();
    upsert_chaos(&side_a, "trigger.txt", b"v2-updated", t2).await;
    side_b_raw
        .delete(&BackendPath::from_rel(
            RelPath::parse("victim.txt").unwrap(),
        ))
        .await
        .unwrap();

    let side_b_hook = Arc::new(MutateAOnPutBackend {
        inner: side_b_raw.clone(),
        side_a: side_a.clone(),
        mutate_time_ns: t2 + 5_000_000_000,
        fired: AtomicBool::new(false),
    });
    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b_hook,
        journal.clone(),
        pool,
        clock,
        CancelFlag::new(),
    );
    let r2 = engine
        .run(
            &BisyncConfig::new("d4-del-2", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();

    assert_eq!(
        side_a.get_file_bytes("victim.txt").as_deref(),
        Some(b"concurrent-edit-during-phase2".as_slice()),
        "Phase 3 delete MUST re-stat and preserve concurrently modified file on Side A"
    );
    assert_eq!(r2.deleted_on_a, 0);
    assert!(
        r2.error_details
            .iter()
            .any(|e| e.kind == ErrorKind::PreconditionFailed),
        "expected PreconditionFailed diagnostic, got: {:?}",
        r2.error_details
    );
}

#[tokio::test]
async fn d4_bisync_phase2_overwrite_restats_when_no_conditional_write() {
    use crate::error::ErrorKind;
    use crate::state::{DiffRow, SyncDiffIndex};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MutateBOnFinalizeIndex {
        inner: InMemorySyncIndex,
        side_b: Arc<ChaosBackend>,
        mutate_time_ns: i64,
        fired: AtomicBool,
    }

    #[async_trait]
    impl SyncDiffIndex for MutateBOnFinalizeIndex {
        async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.inner.insert_src_batch(entries).await
        }
        async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.inner.insert_dst_batch(entries).await
        }
        async fn finalize_and_detect_conflicts(
            &self,
            dst_case_sensitive: bool,
        ) -> Result<Vec<SyncConflict>> {
            let conflicts = self
                .inner
                .finalize_and_detect_conflicts(dst_case_sensitive)
                .await?;
            if !self.fired.swap(true, Ordering::SeqCst) {
                upsert_chaos(
                    &self.side_b,
                    "doc.txt",
                    b"concurrent-edit-on-b-must-not-be-clobbered",
                    self.mutate_time_ns,
                )
                .await;
            }
            Ok(conflicts)
        }
        async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
            self.inner.list_conflicts().await
        }
        async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            self.inner.next_src_page(after_id, limit).await
        }
        async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            self.inner.next_dst_only_page(after_id, limit).await
        }
    }

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    // `sequential_gdrive_like` has `supports_conditional_write = false`.
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("d4-ow-a", 256 * 1024));
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("d4-ow-b", 256 * 1024));
    assert!(!side_b.capabilities().supports_conditional_write);

    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    let t1 = clock.now_unix_nanos();
    side_a.insert_file("doc.txt", b"v1".to_vec(), t1);

    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        pool,
        clock.clone(),
        CancelFlag::new(),
    );
    let r1 = engine
        .run(
            &BisyncConfig::new("d4-ow-1", "a", "b"),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);

    // Edit `doc.txt` on Side A so Phase 1 plans CopyAToB overwriting Side B's v1.
    // Right after Phase 1 observation, Side B is concurrently edited!
    clock.advance(Duration::from_secs(10));
    let t2 = clock.now_unix_nanos();
    upsert_chaos(&side_a, "doc.txt", b"edit-from-a", t2).await;

    let hook_index = Arc::new(MutateBOnFinalizeIndex {
        inner: InMemorySyncIndex::default(),
        side_b: side_b.clone(),
        mutate_time_ns: t2 + 5_000_000_000,
        fired: AtomicBool::new(false),
    });
    let r2 = engine
        .run(&BisyncConfig::new("d4-ow-2", "a", "b"), hook_index)
        .await
        .unwrap();

    assert_eq!(
        side_b.get_file_bytes("doc.txt").as_deref(),
        Some(b"concurrent-edit-on-b-must-not-be-clobbered".as_slice()),
        "Phase 2 overwrite MUST re-stat destination when backend lacks conditional writes"
    );
    assert_eq!(r2.copied_a_to_b, 0);
    assert!(
        r2.error_details
            .iter()
            .any(|e| e.kind == ErrorKind::PreconditionFailed),
        "expected PreconditionFailed diagnostic, got: {:?}",
        r2.error_details
    );
}

#[tokio::test]
async fn d12_bisync_early_error_marks_job_failed() {
    use crate::state::{DiffRow, JobStatus, JournalStore, SyncDiffIndex};
    use async_trait::async_trait;

    struct FailingFinalizeIndex(InMemorySyncIndex);

    #[async_trait]
    impl SyncDiffIndex for FailingFinalizeIndex {
        async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.0.insert_src_batch(entries).await
        }
        async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
            self.0.insert_dst_batch(entries).await
        }
        async fn finalize_and_detect_conflicts(
            &self,
            _dst_case_sensitive: bool,
        ) -> Result<Vec<SyncConflict>> {
            Err(Error::state_store("injected bisync finalize error"))
        }
        async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
            self.0.list_conflicts().await
        }
        async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            self.0.next_src_page(after_id, limit).await
        }
        async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
            self.0.next_dst_only_page(after_id, limit).await
        }
    }

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::sequential_gdrive_like("d12-bs-a", 256 * 1024));
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("d12-bs-b", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    side_a.insert_file("a.txt", b"a".to_vec(), 1_700_000_000_000_000_000);

    let engine = BisyncEngine::new(
        side_a,
        side_b,
        journal.clone(),
        pool,
        clock,
        CancelFlag::new(),
    );
    let err = engine
        .run(
            &BisyncConfig::new("d12-bs-job", "a", "b"),
            Arc::new(FailingFinalizeIndex(InMemorySyncIndex::default())),
        )
        .await
        .unwrap_err();
    assert!(err.message.contains("injected bisync finalize error"));

    let job = journal.get_job("d12-bs-job").await.unwrap().unwrap();
    assert_eq!(
        job.status,
        JobStatus::Failed,
        "bisync early error MUST transition job status from Running to Failed"
    );
}

/// One retry budget for the whole bisync run: every per-file transfer draws from the same
/// token bucket instead of a fresh 500-token bucket per file.
#[tokio::test]
async fn bisync_retry_quota_is_shared_across_all_files_in_a_run() {
    const FILES: usize = 25;
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let side_a = Arc::new(ChaosBackend::parallel_s3_like("a", 64 * 1024));
    let side_b = Arc::new(ChaosBackend::parallel_s3_like("b", 64 * 1024));
    let mut failing = std::collections::HashSet::new();
    for i in 0..FILES {
        let path = format!("f{i:02}.bin");
        side_a.insert_file(&path, vec![i as u8; 64], 1_700_000_000_000_000_000);
        failing.insert(path);
    }
    // Every upload to B fails with a retryable 503.
    side_b.set_faults(crate::chaos::FaultSchedule {
        fail_put_transient_paths: failing,
        ..Default::default()
    });
    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(1024 * 1024, 64 * 1024).unwrap(),
        clock,
        CancelFlag::new(),
    );
    let rep = engine
        .run(
            &BisyncConfig::new("bs-quota", "a", "b")
                .with_transfers(1)
                .with_resync(true),
            Arc::new(InMemorySyncIndex::default()),
        )
        .await
        .unwrap();
    assert!(!rep.errors.is_empty());

    // Default quota: 500 tokens, 5 per retry, never refunded (nothing succeeds) => at most
    // 100 retries for the run. Per-file buckets would allow FILES * (1 + 5) attempts.
    let attempts = side_b.put_single_shot_calls() as usize;
    assert!(
        attempts <= FILES + 100,
        "retry quota must be shared across the run: {attempts} upload attempts for {FILES} files"
    );
}

/// A corrupt object left on side B after an integrity failure (its delete failed) has A's
/// size and mtime. Bisync must not treat the path as in sync, must not write a baseline
/// over it, and must re-copy it from A; the verified copy clears the integrity marker.
#[tokio::test]
async fn bisync_never_trusts_a_corrupt_object_flagged_by_an_integrity_marker() {
    use crate::chaos::FaultSchedule;
    use crate::state::{JournalStore, OperationState};

    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    // A exposes no checksums (local-like), so only size and mtime can be compared.
    let side_a =
        Arc::new(ChaosBackend::parallel_s3_like("a", 64 * 1024).without_listing_checksums());
    let side_b = Arc::new(ChaosBackend::sequential_gdrive_like("b", 64 * 1024));
    let data: Vec<u8> = (0..8 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    side_a.insert_file("doc.bin", data.clone(), 1_700_000_000_000_000_000);
    let mut faults = FaultSchedule {
        corrupt_commit_remaining: u32::MAX,
        corrupt_commit_reports_mismatch: true,
        ..Default::default()
    };
    faults.fail_delete_paths.insert("doc.bin".to_string());
    side_b.set_faults(faults.clone());

    let journal = Arc::new(InMemoryJournal::default());
    let engine = BisyncEngine::new(
        side_a.clone(),
        side_b.clone(),
        journal.clone(),
        BufferPool::new(1024 * 1024, 64 * 1024).unwrap(),
        clock,
        CancelFlag::new(),
    );
    let cfg = |job: &str| {
        BisyncConfig::new(job, "a", "b")
            .with_transfers(1)
            .with_resync(true)
    };
    let markers = |ops: Vec<crate::state::OperationRecord>| {
        ops.iter()
            .filter(|o| o.state == OperationState::IntegrityFailed)
            .count()
    };
    let pair_key = crate::engine::make_prefixed_pair_key(
        &side_a.endpoint_identity(),
        &RelPath::root(),
        &side_b.endpoint_identity(),
        &RelPath::root(),
    );
    let doc = RelPath::parse("doc.bin").unwrap();

    // Run 1: the copy to B fails verification and the corrupt object stays on B.
    let r1 = engine
        .run(&cfg("bs-marker-1"), Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!r1.errors.is_empty());
    let corrupt = side_b
        .get_file_bytes("doc.bin")
        .expect("corrupt object left on B");
    assert_ne!(corrupt, data);
    assert_eq!(markers(journal.list_active_operations().await.unwrap()), 1);

    // Run 2: B still corrupts. The path is not converged: no baseline, A untouched.
    let r2 = engine
        .run(&cfg("bs-marker-2"), Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(
        !r2.errors.is_empty(),
        "the path must be re-copied, not converged"
    );
    assert!(
        journal
            .get_baseline(&pair_key, &doc)
            .await
            .unwrap()
            .is_none(),
        "no baseline may be written over the corrupt object"
    );
    assert_eq!(
        side_a.get_file_bytes("doc.bin").as_deref(),
        Some(data.as_slice())
    );
    assert_eq!(markers(journal.list_active_operations().await.unwrap()), 1);

    // Run 3: B is healthy. The file is re-copied from A and the marker is cleared.
    faults.corrupt_commit_remaining = 0;
    side_b.set_faults(faults);
    let r3 = engine
        .run(&cfg("bs-marker-3"), Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(r3.is_success(), "{:?}", r3.errors);
    assert_eq!(r3.copied_a_to_b, 1, "must re-copy, not converge");
    assert_eq!(
        side_b.get_file_bytes("doc.bin").as_deref(),
        Some(data.as_slice())
    );
    assert_eq!(
        side_a.get_file_bytes("doc.bin").as_deref(),
        Some(data.as_slice())
    );
    assert_eq!(markers(journal.list_active_operations().await.unwrap()), 0);
    assert!(
        journal
            .get_baseline(&pair_key, &doc)
            .await
            .unwrap()
            .is_some()
    );
}
