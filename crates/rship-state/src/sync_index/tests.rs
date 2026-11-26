use super::*;
use crate::lock::ProcessLock;
use rship_core::path::RelPath;
use rship_core::state::ConflictKind;
use rship_core::types::{Checksum, EntryKind, HashKind};
use std::time::Duration;
use tempfile::TempDir;

fn mk_entry(raw: &str, size: u64) -> Entry {
    let nfc_path = RelPath::parse(raw).unwrap();
    Entry {
        node_id: None,
        parent_id: None,
        raw_path: rship_core::types::raw_path_override(&nfc_path, raw),
        nfc_path,
        kind: EntryKind::File,
        size,
        mtime_ns: 100,
        ctime_ns: None,
        etag: None,
        checksum: None,
    }
}

#[tokio::test]
async fn small_run_stays_in_ram_with_zero_disk_files() {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp(tmp.path(), "small-job").unwrap();
    idx.insert_src_batch(vec![mk_entry("a.txt", 10), mk_entry("b.txt", 20)])
        .await
        .unwrap();
    idx.insert_dst_batch(vec![mk_entry("b.txt", 20), mk_entry("c.txt", 30)])
        .await
        .unwrap();
    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());
    assert!(!idx.is_spilled());
    assert!(
        !tmp.path().join("run-small-job").exists(),
        "small runs must not create any run directory on disk"
    );
    assert_eq!(idx.db_size_bytes(), 0);
    assert_eq!(idx.next_src_page(0, 10).await.unwrap().len(), 2);
    let dst_only = idx.next_dst_only_page(0, 10).await.unwrap();
    assert_eq!(dst_only.len(), 1);
    assert_eq!(dst_only[0].dst.as_ref().unwrap().nfc_path.as_str(), "c.txt");
}

#[tokio::test]
async fn detects_nfc_duplicate_and_case_collisions_and_paginates_both_passes() {
    for spill in [false, true] {
        let tmp = TempDir::new().unwrap();
        let idx = if spill {
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "ci-spill", 2).unwrap()
        } else {
            SqliteSyncIndex::open_in_memory().unwrap()
        };
        idx.insert_src_batch(vec![
            mk_entry("Report.pdf", 10),
            mk_entry("report.pdf", 20),
            mk_entry("caf\u{00e9}.txt", 1),
            mk_entry("cafe\u{0301}.txt", 2),
            mk_entry("clean.bin", 42),
        ])
        .await
        .unwrap();
        idx.insert_dst_batch(vec![mk_entry("clean.bin", 42), mk_entry("orphan.bin", 99)])
            .await
            .unwrap();

        assert_eq!(idx.is_spilled(), spill);

        let conflicts = idx.finalize_and_detect_conflicts(false).await.unwrap();
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::UnicodeNfcCollision)
        );
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::CaseInsensitiveCollision)
        );

        // Keyset paginate src pass 2 rows at a time.
        let mut seen_src = 0;
        let mut cursor = 0;
        loop {
            let page = idx.next_src_page(cursor, 2).await.unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().unwrap().row_id;
            seen_src += page.len();
        }
        assert_eq!(seen_src, 5);

        // Destination-only pass finds `orphan.bin`.
        let dst_only = idx.next_dst_only_page(0, 10).await.unwrap();
        assert_eq!(dst_only.len(), 1);
        assert_eq!(
            dst_only[0].dst.as_ref().unwrap().nfc_path.as_str(),
            "orphan.bin"
        );
    }
}

#[tokio::test]
async fn detects_destination_and_cross_side_case_insensitive_collisions() {
    for spill in [false, true] {
        let tmp = TempDir::new().unwrap();
        let idx = if spill {
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "cross-spill", 2).unwrap()
        } else {
            SqliteSyncIndex::open_in_memory().unwrap()
        };
        idx.insert_src_batch(vec![
            mk_entry("CrossSide.txt", 10),
            mk_entry("normal.txt", 5),
        ])
        .await
        .unwrap();
        idx.insert_dst_batch(vec![
            mk_entry("DupDst.pdf", 1),
            mk_entry("dupdst.pdf", 2),
            mk_entry("crossside.txt", 10),
            mk_entry("normal.txt", 5),
        ])
        .await
        .unwrap();

        let conflicts = idx.finalize_and_detect_conflicts(false).await.unwrap();
        let ci_paths: Vec<&str> = conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::CaseInsensitiveCollision)
            .map(|c| c.nfc_path.as_str())
            .collect();
        assert!(ci_paths.contains(&"DupDst.pdf"));
        assert!(ci_paths.contains(&"dupdst.pdf"));
        assert!(ci_paths.contains(&"CrossSide.txt"));
        assert!(ci_paths.contains(&"crossside.txt"));
        assert!(!ci_paths.contains(&"normal.txt"));
    }
}

#[tokio::test]
async fn spilled_index_unlinks_raw_dbs_and_roundtrips_binary_hashes_and_nfd_paths_losslessly() {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "spill-job", 2).unwrap();
    let md5 = "0123456789abcdef0123456789abcdef".to_string();
    let mut s3_obj = mk_entry("shard/obj.bin", 12345);
    s3_obj.etag = Some(format!("\"{md5}\""));
    s3_obj.checksum = Some(Checksum {
        kind: HashKind::Md5,
        hex: md5.clone(),
    });
    let mut mp_obj = mk_entry("shard/multipart.bin", 50_000_000);
    mp_obj.etag = Some("\"deadbeef-8\"".into());
    let nfd_obj = mk_entry("cafe\u{0301}.txt", 7);

    idx.insert_src_batch(vec![s3_obj.clone(), mp_obj.clone(), nfd_obj.clone()])
        .await
        .unwrap();
    idx.insert_dst_batch(vec![s3_obj.clone()]).await.unwrap();
    assert!(idx.is_spilled());

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());

    let run_dir = tmp.path().join("run-spill-job");
    assert!(
        !run_dir.join("src_raw.db").exists(),
        "src_raw.db must be unlinked in O(1)"
    );
    assert!(
        !run_dir.join("dst_raw.db").exists(),
        "dst_raw.db must be unlinked in O(1)"
    );
    assert!(run_dir.join("sorted.db").exists());
    let (_total, free, av) = idx.db_diagnostics();
    assert_eq!(free, 0, "sorted.db should have zero freelist pages");
    assert_eq!(av, 0, "sorted.db uses auto_vacuum = NONE");

    let rows = idx.next_src_page(0, 10).await.unwrap();
    assert_eq!(rows.len(), 3);
    let got_nfd = rows
        .iter()
        .find(|r| r.src.as_ref().unwrap().nfc_path.as_str() == "caf\u{00e9}.txt")
        .unwrap();
    assert_eq!(got_nfd.src.as_ref().unwrap().raw_path(), "cafe\u{0301}.txt");
    let got_s3 = rows
        .iter()
        .find(|r| r.src.as_ref().unwrap().nfc_path.as_str() == "shard/obj.bin")
        .unwrap();
    assert_eq!(got_s3.src.as_ref().unwrap(), &s3_obj);
    assert_eq!(got_s3.dst.as_ref().unwrap(), &s3_obj);
    let got_mp = rows
        .iter()
        .find(|r| r.src.as_ref().unwrap().nfc_path.as_str() == "shard/multipart.bin")
        .unwrap();
    assert_eq!(got_mp.src.as_ref().unwrap(), &mp_obj);
    assert!(got_mp.dst.is_none());
}

#[tokio::test]
async fn same_case_dupes_are_not_case_collisions() {
    for spill in [false, true] {
        let tmp = TempDir::new().unwrap();
        let ci = if spill {
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "same-case", 1).unwrap()
        } else {
            SqliteSyncIndex::open_in_memory().unwrap()
        };
        ci.insert_src_batch(vec![
            mk_entry("Same.txt", 1),
            mk_entry("Same.txt", 2),
            mk_entry("clean.txt", 3),
        ])
        .await
        .unwrap();
        ci.insert_dst_batch(vec![mk_entry("clean.txt", 3)])
            .await
            .unwrap();
        let ci_conflicts = ci.finalize_and_detect_conflicts(false).await.unwrap();
        assert_eq!(ci_conflicts.len(), 1);
        assert_eq!(ci_conflicts[0].kind, ConflictKind::DuplicateSourceName);
        assert_eq!(ci_conflicts[0].nfc_path.as_str(), "Same.txt");
    }
}

#[test]
fn lazy_run_dir_cleans_up_on_drop_and_sweeper_skips_active_locks_only() {
    let tmp = TempDir::new().unwrap();
    let active = LazyRunDir::new(tmp.path().to_path_buf(), "active-job");
    assert!(!active.is_initialized());
    let active_dir = active.ensure_dir().unwrap();
    assert!(active.is_initialized());
    assert!(active_dir.exists());

    // Simulate a crashed orphan run directory + legacy sync-*.db file.
    let orphan_dir = tmp.path().join("run-crashed-job");
    std::fs::create_dir_all(&orphan_dir).unwrap();
    std::fs::write(orphan_dir.join("sorted.db"), b"dead").unwrap();
    let legacy_db = tmp.path().join("sync-legacy.db");
    std::fs::write(&legacy_db, b"old").unwrap();

    let swept = sweep_stale_runs_with_min_age(tmp.path(), Duration::ZERO);
    assert_eq!(swept, 2);
    assert!(!orphan_dir.exists());
    assert!(!legacy_db.exists());
    assert!(
        active_dir.exists(),
        "active locked run dir must NOT be swept"
    );

    drop(active);
    assert!(!active_dir.exists(), "run dir must be deleted on Drop");
}

#[tokio::test]
async fn d7_spilled_sync_index_keeps_synchronous_off() {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "sync-off", 1).unwrap();
    idx.insert_src_batch(vec![mk_entry("a.txt", 1), mk_entry("b.txt", 2)])
        .await
        .unwrap();
    idx.insert_dst_batch(vec![mk_entry("c.txt", 3)])
        .await
        .unwrap();
    assert!(idx.is_spilled());

    {
        let src_g = idx.handles().src.lock().await;
        let SideIngest::Spilled(ref sp) = *src_g else {
            panic!("expected spilled src storage");
        };
        let conn = sp.raw_conn().unwrap();
        let src_sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        let src_mmap: i64 = conn
            .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
            .unwrap();
        let src_temp: i64 = conn
            .query_row("PRAGMA temp_store;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(src_sync, 0, "src_raw.db must keep PRAGMA synchronous = OFF");
        assert_eq!(src_mmap, 0, "src_raw.db must keep PRAGMA mmap_size = 0");
        assert_eq!(src_temp, 1, "src_raw.db must keep PRAGMA temp_store = FILE");
    }

    {
        let dst_g = idx.handles().dst.lock().await;
        let SideIngest::Spilled(ref sp) = *dst_g else {
            panic!("expected spilled dst storage");
        };
        let conn = sp.raw_conn().unwrap();
        let dst_sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        let dst_mmap: i64 = conn
            .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
            .unwrap();
        let dst_temp: i64 = conn
            .query_row("PRAGMA temp_store;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(dst_sync, 0, "dst_raw.db must keep PRAGMA synchronous = OFF");
        assert_eq!(dst_mmap, 0, "dst_raw.db must keep PRAGMA mmap_size = 0");
        assert_eq!(dst_temp, 1, "dst_raw.db must keep PRAGMA temp_store = FILE");
    }

    idx.finalize_and_detect_conflicts(true).await.unwrap();

    let read_g = idx.handles().read.lock().await;
    let ReadState::Spilled(ref sp) = *read_g else {
        panic!("expected spilled sorted storage");
    };
    let sorted_conn = sp.sorted_conn().unwrap();
    let sorted_sync: i64 = sorted_conn
        .query_row("PRAGMA synchronous;", [], |r| r.get(0))
        .unwrap();
    let sorted_mmap: i64 = sorted_conn
        .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
        .unwrap();
    let sorted_temp: i64 = sorted_conn
        .query_row("PRAGMA temp_store;", [], |r| r.get(0))
        .unwrap();
    let sorted_cache: i64 = sorted_conn
        .query_row("PRAGMA cache_size;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        sorted_sync, 0,
        "sorted.db must keep PRAGMA synchronous = OFF"
    );
    assert_eq!(sorted_mmap, 0, "sorted.db must keep PRAGMA mmap_size = 0");
    assert_eq!(
        sorted_temp, 1,
        "sorted.db must keep PRAGMA temp_store = FILE"
    );
    assert_eq!(
        sorted_cache, -8192,
        "sorted.db must keep PRAGMA cache_size = -8192"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn p6_p12_current_thread_reactor_stays_responsive_during_gc_lock_retry_and_concurrent_spill()
{
    let tmp = TempDir::new().unwrap();
    let gc_lock = ProcessLock::try_acquire_file(&tmp.path().join(".gc.lock")).unwrap();
    let idx =
        Arc::new(SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "ct-gc-spill", 2).unwrap());

    let ticks = Arc::new(AtomicUsize::new(0));
    let ticks_task = ticks.clone();
    let releaser = tokio::spawn(async move {
        let _lock = gc_lock;
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            ticks_task.fetch_add(1, Ordering::Relaxed);
        }
        drop(_lock);
    });

    let idx_src = idx.clone();
    let src_task = tokio::spawn(async move {
        let batch: Vec<Entry> = (0..500)
            .map(|i| mk_entry(&format!("src/file_{i:04}.bin"), i as u64))
            .collect();
        idx_src.insert_src_batch(batch).await
    });

    // Give `src_task` a turn to enter the spill path before starting `dst_task`.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    let idx_dst = idx.clone();
    let dst_task = tokio::spawn(async move {
        let batch: Vec<Entry> = (0..500)
            .map(|i| mk_entry(&format!("dst/file_{i:04}.bin"), i as u64))
            .collect();
        idx_dst.insert_dst_batch(batch).await
    });

    let (r_rel, r_src, r_dst) = tokio::join!(releaser, src_task, dst_task);
    r_rel.unwrap();
    r_src
        .unwrap()
        .expect("src spill must succeed once async task releases .gc.lock");
    r_dst
        .unwrap()
        .expect("dst spill must not deadlock current_thread reactor");
    assert!(
        ticks.load(Ordering::Relaxed) >= 5,
        "current_thread async reactor must keep ticking while spills wait on .gc.lock"
    );

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());
    assert_eq!(idx.next_src_page(0, 1000).await.unwrap().len(), 500);
    assert_eq!(idx.next_dst_only_page(0, 1000).await.unwrap().len(), 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p6_concurrent_src_and_dst_spilled_writes_execute_in_parallel() {
    use std::sync::Condvar;

    let tmp = TempDir::new().unwrap();
    let idx =
        Arc::new(SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "parallel-rw", 2).unwrap());

    // Rendezvous inside the blocking raw SQLite write path: if `src` and `dst` were
    // serialized behind a single lock, the first writer would time out waiting for the other.
    let pair = Arc::new((StdMutex::new((false, false)), Condvar::new()));
    let overlapped = Arc::new(AtomicBool::new(false));
    let pair_hook = pair.clone();
    let overlapped_hook = overlapped.clone();
    idx.set_raw_write_hook(Arc::new(move |is_src| {
        let (lock, cvar) = &*pair_hook;
        let mut state = lock.lock().unwrap();
        if is_src {
            state.0 = true;
        } else {
            state.1 = true;
        }
        cvar.notify_all();
        let (guard, timeout) = cvar
            .wait_timeout_while(state, Duration::from_secs(3), |s| !(s.0 && s.1))
            .unwrap();
        if !timeout.timed_out() && guard.0 && guard.1 {
            overlapped_hook.store(true, Ordering::Release);
        }
    }));

    let src_entries: Vec<Entry> = (0..1000)
        .map(|i| mk_entry(&format!("shared/item_{i:04}.dat"), i as u64))
        .collect();
    let dst_entries: Vec<Entry> = (500..1500)
        .map(|i| mk_entry(&format!("shared/item_{i:04}.dat"), i as u64))
        .collect();

    let (r_src, r_dst) = tokio::join!(
        idx.insert_src_batch(src_entries),
        idx.insert_dst_batch(dst_entries),
    );
    r_src.unwrap();
    r_dst.unwrap();

    assert!(
        overlapped.load(Ordering::Acquire),
        "insert_src_batch and insert_dst_batch must execute in parallel on separate locks"
    );
    assert!(idx.is_spilled());

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());

    let src_rows = idx.next_src_page(0, 2000).await.unwrap();
    assert_eq!(src_rows.len(), 1000);
    let matched = src_rows.iter().filter(|r| r.dst.is_some()).count();
    assert_eq!(matched, 500);
    let dst_only = idx.next_dst_only_page(0, 2000).await.unwrap();
    assert_eq!(dst_only.len(), 500);
}

#[tokio::test(flavor = "current_thread")]
async fn p6_same_side_contention_never_blocks_current_thread_reactor_or_opposite_side() {
    use std::sync::Condvar;

    let tmp = TempDir::new().unwrap();
    let idx = Arc::new(
        SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "ct-contention", 2).unwrap(),
    );

    // Gate pauses ONLY the first `src` raw write until an async task on the single-threaded
    // reactor ticks 5 times and opens the gate. While paused:
    // - `dst` must still complete immediately (independent lock);
    // - a second concurrent `src` batch must suspend asynchronously without stalling the ticker.
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let src_hook_calls = Arc::new(AtomicUsize::new(0));
    let gate_hook = gate.clone();
    let calls_hook = src_hook_calls.clone();
    idx.set_raw_write_hook(Arc::new(move |is_src| {
        if is_src && calls_hook.fetch_add(1, Ordering::AcqRel) == 0 {
            let (lock, cvar) = &*gate_hook;
            let g = lock.lock().unwrap();
            let (_g, timeout) = cvar
                .wait_timeout_while(g, Duration::from_secs(3), |open| !*open)
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "current_thread reactor stalled before async task could open src write gate"
            );
        }
    }));

    let idx1 = idx.clone();
    let src1 = tokio::spawn(async move {
        idx1.insert_src_batch(vec![
            mk_entry("a.txt", 1),
            mk_entry("b.txt", 2),
            mk_entry("c.txt", 3),
        ])
        .await
    });

    // Let `src1` enter the blocking pool and pause on the gate.
    while src_hook_calls.load(Ordering::Acquire) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Queue a contending `src` batch AND an independent `dst` batch while `src1` is held.
    let idx2 = idx.clone();
    let src2 = tokio::spawn(async move {
        idx2.insert_src_batch(vec![mk_entry("d.txt", 4), mk_entry("e.txt", 5)])
            .await
    });

    let dst_done_before_gate = Arc::new(AtomicBool::new(false));
    let dst_done_flag = dst_done_before_gate.clone();
    let idx_dst = idx.clone();
    let dst_task = tokio::spawn(async move {
        idx_dst
            .insert_dst_batch(vec![
                mk_entry("b.txt", 2),
                mk_entry("e.txt", 5),
                mk_entry("orphan.txt", 9),
            ])
            .await?;
        dst_done_flag.store(true, Ordering::Release);
        Ok::<(), Error>(())
    });

    // Poll `src2` + `dst_task` on the single-threaded reactor before opening the gate.
    let mut ticks = 0usize;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        ticks += 1;
        if dst_done_before_gate.load(Ordering::Acquire) && ticks >= 5 {
            break;
        }
    }
    assert!(
        dst_done_before_gate.load(Ordering::Acquire),
        "dst write must complete independently even while src write is blocked"
    );
    assert!(
        ticks >= 5,
        "current_thread ticker must make steady progress"
    );

    // Open gate so `src1` completes and wakes `src2`.
    {
        let (lock, cvar) = &*gate;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }

    let (r1, r2, rd) = tokio::join!(src1, src2, dst_task);
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();
    rd.unwrap().unwrap();

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());
    let src_rows = idx.next_src_page(0, 20).await.unwrap();
    assert_eq!(src_rows.len(), 5);
    let dst_only = idx.next_dst_only_page(0, 20).await.unwrap();
    assert_eq!(dst_only.len(), 1);
    assert_eq!(
        dst_only[0].dst.as_ref().unwrap().nfc_path.as_str(),
        "orphan.txt"
    );
}

async fn run_concurrent_large_batches_reactor_check(job_id: &str) {
    let tmp = TempDir::new().unwrap();
    let idx = Arc::new(SqliteSyncIndex::open_temp_with_threshold(tmp.path(), job_id, 256).unwrap());

    let done = Arc::new(AtomicBool::new(false));
    let ticks = Arc::new(AtomicUsize::new(0));
    let done_t = done.clone();
    let ticks_t = ticks.clone();
    let ticker = tokio::spawn(async move {
        while !done_t.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
            ticks_t.fetch_add(1, Ordering::Relaxed);
        }
    });

    const BATCHES: usize = 20;
    const BATCH_SIZE: usize = 500;
    let idx_s = idx.clone();
    let src_writer = tokio::spawn(async move {
        for b in 0..BATCHES {
            let start = b * BATCH_SIZE;
            let batch = (start..start + BATCH_SIZE)
                .map(|i| mk_entry(&format!("tree/dir_{:02}/f_{i:06}.bin", i % 16), i as u64))
                .collect();
            idx_s.insert_src_batch(batch).await?;
        }
        Ok::<(), Error>(())
    });

    let idx_d = idx.clone();
    let dst_writer = tokio::spawn(async move {
        for b in 0..BATCHES {
            let start = b * BATCH_SIZE + 5_000;
            let batch = (start..start + BATCH_SIZE)
                .map(|i| mk_entry(&format!("tree/dir_{:02}/f_{i:06}.bin", i % 16), i as u64))
                .collect();
            idx_d.insert_dst_batch(batch).await?;
        }
        Ok::<(), Error>(())
    });

    let (rs, rd) = tokio::join!(src_writer, dst_writer);
    done.store(true, Ordering::Release);
    ticker.await.unwrap();
    rs.unwrap().unwrap();
    rd.unwrap().unwrap();

    assert!(idx.is_spilled());
    assert!(
        ticks.load(Ordering::Relaxed) >= 1,
        "concurrent async timer must tick during spilled batch ingestion"
    );

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());

    let (total_bytes, free_bytes, auto_vacuum) = idx.db_diagnostics();
    assert!(total_bytes > 0);
    assert_eq!(free_bytes, 0);
    assert_eq!(auto_vacuum, 0);

    let mut after_id = 0;
    let mut src_count = 0usize;
    let mut matched_count = 0usize;
    let mut prev_path: Option<String> = None;
    loop {
        let page = idx.next_src_page(after_id, 512).await.unwrap();
        if page.is_empty() {
            break;
        }
        for row in &page {
            let p = row.src.as_ref().unwrap().nfc_path.as_str();
            if let Some(ref prev) = prev_path {
                assert!(
                    prev.as_str() <= p,
                    "src rows must be deterministically sorted"
                );
            }
            prev_path = Some(p.to_string());
            if row.dst.is_some() {
                matched_count += 1;
            }
        }
        after_id = page.last().unwrap().row_id;
        src_count += page.len();
    }
    assert_eq!(src_count, BATCHES * BATCH_SIZE);
    assert_eq!(matched_count, 5_000);

    let mut dst_after = 0;
    let mut dst_only_count = 0usize;
    loop {
        let page = idx.next_dst_only_page(dst_after, 512).await.unwrap();
        if page.is_empty() {
            break;
        }
        dst_after = page.last().unwrap().row_id;
        dst_only_count += page.len();
    }
    assert_eq!(dst_only_count, 5_000);

    // Verify clean drop removes the ephemeral scratch directory.
    let run_path = idx.run_dir().unwrap().planned_path();
    assert!(run_path.exists());
    drop(idx);
    assert!(
        !run_path.exists(),
        "spilled run dir must be cleaned up on Drop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p6_large_concurrent_batches_multi_thread() {
    run_concurrent_large_batches_reactor_check("large-mt").await;
}

#[tokio::test(flavor = "current_thread")]
async fn p6_large_concurrent_batches_current_thread() {
    run_concurrent_large_batches_reactor_check("large-ct").await;
}

#[tokio::test]
async fn p6_partial_spill_handles_in_memory_opposite_side_losslessly() {
    // Case 1: src spills while dst stays empty (in-memory).
    {
        let tmp = TempDir::new().unwrap();
        let idx =
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "src-only-spill", 2).unwrap();
        idx.insert_src_batch(vec![
            mk_entry("c.txt", 3),
            mk_entry("a.txt", 1),
            mk_entry("b.txt", 2),
        ])
        .await
        .unwrap();
        assert!(idx.is_spilled());
        let run_dir = tmp.path().join("run-src-only-spill");
        assert!(!run_dir.join("dst_raw.db").exists());

        let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
        assert!(conflicts.is_empty());
        assert!(!run_dir.join("src_raw.db").exists());
        let (_total, free, av) = idx.db_diagnostics();
        assert_eq!(free, 0);
        assert_eq!(av, 0);

        let rows = idx.next_src_page(0, 10).await.unwrap();
        let names: Vec<&str> = rows
            .iter()
            .map(|r| r.src.as_ref().unwrap().nfc_path.as_str())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "c.txt"]);
        assert!(idx.next_dst_only_page(0, 10).await.unwrap().is_empty());
    }

    // Case 2: dst inserts small batch in RAM, then src spills; finalize merges both sides
    // including cross-side case collisions.
    {
        let tmp = TempDir::new().unwrap();
        let idx =
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "dst-ram-src-spill", 3).unwrap();
        idx.insert_dst_batch(vec![
            mk_entry("cross.txt", 10),
            mk_entry("dst_only.txt", 20),
        ])
        .await
        .unwrap();
        assert!(!idx.is_spilled());

        idx.insert_src_batch(vec![
            mk_entry("Cross.txt", 10),
            mk_entry("src_a.txt", 1),
            mk_entry("src_b.txt", 2),
        ])
        .await
        .unwrap();
        assert!(idx.is_spilled());

        let conflicts = idx.finalize_and_detect_conflicts(false).await.unwrap();
        let ci_paths: Vec<&str> = conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::CaseInsensitiveCollision)
            .map(|c| c.nfc_path.as_str())
            .collect();
        assert_eq!(ci_paths, vec!["Cross.txt", "cross.txt"]);

        let dst_only = idx.next_dst_only_page(0, 10).await.unwrap();
        let dst_names: Vec<&str> = dst_only
            .iter()
            .map(|r| r.dst.as_ref().unwrap().nfc_path.as_str())
            .collect();
        assert_eq!(dst_names, vec!["cross.txt", "dst_only.txt"]);
    }

    // Case 3: src stays small in RAM while dst spills.
    {
        let tmp = TempDir::new().unwrap();
        let idx =
            SqliteSyncIndex::open_temp_with_threshold(tmp.path(), "src-ram-dst-spill", 2).unwrap();
        idx.insert_src_batch(vec![mk_entry("keep.txt", 1)])
            .await
            .unwrap();
        assert!(!idx.is_spilled());

        idx.insert_dst_batch(vec![
            mk_entry("keep.txt", 1),
            mk_entry("extra1.txt", 2),
            mk_entry("extra2.txt", 3),
        ])
        .await
        .unwrap();
        assert!(idx.is_spilled());

        let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
        assert!(conflicts.is_empty());
        let src_rows = idx.next_src_page(0, 10).await.unwrap();
        assert_eq!(src_rows.len(), 1);
        assert!(src_rows[0].dst.is_some());
        let dst_only = idx.next_dst_only_page(0, 10).await.unwrap();
        assert_eq!(dst_only.len(), 2);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn p12_lazy_run_dir_async_and_sweeper_async_do_not_block_reactor() {
    let tmp = TempDir::new().unwrap();
    let gc_lock = ProcessLock::try_acquire_file(&tmp.path().join(".gc.lock")).unwrap();
    let run_dir = LazyRunDir::new(tmp.path().to_path_buf(), "async-dir");

    let ticks = Arc::new(AtomicUsize::new(0));
    let ticks_t = ticks.clone();
    let releaser = tokio::spawn(async move {
        let _lock = gc_lock;
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            ticks_t.fetch_add(1, Ordering::Relaxed);
        }
        drop(_lock);
    });

    let sub = run_dir.ensure_subdir_async("spool").await.unwrap();
    releaser.await.unwrap();
    assert!(sub.exists());
    assert!(run_dir.is_initialized());
    assert!(ticks.load(Ordering::Relaxed) >= 4);

    let orphan = tmp.path().join("run-stale-async");
    std::fs::create_dir_all(&orphan).unwrap();
    let swept = sweep_stale_runs_with_min_age_async(tmp.path().to_path_buf(), Duration::ZERO).await;
    assert_eq!(swept, 1);
    assert!(!orphan.exists());
    assert!(run_dir.planned_path().exists());

    let planned = run_dir.planned_path();
    drop(run_dir);
    assert!(!planned.exists());
}

/// The engine reaches the run directory through `RunScratchDir` (`--strict-source`, the
/// delete spill log). That path must wait for a contended `.gc.lock` without blocking the
/// executor thread, or a `current_thread` runtime can never run the task that releases it.
#[tokio::test(flavor = "current_thread")]
async fn p12_run_scratch_dir_trait_waits_for_gc_lock_without_blocking_current_thread() {
    use rship_core::state::RunScratchDir;
    let tmp = TempDir::new().unwrap();
    let gc_lock = ProcessLock::try_acquire_file(&tmp.path().join(".gc.lock")).unwrap();
    let scratch: Arc<dyn RunScratchDir> =
        Arc::new(LazyRunDir::new(tmp.path().to_path_buf(), "trait-dir"));
    let releaser = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(gc_lock);
    });
    let sub = scratch
        .ensure_subdir("strict-source")
        .await
        .expect("the gc lock is released by a task on this runtime");
    releaser.await.unwrap();
    assert!(sub.ends_with("strict-source"));
    assert!(sub.is_dir());
}
