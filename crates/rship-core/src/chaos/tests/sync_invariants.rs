use super::super::*;
use crate::backend::{BackendPath, StorageBackend};
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::path::RelPath;
use crate::state::JobMode;
use std::sync::Arc;

#[tokio::test]
async fn rclone_sync_invariants_change_case_mid_error_excluded_and_self_overwrite() {
    use crate::filter::FilterSet;

    let t1 = 1_700_000_000_000_000_000i64;
    let clock = Arc::new(VirtualClock::new(1_700_000_500));
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();

    // 1. rclone `TestSyncChangeCase`: source renamed `readme.txt` -> `README.txt` while
    //    destination is case-insensitive (NTFS/APFS/OneDrive/Dropbox). Sync with `--delete`
    //    MUST detect `CaseInsensitiveCollision` and NEVER delete `readme.txt`!
    let src_case = Arc::new(ChaosBackend::sequential_gdrive_like("src-case", 256 * 1024));
    let dst_case = Arc::new(
        ChaosBackend::sequential_gdrive_like("dst-case", 256 * 1024)
            .with_caps(|c| c.case_sensitive = false),
    );
    src_case.insert_file("README.txt", b"new-content".to_vec(), t1);
    dst_case.insert_file("readme.txt", b"old-content".to_vec(), t1);

    let eng_case = TransferEngine::new(
        src_case.clone(),
        dst_case.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let mut cfg_case = EngineConfig::new("job-change-case", JobMode::Sync, "src:", "dst:");
    cfg_case.delete = true;
    let rep_case = eng_case
        .run(&cfg_case, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(
        rep_case
            .conflicts
            .iter()
            .any(|c| c.kind == crate::state::ConflictKind::CaseInsensitiveCollision),
        "must emit CaseInsensitiveCollision on case-only rename to case-insensitive dst: {:?}",
        rep_case.conflicts
    );
    assert_eq!(rep_case.items_deleted, 0);
    assert_eq!(
        dst_case.get_file_bytes("readme.txt").as_deref(),
        Some(b"old-content".as_slice()),
        "dst file MUST NOT be deleted on case-only rename conflict"
    );

    // 2. rclone `TestSyncWithErrors`: a mid-transfer permanent error MUST block ALL Phase 3 deletes!
    let src_err = Arc::new(ChaosBackend::sequential_gdrive_like("src-err", 256 * 1024));
    let dst_err = Arc::new(ChaosBackend::sequential_gdrive_like("dst-err", 256 * 1024));
    src_err.insert_file("good.txt", b"ok".to_vec(), t1);
    src_err.insert_file("fail.txt", b"boom".to_vec(), t1);
    dst_err.insert_file("extra_on_dst.txt", b"must-survive".to_vec(), t1);
    dst_err.set_faults(FaultSchedule {
        fail_put_paths: ["fail.txt".to_string()].into_iter().collect(),
        ..Default::default()
    });
    let eng_err = TransferEngine::new(
        src_err,
        dst_err.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let mut cfg_err = EngineConfig::new("job-mid-err", JobMode::Sync, "src:", "dst:");
    cfg_err.delete = true;
    cfg_err.max_retries = 0;
    let rep_err = eng_err
        .run(&cfg_err, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep_err.errors.is_empty(), "fail.txt must record error");
    assert_eq!(
        rep_err.items_deleted, 0,
        "transfer error MUST block all deletes"
    );
    assert_eq!(
        dst_err.get_file_bytes("extra_on_dst.txt").as_deref(),
        Some(b"must-survive".as_slice())
    );

    // 3. rclone `TestSyncDeleteExcluded` (default off): excluded dst files are preserved!
    let src_ex = Arc::new(ChaosBackend::sequential_gdrive_like("src-ex", 256 * 1024));
    let dst_ex = Arc::new(ChaosBackend::sequential_gdrive_like("dst-ex", 256 * 1024));
    src_ex.insert_file("keep.txt", b"v1".to_vec(), t1);
    dst_ex.insert_file("stale.txt", b"delete-me".to_vec(), t1);
    dst_ex.insert_file("local.log", b"excluded-keep-me".to_vec(), t1);
    let eng_ex = TransferEngine::new(
        src_ex,
        dst_ex.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let mut cfg_ex = EngineConfig::new("job-ex-dst", JobMode::Sync, "src:", "dst:");
    cfg_ex.delete = true;
    cfg_ex.filter = FilterSet::new(&[], &["*.log".to_string()]).unwrap();
    let rep_ex = eng_ex
        .run(&cfg_ex, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_ex.errors.is_empty());
    assert_eq!(rep_ex.items_deleted, 1);
    assert!(dst_ex.get_file_bytes("stale.txt").is_none());
    assert_eq!(
        dst_ex.get_file_bytes("local.log").as_deref(),
        Some(b"excluded-keep-me".as_slice()),
        "excluded dst files must be preserved by default"
    );

    // 4. rclone `TestMoveDeleteEmptySrcDirs`: moving `sub/a.txt` with `--exclude "*.keep"`
    //    when `sub/stay.keep` remains MUST NOT delete non-empty directory `sub/`!
    let src_mv = Arc::new(ChaosBackend::sequential_gdrive_like("src-mv", 256 * 1024));
    let dst_mv = Arc::new(ChaosBackend::sequential_gdrive_like("dst-mv", 256 * 1024));
    src_mv.mkdir(&RelPath::parse("sub").unwrap()).await.unwrap();
    src_mv.insert_file("sub/a.txt", b"move-me".to_vec(), t1);
    src_mv.insert_file("sub/stay.keep", b"stay".to_vec(), t1);
    let eng_mv = TransferEngine::new(
        src_mv.clone(),
        dst_mv.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );
    let mut cfg_mv = EngineConfig::new("job-mv-dir", JobMode::Move, "src:", "dst:");
    cfg_mv.delete_empty_src_dirs = true;
    cfg_mv.filter = FilterSet::new(&[], &["*.keep".to_string()]).unwrap();
    let rep_mv = eng_mv
        .run(&cfg_mv, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_mv.errors.is_empty());
    assert_eq!(rep_mv.sources_deleted, 1);
    assert_eq!(
        src_mv.get_file_bytes("sub/stay.keep").as_deref(),
        Some(b"stay".as_slice())
    );
    assert!(
        src_mv
            .stat(&BackendPath::from_rel(RelPath::parse("sub").unwrap()))
            .await
            .unwrap()
            .is_some(),
        "non-empty source dir containing excluded file must NOT be deleted"
    );

    // 5. rclone `TestMoveOntoItself`: single-file copyto/moveto onto exact same path fails fast!
    let same = Arc::new(ChaosBackend::sequential_gdrive_like("same", 256 * 1024));
    same.insert_file("self.txt", b"precious".to_vec(), t1);
    let eng_self = TransferEngine::new(
        same.clone(),
        same.clone(),
        Arc::new(InMemoryJournal::default()),
        pool,
        clock,
        CancelFlag::new(),
    );
    let self_cfg = EngineConfig::new("job-self", JobMode::Move, "same:self.txt", "same:self.txt");
    let self_rel = RelPath::parse("self.txt").unwrap();
    let err = eng_self
        .run_single_file(
            &self_cfg,
            &BackendPath::from_rel(self_rel.clone()),
            &self_rel,
        )
        .await
        .expect_err("moveto onto self MUST be rejected");
    assert_eq!(err.kind, crate::ErrorKind::InvalidPath);
    assert_eq!(
        same.get_file_bytes("self.txt").as_deref(),
        Some(b"precious".as_slice())
    );
}

#[tokio::test]
async fn rclone_backup_dir_and_delete_before_during_safety_invariants() {
    use crate::engine::DeleteMode;

    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let t1 = 1_700_000_000_000_000_000;
    let t2 = t1 + 10_000_000_000;

    // 1. `--backup-dir` archives BOTH overwritten and deleted dst files (and skips identical files)!
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("bk-src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("bk-dst", 256 * 1024));
    let backup = Arc::new(ChaosBackend::sequential_gdrive_like(
        "bk-archive",
        256 * 1024,
    ));

    src.insert_file("same.txt", b"unchanged".to_vec(), t1);
    src.insert_file("sub/edit.txt", b"new-content-v2".to_vec(), t2);
    dst.insert_file("same.txt", b"unchanged".to_vec(), t1);
    dst.insert_file("sub/edit.txt", b"old-content-v1".to_vec(), t1);
    dst.insert_file("obsolete.txt", b"deleted-old".to_vec(), t1);

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // 1a. Reject overlapping `--backup-dir` (pointing inside `dst` or `src`) BEFORE any mutation!
    let overlap_cfg = EngineConfig::new("job-bk-overlap", JobMode::Sync, "src:", "dst:")
        .with_backup_dir(dst.clone(), RelPath::parse("archived").unwrap());
    let err = engine
        .run(&overlap_cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap_err();
    assert_eq!(err.kind, crate::ErrorKind::InvalidPath);
    assert!(err.message.contains("--backup-dir overlaps destination"));
    assert_eq!(
        dst.get_file_bytes("obsolete.txt").as_deref(),
        Some(b"deleted-old".as_slice())
    );

    // 1b. Non-overlapping `--backup-dir` archives overwritten + deleted dst files!
    let bk_cfg = EngineConfig::new("job-bk-ok", JobMode::Sync, "src:", "dst:")
        .with_backup_dir(backup.clone(), RelPath::parse("2026-backup").unwrap());
    let rep = engine
        .run(&bk_cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(rep.files_skipped, 1);
    assert_eq!(rep.items_deleted, 1);
    assert_eq!(
        dst.get_file_bytes("sub/edit.txt").as_deref(),
        Some(b"new-content-v2".as_slice())
    );
    assert!(dst.get_file_bytes("obsolete.txt").is_none());
    assert_eq!(
        backup.get_file_bytes("2026-backup/sub/edit.txt").as_deref(),
        Some(b"old-content-v1".as_slice()),
        "overwritten dst file MUST be archived into --backup-dir"
    );
    assert_eq!(
        backup.get_file_bytes("2026-backup/obsolete.txt").as_deref(),
        Some(b"deleted-old".as_slice()),
        "deleted dst file MUST be archived into --backup-dir"
    );
    assert!(
        backup.get_file_bytes("2026-backup/same.txt").is_none(),
        "skipped identical file must NOT be copied into --backup-dir"
    );

    // 2. `--delete-before` deletes extraneous dst files BEFORE transfers start,
    //    AND still enforces `--max-delete` and Observation Completeness Gate!
    let src_db = Arc::new(ChaosBackend::sequential_gdrive_like("db-src", 256 * 1024));
    let dst_db = Arc::new(ChaosBackend::sequential_gdrive_like("db-dst", 256 * 1024));
    src_db.insert_file("new.txt", b"new-payload".to_vec(), t2);
    dst_db.insert_file("junk1.txt", b"j1".to_vec(), t1);
    dst_db.insert_file("junk2.txt", b"j2".to_vec(), t1);

    let eng_db = TransferEngine::new(
        src_db.clone(),
        dst_db.clone(),
        Arc::new(InMemoryJournal::default()),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // 2a. `--delete-before` + `--max-delete 1` trips BEFORE deleting OR uploading!
    let cfg_trip = EngineConfig::new("job-db-trip", JobMode::Sync, "src:", "dst:")
        .with_delete_mode(DeleteMode::Before)
        .with_max_delete(Some(1));
    let rep_trip = eng_db
        .run(&cfg_trip, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep_trip.errors.is_empty());
    assert_eq!(rep_trip.items_deleted, 0);
    assert_eq!(rep_trip.files_transferred, 0);
    assert!(dst_db.get_file_bytes("junk1.txt").is_some());
    assert!(dst_db.get_file_bytes("new.txt").is_none());

    // 2b. `--delete-before` + partial source list error -> Observation Completeness Gate blocks ALL deletes!
    src_db.set_faults(FaultSchedule {
        inject_list_error: true,
        ..Default::default()
    });
    let cfg_gate = EngineConfig::new("job-db-gate", JobMode::Sync, "src:", "dst:")
        .with_delete_mode(DeleteMode::Before);
    let rep_gate = eng_db
        .run(&cfg_gate, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep_gate.src_observation_complete);
    assert_eq!(rep_gate.items_deleted, 0);
    assert!(dst_db.get_file_bytes("junk1.txt").is_some());

    // 2c. Clean `--delete-before` deletes both junk files and transfers `new.txt`!
    src_db.set_faults(FaultSchedule::default());
    let rep_ok = eng_db
        .run(&cfg_gate, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_ok.is_success(), "{:?}", rep_ok.errors);
    assert_eq!(rep_ok.items_deleted, 2);
    assert!(dst_db.get_file_bytes("junk1.txt").is_none());
    assert!(dst_db.get_file_bytes("junk2.txt").is_none());
    assert_eq!(
        dst_db.get_file_bytes("new.txt").as_deref(),
        Some(b"new-payload".as_slice())
    );

    // 3. `--delete-during` deletes extraneous dst files while transferring!
    dst_db.insert_file("during_junk.txt", b"old".to_vec(), t1);
    src_db.insert_file("another.txt", b"fresh".to_vec(), t2);
    let cfg_dur = EngineConfig::new("job-dur", JobMode::Sync, "src:", "dst:")
        .with_delete_mode(DeleteMode::During);
    let rep_dur = eng_db
        .run(&cfg_dur, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_dur.is_success(), "{:?}", rep_dur.errors);
    assert_eq!(rep_dur.items_deleted, 1);
    assert!(dst_db.get_file_bytes("during_junk.txt").is_none());
    assert_eq!(
        dst_db.get_file_bytes("another.txt").as_deref(),
        Some(b"fresh".as_slice())
    );
}

#[tokio::test]
async fn d3_sync_high_delete_emits_warning_without_aborting_and_honors_max_delete_percent() {
    use crate::clock::Clock;
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("d3-src", 256 * 1024));
    let dst = Arc::new(ChaosBackend::sequential_gdrive_like("d3-dst", 256 * 1024));
    let journal = Arc::new(InMemoryJournal::default());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let clock = Arc::new(VirtualClock::new(1_700_000_000));

    let t1 = clock.now_unix_nanos();
    src.insert_file("keep.txt", b"keep".to_vec(), t1);
    dst.insert_file("keep.txt", b"keep".to_vec(), t1);
    for i in 0..3 {
        dst.insert_file(&format!("drop_{i}.txt"), b"old".to_vec(), t1);
    }

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        pool.clone(),
        clock.clone(),
        CancelFlag::new(),
    );

    // 1. Explicit `max_delete_percent = Some(50.0)` aborts deleting 3 of 4 (75% > 50%).
    let cfg_pct = EngineConfig::new("d3-sync-pct", JobMode::Sync, "src:", "dst:")
        .with_max_delete_percent(Some(50.0));
    let rep_pct = engine
        .run(&cfg_pct, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(!rep_pct.is_success());
    assert_eq!(rep_pct.items_deleted, 0);
    assert_eq!(dst.file_count(), 4);

    // 2. Default sync (`max_delete_percent: None`) deletes 3 of 4 (>50%), emits warning,
    // and succeeds WITHOUT aborting!
    let cfg_warn = EngineConfig::new("d3-sync-warn", JobMode::Sync, "src:", "dst:");
    let rep_warn = engine
        .run(&cfg_warn, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_warn.is_success(), "errors: {:?}", rep_warn.errors);
    assert_eq!(rep_warn.items_deleted, 3);
    assert_eq!(dst.file_count(), 1);
    assert!(
        rep_warn.high_delete_warning.is_some(),
        "deleting >50% of observed destination files must emit high_delete_warning"
    );

    // 3. Deleting <= 50% (1 of 2 = 50%) must NOT emit high_delete_warning.
    dst.insert_file("extra.txt", b"x".to_vec(), t1);
    let cfg_ok = EngineConfig::new("d3-sync-ok", JobMode::Sync, "src:", "dst:");
    let rep_ok = engine
        .run(&cfg_ok, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap();
    assert!(rep_ok.is_success());
    assert_eq!(rep_ok.items_deleted, 1);
    assert!(rep_ok.high_delete_warning.is_none());
}
