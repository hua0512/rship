use super::*;
use rship_core::state::{
    DstPrecondition, JobMode, JobStatus, OperationState, SourceVersion, compute_session_key,
};
use rship_core::types::{EntryKind, HashKind};
use tempfile::TempDir;

#[tokio::test]
async fn state_actor_persists_split_journal_and_baselines_atomically() {
    let dir = TempDir::new().unwrap();
    let actor = StateActor::open(dir.path()).unwrap();
    assert!(dir.path().join("journal.db").exists());
    assert!(
        !dir.path().join("baselines").exists(),
        "baselines dir must be created lazily only when a baseline is written"
    );

    let job = JobRecord {
        job_id: "j1".into(),
        mode: JobMode::Sync,
        src_spec: "a".into(),
        dst_spec: "b".into(),
        status: JobStatus::Running,
        files_total: 1,
        files_done: 0,
        bytes_total: 1000,
        bytes_done: 0,
        created_at: 10,
        updated_at: 10,
        options_json: Some(r#"{"checksum":true}"#.into()),
        resume_cursor: None,
    };
    actor.upsert_job(&job).await.unwrap();
    let loaded_job = actor.get_job("j1").await.unwrap().unwrap();
    assert_eq!(
        loaded_job.options_json.as_deref(),
        Some(r#"{"checksum":true}"#)
    );

    let rel = RelPath::parse("dir/file.bin").unwrap();
    // Reading a non-existent pair returns None and creates zero baseline files.
    assert!(actor.get_baseline("pair1", &rel).await.unwrap().is_none());
    assert!(!dir.path().join("baselines").exists());

    let skey = compute_session_key("local://a", "dir/file.bin", "local://b", &rel);
    let op = OperationRecord {
        op_id: "op-1".into(),
        session_key: skey.clone(),
        job_id: "j1".into(),
        src_endpoint: "local://a".into(),
        dst_endpoint: "local://b".into(),
        src_raw_path: "dir/file.bin".into(),
        dst_raw_path: "dir/file.bin".into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: 1000,
            mtime_ns: 100,
            ctime_ns: Some(100),
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "local".into(),
        session_token: Some("tok-1".into()),
        backend_meta: "{}".into(),
        planned_chunk_size: 256,
        confirmed_offset: 512,
        state: OperationState::Active,
        created_at: 10,
        updated_at: 11,
        expires_at: None,
    };
    actor.put_operation(&op).await.unwrap();
    actor
        .upsert_part(
            "op-1",
            &CompletedPart {
                part_number: 1,
                offset: 0,
                length: 256,
                etag: "\"e1\"".into(),
                checksum: None,
            },
        )
        .await
        .unwrap();
    actor.shutdown().await.unwrap();

    // Reopen from disk to prove cross-restart durability.
    let actor2 = StateActor::open(dir.path()).unwrap();
    let loaded = actor2.get_operation_by_key(&skey).await.unwrap().unwrap();
    assert_eq!(loaded.confirmed_offset, 512);
    assert_eq!(actor2.list_parts("op-1").await.unwrap().len(), 1);

    let base = BaselineRecord {
        pair_key: "pair1".into(),
        nfc_path: rel.clone(),
        kind: EntryKind::File,
        src_node_id: None,
        dst_node_id: None,
        size: 1000,
        src_mtime_ns: 100,
        dst_mtime_ns: 105,
        dst_etag: Some("\"deadbeef00112233445566778899aabb\"".into()),
        hash_kind: Some(HashKind::Md5),
        hash_hex: Some("deadbeef00112233445566778899aabb".into()),
        updated_at: 12,
    };
    actor2
        .commit_verified_transfer(Some("op-1"), Some(&base), "j1", 1000)
        .await
        .unwrap();

    assert!(dir.path().join("baselines").join("pair1.db").exists());
    assert!(actor2.get_operation_by_key(&skey).await.unwrap().is_none());
    assert!(actor2.list_parts("op-1").await.unwrap().is_empty());
    assert_eq!(
        actor2.get_baseline("pair1", &rel).await.unwrap().unwrap(),
        base
    );
    let j = actor2.get_job("j1").await.unwrap().unwrap();
    assert_eq!(j.files_done, 1);
    assert_eq!(j.bytes_done, 1000);

    // `delete_pair_baselines` unlinks the shard DB file in O(1).
    actor2.delete_pair_baselines("pair1").await.unwrap();
    assert!(!dir.path().join("baselines").join("pair1.db").exists());
    assert!(actor2.get_baseline("pair1", &rel).await.unwrap().is_none());
    actor2.shutdown().await.unwrap();
}

#[tokio::test]
async fn state_actor_applies_gdrive_change_batch_and_evicts_subtrees_atomically() {
    let actor = StateActor::open_in_memory().unwrap();
    let scope = DeltaScope {
        remote_name: "gd".into(),
        principal: "user@example.com".into(),
        corpus_id: "root".into(),
        root_id: "root".into(),
    };

    let make_node = |id: &str, parent: Option<&str>, name: &str, kind: EntryKind| DeltaNodeRecord {
        file_id: id.into(),
        parent_id: parent.map(str::to_string),
        raw_name: name.into(),
        nfc_name: name.into(),
        kind,
        size: 0,
        mtime_ns: 100,
        md5: None,
        trashed: false,
        generation: 1,
        updated_at: 10,
    };

    actor
        .apply_change_batch(
            &scope,
            DeltaChangeBatch {
                upserts: vec![
                    make_node("d1", Some("root"), "folder", EntryKind::Directory),
                    make_node("d2", Some("d1"), "sub", EntryKind::Directory),
                    make_node("f1", Some("d2"), "deep.bin", EntryKind::File),
                    make_node("keep", Some("root"), "keep.txt", EntryKind::File),
                ],
                remove_file_ids: vec![],
                evict_subtree_root_ids: vec![],
                new_start_page_token: Some("tok-100".into()),
                updated_at: 10,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        actor.get_change_token(&scope).await.unwrap().as_deref(),
        Some("tok-100")
    );
    assert_eq!(actor.list_all_nodes("gd", "root").await.unwrap().len(), 4);

    actor
        .apply_change_batch(
            &scope,
            DeltaChangeBatch {
                upserts: vec![],
                remove_file_ids: vec![],
                evict_subtree_root_ids: vec!["d1".into()],
                new_start_page_token: Some("tok-101".into()),
                updated_at: 11,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        actor.get_change_token(&scope).await.unwrap().as_deref(),
        Some("tok-101")
    );
    let remaining = actor.list_all_nodes("gd", "root").await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].file_id, "keep");
    actor.shutdown().await.unwrap();
}

#[test]
fn concurrent_state_actor_open_never_fails_with_busy() {
    let dir = TempDir::new().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = dir.path().to_path_buf();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            let actor = StateActor::open(&p).expect("concurrent StateActor::open");
            drop(actor);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[tokio::test]
async fn state_actor_next_baseline_page_skips_missing_pair_and_paginates_in_order() {
    let dir = TempDir::new().unwrap();
    let actor = StateActor::open(dir.path()).unwrap();

    // Unknown pair must return empty immediately without creating any baseline DB on disk.
    let empty = actor
        .next_baseline_page("nonexistent-pair", None, 10)
        .await
        .unwrap();
    assert!(empty.is_empty());
    assert!(!dir.path().join("baselines").exists());

    for name in ["c.txt", "a.txt", "e.txt", "b.txt", "d.txt"] {
        let base = BaselineRecord {
            pair_key: "pair-page".into(),
            nfc_path: RelPath::parse(name).unwrap(),
            kind: EntryKind::File,
            size: 42,
            src_mtime_ns: 100,
            dst_mtime_ns: 100,
            src_node_id: None,
            dst_node_id: None,
            dst_etag: None,
            hash_kind: None,
            hash_hex: None,
            updated_at: 1,
        };
        actor
            .commit_verified_transfer(None, Some(&base), "j-page", 42)
            .await
            .unwrap();
    }
    actor.flush().await.unwrap();

    let mut after: Option<String> = None;
    let mut names = Vec::new();
    loop {
        let page = actor
            .next_baseline_page("pair-page", after.as_deref(), 2)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        after = Some(page.last().unwrap().nfc_path.as_str().to_string());
        names.extend(page.into_iter().map(|r| r.nfc_path.as_str().to_string()));
    }
    assert_eq!(names, vec!["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]);
    actor.shutdown().await.unwrap();
}

#[test]
fn filter_options_serde_omits_inline_files_from_blob() {
    use rship_core::filter::FilterOptions;
    let opts = FilterOptions {
        files_from: Some((0..5_000).map(|i| format!("dir/file_{i:05}.bin")).collect()),
        files_from_path: Some("/var/tmp/manifest.txt".into()),
        ..Default::default()
    };
    let encoded = serde_json::to_string(&opts).unwrap();
    assert!(
        encoded.len() < 300,
        "FilterOptions JSON must omit inline files_from list (got {} bytes)",
        encoded.len()
    );
    let decoded: FilterOptions = serde_json::from_str(&encoded).unwrap();
    assert!(decoded.files_from.is_none());
    assert_eq!(
        decoded.files_from_path.as_deref(),
        Some("/var/tmp/manifest.txt")
    );
}

#[tokio::test]
async fn legacy_journal_db_without_bisync_state_upgrades_automatically() {
    let dir = TempDir::new().unwrap();
    let journal_path = dir.path().join("journal.db");
    {
        // Simulate a real pre-upgrade unversioned v0.1.0 `journal.db` (`user_version = 0`)
        // containing `jobs`, `operations`, `operation_parts`, and all indexes, but missing
        // the newly added `bisync_state`.
        let conn = Connection::open(&journal_path).unwrap();
        crate::schema::configure_journal_db(&conn).unwrap();
        conn.execute_batch("DROP TABLE bisync_state; PRAGMA user_version = 0;")
            .unwrap();
    }
    let actor = StateActor::open(dir.path()).unwrap();
    assert!(
        actor
            .get_bisync_state("legacy-pair")
            .await
            .unwrap()
            .is_none()
    );
    actor
        .upsert_bisync_state(&rship_core::state::BisyncPairState {
            pair_key: "legacy-pair".into(),
            filter_hash: "abc".into(),
            last_a_files: 3,
            last_b_files: 3,
            updated_at: 42,
        })
        .await
        .unwrap();
    let loaded = actor
        .get_bisync_state("legacy-pair")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.last_a_files, 3);
    actor.shutdown().await.unwrap();
}

#[test]
fn d11_state_actor_refuses_newer_journal_schema_version() {
    let dir = TempDir::new().unwrap();
    let journal_path = dir.path().join("journal.db");
    {
        let conn = Connection::open(&journal_path).unwrap();
        crate::schema::configure_journal_db(&conn).unwrap();
        conn.execute_batch("PRAGMA user_version = 999;").unwrap();
    }
    let err = match StateActor::open(dir.path()) {
        Ok(_) => panic!("StateActor::open must refuse journal.db with user_version = 999"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), rship_core::ErrorKind::StateStore);
    assert!(err.message().contains("999"));
}

#[tokio::test]
async fn d7_journal_db_uses_synchronous_full() {
    let dir = TempDir::new().unwrap();

    // Direct schema configuration sets `PRAGMA synchronous = FULL` (2).
    {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA synchronous = OFF;").unwrap();
        crate::schema::configure_journal_db(&conn).unwrap();
        let sync_mode: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            sync_mode, 2,
            "journal.db must use PRAGMA synchronous = FULL (2)"
        );
    }

    // Opening `StateActor` configures its live `journal.db` connection with `FULL` (2).
    let actor = StateActor::open(dir.path()).unwrap();
    assert_eq!(
        actor.journal_synchronous_mode().await.unwrap(),
        2,
        "StateActor journal.db connection must run with PRAGMA synchronous = FULL (2)"
    );
    actor.shutdown().await.unwrap();
}

#[tokio::test]
async fn d7_flush_truncates_journal_wal() {
    let dir = TempDir::new().unwrap();
    let actor = StateActor::open(dir.path()).unwrap();
    let job = JobRecord {
        job_id: "flush-job".into(),
        mode: JobMode::Copy,
        src_spec: "a".into(),
        dst_spec: "b".into(),
        status: JobStatus::Running,
        files_total: 1,
        files_done: 0,
        bytes_total: 128,
        bytes_done: 0,
        created_at: 1,
        updated_at: 1,
        options_json: None,
        resume_cursor: None,
    };
    actor.upsert_job(&job).await.unwrap();
    let base = BaselineRecord {
        pair_key: "flush-pair".into(),
        nfc_path: RelPath::parse("doc.txt").unwrap(),
        kind: EntryKind::File,
        src_node_id: None,
        dst_node_id: None,
        size: 128,
        src_mtime_ns: 10,
        dst_mtime_ns: 10,
        dst_etag: None,
        hash_kind: None,
        hash_hex: None,
        updated_at: 2,
    };
    actor
        .commit_verified_transfer(None, Some(&base), "flush-job", 128)
        .await
        .unwrap();

    let wal_path = dir.path().join("journal.db-wal");
    let baseline_wal_path = dir.path().join("baselines").join("flush-pair.db-wal");
    let wal_size_before = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    assert!(
        wal_size_before > 0,
        "expected non-empty journal.db-wal before flush (got {wal_size_before})"
    );
    let baseline_wal_before = std::fs::metadata(&baseline_wal_path)
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        baseline_wal_before > 0,
        "expected non-empty baseline -wal before flush (got {baseline_wal_before})"
    );

    actor.flush().await.unwrap();

    let wal_size_after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        wal_size_after, 0,
        "expected journal.db-wal to be truncated to 0 bytes after flush (got {wal_size_after})"
    );
    let baseline_wal_after = std::fs::metadata(&baseline_wal_path)
        .map(|m| m.len())
        .unwrap_or(0);
    assert_eq!(
        baseline_wal_after, 0,
        "expected baseline -wal to be truncated to 0 bytes after flush (got {baseline_wal_after})"
    );
    actor.shutdown().await.unwrap();
}

#[test]
fn d13_remove_sqlite_files_deletes_wal_and_shm_before_main_db() {
    let dir = TempDir::new().unwrap();

    // 1. If removing `-wal` fails (simulated by a non-empty directory), the main `.db` MUST still exist.
    {
        let db_path = dir.path().join("blocked_wal.db");
        let wal_path = dir.path().join("blocked_wal.db-wal");
        let shm_path = dir.path().join("blocked_wal.db-shm");
        std::fs::write(&db_path, b"main-db").unwrap();
        std::fs::write(&shm_path, b"shm").unwrap();
        std::fs::create_dir(&wal_path).unwrap();
        std::fs::write(wal_path.join("blocker"), b"x").unwrap();

        let res = remove_sqlite_files(&db_path);
        assert!(res.is_err(), "removing directory as -wal file must fail");
        assert!(
            db_path.exists(),
            "main .db must NOT be deleted before -wal is removed"
        );
    }

    // 2. If removing `-shm` fails, `-wal` was removed first and main `.db` MUST still exist.
    {
        let db_path = dir.path().join("blocked_shm.db");
        let wal_path = dir.path().join("blocked_shm.db-wal");
        let shm_path = dir.path().join("blocked_shm.db-shm");
        std::fs::write(&db_path, b"main-db").unwrap();
        std::fs::write(&wal_path, b"wal").unwrap();
        std::fs::create_dir(&shm_path).unwrap();
        std::fs::write(shm_path.join("blocker"), b"x").unwrap();

        let res = remove_sqlite_files(&db_path);
        assert!(res.is_err(), "removing directory as -shm file must fail");
        assert!(!wal_path.exists(), "-wal should be deleted before -shm");
        assert!(
            db_path.exists(),
            "main .db must NOT be deleted before -shm is removed"
        );
    }

    // 3. Normal case: deletes `-wal`, `-shm`, and main `.db` cleanly, and is idempotent.
    {
        let db_path = dir.path().join("clean.db");
        let wal_path = dir.path().join("clean.db-wal");
        let shm_path = dir.path().join("clean.db-shm");
        std::fs::write(&db_path, b"main-db").unwrap();
        std::fs::write(&wal_path, b"wal").unwrap();
        std::fs::write(&shm_path, b"shm").unwrap();

        remove_sqlite_files(&db_path).unwrap();
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());
        assert!(!db_path.exists());

        // Calling again when already deleted succeeds cleanly.
        remove_sqlite_files(&db_path).unwrap();
    }
}
