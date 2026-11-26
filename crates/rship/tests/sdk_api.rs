//! End-to-end integration tests for the top-level `rship` Rust SDK facade crate.

#![cfg(feature = "local")]

use futures::StreamExt;
use rship::prelude::*;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[tokio::test]
async fn ephemeral_client_copy_sync_move_and_push_events() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("nested/b.bin"), vec![42u8; 64 * 1024]).unwrap();
    std::fs::write(src.join("ignored.tmp"), b"temp").unwrap();

    let client = RshipClient::ephemeral().unwrap();

    // 1. Sync with exclude filter + bounded ChannelEventSink push notifications.
    let (sink, mut rx) = ChannelEventSink::bounded(64);
    let rep = client
        .sync(src.as_path(), dst.as_path())
        .exclude("*.tmp")
        .event_sink(sink.clone())
        .run()
        .await
        .unwrap();

    assert!(rep.is_success());
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(sink.dropped_events(), 0);
    assert!(dst.join("a.txt").exists());
    assert!(dst.join("nested/b.bin").exists());
    assert!(!dst.join("ignored.tmp").exists());

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(matches!(
        events.first(),
        Some(TransferEvent::JobStarted {
            seq: 1,
            mode: JobMode::Sync,
            ..
        })
    ));
    assert!(matches!(
        events.last(),
        Some(TransferEvent::JobFinished {
            files_transferred: 2,
            fatal_error: None,
            ..
        })
    ));
    // Verify strictly increasing per-job sequence numbers and uniform job_id.
    let mut prev_seq = 0;
    for ev in &events {
        assert_eq!(ev.job_id(), rep.job_id);
        assert!(ev.seq() > prev_seq, "event seq must strictly increase");
        prev_seq = ev.seq();
    }
    let completed_files = events
        .iter()
        .filter(|e| matches!(e, TransferEvent::FileCompleted { .. }))
        .count();
    assert_eq!(completed_files, 2);

    // 2. Serialize RunReport directly to JSON.
    let json = serde_json::to_value(&rep).unwrap();
    assert_eq!(json["files_transferred"], 2);

    // 3. Direct FS helpers accepting &Path / strings: stat, list, rename, delete.
    let listed: Vec<Entry> = client
        .list(dst.as_path(), &ListOptions::shallow())
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert!(listed.iter().any(|e| e.nfc_path.as_str() == "a.txt"));
    assert!(!listed.iter().any(|e| e.nfc_path.as_str() == "nested/b.bin"));

    let st = client
        .stat(dst.join("a.txt").as_path())
        .await
        .unwrap()
        .expect("a.txt must exist");
    assert_eq!(st.size, 5);

    client
        .rename(dst.join("a.txt").as_path(), "a_renamed.txt")
        .await
        .unwrap();
    assert!(dst.join("a_renamed.txt").exists());
    client
        .delete(dst.join("a_renamed.txt").as_path())
        .await
        .unwrap();
    assert!(!dst.join("a_renamed.txt").exists());
}

#[tokio::test]
async fn client_move_files_and_failover_backend_target_reuse() {
    let tmp = TempDir::new().unwrap();
    let rec = tmp.path().join("recordings");
    let out_a = tmp.path().join("archive_a");
    let out_b = tmp.path().join("archive_b");
    std::fs::create_dir_all(&rec).unwrap();
    std::fs::create_dir_all(&out_a).unwrap();
    std::fs::create_dir_all(&out_b).unwrap();

    std::fs::write(rec.join("seg1.jpg"), b"thumb").unwrap();
    std::fs::write(rec.join("seg1.mp4"), vec![7u8; 128 * 1024]).unwrap();
    std::fs::write(rec.join("seg1.xml"), b"<xml/>").unwrap();
    std::fs::write(rec.join("live.flv"), b"writing").unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend(
            "rec",
            rship::backends::local::LocalBackend::new("rec", &rec).unwrap(),
        )
        .remote("arch_a", RemoteConfig::local(out_a.clone()))
        .remote("arch_b", RemoteConfig::local(out_b.clone()))
        .build()
        .unwrap();

    // Pass leased FailoverPool backend directly via TransferTarget::backend without re-resolving!
    let pool = client.failover_pool(&["arch_a", "arch_b"]).unwrap();
    let lease = pool.acquire().unwrap();
    let dst_target = TransferTarget::backend(lease.backend(), RelPath::parse("2026").unwrap());

    let completed = Arc::new(Mutex::new(Vec::new()));
    let completed_c = completed.clone();
    let batch = client
        .move_files("rec:", dst_target, ["seg1.jpg", "seg1.mp4", "missing.bin"])
        .on_event(move |ev| {
            if let TransferEvent::FileCompleted { result, .. } = ev {
                completed_c.lock().unwrap().push(result.path);
            }
        })
        .run()
        .await
        .unwrap();

    assert!(batch.is_success());
    assert_eq!(batch.files_transferred, 2);
    assert_eq!(batch.sources_deleted, 2);
    assert!(out_a.join("2026/seg1.jpg").exists());
    assert!(out_a.join("2026/seg1.mp4").exists());
    assert!(!rec.join("seg1.jpg").exists());
    assert!(!rec.join("seg1.mp4").exists());
    assert!(rec.join("live.flv").exists());
    assert_eq!(completed.lock().unwrap().len(), 2);

    // Single-file moveto using leased backend directly.
    let single_dst = TransferTarget::backend(
        lease.backend(),
        RelPath::parse("2026/seg1_renamed.xml").unwrap(),
    );
    let single = client
        .move_file("rec:seg1.xml", single_dst)
        .run()
        .await
        .unwrap();
    assert!(single.is_success());
    assert_eq!(single.files_transferred, 1);
    assert_eq!(single.sources_deleted, 1);
    assert!(out_a.join("2026/seg1_renamed.xml").exists());
    assert!(!rec.join("seg1.xml").exists());
    assert!(rec.join("live.flv").exists());
}

#[tokio::test]
async fn client_failover_pool_bisync_events_and_backend_caching() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("from_a.txt"), b"hello-a").unwrap();
    std::fs::write(b.join("from_b.txt"), b"hello-b").unwrap();

    let client = RshipClient::builder()
        .ephemeral()
        .remote("side_a", RemoteConfig::local(a.clone()))
        .remote("side_b", RemoteConfig::local(b.clone()))
        .build()
        .unwrap();

    // Backend cache returns the exact same Arc instance across resolutions until cleared.
    let (b1, _) = client.resolve("side_a:one").unwrap();
    let (b2, _) = client.resolve("side_a:two").unwrap();
    assert!(Arc::ptr_eq(&b1, &b2));
    client.clear_backend_cache();
    let (b3, _) = client.resolve("side_a:three").unwrap();
    assert!(!Arc::ptr_eq(&b1, &b3));

    // Standard traits on RelPath / TargetPath / ErrorKind / BackendKind.
    let rel: RelPath = "dir/file.txt".parse().unwrap();
    assert_eq!(rel.as_ref(), "dir/file.txt");
    let target: TargetPath = "side_a:dir/file.txt".parse().unwrap();
    assert_eq!(target.to_string(), "side_a:dir/file.txt");
    let err = Error::quota_exceeded("daily cap hit");
    assert!(err.is_quota_exceeded());
    assert!(err.is_permanent());
    assert!(!err.is_retryable());
    assert_eq!(err.kind().to_string(), "quota_exceeded");

    // FailoverPool built straight from client remotes returns cloned Arc<dyn StorageBackend>.
    let pool = client.failover_pool(&["side_a", "side_b"]).unwrap();
    assert_eq!(pool.len(), 2);
    let lease = pool.acquire().unwrap();
    assert_eq!(lease.backend().backend_kind(), BackendKind::Local);
    drop(lease);

    // Three-Tree bisync converges both sides and emits full sequenced events!
    let (sink, mut rx) = ChannelEventSink::bounded(64);
    let brep = client
        .bisync("side_a:", "side_b:")
        .resync(true)
        .event_sink(sink)
        .run()
        .await
        .unwrap();
    assert!(brep.is_success());
    assert!(a.join("from_b.txt").exists());
    assert!(b.join("from_a.txt").exists());

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(matches!(
        events.first(),
        Some(TransferEvent::JobStarted { seq: 1, .. })
    ));
    assert!(matches!(
        events.last(),
        Some(TransferEvent::JobFinished {
            files_transferred: 2,
            fatal_error: None,
            ..
        })
    ));
    let mut prev = 0;
    for ev in &events {
        assert!(ev.seq() > prev);
        prev = ev.seq();
    }
}

#[tokio::test]
async fn panicking_event_sink_is_isolated_and_single_file_errors_emit_job_finished() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("ok.txt"), b"safe-payload").unwrap();

    let client = RshipClient::ephemeral().unwrap();

    // 1. A panicking callback must NEVER crash workers or lose transfer results.
    let rep = client
        .copy(src.as_path(), dst.as_path())
        .on_event(|_ev| panic!("boom inside user callback"))
        .run()
        .await
        .unwrap();
    assert!(rep.is_success());
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(std::fs::read(dst.join("ok.txt")).unwrap(), b"safe-payload");

    // 2. Single-file missing source returns NotFound AND still emits paired JobStarted + JobFinished!
    let (sink, mut rx) = ChannelEventSink::bounded(16);
    let err = client
        .copy_file(
            src.join("does_not_exist.bin").as_path(),
            dst.join("out.bin").as_path(),
        )
        .event_sink(sink)
        .run()
        .await
        .unwrap_err();
    assert!(err.is_not_found());

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(matches!(
        events.first(),
        Some(TransferEvent::JobStarted { seq: 1, .. })
    ));
    assert!(matches!(
        events.last(),
        Some(TransferEvent::JobFinished {
            errors: 1,
            fatal_error: Some(_),
            ..
        })
    ));

    // 3. Bounded sink with capacity 1 drops excess events non-blockingly and tracks dropped count.
    let (tiny_sink, _tiny_rx) = ChannelEventSink::bounded(1);
    let _ = client
        .copy(src.as_path(), dst.as_path())
        .event_sink(tiny_sink.clone())
        .run()
        .await
        .unwrap();
    assert!(tiny_sink.dropped_events() >= 1);
}

#[tokio::test]
async fn memory_sync_index_detects_destination_and_cross_side_case_collisions() {
    let idx = MemorySyncIndex::new();
    idx.insert_src_batch(vec![
        Entry::file(RelPath::parse("Cross.txt").unwrap(), 10, 100),
        Entry::file(RelPath::parse("clean.txt").unwrap(), 5, 100),
    ])
    .await
    .unwrap();
    idx.insert_dst_batch(vec![
        Entry::file(RelPath::parse("DupDst.pdf").unwrap(), 1, 100),
        Entry::file(RelPath::parse("dupdst.pdf").unwrap(), 2, 100),
        Entry::file(RelPath::parse("cross.txt").unwrap(), 10, 100),
        Entry::file(RelPath::parse("clean.txt").unwrap(), 5, 100),
    ])
    .await
    .unwrap();

    let conflicts = idx.finalize_and_detect_conflicts(false).await.unwrap();
    let ci: Vec<&str> = conflicts
        .iter()
        .filter(|c| c.kind == rship::core::state::ConflictKind::CaseInsensitiveCollision)
        .map(|c| c.nfc_path.as_str())
        .collect();
    assert!(ci.contains(&"DupDst.pdf"));
    assert!(ci.contains(&"dupdst.pdf"));
    assert!(ci.contains(&"Cross.txt"));
    assert!(ci.contains(&"cross.txt"));
    assert!(!ci.contains(&"clean.txt"));
}

#[cfg(feature = "gdrive")]
#[tokio::test]
async fn ephemeral_rclone_conf_import_writes_zero_files_to_disk() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("ephemeral_state_must_not_exist");
    let raw_conf = r#"
[gd_mem]
type = drive
client_id = test-client.apps.googleusercontent.com
client_secret = test-secret
token = {"access_token":"ya29.mem","token_type":"Bearer","refresh_token":"1//mem","expiry":"2099-01-01T00:00:00Z"}
"#;

    let client = RshipClient::builder()
        .ephemeral()
        .state_dir(&state_dir)
        .rclone_conf_str(raw_conf)
        .build()
        .unwrap();

    assert!(client.config().remotes.contains_key("gd_mem"));
    // Zero files or directories may be created under state_dir in ephemeral mode!
    assert!(
        !state_dir.exists(),
        "ephemeral client must not create state_dir or write token sidecars"
    );
    // Backend resolves cleanly using in-memory token store!
    let (backend, _) = client.resolve("gd_mem:").unwrap();
    assert_eq!(backend.backend_kind(), BackendKind::Gdrive);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn persistent_client_flushes_shuts_down_and_rejects_post_shutdown_jobs() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("doc.txt"), b"persisted").unwrap();

    let client = RshipClient::builder()
        .state_dir(&state_dir)
        .build()
        .unwrap();

    // Persistent client is lazy: read-only local stat/resolve_any never opens journal.db.
    assert!(!state_dir.join("journal.db").exists());
    let resolved = client
        .resolve_any(src.join("doc.txt").as_path())
        .await
        .unwrap();
    assert!(resolved.single_file.is_some());
    assert!(!state_dir.join("journal.db").exists());

    let rep = client
        .copy(src.as_path(), dst.as_path())
        .run()
        .await
        .unwrap();
    assert!(rep.is_success());
    assert!(state_dir.join("journal.db").exists());

    client.flush().await.unwrap();
    client.shutdown().await.unwrap();
    // Idempotent second shutdown returns Ok.
    client.shutdown().await.unwrap();

    // Any new transfer submitted after shutdown is cleanly rejected as Cancelled.
    let err = client
        .copy(src.as_path(), dst.as_path())
        .run()
        .await
        .unwrap_err();
    assert!(err.is_cancelled());
}

#[test]
fn relpath_deserialize_validates_traversal_and_normalizes_nfc() {
    assert!(serde_json::from_str::<RelPath>("\"../etc/passwd\"").is_err());
    assert!(serde_json::from_str::<RelPath>("\"a/../b\"").is_err());
    assert!(serde_json::from_str::<RelPath>("\"bad\\u0000path\"").is_err());
    let nfc: RelPath = serde_json::from_str("\"dir/cafe\\u0301.txt\"").unwrap();
    assert_eq!(nfc.as_str(), "dir/caf\u{00e9}.txt");
}

#[test]
fn app_config_debug_redacts_inline_secrets_and_preserves_keyring_refs() {
    let cfg = AppConfig::new()
        .with_remote(
            "s3",
            S3RemoteConfig::new("aws")
                .with_credentials("AKIA_PUBLIC", "SUPER_SECRET_AWS_KEY")
                .with_session_token("keyring://rship/s3.session_token"),
        )
        .with_remote(
            "vault",
            CryptRemoteConfig::new("s3:bucket")
                .with_password("TOP_SECRET_PASSPHRASE")
                .with_key_hex("deadbeef".repeat(8)),
        );

    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("AKIA_PUBLIC"));
    assert!(dbg.contains("keyring://rship/s3.session_token"));
    assert!(dbg.contains("***REDACTED***"));
    assert!(!dbg.contains("SUPER_SECRET_AWS_KEY"));
    assert!(!dbg.contains("TOP_SECRET_PASSPHRASE"));
    assert!(!dbg.contains(&"deadbeef".repeat(8)));
}

#[tokio::test]
async fn sdk_fsync_mode_and_max_delete_percent_builders() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("keep.txt"), b"keep").unwrap();
    std::fs::write(dst.join("keep.txt"), b"keep").unwrap();
    for i in 0..4 {
        std::fs::write(dst.join(format!("extra_{i}.txt")), b"extra").unwrap();
    }

    let client = RshipClient::builder()
        .ephemeral()
        .fsync_mode(FsyncMode::Always)
        .build()
        .unwrap();
    assert_eq!(client.runtime_options().fsync_mode, FsyncMode::Always);

    // `max_delete_percent(50.0)` trips on 4/5 (80%) planned deletions without deleting anything!
    let rep = client
        .sync(src.as_path(), dst.as_path())
        .fsync_mode(FsyncMode::Batch)
        .max_delete_percent(50.0)
        .run()
        .await
        .unwrap();
    assert!(!rep.is_success(), "80% deletes must trip 50% ceiling");
    assert_eq!(rep.items_deleted, 0);
    assert!(dst.join("extra_0.txt").exists());

    // Without ceiling, deleting >50% emits `high_delete_warning`.
    let rep2 = client
        .sync(src.as_path(), dst.as_path())
        .fsync_mode(FsyncMode::Never)
        .run()
        .await
        .unwrap();
    assert!(rep2.is_success(), "{:?}", rep2.errors);
    assert_eq!(rep2.items_deleted, 4);
    assert!(
        rep2.high_delete_warning.is_some(),
        "deleting 4/5 files (80%) should populate high_delete_warning"
    );

    // BisyncBuilder wires both `fsync_mode` and `max_delete_percent`.
    let ba = tmp.path().join("ba");
    let bb = tmp.path().join("bb");
    std::fs::create_dir_all(&ba).unwrap();
    std::fs::create_dir_all(&bb).unwrap();
    std::fs::write(ba.join("one.txt"), b"1").unwrap();
    let brep = client
        .bisync(ba.as_path(), bb.as_path())
        .fsync_mode(FsyncMode::Always)
        .max_delete_percent(25.0)
        .run()
        .await
        .unwrap();
    assert!(brep.is_success(), "{:?}", brep.errors);
    assert_eq!(std::fs::read(bb.join("one.txt")).unwrap(), b"1");
}
