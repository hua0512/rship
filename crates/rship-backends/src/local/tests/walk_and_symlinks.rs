use super::super::fs_util::path_to_slash_utf8;
use super::super::*;
use futures::StreamExt;
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use tempfile::TempDir;

#[tokio::test]
async fn symlink_escape_write_and_delete_blocked() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("dst");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.txt"), b"keep-me").unwrap();

    let link_path = root.join("pwn");
    #[cfg(unix)]
    let link_res = std::os::unix::fs::symlink(&outside, &link_path);
    #[cfg(windows)]
    let link_res = std::os::windows::fs::symlink_dir(&outside, &link_path);

    if link_res.is_err() {
        return;
    }

    let backend = LocalBackend::new("dst", &root).unwrap();
    let escape_rel = RelPath::parse("pwn/authkeys").unwrap();
    let init = UploadInit {
        op_id: "op-esc".into(),
        dst_path: escape_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 100,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: rship_core::state::DstPrecondition::Any,
        src_etag: None,
    };
    let body: ByteStream = Box::pin(futures::stream::once(async {
        Ok(bytes::Bytes::from_static(b"PWNED"))
    }));
    assert!(
        backend.put_single_shot(&init, body).await.is_err(),
        "write through planted symlink must be blocked"
    );
    assert!(!outside.join("authkeys").exists());

    let victim_bp = BackendPath::from_rel(RelPath::parse("pwn/victim.txt").unwrap());
    assert!(
        backend.delete(&victim_bp).await.is_err(),
        "delete through planted symlink must be blocked"
    );
    assert!(outside.join("victim.txt").exists());
}

#[tokio::test]
async fn local_batched_listing_streams_multi_batch_and_stops_on_early_drop() {
    let tmp = TempDir::new().unwrap();
    for i in 0..150 {
        std::fs::write(tmp.path().join(format!("f_{i:03}.txt")), b"x").unwrap();
    }
    let backend = LocalBackend::new("local", tmp.path()).unwrap();
    let all: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect()
        .await;
    assert_eq!(all.len(), 150);
    assert!(all.iter().all(|r| r.is_ok()));

    // Early drop (`take(1)`) must terminate cleanly without hanging the blocking walker.
    let first: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .take(1)
        .collect()
        .await;
    assert_eq!(first.len(), 1);
}

#[test]
fn path_to_slash_utf8_handles_clean_and_edge_paths() {
    assert_eq!(path_to_slash_utf8(Path::new("")).as_deref(), Some(""));
    assert_eq!(
        path_to_slash_utf8(Path::new("single.txt")).as_deref(),
        Some("single.txt")
    );
    assert_eq!(
        path_to_slash_utf8(Path::new("a/b/c.txt")).as_deref(),
        Some("a/b/c.txt")
    );
    assert_eq!(
        path_to_slash_utf8(Path::new("./a/./b//c.txt")).as_deref(),
        Some("a/b/c.txt")
    );
    assert_eq!(
        path_to_slash_utf8(Path::new(".gitignore")).as_deref(),
        Some(".gitignore")
    );
    #[cfg(windows)]
    assert_eq!(
        path_to_slash_utf8(Path::new(r"a\b\c.txt")).as_deref(),
        Some("a/b/c.txt")
    );
}

#[tokio::test]
async fn local_parallel_walker_handles_wide_nested_tree_pruning_and_max_depth() {
    let tmp = TempDir::new().unwrap();
    // Create 24 subdirectories × 10 files + nested children + a pruned `.git` tree
    // + a `.rship.part.tmp` staging file that must be skipped.
    for d in 0..24 {
        let sub = tmp.path().join(format!("dir_{d:02}"));
        let deep = sub.join("nested");
        std::fs::create_dir_all(&deep).unwrap();
        for f in 0..10 {
            std::fs::write(sub.join(format!("f_{f}.txt")), format!("d{d}-f{f}")).unwrap();
        }
        std::fs::write(deep.join("leaf.txt"), b"leaf").unwrap();
    }
    std::fs::create_dir_all(tmp.path().join(".git/objects")).unwrap();
    std::fs::write(tmp.path().join(".git/objects/pack"), b"ignored").unwrap();
    std::fs::write(tmp.path().join(".rship.part.stale"), b"skip").unwrap();

    let backend = LocalBackend::new("local-par", tmp.path()).unwrap();

    // 1. Full parallel walk with dir_pruner skipping `.git`.
    let opts = ListOptions::new().with_dir_pruner(|p: &RelPath| p.as_str() == ".git");
    let entries: Vec<Entry> = backend
        .list_with_options(&RelPath::root(), &opts)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    let files: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    let dirs: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::Directory)
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert_eq!(files.len(), 24 * 11, "expected 264 files across 24 subdirs");
    assert_eq!(dirs.len(), 24 * 2, "expected 48 non-pruned directories");
    assert!(!dirs.contains(".git"));
    assert!(!files.iter().any(|p| p.starts_with(".git/")));
    assert!(!files.iter().any(|p| p.contains(".rship.part.")));

    // 2. `max_depth(1)` returns ONLY direct children of root (24 dirs + `.git` = 25 dirs, 0 files).
    let depth1: Vec<Entry> = backend
        .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(1))
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(depth1.len(), 25);
    assert!(depth1.iter().all(|e| e.kind == EntryKind::Directory));
}

#[tokio::test]
async fn local_copy_links_dereferences_symlinks_and_detects_cycles_without_hanging() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let external = tmp.path().join("external");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(src_dir.join("sub")).unwrap();
    std::fs::create_dir_all(external.join("ext_dir")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(src_dir.join("real.txt"), b"real-bytes").unwrap();
    std::fs::write(external.join("target.txt"), b"linked-file-bytes").unwrap();
    std::fs::write(external.join("ext_dir/inside.txt"), b"linked-dir-bytes").unwrap();

    #[cfg(unix)]
    let mk_file_link =
        std::os::unix::fs::symlink(external.join("target.txt"), src_dir.join("link_file.txt"));
    #[cfg(windows)]
    let mk_file_link = std::os::windows::fs::symlink_file(
        external.join("target.txt"),
        src_dir.join("link_file.txt"),
    );
    if mk_file_link.is_err() {
        // On Windows without Developer Mode / SeCreateSymbolicLinkPrivilege, skip cleanly.
        return;
    }

    #[cfg(unix)]
    let mk_dir_link =
        std::os::unix::fs::symlink(external.join("ext_dir"), src_dir.join("link_dir"));
    #[cfg(windows)]
    let mk_dir_link =
        std::os::windows::fs::symlink_dir(external.join("ext_dir"), src_dir.join("link_dir"));
    if mk_dir_link.is_err() {
        return;
    }

    // 1. Copy with `follow_symlinks = true` on `src` (and `false` on `dst`):
    //    both `link_file.txt` and `link_dir/inside.txt` must materialize as regular files in `dst`.
    let src = Arc::new(
        LocalBackend::new("src", &src_dir)
            .unwrap()
            .with_follow_symlinks(true),
    );
    let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-links").unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("j-links", JobMode::Copy, "src", "dst");
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(
        rep.errors.is_empty(),
        "unexpected copy-links errors: {:?}",
        rep.errors
    );
    assert_eq!(rep.files_transferred, 3);
    assert_eq!(
        std::fs::read(dst_dir.join("real.txt")).unwrap(),
        b"real-bytes"
    );
    assert_eq!(
        std::fs::read(dst_dir.join("link_file.txt")).unwrap(),
        b"linked-file-bytes"
    );
    assert_eq!(
        std::fs::read(dst_dir.join("link_dir/inside.txt")).unwrap(),
        b"linked-dir-bytes"
    );
    assert!(
        !std::fs::symlink_metadata(dst_dir.join("link_file.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // 2. Introduce a directory symlink cycle (`sub/loop_back -> src_dir`):
    //    walker MUST terminate cleanly and emit a cycle error while still listing valid files.
    #[cfg(unix)]
    std::os::unix::fs::symlink(&src_dir, src_dir.join("sub/loop_back")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&src_dir, src_dir.join("sub/loop_back")).unwrap();

    let items: Vec<Result<Entry>> = src
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect()
        .await;
    let cycle_errs: Vec<_> = items
        .iter()
        .filter_map(|r| r.as_ref().err())
        .filter(|e| e.to_string().contains("symlink cycle"))
        .collect();
    assert_eq!(
        cycle_errs.len(),
        1,
        "expected exactly 1 symlink cycle error, got items: {items:?}"
    );
    let ok_files: HashSet<String> = items
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert!(ok_files.contains("real.txt"));
    assert!(ok_files.contains("link_file.txt"));
    assert!(ok_files.contains("link_dir/inside.txt"));

    // 3. `open_read_entry` with `follow_symlinks == false` MUST reject reading a symlink
    //    (closing TOCTOU swap bypass), while `delete` MUST unlink a leaf symlink cleanly!
    let strict_src = LocalBackend::new("strict-src", &src_dir).unwrap();
    let fake_entry = Entry {
        node_id: None,
        parent_id: None,
        raw_path: None,
        nfc_path: RelPath::parse("link_file.txt").unwrap(),
        kind: EntryKind::File,
        size: 17,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    };
    let link_bp = BackendPath::from_rel(RelPath::parse("link_file.txt").unwrap());
    assert!(
        strict_src
            .open_read_entry(&fake_entry, &link_bp, None)
            .await
            .is_err(),
        "open_read_entry must block symlink reads when follow_symlinks == false"
    );
    strict_src.delete(&link_bp).await.unwrap();
    assert!(
        std::fs::symlink_metadata(src_dir.join("link_file.txt")).is_err(),
        "delete must unlink leaf symlink cleanly"
    );
    assert!(
        external.join("target.txt").exists(),
        "unlinking leaf symlink must NEVER delete its target outside root"
    );
}

#[cfg(windows)]
#[test]
fn strip_root_prefix_handles_windows_verbatim() {
    // Verbatim `\\?\` and `\\?\UNC\` prefix stripping must match non-verbatim roots.
    assert_eq!(
        super::super::fs_util::strip_root_prefix(
            Path::new(r"\\?\D:\repo\sub\file.txt"),
            Path::new(r"D:\repo"),
        )
        .as_deref(),
        Some(Path::new(r"sub\file.txt"))
    );
    assert_eq!(
        super::super::fs_util::strip_root_prefix(
            Path::new(r"\\?\UNC\server\share\repo\a\b.bin"),
            Path::new(r"\\server\share\repo"),
        )
        .as_deref(),
        Some(Path::new(r"a\b.bin"))
    );
}

#[tokio::test]
async fn deep_directory_walk_and_backup_dir_archives_force_type_replace() {
    // 1. Deep directory walk (> 245 chars, exercising `\\?\` prefix on Windows) must yield files.
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("longroot");
    let seg = "segment_0123456789_abcdefghij_0123456789";
    let deep_rel = format!("{seg}/{seg}/{seg}/{seg}/{seg}/{seg}");
    let deep_os =
        super::super::to_os_path(&root.join(deep_rel.replace('/', std::path::MAIN_SEPARATOR_STR)));
    std::fs::create_dir_all(&deep_os).unwrap();
    let deep_file = super::super::to_os_path(&deep_os.join("leaf.txt"));
    std::fs::write(&deep_file, b"deep-ok").unwrap();

    let backend = LocalBackend::new("long", &root).unwrap();
    let prefix = RelPath::parse(&deep_rel).unwrap();
    let listed: Vec<_> = backend
        .list_with_options(&prefix, &ListOptions::recursive())
        .await
        .unwrap()
        .collect()
        .await;
    let files: Vec<String> = listed
        .into_iter()
        .map(|r| r.expect("walk long path cleanly"))
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert_eq!(files, vec![format!("{deep_rel}/leaf.txt")]);

    // 2. `--force-type-replace` (`ReplaceWithDir`) + `--backup-dir` must archive the replaced file
    //    into `--backup-dir` before replacing it with a directory.
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let bak_dir = tmp.path().join("bak");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(src_dir.join("collide")).unwrap();
    std::fs::write(src_dir.join("collide/child.txt"), b"from-dir").unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(dst_dir.join("collide"), b"precious-old-file").unwrap();

    let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
    let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
    let bak = Arc::new(LocalBackend::new("bak", &bak_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "j-ftr-bak").unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        src,
        dst,
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut cfg = EngineConfig::new("j-ftr-bak", JobMode::Sync, "src", "dst")
        .with_backup_dir(bak, RelPath::root());
    cfg.force_type_replace = true;
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "unexpected errors: {:?}", rep.errors);
    assert!(dst_dir.join("collide/child.txt").exists());
    assert_eq!(
        std::fs::read(bak_dir.join("collide")).unwrap(),
        b"precious-old-file",
        "ReplaceWithDir must archive replaced destination file into --backup-dir!"
    );
}

#[tokio::test]
async fn max_depth_zero_returns_empty_on_existing_root_and_not_found_on_missing() {
    use rship_core::error::ErrorKind;

    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();

    let backend = LocalBackend::new("d0", &root).unwrap();
    let items: Vec<_> = backend
        .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
        .await
        .unwrap()
        .collect()
        .await;
    assert!(
        items.is_empty(),
        "max_depth(0) must return 0 entries, got {items:?}"
    );

    let missing = LocalBackend::new("d0m", tmp.path().join("missing")).unwrap();
    let err = missing
        .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
        .await
        .err()
        .expect("max_depth(0) on missing root must still fail with NotFound");
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[tokio::test]
async fn ancestor_cycle_above_root_terminates_without_leaking_outside() {
    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    let root = outside.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside").unwrap();
    std::fs::write(root.join("inside.txt"), b"inside").unwrap();

    let up_link = root.join("up");
    #[cfg(unix)]
    let mk = std::os::unix::fs::symlink(&outside, &up_link);
    #[cfg(windows)]
    let mk = std::os::windows::fs::symlink_dir(&outside, &up_link);
    if mk.is_err() {
        return;
    }

    let backend = LocalBackend::new("follow-up", &root)
        .unwrap()
        .with_follow_symlinks(true);
    let items: Vec<Result<Entry>> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect()
        .await;
    assert!(
        items.iter().any(|r| r
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("symlink cycle"))),
        "expected symlink cycle error for up -> parent, got {items:?}"
    );
    let names: Vec<String> = items
        .into_iter()
        .filter_map(|r| r.ok())
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert!(names.contains(&"inside.txt".to_string()));
    assert!(!names.iter().any(|n| n.contains("secret.txt")));
}

#[tokio::test]
async fn symlink_escape_blocked_in_stat_walk_upload_query_abort_and_sync_durable() {
    use rship_core::error::ErrorKind;
    use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(outside.join("sub")).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
    std::fs::write(outside.join("sub/nested.txt"), b"nested").unwrap();
    std::fs::write(outside.join("forged.part"), b"1234").unwrap();

    let esc = root.join("esc");
    #[cfg(unix)]
    let mk_dir = std::os::unix::fs::symlink(&outside, &esc);
    #[cfg(windows)]
    let mk_dir = std::os::windows::fs::symlink_dir(&outside, &esc);
    if mk_dir.is_err() {
        return;
    }

    let leaf_link = root.join("leaf_link");
    #[cfg(unix)]
    let mk_leaf = std::os::unix::fs::symlink(outside.join("secret.txt"), &leaf_link);
    #[cfg(windows)]
    let mk_leaf = std::os::windows::fs::symlink_file(outside.join("secret.txt"), &leaf_link);
    if mk_leaf.is_err() {
        return;
    }

    let backend = LocalBackend::new("strict", &root).unwrap();

    // Direct leaf symlink stat returns EntryKind::Symlink.
    let leaf_st = backend
        .stat(&BackendPath::from_rel(RelPath::parse("leaf_link").unwrap()))
        .await
        .unwrap()
        .expect("leaf symlink stat");
    assert_eq!(leaf_st.kind, EntryKind::Symlink);

    // Intermediate symlink escape in stat and walk must fail with InvalidPath.
    let err = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("esc/secret.txt").unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidPath);

    let err = backend
        .list_with_options(
            &RelPath::parse("esc/sub").unwrap(),
            &ListOptions::recursive(),
        )
        .await
        .err()
        .expect("walk through symlink prefix must fail");
    assert_eq!(err.kind, ErrorKind::InvalidPath);

    // sync_durable_file through escaped path must fail.
    let err = backend
        .sync_durable_file(&BackendPath::from_rel(
            RelPath::parse("esc/secret.txt").unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidPath);

    // Forged session_token traversing symlink must fail in query, upload_chunk, finish, abort.
    let forged_op = OperationRecord {
        op_id: "op-forged".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "a.bin".into(),
        dst_raw_path: "a.bin".into(),
        dst_nfc_path: RelPath::parse("a.bin").unwrap(),
        src_version: SourceVersion {
            node_id: None,
            size: 4,
            mtime_ns: 100,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "local".into(),
        session_token: Some(esc.join("forged.part").to_string_lossy().into_owned()),
        backend_meta: String::new(),
        planned_chunk_size: 4,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    assert_eq!(
        backend.query_upload(&forged_op).await.unwrap_err().kind,
        ErrorKind::InvalidPath
    );
    let chunk = ChunkUpload::new(
        1,
        0,
        4,
        4,
        Box::pin(futures::stream::once(async {
            Ok(bytes::Bytes::from_static(b"abcd"))
        })),
    );
    assert_eq!(
        backend
            .upload_chunk(&forged_op, chunk)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidPath
    );
    let part = CompletedPart {
        part_number: 1,
        offset: 0,
        length: 4,
        etag: String::new(),
        checksum: None,
    };
    assert_eq!(
        backend
            .finish_upload(&forged_op, &[part])
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidPath
    );
    assert_eq!(
        backend.abort_upload(&forged_op).await.unwrap_err().kind,
        ErrorKind::InvalidPath
    );
    assert_eq!(std::fs::read(outside.join("forged.part")).unwrap(), b"1234");
}

#[test]
fn probe_case_sensitivity_is_non_polluting_and_race_free() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("ro");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Sample.txt"), b"x").unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    let before = std::fs::metadata(&dir).unwrap().modified().unwrap();
    let expected = !dir.join("sample.txt").exists();

    let results: Vec<bool> = std::thread::scope(|s| {
        (0..8)
            .map(|i| {
                let d = &dir;
                s.spawn(move || {
                    LocalBackend::new(format!("c-{i}"), d)
                        .unwrap()
                        .capabilities()
                        .case_sensitive
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    for r in results {
        assert_eq!(r, expected);
    }
    let after = std::fs::metadata(&dir).unwrap().modified().unwrap();
    assert_eq!(before, after, "probe must not mutate directory mtime");
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["Sample.txt".to_string()]);
}

#[cfg(windows)]
#[test]
fn windows_to_os_path_handles_unc_dotdot_short_slashes_and_surrogates() {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let tail = "a".repeat(250);
    let unc_fwd = format!("//server/share/{tail}");
    let out_fwd = to_os_path(Path::new(&unc_fwd))
        .to_string_lossy()
        .into_owned();
    assert!(out_fwd.starts_with(r"\\?\UNC\server\share\"), "{out_fwd}");
    assert!(!out_fwd.contains('/'), "{out_fwd}");

    let unc_mix = format!(r"\\server/share/a\..\b/{tail}");
    let out_mix = to_os_path(Path::new(&unc_mix))
        .to_string_lossy()
        .into_owned();
    assert!(out_mix.starts_with(r"\\?\UNC\server\share\b\"), "{out_mix}");

    let dotdot = format!(r"D:\work\sub\..\dst\{tail}");
    let out_dotdot = to_os_path(Path::new(&dotdot))
        .to_string_lossy()
        .into_owned();
    assert!(out_dotdot.starts_with(r"\\?\D:\work\dst\"), "{out_dotdot}");
    assert!(!out_dotdot.contains(r"\..\"), "{out_dotdot}");

    let short_mixed = Path::new("C:/work/sub/../dst/file.txt");
    assert_eq!(
        to_os_path(short_mixed),
        PathBuf::from(r"C:\work\dst\file.txt")
    );
    assert_eq!(to_os_path(Path::new("rel/path")), PathBuf::from("rel/path"));
    assert_eq!(
        to_os_path(Path::new(r"\\?\C:\verbatim")),
        PathBuf::from(r"\\?\C:\verbatim")
    );

    // Unpaired UTF-16 surrogate 0xD800 must survive bit-for-bit.
    let mut wide: Vec<u16> = OsStr::new(r"C:\dir\").encode_wide().collect();
    wide.push(0xD800);
    wide.push(b'\\' as u16);
    wide.extend(std::iter::repeat_n(b'x' as u16, 240));
    let src = PathBuf::from(OsString::from_wide(&wide));
    let out_w: Vec<u16> = to_os_path(&src).as_os_str().encode_wide().collect();
    assert!(out_w.contains(&0xD800), "unpaired surrogate was lost!");
    assert!(out_w.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]));
}

#[cfg(windows)]
#[tokio::test]
async fn windows_reparse_point_surrogate_vs_non_surrogate_and_about_unc_and_readonly() {
    use super::super::fs_util::{format_disk_free_space_path, is_reparse_tag_name_surrogate};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    assert!(is_reparse_tag_name_surrogate(0xA000_000C)); // symlink
    assert!(is_reparse_tag_name_surrogate(0xA000_0003)); // junction
    assert!(!is_reparse_tag_name_surrogate(0x9000_001A)); // OneDrive cloud
    assert!(!is_reparse_tag_name_surrogate(0x8000_0017)); // WOF
    assert!(!is_reparse_tag_name_surrogate(0x8000_0013)); // Dedup

    let unc_w = format_disk_free_space_path(Path::new("//server/share"));
    let unc_s = String::from_utf16_lossy(&unc_w[..unc_w.len() - 1]);
    assert_eq!(unc_s, r"\\server\share\");

    let tmp = TempDir::new().unwrap();
    let seg = "long_segment_0123456789_abcdefghij_0123456789";
    let deep_root = to_os_path(
        &tmp.path()
            .join(format!("{seg}\\{seg}\\{seg}\\{seg}\\{seg}\\{seg}")),
    );
    std::fs::create_dir_all(&deep_root).unwrap();
    let deep_backend = LocalBackend::new("deep-about", &deep_root).unwrap();
    let quota = deep_backend.about().await.unwrap().expect("disk quota");
    assert!(quota.total_bytes.unwrap_or(0) > 0);

    // Non-surrogate reparse point regular file (IO_REPARSE_TAG_DEDUP).
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_DEDUP: u32 = 0x8000_0013;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            h_device: *mut std::ffi::c_void,
            dw_io_control_code: u32,
            lp_in_buffer: *const u8,
            n_in_buffer_size: u32,
            lp_out_buffer: *mut u8,
            n_out_buffer_size: u32,
            lp_bytes_returned: *mut u32,
            lp_overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }

    let root = tmp.path().join("reparse_root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
    let dedup = root.join("dedup.txt");
    std::fs::write(&dedup, b"hydrated-bytes").unwrap();
    {
        use std::os::windows::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&dedup)
            .unwrap();
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&IO_REPARSE_TAG_DEDUP.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        let mut ret = 0u32;
        // SAFETY: `f.as_raw_handle()` is a valid open file handle and `buf` is a valid 12-byte
        // `REPARSE_DATA_BUFFER` for the duration of `DeviceIoControl`.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buf.as_ptr(),
                buf.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
    }

    let junc = root.join("junc");
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &junc.to_string_lossy(),
            &outside.to_string_lossy(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let backend = LocalBackend::new("rep", &root).unwrap();
    let dedup_bp = BackendPath::from_rel(RelPath::parse("dedup.txt").unwrap());
    let DataSource::LocalSeekable(seek) = backend.open_read(&dedup_bp, None).await.unwrap() else {
        panic!("expected LocalSeekable");
    };
    let mut read_buf = vec![0u8; 14];
    let n = seek.read_at(0, &mut read_buf).await.unwrap();
    assert_eq!(&read_buf[..n], b"hydrated-bytes");
    assert!(
        backend
            .compute_hash(&dedup_bp, HashKind::Sha256)
            .await
            .unwrap()
            .is_some()
    );

    let junc_bp = BackendPath::from_rel(RelPath::parse("junc/secret.txt").unwrap());
    assert!(backend.open_read(&junc_bp, None).await.is_err());

    // Read-only directory delete and read-only destination overwrite via rename().
    let ro_dir = root.join("ro_dir");
    std::fs::create_dir_all(&ro_dir).unwrap();
    let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&ro_dir, perms).unwrap();
    backend
        .delete(&BackendPath::from_rel(RelPath::parse("ro_dir").unwrap()))
        .await
        .expect("delete on read-only empty dir must succeed");
    assert!(!ro_dir.exists());

    std::fs::write(root.join("src_ren.txt"), b"new").unwrap();
    std::fs::write(root.join("dst_ren.txt"), b"old").unwrap();
    let mut dst_perms = std::fs::metadata(root.join("dst_ren.txt"))
        .unwrap()
        .permissions();
    dst_perms.set_readonly(true);
    std::fs::set_permissions(root.join("dst_ren.txt"), dst_perms).unwrap();
    backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("src_ren.txt").unwrap()),
            "dst_ren.txt",
        )
        .await
        .expect("rename overwriting read-only target must succeed");
    assert_eq!(std::fs::read(root.join("dst_ren.txt")).unwrap(), b"new");

    // Suppress unused import warning on OsStringExt check above.
    let _ = std::ffi::OsString::from_wide(&unc_w);
}
