use crate::mock_server::{make_backend, spawn_mock_dropbox};
use axum::body::Bytes;
use futures::StreamExt;
use rship_backends::dropbox::{DROPBOX_CHUNK_ALIGN_BYTES, dropbox_content_hash};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit, UploadProgress};
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::path::RelPath;
use rship_core::source::ByteStream;
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{EntryKind, HashKind};
use std::sync::Arc;

#[tokio::test]
async fn dropbox_passes_full_backend_conformance_suite() {
    let (base_url, _) = spawn_mock_dropbox().await;
    let backend: Arc<dyn StorageBackend> = make_backend(&base_url);
    run_backend_conformance(backend, SystemClock::shared()).await;
}

#[tokio::test]
async fn dropbox_handles_utf16_unicode_429_retry_incorrect_offset_resume_copy_move_and_quota() {
    let (base_url, state) = spawn_mock_dropbox().await;
    let backend = make_backend(&base_url);

    // 1. Quota (`about`)
    let quota = backend.about().await.unwrap().expect("quota");
    assert_eq!(quota.used_bytes, Some(100_000_000));
    assert_eq!(quota.total_bytes, Some(2_000_000_000));
    assert_eq!(quota.free_bytes, Some(1_900_000_000));

    // 2. Unicode + emoji path (`🚀` requires UTF-16 surrogate pair in ASCII Dropbox-API-Arg!)
    //    Also inject `429 too_many_write_operations` on streaming upload to verify it classifies as
    //    `ErrorKind::RateLimited` + `RetryClass::Throttled` + `retry_after` for engine-level replay!
    state.lock().unwrap().inject_429_remaining = 1;
    let unicode_path = RelPath::parse("文档/🚀 emoji & café.txt").unwrap();
    let payload = b"dropbox unicode payload with 429 retry".to_vec();
    let init = UploadInit {
        op_id: "op-uni".into(),
        dst_path: unicode_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_clone1 = payload.clone();
    let body1: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(p_clone1)) },
    ));
    let throttled = backend.put_single_shot(&init, body1).await.unwrap_err();
    assert_eq!(throttled.kind, rship_core::ErrorKind::RateLimited);
    assert_eq!(throttled.retry, rship_core::RetryClass::Throttled);
    assert!(throttled.retry_after.is_some());

    let p_clone2 = payload.clone();
    let body2: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(p_clone2)) },
    ));
    let uploaded = backend.put_single_shot(&init, body2).await.unwrap();
    assert_eq!(uploaded.size, payload.len() as u64);
    assert_eq!(uploaded.kind, EntryKind::File);

    // Dropbox's native content_hash is a 4 MiB SHA-256 tree (NOT flat SHA-256),
    // so compute_hash(Sha256) intentionally returns None rather than misleading cross-backend check!
    assert!(
        backend
            .compute_hash(
                &BackendPath::from_rel(unicode_path.clone()),
                HashKind::Sha256
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(dropbox_content_hash(&payload).len(), 64);

    // 3. Server-side copy (`copy_v2`) with automatic RPC 429 retry + in-place rename (`move_v2`)
    state.lock().unwrap().inject_429_remaining = 1;
    let copy_dst = RelPath::parse("copies/🚀 copied.txt").unwrap();
    let copy_init = UploadInit {
        op_id: "op-copy".into(),
        dst_path: copy_dst.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    assert!(backend.can_server_side_copy_from(&ep));
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(unicode_path.clone()),
            &copy_init,
        )
        .await
        .unwrap()
        .expect("server-side copy succeeded");
    assert_eq!(copied.size, payload.len() as u64);
    assert_eq!(state.lock().unwrap().copy_calls, 1);

    let renamed = backend
        .rename(&BackendPath::from_rel(copy_dst.clone()), "renamed.txt")
        .await
        .unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "copies/renamed.txt");
    assert_eq!(state.lock().unwrap().move_calls, 1);

    // 4. Multi-chunk upload session + `409 incorrect_offset` crash-resume recovery!
    let chunk_size = 64 * 1024u64;
    assert_eq!(DROPBOX_CHUNK_ALIGN_BYTES, 4 * 1024 * 1024);
    let total_size = chunk_size + 1024;
    let big_path = RelPath::parse("resumable/big.bin").unwrap();
    let big_init = UploadInit {
        op_id: "op-big".into(),
        dst_path: big_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_size,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&big_init).await.unwrap();
    let op = OperationRecord {
        op_id: big_init.op_id.clone(),
        session_key: "sk-dbx".into(),
        job_id: "j-dbx".into(),
        src_endpoint: "local://test".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: big_path.as_str().into(),
        dst_raw_path: big_path.as_str().into(),
        dst_nfc_path: big_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total_size,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "dropbox".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    let part1 = vec![0x5Au8; chunk_size as usize];
    let p1_body: ByteStream =
        Box::pin(futures::stream::once(async move { Ok(Bytes::from(part1)) }));
    let ack1 = backend
        .upload_chunk(&op, ChunkUpload::new(1, 0, chunk_size, total_size, p1_body))
        .await
        .unwrap();
    assert_eq!(ack1.next_offset, Some(chunk_size));
    assert!(ack1.completed.is_none());

    // Simulate process crash before SQLite updated `confirmed_offset` (still 0):
    // `query_upload` sends probe at stale offset 0 -> server returns `409 incorrect_offset`
    // with `correct_offset = 4 MiB` -> backend MUST recover exact `SequentialOffset(4 MiB)`!
    let progress = backend.query_upload(&op).await.unwrap();
    assert_eq!(progress, UploadProgress::SequentialOffset(chunk_size));

    // Upload remaining 1024 bytes -> commits!
    let part2 = vec![0xA5u8; 1024];
    let p2_body: ByteStream =
        Box::pin(futures::stream::once(async move { Ok(Bytes::from(part2)) }));
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(2, chunk_size, 1024, total_size, p2_body),
        )
        .await
        .unwrap();
    let finalized = ack2.completed.expect("final chunk commits Dropbox file");
    assert_eq!(finalized.size, total_size);

    // 5. Batch delete + paginated listing
    let failures = backend
        .delete_batch(&[
            BackendPath::from_rel(unicode_path),
            BackendPath::from_rel(RelPath::parse("copies/renamed.txt").unwrap()),
        ])
        .await
        .unwrap();
    assert!(failures.is_empty());
    assert_eq!(state.lock().unwrap().batch_delete_calls, 1);

    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "resumable/big.bin")
    );
}

#[tokio::test]
async fn dropbox_delete_batch_polls_async_job_surfaces_failures_and_guards_root() {
    use crate::mock_server::MockEntry;

    let (base_url, state) = spawn_mock_dropbox().await;
    {
        let mut g = state.lock().unwrap();
        g.ensure_parents("/backups/a.txt");
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/backups"),
            MockEntry {
                id: "id:rootdir".into(),
                path: "/backups".into(),
                is_folder: true,
                data: vec![],
                rev: "rev0".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
        for name in ["/backups/a.txt", "/backups/b.txt", "/backups/locked.txt"] {
            let id = g.alloc_id("id:f");
            let rev = g.alloc_id("rev");
            g.entries.insert(
                crate::mock_server::MockDropboxState::key(name),
                MockEntry {
                    id,
                    path: name.into(),
                    is_folder: false,
                    data: b"data".to_vec(),
                    rev,
                    client_modified: "2026-11-25T02:00:00Z".into(),
                },
            );
        }
        g.delete_batch_async_polls = 2;
        g.delete_batch_fail_keys
            .insert(crate::mock_server::MockDropboxState::key(
                "/backups/locked.txt",
            ));
    }

    let mut cfg =
        rship_backends::dropbox::DropboxConfig::new("dbx-rooted").with_root_path("/backups");
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
    let auth = Arc::new(rship_transport::oauth::StaticBearerAuth::new(
        "dbx-rooted",
        "dbx-test-token",
    ));
    let backend = rship_backends::dropbox::DropboxBackend::new(cfg, auth, transport).unwrap();

    // Non-empty root_path + root in delete_batch must reject root without deleting `/backups`!
    let failures = backend
        .delete_batch(&[
            BackendPath::from_rel(RelPath::root()),
            BackendPath::from_rel(RelPath::parse("a.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("locked.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("missing.txt").unwrap()),
        ])
        .await
        .unwrap();

    assert_eq!(
        failures.len(),
        2,
        "expected root + locked failures: {failures:?}"
    );
    assert!(failures[0].0.nfc_path.is_root());
    assert_eq!(failures[0].1.kind, rship_core::ErrorKind::InvalidPath);
    assert_eq!(failures[1].0.nfc_path.as_str(), "locked.txt");

    let g = state.lock().unwrap();
    assert_eq!(g.delete_batch_check_calls, 3, "must poll until complete");
    assert!(
        g.entries
            .contains_key(&crate::mock_server::MockDropboxState::key("/backups")),
        "root_path folder `/backups` must NEVER be deleted"
    );
    assert!(
        !g.entries
            .contains_key(&crate::mock_server::MockDropboxState::key("/backups/a.txt")),
        "a.txt must be deleted"
    );
    assert!(
        g.entries
            .contains_key(&crate::mock_server::MockDropboxState::key("/backups/b.txt")),
        "b.txt must be untouched"
    );
}

#[tokio::test]
async fn dropbox_server_side_copy_overwrites_under_any_and_existing_and_restores_on_failure() {
    use crate::common::InjectedFault;
    use crate::mock_server::MockEntry;

    let (base_url, state) = spawn_mock_dropbox().await;
    {
        let mut g = state.lock().unwrap();
        g.ensure_parents("/src/file.bin");
        g.ensure_parents("/dst/file.bin");
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/src/file.bin"),
            MockEntry {
                id: "id:src".into(),
                path: "/src/file.bin".into(),
                is_folder: false,
                data: b"new-source-content".to_vec(),
                rev: "rev-src".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/dst/file.bin"),
            MockEntry {
                id: "id:dst".into(),
                path: "/dst/file.bin".into(),
                is_folder: false,
                data: b"old-destination-content".to_vec(),
                rev: "rev-dst-1".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
    }

    let backend = make_backend(&base_url);
    let ep = backend.endpoint_identity();

    // 1. Existing precondition with wrong etag must fail PreconditionFailed without touching dst.
    let bad_pre = UploadInit {
        op_id: "op-copy-wrong-etag".into(),
        dst_path: RelPath::parse("dst/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 18,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: Some("wrong-rev".into()),
            mtime_ns: 0,
            size: 23,
        },
        src_etag: None,
    };
    let err = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src/file.bin").unwrap()),
            &bad_pre,
        )
        .await
        .expect_err("wrong etag must fail");
    assert_eq!(err.kind, rship_core::ErrorKind::PreconditionFailed);

    // 2. If backup-moved copy fails, destination must be restored from backup!
    let faults = state.lock().unwrap().fault_injector();
    // 1st copy_v2 hits 409 to/conflict, then backup move runs, 2nd copy_v2 hits 403 permission_denied.
    faults.push(
        "copy_v2",
        InjectedFault::slow_finalize(std::time::Duration::ZERO),
    );
    faults.push(
        "copy_v2",
        InjectedFault::json_error(
            axum::http::StatusCode::FORBIDDEN,
            r#"{"error_summary":"no_permission"}"#,
        ),
    );

    let overwrite_any = UploadInit {
        op_id: "op-copy-restore".into(),
        dst_path: RelPath::parse("dst/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 18,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let copy_err = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src/file.bin").unwrap()),
            &overwrite_any,
        )
        .await
        .expect_err("2nd copy_v2 failure should propagate");
    assert_eq!(copy_err.kind, rship_core::ErrorKind::PermissionDenied);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .entries
            .get(&crate::mock_server::MockDropboxState::key("/dst/file.bin"))
            .map(|e| e.data.clone()),
        Some(b"old-destination-content".to_vec()),
        "destination must be restored when overwrite copy fails"
    );

    // 3. Overwrite with DstPrecondition::Any succeeds cleanly and removes backup.
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src/file.bin").unwrap()),
            &overwrite_any,
        )
        .await
        .unwrap()
        .expect("overwrite server_side_copy must succeed");
    assert_eq!(copied.size, b"new-source-content".len() as u64);
    let g = state.lock().unwrap();
    assert_eq!(
        g.entries
            .get(&crate::mock_server::MockDropboxState::key("/dst/file.bin"))
            .unwrap()
            .data,
        b"new-source-content"
    );
    assert!(
        !g.entries.keys().any(|k| k.contains(".rship_bak_")),
        "backup file must be deleted after successful overwrite"
    );
}

#[tokio::test]
async fn dropbox_server_side_copy_restores_backup_when_copy_returns_none_and_stat_handles_3dot_not_found()
 {
    use crate::common::InjectedFault;
    use crate::mock_server::MockEntry;

    let (base_url, state) = spawn_mock_dropbox().await;
    {
        let mut g = state.lock().unwrap();
        g.ensure_parents("/src/vanish.bin");
        g.ensure_parents("/dst/precious.bin");
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/src/vanish.bin"),
            MockEntry {
                id: "id:src-v".into(),
                path: "/src/vanish.bin".into(),
                is_folder: false,
                data: b"new-source".to_vec(),
                rev: "rev-src-v".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/dst/precious.bin"),
            MockEntry {
                id: "id:dst-p".into(),
                path: "/dst/precious.bin".into(),
                is_folder: false,
                data: b"precious-old-dst-data".to_vec(),
                rev: "rev-dst-p".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
    }

    let backend = make_backend(&base_url);
    let ep = backend.endpoint_identity();
    let faults = state.lock().unwrap().fault_injector();

    // 1st copy_v2 hits 409 to/conflict, then backup move runs, 2nd copy_v2 returns
    // 409 from_lookup/not_found (making try_copy_v2 return Ok(None)).
    faults.push(
        "copy_v2",
        InjectedFault::slow_finalize(std::time::Duration::ZERO),
    );
    faults.push(
        "copy_v2",
        InjectedFault::json_error(
            axum::http::StatusCode::CONFLICT,
            r#"{"error_summary":"from_lookup/not_found/..."}"#,
        ),
    );

    let overwrite_any = UploadInit {
        op_id: "op-copy-restore-none".into(),
        dst_path: RelPath::parse("dst/precious.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 10,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src/vanish.bin").unwrap()),
            &overwrite_any,
        )
        .await
        .expect("from_lookup/not_found during overwrite must return Ok(None) rather than error");
    assert!(copied.is_none());

    {
        let g = state.lock().unwrap();
        assert_eq!(
            g.entries
                .get(&crate::mock_server::MockDropboxState::key(
                    "/dst/precious.bin"
                ))
                .map(|e| e.data.clone()),
            Some(b"precious-old-dst-data".to_vec()),
            "backup must be restored to destination when try_copy_v2 returns Ok(None)"
        );
        assert!(
            !g.entries.keys().any(|k| k.contains(".rship_bak_")),
            "backup path must not remain after restore"
        );
    }

    // 409 summary-only `path/not_found/...` without `"error"` JSON object must map to Ok(None).
    faults.push(
        "get_metadata",
        InjectedFault::json_error(
            axum::http::StatusCode::CONFLICT,
            r#"{"error_summary":"path/not_found/..."}"#,
        ),
    );
    let missing = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("missing/three-dots.txt").unwrap(),
        ))
        .await
        .expect("409 path/not_found/... must map to Ok(None), not Protocol error");
    assert!(missing.is_none());
}

#[tokio::test]
async fn dropbox_stat_root_with_root_path_and_whitespace_filenames() {
    use crate::mock_server::MockEntry;

    let (base_url, state) = spawn_mock_dropbox().await;
    let mut cfg =
        rship_backends::dropbox::DropboxConfig::new("dbx-rooted").with_root_path("/Café Space");
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
    let auth = Arc::new(rship_transport::oauth::StaticBearerAuth::new(
        "dbx-rooted",
        "dbx-test-token",
    ));
    let backend = rship_backends::dropbox::DropboxBackend::new(cfg, auth, transport).unwrap();

    // Missing root_path -> stat(root) returns Ok(None).
    assert!(
        backend
            .stat(&BackendPath::from_rel(RelPath::root()))
            .await
            .unwrap()
            .is_none()
    );

    // Seed `/Café Space` folder -> stat(root) returns Some(Directory)!
    state.lock().unwrap().entries.insert(
        crate::mock_server::MockDropboxState::key("/Café Space"),
        MockEntry {
            id: "id:root".into(),
            path: "/Café Space".into(),
            is_folder: true,
            data: vec![],
            rev: "rev-root".into(),
            client_modified: "2026-11-25T02:00:00Z".into(),
        },
    );
    let root_entry = backend
        .stat(&BackendPath::from_rel(RelPath::root()))
        .await
        .unwrap()
        .expect("non-empty root_path stat(root) must return root Directory entry");
    assert_eq!(root_entry.kind, EntryKind::Directory);
    assert!(root_entry.nfc_path.is_root());

    // Whitespace-padded filename roundtrip!
    let space_rel = RelPath::parse(" leading / trailing .txt ").unwrap();
    let payload = b"space-padded-dropbox".to_vec();
    let init = UploadInit {
        op_id: "op-spaces".into(),
        dst_path: space_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 0, // Also verifies mtime_ns <= 0 omits client_modified!
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_clone = payload.clone();
    let uploaded = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(p_clone)) },
            )),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.nfc_path.as_str(), " leading / trailing .txt ");
    assert!(
        state
            .lock()
            .unwrap()
            .seen_upload_args
            .last()
            .and_then(|v| v.get("client_modified"))
            .is_none(),
        "client_modified must be omitted when src_mtime_ns <= 0"
    );

    let statted = backend
        .stat(&BackendPath::from_rel(space_rel.clone()))
        .await
        .unwrap()
        .expect("space-padded file must stat");
    assert_eq!(statted.nfc_path.as_str(), " leading / trailing .txt ");
    backend
        .delete(&BackendPath::from_rel(space_rel))
        .await
        .unwrap();
}

#[tokio::test]
async fn dropbox_list_non_downloadable_team_headers_and_quota_and_content_hash_integrity() {
    use crate::mock_server::MockEntry;

    let (base_url, state) = spawn_mock_dropbox().await;
    {
        let mut g = state.lock().unwrap();
        g.ensure_parents("/Café/doc.txt");
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/Café/doc.txt"),
            MockEntry {
                id: "id:doc".into(),
                path: "/Café/doc.txt".into(),
                is_folder: false,
                data: b"hello".to_vec(),
                rev: "rev1".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
        g.entries.insert(
            crate::mock_server::MockDropboxState::key("/Café/paper.paper"),
            MockEntry {
                id: "id:paper".into(),
                path: "/Café/paper.paper".into(),
                is_folder: false,
                data: vec![],
                rev: "rev2".into(),
                client_modified: "2026-11-25T02:00:00Z".into(),
            },
        );
        g.non_downloadable_paths
            .insert(crate::mock_server::MockDropboxState::key(
                "/Café/paper.paper",
            ));
        g.team_members_by_email
            .insert("alice@example.com".into(), "dbmid:alice99".into());
        g.space_usage_override = Some(serde_json::json!({
            "used": 100,
            "allocation": {
                ".tag": "team",
                "used": 500,
                "allocated": 1000,
                "user_within_team_space_allocated": 300,
                "user_within_team_space_used_cached": 120
            }
        }));
    }

    let mut cfg = rship_backends::dropbox::DropboxConfig::new("dbx-team")
        .with_root_path("/café")
        .with_root_namespace("ns:777")
        .with_impersonate("alice@example.com");
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
    let auth = Arc::new(rship_transport::oauth::StaticBearerAuth::new(
        "dbx-team",
        "dbx-test-token",
    ));
    let backend = rship_backends::dropbox::DropboxBackend::new(cfg, auth, transport).unwrap();

    // Team quota with per-member cap: user_free = 300 - 120 = 180, team_free = 500 -> 180.
    let quota = backend.about().await.unwrap().unwrap();
    assert_eq!(quota.total_bytes, Some(300));
    assert_eq!(quota.used_bytes, Some(120));
    assert_eq!(quota.free_bytes, Some(180));

    // Also test uncapped team pool (user_within_team_space_allocated == 0).
    state.lock().unwrap().space_usage_override = Some(serde_json::json!({
        "used": 100,
        "allocation": {
            ".tag": "team",
            "used": 500,
            "allocated": 1000,
            "user_within_team_space_allocated": 0
        }
    }));
    let team_quota = backend.about().await.unwrap().unwrap();
    assert_eq!(team_quota.total_bytes, Some(1000));
    assert_eq!(team_quota.used_bytes, Some(500));
    assert_eq!(team_quota.free_bytes, Some(500));

    // Listing under Unicode case-folded root `/café` vs `/Café` excludes non-downloadable Paper.
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].nfc_path.as_str(), "doc.txt");

    // Verify headers: Path-Root on `/files/*`, omitted on `/users/*` and `/team/*`;
    // Select-User resolved to `dbmid:alice99` on `/files/*` and `/users/*`, omitted on `/team/*`.
    {
        let g = state.lock().unwrap();
        assert_eq!(
            g.seen_list_folder_args
                .last()
                .and_then(|v| v.get("include_non_downloadable_files"))
                .and_then(|b| b.as_bool()),
            Some(false)
        );
        let team_req = g
            .seen_headers
            .iter()
            .find(|(p, _, _)| p == "/2/team/members/get_info")
            .unwrap();
        assert_eq!(team_req.1, None);
        assert_eq!(team_req.2, None);

        let users_req = g
            .seen_headers
            .iter()
            .find(|(p, _, _)| p == "/2/users/get_space_usage")
            .unwrap();
        assert_eq!(users_req.1, None);
        assert_eq!(users_req.2.as_deref(), Some("dbmid:alice99"));

        let list_req = g
            .seen_headers
            .iter()
            .find(|(p, _, _)| p == "/2/files/list_folder")
            .unwrap();
        assert!(list_req.1.as_deref().is_some_and(|v| v.contains("777")));
        assert_eq!(list_req.2.as_deref(), Some("dbmid:alice99"));
    }

    // 409 content_hash_mismatch maps to ErrorKind::Integrity!
    state.lock().unwrap().inject_content_hash_mismatch_once = true;
    let init = UploadInit {
        op_id: "op-hash-mismatch".into(),
        dst_path: RelPath::parse("hash_fail.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 0,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let err = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"test"))
            })),
        )
        .await
        .expect_err("409 content_hash_mismatch must fail");
    assert_eq!(err.kind, rship_core::ErrorKind::Integrity);
    assert_eq!(err.retry, rship_core::RetryClass::Integrity);
}

#[tokio::test]
async fn dropbox_shared_folders_tolerates_unmocked_404_and_finish_omits_zero_mtime() {
    let (base_url, state) = spawn_mock_dropbox().await;
    let mut cfg =
        rship_backends::dropbox::DropboxConfig::new("dbx-shared").with_shared_folders(true);
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    cfg.chunk_align_override = Some(64 * 1024);
    cfg.default_chunk_size = 64 * 1024;
    let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
    let auth = Arc::new(rship_transport::oauth::StaticBearerAuth::new(
        "dbx-shared",
        "dbx-test-token",
    ));
    let backend = rship_backends::dropbox::DropboxBackend::new(cfg, auth, transport).unwrap();

    // 1. `shared_folders = true` queries `/2/sharing/list_folders`; 404 on unmocked server
    //    must NOT break `list_stream`.
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(listed.is_empty());
    assert!(
        state
            .lock()
            .unwrap()
            .seen_headers
            .iter()
            .any(|(p, _, _)| p == "/2/sharing/list_folders"),
        "shared_folders = true should query /2/sharing/list_folders"
    );

    // 2. Resumable upload with `mtime_ns <= 0` omits `client_modified` in `upload_session/finish`
    //    and reconciles properly via `reconcile_operation` when rev changes.
    let rel = RelPath::parse("zero_mtime/sess.bin").unwrap();
    let payload = vec![0x42u8; 64 * 1024 + 128];
    let init = UploadInit {
        op_id: "op-zero-mtime".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 0,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-zero".into(),
        job_id: "j-zero".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: rel.as_str().into(),
        dst_raw_path: rel.as_str().into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns: 0,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "dropbox".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let p1 = payload[..64 * 1024].to_vec();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1)) })),
            ),
        )
        .await
        .unwrap();
    let p2 = payload[64 * 1024..].to_vec();
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                64 * 1024,
                128,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .unwrap();
    assert!(ack2.completed.is_some());
    assert!(
        state
            .lock()
            .unwrap()
            .seen_upload_args
            .last()
            .and_then(|v| v.get("commit"))
            .and_then(|c| c.get("client_modified"))
            .is_none(),
        "upload_session/finish must omit client_modified when mtime_ns <= 0"
    );
    let rec = backend.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(rec, rship_core::backend::ReconcileOutcome::Committed(_)),
        "reconcile_operation must succeed when mtime_ns <= 0 and pre-op was Absent: {rec:?}"
    );
}
