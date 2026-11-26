use bytes::Bytes;
use md5::{Digest as _, Md5};
use rship_backends::gdrive::{FOLDER_MIME, GdriveBackend, StaticBearerAuth};
use rship_core::backend::{BackendPath, StorageBackend, UploadInit, UploadProgress};
use rship_core::buffer::BufferPool;
use rship_core::clock::{Clock, SystemClock, VirtualClock};
use rship_core::conformance::run_backend_conformance;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::ByteStream;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{HashKind, NodeId};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::mock_server::{MockFile, MockGdriveServer, read_gdrive_bytes};

// =========================================================================
// Test 1: Universal Backend Conformance Suite (`rship_core::conformance`)
// =========================================================================

#[tokio::test]
async fn gdrive_passes_full_universal_conformance_suite() {
    let srv = MockGdriveServer::start().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(srv.backend("gdrive-conf"));
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    run_backend_conformance(backend, clock).await;
}

// =========================================================================
// Test 4: Resumable 308 (no Range -> 0), Pre-gen ID, PATCH Overwrite (No Dup)
// =========================================================================

#[tokio::test]
async fn gdrive_resumable_308_missing_range_and_patch_overwrite_no_duplicates() {
    let srv = MockGdriveServer::start().await;
    let mut cfg = srv.config("gd-resumable");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = 256 * 1024;

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice", "tok"));
    let gdrive = Arc::new(GdriveBackend::new(cfg, transport, auth, None, None));

    // Verify missing `Range` on 308 immediately after `begin_upload` parses as offset `0`!
    let path = RelPath::parse("big/video.bin").unwrap();
    let total = 256 * 1024 * 2 + 1234;
    let init = UploadInit {
        op_id: "op-308-zero".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = gdrive.begin_upload(&init).await.unwrap();
    let pregen_id = opened
        .remote_op_id
        .clone()
        .expect("must pregenerate fileId");
    assert!(pregen_id.starts_with("pregen-"));

    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "mem://src".into(),
        dst_endpoint: gdrive.endpoint_identity(),
        src_raw_path: path.as_str().into(),
        dst_raw_path: path.as_str().into(),
        dst_nfc_path: path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id.clone(),
        backend_kind: "gdrive".into(),
        session_token: Some(opened.session_token.clone()),
        backend_meta: opened.backend_meta.clone(),
        planned_chunk_size: 256 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Query immediately -> mock returns `308` with NO `Range` header -> MUST be `SequentialOffset(0)`!
    let progress = gdrive.query_upload(&op).await.unwrap();
    assert_eq!(progress, UploadProgress::SequentialOffset(0));
    gdrive.abort_upload(&op).await.unwrap();

    // Now run full Local -> GDrive TransferEngine upload + overwrite!
    let tmp = tempfile::TempDir::new().unwrap();
    let local_dir = tmp.path().join("src");
    std::fs::create_dir_all(local_dir.join("big")).unwrap();
    let v1: Vec<u8> = (0..total as usize).map(|i| (i % 251) as u8).collect();
    std::fs::write(local_dir.join("big/video.bin"), &v1).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", &local_dir).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local.clone(),
        gdrive.clone(),
        state_actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let idx1 = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg1 = EngineConfig::new("job-v1", JobMode::Copy, "local", "gd");
    let rep1 = engine.run(&cfg1, idx1).await.unwrap();
    assert!(rep1.errors.is_empty(), "{:?}", rep1.errors);
    assert_eq!(rep1.files_transferred, 1);
    assert_eq!(read_gdrive_bytes(&gdrive, &path).await, v1);

    let orig_node = gdrive
        .stat(&BackendPath::from_rel(path.clone()))
        .await
        .unwrap()
        .unwrap();
    let orig_id = orig_node.node_id.unwrap().0;

    // Modify file locally (different size + deterministically newer mtime) and re-copy ->
    // MUST use PATCH on `orig_id`!
    let v2: Vec<u8> = (0..(256 * 1024 + 999))
        .map(|i| ((i * 7) % 251) as u8)
        .collect();
    let local_video_path = local_dir.join("big/video.bin");
    let prev_mtime = std::fs::metadata(&local_video_path)
        .unwrap()
        .modified()
        .unwrap();
    std::fs::write(&local_video_path, &v2).unwrap();
    let newer_mtime = prev_mtime.max(std::time::SystemTime::now()) + Duration::from_secs(5);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&local_video_path)
        .unwrap()
        .set_modified(newer_mtime)
        .unwrap();

    let idx2 = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let cfg2 = EngineConfig::new("job-v2", JobMode::Copy, "local", "gd");
    let rep2 = engine.run(&cfg2, idx2).await.unwrap();
    assert!(rep2.errors.is_empty(), "{:?}", rep2.errors);
    assert_eq!(rep2.files_transferred, 1);
    assert_eq!(read_gdrive_bytes(&gdrive, &path).await, v2);

    let updated_node = gdrive
        .stat(&BackendPath::from_rel(path.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_node.node_id.unwrap().0,
        orig_id,
        "overwrite MUST update existing fileId in-place via PATCH"
    );
    let md5_expected = hex::encode(Md5::digest(&v2));
    assert_eq!(
        gdrive
            .compute_hash(&BackendPath::from_rel(path), HashKind::Md5)
            .await
            .unwrap()
            .unwrap()
            .hex,
        md5_expected
    );

    let g = srv.state.lock().unwrap();
    assert_eq!(g.counters.resumable_begin_patch, 1);
    let matching_files: Vec<_> = g.files.values().filter(|f| f.name == "video.bin").collect();
    assert_eq!(
        matching_files.len(),
        1,
        "PATCH overwrite must never create duplicates"
    );
    assert_eq!(pool.stats().in_use_units, 0);
}

// =========================================================================
// Test 9: Concurrent `mkdir` Segmented Lock Prevents Duplicate Folders
// =========================================================================

#[tokio::test]
async fn gdrive_concurrent_mkdir_prevents_duplicate_folders() {
    let srv = MockGdriveServer::start().await;
    let backend = Arc::new(srv.backend("gd-mkdir"));
    let target = RelPath::parse("team/projects/2026").unwrap();

    let mut handles = Vec::new();
    for _ in 0..12 {
        let b = backend.clone();
        let t = target.clone();
        handles.push(tokio::spawn(async move { b.mkdir(&t).await.unwrap() }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let g = srv.state.lock().unwrap();
    assert_eq!(
        g.counters.folder_creates, 3,
        "12 concurrent mkdir calls for 3-level path must create exactly 3 folders total"
    );
}

// =========================================================================
// Test 10: No-Progress 308 Loop Terminates Cleanly (Bounded Retries)
// =========================================================================

#[tokio::test]
async fn gdrive_308_no_progress_loop_aborts_bounded() {
    let srv = MockGdriveServer::start().await;
    srv.state
        .lock()
        .unwrap()
        .faults
        .always_return_308_no_progress = true;

    let mut cfg = srv.config("gd-stuck");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = 256 * 1024;

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice", "tok"));
    let gdrive = Arc::new(GdriveBackend::new(cfg, transport, auth, None, None));

    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("stuck.bin"), vec![0x5Au8; 256 * 1024 + 128]).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        gdrive,
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let ecfg = EngineConfig::new("job-stuck", JobMode::Copy, "local", "gd");
    let report = engine.run(&ecfg, idx).await.unwrap();
    assert_eq!(report.files_transferred, 0);
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("no upload progress")),
        "expected bounded no-progress error, got {:?}",
        report.errors
    );
    let g = srv.state.lock().unwrap();
    assert_eq!(
        g.counters.chunk_put_calls, 3,
        "engine must stop after MAX_NO_PROGRESS_LOOPS (3) consecutive zero-progress 308s"
    );
}

// ---------------------------------------------------------------------------
// Test 13: Zero-Local-Bandwidth Google Drive Server-Side Copy & Move
// ---------------------------------------------------------------------------
#[tokio::test]
async fn gdrive_server_side_copy_and_move_zero_download_bandwidth() {
    let srv = MockGdriveServer::start().await;
    let payload = b"zero-bandwidth-gdrive-server-side-copy-payload!".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "dir_in".into(),
            MockFile {
                id: "dir_in".into(),
                name: "inbox".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "dir_out".into(),
            MockFile {
                id: "dir_out".into(),
                name: "archive".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "f_orig".into(),
            MockFile {
                id: "f_orig".into(),
                name: "report.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["dir_in".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = Arc::new(srv.backend("gd-ssc"));
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        backend.clone(),
        backend.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-gd-move", JobMode::Move, "gd:inbox", "gd:archive");
    cfg.src_prefix = RelPath::parse("inbox").unwrap();
    cfg.dst_prefix = RelPath::parse("archive").unwrap();

    let rep = engine
        .run(&cfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(rep.server_side_copies, 1);
    assert_eq!(rep.sources_deleted, 1);

    {
        let g = srv.state.lock().unwrap();
        assert_eq!(g.counters.copy_calls, 1, "expected POST /files/{{id}}/copy");
        assert_eq!(
            g.counters.multipart_post, 0,
            "must not upload bytes locally"
        );
        assert_eq!(
            g.counters.resumable_begin_post, 0,
            "must not open resumable upload"
        );
    }

    // Source removed, destination has exact bytes!
    assert!(
        backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("inbox/report.bin").unwrap()
            ))
            .await
            .unwrap()
            .is_none()
    );
    let dst_entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("archive/report.bin").unwrap(),
        ))
        .await
        .unwrap()
        .expect("copied file must exist in archive");
    assert_eq!(dst_entry.size, payload.len() as u64);
}

// =========================================================================
// R2: Default `use_trash_on_delete = true` vs explicit `false`
// =========================================================================

#[tokio::test]
async fn gdrive_default_delete_moves_to_trash_and_false_permanently_deletes() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "f_trash".into(),
            MockFile {
                id: "f_trash".into(),
                name: "to_trash.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"trash-me".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "f_perm".into(),
            MockFile {
                id: "f_perm".into(),
                name: "to_delete.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"delete-me".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let default_backend = srv.backend("gd-trash-default");
    assert!(default_backend.config().use_trash_on_delete);
    default_backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("to_trash.txt").unwrap(),
        ))
        .await
        .unwrap();
    assert!(
        default_backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("to_trash.txt").unwrap()
            ))
            .await
            .unwrap()
            .is_none()
    );
    {
        let g = srv.state.lock().unwrap();
        assert!(
            g.files.get("f_trash").is_some_and(|f| f.trashed),
            "default delete must trash via PATCH trashed=true"
        );
    }

    let perm_cfg = srv.config("gd-perm").with_use_trash_on_delete(false);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("test-user", "test-token"));
    let perm_backend = GdriveBackend::new(perm_cfg, transport, auth, None, None);
    perm_backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("to_delete.txt").unwrap(),
        ))
        .await
        .unwrap();
    assert!(
        !srv.state.lock().unwrap().files.contains_key("f_perm"),
        "use_trash_on_delete=false must permanently DELETE"
    );
}

// =========================================================================
// P1: Cross-Drive `server_side_copy` + Cross-Root `node_id == None` Guard
// =========================================================================

#[tokio::test]
async fn gdrive_cross_drive_server_side_copy_and_cross_root_none_node_id_fallback() {
    let srv = MockGdriveServer::start().await;
    let payload = b"cross-drive-copy-payload".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "my_src".into(),
            MockFile {
                id: "my_src".into(),
                name: "cross.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));

    let my_drive = GdriveBackend::new(
        srv.config("my"),
        transport.clone(),
        auth.clone(),
        None,
        None,
    );
    let shared_drive = GdriveBackend::new(
        srv.config("shared").with_shared_drive_id("0ASharedDriveA"),
        transport.clone(),
        auth.clone(),
        None,
        None,
    );
    let other_user = GdriveBackend::new(
        srv.config("bob").with_shared_drive_id("0ASharedDriveA"),
        transport,
        Arc::new(StaticBearerAuth::new("bob@example.com", "tok")),
        None,
        None,
    );

    assert!(shared_drive.can_server_side_copy_from(&my_drive.endpoint_identity()));
    assert!(!other_user.can_server_side_copy_from(&my_drive.endpoint_identity()));

    let init = UploadInit {
        op_id: "op-cross-drive".into(),
        dst_path: RelPath::parse("copied_from_my_drive.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };

    // With `src_path.node_id = Some(...)`, cross-drive copy succeeds via `files.copy`!
    let copied = shared_drive
        .server_side_copy(
            &my_drive.endpoint_identity(),
            &BackendPath::new(
                "cross.bin",
                RelPath::parse("cross.bin").unwrap(),
                Some(NodeId("my_src".into())),
            ),
            &init,
        )
        .await
        .unwrap()
        .expect("same-principal cross-drive copy must succeed");
    assert_eq!(copied.size, payload.len() as u64);
    assert_eq!(srv.state.lock().unwrap().counters.copy_calls, 1);

    // With `src_path.node_id = None` across different roots/drives, MUST return `Ok(None)`
    // (never resolve `src_path.nfc_path` inside `dst`'s root!).
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "shadow_in_shared".into(),
            MockFile {
                id: "shadow_in_shared".into(),
                name: "cross.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["0ASharedDriveA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"wrong-file-in-dst-root".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }
    let fallback = shared_drive
        .server_side_copy(
            &my_drive.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("cross.bin").unwrap()),
            &UploadInit {
                op_id: "op-cross-none".into(),
                dst_path: RelPath::parse("should_not_copy_shadow.bin").unwrap(),
                ..init
            },
        )
        .await
        .unwrap();
    assert!(
        fallback.is_none(),
        "cross-root copy without src_path.node_id must fall back to streaming copy"
    );
    assert_eq!(srv.state.lock().unwrap().counters.copy_calls, 1);
}

// =========================================================================
// P1 + P2: Same-Name Folder+File Overwrite & `files.generateIds` Pooling
// =========================================================================

#[tokio::test]
async fn gdrive_same_name_folder_and_file_overwrite_and_generate_ids_pooling() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        // Insert folder `"dup"` BEFORE regular file `"dup"` in `files`!
        g.files.insert(
            "a_dir_dup".into(),
            MockFile {
                id: "a_dir_dup".into(),
                name: "dup".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "z_file_dup".into(),
            MockFile {
                id: "z_file_dup".into(),
                name: "dup".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"old".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-dup-pool");
    let new_data = b"updated-regular-file".to_vec();
    let init = UploadInit {
        op_id: "op-dup-ow".into(),
        dst_path: RelPath::parse("dup").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: new_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: new_data.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let body: ByteStream = Box::pin(futures::stream::once(
        async move { Ok(Bytes::from(new_data)) },
    ));
    let entry = backend.put_single_shot(&init, body).await.unwrap();
    assert_eq!(
        entry.node_id.as_ref().map(|n| n.as_str()),
        Some("z_file_dup"),
        "must PATCH existing regular file instead of creating duplicate alongside folder"
    );

    // 10 consecutive creates consume at most 1 `files.generateIds?count=100` RPC!
    let gen_before = srv.state.lock().unwrap().counters.generate_ids;
    for i in 0..10 {
        let p = RelPath::parse(&format!("pooled/file-{i}.bin")).unwrap();
        let data = vec![i as u8; 8];
        let body: ByteStream =
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(data)) }));
        backend
            .put_single_shot(
                &UploadInit {
                    op_id: format!("op-pool-{i}"),
                    dst_path: p,
                    existing_node_id: None,
                    pregenerated_id: None,
                    total_size: 8,
                    src_mtime_ns: 1_700_000_000_000_000_000,
                    planned_chunk_size: 8,
                    checksums: vec![],
                    precondition: DstPrecondition::Absent,
                    src_etag: None,
                },
                body,
            )
            .await
            .unwrap();
    }
    let gen_calls = srv.state.lock().unwrap().counters.generate_ids - gen_before;
    assert_eq!(
        gen_calls, 1,
        "expected 10 creates to pool 1 generateIds RPC"
    );
}
