//! Comprehensive `axum` mock conformance tests covering all P0, P1, and P2 OneDrive
//! remediation items in `M3.2_onedrive`.

use crate::common::InjectedFault;
use crate::mock_server::{MockItem, MockMonitorMode, start_mock_graph};
use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use rship_backends::onedrive::{
    MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveBackend, OnedriveConfig,
    OnedriveDriveType,
};
use rship_core::ErrorKind;
use rship_core::backend::{
    BackendPath, ChunkUpload, ListOptions, StorageBackend, UploadInit, UploadProgress,
};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, Checksum, EntryKind, HashKind, NodeId};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn make_backend(base_url: &str, name: &str) -> Arc<OnedriveBackend> {
    make_backend_with_cfg(
        base_url,
        OnedriveConfig::new(name),
        TransportConfig::default(),
    )
}

fn make_backend_with_cfg(
    base_url: &str,
    mut cfg: OnedriveConfig,
    transport_cfg: TransportConfig,
) -> Arc<OnedriveBackend> {
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.token_url = format!("{base_url}/oauth2/v2.0/token");
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(25);
    cfg.max_retries = 3;
    let transport = HttpTransport::new(transport_cfg).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od"));
    Arc::new(OnedriveBackend::new(cfg, auth, transport).unwrap())
}

fn session_op(
    backend: &OnedriveBackend,
    init: &UploadInit,
    sess: rship_core::backend::UploadSessionInit,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sk-{}", init.op_id),
        job_id: "j-p0p1".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: init.dst_path.as_str().into(),
        dst_raw_path: init.dst_path.as_str().into(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: init.precondition.clone(),
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "onedrive".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: sess.expires_at_unix_secs,
    }
}

async fn read_all(backend: &OnedriveBackend, path: &BackendPath) -> Vec<u8> {
    let ds = backend.open_read(path, None).await.unwrap();
    let DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut s = rr
        .open_range(ByteRange {
            offset: 0,
            len: rr.total_len(),
        })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(chunk) = s.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    out
}

#[tokio::test]
async fn onedrive_server_side_copy_sends_drive_id_handles_303_and_patches_mtime() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.require_sec_precision_z = true;
        g.items_by_path.insert(
            "src.bin".into(),
            MockItem {
                id: "src-1".into(),
                path: "src.bin".into(),
                is_folder: false,
                data: b"server-copy-payload".to_vec(),
                last_modified: "2020-01-01T00:00:00Z".into(),
            },
        );
        g.next_monitor_mode = Some(MockMonitorMode::InProgressThenSeeOther {
            remaining_in_progress: 3,
        });
    }
    let backend = make_backend(&base_url, "od-copy-303");
    let src_mtime_ns = 1_700_000_000_987_654_321i64; // truncates to 2023-11-14T22:13:20Z
    let init = UploadInit {
        op_id: "op-copy-303".into(),
        dst_path: RelPath::parse("copied/dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 19,
        src_mtime_ns,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.bin").unwrap()),
            &init,
        )
        .await
        .unwrap()
        .expect("server_side_copy must succeed across 3x inProgress + 303 See Other");

    assert_eq!(entry.size, 19);
    assert_eq!(entry.mtime_ns / 1_000_000_000, 1_700_000_000);
    let g = state.lock().unwrap();
    assert_eq!(
        g.captured_copy_drive_ids,
        vec![Some("drive-1".to_string())],
        "POST /items/{{id}}/copy must include parentReference.driveId"
    );
    assert_eq!(
        g.items_by_path["copied/dst.bin"].last_modified,
        "2023-11-14T22:13:20Z"
    );
}

#[tokio::test]
async fn onedrive_server_side_copy_survives_slow_monitor_and_handles_delete_failed() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            "src.bin".into(),
            MockItem {
                id: "src-slow".into(),
                path: "src.bin".into(),
                is_folder: false,
                data: b"slow-monitor-data".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.retry_after_zero_on_in_progress = true;
        // >60 polls (65x inProgress) must complete instead of hitting a 60-poll cap.
        g.next_monitor_mode = Some(MockMonitorMode::InProgressThenCompleted {
            remaining_in_progress: 65,
        });
    }
    let backend = make_backend(&base_url, "od-copy-slow");
    let ep = backend.endpoint_identity();
    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap());

    let entry = backend
        .server_side_copy(
            &ep,
            &src_bp,
            &UploadInit {
                op_id: "op-copy-65".into(),
                dst_path: RelPath::parse("dst-65.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 17,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("copy monitor with >60 polls must complete");
    assert_eq!(entry.size, 17);

    // `deleteFailed` must exit immediately with Ok(None) (never spin).
    state.lock().unwrap().next_monitor_mode = Some(MockMonitorMode::DeleteFailed);
    let res = backend
        .server_side_copy(
            &ep,
            &src_bp,
            &UploadInit {
                op_id: "op-copy-df".into(),
                dst_path: RelPath::parse("dst-df.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 17,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap();
    assert!(res.is_none(), "deleteFailed must stop polling immediately");

    // Always-inProgress monitor exceeding `long_control_timeout` must return Timeout (not Ok(None)).
    state.lock().unwrap().next_monitor_mode = Some(MockMonitorMode::AlwaysInProgress);
    let short_timeout_backend = make_backend_with_cfg(
        &base_url,
        OnedriveConfig::new("od-copy-timeout"),
        TransportConfig::default().with_long_control_timeout(Duration::from_millis(150)),
    );
    let err = short_timeout_backend
        .server_side_copy(
            &short_timeout_backend.endpoint_identity(),
            &src_bp,
            &UploadInit {
                op_id: "op-copy-to".into(),
                dst_path: RelPath::parse("dst-timeout.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 17,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .expect_err("timed-out copy monitor must return Timeout");
    assert_eq!(err.kind, ErrorKind::Timeout);
}

#[tokio::test]
async fn onedrive_range_reader_uses_download_url_without_auth_and_refreshes_on_expiry() {
    let (base_url, state) = start_mock_graph().await;
    let payload = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    {
        let mut g = state.lock().unwrap();
        g.valid_token = Some("tok-od".into());
        g.items_by_path.insert(
            "dl.bin".into(),
            MockItem {
                id: "od-dl-1".into(),
                path: "dl.bin".into(),
                is_folder: false,
                data: payload.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
    }
    let backend = make_backend(&base_url, "od-dl");
    let ds = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("dl.bin").unwrap()),
            None,
        )
        .await
        .unwrap();
    let DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };

    // Range read 1: hits `/download/od-dl-1` (which rejects any Authorization header with 401).
    let mut s1 = rr
        .open_range(ByteRange { offset: 0, len: 10 })
        .await
        .unwrap();
    let mut b1 = Vec::new();
    while let Some(c) = s1.next().await {
        b1.extend_from_slice(&c.unwrap());
    }
    assert_eq!(b1, &payload[..10]);
    assert_eq!(state.lock().unwrap().download_url_calls, 1);

    // Expire downloadUrl version on server -> next range read receives 410, refreshes via stat,
    // and succeeds with the refreshed downloadUrl!
    state.lock().unwrap().download_url_version = 2;
    let mut s2 = rr
        .open_range(ByteRange {
            offset: 10,
            len: 20,
        })
        .await
        .unwrap();
    let mut b2 = Vec::new();
    while let Some(c) = s2.next().await {
        b2.extend_from_slice(&c.unwrap());
    }
    assert_eq!(b2, &payload[10..30]);
    assert_eq!(state.lock().unwrap().download_url_calls, 3);

    // When `@microsoft.graph.downloadUrl` is omitted, reader falls back cleanly to `/content`
    // with Authorization header.
    state.lock().unwrap().omit_download_url = true;
    let got_fallback = read_all(
        &backend,
        &BackendPath::from_rel(RelPath::parse("dl.bin").unwrap()),
    )
    .await;
    assert_eq!(got_fallback, payload);
}

#[tokio::test]
async fn onedrive_sends_second_precision_z_last_modified_on_put_session_and_copy() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().require_sec_precision_z = true;
    let backend = make_backend(&base_url, "od-sec-z");
    let subsec_mtime_ns = 1_700_000_000_987_654_321i64;

    // 1. Single-shot PUT + PATCH(mtime)
    let p_single = RelPath::parse("z/single.bin").unwrap();
    let e_single = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-z-single".into(),
                dst_path: p_single.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 5,
                src_mtime_ns: subsec_mtime_ns,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .unwrap();
    assert_eq!(e_single.mtime_ns, 1_700_000_000_000_000_000);

    // 2. Resumable session `createUploadSession`
    let p_sess = RelPath::parse("z/sess.bin").unwrap();
    let sess_init = UploadInit {
        op_id: "op-z-sess".into(),
        dst_path: p_sess.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 6,
        src_mtime_ns: subsec_mtime_ns,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&sess_init).await.unwrap();
    let op = session_op(&backend, &sess_init, sess);
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                6,
                6,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"abcdef"))
                })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack.completed.unwrap().mtime_ns, 1_700_000_000_000_000_000);

    // 3. Server-side copy `PATCH(mtime)`
    let e_copy = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(p_single),
            &UploadInit {
                op_id: "op-z-copy".into(),
                dst_path: RelPath::parse("z/copy.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 5,
                src_mtime_ns: subsec_mtime_ns,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e_copy.mtime_ns, 1_700_000_000_000_000_000);
}

#[tokio::test]
async fn onedrive_416_fragment_overlap_queries_session_and_resumes_upload() {
    let (base_url, state) = start_mock_graph().await;
    let align = ONEDRIVE_CHUNK_ALIGN_BYTES as usize;
    let payload: Vec<u8> = (0..(align + 4096))
        .map(|i| ((i * 13) % 251) as u8)
        .collect();

    // (a) Direct upload_chunk 416 -> retryable -> query_upload reports advanced offset.
    let backend = make_backend(&base_url, "od-416");
    let dst_a = RelPath::parse("overlap/a.bin").unwrap();
    let init_a = UploadInit {
        op_id: "op-416-a".into(),
        dst_path: dst_a.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init_a).await.unwrap();
    let op = session_op(&backend, &init_a, sess);
    state.lock().unwrap().fragment_overlap_once = Some(align);
    let c1 = payload[..align].to_vec();
    let err = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                align as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c1)) })),
            ),
        )
        .await
        .expect_err("416 fragmentOverlap must return retryable error");
    assert!(
        err.is_retryable(),
        "416 on upload session must be retryable"
    );
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(ONEDRIVE_CHUNK_ALIGN_BYTES)
    );
    let c2 = payload[align..].to_vec();
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                ONEDRIVE_CHUNK_ALIGN_BYTES,
                c2.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c2)) })),
            ),
        )
        .await
        .unwrap();
    assert!(ack2.completed.is_some());

    // (b) Full TransferEngine upload recovering from 416 fragmentOverlap via query_upload.
    let (src_url, src_state) = start_mock_graph().await;
    src_state.lock().unwrap().items_by_path.insert(
        "src_overlap.bin".into(),
        MockItem {
            id: "src-ov-1".into(),
            path: "src_overlap.bin".into(),
            is_folder: false,
            data: payload.clone(),
            last_modified: "2023-11-14T22:13:20Z".into(),
        },
    );
    let src_backend = make_backend(&src_url, "od-src-ov");
    let mut dst_cfg = OnedriveConfig::new("od-dst-ov");
    dst_cfg.single_shot_max_bytes = 64 * 1024;
    dst_cfg.default_chunk_size = ONEDRIVE_CHUNK_ALIGN_BYTES;
    let dst_backend = make_backend_with_cfg(&base_url, dst_cfg, TransportConfig::default());
    state.lock().unwrap().fragment_overlap_once = Some(align);

    let engine = TransferEngine::new(
        src_backend,
        dst_backend.clone(),
        Arc::new(StateActor::open_in_memory().unwrap()),
        BufferPool::new(1024 * 1024, 512 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-416", JobMode::Copy, "od-src-ov", "od-dst-ov");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(
        state.lock().unwrap().items_by_path["src_overlap.bin"].data,
        payload
    );
}

#[tokio::test]
async fn onedrive_query_upload_empty_ranges_requires_pre_op_proof() {
    let (base_url, state) = start_mock_graph().await;
    let backend = make_backend(&base_url, "od-empty-ranges");
    let path = RelPath::parse("proof/f.bin").unwrap();
    let payload = b"pre-existing-content".to_vec();
    let mtime = 1_700_000_000_000_000_000i64;

    backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-seed-proof".into(),
                dst_path: path.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: payload.len() as u64,
                src_mtime_ns: mtime,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from(b"pre-existing-content".to_vec()))
            })),
        )
        .await
        .unwrap();

    // Begin new upload over the existing file (captures old eTag in PreOpState).
    let init = UploadInit {
        op_id: "op-new-proof".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: mtime,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = session_op(&backend, &init, sess);

    // Server returns empty `nextExpectedRanges` WITHOUT having committed the new upload!
    state
        .lock()
        .unwrap()
        .force_empty_next_expected_ranges_on_status = true;
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::Expired,
        "empty nextExpectedRanges must NOT return AlreadyCompleted for pre-existing item with old eTag"
    );

    // Now actually commit the session (bumps eTag) -> empty nextExpectedRanges returns AlreadyCompleted!
    state
        .lock()
        .unwrap()
        .force_empty_next_expected_ranges_on_status = false;
    let p2 = payload.clone();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                p2.len() as u64,
                p2.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .unwrap();
    state
        .lock()
        .unwrap()
        .force_empty_next_expected_ranges_on_status = true;
    state.lock().unwrap().sessions.insert(
        op.session_token
            .as_deref()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string(),
        crate::mock_server::MockUploadSess {
            dst_path: "proof/f.bin".into(),
            buf: Vec::new(),
            last_modified: "2023-11-14T22:13:20Z".into(),
        },
    );
    assert!(matches!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::AlreadyCompleted(_)
    ));
}

#[tokio::test]
async fn onedrive_ensure_dir_chain_rejects_regular_file_at_parent_segment() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            "a".into(),
            MockItem {
                id: "dir-a".into(),
                path: "a".into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.items_by_path.insert(
            "a/b".into(),
            MockItem {
                id: "file-ab".into(),
                path: "a/b".into(),
                is_folder: false,
                data: b"i am a file".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
    }
    let backend = make_backend(&base_url, "od-dir-conflict");
    let err_mkdir = backend
        .mkdir(&RelPath::parse("a/b/c").unwrap())
        .await
        .expect_err("mkdir under a regular file must fail");
    assert_eq!(err_mkdir.kind, ErrorKind::Conflict);
    assert!(!err_mkdir.is_retryable());

    let err_put = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-put-under-file".into(),
                dst_path: RelPath::parse("a/b/c/file.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 3,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abc"))
            })),
        )
        .await
        .expect_err("put_single_shot under a regular file must fail");
    assert_eq!(err_put.kind, ErrorKind::Conflict);
}

#[tokio::test]
async fn onedrive_list_with_options_honors_max_depth_zero_one_two() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        for (id, path, is_folder) in [
            ("f1", "a.txt", false),
            ("d1", "sub", true),
            ("f2", "sub/b.txt", false),
            ("d2", "sub/deep", true),
            ("f3", "sub/deep/c.txt", false),
        ] {
            g.items_by_path.insert(
                path.into(),
                MockItem {
                    id: id.into(),
                    path: path.into(),
                    is_folder,
                    data: if is_folder { vec![] } else { b"x".to_vec() },
                    last_modified: "2023-11-14T22:13:20Z".into(),
                },
            );
        }
    }
    let backend = make_backend(&base_url, "od-depth");
    let collect_paths = |opts: ListOptions| {
        let b = backend.clone();
        async move {
            let mut s = b.list_with_options(&RelPath::root(), &opts).await.unwrap();
            let mut out = Vec::new();
            while let Some(e) = s.next().await {
                out.push(e.unwrap().nfc_path.as_str().to_string());
            }
            out.sort();
            out
        }
    };

    assert_eq!(
        collect_paths(ListOptions::new().with_max_depth(0)).await,
        Vec::<String>::new()
    );
    assert_eq!(
        collect_paths(ListOptions::new().with_max_depth(0).with_recursive(true)).await,
        Vec::<String>::new()
    );
    assert_eq!(
        collect_paths(ListOptions::new().with_recursive(false)).await,
        vec!["a.txt", "sub"]
    );
    assert_eq!(
        collect_paths(ListOptions::shallow().with_max_depth(2)).await,
        vec!["a.txt", "sub", "sub/b.txt", "sub/deep"]
    );
}

#[tokio::test]
async fn onedrive_bfs_listing_uses_item_id_top_999_streaming_and_preserves_nfd() {
    let (base_url, state) = start_mock_graph().await;
    let nfd_dir = "cafe\u{0301}";
    let nfd_sub = "cafe\u{0301}/re\u{0301}sume\u{0301}";
    let nfd_file = "cafe\u{0301}/re\u{0301}sume\u{0301}/file.txt";
    let payload = b"nfd-onedrive-content".to_vec();
    {
        let mut g = state.lock().unwrap();
        g.list_page_size = Some(1);
        g.items_by_path.insert(
            nfd_dir.into(),
            MockItem {
                id: "nfd-dir-id".into(),
                path: nfd_dir.into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.items_by_path.insert(
            nfd_sub.into(),
            MockItem {
                id: "nfd-sub-id".into(),
                path: nfd_sub.into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.items_by_path.insert(
            nfd_file.into(),
            MockItem {
                id: "nfd-file-id".into(),
                path: nfd_file.into(),
                is_folder: false,
                data: payload.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
    }

    let backend = make_backend(&base_url, "od-nfd");
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut entries = Vec::new();
    while let Some(item) = s.next().await {
        entries.push(item.unwrap());
    }
    let file_entry = entries
        .iter()
        .find(|e| e.kind == EntryKind::File)
        .expect("file entry");
    assert_eq!(file_entry.raw_path(), nfd_file);

    let urls = state.lock().unwrap().observed_list_urls.clone();
    assert!(
        urls.iter()
            .any(|u| u == "/v1.0/me/drive/root/children?$top=999"),
        "root list must request /root/children?$top=999, got {urls:?}"
    );
    assert!(
        urls.iter()
            .any(|u| u == "/v1.0/me/drive/items/nfd-dir-id/children?$top=999")
            && urls
                .iter()
                .any(|u| u == "/v1.0/me/drive/items/nfd-sub-id/children?$top=999"),
        "subdirs must request /items/{{id}}/children?$top=999, got {urls:?}"
    );

    // Read & delete using raw NFD path without node_id!
    let bp_no_id = BackendPath::new(file_entry.raw_path(), file_entry.nfc_path.clone(), None);
    assert_eq!(read_all(&backend, &bp_no_id).await, payload);
    backend.delete(&bp_no_id).await.unwrap();
    assert!(backend.stat(&bp_no_id).await.unwrap().is_none());
}

#[tokio::test]
async fn onedrive_skips_package_and_traverses_remote_item_mounted_folder() {
    let (base_url, state) = start_mock_graph().await;
    let shared_bytes = b"shared-drive-file".to_vec();
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            "notes.one".into(),
            MockItem {
                id: "pkg-1".into(),
                path: "notes.one".into(),
                is_folder: false,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.package_paths.insert("notes.one".into());

        g.items_by_path.insert(
            "shared".into(),
            MockItem {
                id: "mount-1".into(),
                path: "shared".into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.remote_items
            .insert("shared".into(), ("drv-shared".into(), "rm-dir".into()));

        let mut remote_map = BTreeMap::new();
        remote_map.insert(
            String::new(),
            MockItem {
                id: "rm-dir".into(),
                path: String::new(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        remote_map.insert(
            "shared.txt".into(),
            MockItem {
                id: "rm-file-1".into(),
                path: "shared.txt".into(),
                is_folder: false,
                data: shared_bytes.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.remote_drives.insert("drv-shared".into(), remote_map);
    }

    let backend = make_backend(&base_url, "od-facets");
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut listed = Vec::new();
    while let Some(e) = s.next().await {
        listed.push(e.unwrap());
    }
    assert!(
        !listed.iter().any(|e| e.nfc_path.as_str() == "notes.one"),
        "OneNote package must be skipped from listing"
    );
    let shared_dir = listed
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared")
        .expect("mounted remoteItem folder");
    assert_eq!(shared_dir.kind, EntryKind::Directory);
    let shared_file = listed
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared/shared.txt")
        .expect("file inside remoteItem mounted folder");
    assert_eq!(shared_file.size, shared_bytes.len() as u64);

    let err_pkg = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("notes.one").unwrap()),
            None,
        )
        .await
        .err()
        .expect("open_read on OneNote package must fail");
    assert_eq!(err_pkg.kind, ErrorKind::Unsupported);

    let urls = state.lock().unwrap().observed_list_urls.clone();
    assert!(
        urls.iter()
            .any(|u| u == "/v1.0/drives/drv-shared/items/rm-dir/children?$top=999"),
        "remoteItem traversal must hit /drives/{{driveId}}/items/{{id}}/children?$top=999, got {urls:?}"
    );
}

#[tokio::test]
async fn onedrive_business_reconcile_verifies_quickxor_when_sha_absent() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.business_hashes_only = true;
        g.items_by_path.insert(
            "src.bin".into(),
            MockItem {
                id: "biz-src".into(),
                path: "src.bin".into(),
                is_folder: false,
                data: b"business-payload-1".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
    }
    let cfg = OnedriveConfig::new("od-biz").with_drive_type(OnedriveDriveType::Business);
    let backend = make_backend_with_cfg(&base_url, cfg, TransportConfig::default());
    assert!(backend.capabilities().hashes.is_empty());

    let faults = state.lock().unwrap().fault_injector();
    faults.push("items.copy", InjectedFault::commit_then_reset());
    // 1. `stat(dst)` pre-snapshot -> None, 2. `stat(dst)` reconcile -> lagging 404 -> replay gets 409 and reconciles via quickXorHash!
    let noop = || InjectedFault::slow_finalize(Duration::ZERO);
    let lag = || {
        InjectedFault::json_error(
            StatusCode::NOT_FOUND,
            r#"{"error":{"code":"itemNotFound","message":"lag"}}"#,
        )
    };
    faults.push_many("items.get", [noop(), noop(), lag()]);

    let src = BackendPath::new(
        "src.bin",
        RelPath::parse("src.bin").unwrap(),
        Some(NodeId("biz-src".into())),
    );
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &src,
            &UploadInit {
                op_id: "op-biz-copy".into(),
                dst_path: RelPath::parse("dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 18,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("business reconcile with matching quickXorHash must resolve");
    assert_eq!(copied.size, 18);

    // Mismatched quickXorHash at destination with same size must fail reconcile (fallback Ok(None)).
    state.lock().unwrap().items_by_path.insert(
        "dst-mismatch.bin".into(),
        MockItem {
            id: "biz-diff".into(),
            path: "dst-mismatch.bin".into(),
            is_folder: false,
            data: b"DIFFERENT-PAYLOAD!".to_vec(), // exact same 18 bytes!
            last_modified: "2023-11-14T22:13:20Z".into(),
        },
    );
    let fallback = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &src,
            &UploadInit {
                op_id: "op-biz-diff".into(),
                dst_path: RelPath::parse("dst-mismatch.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 18,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap();
    assert!(
        fallback.is_none(),
        "409 conflict with mismatched quickXorHash must NOT falsely reconcile"
    );
}

#[tokio::test]
async fn onedrive_http_423_locked_retries_and_recovers() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().items_by_path.insert(
        "locked.txt".into(),
        MockItem {
            id: "lock-1".into(),
            path: "locked.txt".into(),
            is_folder: false,
            data: b"locked-body".to_vec(),
            last_modified: "2023-11-14T22:13:20Z".into(),
        },
    );
    let faults = state.lock().unwrap().fault_injector();
    faults.push(
        "items.get",
        InjectedFault::HttpStatus {
            status: StatusCode::LOCKED,
            retry_after: None,
            content_type: "application/json",
            body: r#"{"error":{"code":"resourceLocked"}}"#.into(),
        },
    );
    faults.push(
        "items.patch",
        InjectedFault::HttpStatus {
            status: StatusCode::LOCKED,
            retry_after: None,
            content_type: "application/json",
            body: r#"{"error":{"code":"resourceLocked"}}"#.into(),
        },
    );

    let backend = make_backend(&base_url, "od-423");
    let bp = BackendPath::from_rel(RelPath::parse("locked.txt").unwrap());
    let entry = backend.stat(&bp).await.unwrap().unwrap();
    assert_eq!(entry.size, 11);

    let renamed = backend.rename(&bp, "unlocked.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "unlocked.txt");
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn onedrive_upload_chunk_202_already_completed_and_60mib_guard_and_sha256() {
    let (base_url, state) = start_mock_graph().await;
    let backend = make_backend(&base_url, "od-chunk-fixes");

    // (a) > 60 MiB chunk rejected before any HTTP call.
    let dummy_op = OperationRecord {
        op_id: "op-60mib".into(),
        session_key: "sk-60".into(),
        job_id: "j-60".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "big.bin".into(),
        dst_raw_path: "big.bin".into(),
        dst_nfc_path: RelPath::parse("big.bin").unwrap(),
        src_version: SourceVersion {
            node_id: None,
            size: MAX_ONEDRIVE_CHUNK_BYTES + 1,
            mtime_ns: 0,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "onedrive".into(),
        session_token: Some(format!("{base_url}/upload/fake")),
        backend_meta: String::new(),
        planned_chunk_size: MAX_ONEDRIVE_CHUNK_BYTES,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };
    let err_60 = backend
        .upload_chunk(
            &dummy_op,
            ChunkUpload::new(
                1,
                0,
                MAX_ONEDRIVE_CHUNK_BYTES + 1,
                MAX_ONEDRIVE_CHUNK_BYTES + 1,
                Box::pin(futures::stream::empty()),
            ),
        )
        .await
        .expect_err("chunk > 60 MiB must be rejected");
    assert_eq!(err_60.kind, ErrorKind::InvalidGeometry);

    // (b) 202 without nextExpectedRanges where query_upload proves AlreadyCompleted via PreOpState.
    let payload = vec![0x42u8; (ONEDRIVE_CHUNK_ALIGN_BYTES + 1024) as usize];
    let p_202 = RelPath::parse("chunk202/f.bin").unwrap();
    let init_202 = UploadInit {
        op_id: "op-202-ac".into(),
        dst_path: p_202.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess_202 = backend.begin_upload(&init_202).await.unwrap();
    let op_202 = session_op(&backend, &init_202, sess_202);
    // Simulate server already committed the file and returns empty nextExpectedRanges on status
    // while omitting ranges on 202.
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            p_202.as_str().into(),
            MockItem {
                id: "committed-202".into(),
                path: p_202.as_str().into(),
                is_folder: false,
                data: payload.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.bump_etag("committed-202");
        g.omit_next_expected_ranges = Some(crate::mock_server::OmitRanges {
            drop_fragment: true,
        });
        g.force_empty_next_expected_ranges_on_status = true;
    }
    let head = payload[..ONEDRIVE_CHUNK_ALIGN_BYTES as usize].to_vec();
    let ack_202 = backend
        .upload_chunk(
            &op_202,
            ChunkUpload::new(
                1,
                0,
                ONEDRIVE_CHUNK_ALIGN_BYTES,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(head)) })),
            ),
        )
        .await
        .expect("202 + AlreadyCompleted must succeed cleanly");
    assert!(ack_202.completed.is_some());
    state
        .lock()
        .unwrap()
        .force_empty_next_expected_ranges_on_status = false;

    // (c) Upload session with mismatched `init.checksums` SHA-256 fails with ErrorKind::Integrity.
    let p_sha = RelPath::parse("sha/bad.bin").unwrap();
    let init_sha = UploadInit {
        op_id: "op-sess-sha-bad".into(),
        dst_path: p_sha,
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![Checksum {
            kind: HashKind::Sha256,
            hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess_sha = backend.begin_upload(&init_sha).await.unwrap();
    let op_sha = session_op(&backend, &init_sha, sess_sha);
    let err_sha = backend
        .upload_chunk(
            &op_sha,
            ChunkUpload::new(
                1,
                0,
                16,
                16,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"0123456789abcdef"))
                })),
            ),
        )
        .await
        .expect_err("session with mismatched init.checksums SHA-256 must fail Integrity");
    assert_eq!(err_sha.kind, ErrorKind::Integrity);

    // (d) Malformed PATCH(mtime) response logs warning and still returns entry cleanly.
    state.lock().unwrap().malformed_patch_once = true;
    let entry_malformed = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-malformed-patch".into(),
                dst_path: RelPath::parse("malformed.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 4,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"test"))
            })),
        )
        .await
        .expect("malformed PATCH(mtime) body must warn without failing upload");
    assert_eq!(entry_malformed.size, 4);
}

#[tokio::test]
async fn onedrive_rename_renames_file_and_nfd_parent_item() {
    let (base_url, state) = start_mock_graph().await;
    let nfd_parent = "cafe\u{0301}";
    let nfd_old = "cafe\u{0301}/old.txt";
    let nfd_new = "cafe\u{0301}/new.txt";
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            nfd_parent.into(),
            MockItem {
                id: "dir-nfd".into(),
                path: nfd_parent.into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.items_by_path.insert(
            nfd_old.into(),
            MockItem {
                id: "file-nfd".into(),
                path: nfd_old.into(),
                is_folder: false,
                data: b"hello-rename".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
    }
    let backend = make_backend(&base_url, "od-rename");
    let old_bp = BackendPath::new(nfd_old, RelPath::parse(nfd_old).unwrap(), None);

    let renamed = backend.rename(&old_bp, "new.txt").await.unwrap();
    assert_eq!(renamed.raw_path(), nfd_new);
    assert_eq!(renamed.nfc_path, RelPath::parse(nfd_new).unwrap());
    assert!(backend.stat(&old_bp).await.unwrap().is_none());
    let new_bp = BackendPath::new(
        renamed.raw_path(),
        renamed.nfc_path.clone(),
        renamed.node_id.clone(),
    );
    assert_eq!(read_all(&backend, &new_bp).await, b"hello-rename");

    // Same-name rename must not lose data.
    let same = backend.rename(&new_bp, "new.txt").await.unwrap();
    assert_eq!(same.size, 12);
    assert_eq!(read_all(&backend, &new_bp).await, b"hello-rename");

    // Invalid targets & root must return InvalidPath.
    for bad in ["", ".", "..", "a/b", "a\\b"] {
        assert_eq!(
            backend.rename(&new_bp, bad).await.unwrap_err().kind,
            ErrorKind::InvalidPath,
            "bad target={bad:?}"
        );
    }
    assert_eq!(
        backend
            .rename(&BackendPath::from_rel(RelPath::root()), "x")
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidPath
    );
}

#[tokio::test]
async fn onedrive_about_handles_negative_over_quota_remaining() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().quota_override = Some((1000, 1500, -500, -10));
    let backend = make_backend(&base_url, "od-neg-quota");
    let quota = backend.about().await.unwrap().unwrap();
    assert_eq!(quota.total_bytes, Some(1000));
    assert_eq!(quota.used_bytes, Some(1500));
    assert_eq!(quota.free_bytes, Some(0));
    assert_eq!(quota.trashed_bytes, Some(0));
}

#[tokio::test]
async fn onedrive_remote_item_descendants_preserve_drive_id_across_all_ops() {
    let (base_url, state) = start_mock_graph().await;
    let shared_bytes = b"remote-item-descendant-payload".to_vec();
    let nested_bytes = b"nested-remote-item-payload".to_vec();
    let personal_bytes = b"personal-bang-id-payload".to_vec();
    {
        let mut g = state.lock().unwrap();
        g.valid_token = Some("tok-od".into());
        g.require_sec_precision_z = true;

        // Also place a Personal-style `!` item on `me/drive` to ensure `!` stays local.
        g.items_by_path.insert(
            "local_bang.txt".into(),
            MockItem {
                id: "1234567890ABCDEF!101".into(),
                path: "local_bang.txt".into(),
                is_folder: false,
                data: personal_bytes.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );

        g.items_by_path.insert(
            "shared".into(),
            MockItem {
                id: "mount-1".into(),
                path: "shared".into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.remote_items
            .insert("shared".into(), ("drv-shared".into(), "rm-dir".into()));

        let mut remote_map = BTreeMap::new();
        remote_map.insert(
            String::new(),
            MockItem {
                id: "rm-dir".into(),
                path: String::new(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        remote_map.insert(
            "shared.txt".into(),
            MockItem {
                id: "rm-file!1".into(),
                path: "shared.txt".into(),
                is_folder: false,
                data: shared_bytes.clone(),
                last_modified: "2020-01-01T00:00:00Z".into(),
            },
        );
        remote_map.insert(
            "sub".into(),
            MockItem {
                id: "rm-sub!1".into(),
                path: "sub".into(),
                is_folder: true,
                data: vec![],
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        remote_map.insert(
            "sub/nested.txt".into(),
            MockItem {
                id: "rm-nested!2".into(),
                path: "sub/nested.txt".into(),
                is_folder: false,
                data: nested_bytes.clone(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        remote_map.insert(
            "deletable.txt".into(),
            MockItem {
                id: "rm-del!3".into(),
                path: "deletable.txt".into(),
                is_folder: false,
                data: b"bye".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        remote_map.insert(
            "path_deletable.txt".into(),
            MockItem {
                id: "rm-del-path!4".into(),
                path: "path_deletable.txt".into(),
                is_folder: false,
                data: b"bye-path".to_vec(),
                last_modified: "2023-11-14T22:13:20Z".into(),
            },
        );
        g.remote_drives.insert("drv-shared".into(), remote_map);
    }

    let backend = make_backend(&base_url, "od-remote-strict");
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut entries = Vec::new();
    while let Some(e) = s.next().await {
        entries.push(e.unwrap());
    }

    let local_bang = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "local_bang.txt")
        .expect("local_bang.txt");
    assert_eq!(
        local_bang.node_id.as_ref().map(|n| n.as_str()),
        Some("1234567890ABCDEF!101"),
        "normal drive items with `!` must keep plain NodeId"
    );
    assert_eq!(
        read_all(&backend, &BackendPath::from_entry(local_bang)).await,
        personal_bytes
    );

    let shared_dir = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared")
        .expect("shared dir");
    assert_eq!(
        shared_dir.node_id.as_ref().map(|n| n.as_str()),
        Some("mount-1")
    );

    let shared_entry = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared/shared.txt")
        .expect("shared/shared.txt")
        .clone();
    assert_eq!(
        shared_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("rship-drive:drv-shared/rm-file!1")
    );

    let nested_entry = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared/sub/nested.txt")
        .expect("shared/sub/nested.txt")
        .clone();
    assert_eq!(
        nested_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("rship-drive:drv-shared/rm-nested!2")
    );

    // 0. Listing rooted at a subdirectory inside a remoteItem mounted folder.
    let mut sub_stream = backend
        .list_stream(&RelPath::parse("shared/sub").unwrap(), true)
        .await
        .unwrap();
    let mut sub_entries = Vec::new();
    while let Some(e) = sub_stream.next().await {
        sub_entries.push(e.unwrap());
    }
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].nfc_path.as_str(), "shared/sub/nested.txt");

    let shared_bp = BackendPath::from_entry(&shared_entry);

    // 1. stat via BackendPath::from_entry AND path-only BackendPath.
    let st_from_entry = backend
        .stat(&shared_bp)
        .await
        .unwrap()
        .expect("stat(from_entry) on remoteItem descendant must succeed");
    assert_eq!(st_from_entry.size, shared_bytes.len() as u64);
    assert_eq!(st_from_entry.node_id, shared_entry.node_id);

    let st_path_only = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("shared/sub/nested.txt").unwrap(),
        ))
        .await
        .unwrap()
        .expect("stat(path-only) inside remoteItem mounted folder must succeed");
    assert_eq!(st_path_only.size, nested_bytes.len() as u64);
    assert_eq!(st_path_only.node_id, nested_entry.node_id);

    // 2. compute_hash via BackendPath::from_entry.
    let ck = backend
        .compute_hash(&shared_bp, HashKind::Sha256)
        .await
        .unwrap()
        .expect("compute_hash on remoteItem descendant must succeed");
    assert_eq!(ck.kind, HashKind::Sha256);

    // 3. open_read via BackendPath::from_entry (both downloadUrl and /content fallback).
    assert_eq!(read_all(&backend, &shared_bp).await, shared_bytes);
    state.lock().unwrap().omit_download_url = true;
    assert_eq!(read_all(&backend, &shared_bp).await, shared_bytes);
    state.lock().unwrap().omit_download_url = false;

    // 4. open_read_entry via BackendPath::from_entry (downloadUrl refresh + /content fallback).
    let ds = backend
        .open_read_entry(&shared_entry, &shared_bp, None)
        .await
        .unwrap();
    let DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut r1 = rr
        .open_range(ByteRange { offset: 0, len: 10 })
        .await
        .unwrap();
    let mut b1 = Vec::new();
    while let Some(c) = r1.next().await {
        b1.extend_from_slice(&c.unwrap());
    }
    assert_eq!(b1, &shared_bytes[..10]);
    state.lock().unwrap().download_url_version = 2;
    let mut r2 = rr
        .open_range(ByteRange {
            offset: 10,
            len: shared_bytes.len() as u64 - 10,
        })
        .await
        .unwrap();
    let mut b2 = Vec::new();
    while let Some(c) = r2.next().await {
        b2.extend_from_slice(&c.unwrap());
    }
    assert_eq!(b2, &shared_bytes[10..]);

    state.lock().unwrap().omit_download_url = true;
    let ds_fallback = backend
        .open_read_entry(&shared_entry, &shared_bp, None)
        .await
        .unwrap();
    let DataSource::RemoteRangeReadable(rr_fb) = ds_fallback else {
        panic!("expected RemoteRangeReadable");
    };
    let mut r_fb = rr_fb
        .open_range(ByteRange {
            offset: 0,
            len: shared_bytes.len() as u64,
        })
        .await
        .unwrap();
    let mut b_fb = Vec::new();
    while let Some(c) = r_fb.next().await {
        b_fb.extend_from_slice(&c.unwrap());
    }
    assert_eq!(b_fb, shared_bytes);
    state.lock().unwrap().omit_download_url = false;

    // 5. server_side_copy via BackendPath::from_entry (plus patch_item_mtime) and path-only.
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(
            &ep,
            &shared_bp,
            &UploadInit {
                op_id: "op-rm-copy-1".into(),
                dst_path: RelPath::parse("copied/from-shared.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: shared_bytes.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("server_side_copy from remoteItem descendant must succeed");
    assert_eq!(copied.size, shared_bytes.len() as u64);
    assert_eq!(copied.mtime_ns, 1_700_000_000_000_000_000);
    assert_eq!(
        state.lock().unwrap().items_by_path["copied/from-shared.txt"].data,
        shared_bytes
    );

    let copied_nested = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("shared/sub/nested.txt").unwrap()),
            &UploadInit {
                op_id: "op-rm-copy-2".into(),
                dst_path: RelPath::parse("copied/from-nested.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: nested_bytes.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("server_side_copy from path-only remoteItem descendant must succeed");
    assert_eq!(copied_nested.size, nested_bytes.len() as u64);

    // 6. rename via BackendPath::from_entry AND path-only BackendPath.
    let renamed = backend.rename(&shared_bp, "renamed.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "shared/renamed.txt");
    assert_eq!(
        renamed.node_id.as_ref().map(|n| n.as_str()),
        Some("rship-drive:drv-shared/rm-file!1")
    );
    assert_eq!(
        read_all(&backend, &BackendPath::from_entry(&renamed)).await,
        shared_bytes
    );
    assert!(
        backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("shared/shared.txt").unwrap()
            ))
            .await
            .unwrap()
            .is_none()
    );

    let renamed_nested = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("shared/sub/nested.txt").unwrap()),
            "nested-renamed.txt",
        )
        .await
        .unwrap();
    assert_eq!(
        renamed_nested.nfc_path.as_str(),
        "shared/sub/nested-renamed.txt"
    );

    // 7. delete via BackendPath::from_entry AND path-only BackendPath.
    let del_entry = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "shared/deletable.txt")
        .expect("shared/deletable.txt");
    let del_bp = BackendPath::from_entry(del_entry);
    backend.delete(&del_bp).await.unwrap();
    assert!(backend.stat(&del_bp).await.unwrap().is_none());

    let del_path_bp = BackendPath::from_rel(RelPath::parse("shared/path_deletable.txt").unwrap());
    backend.delete(&del_path_bp).await.unwrap();
    assert!(backend.stat(&del_path_bp).await.unwrap().is_none());
}
