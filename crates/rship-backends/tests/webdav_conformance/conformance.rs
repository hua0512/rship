use crate::mock_server::start_mock_dav;
#[cfg(feature = "local")]
use crate::mock_server::{MockDavState, handle_dav};
#[cfg(feature = "local")]
use axum::Router;
use axum::body::Bytes;
use futures::StreamExt;
use rship_backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit, UploadProgress};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;
#[cfg(feature = "local")]
use std::sync::Mutex;
#[cfg(feature = "local")]
use std::time::Duration;
#[cfg(feature = "local")]
use tokio::net::TcpListener;

#[tokio::test]
async fn webdav_passes_universal_conformance_and_about_quota() {
    let (addr, _st) = start_mock_dav().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = WebdavConfig::new("nc", format!("http://{addr}/remote.php/dav/files/alice"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    cfg.single_shot_max_bytes = Some(32 * 1024);
    cfg.default_chunk_size = Some(16 * 1024);
    let backend = Arc::new(WebdavBackend::new(cfg, transport).unwrap());

    run_backend_conformance(backend.clone(), SystemClock::shared()).await;

    let quota = backend.about().await.unwrap().unwrap();
    assert_eq!(quota.used_bytes, Some(2_000_000));
    assert_eq!(quota.free_bytes, Some(8_000_000));
    assert_eq!(quota.total_bytes, Some(10_000_000));
}

#[tokio::test]
async fn nextcloud_chunked_v2_resumes_across_crash_and_server_side_copies_zero_bandwidth() {
    let (addr, st) = start_mock_dav().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = WebdavConfig::new("nc", format!("http://{addr}/remote.php/dav/files/alice"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.single_shot_max_bytes = Some(16 * 1024);
    cfg.default_chunk_size = Some(32 * 1024);
    let backend = Arc::new(WebdavBackend::new(cfg, transport).unwrap());

    // Simulate chunk 1 uploaded before crash -> query_upload recovers exact offset -> upload chunk 2 -> finish!
    let payload: Vec<u8> = (0..(80 * 1024)).map(|i| ((i * 29) % 251) as u8).collect();
    let dst_rel = RelPath::parse("in/big.bin").unwrap();
    let init = UploadInit {
        op_id: "op-nc-resume-1".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 32 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key(
            "local",
            "big.bin",
            &backend.endpoint_identity(),
            &dst_rel,
        ),
        job_id: "j-nc".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "big.bin".into(),
        dst_raw_path: dst_rel.as_str().into(),
        dst_nfc_path: dst_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "webdav".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 32 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };

    // Upload first 32 KiB chunk.
    let c1 = payload[..32 * 1024].to_vec();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                c1.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c1)) })),
            ),
        )
        .await
        .unwrap();

    // Crash & restart: query_upload MUST confirm exact 32 KiB prefix from PROPFIND!
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(32 * 1024)
    );

    // Upload remaining 48 KiB chunk and assemble via MOVE .file.
    let c2 = payload[32 * 1024..].to_vec();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                32 * 1024,
                c2.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c2)) })),
            ),
        )
        .await
        .unwrap();
    backend.finish_upload(&op, &[]).await.unwrap();

    // Verify assembled bytes via Range read.
    let ds = backend
        .open_read(&BackendPath::from_rel(dst_rel.clone()), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(chunk) = stream.next().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, payload);

    // Test zero-bandwidth WebDAV server-side COPY via TransferEngine!
    {
        let mut g = st.lock().unwrap();
        g.get_calls = 0;
        g.put_calls = 0;
        g.copy_calls = 0;
    }
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
    let mut ecfg = EngineConfig::new("job-dav-ssc", JobMode::Copy, "nc:in", "nc:out");
    ecfg.src_prefix = RelPath::parse("in").unwrap();
    ecfg.dst_prefix = RelPath::parse("out").unwrap();
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.server_side_copies, 1);

    let g = st.lock().unwrap();
    assert_eq!(g.get_calls, 0);
    assert_eq!(g.put_calls, 0);
    assert_eq!(g.copy_calls, 1);
    assert_eq!(g.files["/remote.php/dav/files/alice/out/big.bin"], payload);
}

#[cfg(feature = "local")]
#[tokio::test]
async fn generic_webdav_second_sync_skips_unchanged_despite_server_assigned_mtime() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = Arc::new(Mutex::new(MockDavState::new()));
    let st_clone = st.clone();
    tokio::spawn(async move {
        let app = Router::new().fallback(handle_dav).with_state(st_clone);
        axum::serve(listener, app).await.unwrap();
    });

    let tmp_src = tempfile::tempdir().unwrap();
    let file_path = tmp_src.path().join("doc.txt");
    std::fs::write(&file_path, b"generic webdav sync baseline test").unwrap();
    // Local file mtime is 2026-01-01 (outside D8's 10ms racily-clean window),
    // whereas MockDavServer PROPFIND returns 2026-11-24!
    let past_mtime = std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    std::fs::File::options()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_modified(past_mtime)
        .unwrap();
    let local_src: Arc<dyn StorageBackend> =
        Arc::new(rship_backends::local::LocalBackend::new("local", tmp_src.path()).unwrap());

    let mut cfg = WebdavConfig::new(
        "dav-gen",
        format!("http://{addr}/remote.php/dav/files/alice"),
    );
    cfg.vendor = WebdavVendor::Generic;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let dav_dst: Arc<dyn StorageBackend> = Arc::new(WebdavBackend::new(cfg, transport).unwrap());

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local_src,
        dav_dst,
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let mut cfg1 = EngineConfig::new("job-dav-sync-1", JobMode::Copy, "local:src", "dav-gen:sync");
    cfg1.dst_prefix = RelPath::parse("sync").unwrap();
    let rep1 = engine
        .run(&cfg1, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert_eq!(rep1.files_transferred, 1);

    // Second run (`JobMode::Sync`) MUST skip the unchanged file (0 transfers) via accurate baseline!
    let mut cfg2 = EngineConfig::new("job-dav-sync-2", JobMode::Sync, "local:src", "dav-gen:sync");
    cfg2.dst_prefix = RelPath::parse("sync").unwrap();
    let rep2 = engine
        .run(&cfg2, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        rep2.files_transferred, 0,
        "expected 0 re-transfers, got {rep2:?}"
    );
    assert_eq!(rep2.files_skipped, 1);
}
