use crate::mock_server::start_mock_graph;
use axum::body::Bytes;
use futures::StreamExt;
use rship_backends::onedrive::{ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveBackend, OnedriveConfig};
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
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;

#[tokio::test]
async fn onedrive_passes_universal_conformance_and_quota_about() {
    let (base_url, _st) = start_mock_graph().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = OnedriveConfig::new("od");
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = ONEDRIVE_CHUNK_ALIGN_BYTES;
    let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od"));
    let backend = Arc::new(OnedriveBackend::new(cfg, auth, transport).unwrap());

    run_backend_conformance(backend.clone(), SystemClock::shared()).await;

    let quota = backend.about().await.unwrap().unwrap();
    assert_eq!(quota.total_bytes, Some(100_000_000));
    assert_eq!(quota.used_bytes, Some(25_000_000));
    assert_eq!(quota.free_bytes, Some(75_000_000));
    assert_eq!(quota.trashed_bytes, Some(1_000_000));
}

#[tokio::test]
async fn onedrive_320kib_resumable_session_crash_resume_and_async_server_side_copy() {
    let (base_url, st) = start_mock_graph().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = OnedriveConfig::new("od");
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = ONEDRIVE_CHUNK_ALIGN_BYTES;
    let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od"));
    let backend = Arc::new(OnedriveBackend::new(cfg, auth, transport).unwrap());

    // 400 KiB payload -> chunk 1 = exact 320 KiB, chunk 2 = 80 KiB final tail.
    let payload: Vec<u8> = (0..(400 * 1024)).map(|i| ((i * 31) % 251) as u8).collect();
    let dst_rel = RelPath::parse("in/video.bin").unwrap();
    let init = UploadInit {
        op_id: "op-od-1".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key("local", "v.bin", &backend.endpoint_identity(), &dst_rel),
        job_id: "j-od".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "v.bin".into(),
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
        backend_kind: "onedrive".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: sess.expires_at_unix_secs,
    };

    let c1 = payload[..ONEDRIVE_CHUNK_ALIGN_BYTES as usize].to_vec();
    let ack1 = backend
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
    assert_eq!(ack1.next_offset, Some(ONEDRIVE_CHUNK_ALIGN_BYTES));
    assert!(ack1.completed.is_none());

    // Simulate process crash & restart: `query_upload` inspects `nextExpectedRanges`!
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(ONEDRIVE_CHUNK_ALIGN_BYTES)
    );

    let c2 = payload[ONEDRIVE_CHUNK_ALIGN_BYTES as usize..].to_vec();
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

    // Verify full content via Range read!
    let ds = backend
        .open_read(&BackendPath::from_rel(dst_rel.clone()), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut s = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(b) = s.next().await {
        got.extend_from_slice(&b.unwrap());
    }
    assert_eq!(got, payload);

    // Zero-bandwidth async monitor server-side copy via TransferEngine!
    {
        let mut g = st.lock().unwrap();
        g.get_content_calls = 0;
        g.put_simple_calls = 0;
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
    let mut ecfg = EngineConfig::new("job-od-ssc", JobMode::Copy, "od:in", "od:out");
    ecfg.src_prefix = RelPath::parse("in").unwrap();
    ecfg.dst_prefix = RelPath::parse("out").unwrap();
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.server_side_copies, 1);

    let g = st.lock().unwrap();
    assert_eq!(g.get_content_calls, 0);
    assert_eq!(g.put_simple_calls, 0);
    assert_eq!(g.copy_calls, 1);
    assert_eq!(g.items_by_path["out/video.bin"].data, payload);
}
