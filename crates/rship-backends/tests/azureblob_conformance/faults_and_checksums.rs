use crate::common::InjectedFault;
use crate::mock_server::{MockBlob, TEST_ACCOUNT, make_backend, spawn_mock_azure};
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::azureblob::{
    AZURE_MIN_BLOCK_BYTES, AzureAuth, AzureBlobBackend, AzureBlobConfig,
};
use rship_core::backend::{BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, HashKind};
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{
    HttpTransport, LimiterPlane, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

// =========================================================================
// Shared Fault Harness Tests: 429/503 Retry-After & Quota Refund,
// 500 Non-Throttle Retries, Exhausted Retries, Mid-Body Reset Download,
// Slow Finalize & Long Control Timeout, and Sensitive SharedKey Header
// =========================================================================

fn make_custom_backend(
    remote_name: &str,
    base_url: &str,
    auth: AzureAuth,
    transport_cfg: TransportConfig,
    max_retries: u32,
    base_retry_delay: Duration,
    max_retry_delay: Duration,
) -> Arc<AzureBlobBackend> {
    let mut cfg = AzureBlobConfig::new(remote_name, TEST_ACCOUNT, "test-container")
        .with_max_retries(max_retries)
        .with_retry_delays(base_retry_delay, max_retry_delay);
    cfg.endpoint = Some(base_url.to_string());
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let transport = HttpTransport::new(transport_cfg).unwrap();
    Arc::new(AzureBlobBackend::new(cfg, auth, transport, Some(SystemClock::shared())).unwrap())
}

async fn read_azure_all(backend: &AzureBlobBackend, rel: &RelPath) -> Vec<u8> {
    let reader = match backend
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut stream = reader
        .open_range(ByteRange {
            offset: 0,
            len: reader.total_len(),
        })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    out
}

#[tokio::test]
async fn azureblob_scripted_429_retry_after_and_503_recovery_refunds_retry_quota() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            "quota/item.txt".to_string(),
            MockBlob {
                name: "quota/item.txt".to_string(),
                data: b"hello-quota".to_vec(),
                etag,
                metadata: BTreeMap::new(),
                content_md5: None,
                ..Default::default()
            },
        );
    }
    let faults = state.lock().unwrap().fault_injector();

    let quota_cfg = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let transport_cfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg.clone()));

    // Part A: Scripted 429 with huge `Retry-After: 3600` (clamped by `max_retry_delay = 60ms`)
    // recovers cleanly, trips control-plane CUBIC only (data plane isolated), and refunds
    // retry quota back to `max_tokens`.
    let backend_429 = make_custom_backend(
        "azure-429",
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        transport_cfg.clone(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(60),
    );
    let ctrl_429 = backend_429.control_limiter();
    let data_429 = backend_429.data_limiter();
    assert_eq!(ctrl_429.scope().plane, Some(LimiterPlane::Control));
    assert_eq!(data_429.scope().plane, Some(LimiterPlane::Data));
    assert!(!ctrl_429.snapshot().cubic_enabled);

    faults.push("ListBlobs", InjectedFault::too_many_requests(Some("3600")));
    let started = std::time::Instant::now();
    let listed: Vec<_> = backend_429
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].nfc_path.as_str(), "quota/item.txt");
    assert!(
        elapsed >= Duration::from_millis(45) && elapsed < Duration::from_secs(2),
        "Retry-After: 3600 must be honored and capped to 60ms, elapsed={elapsed:?}"
    );
    assert_eq!(faults.op_requests("ListBlobs"), 2);
    assert_eq!(faults.op_faults("ListBlobs"), 1);

    let snap_429 = ctrl_429.snapshot();
    assert!(
        snap_429.cubic_enabled,
        "429 must activate control-plane CUBIC throttle"
    );
    assert!(
        !data_429.snapshot().cubic_enabled,
        "control-plane 429 must not affect isolated data-plane limiter"
    );
    assert_eq!(
        snap_429.retry_quota_available, snap_429.retry_quota_max,
        "429 recovery must refund exact retry quota back to max_tokens"
    );
    assert_eq!(snap_429.retry_quota_max, 100);

    // Part B: Scripted 503 ServerBusy on `HeadBlob` (`stat`, using HEAD `skip_response_body`)
    // also activates CUBIC and refunds retry quota back to `max_tokens` on recovery.
    let backend_503 = make_custom_backend(
        "azure-503",
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        transport_cfg,
        3,
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    let ctrl_503 = backend_503.control_limiter();
    assert!(!ctrl_503.snapshot().cubic_enabled);

    faults.push(
        "HeadBlob",
        InjectedFault::xml_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "The server is busy.",
        )
        .with_retry_after("0"),
    );
    let entry = backend_503
        .stat(&BackendPath::from_rel(
            RelPath::parse("quota/item.txt").unwrap(),
        ))
        .await
        .unwrap()
        .expect("blob should exist after 503 recovery");
    assert_eq!(entry.size, b"hello-quota".len() as u64);
    assert_eq!(faults.op_requests("HeadBlob"), 2);
    assert_eq!(faults.op_faults("HeadBlob"), 1);

    let snap_503 = ctrl_503.snapshot();
    assert!(
        snap_503.cubic_enabled,
        "503 ServerBusy must activate control-plane CUBIC throttle"
    );
    assert_eq!(
        snap_503.retry_quota_available, snap_503.retry_quota_max,
        "503 recovery must refund exact retry quota back to max_tokens"
    );
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn azureblob_http_500_retries_without_tripping_cubic_throttle() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            "err500/file.txt".to_string(),
            MockBlob {
                name: "err500/file.txt".to_string(),
                data: b"payload-500".to_vec(),
                etag,
                metadata: BTreeMap::new(),
                content_md5: None,
                ..Default::default()
            },
        );
    }
    let faults = state.lock().unwrap().fault_injector();
    let backend = make_custom_backend(
        "azure-500",
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        TransportConfig::default(),
        4,
        Duration::from_millis(5),
        Duration::from_millis(25),
    );
    let control_limiter = backend.control_limiter();
    assert!(!control_limiter.snapshot().cubic_enabled);

    // Single HTTP 500 on ListBlobs retries, recovers, refunds quota, and does NOT trip CUBIC.
    faults.push(
        "ListBlobs",
        InjectedFault::xml_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "transient internal error",
        ),
    );
    let page = backend
        .list_ordered_page(&RelPath::root(), None, None, 100)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(faults.op_requests("ListBlobs"), 2);
    assert_eq!(faults.op_faults("ListBlobs"), 1);
    assert!(
        !control_limiter.snapshot().cubic_enabled,
        "HTTP 500 must NOT trip CUBIC throttle"
    );
    assert_eq!(
        control_limiter.snapshot().retry_quota_available,
        control_limiter.snapshot().retry_quota_max
    );

    // Consecutive 500, 502, 504 on HeadBlob all retry cleanly WITHOUT tripping CUBIC.
    faults.push_many(
        "HeadBlob",
        [
            InjectedFault::xml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "transient 500",
            ),
            InjectedFault::HttpStatus {
                status: StatusCode::BAD_GATEWAY,
                retry_after: None,
                content_type: "text/plain",
                body: "Bad Gateway".into(),
            },
            InjectedFault::HttpStatus {
                status: StatusCode::GATEWAY_TIMEOUT,
                retry_after: None,
                content_type: "text/plain",
                body: "Gateway Timeout".into(),
            },
        ],
    );
    let entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("err500/file.txt").unwrap(),
        ))
        .await
        .unwrap()
        .expect("stat should succeed after 500/502/504 retries");
    assert_eq!(entry.size, b"payload-500".len() as u64);
    assert_eq!(faults.op_requests("HeadBlob"), 4);
    assert_eq!(faults.op_faults("HeadBlob"), 3);
    assert!(
        !control_limiter.snapshot().cubic_enabled,
        "HTTP 500/502/504 must NOT trip CUBIC throttle"
    );
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn azureblob_exhausted_retries_return_retries_exhausted_error() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let faults = state.lock().unwrap().fault_injector();

    let backend = make_custom_backend(
        "azure-exhaust",
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        TransportConfig::default(),
        2,
        Duration::from_millis(5),
        Duration::from_millis(20),
    );
    let control_limiter = backend.control_limiter();

    // 1. Exhausted HTTP 500 on HeadBlob (1 initial + 2 retries = 3 requests):
    //    returns `retries_exhausted() == true` without activating CUBIC.
    faults.push_many(
        "HeadBlob",
        [
            InjectedFault::xml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "still failing 1",
            ),
            InjectedFault::xml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "still failing 2",
            ),
            InjectedFault::xml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "still failing 3",
            ),
        ],
    );
    let err_500 = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("exhaust/obj.bin").unwrap(),
        ))
        .await
        .expect_err("persistent 500 must fail after exhausting retries");
    assert!(
        err_500.retries_exhausted(),
        "exhausted 500 must set retries_exhausted() == true, got {err_500:?}"
    );
    assert!(!err_500.is_retryable());
    assert_eq!(err_500.kind, ErrorKind::Network);
    assert_eq!(err_500.retry, RetryClass::Retryable);
    assert!(!control_limiter.snapshot().cubic_enabled);
    assert_eq!(faults.op_requests("HeadBlob"), 3);

    // 2. Exhausted HTTP 503 on ListBlobs (1 initial + 2 retries = 3 requests):
    //    returns `retries_exhausted() == true` with RateLimited/Throttled + CUBIC enabled.
    faults.push_many(
        "ListBlobs",
        [
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
        ],
    );
    let err_503 = backend
        .list_ordered_page(&RelPath::root(), None, None, 100)
        .await
        .expect_err("persistent 503 must fail after exhausting retries");
    assert!(
        err_503.retries_exhausted(),
        "exhausted 503 must set retries_exhausted() == true, got {err_503:?}"
    );
    assert!(!err_503.is_retryable());
    assert_eq!(err_503.kind, ErrorKind::RateLimited);
    assert_eq!(err_503.retry, RetryClass::Throttled);
    assert!(control_limiter.snapshot().cubic_enabled);
    assert_eq!(faults.op_requests("ListBlobs"), 3);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn azureblob_mid_body_reset_on_get_blob_surfaces_retryable_network_error_and_recovers() {
    let (src_url, src_key, src_state) = spawn_mock_azure().await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 29 + 7) & 0xFF) as u8)
        .collect();
    let rel = RelPath::parse("download/reset.bin").unwrap();

    let src_backend = make_custom_backend(
        "azure-src-reset",
        &src_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &src_key).unwrap(),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    let upload_init = UploadInit {
        op_id: "op-seed-reset".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let seed_payload = payload.clone();
    src_backend
        .put_single_shot(
            &upload_init,
            Box::pin(futures::stream::once(async move {
                Ok(Bytes::from(seed_payload))
            })),
        )
        .await
        .unwrap();

    let faults = src_state.lock().unwrap().fault_injector();

    // 1. Direct GetBlob stream receives prefix bytes then terminates with retryable Network error.
    let prefix = Bytes::from_static(b"partial-azure-get-prefix");
    faults.push("GetBlob", InjectedFault::mid_body_reset(prefix.clone()));

    let reader = match src_backend
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut stream = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut received = Vec::new();
    let mut stream_err = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => received.extend_from_slice(&chunk),
            Err(e) => {
                stream_err = Some(e);
                break;
            }
        }
    }
    assert_eq!(
        received,
        prefix.as_ref(),
        "mid-body reset must deliver prefix bytes before aborting"
    );
    let err = stream_err.expect("mid-body reset must surface an error rather than truncating");
    assert_eq!(err.kind, ErrorKind::Network, "got: {err:?}");
    assert_eq!(err.retry, RetryClass::Retryable, "got: {err:?}");
    assert!(err.is_retryable());

    // Subsequent GetBlob recovers bit-exact.
    assert_eq!(read_azure_all(&src_backend, &rel).await, payload);

    // 2. End-to-end TransferEngine download recovery (distinct mock Azure destination so
    //    server-side copy is ineligible and full GetBlob streaming runs through retry recovery).
    let (dst_url, dst_key, _) = spawn_mock_azure().await;
    let dst_backend = make_custom_backend(
        "azure-dst-reset",
        &dst_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &dst_key).unwrap(),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    faults.push(
        "GetBlob",
        InjectedFault::mid_body_reset(Bytes::from_static(b"corrupt-partial-chunk")),
    );

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        src_backend.clone(),
        dst_backend.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-az-reset", JobMode::Copy, "azure-src", "azure-dst");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(read_azure_all(&dst_backend, &rel).await, payload);
    assert_eq!(faults.op_faults("GetBlob"), 2);
    assert_eq!(faults.op_requests("GetBlob"), 4);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn azureblob_slow_finalize_on_put_blob_and_put_block_succeeds_without_false_stall_timeout() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let faults = state.lock().unwrap().fault_injector();

    // Short data_stall_timeout (80ms) and control_timeout (120ms), but generous
    // data_finalize_timeout (2s) and long_control_timeout (2s).
    let transport_cfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(120))
        .with_long_control_timeout(Duration::from_secs(2))
        .with_data_stall_timeout(Duration::from_millis(80))
        .with_data_finalize_timeout(Duration::from_secs(2));

    let backend = make_custom_backend(
        "azure-slow-finalize",
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        transport_cfg,
        0,
        Duration::from_millis(5),
        Duration::from_millis(20),
    );

    // 1. SlowFinalize (220ms > 80ms data_stall_timeout, < 2s data_finalize_timeout) on PutBlob.
    let single_rel = RelPath::parse("slow/single.bin").unwrap();
    let single_data = vec![0xABu8; 4096];
    let single_init = UploadInit {
        op_id: "op-slow-putblob".into(),
        dst_path: single_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: single_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: single_data.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    faults.push(
        "PutBlob",
        InjectedFault::slow_finalize(Duration::from_millis(220)),
    );
    let t0 = std::time::Instant::now();
    let single_body = single_data.clone();
    let entry = backend
        .put_single_shot(
            &single_init,
            Box::pin(futures::stream::once(async move {
                Ok(Bytes::from(single_body))
            })),
        )
        .await
        .expect("PutBlob SlowFinalize must succeed under data_finalize_timeout");
    assert!(
        t0.elapsed() >= Duration::from_millis(180),
        "PutBlob SlowFinalize must actually wait for slow server response, elapsed={:?}",
        t0.elapsed()
    );
    assert_eq!(entry.size, single_data.len() as u64);
    assert_eq!(read_azure_all(&backend, &single_rel).await, single_data);
    assert_eq!(faults.op_faults("PutBlob"), 1);

    // 2. SlowFinalize (220ms > 80ms data_stall_timeout, < 2s data_finalize_timeout) on PutBlock,
    //    plus slow PutBlockList (240ms > 120ms control_timeout, < 2s long_control_timeout)
    //    and slow CopyBlob (240ms > 120ms control_timeout, < 2s long_control_timeout).
    let blk_rel = RelPath::parse("slow/block.bin").unwrap();
    let blk_sz = AZURE_MIN_BLOCK_BYTES;
    let blk_data = vec![0xCDu8; blk_sz as usize];
    let blk_init = UploadInit {
        op_id: "op-slow-putblock".into(),
        dst_path: blk_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: blk_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: blk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&blk_init).await.unwrap();
    let op = OperationRecord {
        op_id: blk_init.op_id.clone(),
        session_key: "sk-slow".into(),
        job_id: "j-slow".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: blk_rel.as_str().into(),
        dst_raw_path: blk_rel.as_str().into(),
        dst_nfc_path: blk_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: blk_sz,
            mtime_ns: blk_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "azureblob".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: blk_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    faults.push(
        "PutBlock",
        InjectedFault::slow_finalize(Duration::from_millis(220)),
    );
    let t1 = std::time::Instant::now();
    let blk_body = blk_data.clone();
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                blk_sz,
                blk_sz,
                Box::pin(futures::stream::once(
                    async move { Ok(Bytes::from(blk_body)) },
                )),
            ),
        )
        .await
        .expect("PutBlock SlowFinalize must succeed under data_finalize_timeout");
    assert!(
        t1.elapsed() >= Duration::from_millis(180),
        "PutBlock SlowFinalize must actually wait for slow server response, elapsed={:?}",
        t1.elapsed()
    );
    assert_eq!(faults.op_faults("PutBlock"), 1);

    // PutBlockList uses `long_control_timeout` (2s), surviving a 240ms delay > 120ms `control_timeout`.
    faults.push(
        "PutBlockList",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let committed = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: blk_sz,
                etag: ack.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .expect("PutBlockList must use long_control_timeout");
    assert_eq!(committed.size, blk_sz);
    assert_eq!(faults.op_faults("PutBlockList"), 1);

    // CopyBlob (`x-ms-copy-source`) also uses `long_control_timeout` (2s).
    faults.push(
        "CopyBlob",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let copy_rel = RelPath::parse("slow/copied.bin").unwrap();
    let copy_init = UploadInit {
        op_id: "op-slow-copy".into(),
        dst_path: copy_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: blk_sz,
        src_mtime_ns: blk_init.src_mtime_ns,
        planned_chunk_size: blk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(&ep, &BackendPath::from_rel(blk_rel), &copy_init)
        .await
        .expect("CopyBlob must use long_control_timeout")
        .expect("CopyBlob returned committed entry");
    assert_eq!(copied.size, blk_sz);
    assert_eq!(faults.op_faults("CopyBlob"), 1);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[test]
fn azureblob_shared_key_authorization_header_is_marked_sensitive() {
    let key_b64 = B64.encode([0x55u8; 64]);
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let mut headers = HeaderMap::new();
    let url = format!("https://{TEST_ACCOUNT}.blob.core.windows.net/test-container/secret.bin");
    auth.sign_headers(
        &Method::GET,
        &url,
        &mut headers,
        rship_core::time::Timestamp::now(),
    )
    .unwrap();

    let auth_hdr = headers
        .get(http::header::AUTHORIZATION)
        .expect("SharedKey signer must insert Authorization header");
    assert!(
        auth_hdr.is_sensitive(),
        "SharedKey Authorization header must be marked sensitive (is_sensitive() == true)"
    );
    assert!(
        auth_hdr
            .to_str()
            .unwrap()
            .starts_with(&format!("SharedKey {TEST_ACCOUNT}:"))
    );
    assert!(
        !format!("{auth_hdr:?}").contains("SharedKey"),
        "Debug output for sensitive Authorization header must not leak credentials"
    );
}

#[tokio::test]
async fn azureblob_c3_streaming_md5_headers_upload_and_download_verification() {
    use rship_core::types::Checksum;

    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let payload = b"azure blob c3 streaming md5 end-to-end verification payload!".to_vec();
    let md5_raw = Md5::digest(&payload);
    let md5_hex = hex::encode(md5_raw);
    let md5_b64 = B64.encode(md5_raw);

    // (a) Known MD5 in `init.checksums` is sent as `Content-MD5` header (and signed via SharedKey)!
    let blob_path = RelPath::parse("c3/known-md5.bin").unwrap();
    let init = UploadInit {
        op_id: "op-az-c3-md5".into(),
        dst_path: blob_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Md5,
            hex: md5_hex,
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p_c = payload.clone();
    backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .unwrap();
    assert_eq!(
        state
            .lock()
            .unwrap()
            .seen_put_blob_content_md5
            .last()
            .map(String::as_str),
        Some(md5_b64.as_str()),
        "known MD5 in init.checksums must be sent as Content-MD5 header on PutBlob"
    );

    // (b) Streaming upload detects server-side / in-transit MD5 mismatch on BOTH PutBlob and PutBlock!
    state.lock().unwrap().corrupt_put_blob_md5_once = true;
    let bad_blob_init = UploadInit {
        op_id: "op-az-c3-bad-blob".into(),
        dst_path: RelPath::parse("c3/bad-blob.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(11)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let put_err = backend
        .put_single_shot(&bad_blob_init, Box::pin(futures::stream::iter(chunks)))
        .await
        .expect_err("corrupted Azure PutBlob Content-MD5 must fail upload");
    assert_eq!(put_err.kind, ErrorKind::Integrity);
    assert!(put_err.is_integrity());
    assert!(put_err.message().contains("checksum mismatch"));

    let blk_path = RelPath::parse("c3/bad-block.bin").unwrap();
    let blk_init = UploadInit {
        op_id: "op-az-c3-bad-blk".into(),
        dst_path: blk_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: AZURE_MIN_BLOCK_BYTES,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&blk_init).await.unwrap();
    let blk_op = OperationRecord {
        op_id: blk_init.op_id.clone(),
        session_key: "sk-az-c3".into(),
        job_id: "j-az-c3".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: blk_path.as_str().into(),
        dst_raw_path: blk_path.as_str().into(),
        dst_nfc_path: blk_path,
        src_version: SourceVersion {
            node_id: None,
            size: AZURE_MIN_BLOCK_BYTES,
            mtime_ns: blk_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "azureblob".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    state.lock().unwrap().corrupt_put_block_md5_once = true;
    let blk_err = backend
        .upload_chunk(
            &blk_op,
            ChunkUpload::new(
                1,
                0,
                AZURE_MIN_BLOCK_BYTES,
                AZURE_MIN_BLOCK_BYTES,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0x42u8; AZURE_MIN_BLOCK_BYTES as usize]))
                })),
            ),
        )
        .await
        .expect_err("corrupted Azure PutBlock Content-MD5 must fail chunk upload");
    assert_eq!(blk_err.kind, ErrorKind::Integrity);
    assert!(blk_err.is_integrity());
    assert!(blk_err.message().contains("checksum mismatch"));

    // (c) Full-object download detects corrupted payload bytes against `Content-MD5`!
    let reader = match backend
        .open_read(&BackendPath::from_rel(blob_path), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    state.lock().unwrap().corrupt_get_body_once = true;
    let mut bad_dl = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut dl_err = None;
    while let Some(item) = bad_dl.next().await {
        if let Err(e) = item {
            dl_err = Some(e);
            break;
        }
    }
    let dl_err = dl_err.expect("corrupted full-object Azure download must fail checksum check");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(dl_err.message().contains("checksum mismatch"));

    // (d) Sub-range downloads (`offset > 0` or `len < total_len`) do NOT falsely fail!
    for range in [
        ByteRange { offset: 0, len: 10 },
        ByteRange { offset: 8, len: 16 },
        ByteRange {
            offset: payload.len() as u64 - 9,
            len: 9,
        },
    ] {
        let mut s = reader.open_range(range).await.unwrap();
        let mut got = Vec::new();
        while let Some(item) = s.next().await {
            got.extend_from_slice(&item.unwrap());
        }
        assert_eq!(
            got,
            payload[range.offset as usize..(range.offset + range.len) as usize]
        );
    }
}
