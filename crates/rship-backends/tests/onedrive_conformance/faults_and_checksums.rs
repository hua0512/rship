use crate::common::InjectedFault;
use crate::mock_server::{MockItem, hex_encode, start_mock_graph};
use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use rship_backends::onedrive::{
    ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveAuthProvider, OnedriveBackend, OnedriveConfig,
    OnedriveOAuth2Auth, OnedriveToken,
};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit, UploadProgress};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::ByteRange;
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::oauth::{InMemoryTokenStore, StaticBearerAuth};
use rship_transport::{
    HttpTransport, LimiterPlane, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

fn make_custom_backend(
    name: &str,
    base_url: &str,
    auth: Arc<dyn OnedriveAuthProvider>,
    transport_cfg: TransportConfig,
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
) -> Arc<OnedriveBackend> {
    let transport = HttpTransport::new(transport_cfg).unwrap();
    let mut cfg = OnedriveConfig::new(name)
        .with_max_retries(max_retries)
        .with_retry_delays(base_delay, max_delay);
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.token_url = format!("{base_url}/oauth2/v2.0/token");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = ONEDRIVE_CHUNK_ALIGN_BYTES;
    Arc::new(OnedriveBackend::new(cfg, auth, transport).unwrap())
}

async fn seed_onedrive_file(backend: &OnedriveBackend, rel: &RelPath, data: Vec<u8>) {
    let init = UploadInit {
        op_id: format!("seed-{}", rel.as_str()),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(data)) })),
        )
        .await
        .unwrap();
}

async fn read_onedrive_all(backend: &OnedriveBackend, rel: &RelPath) -> Vec<u8> {
    let ds = backend
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap();
    let DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut stream = rr
        .open_range(ByteRange {
            offset: 0,
            len: rr.total_len(),
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
async fn onedrive_scripted_429_retry_after_and_503_quota_refund_and_plane_isolation() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            "hello.txt".into(),
            MockItem {
                id: "od-hello".into(),
                path: "hello.txt".into(),
                is_folder: false,
                data: b"hello-quota".to_vec(),
                last_modified: "2026-11-24T12:00:00Z".into(),
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
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg));

    // Part A: Scripted 429 with `Retry-After: 3600` (clamped by `max_retry_delay = 60ms`)
    // recovers cleanly, activates control-plane CUBIC only (data plane isolated), and
    // refunds exact 5-token retry quota (`available == max_tokens == 100`).
    let backend_429 = make_custom_backend(
        "od-429",
        &base_url,
        Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od")),
        transport_cfg.clone(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(60),
    );
    let ctrl_429 = backend_429.control_limiter();
    let data_429 = backend_429.data_limiter();
    assert!(!Arc::ptr_eq(ctrl_429, data_429));
    assert_eq!(ctrl_429.scope().plane, Some(LimiterPlane::Control));
    assert_eq!(data_429.scope().plane, Some(LimiterPlane::Data));
    assert!(!ctrl_429.snapshot().cubic_enabled);

    faults.push("items.list", InjectedFault::too_many_requests(Some("3600")));
    let started = std::time::Instant::now();
    let listed: Vec<_> = backend_429
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].nfc_path.as_str(), "hello.txt");
    assert!(
        elapsed >= Duration::from_millis(45) && elapsed < Duration::from_secs(2),
        "Retry-After: 3600 must be honored and clamped to max_retry_delay (60ms), elapsed={elapsed:?}"
    );
    assert_eq!(faults.op_requests("items.list"), 2);
    assert_eq!(faults.op_faults("items.list"), 1);

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
        "429 recovery must refund exact 5-token retry quota back to max_tokens"
    );
    assert_eq!(snap_429.retry_quota_max, 100);

    // Part B: Scripted 503 recovery on `stat`, `query_upload`, and `copy.monitor` all
    // refund exact 5-token retry quota back to `max_tokens` with isolated data limiter.
    let backend_503 = make_custom_backend(
        "od-503",
        &base_url,
        Arc::new(StaticBearerAuth::new("bob@outlook.com", "tok-od")),
        transport_cfg,
        3,
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    let ctrl_503 = backend_503.control_limiter();
    let data_503 = backend_503.data_limiter();
    assert!(!ctrl_503.snapshot().cubic_enabled);

    faults.push("items.get", InjectedFault::service_unavailable(Some("0")));
    let entry = backend_503
        .stat(&BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()))
        .await
        .unwrap()
        .expect("hello.txt should exist after 503 recovery");
    assert_eq!(entry.size, b"hello-quota".len() as u64);
    assert_eq!(faults.op_faults("items.get"), 1);
    let snap_503 = ctrl_503.snapshot();
    assert!(
        snap_503.cubic_enabled,
        "503 must activate control-plane CUBIC"
    );
    assert!(!data_503.snapshot().cubic_enabled);
    assert_eq!(snap_503.retry_quota_available, snap_503.retry_quota_max);

    // Also verify `query_upload` retries transient 503 via `execute_with_policy` and refunds quota.
    let init = UploadInit {
        op_id: "op-q-503".into(),
        dst_path: RelPath::parse("sess.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend_503.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-q-503".into(),
        job_id: "j-q-503".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend_503.endpoint_identity(),
        src_raw_path: "sess.bin".into(),
        dst_raw_path: "sess.bin".into(),
        dst_nfc_path: RelPath::parse("sess.bin").unwrap(),
        src_version: SourceVersion {
            node_id: None,
            size: ONEDRIVE_CHUNK_ALIGN_BYTES,
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
    faults.push(
        "upload.status",
        InjectedFault::service_unavailable(Some("0")),
    );
    assert_eq!(
        backend_503.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );
    assert_eq!(faults.op_requests("upload.status"), 2);
    assert_eq!(
        ctrl_503.snapshot().retry_quota_available,
        ctrl_503.snapshot().retry_quota_max
    );

    // Also verify copy monitor polling retries transient 503 via `execute_with_policy`!
    faults.push(
        "copy.monitor",
        InjectedFault::service_unavailable(Some("0")),
    );
    let copy_init = UploadInit {
        op_id: "op-copy-mon-503".into(),
        dst_path: RelPath::parse("hello_copy.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: b"hello-quota".len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let ep = backend_503.endpoint_identity();
    let copied = backend_503
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()),
            &copy_init,
        )
        .await
        .unwrap()
        .expect("server-side copy should recover from transient 503 on copy monitor");
    assert_eq!(copied.size, b"hello-quota".len() as u64);
    assert_eq!(faults.op_requests("copy.monitor"), 2);
    assert_eq!(
        ctrl_503.snapshot().retry_quota_available,
        ctrl_503.snapshot().retry_quota_max
    );
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn onedrive_http_500_retries_without_tripping_cubic_throttle() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.items_by_path.insert(
            "err500/file.txt".into(),
            MockItem {
                id: "od-500".into(),
                path: "err500/file.txt".into(),
                is_folder: false,
                data: b"payload-500".to_vec(),
                last_modified: "2026-11-24T12:00:00Z".into(),
            },
        );
    }
    let faults = state.lock().unwrap().fault_injector();

    let backend = make_custom_backend(
        "od-500",
        &base_url,
        Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od")),
        TransportConfig::default(),
        4,
        Duration::from_millis(5),
        Duration::from_millis(25),
    );
    let control_limiter = backend.control_limiter();
    assert!(!control_limiter.snapshot().cubic_enabled);

    // Single HTTP 500 on `about()` retries, recovers, refunds quota, and does NOT trip CUBIC.
    faults.push(
        "drive.get",
        InjectedFault::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":{"code":"generalException","message":"transient 500"}}"#,
        ),
    );
    let quota = backend.about().await.unwrap().unwrap();
    assert_eq!(quota.total_bytes, Some(100_000_000));
    assert_eq!(faults.op_requests("drive.get"), 2);
    assert_eq!(faults.op_faults("drive.get"), 1);
    assert!(
        !control_limiter.snapshot().cubic_enabled,
        "HTTP 500 must NOT trip CUBIC throttle"
    );
    assert_eq!(
        control_limiter.snapshot().retry_quota_available,
        control_limiter.snapshot().retry_quota_max
    );

    // Consecutive 500, 502, 504 on `stat()` all retry cleanly WITHOUT tripping CUBIC.
    faults.push_many(
        "items.get",
        [
            InjectedFault::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":{"code":"generalException","message":"500"}}"#,
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
    assert_eq!(faults.op_requests("items.get"), 4);
    assert_eq!(faults.op_faults("items.get"), 3);
    assert!(
        !control_limiter.snapshot().cubic_enabled,
        "HTTP 500/502/504 must NOT trip CUBIC throttle"
    );
    // 3 retries charged 3 * 5 = 15 tokens; successful recovery refunded exact 5-token retry_cost.
    assert_eq!(
        control_limiter.snapshot().retry_quota_available,
        control_limiter.snapshot().retry_quota_max - 10
    );
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn onedrive_single_flight_401_refresh_and_exhausted_retries() {
    let (base_url, state) = start_mock_graph().await;
    {
        let mut g = state.lock().unwrap();
        g.valid_token = Some("tok-fresh-v2".into());
        g.next_refreshed_token = Some("tok-fresh-v2".into());
        g.items_by_path.insert(
            "secret.bin".into(),
            MockItem {
                id: "od-sec".into(),
                path: "secret.bin".into(),
                is_folder: false,
                data: b"protected-onedrive-data".to_vec(),
                last_modified: "2026-11-24T12:00:00Z".into(),
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
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg));
    let transport = HttpTransport::new(transport_cfg).unwrap();

    // Seed store with a non-expired but server-revoked token (`tok-stale-v1`) so initial
    // requests hit 401 and trigger single-flight `force_refresh` via `/oauth2/v2.0/token`.
    let now = SystemClock::shared().now_unix_secs();
    let store = Arc::new(InMemoryTokenStore::new(Some(OnedriveToken {
        access_token: "tok-stale-v1".into(),
        refresh_token: Some("refresh-secret-1".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: now + 3600,
        scope: None,
    })));
    let auth = Arc::new(
        OnedriveOAuth2Auth::new(
            "cid-od",
            Some("csec-od".into()),
            format!("{base_url}/oauth2/v2.0/token"),
            "Files.ReadWrite.All offline_access",
            "alice@outlook.com",
            transport.clone(),
            store,
        )
        .unwrap(),
    );
    let mut cfg = OnedriveConfig::new("od-401")
        .with_max_retries(2)
        .with_retry_delays(Duration::from_millis(5), Duration::from_millis(20));
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.token_url = format!("{base_url}/oauth2/v2.0/token");
    let backend = Arc::new(OnedriveBackend::new(cfg, auth, transport).unwrap());
    let ctrl = backend.control_limiter();

    // 1. 4 concurrent `stat()` calls hit 401 simultaneously -> single-flight refresh runs
    //    EXACTLY ONCE, all 4 succeed, ZERO retry quota burned, CUBIC untouched!
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let b = backend.clone();
        tasks.push(tokio::spawn(async move {
            b.stat(&BackendPath::from_rel(
                RelPath::parse("secret.bin").unwrap(),
            ))
            .await
            .unwrap()
            .expect("secret.bin should resolve after single-flight 401 refresh")
        }));
    }
    for t in tasks {
        let entry = t.await.unwrap();
        assert_eq!(entry.size, b"protected-onedrive-data".len() as u64);
    }
    assert_eq!(
        state.lock().unwrap().token_refreshes,
        1,
        "concurrent 401s must deduplicate into a single OAuth2 token refresh"
    );
    assert_eq!(
        ctrl.snapshot().retry_quota_available,
        ctrl.snapshot().retry_quota_max,
        "401 auth refresh must NOT burn retry quota"
    );
    assert!(!ctrl.snapshot().cubic_enabled);

    // 2. Data-plane `open_range` also refreshes cleanly on 401 when the server rotates tokens.
    {
        let mut g = state.lock().unwrap();
        g.valid_token = Some("tok-fresh-v3".into());
        g.next_refreshed_token = Some("tok-fresh-v3".into());
    }
    let data = read_onedrive_all(&backend, &RelPath::parse("secret.bin").unwrap()).await;
    assert_eq!(data, b"protected-onedrive-data");
    assert_eq!(state.lock().unwrap().token_refreshes, 2);
    assert_eq!(
        ctrl.snapshot().retry_quota_available,
        ctrl.snapshot().retry_quota_max
    );

    // 3. Persistent 401 even after refresh fails fast with PermissionDenied without looping
    //    (at most 1 refresh -> 2 HTTP attempts total).
    let reqs_before_401 = faults.op_requests("drive.get");
    faults.push_many(
        "drive.get",
        [
            InjectedFault::json_error(StatusCode::UNAUTHORIZED, r#"{"error":"still-401-a"}"#),
            InjectedFault::json_error(StatusCode::UNAUTHORIZED, r#"{"error":"still-401-b"}"#),
        ],
    );
    let err_401 = backend
        .about()
        .await
        .expect_err("persistent 401 after refresh must fail with PermissionDenied");
    assert_eq!(err_401.kind, ErrorKind::PermissionDenied);
    assert_eq!(faults.op_requests("drive.get") - reqs_before_401, 2);
    assert_eq!(state.lock().unwrap().token_refreshes, 3);
    assert_eq!(
        ctrl.snapshot().retry_quota_available,
        ctrl.snapshot().retry_quota_max
    );

    // 4. Exhausted retries (max_retries = 2 -> 3 attempts) return `err.retries_exhausted() == true`
    //    for both HTTP 500 (no CUBIC) and HTTP 503 (with CUBIC).
    let reqs_before_500 = faults.op_requests("items.get");
    faults.push_many(
        "items.get",
        [
            InjectedFault::json_error(StatusCode::INTERNAL_SERVER_ERROR, "500-1"),
            InjectedFault::json_error(StatusCode::INTERNAL_SERVER_ERROR, "500-2"),
            InjectedFault::json_error(StatusCode::INTERNAL_SERVER_ERROR, "500-3"),
        ],
    );
    let err_500 = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("secret.bin").unwrap(),
        ))
        .await
        .expect_err("3 consecutive 500s with max_retries=2 must exhaust retries");
    assert!(
        err_500.retries_exhausted(),
        "exhausted 500 must set retries_exhausted() == true, got {err_500:?}"
    );
    assert!(!err_500.is_retryable());
    assert_eq!(err_500.kind, ErrorKind::Network);
    assert_eq!(err_500.retry, RetryClass::Retryable);
    assert!(!ctrl.snapshot().cubic_enabled);
    assert_eq!(faults.op_requests("items.get") - reqs_before_500, 3);

    let reqs_before_503 = faults.op_requests("drive.get");
    faults.push_many(
        "drive.get",
        [
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
        ],
    );
    let err_503 = backend
        .about()
        .await
        .expect_err("3 consecutive 503s with max_retries=2 must exhaust retries");
    assert!(
        err_503.retries_exhausted(),
        "exhausted 503 must set retries_exhausted() == true, got {err_503:?}"
    );
    assert!(!err_503.is_retryable());
    assert_eq!(err_503.kind, ErrorKind::RateLimited);
    assert_eq!(err_503.retry, RetryClass::Throttled);
    assert!(ctrl.snapshot().cubic_enabled);
    assert_eq!(faults.op_requests("drive.get") - reqs_before_503, 3);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn onedrive_mid_body_reset_on_download_surfaces_retryable_network_error_and_recovers() {
    let (src_url, src_state) = start_mock_graph().await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 29 + 7) & 0xFF) as u8)
        .collect();
    let rel = RelPath::parse("download/reset.bin").unwrap();

    let src_backend = make_custom_backend(
        "od-src-reset",
        &src_url,
        Arc::new(StaticBearerAuth::new("src@outlook.com", "tok-src")),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    seed_onedrive_file(&src_backend, &rel, payload.clone()).await;

    let faults = src_state.lock().unwrap().fault_injector();

    // 1. Direct `open_range` stream receives prefix bytes then aborts with retryable Network error.
    let prefix = Bytes::from_static(b"partial-onedrive-prefix");
    faults.push(
        "items.content",
        InjectedFault::mid_body_reset(prefix.clone()),
    );

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

    // Subsequent download recovers bit-exact.
    assert_eq!(read_onedrive_all(&src_backend, &rel).await, payload);

    // 2. End-to-end TransferEngine download recovery (distinct mock OneDrive destination so
    //    server-side copy is ineligible and full streaming download runs through retry recovery).
    let (dst_url, _dst_state) = start_mock_graph().await;
    let dst_backend = make_custom_backend(
        "od-dst-reset",
        &dst_url,
        Arc::new(StaticBearerAuth::new("dst@outlook.com", "tok-dst")),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    faults.push(
        "items.content",
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
    let mut ecfg = EngineConfig::new("job-od-reset", JobMode::Copy, "od-src", "od-dst");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(read_onedrive_all(&dst_backend, &rel).await, payload);
    assert_eq!(faults.op_faults("items.content"), 2);
    assert_eq!(faults.op_requests("items.content"), 4);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn onedrive_slow_finalize_on_final_upload_fragment_and_long_copy_succeeds() {
    let (base_url, state) = start_mock_graph().await;
    let faults = state.lock().unwrap().fault_injector();

    // Short `data_stall_timeout` (80ms) and `control_timeout` (120ms), but generous
    // `data_finalize_timeout` (2s) and `long_control_timeout` (2s), with zero retries.
    let transport_cfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(120))
        .with_long_control_timeout(Duration::from_secs(2))
        .with_data_stall_timeout(Duration::from_millis(80))
        .with_data_finalize_timeout(Duration::from_secs(2));

    let backend = make_custom_backend(
        "od-slow-finalize",
        &base_url,
        Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od")),
        transport_cfg,
        0,
        Duration::from_millis(5),
        Duration::from_millis(20),
    );

    // 1. SlowFinalize (240ms > 80ms data_stall_timeout, < 2s data_finalize_timeout) on final
    //    resumable upload fragment (400 KiB = 320 KiB aligned chunk + 80 KiB final fragment).
    let payload: Vec<u8> = (0..(400 * 1024))
        .map(|i| ((i * 19 + 3) % 251) as u8)
        .collect();
    let dst_rel = RelPath::parse("slow/final_fragment.bin").unwrap();
    let init = UploadInit {
        op_id: "op-slow-frag".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-slow-frag".into(),
        job_id: "j-slow-frag".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: dst_rel.as_str().into(),
        dst_raw_path: dst_rel.as_str().into(),
        dst_nfc_path: dst_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
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

    faults.push(
        "upload.chunk_final",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let t_frag = std::time::Instant::now();
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
        .expect("final upload fragment SlowFinalize must succeed under data_finalize_timeout");
    assert!(
        t_frag.elapsed() >= Duration::from_millis(200),
        "expected SlowFinalize wait (~240ms), elapsed={:?}",
        t_frag.elapsed()
    );
    assert!(ack2.completed.is_some());
    assert_eq!(faults.op_requests("upload.chunk_final"), 1);
    assert_eq!(faults.op_faults("upload.chunk_final"), 1);
    assert_eq!(read_onedrive_all(&backend, &dst_rel).await, payload);

    // 2. SlowFinalize on single-shot `PUT /content` (non-empty AND 0-byte empty file)
    //    transitions cleanly to `data_finalize_timeout`.
    for (rel_s, data) in [
        ("slow/single.bin", vec![0xABu8; 4096]),
        ("slow/empty.bin", Vec::new()),
    ] {
        let rel = RelPath::parse(rel_s).unwrap();
        let ss_init = UploadInit {
            op_id: format!("op-slow-{rel_s}"),
            dst_path: rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: data.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        faults.push(
            "upload.simple",
            InjectedFault::slow_finalize(Duration::from_millis(240)),
        );
        let t0 = std::time::Instant::now();
        let body_stream: rship_core::source::ByteStream = if data.is_empty() {
            Box::pin(futures::stream::empty())
        } else {
            let d = data.clone();
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(d)) }))
        };
        let entry = backend
            .put_single_shot(&ss_init, body_stream)
            .await
            .expect("single-shot SlowFinalize must succeed under data_finalize_timeout");
        assert!(
            t0.elapsed() >= Duration::from_millis(200),
            "expected SlowFinalize wait (~240ms) for {rel_s}, elapsed={:?}",
            t0.elapsed()
        );
        assert_eq!(entry.size, data.len() as u64);
    }

    // 3. Slow server-side copy initiation (`POST /items/{id}/copy`) uses `long_control_timeout`
    //    (2s), surviving a 240ms delay > 120ms `control_timeout`.
    faults.push(
        "items.copy",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let copy_rel = RelPath::parse("slow/copied.bin").unwrap();
    let copy_init = UploadInit {
        op_id: "op-slow-copy".into(),
        dst_path: copy_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(&ep, &BackendPath::from_rel(dst_rel), &copy_init)
        .await
        .expect("items.copy must use long_control_timeout")
        .expect("items.copy should return copied entry");
    assert_eq!(copied.size, payload.len() as u64);
    assert_eq!(faults.op_faults("items.copy"), 1);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[test]
fn onedrive_bearer_authorization_header_is_marked_sensitive() {
    let secret = "onedrive-oauth-secret-token-987654";
    let hdr = OnedriveBackend::bearer_header(secret).expect("valid Bearer header");
    assert!(
        hdr.is_sensitive(),
        "OneDrive Bearer Authorization header must be marked sensitive (is_sensitive() == true)"
    );
    assert_eq!(hdr.as_bytes(), format!("Bearer {secret}").as_bytes());
    assert!(
        !format!("{hdr:?}").contains(secret),
        "Debug formatting of sensitive Bearer header must not leak token material"
    );

    let err = OnedriveBackend::bearer_header("top-secret\r\nX-Injected: 1").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Protocol);
    assert!(
        !err.message().contains("top-secret"),
        "invalid header error must not leak raw token material: {}",
        err.message()
    );
}

#[tokio::test]
async fn onedrive_c3_streaming_sha256_upload_and_download_verification() {
    use rship_core::types::{Checksum, HashKind};

    let (base_url, state) = start_mock_graph().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = OnedriveConfig::new("od-c3");
    cfg.api_base_url = format!("{base_url}/v1.0");
    let auth = Arc::new(StaticBearerAuth::new("alice@outlook.com", "tok-od-c3"));
    let backend = OnedriveBackend::new(cfg, auth, transport).unwrap();

    let payload = b"onedrive c3 streaming sha256 end-to-end verification payload bytes!".to_vec();
    let expected_sha256 = hex_encode(&Sha256::digest(&payload));
    let good_path = RelPath::parse("c3/good.bin").unwrap();

    // (a1) Clean multi-chunk streaming upload succeeds with matching SHA-256 (case-insensitive).
    let good_init = UploadInit {
        op_id: "op-od-c3-good".into(),
        dst_path: good_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Sha256,
            hex: expected_sha256.to_ascii_uppercase(),
        }],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let good_chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(19)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let entry = backend
        .put_single_shot(&good_init, Box::pin(futures::stream::iter(good_chunks)))
        .await
        .expect("matching SHA-256 upload must succeed");
    assert_eq!(entry.size, payload.len() as u64);

    // (a2) Streaming upload corruption detection (empty `init.checksums` -> caught purely by
    //      `StreamingHashStream<_, Sha256Hasher>` against mismatched server `sha256Hash`!).
    state.lock().unwrap().corrupt_upload_sha256_once = true;
    let bad_init = UploadInit {
        op_id: "op-od-c3-bad".into(),
        dst_path: RelPath::parse("c3/bad-upload.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let bad_chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(13)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let upload_err = backend
        .put_single_shot(&bad_init, Box::pin(futures::stream::iter(bad_chunks)))
        .await
        .expect_err("mismatched server sha256Hash must fail streaming upload");
    assert_eq!(upload_err.kind, ErrorKind::Integrity);
    assert!(upload_err.is_integrity());
    assert!(
        upload_err
            .message()
            .contains("OneDrive upload checksum mismatch (SHA-256)"),
        "unexpected upload error: {}",
        upload_err.message()
    );

    // (a3) Known `init.checksums` SHA-256 mismatch against server `sha256Hash` also fails!
    let mismatch_known_init = UploadInit {
        op_id: "op-od-c3-known-mismatch".into(),
        dst_path: RelPath::parse("c3/known-mismatch.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Sha256,
            hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        }],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_c = payload.clone();
    let known_err = backend
        .put_single_shot(
            &mismatch_known_init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .expect_err("mismatched init.checksums SHA-256 must fail upload");
    assert_eq!(known_err.kind, ErrorKind::Integrity);
    assert!(known_err.is_integrity());
    assert!(known_err.message().contains("checksum mismatch"));

    // (b) Full-object download detects in-transit body corruption against metadata SHA-256!
    let reader = match backend
        .open_read(&BackendPath::from_rel(good_path.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    state.lock().unwrap().corrupt_download_body_once = true;
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
    let dl_err =
        dl_err.expect("corrupted full-object OneDrive download must fail SHA-256 verification");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(
        dl_err.message().contains("checksum mismatch"),
        "unexpected download error: {}",
        dl_err.message()
    );

    // Clean full-object download via `open_read_entry` succeeds bit-exact.
    let entry_reader = match backend
        .open_read_entry(&entry, &BackendPath::from_rel(good_path), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut full_stream = entry_reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut full_got = Vec::new();
    while let Some(item) = full_stream.next().await {
        full_got.extend_from_slice(&item.unwrap());
    }
    assert_eq!(full_got, payload);

    // (c) Sub-range downloads (`offset > 0` or `len < total_len`) succeed without false SHA-256 error!
    for range in [
        ByteRange { offset: 0, len: 15 },
        ByteRange {
            offset: 11,
            len: 23,
        },
        ByteRange {
            offset: payload.len() as u64 - 9,
            len: 9,
        },
    ] {
        let mut s = entry_reader.open_range(range).await.unwrap();
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

// =========================================================================
// C3: QuickXorHash verification (the only hash OneDrive for Business returns)
// =========================================================================

fn c3_backend(base_url: &str, name: &str) -> Arc<OnedriveBackend> {
    make_custom_backend(
        name,
        base_url,
        Arc::new(StaticBearerAuth::new("bob@contoso.com", "tok-od-qxh")),
        TransportConfig::default(),
        0,
        Duration::from_millis(5),
        Duration::from_millis(20),
    )
}

fn c3_init(op_id: &str, path: &RelPath, total: u64) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: ONEDRIVE_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

fn c3_session_op(
    backend: &OnedriveBackend,
    init: &UploadInit,
    sess: rship_core::backend::UploadSessionInit,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sk-{}", init.op_id),
        job_id: "j-od-qxh".into(),
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
    }
}

/// Upload `data[start..]` through the session in 320 KiB fragments, each streamed in odd
/// item sizes, the way the engine's sequential loop does.
async fn c3_drive_session(
    backend: &OnedriveBackend,
    op: &OperationRecord,
    data: &[u8],
    start: u64,
) -> rship_core::Result<rship_core::types::Entry> {
    let total = data.len() as u64;
    let mut offset = start;
    loop {
        let len = (total - offset).min(ONEDRIVE_CHUNK_ALIGN_BYTES);
        let items: Vec<rship_core::Result<Bytes>> = data[offset as usize..(offset + len) as usize]
            .chunks(70_001)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let ack = backend
            .upload_chunk(
                op,
                ChunkUpload::new(
                    1,
                    offset,
                    len,
                    total,
                    Box::pin(futures::stream::iter(items)),
                ),
            )
            .await?;
        if let Some(entry) = ack.completed {
            return Ok(entry);
        }
        offset = ack.next_offset.unwrap();
    }
}

fn c3_payload(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37 + seed) % 253) as u8).collect()
}

async fn c3_read_full(backend: &OnedriveBackend, rel: &RelPath) -> rship_core::Result<Vec<u8>> {
    let DataSource::RemoteRangeReadable(rr) = backend
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await?
    else {
        panic!("expected RemoteRangeReadable");
    };
    let mut stream = rr
        .open_range(ByteRange {
            offset: 0,
            len: rr.total_len(),
        })
        .await?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

#[tokio::test]
async fn onedrive_c3_single_shot_upload_verifies_quickxor_when_no_sha256_is_returned() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().business_hashes_only = true;
    let backend = c3_backend(&base_url, "od-c3-qxh-single");
    let payload = c3_payload(40_000, 1);

    // Clean upload: the streamed QuickXorHash matches the server's.
    let ok_path = RelPath::parse("c3/qxh-ok.bin").unwrap();
    let p = payload.clone();
    backend
        .put_single_shot(
            &c3_init("op-od-qxh-ok", &ok_path, payload.len() as u64),
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p)) })),
        )
        .await
        .expect("matching quickXorHash upload must succeed");

    // The server reports a different quickXorHash than what was streamed.
    state.lock().unwrap().corrupt_upload_quickxor_once = true;
    let bad_path = RelPath::parse("c3/qxh-bad.bin").unwrap();
    let p = payload.clone();
    let err = backend
        .put_single_shot(
            &c3_init("op-od-qxh-bad", &bad_path, payload.len() as u64),
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p)) })),
        )
        .await
        .expect_err("a mismatched quickXorHash must fail the upload");
    assert!(
        err.message().contains("checksum mismatch (QuickXorHash)"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn onedrive_c3_upload_session_running_quickxor_detects_corrupted_fragment() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().business_hashes_only = true;
    let backend = c3_backend(&base_url, "od-c3-qxh-session");
    let payload = c3_payload((2 * ONEDRIVE_CHUNK_ALIGN_BYTES + 12_345) as usize, 5);

    // Clean three-fragment session upload verifies against the final quickXorHash.
    let ok_path = RelPath::parse("c3/session-ok.bin").unwrap();
    let init = c3_init("op-od-qxh-sess-ok", &ok_path, payload.len() as u64);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = c3_session_op(&backend, &init, sess);
    let entry = c3_drive_session(&backend, &op, &payload, 0)
        .await
        .expect("clean session upload must succeed");
    assert_eq!(entry.size, payload.len() as u64);

    // A fragment corrupted in transit changes the server's quickXorHash for the whole file.
    let bad_path = RelPath::parse("c3/session-bad.bin").unwrap();
    let init = c3_init("op-od-qxh-sess-bad", &bad_path, payload.len() as u64);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = c3_session_op(&backend, &init, sess);
    state.lock().unwrap().corrupt_next_session_fragment = true;
    let err = c3_drive_session(&backend, &op, &payload, 0)
        .await
        .expect_err("corrupted fragment must fail the final quickXorHash check");
    assert!(
        err.message().contains("checksum mismatch (QuickXorHash)"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn onedrive_c3_upload_session_resumed_by_new_process_completes_unverified() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().business_hashes_only = true;
    let payload = c3_payload((ONEDRIVE_CHUNK_ALIGN_BYTES + 777) as usize, 9);
    let path = RelPath::parse("c3/session-resumed.bin").unwrap();
    let init = c3_init("op-od-qxh-resume", &path, payload.len() as u64);

    let first = c3_backend(&base_url, "od-c3-qxh-resume");
    let sess = first.begin_upload(&init).await.unwrap();
    let op = c3_session_op(&first, &init, sess);
    let head = payload[..ONEDRIVE_CHUNK_ALIGN_BYTES as usize].to_vec();
    let ack = first
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                ONEDRIVE_CHUNK_ALIGN_BYTES,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(head)) })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack.next_offset, Some(ONEDRIVE_CHUNK_ALIGN_BYTES));

    // A new process has no running hash for the session: it must still finish the upload
    // (unverified) instead of failing or claiming a comparison.
    let second = c3_backend(&base_url, "od-c3-qxh-resume");
    let entry = c3_drive_session(&second, &op, &payload, ONEDRIVE_CHUNK_ALIGN_BYTES)
        .await
        .expect("resumed session must complete");
    assert_eq!(entry.size, payload.len() as u64);
    assert_eq!(
        state.lock().unwrap().items_by_path["c3/session-resumed.bin"].data,
        payload
    );
}

#[tokio::test]
async fn onedrive_c3_full_download_verifies_quickxor_when_no_sha256_is_returned() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().business_hashes_only = true;
    let backend = c3_backend(&base_url, "od-c3-qxh-download");
    let payload = c3_payload(50_000, 3);
    let path = RelPath::parse("c3/qxh-download.bin").unwrap();
    seed_onedrive_file(&backend, &path, payload.clone()).await;

    assert_eq!(c3_read_full(&backend, &path).await.unwrap(), payload);

    state.lock().unwrap().corrupt_download_body_once = true;
    let err = c3_read_full(&backend, &path)
        .await
        .expect_err("corrupted full download must fail quickXorHash verification");
    assert!(
        err.message().contains("checksum mismatch (QuickXorHash)"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn onedrive_202_without_next_expected_ranges_requeries_the_session() {
    use crate::mock_server::OmitRanges;

    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().business_hashes_only = true;
    let backend = c3_backend(&base_url, "od-202-no-ranges");
    let align = ONEDRIVE_CHUNK_ALIGN_BYTES;
    let payload = c3_payload((2 * align + 4_321) as usize, 13);
    let path = RelPath::parse("c3/202-no-ranges.bin").unwrap();
    let init = c3_init("op-od-202-no-ranges", &path, payload.len() as u64);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = c3_session_op(&backend, &init, sess);
    let fragment = |off: u64| {
        let bytes = payload[off as usize..(off + align) as usize].to_vec();
        ChunkUpload::new(
            1,
            off,
            align,
            payload.len() as u64,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(bytes)) })),
        )
    };

    // The fragment was NOT kept: the session still expects offset 0.
    state.lock().unwrap().omit_next_expected_ranges = Some(OmitRanges {
        drop_fragment: true,
    });
    let ack = backend.upload_chunk(&op, fragment(0)).await.unwrap();
    assert_eq!(
        ack.next_offset,
        Some(0),
        "a 202 without nextExpectedRanges must not be read as the fragment landing"
    );

    // The fragment WAS kept: the re-query reports the real next offset.
    state.lock().unwrap().omit_next_expected_ranges = Some(OmitRanges {
        drop_fragment: false,
    });
    let ack = backend.upload_chunk(&op, fragment(0)).await.unwrap();
    assert_eq!(ack.next_offset, Some(align));

    // The rest of the session completes intact and still verifies its QuickXorHash.
    let entry = c3_drive_session(&backend, &op, &payload, align)
        .await
        .expect("session must complete after the re-queries");
    assert_eq!(entry.size, payload.len() as u64);
    assert_eq!(
        state.lock().unwrap().items_by_path["c3/202-no-ranges.bin"].data,
        payload
    );
}

fn od_session_requests(faults: &crate::common::FaultInjector) -> (usize, usize) {
    (
        faults.op_requests("upload.create_session"),
        faults.op_requests("upload.status"),
    )
}

/// Engine-level C3 check for an integrity failure found only AFTER OneDrive committed the
/// item (the final fragment's `quickXorHash` reveals a corrupted fragment).
///
/// Such a commit must never be accepted through `query_upload` -> `AlreadyCompleted`. The
/// engine discards it and restarts from a fresh session, a bounded number of times; `move`
/// deletes its source only after a verified transfer.
#[tokio::test]
async fn onedrive_engine_move_never_accepts_a_corrupted_session_commit() {
    let (src_url, src_state) = start_mock_graph().await;
    let src_backend = c3_backend(&src_url, "od-int-src");
    let len = (ONEDRIVE_CHUNK_ALIGN_BYTES + 80 * 1024) as usize;
    let transient = RelPath::parse("move/transient.bin").unwrap();
    let persistent = RelPath::parse("move/persistent.bin").unwrap();
    let transient_data = c3_payload(len, 17);
    let persistent_data = c3_payload(len, 29);

    let (dst_url, dst_state) = start_mock_graph().await;
    let dst_faults = {
        let mut g = dst_state.lock().unwrap();
        g.business_hashes_only = true;
        g.fault_injector()
    };
    let dst_backend = c3_backend(&dst_url, "od-int-dst");
    let src_has = |rel: &RelPath| {
        src_state
            .lock()
            .unwrap()
            .items_by_path
            .contains_key(rel.as_str())
    };
    let dst_data = |rel: &RelPath| {
        dst_state
            .lock()
            .unwrap()
            .items_by_path
            .get(rel.as_str())
            .map(|it| it.data.clone())
    };

    let run = |job: &str| {
        let engine = TransferEngine::new(
            src_backend.clone(),
            dst_backend.clone(),
            Arc::new(StateActor::open_in_memory().unwrap()),
            BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
            SystemClock::shared(),
            CancelFlag::new(),
        );
        let mut ecfg = EngineConfig::new(job, JobMode::Move, "od-int-src", "od-int-dst");
        ecfg.base_retry_delay = Duration::from_millis(5);
        async move {
            engine
                .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
                .await
                .unwrap()
        }
    };

    // 1. Corrupted once: the commit is discarded and re-sent through a NEW session; the
    //    source is deleted only after the verified second transfer.
    seed_onedrive_file(&src_backend, &transient, transient_data.clone()).await;
    dst_state.lock().unwrap().corrupt_next_session_fragment = true;
    let rep = run("job-od-int-transient").await;
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(
        od_session_requests(&dst_faults),
        (2, 0),
        "a fresh session, never a status query that could return AlreadyCompleted"
    );
    assert_eq!(dst_data(&transient), Some(transient_data));
    assert!(!src_has(&transient));

    // 2. Corrupted on every attempt: the run ends with the integrity error, the corrupt
    //    object this run created is removed, and `move` keeps its source.
    seed_onedrive_file(&src_backend, &persistent, persistent_data.clone()).await;
    dst_state.lock().unwrap().corrupt_every_first_fragment = true;
    let rep = run("job-od-int-persistent").await;
    assert!(
        !rep.is_success(),
        "a persistently corrupted commit must fail the run"
    );
    assert_eq!(rep.files_transferred, 0, "{rep:?}");
    let result = rep
        .file_results
        .iter()
        .find(|r| r.path == persistent.as_str())
        .expect("file result for the corrupted path");
    assert_eq!(
        result.error_kind,
        Some(ErrorKind::Integrity),
        "got: {result:?}"
    );
    assert!(
        rep.errors
            .iter()
            .any(|e| e.contains("checksum mismatch (QuickXorHash)")),
        "got: {:?}",
        rep.errors
    );
    assert_eq!(
        od_session_requests(&dst_faults).1,
        0,
        "the corrupted session must never be re-queried into an AlreadyCompleted acceptance"
    );
    assert!(
        src_has(&persistent),
        "move must keep its source after an integrity failure"
    );
    assert_eq!(
        dst_data(&persistent),
        None,
        "corrupt object must not be left behind"
    );

    // 3. Once the path is clean again a re-run moves the file verified.
    dst_state.lock().unwrap().corrupt_every_first_fragment = false;
    let rep = run("job-od-int-clean").await;
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(dst_data(&persistent), Some(persistent_data));
    assert!(!src_has(&persistent));
}

/// `reconcile_operation` must prove an item is this operation's result. An older item of
/// the same size (even with the source's mtime) at the destination must never come back
/// `Committed`, e.g. after the upload session expired.
#[tokio::test]
async fn onedrive_reconcile_never_accepts_an_older_same_size_item() {
    use rship_core::backend::ReconcileOutcome;

    let (base_url, state) = start_mock_graph().await;
    let backend = c3_backend(&base_url, "od-reconcile");
    let len = (ONEDRIVE_CHUNK_ALIGN_BYTES + 1_000) as usize;
    let old = c3_payload(len, 1);
    let new = c3_payload(len, 2);
    let path = RelPath::parse("reconcile/same-size.bin").unwrap();
    // The older item even carries the new source's mtime: only the eTag tells them apart.
    let mtime = 1_700_000_000_000_000_000;
    backend
        .put_single_shot(
            &UploadInit {
                src_mtime_ns: mtime,
                ..c3_init("op-od-old", &path, old.len() as u64)
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(old)) })),
        )
        .await
        .unwrap();
    let old_entry = backend
        .stat(&BackendPath::from_rel(path.clone()))
        .await
        .unwrap()
        .unwrap();

    // 1. Upload session that expires before committing.
    let init = UploadInit {
        src_mtime_ns: mtime,
        ..c3_init("op-od-new", &path, new.len() as u64)
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let mut op = c3_session_op(&backend, &init, sess);
    op.dst_precondition = DstPrecondition::Any;
    let head = new[..ONEDRIVE_CHUNK_ALIGN_BYTES as usize].to_vec();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                ONEDRIVE_CHUNK_ALIGN_BYTES,
                new.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(head)) })),
            ),
        )
        .await
        .unwrap();
    state.lock().unwrap().sessions.clear();
    let outcome = backend.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "older same-size item must not be accepted: {outcome:?}"
    );

    // 2. Single-shot op (no session snapshot): the planner's precondition eTag is the proof.
    let mut single = op.clone();
    single.backend_meta = String::new();
    single.session_token = None;
    single.dst_precondition = DstPrecondition::Existing {
        node_id: old_entry.node_id.clone(),
        etag: old_entry.etag.clone(),
        mtime_ns: old_entry.mtime_ns,
        size: old_entry.size,
    };
    let outcome = backend.reconcile_operation(&single).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "{outcome:?}"
    );

    // 3. Nothing recorded about the pre-op item: it cannot be proven ours, so the engine
    // re-transfers instead of trusting it.
    single.dst_precondition = DstPrecondition::Any;
    let outcome = backend.reconcile_operation(&single).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "{outcome:?}"
    );

    // 4. A session that really committed is recognised.
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = c3_session_op(&backend, &init, sess);
    c3_drive_session(&backend, &op, &new, 0).await.unwrap();
    let outcome = backend.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "{outcome:?}"
    );
}
