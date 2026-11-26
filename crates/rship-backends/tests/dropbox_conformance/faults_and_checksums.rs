use crate::common::InjectedFault;
use crate::mock_server::{MockDropboxState, MockEntry, make_backend, spawn_mock_dropbox};
use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use rship_backends::dropbox::backend::{
    build_content_upload_headers, build_download_headers, build_rpc_headers,
};
use rship_backends::dropbox::{
    DropboxAuthProvider, DropboxBackend, DropboxConfig, DropboxOAuth2Auth, DropboxToken,
    dropbox_content_hash,
};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, HashKind};
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::oauth::{InMemoryTokenStore, StaticBearerAuth};
use rship_transport::{
    HttpTransport, LimiterPlane, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// =========================================================================
// Fault-injection, retry-policy, OAuth401, watchdog, and C8 tests
// =========================================================================

fn make_custom_backend(
    remote_name: &str,
    base_url: &str,
    auth: Arc<dyn DropboxAuthProvider>,
    transport_cfg: TransportConfig,
    max_retries: u32,
    base_retry_delay: Duration,
    max_retry_delay: Duration,
) -> Arc<DropboxBackend> {
    let mut cfg = DropboxConfig::new(remote_name)
        .with_max_retries(max_retries)
        .with_retry_delays(base_retry_delay, max_retry_delay);
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    cfg.token_url = format!("{base_url}/oauth2/token");
    cfg.chunk_align_override = Some(64 * 1024);
    cfg.default_chunk_size = 64 * 1024;
    let transport = HttpTransport::new(transport_cfg).unwrap();
    Arc::new(DropboxBackend::new(cfg, auth, transport).unwrap())
}

fn seed_mock_file(state: &Arc<Mutex<MockDropboxState>>, path: &str, data: &[u8]) {
    let mut g = state.lock().unwrap();
    g.ensure_parents(path);
    let id = g.alloc_id("id:file");
    let rev = g.alloc_id("rev");
    let entry = MockEntry {
        id,
        path: path.to_string(),
        is_folder: false,
        data: data.to_vec(),
        rev,
        client_modified: "2026-11-25T02:00:00Z".into(),
    };
    g.entries.insert(MockDropboxState::key(path), entry);
}

async fn read_dropbox_all(backend: &DropboxBackend, rel: &RelPath) -> Vec<u8> {
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
async fn dropbox_scripted_429_and_503_recovery_refunds_exact_retry_quota() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_mock_file(&state, "/quota/item.txt", b"hello-dropbox-quota");
    let faults = state.lock().unwrap().fault_injector();

    let quota_cfg = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let transport_cfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg));

    // Part A: Scripted 429 (`too_many_write_operations` + `Retry-After: 3600` clamped to
    // `max_retry_delay = 60ms`) on `list_folder` recovers cleanly, trips control CUBIC only
    // (leaving data plane isolated), and refunds exact 5-token retry quota back to `max_tokens`.
    let backend_429 = make_custom_backend(
        "dbx-429",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-429", "dbx-test-token")),
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

    faults.push(
        "list_folder",
        InjectedFault::json_error(
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"error_summary":"too_many_write_operations/."}"#,
        )
        .with_retry_after("3600"),
    );
    let t0 = std::time::Instant::now();
    let listed: Vec<_> = backend_429
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let elapsed_429 = t0.elapsed();

    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "quota/item.txt")
    );
    assert!(
        elapsed_429 >= Duration::from_millis(45) && elapsed_429 < Duration::from_secs(2),
        "Retry-After: 3600 must be honored and clamped to 60ms, elapsed={elapsed_429:?}"
    );
    assert_eq!(faults.op_requests("list_folder"), 2);
    assert_eq!(faults.op_faults("list_folder"), 1);

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

    // Part B: Scripted 429 with JSON `error.retry_after: 3600` (no HTTP Retry-After header)
    // on `copy_v2` also clamps delay to `max_retry_delay` and refunds exact retry quota.
    faults.push(
        "copy_v2",
        InjectedFault::json_error(
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"error_summary":"too_many_write_operations/.","error":{".tag":"too_many_write_operations","retry_after":3600}}"#,
        ),
    );
    let copy_init = UploadInit {
        op_id: "op-copy-429".into(),
        dst_path: RelPath::parse("quota/copied.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: b"hello-dropbox-quota".len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = backend_429.endpoint_identity();
    let t_copy = std::time::Instant::now();
    let copied = backend_429
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("quota/item.txt").unwrap()),
            &copy_init,
        )
        .await
        .unwrap()
        .expect("copy_v2 should recover from 429");
    let elapsed_copy = t_copy.elapsed();
    assert_eq!(copied.size, b"hello-dropbox-quota".len() as u64);
    assert!(
        elapsed_copy >= Duration::from_millis(45) && elapsed_copy < Duration::from_secs(2),
        "JSON error.retry_after must be clamped to 60ms, elapsed={elapsed_copy:?}"
    );
    assert_eq!(
        ctrl_429.snapshot().retry_quota_available,
        ctrl_429.snapshot().retry_quota_max
    );

    // Part C: Scripted 503 Service Unavailable on `get_metadata` (`stat`) trips control CUBIC
    // and refunds exact 5-token retry quota back to `max_tokens`.
    let backend_503 = make_custom_backend(
        "dbx-503",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-503", "dbx-test-token")),
        transport_cfg.clone(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    let ctrl_503 = backend_503.control_limiter();
    assert!(!ctrl_503.snapshot().cubic_enabled);

    faults.push(
        "get_metadata",
        InjectedFault::service_unavailable(Some("0")),
    );
    let entry = backend_503
        .stat(&BackendPath::from_rel(
            RelPath::parse("quota/item.txt").unwrap(),
        ))
        .await
        .unwrap()
        .expect("stat should recover after 503");
    assert_eq!(entry.size, b"hello-dropbox-quota".len() as u64);
    assert_eq!(faults.op_requests("get_metadata"), 2);
    assert_eq!(faults.op_faults("get_metadata"), 1);

    let snap_503 = ctrl_503.snapshot();
    assert!(snap_503.cubic_enabled, "503 must activate control CUBIC");
    assert_eq!(
        snap_503.retry_quota_available, snap_503.retry_quota_max,
        "503 recovery must refund exact 5-token retry quota back to max_tokens"
    );

    // Part D: Scripted 500 Internal Server Error retries and refunds quota WITHOUT tripping CUBIC.
    let backend_500 = make_custom_backend(
        "dbx-500",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-500", "dbx-test-token")),
        transport_cfg,
        3,
        Duration::from_millis(5),
        Duration::from_millis(25),
    );
    let ctrl_500 = backend_500.control_limiter();
    faults.push(
        "get_metadata",
        InjectedFault::json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    );
    let entry_500 = backend_500
        .stat(&BackendPath::from_rel(
            RelPath::parse("quota/item.txt").unwrap(),
        ))
        .await
        .unwrap()
        .expect("stat should recover after 500");
    assert_eq!(entry_500.size, b"hello-dropbox-quota".len() as u64);
    assert!(
        !ctrl_500.snapshot().cubic_enabled,
        "HTTP 500 must NOT trip CUBIC throttle"
    );
    assert_eq!(
        ctrl_500.snapshot().retry_quota_available,
        ctrl_500.snapshot().retry_quota_max
    );
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn dropbox_retries_transport_errors_on_control_rpcs_and_refunds_quota() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_mock_file(&state, "/rpc/reset.txt", b"transport-retry-payload");
    let faults = state.lock().unwrap().fault_injector();

    let quota_cfg = RetryQuotaConfig {
        max_tokens: 50,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let transport_cfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg));

    let backend = make_custom_backend(
        "dbx-transport-retry",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-transport", "dbx-test-token")),
        transport_cfg.clone(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    let ctrl = backend.control_limiter();

    // 1. MidBodyReset on JSON RPC `get_metadata` (reproduces old Dropbox bug where transport
    //    errors aborted immediately without retry).
    faults.push(
        "get_metadata",
        InjectedFault::mid_body_reset(Bytes::from_static(br#"{".tag":"file","id":"id:trunc"#)),
    );
    let entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("rpc/reset.txt").unwrap(),
        ))
        .await
        .expect("stat must retry and recover from MidBodyReset")
        .expect("file must exist");
    assert_eq!(entry.size, b"transport-retry-payload".len() as u64);
    assert_eq!(faults.op_requests("get_metadata"), 2);
    assert_eq!(faults.op_faults("get_metadata"), 1);
    assert_eq!(
        ctrl.snapshot().retry_quota_available,
        ctrl.snapshot().retry_quota_max
    );
    assert!(!ctrl.snapshot().cubic_enabled);

    // 2. MidBodyReset on `list_folder` AND `copy_v2` both recover via shared retry policy.
    faults.push("list_folder", InjectedFault::mid_body_reset(Bytes::new()));
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
            .any(|e| e.nfc_path.as_str() == "rpc/reset.txt")
    );
    assert_eq!(faults.op_requests("list_folder"), 2);
    assert_eq!(faults.op_faults("list_folder"), 1);

    faults.push(
        "copy_v2",
        InjectedFault::mid_body_reset(Bytes::from_static(b"{\"metadata\":")),
    );
    let copy_init = UploadInit {
        op_id: "op-copy-reset".into(),
        dst_path: RelPath::parse("rpc/copied.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: b"transport-retry-payload".len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("rpc/reset.txt").unwrap()),
            &copy_init,
        )
        .await
        .expect("copy_v2 must retry and recover from MidBodyReset")
        .expect("copy_v2 returned entry");
    assert_eq!(copied.size, b"transport-retry-payload".len() as u64);
    assert_eq!(faults.op_requests("copy_v2"), 2);
    assert_eq!(
        ctrl.snapshot().retry_quota_available,
        ctrl.snapshot().retry_quota_max
    );

    // 3. Abrupt TCP connection drop on first attempt before any HTTP status line is written ->
    //    second connection returns valid `users/get_space_usage` JSON.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        // Attempt 1: accept and drop immediately (abrupt EOF / connection reset).
        let (mut sock1, _) = listener.accept().await.unwrap();
        let mut scratch = [0u8; 512];
        let _ = sock1.read(&mut scratch).await;
        drop(sock1);

        // Attempt 2: serve valid HTTP/1.1 200 JSON response.
        let (mut sock2, _) = listener.accept().await.unwrap();
        let mut req_buf = [0u8; 2048];
        let _ = sock2.read(&mut req_buf).await;
        let json = br#"{"used":42,"allocation":{".tag":"individual","allocated":1000}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            json.len()
        );
        sock2.write_all(resp.as_bytes()).await.unwrap();
        sock2.write_all(json).await.unwrap();
        let _ = sock2.shutdown().await;
    });

    let drop_backend = make_custom_backend(
        "dbx-tcp-drop",
        &format!("http://{raw_addr}"),
        Arc::new(StaticBearerAuth::new("dbx-tcp-drop", "dbx-test-token")),
        transport_cfg,
        3,
        Duration::from_millis(5),
        Duration::from_millis(25),
    );
    let quota = drop_backend
        .about()
        .await
        .expect("about() must retry and recover after abrupt TCP connection drop")
        .expect("quota present");
    assert_eq!(quota.used_bytes, Some(42));
    assert_eq!(quota.total_bytes, Some(1000));
    assert_eq!(
        drop_backend
            .control_limiter()
            .snapshot()
            .retry_quota_available,
        drop_backend.control_limiter().snapshot().retry_quota_max
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn dropbox_single_flight_401_refresh_preserves_retry_quota_and_exhausted_retries_flag() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_mock_file(&state, "/auth/secret.txt", b"after-refresh-ok");

    // Part A: Single-flight 401 refresh across 4 concurrent RPCs with `max_retries = 0`.
    // Setting `max_retries = 0` proves 401 refresh consumes neither retry attempts nor retry quota!
    {
        let mut g = state.lock().unwrap();
        g.valid_token = "dbx-other-unmatched".to_string();
        g.refreshed_token = "dbx-fresh-token-1".to_string();
        g.oauth_refresh_delay = Some(Duration::from_millis(30));
    }

    let quota_cfg = RetryQuotaConfig {
        max_tokens: 10,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let transport_cfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota_cfg));
    let transport = HttpTransport::new(transport_cfg.clone()).unwrap();

    let store = Arc::new(InMemoryTokenStore::new(Some(DropboxToken {
        access_token: "dbx-stale-token".to_string(),
        refresh_token: Some("dbx-refresh-tok".to_string()),
        token_type: "Bearer".to_string(),
        expires_at_unix_secs: 4_102_444_800, // far future so stale token is sent on the wire -> 401
        scope: None,
    })));
    let oauth = Arc::new(
        DropboxOAuth2Auth::new(
            "dbx-client-id",
            Some("dbx-client-secret".to_string()),
            format!("{base_url}/oauth2/token"),
            "dbx-oauth-singleflight",
            transport.clone(),
            store,
        )
        .unwrap(),
    );

    let mut cfg = DropboxConfig::new("dbx-401-singleflight")
        .with_max_retries(0)
        .with_retry_delays(Duration::from_millis(5), Duration::from_millis(20));
    cfg.api_base_url = format!("{base_url}/2");
    cfg.content_base_url = format!("{base_url}/2");
    cfg.token_url = format!("{base_url}/oauth2/token");
    let backend_oauth = Arc::new(DropboxBackend::new(cfg, oauth, transport).unwrap());
    let ctrl_oauth = backend_oauth.control_limiter();

    let p = BackendPath::from_rel(RelPath::parse("auth/secret.txt").unwrap());
    let (r1, r2, r3, r4) = tokio::join!(
        backend_oauth.stat(&p),
        backend_oauth.stat(&p),
        backend_oauth.about(),
        backend_oauth.about(),
    );
    assert_eq!(
        r1.expect("concurrent stat 1").unwrap().size,
        b"after-refresh-ok".len() as u64
    );
    assert_eq!(
        r2.expect("concurrent stat 2").unwrap().size,
        b"after-refresh-ok".len() as u64
    );
    assert_eq!(
        r3.expect("concurrent about 1").unwrap().used_bytes,
        Some(100_000_000)
    );
    assert_eq!(
        r4.expect("concurrent about 2").unwrap().used_bytes,
        Some(100_000_000)
    );

    assert_eq!(
        state.lock().unwrap().oauth_refresh_calls,
        1,
        "4 concurrent 401s must coalesce into a single OAuth2 token refresh"
    );
    let snap_oauth = ctrl_oauth.snapshot();
    assert_eq!(
        snap_oauth.retry_quota_available, snap_oauth.retry_quota_max,
        "401 auth refresh must NOT burn retry quota"
    );
    assert!(!snap_oauth.cubic_enabled);

    // Part B: Persistent 401 even after refresh fails immediately with PermissionDenied
    // without looping or burning retry quota.
    {
        let mut g = state.lock().unwrap();
        g.valid_token = "dbx-unreachable-token".to_string();
        g.refreshed_token = "dbx-still-rejected-token".to_string();
        g.reject_refreshed_token = true;
        g.oauth_refresh_delay = None;
    }
    let transport_b = HttpTransport::new(transport_cfg.clone()).unwrap();
    let store_b = Arc::new(InMemoryTokenStore::new(Some(DropboxToken {
        access_token: "dbx-bad-initial".to_string(),
        refresh_token: Some("dbx-refresh-tok".to_string()),
        token_type: "Bearer".to_string(),
        expires_at_unix_secs: 4_102_444_800,
        scope: None,
    })));
    let oauth_b = Arc::new(
        DropboxOAuth2Auth::new(
            "dbx-client-id",
            None,
            format!("{base_url}/oauth2/token"),
            "dbx-oauth-reject",
            transport_b.clone(),
            store_b,
        )
        .unwrap(),
    );
    let mut cfg_b = DropboxConfig::new("dbx-401-reject").with_max_retries(2);
    cfg_b.api_base_url = format!("{base_url}/2");
    cfg_b.content_base_url = format!("{base_url}/2");
    let backend_reject = Arc::new(DropboxBackend::new(cfg_b, oauth_b, transport_b).unwrap());

    let refresh_before = state.lock().unwrap().oauth_refresh_calls;
    let err_401 = backend_reject
        .stat(&p)
        .await
        .expect_err("persistent 401 after refresh must fail");
    assert_eq!(err_401.kind, ErrorKind::PermissionDenied);
    assert_eq!(err_401.retry, RetryClass::Permanent);
    assert_eq!(
        state.lock().unwrap().oauth_refresh_calls,
        refresh_before + 1,
        "must attempt refresh at most once per request"
    );
    assert_eq!(
        backend_reject
            .control_limiter()
            .snapshot()
            .retry_quota_available,
        backend_reject.control_limiter().snapshot().retry_quota_max
    );

    // Part C: Exhausted retries return `err.retries_exhausted() == true` (both HTTP 503 & transport).
    {
        let mut g = state.lock().unwrap();
        g.valid_token = "dbx-test-token".to_string();
        g.reject_refreshed_token = false;
    }
    let faults = state.lock().unwrap().fault_injector();
    faults.reset_telemetry();

    let backend_exhaust = make_custom_backend(
        "dbx-exhaust",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-exhaust", "dbx-test-token")),
        TransportConfig::default(),
        2,
        Duration::from_millis(5),
        Duration::from_millis(20),
    );
    faults.push_many(
        "list_folder",
        [
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
        ],
    );
    let mut stream = backend_exhaust
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap();
    let err_503 = stream
        .next()
        .await
        .expect("stream must yield error item")
        .expect_err("persistent 503 must exhaust retries");
    assert!(
        err_503.retries_exhausted(),
        "exhausted 503 must set retries_exhausted() == true, got {err_503:?}"
    );
    assert!(!err_503.is_retryable());
    assert_eq!(err_503.kind, ErrorKind::RateLimited);
    assert_eq!(err_503.retry, RetryClass::Throttled);
    assert_eq!(faults.op_requests("list_folder"), 3);

    faults.push_many(
        "get_metadata",
        [
            InjectedFault::mid_body_reset(Bytes::from_static(b"{\"partial\":1")),
            InjectedFault::mid_body_reset(Bytes::from_static(b"{\"partial\":2")),
            InjectedFault::mid_body_reset(Bytes::from_static(b"{\"partial\":3")),
        ],
    );
    let err_transport = backend_exhaust
        .stat(&p)
        .await
        .expect_err("persistent MidBodyReset must exhaust retries");
    assert!(
        err_transport.retries_exhausted(),
        "exhausted transport error must set retries_exhausted() == true, got {err_transport:?}"
    );
    assert!(!err_transport.is_retryable());
    assert_eq!(err_transport.kind, ErrorKind::Network);
    assert_eq!(faults.op_requests("get_metadata"), 3);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn dropbox_mid_body_reset_on_download_surfaces_retryable_network_error_and_recovers() {
    let (src_url, src_state) = spawn_mock_dropbox().await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 31 + 13) & 0xFF) as u8)
        .collect();
    let rel = RelPath::parse("download/reset.bin").unwrap();

    let src_backend = make_custom_backend(
        "dbx-src-reset",
        &src_url,
        Arc::new(StaticBearerAuth::new("dbx-src-principal", "dbx-test-token")),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    let upload_init = UploadInit {
        op_id: "op-dbx-seed-reset".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
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

    // 1. Direct download stream receives prefix bytes then fails with retryable Network error.
    let prefix = Bytes::from_static(b"partial-dropbox-download-prefix");
    faults.push("download", InjectedFault::mid_body_reset(prefix.clone()));

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

    // Subsequent read recovers bit-exact.
    assert_eq!(read_dropbox_all(&src_backend, &rel).await, payload);

    // 2. End-to-end TransferEngine download recovery (distinct principal/server so server-side
    //    copy is ineligible and streaming download runs through TransferEngine retry recovery).
    let (dst_url, _) = spawn_mock_dropbox().await;
    let dst_backend = make_custom_backend(
        "dbx-dst-reset",
        &dst_url,
        Arc::new(StaticBearerAuth::new("dbx-dst-principal", "dbx-test-token")),
        TransportConfig::default(),
        3,
        Duration::from_millis(5),
        Duration::from_millis(30),
    );
    faults.push(
        "download",
        InjectedFault::mid_body_reset(Bytes::from_static(b"corrupt-partial-dbx-chunk")),
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
    let mut ecfg = EngineConfig::new("job-dbx-reset", JobMode::Copy, "dbx-src", "dbx-dst");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(read_dropbox_all(&dst_backend, &rel).await, payload);
    assert_eq!(faults.op_faults("download"), 2);
    assert_eq!(faults.op_requests("download"), 4);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn dropbox_slow_finalize_on_upload_finish_and_copy_succeeds_without_false_stall_timeout() {
    let (base_url, state) = spawn_mock_dropbox().await;
    let faults = state.lock().unwrap().fault_injector();

    // Short data_stall_timeout (80ms) and control_timeout (120ms), but generous
    // data_finalize_timeout (2s) and long_control_timeout (2s).
    let transport_cfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(120))
        .with_long_control_timeout(Duration::from_secs(2))
        .with_data_stall_timeout(Duration::from_millis(80))
        .with_data_finalize_timeout(Duration::from_secs(2));

    let backend = make_custom_backend(
        "dbx-slow-finalize",
        &base_url,
        Arc::new(StaticBearerAuth::new("dbx-slow", "dbx-test-token")),
        transport_cfg,
        0,
        Duration::from_millis(5),
        Duration::from_millis(20),
    );

    // 1. SlowFinalize (220ms > 80ms data_stall_timeout, < 2s data_finalize_timeout) on
    //    sized non-empty `put_single_shot` (`/files/upload`).
    let single_rel = RelPath::parse("slow/single.bin").unwrap();
    let single_data = vec![0xABu8; 4096];
    let single_init = UploadInit {
        op_id: "op-dbx-slow-single".into(),
        dst_path: single_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: single_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: single_data.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    faults.push(
        "upload",
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
        .expect("files/upload SlowFinalize must succeed under data_finalize_timeout");
    assert!(
        t0.elapsed() >= Duration::from_millis(180),
        "SlowFinalize must actually wait for server response, elapsed={:?}",
        t0.elapsed()
    );
    assert_eq!(entry.size, single_data.len() as u64);
    assert_eq!(read_dropbox_all(&backend, &single_rel).await, single_data);

    // 2. SlowFinalize (220ms) on 0-byte `put_single_shot` verifies immediate `mark_body_eof()`.
    let empty_rel = RelPath::parse("slow/empty.bin").unwrap();
    let empty_init = UploadInit {
        op_id: "op-dbx-slow-empty".into(),
        dst_path: empty_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 0,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 0,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    faults.push(
        "upload",
        InjectedFault::slow_finalize(Duration::from_millis(220)),
    );
    let empty_entry = backend
        .put_single_shot(&empty_init, Box::pin(futures::stream::empty()))
        .await
        .expect("0-byte files/upload SlowFinalize must succeed under data_finalize_timeout");
    assert_eq!(empty_entry.size, 0);
    assert_eq!(faults.op_faults("upload"), 2);

    // 3. SlowFinalize (220ms) on `upload_chunk` (`append_v2` AND final `finish` with payload).
    let chunk_sz = 64 * 1024u64;
    let tail_sz = 1024u64;
    let total_sz = chunk_sz + tail_sz;
    let sess_rel = RelPath::parse("slow/session.bin").unwrap();
    let sess_init = UploadInit {
        op_id: "op-dbx-slow-sess".into(),
        dst_path: sess_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&sess_init).await.unwrap();
    let op = OperationRecord {
        op_id: sess_init.op_id.clone(),
        session_key: "sk-dbx-slow".into(),
        job_id: "j-dbx-slow".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: sess_rel.as_str().into(),
        dst_raw_path: sess_rel.as_str().into(),
        dst_nfc_path: sess_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total_sz,
            mtime_ns: sess_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "dropbox".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: chunk_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    faults.push(
        "upload_session_append_v2",
        InjectedFault::slow_finalize(Duration::from_millis(220)),
    );
    let p1 = vec![0x33u8; chunk_sz as usize];
    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1)) })),
            ),
        )
        .await
        .expect("upload_session/append_v2 SlowFinalize must succeed under data_finalize_timeout");
    assert_eq!(ack1.next_offset, Some(chunk_sz));

    faults.push(
        "upload_session_finish",
        InjectedFault::slow_finalize(Duration::from_millis(220)),
    );
    let p2 = vec![0x44u8; tail_sz as usize];
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk_sz,
                tail_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .expect("final upload_chunk SlowFinalize must succeed under data_finalize_timeout");
    assert_eq!(ack2.completed.expect("committed entry").size, total_sz);

    // 4. SlowFinalize (240ms > 120ms `control_timeout`, < 2s `long_control_timeout`) on
    //    0-byte `finish_upload` (`files/upload_session/finish`) verifies `long_control_timeout`.
    let fin_rel = RelPath::parse("slow/finish_rpc.bin").unwrap();
    let fin_init = UploadInit {
        op_id: "op-dbx-slow-fin".into(),
        dst_path: fin_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: chunk_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let fin_sess = backend.begin_upload(&fin_init).await.unwrap();
    let fin_op = OperationRecord {
        op_id: fin_init.op_id.clone(),
        session_key: "sk-dbx-fin".into(),
        job_id: "j-dbx-fin".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: fin_rel.as_str().into(),
        dst_raw_path: fin_rel.as_str().into(),
        dst_nfc_path: fin_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: chunk_sz,
            mtime_ns: fin_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: fin_sess.remote_op_id,
        backend_kind: "dropbox".into(),
        session_token: Some(fin_sess.session_token),
        backend_meta: fin_sess.backend_meta,
        planned_chunk_size: chunk_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let fin_bytes = vec![0x77u8; chunk_sz as usize];
    let _ = backend
        .upload_chunk(
            &fin_op,
            ChunkUpload::new(
                1,
                0,
                chunk_sz,
                chunk_sz + 1, // non-final so append_v2 runs without committing yet
                Box::pin(futures::stream::once(
                    async move { Ok(Bytes::from(fin_bytes)) },
                )),
            ),
        )
        .await
        .unwrap();
    faults.push(
        "upload_session_finish",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let committed_fin = backend
        .finish_upload(&fin_op, &[])
        .await
        .expect("finish_upload must use long_control_timeout");
    assert_eq!(committed_fin.size, chunk_sz);

    // 5. SlowFinalize (240ms > 120ms `control_timeout`, < 2s `long_control_timeout`) on
    //    `files/copy_v2` (`server_side_copy`) verifies `long_control_timeout`.
    faults.push(
        "copy_v2",
        InjectedFault::slow_finalize(Duration::from_millis(240)),
    );
    let copy_rel = RelPath::parse("slow/copied.bin").unwrap();
    let copy_init = UploadInit {
        op_id: "op-dbx-slow-copy".into(),
        dst_path: copy_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: chunk_sz,
        src_mtime_ns: fin_init.src_mtime_ns,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(&ep, &BackendPath::from_rel(fin_rel), &copy_init)
        .await
        .expect("files/copy_v2 must use long_control_timeout")
        .expect("copy_v2 returned committed entry");
    assert_eq!(copied.size, chunk_sz);
    assert_eq!(faults.op_faults("copy_v2"), 1);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[test]
fn dropbox_authorization_headers_are_marked_sensitive() {
    let secret = "sl.dropbox-conformance-secret-token";
    let expected = format!("Bearer {secret}");

    let rpc = build_rpc_headers(secret).unwrap();
    let upload = build_content_upload_headers(secret, r#"{"path":"/x.bin"}"#, 512).unwrap();
    let download = build_download_headers(secret, r#"{"path":"/x.bin"}"#, 0, 511).unwrap();

    for (label, hdrs) in [
        ("rpc_post", rpc),
        ("content_upload", upload),
        ("files/download", download),
    ] {
        let auth = hdrs
            .get(http::header::AUTHORIZATION)
            .unwrap_or_else(|| panic!("{label}: Authorization header must be present"));
        assert!(
            auth.is_sensitive(),
            "{label}: Authorization header must be marked sensitive (is_sensitive() == true)"
        );
        assert_eq!(auth.to_str().unwrap(), expected);
        assert!(
            !format!("{auth:?}").contains(secret),
            "{label}: Debug output for sensitive Authorization header must not leak token"
        );
    }
}

#[tokio::test]
async fn dropbox_c3_streaming_content_hash_upload_and_download_verification() {
    use rship_core::types::Checksum;
    use sha2::{Digest as _, Sha256};

    let (base_url, state) = spawn_mock_dropbox().await;
    let backend = make_backend(&base_url);

    let payload = b"dropbox c3 streaming content_hash end-to-end verification payload!".to_vec();
    let expected_ch = dropbox_content_hash(&payload);
    let sha256_hex = hex::encode(Sha256::digest(&payload));

    // (a) Known single-block SHA-256 in `init.checksums` derives and sends exact `"content_hash"`
    //     in `Dropbox-API-Arg` on `/files/upload`!
    let path = RelPath::parse("c3/known-hash.bin").unwrap();
    let init = UploadInit {
        op_id: "op-dbx-c3-known".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Sha256,
            hex: sha256_hex,
        }],
        precondition: DstPrecondition::Any,
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
            .seen_upload_content_hashes
            .last()
            .map(String::as_str),
        Some(expected_ch.as_str()),
        "Dropbox /files/upload must send derived content_hash in Dropbox-API-Arg"
    );

    // (b) Streaming upload computes Dropbox content_hash incrementally on-the-fly and rejects
    //     mismatched server-returned `content_hash`!
    state.lock().unwrap().corrupt_upload_content_hash_once = true;
    let bad_init = UploadInit {
        op_id: "op-dbx-c3-bad".into(),
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
    let chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(17)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let upload_err = backend
        .put_single_shot(&bad_init, Box::pin(futures::stream::iter(chunks)))
        .await
        .expect_err("corrupted Dropbox response content_hash must fail upload");
    assert_eq!(upload_err.kind, ErrorKind::Integrity);
    assert!(upload_err.is_integrity());
    assert!(upload_err.message().contains("checksum mismatch"));

    // (c) Full-object download detects corrupted payload bytes against `dropbox-api-result` `content_hash`!
    let reader = match backend
        .open_read(&BackendPath::from_rel(path), None)
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
    let dl_err = dl_err.expect("corrupted full-object Dropbox download must fail checksum check");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(dl_err.message().contains("checksum mismatch"));

    // (d) Sub-range downloads (`offset > 0` or `len < total_len`) do NOT falsely fail!
    for range in [
        ByteRange { offset: 0, len: 14 },
        ByteRange { offset: 9, len: 19 },
        ByteRange {
            offset: payload.len() as u64 - 11,
            len: 11,
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
