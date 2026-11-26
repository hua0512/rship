use crate::common::InjectedFault;
use crate::mock_server::{make_backend, simple_crc32c, spawn_mock_gcs};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::gcs::{GCS_CHUNK_ALIGN_BYTES, GcsAuthProvider, GcsBackend, GcsConfig};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, HashKind};
use rship_core::{ErrorKind, Result, RetryClass};
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{
    HttpTransport, LimiterScope, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// =========================================================================
// Fault Injection & Shared Policy Tests (Step 2e-4)
// =========================================================================

fn make_gcs_config(base_url: &str, remote_name: &str) -> GcsConfig {
    let mut cfg = GcsConfig::new(remote_name, "test-bucket");
    cfg.api_base_url = format!("{base_url}/storage/v1");
    cfg.upload_base_url = format!("{base_url}/upload/storage/v1");
    cfg.chunk_size = GCS_CHUNK_ALIGN_BYTES;
    cfg
}

struct MockRefreshingGcsAuth {
    principal: String,
    current_token: Mutex<String>,
    refreshed_token: String,
    refresh_calls: AtomicU32,
}

impl MockRefreshingGcsAuth {
    fn new(initial: &str, refreshed: &str, principal: &str) -> Self {
        Self {
            principal: principal.to_string(),
            current_token: Mutex::new(initial.to_string()),
            refreshed_token: refreshed.to_string(),
            refresh_calls: AtomicU32::new(0),
        }
    }

    fn refresh_calls(&self) -> u32 {
        self.refresh_calls.load(Ordering::SeqCst)
    }

    fn reset_token(&self, token: &str) {
        *self.current_token.lock().unwrap() = token.to_string();
    }
}

#[async_trait]
impl GcsAuthProvider for MockRefreshingGcsAuth {
    fn principal(&self) -> &str {
        &self.principal
    }

    async fn access_token(&self) -> Result<String> {
        Ok(self.current_token.lock().unwrap().clone())
    }

    async fn force_refresh(&self, failed_token: &str) -> Result<String> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.current_token.lock().unwrap();
        if *guard == failed_token {
            *guard = self.refreshed_token.clone();
        }
        Ok(guard.clone())
    }
}

/// (a) Scripted 429 with `Retry-After` and 503 recovery with accurate retry quota refund
/// (`available == max_tokens` after recovery) and CUBIC activation on control plane.
#[tokio::test]
async fn gcs_fault_429_retry_after_and_503_recover_with_exact_quota_refund() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload = b"gcs-retry-quota-refund-payload".to_vec();
    let faults = {
        let mut g = state.lock().unwrap();
        g.seed_object("quota/target.txt", payload.clone());
        g.faults.clone()
    };

    let quota = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let tcfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota));
    let transport = HttpTransport::new(tcfg).unwrap();

    let mut cfg = make_gcs_config(&base_url, "gcs-fault-429-503");
    cfg.max_retries = 4;
    cfg.base_retry_delay = Duration::from_millis(10);
    cfg.max_retry_delay = Duration::from_millis(120);
    let scope = LimiterScope::new(&cfg.remote_name, "gcs-test");
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport.clone()).unwrap();
    let ctrl_limiter = transport.control_limiter_for(scope.clone());
    let data_limiter = transport.data_limiter_for(scope);

    assert_eq!(ctrl_limiter.snapshot().retry_quota_available, 100);
    assert!(!ctrl_limiter.snapshot().cubic_enabled);

    // 1. 429 with Retry-After: 2 (capped strictly to max_retry_delay = 120ms) recovers & refunds exact quota.
    faults.push("GetObjectMeta", InjectedFault::too_many_requests(Some("2")));
    let t0 = Instant::now();
    let entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("quota/target.txt").unwrap(),
        ))
        .await
        .expect("429 with Retry-After must recover")
        .expect("object exists");
    let elapsed = t0.elapsed();
    assert_eq!(entry.size, payload.len() as u64);
    assert!(
        elapsed >= Duration::from_millis(90) && elapsed < Duration::from_millis(1500),
        "Retry-After: 2 must be honored and capped by max_retry_delay (120ms), took {elapsed:?}"
    );
    assert_eq!(faults.op_requests("GetObjectMeta"), 2);
    let snap_429 = ctrl_limiter.snapshot();
    assert!(snap_429.cubic_enabled, "429 must activate CUBIC throttle");
    assert_eq!(
        snap_429.retry_quota_available, snap_429.retry_quota_max,
        "429 recovery must refund exact retry quota back to max_tokens"
    );

    // 2. 503 Service Unavailable recovers & refunds exact quota back to max_tokens.
    faults.push("ListObjects", InjectedFault::service_unavailable(Some("0")));
    let page = backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect("503 must recover");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(faults.op_requests("ListObjects"), 2);
    let snap_503 = ctrl_limiter.snapshot();
    assert_eq!(
        snap_503.retry_quota_available, snap_503.retry_quota_max,
        "503 recovery must refund exact retry quota back to max_tokens"
    );
    assert!(
        !data_limiter.snapshot().cubic_enabled,
        "control-plane 429/503 throttling must stay isolated from data_limiter"
    );
}

/// (b) HTTP 500 (plus 502/504) retries WITHOUT tripping CUBIC throttle (`!cubic_enabled`),
/// whereas HTTP 503 DOES activate CUBIC.
#[tokio::test]
async fn gcs_fault_http_500_retries_without_tripping_cubic() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload = b"gcs-500-no-cubic".to_vec();
    let faults = {
        let mut g = state.lock().unwrap();
        g.seed_object("transient/file.bin", payload.clone());
        g.faults.clone()
    };

    let quota = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let tcfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota));
    let transport = HttpTransport::new(tcfg).unwrap();

    let mut cfg = make_gcs_config(&base_url, "gcs-fault-500");
    cfg.max_retries = 4;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(25);
    let scope = LimiterScope::new(&cfg.remote_name, "gcs-test");
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport.clone()).unwrap();
    let ctrl_limiter = transport.control_limiter_for(scope);

    // 500, 502, and 504 must each retry and recover WITHOUT enabling CUBIC.
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        faults.push(
            "GetObjectMeta",
            InjectedFault::json_error(status, r#"{"error":"transient backend error"}"#),
        );
        let entry = backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("transient/file.bin").unwrap(),
            ))
            .await
            .expect("5xx transient error must retry and recover")
            .expect("object exists");
        assert_eq!(entry.size, payload.len() as u64);
        let snap = ctrl_limiter.snapshot();
        assert!(
            !snap.cubic_enabled,
            "HTTP {} must NOT trip CUBIC throttle",
            status.as_u16()
        );
        assert_eq!(
            snap.retry_quota_available,
            snap.retry_quota_max,
            "HTTP {} recovery must refund exact retry quota",
            status.as_u16()
        );
    }
    assert_eq!(faults.op_requests("GetObjectMeta"), 6);

    // Contrast: HTTP 503 on the exact same control limiter MUST activate CUBIC.
    faults.push(
        "GetObjectMeta",
        InjectedFault::service_unavailable(Some("0")),
    );
    let entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("transient/file.bin").unwrap(),
        ))
        .await
        .expect("503 must recover")
        .expect("object exists");
    assert_eq!(entry.size, payload.len() as u64);
    assert!(
        ctrl_limiter.snapshot().cubic_enabled,
        "HTTP 503 MUST activate CUBIC throttle"
    );
}

/// (c) Single-flight 401 refresh retries without consuming retry quota (even at `max_retries=0`),
/// refreshes at most once on persistent 401, and exhausted retries return `retries_exhausted() == true`.
#[tokio::test]
async fn gcs_fault_401_single_flight_refresh_and_retries_exhausted() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload = b"gcs-401-refresh-and-exhausted".to_vec();
    let faults = {
        let mut g = state.lock().unwrap();
        g.expected_token = "fresh-gcs-token-2".to_string();
        g.seed_object("auth/item.txt", payload.clone());
        g.faults.clone()
    };

    let quota = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let tcfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota));
    let transport = HttpTransport::new(tcfg).unwrap();

    // Part 1: Even with max_retries == 0, 401 triggers single-flight refresh and succeeds with 0 quota consumed!
    let mut cfg = make_gcs_config(&base_url, "gcs-fault-401");
    cfg.max_retries = 0;
    let scope = LimiterScope::new(&cfg.remote_name, "refresh-principal");
    let auth = Arc::new(MockRefreshingGcsAuth::new(
        "stale-gcs-token-1",
        "fresh-gcs-token-2",
        "refresh-principal",
    ));
    let backend = GcsBackend::new(cfg, Some(auth.clone()), transport.clone()).unwrap();
    let ctrl_limiter = transport.control_limiter_for(scope);

    let entry = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("auth/item.txt").unwrap(),
        ))
        .await
        .expect("single-flight 401 refresh must succeed even with max_retries=0")
        .expect("object exists");
    assert_eq!(entry.size, payload.len() as u64);
    assert_eq!(auth.refresh_calls(), 1, "must invoke force_refresh once");
    assert_eq!(
        ctrl_limiter.snapshot().retry_quota_available,
        100,
        "401 refresh must not consume retry quota"
    );
    assert!(!ctrl_limiter.snapshot().cubic_enabled);

    // Persistent 401 (server rejects refreshed token too) calls force_refresh at most once and fails permanently.
    state.lock().unwrap().expected_token = "unmatchable-token".to_string();
    auth.reset_token("stale-again");
    let perm_err = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("auth/item.txt").unwrap(),
        ))
        .await
        .expect_err("persistent 401 after refresh must fail");
    assert_eq!(perm_err.kind, ErrorKind::PermissionDenied);
    assert_eq!(perm_err.retry, RetryClass::Permanent);
    assert_eq!(
        auth.refresh_calls(),
        2,
        "persistent 401 must invoke force_refresh at most once per call"
    );
    assert_eq!(ctrl_limiter.snapshot().retry_quota_available, 100);

    // Part 2: Exhausted retries return err.retries_exhausted() == true and deduct exact quota.
    state.lock().unwrap().expected_token = "fresh-gcs-token-2".to_string();
    auth.reset_token("fresh-gcs-token-2");
    let mut cfg_ex = make_gcs_config(&base_url, "gcs-fault-exhausted");
    cfg_ex.max_retries = 2;
    cfg_ex.base_retry_delay = Duration::from_millis(5);
    cfg_ex.max_retry_delay = Duration::from_millis(15);
    let scope_ex = LimiterScope::new(&cfg_ex.remote_name, "refresh-principal");
    let backend_ex = GcsBackend::new(cfg_ex, Some(auth.clone()), transport.clone()).unwrap();
    let ctrl_ex = transport.control_limiter_for(scope_ex);

    let reqs_before = faults.op_requests("GetObjectMeta");
    faults.push_many(
        "GetObjectMeta",
        (0..6).map(|_| InjectedFault::service_unavailable(Some("0"))),
    );
    let ex_err = backend_ex
        .stat(&BackendPath::from_rel(
            RelPath::parse("auth/item.txt").unwrap(),
        ))
        .await
        .expect_err("persistent 503 must exhaust retries");
    assert_eq!(ex_err.kind, ErrorKind::RateLimited);
    assert_eq!(ex_err.retry, RetryClass::Throttled);
    assert!(
        ex_err.retries_exhausted(),
        "exhausted retries must set retries_exhausted() == true"
    );
    assert!(
        !ex_err.is_retryable(),
        "retries_exhausted error must suppress outer is_retryable()"
    );
    assert_eq!(
        faults.op_requests("GetObjectMeta") - reqs_before,
        3,
        "must execute 1 initial + max_retries (2) attempts"
    );
    assert_eq!(
        ctrl_ex.snapshot().retry_quota_available,
        90,
        "2 failed retries must deduct 10 tokens (100 -> 90)"
    );
}

/// (d) Mid-body reset on download surfaces a retryable network error and recovers cleanly on retry.
#[tokio::test]
async fn gcs_fault_mid_body_reset_on_download_surfaces_retryable_network_error_and_recovers() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 29 + 11) % 251) as u8)
        .collect();
    let faults = {
        let mut g = state.lock().unwrap();
        g.seed_object("downloads/reset.bin", payload.clone());
        g.faults.clone()
    };

    let backend = make_backend(&base_url);
    let reader = match backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("downloads/reset.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };

    // Full-range mid-body reset -> retryable Network error, then clean full recovery.
    faults.push(
        "DownloadObject",
        InjectedFault::mid_body_reset(Bytes::from_static(b"partial-gcs-prefix")),
    );
    let mut stream = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .expect("206 header arrives before mid-body reset");
    let mut got_err = None;
    let mut partial_bytes = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => partial_bytes.extend_from_slice(&chunk),
            Err(e) => {
                got_err = Some(e);
                break;
            }
        }
    }
    let err = got_err.expect("mid-body reset must surface stream error");
    assert_eq!(err.kind, ErrorKind::Network, "got: {err:?}");
    assert_eq!(err.retry, RetryClass::Retryable, "got: {err:?}");
    assert!(err.is_retryable());
    assert!(!err.retries_exhausted());

    // Retry the same range -> recovers exact payload bit-for-bit.
    let mut recovered_stream = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .expect("clean retry open_range");
    let mut recovered = Vec::with_capacity(payload.len());
    while let Some(chunk) = recovered_stream.next().await {
        recovered.extend_from_slice(&chunk.expect("clean chunk"));
    }
    assert_eq!(recovered, payload);

    // Sub-range mid-body reset also surfaces retryable Network error and recovers cleanly.
    let sub_offset = 4096u64;
    let sub_len = 8192u64;
    faults.push(
        "DownloadObject",
        InjectedFault::mid_body_reset(Bytes::from_static(b"sub-prefix")),
    );
    let mut sub_stream = reader
        .open_range(ByteRange {
            offset: sub_offset,
            len: sub_len,
        })
        .await
        .expect("206 header for sub-range");
    let mut sub_err = None;
    while let Some(item) = sub_stream.next().await {
        if let Err(e) = item {
            sub_err = Some(e);
            break;
        }
    }
    let sub_err = sub_err.expect("sub-range mid-body reset must fail");
    assert_eq!(sub_err.kind, ErrorKind::Network);
    assert_eq!(sub_err.retry, RetryClass::Retryable);

    let mut sub_ok = reader
        .open_range(ByteRange {
            offset: sub_offset,
            len: sub_len,
        })
        .await
        .unwrap();
    let mut sub_buf = Vec::new();
    while let Some(chunk) = sub_ok.next().await {
        sub_buf.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(
        sub_buf,
        payload[sub_offset as usize..(sub_offset + sub_len) as usize]
    );
}

/// (e) Slow finalize (`SlowFinalize` > short `data_stall_timeout`, < `data_finalize_timeout`)
/// on resumable upload chunks succeeds without false stall timeout, while an actual pre-EOF
/// upload stall still trips `data_stall_timeout`.
#[tokio::test]
async fn gcs_fault_resumable_upload_slow_finalize_succeeds_without_false_stall_timeout() {
    let (base_url, state) = spawn_mock_gcs().await;
    let faults = state.lock().unwrap().faults.clone();

    let tcfg = TransportConfig::default()
        .with_data_stall_timeout(Duration::from_millis(150))
        .with_data_finalize_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let cfg = make_gcs_config(&base_url, "gcs-fault-slow-finalize");
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport).unwrap();

    let chunk_sz = GCS_CHUNK_ALIGN_BYTES;
    let tail_sz = 1024u64;
    let total_sz = chunk_sz + tail_sz;
    let res_path = RelPath::parse("resumable/slow-finalize.bin").unwrap();
    let init = UploadInit {
        op_id: "op-gcs-slow-finalize".into(),
        dst_path: res_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-slow-fin".into(),
        job_id: "j-slow-fin".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: res_path.as_str().into(),
        dst_raw_path: res_path.as_str().into(),
        dst_nfc_path: res_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total_sz,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "gcs".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: chunk_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Queue SlowFinalize (350ms > 150ms data_stall_timeout, < 5s data_finalize_timeout)
    // for BOTH the intermediate chunk (308) and final committing chunk (200 OK).
    faults.push(
        "UploadChunk",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    faults.push(
        "UploadChunk",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );

    let c1 = vec![0xAAu8; chunk_sz as usize];
    let t1 = Instant::now();
    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c1)) })),
            ),
        )
        .await
        .expect("intermediate chunk slow finalize must succeed");
    assert_eq!(ack1.next_offset, Some(chunk_sz));
    assert!(
        t1.elapsed() >= Duration::from_millis(300),
        "slow finalize delay must have been exercised on chunk 1"
    );

    let c2 = vec![0xBBu8; tail_sz as usize];
    let t2 = Instant::now();
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk_sz,
                tail_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c2)) })),
            ),
        )
        .await
        .expect("final chunk slow finalize must succeed without false stall timeout");
    assert!(ack2.completed.is_some());
    assert_eq!(ack2.completed.unwrap().size, total_sz);
    assert!(
        t2.elapsed() >= Duration::from_millis(300),
        "slow finalize delay must have been exercised on final chunk"
    );

    // Sanity check: an actual pre-EOF stall (> 150ms data_stall_timeout) MUST fail with Timeout.
    let stall_path = RelPath::parse("resumable/pre-eof-stall.bin").unwrap();
    let stall_init = UploadInit {
        op_id: "op-gcs-pre-eof-stall".into(),
        dst_path: stall_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: chunk_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let stall_sess = backend.begin_upload(&stall_init).await.unwrap();
    let mut stall_op = op;
    stall_op.op_id = stall_init.op_id;
    stall_op.dst_raw_path = stall_path.as_str().into();
    stall_op.dst_nfc_path = stall_path;
    stall_op.src_version.size = chunk_sz;
    stall_op.session_token = Some(stall_sess.session_token);
    stall_op.backend_meta = stall_sess.backend_meta;

    let stalled_stream: ByteStream =
        Box::pin(futures::stream::unfold(0u8, move |step| async move {
            match step {
                0 => Some((Ok(Bytes::from(vec![0xCCu8; 1024])), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_millis(450)).await;
                    Some((Ok(Bytes::from(vec![0xCCu8; chunk_sz as usize - 1024])), 2))
                }
                _ => None,
            }
        }));
    let stall_err = backend
        .upload_chunk(
            &stall_op,
            ChunkUpload::new(1, 0, chunk_sz, chunk_sz, stalled_stream),
        )
        .await
        .expect_err("pre-EOF stalled upload must trip short data_stall_timeout");
    assert_eq!(stall_err.kind, ErrorKind::Timeout, "got: {stall_err:?}");
    assert_eq!(stall_err.retry, RetryClass::Retryable);
    assert!(
        stall_err.message.contains("stalled"),
        "expected stall timeout message, got: {}",
        stall_err.message
    );
}

/// (f) Bearer `Authorization` header built by `GcsBackend` is marked `is_sensitive() == true`.
#[tokio::test]
async fn gcs_bearer_authorization_header_is_marked_sensitive() {
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let secret = "ya29.super-secret-gcs-bearer-token-987654";
    let auth = Some(Arc::new(StaticBearerAuth::new("sensitive-test", secret)) as _);
    let backend = GcsBackend::new(
        GcsConfig::new("gcs-sensitive", "test-bucket"),
        auth,
        transport.clone(),
    )
    .unwrap();

    let mut headers = HeaderMap::new();
    let tok = backend.apply_auth_header(&mut headers).await.unwrap();
    assert_eq!(tok.as_deref(), Some(secret));
    let auth_val = headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization header must be present");
    assert!(
        auth_val.is_sensitive(),
        "GCS Bearer Authorization header must be marked is_sensitive() == true"
    );
    assert_eq!(auth_val.as_bytes(), format!("Bearer {secret}").as_bytes());
    assert!(
        !format!("{auth_val:?}").contains(secret),
        "Debug formatting of sensitive Authorization header must not leak bearer token"
    );

    // Anonymous backend emits no Authorization header.
    let anon = GcsBackend::new(GcsConfig::new("gcs-anon", "test-bucket"), None, transport).unwrap();
    let mut anon_headers = HeaderMap::new();
    assert_eq!(
        anon.apply_auth_header(&mut anon_headers).await.unwrap(),
        None
    );
    assert!(!anon_headers.contains_key(http::header::AUTHORIZATION));
}

/// Slow GCS `rewriteTo` server-side copy RPCs use `long_control_timeout` while standard
/// control-plane RPCs honor the shorter `control_timeout`.
#[tokio::test]
async fn gcs_rewrite_server_side_copy_uses_long_control_timeout() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload = b"gcs-slow-rewrite-payload".to_vec();
    let faults = {
        let mut g = state.lock().unwrap();
        g.seed_object("src/big.bin", payload.clone());
        g.faults.clone()
    };

    let tcfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(150))
        .with_long_control_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let mut cfg = make_gcs_config(&base_url, "gcs-long-rewrite");
    cfg.max_retries = 0;
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport).unwrap();

    // Standard stat trips the short 150ms control_timeout.
    faults.push(
        "GetObjectMeta",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let stat_err = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("src/big.bin").unwrap(),
        ))
        .await
        .expect_err("normal control RPC must honor short control_timeout");
    assert_eq!(stat_err.kind, ErrorKind::Timeout, "got: {stat_err:?}");

    // Both steps of multi-step rewriteTo exceed 150ms control_timeout but succeed via long_control_timeout!
    faults.push(
        "RewriteObject",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    faults.push(
        "RewriteObject",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let copy_init = UploadInit {
        op_id: "op-slow-rewrite".into(),
        dst_path: RelPath::parse("dst/big-copy.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    let copied = backend
        .server_side_copy(
            &ep,
            &BackendPath::from_rel(RelPath::parse("src/big.bin").unwrap()),
            &copy_init,
        )
        .await
        .expect("slow rewriteTo must succeed under long_control_timeout")
        .expect("rewriteTo committed");
    assert_eq!(copied.size, payload.len() as u64);
    assert_eq!(state.lock().unwrap().rewrite_calls, 2);
}

/// Plane-isolated limiters (P2): data-plane upload/download throttling activates CUBIC only
/// on `data_limiter` without impacting `control_limiter`.
#[tokio::test]
async fn gcs_control_and_data_plane_limiters_are_isolated() {
    let (base_url, state) = spawn_mock_gcs().await;
    let payload = b"gcs-plane-isolation-payload".to_vec();
    let faults = {
        let mut g = state.lock().unwrap();
        g.seed_object("plane/existing.bin", payload.clone());
        g.faults.clone()
    };

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let cfg = make_gcs_config(&base_url, "gcs-plane-iso");
    let scope = LimiterScope::new(&cfg.remote_name, "gcs-test");
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport.clone()).unwrap();
    let ctrl_limiter = transport.control_limiter_for(scope.clone());
    let data_limiter = transport.data_limiter_for(scope);

    assert!(!ctrl_limiter.snapshot().cubic_enabled);
    assert!(!data_limiter.snapshot().cubic_enabled);

    // 1. Data-plane HTTP 500 on download must NOT enable CUBIC on either plane.
    let reader = match backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("plane/existing.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    faults.push(
        "DownloadObject",
        InjectedFault::json_error(StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"boom"}"#),
    );
    let dl_500 = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .err()
        .expect("500 must fail open_range");
    assert_eq!(dl_500.kind, ErrorKind::Network);
    assert_eq!(dl_500.retry, RetryClass::Retryable);
    assert!(!data_limiter.snapshot().cubic_enabled);
    assert!(!ctrl_limiter.snapshot().cubic_enabled);

    // 2. Data-plane HTTP 429 on single-shot upload activates CUBIC ONLY on data_limiter.
    faults.push(
        "UploadMultipart",
        InjectedFault::too_many_requests(Some("0")),
    );
    let put_init = UploadInit {
        op_id: "op-plane-put".into(),
        dst_path: RelPath::parse("plane/throttled.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let put_err = backend
        .put_single_shot(
            &put_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .expect_err("429 must fail put_single_shot");
    assert_eq!(put_err.kind, ErrorKind::RateLimited);
    assert_eq!(put_err.retry, RetryClass::Throttled);
    assert!(
        data_limiter.snapshot().cubic_enabled,
        "data-plane 429 must activate CUBIC on data_limiter"
    );
    assert!(
        !ctrl_limiter.snapshot().cubic_enabled,
        "data-plane 429 must NOT activate CUBIC on control_limiter"
    );

    // 3. Control-plane listing succeeds with control_limiter still untouched.
    let page = backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert!(!ctrl_limiter.snapshot().cubic_enabled);
}

#[tokio::test]
async fn gcs_c3_streaming_checksum_metadata_upload_and_download_verification() {
    use rship_core::types::Checksum;

    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);

    let payload = b"gcs c3 end-to-end streaming checksum verification payload!".to_vec();
    let crc_u32 = simple_crc32c(&payload);
    let crc_hex = format!("{crc_u32:08x}");
    let crc_b64 = B64.encode(crc_u32.to_be_bytes());
    let md5_raw = Md5::digest(&payload);
    let md5_hex = hex::encode(md5_raw);
    let md5_b64 = B64.encode(md5_raw);

    // (a) Known CRC32C & MD5 in `init.checksums` are sent in JSON metadata on BOTH
    //     `put_single_shot` and `begin_upload`!
    let single_path = RelPath::parse("c3/single.bin").unwrap();
    let single_init = UploadInit {
        op_id: "op-gcs-c3-single".into(),
        dst_path: single_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![
            Checksum {
                kind: HashKind::Crc32c,
                hex: crc_hex.clone(),
            },
            Checksum {
                kind: HashKind::Md5,
                hex: md5_hex.clone(),
            },
        ],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p_c = payload.clone();
    backend
        .put_single_shot(
            &single_init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .unwrap();

    let resumable_init = UploadInit {
        op_id: "op-gcs-c3-res".into(),
        dst_path: RelPath::parse("c3/resumable.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: GCS_CHUNK_ALIGN_BYTES,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: vec![
            Checksum {
                kind: HashKind::Crc32c,
                hex: crc_hex,
            },
            Checksum {
                kind: HashKind::Md5,
                hex: md5_hex,
            },
        ],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend.begin_upload(&resumable_init).await.unwrap();

    {
        let g = state.lock().unwrap();
        assert_eq!(g.seen_upload_metadata.len(), 2);
        for meta in &g.seen_upload_metadata {
            assert_eq!(meta["crc32c"].as_str(), Some(crc_b64.as_str()));
            assert_eq!(meta["md5Hash"].as_str(), Some(md5_b64.as_str()));
        }
    }

    // (b) Streaming upload computes CRC32C on-the-fly and rejects server-side mismatch!
    state.lock().unwrap().corrupt_upload_crc32c_once = true;
    let bad_init = UploadInit {
        op_id: "op-gcs-c3-bad".into(),
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
    let chunks: Vec<Result<Bytes>> = payload
        .chunks(13)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let upload_err = backend
        .put_single_shot(&bad_init, Box::pin(futures::stream::iter(chunks)))
        .await
        .expect_err("mismatched GCS server crc32c must fail upload");
    assert_eq!(upload_err.kind, ErrorKind::Integrity);
    assert!(upload_err.is_integrity());
    assert!(upload_err.message().contains("checksum mismatch"));

    // (c) Full-object download detects corrupted payload bytes against `x-goog-hash`!
    let reader = match backend
        .open_read(&BackendPath::from_rel(single_path), None)
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
    let dl_err = dl_err.expect("corrupted full-object GCS download must fail checksum check");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(dl_err.message().contains("checksum mismatch"));

    // (d) Sub-range downloads (`offset > 0` or `len < total_len`) do NOT falsely fail!
    for range in [
        ByteRange { offset: 0, len: 12 },
        ByteRange { offset: 7, len: 20 },
        ByteRange {
            offset: payload.len() as u64 - 10,
            len: 10,
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

// =========================================================================
// C3: running CRC32C across resumable chunks + `x-goog-hash` on the final request
// =========================================================================

fn resumable_init(op_id: &str, path: &RelPath, total: u64, chunk: u64) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

fn resumable_op(
    backend: &GcsBackend,
    init: &UploadInit,
    sess: rship_core::backend::UploadSessionInit,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sk-{}", init.op_id),
        job_id: "j-c3-resumable".into(),
        src_endpoint: "local://src".into(),
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
        remote_op_id: None,
        backend_kind: "gcs".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    }
}

/// Body stream yielding `data` in `piece`-sized items, so item boundaries straddle the
/// 256 KiB split point of a final chunk.
fn pieces(data: &[u8], piece: usize) -> ByteStream {
    let items: Vec<Result<Bytes>> = data
        .chunks(piece)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    Box::pin(futures::stream::iter(items))
}

/// Drive every chunk of `data` through `upload_chunk` the way the engine's sequential loop
/// does (re-sending from the server's confirmed offset), returning the committed entry.
async fn drive_resumable(
    backend: &GcsBackend,
    op: &OperationRecord,
    data: &[u8],
    chunk: u64,
    start: u64,
) -> Result<rship_core::types::Entry> {
    let total = data.len() as u64;
    let mut offset = start;
    loop {
        let len = (total - offset).min(chunk);
        let body = pieces(&data[offset as usize..(offset + len) as usize], 100_000);
        let ack = backend
            .upload_chunk(op, ChunkUpload::new(1, offset, len, total, body))
            .await?;
        if let Some(entry) = ack.completed {
            return Ok(entry);
        }
        offset = ack.next_offset.unwrap();
    }
}

fn test_payload(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

#[tokio::test]
async fn gcs_c3_resumable_upload_streams_crc32c_and_sends_x_goog_hash_on_final_request() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let align = GCS_CHUNK_ALIGN_BYTES;
    // Chunks of 2 x 256 KiB; the final chunk is 1.5 x 256 KiB, so it is split into a 256 KiB
    // head and a 128 KiB tail that carries `x-goog-hash`.
    let chunk = 2 * align;
    let data = test_payload((3 * align + align / 2) as usize, 7);
    let path = RelPath::parse("c3/resumable-verified.bin").unwrap();
    let init = resumable_init("op-gcs-c3-res-ok", &path, data.len() as u64, chunk);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = resumable_op(&backend, &init, sess);

    let entry = drive_resumable(&backend, &op, &data, chunk, 0)
        .await
        .expect("verified resumable upload must succeed");
    assert_eq!(entry.size, data.len() as u64);

    let g = state.lock().unwrap();
    assert_eq!(g.objects["c3/resumable-verified.bin"].data, data);
    let expected_hash = B64.encode(simple_crc32c(&data).to_be_bytes());
    let puts = &g.resumable_puts;
    let (last_range, last_hash) = puts.last().unwrap();
    assert_eq!(
        last_hash.as_deref(),
        Some(expected_hash.as_str()),
        "final request must carry the whole-object CRC32C in x-goog-hash (puts: {puts:?})"
    );
    assert_eq!(
        last_range,
        &format!("bytes {}-{}/{}", 3 * align, data.len() - 1, data.len()),
        "only the short tail is buffered for the final request"
    );
    assert!(
        puts[..puts.len() - 1].iter().all(|(_, h)| h.is_none()),
        "non-final requests must not carry x-goog-hash: {puts:?}"
    );
}

#[tokio::test]
async fn gcs_c3_resumable_in_transit_corruption_is_rejected_by_x_goog_hash() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let align = GCS_CHUNK_ALIGN_BYTES;
    let data = test_payload((align + 1000) as usize, 3);
    let path = RelPath::parse("c3/resumable-corrupt.bin").unwrap();
    let init = resumable_init("op-gcs-c3-res-corrupt", &path, data.len() as u64, align);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = resumable_op(&backend, &init, sess);

    // The first (non-final) chunk is corrupted on its way into the session.
    state.lock().unwrap().corrupt_next_resumable_chunk = true;
    let err = drive_resumable(&backend, &op, &data, align, 0)
        .await
        .expect_err("GCS must reject a final request whose x-goog-hash does not match");
    assert!(
        err.message().contains("checksum mismatch"),
        "expected checksum mismatch, got: {err:?}"
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .objects
            .contains_key("c3/resumable-corrupt.bin"),
        "corrupted object must never be committed"
    );
}

#[tokio::test]
async fn gcs_c3_resumable_finalize_crc32c_mismatch_is_detected_client_side() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let align = GCS_CHUNK_ALIGN_BYTES;
    let data = test_payload((2 * align + 17) as usize, 11);
    let path = RelPath::parse("c3/resumable-bad-response.bin").unwrap();
    let init = resumable_init("op-gcs-c3-res-badresp", &path, data.len() as u64, align);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = resumable_op(&backend, &init, sess);

    state.lock().unwrap().corrupt_resumable_final_crc32c_once = true;
    let err = drive_resumable(&backend, &op, &data, align, 0)
        .await
        .expect_err("a finalize response whose crc32c differs from the streamed CRC must fail");
    assert!(
        err.message().contains("checksum mismatch") && err.message().contains("CRC32C"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn gcs_c3_resumable_session_resumed_by_new_process_falls_back_to_unverified() {
    let (base_url, state) = spawn_mock_gcs().await;
    let align = GCS_CHUNK_ALIGN_BYTES;
    let data = test_payload((2 * align + 5) as usize, 19);
    let path = RelPath::parse("c3/resumable-resumed.bin").unwrap();
    let init = resumable_init("op-gcs-c3-res-resume", &path, data.len() as u64, align);

    let first = make_backend(&base_url);
    let sess = first.begin_upload(&init).await.unwrap();
    let op = resumable_op(&first, &init, sess);
    let first_chunk = pieces(&data[..align as usize], 65_536);
    let ack = first
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, align, data.len() as u64, first_chunk),
        )
        .await
        .unwrap();
    assert_eq!(ack.next_offset, Some(align));

    // A new process has no running CRC for this session: the upload completes, unverified.
    let second = make_backend(&base_url);
    let entry = drive_resumable(&second, &op, &data, align, align)
        .await
        .expect("resumed upload must still complete");
    assert_eq!(entry.size, data.len() as u64);
    let g = state.lock().unwrap();
    assert_eq!(g.objects["c3/resumable-resumed.bin"].data, data);
    assert!(
        g.resumable_puts.iter().all(|(_, h)| h.is_none()),
        "without a running CRC no x-goog-hash may be claimed: {:?}",
        g.resumable_puts
    );
}

#[tokio::test]
async fn gcs_resumable_308_without_range_means_nothing_was_persisted() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let align = GCS_CHUNK_ALIGN_BYTES;
    let data = test_payload((2 * align + 99) as usize, 23);
    let path = RelPath::parse("c3/308-no-range.bin").unwrap();
    let init = resumable_init("op-gcs-308-no-range", &path, data.len() as u64, align);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = resumable_op(&backend, &init, sess);

    // GCS persists nothing from the first chunk and answers `308` without `Range`.
    state.lock().unwrap().drop_next_resumable_chunk = true;
    let first = pieces(&data[..align as usize], 65_536);
    let ack = backend
        .upload_chunk(&op, ChunkUpload::new(1, 0, align, data.len() as u64, first))
        .await
        .unwrap();
    assert_eq!(
        ack.next_offset,
        Some(0),
        "a 308 without Range confirms zero bytes, not the whole chunk"
    );

    // Re-sending from the confirmed offset completes the object intact, still verified.
    let entry = drive_resumable(&backend, &op, &data, align, 0)
        .await
        .expect("upload must complete after re-sending from offset 0");
    assert_eq!(entry.size, data.len() as u64);
    let g = state.lock().unwrap();
    assert_eq!(g.objects["c3/308-no-range.bin"].data, data);
    assert_eq!(
        g.resumable_puts.last().unwrap().1.as_deref(),
        Some(B64.encode(simple_crc32c(&data).to_be_bytes()).as_str()),
        "the running CRC survives a chunk that was not persisted"
    );
}

#[tokio::test]
async fn gcs_fault_single_shot_slow_finalize_succeeds_without_false_stall_timeout() {
    let (base_url, state) = spawn_mock_gcs().await;
    let faults = state.lock().unwrap().faults.clone();

    let tcfg = TransportConfig::default()
        .with_data_stall_timeout(Duration::from_millis(150))
        .with_data_finalize_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let cfg = make_gcs_config(&base_url, "gcs-single-slow-fin");
    let auth = Some(Arc::new(StaticBearerAuth::new("gcs-test", "gcs-test-token")) as _);
    let backend = GcsBackend::new(cfg, auth, transport).unwrap();

    faults.push(
        "UploadMultipart",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let payload = b"single-shot-slow-finalize-payload".to_vec();
    let init = UploadInit {
        op_id: "op-single-slow".into(),
        dst_path: RelPath::parse("single/slow.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p_c = payload.clone();
    let t0 = Instant::now();
    let entry = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .expect("single-shot slow finalize must succeed without false stall timeout");
    assert_eq!(entry.size, payload.len() as u64);
    assert!(t0.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn gcs_fault_upload_401_persistent_stops_after_one_refresh() {
    let (base_url, state) = spawn_mock_gcs().await;
    state.lock().unwrap().expected_token = "unmatchable-server-token".to_string();

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let cfg = make_gcs_config(&base_url, "gcs-upload-401-guard");
    let auth = Arc::new(MockRefreshingGcsAuth::new(
        "stale-tok",
        "refreshed-tok",
        "guard-principal",
    ));
    let backend = GcsBackend::new(cfg, Some(auth.clone()), transport).unwrap();

    let init = UploadInit {
        op_id: "op-401-guard".into(),
        dst_path: RelPath::parse("auth/denied.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };

    // First 401 refreshes token and returns Retryable
    let err1 = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abcd"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(err1.kind, ErrorKind::PermissionDenied);
    assert_eq!(err1.retry, RetryClass::Retryable);
    assert_eq!(auth.refresh_calls(), 1);

    // Second 401 on the refreshed token stops immediately as Permanent without looping refresh
    let err2 = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abcd"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(err2.kind, ErrorKind::PermissionDenied);
    assert_eq!(err2.retry, RetryClass::Permanent);
    assert_eq!(auth.refresh_calls(), 1);
}
