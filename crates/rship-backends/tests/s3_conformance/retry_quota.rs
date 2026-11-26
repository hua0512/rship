//! The engine's transfer-level retries and the backend's HTTP-level retries draw from ONE
//! token bucket: the destination backend's per-(remote, principal) control-plane limiter,
//! exposed through `StorageBackend::retry_quota`.

use rship_backends::s3::{S3Backend, S3Provider};
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::state::JobMode;
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, RateLimiterConfig, RetryQuotaConfig, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

use crate::common::InjectedFault;
use crate::mock_server::MockS3Server;

fn backend_with_quota(srv: &MockS3Server, max_tokens: u32) -> Arc<S3Backend> {
    let mut cfg = srv.config(S3Provider::Minio, "quota-bkt", "us-east-1");
    cfg.max_retries = 3;
    let transport = HttpTransport::new(TransportConfig::default().with_default_rate_limit(
        RateLimiterConfig::new().with_retry_quota(RetryQuotaConfig {
            max_tokens,
            retry_cost: 5,
            timeout_retry_cost: 10,
            no_retry_increment: 1,
        }),
    ))
    .unwrap();
    Arc::new(S3Backend::new(cfg, transport, None).unwrap())
}

#[tokio::test]
async fn engine_and_backend_retries_share_the_destination_retry_bucket() {
    let srv = MockS3Server::start("quota-bkt", "us-east-1").await;
    let s3 = backend_with_quota(&srv, 5);
    let quota = s3
        .retry_quota()
        .expect("HTTP backends expose their retry bucket");

    // 1. The hook IS the backend's bucket: spending it from outside makes the backend's own
    //    HTTP retry fail fast.
    assert!(quota.try_acquire(false));
    srv.fault_injector()
        .push("HeadObject", InjectedFault::service_unavailable(Some("0")));
    let err = s3
        .stat(&BackendPath::from_rel(
            RelPath::parse("missing.bin").unwrap(),
        ))
        .await
        .expect_err("no retry budget left for the backend");
    assert!(err.retries_exhausted(), "{err:?}");
    assert_eq!(srv.fault_injector().op_requests("HeadObject"), 1);

    // 2. The engine pins the same bucket for its transfer retries: with it exhausted, a
    //    transient PutObject failure is not retried by the engine either.
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("q.bin"), b"retry-quota-shared").unwrap();
    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    srv.fault_injector()
        .push("PutObject", InjectedFault::service_unavailable(Some("0")));
    let engine = TransferEngine::new(
        local,
        s3.clone(),
        Arc::new(StateActor::open_in_memory().unwrap()),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-quota", JobMode::Copy, "local", "s3");
    ecfg.base_retry_delay = Duration::from_millis(1);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        srv.fault_injector().op_requests("PutObject"),
        1,
        "the engine must draw from the backend's (exhausted) bucket, not a fresh one"
    );
    assert!(!rep.is_success(), "transfer must fail without retry budget");
}
