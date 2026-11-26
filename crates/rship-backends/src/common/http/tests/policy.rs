use super::super::*;
use rship_core::RetryClass;
use rship_core::clock::{Clock as _, VirtualClock};
use rship_transport::{LimiterScope, RateLimiterConfig, RetryQuotaConfig};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};

fn test_limiter(quota: RetryQuotaConfig) -> Arc<ScopedLimiter> {
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let cfg = RateLimiterConfig::new().with_retry_quota(quota);
    Arc::new(ScopedLimiter::new(
        LimiterScope::control("test-remote", "principal"),
        cfg,
        clock,
    ))
}

fn http_resp(status: StatusCode, headers: HeaderMap, body: &'static str) -> HttpResponse {
    HttpResponse {
        status,
        headers,
        body: Bytes::from_static(body.as_bytes()),
    }
}

#[test]
fn sensitive_and_bearer_header_values_mark_sensitive_and_reject_invalid() {
    let bearer = bearer_header_value("secret-oauth-token-xyz").expect("valid bearer");
    assert!(bearer.is_sensitive());
    assert_eq!(bearer.as_bytes(), b"Bearer secret-oauth-token-xyz");
    assert!(
        !format!("{bearer:?}").contains("secret-oauth-token-xyz"),
        "Debug formatting must hide sensitive bearer header value"
    );

    let custom = sensitive_header_value("Basic dXNlcjpzZWNyZXQ=", "WebDAV auth")
        .expect("valid sensitive header");
    assert!(custom.is_sensitive());
    assert_eq!(custom.as_bytes(), b"Basic dXNlcjpzZWNyZXQ=");
    assert!(
        !format!("{custom:?}").contains("dXNlcjpzZWNyZXQ="),
        "Debug formatting must hide sensitive custom header value"
    );

    let secret_with_newline = "top-secret\r\ninjected";
    let err = sensitive_header_value(secret_with_newline, "test auth").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Protocol);
    assert!(
        !err.message().contains("top-secret"),
        "error message must not echo raw secret input: {}",
        err.message()
    );
}

#[tokio::test(start_paused = true)]
async fn idempotent_429_retry_after_capped_and_503_backoff_refund_exact_quota() {
    // Part A: 429 with Retry-After: 3600 strictly capped to cfg.max_delay (2s)
    // and exact 5-token quota charge + refund on recovery.
    let limiter = test_limiter(RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(200), Duration::from_secs(2));

    let mut hdrs_429 = HeaderMap::new();
    hdrs_429.insert(http::header::RETRY_AFTER, HeaderValue::from_static("3600"));
    let mut responses = VecDeque::from([
        Ok((
            http_resp(StatusCode::TOO_MANY_REQUESTS, hdrs_429, "slow"),
            (),
        )),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok-429"), ())),
    ]);
    let quota_during_retry = Arc::new(AtomicU32::new(0));
    let quota_during_retry_c = quota_during_retry.clone();
    let limiter_c = limiter.clone();
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();

    let t0 = tokio::time::Instant::now();
    let out = execute_policy_loop(
        &limiter,
        "test-429",
        &cfg,
        Idempotency::Idempotent,
        || {
            let n = calls_c.fetch_add(1, Ordering::SeqCst);
            if n == 1 {
                quota_during_retry_c
                    .store(limiter_c.snapshot().retry_quota_available, Ordering::SeqCst);
            }
            let next = responses.pop_front().expect("response");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned())
            } else {
                let ra = parse_retry_after(&resp.headers);
                PolicyDecision::Retry(Error::rate_limited("429", ra))
            }
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .expect("should recover after 429");

    assert_eq!(out, "ok-429");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        t0.elapsed(),
        Duration::from_secs(2),
        "Retry-After: 3600 must be capped to cfg.max_delay (2s)"
    );
    assert_eq!(
        quota_during_retry.load(Ordering::SeqCst),
        95,
        "non-timeout retry must charge retry_cost (5)"
    );
    let snap = limiter.snapshot();
    assert!(snap.cubic_enabled, "429 must signal CUBIC throttle");
    assert_eq!(
        snap.retry_quota_available, snap.retry_quota_max,
        "successful recovery must refund exact 5-token retry cost back to max_tokens"
    );

    // Part B: 503 full-jitter backoff without Retry-After also charges 5 and refunds 5.
    let limiter2 = test_limiter(RetryQuotaConfig {
        max_tokens: 50,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let cfg2 = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(200), Duration::from_secs(2));
    let mut responses2 = VecDeque::from([
        Ok((
            http_resp(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new(), "busy"),
            (),
        )),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok-503"), ())),
    ]);
    let quota_seen = Arc::new(AtomicU32::new(0));
    let quota_seen_c = quota_seen.clone();
    let limiter2_c = limiter2.clone();
    let calls2 = Arc::new(AtomicU32::new(0));
    let calls2_c = calls2.clone();

    let t1 = tokio::time::Instant::now();
    let out2 = execute_policy_loop(
        &limiter2,
        "test-503",
        &cfg2,
        Idempotency::Idempotent,
        || {
            let n = calls2_c.fetch_add(1, Ordering::SeqCst);
            if n == 1 {
                quota_seen_c.store(
                    limiter2_c.snapshot().retry_quota_available,
                    Ordering::SeqCst,
                );
            }
            let next = responses2.pop_front().expect("response");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned())
            } else {
                PolicyDecision::Retry(Error::new(
                    ErrorKind::Network,
                    RetryClass::Retryable,
                    "503 service unavailable",
                ))
            }
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .expect("should recover after 503");

    assert_eq!(out2, "ok-503");
    assert!(
        t1.elapsed() <= Duration::from_millis(400),
        "attempt=1 full-jitter delay must be <= base*2^1 (400ms), got {:?}",
        t1.elapsed()
    );
    assert_eq!(quota_seen.load(Ordering::SeqCst), 45);
    assert_eq!(
        limiter2.snapshot().retry_quota_available,
        limiter2.snapshot().retry_quota_max
    );
}

#[tokio::test(start_paused = true)]
async fn timeout_retry_charges_refunds_10_and_quota_exhaustion_fails_fast() {
    // Recovery path: timeout charges 10 and refunds 10.
    let limiter = test_limiter(RetryQuotaConfig {
        max_tokens: 20,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(50), Duration::from_secs(1));

    let mut steps = VecDeque::from([
        Err(SendStepError::Transport(Error::timeout("read timed out"))),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "recovered"), ())),
    ]);
    let seen_quota = Arc::new(AtomicU32::new(0));
    let seen_quota_c = seen_quota.clone();
    let limiter_c = limiter.clone();
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();

    let res = execute_policy_loop(
        &limiter,
        "test-timeout-recover",
        &cfg,
        Idempotency::Idempotent,
        || {
            let n = calls_c.fetch_add(1, Ordering::SeqCst);
            if n == 1 {
                seen_quota_c.store(limiter_c.snapshot().retry_quota_available, Ordering::SeqCst);
            }
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .expect("timeout should recover");
    assert_eq!(res, "recovered");
    assert_eq!(
        seen_quota.load(Ordering::SeqCst),
        10,
        "timeout retry must deduct timeout_retry_cost (10)"
    );
    assert_eq!(
        limiter.snapshot().retry_quota_available,
        20,
        "timeout recovery must refund timeout_retry_cost (10)"
    );

    // Exhaustion path: 15 tokens allows 1 timeout retry (cost 10, leaves 5), then
    // 2nd timeout cannot afford cost 10 and must fail fast with retries_exhausted.
    let tight_limiter = test_limiter(RetryQuotaConfig {
        max_tokens: 15,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let tight_cfg = RetryPolicyConfig::new()
        .with_max_retries(5)
        .with_delays(Duration::from_millis(10), Duration::from_millis(100));
    let exhaust_calls = Arc::new(AtomicU32::new(0));
    let exhaust_calls_c = exhaust_calls.clone();

    let err = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &tight_limiter,
        "test-timeout-exhaust",
        &tight_cfg,
        Idempotency::Idempotent,
        || {
            exhaust_calls_c.fetch_add(1, Ordering::SeqCst);
            async { Err(SendStepError::Transport(Error::timeout("stalled"))) }
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Ok(()),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();

    assert_eq!(
        exhaust_calls.load(Ordering::SeqCst),
        2,
        "should send initial + 1 affordable retry then fail fast when quota < 10"
    );
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert!(err.retries_exhausted());
    assert!(!err.is_retryable());
    assert_eq!(tight_limiter.snapshot().retry_quota_available, 5);
}

#[tokio::test(start_paused = true)]
async fn exhausting_max_retries_marks_retries_exhausted() {
    let limiter = test_limiter(RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(20), Duration::from_millis(200));
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();

    let err = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &limiter,
        "test-max-retries",
        &cfg,
        Idempotency::Idempotent,
        || {
            calls_c.fetch_add(1, Ordering::SeqCst);
            async {
                Ok((
                    http_resp(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new(), "down"),
                    (),
                ))
            }
        },
        |()| async { Ok(false) },
        |_resp| {
            PolicyDecision::Retry(Error::new(
                ErrorKind::Network,
                RetryClass::Retryable,
                "503 down",
            ))
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();

    assert_eq!(calls.load(Ordering::SeqCst), 4, "1 initial + 3 retries");
    assert!(err.retries_exhausted());
    assert!(!err.is_retryable());
    assert_eq!(
        limiter.snapshot().retry_quota_available,
        85,
        "only the 3 actual retries should deduct 5 tokens each"
    );
}

#[tokio::test(start_paused = true)]
async fn non_idempotent_without_reconcile_refuses_blind_retry_on_500_and_reset() {
    let limiter = test_limiter(RetryQuotaConfig::default());
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(5)
        .with_delays(Duration::from_millis(10), Duration::from_millis(100));

    // Case 1: HTTP 500
    let calls_500 = Arc::new(AtomicU32::new(0));
    let calls_500_c = calls_500.clone();
    let err_500 = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &limiter,
        "non-idemp-500",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            calls_500_c.fetch_add(1, Ordering::SeqCst);
            async {
                Ok((
                    http_resp(StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new(), "boom"),
                    (),
                ))
            }
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Retry(Error::network("500 internal error")),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();
    assert_eq!(calls_500.load(Ordering::SeqCst), 1);
    assert!(err_500.retries_exhausted());
    assert!(!err_500.is_retryable());

    // Case 2: Transport connection reset
    let calls_reset = Arc::new(AtomicU32::new(0));
    let calls_reset_c = calls_reset.clone();
    let err_reset = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &limiter,
        "non-idemp-reset",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            calls_reset_c.fetch_add(1, Ordering::SeqCst);
            async { Err(SendStepError::Transport(Error::network("connection reset"))) }
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Ok(()),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();
    assert_eq!(calls_reset.load(Ordering::SeqCst), 1);
    assert!(err_reset.retries_exhausted());
    assert_eq!(
        limiter.snapshot().retry_quota_available,
        limiter.snapshot().retry_quota_max,
        "refused non-idempotent retries must not burn retry quota"
    );
}

#[tokio::test(start_paused = true)]
async fn non_idempotent_with_reconcile_resolved_retry_and_fail() {
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(20), Duration::from_millis(200));

    // 1. ReconcileAction::Resolved returns Ok without duplicating the mutation.
    let limiter_resolved = test_limiter(RetryQuotaConfig::default());
    let http_calls = Arc::new(AtomicU32::new(0));
    let http_calls_c = http_calls.clone();
    let reconcile_calls = Arc::new(AtomicU32::new(0));
    let reconcile_calls_c = reconcile_calls.clone();
    let val = execute_policy_loop(
        &limiter_resolved,
        "reconcile-resolved",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            http_calls_c.fetch_add(1, Ordering::SeqCst);
            async {
                Err(SendStepError::Transport(Error::network(
                    "reset after commit",
                )))
            }
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Ok(String::new()),
        |_err| {
            reconcile_calls_c.fetch_add(1, Ordering::SeqCst);
            async { Ok(ReconcileAction::Resolved("already-committed".to_string())) }
        },
    )
    .await
    .expect("reconcile should resolve");
    assert_eq!(val, "already-committed");
    assert_eq!(http_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reconcile_calls.load(Ordering::SeqCst), 1);

    // 2. ReconcileAction::Retry retries once and succeeds, refunding quota.
    let limiter_retry = test_limiter(RetryQuotaConfig {
        max_tokens: 50,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let retry_http_calls = Arc::new(AtomicU32::new(0));
    let retry_http_calls_c = retry_http_calls.clone();
    let retry_rec_calls = Arc::new(AtomicU32::new(0));
    let retry_rec_calls_c = retry_rec_calls.clone();
    let mut steps = VecDeque::from([
        Ok((
            http_resp(StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new(), "err"),
            (),
        )),
        Ok((
            http_resp(StatusCode::CREATED, HeaderMap::new(), "created"),
            (),
        )),
    ]);
    let val2 = execute_policy_loop(
        &limiter_retry,
        "reconcile-retry",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            retry_http_calls_c.fetch_add(1, Ordering::SeqCst);
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned())
            } else {
                PolicyDecision::Retry(Error::network("500"))
            }
        },
        |err| {
            retry_rec_calls_c.fetch_add(1, Ordering::SeqCst);
            async { Ok(ReconcileAction::Retry(err)) }
        },
    )
    .await
    .expect("reconcile retry should succeed");
    assert_eq!(val2, "created");
    assert_eq!(retry_http_calls.load(Ordering::SeqCst), 2);
    assert_eq!(retry_rec_calls.load(Ordering::SeqCst), 1);
    assert_eq!(limiter_retry.snapshot().retry_quota_available, 50);

    // 3. ReconcileAction::Fail aborts cleanly without retrying.
    let limiter_fail = test_limiter(RetryQuotaConfig::default());
    let fail_http_calls = Arc::new(AtomicU32::new(0));
    let fail_http_calls_c = fail_http_calls.clone();
    let err = execute_policy_loop::<String, _, _, _, _, _, _, _, _>(
        &limiter_fail,
        "reconcile-fail",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            fail_http_calls_c.fetch_add(1, Ordering::SeqCst);
            async {
                Ok((
                    http_resp(StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new(), "err"),
                    (),
                ))
            }
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Retry(Error::network("500")),
        |_err| async {
            Ok(ReconcileAction::Fail(Error::conflict(
                "destination modified by another writer",
            )))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(fail_http_calls.load(Ordering::SeqCst), 1);
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert!(err.retries_exhausted());
}

#[tokio::test(start_paused = true)]
async fn policy_decision_reconcile_runs_even_when_idempotent() {
    let limiter = test_limiter(RetryQuotaConfig::default());
    let cfg = RetryPolicyConfig::new().with_max_retries(2);
    let http_calls = Arc::new(AtomicU32::new(0));
    let http_calls_c = http_calls.clone();
    let rec_calls = Arc::new(AtomicU32::new(0));
    let rec_calls_c = rec_calls.clone();

    let resolved = execute_policy_loop(
        &limiter,
        "s3-copy-412",
        &cfg,
        Idempotency::Idempotent,
        || {
            http_calls_c.fetch_add(1, Ordering::SeqCst);
            async {
                Ok((
                    http_resp(StatusCode::PRECONDITION_FAILED, HeaderMap::new(), "412"),
                    (),
                ))
            }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status == StatusCode::PRECONDITION_FAILED {
                PolicyDecision::Reconcile(Error::precondition_failed("If-None-Match failed"))
            } else {
                PolicyDecision::Ok("direct".to_string())
            }
        },
        |err| {
            rec_calls_c.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(err.kind, ErrorKind::PreconditionFailed);
                Ok(ReconcileAction::Resolved(
                    "verified-op-id-match".to_string(),
                ))
            }
        },
    )
    .await
    .expect("412 reconcile should resolve");

    assert_eq!(resolved, "verified-op-id-match");
    assert_eq!(http_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rec_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn auth_refresh_runs_at_most_once_without_burning_attempts_or_quota() {
    // Subcase 1: max_retries == 0 still succeeds after 1 AuthRefresh with 0 quota consumed.
    let limiter = test_limiter(RetryQuotaConfig {
        max_tokens: 50,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    });
    let cfg = RetryPolicyConfig::new().with_max_retries(0);
    let token = Arc::new(StdMutex::new("stale-tok".to_string()));
    let token_build = token.clone();
    let token_refresh = token.clone();
    let refresh_count = Arc::new(AtomicU32::new(0));
    let refresh_count_c = refresh_count.clone();

    let ok = execute_policy_loop(
        &limiter,
        "auth-once",
        &cfg,
        Idempotency::Idempotent,
        || {
            let current = token_build.lock().expect("tok").clone();
            async move {
                if current == "stale-tok" {
                    Ok((
                        http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), "expired"),
                        current,
                    ))
                } else {
                    Ok((
                        http_resp(StatusCode::OK, HeaderMap::new(), "authed"),
                        current,
                    ))
                }
            }
        },
        |used_tok| {
            refresh_count_c.fetch_add(1, Ordering::SeqCst);
            let token_refresh = token_refresh.clone();
            async move {
                assert_eq!(used_tok, "stale-tok");
                *token_refresh.lock().expect("tok") = "fresh-tok".to_string();
                Ok(true)
            }
        },
        |resp| match resp.status {
            StatusCode::UNAUTHORIZED => PolicyDecision::AuthRefresh,
            s if s.is_success() => {
                PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned())
            }
            _ => PolicyDecision::Fail(Error::protocol("unexpected")),
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .expect("should succeed after single auth refresh");
    assert_eq!(ok, "authed");
    assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.snapshot().retry_quota_available, 50);

    // Subcase 2: Second 401 fails permanently without invoking refresh a second time.
    let calls_401 = Arc::new(AtomicU32::new(0));
    let calls_401_c = calls_401.clone();
    let refresh_count2 = Arc::new(AtomicU32::new(0));
    let refresh_count2_c = refresh_count2.clone();

    let err = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &limiter,
        "auth-double-401",
        &RetryPolicyConfig::new().with_max_retries(5),
        Idempotency::Idempotent,
        || {
            calls_401_c.fetch_add(1, Ordering::SeqCst);
            async {
                Ok((
                    http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), "still-401"),
                    "tok",
                ))
            }
        },
        |_ctx| {
            refresh_count2_c.fetch_add(1, Ordering::SeqCst);
            async { Ok(true) }
        },
        |_resp| PolicyDecision::AuthRefresh,
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();
    assert_eq!(calls_401.load(Ordering::SeqCst), 2);
    assert_eq!(refresh_count2.load(Ordering::SeqCst), 1);
    assert!(err.is_permission_denied());
    assert!(err.is_permanent());
    assert_eq!(limiter.snapshot().retry_quota_available, 50);
}

#[tokio::test(start_paused = true)]
async fn write_permit_paces_when_is_write_enabled() {
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let limiter = Arc::new(ScopedLimiter::new(
        LimiterScope::control("gdrive", "user"),
        RateLimiterConfig::new()
            .with_write_qps(2.0)
            .with_write_burst(1.0),
        clock,
    ));
    let cfg = RetryPolicyConfig::new().with_write_permit(true);

    let t0 = tokio::time::Instant::now();
    for _ in 0..2 {
        execute_policy_loop(
            &limiter,
            "write-op",
            &cfg,
            Idempotency::Idempotent,
            || async { Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok"), ())) },
            |()| async { Ok(false) },
            |_resp| PolicyDecision::Ok(()),
            |err| async move { Ok(ReconcileAction::Fail(err)) },
        )
        .await
        .expect("write succeeds");
    }
    assert!(
        t0.elapsed() >= Duration::from_millis(490),
        "2nd write at 2 QPS with burst 1 must pace ~500ms, got {:?}",
        t0.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn reconcile_retry_preserves_original_error_source_chain() {
    // A NonIdempotent transport failure whose reconcile says "not committed" (Retry) must
    // surface the ORIGINAL error (including its `source` chain) once retries are exhausted.
    let limiter = test_limiter(RetryQuotaConfig::default());
    let cfg = RetryPolicyConfig::new().with_max_retries(1);
    let err = execute_policy_loop::<(), _, _, _, _, _, _, _, _>(
        &limiter,
        "reconcile-retry-source",
        &cfg,
        Idempotency::NonIdempotent,
        || async {
            Err(SendStepError::Transport(
                Error::network("connection reset").with_source(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "peer reset the TCP stream",
                )),
            ))
        },
        |()| async { Ok(false) },
        |_resp| PolicyDecision::Ok(()),
        |err| async move { Ok(ReconcileAction::Retry(err)) },
    )
    .await
    .unwrap_err();
    assert!(err.retries_exhausted());
    assert_eq!(err.kind, ErrorKind::Network);
    let src = std::error::Error::source(&err).expect("source chain must survive reconcile Retry");
    assert!(
        src.to_string().contains("peer reset the TCP stream"),
        "unexpected source: {src}"
    );
}

#[tokio::test(start_paused = true)]
async fn retry_backoff_sleeps_through_the_limiter_clock() {
    // With an instant-sleep virtual clock (DST), the policy backoff must advance VIRTUAL time
    // instead of parking on a tokio timer.
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let limiter = Arc::new(ScopedLimiter::new(
        LimiterScope::control("dst-remote", "principal"),
        RateLimiterConfig::new(),
        clock.clone(),
    ));
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(2)
        .with_delays(Duration::from_millis(200), Duration::from_secs(30));
    let mut hdrs = HeaderMap::new();
    hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("7"));
    let mut steps = VecDeque::from([
        Ok((http_resp(StatusCode::SERVICE_UNAVAILABLE, hdrs, "busy"), ())),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok"), ())),
    ]);
    let v0 = clock.now_unix_nanos();
    let t0 = tokio::time::Instant::now();
    execute_policy_loop(
        &limiter,
        "dst-sleep",
        &cfg,
        Idempotency::Idempotent,
        || {
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok(())
            } else {
                PolicyDecision::Retry(Error::network("503"))
            }
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .expect("retry succeeds");
    assert_eq!(
        t0.elapsed(),
        Duration::ZERO,
        "backoff must not park on a tokio timer when the clock virtualises sleep"
    );
    assert_eq!(
        clock.now_unix_nanos() - v0,
        7_000_000_000,
        "backoff must advance the injected clock by the Retry-After delay"
    );
}

#[tokio::test(start_paused = true)]
async fn non_idempotent_429_is_resent_without_reconcile() {
    // RFC 6585: a 429 was not processed, so reconciling first would only add a probe.
    let limiter = test_limiter(RetryQuotaConfig::default());
    let cfg = RetryPolicyConfig::new().with_max_retries(2);
    let rec_calls = Arc::new(AtomicU32::new(0));
    let rec_calls_c = rec_calls.clone();
    let mut steps = VecDeque::from([
        Ok((
            http_resp(StatusCode::TOO_MANY_REQUESTS, HeaderMap::new(), "slow"),
            (),
        )),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok"), ())),
    ]);
    execute_policy_loop(
        &limiter,
        "copy-429",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok(())
            } else {
                PolicyDecision::Retry(Error::rate_limited("throttled", None))
            }
        },
        |err| {
            rec_calls_c.fetch_add(1, Ordering::SeqCst);
            async move { Ok(ReconcileAction::Fail(err)) }
        },
    )
    .await
    .expect("a 429 is resent directly");
    assert_eq!(rec_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retryable_build_error_retries_without_reconcile_even_when_non_idempotent() {
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let limiter = Arc::new(ScopedLimiter::new(
        LimiterScope::control("build-retry", "principal"),
        RateLimiterConfig::new(),
        clock.clone(),
    ));
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(2)
        .with_delays(Duration::from_millis(10), Duration::from_secs(5));
    let rec_calls = Arc::new(AtomicU32::new(0));
    let rec_calls_c = rec_calls.clone();
    let mut steps = VecDeque::from([
        Err(SendStepError::Build(Error::rate_limited(
            "token 429",
            Some(Duration::from_secs(2)),
        ))),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok"), ())),
    ]);

    let t0 = clock.now_unix_nanos();
    let res = execute_policy_loop(
        &limiter,
        "build-retry",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| async { Ok(false) },
        |resp| {
            if resp.status.is_success() {
                PolicyDecision::Ok("done")
            } else {
                PolicyDecision::Fail(Error::protocol("unexpected"))
            }
        },
        |err| {
            rec_calls_c.fetch_add(1, Ordering::SeqCst);
            async move { Ok(ReconcileAction::Fail(err)) }
        },
    )
    .await
    .expect("retryable build error must retry and succeed");

    assert_eq!(res, "done");
    assert_eq!(rec_calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock.now_unix_nanos() - t0, 2_000_000_000);
    assert_eq!(
        limiter.snapshot().retry_quota_available,
        limiter.snapshot().retry_quota_max
    );

    // Permanent Build error must fail immediately without retry.
    let perm_calls = Arc::new(AtomicU32::new(0));
    let perm_calls_c = perm_calls.clone();
    let perm_err = execute_policy_loop(
        &limiter,
        "build-perm",
        &cfg,
        Idempotency::Idempotent,
        || {
            perm_calls_c.fetch_add(1, Ordering::SeqCst);
            async { Err::<(HttpResponse, ()), _>(SendStepError::Build(Error::config("bad cfg"))) }
        },
        |()| async { Ok(false) },
        |_| PolicyDecision::Ok(()),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();
    assert_eq!(perm_calls.load(Ordering::SeqCst), 1);
    assert_eq!(perm_err.kind, ErrorKind::Config);
    assert!(!perm_err.retries_exhausted());
}

#[tokio::test]
async fn retryable_build_error_exhausts_at_max_retries() {
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let limiter = Arc::new(ScopedLimiter::new(
        LimiterScope::control("build-exhaust", "principal"),
        RateLimiterConfig::new(),
        clock,
    ));
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(2)
        .with_delays(Duration::from_millis(5), Duration::from_millis(20));
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();

    let err = execute_policy_loop(
        &limiter,
        "build-exhaust",
        &cfg,
        Idempotency::Idempotent,
        || {
            calls_c.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(HttpResponse, ()), _>(SendStepError::Build(Error::network(
                    "transient token endpoint error",
                )))
            }
        },
        |()| async { Ok(false) },
        |_| PolicyDecision::Ok(()),
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();

    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(err.retries_exhausted());
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn retryable_auth_refresh_error_retries_and_succeeds_without_reconcile() {
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let limiter = Arc::new(ScopedLimiter::new(
        LimiterScope::control("auth-retry", "principal"),
        RateLimiterConfig::new(),
        clock,
    ));
    let cfg = RetryPolicyConfig::new()
        .with_max_retries(3)
        .with_delays(Duration::from_millis(5), Duration::from_millis(20));
    let rec_calls = Arc::new(AtomicU32::new(0));
    let rec_calls_c = rec_calls.clone();
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let refresh_calls_c = refresh_calls.clone();

    let mut steps = VecDeque::from([
        Ok((
            http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), "401-1"),
            (),
        )),
        Ok((
            http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), "401-2"),
            (),
        )),
        Ok((http_resp(StatusCode::OK, HeaderMap::new(), "ok"), ())),
    ]);

    let res = execute_policy_loop(
        &limiter,
        "auth-retry",
        &cfg,
        Idempotency::NonIdempotent,
        || {
            let next = steps.pop_front().expect("step");
            async move { next }
        },
        |()| {
            let n = refresh_calls_c.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n == 1 {
                    Err(Error::new(
                        ErrorKind::Network,
                        RetryClass::Throttled,
                        "503 from token endpoint",
                    ))
                } else {
                    Ok(true)
                }
            }
        },
        |resp| {
            if resp.status == StatusCode::UNAUTHORIZED {
                PolicyDecision::AuthRefresh
            } else if resp.status.is_success() {
                PolicyDecision::Ok("authed")
            } else {
                PolicyDecision::Fail(Error::protocol("unexpected"))
            }
        },
        |err| {
            rec_calls_c.fetch_add(1, Ordering::SeqCst);
            async move { Ok(ReconcileAction::Fail(err)) }
        },
    )
    .await
    .expect("retryable auth refresh failure should retry and recover");

    assert_eq!(res, "authed");
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
    assert_eq!(rec_calls.load(Ordering::SeqCst), 0);

    // Permanent on_auth_refresh error fails immediately without retry.
    let perm_steps = std::sync::Mutex::new(VecDeque::from([Ok((
        http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), "401"),
        (),
    ))]));
    let perm_refresh_calls = Arc::new(AtomicU32::new(0));
    let perm_refresh_calls_c = perm_refresh_calls.clone();
    let perm_err = execute_policy_loop(
        &limiter,
        "auth-perm",
        &cfg,
        Idempotency::Idempotent,
        || {
            let next = perm_steps.lock().unwrap().pop_front().expect("step");
            async move { next }
        },
        |()| {
            perm_refresh_calls_c.fetch_add(1, Ordering::SeqCst);
            async { Err(Error::permission_denied("invalid_grant")) }
        },
        |resp| {
            if resp.status == StatusCode::UNAUTHORIZED {
                PolicyDecision::AuthRefresh
            } else {
                PolicyDecision::Ok(())
            }
        },
        |err| async move { Ok(ReconcileAction::Fail(err)) },
    )
    .await
    .unwrap_err();
    assert_eq!(perm_refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(perm_err.kind, ErrorKind::PermissionDenied);
    assert!(!perm_err.retries_exhausted());
}

#[test]
fn policy_decision_and_classify_common_http_status_helpers() {
    let mut hdrs = HeaderMap::new();
    hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));

    let e429 = classify_common_http_status("op", StatusCode::TOO_MANY_REQUESTS, &hdrs, "slow down")
        .unwrap();
    assert_eq!(e429.kind, ErrorKind::RateLimited);
    assert_eq!(e429.retry_after, Some(Duration::from_secs(5)));

    let e503 =
        classify_common_http_status("op", StatusCode::SERVICE_UNAVAILABLE, &hdrs, "busy").unwrap();
    assert_eq!(e503.kind, ErrorKind::Network);
    assert!(e503.is_throttled());

    let e408 =
        classify_common_http_status("op", StatusCode::REQUEST_TIMEOUT, &HeaderMap::new(), "")
            .unwrap();
    assert_eq!(e408.kind, ErrorKind::Timeout);
    assert!(e408.is_retryable());

    assert!(
        classify_common_http_status("op", StatusCode::BAD_REQUEST, &HeaderMap::new(), "bad")
            .is_none()
    );

    assert!(matches!(
        PolicyDecision::<()>::from_error(e429),
        PolicyDecision::Retry(_)
    ));
    assert!(matches!(
        PolicyDecision::<()>::from_error(Error::protocol("bad")),
        PolicyDecision::Fail(_)
    ));
    assert!(matches!(
        PolicyDecision::Ok(2u32).map_ok(|n| n * 3),
        PolicyDecision::Ok(6)
    ));
    assert!(matches!(
        policy_decision_from_http(
            http_resp(StatusCode::NOT_FOUND, HeaderMap::new(), ""),
            true,
            true,
            |_, _, _| Error::not_found("missing"),
        ),
        PolicyDecision::Ok((StatusCode::NOT_FOUND, _, _))
    ));
    assert!(matches!(
        policy_decision_from_http(
            http_resp(StatusCode::UNAUTHORIZED, HeaderMap::new(), ""),
            false,
            true,
            |_, _, _| Error::permission_denied("401"),
        ),
        PolicyDecision::AuthRefresh
    ));
}
