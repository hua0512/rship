use super::super::*;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap as AxumHeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, head, post, put};
use futures::StreamExt;
use rship_transport::{LimiterScope, TransportConfig};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct MockState {
    retry_after_hits: Arc<AtomicU32>,
    non_idemp_hits: Arc<AtomicU32>,
}

#[tokio::test]
async fn axum_roundtrip_retry_after_head_auth_reconcile_and_mid_body_reset() {
    let state = MockState::default();
    let app = Router::new()
        .route(
            "/retry-after",
            get(|State(st): State<MockState>| async move {
                if st.retry_after_hits.fetch_add(1, Ordering::SeqCst) == 0 {
                    let mut hdrs = AxumHeaderMap::new();
                    hdrs.insert(http::header::RETRY_AFTER, HeaderValue::from_static("3600"));
                    (StatusCode::TOO_MANY_REQUESTS, hdrs, "throttled").into_response()
                } else {
                    (StatusCode::OK, "recovered").into_response()
                }
            }),
        )
        .route(
            "/head-skip",
            head(|| async {
                let mut hdrs = AxumHeaderMap::new();
                hdrs.insert("x-head-marker", HeaderValue::from_static("present"));
                (StatusCode::OK, hdrs).into_response()
            }),
        )
        .route(
            "/auth",
            get(|hdrs: AxumHeaderMap| async move {
                let ok = hdrs
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    == Some("Bearer fresh-token");
                if ok {
                    (StatusCode::OK, "authed-body").into_response()
                } else {
                    (StatusCode::UNAUTHORIZED, "expired").into_response()
                }
            }),
        )
        .route(
            "/reconcile-412",
            post(|| async { (StatusCode::PRECONDITION_FAILED, "precondition").into_response() }),
        )
        .route(
            "/non-idempotent-500",
            post(|State(st): State<MockState>| async move {
                st.non_idemp_hits.fetch_add(1, Ordering::SeqCst);
                (StatusCode::INTERNAL_SERVER_ERROR, "ambiguous").into_response()
            }),
        )
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(TransportConfig::default()).expect("transport");
    let limiter = transport.control_limiter_for(LimiterScope::new("axum-test", "u"));

    // 1. Retry-After: 3600 capped to 40ms via execute_with_policy
    let cfg_ra = RetryPolicyConfig::new()
        .with_max_retries(2)
        .with_delays(Duration::from_millis(5), Duration::from_millis(40));
    let started = std::time::Instant::now();
    let body = execute_with_policy(
        &transport,
        &limiter,
        "axum-429",
        &cfg_ra,
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .get(format!("http://{addr}/retry-after"));
            async move { Ok(req) }
        },
        |resp| match resp.status {
            StatusCode::OK => PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
            StatusCode::TOO_MANY_REQUESTS => {
                PolicyDecision::Retry(Error::rate_limited("429", parse_retry_after(&resp.headers)))
            }
            s => PolicyDecision::Fail(Error::protocol(format!("unexpected {s}"))),
        },
    )
    .await
    .expect("429 should recover");
    assert_eq!(body, "recovered");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "Retry-After: 3600 must be capped to 40ms, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        limiter.snapshot().retry_quota_available,
        limiter.snapshot().retry_quota_max
    );

    // 2. HEAD with skip_response_body
    let head_cfg = RetryPolicyConfig::new().with_skip_response_body(true);
    let marker = execute_with_policy(
        &transport,
        &limiter,
        "axum-head",
        &head_cfg,
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .head(format!("http://{addr}/head-skip"));
            async move { Ok(req) }
        },
        |resp| {
            assert!(resp.body.is_empty());
            let val = resp
                .headers
                .get("x-head-marker")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            PolicyDecision::Ok(val)
        },
    )
    .await
    .expect("HEAD succeeds");
    assert_eq!(marker, "present");

    // 3. Auth refresh over real HTTP with sensitive bearer_header_value
    let tok = Arc::new(StdMutex::new("expired-token".to_string()));
    let tok_build = tok.clone();
    let tok_refresh = tok.clone();
    let authed = execute_with_auth_policy(
        &transport,
        &limiter,
        "axum-auth",
        &RetryPolicyConfig::new().with_max_retries(0),
        Idempotency::Idempotent,
        || {
            let cur = tok_build.lock().expect("tok").clone();
            let auth_hdr = bearer_header_value(&cur);
            let client = transport.control_client().clone();
            async move {
                let hdr = auth_hdr?;
                let req = client
                    .get(format!("http://{addr}/auth"))
                    .header(http::header::AUTHORIZATION, hdr);
                Ok((req, cur))
            }
        },
        |_old| {
            let tok_refresh = tok_refresh.clone();
            async move {
                *tok_refresh.lock().expect("tok") = "fresh-token".to_string();
                Ok(true)
            }
        },
        |resp| match resp.status {
            StatusCode::UNAUTHORIZED => PolicyDecision::AuthRefresh,
            StatusCode::OK => PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
            s => PolicyDecision::Fail(Error::protocol(format!("unexpected {s}"))),
        },
    )
    .await
    .expect("auth refresh succeeds");
    assert_eq!(authed, "authed-body");

    // 4. execute_with_reconcile_policy resolves HTTP 412
    let reconciled = execute_with_reconcile_policy(
        &transport,
        &limiter,
        "axum-412",
        &RetryPolicyConfig::new().with_max_retries(1),
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .post(format!("http://{addr}/reconcile-412"));
            async move { Ok(req) }
        },
        |resp| {
            if resp.status == StatusCode::PRECONDITION_FAILED {
                PolicyDecision::Reconcile(Error::precondition_failed("412"))
            } else {
                PolicyDecision::Ok("direct".to_string())
            }
        },
        |_err| async { Ok(ReconcileAction::Resolved("confirmed-via-head".to_string())) },
    )
    .await
    .expect("412 should resolve");
    assert_eq!(reconciled, "confirmed-via-head");

    // 5. NonIdempotent without reconcile makes strictly 1 attempt on 500
    let err = execute_with_policy::<(), _, _, _>(
        &transport,
        &limiter,
        "axum-non-idemp",
        &RetryPolicyConfig::new().with_max_retries(4),
        Idempotency::NonIdempotent,
        || {
            let req = transport
                .control_client()
                .post(format!("http://{addr}/non-idempotent-500"));
            async move { Ok(req) }
        },
        |_resp| PolicyDecision::Retry(Error::network("500")),
    )
    .await
    .unwrap_err();
    assert_eq!(state.non_idemp_hits.load(Ordering::SeqCst), 1);
    assert!(err.retries_exhausted());

    // 6. Mid-body TCP drop exercises read_control_body error routing through retry/reconcile
    let raw_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind raw");
    let raw_addr = raw_listener.local_addr().expect("raw addr");
    let raw_hits = Arc::new(AtomicU32::new(0));
    let raw_hits_srv = raw_hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = raw_listener.accept().await else {
                break;
            };
            let hit = raw_hits_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut req_buf = [0u8; 1024];
                let _ = sock.read(&mut req_buf).await;
                if hit == 0 || hit == 2 {
                    // Truncated body: promise 500 bytes, send 5, close socket immediately.
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\nhello",
                        )
                        .await;
                } else {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    let fast_cfg = RetryPolicyConfig::new()
        .with_max_retries(2)
        .with_delays(Duration::from_millis(5), Duration::from_millis(20));
    // Idempotent retries mid-body truncation and succeeds on 2nd connection (hit 0 -> hit 1).
    let recovered_body = execute_with_policy(
        &transport,
        &limiter,
        "mid-body-idemp",
        &fast_cfg,
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .get(format!("http://{raw_addr}/"));
            async move { Ok(req) }
        },
        |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
    )
    .await
    .expect("idempotent mid-body drop should retry and recover");
    assert_eq!(recovered_body, "ok");
    assert_eq!(raw_hits.load(Ordering::SeqCst), 2);

    // NonIdempotent refuses to retry mid-body truncation (hit 2 only, no hit 3).
    let non_idemp_err = execute_with_policy::<String, _, _, _>(
        &transport,
        &limiter,
        "mid-body-non-idemp",
        &fast_cfg,
        Idempotency::NonIdempotent,
        || {
            let req = transport
                .control_client()
                .post(format!("http://{raw_addr}/"));
            async move { Ok(req) }
        },
        |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
    )
    .await
    .unwrap_err();
    assert_eq!(raw_hits.load(Ordering::SeqCst), 3);
    assert!(non_idemp_err.retries_exhausted());
}

#[tokio::test]
async fn request_timeout_overrides_short_control_timeout_on_slow_endpoint() {
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(180)).await;
            (StatusCode::OK, "slow-ok")
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport =
        HttpTransport::new(TransportConfig::new().with_control_timeout(Duration::from_millis(60)))
            .expect("transport");
    let limiter = transport.control_limiter_for(LimiterScope::new("slow-test", "u"));

    // Default request_timeout (None) hits the short 60ms control_timeout.
    let err = execute_with_policy::<String, _, _, _>(
        &transport,
        &limiter,
        "slow-default",
        &RetryPolicyConfig::new().with_max_retries(0),
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .get(format!("http://{addr}/slow"));
            async move { Ok(req) }
        },
        |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert!(err.retries_exhausted());

    // Explicit cfg.request_timeout overrides the short control_timeout and succeeds.
    let ok = execute_with_policy(
        &transport,
        &limiter,
        "slow-override",
        &RetryPolicyConfig::new()
            .with_max_retries(0)
            .with_request_timeout(Duration::from_secs(2)),
        Idempotency::Idempotent,
        || {
            let req = transport
                .control_client()
                .get(format!("http://{addr}/slow"));
            async move { Ok(req) }
        },
        |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
    )
    .await
    .expect("request_timeout override should allow slow endpoint to succeed");
    assert_eq!(ok, "slow-ok");
}

#[tokio::test]
async fn execute_with_policy_future_is_send_for_tokio_spawn() {
    let app = Router::new().route("/ping", get(|| async { "pong" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(TransportConfig::default()).expect("transport");
    let limiter = transport.control_limiter_for(LimiterScope::new("send-test", "u"));
    let handle = tokio::spawn(async move {
        let cfg = RetryPolicyConfig::new();
        execute_with_policy(
            &transport,
            &limiter,
            "spawn-ping",
            &cfg,
            Idempotency::Idempotent,
            || {
                let req = transport
                    .control_client()
                    .get(format!("http://{addr}/ping"));
                async move { Ok(req) }
            },
            |resp| PolicyDecision::Ok(String::from_utf8_lossy(&resp.body).into_owned()),
        )
        .await
    });
    assert_eq!(handle.await.expect("join").expect("ok"), "pong");
}

#[tokio::test]
async fn sized_eof_stream_signals_eof_at_exact_length_and_zero_immediately() {
    // 1. 0-byte stream marks EOF immediately upon construction before any poll.
    let wd_zero = ProgressWatchdog::new(Duration::from_secs(1), None);
    let handle_zero = wd_zero.handle();
    assert!(!handle_zero.is_body_eof());
    let _stream_zero =
        watch_sized_upload_stream(&wd_zero, futures::stream::empty::<Result<Bytes>>(), 0);
    assert!(
        handle_zero.is_body_eof(),
        "0-byte sized upload must mark body EOF immediately on construction"
    );

    // 2. Non-empty stream marks EOF as soon as expected_len is reached (without polling None)
    //    and records total_bytes before signaling EOF.
    let wd = ProgressWatchdog::new(Duration::from_secs(1), None);
    let handle = wd.handle();
    let chunks = vec![
        Ok(Bytes::new()),
        Ok(Bytes::from_static(b"hello")),
        Ok(Bytes::from_static(b" world")),
    ];
    let mut stream = watch_sized_upload_stream(&wd, futures::stream::iter(chunks), 11);

    // Empty chunk must not trigger EOF or byte progress.
    let c0 = stream.next().await.expect("chunk 0").expect("ok");
    assert!(c0.is_empty());
    assert!(!handle.is_body_eof());
    assert_eq!(handle.total_bytes(), 0);

    // Partial chunk (5 of 11 bytes) advances bytes without marking EOF.
    let c1 = stream.next().await.expect("chunk 1").expect("ok");
    assert_eq!(c1.len(), 5);
    assert!(!handle.is_body_eof());
    assert_eq!(handle.total_bytes(), 5);

    // Final chunk reaches 11/11 bytes: marks EOF immediately without requiring trailing None.
    let c2 = stream.next().await.expect("chunk 2").expect("ok");
    assert_eq!(c2.len(), 6);
    assert_eq!(handle.total_bytes(), 11);
    assert!(
        handle.is_body_eof(),
        "reaching expected_len must mark body EOF before any trailing Poll::Ready(None)"
    );

    // 3. Stream error before expected_len must not mark body EOF.
    let wd_err = ProgressWatchdog::new(Duration::from_secs(1), None);
    let handle_err = wd_err.handle();
    let err_chunks: Vec<Result<Bytes>> = vec![
        Ok(Bytes::from_static(b"part")),
        Err(Error::source_mutated("short EOF")),
    ];
    let mut err_stream = watch_sized_upload_stream(&wd_err, futures::stream::iter(err_chunks), 10);
    let _ = err_stream.next().await.expect("first").expect("ok");
    assert!(!handle_err.is_body_eof());
    let err = err_stream.next().await.expect("err").unwrap_err();
    assert_eq!(err.kind, ErrorKind::SourceMutated);
    assert!(
        !handle_err.is_body_eof(),
        "error before expected_len must not mark body EOF"
    );
}

#[tokio::test]
async fn send_strict_upload_content_length_allows_slow_finalize_for_non_empty_and_zero_byte() {
    let app = Router::new().route(
        "/upload",
        put(|body: Bytes| async move {
            // Drain complete request body first, then simulate slow server-side
            // assembly/commit longer than data_stall_timeout (120ms) and shorter
            // than data_finalize_timeout (2s).
            let len = body.len();
            tokio::time::sleep(Duration::from_millis(300)).await;
            (StatusCode::OK, len.to_string()).into_response()
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(
        TransportConfig::new()
            .with_data_stall_timeout(Duration::from_millis(120))
            .with_data_finalize_timeout(Duration::from_secs(2))
            .with_data_total_timeout(Some(Duration::from_secs(10))),
    )
    .expect("transport");

    // 1. Non-empty Content-Length upload across multiple chunks succeeds despite slow finalize.
    let non_empty_chunks = vec![
        Ok(Bytes::from(vec![b'a'; 1024])),
        Ok(Bytes::from(vec![b'b'; 2048])),
        Ok(Bytes::from(vec![b'c'; 512])),
    ];
    let expected_len = 1024u64 + 2048 + 512;
    let body: ByteStream = Box::pin(futures::stream::iter(non_empty_chunks));
    let req = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, expected_len.to_string());
    let resp = send_strict_upload(
        &transport,
        "test-slow-finalize-non-empty",
        "TestUpload",
        req,
        body,
        expected_len,
    )
    .await
    .expect("non-empty Content-Length upload should survive slow finalize");
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_body = transport.read_control_body(resp).await.expect("read body");
    assert_eq!(resp_body.as_ref(), expected_len.to_string().as_bytes());

    // 2. 0-byte Content-Length upload succeeds despite slow finalize (Hyper never polls body).
    let empty_body: ByteStream = Box::pin(futures::stream::empty());
    let req_zero = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "0");
    let resp_zero = send_strict_upload(
        &transport,
        "test-slow-finalize-zero-byte",
        "TestUpload",
        req_zero,
        empty_body,
        0,
    )
    .await
    .expect("0-byte Content-Length upload should survive slow finalize");
    assert_eq!(resp_zero.status(), StatusCode::OK);
    let resp_zero_body = transport
        .read_control_body(resp_zero)
        .await
        .expect("read zero body");
    assert_eq!(resp_zero_body.as_ref(), b"0");

    // 3. Negative control: mid-body stall BEFORE reaching expected_len still trips
    //    data_stall_timeout (not data_finalize_timeout).
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(2);
    tx.send(Ok(Bytes::from(vec![b'x'; 512])))
        .await
        .expect("send");
    let stalled_body: ByteStream = Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    let req_stall = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "2048");
    let started = std::time::Instant::now();
    let err = send_strict_upload(
        &transport,
        "test-mid-body-stall",
        "TestUpload",
        req_stall,
        stalled_body,
        2048,
    )
    .await
    .unwrap_err();
    drop(tx);
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert!(
        err.message().contains("stalled"),
        "expected pre-EOF stall timeout, got: {}",
        err.message()
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "mid-body stall must trip data_stall_timeout (~120ms), not data_finalize_timeout (2s); took {:?}",
        started.elapsed()
    );

    // 4. Negative control: short EOF surfaces SourceMutated through captured_err.
    let short_body: ByteStream = Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
        b"short",
    ))]));
    let req_short = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "64");
    let short_err = send_strict_upload(
        &transport,
        "test-short-eof",
        "TestUpload",
        req_short,
        short_body,
        64,
    )
    .await
    .unwrap_err();
    assert_eq!(short_err.kind, ErrorKind::SourceMutated);
}

#[tokio::test]
async fn send_watched_sized_upload_with_capture_handles_zero_and_non_empty_slow_finalize() {
    let app = Router::new().route(
        "/upload",
        put(|body: Bytes| async move {
            let len = body.len();
            tokio::time::sleep(Duration::from_millis(300)).await;
            (StatusCode::OK, len.to_string()).into_response()
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(
        TransportConfig::new()
            .with_data_stall_timeout(Duration::from_millis(120))
            .with_data_finalize_timeout(Duration::from_secs(2))
            .with_data_total_timeout(Some(Duration::from_secs(10))),
    )
    .expect("transport");

    // 1. Non-empty upload succeeds despite slow finalize (> data_stall_timeout).
    let expected_len = 2560u64;
    let stream = futures::stream::iter(vec![
        Ok(Bytes::from(vec![b'x'; 1024])),
        Ok(Bytes::from(vec![b'y'; 1536])),
    ]);
    let captured_err = Arc::new(StdMutex::new(None));
    let req = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, expected_len.to_string());
    let resp = send_watched_sized_upload_with_capture(
        &transport,
        "sized-non-empty",
        req,
        stream,
        expected_len,
        captured_err,
    )
    .await
    .expect("non-empty sized upload should survive slow finalize");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        transport.read_control_body(resp).await.unwrap().as_ref(),
        b"2560"
    );

    // 2. 0-byte upload marks body EOF immediately and succeeds despite slow finalize.
    let captured_zero = Arc::new(StdMutex::new(None));
    let req_zero = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "0");
    let resp_zero = send_watched_sized_upload_with_capture(
        &transport,
        "sized-zero",
        req_zero,
        futures::stream::empty::<Result<Bytes>>(),
        0,
        captured_zero,
    )
    .await
    .expect("0-byte sized upload should survive slow finalize");
    assert_eq!(resp_zero.status(), StatusCode::OK);
    assert_eq!(
        transport
            .read_control_body(resp_zero)
            .await
            .unwrap()
            .as_ref(),
        b"0"
    );

    // 3. Mid-body stall before expected_len trips data_stall_timeout.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(2);
    tx.send(Ok(Bytes::from(vec![b'z'; 256]))).await.unwrap();
    let stalled = Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    let req_stall = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "1024");
    let started = std::time::Instant::now();
    let stall_err = send_watched_sized_upload_with_capture(
        &transport,
        "sized-stall",
        req_stall,
        stalled,
        1024,
        Arc::new(StdMutex::new(None)),
    )
    .await
    .unwrap_err();
    drop(tx);
    assert_eq!(stall_err.kind, ErrorKind::Timeout);
    assert!(started.elapsed() < Duration::from_secs(1));

    // 4. Captured stream error (SourceMutated) is surfaced intact.
    let captured_mut = Arc::new(StdMutex::new(None));
    let strict = StrictBodyStream::new(
        "sized-capture",
        Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(b"abc"))])),
        32,
        captured_mut.clone(),
    );
    let req_mut = transport
        .data_client()
        .put(format!("http://{addr}/upload"))
        .header(http::header::CONTENT_LENGTH, "32");
    let mut_err = send_watched_sized_upload_with_capture(
        &transport,
        "sized-source-mutated",
        req_mut,
        strict,
        32,
        captured_mut,
    )
    .await
    .unwrap_err();
    assert_eq!(mut_err.kind, ErrorKind::SourceMutated);
}
