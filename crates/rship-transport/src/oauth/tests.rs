use super::*;
use crate::TransportConfig;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Form, Json, Router};
use rship_core::clock::VirtualClock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::net::TcpListener;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rship-oauth-test-{prefix}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_refresh_cfg(token_url: String) -> OAuth2RefreshConfig {
    OAuth2RefreshConfig {
        principal: "alice@example.com".into(),
        client_id: "cid".into(),
        client_secret: Some("csec".into()),
        token_url,
        refresh_scope: None,
        missing_refresh_hint: "re-run auth".into(),
        refresh_error_hint: None,
    }
}

#[tokio::test]
async fn oauth2_rotated_refresh_token_race_across_two_managers_sharing_file_store() {
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let active_rt = Arc::new(StdMutex::new("rt-0".to_string()));
    let rc = refresh_calls.clone();
    let rt_state = active_rt.clone();

    let app = Router::new().route(
        "/token",
        post(move |Form(params): Form<HashMap<String, String>>| {
            let rc = rc.clone();
            let rt_state = rt_state.clone();
            async move {
                let call_no = rc.fetch_add(1, Ordering::SeqCst) + 1;
                let sent_rt = params.get("refresh_token").cloned().unwrap_or_default();
                // Simulate IdP latency so concurrent refreshers overlap in flight.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let mut current = rt_state.lock().unwrap();
                if sent_rt != *current {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_grant",
                            "error_description": format!("stale refresh_token `{sent_rt}`")
                        })),
                    );
                }
                let next_rt = format!("rt-{call_no}");
                *current = next_rt.clone();
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": format!("acc-{call_no}"),
                        "refresh_token": next_rt,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    })),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let tmp = TempDirGuard::new("rotate");
    let tok_path = tmp.path().join("token.json");
    let seed_store = FileTokenStore::new(&tok_path);
    seed_store
        .save(&OAuthToken {
            access_token: "acc-0".into(),
            refresh_token: Some("rt-0".into()),
            token_type: "Bearer".into(),
            expires_at_unix_secs: 1_700_000_000, // expired at clock=1_700_001_000
            scope: None,
        })
        .unwrap();

    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_001_000));
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let cfg = make_refresh_cfg(format!("http://{addr}/token"));

    let mgr1 = OAuth2TokenManager::new(
        cfg.clone(),
        transport.clone(),
        Arc::new(FileTokenStore::new(&tok_path)),
        clock.clone(),
    )
    .unwrap();
    let mgr2 = OAuth2TokenManager::new(
        cfg,
        transport,
        Arc::new(FileTokenStore::new(&tok_path)),
        clock,
    )
    .unwrap();

    let (r1, r2) = tokio::join!(mgr1.access_token(), mgr2.access_token());
    assert_eq!(r1.unwrap(), "acc-1");
    assert_eq!(r2.unwrap(), "acc-1");
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "second manager must adopt refreshed token under file lock instead of reusing rotated refresh_token"
    );

    // Concurrent force_refresh(rejected="acc-1") across both managers must also
    // serialize via file lock and rotate rt-1 -> rt-2 with a single HTTP call.
    let (f1, f2) = tokio::join!(mgr1.force_refresh("acc-1"), mgr2.force_refresh("acc-1"));
    assert_eq!(f1.unwrap(), "acc-2");
    assert_eq!(f2.unwrap(), "acc-2");
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        2,
        "concurrent force_refresh across two managers must only hit token endpoint once"
    );

    // Persisted file holds the latest rotated refresh_token `rt-2`.
    let persisted = FileTokenStore::new(&tok_path).load().unwrap().unwrap();
    assert_eq!(persisted.access_token, "acc-2");
    assert_eq!(persisted.refresh_token.as_deref(), Some("rt-2"));
}

#[tokio::test]
async fn oauth2_short_lived_tokens_do_not_refresh_on_every_call() {
    for ttl in [30i64, 60i64] {
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let rc = refresh_calls.clone();

        let app = Router::new().route(
            "/token",
            post(move || {
                let rc = rc.clone();
                async move {
                    let n = rc.fetch_add(1, Ordering::SeqCst) + 1;
                    Json(serde_json::json!({
                        "access_token": format!("short-acc-{n}"),
                        "refresh_token": "rt-keep",
                        "token_type": "Bearer",
                        "expires_in": ttl,
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let tmp = TempDirGuard::new(&format!("short-ttl-{ttl}"));
        let tok_path = tmp.path().join("token.json");
        let file_store = Arc::new(FileTokenStore::new(&tok_path));
        file_store
            .save(&OAuthToken {
                access_token: "expired".into(),
                refresh_token: Some("rt-keep".into()),
                token_type: "Bearer".into(),
                expires_at_unix_secs: 1_699_999_000,
                scope: None,
            })
            .unwrap();

        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let cfg = make_refresh_cfg(format!("http://{addr}/token"));
        let mgr = OAuth2TokenManager::new(
            cfg.clone(),
            transport.clone(),
            file_store.clone(),
            clock.clone(),
        )
        .unwrap();

        assert_eq!(mgr.access_token().await.unwrap(), "short-acc-1");
        assert_eq!(mgr.access_token().await.unwrap(), "short-acc-1");
        // Advance less than half TTL -> still valid, must NOT refresh again.
        clock.advance(std::time::Duration::from_secs((ttl / 2 - 1) as u64));
        assert_eq!(mgr.access_token().await.unwrap(), "short-acc-1");
        // A second manager loading the persisted file store must also honor
        // the persisted refresh_margin_secs and avoid refreshing prematurely.
        let mgr2 = OAuth2TokenManager::new(cfg, transport, file_store, clock.clone()).unwrap();
        assert_eq!(mgr2.access_token().await.unwrap(), "short-acc-1");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            1,
            "expires_in={ttl}s must not refresh on every call"
        );

        // Advancing past half TTL triggers proactive refresh as expected.
        clock.advance(std::time::Duration::from_secs(2));
        assert_eq!(mgr.access_token().await.unwrap(), "short-acc-2");
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn oauth2_token_store_io_and_locking_never_block_async_worker_thread() {
    use std::sync::mpsc;
    use std::thread::ThreadId;

    struct BlockingCheckLock {
        runtime_tid: ThreadId,
        unblock_rx: mpsc::Receiver<()>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for BlockingCheckLock {
        fn drop(&mut self) {
            assert_ne!(
                std::thread::current().id(),
                self.runtime_tid,
                "refresh lock guard drop must run on spawn_blocking, not async worker thread"
            );
            // Block until sibling Tokio task unblocks drop — deadlocks if on runtime thread!
            self.unblock_rx.recv().unwrap();
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct BlockingCheckStore {
        runtime_tid: ThreadId,
        inner: StdMutex<Option<(OAuthToken, Option<i64>)>>,
        load_gate: StdMutex<Option<mpsc::Receiver<()>>>,
        lock_gate: StdMutex<Option<mpsc::Receiver<()>>>,
        save_gate: StdMutex<Option<mpsc::Receiver<()>>>,
        drop_gate: StdMutex<Option<mpsc::Receiver<()>>>,
        lock_dropped: Arc<std::sync::atomic::AtomicBool>,
        loads: AtomicUsize,
        saves: AtomicUsize,
        locks: AtomicUsize,
    }

    impl TokenStore for BlockingCheckStore {
        fn load(&self) -> Result<Option<OAuthToken>> {
            Ok(self.load_with_margin()?.map(|(t, _)| t))
        }

        fn save(&self, token: &OAuthToken) -> Result<()> {
            self.save_with_margin(token, None)
        }

        fn load_with_margin(&self) -> Result<Option<(OAuthToken, Option<i64>)>> {
            assert_ne!(
                std::thread::current().id(),
                self.runtime_tid,
                "store.load must run on spawn_blocking, not async worker thread"
            );
            self.loads.fetch_add(1, Ordering::SeqCst);
            if let Some(rx) = self.load_gate.lock().unwrap().take() {
                rx.recv().unwrap();
            }
            Ok(self.inner.lock().unwrap().clone())
        }

        fn save_with_margin(
            &self,
            token: &OAuthToken,
            refresh_margin_secs: Option<i64>,
        ) -> Result<()> {
            assert_ne!(
                std::thread::current().id(),
                self.runtime_tid,
                "store.save must run on spawn_blocking, not async worker thread"
            );
            self.saves.fetch_add(1, Ordering::SeqCst);
            if let Some(rx) = self.save_gate.lock().unwrap().take() {
                rx.recv().unwrap();
            }
            *self.inner.lock().unwrap() = Some((token.clone(), refresh_margin_secs));
            Ok(())
        }

        fn lock_refresh(&self) -> Result<Option<Box<dyn Send>>> {
            assert_ne!(
                std::thread::current().id(),
                self.runtime_tid,
                "store.lock_refresh must run on spawn_blocking, not async worker thread"
            );
            self.locks.fetch_add(1, Ordering::SeqCst);
            if let Some(rx) = self.lock_gate.lock().unwrap().take() {
                rx.recv().unwrap();
            }
            let drop_rx = self.drop_gate.lock().unwrap().take().unwrap();
            Ok(Some(Box::new(BlockingCheckLock {
                runtime_tid: self.runtime_tid,
                unblock_rx: drop_rx,
                dropped: Arc::clone(&self.lock_dropped),
            })))
        }
    }

    let app = Router::new().route(
        "/token",
        post(|| async {
            Json(serde_json::json!({
                "access_token": "nonblocking-fresh",
                "refresh_token": "rt-nb",
                "token_type": "Bearer",
                "expires_in": 3600,
            }))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let (load_tx, load_rx) = mpsc::channel();
    let (lock_tx, lock_rx) = mpsc::channel();
    let (save_tx, save_rx) = mpsc::channel();
    let (drop_tx, drop_rx) = mpsc::channel();
    let lock_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let store = Arc::new(BlockingCheckStore {
        runtime_tid: std::thread::current().id(),
        inner: StdMutex::new(Some((
            OAuthToken {
                access_token: "stale".into(),
                refresh_token: Some("rt-nb".into()),
                token_type: "Bearer".into(),
                expires_at_unix_secs: 1_699_999_000,
                scope: None,
            },
            None,
        ))),
        load_gate: StdMutex::new(Some(load_rx)),
        lock_gate: StdMutex::new(Some(lock_rx)),
        save_gate: StdMutex::new(Some(save_rx)),
        drop_gate: StdMutex::new(Some(drop_rx)),
        lock_dropped: Arc::clone(&lock_dropped),
        loads: AtomicUsize::new(0),
        saves: AtomicUsize::new(0),
        locks: AtomicUsize::new(0),
    });

    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        transport,
        store.clone(),
        clock,
    )
    .unwrap();

    // Spawn a sibling task on the SAME single-threaded runtime that unblocks
    // each blocking store phase only after yielding on the async runtime.
    let unblocker = tokio::spawn(async move {
        for tx in [load_tx, lock_tx, save_tx, drop_tx] {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            tx.send(()).unwrap();
        }
    });

    let tok = tokio::time::timeout(std::time::Duration::from_secs(5), mgr.access_token())
        .await
        .expect("must not deadlock single-threaded Tokio runtime")
        .unwrap();
    unblocker.await.unwrap();

    assert_eq!(tok, "nonblocking-fresh");
    assert!(store.loads.load(Ordering::SeqCst) >= 2);
    assert_eq!(store.locks.load(Ordering::SeqCst), 1);
    assert_eq!(store.saves.load(Ordering::SeqCst), 1);
    assert!(lock_dropped.load(Ordering::SeqCst));
}

/// Token store whose first `fail_saves` saves fail (e.g. disk full / read-only config dir).
struct FlakySaveStore {
    inner: InMemoryTokenStore,
    fail_saves: AtomicUsize,
}

impl TokenStore for FlakySaveStore {
    fn load(&self) -> Result<Option<OAuthToken>> {
        self.inner.load()
    }

    fn save(&self, token: &OAuthToken) -> Result<()> {
        self.save_with_margin(token, None)
    }

    fn load_with_margin(&self) -> Result<Option<(OAuthToken, Option<i64>)>> {
        self.inner.load_with_margin()
    }

    fn save_with_margin(&self, token: &OAuthToken, margin: Option<i64>) -> Result<()> {
        if self
            .fail_saves
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(Error::io(
                "persist OAuth token",
                std::io::Error::other("No space left on device"),
            ));
        }
        self.inner.save_with_margin(token, margin)
    }
}

#[tokio::test]
async fn oauth2_rotated_refresh_token_survives_a_failed_token_store_save() {
    // Microsoft-style IdP: every refresh rotates the refresh_token and invalidates the old one.
    let active_rt = Arc::new(StdMutex::new("rt-0".to_string()));
    let calls = Arc::new(AtomicUsize::new(0));
    let rt_state = active_rt.clone();
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/token",
        post(move |Form(params): Form<HashMap<String, String>>| {
            let rt_state = rt_state.clone();
            let calls_c = calls_c.clone();
            async move {
                let n = calls_c.fetch_add(1, Ordering::SeqCst) + 1;
                let sent = params.get("refresh_token").cloned().unwrap_or_default();
                let mut cur = rt_state.lock().unwrap();
                if sent != *cur {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "invalid_grant" })),
                    );
                }
                *cur = format!("rt-{n}");
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": format!("acc-{n}"),
                        "refresh_token": format!("rt-{n}"),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    })),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let store = Arc::new(FlakySaveStore {
        inner: InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "acc-0".into(),
            refresh_token: Some("rt-0".into()),
            token_type: "Bearer".into(),
            expires_at_unix_secs: 1_699_999_000,
            scope: None,
        })),
        fail_saves: AtomicUsize::new(1),
    });
    let clock = Arc::new(VirtualClock::new(1_700_000_000));
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        HttpTransport::new(TransportConfig::default()).unwrap(),
        store.clone(),
        clock.clone(),
    )
    .unwrap();

    // The refresh succeeds at the IdP (rt-0 is now dead) but persisting rt-1 fails: the new
    // token must still be served from memory.
    assert_eq!(mgr.access_token().await.unwrap(), "acc-1");

    // Next refresh must use the rotated rt-1 held in memory, not the stale rt-0 on disk.
    clock.advance(std::time::Duration::from_secs(7200));
    assert_eq!(mgr.access_token().await.unwrap(), "acc-2");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let persisted = store.load().unwrap().unwrap();
    assert_eq!(persisted.refresh_token.as_deref(), Some("rt-2"));
}

#[tokio::test]
async fn oauth2_refresh_retries_429_and_503_with_retry_after_and_persists_rotated_token() {
    use axum::response::IntoResponse;

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/token",
        post(move || {
            let calls_c = calls_c.clone();
            async move {
                let n = calls_c.fetch_add(1, Ordering::SeqCst) + 1;
                match n {
                    1 => (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(http::header::RETRY_AFTER, "0")],
                        "rate limited",
                    )
                        .into_response(),
                    2 => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(http::header::RETRY_AFTER, "1")],
                        "upstream unavailable",
                    )
                        .into_response(),
                    _ => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": "acc-recovered",
                            "refresh_token": "rt-rotated",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        })),
                    )
                        .into_response(),
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "acc-old".into(),
        refresh_token: Some("rt-old".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: 1_699_999_000,
        scope: None,
    })));
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let start_nanos = clock.now_unix_nanos();
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        HttpTransport::new(TransportConfig::default()).unwrap(),
        store.clone(),
        clock.clone(),
    )
    .unwrap();

    let tok = mgr.access_token().await.unwrap();
    assert_eq!(tok, "acc-recovered");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    // 1st 429 Retry-After: 0 applies non-zero jitter floor; 2nd 503 Retry-After: 1 adds 1s.
    let elapsed_ms = (clock.now_unix_nanos() - start_nanos) / 1_000_000;
    assert!(
        elapsed_ms >= 1_001,
        "expected >= 1s + nonzero floor virtual sleep, got {elapsed_ms}ms"
    );
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.access_token, "acc-recovered");
    assert_eq!(saved.refresh_token.as_deref(), Some("rt-rotated"));
}

#[tokio::test]
async fn oauth2_refresh_retries_transient_transport_drop_and_succeeds() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_c = accepts.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let n = accepts_c.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                // Drop connection abruptly before sending any HTTP status/headers.
                drop(stream);
                continue;
            }
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let body = r#"{"access_token":"acc-after-drop","refresh_token":"rt-2","token_type":"Bearer","expires_in":3600}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "acc-old".into(),
        refresh_token: Some("rt-1".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: 1_699_999_000,
        scope: None,
    })));
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        HttpTransport::new(TransportConfig::default()).unwrap(),
        store,
        clock,
    )
    .unwrap();

    let tok = mgr.access_token().await.unwrap();
    assert_eq!(tok, "acc-after-drop");
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn oauth2_refresh_caps_huge_retry_after_and_marks_retries_exhausted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/token",
        post(move || {
            let calls_c = calls_c.clone();
            async move {
                calls_c.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(http::header::RETRY_AFTER, "86400")],
                    "too many requests",
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "acc-old".into(),
        refresh_token: Some("rt-1".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: 1_699_999_000,
        scope: None,
    })));
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let start_nanos = clock.now_unix_nanos();
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        HttpTransport::new(TransportConfig::default()).unwrap(),
        store,
        clock.clone(),
    )
    .unwrap()
    .with_retry_config(2, Duration::from_millis(10), Duration::from_millis(50));

    let err = mgr.access_token().await.unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(err.kind, ErrorKind::RateLimited);
    assert_eq!(err.retry_class(), RetryClass::Throttled);
    assert!(err.retries_exhausted());
    assert!(!err.is_retryable());
    let elapsed_ms = (clock.now_unix_nanos() - start_nanos) / 1_000_000;
    assert_eq!(
        elapsed_ms, 100,
        "2 retries with Retry-After: 86400 capped at 50ms must advance virtual clock by 100ms"
    );
}

#[tokio::test]
async fn oauth2_refresh_does_not_retry_permanent_400_invalid_grant() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/token",
        post(move || {
            let calls_c = calls_c.clone();
            async move {
                calls_c.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "acc-old".into(),
        refresh_token: Some("rt-revoked".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: 1_699_999_000,
        scope: None,
    })));
    let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
    let mgr = OAuth2TokenManager::new(
        make_refresh_cfg(format!("http://{addr}/token")),
        HttpTransport::new(TransportConfig::default()).unwrap(),
        store,
        clock,
    )
    .unwrap();

    let err = mgr.access_token().await.unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(err.kind, ErrorKind::PermissionDenied);
    assert_eq!(err.retry_class(), RetryClass::Permanent);
    assert!(!err.retries_exhausted());
}

#[tokio::test]
async fn pkce_start_omits_empty_and_whitespace_scope_but_keeps_non_empty_scope() {
    let base_cfg = |scope: &str| PkceConfig {
        auth_endpoint: "https://example.com/oauth2/authorize".into(),
        token_endpoint: "https://example.com/oauth2/token".into(),
        client_id: "cid".into(),
        client_secret: None,
        scope: scope.into(),
        callback_path: "/callback".into(),
        preferred_port: None,
        strict_port: false,
        extra_auth_params: Vec::new(),
        include_scope_in_token_exchange: false,
        success_title: "Done".into(),
    };

    for empty_scope in ["", "   \t "] {
        let sess = PkceSession::start(base_cfg(empty_scope)).await.unwrap();
        let parsed = url::Url::parse(&sess.auth_url).unwrap();
        assert!(
            parsed.query_pairs().all(|(k, _)| k != "scope"),
            "scope `{empty_scope:?}` must be omitted from {}",
            sess.auth_url
        );
    }

    let sess = PkceSession::start(base_cfg(" files.read files.write "))
        .await
        .unwrap();
    let parsed = url::Url::parse(&sess.auth_url).unwrap();
    let scopes: Vec<String> = parsed
        .query_pairs()
        .filter(|(k, _)| k == "scope")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(scopes, vec!["files.read files.write"]);
}

#[tokio::test]
async fn static_bearer_auth_preserves_principal_token_order_and_redacts_debug() {
    let auth = StaticBearerAuth::new("alice@example.com", "super-secret-bearer-token");
    assert_eq!(auth.principal(), "alice@example.com");
    assert_eq!(
        auth.access_token().await.unwrap(),
        "super-secret-bearer-token"
    );

    let dbg = format!("{auth:?}");
    assert!(dbg.contains("alice@example.com"));
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("super-secret-bearer-token"));

    let err = auth.force_refresh("old").await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied);
    assert_eq!(err.retry_class(), RetryClass::Permanent);
}
