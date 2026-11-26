#[cfg(any(feature = "gdrive", feature = "gcs"))]
#[allow(dead_code)]
const TEST_SA_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkEYEt8W1qR3Sp
iRmZKbkq3CRZUgvAC3M2nFEGL62wdrjvwQ6GpZi8MwETTCvikAF6Q1qr2zpuy1P/
IVF1zJT0X2XXG/fiVUFUVEpf9FmVPjHkP6tlMWzb1WH1bnYPabwmJJ9eN/lJ3PrU
wLv4MY695GvE2ByQg1xoE3BfWWzFwMbFpaZAvWKzcZCx3EbrWAMEcN39bvcVeT5c
3oHRYmhjFPFtVIrc1g9n4HKKxKyByNSRDdUhfc/fTOXE3vpqtuD1vEAqAu8AVM0E
KG2L1RnLiVglY+eO/SCnxqxtzoR1QjZ75215SgL4tpjQXhNQLkL88Z/Cx7HN9gbc
VzpdlA4TAgMBAAECggEADl25gmUonD8GCHJCmSHf436pREsYj5W12zHIVMugdQyP
CuMuGnZh6ZdY5DGyVGIrBajEFGE9DAkyY4OVkWyinix7Y/jQcE+O5VRhHvkFKSzl
9z4felwjqRe6EbvnvRubwD28U2YGBb+t7F4VORJ+FSFHVi3t/RhmALqz8GQLDjKM
NarYigojkk0IWUlrfbIhN+I8Y+4sJ38+dUVXDKNYzqOmKt+Uyg2lRiDTLOwLZL41
MoyT6yW0OwNdDh62bc0ChagJcZa4+dR29sCNiDAWfuInn+o9vsvIAcURmtQriqNl
bnytlnD7GB0irGjKmRu50xPvKuJLKKSgZNzJckLKSQKBgQD7Gv/DRBDYafXcFi3P
ONJLLPLdNcKHCGay1zT8fG9U5KSGXa6DiJQqV9F/bZ2bZhDIpJ7qXhi37sV5Kh4F
vDPE5H5MQVSMu5EFcbRGNkQv582lexwtU1spEej+v8QDhC+rbrZcvDQJPQCQiUHO
6L8v/3FaUB/pvOGl4aOMSE4EHwKBgQDog41Hmmqh8tOi2k296cMEQLMBuYMh0v3c
RIY9nAp25pqvfZM4+WT/lLWbp5zlVAa0+OlmYjUfPMR9ashpsTanK3BJzpnPcDh5
nw9Q7GqcCnaMGfkXhbFL42Om3WU0etGGYg4fdyNADK9l1VA+4PVSsHJnCF/k21pW
ypTUCCMXjQKBgQCHc5DzrAvKMZ5GElCzr1sA4kY/vXgpjwaXAi+64wTLLmrxcCdr
HImQLb78lgymfvAey25NzmRXE53CNk3rmhHy666VQ8hwAd3Aqg0ssqkljk0ILtiM
OqK6DMc6ZAdAPlXYi+gjLgKD2Twsu12cV0CKi6iBpycP1quB561pRreO0QKBgCQj
XjAE1hH5td8X4wFjdcYRcEESXklBi+dSVzL4L8AvM1eXQuyWBpaavGdG8+HI34n9
LfmVxf/m5/s+P4v92Sq+W6N9Evbk0EJG8JB5TlCWZ7p6xvZa9yV+YBytSG+Rr0Md
tmg5kicAUbqYHvLG8Bo8BmvxJ0ZguXfH4L3bzeh5AoGAV0VffYO++qwvqljZYWM4
lz5fhHD/Of5fQ9o4DByZqwNnOWsmWMnd7h/wHNcFh3FMfGMo90T+LZpToIgm1G8H
3gtNqdk2T/SWfg+VuTDWAJLQF8XHkvVyUpGx6/PFKVUlvqZrNksrnJiLQRd8tGdV
iEP0Q2gYfn8kNNw/KekT9Tg=
-----END PRIVATE KEY-----
";

#[cfg(feature = "http")]
mod transport_and_common_http {
    #[cfg(any(feature = "webdav", feature = "gdrive", feature = "gcs"))]
    use crate::mock_http::MockAction;
    use crate::mock_http::{MockHttpServer, MockResponse};
    use rship::core::ErrorKind;
    use rship::core::clock::{Clock, VirtualClock};
    use rship::transport::oauth::{
        FileTokenStore, InMemoryTokenStore, OAuth2RefreshConfig, OAuth2TokenManager, OAuthProvider,
        OAuthToken, PkceConfig, PkceSession, StaticBearerAuth, TokenStore,
    };
    use rship::transport::{HttpTransport, TransportConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn test_transport() -> HttpTransport {
        HttpTransport::new(TransportConfig::new()).unwrap()
    }

    fn refresh_cfg(token_url: String) -> OAuth2RefreshConfig {
        OAuth2RefreshConfig {
            principal: "user@example.com".to_string(),
            client_id: "cid-123".to_string(),
            client_secret: Some("csec-456".to_string()),
            token_url,
            refresh_scope: Some("drive.file".to_string()),
            missing_refresh_hint: "re-auth".to_string(),
            refresh_error_hint: Some("check client".to_string()),
        }
    }

    // ------------------------------------------------------------------------
    // Area #2: `rship-transport` (Tier 1 >= 5, Tier 2 >= 5)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn tier1_transport_oauth2_valid_cached_token_skips_http() {
        let srv = MockHttpServer::start().await;
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "cached-tok".to_string(),
            refresh_token: Some("ref-1".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_unix_secs: 1_700_003_600,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store,
            clock,
        )
        .unwrap();

        let tok = mgr.access_token().await.unwrap();
        assert_eq!(tok, "cached-tok");
        assert_eq!(srv.hit_count(), 0);
    }

    #[tokio::test]
    async fn tier1_transport_oauth2_proactive_refresh_and_preserves_refresh_token() {
        let srv = MockHttpServer::start().await;
        srv.enqueue_response(MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "refreshed-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        ));

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "near-expiry".to_string(),
            refresh_token: Some("keep-my-refresh-tok".to_string()),
            token_type: "Bearer".to_string(),
            // Within PROACTIVE_REFRESH_MARGIN_SECS (60s).
            expires_at_unix_secs: 1_700_000_030,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store.clone(),
            clock,
        )
        .unwrap();

        let tok = mgr.access_token().await.unwrap();
        assert_eq!(tok, "refreshed-tok");
        assert_eq!(srv.hit_count(), 1);

        let reqs = srv.requests();
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/token");
        assert_eq!(
            reqs[0].form_get("grant_type").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(reqs[0].form_get("client_id").as_deref(), Some("cid-123"));
        assert_eq!(
            reqs[0].form_get("client_secret").as_deref(),
            Some("csec-456")
        );
        assert_eq!(
            reqs[0].form_get("refresh_token").as_deref(),
            Some("keep-my-refresh-tok")
        );
        assert_eq!(reqs[0].form_get("scope").as_deref(), Some("drive.file"));

        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.access_token, "refreshed-tok");
        assert_eq!(saved.refresh_token.as_deref(), Some("keep-my-refresh-tok"));
    }

    #[tokio::test]
    async fn tier1_transport_oauth2_concurrent_force_refresh_single_flight() {
        let srv = MockHttpServer::start().await;
        srv.enqueue_response(
            MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "fresh-sf",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            )
            .with_delay(Duration::from_millis(80)),
        );

        let tmp = TempDir::new().unwrap();
        let tok_path = tmp.path().join("tok.json");
        let file_store = Arc::new(FileTokenStore::new(&tok_path));
        file_store
            .save(&OAuthToken {
                access_token: "old".to_string(),
                refresh_token: Some("ref-sf".to_string()),
                token_type: "Bearer".to_string(),
                expires_at_unix_secs: 1_700_003_600,
                scope: None,
            })
            .unwrap();

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let mgr = Arc::new(
            OAuth2TokenManager::new(
                refresh_cfg(srv.url("/token")),
                test_transport(),
                file_store,
                clock,
            )
            .unwrap(),
        );

        let (r1, r2, r3) = tokio::join!(
            mgr.force_refresh("old"),
            mgr.force_refresh("old"),
            mgr.force_refresh("old")
        );
        assert_eq!(r1.unwrap(), "fresh-sf");
        assert_eq!(r2.unwrap(), "fresh-sf");
        assert_eq!(r3.unwrap(), "fresh-sf");
        assert_eq!(
            srv.hit_count(),
            1,
            "concurrent force_refresh calls must single-flight to 1 HTTP POST"
        );
    }

    #[tokio::test]
    async fn tier1_transport_pkce_start_s256_and_callback_exchange() {
        let token_srv = MockHttpServer::start().await;
        token_srv.enqueue_response(MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "pkce-access",
                "refresh_token": "pkce-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "files.read"
            }),
        ));

        let session = PkceSession::start(PkceConfig {
            client_id: "pkce-cid".to_string(),
            client_secret: None,
            auth_endpoint: "https://auth.example.test/authorize".to_string(),
            token_endpoint: token_srv.url("/token"),
            scope: "files.read".to_string(),
            extra_auth_params: vec![("access_type".into(), "offline".into())],
            include_scope_in_token_exchange: true,
            callback_path: "/callback".to_string(),
            success_title: "OK".to_string(),
            preferred_port: None,
            strict_port: false,
        })
        .await
        .unwrap();

        assert!(session.auth_url.contains("code_challenge_method=S256"));
        assert!(session.auth_url.contains("access_type=offline"));
        assert!(session.auth_url.contains("scope=files.read"));

        let port = session.port();
        let state = session.state.clone();
        let redirect_uri = session.redirect_uri.clone();

        tokio::spawn(async move {
            // 1. Browser incidental /favicon.ico probe (must be ignored).
            if let Ok(mut s1) = TcpStream::connect(("127.0.0.1", port)).await {
                let _ = s1
                    .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    .await;
                let mut sink = [0u8; 512];
                let _ = s1.read(&mut sink).await;
            }
            // 2. Real OAuth callback with valid state & code.
            let mut s2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let req = format!(
                "GET /callback?code=auth-code-99&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            );
            s2.write_all(req.as_bytes()).await.unwrap();
            let mut sink = [0u8; 1024];
            let _ = s2.read(&mut sink).await;
        });

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = test_transport();
        let tok = session.wait_and_exchange(&transport, &clock).await.unwrap();
        assert_eq!(tok.access_token, "pkce-access");
        assert_eq!(tok.refresh_token.as_deref(), Some("pkce-refresh"));

        let reqs = token_srv.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].form_get("grant_type").as_deref(),
            Some("authorization_code")
        );
        assert_eq!(reqs[0].form_get("code").as_deref(), Some("auth-code-99"));
        assert_eq!(
            reqs[0].form_get("redirect_uri").as_deref(),
            Some(redirect_uri.as_str())
        );
        assert!(
            reqs[0]
                .form_get("code_verifier")
                .is_some_and(|v| !v.is_empty())
        );
    }

    #[tokio::test]
    async fn tier1_transport_static_bearer_auth_and_missing_refresh_token() {
        let auth = StaticBearerAuth::new("user@example.com", "tok123");
        assert_eq!(auth.principal(), "user@example.com");
        assert_eq!(auth.access_token().await.unwrap(), "tok123");
        let err = auth.force_refresh("tok123").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err.is_permanent());

        let srv = MockHttpServer::start().await;
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "expired".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at_unix_secs: 1_699_999_000,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store,
            clock,
        )
        .unwrap();
        let err2 = mgr.access_token().await.unwrap_err();
        assert_eq!(err2.kind(), ErrorKind::PermissionDenied);
        assert!(err2.is_permanent());
        assert_eq!(srv.hit_count(), 0);
    }

    #[tokio::test]
    async fn tier2_transport_oauth2_429_retry_after_recovery() {
        let srv = MockHttpServer::start().await;
        srv.enqueue_response(MockResponse::text(429, "slow down").with_header("Retry-After", "0"));
        srv.enqueue_response(MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "recovered-429",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        ));

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "stale".to_string(),
            refresh_token: Some("ref-429".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_unix_secs: 1_699_999_000,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store,
            clock,
        )
        .unwrap();

        let tok = mgr
            .access_token()
            .await
            .expect("OAuth2TokenManager must retry 429 and recover");
        assert_eq!(tok, "recovered-429");
        assert_eq!(srv.hit_count(), 2);
    }

    #[tokio::test]
    async fn tier2_transport_oauth2_503_transient_recovery() {
        let srv = MockHttpServer::start().await;
        srv.enqueue_response(MockResponse::text(503, "unavailable 1"));
        srv.enqueue_response(MockResponse::text(503, "unavailable 2"));
        srv.enqueue_response(MockResponse::json(
            200,
            &serde_json::json!({
                "access_token": "recovered-503",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        ));

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "stale".to_string(),
            refresh_token: Some("ref-503".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_unix_secs: 1_700_003_600,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store.clone(),
            clock,
        )
        .unwrap();

        let tok = mgr
            .force_refresh("stale")
            .await
            .expect("OAuth2TokenManager must retry 503 and recover");
        assert_eq!(tok, "recovered-503");
        assert_eq!(srv.hit_count(), 3);
        assert_eq!(store.load().unwrap().unwrap().access_token, "recovered-503");
    }

    #[tokio::test]
    async fn tier2_transport_oauth2_400_invalid_grant_permanent_no_retry() {
        let srv = MockHttpServer::start().await;
        srv.enqueue_response(MockResponse::json(
            400,
            &serde_json::json!({"error": "invalid_grant"}),
        ));

        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "stale".to_string(),
            refresh_token: Some("bad-ref".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_unix_secs: 1_700_003_600,
            scope: None,
        })));
        let mgr = OAuth2TokenManager::new(
            refresh_cfg(srv.url("/token")),
            test_transport(),
            store,
            clock,
        )
        .unwrap();

        let err = mgr.force_refresh("stale").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err.is_permanent());
        assert_eq!(srv.hit_count(), 1, "400 invalid_grant must not retry");
    }

    #[tokio::test]
    async fn tier2_transport_pkce_omits_empty_scope_in_auth_url() {
        for empty_scope in ["", "   \t "] {
            let sess = PkceSession::start(PkceConfig {
                client_id: "cid".to_string(),
                client_secret: None,
                auth_endpoint: "https://www.dropbox.com/oauth2/authorize".to_string(),
                token_endpoint: "https://api.dropboxapi.com/oauth2/token".to_string(),
                scope: empty_scope.to_string(),
                extra_auth_params: Vec::new(),
                include_scope_in_token_exchange: false,
                callback_path: "/callback".to_string(),
                success_title: "OK".to_string(),
                preferred_port: None,
                strict_port: false,
            })
            .await
            .unwrap();
            assert!(
                !sess.auth_url.contains("scope="),
                "empty/whitespace scope `{empty_scope:?}` must omit `scope=` param, got: {}",
                sess.auth_url
            );
        }
    }

    #[tokio::test]
    async fn tier2_transport_pkce_preserves_non_empty_scope_and_rejects_bad_state() {
        let sess = PkceSession::start(PkceConfig {
            client_id: "cid".to_string(),
            client_secret: None,
            auth_endpoint: "https://auth.example.test/authorize".to_string(),
            token_endpoint: "https://auth.example.test/token".to_string(),
            scope: "files.metadata.read".to_string(),
            extra_auth_params: Vec::new(),
            include_scope_in_token_exchange: false,
            callback_path: "/callback".to_string(),
            success_title: "OK".to_string(),
            preferred_port: None,
            strict_port: false,
        })
        .await
        .unwrap();
        assert!(sess.auth_url.contains("scope=files.metadata.read"));

        let err = sess
            .parse_callback_url("http://127.0.0.1:53682/callback?code=c1&state=wrong-state")
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err.is_permanent());
    }

    // ------------------------------------------------------------------------
    // Area #3: `common` HTTP & `google_sa` (Tier 1 >= 5, Tier 2 >= 5)
    // ------------------------------------------------------------------------

    #[cfg(feature = "webdav")]
    mod common_webdav {
        use super::*;
        use rship::config::WebdavRemoteConfig;
        use rship::core::backend::{BackendPath, UploadInit};
        use rship::core::buffer::BufferPool;
        use rship::core::path::RelPath;
        use rship::core::source::{ByteStream, DataSource, MemorySource, bounded_range_stream};
        use rship::core::state::DstPrecondition;
        use rship::core::types::ByteRange;
        use rship::prelude::*;
        use std::sync::Mutex;

        fn mem_stream(data: Vec<u8>) -> ByteStream {
            let len = data.len() as u64;
            if len == 0 {
                return Box::pin(futures::stream::empty());
            }
            let pool = BufferPool::new(1024 * 1024, 64 * 1024).unwrap();
            bounded_range_stream(Arc::new(MemorySource::new(data)), 0, len, pool)
        }

        #[tokio::test]
        async fn tier1_common_http_upload_normal_put_and_download_roundtrip() {
            let stored: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
            let stored_c = stored.clone();

            let srv = MockHttpServer::start_with_handler(move |req| {
                if req.method == "PUT" && req.path == "/dav/ok.bin" {
                    *stored_c.lock().unwrap() = req.body.clone();
                    return MockAction::Respond(
                        MockResponse::empty(201).with_header("ETag", "\"e1\""),
                    );
                }
                if req.method == "PROPFIND" && req.path == "/dav/ok.bin" {
                    let len = stored_c.lock().unwrap().len();
                    let xml = format!(
                        r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/ok.bin</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>{len}</d:getcontentlength>
        <d:getetag>"e1"</d:getetag>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#
                    );
                    return MockAction::Respond(
                        MockResponse::new(207, xml.into_bytes())
                            .with_header("Content-Type", "application/xml"),
                    );
                }
                if req.method == "GET" && req.path == "/dav/ok.bin" {
                    let bytes = stored_c.lock().unwrap().clone();
                    let end = bytes.len().saturating_sub(1);
                    return MockAction::Respond(
                        MockResponse::new(206, bytes.clone())
                            .with_header("Content-Range", format!("bytes 0-{end}/{}", bytes.len())),
                    );
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            let client = RshipClient::builder()
                .ephemeral()
                .remote(
                    "dav",
                    WebdavRemoteConfig::new(srv.url("/dav")).with_vendor("generic"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("dav:").unwrap();
            let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
            let entry = backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-wd-1".to_string(),
                        dst_path: RelPath::parse("ok.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: payload.len() as u64,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    mem_stream(payload.clone()),
                )
                .await
                .unwrap();
            assert_eq!(entry.size, payload.len() as u64);

            let ds = backend
                .open_read(
                    &BackendPath::from_rel(RelPath::parse("ok.bin").unwrap()),
                    None,
                )
                .await
                .unwrap();
            let mut got = Vec::new();
            match ds {
                DataSource::RemoteRangeReadable(r) => {
                    let mut st = r
                        .open_range(ByteRange {
                            offset: 0,
                            len: payload.len() as u64,
                        })
                        .await
                        .unwrap();
                    use futures::StreamExt;
                    while let Some(chunk) = st.next().await {
                        got.extend_from_slice(&chunk.unwrap());
                    }
                }
                _ => panic!("expected RemoteRangeReadable"),
            }
            assert_eq!(got, payload);
        }

        #[tokio::test]
        async fn tier1_common_http_body_stream_stall_trips_data_stall_timeout() {
            let srv = MockHttpServer::start().await;
            let tcfg = TransportConfig::new()
                .with_data_stall_timeout(Duration::from_millis(150))
                .with_data_finalize_timeout(Duration::from_secs(5));
            let client = RshipClient::builder()
                .ephemeral()
                .transport_config(tcfg)
                .remote(
                    "dav",
                    WebdavRemoteConfig::new(srv.url("/dav")).with_vendor("generic"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("dav:").unwrap();
            let first = futures::stream::once(async { Ok(vec![0x55u8; 512].into()) });
            let stalled: ByteStream = Box::pin(futures::stream::StreamExt::chain(
                first,
                futures::stream::pending(),
            ));

            let t0 = std::time::Instant::now();
            let err = backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-stall".to_string(),
                        dst_path: RelPath::parse("stall.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 4096,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    stalled,
                )
                .await
                .expect_err("stalled body stream must trip data_stall_timeout");
            assert!(t0.elapsed() < Duration::from_secs(2));
            assert_eq!(err.kind(), ErrorKind::Timeout);
            assert!(err.is_retryable());
        }

        #[tokio::test]
        async fn tier1_common_http_short_eof_upload_surfaces_source_mutated() {
            let srv = MockHttpServer::start_with_handler(|_| {
                MockAction::Respond(MockResponse::empty(201))
            })
            .await;
            let client = RshipClient::builder()
                .ephemeral()
                .remote(
                    "dav",
                    WebdavRemoteConfig::new(srv.url("/dav")).with_vendor("generic"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("dav:").unwrap();
            let err = backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-short".to_string(),
                        dst_path: RelPath::parse("short.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 64,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    mem_stream(vec![1, 2, 3, 4, 5]),
                )
                .await
                .expect_err("short EOF upload must fail");
            assert_eq!(err.kind(), ErrorKind::SourceMutated);
        }

        #[tokio::test]
        async fn tier1_common_http_headers_then_body_stall_times_out_read_data_body() {
            let srv = MockHttpServer::start_with_handler(|req| {
                if req.method == "PROPFIND" && req.path == "/dav/stall.bin" {
                    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/stall.bin</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>64</d:getcontentlength>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
                    return MockAction::Respond(
                        MockResponse::new(207, xml.as_bytes().to_vec())
                            .with_header("Content-Type", "application/xml"),
                    );
                }
                if req.method == "GET" && req.path == "/dav/stall.bin" {
                    return MockAction::HeadersThenStall {
                        status: 206,
                        headers: vec![("Content-Range".into(), "bytes 0-63/64".into())],
                        declared_len: 64,
                        prefix: b"abc".to_vec(),
                    };
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            let tcfg = TransportConfig::new().with_data_stall_timeout(Duration::from_millis(150));
            let client = RshipClient::builder()
                .ephemeral()
                .transport_config(tcfg)
                .remote(
                    "dav",
                    WebdavRemoteConfig::new(srv.url("/dav")).with_vendor("generic"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("dav:").unwrap();
            let ds = backend
                .open_read(
                    &BackendPath::from_rel(RelPath::parse("stall.bin").unwrap()),
                    None,
                )
                .await
                .unwrap();
            let DataSource::RemoteRangeReadable(r) = ds else {
                panic!("expected RemoteRangeReadable");
            };
            let mut st = r
                .open_range(ByteRange { offset: 0, len: 64 })
                .await
                .unwrap();
            let t0 = std::time::Instant::now();
            use futures::StreamExt;
            let mut got_err = None;
            while let Some(item) = st.next().await {
                if let Err(e) = item {
                    got_err = Some(e);
                    break;
                }
            }
            let err = got_err.expect("stalled download body must fail with Timeout");
            assert!(t0.elapsed() < Duration::from_secs(2));
            assert_eq!(err.kind(), ErrorKind::Timeout);
        }

        // Opaque-box regression guard verifying `webdav` uses
        // `common::http::send_watched_sized_upload_with_capture` (`SizedEofStream` outside `WatchedByteStream`)
        // so slow response finalize works for both non-empty and 0-byte uploads.
        #[tokio::test]
        async fn tier2_common_http_upload_slow_finalize_succeeds_for_non_empty_and_zero_byte() {
            let srv = MockHttpServer::start_with_handler(|req| {
                if req.method == "PUT" {
                    return MockAction::Respond(
                        MockResponse::empty(201).with_delay(Duration::from_millis(350)),
                    );
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            let tcfg = TransportConfig::new()
                .with_data_stall_timeout(Duration::from_millis(120))
                .with_data_finalize_timeout(Duration::from_secs(2));
            let client = RshipClient::builder()
                .ephemeral()
                .transport_config(tcfg)
                .remote(
                    "dav",
                    WebdavRemoteConfig::new(srv.url("/dav")).with_vendor("generic"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("dav:").unwrap();
            // 4 KiB slow finalize
            backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-fin-4k".to_string(),
                        dst_path: RelPath::parse("slow4k.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 4096,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    mem_stream(vec![0x55u8; 4096]),
                )
                .await
                .expect("4 KiB upload with finalize delay < data_finalize_timeout must succeed");

            // 0-byte slow finalize
            backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-fin-0b".to_string(),
                        dst_path: RelPath::parse("slow0b.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 0,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    mem_stream(Vec::new()),
                )
                .await
                .expect("0-byte upload with finalize delay < data_finalize_timeout must succeed");
        }
    }

    #[cfg(feature = "gdrive")]
    mod common_gdrive_upload {
        use super::*;
        use rship::config::GdriveRemoteConfig;
        use rship::core::backend::UploadInit;
        use rship::core::path::RelPath;
        use rship::core::state::DstPrecondition;
        use rship::prelude::*;

        // Opaque-box regression guard verifying `gdrive` multipart upload uses
        // `common::http::send_watched_sized_upload_with_capture` (`SizedEofStream` outside `WatchedByteStream`)
        // so 0-byte uploads handle slow response finalize without false stall timeouts.
        #[tokio::test]
        async fn tier2_common_http_upload_zero_byte_slow_finalize_gdrive_multipart() {
            let srv = MockHttpServer::start_with_handler(|req| {
                if req.method == "GET" && req.path == "/files" {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({ "files": [] }),
                    ));
                }
                if req.method == "GET" && req.path == "/files/generateIds" {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({ "ids": ["gd-id-0b"] }),
                    ));
                }
                if req.method == "POST" && req.path == "/files" {
                    return MockAction::Respond(
                        MockResponse::json(
                            200,
                            &serde_json::json!({
                                "id": "gd-id-0b",
                                "name": "zero.bin",
                                "mimeType": "application/octet-stream",
                                "size": "0",
                                "md5Checksum": "d41d8cd98f00b204e9800998ecf8427e",
                                "parents": ["root"]
                            }),
                        )
                        .with_delay(Duration::from_millis(350)),
                    );
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            let tcfg = TransportConfig::new()
                .with_data_stall_timeout(Duration::from_millis(120))
                .with_data_finalize_timeout(Duration::from_secs(2));
            let client = RshipClient::builder()
                .ephemeral()
                .transport_config(tcfg)
                .remote(
                    "gd",
                    GdriveRemoteConfig::new()
                        .with_api_base_url(srv.base_url())
                        .with_upload_base_url(srv.base_url())
                        .with_access_token("gd-tok"),
                )
                .build()
                .unwrap();

            let (backend, _) = client.resolve("gd:").unwrap();
            let entry = backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "gd-0b".to_string(),
                        dst_path: RelPath::parse("zero.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 0,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 1024 * 1024,
                        checksums: Vec::new(),
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    Box::pin(futures::stream::empty()),
                )
                .await
                .expect("0-byte GDrive multipart upload with finalize delay < data_finalize_timeout must succeed");
            assert_eq!(entry.size, 0);
        }
    }

    #[cfg(any(feature = "gdrive", feature = "gcs"))]
    mod common_google_sa {
        use super::*;
        use crate::rclone_import_and_auth::TEST_SA_PRIVATE_KEY_PEM;

        #[cfg(feature = "gcs")]
        use rship::backends::gcs::{ServiceAccountAuthProvider, ServiceAccountKey};
        #[cfg(all(not(feature = "gcs"), feature = "gdrive"))]
        use rship::backends::gdrive::{ServiceAccountAuthProvider, ServiceAccountKey};

        fn test_sa_key(token_uri: String) -> ServiceAccountKey {
            let json = serde_json::json!({
                "client_email": "sa@test-proj.iam.gserviceaccount.com",
                "private_key": TEST_SA_PRIVATE_KEY_PEM,
                "private_key_id": "kid-1",
                "token_uri": token_uri,
                "project_id": "test-proj"
            });
            ServiceAccountKey::from_json_str(&json.to_string()).unwrap()
        }

        #[tokio::test]
        async fn tier1_common_google_sa_rs256_jwt_exchange_and_dwd_sub() {
            let srv = MockHttpServer::start().await;
            srv.enqueue_response(MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "ya29.sa-ok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ));

            let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
            let sa = ServiceAccountAuthProvider::new(
                test_sa_key(srv.url("/token")),
                "https://www.googleapis.com/auth/drive",
                Some("dwd@corp.test".to_string()),
                None,
                test_transport(),
                clock,
            )
            .unwrap();

            let jwt = sa.sign_jwt_assertion(1_700_000_000).unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            assert_eq!(parts.len(), 3);
            assert_eq!(
                sa.principal(),
                "sa@test-proj.iam.gserviceaccount.com->dwd@corp.test"
            );

            let t1 = sa.access_token().await.unwrap();
            let t2 = sa.access_token().await.unwrap();
            assert_eq!(t1, "ya29.sa-ok");
            assert_eq!(t2, "ya29.sa-ok");
            assert_eq!(srv.hit_count(), 1);

            let reqs = srv.requests();
            assert_eq!(
                reqs[0].form_get("grant_type").as_deref(),
                Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
            );
            assert!(reqs[0].form_get("assertion").is_some_and(|a| !a.is_empty()));
        }

        #[tokio::test]
        async fn tier2_common_google_sa_token_429_and_503_retry_recovery() {
            let srv = MockHttpServer::start().await;
            srv.enqueue_response(MockResponse::text(429, "limit").with_header("Retry-After", "0"));
            srv.enqueue_response(MockResponse::text(503, "unavailable"));
            srv.enqueue_response(MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "ya29.sa-recovered",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ));

            let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
            let sa = ServiceAccountAuthProvider::new(
                test_sa_key(srv.url("/token")),
                "https://www.googleapis.com/auth/devstorage.read_write",
                None,
                None,
                test_transport(),
                clock,
            )
            .unwrap();

            let tok = sa
                .access_token()
                .await
                .expect("ServiceAccountAuthProvider must retry 429/503 on /token");
            assert_eq!(tok, "ya29.sa-recovered");
            assert_eq!(srv.hit_count(), 3);
        }
    }

    #[cfg(feature = "gcs")]
    mod common_gcs_policy_loop {
        use super::*;
        use rship::config::{AppConfig, AppPaths, GcsRemoteConfig};
        use rship::factory::import_rclone_conf;
        use rship::prelude::*;

        #[tokio::test]
        async fn tier2_common_http_execute_policy_retries_transient_build_auth_failure() {
            let srv = MockHttpServer::start_with_handler(|req| {
                if req.method == "GET" && req.path == "/b/my-b/o/obj.txt" {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "name": "obj.txt",
                            "size": "12",
                            "updated": "2026-01-01T00:00:00Z",
                            "generation": "1"
                        }),
                    ));
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            // Queue 2x 503 on /token followed by 200 OK. Baseline fails immediately on the first 503;
            // M1 retries transient /token errors during Build and recovers cleanly.
            for _ in 0..2 {
                srv.enqueue_response(MockResponse::text(503, "oauth temporarily unavailable"));
            }
            srv.enqueue_response(MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "ya29.fresh-after-build-retry",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ));

            let tmp = TempDir::new().unwrap();
            let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
            let raw = r#"
[gcs_p]
type = google cloud storage
client_id = cid-1
client_secret = csec-1
token = {"access_token":"ya29.expired","token_type":"Bearer","refresh_token":"1//ref","expiry":"2000-01-01T00:00:00Z"}
"#;
            let mut app_cfg = AppConfig::new();
            import_rclone_conf(&mut app_cfg, raw, &paths, true, false).unwrap();
            if let Some(rship::RemoteConfig::Gcs(g)) = app_cfg.remotes.get_mut("gcs_p") {
                g.bucket = Some("my-b".to_string());
                g.api_base_url = Some(srv.base_url());
                g.token_url = Some(srv.url("/token"));
            }

            let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
            let client = RshipClient::builder()
                .paths(paths)
                .config(app_cfg)
                .clock(clock)
                .build()
                .unwrap();

            let entry = client
                .stat("gcs_p:obj.txt")
                .await
                .expect("execute_policy_loop must retry transient auth failures during Build")
                .expect("object must exist");
            assert_eq!(entry.size, 12);
        }

        #[tokio::test]
        async fn tier2_common_http_execute_policy_retries_transient_401_auth_refresh_failure() {
            let srv = MockHttpServer::start_with_handler(|req| {
                if req.method == "POST" && req.path == "/token" {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "access_token": "ya29.fresh-after-401",
                            "token_type": "Bearer",
                            "expires_in": 3600
                        }),
                    ));
                }
                if req.method == "GET" && req.path == "/b/my-b/o/obj.txt" {
                    if req.header("authorization") == Some("Bearer ya29.fresh-after-401") {
                        return MockAction::Respond(MockResponse::json(
                            200,
                            &serde_json::json!({
                                "name": "obj.txt",
                                "size": "21",
                                "updated": "2026-01-01T00:00:00Z",
                                "generation": "2"
                            }),
                        ));
                    }
                    return MockAction::Respond(MockResponse::text(401, "unauthorized"));
                }
                MockAction::Respond(MockResponse::empty(404))
            })
            .await;

            // 1st API call -> 401; then 2x 503 on /token, then /token returns 200 and API returns 200.
            // Baseline fails immediately on the first 503 inside on_auth_refresh; M1 recovers cleanly.
            srv.enqueue_response(MockResponse::text(401, "expired"));
            for _ in 0..2 {
                srv.enqueue_response(MockResponse::text(503, "token server 503"));
            }

            let tmp = TempDir::new().unwrap();
            let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
            let raw = r#"
[gcs_401]
type = google cloud storage
client_id = cid-1
client_secret = csec-1
token = {"access_token":"ya29.stale","token_type":"Bearer","refresh_token":"1//ref","expiry":"2099-01-01T00:00:00Z"}
"#;
            let mut app_cfg = AppConfig::new();
            import_rclone_conf(&mut app_cfg, raw, &paths, true, false).unwrap();
            if let Some(rship::RemoteConfig::Gcs(g)) = app_cfg.remotes.get_mut("gcs_401") {
                g.bucket = Some("my-b".to_string());
                g.api_base_url = Some(srv.base_url());
                g.token_url = Some(srv.url("/token"));
            }

            let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
            let client = RshipClient::builder()
                .paths(paths)
                .config(app_cfg)
                .clock(clock)
                .build()
                .unwrap();

            let entry = client
                .stat("gcs_401:obj.txt")
                .await
                .expect("execute_policy_loop must retry transient 401 refresh errors")
                .expect("object must exist");
            assert_eq!(entry.size, 21);

            // Permanent 400 invalid_grant on /token must fail immediately with PermissionDenied.
            let srv_perm = MockHttpServer::start().await;
            srv_perm.enqueue_response(MockResponse::text(401, "expired"));
            srv_perm.enqueue_response(MockResponse::json(
                400,
                &serde_json::json!({ "error": "invalid_grant" }),
            ));
            let tmp2 = TempDir::new().unwrap();
            let paths2 = AppPaths::new(tmp2.path().join("config.toml"), tmp2.path().join("state"));
            let mut app_cfg2 = AppConfig::new();
            import_rclone_conf(&mut app_cfg2, raw, &paths2, true, false).unwrap();
            let _ = GcsRemoteConfig::new();
            if let Some(rship::RemoteConfig::Gcs(g)) = app_cfg2.remotes.get_mut("gcs_401") {
                g.bucket = Some("my-b".to_string());
                g.api_base_url = Some(srv_perm.base_url());
                g.token_url = Some(srv_perm.url("/token"));
            }
            let client2 = RshipClient::builder()
                .paths(paths2)
                .config(app_cfg2)
                .build()
                .unwrap();
            let err = client2.stat("gcs_401:obj.txt").await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);
            assert_eq!(srv_perm.hit_count(), 2);
        }
    }
}

// ============================================================================
// Area #14: `factory` & `rclone_import` SDK parts (Tier 1 >= 5, Tier 2 >= 5)
// ============================================================================

mod factory_and_rclone_import {
    use rship::config::{AppConfig, AppPaths, RemoteConfig};
    use rship::core::ErrorKind;
    use rship::core::path::TargetPath;
    use rship::factory::{import_rclone_conf, target_needs_inventory, target_needs_transport};
    use rship::prelude::*;
    use tempfile::TempDir;

    #[test]
    fn tier1_factory_import_rclone_conf_empty_and_unknown_type_safe() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let mut cfg = AppConfig::new();
        let summary = import_rclone_conf(
            &mut cfg,
            "# comment\n[mystery]\ntype = totally_unknown_backend\nfoo = bar\n",
            &paths,
            false,
            false,
        )
        .unwrap();
        assert!(summary.imported.is_empty());
        assert!(cfg.remotes.is_empty());

        let local_dir = tmp.path().join("loc");
        std::fs::create_dir_all(&local_dir).unwrap();
        let cfg2 = AppConfig::new().with_remote("loc", RemoteConfig::local(&local_dir));
        let client = RshipClient::builder()
            .ephemeral()
            .config(cfg2)
            .build()
            .unwrap();
        assert!(client.resolve("loc:").is_ok());
        let missing = client
            .resolve("does_not_exist:")
            .err()
            .expect("missing remote must fail");
        assert_eq!(missing.kind(), ErrorKind::Config);
    }

    #[test]
    fn tier1_factory_target_needs_transport_and_inventory_local_and_remotes() {
        let mut cfg = AppConfig::new().with_remote("loc", RemoteConfig::local("/tmp/loc"));
        cfg = cfg.with_remote(
            "s3r",
            S3RemoteConfig::new("aws")
                .with_bucket("b")
                .with_credentials("ak", "sk"),
        );
        cfg = cfg.with_remote("gdr", GdriveRemoteConfig::new().with_access_token("tok"));
        cfg = cfg.with_remote("sfr", SftpRemoteConfig::new("127.0.0.1", "alice"));

        assert!(!target_needs_transport(
            &TargetPath::parse("/tmp/a").unwrap(),
            &cfg
        ));
        assert!(!target_needs_transport(
            &TargetPath::parse("loc:sub").unwrap(),
            &cfg
        ));
        assert!(!target_needs_transport(
            &TargetPath::parse("sfr:sub").unwrap(),
            &cfg
        ));
        assert!(target_needs_transport(
            &TargetPath::parse("s3r:sub").unwrap(),
            &cfg
        ));
        assert!(target_needs_transport(
            &TargetPath::parse("gdr:sub").unwrap(),
            &cfg
        ));

        assert!(!target_needs_inventory(
            &TargetPath::parse("loc:").unwrap(),
            &cfg,
            true
        ));
        assert!(target_needs_inventory(
            &TargetPath::parse("gdr:").unwrap(),
            &cfg,
            true
        ));
        assert!(!target_needs_inventory(
            &TargetPath::parse("gdr:").unwrap(),
            &cfg,
            false
        ));
    }

    #[cfg(feature = "s3")]
    #[test]
    fn tier1_factory_import_rclone_conf_dry_run_overwrite_and_invalid_names() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[a]
type = s3
access_key_id = ak1
secret_access_key = sk1

[bad name]
type = s3
access_key_id = ak2
secret_access_key = sk2

[good_s3]
type = s3
provider = AWS
region = us-east-1
access_key_id = ak_old
secret_access_key = sk_old
"#;

        let mut cfg = AppConfig::new();
        let dry = import_rclone_conf(&mut cfg, raw, &paths, false, true).unwrap();
        assert!(cfg.remotes.is_empty(), "dry_run must not mutate AppConfig");
        assert_eq!(dry.imported.len(), 1);
        assert!(dry.warnings.len() >= 2);

        let first = import_rclone_conf(&mut cfg, raw, &paths, false, false).unwrap();
        assert_eq!(first.imported.len(), 1);
        assert!(cfg.remotes.contains_key("good_s3"));

        let raw_updated = r#"
[good_s3]
type = s3
provider = AWS
region = eu-west-1
access_key_id = ak_new
secret_access_key = sk_new
"#;
        let skipped = import_rclone_conf(&mut cfg, raw_updated, &paths, false, false).unwrap();
        assert_eq!(skipped.skipped_existing, vec!["good_s3".to_string()]);
        match cfg.remotes.get("good_s3") {
            Some(RemoteConfig::S3(s)) => assert_eq!(s.region.as_deref(), Some("us-east-1")),
            other => panic!("unexpected: {other:?}"),
        }

        let replaced = import_rclone_conf(&mut cfg, raw_updated, &paths, true, false).unwrap();
        assert_eq!(replaced.imported.len(), 1);
        match cfg.remotes.get("good_s3") {
            Some(RemoteConfig::S3(s)) => assert_eq!(s.region.as_deref(), Some("eu-west-1")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[cfg(all(feature = "webdav", feature = "sftp"))]
    #[test]
    fn tier1_factory_import_webdav_and_sftp_reveals_rclone_obscured_secrets() {
        use rship::core::rclone_ini::obscure_rclone_secret_with_iv;

        let obs_dav = obscure_rclone_secret_with_iv("dav-secret-1", [0x11; 16]);
        let obs_ssh = obscure_rclone_secret_with_iv("ssh-secret-2", [0x22; 16]);
        let obs_key = obscure_rclone_secret_with_iv("key-pass-3", [0x33; 16]);

        let raw = format!(
            r#"
[dav_obs]
type = webdav
url = https://dav.example.test/remote.php/dav/files/alice
vendor = nextcloud
user = alice
pass = {obs_dav}

[sf_obs]
type = sftp
host = 10.0.0.5
port = 2222
user = deploy
pass = {obs_ssh}
key_file = /tmp/id_ed25519
key_file_pass = {obs_key}
"#
        );

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let mut cfg = AppConfig::new();
        let rep = import_rclone_conf(&mut cfg, &raw, &paths, true, false).unwrap();
        assert_eq!(rep.imported.len(), 2);

        match cfg.remotes.get("dav_obs") {
            Some(RemoteConfig::Webdav(w)) => {
                assert_eq!(w.password.as_deref(), Some("dav-secret-1"));
            }
            other => panic!("expected Webdav, got {other:?}"),
        }
        match cfg.remotes.get("sf_obs") {
            Some(RemoteConfig::Sftp(s)) => {
                assert_eq!(s.password.as_deref(), Some("ssh-secret-2"));
                assert_eq!(s.key_passphrase.as_deref(), Some("key-pass-3"));
            }
            other => panic!("expected Sftp, got {other:?}"),
        }
    }

    #[cfg(feature = "gdrive")]
    #[test]
    fn tier1_factory_client_builder_rclone_conf_str_ephemeral_no_disk_writes() {
        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("must_not_exist");
        let sa_json = serde_json::json!({
            "client_email": "sa@proj.iam.gserviceaccount.com",
            "private_key": super::TEST_SA_PRIVATE_KEY_PEM,
            "token_uri": "https://oauth2.googleapis.com/token"
        })
        .to_string();
        let raw = format!(
            r#"
[gd_tok]
type = drive
client_id = cid
client_secret = csec
token = {{"access_token":"ya29.m","token_type":"Bearer","refresh_token":"1//m","expiry":"2099-01-01T00:00:00Z"}}

[gd_sa]
type = drive
service_account_credentials = {sa_json}
"#
        );

        let client = RshipClient::builder()
            .ephemeral()
            .state_dir(&state_dir)
            .rclone_conf_str(raw)
            .build()
            .unwrap();
        assert!(!state_dir.exists());
        assert!(client.resolve("gd_tok:").is_ok());
        assert!(client.resolve("gd_sa:").is_ok());
    }

    #[cfg(feature = "crypt")]
    #[test]
    fn tier1_factory_crypt_nesting_cycle_rejected_and_needs_transport() {
        let mut cfg = AppConfig::new()
            .with_remote("loc", RemoteConfig::local("/tmp/loc"))
            .with_remote(
                "s3r",
                S3RemoteConfig::new("aws")
                    .with_bucket("b")
                    .with_credentials("ak", "sk"),
            )
            .with_remote("c_loc", CryptRemoteConfig::new("loc:").with_password("pw"))
            .with_remote("c_s3", CryptRemoteConfig::new("s3r:").with_password("pw"))
            .with_remote(
                "cyc_a",
                CryptRemoteConfig::new("cyc_b:").with_password("pw"),
            )
            .with_remote(
                "cyc_b",
                CryptRemoteConfig::new("cyc_a:").with_password("pw"),
            );

        assert!(!target_needs_transport(
            &TargetPath::parse("c_loc:").unwrap(),
            &cfg
        ));
        assert!(target_needs_transport(
            &TargetPath::parse("c_s3:").unwrap(),
            &cfg
        ));

        let client = RshipClient::builder()
            .ephemeral()
            .config(std::mem::take(&mut cfg))
            .build()
            .unwrap();
        let err = client
            .resolve("cyc_a:file")
            .err()
            .expect("cyclic crypt must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidPath);
    }

    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn tier1_factory_resolve_s3_sse_validation_and_bucketless_split() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};

        let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/" {
                return MockAction::Respond(
                    MockResponse::new(
                        200,
                        br#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"#.to_vec(),
                    )
                    .with_header("Content-Type", "application/xml"),
                );
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

        let bad_sse = RshipClient::builder()
            .ephemeral()
            .remote(
                "bad_s3",
                S3RemoteConfig::new("aws")
                    .with_bucket("b")
                    .with_credentials("ak", "sk")
                    .with_sse("AES256")
                    .with_kms_key_id("arn:aws:kms:us-east-1:1:key/x"),
            )
            .build()
            .unwrap();
        let err = bad_sse
            .resolve("bad_s3:f")
            .err()
            .expect("AES256 + kms_key_id must fail");
        assert_eq!(err.kind(), ErrorKind::Config);

        let good_client = RshipClient::builder()
            .ephemeral()
            .remote(
                "bucketless_s3",
                S3RemoteConfig::new("minio")
                    .with_endpoint(srv.base_url())
                    .with_region("us-east-1")
                    .with_force_path_style(true)
                    .with_credentials("minioadmin", "minioadmin"),
            )
            .build()
            .unwrap();

        let (backend, rel) = good_client
            .resolve("bucketless_s3:mybucket/dir/file")
            .unwrap();
        assert_eq!(rel.as_str(), "dir/file");
        assert!(backend.endpoint_identity().contains("mybucket"));

        let ep = good_client
            .probe_bucketless_remote("bucketless_s3")
            .await
            .unwrap();
        assert!(ep.is_some());
        assert_eq!(srv.hit_count(), 1);
    }

    #[test]
    fn tier2_factory_import_rejects_encrypted_rclone_conf_fail_fast() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));

        for raw in [
            "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "\u{FEFF}RCLONE_ENCRYPT_V0:\nYWJj\n",
            "# comment\n  RCLONE_ENCRYPT_V0:\nYWJj\n",
        ] {
            let mut cfg = AppConfig::new();
            let err = import_rclone_conf(&mut cfg, raw, &paths, true, false)
                .expect_err("import_rclone_conf must fail fast on RCLONE_ENCRYPT_V0:");
            assert!(
                err.is_config(),
                "expected Config error, got {:?}: {err}",
                err.kind()
            );

            let err_builder = RshipClient::builder()
                .ephemeral()
                .rclone_conf_str(raw)
                .build()
                .expect_err("ClientBuilder::rclone_conf_str must reject RCLONE_ENCRYPT_V0:");
            assert!(err_builder.is_config());
        }
    }

    #[cfg(all(
        feature = "gdrive",
        feature = "gcs",
        feature = "onedrive",
        feature = "dropbox"
    ))]
    #[test]
    fn tier2_factory_import_warns_missing_client_id_consistently() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[gd_nocid]
type = drive
token = {"access_token":"t","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"}

[gcs_nocid]
type = google cloud storage
token = {"access_token":"t","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"}

[od_nocid]
type = onedrive
token = {"access_token":"t","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"}

[dbx_nocid]
type = dropbox
token = {"access_token":"t","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"}
"#;

        let mut cfg = AppConfig::new();
        let rep = import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();
        for remote_name in ["gd_nocid", "gcs_nocid", "od_nocid", "dbx_nocid"] {
            assert!(
                rep.warnings
                    .iter()
                    .any(|w| w.contains(remote_name) && w.contains("client_id")),
                "missing client_id warning for `{remote_name}` in warnings: {:?}",
                rep.warnings
            );
        }
    }

    #[cfg(all(feature = "gdrive", feature = "gcs", feature = "sftp"))]
    #[test]
    fn tier2_factory_import_expands_tilde_paths() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[gd_tilde]
type = drive
service_account_file = ~/creds/gd_sa.json

[gcs_tilde]
type = google cloud storage
service_account_file = ~/creds/gcs_sa.json

[sf_tilde]
type = sftp
host = 10.0.0.1
user = alice
key_file = ~/.ssh/id_ed25519
known_hosts_file = ~/.ssh/known_hosts
"#;
        let mut cfg = AppConfig::new();
        let _ = import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        let check_expanded = |p: Option<&std::path::PathBuf>, suffix: &[&str]| {
            let p = p.expect("path must be imported");
            assert!(
                !p.starts_with("~"),
                "tilde must be expanded, got: {}",
                p.display()
            );
            let mut expected_tail = std::path::PathBuf::new();
            for s in suffix {
                expected_tail.push(s);
            }
            assert!(
                p.ends_with(&expected_tail),
                "expected `{}` to end with `{}`",
                p.display(),
                expected_tail.display()
            );
        };

        match cfg.remotes.get("gd_tilde") {
            Some(RemoteConfig::Gdrive(g)) => {
                check_expanded(g.service_account_file.as_ref(), &["creds", "gd_sa.json"]);
            }
            other => panic!("expected Gdrive, got {other:?}"),
        }
        match cfg.remotes.get("gcs_tilde") {
            Some(RemoteConfig::Gcs(g)) => {
                check_expanded(g.service_account_file.as_ref(), &["creds", "gcs_sa.json"]);
            }
            other => panic!("expected Gcs, got {other:?}"),
        }
        match cfg.remotes.get("sf_tilde") {
            Some(RemoteConfig::Sftp(s)) => {
                check_expanded(s.key_file.as_ref(), &[".ssh", "id_ed25519"]);
                check_expanded(s.known_hosts_path.as_ref(), &[".ssh", "known_hosts"]);
            }
            other => panic!("expected Sftp, got {other:?}"),
        }
    }

    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn tier2_factory_import_s3_sse_profile_and_disable_checksum() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};

        let srv = MockHttpServer::start_with_handler(|req| {
            match (req.method.as_str(), req.path.as_str()) {
                ("GET", "/my-b") => MockAction::Respond(
                    MockResponse::ok(
                        br#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"#.to_vec(),
                    )
                    .with_header("Content-Type", "application/xml"),
                ),
                ("HEAD", "/my-b/up.bin") | ("HEAD", "/my-b/up.bin/") => {
                    MockAction::Respond(MockResponse::empty(404))
                }
                ("PUT", "/my-b/up.bin") => MockAction::Respond(
                    MockResponse::empty(200)
                        .with_header("ETag", "\"etag-1\"")
                        .with_header("Last-Modified", "Wed, 25 Nov 2026 12:00:00 GMT"),
                ),
                _ => MockAction::Respond(MockResponse::empty(404)),
            }
        })
        .await;

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = format!(
            r#"
[s3_kms]
type = s3
provider = AWS
region = us-east-1
endpoint = {}
force_path_style = true
access_key_id = AKIA_TEST
secret_access_key = SK_TEST
server_side_encryption = aws:kms
sse_kms_key_id = arn:aws:kms:us-east-1:123:key/abc
profile = prod-prof
disable_checksum = true
"#,
            srv.base_url()
        );
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, &raw, &paths, true, false).unwrap();

        match cfg.remotes.get("s3_kms") {
            Some(RemoteConfig::S3(s)) => {
                assert_eq!(s.sse.as_deref(), Some("aws:kms"));
                assert_eq!(
                    s.kms_key_id.as_deref(),
                    Some("arn:aws:kms:us-east-1:123:key/abc")
                );
                assert_eq!(s.profile.as_deref(), Some("prod-prof"));
                assert_eq!(s.send_upload_checksum, Some(false));
            }
            other => panic!("expected S3, got {other:?}"),
        }

        // Verify wire PUT carries KMS headers and omits upload checksum headers.
        if let Some(RemoteConfig::S3(s)) = cfg.remotes.get_mut("s3_kms") {
            s.bucket = Some("my-b".to_string());
            s.profile = None; // Keep static credentials active for wire PUT test.
        }
        let client = RshipClient::builder()
            .ephemeral()
            .config(cfg)
            .build()
            .unwrap();
        let (backend, _) = client.resolve("s3_kms:").unwrap();
        let src_file = tmp.path().join("up.bin");
        std::fs::write(&src_file, b"hello s3").unwrap();
        let rep = client
            .copy_file(src_file.as_path(), "s3_kms:up.bin")
            .run()
            .await
            .unwrap();
        assert!(rep.is_success(), "{:?}", rep.errors);
        let _ = backend;

        let put = srv
            .requests()
            .into_iter()
            .find(|r| r.method == "PUT")
            .expect("expected PUT");
        assert_eq!(put.header("x-amz-server-side-encryption"), Some("aws:kms"));
        assert_eq!(
            put.header("x-amz-server-side-encryption-aws-kms-key-id"),
            Some("arn:aws:kms:us-east-1:123:key/abc")
        );
        assert!(put.header("x-amz-checksum-crc32c").is_none());
        assert!(put.header("x-amz-checksum-crc64nvme").is_none());
    }

    #[cfg(feature = "gdrive")]
    #[tokio::test]
    async fn tier2_factory_import_gdrive_use_trash_default_scopes_and_filters() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
        use rship::core::backend::ListOptions;

        let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "GET" && req.path == "/files" {
                let q = req.query_get("q").unwrap_or_default();
                if q.contains("name = 'hello.txt'") {
                    return MockAction::Respond(MockResponse::json(
                        200,
                        &serde_json::json!({
                            "files": [{
                                "id": "gd-file-1",
                                "name": "hello.txt",
                                "mimeType": "text/plain",
                                "size": "5",
                                "parents": ["root"]
                            }]
                        }),
                    ));
                }
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "files": [] }),
                ));
            }
            if req.method == "PATCH" && req.path == "/files/gd-file-1" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "id": "gd-file-1", "trashed": true }),
                ));
            }
            if req.method == "DELETE" && req.path == "/files/gd-file-1" {
                return MockAction::Respond(MockResponse::empty(204));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[gd_default]
type = drive
client_id = cid
token = {"access_token":"tok1","token_type":"Bearer","refresh_token":"ref1","expiry":"2099-01-01T00:00:00Z"}

[gd_filtered]
type = drive
client_id = cid
shared_with_me = true
trashed_only = true
stop_on_upload_limit = true
scope = drive.readonly,drive.metadata.readonly
token = {"access_token":"tok2","token_type":"Bearer","refresh_token":"ref2","expiry":"2099-01-01T00:00:00Z"}
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        if let Some(RemoteConfig::Gdrive(g)) = cfg.remotes.get("gd_filtered") {
            assert_eq!(g.stop_on_upload_limit, Some(true));
            let scope = g.scope.as_deref().unwrap_or("");
            assert!(
                scope.contains("drive.readonly") && scope.contains("drive.metadata.readonly"),
                "multi-scope must preserve both scopes, got: {scope}"
            );
        } else {
            panic!("missing gd_filtered");
        }

        if let Some(RemoteConfig::Gdrive(g)) = cfg.remotes.get_mut("gd_default") {
            g.api_base_url = Some(srv.base_url());
            g.client_id = None;
            g.access_token = Some("tok1".to_string());
        }
        if let Some(RemoteConfig::Gdrive(g)) = cfg.remotes.get_mut("gd_filtered") {
            g.api_base_url = Some(srv.base_url());
            g.client_id = None;
            g.access_token = Some("tok2".to_string());
        }
        cfg.remotes.insert(
            "gd_new".to_string(),
            GdriveRemoteConfig::new()
                .with_api_base_url(srv.base_url())
                .with_access_token("tok3")
                .into(),
        );

        let client = RshipClient::builder()
            .paths(paths)
            .config(cfg)
            .allow_changes_feed(false)
            .build()
            .unwrap();

        // 1. Default delete on imported remote without `use_trash` MUST trash via PATCH.
        client.delete("gd_default:hello.txt").await.unwrap();
        let reqs_del = srv.take_requests();
        assert!(
            reqs_del.iter().any(|r| {
                r.method == "PATCH"
                    && r.path == "/files/gd-file-1"
                    && r.body_json().ok().and_then(|v| v["trashed"].as_bool()) == Some(true)
            }),
            "omitted use_trash in rclone.conf must default to PATCH trashed=true, saw: {:?}",
            reqs_del
                .iter()
                .map(|r| format!("{} {}", r.method, r.raw_target))
                .collect::<Vec<_>>()
        );

        // 2. Default delete on GdriveRemoteConfig::new() MUST trash via PATCH.
        client.delete("gd_new:hello.txt").await.unwrap();
        let reqs_new = srv.take_requests();
        assert!(
            reqs_new
                .iter()
                .any(|r| r.method == "PATCH" && r.path == "/files/gd-file-1"),
            "GdriveRemoteConfig::new() must default use_trash_on_delete = true"
        );

        // 3. `shared_with_me` & `trashed_only` filters on `list`.
        use futures::StreamExt;
        let _ = client
            .list("gd_filtered:", &ListOptions::shallow())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let reqs_list = srv.take_requests();
        let q = reqs_list
            .iter()
            .find(|r| r.method == "GET" && r.path == "/files")
            .and_then(|r| r.query_get("q"))
            .unwrap_or_default();
        assert!(
            q.contains("sharedWithMe") && q.contains("trashed = true"),
            "shared_with_me & trashed_only must appear in Drive q=, got: `{q}`"
        );
    }

    #[cfg(feature = "gcs")]
    #[tokio::test]
    async fn tier2_factory_import_gcs_endpoint_scope_and_user_project() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};

        let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "POST" && req.path == "/token" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "access_token": "ya29.gcs-sa",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }),
                ));
            }
            if req.method == "GET" && req.path == "/storage/v1/b/my-b/o/obj.txt" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "name": "obj.txt",
                        "size": "7",
                        "updated": "2026-01-01T00:00:00Z",
                        "generation": "1"
                    }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

        let tmp = TempDir::new().unwrap();
        let sa_path = tmp.path().join("sa.json");
        std::fs::write(
            &sa_path,
            serde_json::json!({
                "client_email": "sa@proj.iam.gserviceaccount.com",
                "private_key": super::TEST_SA_PRIVATE_KEY_PEM,
                "token_uri": srv.url("/token")
            })
            .to_string(),
        )
        .unwrap();

        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = format!(
            r#"
[gcs_ep]
type = google cloud storage
endpoint = {}
user_project = pay-proj
scope = read_only
service_account_file = {}
"#,
            srv.base_url(),
            sa_path.display()
        );

        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, &raw, &paths, true, false).unwrap();
        if let Some(RemoteConfig::Gcs(g)) = cfg.remotes.get_mut("gcs_ep") {
            g.bucket = Some("my-b".to_string());
        }

        let client = RshipClient::builder()
            .paths(paths)
            .config(cfg)
            .build()
            .unwrap();
        let entry = client
            .stat("gcs_ep:obj.txt")
            .await
            .expect("GCS remote with imported `endpoint` must hit mock server")
            .expect("obj.txt must exist");
        assert_eq!(entry.size, 7);

        let reqs = srv.requests();
        let token_req = reqs
            .iter()
            .find(|r| r.method == "POST" && r.path == "/token")
            .expect("SA token request expected");
        let assertion = token_req.form_get("assertion").expect("JWT assertion");
        let claims_b64 = assertion.split('.').nth(1).expect("JWT claims segment");
        let claims_bytes = base64_url_decode_unpadded(claims_b64);
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(
            claims["scope"].as_str(),
            Some("https://www.googleapis.com/auth/devstorage.read_only")
        );

        let obj_req = reqs
            .iter()
            .find(|r| r.method == "GET" && r.path == "/storage/v1/b/my-b/o/obj.txt")
            .expect("GCS object GET expected");
        assert_eq!(
            obj_req.query_get("userProject").as_deref(),
            Some("pay-proj")
        );
    }

    #[cfg(feature = "gcs")]
    fn base64_url_decode_unpadded(input: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits: u8 = 0;
        for b in input.bytes() {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                b'=' => break,
                _ => continue,
            };
            acc = (acc << 6) | u32::from(val);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((acc >> bits) & 0xff) as u8);
            }
        }
        out
    }

    #[cfg(feature = "onedrive")]
    #[test]
    fn tier2_factory_import_onedrive_region_drive_type_and_chunk_size() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[od_cn]
type = onedrive
region = cn
drive_type = business
chunk_size = 5Mi
client_id = cid-od
token = {"access_token":"od-tok","token_type":"Bearer","refresh_token":"od-ref","expiry":"2099-01-01T00:00:00Z"}
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();
        let client = RshipClient::builder()
            .paths(paths)
            .config(cfg)
            .build()
            .unwrap();
        let (backend, _) = client.resolve("od_cn:").unwrap();
        assert!(
            backend
                .endpoint_identity()
                .contains("microsoftgraph.chinacloudapi.cn"),
            "region = cn must select 21Vianet endpoint, got: {}",
            backend.endpoint_identity()
        );
        assert_eq!(backend.capabilities().default_chunk_size, 5 * 1024 * 1024);
        assert!(
            backend.capabilities().hashes.is_empty(),
            "drive_type = business must not advertise personal sha256/sha1 hashes, got: {:?}",
            backend.capabilities().hashes
        );
    }

    #[cfg(feature = "dropbox")]
    #[tokio::test]
    async fn tier2_factory_import_dropbox_team_headers_and_shared_folders() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
        use futures::StreamExt;
        use rship::core::backend::ListOptions;

        let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "POST" && req.path == "/files/list_folder" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "entries": [],
                        "cursor": "",
                        "has_more": false
                    }),
                ));
            }
            if req.method == "POST" && req.path == "/sharing/list_folders" {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "entries": [],
                        "cursor": ""
                    }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[dbx_team]
type = dropbox
client_id = dbx-cid
root_namespace = ns:123
impersonate = dbmid:user1
shared_folders = true
token = {"access_token":"sl.tok","token_type":"bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();
        let shared_folders_imported = cfg
            .remotes
            .get("dbx_team")
            .and_then(|r| serde_json::to_value(r).ok())
            .and_then(|v| v.get("shared_folders").and_then(|b| b.as_bool()))
            == Some(true);
        if let Some(RemoteConfig::Dropbox(d)) = cfg.remotes.get_mut("dbx_team") {
            d.api_base_url = Some(srv.base_url());
            d.client_id = None;
            d.access_token = Some("sl.tok".to_string());
        }

        let client = RshipClient::builder()
            .paths(paths)
            .config(cfg)
            .build()
            .unwrap();
        let _ = client
            .list("dbx_team:", &ListOptions::shallow())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;

        let reqs = srv.requests();
        let list_req = reqs
            .iter()
            .find(|r| r.path == "/files/list_folder")
            .expect("list_folder request expected");
        assert!(
            list_req
                .header("dropbox-api-path-root")
                .is_some_and(|v| v.contains("123")),
            "expected Dropbox-API-Path-Root header for root_namespace"
        );
        assert_eq!(
            list_req.header("dropbox-api-select-user"),
            Some("dbmid:user1")
        );
        let shared_folders_queried = reqs.iter().any(|r| r.path == "/sharing/list_folders");
        assert!(
            shared_folders_imported || shared_folders_queried,
            "shared_folders = true must be preserved in DropboxRemoteConfig or trigger /sharing/list_folders"
        );
    }

    #[cfg(feature = "webdav")]
    #[tokio::test]
    async fn tier2_factory_import_webdav_headers_bearer_cmd_and_strict_vendor() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};

        let srv = MockHttpServer::start_with_handler(|req| {
            if req.method == "PROPFIND" {
                let xml = format!(
                    r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>{}</d:href>
    <d:propstat>
      <d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#,
                    req.path
                );
                return MockAction::Respond(
                    MockResponse::new(207, xml.into_bytes())
                        .with_header("Content-Type", "application/xml"),
                );
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));

        // 1. Custom `headers` from rclone.conf must be sent on wire requests.
        let raw_hdrs = format!(
            r#"
[dav_hdrs]
type = webdav
url = {}/dav/
vendor = nextcloud
headers = X-Trace,abc,X-Env,e2e
bearer_token = tok-hdr
"#,
            srv.base_url()
        );
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, &raw_hdrs, &paths, true, false).unwrap();
        let client = RshipClient::builder()
            .ephemeral()
            .config(cfg)
            .build()
            .unwrap();
        let _ = client.stat("dav_hdrs:f.txt").await.unwrap();
        let reqs = srv.take_requests();
        assert_eq!(reqs[0].header("x-trace"), Some("abc"));
        assert_eq!(reqs[0].header("x-env"), Some("e2e"));

        // 2. `bearer_token_command` must never be silently dropped with 0 warnings and no auth.
        #[cfg(windows)]
        let token_cmd = "cmd /C echo dyn-tok-123";
        #[cfg(not(windows))]
        let token_cmd = "echo dyn-tok-123";
        let raw_cmd = format!(
            r#"
[dav_cmd]
type = webdav
url = {}/dav/
vendor = generic
bearer_token_command = {token_cmd}
"#,
            srv.base_url()
        );
        let mut cfg_cmd = AppConfig::new();
        let res_cmd = import_rclone_conf(&mut cfg_cmd, &raw_cmd, &paths, true, false);
        match res_cmd {
            Err(e) => {
                assert!(e.is_config() || e.to_string().contains("bearer_token_command"));
            }
            Ok(summary) => {
                let warned = summary
                    .warnings
                    .iter()
                    .any(|w| w.contains("bearer_token_command"));
                if !warned {
                    // If accepted without warning, it must actually supply the Bearer token on the wire.
                    let client_cmd = RshipClient::builder()
                        .ephemeral()
                        .config(cfg_cmd)
                        .build()
                        .unwrap();
                    let _ = client_cmd.stat("dav_cmd:f.txt").await.unwrap();
                    let cmd_reqs = srv.take_requests();
                    assert_eq!(
                        cmd_reqs[0].header("authorization"),
                        Some("Bearer dyn-tok-123"),
                        "bearer_token_command was neither warned/rejected nor executed"
                    );
                }
            }
        }

        // 3. Unknown vendor must warn or error rather than silently falling back to Generic.
        let raw_bad_vendor = format!(
            r#"
[dav_bad_vendor]
type = webdav
url = {}/dav/
vendor = bogus_vendor
"#,
            srv.base_url()
        );
        let mut cfg_bad = AppConfig::new();
        let res_bad = import_rclone_conf(&mut cfg_bad, &raw_bad_vendor, &paths, true, false);
        match res_bad {
            Err(e) => {
                assert!(
                    e.is_config()
                        || e.to_string().contains("vendor")
                        || e.to_string().contains("bogus_vendor"),
                    "unexpected error kind/message for unknown WebDAV vendor: {e:?}"
                );
            }
            Ok(summary) => {
                assert!(
                    summary
                        .warnings
                        .iter()
                        .any(|w| w.contains("bogus_vendor") || w.contains("vendor")),
                    "unknown vendor must warn or fail rather than silently degrading to Generic; warnings={:?}",
                    summary.warnings
                );
            }
        }
    }

    #[cfg(feature = "sftp")]
    #[test]
    fn tier2_factory_import_sftp_default_os_user_known_hosts_and_key_pem() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let os_user = ["USER", "LOGNAME", "USERNAME"].into_iter().find_map(|k| {
            std::env::var(k)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

        let raw = r#"
[sf_default_user]
type = sftp
host = 127.0.0.1
pass = pw1

[sf_kh]
type = sftp
host = 127.0.0.1
user = alice
pass = pw2
known_hosts_file = /opt/ssh/known_hosts

[sf_pem]
type = sftp
host = 127.0.0.1
user = alice
key_pem = -----BEGIN OPENSSH PRIVATE KEY-----
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        let imported_default_user = match cfg.remotes.get("sf_default_user") {
            Some(RemoteConfig::Sftp(s)) => s.user.clone(),
            other => panic!("expected Sftp for sf_default_user, got {other:?}"),
        };
        match os_user.as_deref() {
            Some("root") => assert_eq!(imported_default_user, "root"),
            Some(expected) => {
                assert_ne!(
                    imported_default_user, "root",
                    "omitted SFTP user must not hardcode `root`"
                );
                assert_eq!(
                    imported_default_user, expected,
                    "omitted SFTP user must default to OS user `{expected}`"
                );
            }
            None => {
                assert!(
                    !imported_default_user.is_empty() && imported_default_user != "root",
                    "omitted SFTP user must not hardcode `root` when OS user env vars are unset, got `{imported_default_user}`"
                );
            }
        }

        match cfg.remotes.get("sf_kh") {
            Some(RemoteConfig::Sftp(s)) => {
                assert_eq!(
                    s.known_hosts_path.as_deref(),
                    Some(std::path::Path::new("/opt/ssh/known_hosts"))
                );
            }
            other => panic!("expected Sftp, got {other:?}"),
        }

        let client = RshipClient::builder()
            .ephemeral()
            .config(cfg)
            .build()
            .unwrap();

        let (sf_user_backend, _) = client.resolve("sf_default_user:").unwrap();
        assert!(
            sf_user_backend
                .endpoint_identity()
                .starts_with(&format!("sftp://{imported_default_user}@")),
            "resolved SftpBackend must use imported user `{imported_default_user}`, got: {}",
            sf_user_backend.endpoint_identity()
        );

        assert!(
            client.resolve("sf_pem:").is_ok(),
            "inline key_pem must resolve SftpBackend without key_file/password"
        );
    }

    #[cfg(feature = "azureblob")]
    #[test]
    fn tier2_factory_import_azureblob_azurite_and_container_sas_url() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[az_azurite]
type = azureblob
sas_url = http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sig=x

[az_cont]
type = azureblob
sas_url = https://myacct.blob.core.windows.net/mycont?sv=2023-11-03&sig=x
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("az_azurite") {
            Some(RemoteConfig::Azureblob(a)) => {
                assert_eq!(a.account.as_deref(), Some("devstoreaccount1"));
                assert_eq!(a.container.as_deref(), Some("mycont"));
            }
            other => panic!("expected Azureblob, got {other:?}"),
        }
        match cfg.remotes.get("az_cont") {
            Some(RemoteConfig::Azureblob(a)) => {
                assert_eq!(a.account.as_deref(), Some("myacct"));
                assert_eq!(a.container.as_deref(), Some("mycont"));
                assert_eq!(
                    a.endpoint.as_deref(),
                    Some("https://myacct.blob.core.windows.net")
                );
            }
            other => panic!("expected Azureblob, got {other:?}"),
        }

        let client = RshipClient::builder()
            .ephemeral()
            .config(cfg)
            .build()
            .unwrap();
        assert!(client.resolve("az_azurite:").is_ok());
        assert!(client.resolve("az_cont:").is_ok());
    }
}
