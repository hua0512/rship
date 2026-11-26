use super::*;
use axum::routing::get;
use axum::{Router, body::Body};
use http::header::{HeaderName, HeaderValue};
use tokio::net::TcpListener;

#[test]
fn parses_retry_after_delta_and_http_date() {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_static("12"),
    );
    assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(12)));

    let future = rship_core::time::format_http_date(rship_core::time::now_unix_secs() + 30);
    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_str(&future).unwrap(),
    );
    let parsed = parse_retry_after(&h).unwrap();
    assert!(parsed.as_secs() >= 25 && parsed.as_secs() <= 35);

    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_static("Sun, 6 Nov 1994 08:49:37 +0000"),
    );
    assert_eq!(parse_retry_after(&h), Some(Duration::ZERO));
}

#[test]
fn parse_retry_after_handles_overflow_and_negative_headers() {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_static("99999999999999999999999"),
    );
    assert_eq!(parse_retry_after(&h), None);

    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_static("-5"),
    );
    assert_eq!(parse_retry_after(&h), None);

    h.insert(
        HeaderName::from_static("retry-after"),
        HeaderValue::from_static("0"),
    );
    assert_eq!(parse_retry_after(&h), Some(Duration::ZERO));
}

#[tokio::test]
async fn bounded_control_body_rejects_oversized_response() {
    let app = Router::new()
        .route("/small", get(|| async { r#"{"ok":true}"# }))
        .route("/huge", get(|| async { Body::from(vec![b'x'; 8192]) }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let cfg = TransportConfig {
        max_control_response_bytes: 1024,
        ..Default::default()
    };
    let transport = HttpTransport::new(cfg).unwrap();

    let ok_resp = transport
        .control_client()
        .get(format!("http://{addr}/small"))
        .send()
        .await
        .unwrap();
    let val: serde_json::Value = transport.read_control_json(ok_resp).await.unwrap();
    assert_eq!(val["ok"], true);

    let big_resp = transport
        .control_client()
        .get(format!("http://{addr}/huge"))
        .send()
        .await
        .unwrap();
    let err = transport.read_control_body(big_resp).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Protocol);
}

#[tokio::test]
async fn data_plane_uses_http1_only_by_default() {
    let cfg = TransportConfig::default();
    assert!(cfg.data_http1_only);
    let transport = HttpTransport::new(cfg).unwrap();

    let app = Router::new().route(
        "/ver",
        get(|req: axum::extract::Request| async move { format!("{:?}", req.version()) }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resp = transport
        .data_client()
        .get(format!("http://{addr}/ver"))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert_eq!(body, "HTTP/1.1");
}

#[test]
fn redact_url_credentials_scrubs_proxy_secrets() {
    let s = redact_url_credentials(
        "proxy error via socks5h://alice:super_secret_99@proxy.internal:1080/path",
    );
    assert!(!s.contains("alice"));
    assert!(!s.contains("super_secret_99"));
    assert!(s.contains("socks5h://***@proxy.internal:1080/path"));

    // Invalid proxy URL must also redact credentials from TransportConfig error,
    // including unencoded `#`, `?`, `/`, whitespace, quotes, `)`, and extra `@` in password!
    for bad_proxy in [
        "http://bob:topsecret@bad host:9999",
        "http://alice:sec#ret@proxy.corp:8080",
        "http://alice:sec?ret@proxy.corp:8080",
        "http://alice:sec/ret@proxy.corp:8080",
        "http://alice:my secret@proxy.corp:8080",
        "http://alice:P@ss#word@proxy.corp:8080",
        "http://alice:sec)ret@proxy.corp:8080",
        "http://alice:sec\"ret@proxy.corp:8080",
    ] {
        let err = validate_proxy_url(bad_proxy);
        if let Err(e) = err {
            let msg = e.to_string();
            assert!(!msg.contains("topsecret"), "leaked secret in error: {msg}");
            assert!(!msg.contains("bob"), "leaked user in error: {msg}");
            assert!(!msg.contains("alice"), "leaked user in error: {msg}");
            assert!(
                !msg.contains("sec"),
                "leaked password fragment in error: {msg}"
            );
            assert!(
                !msg.contains("word"),
                "leaked password suffix in error: {msg}"
            );
        }
        let scrubbed = redact_url_credentials(bad_proxy);
        assert!(!scrubbed.contains("alice"), "leaked user in `{scrubbed}`");
        assert!(!scrubbed.contains("sec"), "leaked pass in `{scrubbed}`");
        assert!(!scrubbed.contains("word"), "leaked suffix in `{scrubbed}`");
    }
    // Legitimate `@` inside object path (no authority credentials) must stay readable!
    let email_path = "https://storage.googleapis.com:443/b/bucket/o/alice@example.com?alt=media";
    assert_eq!(redact_url_credentials(email_path), email_path);
}

#[tokio::test]
async fn http_dump_redacts_secrets_in_headers_and_urls_and_executes_cleanly() {
    assert_eq!(HttpDumpMode::parse("headers"), Some(HttpDumpMode::Headers));
    assert_eq!(HttpDumpMode::parse("off"), Some(HttpDumpMode::None));
    assert_eq!(HttpDumpMode::parse("bogus"), None);

    let url = "https://user:pw@acct.blob.core.windows.net/c/f?sv=2022&sig=SUPER_SAS_SECRET;X-Amz-Signature=deadbeef&X-Amz-Security-Token=tok123&tempauth=OD_JWT_SECRET&upload_id=GDRIVE_SESS_99&%74oken=ENC_TOK&list-type=2#access_token=FRAG_TOK;state=ok";
    let safe = redact_url_for_dump(url);
    assert!(!safe.contains("pw"));
    assert!(!safe.contains("SUPER_SAS_SECRET"));
    assert!(!safe.contains("deadbeef"));
    assert!(!safe.contains("tok123"));
    assert!(!safe.contains("OD_JWT_SECRET"));
    assert!(!safe.contains("GDRIVE_SESS_99"));
    assert!(!safe.contains("ENC_TOK"));
    assert!(!safe.contains("FRAG_TOK"));
    assert!(safe.contains("list-type=2"));
    assert!(safe.contains("sig=***REDACTED***;X-Amz-Signature=***REDACTED***"));
    assert!(safe.contains("tempauth=***REDACTED***"));
    assert!(safe.contains("upload_id=***REDACTED***"));
    assert!(safe.contains("%74oken=***REDACTED***"));
    assert!(safe.contains("#access_token=***REDACTED***;state=ok"));

    let err_text = redact_urls_in_text(
        "error sending request for url (https://alice:pw#99@blob.example/x?sig=SAS_SECRET&sp=r): timeout",
    );
    assert!(!err_text.contains("alice"));
    assert!(!err_text.contains("pw#99"));
    assert!(!err_text.contains("SAS_SECRET"));
    assert!(err_text.contains("https://***@blob.example/x?sig=***REDACTED***&sp=r"));

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKIA/2026, Signature=secret999"),
    );
    hdrs.insert(
        HeaderName::from_static("x-amz-security-token"),
        HeaderValue::from_static("IQoJb3JpZ2luX2VjSecret"),
    );
    hdrs.insert(
        HeaderName::from_static("x-amz-server-side-encryption-customer-key"),
        HeaderValue::from_static("RAW_SSEC_KEY_BASE64"),
    );
    hdrs.insert(
        HeaderName::from_static("x-goog-encryption-key"),
        HeaderValue::from_static("RAW_CSEK_KEY"),
    );
    hdrs.insert(
        HeaderName::from_static("x-goog-copy-source-encryption-key"),
        HeaderValue::from_static("RAW_COPY_CSEK_KEY"),
    );
    hdrs.insert(
        HeaderName::from_static("destination"),
        HeaderValue::from_static(
            "https://davuser:davpass@dav.example.com/remote.php/dav/files/u/a?token=DAV_TOK",
        ),
    );
    hdrs.insert(
        HeaderName::from_static("x-goog-upload-url"),
        HeaderValue::from_static("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=RESUMABLE_CAP_SECRET"),
    );
    hdrs.insert(
        http::header::COOKIE,
        HeaderValue::from_static("session=topsecret"),
    );
    hdrs.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    hdrs.insert(
        HeaderName::from_static("x-amz-content-sha256"),
        HeaderValue::from_static("UNSIGNED-PAYLOAD"),
    );
    let formatted = format_redacted_headers(&hdrs);
    assert!(formatted.contains("authorization: AWS4-HMAC-SHA256 ***REDACTED***"));
    assert!(!formatted.contains("secret999"));
    assert!(!formatted.contains("IQoJb3JpZ2luX2VjSecret"));
    assert!(!formatted.contains("RAW_SSEC_KEY_BASE64"));
    assert!(!formatted.contains("RAW_CSEK_KEY"));
    assert!(!formatted.contains("RAW_COPY_CSEK_KEY"));
    assert!(!formatted.contains("davpass"));
    assert!(!formatted.contains("DAV_TOK"));
    assert!(!formatted.contains("RESUMABLE_CAP_SECRET"));
    assert!(!formatted.contains("topsecret"));
    assert!(formatted.contains(
        "destination: https://***@dav.example.com/remote.php/dav/files/u/a?token=***REDACTED***"
    ));
    assert!(formatted.contains("x-goog-upload-url: https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=***REDACTED***"));
    assert!(formatted.contains("content-type: application/json"));
    assert!(formatted.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));

    // Exercise both control-plane and data-plane dump paths end-to-end.
    let app = Router::new().route("/ping", get(|| async { "pong" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let transport =
        HttpTransport::new(TransportConfig::new().with_dump_mode(HttpDumpMode::Headers)).unwrap();
    let req1 = transport
        .control_client()
        .get(format!("http://{addr}/ping?sig=hide_me"))
        .header(http::header::AUTHORIZATION, "Bearer secret-tok");
    let r1 = transport
        .send_control_request("test-ctrl", req1)
        .await
        .unwrap();
    assert_eq!(r1.text().await.unwrap(), "pong");

    let req2 = transport.data_client().get(format!("http://{addr}/ping"));
    let r2 = transport
        .send_data_request("test-data", req2)
        .await
        .unwrap();
    assert_eq!(r2.text().await.unwrap(), "pong");
}

#[tokio::test]
async fn data_plane_does_not_transparently_decompress_gzip_payload() {
    // RFC 1952 gzip of "hello rship raw gzip data plane test payload - repeated repeated repeated 1234567890"
    const GZIP_WIRE_BYTES: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x6d, 0xc6, 0xdb, 0x09, 0x80,
        0x30, 0x0c, 0x05, 0xd0, 0x55, 0xee, 0x02, 0x82, 0xef, 0xc7, 0x38, 0x17, 0x1a, 0x6c, 0x21,
        0xd8, 0x90, 0x06, 0x44, 0xa7, 0x77, 0x01, 0xcf, 0xd7, 0xc9, 0xa2, 0x5a, 0xe1, 0x2d, 0x17,
        0x83, 0xf3, 0xc6, 0xf9, 0x16, 0x43, 0x62, 0x10, 0xa6, 0xbc, 0x04, 0x21, 0x2d, 0x60, 0x7c,
        0xb4, 0x32, 0xa1, 0x83, 0x8b, 0x09, 0x43, 0xd2, 0x4f, 0x86, 0x71, 0x9a, 0x97, 0x75, 0xdb,
        0x8f, 0xfe, 0x03, 0x7d, 0xb1, 0xa4, 0x75, 0x54, 0x00, 0x00, 0x00,
    ];

    let app = Router::new().route(
        "/gzip-object",
        get(|| async {
            let mut resp = axum::response::Response::new(Body::from(GZIP_WIRE_BYTES));
            resp.headers_mut().insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            resp.headers_mut().insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&GZIP_WIRE_BYTES.len().to_string()).unwrap(),
            );
            resp
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let resp = transport
        .data_client()
        .get(format!("http://{addr}/gzip-object"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "data plane must retain Content-Encoding: gzip header verbatim"
    );
    assert_eq!(
        resp.content_length(),
        Some(GZIP_WIRE_BYTES.len() as u64),
        "data plane must retain exact compressed Content-Length"
    );
    let wire = resp.bytes().await.unwrap();
    assert_eq!(
        wire.as_ref(),
        GZIP_WIRE_BYTES,
        "data plane must return raw compressed wire bytes without transparent decompression"
    );
}

#[tokio::test]
async fn send_long_control_request_overrides_short_control_timeout() {
    let app = Router::new().route(
        "/slow-rpc",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            "slow-ok"
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    for dump_mode in [HttpDumpMode::None, HttpDumpMode::Headers] {
        let cfg = TransportConfig::new()
            .with_control_timeout(Duration::from_millis(60))
            .with_long_control_timeout(Duration::from_secs(2))
            .with_dump_mode(dump_mode);
        let transport = HttpTransport::new(cfg).unwrap();

        // Standard control request times out under control_timeout (60ms < 200ms).
        let req = transport
            .control_client()
            .get(format!("http://{addr}/slow-rpc"));
        let err = transport
            .send_control_request("slow-control-rpc", req)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert_eq!(err.retry, RetryClass::Retryable);

        // Long control request overrides timeout to long_control_timeout (2s > 200ms).
        let req_long = transport
            .control_client()
            .get(format!("http://{addr}/slow-rpc"));
        let ok = transport
            .send_long_control_request("slow-control-rpc-long", req_long)
            .await
            .unwrap();
        assert_eq!(ok.text().await.unwrap(), "slow-ok");

        // Explicit per-request timeout override also succeeds.
        let req_custom = transport
            .control_client()
            .get(format!("http://{addr}/slow-rpc"));
        let ok_custom = transport
            .send_control_request_with_timeout(
                "slow-control-rpc-custom",
                req_custom,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(ok_custom.text().await.unwrap(), "slow-ok");
    }
}

#[test]
fn transport_plane_limiters_and_data_watchdog_finalize_config() {
    let cfg = TransportConfig::new().with_data_finalize_timeout(Duration::from_secs(420));
    let transport = HttpTransport::new(cfg).unwrap();

    assert_eq!(
        transport.data_watchdog().finalize_timeout(),
        Duration::from_secs(420)
    );

    let scope = LimiterScope::new("s3", "bucket");
    let ctrl = transport.control_limiter_for(scope.clone());
    let data = transport.data_limiter_for(scope.clone());
    let ctrl_cfg =
        transport.control_limiter_for_with_config(scope.clone(), RateLimiterConfig::default());
    let data_cfg = transport.data_limiter_for_with_config(scope, RateLimiterConfig::default());

    assert!(Arc::ptr_eq(&ctrl, &ctrl_cfg));
    assert!(Arc::ptr_eq(&data, &data_cfg));
    assert!(!Arc::ptr_eq(&ctrl, &data));
    data.record_throttle();
    assert!(data.snapshot().cubic_enabled);
    assert!(!ctrl.snapshot().cubic_enabled);
}
