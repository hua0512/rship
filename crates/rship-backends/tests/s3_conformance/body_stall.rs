//! Upload response bodies must be read under a deadline: the data-plane client has no total
//! `.timeout()`, and the stall watchdog stops guarding once the response headers arrive.

use axum::body::Bytes;
use rship_backends::s3::{S3Backend, S3Config, S3Credentials, S3Provider};
use rship_core::ErrorKind;
use rship_core::backend::{StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_transport::{HttpTransport, TransportConfig};
use std::time::{Duration, Instant};

#[tokio::test]
async fn s3_put_object_response_body_stall_times_out_instead_of_hanging() {
    let base =
        crate::common::spawn_headers_then_stall_server("200 OK", "ETag: \"abc\"\r\n", b"<").await;
    let creds = S3Credentials::new("AKIA_TEST_KEY", "SECRET_TEST_KEY_12345");
    let mut cfg = S3Config::new("stall", S3Provider::Minio, "bkt", creds);
    cfg.endpoint = Some(base);
    cfg.force_path_style = Some(true);
    cfg.max_retries = 0;
    let transport = HttpTransport::new(
        TransportConfig::default()
            .with_data_stall_timeout(Duration::from_millis(300))
            .with_data_finalize_timeout(Duration::from_secs(1)),
    )
    .unwrap();
    let backend = S3Backend::new(cfg, transport, None).unwrap();
    let payload = Bytes::from_static(b"hello stall");
    let init = UploadInit {
        op_id: "op-stall".into(),
        dst_path: RelPath::parse("stall.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(20),
        backend.put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(payload) })),
        ),
    )
    .await
    .expect("upload response body read must be bounded, not hang forever");
    let err = res.expect_err("stalled response body must fail");
    assert!(
        matches!(err.kind, ErrorKind::Timeout | ErrorKind::Network),
        "unexpected error: {err:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}
