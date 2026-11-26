//! Upload response bodies must be read under a deadline: the data-plane client has no total
//! `.timeout()`, and the stall watchdog stops guarding once the response headers arrive.

use axum::body::Bytes;
use rship_backends::webdav::{WebdavBackend, WebdavConfig};
use rship_core::ErrorKind;
use rship_core::backend::{StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_transport::{HttpTransport, TransportConfig};
use std::time::{Duration, Instant};

#[tokio::test]
async fn webdav_put_response_body_stall_times_out_instead_of_hanging() {
    // The server commits the PUT, sends `201` headers, then blackholes the response body.
    let base =
        crate::common::spawn_headers_then_stall_server("201 Created", "ETag: \"x\"\r\n", b"ok")
            .await;
    let mut cfg = WebdavConfig::new("stall", format!("{base}/dav"));
    cfg.max_retries = 0;
    let transport = HttpTransport::new(
        TransportConfig::default()
            .with_data_stall_timeout(Duration::from_millis(300))
            .with_data_finalize_timeout(Duration::from_secs(1)),
    )
    .unwrap();
    let backend = WebdavBackend::new(cfg, transport).unwrap();
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
