//! Live S3-compatible E2E smoke test suite against real MinIO / AWS S3 / Cloudflare R2.
//!
//! Gated behind `#[ignore]` and environment variables so `cargo test --workspace` stays
//! fast and offline by default, while CI (with a live MinIO Docker service) and developers
//! can run it against real S3 servers:
//!
//! ```bash
//! RSHIP_LIVE_S3_ENDPOINT=http://127.0.0.1:9000 \
//! RSHIP_LIVE_S3_BUCKET=rship-ci \
//! RSHIP_LIVE_S3_ACCESS_KEY=minioadmin \
//! RSHIP_LIVE_S3_SECRET_KEY=minioadmin \
//! RSHIP_LIVE_S3_PROVIDER=minio \
//! cargo test -p rship-backends --no-default-features --features s3 --test s3_live_smoke -- --ignored --nocapture
//! ```

use bytes::Bytes;
use futures::StreamExt;
use rship_backends::s3::{S3Backend, S3Config, S3Credentials, S3Provider};
use rship_core::backend::{
    BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit, UploadProgress,
};
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;

fn live_s3_backend(prefix: &str) -> Option<S3Backend> {
    let endpoint = std::env::var("RSHIP_LIVE_S3_ENDPOINT").ok()?;
    let bucket = std::env::var("RSHIP_LIVE_S3_BUCKET").ok()?;
    let ak = std::env::var("RSHIP_LIVE_S3_ACCESS_KEY").ok()?;
    let sk = std::env::var("RSHIP_LIVE_S3_SECRET_KEY").ok()?;
    let provider = std::env::var("RSHIP_LIVE_S3_PROVIDER")
        .ok()
        .and_then(|s| S3Provider::parse(&s))
        .unwrap_or(S3Provider::Minio);
    let region = std::env::var("RSHIP_LIVE_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let creds = S3Credentials::new(ak, sk);
    let mut cfg = S3Config::new("live-s3", provider, bucket, creds);
    cfg.endpoint = Some(endpoint);
    cfg.region = region;
    cfg.prefix = prefix.to_string();
    cfg.force_path_style = Some(true);
    let transport = HttpTransport::new(TransportConfig::default()).ok()?;
    S3Backend::new(cfg, transport, None).ok()
}

#[tokio::test]
#[ignore = "requires live MinIO/S3 server configured via RSHIP_LIVE_S3_* env vars"]
async fn live_s3_conformance_multipart_resume_server_side_copy_and_bulk_delete() {
    let run_prefix = format!(
        "smoke-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let s3 = Arc::new(
        live_s3_backend(&run_prefix)
            .expect("RSHIP_LIVE_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY must be set"),
    );

    // 1. Universal backend conformance against the real S3 server!
    run_backend_conformance(s3.clone(), SystemClock::shared()).await;

    // 2. Real 11 MiB multipart upload (6 MiB + 5 MiB) with live `ListParts` resume check!
    let part1_len = 6 * 1024 * 1024usize;
    let part2_len = 5 * 1024 * 1024usize;
    let total_len = (part1_len + part2_len) as u64;
    let part1_data: Vec<u8> = (0..part1_len).map(|i| (i % 251) as u8).collect();
    let part2_data: Vec<u8> = (0..part2_len).map(|i| ((i + 77) % 251) as u8).collect();

    let dst_rel = RelPath::parse("mp/eleven-mib.bin").unwrap();
    let init = UploadInit {
        op_id: format!("live-mp-{run_prefix}"),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_len,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: part1_len as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = s3.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key("local", "mp", &s3.endpoint_identity(), &dst_rel),
        job_id: "live-job".into(),
        src_endpoint: "local".into(),
        dst_endpoint: s3.endpoint_identity(),
        src_raw_path: "mp".into(),
        dst_raw_path: dst_rel.as_str().into(),
        dst_nfc_path: dst_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total_len,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: part1_len as u64,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };

    let p1 = part1_data.clone();
    let ack1 = s3
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                part1_len as u64,
                total_len,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1)) })),
            ),
        )
        .await
        .unwrap();

    // Live `ListParts` query must report Part 1 cleanly.
    match s3.query_upload(&op).await.unwrap() {
        UploadProgress::CompletedParts(parts) => {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].part_number, 1);
            assert_eq!(parts[0].length, part1_len as u64);
        }
        other => panic!("expected CompletedParts from live S3, got {other:?}"),
    }

    let p2 = part2_data.clone();
    let ack2 = s3
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                part1_len as u64,
                part2_len as u64,
                total_len,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .unwrap();

    let committed = s3
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: part1_len as u64,
                    etag: ack1.etag.unwrap(),
                    // An upload created with `x-amz-checksum-algorithm` (CRC32C on
                    // MinIO/silo) must list each part's checksum in Complete.
                    checksum: ack1.checksum,
                },
                CompletedPart {
                    part_number: 2,
                    offset: part1_len as u64,
                    length: part2_len as u64,
                    etag: ack2.etag.unwrap(),
                    checksum: ack2.checksum,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(committed.size, total_len);

    // 3. Server-side CopyObject on live S3!
    let copy_rel = RelPath::parse("mp/eleven-mib-copy.bin").unwrap();
    let copy_init = UploadInit {
        op_id: format!("live-copy-{run_prefix}"),
        dst_path: copy_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_len,
        src_mtime_ns: init.src_mtime_ns,
        planned_chunk_size: total_len,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let copied = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(dst_rel.clone()),
            &copy_init,
        )
        .await
        .unwrap()
        .expect("server_side_copy must succeed on live S3");
    assert_eq!(copied.size, total_len);

    // Spot-check Range read across part boundary!
    let ds = s3
        .open_read(&BackendPath::from_rel(copy_rel.clone()), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: (part1_len - 16) as u64,
            len: 32,
        })
        .await
        .unwrap();
    let mut slice = Vec::new();
    while let Some(c) = stream.next().await {
        slice.extend_from_slice(&c.unwrap());
    }
    assert_eq!(&slice[..16], &part1_data[part1_len - 16..]);
    assert_eq!(&slice[16..], &part2_data[..16]);

    // 4. Bulk `DeleteObjects` cleanup!
    let failures = s3
        .delete_batch(&[
            BackendPath::from_rel(dst_rel),
            BackendPath::from_rel(copy_rel),
        ])
        .await
        .unwrap();
    assert!(
        failures.is_empty(),
        "live delete_batch failures: {failures:?}"
    );
}
