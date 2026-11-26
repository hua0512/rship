use axum::body::Bytes;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::s3::{
    PayloadSigningMode, S3Backend, S3Config, S3Credentials, S3Provider, UNSIGNED_PAYLOAD,
    crc64_nvme, crc64_nvme_base64, sha256_hex,
};
use rship_core::backend::{
    BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit, UploadProgress,
};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{
    DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_core::types::{ByteRange, HashKind};
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::HashMap;
use std::sync::Arc;

use crate::mock_server::{MockS3Object, MockS3Server};

// =========================================================================
// Test 5: Payload Signing Policy (HTTPS UNSIGNED vs HTTP/Strict SHA-256)
//         + AWS `CRC64NVME` vs R2 Equal-Non-Final-Part Guard
// =========================================================================

#[tokio::test]
async fn s3_payload_signing_policy_and_provider_matrix_crc64nvme_vs_r2() {
    let srv = MockS3Server::start("matrix-bucket", "us-east-1").await;

    // 1. Verify default Auto policy over HTTPS vs HTTP!
    let https_cfg = S3Config::new(
        "aws-https",
        S3Provider::Aws,
        "b",
        S3Credentials::new("ak", "sk"),
    );
    assert!(https_cfg.is_https());
    assert!(
        !https_cfg.requires_payload_sha256(),
        "HTTPS defaults to UNSIGNED-PAYLOAD"
    );

    let mut strict_https = https_cfg.clone();
    strict_https.payload_signing = PayloadSigningMode::StrictSha256;
    assert!(strict_https.requires_payload_sha256());

    let http_cfg = srv.config(S3Provider::Aws, "matrix-bucket", "us-east-1");
    assert!(!http_cfg.is_https());
    assert!(
        http_cfg.requires_payload_sha256(),
        "plain HTTP automatically computes real SHA-256 (never aws-chunked)"
    );

    // 2. Upload over HTTP with AWS profile + `send_upload_checksum = true`:
    //    verifies real SHA-256 header AND `x-amz-checksum-crc64nvme`!
    let mut aws_cfg = http_cfg;
    aws_cfg.send_upload_checksum = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let aws = S3Backend::new(aws_cfg, transport.clone(), None).unwrap();

    let payload = b"123456789".to_vec();
    let expected_sha = sha256_hex(&payload);
    let expected_crc64 = crc64_nvme_base64(&payload);
    let p = RelPath::parse("check/aws.bin").unwrap();
    let init = UploadInit {
        op_id: "op-aws-ck".into(),
        dst_path: p.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4096,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p_c = payload.clone();
    aws.put_single_shot(
        &init,
        Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
    )
    .await
    .unwrap();

    {
        let g = srv.state.lock().unwrap();
        assert_eq!(
            g.counters.seen_payload_hashes.last().unwrap(),
            &expected_sha
        );
        assert_eq!(
            g.counters.seen_crc64nvme_headers.last().unwrap(),
            &expected_crc64
        );
    }

    // 3. Same `If-None-Match: *` second upload on existing key -> PreconditionFailed!
    let p_c2 = payload.clone();
    let cond_err = aws
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c2)) })),
        )
        .await
        .unwrap_err();
    assert_eq!(cond_err.kind, ErrorKind::PreconditionFailed);

    // 4. Explicit `Unsigned` mode emits `UNSIGNED-PAYLOAD` and still preserves existing file on short EOF!
    let mut uns_cfg = srv.config(S3Provider::R2, "matrix-bucket", "us-east-1");
    uns_cfg.payload_signing = PayloadSigningMode::Unsigned;
    uns_cfg.send_upload_checksum = false;
    uns_cfg.min_part_bytes_override = Some(256 * 1024);
    let r2 = S3Backend::new(uns_cfg, transport, None).unwrap();

    let ok_p = RelPath::parse("check/unsigned.bin").unwrap();
    let ok_init = UploadInit {
        op_id: "op-uns".into(),
        dst_path: ok_p.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 0,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    r2.put_single_shot(
        &ok_init,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from_static(b"hello"))
        })),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.state
            .lock()
            .unwrap()
            .counters
            .seen_payload_hashes
            .last()
            .unwrap(),
        UNSIGNED_PAYLOAD
    );

    // 5. Cloudflare R2 rejects unequal non-final parts before touching network!
    let dummy_op = OperationRecord {
        op_id: "op-r2".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "a".into(),
        dst_endpoint: "b".into(),
        src_raw_path: "x".into(),
        dst_raw_path: "x".into(),
        dst_nfc_path: RelPath::parse("x").unwrap(),
        src_version: SourceVersion {
            node_id: None,
            size: 1_000_000,
            mtime_ns: 0,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "s3".into(),
        session_token: Some("uid-1".into()),
        backend_meta: String::new(),
        planned_chunk_size: 256 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let r2_err = r2
        .finish_upload(
            &dummy_op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: 256 * 1024,
                    etag: "\"e1\"".into(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 2,
                    offset: 256 * 1024,
                    length: 512 * 1024, // unequal non-final part!
                    etag: "\"e2\"".into(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 3,
                    offset: 768 * 1024,
                    length: 1000,
                    etag: "\"e3\"".into(),
                    checksum: None,
                },
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(r2_err.kind, ErrorKind::InvalidGeometry);
    assert_eq!(r2_err.retry, RetryClass::Permanent);
}

#[tokio::test]
async fn s3_multipart_crc64nvme_and_hex_normalization_conformance() {
    let srv = MockS3Server::start("ck-bkt", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    // 1. AWS S3 single-shot + multipart with `send_upload_checksum = true` and `Unsigned`
    //    (HTTPS-equivalent): verifies base64->lowercase hex normalization, per-part
    //    `<ChecksumCRC64NVME>` in `CompleteMultipartUpload`, `ListParts` checksum recovery,
    //    and `UNSIGNED-PAYLOAD` on `UploadPart` (dead SHA-256 pass skipped).
    let mut aws_cfg = srv.config(S3Provider::Aws, "ck-bkt", "us-east-1");
    aws_cfg.send_upload_checksum = true;
    aws_cfg.payload_signing = PayloadSigningMode::Unsigned;
    aws_cfg.min_part_bytes_override = Some(64 * 1024);
    aws_cfg.default_chunk_size = Some(64 * 1024);
    let aws = S3Backend::new(aws_cfg, transport.clone(), None).unwrap();

    // Single-shot PutObject + stat must return lowercase hex CRC64NVME, NOT base64.
    let single_data = b"123456789".to_vec();
    let expected_single_hex = format!("{:016x}", crc64_nvme(&single_data));
    let single_path = RelPath::parse("ck/single.bin").unwrap();
    let single_init = UploadInit {
        op_id: "op-single-ck".into(),
        dst_path: single_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: single_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let s_clone = single_data.clone();
    let put_entry = aws
        .put_single_shot(
            &single_init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(s_clone)) },
            )),
        )
        .await
        .unwrap();
    assert_eq!(
        put_entry
            .checksum
            .as_ref()
            .map(|c| (c.kind, c.hex.as_str())),
        Some((HashKind::Crc64Nvme, expected_single_hex.as_str()))
    );
    let stat_entry = aws
        .stat(&BackendPath::from_rel(single_path))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stat_entry
            .checksum
            .as_ref()
            .map(|c| (c.kind, c.hex.as_str())),
        Some((HashKind::Crc64Nvme, expected_single_hex.as_str()))
    );

    // Multipart upload (2 parts: 64 KiB + 32 KiB) with strict CompleteMultipartUpload validation.
    let p1: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 31 + 5) & 0xFF) as u8)
        .collect();
    let p2: Vec<u8> = (0..(32 * 1024))
        .map(|i| ((i * 17 + 9) & 0xFF) as u8)
        .collect();
    let mut full = Vec::with_capacity(p1.len() + p2.len());
    full.extend_from_slice(&p1);
    full.extend_from_slice(&p2);
    let expected_mp_hex = format!("{:016x}", crc64_nvme(&full));

    let mp_path = RelPath::parse("ck/multi.bin").unwrap();
    let mp_init = UploadInit {
        op_id: "op-mp-ck".into(),
        dst_path: mp_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: full.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = aws.begin_upload(&mp_init).await.unwrap();
    let op = OperationRecord {
        op_id: mp_init.op_id.clone(),
        session_key: compute_session_key(
            "local://src",
            &aws.endpoint_identity(),
            mp_path.as_str(),
            &mp_path,
        ),
        job_id: "job-ck".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: aws.endpoint_identity(),
        src_raw_path: mp_path.as_str().into(),
        dst_raw_path: mp_path.as_str().into(),
        dst_nfc_path: mp_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: full.len() as u64,
            mtime_ns: mp_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened.session_token),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    let p1_c = p1.clone();
    let ack1 = aws
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                p1.len() as u64,
                full.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1_c)) })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        ack1.checksum.as_deref(),
        Some(format!("crc64nvme:{}", crc64_nvme_base64(&p1)).as_str())
    );

    let p2_c = p2.clone();
    let ack2 = aws
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                p1.len() as u64,
                p2.len() as u64,
                full.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2_c)) })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        ack2.checksum.as_deref(),
        Some(format!("crc64nvme:{}", crc64_nvme_base64(&p2)).as_str())
    );

    // Verify `ListParts` resume also recovers per-part checksums!
    let resumed_parts = match aws.query_upload(&op).await.unwrap() {
        UploadProgress::CompletedParts(parts) => parts,
        other => panic!("expected CompletedParts, got {other:?}"),
    };
    assert_eq!(resumed_parts.len(), 2);
    assert_eq!(resumed_parts[0].checksum, ack1.checksum);
    assert_eq!(resumed_parts[1].checksum, ack2.checksum);

    let committed = aws.finish_upload(&op, &resumed_parts).await.unwrap();
    assert_eq!(
        committed
            .checksum
            .as_ref()
            .map(|c| (c.kind, c.hex.as_str())),
        Some((HashKind::Crc64Nvme, expected_mp_hex.as_str()))
    );
    {
        let g = srv.state.lock().unwrap();
        // Last two UploadPart requests must have used UNSIGNED-PAYLOAD (no redundant SHA-256).
        let tail = &g.counters.seen_payload_hashes[g.counters.seen_payload_hashes.len() - 2..];
        assert_eq!(tail, &[UNSIGNED_PAYLOAD, UNSIGNED_PAYLOAD]);
    }

    // 2. R2 multipart with `CRC32C`: strict mock validates `<ChecksumCRC32C>` per part,
    //    and returns composite `<b64>-2` which client must reject (`checksum == None`).
    let mut r2_cfg = srv.config(S3Provider::R2, "ck-bkt", "us-east-1");
    r2_cfg.send_upload_checksum = true;
    r2_cfg.payload_signing = PayloadSigningMode::Unsigned;
    r2_cfg.min_part_bytes_override = Some(64 * 1024);
    r2_cfg.default_chunk_size = Some(64 * 1024);
    let r2 = S3Backend::new(r2_cfg, transport, None).unwrap();

    let r2_path = RelPath::parse("ck/r2-multi.bin").unwrap();
    let r2_init = UploadInit {
        op_id: "op-r2-ck".into(),
        dst_path: r2_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: full.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let r2_open = r2.begin_upload(&r2_init).await.unwrap();
    let r2_op = OperationRecord {
        op_id: r2_init.op_id.clone(),
        session_key: compute_session_key(
            "local://src",
            &r2.endpoint_identity(),
            r2_path.as_str(),
            &r2_path,
        ),
        job_id: "job-r2-ck".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: r2.endpoint_identity(),
        src_raw_path: r2_path.as_str().into(),
        dst_raw_path: r2_path.as_str().into(),
        dst_nfc_path: r2_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: full.len() as u64,
            mtime_ns: r2_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: r2_open.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(r2_open.session_token),
        backend_meta: r2_open.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let r2_ack1 = r2
        .upload_chunk(
            &r2_op,
            ChunkUpload::new(
                1,
                0,
                p1.len() as u64,
                full.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p1)) })),
            ),
        )
        .await
        .unwrap();
    let r2_ack2 = r2
        .upload_chunk(
            &r2_op,
            ChunkUpload::new(
                2,
                64 * 1024,
                p2.len() as u64,
                full.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2)) })),
            ),
        )
        .await
        .unwrap();
    let r2_parts = vec![
        CompletedPart {
            part_number: 1,
            offset: 0,
            length: 64 * 1024,
            etag: r2_ack1.etag.unwrap(),
            checksum: r2_ack1.checksum,
        },
        CompletedPart {
            part_number: 2,
            offset: 64 * 1024,
            length: 32 * 1024,
            etag: r2_ack2.etag.unwrap(),
            checksum: r2_ack2.checksum,
        },
    ];
    let r2_done = r2.finish_upload(&r2_op, &r2_parts).await.unwrap();
    assert!(
        r2_done.checksum.is_none(),
        "composite multipart CRC32C (`<b64>-2`) must not be stored as full-object checksum: {:?}",
        r2_done.checksum
    );
}

#[tokio::test]
async fn s3_to_local_checksum_sync_handles_legacy_md5_and_crc64nvme_multipart() {
    use rship_backends::local::LocalBackend;

    let srv = MockS3Server::start("sync-ck", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    let mut aws_cfg = srv.config(S3Provider::Aws, "sync-ck", "us-east-1");
    aws_cfg.send_upload_checksum = true;
    aws_cfg.payload_signing = PayloadSigningMode::Unsigned;
    aws_cfg.single_shot_max_bytes = Some(64 * 1024);
    aws_cfg.min_part_bytes_override = Some(64 * 1024);
    aws_cfg.default_chunk_size = Some(64 * 1024);
    let aws = Arc::new(S3Backend::new(aws_cfg, transport, None).unwrap());

    // AWS profile with `send_upload_checksum = true` advertises CRC64NVME and MD5, NOT CRC32C.
    let aws_caps = aws.capabilities();
    assert!(aws_caps.hashes.contains(&HashKind::Crc64Nvme));
    assert!(aws_caps.hashes.contains(&HashKind::Md5));
    assert!(
        !aws_caps.hashes.contains(&HashKind::Crc32c),
        "AWS S3 must not advertise CRC32C when CRC64NVME is active"
    );

    // 1. Seed a legacy MD5-only single-part S3 object (no CRC64NVME stored on S3!).
    let legacy_data = b"legacy single-part object without crc64nvme".to_vec();
    let legacy_md5 = hex::encode(Md5::digest(&legacy_data));
    // 2. Seed a modern multipart S3 object with full-object CRC64NVME (and `-2` multipart ETag).
    let mp_data: Vec<u8> = (0..(96 * 1024))
        .map(|i| ((i * 29 + 3) & 0xFF) as u8)
        .collect();
    let mp_crc64_b64 = crc64_nvme_base64(&mp_data);
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "legacy.txt".to_string(),
            MockS3Object {
                data: legacy_data.clone(),
                etag: format!("\"{legacy_md5}\""),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        g.objects.insert(
            "multipart.bin".to_string(),
            MockS3Object {
                data: mp_data.clone(),
                etag: "\"0123456789abcdef0123456789abcdef-2\"".to_string(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                metadata: HashMap::new(),
                checksum_crc64nvme: Some(mp_crc64_b64),
                checksum_crc32c: None,
            },
        );
    }

    // Write matching bytes locally (with different local mtime -> forces `--checksum` path!).
    let tmp = tempfile::TempDir::new().unwrap();
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(dst_dir.join("legacy.txt"), &legacy_data).unwrap();
    std::fs::write(dst_dir.join("multipart.bin"), &mp_data).unwrap();

    let local = Arc::new(LocalBackend::new("local", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();

    // S3 -> Local `--checksum` sync must fast-skip BOTH files (legacy via MD5, multipart via CRC64NVME)
    // with ZERO GetObject downloads!
    let idx = Arc::new(SqliteSyncIndex::open_temp(&state_dir, "s3-to-local-ck").unwrap());
    let engine = TransferEngine::new(
        aws.clone(),
        local.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut cfg = EngineConfig::new("s3-to-local-ck", JobMode::Sync, "s3:sync-ck", "local");
    cfg.checksum = true;
    let rep = engine.run(&cfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(
        rep.files_transferred, 0,
        "both legacy MD5 and multipart CRC64NVME objects must fast-skip"
    );
    assert_eq!(rep.files_skipped, 2);
    assert_eq!(
        srv.state.lock().unwrap().counters.get_object_calls,
        0,
        "S3 -> Local --checksum fast-skip must issue 0 GetObject downloads"
    );
}

#[tokio::test]
async fn s3_c3_streaming_checksum_headers_zero_spool_upload_and_download_verification() {
    use base64::Engine as _;
    use rship_backends::s3::{crc32c, crc32c_base64};
    use rship_core::types::Checksum;

    let srv = MockS3Server::start("c3-bkt", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    // Default `S3Config::send_upload_checksum` is now `true`.
    let default_cfg = S3Config::new(
        "aws-default",
        S3Provider::Aws,
        "c3-bkt",
        S3Credentials::new("ak", "sk"),
    );
    assert!(
        default_cfg.send_upload_checksum,
        "S3Config::send_upload_checksum must default to true (C3)"
    );

    // (a) Known source checksum headers sent directly WITHOUT spooling:
    //     1. MinIO with known CRC32C -> sends `x-amz-checksum-crc32c`
    //     2. R2 with known CRC32C -> omits `x-amz-checksum-crc32c` on single-part `PutObject`
    //     3. Generic S3 with known MD5 -> sends `Content-MD5`
    let spool_tmp = tempfile::TempDir::new().unwrap();
    let spool_dir = spool_tmp.path().join("s3-spool");

    let mut minio_cfg = srv.config(S3Provider::Minio, "c3-bkt", "us-east-1");
    minio_cfg.payload_signing = PayloadSigningMode::Unsigned;
    minio_cfg.spool_dir = Some(spool_dir.clone());
    let minio = S3Backend::new(minio_cfg, transport.clone(), None).unwrap();

    let mut r2_cfg = srv.config(S3Provider::R2, "c3-bkt", "us-east-1");
    r2_cfg.payload_signing = PayloadSigningMode::Unsigned;
    r2_cfg.spool_dir = Some(spool_dir.clone());
    let r2 = S3Backend::new(r2_cfg, transport.clone(), None).unwrap();

    let known_payload = b"s3 known crc32c header payload".to_vec();
    let known_crc32c_hex = format!("{:08x}", crc32c(&known_payload));
    let known_crc32c_b64 = crc32c_base64(&known_payload);
    let known_init = UploadInit {
        op_id: "op-c3-known-crc32c".into(),
        dst_path: RelPath::parse("c3/known-crc32c.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: known_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: known_payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Crc32c,
            hex: known_crc32c_hex.clone(),
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let kp = known_payload.clone();
    minio
        .put_single_shot(
            &known_init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(kp)) })),
        )
        .await
        .unwrap();
    assert_eq!(
        srv.state
            .lock()
            .unwrap()
            .counters
            .seen_crc32c_headers
            .last()
            .map(String::as_str),
        Some(known_crc32c_b64.as_str()),
        "known CRC32C in init.checksums must be sent as x-amz-checksum-crc32c on MinIO"
    );
    assert!(
        !spool_dir.exists(),
        "known-checksum UNSIGNED-PAYLOAD upload must not create spool dir"
    );

    // Verify R2 omits `x-amz-checksum-crc32c` on single-part PutObject (`supports_single_part_crc32c == false`).
    let crc32c_count_before_r2 = srv.state.lock().unwrap().counters.seen_crc32c_headers.len();
    let r2_single_init = UploadInit {
        op_id: "op-c3-r2-no-single-crc32c".into(),
        dst_path: RelPath::parse("c3/r2-single-crc32c.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: known_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: known_payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Crc32c,
            hex: known_crc32c_hex,
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let kp_r2 = known_payload.clone();
    r2.put_single_shot(
        &r2_single_init,
        Box::pin(futures::stream::once(async move { Ok(Bytes::from(kp_r2)) })),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.state.lock().unwrap().counters.seen_crc32c_headers.len(),
        crc32c_count_before_r2,
        "R2 single-part PutObject must NOT send x-amz-checksum-crc32c"
    );

    let mut gen_cfg = srv.config(S3Provider::Generic, "c3-bkt", "us-east-1");
    gen_cfg.payload_signing = PayloadSigningMode::Unsigned;
    gen_cfg.spool_dir = Some(spool_dir.clone());
    let generic = S3Backend::new(gen_cfg, transport.clone(), None).unwrap();

    let md5_payload = b"s3 known md5 header payload".to_vec();
    let md5_raw = Md5::digest(&md5_payload);
    let md5_hex = hex::encode(md5_raw);
    let md5_b64 = base64::engine::general_purpose::STANDARD.encode(md5_raw);
    let md5_init = UploadInit {
        op_id: "op-c3-known-md5".into(),
        dst_path: RelPath::parse("c3/known-md5.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: md5_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: md5_payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Md5,
            hex: md5_hex,
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let mp = md5_payload.clone();
    generic
        .put_single_shot(
            &md5_init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(mp)) })),
        )
        .await
        .unwrap();
    assert_eq!(
        srv.state
            .lock()
            .unwrap()
            .counters
            .seen_content_md5_headers
            .last()
            .map(String::as_str),
        Some(md5_b64.as_str()),
        "known MD5 in init.checksums must be sent as Content-MD5"
    );

    // (e) Streaming upload > 4 MiB with UNSIGNED-PAYLOAD computes CRC32C + MD5 on-the-fly
    //     WITHOUT spooling to temp disk files, and catches server-side CRC32C mismatch!
    srv.state.lock().unwrap().faults.always_return_crc32c_on_put = true;
    let big_len = 5 * 1024 * 1024 + 37;
    let big_payload: Vec<u8> = (0..big_len).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();
    let big_init = UploadInit {
        op_id: "op-c3-stream-5m".into(),
        dst_path: RelPath::parse("c3/stream-5m.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big_len as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: big_len as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let chunks_ok: Vec<rship_core::Result<Bytes>> = big_payload
        .chunks(256 * 1024)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let big_entry = r2
        .put_single_shot(&big_init, Box::pin(futures::stream::iter(chunks_ok)))
        .await
        .expect("5 MiB UNSIGNED-PAYLOAD streaming upload must succeed without disk spool");
    assert_eq!(big_entry.size, big_len as u64);
    assert_eq!(
        srv.state
            .lock()
            .unwrap()
            .counters
            .seen_payload_hashes
            .last()
            .map(String::as_str),
        Some(UNSIGNED_PAYLOAD)
    );
    assert!(
        !spool_dir.exists(),
        "UNSIGNED-PAYLOAD 5 MiB upload must NEVER spool to disk (spool_dir must not be created)"
    );

    // Same 5 MiB streaming path: inject corrupted server CRC32C -> rejected with retryable Network error!
    srv.state.lock().unwrap().faults.corrupt_put_crc32c_once = true;
    let bad_crc_init = UploadInit {
        op_id: "op-c3-stream-5m-bad".into(),
        dst_path: RelPath::parse("c3/stream-5m-bad.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big_len as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: big_len as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let chunks_bad: Vec<rship_core::Result<Bytes>> = big_payload
        .chunks(256 * 1024)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let crc_err = r2
        .put_single_shot(&bad_crc_init, Box::pin(futures::stream::iter(chunks_bad)))
        .await
        .expect_err("mismatched server x-amz-checksum-crc32c must fail streaming upload");
    assert_eq!(crc_err.kind, ErrorKind::Integrity);
    assert!(crc_err.is_integrity());
    assert!(
        crc_err.message().contains("checksum mismatch"),
        "unexpected error: {crc_err}"
    );
    assert!(
        !spool_dir.exists(),
        "UNSIGNED-PAYLOAD streaming upload must not create spool files"
    );
    srv.state.lock().unwrap().faults.always_return_crc32c_on_put = false;

    // (b) Single-shot PutObject & multipart UploadPart reject corrupted server ETag MD5!
    srv.state.lock().unwrap().faults.corrupt_put_etag_once = true;
    let bad_etag_init = UploadInit {
        op_id: "op-c3-bad-etag".into(),
        dst_path: RelPath::parse("c3/bad-etag.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 11,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 11,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let etag_err = generic
        .put_single_shot(
            &bad_etag_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello world"))
            })),
        )
        .await
        .expect_err("corrupted PutObject ETag must fail upload");
    assert_eq!(etag_err.kind, ErrorKind::Integrity);
    assert!(etag_err.is_integrity());
    assert!(etag_err.message().contains("checksum mismatch"));

    let mut mp_cfg = srv.config(S3Provider::Generic, "c3-bkt", "us-east-1");
    mp_cfg.payload_signing = PayloadSigningMode::Unsigned;
    mp_cfg.min_part_bytes_override = Some(64 * 1024);
    mp_cfg.default_chunk_size = Some(64 * 1024);
    let mp_backend = S3Backend::new(mp_cfg, transport, None).unwrap();
    let mp_path = RelPath::parse("c3/bad-part.bin").unwrap();
    let mp_init = UploadInit {
        op_id: "op-c3-bad-part".into(),
        dst_path: mp_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 64 * 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let opened = mp_backend.begin_upload(&mp_init).await.unwrap();
    let mp_op = OperationRecord {
        op_id: mp_init.op_id.clone(),
        session_key: "sk-c3-mp".into(),
        job_id: "j-c3-mp".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: mp_backend.endpoint_identity(),
        src_raw_path: mp_path.as_str().into(),
        dst_raw_path: mp_path.as_str().into(),
        dst_nfc_path: mp_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: 64 * 1024,
            mtime_ns: mp_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened.session_token),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    srv.state
        .lock()
        .unwrap()
        .faults
        .corrupt_upload_part_etag_once = true;
    let part_err = mp_backend
        .upload_chunk(
            &mp_op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                64 * 1024,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0x5Au8; 64 * 1024]))
                })),
            ),
        )
        .await
        .expect_err("corrupted UploadPart ETag must fail chunk upload");
    assert_eq!(part_err.kind, ErrorKind::Integrity);
    assert!(part_err.is_integrity());
    assert!(part_err.message().contains("checksum mismatch"));

    // (c) Full-object download detects corrupted payload bytes against server checksum header!
    let dl_reader = match r2
        .open_read(
            &BackendPath::from_rel(RelPath::parse("c3/known-crc32c.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    srv.state.lock().unwrap().faults.corrupt_get_body_once = true;
    let mut bad_dl = dl_reader
        .open_range(ByteRange {
            offset: 0,
            len: known_payload.len() as u64,
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
    let dl_err = dl_err.expect("corrupted full-object S3 download must return checksum error");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(dl_err.message().contains("checksum mismatch"));

    // (d) Sub-range downloads (`offset > 0` and `len < total_len`) do NOT falsely fail
    //     against full-object ETag / CRC32C checksums!
    for range in [
        ByteRange { offset: 0, len: 10 },
        ByteRange { offset: 5, len: 12 },
        ByteRange {
            offset: known_payload.len() as u64 - 8,
            len: 8,
        },
    ] {
        let mut s = dl_reader.open_range(range).await.unwrap();
        let mut out = Vec::new();
        while let Some(item) = s.next().await {
            out.extend_from_slice(&item.unwrap());
        }
        assert_eq!(
            out,
            known_payload[range.offset as usize..(range.offset + range.len) as usize]
        );
    }
}
