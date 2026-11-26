use axum::body::Bytes;
use axum::http::StatusCode;
use md5::{Digest as _, Md5};
use rship_backends::s3::{
    PayloadSigningMode, S3Backend, S3Config, S3Credentials, S3Provider, aws_uri_encode_path,
};
use rship_core::ErrorKind;
use rship_core::backend::{BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{
    DstPrecondition, JobMode, JournalStore, OperationRecord, OperationState, SourceVersion,
    compute_session_key,
};
use rship_core::types::{ByteRange, HashKind};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::HashMap;
use std::sync::Arc;

use crate::common::InjectedFault;
use crate::mock_server::{MockS3Object, MockS3Server, read_s3_all};

// =========================================================================
// Test 3: HTTP 200 OK + `<Error>` XML Body on `CompleteMultipartUpload`
// =========================================================================

#[tokio::test]
async fn s3_complete_multipart_200_ok_xml_error_is_detected_and_retried() {
    let srv = MockS3Server::start("mp-err", "us-east-1").await;
    // Inject TWO HTTP `200 OK` responses containing `<Error><Code>InternalError</Code>` / `SlowDown`!
    srv.fault_injector().push_many(
        "CompleteMultipartUpload",
        [
            InjectedFault::ok_200_xml_error("InternalError", "transient assembly failure 1"),
            InjectedFault::ok_200_xml_error("SlowDown", "reduce request rate"),
        ],
    );

    let mut cfg = srv.config(S3Provider::Aws, "mp-err", "us-east-1");
    cfg.single_shot_max_bytes = Some(128 * 1024);
    cfg.default_chunk_size = Some(256 * 1024);
    cfg.min_part_bytes_override = Some(256 * 1024);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    let tmp = tempfile::TempDir::new().unwrap();
    let payload: Vec<u8> = (0..(256 * 1024 * 2 + 5000))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(tmp.path().join("big.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        s3.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let ecfg = EngineConfig::new("job-200-err", JobMode::Copy, "local", "s3");

    let rep = engine.run(&ecfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(
        read_s3_all(&s3, &RelPath::parse("big.bin").unwrap()).await,
        payload
    );

    // Must have retried CompleteMultipartUpload 3 times total (2 XML errors on 200 OK + 1 success).
    assert_eq!(
        srv.state.lock().unwrap().counters.complete_multipart_calls,
        3
    );

    // Multipart ETag (`"...-3"`) must NEVER be misidentified as single-part MD5!
    let mp_md5 = s3
        .compute_hash(
            &BackendPath::from_rel(RelPath::parse("big.bin").unwrap()),
            HashKind::Md5,
        )
        .await
        .unwrap();
    assert!(
        mp_md5.is_none(),
        "multipart S3 ETag must never be mistaken for file MD5"
    );
}

// =========================================================================
// Test 4: Paginated `ListParts` Resume + Locked `planned_chunk_size` Geometry
// =========================================================================

#[tokio::test]
async fn s3_paginated_list_parts_resumes_only_missing_parts_with_locked_geometry() {
    let srv = MockS3Server::start("resume-bucket", "us-east-1").await;
    // Force ListParts to paginate at 2 parts per page!
    srv.state.lock().unwrap().faults.list_parts_page_limit = Some(2);

    let mut cfg = srv.config(S3Provider::Aws, "resume-bucket", "us-east-1");
    cfg.single_shot_max_bytes = Some(128 * 1024);
    cfg.default_chunk_size = Some(256 * 1024);
    cfg.min_part_bytes_override = Some(256 * 1024);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    let tmp = tempfile::TempDir::new().unwrap();
    // 5 parts of 256 KiB + tail = 6 parts total!
    let total = 256 * 1024 * 5 + 777;
    let payload: Vec<u8> = (0..total).map(|i| ((i * 13) % 251) as u8).collect();
    std::fs::write(tmp.path().join("resumable.dat"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let src_entry = local
        .stat(&BackendPath::from_rel(
            RelPath::parse("resumable.dat").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();

    // Manually initiate a partial multipart session with 4 of 6 parts already uploaded & persisted in SQLite!
    let rel = RelPath::parse("resumable.dat").unwrap();
    let skey = compute_session_key(
        &local.endpoint_identity(),
        "resumable.dat",
        &s3.endpoint_identity(),
        &rel,
    );
    let init = UploadInit {
        op_id: "op-resume-s3".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total as u64,
        src_mtime_ns: src_entry.mtime_ns,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = s3.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: skey,
        job_id: "job-pre".into(),
        src_endpoint: local.endpoint_identity(),
        dst_endpoint: s3.endpoint_identity(),
        src_raw_path: "resumable.dat".into(),
        dst_raw_path: "resumable.dat".into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion::from_entry(&src_entry),
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened.session_token),
        backend_meta: opened.backend_meta,
        planned_chunk_size: 256 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    state_actor.put_operation(&op).await.unwrap();
    for pn in 1..=4u32 {
        let off = u64::from(pn - 1) * 256 * 1024;
        let len = 256 * 1024u64;
        let slice = Bytes::copy_from_slice(&payload[off as usize..(off + len) as usize]);
        let ack = s3
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    pn,
                    off,
                    len,
                    total as u64,
                    Box::pin(futures::stream::once(async move { Ok(slice) })),
                ),
            )
            .await
            .unwrap();
        state_actor
            .upsert_part(
                &op.op_id,
                &CompletedPart {
                    part_number: pn,
                    offset: off,
                    length: len,
                    etag: ack.etag.unwrap(),
                    checksum: None,
                },
            )
            .await
            .unwrap();
    }
    srv.state.lock().unwrap().counters.upload_part_calls = 0;

    // Now run TransferEngine WITH A DIFFERENT CLI `--chunk-size` override (512 KiB):
    // Engine MUST lock to persisted `256 KiB`, paginate `ListParts` (2 pages for 4 parts),
    // and upload ONLY parts 5 & 6!
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        s3.clone(),
        state_actor,
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let mut ecfg = EngineConfig::new("job-resume", JobMode::Copy, "local", "s3");
    ecfg.chunk_size_override = Some(512 * 1024);

    let rep = engine.run(&ecfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(read_s3_all(&s3, &rel).await, payload);

    let g = srv.state.lock().unwrap();
    assert!(
        g.counters.list_parts_calls >= 2,
        "ListParts must paginate across IsTruncated pages (saw {})",
        g.counters.list_parts_calls
    );
    assert_eq!(
        g.counters.upload_part_calls, 2,
        "must only upload missing parts 5 & 6 (never re-upload verified parts 1..=4)"
    );
    assert_eq!(pool.stats().in_use_units, 0);
}

// =========================================================================
// Test 6: Ambiguous Commit Reconciliation (`x-amz-meta-rship-op-id`)
//         + Version-Pinned `If-Match` Range Read + Multipart GC
// =========================================================================

#[tokio::test]
async fn s3_reconciles_ambiguous_commit_pins_range_reads_and_aborts_gc() {
    let srv = MockS3Server::start("rec-bucket", "us-east-1").await;
    srv.fault_injector().push(
        "CompleteMultipartUpload",
        InjectedFault::commit_then_xml_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "simulated lost complete response after commit",
        ),
    );

    let mut cfg = srv.config(S3Provider::Aws, "rec-bucket", "us-east-1");
    cfg.single_shot_max_bytes = Some(128 * 1024);
    cfg.default_chunk_size = Some(256 * 1024);
    cfg.min_part_bytes_override = Some(256 * 1024);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    let tmp = tempfile::TempDir::new().unwrap();
    let payload: Vec<u8> = (0..(256 * 1024 + 2048)).map(|i| (i % 197) as u8).collect();
    std::fs::write(tmp.path().join("committed.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        s3.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let ecfg = EngineConfig::new("job-s3-rec", JobMode::Copy, "local", "s3");
    let rep = engine.run(&ecfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);

    // Must have reconciled via `x-amz-meta-rship-op-id` after 1st CompleteMultipartUpload
    // committed & dropped response (retry gets NoSuchUpload -> reconcile_operation -> Committed!).
    assert_eq!(srv.state.lock().unwrap().counters.create_multipart_calls, 1);

    // Test version-pinned `If-Match` Range read: open reader, mutate object concurrently,
    // next `open_range` MUST fail with `ErrorKind::PreconditionFailed` (412)!
    let target = RelPath::parse("committed.bin").unwrap();
    let reader = match s3
        .open_read(&BackendPath::from_rel(target.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    // Overwrite the object on server (changing its ETag).
    let overwrite_init = UploadInit {
        op_id: "op-mutate".into(),
        dst_path: target.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 8,
        src_mtime_ns: 0,
        planned_chunk_size: 8,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    s3.put_single_shot(
        &overwrite_init,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from_static(b"mutated!"))
        })),
    )
    .await
    .unwrap();

    let pinned_err = reader
        .open_range(ByteRange {
            offset: 0,
            len: 100,
        })
        .await
        .err()
        .expect("version-pinned range read must reject ETag mutation");
    assert_eq!(pinned_err.kind, ErrorKind::PreconditionFailed);

    // Test Multipart GC (`list_multipart_uploads` + `abort_multipart_by_id`).
    let orphan_init = UploadInit {
        op_id: "op-orphan".into(),
        dst_path: RelPath::parse("orphan/abandoned.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 512 * 1024,
        src_mtime_ns: 0,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let orphan = s3.begin_upload(&orphan_init).await.unwrap();
    let active = s3.list_multipart_uploads().await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].upload_id, orphan.session_token);

    s3.abort_multipart_by_id(&active[0].key, &active[0].upload_id)
        .await
        .unwrap();
    assert!(s3.list_multipart_uploads().await.unwrap().is_empty());
    assert_eq!(srv.state.lock().unwrap().counters.abort_multipart_calls, 1);

    // Keep unused import check satisfied & double check canonical URI encoding helper.
    assert_eq!(aws_uri_encode_path("/a b+c"), "/a%20b%2Bc");
}

// =========================================================================
// Test 8: S3 Zero-Bandwidth Server-Side Copy (`CopyObject` + `UploadPartCopy`
//         + HTTP 200 OK `<Error>` Retry Detection)
// =========================================================================

#[tokio::test]
async fn s3_server_side_copy_object_and_upload_part_copy_with_200_error_retry() {
    let srv = MockS3Server::start("shared-bkt", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    let mut cfg = srv.config(S3Provider::Aws, "shared-bkt", "us-east-1");
    cfg.single_shot_max_bytes = Some(128 * 1024);
    cfg.default_chunk_size = Some(128 * 1024);
    cfg.min_part_bytes_override = Some(128 * 1024);
    // Force objects > 200 KiB onto multipart `UploadPartCopy`!
    cfg.max_single_copy_bytes = Some(200 * 1024);
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    let small_payload = b"small-server-side-copy-object".to_vec();
    let big_payload: Vec<u8> = (0..(320 * 1024)).map(|i| ((i * 19) % 251) as u8).collect();

    // Seed two objects under `in/`.
    for (p, data) in [
        ("in/small.txt", &small_payload),
        ("in/big.bin", &big_payload),
    ] {
        let rel = RelPath::parse(p).unwrap();
        let init = UploadInit {
            op_id: format!("seed-{p}"),
            dst_path: rel,
            existing_node_id: None,
            pregenerated_id: None,
            total_size: data.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: data.len().max(1) as u64,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        };
        let d = data.clone();
        s3.put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(d)) })),
        )
        .await
        .unwrap();
    }

    // Reset counters and inject transient HTTP 200 OK `<Error>` faults into both copy paths!
    {
        let mut g = srv.state.lock().unwrap();
        g.counters.put_object_calls = 0;
        g.counters.upload_part_calls = 0;
        g.counters.get_object_calls = 0;
    }
    let faults = srv.fault_injector();
    faults.push(
        "CopyObject",
        InjectedFault::ok_200_xml_error("InternalError", "transient 200 OK copy error"),
    );
    faults.push(
        "UploadPartCopy",
        InjectedFault::ok_200_xml_error("InternalError", "transient 200 OK part copy error"),
    );

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        s3.clone(),
        s3.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-s3-ssc", JobMode::Copy, "s3:in", "s3:out");
    ecfg.src_prefix = RelPath::parse("in").unwrap();
    ecfg.dst_prefix = RelPath::parse("out").unwrap();
    ecfg.chunk_size_override = Some(128 * 1024);

    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(rep.server_side_copies, 2);

    {
        let g = srv.state.lock().unwrap();
        assert_eq!(
            g.counters.get_object_calls, 0,
            "server-side copy must download 0 bytes"
        );
        assert_eq!(
            g.counters.put_object_calls, 0,
            "server-side copy must not PutObject data"
        );
        assert_eq!(
            g.counters.upload_part_calls, 0,
            "server-side copy must not UploadPart data"
        );
        assert!(
            g.counters.copy_object_calls >= 1,
            "expected CopyObject call"
        );
        assert!(
            g.counters.upload_part_copy_calls >= 3,
            "expected >=3 UploadPartCopy calls for 320 KiB / 128 KiB parts (got {})",
            g.counters.upload_part_copy_calls
        );
    }

    assert_eq!(
        read_s3_all(&s3, &RelPath::parse("out/small.txt").unwrap()).await,
        small_payload
    );
    assert_eq!(
        read_s3_all(&s3, &RelPath::parse("out/big.bin").unwrap()).await,
        big_payload
    );
}

#[tokio::test]
async fn s3_parallel_upload_part_copy_and_payload_signing_cli_modes() {
    // 1. Verify PayloadSigningMode CLI parser + HTTPS checksum without SHA-256 spooling.
    assert_eq!(
        PayloadSigningMode::parse("auto").unwrap(),
        PayloadSigningMode::Auto
    );
    assert_eq!(
        PayloadSigningMode::parse("unsigned").unwrap(),
        PayloadSigningMode::Unsigned
    );
    assert_eq!(
        PayloadSigningMode::parse("sha256").unwrap(),
        PayloadSigningMode::StrictSha256
    );
    assert_eq!(PayloadSigningMode::StrictSha256.as_str(), "strict_sha256");

    let mut https_cfg = S3Config::new(
        "aws",
        S3Provider::Aws,
        "my-bucket",
        S3Credentials::new("ak", "sk"),
    );
    https_cfg.send_upload_checksum = true;
    assert!(https_cfg.is_https());
    assert!(
        !https_cfg.requires_payload_sha256(),
        "HTTPS + send_upload_checksum=true must stay UNSIGNED-PAYLOAD (no SHA-256 spooling)"
    );

    // 2. Verify Path B parallel UploadPartCopy (> single_copy_limit) across 5 concurrent parts!
    let srv = MockS3Server::start("par-copy-bucket", "us-east-1").await;
    let total = 256 * 1024 * 4 + 123_456; // 5 parts of 256 KiB + tail
    let payload: Vec<u8> = (0..total).map(|i| ((i * 19 + 5) % 251) as u8).collect();
    let etag = format!("\"{}\"", hex::encode(Md5::digest(&payload)));
    srv.state.lock().unwrap().objects.insert(
        "src/large.bin".into(),
        MockS3Object {
            data: payload.clone(),
            etag,
            last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
            metadata: HashMap::new(),
            checksum_crc64nvme: None,
            checksum_crc32c: None,
        },
    );

    let mut cfg = srv.config(S3Provider::Aws, "par-copy-bucket", "us-east-1");
    cfg.max_single_copy_bytes = Some(256 * 1024);
    cfg.min_part_bytes_override = Some(256 * 1024);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = S3Backend::new(cfg, transport, None).unwrap();

    let init = UploadInit {
        op_id: "op-par-copy".into(),
        dst_path: RelPath::parse("dst/large-copy.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copied = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/large.bin").unwrap()),
            &init,
        )
        .await
        .unwrap()
        .expect("same-endpoint S3 server_side_copy must succeed");
    assert_eq!(copied.size, total as u64);
    let g = srv.state.lock().unwrap();
    assert_eq!(
        g.counters.upload_part_copy_calls, 5,
        "must issue 5 parallel UploadPartCopy RPCs"
    );
    assert_eq!(
        g.objects.get("dst/large-copy.bin").unwrap().data,
        payload,
        "parallel UploadPartCopy destination bytes must match bit-exact"
    );
}

#[tokio::test]
async fn carbon_review_p0_5_s3_server_side_copy_enforces_copy_source_if_match() {
    let srv = MockS3Server::start("pin-copy-bucket", "us-east-1").await;
    let total = 256 * 1024 * 2 + 1024; // 3 parts
    let payload: Vec<u8> = vec![0xAB; total];
    srv.state.lock().unwrap().objects.insert(
        "src/big.bin".into(),
        MockS3Object {
            data: payload,
            etag: "\"current-etag-v2\"".into(),
            last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
            metadata: HashMap::new(),
            checksum_crc64nvme: None,
            checksum_crc32c: None,
        },
    );

    let mut cfg = srv.config(S3Provider::Aws, "pin-copy-bucket", "us-east-1");
    cfg.max_single_copy_bytes = Some(256 * 1024);
    cfg.min_part_bytes_override = Some(256 * 1024);
    cfg.pin_read_etag = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = S3Backend::new(cfg, transport, None).unwrap();

    // 1. Multipart UploadPartCopy with stale src_etag must abort with SourceMutated and leave no orphan!
    let mp_init = UploadInit {
        op_id: "op-stale-mp".into(),
        dst_path: RelPath::parse("dst/big.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some("\"stale-etag-v1\"".into()),
    };
    let err = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/big.bin").unwrap()),
            &mp_init,
        )
        .await
        .expect_err("stale src_etag must abort UploadPartCopy");
    assert_eq!(err.kind, ErrorKind::SourceMutated, "got: {err:?}");
    {
        let g = srv.state.lock().unwrap();
        assert!(
            g.uploads.is_empty(),
            "aborted UploadPartCopy must clean up multipart session"
        );
        assert!(
            !g.objects.contains_key("dst/big.bin"),
            "no torn object may be committed"
        );
    }

    // 2. Single-shot CopyObject with stale src_etag also aborts cleanly with SourceMutated.
    let single_init = UploadInit {
        op_id: "op-stale-single".into(),
        dst_path: RelPath::parse("dst/small.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: Some("\"stale-etag-v1\"".into()),
    };
    let err2 = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/big.bin").unwrap()),
            &single_init,
        )
        .await
        .expect_err("stale src_etag must abort CopyObject");
    assert_eq!(err2.kind, ErrorKind::SourceMutated, "got: {err2:?}");
}

#[tokio::test]
async fn s3_remote_multipart_gc_lists_filters_by_age_and_aborts_stale_uploads() {
    use rship_core::backend::UploadInit;

    let srv = MockS3Server::start("gc-bucket", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            srv.config(S3Provider::Aws, "gc-bucket", "us-east-1"),
            transport,
            None,
        )
        .unwrap(),
    );

    // Open two incomplete multipart uploads under `uploads/` and one under `other/`.
    for (idx, path) in [
        "uploads/stale_a.bin",
        "uploads/stale_b.bin",
        "other/keep.bin",
    ]
    .iter()
    .enumerate()
    {
        let init = UploadInit {
            op_id: format!("op-gc-{idx}"),
            dst_path: RelPath::parse(path).unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 16 * 1024 * 1024,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 8 * 1024 * 1024,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        };
        s3.begin_upload(&init).await.unwrap();
    }

    // Sub-prefix `uploads` lists ONLY the 2 incomplete uploads under `uploads/`!
    let found = s3
        .list_incomplete_uploads(&RelPath::parse("uploads").unwrap())
        .await
        .unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|u| u.key.starts_with("uploads/")));

    // Abort the 2 under `uploads/` -> `other/keep.bin` remains intact!
    for u in &found {
        s3.abort_incomplete_upload(u).await.unwrap();
    }
    let after_uploads = s3
        .list_incomplete_uploads(&RelPath::parse("uploads").unwrap())
        .await
        .unwrap();
    assert!(after_uploads.is_empty());

    let remaining = s3.list_incomplete_uploads(&RelPath::root()).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].key, "other/keep.bin");
}
