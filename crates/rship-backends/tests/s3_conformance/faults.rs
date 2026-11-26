use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::s3::{S3Backend, S3Provider};
use rship_core::backend::{
    BackendPath, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend, UploadInit,
};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{
    DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_core::types::ByteRange;
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{
    HttpTransport, LimiterScope, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::common::{self, FaultInjector, FaultRates, InjectedFault};
use crate::mock_server::{MockS3Object, MockS3Server, read_s3_all};

// =========================================================================
// Shared Fault Harness Tests: 429/503 Retry-After, Mid-Body Reset,
// Commit-then-503 Reconciliation, and Seeded PRNG Determinism
// =========================================================================

#[tokio::test]
async fn s3_scripted_429_and_503_slow_down_with_retry_after_recovery() {
    let srv = MockS3Server::start("throttle-bkt", "us-east-1").await;
    {
        let mut g = srv.state.lock().unwrap();
        for (k, data) in [
            ("a.txt", b"alpha".as_slice()),
            ("b.txt", b"beta".as_slice()),
        ] {
            g.objects.insert(
                k.to_string(),
                MockS3Object {
                    data: data.to_vec(),
                    etag: format!("\"{}\"", hex::encode(Md5::digest(data))),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
    }

    let faults = srv.fault_injector();
    faults.push_many(
        "ListObjectsV2",
        [
            InjectedFault::too_many_requests(Some("1")),
            InjectedFault::s3_slow_down(Some("1")),
        ],
    );

    let mut cfg = srv.config(S3Provider::Aws, "throttle-bkt", "us-east-1");
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(60);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    // 1. Control-plane ListObjectsV2 recovers across scripted 429 + 503 SlowDown while honoring
    //    `Retry-After` (clamped by `max_retry_delay = 60ms` => 2 sleeps >= 90ms).
    let started = std::time::Instant::now();
    let mut ls = s3.list_stream(&RelPath::root(), true).await.unwrap();
    let mut keys = Vec::new();
    while let Some(item) = ls.next().await {
        keys.push(item.unwrap().nfc_path.as_str().to_string());
    }
    let elapsed = started.elapsed();
    keys.sort();
    assert_eq!(keys, vec!["a.txt", "b.txt"]);
    assert!(
        elapsed >= Duration::from_millis(90),
        "expected Retry-After backoff (~120ms across 2 throttles), elapsed={elapsed:?}"
    );
    assert_eq!(srv.state.lock().unwrap().counters.list_objects_calls, 3);
    assert_eq!(faults.op_requests("ListObjectsV2"), 3);
    assert_eq!(faults.op_faults("ListObjectsV2"), 2);
    assert_eq!(faults.remaining_scripted("ListObjectsV2"), 0);

    // 2. Data-plane PutObject propagates parsed `Retry-After` on 503 SlowDown.
    faults.push("PutObject", InjectedFault::s3_slow_down(Some("2")));
    let probe_init = UploadInit {
        op_id: "op-throttle-probe".into(),
        dst_path: RelPath::parse("throttled/probe.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err = s3
        .put_single_shot(
            &probe_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .expect_err("503 SlowDown must fail PutObject with RateLimited");
    assert_eq!(err.kind, ErrorKind::RateLimited);
    assert_eq!(err.retry, RetryClass::Throttled);
    assert_eq!(err.retry_after, Some(Duration::from_secs(2)));

    // 3. End-to-end TransferEngine recovers from scripted 429 + 503 SlowDown on PutObject.
    faults.push_many(
        "PutObject",
        [
            InjectedFault::too_many_requests(Some("0")),
            InjectedFault::s3_slow_down(Some("0")),
        ],
    );
    let tmp = tempfile::TempDir::new().unwrap();
    let payload = b"recovered-after-429-and-503-slowdown".to_vec();
    std::fs::write(tmp.path().join("recovered.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        s3.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-throttle", JobMode::Copy, "local", "s3");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(
        read_s3_all(&s3, &RelPath::parse("recovered.bin").unwrap()).await,
        payload
    );
    assert_eq!(faults.op_faults("PutObject"), 3);
    assert_eq!(faults.op_requests("PutObject"), 4);
    assert_eq!(faults.total_remaining_scripted(), 0);
}

#[tokio::test]
async fn s3_mid_body_reset_on_get_object_download_errors_and_recovers() {
    let srv = MockS3Server::start("reset-bkt", "us-east-1").await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 37 + 11) & 0xFF) as u8)
        .collect();
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "download/reset.bin".to_string(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&payload))),
                data: payload.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let cfg = srv.config(S3Provider::Aws, "reset-bkt", "us-east-1");
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());
    let faults = srv.fault_injector();

    // 1. Direct GetObject stream receives the prefix bytes and then surfaces a retryable
    //    `ErrorKind::Network` error (never silently truncating!).
    let prefix = Bytes::from_static(b"partial-get-prefix-bytes");
    faults.push("GetObject", InjectedFault::mid_body_reset(prefix.clone()));

    let rel = RelPath::parse("download/reset.bin").unwrap();
    let reader = match s3
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut stream = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut received = Vec::new();
    let mut stream_err = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => received.extend_from_slice(&chunk),
            Err(e) => {
                stream_err = Some(e);
                break;
            }
        }
    }
    assert_eq!(
        received,
        prefix.as_ref(),
        "mid-body reset must stream prefix bytes before aborting"
    );
    let err = stream_err.expect("mid-body reset must terminate download stream with error");
    assert_eq!(err.kind, ErrorKind::Network, "got: {err:?}");
    assert_eq!(err.retry, RetryClass::Retryable, "got: {err:?}");

    // Subsequent open_range (fault queue drained) succeeds bit-exact.
    assert_eq!(read_s3_all(&s3, &rel).await, payload);

    // 2. End-to-end S3 -> Local TransferEngine download recovers from mid-body reset cleanly
    //    without corrupting the destination file.
    faults.push(
        "GetObject",
        InjectedFault::mid_body_reset(Bytes::from_static(b"corrupt-partial-bytes")),
    );
    let tmp = tempfile::TempDir::new().unwrap();
    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        s3.clone(),
        local,
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-get-reset", JobMode::Copy, "s3", "local");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.is_success(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert_eq!(
        std::fs::read(tmp.path().join("download/reset.bin")).unwrap(),
        payload
    );
    assert_eq!(faults.op_faults("GetObject"), 2);
    assert_eq!(srv.state.lock().unwrap().counters.get_object_calls, 4);
}

#[tokio::test]
async fn s3_commit_then_503_complete_multipart_reconciles_via_op_id() {
    let srv = MockS3Server::start("reconcile-503-bkt", "us-east-1").await;
    let mut cfg = srv.config(S3Provider::Aws, "reconcile-503-bkt", "us-east-1");
    cfg.single_shot_max_bytes = Some(64 * 1024);
    cfg.default_chunk_size = Some(64 * 1024);
    cfg.min_part_bytes_override = Some(64 * 1024);
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(20);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = S3Backend::new(cfg, transport, None).unwrap();
    let faults = srv.fault_injector();

    let p1: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 241) as u8).collect();
    let p2: Vec<u8> = (0..(12 * 1024))
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect();
    let mut full = Vec::with_capacity(p1.len() + p2.len());
    full.extend_from_slice(&p1);
    full.extend_from_slice(&p2);

    // 1. Commit-then-503 on CompleteMultipartUpload: attempt 1 commits object + deletes session
    //    then returns 503; retry hits NoSuchUpload -> finish_upload reconciles via HeadObject
    //    matching `x-amz-meta-rship-op-id` and returns Committed entry!
    faults.push(
        "CompleteMultipartUpload",
        InjectedFault::commit_then_xml_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "lost 503 response after commit",
        )
        .with_retry_after("0"),
    );

    let rel = RelPath::parse("mp/commit-then-503.bin").unwrap();
    let init = UploadInit {
        op_id: "op-commit-503-reconcile".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: full.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = s3.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key("local://src", "a", &s3.endpoint_identity(), &rel),
        job_id: "job-commit-503".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: s3.endpoint_identity(),
        src_raw_path: rel.as_str().into(),
        dst_raw_path: rel.as_str().into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: full.len() as u64,
            mtime_ns: init.src_mtime_ns,
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
    let ack1 = s3
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
    let p2_c = p2.clone();
    let ack2 = s3
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
    let parts = vec![
        CompletedPart {
            part_number: 1,
            offset: 0,
            length: p1.len() as u64,
            etag: ack1.etag.unwrap(),
            checksum: ack1.checksum,
        },
        CompletedPart {
            part_number: 2,
            offset: p1.len() as u64,
            length: p2.len() as u64,
            etag: ack2.etag.unwrap(),
            checksum: ack2.checksum,
        },
    ];

    let committed = s3.finish_upload(&op, &parts).await.unwrap();
    assert_eq!(committed.size, full.len() as u64);
    assert_eq!(read_s3_all(&s3, &rel).await, full);
    {
        let g = srv.state.lock().unwrap();
        assert_eq!(g.counters.complete_multipart_calls, 2);
        assert!(g.counters.head_object_calls >= 1);
        let stored = g.objects.get("mp/commit-then-503.bin").unwrap();
        assert_eq!(
            stored
                .metadata
                .get("x-amz-meta-rship-op-id")
                .map(String::as_str),
            Some("op-commit-503-reconcile")
        );
    }
    assert_eq!(faults.op_faults("CompleteMultipartUpload"), 1);

    // 2. Negative guard: if a different writer replaced the object with another op-id,
    //    `reconcile_operation` MUST report `Ambiguous` instead of falsely claiming `Committed`.
    srv.state
        .lock()
        .unwrap()
        .objects
        .get_mut("mp/commit-then-503.bin")
        .unwrap()
        .metadata
        .insert(
            "x-amz-meta-rship-op-id".to_string(),
            "op-some-other-writer".to_string(),
        );
    let mismatch = s3.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(mismatch, ReconcileOutcome::Ambiguous(_)),
        "mismatched x-amz-meta-rship-op-id must return Ambiguous, got: {mismatch:?}"
    );

    // 3. SlowFinalize on CreateMultipartUpload + CommitThenReset on CompleteMultipartUpload:
    //    delay is honored without blocking, commit succeeds before reset, and reconcile confirms it.
    faults.push(
        "CreateMultipartUpload",
        InjectedFault::slow_finalize(Duration::from_millis(25)),
    );
    faults.push(
        "CompleteMultipartUpload",
        InjectedFault::commit_then_reset(),
    );

    let rel2 = RelPath::parse("mp/commit-then-reset.bin").unwrap();
    let init2 = UploadInit {
        op_id: "op-commit-reset-reconcile".into(),
        dst_path: rel2.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: full.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let begin_started = std::time::Instant::now();
    let opened2 = s3.begin_upload(&init2).await.unwrap();
    assert!(
        begin_started.elapsed() >= Duration::from_millis(20),
        "SlowFinalize must delay CreateMultipartUpload before completing"
    );
    let op2 = OperationRecord {
        op_id: init2.op_id.clone(),
        session_key: compute_session_key("local://src", "b", &s3.endpoint_identity(), &rel2),
        job_id: "job-commit-reset".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: s3.endpoint_identity(),
        src_raw_path: rel2.as_str().into(),
        dst_raw_path: rel2.as_str().into(),
        dst_nfc_path: rel2.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: full.len() as u64,
            mtime_ns: init2.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: opened2.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened2.session_token),
        backend_meta: opened2.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let a1 = s3
        .upload_chunk(
            &op2,
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
    let a2 = s3
        .upload_chunk(
            &op2,
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
    let parts2 = vec![
        CompletedPart {
            part_number: 1,
            offset: 0,
            length: 64 * 1024,
            etag: a1.etag.unwrap(),
            checksum: a1.checksum,
        },
        CompletedPart {
            part_number: 2,
            offset: 64 * 1024,
            length: 12 * 1024,
            etag: a2.etag.unwrap(),
            checksum: a2.checksum,
        },
    ];
    let committed2 = s3
        .finish_upload(&op2, &parts2)
        .await
        .expect("CommitThenReset must retry and self-reconcile via x-amz-meta-rship-op-id");
    assert_eq!(committed2.size, full.len() as u64);

    match s3.reconcile_operation(&op2).await.unwrap() {
        ReconcileOutcome::Committed(entry) => {
            assert_eq!(entry.size, full.len() as u64);
        }
        other => panic!("expected Committed after CommitThenReset, got {other:?}"),
    }
    assert_eq!(read_s3_all(&s3, &rel2).await, full);
}

#[test]
fn fault_injector_seeded_determinism_and_precedence() {
    let seed = 0x5EED_CAFE_1234_5678u64;
    let rates = FaultRates::none()
        .with_throttle_429(0.12)
        .with_service_unavailable_503(0.12)
        .with_ok_200_xml_error(0.10)
        .with_mid_body_reset(0.10)
        .with_commit_then_503(0.10)
        .with_commit_then_reset(0.10)
        .with_slow_finalize(0.10, Duration::from_millis(15));

    let ops = [
        "GetObject",
        "PutObject",
        "UploadPart",
        "CompleteMultipartUpload",
        "ListObjectsV2",
    ];

    let inj_a = FaultInjector::seeded(seed, rates.clone());
    let inj_b = FaultInjector::seeded(seed, rates.clone());
    let inj_c = FaultInjector::seeded(seed ^ 0xDEAD_BEEF, rates.clone());

    assert_eq!(inj_a.seed(), Some(seed));
    assert_eq!(inj_b.seed(), Some(seed));

    let seq_a: Vec<Option<InjectedFault>> = (0..250)
        .map(|i| inj_a.next_fault(ops[i % ops.len()]))
        .collect();
    let seq_b: Vec<Option<InjectedFault>> = (0..250)
        .map(|i| inj_b.next_fault(ops[i % ops.len()]))
        .collect();
    let seq_c: Vec<Option<InjectedFault>> = (0..250)
        .map(|i| inj_c.next_fault(ops[i % ops.len()]))
        .collect();

    assert_eq!(
        seq_a, seq_b,
        "identical seeds must produce bit-identical fault sequences"
    );
    assert_eq!(
        inj_a.telemetry(),
        inj_b.telemetry(),
        "identical seeds must produce identical telemetry"
    );
    assert_eq!(inj_a.requests_seen(), 250);
    assert_ne!(
        seq_a, seq_c,
        "distinct seeds must produce distinct fault sequences"
    );

    // Every configured fault variant must trigger at least once in 250 draws.
    assert!(seq_a.iter().any(|f| matches!(
        f,
        Some(InjectedFault::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            ..
        })
    )));
    assert!(seq_a.iter().any(|f| matches!(
        f,
        Some(InjectedFault::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    )));
    assert!(
        seq_a
            .iter()
            .any(|f| matches!(f, Some(InjectedFault::Ok200XmlError { .. })))
    );
    assert!(
        seq_a
            .iter()
            .any(|f| matches!(f, Some(InjectedFault::MidBodyReset { .. })))
    );
    assert!(
        seq_a
            .iter()
            .any(|f| matches!(f, Some(InjectedFault::CommitThenError { .. })))
    );
    assert!(
        seq_a
            .iter()
            .any(|f| matches!(f, Some(InjectedFault::CommitThenReset)))
    );
    assert!(
        seq_a
            .iter()
            .any(|f| matches!(f, Some(InjectedFault::SlowFinalize { .. })))
    );

    // Precedence: exact op queue > "*" wildcard queue > seeded PRNG (filtered by `with_seeded_ops`).
    let scoped = FaultInjector::seeded(42, FaultRates::none().with_throttle_429(1.0))
        .with_seeded_ops(["GetObject"]);
    let exact_fault = InjectedFault::ok_200_xml_error("SlowDown", "exact");
    let wildcard_fault = InjectedFault::service_unavailable(Some("1"));
    scoped.push("GetObject", exact_fault.clone());
    scoped.push(common::WILDCARD_OP, wildcard_fault.clone());

    assert_eq!(scoped.next_fault("GetObject"), Some(exact_fault));
    assert_eq!(scoped.next_fault("HeadObject"), Some(wildcard_fault));
    // Wildcard now drained: HeadObject is outside `with_seeded_ops`, GetObject is inside.
    assert_eq!(scoped.next_fault("HeadObject"), None);
    assert!(matches!(
        scoped.next_fault("GetObject"),
        Some(InjectedFault::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            ..
        })
    ));
    assert_eq!(scoped.requests_seen(), 4);
    assert_eq!(scoped.faults_injected(), 3);
    assert_eq!(scoped.op_requests("HeadObject"), 2);
    assert_eq!(scoped.op_faults("HeadObject"), 1);
    assert_eq!(scoped.op_requests("GetObject"), 2);
    assert_eq!(scoped.op_faults("GetObject"), 2);
}

// =========================================================================
// C4 & Shared Retry Policy Tests: CopyObject 412 Reconciliation,
// Long Copy/Complete Timeouts, Retries-Exhausted & Quota Refund,
// and Plane-Isolated Limiters
// =========================================================================

#[tokio::test]
async fn s3_c4_copy_object_if_none_match_commit_then_503_and_412_reconciliation() {
    let srv = MockS3Server::start("c4-copy-bkt", "us-east-1").await;
    let payload = b"server-side-copy-reconcile-payload-bytes".to_vec();
    let src_etag = format!("\"{}\"", hex::encode(Md5::digest(&payload)));
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "src/doc.bin".to_string(),
            MockS3Object {
                data: payload.clone(),
                etag: src_etag.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let mut cfg = srv.config(S3Provider::Aws, "c4-copy-bkt", "us-east-1");
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(20);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = S3Backend::new(cfg, transport, None).unwrap();
    let faults = srv.fault_injector();
    let src_path = BackendPath::from_rel(RelPath::parse("src/doc.bin").unwrap());

    // 1. CopyObject with DstPrecondition::Absent (`If-None-Match: *`) commits on attempt 1
    //    then returns 503 (`CommitThenError`). Must reconcile via `x-amz-meta-rship-op-id`
    //    and return `Ok(Some(entry))` instead of failing with 412!
    faults.push(
        "CopyObject",
        InjectedFault::commit_then_xml_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "lost 503 response after CopyObject commit",
        )
        .with_retry_after("0"),
    );
    let dst_503 = RelPath::parse("dst/commit-then-503.bin").unwrap();
    let init_503 = UploadInit {
        op_id: "op-c4-copy-503".into(),
        dst_path: dst_503.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some(src_etag.clone()),
    };
    let entry_503 = s3
        .server_side_copy(&s3.endpoint_identity(), &src_path, &init_503)
        .await
        .expect("CopyObject commit-then-503 must reconcile via op_id")
        .expect("CopyObject must return Some(Entry)");
    assert_eq!(entry_503.size, payload.len() as u64);
    assert_eq!(entry_503.etag.as_deref(), Some(src_etag.as_str()));
    assert_eq!(read_s3_all(&s3, &dst_503).await, payload);
    assert!(
        srv.state.lock().unwrap().counters.head_object_calls >= 1,
        "reconciliation must HEAD the destination key"
    );

    // 2. Direct HTTP 412 PreconditionFailed when destination already holds the SAME op_id
    //    (e.g. second attempt after a dropped response or resumed op): reconciles cleanly!
    let entry_412 = s3
        .server_side_copy(&s3.endpoint_identity(), &src_path, &init_503)
        .await
        .expect("direct 412 with matching x-amz-meta-rship-op-id must reconcile")
        .expect("CopyObject 412 reconciliation must return Some(Entry)");
    assert_eq!(entry_412.size, payload.len() as u64);
    assert_eq!(entry_412.etag.as_deref(), Some(src_etag.as_str()));

    // 3. CommitThenReset on CopyObject with DstPrecondition::Absent also reconciles!
    faults.push("CopyObject", InjectedFault::commit_then_reset());
    let dst_reset = RelPath::parse("dst/commit-then-reset.bin").unwrap();
    let init_reset = UploadInit {
        op_id: "op-c4-copy-reset".into(),
        dst_path: dst_reset.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some(src_etag.clone()),
    };
    let entry_reset = s3
        .server_side_copy(&s3.endpoint_identity(), &src_path, &init_reset)
        .await
        .expect("CopyObject commit-then-reset must reconcile via op_id")
        .expect("CopyObject reset reconciliation must return Some(Entry)");
    assert_eq!(entry_reset.size, payload.len() as u64);
    assert_eq!(read_s3_all(&s3, &dst_reset).await, payload);

    // 4. Pre-commit transient 503 (destination still absent) retries and succeeds!
    let calls_before = srv.state.lock().unwrap().counters.copy_object_calls;
    faults.push("CopyObject", InjectedFault::s3_slow_down(Some("0")));
    let dst_retry = RelPath::parse("dst/pre-commit-503.bin").unwrap();
    let init_retry = UploadInit {
        op_id: "op-c4-copy-retry".into(),
        dst_path: dst_retry.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some(src_etag.clone()),
    };
    let entry_retry = s3
        .server_side_copy(&s3.endpoint_identity(), &src_path, &init_retry)
        .await
        .expect("pre-commit 503 must retry CopyObject when destination is absent")
        .expect("retried CopyObject must return Some(Entry)");
    assert_eq!(entry_retry.size, payload.len() as u64);
    assert_eq!(
        srv.state.lock().unwrap().counters.copy_object_calls - calls_before,
        2,
        "pre-commit 503 must retry CopyObject once"
    );

    // 5. 412 when DstPrecondition::Absent AND src_etag is stale while destination does NOT exist
    //    must classify as SourceMutated (came from x-amz-copy-source-if-match, not dst)!
    let init_stale_src = UploadInit {
        op_id: "op-c4-stale-src".into(),
        dst_path: RelPath::parse("dst/never-created.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some("\"stale-src-etag\"".into()),
    };
    let stale_err = s3
        .server_side_copy(&s3.endpoint_identity(), &src_path, &init_stale_src)
        .await
        .expect_err("stale src_etag with absent destination must fail with SourceMutated");
    assert_eq!(
        stale_err.kind,
        ErrorKind::SourceMutated,
        "got: {stale_err:?}"
    );
}

#[tokio::test]
async fn s3_c4_copy_object_if_none_match_different_op_id_returns_precondition_failed() {
    let srv = MockS3Server::start("c4-diff-op-bkt", "us-east-1").await;
    let src_data = b"source-payload-bytes".to_vec();
    let existing_data = b"other-writer-object!".to_vec();
    let src_etag = format!("\"{}\"", hex::encode(Md5::digest(&src_data)));
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "src/a.bin".to_string(),
            MockS3Object {
                data: src_data.clone(),
                etag: src_etag.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        let mut other_meta = HashMap::new();
        other_meta.insert(
            "x-amz-meta-rship-op-id".to_string(),
            "op-some-other-writer".to_string(),
        );
        g.objects.insert(
            "dst/conflict.bin".to_string(),
            MockS3Object {
                data: existing_data.clone(),
                etag: format!("\"{}\"", hex::encode(Md5::digest(&existing_data))),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: other_meta,
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let cfg = srv.config(S3Provider::Aws, "c4-diff-op-bkt", "us-east-1");
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3 = S3Backend::new(cfg, transport, None).unwrap();

    let init = UploadInit {
        op_id: "op-my-copy-123".into(),
        dst_path: RelPath::parse("dst/conflict.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: src_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: src_data.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: Some(src_etag),
    };
    let err = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/a.bin").unwrap()),
            &init,
        )
        .await
        .expect_err("CopyObject onto existing object with different op_id must fail");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed, "got: {err:?}");
    // Existing destination object must remain untouched.
    assert_eq!(
        read_s3_all(&s3, &RelPath::parse("dst/conflict.bin").unwrap()).await,
        existing_data
    );
}

#[tokio::test]
async fn s3_c4_slow_copy_object_upload_part_copy_and_complete_multipart_use_long_control_timeout() {
    let srv = MockS3Server::start("c4-slow-bkt", "us-east-1").await;
    let small_payload = b"slow-single-copy-payload".to_vec();
    let big_payload: Vec<u8> = (0..(160 * 1024))
        .map(|i| ((i * 13 + 7) % 251) as u8)
        .collect();
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "src/small.bin".to_string(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&small_payload))),
                data: small_payload.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        g.objects.insert(
            "src/big.bin".to_string(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&big_payload))),
                data: big_payload.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    // Short control_timeout (120ms) vs generous long_control_timeout (5s);
    // SlowFinalize(300ms) exceeds control_timeout but stays well below long_control_timeout.
    let tcfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(120))
        .with_long_control_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();

    let mut cfg = srv.config(S3Provider::Aws, "c4-slow-bkt", "us-east-1");
    cfg.max_retries = 0;
    cfg.min_part_bytes_override = Some(64 * 1024);
    cfg.max_single_copy_bytes = Some(100 * 1024);
    let s3 = S3Backend::new(cfg, transport, None).unwrap();
    let faults = srv.fault_injector();

    // 1. Sanity check: normal control-plane ListObjectsV2 DOES trip the short 120ms control_timeout.
    faults.push(
        "ListObjectsV2",
        InjectedFault::slow_finalize(Duration::from_millis(300)),
    );
    let list_err = s3
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect_err("normal ListObjectsV2 must honor short control_timeout");
    assert_eq!(list_err.kind, ErrorKind::Timeout, "got: {list_err:?}");

    // 2. Slow single-shot CopyObject (300ms > 120ms control_timeout) MUST succeed via long_control_timeout!
    faults.push(
        "CopyObject",
        InjectedFault::slow_finalize(Duration::from_millis(300)),
    );
    let small_dst = RelPath::parse("dst/slow-small.bin").unwrap();
    let small_init = UploadInit {
        op_id: "op-slow-copy-single".into(),
        dst_path: small_dst.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: small_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: small_payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copied_small = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/small.bin").unwrap()),
            &small_init,
        )
        .await
        .expect("slow CopyObject must use long_control_timeout and succeed")
        .expect("CopyObject must return Some(Entry)");
    assert_eq!(copied_small.size, small_payload.len() as u64);
    assert_eq!(read_s3_all(&s3, &small_dst).await, small_payload);

    // 3. Slow UploadPartCopy + slow CompleteMultipartUpload (both 300ms > 120ms control_timeout)
    //    MUST both succeed via long_control_timeout!
    faults.push(
        "UploadPartCopy",
        InjectedFault::slow_finalize(Duration::from_millis(300)),
    );
    faults.push(
        "CompleteMultipartUpload",
        InjectedFault::slow_finalize(Duration::from_millis(300)),
    );
    let big_dst = RelPath::parse("dst/slow-big.bin").unwrap();
    let big_init = UploadInit {
        op_id: "op-slow-copy-mp".into(),
        dst_path: big_dst.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copied_big = s3
        .server_side_copy(
            &s3.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/big.bin").unwrap()),
            &big_init,
        )
        .await
        .expect("slow UploadPartCopy + CompleteMultipartUpload must use long_control_timeout")
        .expect("multipart copy must return Some(Entry)");
    assert_eq!(copied_big.size, big_payload.len() as u64);
    assert_eq!(read_s3_all(&s3, &big_dst).await, big_payload);
}

#[tokio::test]
async fn s3_control_plane_retries_exhausted_and_exact_quota_refund() {
    let srv = MockS3Server::start("quota-bkt", "us-east-1").await;
    let quota = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let tcfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota));
    let transport = HttpTransport::new(tcfg).unwrap();

    let mut cfg = srv.config(S3Provider::Aws, "quota-bkt", "us-east-1");
    cfg.max_retries = 2;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(15);
    let base_scope = LimiterScope::new(
        &cfg.remote_name,
        format!("{}:{}", cfg.credentials.access_key_id, cfg.bucket),
    );
    let s3 = S3Backend::new(cfg, transport.clone(), None).unwrap();
    let ctrl_limiter = transport.control_limiter_for(base_scope);
    let faults = srv.fault_injector();

    // 1. Recovery after a single transient 503 refunds the exact 5-token retry cost.
    faults.push("ListObjectsV2", InjectedFault::s3_slow_down(Some("0")));
    let page = s3
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect("single transient 503 must recover");
    assert!(page.entries.is_empty());
    assert_eq!(srv.state.lock().unwrap().counters.list_objects_calls, 2);
    let snap_recovered = ctrl_limiter.snapshot();
    assert_eq!(
        snap_recovered.retry_quota_available, snap_recovered.retry_quota_max,
        "successful recovery must refund exact 5-token retry cost back to max_tokens"
    );

    // 2. Exhausting max_retries=2 returns `retries_exhausted() == true` (preventing 5x5
    //    outer engine retry stacking) and keeps the 2 * 5 = 10 spent quota tokens deducted.
    let calls_before = srv.state.lock().unwrap().counters.list_objects_calls;
    faults.push_many(
        "ListObjectsV2",
        (0..10).map(|_| InjectedFault::s3_slow_down(Some("0"))),
    );
    let err = s3
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect_err("persistent 503 must exhaust retries");
    assert_eq!(err.kind, ErrorKind::RateLimited, "got: {err:?}");
    assert_eq!(err.retry, RetryClass::Throttled, "got: {err:?}");
    assert!(
        err.retries_exhausted(),
        "exhausted control-plane retries must set retries_exhausted=true"
    );
    assert!(
        !err.is_retryable(),
        "retries_exhausted error must suppress outer is_retryable()"
    );
    assert_eq!(
        srv.state.lock().unwrap().counters.list_objects_calls - calls_before,
        3,
        "must issue exactly 1 initial + max_retries (2) attempts"
    );
    let snap_exhausted = ctrl_limiter.snapshot();
    assert_eq!(
        snap_exhausted.retry_quota_available, 90,
        "2 failed retries must deduct 10 tokens (100 -> 90)"
    );
}

#[tokio::test]
async fn s3_control_and_data_plane_limiters_are_isolated() {
    let srv = MockS3Server::start("plane-iso-bkt", "us-east-1").await;
    let payload = b"plane-isolation-payload".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "existing.bin".to_string(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&payload))),
                data: payload.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let cfg = srv.config(S3Provider::Aws, "plane-iso-bkt", "us-east-1");
    let base_scope = LimiterScope::new(
        &cfg.remote_name,
        format!("{}:{}", cfg.credentials.access_key_id, cfg.bucket),
    );
    let s3 = S3Backend::new(cfg, transport.clone(), None).unwrap();
    let ctrl_limiter = transport.control_limiter_for(base_scope.clone());
    let data_limiter = transport.data_limiter_for(base_scope);
    let faults = srv.fault_injector();

    assert!(!ctrl_limiter.snapshot().cubic_enabled);
    assert!(!data_limiter.snapshot().cubic_enabled);

    // 1. Throttle data-plane `PutObject` with 503 SlowDown -> activates CUBIC ONLY on data plane!
    faults.push("PutObject", InjectedFault::s3_slow_down(Some("0")));
    let put_init = UploadInit {
        op_id: "op-plane-put".into(),
        dst_path: RelPath::parse("throttled.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 5,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err = s3
        .put_single_shot(
            &put_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .expect_err("503 SlowDown must fail PutObject");
    assert_eq!(err.kind, ErrorKind::RateLimited);
    assert!(
        data_limiter.snapshot().cubic_enabled,
        "data-plane 503 SlowDown must activate CUBIC on data_limiter"
    );
    assert!(
        !ctrl_limiter.snapshot().cubic_enabled,
        "data-plane throttling must NOT activate CUBIC on control_limiter"
    );

    // 2. Control-plane listing succeeds without CUBIC engagement on control_limiter.
    let page = s3
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .expect("control-plane ListObjectsV2 must succeed cleanly");
    assert_eq!(page.entries.len(), 1);
    assert!(!ctrl_limiter.snapshot().cubic_enabled);

    // 3. Also verify data-plane `GetObject` throttling stays isolated to data_limiter.
    let reader = match s3
        .open_read(
            &BackendPath::from_rel(RelPath::parse("existing.bin").unwrap()),
            None,
        )
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    faults.push("GetObject", InjectedFault::s3_slow_down(Some("0")));
    let get_err = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .err()
        .expect("503 SlowDown must fail GetObject");
    assert_eq!(get_err.kind, ErrorKind::RateLimited);
    assert!(data_limiter.snapshot().cubic_enabled);
    assert!(
        !ctrl_limiter.snapshot().cubic_enabled,
        "GetObject data-plane throttling must NOT affect control_limiter"
    );
}
