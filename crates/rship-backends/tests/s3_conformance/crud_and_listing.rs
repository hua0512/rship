use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::s3::{PayloadSigningMode, S3Backend, S3Config, S3Credentials, S3Provider};
use rship_core::ErrorKind;
use rship_core::backend::{BackendPath, StorageBackend, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::clock::{Clock, SystemClock, VirtualClock};
use rship_core::conformance::run_backend_conformance;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::ByteStream;
use rship_core::state::{DstPrecondition, JobMode, JournalStore};
use rship_core::types::EntryKind;
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::mock_server::{MockS3Object, MockS3Server, read_s3_all};

// =========================================================================
// Test 1: Full Universal Conformance Suite (both Strict HTTP SHA-256 & Unsigned)
// =========================================================================

#[tokio::test]
async fn s3_passes_full_universal_conformance_suite() {
    let srv = MockS3Server::start("conf-bucket", "us-east-1").await;
    let mut cfg = srv.config(S3Provider::Aws, "conf-bucket", "us-east-1");
    cfg.min_part_bytes_override = Some(256 * 1024);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    let backend: Arc<dyn StorageBackend> =
        Arc::new(S3Backend::new(cfg, transport, Some(clock.clone())).unwrap());

    run_backend_conformance(backend, clock).await;
    assert!(
        srv.state.lock().unwrap().counters.verified_sigv4_count > 10,
        "every S3 conformance call must pass real SigV4 verification"
    );
}

// =========================================================================
// Test 2: URL-Encoded Keys (` `, `+`, `%20`, `&`, `#`, UTF-8) + SigV4
// =========================================================================

#[tokio::test]
async fn s3_handles_url_encoded_special_keys_and_sigv4_end_to_end() {
    let srv = MockS3Server::start("enc-bucket", "us-east-1").await;
    let cfg = srv.config(S3Provider::Aws, "enc-bucket", "us-east-1");
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend = S3Backend::new(cfg, transport, None).unwrap();

    let tricky = RelPath::parse("dir with spaces/a + b %20 & # café 中文.txt").unwrap();
    let data = b"url-encoded key integrity verified".to_vec();
    let init = UploadInit {
        op_id: "op-enc".into(),
        dst_path: tricky.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4096,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let dc = data.clone();
    let body: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(dc)) }));
    backend.put_single_shot(&init, body).await.unwrap();

    // Verify ListObjectsV2 decodes `+`, `%20`, `&`, `#`, UTF-8 back verbatim!
    let mut ls = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut listed = Vec::new();
    while let Some(item) = ls.next().await {
        listed.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(listed, vec![tricky.as_str()]);

    // Verify stat + GetObject + DeleteObject all pass SigV4 verification on tricky key!
    assert_eq!(read_s3_all(&backend, &tricky).await, data);
    backend
        .delete(&BackendPath::from_rel(tricky.clone()))
        .await
        .unwrap();
    assert!(
        backend
            .stat(&BackendPath::from_rel(tricky))
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Test 7: Parallel Prefix-Split Listing + Zero-RAM Cloud-to-Cloud S3 Relay
// =========================================================================

#[tokio::test]
async fn s3_prefix_split_listing_and_zero_ram_cloud_to_cloud_relay() {
    let srv_src = MockS3Server::start("src-bkt", "us-east-1").await;
    let srv_dst = MockS3Server::start("dst-bkt", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    let mut src_cfg = srv_src.config(S3Provider::Aws, "src-bkt", "us-east-1");
    src_cfg.list_prefix_concurrency = 4;
    let mut dst_cfg = srv_dst.config(S3Provider::R2, "dst-bkt", "us-east-1");
    dst_cfg.single_shot_max_bytes = Some(128 * 1024);
    dst_cfg.default_chunk_size = Some(256 * 1024);
    dst_cfg.min_part_bytes_override = Some(256 * 1024);

    let src_s3 = Arc::new(S3Backend::new(src_cfg, transport.clone(), None).unwrap());
    let dst_s3 = Arc::new(S3Backend::new(dst_cfg, transport, None).unwrap());

    // Seed multi-prefix objects including a multipart-sized file (> 256 KiB).
    let samples = [
        ("alpha/one.txt", vec![b'A'; 1024]),
        ("beta/sub/two.txt", vec![b'B'; 2048]),
        (
            "gamma/big.bin",
            (0..(256 * 1024 + 4096)).map(|i| (i % 251) as u8).collect(),
        ),
        ("root_item.txt", b"top-level".to_vec()),
    ];
    for (p, data) in &samples {
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
        let dc = data.clone();
        src_s3
            .put_single_shot(
                &init,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(dc)) })),
            )
            .await
            .unwrap();
    }

    // Cloud-to-cloud zero-RAM relay (`RemoteRangeReadable` -> `S3Backend` multipart/single-shot)!
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        src_s3,
        dst_s3.clone(),
        state_actor,
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let ecfg = EngineConfig::new("job-s3-relay", JobMode::Sync, "s3-src", "s3-dst");
    let rep = engine.run(&ecfg, idx).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 4);
    assert_eq!(pool.stats().in_use_units, 0);

    for (p, data) in &samples {
        let rel = RelPath::parse(p).unwrap();
        assert_eq!(&read_s3_all(&dst_s3, &rel).await, data);
    }
}

#[tokio::test]
async fn s3_bulk_delete_objects_1000_batch_and_partial_errors() {
    let srv = MockS3Server::start("bulk-del-bkt", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let cfg = srv.config(S3Provider::Aws, "bulk-del-bkt", "us-east-1");
    let s3 = Arc::new(S3Backend::new(cfg, transport, None).unwrap());

    // Seed 1,050 objects directly in the mock server + mark 1 key as AccessDenied.
    let mut paths = Vec::with_capacity(1050);
    {
        let mut g = srv.state.lock().unwrap();
        for i in 0..1050usize {
            let key = format!("bulk/obj-{i:04}.txt");
            g.objects.insert(
                key.clone(),
                MockS3Object {
                    data: b"x".to_vec(),
                    etag: "\"e\"".to_string(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".to_string(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
            paths.push(BackendPath::from_rel(RelPath::parse(&key).unwrap()));
        }
        g.faults
            .delete_batch_error_keys
            .insert("bulk/obj-0500.txt".to_string());
    }

    let failures = s3.delete_batch(&paths).await.unwrap();
    assert_eq!(failures.len(), 1, "expected exactly 1 denied key");
    assert_eq!(failures[0].0.nfc_path.as_str(), "bulk/obj-0500.txt");
    assert_eq!(failures[0].1.kind, ErrorKind::PermissionDenied);

    let g = srv.state.lock().unwrap();
    assert_eq!(
        g.counters.delete_objects_calls, 2,
        "1,050 objects must be deleted in exactly 2 DeleteObjects batches (1000 + 50)"
    );
    assert_eq!(
        g.objects.len(),
        1,
        "only the 1 AccessDenied key should remain"
    );
    assert!(g.objects.contains_key("bulk/obj-0500.txt"));
}

#[tokio::test]
async fn s3_list_is_truncated_without_token_errors_and_v1_next_marker_paginates() {
    // 1. Server returns `IsTruncated=true` with NO NextContinuationToken and NO NextMarker ->
    //    MUST return an explicit protocol error instead of silently truncating the listing!
    let bad_app = Router::new().fallback(|| async {
        (
            StatusCode::OK,
            [("content-type", "application/xml")],
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>partial.bin</Key>
    <LastModified>2024-05-23T19:48:40Z</LastModified>
    <ETag>"0123456789abcdef0123456789abcdef"</ETag>
    <Size>10</Size>
  </Contents>
</ListBucketResult>"#,
        )
    });
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener1, bad_app).await;
    });

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let creds = S3Credentials::new("AK", "SK");
    let mut cfg1 = S3Config::new("swift-bad", S3Provider::Generic, "bkt", creds.clone());
    cfg1.endpoint = Some(format!("http://{addr1}"));
    cfg1.force_path_style = Some(true);
    cfg1.list_prefix_concurrency = 1;
    let b1 = S3Backend::new(cfg1, transport.clone(), None).unwrap();

    let mut stream = b1.list_stream(&RelPath::root(), true).await.unwrap();
    let mut saw_err = false;
    while let Some(item) = stream.next().await {
        if let Err(e) = item {
            assert_eq!(e.kind, ErrorKind::Protocol);
            saw_err = true;
        }
    }
    assert!(
        saw_err,
        "IsTruncated=true without NextContinuationToken/NextMarker MUST emit an error"
    );

    // 2. Swift-like S3 gateway returning v1 `<NextMarker>` instead of `<NextContinuationToken>`:
    //    MUST paginate via `marker=` and yield ALL items without truncation!
    let v1_app = Router::new().fallback(|OriginalUri(uri): OriginalUri| async move {
        let q = uri.query().unwrap_or("");
        if q.contains("marker=a.bin") {
            (
                StatusCode::OK,
                [("content-type", "application/xml")],
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>b.bin</Key>
    <LastModified>2024-05-23T19:48:41Z</LastModified>
    <ETag>"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"</ETag>
    <Size>20</Size>
  </Contents>
</ListBucketResult>"#,
            )
        } else {
            (
                StatusCode::OK,
                [("content-type", "application/xml")],
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextMarker>a.bin</NextMarker>
  <Contents>
    <Key>a.bin</Key>
    <LastModified>2024-05-23T19:48:40Z</LastModified>
    <ETag>"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"</ETag>
    <Size>10</Size>
  </Contents>
</ListBucketResult>"#,
            )
        }
    });
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener2, v1_app).await;
    });

    let mut cfg2 = S3Config::new("swift-v1", S3Provider::Generic, "bkt", creds);
    cfg2.endpoint = Some(format!("http://{addr2}"));
    cfg2.force_path_style = Some(true);
    cfg2.list_prefix_concurrency = 1;
    let b2 = S3Backend::new(cfg2, transport, None).unwrap();

    let mut stream2 = b2.list_stream(&RelPath::root(), true).await.unwrap();
    let mut keys = Vec::new();
    while let Some(item) = stream2.next().await {
        keys.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(keys, vec!["a.bin", "b.bin"]);
}

#[tokio::test]
async fn s3_delete_known_file_skips_head_probe_and_copy_parses_last_modified() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let head_count = Arc::new(AtomicUsize::new(0));
    let delete_count = Arc::new(AtomicUsize::new(0));
    let hc = head_count.clone();
    let dc = delete_count.clone();

    let app = Router::new().fallback(move |method: Method, headers: HeaderMap| {
        let hc = hc.clone();
        let dc = dc.clone();
        async move {
            match method {
                Method::HEAD => {
                    hc.fetch_add(1, Ordering::Relaxed);
                    StatusCode::NOT_FOUND.into_response()
                }
                Method::DELETE => {
                    dc.fetch_add(1, Ordering::Relaxed);
                    StatusCode::NO_CONTENT.into_response()
                }
                Method::PUT if headers.contains_key("x-amz-copy-source") => (
                    StatusCode::OK,
                    [("content-type", "application/xml")],
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult>
  <LastModified>2025-01-15T12:34:56.000Z</LastModified>
  <ETag>"0123456789abcdef0123456789abcdef"</ETag>
</CopyObjectResult>"#,
                )
                    .into_response(),
                _ => StatusCode::OK.into_response(),
            }
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let mut cfg = S3Config::new(
        "s3test",
        S3Provider::Generic,
        "bkt",
        S3Credentials::new("AK", "SK"),
    );
    cfg.endpoint = Some(format!("http://{addr}"));
    cfg.force_path_style = Some(true);
    let backend = S3Backend::new(cfg, transport, None).unwrap();

    // 1. Deleting a known file (`BackendPath::from_entry`) issues 0 HEAD probes!
    let file_entry =
        rship_core::types::Entry::file(RelPath::parse("dir/file.bin").unwrap(), 100, 1);
    backend
        .delete(&BackendPath::from_entry(&file_entry))
        .await
        .unwrap();
    assert_eq!(head_count.load(Ordering::Relaxed), 0);
    assert_eq!(delete_count.load(Ordering::Relaxed), 1);

    // 2. Server-side `CopyObject` parses `<LastModified>` from XML instead of echoing `src_mtime_ns`!
    let init = UploadInit {
        op_id: "op-ssc".into(),
        dst_path: RelPath::parse("dir/copy.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 100,
        src_mtime_ns: 1_000_000_000, // deliberately old source mtime
        planned_chunk_size: 100,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_entry(&file_entry),
            &init,
        )
        .await
        .unwrap()
        .expect("expected SSC entry");
    let expected_ns = 1_736_944_496_000_000_000; // 2025-01-15T12:34:56.000Z
    assert_eq!(copied.mtime_ns, expected_ns);
}

#[tokio::test]
async fn s3_to_s3_auto_baseline_skips_head_object_and_baseline_writes_on_single_part() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TinyS3 {
        objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
        head_calls: AtomicUsize,
        put_calls: AtomicUsize,
    }

    async fn tiny_handler(
        State(st): State<Arc<TinyS3>>,
        method: Method,
        OriginalUri(uri): OriginalUri,
        body: Bytes,
    ) -> Response {
        let key = uri
            .path()
            .trim_start_matches('/')
            .split_once('/')
            .map(|(_, k)| k)
            .unwrap_or("");
        if method == Method::GET && uri.query().unwrap_or("").contains("list-type=2") {
            let g = st.objects.lock().unwrap();
            let mut xml = String::from(
                "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>",
            );
            for (k, (d, etag)) in g.iter() {
                xml.push_str(&format!(
                    "<Contents><Key>{k}</Key><LastModified>2024-05-23T19:48:40Z</LastModified><ETag>{etag}</ETag><Size>{}</Size></Contents>",
                    d.len()
                ));
            }
            xml.push_str("</ListBucketResult>");
            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
        }
        if method == Method::HEAD {
            st.head_calls.fetch_add(1, Ordering::Relaxed);
            return StatusCode::NOT_FOUND.into_response();
        }
        if method == Method::GET {
            let g = st.objects.lock().unwrap();
            if let Some((d, etag)) = g.get(key) {
                return Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("content-length", d.len().to_string())
                    .header("etag", etag.as_str())
                    .body(Body::from(d.clone()))
                    .unwrap();
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        if method == Method::PUT {
            st.put_calls.fetch_add(1, Ordering::Relaxed);
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&body)));
            st.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), (body.to_vec(), etag.clone()));
            return Response::builder()
                .status(StatusCode::OK)
                .header("etag", etag)
                .body(Body::empty())
                .unwrap();
        }
        StatusCode::METHOD_NOT_ALLOWED.into_response()
    }

    let src_st = Arc::new(TinyS3 {
        objects: Mutex::new(BTreeMap::new()),
        head_calls: AtomicUsize::new(0),
        put_calls: AtomicUsize::new(0),
    });
    let dst_st = Arc::new(TinyS3 {
        objects: Mutex::new(BTreeMap::new()),
        head_calls: AtomicUsize::new(0),
        put_calls: AtomicUsize::new(0),
    });
    for i in 0..10 {
        let data = format!("payload-{i}").into_bytes();
        let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
        src_st
            .objects
            .lock()
            .unwrap()
            .insert(format!("f{i}.bin"), (data, etag));
    }

    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a1 = l1.local_addr().unwrap().to_string();
    tokio::spawn(
        axum::serve(
            l1,
            Router::new()
                .fallback(tiny_handler)
                .with_state(src_st.clone()),
        )
        .into_future(),
    );
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a2 = l2.local_addr().unwrap().to_string();
    tokio::spawn(
        axum::serve(
            l2,
            Router::new()
                .fallback(tiny_handler)
                .with_state(dst_st.clone()),
        )
        .into_future(),
    );

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let creds = S3Credentials::new("AK", "SK");
    let mut scfg = S3Config::new("src", S3Provider::Generic, "b1", creds.clone());
    scfg.endpoint = Some(format!("http://{a1}"));
    scfg.force_path_style = Some(true);
    scfg.payload_signing = PayloadSigningMode::Unsigned;
    let mut dcfg = S3Config::new("dst", S3Provider::Generic, "b2", creds);
    dcfg.endpoint = Some(format!("http://{a2}"));
    dcfg.force_path_style = Some(true);
    dcfg.payload_signing = PayloadSigningMode::Unsigned;

    let src = Arc::new(S3Backend::new(scfg, transport.clone(), None).unwrap());
    let dst = Arc::new(S3Backend::new(dcfg, transport, None).unwrap());
    let tmp = tempfile::TempDir::new().unwrap();
    let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
    let engine = TransferEngine::new(
        src,
        dst,
        actor.clone(),
        BufferPool::with_default_slab(4 * 1024 * 1024).unwrap(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    // Pass 1: fresh S3 -> S3 copy with default BaselineMode::Auto.
    let cfg1 = EngineConfig::new("s3-auto-1", JobMode::Copy, "src:b1", "dst:b2");
    let r1 = engine
        .run(&cfg1, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);
    assert_eq!(r1.files_transferred, 10);
    assert_eq!(
        src_st.head_calls.load(Ordering::Relaxed),
        0,
        "version-pinned If-Match reads must emit 0 HeadObject RPCs on copy"
    );
    assert!(
        !tmp.path().join("baselines").exists(),
        "single-part S3 -> S3 under BaselineMode::Auto must write 0 baseline DB files"
    );

    // Pass 2: incremental re-run skips all 10 files via live MD5 ETag comparison (0 PUTs, 0 HEADs)!
    let cfg2 = EngineConfig::new("s3-auto-2", JobMode::Copy, "src:b1", "dst:b2");
    let r2 = engine
        .run(&cfg2, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(r2.is_success());
    assert_eq!(r2.files_transferred, 0);
    assert_eq!(r2.files_skipped, 10);
    assert_eq!(dst_st.put_calls.load(Ordering::Relaxed), 10);
    assert_eq!(src_st.head_calls.load(Ordering::Relaxed), 0);
    actor.shutdown().await.unwrap();
}

#[tokio::test]
async fn s3_two_gear_streaming_merge_join_small_large_post_filter_delete_and_resume() {
    use rship_core::filter::{FilterOptions, FilterSet};
    use rship_core::progress::{EventSink, TransferEvent, TransferProgress};
    use rship_core::state::JobStatus;
    use rship_state::LazyRunDir;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // --- Part 1: Gear 1 small run + wire ordering ("a-b" vs "a/f") + zero temp files ---
    let src_srv = MockS3Server::start("gear1-src", "us-east-1").await;
    let dst_srv = MockS3Server::start("gear1-dst", "us-east-1").await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    let mut scfg = src_srv.config(S3Provider::Generic, "gear1-src", "us-east-1");
    scfg.payload_signing = PayloadSigningMode::Unsigned;
    let mut dcfg = dst_srv.config(S3Provider::Generic, "gear1-dst", "us-east-1");
    dcfg.payload_signing = PayloadSigningMode::Unsigned;

    let src = Arc::new(S3Backend::new(scfg.clone(), transport.clone(), None).unwrap());
    let dst = Arc::new(S3Backend::new(dcfg.clone(), transport.clone(), None).unwrap());

    // Populate 20 small files including tricky hyphen-vs-slash wire ordering.
    {
        let mut g = src_srv.state.lock().unwrap();
        for key in ["a", "a-b", "a/inner.txt", "a0.txt", "b.txt"] {
            let data = format!("body-{key}").into_bytes();
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            g.objects.insert(
                key.to_string(),
                MockS3Object {
                    data,
                    etag,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
        for i in 0..15 {
            let key = format!("items/k-{i:03}.bin");
            let data = vec![(i as u8).wrapping_add(1); 128];
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            g.objects.insert(
                key,
                MockS3Object {
                    data,
                    etag,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let scratch_root = tmp.path().join("scratch");
    let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
    let pool = BufferPool::with_default_slab(8 * 1024 * 1024).unwrap();
    let progress = TransferProgress::new();
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    )
    .with_progress(progress.clone());

    let mut cfg1 = EngineConfig::new("g1-copy", JobMode::Copy, "src:gear1-src", "dst:gear1-dst");
    cfg1.scratch_dir = Some(Arc::new(LazyRunDir::new(scratch_root.clone(), "g1-copy")));
    let r1 = engine
        .run(&cfg1, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(r1.is_success(), "{:?}", r1.errors);
    assert_eq!(r1.files_transferred, 20);
    assert!(
        progress.snapshot(None).totals_discovered,
        "Gear 1 (<=1,000 objects) must mark totals_discovered=true immediately"
    );
    assert_eq!(
        src_srv.state.lock().unwrap().counters.list_objects_calls,
        1,
        "Gear 1 must issue exactly 1 LIST RPC on source"
    );
    assert_eq!(
        dst_srv.state.lock().unwrap().counters.list_objects_calls,
        1,
        "Gear 1 must issue exactly 1 LIST RPC on destination"
    );
    assert_eq!(src_srv.state.lock().unwrap().counters.head_object_calls, 0);
    assert!(
        !scratch_root.exists(),
        "Gear 1 small run must create 0 scratch temp files/dirs on disk"
    );

    // --- Part 2: Post-merge `--min-size` + `--delete` must NOT delete filtered existing src files ---
    {
        let mut sg = src_srv.state.lock().unwrap();
        sg.objects.clear();
        let small = b"tiny".to_vec();
        let big = vec![0xABu8; 256];
        sg.objects.insert(
            "small.bin".into(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&small))),
                data: small.clone(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        sg.objects.insert(
            "big.bin".into(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&big))),
                data: big,
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        let mut dg = dst_srv.state.lock().unwrap();
        dg.objects.clear();
        dg.objects.insert(
            "small.bin".into(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&small))),
                data: small,
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
        let orphan = vec![0xCDu8; 300];
        dg.objects.insert(
            "orphan.bin".into(),
            MockS3Object {
                etag: format!("\"{}\"", hex::encode(Md5::digest(&orphan))),
                data: orphan,
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let mut cfg_sync =
        EngineConfig::new("g1-sync", JobMode::Sync, "src:gear1-src", "dst:gear1-dst");
    cfg_sync.filter = FilterSet::from_options(&FilterOptions {
        min_size: Some(100),
        ..Default::default()
    })
    .unwrap();
    let r_sync = engine
        .run(
            &cfg_sync,
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_sync.is_success(), "{:?}", r_sync.errors);
    assert_eq!(r_sync.files_transferred, 1);
    assert_eq!(r_sync.items_deleted, 1);
    {
        let dg = dst_srv.state.lock().unwrap();
        assert!(dg.objects.contains_key("big.bin"));
        assert!(
            dg.objects.contains_key("small.bin"),
            "filtered source file existing on dst MUST NOT be deleted by --delete"
        );
        assert!(
            !dg.objects.contains_key("orphan.bin"),
            "true destination-only orphan MUST be deleted by --delete"
        );
    }

    // --- Part 3: `pin_read_etag = false` (Swift atomic single read): 0 HEAD on copy, HEAD on move ---
    let mut swift_scfg = scfg.clone();
    swift_scfg.pin_read_etag = false;
    let swift_src = Arc::new(S3Backend::new(swift_scfg, transport.clone(), None).unwrap());
    assert!(swift_src.capabilities().supports_atomic_single_read);
    assert!(!swift_src.capabilities().supports_version_pinned_read);

    src_srv.state.lock().unwrap().counters.head_object_calls = 0;
    dst_srv.state.lock().unwrap().objects.clear();
    let swift_copy_engine = TransferEngine::new(
        swift_src.clone(),
        dst.clone(),
        actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let r_sw_copy = swift_copy_engine
        .run(
            &EngineConfig::new("sw-copy", JobMode::Copy, "src:gear1-src", "dst:gear1-dst"),
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_sw_copy.is_success(), "{:?}", r_sw_copy.errors);
    assert_eq!(
        src_srv.state.lock().unwrap().counters.head_object_calls,
        0,
        "atomic single read with pin_read_etag=false must emit 0 HeadObject RPCs on copy"
    );

    // Now Move MUST still verify source via HeadObject before deleting source!
    dst_srv.state.lock().unwrap().objects.clear();
    let r_sw_move = swift_copy_engine
        .run(
            &EngineConfig::new("sw-move", JobMode::Move, "src:gear1-src", "dst:gear1-dst"),
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_sw_move.is_success(), "{:?}", r_sw_move.errors);
    assert!(
        src_srv.state.lock().unwrap().counters.head_object_calls >= 2,
        "move with pin_read_etag=false must still verify source with HeadObject before deleting"
    );
    assert!(src_srv.state.lock().unwrap().objects.is_empty());

    // --- Part 4: Ctrl+C (`Paused`) preserves progress counters + `resume_cursor` StartAfter ---
    {
        let mut sg = src_srv.state.lock().unwrap();
        sg.objects.clear();
        for i in 0..30 {
            let key = format!("res/file-{i:03}.bin");
            let data = vec![(i as u8).wrapping_add(3); 64];
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            sg.objects.insert(
                key,
                MockS3Object {
                    data,
                    etag,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
        dst_srv.state.lock().unwrap().objects.clear();
    }

    struct CancelAfterN {
        cancel: CancelFlag,
        done: AtomicUsize,
        limit: usize,
    }
    impl EventSink for CancelAfterN {
        fn on_event(&self, event: TransferEvent) {
            if matches!(event, TransferEvent::FileCompleted { .. })
                && self.done.fetch_add(1, Ordering::SeqCst) + 1 >= self.limit
            {
                self.cancel.cancel();
            }
        }
    }

    let cancel = CancelFlag::new();
    let sink = Arc::new(CancelAfterN {
        cancel: cancel.clone(),
        done: AtomicUsize::new(0),
        limit: 5,
    });
    let pause_engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        cancel,
    )
    .with_event_sink(sink);
    let mut cfg_pause =
        EngineConfig::new("job-pause", JobMode::Copy, "src:gear1-src", "dst:gear1-dst");
    cfg_pause.transfers = 1;
    let r_pause = pause_engine
        .run(
            &cfg_pause,
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_pause.cancelled);
    actor.flush().await.unwrap();

    let paused_job = actor.get_job("job-pause").await.unwrap().unwrap();
    assert_eq!(paused_job.status, JobStatus::Paused);
    assert!(
        paused_job.files_done >= 5,
        "Paused job must preserve real files_done (got {})",
        paused_job.files_done
    );
    assert!(
        paused_job.bytes_done >= 5 * 64,
        "Paused job must preserve real bytes_done (got {})",
        paused_job.bytes_done
    );
    let saved_cursor = paused_job
        .resume_cursor
        .clone()
        .expect("streaming paused job must persist safe watermark resume_cursor");

    // Resume from `saved_cursor`: StartAfter must be sent and all 30 objects must exist afterward!
    src_srv
        .state
        .lock()
        .unwrap()
        .counters
        .seen_start_afters
        .clear();
    let mut cfg_resume =
        EngineConfig::new("job-pause", JobMode::Copy, "src:gear1-src", "dst:gear1-dst");
    cfg_resume.transfers = 4;
    cfg_resume.resume_cursor = Some(saved_cursor.clone());
    let r_resumed = engine
        .run(
            &cfg_resume,
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_resumed.is_success(), "{:?}", r_resumed.errors);
    assert!(
        src_srv
            .state
            .lock()
            .unwrap()
            .counters
            .seen_start_afters
            .iter()
            .any(|sa| sa == &saved_cursor),
        "resume must pass saved resume_cursor as S3 start-after"
    );
    assert_eq!(dst_srv.state.lock().unwrap().objects.len(), 30);

    // --- Part 5: Gear 2 parallel range bisection (> 1,000 keys, skewed + flat) ---
    {
        let mut sg = src_srv.state.lock().unwrap();
        sg.objects.clear();
        sg.counters.seen_start_afters.clear();
        for i in 0..1_250 {
            let key = if i < 900 {
                // Heavily skewed single prefix!
                format!("hot/2026/04/obj-{i:05}.bin")
            } else {
                // Flat root keys!
                format!("z-flat-{i:05}.bin")
            };
            let data = vec![(i % 251) as u8; 32];
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            sg.objects.insert(
                key,
                MockS3Object {
                    data,
                    etag,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
        dst_srv.state.lock().unwrap().objects.clear();
    }

    let g2_scratch = tmp.path().join("g2-scratch");
    let mut cfg_g2 = EngineConfig::new("g2-copy", JobMode::Copy, "src:gear1-src", "dst:gear1-dst");
    cfg_g2.transfers = 16;
    cfg_g2.scratch_dir = Some(Arc::new(LazyRunDir::new(g2_scratch.clone(), "g2-copy")));
    let r_g2 = engine
        .run(
            &cfg_g2,
            Arc::new(SqliteSyncIndex::open_in_memory().unwrap()),
        )
        .await
        .unwrap();
    assert!(r_g2.is_success(), "{:?}", r_g2.errors);
    assert_eq!(r_g2.files_transferred, 1_250);
    assert_eq!(dst_srv.state.lock().unwrap().objects.len(), 1_250);
    assert!(
        !src_srv
            .state
            .lock()
            .unwrap()
            .counters
            .seen_start_afters
            .is_empty(),
        "Gear 2 (> 1,000 keys) must engage parallel start-after range bisection"
    );
    assert!(
        !g2_scratch.exists(),
        "Gear 2 streaming copy must create 0 temp files on disk"
    );
    actor.shutdown().await.unwrap();
}

#[tokio::test]
async fn carbon_review_p0_3_p0_4_p1_4_type_flip_siblings_dir_delete_and_force_replace() {
    use rship_core::buffer::BufferPool;
    use rship_core::clock::SystemClock;
    use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
    use rship_core::state::{ConflictKind, JobMode, MemoryJournalStore, MemorySyncIndex};

    let src_srv = MockS3Server::start("src-flip", "us-east-1").await;
    let dst_srv = MockS3Server::start("dst-flip", "us-east-1").await;
    let put_obj = |srv: &MockS3Server, key: &str, data: &[u8]| {
        srv.state.lock().unwrap().objects.insert(
            key.to_string(),
            MockS3Object {
                data: data.to_vec(),
                etag: format!("\"{}\"", hex::encode(Md5::digest(data))),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    };

    // Case A (P0-3): src has [File("app.conf"), Dir("app/")], dst has [File("app"), File("app.conf")].
    // Sibling "app.conf" sits between "app" and "app/" in UTF-8 wire order, yet TypeFlipDirOverFile
    // MUST still be detected and File("app") on dst MUST NOT be deleted without --force-type-replace!
    put_obj(&src_srv, "app.conf", b"cfg");
    put_obj(&src_srv, "app/", b"");
    put_obj(&dst_srv, "app", b"live-binary");
    put_obj(&dst_srv, "app.conf", b"cfg");

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let src_b: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            src_srv.config(S3Provider::Aws, "src-flip", "us-east-1"),
            transport.clone(),
            None,
        )
        .unwrap(),
    );
    let dst_b: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            dst_srv.config(S3Provider::Aws, "dst-flip", "us-east-1"),
            transport,
            None,
        )
        .unwrap(),
    );
    let journal: Arc<dyn rship_core::state::JournalStore> = Arc::new(MemoryJournalStore::new());
    let pool = BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        src_b.clone(),
        dst_b.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-flip-guard", JobMode::Sync, "s3:src", "s3:dst");
    cfg.delete = true;
    cfg.allow_server_side_copy = false;
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(
        rep.conflicts
            .iter()
            .any(|c| c.nfc_path.as_str() == "app" && c.kind == ConflictKind::TypeFlipDirOverFile),
        "must detect TypeFlipDirOverFile despite app.conf sibling: {:?}",
        rep.conflicts
    );
    assert_eq!(
        dst_srv
            .state
            .lock()
            .unwrap()
            .objects
            .get("app")
            .unwrap()
            .data,
        b"live-binary",
        "dst File('app') must NOT be silently deleted without --force-type-replace"
    );

    // Case B (P1-4): With --force-type-replace, DirOverFile replaces File("app") with Dir("app/").
    cfg.job_id = "job-flip-force-dir".into();
    cfg.force_type_replace = true;
    let rep2 = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep2.errors.is_empty(), "errors: {:?}", rep2.errors);
    assert!(rep2.conflicts.is_empty(), "conflicts: {:?}", rep2.conflicts);
    {
        let g = dst_srv.state.lock().unwrap();
        assert!(
            !g.objects.contains_key("app"),
            "old File('app') must be removed"
        );
        assert!(g.objects.contains_key("app/"), "new Dir('app/') must exist");
    }

    // Case C (P1-4): Reverse flip FileOverDir (src has File("app"), dst has Dir("app/")).
    {
        let mut g = src_srv.state.lock().unwrap();
        g.objects.remove("app/");
    }
    put_obj(&src_srv, "app", b"replacement-file");
    cfg.job_id = "job-flip-force-file".into();
    cfg.force_type_replace = true;
    let rep3 = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep3.errors.is_empty(), "errors: {:?}", rep3.errors);
    assert!(rep3.conflicts.is_empty(), "conflicts: {:?}", rep3.conflicts);
    {
        let g = dst_srv.state.lock().unwrap();
        assert!(
            !g.objects.contains_key("app/"),
            "old Dir('app/') must be removed"
        );
        assert_eq!(g.objects.get("app").unwrap().data, b"replacement-file");
    }

    // Case D (P0-4): Deleting Dir("foo/") directly when File("foo") also exists on dst
    // MUST delete ONLY "foo/" (1 RPC) and MUST preserve File("foo") untouched!
    put_obj(&dst_srv, "foo", b"keep-me-intact");
    put_obj(&dst_srv, "foo/", b"");
    dst_srv.state.lock().unwrap().counters.delete_object_calls = 0;
    let dir_bp =
        BackendPath::from_rel(RelPath::parse("foo").unwrap()).with_kind(Some(EntryKind::Directory));
    dst_b.delete(&dir_bp).await.unwrap();
    {
        let g = dst_srv.state.lock().unwrap();
        assert_eq!(
            g.counters.delete_object_calls, 1,
            "deleting EntryKind::Directory must issue exactly 1 DELETE RPC for 'foo/'"
        );
        assert!(
            !g.objects.contains_key("foo/"),
            "'foo/' marker must be deleted"
        );
        assert_eq!(
            g.objects.get("foo").unwrap().data,
            b"keep-me-intact",
            "live File('foo') MUST NOT be deleted when deleting Dir('foo/')"
        );
    }
}

#[tokio::test]
async fn carbon_review_p1_1_and_p1_2_unicode_contraction_and_resume_cursor_clear() {
    use rship_core::buffer::BufferPool;
    use rship_core::clock::SystemClock;
    use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
    use rship_core::state::{JobMode, JobRecord, JobStatus, JournalStore, MemorySyncIndex};

    let src_srv = MockS3Server::start("src-p1", "us-east-1").await;
    let dst_srv = MockS3Server::start("dst-p1", "us-east-1").await;
    let put_obj = |srv: &MockS3Server, key: &str, data: &[u8]| {
        srv.state.lock().unwrap().objects.insert(
            key.to_string(),
            MockS3Object {
                data: data.to_vec(),
                etag: format!("\"{}\"", hex::encode(Md5::digest(data))),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    };

    // P1-1: Kelvin U+212A (raw 0xE2 84 AA > "README.md" 0x52) contracts to NFC "Kelvin.csv" (0x4B < 0x52).
    // Must transfer BOTH without false UnicodeNfcCollision!
    put_obj(&src_srv, "README.md", b"readme");
    put_obj(&src_srv, "\u{212A}elvin.csv", b"temp,300");

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let src_b: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            src_srv.config(S3Provider::Aws, "src-p1", "us-east-1"),
            transport.clone(),
            None,
        )
        .unwrap(),
    );
    let dst_b: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            dst_srv.config(S3Provider::Aws, "dst-p1", "us-east-1"),
            transport,
            None,
        )
        .unwrap(),
    );

    let tmp = tempfile::tempdir().unwrap();
    let actor = rship_state::StateActor::open(tmp.path()).unwrap();
    let journal: Arc<dyn JournalStore> = Arc::new(actor);
    let pool = BufferPool::new(4 * 1024 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        src_b.clone(),
        dst_b.clone(),
        journal.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let mut cfg = EngineConfig::new("job-kelvin", JobMode::Copy, "s3:src", "s3:dst");
    cfg.allow_server_side_copy = false;
    let rep = engine
        .run(&cfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "errors: {:?}", rep.errors);
    assert!(
        rep.conflicts.is_empty(),
        "Kelvin singleton contraction must not emit false UnicodeNfcCollision: {:?}",
        rep.conflicts
    );
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(
        dst_srv
            .state
            .lock()
            .unwrap()
            .objects
            .get("Kelvin.csv")
            .unwrap()
            .data,
        b"temp,300"
    );

    // P1-2: Resuming a paused job in SQLite StateActor preserves cumulative files_done/bytes_done
    // AND actually clears `resume_cursor` back to NULL on completion!
    let src_srv2 = MockS3Server::start("src-res", "us-east-1").await;
    let dst_srv2 = MockS3Server::start("dst-res", "us-east-1").await;
    put_obj(&src_srv2, "a_done.bin", b"1111");
    put_obj(&src_srv2, "b_rem.bin", b"22222");
    put_obj(&src_srv2, "c_rem.bin", b"333333");

    let transport2 = HttpTransport::new(TransportConfig::default()).unwrap();
    let src_b2: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            src_srv2.config(S3Provider::Aws, "src-res", "us-east-1"),
            transport2.clone(),
            None,
        )
        .unwrap(),
    );
    let dst_b2: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            dst_srv2.config(S3Provider::Aws, "dst-res", "us-east-1"),
            transport2,
            None,
        )
        .unwrap(),
    );

    let prev = JobRecord {
        job_id: "job-resume-p1-2".into(),
        mode: JobMode::Copy,
        src_spec: "s3:src".into(),
        dst_spec: "s3:dst".into(),
        status: JobStatus::Paused,
        files_total: 3,
        files_done: 1,
        bytes_total: 15,
        bytes_done: 4,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_010,
        options_json: None,
        resume_cursor: Some("a_done.bin".into()),
    };
    journal.upsert_job(&prev).await.unwrap();

    let engine2 = TransferEngine::new(
        src_b2,
        dst_b2,
        journal.clone(),
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut rcfg = EngineConfig::new("job-resume-p1-2", JobMode::Copy, "s3:src", "s3:dst");
    rcfg.allow_server_side_copy = false;
    rcfg.resume_cursor = Some("a_done.bin".into());
    let rep_res = engine2
        .run(&rcfg, Arc::new(MemorySyncIndex::new()))
        .await
        .unwrap();
    assert!(rep_res.errors.is_empty(), "errors: {:?}", rep_res.errors);
    assert_eq!(
        rep_res.files_transferred, 2,
        "must skip a_done.bin via StartAfter"
    );

    let persisted = journal.get_job("job-resume-p1-2").await.unwrap().unwrap();
    assert_eq!(persisted.status, JobStatus::Completed);
    assert_eq!(
        persisted.created_at, 1_700_000_000,
        "created_at must be preserved"
    );
    assert_eq!(
        persisted.files_done, 3,
        "cumulative files_done must be 1 + 2 = 3"
    );
    assert_eq!(
        persisted.bytes_done, 15,
        "cumulative bytes_done must be 4 + 5 + 6 = 15"
    );
    assert_eq!(
        persisted.resume_cursor, None,
        "resume_cursor MUST be cleared to NULL in SQLite on completion"
    );
}

#[tokio::test]
async fn rclone_s3_list_r_differential_parity_and_special_char_server_side_copy() {
    use rship_core::backend::ListOptions;
    use rship_core::engine::CancelFlag;
    use rship_core::engine::diff::{DiffItem, StreamingMergeDiffSource};
    use rship_core::filter::FilterSet;
    use std::collections::HashSet;

    let srv = MockS3Server::start("parity-bucket", "us-east-1").await;
    let special_keys = [
        "alpha/hello world+plus%20pct.txt",
        "alpha/hash#1?q=2&k=v;semi[1].txt",
        "alpha/café_中文_🚀.bin",
        "alpha/empty_dir/",
        "excluded_dir/skip_me.txt",
        "excluded_dir/🚀_emoji.txt",
        "zeta/final.dat",
    ];
    {
        let mut g = srv.state.lock().unwrap();
        for k in special_keys {
            let data = if k.ends_with('/') {
                Vec::new()
            } else {
                format!("body:{k}").into_bytes()
            };
            g.objects.insert(
                k.to_string(),
                MockS3Object {
                    etag: format!("\"{}\"", hex::encode(Md5::digest(&data))),
                    data,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
        // Also seed 12 keys under "many/" so Gear 2 small-page mode exercises multiple pages/shards.
        for i in 0..12 {
            let k = format!("many/item_{i:02}.bin");
            let data = vec![i as u8; 8];
            g.objects.insert(
                k,
                MockS3Object {
                    etag: format!("\"{}\"", hex::encode(Md5::digest(&data))),
                    data,
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
    }

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let s3: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            srv.config(S3Provider::Aws, "parity-bucket", "us-east-1"),
            transport.clone(),
            None,
        )
        .unwrap(),
    );

    let filter = FilterSet::new(&[], &["excluded_dir/".to_string()]).unwrap();
    let list_opts = ListOptions::recursive().with_filter_pruning(&filter, &RelPath::root());

    // Path 1: Standard `list_with_options` (ListObjectsV2 + dir pruner)
    let mut std_set: HashSet<(String, EntryKind)> = HashSet::new();
    let mut ls = s3
        .list_with_options(&RelPath::root(), &list_opts)
        .await
        .unwrap();
    while let Some(item) = ls.next().await {
        let e = item.unwrap();
        if filter.matches_entry(&e, 0) {
            std_set.insert((e.nfc_path.as_str().to_string(), e.kind));
        }
    }

    // Path 2: `StreamingMergeDiffSource` (ordered UTF-8 stream + dir pruner) against an empty bucket!
    let empty_srv = MockS3Server::start("parity-empty", "us-east-1").await;
    let empty_s3: Arc<dyn StorageBackend> = Arc::new(
        S3Backend::new(
            empty_srv.config(S3Provider::Aws, "parity-empty", "us-east-1"),
            transport,
            None,
        )
        .unwrap(),
    );
    let pruner = list_opts.dir_pruner().cloned();
    let mut diff = StreamingMergeDiffSource::start(
        s3.clone(),
        RelPath::root(),
        empty_s3,
        RelPath::root(),
        None,
        pruner.clone(),
        pruner,
        CancelFlag::new(),
    )
    .await
    .unwrap();
    let mut stream_set: HashSet<(String, EntryKind)> = HashSet::new();
    while let Some(item) = diff.next_item().await {
        if let DiffItem::SrcOnly(e) = item
            && filter.matches_entry(&e, 0)
        {
            stream_set.insert((e.nfc_path.as_str().to_string(), e.kind));
        }
    }
    assert!(diff.src_complete());
    assert_eq!(
        std_set, stream_set,
        "rclone TestFsListR differential parity: list_with_options vs StreamingMergeDiffSource MUST match 100%"
    );
    assert!(!std_set.iter().any(|(p, _)| p.starts_with("excluded_dir")));

    // Path 3: rclone `TestFsServerSideCopy` on special-character keys (`+`, `%20`, `#`, `?`, `&`, Emoji)!
    for (idx, k) in [
        "alpha/hello world+plus%20pct.txt",
        "alpha/hash#1?q=2&k=v;semi[1].txt",
        "alpha/café_中文_🚀.bin",
    ]
    .iter()
    .enumerate()
    {
        let src_rel = RelPath::parse(k).unwrap();
        let dst_rel = RelPath::parse(&format!("copied/{k}")).unwrap();
        let expected = format!("body:{k}").into_bytes();
        let init = UploadInit {
            op_id: format!("op-ssc-special-{idx}"),
            dst_path: dst_rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: expected.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: expected.len().max(1) as u64,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        let copied = s3
            .server_side_copy(
                &s3.endpoint_identity(),
                &BackendPath::from_rel(src_rel),
                &init,
            )
            .await
            .unwrap_or_else(|e| panic!("SSC failed for special key `{k}`: {e}"))
            .expect("SSC must execute on same endpoint");
        assert_eq!(copied.size, expected.len() as u64);
        assert_eq!(
            srv.state
                .lock()
                .unwrap()
                .objects
                .get(dst_rel.as_str())
                .unwrap_or_else(|| panic!("copied key `{dst_rel}` missing"))
                .data,
            expected,
            "SSC bytes must match for special key `{k}`"
        );
    }
}

#[tokio::test]
async fn s3_dynamic_imdsv2_expired_token_retry_sse_kms_and_mime_content_type_fidelity() {
    use axum::extract::State;
    use axum::routing::{get, put};
    use rship_backends::s3::{S3CredentialSource, S3ServerSideEncryption, infer_content_type};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 1. Unit sanity check for MIME inference.
    assert_eq!(
        infer_content_type("site/index.html"),
        "text/html; charset=utf-8"
    );
    assert_eq!(infer_content_type("api/data.JSON"), "application/json");
    assert_eq!(infer_content_type("img/logo.png"), "image/png");
    assert_eq!(infer_content_type("pkg/app.wasm"), "application/wasm");
    assert_eq!(infer_content_type("noext"), "application/octet-stream");

    // 2. Capture exact wire headers for PutObject, CreateMultipartUpload, CopyObject,
    //    AND simulate an ExpiredToken 403 on the first key ("ASIA_OLD") forcing IMDSv2 refresh to "ASIA_NEW"!
    type CapturedWireHeader = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    #[derive(Clone, Default)]
    struct WireProbe {
        captured: Arc<Mutex<Vec<CapturedWireHeader>>>,
        imds_fetches: Arc<AtomicUsize>,
        rejected_expired: Arc<AtomicUsize>,
    }

    let probe = WireProbe::default();

    let imds_app = Router::new()
        .route(
            "/latest/api/token",
            put(|| async { (StatusCode::OK, "tok-v2") }),
        )
        .route(
            "/latest/meta-data/iam/security-credentials/",
            get(|| async { (StatusCode::OK, "prod-role") }),
        )
        .route(
            "/latest/meta-data/iam/security-credentials/prod-role",
            get(|State(st): State<WireProbe>| async move {
                let n = st.imds_fetches.fetch_add(1, Ordering::SeqCst) + 1;
                let ak = if n == 1 { "ASIA_OLD" } else { "ASIA_NEW" };
                let body = serde_json::json!({
                    "AccessKeyId": ak,
                    "SecretAccessKey": format!("SECRET_{n}"),
                    "Token": format!("SESS_{n}"),
                    "Expiration": "2099-01-01T00:00:00Z",
                });
                (StatusCode::OK, axum::Json(body)).into_response()
            }),
        )
        .with_state(probe.clone());

    let imds_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let imds_addr = imds_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(imds_listener, imds_app).await.unwrap();
    });

    let s3_app = Router::new()
        .fallback(
            |State(st): State<WireProbe>,
             method: Method,
             uri: axum::http::Uri,
             headers: HeaderMap,
             _body: Bytes| async move {
                let auth = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                // Reject the initial IMDS key ONCE with S3 XML `ExpiredToken` -> S3Backend must refresh & retry!
                if auth.contains("ASIA_OLD/") {
                    st.rejected_expired.fetch_add(1, Ordering::SeqCst);
                    return (
                        StatusCode::BAD_REQUEST,
                        [("content-type", "application/xml")],
                        "<Error><Code>ExpiredToken</Code><Message>The provided token has expired.</Message></Error>",
                    )
                        .into_response();
                }

                let ct = headers
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let sse = headers
                    .get("x-amz-server-side-encryption")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let kms = headers
                    .get("x-amz-server-side-encryption-aws-kms-key-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let q = uri.query().unwrap_or("");
                st.captured.lock().unwrap().push((
                    format!("{} {}", method.as_str(), uri.path()),
                    q.to_string(),
                    ct,
                    sse,
                    kms,
                ));

                if method == Method::HEAD {
                    return (
                        StatusCode::OK,
                        [
                            ("content-length", "12"),
                            ("etag", "\"abc\""),
                            ("last-modified", "Wed, 15 Nov 2023 00:00:00 GMT"),
                        ],
                    )
                        .into_response();
                }
                if method == Method::POST && q.contains("uploads") {
                    return (
                        StatusCode::OK,
                        [("content-type", "application/xml")],
                        "<?xml version=\"1.0\"?><InitiateMultipartUploadResult><UploadId>u-1</UploadId></InitiateMultipartUploadResult>",
                    )
                        .into_response();
                }
                if method == Method::PUT && headers.contains_key("x-amz-copy-source") {
                    return (
                        StatusCode::OK,
                        [("content-type", "application/xml")],
                        "<?xml version=\"1.0\"?><CopyObjectResult><ETag>\"copied\"</ETag><LastModified>2023-11-15T00:00:00.000Z</LastModified></CopyObjectResult>",
                    )
                        .into_response();
                }
                (
                    StatusCode::OK,
                    [
                        ("etag", "\"put-ok\""),
                        ("last-modified", "Wed, 15 Nov 2023 00:00:00 GMT"),
                    ],
                )
                    .into_response()
            },
        )
        .with_state(probe.clone());

    let s3_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(s3_listener, s3_app).await.unwrap();
    });

    let tmp = tempfile::TempDir::new().unwrap();
    let missing = tmp.path().join("no-aws-file");
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    // Test SSE-KMS + MIME inference + IMDSv2 ExpiredToken recovery (skip IMDS part only if runner has AWS env vars).
    let mut cfg = S3Config::new(
        "kms-s3",
        S3Provider::Aws,
        "bkt",
        S3Credentials::new("STATIC_FALLBACK", "SECRET"),
    )
    .with_endpoint(format!("http://{s3_addr}"))
    .with_force_path_style(true)
    .with_payload_signing(PayloadSigningMode::Unsigned)
    .with_server_side_encryption(S3ServerSideEncryption::AwsKms {
        key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-key".into()),
    });
    let test_imds = S3Credentials::from_env().is_none();
    if test_imds {
        cfg = cfg.with_credential_source(S3CredentialSource::AwsChain {
            profile: None,
            credentials_file: Some(missing.clone()),
            config_file: Some(missing),
            ecs_endpoint: None,
            imds_endpoint: Some(format!("http://{imds_addr}")),
        });
    }
    let s3 = S3Backend::new(cfg, transport, None).unwrap();

    // 1. Control request (`stat` -> HEAD): first attempt signs with ASIA_OLD -> 400 ExpiredToken ->
    //    auto-refreshes to ASIA_NEW and succeeds transparently!
    let st_entry = s3
        .stat(&BackendPath::from_rel(
            RelPath::parse("site/index.html").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st_entry.size, 12);
    if test_imds {
        assert_eq!(probe.rejected_expired.load(Ordering::SeqCst), 1);
        assert_eq!(probe.imds_fetches.load(Ordering::SeqCst), 2);
    }

    // 2. PutObject (`site/index.html`) -> text/html + aws:kms + KMS key ID
    let put_init = UploadInit {
        op_id: "op-html".into(),
        dst_path: RelPath::parse("site/index.html").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let body = Box::pin(futures::stream::once(async {
        Ok(Bytes::from_static(b"<h1>"))
    }));
    s3.put_single_shot(&put_init, body).await.unwrap();

    // 3. CreateMultipartUpload (`data/records.json`) -> application/json + aws:kms + KMS key ID
    let mp_init = UploadInit {
        op_id: "op-json".into(),
        dst_path: RelPath::parse("data/records.json").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16 * 1024 * 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8 * 1024 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    s3.begin_upload(&mp_init).await.unwrap();

    // 4. CopyObject (`img/logo.png`) -> image/png + aws:kms + KMS key ID
    let cp_init = UploadInit {
        op_id: "op-png".into(),
        dst_path: RelPath::parse("img/logo.png").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 100,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 100,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    s3.server_side_copy(
        &s3.endpoint_identity(),
        &BackendPath::from_rel(RelPath::parse("site/index.html").unwrap()),
        &cp_init,
    )
    .await
    .unwrap();

    // 5. Mkdir (`sse_dir/`) -> MUST also carry SSE-KMS headers!
    s3.mkdir(&RelPath::parse("sse_dir").unwrap()).await.unwrap();

    let cap = probe.captured.lock().unwrap().clone();
    let find_req = |needle: &str| {
        cap.iter()
            .find(|(req, _, _, _, _)| req.contains(needle))
            .cloned()
            .unwrap_or_else(|| panic!("missing captured request `{needle}` in {cap:?}"))
    };
    let (_, _, _, sse_dir, kms_dir) = find_req("PUT /bkt/sse_dir/");
    assert_eq!(sse_dir.as_deref(), Some("aws:kms"));
    assert_eq!(
        kms_dir.as_deref(),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-key")
    );
    let (_, _, ct_html, sse_html, kms_html) = find_req("PUT /bkt/site/index.html");
    assert_eq!(ct_html.as_deref(), Some("text/html; charset=utf-8"));
    assert_eq!(sse_html.as_deref(), Some("aws:kms"));
    assert_eq!(
        kms_html.as_deref(),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-key")
    );

    let (_, _, ct_json, sse_json, kms_json) = find_req("POST /bkt/data/records.json");
    assert_eq!(ct_json.as_deref(), Some("application/json"));
    assert_eq!(sse_json.as_deref(), Some("aws:kms"));
    assert_eq!(
        kms_json.as_deref(),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-key")
    );

    let (_, _, ct_png, sse_png, kms_png) = find_req("PUT /bkt/img/logo.png");
    assert_eq!(ct_png.as_deref(), Some("image/png"));
    assert_eq!(sse_png.as_deref(), Some("aws:kms"));
    assert_eq!(
        kms_png.as_deref(),
        Some("arn:aws:kms:us-east-1:123456789012:key/test-key")
    );
}
