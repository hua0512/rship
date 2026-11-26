use crate::common::InjectedFault;
use crate::mock_server::{
    MockGcsObject, make_backend, make_backend_with_config, simple_crc32c, spawn_mock_gcs,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::gcs::{GCS_CHUNK_ALIGN_BYTES, gcs_encode_object_name};
use rship_core::ErrorKind;
use rship_core::backend::{
    BackendPath, ChunkUpload, ReconcileOutcome, StorageBackend, UploadInit, UploadProgress,
};
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, Checksum, EntryKind, HashKind, NodeId};
use std::collections::BTreeMap;
use std::sync::Arc;

#[tokio::test]
async fn gcs_passes_full_backend_conformance_suite() {
    let (base_url, _) = spawn_mock_gcs().await;
    let backend: Arc<dyn StorageBackend> = make_backend(&base_url);
    run_backend_conformance(backend, SystemClock::shared()).await;
}

#[tokio::test]
async fn gcs_handles_special_chars_hashes_precondition_308_resume_and_multistep_rewrite() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);

    // 1. Strict `%2F`/`#`/`?`/`+`/`%`/UTF-8 encoding + MD5 & CRC32C hashes + ifGenerationMatch=0!
    let weird = RelPath::parse("dir/a + b #1?x=1%20/中文.txt").unwrap();
    let payload = b"gcs special chars & checksums!".to_vec();
    let init = UploadInit {
        op_id: "op-gcs-weird".into(),
        dst_path: weird.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p_c = payload.clone();
    let body: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) }));
    let entry = backend.put_single_shot(&init, body).await.unwrap();
    assert_eq!(entry.size, payload.len() as u64);

    // Conditional Absent overwrite MUST fail with 412 PreconditionFailed (`ifGenerationMatch=0`)!
    let p_c2 = payload.clone();
    let body2: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c2)) }));
    let err = backend.put_single_shot(&init, body2).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);

    // Check both MD5 and CRC32C metadata hashes
    let md5 = backend
        .compute_hash(&BackendPath::from_rel(weird.clone()), HashKind::Md5)
        .await
        .unwrap()
        .expect("md5");
    assert_eq!(md5.hex, hex::encode(Md5::digest(&payload)));
    let crc = backend
        .compute_hash(&BackendPath::from_rel(weird.clone()), HashKind::Crc32c)
        .await
        .unwrap()
        .expect("crc32c");
    assert_eq!(crc.hex, hex::encode(simple_crc32c(&payload).to_be_bytes()));

    // 2. Multi-step `rewriteTo` server-side copy (`rewriteToken` loop) + `rename`!
    let copy_dst = RelPath::parse("copies/rewritten #2.txt").unwrap();
    let copy_init = UploadInit {
        op_id: "op-rw".into(),
        dst_path: copy_dst.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = backend.endpoint_identity();
    assert!(backend.can_server_side_copy_from(&ep));
    let copied = backend
        .server_side_copy(&ep, &BackendPath::from_rel(weird.clone()), &copy_init)
        .await
        .unwrap()
        .expect("rewriteTo committed");
    assert_eq!(copied.size, payload.len() as u64);
    assert_eq!(
        state.lock().unwrap().rewrite_calls,
        2,
        "must loop across rewriteToken"
    );

    let renamed = backend
        .rename(&BackendPath::from_rel(copy_dst), "final.txt")
        .await
        .unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "copies/final.txt");

    // 3. 256 KiB-aligned resumable upload + `308 Resume Incomplete` (both missing Range & partial Range)
    let chunk_sz = GCS_CHUNK_ALIGN_BYTES;
    let total_sz = chunk_sz + 512;
    let res_path = RelPath::parse("resumable/stream.bin").unwrap();
    let res_init = UploadInit {
        op_id: "op-gcs-res".into(),
        dst_path: res_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&res_init).await.unwrap();
    let op = OperationRecord {
        op_id: res_init.op_id.clone(),
        session_key: "sk-gcs".into(),
        job_id: "j-gcs".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: res_path.as_str().into(),
        dst_raw_path: res_path.as_str().into(),
        dst_nfc_path: res_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: total_sz,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "gcs".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: chunk_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Before any chunk: 308 without Range header -> SequentialOffset(0)!
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );

    // Upload chunk 1 (256 KiB) -> 308 with Range: bytes=0-262143 -> next_offset = 262144
    let c1 = vec![0x11u8; chunk_sz as usize];
    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                chunk_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c1)) })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack1.next_offset, Some(chunk_sz));
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(chunk_sz)
    );

    // Upload tail (512 bytes) -> 200 OK commits object!
    let c2 = vec![0x22u8; 512];
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                chunk_sz,
                512,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c2)) })),
            ),
        )
        .await
        .unwrap();
    assert!(ack2.completed.is_some());

    // Reconcile confirms committed object via `rship-op-id` metadata!
    match backend.reconcile_operation(&op).await.unwrap() {
        ReconcileOutcome::Committed(e) => assert_eq!(e.size, total_sz),
        other => panic!("expected Committed, got {other:?}"),
    }

    // Abort returns Ok on GCS 499 Client Closed Request!
    backend.abort_upload(&op).await.unwrap();
    assert_eq!(state.lock().unwrap().abort_499_calls, 1);
}

fn simple_init(op_id: &str, path: &RelPath, size: u64, mtime_ns: i64) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: size,
        src_mtime_ns: mtime_ns,
        planned_chunk_size: GCS_CHUNK_ALIGN_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    }
}

fn make_op(
    backend: &dyn StorageBackend,
    init: &UploadInit,
    dst_raw_path: &str,
    session_token: Option<String>,
    backend_meta: String,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sk-{}", init.op_id),
        job_id: "j-gcs-conf".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: dst_raw_path.into(),
        dst_raw_path: dst_raw_path.into(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: init.precondition.clone(),
        existing_dst_node_id: init.existing_node_id.clone(),
        remote_op_id: None,
        backend_kind: "gcs".into(),
        session_token,
        backend_meta,
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    }
}

async fn read_data_source(src: DataSource) -> rship_core::Result<Vec<u8>> {
    match src {
        DataSource::RemoteRangeReadable(r) => {
            let mut s = r
                .open_range(ByteRange {
                    offset: 0,
                    len: r.total_len(),
                })
                .await?;
            let mut out = Vec::new();
            while let Some(item) = s.next().await {
                out.extend_from_slice(&item?);
            }
            Ok(out)
        }
        DataSource::SequentialStream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(item) = stream.next().await {
                out.extend_from_slice(&item?);
            }
            Ok(out)
        }
        DataSource::LocalSeekable(_) => panic!("unexpected LocalSeekable"),
    }
}

#[tokio::test]
async fn gcs_list_stream_suppresses_self_marker_and_skips_invalid_keys() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);

    backend
        .mkdir(&RelPath::parse("sub").unwrap())
        .await
        .unwrap();
    let p1 = RelPath::parse("sub/a.txt").unwrap();
    backend
        .put_single_shot(
            &simple_init("op-sub-a", &p1, 3, 1_700_000_000_000_000_000),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"aaa"))
            })),
        )
        .await
        .unwrap();
    let p2 = RelPath::parse("sub/nested/b.txt").unwrap();
    backend
        .put_single_shot(
            &simple_init("op-sub-b", &p2, 3, 1_700_000_000_000_000_000),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"bbb"))
            })),
        )
        .await
        .unwrap();

    for recursive in [false, true] {
        let mut s = backend
            .list_stream(&RelPath::parse("sub").unwrap(), recursive)
            .await
            .unwrap();
        let mut names = Vec::new();
        while let Some(item) = s.next().await {
            names.push(item.unwrap().nfc_path.as_str().to_string());
        }
        assert!(
            !names.iter().any(|n| n == "sub"),
            "list_stream(sub, recursive={recursive}) must suppress self-marker: {names:?}"
        );
        assert!(names.contains(&"sub/a.txt".to_string()));
    }

    // Seed pre-existing invalid RelPath keys alongside a valid key; neither list_stream nor
    // list_ordered_page may abort.
    {
        let mut g = state.lock().unwrap();
        g.seed_object("bad/\0key.txt", b"x".to_vec());
        g.seed_object("../escape.txt", b"y".to_vec());
        g.seed_object("good.txt", b"ok".to_vec());
    }
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut streamed = Vec::new();
    while let Some(item) = s.next().await {
        streamed.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert!(streamed.contains(&"good.txt".to_string()), "{streamed:?}");

    let mut cursor = None;
    let mut page_names = Vec::new();
    loop {
        let page = backend
            .list_ordered_page(&RelPath::root(), None, cursor.as_deref(), 100)
            .await
            .unwrap();
        page_names.extend(page.entries.iter().map(|e| e.nfc_path.as_str().to_string()));
        if !page.is_truncated {
            break;
        }
        cursor = page.next_cursor;
    }
    assert!(
        page_names.contains(&"good.txt".to_string()),
        "{page_names:?}"
    );
}

#[tokio::test]
async fn gcs_list_ordered_page_start_offset_max_keys_one_and_stat_dir_marker() {
    let (base_url, state) = spawn_mock_gcs().await;
    {
        let mut g = state.lock().unwrap();
        g.seed_object("a.txt", b"1".to_vec());
        g.seed_object("b.txt", b"2".to_vec());
        g.seed_object("c.txt", b"3".to_vec());
        let mut dir_meta = BTreeMap::new();
        dir_meta.insert(
            "goog-reserved-file-mtime".to_string(),
            "1700000005".to_string(),
        );
        let gen_id = g.alloc_gen();
        g.objects.insert(
            "explicit-dir/".to_string(),
            MockGcsObject {
                name: "explicit-dir/".to_string(),
                data: Vec::new(),
                generation: gen_id,
                metadata: dir_meta,
                ..Default::default()
            },
        );
    }
    let backend = make_backend(&base_url);

    let p1 = backend
        .list_ordered_page(&RelPath::root(), Some("a.txt"), None, 1)
        .await
        .unwrap();
    let names1: Vec<_> = p1.entries.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(names1, vec!["b.txt"]);
    assert!(p1.is_truncated);

    let p2 = backend
        .list_ordered_page(
            &RelPath::root(),
            Some("a.txt"),
            p1.next_cursor.as_deref(),
            1,
        )
        .await
        .unwrap();
    let names2: Vec<_> = p2.entries.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(names2, vec!["c.txt"]);

    // stat on explicit "dir/" marker preserves node_id, mtime_ns, and etag
    let dir_stat = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("explicit-dir").unwrap(),
        ))
        .await
        .unwrap()
        .expect("explicit dir exists");
    assert_eq!(dir_stat.kind, EntryKind::Directory);
    assert!(dir_stat.node_id.is_some());
    assert!(dir_stat.etag.is_some());
    assert_eq!(dir_stat.mtime_ns, 1_700_000_005_000_000_000);
}

#[tokio::test]
async fn gcs_rename_guards_nfd_parent_same_name_and_unique_op_id() {
    let (base_url, state) = spawn_mock_gcs().await;
    let nfd_parent = "caf\u{0065}\u{0301}";
    let nfd_old = format!("{nfd_parent}/old.txt");
    let nfd_new = format!("{nfd_parent}/new.txt");
    {
        let mut g = state.lock().unwrap();
        g.seed_object("same.txt", b"keep".to_vec());
        g.seed_object("sub/same.txt", b"keep-sub".to_vec());
        g.seed_object("mydir/", Vec::new());
        g.seed_object("mydir/child.txt", b"child".to_vec());
        g.seed_object(&nfd_old, b"nfd-data".to_vec());
        g.seed_object("x1.txt", b"1".to_vec());
        g.seed_object("x2.txt", b"2".to_vec());
        // Force identical mtime_ns on x1 and x2
        for k in ["x1.txt", "x2.txt"] {
            g.objects
                .get_mut(k)
                .unwrap()
                .metadata
                .insert("goog-reserved-file-mtime".into(), "1700000000".into());
        }
    }
    let backend = make_backend(&base_url);

    // 1. Root and invalid names rejected without mutating RPCs
    assert_eq!(
        backend
            .rename(&BackendPath::from_rel(RelPath::root()), "x")
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidPath
    );
    for bad in ["", ".", "..", "a/b", "a\\b"] {
        assert_eq!(
            backend
                .rename(
                    &BackendPath::from_rel(RelPath::parse("same.txt").unwrap()),
                    bad
                )
                .await
                .unwrap_err()
                .kind,
            ErrorKind::InvalidPath
        );
    }

    // 2. Directory rename rejected before any rewriteTo or DELETE
    let dir_err = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("mydir").unwrap()),
            "mydir2",
        )
        .await
        .unwrap_err();
    assert_eq!(dir_err.kind, ErrorKind::Unsupported);
    let dir_err_hinted = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("mydir").unwrap())
                .with_kind(Some(EntryKind::Directory)),
            "mydir2",
        )
        .await
        .unwrap_err();
    assert_eq!(dir_err_hinted.kind, ErrorKind::Unsupported);
    {
        let g = state.lock().unwrap();
        assert_eq!(g.rewrite_calls, 0);
        assert_eq!(g.delete_calls, 0);
        assert!(g.objects.contains_key("mydir/child.txt"));
    }

    // 3. Same-name rename is a no-op (no rewriteTo, no DELETE)
    let same_entry = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("same.txt").unwrap()),
            "same.txt",
        )
        .await
        .unwrap();
    assert_eq!(same_entry.nfc_path.as_str(), "same.txt");
    let sub_same_entry = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("sub/same.txt").unwrap()),
            "same.txt",
        )
        .await
        .unwrap();
    assert_eq!(sub_same_entry.nfc_path.as_str(), "sub/same.txt");
    {
        let g = state.lock().unwrap();
        assert_eq!(g.rewrite_calls, 0);
        assert_eq!(g.delete_calls, 0);
        assert!(g.objects.contains_key("same.txt"));
        assert!(g.objects.contains_key("sub/same.txt"));
    }

    // 4. NFD parent bytes preserved in rewriteTo dst URL and returned Entry.raw_path
    let nfd_bp = BackendPath::new(&nfd_old, RelPath::parse(&nfd_old).unwrap(), None);
    let nfd_renamed = backend.rename(&nfd_bp, "new.txt").await.unwrap();
    assert_eq!(nfd_renamed.raw_path.as_deref(), Some(nfd_new.as_str()));
    let enc_nfd_new = gcs_encode_object_name(&nfd_new);
    {
        let g = state.lock().unwrap();
        assert!(
            g.seen_rewrite_bodies
                .iter()
                .any(|(p, _)| p.ends_with(&format!("/o/{enc_nfd_new}"))),
            "rewriteTo URL must preserve NFD parent bytes `{enc_nfd_new}`, saw: {:?}",
            g.seen_rewrite_bodies
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>()
        );
    }

    // 5. Identical mtime_ns across renames yields distinct rship-op-id
    backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("x1.txt").unwrap()),
            "y1.txt",
        )
        .await
        .unwrap();
    backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("x2.txt").unwrap()),
            "y2.txt",
        )
        .await
        .unwrap();
    let g = state.lock().unwrap();
    let op1 = g.objects["y1.txt"].metadata.get("rship-op-id").cloned();
    let op2 = g.objects["y2.txt"].metadata.get("rship-op-id").cloned();
    assert!(op1.is_some() && op2.is_some() && op1 != op2);
}

#[tokio::test]
async fn gcs_gzip_accept_encoding_oob_invalid_geometry_and_pinned_source_mutated() {
    let (base_url, state) = spawn_mock_gcs().await;
    let raw_gzip: Vec<u8> = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
    ];
    let gen_id = {
        let mut g = state.lock().unwrap();
        let gen_id = g.alloc_gen();
        g.objects.insert(
            "archive.gz".to_string(),
            MockGcsObject {
                name: "archive.gz".to_string(),
                data: raw_gzip.clone(),
                generation: gen_id,
                content_encoding: Some("gzip".to_string()),
                gzip_uncompressed: Some(b"hello".to_vec()),
                ..Default::default()
            },
        );
        gen_id
    };
    let backend = make_backend(&base_url);

    // Full download preserves raw gzip bytes
    let src = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("archive.gz").unwrap()),
            None,
        )
        .await
        .unwrap();
    let reader = match &src {
        DataSource::RemoteRangeReadable(r) => r.clone(),
        _ => panic!("expected RemoteRangeReadable"),
    };
    let got = read_data_source(src).await.unwrap();
    assert_eq!(got, raw_gzip);

    // Sub-range download also sends Accept-Encoding: gzip and returns raw slice
    let sub_src = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("archive.gz").unwrap()),
            Some(ByteRange { offset: 4, len: 6 }),
        )
        .await
        .unwrap();
    assert_eq!(read_data_source(sub_src).await.unwrap(), raw_gzip[4..10]);
    {
        let g = state.lock().unwrap();
        assert!(
            g.seen_download_accept_encoding
                .iter()
                .all(|h| h.as_deref() == Some("gzip"))
        );
    }

    // Local OOB range fails immediately with InvalidGeometry
    let oob_err = reader
        .open_range(ByteRange {
            offset: raw_gzip.len() as u64 - 2,
            len: 5,
        })
        .await
        .err()
        .expect("OOB range must fail");
    assert_eq!(oob_err.kind, ErrorKind::InvalidGeometry);

    // Pinned generation mismatch in open_read -> SourceMutated
    let wrong_pin = BackendPath::from_rel(RelPath::parse("archive.gz").unwrap())
        .with_node_id(Some(NodeId((gen_id + 999).to_string())));
    let pin_err = backend
        .open_read(&wrong_pin, None)
        .await
        .err()
        .expect("pinned generation mismatch must fail");
    assert_eq!(pin_err.kind, ErrorKind::SourceMutated);

    // Pinned ?generation=404 in GcsRangeReader::open_range -> SourceMutated
    {
        let mut g = state.lock().unwrap();
        let obj = g.objects.get_mut("archive.gz").unwrap();
        obj.generation += 1;
    }
    let reader_404 = reader
        .open_range(ByteRange { offset: 0, len: 4 })
        .await
        .err()
        .expect("stale ?generation= must fail with SourceMutated");
    assert_eq!(reader_404.kind, ErrorKind::SourceMutated);
}

#[tokio::test]
async fn gcs_dst_precondition_existing_and_409_conflict_mapping() {
    let (base_url, state) = spawn_mock_gcs().await;
    let gen_id = {
        let mut g = state.lock().unwrap();
        g.seed_object("target.txt", b"v1".to_vec());
        g.seed_object("src.txt", b"new-src".to_vec());
        g.objects["target.txt"].generation
    };
    let backend = make_backend(&base_url);
    let path = RelPath::parse("target.txt").unwrap();

    // 1. Stale Existing node_id -> 412 PreconditionFailed across put, begin_upload, rewriteTo
    let mut stale_init = simple_init("op-ex-stale", &path, 4, 1_700_000_000_000_000_000);
    stale_init.precondition = DstPrecondition::Existing {
        node_id: Some(NodeId((gen_id + 77).to_string())),
        etag: None,
        mtime_ns: 0,
        size: 2,
    };
    assert_eq!(
        backend
            .put_single_shot(
                &stale_init,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"abcd"))
                })),
            )
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PreconditionFailed
    );
    assert_eq!(
        backend.begin_upload(&stale_init).await.unwrap_err().kind,
        ErrorKind::PreconditionFailed
    );
    assert_eq!(
        backend
            .server_side_copy(
                &backend.endpoint_identity(),
                &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
                &stale_init,
            )
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PreconditionFailed
    );

    // 2. Matching Existing node_id succeeds
    let mut ok_init = stale_init.clone();
    ok_init.op_id = "op-ex-ok".into();
    ok_init.precondition = DstPrecondition::Existing {
        node_id: Some(NodeId(gen_id.to_string())),
        etag: None,
        mtime_ns: 0,
        size: 2,
    };
    let updated = backend
        .put_single_shot(
            &ok_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abcd"))
            })),
        )
        .await
        .unwrap();
    let gen2: u64 = updated.node_id.as_ref().unwrap().0.parse().unwrap();
    assert_ne!(gen2, gen_id);

    // begin_upload + server_side_copy with matching generation also succeed
    let mut res_init = ok_init.clone();
    res_init.op_id = "op-ex-res".into();
    res_init.total_size = GCS_CHUNK_ALIGN_BYTES;
    res_init.precondition = DstPrecondition::Existing {
        node_id: Some(NodeId(gen2.to_string())),
        etag: None,
        mtime_ns: 0,
        size: 4,
    };
    assert!(backend.begin_upload(&res_init).await.is_ok());

    let mut rw_init = ok_init.clone();
    rw_init.op_id = "op-ex-rw".into();
    rw_init.total_size = 7;
    rw_init.precondition = DstPrecondition::Existing {
        node_id: Some(NodeId(gen2.to_string())),
        etag: None,
        mtime_ns: 0,
        size: 4,
    };
    let rw_entry = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
            &rw_init,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rw_entry.size, 7);

    // 3. HTTP 409 maps to ErrorKind::Conflict
    state.lock().unwrap().faults.push(
        "UploadMultipart",
        InjectedFault::json_error(StatusCode::CONFLICT, r#"{"error":{"code":409}}"#),
    );
    let err_409 = backend
        .put_single_shot(
            &simple_init("op-409", &RelPath::parse("c409.txt").unwrap(), 2, 0),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hi"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(err_409.kind, ErrorKind::Conflict);
}

#[tokio::test]
async fn gcs_multipart_boundary_is_dynamic_and_payload_safe() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let payload =
        b"head\r\n--rship_gcs_mp_boundary_9f3c7e2b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--rship_gcs_mp_boundary_9f3c7e2b--\r\n".to_vec();

    for i in 0..2 {
        let p = RelPath::parse(&format!("bnd-{i}.bin")).unwrap();
        let init = simple_init(&format!("op-bnd-{i}"), &p, payload.len() as u64, 10);
        let p_c = payload.clone();
        let entry = backend
            .put_single_shot(
                &init,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
            )
            .await
            .unwrap();
        assert_eq!(entry.size, payload.len() as u64);
        assert_eq!(state.lock().unwrap().objects[p.as_str()].data, payload);
    }

    let g = state.lock().unwrap();
    assert_eq!(g.seen_multipart_boundaries.len(), 2);
    assert_ne!(
        g.seen_multipart_boundaries[0],
        "rship_gcs_mp_boundary_9f3c7e2b"
    );
    assert_ne!(
        g.seen_multipart_boundaries[0],
        g.seen_multipart_boundaries[1]
    );
}

#[tokio::test]
async fn gcs_rewrite_metadata_preservation_403_fallback_over_1024_steps_and_dup_token() {
    let (base_url, state) = spawn_mock_gcs().await;
    let src_gen = {
        let mut g = state.lock().unwrap();
        let gen_id = g.alloc_gen();
        let mut meta = BTreeMap::new();
        meta.insert("x-custom".into(), "keep-me".into());
        g.objects.insert(
            "src.bin".into(),
            MockGcsObject {
                name: "src.bin".into(),
                data: b"rewrite-payload".to_vec(),
                generation: gen_id,
                metadata: meta,
                content_type: Some("text/plain".into()),
                content_encoding: Some("gzip".into()),
                cache_control: Some("max-age=60".into()),
                content_disposition: Some("inline".into()),
                content_language: Some("en".into()),
                custom_time: Some("2025-01-01T00:00:00Z".into()),
                ..Default::default()
            },
        );
        g.rewrite_steps = 1026;
        gen_id
    };
    let backend = make_backend(&base_url);
    let ep = backend.endpoint_identity();
    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap());

    // 1. Over-1024-step rewriteToken loop succeeds AND preserves all editable + custom metadata
    let mut init = simple_init(
        "op-rw-1026",
        &RelPath::parse("dst.bin").unwrap(),
        15,
        1_700_000_000_000_000_000,
    );
    init.checksums = vec![Checksum {
        kind: HashKind::Crc32c,
        hex: "01020304".into(),
    }];
    let copied = backend
        .server_side_copy(&ep, &src_bp, &init)
        .await
        .unwrap()
        .expect("1026-step rewriteTo must succeed");
    assert_eq!(copied.size, 15);
    {
        let g = state.lock().unwrap();
        assert_eq!(g.rewrite_calls, 1026);
        let dst = &g.objects["dst.bin"];
        assert_eq!(dst.content_type.as_deref(), Some("text/plain"));
        assert_eq!(dst.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(dst.cache_control.as_deref(), Some("max-age=60"));
        assert_eq!(dst.content_disposition.as_deref(), Some("inline"));
        assert_eq!(dst.content_language.as_deref(), Some("en"));
        assert_eq!(dst.custom_time.as_deref(), Some("2025-01-01T00:00:00Z"));
        assert_eq!(
            dst.metadata.get("x-custom").map(String::as_str),
            Some("keep-me")
        );
        assert_eq!(
            g.seen_rewrite_queries[0]
                .get("ifSourceGenerationMatch")
                .map(String::as_str),
            Some(src_gen.to_string().as_str())
        );
        let req_json: serde_json::Value =
            serde_json::from_slice(&g.seen_rewrite_bodies[0].1).unwrap();
        assert!(req_json.get("name").is_none());
        assert!(req_json.get("crc32c").is_none());
        assert!(req_json.get("md5Hash").is_none());
    }

    // 2. 403 on rewriteTo falls back cleanly to Ok(None)
    {
        let mut g = state.lock().unwrap();
        g.rewrite_steps = 1;
        g.faults.push(
            "RewriteObject",
            InjectedFault::json_error(StatusCode::FORBIDDEN, r#"{"error":{"code":403}}"#),
        );
    }
    let fb = backend
        .server_side_copy(
            &ep,
            &src_bp,
            &simple_init("op-rw-403", &RelPath::parse("dst-403.bin").unwrap(), 15, 0),
        )
        .await
        .unwrap();
    assert!(fb.is_none());

    // 3. Stale ifSourceGenerationMatch (412 with absent dst) fails immediately with SourceMutated
    let stale_src = src_bp.clone().with_node_id(Some(NodeId("999999".into())));
    let calls_before = state.lock().unwrap().rewrite_calls;
    let src_mut_err = backend
        .server_side_copy(
            &ep,
            &stale_src,
            &simple_init(
                "op-rw-srcmut",
                &RelPath::parse("dst-absent.bin").unwrap(),
                15,
                0,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(src_mut_err.kind, ErrorKind::SourceMutated);
    assert_eq!(
        state.lock().unwrap().rewrite_calls - calls_before,
        1,
        "absent-dst 412 must fail immediately without retry"
    );

    // 4. Duplicate rewriteToken fails with Protocol
    {
        let mut g = state.lock().unwrap();
        g.rewrite_steps = 3;
        g.rewrite_force_duplicate_token = true;
    }
    let dup_err = backend
        .server_side_copy(
            &ep,
            &src_bp,
            &simple_init("op-rw-dup", &RelPath::parse("dst-dup.bin").unwrap(), 15, 0),
        )
        .await
        .unwrap_err();
    assert_eq!(dup_err.kind, ErrorKind::Protocol);
}

#[tokio::test]
async fn gcs_zero_byte_resumable_query_and_finalize() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend(&base_url);
    let path = RelPath::parse("zero/empty.bin").unwrap();
    let init = simple_init("op-zero-res", &path, 0, 1_700_000_000_000_000_000);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op(
        backend.as_ref(),
        &init,
        path.as_str(),
        Some(sess.session_token.clone()),
        sess.backend_meta.clone(),
    );

    // query_upload must send Content-Range: bytes */* and NOT prematurely commit!
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );
    assert!(!state.lock().unwrap().objects.contains_key("zero/empty.bin"));

    // Intentional 0-byte upload_chunk sends Content-Range: bytes */0 and commits!
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, 0, 0, Box::pin(futures::stream::empty())),
        )
        .await
        .unwrap();
    let entry = ack.completed.expect("0-byte final chunk must commit");
    assert_eq!(entry.size, 0);
    assert_eq!(state.lock().unwrap().objects["zero/empty.bin"].data, b"");
    assert_eq!(
        state.lock().unwrap().resumable_puts.last().unwrap().0,
        "bytes */0"
    );
}

#[tokio::test]
async fn gcs_user_project_r2_mtime_and_finish_upload_nfd_crc32c() {
    let (base_url, state) = spawn_mock_gcs().await;
    let backend = make_backend_with_config(&base_url, |cfg| {
        cfg.user_project = Some("billing-proj".to_string());
    });

    backend
        .mkdir(&RelPath::parse("updir").unwrap())
        .await
        .unwrap();
    let init = simple_init(
        "op-r2-up",
        &RelPath::parse("updir/item.txt").unwrap(),
        4,
        1_700_000_000_123_456_789,
    );
    let entry = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"data"))
            })),
        )
        .await
        .unwrap();
    assert_eq!(entry.mtime_ns, 1_700_000_000_123_456_789);
    {
        let g = state.lock().unwrap();
        let meta = &g.objects["updir/item.txt"].metadata;
        assert_eq!(
            meta.get("goog-reserved-file-mtime").map(String::as_str),
            Some("1700000000")
        );
        assert!(meta.contains_key("mtime"));
        assert!(!meta.contains_key("rship-mtime-ns"));
    }

    // Exercise stat, list_stream, list_ordered_page, open_read, begin_upload, server_side_copy, delete
    let _ = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("updir/item.txt").unwrap(),
        ))
        .await
        .unwrap();
    let _ = backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .next()
        .await;
    let _ = backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .unwrap();
    let _ = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("updir/item.txt").unwrap()),
            None,
        )
        .await
        .unwrap();
    let _ = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("updir/item.txt").unwrap()),
            &simple_init(
                "op-r2-cp",
                &RelPath::parse("updir/copy.txt").unwrap(),
                4,
                1_700_000_000_000_000_000,
            ),
        )
        .await
        .unwrap();
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("updir/copy.txt").unwrap(),
        ))
        .await
        .unwrap();

    // Every single API / upload-init request must carry userProject=billing-proj
    {
        let g = state.lock().unwrap();
        assert!(!g.seen_user_projects.is_empty());
        for (m, p, up) in &g.seen_user_projects {
            assert_eq!(
                up.as_deref(),
                Some("billing-proj"),
                "request `{m} {p}` missing userProject=billing-proj"
            );
        }
    }

    // finish_upload with NFD dst_raw_path and Crc32c-only expected checksums catches CRC32C
    // mismatch even when md5Hash is present and valid.
    let nfd_raw = "caf\u{0065}\u{0301}/fin.bin";
    let payload = b"fin-payload".to_vec();
    {
        let mut g = state.lock().unwrap();
        g.seed_object(nfd_raw, payload.clone());
    }
    let crc_hex = format!("{:08x}", simple_crc32c(&payload));
    let mut fin_init = simple_init(
        "op-fin-nfd",
        &RelPath::parse(nfd_raw).unwrap(),
        payload.len() as u64,
        1_700_000_000_000_000_000,
    );
    fin_init.checksums = vec![Checksum {
        kind: HashKind::Crc32c,
        hex: crc_hex,
    }];
    let sess = backend.begin_upload(&fin_init).await.unwrap();
    let op = make_op(
        backend.as_ref(),
        &fin_init,
        nfd_raw,
        Some(sess.session_token),
        serde_json::json!({
            "full_key": nfd_raw,
            "checksums": fin_init.checksums,
        })
        .to_string(),
    );

    // 1. Valid CRC32C succeeds and preserves NFD raw_path
    let fin_ok = backend.finish_upload(&op, &[]).await.unwrap();
    assert_eq!(fin_ok.raw_path.as_deref(), Some(nfd_raw));

    // 2. Corrupt server crc32c while md5Hash remains valid -> caught as Integrity!
    state.lock().unwrap().corrupt_get_meta_crc32c_once = true;
    let fin_err = backend.finish_upload(&op, &[]).await.unwrap_err();
    assert_eq!(fin_err.kind, ErrorKind::Integrity);
}
