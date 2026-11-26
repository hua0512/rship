use crate::common::InjectedFault;
use crate::mock_server::start_mock_dav;
use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use rship_backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};
use rship_core::backend::{
    BackendPath, ChunkUpload, ListOptions, StorageBackend, UploadInit, UploadProgress,
};
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_core::types::{Checksum, EntryKind, HashKind};
use rship_core::{ErrorKind, RetryClass};
use rship_transport::{HttpDumpMode, HttpTransport, TransportConfig};
use std::time::Duration;

const ROOT: &str = "/remote.php/dav/files/alice";

fn nc_backend(addr: &str) -> WebdavBackend {
    let mut cfg = WebdavConfig::new("nc-audit", format!("http://{addr}{ROOT}"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    cfg.max_retries = 3;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(20);
    WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap()
}

fn make_op(
    backend: &WebdavBackend,
    init: &UploadInit,
    sess: &rship_core::backend::UploadSessionInit,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key(
            "local",
            init.dst_path.as_str(),
            &backend.endpoint_identity(),
            &init.dst_path,
        ),
        job_id: "j-audit".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: init.dst_path.as_str().into(),
        dst_raw_path: init.dst_path.as_str().into(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: init.precondition.clone(),
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id.clone(),
        backend_kind: "webdav".into(),
        session_token: Some(sess.session_token.clone()),
        backend_meta: sess.backend_meta.clone(),
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    }
}

fn sha1_hex_ref(data: &[u8]) -> String {
    // Use sha2? No, compute via simple RFC 3174 in test to cross-verify independently.
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    state.iter().map(|w| format!("{w:08x}")).collect()
}

#[tokio::test]
async fn webdav_p0_207_multistatus_per_href_failures_and_423_retry() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.files.insert(format!("{ROOT}/f.txt"), b"hello".to_vec());
        g.dirs.insert(format!("{ROOT}/dir"));
        g.files
            .insert(format!("{ROOT}/dir/locked.txt"), b"locked".to_vec());
    }
    let backend = nc_backend(&addr);

    let body_403 = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/remote.php/dav/files/alice/dir/ok.txt</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>
  <d:response><d:href>/remote.php/dav/files/alice/dir/denied.txt</d:href><d:status>HTTP/1.1 403 Forbidden</d:status></d:response>
</d:multistatus>"#;

    // 1. DELETE returning 207 with 403 must fail (not silently Ok).
    st.lock().unwrap().scripted_responses.push_back((
        "DELETE".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        body_403.into(),
    ));
    let err = backend
        .delete(&BackendPath::from_rel(RelPath::parse("f.txt").unwrap()))
        .await
        .expect_err("207 with 403 on DELETE must fail");
    assert_eq!(err.kind, ErrorKind::PermissionDenied);

    // 2. COPY returning 207 with 403 must fail.
    st.lock().unwrap().scripted_responses.push_back((
        "COPY".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        body_403.into(),
    ));
    let copy_init = UploadInit {
        op_id: "op-207-copy".into(),
        dst_path: RelPath::parse("copied.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("f.txt").unwrap()),
            &copy_init,
        )
        .await
        .expect_err("207 with 403 on COPY must fail");
    assert_eq!(err.kind, ErrorKind::PermissionDenied);

    // 3. rename (MOVE) returning 207 with 403 must fail.
    st.lock().unwrap().scripted_responses.push_back((
        "MOVE".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        body_403.into(),
    ));
    let err = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("f.txt").unwrap()),
            "f2.txt",
        )
        .await
        .expect_err("207 with 403 on MOVE must fail");
    assert_eq!(err.kind, ErrorKind::PermissionDenied);

    // 4. DELETE returning 207 with 423 Locked must retry (LockBusy) and succeed once cleared!
    let body_423 = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/remote.php/dav/files/alice/f.txt</d:href><d:status>HTTP/1.1 423 Locked</d:status></d:response>
</d:multistatus>"#;
    st.lock().unwrap().scripted_responses.push_back((
        "DELETE".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        body_423.into(),
    ));
    backend
        .delete(&BackendPath::from_rel(RelPath::parse("f.txt").unwrap()))
        .await
        .expect("207 with 423 Locked on DELETE must retry and succeed");
    assert!(
        !st.lock()
            .unwrap()
            .files
            .contains_key(&format!("{ROOT}/f.txt"))
    );

    // 5. Direct 423 Locked is retryable LockBusy and recovers cleanly.
    st.lock().unwrap().scripted_responses.push_back((
        "DELETE".into(),
        StatusCode::LOCKED,
        vec![],
        "locked".into(),
    ));
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("dir/locked.txt").unwrap(),
        ))
        .await
        .expect("HTTP 423 Locked must retry and succeed");

    // 6. Exhausted 423 Locked on an existing file surfaces ErrorKind::LockBusy + RetryClass::Retryable.
    st.lock()
        .unwrap()
        .files
        .insert(format!("{ROOT}/dir/still_here.txt"), b"busy".to_vec());
    let mut cfg0 = WebdavConfig::new("nc-423-0", format!("http://{addr}{ROOT}"));
    cfg0.vendor = WebdavVendor::Nextcloud;
    cfg0.max_retries = 0;
    let b0 = WebdavBackend::new(
        cfg0,
        HttpTransport::new(TransportConfig::default()).unwrap(),
    )
    .unwrap();
    st.lock().unwrap().scripted_responses.push_back((
        "DELETE".into(),
        StatusCode::LOCKED,
        vec![],
        "locked".into(),
    ));
    let err_423 = b0
        .delete(&BackendPath::from_rel(
            RelPath::parse("dir/still_here.txt").unwrap(),
        ))
        .await
        .expect_err("0-retry 423 must fail with LockBusy");
    assert_eq!(err_423.kind, ErrorKind::LockBusy);
    assert_eq!(err_423.retry, RetryClass::Retryable);

    // 7. MOVE .file (Nextcloud chunk assembly) returning 207 with 403 must fail (never Ok).
    let chunk_init = UploadInit {
        op_id: "op-207-assemble".into(),
        dst_path: RelPath::parse("dir/assembled_207.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&chunk_init).await.unwrap();
    let op = make_op(&backend, &chunk_init, &sess);
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                4,
                4,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"data"))
                })),
            ),
        )
        .await
        .unwrap();
    st.lock().unwrap().scripted_responses.push_back((
        "MOVE_ASSEMBLE".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        body_403.into(),
    ));
    let err_asm = backend
        .finish_upload(&op, &[])
        .await
        .expect_err("207 with 403 on MOVE .file must fail");
    assert_eq!(err_asm.kind, ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn webdav_p0_finish_upload_reconcile_rejects_stale_same_size_and_retries_precommit_503() {
    let (addr, st) = start_mock_dav().await;
    let backend = nc_backend(&addr);
    let stale_bytes = b"STALE-OLD-DATA-1".to_vec();
    let new_bytes = b"FRESH-NEW-DATA-2".to_vec();
    let len = stale_bytes.len() as u64;

    // Case 1: Stale same-size file pre-exists. Staging vanishes while response is lost
    // (simulating expired staging / someone else's stale file, ETag unchanged!).
    // Reconcile must NOT accept the stale same-size destination.
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/stale.bin"), stale_bytes.clone());
        g.bump_etag(&format!("{ROOT}/stale.bin"));
    }
    let rel1 = RelPath::parse("stale.bin").unwrap();
    let init1 = UploadInit {
        op_id: "op-stale-check".into(),
        dst_path: rel1.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: len,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: len,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess1 = backend.begin_upload(&init1).await.unwrap();
    let op1 = make_op(&backend, &init1, &sess1);
    backend
        .upload_chunk(
            &op1,
            ChunkUpload::new(
                1,
                0,
                len,
                len,
                Box::pin(futures::stream::once(async move {
                    Ok(Bytes::from(new_bytes.clone()))
                })),
            ),
        )
        .await
        .unwrap();

    // Remove staging manually so staging is gone while dst still holds stale ETag,
    // and inject 503 on MOVE_ASSEMBLE!
    st.lock()
        .unwrap()
        .dirs
        .remove("/remote.php/dav/uploads/alice/op-stale-check");
    st.lock().unwrap().faults.push(
        "MOVE_ASSEMBLE",
        InjectedFault::service_unavailable(Some("0")),
    );
    let err = backend.finish_upload(&op1, &[]).await.expect_err(
        "finish_upload must NOT accept stale same-size destination when ETag is unchanged",
    );
    assert_eq!(err.kind, ErrorKind::RateLimited);

    // Case 2: Overwriting an existing same-size file where MOVE .file gets pre-commit 503
    // (staging still exists!). Must retry instead of failing permanently.
    let new_bytes2 = b"FRESH-NEW-DATA-3".to_vec();
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/ow_same.bin"), stale_bytes.clone());
        g.bump_etag(&format!("{ROOT}/ow_same.bin"));
    }
    let rel2 = RelPath::parse("ow_same.bin").unwrap();
    let init2 = UploadInit {
        op_id: "op-ow-same-503".into(),
        dst_path: rel2.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: len,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: len,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess2 = backend.begin_upload(&init2).await.unwrap();
    let op2 = make_op(&backend, &init2, &sess2);
    backend
        .upload_chunk(
            &op2,
            ChunkUpload::new(
                1,
                0,
                len,
                len,
                Box::pin(futures::stream::once(async move {
                    Ok(Bytes::from(new_bytes2.clone()))
                })),
            ),
        )
        .await
        .unwrap();
    st.lock().unwrap().faults.push(
        "MOVE_ASSEMBLE",
        InjectedFault::service_unavailable(Some("0")),
    );
    let entry2 = backend
        .finish_upload(&op2, &[])
        .await
        .expect("pre-commit 503 on same-size overwrite must retry and succeed");
    assert_eq!(entry2.size, len);
    assert_eq!(
        st.lock().unwrap().files[&format!("{ROOT}/ow_same.bin")],
        b"FRESH-NEW-DATA-3".to_vec()
    );
}

#[tokio::test]
async fn webdav_p0_query_upload_rejects_zero_byte_chunks() {
    let (addr, st) = start_mock_dav().await;
    let backend = nc_backend(&addr);

    let init = UploadInit {
        op_id: "op-zero-chunk".into(),
        dst_path: RelPath::parse("zero_chunk.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 16_384,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8_192,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op(&backend, &init, &sess);

    // Seed both a 0-byte numeric chunk `1` and a 0-byte range chunk `0000000000000000-0000000000008192`.
    {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/uploads/alice/op-zero-chunk/1".into(),
            Vec::new(),
        );
        g.files.insert(
            "/remote.php/dav/uploads/alice/op-zero-chunk/0000000000000000-0000000000008192".into(),
            Vec::new(),
        );
    }

    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0),
        "0-byte chunk files must NEVER advance confirmed offset"
    );
}

#[tokio::test]
async fn webdav_p0_trailing_slash_strict_nginx_and_no_301_get_downgrade() {
    let (addr, st) = start_mock_dav().await;
    st.lock().unwrap().require_trailing_slash = true;
    let backend = nc_backend(&addr);

    // Strict Nginx mode: MKCOL, PROPFIND, DELETE on dirs must all send trailing `/`.
    let dir = RelPath::parse("strict/sub").unwrap();
    backend.mkdir(&dir).await.expect("mkdir with trailing /");
    let st_dir = backend
        .stat(&BackendPath::from_rel(dir.clone()).with_kind(Some(EntryKind::Directory)))
        .await
        .unwrap()
        .expect("stat dir");
    assert_eq!(st_dir.kind, EntryKind::Directory);
    assert!(backend.about().await.unwrap().is_some());

    let items: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect()
        .await;
    assert_eq!(items.len(), 2);

    // Chunked begin_upload + query_upload + abort_upload under strict trailing `/`.
    let init = UploadInit {
        op_id: "op-strict-slash".into(),
        dst_path: RelPath::parse("strict/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    assert!(sess.session_token.ends_with("/op-strict-slash"));
    let op = make_op(&backend, &init, &sess);
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );
    backend.abort_upload(&op).await.unwrap();

    // Delete directory even when caller didn't populate `kind` (`kind == None`)!
    backend
        .delete(&BackendPath::from_rel(RelPath::parse("strict").unwrap()))
        .await
        .expect("dir delete must succeed in strict trailing-slash mode");

    // Verify 301/302 redirect on MKCOL does NOT downgrade to GET!
    st.lock().unwrap().requests_seen.clear();
    st.lock().unwrap().scripted_responses.push_back((
        "MKCOL".into(),
        StatusCode::MOVED_PERMANENTLY,
        vec![("location".into(), format!("{ROOT}/redir_target/"))],
        String::new(),
    ));
    backend
        .mkdir(&RelPath::parse("redir_src").unwrap())
        .await
        .expect("301 on MKCOL must preserve MKCOL method and succeed");

    let seen = st.lock().unwrap().requests_seen.clone();
    assert!(
        seen.iter().all(|(m, _, _)| m != "GET"),
        "301 redirect must NEVER downgrade WebDAV control verb to GET: {seen:?}"
    );
    assert_eq!(
        seen.iter().filter(|(m, _, _)| m == "MKCOL").count(),
        2,
        "expected MKCOL to be re-issued on redirect target: {seen:?}"
    );
    assert!(
        st.lock()
            .unwrap()
            .dirs
            .contains(&format!("{ROOT}/redir_target"))
    );
}

#[tokio::test]
async fn webdav_p0_percent_encoded_destination_and_nfd_bfs_and_rename() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.dirs.insert("/remote.php/dav/files/alice smith".into());
        g.dirs.insert("/remote.php/dav/uploads/alice smith".into());
        // Byte-exact NFD directory tree!
        g.dirs
            .insert("/remote.php/dav/files/alice smith/cafe\u{0301}".into());
        g.dirs
            .insert("/remote.php/dav/files/alice smith/cafe\u{0301}/sub\u{0301}".into());
        g.files.insert(
            "/remote.php/dav/files/alice smith/cafe\u{0301}/sub\u{0301}/note file.txt".into(),
            b"nfd-payload".to_vec(),
        );
    }

    let mut cfg = WebdavConfig::new(
        "nc-enc",
        format!("http://{addr}/remote.php/dav/files/alice smith"),
    );
    cfg.vendor = WebdavVendor::Nextcloud;
    let backend =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();

    // 1. Recursive BFS over NFD subtree preserves raw_rel and finds the nested leaf!
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
        .await;
    let leaf = listed
        .iter()
        .find(|e| e.nfc_path.as_str().ends_with("note file.txt"))
        .expect("NFD subtree leaf must NOT be dropped during recursive BFS");
    assert_eq!(
        leaf.raw_path.as_deref(),
        Some("cafe\u{0301}/sub\u{0301}/note file.txt")
    );

    // 2. Rename inside NFD parent preserves NFD parent in source, Destination, and returned Entry.
    let renamed = backend
        .rename(&BackendPath::from_entry(leaf), "renamed file.txt")
        .await
        .expect("rename inside NFD parent must succeed");
    assert_eq!(
        renamed.raw_path.as_deref(),
        Some("cafe\u{0301}/sub\u{0301}/renamed file.txt")
    );

    // 3. Verify Destination header sent on COPY / MOVE is properly percent-encoded (no raw spaces!).
    let copy_init = UploadInit {
        op_id: "op space id".into(),
        dst_path: RelPath::parse("dest dir/copied file.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 11,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_entry(&renamed),
            &copy_init,
        )
        .await
        .unwrap();

    let seen = st.lock().unwrap().requests_seen.clone();
    let copy_req = seen
        .iter()
        .rev()
        .find(|(m, _, _)| m == "COPY")
        .expect("COPY recorded");
    let dst_hdr = copy_req.2.get("destination").unwrap().to_str().unwrap();
    assert!(
        !dst_hdr.contains(' '),
        "Destination must be percent-encoded: {dst_hdr}"
    );
    assert!(dst_hdr.contains("alice%20smith"));
    assert!(dst_hdr.contains("copied%20file.txt"));
}

#[tokio::test]
async fn webdav_p0_nextcloud_chunking_v2_headers_and_11_numeric_parts() {
    let (addr, st) = start_mock_dav().await;
    let backend = nc_backend(&addr);

    // 11 chunks of 1024 bytes each -> tests numeric sorting (10 & 11 must sort AFTER 2!).
    let chunk_size = 1024u64;
    let total_size = 11 * chunk_size;
    let payload: Vec<u8> = (0..total_size as usize).map(|i| (i % 251) as u8).collect();
    let dst_rel = RelPath::parse("nc11/big.bin").unwrap();
    let init = UploadInit {
        op_id: "op-nc-11".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: chunk_size,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op(&backend, &init, &sess);

    // Verify MKCOL included Destination & OC-Total-Length.
    {
        let g = st.lock().unwrap();
        let mkcol = g
            .requests_seen
            .iter()
            .find(|(m, p, _)| m == "MKCOL" && p.ends_with("/op-nc-11/"))
            .expect("MKCOL trailing slash recorded");
        assert!(mkcol.2.get("destination").is_some());
        assert_eq!(
            mkcol.2.get("oc-total-length").unwrap().to_str().unwrap(),
            total_size.to_string()
        );
    }

    // Out-of-range part_number 0 or 10_001 must be rejected cleanly.
    let err0 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                0,
                0,
                chunk_size,
                total_size,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0u8; 1024]))
                })),
            ),
        )
        .await
        .expect_err("part_number 0 invalid for Nextcloud v2");
    assert_eq!(err0.kind, ErrorKind::InvalidGeometry);

    for part in 1..=11u32 {
        let start = ((part - 1) as u64 * chunk_size) as usize;
        let slice = payload[start..start + chunk_size as usize].to_vec();
        backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    part,
                    start as u64,
                    chunk_size,
                    total_size,
                    Box::pin(futures::stream::once(async move { Ok(Bytes::from(slice)) })),
                ),
            )
            .await
            .unwrap();
        if part == 5 {
            assert_eq!(
                backend.query_upload(&op).await.unwrap(),
                UploadProgress::SequentialOffset(5 * chunk_size)
            );
        }
    }

    backend.finish_upload(&op, &[]).await.unwrap();

    let g = st.lock().unwrap();
    // Verify chunk PUTs used numeric `1..=11` and carried `Destination` + `OC-Total-Length`.
    let put_10 = g
        .requests_seen
        .iter()
        .find(|(m, p, _)| m == "PUT" && p.ends_with("/op-nc-11/10"))
        .expect("Nextcloud numeric chunk 10 PUT recorded");
    assert!(put_10.2.get("destination").is_some());
    assert_eq!(
        put_10.2.get("oc-total-length").unwrap().to_str().unwrap(),
        total_size.to_string()
    );
    assert_eq!(g.files[&format!("{ROOT}/nc11/big.bin")], payload);
}

#[tokio::test]
async fn webdav_p0_and_p1_list_max_depth_cycle_guard_and_phantom_filter() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.dirs.insert(format!("{ROOT}/a"));
        g.dirs.insert(format!("{ROOT}/a/b"));
        g.files.insert(format!("{ROOT}/a/f1.txt"), b"1".to_vec());
        g.files.insert(format!("{ROOT}/a/b/f2.txt"), b"2".to_vec());
        // Inject ancestor, sibling, and cyclic entries into `a/b`!
        g.extra_propfind_entries.insert(
            format!("{ROOT}/a/b"),
            vec![
                (format!("{ROOT}/a/"), true, 0),       // ancestor cycle
                (format!("{ROOT}/sibling/"), true, 0), // out-of-subtree sibling
            ],
        );
    }
    let backend = nc_backend(&addr);

    // 1. max_depth(0) must return empty stream.
    let d0: Vec<_> = backend
        .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
        .await
        .unwrap()
        .collect()
        .await;
    assert!(d0.is_empty(), "max_depth(0) must yield 0 entries");

    // 2. with_max_depth(2).with_recursive(false) must still traverse depth 2!
    let d2: Vec<_> = backend
        .list_with_options(
            &RelPath::root(),
            &ListOptions::new().with_max_depth(2).with_recursive(false),
        )
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert!(d2.contains(&"a".to_string()));
    assert!(d2.contains(&"a/b".to_string()));
    assert!(d2.contains(&"a/f1.txt".to_string()));
    assert!(!d2.contains(&"a/b/f2.txt".to_string()));

    // 3. Full recursive listing terminates cleanly despite ancestor/sibling cycle injections.
    let full: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert!(full.contains(&"a/b/f2.txt".to_string()));
    assert!(!full.contains(&"sibling".to_string()));

    // 4. Non-2xx <propstat> in PROPFIND never emits 0-byte phantom entries.
    let phantom_xml = br#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/alice/phantom.txt</d:href>
    <d:propstat>
      <d:prop><d:getcontentlength/></d:prop>
      <d:status>HTTP/1.1 404 Not Found</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/real.txt</d:href>
    <d:propstat>
      <d:prop><d:getcontentlength>9</d:getcontentlength></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
    st.lock().unwrap().scripted_responses.push_back((
        "PROPFIND".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        String::from_utf8_lossy(phantom_xml).to_string(),
    ));
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
        .await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].nfc_path.as_str(), "real.txt");
    assert_eq!(listed[0].size, 9);
}

#[tokio::test]
async fn webdav_p1_ocis_chunked_root_and_known_dirs_409_eviction() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.dirs.insert("/dav/files/alice".into());
        g.dirs.insert("/dav/uploads/alice".into());
    }
    let mut cfg = WebdavConfig::new("ocis", format!("http://{addr}/dav/files/alice"));
    cfg.vendor = WebdavVendor::Nextcloud;
    let ocis_backend =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();

    let payload = b"ocis-chunked-upload-body".to_vec();
    let init = UploadInit {
        op_id: "op-ocis-1".into(),
        dst_path: RelPath::parse("docs/ocis.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = ocis_backend.begin_upload(&init).await.unwrap();
    assert!(sess.session_token.ends_with("/dav/uploads/alice/op-ocis-1"));
    let op = make_op(&ocis_backend, &init, &sess);
    let p_clone = payload.clone();
    ocis_backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                payload.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(
                    async move { Ok(Bytes::from(p_clone)) },
                )),
            ),
        )
        .await
        .unwrap();
    ocis_backend.finish_upload(&op, &[]).await.unwrap();
    assert_eq!(
        st.lock().unwrap().files["/dav/files/alice/docs/ocis.bin"],
        payload
    );

    // PUT 409 eviction of `known_dirs`:
    let nc = nc_backend(&addr);
    st.lock().unwrap().enforce_parent_dir_on_put = true;
    nc.mkdir(&RelPath::parse("evict/sub").unwrap())
        .await
        .unwrap();
    // Simulate external deletion of parent dir `evict` & `evict/sub` on server!
    {
        let mut g = st.lock().unwrap();
        g.dirs.remove(&format!("{ROOT}/evict/sub"));
        g.dirs.remove(&format!("{ROOT}/evict"));
    }
    let put_init = UploadInit {
        op_id: "op-409-evict".into(),
        dst_path: RelPath::parse("evict/sub/file.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let err = nc
        .put_single_shot(
            &put_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"test"))
            })),
        )
        .await
        .expect_err("missing parent on server must fail with 409");
    assert_eq!(err.kind, ErrorKind::PreconditionFailed);

    // Retry: because `known_dirs` evicted `evict` and `evict/sub`, next PUT recreates them!
    nc.put_single_shot(
        &put_init,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from_static(b"test"))
        })),
    )
    .await
    .expect("PUT after 409 must recreate evicted parent dirs and succeed");
}

#[tokio::test]
async fn webdav_p1_sha1_oc_checksum_and_overwrite_false_and_mtime_and_custom_headers() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.x_hash_supported = false;
        g.validate_oc_checksum = true;
    }

    let mut oc_cfg = WebdavConfig::new("oc-sha1", format!("http://{addr}{ROOT}"));
    oc_cfg.vendor = WebdavVendor::Owncloud;
    oc_cfg.headers = vec![("X-Rship-Custom".into(), "magic-val".into())];
    let oc = WebdavBackend::new(
        oc_cfg,
        HttpTransport::new(TransportConfig::default()).unwrap(),
    )
    .unwrap();

    let data = b"sha1-verified-webdav-payload".to_vec();
    let sha1 = sha1_hex_ref(&data);
    let path = RelPath::parse("sha1/ok.bin").unwrap();
    let init = UploadInit {
        op_id: "op-sha1-ok".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        // Sub-second timestamp -> server stores whole seconds!
        src_mtime_ns: 1_700_000_000_123_456_789,
        planned_chunk_size: data.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Sha1,
            hex: sha1.clone(),
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let d1 = data.clone();
    let uploaded = oc
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(d1)) })),
        )
        .await
        .expect("SHA1 OC-Checksum upload must succeed");
    assert_eq!(
        uploaded.mtime_ns, 1_700_000_000_000_000_000,
        "X-OC-Mtime accepted response must normalize mtime_ns to whole seconds"
    );

    // Full download verifies SHA1 OC-Checksum, and corruption triggers integrity error.
    let ds = oc
        .open_read(&BackendPath::from_rel(path.clone()), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut got = Vec::new();
    let mut s = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: data.len() as u64,
        })
        .await
        .unwrap();
    while let Some(c) = s.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got, data);

    st.lock().unwrap().corrupt_download_body_once = true;
    let mut s_bad = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: data.len() as u64,
        })
        .await
        .unwrap();
    let mut dl_err = None;
    while let Some(item) = s_bad.next().await {
        if let Err(e) = item {
            dl_err = Some(e);
            break;
        }
    }
    let dl_err = dl_err.expect("corrupted SHA1 download must fail");
    assert!(
        dl_err.message().contains("checksum mismatch (SHA1)"),
        "got: {dl_err:?}"
    );

    // Verify custom header was sent on control (PROPFIND) and data (PUT/GET) requests!
    {
        let g = st.lock().unwrap();
        for method in ["PROPFIND", "PUT", "GET"] {
            assert!(
                g.requests_seen.iter().any(|(m, _, h)| {
                    m == method
                        && h.get("x-rship-custom").and_then(|v| v.to_str().ok())
                            == Some("magic-val")
                }),
                "missing custom header on {method}"
            );
        }
    }

    // Overwrite: F when DstPrecondition::Absent on COPY & MOVE .file!
    let copy_absent = UploadInit {
        op_id: "op-copy-absent".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: data.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let copy_err = oc
        .server_side_copy(
            &oc.endpoint_identity(),
            &BackendPath::from_rel(path.clone()),
            &copy_absent,
        )
        .await
        .expect_err("COPY with DstPrecondition::Absent against existing target must fail 412");
    assert_eq!(copy_err.kind, ErrorKind::PreconditionFailed);

    let sess = oc.begin_upload(&copy_absent).await.unwrap();
    let op = make_op(&oc, &copy_absent, &sess);
    let d2 = data.clone();
    oc.upload_chunk(
        &op,
        ChunkUpload::new(
            1,
            0,
            data.len() as u64,
            data.len() as u64,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(d2)) })),
        ),
    )
    .await
    .unwrap();
    let move_err = oc.finish_upload(&op, &[]).await.expect_err(
        "MOVE .file with DstPrecondition::Absent against existing target must fail 412",
    );
    assert_eq!(move_err.kind, ErrorKind::PreconditionFailed);

    // Server ignoring X-OC-Mtime falls back to stat() for accurate server mtime; Generic never sends X-OC-Mtime.
    st.lock().unwrap().ignore_x_oc_mtime = true;
    let nc = nc_backend(&addr);
    let fallback_entry = nc
        .put_single_shot(
            &UploadInit {
                op_id: "op-mtime-fallback".into(),
                dst_path: RelPath::parse("mtime/ignored.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 3,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 3,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abc"))
            })),
        )
        .await
        .unwrap();
    // Mock server default mtime when `g.mtimes` has no entry is `Tue, 24 Nov 2026 12:00:00 GMT` (> 1_795_000_000s).
    assert!(
        fallback_entry.mtime_ns > 1_790_000_000_000_000_000,
        "expected server-assigned mtime from stat fallback, got {}",
        fallback_entry.mtime_ns
    );

    let mut gen_cfg = WebdavConfig::new("gen-mtime", format!("http://{addr}{ROOT}"));
    gen_cfg.vendor = WebdavVendor::Generic;
    let generic_dav = WebdavBackend::new(
        gen_cfg,
        HttpTransport::new(TransportConfig::default()).unwrap(),
    )
    .unwrap();
    assert!(!generic_dav.capabilities().can_set_mtime);
    st.lock().unwrap().requests_seen.clear();
    generic_dav
        .put_single_shot(
            &UploadInit {
                op_id: "op-gen-mtime".into(),
                dst_path: RelPath::parse("mtime/generic.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 3,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 3,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abc"))
            })),
        )
        .await
        .unwrap();
    let gen_put = st
        .lock()
        .unwrap()
        .requests_seen
        .iter()
        .find(|(m, _, _)| m == "PUT")
        .cloned()
        .unwrap();
    assert!(gen_put.2.get("x-oc-mtime").is_none());
}

#[tokio::test]
async fn webdav_r2_truncated_207_and_propfind_xml_fail_with_protocol_error() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/trunc_del.txt"), b"hello".to_vec());
    }
    let backend = nc_backend(&addr);

    // 1. Truncated 207 on DELETE (closed 200 followed by unclosed 403) must fail with Protocol.
    let truncated_207 = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/remote.php/dav/files/alice/ok.txt</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>
  <d:response><d:href>/remote.php/dav/files/alice/trunc_del.txt</d:href><d:status>HTTP/1.1 403 Forbidden"#;
    st.lock().unwrap().scripted_responses.push_back((
        "DELETE".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        truncated_207.into(),
    ));
    let err = backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("trunc_del.txt").unwrap(),
        ))
        .await
        .expect_err("truncated 207 on DELETE must fail");
    assert_eq!(err.kind, ErrorKind::Protocol);

    // 2. Truncated PROPFIND on list_stream must yield Err(Protocol).
    let truncated_propfind = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/alice/real.txt</d:href>
    <d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/cut.txt</d:href>"#;
    st.lock().unwrap().scripted_responses.push_back((
        "PROPFIND".into(),
        StatusCode::MULTI_STATUS,
        vec![("content-type".into(), "application/xml".into())],
        truncated_propfind.into(),
    ));
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .collect()
        .await;
    assert_eq!(listed.len(), 1);
    let list_err = listed[0]
        .as_ref()
        .expect_err("truncated PROPFIND must surface Protocol error");
    assert_eq!(list_err.kind, ErrorKind::Protocol);
}

#[tokio::test]
async fn webdav_r2_redirects_refused_cross_origin_and_303_and_safe_same_origin_under_both_dump_modes()
 {
    use axum::Router;
    use axum::extract::{OriginalUri, State as AxState};
    use axum::http::{HeaderMap, Method};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct ForeignHits {
        hits: Vec<(String, String, HeaderMap)>,
    }

    let foreign_state = Arc::new(Mutex::new(ForeignHits::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let foreign_addr = listener.local_addr().unwrap().to_string();
    let foreign_app = Router::new()
        .fallback(
            |AxState(st): AxState<Arc<Mutex<ForeignHits>>>,
             method: Method,
             OriginalUri(uri): OriginalUri,
             headers: HeaderMap| async move {
                st.lock().unwrap().hits.push((
                    method.as_str().to_string(),
                    uri.path().to_string(),
                    headers,
                ));
                StatusCode::OK
            },
        )
        .with_state(foreign_state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, foreign_app).await;
    });

    for dump_mode in [HttpDumpMode::None, HttpDumpMode::Headers] {
        let (addr, st) = start_mock_dav().await;
        foreign_state.lock().unwrap().hits.clear();

        let mut cfg = WebdavConfig::new("nc-redir", format!("http://{addr}{ROOT}"));
        cfg.vendor = WebdavVendor::Nextcloud;
        cfg.auth = WebdavAuth::Basic {
            username: "alice".into(),
            password: "secret".into(),
        };
        cfg.headers = vec![("X-Custom-Secret".into(), "top-secret-token".into())];
        cfg.max_retries = 0;

        let mut tcfg = TransportConfig::default();
        tcfg.dump_mode = dump_mode;
        let backend = WebdavBackend::new(cfg, HttpTransport::new(tcfg).unwrap()).unwrap();

        {
            let mut g = st.lock().unwrap();
            g.files.insert(
                format!("{ROOT}/src.txt"),
                b"redirect-range-payload".to_vec(),
            );
            g.files
                .insert(format!("{ROOT}/ren.txt"), b"rename-payload".to_vec());
            g.files
                .insert(format!("{ROOT}/del.txt"), b"delete-payload".to_vec());
            g.dirs.insert(format!("{ROOT}/same_dir"));
        }

        // 1. Control plane: cross-origin 302 across PROPFIND/MKCOL/DELETE/COPY/MOVE -> Protocol, 0 foreign hits.
        for (op_name, action_label) in [
            ("PROPFIND", "stat"),
            ("MKCOL", "mkdir"),
            ("DELETE", "delete"),
            ("COPY", "copy"),
            ("MOVE", "rename"),
        ] {
            st.lock().unwrap().scripted_responses.push_back((
                op_name.into(),
                StatusCode::FOUND,
                vec![(
                    "location".into(),
                    format!("http://{foreign_addr}/evil/{op_name}"),
                )],
                String::new(),
            ));
            let err = match action_label {
                "stat" => backend
                    .stat(&BackendPath::from_rel(RelPath::parse("src.txt").unwrap()))
                    .await
                    .expect_err("cross-origin 302 on PROPFIND must fail"),
                "mkdir" => backend
                    .mkdir(&RelPath::parse("xorig_dir").unwrap())
                    .await
                    .expect_err("cross-origin 302 on MKCOL must fail"),
                "delete" => backend
                    .delete(&BackendPath::from_rel(RelPath::parse("del.txt").unwrap()))
                    .await
                    .expect_err("cross-origin 302 on DELETE must fail"),
                "copy" => backend
                    .server_side_copy(
                        &backend.endpoint_identity(),
                        &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
                        &UploadInit {
                            op_id: "op-xorig-copy".into(),
                            dst_path: RelPath::parse("copy_dst.txt").unwrap(),
                            existing_node_id: None,
                            pregenerated_id: None,
                            total_size: 22,
                            src_mtime_ns: 1_700_000_000_000_000_000,
                            planned_chunk_size: 22,
                            checksums: vec![],
                            precondition: DstPrecondition::Any,
                            src_etag: None,
                        },
                    )
                    .await
                    .expect_err("cross-origin 302 on COPY must fail"),
                "rename" => backend
                    .rename(
                        &BackendPath::from_rel(RelPath::parse("ren.txt").unwrap()),
                        "ren2.txt",
                    )
                    .await
                    .expect_err("cross-origin 302 on MOVE must fail"),
                _ => unreachable!(),
            };
            assert_eq!(
                err.kind,
                ErrorKind::Protocol,
                "mode={dump_mode:?} op={op_name} got {err:?}"
            );
            assert!(
                foreign_state.lock().unwrap().hits.is_empty(),
                "mode={dump_mode:?} op={op_name} leaked request to foreign host!"
            );
        }

        // 2. Control plane: 303 See Other (even same-origin) must fail with Protocol and NEVER downgrade to GET.
        for (op_name, is_mkcol) in [("PROPFIND", false), ("MKCOL", true), ("DELETE", false)] {
            st.lock().unwrap().requests_seen.clear();
            st.lock().unwrap().scripted_responses.push_back((
                op_name.into(),
                StatusCode::SEE_OTHER,
                vec![("location".into(), format!("{ROOT}/same_dir/"))],
                String::new(),
            ));
            let err = if is_mkcol {
                backend
                    .mkdir(&RelPath::parse("see_other_dir").unwrap())
                    .await
                    .unwrap_err()
            } else if op_name == "PROPFIND" {
                backend
                    .stat(&BackendPath::from_rel(RelPath::parse("src.txt").unwrap()))
                    .await
                    .unwrap_err()
            } else {
                backend
                    .delete(&BackendPath::from_rel(RelPath::parse("del.txt").unwrap()))
                    .await
                    .unwrap_err()
            };
            assert_eq!(err.kind, ErrorKind::Protocol);
            assert!(
                st.lock()
                    .unwrap()
                    .requests_seen
                    .iter()
                    .all(|(m, _, _)| m != "GET"),
                "mode={dump_mode:?} 303 on {op_name} must not downgrade to GET"
            );
        }

        // 3. Control plane: same-origin 301/302 preserves method (PROPFIND/MKCOL/DELETE/COPY/MOVE) and succeeds.
        st.lock().unwrap().requests_seen.clear();
        st.lock().unwrap().scripted_responses.push_back((
            "PROPFIND".into(),
            StatusCode::FOUND,
            vec![("location".into(), format!("{ROOT}/src.txt"))],
            String::new(),
        ));
        let st_ok = backend
            .stat(&BackendPath::from_rel(RelPath::parse("src.txt").unwrap()))
            .await
            .unwrap()
            .expect("same-origin 302 on PROPFIND must succeed");
        assert_eq!(st_ok.size, 22);
        st.lock().unwrap().scripted_responses.push_back((
            "MKCOL".into(),
            StatusCode::MOVED_PERMANENTLY,
            vec![("location".into(), format!("{ROOT}/same_mkcol_2/"))],
            String::new(),
        ));
        backend
            .mkdir(&RelPath::parse("same_mkcol_1").unwrap())
            .await
            .expect("same-origin 301 on MKCOL must succeed");
        assert!(
            st.lock()
                .unwrap()
                .dirs
                .contains(&format!("{ROOT}/same_mkcol_2"))
        );

        // Same-origin 302 on COPY, MOVE (rename), and DELETE.
        st.lock().unwrap().scripted_responses.push_back((
            "COPY".into(),
            StatusCode::FOUND,
            vec![("location".into(), format!("{ROOT}/src.txt"))],
            String::new(),
        ));
        backend
            .server_side_copy(
                &backend.endpoint_identity(),
                &BackendPath::from_rel(RelPath::parse("del.txt").unwrap()),
                &UploadInit {
                    op_id: "op-same-copy".into(),
                    dst_path: RelPath::parse("same_copied.txt").unwrap(),
                    existing_node_id: None,
                    pregenerated_id: None,
                    total_size: 22,
                    src_mtime_ns: 1_700_000_000_000_000_000,
                    planned_chunk_size: 22,
                    checksums: vec![],
                    precondition: DstPrecondition::Any,
                    src_etag: None,
                },
            )
            .await
            .expect("same-origin 302 on COPY must succeed");
        assert!(
            st.lock()
                .unwrap()
                .files
                .contains_key(&format!("{ROOT}/same_copied.txt"))
        );

        st.lock().unwrap().scripted_responses.push_back((
            "MOVE".into(),
            StatusCode::TEMPORARY_REDIRECT,
            vec![("location".into(), format!("{ROOT}/same_copied.txt"))],
            String::new(),
        ));
        backend
            .rename(
                &BackendPath::from_rel(RelPath::parse("ren.txt").unwrap()),
                "same_renamed.txt",
            )
            .await
            .expect("same-origin 307 on MOVE must succeed");
        assert!(
            st.lock()
                .unwrap()
                .files
                .contains_key(&format!("{ROOT}/same_renamed.txt"))
        );

        st.lock().unwrap().scripted_responses.push_back((
            "DELETE".into(),
            StatusCode::MOVED_PERMANENTLY,
            vec![("location".into(), format!("{ROOT}/same_renamed.txt"))],
            String::new(),
        ));
        backend
            .delete(&BackendPath::from_rel(RelPath::parse("del.txt").unwrap()))
            .await
            .expect("same-origin 301 on DELETE must succeed");
        assert!(
            !st.lock()
                .unwrap()
                .files
                .contains_key(&format!("{ROOT}/same_renamed.txt"))
        );

        assert!(
            st.lock()
                .unwrap()
                .requests_seen
                .iter()
                .all(|(m, _, _)| m != "GET"),
            "mode={dump_mode:?} same-origin 301/302/307 must preserve WebDAV verb"
        );

        // 4. Data plane GET(Range): cross-origin 302 & 303 fail with 0 foreign hits; same-origin 302 preserves Range & headers.
        let ds = backend
            .open_read(
                &BackendPath::from_rel(RelPath::parse("src.txt").unwrap()),
                None,
            )
            .await
            .unwrap();
        let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
            panic!("expected RemoteRangeReadable");
        };

        st.lock().unwrap().scripted_responses.push_back((
            "GET".into(),
            StatusCode::FOUND,
            vec![("location".into(), format!("http://{foreign_addr}/steal"))],
            String::new(),
        ));
        let get_xorig_err = match rr
            .open_range(rship_core::types::ByteRange { offset: 0, len: 8 })
            .await
        {
            Ok(_) => panic!("cross-origin 302 on GET(Range) must fail"),
            Err(e) => e,
        };
        assert_eq!(get_xorig_err.kind, ErrorKind::Protocol);
        assert!(
            foreign_state.lock().unwrap().hits.is_empty(),
            "mode={dump_mode:?} GET(Range) leaked custom header to foreign host!"
        );

        st.lock().unwrap().scripted_responses.push_back((
            "GET".into(),
            StatusCode::SEE_OTHER,
            vec![("location".into(), format!("{ROOT}/src.txt"))],
            String::new(),
        ));
        let get_303_err = match rr
            .open_range(rship_core::types::ByteRange { offset: 0, len: 8 })
            .await
        {
            Ok(_) => panic!("303 on GET(Range) must fail"),
            Err(e) => e,
        };
        assert_eq!(get_303_err.kind, ErrorKind::Protocol);

        st.lock().unwrap().requests_seen.clear();
        st.lock().unwrap().scripted_responses.push_back((
            "GET".into(),
            StatusCode::FOUND,
            vec![("location".into(), format!("{ROOT}/src.txt"))],
            String::new(),
        ));
        let mut s_ok = rr
            .open_range(rship_core::types::ByteRange { offset: 9, len: 5 })
            .await
            .expect("same-origin 302 on GET(Range) must succeed");
        let mut range_bytes = Vec::new();
        while let Some(c) = s_ok.next().await {
            range_bytes.extend_from_slice(&c.unwrap());
        }
        assert_eq!(range_bytes, b"range");
        assert_eq!(
            st.lock()
                .unwrap()
                .requests_seen
                .iter()
                .filter(|(m, _, h)| m == "GET"
                    && h.get("range").and_then(|v| v.to_str().ok()) == Some("bytes=9-13")
                    && h.get("x-custom-secret").and_then(|v| v.to_str().ok())
                        == Some("top-secret-token"))
                .count(),
            2,
            "mode={dump_mode:?} GET(Range) must preserve Range and custom headers across same-origin 302"
        );

        // 5. Data plane PUT (single-shot & upload_chunk): cross-origin 302 & same-origin 303/302 refused, 0 foreign hits, never GET.
        for (status_code, loc) in [
            (StatusCode::FOUND, format!("http://{foreign_addr}/evil_put")),
            (StatusCode::SEE_OTHER, format!("{ROOT}/src.txt")),
            (StatusCode::MOVED_PERMANENTLY, format!("{ROOT}/src.txt")),
        ] {
            st.lock().unwrap().requests_seen.clear();
            st.lock().unwrap().scripted_responses.push_back((
                "PUT".into(),
                status_code,
                vec![("location".into(), loc.clone())],
                String::new(),
            ));
            let put_err = backend
                .put_single_shot(
                    &UploadInit {
                        op_id: "op-put-redir".into(),
                        dst_path: RelPath::parse("put_redir.bin").unwrap(),
                        existing_node_id: None,
                        pregenerated_id: None,
                        total_size: 4,
                        src_mtime_ns: 1_700_000_000_000_000_000,
                        planned_chunk_size: 4,
                        checksums: vec![],
                        precondition: DstPrecondition::Any,
                        src_etag: None,
                    },
                    Box::pin(futures::stream::once(async {
                        Ok(Bytes::from_static(b"abcd"))
                    })),
                )
                .await
                .expect_err("redirect on streaming single-shot PUT must be refused");
            assert_eq!(put_err.kind, ErrorKind::Protocol);
            assert!(
                foreign_state.lock().unwrap().hits.is_empty(),
                "mode={dump_mode:?} PUT {status_code} leaked to foreign host!"
            );
            assert!(
                st.lock()
                    .unwrap()
                    .requests_seen
                    .iter()
                    .all(|(m, _, _)| m != "GET"),
                "mode={dump_mode:?} PUT {status_code} must never downgrade to GET"
            );
        }

        // Also test upload_chunk (session PUT) cross-origin 302 & 303 refusal.
        let chunk_init = UploadInit {
            op_id: "op-chunk-redir".into(),
            dst_path: RelPath::parse("chunk_redir.bin").unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 4,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 4,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        };
        let sess = backend.begin_upload(&chunk_init).await.unwrap();
        let op = make_op(&backend, &chunk_init, &sess);
        for (status_code, loc) in [
            (
                StatusCode::FOUND,
                format!("http://{foreign_addr}/evil_chunk"),
            ),
            (StatusCode::SEE_OTHER, format!("{ROOT}/src.txt")),
        ] {
            st.lock().unwrap().requests_seen.clear();
            st.lock().unwrap().scripted_responses.push_back((
                "PUT".into(),
                status_code,
                vec![("location".into(), loc)],
                String::new(),
            ));
            let chunk_err = backend
                .upload_chunk(
                    &op,
                    ChunkUpload::new(
                        1,
                        0,
                        4,
                        4,
                        Box::pin(futures::stream::once(async {
                            Ok(Bytes::from_static(b"wxyz"))
                        })),
                    ),
                )
                .await
                .expect_err("redirect on upload_chunk PUT must be refused");
            assert_eq!(chunk_err.kind, ErrorKind::Protocol);
            assert!(foreign_state.lock().unwrap().hits.is_empty());
            assert!(
                st.lock()
                    .unwrap()
                    .requests_seen
                    .iter()
                    .all(|(m, _, _)| m != "GET")
            );
        }
    }
}

#[tokio::test]
async fn webdav_r2_streaming_sha1_multi_mb_oc_checksum_and_corruption_rejection() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.x_hash_supported = false;
        g.validate_oc_checksum = true;
    }

    let mut oc_cfg = WebdavConfig::new("oc-sha1-mb", format!("http://{addr}{ROOT}"));
    oc_cfg.vendor = WebdavVendor::Owncloud;
    let oc = WebdavBackend::new(
        oc_cfg,
        HttpTransport::new(TransportConfig::default()).unwrap(),
    )
    .unwrap();

    // > 2 MiB non-block-aligned payload streamed over multi-chunk HTTP response.
    let total_len = 2 * 1024 * 1024 + 17;
    let data: Vec<u8> = (0..total_len)
        .map(|i| ((i * 29 + 11) & 0xff) as u8)
        .collect();
    let sha1 = sha1_hex_ref(&data);
    let path = RelPath::parse("sha1/multi_mb.bin").unwrap();
    let init = UploadInit {
        op_id: "op-sha1-multi-mb".into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: data.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Sha1,
            hex: sha1,
        }],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let d1 = data.clone();
    oc.put_single_shot(
        &init,
        Box::pin(futures::stream::once(async move { Ok(Bytes::from(d1)) })),
    )
    .await
    .expect("2+ MiB SHA1 OC-Checksum upload must succeed");

    let ds = oc
        .open_read(&BackendPath::from_rel(path), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut got = Vec::with_capacity(total_len);
    let mut s = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: data.len() as u64,
        })
        .await
        .unwrap();
    while let Some(c) = s.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got, data);

    // Corrupted final byte in >2 MiB multi-chunk download must fail with ErrorKind::Integrity.
    st.lock().unwrap().corrupt_download_body_once = true;
    let mut s_bad = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: data.len() as u64,
        })
        .await
        .unwrap();
    let mut dl_err = None;
    while let Some(item) = s_bad.next().await {
        if let Err(e) = item {
            dl_err = Some(e);
            break;
        }
    }
    let dl_err = dl_err.expect("corrupted 2+ MiB SHA1 download must fail");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(
        dl_err.message().contains("checksum mismatch (SHA1)"),
        "got: {dl_err:?}"
    );
}
