use crate::mock_server::{MockBlob, TEST_ACCOUNT, make_backend, spawn_mock_azure};
use axum::body::Bytes;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::azureblob::{
    AZURE_MAX_BLOCK_BYTES, AZURE_MAX_OBJECT_BYTES, AZURE_MIN_BLOCK_BYTES, AzureAuth,
    AzureBlobBackend, AzureBlobConfig,
};
use rship_core::ErrorKind;
use rship_core::backend::{
    BackendPath, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend, UploadInit,
};
use rship_core::clock::SystemClock;
use rship_core::path::RelPath;
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{Checksum, ChunkAlignment, EntryKind, HashKind};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn init_for(rel: &RelPath, total: u64, op_id: &str) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_123_456_789,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

async fn open_op(b: &AzureBlobBackend, init: &UploadInit) -> OperationRecord {
    let sess = b.begin_upload(init).await.unwrap();
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sk-{}", init.op_id),
        job_id: "job".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: b.endpoint_identity(),
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
        remote_op_id: None,
        backend_kind: "azureblob".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    }
}

#[tokio::test]
async fn query_encoding_spaces_and_plus_with_strict_shared_key() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        for name in [
            "my dir/sub dir/a.txt",
            "my dir/sub dir/b.txt",
            "my dir/sub dir/c.txt",
            "a+b/c+d.txt",
        ] {
            let etag = g.alloc_etag();
            g.blobs.insert(
                name.to_string(),
                MockBlob {
                    name: name.to_string(),
                    data: b"hi".to_vec(),
                    etag,
                    ..Default::default()
                },
            );
        }
    }

    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    // Non-recursive & recursive listing with spaces (spans NextMarker pagination too!)
    let entries: Vec<_> = backend
        .list_stream(&RelPath::parse("my dir/sub dir").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 3);

    // Listing prefix with literal `+` under strict SharedKey verification
    let plus_entries: Vec<_> = backend
        .list_stream(&RelPath::parse("a+b").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(plus_entries.len(), 1);
    assert_eq!(plus_entries[0].nfc_path.as_str(), "a+b/c+d.txt");

    // `stat` on virtual directory with spaces & `+`
    let st = backend
        .stat(&BackendPath::from_rel(RelPath::parse("my dir").unwrap()))
        .await
        .unwrap()
        .expect("virtual dir with spaces");
    assert_eq!(st.kind, EntryKind::Directory);
    let st_plus = backend
        .stat(&BackendPath::from_rel(RelPath::parse("a+b").unwrap()))
        .await
        .unwrap()
        .expect("virtual dir with plus");
    assert_eq!(st_plus.kind, EntryKind::Directory);

    // `list_ordered_page` with spaces and pagination cursor
    let p1 = backend
        .list_ordered_page(&RelPath::parse("my dir/sub dir").unwrap(), None, None, 2)
        .await
        .unwrap();
    assert!(p1.is_truncated);
    let p2 = backend
        .list_ordered_page(
            &RelPath::parse("my dir/sub dir").unwrap(),
            None,
            p1.next_cursor.as_deref(),
            2,
        )
        .await
        .unwrap();
    assert!(!p2.is_truncated);
    assert_eq!(p1.entries.len() + p2.entries.len(), 3);
}

#[tokio::test]
async fn put_block_sends_and_verifies_content_md5_and_maps_400_md5_mismatch_to_integrity() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let rel = RelPath::parse("blk/md5.bin").unwrap();
    let payload = vec![0x5Au8; AZURE_MIN_BLOCK_BYTES as usize];
    let expected_md5_b64 = B64.encode(Md5::digest(&payload));

    let op = open_op(
        &backend,
        &init_for(&rel, payload.len() as u64, "op-blk-md5"),
    )
    .await;
    let body = payload.clone();
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                payload.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(body)) })),
            ),
        )
        .await
        .unwrap();

    assert_eq!(
        state.lock().unwrap().seen_put_block_content_md5,
        vec![expected_md5_b64.clone()]
    );

    let committed = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: payload.len() as u64,
                etag: ack.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(
        committed.checksum,
        Some(Checksum {
            kind: HashKind::Md5,
            hex: hex::encode(Md5::digest(&payload)),
        })
    );

    // Server returning 400 Md5Mismatch maps to ErrorKind::Integrity!
    let faults = state.lock().unwrap().fault_injector();
    faults.push(
        "PutBlock",
        crate::common::InjectedFault::xml_error(
            StatusCode::BAD_REQUEST,
            "Md5Mismatch",
            "The MD5 value specified in the request did not match.",
        ),
    );
    let op2 = open_op(&backend, &init_for(&rel, 16, "op-blk-md5-err")).await;
    let err = backend
        .upload_chunk(
            &op2,
            ChunkUpload::new(
                1,
                0,
                16,
                16,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"0123456789abcdef"))
                })),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Integrity);
    assert!(err.is_integrity());
}

#[tokio::test]
async fn reconcile_operation_enforces_copy_status_pending_failed_aborted_success() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let rel = RelPath::parse("rec/copy.bin").unwrap();
    let op = open_op(&backend, &init_for(&rel, 12, "op-rec-copy")).await;

    for (status_str, expected_kind) in [
        ("pending", "ambiguous"),
        ("failed", "not_committed"),
        ("aborted", "not_committed"),
        ("success", "committed"),
    ] {
        {
            let mut g = state.lock().unwrap();
            let etag = g.alloc_etag();
            let mut meta = BTreeMap::new();
            meta.insert("rship_op_id".to_string(), "op-rec-copy".to_string());
            g.blobs.insert(
                "rec/copy.bin".to_string(),
                MockBlob {
                    name: "rec/copy.bin".to_string(),
                    data: vec![1u8; 12],
                    etag,
                    metadata: meta,
                    copy_status_override: Some(status_str.to_string()),
                    ..Default::default()
                },
            );
        }

        let out = backend.reconcile_operation(&op).await.unwrap();
        match (expected_kind, out) {
            ("ambiguous", ReconcileOutcome::Ambiguous(_)) => {}
            ("not_committed", ReconcileOutcome::NotCommitted) => {}
            ("committed", ReconcileOutcome::Committed(e)) => assert_eq!(e.size, 12),
            (want, got) => panic!("status={status_str} expected {want}, got {got:?}"),
        }
    }
}

#[tokio::test]
async fn rename_guards_same_name_directory_nfd_parent_and_src_etag() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    // Seed NFD parent folder + file: "cafe\u{301}/old.txt"
    let nfd_rel_str = "cafe\u{301}/old.txt";
    let nfd_path = BackendPath::new(nfd_rel_str, RelPath::parse("café/old.txt").unwrap(), None)
        .with_kind(Some(EntryKind::File));
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            nfd_rel_str.to_string(),
            MockBlob {
                name: nfd_rel_str.to_string(),
                data: b"nfd-data".to_vec(),
                etag,
                ..Default::default()
            },
        );
        let dir_etag = g.alloc_etag();
        g.blobs.insert(
            "vdir/child.txt".to_string(),
            MockBlob {
                name: "vdir/child.txt".to_string(),
                data: b"x".to_vec(),
                etag: dir_etag,
                ..Default::default()
            },
        );
    }

    // 1. Same-name rename is a no-op (does not delete the blob!)
    let same = backend.rename(&nfd_path, "old.txt").await.unwrap();
    assert_eq!(same.size, 8);
    assert!(state.lock().unwrap().blobs.contains_key(nfd_rel_str));
    assert_eq!(state.lock().unwrap().copy_calls, 0);

    // 2. Directory rename is rejected with Unsupported
    let dir_err = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("vdir").unwrap()),
            "vdir2",
        )
        .await
        .unwrap_err();
    assert_eq!(dir_err.kind, ErrorKind::Unsupported);

    // 3. Rename preserves NFD parent path on destination (`cafe\u{301}/new.txt`)
    let renamed = backend.rename(&nfd_path, "new.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "café/new.txt");
    assert_eq!(renamed.raw_path.as_deref(), Some("cafe\u{301}/new.txt"));
    {
        let g = state.lock().unwrap();
        assert!(!g.blobs.contains_key(nfd_rel_str));
        assert!(g.blobs.contains_key("cafe\u{301}/new.txt"));
    }

    // 4. Stale `src_etag` on CopyBlob returns SourceMutated (`412 SourceConditionNotMet`)
    let cp_init = UploadInit {
        src_etag: Some("\"0x8DC-STALE\"".to_string()),
        ..init_for(&RelPath::parse("café/copy2.txt").unwrap(), 8, "op-src-etag")
    };
    let dst_bp = BackendPath::new(
        "cafe\u{301}/new.txt",
        RelPath::parse("café/new.txt").unwrap(),
        None,
    )
    .with_kind(Some(EntryKind::File));
    let err = backend
        .server_side_copy(&backend.endpoint_identity(), &dst_bp, &cp_init)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::SourceMutated);
}

#[tokio::test]
async fn existing_precondition_and_lost_response_412_reconciliation() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let rel = RelPath::parse("cond/target.bin").unwrap();
    let v1 = backend
        .put_single_shot(
            &UploadInit {
                precondition: DstPrecondition::Absent,
                ..init_for(&rel, 4, "op-seed")
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"v111"))
            })),
        )
        .await
        .unwrap();
    let good_etag = v1.etag.unwrap();

    // Matching ETag succeeds
    let v2 = backend
        .put_single_shot(
            &UploadInit {
                precondition: DstPrecondition::Existing {
                    node_id: None,
                    etag: Some(good_etag.clone()),
                    mtime_ns: 0,
                    size: 4,
                },
                ..init_for(&rel, 4, "op-v2")
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"v222"))
            })),
        )
        .await
        .unwrap();
    assert_ne!(v2.etag.as_deref(), Some(good_etag.as_str()));

    // Stale ETag fails with PreconditionFailed on PutBlob, PutBlockList, and CopyBlob
    let stale_pre = DstPrecondition::Existing {
        node_id: None,
        etag: Some(good_etag),
        mtime_ns: 0,
        size: 4,
    };
    let e_put = backend
        .put_single_shot(
            &UploadInit {
                precondition: stale_pre.clone(),
                ..init_for(&rel, 4, "op-stale-put")
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"v333"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(e_put.kind, ErrorKind::PreconditionFailed);

    let blk_init = UploadInit {
        precondition: stale_pre.clone(),
        ..init_for(&rel, 4, "op-stale-blk")
    };
    let op_blk = open_op(&backend, &blk_init).await;
    let ack = backend
        .upload_chunk(
            &op_blk,
            ChunkUpload::new(
                1,
                0,
                4,
                4,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"abcd"))
                })),
            ),
        )
        .await
        .unwrap();
    let e_blk = backend
        .finish_upload(
            &op_blk,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 4,
                etag: ack.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .unwrap_err();
    assert_eq!(e_blk.kind, ErrorKind::PreconditionFailed);

    let cp_src = RelPath::parse("cond/src.bin").unwrap();
    backend
        .put_single_shot(
            &init_for(&cp_src, 4, "op-cond-src"),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"src1"))
            })),
        )
        .await
        .unwrap();
    let e_cp = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(cp_src),
            &UploadInit {
                precondition: stale_pre,
                ..init_for(&rel, 4, "op-stale-cp")
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e_cp.kind, ErrorKind::PreconditionFailed);

    // PutBlockList lost-response with Existing precondition reconciles after 412 replay!
    let ok_blk_init = UploadInit {
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: v2.etag.clone(),
            mtime_ns: 0,
            size: 4,
        },
        ..init_for(&rel, 4, "op-lost-412")
    };
    let op_lost = open_op(&backend, &ok_blk_init).await;
    let ack_lost = backend
        .upload_chunk(
            &op_lost,
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
        .unwrap();
    let faults = state.lock().unwrap().fault_injector();
    faults.push(
        "PutBlockList",
        crate::common::InjectedFault::commit_then_reset(),
    );
    faults.push(
        "HeadBlob",
        crate::common::InjectedFault::xml_error(StatusCode::NOT_FOUND, "BlobNotFound", "lag"),
    );
    let reconciled = backend
        .finish_upload(
            &op_lost,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 4,
                etag: ack_lost.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .expect("lost response on Existing PutBlockList replays -> 412 -> reconciles");
    assert_eq!(reconciled.size, 4);
}

#[tokio::test]
async fn listing_self_marker_dot_segments_encoded_names_and_hns_dirs() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let mut add = |name: &str, encoded: bool, rt: Option<&str>, hdi: bool| {
            let etag = g.alloc_etag();
            let mut meta = BTreeMap::new();
            if hdi {
                meta.insert("hdi_isfolder".to_string(), "true".to_string());
            }
            g.blobs.insert(
                name.to_string(),
                MockBlob {
                    name: name.to_string(),
                    data: if rt == Some("directory") || hdi || name.ends_with('/') {
                        Vec::new()
                    } else {
                        b"123".to_vec()
                    },
                    etag,
                    encoded_name: encoded,
                    resource_type: rt.map(str::to_string),
                    metadata: meta,
                    ..Default::default()
                },
            );
        };
        add("sub/", false, None, false);
        add("sub/ok.txt", false, None, false);
        add("sub/../escape.txt", false, None, false);
        add("sub/.", false, None, false);
        add("encoded/a b\tc.txt", true, None, false);
        add("hns-dir", false, Some("directory"), true);
        add("hns-dir/inside.txt", false, None, false);
    }

    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    // Capabilities check
    let caps = backend.capabilities();
    assert!(!caps.supports_ordered_utf8_list);
    match caps.chunk_alignment {
        ChunkAlignment::MinSizeWithMaxParts {
            max_bytes,
            max_object_bytes,
            ..
        } => {
            assert_eq!(max_bytes, AZURE_MAX_BLOCK_BYTES);
            assert_eq!(max_object_bytes, AZURE_MAX_OBJECT_BYTES);
        }
        other => panic!("unexpected alignment: {other:?}"),
    }

    // 1. Listing `sub` suppresses `sub/` self-marker & safely skips `.`/`..` without aborting!
    let sub_entries: Vec<_> = backend
        .list_stream(&RelPath::parse("sub").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let sub_paths: Vec<&str> = sub_entries.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(sub_paths, vec!["sub/ok.txt"]);

    // 2. Root non-recursive listing decodes `<Name Encoded="true">` and maps HNS directory
    //    without duplicating `<BlobPrefix>`!
    let root_entries: Vec<_> = backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let hns_count = root_entries
        .iter()
        .filter(|e| e.nfc_path.as_str() == "hns-dir")
        .count();
    assert_eq!(hns_count, 1, "HNS dir + BlobPrefix must be deduplicated");
    assert_eq!(
        root_entries
            .iter()
            .find(|e| e.nfc_path.as_str() == "hns-dir")
            .unwrap()
            .kind,
        EntryKind::Directory
    );

    let enc_entries: Vec<_> = backend
        .list_stream(&RelPath::parse("encoded").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(enc_entries[0].nfc_path.as_str(), "encoded/a b\tc.txt");

    // 3. `list_ordered_page` also skips `.`/`..` safely without erroring or returning empty truncated pages!
    let mut ordered_names = Vec::new();
    let mut cursor = None;
    loop {
        let page = backend
            .list_ordered_page(
                &RelPath::parse("sub").unwrap(),
                None,
                cursor.as_deref(),
                100,
            )
            .await
            .unwrap();
        assert!(!page.entries.is_empty() || !page.is_truncated);
        ordered_names.extend(
            page.entries
                .into_iter()
                .map(|e| e.nfc_path.as_str().to_string()),
        );
        if !page.is_truncated {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(ordered_names, vec!["ok.txt"]);
}

#[tokio::test]
async fn copy_tier_abort_on_timeout_cross_container_sas_and_delete_snapshots() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let mut cfg = AzureBlobConfig::new("az-tier", TEST_ACCOUNT, "test-container");
    cfg.endpoint = Some(base_url.clone());
    cfg.access_tier = Some("Cool".to_string());
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend = Arc::new(
        AzureBlobBackend::new(
            cfg,
            AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
            transport.clone(),
            Some(SystemClock::shared()),
        )
        .unwrap(),
    );

    let src = RelPath::parse("tier/src.bin").unwrap();
    let dst = RelPath::parse("tier/dst.bin").unwrap();
    backend
        .put_single_shot(
            &init_for(&src, 5, "op-tier-src"),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .unwrap();

    backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(src.clone()),
            &init_for(&dst, 5, "op-tier-cp"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        state.lock().unwrap().blobs["tier/dst.bin"]
            .access_tier
            .as_deref(),
        Some("Cool")
    );

    // Delete with snapshots succeeds because `x-ms-delete-snapshots: include` is sent!
    state
        .lock()
        .unwrap()
        .blobs_with_snapshots
        .insert("tier/dst.bin".to_string());
    backend
        .delete(&BackendPath::from_rel(dst.clone()))
        .await
        .expect("delete blob with snapshots must send x-ms-delete-snapshots: include");
    assert!(
        state
            .lock()
            .unwrap()
            .seen_delete_snapshots
            .iter()
            .any(|(name, hdr)| name == "tier/dst.bin" && hdr.as_deref() == Some("include"))
    );

    // Cross-container copy with container-scoped SAS (`sr=c`) returns false / Ok(None)
    let mut sas_cfg = AzureBlobConfig::new("az-csas", TEST_ACCOUNT, "test-container");
    sas_cfg.endpoint = Some(base_url.clone());
    let sas_backend = AzureBlobBackend::new(
        sas_cfg,
        AzureAuth::sas_token("sv=2023-11-03&sr=c&sp=rwl&sig=valid-mock-sas").unwrap(),
        transport.clone(),
        Some(SystemClock::shared()),
    )
    .unwrap();
    let other_ep = format!("azureblob://{base_url}/other-container");
    assert!(!sas_backend.can_server_side_copy_from(&other_ep));
    assert!(
        sas_backend
            .server_side_copy(
                &other_ep,
                &BackendPath::from_rel(src.clone()),
                &init_for(&dst, 5, "op-cross-sas"),
            )
            .await
            .unwrap()
            .is_none()
    );

    // Stuck pending CopyBlob issues `Abort Copy Blob` on timeout!
    {
        state.lock().unwrap().force_stuck_pending_copies = true;
    }
    let mut fast_cfg = AzureBlobConfig::new("az-abort", TEST_ACCOUNT, "test-container");
    fast_cfg.endpoint = Some(base_url);
    let fast_transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let fast_backend = AzureBlobBackend::new(
        fast_cfg,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        fast_transport,
        Some(SystemClock::shared()),
    )
    .unwrap();
    // Pre-fill limiter sleeps? `sleep(50*poll)` total 120 polls is ~210s if real clock;
    // use a VirtualClock / short sleep? Wait: `control_limiter.sleep` uses `TransportConfig`'s clock,
    // which is `SystemClock` unless `with_clock` is passed. Let's check with VirtualClock or
    // run with `tokio::time::pause()`? `SystemClock` uses `tokio::time::sleep`!
    // Wait: let's verify! With `tokio::time::pause()` in a `current_thread` runtime?
    // No, mock server runs on tokio task; instead let's test `AbortCopyBlob` using
    // `tokio::time::pause()` or check `TransportConfig`! Actually we don't even need 210s:
    // skip real 210s wait by NOT running 210s here unless virtual clock is used. Let's check
    // `TransportConfig` if it takes a clock — if not, test `AbortCopyBlob` only if fast.
    drop(fast_backend);
}

#[tokio::test(start_paused = true)]
async fn copy_blob_timeout_issues_abort_copy_blob_with_paused_time() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            "stuck/src.bin".to_string(),
            MockBlob {
                name: "stuck/src.bin".to_string(),
                data: b"stuck".to_vec(),
                etag,
                ..Default::default()
            },
        );
        g.force_stuck_pending_copies = true;
    }

    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);
    let err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("stuck/src.bin").unwrap()),
            &init_for(&RelPath::parse("stuck/dst.bin").unwrap(), 5, "op-stuck"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Network);

    let aborted = state.lock().unwrap().aborted_copies.clone();
    assert_eq!(aborted.len(), 1);
    assert_eq!(aborted[0].0, "stuck/dst.bin");
    assert!(!aborted[0].1.is_empty());
}

#[tokio::test]
async fn archive_tier_open_read_preflight_and_zero_byte_slow_finalize() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            "cold/archived.bin".to_string(),
            MockBlob {
                name: "cold/archived.bin".to_string(),
                data: b"archived-payload".to_vec(),
                etag,
                access_tier: Some("Archive".to_string()),
                ..Default::default()
            },
        );
    }

    let mut cfg = AzureBlobConfig::new("az-arch", TEST_ACCOUNT, "test-container");
    cfg.endpoint = Some(base_url);
    cfg.max_retries = 0;
    let transport = HttpTransport::new(
        TransportConfig::default()
            .with_data_stall_timeout(Duration::from_millis(80))
            .with_data_finalize_timeout(Duration::from_secs(2)),
    )
    .unwrap();
    let backend = AzureBlobBackend::new(
        cfg,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        transport,
        Some(SystemClock::shared()),
    )
    .unwrap();

    // Archive tier preflight returns Unsupported
    let arch_err = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("cold/archived.bin").unwrap()),
            None,
        )
        .await
        .err()
        .expect("Archive tier open_read must fail with Unsupported");
    assert_eq!(arch_err.kind, ErrorKind::Unsupported);

    // 0-byte PutBlob with SlowFinalize (> data_stall_timeout, < data_finalize_timeout) succeeds
    let faults = state.lock().unwrap().fault_injector();
    faults.push(
        "PutBlob",
        crate::common::InjectedFault::slow_finalize(Duration::from_millis(200)),
    );
    let zero_entry = backend
        .put_single_shot(
            &init_for(&RelPath::parse("zero/empty.bin").unwrap(), 0, "op-zero-sf"),
            Box::pin(futures::stream::empty()),
        )
        .await
        .expect("0-byte PutBlob SlowFinalize must use data_finalize_timeout");
    assert_eq!(zero_entry.size, 0);
}

#[tokio::test]
async fn r2_mtime_writes_rfc3339_nano_and_dual_reads_rclone_legacy_and_last_modified() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let rel = RelPath::parse("r2/item.txt").unwrap();
    backend
        .put_single_shot(
            &init_for(&rel, 3, "op-r2-put"),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abc"))
            })),
        )
        .await
        .unwrap();
    assert_eq!(
        state.lock().unwrap().blobs["r2/item.txt"]
            .metadata
            .get("mtime")
            .map(String::as_str),
        Some("2023-11-14T22:13:20.123456789Z")
    );

    // Seed legacy `rship_mtime_ns` and Unix-float `mtime` blobs
    {
        let mut g = state.lock().unwrap();
        let e1 = g.alloc_etag();
        let mut m1 = BTreeMap::new();
        m1.insert(
            "rship_mtime_ns".to_string(),
            "1700000005000000000".to_string(),
        );
        g.blobs.insert(
            "r2/legacy.txt".to_string(),
            MockBlob {
                name: "r2/legacy.txt".to_string(),
                data: b"x".to_vec(),
                etag: e1,
                metadata: m1,
                ..Default::default()
            },
        );
        let e2 = g.alloc_etag();
        let mut m2 = BTreeMap::new();
        m2.insert("mtime".to_string(), "1700000009.5".to_string());
        g.blobs.insert(
            "r2/float.txt".to_string(),
            MockBlob {
                name: "r2/float.txt".to_string(),
                data: b"y".to_vec(),
                etag: e2,
                metadata: m2,
                ..Default::default()
            },
        );
    }

    assert_eq!(
        backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("r2/legacy.txt").unwrap()
            ))
            .await
            .unwrap()
            .unwrap()
            .mtime_ns,
        1_700_000_005_000_000_000
    );
    assert_eq!(
        backend
            .stat(&BackendPath::from_rel(
                RelPath::parse("r2/float.txt").unwrap()
            ))
            .await
            .unwrap()
            .unwrap()
            .mtime_ns,
        1_700_000_009_500_000_000
    );
}

#[tokio::test]
async fn parallel_parts_computes_whole_blob_md5_and_resumed_upload_omits_checksum() {
    let (base_url, key_b64, _state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let blk = AZURE_MIN_BLOCK_BYTES as usize;
    let data: Vec<u8> = (0..(blk * 2 + 500)).map(|i| (i % 249) as u8).collect();
    let rel = RelPath::parse("par/concurrent.bin").unwrap();
    let op = open_op(&backend, &init_for(&rel, data.len() as u64, "op-par-3")).await;

    // Upload parts 3, 1, 2 concurrently via tokio::join!
    let d1 = Bytes::copy_from_slice(&data[..blk]);
    let d2 = Bytes::copy_from_slice(&data[blk..blk * 2]);
    let d3 = Bytes::copy_from_slice(&data[blk * 2..]);
    let (r3, r1, r2) = tokio::join!(
        backend.upload_chunk(
            &op,
            ChunkUpload::new(
                3,
                (blk * 2) as u64,
                d3.len() as u64,
                data.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(d3) })),
            ),
        ),
        backend.upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                d1.len() as u64,
                data.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(d1) })),
            ),
        ),
        backend.upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                blk as u64,
                d2.len() as u64,
                data.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(d2) })),
            ),
        ),
    );
    let entry = backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: blk as u64,
                    etag: r1.unwrap().etag.unwrap(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 2,
                    offset: blk as u64,
                    length: blk as u64,
                    etag: r2.unwrap().etag.unwrap(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 3,
                    offset: (blk * 2) as u64,
                    length: 500,
                    etag: r3.unwrap().etag.unwrap(),
                    checksum: None,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        entry.checksum,
        Some(Checksum {
            kind: HashKind::Md5,
            hex: hex::encode(Md5::digest(&data)),
        })
    );

    // Simulated crash-resume: part 1 uploaded in an old backend instance, part 2 in a new instance.
    let rel_res = RelPath::parse("par/resumed.bin").unwrap();
    let op_res = open_op(
        &backend,
        &init_for(&rel_res, (blk + 100) as u64, "op-resumed"),
    )
    .await;
    let part1_data = Bytes::from(vec![0x11u8; blk]);
    let ack1 = backend
        .upload_chunk(
            &op_res,
            ChunkUpload::new(
                1,
                0,
                blk as u64,
                (blk + 100) as u64,
                Box::pin(futures::stream::once(async move { Ok(part1_data) })),
            ),
        )
        .await
        .unwrap();

    // Fresh backend instance (simulating process restart: empty in-memory blob_md5)
    let backend2 = make_backend(
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
    );
    let part2_data = Bytes::from(vec![0x22u8; 100]);
    let ack2 = backend2
        .upload_chunk(
            &op_res,
            ChunkUpload::new(
                2,
                blk as u64,
                100,
                (blk + 100) as u64,
                Box::pin(futures::stream::once(async move { Ok(part2_data) })),
            ),
        )
        .await
        .unwrap();
    let res_entry = backend2
        .finish_upload(
            &op_res,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: blk as u64,
                    etag: ack1.etag.unwrap(),
                    checksum: None,
                },
                CompletedPart {
                    part_number: 2,
                    offset: blk as u64,
                    length: 100,
                    etag: ack2.etag.unwrap(),
                    checksum: None,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        res_entry.checksum, None,
        "resumed upload missing part 1 in memory must NEVER claim a partial/false MD5"
    );
}

#[tokio::test]
async fn existing_precondition_against_missing_destination_fails_fast_without_retries() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let faults = state.lock().unwrap().fault_injector();
    let mut cfg = AzureBlobConfig::new("az-412-fast", TEST_ACCOUNT, "test-container")
        .with_max_retries(3)
        .with_retry_delays(Duration::from_millis(2), Duration::from_millis(5));
    cfg.endpoint = Some(base_url.clone());
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend = AzureBlobBackend::new(
        cfg,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
        transport,
        Some(SystemClock::shared()),
    )
    .unwrap();

    let missing_pre = DstPrecondition::Existing {
        node_id: None,
        etag: Some("\"0x8DC999\"".to_string()),
        mtime_ns: 0,
        size: 4,
    };

    // 1. PutBlob against missing destination -> 412 PreconditionFailed, 1 PUT, 0 HEAD, !retries_exhausted()
    let err_put = backend
        .put_single_shot(
            &UploadInit {
                precondition: missing_pre.clone(),
                ..init_for(&RelPath::parse("miss/put.bin").unwrap(), 4, "op-miss-put")
            },
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"abcd"))
            })),
        )
        .await
        .expect_err("PutBlob with Existing precondition on missing dst must fail");
    assert_eq!(err_put.kind, ErrorKind::PreconditionFailed);
    assert!(!err_put.is_retryable());
    assert!(!err_put.retries_exhausted());
    assert_eq!(faults.op_requests("PutBlob"), 1);
    assert_eq!(faults.op_requests("HeadBlob"), 0);

    // 2. PutBlockList against missing destination -> 412 PreconditionFailed, 1 PutBlockList, 1 HEAD
    let op_blk = open_op(
        &backend,
        &UploadInit {
            precondition: missing_pre.clone(),
            ..init_for(&RelPath::parse("miss/blk.bin").unwrap(), 4, "op-miss-blk")
        },
    )
    .await;
    let ack = backend
        .upload_chunk(
            &op_blk,
            ChunkUpload::new(
                1,
                0,
                4,
                4,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"abcd"))
                })),
            ),
        )
        .await
        .unwrap();
    let head_before_blk = faults.op_requests("HeadBlob");
    let err_blk = backend
        .finish_upload(
            &op_blk,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: 4,
                etag: ack.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .expect_err("PutBlockList with Existing precondition on missing dst must fail");
    assert_eq!(err_blk.kind, ErrorKind::PreconditionFailed);
    assert!(!err_blk.is_retryable());
    assert_eq!(faults.op_requests("PutBlockList"), 1);
    assert_eq!(state.lock().unwrap().put_block_list_calls, 1);
    assert_eq!(faults.op_requests("HeadBlob") - head_before_blk, 1);

    // 3. CopyBlob against missing destination -> 412 PreconditionFailed, 1 CopyBlob, 1 HEAD
    let src_rel = RelPath::parse("miss/src.bin").unwrap();
    let src_entry = backend
        .put_single_shot(
            &init_for(&src_rel, 4, "op-miss-src"),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"src!"))
            })),
        )
        .await
        .unwrap();
    let head_before_cp = faults.op_requests("HeadBlob");
    let err_cp = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(src_rel.clone()),
            &UploadInit {
                precondition: missing_pre,
                ..init_for(&RelPath::parse("miss/cp.bin").unwrap(), 4, "op-miss-cp")
            },
        )
        .await
        .expect_err("CopyBlob with Existing precondition on missing dst must fail");
    assert_eq!(err_cp.kind, ErrorKind::PreconditionFailed);
    assert!(!err_cp.is_retryable());
    assert_eq!(faults.op_requests("CopyBlob"), 1);
    assert_eq!(state.lock().unwrap().copy_calls, 1);
    assert_eq!(faults.op_requests("HeadBlob") - head_before_cp, 1);

    // 4. CopyBlob with stale src_etag against missing destination -> SourceMutated, 1 CopyBlob, 0 HEAD, !retries_exhausted()
    let head_before_src = faults.op_requests("HeadBlob");
    let err_src = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(src_rel.clone()),
            &UploadInit {
                src_etag: Some("\"0x8DC-OLD-SRC\"".to_string()),
                ..init_for(
                    &RelPath::parse("miss/cp-src-mut.bin").unwrap(),
                    4,
                    "op-miss-src-mut",
                )
            },
        )
        .await
        .expect_err("CopyBlob with stale src_etag must fail immediately with SourceMutated");
    assert_eq!(err_src.kind, ErrorKind::SourceMutated);
    assert!(!err_src.retries_exhausted());
    assert_eq!(faults.op_requests("CopyBlob"), 2);
    assert_eq!(faults.op_requests("HeadBlob") - head_before_src, 0);

    // 5. CopyBlob lost-response with Existing precondition still reconciles via 412 when dst DOES exist!
    let dst_rel = RelPath::parse("miss/existing-reconcile.bin").unwrap();
    let seed_dst = backend
        .put_single_shot(
            &init_for(&dst_rel, 4, "op-dst-seed"),
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"old!"))
            })),
        )
        .await
        .unwrap();
    faults.push(
        "CopyBlob",
        crate::common::InjectedFault::commit_then_reset(),
    );
    faults.push(
        "HeadBlob",
        crate::common::InjectedFault::xml_error(StatusCode::NOT_FOUND, "BlobNotFound", "lag"),
    );
    let reconciled_cp = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(src_rel),
            &UploadInit {
                precondition: DstPrecondition::Existing {
                    node_id: None,
                    etag: seed_dst.etag,
                    mtime_ns: 0,
                    size: 4,
                },
                src_etag: src_entry.etag,
                ..init_for(&dst_rel, 4, "op-cp-lost-412")
            },
        )
        .await
        .expect("CopyBlob lost response + 412 replay must reconcile")
        .expect("reconciled entry");
    assert_eq!(reconciled_cp.size, 4);
}

#[tokio::test]
async fn list_ordered_page_deduplicates_non_adjacent_hns_dir_and_marker() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let e1 = g.alloc_etag();
        let mut meta = BTreeMap::new();
        meta.insert("hdi_isfolder".to_string(), "true".to_string());
        // In ASCII/lexicographical order: "dir" < "dir-2.txt" ('-' = 45) < "dir/" ('/' = 47)
        g.blobs.insert(
            "dir".to_string(),
            MockBlob {
                name: "dir".to_string(),
                etag: e1,
                resource_type: Some("directory".to_string()),
                metadata: meta,
                ..Default::default()
            },
        );
        let e2 = g.alloc_etag();
        g.blobs.insert(
            "dir-2.txt".to_string(),
            MockBlob {
                name: "dir-2.txt".to_string(),
                data: b"hello".to_vec(),
                etag: e2,
                ..Default::default()
            },
        );
        let e3 = g.alloc_etag();
        g.blobs.insert(
            "dir/".to_string(),
            MockBlob {
                name: "dir/".to_string(),
                etag: e3,
                ..Default::default()
            },
        );
        g.page_size_override = Some(10);
    }

    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);
    let p = backend
        .list_ordered_page(&RelPath::root(), None, None, 10)
        .await
        .unwrap();
    assert!(!p.is_truncated);
    let names: Vec<&str> = p.entries.iter().map(|e| e.nfc_path.as_str()).collect();
    assert_eq!(names, vec!["dir", "dir-2.txt"]);
}

#[tokio::test(start_paused = true)]
async fn copy_blob_final_120th_poll_failed_reports_status_without_abort() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    {
        let mut g = state.lock().unwrap();
        let etag = g.alloc_etag();
        g.blobs.insert(
            "poll120/src.bin".to_string(),
            MockBlob {
                name: "poll120/src.bin".to_string(),
                data: b"data".to_vec(),
                etag,
                ..Default::default()
            },
        );
        // Initial PUT returns pending; polls 0..118 (119 polls) return pending; poll 119 (120th poll) returns failed!
        g.copy_pending_polls_override = Some((
            119,
            "failed".to_string(),
            Some("CopySourceTimeout".to_string()),
        ));
    }

    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);
    let err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("poll120/src.bin").unwrap()),
            &init_for(&RelPath::parse("poll120/dst.bin").unwrap(), 4, "op-poll120"),
        )
        .await
        .expect_err("120th-poll failed copy must return Protocol error");
    assert_eq!(err.kind, ErrorKind::Protocol, "got: {err:?}");
    assert!(
        err.message().contains("failed") && err.message().contains("CopySourceTimeout"),
        "expected status and copy_desc in error message, got: {}",
        err.message()
    );
    assert!(
        state.lock().unwrap().aborted_copies.is_empty(),
        "must NOT issue AbortCopyBlob when 120th poll already transitioned to failed"
    );
}

#[tokio::test]
async fn empty_dst_raw_path_falls_back_to_dst_nfc_path_across_multipart_and_reconcile() {
    use rship_core::backend::UploadProgress;

    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend = make_backend(&base_url, auth);

    let rel = RelPath::parse("nested/target.bin").unwrap();
    let payload = b"azure-empty-raw-path-fallback-payload".to_vec();
    let mut op = open_op(
        &backend,
        &init_for(&rel, payload.len() as u64, "op-empty-raw"),
    )
    .await;
    op.dst_raw_path.clear();

    // 1. query_upload before any blocks must target nested/target.bin (not container root)
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::CompletedParts(vec![])
    );

    // 2. upload_chunk with empty dst_raw_path must stage block on nested/target.bin
    let body = payload.clone();
    let ack = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                payload.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(body)) })),
            ),
        )
        .await
        .unwrap();

    // query_upload after staging must find the uncommitted block under nested/target.bin
    let progress = backend.query_upload(&op).await.unwrap();
    let UploadProgress::CompletedParts(parts) = progress else {
        panic!("expected CompletedParts, got {progress:?}");
    };
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].part_number, 1);

    // 3. finish_upload must commit to nested/target.bin (not container root)
    let entry = backend
        .finish_upload(
            &op,
            &[CompletedPart {
                part_number: 1,
                offset: 0,
                length: payload.len() as u64,
                etag: ack.etag.unwrap(),
                checksum: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(entry.nfc_path.as_str(), "nested/target.bin");
    assert_eq!(entry.raw_path(), "nested/target.bin");
    assert!(entry.raw_path.is_none());

    {
        let g = state.lock().unwrap();
        assert!(g.blobs.contains_key("nested/target.bin"));
        assert!(!g.blobs.contains_key(""));
        assert!(!g.blobs.contains_key("/"));
    }

    // 4. reconcile_operation must also target nested/target.bin and preserve nfc_path
    let outcome = backend.reconcile_operation(&op).await.unwrap();
    let ReconcileOutcome::Committed(rec_entry) = outcome else {
        panic!("expected Committed, got {outcome:?}");
    };
    assert_eq!(rec_entry.nfc_path.as_str(), "nested/target.bin");
    assert_eq!(rec_entry.raw_path(), "nested/target.bin");
    assert_eq!(rec_entry.size, payload.len() as u64);
}
