use crate::mock_server::{TEST_ACCOUNT, TEST_SAS_TOKEN, make_backend, spawn_mock_azure};
use axum::body::Bytes;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::azureblob::{AZURE_MIN_BLOCK_BYTES, AzureAuth};
use rship_core::backend::{
    BackendPath, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend, UploadInit,
    UploadProgress,
};
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::path::RelPath;
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::HashKind;
use std::sync::Arc;

#[tokio::test]
async fn azureblob_passes_full_conformance_with_strict_shared_key_hmac() {
    let (base_url, key_b64, _) = spawn_mock_azure().await;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap();
    let backend: Arc<dyn StorageBackend> = make_backend(&base_url, auth);
    run_backend_conformance(backend, SystemClock::shared()).await;
}

#[tokio::test]
async fn azureblob_handles_parallel_block_resume_async_copy_polling_xml_specials_and_sas() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let shared_key_backend = make_backend(
        &base_url,
        AzureAuth::shared_key(TEST_ACCOUNT, &key_b64).unwrap(),
    );

    // 1. Parallel PutBlock + GetBlockList crash-resume + PutBlockList commit!
    let block_sz = AZURE_MIN_BLOCK_BYTES;
    let total_sz = block_sz + 777;
    let big_path = RelPath::parse("parallel/a & b <1>/中文.bin").unwrap();
    let init = UploadInit {
        op_id: "op-az-par-001".into(),
        dst_path: big_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: block_sz,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = shared_key_backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-az".into(),
        job_id: "j-az".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: shared_key_backend.endpoint_identity(),
        src_raw_path: big_path.as_str().into(),
        dst_raw_path: big_path.as_str().into(),
        dst_nfc_path: big_path.clone(),
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
        backend_kind: "azureblob".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: block_sz,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Upload block 1
    let b1 = vec![0x77u8; block_sz as usize];
    let ack1 = shared_key_backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                block_sz,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(b1)) })),
            ),
        )
        .await
        .unwrap();
    let id1 = ack1.etag.expect("block 1 ID");

    // Simulate crash-resume: `query_upload` inspects Azure GetBlockList (uncommitted)
    // and recovers part 1 without re-uploading!
    let progress = shared_key_backend.query_upload(&op).await.unwrap();
    match progress {
        UploadProgress::CompletedParts(parts) => {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].part_number, 1);
            assert_eq!(parts[0].etag, id1);
            assert_eq!(parts[0].length, block_sz);
        }
        other => panic!("expected CompletedParts, got {other:?}"),
    }

    // Upload block 2 & commit via PutBlockList!
    let b2 = vec![0x88u8; 777];
    let ack2 = shared_key_backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                block_sz,
                777,
                total_sz,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(b2)) })),
            ),
        )
        .await
        .unwrap();
    let id2 = ack2.etag.expect("block 2 ID");

    let committed = shared_key_backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 2,
                    offset: block_sz,
                    length: 777,
                    etag: id2,
                    checksum: None,
                },
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: block_sz,
                    etag: id1,
                    checksum: None,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(committed.size, total_sz);
    // PutBlockList's response `Content-MD5` is the MD5 of the block-list XML, never the blob's:
    // the committed checksum must be the real whole-blob MD5 (blocks were hashed in order).
    let mut whole = vec![0x77u8; block_sz as usize];
    whole.extend_from_slice(&[0x88u8; 777]);
    assert_eq!(
        committed.checksum.as_ref().map(|c| (c.kind, c.hex.clone())),
        Some((HashKind::Md5, hex::encode(Md5::digest(&whole)))),
        "committed checksum must be the whole-blob MD5"
    );

    // Reconcile verifies committed blob via `x-ms-meta-rship_op_id`!
    match shared_key_backend.reconcile_operation(&op).await.unwrap() {
        ReconcileOutcome::Committed(e) => assert_eq!(e.size, total_sz),
        other => panic!("expected Committed, got {other:?}"),
    }

    // Check MD5 over the assembled 2-block blob
    let mut expected_bytes = vec![0x77u8; block_sz as usize];
    expected_bytes.extend_from_slice(&vec![0x88u8; 777]);
    let md5 = shared_key_backend
        .compute_hash(&BackendPath::from_rel(big_path.clone()), HashKind::Md5)
        .await
        .unwrap()
        .expect("md5");
    assert_eq!(md5.hex, hex::encode(Md5::digest(&expected_bytes)));

    // 2. Async server-side `x-ms-copy-source` (`pending` -> poll -> `success`) + `rename`!
    let copy_dst = RelPath::parse("copies/async_copy.bin").unwrap();
    let copy_init = UploadInit {
        op_id: "op-az-copy".into(),
        dst_path: copy_dst.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_sz,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: block_sz,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let ep = shared_key_backend.endpoint_identity();
    assert!(shared_key_backend.can_server_side_copy_from(&ep));
    let copied = shared_key_backend
        .server_side_copy(&ep, &BackendPath::from_rel(big_path.clone()), &copy_init)
        .await
        .unwrap()
        .expect("async server-side copy completed");
    assert_eq!(copied.size, total_sz);
    assert!(state.lock().unwrap().pending_polls_served >= 1);

    let renamed = shared_key_backend
        .rename(&BackendPath::from_rel(copy_dst), "moved.bin")
        .await
        .unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "copies/moved.bin");

    // 3. SAS token client can list paginated blobs (including XML special chars) & stat!
    let sas_backend = make_backend(&base_url, AzureAuth::sas_token(TEST_SAS_TOKEN).unwrap());
    let listed: Vec<_> = sas_backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "parallel/a & b <1>/中文.bin")
    );
    assert!(
        listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "copies/moved.bin")
    );
}
