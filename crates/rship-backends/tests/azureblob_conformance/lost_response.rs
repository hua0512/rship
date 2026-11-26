//! Non-idempotent Azure commits (`Put Block List` and `Copy Blob` with `If-None-Match: *`)
//! whose response is lost after the service committed. The retry gets `409 BlobAlreadyExists`;
//! the backend must reconcile through its `rship_op_id` metadata and succeed, not surface a
//! Conflict. Also: block-list uploads report the real whole-blob MD5 (or none).

use crate::common::InjectedFault;
use crate::mock_server::{TEST_ACCOUNT, spawn_mock_azure};
use axum::body::Bytes;
use axum::http::StatusCode;
use md5::{Digest as _, Md5};
use rship_backends::azureblob::{
    AZURE_MIN_BLOCK_BYTES, AzureAuth, AzureBlobBackend, AzureBlobConfig,
};
use rship_core::backend::{BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit};
use rship_core::clock::SystemClock;
use rship_core::path::RelPath;
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{Checksum, HashKind};
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

fn backend(base_url: &str, key_b64: &str) -> Arc<AzureBlobBackend> {
    let mut cfg = AzureBlobConfig::new("azure-lost", TEST_ACCOUNT, "test-container")
        .with_max_retries(3)
        .with_retry_delays(Duration::from_millis(5), Duration::from_millis(20));
    cfg.endpoint = Some(base_url.to_string());
    cfg.block_size = AZURE_MIN_BLOCK_BYTES;
    let auth = AzureAuth::shared_key(TEST_ACCOUNT, key_b64).unwrap();
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    Arc::new(AzureBlobBackend::new(cfg, auth, transport, Some(SystemClock::shared())).unwrap())
}

fn init_for(rel: &RelPath, total: u64, op_id: &str, checksums: Vec<Checksum>) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: AZURE_MIN_BLOCK_BYTES,
        checksums,
        precondition: DstPrecondition::Absent,
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

fn two_block_payload() -> Vec<u8> {
    let total = AZURE_MIN_BLOCK_BYTES as usize + 4321;
    (0..total).map(|i| (i % 253) as u8).collect()
}

/// Upload the blocks in `order` (1-based part numbers) and return the completed parts.
async fn upload_blocks(
    b: &AzureBlobBackend,
    op: &OperationRecord,
    data: &[u8],
    order: &[u32],
) -> Vec<CompletedPart> {
    let block = AZURE_MIN_BLOCK_BYTES as usize;
    let mut parts = Vec::new();
    for &pn in order {
        let off = (pn as usize - 1) * block;
        let chunk = Bytes::copy_from_slice(&data[off..data.len().min(off + block)]);
        let len = chunk.len() as u64;
        let ack = b
            .upload_chunk(
                op,
                ChunkUpload::new(
                    pn,
                    off as u64,
                    len,
                    data.len() as u64,
                    Box::pin(futures::stream::once(async move { Ok(chunk) })),
                ),
            )
            .await
            .unwrap();
        parts.push(CompletedPart {
            part_number: pn,
            offset: off as u64,
            length: len,
            etag: ack.etag.unwrap(),
            checksum: None,
        });
    }
    parts
}

#[tokio::test]
async fn put_block_list_lost_response_then_409_reconciles_via_op_id() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let b = backend(&base_url, &key_b64);
    let rel = RelPath::parse("lost/pbl.bin").unwrap();
    let data = two_block_payload();
    let op = open_op(
        &b,
        &init_for(&rel, data.len() as u64, "op-pbl-lost", vec![]),
    )
    .await;
    let parts = upload_blocks(&b, &op, &data, &[1, 2]).await;

    let faults = state.lock().unwrap().fault_injector();
    faults.push("PutBlockList", InjectedFault::commit_then_reset());
    // The first reconcile HEAD does not see the blob yet, so the commit is replayed and gets
    // `409 BlobAlreadyExists`; the second reconcile proves the blob is ours.
    faults.push(
        "HeadBlob",
        InjectedFault::xml_error(StatusCode::NOT_FOUND, "BlobNotFound", "lag"),
    );
    let entry = b
        .finish_upload(&op, &parts)
        .await
        .expect("lost PutBlockList response + 409 retry must reconcile, not Conflict");
    assert_eq!(entry.size, data.len() as u64);
    let g = state.lock().unwrap();
    assert_eq!(g.blobs["lost/pbl.bin"].data, data);
    assert_eq!(
        g.put_block_list_calls, 2,
        "commit replayed once, then reconciled"
    );
}

#[tokio::test]
async fn copy_blob_lost_response_then_409_reconciles_via_op_id() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let b = backend(&base_url, &key_b64);
    let src = RelPath::parse("lost/src.txt").unwrap();
    let init = UploadInit {
        precondition: DstPrecondition::Any,
        ..init_for(&src, 11, "op-src", vec![])
    };
    b.put_single_shot(
        &init,
        Box::pin(futures::stream::once(async {
            Ok(Bytes::from_static(b"hello-copy!"))
        })),
    )
    .await
    .unwrap();

    let faults = state.lock().unwrap().fault_injector();
    faults.push("CopyBlob", InjectedFault::commit_then_reset());
    faults.push(
        "HeadBlob",
        InjectedFault::xml_error(StatusCode::NOT_FOUND, "BlobNotFound", "lag"),
    );
    let dst = RelPath::parse("lost/dst.txt").unwrap();
    let copied = b
        .server_side_copy(
            &b.endpoint_identity(),
            &BackendPath::from_rel(src),
            &init_for(&dst, 11, "op-copy-lost", vec![]),
        )
        .await
        .expect("lost CopyBlob response + 409 retry must reconcile, not Conflict")
        .expect("copied entry");
    assert_eq!(copied.size, 11);
    assert_eq!(state.lock().unwrap().copy_calls, 2);
}

/// Blocks uploaded slightly out of order within the bounded reorder window (`MAX_REORDER_PARTS`)
/// still compute the exact whole-blob MD5, whereas exceeding the window or missing a part
/// (resumed upload) leaves `entry.checksum == None` rather than a corrupted MD5 or
/// PutBlockList's request-body MD5.
#[tokio::test]
async fn out_of_order_block_upload_respects_bounded_reorder_window() {
    let (base_url, key_b64, _state) = spawn_mock_azure().await;
    let b = backend(&base_url, &key_b64);
    let rel = RelPath::parse("ooo/within-window.bin").unwrap();
    let data = two_block_payload();
    let op = open_op(&b, &init_for(&rel, data.len() as u64, "op-ooo-ok", vec![])).await;
    let parts = upload_blocks(&b, &op, &data, &[2, 1]).await;
    let entry = b.finish_upload(&op, &parts).await.unwrap();
    assert_eq!(
        entry.checksum,
        Some(Checksum {
            kind: HashKind::Md5,
            hex: hex::encode(Md5::digest(&data)),
        })
    );

    // Exceeding the 8-part reorder window (uploading parts 10..=1 in reverse) drops the
    // reorder buffer and reports NO checksum rather than risking OOM or a corrupted MD5.
    let block = AZURE_MIN_BLOCK_BYTES as usize;
    let big_data: Vec<u8> = (0..(block * 9 + 123)).map(|i| (i % 251) as u8).collect();
    let big_rel = RelPath::parse("ooo/exceed-window.bin").unwrap();
    let big_op = open_op(
        &b,
        &init_for(&big_rel, big_data.len() as u64, "op-ooo-big", vec![]),
    )
    .await;
    let big_parts = upload_blocks(&b, &big_op, &big_data, &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1]).await;
    let big_entry = b.finish_upload(&big_op, &big_parts).await.unwrap();
    assert_eq!(big_entry.checksum, None);
}

/// A known source MD5 that disagrees with the bytes actually uploaded (source changed while
/// it was read) must fail BEFORE the block list is committed.
#[tokio::test]
async fn in_order_block_upload_rejects_a_source_md5_mismatch_before_commit() {
    let (base_url, key_b64, state) = spawn_mock_azure().await;
    let b = backend(&base_url, &key_b64);
    let rel = RelPath::parse("mismatch/blob.bin").unwrap();
    let data = two_block_payload();
    let wrong = Checksum {
        kind: HashKind::Md5,
        hex: hex::encode(Md5::digest(b"something else")),
    };
    let op = open_op(&b, &init_for(&rel, data.len() as u64, "op-mm", vec![wrong])).await;
    let parts = upload_blocks(&b, &op, &data, &[1, 2]).await;
    let err = b.finish_upload(&op, &parts).await.unwrap_err();
    assert!(err.message().contains("MD5"), "{err}");
    assert!(
        !state
            .lock()
            .unwrap()
            .blobs
            .contains_key("mismatch/blob.bin")
    );
}
