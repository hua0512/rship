//! Multipart checksum contract: an upload created with `x-amz-checksum-algorithm` must send
//! that algorithm's checksum on every `UploadPart`, and (for COMPOSITE checksums) list every
//! part's checksum in `CompleteMultipartUpload`. The mock enforces the AWS rules (see
//! `validate_complete_manifest`), which is what broke the live silo job.

use axum::body::Bytes;
use rship_backends::s3::{S3Backend, S3Provider};
use rship_core::backend::{ChunkUpload, CompletedPart, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;

use crate::mock_server::{MockS3Server, read_s3_all};

const PART: usize = 256 * 1024;

fn backend(srv: &MockS3Server, provider: S3Provider) -> Arc<S3Backend> {
    let mut cfg = srv.config(provider, "ck-bucket", "us-east-1");
    cfg.single_shot_max_bytes = Some(64 * 1024);
    cfg.default_chunk_size = Some(PART as u64);
    cfg.min_part_bytes_override = Some(PART as u64);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    Arc::new(S3Backend::new(cfg, transport, None).unwrap())
}

fn init_for(rel: &RelPath, total: u64, op_id: &str) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: PART as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

async fn open_op(s3: &S3Backend, init: &UploadInit) -> OperationRecord {
    let opened = s3.begin_upload(init).await.unwrap();
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key("src://", "x", &s3.endpoint_identity(), &init.dst_path),
        job_id: "job".into(),
        src_endpoint: "src://".into(),
        dst_endpoint: s3.endpoint_identity(),
        src_raw_path: init.dst_path.as_str().into(),
        dst_raw_path: init.dst_path.as_str().into(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
            node_id: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened.session_token),
        backend_meta: opened.backend_meta,
        planned_chunk_size: PART as u64,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    }
}

fn payload(total: usize) -> Vec<u8> {
    (0..total).map(|i| ((i * 31) % 251) as u8).collect()
}

async fn upload_parts(
    s3: &S3Backend,
    op: &OperationRecord,
    data: &[u8],
) -> Vec<rship_core::backend::ChunkAck> {
    let mut acks = Vec::new();
    for (i, chunk) in data.chunks(PART).enumerate() {
        let slice = Bytes::copy_from_slice(chunk);
        let ack = s3
            .upload_chunk(
                op,
                ChunkUpload::new(
                    i as u32 + 1,
                    (i * PART) as u64,
                    chunk.len() as u64,
                    data.len() as u64,
                    Box::pin(futures::stream::once(async move { Ok(slice) })),
                ),
            )
            .await
            .unwrap();
        acks.push(ack);
    }
    acks
}

/// The live-smoke flow (and parts resumed from an older journal) completes with parts whose
/// recorded checksum is `None`. S3 rejects that for a COMPOSITE (CRC32C) upload, so
/// `finish_upload` must recover the part checksums via `ListParts` first.
#[tokio::test]
async fn s3_finish_upload_recovers_missing_composite_part_checksums_via_list_parts() {
    let srv = MockS3Server::start("ck-bucket", "us-east-1").await;
    let s3 = backend(&srv, S3Provider::Minio);
    let rel = RelPath::parse("mp/composite.bin").unwrap();
    let data = payload(PART * 2 + 1234);
    let init = init_for(&rel, data.len() as u64, "op-composite");
    let op = open_op(&s3, &init).await;
    assert_eq!(
        srv.state
            .lock()
            .unwrap()
            .uploads
            .values()
            .next()
            .unwrap()
            .checksum_algorithm
            .as_deref(),
        Some("CRC32C"),
        "MinIO profile over plain HTTP must create a CRC32C multipart upload"
    );
    let acks = upload_parts(&s3, &op, &data).await;
    assert!(acks.iter().all(|a| a.checksum.is_some()));

    // Parts as journaled by an older binary: no per-part checksum.
    let parts: Vec<CompletedPart> = acks
        .iter()
        .enumerate()
        .map(|(i, a)| CompletedPart {
            part_number: i as u32 + 1,
            offset: (i * PART) as u64,
            length: data[i * PART..].len().min(PART) as u64,
            etag: a.etag.clone().unwrap(),
            checksum: None,
        })
        .collect();
    let entry = s3.finish_upload(&op, &parts).await.unwrap();
    assert_eq!(entry.size, data.len() as u64);
    assert_eq!(read_s3_all(&s3, &rel).await, data);
}

/// `upload_chunk` must send the checksum algorithm the upload was CREATED with (recorded in
/// the session), not whatever the current profile prefers: S3 rejects a mismatching part
/// checksum ("Checksum Type mismatch occurred").
#[tokio::test]
async fn s3_upload_chunk_uses_the_session_checksum_algorithm() {
    let srv = MockS3Server::start("ck-bucket", "us-east-1").await;
    // Session created by a CRC32C profile...
    let creator = backend(&srv, S3Provider::Minio);
    let rel = RelPath::parse("mp/session-alg.bin").unwrap();
    let data = payload(PART + 999);
    let init = init_for(&rel, data.len() as u64, "op-session-alg");
    let op = open_op(&creator, &init).await;
    // ...resumed by a profile that prefers CRC64NVME.
    let resumer = backend(&srv, S3Provider::Aws);
    let acks = upload_parts(&resumer, &op, &data).await;
    let parts: Vec<CompletedPart> = acks
        .iter()
        .enumerate()
        .map(|(i, a)| CompletedPart {
            part_number: i as u32 + 1,
            offset: (i * PART) as u64,
            length: data[i * PART..].len().min(PART) as u64,
            etag: a.etag.clone().unwrap(),
            checksum: a.checksum.clone(),
        })
        .collect();
    assert!(
        parts.iter().all(|p| p
            .checksum
            .as_deref()
            .is_some_and(|c| c.starts_with("crc32c:"))),
        "parts must carry the session's CRC32C checksum: {parts:?}"
    );
    resumer.finish_upload(&op, &parts).await.unwrap();
    assert_eq!(read_s3_all(&resumer, &rel).await, data);
}

/// The mock must reject what S3 rejects: completing a COMPOSITE upload without part checksums
/// when they cannot be recovered (parts uploaded without a checksum header).
#[tokio::test]
async fn s3_mock_rejects_composite_complete_without_part_checksums() {
    let srv = MockS3Server::start("ck-bucket", "us-east-1").await;
    let s3 = backend(&srv, S3Provider::Minio);
    let rel = RelPath::parse("mp/raw.bin").unwrap();
    let data = payload(PART + 10);
    let init = init_for(&rel, data.len() as u64, "op-raw");
    let op = open_op(&s3, &init).await;
    let acks = upload_parts(&s3, &op, &data).await;
    // Forget the stored part checksums (as if the parts were sent without the header).
    srv.state
        .lock()
        .unwrap()
        .uploads
        .values_mut()
        .for_each(|u| u.part_checksums.clear());
    let parts: Vec<CompletedPart> = acks
        .iter()
        .enumerate()
        .map(|(i, a)| CompletedPart {
            part_number: i as u32 + 1,
            offset: (i * PART) as u64,
            length: data[i * PART..].len().min(PART) as u64,
            etag: a.etag.clone().unwrap(),
            checksum: None,
        })
        .collect();
    let err = s3.finish_upload(&op, &parts).await.unwrap_err();
    assert!(
        err.message().contains("checksum"),
        "error must explain the missing part checksum: {err}"
    );
    assert!(!srv.state.lock().unwrap().objects.contains_key(rel.as_str()));
}
