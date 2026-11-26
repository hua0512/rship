use axum::Router;
use axum::body::Bytes;
use axum::extract::OriginalUri;
use axum::http::Method;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::s3::{
    PayloadSigningMode, S3Backend, S3Config, S3Credentials, S3Provider, S3ServerSideEncryption,
};
use rship_core::backend::{BackendPath, ChunkUpload, CompletedPart, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_core::types::{ByteRange, Checksum, EntryKind, HashKind};
use rship_core::{ErrorKind, RetryClass};
use rship_transport::{HttpTransport, TransportConfig};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::mock_server::{MockS3Object, MockS3Server, read_s3_all};

fn fast_transport() -> HttpTransport {
    HttpTransport::new(TransportConfig::default()).unwrap()
}

#[tokio::test]
async fn s3_sse_kms_and_ssec_suppress_etag_as_md5_while_sse_s3_preserves_md5() {
    let srv = MockS3Server::start("sse-bkt", "us-east-1").await;
    let transport = fast_transport();

    // 1. SSE-KMS: `ETag` is opaque (NOT MD5) — backend must suppress MD5 in capabilities,
    //    `stat`, `list_stream`, `list_ordered_page`, `compute_hash`, and `open_read`.
    srv.state.lock().unwrap().faults.sse_kms_mode = true;
    let mut kms_cfg = srv.config(S3Provider::Aws, "sse-bkt", "us-east-1");
    kms_cfg.send_upload_checksum = false;
    kms_cfg.payload_signing = PayloadSigningMode::Unsigned;
    kms_cfg.server_side_encryption = Some(S3ServerSideEncryption::AwsKms {
        key_id: Some("alias/rship-key".into()),
    });
    let kms = S3Backend::new(kms_cfg, transport.clone(), None).unwrap();

    assert!(
        !kms.capabilities().hashes.contains(&HashKind::Md5),
        "SSE-KMS must omit HashKind::Md5 from capabilities"
    );

    let payload = b"kms encrypted object payload".to_vec();
    let init = UploadInit {
        op_id: "op-kms-put".into(),
        dst_path: RelPath::parse("kms/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let put_bytes = payload.clone();
    let put_entry = kms
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(put_bytes)) },
            )),
        )
        .await
        .expect("SSE-KMS put with opaque non-MD5 ETag must succeed");
    assert!(put_entry.etag.is_some());
    assert_eq!(put_entry.checksum, None);

    let bp = BackendPath::from_rel(RelPath::parse("kms/file.bin").unwrap());
    let stat_entry = kms.stat(&bp).await.unwrap().unwrap();
    assert_eq!(
        stat_entry.checksum, None,
        "stat under SSE-KMS must suppress ETag-as-MD5"
    );

    assert_eq!(
        kms.compute_hash(&bp, HashKind::Md5).await.unwrap(),
        None,
        "compute_hash(Md5) under SSE-KMS must return None"
    );

    let mut listed = kms.list_stream(&RelPath::root(), true).await.unwrap();
    let mut listed_entries = Vec::new();
    while let Some(item) = listed.next().await {
        listed_entries.push(item.unwrap());
    }
    assert_eq!(listed_entries.len(), 1);
    assert_eq!(
        listed_entries[0].checksum, None,
        "list_stream under SSE-KMS must suppress ETag-as-MD5"
    );

    let page = kms
        .list_ordered_page(&RelPath::root(), None, None, 100)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(
        page.entries[0].checksum, None,
        "list_ordered_page under SSE-KMS must suppress ETag-as-MD5"
    );

    assert_eq!(read_s3_all(&kms, &bp.nfc_path).await, payload);

    // 2. SSE-C: customer key headers must be sent on Put/Head/Get and MD5 suppressed.
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.sse_kms_mode = false;
        g.faults.sse_c_mode = true;
    }
    let mut ssec_cfg = srv.config(S3Provider::Aws, "sse-bkt", "us-east-1");
    ssec_cfg.send_upload_checksum = false;
    ssec_cfg.payload_signing = PayloadSigningMode::Unsigned;
    ssec_cfg.server_side_encryption =
        Some(S3ServerSideEncryption::sse_c_from_bytes(&[0x42u8; 32]).unwrap());
    let ssec = S3Backend::new(ssec_cfg, transport.clone(), None).unwrap();
    assert!(
        !ssec.capabilities().hashes.contains(&HashKind::Md5),
        "SSE-C must omit HashKind::Md5 from capabilities"
    );
    let ssec_init = UploadInit {
        op_id: "op-ssec-put".into(),
        dst_path: RelPath::parse("ssec/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let put_bytes = payload.clone();
    let ssec_put = ssec
        .put_single_shot(
            &ssec_init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(put_bytes)) },
            )),
        )
        .await
        .expect("SSE-C put must send customer key headers and ignore non-MD5 ETag");
    assert_eq!(ssec_put.checksum, None);
    let ssec_bp = BackendPath::from_rel(RelPath::parse("ssec/file.bin").unwrap());
    assert_eq!(ssec.stat(&ssec_bp).await.unwrap().unwrap().checksum, None);
    assert_eq!(
        ssec.compute_hash(&ssec_bp, HashKind::Md5).await.unwrap(),
        None
    );
    assert_eq!(read_s3_all(&ssec, &ssec_bp.nfc_path).await, payload);

    // 3. SSE-S3 (`AES256`): ETag IS valid single-part MD5 and MUST still be extracted!
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.sse_c_mode = false;
        g.objects.clear();
    }
    let mut aes_cfg = srv.config(S3Provider::Aws, "sse-bkt", "us-east-1");
    aes_cfg.send_upload_checksum = false;
    aes_cfg.server_side_encryption = Some(S3ServerSideEncryption::Aes256);
    let aes = S3Backend::new(aes_cfg, transport, None).unwrap();
    assert!(aes.capabilities().hashes.contains(&HashKind::Md5));
    let aes_init = UploadInit {
        op_id: "op-aes-put".into(),
        dst_path: RelPath::parse("aes/file.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let put_bytes = payload.clone();
    let aes_put = aes
        .put_single_shot(
            &aes_init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(put_bytes)) },
            )),
        )
        .await
        .unwrap();
    assert_eq!(
        aes_put.checksum,
        Some(Checksum {
            kind: HashKind::Md5,
            hex: hex::encode(Md5::digest(&payload)),
        })
    );
}

#[tokio::test]
async fn s3_oss_and_dotted_bucket_and_ip_literals_path_style_auto_fallback() {
    // 1. Alibaba OSS default region & signing_region normalization + S3 endpoint.
    let oss_default = S3Config::new(
        "oss",
        S3Provider::Oss,
        "my-bkt",
        S3Credentials::new("ak", "sk"),
    );
    assert_eq!(oss_default.region, "cn-hangzhou");
    assert_eq!(oss_default.signing_region(), "cn-hangzhou");
    assert_eq!(
        oss_default.effective_endpoint(),
        "https://s3.oss-cn-hangzhou.aliyuncs.com"
    );

    let mut oss_prefixed = oss_default.clone();
    oss_prefixed.region = "oss-cn-shanghai".into();
    assert_eq!(oss_prefixed.signing_region(), "cn-shanghai");
    assert_eq!(
        oss_prefixed.effective_endpoint(),
        "https://s3.oss-cn-shanghai.aliyuncs.com"
    );

    // 2. Dotted bucket `my.dotted.bucket` with `force_path_style = None` auto-falls back
    //    to path-style against IPv4 `http://127.0.0.1:<port>` with full SigV4 verification!
    let srv = MockS3Server::start("my.dotted.bucket", "us-east-1").await;
    let transport = fast_transport();
    let mut cfg = srv.config(S3Provider::Aws, "my.dotted.bucket", "us-east-1");
    cfg.force_path_style = None;
    assert!(cfg.use_path_style());
    let backend = S3Backend::new(cfg, transport.clone(), None).unwrap();

    let payload = b"dotted bucket path-style payload".to_vec();
    let init = UploadInit {
        op_id: "op-dotted".into(),
        dst_path: RelPath::parse("nested/obj.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let b = payload.clone();
    backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(b)) })),
        )
        .await
        .unwrap();
    assert_eq!(
        read_s3_all(&backend, &RelPath::parse("nested/obj.bin").unwrap()).await,
        payload
    );

    // 3. IPv6 literal endpoint `[::1]:<port>` preserves brackets + port and auto-selects path-style!
    if let Ok(v6_listener) = TcpListener::bind("[::1]:0").await {
        let v6_addr = v6_listener.local_addr().unwrap();
        let seen_v6 = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let seen_c = seen_v6.clone();
        let app = Router::new().fallback(
            move |method: Method, OriginalUri(uri): OriginalUri, headers: axum::http::HeaderMap| {
                let s = seen_c.clone();
                async move {
                    let host = headers
                        .get(axum::http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    s.lock().unwrap().push((host, uri.path().to_string()));
                    if method == Method::HEAD {
                        axum::http::StatusCode::NOT_FOUND
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            },
        );
        tokio::spawn(async move {
            let _ = axum::serve(v6_listener, app).await;
        });

        let mut v6_cfg = S3Config::new(
            "v6",
            S3Provider::Generic,
            "v6bkt",
            S3Credentials::new("ak", "sk"),
        );
        v6_cfg.endpoint = Some(format!("http://[::1]:{}", v6_addr.port()));
        v6_cfg.force_path_style = None;
        assert!(v6_cfg.use_path_style());
        let v6_backend = S3Backend::new(v6_cfg, transport, None).unwrap();
        let _ = v6_backend
            .stat(&BackendPath::from_rel(RelPath::parse("probe.txt").unwrap()))
            .await
            .unwrap();
        let reqs = seen_v6.lock().unwrap();
        assert_eq!(
            reqs.first().map(|(h, p)| (h.as_str(), p.as_str())),
            Some((
                format!("[::1]:{}", v6_addr.port()).as_str(),
                "/v6bkt/probe.txt"
            ))
        );
    }
}

#[tokio::test]
async fn s3_r2_cf_copy_headers_and_wasabi_no_if_none_match() {
    let srv = MockS3Server::start("r2-wasabi-bkt", "auto").await;
    let transport = fast_transport();

    // 1. R2: `reject_r2_single_part_crc32c` + `r2_copy_headers_only`
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.reject_r2_single_part_crc32c = true;
        g.faults.r2_copy_headers_only = true;
        g.objects.insert(
            "src.bin".into(),
            MockS3Object {
                data: b"r2 copy source".to_vec(),
                etag: "\"src-etag-1\"".into(),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }
    let mut r2_cfg = srv.config(S3Provider::R2, "r2-wasabi-bkt", "auto");
    r2_cfg.send_upload_checksum = true;
    let r2 = S3Backend::new(r2_cfg, transport.clone(), None).unwrap();

    // Copy with Absent -> sends `cf-copy-destination-if-none-match: *`, NOT `If-None-Match`.
    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap());
    let dst_entry = r2
        .server_side_copy(
            &r2.endpoint_identity(),
            &src_bp,
            &UploadInit {
                op_id: "op-r2-copy-absent".into(),
                dst_path: RelPath::parse("dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 14,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 14,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .expect("R2 CopyObject with cf-copy-destination-if-none-match must succeed")
        .expect("R2 CopyObject must commit");
    assert_eq!(dst_entry.size, 14);
    assert!(
        srv.state
            .lock()
            .unwrap()
            .counters
            .seen_cf_copy_headers
            .iter()
            .any(|(k, v)| k == "cf-copy-destination-if-none-match" && v == "*")
    );

    // Repeat Absent -> mock checks `cf-copy-destination-if-none-match` and returns PreconditionFailed!
    let conflict = r2
        .server_side_copy(
            &r2.endpoint_identity(),
            &src_bp,
            &UploadInit {
                op_id: "op-r2-copy-dup".into(),
                dst_path: RelPath::parse("dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 14,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 14,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(conflict.kind, ErrorKind::PreconditionFailed);

    // Existing with matching ETag -> sends `cf-copy-destination-if-match` and succeeds.
    r2.server_side_copy(
        &r2.endpoint_identity(),
        &src_bp,
        &UploadInit {
            op_id: "op-r2-copy-existing".into(),
            dst_path: RelPath::parse("dst.bin").unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 14,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 14,
            checksums: vec![],
            precondition: DstPrecondition::Existing {
                node_id: None,
                etag: dst_entry.etag.clone(),
                mtime_ns: 0,
                size: 14,
            },
            src_etag: None,
        },
    )
    .await
    .expect("R2 CopyObject with matching cf-copy-destination-if-match must succeed");

    // 2. Wasabi: `supports_if_none_match = false` omits `If-None-Match` on PutObject.
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.r2_copy_headers_only = false;
        g.faults.reject_r2_single_part_crc32c = false;
        g.faults.forbid_if_none_match = true;
        g.counters.seen_if_none_match_count = 0;
    }
    let wasabi = S3Backend::new(
        srv.config(S3Provider::Wasabi, "r2-wasabi-bkt", "auto"),
        transport,
        None,
    )
    .unwrap();
    assert!(!wasabi.capabilities().supports_conditional_write);
    let wasabi_init = UploadInit {
        op_id: "op-wasabi-put".into(),
        dst_path: RelPath::parse("wasabi/item.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 6,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 6,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    wasabi
        .put_single_shot(
            &wasabi_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"wasabi"))
            })),
        )
        .await
        .expect("Wasabi put must omit If-None-Match");
    assert_eq!(
        srv.state.lock().unwrap().counters.seen_if_none_match_count,
        0
    );
}

#[tokio::test]
async fn s3_complete_multipart_if_match_and_upload_part_copy_and_meta_sha256() {
    let srv = MockS3Server::start("mp-copy-bkt", "us-east-1").await;
    let transport = fast_transport();

    // 1. CompleteMultipartUpload `If-Match` for `DstPrecondition::Existing { etag: Some(...) }`.
    let mut aws_cfg = srv.config(S3Provider::Aws, "mp-copy-bkt", "us-east-1");
    aws_cfg.min_part_bytes_override = Some(8);
    aws_cfg.default_chunk_size = Some(8);
    let aws = S3Backend::new(aws_cfg, transport.clone(), None).unwrap();
    let base_init = UploadInit {
        op_id: "op-base".into(),
        dst_path: RelPath::parse("mp/target.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let old_entry = aws
        .put_single_shot(
            &base_init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"old!"))
            })),
        )
        .await
        .unwrap();

    // Overwrite via multipart with matching `etag` -> succeeds.
    let part_data = vec![b'N'; 16];
    let ok_pre = DstPrecondition::Existing {
        node_id: None,
        etag: old_entry.etag.clone(),
        mtime_ns: 0,
        size: 4,
    };
    let ok_init = UploadInit {
        op_id: "op-mp-ifmatch-ok".into(),
        dst_path: RelPath::parse("mp/target.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: part_data.len() as u64,
        planned_chunk_size: part_data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_100,
        checksums: vec![],
        precondition: ok_pre.clone(),
        src_etag: None,
    };
    let opened_ok = aws.begin_upload(&ok_init).await.unwrap();
    let op_ok = OperationRecord {
        op_id: ok_init.op_id.clone(),
        session_key: compute_session_key(
            "src://",
            "x",
            &aws.endpoint_identity(),
            &ok_init.dst_path,
        ),
        job_id: "job-ifmatch".into(),
        src_endpoint: "src://".into(),
        dst_endpoint: aws.endpoint_identity(),
        src_raw_path: ok_init.dst_path.as_str().into(),
        dst_raw_path: ok_init.dst_path.as_str().into(),
        dst_nfc_path: ok_init.dst_path.clone(),
        src_version: SourceVersion {
            size: ok_init.total_size,
            mtime_ns: ok_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
            node_id: None,
        },
        dst_precondition: ok_pre,
        existing_dst_node_id: None,
        remote_op_id: opened_ok.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened_ok.session_token),
        backend_meta: opened_ok.backend_meta,
        planned_chunk_size: part_data.len() as u64,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let ack = aws
        .upload_chunk(
            &op_ok,
            ChunkUpload::new(
                1,
                0,
                part_data.len() as u64,
                part_data.len() as u64,
                Box::pin(futures::stream::once({
                    let d = part_data.clone();
                    async move { Ok(Bytes::from(d)) }
                })),
            ),
        )
        .await
        .unwrap();
    let replaced = aws
        .finish_upload(
            &op_ok,
            &[CompletedPart {
                part_number: 1,
                etag: ack.etag.unwrap(),
                offset: 0,
                length: part_data.len() as u64,
                checksum: ack.checksum,
            }],
        )
        .await
        .expect("CompleteMultipartUpload with matching If-Match must succeed");
    assert_eq!(replaced.size, 16);

    // Overwrite via multipart with stale `etag` -> rejected!
    let bad_pre = DstPrecondition::Existing {
        node_id: None,
        etag: Some("\"stale-etag\"".into()),
        mtime_ns: 0,
        size: 16,
    };
    let bad_init = UploadInit {
        op_id: "op-mp-ifmatch-stale".into(),
        dst_path: RelPath::parse("mp/target.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 8,
        planned_chunk_size: 8,
        src_mtime_ns: 1_700_000_000_000_000_200,
        checksums: vec![],
        precondition: bad_pre.clone(),
        src_etag: None,
    };
    let opened_bad = aws.begin_upload(&bad_init).await.unwrap();
    let op_bad = OperationRecord {
        op_id: bad_init.op_id.clone(),
        session_key: compute_session_key(
            "src://",
            "x",
            &aws.endpoint_identity(),
            &bad_init.dst_path,
        ),
        job_id: "job-ifmatch".into(),
        src_endpoint: "src://".into(),
        dst_endpoint: aws.endpoint_identity(),
        src_raw_path: bad_init.dst_path.as_str().into(),
        dst_raw_path: bad_init.dst_path.as_str().into(),
        dst_nfc_path: bad_init.dst_path.clone(),
        src_version: SourceVersion {
            size: bad_init.total_size,
            mtime_ns: bad_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
            node_id: None,
        },
        dst_precondition: bad_pre,
        existing_dst_node_id: None,
        remote_op_id: opened_bad.remote_op_id,
        backend_kind: "s3".into(),
        session_token: Some(opened_bad.session_token),
        backend_meta: opened_bad.backend_meta,
        planned_chunk_size: 8,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let ack_bad = aws
        .upload_chunk(
            &op_bad,
            ChunkUpload::new(
                1,
                0,
                8,
                8,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"12345678"))
                })),
            ),
        )
        .await
        .unwrap();
    let stale_err = aws
        .finish_upload(
            &op_bad,
            &[CompletedPart {
                part_number: 1,
                etag: ack_bad.etag.unwrap(),
                offset: 0,
                length: 8,
                checksum: ack_bad.checksum,
            }],
        )
        .await
        .expect_err("CompleteMultipartUpload with mismatched If-Match must fail");
    assert_eq!(
        stale_err.kind,
        ErrorKind::PreconditionFailed,
        "unexpected error kind: {:?}",
        stale_err.kind
    );
    let _ = aws.abort_upload(&op_bad).await;

    // 2. UploadPartCopy checksum switch + Path A CopyObject preserving META_SHA256!
    let mut minio_cfg = srv.config(S3Provider::Minio, "mp-copy-bkt", "us-east-1");
    minio_cfg.send_upload_checksum = true;
    minio_cfg.max_single_copy_bytes = Some(64 * 1024);
    minio_cfg.default_chunk_size = Some(64 * 1024);
    minio_cfg.min_part_bytes_override = Some(64 * 1024);
    let minio = S3Backend::new(minio_cfg, transport, None).unwrap();

    // Small file with known SHA256 -> Path A CopyObject must preserve `x-amz-meta-rship-sha256`!
    let small_src = b"small copy sha256 payload".to_vec();
    let small_sha = hex::encode(Sha256::digest(&small_src));
    minio
        .put_single_shot(
            &UploadInit {
                op_id: "op-small-sha".into(),
                dst_path: RelPath::parse("copy/small-src.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: small_src.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: small_src.len() as u64,
                checksums: vec![Checksum {
                    kind: HashKind::Sha256,
                    hex: small_sha.clone(),
                }],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once({
                let b = small_src.clone();
                async move { Ok(Bytes::from(b)) }
            })),
        )
        .await
        .unwrap();
    let small_copied = minio
        .server_side_copy(
            &minio.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("copy/small-src.bin").unwrap()),
            &UploadInit {
                op_id: "op-small-copy".into(),
                dst_path: RelPath::parse("copy/small-dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: small_src.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: small_src.len() as u64,
                checksums: vec![Checksum {
                    kind: HashKind::Sha256,
                    hex: small_sha.clone(),
                }],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(small_copied.size, small_src.len() as u64);
    assert_eq!(
        srv.state.lock().unwrap().objects["copy/small-dst.bin"]
            .metadata
            .get("x-amz-meta-rship-sha256")
            .map(String::as_str),
        Some(small_sha.as_str()),
        "Path A CopyObject must preserve x-amz-meta-rship-sha256"
    );

    // 150 KiB (> 64 KiB single copy limit) -> UploadPartCopy with send_upload_checksum=true on plain HTTP MinIO!
    let big_src = vec![0x5Au8; 150 * 1024];
    minio
        .put_single_shot(
            &UploadInit {
                op_id: "op-big-copy-src".into(),
                dst_path: RelPath::parse("copy/big-src.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: big_src.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: big_src.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once({
                let b = big_src.clone();
                async move { Ok(Bytes::from(b)) }
            })),
        )
        .await
        .unwrap();
    let big_copied = minio
        .server_side_copy(
            &minio.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("copy/big-src.bin").unwrap()),
            &UploadInit {
                op_id: "op-big-copy".into(),
                dst_path: RelPath::parse("copy/big-dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: big_src.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 64 * 1024,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .expect("UploadPartCopy with send_upload_checksum=true must succeed without part checksum conflict")
        .unwrap();
    assert_eq!(big_copied.size, big_src.len() as u64);
    assert!(
        srv.state.lock().unwrap().counters.upload_part_copy_calls >= 3,
        "expected >= 3 UploadPartCopy parts for 150 KiB with 64 KiB part size"
    );
    assert_eq!(
        read_s3_all(&minio, &RelPath::parse("copy/big-dst.bin").unwrap()).await,
        big_src
    );
}

#[tokio::test]
async fn s3_leading_slash_and_non_empty_trailing_slash_objects() {
    let srv = MockS3Server::start("slash-bkt", "us-east-1").await;
    {
        let mut g = srv.state.lock().unwrap();
        for (k, bytes) in [
            ("/leading.txt", b"with-leading-slash".as_slice()),
            ("leading.txt", b"no-leading".as_slice()),
            ("real-dir/", b"".as_slice()),
            ("file-slash/", b"non-empty-body".as_slice()),
        ] {
            g.objects.insert(
                k.to_string(),
                MockS3Object {
                    data: bytes.to_vec(),
                    etag: format!("\"{}\"", hex::encode(Md5::digest(bytes))),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
    }

    let backend = S3Backend::new(
        srv.config(S3Provider::Aws, "slash-bkt", "us-east-1"),
        fast_transport(),
        None,
    )
    .unwrap();

    // 1. Recursive listing emits all 4 cleanly without collapsing `/leading.txt` & `leading.txt`
    //    and treats `real-dir/` (size 0) as Directory vs `file-slash/` (size > 0) as File!
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut entries = Vec::new();
    while let Some(item) = s.next().await {
        entries.push(item.unwrap());
    }
    let find_raw = |raw: Option<&str>, nfc: &str| {
        entries
            .iter()
            .find(|e| e.raw_path.as_deref() == raw && e.nfc_path.as_str() == nfc)
            .cloned()
    };
    let e_lead = find_raw(Some("/leading.txt"), "leading.txt").expect("missing /leading.txt");
    assert_eq!(e_lead.kind, EntryKind::File);
    assert_eq!(e_lead.size, 18);

    let e_nolead = find_raw(None, "leading.txt").expect("missing leading.txt");
    assert_eq!(e_nolead.kind, EntryKind::File);
    assert_eq!(e_nolead.size, 10);

    let e_dir = find_raw(None, "real-dir").expect("missing real-dir");
    assert_eq!(e_dir.kind, EntryKind::Directory);
    assert_eq!(e_dir.size, 0);

    let e_fslash = find_raw(Some("file-slash/"), "file-slash").expect("missing file-slash/");
    assert_eq!(e_fslash.kind, EntryKind::File);
    assert_eq!(e_fslash.size, 14);

    // 2. Stat & open_read preserve raw_path (`"/leading.txt"` vs `"leading.txt"`, `"file-slash/"`).
    let lead_bp = BackendPath::join_prefixed(
        &RelPath::root(),
        "/leading.txt",
        &RelPath::parse("leading.txt").unwrap(),
        None,
        Some(EntryKind::File),
    )
    .unwrap();
    let nolead_bp = BackendPath::from_rel(RelPath::parse("leading.txt").unwrap());
    assert_eq!(backend.stat(&lead_bp).await.unwrap().unwrap().size, 18);
    assert_eq!(backend.stat(&nolead_bp).await.unwrap().unwrap().size, 10);

    let fslash_bp = BackendPath::join_prefixed(
        &RelPath::root(),
        "file-slash/",
        &RelPath::parse("file-slash").unwrap(),
        None,
        Some(EntryKind::File),
    )
    .unwrap();
    let fslash_stat = backend.stat(&fslash_bp).await.unwrap().unwrap();
    assert_eq!(fslash_stat.kind, EntryKind::File);
    assert_eq!(fslash_stat.size, 14);
    assert_eq!(fslash_stat.raw_path.as_deref(), Some("file-slash/"));

    // Read `/leading.txt` via BackendPath and verify exact distinct content!
    match backend.open_read(&lead_bp, None).await.unwrap() {
        DataSource::RemoteRangeReadable(r) => {
            let mut rs = r
                .open_range(ByteRange { offset: 0, len: 18 })
                .await
                .unwrap();
            let mut got = Vec::new();
            while let Some(c) = rs.next().await {
                got.extend_from_slice(&c.unwrap());
            }
            assert_eq!(got, b"with-leading-slash");
        }
        _ => panic!("expected RemoteRangeReadable"),
    }

    // Copy `/leading.txt` -> `"copied-lead.txt"` preserves source leading `/`.
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &lead_bp,
            &UploadInit {
                op_id: "op-copy-leading".into(),
                dst_path: RelPath::parse("copied-lead.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 18,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 18,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(copied.size, 18);
}

#[tokio::test]
async fn s3_request_time_too_skewed_and_invalid_object_state() {
    let srv = MockS3Server::start("skew-bkt", "us-east-1").await;
    srv.state.lock().unwrap().objects.insert(
        "archived.bin".into(),
        MockS3Object {
            data: b"glacier bytes".to_vec(),
            etag: format!("\"{}\"", hex::encode(Md5::digest(b"glacier bytes"))),
            last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
            metadata: HashMap::new(),
            checksum_crc64nvme: None,
            checksum_crc32c: None,
        },
    );

    let backend = S3Backend::new(
        srv.config(S3Provider::Aws, "skew-bkt", "us-east-1"),
        fast_transport(),
        None,
    )
    .unwrap();

    // 1. Server clock skewed +3600s -> ListObjectsV2 gets 403 `RequestTimeTooSkewed` with
    //    `<ServerTime>`, client updates `clock_offset_secs`, retries, and succeeds!
    srv.state.lock().unwrap().faults.skew_server_offset_secs = 3600;
    let bp = BackendPath::from_rel(RelPath::parse("archived.bin").unwrap());
    let page = backend
        .list_ordered_page(&RelPath::root(), None, None, 100)
        .await
        .expect("list must recover automatically from RequestTimeTooSkewed");
    assert_eq!(page.entries.len(), 1);
    let entry = backend
        .stat(&bp)
        .await
        .expect("stat with adjusted clock_offset_secs must succeed")
        .unwrap();
    assert_eq!(entry.size, 13);
    assert_eq!(read_s3_all(&backend, &bp.nfc_path).await, b"glacier bytes");

    // 2. `403 InvalidObjectState` on GetObject -> Permanent `ErrorKind::Unsupported` (not PermissionDenied).
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.skew_server_offset_secs = 0;
        g.faults.force_invalid_object_state_on_get = true;
    }
    let reader = match backend.open_read(&bp, None).await.unwrap() {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let err = match reader.open_range(ByteRange { offset: 0, len: 13 }).await {
        Err(e) => e,
        Ok(mut range_stream) => match range_stream.next().await {
            Some(Err(e)) => e,
            other => panic!(
                "expected InvalidObjectState error, got {:?}",
                other.is_some()
            ),
        },
    };
    assert_eq!(err.kind, ErrorKind::Unsupported);
    assert_eq!(err.retry_class(), RetryClass::Permanent);
    assert!(
        err.message().contains("InvalidObjectState"),
        "unexpected message: {}",
        err.message()
    );
}

#[tokio::test]
async fn s3_delete_batch_per_key_transient_retry_and_xml10_unsafe_key_isolation() {
    let srv = MockS3Server::start("del-bkt", "us-east-1").await;
    let unsafe_key = "del/bad\x07ctrl.txt".to_string();
    {
        let mut g = srv.state.lock().unwrap();
        for k in [
            "del/ok.txt",
            "del/transient.txt",
            "del/denied.txt",
            &unsafe_key,
        ] {
            g.objects.insert(
                k.to_string(),
                MockS3Object {
                    data: b"x".to_vec(),
                    etag: "\"9dd4e461268c8034f5c8564e155c67a6\"".into(),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
        g.faults.delete_batch_transient_errors.insert(
            "del/transient.txt".into(),
            vec!["SlowDown".into(), "InternalError".into()],
        );
        g.faults
            .delete_batch_error_keys
            .insert("del/denied.txt".into());
    }

    let backend = S3Backend::new(
        srv.config(S3Provider::Aws, "del-bkt", "us-east-1"),
        fast_transport(),
        None,
    )
    .unwrap();

    let unsafe_bp = BackendPath::join_prefixed(
        &RelPath::root(),
        &unsafe_key,
        &RelPath::parse("del/bad-ctrl.txt").unwrap(),
        None,
        Some(EntryKind::File),
    )
    .unwrap();
    let failures = backend
        .delete_batch(&[
            BackendPath::from_rel(RelPath::parse("del/ok.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("del/transient.txt").unwrap()),
            BackendPath::from_rel(RelPath::parse("del/denied.txt").unwrap()),
            unsafe_bp,
        ])
        .await
        .expect("delete_batch must succeed overall while returning only permanent per-key errors");

    assert_eq!(
        failures.len(),
        1,
        "only del/denied.txt should remain failed"
    );
    assert_eq!(failures[0].0.nfc_path.as_str(), "del/denied.txt");
    assert_eq!(failures[0].1.kind, ErrorKind::PermissionDenied);

    let g = srv.state.lock().unwrap();
    assert!(!g.objects.contains_key("del/ok.txt"));
    assert!(!g.objects.contains_key("del/transient.txt"));
    assert!(!g.objects.contains_key(&unsafe_key));
    assert!(g.objects.contains_key("del/denied.txt"));
    assert!(g.counters.delete_object_calls >= 1);
    assert_eq!(g.counters.delete_objects_calls, 3);
}

#[test]
fn s3_capabilities_hash_alignment_with_transport_and_size() {
    let transport = fast_transport();
    let creds = S3Credentials::new("ak", "sk");

    // 1. HTTPS AWS Auto: `supports_streaming_hashes == false` (no CRC64NVME/CRC32C on >4 MiB HTTPS)
    let mut https_auto_cfg = S3Config::new("aws-https", S3Provider::Aws, "bkt", creds.clone());
    https_auto_cfg.endpoint = Some("https://s3.us-east-1.amazonaws.com".into());
    https_auto_cfg.payload_signing = PayloadSigningMode::Auto;
    let https_auto = S3Backend::new(https_auto_cfg, transport.clone(), None).unwrap();
    let caps_auto = https_auto.capabilities();
    assert!(caps_auto.hashes.contains(&HashKind::Md5));
    assert!(!caps_auto.hashes.contains(&HashKind::Crc64Nvme));
    assert!(!caps_auto.hashes.contains(&HashKind::Crc32c));

    // 2. HTTPS AWS StrictSha256: `requires_payload_sha256() == true` -> CRC64NVME advertised!
    let mut https_strict_cfg = S3Config::new("aws-strict", S3Provider::Aws, "bkt", creds.clone());
    https_strict_cfg.endpoint = Some("https://s3.us-east-1.amazonaws.com".into());
    https_strict_cfg.payload_signing = PayloadSigningMode::StrictSha256;
    let https_strict = S3Backend::new(https_strict_cfg, transport.clone(), None).unwrap();
    let caps_strict = https_strict.capabilities();
    assert!(caps_strict.hashes.contains(&HashKind::Md5));
    assert!(caps_strict.hashes.contains(&HashKind::Crc64Nvme));
    assert!(!caps_strict.hashes.contains(&HashKind::Crc32c));

    // 3. Plain HTTP AWS & MinIO: `requires_payload_sha256() == true` -> CRC64NVME (AWS) / CRC32C (MinIO).
    let mut http_cfg = S3Config::new("aws-http", S3Provider::Aws, "bkt", creds.clone());
    http_cfg.endpoint = Some("http://127.0.0.1:9000".into());
    let http_aws = S3Backend::new(http_cfg, transport.clone(), None).unwrap();
    let caps_http = http_aws.capabilities();
    assert!(caps_http.hashes.contains(&HashKind::Crc64Nvme));

    let mut minio_http_cfg = S3Config::new("minio-http", S3Provider::Minio, "bkt", creds.clone());
    minio_http_cfg.endpoint = Some("http://127.0.0.1:9000".into());
    let minio_http = S3Backend::new(minio_http_cfg, transport.clone(), None).unwrap();
    assert!(minio_http.capabilities().hashes.contains(&HashKind::Crc32c));

    // 4. R2 plain HTTP (`supports_single_part_crc32c == false`, multipart `supports_crc32c == true`):
    //    omits CRC32C from single-part capabilities so planner never assumes single-part CRC32C.
    let mut r2_cfg = S3Config::new("r2", S3Provider::R2, "bkt", creds);
    r2_cfg.endpoint = Some("http://127.0.0.1:9000".into());
    let r2 = S3Backend::new(r2_cfg, transport, None).unwrap();
    let caps_r2 = r2.capabilities();
    assert!(caps_r2.hashes.contains(&HashKind::Md5));
    assert!(!caps_r2.hashes.contains(&HashKind::Crc32c));
}

#[tokio::test]
async fn s3_list_prefix_split_preserves_dir_markers_and_trailing_slash_files() {
    let srv = MockS3Server::start("split-bkt", "us-east-1").await;
    {
        let mut g = srv.state.lock().unwrap();
        for (k, bytes) in [
            ("top.txt", b"top".as_slice()),
            ("dir/", b"".as_slice()),
            ("dir/a.txt", b"hello".as_slice()),
            ("empty_dir/", b"".as_slice()),
            ("weird/", b"trailing-slash".as_slice()),
            ("weird/child.txt", b"child".as_slice()),
        ] {
            g.objects.insert(
                k.to_string(),
                MockS3Object {
                    data: bytes.to_vec(),
                    etag: format!("\"{}\"", hex::encode(Md5::digest(bytes))),
                    last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                    metadata: HashMap::new(),
                    checksum_crc64nvme: None,
                    checksum_crc32c: None,
                },
            );
        }
    }

    let transport = fast_transport();
    let mut cfg1 = srv.config(S3Provider::Aws, "split-bkt", "us-east-1");
    cfg1.list_prefix_concurrency = 1;
    let b1 = S3Backend::new(cfg1, transport.clone(), None).unwrap();

    let mut cfg4 = srv.config(S3Provider::Aws, "split-bkt", "us-east-1");
    cfg4.list_prefix_concurrency = 4;
    let b4 = S3Backend::new(cfg4, transport, None).unwrap();

    async fn collect_sorted(
        backend: &S3Backend,
        prefix: &RelPath,
    ) -> Vec<(String, Option<String>, EntryKind, u64)> {
        let mut s = backend.list_stream(prefix, true).await.unwrap();
        let mut out = Vec::new();
        while let Some(item) = s.next().await {
            let e = item.unwrap();
            out.push((
                e.nfc_path.as_str().to_string(),
                e.raw_path.as_deref().map(str::to_string),
                e.kind,
                e.size,
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out
    }

    let root_1 = collect_sorted(&b1, &RelPath::root()).await;
    let root_4 = collect_sorted(&b4, &RelPath::root()).await;
    assert_eq!(
        root_4, root_1,
        "list_prefix_concurrency=4 must match concurrency=1 on root listing"
    );
    assert_eq!(
        root_4,
        vec![
            ("dir".into(), None, EntryKind::Directory, 0),
            ("dir/a.txt".into(), None, EntryKind::File, 5),
            ("empty_dir".into(), None, EntryKind::Directory, 0),
            ("top.txt".into(), None, EntryKind::File, 3),
            ("weird".into(), Some("weird/".into()), EntryKind::File, 14),
            ("weird/child.txt".into(), None, EntryKind::File, 5),
        ]
    );

    // Sub-prefix listing must still omit the queried prefix marker `"dir/"` itself
    // for both `list_prefix_concurrency = 1` and `list_prefix_concurrency = 4`.
    let sub_dir = RelPath::parse("dir").unwrap();
    let sub_1 = collect_sorted(&b1, &sub_dir).await;
    let sub_4 = collect_sorted(&b4, &sub_dir).await;
    assert_eq!(sub_4, sub_1);
    assert_eq!(sub_4, vec![("dir/a.txt".into(), None, EntryKind::File, 5)]);
}

#[tokio::test]
async fn s3_sse_c_copy_object_and_upload_part_copy_and_complete_multipart() {
    let srv = MockS3Server::start("ssec-copy-bkt", "us-east-1").await;
    srv.state.lock().unwrap().faults.sse_c_mode = true;

    let mut cfg = srv.config(S3Provider::Aws, "ssec-copy-bkt", "us-east-1");
    cfg.send_upload_checksum = false;
    cfg.payload_signing = PayloadSigningMode::Unsigned;
    cfg.max_single_copy_bytes = Some(64 * 1024);
    cfg.min_part_bytes_override = Some(64 * 1024);
    cfg.default_chunk_size = Some(64 * 1024);
    cfg.server_side_encryption =
        Some(S3ServerSideEncryption::sse_c_from_bytes(&[0x42u8; 32]).unwrap());
    let ssec = S3Backend::new(cfg, fast_transport(), None).unwrap();

    // 1. Small SSE-C object -> single-request `CopyObject` must send copy-source SSE-C headers.
    let small_payload = b"sse-c small copy payload".to_vec();
    let small_src_path = RelPath::parse("ssec/small-src.bin").unwrap();
    ssec.put_single_shot(
        &UploadInit {
            op_id: "op-ssec-small-src".into(),
            dst_path: small_src_path.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: small_payload.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: small_payload.len() as u64,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        },
        Box::pin(futures::stream::once({
            let d = small_payload.clone();
            async move { Ok(Bytes::from(d)) }
        })),
    )
    .await
    .unwrap();

    let small_dst_path = RelPath::parse("ssec/small-dst.bin").unwrap();
    let copied_small = ssec
        .server_side_copy(
            &ssec.endpoint_identity(),
            &BackendPath::from_rel(small_src_path),
            &UploadInit {
                op_id: "op-ssec-small-copy".into(),
                dst_path: small_dst_path.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: small_payload.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: small_payload.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .expect("SSE-C CopyObject must include copy-source SSE-C headers")
        .unwrap();
    assert_eq!(copied_small.size, small_payload.len() as u64);
    assert_eq!(copied_small.checksum, None);
    assert_eq!(read_s3_all(&ssec, &small_dst_path).await, small_payload);

    // 2. Large SSE-C object (> 64 KiB) -> multipart `UploadPartCopy` must send copy-source SSE-C
    //    headers on every `UploadPartCopy` AND omit SSE-C request headers on `CompleteMultipartUpload`.
    let big_payload = vec![0xA5u8; 150 * 1024];
    let big_src_path = RelPath::parse("ssec/big-src.bin").unwrap();
    let big_init = UploadInit {
        op_id: "op-ssec-big-src".into(),
        dst_path: big_src_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let opened = ssec.begin_upload(&big_init).await.unwrap();
    let op = OperationRecord {
        op_id: big_init.op_id.clone(),
        session_key: compute_session_key("src://", "x", &ssec.endpoint_identity(), &big_src_path),
        job_id: "job-ssec-mp".into(),
        src_endpoint: "src://".into(),
        dst_endpoint: ssec.endpoint_identity(),
        src_raw_path: big_src_path.as_str().into(),
        dst_raw_path: big_src_path.as_str().into(),
        dst_nfc_path: big_src_path.clone(),
        src_version: SourceVersion {
            size: big_init.total_size,
            mtime_ns: big_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
            node_id: None,
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
    let mut parts = Vec::new();
    for (idx, chunk) in big_payload.chunks(64 * 1024).enumerate() {
        let pn = (idx + 1) as u32;
        let offset = (idx * 64 * 1024) as u64;
        let len = chunk.len() as u64;
        let bytes = Bytes::copy_from_slice(chunk);
        let ack = ssec
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    pn,
                    offset,
                    len,
                    big_payload.len() as u64,
                    Box::pin(futures::stream::once(async move { Ok(bytes) })),
                ),
            )
            .await
            .unwrap();
        parts.push(CompletedPart {
            part_number: pn,
            etag: ack.etag.unwrap(),
            offset,
            length: len,
            checksum: ack.checksum,
        });
    }
    ssec.finish_upload(&op, &parts)
        .await
        .expect("CompleteMultipartUpload must omit SSE-C request headers");

    let big_dst_path = RelPath::parse("ssec/big-dst.bin").unwrap();
    let copied_big = ssec
        .server_side_copy(
            &ssec.endpoint_identity(),
            &BackendPath::from_rel(big_src_path),
            &UploadInit {
                op_id: "op-ssec-big-copy".into(),
                dst_path: big_dst_path.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: big_payload.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 64 * 1024,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .expect("SSE-C UploadPartCopy must include copy-source SSE-C headers")
        .unwrap();
    assert_eq!(copied_big.size, big_payload.len() as u64);
    assert_eq!(copied_big.checksum, None);
    assert!(
        srv.state.lock().unwrap().counters.upload_part_copy_calls >= 3,
        "expected >= 3 UploadPartCopy requests for 150 KiB object"
    );
    assert_eq!(read_s3_all(&ssec, &big_dst_path).await, big_payload);
}

#[tokio::test]
async fn s3_stat_sole_non_empty_trailing_slash_object() {
    let srv = MockS3Server::start("stat-slash-bkt", "us-east-1").await;
    let payload = b"14-byte-object";
    assert_eq!(payload.len(), 14);
    {
        let mut g = srv.state.lock().unwrap();
        g.objects.insert(
            "sole_file_slash/".into(),
            MockS3Object {
                data: payload.to_vec(),
                etag: format!("\"{}\"", hex::encode(Md5::digest(payload))),
                last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
                metadata: HashMap::new(),
                checksum_crc64nvme: None,
                checksum_crc32c: None,
            },
        );
    }

    let backend = S3Backend::new(
        srv.config(S3Provider::Aws, "stat-slash-bkt", "us-east-1"),
        fast_transport(),
        None,
    )
    .unwrap();

    // 1. Sole 14B `"sole_file_slash/"` with no children:
    //    `stat(&BackendPath::from_rel("sole_file_slash"))` must return `None` (NOT Directory!),
    //    while querying with `raw_path: Some("sole_file_slash/")` returns `Some(File { size: 14 })`.
    let rel = RelPath::parse("sole_file_slash").unwrap();
    let plain_bp = BackendPath::from_rel(rel.clone());
    assert!(
        backend.stat(&plain_bp).await.unwrap().is_none(),
        "sole non-empty trailing-slash object must not be misclassified as Directory"
    );

    let raw_bp = BackendPath::join_prefixed(
        &RelPath::root(),
        "sole_file_slash/",
        &rel,
        None,
        Some(EntryKind::File),
    )
    .unwrap();
    let file_entry = backend.stat(&raw_bp).await.unwrap().unwrap();
    assert_eq!(file_entry.kind, EntryKind::File);
    assert_eq!(file_entry.size, 14);
    assert_eq!(file_entry.raw_path.as_deref(), Some("sole_file_slash/"));

    // 2. Once a real child `"sole_file_slash/child.txt"` also exists, `max_keys = 2` sees the child
    //    and `stat("sole_file_slash")` returns `Some(Directory)`.
    srv.state.lock().unwrap().objects.insert(
        "sole_file_slash/child.txt".into(),
        MockS3Object {
            data: b"child".to_vec(),
            etag: format!("\"{}\"", hex::encode(Md5::digest(b"child"))),
            last_modified: "Tue, 24 Nov 2026 12:00:00 GMT".into(),
            metadata: HashMap::new(),
            checksum_crc64nvme: None,
            checksum_crc32c: None,
        },
    );
    let dir_entry = backend.stat(&plain_bp).await.unwrap().unwrap();
    assert_eq!(dir_entry.kind, EntryKind::Directory);
    assert_eq!(dir_entry.size, 0);
}
