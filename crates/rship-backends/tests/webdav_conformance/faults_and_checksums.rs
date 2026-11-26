use crate::common::InjectedFault;
use crate::mock_server::start_mock_dav;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use futures::StreamExt;
use rship_backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use rship_core::{ErrorKind, RetryClass};
use rship_transport::{
    HttpTransport, LimiterScope, RateLimiterConfig, RetryQuotaConfig, TransportConfig,
};
use std::time::{Duration, Instant};

// =========================================================================
// C6 Non-Idempotent Reconciliation & Fault Injection Tests (Step 2e-7)
// =========================================================================

fn make_nextcloud_config(addr: &str, remote_name: &str) -> WebdavConfig {
    let mut cfg = WebdavConfig::new(
        remote_name,
        format!("http://{addr}/remote.php/dav/files/alice"),
    );
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    cfg.single_shot_max_bytes = Some(16 * 1024);
    cfg.default_chunk_size = Some(32 * 1024);
    cfg.max_retries = 4;
    cfg.base_retry_delay = Duration::from_millis(10);
    cfg.max_retry_delay = Duration::from_millis(120);
    cfg
}

fn make_op_record(
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
        job_id: "j-nc-fault".into(),
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

/// (a1) C6: Nextcloud chunked `.file` MOVE assembly with `CommitThenError(503)` and
/// `CommitThenReset` MUST reconcile cleanly via PROPFIND instead of blindly retrying
/// into a 404 Not Found / SessionExpired failure; pre-commit 503 retries and commits.
#[tokio::test]
async fn webdav_c6_nextcloud_move_assemble_reconciles_commit_then_503_and_reset() {
    let (addr, st) = start_mock_dav().await;
    let faults = st.lock().unwrap().faults.clone();
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c6-move"), transport).unwrap();

    // Case 1: CommitThenError(503) on MOVE .file
    {
        let payload = vec![0xABu8; 40 * 1024];
        let dst_rel = RelPath::parse("assembled/case503.bin").unwrap();
        let init = UploadInit {
            op_id: "op-move-503".into(),
            dst_path: dst_rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: payload.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 40 * 1024,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        let sess = backend.begin_upload(&init).await.unwrap();
        let op = make_op_record(&backend, &init, &sess);
        let chunk_data = payload.clone();
        backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    1,
                    0,
                    chunk_data.len() as u64,
                    payload.len() as u64,
                    Box::pin(futures::stream::once(
                        async move { Ok(Bytes::from(chunk_data)) },
                    )),
                ),
            )
            .await
            .unwrap();

        faults.reset_telemetry();
        faults.push(
            "MOVE_ASSEMBLE",
            InjectedFault::commit_then_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "text/plain",
                "lost response after Nextcloud assembly commit",
            ),
        );

        let entry = backend.finish_upload(&op, &[]).await.expect(
            "MOVE .file CommitThenError(503) must reconcile cleanly instead of failing with 404",
        );
        assert_eq!(entry.size, payload.len() as u64);
        assert_eq!(
            faults.op_requests("MOVE_ASSEMBLE"),
            1,
            "reconciled MOVE .file must not blindly re-send MOVE"
        );
        assert!(
            faults.op_requests("PROPFIND") >= 2,
            "reconciliation must PROPFIND both staging source and destination"
        );
        assert_eq!(
            st.lock().unwrap().files["/remote.php/dav/files/alice/assembled/case503.bin"],
            payload
        );
    }

    // Case 2: CommitThenReset on MOVE .file
    {
        let payload = vec![0xCDu8; 24 * 1024];
        let dst_rel = RelPath::parse("assembled/casereset.bin").unwrap();
        let init = UploadInit {
            op_id: "op-move-reset".into(),
            dst_path: dst_rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: payload.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 24 * 1024,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        let sess = backend.begin_upload(&init).await.unwrap();
        let op = make_op_record(&backend, &init, &sess);
        let chunk_data = payload.clone();
        backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    1,
                    0,
                    chunk_data.len() as u64,
                    payload.len() as u64,
                    Box::pin(futures::stream::once(
                        async move { Ok(Bytes::from(chunk_data)) },
                    )),
                ),
            )
            .await
            .unwrap();

        faults.reset_telemetry();
        faults.push("MOVE_ASSEMBLE", InjectedFault::commit_then_reset());

        let entry = backend
            .finish_upload(&op, &[])
            .await
            .expect("MOVE .file CommitThenReset must reconcile cleanly");
        assert_eq!(entry.size, payload.len() as u64);
        assert_eq!(faults.op_requests("MOVE_ASSEMBLE"), 1);
        assert_eq!(
            st.lock().unwrap().files["/remote.php/dav/files/alice/assembled/casereset.bin"],
            payload
        );
    }

    // Case 3: Pre-commit 503 on MOVE .file -> source still exists & dst absent -> retries and succeeds
    {
        let payload = vec![0xEFu8; 20 * 1024];
        let dst_rel = RelPath::parse("assembled/precommit503.bin").unwrap();
        let init = UploadInit {
            op_id: "op-move-precommit".into(),
            dst_path: dst_rel.clone(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: payload.len() as u64,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 20 * 1024,
            checksums: vec![],
            precondition: DstPrecondition::Absent,
            src_etag: None,
        };
        let sess = backend.begin_upload(&init).await.unwrap();
        let op = make_op_record(&backend, &init, &sess);
        let chunk_data = payload.clone();
        backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    1,
                    0,
                    chunk_data.len() as u64,
                    payload.len() as u64,
                    Box::pin(futures::stream::once(
                        async move { Ok(Bytes::from(chunk_data)) },
                    )),
                ),
            )
            .await
            .unwrap();

        faults.reset_telemetry();
        faults.push(
            "MOVE_ASSEMBLE",
            InjectedFault::service_unavailable(Some("0")),
        );

        let entry = backend
            .finish_upload(&op, &[])
            .await
            .expect("pre-commit 503 on MOVE .file must retry and succeed");
        assert_eq!(entry.size, payload.len() as u64);
        assert_eq!(faults.op_requests("MOVE_ASSEMBLE"), 2);
        assert_eq!(
            st.lock().unwrap().files["/remote.php/dav/files/alice/assembled/precommit503.bin"],
            payload
        );
    }
}

/// (a2) C6: `rename` (RFC 4918 `MOVE`) with `CommitThenError(503)` and `CommitThenReset`
/// reconciles cleanly via PROPFIND instead of blindly retrying into 404; pre-commit 503 retries.
#[tokio::test]
async fn webdav_c6_rename_move_reconciles_commit_then_503_and_reset() {
    let (addr, st) = start_mock_dav().await;
    let faults = {
        let mut g = st.lock().unwrap();
        g.dirs.insert("/remote.php/dav/files/alice/docs".into());
        g.files.insert(
            "/remote.php/dav/files/alice/docs/a.txt".into(),
            b"rename-503-body".to_vec(),
        );
        g.files.insert(
            "/remote.php/dav/files/alice/docs/b.txt".into(),
            b"rename-reset-body".to_vec(),
        );
        g.files.insert(
            "/remote.php/dav/files/alice/docs/c.txt".into(),
            b"rename-retry-body".to_vec(),
        );
        g.faults.clone()
    };
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c6-rename"), transport).unwrap();

    // 1. CommitThenError(503)
    faults.reset_telemetry();
    faults.push(
        "MOVE",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost response after MOVE commit",
        ),
    );
    let renamed_a = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("docs/a.txt").unwrap()),
            "a_renamed.txt",
        )
        .await
        .expect("MOVE CommitThenError(503) must reconcile cleanly instead of failing with 404");
    assert_eq!(renamed_a.nfc_path.as_str(), "docs/a_renamed.txt");
    assert_eq!(renamed_a.size, b"rename-503-body".len() as u64);
    assert_eq!(faults.op_requests("MOVE"), 1);
    assert!(faults.op_requests("PROPFIND") >= 2);

    // 2. CommitThenReset
    faults.reset_telemetry();
    faults.push("MOVE", InjectedFault::commit_then_reset());
    let renamed_b = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("docs/b.txt").unwrap()),
            "b_renamed.txt",
        )
        .await
        .expect("MOVE CommitThenReset must reconcile cleanly");
    assert_eq!(renamed_b.nfc_path.as_str(), "docs/b_renamed.txt");
    assert_eq!(renamed_b.size, b"rename-reset-body".len() as u64);
    assert_eq!(faults.op_requests("MOVE"), 1);

    // 3. Pre-commit 503 -> source still exists & dst absent -> retries and commits
    faults.reset_telemetry();
    faults.push("MOVE", InjectedFault::service_unavailable(Some("0")));
    let renamed_c = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("docs/c.txt").unwrap()),
            "c_renamed.txt",
        )
        .await
        .expect("pre-commit 503 on MOVE must retry and commit");
    assert_eq!(renamed_c.nfc_path.as_str(), "docs/c_renamed.txt");
    assert_eq!(faults.op_requests("MOVE"), 2);

    let g = st.lock().unwrap();
    assert!(
        !g.files
            .contains_key("/remote.php/dav/files/alice/docs/a.txt")
    );
    assert_eq!(
        g.files["/remote.php/dav/files/alice/docs/a_renamed.txt"],
        b"rename-503-body"
    );
    assert_eq!(
        g.files["/remote.php/dav/files/alice/docs/b_renamed.txt"],
        b"rename-reset-body"
    );
    assert_eq!(
        g.files["/remote.php/dav/files/alice/docs/c_renamed.txt"],
        b"rename-retry-body"
    );
}

/// (b) C6: `MKCOL` (`begin_upload` staging dir AND `mkdir`) with `CommitThenError(503)` /
/// `CommitThenReset` reconciles via PROPFIND depth 0 instead of failing with 405 Method Not Allowed.
#[tokio::test]
async fn webdav_c6_mkcol_reconciles_commit_then_503_and_reset_without_405_failure() {
    let (addr, st) = start_mock_dav().await;
    let faults = st.lock().unwrap().faults.clone();
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c6-mkcol"), transport).unwrap();

    // 1. begin_upload MKCOL with CommitThenError(503) — pre-fix blindly retried and failed with HTTP 405!
    let init1 = UploadInit {
        op_id: "op-mkcol-503".into(),
        dst_path: RelPath::parse("mkcol/f1.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    faults.reset_telemetry();
    faults.push(
        "MKCOL",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost response after MKCOL commit",
        ),
    );
    let sess1 = backend
        .begin_upload(&init1)
        .await
        .expect("begin_upload MKCOL CommitThenError(503) must reconcile cleanly instead of 405");
    assert!(sess1.session_token.ends_with("/op-mkcol-503"));
    assert_eq!(
        faults.op_requests("MKCOL"),
        1,
        "reconciled MKCOL must not send a redundant second MKCOL"
    );
    assert!(faults.op_requests("PROPFIND") >= 1);

    // 2. begin_upload MKCOL with CommitThenReset
    let init2 = UploadInit {
        op_id: "op-mkcol-reset".into(),
        ..init1.clone()
    };
    faults.reset_telemetry();
    faults.push("MKCOL", InjectedFault::commit_then_reset());
    backend
        .begin_upload(&init2)
        .await
        .expect("begin_upload MKCOL CommitThenReset must reconcile cleanly");
    assert_eq!(faults.op_requests("MKCOL"), 1);

    // 3. mkdir MKCOL with CommitThenError(503) and pre-commit 503 retry
    faults.reset_telemetry();
    faults.push(
        "MKCOL",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost response after mkdir commit",
        ),
    );
    backend
        .mkdir(&RelPath::parse("reconciled_dir").unwrap())
        .await
        .expect("mkdir CommitThenError(503) must reconcile via PROPFIND");
    assert_eq!(faults.op_requests("MKCOL"), 1);
    assert!(faults.op_requests("PROPFIND") >= 1);

    faults.reset_telemetry();
    faults.push("MKCOL", InjectedFault::service_unavailable(Some("0")));
    backend
        .mkdir(&RelPath::parse("retried_dir").unwrap())
        .await
        .expect("mkdir pre-commit 503 must retry after PROPFIND sees 404");
    assert_eq!(faults.op_requests("MKCOL"), 2);
    assert!(
        st.lock()
            .unwrap()
            .dirs
            .contains("/remote.php/dav/files/alice/retried_dir")
    );

    // 4. mkdir onto an existing FILE (not a collection) must NOT falsely succeed on 405!
    st.lock().unwrap().files.insert(
        "/remote.php/dav/files/alice/not_a_dir".into(),
        b"i am a file".to_vec(),
    );
    let err = backend
        .mkdir(&RelPath::parse("not_a_dir").unwrap())
        .await
        .expect_err(
            "mkdir against an existing regular file must fail even though server returns 405",
        );
    assert_eq!(err.kind, ErrorKind::Protocol);
}

/// (c) C6: `DELETE` (`delete` and `abort_upload`) with `CommitThenError(503)` /
/// `CommitThenReset` reconciles via PROPFIND depth 0 instead of blindly re-issuing DELETE.
#[tokio::test]
async fn webdav_c6_delete_reconciles_commit_then_503_and_reset() {
    let (addr, st) = start_mock_dav().await;
    let faults = {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/files/alice/del503.txt".into(),
            b"delete-503".to_vec(),
        );
        g.files.insert(
            "/remote.php/dav/files/alice/delreset.txt".into(),
            b"delete-reset".to_vec(),
        );
        g.files.insert(
            "/remote.php/dav/files/alice/delretry.txt".into(),
            b"delete-retry".to_vec(),
        );
        g.faults.clone()
    };
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend = WebdavBackend::new(make_nextcloud_config(&addr, "nc-c6-del"), transport).unwrap();

    // 1. CommitThenError(503) -> PROPFIND sees 404 -> resolves cleanly with ONLY 1 DELETE!
    faults.reset_telemetry();
    faults.push(
        "DELETE",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost response after DELETE commit",
        ),
    );
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("del503.txt").unwrap(),
        ))
        .await
        .expect("DELETE CommitThenError(503) must reconcile cleanly");
    assert_eq!(
        faults.op_requests("DELETE"),
        1,
        "reconciled DELETE must not blindly send a second DELETE into 404"
    );
    assert!(faults.op_requests("PROPFIND") >= 1);
    assert!(
        !st.lock()
            .unwrap()
            .files
            .contains_key("/remote.php/dav/files/alice/del503.txt")
    );

    // 2. CommitThenReset -> PROPFIND sees 404 -> resolves cleanly with ONLY 1 DELETE!
    faults.reset_telemetry();
    faults.push("DELETE", InjectedFault::commit_then_reset());
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("delreset.txt").unwrap(),
        ))
        .await
        .expect("DELETE CommitThenReset must reconcile cleanly");
    assert_eq!(faults.op_requests("DELETE"), 1);
    assert!(faults.op_requests("PROPFIND") >= 1);

    // 3. Pre-commit 503 -> PROPFIND sees file still exists -> retries and deletes!
    faults.reset_telemetry();
    faults.push("DELETE", InjectedFault::service_unavailable(Some("0")));
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("delretry.txt").unwrap(),
        ))
        .await
        .expect("pre-commit 503 on DELETE must retry after PROPFIND confirms still present");
    assert_eq!(faults.op_requests("DELETE"), 2);
    assert!(
        !st.lock()
            .unwrap()
            .files
            .contains_key("/remote.php/dav/files/alice/delretry.txt")
    );
}

/// (d) C6 & C5: `COPY` (`server_side_copy`) reconciles `CommitThenError(503)` /
/// `CommitThenReset` via destination `PROPFIND`, retries pre-commit `503`, and uses
/// `long_control_timeout` for slow server-side copies.
#[tokio::test]
async fn webdav_c6_copy_reconciles_commit_then_503_and_uses_long_control_timeout() {
    let (addr, st) = start_mock_dav().await;
    let payload = b"webdav-server-side-copy-reconcile-payload".to_vec();
    let faults = {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/files/alice/src.bin".into(),
            payload.clone(),
        );
        g.faults.clone()
    };

    let tcfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(150))
        .with_long_control_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c6-copy"), transport).unwrap();
    let ep = backend.endpoint_identity();
    let src_bp = BackendPath::from_rel(RelPath::parse("src.bin").unwrap());

    let make_init = |dst: &str| UploadInit {
        op_id: format!("op-{dst}"),
        dst_path: RelPath::parse(dst).unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 32 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };

    // 1. CommitThenError(503) -> reconciles via PROPFIND with only 1 COPY request
    faults.reset_telemetry();
    faults.push(
        "COPY",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost response after COPY commit",
        ),
    );
    let entry1 = backend
        .server_side_copy(&ep, &src_bp, &make_init("dst_503.bin"))
        .await
        .expect("COPY CommitThenError(503) must reconcile cleanly")
        .expect("expected Some(Entry)");
    assert_eq!(entry1.size, payload.len() as u64);
    assert_eq!(faults.op_requests("COPY"), 1);
    assert!(faults.op_requests("PROPFIND") >= 1);

    // 2. CommitThenReset -> reconciles via PROPFIND with only 1 COPY request
    faults.reset_telemetry();
    faults.push("COPY", InjectedFault::commit_then_reset());
    let entry2 = backend
        .server_side_copy(&ep, &src_bp, &make_init("dst_reset.bin"))
        .await
        .expect("COPY CommitThenReset must reconcile cleanly")
        .expect("expected Some(Entry)");
    assert_eq!(entry2.size, payload.len() as u64);
    assert_eq!(faults.op_requests("COPY"), 1);

    // 3. Pre-commit 503 -> PROPFIND sees absent -> retries and succeeds
    faults.reset_telemetry();
    faults.push("COPY", InjectedFault::service_unavailable(Some("0")));
    let entry3 = backend
        .server_side_copy(&ep, &src_bp, &make_init("dst_retry.bin"))
        .await
        .expect("COPY pre-commit 503 must retry")
        .expect("expected Some(Entry)");
    assert_eq!(entry3.size, payload.len() as u64);
    assert_eq!(faults.op_requests("COPY"), 2);

    // 4. SlowFinalize (350ms > 150ms control_timeout, < 5s long_control_timeout) succeeds!
    faults.reset_telemetry();
    faults.push(
        "COPY",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let entry4 = backend
        .server_side_copy(&ep, &src_bp, &make_init("dst_slow.bin"))
        .await
        .expect("slow COPY must honor long_control_timeout instead of short control_timeout")
        .expect("expected Some(Entry)");
    assert_eq!(entry4.size, payload.len() as u64);
    assert_eq!(faults.op_requests("COPY"), 1);
}

/// (e) Scripted 429 (with Retry-After capped to max_retry_delay) and 503 recovery on PROPFIND
/// refunds exact 5-token retry quota (`available == max_tokens`), isolates control vs data
/// limiters, and sets `retries_exhausted() == true` when retries exhaust.
#[tokio::test]
async fn webdav_fault_propfind_429_503_exact_quota_refund_and_exhaustion() {
    let (addr, st) = start_mock_dav().await;
    let faults = {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/files/alice/quota.txt".into(),
            b"webdav-quota-payload".to_vec(),
        );
        g.faults.clone()
    };

    let quota = RetryQuotaConfig {
        max_tokens: 100,
        retry_cost: 5,
        timeout_retry_cost: 10,
        no_retry_increment: 1,
    };
    let tcfg = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota.clone()));
    let transport = HttpTransport::new(tcfg).unwrap();

    let mut cfg = make_nextcloud_config(&addr, "nc-fault-quota");
    cfg.max_retries = 4;
    cfg.base_retry_delay = Duration::from_millis(10);
    cfg.max_retry_delay = Duration::from_millis(120);
    let scope = LimiterScope::new(&cfg.remote_name, "alice");
    let backend = WebdavBackend::new(cfg, transport.clone()).unwrap();
    let ctrl_limiter = transport.control_limiter_for(scope.clone());
    let data_limiter = transport.data_limiter_for(scope);

    assert_eq!(ctrl_limiter.snapshot().retry_quota_available, 100);
    assert!(!ctrl_limiter.snapshot().cubic_enabled);
    assert!(!data_limiter.snapshot().cubic_enabled);

    // 1. 429 with Retry-After: 2 (capped strictly to max_retry_delay = 120ms) recovers & refunds 5 tokens!
    faults.push("PROPFIND", InjectedFault::too_many_requests(Some("2")));
    let t0 = Instant::now();
    let entry = backend
        .stat(&BackendPath::from_rel(RelPath::parse("quota.txt").unwrap()))
        .await
        .expect("PROPFIND must recover after 429")
        .expect("entry must exist");
    let elapsed_429 = t0.elapsed();
    assert_eq!(entry.size, b"webdav-quota-payload".len() as u64);
    assert!(
        elapsed_429 < Duration::from_secs(1),
        "Retry-After: 2s must be capped to max_retry_delay (120ms), took {elapsed_429:?}"
    );
    let snap_429 = ctrl_limiter.snapshot();
    assert!(snap_429.cubic_enabled, "429 must activate control CUBIC");
    assert!(
        !data_limiter.snapshot().cubic_enabled,
        "control-plane 429 must NOT trip isolated data-plane limiter"
    );
    assert_eq!(
        snap_429.retry_quota_available, snap_429.retry_quota_max,
        "429 recovery must refund exact 5-token retry cost back to max_tokens"
    );

    // 2. 503 recovery on PROPFIND refunds exact 5-token quota back to max_tokens!
    faults.push("PROPFIND", InjectedFault::service_unavailable(Some("0")));
    let entry2 = backend
        .stat(&BackendPath::from_rel(RelPath::parse("quota.txt").unwrap()))
        .await
        .expect("PROPFIND must recover after 503")
        .expect("entry must exist");
    assert_eq!(entry2.size, b"webdav-quota-payload".len() as u64);
    let snap_503 = ctrl_limiter.snapshot();
    assert_eq!(
        snap_503.retry_quota_available, snap_503.retry_quota_max,
        "503 recovery must refund exact 5-token retry cost back to max_tokens"
    );

    // 3. Exhaustion: max_retries = 2 -> 3 attempts total, 10 tokens deducted, retries_exhausted() == true!
    let tcfg_ex = TransportConfig::default()
        .with_default_rate_limit(RateLimiterConfig::new().with_retry_quota(quota));
    let transport_ex = HttpTransport::new(tcfg_ex).unwrap();
    let mut cfg_ex = make_nextcloud_config(&addr, "nc-fault-exhaust");
    cfg_ex.max_retries = 2;
    cfg_ex.base_retry_delay = Duration::from_millis(5);
    cfg_ex.max_retry_delay = Duration::from_millis(20);
    let scope_ex = LimiterScope::new(&cfg_ex.remote_name, "alice");
    let backend_ex = WebdavBackend::new(cfg_ex, transport_ex.clone()).unwrap();
    let ctrl_ex = transport_ex.control_limiter_for(scope_ex);

    faults.reset_telemetry();
    faults.push_many(
        "PROPFIND",
        [
            InjectedFault::too_many_requests(Some("0")),
            InjectedFault::too_many_requests(Some("0")),
            InjectedFault::too_many_requests(Some("0")),
        ],
    );
    let err = backend_ex
        .stat(&BackendPath::from_rel(RelPath::parse("quota.txt").unwrap()))
        .await
        .expect_err("exhausted 429s must fail");
    assert_eq!(err.kind, ErrorKind::RateLimited);
    assert_eq!(err.retry, RetryClass::Throttled);
    assert!(
        err.retries_exhausted(),
        "exhausted retries must set retries_exhausted() == true"
    );
    assert!(
        !err.is_retryable(),
        "retries_exhausted error must suppress outer is_retryable()"
    );
    assert_eq!(
        faults.op_requests("PROPFIND"),
        3,
        "must execute 1 initial + 2 retries"
    );
    assert_eq!(
        ctrl_ex.snapshot().retry_quota_available,
        90,
        "2 failed retries must deduct exact 10 tokens (100 -> 90)"
    );
}

/// (f) C5: `SlowFinalize` on upload `PUT` (> short `data_stall_timeout`, < `data_finalize_timeout`)
/// and `SlowFinalize` on Nextcloud `.file` `MOVE` (> short `control_timeout`, < `long_control_timeout`)
/// both succeed cleanly!
#[tokio::test]
async fn webdav_c5_slow_finalize_put_and_nextcloud_move_assemble_succeed() {
    let (addr, st) = start_mock_dav().await;
    let faults = st.lock().unwrap().faults.clone();

    let tcfg = TransportConfig::default()
        .with_control_timeout(Duration::from_millis(150))
        .with_long_control_timeout(Duration::from_secs(5))
        .with_data_stall_timeout(Duration::from_millis(150))
        .with_data_finalize_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c5-slow"), transport).unwrap();

    // 1. Single-shot PUT with SlowFinalize (350ms > 150ms data_stall_timeout, < 5s data_finalize_timeout)
    let single_payload = vec![0x42u8; 8 * 1024];
    let single_init = UploadInit {
        op_id: "op-slow-put-single".into(),
        dst_path: RelPath::parse("slow/single.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: single_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    faults.push(
        "PUT",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let p_clone = single_payload.clone();
    let entry = backend
        .put_single_shot(
            &single_init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(p_clone)) },
            )),
        )
        .await
        .expect(
            "single-shot PUT SlowFinalize must transition to data_finalize_timeout and succeed",
        );
    assert_eq!(entry.size, single_payload.len() as u64);

    // 2. Nextcloud chunk PUT with SlowFinalize AND `.file` MOVE assembly with SlowFinalize!
    let chunked_payload = vec![0x77u8; 24 * 1024];
    let chunked_init = UploadInit {
        op_id: "op-slow-nc-assemble".into(),
        dst_path: RelPath::parse("slow/chunked.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: chunked_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 24 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let sess = backend.begin_upload(&chunked_init).await.unwrap();
    let op = make_op_record(&backend, &chunked_init, &sess);

    faults.push(
        "PUT",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let c_clone = chunked_payload.clone();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                c_clone.len() as u64,
                chunked_payload.len() as u64,
                Box::pin(futures::stream::once(
                    async move { Ok(Bytes::from(c_clone)) },
                )),
            ),
        )
        .await
        .expect("chunk PUT SlowFinalize must transition to data_finalize_timeout and succeed");

    faults.push(
        "MOVE_ASSEMBLE",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let assembled = backend
        .finish_upload(&op, &[])
        .await
        .expect("Nextcloud MOVE .file SlowFinalize must honor long_control_timeout and succeed");
    assert_eq!(assembled.size, chunked_payload.len() as u64);
    assert_eq!(
        st.lock().unwrap().files["/remote.php/dav/files/alice/slow/chunked.bin"],
        chunked_payload
    );
}

/// (g) Mid-body reset on download surfaces a retryable network error and recovers cleanly on retry.
#[tokio::test]
async fn webdav_fault_mid_body_reset_on_download_surfaces_retryable_network_error_and_recovers() {
    let (addr, st) = start_mock_dav().await;
    let payload: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    let faults = {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/files/alice/dl/reset.bin".into(),
            payload.clone(),
        );
        g.faults.clone()
    };

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-dl-reset"), transport).unwrap();
    let ds = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("dl/reset.bin").unwrap()),
            None,
        )
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(reader) = ds else {
        panic!("expected RemoteRangeReadable");
    };

    faults.push(
        "GET",
        InjectedFault::mid_body_reset(Bytes::from_static(b"partial-webdav-body")),
    );
    let mut stream = reader
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .expect("headers should arrive before mid-body reset");
    let mut read_err = None;
    while let Some(item) = stream.next().await {
        if let Err(e) = item {
            read_err = Some(e);
            break;
        }
    }
    let err = read_err.expect("mid-body reset must surface an error");
    assert_eq!(err.kind, ErrorKind::Network, "got: {err:?}");
    assert_eq!(err.retry, RetryClass::Retryable, "got: {err:?}");
    assert!(err.is_retryable());
    assert!(!err.retries_exhausted());

    // Retry the same range -> recovers exact payload bit-for-bit.
    let mut recovered_stream = reader
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(chunk) = recovered_stream.next().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, payload);
}

/// (h) C8: Basic and Bearer `Authorization` headers constructed by `WebdavBackend`
/// are marked `is_sensitive() == true` so hyper/tracing never leaks credentials.
#[test]
fn webdav_authorization_headers_are_marked_sensitive() {
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();

    let mut basic_cfg = WebdavConfig::new("nc-sens-basic", "https://dav.example.com/files");
    basic_cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "top-secret-password-999".into(),
    };
    let basic_backend = WebdavBackend::new(basic_cfg, transport.clone()).unwrap();
    let mut basic_headers = HeaderMap::new();
    basic_backend.apply_auth_header(&mut basic_headers);
    let basic_val = basic_headers
        .get(axum::http::header::AUTHORIZATION)
        .expect("Basic Authorization header must be present");
    assert!(
        basic_val.is_sensitive(),
        "WebDAV Basic Authorization header must have is_sensitive() == true"
    );
    assert!(
        !format!("{basic_val:?}").contains("Basic "),
        "Debug formatting of sensitive Basic header must redact credential value"
    );

    let secret_token = "nc-secret-bearer-token-xyz123";
    let mut bearer_cfg = WebdavConfig::new("nc-sens-bearer", "https://dav.example.com/files");
    bearer_cfg.auth = WebdavAuth::Bearer {
        token: secret_token.into(),
    };
    let bearer_backend = WebdavBackend::new(bearer_cfg, transport.clone()).unwrap();
    let mut bearer_headers = HeaderMap::new();
    bearer_backend.apply_auth_header(&mut bearer_headers);
    let bearer_val = bearer_headers
        .get(axum::http::header::AUTHORIZATION)
        .expect("Bearer Authorization header must be present");
    assert!(
        bearer_val.is_sensitive(),
        "WebDAV Bearer Authorization header must have is_sensitive() == true"
    );
    assert_eq!(
        bearer_val.as_bytes(),
        format!("Bearer {secret_token}").as_bytes()
    );
    assert!(
        !format!("{bearer_val:?}").contains(secret_token),
        "Debug formatting of sensitive Bearer header must redact bearer token"
    );

    let anon_backend = WebdavBackend::new(
        WebdavConfig::new("nc-sens-anon", "https://dav.example.com/files"),
        transport,
    )
    .unwrap();
    let mut anon_headers = HeaderMap::new();
    anon_backend.apply_auth_header(&mut anon_headers);
    assert!(
        anon_headers
            .get(axum::http::header::AUTHORIZATION)
            .is_none()
    );
}

/// Additional coverage: `abort_upload` DELETE reconciliation, zero-byte PUT `SlowFinalize`,
/// pre-EOF upload stall still tripping `data_stall_timeout`, and `COPY` with
/// `DstPrecondition::Existing` overwrite reconciliation.
#[tokio::test]
async fn webdav_abort_upload_zero_byte_slow_finalize_pre_eof_stall_and_existing_copy_reconcile() {
    let (addr, st) = start_mock_dav().await;
    let faults = st.lock().unwrap().faults.clone();

    let tcfg = TransportConfig::default()
        .with_data_stall_timeout(Duration::from_millis(150))
        .with_data_finalize_timeout(Duration::from_secs(5));
    let transport = HttpTransport::new(tcfg).unwrap();
    let backend = WebdavBackend::new(make_nextcloud_config(&addr, "nc-extra"), transport).unwrap();

    // 1. abort_upload DELETE with CommitThenError(503) reconciles with 1 DELETE!
    let init = UploadInit {
        op_id: "op-abort-503".into(),
        dst_path: RelPath::parse("abort/f.bin").unwrap(),
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
    let op = make_op_record(&backend, &init, &sess);
    faults.reset_telemetry();
    faults.push(
        "DELETE",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost abort DELETE response",
        ),
    );
    backend.abort_upload(&op).await.unwrap();
    assert_eq!(faults.op_requests("DELETE"), 1);
    assert!(faults.op_requests("PROPFIND") >= 1);
    assert!(
        !st.lock()
            .unwrap()
            .dirs
            .contains("/remote.php/dav/uploads/alice/op-abort-503")
    );

    // 2. Zero-byte PUT SlowFinalize transitions immediately to data_finalize_timeout!
    let empty_init = UploadInit {
        op_id: "op-empty-slow".into(),
        dst_path: RelPath::parse("slow/empty.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 0,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    faults.push(
        "PUT",
        InjectedFault::slow_finalize(Duration::from_millis(350)),
    );
    let empty_entry = backend
        .put_single_shot(&empty_init, Box::pin(futures::stream::empty()))
        .await
        .expect("0-byte PUT SlowFinalize must succeed via immediate mark_body_eof()");
    assert_eq!(empty_entry.size, 0);

    // 3. Genuine pre-EOF upload stall MUST still trip short data_stall_timeout (150ms)!
    let stall_init = UploadInit {
        op_id: "op-stall-pre-eof".into(),
        dst_path: RelPath::parse("slow/stalled.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let stalled_stream = futures::stream::once(async { Ok(Bytes::from(vec![0u8; 512])) })
        .chain(futures::stream::pending());
    let stall_err = backend
        .put_single_shot(&stall_init, Box::pin(stalled_stream))
        .await
        .expect_err("pre-EOF stalled upload must still trip data_stall_timeout");
    assert_eq!(stall_err.kind, ErrorKind::Timeout);

    // 4. COPY overwriting an existing file (`DstPrecondition::Existing`):
    //    - pre-commit 503 sees unchanged old ETag -> retries!
    //    - post-commit 503 sees updated ETag & matching size -> resolves with 1 COPY!
    {
        let mut g = st.lock().unwrap();
        g.files.insert(
            "/remote.php/dav/files/alice/overwrite_src.bin".into(),
            vec![0x99u8; 64],
        );
        g.files.insert(
            "/remote.php/dav/files/alice/overwrite_dst1.bin".into(),
            vec![0x11u8; 16],
        );
        g.files.insert(
            "/remote.php/dav/files/alice/overwrite_dst2.bin".into(),
            vec![0x11u8; 16],
        );
    }
    let ep = backend.endpoint_identity();
    let src_bp = BackendPath::from_rel(RelPath::parse("overwrite_src.bin").unwrap());

    let dst1_etag = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("overwrite_dst1.bin").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap()
        .etag;
    let existing_precond = DstPrecondition::Existing {
        node_id: None,
        etag: dst1_etag,
        mtime_ns: 0,
        size: 16,
    };

    faults.reset_telemetry();
    faults.push("COPY", InjectedFault::service_unavailable(Some("0")));
    let copy_retry_init = UploadInit {
        op_id: "op-copy-ov-retry".into(),
        dst_path: RelPath::parse("overwrite_dst1.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: existing_precond.clone(),
        src_etag: None,
    };
    let e1 = backend
        .server_side_copy(&ep, &src_bp, &copy_retry_init)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e1.size, 64);
    assert_eq!(faults.op_requests("COPY"), 2);

    faults.reset_telemetry();
    faults.push(
        "COPY",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost overwrite COPY response",
        ),
    );
    let copy_resolve_init = UploadInit {
        op_id: "op-copy-ov-resolve".into(),
        dst_path: RelPath::parse("overwrite_dst2.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 1024,
        checksums: vec![],
        precondition: existing_precond,
        src_etag: None,
    };
    let e2 = backend
        .server_side_copy(&ep, &src_bp, &copy_resolve_init)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e2.size, 64);
    assert_eq!(faults.op_requests("COPY"), 1);
}

// =========================================================================
// C3: Nextcloud/ownCloud checksum headers (`X-Hash`, `OC-Checksum`)
// =========================================================================

fn c3_md5_hex(data: &[u8]) -> String {
    use md5::{Digest as _, Md5};
    hex::encode(Md5::digest(data))
}

fn c3_init(op_id: &str, path: &RelPath, data: &[u8], md5: Option<String>) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: data.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 32 * 1024,
        checksums: md5
            .map(|hex| {
                vec![rship_core::types::Checksum {
                    kind: rship_core::types::HashKind::Md5,
                    hex,
                }]
            })
            .unwrap_or_default(),
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

fn c3_body(data: &[u8]) -> rship_core::source::ByteStream {
    let items: Vec<rship_core::Result<Bytes>> = data
        .chunks(5_000)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    Box::pin(futures::stream::iter(items))
}

fn c3_payload(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 41 + seed) % 255) as u8).collect()
}

async fn c3_read_full(backend: &WebdavBackend, rel: &RelPath) -> rship_core::Result<Vec<u8>> {
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = backend
        .open_read(&BackendPath::from_rel(rel.clone()), None)
        .await?
    else {
        panic!("expected RemoteRangeReadable");
    };
    let mut stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: rr.total_len(),
        })
        .await?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

#[tokio::test]
async fn webdav_c3_nextcloud_single_shot_put_verifies_server_x_hash_md5() {
    let (addr, state) = start_mock_dav().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c3-xhash"), transport).unwrap();
    let data = c3_payload(12_000, 1);

    let ok = RelPath::parse("c3/ok.bin").unwrap();
    backend
        .put_single_shot(&c3_init("op-c3-ok", &ok, &data, None), c3_body(&data))
        .await
        .expect("matching X-Hash-MD5 must succeed");
    let seen = state.lock().unwrap().checksum_headers_seen.clone();
    assert_eq!(seen.last().unwrap().1.as_deref(), Some("md5"));

    // The server stores (and hashes) different bytes than were sent.
    state.lock().unwrap().corrupt_next_put = true;
    let bad = RelPath::parse("c3/bad.bin").unwrap();
    let err = backend
        .put_single_shot(&c3_init("op-c3-bad", &bad, &data, None), c3_body(&data))
        .await
        .expect_err("X-Hash-MD5 differing from the streamed MD5 must fail");
    assert!(
        err.message().contains("checksum mismatch (MD5)"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn webdav_c3_nextcloud_chunk_put_verifies_x_hash_md5_and_drops_corrupt_chunk() {
    let (addr, state) = start_mock_dav().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend =
        WebdavBackend::new(make_nextcloud_config(&addr, "nc-c3-chunk"), transport).unwrap();
    let data = c3_payload(40_000, 2);
    let path = RelPath::parse("c3/chunked.bin").unwrap();
    let init = c3_init("op-c3-chunk", &path, &data, None);
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op_record(&backend, &init, &sess);

    state.lock().unwrap().corrupt_next_put = true;
    let first = &data[..32 * 1024];
    let err = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(1, 0, first.len() as u64, data.len() as u64, c3_body(first)),
        )
        .await
        .expect_err("corrupted chunk must fail X-Hash-MD5 verification");
    assert!(
        err.message().contains("checksum mismatch (MD5)"),
        "got: {err:?}"
    );

    // The corrupt chunk was removed, so recovery does not count it as uploaded.
    match backend.query_upload(&op).await.unwrap() {
        rship_core::backend::UploadProgress::SequentialOffset(off) => assert_eq!(off, 0),
        other => panic!("unexpected progress: {other:?}"),
    }
}

#[tokio::test]
async fn webdav_c3_owncloud_validates_known_source_md5_sent_as_oc_checksum() {
    let (addr, state) = start_mock_dav().await;
    {
        let mut g = state.lock().unwrap();
        g.x_hash_supported = false;
        g.validate_oc_checksum = true;
    }
    let mut cfg = make_nextcloud_config(&addr, "oc-c3");
    cfg.vendor = WebdavVendor::Owncloud;
    let backend =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();
    let data = c3_payload(10_000, 3);
    let md5 = c3_md5_hex(&data);

    // Single-shot: ownCloud rejects bytes that do not match `OC-Checksum`.
    state.lock().unwrap().corrupt_next_put = true;
    let path = RelPath::parse("c3/oc-single.bin").unwrap();
    let err = backend
        .put_single_shot(
            &c3_init("op-oc-single", &path, &data, Some(md5.clone())),
            c3_body(&data),
        )
        .await
        .expect_err("ownCloud must reject a mismatched OC-Checksum");
    assert!(
        err.message().contains("checksum mismatch (MD5)"),
        "got: {err:?}"
    );
    let seen = state.lock().unwrap().checksum_headers_seen.clone();
    assert_eq!(seen.last().unwrap().2, Some(format!("MD5:{md5}")));

    // Chunked: the assembling MOVE carries the whole-file `OC-Checksum`.
    let big = c3_payload(40_000, 4);
    let big_md5 = c3_md5_hex(&big);
    let path = RelPath::parse("c3/oc-chunked.bin").unwrap();
    let init = c3_init("op-oc-chunked", &path, &big, Some(big_md5.clone()));
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op_record(&backend, &init, &sess);
    let mut offset = 0usize;
    state.lock().unwrap().corrupt_next_put = true;
    while offset < big.len() {
        let end = (offset + 32 * 1024).min(big.len());
        backend
            .upload_chunk(
                &op,
                ChunkUpload::new(
                    1,
                    offset as u64,
                    (end - offset) as u64,
                    big.len() as u64,
                    c3_body(&big[offset..end]),
                ),
            )
            .await
            .expect("ownCloud without X-Hash cannot reject a chunk itself");
        offset = end;
    }
    let err = backend
        .finish_upload(&op, &[])
        .await
        .expect_err("assembled file with a corrupted chunk must fail OC-Checksum");
    assert!(
        err.message().contains("checksum mismatch (MD5)"),
        "got: {err:?}"
    );
    let seen = state.lock().unwrap().checksum_headers_seen.clone();
    assert_eq!(seen.last().unwrap().2, Some(format!("MD5:{big_md5}")));
}

#[tokio::test]
async fn webdav_c3_full_download_verifies_oc_checksum_md5() {
    let (addr, state) = start_mock_dav().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let backend = WebdavBackend::new(make_nextcloud_config(&addr, "nc-c3-dl"), transport).unwrap();
    let data = c3_payload(9_000, 5);
    let path = RelPath::parse("c3/dl.bin").unwrap();
    backend
        .put_single_shot(
            &c3_init("op-c3-dl", &path, &data, Some(c3_md5_hex(&data))),
            c3_body(&data),
        )
        .await
        .unwrap();
    assert_eq!(c3_read_full(&backend, &path).await.unwrap(), data);

    state.lock().unwrap().corrupt_download_body_once = true;
    let err = c3_read_full(&backend, &path)
        .await
        .expect_err("corrupted download must fail OC-Checksum verification");
    assert!(
        err.message().contains("checksum mismatch (MD5)"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn webdav_c3_generic_vendor_sends_no_checksum_headers_and_stays_unverified() {
    let (addr, state) = start_mock_dav().await;
    let mut cfg = make_nextcloud_config(&addr, "generic-c3");
    cfg.vendor = WebdavVendor::Generic;
    let backend =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();
    assert!(backend.capabilities().hashes.is_empty());
    let data = c3_payload(8_000, 6);
    let path = RelPath::parse("c3/generic.bin").unwrap();
    let entry = backend
        .put_single_shot(
            &c3_init("op-generic", &path, &data, Some(c3_md5_hex(&data))),
            c3_body(&data),
        )
        .await
        .unwrap();
    assert!(entry.checksum.is_none(), "WebDAV must not claim a checksum");
    let seen = state.lock().unwrap().checksum_headers_seen.clone();
    assert_eq!(
        seen.last().unwrap().1,
        None,
        "no X-Hash for generic servers"
    );
    assert_eq!(
        seen.last().unwrap().2,
        None,
        "no OC-Checksum for generic servers"
    );
}
