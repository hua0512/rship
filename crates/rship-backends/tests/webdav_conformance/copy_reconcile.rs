//! WebDAV `COPY` is non-idempotent and reconciled after an ambiguous failure. Reconcile must
//! PROVE the copy happened: a destination that merely has the expected size (e.g. a stale
//! `--backup-dir` archive of the same length) is not proof.

use crate::common::InjectedFault;
use crate::mock_server::start_mock_dav;
use axum::http::StatusCode;
use rship_backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig};
use rship_core::backend::{BackendPath, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_transport::{HttpTransport, TransportConfig};
use std::time::Duration;

const ROOT: &str = "/remote.php/dav/files/alice";

fn backend(addr: &str) -> WebdavBackend {
    let mut cfg = WebdavConfig::new("dav", format!("http://{addr}{ROOT}"));
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    cfg.max_retries = 3;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(20);
    WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap()
}

fn archive_init(dst: &str, size: u64) -> UploadInit {
    UploadInit {
        op_id: format!("op-{dst}"),
        dst_path: RelPath::parse(dst).unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: size,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: size,
        checksums: vec![],
        // `--backup-dir` archives with `Any` (rship-core engine/task.rs).
        precondition: DstPrecondition::Any,
        src_etag: None,
    }
}

/// The COPY fails BEFORE committing (503), and a stale same-size `backup/x` already exists.
/// Reconcile must not count the stale file as our result: it must retry the COPY so the
/// archive really holds the current `x`.
#[tokio::test]
async fn copy_reconcile_does_not_accept_a_stale_same_size_destination() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/x"), b"NEW-CONTENT-0001".to_vec());
        g.dirs.insert(format!("{ROOT}/backup"));
        g.files
            .insert(format!("{ROOT}/backup/x"), b"stale-backup-000".to_vec());
    }
    let dav = backend(&addr);
    let faults = st.lock().unwrap().faults.clone();
    faults.push("COPY", InjectedFault::service_unavailable(Some("0")));

    dav.server_side_copy(
        &dav.endpoint_identity(),
        &BackendPath::from_rel(RelPath::parse("x").unwrap()),
        &archive_init("backup/x", 16),
    )
    .await
    .unwrap()
    .expect("COPY result");

    let g = st.lock().unwrap();
    assert_eq!(
        g.files[&format!("{ROOT}/backup/x")],
        b"NEW-CONTENT-0001".to_vec(),
        "a failed COPY must not be reported as success because a stale same-size file exists"
    );
    assert_eq!(
        faults.op_requests("COPY"),
        2,
        "the COPY must be retried after reconcile"
    );
}

/// The COPY commits but its response is lost: reconcile sees the destination changed since
/// the pre-COPY snapshot and has the source's size, and resolves without a second COPY.
#[tokio::test]
async fn copy_reconcile_resolves_a_lost_response_over_a_stale_destination() {
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/y"), b"NEW-CONTENT-0002".to_vec());
        g.dirs.insert(format!("{ROOT}/backup"));
        g.files
            .insert(format!("{ROOT}/backup/y"), b"stale-backup-000".to_vec());
    }
    let dav = backend(&addr);
    let faults = st.lock().unwrap().faults.clone();
    faults.push(
        "COPY",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "lost COPY response",
        ),
    );

    let entry = dav
        .server_side_copy(
            &dav.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("y").unwrap()),
            &archive_init("backup/y", 16),
        )
        .await
        .unwrap()
        .expect("COPY result");
    assert_eq!(entry.size, 16);
    let g = st.lock().unwrap();
    assert_eq!(
        g.files[&format!("{ROOT}/backup/y")],
        b"NEW-CONTENT-0002".to_vec()
    );
    assert_eq!(g.copy_calls, 1, "a committed COPY must not be re-sent");
}

/// `reconcile_operation` must prove a file is this operation's result: an older file of the
/// source size whose ETag did not change must never come back `Committed`.
#[tokio::test]
async fn reconcile_operation_never_accepts_an_older_same_size_file() {
    use rship_core::backend::ReconcileOutcome;
    use rship_core::state::{OperationRecord, OperationState, SourceVersion};
    let (addr, st) = start_mock_dav().await;
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/old.bin"), b"old-content-0001".to_vec());
        g.bump_etag(&format!("{ROOT}/old.bin"));
    }
    let dav = backend(&addr);
    let rel = RelPath::parse("old.bin").unwrap();
    let old = dav
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    assert!(old.etag.is_some(), "mock must expose getetag");
    let mut op = OperationRecord {
        op_id: "op-dav-reconcile".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: dav.endpoint_identity(),
        src_raw_path: "old.bin".into(),
        dst_raw_path: "old.bin".into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: old.size,
            mtime_ns: old.mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Existing {
            node_id: None,
            etag: old.etag.clone(),
            mtime_ns: old.mtime_ns,
            size: old.size,
        },
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "webdav".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: old.size,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let outcome = dav.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "unchanged ETag must not be accepted: {outcome:?}"
    );
    let pre = op.dst_precondition.clone();
    op.dst_precondition = DstPrecondition::Any;
    let outcome = dav.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "{outcome:?}"
    );

    // A write that changed the ETag and has the source size is ours.
    op.dst_precondition = pre;
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/old.bin"), b"new-content-0001".to_vec());
        g.bump_etag(&format!("{ROOT}/old.bin"));
    }
    let outcome = dav.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn reconcile_operation_honors_meta_pre_op_for_dst_precondition_any_absent_and_existing() {
    use axum::body::Bytes;
    use rship_backends::webdav::WebdavVendor;
    use rship_core::backend::{ChunkUpload, ReconcileOutcome};
    use rship_core::state::{OperationRecord, OperationState, SourceVersion, compute_session_key};

    let (addr, st) = start_mock_dav().await;
    let mut cfg = WebdavConfig::new("nc-rec", format!("http://{addr}{ROOT}"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    let dav =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();

    // Subcase A (Probe 2e): DstPrecondition::Any when dst was originally Absent.
    let abs_rel = RelPath::parse("rec_any_absent.bin").unwrap();
    let abs_init = UploadInit {
        op_id: "op-rec-any-absent".into(),
        dst_path: abs_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 8,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess_a = dav.begin_upload(&abs_init).await.unwrap();
    let op_a = OperationRecord {
        op_id: abs_init.op_id.clone(),
        session_key: compute_session_key(
            "local",
            "rec_any_absent.bin",
            &dav.endpoint_identity(),
            &abs_rel,
        ),
        job_id: "j-rec".into(),
        src_endpoint: "local".into(),
        dst_endpoint: dav.endpoint_identity(),
        src_raw_path: "rec_any_absent.bin".into(),
        dst_raw_path: "rec_any_absent.bin".into(),
        dst_nfc_path: abs_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: 8,
            mtime_ns: abs_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess_a.remote_op_id.clone(),
        backend_kind: "webdav".into(),
        session_token: Some(sess_a.session_token.clone()),
        backend_meta: sess_a.backend_meta.clone(),
        planned_chunk_size: 8,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };
    dav.upload_chunk(
        &op_a,
        ChunkUpload::new(
            1,
            0,
            8,
            8,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"NEW-BODY"))
            })),
        ),
    )
    .await
    .unwrap();
    // While staging still exists, reconcile must report NotCommitted.
    assert!(matches!(
        dav.reconcile_operation(&op_a).await.unwrap(),
        ReconcileOutcome::NotCommitted
    ));
    // Once MOVE .file commits (staging gone, dst exists), reconcile must report Committed.
    dav.finish_upload(&op_a, &[]).await.unwrap();
    let outcome_a = dav.reconcile_operation(&op_a).await.unwrap();
    assert!(
        matches!(outcome_a, ReconcileOutcome::Committed(ref e) if e.size == 8),
        "DstPrecondition::Any with snapshot Absent must reconcile as Committed: {outcome_a:?}"
    );

    // Subcase B: DstPrecondition::Any when dst originally Existed with same size & ETag w1.
    let ex_rel = RelPath::parse("rec_any_existing.bin").unwrap();
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/rec_any_existing.bin"), b"OLD-BODY".to_vec());
        g.bump_etag(&format!("{ROOT}/rec_any_existing.bin"));
    }
    let ex_init = UploadInit {
        op_id: "op-rec-any-existing".into(),
        dst_path: ex_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 8,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 8,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess_b = dav.begin_upload(&ex_init).await.unwrap();
    let op_b = OperationRecord {
        op_id: ex_init.op_id.clone(),
        session_key: compute_session_key(
            "local",
            "rec_any_existing.bin",
            &dav.endpoint_identity(),
            &ex_rel,
        ),
        job_id: "j-rec".into(),
        src_endpoint: "local".into(),
        dst_endpoint: dav.endpoint_identity(),
        src_raw_path: "rec_any_existing.bin".into(),
        dst_raw_path: "rec_any_existing.bin".into(),
        dst_nfc_path: ex_rel,
        src_version: SourceVersion {
            node_id: None,
            size: 8,
            mtime_ns: ex_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess_b.remote_op_id.clone(),
        backend_kind: "webdav".into(),
        session_token: Some(sess_b.session_token.clone()),
        backend_meta: sess_b.backend_meta.clone(),
        planned_chunk_size: 8,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };
    // Staging vanishes WITHOUT commit -> ETag unchanged -> must be NotCommitted.
    {
        let mut g = st.lock().unwrap();
        g.dirs
            .remove("/remote.php/dav/uploads/alice/op-rec-any-existing");
    }
    assert!(matches!(
        dav.reconcile_operation(&op_b).await.unwrap(),
        ReconcileOutcome::NotCommitted
    ));
    // Once dst is updated (ETag changed to w2), reconcile reports Committed.
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/rec_any_existing.bin"), b"NEW-BODY".to_vec());
        g.bump_etag(&format!("{ROOT}/rec_any_existing.bin"));
    }
    let outcome_b = dav.reconcile_operation(&op_b).await.unwrap();
    assert!(
        matches!(outcome_b, ReconcileOutcome::Committed(ref e) if e.size == 8),
        "DstPrecondition::Any with changed ETag must reconcile as Committed: {outcome_b:?}"
    );
}

#[tokio::test]
async fn reconcile_operation_nextcloud_mtime_tol_without_etag_and_non_multipart_ops() {
    use rship_backends::webdav::WebdavVendor;
    use rship_core::backend::ReconcileOutcome;
    use rship_core::state::{OperationRecord, OperationState, SourceVersion};

    let (addr, st) = start_mock_dav().await;
    st.lock().unwrap().omit_etag = true;

    let mut cfg = WebdavConfig::new("nc-mtime-rec", format!("http://{addr}{ROOT}"));
    cfg.vendor = WebdavVendor::Nextcloud;
    cfg.auth = WebdavAuth::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    let nc =
        WebdavBackend::new(cfg, HttpTransport::new(TransportConfig::default()).unwrap()).unwrap();

    let rel = RelPath::parse("no_etag_mtime.bin").unwrap();
    {
        let mut g = st.lock().unwrap();
        g.files
            .insert(format!("{ROOT}/no_etag_mtime.bin"), b"payload-12".to_vec());
        // X-OC-Mtime truncates sub-second nanoseconds to 1s granularity.
        g.mtimes
            .insert(format!("{ROOT}/no_etag_mtime.bin"), 1_700_000_000);
    }

    // Non-multipart op (`session_token: None`, `backend_meta: ""`) with DstPrecondition::Absent
    // and sub-second src mtime -> mtime_tol (1s) lets it reconcile as Committed even without ETag.
    let mut op = OperationRecord {
        op_id: "op-nc-mtime".into(),
        session_key: "sk-mtime".into(),
        job_id: "j-mtime".into(),
        src_endpoint: "local".into(),
        dst_endpoint: nc.endpoint_identity(),
        src_raw_path: "no_etag_mtime.bin".into(),
        dst_raw_path: "no_etag_mtime.bin".into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: 10,
            mtime_ns: 1_700_000_000_750_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "webdav".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: 10,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };

    let outcome_match = nc.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome_match, ReconcileOutcome::Committed(_)),
        "Nextcloud mtime within 1s tolerance should commit: {outcome_match:?}"
    );

    // Mismatched server mtime (>1s off) must NOT commit when ETag is absent.
    st.lock()
        .unwrap()
        .mtimes
        .insert(format!("{ROOT}/no_etag_mtime.bin"), 1_600_000_000);
    let outcome_mismatch = nc.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome_mismatch, ReconcileOutcome::NotCommitted),
        "mismatched mtime without ETag must return NotCommitted: {outcome_mismatch:?}"
    );

    // Non-multipart op with DstPrecondition::Any + empty backend_meta -> NotCommitted.
    op.dst_precondition = DstPrecondition::Any;
    assert!(matches!(
        nc.reconcile_operation(&op).await.unwrap(),
        ReconcileOutcome::NotCommitted
    ));
}
