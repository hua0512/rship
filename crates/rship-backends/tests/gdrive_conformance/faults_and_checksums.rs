use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rship_backends::gdrive::{
    FOLDER_MIME, GdriveBackend, InMemoryTokenStore, OAuth2AuthProvider, OAuthToken,
    StaticBearerAuth,
};
use rship_core::backend::{BackendPath, ReconcileOutcome, StorageBackend, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::clock::{Clock, SystemClock, VirtualClock};
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::DataSource;
use rship_core::state::{DstPrecondition, JobMode, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{HashKind, NodeId};
use rship_core::{ErrorKind, RetryClass};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, LimiterScope, TransportConfig};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::common::InjectedFault;
use crate::mock_server::{MockFile, MockGdriveServer, read_gdrive_bytes};

// =========================================================================
// Test 5: Lost Final Response -> 404 on query_upload -> Reconcile by fileId
// =========================================================================

#[tokio::test]
async fn gdrive_lost_final_response_then_404_reconciles_without_duplicate() {
    let srv = MockGdriveServer::start().await;
    srv.state
        .lock()
        .unwrap()
        .faults
        .drop_final_chunk_response_after_commit = true;

    let mut cfg = srv.config("gd-reconcile");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = 256 * 1024;

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice", "tok"));
    let gdrive = Arc::new(GdriveBackend::new(cfg, transport, auth, None, None));

    let tmp = tempfile::TempDir::new().unwrap();
    let payload: Vec<u8> = (0..(256 * 1024 + 4096)).map(|i| (i % 239) as u8).collect();
    std::fs::write(tmp.path().join("reconcile.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        gdrive.clone(),
        state_actor.clone(),
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let mut ecfg = EngineConfig::new("job-rec", JobMode::Copy, "local", "gd");
    ecfg.base_retry_delay = Duration::from_millis(5);

    let report = engine.run(&ecfg, idx).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.files_transferred, 1);

    // Must have reconciled via pregenerated fileId with ONLY 1 session init (no restart/duplicate!).
    let g = srv.state.lock().unwrap();
    assert_eq!(g.counters.resumable_begin_post, 1);
    assert_eq!(g.counters.query_upload_calls, 1);
    let files: Vec<_> = g
        .files
        .values()
        .filter(|f| f.name == "reconcile.bin")
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].data, payload);
}

// =========================================================================
// Test 6: 401 Mid-Upload Token Refresh Preserves Active `session_uri`
// =========================================================================

#[tokio::test]
async fn gdrive_401_refresh_mid_upload_preserves_session_uri() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.valid_token = Some("token-v1".to_string());
        g.faults.next_refreshed_token = Some("token-v2".to_string());
        // Force 401 specifically on chunk #2 of a 3-chunk upload!
        g.faults.expire_token_on_chunk_call = Some(2);
    }

    let mut cfg = srv.config("gd-401");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = 256 * 1024;

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "token-v1".into(),
        refresh_token: Some("refresh-secret".into()),
        token_type: "Bearer".into(),
        expires_at_unix_secs: 1_700_003_600,
        scope: None,
    })));
    let auth = Arc::new(
        OAuth2AuthProvider::new(
            "alice@example.com",
            "cid",
            "csec",
            cfg.token_url.clone(),
            transport.clone(),
            store,
            clock.clone(),
        )
        .unwrap(),
    );
    let gdrive = Arc::new(GdriveBackend::new(
        cfg,
        transport,
        auth,
        None,
        Some(clock.clone()),
    ));

    let tmp = tempfile::TempDir::new().unwrap();
    // 3 chunks: 256 KiB + 256 KiB + 512 bytes.
    let payload: Vec<u8> = (0..(256 * 1024 * 2 + 512))
        .map(|i| (i % 199) as u8)
        .collect();
    std::fs::write(tmp.path().join("resilient.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        gdrive.clone(),
        state_actor,
        pool,
        clock,
        CancelFlag::new(),
    );

    let idx = Arc::new(SqliteSyncIndex::open_in_memory().unwrap());
    let mut ecfg = EngineConfig::new("job-401", JobMode::Copy, "local", "gd");
    ecfg.base_retry_delay = Duration::from_millis(5);

    let report = engine.run(&ecfg, idx).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.files_transferred, 1);

    assert_eq!(
        read_gdrive_bytes(&gdrive, &RelPath::parse("resilient.bin").unwrap()).await,
        payload
    );

    let g = srv.state.lock().unwrap();
    assert_eq!(
        g.counters.token_refreshes, 1,
        "must refresh token exactly once"
    );
    assert_eq!(
        g.counters.resumable_begin_post, 1,
        "401 refresh MUST preserve active session_uri without restarting session!"
    );
    assert_eq!(
        g.counters.query_upload_calls, 1,
        "after 401 refresh, engine queries 308 on same session_uri and resumes from chunk 2"
    );
    // Chunk 1 (ok) + Chunk 2 (401) + Chunk 2 retry (ok) + Chunk 3 (ok) = 4 PUTs (chunk 1 NOT resent!).
    assert_eq!(g.counters.chunk_put_calls, 4);
}

// =========================================================================
// Test 7: 403 Reason Classification (Throttle Retries vs Quota Fails Fast)
// =========================================================================

#[tokio::test]
async fn gdrive_403_reason_retries_rate_limit_and_fails_fast_on_quota_exhausted() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        let rate_err = json!({
            "error": {
                "code": 403,
                "message": "User Rate Limit Exceeded",
                "errors": [{ "domain": "usageLimits", "reason": "userRateLimitExceeded" }]
            }
        })
        .to_string();
        g.faults
            .queued_control_errors
            .push_back((StatusCode::FORBIDDEN, rate_err.clone()));
        g.faults
            .queued_control_errors
            .push_back((StatusCode::FORBIDDEN, rate_err));
    }

    let backend = srv.backend("gd-403");
    // Two 403 `userRateLimitExceeded` responses -> MUST retry and succeed!
    backend
        .mkdir(&RelPath::parse("throttled_ok").unwrap())
        .await
        .expect("userRateLimitExceeded should be retried until success");

    // Now inject fatal `storageQuotaExceeded` -> MUST fail fast on attempt 1!
    {
        let mut g = srv.state.lock().unwrap();
        let quota_err = json!({
            "error": {
                "code": 403,
                "message": "Storage quota exceeded",
                "errors": [{ "domain": "usageLimits", "reason": "storageQuotaExceeded" }]
            }
        })
        .to_string();
        // Queue 2 identical errors: if backend wrongly retried, both would be consumed!
        g.faults
            .queued_control_errors
            .push_back((StatusCode::FORBIDDEN, quota_err.clone()));
        g.faults
            .queued_control_errors
            .push_back((StatusCode::FORBIDDEN, quota_err));
    }

    let err = backend
        .mkdir(&RelPath::parse("quota_fail").unwrap())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::QuotaExceeded);
    assert_eq!(err.retry, RetryClass::Permanent);
    // Second queued error must still be untouched, proving ZERO retries occurred!
    assert_eq!(
        srv.state.lock().unwrap().faults.queued_control_errors.len(),
        1
    );
}

// =========================================================================
// Test 14 (D5a): Folder Create (`mkdir`) Lost Response After Commit -> Zero Duplicates
// =========================================================================

#[tokio::test]
async fn gdrive_d5_folder_create_lost_response_reconciles_without_duplicate() {
    let srv = MockGdriveServer::start().await;
    let faults = srv.fault_injector();
    let backend = srv.backend("gd-d5-mkdir");

    // 1. CommitThenError(503): folder commits on server, response lost as 503.
    //    Pre-fix: blind retry creates 2 duplicate folders!
    //    Post-fix: pre-generated ID reconciles via files.get -> strictly 1 folder!
    faults.push(
        "files.create",
        InjectedFault::commit_then_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": {
                    "code": 503,
                    "message": "Backend Error",
                    "errors": [{ "domain": "global", "reason": "backendError" }]
                }
            })
            .to_string(),
        ),
    );
    backend
        .mkdir(&RelPath::parse("d5_dir_503").unwrap())
        .await
        .expect("folder create should reconcile after post-commit 503");

    {
        let g = srv.state.lock().unwrap();
        let dirs: Vec<_> = g
            .files
            .values()
            .filter(|f| f.name == "d5_dir_503" && f.mime_type == FOLDER_MIME)
            .collect();
        assert_eq!(
            dirs.len(),
            1,
            "lost 503 after folder create commit must NOT create duplicate folder; found {:?}",
            dirs.iter().map(|d| &d.id).collect::<Vec<_>>()
        );
        assert!(
            dirs[0].id.starts_with("pregen-"),
            "folder create must use pre-generated ID from files.generateIds, got `{}`",
            dirs[0].id
        );
        assert_eq!(g.counters.folder_creates, 1);
    }

    // 2. CommitThenReset: folder commits on server, TCP stream resets before response body.
    faults.push("files.create", InjectedFault::commit_then_reset());
    backend
        .mkdir(&RelPath::parse("d5_dir_reset").unwrap())
        .await
        .expect("folder create should reconcile after post-commit reset");

    {
        let g = srv.state.lock().unwrap();
        let dirs: Vec<_> = g
            .files
            .values()
            .filter(|f| f.name == "d5_dir_reset" && f.mime_type == FOLDER_MIME)
            .collect();
        assert_eq!(
            dirs.len(),
            1,
            "lost reset after folder create commit must NOT create duplicate folder; found {:?}",
            dirs.iter().map(|d| &d.id).collect::<Vec<_>>()
        );
        assert!(dirs[0].id.starts_with("pregen-"));
        assert_eq!(g.counters.folder_creates, 2);
    }

    // 3. Pre-commit transient 503 (NOT committed): reconcile sees 404 -> retries with SAME pregen ID!
    let gen_before = srv.state.lock().unwrap().counters.generate_ids;
    faults.push(
        "files.create",
        InjectedFault::service_unavailable(Some("0")),
    );
    backend
        .mkdir(&RelPath::parse("d5_dir_precommit_retry").unwrap())
        .await
        .expect("pre-commit 503 on folder create should retry cleanly with same pregen ID");
    {
        let g = srv.state.lock().unwrap();
        let dirs: Vec<_> = g
            .files
            .values()
            .filter(|f| f.name == "d5_dir_precommit_retry" && f.mime_type == FOLDER_MIME)
            .collect();
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].id.starts_with("pregen-"));
        assert!(
            g.counters.generate_ids - gen_before <= 1,
            "retry after pre-commit 503 must reuse the exact same pre-generated ID (generate_ids delta={})",
            g.counters.generate_ids - gen_before
        );
        assert_eq!(g.counters.folder_creates, 3);
    }
}

// =========================================================================
// Test 15 (D5b): `files.copy` Lost Response After Commit -> Zero Duplicates
// =========================================================================

#[tokio::test]
async fn gdrive_d5_server_side_copy_lost_response_reconciles_without_duplicate() {
    let srv = MockGdriveServer::start().await;
    let payload = b"d5-server-side-copy-payload-no-duplicates".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "f_src_d5".into(),
            MockFile {
                id: "f_src_d5".into(),
                name: "source.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let faults = srv.fault_injector();
    let backend = srv.backend("gd-d5-copy");
    let endpoint = backend.endpoint_identity();
    let src_bp = BackendPath::new(
        "source.bin",
        RelPath::parse("source.bin").unwrap(),
        Some(NodeId("f_src_d5".into())),
    );

    // 1. CommitThenError(503) without explicit pregenerated_id: backend generates ID via
    //    files.generateIds, commits once, reconciles via files.get -> strictly 1 copied file!
    faults.push(
        "files.copy",
        InjectedFault::commit_then_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": {
                    "code": 503,
                    "message": "Backend Error",
                    "errors": [{ "domain": "global", "reason": "backendError" }]
                }
            })
            .to_string(),
        ),
    );
    let init1 = UploadInit {
        op_id: "op-d5-copy-503".into(),
        dst_path: RelPath::parse("copied_503.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry1 = backend
        .server_side_copy(&endpoint, &src_bp, &init1)
        .await
        .expect("files.copy should reconcile post-commit 503")
        .expect("server-side copy should succeed");
    assert_eq!(entry1.size, payload.len() as u64);

    {
        let g = srv.state.lock().unwrap();
        let copies: Vec<_> = g
            .files
            .values()
            .filter(|f| f.name == "copied_503.bin")
            .collect();
        assert_eq!(
            copies.len(),
            1,
            "lost 503 after files.copy commit must NOT create duplicate copy; found {:?}",
            copies.iter().map(|c| &c.id).collect::<Vec<_>>()
        );
        assert!(
            copies[0].id.starts_with("pregen-"),
            "files.copy must send pre-generated id, got `{}`",
            copies[0].id
        );
        assert_eq!(
            copies[0]
                .app_properties
                .get("rship_op_id")
                .map(String::as_str),
            Some("op-d5-copy-503")
        );
        assert_eq!(g.counters.copy_calls, 1);
    }

    // 2. CommitThenReset WITH explicit `init.pregenerated_id`: honors caller-supplied ID!
    faults.push("files.copy", InjectedFault::commit_then_reset());
    let init2 = UploadInit {
        op_id: "op-d5-copy-reset".into(),
        dst_path: RelPath::parse("copied_reset.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: Some(NodeId("caller-pregen-copy-id".into())),
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry2 = backend
        .server_side_copy(&endpoint, &src_bp, &init2)
        .await
        .expect("files.copy should reconcile post-commit reset")
        .expect("server-side copy should succeed");
    assert_eq!(
        entry2.node_id.as_ref().map(|n| n.0.as_str()),
        Some("caller-pregen-copy-id")
    );
    {
        let g = srv.state.lock().unwrap();
        let copies: Vec<_> = g
            .files
            .values()
            .filter(|f| f.name == "copied_reset.bin")
            .collect();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].id, "caller-pregen-copy-id");
        assert_eq!(g.counters.copy_calls, 2);
    }

    // 3. Re-issuing `files.copy` with an already-committed `pregenerated_id` + matching `op_id`
    //    hits HTTP 409 Conflict -> `PolicyDecision::Reconcile` resolves via `files.get`!
    let init3_same_op = UploadInit {
        op_id: "op-d5-copy-reset".into(),
        dst_path: RelPath::parse("copied_reset_alias.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: Some(NodeId("caller-pregen-copy-id".into())),
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let resolved_409 = backend
        .server_side_copy(&endpoint, &src_bp, &init3_same_op)
        .await
        .expect("409 on already-committed pregenerated copy_id should reconcile")
        .expect("reconciled copy should return Some(Entry)");
    assert_eq!(
        resolved_409.node_id.as_ref().map(|n| n.0.as_str()),
        Some("caller-pregen-copy-id")
    );

    // A conflicting `op_id` reusing the same `pregenerated_id` MUST fail with Conflict!
    let init3_other_op = UploadInit {
        op_id: "op-different-writer".into(),
        ..init3_same_op
    };
    let conflict_err = backend
        .server_side_copy(&endpoint, &src_bp, &init3_other_op)
        .await
        .expect_err("409 with mismatched rship_op_id must fail with Conflict");
    assert_eq!(conflict_err.kind, ErrorKind::Conflict);
}

// =========================================================================
// Test 16 (D5c): Single-Shot Upload Pre-Generated ID & Lost Response -> Zero Duplicates
// =========================================================================

#[tokio::test]
async fn gdrive_d5_single_shot_upload_lost_response_reconciles_without_duplicate() {
    let srv = MockGdriveServer::start().await;
    let faults = srv.fault_injector();

    // 1. End-to-end TransferEngine single-shot upload with CommitThenError(503):
    //    `init.pregenerated_id` is None and `op.remote_op_id` is None.
    //    Pre-fix: `put_single_shot` skips generateIds, `reconcile_operation` returns NotCommitted,
    //    engine retries `put_single_shot` and creates 2 duplicate files!
    //    Post-fix: `put_single_shot` generates ID + writes `appProperties.rship_op_id`,
    //    `reconcile_operation` falls back to `appProperties.rship_op_id` search -> strictly 1 file!
    faults.push(
        "upload.multipart",
        InjectedFault::commit_then_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": {
                    "code": 503,
                    "message": "Backend Error",
                    "errors": [{ "domain": "global", "reason": "backendError" }]
                }
            })
            .to_string(),
        ),
    );

    let gdrive = Arc::new(srv.backend("gd-d5-ss"));
    let tmp = tempfile::TempDir::new().unwrap();
    let payload = b"single-shot-d5-lost-response-payload".to_vec();
    std::fs::write(tmp.path().join("small.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(512 * 1024, 64 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        gdrive.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-d5-ss", JobMode::Copy, "local", "gd");
    ecfg.base_retry_delay = Duration::from_millis(5);
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);

    {
        let g = srv.state.lock().unwrap();
        let files: Vec<_> = g.files.values().filter(|f| f.name == "small.bin").collect();
        assert_eq!(
            files.len(),
            1,
            "lost 503 after single-shot commit must NOT create duplicate file; found {:?}",
            files.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert!(
            files[0].id.starts_with("pregen-"),
            "single-shot upload must pre-generate file ID when init.pregenerated_id is None, got `{}`",
            files[0].id
        );
        assert!(
            files[0].app_properties.contains_key("rship_op_id"),
            "single-shot upload must attach appProperties.rship_op_id"
        );
        assert_eq!(g.counters.multipart_post, 1);
        assert_eq!(files[0].data, payload);
    }

    // 2. Direct single-shot with explicit `init.pregenerated_id` + `CommitThenError(503)`:
    //    `reconcile_operation` with `op.remote_op_id` checks `files.get` FIRST (0 `files.list`),
    //    and even a bare retry of `put_single_shot` with the same `pregenerated_id` handles 409
    //    without duplicating!
    faults.push(
        "upload.multipart",
        InjectedFault::commit_then_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": {
                    "code": 503,
                    "message": "Backend Error",
                    "errors": [{ "domain": "global", "reason": "backendError" }]
                }
            })
            .to_string(),
        ),
    );
    let explicit_id = gdrive
        .generate_file_id()
        .await
        .expect("public generate_file_id helper must return pregen ID");
    assert!(explicit_id.starts_with("pregen-"));
    let rel2 = RelPath::parse("explicit_pregen.bin").unwrap();
    let payload2 = b"explicit-pregenerated-id-single-shot".to_vec();
    let init2 = UploadInit {
        op_id: "op-d5-ss-explicit".into(),
        dst_path: rel2.clone(),
        existing_node_id: None,
        pregenerated_id: Some(NodeId(explicit_id.clone())),
        total_size: payload2.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload2.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let p2_c = payload2.clone();
    let err = gdrive
        .put_single_shot(
            &init2,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p2_c)) })),
        )
        .await
        .expect_err("CommitThenError(503) must surface error from put_single_shot");
    assert_eq!(err.kind, ErrorKind::RateLimited);

    let list_calls_before = srv.state.lock().unwrap().counters.list_queries.len();
    let op2 = OperationRecord {
        op_id: init2.op_id.clone(),
        session_key: "sk-explicit".into(),
        job_id: "job-explicit".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: gdrive.endpoint_identity(),
        src_raw_path: rel2.as_str().into(),
        dst_raw_path: rel2.as_str().into(),
        dst_nfc_path: rel2.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload2.len() as u64,
            mtime_ns: init2.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Absent,
        existing_dst_node_id: None,
        remote_op_id: Some(explicit_id.clone()),
        backend_kind: "gdrive".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: payload2.len() as u64,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    match gdrive.reconcile_operation(&op2).await.unwrap() {
        ReconcileOutcome::Committed(entry) => {
            assert_eq!(
                entry.node_id.as_ref().map(|n| n.0.as_str()),
                Some(explicit_id.as_str())
            );
            assert_eq!(entry.size, payload2.len() as u64);
        }
        other => panic!("expected Committed via remote_op_id, got {other:?}"),
    }
    assert_eq!(
        srv.state.lock().unwrap().counters.list_queries.len(),
        list_calls_before,
        "reconcile_operation with remote_op_id must check files.get first without files.list"
    );

    // Retrying put_single_shot directly with the same pregenerated_id + op_id hits mock 409
    // and resolves cleanly without creating a duplicate!
    let p2_retry = payload2.clone();
    let resolved = gdrive
        .put_single_shot(
            &init2,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(p2_retry)) },
            )),
        )
        .await
        .expect("409 on duplicate pregenerated_id with matching op_id should reconcile");
    assert_eq!(
        resolved.node_id.as_ref().map(|n| n.0.as_str()),
        Some(explicit_id.as_str())
    );
    let g = srv.state.lock().unwrap();
    let files2: Vec<_> = g
        .files
        .values()
        .filter(|f| f.name == "explicit_pregen.bin")
        .collect();
    assert_eq!(files2.len(), 1);
    assert_eq!(files2[0].id, explicit_id);
}

// =========================================================================
// Test 17: Scripted 429 (`userRateLimitExceeded` + `Retry-After`), 503 Quota
//          Refund, Plane Isolation, and `retries_exhausted == true`
// =========================================================================

#[tokio::test]
async fn gdrive_scripted_429_retry_after_and_503_quota_refund_and_exhaustion() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "f_ok".into(),
            MockFile {
                id: "f_ok".into(),
                name: "hello.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"hello".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let faults = srv.fault_injector();
    let mut cfg = srv.config("gd-quota");
    cfg.max_retries = 2;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(50);

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport.clone(), auth, None, None);

    // 1. Scripted 429 (`userRateLimitExceeded`) with `Retry-After: 3600` (capped to 50ms).
    let rate_limit_429 = json!({
        "error": {
            "code": 429,
            "message": "User rate limit exceeded.",
            "errors": [{
                "domain": "usageLimits",
                "reason": "userRateLimitExceeded",
                "message": "User rate limit exceeded."
            }]
        }
    })
    .to_string();
    faults.push(
        "files.list",
        InjectedFault::json_error(StatusCode::TOO_MANY_REQUESTS, rate_limit_429)
            .with_retry_after("3600"),
    );

    let t0 = std::time::Instant::now();
    let mut stream = backend.list_stream(&RelPath::root(), false).await.unwrap();
    let mut names = Vec::new();
    while let Some(item) = stream.next().await {
        names.push(item.unwrap().nfc_path.as_str().to_string());
    }
    let elapsed_429 = t0.elapsed();
    assert_eq!(names, vec!["hello.txt"]);
    assert!(
        elapsed_429 >= Duration::from_millis(35) && elapsed_429 < Duration::from_secs(2),
        "Retry-After: 3600 must be capped to max_retry_delay (50ms), took {elapsed_429:?}"
    );
    assert_eq!(faults.op_faults("files.list"), 1);
    assert_eq!(faults.op_requests("files.list"), 2);

    // Verify exact retry quota refund (`available == max_tokens`) and plane isolation (P2)!
    let ctrl_lim =
        transport.control_limiter_for(LimiterScope::new("gd-quota", "alice@example.com"));
    let data_lim = transport.data_limiter_for(LimiterScope::new("gd-quota", "alice@example.com"));
    assert!(Arc::ptr_eq(&ctrl_lim, backend.control_limiter()));
    assert!(Arc::ptr_eq(&data_lim, backend.data_limiter()));
    let ctrl_snap = ctrl_lim.snapshot();
    assert!(
        ctrl_snap.cubic_enabled,
        "429 must activate control-plane CUBIC"
    );
    assert!(
        !data_lim.snapshot().cubic_enabled,
        "control-plane 429 must NOT throttle isolated data-plane limiter"
    );
    assert_eq!(
        ctrl_snap.retry_quota_available, ctrl_snap.retry_quota_max,
        "successful recovery after 429 must refund exact retry quota back to max_tokens"
    );

    // 2. Scripted 503 recovery ALSO refunds exact retry quota (`available == max_tokens`).
    faults.push("files.list", InjectedFault::service_unavailable(Some("0")));
    let mut stream2 = backend.list_stream(&RelPath::root(), false).await.unwrap();
    let mut names2 = Vec::new();
    while let Some(item) = stream2.next().await {
        names2.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(names2, vec!["hello.txt"]);
    let ctrl_snap2 = ctrl_lim.snapshot();
    assert_eq!(
        ctrl_snap2.retry_quota_available, ctrl_snap2.retry_quota_max,
        "successful recovery after 503 must refund exact retry quota back to max_tokens"
    );

    // 3. Exhausting `max_retries` (2 retries = 3 total attempts) sets `retries_exhausted == true`!
    let reqs_before = faults.op_requests("files.list");
    faults.push_many(
        "files.list",
        [
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
            InjectedFault::service_unavailable(Some("0")),
        ],
    );
    let err = backend
        .stat(&BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()))
        .await
        .expect_err("3 consecutive 503s with max_retries=2 must fail");
    assert_eq!(err.kind, ErrorKind::RateLimited);
    assert!(
        err.retries_exhausted(),
        "exhausted control-plane error must set retries_exhausted == true"
    );
    assert!(
        !err.is_retryable(),
        "retries_exhausted must prevent outer engine retry stacking"
    );
    assert_eq!(
        faults.op_requests("files.list") - reqs_before,
        3,
        "expected 1 initial attempt + 2 retries = 3 requests"
    );
}

// =========================================================================
// Test 18: Slow Finalize on Final Resumable Upload Chunk Succeeds Without Stall Timeout
// =========================================================================

#[tokio::test]
async fn gdrive_slow_finalize_on_final_resumable_chunk_succeeds_without_stall_timeout() {
    let srv = MockGdriveServer::start().await;
    let faults = srv.fault_injector();

    // Delay exceeds short `data_stall_timeout` (80ms) while staying well below
    // `data_finalize_timeout` (5s): ProgressWatchdog must transition to finalize
    // timeout after body EOF and complete without a false stall timeout!
    faults.push(
        "upload.chunk_final",
        InjectedFault::slow_finalize(Duration::from_millis(250)),
    );

    let mut cfg = srv.config("gd-slow-fin");
    cfg.single_shot_max_bytes = 64 * 1024;
    cfg.default_chunk_size = 256 * 1024;

    let transport = HttpTransport::new(
        TransportConfig::new()
            .with_data_stall_timeout(Duration::from_millis(80))
            .with_data_finalize_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let gdrive = Arc::new(GdriveBackend::new(cfg, transport, auth, None, None));

    let tmp = tempfile::TempDir::new().unwrap();
    let payload: Vec<u8> = (0..(256 * 1024 + 4096))
        .map(|i| ((i * 17 + 5) % 251) as u8)
        .collect();
    std::fs::write(tmp.path().join("slow_finalize.bin"), &payload).unwrap();

    let local = Arc::new(rship_backends::local::LocalBackend::new("local", tmp.path()).unwrap());
    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap();
    let engine = TransferEngine::new(
        local,
        gdrive.clone(),
        state_actor,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    );
    let mut ecfg = EngineConfig::new("job-slow-fin", JobMode::Copy, "local", "gd");
    ecfg.base_retry_delay = Duration::from_millis(5);

    let started = std::time::Instant::now();
    let rep = engine
        .run(&ecfg, Arc::new(SqliteSyncIndex::open_in_memory().unwrap()))
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 1);
    assert!(
        elapsed >= Duration::from_millis(200),
        "expected SlowFinalize delay (~250ms), elapsed={elapsed:?}"
    );
    assert_eq!(
        faults.op_requests("upload.chunk_final"),
        1,
        "final resumable chunk must succeed on first attempt without false stall timeout"
    );
    assert_eq!(faults.op_faults("upload.chunk_final"), 1);
    assert_eq!(
        read_gdrive_bytes(&gdrive, &RelPath::parse("slow_finalize.bin").unwrap()).await,
        payload
    );
}

// =========================================================================
// Test 19: C3 — Streaming MD5 Upload & Full-Object Download Verification
// =========================================================================

#[tokio::test]
async fn gdrive_c3_streaming_md5_upload_and_download_verification() {
    use rship_core::types::{ByteRange, Checksum};

    let srv = MockGdriveServer::start().await;
    let backend = srv.backend("gd-c3");

    let payload = b"gdrive c3 streaming md5 end-to-end verification payload bytes!".to_vec();
    let expected_md5 = hex::encode(Md5::digest(&payload));
    let good_path = RelPath::parse("c3/good.bin").unwrap();

    // (a1) Clean multi-chunk streaming upload succeeds with matching known MD5 (case-insensitive).
    let good_init = UploadInit {
        op_id: "op-gd-c3-good".into(),
        dst_path: good_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Md5,
            hex: expected_md5.to_ascii_uppercase(),
        }],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let good_chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(17)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let entry = backend
        .put_single_shot(&good_init, Box::pin(futures::stream::iter(good_chunks)))
        .await
        .expect("matching MD5 upload must succeed");
    assert_eq!(entry.size, payload.len() as u64);

    // (a2) Streaming upload corruption detection (empty `init.checksums` -> caught purely by
    //      `StreamingHashStream<_, StreamingMd5>` against mismatched server `md5Checksum`!).
    srv.state.lock().unwrap().faults.corrupt_upload_md5_once = true;
    let bad_init = UploadInit {
        op_id: "op-gd-c3-bad".into(),
        dst_path: RelPath::parse("c3/bad-upload.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let bad_chunks: Vec<rship_core::Result<Bytes>> = payload
        .chunks(13)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let upload_err = backend
        .put_single_shot(&bad_init, Box::pin(futures::stream::iter(bad_chunks)))
        .await
        .expect_err("mismatched server md5Checksum must fail streaming upload");
    assert_eq!(upload_err.kind, ErrorKind::Integrity);
    assert!(upload_err.is_integrity());
    assert!(
        upload_err
            .message()
            .contains("GDrive upload MD5 checksum mismatch"),
        "unexpected error message: {}",
        upload_err.message()
    );

    // (a3) Known `init.checksums` MD5 mismatch against server `md5Checksum` also fails!
    let mismatch_known_init = UploadInit {
        op_id: "op-gd-c3-known-mismatch".into(),
        dst_path: RelPath::parse("c3/known-mismatch.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![Checksum {
            kind: HashKind::Md5,
            hex: "ffffffffffffffffffffffffffffffff".into(),
        }],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_c = payload.clone();
    let known_err = backend
        .put_single_shot(
            &mismatch_known_init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .expect_err("mismatched init.checksums MD5 must fail upload");
    assert_eq!(known_err.kind, ErrorKind::Integrity);
    assert!(known_err.is_integrity());
    assert!(known_err.message().contains("checksum mismatch"));

    // (b) Full-object download detects in-transit body corruption against metadata MD5!
    let reader = match backend
        .open_read(&BackendPath::from_rel(good_path.clone()), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    srv.state.lock().unwrap().faults.corrupt_download_body_once = true;
    let mut bad_dl = reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut dl_err = None;
    while let Some(item) = bad_dl.next().await {
        if let Err(e) = item {
            dl_err = Some(e);
            break;
        }
    }
    let dl_err = dl_err.expect("corrupted full-object GDrive download must fail MD5 verification");
    assert_eq!(dl_err.kind, ErrorKind::Integrity);
    assert!(dl_err.is_integrity());
    assert!(
        dl_err.message().contains("checksum mismatch"),
        "unexpected download error: {}",
        dl_err.message()
    );

    // Clean full-object download via `open_read_entry` succeeds bit-exact.
    let entry_reader = match backend
        .open_read_entry(&entry, &BackendPath::from_rel(good_path), None)
        .await
        .unwrap()
    {
        DataSource::RemoteRangeReadable(r) => r,
        _ => panic!("expected RemoteRangeReadable"),
    };
    let mut full_stream = entry_reader
        .open_range(ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut full_got = Vec::new();
    while let Some(item) = full_stream.next().await {
        full_got.extend_from_slice(&item.unwrap());
    }
    assert_eq!(full_got, payload);

    // (c) Sub-range downloads (`offset > 0` or `len < total_len`) succeed without false MD5 error!
    for range in [
        ByteRange { offset: 0, len: 13 },
        ByteRange { offset: 7, len: 19 },
        ByteRange {
            offset: payload.len() as u64 - 11,
            len: 11,
        },
    ] {
        let mut s = entry_reader.open_range(range).await.unwrap();
        let mut got = Vec::new();
        while let Some(item) = s.next().await {
            got.extend_from_slice(&item.unwrap());
        }
        assert_eq!(
            got,
            payload[range.offset as usize..(range.offset + range.len) as usize]
        );
    }
}

// =========================================================================
// P1: `stop_on_upload_limit` on `files.copy` & Exact Message Match
// =========================================================================

#[tokio::test]
async fn gdrive_stop_on_upload_limit_fast_fails_copy_and_allows_burst_403_retry() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "f_copy_src".into(),
            MockFile {
                id: "f_copy_src".into(),
                name: "src.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"copy-me".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let faults = srv.fault_injector();
    let cfg = srv.config("gd-limit").with_stop_on_upload_limit(true);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, None, None);

    // 1. Exact `"User rate limit exceeded."` on `files.copy` MUST fail fast with QuotaExceeded!
    let daily_limit_body = json!({
        "error": {
            "code": 403,
            "message": "User rate limit exceeded.",
            "errors": [{
                "domain": "usageLimits",
                "reason": "userRateLimitExceeded",
                "message": "User rate limit exceeded."
            }]
        }
    })
    .to_string();
    faults.push_many(
        "files.copy",
        [
            InjectedFault::json_error(StatusCode::FORBIDDEN, daily_limit_body.clone()),
            InjectedFault::json_error(StatusCode::FORBIDDEN, daily_limit_body),
        ],
    );
    let reqs_before = faults.op_requests("files.copy");
    let err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::new(
                "src.bin",
                RelPath::parse("src.bin").unwrap(),
                Some(NodeId("f_copy_src".into())),
            ),
            &UploadInit {
                op_id: "op-copy-limit".into(),
                dst_path: RelPath::parse("dst.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 7,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 7,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::QuotaExceeded);
    assert_eq!(err.retry, RetryClass::Permanent);
    assert_eq!(
        faults.op_requests("files.copy") - reqs_before,
        1,
        "exact upload limit on files.copy must not retry"
    );
    assert!(
        faults.next_fault("files.copy").is_some(),
        "second queued fault must remain unconsumed because exact upload limit did not retry"
    );

    // 2. Short-term burst `"User Rate Limit Exceeded"` on `files.copy` MUST retry & succeed!
    let burst_body = json!({
        "error": {
            "code": 403,
            "message": "User Rate Limit Exceeded",
            "errors": [{ "domain": "usageLimits", "reason": "userRateLimitExceeded" }]
        }
    })
    .to_string();
    faults.push(
        "files.copy",
        InjectedFault::json_error(StatusCode::FORBIDDEN, burst_body),
    );
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::new(
                "src.bin",
                RelPath::parse("src.bin").unwrap(),
                Some(NodeId("f_copy_src".into())),
            ),
            &UploadInit {
                op_id: "op-copy-burst-ok".into(),
                dst_path: RelPath::parse("dst_ok.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 7,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 7,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap();
    assert!(copied.is_some());
}

// =========================================================================
// P1: Single-Shot Overwrite With Pregenerated `remote_op_id` Reconciles
// =========================================================================

#[tokio::test]
async fn gdrive_single_shot_overwrite_with_pregenerated_id_reconciles_after_503() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "existing_ow".into(),
            MockFile {
                id: "existing_ow".into(),
                name: "ow.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"old-data".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-ss-ow-rec");
    let faults = srv.fault_injector();
    faults.push(
        "upload.multipart",
        InjectedFault::commit_then_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": {
                    "code": 503,
                    "message": "Backend Error",
                    "errors": [{ "domain": "global", "reason": "backendError" }]
                }
            })
            .to_string(),
        ),
    );

    let new_payload = b"new-overwrite-payload-12345".to_vec();
    let rel = RelPath::parse("ow.bin").unwrap();
    let unused_pregen = backend.generate_file_id().await.unwrap();
    let init = UploadInit {
        op_id: "op-ss-ow-503".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: Some(NodeId(unused_pregen.clone())),
        total_size: new_payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: new_payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_c = new_payload.clone();
    let err = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::RateLimited);

    // Reconcile with `existing_dst_node_id = None` and unused `remote_op_id`:
    // MUST fall back to `find_child_by_op_id` and return `Committed`!
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-ow".into(),
        job_id: "job-ow".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: rel.as_str().into(),
        dst_raw_path: rel.as_str().into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: new_payload.len() as u64,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: Some(unused_pregen),
        backend_kind: "gdrive".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: new_payload.len() as u64,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    match backend.reconcile_operation(&op).await.unwrap() {
        ReconcileOutcome::Committed(entry) => {
            assert_eq!(
                entry.node_id.as_ref().map(|n| n.as_str()),
                Some("existing_ow")
            );
            assert_eq!(entry.size, new_payload.len() as u64);
        }
        other => panic!("expected Committed via find_child_by_op_id, got {other:?}"),
    }
}

// =========================================================================
// P2: Single-Shot `SlowFinalize` via `send_watched_sized_upload_with_capture`
// =========================================================================

#[tokio::test]
async fn gdrive_single_shot_slow_finalize_succeeds_without_stall_timeout() {
    let srv = MockGdriveServer::start().await;
    let faults = srv.fault_injector();
    faults.push(
        "upload.multipart",
        InjectedFault::slow_finalize(Duration::from_millis(250)),
    );

    let transport = HttpTransport::new(
        TransportConfig::new()
            .with_data_stall_timeout(Duration::from_millis(80))
            .with_data_finalize_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(srv.config("gd-ss-slow"), transport, auth, None, None);

    let payload = b"single-shot-slow-finalize-bytes".to_vec();
    let p_c = payload.clone();
    let entry = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-ss-slow".into(),
                dst_path: RelPath::parse("slow_ss.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: payload.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: payload.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) })),
        )
        .await
        .expect("single-shot SlowFinalize must transition to data_finalize_timeout");
    assert_eq!(entry.size, payload.len() as u64);
}

// =========================================================================
// P1: SHA-256 / SHA-1 / MD5 `compute_hash` & Shared-Drive `about()`
// =========================================================================

#[tokio::test]
async fn gdrive_computes_sha256_sha1_md5_and_shared_drive_about_is_none() {
    use sha2::{Digest as _, Sha256};

    let srv = MockGdriveServer::start().await;
    let payload = b"hash-verification-payload-123".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "f_hash".into(),
            MockFile {
                id: "f_hash".into(),
                name: "hashed.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-hash");
    let caps = backend.capabilities();
    assert!(caps.hashes.contains(&HashKind::Sha256));
    assert!(caps.hashes.contains(&HashKind::Sha1));
    assert!(caps.hashes.contains(&HashKind::Md5));

    let bp = BackendPath::from_rel(RelPath::parse("hashed.bin").unwrap());
    let h_sha256 = backend
        .compute_hash(&bp, HashKind::Sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_sha256.kind, HashKind::Sha256);
    assert_eq!(h_sha256.hex, hex::encode(Sha256::digest(&payload)));

    let h_sha1 = backend
        .compute_hash(&bp, HashKind::Sha1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_sha1.kind, HashKind::Sha1);
    assert_eq!(h_sha1.hex.len(), 40);

    let h_md5 = backend
        .compute_hash(&bp, HashKind::Md5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_md5.kind, HashKind::Md5);
    assert_eq!(h_md5.hex, hex::encode(Md5::digest(&payload)));

    // Personal Drive `about()` returns quota; Shared Drive `about()` returns `Ok(None)`.
    let quota = backend.about().await.unwrap().expect("personal quota");
    assert_eq!(quota.total_bytes, Some(107_374_182_400));

    let shared_cfg = srv.config("gd-sd").with_shared_drive_id("0ASharedDrive");
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("test-user", "tok"));
    let shared_backend = GdriveBackend::new(shared_cfg, transport, auth, None, None);
    assert!(shared_backend.about().await.unwrap().is_none());
}
