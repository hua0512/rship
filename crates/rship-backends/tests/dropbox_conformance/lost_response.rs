//! Non-idempotent Dropbox commits (`copy_v2`, `move_v2`, `upload_session/finish`) whose
//! response is lost after Dropbox committed. The replay gets a 409 (`to/conflict`,
//! `from_lookup/not_found`, `lookup_failed/not_found`); the backend must reconcile and
//! succeed instead of surfacing the 409.
//!
//! In each test the first reconcile lookup is made to lag (`get_metadata` 409 not_found), so
//! the commit is replayed and the 409 path is exercised.

use crate::common::InjectedFault;
use crate::mock_server::{MockDropboxState, MockEntry, make_backend, spawn_mock_dropbox};
use axum::http::StatusCode;
use rship_core::backend::{BackendPath, CompletedPart, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use std::time::Duration;

fn lag_fault() -> InjectedFault {
    InjectedFault::json_error(
        StatusCode::CONFLICT,
        r#"{"error_summary": "path/not_found/..", "error": {".tag": "path", "path": {".tag": "not_found"}}}"#,
    )
}

fn seed_file(st: &std::sync::Mutex<MockDropboxState>, path: &str, data: &[u8]) {
    let mut g = st.lock().unwrap();
    let id = g.alloc_id("id:seed");
    g.ensure_parents(path);
    g.entries.insert(
        MockDropboxState::key(path),
        MockEntry {
            id,
            path: path.to_string(),
            is_folder: false,
            data: data.to_vec(),
            rev: "015seed".into(),
            client_modified: "2026-11-25T02:00:00Z".into(),
        },
    );
}

#[tokio::test]
async fn copy_v2_lost_response_then_to_conflict_reconciles_by_content_hash() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_file(&state, "/src/a.bin", b"dropbox-copy-payload");
    let dbx = make_backend(&base_url);
    let faults = state.lock().unwrap().fault_injector();
    faults.push("copy_v2", InjectedFault::commit_then_reset());
    faults.push("get_metadata", lag_fault());

    let init = UploadInit {
        op_id: "op-copy".into(),
        dst_path: RelPath::parse("dst/a.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 20,
        src_mtime_ns: 0,
        planned_chunk_size: 20,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry = dbx
        .server_side_copy(
            &dbx.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/a.bin").unwrap()),
            &init,
        )
        .await
        .expect("lost copy_v2 response + to/conflict replay must reconcile")
        .expect("copied entry");
    assert_eq!(entry.size, 20);
    assert_eq!(state.lock().unwrap().copy_calls, 2);
}

#[tokio::test]
async fn copy_v2_onto_a_different_existing_file_still_conflicts() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_file(&state, "/src/b.bin", b"source-bytes");
    seed_file(&state, "/dst/b.bin", b"other-bytes!");
    let dbx = make_backend(&base_url);
    let init = UploadInit {
        op_id: "op-copy-conflict".into(),
        dst_path: RelPath::parse("dst/b.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 12,
        src_mtime_ns: 0,
        planned_chunk_size: 12,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    dbx.server_side_copy(
        &dbx.endpoint_identity(),
        &BackendPath::from_rel(RelPath::parse("src/b.bin").unwrap()),
        &init,
    )
    .await
    .expect_err("a different file at the destination is a genuine conflict");
}

#[tokio::test]
async fn copy_v2_absent_precondition_onto_identical_existing_file_still_conflicts() {
    let (base_url, state) = spawn_mock_dropbox().await;
    let identical = b"identical-content-for-src-and-dst";
    seed_file(&state, "/src/same.bin", identical);
    seed_file(&state, "/dst/same.bin", identical);
    let dbx = make_backend(&base_url);
    let init = UploadInit {
        op_id: "op-copy-same-conflict".into(),
        dst_path: RelPath::parse("dst/same.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: identical.len() as u64,
        src_mtime_ns: 0,
        planned_chunk_size: identical.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err = dbx
        .server_side_copy(
            &dbx.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/same.bin").unwrap()),
            &init,
        )
        .await
        .expect_err("DstPrecondition::Absent must reject pre-existing identical dst");
    assert_eq!(err.kind, rship_core::ErrorKind::Conflict);
    assert_eq!(state.lock().unwrap().copy_calls, 1);
}

#[tokio::test]
async fn move_v2_lost_response_then_from_not_found_reconciles_by_file_id() {
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_file(&state, "/dir/old.txt", b"rename-me");
    let dbx = make_backend(&base_url);
    let faults = state.lock().unwrap().fault_injector();
    faults.push("move_v2", InjectedFault::commit_then_reset());
    // The pre-move lookup succeeds; the first reconcile lookup lags.
    faults.push("get_metadata", InjectedFault::slow_finalize(Duration::ZERO));
    faults.push("get_metadata", lag_fault());

    let entry = dbx
        .rename(
            &BackendPath::from_rel(RelPath::parse("dir/old.txt").unwrap()),
            "new.txt",
        )
        .await
        .expect("lost move_v2 response + from_lookup/not_found replay must reconcile");
    assert_eq!(entry.nfc_path.as_str(), "dir/new.txt");
    assert_eq!(state.lock().unwrap().move_calls, 2);
}

#[tokio::test]
async fn upload_session_finish_lost_response_then_lookup_failed_reconciles() {
    let (base_url, state) = spawn_mock_dropbox().await;
    let dbx = make_backend(&base_url);
    let payload = b"session-payload-bytes".to_vec();
    let rel = RelPath::parse("up/session.bin").unwrap();
    let init = UploadInit {
        op_id: "op-finish".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = dbx.begin_upload(&init).await.unwrap();
    // All bytes already appended (e.g. a resume found the session complete).
    state
        .lock()
        .unwrap()
        .sessions
        .get_mut(&sess.session_token)
        .unwrap()
        .data = payload.clone();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk-finish".into(),
        job_id: "job".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: dbx.endpoint_identity(),
        src_raw_path: rel.as_str().into(),
        dst_raw_path: rel.as_str().into(),
        dst_nfc_path: rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "dropbox".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: payload.len() as u64,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    let faults = state.lock().unwrap().fault_injector();
    faults.push("upload_session_finish", InjectedFault::commit_then_reset());
    faults.push("get_metadata", InjectedFault::slow_finalize(Duration::ZERO));
    faults.push("get_metadata", lag_fault());
    let parts: Vec<CompletedPart> = Vec::new();
    let entry = dbx
        .finish_upload(&op, &parts)
        .await
        .expect("lost finish response + lookup_failed replay must reconcile");
    assert_eq!(entry.size, payload.len() as u64);
    assert_eq!(
        faults.op_requests("upload_session_finish"),
        2,
        "the commit is replayed once, then reconciled"
    );
    let g = state.lock().unwrap();
    assert_eq!(
        g.entries[&MockDropboxState::key("/up/session.bin")].data,
        payload
    );
}

/// `reconcile_operation` must prove a file is this operation's result. An older file of the
/// same size (even with the source's `client_modified`) whose `rev` did not change must never
/// come back `Committed`; otherwise `move` could delete the only good source.
#[tokio::test]
async fn reconcile_never_accepts_an_older_same_size_file() {
    use rship_core::backend::ReconcileOutcome;
    let (base_url, state) = spawn_mock_dropbox().await;
    seed_file(&state, "/dst/old.bin", b"old-content-20bytes!");
    let dbx = make_backend(&base_url);
    let rel = RelPath::parse("dst/old.bin").unwrap();
    let old = dbx
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let mut op = OperationRecord {
        op_id: "op-reconcile".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: "dst".into(),
        src_raw_path: "old.bin".into(),
        dst_raw_path: "dst/old.bin".into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: old.size,
            mtime_ns: old.mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Existing {
            node_id: old.node_id.clone(),
            etag: old.etag.clone(),
            mtime_ns: old.mtime_ns,
            size: old.size,
        },
        existing_dst_node_id: old.node_id.clone(),
        remote_op_id: None,
        backend_kind: "dropbox".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: old.size,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let outcome = dbx.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "unchanged rev must not be accepted: {outcome:?}"
    );
    op.dst_precondition = DstPrecondition::Any;
    let outcome = dbx.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "{outcome:?}"
    );

    // A new revision with the source size and client_modified is ours.
    op.dst_precondition = DstPrecondition::Existing {
        node_id: old.node_id.clone(),
        etag: old.etag.clone(),
        mtime_ns: old.mtime_ns,
        size: old.size,
    };
    state
        .lock()
        .unwrap()
        .entries
        .get_mut(&MockDropboxState::key("/dst/old.bin"))
        .unwrap()
        .rev = "016new".into();
    let outcome = dbx.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn move_v2_nfd_parent_preserved_and_case_only_rename_reconcile_checks_leaf_casing() {
    let (base_url, state) = spawn_mock_dropbox().await;
    // Seed NFD parent `cafe\u{0301}` and case-only file `dir/old.txt`.
    seed_file(&state, "/cafe\u{0301}/old.txt", b"nfd-rename-bytes");
    seed_file(&state, "/dir/old.txt", b"case-rename-bytes");
    let dbx = make_backend(&base_url);

    // 1. Rename inside NFD parent must preserve raw NFD parent path in `move_v2`.
    let nfd_rel = RelPath::parse("café/old.txt").unwrap();
    let nfd_bp = BackendPath::new("cafe\u{0301}/old.txt", nfd_rel, None);
    let renamed_nfd = dbx.rename(&nfd_bp, "new.txt").await.unwrap();
    assert_eq!(renamed_nfd.nfc_path.as_str(), "café/new.txt");
    assert!(
        state
            .lock()
            .unwrap()
            .entries
            .contains_key(&MockDropboxState::key("/cafe\u{0301}/new.txt")),
        "move_v2 must preserve NFD parent directory bytes"
    );

    // 2. Case-only rename (`dir/old.txt` -> `dir/OLD.txt`) with PRE-commit reset:
    //    `get_meta("/dir/OLD.txt")` returns the still-lowercase `/dir/old.txt` with same `id`!
    //    Reconcile MUST NOT falsely treat it as moved; it must retry `move_v2` and actually commit!
    let faults = state.lock().unwrap().fault_injector();
    faults.push(
        "move_v2",
        InjectedFault::mid_body_reset(axum::body::Bytes::new()),
    );
    let case_bp = BackendPath::from_rel(RelPath::parse("dir/old.txt").unwrap());
    let renamed_case = dbx.rename(&case_bp, "OLD.txt").await.unwrap();
    assert_eq!(renamed_case.nfc_path.as_str(), "dir/OLD.txt");
    assert_eq!(
        state
            .lock()
            .unwrap()
            .entries
            .get(&MockDropboxState::key("/dir/OLD.txt"))
            .unwrap()
            .path,
        "/dir/OLD.txt",
        "pre-commit reset must retry move_v2 so server path becomes /dir/OLD.txt"
    );

    // 3. Case-only rename (`dir/OLD.txt` -> `dir/Old.txt`) with POST-commit reset:
    //    `move_v2` committed on server, response lost -> `from_lookup/not_found` -> reconciles!
    faults.push("move_v2", InjectedFault::commit_then_reset());
    let case_bp2 = BackendPath::from_rel(RelPath::parse("dir/OLD.txt").unwrap());
    let renamed_post = dbx.rename(&case_bp2, "Old.txt").await.unwrap();
    assert_eq!(renamed_post.nfc_path.as_str(), "dir/Old.txt");
}
