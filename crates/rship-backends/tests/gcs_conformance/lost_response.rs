//! `rewriteTo` with `ifGenerationMatch=0` is not idempotent: if the final step commits but
//! its response is lost, a replay gets `412 conditionNotMet`. The backend must reconcile via
//! the destination's `rship-op-id` metadata and succeed instead of surfacing a Conflict.

use crate::common::InjectedFault;
use crate::mock_server::{make_backend, spawn_mock_gcs};
use axum::http::StatusCode;
use rship_core::backend::{BackendPath, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use std::time::Duration;

fn copy_init(dst: &str, size: u64, op_id: &str) -> UploadInit {
    UploadInit {
        op_id: op_id.into(),
        dst_path: RelPath::parse(dst).unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: size,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: size,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    }
}

#[tokio::test]
async fn rewrite_lost_final_response_then_412_reconciles_via_op_id() {
    let (base_url, state) = spawn_mock_gcs().await;
    state
        .lock()
        .unwrap()
        .seed_object("src/a.bin", b"rewrite-me-please".to_vec());
    let backend = make_backend(&base_url);
    let faults = {
        let mut g = state.lock().unwrap();
        g.get_meta_fault_only_for = Some("dst/a.bin".to_string());
        g.faults.clone()
    };
    // Step 1 (token) proceeds; the final step commits and its response is lost (503). The
    // reconcile GET is lagging (404), so the final step is replayed and gets 412.
    faults.push(
        "RewriteObject",
        InjectedFault::slow_finalize(Duration::ZERO),
    );
    faults.push(
        "RewriteObject",
        InjectedFault::commit_then_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "application/json",
            r#"{"error":{"code":503,"message":"backendError"}}"#,
        ),
    );
    faults.push(
        "GetObjectMeta",
        InjectedFault::json_error(StatusCode::NOT_FOUND, r#"{"error":{"code":404}}"#),
    );

    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/a.bin").unwrap()),
            &copy_init("dst/a.bin", 17, "op-rewrite-lost"),
        )
        .await
        .expect("lost rewrite response + 412 replay must reconcile, not Conflict")
        .expect("rewritten entry");
    assert_eq!(copied.size, 17);
    let g = state.lock().unwrap();
    assert_eq!(g.objects["dst/a.bin"].data, b"rewrite-me-please".to_vec());
    assert_eq!(
        g.rewrite_calls, 3,
        "initial step, lost final step, 412 replay"
    );
}

#[tokio::test]
async fn rewrite_onto_someone_elses_object_still_conflicts() {
    let (base_url, state) = spawn_mock_gcs().await;
    {
        let mut g = state.lock().unwrap();
        g.seed_object("src/b.bin", b"source".to_vec());
        g.seed_object("dst/b.bin", b"theirs".to_vec());
    }
    let backend = make_backend(&base_url);
    let err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::from_rel(RelPath::parse("src/b.bin").unwrap()),
            &copy_init("dst/b.bin", 6, "op-rewrite-conflict"),
        )
        .await
        .expect_err("an existing object of another writer must not be adopted");
    assert!(
        matches!(
            err.kind,
            rship_core::ErrorKind::Conflict | rship_core::ErrorKind::PreconditionFailed
        ),
        "{err:?}"
    );
    assert_eq!(
        state.lock().unwrap().objects["dst/b.bin"].data,
        b"theirs".to_vec()
    );
}
