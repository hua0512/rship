//! Non-idempotent Graph commits (`POST /items/{id}/copy` and createFolder, both with
//! `conflictBehavior=fail`) whose response is lost after OneDrive committed. The replay gets
//! `409 nameAlreadyExists`; the backend must reconcile and succeed instead of falling back or
//! failing.

use crate::common::InjectedFault;
use crate::mock_server::{MockItem, start_mock_graph};
use axum::http::StatusCode;
use rship_backends::onedrive::{OnedriveBackend, OnedriveConfig};
use rship_core::backend::{BackendPath, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_core::types::NodeId;
use rship_transport::oauth::StaticBearerAuth;
use rship_transport::{HttpTransport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

fn backend(base_url: &str) -> Arc<OnedriveBackend> {
    let mut cfg = OnedriveConfig::new("od-lost")
        .with_max_retries(3)
        .with_retry_delays(Duration::from_millis(5), Duration::from_millis(20));
    cfg.api_base_url = format!("{base_url}/v1.0");
    cfg.token_url = format!("{base_url}/oauth2/v2.0/token");
    let auth = Arc::new(StaticBearerAuth::new("od-lost", "tok"));
    Arc::new(
        OnedriveBackend::new(
            cfg,
            auth,
            HttpTransport::new(TransportConfig::default()).unwrap(),
        )
        .unwrap(),
    )
}

fn noop() -> InjectedFault {
    InjectedFault::slow_finalize(Duration::ZERO)
}

fn lag() -> InjectedFault {
    InjectedFault::json_error(
        StatusCode::NOT_FOUND,
        r#"{"error":{"code":"itemNotFound","message":"lagging replica"}}"#,
    )
}

#[tokio::test]
async fn items_copy_lost_response_then_409_reconciles() {
    let (base_url, state) = start_mock_graph().await;
    state.lock().unwrap().items_by_path.insert(
        "src.bin".into(),
        MockItem {
            id: "src-id".into(),
            path: "src.bin".into(),
            is_folder: false,
            data: b"onedrive-copy-bytes".to_vec(),
            last_modified: "2026-11-24T12:00:00Z".into(),
        },
    );
    let od = backend(&base_url);
    let faults = state.lock().unwrap().fault_injector();
    faults.push("items.copy", InjectedFault::commit_then_reset());
    // GET root (parent chain), GET dst (pre-copy snapshot) proceed; the first reconcile
    // lookup lags so the copy is replayed and gets 409 nameAlreadyExists.
    faults.push_many("items.get", [noop(), noop(), lag()]);

    let src = BackendPath::new(
        "src.bin",
        RelPath::parse("src.bin").unwrap(),
        Some(NodeId("src-id".into())),
    );
    let init = UploadInit {
        op_id: "op-od-copy".into(),
        dst_path: RelPath::parse("dst.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 19,
        src_mtime_ns: 0,
        planned_chunk_size: 19,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let entry = od
        .server_side_copy(&od.endpoint_identity(), &src, &init)
        .await
        .expect("lost copy response + 409 replay must reconcile")
        .expect("a reconciled copy is a server-side copy, not a fallback");
    assert_eq!(entry.size, 19);
    assert_eq!(state.lock().unwrap().copy_calls, 2);
}

#[tokio::test]
async fn create_folder_lost_response_then_409_reconciles() {
    let (base_url, state) = start_mock_graph().await;
    let od = backend(&base_url);
    let faults = state.lock().unwrap().fault_injector();
    faults.push("items.mkdir", InjectedFault::commit_then_reset());
    // GET "newdir" (absent) proceeds; the first reconcile lookup lags.
    faults.push_many("items.get", [noop(), lag()]);

    od.mkdir(&RelPath::parse("newdir").unwrap())
        .await
        .expect("lost createFolder response + 409 replay must reconcile");
    assert_eq!(faults.op_requests("items.mkdir"), 2);
    assert!(state.lock().unwrap().items_by_path["newdir"].is_folder);
}
