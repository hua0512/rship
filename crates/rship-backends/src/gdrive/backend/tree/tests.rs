use super::listing::{AncestorNode, BoundedDirTracker, MAX_SHORTCUT_RESOLVE_CONCURRENCY};
use super::*;
use crate::gdrive::auth::StaticBearerAuth;
use crate::gdrive::config::GdriveConfig;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures::StreamExt;
use rship_core::backend::StorageBackend;
use rship_core::state::DeltaNodeRecord;
use rship_transport::{HttpTransport, TransportConfig};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

fn test_backend(api_base_url: String) -> GdriveBackend {
    let mut cfg = GdriveConfig::new("gdrive-tree-test");
    cfg.api_base_url = api_base_url;
    cfg.write_qps = None;
    cfg.base_retry_delay = Duration::from_millis(5);
    cfg.max_retry_delay = Duration::from_millis(20);
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("test-user", "test-token"));
    GdriveBackend::new(cfg, transport, auth, None, None)
}

fn parse_parent_id(q: &str) -> String {
    let rest = q.strip_prefix('\'').unwrap_or(q);
    rest.split('\'').next().unwrap_or("").to_string()
}

struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn make_file_json(id: &str, name: &str, parent: &str, size: u64, md5: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "mimeType": "application/octet-stream",
        "size": size.to_string(),
        "modifiedTime": "2026-11-26T00:00:00.000Z",
        "md5Checksum": md5,
        "parents": [parent],
        "trashed": false,
    })
}

fn make_folder_json(id: &str, name: &str, parent: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "mimeType": FOLDER_MIME,
        "modifiedTime": "2026-11-26T00:00:00.000Z",
        "parents": [parent],
        "trashed": false,
    })
}

fn make_shortcut_json(
    id: &str,
    name: &str,
    parent: &str,
    target_id: &str,
    target_mime: &str,
) -> Value {
    json!({
        "id": id,
        "name": name,
        "mimeType": SHORTCUT_MIME,
        "modifiedTime": "2026-11-26T00:00:00.000Z",
        "parents": [parent],
        "trashed": false,
        "shortcutDetails": {
            "targetId": target_id,
            "targetMimeType": target_mime,
        }
    })
}

#[tokio::test]
async fn list_stream_streams_pages_incrementally_and_stops_on_early_drop() {
    struct PagedState {
        per_page: usize,
        total_pages: usize,
        pages_requested: AtomicUsize,
        requested_tokens: Mutex<Vec<Option<String>>>,
        page2_gate: Option<watch::Receiver<bool>>,
    }

    async fn handle_list(
        State(st): State<Arc<PagedState>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        let token = params.get("pageToken").cloned();
        let page_idx = match token.as_deref() {
            None => 1usize,
            Some(tok) => tok
                .strip_prefix('p')
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1),
        };
        st.pages_requested.fetch_add(1, Ordering::SeqCst);
        st.requested_tokens.lock().unwrap().push(token);

        if page_idx == 2
            && let Some(gate) = &st.page2_gate
        {
            let mut rx = gate.clone();
            let _ = rx.wait_for(|&open| open).await;
        }

        let files: Vec<Value> = (0..st.per_page)
            .map(|i| {
                let id = format!("p{page_idx}-id-{i:03}");
                let name = format!("p{page_idx}-file-{i:03}.bin");
                make_file_json(
                    &id,
                    &name,
                    "root",
                    10 + i as u64,
                    "d41d8cd98f00b204e9800998ecf8427e",
                )
            })
            .collect();
        let next_token = if page_idx < st.total_pages {
            Some(format!("p{}", page_idx + 1))
        } else {
            None
        };
        Json(json!({
            "files": files,
            "nextPageToken": next_token,
            "incompleteSearch": false,
        }))
        .into_response()
    }

    // Part A: 5 pages of 160 items (> channel capacity 128).
    // Consumer must receive page 1 entries BEFORE page 2 is even requested,
    // and dropping the stream stops fetching pages 2..5 completely!
    let state_a = Arc::new(PagedState {
        per_page: 160,
        total_pages: 5,
        pages_requested: AtomicUsize::new(0),
        requested_tokens: Mutex::new(Vec::new()),
        page2_gate: None,
    });
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let app_a = Router::new()
        .route("/drive/v3/files", get(handle_list))
        .with_state(Arc::clone(&state_a));
    tokio::spawn(async move {
        let _ = axum::serve(listener_a, app_a).await;
    });

    let backend_a = test_backend(format!("http://{addr_a}/drive/v3"));
    let mut stream_a = backend_a.list_stream(&RelPath::root(), true).await.unwrap();

    for i in 0..10 {
        let entry = tokio::time::timeout(Duration::from_secs(5), stream_a.next())
            .await
            .expect("timed out waiting for page 1 entry")
            .expect("stream ended unexpectedly")
            .expect("page 1 entry returned error");
        assert_eq!(entry.nfc_path.as_str(), format!("p1-file-{i:03}.bin"));
        assert_eq!(
            state_a.pages_requested.load(Ordering::SeqCst),
            1,
            "page 2 must not be requested before page 1 drains past channel backpressure"
        );
    }

    // Drop the stream after reading page 1 entries -> pages 2..5 must NEVER be requested.
    drop(stream_a);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        state_a.pages_requested.load(Ordering::SeqCst),
        1,
        "dropping stream after page 1 must stop fetching remaining pages"
    );
    assert_eq!(*state_a.requested_tokens.lock().unwrap(), vec![None]);

    // Part B: 5 pages of 10 items where page 2 blocks on a gate until the
    // consumer has received all of page 1 — deterministically proving page 1
    // streams as it arrives instead of collecting all pages first.
    let (gate_tx, gate_rx) = watch::channel(false);
    let state_b = Arc::new(PagedState {
        per_page: 10,
        total_pages: 5,
        pages_requested: AtomicUsize::new(0),
        requested_tokens: Mutex::new(Vec::new()),
        page2_gate: Some(gate_rx),
    });
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    let app_b = Router::new()
        .route("/drive/v3/files", get(handle_list))
        .with_state(Arc::clone(&state_b));
    tokio::spawn(async move {
        let _ = axum::serve(listener_b, app_b).await;
    });

    let backend_b = test_backend(format!("http://{addr_b}/drive/v3"));
    let mut stream_b = backend_b.list_stream(&RelPath::root(), true).await.unwrap();

    let mut received = Vec::new();
    for i in 0..10 {
        let entry = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
            .await
            .expect("page 1 must stream before page 2 responds")
            .expect("stream ended early")
            .expect("entry error");
        assert_eq!(entry.nfc_path.as_str(), format!("p1-file-{i:03}.bin"));
        received.push(entry.nfc_path.as_str().to_string());
    }

    // Release page 2 and verify all 5 pages stream cleanly to completion.
    gate_tx.send_replace(true);
    while let Some(item) = tokio::time::timeout(Duration::from_secs(5), stream_b.next())
        .await
        .expect("timed out draining pages 2..5")
    {
        received.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(received.len(), 50);
    assert_eq!(state_b.pages_requested.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn list_stream_resolves_file_shortcuts_concurrently_with_dedup_and_cache() {
    struct ShortcutState {
        in_flight: Arc<AtomicUsize>,
        max_in_flight: AtomicUsize,
        get_counts: Mutex<HashMap<String, usize>>,
    }

    async fn handle_list() -> Response {
        let mut files: Vec<Value> = (0..8)
            .map(|i| {
                make_shortcut_json(
                    &format!("sc-{i}"),
                    &format!("link-{i}.bin"),
                    "root",
                    &format!("target-{i}"),
                    "application/octet-stream",
                )
            })
            .collect();
        // Duplicate target sharing `target-0` -> must be deduplicated into 1 RPC.
        files.push(make_shortcut_json(
            "sc-dup",
            "link-dup.bin",
            "root",
            "target-0",
            "application/octet-stream",
        ));
        // Cached target present in local inventory -> must issue 0 remote RPCs.
        files.push(make_shortcut_json(
            "sc-cached",
            "link-cached.bin",
            "root",
            "target-cached",
            "application/octet-stream",
        ));
        Json(json!({
            "files": files,
            "incompleteSearch": false,
        }))
        .into_response()
    }

    async fn handle_get(State(st): State<Arc<ShortcutState>>, Path(id): Path<String>) -> Response {
        let active = st.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        let _guard = InFlightGuard(Arc::clone(&st.in_flight));
        st.max_in_flight.fetch_max(active, Ordering::SeqCst);
        *st.get_counts.lock().unwrap().entry(id.clone()).or_insert(0) += 1;

        tokio::time::sleep(Duration::from_millis(50)).await;

        if let Some(idx_s) = id.strip_prefix("target-")
            && let Ok(idx) = idx_s.parse::<u64>()
        {
            let md5 = format!("{idx:032x}");
            return Json(make_file_json(
                &id,
                &format!("real-{idx}.bin"),
                "external-parent",
                100 + idx,
                &md5,
            ))
            .into_response();
        }
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": 404 } })),
        )
            .into_response()
    }

    let state = Arc::new(ShortcutState {
        in_flight: Arc::new(AtomicUsize::new(0)),
        max_in_flight: AtomicUsize::new(0),
        get_counts: Mutex::new(HashMap::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/drive/v3/files", get(handle_list))
        .route("/drive/v3/files/{id}", get(handle_get))
        .with_state(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let backend = test_backend(format!("http://{addr}/drive/v3"));
    // Pre-populate `target-cached` in local inventory so `get_nodes_batch` resolves it.
    backend
        .inventory()
        .apply_change_batch(
            &backend.scope(),
            DeltaChangeBatch {
                upserts: vec![DeltaNodeRecord {
                    file_id: "target-cached".into(),
                    parent_id: Some("external-parent".into()),
                    raw_name: "cached-real.bin".into(),
                    nfc_name: "cached-real.bin".into(),
                    kind: EntryKind::File,
                    size: 777,
                    mtime_ns: 1_700_000_000_000_000_000,
                    md5: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
                    trashed: false,
                    generation: 1,
                    updated_at: 1_700_000_000,
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut stream = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut by_path: HashMap<String, Entry> = HashMap::new();
    while let Some(item) = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("shortcut listing timed out")
    {
        let entry = item.unwrap();
        by_path.insert(entry.nfc_path.as_str().to_string(), entry);
    }

    assert_eq!(by_path.len(), 10, "expected all 10 file shortcut entries");
    for i in 0..8 {
        let e = &by_path[&format!("link-{i}.bin")];
        assert_eq!(
            e.node_id.as_ref().map(|n| n.as_str()),
            Some(format!("sc-{i}").as_str())
        );
        assert_eq!(e.size, 100 + i as u64);
    }
    assert_eq!(by_path["link-dup.bin"].size, 100);
    assert_eq!(
        by_path["link-dup.bin"].node_id.as_ref().map(|n| n.as_str()),
        Some("sc-dup")
    );
    assert_eq!(
        by_path["link-cached.bin"]
            .node_id
            .as_ref()
            .map(|n| n.as_str()),
        Some("sc-cached")
    );
    assert_eq!(by_path["link-cached.bin"].size, 777);
    assert_eq!(
        by_path["link-cached.bin"]
            .checksum
            .as_ref()
            .map(|c| c.hex.as_str()),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    let max_in_flight = state.max_in_flight.load(Ordering::SeqCst);
    assert!(
        max_in_flight >= 2,
        "expected concurrent files.get shortcut resolution (max_in_flight={max_in_flight})"
    );
    assert!(
        max_in_flight <= MAX_SHORTCUT_RESOLVE_CONCURRENCY,
        "shortcut resolution concurrency exceeded bound ({max_in_flight} > {MAX_SHORTCUT_RESOLVE_CONCURRENCY})"
    );

    let counts = state.get_counts.lock().unwrap();
    assert_eq!(
        counts.get("target-0").copied(),
        Some(1),
        "duplicate shortcut target_id must be resolved with a single files.get RPC"
    );
    assert!(
        !counts.contains_key("target-cached"),
        "inventory-cached shortcut target must not trigger remote files.get"
    );
    let total_gets: usize = counts.values().sum();
    assert_eq!(
        total_gets, 8,
        "expected exactly 8 unique uncached files.get RPCs"
    );
}

#[tokio::test]
async fn list_stream_breaks_folder_shortcut_cycles_with_bounded_visited_tracker() {
    struct CycleState {
        children_by_parent: HashMap<String, Vec<Value>>,
        list_calls: AtomicUsize,
    }

    async fn handle_list(
        State(st): State<Arc<CycleState>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        st.list_calls.fetch_add(1, Ordering::SeqCst);
        let parent = parse_parent_id(params.get("q").map(String::as_str).unwrap_or(""));
        let files = st
            .children_by_parent
            .get(&parent)
            .cloned()
            .unwrap_or_default();
        Json(json!({
            "files": files,
            "incompleteSearch": false,
        }))
        .into_response()
    }

    let mut children: HashMap<String, Vec<Value>> = HashMap::new();
    children.insert(
        "root".into(),
        vec![
            make_folder_json("dirA", "dirA", "root"),
            make_shortcut_json("sc_ext1", "ext_entry", "root", "ext1", FOLDER_MIME),
            make_shortcut_json("sc_d1", "diamond_one", "root", "shared_dir", FOLDER_MIME),
            make_shortcut_json("sc_d2", "diamond_two", "root", "shared_dir", FOLDER_MIME),
        ],
    );
    children.insert(
        "dirA".into(),
        vec![make_folder_json("dirB", "dirB", "dirA")],
    );
    children.insert(
        "dirB".into(),
        vec![
            make_file_json(
                "leaf1",
                "leaf.txt",
                "dirB",
                12,
                "d41d8cd98f00b204e9800998ecf8427e",
            ),
            // Multi-hop cycle back to ancestor `dirA`, root cycle, and self-loop.
            make_shortcut_json("sc_anc", "back_to_dirA", "dirB", "dirA", FOLDER_MIME),
            make_shortcut_json("sc_root", "back_to_root", "dirB", "root", FOLDER_MIME),
            make_shortcut_json("sc_self", "back_to_self", "dirB", "dirB", FOLDER_MIME),
        ],
    );
    // External 2-hop shortcut cycle: ext1 -> ext2 -> ext1.
    children.insert(
        "ext1".into(),
        vec![make_shortcut_json(
            "sc_ext2",
            "hop_ext2",
            "ext1",
            "ext2",
            FOLDER_MIME,
        )],
    );
    children.insert(
        "ext2".into(),
        vec![
            make_file_json(
                "ext_file",
                "found.txt",
                "ext2",
                42,
                "d41d8cd98f00b204e9800998ecf8427e",
            ),
            make_shortcut_json("sc_back_ext1", "loop_ext1", "ext2", "ext1", FOLDER_MIME),
        ],
    );
    children.insert(
        "shared_dir".into(),
        vec![make_file_json(
            "shared_file",
            "once.txt",
            "shared_dir",
            7,
            "d41d8cd98f00b204e9800998ecf8427e",
        )],
    );

    let state = Arc::new(CycleState {
        children_by_parent: children,
        list_calls: AtomicUsize::new(0),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/drive/v3/files", get(handle_list))
        .with_state(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let backend = test_backend(format!("http://{addr}/drive/v3"));
    let mut stream = backend.list_stream(&RelPath::root(), true).await.unwrap();

    let mut paths = Vec::new();
    while let Some(item) = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("folder shortcut cycle did not terminate cleanly")
    {
        paths.push(item.unwrap().nfc_path.as_str().to_string());
    }
    paths.sort();

    assert_eq!(
        paths,
        vec![
            "diamond_one",
            "diamond_one/once.txt",
            "diamond_two",
            "diamond_two/once.txt",
            "dirA",
            "dirA/dirB",
            "dirA/dirB/leaf.txt",
            "ext_entry",
            "ext_entry/hop_ext2",
            "ext_entry/hop_ext2/found.txt",
        ]
    );
    assert!(
        state.list_calls.load(Ordering::SeqCst) <= 8,
        "cyclic shortcuts must not trigger repeated listings"
    );
}

#[test]
fn bounded_dir_tracker_preserves_exact_ancestor_cycle_checks_and_allows_diamonds() {
    let mut tracker = BoundedDirTracker::new(4);
    let mut ancestors = AncestorNode::root("root");

    for i in 0..50 {
        let dir_id = format!("dir-{i}");
        assert!(tracker.try_enter(&ancestors, &dir_id, Some("0AI_ACTUAL_ROOT")));
        ancestors = AncestorNode::push(&ancestors, dir_id.as_str());
    }

    // Exact ancestor tracking MUST reject cycles back to any ancestor (and `actual_root_id`).
    assert!(!tracker.try_enter(&ancestors, "root", Some("0AI_ACTUAL_ROOT")));
    assert!(!tracker.try_enter(&ancestors, "0AI_ACTUAL_ROOT", Some("0AI_ACTUAL_ROOT")));
    assert!(!tracker.try_enter(&ancestors, "dir-0", Some("0AI_ACTUAL_ROOT")));
    assert!(!tracker.try_enter(&ancestors, "dir-49", Some("0AI_ACTUAL_ROOT")));

    // Sibling / diamond non-ancestor branches MUST both be allowed to enter `shared_dir`.
    let branch_a = AncestorNode::push(&ancestors, "branch-a");
    let branch_b = AncestorNode::push(&ancestors, "branch-b");
    assert!(tracker.try_enter(&branch_a, "shared_dir", Some("0AI_ACTUAL_ROOT")));
    assert!(tracker.try_enter(&branch_b, "shared_dir", Some("0AI_ACTUAL_ROOT")));
}

#[tokio::test]
async fn list_stream_tolerates_broken_403_shortcuts_and_follows_chains_and_max_depth() {
    async fn handle_list(Query(params): Query<HashMap<String, String>>) -> Response {
        let parent = parse_parent_id(params.get("q").map(String::as_str).unwrap_or(""));
        let files = match parent.as_str() {
            "root" => vec![
                make_folder_json("real_dir", "real_dir", "root"),
                make_shortcut_json("sc_fast_dir", "fast_link", "root", "real_dir", FOLDER_MIME),
                make_shortcut_json(
                    "sc_broken_file",
                    "broken_403.bin",
                    "root",
                    "forbidden_target",
                    "application/octet-stream",
                ),
                make_shortcut_json(
                    "sc_broken_dir",
                    "broken_dir_link",
                    "root",
                    "forbidden_dir",
                    FOLDER_MIME,
                ),
                make_shortcut_json(
                    "sc_chain_1",
                    "chained_file.bin",
                    "root",
                    "sc_chain_2",
                    SHORTCUT_MIME,
                ),
                make_shortcut_json(
                    "sc_dir_chain_1",
                    "chained_dir",
                    "root",
                    "sc_dir_chain_2",
                    SHORTCUT_MIME,
                ),
            ],
            "real_dir" => vec![make_file_json(
                "real_child",
                "child.txt",
                "real_dir",
                99,
                "d41d8cd98f00b204e9800998ecf8427e",
            )],
            "chain_target_dir" => vec![make_file_json(
                "chain_leaf",
                "deep.txt",
                "chain_target_dir",
                11,
                "d41d8cd98f00b204e9800998ecf8427e",
            )],
            "forbidden_dir" => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": {
                            "code": 403,
                            "message": "Insufficient File Permissions",
                            "errors": [{ "reason": "insufficientFilePermissions" }]
                        }
                    })),
                )
                    .into_response();
            }
            _ => vec![],
        };
        Json(json!({ "files": files, "incompleteSearch": false })).into_response()
    }

    async fn handle_get(Path(id): Path<String>) -> Response {
        match id.as_str() {
            "forbidden_target" => (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "code": 403,
                        "message": "Insufficient File Permissions",
                        "errors": [{ "reason": "insufficientFilePermissions" }]
                    }
                })),
            )
                .into_response(),
            "sc_chain_2" => Json(make_shortcut_json(
                "sc_chain_2",
                "hop2",
                "ext",
                "chain_target_file",
                "application/octet-stream",
            ))
            .into_response(),
            "chain_target_file" => Json(make_file_json(
                "chain_target_file",
                "target.bin",
                "ext",
                55,
                "d41d8cd98f00b204e9800998ecf8427e",
            ))
            .into_response(),
            "sc_dir_chain_2" => Json(make_shortcut_json(
                "sc_dir_chain_2",
                "dir_hop2",
                "ext",
                "chain_target_dir",
                FOLDER_MIME,
            ))
            .into_response(),
            "chain_target_dir" => {
                Json(make_folder_json("chain_target_dir", "target_dir", "ext")).into_response()
            }
            _ => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": { "code": 404 } })),
            )
                .into_response(),
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/drive/v3/files", get(handle_list))
        .route("/drive/v3/files/{id}", get(handle_get));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let backend = test_backend(format!("http://{addr}/drive/v3"));

    // Recursive listing tolerates 403 broken file & folder shortcuts, resolves shortcut
    // chains, and emits both `real_dir/child.txt` AND `fast_link/child.txt`.
    let mut stream = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut entries = Vec::new();
    while let Some(item) = stream.next().await {
        entries.push(item.unwrap());
    }
    let mut paths: Vec<String> = entries
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "broken_dir_link",
            "chained_dir",
            "chained_dir/deep.txt",
            "chained_file.bin",
            "fast_link",
            "fast_link/child.txt",
            "real_dir",
            "real_dir/child.txt",
        ]
    );
    let chained_file = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "chained_file.bin")
        .unwrap();
    assert_eq!(chained_file.size, 55);
    assert_eq!(
        chained_file.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_chain_1")
    );

    // `with_max_depth(0)` MUST return empty stream (never overridden to depth 1).
    let d0: Vec<_> = backend
        .list_with_options(
            &RelPath::root(),
            &rship_core::backend::ListOptions::new().with_max_depth(0),
        )
        .await
        .unwrap()
        .collect()
        .await;
    assert!(d0.is_empty(), "with_max_depth(0) must emit 0 entries");

    // `with_max_depth(1)` returns top-level entries only without descending.
    let mut d1_paths: Vec<String> = backend
        .list_with_options(
            &RelPath::root(),
            &rship_core::backend::ListOptions::new().with_max_depth(1),
        )
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    d1_paths.sort();
    assert_eq!(
        d1_paths,
        vec![
            "broken_dir_link",
            "chained_dir",
            "chained_file.bin",
            "fast_link",
            "real_dir",
        ]
    );
}
