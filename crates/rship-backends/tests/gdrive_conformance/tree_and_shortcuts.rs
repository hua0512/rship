use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use rship_backends::gdrive::{FOLDER_MIME, GdriveBackend, SHORTCUT_MIME, StaticBearerAuth};
use rship_core::backend::{BackendPath, ListOptions, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::source::ByteStream;
use rship_core::state::{DeltaInventoryStore, DstPrecondition};
use rship_core::types::{EntryKind, HashKind, NodeId};
use rship_state::StateActor;
use rship_transport::{HttpTransport, TransportConfig};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::common::InjectedFault;

use crate::mock_server::{
    MockChangeItem, MockChangePage, MockFile, MockGdriveServer, read_gdrive_bytes,
};

// =========================================================================
// Test 2: SingleQuoteFolder & Backslash Escaping (`SingleQuoteFolder`)
// =========================================================================

#[tokio::test]
async fn gdrive_single_quote_and_backslash_folder_escaping() {
    let srv = MockGdriveServer::start().await;
    let backend = srv.backend("gd-quote");

    let dir = RelPath::parse("O'Reilly/Bob's_Folder").unwrap();
    backend.mkdir(&dir).await.unwrap();

    let file_path = RelPath::parse("O'Reilly/Bob's_Folder/it's_working.txt").unwrap();
    let payload = b"escaped single quotes work cleanly".to_vec();
    let init = UploadInit {
        op_id: "op-quote".into(),
        dst_path: file_path.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 4096,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let p_c = payload.clone();
    let body: ByteStream = Box::pin(futures::stream::once(async move { Ok(Bytes::from(p_c)) }));
    backend.put_single_shot(&init, body).await.unwrap();

    let st = backend
        .stat(&BackendPath::from_rel(file_path.clone()))
        .await
        .unwrap()
        .expect("file with single quotes must stat");
    assert_eq!(st.size, payload.len() as u64);
    assert_eq!(read_gdrive_bytes(&backend, &file_path).await, payload);

    // Verify queries actually sent escaped `\'` to Drive API.
    let g = srv.state.lock().unwrap();
    assert!(
        g.counters
            .list_queries
            .iter()
            .any(|q| q.contains(r"name = 'O\'Reilly'")),
        "expected escaped single-quote query in {:?}",
        g.counters.list_queries
    );
}

// =========================================================================
// Test 3: Shortcut Loop Detection + Workspace Docs + Trashed Filtering
// =========================================================================

#[tokio::test]
async fn gdrive_shortcut_loop_and_workspace_docs_and_trashed_filtering() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        // Folder `dirA` under `root`.
        g.files.insert(
            "dirA".into(),
            MockFile {
                id: "dirA".into(),
                name: "dirA".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        // Real binary file under `dirA`.
        g.files.insert(
            "real1".into(),
            MockFile {
                id: "real1".into(),
                name: "good.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["dirA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"hello".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        // Cyclic shortcut inside `dirA` pointing back to `root`!
        g.files.insert(
            "sc_root".into(),
            MockFile {
                id: "sc_root".into(),
                name: "loop_to_root".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["dirA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("root".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        // Self-loop shortcut inside `dirA` pointing to `dirA`!
        g.files.insert(
            "sc_self".into(),
            MockFile {
                id: "sc_self".into(),
                name: "loop_to_self".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["dirA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("dirA".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        // Export-only Google Doc -> must be skipped!
        g.files.insert(
            "gdoc1".into(),
            MockFile {
                id: "gdoc1".into(),
                name: "MyDoc".into(),
                mime_type: "application/vnd.google-apps.document".into(),
                parents: vec!["dirA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        // Trashed file -> must be filtered out!
        g.files.insert(
            "trashed1".into(),
            MockFile {
                id: "trashed1".into(),
                name: "deleted.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["dirA".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"trash".to_vec(),
                trashed: true,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-loop");
    let mut stream = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut paths = Vec::new();
    while let Some(item) = stream.next().await {
        paths.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(paths, vec!["dirA", "dirA/good.bin"]);
}

// =========================================================================
// Test 8: `changes.list` Move-In Crawl, Move-Out Evict, Removed Null, Gate
// =========================================================================

#[tokio::test]
async fn gdrive_changes_list_handles_move_in_move_out_removed_and_incomplete_search() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        // Initial tracked tree under `root`:
        //   root/keep.txt
        //   root/dir_out/nested.txt
        //   root/gone.txt
        //   root/trash_dir/inside.txt
        // External tree outside `root` (parent = "other_root"):
        //   other_root/ext_dir/sub/deep.bin
        //   other_root/ext_dir/top.txt
        for f in [
            MockFile {
                id: "keep".into(),
                name: "keep.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"k".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "dir_out".into(),
                name: "dir_out".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "nested_out".into(),
                name: "nested.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["dir_out".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"bye".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "gone".into(),
                name: "gone.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"g".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "trash_dir".into(),
                name: "trash_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "trash_child".into(),
                name: "inside.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["trash_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"t".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "ext_dir".into(),
                name: "ext_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "ext_sub".into(),
                name: "sub".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["ext_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
            MockFile {
                id: "ext_deep".into(),
                name: "deep.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["ext_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"deep-moved-in".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        ] {
            g.files.insert(f.id.clone(), f);
        }
        g.start_page_token = "tok-100".into();
    }

    let state_actor = Arc::new(StateActor::open_in_memory().unwrap());
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice", "tok"));
    let backend = GdriveBackend::new(
        srv.config("gd-chg"),
        transport,
        auth,
        Some(state_actor.clone()),
        None,
    );

    // 1. Bootstrap initial inventory into SQLite `gdrive_nodes` + `change_tokens`.
    let boot = backend.bootstrap_inventory().await.unwrap();
    assert!(boot.bootstrapped);
    assert!(!boot.incomplete_search);
    assert_eq!(boot.new_start_page_token.as_deref(), Some("tok-100"));
    assert_eq!(boot.upserted_nodes, 6);

    // 2. Apply mutations on Drive and emit `changes.list` at `tok-100` -> `tok-101`:
    //    - `ext_dir` moved IN to `root` (ONLY `ext_dir` is in changes, NOT its children!)
    //    - `dir_out` moved OUT to `other_root`
    //    - `gone` permanently removed (`removed: true, file: null`)
    //    - `trash_dir` trashed (`trashed: true`)
    {
        let mut g = srv.state.lock().unwrap();
        g.files.get_mut("ext_dir").unwrap().parents = vec!["root".into()];
        let ext_dir_snapshot = g.files["ext_dir"].clone();

        g.files.get_mut("dir_out").unwrap().parents = vec!["other_root".into()];
        let dir_out_snapshot = g.files["dir_out"].clone();

        g.files.remove("gone");
        g.files.get_mut("trash_dir").unwrap().trashed = true;
        let trash_dir_snapshot = g.files["trash_dir"].clone();

        g.changes_by_token.insert(
            "tok-100".into(),
            MockChangePage {
                items: vec![
                    MockChangeItem {
                        file_id: "ext_dir".into(),
                        removed: false,
                        file: Some(ext_dir_snapshot),
                    },
                    MockChangeItem {
                        file_id: "dir_out".into(),
                        removed: false,
                        file: Some(dir_out_snapshot),
                    },
                    MockChangeItem {
                        file_id: "gone".into(),
                        removed: true,
                        file: None,
                    },
                    MockChangeItem {
                        file_id: "trash_dir".into(),
                        removed: false,
                        file: Some(trash_dir_snapshot),
                    },
                ],
                next_page_token: None,
                new_start_page_token: Some("tok-101".into()),
            },
        );
    }

    let rep = backend.sync_changes().await.unwrap();
    assert!(!rep.bootstrapped);
    assert!(!rep.incomplete_search);
    assert_eq!(rep.new_start_page_token.as_deref(), Some("tok-101"));
    assert!(rep.crawled_moved_in_dirs >= 2); // ext_dir + ext_sub
    assert_eq!(rep.evicted_subtrees, 2); // dir_out + trash_dir

    let projected = backend
        .project_cached_entries(&RelPath::root(), true)
        .await
        .unwrap();
    let mut paths: Vec<String> = projected
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec!["ext_dir", "ext_dir/sub", "ext_dir/sub/deep.bin", "keep.txt"]
    );
    assert_eq!(
        state_actor
            .get_change_token(&backend.scope())
            .await
            .unwrap()
            .as_deref(),
        Some("tok-101")
    );

    // 3. Test `incompleteSearch: true` gate:
    //    - Must NOT advance `change_tokens` during `sync_changes`.
    //    - Must surface an error in `list_stream` so `TransferEngine` disables `sync --delete`.
    {
        let mut g = srv.state.lock().unwrap();
        let inc_dir = MockFile {
            id: "inc_dir".into(),
            name: "inc_dir".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("inc_dir".into(), inc_dir.clone());
        g.faults.incomplete_search_for_parent = Some("inc_dir".into());
        g.changes_by_token.insert(
            "tok-101".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "inc_dir".into(),
                    removed: false,
                    file: Some(inc_dir),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-102".into()),
            },
        );
    }

    let rep_inc = backend.sync_changes().await.unwrap();
    assert!(rep_inc.incomplete_search);
    assert!(rep_inc.new_start_page_token.is_none());
    // Token in SQLite MUST remain at `tok-101` (NOT `tok-102`)!
    assert_eq!(
        state_actor
            .get_change_token(&backend.scope())
            .await
            .unwrap()
            .as_deref(),
        Some("tok-101")
    );

    // `list_stream` must emit an error on `incompleteSearch: true`!
    let mut ls = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut saw_err = false;
    while let Some(item) = ls.next().await {
        if item.is_err() {
            saw_err = true;
            break;
        }
    }
    assert!(
        saw_err,
        "list_stream must surface incompleteSearch as error"
    );
}

// =========================================================================
// Test 11: Shared Drive Queries Set `corpora=drive` & `driveId` Everywhere
// =========================================================================

#[tokio::test]
async fn gdrive_shared_drive_sets_corpora_and_drive_id_params() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "sd_file".into(),
            MockFile {
                id: "sd_file".into(),
                name: "shared.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["0ASharedDrive42".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"team".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "sd-tok-1".into();
        g.changes_by_token.insert(
            "sd-tok-1".into(),
            MockChangePage {
                items: vec![],
                next_page_token: None,
                new_start_page_token: Some("sd-tok-2".into()),
            },
        );
    }

    let mut cfg = srv.config("gd-shared");
    cfg.shared_drive_id = Some("0ASharedDrive42".into());
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new(
        "bot@proj.iam.gserviceaccount.com",
        "tok",
    ));
    let backend = GdriveBackend::new(cfg, transport, auth, None, None);

    let boot = backend.bootstrap_inventory().await.unwrap();
    assert_eq!(boot.upserted_nodes, 1);
    let sync = backend.sync_changes().await.unwrap();
    assert_eq!(sync.new_start_page_token.as_deref(), Some("sd-tok-2"));

    let g = srv.state.lock().unwrap();
    assert!(g.counters.list_params.iter().all(|p| {
        p.get("corpora").map(String::as_str) == Some("drive")
            && p.get("driveId").map(String::as_str) == Some("0ASharedDrive42")
            && p.get("supportsAllDrives").map(String::as_str) == Some("true")
            && p.get("includeItemsFromAllDrives").map(String::as_str) == Some("true")
    }));
    assert!(g.counters.change_params.iter().all(|p| {
        p.get("driveId").map(String::as_str) == Some("0ASharedDrive42")
            && p.get("supportsAllDrives").map(String::as_str) == Some("true")
            && p.get("includeItemsFromAllDrives").map(String::as_str) == Some("true")
    }));
}

// ---------------------------------------------------------------------------
// Test 12: `list_stream` with `use_changes_feed = true` uses delta `changes.list`
//          instead of re-crawling Drive folders, and respects `incompleteSearch`
// ---------------------------------------------------------------------------
#[tokio::test]
async fn gdrive_list_stream_with_changes_feed_uses_delta_not_full_recrawl() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "d_docs".into(),
            MockFile {
                id: "d_docs".into(),
                name: "docs".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "f_init".into(),
            MockFile {
                id: "f_init".into(),
                name: "readme.md".into(),
                mime_type: "text/markdown".into(),
                parents: vec!["d_docs".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"hello".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "feed-1".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-feed");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("user@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    // 1. Cold `list_stream` bootstraps the inventory via `files.list` and saves `startPageToken`.
    let first: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(first.len(), 2);
    let list_calls_after_boot = srv.state.lock().unwrap().counters.list_params.len();
    assert!(
        list_calls_after_boot >= 2,
        "expected bootstrap folder crawl"
    );

    // 2. Remote change adds `docs/notes.txt` via `changes.list` delta (feed-1 -> feed-2).
    {
        let mut g = srv.state.lock().unwrap();
        let added = MockFile {
            id: "f_notes".into(),
            name: "notes.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["d_docs".into()],
            modified_time: "2026-11-24T01:00:00.000Z".into(),
            data: b"delta-content".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("f_notes".into(), added.clone());
        g.changes_by_token.insert(
            "feed-1".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "f_notes".into(),
                    removed: false,
                    file: Some(added),
                }],
                next_page_token: None,
                new_start_page_token: Some("feed-2".into()),
            },
        );
    }

    // Warm `list_stream` MUST issue ZERO additional `files.list` calls, using only `changes.list`!
    let second: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let list_calls_after_delta = srv.state.lock().unwrap().counters.list_params.len();
    assert_eq!(
        list_calls_after_delta, list_calls_after_boot,
        "warm incremental list_stream must not re-crawl files.list"
    );
    let mut paths: Vec<String> = second
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    paths.sort();
    assert_eq!(paths, vec!["docs", "docs/notes.txt", "docs/readme.md"]);

    // Single-file prefix projection also works directly from cached inventory!
    {
        let mut g = srv.state.lock().unwrap();
        g.changes_by_token.insert(
            "feed-2".into(),
            MockChangePage {
                items: vec![],
                next_page_token: None,
                new_start_page_token: Some("feed-2".into()),
            },
        );
    }
    let single: Vec<_> = backend
        .list_stream(&RelPath::parse("docs/notes.txt").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].nfc_path.as_str(), "docs/notes.txt");
    assert_eq!(single[0].size, 13);
}

// =========================================================================
// P0-1 & P0-4: Shortcut ID vs Target ID Isolation + Folder-Shortcut Traversal
// =========================================================================

#[tokio::test]
async fn gdrive_p0_shortcut_isolation_and_folder_shortcut_traversal() {
    let srv = MockGdriveServer::start().await;
    let target_bytes = b"external-target-must-remain-intact!".to_vec();
    let nested_bytes = b"nested-through-folder-shortcut".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        // External files outside `root` (in `other_root`).
        g.files.insert(
            "ext_file".into(),
            MockFile {
                id: "ext_file".into(),
                name: "real.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: target_bytes.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_dir".into(),
            MockFile {
                id: "ext_dir".into(),
                name: "real_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_sub".into(),
            MockFile {
                id: "ext_sub".into(),
                name: "sub".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["ext_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_nested".into(),
            MockFile {
                id: "ext_nested".into(),
                name: "nested.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["ext_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: nested_bytes.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );

        // Shortcuts inside `root`.
        g.files.insert(
            "sc_file".into(),
            MockFile {
                id: "sc_file".into(),
                name: "link.txt".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("ext_file".into(), "text/plain".into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_dir".into(),
            MockFile {
                id: "sc_dir".into(),
                name: "link_dir".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("ext_dir".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-sc-iso");

    // 1. `stat` & `list_stream` report shortcut's OWN `node_id` (`sc_file` / `sc_dir`),
    //    while exposing target size & content!
    let listed: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
        .await;
    let sc_file_entry = listed
        .iter()
        .find(|e| e.nfc_path.as_str() == "link.txt")
        .unwrap();
    assert_eq!(
        sc_file_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_file")
    );
    assert_eq!(sc_file_entry.size, target_bytes.len() as u64);

    let sc_dir_entry = listed
        .iter()
        .find(|e| e.nfc_path.as_str() == "link_dir")
        .unwrap();
    assert_eq!(
        sc_dir_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_dir")
    );
    assert_eq!(sc_dir_entry.kind, EntryKind::Directory);

    // `stat(node_id)` on `sc_file` resolves target metadata while keeping `node_id == sc_file`.
    let st_by_id = backend
        .stat(&BackendPath::new(
            "link.txt",
            RelPath::parse("link.txt").unwrap(),
            Some(NodeId("sc_file".into())),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        st_by_id.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_file")
    );
    assert_eq!(st_by_id.size, target_bytes.len() as u64);

    // 2. Reading via `open_read_entry` and cold `GdriveRangeReader` with `sc_file` node_id
    //    reads `ext_file` bytes cleanly!
    let cold_backend = srv.backend("gd-sc-cold");
    let ds = cold_backend
        .open_read_entry(
            &st_by_id,
            &BackendPath::new(
                "link.txt",
                RelPath::parse("link.txt").unwrap(),
                Some(NodeId("sc_file".into())),
            ),
            None,
        )
        .await
        .unwrap();
    if let rship_core::source::DataSource::RemoteRangeReadable(r) = ds {
        let mut s = r
            .open_range(rship_core::types::ByteRange {
                offset: 0,
                len: r.total_len(),
            })
            .await
            .unwrap();
        let mut got = Vec::new();
        while let Some(c) = s.next().await {
            got.extend_from_slice(&c.unwrap());
        }
        assert_eq!(got, target_bytes);
    } else {
        panic!("expected RemoteRangeReadable");
    }

    // 3. P0-4: `resolve_rel_path` / `stat` / `open_read` / `compute_hash` through folder shortcut!
    let nested_rel = RelPath::parse("link_dir/sub/nested.txt").unwrap();
    let nested_st = backend
        .stat(&BackendPath::from_rel(nested_rel.clone()))
        .await
        .unwrap()
        .expect("path through folder shortcut must resolve");
    assert_eq!(nested_st.size, nested_bytes.len() as u64);
    assert_eq!(read_gdrive_bytes(&backend, &nested_rel).await, nested_bytes);
    assert!(
        backend
            .compute_hash(&BackendPath::from_rel(nested_rel), HashKind::Sha256)
            .await
            .unwrap()
            .is_some()
    );

    // 4. `server_side_copy` on shortcut `NodeId("sc_file")` copies `ext_file` target bytes!
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::new(
                "link.txt",
                RelPath::parse("link.txt").unwrap(),
                Some(NodeId("sc_file".into())),
            ),
            &UploadInit {
                op_id: "op-copy-sc".into(),
                dst_path: RelPath::parse("copied_from_shortcut.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: target_bytes.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: target_bytes.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("server_side_copy from shortcut must copy target");
    assert_eq!(copied.size, target_bytes.len() as u64);

    // 5. `rename` on file & folder shortcut renames ONLY the shortcut; external targets untouched!
    let renamed_file_sc = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("link.txt").unwrap()),
            "link_renamed.txt",
        )
        .await
        .unwrap();
    assert_eq!(
        renamed_file_sc.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_file")
    );
    assert_eq!(renamed_file_sc.kind, EntryKind::File);

    let renamed_dir_sc = backend
        .rename(
            &BackendPath::from_rel(RelPath::parse("link_dir").unwrap()),
            "link_dir_renamed",
        )
        .await
        .unwrap();
    assert_eq!(
        renamed_dir_sc.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_dir")
    );
    assert_eq!(renamed_dir_sc.kind, EntryKind::Directory);
    {
        let g = srv.state.lock().unwrap();
        assert_eq!(g.files["sc_file"].name, "link_renamed.txt");
        assert_eq!(g.files["ext_file"].name, "real.txt");
        assert_eq!(g.files["sc_dir"].name, "link_dir_renamed");
        assert_eq!(g.files["ext_dir"].name, "real_dir");
    }

    // 6. Overwriting a shortcut (`existing_node_id = Some("sc_file")`) replaces
    //    ONLY the shortcut with a new regular file; `ext_file` remains 100% intact!
    //    (See `gdrive_overwrite_shortcut_with_existing_node_id_none` for `existing_node_id = None`.)
    let replacement = b"regular-file-replacing-shortcut".to_vec();
    let rep_c = replacement.clone();
    let ow_entry = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-replace-sc".into(),
                dst_path: RelPath::parse("link_renamed.txt").unwrap(),
                existing_node_id: Some(NodeId("sc_file".into())),
                pregenerated_id: None,
                total_size: replacement.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: replacement.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(rep_c)) })),
        )
        .await
        .unwrap();
    assert_ne!(
        ow_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_file")
    );
    assert_ne!(
        ow_entry.node_id.as_ref().map(|n| n.as_str()),
        Some("ext_file")
    );
    assert_eq!(
        srv.state.lock().unwrap().files["ext_file"].data,
        target_bytes
    );

    // 7. `delete` on folder shortcut deletes ONLY the shortcut; `ext_dir` & `ext_nested` intact!
    backend
        .delete(&BackendPath::from_rel(
            RelPath::parse("link_dir_renamed").unwrap(),
        ))
        .await
        .unwrap();
    {
        let g = srv.state.lock().unwrap();
        assert!(g.files["sc_dir"].trashed);
        assert!(!g.files["ext_dir"].trashed);
        assert!(!g.files["ext_nested"].trashed);
    }
}

// =========================================================================
// P0-2, P0-3, P0-5, P0-7: Changes Feed Atomic Gate, 410/400 Reset,
//                         `restrictToMyDrive` + 403 Parent, and Shortcuts
// =========================================================================

#[tokio::test]
async fn gdrive_p0_changes_feed_atomic_gate_410_400_reset_403_parent_and_shortcuts() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "init_f".into(),
            MockFile {
                id: "init_f".into(),
                name: "init.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"init".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-p0-feed");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    // Cold bootstrap.
    let boot = backend.bootstrap_inventory().await.unwrap();
    assert_eq!(boot.new_start_page_token.as_deref(), Some("tok-0"));

    // Prepare a moved-in directory `big_moved_in` with 2050 files (> INVENTORY_FLUSH_BATCH = 2000!)
    // AND a sibling `inc_sub` that triggers `incompleteSearch=true` during crawl!
    // Also call `ensure_dir_chain("big_moved_in")` beforehand to verify no premature `cache_node`!
    {
        let mut g = srv.state.lock().unwrap();
        let big_dir = MockFile {
            id: "big_moved_in".into(),
            name: "big_moved_in".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("big_moved_in".into(), big_dir.clone());
        for i in 0..2050 {
            let fid = format!("big_child_{i:04}");
            g.files.insert(
                fid.clone(),
                MockFile {
                    id: fid,
                    name: format!("f_{i:04}.bin"),
                    mime_type: "application/octet-stream".into(),
                    parents: vec!["big_moved_in".into()],
                    modified_time: "2026-11-24T00:00:00.000Z".into(),
                    data: vec![1, 2, 3],
                    trashed: false,
                    shortcut_target: None,
                    app_properties: HashMap::new(),
                },
            );
        }
        let inc_sub = MockFile {
            id: "inc_sub".into(),
            name: "inc_sub".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["big_moved_in".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("inc_sub".into(), inc_sub);
        g.files.insert(
            "inc_leaf".into(),
            MockFile {
                id: "inc_leaf".into(),
                name: "leaf.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["inc_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"leaf".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.faults.incomplete_search_for_parent = Some("inc_sub".into());

        // Also include an unrelated change whose parent returns HTTP 403!
        g.faults.forbidden_file_ids.insert("403_parent".into());
        let unrelated_403_child = MockFile {
            id: "unrelated_403".into(),
            name: "secret.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["403_parent".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: b"secret".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.changes_by_token.insert(
            "tok-0".into(),
            MockChangePage {
                items: vec![
                    MockChangeItem {
                        file_id: "big_moved_in".into(),
                        removed: false,
                        file: Some(big_dir),
                    },
                    MockChangeItem {
                        file_id: "unrelated_403".into(),
                        removed: false,
                        file: Some(unrelated_403_child),
                    },
                ],
                next_page_token: None,
                new_start_page_token: Some("tok-1".into()),
            },
        );
    }

    // Calling `mkdir` (which runs `ensure_dir_chain`) on existing `big_moved_in` before
    // `sync_changes` MUST NOT prematurely persist `big_moved_in` into `gdrive_nodes`!
    backend
        .mkdir(&RelPath::parse("big_moved_in").unwrap())
        .await
        .unwrap();
    assert!(
        actor
            .get_node("gd-p0-feed", "root", "big_moved_in")
            .await
            .unwrap()
            .is_none(),
        "ensure_dir_chain must not prematurely cache directories into gdrive_nodes"
    );

    // Run 1: `incompleteSearch=true` -> MUST NOT flush `big_moved_in` mid-crawl or advance token!
    let rep_inc = backend.sync_changes().await.unwrap();
    assert!(rep_inc.incomplete_search);
    assert_eq!(
        actor
            .get_change_token(&backend.scope())
            .await
            .unwrap()
            .as_deref(),
        Some("tok-0")
    );
    assert!(
        actor
            .get_node("gd-p0-feed", "root", "big_moved_in")
            .await
            .unwrap()
            .is_none(),
        "incomplete sync_changes must NOT flush moved-in dir into gdrive_nodes"
    );

    // Verify My Drive `changes.list` sent `restrictToMyDrive=true` and omitted `includeItemsFromAllDrives`.
    {
        let g = srv.state.lock().unwrap();
        let last_chg = g.counters.change_params.last().unwrap();
        assert_eq!(
            last_chg.get("restrictToMyDrive").map(String::as_str),
            Some("true")
        );
        assert!(!last_chg.contains_key("includeItemsFromAllDrives"));
    }

    // Clear `incompleteSearch` and retry `sync_changes` -> MUST crawl all 2050+ children and
    // tolerate the 403 unrelated parent without failing!
    srv.state
        .lock()
        .unwrap()
        .faults
        .incomplete_search_for_parent = None;
    let rep_ok = backend.sync_changes().await.unwrap();
    assert!(!rep_ok.incomplete_search);
    assert_eq!(rep_ok.new_start_page_token.as_deref(), Some("tok-1"));
    let projected = backend
        .project_cached_entries(&RelPath::root(), true)
        .await
        .unwrap();
    assert_eq!(projected.len(), 2054); // init.txt + big_moved_in + 2050 children + inc_sub + inc_leaf

    // P0-7: Add file & folder shortcuts in `changes.list` delta (tok-1 -> tok-2), verify
    // `use_changes_feed = true` `list_stream`, `project_cached_entries`, `with_max_depth(0)`,
    // and safe folder-shortcut removal (does not evict target!).
    {
        let mut g = srv.state.lock().unwrap();
        let real_folder = MockFile {
            id: "real_target_dir".into(),
            name: "real_target_dir".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let real_inside = MockFile {
            id: "real_inside".into(),
            name: "inside.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["real_target_dir".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: b"target-dir-file".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let sc_f = MockFile {
            id: "sc_feed_file".into(),
            name: "sc_init.txt".into(),
            mime_type: SHORTCUT_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: Some(("init_f".into(), "text/plain".into())),
            app_properties: HashMap::new(),
        };
        let sc_d = MockFile {
            id: "sc_feed_dir".into(),
            name: "sc_dir".into(),
            mime_type: SHORTCUT_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: Some(("real_target_dir".into(), FOLDER_MIME.into())),
            app_properties: HashMap::new(),
        };
        g.files
            .insert("real_target_dir".into(), real_folder.clone());
        g.files.insert("real_inside".into(), real_inside.clone());
        g.files.insert("sc_feed_file".into(), sc_f.clone());
        g.files.insert("sc_feed_dir".into(), sc_d.clone());
        g.changes_by_token.insert(
            "tok-1".into(),
            MockChangePage {
                items: vec![
                    MockChangeItem {
                        file_id: "real_target_dir".into(),
                        removed: false,
                        file: Some(real_folder),
                    },
                    MockChangeItem {
                        file_id: "real_inside".into(),
                        removed: false,
                        file: Some(real_inside),
                    },
                    MockChangeItem {
                        file_id: "sc_feed_file".into(),
                        removed: false,
                        file: Some(sc_f),
                    },
                    MockChangeItem {
                        file_id: "sc_feed_dir".into(),
                        removed: false,
                        file: Some(sc_d),
                    },
                ],
                next_page_token: None,
                new_start_page_token: Some("tok-2".into()),
            },
        );
        g.changes_by_token.insert(
            "tok-2".into(),
            MockChangePage {
                items: vec![],
                next_page_token: None,
                new_start_page_token: Some("tok-2".into()),
            },
        );
    }

    let entries: Vec<_> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
        .await;
    let sc_file_e = entries
        .iter()
        .find(|e| e.nfc_path.as_str() == "sc_init.txt")
        .expect("file shortcut must be visible in use_changes_feed=true");
    assert_eq!(
        sc_file_e.node_id.as_ref().map(|n| n.as_str()),
        Some("sc_feed_file")
    );
    assert_eq!(sc_file_e.size, 4);
    assert!(
        entries
            .iter()
            .any(|e| e.nfc_path.as_str() == "sc_dir/inside.txt"),
        "folder shortcut subtree must be visible in use_changes_feed=true"
    );

    // P1: `with_max_depth(0)` in `use_changes_feed=true` emits 0 entries!
    let d0: Vec<_> = backend
        .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
        .await
        .unwrap()
        .collect()
        .await;
    assert!(d0.is_empty());

    // Remove folder shortcut `sc_feed_dir` in tok-2 -> target `real_target_dir` must stay!
    {
        let mut g = srv.state.lock().unwrap();
        g.files.remove("sc_feed_dir");
        g.changes_by_token.insert(
            "tok-2".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "sc_feed_dir".into(),
                    removed: true,
                    file: None,
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-3".into()),
            },
        );
        g.changes_by_token.insert(
            "tok-3".into(),
            MockChangePage {
                items: vec![],
                next_page_token: None,
                new_start_page_token: Some("tok-3".into()),
            },
        );
    }
    backend.sync_changes().await.unwrap();
    let after_sc_del = backend
        .project_cached_entries(&RelPath::root(), true)
        .await
        .unwrap();
    assert!(
        after_sc_del
            .iter()
            .any(|e| e.nfc_path.as_str() == "real_target_dir/inside.txt"),
        "deleting folder shortcut must NOT evict target directory from inventory"
    );

    // P0-3: HTTP 410 Gone AND HTTP 400 Bad Request on `changes.list` auto-reset & re-bootstrap!
    let faults = srv.fault_injector();
    srv.state.lock().unwrap().start_page_token = "tok-reboot-1".into();
    faults.push(
        "changes.list",
        InjectedFault::json_error(
            StatusCode::GONE,
            json!({ "error": { "code": 410, "message": "Token expired" } }).to_string(),
        ),
    );
    let rep_410 = backend.sync_changes().await.unwrap();
    assert!(rep_410.bootstrapped);
    assert_eq!(
        rep_410.new_start_page_token.as_deref(),
        Some("tok-reboot-1")
    );

    srv.state.lock().unwrap().start_page_token = "tok-reboot-2".into();
    faults.push(
        "changes.list",
        InjectedFault::json_error(
            StatusCode::BAD_REQUEST,
            json!({ "error": { "code": 400, "message": "Invalid pageToken" } }).to_string(),
        ),
    );
    let rep_400 = backend.sync_changes().await.unwrap();
    assert!(rep_400.bootstrapped);
    assert_eq!(
        rep_400.new_start_page_token.as_deref(),
        Some("tok-reboot-2")
    );
}

// =========================================================================
// P1: `drive.appfolder` (`spaces=appDataFolder`) & Non-Changes-Feed Eviction
// =========================================================================

#[tokio::test]
async fn gdrive_app_data_folder_params_and_non_changes_feed_cache_eviction() {
    let srv = MockGdriveServer::start().await;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));

    // 1. `drive.appfolder` scope wires `spaces=appDataFolder` & `space=appDataFolder`!
    let app_cfg = srv.config("gd-app").with_scope("drive.appfolder");
    assert!(app_cfg.is_app_data_folder());
    let app_backend = GdriveBackend::new(app_cfg, transport.clone(), auth.clone(), None, None);

    app_backend
        .mkdir(&RelPath::parse("app_cfg").unwrap())
        .await
        .unwrap();
    let _ = app_backend
        .list_stream(&RelPath::root(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    {
        let g = srv.state.lock().unwrap();
        assert!(
            g.counters
                .list_params
                .iter()
                .all(|p| p.get("spaces").map(String::as_str) == Some("appDataFolder")),
            "appDataFolder must pass spaces=appDataFolder on files.list"
        );
    }

    // 2. Non-changes-feed cache eviction on delete & stale ancestor recovery!
    let srv2 = MockGdriveServer::start().await;
    let backend2 = srv2.backend("gd-no-feed-evict");
    let data = b"hello".to_vec();
    backend2
        .put_single_shot(
            &UploadInit {
                op_id: "op-ev-1".into(),
                dst_path: RelPath::parse("parent_d/sub_d/file.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: data.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: data.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(data)) })),
        )
        .await
        .unwrap();

    // Simulate external deletion of `parent_d` subtree on Drive (removing `parent_d` and
    // its descendants from the remote state). Next `stat("parent_d/sub_d/file.txt")` must
    // evict stale `dir_id_cache` entries and return `None`, and re-creating the path
    // must create fresh folders instead of reusing deleted folder IDs!
    let parent_entry = backend2
        .stat(&BackendPath::from_rel(RelPath::parse("parent_d").unwrap()))
        .await
        .unwrap()
        .unwrap();
    let old_parent_id = parent_entry.node_id.unwrap().0;
    {
        let mut g = srv2.state.lock().unwrap();
        let sub_ids: Vec<String> = g
            .files
            .values()
            .filter(|f| f.parents.contains(&old_parent_id))
            .map(|f| f.id.clone())
            .collect();
        g.files.retain(|_, f| {
            f.id != old_parent_id
                && !sub_ids.contains(&f.id)
                && !f.parents.iter().any(|p| sub_ids.contains(p))
        });
    }

    assert!(
        backend2
            .stat(&BackendPath::from_rel(
                RelPath::parse("parent_d/sub_d/file.txt").unwrap()
            ))
            .await
            .unwrap()
            .is_none(),
        "stale cached ancestor must self-heal to None when remote parent is deleted"
    );

    let data2 = b"recreated".to_vec();
    let d2_c = data2.clone();
    let recreated = backend2
        .put_single_shot(
            &UploadInit {
                op_id: "op-ev-2".into(),
                dst_path: RelPath::parse("parent_d/sub_d/file.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: data2.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: data2.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(d2_c)) })),
        )
        .await
        .unwrap();
    assert_eq!(recreated.size, data2.len() as u64);
    assert_eq!(
        read_gdrive_bytes(
            &backend2,
            &RelPath::parse("parent_d/sub_d/file.txt").unwrap()
        )
        .await,
        data2
    );
}

// =========================================================================
// Iteration 2 Regression 1: External folder shortcut `max_depth(1)` in
// `use_changes_feed = true` must NOT cache external dirs into `gdrive_nodes`
// =========================================================================

#[tokio::test]
async fn gdrive_external_shortcut_max_depth_1_does_not_cache_dir_before_move_in() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "ext_root".into(),
            MockFile {
                id: "ext_root".into(),
                name: "ext_root".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_sub".into(),
            MockFile {
                id: "ext_sub".into(),
                name: "ext_sub".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["ext_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_hidden".into(),
            MockFile {
                id: "ext_hidden".into(),
                name: "hidden.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["ext_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"must-not-be-lost".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "ext_link".into(),
            MockFile {
                id: "ext_link".into(),
                name: "ext_link".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("ext_root".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-ext-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-ext-depth1");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    // 1. List `ext_link` at `with_max_depth(1)` under `use_changes_feed = true`.
    let d1: Vec<String> = backend
        .list_with_options(
            &RelPath::parse("ext_link").unwrap(),
            &ListOptions::new().with_max_depth(1),
        )
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert_eq!(d1, vec!["ext_link/ext_sub"]);

    // `ext_sub` is external and must NOT be cached into `gdrive_nodes`!
    assert!(
        actor
            .get_node("gd-ext-depth1", "root", "ext_sub")
            .await
            .unwrap()
            .is_none(),
        "external shortcut dir must not be cached into gdrive_nodes under use_changes_feed=true"
    );

    // 2. Move `ext_sub` into `root` via `changes.list`, run `sync_changes`, and verify
    //    `ext_sub/hidden.txt` is crawled and present!
    {
        let mut g = srv.state.lock().unwrap();
        let mut moved = g.files.get("ext_sub").unwrap().clone();
        moved.parents = vec!["root".into()];
        g.files.insert("ext_sub".into(), moved.clone());
        g.changes_by_token.insert(
            "tok-ext-0".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "ext_sub".into(),
                    removed: false,
                    file: Some(moved),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-ext-1".into()),
            },
        );
    }
    backend.sync_changes().await.unwrap();

    let mut listed: Vec<String> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    listed.sort();
    assert!(
        listed.contains(&"ext_sub/hidden.txt".to_string()),
        "moved-in ext_sub must be crawled with hidden.txt present, got: {listed:?}"
    );
}

// =========================================================================
// Iteration 2 Regression 2: 8 concurrent `open_range` calls on a cold
// `GdriveRangeReader` holding a shortcut `node_id`
// =========================================================================

#[tokio::test]
async fn gdrive_concurrent_cold_open_range_on_file_shortcut_succeeds() {
    use rship_core::source::DataSource;
    use rship_core::types::ByteRange;

    let srv = MockGdriveServer::start().await;
    let payload: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "ext_big".into(),
            MockFile {
                id: "ext_big".into(),
                name: "big_target.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_big".into(),
            MockFile {
                id: "sc_big".into(),
                name: "big_link.bin".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("ext_big".into(), "application/octet-stream".into())),
                app_properties: HashMap::new(),
            },
        );
    }

    // Build entry without populating `shortcut_targets` on the reader's cold backend.
    let cold_backend = srv.backend("gd-cold-range");
    let synth_entry = rship_core::types::Entry {
        node_id: Some(NodeId("sc_big".into())),
        parent_id: Some(NodeId("root".into())),
        raw_path: None,
        nfc_path: RelPath::parse("big_link.bin").unwrap(),
        kind: EntryKind::File,
        size: payload.len() as u64,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    };
    let bp = BackendPath::new(
        "big_link.bin",
        RelPath::parse("big_link.bin").unwrap(),
        Some(NodeId("sc_big".into())),
    );
    let DataSource::RemoteRangeReadable(reader) = cold_backend
        .open_read_entry(&synth_entry, &bp, None)
        .await
        .unwrap()
    else {
        panic!("expected RemoteRangeReadable");
    };

    let mut handles = Vec::new();
    for i in 0..8usize {
        let r = reader.clone();
        handles.push(tokio::spawn(async move {
            let offset = (i * 8192) as u64;
            let mut s = r.open_range(ByteRange { offset, len: 8192 }).await?;
            let mut buf = Vec::new();
            while let Some(chunk) = s.next().await {
                buf.extend_from_slice(&chunk?);
            }
            Ok::<_, rship_core::Error>((i, buf))
        }));
    }

    for h in handles {
        let (idx, got) = h
            .await
            .unwrap()
            .expect("concurrent cold open_range must succeed");
        let start = idx * 8192;
        assert_eq!(got, payload[start..start + 8192]);
    }
}

// =========================================================================
// Iteration 2 Regression 3: Overwriting a shortcut with `existing_node_id = None`
// across single-shot, resumable, `server_side_copy`, and `DstPrecondition::Absent`
// =========================================================================

#[tokio::test]
async fn gdrive_overwrite_shortcut_with_existing_node_id_none() {
    use rship_core::backend::ChunkUpload;
    use rship_core::state::{OperationRecord, OperationState, SourceVersion};

    let srv = MockGdriveServer::start().await;
    let target_orig = b"ORIGINAL_TARGET_BYTES_MUST_STAY_INTACT".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "ext_t".into(),
            MockFile {
                id: "ext_t".into(),
                name: "target.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: target_orig.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "copy_src".into(),
            MockFile {
                id: "copy_src".into(),
                name: "copy_src.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"COPIED_OVER_SHORTCUT".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        for (id, name) in [
            ("sc_ss", "link_ss.txt"),
            ("sc_res", "link_res.txt"),
            ("sc_cpy", "link_cpy.txt"),
            ("sc_abs", "link_abs.txt"),
        ] {
            g.files.insert(
                id.into(),
                MockFile {
                    id: id.into(),
                    name: name.into(),
                    mime_type: SHORTCUT_MIME.into(),
                    parents: vec!["root".into()],
                    modified_time: "2026-11-24T00:00:00.000Z".into(),
                    data: vec![],
                    trashed: false,
                    shortcut_target: Some(("ext_t".into(), "text/plain".into())),
                    app_properties: HashMap::new(),
                },
            );
        }
    }

    let backend = srv.backend("gd-ow-sc-none");

    // 1. `DstPrecondition::Absent` with `existing_node_id = None` MUST reject existing shortcut!
    let abs_payload = b"should-fail".to_vec();
    let abs_c = abs_payload.clone();
    let abs_err = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-sc-abs".into(),
                dst_path: RelPath::parse("link_abs.txt").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: abs_payload.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: abs_payload.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(abs_c)) })),
        )
        .await
        .unwrap_err();
    assert_eq!(abs_err.kind, rship_core::ErrorKind::AlreadyExists);
    assert!(!srv.state.lock().unwrap().files["sc_abs"].trashed);

    // 2. Single-shot overwrite with `existing_node_id = None` and `DstPrecondition::Any`.
    let ss_new = b"NEW_SINGLE_SHOT_BYTES".to_vec();
    let ss_c = ss_new.clone();
    let ss_rel = RelPath::parse("link_ss.txt").unwrap();
    let ss_entry = backend
        .put_single_shot(
            &UploadInit {
                op_id: "op-sc-ss".into(),
                dst_path: ss_rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: ss_new.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: ss_new.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(ss_c)) })),
        )
        .await
        .unwrap();
    assert_ne!(ss_entry.node_id.as_ref().map(|n| n.as_str()), Some("sc_ss"));
    assert_eq!(read_gdrive_bytes(&backend, &ss_rel).await, ss_new);
    assert!(srv.state.lock().unwrap().files["sc_ss"].trashed);

    // 3. Resumable overwrite with `existing_node_id = None` and `DstPrecondition::Any`.
    let res_new = b"NEW_RESUMABLE_OVERWRITE_BYTES".to_vec();
    let res_rel = RelPath::parse("link_res.txt").unwrap();
    let res_init = UploadInit {
        op_id: "op-sc-res".into(),
        dst_path: res_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: res_new.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let opened = backend.begin_upload(&res_init).await.unwrap();
    let op = OperationRecord {
        op_id: res_init.op_id.clone(),
        session_key: "sk-res-sc".into(),
        job_id: "j-res-sc".into(),
        src_endpoint: "local://src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: res_rel.as_str().into(),
        dst_raw_path: res_rel.as_str().into(),
        dst_nfc_path: res_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: res_new.len() as u64,
            mtime_ns: res_init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: opened.remote_op_id.clone(),
        backend_kind: "gdrive".into(),
        session_token: Some(opened.session_token.clone()),
        backend_meta: opened.backend_meta.clone(),
        planned_chunk_size: 256 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let res_c = res_new.clone();
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                res_new.len() as u64,
                res_new.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(res_c)) })),
            ),
        )
        .await
        .unwrap();
    let res_fin = backend.finish_upload(&op, &[]).await.unwrap();
    assert_ne!(res_fin.node_id.as_ref().map(|n| n.as_str()), Some("sc_res"));
    assert_eq!(read_gdrive_bytes(&backend, &res_rel).await, res_new);
    assert!(srv.state.lock().unwrap().files["sc_res"].trashed);

    // 4. `server_side_copy` overwrite with `existing_node_id = None` and `DstPrecondition::Any`.
    let cpy_rel = RelPath::parse("link_cpy.txt").unwrap();
    let copied = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::new(
                "copy_src.txt",
                RelPath::parse("copy_src.txt").unwrap(),
                Some(NodeId("copy_src".into())),
            ),
            &UploadInit {
                op_id: "op-sc-cpy".into(),
                dst_path: cpy_rel.clone(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: b"COPIED_OVER_SHORTCUT".len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: b"COPIED_OVER_SHORTCUT".len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Any,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("server_side_copy overwriting shortcut with existing_node_id=None must succeed");
    assert_ne!(copied.node_id.as_ref().map(|n| n.as_str()), Some("sc_cpy"));
    assert_eq!(
        read_gdrive_bytes(&backend, &cpy_rel).await,
        b"COPIED_OVER_SHORTCUT"
    );
    assert!(srv.state.lock().unwrap().files["sc_cpy"].trashed);

    // Shortcut target `ext_t` remained 100% intact across all overwrites!
    assert_eq!(srv.state.lock().unwrap().files["ext_t"].data, target_orig);
}

// =========================================================================
// Iteration 2 Regression 4: Chained folder shortcuts (`sc_1 -> sc_2 -> dir`)
// under `use_changes_feed = true`
// =========================================================================

#[tokio::test]
async fn gdrive_chained_folder_shortcuts_in_changes_feed_mode() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        // External chained folder target (`real_dir/sub/deep.txt`) + external `sc_2`.
        g.files.insert(
            "real_dir".into(),
            MockFile {
                id: "real_dir".into(),
                name: "real_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "real_sub".into(),
            MockFile {
                id: "real_sub".into(),
                name: "sub".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["real_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "deep_txt".into(),
            MockFile {
                id: "deep_txt".into(),
                name: "deep.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["real_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"deep-chain-data".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_2".into(),
            MockFile {
                id: "sc_2".into(),
                name: "sc_2".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("real_dir".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_1".into(),
            MockFile {
                id: "sc_1".into(),
                name: "chained_dir".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("sc_2".into(), SHORTCUT_MIME.into())),
                app_properties: HashMap::new(),
            },
        );

        // In-corpus chained folder shortcut (`local_sc_1 -> local_sc_2 -> local_dir/sub/local.txt`).
        g.files.insert(
            "local_dir".into(),
            MockFile {
                id: "local_dir".into(),
                name: "local_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "local_sub".into(),
            MockFile {
                id: "local_sub".into(),
                name: "sub".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["local_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "local_txt".into(),
            MockFile {
                id: "local_txt".into(),
                name: "local.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["local_sub".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"local-chain".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "local_sc_2".into(),
            MockFile {
                id: "local_sc_2".into(),
                name: "local_sc_2".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("local_dir".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "local_sc_1".into(),
            MockFile {
                id: "local_sc_1".into(),
                name: "local_chained".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("local_sc_2".into(), SHORTCUT_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-chain-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor;
    let mut cfg = srv.config("gd-chain-feed");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    let mut root_paths: Vec<String> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    root_paths.sort();
    assert!(
        root_paths.contains(&"chained_dir/sub/deep.txt".to_string()),
        "root list_stream must emit external chained_dir/sub/deep.txt, got: {root_paths:?}"
    );
    assert!(
        root_paths.contains(&"local_chained/sub/local.txt".to_string()),
        "root list_stream must emit local_chained/sub/local.txt, got: {root_paths:?}"
    );

    let sub_paths: Vec<String> = backend
        .list_stream(&RelPath::parse("chained_dir/sub").unwrap(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert_eq!(sub_paths, vec!["chained_dir/sub/deep.txt"]);

    let local_sub_paths: Vec<String> = backend
        .list_stream(&RelPath::parse("local_chained/sub").unwrap(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert_eq!(local_sub_paths, vec!["local_chained/sub/local.txt"]);

    let projected = backend
        .project_cached_entries(&RelPath::parse("local_chained/sub").unwrap(), true)
        .await
        .unwrap();
    assert_eq!(
        projected
            .iter()
            .map(|e| e.nfc_path.as_str())
            .collect::<Vec<_>>(),
        vec!["local_chained/sub/local.txt"]
    );
}

// =========================================================================
// Iteration 2 Regression 5: Multi-hop shortcut resolution in
// `server_side_copy_impl` from cached `StateActor` inventory + folder reject
// =========================================================================

#[tokio::test]
async fn gdrive_server_side_copy_on_cached_chained_shortcut_and_folder_rejection() {
    let srv = MockGdriveServer::start().await;
    let target_data = b"CHAIN_COPY_DATA_EXACT_CONTENT!".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "real_f".into(),
            MockFile {
                id: "real_f".into(),
                name: "real_f.bin".into(),
                mime_type: "application/octet-stream".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: target_data.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_f2".into(),
            MockFile {
                id: "sc_f2".into(),
                name: "sc_f2.bin".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("real_f".into(), "application/octet-stream".into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_f1".into(),
            MockFile {
                id: "sc_f1".into(),
                name: "sc_f1.bin".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("sc_f2".into(), SHORTCUT_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "real_dir".into(),
            MockFile {
                id: "real_dir".into(),
                name: "real_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_d2".into(),
            MockFile {
                id: "sc_d2".into(),
                name: "sc_d2".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("real_dir".into(), FOLDER_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_d1".into(),
            MockFile {
                id: "sc_d1".into(),
                name: "sc_d1".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("sc_d2".into(), SHORTCUT_MIME.into())),
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-copy-chain-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor;
    let mut cfg = srv.config("gd-copy-chain");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));

    // Backend 1 populates `StateActor` inventory (`sc_f1 -> "sc:c:sc_f2"`).
    let b1 = GdriveBackend::new(
        cfg.clone(),
        transport.clone(),
        auth.clone(),
        Some(inv.clone()),
        None,
    );
    let _ = b1
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;

    // Backend 2 has cold `shortcut_targets` sharing `StateActor` inventory!
    let b2 = GdriveBackend::new(cfg, transport, auth, Some(inv), None);
    let copied = b2
        .server_side_copy(
            &b2.endpoint_identity(),
            &BackendPath::new(
                "sc_f1.bin",
                RelPath::parse("sc_f1.bin").unwrap(),
                Some(NodeId("sc_f1".into())),
            ),
            &UploadInit {
                op_id: "op-chain-copy".into(),
                dst_path: RelPath::parse("copied_chain.bin").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: target_data.len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: target_data.len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap()
        .expect("server_side_copy on cached chained shortcut must copy real_f");
    assert_eq!(copied.size, target_data.len() as u64);
    assert_eq!(
        read_gdrive_bytes(&b2, &RelPath::parse("copied_chain.bin").unwrap()).await,
        target_data
    );

    // Chained folder shortcut copy MUST return Ok(None) (not 400 from mock)!
    let dir_copy = b2
        .server_side_copy(
            &b2.endpoint_identity(),
            &BackendPath::new(
                "sc_d1",
                RelPath::parse("sc_d1").unwrap(),
                Some(NodeId("sc_d1".into())),
            ),
            &UploadInit {
                op_id: "op-chain-dir-copy".into(),
                dst_path: RelPath::parse("should_not_copy").unwrap(),
                existing_node_id: None,
                pregenerated_id: None,
                total_size: 0,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: 256 * 1024,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap();
    assert!(dir_copy.is_none());
}

// =========================================================================
// Iteration 2 Regression 6: `shared_with_me = true` + `use_changes_feed = true`
// does NOT poison `actual_root_id` and retains incremental shared changes
// =========================================================================

#[tokio::test]
async fn gdrive_shared_with_me_changes_feed_no_root_poison_and_incremental_sync() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "s1".into(),
            MockFile {
                id: "s1".into(),
                name: "s1.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["owner_shared_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"shared-1".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.shared_with_me_times
            .insert("s1".into(), "2026-11-24T00:00:00.000Z".into());
        g.files.insert(
            "sh_dir".into(),
            MockFile {
                id: "sh_dir".into(),
                name: "sh_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["owner_shared_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.shared_with_me_times
            .insert("sh_dir".into(), "2026-11-24T00:00:00.000Z".into());
        g.files.insert(
            "sh_in".into(),
            MockFile {
                id: "sh_in".into(),
                name: "inside.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["sh_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"inside".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-swm-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor;
    let mut cfg = srv.config("gd-swm-feed");
    cfg.shared_with_me = true;
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    backend.bootstrap_inventory().await.unwrap();

    // Incremental `changes.list` adds:
    // - `s2.txt` from another owner (`parents = ["another_owner_dir"]`, with `sharedWithMeTime`)
    // - `s3.txt` (`parents = ["third_owner_dir"]`, sharedWithMe in `files.list`, simulating mock without `sharedWithMeTime` on `changes.list`)
    // - `sh_added.txt` inside already-cached `sh_dir`
    {
        let mut g = srv.state.lock().unwrap();
        let s2 = MockFile {
            id: "s2".into(),
            name: "s2.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["another_owner_dir".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"shared-2".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let s3 = MockFile {
            id: "s3".into(),
            name: "s3.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["third_owner_dir".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"shared-3".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let sh_added = MockFile {
            id: "sh_added".into(),
            name: "added.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["sh_dir".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"added".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("s2".into(), s2.clone());
        g.shared_with_me_times
            .insert("s2".into(), "2026-11-25T00:00:00.000Z".into());
        g.files.insert("s3".into(), s3.clone());
        g.shared_with_me_times
            .insert("s3".into(), "2026-11-25T00:00:00.000Z".into());
        g.files.insert("sh_added".into(), sh_added.clone());
        g.changes_by_token.insert(
            "tok-swm-0".into(),
            MockChangePage {
                items: vec![
                    MockChangeItem {
                        file_id: "s2".into(),
                        removed: false,
                        file: Some(s2),
                    },
                    MockChangeItem {
                        file_id: "s3".into(),
                        removed: false,
                        file: Some(s3),
                    },
                    MockChangeItem {
                        file_id: "sh_added".into(),
                        removed: false,
                        file: Some(sh_added),
                    },
                ],
                next_page_token: None,
                new_start_page_token: Some("tok-swm-1".into()),
            },
        );
    }

    backend.sync_changes().await.unwrap();

    let mut paths: Vec<String> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "s1.txt",
            "s2.txt",
            "s3.txt",
            "sh_dir",
            "sh_dir/added.txt",
            "sh_dir/inside.txt",
        ]
    );
}

// =========================================================================
// Iteration 2 Regression 7: NFD `BackendPath::raw_path()` resolution in
// `stat`, `open_read`, `compute_hash`, `rename`, and `delete` with `node_id = None`
// =========================================================================

#[tokio::test]
async fn gdrive_nfd_raw_path_resolution_and_rename() {
    let srv = MockGdriveServer::start().await;
    let payload = b"nfd-folder-file-bytes".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "nfd_dir".into(),
            MockFile {
                id: "nfd_dir".into(),
                name: "cafe\u{301}".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "nfd_file".into(),
            MockFile {
                id: "nfd_file".into(),
                name: "old.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["nfd_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: payload.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-nfd");
    let old_bp = BackendPath::new(
        "cafe\u{301}/old.txt",
        RelPath::parse("caf\u{e9}/old.txt").unwrap(),
        None,
    );

    let st = backend
        .stat(&old_bp)
        .await
        .unwrap()
        .expect("stat on NFD raw_path with node_id=None must succeed");
    assert_eq!(st.size, payload.len() as u64);
    assert_eq!(st.raw_path(), "cafe\u{301}/old.txt");

    let hash = backend
        .compute_hash(&old_bp, HashKind::Md5)
        .await
        .unwrap()
        .expect("compute_hash on NFD raw_path must succeed");
    assert!(!hash.hex.is_empty());

    let ds = backend
        .open_read_entry(
            &st,
            &BackendPath::new("cafe\u{301}/old.txt", st.nfc_path.clone(), None),
            None,
        )
        .await
        .unwrap();
    if let rship_core::source::DataSource::RemoteRangeReadable(r) = ds {
        let mut s = r
            .open_range(rship_core::types::ByteRange {
                offset: 0,
                len: r.total_len(),
            })
            .await
            .unwrap();
        let mut got = Vec::new();
        while let Some(c) = s.next().await {
            got.extend_from_slice(&c.unwrap());
        }
        assert_eq!(got, payload);
    } else {
        panic!("expected RemoteRangeReadable");
    }

    let renamed = backend.rename(&old_bp, "new.txt").await.unwrap();
    assert_eq!(renamed.nfc_path.as_str(), "caf\u{e9}/new.txt");
    assert_eq!(renamed.raw_path(), "cafe\u{301}/new.txt");

    let new_bp = BackendPath::new(
        "cafe\u{301}/new.txt",
        RelPath::parse("caf\u{e9}/new.txt").unwrap(),
        None,
    );
    assert!(backend.stat(&new_bp).await.unwrap().is_some());
    backend.delete(&new_bp).await.unwrap();
    assert!(backend.stat(&new_bp).await.unwrap().is_none());
}

// =========================================================================
// Iteration 2 Regression 8: Multi-page `sync_changes` prunes `moved_in_dirs`
// when a folder is moved in on page 1 and removed/trashed on page 2
// =========================================================================

#[tokio::test]
async fn gdrive_sync_changes_prunes_moved_in_then_removed_dir_across_pages() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.start_page_token = "tok-ephem-0".into();
        // Child still exists on server if crawled (simulating race), so only pruning prevents orphan!
        g.files.insert(
            "ephem_child".into(),
            MockFile {
                id: "ephem_child".into(),
                name: "orphan.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["ephem_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"should-never-appear".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        let ephem_dir = MockFile {
            id: "ephem_dir".into(),
            name: "ephem_dir".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["root".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.changes_by_token.insert(
            "tok-ephem-0".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "ephem_dir".into(),
                    removed: false,
                    file: Some(ephem_dir),
                }],
                next_page_token: Some("tok-ephem-p2".into()),
                new_start_page_token: None,
            },
        );
        g.changes_by_token.insert(
            "tok-ephem-p2".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "ephem_dir".into(),
                    removed: true,
                    file: None,
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-ephem-1".into()),
            },
        );
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-ephem");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    backend.bootstrap_inventory().await.unwrap();
    backend.sync_changes().await.unwrap();

    assert!(
        actor
            .get_node("gd-ephem", "root", "ephem_dir")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        actor
            .get_node("gd-ephem", "root", "ephem_child")
            .await
            .unwrap()
            .is_none(),
        "ephem_child must NOT be left orphaned in gdrive_nodes when ephem_dir is removed on page 2"
    );
    assert!(
        actor
            .list_all_nodes("gd-ephem", "root")
            .await
            .unwrap()
            .is_empty()
    );
}

// =========================================================================
// Extra Coverage 1: Mid-crawl HTTP 500 inside `sync_changes` on >2000-file
// moved-in subtree leaves DB completely untouched; next sync recovers all
// =========================================================================

#[tokio::test]
async fn gdrive_sync_changes_mid_crawl_500_on_large_subtree_leaves_db_untouched() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "init_f".into(),
            MockFile {
                id: "init_f".into(),
                name: "init.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"init".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        let mut big_dir = MockFile {
            id: "big_moved".into(),
            name: "big_moved".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["outside_dir".into()],
            modified_time: "2026-11-24T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("big_moved".into(), big_dir.clone());
        for i in 0..2050 {
            let fid = format!("big_f_{i:04}");
            g.files.insert(
                fid.clone(),
                MockFile {
                    id: fid,
                    name: format!("f_{i:04}.bin"),
                    mime_type: "application/octet-stream".into(),
                    parents: vec!["big_moved".into()],
                    modified_time: "2026-11-24T00:00:00.000Z".into(),
                    data: vec![7],
                    trashed: false,
                    shortcut_target: None,
                    app_properties: HashMap::new(),
                },
            );
        }
        g.files.insert(
            "sub_500".into(),
            MockFile {
                id: "sub_500".into(),
                name: "sub_500".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["big_moved".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sub_leaf".into(),
            MockFile {
                id: "sub_leaf".into(),
                name: "leaf.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["sub_500".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"leaf".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.faults.fail_500_for_parent = Some("sub_500".into());
        g.start_page_token = "tok-500-0".into();
        big_dir.parents = vec!["root".into()];
        g.files.insert("big_moved".into(), big_dir.clone());
        // Keep `big_moved` outside `root` until after bootstrap!
        g.files.get_mut("big_moved").unwrap().parents = vec!["outside_dir".into()];
        g.changes_by_token.insert(
            "tok-500-0".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "big_moved".into(),
                    removed: false,
                    file: Some(big_dir),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-500-1".into()),
            },
        );
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-500-crawl");
    cfg.use_changes_feed = true;
    cfg.max_retries = 1;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    backend.bootstrap_inventory().await.unwrap();
    // Move `big_moved` into `root` before `sync_changes`.
    srv.state
        .lock()
        .unwrap()
        .files
        .get_mut("big_moved")
        .unwrap()
        .parents = vec!["root".into()];

    // Mid-crawl 500 on `sub_500` after >2000 children crawled MUST return Err and leave DB untouched!
    let err = backend.sync_changes().await.unwrap_err();
    assert_eq!(err.kind, rship_core::ErrorKind::Network);
    assert_eq!(
        actor
            .get_change_token(&backend.scope())
            .await
            .unwrap()
            .as_deref(),
        Some("tok-500-0")
    );
    let nodes_after_err = actor.list_all_nodes("gd-500-crawl", "root").await.unwrap();
    assert_eq!(nodes_after_err.len(), 1);
    assert_eq!(nodes_after_err[0].file_id, "init_f");

    // Clear 500 fault and retry -> recovers all 2050+ files atomically!
    srv.state.lock().unwrap().faults.fail_500_for_parent = None;
    let rep = backend.sync_changes().await.unwrap();
    assert_eq!(rep.new_start_page_token.as_deref(), Some("tok-500-1"));
    let projected = backend
        .project_cached_entries(&RelPath::root(), true)
        .await
        .unwrap();
    assert_eq!(projected.len(), 2054); // init.txt + big_moved + 2050 + sub_500 + sub_leaf
}

// =========================================================================
// Extra Coverage 2: `401` inside `is_under_root` (`get_file_by_id_tolerating_403`)
// triggers token refresh and succeeds when recoverable, or fails if unrecoverable
// =========================================================================

#[tokio::test]
async fn gdrive_is_under_root_401_triggers_token_refresh_and_fails_when_unrecoverable() {
    use rship_backends::gdrive::{InMemoryTokenStore, OAuth2AuthProvider, OAuthToken};
    use rship_core::clock::{Clock, VirtualClock};

    // Part A: Recoverable 401 during `is_under_root` parent probe triggers `force_refresh`!
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.valid_token = Some("tok-v1".into());
        g.faults.next_refreshed_token = Some("tok-v2".into());
        g.start_page_token = "tok-401-0".into();

        g.files.insert(
            "boot_f".into(),
            MockFile {
                id: "boot_f".into(),
                name: "boot.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"boot".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
    }

    let mut cfg = srv.config("gd-401-iur");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
    let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
        access_token: "tok-v1".into(),
        refresh_token: Some("ref-tok".into()),
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
            clock,
        )
        .unwrap(),
    );
    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let backend = GdriveBackend::new(cfg, transport.clone(), auth, Some(inv), None);

    // Bootstrap first so `actual_root_id` is already populated (`"root"`).
    backend.bootstrap_inventory().await.unwrap();

    // Now add an uncached parent `uncached_p` and a change for `child_u` under it.
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "uncached_p".into(),
            MockFile {
                id: "uncached_p".into(),
                name: "uncached_p".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        let child_in_uncached = MockFile {
            id: "child_u".into(),
            name: "child_u.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["uncached_p".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"ok".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("child_u".into(), child_in_uncached.clone());
        g.changes_by_token.insert(
            "tok-401-0".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "child_u".into(),
                    removed: false,
                    file: Some(child_in_uncached),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-401-1".into()),
            },
        );
    }

    // Inject 401 specifically on `files.get` (called inside `is_under_root` -> `get_file_by_id_tolerating_403` for `uncached_p`)!
    srv.fault_injector().push(
        "files.get",
        InjectedFault::json_error(
            StatusCode::UNAUTHORIZED,
            json!({ "error": { "code": 401, "message": "Invalid Credentials" } }).to_string(),
        ),
    );

    backend.sync_changes().await.unwrap();
    assert_eq!(srv.state.lock().unwrap().counters.token_refreshes, 1);
    assert!(
        actor
            .get_node("gd-401-iur", "root", "child_u")
            .await
            .unwrap()
            .is_some(),
        "recoverable 401 inside is_under_root must refresh token and retain child_u"
    );

    // Part B: Unrecoverable 401 inside `is_under_root` MUST propagate error (never treated as 403 Forbidden!).
    let static_auth = Arc::new(StaticBearerAuth::new("alice@example.com", "static-tok"));
    let mut cfg_b = srv.config("gd-401-fail");
    cfg_b.use_changes_feed = true;
    let actor_b = Arc::new(StateActor::open_in_memory().unwrap());
    let inv_b: Arc<dyn DeltaInventoryStore> = actor_b.clone();
    let backend_b = GdriveBackend::new(cfg_b, transport, static_auth, Some(inv_b), None);
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.valid_token = None;
        g.files.remove("uncached_p");
    }
    backend_b.bootstrap_inventory().await.unwrap();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "uncached_p2".into(),
            MockFile {
                id: "uncached_p2".into(),
                name: "uncached_p2".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        let child_u2 = MockFile {
            id: "child_u2".into(),
            name: "child_u2.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["uncached_p2".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"fail".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("child_u2".into(), child_u2.clone());
        g.changes_by_token.insert(
            "tok-401-0".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "child_u2".into(),
                    removed: false,
                    file: Some(child_u2),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-401-2".into()),
            },
        );
    }
    srv.fault_injector().push(
        "files.get",
        InjectedFault::json_error(
            StatusCode::UNAUTHORIZED,
            json!({ "error": { "code": 401, "message": "Revoked" } }).to_string(),
        ),
    );
    let err_b = backend_b.sync_changes().await.unwrap_err();
    assert_eq!(err_b.kind, rship_core::ErrorKind::PermissionDenied);
}

// =========================================================================
// Iteration 3 Regression 1 (Challenger 2 Finding 1): `shared_with_me = true`
// + `use_changes_feed = true`: modifying/renaming an existing shared folder
// in the same `changes.list` batch as new/modified children must retain all
// children and cleanly evict them if the folder is later unshared.
// =========================================================================

#[tokio::test]
async fn gdrive_shared_with_me_changes_feed_folder_modified_with_children() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.faults.forbidden_file_ids.insert("owner1".into());
        g.files.insert(
            "sh_dir".into(),
            MockFile {
                id: "sh_dir".into(),
                name: "sh_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["owner1".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.shared_with_me_times
            .insert("sh_dir".into(), "2026-11-24T00:00:00.000Z".into());
        g.files.insert(
            "sh_in".into(),
            MockFile {
                id: "sh_in".into(),
                name: "inside.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["sh_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"inside-v1".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.start_page_token = "tok-swm-batch-0".into();
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor.clone();
    let mut cfg = srv.config("gd-swm-batch");
    cfg.shared_with_me = true;
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    backend.bootstrap_inventory().await.unwrap();

    // Same `changes.list` batch renames `sh_dir` -> `sh_dir_v2`, adds `added.txt`,
    // and modifies existing `inside.txt`.
    {
        let mut g = srv.state.lock().unwrap();
        let sh_dir_v2 = MockFile {
            id: "sh_dir".into(),
            name: "sh_dir_v2".into(),
            mime_type: FOLDER_MIME.into(),
            parents: vec!["owner1".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: vec![],
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let sh_added = MockFile {
            id: "sh_added".into(),
            name: "added.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["sh_dir".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"added".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        let sh_in_v2 = MockFile {
            id: "sh_in".into(),
            name: "inside.txt".into(),
            mime_type: "text/plain".into(),
            parents: vec!["sh_dir".into()],
            modified_time: "2026-11-25T00:00:00.000Z".into(),
            data: b"inside-v2-updated".to_vec(),
            trashed: false,
            shortcut_target: None,
            app_properties: HashMap::new(),
        };
        g.files.insert("sh_dir".into(), sh_dir_v2.clone());
        g.files.insert("sh_added".into(), sh_added.clone());
        g.files.insert("sh_in".into(), sh_in_v2.clone());
        g.changes_by_token.insert(
            "tok-swm-batch-0".into(),
            MockChangePage {
                items: vec![
                    MockChangeItem {
                        file_id: "sh_dir".into(),
                        removed: false,
                        file: Some(sh_dir_v2),
                    },
                    MockChangeItem {
                        file_id: "sh_added".into(),
                        removed: false,
                        file: Some(sh_added),
                    },
                    MockChangeItem {
                        file_id: "sh_in".into(),
                        removed: false,
                        file: Some(sh_in_v2),
                    },
                ],
                next_page_token: None,
                new_start_page_token: Some("tok-swm-batch-1".into()),
            },
        );
    }

    backend.sync_changes().await.unwrap();

    let mut paths: Vec<String> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    paths.sort();
    assert_eq!(
        paths,
        vec!["sh_dir_v2", "sh_dir_v2/added.txt", "sh_dir_v2/inside.txt",]
    );

    // Subsequent batch unshares `sh_dir` -> `sh_dir_v2` and its children are evicted cleanly.
    {
        let mut g = srv.state.lock().unwrap();
        g.shared_with_me_times.remove("sh_dir");
        let sh_dir_unshared = g.files.get("sh_dir").unwrap().clone();
        g.changes_by_token.insert(
            "tok-swm-batch-1".into(),
            MockChangePage {
                items: vec![MockChangeItem {
                    file_id: "sh_dir".into(),
                    removed: false,
                    file: Some(sh_dir_unshared),
                }],
                next_page_token: None,
                new_start_page_token: Some("tok-swm-batch-2".into()),
            },
        );
    }

    backend.sync_changes().await.unwrap();
    let after_unshare: Vec<String> = backend
        .list_stream(&RelPath::root(), true)
        .await
        .unwrap()
        .map(|r| r.unwrap().nfc_path.as_str().to_string())
        .collect()
        .await;
    assert!(
        after_unshare.is_empty(),
        "expected empty after unshare, got {after_unshare:?}"
    );
}

// =========================================================================
// Iteration 3 Regression 2 (Challenger 2 Finding 2): `existing_node_id = Some(sc_id)`
// + `DstPrecondition::Absent` across `put_single_shot`, `begin_upload`, and
// `server_side_copy` must fail with `AlreadyExists` without trashing `sc_id`.
// =========================================================================

#[tokio::test]
async fn gdrive_existing_node_id_some_shortcut_with_absent_precondition_fails_atomically() {
    let srv = MockGdriveServer::start().await;
    let target_orig = b"ORIGINAL_TARGET_INTACT".to_vec();
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "ext_t".into(),
            MockFile {
                id: "ext_t".into(),
                name: "target.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: target_orig.clone(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "copy_src".into(),
            MockFile {
                id: "copy_src".into(),
                name: "copy_src.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["other_root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: b"COPY_SRC".to_vec(),
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "sc_abs_some".into(),
            MockFile {
                id: "sc_abs_some".into(),
                name: "abs_some.txt".into(),
                mime_type: SHORTCUT_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: Some(("ext_t".into(), "text/plain".into())),
                app_properties: HashMap::new(),
            },
        );
    }

    let backend = srv.backend("gd-abs-some");
    let dst_rel = RelPath::parse("abs_some.txt").unwrap();
    let payload = b"should-not-overwrite".to_vec();
    let init = UploadInit {
        op_id: "op-abs-some".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: Some(NodeId("sc_abs_some".into())),
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: payload.len() as u64,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };

    let ss_err = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(
                async move { Ok(Bytes::from(payload)) },
            )),
        )
        .await
        .unwrap_err();
    assert_eq!(ss_err.kind, rship_core::ErrorKind::AlreadyExists);
    assert!(!srv.state.lock().unwrap().files["sc_abs_some"].trashed);

    let begin_err = backend.begin_upload(&init).await.unwrap_err();
    assert_eq!(begin_err.kind, rship_core::ErrorKind::AlreadyExists);
    assert!(!srv.state.lock().unwrap().files["sc_abs_some"].trashed);

    let copy_err = backend
        .server_side_copy(
            &backend.endpoint_identity(),
            &BackendPath::new(
                "copy_src.txt",
                RelPath::parse("copy_src.txt").unwrap(),
                Some(NodeId("copy_src".into())),
            ),
            &UploadInit {
                op_id: "op-abs-some-copy".into(),
                dst_path: dst_rel,
                existing_node_id: Some(NodeId("sc_abs_some".into())),
                pregenerated_id: None,
                total_size: b"COPY_SRC".len() as u64,
                src_mtime_ns: 1_700_000_000_000_000_000,
                planned_chunk_size: b"COPY_SRC".len() as u64,
                checksums: vec![],
                precondition: DstPrecondition::Absent,
                src_etag: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(copy_err.kind, rship_core::ErrorKind::AlreadyExists);
    assert!(!srv.state.lock().unwrap().files["sc_abs_some"].trashed);
    assert_eq!(srv.state.lock().unwrap().files["ext_t"].data, target_orig);
}

// =========================================================================
// Iteration 3 Regression 3 (Reviewer 2 Caveat 1): Prefix >8-hop shortcut
// chain in `stream_cached_entries` must return empty instead of a 0-byte entry.
// =========================================================================

#[tokio::test]
async fn gdrive_prefix_over_8_hop_shortcut_chain_returns_empty() {
    let srv = MockGdriveServer::start().await;
    {
        let mut g = srv.state.lock().unwrap();
        g.files.insert(
            "deep_target".into(),
            MockFile {
                id: "deep_target".into(),
                name: "deep_target.txt".into(),
                mime_type: "text/plain".into(),
                parents: vec!["store_dir".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![42u8; 128],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        g.files.insert(
            "store_dir".into(),
            MockFile {
                id: "store_dir".into(),
                name: "store_dir".into(),
                mime_type: FOLDER_MIME.into(),
                parents: vec!["root".into()],
                modified_time: "2026-11-24T00:00:00.000Z".into(),
                data: vec![],
                trashed: false,
                shortcut_target: None,
                app_properties: HashMap::new(),
            },
        );
        // 9-hop shortcut chain: sc_0 (in root) -> sc_1 -> ... -> sc_8 -> deep_target
        for hop in 0..9 {
            let id = format!("sc_{hop}");
            let (parent, name) = if hop == 0 {
                ("root".to_string(), "deep_sc.txt".to_string())
            } else {
                ("store_dir".to_string(), format!("hop_{hop}.sc"))
            };
            let (tid, tmime) = if hop == 8 {
                ("deep_target".to_string(), "text/plain".to_string())
            } else {
                (format!("sc_{}", hop + 1), SHORTCUT_MIME.to_string())
            };
            g.files.insert(
                id,
                MockFile {
                    id: format!("sc_{hop}"),
                    name,
                    mime_type: SHORTCUT_MIME.into(),
                    parents: vec![parent],
                    modified_time: "2026-11-24T00:00:00.000Z".into(),
                    data: vec![],
                    trashed: false,
                    shortcut_target: Some((tid, tmime)),
                    app_properties: HashMap::new(),
                },
            );
        }
    }

    let actor = Arc::new(StateActor::open_in_memory().unwrap());
    let inv: Arc<dyn DeltaInventoryStore> = actor;
    let mut cfg = srv.config("gd-9hop");
    cfg.use_changes_feed = true;
    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let auth = Arc::new(StaticBearerAuth::new("alice@example.com", "tok"));
    let backend = GdriveBackend::new(cfg, transport, auth, Some(inv), None);

    backend.bootstrap_inventory().await.unwrap();

    let entries: Vec<_> = backend
        .list_stream(&RelPath::parse("deep_sc.txt").unwrap(), false)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert!(
        entries.is_empty(),
        "prefix listing of >8-hop shortcut chain must return empty, got {entries:?}"
    );
}
