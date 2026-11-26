//! Microsoft Graph control-plane namespace operations: directory chain creation,
//! `stat`, streaming concurrent BFS directory listing, deletion, rename, metadata checksums,
//! async-monitored server-side copy (`POST /items/{id}/copy`), and drive quota.

use http::{Method, StatusCode};
use rship_core::backend::{BackendPath, EntryStream, ListOptions, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::types::{Checksum, Entry, HashKind, StorageQuota};
use rship_core::{Error, ErrorKind, Result};
use rship_transport::parse_retry_after;
use serde::Deserialize;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::common::http::{Idempotency, PolicyDecision, ReconcileAction, execute_with_policy};

use super::transfer::format_rfc3339_secs;
use super::{
    GraphItem, GraphOutcome, OnedriveBackend, decode_node_id, encode_node_id, graph_error_decision,
};

#[derive(Debug, Deserialize)]
pub(super) struct GraphChildrenPage {
    #[serde(default)]
    pub(super) value: Vec<GraphItem>,
    #[serde(rename = "@odata.nextLink")]
    pub(super) next_link: Option<String>,
}

impl OnedriveBackend {
    pub(super) async fn ensure_dir_chain(&self, rel: &RelPath) -> Result<(String, Option<String>)> {
        let _guard = self.inner.mkdir_lock.lock().await;
        if rel.is_root() {
            let root_url = format!("{}/root", self.inner.drive_base);
            let (_, _, body) = self
                .graph_request("stat(root)", Method::GET, &root_url, None, false)
                .await?;
            let item: GraphItem = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode root GraphItem: {e}")))?;
            return Ok((item.id, None));
        }

        let mut cur_rel = RelPath::root();
        let mut last_id = String::new();
        let mut cur_drive_id: Option<String> = None;
        for seg in rel.segments() {
            let next_str = if cur_rel.is_root() {
                seg.to_string()
            } else {
                format!("{}/{}", cur_rel.as_str(), seg)
            };
            let next_rel = RelPath::parse(&next_str)?;
            let existing_opt = if let Some(ref did) = cur_drive_id {
                self.find_child_in_drive_folder(Some(did.as_str()), &last_id, seg)
                    .await?
                    .map(|it| (it, Some(did.clone())))
            } else {
                self.stat_graph_item_with_drive(&BackendPath::from_rel(next_rel.clone()))
                    .await?
            };
            if let Some((existing, existing_did)) = existing_opt {
                if !existing.is_folder() {
                    return Err(Error::conflict(format!(
                        "cannot create OneDrive directory `{next_rel}`: a non-directory item exists at that path"
                    )));
                }
                if existing.remote_item.is_some() {
                    let (target_did, target_id) = existing.remote_target();
                    cur_drive_id = self.external_drive_id(target_did).await?.or(existing_did);
                    last_id = target_id.to_string();
                } else {
                    cur_drive_id = existing_did;
                    last_id = existing.id;
                }
                cur_rel = next_rel;
                continue;
            }
            let parent_children_url = if let Some(ref did) = cur_drive_id {
                self.drive_item_url(Some(did.as_str()), &last_id, "children")
            } else {
                self.item_path_url(&cur_rel, "children")
            };
            let payload = serde_json::json!({
                "name": seg,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "fail"
            });
            // A replay after a lost createFolder response gets 409 nameAlreadyExists: a
            // folder at that path is exactly the result we asked for.
            let folder_bp = BackendPath::from_rel(next_rel.clone());
            let cur_did_snap = cur_drive_id.clone();
            let cur_pid_snap = last_id.clone();
            let seg_snap = seg.to_string();
            match self
                .graph_commit(
                    "mkdir(createFolder)",
                    &parent_children_url,
                    &payload,
                    None,
                    |err| {
                        let folder_bp = folder_bp.clone();
                        let cur_did_snap = cur_did_snap.clone();
                        let cur_pid_snap = cur_pid_snap.clone();
                        let seg_snap = seg_snap.clone();
                        async move {
                            let found = if let Some(ref did) = cur_did_snap {
                                self.find_child_in_drive_folder(
                                    Some(did.as_str()),
                                    &cur_pid_snap,
                                    &seg_snap,
                                )
                                .await?
                            } else {
                                self.stat_graph_item(&folder_bp).await?
                            };
                            match found {
                                Some(it) if it.is_folder() => {
                                    Ok(ReconcileAction::Resolved(GraphOutcome::Item(Box::new(it))))
                                }
                                Some(_) => Ok(ReconcileAction::Fail(err)),
                                None => Ok(ReconcileAction::Retry(err)),
                            }
                        }
                    },
                )
                .await
            {
                Ok(GraphOutcome::Item(created)) => last_id = created.id,
                Ok(GraphOutcome::Response(_, _, body)) => {
                    let created: GraphItem = serde_json::from_slice(&body)
                        .map_err(|e| Error::protocol(format!("decode mkdir GraphItem: {e}")))?;
                    last_id = created.id;
                }
                Err(e)
                    if e.kind == ErrorKind::Conflict || e.kind == ErrorKind::PreconditionFailed =>
                {
                    let existing_opt = if let Some(ref did) = cur_drive_id {
                        self.find_child_in_drive_folder(Some(did.as_str()), &last_id, seg)
                            .await?
                    } else {
                        self.stat_graph_item(&BackendPath::from_rel(next_rel.clone()))
                            .await?
                    };
                    if let Some(existing) = existing_opt {
                        if !existing.is_folder() {
                            return Err(Error::conflict(format!(
                                "cannot create OneDrive directory `{next_rel}`: a non-directory item exists at that path"
                            )));
                        }
                        if existing.remote_item.is_some() {
                            let (target_did, target_id) = existing.remote_target();
                            cur_drive_id = self.external_drive_id(target_did).await?;
                            last_id = target_id.to_string();
                        } else {
                            last_id = existing.id;
                        }
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
            cur_rel = next_rel;
        }
        Ok((last_id, cur_drive_id))
    }

    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let Some((item, remote_drive_id)) = self.stat_graph_item_with_drive(path).await? else {
            return Ok(None);
        };
        Ok(Some(self.item_to_entry(
            &item,
            path.raw_path(),
            path.nfc_path.clone(),
            remote_drive_id.as_deref(),
        )))
    }

    pub(super) async fn list_with_options_impl(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let effective_max_depth = options.effective_max_depth();
        if effective_max_depth == Some(0) {
            return Ok(Box::pin(futures::stream::empty()));
        }

        let start_task = if prefix.is_root() {
            DirTask {
                raw_rel: String::new(),
                item_id: None,
                drive_id: None,
            }
        } else {
            let Some((item, item_remote_did)) = self
                .stat_graph_item_with_drive(&BackendPath::from_rel(prefix.clone()))
                .await?
            else {
                return Ok(Box::pin(futures::stream::empty()));
            };
            if !item.is_folder() {
                return Ok(Box::pin(futures::stream::empty()));
            }
            let (target_drive_id, target_id) = item.remote_target();
            let dir_drive_id = if item.remote_item.is_some() {
                self.external_drive_id(target_drive_id)
                    .await?
                    .or(item_remote_did)
            } else {
                item_remote_did.or(self.external_drive_id(target_drive_id).await?)
            };
            DirTask {
                raw_rel: prefix.as_str().to_string(),
                item_id: (!target_id.is_empty()).then(|| target_id.to_string()),
                drive_id: dir_drive_id,
            }
        };

        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let backend = self.clone();
        let base_depth = prefix.segments().count();
        let pruner = options.dir_pruner().cloned();

        tokio::spawn(async move {
            const MAX_LIST_CONCURRENCY: usize = 8;

            let mut queue: VecDeque<DirTask> = VecDeque::new();
            queue.push_back(start_task);

            let mut in_flight: tokio::task::JoinSet<Result<Vec<DirTask>>> =
                tokio::task::JoinSet::new();

            loop {
                if tx.is_closed() {
                    in_flight.abort_all();
                    return;
                }
                while in_flight.len() < MAX_LIST_CONCURRENCY {
                    let Some(dir) = queue.pop_front() else {
                        break;
                    };
                    let b = backend.clone();
                    let tx_page = tx.clone();
                    let pruner = pruner.clone();
                    in_flight.spawn(async move {
                        let mut subdirs = Vec::new();
                        let mut next_url = Some(match &dir.item_id {
                            Some(id) => format!(
                                "{}?$top=999",
                                b.drive_item_url(dir.drive_id.as_deref(), id, "children")
                            ),
                            None => format!("{}/root/children?$top=999", b.inner.drive_base),
                        });
                        while let Some(url) = next_url.take() {
                            let (status, _, body) = b
                                .graph_request("list(children)", Method::GET, &url, None, true)
                                .await?;
                            if status == StatusCode::NOT_FOUND {
                                break;
                            }
                            let page: GraphChildrenPage =
                                serde_json::from_slice(&body).map_err(|e| {
                                    Error::protocol(format!("decode children page: {e}"))
                                })?;
                            next_url = page.next_link;
                            for item in page.value {
                                if item.is_package() {
                                    continue;
                                }
                                let item_name = if !item.name.is_empty() {
                                    item.name.as_str()
                                } else {
                                    item.effective().name.as_str()
                                };
                                if item_name.is_empty() {
                                    continue;
                                }
                                let raw_rel = if dir.raw_rel.is_empty() {
                                    item_name.to_string()
                                } else {
                                    format!("{}/{}", dir.raw_rel, item_name)
                                };
                                let Ok(nfc_rel) = RelPath::parse(&raw_rel) else {
                                    continue;
                                };
                                let rel_depth =
                                    nfc_rel.segments().count().saturating_sub(base_depth);
                                if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                                    continue;
                                }
                                let is_dir = item.is_folder();
                                if is_dir && pruner.as_ref().is_some_and(|p| p(&nfc_rel)) {
                                    continue;
                                }
                                let (child_drive_id, child_item_id) = item.remote_target();
                                let entry = b.item_to_entry(
                                    &item,
                                    &raw_rel,
                                    nfc_rel.clone(),
                                    dir.drive_id.as_deref(),
                                );
                                if tx_page.send(Ok(entry)).await.is_err() {
                                    return Ok(Vec::new());
                                }
                                if is_dir
                                    && effective_max_depth.is_none_or(|limit| rel_depth < limit)
                                {
                                    let child_id = (!child_item_id.is_empty())
                                        .then(|| child_item_id.to_string());
                                    let next_drive_id = if item.remote_item.is_some() {
                                        b.external_drive_id(child_drive_id)
                                            .await?
                                            .or_else(|| dir.drive_id.clone())
                                    } else {
                                        dir.drive_id.clone()
                                    };
                                    subdirs.push(DirTask {
                                        raw_rel,
                                        item_id: child_id,
                                        drive_id: next_drive_id,
                                    });
                                }
                            }
                        }
                        Ok(subdirs)
                    });
                }
                let Some(joined) = in_flight.join_next().await else {
                    break;
                };
                match joined {
                    Ok(Ok(subdirs)) => {
                        for sub in subdirs {
                            queue.push_back(sub);
                        }
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(e)).await;
                        in_flight.abort_all();
                        return;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!(
                                "OneDrive list task failed: {e}"
                            ))))
                            .await;
                        in_flight.abort_all();
                        return;
                    }
                }
            }
        });

        Ok(crate::common::rx_to_entry_stream(rx))
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        let _ = self.ensure_dir_chain(path).await?;
        Ok(())
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Ok(());
        }
        if let Some(nid) = &path.node_id {
            let (drive_id, item_id) = decode_node_id(nid.as_str());
            let url = self.drive_item_url(drive_id, item_id, "");
            let _ = self
                .graph_request("delete", Method::DELETE, &url, None, true)
                .await?;
            return Ok(());
        }
        let url = self.raw_item_path_url(path.raw_path(), "");
        let (status, _, _) = self
            .graph_request("delete", Method::DELETE, &url, None, true)
            .await?;
        if status == StatusCode::NOT_FOUND
            && path.raw_path().contains('/')
            && let Some((item, remote_drive_id)) =
                self.stat_through_remote_mount(path.raw_path()).await?
        {
            let remote_url = self.drive_item_url(remote_drive_id.as_deref(), &item.id, "");
            let _ = self
                .graph_request("delete", Method::DELETE, &remote_url, None, true)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn rename_impl(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename OneDrive root"));
        }
        if new_name.is_empty()
            || new_name == "."
            || new_name == ".."
            || new_name.contains('/')
            || new_name.contains('\\')
        {
            return Err(Error::invalid_path(format!(
                "invalid OneDrive rename target `{new_name}`"
            )));
        }
        let Some((item, remote_drive_id)) = self.stat_graph_item_with_drive(path).await? else {
            return Err(Error::not_found(format!(
                "OneDrive item `{}` not found",
                path.nfc_path
            )));
        };
        let url = self.drive_item_url(remote_drive_id.as_deref(), &item.id, "");
        let payload = serde_json::json!({ "name": new_name });
        let (_, _, body) = self
            .graph_request("rename", Method::PATCH, &url, Some(&payload), false)
            .await?;
        let updated: GraphItem = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode rename GraphItem: {e}")))?;
        let updated_drive_id = if updated.remote_item.is_some() {
            remote_drive_id
        } else {
            let cand = updated
                .parent_reference
                .as_ref()
                .and_then(|p| p.drive_id.as_deref());
            self.external_drive_id(cand).await?.or(remote_drive_id)
        };

        let raw = path.raw_path();
        let new_raw = match raw.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => format!("{parent}/{new_name}"),
            _ => new_name.to_string(),
        };
        let new_nfc = RelPath::parse(&new_raw)?;
        Ok(self.item_to_entry(&updated, new_raw, new_nfc, updated_drive_id.as_deref()))
    }

    pub(super) async fn compute_hash_impl(
        &self,
        path: &BackendPath,
        kind: HashKind,
    ) -> Result<Option<Checksum>> {
        let Some(item) = self.stat_graph_item(path).await? else {
            return Ok(None);
        };
        if item.is_package() {
            return Ok(None);
        }
        let Some(hashes) = item
            .effective()
            .file
            .as_ref()
            .and_then(|f| f.hashes.as_ref())
        else {
            return Ok(None);
        };
        let hex = match kind {
            HashKind::Sha256 => hashes.sha256_hex(),
            HashKind::Sha1 => hashes.sha1_hex(),
            _ => None,
        };
        Ok(hex.map(|hex| Checksum { kind, hex }))
    }

    pub(super) async fn resolve_drive_id(&self) -> Result<String> {
        if let Some(id) = self
            .inner
            .cfg
            .drive_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(id.to_string());
        }
        self.inner
            .resolved_drive_id
            .get_or_try_init(|| async {
                let (_, _, body) = self
                    .graph_request(
                        "drive.get",
                        Method::GET,
                        &self.inner.drive_base,
                        None,
                        false,
                    )
                    .await?;
                #[derive(Deserialize)]
                struct DriveIdResp {
                    id: Option<String>,
                }
                let parsed: DriveIdResp = serde_json::from_slice(&body)
                    .map_err(|e| Error::protocol(format!("decode drive JSON: {e}")))?;
                parsed
                    .id
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| Error::protocol("OneDrive drive response missing `id`"))
            })
            .await
            .cloned()
    }

    pub(super) async fn patch_item_mtime(
        &self,
        item: GraphItem,
        src_mtime_ns: i64,
        context_label: &str,
        drive_id_hint: Option<&str>,
    ) -> Result<GraphItem> {
        if src_mtime_ns < 0 {
            return Ok(item);
        }
        let target_secs = src_mtime_ns.div_euclid(1_000_000_000);
        let current_secs = item
            .effective()
            .file_system_info
            .as_ref()
            .and_then(|fs| fs.last_modified_date_time.as_deref())
            .or(item.effective().last_modified_date_time.as_deref())
            .and_then(rship_core::time::parse_rfc3339_to_secs);
        if current_secs == Some(target_secs) {
            return Ok(item);
        }
        let (target_drive_id, target_id) = item.remote_target();
        let remote_drive_id = self
            .external_drive_id(target_drive_id.or(drive_id_hint))
            .await?;
        let patch_url = self.drive_item_url(remote_drive_id.as_deref(), target_id, "");
        let patch_body = serde_json::json!({
            "fileSystemInfo": {
                "lastModifiedDateTime": format_rfc3339_secs(src_mtime_ns),
            }
        });
        let (_, _, pbody) = self
            .graph_request(
                "PATCH(mtime)",
                Method::PATCH,
                &patch_url,
                Some(&patch_body),
                false,
            )
            .await?;
        match serde_json::from_slice::<GraphItem>(&pbody) {
            Ok(patched) => Ok(patched),
            Err(e) => {
                tracing::warn!(
                    context = context_label,
                    item_id = %item.id,
                    error = %e,
                    "OneDrive PATCH(mtime) returned unexpected JSON; retaining prior GraphItem"
                );
                Ok(item)
            }
        }
    }

    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        src_endpoint == self.endpoint_identity()
    }

    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        if !self.can_server_side_copy_from(src_endpoint) {
            return Ok(None);
        }
        // Graph `POST /items/{id}/copy` defaults to conflictBehavior=fail and cannot overwrite
        // an existing destination item in place; fall back cleanly when overwriting.
        if matches!(
            init.precondition,
            rship_core::state::DstPrecondition::Existing { .. }
        ) {
            return Ok(None);
        }
        let (src_drive_id, src_id) = match &src_path.node_id {
            Some(id) => {
                let (did, iid) = decode_node_id(id.as_str());
                (did.map(str::to_string), iid.to_string())
            }
            None => match self.stat_graph_item_with_drive(src_path).await? {
                Some((it, remote_did)) if !it.is_folder() && !it.is_package() => {
                    if it.remote_item.is_some() {
                        let (did, tid) = it.remote_target();
                        (
                            self.external_drive_id(did).await?.or(remote_did),
                            tid.to_string(),
                        )
                    } else {
                        (remote_did, it.id)
                    }
                }
                _ => return Ok(None),
            },
        };
        let dst_name = init
            .dst_path
            .file_name()
            .ok_or_else(|| Error::invalid_path("cannot server-side copy to root"))?;
        let parent_rel = init.dst_path.parent().unwrap_or_else(RelPath::root);
        let (parent_id, parent_drive_id) = self.ensure_dir_chain(&parent_rel).await?;
        let drive_id = match parent_drive_id {
            Some(ref did) => did.clone(),
            None => self.resolve_drive_id().await?,
        };

        let copy_url = self.drive_item_url(src_drive_id.as_deref(), &src_id, "copy");
        let payload = serde_json::json!({
            "parentReference": {
                "driveId": drive_id,
                "id": parent_id
            },
            "name": dst_name
        });

        // `items.copy` is not idempotent: a replay after a lost 202 gets 409
        // nameAlreadyExists. Reconcile requires a destination item that did not exist before
        // the copy (snapshot) with the source's size, and equal content hashes when both
        // sides report one.
        let dst_bp = BackendPath::from_rel(init.dst_path.clone());
        let dst_before = self.stat_graph_item(&dst_bp).await?.map(|it| it.id);
        let src_bp = BackendPath::new(
            src_path.raw_path(),
            src_path.nfc_path.clone(),
            encode_node_id(src_drive_id.as_deref(), &src_id),
        );
        let outcome = match self
            .graph_commit(
                "items.copy",
                &copy_url,
                &payload,
                Some(self.inner.transport.config().long_control_timeout),
                |err| {
                    let dst_bp = dst_bp.clone();
                    let src_bp = src_bp.clone();
                    let dst_before = dst_before.clone();
                    async move {
                        let Some(dst) = self.stat_graph_item(&dst_bp).await? else {
                            return Ok(ReconcileAction::Retry(err));
                        };
                        let fresh = dst_before.as_deref() != Some(dst.id.as_str());
                        let src = self.stat_graph_item(&src_bp).await?;
                        let same = src
                            .as_ref()
                            .is_some_and(|src| fresh && graph_items_match(src, &dst));
                        if same {
                            return Ok(ReconcileAction::Resolved(GraphOutcome::Item(Box::new(
                                dst,
                            ))));
                        }
                        if err.kind == ErrorKind::Conflict {
                            return Ok(ReconcileAction::Fail(err));
                        }
                        Ok(ReconcileAction::Retry(err))
                    }
                },
            )
            .await
        {
            Ok(v) => v,
            Err(e) if e.kind == ErrorKind::Conflict => return Ok(None),
            Err(e) => return Err(e),
        };

        let finalize_copied = |item: GraphItem, item_drive_id: Option<String>| {
            let this = self.clone();
            let dst_path = init.dst_path.clone();
            let dst_raw = dst_path.as_str().to_string();
            let src_mtime_ns = init.src_mtime_ns;
            let fallback_did = parent_drive_id.clone();
            async move {
                let effective_did = item_drive_id.or(fallback_did);
                let item = this
                    .patch_item_mtime(
                        item,
                        src_mtime_ns,
                        "server_side_copy",
                        effective_did.as_deref(),
                    )
                    .await?;
                Ok(Some(this.item_to_entry(
                    &item,
                    dst_raw,
                    dst_path,
                    effective_did.as_deref(),
                )))
            }
        };

        let (status, headers) = match outcome {
            GraphOutcome::Item(item) => {
                return finalize_copied(*item, None).await;
            }
            GraphOutcome::Response(status, headers, _) => (status, headers),
        };

        if status == StatusCode::ACCEPTED
            && let Some(monitor_url) = headers
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
        {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct MonitorResp {
                #[serde(default)]
                status: Option<String>,
                #[serde(default)]
                resource_id: Option<String>,
                #[serde(default)]
                id: Option<String>,
            }
            enum MonitorStep {
                Completed(Option<String>),
                TerminalFail,
                InProgress(Option<Duration>),
                Redirect,
                CheckDestination(Error),
            }

            let policy_cfg = self.retry_policy_config(None);
            let deadline =
                tokio::time::Instant::now() + self.inner.transport.config().long_control_timeout;
            let mut poll_delay = Duration::from_millis(50);

            loop {
                let step: MonitorStep = execute_with_policy(
                    &self.inner.transport,
                    &self.inner.control_limiter,
                    "GET(copy monitor)",
                    &policy_cfg,
                    Idempotency::Idempotent,
                    || {
                        let monitor_url = monitor_url.to_string();
                        async move {
                            // Pre-authenticated copy monitor URL (no Bearer header required).
                            Ok(self.inner.transport.control_client().get(&monitor_url))
                        }
                    },
                    |resp| {
                        if resp.status == StatusCode::SEE_OTHER {
                            return PolicyDecision::Ok(MonitorStep::Redirect);
                        }
                        if resp.status.is_success() {
                            let header_ra = parse_retry_after(&resp.headers);
                            return match serde_json::from_slice::<MonitorResp>(&resp.body) {
                                Ok(m) => match m.status.as_deref() {
                                    Some("completed") => PolicyDecision::Ok(
                                        MonitorStep::Completed(m.resource_id.or(m.id)),
                                    ),
                                    Some("failed" | "deleteFailed" | "cancelled") => {
                                        PolicyDecision::Ok(MonitorStep::TerminalFail)
                                    }
                                    None if m.id.is_some() => {
                                        // reqwest auto-followed a 303 redirect to a DriveItem body.
                                        PolicyDecision::Ok(MonitorStep::Completed(m.id))
                                    }
                                    _ => PolicyDecision::Ok(MonitorStep::InProgress(header_ra)),
                                },
                                Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                                    "decode copy monitor JSON: {e}"
                                ))),
                            };
                        }
                        if resp.status == StatusCode::UNAUTHORIZED {
                            // If reqwest auto-followed a 303 redirect to an auth-protected Graph
                            // item URL, check whether the destination item is already present.
                            let err = super::classify_graph_status(
                                "GET(copy monitor)",
                                resp.status,
                                &resp.headers,
                                &resp.body,
                                false,
                            );
                            return PolicyDecision::Ok(MonitorStep::CheckDestination(err));
                        }
                        graph_error_decision(
                            "GET(copy monitor)",
                            resp.status,
                            &resp.headers,
                            &resp.body,
                            false,
                        )
                    },
                )
                .await?;

                match step {
                    MonitorStep::Completed(resource_id) => {
                        let bp = BackendPath::new(
                            init.dst_path.as_str(),
                            init.dst_path.clone(),
                            resource_id
                                .as_deref()
                                .and_then(|rid| encode_node_id(parent_drive_id.as_deref(), rid)),
                        );
                        if let Some((item, item_did)) = self.stat_graph_item_with_drive(&bp).await?
                        {
                            return finalize_copied(item, item_did).await;
                        }
                        if let Some((item, item_did)) =
                            self.stat_graph_item_with_drive(&dst_bp).await?
                        {
                            return finalize_copied(item, item_did).await;
                        }
                        break;
                    }
                    MonitorStep::Redirect => {
                        if let Some((item, item_did)) =
                            self.stat_graph_item_with_drive(&dst_bp).await?
                        {
                            return finalize_copied(item, item_did).await;
                        }
                        break;
                    }
                    MonitorStep::CheckDestination(err) => {
                        if let Some((item, item_did)) =
                            self.stat_graph_item_with_drive(&dst_bp).await?
                            && dst_before.as_deref() != Some(item.id.as_str())
                        {
                            return finalize_copied(item, item_did).await;
                        }
                        return Err(err);
                    }
                    MonitorStep::TerminalFail => return Ok(None),
                    MonitorStep::InProgress(retry_after) => {
                        let now = tokio::time::Instant::now();
                        if now >= deadline {
                            break;
                        }
                        let remaining = deadline.saturating_duration_since(now);
                        let wait = retry_after
                            .unwrap_or(poll_delay)
                            .min(self.inner.cfg.max_retry_delay)
                            .min(remaining);
                        if !wait.is_zero() {
                            self.inner.control_limiter.sleep(wait).await;
                        }
                        poll_delay = (poll_delay * 2).min(Duration::from_secs(2));
                    }
                }
            }

            if let Some((item, item_did)) = self.stat_graph_item_with_drive(&dst_bp).await? {
                return finalize_copied(item, item_did).await;
            }
            return Err(Error::timeout(
                "OneDrive server-side copy monitor timed out",
            ));
        }

        if let Some((item, item_did)) = self.stat_graph_item_with_drive(&dst_bp).await? {
            return finalize_copied(item, item_did).await;
        }
        Ok(None)
    }

    pub(super) async fn about_impl(&self) -> Result<Option<StorageQuota>> {
        let (_, _, body) = self
            .graph_request(
                "drive.get",
                Method::GET,
                &self.inner.drive_base,
                None,
                false,
            )
            .await?;
        #[derive(Deserialize)]
        struct DriveResp {
            #[serde(default)]
            id: Option<String>,
            quota: Option<GraphQuota>,
        }
        #[derive(Deserialize)]
        struct GraphQuota {
            total: Option<i64>,
            used: Option<i64>,
            remaining: Option<i64>,
            deleted: Option<i64>,
        }
        let parsed: DriveResp = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode drive quota JSON: {e}")))?;
        if let Some(id) = parsed
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let _ = self.inner.resolved_drive_id.set(id.to_string());
        }
        let Some(q) = parsed.quota else {
            return Ok(None);
        };
        Ok(Some(StorageQuota {
            total_bytes: q.total.and_then(|v| (v >= 0).then_some(v as u64)),
            used_bytes: q.used.map(|v| v.max(0) as u64),
            free_bytes: q.remaining.map(|v| v.max(0) as u64),
            trashed_bytes: q.deleted.map(|v| v.max(0) as u64),
        }))
    }
}

struct DirTask {
    raw_rel: String,
    item_id: Option<String>,
    drive_id: Option<String>,
}

/// `dst` is a plain file with `src`'s size, and their content hashes agree whenever both
/// report the same kind (SHA-256, SHA-1, or QuickXorHash).
fn graph_items_match(src: &GraphItem, dst: &GraphItem) -> bool {
    if src.is_folder() || dst.is_folder() || src.is_package() || dst.is_package() {
        return false;
    }
    let se = src.effective();
    let de = dst.effective();
    if se.size != de.size {
        return false;
    }
    let sh_opt = se.file.as_ref().and_then(|f| f.hashes.as_ref());
    let dh_opt = de.file.as_ref().and_then(|f| f.hashes.as_ref());
    match (sh_opt, dh_opt) {
        (Some(sh), Some(dh)) => {
            let differ = |a: Option<String>, b: Option<String>| matches!((a, b), (Some(a), Some(b)) if a != b);
            !differ(sh.sha256_hex(), dh.sha256_hex())
                && !differ(sh.sha1_hex(), dh.sha1_hex())
                && !differ(sh.quickxor_hex(), dh.quickxor_hex())
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onedrive::backend::{GraphFileFacet, GraphHashes};

    fn make_file_item(
        size: u64,
        sha256: Option<&str>,
        sha1: Option<&str>,
        qxh: Option<&str>,
    ) -> GraphItem {
        GraphItem {
            id: "id-1".into(),
            name: "f.bin".into(),
            size,
            e_tag: None,
            last_modified_date_time: None,
            file_system_info: None,
            folder: None,
            file: Some(GraphFileFacet {
                hashes: Some(GraphHashes {
                    sha256_hash: sha256.map(str::to_string),
                    sha1_hash: sha1.map(str::to_string),
                    quick_xor_hash: qxh.map(str::to_string),
                }),
            }),
            package: None,
            remote_item: None,
            parent_reference: None,
            download_url: None,
        }
    }

    #[test]
    fn graph_items_match_compares_quickxor_and_rejects_mismatch() {
        let q1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let q2 = "SgAAAAAAAAAAAAAAAQAAAAAAAAA=";
        let src = make_file_item(10, None, None, Some(q1));
        let dst_same = make_file_item(10, None, None, Some(q1));
        let dst_diff = make_file_item(10, None, None, Some(q2));
        let dst_diff_size = make_file_item(11, None, None, Some(q1));
        assert!(graph_items_match(&src, &dst_same));
        assert!(!graph_items_match(&src, &dst_diff));
        assert!(!graph_items_match(&src, &dst_diff_size));

        let mut folder = make_file_item(10, None, None, Some(q1));
        folder.folder = Some(serde_json::json!({}));
        assert!(!graph_items_match(&src, &folder));
    }
}
