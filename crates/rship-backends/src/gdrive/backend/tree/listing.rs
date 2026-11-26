//! Concurrent bounded-DFS Google Drive directory traversal, cycle-safe folder
//! shortcut tracking, and batched file shortcut resolution.

use futures::StreamExt;
use rship_core::backend::{DirPruner, EntryStream, ListOptions};
use rship_core::path::RelPath;
use rship_core::types::{Entry, EntryKind, NodeId};
use rship_core::{Error, ErrorKind, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

use crate::gdrive::changes::{join_raw_seg, shortcut_target_to_entry};
use crate::gdrive::query::{
    FOLDER_MIME, SHORTCUT_MIME, is_exportable_workspace_doc, parse_rfc3339_nanos,
};

use super::super::{DriveFile, GdriveBackend};
use super::{ProbeFileOutcome, RemoteChildrenPage, ResolvedDriveNode};

/// Maximum concurrent `files.list` page RPCs during directory traversal.
const MAX_LIST_CONCURRENCY: usize = 8;

/// Maximum concurrent `files.get` RPCs when resolving uncached file shortcuts
/// within a single listing page.
pub(in crate::gdrive::backend) const MAX_SHORTCUT_RESOLVE_CONCURRENCY: usize = 8;

/// Bounded output channel capacity for `list_with_options_impl`.
const LIST_CHANNEL_CAPACITY: usize = 128;

/// Soft cap on the DFS pending-page stack. When exceeded on extremely wide
/// trees, listing concurrency temporarily throttles to 1 (strict DFS) so the
/// stack drains depth-first instead of expanding parallel wide frontiers.
const PENDING_STACK_SOFT_CAP: usize = 16_384;

/// Persistent singly-linked ancestor chain shared via `Arc` across siblings so
/// exact path-cycle detection costs `O(depth)` memory instead of cloning a
/// `HashSet` per queued directory.
#[derive(Debug)]
pub(in crate::gdrive::backend) struct AncestorNode {
    dir_id: Arc<str>,
    parent: Option<Arc<AncestorNode>>,
}

impl AncestorNode {
    pub(in crate::gdrive::backend) fn root(dir_id: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            dir_id: dir_id.into(),
            parent: None,
        })
    }

    pub(in crate::gdrive::backend) fn push(
        parent: &Arc<Self>,
        dir_id: impl Into<Arc<str>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dir_id: dir_id.into(),
            parent: Some(Arc::clone(parent)),
        })
    }

    pub(in crate::gdrive::backend) fn contains(&self, target: &str) -> bool {
        let mut cur = Some(self);
        while let Some(node) = cur {
            if node.dir_id.as_ref() == target {
                return true;
            }
            cur = node.parent.as_deref();
        }
        false
    }
}

/// Ancestor-only directory cycle tracker.
///
/// Cycle detection checks ONLY the current root-to-node [`AncestorNode`] chain (plus
/// `"root"` <-> `actual_root_id` alias equivalence), so diamond folder shortcuts and
/// concurrent 8-way branches visiting the same shared directory from distinct parent
/// paths never block each other.
#[derive(Debug, Default)]
pub(in crate::gdrive::backend) struct BoundedDirTracker;

impl BoundedDirTracker {
    pub(in crate::gdrive::backend) fn new(_max_global: usize) -> Self {
        Self
    }

    /// Attempt to enter `target_id` from a directory whose ancestor chain is
    /// `ancestors`. Returns `false` if and only if entering would form a cycle
    /// back to an ancestor on the current traversal path.
    pub(in crate::gdrive::backend) fn try_enter(
        &mut self,
        ancestors: &AncestorNode,
        target_id: &str,
        actual_root_id: Option<&str>,
    ) -> bool {
        if ancestors.contains(target_id) {
            return false;
        }
        if let Some(actual) = actual_root_id
            && ((actual == target_id && ancestors.contains("root"))
                || (target_id == "root" && ancestors.contains(actual)))
        {
            return false;
        }
        true
    }
}

struct PendingDirPage {
    dir_id: String,
    dir_raw: String,
    dir_nfc: RelPath,
    ancestors: Arc<AncestorNode>,
    page_token: Option<String>,
    from_shortcut: bool,
}

pub(in crate::gdrive::backend) struct PendingFileShortcut {
    pub shortcut_id: String,
    pub shortcut_parent_id: String,
    pub shortcut_mtime_ns: i64,
    pub target_id: String,
    pub child_raw: String,
    pub child_nfc: RelPath,
}

impl GdriveBackend {
    pub(in crate::gdrive::backend) async fn list_with_options_impl(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let base_depth = prefix.segments().count();
        let effective_max_depth = options.effective_max_depth();

        if self.inner.cfg.use_changes_feed {
            let report = self.sync_changes().await?;
            if report.incomplete_search {
                return Err(Error::protocol(
                    "Google Drive returned incompleteSearch=true during incremental changes.list sync; blocking incomplete observation",
                ));
            }
            return self.stream_cached_entries(prefix, options).await;
        }

        let Some(start_resolved) = self.resolve_rel_path_raw(prefix, true).await? else {
            // Conformance invariant (`list_not_found_and_empty`): missing prefix -> empty stream.
            return Ok(Box::pin(futures::stream::empty()));
        };
        if start_resolved.effective_mime() != FOLDER_MIME {
            let entry = start_resolved.into_entry(self, prefix.as_str(), prefix.clone());
            return Ok(Box::pin(futures::stream::once(async move { Ok(entry) })));
        }
        if effective_max_depth == Some(0) {
            return Ok(Box::pin(futures::stream::empty()));
        }

        let from_shortcut = start_resolved.node.mime_type == SHORTCUT_MIME;
        let start_id = start_resolved.content_id().to_string();
        Ok(self.stream_remote_dir_from_id(
            start_id,
            prefix.as_str().to_string(),
            prefix.clone(),
            base_depth,
            effective_max_depth,
            from_shortcut,
            options.dir_pruner().cloned(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::gdrive::backend) fn stream_remote_dir_from_id(
        &self,
        start_id: String,
        start_raw: String,
        start_nfc: RelPath,
        base_depth: usize,
        effective_max_depth: Option<usize>,
        from_shortcut: bool,
        pruner: Option<DirPruner>,
    ) -> EntryStream {
        if effective_max_depth == Some(0) {
            return Box::pin(futures::stream::empty());
        }

        let (tx, rx) = mpsc::channel::<Result<Entry>>(LIST_CHANNEL_CAPACITY);
        let backend = self.clone();
        let root_id = self.inner.cfg.effective_root_id().to_string();

        tokio::spawn(async move {
            let mut tracker = BoundedDirTracker::new(0);
            let root_ancestors = AncestorNode::root(root_id.as_str());
            let start_ancestors = if start_id == root_id {
                root_ancestors
            } else {
                AncestorNode::push(&root_ancestors, start_id.as_str())
            };

            let mut pending_stack: Vec<PendingDirPage> = vec![PendingDirPage {
                dir_id: start_id,
                dir_raw: start_raw,
                dir_nfc: start_nfc,
                ancestors: start_ancestors,
                page_token: None,
                from_shortcut,
            }];

            type TreePageItem = (PendingDirPage, Result<RemoteChildrenPage>);
            let mut in_flight: tokio::task::JoinSet<TreePageItem> = tokio::task::JoinSet::new();

            loop {
                if tx.is_closed() {
                    in_flight.abort_all();
                    return;
                }

                if in_flight.is_empty()
                    && !pending_stack.is_empty()
                    && tx.capacity() == 0
                    && tx.reserve().await.is_err()
                {
                    return;
                }

                let target_concurrency = if tx.capacity() == 0 {
                    0
                } else if pending_stack.len() >= PENDING_STACK_SOFT_CAP
                    || tx.capacity() < LIST_CHANNEL_CAPACITY / 2
                {
                    1
                } else {
                    MAX_LIST_CONCURRENCY
                };

                while in_flight.len() < target_concurrency {
                    let Some(work) = pending_stack.pop() else {
                        break;
                    };
                    let b = backend.clone();
                    in_flight.spawn(async move {
                        let res = b
                            .list_children_remote_page(&work.dir_id, work.page_token.as_deref())
                            .await;
                        (work, res)
                    });
                }

                if in_flight.is_empty() {
                    break;
                }

                let joined = tokio::select! {
                    biased;
                    _ = tx.closed() => {
                        in_flight.abort_all();
                        return;
                    }
                    next = in_flight.join_next() => match next {
                        Some(j) => j,
                        None => break,
                    }
                };

                let (work, page_res) = match joined {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!(
                                "gdrive list task failed: {e}"
                            ))))
                            .await;
                        in_flight.abort_all();
                        return;
                    }
                };
                let page = match page_res {
                    Ok(p) => p,
                    Err(e) => {
                        if work.from_shortcut
                            && matches!(e.kind, ErrorKind::PermissionDenied | ErrorKind::NotFound)
                        {
                            warn!(
                                dir_id = %work.dir_id,
                                path = %work.dir_nfc,
                                error = %e,
                                "skipping broken or inaccessible folder shortcut target during listing"
                            );
                            continue;
                        }
                        if e.is_not_found() {
                            backend.evict_cached_dir(&work.dir_id).await;
                        }
                        let _ = tx.send(Err(e)).await;
                        in_flight.abort_all();
                        return;
                    }
                };
                if page.incomplete_search {
                    let _ = tx
                        .send(Err(Error::protocol(
                            "Google Drive returned incompleteSearch=true during listing; blocking incomplete observation",
                        )))
                        .await;
                    in_flight.abort_all();
                    return;
                }

                if work.dir_id == "root"
                    && !backend.inner.cfg.shared_with_me
                    && backend.inner.cfg.effective_root_id() == "root"
                    && backend.inner.actual_root_id.get().is_none()
                {
                    for file in &page.files {
                        if let Some(raw_parent) = file.parents.first() {
                            backend.record_root_alias_id(raw_parent);
                            break;
                        }
                    }
                }
                let actual_root_id = backend.inner.actual_root_id.get().map(String::as_str);

                let mut batch_to_cache: Vec<DriveFile> = Vec::with_capacity(page.files.len());
                let mut pending_file_shortcuts: Vec<PendingFileShortcut> = Vec::new();
                let mut discovered_subdirs: Vec<PendingDirPage> = Vec::new();

                for file in page.files {
                    if tx.is_closed() {
                        in_flight.abort_all();
                        return;
                    }
                    if (!backend.inner.cfg.trashed_only && file.trashed)
                        || is_exportable_workspace_doc(&file.mime_type)
                    {
                        continue;
                    }

                    let child_raw = join_raw_seg(&work.dir_raw, &file.name);
                    let Ok(child_nfc) = work.dir_nfc.join(&file.name) else {
                        warn!(name = %file.name, "skipping Drive entry with invalid relative path segment");
                        continue;
                    };
                    let rel_depth = child_nfc.segments().count().saturating_sub(base_depth);
                    if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                        continue;
                    }
                    let can_descend = effective_max_depth.is_none_or(|limit| rel_depth < limit);

                    // Handle Google Drive Shortcuts with strict loop detection & ID separation!
                    if file.mime_type == SHORTCUT_MIME {
                        let Some(sd) = &file.shortcut_details else {
                            continue;
                        };
                        backend.record_shortcut_target(
                            &file.id,
                            &sd.target_id,
                            &sd.target_mime_type,
                        );
                        let shortcut_mtime = file
                            .modified_time
                            .as_deref()
                            .map(parse_rfc3339_nanos)
                            .unwrap_or(0);

                        if sd.target_mime_type == FOLDER_MIME {
                            if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                continue;
                            }
                            if !tracker.try_enter(&work.ancestors, &sd.target_id, actual_root_id) {
                                warn!(
                                    shortcut_id = %file.id,
                                    target_id = %sd.target_id,
                                    path = %child_nfc,
                                    "detected cyclic Google Drive folder shortcut; breaking loop"
                                );
                                continue;
                            }
                            let dir_entry = Entry {
                                node_id: Some(NodeId(file.id.clone())),
                                parent_id: Some(NodeId(work.dir_id.clone())),
                                raw_path: rship_core::types::raw_path_override(
                                    &child_nfc, &child_raw,
                                ),
                                nfc_path: child_nfc.clone(),
                                kind: EntryKind::Directory,
                                size: 0,
                                mtime_ns: shortcut_mtime,
                                ctime_ns: None,
                                etag: None,
                                checksum: None,
                            };
                            if tx.send(Ok(dir_entry)).await.is_err() {
                                in_flight.abort_all();
                                return;
                            }
                            if can_descend {
                                discovered_subdirs.push(PendingDirPage {
                                    dir_id: sd.target_id.clone(),
                                    dir_raw: child_raw,
                                    dir_nfc: child_nfc,
                                    ancestors: AncestorNode::push(
                                        &work.ancestors,
                                        sd.target_id.as_str(),
                                    ),
                                    page_token: None,
                                    from_shortcut: true,
                                });
                            }
                        } else if sd.target_mime_type == SHORTCUT_MIME {
                            match backend.resolve_shortcut_target(file.clone()).await {
                                Ok(Some(resolved_target)) => {
                                    let resolved_is_dir = resolved_target.mime_type == FOLDER_MIME;
                                    if resolved_is_dir {
                                        if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                            continue;
                                        }
                                        if !tracker.try_enter(
                                            &work.ancestors,
                                            &resolved_target.id,
                                            actual_root_id,
                                        ) {
                                            continue;
                                        }
                                    }
                                    let entry = ResolvedDriveNode {
                                        node: file,
                                        target: Some(resolved_target.clone()),
                                    }
                                    .into_entry(
                                        &backend,
                                        child_raw.clone(),
                                        child_nfc.clone(),
                                    );
                                    if tx.send(Ok(entry)).await.is_err() {
                                        in_flight.abort_all();
                                        return;
                                    }
                                    if resolved_is_dir && can_descend {
                                        discovered_subdirs.push(PendingDirPage {
                                            dir_id: resolved_target.id.clone(),
                                            dir_raw: child_raw,
                                            dir_nfc: child_nfc,
                                            ancestors: AncestorNode::push(
                                                &work.ancestors,
                                                resolved_target.id.as_str(),
                                            ),
                                            page_token: None,
                                            from_shortcut: true,
                                        });
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    let _ = tx.send(Err(e)).await;
                                    in_flight.abort_all();
                                    return;
                                }
                            }
                        } else if !is_exportable_workspace_doc(&sd.target_mime_type) {
                            pending_file_shortcuts.push(PendingFileShortcut {
                                shortcut_id: file.id,
                                shortcut_parent_id: work.dir_id.clone(),
                                shortcut_mtime_ns: shortcut_mtime,
                                target_id: sd.target_id.clone(),
                                child_raw,
                                child_nfc,
                            });
                        }
                        continue;
                    }

                    let is_dir = file.mime_type == FOLDER_MIME;
                    if is_dir {
                        backend.insert_dir_cache(&work.dir_id, &file.name, &file.id);
                        if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                            continue;
                        }
                    }
                    let entry =
                        backend.drive_file_to_entry(&file, child_raw.clone(), child_nfc.clone());
                    let next_subdir = if can_descend
                        && is_dir
                        && tracker.try_enter(&work.ancestors, &file.id, actual_root_id)
                    {
                        Some(PendingDirPage {
                            dir_id: file.id.clone(),
                            dir_raw: child_raw,
                            dir_nfc: child_nfc,
                            ancestors: AncestorNode::push(&work.ancestors, file.id.as_str()),
                            page_token: None,
                            from_shortcut: work.from_shortcut,
                        })
                    } else {
                        None
                    };
                    if !is_dir && !backend.inner.cfg.use_changes_feed && !work.from_shortcut {
                        batch_to_cache.push(file);
                    }

                    if tx.send(Ok(entry)).await.is_err() {
                        in_flight.abort_all();
                        return;
                    }

                    if let Some(subdir) = next_subdir {
                        discovered_subdirs.push(subdir);
                    }
                }

                if tx.is_closed() {
                    in_flight.abort_all();
                    return;
                }

                if !batch_to_cache.is_empty()
                    && !backend.inner.cfg.use_changes_feed
                    && !work.from_shortcut
                {
                    backend
                        .cache_nodes_batch(&batch_to_cache, &work.dir_id)
                        .await;
                }

                if !pending_file_shortcuts.is_empty()
                    && !resolve_and_emit_file_shortcuts(&backend, pending_file_shortcuts, &tx).await
                {
                    in_flight.abort_all();
                    return;
                }

                // Push the continuation page of the current directory BEFORE newly
                // discovered subdirectories so DFS finishes this page's subtrees
                // first, bounding pending stack memory to `O(depth * page_size)`.
                if let Some(next_tok) = page.next_page_token {
                    pending_stack.push(PendingDirPage {
                        dir_id: work.dir_id,
                        dir_raw: work.dir_raw,
                        dir_nfc: work.dir_nfc,
                        ancestors: work.ancestors,
                        page_token: Some(next_tok),
                        from_shortcut: work.from_shortcut,
                    });
                }
                for subdir in discovered_subdirs.into_iter().rev() {
                    pending_stack.push(subdir);
                }
            }
        });

        crate::common::rx_to_entry_stream(rx)
    }
}

/// Resolve all file shortcuts discovered on a single listing page:
/// 1. Deduplicate repeated `target_id`s within the page.
/// 2. Batch-check local inventory cache via `get_nodes_batch` before issuing
///    any remote RPCs.
/// 3. Resolve remaining uncached targets concurrently with bounded
///    `buffer_unordered(MAX_SHORTCUT_RESOLVE_CONCURRENCY)`, tolerating 403/404 on
///    broken or inaccessible targets and following shortcut chains up to 8 hops.
///
/// Returns `false` if the downstream stream closed or an unrecoverable error
/// was emitted, signaling the caller to abort remaining traversal tasks.
pub(in crate::gdrive::backend) async fn resolve_and_emit_file_shortcuts(
    backend: &GdriveBackend,
    shortcuts: Vec<PendingFileShortcut>,
    tx: &mpsc::Sender<Result<Entry>>,
) -> bool {
    if shortcuts.is_empty() || tx.is_closed() {
        return !tx.is_closed();
    }

    let mut unique_ids: Vec<String> = Vec::new();
    let mut by_target: HashMap<String, Vec<PendingFileShortcut>> = HashMap::new();
    for sc in shortcuts {
        match by_target.entry(sc.target_id.clone()) {
            std::collections::hash_map::Entry::Occupied(mut occ) => {
                occ.get_mut().push(sc);
            }
            std::collections::hash_map::Entry::Vacant(vac) => {
                unique_ids.push(vac.key().clone());
                vac.insert(vec![sc]);
            }
        }
    }

    let scope = backend.scope();
    let cached_nodes = match backend
        .inner
        .inventory
        .get_nodes_batch(&scope.remote_name, &scope.corpus_id, &unique_ids)
        .await
    {
        Ok(map) => map,
        Err(e) => {
            warn!(
                error = %e,
                "gdrive inventory batch lookup failed during shortcut resolution; falling back to remote"
            );
            HashMap::new()
        }
    };

    let mut missing_ids: Vec<String> = Vec::new();
    for target_id in unique_ids {
        if let Some(node) = cached_nodes.get(&target_id)
            && node.kind != EntryKind::Symlink
        {
            if let Some(occurrences) = by_target.remove(&target_id)
                && (backend.inner.cfg.trashed_only || !node.trashed)
            {
                let is_folder = node.kind == EntryKind::Directory;
                for occ in occurrences {
                    let entry = shortcut_target_to_entry(
                        &occ.shortcut_id,
                        Some(&occ.shortcut_parent_id),
                        occ.shortcut_mtime_ns,
                        is_folder,
                        Some(node),
                        occ.child_raw,
                        occ.child_nfc,
                    );
                    if tx.send(Ok(entry)).await.is_err() {
                        return false;
                    }
                }
            }
        } else {
            missing_ids.push(target_id);
        }
    }

    if missing_ids.is_empty() {
        return true;
    }

    let mut fetches = futures::stream::iter(missing_ids.into_iter().map(|target_id| {
        let b = backend.clone();
        async move {
            let res = match b.get_file_by_id_tolerating_403(&target_id).await {
                Ok(ProbeFileOutcome::Found(f)) => {
                    let f = *f;
                    if f.mime_type == SHORTCUT_MIME {
                        b.resolve_shortcut_target(f).await
                    } else if (!b.inner.cfg.trashed_only && f.trashed)
                        || is_exportable_workspace_doc(&f.mime_type)
                    {
                        Ok(None)
                    } else {
                        Ok(Some(f))
                    }
                }
                Ok(ProbeFileOutcome::NotFound | ProbeFileOutcome::Forbidden) => {
                    warn!(
                        target_id = %target_id,
                        "skipping broken or inaccessible file shortcut target"
                    );
                    Ok(None)
                }
                Err(e) => Err(e),
            };
            (target_id, res)
        }
    }))
    .buffer_unordered(MAX_SHORTCUT_RESOLVE_CONCURRENCY);

    loop {
        let next = tokio::select! {
            biased;
            _ = tx.closed() => return false,
            item = fetches.next() => item,
        };
        let Some((target_id, res)) = next else {
            break;
        };
        match res {
            Ok(Some(target)) => {
                if let Some(occurrences) = by_target.remove(&target_id) {
                    let target_is_dir = target.mime_type == FOLDER_MIME;
                    let target_mtime = target
                        .modified_time
                        .as_deref()
                        .map(parse_rfc3339_nanos)
                        .unwrap_or(0);
                    let target_checksum = if target_is_dir {
                        None
                    } else {
                        target.best_checksum()
                    };
                    for occ in occurrences {
                        let entry = Entry {
                            node_id: Some(NodeId(occ.shortcut_id)),
                            parent_id: Some(NodeId(occ.shortcut_parent_id)),
                            raw_path: rship_core::types::raw_path_override(
                                &occ.child_nfc,
                                &occ.child_raw,
                            ),
                            nfc_path: occ.child_nfc,
                            kind: if target_is_dir {
                                EntryKind::Directory
                            } else {
                                EntryKind::File
                            },
                            size: if target_is_dir { 0 } else { target.size },
                            mtime_ns: if target_mtime != 0 {
                                target_mtime
                            } else {
                                occ.shortcut_mtime_ns
                            },
                            ctime_ns: None,
                            etag: if target_is_dir {
                                None
                            } else {
                                target.md5_checksum.clone()
                            },
                            checksum: target_checksum.clone(),
                        };
                        if tx.send(Ok(entry)).await.is_err() {
                            return false;
                        }
                    }
                }
            }
            Ok(None) => {
                by_target.remove(&target_id);
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return false;
            }
        }
    }

    true
}
