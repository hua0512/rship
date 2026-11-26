//! Google Drive incremental `changes.list` inventory sync and ID-graph projection.

use rship_core::backend::{EntryStream, ListOptions};
use rship_core::path::RelPath;
use rship_core::state::{DeltaChangeBatch, DeltaNodeRecord, DeltaScope};
use rship_core::types::{Entry, EntryKind, NodeId};
use rship_core::{Error, ErrorKind, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::mpsc;
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

use crate::gdrive::changes::{
    ChangesSyncReport, MAX_SHORTCUT_CHAIN_HOPS, ShortcutTargetKind, decode_shortcut_ref,
    delta_node_to_entry, encode_shortcut_ref, join_raw_seg, project_graph_to_entries,
    shortcut_target_to_entry,
};
use crate::gdrive::query::{
    FOLDER_MIME, SHORTCUT_MIME, is_exportable_workspace_doc, parse_rfc3339_nanos,
};

use super::tree::listing::{
    AncestorNode, BoundedDirTracker, PendingFileShortcut, resolve_and_emit_file_shortcuts,
};
use super::tree::{ChangesPageOutcome, ProbeFileOutcome, ResolvedDriveNode};
use super::{DriveChange, DriveFile, GdriveBackend, MAX_ANCESTOR_HOPS};

const INVENTORY_FLUSH_BATCH: usize = 2_000;
const MAX_ANCESTRY_CACHE_ENTRIES: usize = 16_384;
const MAX_CRAWL_CONCURRENCY: usize = 8;

impl GdriveBackend {
    /// Crawl `seed_dirs` concurrently (8-way BFS). When `flush_scope` is `Some(scope)`
    /// (used by `bootstrap_inventory`), upserts are flushed in `INVENTORY_FLUSH_BATCH`
    /// chunks with `new_start_page_token = None` to bound RAM. When `flush_scope` is
    /// `None` (used by `sync_changes`), nothing is written to SQLite during the crawl so
    /// an incomplete/failed crawl never leaves `was_known.is_some()` directories behind.
    async fn crawl_subtrees(
        &self,
        seed_dirs: Vec<String>,
        flush_scope: Option<&DeltaScope>,
        upserts: &mut HashMap<String, DeltaNodeRecord>,
        seen_upserted_ids: &mut HashSet<String>,
        report: &mut ChangesSyncReport,
    ) -> Result<()> {
        if seed_dirs.is_empty() {
            return Ok(());
        }

        let mut visited_dirs: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        for dir_id in seed_dirs {
            if visited_dirs.insert(dir_id.clone()) {
                queue.push_back(dir_id);
            }
        }

        type BfsListItem = (String, Result<(Vec<DriveFile>, bool)>);
        let mut in_flight: tokio::task::JoinSet<BfsListItem> = tokio::task::JoinSet::new();

        loop {
            while in_flight.len() < MAX_CRAWL_CONCURRENCY {
                let Some(dir_id) = queue.pop_front() else {
                    break;
                };
                let b = self.clone();
                in_flight.spawn(async move {
                    let res = b.list_children_remote(&dir_id).await;
                    (dir_id, res)
                });
            }
            let Some(joined) = in_flight.join_next().await else {
                break;
            };
            let (dir_id, res) = joined
                .map_err(|e| Error::protocol(format!("gdrive inventory crawl task failed: {e}")))?;
            let (children, incomplete) = match res {
                Ok(v) => v,
                Err(e) => {
                    in_flight.abort_all();
                    return Err(e);
                }
            };
            if flush_scope.is_some() {
                report.pages_processed += 1;
            } else {
                report.crawled_moved_in_dirs += 1;
            }
            if incomplete {
                report.incomplete_search = true;
            }
            for f in children {
                if (!self.inner.cfg.trashed_only && f.trashed)
                    || is_exportable_workspace_doc(&f.mime_type)
                {
                    continue;
                }
                if f.mime_type == SHORTCUT_MIME {
                    let Some(sd) = &f.shortcut_details else {
                        continue;
                    };
                    if sd.target_mime_type != FOLDER_MIME
                        && is_exportable_workspace_doc(&sd.target_mime_type)
                    {
                        continue;
                    }
                    self.record_shortcut_target(&f.id, &sd.target_id, &sd.target_mime_type);
                }
                let rec = self.drive_file_to_node(&f, Some(&dir_id));
                if rec.kind == EntryKind::Directory {
                    self.insert_dir_cache(&dir_id, &f.name, &f.id);
                    if visited_dirs.insert(rec.file_id.clone()) {
                        queue.push_back(rec.file_id.clone());
                    }
                }
                seen_upserted_ids.insert(rec.file_id.clone());
                upserts.insert(rec.file_id.clone(), rec);

                if let Some(scope) = flush_scope
                    && upserts.len() >= INVENTORY_FLUSH_BATCH
                {
                    let batch: Vec<DeltaNodeRecord> = upserts.drain().map(|(_, v)| v).collect();
                    report.upserted_nodes += batch.len();
                    self.inner
                        .inventory
                        .apply_change_batch(
                            scope,
                            DeltaChangeBatch {
                                upserts: batch,
                                remove_file_ids: vec![],
                                evict_subtree_root_ids: vec![],
                                new_start_page_token: None,
                                updated_at: self.inner.clock.now_unix_secs(),
                            },
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn bootstrap_inventory(&self) -> Result<ChangesSyncReport> {
        let scope = self.scope();
        let start_token = self.get_start_page_token().await?;

        // Clear any stale inventory before streaming chunks into SQLite so peak RAM
        // stays O(INVENTORY_FLUSH_BATCH) even on million-file Drives.
        self.inner.inventory.clear_inventory(&scope).await?;

        let mut report = ChangesSyncReport {
            bootstrapped: true,
            ..Default::default()
        };
        let mut upserts: HashMap<String, DeltaNodeRecord> =
            HashMap::with_capacity(INVENTORY_FLUSH_BATCH);
        let mut seen_upserted_ids: HashSet<String> = HashSet::new();
        self.crawl_subtrees(
            vec![scope.root_id.clone()],
            Some(&scope),
            &mut upserts,
            &mut seen_upserted_ids,
            &mut report,
        )
        .await?;

        let batch: Vec<DeltaNodeRecord> = upserts.into_values().collect();
        report.upserted_nodes += batch.len();
        let now = self.inner.clock.now_unix_secs();

        // Observation Completeness Gate: do NOT persist `startPageToken` if Drive
        // reported `incompleteSearch=true`!
        let token_to_commit = if report.incomplete_search {
            None
        } else {
            report.new_start_page_token = Some(start_token.clone());
            Some(start_token)
        };

        if !batch.is_empty() || token_to_commit.is_some() {
            self.inner
                .inventory
                .apply_change_batch(
                    &scope,
                    DeltaChangeBatch {
                        upserts: batch,
                        remove_file_ids: vec![],
                        evict_subtree_root_ids: vec![],
                        new_start_page_token: token_to_commit,
                        updated_at: now,
                    },
                )
                .await?;
        }

        Ok(report)
    }

    /// Incrementally replay Google Drive `changes.list` into `gdrive_nodes`:
    /// - Automatically resets & re-bootstraps on expired `pageToken` (`410`/`400`).
    /// - Handles `removed: true` with empty `file`.
    /// - Handles `trashed: true` (evicting entire descendant subtrees for real folders).
    /// - Tracks file & folder shortcuts as `EntryKind::Symlink` nodes.
    /// - Detects folders moved **into** `root_id` and recursively crawls their children
    ///   without flushing mid-crawl (`incompleteSearch=true` aborts DB mutation atomically).
    /// - Detects folders moved **out of** `root_id` and recursively evicts their subtrees.
    pub async fn sync_changes(&self) -> Result<ChangesSyncReport> {
        let scope = self.scope();
        let Some(mut page_token) = self.inner.inventory.get_change_token(&scope).await? else {
            return self.bootstrap_inventory().await;
        };

        let mut report = ChangesSyncReport::default();
        let mut all_changes: Vec<DriveChange> = Vec::new();
        let final_new_token: Option<String> = loop {
            match self.fetch_changes_page(&page_token).await? {
                ChangesPageOutcome::TokenExpired => {
                    warn!(
                        remote = %scope.remote_name,
                        "Google Drive changes pageToken expired (410/400); clearing inventory and re-bootstrapping"
                    );
                    self.inner.inventory.clear_inventory(&scope).await?;
                    return self.bootstrap_inventory().await;
                }
                ChangesPageOutcome::Page(page) => {
                    report.pages_processed += 1;
                    all_changes.extend(page.changes);

                    if let Some(next) = page.next_page_token
                        && !next.is_empty()
                    {
                        page_token = next;
                        continue;
                    }
                    break page.new_start_page_token;
                }
            }
        };

        // Query ONLY the changed `file_id`s from persistent inventory (O(delta) instead of
        // loading the entire million-node Drive graph into RAM).
        let mut unique_changed_ids: Vec<String> = Vec::with_capacity(all_changes.len());
        {
            let mut seen_ids = HashSet::with_capacity(all_changes.len());
            for ch in &all_changes {
                if seen_ids.insert(ch.file_id.clone()) {
                    unique_changed_ids.push(ch.file_id.clone());
                }
            }
        }
        let mut existing_nodes: HashMap<String, DeltaNodeRecord> =
            HashMap::with_capacity(unique_changed_ids.len());
        for chunk in unique_changed_ids.chunks(INVENTORY_FLUSH_BATCH) {
            let part = self
                .inner
                .inventory
                .get_nodes_batch(&scope.remote_name, &scope.corpus_id, chunk)
                .await?;
            existing_nodes.extend(part);
        }

        let (shared_top_files, shared_top_ids, shared_top_incomplete) =
            if self.inner.cfg.shared_with_me {
                let (files, inc) = self.list_children_remote(&scope.root_id).await?;
                let mut ids = HashSet::with_capacity(files.len());
                for f in &files {
                    if (self.inner.cfg.trashed_only || !f.trashed)
                        && !is_exportable_workspace_doc(&f.mime_type)
                    {
                        ids.insert(f.id.clone());
                    }
                }
                (files, ids, inc)
            } else {
                (Vec::new(), HashSet::new(), false)
            };
        if shared_top_incomplete {
            report.incomplete_search = true;
        }

        // Pre-populate updated parent pointers from all non-removed changes so a child
        // appearing before its newly-moved parent in the same batch resolves cleanly.
        let mut batch_parents: HashMap<String, Option<String>> = HashMap::new();
        for ch in &all_changes {
            if ch.removed {
                batch_parents.insert(ch.file_id.clone(), None);
            } else if let Some(f) = &ch.file {
                if !self.inner.cfg.trashed_only && f.trashed {
                    batch_parents.insert(f.id.clone(), None);
                } else if self.inner.cfg.shared_with_me
                    && !f.trashed
                    && (f.shared_with_me_time.is_some() || shared_top_ids.contains(&f.id))
                {
                    batch_parents.insert(f.id.clone(), Some(scope.root_id.clone()));
                } else {
                    batch_parents.insert(f.id.clone(), f.parents.first().cloned());
                }
            }
        }
        let mut ancestry_cache: HashMap<String, Option<String>> = HashMap::new();

        let mut upserts: HashMap<String, DeltaNodeRecord> = HashMap::new();
        let mut seen_upserted_ids: HashSet<String> = HashSet::new();
        let mut remove_file_ids: Vec<String> = Vec::new();
        let mut evict_subtree_root_ids: Vec<String> = Vec::new();
        let mut moved_in_dirs: Vec<String> = Vec::new();
        let mut suppressed_ids: HashSet<String> = HashSet::new();

        for ch in all_changes {
            let was_known = existing_nodes.get(&ch.file_id);

            // Case 1: `removed: true` (often accompanied by `file: null`!)
            if ch.removed || ch.file.is_none() {
                self.invalidate_dir_cache_for_id(&ch.file_id);
                if was_known.is_some_and(|n| n.kind == EntryKind::Directory) {
                    evict_subtree_root_ids.push(ch.file_id.clone());
                    report.evicted_subtrees += 1;
                } else {
                    remove_file_ids.push(ch.file_id.clone());
                    report.removed_nodes += 1;
                }
                upserts.remove(&ch.file_id);
                seen_upserted_ids.remove(&ch.file_id);
                suppressed_ids.insert(ch.file_id);
                continue;
            }

            let file = ch.file.unwrap();

            // Case 2: Trashed item -> evict subtree for directories, remove file/shortcut otherwise.
            if !self.inner.cfg.trashed_only && file.trashed {
                self.invalidate_dir_cache_for_id(&file.id);
                if file.mime_type == FOLDER_MIME
                    || was_known.is_some_and(|n| n.kind == EntryKind::Directory)
                {
                    evict_subtree_root_ids.push(file.id.clone());
                    report.evicted_subtrees += 1;
                } else {
                    remove_file_ids.push(file.id.clone());
                    report.removed_nodes += 1;
                }
                upserts.remove(&file.id);
                seen_upserted_ids.remove(&file.id);
                suppressed_ids.insert(file.id);
                continue;
            }

            // Case 3: Export-only Workspace docs (and shortcuts to them) are excluded.
            let is_workspace_doc_shortcut = file.mime_type == SHORTCUT_MIME
                && file.shortcut_details.as_ref().is_none_or(|sd| {
                    sd.target_mime_type != FOLDER_MIME
                        && is_exportable_workspace_doc(&sd.target_mime_type)
                });
            if is_exportable_workspace_doc(&file.mime_type) || is_workspace_doc_shortcut {
                self.invalidate_dir_cache_for_id(&file.id);
                if was_known.is_some() {
                    remove_file_ids.push(file.id.clone());
                    report.removed_nodes += 1;
                }
                suppressed_ids.insert(file.id);
                continue;
            }

            // Case 4: Live file/folder/shortcut -> check whether its current ancestry leads to `scope.root_id`!
            let mut in_scope = self
                .is_under_root(
                    &scope,
                    &file.id,
                    file.parents.first().map(String::as_str),
                    &scope.root_id,
                    &batch_parents,
                    &mut ancestry_cache,
                )
                .await?;
            let mut fallback_parent: Option<&str> = None;
            if !in_scope
                && self.inner.cfg.shared_with_me
                && (file.shared_with_me_time.is_some() || shared_top_ids.contains(&file.id))
            {
                in_scope = true;
                fallback_parent = Some(scope.root_id.as_str());
            }

            if !in_scope {
                // Moved OUT of tracked root -> evict entire subtree if it was tracked!
                self.invalidate_dir_cache_for_id(&file.id);
                if let Some(prev) = was_known {
                    if prev.kind == EntryKind::Directory || file.mime_type == FOLDER_MIME {
                        evict_subtree_root_ids.push(file.id.clone());
                        report.evicted_subtrees += 1;
                    } else {
                        remove_file_ids.push(file.id.clone());
                        report.removed_nodes += 1;
                    }
                }
                upserts.remove(&file.id);
                seen_upserted_ids.remove(&file.id);
                continue;
            }

            // Inside tracked root!
            if file.mime_type == SHORTCUT_MIME
                && let Some(sd) = &file.shortcut_details
            {
                self.record_shortcut_target(&file.id, &sd.target_id, &sd.target_mime_type);
            }
            if file.mime_type == FOLDER_MIME {
                self.invalidate_dir_cache_for_id(&file.id);
            }
            let rec = self.drive_file_to_node(&file, fallback_parent);
            let is_dir = rec.kind == EntryKind::Directory;
            seen_upserted_ids.insert(rec.file_id.clone());
            upserts.insert(rec.file_id.clone(), rec);

            // If this is a real directory that was NOT previously tracked (newly created or
            // moved IN from outside `root_id`), crawl its subtree because Drive's
            // `changes.list` does NOT emit change events for pre-existing descendants!
            if is_dir && was_known.is_none() {
                moved_in_dirs.push(file.id.clone());
            }
        }

        if self.inner.cfg.shared_with_me && !shared_top_files.is_empty() {
            let mut dir_ids_to_check: Vec<String> = Vec::new();
            for f in &shared_top_files {
                if f.mime_type == FOLDER_MIME
                    && (self.inner.cfg.trashed_only || !f.trashed)
                    && !suppressed_ids.contains(&f.id)
                    && !upserts.contains_key(&f.id)
                    && !existing_nodes.contains_key(&f.id)
                {
                    dir_ids_to_check.push(f.id.clone());
                }
            }
            let known_shared_dirs = if dir_ids_to_check.is_empty() {
                HashMap::new()
            } else {
                self.inner
                    .inventory
                    .get_nodes_batch(&scope.remote_name, &scope.corpus_id, &dir_ids_to_check)
                    .await?
            };
            for f in shared_top_files {
                if (!self.inner.cfg.trashed_only && f.trashed)
                    || is_exportable_workspace_doc(&f.mime_type)
                    || suppressed_ids.contains(&f.id)
                    || upserts.contains_key(&f.id)
                {
                    continue;
                }
                if f.mime_type == SHORTCUT_MIME {
                    let Some(sd) = &f.shortcut_details else {
                        continue;
                    };
                    if sd.target_mime_type != FOLDER_MIME
                        && is_exportable_workspace_doc(&sd.target_mime_type)
                    {
                        continue;
                    }
                    self.record_shortcut_target(&f.id, &sd.target_id, &sd.target_mime_type);
                }
                let rec = self.drive_file_to_node(&f, Some(scope.root_id.as_str()));
                let is_dir = rec.kind == EntryKind::Directory;
                let dir_was_known =
                    existing_nodes.contains_key(&f.id) || known_shared_dirs.contains_key(&f.id);
                seen_upserted_ids.insert(rec.file_id.clone());
                upserts.insert(rec.file_id.clone(), rec);
                if is_dir && !dir_was_known {
                    moved_in_dirs.push(f.id);
                }
            }
        }

        // Prune any directory that was moved-in earlier in the batch and later
        // removed, trashed, or moved out before crawling its subtree.
        moved_in_dirs.retain(|id| upserts.contains_key(id));

        // Crawl moved-in directories WITHOUT flushing mid-crawl (`flush_scope = None`).
        self.crawl_subtrees(
            moved_in_dirs,
            None,
            &mut upserts,
            &mut seen_upserted_ids,
            &mut report,
        )
        .await?;

        let upsert_vec: Vec<DeltaNodeRecord> = upserts.into_values().collect();
        report.upserted_nodes = seen_upserted_ids.len();

        // Atomic Observation Completeness Gate: when `incompleteSearch=true` occurred,
        // skip `apply_change_batch` completely so `gdrive_nodes` and `change_tokens`
        // remain at the prior atomic checkpoint and moved-in directories will be
        // re-crawled on the next `sync_changes` retry.
        if report.incomplete_search {
            return Ok(report);
        }

        report.new_start_page_token = final_new_token.clone();
        self.inner
            .inventory
            .apply_change_batch(
                &scope,
                DeltaChangeBatch {
                    upserts: upsert_vec,
                    remove_file_ids,
                    evict_subtree_root_ids,
                    new_start_page_token: final_new_token,
                    updated_at: self.inner.clock.now_unix_secs(),
                },
            )
            .await?;

        Ok(report)
    }

    /// Project the cached `gdrive_nodes` ID graph into [`Entry`] items.
    pub async fn project_cached_entries(
        &self,
        prefix: &RelPath,
        recursive: bool,
    ) -> Result<Vec<Entry>> {
        let scope = self.scope();
        let nodes = self
            .inner
            .inventory
            .list_all_nodes(&scope.remote_name, &scope.corpus_id)
            .await?;
        Ok(project_graph_to_entries(
            &nodes,
            &scope.root_id,
            prefix,
            recursive,
        ))
    }

    /// Stream cached `gdrive_nodes` directory-by-directory over a bounded channel with
    /// O(single directory) peak RAM, inline directory-subtree pruning, and full
    /// file/folder shortcut resolution (in-corpus and external targets).
    pub async fn stream_cached_entries(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let scope = self.scope();
        let base_depth = prefix.segments().count();
        let effective_max_depth = options.effective_max_depth();

        let mut current_id = scope.root_id.clone();
        let mut raw_acc = String::new();
        let mut nfc_acc = RelPath::root();
        let mut start_from_shortcut = false;
        let mut start_ancestors = AncestorNode::root(scope.root_id.as_str());

        if !prefix.is_root() {
            let segs: Vec<&str> = prefix.segments().collect();
            for (idx, seg) in segs.iter().enumerate() {
                let is_last = idx + 1 == segs.len();
                let mut kids = self
                    .inner
                    .inventory
                    .find_children_by_name(&scope.remote_name, &scope.corpus_id, &current_id, seg)
                    .await?;
                kids.sort_by(|a, b| a.nfc_name.cmp(&b.nfc_name).then(a.file_id.cmp(&b.file_id)));
                let next = kids.into_iter().find(|k| {
                    let is_dir_or_dir_sc = k.kind == EntryKind::Directory
                        || decode_shortcut_ref(k)
                            .is_some_and(|(tk, _)| tk != ShortcutTargetKind::File);
                    (is_last || is_dir_or_dir_sc) && (k.nfc_name == *seg || k.raw_name == *seg)
                });
                match next {
                    Some(node) if is_last && node.kind == EntryKind::File => {
                        let raw_path = join_raw_seg(&raw_acc, &node.raw_name);
                        let Ok(nfc_path) = nfc_acc.join(&node.nfc_name) else {
                            return Ok(Box::pin(futures::stream::empty()));
                        };
                        let entry = delta_node_to_entry(node, raw_path, nfc_path);
                        return Ok(Box::pin(futures::stream::once(async move { Ok(entry) })));
                    }
                    Some(node) if node.kind == EntryKind::Symlink => {
                        let Some((mut target_kind, mut target_id_owned)) =
                            decode_shortcut_ref(&node).map(|(tk, t)| (tk, t.to_string()))
                        else {
                            return Ok(Box::pin(futures::stream::empty()));
                        };
                        raw_acc = join_raw_seg(&raw_acc, &node.raw_name);
                        let Ok(joined) = nfc_acc.join(&node.nfc_name) else {
                            return Ok(Box::pin(futures::stream::empty()));
                        };
                        nfc_acc = joined;

                        // Follow any in-corpus shortcut hops first before checking external targets.
                        let mut hop_seen = HashSet::new();
                        hop_seen.insert(node.file_id.clone());
                        let mut resolved_local_target: Option<DeltaNodeRecord> = None;
                        let mut external_target = false;
                        let mut resolved_root = false;
                        for _ in 0..MAX_SHORTCUT_CHAIN_HOPS {
                            if !hop_seen.insert(target_id_owned.clone()) {
                                return Ok(Box::pin(futures::stream::empty()));
                            }
                            if target_id_owned == scope.root_id {
                                target_kind = ShortcutTargetKind::Folder;
                                resolved_root = true;
                                break;
                            }
                            if let Some(t) = self
                                .inner
                                .inventory
                                .get_node(&scope.remote_name, &scope.corpus_id, &target_id_owned)
                                .await?
                            {
                                if !self.inner.cfg.trashed_only && t.trashed {
                                    return Ok(Box::pin(futures::stream::empty()));
                                }
                                if let Some((next_tk, next_t)) = decode_shortcut_ref(&t) {
                                    target_kind = next_tk;
                                    target_id_owned = next_t.to_string();
                                    continue;
                                }
                                target_kind = if t.kind == EntryKind::Directory {
                                    ShortcutTargetKind::Folder
                                } else {
                                    ShortcutTargetKind::File
                                };
                                resolved_local_target = Some(t);
                                break;
                            } else {
                                external_target = true;
                                break;
                            }
                        }

                        if !external_target && !resolved_root && resolved_local_target.is_none() {
                            return Ok(Box::pin(futures::stream::empty()));
                        }

                        if external_target {
                            // Target is outside local corpus: resolve remotely!
                            if target_kind == ShortcutTargetKind::ChainedShortcut || is_last {
                                let ProbeFileOutcome::Found(f) =
                                    self.get_file_by_id_tolerating_403(&target_id_owned).await?
                                else {
                                    return Ok(Box::pin(futures::stream::empty()));
                                };
                                let Some(target) = self.resolve_shortcut_target(*f).await? else {
                                    return Ok(Box::pin(futures::stream::empty()));
                                };
                                if target.mime_type != FOLDER_MIME {
                                    if !is_last {
                                        return Ok(Box::pin(futures::stream::empty()));
                                    }
                                    let mut entry =
                                        self.drive_file_to_entry(&target, raw_acc, nfc_acc);
                                    entry.node_id = Some(NodeId(node.file_id));
                                    entry.parent_id = node.parent_id.map(NodeId);
                                    return Ok(Box::pin(futures::stream::once(async move {
                                        Ok(entry)
                                    })));
                                }
                                target_kind = ShortcutTargetKind::Folder;
                                target_id_owned = target.id;
                                let in_corpus = target_id_owned == scope.root_id
                                    || self
                                        .inner
                                        .inventory
                                        .get_node(
                                            &scope.remote_name,
                                            &scope.corpus_id,
                                            &target_id_owned,
                                        )
                                        .await?
                                        .is_some();
                                if in_corpus {
                                    if start_ancestors.contains(&target_id_owned) {
                                        return Ok(Box::pin(futures::stream::empty()));
                                    }
                                    start_ancestors = AncestorNode::push(
                                        &start_ancestors,
                                        target_id_owned.as_str(),
                                    );
                                    current_id = target_id_owned;
                                    start_from_shortcut = true;
                                    continue;
                                }
                            }

                            if !is_last {
                                if target_kind != ShortcutTargetKind::Folder {
                                    return Ok(Box::pin(futures::stream::empty()));
                                }
                                let Some(resolved) = self
                                    .resolve_rel_path_from_id(
                                        &target_id_owned,
                                        &segs[idx + 1..],
                                        true,
                                    )
                                    .await?
                                else {
                                    return Ok(Box::pin(futures::stream::empty()));
                                };
                                if resolved.effective_mime() != FOLDER_MIME {
                                    let entry =
                                        resolved.into_entry(self, prefix.as_str(), prefix.clone());
                                    return Ok(Box::pin(futures::stream::once(async move {
                                        Ok(entry)
                                    })));
                                }
                                return Ok(self.stream_remote_dir_from_id(
                                    resolved.content_id().to_string(),
                                    prefix.as_str().to_string(),
                                    prefix.clone(),
                                    base_depth,
                                    effective_max_depth,
                                    true,
                                    options.dir_pruner().cloned(),
                                ));
                            }
                            return Ok(self.stream_remote_dir_from_id(
                                target_id_owned,
                                raw_acc,
                                nfc_acc,
                                base_depth,
                                effective_max_depth,
                                true,
                                options.dir_pruner().cloned(),
                            ));
                        }

                        let is_folder = target_kind == ShortcutTargetKind::Folder;
                        if is_last && !is_folder {
                            let entry = shortcut_target_to_entry(
                                &node.file_id,
                                node.parent_id.as_deref(),
                                node.mtime_ns,
                                false,
                                resolved_local_target.as_ref(),
                                raw_acc,
                                nfc_acc,
                            );
                            return Ok(Box::pin(futures::stream::once(async move { Ok(entry) })));
                        }
                        if !is_folder || start_ancestors.contains(&target_id_owned) {
                            return Ok(Box::pin(futures::stream::empty()));
                        }
                        start_ancestors =
                            AncestorNode::push(&start_ancestors, target_id_owned.as_str());
                        current_id = target_id_owned;
                        start_from_shortcut = true;
                    }
                    Some(dir) => {
                        raw_acc = join_raw_seg(&raw_acc, &dir.raw_name);
                        if let Ok(joined) = nfc_acc.join(&dir.nfc_name) {
                            nfc_acc = joined;
                        }
                        if start_ancestors.contains(&dir.file_id) {
                            return Ok(Box::pin(futures::stream::empty()));
                        }
                        start_ancestors =
                            AncestorNode::push(&start_ancestors, dir.file_id.as_str());
                        current_id = dir.file_id;
                    }
                    None => {
                        return Ok(Box::pin(futures::stream::empty()));
                    }
                }
            }
        }

        if effective_max_depth == Some(0) {
            return Ok(Box::pin(futures::stream::empty()));
        }

        enum QueueSource {
            Local {
                dir_id: String,
            },
            Remote {
                dir_id: String,
                page_token: Option<String>,
            },
        }
        struct CachedQueueItem {
            source: QueueSource,
            dir_raw: String,
            dir_nfc: RelPath,
            ancestors: std::sync::Arc<AncestorNode>,
            from_shortcut: bool,
        }

        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let backend = self.clone();
        let inventory = self.inner.inventory.clone();
        let pruner = options.dir_pruner().cloned();
        let actual_root_id = self.inner.actual_root_id.get().cloned();

        tokio::spawn(async move {
            let mut tracker = BoundedDirTracker::new(0);
            let mut queue: VecDeque<CachedQueueItem> = VecDeque::new();
            queue.push_back(CachedQueueItem {
                source: QueueSource::Local { dir_id: current_id },
                dir_raw: raw_acc,
                dir_nfc: nfc_acc,
                ancestors: start_ancestors,
                from_shortcut: start_from_shortcut,
            });

            while let Some(item) = queue.pop_front() {
                if tx.is_closed() {
                    return;
                }
                match item.source {
                    QueueSource::Local { dir_id } => {
                        let mut children = match inventory
                            .list_children(&scope.remote_name, &scope.corpus_id, &dir_id)
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        };
                        children.sort_by(|a, b| {
                            a.nfc_name.cmp(&b.nfc_name).then(a.file_id.cmp(&b.file_id))
                        });

                        let mut pending_file_shortcuts: Vec<PendingFileShortcut> = Vec::new();
                        let mut in_corpus_targets: HashMap<String, DeltaNodeRecord> =
                            HashMap::new();
                        let mut local_shortcut_ids: Vec<(
                            DeltaNodeRecord,
                            bool,
                            String,
                            RelPath,
                            String,
                        )> = Vec::new();

                        // Collect shortcut target IDs to batch-lookup in `inventory` in one query.
                        let mut lookup_ids: Vec<String> = Vec::new();
                        for child in &children {
                            if let Some((tk, tid)) = decode_shortcut_ref(child)
                                && tk != ShortcutTargetKind::Folder
                            {
                                lookup_ids.push(tid.to_string());
                            }
                        }
                        if !lookup_ids.is_empty()
                            && let Ok(found) = inventory
                                .get_nodes_batch(&scope.remote_name, &scope.corpus_id, &lookup_ids)
                                .await
                        {
                            in_corpus_targets = found;
                        }

                        for child in children {
                            if tx.is_closed() {
                                return;
                            }
                            let Ok(child_nfc) = item.dir_nfc.join(&child.nfc_name) else {
                                continue;
                            };
                            let rel_depth = child_nfc.segments().count().saturating_sub(base_depth);
                            if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                                continue;
                            }
                            let can_descend =
                                effective_max_depth.is_none_or(|limit| rel_depth < limit);
                            let child_raw = join_raw_seg(&item.dir_raw, &child.raw_name);

                            if let Some((tk, tid)) = decode_shortcut_ref(&child) {
                                let tid_owned = tid.to_string();
                                match tk {
                                    ShortcutTargetKind::Folder => {
                                        if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                            continue;
                                        }
                                        if !tracker.try_enter(
                                            &item.ancestors,
                                            &tid_owned,
                                            actual_root_id.as_deref(),
                                        ) {
                                            warn!(
                                                shortcut_id = %child.file_id,
                                                target_id = %tid_owned,
                                                path = %child_nfc,
                                                "detected cyclic Google Drive folder shortcut in inventory; breaking loop"
                                            );
                                            continue;
                                        }
                                        let entry = shortcut_target_to_entry(
                                            &child.file_id,
                                            child.parent_id.as_deref(),
                                            child.mtime_ns,
                                            true,
                                            None,
                                            child_raw.clone(),
                                            child_nfc.clone(),
                                        );
                                        if tx.send(Ok(entry)).await.is_err() {
                                            return;
                                        }
                                        if can_descend {
                                            local_shortcut_ids.push((
                                                child, true, child_raw, child_nfc, tid_owned,
                                            ));
                                        }
                                    }
                                    ShortcutTargetKind::File => {
                                        if let Some(target_rec) = in_corpus_targets.get(&tid_owned)
                                            && target_rec.kind != EntryKind::Symlink
                                        {
                                            if !backend.inner.cfg.trashed_only && target_rec.trashed
                                            {
                                                continue;
                                            }
                                            let entry = shortcut_target_to_entry(
                                                &child.file_id,
                                                child.parent_id.as_deref(),
                                                child.mtime_ns,
                                                target_rec.kind == EntryKind::Directory,
                                                Some(target_rec),
                                                child_raw,
                                                child_nfc,
                                            );
                                            if tx.send(Ok(entry)).await.is_err() {
                                                return;
                                            }
                                        } else {
                                            pending_file_shortcuts.push(PendingFileShortcut {
                                                shortcut_id: child.file_id,
                                                shortcut_parent_id: dir_id.clone(),
                                                shortcut_mtime_ns: child.mtime_ns,
                                                target_id: tid_owned,
                                                child_raw,
                                                child_nfc,
                                            });
                                        }
                                    }
                                    ShortcutTargetKind::ChainedShortcut => {
                                        let mut hop_seen = HashSet::new();
                                        hop_seen.insert(child.file_id.clone());
                                        let mut cur_tid = tid_owned;
                                        let mut local_resolved: Option<DeltaNodeRecord> = None;
                                        let mut external_tid: Option<String> = None;
                                        let mut resolved_root = false;

                                        for hop in 0..8 {
                                            if !hop_seen.insert(cur_tid.clone()) {
                                                break;
                                            }
                                            if cur_tid == scope.root_id {
                                                resolved_root = true;
                                                break;
                                            }
                                            let next_rec = if hop == 0 {
                                                in_corpus_targets.get(&cur_tid).cloned()
                                            } else {
                                                inventory
                                                    .get_node(
                                                        &scope.remote_name,
                                                        &scope.corpus_id,
                                                        &cur_tid,
                                                    )
                                                    .await
                                                    .ok()
                                                    .flatten()
                                            };
                                            let Some(rec) = next_rec else {
                                                external_tid = Some(cur_tid);
                                                break;
                                            };
                                            if !backend.inner.cfg.trashed_only && rec.trashed {
                                                break;
                                            }
                                            if let Some((_, next_t)) = decode_shortcut_ref(&rec) {
                                                cur_tid = next_t.to_string();
                                                continue;
                                            }
                                            local_resolved = Some(rec);
                                            break;
                                        }

                                        if resolved_root {
                                            if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                                continue;
                                            }
                                            if !tracker.try_enter(
                                                &item.ancestors,
                                                &scope.root_id,
                                                actual_root_id.as_deref(),
                                            ) {
                                                continue;
                                            }
                                            let entry = shortcut_target_to_entry(
                                                &child.file_id,
                                                child.parent_id.as_deref(),
                                                child.mtime_ns,
                                                true,
                                                None,
                                                child_raw.clone(),
                                                child_nfc.clone(),
                                            );
                                            if tx.send(Ok(entry)).await.is_err() {
                                                return;
                                            }
                                            if can_descend {
                                                local_shortcut_ids.push((
                                                    child,
                                                    true,
                                                    child_raw,
                                                    child_nfc,
                                                    scope.root_id.clone(),
                                                ));
                                            }
                                        } else if let Some(target_rec) = local_resolved {
                                            let target_is_dir =
                                                target_rec.kind == EntryKind::Directory;
                                            if target_is_dir {
                                                if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                                    continue;
                                                }
                                                if !tracker.try_enter(
                                                    &item.ancestors,
                                                    &target_rec.file_id,
                                                    actual_root_id.as_deref(),
                                                ) {
                                                    continue;
                                                }
                                            }
                                            let entry = shortcut_target_to_entry(
                                                &child.file_id,
                                                child.parent_id.as_deref(),
                                                child.mtime_ns,
                                                target_is_dir,
                                                Some(&target_rec),
                                                child_raw.clone(),
                                                child_nfc.clone(),
                                            );
                                            if tx.send(Ok(entry)).await.is_err() {
                                                return;
                                            }
                                            if target_is_dir && can_descend {
                                                let tid_final = target_rec.file_id.clone();
                                                local_shortcut_ids.push((
                                                    child, true, child_raw, child_nfc, tid_final,
                                                ));
                                            }
                                        } else if let Some(ext_id) = external_tid {
                                            let resolved = match backend
                                                .get_file_by_id_tolerating_403(&ext_id)
                                                .await
                                            {
                                                Ok(ProbeFileOutcome::Found(f)) => {
                                                    let f = *f;
                                                    if f.mime_type == SHORTCUT_MIME {
                                                        backend.resolve_shortcut_target(f).await
                                                    } else if (!backend.inner.cfg.trashed_only
                                                        && f.trashed)
                                                        || is_exportable_workspace_doc(&f.mime_type)
                                                    {
                                                        Ok(None)
                                                    } else {
                                                        Ok(Some(f))
                                                    }
                                                }
                                                Ok(
                                                    ProbeFileOutcome::NotFound
                                                    | ProbeFileOutcome::Forbidden,
                                                ) => Ok(None),
                                                Err(e) => Err(e),
                                            };
                                            match resolved {
                                                Ok(Some(target)) => {
                                                    if hop_seen.contains(&target.id) {
                                                        continue;
                                                    }
                                                    let target_is_dir =
                                                        target.mime_type == FOLDER_MIME;
                                                    if target_is_dir {
                                                        if pruner
                                                            .as_ref()
                                                            .is_some_and(|p| p(&child_nfc))
                                                        {
                                                            continue;
                                                        }
                                                        if !tracker.try_enter(
                                                            &item.ancestors,
                                                            &target.id,
                                                            actual_root_id.as_deref(),
                                                        ) {
                                                            continue;
                                                        }
                                                    }
                                                    let mut entry = backend.drive_file_to_entry(
                                                        &target,
                                                        child_raw.clone(),
                                                        child_nfc.clone(),
                                                    );
                                                    entry.node_id =
                                                        Some(NodeId(child.file_id.clone()));
                                                    entry.parent_id =
                                                        child.parent_id.clone().map(NodeId);
                                                    if tx.send(Ok(entry)).await.is_err() {
                                                        return;
                                                    }
                                                    if target_is_dir && can_descend {
                                                        local_shortcut_ids.push((
                                                            child, true, child_raw, child_nfc,
                                                            target.id,
                                                        ));
                                                    }
                                                }
                                                Ok(None) => {}
                                                Err(e) => {
                                                    let _ = tx.send(Err(e)).await;
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                                continue;
                            }

                            let is_dir = child.kind == EntryKind::Directory;
                            if is_dir && pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                continue;
                            }
                            let next_id = if is_dir
                                && can_descend
                                && tracker.try_enter(
                                    &item.ancestors,
                                    &child.file_id,
                                    actual_root_id.as_deref(),
                                ) {
                                Some(child.file_id.clone())
                            } else {
                                None
                            };
                            let entry =
                                delta_node_to_entry(child, child_raw.clone(), child_nfc.clone());
                            if tx.send(Ok(entry)).await.is_err() {
                                return;
                            }
                            if let Some(fid) = next_id {
                                let next_anc = AncestorNode::push(&item.ancestors, fid.as_str());
                                queue.push_back(CachedQueueItem {
                                    source: QueueSource::Local { dir_id: fid },
                                    dir_raw: child_raw,
                                    dir_nfc: child_nfc,
                                    ancestors: next_anc,
                                    from_shortcut: item.from_shortcut,
                                });
                            }
                        }

                        if !pending_file_shortcuts.is_empty()
                            && !resolve_and_emit_file_shortcuts(
                                &backend,
                                pending_file_shortcuts,
                                &tx,
                            )
                            .await
                        {
                            return;
                        }

                        for (_sc, _is_folder, child_raw, child_nfc, tid_owned) in local_shortcut_ids
                        {
                            let in_corpus = tid_owned == scope.root_id
                                || matches!(
                                    inventory
                                        .get_node(&scope.remote_name, &scope.corpus_id, &tid_owned)
                                        .await,
                                    Ok(Some(_))
                                );
                            let next_anc = AncestorNode::push(&item.ancestors, tid_owned.as_str());
                            let source = if in_corpus {
                                QueueSource::Local { dir_id: tid_owned }
                            } else {
                                QueueSource::Remote {
                                    dir_id: tid_owned,
                                    page_token: None,
                                }
                            };
                            queue.push_back(CachedQueueItem {
                                source,
                                dir_raw: child_raw,
                                dir_nfc: child_nfc,
                                ancestors: next_anc,
                                from_shortcut: true,
                            });
                        }
                    }
                    QueueSource::Remote { dir_id, page_token } => {
                        let page = match backend
                            .list_children_remote_page(&dir_id, page_token.as_deref())
                            .await
                        {
                            Ok(p) => p,
                            Err(e)
                                if item.from_shortcut
                                    && matches!(
                                        e.kind,
                                        ErrorKind::PermissionDenied | ErrorKind::NotFound
                                    ) =>
                            {
                                warn!(
                                    dir_id = %dir_id,
                                    path = %item.dir_nfc,
                                    error = %e,
                                    "skipping inaccessible external folder shortcut target in changes-feed mode"
                                );
                                continue;
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        };
                        if page.incomplete_search {
                            let _ = tx
                                .send(Err(Error::protocol(
                                    "Google Drive returned incompleteSearch=true during shortcut target listing; blocking incomplete observation",
                                )))
                                .await;
                            return;
                        }
                        let mut pending_file_shortcuts: Vec<PendingFileShortcut> = Vec::new();
                        for file in page.files {
                            if (!backend.inner.cfg.trashed_only && file.trashed)
                                || is_exportable_workspace_doc(&file.mime_type)
                            {
                                continue;
                            }
                            let Ok(child_nfc) = item.dir_nfc.join(&file.name) else {
                                continue;
                            };
                            let rel_depth = child_nfc.segments().count().saturating_sub(base_depth);
                            if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                                continue;
                            }
                            let can_descend =
                                effective_max_depth.is_none_or(|limit| rel_depth < limit);
                            let child_raw = join_raw_seg(&item.dir_raw, &file.name);

                            if file.mime_type == SHORTCUT_MIME {
                                let Some(sd) = &file.shortcut_details else {
                                    continue;
                                };
                                let sc_mtime = file
                                    .modified_time
                                    .as_deref()
                                    .map(parse_rfc3339_nanos)
                                    .unwrap_or(0);
                                if sd.target_mime_type == FOLDER_MIME {
                                    if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                        continue;
                                    }
                                    if !tracker.try_enter(
                                        &item.ancestors,
                                        &sd.target_id,
                                        actual_root_id.as_deref(),
                                    ) {
                                        continue;
                                    }
                                    let entry = shortcut_target_to_entry(
                                        &file.id,
                                        Some(&dir_id),
                                        sc_mtime,
                                        true,
                                        None,
                                        child_raw.clone(),
                                        child_nfc.clone(),
                                    );
                                    if tx.send(Ok(entry)).await.is_err() {
                                        return;
                                    }
                                    if can_descend {
                                        let next_anc = AncestorNode::push(
                                            &item.ancestors,
                                            sd.target_id.as_str(),
                                        );
                                        queue.push_back(CachedQueueItem {
                                            source: QueueSource::Remote {
                                                dir_id: sd.target_id.clone(),
                                                page_token: None,
                                            },
                                            dir_raw: child_raw,
                                            dir_nfc: child_nfc,
                                            ancestors: next_anc,
                                            from_shortcut: true,
                                        });
                                    }
                                } else if sd.target_mime_type == SHORTCUT_MIME {
                                    match backend.resolve_shortcut_target(file.clone()).await {
                                        Ok(Some(resolved_target)) => {
                                            let resolved_is_dir =
                                                resolved_target.mime_type == FOLDER_MIME;
                                            if resolved_is_dir {
                                                if pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                                    continue;
                                                }
                                                if !tracker.try_enter(
                                                    &item.ancestors,
                                                    &resolved_target.id,
                                                    actual_root_id.as_deref(),
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
                                                return;
                                            }
                                            if resolved_is_dir && can_descend {
                                                let next_anc = AncestorNode::push(
                                                    &item.ancestors,
                                                    resolved_target.id.as_str(),
                                                );
                                                queue.push_back(CachedQueueItem {
                                                    source: QueueSource::Remote {
                                                        dir_id: resolved_target.id,
                                                        page_token: None,
                                                    },
                                                    dir_raw: child_raw,
                                                    dir_nfc: child_nfc,
                                                    ancestors: next_anc,
                                                    from_shortcut: true,
                                                });
                                            }
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            let _ = tx.send(Err(e)).await;
                                            return;
                                        }
                                    }
                                } else if !is_exportable_workspace_doc(&sd.target_mime_type) {
                                    pending_file_shortcuts.push(PendingFileShortcut {
                                        shortcut_id: file.id,
                                        shortcut_parent_id: dir_id.clone(),
                                        shortcut_mtime_ns: sc_mtime,
                                        target_id: sd.target_id.clone(),
                                        child_raw,
                                        child_nfc,
                                    });
                                }
                                continue;
                            }

                            let is_dir = file.mime_type == FOLDER_MIME;
                            if is_dir && pruner.as_ref().is_some_and(|p| p(&child_nfc)) {
                                continue;
                            }
                            let next_id = if is_dir
                                && can_descend
                                && tracker.try_enter(
                                    &item.ancestors,
                                    &file.id,
                                    actual_root_id.as_deref(),
                                ) {
                                Some(file.id.clone())
                            } else {
                                None
                            };
                            let entry = backend.drive_file_to_entry(
                                &file,
                                child_raw.clone(),
                                child_nfc.clone(),
                            );
                            if tx.send(Ok(entry)).await.is_err() {
                                return;
                            }
                            if let Some(fid) = next_id {
                                let next_anc = AncestorNode::push(&item.ancestors, fid.as_str());
                                queue.push_back(CachedQueueItem {
                                    source: QueueSource::Remote {
                                        dir_id: fid,
                                        page_token: None,
                                    },
                                    dir_raw: child_raw,
                                    dir_nfc: child_nfc,
                                    ancestors: next_anc,
                                    from_shortcut: true,
                                });
                            }
                        }

                        if !pending_file_shortcuts.is_empty()
                            && !resolve_and_emit_file_shortcuts(
                                &backend,
                                pending_file_shortcuts,
                                &tx,
                            )
                            .await
                        {
                            return;
                        }
                        if let Some(next_tok) = page.next_page_token {
                            queue.push_front(CachedQueueItem {
                                source: QueueSource::Remote {
                                    dir_id,
                                    page_token: Some(next_tok),
                                },
                                dir_raw: item.dir_raw,
                                dir_nfc: item.dir_nfc,
                                ancestors: item.ancestors,
                                from_shortcut: item.from_shortcut,
                            });
                        }
                    }
                }
            }
        });

        Ok(crate::common::rx_to_entry_stream(rx))
    }

    pub(super) async fn is_under_root(
        &self,
        scope: &DeltaScope,
        file_id: &str,
        initial_parent: Option<&str>,
        root_id: &str,
        batch_parents: &HashMap<String, Option<String>>,
        ancestry_cache: &mut HashMap<String, Option<String>>,
    ) -> Result<bool> {
        if file_id == root_id {
            return Ok(true);
        }
        let mut cursor = initial_parent.map(str::to_string);
        let mut seen = HashSet::new();
        seen.insert(file_id.to_string());

        for _ in 0..MAX_ANCESTOR_HOPS {
            let Some(pid) = cursor else {
                return Ok(false);
            };
            if pid == root_id
                || (root_id == "root"
                    && self
                        .inner
                        .actual_root_id
                        .get()
                        .is_some_and(|actual| actual == &pid))
            {
                return Ok(true);
            }
            if !seen.insert(pid.clone()) {
                // Parent cycle -> treat as outside root.
                return Ok(false);
            }
            if let Some(next_p) = batch_parents.get(&pid) {
                cursor = next_p.clone();
                continue;
            }
            if let Some(next_p) = ancestry_cache.get(&pid) {
                cursor = next_p.clone();
                continue;
            }
            // Check persistent SQLite inventory before probing Drive over HTTP!
            if let Some(local_node) = self
                .inner
                .inventory
                .get_node(&scope.remote_name, &scope.corpus_id, &pid)
                .await?
            {
                if ancestry_cache.len() >= MAX_ANCESTRY_CACHE_ENTRIES {
                    ancestry_cache.clear();
                }
                if !self.inner.cfg.trashed_only && local_node.trashed {
                    ancestry_cache.insert(pid, None);
                    return Ok(false);
                }
                let next_p = local_node.parent_id;
                ancestry_cache.insert(pid, next_p.clone());
                cursor = next_p;
                continue;
            }
            // If tracking `"root"` (and not in `shared_with_me` mode), resolve its real
            // alphanumeric Drive ID once before treating an uncached top-level parent as outside root!
            if root_id == "root"
                && !self.inner.cfg.shared_with_me
                && self.inner.actual_root_id.get().is_none()
                && let Some(actual_root) = self.ensure_actual_root_id().await?
                && actual_root == pid
            {
                return Ok(true);
            }
            // Unknown parent not in local graph -> probe Drive once, tolerating 403 on
            // unrelated Shared Drive / "Shared with me" parent folders!
            if ancestry_cache.len() >= MAX_ANCESTRY_CACHE_ENTRIES {
                ancestry_cache.clear();
            }
            match self.get_file_by_id_tolerating_403(&pid).await? {
                ProbeFileOutcome::Found(parent_file)
                    if self.inner.cfg.trashed_only || !parent_file.trashed =>
                {
                    let next_p = parent_file.parents.first().cloned();
                    ancestry_cache.insert(pid, next_p.clone());
                    cursor = next_p;
                }
                ProbeFileOutcome::Found(_)
                | ProbeFileOutcome::NotFound
                | ProbeFileOutcome::Forbidden => {
                    ancestry_cache.insert(pid, None);
                    return Ok(false);
                }
            }
        }
        Ok(false)
    }

    pub(super) fn drive_file_to_node(
        &self,
        f: &DriveFile,
        fallback_parent: Option<&str>,
    ) -> DeltaNodeRecord {
        let mtime_ns = f
            .modified_time
            .as_deref()
            .map(parse_rfc3339_nanos)
            .unwrap_or(0);
        let nfc_name: String = f.name.nfc().collect();
        let (kind, size, md5) = if f.mime_type == SHORTCUT_MIME {
            let encoded = f
                .shortcut_details
                .as_ref()
                .map(|sd| encode_shortcut_ref(&sd.target_mime_type, &sd.target_id));
            (EntryKind::Symlink, 0, encoded)
        } else if f.mime_type == FOLDER_MIME {
            (EntryKind::Directory, 0, f.md5_checksum.clone())
        } else {
            (EntryKind::File, f.size, f.md5_checksum.clone())
        };
        DeltaNodeRecord {
            file_id: f.id.clone(),
            parent_id: self.normalize_parent_id(f.parents.first().cloned(), fallback_parent),
            raw_name: f.name.clone(),
            nfc_name,
            kind,
            size,
            mtime_ns,
            md5,
            trashed: f.trashed,
            generation: 1,
            updated_at: self.inner.clock.now_unix_secs(),
        }
    }

    pub(super) fn drive_file_to_entry(
        &self,
        f: &DriveFile,
        raw_path: impl AsRef<str>,
        nfc_path: RelPath,
    ) -> Entry {
        let is_dir = f.mime_type == FOLDER_MIME
            || (f.mime_type == SHORTCUT_MIME
                && f.shortcut_details
                    .as_ref()
                    .is_some_and(|sd| sd.target_mime_type == FOLDER_MIME));
        let kind = if is_dir {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let mtime_ns = f
            .modified_time
            .as_deref()
            .map(parse_rfc3339_nanos)
            .unwrap_or(0);
        let checksum = if is_dir { None } else { f.best_checksum() };
        Entry {
            node_id: Some(NodeId(f.id.clone())),
            parent_id: f.parents.first().cloned().map(NodeId),
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
            nfc_path,
            kind,
            size: if is_dir { 0 } else { f.size },
            mtime_ns,
            ctime_ns: None,
            etag: if is_dir { None } else { f.md5_checksum.clone() },
            checksum,
        }
    }

    /// Persist a single Drive file/shortcut metadata record into the local `inventory` cache.
    pub(super) async fn cache_node(&self, f: &DriveFile, fallback_parent: Option<&str>) {
        if (!self.inner.cfg.trashed_only && f.trashed) || is_exportable_workspace_doc(&f.mime_type)
        {
            return;
        }
        if f.mime_type == SHORTCUT_MIME
            && f.shortcut_details.as_ref().is_none_or(|sd| {
                sd.target_mime_type != FOLDER_MIME
                    && is_exportable_workspace_doc(&sd.target_mime_type)
            })
        {
            return;
        }
        if fallback_parent.is_none()
            && !self.inner.cfg.shared_with_me
            && self.inner.cfg.effective_root_id() == "root"
            && self.inner.actual_root_id.get().is_none()
            && f.parents.first().is_some_and(|p| p != "root")
        {
            let _ = self.ensure_actual_root_id().await;
        }
        let scope = self.scope();
        let rec = self.drive_file_to_node(f, fallback_parent);
        let _ = self
            .inner
            .inventory
            .apply_change_batch(
                &scope,
                DeltaChangeBatch {
                    upserts: vec![rec],
                    remove_file_ids: vec![],
                    evict_subtree_root_ids: vec![],
                    new_start_page_token: None,
                    updated_at: self.inner.clock.now_unix_secs(),
                },
            )
            .await;
    }

    pub(super) async fn cache_nodes_batch(&self, files: &[DriveFile], fallback_parent: &str) {
        let upserts: Vec<DeltaNodeRecord> = files
            .iter()
            .filter(|f| {
                (self.inner.cfg.trashed_only || !f.trashed)
                    && !is_exportable_workspace_doc(&f.mime_type)
                    && (f.mime_type != SHORTCUT_MIME
                        || f.shortcut_details.as_ref().is_some_and(|sd| {
                            sd.target_mime_type == FOLDER_MIME
                                || !is_exportable_workspace_doc(&sd.target_mime_type)
                        }))
            })
            .map(|f| self.drive_file_to_node(f, Some(fallback_parent)))
            .collect();
        if upserts.is_empty() {
            return;
        }
        let scope = self.scope();
        let _ = self
            .inner
            .inventory
            .apply_change_batch(
                &scope,
                DeltaChangeBatch {
                    upserts,
                    remove_file_ids: vec![],
                    evict_subtree_root_ids: vec![],
                    new_start_page_token: None,
                    updated_at: self.inner.clock.now_unix_secs(),
                },
            )
            .await;
    }
}
