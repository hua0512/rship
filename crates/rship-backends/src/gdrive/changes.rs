//! ID-keyed `gdrive_nodes` graph cache and Google Drive `changes.list`
//! incremental synchronization engine.
//!
//! Handles all Drive change-feed edge cases (`CONFORMANCE_TESTS.md` §4):
//! - `removed: true` with empty/null `file` payload.
//! - `trashed: true` recursive subtree eviction for folders.
//! - Folder moved **into** tracked root -> recursive subtree crawl of its
//!   children (since `changes.list` only reports the moved folder itself!).
//! - Folder moved **out of** tracked root -> recursive subtree eviction from
//!   `gdrive_nodes`.
//! - `incompleteSearch: true` gate: refuses to advance `startPageToken` when
//!   any crawl page is incomplete, preserving Observation Completeness.

use async_trait::async_trait;
use rship_core::Result;
use rship_core::path::RelPath;
use rship_core::state::{DeltaChangeBatch, DeltaInventoryStore, DeltaNodeRecord, DeltaScope};
use rship_core::types::{Checksum, Entry, EntryKind, HashKind, NodeId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

/// Summary returned by [`crate::gdrive::GdriveBackend::bootstrap_inventory`] and
/// [`crate::gdrive::GdriveBackend::sync_changes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangesSyncReport {
    pub bootstrapped: bool,
    pub pages_processed: usize,
    pub upserted_nodes: usize,
    pub removed_nodes: usize,
    pub crawled_moved_in_dirs: usize,
    pub evicted_subtrees: usize,
    pub incomplete_search: bool,
    pub new_start_page_token: Option<String>,
}

/// Thread-safe in-memory [`DeltaInventoryStore`] used as default when no SQLite
/// `StateActor` is wired (e.g. unit tests or ephemeral invocations).
#[derive(Debug, Default)]
pub struct InMemoryGdriveStore {
    inner: RwLock<InMemState>,
}

#[derive(Debug, Default)]
struct InMemState {
    tokens: HashMap<DeltaScope, String>,
    /// Keyed by `(remote_name, corpus_id)` -> `file_id -> DeltaNodeRecord`.
    nodes: HashMap<(String, String), HashMap<String, DeltaNodeRecord>>,
}

impl InMemoryGdriveStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeltaInventoryStore for InMemoryGdriveStore {
    async fn get_change_token(&self, scope: &DeltaScope) -> Result<Option<String>> {
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        Ok(guard.tokens.get(scope).cloned())
    }

    async fn apply_change_batch(&self, scope: &DeltaScope, batch: DeltaChangeBatch) -> Result<()> {
        let mut guard = self.inner.write().expect("gdrive mem store poisoned");
        let bucket = guard
            .nodes
            .entry((scope.remote_name.clone(), scope.corpus_id.clone()))
            .or_default();

        // 1. Recursive cycle-safe subtree eviction.
        for root_id in &batch.evict_subtree_root_ids {
            let mut to_remove = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(root_id.clone());
            while let Some(fid) = queue.pop_front() {
                if !to_remove.insert(fid.clone()) {
                    continue;
                }
                for (child_id, rec) in bucket.iter() {
                    if rec.parent_id.as_deref() == Some(fid.as_str())
                        && !to_remove.contains(child_id)
                    {
                        queue.push_back(child_id.clone());
                    }
                }
            }
            for fid in to_remove {
                bucket.remove(&fid);
            }
        }

        // 2. Individual removals.
        for fid in &batch.remove_file_ids {
            bucket.remove(fid);
        }

        // 3. Upserts.
        for rec in batch.upserts {
            bucket.insert(rec.file_id.clone(), rec);
        }

        // 4. Atomic token update.
        if let Some(tok) = batch.new_start_page_token {
            guard.tokens.insert(scope.clone(), tok);
        }
        Ok(())
    }

    async fn get_node(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_id: &str,
    ) -> Result<Option<DeltaNodeRecord>> {
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        Ok(guard
            .nodes
            .get(&(remote_name.to_string(), corpus_id.to_string()))
            .and_then(|m| m.get(file_id))
            .cloned())
    }

    async fn get_nodes_batch(
        &self,
        remote_name: &str,
        corpus_id: &str,
        file_ids: &[String],
    ) -> Result<HashMap<String, DeltaNodeRecord>> {
        if file_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        let Some(m) = guard
            .nodes
            .get(&(remote_name.to_string(), corpus_id.to_string()))
        else {
            return Ok(HashMap::new());
        };
        let mut out = HashMap::with_capacity(file_ids.len());
        for fid in file_ids {
            if let Some(rec) = m.get(fid)
                && !rec.trashed
            {
                out.insert(fid.clone(), rec.clone());
            }
        }
        Ok(out)
    }

    async fn list_children(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        let Some(m) = guard
            .nodes
            .get(&(remote_name.to_string(), corpus_id.to_string()))
        else {
            return Ok(Vec::new());
        };
        Ok(m.values()
            .filter(|n| !n.trashed && n.parent_id.as_deref() == Some(parent_id))
            .cloned()
            .collect())
    }

    async fn find_children_by_name(
        &self,
        remote_name: &str,
        corpus_id: &str,
        parent_id: &str,
        name: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        let Some(m) = guard
            .nodes
            .get(&(remote_name.to_string(), corpus_id.to_string()))
        else {
            return Ok(Vec::new());
        };
        Ok(m.values()
            .filter(|n| {
                !n.trashed
                    && n.parent_id.as_deref() == Some(parent_id)
                    && (n.raw_name == name || n.nfc_name == name)
            })
            .cloned()
            .collect())
    }

    async fn list_all_nodes(
        &self,
        remote_name: &str,
        corpus_id: &str,
    ) -> Result<Vec<DeltaNodeRecord>> {
        let guard = self.inner.read().expect("gdrive mem store poisoned");
        let Some(m) = guard
            .nodes
            .get(&(remote_name.to_string(), corpus_id.to_string()))
        else {
            return Ok(Vec::new());
        };
        Ok(m.values().filter(|n| !n.trashed).cloned().collect())
    }

    async fn clear_inventory(&self, scope: &DeltaScope) -> Result<()> {
        let mut guard = self.inner.write().expect("gdrive mem store poisoned");
        guard
            .nodes
            .remove(&(scope.remote_name.clone(), scope.corpus_id.clone()));
        guard.tokens.remove(scope);
        Ok(())
    }
}

use super::query::{FOLDER_MIME, SHORTCUT_MIME};

pub(crate) const MAX_SHORTCUT_CHAIN_HOPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShortcutTargetKind {
    Folder,
    File,
    ChainedShortcut,
}

pub(crate) fn encode_shortcut_ref(target_mime_type: &str, target_id: &str) -> String {
    if target_mime_type == FOLDER_MIME {
        format!("sc:d:{target_id}")
    } else if target_mime_type == SHORTCUT_MIME {
        format!("sc:c:{target_id}")
    } else {
        format!("sc:f:{target_id}")
    }
}

pub(crate) fn decode_shortcut_ref(rec: &DeltaNodeRecord) -> Option<(ShortcutTargetKind, &str)> {
    if rec.kind != EntryKind::Symlink {
        return None;
    }
    let raw = rec.md5.as_deref()?;
    if let Some(tid) = raw.strip_prefix("sc:d:") {
        Some((ShortcutTargetKind::Folder, tid))
    } else if let Some(tid) = raw.strip_prefix("sc:c:") {
        Some((ShortcutTargetKind::ChainedShortcut, tid))
    } else if let Some(tid) = raw.strip_prefix("sc:f:") {
        Some((ShortcutTargetKind::File, tid))
    } else {
        None
    }
}

pub(crate) fn join_raw_seg(base: &str, seg: &str) -> String {
    if base.is_empty() {
        seg.to_string()
    } else {
        format!("{base}/{seg}")
    }
}

pub(crate) fn delta_node_to_entry(
    node: DeltaNodeRecord,
    raw_path: impl AsRef<str>,
    nfc_path: RelPath,
) -> Entry {
    if let Some((target_kind, _)) = decode_shortcut_ref(&node) {
        return Entry {
            node_id: Some(NodeId(node.file_id)),
            parent_id: node.parent_id.map(NodeId),
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
            nfc_path,
            kind: if target_kind == ShortcutTargetKind::Folder {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            size: 0,
            mtime_ns: node.mtime_ns,
            ctime_ns: None,
            etag: None,
            checksum: None,
        };
    }
    let checksum = if node.kind == EntryKind::Directory {
        None
    } else {
        node.md5.as_ref().map(|hex| Checksum {
            kind: HashKind::Md5,
            hex: hex.clone(),
        })
    };
    Entry {
        node_id: Some(NodeId(node.file_id)),
        parent_id: node.parent_id.map(NodeId),
        raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
        nfc_path,
        kind: node.kind,
        size: if node.kind == EntryKind::Directory {
            0
        } else {
            node.size
        },
        mtime_ns: node.mtime_ns,
        ctime_ns: None,
        etag: if node.kind == EntryKind::Directory {
            None
        } else {
            node.md5
        },
        checksum,
    }
}

pub(crate) fn shortcut_target_to_entry(
    shortcut_id: &str,
    shortcut_parent_id: Option<&str>,
    shortcut_mtime_ns: i64,
    is_folder: bool,
    target: Option<&DeltaNodeRecord>,
    raw_path: impl AsRef<str>,
    nfc_path: RelPath,
) -> Entry {
    if is_folder {
        return Entry {
            node_id: Some(NodeId(shortcut_id.to_string())),
            parent_id: shortcut_parent_id.map(|s| NodeId(s.to_string())),
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
            nfc_path,
            kind: EntryKind::Directory,
            size: 0,
            mtime_ns: shortcut_mtime_ns,
            ctime_ns: None,
            etag: None,
            checksum: None,
        };
    }
    let (size, mtime_ns, etag, checksum) = if let Some(t) = target {
        let ck = t.md5.as_ref().map(|hex| Checksum {
            kind: HashKind::Md5,
            hex: hex.clone(),
        });
        (t.size, t.mtime_ns, t.md5.clone(), ck)
    } else {
        (0, shortcut_mtime_ns, None, None)
    };
    Entry {
        node_id: Some(NodeId(shortcut_id.to_string())),
        parent_id: shortcut_parent_id.map(|s| NodeId(s.to_string())),
        raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
        nfc_path,
        kind: EntryKind::File,
        size,
        mtime_ns,
        ctime_ns: None,
        etag,
        checksum,
    }
}

fn resolve_graph_shortcut<'a>(
    by_id: &HashMap<&'a str, &'a DeltaNodeRecord>,
    node: &'a DeltaNodeRecord,
) -> Option<(bool, &'a str, Option<&'a DeltaNodeRecord>)> {
    let (mut target_kind, mut target_id) = decode_shortcut_ref(node)?;
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(node.file_id.as_str());

    for _ in 0..MAX_SHORTCUT_CHAIN_HOPS {
        if !visited.insert(target_id) {
            return None;
        }
        let Some(target) = by_id.get(target_id).copied() else {
            return Some((target_kind == ShortcutTargetKind::Folder, target_id, None));
        };
        if target.trashed {
            return None;
        }
        if let Some((next_kind, next_target_id)) = decode_shortcut_ref(target) {
            target_kind = next_kind;
            target_id = next_target_id;
            continue;
        }
        let target_is_folder = target.kind == EntryKind::Directory;
        return Some((target_is_folder, target_id, Some(target)));
    }
    None
}

/// Project an ID-keyed node map (`file_id -> DeltaNodeRecord`) rooted at
/// `root_id` into canonical `Entry` objects, guarding against parent cycles
/// and preserving duplicate sibling names cleanly.
pub fn project_graph_to_entries(
    nodes: &[DeltaNodeRecord],
    root_id: &str,
    prefix: &RelPath,
    recursive: bool,
) -> Vec<Entry> {
    let mut by_id: HashMap<&str, &DeltaNodeRecord> = HashMap::with_capacity(nodes.len());
    let mut children_by_parent: HashMap<&str, Vec<&DeltaNodeRecord>> = HashMap::new();
    for n in nodes {
        if n.trashed {
            continue;
        }
        by_id.insert(n.file_id.as_str(), n);
        if let Some(pid) = n.parent_id.as_deref() {
            children_by_parent.entry(pid).or_default().push(n);
        }
    }
    for list in children_by_parent.values_mut() {
        list.sort_by(|a, b| a.nfc_name.cmp(&b.nfc_name).then(a.file_id.cmp(&b.file_id)));
    }

    // Resolve `prefix` to starting folder ID(s) or a direct single-file match.
    let mut start_ids: Vec<(String, String, RelPath, Vec<String>)> = vec![(
        root_id.to_string(),
        String::new(),
        RelPath::root(),
        vec![root_id.to_string()],
    )];
    if !prefix.is_root() {
        let segs: Vec<&str> = prefix.segments().collect();
        let mut current_id = root_id.to_string();
        let mut raw_acc = String::new();
        let mut nfc_acc = RelPath::root();
        let mut ancestors = vec![root_id.to_string()];
        let mut found = true;
        for (idx, seg) in segs.iter().enumerate() {
            let is_last = idx + 1 == segs.len();
            let next = children_by_parent
                .get(current_id.as_str())
                .and_then(|kids| {
                    kids.iter()
                        .find(|k| {
                            let is_dir_or_dir_sc = k.kind == EntryKind::Directory
                                || (k.kind == EntryKind::Symlink
                                    && resolve_graph_shortcut(&by_id, k)
                                        .is_some_and(|(is_d, _, _)| is_d));
                            (is_last || is_dir_or_dir_sc)
                                && (k.nfc_name == *seg || k.raw_name == *seg)
                        })
                        .copied()
                });
            match next {
                Some(node) if is_last && node.kind == EntryKind::File => {
                    let raw_path = join_raw_seg(&raw_acc, &node.raw_name);
                    let Ok(nfc_path) = nfc_acc.join(&node.nfc_name) else {
                        return Vec::new();
                    };
                    return vec![delta_node_to_entry(node.clone(), raw_path, nfc_path)];
                }
                Some(node) if node.kind == EntryKind::Symlink => {
                    let Some((is_folder, target_id, target_rec)) =
                        resolve_graph_shortcut(&by_id, node)
                    else {
                        return Vec::new();
                    };
                    raw_acc = join_raw_seg(&raw_acc, &node.raw_name);
                    let Ok(joined) = nfc_acc.join(&node.nfc_name) else {
                        return Vec::new();
                    };
                    nfc_acc = joined;
                    if is_last && !is_folder {
                        return vec![shortcut_target_to_entry(
                            &node.file_id,
                            node.parent_id.as_deref(),
                            node.mtime_ns,
                            false,
                            target_rec,
                            raw_acc,
                            nfc_acc,
                        )];
                    }
                    if !is_folder || ancestors.iter().any(|a| a == target_id) {
                        return Vec::new();
                    }
                    ancestors.push(target_id.to_string());
                    current_id = target_id.to_string();
                }
                Some(dir) => {
                    raw_acc = join_raw_seg(&raw_acc, &dir.raw_name);
                    if let Ok(joined) = nfc_acc.join(&dir.nfc_name) {
                        nfc_acc = joined;
                    }
                    if ancestors.iter().any(|a| a == &dir.file_id) {
                        return Vec::new();
                    }
                    ancestors.push(dir.file_id.clone());
                    current_id = dir.file_id.clone();
                }
                None => {
                    found = false;
                    break;
                }
            }
        }
        if !found {
            return Vec::new();
        }
        start_ids = vec![(current_id, raw_acc, nfc_acc, ancestors)];
    }

    let mut out = Vec::new();
    let mut queue: VecDeque<(String, String, RelPath, Vec<String>)> =
        start_ids.into_iter().collect();

    while let Some((dir_id, dir_raw, dir_nfc, ancestors)) = queue.pop_front() {
        let Some(children) = children_by_parent.get(dir_id.as_str()) else {
            continue;
        };
        for child in children {
            let Ok(child_nfc) = dir_nfc.join(&child.nfc_name) else {
                continue;
            };
            let child_raw = join_raw_seg(&dir_raw, &child.raw_name);

            if child.kind == EntryKind::Symlink {
                let Some((is_folder, target_id, target_rec)) =
                    resolve_graph_shortcut(&by_id, child)
                else {
                    continue;
                };
                if is_folder && ancestors.iter().any(|a| a == target_id) {
                    continue;
                }
                out.push(shortcut_target_to_entry(
                    &child.file_id,
                    child.parent_id.as_deref(),
                    child.mtime_ns,
                    is_folder,
                    target_rec,
                    child_raw.clone(),
                    child_nfc.clone(),
                ));
                if recursive && is_folder && !ancestors.iter().any(|a| a == target_id) {
                    let mut next_anc = ancestors.clone();
                    next_anc.push(target_id.to_string());
                    queue.push_back((target_id.to_string(), child_raw, child_nfc, next_anc));
                }
                continue;
            }

            let is_dir = child.kind == EntryKind::Directory;
            out.push(delta_node_to_entry(
                (*child).clone(),
                child_raw.clone(),
                child_nfc.clone(),
            ));
            if recursive && is_dir && !ancestors.iter().any(|a| a == &child.file_id) {
                let mut next_anc = ancestors.clone();
                next_anc.push(child.file_id.clone());
                queue.push_back((child.file_id.clone(), child_raw, child_nfc, next_anc));
            }
        }
    }

    out
}
