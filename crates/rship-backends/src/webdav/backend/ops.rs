//! WebDAV RFC 4918 namespace operations: `PROPFIND` metadata and concurrent BFS listing,
//! reconciled `MKCOL`/`DELETE`/`COPY`/`MOVE`, and RFC 4331 storage quota (`about`).

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use rship_core::backend::{BackendPath, EntryStream, ListOptions, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_core::types::{Entry, EntryKind, StorageQuota};
use rship_core::{Error, ErrorKind, Result};
use std::collections::{HashSet, VecDeque};
use tokio::sync::mpsc;

use crate::common::http::{HttpResponse, ReconcileAction};
use crate::common::lock_unpoisoned;
use crate::webdav::xml::{DavPropItem, PROPFIND_ALL_BODY, PROPFIND_QUOTA_BODY};

use super::{METHOD_COPY, METHOD_MOVE, WebdavBackend, dav_mutation_policy_decision};

struct BfsDir {
    raw_rel: String,
    nfc_rel: RelPath,
}

fn is_strict_descendant(parent: &RelPath, child: &RelPath) -> bool {
    if parent.is_root() {
        !child.is_root()
    } else {
        child
            .as_str()
            .strip_prefix(parent.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl WebdavBackend {
    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let raw_rel = path.raw_path();
        let is_dir = path.kind == Some(EntryKind::Directory)
            || path.nfc_path.is_root()
            || lock_unpoisoned(&self.inner.known_dirs).contains(path.nfc_path.as_str());
        let url = if is_dir {
            self.dir_url_for_rel(raw_rel)
        } else {
            self.url_for_rel(raw_rel)
        };
        let Some(items) = self.propfind(&url, "0", PROPFIND_ALL_BODY, true).await? else {
            return Ok(None);
        };
        let Some(first) = items.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(dav_item_entry(path, first)))
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

        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let backend = self.clone();
        let start_rel = prefix.clone();
        let base_depth = prefix.segments().count();
        let pruner = options.dir_pruner().cloned();

        tokio::spawn(async move {
            const MAX_LIST_CONCURRENCY: usize = 8;

            let mut visited: HashSet<RelPath> = HashSet::new();
            visited.insert(start_rel.clone());

            let mut queue: VecDeque<BfsDir> = VecDeque::new();
            queue.push_back(BfsDir {
                raw_rel: start_rel.as_str().to_string(),
                nfc_rel: start_rel,
            });

            type DavDirResult = (BfsDir, Result<Option<Vec<DavPropItem>>>);
            let mut in_flight: tokio::task::JoinSet<DavDirResult> = tokio::task::JoinSet::new();

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
                    in_flight.spawn(async move {
                        let url = b.dir_url_for_rel(&dir.raw_rel);
                        let res = b.propfind(&url, "1", PROPFIND_ALL_BODY, true).await;
                        (dir, res)
                    });
                }
                let Some(joined) = in_flight.join_next().await else {
                    break;
                };
                let (dir, res) = match joined {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!(
                                "WebDAV list task failed: {e}"
                            ))))
                            .await;
                        in_flight.abort_all();
                        return;
                    }
                };
                let items = match res {
                    Ok(Some(items)) => items,
                    Ok(None) => continue,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        in_flight.abort_all();
                        return;
                    }
                };

                for item in items {
                    let Some((raw_rel, nfc_rel)) = backend.href_to_rel(&item.href) else {
                        continue;
                    };
                    if nfc_rel == dir.nfc_rel || !is_strict_descendant(&dir.nfc_rel, &nfc_rel) {
                        continue;
                    }
                    let rel_depth = nfc_rel.segments().count().saturating_sub(base_depth);
                    if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                        continue;
                    }
                    let is_dir = item.is_collection;
                    if is_dir && pruner.as_ref().is_some_and(|p| p(&nfc_rel)) {
                        continue;
                    }
                    let bp = BackendPath::new(&raw_rel, nfc_rel.clone(), None);
                    let entry = dav_item_entry(&bp, item);
                    if tx.send(Ok(entry)).await.is_err() {
                        in_flight.abort_all();
                        return;
                    }
                    if is_dir
                        && effective_max_depth.is_none_or(|limit| rel_depth < limit)
                        && visited.insert(nfc_rel.clone())
                    {
                        queue.push_back(BfsDir { raw_rel, nfc_rel });
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
        if lock_unpoisoned(&self.inner.known_dirs).contains(path.as_str()) {
            return Ok(());
        }
        let _guard = self.inner.mkdir_lock.lock().await;
        if lock_unpoisoned(&self.inner.known_dirs).contains(path.as_str()) {
            return Ok(());
        }

        let mut acc = String::new();
        for seg in path.segments() {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            if lock_unpoisoned(&self.inner.known_dirs).contains(&acc) {
                continue;
            }
            let url = self.dir_url_for_rel(&acc);
            self.mkcol_reconciled("MKCOL", &url).await?;
            lock_unpoisoned(&self.inner.known_dirs).insert(acc.clone());
        }
        Ok(())
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Ok(());
        }
        let raw_rel = path.raw_path();
        let is_known_dir = path.kind == Some(EntryKind::Directory)
            || lock_unpoisoned(&self.inner.known_dirs).contains(path.nfc_path.as_str());
        let url = if is_known_dir {
            self.dir_url_for_rel(raw_rel)
        } else {
            self.url_for_rel(raw_rel)
        };
        if let Err(err) = self.delete_reconciled("DELETE", &url).await {
            if !is_known_dir
                && err.kind == ErrorKind::PreconditionFailed
                && err.message().contains("HTTP 409")
            {
                let dir_url = self.dir_url_for_rel(raw_rel);
                if self
                    .propfind(&dir_url, "0", PROPFIND_ALL_BODY, true)
                    .await?
                    .and_then(|v| v.into_iter().next())
                    .is_some_and(|item| item.is_collection)
                {
                    self.delete_reconciled("DELETE", &dir_url).await?;
                } else {
                    return Err(err);
                }
            } else {
                return Err(err);
            }
        }
        {
            let mut dirs = lock_unpoisoned(&self.inner.known_dirs);
            let target = path.nfc_path.as_str();
            let prefix = format!("{target}/");
            dirs.retain(|d| d != target && !d.starts_with(&prefix));
        }
        Ok(())
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
        self.ensure_parent_dirs(&init.dst_path).await?;
        let src_rel = src_path.raw_path();
        let src_url = self.url_for_rel(src_rel);
        let dst_url = self.url_for_rel(init.dst_path.as_str());

        let overwrite = if matches!(init.precondition, DstPrecondition::Absent) {
            "F"
        } else {
            "T"
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("destination"),
            HeaderValue::from_str(&dst_url)
                .map_err(|e| Error::protocol(format!("invalid Destination header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static("overwrite"),
            HeaderValue::from_static(overwrite),
        );

        let policy_cfg = self.control_retry_config(true);
        let dst_bp = BackendPath::from_rel(init.dst_path.clone());
        // Snapshot the destination BEFORE the COPY: reconcile must prove the destination
        // changed since then. With `Any`/`Absent` (e.g. `--backup-dir` archives), a stale
        // same-size file already sitting there is otherwise indistinguishable from our result,
        // and the engine would go on to overwrite or delete the only current copy.
        let dst_before = self.propfind_one(&dst_url).await?.map(DavFingerprint::of);
        let res = self
            .execute_reconcile_control(
                "COPY",
                &src_url,
                &policy_cfg,
                |active_src_url| {
                    self.build_control_request(
                        METHOD_COPY.clone(),
                        active_src_url,
                        &headers,
                        Bytes::new(),
                    )
                },
                |resp: HttpResponse| dav_mutation_policy_decision("COPY", resp, false, |_| None),
                |err, active_src_url| {
                    let dst_bp = dst_bp.clone();
                    let precondition = init.precondition.clone();
                    let dst_before = dst_before.clone();
                    let dst_url = dst_url.clone();
                    async move {
                        let Some(dst_now) = self.propfind_one(&dst_url).await? else {
                            // Nothing at the destination: the COPY did not land.
                            return Ok(ReconcileAction::Retry(err));
                        };
                        if dst_now.is_collection {
                            return Ok(ReconcileAction::Fail(err));
                        }
                        let fingerprint = DavFingerprint::of(dst_now.clone());
                        if dst_before.as_ref() == Some(&fingerprint) {
                            // Unchanged since before the COPY (same ETag, mtime and size): the
                            // file there is the pre-existing one, not our result.
                            return Ok(ReconcileAction::Retry(err));
                        }
                        // The destination changed; it must also match the source. WebDAV servers
                        // assign a fresh ETag (and often mtime) to the copy, so the comparable
                        // evidence is the size.
                        let Some(src_now) = self.propfind_one(&active_src_url).await? else {
                            return Ok(ReconcileAction::Fail(err));
                        };
                        if !src_now.is_collection
                            && src_now.content_length == dst_now.content_length
                        {
                            return Ok(ReconcileAction::Resolved(Some(dav_item_entry(
                                &dst_bp, dst_now,
                            ))));
                        }
                        // Another writer replaced the destination concurrently.
                        match precondition {
                            // We were asked to replace whatever is there: COPY again.
                            DstPrecondition::Any => Ok(ReconcileAction::Retry(err)),
                            _ => Ok(ReconcileAction::Fail(err)),
                        }
                    }
                },
            )
            .await;

        let reconciled = match res {
            Ok(v) => v,
            Err(err) => {
                if err.kind == ErrorKind::PreconditionFailed
                    && err.message().contains("HTTP 409")
                    && let Some(parent) = init.dst_path.parent()
                {
                    self.evict_known_dir_chain(&parent);
                }
                return Err(err);
            }
        };

        if let Some(entry) = reconciled {
            return Ok(Some(entry));
        }
        if let Some(entry) = self.stat(&dst_bp).await? {
            return Ok(Some(entry));
        }
        Ok(Some(Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
            checksum: None,
        }))
    }

    /// Depth-0 `PROPFIND` of `url`, or `None` when it does not exist.
    async fn propfind_one(&self, url: &str) -> Result<Option<DavPropItem>> {
        Ok(self
            .propfind(url, "0", PROPFIND_ALL_BODY, true)
            .await?
            .and_then(|items| items.into_iter().next()))
    }

    pub(super) async fn rename_impl(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if new_name.is_empty()
            || new_name == "."
            || new_name == ".."
            || new_name.contains('/')
            || new_name.contains('\\')
        {
            return Err(Error::invalid_path(format!(
                "invalid rename target `{new_name}` (must be a single filename within the same directory)"
            )));
        }
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename WebDAV root directory"));
        }

        let raw_src = path.raw_path();
        let raw_dst = match raw_src.rsplit_once('/') {
            Some((raw_parent, _)) if !raw_parent.is_empty() => format!("{raw_parent}/{new_name}"),
            _ => new_name.to_string(),
        };
        let new_rel = RelPath::parse(&raw_dst)?;
        let is_dir = path.kind == Some(EntryKind::Directory)
            || lock_unpoisoned(&self.inner.known_dirs).contains(path.nfc_path.as_str());
        let src_url = if is_dir {
            self.dir_url_for_rel(raw_src)
        } else {
            self.url_for_rel(raw_src)
        };
        let dst_url = if is_dir {
            self.dir_url_for_rel(&raw_dst)
        } else {
            self.url_for_rel(&raw_dst)
        };
        let dst_bp = BackendPath::new(&raw_dst, new_rel, None).with_kind(path.kind);

        if src_url == dst_url {
            return self.stat(path).await?.ok_or_else(|| {
                Error::not_found(format!("WebDAV object `{}` not found", path.nfc_path))
            });
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("destination"),
            HeaderValue::from_str(&dst_url)
                .map_err(|e| Error::protocol(format!("invalid Destination header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static("overwrite"),
            HeaderValue::from_static("T"),
        );

        let policy_cfg = self.control_retry_config(false);
        let reconciled = self
            .execute_reconcile_control(
                "MOVE(rename)",
                &src_url,
                &policy_cfg,
                |active_src_url| {
                    self.build_control_request(
                        METHOD_MOVE.clone(),
                        active_src_url,
                        &headers,
                        Bytes::new(),
                    )
                },
                |resp: HttpResponse| {
                    dav_mutation_policy_decision("MOVE(rename)", resp, false, |_| None)
                },
                |err, _| {
                    let src_bp = path.clone();
                    let dst_bp = dst_bp.clone();
                    async move {
                        let src_entry = self.stat(&src_bp).await?;
                        let dst_entry = self.stat(&dst_bp).await?;
                        match (src_entry, dst_entry) {
                            (None, Some(dst)) => Ok(ReconcileAction::Resolved(Some(dst))),
                            (Some(_), None) => Ok(ReconcileAction::Retry(err)),
                            (Some(src), Some(dst))
                                if src.kind != dst.kind
                                    || (src.kind == EntryKind::File && src.size != dst.size) =>
                            {
                                Ok(ReconcileAction::Retry(err))
                            }
                            _ => Ok(ReconcileAction::Fail(err)),
                        }
                    }
                },
            )
            .await?;

        {
            let mut dirs = lock_unpoisoned(&self.inner.known_dirs);
            let target = path.nfc_path.as_str();
            let prefix = format!("{target}/");
            dirs.retain(|d| d != target && !d.starts_with(&prefix));
        }

        if let Some(entry) = reconciled {
            return Ok(entry);
        }
        self.stat(&dst_bp).await?.ok_or_else(|| {
            Error::not_found(format!(
                "WebDAV renamed destination `{}` not found after MOVE",
                dst_bp.nfc_path
            ))
        })
    }

    pub(super) async fn about_impl(&self) -> Result<Option<StorageQuota>> {
        let Some(items) = self
            .propfind(&self.dir_url_for_rel(""), "0", PROPFIND_QUOTA_BODY, true)
            .await?
        else {
            return Ok(None);
        };
        let Some(first) = items.into_iter().next() else {
            return Ok(None);
        };
        if first.quota_available_bytes.is_none() && first.quota_used_bytes.is_none() {
            return Ok(None);
        }
        let total = match (first.quota_used_bytes, first.quota_available_bytes) {
            (Some(u), Some(a)) => Some(u.saturating_add(a)),
            _ => None,
        };
        Ok(Some(StorageQuota {
            total_bytes: total,
            used_bytes: first.quota_used_bytes,
            free_bytes: first.quota_available_bytes,
            trashed_bytes: None,
        }))
    }
}

/// What a WebDAV server reports about a file that changes on every write.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DavFingerprint {
    etag: Option<String>,
    last_modified_ns: i64,
    size: u64,
    is_collection: bool,
}

impl DavFingerprint {
    fn of(item: DavPropItem) -> Self {
        Self {
            etag: item.etag,
            last_modified_ns: item.last_modified_ns,
            size: item.content_length,
            is_collection: item.is_collection,
        }
    }
}

fn dav_item_entry(path: &BackendPath, item: DavPropItem) -> Entry {
    Entry {
        node_id: None,
        parent_id: None,
        raw_path: path.raw_path.clone(),
        nfc_path: path.nfc_path.clone(),
        kind: if item.is_collection {
            EntryKind::Directory
        } else {
            EntryKind::File
        },
        size: if item.is_collection {
            0
        } else {
            item.content_length
        },
        mtime_ns: item.last_modified_ns,
        ctime_ns: None,
        etag: item.etag,
        checksum: None,
    }
}
