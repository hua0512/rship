//! Dropbox v2 control-plane namespace operations: metadata (`get_metadata`),
//! paginated listing (`list_folder`), directory creation, single/batch deletion,
//! server-side copy (`copy_v2`), rename (`move_v2`), and quota (`get_space_usage`).

use std::collections::HashSet;
use std::time::{Duration, Instant};

use http::StatusCode;
use rship_core::backend::{BackendPath, EntryStream, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_core::types::{Entry, EntryKind, NodeId, StorageQuota};
use rship_core::{Error, ErrorKind, Result};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::common::http::{HttpResponse, Idempotency, PolicyDecision, ReconcileAction};

use super::{
    DbxOutcome, DropboxApiError, DropboxBackend, DropboxCall, DropboxMeta, classify_dropbox_error,
    classify_dropbox_rpc_response, parse_meta_mtime_ns, unicode_eq_ignore_case,
};

#[derive(Debug, Deserialize)]
struct ListFolderResp {
    #[serde(default)]
    entries: Vec<DropboxMeta>,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct SharingListFoldersResp {
    #[serde(default)]
    entries: Vec<SharedFolderMeta>,
}

#[derive(Debug, Deserialize)]
struct SharedFolderMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    shared_folder_id: Option<String>,
    #[serde(default)]
    path_lower: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpaceUsageResp {
    #[serde(default)]
    used: u64,
    #[serde(default)]
    allocation: Option<SpaceAllocation>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum SpaceAllocation {
    Individual {
        #[serde(default)]
        allocated: u64,
    },
    Team {
        #[serde(default)]
        used: u64,
        #[serde(default)]
        allocated: u64,
        #[serde(default)]
        user_within_team_space_allocated: u64,
        #[serde(default)]
        user_within_team_space_used_cached: Option<u64>,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum DeleteBatchResp {
    Complete {
        #[serde(default)]
        entries: Vec<DeleteBatchItemStatus>,
    },
    AsyncJobId {
        async_job_id: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum DeleteBatchCheckResp {
    InProgress,
    Complete {
        #[serde(default)]
        entries: Vec<DeleteBatchItemStatus>,
    },
    Failed {
        #[serde(default)]
        failed: Option<serde_json::Value>,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum DeleteBatchItemStatus {
    Success,
    Failure {
        #[serde(default)]
        failure: serde_json::Value,
    },
    #[serde(other)]
    Unknown,
}

fn sanitize_backup_suffix(op_id: &str) -> String {
    let cleaned: String = op_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "bak".to_string()
    } else {
        cleaned
    }
}

impl DropboxBackend {
    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let raw_rel = path.raw_path();
        let api_path = self.inner.cfg.api_path(raw_rel);
        if api_path.is_empty() {
            return Ok(Some(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::root(),
                kind: EntryKind::Directory,
                size: 0,
                mtime_ns: 0,
                ctime_ns: None,
                etag: None,
                checksum: None,
            }));
        }
        let Some(meta) = self.get_meta(&api_path).await? else {
            return Ok(None);
        };
        if path.nfc_path.is_root() {
            if meta.tag != "folder" {
                return Ok(None);
            }
            return Ok(Some(Entry {
                node_id: meta.id.clone().map(NodeId),
                parent_id: None,
                raw_path: None,
                nfc_path: RelPath::root(),
                kind: EntryKind::Directory,
                size: 0,
                mtime_ns: parse_meta_mtime_ns(&meta),
                ctime_ns: None,
                etag: meta.rev,
                checksum: None,
            }));
        }
        Ok(self.entry_from_meta(meta))
    }

    pub(super) async fn list_stream_impl(
        &self,
        prefix: &RelPath,
        recursive: bool,
    ) -> Result<EntryStream> {
        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let backend = self.clone();
        let api_path = self.inner.cfg.api_path(prefix.as_str());
        let prefix_owned = prefix.clone();
        let prefix_folded = prefix_owned.fold_key();
        let query_shared_folders = backend.inner.cfg.shared_folders
            && prefix_owned.is_root()
            && backend.inner.cfg.root_path.trim_matches('/').is_empty();

        tokio::spawn(async move {
            let mut seen_folded: HashSet<String> = HashSet::new();
            let (status, headers, body) = match backend
                .rpc_post(
                    "Dropbox list_folder",
                    "files/list_folder",
                    serde_json::json!({
                        "path": api_path,
                        "recursive": recursive,
                        "include_deleted": false,
                        "include_non_downloadable_files": false,
                    }),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            if status == StatusCode::CONFLICT {
                if DropboxApiError::parse(&body).is_not_found() {
                    return;
                }
                let _ = tx
                    .send(Err(classify_dropbox_error(
                        "Dropbox list_folder",
                        status,
                        &headers,
                        &body,
                    )))
                    .await;
                return;
            }
            let mut page: ListFolderResp = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx
                        .send(Err(Error::protocol(format!("parse list_folder: {e}"))))
                        .await;
                    return;
                }
            };

            loop {
                for m in page.entries {
                    if let Some(entry) = backend.entry_from_meta(m)
                        && entry.nfc_path.fold_key_cow() != prefix_folded
                    {
                        if query_shared_folders {
                            seen_folded.insert(entry.nfc_path.fold_key());
                        }
                        if tx.send(Ok(entry)).await.is_err() {
                            return;
                        }
                    }
                }
                if !page.has_more || page.cursor.is_empty() {
                    break;
                }
                let (st, hdr, b) = match backend
                    .rpc_post(
                        "Dropbox list_folder/continue",
                        "files/list_folder/continue",
                        serde_json::json!({ "cursor": page.cursor }),
                    )
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if st == StatusCode::CONFLICT {
                    let _ = tx
                        .send(Err(classify_dropbox_error(
                            "Dropbox list_folder/continue",
                            st,
                            &hdr,
                            &b,
                        )))
                        .await;
                    return;
                }
                page = match serde_json::from_slice(&b) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!(
                                "parse list_folder/continue: {e}"
                            ))))
                            .await;
                        return;
                    }
                };
            }

            if query_shared_folders
                && let Ok((st, _, b)) = backend
                    .rpc_post(
                        "Dropbox sharing/list_folders",
                        "sharing/list_folders",
                        serde_json::json!({ "limit": 1000 }),
                    )
                    .await
                && st.is_success()
                && let Ok(shared) = serde_json::from_slice::<SharingListFoldersResp>(&b)
            {
                for sf in shared.entries {
                    if sf.path_lower.is_some() || sf.name.is_empty() {
                        continue;
                    }
                    let Ok(nfc_path) = RelPath::parse(&sf.name) else {
                        continue;
                    };
                    if !seen_folded.insert(nfc_path.fold_key()) {
                        continue;
                    }
                    let entry = Entry {
                        node_id: sf.shared_folder_id.map(NodeId),
                        parent_id: None,
                        raw_path: rship_core::types::raw_path_override(&nfc_path, &sf.name),
                        nfc_path,
                        kind: EntryKind::Directory,
                        size: 0,
                        mtime_ns: 0,
                        ctime_ns: None,
                        etag: None,
                        checksum: None,
                    };
                    if tx.send(Ok(entry)).await.is_err() {
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
        let api_path = self.inner.cfg.api_path(path.as_str());
        let (status, headers, body) = self
            .rpc_post(
                "Dropbox create_folder_v2",
                "files/create_folder_v2",
                serde_json::json!({ "path": api_path, "autorename": false }),
            )
            .await?;
        if status == StatusCode::CONFLICT {
            // Dropbox returns `path/conflict/folder` when the folder already exists (idempotent).
            if matches!(
                DropboxApiError::parse(&body),
                DropboxApiError::FolderConflict { .. }
            ) {
                return Ok(());
            }
            return Err(classify_dropbox_error(
                "Dropbox create_folder_v2",
                status,
                &headers,
                &body,
            ));
        }
        Ok(())
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Ok(());
        }
        let raw_rel = path.raw_path();
        let api_path = self.inner.cfg.api_path(raw_rel);
        let (status, headers, body) = self
            .rpc_post(
                "Dropbox delete_v2",
                "files/delete_v2",
                serde_json::json!({ "path": api_path }),
            )
            .await?;
        if status == StatusCode::CONFLICT && !DropboxApiError::parse(&body).is_not_found() {
            return Err(classify_dropbox_error(
                "Dropbox delete_v2",
                status,
                &headers,
                &body,
            ));
        }
        Ok(())
    }

    pub(super) async fn delete_batch_impl(
        &self,
        paths: &[BackendPath],
    ) -> Result<Vec<(BackendPath, Error)>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut failures = Vec::new();
        let mut non_root = Vec::with_capacity(paths.len());
        for bp in paths {
            if bp.nfc_path.is_root() {
                failures.push((
                    bp.clone(),
                    Error::invalid_path("cannot delete Dropbox root path"),
                ));
            } else {
                non_root.push(bp);
            }
        }
        for chunk in non_root.chunks(1000) {
            let entries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|bp| {
                    let raw_rel = bp.raw_path();
                    serde_json::json!({ "path": self.inner.cfg.api_path(raw_rel) })
                })
                .collect();
            let (status, headers, body) = self
                .rpc_post(
                    "Dropbox delete_batch",
                    "files/delete_batch",
                    serde_json::json!({ "entries": entries }),
                )
                .await?;
            if status == StatusCode::CONFLICT {
                for bp in chunk {
                    failures.push((
                        (*bp).clone(),
                        classify_dropbox_error("Dropbox delete_batch", status, &headers, &body),
                    ));
                }
                continue;
            }
            let parsed: DeleteBatchResp = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("parse Dropbox delete_batch: {e}")))?;
            let items = match parsed {
                DeleteBatchResp::Complete { entries } => entries,
                DeleteBatchResp::AsyncJobId { async_job_id } => {
                    self.poll_delete_batch(&async_job_id).await?
                }
                DeleteBatchResp::Unknown => {
                    return Err(Error::protocol(format!(
                        "unexpected Dropbox delete_batch response: {}",
                        String::from_utf8_lossy(&body).trim()
                    )));
                }
            };
            for (i, bp) in chunk.iter().enumerate() {
                match items.get(i) {
                    Some(DeleteBatchItemStatus::Success) => {}
                    Some(DeleteBatchItemStatus::Failure { failure }) => {
                        let api_err = DropboxApiError::from_error_value(failure, "");
                        if !api_err.is_not_found() {
                            let err = match api_err {
                                DropboxApiError::InsufficientSpace { .. } => Error::new(
                                    ErrorKind::QuotaExceeded,
                                    rship_core::RetryClass::Permanent,
                                    "Dropbox delete_batch: storage quota exceeded",
                                ),
                                other => Error::protocol(format!(
                                    "Dropbox delete_batch failed: {}",
                                    other.summary()
                                )),
                            };
                            failures.push(((*bp).clone(), err));
                        }
                    }
                    Some(DeleteBatchItemStatus::Unknown) | None => {
                        failures.push((
                            (*bp).clone(),
                            Error::protocol("Dropbox delete_batch returned incomplete item status"),
                        ));
                    }
                }
            }
        }
        Ok(failures)
    }

    async fn poll_delete_batch(&self, async_job_id: &str) -> Result<Vec<DeleteBatchItemStatus>> {
        let timeout = self
            .inner
            .transport
            .config()
            .long_control_timeout
            .max(Duration::from_secs(60));
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(25);
        loop {
            let (status, headers, body) = self
                .rpc_post(
                    "Dropbox delete_batch/check",
                    "files/delete_batch/check",
                    serde_json::json!({ "async_job_id": async_job_id }),
                )
                .await?;
            if status == StatusCode::CONFLICT {
                return Err(classify_dropbox_error(
                    "Dropbox delete_batch/check",
                    status,
                    &headers,
                    &body,
                ));
            }
            let check: DeleteBatchCheckResp = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("parse Dropbox delete_batch/check: {e}")))?;
            match check {
                DeleteBatchCheckResp::Complete { entries } => return Ok(entries),
                DeleteBatchCheckResp::InProgress => {
                    if Instant::now() >= deadline {
                        return Err(Error::timeout(format!(
                            "Dropbox delete_batch/check timed out for job `{async_job_id}`"
                        )));
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(1));
                }
                DeleteBatchCheckResp::Failed { failed } => {
                    let detail = failed
                        .map(|v| {
                            DropboxApiError::from_error_value(&v, "")
                                .summary()
                                .to_string()
                        })
                        .unwrap_or_else(|| "unknown failure".to_string());
                    return Err(Error::protocol(format!(
                        "Dropbox delete_batch job `{async_job_id}` failed: {detail}"
                    )));
                }
                DeleteBatchCheckResp::Unknown => {
                    return Err(Error::protocol(format!(
                        "unexpected Dropbox delete_batch/check response: {}",
                        String::from_utf8_lossy(&body).trim()
                    )));
                }
            }
        }
    }

    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        src_endpoint == self.endpoint_identity()
    }

    async fn try_copy_v2(&self, from_path: &str, to_path: &str) -> Result<Option<Entry>> {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Only treat `409 to/conflict` as a possible lost-response replay when an earlier
        // attempt actually entered reconciliation after an ambiguous failure; an initial
        // `409 to/conflict` means the destination already existed before our call.
        let saw_ambiguous = AtomicBool::new(false);
        let outcome = self
            .dropbox_request(
                "Dropbox copy_v2",
                DropboxCall::rpc(
                    "files/copy_v2",
                    &serde_json::json!({
                        "from_path": from_path,
                        "to_path": to_path,
                        "autorename": false,
                    }),
                )?,
                Some(self.inner.transport.config().long_control_timeout),
                Idempotency::NonIdempotent,
                |resp| {
                    if resp.status == StatusCode::CONFLICT {
                        let parsed = DropboxApiError::parse(&resp.body);
                        if matches!(parsed, DropboxApiError::ToConflict { .. }) {
                            let err = Error::conflict(format!(
                                "Dropbox copy_v2: HTTP 409: {}",
                                parsed.summary()
                            ));
                            return if saw_ambiguous.load(Ordering::Acquire) {
                                PolicyDecision::Reconcile(err)
                            } else {
                                PolicyDecision::Fail(err)
                            };
                        }
                    }
                    classify_dropbox_rpc_response("Dropbox copy_v2", resp)
                        .map_ok(DbxOutcome::Response)
                },
                |err| {
                    if err.kind != ErrorKind::Conflict {
                        saw_ambiguous.store(true, Ordering::Release);
                    }
                    let from_path = from_path.to_string();
                    let to_path = to_path.to_string();
                    async move {
                        let Some(dst) = self.get_meta(&to_path).await? else {
                            return Ok(ReconcileAction::Retry(err));
                        };
                        let src = self.get_meta(&from_path).await?;
                        let same_content = src.as_ref().is_some_and(|src| {
                            src.tag == "file"
                                && dst.tag == "file"
                                && src.size == dst.size
                                && src.content_hash.is_some()
                                && src.content_hash == dst.content_hash
                        });
                        if same_content {
                            return Ok(ReconcileAction::Resolved(DbxOutcome::Reconciled(dst)));
                        }
                        if err.kind == ErrorKind::Conflict {
                            return Ok(ReconcileAction::Fail(err));
                        }
                        Ok(ReconcileAction::Retry(err))
                    }
                },
            )
            .await?;
        let (status, headers, body) = match outcome {
            DbxOutcome::Reconciled(meta) => return Ok(self.entry_from_meta(meta)),
            DbxOutcome::Response(r) => r,
        };
        if status == StatusCode::CONFLICT {
            if DropboxApiError::parse(&body).is_not_found() {
                return Ok(None);
            }
            return Err(classify_dropbox_error(
                "Dropbox copy_v2",
                status,
                &headers,
                &body,
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse Dropbox copy_v2: {e}")))?;
        let meta: DropboxMeta = serde_json::from_value(v["metadata"].clone())
            .map_err(|e| Error::protocol(format!("parse Dropbox copy_v2 metadata: {e}")))?;
        Ok(self.entry_from_meta(meta))
    }

    async fn move_v2_simple(&self, from_path: &str, to_path: &str) -> Result<()> {
        let (status, headers, body) = self
            .execute_rpc_post(
                "Dropbox move_v2",
                "files/move_v2",
                serde_json::json!({
                    "from_path": from_path,
                    "to_path": to_path,
                    "autorename": false,
                }),
                Some(self.inner.transport.config().long_control_timeout),
            )
            .await?;
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox move_v2",
                status,
                &headers,
                &body,
            ));
        }
        Ok(())
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
        let src_rel = src_path.raw_path();
        let from_path = self.inner.cfg.api_path(src_rel);
        let to_path = self.inner.cfg.api_path(init.dst_path.as_str());
        if from_path.is_empty() || to_path.is_empty() {
            return Err(Error::invalid_path("cannot server-side copy Dropbox root"));
        }

        if unicode_eq_ignore_case(&from_path, &to_path) {
            let Some(dst) = self.get_meta(&to_path).await? else {
                return Ok(None);
            };
            if dst.tag != "file" {
                return Err(Error::conflict("cannot overwrite Dropbox folder with file"));
            }
            match &init.precondition {
                DstPrecondition::Absent => {
                    return Err(Error::conflict(format!(
                        "Dropbox copy_v2 destination `{to_path}` already exists"
                    )));
                }
                DstPrecondition::Existing {
                    etag: Some(exp), ..
                } if dst.rev.as_deref() != Some(exp.as_str()) => {
                    return Err(Error::precondition_failed(format!(
                        "Dropbox copy_v2 precondition mismatch on `{to_path}`"
                    )));
                }
                _ => return Ok(self.entry_from_meta(dst)),
            }
        }

        if let DstPrecondition::Existing { etag, .. } = &init.precondition {
            let Some(dst) = self.get_meta(&to_path).await? else {
                return Err(Error::precondition_failed(format!(
                    "Dropbox copy_v2 precondition failed: `{to_path}` does not exist"
                )));
            };
            if dst.tag != "file" {
                return Err(Error::conflict("cannot overwrite Dropbox folder with file"));
            }
            if let Some(exp) = etag
                && dst.rev.as_deref() != Some(exp.as_str())
            {
                return Err(Error::precondition_failed(format!(
                    "Dropbox copy_v2 precondition mismatch on `{to_path}`"
                )));
            }
        }

        match self.try_copy_v2(&from_path, &to_path).await {
            Ok(res) => Ok(res),
            Err(err)
                if err.kind == ErrorKind::Conflict
                    && !matches!(init.precondition, DstPrecondition::Absent) =>
            {
                let Some(dst) = self.get_meta(&to_path).await? else {
                    // Destination vanished concurrently; retry copy_v2 once.
                    return self.try_copy_v2(&from_path, &to_path).await;
                };
                if dst.tag != "file" {
                    return Err(Error::conflict("cannot overwrite Dropbox folder with file"));
                }
                if let DstPrecondition::Existing {
                    etag: Some(exp), ..
                } = &init.precondition
                    && dst.rev.as_deref() != Some(exp.as_str())
                {
                    return Err(Error::precondition_failed(format!(
                        "Dropbox copy_v2 precondition mismatch on `{to_path}`"
                    )));
                }
                // `copy_v2` has no `overwrite` flag; move destination to a temporary backup,
                // run `copy_v2`, and remove backup on success (or restore on failure).
                let backup_path = format!(
                    "{to_path}.rship_bak_{}",
                    sanitize_backup_suffix(&init.op_id)
                );
                if self.move_v2_simple(&to_path, &backup_path).await.is_err() {
                    return Ok(None);
                }
                match self.try_copy_v2(&from_path, &to_path).await {
                    Ok(Some(entry)) => {
                        let _ = self
                            .rpc_post(
                                "Dropbox cleanup copy backup",
                                "files/delete_v2",
                                serde_json::json!({ "path": backup_path }),
                            )
                            .await;
                        Ok(Some(entry))
                    }
                    Ok(None) => {
                        let _ = self.move_v2_simple(&backup_path, &to_path).await;
                        Ok(None)
                    }
                    Err(copy_err) => {
                        let _ = self.move_v2_simple(&backup_path, &to_path).await;
                        Err(copy_err)
                    }
                }
            }
            Err(err) => Err(err),
        }
    }

    pub(super) async fn rename_impl(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename Dropbox root path"));
        }
        if new_name.is_empty()
            || new_name == "."
            || new_name == ".."
            || new_name.contains('/')
            || new_name.contains('\\')
            || new_name.contains('\0')
        {
            return Err(Error::invalid_path(format!(
                "invalid rename target name `{new_name}`"
            )));
        }
        let from_rel = path.raw_path();
        let trimmed_raw = from_rel.trim_matches('/');
        let to_rel = match trimmed_raw.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => format!("{parent}/{new_name}"),
            _ => new_name.to_string(),
        };
        let from_path = self.inner.cfg.api_path(from_rel);
        let to_path = self.inner.cfg.api_path(&to_rel);
        // move_v2 keeps the file id, so the id recorded BEFORE the move proves a later
        // `to_path` entry is our moved file (the replay after a lost response gets 409
        // `from_lookup/not_found`).
        let Some(src_meta) = self.get_meta(&from_path).await? else {
            return Err(Error::not_found(format!(
                "Dropbox move_v2 source `{from_path}` not found"
            )));
        };
        if from_path == to_path {
            return self
                .entry_from_meta(src_meta)
                .ok_or_else(|| Error::protocol("Dropbox move_v2 returned non-file metadata"));
        }
        let is_case_only = unicode_eq_ignore_case(&from_path, &to_path);
        let src_id = src_meta.id.clone();
        let outcome = self
            .dropbox_request(
                "Dropbox move_v2",
                DropboxCall::rpc(
                    "files/move_v2",
                    &serde_json::json!({
                        "from_path": from_path,
                        "to_path": to_path,
                        "autorename": false,
                    }),
                )?,
                None,
                Idempotency::NonIdempotent,
                |resp| {
                    reconcile_on_409(resp, "Dropbox move_v2", |e| {
                        matches!(
                            e,
                            DropboxApiError::FromNotFound { .. }
                                | DropboxApiError::ToConflict { .. }
                        )
                    })
                },
                |err| {
                    let to_path = to_path.clone();
                    let src_id = src_id.clone();
                    let new_name_owned = new_name.to_string();
                    async move {
                        if let Some(dst) = self.get_meta(&to_path).await?
                            && src_id.is_some()
                            && dst.id == src_id
                        {
                            let dst_leaf = dst.name.as_deref().or_else(|| {
                                dst.path_display
                                    .as_deref()
                                    .and_then(|p| p.rsplit('/').next())
                            });
                            if !is_case_only || dst_leaf.is_some_and(|leaf| leaf == new_name_owned)
                            {
                                return Ok(ReconcileAction::Resolved(DbxOutcome::Reconciled(dst)));
                            }
                        }
                        if err.kind == ErrorKind::Conflict {
                            return Ok(ReconcileAction::Fail(err));
                        }
                        Ok(ReconcileAction::Retry(err))
                    }
                },
            )
            .await?;
        let (status, headers, body) = match outcome {
            DbxOutcome::Reconciled(meta) => {
                return self
                    .entry_from_meta(meta)
                    .ok_or_else(|| Error::protocol("Dropbox move_v2 returned non-file metadata"));
            }
            DbxOutcome::Response(r) => r,
        };
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox move_v2",
                status,
                &headers,
                &body,
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse Dropbox move_v2: {e}")))?;
        let meta: DropboxMeta = serde_json::from_value(v["metadata"].clone())
            .map_err(|e| Error::protocol(format!("parse Dropbox move_v2 metadata: {e}")))?;
        self.entry_from_meta(meta)
            .ok_or_else(|| Error::protocol("Dropbox move_v2 returned non-file metadata"))
    }

    pub(super) async fn about_impl(&self) -> Result<Option<StorageQuota>> {
        let (status, headers, body) = self
            .rpc_post(
                "Dropbox get_space_usage",
                "users/get_space_usage",
                serde_json::Value::Null,
            )
            .await?;
        if status == StatusCode::CONFLICT {
            return Err(classify_dropbox_error(
                "Dropbox get_space_usage",
                status,
                &headers,
                &body,
            ));
        }
        let resp: SpaceUsageResp = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse get_space_usage: {e}")))?;
        let (total_bytes, used_bytes, free_bytes) = match resp.allocation {
            Some(SpaceAllocation::Individual { allocated }) => (
                Some(allocated),
                Some(resp.used),
                Some(allocated.saturating_sub(resp.used)),
            ),
            Some(SpaceAllocation::Team {
                used: team_used,
                allocated: team_allocated,
                user_within_team_space_allocated,
                user_within_team_space_used_cached,
            }) => {
                if user_within_team_space_allocated > 0 {
                    let user_used = user_within_team_space_used_cached.unwrap_or(resp.used);
                    let team_free = team_allocated.saturating_sub(team_used);
                    let user_free = user_within_team_space_allocated.saturating_sub(user_used);
                    (
                        Some(user_within_team_space_allocated),
                        Some(user_used),
                        Some(user_free.min(team_free)),
                    )
                } else {
                    (
                        Some(team_allocated),
                        Some(team_used),
                        Some(team_allocated.saturating_sub(team_used)),
                    )
                }
            }
            Some(SpaceAllocation::Unknown) | None => (None, Some(resp.used), None),
        };
        Ok(Some(StorageQuota {
            total_bytes,
            used_bytes,
            free_bytes,
            trashed_bytes: None,
        }))
    }
}

/// Classify a non-idempotent Dropbox commit's reply: a 409 whose structured
/// [`DropboxApiError`] matches `should_reconcile` is what a replay after a lost response
/// gets, so it is reconciled (as [`ErrorKind::Conflict`]); everything else is classified as usual.
pub(super) fn reconcile_on_409(
    resp: HttpResponse,
    context: &str,
    should_reconcile: impl Fn(&DropboxApiError) -> bool,
) -> PolicyDecision<DbxOutcome> {
    if resp.status == StatusCode::CONFLICT {
        let parsed = DropboxApiError::parse(&resp.body);
        if should_reconcile(&parsed) {
            return PolicyDecision::Reconcile(Error::conflict(format!(
                "{context}: HTTP 409: {}",
                parsed.summary()
            )));
        }
    }
    classify_dropbox_rpc_response(context, resp).map_ok(DbxOutcome::Response)
}
