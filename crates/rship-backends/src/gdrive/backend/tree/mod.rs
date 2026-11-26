//! Google Drive metadata RPCs, path resolution, single-flight `mkdir`,
//! `stat`, `list_stream`, `delete`, and `compute_hash`.

pub(super) mod listing;
#[cfg(test)]
mod tests;

use http::{Method, StatusCode};
use rship_core::backend::{BackendPath, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::{DeltaChangeBatch, DstPrecondition};
use rship_core::types::{Checksum, Entry, EntryKind, HashKind, NodeId};
use rship_core::{Error, Result, RetryClass};
use std::collections::{HashMap, HashSet};
use tracing::warn;

use crate::common::http::{
    Idempotency, PolicyDecision, bearer_header_value, execute_with_auth_policy,
};
use crate::gdrive::error::classify_gdrive_error;
use crate::gdrive::query::{
    CHANGES_LIST_FIELDS, FILE_FIELDS, FILE_LIST_FIELDS, FOLDER_MIME, SHORTCUT_MIME,
    escape_query_literal, is_exportable_workspace_doc, parse_rfc3339_nanos,
};

use super::{
    ChangeListResponse, DriveFile, FileListResponse, GdriveBackend, GenerateIdsResponse,
    StartPageTokenResponse,
};

const MAX_SHORTCUT_HOPS: usize = 8;
const GENERATE_IDS_BATCH_SIZE: &str = "100";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildFilter {
    Any,
    DirOrFolderShortcut,
}

pub(super) enum ChangesPageOutcome {
    Page(ChangeListResponse),
    TokenExpired,
}

pub(super) enum ProbeFileOutcome {
    Found(Box<DriveFile>),
    NotFound,
    Forbidden,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedDriveNode {
    pub node: DriveFile,
    pub target: Option<DriveFile>,
}

impl ResolvedDriveNode {
    pub(crate) fn own_id(&self) -> &str {
        &self.node.id
    }

    pub(crate) fn content_id(&self) -> &str {
        self.target.as_ref().map_or(&self.node.id, |t| &t.id)
    }

    pub(crate) fn effective_mime(&self) -> &str {
        self.target
            .as_ref()
            .map_or(&self.node.mime_type, |t| &t.mime_type)
    }

    pub(crate) fn into_entry(
        self,
        backend: &GdriveBackend,
        raw_path: impl AsRef<str>,
        nfc_path: RelPath,
    ) -> Entry {
        let Some(target) = self.target else {
            return backend.drive_file_to_entry(&self.node, raw_path, nfc_path);
        };
        let is_dir = target.mime_type == FOLDER_MIME;
        let kind = if is_dir {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let mtime_ns = target
            .modified_time
            .as_deref()
            .or(self.node.modified_time.as_deref())
            .map(parse_rfc3339_nanos)
            .unwrap_or(0);
        let checksum = if is_dir { None } else { target.best_checksum() };
        Entry {
            node_id: Some(NodeId(self.node.id)),
            parent_id: self.node.parents.first().cloned().map(NodeId),
            raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
            nfc_path,
            kind,
            size: if is_dir { 0 } else { target.size },
            mtime_ns,
            ctime_ns: None,
            etag: if is_dir {
                None
            } else {
                target.md5_checksum.clone()
            },
            checksum,
        }
    }
}

pub(super) struct RemoteChildrenPage {
    pub files: Vec<DriveFile>,
    pub next_page_token: Option<String>,
    pub incomplete_search: bool,
}

impl GdriveBackend {
    pub(super) fn build_files_list_url(&self, q: &str, page_token: Option<&str>) -> Result<String> {
        let mut params: Vec<(&str, &str)> = vec![
            ("q", q),
            ("fields", FILE_LIST_FIELDS),
            ("pageSize", "1000"),
            ("supportsAllDrives", "true"),
        ];
        if self.inner.cfg.is_app_data_folder() {
            params.push(("spaces", "appDataFolder"));
        } else {
            params.push(("includeItemsFromAllDrives", "true"));
        }
        if let Some(drive_id) = &self.inner.cfg.shared_drive_id {
            params.push(("corpora", "drive"));
            params.push(("driveId", drive_id.as_str()));
        }
        if let Some(pt) = page_token {
            params.push(("pageToken", pt));
        }
        self.api_url(&["files"], &params)
    }

    pub(super) fn build_file_url(&self, file_id: &str) -> Result<String> {
        self.api_url(
            &["files", file_id],
            &[("fields", FILE_FIELDS), ("supportsAllDrives", "true")],
        )
    }

    pub(super) async fn get_file_by_id(&self, file_id: &str) -> Result<Option<DriveFile>> {
        let url = self.build_file_url(file_id)?;
        let (status, _, body) = self
            .control_request("files.get", Method::GET, url, None, false, true)
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let file: DriveFile = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode files.get JSON: {e}")))?;
        if file.mime_type == SHORTCUT_MIME
            && let Some(sd) = &file.shortcut_details
        {
            self.record_shortcut_target(&file.id, &sd.target_id, &sd.target_mime_type);
        }
        Ok(Some(file))
    }

    pub(super) async fn get_file_by_id_tolerating_403(
        &self,
        file_id: &str,
    ) -> Result<ProbeFileOutcome> {
        let url = self.build_file_url(file_id)?;
        let cfg = self.retry_policy_config(false);
        let outcome = execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            "files.get",
            &cfg,
            Idempotency::Idempotent,
            || {
                let url = url.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .get(&url)
                        .header(http::header::AUTHORIZATION, auth_hdr);
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                if resp.status == StatusCode::NOT_FOUND {
                    return PolicyDecision::Ok(ProbeFileOutcome::NotFound);
                }
                if resp.status.is_success() {
                    return match serde_json::from_slice::<DriveFile>(&resp.body) {
                        Ok(file) => PolicyDecision::Ok(ProbeFileOutcome::Found(Box::new(file))),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "files.get: decode JSON: {e}"
                        ))),
                    };
                }
                let err = classify_gdrive_error(
                    "files.get",
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    false,
                );
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else if resp.status == StatusCode::FORBIDDEN {
                    PolicyDecision::Ok(ProbeFileOutcome::Forbidden)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
        )
        .await?;
        if let ProbeFileOutcome::Found(ref file) = outcome
            && file.mime_type == SHORTCUT_MIME
            && let Some(sd) = &file.shortcut_details
        {
            self.record_shortcut_target(&file.id, &sd.target_id, &sd.target_mime_type);
        }
        Ok(outcome)
    }

    pub(crate) async fn resolve_shortcut_target(
        &self,
        file: DriveFile,
    ) -> Result<Option<DriveFile>> {
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(file.id.clone());
        let mut cur = file;

        for _ in 0..MAX_SHORTCUT_HOPS {
            if cur.mime_type != SHORTCUT_MIME {
                if (!self.inner.cfg.trashed_only && cur.trashed)
                    || is_exportable_workspace_doc(&cur.mime_type)
                {
                    return Ok(None);
                }
                return Ok(Some(cur));
            }
            let Some(sd) = cur.shortcut_details.as_ref() else {
                return Ok(None);
            };
            self.record_shortcut_target(&cur.id, &sd.target_id, &sd.target_mime_type);
            if !visited.insert(sd.target_id.clone()) {
                warn!(
                    shortcut_id = %cur.id,
                    target_id = %sd.target_id,
                    "shortcut chain cycle detected; skipping"
                );
                return Ok(None);
            }
            match self.get_file_by_id_tolerating_403(&sd.target_id).await? {
                ProbeFileOutcome::Found(next) => cur = *next,
                ProbeFileOutcome::NotFound | ProbeFileOutcome::Forbidden => {
                    warn!(
                        shortcut_id = %cur.id,
                        target_id = %sd.target_id,
                        "skipping broken or inaccessible shortcut target"
                    );
                    return Ok(None);
                }
            }
        }
        warn!(
            shortcut_id = %cur.id,
            "shortcut chain exceeded max hops ({MAX_SHORTCUT_HOPS}); skipping"
        );
        Ok(None)
    }

    pub(super) fn list_query_for_parent(&self, parent_id: &str) -> String {
        let trashed_val = if self.inner.cfg.trashed_only {
            "true"
        } else {
            "false"
        };
        if self.inner.cfg.shared_with_me && parent_id == self.inner.cfg.effective_root_id() {
            format!("sharedWithMe = true and trashed = {trashed_val}")
        } else {
            format!(
                "'{}' in parents and trashed = {trashed_val}",
                escape_query_literal(parent_id)
            )
        }
    }

    pub(super) async fn list_children_remote_page(
        &self,
        parent_id: &str,
        page_token: Option<&str>,
    ) -> Result<RemoteChildrenPage> {
        let q = self.list_query_for_parent(parent_id);
        let url = self.build_files_list_url(&q, page_token)?;
        let (_, _, body) = self
            .control_request("files.list", Method::GET, url, None, false, false)
            .await?;
        let page: FileListResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode files.list JSON: {e}")))?;
        let next_page_token = page.next_page_token.filter(|tok| !tok.is_empty());
        Ok(RemoteChildrenPage {
            files: page.files,
            next_page_token,
            incomplete_search: page.incomplete_search,
        })
    }

    pub(super) async fn list_children_remote(
        &self,
        parent_id: &str,
    ) -> Result<(Vec<DriveFile>, bool)> {
        let mut all = Vec::new();
        let mut incomplete_any = false;
        let mut page_token: Option<String> = None;

        loop {
            let page = self
                .list_children_remote_page(parent_id, page_token.as_deref())
                .await?;
            if page.incomplete_search {
                incomplete_any = true;
            }
            all.extend(page.files);
            match page.next_page_token {
                Some(tok) => page_token = Some(tok),
                None => break,
            }
        }
        Ok((all, incomplete_any))
    }

    pub(super) async fn find_child_in_parent(
        &self,
        parent_id: &str,
        name: &str,
        filter: ChildFilter,
    ) -> Result<Option<DriveFile>> {
        let trashed_val = if self.inner.cfg.trashed_only {
            "true"
        } else {
            "false"
        };
        let parent_clause =
            if self.inner.cfg.shared_with_me && parent_id == self.inner.cfg.effective_root_id() {
                "sharedWithMe = true".to_string()
            } else {
                format!("'{}' in parents", escape_query_literal(parent_id))
            };
        let mut q = format!(
            "{parent_clause} and name = '{}' and trashed = {trashed_val}",
            escape_query_literal(name)
        );
        match filter {
            ChildFilter::Any => {}
            ChildFilter::DirOrFolderShortcut => {
                q.push_str(&format!(
                    " and (mimeType = '{FOLDER_MIME}' or mimeType = '{SHORTCUT_MIME}')"
                ));
            }
        }

        let mut page_token: Option<String> = None;
        let mut fallback_shortcut: Option<DriveFile> = None;

        loop {
            let url = self.build_files_list_url(&q, page_token.as_deref())?;
            let (_, _, body) = self
                .control_request("files.list(find)", Method::GET, url, None, false, false)
                .await?;
            let page: FileListResponse = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("decode files.list(find) JSON: {e}")))?;

            for f in page.files {
                if (!self.inner.cfg.trashed_only && f.trashed)
                    || is_exportable_workspace_doc(&f.mime_type)
                {
                    continue;
                }
                if f.mime_type == SHORTCUT_MIME
                    && let Some(sd) = &f.shortcut_details
                {
                    self.record_shortcut_target(&f.id, &sd.target_id, &sd.target_mime_type);
                }
                match filter {
                    ChildFilter::Any => return Ok(Some(f)),
                    ChildFilter::DirOrFolderShortcut => {
                        if f.mime_type == FOLDER_MIME {
                            return Ok(Some(f));
                        }
                        if f.mime_type == SHORTCUT_MIME
                            && f.shortcut_details.as_ref().is_some_and(|sd| {
                                sd.target_mime_type == FOLDER_MIME
                                    || sd.target_mime_type == SHORTCUT_MIME
                            })
                            && fallback_shortcut.is_none()
                        {
                            fallback_shortcut = Some(f);
                        }
                    }
                }
            }

            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(tok) => page_token = Some(tok),
                None => break,
            }
        }

        Ok(fallback_shortcut)
    }

    pub(super) async fn find_non_folder_children_in_parent(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<(Vec<DriveFile>, Vec<DriveFile>)> {
        let trashed_val = if self.inner.cfg.trashed_only {
            "true"
        } else {
            "false"
        };
        let parent_clause =
            if self.inner.cfg.shared_with_me && parent_id == self.inner.cfg.effective_root_id() {
                "sharedWithMe = true".to_string()
            } else {
                format!("'{}' in parents", escape_query_literal(parent_id))
            };
        let q = format!(
            "{parent_clause} and name = '{}' and mimeType != '{FOLDER_MIME}' and trashed = {trashed_val}",
            escape_query_literal(name)
        );
        let mut regular_files = Vec::new();
        let mut shortcuts = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let url = self.build_files_list_url(&q, page_token.as_deref())?;
            let (_, _, body) = self
                .control_request(
                    "files.list(find_non_dir)",
                    Method::GET,
                    url,
                    None,
                    false,
                    false,
                )
                .await?;
            let page: FileListResponse = serde_json::from_slice(&body).map_err(|e| {
                Error::protocol(format!("decode files.list(find_non_dir) JSON: {e}"))
            })?;

            for f in page.files {
                if (!self.inner.cfg.trashed_only && f.trashed)
                    || f.mime_type == FOLDER_MIME
                    || is_exportable_workspace_doc(&f.mime_type)
                {
                    continue;
                }
                if f.mime_type == SHORTCUT_MIME {
                    if let Some(sd) = &f.shortcut_details {
                        self.record_shortcut_target(&f.id, &sd.target_id, &sd.target_mime_type);
                    }
                    shortcuts.push(f);
                } else {
                    regular_files.push(f);
                }
            }

            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(tok) => page_token = Some(tok),
                None => break,
            }
        }
        Ok((regular_files, shortcuts))
    }

    pub(super) async fn find_child_by_op_id(
        &self,
        parent_id: &str,
        op_id: &str,
    ) -> Result<Option<DriveFile>> {
        let q = format!(
            "'{}' in parents and appProperties has {{ key='rship_op_id' and value='{}' }} and trashed = false",
            escape_query_literal(parent_id),
            escape_query_literal(op_id)
        );
        let url = self.build_files_list_url(&q, None)?;
        let (_, _, body) = self
            .control_request(
                "files.list(reconcile)",
                Method::GET,
                url,
                None,
                false,
                false,
            )
            .await?;
        let page: FileListResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode files.list(reconcile) JSON: {e}")))?;

        for f in page.files {
            if f.trashed
                || f.mime_type == FOLDER_MIME
                || f.mime_type == SHORTCUT_MIME
                || is_exportable_workspace_doc(&f.mime_type)
            {
                continue;
            }
            if f.app_properties
                .get("rship_op_id")
                .is_some_and(|v| v == op_id)
            {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    /// Pre-generate a globally unique Google Drive `fileId` via pooled `files.generateIds`
    /// (`count=100`) so creates (`mkdir`, single-shot multipart, resumable uploads, and
    /// `files.copy`) can reconcile lost responses without creating duplicate objects.
    pub async fn generate_file_id(&self) -> Result<String> {
        let space = if self.inner.cfg.is_app_data_folder() {
            "appDataFolder"
        } else {
            "drive"
        };
        let mut pool = self.inner.generated_id_pool.lock().await;
        if pool.0 == space
            && let Some(id) = pool.1.pop()
        {
            return Ok(id);
        }

        let url = self.api_url(
            &["files", "generateIds"],
            &[("count", GENERATE_IDS_BATCH_SIZE), ("space", space)],
        )?;
        let (_, _, body) = self
            .control_request("files.generateIds", Method::GET, url, None, false, false)
            .await?;
        let parsed: GenerateIdsResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode files.generateIds JSON: {e}")))?;
        let mut ids: Vec<String> = parsed.ids.into_iter().filter(|id| !id.is_empty()).collect();
        if ids.is_empty() {
            return Err(Error::protocol("files.generateIds returned empty ids list"));
        }
        ids.reverse();
        let first = ids.pop().expect("non-empty verified");
        pool.0 = space.to_string();
        pool.1 = ids;
        Ok(first)
    }

    pub(super) async fn get_start_page_token(&self) -> Result<String> {
        let mut params = vec![("supportsAllDrives", "true")];
        if let Some(drive_id) = &self.inner.cfg.shared_drive_id {
            params.push(("driveId", drive_id.as_str()));
        }
        let url = self.api_url(&["changes", "startPageToken"], &params)?;
        let (_, _, body) = self
            .control_request(
                "changes.getStartPageToken",
                Method::GET,
                url,
                None,
                false,
                false,
            )
            .await?;
        let parsed: StartPageTokenResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("decode startPageToken JSON: {e}")))?;
        Ok(parsed.start_page_token)
    }

    pub(super) async fn fetch_changes_page(&self, page_token: &str) -> Result<ChangesPageOutcome> {
        let mut params = vec![
            ("pageToken", page_token),
            ("pageSize", "1000"),
            ("fields", CHANGES_LIST_FIELDS),
            ("supportsAllDrives", "true"),
            ("includeCorpusRemovals", "true"),
        ];
        if let Some(drive_id) = &self.inner.cfg.shared_drive_id {
            params.push(("includeItemsFromAllDrives", "true"));
            params.push(("driveId", drive_id.as_str()));
        } else if self.inner.cfg.is_app_data_folder() {
            params.push(("spaces", "appDataFolder"));
        } else if self.inner.cfg.shared_with_me {
            params.push(("includeItemsFromAllDrives", "true"));
        } else {
            params.push(("restrictToMyDrive", "true"));
        }
        let url = self.api_url(&["changes"], &params)?;
        let cfg = self.retry_policy_config(false);

        execute_with_auth_policy(
            &self.inner.transport,
            &self.inner.control_limiter,
            "changes.list",
            &cfg,
            Idempotency::Idempotent,
            || {
                let url = url.clone();
                async move {
                    let token = self.inner.auth.access_token().await?;
                    let auth_hdr = bearer_header_value(&token)?;
                    let req = self
                        .inner
                        .transport
                        .control_client()
                        .get(&url)
                        .header(http::header::AUTHORIZATION, auth_hdr);
                    Ok((req, token))
                }
            },
            |rejected_token| async move {
                let _ = self.inner.auth.force_refresh(&rejected_token).await?;
                Ok(true)
            },
            |resp| {
                if resp.status == StatusCode::UNAUTHORIZED {
                    return PolicyDecision::AuthRefresh;
                }
                if resp.status == StatusCode::GONE || resp.status == StatusCode::BAD_REQUEST {
                    return PolicyDecision::Ok(ChangesPageOutcome::TokenExpired);
                }
                if resp.status.is_success() {
                    return match serde_json::from_slice::<ChangeListResponse>(&resp.body) {
                        Ok(page) => PolicyDecision::Ok(ChangesPageOutcome::Page(page)),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "decode changes.list JSON: {e}"
                        ))),
                    };
                }
                let err = classify_gdrive_error(
                    "changes.list",
                    resp.status,
                    &resp.headers,
                    &resp.body,
                    false,
                );
                if matches!(err.retry, RetryClass::Retryable | RetryClass::Throttled) {
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(err)
                }
            },
        )
        .await
    }

    pub(super) async fn ensure_dir_chain(&self, dir_path: &RelPath) -> Result<String> {
        let mut parent_id = self.inner.cfg.effective_root_id().to_string();
        if dir_path.is_root() {
            return Ok(parent_id);
        }

        let scope = self.scope();
        let use_changes_feed = self.inner.cfg.use_changes_feed;
        let mut prefix = String::new();

        for seg in dir_path.segments() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);

            // Level 0 fast path: bounded in-memory `(parent_id, name) -> folder_id` cache.
            if let Some(dir_id) = self.lookup_dir_cache(&parent_id, seg) {
                parent_id = dir_id;
                continue;
            }

            // Level 1 fast path: check persistent inventory cache ONLY when `use_changes_feed` is active.
            if use_changes_feed {
                let cached = self
                    .inner
                    .inventory
                    .find_children_by_name(&scope.remote_name, &scope.corpus_id, &parent_id, seg)
                    .await?;
                if let Some(dir) = cached.into_iter().find(|n| n.kind == EntryKind::Directory) {
                    self.insert_dir_cache(&parent_id, seg, &dir.file_id);
                    parent_id = dir.file_id;
                    continue;
                }
            }

            // Acquire segmented lock for this exact path prefix before checking/creating remotely.
            let lock = self.mkdir_lock_for(&prefix);
            let _guard = lock.lock().await;

            // Double-check caches after winning the lock.
            if let Some(dir_id) = self.lookup_dir_cache(&parent_id, seg) {
                parent_id = dir_id;
                continue;
            }
            if use_changes_feed {
                let cached2 = self
                    .inner
                    .inventory
                    .find_children_by_name(&scope.remote_name, &scope.corpus_id, &parent_id, seg)
                    .await?;
                if let Some(dir) = cached2.into_iter().find(|n| n.kind == EntryKind::Directory) {
                    self.insert_dir_cache(&parent_id, seg, &dir.file_id);
                    parent_id = dir.file_id;
                    continue;
                }
            }

            // Check remote before creating (also traversing folder shortcuts).
            if let Some(existing) = self
                .find_child_in_parent(&parent_id, seg, ChildFilter::DirOrFolderShortcut)
                .await?
            {
                if existing.mime_type == SHORTCUT_MIME {
                    if let Some(target) = self.resolve_shortcut_target(existing).await?
                        && target.mime_type == FOLDER_MIME
                    {
                        parent_id = target.id;
                        continue;
                    }
                } else {
                    self.insert_dir_cache(&parent_id, seg, &existing.id);
                    parent_id = existing.id;
                    continue;
                }
            }

            // Create folder remotely with pre-generated ID (write-QPS paced & D5 reconciled!).
            let folder_id = self.generate_file_id().await?;
            let url = self.api_url(
                &["files"],
                &[("fields", FILE_FIELDS), ("supportsAllDrives", "true")],
            )?;

            let meta = serde_json::json!({
                "id": folder_id,
                "name": seg,
                "mimeType": FOLDER_MIME,
                "parents": [parent_id],
            });
            let created = self
                .control_create_with_id(
                    "files.create(folder)",
                    url,
                    &meta,
                    &folder_id,
                    None,
                    true,
                    false,
                    None,
                )
                .await?;
            self.insert_dir_cache(&parent_id, seg, &created.id);
            parent_id = created.id;
        }

        Ok(parent_id)
    }

    /// Resolve a [`BackendPath`] using its raw (possibly NFD) segments first, falling
    /// back to NFC segments only when `raw_path` differs and did not match.
    pub(super) async fn resolve_backend_path(
        &self,
        path: &BackendPath,
        resolve_terminal_target: bool,
    ) -> Result<Option<ResolvedDriveNode>> {
        let raw = path.raw_path();
        if raw != path.nfc_path.as_str() {
            let raw_segs: Vec<&str> = raw.split('/').filter(|s| !s.is_empty()).collect();
            if raw_segs.is_empty() {
                return self
                    .resolve_rel_path_raw(&path.nfc_path, resolve_terminal_target)
                    .await;
            }
            let root_id = self.inner.cfg.effective_root_id().to_string();
            if let Some(found) = self
                .resolve_rel_path_from_id(&root_id, &raw_segs, resolve_terminal_target)
                .await?
            {
                return Ok(Some(found));
            }
        }
        self.resolve_rel_path_raw(&path.nfc_path, resolve_terminal_target)
            .await
    }

    /// Resolve a `RelPath` to its [`ResolvedDriveNode`], separating the node's own
    /// `id` from any shortcut `targetId` so callers choose whether to act on the
    /// shortcut itself (`delete`, `rename`) or its target (`open_read`, `stat`, `copy`).
    pub(super) async fn resolve_rel_path_raw(
        &self,
        rel: &RelPath,
        resolve_terminal_target: bool,
    ) -> Result<Option<ResolvedDriveNode>> {
        let root_id = self.inner.cfg.effective_root_id().to_string();
        if rel.is_root() {
            return Ok(Some(ResolvedDriveNode {
                node: DriveFile {
                    id: root_id,
                    name: String::new(),
                    mime_type: FOLDER_MIME.to_string(),
                    size: 0,
                    modified_time: None,
                    md5_checksum: None,
                    sha1_checksum: None,
                    sha256_checksum: None,
                    parents: vec![],
                    trashed: false,
                    shared_with_me_time: None,
                    shortcut_details: None,
                    app_properties: HashMap::new(),
                },
                target: None,
            }));
        }

        let segments: Vec<&str> = rel.segments().collect();
        self.resolve_rel_path_from_id(&root_id, &segments, resolve_terminal_target)
            .await
    }

    pub(super) async fn resolve_rel_path_from_id(
        &self,
        start_id: &str,
        segments: &[&str],
        resolve_terminal_target: bool,
    ) -> Result<Option<ResolvedDriveNode>> {
        if segments.is_empty() {
            return match self.get_file_by_id(start_id).await? {
                Some(f) => Ok(Some(ResolvedDriveNode {
                    node: f,
                    target: None,
                })),
                None => Ok(None),
            };
        }

        let scope = self.scope();
        let use_changes_feed = self.inner.cfg.use_changes_feed;

        for attempt in 0..2 {
            let mut parent_id = start_id.to_string();
            let mut visited = HashSet::new();
            visited.insert(parent_id.clone());
            let mut cached_ancestors: Vec<String> = Vec::new();
            let mut stale_cache_hit = false;

            for (idx, seg) in segments.iter().enumerate() {
                let is_last = idx + 1 == segments.len();
                if !is_last {
                    if let Some(cached_id) = self.lookup_dir_cache(&parent_id, seg) {
                        if !visited.insert(cached_id.clone()) {
                            warn!(dir_id = %cached_id, seg = %seg, "directory shortcut cycle detected");
                            return Ok(None);
                        }
                        cached_ancestors.push(cached_id.clone());
                        parent_id = cached_id;
                        continue;
                    }
                    if use_changes_feed
                        && let Ok(cached_nodes) = self
                            .inner
                            .inventory
                            .find_children_by_name(
                                &scope.remote_name,
                                &scope.corpus_id,
                                &parent_id,
                                seg,
                            )
                            .await
                        && let Some(dir) = cached_nodes
                            .into_iter()
                            .find(|n| n.kind == EntryKind::Directory)
                    {
                        self.insert_dir_cache(&parent_id, seg, &dir.file_id);
                        if !visited.insert(dir.file_id.clone()) {
                            warn!(dir_id = %dir.file_id, seg = %seg, "directory shortcut cycle detected");
                            return Ok(None);
                        }
                        cached_ancestors.push(dir.file_id.clone());
                        parent_id = dir.file_id;
                        continue;
                    }
                }

                let filter = if !is_last {
                    ChildFilter::DirOrFolderShortcut
                } else {
                    ChildFilter::Any
                };
                let found = match self.find_child_in_parent(&parent_id, seg, filter).await {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        if attempt == 0 && !cached_ancestors.is_empty() {
                            for cid in &cached_ancestors {
                                self.evict_cached_dir(cid).await;
                            }
                            stale_cache_hit = true;
                            break;
                        }
                        return Ok(None);
                    }
                    Err(e) if attempt == 0 && !cached_ancestors.is_empty() && e.is_not_found() => {
                        for cid in &cached_ancestors {
                            self.evict_cached_dir(cid).await;
                        }
                        stale_cache_hit = true;
                        break;
                    }
                    Err(e) => return Err(e),
                };

                if is_last {
                    if found.mime_type == SHORTCUT_MIME {
                        if let Some(sd) = &found.shortcut_details {
                            self.record_shortcut_target(
                                &found.id,
                                &sd.target_id,
                                &sd.target_mime_type,
                            );
                        }
                        if !resolve_terminal_target {
                            return Ok(Some(ResolvedDriveNode {
                                node: found,
                                target: None,
                            }));
                        }
                        let Some(target) = self.resolve_shortcut_target(found.clone()).await?
                        else {
                            return Ok(None);
                        };
                        if visited.contains(&target.id) {
                            warn!(target_id = %target.id, seg = %seg, "shortcut loop detected during stat");
                            return Ok(None);
                        }
                        return Ok(Some(ResolvedDriveNode {
                            node: found,
                            target: Some(target),
                        }));
                    }
                    if found.mime_type == FOLDER_MIME {
                        self.insert_dir_cache(&parent_id, seg, &found.id);
                    }
                    return Ok(Some(ResolvedDriveNode {
                        node: found,
                        target: None,
                    }));
                }

                let next_dir_id = if found.mime_type == SHORTCUT_MIME {
                    let Some(target) = self.resolve_shortcut_target(found).await? else {
                        return Ok(None);
                    };
                    if target.mime_type != FOLDER_MIME {
                        return Ok(None);
                    }
                    target.id
                } else if found.mime_type == FOLDER_MIME {
                    self.insert_dir_cache(&parent_id, seg, &found.id);
                    found.id
                } else {
                    return Ok(None);
                };

                if !visited.insert(next_dir_id.clone()) {
                    warn!(dir_id = %next_dir_id, seg = %seg, "directory shortcut cycle detected");
                    return Ok(None);
                }
                parent_id = next_dir_id;
            }

            if !stale_cache_hit {
                break;
            }
        }

        Ok(None)
    }

    pub(super) async fn resolve_existing_file_id_for_upload(
        &self,
        init: &UploadInit,
        parent_id: &str,
        file_name: &str,
    ) -> Result<Option<String>> {
        if let Some(existing) = &init.existing_node_id {
            if matches!(init.precondition, DstPrecondition::Absent)
                && init.pregenerated_id.as_ref() != init.existing_node_id.as_ref()
            {
                return Err(Error::already_exists(format!(
                    "gdrive destination `{}` already exists",
                    init.dst_path
                )));
            }
            let mut is_shortcut = self.lookup_shortcut_target(&existing.0).is_some();
            if !is_shortcut {
                let scope = self.scope();
                if let Ok(Some(rec)) = self
                    .inner
                    .inventory
                    .get_node(&scope.remote_name, &scope.corpus_id, &existing.0)
                    .await
                {
                    is_shortcut = rec.kind == EntryKind::Symlink;
                } else if let Ok(Some(f)) = self.get_file_by_id(&existing.0).await {
                    is_shortcut = f.mime_type == SHORTCUT_MIME;
                }
            }
            if !is_shortcut {
                return Ok(Some(existing.0.clone()));
            }
            // Overwriting a shortcut replaces ONLY the shortcut itself with a new regular
            // file — never `PATCH /upload/.../{shortcut_id}` and never overwrite the target!
            self.delete_node_by_id(&existing.0, false).await?;
            let (regular_files, shortcuts) = self
                .find_non_folder_children_in_parent(parent_id, file_name)
                .await?;
            if matches!(init.precondition, DstPrecondition::Absent) {
                let has_conflict = !shortcuts.is_empty()
                    || regular_files
                        .iter()
                        .any(|f| init.pregenerated_id.as_ref().is_none_or(|p| p.0 != f.id));
                if has_conflict {
                    return Err(Error::already_exists(format!(
                        "gdrive destination `{}` already exists",
                        init.dst_path
                    )));
                }
                return Ok(None);
            }
            for sc in shortcuts {
                self.delete_node_by_id(&sc.id, false).await?;
            }
            return Ok(regular_files.into_iter().next().map(|f| f.id));
        }

        let (regular_files, shortcuts) = self
            .find_non_folder_children_in_parent(parent_id, file_name)
            .await?;
        if matches!(init.precondition, DstPrecondition::Absent) {
            let has_conflict = !shortcuts.is_empty()
                || regular_files
                    .iter()
                    .any(|f| init.pregenerated_id.as_ref().is_none_or(|p| p.0 != f.id));
            if has_conflict {
                return Err(Error::already_exists(format!(
                    "gdrive destination `{}` already exists",
                    init.dst_path
                )));
            }
            return Ok(None);
        }
        // When overwriting without `existing_node_id`, delete/trash any matching
        // shortcut(s) at `(parent_id, file_name)` (leaving targets untouched!) so no
        // duplicate shortcut remains to poison subsequent `stat`/`open_read`.
        for sc in shortcuts {
            self.delete_node_by_id(&sc.id, false).await?;
        }
        Ok(regular_files.into_iter().next().map(|f| f.id))
    }

    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        if let Some(nid) = &path.node_id {
            let ProbeFileOutcome::Found(f) =
                self.get_file_by_id_tolerating_403(nid.as_str()).await?
            else {
                return Ok(None);
            };
            let f = *f;
            if (!self.inner.cfg.trashed_only && f.trashed)
                || is_exportable_workspace_doc(&f.mime_type)
            {
                return Ok(None);
            }
            if f.mime_type == SHORTCUT_MIME {
                let Some(target) = self.resolve_shortcut_target(f.clone()).await? else {
                    return Ok(None);
                };
                return Ok(Some(
                    ResolvedDriveNode {
                        node: f,
                        target: Some(target),
                    }
                    .into_entry(self, path.raw_path(), path.nfc_path.clone()),
                ));
            }
            return Ok(Some(self.drive_file_to_entry(
                &f,
                path.raw_path(),
                path.nfc_path.clone(),
            )));
        }

        let Some(resolved) = self.resolve_backend_path(path, true).await? else {
            return Ok(None);
        };
        Ok(Some(resolved.into_entry(
            self,
            path.raw_path(),
            path.nfc_path.clone(),
        )))
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        let _ = self.ensure_dir_chain(path).await?;
        Ok(())
    }

    pub(super) async fn delete_node_by_id(&self, file_id: &str, is_folder: bool) -> Result<()> {
        let url = self.api_url(&["files", file_id], &[("supportsAllDrives", "true")])?;

        if self.inner.cfg.use_trash_on_delete {
            let body = serde_json::json!({ "trashed": true });
            let _ = self
                .control_request("files.trash", Method::PATCH, url, Some(&body), true, true)
                .await?;
        } else {
            let _ = self
                .control_request("files.delete", Method::DELETE, url, None, true, true)
                .await?;
        }

        // Evict deleted file/folder subtree from in-memory caches & local node inventory.
        self.invalidate_dir_cache_for_id(file_id);
        let scope = self.scope();
        let batch = if is_folder {
            DeltaChangeBatch {
                evict_subtree_root_ids: vec![file_id.to_string()],
                updated_at: self.inner.clock.now_unix_secs(),
                ..Default::default()
            }
        } else {
            DeltaChangeBatch {
                remove_file_ids: vec![file_id.to_string()],
                updated_at: self.inner.clock.now_unix_secs(),
                ..Default::default()
            }
        };
        let _ = self.inner.inventory.apply_change_batch(&scope, batch).await;
        Ok(())
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        let target = if let Some(nid) = &path.node_id {
            self.get_file_by_id(nid.as_str()).await?
        } else {
            self.resolve_backend_path(path, false)
                .await?
                .map(|r| r.node)
        };
        let Some(file) = target else {
            // Idempotent delete (`delete_not_found_idempotent`).
            return Ok(());
        };

        self.delete_node_by_id(&file.id, file.mime_type == FOLDER_MIME)
            .await
    }

    pub(super) async fn compute_hash_impl(
        &self,
        path: &BackendPath,
        kind: HashKind,
    ) -> Result<Option<Checksum>> {
        if !matches!(kind, HashKind::Md5 | HashKind::Sha1 | HashKind::Sha256) {
            return Ok(None);
        }
        let target_file = if let Some(nid) = &path.node_id {
            let ProbeFileOutcome::Found(f) =
                self.get_file_by_id_tolerating_403(nid.as_str()).await?
            else {
                return Ok(None);
            };
            let f = *f;
            if (!self.inner.cfg.trashed_only && f.trashed)
                || is_exportable_workspace_doc(&f.mime_type)
            {
                return Ok(None);
            }
            if f.mime_type == SHORTCUT_MIME {
                let Some(t) = self.resolve_shortcut_target(f).await? else {
                    return Ok(None);
                };
                t
            } else {
                f
            }
        } else {
            let Some(resolved) = self.resolve_backend_path(path, true).await? else {
                return Ok(None);
            };
            resolved.target.unwrap_or(resolved.node)
        };

        if target_file.mime_type == FOLDER_MIME {
            return Ok(None);
        }
        Ok(target_file.checksum_for(kind))
    }
}
