//! Azure Blob metadata, `ListBlobs` streaming/ordered listing, directory markers,
//! deletion, server-side `CopyBlob` polling, and rename operations.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{BackendPath, EntryStream, OrderedListPage, StorageBackend, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_core::types::{Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::azureblob::auth::{AzureAuth, sas_is_resource_scoped};
use crate::azureblob::config::{
    append_rfc3986_query, azure_encode_blob_path, azure_encode_segment,
};
use crate::azureblob::xml::{ListedBlob, parse_list_blobs};

use super::{
    AzureBlobBackend, HDR_META_MTIME, HDR_META_OP_ID, META_KEY_MTIME, META_KEY_MTIME_LEGACY,
    decode_md5_b64, format_azure_mtime, insert_write_precondition_header, parse_azure_mtime_ns,
};

fn delete_blob_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("x-ms-delete-snapshots"),
        HeaderValue::from_static("include"),
    );
    h
}

fn prefix_to_entry(rel_raw: &str) -> Option<Entry> {
    let trimmed = rel_raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let nfc_path = match RelPath::parse(trimmed) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(raw_rel = %rel_raw, error = %e, "skipping Azure BlobPrefix with invalid RelPath");
            return None;
        }
    };
    Some(Entry {
        node_id: None,
        parent_id: None,
        raw_path: rship_core::types::raw_path_override(&nfc_path, trimmed),
        nfc_path,
        kind: EntryKind::Directory,
        size: 0,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    })
}

fn listed_blob_to_entry(rel_raw: &str, blob: &ListedBlob) -> Option<Entry> {
    let is_dir = blob.is_directory();
    let trimmed = if is_dir {
        rel_raw.trim_end_matches('/')
    } else {
        rel_raw
    };
    if trimmed.is_empty() {
        return None;
    }
    let nfc_path = match RelPath::parse(trimmed) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(raw_rel = %rel_raw, error = %e, "skipping Azure blob with invalid RelPath");
            return None;
        }
    };
    let mtime_ns = parse_azure_mtime_ns(
        blob.metadata.get(META_KEY_MTIME).map(String::as_str),
        blob.metadata.get(META_KEY_MTIME_LEGACY).map(String::as_str),
        blob.last_modified.as_deref(),
    );
    let checksum = if is_dir {
        None
    } else {
        blob.content_md5_b64.as_deref().and_then(decode_md5_b64)
    };
    Some(Entry {
        node_id: None,
        parent_id: None,
        raw_path: rship_core::types::raw_path_override(&nfc_path, trimmed),
        nfc_path,
        kind: if is_dir {
            EntryKind::Directory
        } else {
            EntryKind::File
        },
        size: if is_dir { 0 } else { blob.size },
        mtime_ns,
        ctime_ns: None,
        etag: blob.etag.clone(),
        checksum,
    })
}

impl AzureBlobBackend {
    fn list_prefix_for(&self, prefix: &RelPath) -> String {
        if prefix.is_root() {
            self.inner.cfg.normalized_prefix()
        } else {
            self.inner.cfg.dir_marker_key(prefix.as_str())
        }
    }

    fn list_blobs_url(
        &self,
        list_prefix: &str,
        delimiter: Option<&str>,
        marker: Option<&str>,
        max_results: Option<u32>,
    ) -> String {
        let max_str = max_results.map(|m| m.clamp(1, 5000).to_string());
        let mut params: Vec<(&str, &str)> = vec![
            ("restype", "container"),
            ("comp", "list"),
            ("include", "metadata"),
        ];
        if let Some(ref m) = max_str {
            params.push(("maxresults", m.as_str()));
        }
        if !list_prefix.is_empty() {
            params.push(("prefix", list_prefix));
        }
        if let Some(d) = delimiter {
            params.push(("delimiter", d));
        }
        if let Some(m) = marker {
            params.push(("marker", m));
        }
        append_rfc3986_query(&self.inner.cfg.container_url(), &params)
    }

    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        if path.nfc_path.is_root() {
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
        let raw_rel = path.raw_path();
        let full_key = self.inner.cfg.full_key(raw_rel);
        if let Some(headers) = self.head_blob(&full_key).await? {
            return Ok(Some(self.headers_to_entry(raw_rel, &headers)?));
        }

        let dir_prefix = self.inner.cfg.dir_marker_key(raw_rel);
        if self.has_prefix(&dir_prefix).await? {
            return Ok(Some(Entry {
                node_id: None,
                parent_id: None,
                raw_path: path.raw_path.clone(),
                nfc_path: path.nfc_path.clone(),
                kind: EntryKind::Directory,
                size: 0,
                mtime_ns: 0,
                ctime_ns: None,
                etag: None,
                checksum: None,
            }));
        }
        Ok(None)
    }

    pub(super) async fn list_stream_impl(
        &self,
        prefix: &RelPath,
        recursive: bool,
    ) -> Result<EntryStream> {
        let list_prefix = self.list_prefix_for(prefix);
        let this = self.clone();
        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);

        tokio::spawn(async move {
            let mut marker: Option<String> = None;
            let mut seen_dirs: HashSet<RelPath> = HashSet::new();
            let delimiter = (!recursive).then_some("/");
            loop {
                let url = this.list_blobs_url(&list_prefix, delimiter, marker.as_deref(), None);

                let (status, _, body) = match this
                    .control_request(
                        "Azure ListBlobs",
                        Method::GET,
                        &url,
                        HeaderMap::new(),
                        None,
                        true,
                    )
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if status == StatusCode::NOT_FOUND {
                    return;
                }

                let page = match parse_list_blobs(&body) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };

                for pfx in page.prefixes {
                    if !list_prefix.is_empty() && pfx == list_prefix {
                        continue;
                    }
                    if let Some(rel_raw) = this.inner.cfg.strip_prefix(&pfx)
                        && let Some(entry) = prefix_to_entry(rel_raw)
                    {
                        if !recursive && !seen_dirs.insert(entry.nfc_path.clone()) {
                            continue;
                        }
                        if tx.send(Ok(entry)).await.is_err() {
                            return;
                        }
                    }
                }

                for blob in page.blobs {
                    if !list_prefix.is_empty()
                        && (blob.name == list_prefix
                            || (blob.is_directory()
                                && blob.name.trim_end_matches('/')
                                    == list_prefix.trim_end_matches('/')))
                    {
                        continue;
                    }
                    let Some(rel_raw) = this.inner.cfg.strip_prefix(&blob.name) else {
                        continue;
                    };
                    if rel_raw.is_empty() {
                        continue;
                    }
                    let Some(entry) = listed_blob_to_entry(rel_raw, &blob) else {
                        continue;
                    };
                    if !recursive
                        && entry.kind == EntryKind::Directory
                        && !seen_dirs.insert(entry.nfc_path.clone())
                    {
                        continue;
                    }
                    if tx.send(Ok(entry)).await.is_err() {
                        return;
                    }
                }

                match page.next_marker {
                    Some(m) if !m.is_empty() => marker = Some(m),
                    _ => break,
                }
            }
        });

        Ok(crate::common::http::rx_to_entry_stream(rx))
    }

    pub(super) async fn list_ordered_page_impl(
        &self,
        prefix: &RelPath,
        start_after: Option<&str>,
        continuation: Option<&str>,
        max_keys: u32,
    ) -> Result<OrderedListPage> {
        if start_after.is_some() {
            return Err(Error::unsupported(
                "Azure Blob ListBlobs does not support arbitrary start_after keys",
            ));
        }
        let list_prefix = self.list_prefix_for(prefix);
        let mut cursor = continuation.map(str::to_string);
        loop {
            let url = self.list_blobs_url(&list_prefix, None, cursor.as_deref(), Some(max_keys));
            let (status, _, body) = self
                .control_request(
                    "Azure ListBlobs",
                    Method::GET,
                    &url,
                    HeaderMap::new(),
                    None,
                    true,
                )
                .await?;
            if status == StatusCode::NOT_FOUND {
                return Ok(OrderedListPage {
                    entries: Vec::new(),
                    is_truncated: false,
                    next_cursor: None,
                    last_wire_key: None,
                    supports_start_after: false,
                });
            }
            let page = parse_list_blobs(&body)?;
            let mut entries = Vec::with_capacity(page.blobs.len());
            let mut last_wire_key = None;
            let mut seen_dirs: HashSet<RelPath> = HashSet::new();
            for blob in page.blobs {
                if !list_prefix.is_empty()
                    && (blob.name == list_prefix
                        || (blob.is_directory()
                            && blob.name.trim_end_matches('/')
                                == list_prefix.trim_end_matches('/')))
                {
                    continue;
                }
                let rel_raw = if list_prefix.is_empty() {
                    blob.name.as_str()
                } else {
                    let Some(rest) = blob.name.strip_prefix(&list_prefix) else {
                        continue;
                    };
                    rest
                };
                if rel_raw.is_empty() {
                    continue;
                }
                last_wire_key = Some(rel_raw.to_string());
                let Some(entry) = listed_blob_to_entry(rel_raw, &blob) else {
                    continue;
                };
                if entry.kind == EntryKind::Directory && !seen_dirs.insert(entry.nfc_path.clone()) {
                    continue;
                }
                entries.push(entry);
            }
            let next_cursor = page.next_marker.filter(|m| !m.is_empty());
            if !entries.is_empty() || next_cursor.is_none() {
                return Ok(OrderedListPage {
                    entries,
                    is_truncated: next_cursor.is_some(),
                    next_cursor,
                    last_wire_key,
                    supports_start_after: false,
                });
            }
            cursor = next_cursor;
        }
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        let marker_key = self.inner.cfg.dir_marker_key(path.as_str());
        let url = self.inner.cfg.blob_url(&marker_key);
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("BlockBlob"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-directory"),
        );
        self.control_request(
            "Azure mkdir marker",
            Method::PUT,
            &url,
            headers,
            Some(Bytes::new()),
            false,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Ok(());
        }
        let raw_rel = path.raw_path();
        let full_key = self.inner.cfg.full_key(raw_rel);
        let headers = delete_blob_headers();
        match path.kind {
            Some(EntryKind::Directory) => {
                let marker = self.inner.cfg.dir_marker_key(raw_rel);
                let murl = self.inner.cfg.blob_url(&marker);
                self.control_request(
                    "Azure delete dir marker",
                    Method::DELETE,
                    &murl,
                    headers,
                    None,
                    true,
                )
                .await?;
            }
            Some(EntryKind::File) => {
                let url = self.inner.cfg.blob_url(&full_key);
                self.control_request(
                    "Azure delete blob",
                    Method::DELETE,
                    &url,
                    headers,
                    None,
                    true,
                )
                .await?;
            }
            _ => {
                let url = self.inner.cfg.blob_url(&full_key);
                let (status, _, _) = self
                    .control_request(
                        "Azure delete blob",
                        Method::DELETE,
                        &url,
                        headers.clone(),
                        None,
                        true,
                    )
                    .await?;
                if status == StatusCode::NOT_FOUND {
                    let marker = self.inner.cfg.dir_marker_key(raw_rel);
                    let murl = self.inner.cfg.blob_url(&marker);
                    self.control_request(
                        "Azure delete dir marker",
                        Method::DELETE,
                        &murl,
                        headers,
                        None,
                        true,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn compute_hash_impl(
        &self,
        path: &BackendPath,
        kind: HashKind,
    ) -> Result<Option<Checksum>> {
        if kind != HashKind::Md5 {
            return Ok(None);
        }
        let full_key = self.inner.cfg.full_key(path.raw_path());
        let Some(headers) = self.head_blob(&full_key).await? else {
            return Ok(None);
        };
        Ok(headers
            .get("content-md5")
            .and_then(|v| v.to_str().ok())
            .and_then(decode_md5_b64))
    }

    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        let Some((src_container, _)) = self.parse_src_container_and_prefix(src_endpoint) else {
            return false;
        };
        !(src_container != self.inner.cfg.container
            && matches!(&self.inner.auth, AzureAuth::SasToken(sas) if sas_is_resource_scoped(sas)))
    }

    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        self.server_side_copy_to_raw(src_endpoint, src_path, init, None)
            .await
    }

    async fn server_side_copy_to_raw(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
        dst_raw_override: Option<&str>,
    ) -> Result<Option<Entry>> {
        let Some((src_container, src_pfx)) = self.parse_src_container_and_prefix(src_endpoint)
        else {
            return Ok(None);
        };
        if src_container != self.inner.cfg.container
            && matches!(&self.inner.auth, AzureAuth::SasToken(sas) if sas_is_resource_scoped(sas))
        {
            return Ok(None);
        }
        let src_raw = src_path.raw_path();
        let src_full_key = if src_pfx.is_empty() {
            src_raw.trim_start_matches('/').to_string()
        } else {
            format!(
                "{}/{}",
                src_pfx.trim_matches('/'),
                src_raw.trim_start_matches('/')
            )
        };
        let raw_src_url = format!(
            "{}/{}/{}",
            self.inner.cfg.effective_endpoint(),
            azure_encode_segment(src_container),
            azure_encode_blob_path(&src_full_key)
        );
        let copy_source = self.inner.auth.apply_url(&raw_src_url);

        let dst_raw_rel = dst_raw_override.unwrap_or_else(|| init.dst_path.as_str());
        let dst_full_key = self.inner.cfg.full_key(dst_raw_rel);
        let dst_url = self.inner.cfg.blob_url(&dst_full_key);

        let mut headers = HeaderMap::new();
        let copy_source_val = if matches!(self.inner.auth, AzureAuth::SasToken(_)) {
            crate::common::http::sensitive_header_value(&copy_source, "x-ms-copy-source header")?
        } else {
            HeaderValue::from_str(&copy_source)
                .map_err(|e| Error::protocol(format!("x-ms-copy-source header: {e}")))?
        };
        headers.insert(HeaderName::from_static("x-ms-copy-source"), copy_source_val);
        headers.insert(
            HeaderName::from_static(HDR_META_MTIME),
            HeaderValue::from_str(&format_azure_mtime(init.src_mtime_ns))
                .map_err(|e| Error::protocol(format!("mtime header: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static(HDR_META_OP_ID),
            HeaderValue::from_str(&init.op_id)
                .map_err(|e| Error::protocol(format!("op-id header: {e}")))?,
        );
        self.insert_access_tier_header(&mut headers)?;
        insert_write_precondition_header(&init.precondition, &mut headers)?;
        if let Some(ref src_etag) = init.src_etag
            && !src_etag.trim().is_empty()
        {
            headers.insert(
                HeaderName::from_static("x-ms-source-if-match"),
                HeaderValue::from_str(src_etag.trim())
                    .map_err(|e| Error::protocol(format!("x-ms-source-if-match header: {e}")))?,
            );
        }

        let op_id = init.op_id.clone();
        let commit_res = self
            .long_control_commit(
                "Azure CopyBlob",
                &dst_url,
                headers,
                Bytes::new(),
                true,
                |err| {
                    let dst_full_key = dst_full_key.clone();
                    let op_id = op_id.clone();
                    async move {
                        self.reconcile_commit_by_op_id(
                            &dst_full_key,
                            &op_id,
                            Some(init.total_size),
                            true,
                            err,
                        )
                        .await
                    }
                },
            )
            .await;
        let (status, resp_headers, _) = match commit_res {
            Ok(ok) => ok,
            Err(e)
                if src_container != self.inner.cfg.container
                    && matches!(self.inner.auth, AzureAuth::SasToken(_))
                    && e.kind == ErrorKind::PermissionDenied =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let mut copy_id = resp_headers
            .get("x-ms-copy-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let mut copy_status = resp_headers
            .get("x-ms-copy-status")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("success")
            .trim()
            .to_ascii_lowercase();
        let mut copy_desc = resp_headers
            .get("x-ms-copy-status-description")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        for poll in 0..=120u32 {
            match copy_status.as_str() {
                "success" => break,
                "pending" if poll < 120 => {
                    let wait = Duration::from_millis((50 * u64::from(poll + 1)).min(2_000));
                    self.inner.control_limiter.sleep(wait).await;
                    let Some(h) = self.head_blob(&dst_full_key).await? else {
                        return Err(Error::protocol(
                            "Azure CopyBlob destination disappeared while polling",
                        ));
                    };
                    if copy_id.is_none() {
                        copy_id = h
                            .get("x-ms-copy-id")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                    }
                    copy_status = h
                        .get("x-ms-copy-status")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("success")
                        .trim()
                        .to_ascii_lowercase();
                    copy_desc = h
                        .get("x-ms-copy-status-description")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
                "pending" => {
                    if let Some(ref cid) = copy_id {
                        let abort_url =
                            append_rfc3986_query(&dst_url, &[("comp", "copy"), ("copyid", cid)]);
                        let mut abort_headers = HeaderMap::new();
                        abort_headers.insert(
                            HeaderName::from_static("x-ms-copy-action"),
                            HeaderValue::from_static("abort"),
                        );
                        let _ = self
                            .control_request(
                                "Azure AbortCopyBlob",
                                Method::PUT,
                                &abort_url,
                                abort_headers,
                                Some(Bytes::new()),
                                true,
                            )
                            .await;
                    }
                    return Err(Error::network(
                        "Azure CopyBlob timed out waiting for server-side copy completion",
                    ));
                }
                other => {
                    let detail = copy_desc
                        .as_deref()
                        .map(|d| format!(" ({d})"))
                        .unwrap_or_default();
                    return Err(Error::protocol(format!(
                        "Azure CopyBlob ended in status `{other}`{detail}"
                    )));
                }
            }
        }

        let stat_path = BackendPath::new(dst_raw_rel, init.dst_path.clone(), None)
            .with_kind(Some(EntryKind::File));
        self.stat(&stat_path).await
    }

    pub(super) async fn rename_impl(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename root directory"));
        }
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
        let Some(existing) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "Azure blob `{}` not found",
                path.raw_path()
            )));
        };
        if existing.kind != EntryKind::File {
            return Err(Error::unsupported(format!(
                "Azure Blob does not support renaming directory `{}`",
                path.nfc_path
            )));
        }

        let src_raw = path.raw_path();
        let dst_raw_rel = match src_raw.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => format!("{parent}/{new_name}"),
            _ => new_name.to_string(),
        };
        let new_rel = RelPath::parse(&dst_raw_rel)?;
        let src_full_key = self.inner.cfg.full_key(src_raw);
        let dst_full_key = self.inner.cfg.full_key(&dst_raw_rel);
        if dst_full_key == src_full_key {
            return Ok(existing);
        }

        let init = UploadInit {
            // Unique per rename so a reconcile can tell this copy from an earlier one.
            op_id: format!(
                "rename-{}-{}",
                existing.mtime_ns,
                self.inner.clock.now_unix_nanos()
            ),
            dst_path: new_rel,
            existing_node_id: None,
            pregenerated_id: None,
            total_size: existing.size,
            src_mtime_ns: existing.mtime_ns,
            planned_chunk_size: self.inner.cfg.block_size,
            checksums: existing.checksum.iter().cloned().collect(),
            precondition: DstPrecondition::Any,
            src_etag: existing.etag.clone(),
        };
        let ep = self.endpoint_identity();
        let entry = self
            .server_side_copy_to_raw(&ep, path, &init, Some(&dst_raw_rel))
            .await?
            .ok_or_else(|| Error::protocol("Azure rename server_side_copy failed"))?;
        self.delete(path).await?;
        Ok(entry)
    }
}
