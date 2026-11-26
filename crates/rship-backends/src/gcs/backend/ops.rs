//! GCS metadata, ordered/streaming object listing, directory markers, deletion,
//! multi-step `rewriteTo` server-side copy, and rename operations.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rship_core::backend::{BackendPath, EntryStream, OrderedListPage, UploadInit};
use rship_core::path::RelPath;
use rship_core::state::DstPrecondition;
use rship_core::types::{Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

use crate::common::http::{Idempotency, PolicyDecision, ReconcileAction};
use crate::gcs::config::gcs_encode_object_name;

use super::{
    GcsBackend, GcsListResponse, GcsObject, META_OP_ID, append_dst_precondition_query,
    map_gcs_http_error_with_headers,
};

static RENAME_OP_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcsRewriteResponse {
    #[serde(default)]
    done: bool,
    #[serde(default)]
    rewrite_token: Option<String>,
    #[serde(default)]
    resource: Option<GcsObject>,
}

impl GcsBackend {
    fn list_prefix_for(&self, prefix: &RelPath) -> String {
        if prefix.is_root() {
            self.inner.cfg.normalized_prefix()
        } else {
            format!(
                "{}/",
                self.inner
                    .cfg
                    .full_key(prefix.as_str())
                    .trim_end_matches('/')
            )
        }
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
        let full_key = self.inner.cfg.full_key(path.raw_path());
        if path.kind != Some(EntryKind::Directory)
            && let Some(obj) = self.get_object_meta(&full_key).await?
            && let Some(entry) = self.object_to_entry(&obj)?
        {
            return Ok(Some(entry));
        }

        if path.kind == Some(EntryKind::File) {
            return Ok(None);
        }

        // Check explicit trailing-slash directory marker first so node_id/mtime_ns/etag survive.
        let dir_prefix = format!("{}/", full_key.trim_end_matches('/'));
        if let Some(obj) = self.get_object_meta(&dir_prefix).await?
            && let Some(entry) = self.object_to_entry(&obj)?
        {
            return Ok(Some(entry));
        }

        // Fallback to virtual directory check via child objects.
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
            let mut page_token: Option<String> = None;
            loop {
                let mut url = match this.bucket_objects_api_url() {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                {
                    let mut qp = url.query_pairs_mut();
                    qp.append_pair("maxResults", "1000");
                    if !list_prefix.is_empty() {
                        qp.append_pair("prefix", &list_prefix);
                    }
                    if !recursive {
                        qp.append_pair("delimiter", "/");
                    }
                    if let Some(tok) = &page_token {
                        qp.append_pair("pageToken", tok);
                    }
                    this.append_user_project_pair(&mut qp);
                }

                let (status, _, body) = match this
                    .control_request(
                        "GCS list objects",
                        Method::GET,
                        url.as_str(),
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
                let page: GcsListResponse = match serde_json::from_slice(&body) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!("parse GCS list JSON: {e}"))))
                            .await;
                        return;
                    }
                };

                for pfx in page.prefixes {
                    if !list_prefix.is_empty() && pfx == list_prefix {
                        continue;
                    }
                    let Some(rel_raw) = this.inner.cfg.strip_prefix(&pfx) else {
                        continue;
                    };
                    let trimmed = rel_raw.trim_end_matches('/');
                    if trimmed.is_empty() {
                        continue;
                    }
                    match RelPath::parse(trimmed) {
                        Ok(nfc_path) => {
                            let entry = Entry {
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
                            };
                            if tx.send(Ok(entry)).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                prefix = %pfx,
                                error = %e,
                                "skipping GCS directory prefix with invalid relative path"
                            );
                        }
                    }
                }

                for obj in page.items {
                    if !list_prefix.is_empty()
                        && (obj.name == list_prefix
                            || obj
                                .name
                                .strip_prefix(&list_prefix)
                                .is_none_or(str::is_empty))
                    {
                        continue;
                    }
                    match this.object_to_entry(&obj) {
                        Ok(Some(entry)) => {
                            if tx.send(Ok(entry)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(
                                object = %obj.name,
                                error = %e,
                                "skipping GCS object with invalid relative path"
                            );
                        }
                    }
                }

                match page.next_page_token {
                    Some(tok) if !tok.is_empty() => page_token = Some(tok),
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
        let list_prefix = self.list_prefix_for(prefix);
        let mut current_continuation = continuation.map(str::to_string);
        let mut entries = Vec::new();
        let mut last_wire_key = None;
        let mut next_cursor: Option<String>;

        loop {
            let mut url = self.bucket_objects_api_url()?;
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("maxResults", &max_keys.clamp(1, 1000).to_string());
                if !list_prefix.is_empty() {
                    qp.append_pair("prefix", &list_prefix);
                }
                if let Some(tok) = &current_continuation {
                    qp.append_pair("pageToken", tok);
                } else if let Some(sa) = start_after {
                    // GCS `startOffset` is inclusive; skip any returned key `<= sa` below.
                    let full_sa = format!("{list_prefix}{sa}");
                    qp.append_pair("startOffset", &full_sa);
                }
                self.append_user_project_pair(&mut qp);
            }
            let (status, _, body) = self
                .control_request(
                    "GCS list objects",
                    Method::GET,
                    url.as_str(),
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
                    supports_start_after: true,
                });
            }
            let page: GcsListResponse = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("parse GCS list JSON: {e}")))?;

            let mut last_dir: Option<String> = None;
            for obj in page.items {
                let rel_raw = if list_prefix.is_empty() {
                    obj.name.as_str()
                } else {
                    let Some(rest) = obj.name.strip_prefix(&list_prefix) else {
                        continue;
                    };
                    rest
                };
                if rel_raw.is_empty() {
                    continue;
                }
                if current_continuation.is_none()
                    && let Some(sa) = start_after
                    && rel_raw <= sa
                {
                    continue;
                }
                last_wire_key = Some(rel_raw.to_string());
                if rel_raw.ends_with('/') {
                    let trimmed = rel_raw.trim_end_matches('/');
                    if !trimmed.is_empty() && last_dir.as_deref() != Some(trimmed) {
                        match self.object_to_entry_rel(&obj, rel_raw) {
                            Ok(Some(entry)) => {
                                last_dir = Some(trimmed.to_string());
                                entries.push(entry);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(
                                    object = %obj.name,
                                    error = %e,
                                    "skipping GCS directory marker with invalid relative path"
                                );
                            }
                        }
                    }
                    continue;
                }
                match self.object_to_entry_rel(&obj, rel_raw) {
                    Ok(Some(entry)) => entries.push(entry),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            object = %obj.name,
                            error = %e,
                            "skipping GCS object with invalid relative path"
                        );
                    }
                }
            }

            next_cursor = page.next_page_token.filter(|t| !t.is_empty());
            if !entries.is_empty() || next_cursor.is_none() {
                break;
            }
            if current_continuation.as_deref() == next_cursor.as_deref() {
                return Err(Error::protocol(
                    "GCS list_ordered_page returned duplicate nextPageToken",
                ));
            }
            current_continuation = next_cursor.clone();
        }

        Ok(OrderedListPage {
            entries,
            is_truncated: next_cursor.is_some(),
            next_cursor,
            last_wire_key,
            supports_start_after: true,
        })
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        let marker_key = format!(
            "{}/",
            self.inner.cfg.full_key(path.as_str()).trim_end_matches('/')
        );
        let mut url = self.bucket_upload_url()?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("uploadType", "media");
            qp.append_pair("name", &marker_key);
            self.append_user_project_pair(&mut qp);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-directory"),
        );
        let _ = self
            .control_request(
                "GCS mkdir marker",
                Method::POST,
                url.as_str(),
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
        let full_key = self.inner.cfg.full_key(path.raw_path());
        match path.kind {
            Some(EntryKind::Directory) => {
                let marker = format!("{}/", full_key.trim_end_matches('/'));
                let murl = self.object_api_url(&marker)?;
                let _ = self
                    .control_request(
                        "GCS delete dir marker",
                        Method::DELETE,
                        murl.as_str(),
                        HeaderMap::new(),
                        None,
                        true,
                    )
                    .await?;
            }
            Some(EntryKind::File) => {
                let url = self.object_api_url(&full_key)?;
                let _ = self
                    .control_request(
                        "GCS delete",
                        Method::DELETE,
                        url.as_str(),
                        HeaderMap::new(),
                        None,
                        true,
                    )
                    .await?;
            }
            _ => {
                let url = self.object_api_url(&full_key)?;
                let (status, _, _) = self
                    .control_request(
                        "GCS delete",
                        Method::DELETE,
                        url.as_str(),
                        HeaderMap::new(),
                        None,
                        true,
                    )
                    .await?;
                if status == StatusCode::NOT_FOUND {
                    let marker = format!("{}/", full_key.trim_end_matches('/'));
                    let murl = self.object_api_url(&marker)?;
                    let _ = self
                        .control_request(
                            "GCS delete dir marker",
                            Method::DELETE,
                            murl.as_str(),
                            HeaderMap::new(),
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
        if !matches!(kind, HashKind::Md5 | HashKind::Crc32c) {
            return Ok(None);
        }
        let full_key = self.inner.cfg.full_key(path.raw_path());
        let Some(obj) = self.get_object_meta(&full_key).await? else {
            return Ok(None);
        };
        let hex = match kind {
            HashKind::Md5 => obj.md5_hex(),
            HashKind::Crc32c => obj.crc32c_hex(),
            _ => None,
        };
        Ok(hex.map(|hex| Checksum { kind, hex }))
    }

    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        self.parse_src_bucket_and_prefix(src_endpoint).is_some()
    }

    async fn rewrite_object(
        &self,
        src_bucket: &str,
        src_full_key: &str,
        src_path: &BackendPath,
        dst_full_key: &str,
        init: &UploadInit,
        fallback_on_403: bool,
    ) -> Result<Option<Entry>> {
        let src_obj = self
            .get_object_meta_in_optional(src_bucket, src_full_key, true)
            .await?;
        let src_gen = src_path
            .node_id
            .as_ref()
            .map(|n| n.0.trim())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                src_obj
                    .as_ref()
                    .and_then(|o| o.generation.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            });

        let base_rewrite_url = format!(
            "{}/b/{}/o/{}/rewriteTo/b/{}/o/{}",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            gcs_encode_object_name(src_bucket),
            gcs_encode_object_name(src_full_key),
            self.encoded_bucket(),
            gcs_encode_object_name(dst_full_key)
        );
        let meta_json = self.build_rewrite_metadata_json(src_obj.as_ref(), init);
        let has_json_body = meta_json.is_some();
        let meta_body = match meta_json {
            Some(val) => Bytes::from(
                serde_json::to_vec(&val)
                    .map_err(|e| Error::protocol(format!("encode GCS rewrite body: {e}")))?,
            ),
            None => Bytes::new(),
        };

        let mut rewrite_token: Option<String> = None;
        loop {
            let mut url = url::Url::parse(&base_rewrite_url)
                .map_err(|e| Error::protocol(format!("parse GCS rewrite URL: {e}")))?;
            {
                let mut qp = url.query_pairs_mut();
                append_dst_precondition_query(
                    &mut qp,
                    &init.precondition,
                    init.existing_node_id.as_ref(),
                );
                if let Some(sg) = src_gen {
                    qp.append_pair("ifSourceGenerationMatch", sg);
                }
                if let Some(tok) = &rewrite_token {
                    qp.append_pair("rewriteToken", tok);
                }
                self.append_user_project_pair(&mut qp);
            }
            let mut headers = HeaderMap::new();
            if has_json_body {
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json; charset=UTF-8"),
                );
            }
            // The step that completes the rewrite commits the destination. With
            // `ifGenerationMatch=0`, replaying it after a lost response gets 412, so ambiguous
            // failures and 412s are reconciled against the destination's `rship-op-id`.
            let step = self
                .control_request_with_reconcile(
                    "GCS rewriteTo server-side copy",
                    Method::POST,
                    url.as_str(),
                    headers,
                    Some(meta_body.clone()),
                    true,
                    Idempotency::NonIdempotent,
                    |resp| {
                        if resp.status.is_success() {
                            return PolicyDecision::Ok(RewriteStep::Response(resp.body));
                        }
                        if resp.status == StatusCode::NOT_FOUND
                            || (fallback_on_403 && resp.status == StatusCode::FORBIDDEN)
                        {
                            return PolicyDecision::Ok(RewriteStep::Fallback);
                        }
                        let err = map_gcs_http_error_with_headers(
                            "GCS rewriteTo server-side copy",
                            resp.status,
                            Some(&resp.headers),
                            &resp.body,
                        );
                        if resp.status == StatusCode::PRECONDITION_FAILED {
                            return PolicyDecision::Reconcile(err);
                        }
                        PolicyDecision::from_error(err)
                    },
                    |err| {
                        let dst_full_key = dst_full_key.to_string();
                        async move {
                            let Some(obj) = self.get_object_meta(&dst_full_key).await? else {
                                if err.kind == ErrorKind::PreconditionFailed {
                                    if src_gen.is_some()
                                        && matches!(
                                            init.precondition,
                                            DstPrecondition::Absent | DstPrecondition::Any
                                        )
                                    {
                                        return Ok(ReconcileAction::Fail(Error::source_mutated(
                                            format!(
                                                "GCS rewriteTo source `{src_full_key}` mutated before copy ({err})"
                                            ),
                                        )));
                                    }
                                    return Ok(ReconcileAction::Fail(err));
                                }
                                return Ok(ReconcileAction::Retry(err));
                            };
                            let ours = obj
                                .metadata
                                .as_ref()
                                .and_then(|m| m.get(META_OP_ID))
                                .is_some_and(|id| *id == init.op_id);
                            if ours && obj.parsed_size() == init.total_size {
                                return Ok(ReconcileAction::Resolved(RewriteStep::Reconciled(
                                    Box::new(obj),
                                )));
                            }
                            if matches!(
                                err.kind,
                                ErrorKind::Conflict | ErrorKind::PreconditionFailed
                            ) {
                                // Another writer's object: a genuine conflict/precondition mismatch.
                                return Ok(ReconcileAction::Fail(err));
                            }
                            Ok(ReconcileAction::Retry(err))
                        }
                    },
                )
                .await?;

            let body = match step {
                RewriteStep::Reconciled(obj) => return self.object_to_entry(&obj),
                RewriteStep::Fallback => return Ok(None),
                RewriteStep::Response(body) => body,
            };
            let rw: GcsRewriteResponse = serde_json::from_slice(&body)
                .map_err(|e| Error::protocol(format!("parse GCS rewrite JSON: {e}")))?;
            if rw.done {
                if let Some(obj) = rw.resource {
                    return self.object_to_entry(&obj);
                }
                let Some(obj) = self.get_object_meta(dst_full_key).await? else {
                    return Ok(None);
                };
                return self.object_to_entry(&obj);
            }
            match rw.rewrite_token {
                Some(tok) if !tok.is_empty() => {
                    if rewrite_token.as_deref() == Some(tok.as_str()) {
                        return Err(Error::protocol(
                            "GCS rewriteTo returned duplicate rewriteToken",
                        ));
                    }
                    rewrite_token = Some(tok);
                }
                _ => {
                    return Err(Error::protocol(
                        "GCS rewriteTo returned done=false without rewriteToken",
                    ));
                }
            }
        }
    }

    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        let Some((src_bucket, src_pfx)) = self.parse_src_bucket_and_prefix(src_endpoint) else {
            return Ok(None);
        };
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
        let dst_full_key = self.inner.cfg.full_key(init.dst_path.as_str());
        self.rewrite_object(
            src_bucket,
            &src_full_key,
            src_path,
            &dst_full_key,
            init,
            true,
        )
        .await
    }

    pub(super) async fn rename_impl(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename GCS root path"));
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
        if path.kind == Some(EntryKind::Directory) {
            return Err(Error::unsupported(
                "GCS does not support renaming directories",
            ));
        }

        let src_raw_rel = path.raw_path().trim_end_matches('/');
        if src_raw_rel.is_empty() {
            return Err(Error::invalid_path("cannot rename empty GCS path"));
        }
        let dst_raw_rel = match src_raw_rel.rsplit_once('/') {
            Some((parent_raw, _)) if !parent_raw.is_empty() => format!("{parent_raw}/{new_name}"),
            _ => new_name.to_string(),
        };
        let new_rel = RelPath::parse(&dst_raw_rel)?;

        let Some(existing) = self.stat_impl(path).await? else {
            return Err(Error::not_found(format!(
                "GCS object `{}` not found",
                path.raw_path()
            )));
        };
        if existing.kind == EntryKind::Directory {
            return Err(Error::unsupported(
                "GCS does not support renaming directories",
            ));
        }
        if dst_raw_rel == src_raw_rel {
            return Ok(existing);
        }

        let seq = RENAME_OP_SEQ.fetch_add(1, Ordering::Relaxed);
        let now_ns = rship_core::time::now_unix_nanos();
        let src_full_key = self.inner.cfg.full_key(src_raw_rel);
        let dst_full_key = self.inner.cfg.full_key(&dst_raw_rel);
        let init = UploadInit {
            op_id: format!("rename-{}-{now_ns}-{seq}", existing.mtime_ns),
            dst_path: new_rel,
            existing_node_id: None,
            pregenerated_id: None,
            total_size: existing.size,
            src_mtime_ns: existing.mtime_ns,
            planned_chunk_size: self.inner.cfg.aligned_chunk_size(),
            checksums: existing.checksum.into_iter().collect(),
            precondition: DstPrecondition::Any,
            src_etag: existing.etag.clone(),
        };
        let entry = self
            .rewrite_object(
                &self.inner.cfg.bucket,
                &src_full_key,
                path,
                &dst_full_key,
                &init,
                false,
            )
            .await?
            .ok_or_else(|| Error::protocol("GCS rename rewriteTo failed"))?;
        self.delete_impl(path).await?;
        Ok(entry)
    }
}

/// Outcome of one `rewriteTo` step: the service's reply, a 404/403 fallback signal, or the
/// destination object proven (by reconcile) to be the committed result of this copy.
enum RewriteStep {
    Response(Bytes),
    Fallback,
    Reconciled(Box<GcsObject>),
}
