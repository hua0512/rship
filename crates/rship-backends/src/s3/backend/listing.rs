//! S3 object listing (single-prefix & parallel prefix-split), stat, mkdir,
//! single/bulk delete (`DeleteObjects`), multipart upload listing, and checksum lookup.

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use md5::Md5;
use rship_core::backend::{BackendPath, EntryStream, OrderedListPage};
use rship_core::path::RelPath;
use rship_core::types::{Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, Result};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

use crate::common::http::{Idempotency, PolicyDecision, ReconcileAction};
use crate::s3::error::{classify_s3_error, classify_s3_xml_error};
use crate::s3::xml::{
    DeleteObjectsBody, ListedObject, S3ErrorXml, build_delete_objects_xml, is_xml10_safe,
    parse_delete_objects_response, parse_list_multipart_uploads,
};

use super::streams::{extract_checksum_of_kind_from_headers, parse_single_part_md5_from_etag};
use super::{MultipartUploadInfo, S3Backend};

impl S3Backend {
    pub async fn list_multipart_uploads(&self) -> Result<Vec<MultipartUploadInfo>> {
        self.list_multipart_uploads_under(&RelPath::root()).await
    }

    pub async fn list_multipart_uploads_under(
        &self,
        sub_prefix: &RelPath,
    ) -> Result<Vec<MultipartUploadInfo>> {
        let mut all = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut upload_id_marker: Option<String> = None;
        let prefix = if sub_prefix.is_root() {
            self.bucket_prefix_with_slash().to_string()
        } else {
            format!(
                "{}/",
                self.full_key(sub_prefix.as_str()).trim_end_matches('/')
            )
        };

        loop {
            let mut query = vec![
                ("uploads".to_string(), String::new()),
                ("encoding-type".to_string(), "url".to_string()),
            ];
            if !prefix.is_empty() {
                query.push(("prefix".to_string(), prefix.clone()));
            }
            if let Some(ref km) = key_marker {
                query.push(("key-marker".to_string(), km.clone()));
            }
            if let Some(ref um) = upload_id_marker {
                query.push(("upload-id-marker".to_string(), um.clone()));
            }

            let (_, _, body) = self
                .control_signed_request(
                    "ListMultipartUploads",
                    Method::GET,
                    "",
                    &query,
                    HeaderMap::new(),
                    Bytes::new(),
                    false,
                    false,
                )
                .await?;
            let page = parse_list_multipart_uploads(&body)?;
            for u in page.uploads {
                all.push(MultipartUploadInfo {
                    key: u.key,
                    upload_id: u.upload_id,
                    initiated: u.initiated,
                });
            }
            if page.is_truncated {
                key_marker = page.next_key_marker;
                upload_id_marker = page.next_upload_id_marker;
                if key_marker.is_none() && upload_id_marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(all)
    }

    /// Abort an explicit `(key, upload_id)` multipart upload session (bucket GC).
    pub async fn abort_multipart_by_id(&self, full_key: &str, upload_id: &str) -> Result<()> {
        let query = vec![("uploadId".to_string(), upload_id.to_string())];
        let _ = self
            .control_signed_request(
                "AbortMultipartUpload",
                Method::DELETE,
                full_key,
                &query,
                HeaderMap::new(),
                Bytes::new(),
                true,
                true,
            )
            .await?;
        Ok(())
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
        let key = self.full_key(raw_rel);

        // 1. Check exact object key first.
        if let Some(headers) = self.head_object_raw(&key).await? {
            let content_len = headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let kind = if raw_rel.ends_with('/') && content_len == 0 {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            let entry_raw = if kind == EntryKind::Directory {
                raw_rel.trim_end_matches('/')
            } else {
                raw_rel
            };
            return Ok(Some(self.headers_to_entry(
                &headers,
                entry_raw,
                path.nfc_path.clone(),
                kind,
            )));
        }

        // 2. Check explicit 0-byte directory marker `{key}/`.
        if !key.ends_with('/') {
            let dir_marker = format!("{key}/");
            if let Some(headers) = self.head_object_raw(&dir_marker).await? {
                let content_len = headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                if content_len == 0 {
                    return Ok(Some(self.headers_to_entry(
                        &headers,
                        raw_rel,
                        path.nfc_path.clone(),
                        EntryKind::Directory,
                    )));
                }
            }

            // 3. Check implicit prefix directory (any child under `{key}/`).
            // Request `max_keys = 2` so a non-empty trailing-`/` object `{key}/` does not hide
            // an actual child `{key}/child` behind `max_keys = 1`, and require a non-self child.
            let page = self
                .list_v2_page(&dir_marker, None, None, None, Some(2))
                .await?;
            if page.objects.iter().any(|o| o.key != dir_marker) || !page.common_prefixes.is_empty()
            {
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
        }

        Ok(None)
    }

    pub(super) async fn list_stream_impl(
        &self,
        prefix: &RelPath,
        recursive: bool,
    ) -> Result<EntryStream> {
        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let backend = self.clone();
        let search_prefix = if prefix.is_root() {
            self.bucket_prefix_with_slash().to_string()
        } else {
            format!("{}/", self.full_key(prefix.as_str()))
        };

        tokio::spawn(async move {
            let split_conc = backend.inner.cfg.list_prefix_concurrency;
            if recursive && split_conc > 1 {
                // Parallel lexicographical prefix-split listing (`s5cmd` / `s3sync` style):
                // probe 1st-level prefixes via `delimiter="/"` then fan out concurrently.
                if let Err(e) = list_prefix_split(&backend, &search_prefix, split_conc, &tx).await {
                    let _ = tx.send(Err(e)).await;
                }
            } else if let Err(e) =
                list_single_prefix(&backend, &search_prefix, recursive, true, &tx).await
            {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(crate::common::rx_to_entry_stream(rx))
    }

    /// Fetch one lexicographically ascending UTF-8 page relative to `prefix` (`delimiter = None`)
    /// for zero-disk streaming merge-join and Two-Gear range work-stealing.
    pub(super) async fn list_ordered_page_impl(
        &self,
        prefix: &RelPath,
        start_after: Option<&str>,
        continuation: Option<&str>,
        max_keys: u32,
    ) -> Result<OrderedListPage> {
        let search_prefix = if prefix.is_root() {
            self.bucket_prefix_with_slash().to_string()
        } else {
            format!("{}/", self.full_key(prefix.as_str()))
        };

        let prev_cursor = match continuation {
            Some(c) if let Some(tok) = c.strip_prefix("v2:") => ListCursor::V2(tok.to_string()),
            Some(c) if let Some(m) = c.strip_prefix("v1:") => ListCursor::V1(m.to_string()),
            Some(c) => ListCursor::V2(c.to_string()),
            None => ListCursor::Start,
        };
        let (ct, v1_marker) = prev_cursor.tokens();
        let full_start_after = if continuation.is_none() {
            start_after.map(|sa| format!("{search_prefix}{sa}"))
        } else {
            None
        };

        let page = self
            .list_v2_page_with_start_after(
                &search_prefix,
                None,
                ct,
                v1_marker,
                full_start_after.as_deref(),
                Some(max_keys.clamp(1, 1000)),
            )
            .await?;

        let next = advance_list_cursor(&prev_cursor, &page)?;
        let (is_truncated, next_cursor, supports_start_after) = match next {
            Some(ListCursor::V2(tok)) => (true, Some(format!("v2:{tok}")), true),
            Some(ListCursor::V1(m)) => (true, Some(format!("v1:{m}")), false),
            Some(ListCursor::Start) => unreachable!(),
            None => (false, None, true),
        };

        let mut entries = Vec::with_capacity(page.objects.len());
        let mut last_wire_key: Option<String> = None;
        let mut last_dir: Option<String> = None;
        let mut dedupe = DirDedupe::Last(&mut last_dir);

        for obj in page.objects {
            if obj.key == search_prefix {
                continue;
            }
            let rel_raw = if search_prefix.is_empty() {
                obj.key.clone()
            } else {
                let Some(rest) = obj.key.strip_prefix(&search_prefix) else {
                    continue;
                };
                rest.to_string()
            };
            if rel_raw.is_empty() {
                continue;
            }
            last_wire_key = Some(rel_raw.clone());

            if let Some(entry) = listed_object_to_entry(self, obj, &rel_raw, &mut dedupe) {
                entries.push(entry);
            }
        }

        Ok(OrderedListPage {
            entries,
            is_truncated,
            next_cursor,
            last_wire_key,
            supports_start_after,
        })
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        let dir_key = format!("{}/", self.full_key(path.as_str()));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-directory"),
        );
        self.apply_sse_headers(&mut headers)?;
        let _ = self
            .control_signed_request(
                "PutObject(dir_marker)",
                Method::PUT,
                &dir_key,
                &[],
                headers,
                Bytes::new(),
                false,
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
        let key = self.full_key(raw_rel);
        // Branch strictly on `path.kind` so deleting a directory marker (`"foo/"`) NEVER
        // deletes a live file named `"foo"`, and deleting a known file emits 1 RPC.
        match path.kind {
            Some(EntryKind::Directory) => {
                let dir_key = format!("{}/", key.trim_end_matches('/'));
                let _ = self
                    .control_signed_request(
                        "DeleteObject(dir_marker)",
                        Method::DELETE,
                        &dir_key,
                        &[],
                        HeaderMap::new(),
                        Bytes::new(),
                        true,
                        false,
                    )
                    .await?;
            }
            Some(EntryKind::File) => {
                let _ = self
                    .control_signed_request(
                        "DeleteObject",
                        Method::DELETE,
                        &key,
                        &[],
                        HeaderMap::new(),
                        Bytes::new(),
                        true,
                        false,
                    )
                    .await?;
            }
            _ => {
                let _ = self
                    .control_signed_request(
                        "DeleteObject",
                        Method::DELETE,
                        &key,
                        &[],
                        HeaderMap::new(),
                        Bytes::new(),
                        true,
                        false,
                    )
                    .await?;
                let dir_key = format!("{}/", key.trim_end_matches('/'));
                if self.head_object_raw(&dir_key).await?.is_some() {
                    let _ = self
                        .control_signed_request(
                            "DeleteObject(dir_marker)",
                            Method::DELETE,
                            &dir_key,
                            &[],
                            HeaderMap::new(),
                            Bytes::new(),
                            true,
                            false,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn delete_batch_impl(
        &self,
        paths: &[BackendPath],
    ) -> Result<Vec<(BackendPath, Error)>> {
        let items: Vec<(String, BackendPath)> = paths
            .iter()
            .filter(|bp| !bp.nfc_path.is_root())
            .map(|bp| {
                let full = self.full_key(bp.raw_path());
                let key = if bp.kind == Some(EntryKind::Directory) {
                    format!("{}/", full.trim_end_matches('/'))
                } else {
                    full
                };
                (key, bp.clone())
            })
            .collect();
        if items.is_empty() {
            return Ok(Vec::new());
        }

        let mut failures: Vec<(BackendPath, Error)> = Vec::new();
        let (xml_safe_items, unsafe_items): (Vec<_>, Vec<_>) =
            items.into_iter().partition(|(key, _)| is_xml10_safe(key));

        // Keys containing XML 1.0 illegal characters (e.g. ASCII control chars)
        // cannot appear in `<Delete>` XML without triggering `MalformedXML` for the
        // entire batch; isolate and delete them individually via `DELETE`.
        for (key, bp) in unsafe_items {
            if let Err(err) = self
                .control_signed_request(
                    "DeleteObject",
                    Method::DELETE,
                    &key,
                    &[],
                    HeaderMap::new(),
                    Bytes::new(),
                    true,
                    false,
                )
                .await
            {
                failures.push((bp, err));
            }
        }

        let query = vec![("delete".to_string(), String::new())];
        let max_retries = self.inner.cfg.max_retries;

        // S3 `DeleteObjects` accepts up to 1,000 keys per POST request.
        for chunk in xml_safe_items.chunks(1000) {
            let mut pending: Vec<(String, BackendPath)> = chunk.to_vec();
            let mut attempt = 0u32;

            while !pending.is_empty() {
                let key_refs: Vec<&str> = pending.iter().map(|(k, _)| k.as_str()).collect();
                let xml = build_delete_objects_xml(&key_refs);
                let md5_digest = Md5::digest(xml.as_bytes());
                let content_md5 = base64::engine::general_purpose::STANDARD.encode(md5_digest);

                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                );
                headers.insert(
                    HeaderName::from_static("content-md5"),
                    HeaderValue::from_str(&content_md5)
                        .map_err(|e| Error::protocol(format!("invalid Content-MD5 header: {e}")))?,
                );

                let (resp_status, resp_headers, batch_errors) = self
                    .control_signed_request_with_policy(
                        "DeleteObjects",
                        Method::POST,
                        "",
                        &query,
                        headers,
                        Bytes::from(xml),
                        false,
                        Idempotency::Idempotent,
                        |resp| {
                            if !resp.status.is_success() {
                                let err = classify_s3_error(
                                    "DeleteObjects",
                                    resp.status,
                                    &resp.headers,
                                    &resp.body,
                                    false,
                                );
                                return PolicyDecision::from_error(err);
                            }
                            match parse_delete_objects_response(&resp.body) {
                                Ok(DeleteObjectsBody::Result { errors }) => {
                                    PolicyDecision::Ok((resp.status, resp.headers, errors))
                                }
                                Ok(DeleteObjectsBody::TopLevelError(xml_err)) => {
                                    let mapped = classify_s3_xml_error(
                                        "DeleteObjects",
                                        resp.status,
                                        &resp.headers,
                                        &xml_err,
                                    );
                                    PolicyDecision::from_error(mapped)
                                }
                                Err(parse_err) => PolicyDecision::from_error(parse_err),
                            }
                        },
                        |err| async move { Ok(ReconcileAction::Fail(err)) },
                    )
                    .await?;

                if batch_errors.is_empty() {
                    break;
                }

                let by_key: HashMap<&str, &BackendPath> =
                    pending.iter().map(|(k, bp)| (k.as_str(), bp)).collect();
                let mut next_pending = Vec::new();
                let mut retry_after: Option<Duration> = None;

                for de in batch_errors {
                    let xml_err = S3ErrorXml {
                        code: de.code,
                        message: de.message,
                        request_id: None,
                    };
                    let err = classify_s3_xml_error(
                        "DeleteObjects",
                        resp_status,
                        &resp_headers,
                        &xml_err,
                    );
                    if let Some(&bp) = by_key.get(de.key.as_str()) {
                        if err.is_retryable() && attempt < max_retries {
                            if let Some(ra) = err.retry_after {
                                retry_after =
                                    Some(retry_after.map_or(ra, |cur: Duration| cur.max(ra)));
                            }
                            next_pending.push((de.key, bp.clone()));
                        } else {
                            failures.push((bp.clone(), err));
                        }
                    } else if let Ok(rel) = RelPath::parse(&de.key) {
                        failures.push((BackendPath::from_rel(rel), err));
                    }
                }

                if next_pending.is_empty() {
                    break;
                }
                let exp_ms = (self.inner.cfg.base_retry_delay.as_millis() as u64)
                    .saturating_mul(1u64 << attempt.min(10));
                let mut delay = Duration::from_millis(exp_ms).min(self.inner.cfg.max_retry_delay);
                if let Some(ra) = retry_after {
                    delay = delay.max(ra).min(self.inner.cfg.max_retry_delay);
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                pending = next_pending;
                attempt += 1;
            }
        }

        Ok(failures)
    }

    pub(super) async fn compute_hash_impl(
        &self,
        path: &BackendPath,
        kind: HashKind,
    ) -> Result<Option<Checksum>> {
        if path.nfc_path.is_root() {
            return Ok(None);
        }
        let key = self.full_key(path.raw_path());
        let Some(headers) = self.head_object_raw(&key).await? else {
            return Ok(None);
        };
        let etag = headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok());
        Ok(extract_checksum_of_kind_from_headers(
            &headers,
            etag,
            kind,
            self.is_non_md5_sse(),
        ))
    }
}

enum ListCursor {
    Start,
    V2(String),
    V1(String),
}

impl ListCursor {
    fn tokens(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Start => (None, None),
            Self::V2(ct) => (Some(ct.as_str()), None),
            Self::V1(m) => (None, Some(m.as_str())),
        }
    }
}

/// Resolve the next pagination cursor for `ListObjectsV2` / legacy v1 fallback.
///
/// Crucially NEVER silently terminates on `IsTruncated = true` without a valid advancing
/// token/marker (preventing 1,000-key silent truncation & mass-delete hazards on legacy
/// Swift `swift3` / S3 gateways).
fn advance_list_cursor(
    prev: &ListCursor,
    page: &crate::s3::xml::ListObjectsV2Page,
) -> Result<Option<ListCursor>> {
    if !page.is_truncated {
        return Ok(None);
    }
    if let Some(ref ct) = page.next_continuation_token {
        if let ListCursor::V2(old) = prev
            && ct == old
        {
            return Err(Error::protocol(
                "S3 ListObjectsV2 returned IsTruncated=true with unchanged NextContinuationToken",
            ));
        }
        return Ok(Some(ListCursor::V2(ct.clone())));
    }
    // Legacy v1 fallback: use `<NextMarker>`, or the lexicographically greatest returned key/prefix.
    let candidate = page.next_marker.as_deref().or_else(|| {
        page.objects
            .last()
            .map(|o| o.key.as_str())
            .into_iter()
            .chain(page.common_prefixes.last().map(String::as_str))
            .max()
    });
    match candidate {
        Some(m) if !m.is_empty() => {
            if let ListCursor::V1(old) = prev
                && m <= old.as_str()
            {
                return Err(Error::protocol(format!(
                    "S3 ListObjects returned IsTruncated=true with non-advancing v1 marker `{m}` <= `{old}`"
                )));
            }
            Ok(Some(ListCursor::V1(m.to_string())))
        }
        _ => Err(Error::protocol(
            "S3 ListObjects returned IsTruncated=true without NextContinuationToken or NextMarker",
        )),
    }
}

async fn list_single_prefix(
    backend: &S3Backend,
    search_prefix: &str,
    recursive: bool,
    skip_exact_prefix: bool,
    tx: &mpsc::Sender<Result<Entry>>,
) -> Result<()> {
    let delimiter = if recursive { None } else { Some("/") };
    let mut cursor = ListCursor::Start;
    // In recursive mode (`delimiter=None`), S3 keys are unique & sorted so O(1) last-dir
    // tracking replaces an unbounded `HashSet` over millions of directory markers.
    let mut last_recursive_dir: Option<String> = None;
    let mut shallow_emitted_dirs: HashSet<String> = HashSet::new();

    loop {
        if tx.is_closed() {
            return Ok(());
        }
        let (ct, v1_marker) = cursor.tokens();
        let page = backend
            .list_v2_page(search_prefix, delimiter, ct, v1_marker, None)
            .await?;
        let next_cursor = advance_list_cursor(&cursor, &page)?;

        for cp in page.common_prefixes {
            if tx.is_closed() {
                return Ok(());
            }
            if cp == search_prefix {
                continue;
            }
            if let Some(rel) = backend.strip_bucket_prefix(&cp) {
                let trimmed = rel.trim_end_matches('/');
                if !trimmed.is_empty()
                    && shallow_emitted_dirs.insert(trimmed.to_string())
                    && let Ok(nfc) = RelPath::parse(trimmed)
                {
                    let entry = Entry {
                        node_id: None,
                        parent_id: None,
                        raw_path: rship_core::types::raw_path_override(&nfc, trimmed),
                        nfc_path: nfc,
                        kind: EntryKind::Directory,
                        size: 0,
                        mtime_ns: 0,
                        ctime_ns: None,
                        etag: None,
                        checksum: None,
                    };
                    if tx.send(Ok(entry)).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }

        for obj in page.objects {
            if tx.is_closed() {
                return Ok(());
            }
            if skip_exact_prefix && obj.key == search_prefix {
                continue;
            }
            let Some(rel_raw) = backend.strip_bucket_prefix(&obj.key).map(str::to_string) else {
                continue;
            };
            if rel_raw.is_empty() {
                continue;
            }
            let mut dedupe = if recursive {
                DirDedupe::Last(&mut last_recursive_dir)
            } else {
                DirDedupe::Set(&mut shallow_emitted_dirs)
            };
            if let Some(entry) = listed_object_to_entry(backend, obj, &rel_raw, &mut dedupe)
                && tx.send(Ok(entry)).await.is_err()
            {
                return Ok(());
            }
        }

        match next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Ok(())
}

enum DirDedupe<'a> {
    None,
    Last(&'a mut Option<String>),
    Set(&'a mut HashSet<String>),
}

impl DirDedupe<'_> {
    fn should_emit_dir(&mut self, trimmed: &str) -> bool {
        match self {
            Self::None => true,
            Self::Last(last) => {
                if last.as_deref() == Some(trimmed) {
                    false
                } else {
                    **last = Some(trimmed.to_string());
                    true
                }
            }
            Self::Set(set) => set.insert(trimmed.to_string()),
        }
    }
}

fn listed_object_to_entry(
    backend: &S3Backend,
    obj: ListedObject,
    rel_raw: &str,
    dedupe: &mut DirDedupe<'_>,
) -> Option<Entry> {
    // Only 0-byte objects ending with `/` are explicit S3 directory markers;
    // non-empty keys ending with `/` are genuine objects whose key ends in `/`.
    if rel_raw.ends_with('/') && obj.size == 0 {
        let trimmed = rel_raw.trim_end_matches('/');
        if trimmed.is_empty() || !dedupe.should_emit_dir(trimmed) {
            return None;
        }
        let nfc = RelPath::parse(trimmed).ok()?;
        return Some(Entry {
            node_id: None,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(&nfc, trimmed),
            nfc_path: nfc,
            kind: EntryKind::Directory,
            size: 0,
            mtime_ns: obj.last_modified_ns.unwrap_or(0),
            ctime_ns: None,
            etag: obj.etag,
            checksum: None,
        });
    }

    let nfc = RelPath::parse(rel_raw).ok()?;
    if nfc.is_root() {
        return None;
    }
    let raw_path = rship_core::types::raw_path_override(&nfc, rel_raw);
    let mtime_ns = obj.last_modified_ns.unwrap_or(0);
    let checksum = if backend.is_non_md5_sse() {
        None
    } else {
        obj.etag
            .as_deref()
            .and_then(parse_single_part_md5_from_etag)
            .map(|hex| Checksum {
                kind: HashKind::Md5,
                hex,
            })
    };
    Some(Entry {
        node_id: None,
        parent_id: None,
        raw_path,
        nfc_path: nfc,
        kind: EntryKind::File,
        size: obj.size,
        mtime_ns,
        ctime_ns: None,
        etag: obj.etag,
        checksum,
    })
}

async fn list_prefix_split(
    backend: &S3Backend,
    search_prefix: &str,
    concurrency: usize,
    tx: &mpsc::Sender<Result<Entry>>,
) -> Result<()> {
    // 1. Discover top-level `CommonPrefixes` + top-level objects using `delimiter="/"`.
    let mut sub_prefixes = Vec::new();
    let mut seen_prefixes = HashSet::new();
    let mut cursor = ListCursor::Start;

    loop {
        if tx.is_closed() {
            return Ok(());
        }
        let (ct, v1_marker) = cursor.tokens();
        let page = backend
            .list_v2_page(search_prefix, Some("/"), ct, v1_marker, None)
            .await?;
        let next_cursor = advance_list_cursor(&cursor, &page)?;

        for cp in page.common_prefixes {
            if cp != search_prefix && seen_prefixes.insert(cp.clone()) {
                sub_prefixes.push(cp);
            }
        }
        for obj in page.objects {
            if tx.is_closed() {
                return Ok(());
            }
            if obj.key == search_prefix {
                continue;
            }
            let Some(rel_raw) = backend.strip_bucket_prefix(&obj.key).map(str::to_string) else {
                continue;
            };
            if rel_raw.is_empty() {
                continue;
            }
            if let Some(entry) =
                listed_object_to_entry(backend, obj, &rel_raw, &mut DirDedupe::None)
                && tx.send(Ok(entry)).await.is_err()
            {
                return Ok(());
            }
        }

        match next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }

    // 2. Fan out listing each discovered sub-prefix concurrently under bounded semaphore.
    //    Only real `"{dir}/"` marker objects inside `list_single_prefix` emit `EntryKind::Directory`
    //    (matching `list_single_prefix` and `list_ordered_page_impl` without synthesizing phantom dirs).
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(sub_prefixes.len());
    for sp in sub_prefixes {
        if tx.is_closed() {
            break;
        }
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::cancelled("prefix split semaphore closed"))?;
        let b = backend.clone();
        let tx_c = tx.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            list_single_prefix(&b, &sp, true, false, &tx_c).await
        }));
    }

    for h in handles {
        if let Ok(Err(e)) = h.await {
            return Err(e);
        }
    }
    Ok(())
}
