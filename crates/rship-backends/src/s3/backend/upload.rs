//! S3 data-plane reads (`open_read`), single-shot `PutObject`, parallel multipart
//! (`CreateMultipartUpload` / `ListParts` / `UploadPart` / `CompleteMultipartUpload` /
//! `AbortMultipartUpload`), and ambiguous-commit reconciliation.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{ByteRange, Checksum, Entry, EntryKind, HashKind};
use rship_core::{Error, ErrorKind, Result, RetryClass};
use std::sync::Arc;

use crate::common::http::{Idempotency, PolicyDecision, ReconcileAction};
use crate::s3::error::{classify_s3_error, classify_s3_xml_error};
use crate::s3::xml::{
    CompleteMultipartBody, build_complete_multipart_xml, parse_complete_multipart_response,
    parse_initiate_multipart_upload, parse_list_parts,
};
use rship_core::path::RelPath;

use super::streams::{
    S3RangeReader, decode_s3_base64_checksum_hex, extract_tagged_part_checksum_from_headers,
    extract_verified_checksum_from_headers, parse_http_date_nanos,
    try_insert_known_s3_checksum_header, verify_known_source_checksums_against_entry,
};
use super::{META_OP_ID, S3Backend, S3SessionMeta};

pub(super) struct MultipartCompleteParams<'a> {
    pub(super) op_id: &'a str,
    pub(super) full_key: &'a str,
    pub(super) upload_id: &'a str,
    pub(super) dst_nfc_path: &'a RelPath,
    pub(super) dst_raw_path: &'a str,
    pub(super) expected_size: u64,
    pub(super) planned_chunk_size: u64,
    pub(super) dst_precondition: &'a DstPrecondition,
    pub(super) part_checksum_kind: Option<HashKind>,
    pub(super) expected_checksums: &'a [Checksum],
}

pub(super) struct ReconcileParams<'a> {
    pub(super) op_id: &'a str,
    pub(super) full_key: &'a str,
    pub(super) dst_nfc_path: &'a RelPath,
    pub(super) dst_raw_path: &'a str,
    pub(super) expected_size: u64,
    pub(super) dst_precondition: &'a DstPrecondition,
}

impl S3Backend {
    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some(entry) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "S3 object `{}` not found",
                path.nfc_path
            )));
        };
        self.open_read_entry_impl(&entry, path, None)
    }

    pub(super) fn open_read_entry_impl(
        &self,
        entry: &Entry,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let raw_rel = path
            .raw_path
            .as_deref()
            .or(entry.raw_path.as_deref())
            .unwrap_or_else(|| path.nfc_path.as_str());
        let full_key = self.full_key(raw_rel);

        Ok(DataSource::RemoteRangeReadable(Arc::new(S3RangeReader {
            backend: self.clone(),
            full_key,
            total_len: entry.size,
            pinned_etag: entry.etag.clone(),
        })))
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        body: ByteStream,
    ) -> Result<Entry> {
        let full_key = self.full_key(init.dst_path.as_str());
        let mut headers = HeaderMap::new();
        let precomputed_sha256 = self.insert_common_object_headers(
            &mut headers,
            &init.dst_path,
            &init.op_id,
            init.src_mtime_ns,
            &init.checksums,
        )?;
        let has_preknown_checksum_header = try_insert_known_s3_checksum_header(
            &mut headers,
            &init.checksums,
            self.inner.profile.supports_crc64nvme,
            self.inner.profile.supports_single_part_crc32c,
        )?;

        // Conditional write protection when provider supports it!
        match &init.precondition {
            DstPrecondition::Absent if self.inner.profile.supports_if_none_match => {
                headers.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("*"));
            }
            DstPrecondition::Existing {
                etag: Some(etag), ..
            } if self.inner.profile.supports_if_match_write => {
                headers.insert(
                    http::header::IF_MATCH,
                    HeaderValue::from_str(etag)
                        .map_err(|e| Error::protocol(format!("invalid If-Match ETag: {e}")))?,
                );
            }
            _ => {}
        }

        let (resp_headers, _) = self
            .send_data_put(
                "PutObject",
                &full_key,
                &[],
                headers,
                body,
                init.total_size,
                precomputed_sha256.as_deref(),
                has_preknown_checksum_header,
                None,
                false,
            )
            .await?;

        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let server_checksum = extract_verified_checksum_from_headers(
            &resp_headers,
            etag.as_deref(),
            self.is_non_md5_sse(),
        );
        verify_known_source_checksums_against_entry(
            "PutObject",
            &init.checksums,
            server_checksum.as_ref(),
        )?;
        let checksum = server_checksum.or_else(|| {
            precomputed_sha256.map(|hex| Checksum {
                kind: HashKind::Sha256,
                hex,
            })
        });
        let mtime_ns = self
            .resolve_committed_mtime_ns(&full_key, &resp_headers)
            .await;

        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: init.total_size,
            mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        })
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.begin_multipart_upload_internal(init, true).await
    }

    pub(super) async fn begin_multipart_upload_internal(
        &self,
        init: &UploadInit,
        allow_part_checksums: bool,
    ) -> Result<UploadSessionInit> {
        let min_part = self
            .inner
            .cfg
            .min_part_bytes_override
            .unwrap_or(self.inner.profile.min_part_bytes);
        if init.total_size > self.inner.profile.max_object_bytes {
            return Err(Error::invalid_geometry(format!(
                "file size ({}) exceeds {} max_object_bytes ({})",
                init.total_size,
                self.inner.profile.provider.as_str(),
                self.inner.profile.max_object_bytes
            )));
        }
        if init.planned_chunk_size == 0
            || init.planned_chunk_size < min_part
            || init.planned_chunk_size > self.inner.profile.max_part_bytes
        {
            return Err(Error::invalid_geometry(format!(
                "planned_chunk_size ({}) outside {} part bounds [{min_part}, {}]",
                init.planned_chunk_size,
                self.inner.profile.provider.as_str(),
                self.inner.profile.max_part_bytes
            )));
        }
        let parts = init.total_size.div_ceil(init.planned_chunk_size);
        if parts > u64::from(self.inner.profile.max_parts) {
            return Err(Error::invalid_geometry(format!(
                "multipart upload requires {parts} parts > max_parts ({})",
                self.inner.profile.max_parts
            )));
        }

        let full_key = self.full_key(init.dst_path.as_str());
        let mut headers = HeaderMap::new();
        self.insert_common_object_headers(
            &mut headers,
            &init.dst_path,
            &init.op_id,
            init.src_mtime_ns,
            &init.checksums,
        )?;
        let part_checksum_algorithm = if allow_part_checksums {
            self.multipart_part_checksum_kind(init.planned_chunk_size)
        } else {
            None
        };
        match part_checksum_algorithm {
            // CRC64NVME supports only the FULL_OBJECT checksum type (the S3 default for it).
            Some(HashKind::Crc64Nvme) => {
                headers.insert(
                    HeaderName::from_static("x-amz-checksum-algorithm"),
                    HeaderValue::from_static("CRC64NVME"),
                );
            }
            // CRC32C defaults to COMPOSITE: Complete must list every part's checksum.
            Some(HashKind::Crc32c) => {
                headers.insert(
                    HeaderName::from_static("x-amz-checksum-algorithm"),
                    HeaderValue::from_static("CRC32C"),
                );
            }
            _ => {}
        }

        let query = vec![("uploads".to_string(), String::new())];
        let (_, _, body) = self
            .control_signed_request(
                "CreateMultipartUpload",
                Method::POST,
                &full_key,
                &query,
                headers,
                Bytes::new(),
                false,
                true,
            )
            .await?;

        let upload_id = parse_initiate_multipart_upload(&body)?;
        let backend_meta = serde_json::to_string(&S3SessionMeta {
            key: full_key,
            total_size: init.total_size,
            planned_chunk_size: init.planned_chunk_size,
            op_id: init.op_id.clone(),
            src_mtime_ns: init.src_mtime_ns,
            send_part_checksum_header: part_checksum_algorithm.is_some(),
            part_checksum_algorithm,
            expected_checksums: init.checksums.clone(),
        })
        .unwrap_or_default();

        Ok(UploadSessionInit {
            session_token: upload_id,
            backend_meta,
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    /// Paginate `ListParts` (`IsTruncated` / `NextPartNumberMarker`) to recover all
    /// completed parts on resume, returning `UploadProgress::Expired` on `NoSuchUpload`.
    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let upload_id = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("S3 query_upload called without upload_id"))?;
        let full_key = serde_json::from_str::<S3SessionMeta>(&op.backend_meta)
            .map(|m| m.key)
            .unwrap_or_else(|_| self.full_key(op.dst_nfc_path.as_str()));
        self.query_multipart_parts(&full_key, upload_id, op.planned_chunk_size)
            .await
    }

    async fn query_multipart_parts(
        &self,
        full_key: &str,
        upload_id: &str,
        planned_chunk_size: u64,
    ) -> Result<UploadProgress> {
        let mut parts = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut query = vec![
                ("uploadId".to_string(), upload_id.to_string()),
                ("max-parts".to_string(), "1000".to_string()),
            ];
            if let Some(ref m) = marker {
                query.push(("part-number-marker".to_string(), m.clone()));
            }

            let res = self
                .control_signed_request(
                    "ListParts",
                    Method::GET,
                    full_key,
                    &query,
                    HeaderMap::new(),
                    Bytes::new(),
                    false,
                    true,
                )
                .await;

            match res {
                Ok((_, _, body)) => {
                    let page = parse_list_parts(&body)?;
                    for lp in page.parts {
                        let offset = u64::from(lp.part_number.saturating_sub(1))
                            .saturating_mul(planned_chunk_size);
                        parts.push(CompletedPart {
                            part_number: lp.part_number,
                            offset,
                            length: lp.size,
                            etag: lp.etag,
                            checksum: lp.checksum,
                        });
                    }
                    if page.is_truncated {
                        marker = page
                            .next_part_number_marker
                            .or_else(|| parts.last().map(|p| p.part_number.to_string()));
                        if marker.is_none() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Err(e) if e.retry == RetryClass::SessionExpired => {
                    return Ok(UploadProgress::Expired);
                }
                Err(e) => return Err(e),
            }
        }

        parts.sort_by_key(|p| p.part_number);
        Ok(UploadProgress::CompletedParts(parts))
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        if chunk.part_number == 0 || chunk.part_number > self.inner.profile.max_parts {
            return Err(Error::invalid_geometry(format!(
                "invalid S3 part_number {} (must be in 1..={})",
                chunk.part_number, self.inner.profile.max_parts
            )));
        }
        let end_exclusive = chunk
            .offset
            .checked_add(chunk.len)
            .ok_or_else(|| Error::invalid_geometry("part offset + len overflow"))?;
        let is_final = end_exclusive == chunk.total_size;
        let min_part = self
            .inner
            .cfg
            .min_part_bytes_override
            .unwrap_or(self.inner.profile.min_part_bytes);
        if !is_final && chunk.len < min_part {
            return Err(Error::invalid_geometry(format!(
                "non-final S3 part {} length ({}) < min_part ({min_part})",
                chunk.part_number, chunk.len
            )));
        }
        if !is_final
            && self.inner.profile.require_equal_non_final_parts
            && chunk.len != op.planned_chunk_size
        {
            return Err(Error::invalid_geometry(format!(
                "{} requires equal non-final part sizes (got {}, expected locked {})",
                self.inner.profile.provider.as_str(),
                chunk.len,
                op.planned_chunk_size
            )));
        }

        let upload_id = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("S3 upload_chunk called without upload_id"))?;
        let session_meta = serde_json::from_str::<S3SessionMeta>(&op.backend_meta).ok();
        let full_key = session_meta
            .as_ref()
            .map(|m| m.key.clone())
            .unwrap_or_else(|| self.full_key(op.dst_nfc_path.as_str()));
        let multipart_checksum =
            self.session_part_checksum_kind(session_meta.as_ref(), op.planned_chunk_size);

        let query = vec![
            ("partNumber".to_string(), chunk.part_number.to_string()),
            ("uploadId".to_string(), upload_id.to_string()),
        ];
        let mut extra_headers = HeaderMap::new();
        self.apply_sse_c_headers_if_needed(&mut extra_headers)?;

        let (resp_headers, sent_part_checksum) = self
            .send_data_put(
                "UploadPart",
                &full_key,
                &query,
                extra_headers,
                chunk.body,
                chunk.len,
                None,
                false,
                multipart_checksum,
                true,
            )
            .await?;

        let etag = resp_headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                Error::protocol(format!(
                    "S3 UploadPart {} succeeded without ETag header",
                    chunk.part_number
                ))
            })?;
        let part_checksum =
            extract_tagged_part_checksum_from_headers(&resp_headers).or(sent_part_checksum);

        Ok(ChunkAck {
            next_offset: None,
            etag: Some(etag),
            completed: None,
            checksum: part_checksum,
        })
    }

    /// Per-part checksums to list in `CompleteMultipartUpload`, in `sorted` order.
    ///
    /// An upload created with `x-amz-checksum-algorithm` needs each part's checksum of THAT
    /// algorithm in the Complete request (required for COMPOSITE CRC32C, validated if present
    /// for FULL_OBJECT CRC64NVME). Parts recorded without one (e.g. resumed from a journal
    /// written by an older binary) are recovered from `ListParts`; if a COMPOSITE part checksum
    /// is still unknown, this fails with a clear error instead of sending a request S3 rejects.
    async fn complete_part_checksums(
        &self,
        full_key: &str,
        upload_id: &str,
        planned_chunk_size: u64,
        sorted: &[&CompletedPart],
        kind: Option<HashKind>,
    ) -> Result<Vec<Option<String>>> {
        let Some(kind) = kind else {
            return Ok(sorted.iter().map(|p| p.checksum.clone()).collect());
        };
        let tag = match kind {
            HashKind::Crc64Nvme => "crc64nvme:",
            HashKind::Crc32c => "crc32c:",
            _ => return Ok(sorted.iter().map(|p| p.checksum.clone()).collect()),
        };
        let usable = |ck: &Option<String>| {
            ck.as_deref()
                .filter(|c| c.starts_with(tag))
                .map(str::to_string)
        };
        let mut out: Vec<Option<String>> = sorted.iter().map(|p| usable(&p.checksum)).collect();
        if out.iter().all(Option::is_some) {
            return Ok(out);
        }

        if let UploadProgress::CompletedParts(listed) = self
            .query_multipart_parts(full_key, upload_id, planned_chunk_size)
            .await?
        {
            for (slot, part) in out.iter_mut().zip(sorted) {
                if slot.is_none()
                    && let Some(lp) = listed.iter().find(|lp| {
                        lp.part_number == part.part_number
                            && lp.etag.trim_matches('"') == part.etag.trim_matches('"')
                    })
                {
                    *slot = usable(&lp.checksum);
                }
            }
        }
        // FULL_OBJECT (CRC64NVME) uploads may omit part checksums; COMPOSITE ones may not.
        if kind == HashKind::Crc32c
            && let Some(missing) = sorted
                .iter()
                .zip(&out)
                .find_map(|(p, ck)| ck.is_none().then_some(p.part_number))
        {
            return Err(Error::protocol(format!(
                "S3 CompleteMultipartUpload: upload `{upload_id}` was created with a CRC32C (COMPOSITE) \
                 checksum but part {missing} has no recorded checksum and ListParts does not \
                 report one; S3 would reject the request. Abort the upload and transfer the \
                 file again.",
            )));
        }
        Ok(out)
    }

    /// Finalize S3 multipart upload, **mandatory inspection of `<Error>` XML inside
    /// HTTP `200 OK` responses** (`PLAN.md` P0-5) and R2 equal-non-final-part guard!
    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        parts: &[CompletedPart],
    ) -> Result<Entry> {
        let upload_id = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("S3 finish_upload called without upload_id"))?;
        let session_meta = serde_json::from_str::<S3SessionMeta>(&op.backend_meta).ok();
        let full_key = session_meta
            .as_ref()
            .map(|m| m.key.clone())
            .unwrap_or_else(|| self.full_key(op.dst_nfc_path.as_str()));
        let part_checksum_kind =
            self.session_part_checksum_kind(session_meta.as_ref(), op.planned_chunk_size);
        let expected_checksums = session_meta
            .map(|m| m.expected_checksums)
            .unwrap_or_default();

        self.complete_multipart_impl(
            MultipartCompleteParams {
                op_id: &op.op_id,
                full_key: &full_key,
                upload_id,
                dst_nfc_path: &op.dst_nfc_path,
                dst_raw_path: &op.dst_raw_path,
                expected_size: op.src_version.size,
                planned_chunk_size: op.planned_chunk_size,
                dst_precondition: &op.dst_precondition,
                part_checksum_kind,
                expected_checksums: &expected_checksums,
            },
            parts,
        )
        .await
    }

    pub(super) async fn complete_multipart_impl(
        &self,
        params: MultipartCompleteParams<'_>,
        parts: &[CompletedPart],
    ) -> Result<Entry> {
        if parts.is_empty() {
            return Err(Error::invalid_geometry(
                "CompleteMultipartUpload requires at least 1 part",
            ));
        }

        let mut sorted: Vec<&CompletedPart> = parts.iter().collect();
        sorted.sort_by_key(|p| p.part_number);

        // Cloudflare R2 enforces equal non-final part sizes across the manifest.
        if self.inner.profile.require_equal_non_final_parts && sorted.len() >= 2 {
            let expected = sorted[0].length;
            for p in &sorted[..sorted.len() - 1] {
                if p.length != expected {
                    return Err(Error::invalid_geometry(format!(
                        "{} requires equal non-final part sizes (part 1 = {expected}, part {} = {})",
                        self.inner.profile.provider.as_str(),
                        p.part_number,
                        p.length
                    )));
                }
            }
        }

        let recovered = self
            .complete_part_checksums(
                params.full_key,
                params.upload_id,
                params.planned_chunk_size,
                &sorted,
                params.part_checksum_kind,
            )
            .await?;
        let xml_parts: Vec<(u32, &str, Option<&str>)> = sorted
            .iter()
            .zip(&recovered)
            .map(|(p, ck)| (p.part_number, p.etag.as_str(), ck.as_deref()))
            .collect();
        let xml_body = Bytes::from(build_complete_multipart_xml(&xml_parts));

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        match params.dst_precondition {
            DstPrecondition::Absent if self.inner.profile.supports_if_none_match => {
                headers.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("*"));
            }
            DstPrecondition::Existing {
                etag: Some(etag), ..
            } if self.inner.profile.supports_if_match_write => {
                headers.insert(
                    http::header::IF_MATCH,
                    HeaderValue::from_str(etag)
                        .map_err(|e| Error::protocol(format!("invalid If-Match ETag: {e}")))?,
                );
            }
            _ => {}
        }

        enum CompleteOutcome {
            Completed {
                etag: Option<String>,
                checksum_crc64nvme: Option<String>,
                checksum_crc32c: Option<String>,
                checksum_sha256: Option<String>,
                resp_headers: HeaderMap,
            },
            Reconciled(Entry),
        }

        let query = vec![("uploadId".to_string(), params.upload_id.to_string())];
        let reconcile_params = ReconcileParams {
            op_id: params.op_id,
            full_key: params.full_key,
            dst_nfc_path: params.dst_nfc_path,
            dst_raw_path: params.dst_raw_path,
            expected_size: params.expected_size,
            dst_precondition: params.dst_precondition,
        };
        let outcome = self
            .control_signed_request_with_policy(
                "CompleteMultipartUpload",
                Method::POST,
                params.full_key,
                &query,
                headers,
                xml_body,
                true,
                Idempotency::Idempotent,
                |resp| {
                    if !resp.status.is_success() {
                        let err = classify_s3_error(
                            "CompleteMultipartUpload",
                            resp.status,
                            &resp.headers,
                            &resp.body,
                            true,
                        );
                        if err.retry == RetryClass::SessionExpired
                            || err.kind == ErrorKind::PreconditionFailed
                        {
                            return PolicyDecision::Reconcile(err);
                        }
                        return PolicyDecision::from_error(err);
                    }

                    // CRITICAL (`PLAN.md` P0-5): Inspect XML body EVEN on HTTP `200 OK`!
                    match parse_complete_multipart_response(&resp.body) {
                        Ok(CompleteMultipartBody::Completed {
                            etag,
                            checksum_crc64nvme,
                            checksum_crc32c,
                            checksum_sha256,
                        }) => PolicyDecision::Ok(CompleteOutcome::Completed {
                            etag,
                            checksum_crc64nvme,
                            checksum_crc32c,
                            checksum_sha256,
                            resp_headers: resp.headers,
                        }),
                        Ok(CompleteMultipartBody::Error(xml_err)) => {
                            let mapped = classify_s3_xml_error(
                                "CompleteMultipartUpload(200)",
                                resp.status,
                                &resp.headers,
                                &xml_err,
                            );
                            if mapped.retry == RetryClass::SessionExpired
                                || mapped.kind == ErrorKind::PreconditionFailed
                            {
                                return PolicyDecision::Reconcile(mapped);
                            }
                            PolicyDecision::from_error(mapped)
                        }
                        Err(parse_err) => PolicyDecision::from_error(parse_err),
                    }
                },
                |err| async {
                    if let Ok(ReconcileOutcome::Committed(entry)) =
                        self.reconcile_object_impl(&reconcile_params).await
                    {
                        return Ok(ReconcileAction::Resolved(CompleteOutcome::Reconciled(
                            entry,
                        )));
                    }
                    Ok(ReconcileAction::Fail(err))
                },
            )
            .await?;

        let (etag, ck_crc64, ck_crc32c, ck_sha256, complete_headers) = match outcome {
            CompleteOutcome::Reconciled(entry) => return Ok(entry),
            CompleteOutcome::Completed {
                etag,
                checksum_crc64nvme,
                checksum_crc32c,
                checksum_sha256,
                resp_headers,
            } => (
                etag,
                checksum_crc64nvme,
                checksum_crc32c,
                checksum_sha256,
                resp_headers,
            ),
        };
        let checksum = ck_crc64
            .as_deref()
            .and_then(|v| decode_s3_base64_checksum_hex(v, 8))
            .map(|hex| Checksum {
                kind: HashKind::Crc64Nvme,
                hex,
            })
            .or_else(|| {
                ck_crc32c
                    .as_deref()
                    .and_then(|v| decode_s3_base64_checksum_hex(v, 4))
                    .map(|hex| Checksum {
                        kind: HashKind::Crc32c,
                        hex,
                    })
            })
            .or_else(|| {
                ck_sha256
                    .as_deref()
                    .and_then(|v| decode_s3_base64_checksum_hex(v, 32))
                    .map(|hex| Checksum {
                        kind: HashKind::Sha256,
                        hex,
                    })
            });
        verify_known_source_checksums_against_entry(
            "CompleteMultipartUpload",
            params.expected_checksums,
            checksum.as_ref(),
        )?;
        let mtime_ns = self
            .resolve_committed_mtime_ns(params.full_key, &complete_headers)
            .await;

        Ok(Entry {
            node_id: None,
            parent_id: None,
            raw_path: rship_core::types::raw_path_override(
                params.dst_nfc_path,
                params.dst_raw_path,
            ),
            nfc_path: params.dst_nfc_path.clone(),
            kind: EntryKind::File,
            size: params.expected_size,
            mtime_ns,
            ctime_ns: None,
            etag,
            checksum,
        })
    }

    /// Resolve S3's server-assigned `Last-Modified` timestamp so `sync_baseline` matches
    /// subsequent `ListObjectsV2` / `HeadObject` observations without re-hashing local files
    /// (and enabling O(1) skips when wrapped by `CryptoBackend`).
    pub(super) async fn resolve_committed_mtime_ns(
        &self,
        full_key: &str,
        resp_headers: &HeaderMap,
    ) -> i64 {
        if let Some(ns) = resp_headers
            .get(http::header::LAST_MODIFIED)
            .or_else(|| resp_headers.get(http::header::DATE))
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date_nanos)
        {
            return ns;
        }
        if let Ok(Some(h)) = self.head_object_raw(full_key).await
            && let Some(ns) = h
                .get(http::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_http_date_nanos)
        {
            return ns;
        }
        self.inner.clock.now_unix_secs() * 1_000_000_000
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        let Some(upload_id) = op.session_token.as_deref() else {
            return Ok(());
        };
        let full_key = serde_json::from_str::<S3SessionMeta>(&op.backend_meta)
            .map(|m| m.key)
            .unwrap_or_else(|_| self.full_key(op.dst_nfc_path.as_str()));

        match self.abort_multipart_by_id(&full_key, upload_id).await {
            Ok(()) => Ok(()),
            Err(e) if e.retry == RetryClass::SessionExpired || e.kind == ErrorKind::NotFound => {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Reconcile an ambiguous S3 commit (`NoSuchUpload` / crash during `Completing`)
    /// by checking `HeadObject` for `x-amz-meta-rship-op-id == op.op_id` + size match.
    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let full_key = serde_json::from_str::<S3SessionMeta>(&op.backend_meta)
            .map(|m| m.key)
            .unwrap_or_else(|_| self.full_key(op.dst_nfc_path.as_str()));
        self.reconcile_object_impl(&ReconcileParams {
            op_id: &op.op_id,
            full_key: &full_key,
            dst_nfc_path: &op.dst_nfc_path,
            dst_raw_path: &op.dst_raw_path,
            expected_size: op.src_version.size,
            dst_precondition: &op.dst_precondition,
        })
        .await
    }

    pub(super) async fn reconcile_object_impl(
        &self,
        params: &ReconcileParams<'_>,
    ) -> Result<ReconcileOutcome> {
        let Some(headers) = self.head_object_raw(params.full_key).await? else {
            return Ok(ReconcileOutcome::NotCommitted);
        };

        let entry = self.headers_to_entry(
            &headers,
            params.dst_raw_path,
            params.dst_nfc_path.clone(),
            EntryKind::File,
        );
        let op_id_matches = headers
            .get(META_OP_ID)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == params.op_id);

        if op_id_matches && entry.size == params.expected_size {
            return Ok(ReconcileOutcome::Committed(entry));
        }

        if let DstPrecondition::Existing {
            etag: Some(old_etag),
            size: old_size,
            ..
        } = params.dst_precondition
            && !op_id_matches
            && entry.etag.as_deref() == Some(old_etag.as_str())
            && entry.size == *old_size
        {
            return Ok(ReconcileOutcome::NotCommitted);
        }

        Ok(ReconcileOutcome::Ambiguous(format!(
            "S3 object `{}` does not match op_id `{}` (size={}, expected={}, op_id_match={op_id_matches})",
            params.full_key, params.op_id, entry.size, params.expected_size
        )))
    }
}
