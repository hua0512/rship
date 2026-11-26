//! Zero-local-bandwidth S3 server-side copy (`CopyObject` + multipart `UploadPartCopy`).

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rship_core::backend::{BackendPath, CompletedPart, UploadInit};
use rship_core::state::DstPrecondition;
use rship_core::types::{Entry, EntryKind};
use rship_core::{Error, ErrorKind, Result};

use crate::common::http::{Idempotency, PolicyDecision, ReconcileAction};
use crate::s3::error::{classify_s3_error, classify_s3_xml_error};
use crate::s3::provider::S3Provider;
use crate::s3::sigv4::{aws_uri_encode, aws_uri_encode_path};
use crate::s3::xml::{CopyResultBody, parse_copy_result};

use super::streams::{extract_tagged_part_checksum_from_headers, parse_rfc3339_or_http_nanos};
use super::upload::MultipartCompleteParams;
use super::{META_OP_ID, S3Backend};

/// Default ceiling for single-request `CopyObject` (512 MiB), clamped by the provider's
/// `max_part_bytes`. Larger objects automatically switch to parallel multipart `UploadPartCopy`
/// so multi-GiB server-side copies do not stall on a single HTTP request.
pub(crate) const DEFAULT_MAX_SINGLE_COPY_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn effective_single_copy_limit(
    cfg_override: Option<u64>,
    profile_max_part_bytes: u64,
) -> u64 {
    cfg_override
        .map(|v| v.clamp(1, profile_max_part_bytes))
        .unwrap_or_else(|| DEFAULT_MAX_SINGLE_COPY_BYTES.min(profile_max_part_bytes))
}

pub(crate) fn compute_multipart_copy_part_size(
    total_size: u64,
    planned_chunk_size: u64,
    min_part: u64,
    max_parts: u32,
    single_copy_limit: u64,
    profile_max_part_bytes: u64,
) -> u64 {
    let min_for_count = total_size.div_ceil(u64::from(max_parts));
    let part_cap = single_copy_limit
        .max(min_for_count)
        .min(profile_max_part_bytes);
    planned_chunk_size
        .max(min_part)
        .max(min_for_count)
        .min(part_cap)
}

enum CopyObjectOutcome {
    Completed {
        etag: Option<String>,
        last_modified: Option<String>,
        resp_headers: HeaderMap,
    },
    Reconciled(Entry),
}

impl S3Backend {
    pub(super) fn can_server_side_copy_from_impl(&self, src_endpoint: &str) -> bool {
        let Some((src_ep, _, _)) = parse_s3_endpoint(src_endpoint) else {
            return false;
        };
        src_ep == self.inner.cfg.effective_endpoint()
    }

    /// Zero-local-bandwidth S3 server-side copy:
    /// - Objects `<= max_single_copy_bytes` (default 512 MiB, clamped to `profile.max_part_bytes`)
    ///   use `CopyObject`.
    /// - Larger objects automatically use multipart `UploadPartCopy` (`x-amz-copy-source-range`).
    /// - Uses `long_control_timeout`, inspects HTTP `200 OK` XML bodies for embedded `<Error>`
    ///   documents, and reconciles ambiguous failures / HTTP `412 PreconditionFailed` via
    ///   `x-amz-meta-rship-op-id` when destination preconditions are active.
    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        let Some((src_ep, src_bucket, src_prefix)) = parse_s3_endpoint(src_endpoint) else {
            return Ok(None);
        };
        if src_ep != self.inner.cfg.effective_endpoint() {
            return Ok(None);
        }

        let (src_full_key, copy_source) = build_copy_source(&src_bucket, &src_prefix, src_path);
        let dst_full_key = self.full_key(init.dst_path.as_str());
        let single_copy_limit = effective_single_copy_limit(
            self.inner.cfg.max_single_copy_bytes,
            self.inner.profile.max_part_bytes,
        );

        if init.total_size <= single_copy_limit {
            self.copy_object_single(&src_full_key, &copy_source, &dst_full_key, init)
                .await
                .map(Some)
        } else {
            self.copy_object_multipart(&copy_source, &dst_full_key, init, single_copy_limit)
                .await
                .map(Some)
        }
    }

    async fn copy_object_single(
        &self,
        src_full_key: &str,
        copy_source: &str,
        dst_full_key: &str,
        init: &UploadInit,
    ) -> Result<Entry> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-amz-copy-source"),
            HeaderValue::from_str(copy_source)
                .map_err(|e| Error::protocol(format!("invalid x-amz-copy-source: {e}")))?,
        );
        headers.insert(
            HeaderName::from_static("x-amz-metadata-directive"),
            HeaderValue::from_static("REPLACE"),
        );
        self.insert_common_object_headers(
            &mut headers,
            &init.dst_path,
            &init.op_id,
            init.src_mtime_ns,
            &init.checksums,
        )?;
        self.apply_sse_c_copy_source_headers_if_needed(&mut headers)?;
        let has_src_etag_pin =
            self.insert_copy_source_if_match(&mut headers, init.src_etag.as_deref())?;

        let is_r2 = self.inner.profile.provider == S3Provider::R2;
        let has_dst_precond = match &init.precondition {
            DstPrecondition::Absent if self.inner.profile.supports_if_none_match => {
                let hdr = if is_r2 {
                    HeaderName::from_static("cf-copy-destination-if-none-match")
                } else {
                    http::header::IF_NONE_MATCH
                };
                headers.insert(hdr, HeaderValue::from_static("*"));
                true
            }
            DstPrecondition::Existing {
                etag: Some(etag), ..
            } if self.inner.profile.supports_if_match_write => {
                let hdr = if is_r2 {
                    HeaderName::from_static("cf-copy-destination-if-match")
                } else {
                    http::header::IF_MATCH
                };
                headers.insert(
                    hdr,
                    HeaderValue::from_str(etag).map_err(|e| {
                        Error::protocol(format!("invalid destination If-Match ETag: {e}"))
                    })?,
                );
                true
            }
            _ => false,
        };

        let idempotency = if has_dst_precond {
            Idempotency::NonIdempotent
        } else {
            Idempotency::Idempotent
        };

        let outcome = self
            .control_signed_request_with_policy(
                "CopyObject",
                Method::PUT,
                dst_full_key,
                &[],
                headers,
                Bytes::new(),
                true,
                idempotency,
                |resp| {
                    if resp.status.is_success() {
                        return match parse_copy_result(&resp.body) {
                            Ok(CopyResultBody::Completed {
                                etag,
                                last_modified,
                                ..
                            }) => PolicyDecision::Ok(CopyObjectOutcome::Completed {
                                etag,
                                last_modified,
                                resp_headers: resp.headers,
                            }),
                            Ok(CopyResultBody::Error(xml_err)) => {
                                let mapped = classify_s3_xml_error(
                                    "CopyObject(200-OK)",
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &resp.headers,
                                    &xml_err,
                                );
                                classify_copy_object_error(
                                    mapped,
                                    src_full_key,
                                    has_src_etag_pin,
                                    has_dst_precond,
                                )
                            }
                            Err(parse_err) => PolicyDecision::from_error(parse_err),
                        };
                    }
                    let err = classify_s3_error(
                        "CopyObject",
                        resp.status,
                        &resp.headers,
                        &resp.body,
                        false,
                    );
                    classify_copy_object_error(err, src_full_key, has_src_etag_pin, has_dst_precond)
                },
                |err| async move {
                    let head = self.head_object_raw(dst_full_key).await?;
                    if let Some(resp_headers) = head {
                        let mut entry = self.headers_to_entry(
                            &resp_headers,
                            init.dst_path.as_str(),
                            init.dst_path.clone(),
                            EntryKind::File,
                        );
                        let op_id_matches = resp_headers
                            .get(META_OP_ID)
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|v| v == init.op_id);
                        if op_id_matches && entry.size == init.total_size {
                            if entry.checksum.is_none() {
                                entry.checksum = init.checksums.first().cloned();
                            }
                            return Ok(ReconcileAction::Resolved(
                                CopyObjectOutcome::Reconciled(entry),
                            ));
                        }
                        if err.kind == ErrorKind::PreconditionFailed {
                            if has_src_etag_pin
                                && let DstPrecondition::Existing {
                                    etag: Some(expected_dst_etag),
                                    ..
                                } = &init.precondition
                                && entry.etag.as_deref() == Some(expected_dst_etag.as_str())
                            {
                                return Ok(ReconcileAction::Fail(Error::source_mutated(format!(
                                    "S3 CopyObject source `{src_full_key}` mutated before copy ({err})"
                                ))));
                            }
                            return Ok(ReconcileAction::Fail(err));
                        }
                        return Ok(ReconcileAction::Retry(err));
                    }

                    if err.kind == ErrorKind::PreconditionFailed {
                        if has_src_etag_pin
                            && matches!(init.precondition, DstPrecondition::Absent)
                        {
                            return Ok(ReconcileAction::Fail(Error::source_mutated(format!(
                                "S3 CopyObject source `{src_full_key}` mutated before copy ({err})"
                            ))));
                        }
                        return Ok(ReconcileAction::Fail(err));
                    }
                    Ok(ReconcileAction::Retry(err))
                },
            )
            .await?;

        match outcome {
            CopyObjectOutcome::Reconciled(entry) => Ok(entry),
            CopyObjectOutcome::Completed {
                etag,
                last_modified,
                resp_headers,
            } => {
                let resolved_etag = etag.or_else(|| {
                    resp_headers
                        .get(http::header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                });
                let mtime_ns = match last_modified
                    .as_deref()
                    .and_then(parse_rfc3339_or_http_nanos)
                {
                    Some(ns) => ns,
                    None => {
                        self.resolve_committed_mtime_ns(dst_full_key, &resp_headers)
                            .await
                    }
                };
                Ok(Entry {
                    node_id: None,
                    parent_id: None,
                    raw_path: None,
                    nfc_path: init.dst_path.clone(),
                    kind: EntryKind::File,
                    size: init.total_size,
                    mtime_ns,
                    ctime_ns: None,
                    etag: resolved_etag,
                    checksum: init.checksums.first().cloned(),
                })
            }
        }
    }

    async fn copy_object_multipart(
        &self,
        copy_source: &str,
        dst_full_key: &str,
        init: &UploadInit,
        single_copy_limit: u64,
    ) -> Result<Entry> {
        let min_part = self
            .inner
            .cfg
            .min_part_bytes_override
            .unwrap_or(self.inner.profile.min_part_bytes);
        let part_size = compute_multipart_copy_part_size(
            init.total_size,
            init.planned_chunk_size,
            min_part,
            self.inner.profile.max_parts,
            single_copy_limit,
            self.inner.profile.max_part_bytes,
        );
        let total_parts = init.total_size.div_ceil(part_size) as u32;

        let mut mp_init = init.clone();
        mp_init.planned_chunk_size = part_size;
        // `UploadPartCopy` does not send client-computed part checksums, so disable
        // `x-amz-checksum-algorithm` on `CreateMultipartUpload`.
        let opened = self
            .begin_multipart_upload_internal(&mp_init, false)
            .await?;
        let upload_id = opened.session_token;

        const MAX_PART_COPY_CONCURRENCY: usize = 8;
        let part_conc = (total_parts as usize).clamp(1, MAX_PART_COPY_CONCURRENCY);
        let mut join_set: tokio::task::JoinSet<Result<CompletedPart>> = tokio::task::JoinSet::new();
        let mut completed_parts = Vec::with_capacity(total_parts as usize);
        let mut next_pn = 1u32;
        let mut first_err: Option<Error> = None;

        while next_pn <= total_parts || !join_set.is_empty() {
            while first_err.is_none() && next_pn <= total_parts && join_set.len() < part_conc {
                let pn = next_pn;
                next_pn += 1;
                let start = u64::from(pn - 1) * part_size;
                let len = (init.total_size - start).min(part_size);
                let end_inclusive = start + len - 1;
                let this = self.clone();
                let dst_key_c = dst_full_key.to_string();
                let upload_id_c = upload_id.clone();
                let copy_source_c = copy_source.to_string();
                let src_etag_c = init.src_etag.clone();

                join_set.spawn(async move {
                    let query = vec![
                        ("partNumber".to_string(), pn.to_string()),
                        ("uploadId".to_string(), upload_id_c),
                    ];
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        HeaderName::from_static("x-amz-copy-source"),
                        HeaderValue::from_str(&copy_source_c).map_err(|e| {
                            Error::protocol(format!("invalid x-amz-copy-source: {e}"))
                        })?,
                    );
                    headers.insert(
                        HeaderName::from_static("x-amz-copy-source-range"),
                        HeaderValue::from_str(&format!("bytes={start}-{end_inclusive}"))
                            .expect("valid range"),
                    );
                    this.apply_sse_c_headers_if_needed(&mut headers)?;
                    this.apply_sse_c_copy_source_headers_if_needed(&mut headers)?;
                    let has_pinned_src =
                        this.insert_copy_source_if_match(&mut headers, src_etag_c.as_deref())?;

                    this.control_signed_request_with_policy(
                        "UploadPartCopy",
                        Method::PUT,
                        &dst_key_c,
                        &query,
                        headers,
                        Bytes::new(),
                        true,
                        Idempotency::Idempotent,
                        |resp| {
                            if resp.status.is_success() {
                                return match parse_copy_result(&resp.body) {
                                    Ok(CopyResultBody::Completed { etag, checksum, .. }) => {
                                        let Some(et) = etag.or_else(|| {
                                            resp.headers
                                                .get(http::header::ETAG)
                                                .and_then(|v| v.to_str().ok())
                                                .map(str::to_string)
                                        }) else {
                                            return PolicyDecision::Fail(Error::protocol(format!(
                                                "UploadPartCopy part {pn} missing ETag"
                                            )));
                                        };
                                        let ck = checksum.or_else(|| {
                                            extract_tagged_part_checksum_from_headers(&resp.headers)
                                        });
                                        PolicyDecision::Ok(CompletedPart {
                                            part_number: pn,
                                            offset: start,
                                            length: len,
                                            etag: et,
                                            checksum: ck,
                                        })
                                    }
                                    Ok(CopyResultBody::Error(xml_err)) => {
                                        let mapped = classify_s3_xml_error(
                                            "UploadPartCopy(200-OK)",
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            &resp.headers,
                                            &xml_err,
                                        );
                                        if mapped.kind == ErrorKind::PreconditionFailed
                                            && has_pinned_src
                                        {
                                            return PolicyDecision::Fail(Error::source_mutated(
                                                format!(
                                                    "S3 UploadPartCopy part {pn} aborted: source mutated mid-copy ({mapped})"
                                                ),
                                            ));
                                        }
                                        PolicyDecision::from_error(mapped)
                                    }
                                    Err(parse_err) => PolicyDecision::from_error(parse_err),
                                };
                            }
                            let err = classify_s3_error(
                                "UploadPartCopy",
                                resp.status,
                                &resp.headers,
                                &resp.body,
                                true,
                            );
                            if err.kind == ErrorKind::PreconditionFailed && has_pinned_src {
                                return PolicyDecision::Fail(Error::source_mutated(format!(
                                    "S3 UploadPartCopy part {pn} aborted: source mutated mid-copy ({err})"
                                )));
                            }
                            PolicyDecision::from_error(err)
                        },
                        |err| async move { Ok(ReconcileAction::Fail(err)) },
                    )
                    .await
                });
            }

            if let Some(joined) = join_set.join_next().await {
                match joined {
                    Ok(Ok(part)) => completed_parts.push(part),
                    Ok(Err(e)) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                            join_set.abort_all();
                        }
                    }
                    Err(e) if !e.is_cancelled() => {
                        if first_err.is_none() {
                            first_err = Some(Error::protocol(format!(
                                "UploadPartCopy task panicked: {e}"
                            )));
                            join_set.abort_all();
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        if let Some(e) = first_err {
            let _ = self.abort_multipart_by_id(dst_full_key, &upload_id).await;
            return Err(e);
        }

        completed_parts.sort_by_key(|p| p.part_number);

        let complete_res = self
            .complete_multipart_impl(
                MultipartCompleteParams {
                    op_id: &init.op_id,
                    full_key: dst_full_key,
                    upload_id: &upload_id,
                    dst_nfc_path: &init.dst_path,
                    dst_raw_path: init.dst_path.as_str(),
                    expected_size: init.total_size,
                    planned_chunk_size: part_size,
                    dst_precondition: &init.precondition,
                    part_checksum_kind: None,
                    expected_checksums: &init.checksums,
                },
                &completed_parts,
            )
            .await;

        match complete_res {
            Ok(entry) => Ok(entry),
            Err(e) => {
                let _ = self.abort_multipart_by_id(dst_full_key, &upload_id).await;
                Err(e)
            }
        }
    }

    fn insert_copy_source_if_match(
        &self,
        headers: &mut HeaderMap,
        src_etag: Option<&str>,
    ) -> Result<bool> {
        if self.inner.cfg.pin_read_etag
            && let Some(etag) = src_etag
            && !etag.is_empty()
        {
            headers.insert(
                HeaderName::from_static("x-amz-copy-source-if-match"),
                HeaderValue::from_str(etag).map_err(|e| {
                    Error::protocol(format!("invalid x-amz-copy-source-if-match: {e}"))
                })?,
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn build_copy_source(
    src_bucket: &str,
    src_prefix: &str,
    src_path: &BackendPath,
) -> (String, String) {
    let raw_rel = src_path.raw_path();
    let src_full_key = match (src_prefix.is_empty(), raw_rel.is_empty()) {
        (true, true) => String::new(),
        (true, false) => raw_rel.to_string(),
        (false, true) => src_prefix.to_string(),
        (false, false) => format!("{src_prefix}/{raw_rel}"),
    };
    let encoded_src_key = aws_uri_encode_path(&src_full_key);
    let copy_source = format!("/{}/{}", aws_uri_encode(src_bucket), encoded_src_key);
    (src_full_key, copy_source)
}

fn classify_copy_object_error(
    err: Error,
    src_full_key: &str,
    has_src_etag_pin: bool,
    has_dst_precond: bool,
) -> PolicyDecision<CopyObjectOutcome> {
    if err.kind == ErrorKind::PreconditionFailed {
        if !has_dst_precond && has_src_etag_pin {
            return PolicyDecision::Fail(Error::source_mutated(format!(
                "S3 CopyObject source `{src_full_key}` mutated before copy ({err})"
            )));
        }
        if has_dst_precond {
            return PolicyDecision::Reconcile(err);
        }
        return PolicyDecision::Fail(err);
    }
    PolicyDecision::from_error(err)
}

fn parse_s3_endpoint(ep: &str) -> Option<(String, String, String)> {
    let rest = ep.strip_prefix("s3://")?;
    let scheme_sep = rest.find("://")?;
    let after_scheme = scheme_sep + 3;
    let slash_rel = rest[after_scheme..].find('/')?;
    let slash = after_scheme + slash_rel;
    let effective_endpoint = rest[..slash].to_string();
    let bucket_and_prefix = &rest[slash + 1..];
    let (bucket, prefix) = match bucket_and_prefix.split_once('/') {
        Some((b, p)) => (b.to_string(), p.trim_matches('/').to_string()),
        None => (bucket_and_prefix.to_string(), String::new()),
    };
    if bucket.is_empty() {
        return None;
    }
    Some((effective_endpoint, bucket, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::provider::{GIB, MIB, S3Provider};

    #[test]
    fn default_single_copy_cutoff_switches_to_multipart_above_512_mib() {
        let aws = S3Provider::Aws.profile();
        let default_limit = effective_single_copy_limit(None, aws.max_part_bytes);
        assert_eq!(default_limit, 512 * MIB);
        assert_eq!(default_limit, DEFAULT_MAX_SINGLE_COPY_BYTES);

        // Objects <= 512 MiB use single-shot CopyObject; objects > 512 MiB use UploadPartCopy.
        assert!(512 * MIB <= default_limit);
        assert!(512 * MIB + 1 > default_limit);

        // Clamped by smaller provider max_part_bytes.
        assert_eq!(effective_single_copy_limit(None, 128 * MIB), 128 * MIB);

        // Explicit cfg.max_single_copy_bytes override is honored up to `profile_max_part_bytes`
        // (and clamped >= 1).
        assert_eq!(
            effective_single_copy_limit(Some(64 * MIB), aws.max_part_bytes),
            64 * MIB
        );
        assert_eq!(
            effective_single_copy_limit(Some(2 * GIB), aws.max_part_bytes),
            2 * GIB
        );
        assert_eq!(
            effective_single_copy_limit(Some(10 * GIB), aws.max_part_bytes),
            aws.max_part_bytes
        );
        let r2 = S3Provider::R2.profile();
        assert_eq!(
            effective_single_copy_limit(Some(5 * GIB), r2.max_part_bytes),
            r2.max_part_bytes
        );

        // Multipart copy part size respects 512 MiB for normal large objects (e.g. 600 MiB)
        // AND scales up above 512 MiB up to max_part_bytes (5 GiB) for multi-TiB objects so
        // 10,000 max_parts is never exceeded.
        let part_600m = compute_multipart_copy_part_size(
            600 * MIB,
            16 * MIB,
            aws.min_part_bytes,
            aws.max_parts,
            default_limit,
            aws.max_part_bytes,
        );
        assert_eq!(part_600m, 16 * MIB);

        let part_48tib = compute_multipart_copy_part_size(
            aws.max_object_bytes,
            16 * MIB,
            aws.min_part_bytes,
            aws.max_parts,
            default_limit,
            aws.max_part_bytes,
        );
        assert_eq!(part_48tib, aws.max_part_bytes);
        assert!(aws.max_object_bytes.div_ceil(part_48tib) <= u64::from(aws.max_parts));
    }
}
