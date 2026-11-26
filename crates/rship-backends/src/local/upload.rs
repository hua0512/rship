//! Local single-shot and resumable `ParallelParts` staging uploads with CRC-32C
//! part-manifest crash recovery and atomic commit/reconciliation.

use super::fs_util::{
    StagingGuard, cache_verified_dir, commit_staging_file, create_staging_exclusive,
    ensure_no_symlink_escape, ensure_no_symlink_escape_cached, entry_raw_override,
    metadata_to_entry, open_append_shared, open_read_shared_opt, open_write_shared,
    staging_manifest_path,
};
use super::{LocalBackend, SMALL_SINGLE_SHOT_INLINE_MAX};
use crate::common::crc32c_update;
use bytes::Bytes;
use futures::StreamExt;
use rship_core::backend::{
    ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, UploadInit, UploadProgress,
    UploadSessionInit,
};
use rship_core::source::ByteStream;
use rship_core::state::OperationRecord;
use rship_core::types::Entry;
use rship_core::{Error, ErrorKind, Result};
use std::collections::HashMap;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

const STREAM_WRITER_BUF_BYTES: usize = 256 * 1024;
const STREAM_WRITER_QUEUE_CAP: usize = 3;

enum WriteMsg {
    Data(Bytes),
    Commit,
}

struct RecordedPart {
    offset: u64,
    length: u64,
    crc32c: u32,
}

fn parse_parts_manifest(
    manifest_path: &Path,
    expected_total: u64,
) -> Result<Option<HashMap<u32, RecordedPart>>> {
    let mut f = match open_read_shared_opt(manifest_path, false) {
        Ok(f) => f,
        Err(e) if e.kind == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut manifest_raw = String::new();
    f.read_to_string(&mut manifest_raw).map_err(|e| {
        Error::io(
            format!("read part manifest `{}`", manifest_path.display()),
            e,
        )
    })?;
    let mut recorded = HashMap::new();
    for line in manifest_raw.lines() {
        let mut cols = line.split_ascii_whitespace();
        let (Some(pn_s), Some(off_s), Some(len_s), Some(crc_s)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if let (Ok(pn), Ok(offset), Ok(length), Ok(crc32c)) = (
            pn_s.parse::<u32>(),
            off_s.parse::<u64>(),
            len_s.parse::<u64>(),
            u32::from_str_radix(crc_s, 16),
        ) && (length > 0 || expected_total == 0)
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= expected_total)
        {
            recorded.insert(
                pn,
                RecordedPart {
                    offset,
                    length,
                    crc32c,
                },
            );
        }
    }
    Ok(Some(recorded))
}

fn validate_completed_parts(parts: &[CompletedPart], expected_size: u64) -> Result<()> {
    if expected_size == 0 {
        if !parts.is_empty() {
            return Err(Error::invalid_geometry(format!(
                "non-empty parts list ({}) for 0-byte upload",
                parts.len()
            )));
        }
        return Ok(());
    }
    if parts.is_empty() {
        return Err(Error::invalid_geometry(format!(
            "incomplete upload: empty parts list for {expected_size}-byte upload"
        )));
    }
    let mut sorted: Vec<&CompletedPart> = parts.iter().collect();
    sorted.sort_by_key(|p| (p.offset, p.part_number));
    let mut cursor = 0u64;
    for p in sorted {
        if p.length == 0 {
            return Err(Error::invalid_geometry(format!(
                "zero-length part {} at offset {}",
                p.part_number, p.offset
            )));
        }
        if p.offset != cursor {
            return Err(Error::invalid_geometry(format!(
                "non-contiguous part {}: expected offset {cursor}, got {}",
                p.part_number, p.offset
            )));
        }
        cursor = p.offset.checked_add(p.length).ok_or_else(|| {
            Error::invalid_geometry(format!("part {} length overflow", p.part_number))
        })?;
        if cursor > expected_size {
            return Err(Error::invalid_geometry(format!(
                "part {} exceeds expected upload size ({cursor} > {expected_size})",
                p.part_number
            )));
        }
    }
    if cursor != expected_size {
        return Err(Error::invalid_geometry(format!(
            "incomplete upload coverage: covered {cursor} of {expected_size} bytes"
        )));
    }
    Ok(())
}

impl LocalBackend {
    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        mut body: ByteStream,
    ) -> Result<Entry> {
        let root = self.root.clone();
        let encoding = self.encoding;
        let final_path = self
            .resolve_write_path(&init.dst_path, init.precondition.may_exist())
            .await?;
        let part_path = self.staging_path(&final_path, &init.op_id);
        let src_mtime_ns = init.src_mtime_ns;
        let dst_rel = init.dst_path.clone();

        // Fast small-file path (<= 256 KiB): collect exact payload and perform symlink
        // check, parent dir creation, atomic staging write, mtime, rename, and stat in
        // ONE `spawn_blocking` call (eliminating 4+ thread-pool handoffs per file).
        if init.total_size <= SMALL_SINGLE_SHOT_INLINE_MAX {
            let expected = init.total_size as usize;
            let mut payload = Vec::with_capacity(expected);
            while let Some(chunk) = body.next().await {
                let data = chunk?;
                if payload.len().saturating_add(data.len()) > expected {
                    return Err(Error::source_mutated(format!(
                        "oversized write: expected {} bytes, exceeded stream limit",
                        init.total_size
                    )));
                }
                payload.extend_from_slice(&data);
            }
            if payload.len() != expected {
                return Err(Error::source_mutated(format!(
                    "short write: expected {} bytes, got {}",
                    init.total_size,
                    payload.len()
                )));
            }
            let verified_dirs = self.verified_dirs.clone();
            let precondition = init.precondition.clone();
            let durability = self.durability.clone();
            let skip_leaf = matches!(precondition, rship_core::state::DstPrecondition::Absent);

            return tokio::task::spawn_blocking(move || {
                let parent_exists =
                    ensure_no_symlink_escape_cached(&root, &final_path, &verified_dirs, skip_leaf)?;
                if !parent_exists && let Some(parent) = final_path.parent() {
                    durability.create_dir_all(parent)?;
                    cache_verified_dir(&verified_dirs, parent);
                }
                let mut guard = StagingGuard::new(part_path.clone());
                let mut file = create_staging_exclusive(&part_path)?;
                if !payload.is_empty() {
                    file.write_all(&payload).map_err(|e| {
                        Error::io(format!("write staging `{}`", part_path.display()), e)
                    })?;
                }
                let durable = durability.commit_durably();
                let entry = commit_staging_file(
                    file,
                    &part_path,
                    &final_path,
                    src_mtime_ns,
                    &precondition,
                    durable,
                    &root,
                    dst_rel,
                    encoding,
                    false,
                )?;
                guard.disarm();
                durability.after_commit(&final_path)?;
                Ok(entry)
            })
            .await
            .map_err(|e| Error::protocol(format!("small put_single_shot join: {e}")))?;
        }

        // Large single-shot streaming path (> 256 KiB): pipeline incoming chunks to ONE
        // dedicated `spawn_blocking` buffered writer over a bounded channel (<= 2 MiB in flight)
        // so reading/encryption and disk I/O overlap without per-chunk thread-pool handoffs.
        let precondition = init.precondition.clone();
        let durability = self.durability.clone();
        let (tx, mut rx) = mpsc::channel::<WriteMsg>(STREAM_WRITER_QUEUE_CAP);
        let writer_handle = tokio::task::spawn_blocking(move || {
            let parent_exists = ensure_no_symlink_escape(&root, &final_path)?;
            if !parent_exists && let Some(parent) = final_path.parent() {
                durability.create_dir_all(parent)?;
            }
            let mut guard = StagingGuard::new(part_path.clone());
            let file = create_staging_exclusive(&part_path)?;
            let mut writer = BufWriter::with_capacity(STREAM_WRITER_BUF_BYTES, file);
            let mut committed = false;

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    WriteMsg::Data(data) => {
                        writer.write_all(&data).map_err(|e| {
                            Error::io(format!("write staging `{}`", part_path.display()), e)
                        })?;
                    }
                    WriteMsg::Commit => {
                        committed = true;
                        break;
                    }
                }
            }

            if !committed {
                return Err(Error::cancelled("single-shot upload aborted before commit"));
            }

            let file = writer.into_inner().map_err(|e| {
                Error::io(
                    format!("flush staging `{}`", part_path.display()),
                    e.into_error(),
                )
            })?;
            let durable = durability.commit_durably();
            let entry = commit_staging_file(
                file,
                &part_path,
                &final_path,
                src_mtime_ns,
                &precondition,
                durable,
                &root,
                dst_rel,
                encoding,
                false,
            )?;
            guard.disarm();
            durability.after_commit(&final_path)?;
            Ok(entry)
        });

        let mut written = 0u64;
        while let Some(chunk) = body.next().await {
            let data = match chunk {
                Ok(b) => b,
                Err(e) => {
                    drop(tx);
                    let _ = writer_handle.await;
                    return Err(e);
                }
            };
            if data.is_empty() {
                continue;
            }
            written = written.saturating_add(data.len() as u64);
            if written > init.total_size {
                drop(tx);
                let _ = writer_handle.await;
                return Err(Error::source_mutated(format!(
                    "oversized write: expected {} bytes, received {written}",
                    init.total_size
                )));
            }
            if tx.send(WriteMsg::Data(data)).await.is_err() {
                return writer_handle
                    .await
                    .map_err(|e| Error::protocol(format!("writer join: {e}")))?;
            }
        }

        if written != init.total_size {
            drop(tx);
            let _ = writer_handle.await;
            return Err(Error::source_mutated(format!(
                "short write: expected {} bytes, got {written}",
                init.total_size
            )));
        }

        let _ = tx.send(WriteMsg::Commit).await;
        drop(tx);
        writer_handle
            .await
            .map_err(|e| Error::protocol(format!("commit join: {e}")))?
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let root = self.root.clone();
        let final_path = self
            .resolve_write_path(&init.dst_path, init.precondition.may_exist())
            .await?;
        let part_path = self.staging_path(&final_path, &init.op_id);
        let manifest_path = staging_manifest_path(&part_path);
        let total_size = init.total_size;
        let pp = part_path.clone();
        let mp = manifest_path.clone();
        let fp = final_path.clone();
        let durability = self.durability.clone();
        tokio::task::spawn_blocking(move || {
            let parent_exists = ensure_no_symlink_escape(&root, &fp)?;
            if !parent_exists && let Some(parent) = fp.parent() {
                durability.create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(&mp);
            let mut guard = StagingGuard::with_manifest(pp.clone(), mp);
            let f = create_staging_exclusive(&pp)?;
            if total_size > 0 {
                f.set_len(total_size)
                    .map_err(|e| Error::io(format!("preallocate part `{}`", pp.display()), e))?;
            }
            guard.disarm();
            Ok::<_, Error>(())
        })
        .await
        .map_err(|e| Error::protocol(format!("begin_upload join: {e}")))??;

        Ok(UploadSessionInit {
            session_token: part_path.to_string_lossy().into_owned(),
            backend_meta: final_path.to_string_lossy().into_owned(),
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(tok) = &op.session_token else {
            return Ok(UploadProgress::Expired);
        };
        let root = self.root.clone();
        let part_path = PathBuf::from(tok);
        let manifest_path = staging_manifest_path(&part_path);
        let expected_total = op.src_version.size;

        tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &part_path)?;
            ensure_no_symlink_escape(&root, &manifest_path)?;
            let meta = match std::fs::symlink_metadata(&part_path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(UploadProgress::Expired);
                }
                Err(e) => {
                    return Err(Error::io(
                        format!("query part `{}`", part_path.display()),
                        e,
                    ));
                }
            };
            if !meta.is_file() || meta.len() != expected_total {
                return Ok(UploadProgress::Expired);
            }

            let Some(recorded) = parse_parts_manifest(&manifest_path, expected_total)? else {
                return Ok(UploadProgress::CompletedParts(Vec::new()));
            };

            if recorded.is_empty() {
                return Ok(UploadProgress::CompletedParts(Vec::new()));
            }

            let mut f = open_read_shared_opt(&part_path, false)?;
            let mut verify_buf = vec![0u8; 64 * 1024];
            let mut verified = Vec::with_capacity(recorded.len());

            for (pn, rec) in recorded {
                if f.seek(SeekFrom::Start(rec.offset)).is_err() {
                    continue;
                }
                let mut crc = u32::MAX;
                let mut rem = rec.length;
                let mut ok = true;
                while rem > 0 {
                    let want = (rem as usize).min(verify_buf.len());
                    match f.read(&mut verify_buf[..want]) {
                        Ok(0) => {
                            ok = false;
                            break;
                        }
                        Ok(n) => {
                            crc = crc32c_update(crc, &verify_buf[..n]);
                            rem -= n as u64;
                        }
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && !crc == rec.crc32c {
                    verified.push(CompletedPart {
                        part_number: pn,
                        offset: rec.offset,
                        length: rec.length,
                        etag: format!("crc32c:{:08x}", rec.crc32c),
                        checksum: None,
                    });
                }
            }

            verified.sort_by_key(|p| p.part_number);
            Ok(UploadProgress::CompletedParts(verified))
        })
        .await
        .map_err(|e| Error::protocol(format!("query_upload join: {e}")))?
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        mut chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let tok = op
            .session_token
            .as_ref()
            .ok_or_else(|| Error::session_expired("missing local staging path"))?;
        let expected_total = op.src_version.size;
        if chunk.total_size != expected_total {
            return Err(Error::invalid_geometry(format!(
                "chunk total_size ({}) != expected operation size ({expected_total})",
                chunk.total_size
            )));
        }
        let part_number = chunk.part_number;
        let offset = chunk.offset;
        let expected_len = chunk.len;
        if offset
            .checked_add(expected_len)
            .is_none_or(|end| end > expected_total)
        {
            return Err(Error::invalid_geometry(format!(
                "chunk {part_number} range [{offset}..+{expected_len}) exceeds total_size {expected_total}"
            )));
        }

        let root = self.root.clone();
        let part_path = PathBuf::from(tok);
        let manifest_path = staging_manifest_path(&part_path);

        let (tx, mut rx) = mpsc::channel::<WriteMsg>(STREAM_WRITER_QUEUE_CAP);
        let writer_handle = tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &part_path)?;
            ensure_no_symlink_escape(&root, &manifest_path)?;
            let mut f = match open_write_shared(&part_path) {
                Ok(f) => f,
                Err(e) if e.kind == ErrorKind::NotFound => {
                    return Err(Error::session_expired(format!(
                        "local staging part `{}` missing",
                        part_path.display()
                    )));
                }
                Err(e) => return Err(e),
            };
            let part_meta = f
                .metadata()
                .map_err(|e| Error::io(format!("stat part `{}`", part_path.display()), e))?;
            if !part_meta.is_file() || part_meta.len() != expected_total {
                return Err(Error::session_expired(format!(
                    "local staging part `{}` invalid or resized",
                    part_path.display()
                )));
            }
            f.seek(SeekFrom::Start(offset))
                .map_err(|e| Error::io("seek part", e))?;
            let mut writer = BufWriter::with_capacity(STREAM_WRITER_BUF_BYTES, f);
            let mut crc = u32::MAX;
            let mut committed = false;

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    WriteMsg::Data(data) => {
                        crc = crc32c_update(crc, &data);
                        writer
                            .write_all(&data)
                            .map_err(|e| Error::io("write part chunk", e))?;
                    }
                    WriteMsg::Commit => {
                        committed = true;
                        break;
                    }
                }
            }

            if !committed {
                return Err(Error::cancelled("chunk upload aborted before commit"));
            }

            let f_handle = writer
                .into_inner()
                .map_err(|e| Error::io("flush part chunk", e.into_error()))?;
            drop(f_handle);

            let checksum = !crc;
            let line = format!("{part_number} {offset} {expected_len} {checksum:08x}\n");
            let mut mf = open_append_shared(&manifest_path)?;
            mf.write_all(line.as_bytes())
                .map_err(|e| Error::io("write part manifest", e))?;
            Ok::<u32, Error>(checksum)
        });

        let mut written = 0u64;
        while let Some(slice) = chunk.body.next().await {
            let data = match slice {
                Ok(b) => b,
                Err(e) => {
                    drop(tx);
                    let _ = writer_handle.await;
                    return Err(e);
                }
            };
            if data.is_empty() {
                continue;
            }
            written = written.saturating_add(data.len() as u64);
            if written > expected_len {
                drop(tx);
                let _ = writer_handle.await;
                return Err(Error::source_mutated(format!(
                    "oversized part {part_number}: expected {expected_len} bytes, received {written}"
                )));
            }
            if tx.send(WriteMsg::Data(data)).await.is_err() {
                writer_handle
                    .await
                    .map_err(|e| Error::protocol(format!("chunk writer join: {e}")))??;
                return Err(Error::protocol("chunk writer closed unexpectedly"));
            }
        }

        if written != expected_len {
            drop(tx);
            let _ = writer_handle.await;
            return Err(Error::source_mutated(format!(
                "short part {part_number}: expected {expected_len} bytes, got {written}"
            )));
        }

        let _ = tx.send(WriteMsg::Commit).await;
        drop(tx);
        let checksum = writer_handle
            .await
            .map_err(|e| Error::protocol(format!("chunk commit join: {e}")))??;

        let next_offset = offset
            .checked_add(written)
            .ok_or_else(|| Error::invalid_geometry("chunk next_offset overflow"))?;
        Ok(ChunkAck {
            next_offset: Some(next_offset),
            etag: Some(format!("crc32c:{checksum:08x}")),
            completed: None,
            checksum: None,
        })
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        parts: &[CompletedPart],
    ) -> Result<Entry> {
        let tok = op
            .session_token
            .as_ref()
            .ok_or_else(|| Error::session_expired("missing local staging path"))?;
        let expected_size = op.src_version.size;
        validate_completed_parts(parts, expected_size)?;

        let root = self.root.clone();
        let encoding = self.encoding;
        let part_path = PathBuf::from(tok);
        let manifest_path = staging_manifest_path(&part_path);
        let final_path = self
            .resolve_write_path(&op.dst_nfc_path, op.dst_precondition.may_exist())
            .await?;
        let mtime_ns = op.src_version.mtime_ns;
        let nfc_path = op.dst_nfc_path.clone();
        let precondition = op.dst_precondition.clone();
        let durability = self.durability.clone();
        let parts_owned: Vec<CompletedPart> = parts.to_vec();

        tokio::task::spawn_blocking(move || {
            // Re-validate containment immediately before opening/renaming (TOCTOU symlink defense).
            ensure_no_symlink_escape(&root, &final_path)?;
            ensure_no_symlink_escape(&root, &part_path)?;
            ensure_no_symlink_escape(&root, &manifest_path)?;

            // Declare guard BEFORE `f` so on commit failure `f` closes before `guard` unlinks,
            // while remaining disarmed until completeness validation passes so incomplete calls
            // preserve resumable staging.
            let mut guard = StagingGuard::disarmed();
            let f = match open_write_shared(&part_path) {
                Ok(f) => f,
                Err(e) if e.kind == ErrorKind::NotFound => {
                    return Err(Error::session_expired(format!(
                        "local staging part `{}` missing",
                        part_path.display()
                    )));
                }
                Err(e) => return Err(e),
            };
            let part_meta = f
                .metadata()
                .map_err(|e| Error::io(format!("stat part `{}`", part_path.display()), e))?;
            if !part_meta.is_file() || part_meta.len() != expected_size {
                return Err(Error::session_expired(format!(
                    "staged part length mismatch ({} != {expected_size})",
                    part_meta.len()
                )));
            }

            if expected_size > 0 {
                let Some(recorded) = parse_parts_manifest(&manifest_path, expected_size)? else {
                    return Err(Error::protocol(format!(
                        "missing local staging manifest `{}`",
                        manifest_path.display()
                    )));
                };
                for p in &parts_owned {
                    let Some(rec) = recorded.get(&p.part_number) else {
                        return Err(Error::invalid_geometry(format!(
                            "part {} missing from staging manifest",
                            p.part_number
                        )));
                    };
                    if rec.offset != p.offset || rec.length != p.length {
                        return Err(Error::invalid_geometry(format!(
                            "part {} geometry mismatch against manifest",
                            p.part_number
                        )));
                    }
                    let expected_etag = format!("crc32c:{:08x}", rec.crc32c);
                    if p.etag != expected_etag {
                        return Err(Error::integrity(format!(
                            "part {} etag mismatch (expected {expected_etag}, got {})",
                            p.part_number, p.etag
                        )));
                    }
                }
            }

            guard.arm(part_path.clone(), manifest_path.clone());
            let durable = durability.commit_durably();
            let entry = commit_staging_file(
                f,
                &part_path,
                &final_path,
                mtime_ns,
                &precondition,
                durable,
                &root,
                nfc_path,
                encoding,
                false,
            )?;
            let _ = std::fs::remove_file(&manifest_path);
            guard.disarm();
            durability.after_commit(&final_path)?;
            Ok(entry)
        })
        .await
        .map_err(|e| Error::protocol(format!("finish_upload join: {e}")))?
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        let root = self.root.clone();
        let final_path = self.resolve_write_path(&op.dst_nfc_path, false).await?;
        let part_path = op
            .session_token
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.staging_path(&final_path, &op.op_id));
        let manifest_path = staging_manifest_path(&part_path);
        tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &part_path)?;
            ensure_no_symlink_escape(&root, &manifest_path)?;
            let _ = std::fs::remove_file(&part_path);
            let _ = std::fs::remove_file(&manifest_path);
            Ok::<_, Error>(())
        })
        .await
        .map_err(|e| Error::protocol(format!("abort_upload join: {e}")))?
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let root = self.root.clone();
        let encoding = self.encoding;
        let final_path = self.resolve_write_path(&op.dst_nfc_path, true).await?;
        let part_path = op
            .session_token
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.staging_path(&final_path, &op.op_id));
        let nfc_path = op.dst_nfc_path.clone();
        let op_c = op.clone();

        tokio::task::spawn_blocking(move || {
            // Proof: staging part gone, source size and mtime, and an inode (dev+ino) that
            // differs from the planner's pre-op file, since publication renames a new inode
            // into place. Size and mtime alone never prove a commit (see `common::reconcile`).
            if part_path.exists() {
                return Ok(ReconcileOutcome::NotCommitted);
            }
            let Ok(meta) = std::fs::symlink_metadata(&final_path) else {
                return Ok(ReconcileOutcome::NotCommitted);
            };
            if !meta.is_file() {
                return Ok(ReconcileOutcome::NotCommitted);
            }
            let raw_override = entry_raw_override(&root, &final_path, &nfc_path, encoding);
            let Some(entry) = metadata_to_entry(&meta, raw_override, nfc_path) else {
                return Ok(ReconcileOutcome::NotCommitted);
            };
            let pre_op = crate::common::reconcile::PreOpState::from_precondition(
                &op_c.dst_precondition,
                |node_id, _| node_id.as_ref().map(|n| n.0.clone()),
            );
            let identity = entry.node_id.as_ref().map(|n| n.0.clone());
            Ok(crate::common::reconcile::judge_reconciled_object(
                &op_c,
                entry,
                identity.as_deref(),
                &pre_op,
                Some(2_000_000_000),
                "local reconcile",
            ))
        })
        .await
        .map_err(|e| Error::protocol(format!("reconcile join: {e}")))?
    }
}
