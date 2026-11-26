//! SFTP data-plane streaming reads (`RemoteRangeReadable`), coalesced offset writes,
//! `.rship.part.<op_id>` crash-resumable staging uploads, atomic `posix-rename@openssh.com`
//! publication with backup rollback fallback, `DstPrecondition` enforcement, and reconciliation.

use async_trait::async_trait;
use bytes::BytesMut;
use futures::StreamExt;
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, ReconcileOutcome, StorageBackend,
    UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{ByteRange, Entry, EntryKind};
use rship_core::{Error, ErrorKind, Result};
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpClientError;
use russh_sftp::client::fs::File as SftpFile;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode as SftpStatus};
use std::future::Future;
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::SftpBackend;
use super::ops::{attrs_to_entry, is_regular_file_attrs, is_special_node};
use super::pool::{
    PooledSftpConn, SftpOpError, is_sftp_connection_error, is_sftp_not_found, map_sftp_err,
    map_sftp_io_err,
};

/// Read slices match OpenSSH's 256 KiB SFTP packet ceiling so pipelined `File` reads
/// drain full packets in one step with minimal copies.
const READ_SLICE_BYTES: usize = 256 * 1024;
/// Coalesce small incoming stream chunks into 32 KiB SFTP write packets before feeding
/// `russh-sftp`'s 32-deep pipelined write window.
const WRITE_COALESCE_BYTES: usize = 32 * 1024;

struct SftpRangeReader {
    backend: SftpBackend,
    remote_path: String,
    total_len: u64,
}

/// Field order (`file` before `conn`) guarantees `SftpFile` drops BEFORE `PooledSftpConn`.
struct SftpRangeStreamState {
    file: Option<SftpFile>,
    conn: PooledSftpConn,
    buf: BytesMut,
    remaining: u64,
    io_timeout: Duration,
}

#[async_trait]
impl RemoteRangeReadable for SftpRangeReader {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("SFTP range overflow"))?;
        if end_exclusive > self.total_len {
            return Err(Error::invalid_geometry("SFTP range exceeds file size"));
        }

        let io_timeout = self.backend.inner.cfg.io_timeout;
        let (conn, mut file) = self
            .backend
            .open_with_sftp_retry("open SFTP file for reading", |sftp| {
                let rpath = self.remote_path.clone();
                async move {
                    // Guard against POSIX FIFOs/devices/sockets before calling `open()` (which
                    // can block indefinitely in `O_RDONLY` on a named pipe).
                    let meta = match tokio::time::timeout(io_timeout, sftp.symlink_metadata(&rpath))
                        .await
                    {
                        Ok(Ok(m)) => m,
                        Ok(Err(e)) => return Err(SftpOpError::Sftp(e)),
                        Err(_) => {
                            return Err(SftpOpError::Core(Error::timeout(format!(
                                "stat SFTP file before read stalled for {io_timeout:?}"
                            ))));
                        }
                    };
                    if is_special_node(&meta) || meta.is_dir() || meta.is_symlink() {
                        return Err(SftpOpError::Core(Error::invalid_path(format!(
                            "cannot open non-regular SFTP path `{rpath}` for reading"
                        ))));
                    }
                    match tokio::time::timeout(io_timeout, sftp.open(&rpath)).await {
                        Ok(Ok(f)) => Ok(f),
                        Ok(Err(e)) => Err(SftpOpError::Sftp(e)),
                        Err(_) => Err(SftpOpError::Core(Error::timeout(format!(
                            "open SFTP file stalled for {io_timeout:?}"
                        )))),
                    }
                }
            })
            .await?;

        if let Err(e) = timed_file_io(
            io_timeout,
            "seek SFTP read",
            file.seek(SeekFrom::Start(range.offset)),
        )
        .await
        {
            drop(file);
            return Err(e);
        }

        let init_cap = (range.len as usize).min(READ_SLICE_BYTES);
        let init_state = SftpRangeStreamState {
            file: Some(file),
            conn,
            buf: BytesMut::with_capacity(init_cap),
            remaining: range.len,
            io_timeout,
        };
        let stream = futures::stream::unfold(init_state, |mut state| async move {
            let f = state.file.as_mut()?;
            let want = (state.remaining as usize).min(READ_SLICE_BYTES);
            state.buf.clear();
            if !state.buf.try_reclaim(want) {
                state.buf.reserve(want);
            }
            match tokio::time::timeout(
                state.io_timeout,
                (&mut *f).take(want as u64).read_buf(&mut state.buf),
            )
            .await
            {
                Ok(Ok(0)) => {
                    state.file.take();
                    Some((
                        Err(Error::short_eof(
                            "SFTP stream ended before declared range len",
                        )),
                        state,
                    ))
                }
                Ok(Ok(n)) => {
                    let chunk = state.buf.split().freeze();
                    state.remaining -= n as u64;
                    if state.remaining == 0
                        && let Some(mut f_done) = state.file.take()
                        && matches!(
                            tokio::time::timeout(state.io_timeout, f_done.shutdown()).await,
                            Ok(Ok(()))
                        )
                    {
                        drop(f_done);
                        state.conn.mark_healthy();
                    }
                    Some((Ok(chunk), state))
                }
                Ok(Err(e)) => {
                    state.file.take();
                    Some((Err(map_sftp_io_err("SFTP read chunk", e)), state))
                }
                Err(_) => {
                    state.file.take();
                    let timeout_dur = state.io_timeout;
                    Some((
                        Err(Error::timeout(format!(
                            "SFTP read chunk stalled for {timeout_dur:?}"
                        ))),
                        state,
                    ))
                }
            }
        });
        Ok(Box::pin(stream))
    }
}

async fn timed_file_io<T, Fut>(io_timeout: Duration, label: &str, fut: Fut) -> Result<T>
where
    Fut: Future<Output = std::io::Result<T>>,
{
    match tokio::time::timeout(io_timeout, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(map_sftp_io_err(label, e)),
        Err(_) => Err(Error::timeout(format!(
            "{label} stalled for {io_timeout:?}"
        ))),
    }
}

async fn cleanup_aborted_write(
    conn: &mut PooledSftpConn,
    mut file: SftpFile,
    io_timeout: Duration,
    remove_on_abort: Option<&str>,
) {
    let closed_ok = matches!(
        tokio::time::timeout(io_timeout, file.shutdown()).await,
        Ok(Ok(()))
    );
    drop(file);
    if closed_ok {
        let removed_ok = match remove_on_abort {
            Some(path) => matches!(
                tokio::time::timeout(io_timeout, conn.session().remove_file(path)).await,
                Ok(Ok(())) | Ok(Err(SftpClientError::Status(_)))
            ),
            None => true,
        };
        if removed_ok {
            conn.mark_healthy();
        }
    }
}

async fn write_stream_to_sftp_file(
    conn: &mut PooledSftpConn,
    mut file: SftpFile,
    body: &mut ByteStream,
    expected_len: u64,
    io_timeout: Duration,
    label: &str,
    remove_on_abort: Option<&str>,
) -> Result<u64> {
    let mut written = 0u64;
    let mut coalesce = BytesMut::with_capacity(WRITE_COALESCE_BYTES);
    let write_label = format!("write {label}");
    let flush_label = format!("flush {label}");
    let close_label = format!("close {label}");

    while let Some(item) = body.next().await {
        let chunk = match item {
            Ok(c) => c,
            Err(e) => {
                cleanup_aborted_write(conn, file, io_timeout, remove_on_abort).await;
                return Err(e);
            }
        };
        if chunk.is_empty() {
            continue;
        }
        written = written.saturating_add(chunk.len() as u64);
        if written > expected_len {
            cleanup_aborted_write(conn, file, io_timeout, remove_on_abort).await;
            return Err(Error::invalid_geometry(format!(
                "{label} exceeded declared length ({written} > {expected_len})"
            )));
        }
        if coalesce.is_empty() && chunk.len() >= WRITE_COALESCE_BYTES {
            if let Err(e) = timed_file_io(io_timeout, &write_label, file.write_all(&chunk)).await {
                drop(file);
                return Err(e);
            }
        } else {
            coalesce.extend_from_slice(&chunk);
            if coalesce.len() >= WRITE_COALESCE_BYTES {
                if let Err(e) =
                    timed_file_io(io_timeout, &write_label, file.write_all(&coalesce)).await
                {
                    drop(file);
                    return Err(e);
                }
                coalesce.clear();
            }
        }
    }
    if !coalesce.is_empty() {
        if let Err(e) = timed_file_io(io_timeout, &write_label, file.write_all(&coalesce)).await {
            drop(file);
            return Err(e);
        }
        coalesce.clear();
    }
    if let Err(e) = timed_file_io(io_timeout, &flush_label, file.flush()).await {
        drop(file);
        return Err(e);
    }
    if let Err(e) = timed_file_io(io_timeout, &close_label, file.shutdown()).await {
        drop(file);
        return Err(e);
    }
    drop(file);

    if written != expected_len {
        let removed_ok = match remove_on_abort {
            Some(path) => matches!(
                tokio::time::timeout(io_timeout, conn.session().remove_file(path)).await,
                Ok(Ok(())) | Ok(Err(SftpClientError::Status(_)))
            ),
            None => true,
        };
        if removed_ok {
            conn.mark_healthy();
        }
        return Err(Error::short_eof(format!(
            "{label} short EOF: wrote {written} of {expected_len} bytes"
        )));
    }
    Ok(written)
}

async fn check_dst_precondition_sftp(
    sftp: &SftpSession,
    final_remote: &str,
    precondition: &DstPrecondition,
) -> std::result::Result<(), SftpOpError> {
    match precondition {
        DstPrecondition::Any => Ok(()),
        DstPrecondition::Absent => match sftp.symlink_metadata(final_remote).await {
            Err(e) if is_sftp_not_found(&e) => Ok(()),
            Ok(_) => Err(SftpOpError::Core(Error::precondition_failed(format!(
                "SFTP destination `{final_remote}` already exists (precondition Absent)"
            )))),
            Err(e) => Err(SftpOpError::Sftp(e)),
        },
        DstPrecondition::Existing { size, mtime_ns, .. } => {
            match sftp.symlink_metadata(final_remote).await {
                Ok(meta) => {
                    if !is_regular_file_attrs(&meta) || meta.is_dir() || meta.is_symlink() {
                        return Err(SftpOpError::Core(Error::precondition_failed(format!(
                            "SFTP destination `{final_remote}` is no longer a regular file (precondition Existing)"
                        ))));
                    }
                    let actual_size = meta.size.unwrap_or(0);
                    let actual_secs = meta.mtime.map(i64::from).unwrap_or(0);
                    let expected_secs = mtime_ns.div_euclid(1_000_000_000);
                    if actual_size != *size || actual_secs != expected_secs {
                        return Err(SftpOpError::Core(Error::precondition_failed(format!(
                            "SFTP destination `{final_remote}` modified concurrently (expected size={size} mtime_s={expected_secs}, actual size={actual_size} mtime_s={actual_secs})"
                        ))));
                    }
                    Ok(())
                }
                Err(e) if is_sftp_not_found(&e) => {
                    Err(SftpOpError::Core(Error::precondition_failed(format!(
                        "SFTP destination `{final_remote}` disappeared concurrently (precondition Existing)"
                    ))))
                }
                Err(e) => Err(SftpOpError::Sftp(e)),
            }
        }
        _ => Ok(()),
    }
}

impl SftpBackend {
    /// Publish staged `part_remote` to `final_remote` atomically without risking deletion
    /// of an existing destination file on permission, missing-staging, or transport errors.
    async fn publish_atomic(
        &self,
        sftp: &SftpSession,
        op_id: &str,
        part_remote: &str,
        final_remote: &str,
        mtime_ns: i64,
        may_overwrite: bool,
    ) -> std::result::Result<(), SftpOpError> {
        let mtime_secs = u32::try_from(mtime_ns.div_euclid(1_000_000_000).max(0)).ok();
        if let Some(mt) = mtime_secs {
            let attrs = FileAttributes {
                mtime: Some(mt),
                atime: Some(mt),
                ..Default::default()
            };
            sftp.set_metadata(part_remote, attrs).await?;
        }

        if !may_overwrite {
            // `DstPrecondition::Absent`: never fall back to backup-overwrite!
            match sftp.rename(part_remote, final_remote).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !is_sftp_connection_error(&e)
                        && sftp.symlink_metadata(final_remote).await.is_ok()
                    {
                        return Err(SftpOpError::Core(Error::precondition_failed(format!(
                            "SFTP destination `{final_remote}` appeared concurrently (precondition Absent)"
                        ))));
                    }
                    return Err(SftpOpError::Sftp(e));
                }
            }
        }

        // Prefer atomic overwrite `posix-rename@openssh.com`.
        // ONLY fall back to standard SFTP rename when the server explicitly lacks the extension.
        match sftp.posix_rename(part_remote, final_remote).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.rename_with_backup_fallback(sftp, op_id, part_remote, final_remote)
                    .await
            }
            Err(SftpClientError::Status(s)) if s.status_code == SftpStatus::OpUnsupported => {
                self.rename_with_backup_fallback(sftp, op_id, part_remote, final_remote)
                    .await
            }
            Err(e) => Err(SftpOpError::Sftp(e)),
        }
    }

    async fn rename_with_backup_fallback(
        &self,
        sftp: &SftpSession,
        op_id: &str,
        part_remote: &str,
        final_remote: &str,
    ) -> std::result::Result<(), SftpOpError> {
        match sftp.rename(part_remote, final_remote).await {
            Ok(()) => Ok(()),
            Err(first_err) => {
                if is_sftp_connection_error(&first_err) {
                    return Err(SftpOpError::Sftp(first_err));
                }
                // Verify staging file actually exists AND destination is a replaceable non-dir file
                // before touching `final_remote` — never unlink or backup a directory or special node!
                sftp.symlink_metadata(part_remote).await?;
                match sftp.symlink_metadata(final_remote).await {
                    Ok(meta) if meta.is_dir() => {
                        return Err(SftpOpError::Core(Error::conflict(format!(
                            "SFTP destination `{final_remote}` is a directory"
                        ))));
                    }
                    Ok(meta) if is_special_node(&meta) => {
                        return Err(SftpOpError::Core(Error::conflict(format!(
                            "SFTP destination `{final_remote}` is a POSIX special node"
                        ))));
                    }
                    Ok(_) => {}
                    Err(e) if is_sftp_not_found(&e) => {
                        return Err(SftpOpError::Sftp(first_err));
                    }
                    Err(e) => {
                        // Do NOT mask transport/stat errors behind `first_err`.
                        return Err(SftpOpError::Sftp(e));
                    }
                }

                // Stage existing destination to a backup path instead of unlinking it up front.
                let backup_remote = self.backup_remote_path(final_remote, op_id);
                if let Err(e) = sftp.remove_file(&backup_remote).await
                    && !is_sftp_not_found(&e)
                {
                    if is_sftp_connection_error(&e) {
                        return Err(SftpOpError::Sftp(e));
                    }
                    tracing::warn!(
                        backup = %backup_remote,
                        error = %e,
                        "failed to clean pre-existing SFTP backup before fallback rename"
                    );
                }
                sftp.rename(final_remote, &backup_remote).await?;

                match sftp.rename(part_remote, final_remote).await {
                    Ok(()) => {
                        if let Err(e) = sftp.remove_file(&backup_remote).await
                            && !is_sftp_not_found(&e)
                        {
                            tracing::warn!(
                                backup = %backup_remote,
                                error = %e,
                                "failed to remove SFTP backup after successful publish"
                            );
                        }
                        Ok(())
                    }
                    Err(e) => {
                        // Best-effort rollback so original destination is preserved.
                        if let Err(rb_err) = sftp.rename(&backup_remote, final_remote).await {
                            tracing::warn!(
                                backup = %backup_remote,
                                target = %final_remote,
                                error = %rb_err,
                                "failed to roll back SFTP backup after failed rename"
                            );
                        }
                        Err(SftpOpError::Sftp(e))
                    }
                }
            }
        }
    }

    pub(super) async fn open_read_impl(
        &self,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let Some(entry) = self.stat(path).await? else {
            return Err(Error::not_found(format!(
                "SFTP file `{}` not found",
                path.nfc_path
            )));
        };
        self.open_read_entry(&entry, path, None).await
    }

    pub(super) async fn open_read_entry_impl(
        &self,
        entry: &Entry,
        path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open SFTP {:?} `{}` for reading",
                entry.kind, path.nfc_path
            )));
        }
        let raw_rel = path
            .raw_path
            .as_deref()
            .or(entry.raw_path.as_deref())
            .unwrap_or_else(|| path.nfc_path.as_str());
        let remote_path = self.remote_path(raw_rel);
        Ok(DataSource::RemoteRangeReadable(Arc::new(SftpRangeReader {
            backend: self.clone(),
            remote_path,
            total_len: entry.size,
        })))
    }

    pub(super) async fn put_single_shot_impl(
        &self,
        init: &UploadInit,
        mut body: ByteStream,
    ) -> Result<Entry> {
        self.ensure_parent_dirs(&init.dst_path).await?;
        let final_remote = self.remote_path(init.dst_path.as_str());
        let part_remote = self.staging_remote_path(&final_remote, &init.op_id);

        let (mut conn, file) = self
            .open_with_sftp_retry("open staging file", |sftp| {
                let final_remote = final_remote.clone();
                let part_remote = part_remote.clone();
                async move {
                    check_dst_precondition_sftp(&sftp, &final_remote, &init.precondition).await?;
                    sftp.open_with_flags(
                        &part_remote,
                        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    )
                    .await
                    .map_err(SftpOpError::Sftp)
                }
            })
            .await?;

        let io_timeout = self.inner.cfg.io_timeout;
        write_stream_to_sftp_file(
            &mut conn,
            file,
            &mut body,
            init.total_size,
            io_timeout,
            "SFTP staging file",
            Some(&part_remote),
        )
        .await?;

        // Re-check destination precondition immediately prior to atomic publish.
        if let Err(err) =
            check_dst_precondition_sftp(conn.session(), &final_remote, &init.precondition).await
        {
            match err {
                SftpOpError::Core(core_err) => {
                    if !core_err.is_retryable()
                        && matches!(
                            tokio::time::timeout(
                                io_timeout,
                                conn.session().remove_file(&part_remote)
                            )
                            .await,
                            Ok(Ok(())) | Ok(Err(SftpClientError::Status(_)))
                        )
                    {
                        conn.mark_healthy();
                    }
                    return Err(core_err);
                }
                SftpOpError::Sftp(se) => {
                    if !is_sftp_connection_error(&se) {
                        let _ = conn.session().remove_file(&part_remote).await;
                        conn.mark_healthy();
                    }
                    return Err(map_sftp_err("check precondition before SFTP publish", se));
                }
            }
        }

        if let Err(err) = self
            .publish_atomic(
                conn.session(),
                &init.op_id,
                &part_remote,
                &final_remote,
                init.src_mtime_ns,
                init.precondition.may_exist(),
            )
            .await
        {
            match err {
                SftpOpError::Core(core_err) => {
                    if !core_err.is_retryable() {
                        let _ = conn.session().remove_file(&part_remote).await;
                        conn.mark_healthy();
                    }
                    return Err(core_err);
                }
                SftpOpError::Sftp(se) => {
                    if !is_sftp_connection_error(&se) {
                        let _ = conn.session().remove_file(&part_remote).await;
                        conn.mark_healthy();
                    }
                    return Err(map_sftp_err("publish SFTP staging file", se));
                }
            }
        }

        // Re-stat committed file so returned `Entry::mtime_ns` reflects server-persisted
        // whole-second mtime rather than fabricating subseconds.
        let entry = match conn.session().symlink_metadata(&final_remote).await {
            Ok(meta) => {
                conn.mark_healthy();
                attrs_to_entry(&meta, init.dst_path.as_str(), init.dst_path.clone()).ok_or_else(
                    || {
                        Error::protocol(format!(
                            "committed SFTP path `{final_remote}` is non-regular"
                        ))
                    },
                )?
            }
            Err(e) if !is_sftp_connection_error(&e) => {
                conn.mark_healthy();
                return Err(map_sftp_err("stat committed SFTP file", e));
            }
            Err(e) => return Err(map_sftp_err("stat committed SFTP file", e)),
        };
        Ok(entry)
    }

    pub(super) async fn begin_upload_impl(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.ensure_parent_dirs(&init.dst_path).await?;
        let final_remote = self.remote_path(init.dst_path.as_str());
        let part_remote = self.staging_remote_path(&final_remote, &init.op_id);
        let io_timeout = self.inner.cfg.io_timeout;

        let (mut conn, mut file) = self
            .open_with_sftp_retry("begin SFTP staging file", |sftp| {
                let final_remote = final_remote.clone();
                let part_remote = part_remote.clone();
                async move {
                    check_dst_precondition_sftp(&sftp, &final_remote, &init.precondition).await?;
                    sftp.open_with_flags(
                        &part_remote,
                        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    )
                    .await
                    .map_err(SftpOpError::Sftp)
                }
            })
            .await?;

        if let Err(e) = timed_file_io(io_timeout, "close SFTP staging file", file.shutdown()).await
        {
            drop(file);
            return Err(e);
        }
        drop(file);
        conn.mark_healthy();
        Ok(UploadSessionInit {
            session_token: part_remote,
            backend_meta: final_remote,
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    pub(super) async fn query_upload_impl(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(part_remote) = op.session_token.as_deref() else {
            return Ok(UploadProgress::Expired);
        };
        self.with_sftp_retry("query_upload stat", |sftp| async move {
            match sftp.symlink_metadata(part_remote).await {
                Ok(meta) => {
                    if !is_regular_file_attrs(&meta) || meta.is_dir() || meta.is_symlink() {
                        return Ok(UploadProgress::Expired);
                    }
                    let remote_len = meta.size.unwrap_or(0);
                    // Trust at most the durable journal checkpoint prefix (`min(remote_len, confirmed_offset)`).
                    // Never trust `remote_len` when `confirmed_offset == 0` because 32-deep pipelined writes
                    // may have written out-of-order packets leaving a sparse zero hole before offset 0..N.
                    let safe_offset = remote_len.min(op.confirmed_offset);
                    Ok(UploadProgress::SequentialOffset(safe_offset))
                }
                Err(e) if is_sftp_not_found(&e) => Ok(UploadProgress::Expired),
                Err(e) => Err(SftpOpError::Sftp(e)),
            }
        })
        .await
    }

    pub(super) async fn upload_chunk_impl(
        &self,
        op: &OperationRecord,
        mut chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let part_remote = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing SFTP staging path"))?;
        let (mut conn, mut file) = self
            .open_with_sftp_retry("open SFTP part for chunk", |sftp| async move {
                match sftp.open_with_flags(part_remote, OpenFlags::WRITE).await {
                    Ok(f) => Ok(f),
                    Err(e) if is_sftp_not_found(&e) => {
                        Err(SftpOpError::Core(Error::session_expired(format!(
                            "SFTP staging file `{part_remote}` missing during chunk upload"
                        ))))
                    }
                    Err(e) => Err(SftpOpError::Sftp(e)),
                }
            })
            .await?;

        let map_chunk_missing = |e: Error| -> Error {
            if e.kind() == ErrorKind::NotFound {
                Error::session_expired(format!(
                    "SFTP staging file `{part_remote}` missing during chunk upload: {}",
                    e.message()
                ))
            } else {
                e
            }
        };

        let io_timeout = self.inner.cfg.io_timeout;
        if let Err(e) = timed_file_io(
            io_timeout,
            "seek SFTP part",
            file.seek(SeekFrom::Start(chunk.offset)),
        )
        .await
        {
            drop(file);
            return Err(map_chunk_missing(e));
        }

        let written = match write_stream_to_sftp_file(
            &mut conn,
            file,
            &mut chunk.body,
            chunk.len,
            io_timeout,
            "SFTP chunk",
            None,
        )
        .await
        {
            Ok(w) => w,
            Err(e) => {
                if e.kind() == ErrorKind::Io || e.kind() == ErrorKind::NotFound {
                    match tokio::time::timeout(
                        io_timeout,
                        conn.session().symlink_metadata(part_remote),
                    )
                    .await
                    {
                        Ok(Err(stat_err)) if is_sftp_not_found(&stat_err) => {
                            return Err(Error::session_expired(format!(
                                "SFTP staging file `{part_remote}` missing during chunk upload: {}",
                                e.message()
                            )));
                        }
                        Ok(Err(stat_err)) if is_sftp_connection_error(&stat_err) => {
                            return Err(map_sftp_err(
                                "probe SFTP staging file after chunk write failure",
                                stat_err,
                            ));
                        }
                        _ => {}
                    }
                }
                return Err(map_chunk_missing(e));
            }
        };

        conn.mark_healthy();
        Ok(ChunkAck {
            next_offset: Some(chunk.offset + written),
            etag: None,
            completed: None,
            checksum: None,
        })
    }

    pub(super) async fn finish_upload_impl(
        &self,
        op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        let part_remote = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::session_expired("missing SFTP staging path"))?;
        let dst_raw = if op.dst_raw_path.is_empty() {
            op.dst_nfc_path.as_str()
        } else {
            op.dst_raw_path.as_str()
        };
        let final_remote = if op.backend_meta.is_empty() {
            self.remote_path(dst_raw)
        } else {
            op.backend_meta.clone()
        };

        // Phase 1 (stale-retryable): verify staged part completeness + DstPrecondition + publish.
        self.with_sftp_retry("finish SFTP upload", |sftp| {
            let final_remote = final_remote.clone();
            async move {
                let part_meta = match sftp.symlink_metadata(part_remote).await {
                    Ok(m) => m,
                    Err(e) if is_sftp_not_found(&e) => {
                        return Err(SftpOpError::Core(Error::session_expired(format!(
                            "SFTP staging file `{part_remote}` missing before finish"
                        ))));
                    }
                    Err(e) => return Err(SftpOpError::Sftp(e)),
                };
                if !is_regular_file_attrs(&part_meta)
                    || part_meta.is_dir()
                    || part_meta.is_symlink()
                {
                    return Err(SftpOpError::Core(Error::protocol(format!(
                        "SFTP staging path `{part_remote}` is not a regular file"
                    ))));
                }
                let actual_size = part_meta.size.unwrap_or(0);
                if actual_size != op.src_version.size {
                    return Err(SftpOpError::Core(Error::protocol(format!(
                        "SFTP staged part `{part_remote}` size mismatch: expected {}, got {actual_size}",
                        op.src_version.size
                    ))));
                }

                if let Err(err) =
                    check_dst_precondition_sftp(&sftp, &final_remote, &op.dst_precondition).await
                {
                    if let SftpOpError::Core(ref ce) = err
                        && !ce.is_retryable()
                    {
                        let _ = sftp.remove_file(part_remote).await;
                    }
                    return Err(err);
                }

                self.publish_atomic(
                    &sftp,
                    &op.op_id,
                    part_remote,
                    &final_remote,
                    op.src_version.mtime_ns,
                    op.dst_precondition.may_exist(),
                )
                .await
            }
        })
        .await?;

        // Phase 2 (separate stale-retryable step): stat committed destination without re-running publish.
        self.with_sftp_retry("stat committed SFTP file", |sftp| {
            let final_remote = final_remote.clone();
            async move {
                let meta = sftp.symlink_metadata(&final_remote).await?;
                attrs_to_entry(&meta, dst_raw, op.dst_nfc_path.clone()).ok_or_else(|| {
                    SftpOpError::Core(Error::protocol(format!(
                        "committed SFTP path `{final_remote}` is non-regular"
                    )))
                })
            }
        })
        .await
    }

    pub(super) async fn abort_upload_impl(&self, op: &OperationRecord) -> Result<()> {
        let dst_raw = if op.dst_raw_path.is_empty() {
            op.dst_nfc_path.as_str()
        } else {
            op.dst_raw_path.as_str()
        };
        let final_remote = if op.backend_meta.is_empty() {
            self.remote_path(dst_raw)
        } else {
            op.backend_meta.clone()
        };
        let part_remote = op
            .session_token
            .clone()
            .unwrap_or_else(|| self.staging_remote_path(&final_remote, &op.op_id));
        let _ = self
            .with_sftp_retry("abort SFTP upload", |sftp| {
                let part_remote = part_remote.clone();
                async move {
                    match sftp.remove_file(&part_remote).await {
                        Ok(()) => Ok(()),
                        Err(e) if is_sftp_not_found(&e) => Ok(()),
                        Err(e) => Err(SftpOpError::Sftp(e)),
                    }
                }
            })
            .await;
        Ok(())
    }

    pub(super) async fn reconcile_operation_impl(
        &self,
        op: &OperationRecord,
    ) -> Result<ReconcileOutcome> {
        let dst_raw = if op.dst_raw_path.is_empty() {
            op.dst_nfc_path.as_str()
        } else {
            op.dst_raw_path.as_str()
        };
        let final_remote = if op.backend_meta.is_empty() {
            self.remote_path(dst_raw)
        } else {
            op.backend_meta.clone()
        };
        let part_remote = op
            .session_token
            .clone()
            .unwrap_or_else(|| self.staging_remote_path(&final_remote, &op.op_id));

        self.with_sftp_retry("reconcile SFTP operation", |sftp| {
            let final_remote = final_remote.clone();
            let part_remote = part_remote.clone();
            async move {
                let part_exists = match sftp.symlink_metadata(&part_remote).await {
                    Ok(_) => true,
                    Err(e) if is_sftp_not_found(&e) => false,
                    Err(e) => return Err(SftpOpError::Sftp(e)),
                };
                if !part_exists {
                    match sftp.symlink_metadata(&final_remote).await {
                        Ok(meta) if is_regular_file_attrs(&meta) && !meta.is_dir() => {
                            if let Some(entry) =
                                attrs_to_entry(&meta, dst_raw, op.dst_nfc_path.clone())
                            {
                                let pre_op =
                                    crate::common::reconcile::PreOpState::from_precondition(
                                        &op.dst_precondition,
                                        |_, _| None,
                                    );
                                return Ok(crate::common::reconcile::judge_reconciled_object(
                                    op,
                                    entry,
                                    None,
                                    &pre_op,
                                    Some(1_000_000_000),
                                    "SFTP reconcile",
                                ));
                            }
                        }
                        Ok(_) => {}
                        Err(e) if is_sftp_not_found(&e) => {}
                        Err(e) => return Err(SftpOpError::Sftp(e)),
                    }
                }
                Ok(ReconcileOutcome::NotCommitted)
            }
        })
        .await
    }
}
