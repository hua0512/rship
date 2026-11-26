//! OS-native local-to-local fast copy (`fclonefileat` on macOS, `FICLONE` on Linux,
//! `CopyFileExW` on Windows) with pre/post TOCTOU source verification, RAII
//! `StagingGuard`, and shared atomic commit.

#[cfg(windows)]
use super::fs_util::copy_file_ex_to_staging;
#[cfg(not(windows))]
use super::fs_util::create_staging_exclusive;
use super::fs_util::{
    StagingGuard, cache_verified_dir, commit_staging_file, create_staging_exclusive_for_rename,
    ensure_no_symlink_escape, ensure_no_symlink_escape_cached, open_read_sequential_opt,
    open_read_shared_opt, to_os_path,
};
use super::{LocalBackend, SMALL_SINGLE_SHOT_INLINE_MAX};
use rship_core::backend::{BackendPath, UploadInit};
use rship_core::clock::system_time_to_unix_nanos;
use rship_core::types::Entry;
use rship_core::{Error, ErrorKind, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn should_fallback_source_open(err: &Error) -> bool {
    #[cfg(windows)]
    {
        const ERROR_INVALID_NAME: i32 = 123;
        err.kind == ErrorKind::NotFound
            || err
                .source
                .as_deref()
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .is_some_and(|io| io.raw_os_error() == Some(ERROR_INVALID_NAME))
    }
    #[cfg(not(windows))]
    {
        err.kind == ErrorKind::NotFound
    }
}

fn copy_large_to_staging(
    src_f: &mut File,
    src_abs: &Path,
    part_path: &Path,
    expected_size: u64,
) -> Result<File> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::os::unix::io::AsRawFd;

        if let Ok(part_c) = CString::new(part_path.as_os_str().as_bytes()) {
            for attempt in 0..2 {
                // SAFETY: `src_f` is an open valid fd and `part_c` is NUL-terminated.
                let rc = unsafe {
                    libc::fclonefileat(src_f.as_raw_fd(), libc::AT_FDCWD, part_c.as_ptr(), 0)
                };
                if rc == 0 {
                    // `fclonefileat` preserves the source `st_mode` (`0o444` when read-only);
                    // ensure owner write permission before reopening `.write(true)` for mtime/fsync.
                    if let Ok(meta) = std::fs::symlink_metadata(part_path)
                        && !meta.file_type().is_symlink()
                    {
                        let mode = meta.permissions().mode();
                        if (mode & 0o200) == 0 {
                            let _ = std::fs::set_permissions(
                                part_path,
                                std::fs::Permissions::from_mode(mode | 0o200),
                            );
                        }
                    }
                    return std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(part_path)
                        .map_err(|e| {
                            Error::io(format!("open cloned staging `{}`", part_path.display()), e)
                        });
                }
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(0);
                if errno == libc::EEXIST && attempt == 0 {
                    let _ = std::fs::remove_file(part_path);
                    continue;
                }
                if matches!(
                    errno,
                    libc::ENOTSUP | libc::EXDEV | libc::EINVAL | libc::EACCES | libc::EPERM
                ) {
                    break;
                }
                return Err(Error::io(
                    format!(
                        "fclonefileat `{}` -> `{}`",
                        src_abs.display(),
                        part_path.display()
                    ),
                    err,
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;

        let mut dst_f = create_staging_exclusive(part_path)?;
        // SAFETY: both fds are valid open file descriptors; `ioctl(FICLONE)` either succeeds
        // atomically on CoW filesystems or returns `-1` cleanly so we fall back to `io::copy`.
        let rc = unsafe { libc::ioctl(dst_f.as_raw_fd(), libc::FICLONE as _, src_f.as_raw_fd()) };
        if rc == 0 {
            return Ok(dst_f);
        }
        let copied = std::io::copy(src_f, &mut dst_f).map_err(|e| {
            Error::io(
                format!(
                    "native local copy `{}` -> `{}`",
                    src_abs.display(),
                    part_path.display()
                ),
                e,
            )
        })?;
        if copied != expected_size {
            return Err(Error::source_mutated(format!(
                "source `{}` changed length during local copy ({copied} != {expected_size})",
                src_abs.display()
            )));
        }
        Ok(dst_f)
    }

    #[cfg(windows)]
    {
        match copy_file_ex_to_staging(src_abs, part_path) {
            Ok(dst_f) => Ok(dst_f),
            Err((err, false)) => Err(err),
            Err((_, true)) => {
                let mut dst_f = create_staging_exclusive_for_rename(part_path)?;
                let copied = std::io::copy(src_f, &mut dst_f).map_err(|e| {
                    Error::io(
                        format!(
                            "native local copy `{}` -> `{}`",
                            src_abs.display(),
                            part_path.display()
                        ),
                        e,
                    )
                })?;
                if copied != expected_size {
                    return Err(Error::source_mutated(format!(
                        "source `{}` changed length during local copy ({copied} != {expected_size})",
                        src_abs.display()
                    )));
                }
                Ok(dst_f)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let mut dst_f = create_staging_exclusive(part_path)?;
        let copied = std::io::copy(src_f, &mut dst_f).map_err(|e| {
            Error::io(
                format!(
                    "native local copy `{}` -> `{}`",
                    src_abs.display(),
                    part_path.display()
                ),
                e,
            )
        })?;
        if copied != expected_size {
            return Err(Error::source_mutated(format!(
                "source `{}` changed length during local copy ({copied} != {expected_size})",
                src_abs.display()
            )));
        }
        Ok(dst_f)
    }
}

impl LocalBackend {
    pub(super) async fn server_side_copy_impl(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        let Some(src_root_str) = src_endpoint.strip_prefix("local://") else {
            return Ok(None);
        };
        let src_root = PathBuf::from(src_root_str);
        let mut src_abs = src_root.clone();
        let src_raw = src_path.raw_path();
        if !src_raw.is_empty() {
            for seg in src_raw.split('/') {
                if !seg.is_empty() {
                    src_abs.push(seg);
                }
            }
        }
        let src_abs = to_os_path(&src_abs);

        let dst_root = self.root.clone();
        let encoding = self.encoding;
        let final_path = self
            .resolve_write_path(&init.dst_path, init.precondition.may_exist())
            .await?;
        let part_path = self.staging_path(&final_path, &init.op_id);
        let expected_size = init.total_size;
        let expected_mtime_ns = init.src_mtime_ns;
        let dst_rel = init.dst_path.clone();
        let verified_dirs = self.verified_dirs.clone();
        let precondition = init.precondition.clone();
        let durability = self.durability.clone();
        let skip_dst_leaf = matches!(precondition, rship_core::state::DstPrecondition::Absent);

        tokio::task::spawn_blocking(move || {
            let durable = durability.commit_durably();
            // Do not pass destination `self.verified_dirs` when checking `src_root`.
            // If source traverses a symlink (e.g. `--copy-links`), fall back cleanly to
            // streaming `src.open_read_entry` (which strictly enforces `src.follow_symlinks`),
            // while destination writes ALWAYS strictly enforce symlink-escape containment below.
            if ensure_no_symlink_escape(&src_root, &src_abs).is_err() {
                return Ok(None);
            }
            let parent_exists = ensure_no_symlink_escape_cached(
                &dst_root,
                &final_path,
                &verified_dirs,
                skip_dst_leaf,
            )?;

            if !parent_exists && let Some(parent) = final_path.parent() {
                durability.create_dir_all(parent)?;
                cache_verified_dir(&verified_dirs, parent);
            }

            let mut guard = StagingGuard::new(part_path.clone());
            let (src_f, dst_f, use_in_handle_rename) = if expected_size
                <= SMALL_SINGLE_SHOT_INLINE_MAX
            {
                let mut src_f = match open_read_shared_opt(&src_abs, false) {
                    Ok(f) => f,
                    Err(e) if should_fallback_source_open(&e) => return Ok(None),
                    Err(e) => return Err(e),
                };
                let pre_meta = src_f
                    .metadata()
                    .map_err(|e| Error::io(format!("stat source `{}`", src_abs.display()), e))?;
                if !pre_meta.is_file() {
                    return Err(Error::invalid_path(format!(
                        "`{}` is not a regular file",
                        src_abs.display()
                    )));
                }
                let pre_mtime_ns = pre_meta
                    .modified()
                    .map(system_time_to_unix_nanos)
                    .unwrap_or(0);
                if pre_meta.len() != expected_size || pre_mtime_ns != expected_mtime_ns {
                    return Err(Error::source_mutated(format!(
                        "source `{}` mutated before local fast copy",
                        src_abs.display()
                    )));
                }
                let mut buf = vec![0u8; expected_size as usize];
                if !buf.is_empty()
                    && let Err(e) = src_f.read_exact(&mut buf)
                {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        return Err(Error::source_mutated(format!(
                            "source `{}` truncated during local fast copy",
                            src_abs.display()
                        )));
                    }
                    return Err(Error::io(format!("read source `{}`", src_abs.display()), e));
                }
                let mut dst_f = create_staging_exclusive_for_rename(&part_path)?;
                if !buf.is_empty() {
                    dst_f.write_all(&buf).map_err(|e| {
                        Error::io(format!("write staging `{}`", part_path.display()), e)
                    })?;
                }
                (src_f, dst_f, true)
            } else {
                let mut src_f = match open_read_sequential_opt(&src_abs, false) {
                    Ok(f) => f,
                    Err(e) if should_fallback_source_open(&e) => return Ok(None),
                    Err(e) => return Err(e),
                };
                let pre_meta = src_f
                    .metadata()
                    .map_err(|e| Error::io(format!("stat source `{}`", src_abs.display()), e))?;
                if !pre_meta.is_file() {
                    return Err(Error::invalid_path(format!(
                        "`{}` is not a regular file",
                        src_abs.display()
                    )));
                }
                let pre_mtime_ns = pre_meta
                    .modified()
                    .map(system_time_to_unix_nanos)
                    .unwrap_or(0);
                if pre_meta.len() != expected_size || pre_mtime_ns != expected_mtime_ns {
                    return Err(Error::source_mutated(format!(
                        "source `{}` mutated before local fast copy",
                        src_abs.display()
                    )));
                }
                let dst_f = copy_large_to_staging(&mut src_f, &src_abs, &part_path, expected_size)?;
                (src_f, dst_f, false)
            };

            let post_meta = src_f.metadata().map_err(|e| {
                Error::source_mutated(format!(
                    "source `{}` disappeared during copy: {e}",
                    src_abs.display()
                ))
            })?;
            drop(src_f);
            let post_mtime_ns = post_meta
                .modified()
                .map(system_time_to_unix_nanos)
                .unwrap_or(0);
            if post_meta.len() != expected_size || post_mtime_ns != expected_mtime_ns {
                return Err(Error::source_mutated(format!(
                    "source `{}` mutated during local fast copy",
                    src_abs.display()
                )));
            }

            let entry = commit_staging_file(
                dst_f,
                &part_path,
                &final_path,
                expected_mtime_ns,
                &precondition,
                durable,
                &dst_root,
                dst_rel,
                encoding,
                use_in_handle_rename,
            )?;
            guard.disarm();
            durability.after_commit(&final_path)?;

            Ok(Some(entry))
        })
        .await
        .map_err(|e| Error::protocol(format!("local server_side_copy join: {e}")))?
    }
}
