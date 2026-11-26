//! Unix/POSIX OS-specific filesystem helpers (`statvfs`, `pread`, `O_NOFOLLOW`,
//! `O_NONBLOCK` FIFO protection, `posix_fadvise`, atomic `RENAME_NOREPLACE`/`RENAME_EXCL`/
//! `link`+`unlink`, `F_FULLFSYNC` -> `fsync` fallback, `pathconf`/`statfs` probing, and
//! Linux `syncfs`).

use rship_core::types::NodeId;
use rship_core::{Error, Result};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub(in crate::local) fn local_disk_quota(
    path: &Path,
) -> Result<Option<rship_core::types::StorageQuota>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut target = path.to_path_buf();
    while !target.exists() {
        if !target.pop() {
            break;
        }
    }
    let cpath = CString::new(target.as_os_str().as_bytes())
        .map_err(|e| Error::invalid_path(format!("invalid unix path for statvfs: {e}")))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `cpath` is a valid NUL-terminated path and `stat` points to writable stack storage
    // sized and aligned for `libc::statvfs`.
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Ok(None);
    }
    // SAFETY: `libc::statvfs` returned 0, so `stat` has been fully initialized by the OS.
    let stat = unsafe { stat.assume_init() };
    // `libc::statvfs` field types (`c_ulong` / `fsblkcnt_t`) vary between `u32` and `u64`
    // across Unix targets (e.g. macOS vs 64-bit Linux vs 32-bit Unix).
    #[allow(clippy::unnecessary_cast)]
    let (total, free_avail, free_total) = {
        let frsize = if stat.f_frsize > 0 {
            stat.f_frsize as u64
        } else {
            stat.f_bsize as u64
        };
        let total = (stat.f_blocks as u64).saturating_mul(frsize);
        let free_avail = (stat.f_bavail as u64).saturating_mul(frsize);
        let free_total = (stat.f_bfree as u64).saturating_mul(frsize);
        (total, free_avail, free_total)
    };
    Ok(Some(rship_core::types::StorageQuota {
        total_bytes: Some(total),
        used_bytes: Some(total.saturating_sub(free_total)),
        free_bytes: Some(free_avail),
        trashed_bytes: None,
    }))
}

#[derive(Clone)]
pub(super) struct PlatformReadHandle(Arc<File>);

impl PlatformReadHandle {
    pub(super) fn new(file: File, _follow_symlinks: bool) -> Self {
        Self(Arc::new(file))
    }

    pub(super) fn read_exact_at(&self, offset: u64, buf: &mut [u8], path: &Path) -> Result<usize> {
        use std::os::unix::fs::FileExt;
        self.0
            .read_at(buf, offset)
            .map_err(|e| Error::io(format!("pread `{}` at {offset}", path.display()), e))
    }
}

fn open_regular_file_nonblocking(path: &Path, follow_symlinks: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let mut flags = libc::O_NONBLOCK;
    if !follow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(flags);
    let file = opts
        .open(path)
        .map_err(|e| Error::io(format!("open `{}`", path.display()), e))?;

    let meta = file
        .metadata()
        .map_err(|e| Error::io(format!("fstat `{}`", path.display()), e))?;
    if !meta.is_file() {
        return Err(Error::invalid_path(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }

    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid open file descriptor for the regular file we just fstat-checked.
    let cur_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if cur_flags != -1 && (cur_flags & libc::O_NONBLOCK) != 0 {
        // SAFETY: clearing `O_NONBLOCK` on a verified regular-file descriptor.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, cur_flags & !libc::O_NONBLOCK) };
    }
    Ok(file)
}

pub(in crate::local) fn open_read_shared_opt(path: &Path, follow_symlinks: bool) -> Result<File> {
    open_regular_file_nonblocking(path, follow_symlinks)
}

/// Open a file for sequential streaming reads (e.g. full-file hashing) with OS
/// prefetch/readahead hints.
pub(in crate::local) fn open_read_sequential_opt(
    path: &Path,
    follow_symlinks: bool,
) -> Result<File> {
    let file = open_regular_file_nonblocking(path, follow_symlinks)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` holds a valid open file descriptor; `posix_fadvise` is advisory.
        let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    }
    Ok(file)
}

pub(in crate::local) fn open_write_shared(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.write(true).custom_flags(libc::O_NOFOLLOW);
    opts.open(path)
        .map_err(|e| Error::io(format!("open part `{}`", path.display()), e))
}

pub(in crate::local) fn open_append_shared(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW);
    opts.open(path)
        .map_err(|e| Error::io(format!("open manifest `{}`", path.display()), e))
}

pub(in crate::local) fn create_staging_exclusive_for_rename(part_path: &Path) -> Result<File> {
    super::create_staging_exclusive(part_path)
}

fn is_not_supported_errno(errno: i32) -> bool {
    errno == libc::ENOTSUP || errno == libc::EOPNOTSUPP
}

fn replace_absent_atomic(part_path: &Path, final_path: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = CString::new(part_path.as_os_str().as_bytes())
        .map_err(|e| Error::invalid_path(format!("invalid staging path: {e}")))?;
    let dst_c = CString::new(final_path.as_os_str().as_bytes())
        .map_err(|e| Error::invalid_path(format!("invalid destination path: {e}")))?;

    let precond_err = || {
        Error::precondition_failed(format!(
            "destination `{}` already exists (precondition Absent)",
            final_path.display()
        ))
    };

    #[cfg(target_os = "linux")]
    {
        // Use `SYS_renameat2` via `libc::syscall` so both `linux-gnu` and `linux-musl` compile.
        // SAFETY: `src_c` and `dst_c` are valid NUL-terminated paths for `AT_FDCWD`.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                src_c.as_ptr(),
                libc::AT_FDCWD,
                dst_c.as_ptr(),
                libc::RENAME_NOREPLACE as libc::c_long,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        if errno == libc::EEXIST {
            return Err(precond_err());
        }
        if errno != libc::ENOSYS && errno != libc::EINVAL && !is_not_supported_errno(errno) {
            return Err(Error::io(
                format!(
                    "renameat2 `{}` -> `{}`",
                    part_path.display(),
                    final_path.display()
                ),
                err,
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // SAFETY: `src_c` and `dst_c` are valid NUL-terminated paths for `AT_FDCWD`.
        let rc = unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                src_c.as_ptr(),
                libc::AT_FDCWD,
                dst_c.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        if errno == libc::EEXIST {
            return Err(precond_err());
        }
        if errno != libc::EINVAL && errno != libc::ENOSYS && !is_not_supported_errno(errno) {
            return Err(Error::io(
                format!(
                    "renameatx_np `{}` -> `{}`",
                    part_path.display(),
                    final_path.display()
                ),
                err,
            ));
        }
    }

    // Portable atomic creation fallback: `link` (fails atomically with EEXIST) + `unlink`.
    // SAFETY: `src_c` and `dst_c` are valid NUL-terminated paths.
    let rc = unsafe { libc::link(src_c.as_ptr(), dst_c.as_ptr()) };
    if rc == 0 {
        let _ = std::fs::remove_file(part_path);
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(0);
    if errno == libc::EEXIST {
        return Err(precond_err());
    }
    if errno == libc::EPERM || errno == libc::ENOSYS || is_not_supported_errno(errno) {
        // Filesystems without hardlinks (e.g. FAT32/exFAT): check and rename.
        match std::fs::symlink_metadata(final_path) {
            Ok(_) => return Err(precond_err()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::fs::rename(part_path, final_path).map_err(|re| {
                    Error::io(
                        format!(
                            "rename `{}` -> `{}`",
                            part_path.display(),
                            final_path.display()
                        ),
                        re,
                    )
                });
            }
            Err(e) => {
                return Err(Error::io(
                    format!("stat destination `{}`", final_path.display()),
                    e,
                ));
            }
        }
    }
    Err(Error::io(
        format!(
            "link `{}` -> `{}`",
            part_path.display(),
            final_path.display()
        ),
        err,
    ))
}

pub(in crate::local) fn atomic_replace(
    part_path: &Path,
    final_path: &Path,
    durable: bool,
    replace: bool,
) -> Result<()> {
    if replace {
        std::fs::rename(part_path, final_path).map_err(|e| {
            Error::io(
                format!(
                    "rename `{}` -> `{}`",
                    part_path.display(),
                    final_path.display()
                ),
                e,
            )
        })?;
    } else {
        replace_absent_atomic(part_path, final_path)?;
    }
    if durable && let Some(parent) = final_path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

pub(in crate::local) fn clear_readonly_if_windows(path: &Path) {
    let _ = path;
}

/// Whether `File::sync_all()` (`F_FULLFSYNC` on macOS) failed because the mount
/// (SMB/NFS/exFAT/FUSE/VirtioFS) does not support `F_FULLFSYNC` and should fall back
/// to `fsync(2)`.
#[cfg(any(target_os = "macos", test))]
pub(in crate::local) fn is_fullfsync_unsupported(err: &std::io::Error) -> bool {
    err.raw_os_error().is_some_and(|code| {
        code == libc::ENOTSUP
            || code == libc::EINVAL
            || code == libc::EOPNOTSUPP
            || code == libc::ENOTTY
    })
}

pub(in crate::local) fn sync_file_durable(file: &File) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        match file.sync_all() {
            Ok(()) => Ok(()),
            Err(e) if is_fullfsync_unsupported(&e) => {
                use std::os::unix::io::AsRawFd;
                loop {
                    // SAFETY: `file.as_raw_fd()` is a valid open file descriptor.
                    let rc = unsafe { libc::fsync(file.as_raw_fd()) };
                    if rc == 0 {
                        return Ok(());
                    }
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

/// Whether a directory `fsync` error means the filesystem genuinely cannot sync directories
/// (some FUSE, CIFS/SMB and NFS configurations return `EINVAL` or `ENOTSUP`), as opposed to
/// a real I/O failure that must be reported.
fn dir_fsync_unsupported(err: &std::io::Error) -> bool {
    err.raw_os_error().is_some_and(|code| {
        code == libc::EINVAL
            || code == libc::ENOTSUP
            || code == libc::EOPNOTSUPP
            || code == libc::ENOSYS
    })
}

fn open_nofollow_readonly(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Durably `fsync` a directory so the entries created, renamed or removed in it survive a
/// power loss.
///
/// Returns `Ok(true)` when the directory was synced and `Ok(false)` when the filesystem
/// cannot sync directories. Open failures and real `fsync` failures (e.g. `EIO`) are errors.
pub(in crate::local) fn sync_dir(dir: &Path) -> Result<bool> {
    let handle = open_nofollow_readonly(dir)
        .map_err(|e| Error::io(format!("open directory `{}` for fsync", dir.display()), e))?;
    sync_open_dir(&handle, dir)
}

fn sync_open_dir(handle: &File, dir: &Path) -> Result<bool> {
    match sync_file_durable(handle) {
        Ok(()) => Ok(true),
        Err(e) if dir_fsync_unsupported(&e) => Ok(false),
        Err(e) => Err(Error::io(format!("fsync directory `{}`", dir.display()), e)),
    }
}

/// Durably sync a single committed file (`sync_file_durable`), its parent directory, and then
/// every extra directory in `extra_dirs` (the parents of newly created intermediate
/// directories), in that order.
///
/// Returns the number of directories synced.
pub(in crate::local) fn sync_file_and_parent(path: &Path, extra_dirs: &[PathBuf]) -> Result<u64> {
    let file = open_nofollow_readonly(path)
        .map_err(|e| Error::io(format!("open `{}` for durable fsync", path.display()), e))?;
    sync_file_durable(&file).map_err(|e| Error::io(format!("fsync `{}`", path.display()), e))?;
    let mut dirs = 0u64;
    if let Some(parent) = path.parent() {
        dirs += u64::from(sync_dir(parent)?);
    }
    for dir in extra_dirs {
        dirs += u64::from(sync_dir(dir)?);
    }
    Ok(dirs)
}

/// Whether a `syncfs(2)` failure means the call itself is unavailable (old kernels, seccomp
/// or container policies, filesystems without `sync_fs`), so falling back to per-path
/// `fsync` is correct. Any other error (notably `EIO`) is a real write-back failure.
#[cfg(target_os = "linux")]
pub(in crate::local) fn syncfs_unsupported(errno: i32) -> bool {
    errno == libc::ENOSYS
        || errno == libc::EPERM
        || errno == libc::ENOTSUP
        || errno == libc::EOPNOTSUPP
}

/// Flush a batch of deferred local writes (`FsyncMode::Batch`):
/// - Linux: single `syncfs(2)` on the root directory fd, falling back to per-file/dir `fsync`
///   only when `syncfs` is unavailable (`ENOSYS`, `EPERM`, `EOPNOTSUPP`). Real failures such
///   as `EIO` are returned.
/// - macOS / other Unix: `fsync` each pending written file, then each parent directory.
///
/// The sets are borrowed so a caller can keep every path pending when this returns an error.
pub(in crate::local) fn flush_pending_batch(
    root: &Path,
    files: &HashSet<PathBuf>,
    dirs: &HashSet<PathBuf>,
    opts: &super::BatchFlushOptions,
) -> Result<super::BatchSyncStats> {
    if files.is_empty() && dirs.is_empty() {
        return Ok(super::BatchSyncStats::default());
    }

    #[cfg(target_os = "linux")]
    if opts.allow_syncfs {
        use std::os::unix::io::AsRawFd;
        if let Ok(dir) = File::open(to_os_path(root)) {
            #[cfg(test)]
            let forced = opts.syncfs_errno;
            #[cfg(not(test))]
            let forced: Option<i32> = None;
            let errno = match forced {
                Some(errno) => Some(errno),
                None => {
                    // SAFETY: `dir.as_raw_fd()` is an open valid file descriptor owned by `dir`.
                    let rc = unsafe { libc::syncfs(dir.as_raw_fd()) };
                    if rc == 0 {
                        None
                    } else {
                        Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
                    }
                }
            };
            match errno {
                None => {
                    return Ok(super::BatchSyncStats {
                        syncfs: true,
                        ..Default::default()
                    });
                }
                Some(errno) if syncfs_unsupported(errno) => {}
                Some(errno) => {
                    return Err(Error::io(
                        format!("syncfs `{}`", root.display()),
                        std::io::Error::from_raw_os_error(errno),
                    ));
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (root, opts);

    let file_list: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    let synced_files = super::parallel_sync_paths(&file_list, |file_path| {
        match open_nofollow_readonly(file_path) {
            Ok(f) => {
                sync_file_durable(&f)
                    .map_err(|e| Error::io(format!("batch fsync `{}`", file_path.display()), e))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(
                format!("open `{}` for batch fsync", file_path.display()),
                e,
            )),
        }
    })?;

    // Sync parent directories strictly AFTER file data flushes complete (OSDI-2014 order).
    // A directory removed since the write (e.g. by a later delete pass) has nothing to sync.
    let dir_list: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
    let synced_dirs =
        super::parallel_sync_paths(&dir_list, |dir_path| {
            match open_nofollow_readonly(dir_path) {
                Ok(handle) => sync_open_dir(&handle, dir_path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(Error::io(
                    format!("open directory `{}` for batch fsync", dir_path.display()),
                    e,
                )),
            }
        })?;

    Ok(super::BatchSyncStats {
        files: synced_files,
        dirs: synced_dirs,
        syncfs: false,
    })
}

pub(super) fn metadata_node_and_ctime(meta: &std::fs::Metadata) -> (Option<NodeId>, Option<i64>) {
    use std::os::unix::fs::MetadataExt;
    let nid = Some(NodeId(format!("{}:{}", meta.dev(), meta.ino())));
    let ct = meta
        .ctime()
        .saturating_mul(1_000_000_000)
        .saturating_add(meta.ctime_nsec());
    (nid, Some(ct))
}

pub(super) fn same_file_identity(
    _a_path: &Path,
    a_meta: &std::fs::Metadata,
    _b_path: &Path,
    b_meta: &std::fs::Metadata,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    a_meta.dev() == b_meta.dev()
        && a_meta.ino() == b_meta.ino()
        && (a_meta.is_dir() || b_meta.is_dir() || a_meta.nlink() == 1)
}

fn deepest_existing_dir(root: &Path) -> Option<PathBuf> {
    let mut cur = root.to_path_buf();
    while !cur.is_dir() {
        if !cur.pop() {
            return None;
        }
    }
    Some(cur)
}

pub(in crate::local) fn probe_case_sensitivity(root: &Path) -> bool {
    let Some(cur) = deepest_existing_dir(root) else {
        return cfg!(target_os = "linux");
    };

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        if let Ok(cpath) = CString::new(cur.as_os_str().as_bytes()) {
            // SAFETY: `cpath` is NUL-terminated.
            let res = unsafe { libc::pathconf(cpath.as_ptr(), libc::_PC_CASE_SENSITIVE) };
            if res == 1 {
                return true;
            }
            if res == 0 {
                return false;
            }
        }
        super::probe_dir_case_sensitive_readonly(&cur).unwrap_or(false)
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(cs) = super::probe_dir_case_sensitive_readonly(&cur) {
            return cs;
        }
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            const MSDOS_SUPER_MAGIC: u64 = 0x4d44;
            const EXFAT_SUPER_MAGIC: u64 = 0x2011_bab0;
            if let Ok(cpath) = CString::new(cur.as_os_str().as_bytes()) {
                let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
                // SAFETY: `cpath` is NUL-terminated and `st` is valid stack storage.
                if unsafe { libc::statfs(cpath.as_ptr(), st.as_mut_ptr()) } == 0 {
                    // SAFETY: `statfs` succeeded.
                    let st = unsafe { st.assume_init() };
                    #[allow(clippy::unnecessary_cast)]
                    let f_type = st.f_type as u64;
                    if f_type == MSDOS_SUPER_MAGIC || f_type == EXFAT_SUPER_MAGIC {
                        return false;
                    }
                }
            }
        }
        cfg!(target_os = "linux")
    }
}

pub(in crate::local) fn detect_mtime_granularity(path: &Path) -> Duration {
    let Some(cur) = deepest_existing_dir(path) else {
        return Duration::from_millis(10);
    };

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        const MSDOS_SUPER_MAGIC: u64 = 0x4d44;
        if let Ok(cpath) = CString::new(cur.as_os_str().as_bytes()) {
            let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            // SAFETY: `cpath` is NUL-terminated and `st` is valid stack storage.
            if unsafe { libc::statfs(cpath.as_ptr(), st.as_mut_ptr()) } == 0 {
                // SAFETY: `statfs` succeeded.
                let st = unsafe { st.assume_init() };
                #[allow(clippy::unnecessary_cast)]
                if (st.f_type as u64) == MSDOS_SUPER_MAGIC {
                    return Duration::from_secs(2);
                }
            }
        }
        Duration::from_millis(10)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::ffi::{CStr, CString};
        use std::os::unix::ffi::OsStrExt;
        if let Ok(cpath) = CString::new(cur.as_os_str().as_bytes()) {
            let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            // SAFETY: `cpath` is NUL-terminated and `st` is valid stack storage.
            if unsafe { libc::statfs(cpath.as_ptr(), st.as_mut_ptr()) } == 0 {
                // SAFETY: `statfs` succeeded and `f_fstypename` is NUL-terminated.
                let st = unsafe { st.assume_init() };
                // SAFETY: `statfs` succeeded, so `f_fstypename` holds a NUL-terminated
                // filesystem name within the initialized `statfs` struct.
                let fs_name = unsafe { CStr::from_ptr(st.f_fstypename.as_ptr()) }.to_string_lossy();
                return super::fs_name_mtime_granularity(&fs_name);
            }
        }
        Duration::from_millis(10)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = cur;
        Duration::from_millis(10)
    }
}

/// Apply Windows extended-length verbatim syntax (`\\?\` or `\\?\UNC\`) for long
/// absolute paths (no-op on Unix, returning the path untouched).
pub fn to_os_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}
