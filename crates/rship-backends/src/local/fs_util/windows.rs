//! Windows OS-specific filesystem helpers (`GetDiskFreeSpaceExW`, pooled shared
//! `seek_read` handles with `ReOpenFile` TOCTOU pinning, `IsReparseTagNameSurrogate`
//! reparse-point checks, `SetFileInformationByHandle` rename, `MoveFileExW` retry,
//! `CopyFileExW`, `FileCaseSensitiveInfo`, FAT32 volume detection, and `\\?\` /
//! `\\?\UNC\` UTF-16 long-path normalization).

use rship_core::types::NodeId;
use rship_core::{Error, Result};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const REPARSE_TAG_NAME_SURROGATE_BIT: u32 = 0x2000_0000;
const FILE_ATTRIBUTE_OFFLINE_FLAG: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG: u32 = 0x0040_0000;
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 1;
const ERROR_CANT_ACCESS_FILE_CODE: i32 = 1920;

pub(in crate::local) const fn is_reparse_tag_name_surrogate(tag: u32) -> bool {
    (tag & REPARSE_TAG_NAME_SURROGATE_BIT) != 0
}

pub(in crate::local) fn format_disk_free_space_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let os_target = to_os_path(path);
    let mut wide: Vec<u16> = os_target.as_os_str().encode_wide().collect();
    let is_unc = matches!(
        os_target.components().next(),
        Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _))
    );
    let needs_trailing_slash = is_unc || std::fs::metadata(&os_target).is_ok_and(|m| m.is_dir());
    if needs_trailing_slash && !wide.ends_with(&[b'\\' as u16]) {
        wide.push(b'\\' as u16);
    }
    wide.push(0);
    wide
}

pub(in crate::local) fn local_disk_quota(
    path: &Path,
) -> Result<Option<rship_core::types::StorageQuota>> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let mut target = path.to_path_buf();
    while std::fs::metadata(to_os_path(&target)).is_err() {
        if !target.pop() {
            break;
        }
    }
    let wide = format_disk_free_space_path(&target);
    let mut free_avail = 0u64;
    let mut total = 0u64;
    let mut total_free = 0u64;
    // SAFETY: `wide` is null-terminated UTF-16 and output pointers are valid stack locals.
    let ok =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free_avail, &mut total, &mut total_free) };
    if ok == 0 {
        return Ok(None);
    }
    Ok(Some(rship_core::types::StorageQuota {
        total_bytes: Some(total),
        used_bytes: Some(total.saturating_sub(total_free)),
        free_bytes: Some(free_avail),
        trashed_bytes: None,
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct WinFileIdentity {
    vol_serial: u32,
    index_high: u32,
    index_low: u32,
    size_high: u32,
    size_low: u32,
    mtime_low: u32,
    mtime_high: u32,
}

fn win_file_identity(file: &File) -> Option<WinFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `file.as_raw_handle()` is a live Win32 handle and `info` is valid stack storage.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return None;
    }
    // SAFETY: `GetFileInformationByHandle` succeeded and initialized `info`.
    let info = unsafe { info.assume_init() };
    Some(WinFileIdentity {
        vol_serial: info.dwVolumeSerialNumber,
        index_high: info.nFileIndexHigh,
        index_low: info.nFileIndexLow,
        size_high: info.nFileSizeHigh,
        size_low: info.nFileSizeLow,
        mtime_low: info.ftLastWriteTime.dwLowDateTime,
        mtime_high: info.ftLastWriteTime.dwHighDateTime,
    })
}

/// Pool of independent `FILE_SHARE_READ|WRITE|DELETE` OS handles on Windows so
/// concurrent multipart chunk reads execute `seek_read` truly in parallel in the
/// NT kernel without serializing on a single synchronous `HANDLE` or mutex, while
/// pinning the original inode via `anchor` + `ReOpenFile` + `WinFileIdentity`.
#[derive(Clone)]
pub(super) struct PlatformReadHandle {
    anchor: Arc<File>,
    anchor_busy: Arc<AtomicBool>,
    pinned_id: Option<WinFileIdentity>,
    pool: Arc<StdMutex<Vec<File>>>,
    follow_symlinks: bool,
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl PlatformReadHandle {
    pub(super) fn new(file: File, follow_symlinks: bool) -> Self {
        let pinned_id = win_file_identity(&file);
        Self {
            anchor: Arc::new(file),
            anchor_busy: Arc::new(AtomicBool::new(false)),
            pinned_id,
            pool: Arc::new(StdMutex::new(Vec::new())),
            follow_symlinks,
        }
    }

    fn verify_handle_identity(&self, handle: &File, path: &Path) -> Result<()> {
        if let Some(expected) = self.pinned_id {
            let actual = win_file_identity(handle);
            if actual != Some(expected) {
                return Err(Error::source_mutated(format!(
                    "source `{}` replaced or mutated during concurrent read",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn open_concurrent_handle(&self, path: &Path) -> Result<File> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
        };

        // SAFETY: `self.anchor` is a live open handle for the lifetime of `self`.
        let reopened = unsafe {
            ReOpenFile(
                self.anchor.as_raw_handle(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        if reopened != INVALID_HANDLE_VALUE && !reopened.is_null() {
            // SAFETY: `ReOpenFile` returned a fresh owned Win32 handle.
            let file = unsafe { File::from_raw_handle(reopened) };
            self.verify_handle_identity(&file, path)?;
            return Ok(file);
        }

        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if matches!(
            code,
            ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER | ERROR_ACCESS_DENIED
        ) {
            let file = open_read_shared_opt(path, self.follow_symlinks)?;
            self.verify_handle_identity(&file, path)?;
            return Ok(file);
        }
        Err(Error::io(format!("ReOpenFile `{}`", path.display()), err))
    }

    pub(super) fn read_exact_at(&self, offset: u64, buf: &mut [u8], path: &Path) -> Result<usize> {
        use std::os::windows::fs::FileExt;
        const MAX_POOLED_READ_HANDLES: usize = 16;

        if self
            .anchor_busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let _busy = BusyGuard(&self.anchor_busy);
            let n = self
                .anchor
                .seek_read(buf, offset)
                .map_err(|e| Error::io(format!("seek_read `{}` at {offset}", path.display()), e))?;
            self.verify_handle_identity(&self.anchor, path)?;
            return Ok(n);
        }

        let handle = match crate::common::lock_unpoisoned(&self.pool).pop() {
            Some(f) => f,
            None => self.open_concurrent_handle(path)?,
        };
        let res = handle
            .seek_read(buf, offset)
            .map_err(|e| Error::io(format!("seek_read `{}` at {offset}", path.display()), e));
        if res.is_ok() {
            self.verify_handle_identity(&handle, path)?;
            let mut g = crate::common::lock_unpoisoned(&self.pool);
            if g.len() < MAX_POOLED_READ_HANDLES {
                g.push(handle);
            }
        }
        res
    }
}

fn file_reparse_status(file: &File, path: &Path) -> Result<(bool, bool, u32)> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo,
        GetFileInformationByHandleEx,
    };

    let mut info = std::mem::MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
    // SAFETY: `file.as_raw_handle()` is a valid open Win32 handle and `info` has exact size.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            info.as_mut_ptr() as *mut std::ffi::c_void,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok != 0 {
        // SAFETY: `GetFileInformationByHandleEx` succeeded and initialized `info`.
        let info = unsafe { info.assume_init() };
        if (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
            return Ok((false, false, info.FileAttributes));
        }
        return Ok((
            true,
            is_reparse_tag_name_surrogate(info.ReparseTag),
            info.FileAttributes,
        ));
    }

    let meta = file
        .metadata()
        .map_err(|e| Error::io(format!("fstat `{}`", path.display()), e))?;
    let attrs = meta.file_attributes();
    let is_reparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    let is_surrogate = meta.file_type().is_symlink();
    Ok((is_reparse, is_surrogate, attrs))
}

fn file_id_info(file: &File) -> Option<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: `file.as_raw_handle()` is a valid Win32 handle and `info` is valid stack storage.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr() as *mut std::ffi::c_void,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: `GetFileInformationByHandleEx` succeeded and initialized `info`.
    let info = unsafe { info.assume_init() };
    Some((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn open_reparse_safe_with(
    path: &Path,
    follow_symlinks: bool,
    make_opts: impl Fn(bool /*include_open_reparse_flag*/) -> OpenOptions,
    label: &str,
) -> Result<File> {
    let probe = make_opts(!follow_symlinks)
        .open(path)
        .map_err(|e| Error::io(format!("{label} `{}`", path.display()), e))?;
    if follow_symlinks {
        return Ok(probe);
    }

    let (is_reparse, is_surrogate, attrs) = file_reparse_status(&probe, path)?;
    if !is_reparse {
        return Ok(probe);
    }
    if is_surrogate {
        return Err(Error::invalid_path(format!(
            "refusing to follow symlink/reparse point `{}`",
            path.display()
        )));
    }

    // Non-surrogate reparse point (OneDrive Files On-Demand, CompactOS/WOF, NTFS dedup):
    // reopen WITHOUT `FILE_FLAG_OPEN_REPARSE_POINT` so Windows minifilters hydrate/decompress
    // normally, verifying FileIdInfo to close swap races.
    let probe_id = file_id_info(&probe);
    match make_opts(false).open(path) {
        Ok(hydrated) => {
            let hydrated_id = file_id_info(&hydrated);
            let same_file = match (probe_id, hydrated_id) {
                (Some(a), Some(b)) => a == b,
                _ => !std::fs::symlink_metadata(path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(true),
            };
            if !same_file {
                return Err(Error::invalid_path(format!(
                    "reparse point `{}` swapped to symlink during open",
                    path.display()
                )));
            }
            Ok(hydrated)
        }
        Err(e)
            if e.raw_os_error() == Some(ERROR_CANT_ACCESS_FILE_CODE)
                && (attrs
                    & (FILE_ATTRIBUTE_OFFLINE_FLAG
                        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG))
                    == 0 =>
        {
            // Non-surrogate reparse tag without an active minifilter (e.g., synthetic test tag):
            // `probe` is already open safely and verified non-surrogate.
            Ok(probe)
        }
        Err(e) => Err(Error::io(format!("{label} `{}`", path.display()), e)),
    }
}

fn open_read_windows_opt(path: &Path, follow_symlinks: bool, sequential: bool) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    open_reparse_safe_with(
        path,
        follow_symlinks,
        |open_reparse| {
            let mut flags = if sequential {
                FILE_FLAG_SEQUENTIAL_SCAN
            } else {
                0
            };
            if open_reparse {
                flags |= FILE_FLAG_OPEN_REPARSE_POINT;
            }
            let mut opts = OpenOptions::new();
            opts.read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            if flags != 0 {
                opts.custom_flags(flags);
            }
            opts
        },
        "open",
    )
}

pub(in crate::local) fn open_read_shared_opt(path: &Path, follow_symlinks: bool) -> Result<File> {
    open_read_windows_opt(path, follow_symlinks, false)
}

/// Open a file for sequential streaming reads (e.g. full-file hashing) with OS
/// prefetch/readahead hints while preserving shared access on Windows.
pub(in crate::local) fn open_read_sequential_opt(
    path: &Path,
    follow_symlinks: bool,
) -> Result<File> {
    open_read_windows_opt(path, follow_symlinks, true)
}

pub(in crate::local) fn open_write_shared(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    open_reparse_safe_with(
        path,
        false,
        |open_reparse| {
            let mut opts = OpenOptions::new();
            opts.write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            if open_reparse {
                opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            opts
        },
        "open part",
    )
}

pub(in crate::local) fn open_append_shared(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    open_reparse_safe_with(
        path,
        false,
        |open_reparse| {
            let mut opts = OpenOptions::new();
            opts.create(true)
                .append(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            if open_reparse {
                opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            opts
        },
        "open manifest",
    )
}

pub(in crate::local) fn create_staging_exclusive_for_rename(part_path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    };

    let make_opts = || {
        let mut opts = OpenOptions::new();
        opts.create_new(true)
            .access_mode(FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE);
        opts
    };
    match make_opts().open(part_path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(part_path);
            make_opts()
                .open(part_path)
                .map_err(|e| Error::io(format!("create staging `{}`", part_path.display()), e))
        }
        Err(e) => Err(Error::io(
            format!("create staging `{}`", part_path.display()),
            e,
        )),
    }
}

pub(in crate::local) fn copy_file_ex_to_staging(
    src_abs: &Path,
    part_path: &Path,
) -> std::result::Result<File, (Error, bool)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_NOT_SUPPORTED, ERROR_SHARING_VIOLATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        COPY_FILE_ALLOW_DECRYPTED_DESTINATION, COPY_FILE_FAIL_IF_EXISTS, CopyFileExW,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let src_w: Vec<u16> = to_os_path(src_abs)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = to_os_path(part_path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let flags = COPY_FILE_FAIL_IF_EXISTS | COPY_FILE_ALLOW_DECRYPTED_DESTINATION;

    for attempt in 0..2 {
        // SAFETY: `src_w` and `dst_w` are NUL-terminated UTF-16 paths valid for this call.
        let ok = unsafe {
            CopyFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                None,
                std::ptr::null(),
                std::ptr::null_mut(),
                flags,
            )
        };
        if ok != 0 {
            clear_readonly_if_windows(part_path);
            let f = open_reparse_safe_with(
                part_path,
                false,
                |open_reparse| {
                    let mut opts = OpenOptions::new();
                    opts.access_mode(FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES)
                        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
                    if open_reparse {
                        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                    }
                    opts
                },
                "open copied staging",
            )
            .map_err(|e| (e, false))?;
            return Ok(f);
        }
        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS) && attempt == 0 {
            let _ = std::fs::remove_file(part_path);
            continue;
        }
        let can_fallback = code == ERROR_SHARING_VIOLATION || code == ERROR_NOT_SUPPORTED;
        return Err((
            Error::io(
                format!(
                    "CopyFileExW `{}` -> `{}`",
                    src_abs.display(),
                    part_path.display()
                ),
                err,
            ),
            can_fallback,
        ));
    }
    unreachable!()
}

/// Perform an atomic NTFS rename (`ReplaceIfExists = replace`) directly on an already-open
/// staging handle (`FILE_GENERIC_WRITE | DELETE`), avoiding the extra `NtOpenFile` +
/// `NtClose` + AV mini-filter scan incurred by closing and calling `MoveFileExW`.
pub(in crate::local) fn try_rename_open_handle_windows(
    file: &File,
    final_path: &Path,
    replace: bool,
) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle,
    };

    let norm_final = to_os_path(final_path);
    let wide: Vec<u16> = norm_final
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let name_bytes = (wide.len().saturating_sub(1)) * std::mem::size_of::<u16>();
    let Ok(name_bytes_u32) = u32::try_from(name_bytes) else {
        return false;
    };

    const {
        assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<FILE_RENAME_INFO>());
    }
    let header_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let total_bytes = (header_offset + wide.len() * std::mem::size_of::<u16>())
        .max(std::mem::size_of::<FILE_RENAME_INFO>());
    let Ok(total_bytes_u32) = u32::try_from(total_bytes) else {
        return false;
    };

    let word_len = total_bytes.div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; word_len];
    let ptr = storage.as_mut_ptr() as *mut FILE_RENAME_INFO;

    // SAFETY: `storage` is zero-initialized, aligned to `align_of::<usize>() >= align_of::<FILE_RENAME_INFO>()`,
    // and sized to at least `max(size_of::<FILE_RENAME_INFO>(), header_offset + wide.len() * 2)` bytes.
    // Header fields are written via `addr_of_mut!` (avoiding intermediate `&mut FILE_RENAME_INFO`
    // references), `wide` fits inside the trailing `FileName` buffer, and `file.as_raw_handle()`
    // is a live Win32 file handle for the duration of `SetFileInformationByHandle`.
    unsafe {
        std::ptr::addr_of_mut!((*ptr).Anonymous.ReplaceIfExists).write(replace);
        std::ptr::addr_of_mut!((*ptr).RootDirectory).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*ptr).FileNameLength).write(name_bytes_u32);
        let dst_name = (storage.as_mut_ptr() as *mut u8).add(header_offset) as *mut u16;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst_name, wide.len());

        let ok = SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            storage.as_ptr() as *const std::ffi::c_void,
            total_bytes_u32,
        );
        ok != 0
    }
}

pub(in crate::local) fn atomic_replace(
    part_path: &Path,
    final_path: &Path,
    durable: bool,
    replace: bool,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_SHARING_VIOLATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let src_w: Vec<u16> = part_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = final_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut flags = if durable { MOVEFILE_WRITE_THROUGH } else { 0 };
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }

    let mut cleared_readonly = false;
    let mut delay_ms = 20u64;
    for attempt in 0..5 {
        // SAFETY: `src_w` and `dst_w` are NUL-terminated UTF-16 paths valid for this call.
        let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), flags) };
        if ok != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if !replace && (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) {
            return Err(Error::precondition_failed(format!(
                "destination `{}` already exists (precondition Absent)",
                final_path.display()
            )));
        }
        if replace && code == ERROR_ACCESS_DENIED && !cleared_readonly {
            cleared_readonly = true;
            clear_readonly_if_windows(final_path);
            continue;
        }
        if (code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED) && attempt < 4 {
            std::thread::sleep(Duration::from_millis(delay_ms));
            delay_ms *= 2;
            continue;
        }
        return Err(Error::io(
            format!(
                "MoveFileExW `{}` -> `{}` (original and staged file preserved)",
                part_path.display(),
                final_path.display()
            ),
            err,
        ));
    }
    unreachable!()
}

#[allow(clippy::permissions_set_readonly_false)]
pub(in crate::local) fn clear_readonly_if_windows(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

fn open_file_for_flush(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let open_rw = |open_reparse: bool| {
        let mut opts = OpenOptions::new();
        opts.write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        if open_reparse {
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        opts
    };
    match open_reparse_safe_with(path, false, open_rw, "open for durable flush") {
        Ok(f) => Ok(f),
        Err(err) if err.kind == rship_core::ErrorKind::PermissionDenied => {
            // `FlushFileBuffers` requires write access; if a moved/copied file is marked
            // read-only, temporarily clear the readonly bit to flush, then leave it intact.
            if let Ok(meta) = std::fs::symlink_metadata(path)
                && !meta.file_type().is_symlink()
                && meta.permissions().readonly()
            {
                let orig = meta.permissions();
                let mut writable = orig.clone();
                #[allow(clippy::permissions_set_readonly_false)]
                writable.set_readonly(false);
                if std::fs::set_permissions(path, writable).is_ok() {
                    let res =
                        open_reparse_safe_with(path, false, open_rw, "open for durable flush");
                    let _ = std::fs::set_permissions(path, orig);
                    return res;
                }
            }
            Err(err)
        }
        Err(err) => Err(err),
    }
}

pub(in crate::local) fn sync_file_durable(file: &File) -> std::io::Result<()> {
    file.sync_all()
}

/// Directory `fsync` is not available on Windows (NTFS journals directory metadata itself),
/// so this always reports "not synced".
pub(in crate::local) fn sync_dir(dir: &Path) -> Result<bool> {
    let _ = dir;
    Ok(false)
}

/// Durably sync a single committed file (`FlushFileBuffers` via `File::sync_all`).
/// Directories cannot be flushed on Windows, so `extra_dirs` is ignored and `0` directories
/// are reported.
pub(in crate::local) fn sync_file_and_parent(path: &Path, extra_dirs: &[PathBuf]) -> Result<u64> {
    let _ = extra_dirs;
    let file = open_file_for_flush(path)?;
    sync_file_durable(&file)
        .map_err(|e| Error::io(format!("FlushFileBuffers `{}`", path.display()), e))?;
    Ok(0)
}

/// Flush a batch of deferred local writes (`FsyncMode::Batch`) via bounded-parallel
/// `FlushFileBuffers` so NVMe/storage flush queues stay saturated instead of serializing
/// at queue depth 1.
pub(in crate::local) fn flush_pending_batch(
    root: &Path,
    files: &HashSet<PathBuf>,
    dirs: &HashSet<PathBuf>,
    opts: &super::BatchFlushOptions,
) -> Result<super::BatchSyncStats> {
    let _ = (root, dirs, opts);
    if files.is_empty() {
        return Ok(super::BatchSyncStats::default());
    }
    let file_list: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    let synced = super::parallel_sync_paths(&file_list, |file_path| {
        match open_file_for_flush(file_path) {
            Ok(f) => {
                sync_file_durable(&f).map_err(|e| {
                    Error::io(
                        format!("batch FlushFileBuffers `{}`", file_path.display()),
                        e,
                    )
                })?;
                Ok(true)
            }
            Err(e) if e.kind == rship_core::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    })?;
    Ok(super::BatchSyncStats {
        files: synced,
        dirs: 0,
        syncfs: false,
    })
}

pub(super) fn metadata_node_and_ctime(_meta: &std::fs::Metadata) -> (Option<NodeId>, Option<i64>) {
    (None, None)
}

pub(super) fn same_file_identity(
    a_path: &Path,
    a_meta: &std::fs::Metadata,
    b_path: &Path,
    b_meta: &std::fs::Metadata,
) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    };

    let open_meta = |p: &Path| {
        OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(to_os_path(p))
            .ok()
            .and_then(|f| {
                let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
                // SAFETY: `f.as_raw_handle()` is a valid handle and `info` is stack-allocated.
                let ok =
                    unsafe { GetFileInformationByHandle(f.as_raw_handle(), info.as_mut_ptr()) };
                if ok == 0 {
                    None
                } else {
                    // SAFETY: `GetFileInformationByHandle` succeeded.
                    Some(unsafe { info.assume_init() })
                }
            })
    };
    let (Some(ia), Some(ib)) = (open_meta(a_path), open_meta(b_path)) else {
        return false;
    };
    ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber
        && ia.nFileIndexHigh == ib.nFileIndexHigh
        && ia.nFileIndexLow == ib.nFileIndexLow
        && (a_meta.is_dir() || b_meta.is_dir() || ia.nNumberOfLinks == 1)
}

pub(in crate::local) fn probe_case_sensitivity(root: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    };

    let mut cur = root.to_path_buf();
    while !std::fs::metadata(to_os_path(&cur)).is_ok_and(|m| m.is_dir()) {
        if !cur.pop() {
            return false;
        }
    }
    let os_cur = to_os_path(&cur);
    if let Ok(dir) = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&os_cur)
    {
        let mut info = std::mem::MaybeUninit::<FILE_CASE_SENSITIVE_INFO>::zeroed();
        // SAFETY: `dir.as_raw_handle()` is a valid open directory handle and `info` is valid.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.as_raw_handle(),
                FileCaseSensitiveInfo,
                info.as_mut_ptr() as *mut std::ffi::c_void,
                std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
            )
        };
        if ok != 0 {
            // SAFETY: `GetFileInformationByHandleEx` succeeded.
            let info = unsafe { info.assume_init() };
            return (info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0;
        }
    }
    super::probe_dir_case_sensitive_readonly(&cur).unwrap_or(false)
}

pub(in crate::local) fn detect_mtime_granularity(path: &Path) -> Duration {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

    let mut cur = path.to_path_buf();
    while std::fs::metadata(to_os_path(&cur)).is_err() {
        if !cur.pop() {
            return Duration::from_millis(20);
        }
    }
    let wide: Vec<u16> = to_os_path(&cur)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut vol_root = vec![0u16; wide.len().max(1024)];
    // SAFETY: `wide` is NUL-terminated UTF-16 and `vol_root` has its stated capacity.
    let ok =
        unsafe { GetVolumePathNameW(wide.as_ptr(), vol_root.as_mut_ptr(), vol_root.len() as u32) };
    if ok == 0 {
        return Duration::from_millis(20);
    }
    let mut fs_name = [0u16; 64];
    // SAFETY: `vol_root` is NUL-terminated by `GetVolumePathNameW` and `fs_name` has 64 u16s.
    let ok = unsafe {
        GetVolumeInformationW(
            vol_root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Duration::from_millis(20);
    }
    let nul_pos = fs_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name.len());
    let name = String::from_utf16_lossy(&fs_name[..nul_pos]);
    super::fs_name_mtime_granularity(&name)
}

/// Apply Windows extended-length verbatim syntax (`\\?\` or `\\?\UNC\`) for long
/// absolute paths, normalizing `/` -> `\` and `.` / `..` components purely in UTF-16
/// (preserving unpaired UTF-16 surrogates without `to_string_lossy()`).
pub fn to_os_path(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let raw_w: Vec<u16> = path.as_os_str().encode_wide().collect();
    const VERBATIM: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const DEVICE: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16];
    if raw_w.starts_with(&VERBATIM) || raw_w.starts_with(&DEVICE) || !path.is_absolute() {
        return path.to_path_buf();
    }

    enum RootKind {
        Disk(u16),
        Unc(Vec<u16>, Vec<u16>),
    }

    let mut root_kind: Option<RootKind> = None;
    let mut segs: Vec<Vec<u16>> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(pre) => match pre.kind() {
                Prefix::Verbatim(_)
                | Prefix::VerbatimUNC(_, _)
                | Prefix::VerbatimDisk(_)
                | Prefix::DeviceNS(_) => return path.to_path_buf(),
                Prefix::Disk(drive) => {
                    root_kind = Some(RootKind::Disk(u16::from(drive)));
                }
                Prefix::UNC(server, share) => {
                    root_kind = Some(RootKind::Unc(
                        server.encode_wide().collect(),
                        share.encode_wide().collect(),
                    ));
                }
            },
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                segs.pop();
            }
            Component::Normal(s) => {
                segs.push(s.encode_wide().collect());
            }
        }
    }

    let Some(root_kind) = root_kind else {
        return path.to_path_buf();
    };

    let mut norm_w: Vec<u16> = Vec::with_capacity(raw_w.len() + 8);
    let is_unc = match root_kind {
        RootKind::Disk(drive) => {
            norm_w.push(drive);
            norm_w.push(b':' as u16);
            norm_w.push(b'\\' as u16);
            for (i, seg) in segs.iter().enumerate() {
                if i > 0 {
                    norm_w.push(b'\\' as u16);
                }
                norm_w.extend_from_slice(seg);
            }
            false
        }
        RootKind::Unc(server, share) => {
            norm_w.push(b'\\' as u16);
            norm_w.push(b'\\' as u16);
            norm_w.extend_from_slice(&server);
            norm_w.push(b'\\' as u16);
            norm_w.extend_from_slice(&share);
            for seg in &segs {
                norm_w.push(b'\\' as u16);
                norm_w.extend_from_slice(seg);
            }
            true
        }
    };

    if norm_w.len() < 240 {
        return PathBuf::from(std::ffi::OsString::from_wide(&norm_w));
    }

    let mut out_w: Vec<u16> = Vec::with_capacity(norm_w.len() + 8);
    if is_unc {
        const VERBATIM_UNC: [u16; 8] = [
            b'\\' as u16,
            b'\\' as u16,
            b'?' as u16,
            b'\\' as u16,
            b'U' as u16,
            b'N' as u16,
            b'C' as u16,
            b'\\' as u16,
        ];
        out_w.extend_from_slice(&VERBATIM_UNC);
        out_w.extend_from_slice(&norm_w[2..]);
    } else {
        out_w.extend_from_slice(&VERBATIM);
        out_w.extend_from_slice(&norm_w);
    }
    PathBuf::from(std::ffi::OsString::from_wide(&out_w))
}
