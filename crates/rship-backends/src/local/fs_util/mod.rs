//! OS-specific filesystem helpers for [`super::LocalBackend`]:
//! - Stateless `LocalSeekableFile` (`pread` on Unix, `ReOpenFile`-pinned handles on Windows).
//! - OSDI-2014 ordered atomic staging, RAII `StagingGuard`, shared `commit_staging_file`,
//!   in-handle NTFS rename, and `MoveFileExW` / `renameat2(RENAME_NOREPLACE)` / `link`+`unlink`.
//! - Symlink-escape containment defense, disk quota queries, FAT32 detection, and
//!   non-polluting case-sensitivity probing.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

pub use platform::to_os_path;
pub(super) use platform::{
    atomic_replace, clear_readonly_if_windows, create_staging_exclusive_for_rename,
    detect_mtime_granularity, flush_pending_batch, local_disk_quota, open_append_shared,
    open_read_sequential_opt, open_read_shared_opt, open_write_shared, probe_case_sensitivity,
    sync_dir, sync_file_and_parent, sync_file_durable,
};
#[cfg(all(unix, test))]
pub(super) use unix::is_fullfsync_unsupported;
#[cfg(windows)]
pub(super) use windows::{copy_file_ex_to_staging, try_rename_open_handle_windows};
#[cfg(all(windows, test))]
pub(super) use windows::{format_disk_free_space_path, is_reparse_tag_name_surrogate};

use async_trait::async_trait;
use platform::PlatformReadHandle;
use rship_core::buffer::PooledSlice;
use rship_core::clock::{system_time_to_unix_nanos, unix_nanos_to_system_time};
use rship_core::encoding::EncodingMode;
use rship_core::path::RelPath;
use rship_core::source::SeekableSource;
use rship_core::types::{Entry, EntryKind};
use rship_core::{Error, Result};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// -----------------------------------------------------------------------------
// Stateless `LocalSeekableFile`
// -----------------------------------------------------------------------------

pub(super) struct LocalSeekableFile {
    handle: PlatformReadHandle,
    len: u64,
    path: PathBuf,
}

impl LocalSeekableFile {
    pub(super) fn new(file: File, len: u64, path: PathBuf, follow_symlinks: bool) -> Self {
        Self {
            handle: PlatformReadHandle::new(file, follow_symlinks),
            len,
            path,
        }
    }
}

#[async_trait]
impl SeekableSource for LocalSeekableFile {
    fn total_len(&self) -> u64 {
        self.len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() || offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        let handle = self.handle.clone();
        let path = self.path.clone();
        let tmp = tokio::task::spawn_blocking(move || {
            let mut local = vec![0u8; want];
            let n = handle.read_exact_at(offset, &mut local, &path)?;
            local.truncate(n);
            Ok::<_, Error>(local)
        })
        .await
        .map_err(|e| Error::protocol(format!("read_at join: {e}")))??;
        buf[..tmp.len()].copy_from_slice(&tmp);
        Ok(tmp.len())
    }

    async fn read_into_slice(
        &self,
        offset: u64,
        mut slice: PooledSlice,
        want: usize,
    ) -> Result<(PooledSlice, usize)> {
        if want == 0 || offset >= self.len {
            return Ok((slice, 0));
        }
        let want = want.min((self.len - offset) as usize);
        let handle = self.handle.clone();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut filled = 0usize;
            let dst = &mut slice.spare_mut()[..want];
            while filled < want {
                let n = handle.read_exact_at(offset + filled as u64, &mut dst[filled..], &path)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            Ok::<_, Error>((slice, filled))
        })
        .await
        .map_err(|e| Error::protocol(format!("read_into_slice join: {e}")))?
    }
}

// -----------------------------------------------------------------------------
// Staging & Preconditions
// -----------------------------------------------------------------------------

pub(super) struct StagingGuard {
    part_path: Option<PathBuf>,
    manifest_path: Option<PathBuf>,
}

impl StagingGuard {
    pub(super) fn new(part_path: PathBuf) -> Self {
        Self {
            part_path: Some(part_path),
            manifest_path: None,
        }
    }

    pub(super) fn with_manifest(part_path: PathBuf, manifest_path: PathBuf) -> Self {
        Self {
            part_path: Some(part_path),
            manifest_path: Some(manifest_path),
        }
    }

    pub(super) fn disarmed() -> Self {
        Self {
            part_path: None,
            manifest_path: None,
        }
    }

    pub(super) fn arm(&mut self, part_path: PathBuf, manifest_path: PathBuf) {
        self.part_path = Some(part_path);
        self.manifest_path = Some(manifest_path);
    }

    pub(super) fn disarm(&mut self) {
        self.part_path = None;
        self.manifest_path = None;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(p) = self.part_path.take() {
            let _ = std::fs::remove_file(p);
        }
        if let Some(m) = self.manifest_path.take() {
            let _ = std::fs::remove_file(m);
        }
    }
}

pub(super) fn staging_manifest_path(part_path: &Path) -> PathBuf {
    let mut s = part_path.as_os_str().to_os_string();
    s.push(".parts");
    PathBuf::from(s)
}

pub(super) fn create_staging_exclusive(part_path: &Path) -> Result<File> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part_path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(part_path);
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(part_path)
                .map_err(|e| Error::io(format!("create staging `{}`", part_path.display()), e))
        }
        Err(e) => Err(Error::io(
            format!("create staging `{}`", part_path.display()),
            e,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_staging_file(
    file: File,
    part_path: &Path,
    final_path: &Path,
    src_mtime_ns: i64,
    precondition: &rship_core::state::DstPrecondition,
    durable: bool,
    root: &Path,
    dst_rel: RelPath,
    encoding: EncodingMode,
    use_in_handle_rename: bool,
) -> Result<Entry> {
    let mtime = unix_nanos_to_system_time(src_mtime_ns);
    let _ = file.set_modified(mtime);

    check_dst_precondition(final_path, precondition)?;

    if durable {
        sync_file_durable(&file)
            .map_err(|e| Error::io(format!("fsync staging `{}`", part_path.display()), e))?;
    }

    let meta = file
        .metadata()
        .map_err(|e| Error::io(format!("stat staging `{}`", part_path.display()), e))?;

    let replace = !matches!(precondition, rship_core::state::DstPrecondition::Absent);

    #[cfg(windows)]
    {
        if !durable && use_in_handle_rename {
            let renamed_in_handle = try_rename_open_handle_windows(&file, final_path, replace);
            drop(file);
            if !renamed_in_handle {
                atomic_replace(part_path, final_path, false, replace)?;
            }
        } else {
            drop(file);
            atomic_replace(part_path, final_path, durable, replace)?;
        }
    }
    #[cfg(not(windows))]
    {
        let _ = use_in_handle_rename;
        drop(file);
        atomic_replace(part_path, final_path, durable, replace)?;
    }

    let raw_override = entry_raw_override(root, final_path, &dst_rel, encoding);
    metadata_to_entry(&meta, raw_override, dst_rel)
        .ok_or_else(|| Error::protocol("committed file disappeared"))
}

/// Verify destination [`DstPrecondition`] immediately before atomic publication.
pub(super) fn check_dst_precondition(
    final_path: &Path,
    precondition: &rship_core::state::DstPrecondition,
) -> Result<()> {
    use rship_core::state::DstPrecondition;

    match precondition {
        DstPrecondition::Any => Ok(()),
        DstPrecondition::Absent => match std::fs::symlink_metadata(final_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(Error::precondition_failed(format!(
                "destination `{}` already exists (precondition Absent)",
                final_path.display()
            ))),
            Err(e) => Err(Error::io(
                format!(
                    "stat destination `{}` for Absent precondition",
                    final_path.display()
                ),
                e,
            )),
        },
        DstPrecondition::Existing {
            node_id,
            size,
            mtime_ns,
            ..
        } => match std::fs::symlink_metadata(final_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(Error::precondition_failed(format!(
                        "destination `{}` is no longer a regular file (precondition Existing)",
                        final_path.display()
                    )));
                }
                let (actual_node_id, _) = platform::metadata_node_and_ctime(&meta);
                if let (Some(expected_nid), Some(actual_nid)) =
                    (node_id.as_ref(), actual_node_id.as_ref())
                    && actual_nid != expected_nid
                {
                    return Err(Error::precondition_failed(format!(
                        "destination `{}` inode modified concurrently (expected node_id={expected_nid}, actual node_id={actual_nid})",
                        final_path.display()
                    )));
                }
                let actual_size = meta.len();
                let actual_mtime_ns = meta.modified().map(system_time_to_unix_nanos).unwrap_or(0);
                if actual_size != *size || actual_mtime_ns != *mtime_ns {
                    return Err(Error::precondition_failed(format!(
                        "destination `{}` modified concurrently (expected size={size} mtime_ns={mtime_ns}, actual size={actual_size} mtime_ns={actual_mtime_ns})",
                        final_path.display()
                    )));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::precondition_failed(format!(
                    "destination `{}` disappeared concurrently (precondition Existing)",
                    final_path.display()
                )))
            }
            Err(e) => Err(Error::io(
                format!(
                    "stat destination `{}` for Existing precondition",
                    final_path.display()
                ),
                e,
            )),
        },
        _ => Ok(()),
    }
}

// -----------------------------------------------------------------------------
// Path, Metadata & Case Sensitivity Helpers
// -----------------------------------------------------------------------------

pub(super) fn metadata_to_entry(
    meta: &std::fs::Metadata,
    raw_path: Option<Box<str>>,
    nfc_path: RelPath,
) -> Option<Entry> {
    let ft = meta.file_type();
    let kind = if ft.is_file() {
        EntryKind::File
    } else if ft.is_dir() {
        EntryKind::Directory
    } else if ft.is_symlink() {
        EntryKind::Symlink
    } else {
        return None;
    };

    let mtime_ns = meta.modified().map(system_time_to_unix_nanos).unwrap_or(0);
    let (node_id, ctime_ns) = platform::metadata_node_and_ctime(meta);

    Some(Entry {
        node_id,
        parent_id: None,
        raw_path,
        nfc_path,
        kind,
        size: if kind == EntryKind::File {
            meta.len()
        } else {
            0
        },
        mtime_ns,
        ctime_ns,
        etag: None,
        checksum: None,
    })
}

pub(super) fn path_to_slash_utf8(rel: &Path) -> Option<String> {
    if let Some(s) = rel.to_str() {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Some(String::new());
        }
        // Single-pass fast path: normal relative paths from `strip_prefix` contain no
        // `.`, `..`, leading/trailing/duplicate separators, or Windows `:` prefixes.
        let mut clean = true;
        let mut has_backslash = false;
        let mut seg_start = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            if cfg!(windows) && b == b':' {
                clean = false;
                break;
            }
            let is_sep = if cfg!(windows) {
                if b == b'\\' {
                    has_backslash = true;
                    true
                } else {
                    b == b'/'
                }
            } else {
                b == b'/'
            };
            if is_sep {
                let seg = &bytes[seg_start..i];
                if seg.is_empty() || seg == b"." || seg == b".." {
                    clean = false;
                    break;
                }
                seg_start = i + 1;
            }
        }
        if clean {
            let last = &bytes[seg_start..];
            if last.is_empty() || last == b"." || last == b".." {
                clean = false;
            }
        }
        if clean {
            if !has_backslash {
                return Some(s.to_owned());
            }
            let mut out = String::with_capacity(s.len());
            for seg in s.split('\\') {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(seg);
            }
            return Some(out);
        }
    }

    let mut out = String::with_capacity(rel.as_os_str().len());
    for comp in rel.components() {
        if let std::path::Component::Normal(s) = comp {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(s.to_str()?);
        }
    }
    Some(out)
}

pub(super) fn is_windows_reserved_name_strict(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "COM\u{00B9}"
            | "COM\u{00B2}"
            | "COM\u{00B3}"
            | "LPT\u{00B9}"
            | "LPT\u{00B2}"
            | "LPT\u{00B3}"
    )
}

pub(super) fn encode_local_segment(mode: EncodingMode, seg: &str) -> String {
    match mode {
        EncodingMode::Identity => seg.to_string(),
        EncodingMode::WindowsSafe => {
            let mut out = mode.encode_segment(seg);
            if is_windows_reserved_name_strict(seg)
                && !rship_core::encoding::is_windows_reserved_name(seg)
                && let Some(first) = out.chars().next()
                && first != '^'
            {
                let escaped = format!("^{:02X}", first as u32);
                out.replace_range(..first.len_utf8(), &escaped);
            }
            out
        }
    }
}

pub(super) fn decode_local_rel_path(mode: EncodingMode, disk_rel: &str) -> Result<String> {
    if mode == EncodingMode::Identity || disk_rel.is_empty() {
        return Ok(disk_rel.to_string());
    }
    let mut out = String::with_capacity(disk_rel.len());
    for seg in disk_rel.split('/') {
        if seg.is_empty() {
            continue;
        }
        let decoded = mode.decode_segment(seg)?;
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains(['/', '\\', '\0'])
        {
            return Err(Error::invalid_path(format!(
                "decoded segment `{decoded}` from `{seg}` is illegal"
            )));
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&decoded);
    }
    Ok(out)
}

pub(super) fn entry_raw_override(
    root: &Path,
    final_path: &Path,
    nfc_path: &RelPath,
    encoding: EncodingMode,
) -> Option<Box<str>> {
    if encoding == EncodingMode::Identity && nfc_path.as_str().is_ascii() {
        return None;
    }
    let rel_os = strip_root_prefix(final_path, root)?;
    let disk_rel = path_to_slash_utf8(&rel_os)?;
    let decoded_raw = decode_local_rel_path(encoding, &disk_rel).ok()?;
    rship_core::types::raw_path_override(nfc_path, &decoded_raw)
}

/// Blocking body of `LocalBackend::resolve_write_path`: join `rel` onto `root`, replacing
/// each component that is missing under its NFC (encoded) spelling with an existing sibling
/// whose name normalizes to the same NFC string. See that method for when lookups happen.
pub(super) fn resolve_existing_spelling(
    root: &Path,
    encoding: EncodingMode,
    rel: &RelPath,
    leaf_may_exist: bool,
) -> PathBuf {
    let segs: Vec<&str> = rel.segments().collect();
    let mut p = root.to_path_buf();
    let mut parent_exists = true;
    for (i, seg) in segs.iter().enumerate() {
        let enc = encode_local_segment(encoding, seg);
        let is_leaf = i + 1 == segs.len();
        let lookup = parent_exists && !enc.is_ascii() && (!is_leaf || leaf_may_exist);
        if !lookup {
            p.push(&enc);
            continue;
        }
        let cand = p.join(&enc);
        match std::fs::symlink_metadata(to_os_path(&cand)) {
            Ok(_) => p = cand,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match find_normalization_twin(&p, &enc) {
                    Some(twin) => p.push(twin),
                    None => {
                        p = cand;
                        parent_exists = false;
                    }
                }
            }
            Err(_) => p = cand,
        }
    }
    to_os_path(&p)
}

/// Find an entry of `dir` whose name differs from `name` only by Unicode normalization.
fn find_normalization_twin(dir: &Path, name: &str) -> Option<std::ffi::OsString> {
    let want = RelPath::parse(name).ok()?;
    let rd = std::fs::read_dir(to_os_path(dir)).ok()?;
    for entry in rd.flatten() {
        let os_name = entry.file_name();
        if let Some(s) = os_name.to_str()
            && !s.is_ascii()
            && s != name
            && RelPath::parse(s).is_ok_and(|r| r == want)
        {
            return Some(os_name);
        }
    }
    None
}

/// Strip Windows verbatim prefix (`\\?\UNC\` -> `\\`, `\\?\` -> ``) for prefix comparison.
fn strip_windows_verbatim(s: &str) -> std::borrow::Cow<'_, str> {
    if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        std::borrow::Cow::Owned(format!(r"\\{unc}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        std::borrow::Cow::Borrowed(rest)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// Verbatim-aware `path.strip_prefix(root)` that succeeds even when one path carries
/// Windows extended-length `\\?\` or `\\?\UNC\` syntax and the other does not.
pub(super) fn strip_root_prefix(path: &Path, root: &Path) -> Option<PathBuf> {
    if let Ok(rel) = path.strip_prefix(root) {
        return Some(rel.to_path_buf());
    }
    let p_str = path.to_string_lossy();
    let r_str = root.to_string_lossy();
    let p_norm = strip_windows_verbatim(&p_str);
    let r_norm = strip_windows_verbatim(&r_str);
    Path::new(p_norm.as_ref())
        .strip_prefix(Path::new(r_norm.as_ref()))
        .ok()
        .map(Path::to_path_buf)
}

/// Canonicalize `path` if it exists, or canonicalize its deepest existing ancestor and
/// re-append the non-existent tail components so `--dry-run` / pre-creation overlap checks
/// match post-creation canonical paths across symlinks (e.g. macOS `/tmp` -> `/private/tmp`).
pub(super) fn canonicalize_deepest_ancestor(path: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(canon) = std::fs::canonicalize(to_os_path(cur)) {
            let mut out = canon;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        match (cur.file_name(), cur.parent()) {
            (Some(name), Some(parent)) if parent != cur => {
                tail.push(name.to_os_string());
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

pub(super) fn cache_verified_dir(cache: &StdMutex<HashSet<PathBuf>>, dir: &Path) {
    let mut g = crate::common::lock_unpoisoned(cache);
    if g.len() >= 16_384 {
        g.clear();
    }
    g.insert(dir.to_path_buf());
}

pub(super) fn ensure_no_symlink_escape_cached(
    root: &Path,
    target: &Path,
    cache: &StdMutex<HashSet<PathBuf>>,
    skip_leaf_check: bool,
) -> Result<bool> {
    if let Some(parent) = target.parent()
        && crate::common::lock_unpoisoned(cache).contains(parent)
    {
        if !skip_leaf_check {
            match std::fs::symlink_metadata(to_os_path(target)) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(Error::invalid_path(format!(
                        "refusing operation through symlink `{}` (is_last=true)",
                        target.display()
                    )));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::io(
                        format!("symlink check `{}`", target.display()),
                        e,
                    ));
                }
            }
        }
        return Ok(true);
    }

    let parent_exists = ensure_no_symlink_escape(root, target)?;
    if parent_exists && let Some(parent) = target.parent() {
        cache_verified_dir(cache, parent);
    }
    Ok(parent_exists)
}

/// Refuse traversing any planted symlink component under `root`.
/// Returns `Ok(true)` if the immediate parent directory of `target` was already
/// verified to exist as a real directory.
pub(super) fn ensure_no_symlink_escape(root: &Path, target: &Path) -> Result<bool> {
    let rel = strip_root_prefix(target, root).ok_or_else(|| {
        Error::invalid_path(format!(
            "target `{}` escapes backend root `{}`",
            target.display(),
            root.display()
        ))
    })?;

    let mut cur = root.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    let mut parent_is_dir = comps.len() <= 1 && to_os_path(root).is_dir();
    for (idx, comp) in comps.iter().enumerate() {
        match comp {
            std::path::Component::Normal(seg) => {
                cur.push(seg);
                let is_last = idx + 1 == comps.len();
                let is_parent = idx + 2 == comps.len();
                match std::fs::symlink_metadata(to_os_path(&cur)) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(Error::invalid_path(format!(
                                "refusing operation through symlink `{}` (is_last={is_last})",
                                cur.display()
                            )));
                        }
                        if is_parent {
                            parent_is_dir = meta.is_dir();
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        break;
                    }
                    Err(e) => {
                        return Err(Error::io(format!("symlink check `{}`", cur.display()), e));
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => {
                return Err(Error::invalid_path(format!(
                    "illegal path component in `{}`",
                    target.display()
                )));
            }
        }
    }
    Ok(parent_is_dir)
}

/// Options for [`flush_pending_batch`].
#[derive(Debug, Clone)]
pub(super) struct BatchFlushOptions {
    /// Use one filesystem-wide `syncfs(2)` where the platform has it (Linux). When `false`,
    /// every pending file and directory is synced individually (the macOS / BSD path).
    // Only Linux has `syncfs(2)`; elsewhere the per-path fallback ignores this flag.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) allow_syncfs: bool,
    /// Test hook: pretend `syncfs(2)` failed with this `errno` instead of calling it.
    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) syncfs_errno: Option<i32>,
}

impl Default for BatchFlushOptions {
    fn default() -> Self {
        Self {
            allow_syncfs: true,
            #[cfg(test)]
            syncfs_errno: None,
        }
    }
}

/// What one [`flush_pending_batch`] call synced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct BatchSyncStats {
    /// Files synced individually (`fsync` / `FlushFileBuffers`).
    pub(super) files: u64,
    /// Directories synced individually.
    pub(super) dirs: u64,
    /// Whether one filesystem-wide `syncfs(2)` covered the whole batch.
    pub(super) syncfs: bool,
}

/// Create `dir` and any missing ancestors, recording every directory this call created in
/// `created` so a later durable commit can `fsync` the parents that hold their entries
/// (see [`created_ancestors`]).
pub(super) fn create_dir_all_tracked(dir: &Path, created: &StdMutex<CreatedDirs>) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(p) = cur {
        match std::fs::symlink_metadata(p) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(p.to_path_buf());
                cur = p.parent();
            }
            Err(_) => break,
        }
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::io(format!("create directory `{}`", dir.display()), e))?;
    if !missing.is_empty() {
        let mut g = crate::common::lock_unpoisoned(created);
        for p in missing {
            g.insert(p);
        }
    }
    Ok(())
}

/// Directories created by a [`super::LocalBackend`] whose entries in their parent directory
/// have not been made durable yet. Bounded: past [`CREATED_DIRS_CAP`] entries the set stops
/// tracking and every durable commit syncs all ancestors up to the root instead.
#[derive(Debug, Default)]
pub(super) struct CreatedDirs {
    dirs: HashSet<PathBuf>,
    overflowed: bool,
}

const CREATED_DIRS_CAP: usize = 65_536;

impl CreatedDirs {
    fn insert(&mut self, dir: PathBuf) {
        if self.overflowed {
            return;
        }
        if self.dirs.len() >= CREATED_DIRS_CAP {
            self.dirs.clear();
            self.overflowed = true;
            return;
        }
        self.dirs.insert(dir);
    }

    /// Forget every tracked directory (after a filesystem-wide flush made them durable).
    pub(super) fn clear(&mut self) {
        self.dirs.clear();
        self.overflowed = false;
    }
}

/// Return, deepest first, the directories between `file` and `root` (inclusive) that this
/// backend created and whose entries are not yet durable. Syncing each one's parent (see
/// [`entry_parents`]) makes the whole chain durable; call [`forget_created_dirs`] once that
/// succeeded.
pub(super) fn created_ancestors(
    root: &Path,
    file: &Path,
    created: &StdMutex<CreatedDirs>,
) -> Vec<PathBuf> {
    let g = crate::common::lock_unpoisoned(created);
    if g.dirs.is_empty() && !g.overflowed {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = file.parent();
    while let Some(dir) = cur {
        if !dir.starts_with(root) {
            break;
        }
        if g.overflowed || g.dirs.contains(dir) {
            out.push(dir.to_path_buf());
        }
        if dir == root {
            break;
        }
        cur = dir.parent();
    }
    out
}

/// Stop tracking `dirs` (their entries were just synced).
pub(super) fn forget_created_dirs(created: &StdMutex<CreatedDirs>, dirs: &[PathBuf]) {
    if dirs.is_empty() {
        return;
    }
    let mut g = crate::common::lock_unpoisoned(created);
    for d in dirs {
        g.dirs.remove(d);
    }
}

/// Parent directories holding the entries of `created` (deduplicated, deepest first).
pub(super) fn entry_parents(created: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::with_capacity(created.len());
    for d in created {
        if let Some(p) = d.parent()
            && !out.iter().any(|x| x == p)
        {
            out.push(p.to_path_buf());
        }
    }
    out
}

pub(super) fn parallel_sync_paths<F>(paths: &[&Path], sync_one: F) -> Result<u64>
where
    F: Fn(&Path) -> Result<bool> + Sync,
{
    if paths.is_empty() {
        return Ok(0);
    }
    if paths.len() == 1 {
        return Ok(u64::from(sync_one(paths[0])?));
    }

    let max_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .clamp(4, 16);
    let workers = paths.len().min(max_workers);
    let next = AtomicUsize::new(0);
    let synced = AtomicU64::new(0);
    let failed = AtomicBool::new(false);
    let first_err: StdMutex<Option<Error>> = StdMutex::new(None);

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = paths.get(idx) else {
                        break;
                    };
                    match sync_one(path) {
                        Ok(true) => {
                            synced.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(e) => {
                            failed.store(true, Ordering::Relaxed);
                            let mut slot = crate::common::lock_unpoisoned(&first_err);
                            if slot.is_none() {
                                *slot = Some(e);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });

    if let Some(err) = first_err.into_inner().unwrap_or_else(|e| e.into_inner()) {
        return Err(err);
    }
    Ok(synced.load(Ordering::Relaxed))
}

#[cfg(any(
    windows,
    test,
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub(super) fn fs_name_mtime_granularity(fs_name: &str) -> std::time::Duration {
    let upper = fs_name.trim().to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "FAT" | "FAT12" | "FAT16" | "FAT32" | "MSDOS" | "VFAT"
    ) {
        std::time::Duration::from_secs(2)
    } else if cfg!(windows) {
        std::time::Duration::from_millis(20)
    } else {
        std::time::Duration::from_millis(10)
    }
}

/// Non-polluting, read-only case-sensitivity probe using existing directory entries.
/// Never creates or deletes any file on disk.
pub(super) fn probe_dir_case_sensitive_readonly(dir: &Path) -> Option<bool> {
    let rd = std::fs::read_dir(to_os_path(dir)).ok()?;
    for entry in rd.flatten().take(32) {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == "." || name_str == ".." {
            continue;
        }
        let Some((idx, ch)) = name_str
            .char_indices()
            .find(|(_, c)| c.is_ascii_alphabetic())
        else {
            continue;
        };
        let toggled = if ch.is_ascii_lowercase() {
            ch.to_ascii_uppercase()
        } else {
            ch.to_ascii_lowercase()
        };
        let mut alt_name = String::with_capacity(name_str.len());
        alt_name.push_str(&name_str[..idx]);
        alt_name.push(toggled);
        alt_name.push_str(&name_str[idx + ch.len_utf8()..]);

        let orig_path = dir.join(&name);
        let alt_path = dir.join(&alt_name);
        let Ok(orig_meta) = std::fs::symlink_metadata(to_os_path(&orig_path)) else {
            continue;
        };
        match std::fs::symlink_metadata(to_os_path(&alt_path)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(true),
            Ok(alt_meta) => {
                if platform::same_file_identity(&orig_path, &orig_meta, &alt_path, &alt_meta) {
                    return Some(false);
                }
            }
            Err(_) => {}
        }
    }
    None
}
