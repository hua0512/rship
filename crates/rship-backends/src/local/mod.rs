//! Cross-platform local filesystem backend implementing `StorageBackend`.
//!
//! Highlights:
//! - Streaming directory walk via bounded `mpsc::channel(256)` (never loads trees in RAM).
//! - Skips `.rship.part.*` staging files and Unix special files (FIFOs, sockets, devices)
//!   via `symlink_metadata()` before ever opening a file descriptor.
//! - Stateless `SeekableSource` (`pread` on Unix; independent `FILE_SHARE_READ|WRITE|DELETE`
//!   handles on Windows).
//! - OSDI-2014 ordered atomic commit:
//!   `write(.rship.part.<op_id>) -> set_modified(mtime) -> sync_all() -> close -> atomic rename / MoveFileExW -> parent.sync_all()`.
//! - Bijective Windows-safe filename encoding (when enabled) + `\\?\` / `\\?\UNC\` long-path support.

mod copy;
mod durability;
mod fs_util;
#[cfg(test)]
mod tests;
mod upload;
mod walk;

pub use fs_util::to_os_path;

use crate::common::{crc32c_update, crc64_nvme_update};
use async_trait::async_trait;
use durability::DurabilityTracker;
use fs_util::{
    BatchFlushOptions, LocalSeekableFile, canonicalize_deepest_ancestor, clear_readonly_if_windows,
    detect_mtime_granularity, encode_local_segment, ensure_no_symlink_escape, entry_raw_override,
    local_disk_quota, metadata_to_entry, open_read_sequential_opt, open_read_shared_opt,
    probe_case_sensitivity, strip_root_prefix,
};
use md5::Md5;
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::encoding::EncodingMode;
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource, MemorySource};
use rship_core::state::OperationRecord;
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, FsyncMode, HashKind,
    UploadTopology,
};
use rship_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

pub(super) const PART_FILE_PREFIX: &str = ".rship.part.";
const DEFAULT_SINGLE_SHOT_MAX: u64 = 64 * 1024 * 1024; // 64 MiB
const DEFAULT_LOCAL_CHUNK: u64 = 32 * 1024 * 1024; // 32 MiB
const SMALL_SINGLE_SHOT_INLINE_MAX: u64 = 256 * 1024; // 256 KiB
const SMALL_READ_MAX: usize = 64 * 1024; // 64 KiB

/// Pure-Rust FIPS 180-1 SHA-1 (zero external crate dependencies).
struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self
            .total_bits
            .wrapping_add((data.len() as u64).wrapping_mul(8));
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().expect("64-byte block");
            Self::compress(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        let total_bits = self.total_bits;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::compress(&mut self.state, &self.buf);
        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        hex::encode(out)
    }
}

enum HashAcc {
    Sha256(Sha256),
    Sha1(Sha1),
    Md5(Md5),
    Crc32c(u32),
    Crc64Nvme(u64),
}

impl HashAcc {
    fn new(kind: HashKind) -> Option<Self> {
        match kind {
            HashKind::Sha256 => Some(Self::Sha256(Sha256::new())),
            HashKind::Sha1 => Some(Self::Sha1(Sha1::new())),
            HashKind::Md5 => Some(Self::Md5(Md5::new())),
            HashKind::Crc32c => Some(Self::Crc32c(0xFFFF_FFFF)),
            HashKind::Crc64Nvme => Some(Self::Crc64Nvme(u64::MAX)),
            _ => None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha1(h) => h.update(data),
            Self::Md5(h) => h.update(data),
            Self::Crc32c(crc) => *crc = crc32c_update(*crc, data),
            Self::Crc64Nvme(crc) => *crc = crc64_nvme_update(*crc, data),
        }
    }

    fn finalize_hex(self) -> String {
        match self {
            Self::Sha256(h) => hex::encode(h.finalize()),
            Self::Sha1(h) => h.finalize_hex(),
            Self::Md5(h) => hex::encode(h.finalize()),
            Self::Crc32c(crc) => format!("{:08x}", !crc),
            Self::Crc64Nvme(crc) => format!("{:016x}", !crc),
        }
    }
}

fn normalize_abs_root(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        to_os_path(&path)
    }
    #[cfg(not(windows))]
    {
        use std::path::Component;
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Prefix(p) => out.push(p.as_os_str()),
                Component::RootDir => out.push(comp.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !out.as_os_str().is_empty() && out != Path::new("/") {
                        out.pop();
                    }
                }
                Component::Normal(s) => out.push(s),
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct LocalBackend {
    name: String,
    root: PathBuf,
    encoding: EncodingMode,
    case_sensitive: bool,
    mtime_granularity: Duration,
    follow_symlinks: bool,
    single_shot_max_bytes: u64,
    default_chunk_size: u64,
    cached_endpoint_id: Arc<OnceLock<String>>,
    /// Bounded cache of verified non-symlink parent directories under `root` (and
    /// source roots during native local fast-copy), eliminating repeated ancestor
    /// `symlink_metadata` walks on thousands of sibling files. Cleared on `delete`/`rename`.
    verified_dirs: Arc<StdMutex<HashSet<PathBuf>>>,
    /// `--fsync` policy state: deferred batch flushes, newly created directories, telemetry.
    durability: Arc<DurabilityTracker>,
}

impl LocalBackend {
    pub fn new(name: impl Into<String>, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let raw_abs = if root.is_absolute() {
            root
        } else {
            std::env::current_dir()
                .map_err(|e| Error::io("get current_dir", e))?
                .join(root)
        };
        let abs = normalize_abs_root(raw_abs);
        let case_sensitive = probe_case_sensitivity(&abs);
        let mtime_granularity = detect_mtime_granularity(&abs);
        let cached_endpoint_id = Arc::new(OnceLock::new());
        if let Ok(canonical) = std::fs::canonicalize(to_os_path(&abs)) {
            let _ = cached_endpoint_id.set(format!("local://{}", canonical.display()));
        }
        Ok(Self {
            name: name.into(),
            encoding: EncodingMode::Identity,
            case_sensitive,
            mtime_granularity,
            follow_symlinks: false,
            single_shot_max_bytes: DEFAULT_SINGLE_SHOT_MAX,
            default_chunk_size: DEFAULT_LOCAL_CHUNK,
            cached_endpoint_id,
            verified_dirs: Arc::new(StdMutex::new(HashSet::new())),
            durability: Arc::new(DurabilityTracker::new(
                abs.clone(),
                FsyncMode::Batch,
                BatchFlushOptions::default(),
            )),
            root: abs,
        })
    }

    pub fn with_encoding(mut self, mode: EncodingMode) -> Self {
        self.encoding = mode;
        self
    }

    /// Dereference symlinks during `stat`, `list_with_options`, and `open_read`
    /// (`--copy-links` / `-L`), with ancestor cycle detection. Destination write/delete
    /// operations ALWAYS continue enforcing symlink-escape containment.
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Configure the local filesystem durability policy (`--fsync=always|batch|never`).
    ///
    /// Call this while building the backend: it starts a fresh durability tracker, so writes
    /// already deferred by an earlier mode are not carried over.
    pub fn with_fsync_mode(mut self, mode: FsyncMode) -> Self {
        self.durability = Arc::new(DurabilityTracker::new(
            self.root.clone(),
            mode,
            BatchFlushOptions::default(),
        ));
        self
    }

    /// Test hook: replace the batch flush options (e.g. force the per-path fallback that
    /// macOS and BSD use instead of Linux `syncfs`).
    #[cfg(test)]
    pub(in crate::local) fn with_batch_flush_options(mut self, opts: BatchFlushOptions) -> Self {
        self.durability = Arc::new(DurabilityTracker::new(
            self.root.clone(),
            self.durability.mode(),
            opts,
        ));
        self
    }

    /// Return the configured [`FsyncMode`] for this local backend.
    pub fn fsync_mode(&self) -> FsyncMode {
        self.durability.mode()
    }

    /// Number of durable file fsyncs (plus filesystem-wide `syncfs` calls) performed by this
    /// backend.
    pub fn fsync_count(&self) -> u64 {
        self.durability.fsync_count()
    }

    /// Number of directory fsyncs performed by this backend (always `0` on Windows, which
    /// cannot flush directories, and on Linux batches covered by one `syncfs`).
    pub fn dir_fsync_count(&self) -> u64 {
        self.durability.dir_fsync_count()
    }

    /// Number of batch flushes executed by [`StorageBackend::flush_durable_writes`].
    pub fn batch_flush_count(&self) -> u64 {
        self.durability.batch_flush_count()
    }

    /// Override single-shot threshold and chunk size (useful in resumable local tests).
    pub fn with_chunking(mut self, single_shot_max_bytes: u64, default_chunk_size: u64) -> Self {
        self.single_shot_max_bytes = single_shot_max_bytes;
        self.default_chunk_size = default_chunk_size;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an existing entry's exact native path (preserving raw NFD spelling and
    /// applying `EncodingMode` per segment).
    fn resolve_existing(&self, bp: &BackendPath) -> PathBuf {
        let mut p = self.root.clone();
        let raw = bp.raw_path();
        if !raw.is_empty() {
            for seg in raw.split('/') {
                if !seg.is_empty() {
                    p.push(encode_local_segment(self.encoding, seg));
                }
            }
        }
        to_os_path(&p)
    }

    /// Resolve a new destination path (applying `EncodingMode` BEFORE Windows `\\?\`).
    fn resolve_new(&self, rel: &RelPath) -> PathBuf {
        let mut p = self.root.clone();
        for seg in rel.segments() {
            p.push(encode_local_segment(self.encoding, seg));
        }
        to_os_path(&p)
    }

    /// Resolve a destination path for writing, reusing the on-disk spelling of existing
    /// components whose names differ only by Unicode normalization.
    ///
    /// The engine addresses destination files by NFC path. On normalization-sensitive
    /// filesystems (Linux, Windows) an existing file or directory can be spelled NFD (e.g.
    /// copied there from macOS); writing to the NFC spelling would then fail an `Existing`
    /// precondition, or create an NFC sibling of the NFD entry. Every non-ASCII directory
    /// component that is missing in NFC is looked up by normalization in its parent, and so
    /// is the leaf when `leaf_may_exist` is set (overwrites, reconcile, durable sync). New
    /// leaves (`Absent` precondition) and ASCII-only paths cost no extra I/O.
    async fn resolve_write_path(&self, rel: &RelPath, leaf_may_exist: bool) -> Result<PathBuf> {
        if rel.as_str().is_ascii() {
            return Ok(self.resolve_new(rel));
        }
        let root = self.root.clone();
        let encoding = self.encoding;
        let rel = rel.clone();
        tokio::task::spawn_blocking(move || {
            fs_util::resolve_existing_spelling(&root, encoding, &rel, leaf_may_exist)
        })
        .await
        .map_err(|e| Error::protocol(format!("resolve destination path join: {e}")))
    }

    fn staging_path(&self, final_path: &Path, op_id: &str) -> PathBuf {
        let safe_id: String = op_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let parent = final_path.parent().unwrap_or(&self.root);
        to_os_path(&parent.join(format!("{PART_FILE_PREFIX}{safe_id}")))
    }
}

#[async_trait]
impl StorageBackend for LocalBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "local"
    }

    fn endpoint_identity(&self) -> String {
        if let Some(id) = self.cached_endpoint_id.get() {
            return id.clone();
        }
        match std::fs::canonicalize(to_os_path(&self.root)) {
            Ok(canonical) => {
                let id = format!("local://{}", canonical.display());
                let _ = self.cached_endpoint_id.set(id.clone());
                id
            }
            Err(_) => format!(
                "local://{}",
                canonicalize_deepest_ancestor(&self.root).display()
            ),
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![
                HashKind::Sha256,
                HashKind::Sha1,
                HashKind::Crc64Nvme,
                HashKind::Md5,
                HashKind::Crc32c,
            ],
            mtime_granularity: self.mtime_granularity,
            can_set_mtime: true,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: self.single_shot_max_bytes,
            default_chunk_size: self.default_chunk_size,
            allows_duplicate_names: false,
            case_sensitive: self.case_sensitive,
            supports_node_id: cfg!(unix),
            supports_range_read: true,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let root = self.root.clone();
        let os_path = self.resolve_existing(path);
        let raw = path.raw_path.clone();
        let nfc = path.nfc_path.clone();
        let follow = self.follow_symlinks;
        let is_root = path.nfc_path.is_root();
        tokio::task::spawn_blocking(move || {
            if !follow && !is_root {
                if strip_root_prefix(&os_path, &root).is_none() {
                    return Err(Error::invalid_path(format!(
                        "stat target `{}` escapes backend root `{}`",
                        os_path.display(),
                        root.display()
                    )));
                }
                let parent = os_path.parent().unwrap_or(&root);
                ensure_no_symlink_escape(&root, parent)?;
            }
            let res = if follow {
                std::fs::metadata(&os_path)
            } else {
                std::fs::symlink_metadata(&os_path)
            };
            match res {
                Ok(meta) => Ok(metadata_to_entry(&meta, raw, nfc)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(Error::io(format!("stat `{}`", os_path.display()), e)),
            }
        })
        .await
        .map_err(|e| Error::protocol(format!("stat task join: {e}")))?
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_with_options(prefix, &ListOptions::new().with_recursive(recursive))
            .await
    }

    async fn list_with_options(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        self.list_with_options_impl(prefix, options).await
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        let root = self.root.clone();
        let os_path = self.resolve_write_path(path, true).await?;
        let durability = self.durability.clone();
        tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &os_path)?;
            durability.create_dir_all(&os_path)
        })
        .await
        .map_err(|e| Error::protocol(format!("mkdir task join: {e}")))?
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("refusing to delete local backend root"));
        }
        let root = self.root.clone();
        let os_path = self.resolve_existing(path);
        crate::common::lock_unpoisoned(&self.verified_dirs).clear();
        tokio::task::spawn_blocking(move || {
            // Check parent containment strictly (blocking planted symlink directory escapes
            // like `pwn/victim.txt`), while allowing unlinking a symlink leaf itself (`move -L`).
            let parent = os_path.parent().unwrap_or(&root);
            ensure_no_symlink_escape(&root, parent)?;
            match std::fs::symlink_metadata(&os_path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
                        if meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
                            return match std::fs::remove_dir(&os_path) {
                                Ok(()) => Ok(()),
                                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                                    clear_readonly_if_windows(&os_path);
                                    std::fs::remove_dir(&os_path).map_err(|e2| {
                                        Error::io(
                                            format!("remove dir symlink `{}`", os_path.display()),
                                            e2,
                                        )
                                    })
                                }
                                Err(e) => Err(Error::io(
                                    format!("remove dir symlink `{}`", os_path.display()),
                                    e,
                                )),
                            };
                        }
                    }
                    match std::fs::remove_file(&os_path) {
                        Ok(()) => Ok(()),
                        #[cfg(windows)]
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            clear_readonly_if_windows(&os_path);
                            std::fs::remove_file(&os_path).map_err(|e2| {
                                Error::io(format!("remove symlink `{}`", os_path.display()), e2)
                            })
                        }
                        Err(e) => Err(Error::io(
                            format!("remove symlink `{}`", os_path.display()),
                            e,
                        )),
                    }
                }
                // Never execute `remove_dir_all` inside `delete` — non-empty directories
                // (e.g. containing filtered/excluded files) must NEVER be recursively wiped.
                Ok(meta) if meta.is_dir() => match std::fs::remove_dir(&os_path) {
                    Ok(()) => Ok(()),
                    #[cfg(windows)]
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        clear_readonly_if_windows(&os_path);
                        std::fs::remove_dir(&os_path)
                            .map_err(|e2| Error::io(format!("rmdir `{}`", os_path.display()), e2))
                    }
                    Err(e) => Err(Error::io(format!("rmdir `{}`", os_path.display()), e)),
                },
                Ok(_) => {
                    clear_readonly_if_windows(&os_path);
                    std::fs::remove_file(&os_path)
                        .map_err(|e| Error::io(format!("remove `{}`", os_path.display()), e))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(Error::io(
                    format!("stat for delete `{}`", os_path.display()),
                    e,
                )),
            }
        })
        .await
        .map_err(|e| Error::protocol(format!("delete task join: {e}")))?
    }

    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        if HashAcc::new(kind).is_none() {
            return Ok(None);
        }
        let root = self.root.clone();
        let os_path = self.resolve_existing(path);
        let follow = self.follow_symlinks;
        tokio::task::spawn_blocking(move || {
            if !follow {
                ensure_no_symlink_escape(&root, &os_path)?;
            }
            let pre_meta = if follow {
                std::fs::metadata(&os_path)
            } else {
                std::fs::symlink_metadata(&os_path)
            }
            .map_err(|e| Error::io(format!("stat `{}`", os_path.display()), e))?;
            if !pre_meta.is_file() {
                return Err(Error::invalid_path(format!(
                    "`{}` is not a regular file",
                    os_path.display()
                )));
            }
            let mut file = open_read_sequential_opt(&os_path, follow)?;
            let buf_len = file
                .metadata()
                .map(|m| m.len().clamp(4096, 256 * 1024) as usize)
                .unwrap_or(256 * 1024);
            let mut buf = vec![0u8; buf_len];
            let mut acc = HashAcc::new(kind).expect("validated hash kind");
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| Error::io(format!("hash read `{}`", os_path.display()), e))?;
                if n == 0 {
                    break;
                }
                acc.update(&buf[..n]);
            }
            Ok(Some(Checksum {
                kind,
                hex: acc.finalize_hex(),
            }))
        })
        .await
        .map_err(|e| Error::protocol(format!("hash task join: {e}")))?
    }

    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        let root = self.root.clone();
        let os_path = self.resolve_existing(path);
        let inline_small = range.is_some_and(|r| r.offset == 0 && r.len <= SMALL_READ_MAX as u64);
        let follow = self.follow_symlinks;
        tokio::task::spawn_blocking(move || {
            if !follow {
                ensure_no_symlink_escape(&root, &os_path)?;
            }
            let mut file = open_read_shared_opt(&os_path, follow)?;
            let meta = file
                .metadata()
                .map_err(|e| Error::io(format!("fstat `{}`", os_path.display()), e))?;
            if !meta.is_file() {
                return Err(Error::invalid_path(format!(
                    "`{}` is not a regular file",
                    os_path.display()
                )));
            }
            let file_len = meta.len();
            if inline_small && file_len <= SMALL_READ_MAX as u64 {
                let mut buf = Vec::with_capacity(file_len as usize);
                file.by_ref()
                    .take((SMALL_READ_MAX + 1) as u64)
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::io(format!("read `{}`", os_path.display()), e))?;
                if buf.len() > SMALL_READ_MAX || buf.len() as u64 != file_len {
                    return Err(Error::source_mutated(format!(
                        "source `{}` changed size during inline read (expected {file_len}, got {})",
                        os_path.display(),
                        buf.len()
                    )));
                }
                return Ok::<_, Error>(DataSource::LocalSeekable(Arc::new(MemorySource::new(buf))));
            }
            Ok(DataSource::LocalSeekable(Arc::new(LocalSeekableFile::new(
                file, file_len, os_path, follow,
            ))))
        })
        .await
        .map_err(|e| Error::protocol(format!("open_read task join: {e}")))?
    }

    async fn open_read_entry(
        &self,
        entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "`{}` is not a regular file",
                path.nfc_path
            )));
        }
        let root = self.root.clone();
        let os_path = self.resolve_existing(path);
        let hint_len = entry.size;
        let inline_small = range.is_some_and(|r| r.offset == 0 && r.len <= SMALL_READ_MAX as u64);
        let follow = self.follow_symlinks;
        tokio::task::spawn_blocking(move || {
            if !follow {
                ensure_no_symlink_escape(&root, &os_path)?;
            }
            let mut file = open_read_shared_opt(&os_path, follow)?;
            // `file.metadata()` queries the already-open OS handle (`fstat` / `GetFileInformationByHandle`)
            // without repeating a full path-resolving `symlink_metadata` syscall!
            let meta = file
                .metadata()
                .map_err(|e| Error::io(format!("fstat `{}`", os_path.display()), e))?;
            if !meta.is_file() {
                return Err(Error::invalid_path(format!(
                    "`{}` is not a regular file",
                    os_path.display()
                )));
            }
            let file_len = meta.len();
            if inline_small
                && file_len <= SMALL_READ_MAX as u64
                && hint_len <= SMALL_READ_MAX as u64
            {
                let mut buf = Vec::with_capacity(file_len as usize);
                file.by_ref()
                    .take((SMALL_READ_MAX + 1) as u64)
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::io(format!("read `{}`", os_path.display()), e))?;
                if buf.len() > SMALL_READ_MAX || buf.len() as u64 != file_len {
                    return Err(Error::source_mutated(format!(
                        "source `{}` changed size during inline read (expected {file_len}, got {})",
                        os_path.display(),
                        buf.len()
                    )));
                }
                return Ok::<_, Error>(DataSource::LocalSeekable(Arc::new(MemorySource::new(buf))));
            }
            Ok(DataSource::LocalSeekable(Arc::new(LocalSeekableFile::new(
                file, file_len, os_path, follow,
            ))))
        })
        .await
        .map_err(|e| Error::protocol(format!("open_read_entry task join: {e}")))?
    }

    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        self.put_single_shot_impl(init, body).await
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        self.begin_upload_impl(init).await
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        self.query_upload_impl(op).await
    }

    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
        self.upload_chunk_impl(op, chunk).await
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        self.finish_upload_impl(op, parts).await
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        self.abort_upload_impl(op).await
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        self.reconcile_operation_impl(op).await
    }

    async fn about(&self) -> Result<Option<rship_core::types::StorageQuota>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || local_disk_quota(&root))
            .await
            .map_err(|e| Error::protocol(format!("about join: {e}")))?
    }

    fn can_server_side_copy_from(&self, src_endpoint: &str) -> bool {
        src_endpoint.starts_with("local://")
    }

    /// OS-native local-to-local fast copy (`CopyFileExW` on Windows, `copy_file_range` /
    /// Btrfs-XFS CoW on Linux, `fclonefileat` APFS CoW on macOS) into an exclusive
    /// `.rship.part.<op_id>` staging file with pre-commit TOCTOU source verification and
    /// atomic rename publication.
    async fn server_side_copy(
        &self,
        src_endpoint: &str,
        src_path: &BackendPath,
        init: &UploadInit,
    ) -> Result<Option<Entry>> {
        self.server_side_copy_impl(src_endpoint, src_path, init)
            .await
    }

    fn defers_durable_writes(&self) -> bool {
        self.durability.mode() == FsyncMode::Batch
    }

    async fn flush_durable_writes(&self) -> Result<()> {
        if self.durability.mode() != FsyncMode::Batch {
            return Ok(());
        }
        let durability = self.durability.clone();
        tokio::task::spawn_blocking(move || durability.flush())
            .await
            .map_err(|e| Error::protocol(format!("flush_durable_writes join: {e}")))?
    }

    async fn sync_durable_file(&self, path: &BackendPath) -> Result<()> {
        let root = self.root.clone();
        let os_path = if path.raw_path.is_some()
            || (self.encoding == EncodingMode::Identity && path.nfc_path.as_str().is_ascii())
        {
            self.resolve_existing(path)
        } else {
            self.resolve_write_path(&path.nfc_path, true).await?
        };
        let durability = self.durability.clone();
        tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &os_path)?;
            durability.sync_file(&os_path)
        })
        .await
        .map_err(|e| Error::protocol(format!("sync_durable_file join: {e}")))?
    }

    async fn rename(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if path.nfc_path.is_root() {
            return Err(Error::invalid_path("cannot rename local backend root"));
        }
        if new_name.is_empty()
            || new_name == "."
            || new_name == ".."
            || new_name.contains(['/', '\\', '\0'])
        {
            return Err(Error::invalid_path(format!(
                "invalid rename target name `{new_name}`"
            )));
        }
        crate::common::lock_unpoisoned(&self.verified_dirs).clear();
        let src_abs = if path.raw_path.is_some()
            || (self.encoding == EncodingMode::Identity && path.nfc_path.as_str().is_ascii())
        {
            self.resolve_existing(path)
        } else {
            self.resolve_write_path(&path.nfc_path, true).await?
        };
        let new_rel = match path.nfc_path.parent() {
            Some(parent) => parent.join(new_name)?,
            None => RelPath::parse(new_name)?,
        };
        let encoded_new = encode_local_segment(self.encoding, new_name);
        let dst_parent = src_abs.parent().unwrap_or(&self.root);
        let dst_abs = to_os_path(&dst_parent.join(encoded_new));
        let root = self.root.clone();
        let nfc_new = new_rel.clone();
        let encoding = self.encoding;

        tokio::task::spawn_blocking(move || {
            ensure_no_symlink_escape(&root, &src_abs)?;
            ensure_no_symlink_escape(&root, &dst_abs)?;
            match std::fs::rename(&src_abs, &dst_abs) {
                Ok(()) => {}
                #[cfg(windows)]
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    clear_readonly_if_windows(&dst_abs);
                    std::fs::rename(&src_abs, &dst_abs).map_err(|e2| {
                        Error::io(
                            format!("rename `{}` -> `{}`", src_abs.display(), dst_abs.display()),
                            e2,
                        )
                    })?;
                }
                Err(e) => {
                    return Err(Error::io(
                        format!("rename `{}` -> `{}`", src_abs.display(), dst_abs.display()),
                        e,
                    ));
                }
            }
            let meta = std::fs::symlink_metadata(&dst_abs)
                .map_err(|e| Error::io(format!("stat renamed `{}`", dst_abs.display()), e))?;
            let raw_override = entry_raw_override(&root, &dst_abs, &nfc_new, encoding);
            metadata_to_entry(&meta, raw_override, nfc_new)
                .ok_or_else(|| Error::protocol("renamed entry is neither file nor directory"))
        })
        .await
        .map_err(|e| Error::protocol(format!("rename join: {e}")))?
    }
}
