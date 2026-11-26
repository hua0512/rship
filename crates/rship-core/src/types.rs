use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::path::RelPath;

/// Strongly-typed storage backend driver identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BackendKind {
    Local,
    Gdrive,
    S3,
    Webdav,
    Onedrive,
    Sftp,
    Dropbox,
    Gcs,
    Azureblob,
    Crypt,
    Memory,
    Custom,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Gdrive => "gdrive",
            Self::S3 => "s3",
            Self::Webdav => "webdav",
            Self::Onedrive => "onedrive",
            Self::Sftp => "sftp",
            Self::Dropbox => "dropbox",
            Self::Gcs => "gcs",
            Self::Azureblob => "azureblob",
            Self::Crypt => "crypt",
            Self::Memory => "memory",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Self::Local,
            "gdrive" | "drive" => Self::Gdrive,
            "s3" => Self::S3,
            "webdav" => Self::Webdav,
            "onedrive" => Self::Onedrive,
            "sftp" => Self::Sftp,
            "dropbox" => Self::Dropbox,
            "gcs" | "google cloud storage" => Self::Gcs,
            "azureblob" | "azure" => Self::Azureblob,
            "crypt" | "crypto" => Self::Crypt,
            "memory" | "mem" | "chaos" => Self::Memory,
            _ => Self::Custom,
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BackendKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Error::invalid_path("backend kind cannot be empty"));
        }
        Ok(Self::parse(trimmed))
    }
}

/// Local filesystem durability policy for committed writes (`--fsync`).
///
/// Even in `Batch` or `Never` mode, source deletions (`move` / `bisync`) always
/// durably sync the destination file and parent directory before removing the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsyncMode {
    /// Sync every committed file (`sync_all`) plus its parent directory on every write.
    Always,
    /// Defer per-file fsyncs and flush pending writes in one batch (`syncfs` on Linux,
    /// `FlushFileBuffers` on Windows, per-file/dir `fsync` on macOS) before baseline/job
    /// commits and deletion passes.
    #[default]
    Batch,
    /// Skip fsync on normal writes (source deletions in `move` still sync the destination first).
    Never,
}

impl FsyncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Batch => "batch",
            Self::Never => "never",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "always" => Some(Self::Always),
            "batch" => Some(Self::Batch),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

impl fmt::Display for FsyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FsyncMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| {
            Error::config(format!(
                "invalid fsync mode `{s}` (expected: always, batch, never)"
            ))
        })
    }
}

/// Opaque backend-native node identifier (e.g. Google Drive `fileId`,
/// POSIX `dev:ino`, Windows `vol:file_index`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for NodeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "dir",
            Self::Symlink => "symlink",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "dir" | "directory" => Some(Self::Directory),
            "symlink" => Some(Self::Symlink),
            _ => None,
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EntryKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown entry kind `{s}`")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HashKind {
    Md5,
    Sha1,
    Sha256,
    Crc32c,
    Crc64Nvme,
    Blake3,
}

impl HashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Crc32c => "crc32c",
            Self::Crc64Nvme => "crc64nvme",
            Self::Blake3 => "blake3",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "crc32c" => Some(Self::Crc32c),
            "crc64nvme" | "crc64_nvme" => Some(Self::Crc64Nvme),
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }
}

impl fmt::Display for HashKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown hash kind `{s}`")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    pub kind: HashKind,
    pub hex: String,
}

/// Inclusive-start, length-bounded byte range for `open_read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

impl ByteRange {
    pub fn end_exclusive(self) -> Option<u64> {
        self.offset.checked_add(self.len)
    }
}

/// Return `Some(raw)` ONLY when `raw != nfc.as_str()` (e.g. macOS NFD bytes);
/// returns `None` (zero heap allocation) on the 99.99% NFC fast path.
#[inline]
pub fn raw_path_override(nfc: &RelPath, raw: &str) -> Option<Box<str>> {
    (raw != nfc.as_str()).then(|| Box::<str>::from(raw))
}

/// An observed object/entry in a storage backend.
///
/// Crucially preserves **both** `raw_path()` (exact backend key, preserving NFD or
/// native spelling so reads/deletes never hit 404/ENOENT) and `nfc_path` (the
/// NFC-normalized canonical matching key). When `raw == nfc` (99.99% of entries),
/// `raw_path` is `None`, saving 1 heap allocation per object and shrinking `Entry` by 8 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub node_id: Option<NodeId>,
    pub parent_id: Option<NodeId>,
    /// Native relative path ONLY when it differs from `nfc_path` (e.g. NFD bytes).
    /// Prefer [`Entry::raw_path()`] to read the effective raw path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_path: Option<Box<str>>,
    /// Canonical NFC-normalized relative path for cross-backend matching.
    pub nfc_path: RelPath,
    pub kind: EntryKind,
    pub size: u64,
    /// Modification time in Unix nanoseconds.
    pub mtime_ns: i64,
    /// Inode/metadata change time in Unix nanoseconds when available (Unix ctime).
    pub ctime_ns: Option<i64>,
    /// Opaque server revision/ETag (never blindly assumed to be MD5!).
    pub etag: Option<String>,
    /// Verified full-object checksum when natively provided by backend.
    pub checksum: Option<Checksum>,
}

impl Entry {
    /// Construct a file [`Entry`] with canonical `nfc_path` (zero extra `raw_path` allocation).
    pub fn file(nfc_path: RelPath, size: u64, mtime_ns: i64) -> Self {
        Self {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path,
            kind: EntryKind::File,
            size,
            mtime_ns,
            ctime_ns: None,
            etag: None,
            checksum: None,
        }
    }

    /// Construct a directory [`Entry`] with canonical `nfc_path` (zero extra `raw_path` allocation).
    pub fn dir(nfc_path: RelPath, mtime_ns: i64) -> Self {
        Self {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path,
            kind: EntryKind::Directory,
            size: 0,
            mtime_ns,
            ctime_ns: None,
            etag: None,
            checksum: None,
        }
    }

    /// Effective backend-native relative path (`raw_path` override if distinct, else `nfc_path`).
    #[inline]
    pub fn raw_path(&self) -> &str {
        self.raw_path.as_deref().unwrap_or(self.nfc_path.as_str())
    }

    /// True if this entry's native spelling differs from its canonical NFC path (e.g. NFD).
    #[inline]
    pub fn has_distinct_raw_path(&self) -> bool {
        self.raw_path.is_some()
    }

    /// Update the native raw path, clearing the override whenever it equals `nfc_path`.
    #[inline]
    pub fn set_raw_path(&mut self, raw: &str) {
        self.raw_path = raw_path_override(&self.nfc_path, raw);
    }

    pub fn with_raw_path(mut self, raw_path: impl AsRef<str>) -> Self {
        self.raw_path = raw_path_override(&self.nfc_path, raw_path.as_ref());
        self
    }

    pub fn with_node_id(mut self, node_id: impl Into<NodeId>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    pub fn with_parent_id(mut self, parent_id: impl Into<NodeId>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    pub fn with_ctime_ns(mut self, ctime_ns: i64) -> Self {
        self.ctime_ns = Some(ctime_ns);
        self
    }

    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    pub fn with_checksum(mut self, checksum: Checksum) -> Self {
        self.checksum = Some(checksum);
        self
    }
}

/// Protocol-level chunk alignment rules across cloud storage providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChunkAlignment {
    /// Any byte boundary is valid (Local, IETF HTTPbis / tus).
    Arbitrary,
    /// Non-final chunks must be exact multiples of `align_bytes`
    /// (Google Drive = 256 KiB; OneDrive = 320 KiB with max 60 MiB).
    MultipleOf {
        align_bytes: u64,
        max_chunk_bytes: Option<u64>,
    },
    /// Non-final parts must satisfy `[min_bytes, max_bytes]` and total parts <= `max_parts`
    /// (AWS S3: min 5 MiB, max 5 GiB, 10,000 parts, 48.8 TiB; R2: 5 TiB + equal non-final parts).
    MinSizeWithMaxParts {
        min_bytes: u64,
        max_bytes: u64,
        max_parts: u32,
        max_object_bytes: u64,
        require_equal_non_final_parts: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UploadTopology {
    /// Strict sequential byte offsets (Google Drive, OneDrive, Local temp append).
    Sequential,
    /// Concurrent out-of-order part uploads committed via part manifest (S3, R2, OSS, B2).
    ParallelParts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub hashes: Vec<HashKind>,
    pub mtime_granularity: Duration,
    pub can_set_mtime: bool,
    pub upload_topology: UploadTopology,
    pub chunk_alignment: ChunkAlignment,
    /// Files <= this size use a 1-request fast path (GDrive multipart/related, S3 PutObject).
    pub single_shot_max_bytes: u64,
    pub default_chunk_size: u64,
    pub allows_duplicate_names: bool,
    pub case_sensitive: bool,
    pub supports_node_id: bool,
    pub supports_range_read: bool,
    /// Single un-ranged (or full-object `0..size`) read returns an atomic immutable snapshot
    /// without torn bytes from concurrent writers (S3, GCS, Azure, GDrive, OneDrive, Dropbox).
    pub supports_atomic_single_read: bool,
    /// Multi-request ranged reads enforce version identity (`If-Match` / `generation`)
    /// across independent chunk requests.
    pub supports_version_pinned_read: bool,
    /// `list_ordered_range` returns entries in ascending raw UTF-8 key order (S3, GCS, Azure).
    pub supports_ordered_utf8_list: bool,
    pub supports_conditional_write: bool,
    pub supports_change_feed: bool,
    pub supports_server_side_copy: bool,
    pub default_write_qps: Option<u32>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            hashes: Vec::new(),
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: false,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: 5 * 1024 * 1024,
            default_chunk_size: 16 * 1024 * 1024,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: false,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
            default_write_qps: None,
        }
    }
}

impl Capabilities {
    /// Find the strongest common hash algorithm supported by both backends.
    pub fn best_common_hash(&self, other: &Self) -> Option<HashKind> {
        const PREFERENCE: [HashKind; 6] = [
            HashKind::Blake3,
            HashKind::Sha256,
            HashKind::Crc64Nvme,
            HashKind::Crc32c,
            HashKind::Sha1,
            HashKind::Md5,
        ];
        PREFERENCE
            .into_iter()
            .find(|h| self.hashes.contains(h) && other.hashes.contains(h))
    }

    /// Effective mtime comparison tolerance between two backends.
    pub fn effective_mtime_tolerance(&self, other: &Self) -> Duration {
        self.mtime_granularity.max(other.mtime_granularity)
    }
}

/// Storage space & quota summary reported by `StorageBackend::about` (`rship about`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageQuota {
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub trashed_bytes: Option<u64>,
}

impl StorageQuota {
    pub fn new(
        total_bytes: Option<u64>,
        used_bytes: Option<u64>,
        free_bytes: Option<u64>,
        trashed_bytes: Option<u64>,
    ) -> Self {
        Self {
            total_bytes,
            used_bytes,
            free_bytes,
            trashed_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendPath;

    #[test]
    fn raw_path_is_zero_alloc_none_for_nfc_and_lossless_for_nfd() {
        let nfc = RelPath::parse("dir/caf\u{00e9}.txt").unwrap();
        assert_eq!(raw_path_override(&nfc, "dir/caf\u{00e9}.txt"), None);

        let nfd_raw = "dir/cafe\u{0301}.txt";
        let nfc_from_nfd = RelPath::parse(nfd_raw).unwrap();
        assert_eq!(nfc_from_nfd.as_str(), "dir/caf\u{00e9}.txt");

        let e_nfc = Entry::file(nfc.clone(), 10, 1);
        assert!(e_nfc.raw_path.is_none());
        assert!(!e_nfc.has_distinct_raw_path());
        assert_eq!(e_nfc.raw_path(), "dir/caf\u{00e9}.txt");

        let e_nfd = Entry::file(nfc_from_nfd.clone(), 10, 1).with_raw_path(nfd_raw);
        assert_eq!(e_nfd.raw_path.as_deref(), Some(nfd_raw));
        assert!(e_nfd.has_distinct_raw_path());
        assert_eq!(e_nfd.raw_path(), nfd_raw);

        let pfx = RelPath::parse("root").unwrap();
        let bp_nfc = BackendPath::join_prefixed(
            &pfx,
            e_nfc.raw_path(),
            &e_nfc.nfc_path,
            None,
            Some(EntryKind::File),
        )
        .unwrap();
        assert!(bp_nfc.raw_path.is_none());
        assert_eq!(bp_nfc.raw_path(), "root/dir/caf\u{00e9}.txt");

        let bp_nfd = BackendPath::join_prefixed(
            &pfx,
            e_nfd.raw_path(),
            &e_nfd.nfc_path,
            None,
            Some(EntryKind::File),
        )
        .unwrap();
        assert_eq!(
            bp_nfd.raw_path.as_deref(),
            Some("root/dir/cafe\u{0301}.txt")
        );
        assert_eq!(bp_nfd.nfc_path.as_str(), "root/dir/caf\u{00e9}.txt");
    }
}
