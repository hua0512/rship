//! Per-backend `--fsync` bookkeeping for [`super::LocalBackend`]: deferred batch flushes,
//! newly created directory tracking, and the durable pre-delete sync.
//!
//! Every method here does blocking filesystem I/O and must run inside `spawn_blocking`.

use super::fs_util::{
    BatchFlushOptions, CreatedDirs, create_dir_all_tracked, created_ancestors, entry_parents,
    flush_pending_batch, forget_created_dirs, sync_dir, sync_file_and_parent,
};
use rship_core::Result;
use rship_core::types::FsyncMode;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Pending paths past this count are flushed inline by the writer that crossed it, so the
/// set stays bounded however long the engine defers [`DurabilityTracker::flush`].
const PENDING_SYNC_CAP: usize = 8_192;

#[derive(Debug, Default)]
struct PendingSync {
    files: HashSet<PathBuf>,
    dirs: HashSet<PathBuf>,
    created_to_forget: Vec<PathBuf>,
}

impl PendingSync {
    fn len(&self) -> usize {
        self.files.len() + self.dirs.len()
    }
}

#[derive(Debug)]
pub(super) struct DurabilityTracker {
    root: PathBuf,
    mode: FsyncMode,
    flush_opts: BatchFlushOptions,
    /// Written files and modified directories awaiting [`Self::flush`] in `Batch` mode.
    pending: StdMutex<PendingSync>,
    /// Directories this backend created whose entries are not yet known to be durable.
    created_dirs: StdMutex<CreatedDirs>,
    fsync_count: AtomicU64,
    dir_fsync_count: AtomicU64,
    batch_flush_count: AtomicU64,
}

impl DurabilityTracker {
    pub(super) fn new(root: PathBuf, mode: FsyncMode, flush_opts: BatchFlushOptions) -> Self {
        Self {
            root,
            mode,
            flush_opts,
            pending: StdMutex::new(PendingSync::default()),
            created_dirs: StdMutex::new(CreatedDirs::default()),
            fsync_count: AtomicU64::new(0),
            dir_fsync_count: AtomicU64::new(0),
            batch_flush_count: AtomicU64::new(0),
        }
    }

    pub(super) fn mode(&self) -> FsyncMode {
        self.mode
    }

    /// Whether a commit must `fsync` the file (and its parent directory) before returning.
    pub(super) fn commit_durably(&self) -> bool {
        self.mode == FsyncMode::Always
    }

    pub(super) fn fsync_count(&self) -> u64 {
        self.fsync_count.load(Ordering::Relaxed)
    }

    pub(super) fn dir_fsync_count(&self) -> u64 {
        self.dir_fsync_count.load(Ordering::Relaxed)
    }

    pub(super) fn batch_flush_count(&self) -> u64 {
        self.batch_flush_count.load(Ordering::Relaxed)
    }

    /// Create `dir` and its missing ancestors, remembering the new ones.
    pub(super) fn create_dir_all(&self, dir: &Path) -> Result<()> {
        create_dir_all_tracked(dir, &self.created_dirs)
    }

    /// Record that `final_path` was just published by rename.
    ///
    /// - `Always`: the commit already synced the file and its parent; this also syncs the
    ///   parents of any directories created for it, so the whole chain is durable.
    /// - `Batch`: queue the file, its parent and those directories for the next flush.
    /// - `Never`: nothing.
    pub(super) fn after_commit(&self, final_path: &Path) -> Result<()> {
        match self.mode {
            FsyncMode::Always => {
                self.fsync_count.fetch_add(1, Ordering::Relaxed);
                let created = created_ancestors(&self.root, final_path, &self.created_dirs);
                for dir in entry_parents(&created) {
                    if sync_dir(&dir)? {
                        self.dir_fsync_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                forget_created_dirs(&self.created_dirs, &created);
                Ok(())
            }
            FsyncMode::Batch => {
                let created = created_ancestors(&self.root, final_path, &self.created_dirs);
                let overflow = {
                    let mut p = crate::common::lock_unpoisoned(&self.pending);
                    p.files.insert(final_path.to_path_buf());
                    if let Some(parent) = final_path.parent() {
                        p.dirs.insert(parent.to_path_buf());
                    }
                    p.dirs.extend(entry_parents(&created));
                    p.created_to_forget.extend(created);
                    (p.len() >= PENDING_SYNC_CAP).then(|| std::mem::take(&mut *p))
                };
                match overflow {
                    Some(batch) => self.flush_batch(batch),
                    None => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }

    /// Flush every deferred write (`Batch` mode only).
    pub(super) fn flush(&self) -> Result<()> {
        if self.mode != FsyncMode::Batch {
            return Ok(());
        }
        let batch = std::mem::take(&mut *crate::common::lock_unpoisoned(&self.pending));
        if batch.len() == 0 {
            return Ok(());
        }
        self.flush_batch(batch)
    }

    /// Flush `batch`. On failure every path in it goes back into the pending set, so a later
    /// flush retries them instead of silently treating them as durable.
    fn flush_batch(&self, batch: PendingSync) -> Result<()> {
        match flush_pending_batch(&self.root, &batch.files, &batch.dirs, &self.flush_opts) {
            Ok(stats) => {
                self.batch_flush_count.fetch_add(1, Ordering::Relaxed);
                self.fsync_count
                    .fetch_add(stats.files + u64::from(stats.syncfs), Ordering::Relaxed);
                self.dir_fsync_count
                    .fetch_add(stats.dirs, Ordering::Relaxed);
                if stats.syncfs {
                    // `syncfs` made every directory entry on the filesystem durable.
                    crate::common::lock_unpoisoned(&self.created_dirs).clear();
                } else {
                    forget_created_dirs(&self.created_dirs, &batch.created_to_forget);
                }
                Ok(())
            }
            Err(err) => {
                let mut p = crate::common::lock_unpoisoned(&self.pending);
                p.files.extend(batch.files);
                p.dirs.extend(batch.dirs);
                p.created_to_forget.extend(batch.created_to_forget);
                Err(err)
            }
        }
    }

    /// Durably sync one committed file, its parent, and the parents of every directory
    /// created for it up to the backend root, regardless of `mode` (the pre-delete path).
    pub(super) fn sync_file(&self, path: &Path) -> Result<()> {
        let created = created_ancestors(&self.root, path, &self.created_dirs);
        let dirs = sync_file_and_parent(path, &entry_parents(&created))?;
        forget_created_dirs(&self.created_dirs, &created);
        crate::common::lock_unpoisoned(&self.pending)
            .files
            .remove(path);
        self.fsync_count.fetch_add(1, Ordering::Relaxed);
        self.dir_fsync_count.fetch_add(dirs, Ordering::Relaxed);
        Ok(())
    }
}
