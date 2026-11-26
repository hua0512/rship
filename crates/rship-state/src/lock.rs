//! Cross-platform exclusive advisory process lock preventing two `rship`
//! processes from mutating the same destination target concurrently.

use rship_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const MAX_LOCK_ACQUIRE_RETRIES: usize = 8;
/// Extra attempts after finding the lock held. `sweep_stale_locks` briefly locks a stale
/// file before unlinking it; that is not a real holder, so a few short backoffs (about
/// 30 ms in total) let the sweep finish before reporting the lock as busy.
const MAX_BUSY_RETRIES: usize = 4;

#[must_use]
pub struct ProcessLock {
    _file: File,
    path: PathBuf,
}

impl ProcessLock {
    /// Acquire a non-blocking exclusive lock for `scope_key` under `lock_dir`.
    pub fn try_acquire(lock_dir: &Path, scope_key: &str) -> Result<Self> {
        std::fs::create_dir_all(lock_dir)
            .map_err(|e| Error::io(format!("create lock dir `{}`", lock_dir.display()), e))?;
        let mut h = Sha256::new();
        h.update(scope_key.as_bytes());
        let name = format!("{}.lock", &hex::encode(h.finalize())[..24]);
        let path = lock_dir.join(name);
        Self::try_acquire_file(&path)
    }

    /// Acquire a non-blocking exclusive lock directly on `lock_path`.
    pub fn try_acquire_file(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::io(format!("create lock dir `{}`", parent.display()), e))?;
        }

        let mut busy_retries = 0usize;
        for attempt in 0..MAX_LOCK_ACQUIRE_RETRIES + MAX_BUSY_RETRIES {
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
            {
                Ok(f) => f,
                // On Windows, a stale lock file unlinked by a concurrent `sweep_stale_locks`
                // stays briefly delete-pending until the sweeper drops its handle, during
                // which `CreateFileW` returns `ERROR_ACCESS_DENIED` (`PermissionDenied`).
                #[cfg(windows)]
                Err(e)
                    if e.kind() == std::io::ErrorKind::PermissionDenied
                        && attempt + 1 < MAX_LOCK_ACQUIRE_RETRIES =>
                {
                    backoff_acquire_retry(attempt);
                    continue;
                }
                Err(e) => {
                    return Err(Error::io(format!("open lock file `{}`", path.display()), e));
                }
            };

            match try_lock_exclusive(&file, path)? {
                LockAttempt::Locked => {}
                LockAttempt::Busy if busy_retries < MAX_BUSY_RETRIES => {
                    busy_retries += 1;
                    drop(file);
                    backoff_acquire_retry(busy_retries);
                    continue;
                }
                LockAttempt::Busy => return Err(lock_busy_error(path)),
            }

            // Verify our locked handle still points to the live file currently at `path`
            // (guarding against an unlink/replace race with `sweep_stale_locks`).
            if verify_locked_file_matches_path(&file, path)? {
                return Ok(Self {
                    _file: file,
                    path: path.to_path_buf(),
                });
            }

            // Drop the stale handle BEFORE retrying so the OS can finish removing any
            // unlinked/delete-pending entry at `path`.
            drop(file);
            backoff_acquire_retry(attempt);
        }

        Err(Error::lock_busy(format!(
            "lock file `{}` was repeatedly unlinked during acquisition",
            path.display()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Remove unlocked `.lock` files under `lock_dir` whose modification time is older
/// than `max_age` (prevents unbounded inode accumulation from one-off lock scopes).
pub fn sweep_stale_locks(lock_dir: &Path, max_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(lock_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut swept = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("lock") {
            continue;
        }
        if !max_age.is_zero()
            && let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && let Ok(age) = now.duration_since(modified)
            && age < max_age
        {
            continue;
        }
        // Open existing file only (`create(false)`) so racing sweepers never recreate
        // a lock file that another sweeper just unlinked.
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
            continue;
        };
        if file.try_lock().is_err() {
            continue;
        }
        // Verify our locked handle still refers to the live directory entry before unlinking.
        if !matches!(verify_locked_file_matches_path(&file, &path), Ok(true)) {
            continue;
        }
        // Unlink WHILE STILL HOLDING the exclusive lock so no other process can acquire
        // this file and have its lock file unlinked out from under it.
        if std::fs::remove_file(&path).is_ok() {
            swept += 1;
        }
        drop(file);
    }
    swept
}

fn backoff_acquire_retry(attempt: usize) {
    if attempt == 0 {
        std::thread::yield_now();
    } else {
        let ms = (1u64 << attempt.min(4)).min(15);
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(unix)]
fn verify_locked_file_matches_path(file: &File, path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let fd_meta = file
        .metadata()
        .map_err(|e| Error::io(format!("stat open lock fd `{}`", path.display()), e))?;
    let path_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(Error::io(format!("stat lock path `{}`", path.display()), e));
        }
    };
    Ok(fd_meta.dev() == path_meta.dev() && fd_meta.ino() == path_meta.ino())
}

#[cfg(windows)]
fn verify_locked_file_matches_path(file: &File, path: &Path) -> Result<bool> {
    use std::os::windows::fs::MetadataExt;
    let fd_meta = file
        .metadata()
        .map_err(|e| Error::io(format!("stat open lock handle `{}`", path.display()), e))?;
    let path_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        // On Windows NTFS, a file unlinked while open enters delete-pending state,
        // surfacing as `PermissionDenied` or `NotFound`.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(false);
        }
        Err(e) => {
            return Err(Error::io(format!("stat lock path `{}`", path.display()), e));
        }
    };
    if fd_meta.creation_time() != path_meta.creation_time() {
        return Ok(false);
    }
    // Probe-open the path: a delete-pending entry fails immediately with `PermissionDenied`,
    // and if `path` was replaced by a different unlocked file within the same timestamp tick,
    // `probe.try_lock()` would succeed instead of returning `WouldBlock` against `file`'s lock.
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(probe) => {
            let probe_meta = probe
                .metadata()
                .map_err(|e| Error::io(format!("stat lock probe `{}`", path.display()), e))?;
            if fd_meta.creation_time() != probe_meta.creation_time() {
                return Ok(false);
            }
            match probe.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => Ok(true),
                Ok(()) => Ok(false),
                Err(std::fs::TryLockError::Error(e)) => Err(Error::io(
                    format!("verify lock probe `{}`", path.display()),
                    e,
                )),
            }
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(Error::io(
            format!("verify lock path `{}`", path.display()),
            e,
        )),
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_locked_file_matches_path(_file: &File, path: &Path) -> Result<bool> {
    Ok(path.exists())
}

enum LockAttempt {
    Locked,
    Busy,
}

fn try_lock_exclusive(file: &File, path: &Path) -> Result<LockAttempt> {
    match file.try_lock() {
        Ok(()) => Ok(LockAttempt::Locked),
        Err(std::fs::TryLockError::WouldBlock) => Ok(LockAttempt::Busy),
        Err(std::fs::TryLockError::Error(err)) => Err(Error::io(
            format!("acquire exclusive lock `{}`", path.display()),
            err,
        )),
    }
}

fn lock_busy_error(path: &Path) -> Error {
    Error::lock_busy(format!(
        "another rship process already holds exclusive lock `{}`",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn exclusive_lock_blocks_second_holder_and_releases_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock1 = ProcessLock::try_acquire(dir.path(), "dst://bucket/prefix").unwrap();
        assert!(ProcessLock::try_acquire(dir.path(), "dst://bucket/prefix").is_err());
        drop(lock1);
        let _lock2 = ProcessLock::try_acquire(dir.path(), "dst://bucket/prefix").unwrap();
    }

    // Unlinking a file that another handle has open is a Unix-only move.
    #[cfg(unix)]
    #[test]
    fn d9_acquire_waits_out_a_sweeper_briefly_holding_a_stale_lock() {
        use std::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("stale.lock");
        std::fs::write(&path, b"").unwrap();
        let (locked_tx, locked_rx) = mpsc::channel();
        let sweeper_path = path.clone();
        // What `sweep_stale_locks` does: lock the stale file, unlink it, then release.
        let sweeper = std::thread::spawn(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&sweeper_path)
                .unwrap();
            file.try_lock().unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(5));
            std::fs::remove_file(&sweeper_path).unwrap();
            drop(file);
        });
        locked_rx.recv().unwrap();
        let lock = ProcessLock::try_acquire_file(&path)
            .expect("a sweeper's momentary lock on a stale file is not a real holder");
        sweeper.join().unwrap();
        assert!(
            path.exists(),
            "the acquired lock file must be the live entry"
        );
        assert!(ProcessLock::try_acquire_file(&path).is_err());
        drop(lock);
    }

    #[test]
    fn d9_sweep_stale_locks_never_allows_dual_holders_under_contention() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let dir = TempDir::new().unwrap();
        let lock_dir = Arc::new(dir.path().to_path_buf());
        let stop = Arc::new(AtomicBool::new(false));
        let active_holders = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let acquisitions = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let d = lock_dir.clone();
            let s = stop.clone();
            let active = active_holders.clone();
            let max_c = max_concurrent.clone();
            let acq = acquisitions.clone();
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if let Ok(lock) = ProcessLock::try_acquire(&d, "contended-scope") {
                        let cur = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_c.fetch_max(cur, Ordering::SeqCst);
                        acq.fetch_add(1, Ordering::Relaxed);
                        std::thread::yield_now();
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(lock);
                    } else {
                        std::thread::yield_now();
                    }
                }
            }));
        }

        for _ in 0..2 {
            let d = lock_dir.clone();
            let s = stop.clone();
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    let _ = sweep_stale_locks(&d, Duration::ZERO);
                    std::thread::yield_now();
                }
            }));
        }

        std::thread::sleep(Duration::from_millis(500));
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }

        assert!(
            acquisitions.load(Ordering::Relaxed) > 0,
            "workers should have acquired the lock at least once"
        );
        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "sweep_stale_locks race allowed multiple simultaneous lock holders!"
        );
    }

    #[test]
    fn d9_sweep_stale_locks_keeps_active_lock_and_sweeps_stale_lock() {
        let dir = TempDir::new().unwrap();
        let active = ProcessLock::try_acquire(dir.path(), "active-scope").unwrap();
        let stale = ProcessLock::try_acquire(dir.path(), "stale-scope").unwrap();
        let stale_path = stale.path().to_path_buf();
        let active_path = active.path().to_path_buf();
        drop(stale);

        let swept = sweep_stale_locks(dir.path(), Duration::ZERO);
        assert_eq!(swept, 1, "only the unlocked stale lock should be swept");
        assert!(!stale_path.exists(), "stale lock file must be removed");
        assert!(active_path.exists(), "active lock file must NOT be removed");
        assert!(
            ProcessLock::try_acquire(dir.path(), "active-scope").is_err(),
            "active lock must still block a second holder after sweep"
        );
        drop(active);
    }

    #[test]
    fn d9_unlink_while_locked_and_probe_os_delete_behavior() {
        // Test what happens when a lock file is unlinked while another holder holds it,
        // and verify `try_acquire_file` on a replaced/unlinked lock file still guarantees
        // mutual exclusion on the live path.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("race.lock");

        let lock1 = ProcessLock::try_acquire_file(&path).unwrap();
        // Unlink while locked (this is what the fixed sweeper does before drop).
        let rm_res = std::fs::remove_file(&path);
        assert!(
            rm_res.is_ok(),
            "remove_file while holding exclusive lock should succeed: {rm_res:?}"
        );
        // While `lock1` is still open after `remove_file`:
        // - On Unix: `path` no longer exists and a new `try_acquire_file` creates a new inode.
        // - On Windows: `path` is delete-pending until `lock1` drops; once `lock1` drops,
        //   `path` disappears cleanly and a new `try_acquire_file` succeeds on a live file.
        drop(lock1);
        assert!(
            !path.exists(),
            "lock file must be gone once the sweeping holder drops its lock"
        );
        let lock2 = ProcessLock::try_acquire_file(&path).unwrap();
        assert!(path.exists());
        assert!(ProcessLock::try_acquire_file(&path).is_err());
        drop(lock2);
    }

    #[test]
    fn d9_verify_locked_file_detects_unlinked_and_replaced_handles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("verify.lock");

        let file1 = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        file1.try_lock().unwrap();

        assert!(
            verify_locked_file_matches_path(&file1, &path).unwrap(),
            "live locked handle must match its path"
        );

        // Unlink the file while holding `file1` locked.
        std::fs::remove_file(&path).unwrap();
        assert!(
            !verify_locked_file_matches_path(&file1, &path).unwrap(),
            "unlinked/delete-pending lock handle must NOT match path"
        );

        #[cfg(unix)]
        {
            // On Unix, creating a new file at `path` gives a distinct inode; `file1` must
            // still fail the `(dev, ino)` check while `try_acquire_file` locks the live path.
            let lock2 = ProcessLock::try_acquire_file(&path).unwrap();
            assert!(
                !verify_locked_file_matches_path(&file1, &path).unwrap(),
                "stale handle pointing to unlinked inode must fail inode check against new file"
            );
            assert!(ProcessLock::try_acquire_file(&path).is_err());
            drop(lock2);
        }

        drop(file1);
    }

    #[test]
    fn d9_try_acquire_retries_cleanly_across_concurrent_unlink() {
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new().unwrap();
        let path = Arc::new(dir.path().join("retry_unlink.lock"));
        let barrier = Arc::new(Barrier::new(2));

        let holder_path = path.clone();
        let holder_barrier = barrier.clone();
        let holder = std::thread::spawn(move || {
            let lock = ProcessLock::try_acquire_file(&holder_path).unwrap();
            std::fs::remove_file(&*holder_path).unwrap();
            // Release the contender right while `lock` is still held & unlinked/delete-pending.
            holder_barrier.wait();
            std::thread::sleep(Duration::from_millis(10));
            drop(lock);
        });

        barrier.wait();
        let lock2 = ProcessLock::try_acquire_file(&path)
            .expect("try_acquire_file must retry cleanly onto the live path after unlink");
        holder.join().unwrap();

        assert!(path.exists());
        assert!(
            ProcessLock::try_acquire_file(&path).is_err(),
            "acquired lock after retry must enforce mutual exclusion"
        );
        drop(lock2);
    }
}
