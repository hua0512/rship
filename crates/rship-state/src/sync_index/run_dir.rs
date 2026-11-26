//! Lazy per-run ephemeral scratch directory (`LazyRunDir`) and race-free stale-run sweeper.

use rship_core::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime};

use crate::lock::ProcessLock;

const SWEEP_MIN_AGE: Duration = Duration::from_secs(10);
const GC_LOCK_MAX_ATTEMPTS: u32 = 40;
const GC_LOCK_RETRY_DELAY: Duration = Duration::from_millis(25);

fn sanitize_job_id(job_id: &str) -> String {
    job_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Run a synchronous filesystem/lock operation without stalling a Tokio multi-thread worker
/// pool. Falls back directly on `current_thread` runtimes or non-Tokio threads where
/// `block_in_place` is unsupported.
pub(super) fn run_blocking_fs<T>(f: impl FnOnce() -> T) -> T {
    if let Ok(handle) = tokio::runtime::Handle::try_current()
        && handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
    {
        return tokio::task::block_in_place(f);
    }
    f()
}

/// Ensure the configured `SQLITE_TMPDIR` directory exists lazily right before opening
/// any spilled SQLite database (zero syscalls on read-only CLI commands or small runs).
pub(super) fn ensure_sqlite_tmpdir_exists() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        if let Some(dir) = std::env::var_os("SQLITE_TMPDIR") {
            let p = PathBuf::from(dir);
            if !p.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(&p);
            }
        }
    });
}

enum InitAttempt {
    Ready(PathBuf),
    GcLockContended(Error),
}

struct InitializedRunDir {
    dir: PathBuf,
    run_lock: Option<ProcessLock>,
}

impl Drop for InitializedRunDir {
    fn drop(&mut self) {
        run_blocking_fs(|| {
            // Release the `.run.lock` handle BEFORE removing the directory (Windows requirement).
            let _ = self.run_lock.take();
            let _ = std::fs::remove_dir_all(&self.dir);
        });
    }
}

struct LazyRunDirInner {
    runs_dir: PathBuf,
    safe_id: String,
    init_done: AtomicBool,
    initialized: StdMutex<Option<InitializedRunDir>>,
}

impl LazyRunDirInner {
    fn planned_path(&self) -> PathBuf {
        self.runs_dir.join(format!("run-{}", self.safe_id))
    }

    /// Perform a single non-blocking attempt to materialize `<runs_dir>/run-<job_id>/` and
    /// acquire `.run.lock` under `.gc.lock`. Never sleeps internally so async callers can
    /// retry with `tokio::time::sleep` instead of blocking a thread.
    fn try_init_once(&self) -> Result<InitAttempt> {
        if self.init_done.load(Ordering::Acquire) {
            return Ok(InitAttempt::Ready(self.planned_path()));
        }

        let mut guard = self.initialized.lock().expect("LazyRunDir mutex poisoned");
        if let Some(ref init) = *guard {
            return Ok(InitAttempt::Ready(init.dir.clone()));
        }

        std::fs::create_dir_all(&self.runs_dir)
            .map_err(|e| Error::io(format!("create runs dir `{}`", self.runs_dir.display()), e))?;
        // Coordinate briefly with `.gc.lock` so a concurrent sweeper cannot unlink
        // the brand-new directory between `create_dir_all` and `.run.lock` acquisition.
        let gc_lock_path = self.runs_dir.join(".gc.lock");
        let gc_guard = match ProcessLock::try_acquire_file(&gc_lock_path) {
            Ok(lock) => lock,
            Err(e) => return Ok(InitAttempt::GcLockContended(e)),
        };

        let dir = self.planned_path();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::io(format!("create run dir `{}`", dir.display()), e))?;
        let lock = ProcessLock::try_acquire_file(&dir.join(".run.lock"))?;
        drop(gc_guard);

        *guard = Some(InitializedRunDir {
            dir: dir.clone(),
            run_lock: Some(lock),
        });
        self.init_done.store(true, Ordering::Release);
        Ok(InitAttempt::Ready(dir))
    }
}

/// Lazily-materialized per-job ephemeral scratch directory `<runs_dir>/run-<job_id>/`
/// guarded by `.run.lock`.
///
/// Small/everyday runs that never spill to SQLite, `--strict-source`, S3 disk spools,
/// or `delete.log` never create any directory or lock file on disk. When the last
/// [`LazyRunDir`] clone drops, the entire `run-<job_id>/` tree is deleted automatically.
#[derive(Clone)]
pub struct LazyRunDir {
    inner: Arc<LazyRunDirInner>,
}

impl LazyRunDir {
    pub fn new(runs_dir: PathBuf, job_id: impl AsRef<str>) -> Self {
        Self {
            inner: Arc::new(LazyRunDirInner {
                runs_dir,
                safe_id: sanitize_job_id(job_id.as_ref()),
                init_done: AtomicBool::new(false),
                initialized: StdMutex::new(None),
            }),
        }
    }

    /// Return the planned path of `<runs_dir>/run-<job_id>/` without creating it.
    pub fn planned_path(&self) -> PathBuf {
        self.inner.planned_path()
    }

    /// Whether this run directory has been materialized on disk.
    pub fn is_initialized(&self) -> bool {
        self.inner.init_done.load(Ordering::Acquire)
    }

    /// Lazily create `<runs_dir>/run-<job_id>/` and acquire `.run.lock` race-freely
    /// against concurrent [`sweep_stale_runs`] calls.
    ///
    /// On a Tokio multi-thread worker this transitions via `block_in_place` so GC-lock
    /// retries never stall the async executor. Async callers (especially on
    /// `current_thread` runtimes) should prefer [`Self::ensure_dir_async`].
    pub fn ensure_dir(&self) -> Result<PathBuf> {
        if self.inner.init_done.load(Ordering::Acquire) {
            return Ok(self.planned_path());
        }
        run_blocking_fs(|| {
            for attempt in 0..GC_LOCK_MAX_ATTEMPTS {
                match self.inner.try_init_once()? {
                    InitAttempt::Ready(dir) => return Ok(dir),
                    InitAttempt::GcLockContended(_) if attempt + 1 < GC_LOCK_MAX_ATTEMPTS => {
                        std::thread::sleep(GC_LOCK_RETRY_DELAY);
                    }
                    InitAttempt::GcLockContended(e) => return Err(e),
                }
            }
            unreachable!("loop always returns")
        })
    }

    /// Async version of [`Self::ensure_dir`] that runs filesystem and lock operations on
    /// Tokio's blocking pool and awaits [`tokio::time::sleep`] between `.gc.lock` retries,
    /// keeping async executor threads completely unblocked on both `multi_thread` and
    /// `current_thread` runtimes.
    pub async fn ensure_dir_async(&self) -> Result<PathBuf> {
        if self.inner.init_done.load(Ordering::Acquire) {
            return Ok(self.planned_path());
        }
        for attempt in 0..GC_LOCK_MAX_ATTEMPTS {
            let inner = self.inner.clone();
            let outcome = tokio::task::spawn_blocking(move || inner.try_init_once())
                .await
                .map_err(|e| Error::state_store(format!("ensure_dir_async join: {e}")))??;
            match outcome {
                InitAttempt::Ready(dir) => return Ok(dir),
                InitAttempt::GcLockContended(_) if attempt + 1 < GC_LOCK_MAX_ATTEMPTS => {
                    // Deliberately real time, not `Clock::sleep`: this waits for another
                    // *process* to release its `.gc.lock` file lock. An instant-sleep DST
                    // clock would burn every retry before that process could make progress.
                    tokio::time::sleep(GC_LOCK_RETRY_DELAY).await;
                }
                InitAttempt::GcLockContended(e) => return Err(e),
            }
        }
        unreachable!("loop always returns")
    }

    /// Lazily create and return `<runs_dir>/run-<job_id>/<name>`.
    pub fn ensure_subdir(&self, name: &str) -> Result<PathBuf> {
        run_blocking_fs(|| {
            let sub = self.ensure_dir()?.join(name);
            std::fs::create_dir_all(&sub)
                .map_err(|e| Error::io(format!("create run subdir `{}`", sub.display()), e))?;
            Ok(sub)
        })
    }

    /// Async version of [`Self::ensure_subdir`], running all filesystem work off async threads.
    pub async fn ensure_subdir_async(&self, name: &str) -> Result<PathBuf> {
        let sub = self.ensure_dir_async().await?.join(name);
        let sub_clone = sub.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&sub_clone)
                .map_err(|e| Error::io(format!("create run subdir `{}`", sub_clone.display()), e))
        })
        .await
        .map_err(|e| Error::state_store(format!("ensure_subdir_async join: {e}")))??;
        Ok(sub)
    }
}

impl std::fmt::Debug for LazyRunDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyRunDir")
            .field("planned_path", &self.planned_path())
            .field("initialized", &self.is_initialized())
            .finish()
    }
}

#[async_trait::async_trait]
impl rship_core::state::RunScratchDir for LazyRunDir {
    async fn ensure_subdir(&self, name: &str) -> Result<PathBuf> {
        self.ensure_subdir_async(name).await
    }
}

/// Reclaim orphaned `run-*` directories (and any legacy `sync-*.db` files) under
/// `runs_dir` left behind by crashed processes. Active runs holding `.run.lock` and
/// brand-new directories (< 10s old) are skipped safely.
pub fn sweep_stale_runs(runs_dir: &Path) -> usize {
    sweep_stale_runs_with_min_age(runs_dir, SWEEP_MIN_AGE)
}

/// Same as [`sweep_stale_runs`] with an explicit minimum directory age guard.
///
/// On a Tokio multi-thread worker this transitions via `block_in_place` so filesystem
/// traversal never stalls async tasks. Async callers can also use
/// [`sweep_stale_runs_with_min_age_async`].
pub fn sweep_stale_runs_with_min_age(runs_dir: &Path, min_age: Duration) -> usize {
    run_blocking_fs(|| sweep_stale_runs_blocking(runs_dir, min_age))
}

/// Async version of [`sweep_stale_runs`] executing on Tokio's blocking pool.
pub async fn sweep_stale_runs_async(runs_dir: PathBuf) -> usize {
    sweep_stale_runs_with_min_age_async(runs_dir, SWEEP_MIN_AGE).await
}

/// Async version of [`sweep_stale_runs_with_min_age`] executing on Tokio's blocking pool.
pub async fn sweep_stale_runs_with_min_age_async(runs_dir: PathBuf, min_age: Duration) -> usize {
    tokio::task::spawn_blocking(move || sweep_stale_runs_blocking(&runs_dir, min_age))
        .await
        .unwrap_or(0)
}

fn sweep_stale_runs_blocking(runs_dir: &Path, min_age: Duration) -> usize {
    if !runs_dir.exists() {
        return 0;
    }
    // Non-blocking coordination lock with `LazyRunDir::ensure_dir`: if another process is
    // currently creating a run dir or sweeping, skip cleanly without blocking startup.
    let Ok(_gc_lock) = ProcessLock::try_acquire_file(&runs_dir.join(".gc.lock")) else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(runs_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut reclaimed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if path.is_dir() && name.starts_with("run-") {
            if !min_age.is_zero()
                && let Ok(meta) = entry.metadata()
                && let Ok(modified) = meta.modified()
                && let Ok(age) = now.duration_since(modified)
                && age < min_age
            {
                continue;
            }
            let lock_path = path.join(".run.lock");
            if let Ok(lock) = ProcessLock::try_acquire_file(&lock_path) {
                drop(lock);
                if std::fs::remove_dir_all(&path).is_ok() {
                    reclaimed += 1;
                }
            }
        } else if path.is_file()
            && name.starts_with("sync-")
            && (name.ends_with(".db")
                || name.ends_with(".db-journal")
                || name.ends_with(".db-wal")
                || name.ends_with(".db-shm"))
            && std::fs::remove_file(&path).is_ok()
        {
            reclaimed += 1;
        }
    }
    reclaimed
}
