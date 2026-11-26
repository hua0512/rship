//! Adaptive hybrid ephemeral `SyncDiffIndex` (`SqliteSyncIndex` / `AdaptiveHybridDiffIndex`)
//! plus lazy per-run scratch directory (`LazyRunDir`) and race-free stale-run sweeper.
//!
//! - **Small/everyday runs (`<= 32,768` entries across `src + dst`)**: stay 100% in RAM
//!   (`Vec<Entry>` + `<0.5ms` `sort_by` + linear conflict scan + direct slice cursor merge).
//!   Zero directories, zero `.run.lock` files, zero SQLite connections, zero `spawn_blocking`.
//! - **Large runs (`> 32,768` entries)**: transparently spill to `LazyRunDir` (`run-<job_id>/`)
//!   with separate append-only `src_raw.db` and `dst_raw.db` (`auto_vacuum = NONE`), external-sort
//!   each via `ATTACH DATABASE` into `WITHOUT ROWID` `src_sorted`/`dst_sorted` in `sorted.db`,
//!   immediately unlink (`O(1)`) each raw DB, and serve sequential dual forward-cursor merges.

mod memory;
mod run_dir;
mod sqlite;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use rship_core::state::{DiffRow, SyncConflict, SyncDiffIndex};
use rship_core::types::Entry;
use rship_core::{Error, Result};
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::Mutex as AsyncMutex;

use memory::InMemoryReadState;
use run_dir::run_blocking_fs;
use sqlite::{SpilledReadState, SpilledSide};

pub use run_dir::{
    LazyRunDir, sweep_stale_runs, sweep_stale_runs_async, sweep_stale_runs_with_min_age,
    sweep_stale_runs_with_min_age_async,
};

/// Total entry ceiling (`src + dst`) kept in RAM before transparently spilling to SQLite.
/// `32,768` entries occupy ~6–8 MiB and sort in `< 0.5 ms`.
pub const DEFAULT_RAM_SPILL_THRESHOLD: usize = 32_768;

enum SideIngest {
    InMemory(Vec<Entry>),
    Spilled(SpilledSide),
    Finalized,
}

enum ReadState {
    Unfinalized,
    InMemory(InMemoryReadState),
    Spilled(Box<SpilledReadState>),
}

#[cfg(test)]
type RawWriteHook = Arc<dyn Fn(bool) + Send + Sync>;

struct IndexShared {
    spill_threshold: usize,
    run_dir: Option<LazyRunDir>,
    total_entries: AtomicUsize,
    spilled: AtomicBool,
    sorted_total_bytes: AtomicU64,
    sorted_freelist_bytes: AtomicU64,
    sorted_auto_vacuum: AtomicI64,
    #[cfg(test)]
    raw_write_hook: StdMutex<Option<RawWriteHook>>,
}

struct IndexHandles {
    /// Independent source-side writer state (`src_raw.db` once spilled).
    src: Arc<AsyncMutex<SideIngest>>,
    /// Independent destination-side writer state (`dst_raw.db` once spilled).
    dst: Arc<AsyncMutex<SideIngest>>,
    /// Finalized read/cursor state (`sorted.db` once spilled).
    read: Arc<AsyncMutex<ReadState>>,
    /// Shared configuration and lock-free diagnostics; declared LAST so `src`, `dst`, and
    /// `read` drop (closing all SQLite handles) before `shared.run_dir` releases.
    shared: Arc<IndexShared>,
}

/// Adaptive hybrid ephemeral diff index: pure RAM up to `spill_threshold` (default 32,768),
/// spilling transparently to split-DB external-sorted SQLite for larger trees.
///
/// Source and destination ingestion hold completely separate async mutexes (`src` vs `dst`)
/// whose owned guards are moved into `tokio::task::spawn_blocking` for SQLite I/O, so:
/// - concurrent `insert_src_batch` and `insert_dst_batch` writes run truly in parallel;
/// - Tokio async executor threads never block on a `std::sync::Mutex` held by SQLite I/O.
pub struct SqliteSyncIndex {
    handles: Option<IndexHandles>,
    run_dir: Option<LazyRunDir>,
}

/// Alias highlighting the adaptive RAM -> split-SQLite spill behavior.
pub type AdaptiveHybridDiffIndex = SqliteSyncIndex;

impl SqliteSyncIndex {
    /// Open an adaptive diff index backed lazily by `<runs_dir>/run-<job_id>/`.
    /// Small runs (`<= 32,768` entries) stay purely in RAM with zero filesystem I/O.
    ///
    /// Performs no filesystem or locking syscalls on construction; safe to call directly
    /// from async code.
    pub fn open_temp(runs_dir: &Path, job_id: &str) -> Result<Self> {
        Ok(Self::open_with_run_dir(
            LazyRunDir::new(runs_dir.to_path_buf(), job_id),
            DEFAULT_RAM_SPILL_THRESHOLD,
        ))
    }

    /// Open an adaptive diff index sharing an existing [`LazyRunDir`] and explicit spill threshold.
    pub fn open_with_run_dir(run_dir: LazyRunDir, spill_threshold: usize) -> Self {
        let shared = Arc::new(IndexShared {
            spill_threshold,
            run_dir: Some(run_dir.clone()),
            total_entries: AtomicUsize::new(0),
            spilled: AtomicBool::new(false),
            sorted_total_bytes: AtomicU64::new(0),
            sorted_freelist_bytes: AtomicU64::new(0),
            sorted_auto_vacuum: AtomicI64::new(0),
            #[cfg(test)]
            raw_write_hook: StdMutex::new(None),
        });
        Self {
            handles: Some(IndexHandles {
                src: Arc::new(AsyncMutex::new(SideIngest::InMemory(Vec::new()))),
                dst: Arc::new(AsyncMutex::new(SideIngest::InMemory(Vec::new()))),
                read: Arc::new(AsyncMutex::new(ReadState::Unfinalized)),
                shared,
            }),
            run_dir: Some(run_dir),
        }
    }

    /// Open an adaptive diff index with a custom spill threshold (useful for tests/benchmarks).
    pub fn open_temp_with_threshold(
        runs_dir: &Path,
        job_id: &str,
        spill_threshold: usize,
    ) -> Result<Self> {
        Ok(Self::open_with_run_dir(
            LazyRunDir::new(runs_dir.to_path_buf(), job_id),
            spill_threshold,
        ))
    }

    /// Open a purely in-memory index (never spills to disk).
    pub fn open_in_memory() -> Result<Self> {
        let shared = Arc::new(IndexShared {
            spill_threshold: usize::MAX,
            run_dir: None,
            total_entries: AtomicUsize::new(0),
            spilled: AtomicBool::new(false),
            sorted_total_bytes: AtomicU64::new(0),
            sorted_freelist_bytes: AtomicU64::new(0),
            sorted_auto_vacuum: AtomicI64::new(0),
            #[cfg(test)]
            raw_write_hook: StdMutex::new(None),
        });
        Ok(Self {
            handles: Some(IndexHandles {
                src: Arc::new(AsyncMutex::new(SideIngest::InMemory(Vec::new()))),
                dst: Arc::new(AsyncMutex::new(SideIngest::InMemory(Vec::new()))),
                read: Arc::new(AsyncMutex::new(ReadState::Unfinalized)),
                shared,
            }),
            run_dir: None,
        })
    }

    fn handles(&self) -> &IndexHandles {
        self.handles
            .as_ref()
            .expect("SqliteSyncIndex handles taken only in Drop")
    }

    #[cfg(test)]
    fn set_raw_write_hook(&self, hook: RawWriteHook) {
        *self.handles().shared.raw_write_hook.lock().unwrap() = Some(hook);
    }

    /// Whether this index has spilled to disk-backed SQLite.
    pub fn is_spilled(&self) -> bool {
        self.handles().shared.spilled.load(Ordering::Acquire)
    }

    /// Access the shared [`LazyRunDir`] handle when disk-backed spilling is configured.
    pub fn run_dir(&self) -> Option<&LazyRunDir> {
        self.run_dir.as_ref()
    }

    /// Return `(total_bytes, freelist_bytes, auto_vacuum_mode)` for diagnostics/benchmarks.
    /// Returns `(0, 0, 0)` while running purely in RAM.
    pub fn db_diagnostics(&self) -> (u64, u64, i64) {
        let s = &self.handles().shared;
        (
            s.sorted_total_bytes.load(Ordering::Acquire),
            s.sorted_freelist_bytes.load(Ordering::Acquire),
            s.sorted_auto_vacuum.load(Ordering::Acquire),
        )
    }

    /// Return the current sorted SQLite database size in bytes (`0` if purely in RAM).
    pub fn db_size_bytes(&self) -> u64 {
        self.db_diagnostics().0
    }
}

impl Drop for SqliteSyncIndex {
    fn drop(&mut self) {
        let needs_fs_cleanup = self
            .handles
            .as_ref()
            .is_some_and(|h| h.shared.spilled.load(Ordering::Acquire))
            || self
                .run_dir
                .as_ref()
                .is_some_and(LazyRunDir::is_initialized);

        if needs_fs_cleanup {
            run_blocking_fs(|| {
                // Close all SQLite connections (owned inside `handles`) BEFORE releasing
                // `run_dir` so Windows can cleanly remove the scratch directory.
                let _ = self.handles.take();
                let _ = self.run_dir.take();
            });
        } else {
            let _ = self.handles.take();
            let _ = self.run_dir.take();
        }
    }
}

#[cfg(test)]
fn invoke_raw_write_hook(shared: &IndexShared, is_src: bool) {
    let hook = shared.raw_write_hook.lock().unwrap().clone();
    if let Some(cb) = hook {
        cb(is_src);
    }
}

async fn insert_side_batch(
    side_lock: &Arc<AsyncMutex<SideIngest>>,
    shared: &Arc<IndexShared>,
    is_src: bool,
    entries: Vec<Entry>,
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    // Acquire ONLY this side's async mutex: never blocks a Tokio worker thread and never
    // serializes `src` against `dst`.
    let mut guard = side_lock.clone().lock_owned().await;

    match &mut *guard {
        SideIngest::Finalized => {
            return Err(Error::state_store(if is_src {
                "src_raw connection already finalized"
            } else {
                "dst_raw connection already finalized"
            }));
        }
        SideIngest::InMemory(buf) => {
            let batch_len = entries.len();
            if shared.run_dir.is_none() {
                buf.extend(entries);
                shared.total_entries.fetch_add(batch_len, Ordering::Relaxed);
                return Ok(());
            }

            let stay_in_ram = !shared.spilled.load(Ordering::Acquire)
                && shared
                    .total_entries
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                        let next = cur.saturating_add(batch_len);
                        (next <= shared.spill_threshold).then_some(next)
                    })
                    .is_ok();

            if stay_in_ram {
                buf.extend(entries);
                return Ok(());
            }

            // Spill threshold exceeded (or opposite side already spilled): ensure the run
            // directory asynchronously off-thread (never sleeping on async workers), then
            // move our owned per-side guard into `spawn_blocking` for SQLite ingest.
            let run_dir = shared
                .run_dir
                .as_ref()
                .expect("checked run_dir is Some")
                .clone();
            let dir = run_dir.ensure_dir_async().await?;
            let shared_clone = shared.clone();
            return tokio::task::spawn_blocking(move || {
                let res = match &mut *guard {
                    SideIngest::InMemory(buffered) => {
                        let spilled = SpilledSide::create_and_spill(
                            run_dir,
                            dir,
                            is_src,
                            buffered.as_slice(),
                            entries.as_slice(),
                            #[cfg(test)]
                            || invoke_raw_write_hook(&shared_clone, is_src),
                        )?;
                        *guard = SideIngest::Spilled(spilled);
                        shared_clone.spilled.store(true, Ordering::Release);
                        Ok(())
                    }
                    SideIngest::Spilled(sp) => sp.write_batch(
                        is_src,
                        entries.as_slice(),
                        #[cfg(test)]
                        || invoke_raw_write_hook(&shared_clone, is_src),
                    ),
                    SideIngest::Finalized => Err(Error::state_store(if is_src {
                        "src_raw connection already finalized"
                    } else {
                        "dst_raw connection already finalized"
                    })),
                };
                drop(guard);
                drop(shared_clone);
                res
            })
            .await
            .map_err(|e| Error::state_store(format!("sync index task join: {e}")))?;
        }
        SideIngest::Spilled(_) => {}
    }

    let shared_clone = shared.clone();
    tokio::task::spawn_blocking(move || {
        let res = match &mut *guard {
            SideIngest::Spilled(sp) => sp.write_batch(
                is_src,
                entries.as_slice(),
                #[cfg(test)]
                || invoke_raw_write_hook(&shared_clone, is_src),
            ),
            SideIngest::InMemory(_) | SideIngest::Finalized => Err(Error::state_store(if is_src {
                "src_raw connection already finalized"
            } else {
                "dst_raw connection already finalized"
            })),
        };
        drop(guard);
        drop(shared_clone);
        res
    })
    .await
    .map_err(|e| Error::state_store(format!("sync index task join: {e}")))?
}

#[async_trait]
impl SyncDiffIndex for SqliteSyncIndex {
    async fn insert_src_batch(&self, entries: Vec<Entry>) -> Result<()> {
        let handles = self.handles();
        insert_side_batch(&handles.src, &handles.shared, true, entries).await
    }

    async fn insert_dst_batch(&self, entries: Vec<Entry>) -> Result<()> {
        let handles = self.handles();
        insert_side_batch(&handles.dst, &handles.shared, false, entries).await
    }

    async fn finalize_and_detect_conflicts(
        &self,
        dst_case_sensitive: bool,
    ) -> Result<Vec<SyncConflict>> {
        let handles = self.handles();
        // Acquire locks in strict acyclic order (`read` -> `src` -> `dst`) via async `.await`.
        let mut read_guard = handles.read.clone().lock_owned().await;
        match &*read_guard {
            ReadState::InMemory(mem) => return Ok(mem.conflicts().to_vec()),
            ReadState::Spilled(_) => {
                return tokio::task::spawn_blocking(move || match &*read_guard {
                    ReadState::InMemory(mem) => Ok(mem.conflicts().to_vec()),
                    ReadState::Unfinalized => Err(Error::state_store("sync index not finalized")),
                    ReadState::Spilled(sp) => sp.load_conflicts(),
                })
                .await
                .map_err(|e| Error::state_store(format!("finalize sync index join: {e}")))?;
            }
            ReadState::Unfinalized => {}
        }

        let mut src_guard = handles.src.clone().lock_owned().await;
        let mut dst_guard = handles.dst.clone().lock_owned().await;

        let any_spilled = matches!(&*src_guard, SideIngest::Spilled(_))
            || matches!(&*dst_guard, SideIngest::Spilled(_));

        if !any_spilled {
            // Pure in-memory finalize avoids `spawn_blocking` overhead completely for small trees.
            let src = match std::mem::replace(&mut *src_guard, SideIngest::Finalized) {
                SideIngest::InMemory(v) => v,
                SideIngest::Spilled(_) | SideIngest::Finalized => unreachable!(),
            };
            let dst = match std::mem::replace(&mut *dst_guard, SideIngest::Finalized) {
                SideIngest::InMemory(v) => v,
                SideIngest::Spilled(_) | SideIngest::Finalized => unreachable!(),
            };
            drop(dst_guard);
            drop(src_guard);
            let (mem_state, conflicts) = InMemoryReadState::finalize(src, dst, dst_case_sensitive);
            *read_guard = ReadState::InMemory(mem_state);
            return Ok(conflicts);
        }

        let shared = handles.shared.clone();
        tokio::task::spawn_blocking(move || {
            let res = (|| {
                if let ReadState::Spilled(ref sp) = *read_guard {
                    return sp.load_conflicts();
                }
                let run_dir = shared
                    .run_dir
                    .as_ref()
                    .ok_or_else(|| Error::state_store("spilled SyncDiffIndex missing LazyRunDir"))?
                    .clone();
                let outcome = SpilledReadState::finalize(
                    run_dir,
                    &mut src_guard,
                    &mut dst_guard,
                    dst_case_sensitive,
                )?;
                // Cache immutable sorted.db diagnostics so `db_diagnostics()` / `db_size_bytes()`
                // are lock-free and never query SQLite on async worker threads.
                shared
                    .sorted_total_bytes
                    .store(outcome.total_bytes, Ordering::Release);
                shared
                    .sorted_freelist_bytes
                    .store(outcome.freelist_bytes, Ordering::Release);
                shared
                    .sorted_auto_vacuum
                    .store(outcome.auto_vacuum, Ordering::Release);
                *read_guard = ReadState::Spilled(Box::new(outcome.state));
                Ok(outcome.conflicts)
            })();
            drop(dst_guard);
            drop(src_guard);
            drop(read_guard);
            drop(shared);
            res
        })
        .await
        .map_err(|e| Error::state_store(format!("finalize sync index join: {e}")))?
    }

    async fn list_conflicts(&self) -> Result<Vec<SyncConflict>> {
        let handles = self.handles();
        let read_guard = handles.read.clone().lock_owned().await;
        match &*read_guard {
            ReadState::InMemory(mem) => Ok(mem.conflicts().to_vec()),
            ReadState::Unfinalized => {
                if handles.shared.spilled.load(Ordering::Acquire) {
                    Err(Error::state_store("sync index not finalized"))
                } else {
                    Ok(Vec::new())
                }
            }
            ReadState::Spilled(_) => tokio::task::spawn_blocking(move || match &*read_guard {
                ReadState::InMemory(mem) => Ok(mem.conflicts().to_vec()),
                ReadState::Unfinalized => Err(Error::state_store("sync index not finalized")),
                ReadState::Spilled(sp) => sp.load_conflicts(),
            })
            .await
            .map_err(|e| Error::state_store(format!("list conflicts join: {e}")))?,
        }
    }

    async fn next_src_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let handles = self.handles();
        let mut read_guard = handles.read.clone().lock_owned().await;
        match &mut *read_guard {
            ReadState::InMemory(mem) => Ok(mem.next_src_page(after_id, limit)),
            ReadState::Unfinalized => {
                if handles.shared.spilled.load(Ordering::Acquire) {
                    Err(Error::state_store("sync index not finalized"))
                } else {
                    Ok(Vec::new())
                }
            }
            ReadState::Spilled(_) => tokio::task::spawn_blocking(move || match &mut *read_guard {
                ReadState::InMemory(mem) => Ok(mem.next_src_page(after_id, limit)),
                ReadState::Unfinalized => Err(Error::state_store("sync index not finalized")),
                ReadState::Spilled(sp) => sp.next_src_page(after_id, limit),
            })
            .await
            .map_err(|e| Error::state_store(format!("next_src_page join: {e}")))?,
        }
    }

    async fn next_dst_only_page(&self, after_id: i64, limit: usize) -> Result<Vec<DiffRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let handles = self.handles();
        let mut read_guard = handles.read.clone().lock_owned().await;
        match &mut *read_guard {
            ReadState::InMemory(mem) => Ok(mem.next_dst_only_page(after_id, limit)),
            ReadState::Unfinalized => {
                if handles.shared.spilled.load(Ordering::Acquire) {
                    Err(Error::state_store("sync index not finalized"))
                } else {
                    Ok(Vec::new())
                }
            }
            ReadState::Spilled(_) => tokio::task::spawn_blocking(move || match &mut *read_guard {
                ReadState::InMemory(mem) => Ok(mem.next_dst_only_page(after_id, limit)),
                ReadState::Unfinalized => Err(Error::state_store("sync index not finalized")),
                ReadState::Spilled(sp) => sp.next_dst_only_page(after_id, limit),
            })
            .await
            .map_err(|e| Error::state_store(format!("next_dst_only_page join: {e}")))?,
        }
    }
}
