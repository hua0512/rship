//! Durability fence between destination writes and the journal records that trust them.
//!
//! A backend whose committed writes become visible before they are durable
//! ([`StorageBackend::defers_durable_writes`], e.g. `LocalBackend` in `FsyncMode::Batch`)
//! must never have a journal record that lets a later run trust one of its files become
//! durable before that file's data is flushed. Those records are:
//!
//! - `sync_baseline` rows (a later run skips the file when the listing matches them),
//! - operation retirement (a later run then has no reason to reconcile the file),
//! - a finished job status (`Completed`, `CompletedWithConflicts`, `Paused`) and the bisync
//!   pair state.
//!
//! [`DurabilityFence`] wraps the engine's [`JournalStore`]. While any fenced backend defers
//! durability, every [`JournalStore::commit_verified_transfer`] is queued instead of being
//! written. A drain runs `flush_durable_writes` on every fenced backend and only then
//! commits the queued records, so each committed record covers data that was written
//! before the flush started. A drain runs:
//!
//! - when [`MAX_PENDING_COMMITS`] records are queued or the oldest is [`MAX_PENDING_AGE`]
//!   old (checked on every commit and every job heartbeat), which bounds memory and the
//!   amount of work a crash can discard,
//! - before a finished job status or bisync pair state is written, on success, cancel and
//!   error paths alike,
//! - at the engine's explicit finalize points ([`DurabilityFence::drain`]),
//! - before any write that touches a queued record's rows (ordering).
//!
//! Reads see queued records (read-your-writes): a queued operation retirement hides the
//! operation, and a queued baseline overrides the stored one.
//!
//! A failed flush (or commit) drops the queued batch, so none of its records is ever
//! written, and poisons the fence: every later commit and finished-status write fails, and
//! the job is recorded as `Failed`. Retrying the flush is not safe, because after a
//! write-back error the kernel may report a later `fsync` / `syncfs` as successful although
//! the data is gone.
//!
//! Records whose data the caller already made durable (the `move` pre-delete sync) bypass
//! the queue through [`JournalStore::commit_verified_transfer_durable`].

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use crate::backend::{CompletedPart, StorageBackend};
use crate::clock::Clock;
use crate::error::{Error, ErrorKind, Result, RetryClass};
use crate::path::RelPath;
use crate::state::{
    BaselineRecord, BisyncPairState, JobRecord, JobStatus, JournalStore, OperationRecord,
};

/// Queued commits that force a drain (one destination flush per batch).
pub(crate) const MAX_PENDING_COMMITS: usize = 1024;
/// Age of the oldest queued commit that forces a drain.
pub(crate) const MAX_PENDING_AGE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct PendingCommit {
    op_id: Option<String>,
    baseline: Option<BaselineRecord>,
    job_id: String,
    bytes: u64,
}

#[derive(Default)]
struct FenceState {
    queue: Vec<PendingCommit>,
    oldest_ns: Option<i64>,
    /// Operation retirements queued or being committed (hidden from reads).
    retired_ops: HashSet<String>,
    /// Baselines queued or being committed, keyed by `(pair_key, nfc_path)`.
    baselines: HashMap<(String, RelPath), BaselineRecord>,
    /// First flush/commit failure; once set, the fence refuses further trust records.
    failure: Option<(ErrorKind, String)>,
}

impl FenceState {
    fn failure_error(&self) -> Option<Error> {
        self.failure
            .as_ref()
            .map(|(kind, msg)| fence_error(*kind, msg))
    }

    fn forget(&mut self, batch: &[PendingCommit]) {
        for c in batch {
            if let Some(id) = &c.op_id {
                self.retired_ops.remove(id);
            }
            if let Some(b) = &c.baseline {
                self.baselines
                    .remove(&(b.pair_key.clone(), b.nfc_path.clone()));
            }
        }
    }
}

fn fence_error(kind: ErrorKind, msg: &str) -> Error {
    Error::new(
        kind,
        RetryClass::Permanent,
        format!(
            "destination durability flush failed earlier in this run; journal records for files written since the previous flush were not committed: {msg}"
        ),
    )
}

/// Journal wrapper that holds back trust records until the destination data is durable.
/// See the module documentation.
pub struct DurabilityFence {
    inner: Arc<dyn JournalStore>,
    backends: Vec<Arc<dyn StorageBackend>>,
    clock: Arc<dyn Clock>,
    /// `false` when no fenced backend defers durability: every call passes straight through.
    enabled: bool,
    state: StdMutex<FenceState>,
    /// Serializes drains, so a drain never commits records queued after its flush began.
    flush_lock: tokio::sync::Mutex<()>,
    self_ref: Weak<DurabilityFence>,
}

impl DurabilityFence {
    /// Wrap `inner`, fencing commits behind `flush_durable_writes` on every backend in
    /// `backends` (the destination, or both bisync sides).
    pub fn new(
        inner: Arc<dyn JournalStore>,
        backends: Vec<Arc<dyn StorageBackend>>,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let enabled = backends.iter().any(|b| b.defers_durable_writes());
        Arc::new_cyclic(|self_ref| Self {
            inner,
            backends,
            clock,
            enabled,
            state: StdMutex::new(FenceState::default()),
            flush_lock: tokio::sync::Mutex::new(()),
            self_ref: self_ref.clone(),
        })
    }

    /// Whether commits are being held back behind destination flushes.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of commits queued behind the next destination flush.
    pub fn pending_commits(&self) -> usize {
        self.lock().queue.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FenceState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush every fenced backend, then commit every queued record.
    ///
    /// Runs the flush even when nothing is queued, so callers can use it as the
    /// end-of-phase "make everything written so far durable" step.
    pub async fn drain(&self) -> Result<()> {
        self.drain_spawned(true).await
    }

    /// Drain only if something is queued (no flush otherwise).
    async fn drain_if_pending(&self) -> Result<()> {
        self.drain_spawned(false).await
    }

    /// Run the drain on its own task so dropping the caller (an aborted heartbeat or worker)
    /// can never leave a batch half-applied with stale read overlays.
    async fn drain_spawned(&self, always_flush: bool) -> Result<()> {
        if !always_flush {
            let st = self.lock();
            // Nothing queued and nothing in flight (an in-flight batch still has overlay
            // entries, and callers deduplicating against it must wait for it).
            if st.failure.is_none()
                && st.queue.is_empty()
                && st.retired_ops.is_empty()
                && st.baselines.is_empty()
            {
                return Ok(());
            }
        }
        let Some(this) = self.self_ref.upgrade() else {
            return self.drain_now(always_flush).await;
        };
        match tokio::spawn(async move { this.drain_now(always_flush).await }).await {
            Ok(res) => res,
            Err(join) => Err(Error::state_store(format!(
                "durability fence drain task failed: {join}"
            ))),
        }
    }

    async fn drain_now(&self, always_flush: bool) -> Result<()> {
        let _guard = self.flush_lock.lock().await;
        let batch = {
            let mut st = self.lock();
            if let Some(err) = st.failure_error() {
                return Err(err);
            }
            st.oldest_ns = None;
            std::mem::take(&mut st.queue)
        };
        if batch.is_empty() && !always_flush {
            return Ok(());
        }
        let res = self.flush_then_commit(&batch).await;
        let mut st = self.lock();
        st.forget(&batch);
        if let Err(e) = &res
            && st.failure.is_none()
        {
            st.failure = Some((e.kind, e.message.clone()));
        }
        res
    }

    async fn flush_then_commit(&self, batch: &[PendingCommit]) -> Result<()> {
        for backend in &self.backends {
            backend.flush_durable_writes().await?;
        }
        if batch.is_empty() {
            return Ok(());
        }
        // Concurrent submission lets the state actor group-commit the batch into one
        // transaction. Queued records never share a baseline key or an operation (a
        // duplicate key drains first), so their relative order does not matter.
        let results = futures::future::join_all(batch.iter().map(|c| {
            self.inner.commit_verified_transfer(
                c.op_id.as_deref(),
                c.baseline.as_ref(),
                &c.job_id,
                c.bytes,
            )
        }))
        .await;
        results.into_iter().collect::<Result<Vec<()>>>()?;
        Ok(())
    }

    fn due_by_age(&self, st: &FenceState) -> bool {
        st.oldest_ns.is_some_and(|t| {
            let age = self.clock.now_unix_nanos().saturating_sub(t);
            u128::try_from(age).unwrap_or(0) >= MAX_PENDING_AGE.as_nanos()
        })
    }

    fn baseline_pending(&self, pair_key: &str, nfc_path: &RelPath) -> bool {
        self.lock()
            .baselines
            .contains_key(&(pair_key.to_string(), nfc_path.clone()))
    }

    fn any_baseline_pending_for_pair(&self, pair_key: &str) -> bool {
        self.lock().baselines.keys().any(|(p, _)| p == pair_key)
    }

    fn op_pending(&self, op_id: &str) -> bool {
        self.lock().retired_ops.contains(op_id)
    }

    fn queue_nonempty(&self) -> bool {
        !self.lock().queue.is_empty()
    }
}

#[async_trait]
impl JournalStore for DurabilityFence {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()> {
        if !self.enabled {
            return self.inner.upsert_job(job).await;
        }
        match job.status {
            JobStatus::Completed | JobStatus::CompletedWithConflicts | JobStatus::Paused => {
                if let Err(err) = self.drain().await {
                    // The run cannot claim success: its last records never became durable.
                    let mut failed = job.clone();
                    failed.status = JobStatus::Failed;
                    let _ = self.inner.upsert_job(&failed).await;
                    return Err(err);
                }
            }
            JobStatus::Failed => {
                // Best effort: commit what was durably written before the failure. A failed
                // status vouches for nothing, so there is no flush when nothing is queued.
                let _ = self.drain_if_pending().await;
            }
            _ => {
                let due = {
                    let st = self.lock();
                    !st.queue.is_empty() && self.due_by_age(&st)
                };
                if due {
                    // A failure poisons the fence and surfaces at the next commit/finish.
                    let _ = self.drain_if_pending().await;
                }
            }
        }
        self.inner.upsert_job(job).await
    }

    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>> {
        if self.enabled && self.queue_nonempty() {
            self.drain_if_pending().await?;
        }
        self.inner.get_job(job_id).await
    }

    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        self.inner.list_jobs(limit).await
    }

    async fn put_operation(&self, op: &OperationRecord) -> Result<()> {
        if self.enabled && self.op_pending(&op.op_id) {
            self.drain_if_pending().await?;
        }
        self.inner.put_operation(op).await
    }

    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>> {
        let op = self.inner.get_operation_by_key(session_key).await?;
        if self.enabled
            && let Some(o) = &op
            && self.op_pending(&o.op_id)
        {
            return Ok(None);
        }
        Ok(op)
    }

    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>> {
        let mut ops = self.inner.list_active_operations().await?;
        if self.enabled {
            let st = self.lock();
            if !st.retired_ops.is_empty() {
                ops.retain(|o| !st.retired_ops.contains(&o.op_id));
            }
        }
        Ok(ops)
    }

    async fn delete_operation(&self, op_id: &str) -> Result<()> {
        self.inner.delete_operation(op_id).await
    }

    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()> {
        if self.enabled && self.op_pending(op_id) {
            self.drain_if_pending().await?;
        }
        self.inner.upsert_part(op_id, part).await
    }

    async fn list_parts(&self, op_id: &str) -> Result<Vec<CompletedPart>> {
        self.inner.list_parts(op_id).await
    }

    async fn commit_verified_transfer(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()> {
        if !self.enabled {
            return self
                .inner
                .commit_verified_transfer(op_id, baseline, job_id, bytes_transferred)
                .await;
        }
        if let Some(b) = baseline
            && self.baseline_pending(&b.pair_key, &b.nfc_path)
        {
            self.drain_if_pending().await?;
        }
        let due = {
            let mut st = self.lock();
            if let Some(err) = st.failure_error() {
                return Err(err);
            }
            if let Some(id) = op_id {
                st.retired_ops.insert(id.to_string());
            }
            if let Some(b) = baseline {
                st.baselines
                    .insert((b.pair_key.clone(), b.nfc_path.clone()), b.clone());
            }
            st.queue.push(PendingCommit {
                op_id: op_id.map(str::to_string),
                baseline: baseline.cloned(),
                job_id: job_id.to_string(),
                bytes: bytes_transferred,
            });
            if st.oldest_ns.is_none() {
                st.oldest_ns = Some(self.clock.now_unix_nanos());
            }
            st.queue.len() >= MAX_PENDING_COMMITS || self.due_by_age(&st)
        };
        if due {
            self.drain_if_pending().await?;
        }
        Ok(())
    }

    async fn commit_verified_transfer_durable(
        &self,
        op_id: Option<&str>,
        baseline: Option<&BaselineRecord>,
        job_id: &str,
        bytes_transferred: u64,
    ) -> Result<()> {
        if self.enabled {
            if let Some(err) = self.lock().failure_error() {
                return Err(err);
            }
            if let Some(b) = baseline
                && self.baseline_pending(&b.pair_key, &b.nfc_path)
            {
                self.drain_if_pending().await?;
            }
        }
        self.inner
            .commit_verified_transfer_durable(op_id, baseline, job_id, bytes_transferred)
            .await
    }

    async fn get_baseline(
        &self,
        pair_key: &str,
        nfc_path: &RelPath,
    ) -> Result<Option<BaselineRecord>> {
        if self.enabled
            && let Some(b) = self
                .lock()
                .baselines
                .get(&(pair_key.to_string(), nfc_path.clone()))
        {
            return Ok(Some(b.clone()));
        }
        self.inner.get_baseline(pair_key, nfc_path).await
    }

    async fn get_baselines_batch(
        &self,
        pair_key: &str,
        nfc_paths: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        let mut out = self.inner.get_baselines_batch(pair_key, nfc_paths).await?;
        if self.enabled {
            let st = self.lock();
            if !st.baselines.is_empty() {
                for p in nfc_paths {
                    if let Some(b) = st.baselines.get(&(pair_key.to_string(), p.clone())) {
                        out.insert(p.clone(), b.clone());
                    }
                }
            }
        }
        Ok(out)
    }

    async fn delete_baseline(&self, pair_key: &str, nfc_path: &RelPath) -> Result<()> {
        if self.enabled && self.baseline_pending(pair_key, nfc_path) {
            self.drain_if_pending().await?;
        }
        self.inner.delete_baseline(pair_key, nfc_path).await
    }

    async fn delete_baselines_batch(&self, pair_key: &str, nfc_paths: &[RelPath]) -> Result<()> {
        if self.enabled && nfc_paths.iter().any(|p| self.baseline_pending(pair_key, p)) {
            self.drain_if_pending().await?;
        }
        self.inner.delete_baselines_batch(pair_key, nfc_paths).await
    }

    async fn delete_pair_baselines(&self, pair_key: &str) -> Result<()> {
        if self.enabled && self.any_baseline_pending_for_pair(pair_key) {
            self.drain_if_pending().await?;
        }
        self.inner.delete_pair_baselines(pair_key).await
    }

    async fn next_baseline_page(
        &self,
        pair_key: &str,
        after_nfc_path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        if self.enabled && self.any_baseline_pending_for_pair(pair_key) {
            self.drain_if_pending().await?;
        }
        self.inner
            .next_baseline_page(pair_key, after_nfc_path, limit)
            .await
    }

    async fn get_bisync_state(&self, pair_key: &str) -> Result<Option<BisyncPairState>> {
        self.inner.get_bisync_state(pair_key).await
    }

    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        if self.enabled {
            self.drain().await?;
        }
        self.inner.upsert_bisync_state(state).await
    }
}
