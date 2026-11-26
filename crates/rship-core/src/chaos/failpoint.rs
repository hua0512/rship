use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(doc)]
use super::ChaosBackend;
use crate::backend::CompletedPart;
use crate::engine::CancelFlag;
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::state::{BaselineRecord, BisyncPairState, JobRecord, JournalStore, OperationRecord};

/// Shared monotonic failpoint step counter coordinated across [`FailingJournalStore`]
/// and [`ChaosBackend`] so every observable journal write AND remote commit boundary
/// is numbered `1..=N` for crash-at-every-step `k` sweeps.
#[derive(Debug, Clone)]
pub struct FailpointCoordinator {
    step: Arc<AtomicUsize>,
    crash_at_step: Arc<AtomicUsize>,
    crashed: Arc<AtomicBool>,
    cancel: Option<CancelFlag>,
    trace: Arc<Mutex<Vec<(usize, &'static str)>>>,
}

impl FailpointCoordinator {
    /// Create a new unarmed coordinator (`crash_at_step = 0` for dry-counting baseline runs).
    pub fn new(cancel: Option<CancelFlag>) -> Self {
        Self::with_shared_counter(Arc::new(AtomicUsize::new(0)), cancel)
    }

    /// Create a coordinator backed by a caller-supplied shared monotonic counter.
    pub fn with_shared_counter(step: Arc<AtomicUsize>, cancel: Option<CancelFlag>) -> Self {
        Self {
            step,
            crash_at_step: Arc::new(AtomicUsize::new(0)),
            crashed: Arc::new(AtomicBool::new(false)),
            cancel,
            trace: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Expose the shared monotonic step counter (`Arc<AtomicUsize>`).
    pub fn step_counter(&self) -> Arc<AtomicUsize> {
        self.step.clone()
    }

    /// Arm a simulated crash at exact 1-based boundary `step` (`0` disables crashing).
    pub fn arm_crash_at(&self, step: usize) {
        self.crashed.store(false, Ordering::SeqCst);
        self.crash_at_step.store(step, Ordering::SeqCst);
    }

    /// Disarm crashing and clear the crashed latch.
    pub fn disarm(&self) {
        self.crash_at_step.store(0, Ordering::SeqCst);
        self.crashed.store(false, Ordering::SeqCst);
    }

    /// Total boundary steps observed so far.
    pub fn steps_reached(&self) -> usize {
        self.step.load(Ordering::SeqCst)
    }

    /// Returns `true` once the armed crash failpoint has fired.
    pub fn is_crashed(&self) -> bool {
        self.crashed.load(Ordering::SeqCst)
    }

    /// Snapshot the ordered `(step_number, label)` trace of all crossed boundaries.
    pub fn trace(&self) -> Vec<(usize, &'static str)> {
        self.trace.lock().unwrap().clone()
    }

    /// Reject any post-crash write/mutation attempt so unwinding cleanup cannot mutate
    /// persisted state after a simulated instant `SIGKILL` crash.
    pub fn check_not_crashed(&self) -> Result<()> {
        if self.crashed.load(Ordering::SeqCst) {
            return Err(Error::cancelled(
                "simulated crash already triggered at failpoint",
            ));
        }
        Ok(())
    }

    /// Record crossing boundary `label` and trigger a simulated crash if `step == crash_at_step`.
    pub fn hit(&self, label: &'static str) -> Result<()> {
        self.check_not_crashed()?;
        let n = self.step.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut t) = self.trace.lock() {
            t.push((n, label));
        }
        let target = self.crash_at_step.load(Ordering::SeqCst);
        if target != 0 && n == target {
            self.crashed.store(true, Ordering::SeqCst);
            if let Some(ref cancel) = self.cancel {
                cancel.cancel();
            }
            return Err(Error::cancelled(format!(
                "simulated crash at failpoint step {n} ({label})"
            )));
        }
        Ok(())
    }
}

/// Write/commit boundary on [`JournalStore`] where [`FailingJournalStore`] can inject faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalBoundary {
    UpsertJob,
    PutOperation,
    UpsertPart,
    DeleteOperation,
    CommitVerifiedTransfer,
    UpsertBaseline,
    DeleteBaseline,
    UpsertBisyncState,
}

/// Fault injected at a [`JournalBoundary`] by [`FailingJournalStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalFault {
    /// Fail BEFORE persisting with `Error::state_store(msg)` (simulating `SQLITE_FULL` / disk I/O error).
    StateStoreError(String),
    /// Trigger a simulated crash BEFORE persisting to the wrapped store.
    CrashBeforeWrite,
    /// Persist to the wrapped store, then immediately trigger a simulated crash AFTER writing.
    CrashAfterWrite,
}

#[derive(Debug, Default)]
struct FailingJournalState {
    faults: HashMap<JournalBoundary, VecDeque<(Option<usize>, JournalFault)>>,
    call_counts: HashMap<JournalBoundary, usize>,
    cancel: Option<CancelFlag>,
    coordinator: Option<FailpointCoordinator>,
}

/// Fault-injecting wrapper around any [`Arc<dyn JournalStore>`] supporting `SQLITE_FULL`
/// (`Error::state_store`) injection, before/after write crashes, and shared step-numbered
/// failpoint coordination with [`ChaosBackend`].
pub struct FailingJournalStore {
    inner: Arc<dyn JournalStore>,
    state: Mutex<FailingJournalState>,
}

impl std::fmt::Debug for FailingJournalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailingJournalStore")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl FailingJournalStore {
    pub fn new(inner: Arc<dyn JournalStore>) -> Self {
        Self {
            inner,
            state: Mutex::new(FailingJournalState::default()),
        }
    }

    pub fn with_coordinator(
        inner: Arc<dyn JournalStore>,
        coordinator: FailpointCoordinator,
    ) -> Self {
        let cancel = coordinator.cancel.clone();
        Self {
            inner,
            state: Mutex::new(FailingJournalState {
                cancel,
                coordinator: Some(coordinator),
                ..Default::default()
            }),
        }
    }

    pub fn set_coordinator(&self, coordinator: Option<FailpointCoordinator>) {
        let mut g = self.state.lock().unwrap();
        g.cancel = coordinator.as_ref().and_then(|c| c.cancel.clone());
        g.coordinator = coordinator;
    }

    pub fn set_cancel_flag(&self, cancel: Option<CancelFlag>) {
        self.state.lock().unwrap().cancel = cancel;
    }

    /// Inject `fault` on the next call to `boundary`.
    pub fn inject_fault(&self, boundary: JournalBoundary, fault: JournalFault) {
        self.state
            .lock()
            .unwrap()
            .faults
            .entry(boundary)
            .or_default()
            .push_back((None, fault));
    }

    /// Inject `fault` on the exact 1-based `nth_call` to `boundary`.
    pub fn inject_fault_on_call(
        &self,
        boundary: JournalBoundary,
        nth_call: usize,
        fault: JournalFault,
    ) {
        self.state
            .lock()
            .unwrap()
            .faults
            .entry(boundary)
            .or_default()
            .push_back((Some(nth_call.max(1)), fault));
    }

    pub fn clear_faults(&self) {
        self.state.lock().unwrap().faults.clear();
    }

    pub fn boundary_calls(&self, boundary: JournalBoundary) -> usize {
        self.state
            .lock()
            .unwrap()
            .call_counts
            .get(&boundary)
            .copied()
            .unwrap_or(0)
    }

    pub fn inner(&self) -> &Arc<dyn JournalStore> {
        &self.inner
    }

    fn take_fault_for(
        &self,
        boundary: JournalBoundary,
        secondary: Option<JournalBoundary>,
    ) -> (
        Option<JournalFault>,
        Option<CancelFlag>,
        Option<FailpointCoordinator>,
    ) {
        let mut g = self.state.lock().unwrap();
        let count = {
            let c = g.call_counts.entry(boundary).or_insert(0);
            *c += 1;
            *c
        };
        let mut matched = pop_matching_fault(&mut g.faults, boundary, count);
        if matched.is_none()
            && let Some(sec) = secondary
        {
            let sec_count = {
                let c = g.call_counts.entry(sec).or_insert(0);
                *c += 1;
                *c
            };
            matched = pop_matching_fault(&mut g.faults, sec, sec_count);
        }
        (matched, g.cancel.clone(), g.coordinator.clone())
    }

    async fn run_write<F, Fut>(
        &self,
        boundary: JournalBoundary,
        secondary: Option<JournalBoundary>,
        before_label: &'static str,
        after_label: &'static str,
        write_op: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let (fault, cancel, coord) = self.take_fault_for(boundary, secondary);
        if let Some(ref c) = coord {
            c.check_not_crashed()?;
        }
        match fault {
            Some(JournalFault::StateStoreError(msg)) => return Err(Error::state_store(msg)),
            Some(JournalFault::CrashBeforeWrite) => {
                if let Some(ref fl) = cancel {
                    fl.cancel();
                }
                return Err(Error::cancelled(format!(
                    "simulated crash at failpoint {before_label}"
                )));
            }
            Some(JournalFault::CrashAfterWrite) | None => {}
        }
        if let Some(ref c) = coord {
            c.hit(before_label)?;
        }
        write_op().await?;
        if let Some(ref c) = coord {
            c.hit(after_label)?;
        }
        if matches!(fault, Some(JournalFault::CrashAfterWrite)) {
            if let Some(ref fl) = cancel {
                fl.cancel();
            }
            return Err(Error::cancelled(format!(
                "simulated crash at failpoint {after_label}"
            )));
        }
        Ok(())
    }
}

fn pop_matching_fault(
    map: &mut HashMap<JournalBoundary, VecDeque<(Option<usize>, JournalFault)>>,
    boundary: JournalBoundary,
    call_num: usize,
) -> Option<JournalFault> {
    let queue = map.get_mut(&boundary)?;
    let pos = queue
        .iter()
        .position(|(nth, _)| nth.is_none() || *nth == Some(call_num))?;
    queue.remove(pos).map(|(_, f)| f)
}

#[async_trait]
impl JournalStore for FailingJournalStore {
    async fn upsert_job(&self, job: &JobRecord) -> Result<()> {
        self.run_write(
            JournalBoundary::UpsertJob,
            None,
            "journal:upsert_job:before",
            "journal:upsert_job:after",
            || self.inner.upsert_job(job),
        )
        .await
    }

    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>> {
        self.inner.get_job(job_id).await
    }

    async fn list_jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        self.inner.list_jobs(limit).await
    }

    async fn put_operation(&self, op: &OperationRecord) -> Result<()> {
        self.run_write(
            JournalBoundary::PutOperation,
            None,
            "journal:put_operation:before",
            "journal:put_operation:after",
            || self.inner.put_operation(op),
        )
        .await
    }

    async fn get_operation_by_key(&self, session_key: &str) -> Result<Option<OperationRecord>> {
        self.inner.get_operation_by_key(session_key).await
    }

    async fn list_active_operations(&self) -> Result<Vec<OperationRecord>> {
        self.inner.list_active_operations().await
    }

    async fn delete_operation(&self, op_id: &str) -> Result<()> {
        self.run_write(
            JournalBoundary::DeleteOperation,
            None,
            "journal:delete_operation:before",
            "journal:delete_operation:after",
            || self.inner.delete_operation(op_id),
        )
        .await
    }

    async fn upsert_part(&self, op_id: &str, part: &CompletedPart) -> Result<()> {
        self.run_write(
            JournalBoundary::UpsertPart,
            None,
            "journal:upsert_part:before",
            "journal:upsert_part:after",
            || self.inner.upsert_part(op_id, part),
        )
        .await
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
        let secondary = baseline.map(|_| JournalBoundary::UpsertBaseline);
        self.run_write(
            JournalBoundary::CommitVerifiedTransfer,
            secondary,
            "journal:commit_verified_transfer:before",
            "journal:commit_verified_transfer:after",
            || {
                self.inner
                    .commit_verified_transfer(op_id, baseline, job_id, bytes_transferred)
            },
        )
        .await
    }

    async fn get_baseline(
        &self,
        pair_key: &str,
        nfc_path: &RelPath,
    ) -> Result<Option<BaselineRecord>> {
        self.inner.get_baseline(pair_key, nfc_path).await
    }

    async fn get_baselines_batch(
        &self,
        pair_key: &str,
        nfc_paths: &[RelPath],
    ) -> Result<HashMap<RelPath, BaselineRecord>> {
        self.inner.get_baselines_batch(pair_key, nfc_paths).await
    }

    async fn delete_baseline(&self, pair_key: &str, nfc_path: &RelPath) -> Result<()> {
        self.run_write(
            JournalBoundary::DeleteBaseline,
            None,
            "journal:delete_baseline:before",
            "journal:delete_baseline:after",
            || self.inner.delete_baseline(pair_key, nfc_path),
        )
        .await
    }

    async fn delete_baselines_batch(&self, pair_key: &str, nfc_paths: &[RelPath]) -> Result<()> {
        self.run_write(
            JournalBoundary::DeleteBaseline,
            None,
            "journal:delete_baselines_batch:before",
            "journal:delete_baselines_batch:after",
            || self.inner.delete_baselines_batch(pair_key, nfc_paths),
        )
        .await
    }

    async fn delete_pair_baselines(&self, pair_key: &str) -> Result<()> {
        self.run_write(
            JournalBoundary::DeleteBaseline,
            None,
            "journal:delete_pair_baselines:before",
            "journal:delete_pair_baselines:after",
            || self.inner.delete_pair_baselines(pair_key),
        )
        .await
    }

    async fn next_baseline_page(
        &self,
        pair_key: &str,
        after_nfc_path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BaselineRecord>> {
        self.inner
            .next_baseline_page(pair_key, after_nfc_path, limit)
            .await
    }

    async fn get_bisync_state(&self, pair_key: &str) -> Result<Option<BisyncPairState>> {
        self.inner.get_bisync_state(pair_key).await
    }

    async fn upsert_bisync_state(&self, state: &BisyncPairState) -> Result<()> {
        self.run_write(
            JournalBoundary::UpsertBisyncState,
            None,
            "journal:upsert_bisync_state:before",
            "journal:upsert_bisync_state:after",
            || self.inner.upsert_bisync_state(state),
        )
        .await
    }
}
