//! Shared pull-driven bounded worker pool for both `TransferEngine::run` and
//! `TransferEngine::run_file_list` (supporting both fixed worker pools and Falcon
//! Dual-Lane adaptive concurrency).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex, Notify, mpsc};
use tracing::warn;

use crate::adaptive::{FalconConfig, FalconController, TransferLane};
use crate::error::{Error, Result, RetryClass};
use crate::progress::{JobEventEmitter, TransferProgress};
use crate::types::Capabilities;

use super::diff::SafeWatermarkTracker;
use super::task::{TransferOutcome, TransferTask, execute_transfer_task};
use super::{
    EngineConfig, FileTransferResult, MAX_REPORT_ERRORS, RunReport, TransferEngine,
    TransferErrorInfo, WORK_QUEUE_CAPACITY, push_file_result,
};

#[derive(Clone)]
struct SharedWorkerStats {
    files_transferred: Arc<AtomicU64>,
    files_skipped: Arc<AtomicU64>,
    server_side_copies: Arc<AtomicU64>,
    sources_deleted: Arc<AtomicU64>,
    bytes_transferred: Arc<AtomicU64>,
    errors_suppressed: Arc<AtomicU64>,
    results_capped: Arc<AtomicBool>,
    /// Set when [`TransferWorkerPool::send`] could not hand a task to any worker
    /// (every worker exited), so planned work was silently dropped.
    dispatch_failed: Arc<AtomicBool>,
    worker_errors: Arc<Mutex<Vec<TransferErrorInfo>>>,
    file_results: Arc<Mutex<(Vec<FileTransferResult>, bool)>>,
}

impl SharedWorkerStats {
    fn new() -> Self {
        Self {
            files_transferred: Arc::new(AtomicU64::new(0)),
            files_skipped: Arc::new(AtomicU64::new(0)),
            server_side_copies: Arc::new(AtomicU64::new(0)),
            sources_deleted: Arc::new(AtomicU64::new(0)),
            bytes_transferred: Arc::new(AtomicU64::new(0)),
            errors_suppressed: Arc::new(AtomicU64::new(0)),
            results_capped: Arc::new(AtomicBool::new(false)),
            dispatch_failed: Arc::new(AtomicBool::new(false)),
            worker_errors: Arc::new(Mutex::new(Vec::new())),
            file_results: Arc::new(Mutex::new((Vec::new(), false))),
        }
    }

    async fn record_file_result<F>(&self, emitter: &JobEventEmitter, make_item: F)
    where
        F: FnOnce() -> FileTransferResult,
    {
        if self.results_capped.load(Ordering::Relaxed) {
            if emitter.has_sink() {
                emitter.emit_file_completed(make_item());
            }
            return;
        }
        let item = make_item();
        let mut g = self.file_results.lock().await;
        let (vec, trunc) = &mut *g;
        push_file_result(vec, trunc, Some(emitter), item);
        if *trunc {
            self.results_capped.store(true, Ordering::Relaxed);
        }
    }

    async fn record_outcome(
        &self,
        res: Result<TransferOutcome>,
        task_path: String,
        task_size: u64,
        falcon_lane: Option<(&FalconController, TransferLane)>,
        prog: Option<&Arc<TransferProgress>>,
        emitter: &JobEventEmitter,
    ) -> bool {
        match res {
            Ok(TransferOutcome::Transferred {
                bytes,
                source_deleted,
                ..
            }) => {
                if let Some((fctrl, lane)) = falcon_lane {
                    // Live streamed / fast-copy bytes were already reported via `record_bytes`;
                    // flush any due telemetry window without double-counting `bytes`.
                    fctrl.record_transfer(lane, 0, 0, 0);
                    if let Some(p) = prog {
                        p.set_falcon_concurrency(
                            fctrl.concurrency(TransferLane::SmallPipelined),
                            fctrl.concurrency(TransferLane::LargeStreaming),
                        );
                    }
                }
                if let Some(p) = prog {
                    p.inc_files_done();
                    if source_deleted {
                        p.inc_sources_deleted();
                    }
                }
                self.files_transferred.fetch_add(1, Ordering::Relaxed);
                self.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
                if source_deleted {
                    self.sources_deleted.fetch_add(1, Ordering::Relaxed);
                }
                self.record_file_result(emitter, || {
                    FileTransferResult::transferred(task_path, bytes, source_deleted)
                })
                .await;
                true
            }
            Ok(TransferOutcome::ServerSideCopied {
                bytes,
                source_deleted,
                ..
            }) => {
                if let Some((fctrl, lane)) = falcon_lane {
                    fctrl.record_transfer(lane, 0, 0, 0);
                    if let Some(p) = prog {
                        p.set_falcon_concurrency(
                            fctrl.concurrency(TransferLane::SmallPipelined),
                            fctrl.concurrency(TransferLane::LargeStreaming),
                        );
                    }
                }
                if let Some(p) = prog {
                    p.inc_files_done();
                    p.inc_server_side_copies();
                    if source_deleted {
                        p.inc_sources_deleted();
                    }
                }
                self.files_transferred.fetch_add(1, Ordering::Relaxed);
                self.server_side_copies.fetch_add(1, Ordering::Relaxed);
                self.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
                if source_deleted {
                    self.sources_deleted.fetch_add(1, Ordering::Relaxed);
                }
                self.record_file_result(emitter, || {
                    FileTransferResult::server_side_copied(task_path, bytes, source_deleted)
                })
                .await;
                true
            }
            Ok(TransferOutcome::Skipped { source_deleted }) => {
                self.files_skipped.fetch_add(1, Ordering::Relaxed);
                if source_deleted {
                    self.sources_deleted.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(p) = prog {
                    p.record_worker_skip(task_size);
                    if source_deleted {
                        p.inc_sources_deleted();
                    }
                }
                self.record_file_result(emitter, || {
                    FileTransferResult::skipped(task_path, source_deleted)
                })
                .await;
                true
            }
            Err(e) if e.retry == RetryClass::Cancelled => false,
            Err(e) => {
                // Only throttle (`429`/`503`) and transient retryable failures signal congestion
                // to Falcon; permanent errors (`PermissionDenied`, `NotFound`, `Conflict`,
                // `QuotaExceeded`, etc.) MUST NEVER crush concurrency.
                if let Some((fctrl, lane)) = falcon_lane
                    && matches!(e.retry, RetryClass::Throttled | RetryClass::Retryable)
                {
                    let is_throttle = u32::from(e.retry == RetryClass::Throttled);
                    let is_transient_err = u32::from(e.retry == RetryClass::Retryable);
                    fctrl.record_transfer(lane, 0, is_throttle, is_transient_err);
                    if let Some(p) = prog {
                        p.set_falcon_concurrency(
                            fctrl.concurrency(TransferLane::SmallPipelined),
                            fctrl.concurrency(TransferLane::LargeStreaming),
                        );
                    }
                }
                if let Some(p) = prog {
                    p.inc_errors();
                }
                warn!(error = %e, "transfer failed");
                let info = TransferErrorInfo::from_error(Some(task_path.clone()), &e);
                {
                    let mut we = self.worker_errors.lock().await;
                    if we.len() < MAX_REPORT_ERRORS {
                        we.push(info);
                    } else {
                        self.errors_suppressed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.record_file_result(emitter, || FileTransferResult::failed(task_path, &e))
                    .await;
                true
            }
        }
    }
}

struct FalconOverflowState {
    small: VecDeque<TransferTask>,
    large: VecDeque<TransferTask>,
    producer_closed: bool,
    small_closed: bool,
    large_closed: bool,
}

struct FalconRouter {
    state: std::sync::Mutex<FalconOverflowState>,
    feeder_notify: Notify,
    small_space_notify: Notify,
    large_space_notify: Notify,
    max_lane_overflow: usize,
}

impl FalconRouter {
    fn new(max_lane_overflow: usize) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(FalconOverflowState {
                small: VecDeque::new(),
                large: VecDeque::new(),
                producer_closed: false,
                small_closed: false,
                large_closed: false,
            }),
            feeder_notify: Notify::new(),
            small_space_notify: Notify::new(),
            large_space_notify: Notify::new(),
            max_lane_overflow: max_lane_overflow.max(1),
        })
    }

    /// Non-blocking fast path into the target lane's channel when its overflow deque is empty,
    /// falling back to a bounded per-lane overflow deque drained independently by the feeder task.
    /// This prevents a saturated large-file lane from head-of-line blocking an idle small-file lane
    /// while keeping queued tasks strictly O(1) bounded (`<= WORK_QUEUE_CAPACITY * 2`).
    async fn enqueue(
        &self,
        lane: TransferLane,
        tx: &mpsc::Sender<TransferTask>,
        mut task: TransferTask,
    ) -> bool {
        let space_notify = match lane {
            TransferLane::SmallPipelined => &self.small_space_notify,
            TransferLane::LargeStreaming => &self.large_space_notify,
        };
        loop {
            let notified = space_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut guard = self.state.lock().expect("falcon router mutex poisoned");
                let st = &mut *guard;
                let (deque, closed) = match lane {
                    TransferLane::SmallPipelined => (&mut st.small, &mut st.small_closed),
                    TransferLane::LargeStreaming => (&mut st.large, &mut st.large_closed),
                };
                if *closed {
                    return false;
                }
                if deque.is_empty() {
                    match tx.try_send(task) {
                        Ok(()) => return true,
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            *closed = true;
                            drop(guard);
                            space_notify.notify_waiters();
                            return false;
                        }
                        Err(mpsc::error::TrySendError::Full(returned)) => {
                            task = returned;
                        }
                    }
                }
                if deque.len() < self.max_lane_overflow {
                    deque.push_back(task);
                    drop(guard);
                    self.feeder_notify.notify_one();
                    return true;
                }
            }
            notified.await;
        }
    }
}

struct FalconProducerGuard {
    router: Arc<FalconRouter>,
}

impl Drop for FalconProducerGuard {
    fn drop(&mut self) {
        {
            let mut st = self
                .router
                .state
                .lock()
                .expect("falcon router mutex poisoned");
            st.producer_closed = true;
        }
        self.router.feeder_notify.notify_one();
    }
}

async fn reserve_opt(
    tx: &Option<mpsc::Sender<TransferTask>>,
) -> std::result::Result<mpsc::Permit<'_, TransferTask>, mpsc::error::SendError<()>> {
    match tx {
        Some(sender) => sender.reserve().await,
        None => std::future::pending().await,
    }
}

async fn run_falcon_feeder(
    router: Arc<FalconRouter>,
    mut small_tx: Option<mpsc::Sender<TransferTask>>,
    mut large_tx: Option<mpsc::Sender<TransferTask>>,
    cancel: super::CancelFlag,
) {
    loop {
        let notified = router.feeder_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let (has_small, has_large) = {
            let st = router.state.lock().expect("falcon router mutex poisoned");
            if st.producer_closed {
                if st.small.is_empty() {
                    small_tx = None;
                }
                if st.large.is_empty() {
                    large_tx = None;
                }
            }
            if small_tx.is_none() && large_tx.is_none() {
                break;
            }
            (
                !st.small.is_empty() && small_tx.is_some(),
                !st.large.is_empty() && large_tx.is_some(),
            )
        };

        enum FeederAction {
            Continue,
            CloseSmall,
            CloseLarge,
            Break,
        }

        let action = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                let mut st = router.state.lock().expect("falcon router mutex poisoned");
                st.small.clear();
                st.large.clear();
                st.small_closed = true;
                st.large_closed = true;
                drop(st);
                router.small_space_notify.notify_waiters();
                router.large_space_notify.notify_waiters();
                FeederAction::Break
            }
            res = reserve_opt(&small_tx), if has_small => {
                match res {
                    Ok(permit) => {
                        let mut st = router.state.lock().expect("falcon router mutex poisoned");
                        if let Some(task) = st.small.pop_front() {
                            permit.send(task);
                        }
                        drop(st);
                        router.small_space_notify.notify_one();
                        FeederAction::Continue
                    }
                    Err(_) => {
                        let mut st = router.state.lock().expect("falcon router mutex poisoned");
                        st.small.clear();
                        st.small_closed = true;
                        drop(st);
                        router.small_space_notify.notify_waiters();
                        FeederAction::CloseSmall
                    }
                }
            }
            res = reserve_opt(&large_tx), if has_large => {
                match res {
                    Ok(permit) => {
                        let mut st = router.state.lock().expect("falcon router mutex poisoned");
                        if let Some(task) = st.large.pop_front() {
                            permit.send(task);
                        }
                        drop(st);
                        router.large_space_notify.notify_one();
                        FeederAction::Continue
                    }
                    Err(_) => {
                        let mut st = router.state.lock().expect("falcon router mutex poisoned");
                        st.large.clear();
                        st.large_closed = true;
                        drop(st);
                        router.large_space_notify.notify_waiters();
                        FeederAction::CloseLarge
                    }
                }
            }
            () = &mut notified, if !has_small || !has_large => FeederAction::Continue,
        };
        match action {
            FeederAction::Continue => {}
            FeederAction::CloseSmall => small_tx = None,
            FeederAction::CloseLarge => large_tx = None,
            FeederAction::Break => break,
        }
    }
}

enum PoolDispatch {
    Fixed {
        tx: mpsc::Sender<TransferTask>,
    },
    Falcon {
        ctrl: Arc<FalconController>,
        router: Arc<FalconRouter>,
        small_tx: mpsc::Sender<TransferTask>,
        large_tx: mpsc::Sender<TransferTask>,
        _producer_guard: FalconProducerGuard,
    },
}

pub(super) struct TransferWorkerPool {
    dispatch: Option<PoolDispatch>,
    cancel: super::CancelFlag,
    progress: Option<Arc<TransferProgress>>,
    feeder: Option<tokio::task::JoinHandle<()>>,
    falcon_report: Option<Arc<FalconController>>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    stats: SharedWorkerStats,
    watermark: Option<SafeWatermarkTracker>,
}

impl Drop for TransferWorkerPool {
    fn drop(&mut self) {
        // Close channels first, then abort any feeder/workers not already awaited by `finish()`
        // (e.g. when the caller returns early via `?` before calling `pool.finish(...)`).
        drop(self.dispatch.take());
        if let Some(f) = self.feeder.take() {
            f.abort();
        }
        for w in self.workers.drain(..) {
            w.abort();
        }
    }
}

impl TransferWorkerPool {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        engine: &TransferEngine,
        cfg: &EngineConfig,
        pair_key: &str,
        src_caps: &Capabilities,
        dst_caps: &Capabilities,
        emitter: &JobEventEmitter,
        bwlimit: Option<Arc<crate::bandwidth::BandwidthLimiter>>,
        max_fixed_workers: Option<usize>,
        watermark: Option<SafeWatermarkTracker>,
    ) -> Result<Self> {
        let stats = SharedWorkerStats::new();
        let shared_cfg = Arc::new(cfg.clone());
        let shared_pair_key: Arc<str> = Arc::from(pair_key);
        let shared_src_caps = Arc::new(src_caps.clone());
        let shared_dst_caps = Arc::new(dst_caps.clone());

        let falcon = if cfg.adaptive_concurrency {
            let fcfg = cfg
                .falcon_config
                .clone()
                .unwrap_or_else(|| FalconConfig::from_max_transfers(cfg.transfers));
            let ctrl = Arc::new(FalconController::with_clock(fcfg, engine.clock.clone()));
            if let Some(p) = &engine.progress {
                p.set_falcon_concurrency(
                    ctrl.concurrency(TransferLane::SmallPipelined),
                    ctrl.concurrency(TransferLane::LargeStreaming),
                );
            }
            Some(ctrl)
        } else {
            None
        };

        let mut workers = Vec::new();
        let mut feeder: Option<tokio::task::JoinHandle<()>> = None;
        let dispatch = if let Some(ref fctrl) = falcon {
            let lane_cap = (WORK_QUEUE_CAPACITY / 2).max(16);
            let (stx, srx) = mpsc::channel::<TransferTask>(lane_cap);
            let (ltx, lrx) = mpsc::channel::<TransferTask>(lane_cap);
            let srx = Arc::new(Mutex::new(srx));
            let lrx = Arc::new(Mutex::new(lrx));

            for (lane, lane_tag, rx_lane) in [
                (TransferLane::SmallPipelined, "S", srx),
                (TransferLane::LargeStreaming, "L", lrx),
            ] {
                let max_w = fctrl.max_concurrency(lane);
                for _ in 0..max_w {
                    let rx = rx_lane.clone();
                    let src = engine.src.clone();
                    let dst = engine.dst.clone();
                    let journal = engine.journal.clone();
                    let pool = engine.pool.clone();
                    let clock = engine.clock.clone();
                    let cancel = engine.cancel.clone();
                    let bw = bwlimit.clone();
                    let prog = engine.progress.clone();
                    let emitter_c = emitter.clone();
                    let fctrl_c = fctrl.clone();
                    let cfg_c = shared_cfg.clone();
                    let pair_key_c = shared_pair_key.clone();
                    let src_caps_c = shared_src_caps.clone();
                    let dst_caps_c = shared_dst_caps.clone();
                    let stats_c = stats.clone();
                    let wm_c = watermark.clone();

                    workers.push(tokio::spawn(async move {
                        loop {
                            let task = {
                                let mut guard = rx.lock().await;
                                guard.recv().await
                            };
                            let Some(task) = task else { break };
                            if cancel.is_cancelled() {
                                break;
                            }
                            let _lane_permit = fctrl_c.acquire_permit(lane).await;
                            if cancel.is_cancelled() {
                                break;
                            }
                            let task_path = task.dst_rel.as_str().to_string();
                            let task_size = task.src.size;
                            let wire_key = task.wire_key.clone();
                            emitter_c.emit_file_started(&task_path, task_size);
                            let slot_guard = prog
                                .as_ref()
                                .map(|p| p.start_transfer(&task_path, task_size, lane_tag));
                            let res = execute_transfer_task(
                                &src,
                                &dst,
                                &journal,
                                &pool,
                                &clock,
                                &cancel,
                                bw.as_ref(),
                                prog.as_ref(),
                                slot_guard.as_ref(),
                                Some((&fctrl_c, lane)),
                                &cfg_c,
                                &pair_key_c,
                                &src_caps_c,
                                &dst_caps_c,
                                task,
                            )
                            .await;
                            drop(slot_guard);
                            if let (Some(wm), Some(wk)) = (&wm_c, wire_key.as_deref()) {
                                wm.mark_completed(wk, res.is_ok());
                            }
                            if !stats_c
                                .record_outcome(
                                    res,
                                    task_path,
                                    task_size,
                                    Some((&fctrl_c, lane)),
                                    prog.as_ref(),
                                    &emitter_c,
                                )
                                .await
                            {
                                break;
                            }
                        }
                    }));
                }
            }
            let router = FalconRouter::new(WORK_QUEUE_CAPACITY);
            feeder = Some(tokio::spawn(run_falcon_feeder(
                router.clone(),
                Some(stx.clone()),
                Some(ltx.clone()),
                engine.cancel.clone(),
            )));
            PoolDispatch::Falcon {
                ctrl: fctrl.clone(),
                router: router.clone(),
                small_tx: stx,
                large_tx: ltx,
                _producer_guard: FalconProducerGuard { router },
            }
        } else {
            let base_workers = cfg.transfers.max(1);
            let worker_count =
                max_fixed_workers.map_or(base_workers, |cap| base_workers.min(cap.max(1)));
            let (tx, rx) = mpsc::channel::<TransferTask>(WORK_QUEUE_CAPACITY);
            let rx = Arc::new(Mutex::new(rx));

            for _ in 0..worker_count {
                let rx = rx.clone();
                let src = engine.src.clone();
                let dst = engine.dst.clone();
                let journal = engine.journal.clone();
                let pool = engine.pool.clone();
                let clock = engine.clock.clone();
                let cancel = engine.cancel.clone();
                let bw = bwlimit.clone();
                let prog = engine.progress.clone();
                let emitter_c = emitter.clone();
                let cfg_c = shared_cfg.clone();
                let pair_key_c = shared_pair_key.clone();
                let src_caps_c = shared_src_caps.clone();
                let dst_caps_c = shared_dst_caps.clone();
                let stats_c = stats.clone();
                let wm_c = watermark.clone();

                workers.push(tokio::spawn(async move {
                    loop {
                        let task = {
                            let mut guard = rx.lock().await;
                            guard.recv().await
                        };
                        let Some(task) = task else { break };
                        if cancel.is_cancelled() {
                            break;
                        }
                        let task_path = task.dst_rel.as_str().to_string();
                        let task_size = task.src.size;
                        let wire_key = task.wire_key.clone();
                        emitter_c.emit_file_started(&task_path, task_size);
                        let slot_guard = prog
                            .as_ref()
                            .map(|p| p.start_transfer(&task_path, task_size, ""));
                        let res = execute_transfer_task(
                            &src,
                            &dst,
                            &journal,
                            &pool,
                            &clock,
                            &cancel,
                            bw.as_ref(),
                            prog.as_ref(),
                            slot_guard.as_ref(),
                            None,
                            &cfg_c,
                            &pair_key_c,
                            &src_caps_c,
                            &dst_caps_c,
                            task,
                        )
                        .await;
                        drop(slot_guard);
                        if let (Some(wm), Some(wk)) = (&wm_c, wire_key.as_deref()) {
                            wm.mark_completed(wk, res.is_ok());
                        }
                        if !stats_c
                            .record_outcome(
                                res,
                                task_path,
                                task_size,
                                None,
                                prog.as_ref(),
                                &emitter_c,
                            )
                            .await
                        {
                            break;
                        }
                    }
                }));
            }
            PoolDispatch::Fixed { tx }
        };

        Ok(Self {
            dispatch: Some(dispatch),
            cancel: engine.cancel.clone(),
            progress: engine.progress.clone(),
            feeder,
            falcon_report: falcon,
            workers,
            stats,
            watermark,
        })
    }

    /// Hand `task` to the workers. Returns `false` when no worker can accept work any more
    /// (all workers exited, or cancellation closed the lanes). Outside cancellation, the
    /// failure is recorded and reported as a run error by [`Self::finish`].
    pub(super) async fn send(&self, task: TransferTask) -> bool {
        if let (Some(wm), Some(wk)) = (&self.watermark, task.wire_key.as_ref()) {
            wm.mark_dispatched(wk.clone());
        }
        let sent = self.dispatch_task(task).await;
        if !sent && !self.cancel.is_cancelled() {
            self.stats.dispatch_failed.store(true, Ordering::Relaxed);
        }
        sent
    }

    async fn dispatch_task(&self, task: TransferTask) -> bool {
        match self.dispatch.as_ref() {
            Some(PoolDispatch::Falcon {
                ctrl,
                router,
                small_tx,
                large_tx,
                ..
            }) => match ctrl.classify(task.src.size) {
                TransferLane::SmallPipelined => {
                    router
                        .enqueue(TransferLane::SmallPipelined, small_tx, task)
                        .await
                }
                TransferLane::LargeStreaming => {
                    router
                        .enqueue(TransferLane::LargeStreaming, large_tx, task)
                        .await
                }
            },
            Some(PoolDispatch::Fixed { tx }) => tx.send(task).await.is_ok(),
            None => false,
        }
    }

    pub(super) fn progress_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            self.stats.files_transferred.clone(),
            self.stats.bytes_transferred.clone(),
        )
    }

    /// Abort and join every worker on an early-error path. The caller already returns an
    /// error; panics found while joining are logged so they are not lost.
    pub(super) async fn abort_and_join(mut self) {
        drop(self.dispatch.take());
        if let Some(f) = self.feeder.take() {
            f.abort();
            if let Err(e) = f.await
                && e.is_panic()
            {
                warn!(panic = %panic_message(e), "transfer feeder task panicked");
            }
        }
        for w in &self.workers {
            w.abort();
        }
        for w in std::mem::take(&mut self.workers) {
            if let Err(e) = w.await
                && e.is_panic()
            {
                warn!(panic = %panic_message(e), "transfer worker panicked");
            }
        }
    }

    pub(super) async fn finish(mut self, report: &mut RunReport) {
        drop(self.dispatch.take());
        let mut join_failures: Vec<String> = Vec::new();
        if let Some(f) = self.feeder.take()
            && let Err(e) = f.await
        {
            join_failures.push(format!("transfer feeder task failed: {}", panic_message(e)));
        }

        for w in std::mem::take(&mut self.workers) {
            if let Err(e) = w.await {
                join_failures.push(format!("transfer worker failed: {}", panic_message(e)));
            }
        }
        // A worker that panicked or was aborted lost its in-flight file and every task it
        // would have run: the run is incomplete and destination deletes must be blocked.
        for msg in join_failures {
            warn!("{msg}");
            if let Some(p) = &self.progress {
                p.inc_errors();
            }
            report.push_error(TransferErrorInfo::from_error(None, &Error::protocol(msg)));
        }
        if self.stats.dispatch_failed.load(Ordering::Relaxed) && !self.cancel.is_cancelled() {
            if let Some(p) = &self.progress {
                p.inc_errors();
            }
            report.push_error(TransferErrorInfo::from_error(
                None,
                &Error::protocol(
                    "transfer workers exited before all planned transfers were dispatched",
                ),
            ));
        }

        if let Some(ref fctrl) = self.falcon_report {
            report.final_small_concurrency = Some(fctrl.concurrency(TransferLane::SmallPipelined));
            report.final_large_concurrency = Some(fctrl.concurrency(TransferLane::LargeStreaming));
        }

        report.files_transferred += self.stats.files_transferred.load(Ordering::Relaxed);
        report.files_skipped += self.stats.files_skipped.load(Ordering::Relaxed);
        report.server_side_copies += self.stats.server_side_copies.load(Ordering::Relaxed);
        report.sources_deleted += self.stats.sources_deleted.load(Ordering::Relaxed);
        report.bytes_transferred += self.stats.bytes_transferred.load(Ordering::Relaxed);
        for info in self.stats.worker_errors.lock().await.drain(..) {
            report.push_error(info);
        }
        let suppressed = self.stats.errors_suppressed.load(Ordering::Relaxed);
        if suppressed > 0 {
            report.errors_truncated = report.errors_truncated.saturating_add(suppressed);
        }
        let mut fr_guard = self.stats.file_results.lock().await;
        if report.file_results.is_empty() {
            report.file_results.append(&mut fr_guard.0);
        } else {
            for item in fr_guard.0.drain(..) {
                push_file_result(
                    &mut report.file_results,
                    &mut report.file_results_truncated,
                    None,
                    item,
                );
            }
        }
        if fr_guard.1 {
            report.file_results_truncated = true;
        }
    }
}

/// Render a [`tokio::task::JoinError`] (panic payload or cancellation) as text.
fn panic_message(err: tokio::task::JoinError) -> String {
    if !err.is_panic() {
        return err.to_string();
    }
    let payload = err.into_panic();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        format!("panicked: {s}")
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("panicked: {s}")
    } else {
        "panicked".to_string()
    }
}
