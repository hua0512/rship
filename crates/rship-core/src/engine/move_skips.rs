//! Bounded background executor for planned `move` skips.
//!
//! A planned skip in `move` means the destination already holds the file, so the source
//! only has to be verified unchanged and deleted (`sync_durable_file` on the destination,
//! `verify_source_unchanged`, then `src.delete`). Running those calls inline in the
//! producer stalled listing and the dispatch of later transfers for every page; this
//! executor runs them on a spawned task with bounded fan-out and a bounded queue, keeping
//! verify-before-delete per file.

use futures::StreamExt;
use tokio::sync::mpsc;

use super::diff::SafeWatermarkTracker;
use super::{
    EngineConfig, PlannedMoveSkip, RunReport, TransferEngine, TransferErrorInfo, push_file_result,
    record_move_skip_outcome, verify_and_delete_skipped_move_source,
};
use crate::error::Error;
use crate::progress::JobEventEmitter;

/// Queued skips beyond which the producer waits (back-pressure on listing).
const MOVE_SKIP_QUEUE_CAPACITY: usize = 1024;

pub(super) struct MoveSkipRunner {
    tx: Option<mpsc::Sender<PlannedMoveSkip>>,
    handle: Option<tokio::task::JoinHandle<RunReport>>,
    watermark: Option<SafeWatermarkTracker>,
}

impl MoveSkipRunner {
    /// Spawn the executor for a `move` run (`None` when the run never deletes sources).
    pub(super) fn spawn_for(
        engine: &TransferEngine,
        cfg: &EngineConfig,
        watermark: Option<SafeWatermarkTracker>,
        emitter: &JobEventEmitter,
    ) -> Option<Self> {
        if !cfg.delete_source_after_transfer || cfg.dry_run {
            return None;
        }
        let (tx, mut rx) = mpsc::channel::<PlannedMoveSkip>(MOVE_SKIP_QUEUE_CAPACITY);
        let conc = cfg.transfers.clamp(1, 32);
        let src = engine.src.clone();
        let dst = engine.dst.clone();
        let dst_prefix = cfg.dst_prefix.clone();
        let cancel = engine.cancel.clone();
        let progress = engine.progress.clone();
        let emitter = emitter.clone();
        let wm = watermark.clone();

        let handle = tokio::spawn(async move {
            let mut local = RunReport::default();
            let items = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
            let mut results = items
                .map(|item| {
                    let src = src.clone();
                    let dst = dst.clone();
                    let dst_prefix = dst_prefix.clone();
                    let cancel = cancel.clone();
                    async move {
                        if cancel.is_cancelled() {
                            return (item, None);
                        }
                        let res = verify_and_delete_skipped_move_source(
                            &src,
                            &dst,
                            &dst_prefix,
                            &item.src_bp,
                            &item.result_path,
                            &item.expected_ver,
                        )
                        .await;
                        (item, Some(res))
                    }
                })
                .buffer_unordered(conc);
            while let Some((item, outcome)) = results.next().await {
                let ok = match outcome {
                    Some(res) => record_move_skip_outcome(
                        progress.as_ref(),
                        &item.result_path,
                        &item.src_bp,
                        res,
                        &emitter,
                        &mut local,
                    ),
                    None => false,
                };
                if let (Some(w), Some(wk)) = (&wm, item.wire_key.as_deref()) {
                    w.mark_completed(wk, ok);
                }
            }
            local
        });
        Some(Self {
            tx: Some(tx),
            handle: Some(handle),
            watermark,
        })
    }

    /// Queue `skips`, waiting only when the bounded queue is full.
    pub(super) async fn submit(&self, skips: Vec<PlannedMoveSkip>) {
        let mut iter = skips.into_iter();
        if let Some(tx) = &self.tx {
            for item in iter.by_ref() {
                if let Err(mpsc::error::SendError(item)) = tx.send(item).await {
                    self.mark_unprocessed(&item);
                    break;
                }
            }
        }
        for item in iter {
            self.mark_unprocessed(&item);
        }
    }

    fn mark_unprocessed(&self, item: &PlannedMoveSkip) {
        if let (Some(w), Some(wk)) = (&self.watermark, item.wire_key.as_deref()) {
            w.mark_completed(wk, false);
        }
    }

    /// Wait for every queued skip and merge their outcomes into `report`.
    pub(super) async fn finish(mut self, report: &mut RunReport) {
        drop(self.tx.take());
        let Some(handle) = self.handle.take() else {
            return;
        };
        match handle.await {
            Ok(local) => {
                report.files_skipped += local.files_skipped;
                report.sources_deleted += local.sources_deleted;
                for info in local.error_details {
                    report.push_error(info);
                }
                report.errors_truncated = report
                    .errors_truncated
                    .saturating_add(local.errors_truncated);
                for item in local.file_results {
                    push_file_result(
                        &mut report.file_results,
                        &mut report.file_results_truncated,
                        None,
                        item,
                    );
                }
                if local.file_results_truncated {
                    report.file_results_truncated = true;
                }
            }
            Err(e) => {
                report.push_error(TransferErrorInfo::from_error(
                    None,
                    &Error::protocol(format!("move skip executor failed: {e}")),
                ));
            }
        }
    }

    /// Abort on an early-error path (the caller already returns an error).
    pub(super) async fn abort(mut self) {
        drop(self.tx.take());
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for MoveSkipRunner {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// `submit` on an optional runner (no-op without one).
pub(super) async fn submit_move_skips(
    runner: Option<&MoveSkipRunner>,
    skips: Vec<PlannedMoveSkip>,
) {
    if skips.is_empty() {
        return;
    }
    if let Some(r) = runner {
        r.submit(skips).await;
    }
}
