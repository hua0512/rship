//! Lock-free live transfer progress metrics, per-file active transfer tracking
//! for multi-task terminal TUI dashboards, and human-readable status formatting.

use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use crate::buffer::{BufferPool, BufferPoolStats};
use crate::engine::{FileTransferResult, TransferErrorInfo};
use crate::error::{Error, Result};
use crate::source::ByteStream;
use crate::state::{JobMode, SyncConflict};

/// Coarse lifecycle phase of a transfer/sync job for structured progress consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransferPhase {
    Preparing,
    Observing,
    CreatingDirs,
    Transferring,
    Finalizing,
    Completed,
}

impl TransferPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Observing => "observing",
            Self::CreatingDirs => "creating_dirs",
            Self::Transferring => "transferring",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "preparing" => Some(Self::Preparing),
            "observing" => Some(Self::Observing),
            "creating_dirs" => Some(Self::CreatingDirs),
            "transferring" => Some(Self::Transferring),
            "finalizing" => Some(Self::Finalizing),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Preparing => 0,
            Self::Observing => 1,
            Self::CreatingDirs => 2,
            Self::Transferring => 3,
            Self::Finalizing => 4,
            Self::Completed => 5,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Preparing,
            1 => Self::Observing,
            2 => Self::CreatingDirs,
            3 => Self::Transferring,
            4 => Self::Finalizing,
            _ => Self::Completed,
        }
    }
}

impl fmt::Display for TransferPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransferPhase {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown transfer phase `{s}`")))
    }
}

/// Structured push event emitted during [`crate::engine::TransferEngine`] or
/// [`crate::bisync::BisyncEngine`] execution.
///
/// ## Ordering & Pairing Guarantees
/// - Every event carries a job-scoped `job_id` and a strictly monotonically increasing
///   `seq` starting at `1`.
/// - `JobStarted` is always the first event (`seq == 1`) and `JobFinished` is always
///   the single terminal event emitted for every started job — including cancellation
///   and fatal errors.
/// - `FileStarted` for a path always has a smaller `seq` than its corresponding
///   `FileCompleted`; events from concurrent file workers may interleave across paths.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransferEvent {
    JobStarted {
        seq: u64,
        job_id: String,
        mode: JobMode,
    },
    PhaseChanged {
        seq: u64,
        job_id: String,
        phase: TransferPhase,
    },
    FileStarted {
        seq: u64,
        job_id: String,
        path: String,
        total_bytes: u64,
    },
    FileCompleted {
        seq: u64,
        job_id: String,
        result: FileTransferResult,
    },
    ConflictDetected {
        seq: u64,
        job_id: String,
        conflict: SyncConflict,
    },
    ErrorOccurred {
        seq: u64,
        job_id: String,
        error: TransferErrorInfo,
    },
    JobFinished {
        seq: u64,
        job_id: String,
        files_transferred: u64,
        files_skipped: u64,
        bytes_transferred: u64,
        errors: usize,
        conflicts: usize,
        cancelled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fatal_error: Option<String>,
    },
}

impl TransferEvent {
    /// Monotonic per-job event sequence number (starts at `1`).
    pub fn seq(&self) -> u64 {
        match self {
            Self::JobStarted { seq, .. }
            | Self::PhaseChanged { seq, .. }
            | Self::FileStarted { seq, .. }
            | Self::FileCompleted { seq, .. }
            | Self::ConflictDetected { seq, .. }
            | Self::ErrorOccurred { seq, .. }
            | Self::JobFinished { seq, .. } => *seq,
        }
    }

    /// Job identifier that emitted this event.
    pub fn job_id(&self) -> &str {
        match self {
            Self::JobStarted { job_id, .. }
            | Self::PhaseChanged { job_id, .. }
            | Self::FileStarted { job_id, .. }
            | Self::FileCompleted { job_id, .. }
            | Self::ConflictDetected { job_id, .. }
            | Self::ErrorOccurred { job_id, .. }
            | Self::JobFinished { job_id, .. } => job_id,
        }
    }
}

/// Non-blocking observer receiving push [`TransferEvent`] notifications from the engine.
///
/// Implementations must avoid long blocking I/O on the callback thread. To receive
/// events asynchronously without stalling workers, prefer [`ChannelEventSink::bounded`].
/// Panics inside `on_event` are isolated via [`dispatch_event`] (`catch_unwind`) so a
/// misbehaving callback never crashes a transfer worker or corrupts reports.
pub trait EventSink: Send + Sync {
    fn on_event(&self, event: TransferEvent);
}

/// Safely invoke [`EventSink::on_event`], isolating panics via `catch_unwind` so a
/// callback panic can never crash a transfer worker or lose transfer state.
///
/// Returns `true` if the callback completed normally, or `false` if it panicked.
pub fn dispatch_event(sink: &dyn EventSink, event: TransferEvent) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.on_event(event))) {
        Ok(()) => true,
        Err(_) => {
            tracing::warn!(
                "rship EventSink::on_event callback panicked; isolated from transfer worker"
            );
            false
        }
    }
}

/// Closure-backed [`EventSink`] adapter.
pub struct FnEventSink<F>(F);

impl<F> FnEventSink<F>
where
    F: Fn(TransferEvent) + Send + Sync + 'static,
{
    pub fn new(f: F) -> Arc<Self> {
        Arc::new(Self(f))
    }
}

impl<F> EventSink for FnEventSink<F>
where
    F: Fn(TransferEvent) + Send + Sync,
{
    fn on_event(&self, event: TransferEvent) {
        (self.0)(event);
    }
}

/// Overflow policy applied by a bounded [`ChannelEventSink`] when its receiver falls behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OverflowPolicy {
    /// Drop the newest event immediately via non-blocking `try_send` so transfer
    /// workers are never stalled; increments [`ChannelEventSink::dropped_events`].
    #[default]
    DropNewest,
}

#[derive(Debug, Clone)]
enum ChannelSinkMode {
    Bounded {
        tx: tokio::sync::mpsc::Sender<TransferEvent>,
        policy: OverflowPolicy,
        dropped: Arc<AtomicU64>,
    },
    Unbounded(tokio::sync::mpsc::UnboundedSender<TransferEvent>),
}

/// Async channel-backed [`EventSink`] pushing [`TransferEvent`]s into a Tokio channel.
///
/// Prefer [`Self::bounded`] in production to keep memory strictly bounded when consumers
/// fall behind; [`Self::unbounded`] is opt-in for tests or guaranteed-fast consumers.
#[derive(Debug, Clone)]
pub struct ChannelEventSink {
    mode: ChannelSinkMode,
}

impl ChannelEventSink {
    /// Create a non-blocking bounded channel sink using [`OverflowPolicy::DropNewest`].
    pub fn bounded(capacity: usize) -> (Arc<Self>, tokio::sync::mpsc::Receiver<TransferEvent>) {
        Self::bounded_with_policy(capacity, OverflowPolicy::DropNewest)
    }

    /// Create a bounded channel sink with an explicit [`OverflowPolicy`].
    pub fn bounded_with_policy(
        capacity: usize,
        policy: OverflowPolicy,
    ) -> (Arc<Self>, tokio::sync::mpsc::Receiver<TransferEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
        (
            Arc::new(Self {
                mode: ChannelSinkMode::Bounded {
                    tx,
                    policy,
                    dropped: Arc::new(AtomicU64::new(0)),
                },
            }),
            rx,
        )
    }

    /// Wrap an existing bounded Tokio sender using [`OverflowPolicy::DropNewest`].
    pub fn from_bounded_sender(tx: tokio::sync::mpsc::Sender<TransferEvent>) -> Arc<Self> {
        Arc::new(Self {
            mode: ChannelSinkMode::Bounded {
                tx,
                policy: OverflowPolicy::DropNewest,
                dropped: Arc::new(AtomicU64::new(0)),
            },
        })
    }

    /// Create an opt-in unbounded channel sink.
    pub fn unbounded() -> (
        Arc<Self>,
        tokio::sync::mpsc::UnboundedReceiver<TransferEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(Self {
                mode: ChannelSinkMode::Unbounded(tx),
            }),
            rx,
        )
    }

    /// Wrap an existing unbounded Tokio sender.
    pub fn from_sender(tx: tokio::sync::mpsc::UnboundedSender<TransferEvent>) -> Arc<Self> {
        Arc::new(Self {
            mode: ChannelSinkMode::Unbounded(tx),
        })
    }

    /// Number of events dropped due to bounded channel saturation (`0` for unbounded sinks).
    pub fn dropped_events(&self) -> u64 {
        match &self.mode {
            ChannelSinkMode::Bounded { dropped, .. } => dropped.load(Ordering::Relaxed),
            ChannelSinkMode::Unbounded(_) => 0,
        }
    }
}

impl EventSink for ChannelEventSink {
    fn on_event(&self, event: TransferEvent) {
        match &self.mode {
            ChannelSinkMode::Bounded {
                tx,
                policy: OverflowPolicy::DropNewest,
                dropped,
            } => {
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            ChannelSinkMode::Unbounded(tx) => {
                let _ = tx.send(event);
            }
        }
    }
}

/// Internal per-job sequenced, panic-isolated event emitter shared by `TransferEngine`
/// and `BisyncEngine`.
#[derive(Clone)]
pub(crate) struct JobEventEmitter {
    job_id: Arc<str>,
    sink: Option<Arc<dyn EventSink>>,
    seq: Arc<AtomicU64>,
    finished: Arc<AtomicBool>,
}

impl JobEventEmitter {
    #[inline]
    pub(crate) fn has_sink(&self) -> bool {
        self.sink.is_some()
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn emit(&self, event: TransferEvent) {
        if let Some(sink) = &self.sink {
            let _ = dispatch_event(sink.as_ref(), event);
        }
    }

    pub(crate) fn emit_phase(&self, phase: TransferPhase) {
        if self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::PhaseChanged {
                seq,
                job_id: self.job_id.to_string(),
                phase,
            });
        }
    }

    pub(crate) fn emit_file_started(&self, path: impl Into<String>, total_bytes: u64) {
        if self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::FileStarted {
                seq,
                job_id: self.job_id.to_string(),
                path: path.into(),
                total_bytes,
            });
        }
    }

    pub(crate) fn emit_file_completed(&self, result: FileTransferResult) {
        if self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::FileCompleted {
                seq,
                job_id: self.job_id.to_string(),
                result,
            });
        }
    }

    pub(crate) fn emit_conflict(&self, conflict: SyncConflict) {
        if self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::ConflictDetected {
                seq,
                job_id: self.job_id.to_string(),
                conflict,
            });
        }
    }

    pub(crate) fn emit_error(&self, error: TransferErrorInfo) {
        if self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::ErrorOccurred {
                seq,
                job_id: self.job_id.to_string(),
                error,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_finished_once(
        &self,
        files_transferred: u64,
        files_skipped: u64,
        bytes_transferred: u64,
        errors: usize,
        conflicts: usize,
        cancelled: bool,
        fatal_error: Option<String>,
    ) {
        if !self.finished.swap(true, Ordering::AcqRel) && self.sink.is_some() {
            let seq = self.next_seq();
            self.emit(TransferEvent::JobFinished {
                seq,
                job_id: self.job_id.to_string(),
                files_transferred,
                files_skipped,
                bytes_transferred,
                errors,
                conflicts,
                cancelled,
                fatal_error,
            });
        }
    }
}

/// RAII lifecycle guard guaranteeing that every emitted [`TransferEvent::JobStarted`]
/// is paired with strictly one terminal [`TransferEvent::JobFinished`] event.
pub(crate) struct JobEventGuard {
    emitter: JobEventEmitter,
}

impl JobEventGuard {
    pub(crate) fn start(
        job_id: impl Into<String>,
        mode: JobMode,
        sink: Option<Arc<dyn EventSink>>,
    ) -> (Self, JobEventEmitter) {
        let job_id_str = job_id.into();
        let emitter = JobEventEmitter {
            job_id: Arc::from(job_id_str.as_str()),
            sink,
            seq: Arc::new(AtomicU64::new(1)),
            finished: Arc::new(AtomicBool::new(false)),
        };
        if emitter.sink.is_some() {
            let seq = emitter.next_seq();
            emitter.emit(TransferEvent::JobStarted {
                seq,
                job_id: job_id_str,
                mode,
            });
        }
        (
            Self {
                emitter: emitter.clone(),
            },
            emitter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish(
        &self,
        files_transferred: u64,
        files_skipped: u64,
        bytes_transferred: u64,
        errors: usize,
        conflicts: usize,
        cancelled: bool,
    ) {
        self.emitter.emit_finished_once(
            files_transferred,
            files_skipped,
            bytes_transferred,
            errors,
            conflicts,
            cancelled,
            None,
        );
    }

    pub(crate) fn finish_err(&self, err: &Error) {
        self.emitter
            .emit_finished_once(0, 0, 0, 1, 0, err.is_cancelled(), Some(err.to_string()));
    }
}

impl Drop for JobEventGuard {
    fn drop(&mut self) {
        if !self.emitter.finished.load(Ordering::Acquire) {
            self.emitter.emit_finished_once(
                0,
                0,
                0,
                1,
                0,
                false,
                Some("job terminated before explicit completion".to_string()),
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[non_exhaustive]
pub struct ActiveTransferSnapshot {
    pub id: u64,
    pub path: String,
    pub lane_tag: &'static str,
    pub total_bytes: u64,
    pub done_bytes: u64,
    pub elapsed_secs: f64,
    pub speed_bps: f64,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ProgressSnapshot {
    pub phase: TransferPhase,
    /// Total examined file items across planned transfers, planning skips, and planning errors
    /// (`files_done + files_skipped + file_errors == files_total` upon completion; non-file
    /// operational errors such as directory creation or destination deletions increment
    /// `errors` separately).
    pub files_total: u64,
    /// False while streaming object-store listing is still discovering objects beyond Gear 1
    /// (`> 1,000` keys); true once listing finishes or for upfront two-phase / single-page runs.
    pub totals_discovered: bool,
    /// Subset of `files_total` explicitly scheduled for transfer by the planner.
    pub files_planned: u64,
    pub files_done: u64,
    pub files_skipped: u64,
    pub server_side_copies: u64,
    pub sources_deleted: u64,
    pub dirs_created: u64,
    pub items_deleted: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub active_transfers: usize,
    pub errors: u64,
    pub elapsed_secs: f64,
    pub throughput_bps: f64,
    pub eta_secs: Option<u64>,
    pub pool: Option<BufferPoolStats>,
    pub small_lane_concurrency: Option<usize>,
    pub large_lane_concurrency: Option<usize>,
    pub active_items: Vec<ActiveTransferSnapshot>,
}

impl Default for ProgressSnapshot {
    fn default() -> Self {
        Self {
            phase: TransferPhase::Preparing,
            files_total: 0,
            totals_discovered: true,
            files_planned: 0,
            files_done: 0,
            files_skipped: 0,
            server_side_copies: 0,
            sources_deleted: 0,
            dirs_created: 0,
            items_deleted: 0,
            bytes_total: 0,
            bytes_done: 0,
            active_transfers: 0,
            errors: 0,
            elapsed_secs: 0.0,
            throughput_bps: 0.0,
            eta_secs: None,
            pool: None,
            small_lane_concurrency: None,
            large_lane_concurrency: None,
            active_items: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct ActiveSlot {
    id: u64,
    path: String,
    lane_tag: &'static str,
    total_bytes: u64,
    done_bytes: Arc<AtomicU64>,
    started_at: Instant,
}

/// RAII handle for one in-flight file transfer. Updates its slot counter lock-freely
/// on every streamed chunk and unregisters automatically on drop.
#[derive(Debug)]
pub struct ActiveTransferGuard {
    progress: Arc<TransferProgress>,
    slot_id: u64,
    slot_bytes: Arc<AtomicU64>,
}

impl ActiveTransferGuard {
    pub fn add_bytes(&self, n: u64) {
        self.slot_bytes.fetch_add(n, Ordering::Relaxed);
        self.progress.add_bytes_done(n);
    }

    pub fn slot_counter(&self) -> Arc<AtomicU64> {
        self.slot_bytes.clone()
    }

    /// Wrap a `ByteStream` so every streamed chunk advances both aggregate and
    /// per-file atomic counters with zero mutex contention.
    pub fn track_stream(&self, stream: ByteStream) -> ByteStream {
        Box::pin(ProgressByteStream {
            inner: stream,
            progress: self.progress.clone(),
            slot_bytes: Some(self.slot_bytes.clone()),
        })
    }
}

impl Drop for ActiveTransferGuard {
    fn drop(&mut self) {
        self.progress.dec_active();
        if let Ok(mut slots) = self.progress.active_slots.lock()
            && let Some(pos) = slots.iter().position(|s| s.id == self.slot_id)
        {
            slots.swap_remove(pos);
        }
    }
}

/// Shared lock-free live progress tracker updated on the hot transfer path.
#[derive(Debug)]
pub struct TransferProgress {
    started_at: Instant,
    phase: AtomicU8,
    next_slot_id: AtomicU64,
    files_total: AtomicU64,
    totals_discovered: AtomicBool,
    files_planned: AtomicU64,
    files_done: AtomicU64,
    files_skipped: AtomicU64,
    server_side_copies: AtomicU64,
    sources_deleted: AtomicU64,
    dirs_created: AtomicU64,
    items_deleted: AtomicU64,
    bytes_total: AtomicU64,
    bytes_done: AtomicU64,
    active_transfers: AtomicUsize,
    errors: AtomicU64,
    small_lane_c: AtomicUsize,
    large_lane_c: AtomicUsize,
    active_slots: Mutex<Vec<ActiveSlot>>,
}

impl TransferProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            phase: AtomicU8::new(TransferPhase::Preparing.as_u8()),
            next_slot_id: AtomicU64::new(1),
            files_total: AtomicU64::new(0),
            totals_discovered: AtomicBool::new(true),
            files_planned: AtomicU64::new(0),
            files_done: AtomicU64::new(0),
            files_skipped: AtomicU64::new(0),
            server_side_copies: AtomicU64::new(0),
            sources_deleted: AtomicU64::new(0),
            dirs_created: AtomicU64::new(0),
            items_deleted: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            bytes_done: AtomicU64::new(0),
            active_transfers: AtomicUsize::new(0),
            errors: AtomicU64::new(0),
            small_lane_c: AtomicUsize::new(0),
            large_lane_c: AtomicUsize::new(0),
            active_slots: Mutex::new(Vec::new()),
        })
    }

    pub fn set_phase(&self, phase: TransferPhase) {
        self.phase.store(phase.as_u8(), Ordering::Relaxed);
    }

    pub fn phase(&self) -> TransferPhase {
        TransferPhase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    pub fn set_totals_discovered(&self, discovered: bool) {
        self.totals_discovered.store(discovered, Ordering::Relaxed);
    }

    pub fn totals_discovered(&self) -> bool {
        self.totals_discovered.load(Ordering::Relaxed)
    }

    /// Account for a file queued for transfer by the planner (advances `files_total`,
    /// `files_planned`, and `bytes_total`).
    pub fn add_planned_file(&self, size: u64) {
        self.files_total.fetch_add(1, Ordering::Relaxed);
        self.files_planned.fetch_add(1, Ordering::Relaxed);
        self.bytes_total.fetch_add(size, Ordering::Relaxed);
    }

    /// Account for an item skipped during planning (advances both `files_total` and
    /// `files_skipped` without counting it as a planned transfer).
    pub fn add_planned_skip(&self) {
        self.files_total.fetch_add(1, Ordering::Relaxed);
        self.files_skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Account for an item that failed during observation or planning before entering
    /// the transfer queue (advances both `files_total` and `errors`).
    pub fn add_planned_error(&self) {
        self.files_total.fetch_add(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active(&self) {
        self.active_transfers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_transfers.fetch_sub(1, Ordering::Relaxed);
    }

    /// Register a live per-file transfer slot for the multi-task TUI dashboard.
    pub fn start_transfer(
        self: &Arc<Self>,
        path: impl Into<String>,
        total_bytes: u64,
        lane_tag: &'static str,
    ) -> ActiveTransferGuard {
        let slot_id = self.next_slot_id.fetch_add(1, Ordering::Relaxed);
        let slot_bytes = Arc::new(AtomicU64::new(0));
        self.inc_active();
        if let Ok(mut slots) = self.active_slots.lock() {
            slots.push(ActiveSlot {
                id: slot_id,
                path: path.into(),
                lane_tag,
                total_bytes,
                done_bytes: slot_bytes.clone(),
                started_at: Instant::now(),
            });
        }
        ActiveTransferGuard {
            progress: self.clone(),
            slot_id,
            slot_bytes,
        }
    }

    pub fn set_falcon_concurrency(&self, small: usize, large: usize) {
        self.small_lane_c.store(small, Ordering::Relaxed);
        self.large_lane_c.store(large, Ordering::Relaxed);
    }

    pub fn add_bytes_done(&self, n: u64) {
        self.bytes_done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_files_done(&self) {
        self.files_done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_skipped(&self) {
        self.files_skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a worker-level skip (e.g. `--checksum` hash match on a queued file),
    /// incrementing `files_skipped` and subtracting `planned_size` from `bytes_total`
    /// so byte progress ratios converge cleanly to 100%.
    pub fn record_worker_skip(&self, planned_size: u64) {
        self.files_skipped.fetch_add(1, Ordering::Relaxed);
        if planned_size > 0 {
            let _ = self
                .bytes_total
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some(cur.saturating_sub(planned_size))
                });
        }
    }

    pub fn inc_server_side_copies(&self) {
        self.server_side_copies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_sources_deleted(&self) {
        self.sources_deleted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dirs_created(&self) {
        self.dirs_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_items_deleted(&self) {
        self.items_deleted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Wrap a `ByteStream` so every chunk advances `bytes_done` live!
    pub fn track_stream(self: &Arc<Self>, stream: ByteStream) -> ByteStream {
        Box::pin(ProgressByteStream {
            inner: stream,
            progress: self.clone(),
            slot_bytes: None,
        })
    }

    /// Wrap a `ByteStream` updating both aggregate and a shared per-file atomic counter.
    pub fn track_stream_with_slot(
        self: &Arc<Self>,
        stream: ByteStream,
        slot_bytes: Arc<AtomicU64>,
    ) -> ByteStream {
        Box::pin(ProgressByteStream {
            inner: stream,
            progress: self.clone(),
            slot_bytes: Some(slot_bytes),
        })
    }

    pub fn snapshot(&self, pool: Option<&BufferPool>) -> ProgressSnapshot {
        let elapsed_secs = self.started_at.elapsed().as_secs_f64().max(0.001);
        let bytes_done = self.bytes_done.load(Ordering::Relaxed);
        let bytes_total = self.bytes_total.load(Ordering::Relaxed);
        let throughput_bps = bytes_done as f64 / elapsed_secs;
        let totals_discovered = self.totals_discovered.load(Ordering::Relaxed);
        let eta_secs = if totals_discovered && bytes_total > bytes_done && throughput_bps > 1.0 {
            Some(((bytes_total - bytes_done) as f64 / throughput_bps).ceil() as u64)
        } else {
            None
        };
        let active_items = self
            .active_slots
            .lock()
            .map(|slots| {
                slots
                    .iter()
                    .map(|s| {
                        let done = s.done_bytes.load(Ordering::Relaxed);
                        let dt = s.started_at.elapsed().as_secs_f64().max(0.001);
                        ActiveTransferSnapshot {
                            id: s.id,
                            path: s.path.clone(),
                            lane_tag: s.lane_tag,
                            total_bytes: s.total_bytes,
                            done_bytes: done,
                            elapsed_secs: dt,
                            speed_bps: done as f64 / dt,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let small_c = self.small_lane_c.load(Ordering::Relaxed);
        let large_c = self.large_lane_c.load(Ordering::Relaxed);

        ProgressSnapshot {
            phase: self.phase(),
            files_total: self.files_total.load(Ordering::Relaxed),
            totals_discovered,
            files_planned: self.files_planned.load(Ordering::Relaxed),
            files_done: self.files_done.load(Ordering::Relaxed),
            files_skipped: self.files_skipped.load(Ordering::Relaxed),
            server_side_copies: self.server_side_copies.load(Ordering::Relaxed),
            sources_deleted: self.sources_deleted.load(Ordering::Relaxed),
            dirs_created: self.dirs_created.load(Ordering::Relaxed),
            items_deleted: self.items_deleted.load(Ordering::Relaxed),
            bytes_total,
            bytes_done,
            active_transfers: self.active_transfers.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            elapsed_secs,
            throughput_bps,
            eta_secs,
            pool: pool.map(BufferPool::stats),
            small_lane_concurrency: (small_c > 0).then_some(small_c),
            large_lane_concurrency: (large_c > 0).then_some(large_c),
            active_items,
        }
    }
}

struct ProgressByteStream {
    inner: ByteStream,
    progress: Arc<TransferProgress>,
    slot_bytes: Option<Arc<AtomicU64>>,
}

impl Stream for ProgressByteStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if !chunk.is_empty() {
                    let n = chunk.len() as u64;
                    this.progress.add_bytes_done(n);
                    if let Some(ref sb) = this.slot_bytes {
                        sb.fetch_add(n, Ordering::Relaxed);
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}

pub fn format_human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = bytes as f64;
    let mut idx = 0usize;
    while val >= 1024.0 && idx + 1 < UNITS.len() {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.2} {}", UNITS[idx])
    }
}

/// Format a crisp single-line progress bar suitable for non-TUI stderr display.
pub fn format_progress_line(snap: &ProgressSnapshot) -> String {
    let pct = if snap.bytes_total > 0 {
        format!(
            "{:5.1}%",
            ((snap.bytes_done as f64 / snap.bytes_total as f64) * 100.0).min(100.0)
        )
    } else {
        "  --.-%".to_string()
    };
    let eta = match snap.eta_secs {
        Some(s) if s >= 3600 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        Some(s) if s >= 60 => format!("{}m{:02}s", s / 60, s % 60),
        Some(s) => format!("{s}s"),
        None => "--".to_string(),
    };
    let pool_str = match snap.pool {
        Some(p) => format!(
            " | buf {}/{}",
            format_human_bytes(p.in_use_bytes() as u64),
            format_human_bytes(p.max_bytes() as u64)
        ),
        None => String::new(),
    };
    format!(
        "[{pct}] {}/{} ({}/s) | files {}/{} (skip {}, active {}, err {}) | ETA {eta}{pool_str}",
        format_human_bytes(snap.bytes_done),
        format_human_bytes(snap.bytes_total),
        format_human_bytes(snap.throughput_bps as u64),
        snap.files_done,
        snap.files_total,
        snap.files_skipped,
        snap.active_transfers,
        snap.errors,
    )
}
