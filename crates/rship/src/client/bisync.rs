use rship_core::Result;
use rship_core::bandwidth::BandwidthSchedule;
use rship_core::bisync::{BisyncConfig, BisyncEngine, BisyncReport, ConflictStrategy};
use rship_core::engine::CancelFlag;
use rship_core::filter::{FilterOptions, FilterSet};
use rship_core::progress::{EventSink, FnEventSink, TransferEvent, TransferProgress};
use rship_core::types::FsyncMode;
use std::fmt;
use std::sync::Arc;

use super::{RshipClient, TransferTarget, next_job_id};

/// Fluent builder for Three-Tree bidirectional synchronization (`bisync`).
#[must_use = "bisync builders do nothing unless `.run().await` is called"]
pub struct BisyncBuilder<'a> {
    client: &'a RshipClient,
    side_a: TransferTarget,
    side_b: TransferTarget,
    job_id: Option<String>,
    transfers: usize,
    conflict_strategy: ConflictStrategy,
    resync: bool,
    force_empty_side: bool,
    max_delete: Option<u64>,
    max_delete_percent: Option<f64>,
    fsync_mode: Option<FsyncMode>,
    dry_run: bool,
    filter_opts: FilterOptions,
    explicit_filter: Option<FilterSet>,
    bwlimit: Option<u64>,
    bwlimit_schedule: Option<BandwidthSchedule>,
    cancel: Option<CancelFlag>,
    progress: Option<Arc<TransferProgress>>,
    event_sink: Option<Arc<dyn EventSink>>,
}

impl fmt::Debug for BisyncBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BisyncBuilder")
            .field("side_a", &self.side_a)
            .field("side_b", &self.side_b)
            .field("job_id", &self.job_id)
            .field("transfers", &self.transfers)
            .field("conflict_strategy", &self.conflict_strategy)
            .field("resync", &self.resync)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

impl<'a> BisyncBuilder<'a> {
    pub(super) fn new(
        client: &'a RshipClient,
        side_a: TransferTarget,
        side_b: TransferTarget,
    ) -> Self {
        let defaults = &client.config().defaults;
        let filter_opts = FilterOptions {
            includes: defaults.include.clone(),
            excludes: defaults.exclude.clone(),
            ..Default::default()
        };
        Self {
            client,
            side_a,
            side_b,
            job_id: None,
            transfers: defaults.transfers.max(1),
            conflict_strategy: ConflictStrategy::KeepBoth,
            resync: false,
            force_empty_side: false,
            max_delete: None,
            max_delete_percent: Some(50.0),
            fsync_mode: None,
            dry_run: false,
            filter_opts,
            explicit_filter: None,
            bwlimit: None,
            bwlimit_schedule: None,
            cancel: None,
            progress: None,
            event_sink: None,
        }
    }

    /// Set a custom durable job identifier.
    pub fn job_id(mut self, id: impl Into<String>) -> Self {
        self.job_id = Some(id.into());
        self
    }

    /// Set concurrent file worker count (`--transfers`).
    pub fn transfers(mut self, n: usize) -> Self {
        self.transfers = n.max(1);
        self
    }

    /// Set how concurrent edits on both sides are reconciled.
    pub fn conflict_strategy(mut self, strategy: ConflictStrategy) -> Self {
        self.conflict_strategy = strategy;
        self
    }

    /// Allow merging two non-empty trees with no prior baseline.
    pub fn resync(mut self, enabled: bool) -> Self {
        self.resync = enabled;
        self
    }

    /// Bypass the empty-side wipe circuit breaker when one side legitimately became empty.
    pub fn force_empty_side(mut self, enabled: bool) -> Self {
        self.force_empty_side = enabled;
        self
    }

    /// Cap total deletions across both sides.
    pub fn max_delete(mut self, limit: u64) -> Self {
        self.max_delete = Some(limit);
        self
    }

    /// Cap file deletions as a percentage (`0.0..=100.0`, default `50.0`) of observed files
    /// on each side when [`Self::max_delete`] is not set.
    pub fn max_delete_percent(mut self, percent: f64) -> Self {
        self.max_delete_percent = Some(percent);
        self
    }

    /// Override the local filesystem durability policy (`--fsync=always|batch|never`) for this bisync run.
    pub fn fsync_mode(mut self, mode: FsyncMode) -> Self {
        self.fsync_mode = Some(mode);
        self
    }

    /// Simulate the bisync run without mutating either side.
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Cap sustained transfer throughput in bytes/sec.
    pub fn bwlimit(mut self, bytes_per_sec: u64) -> Self {
        self.bwlimit = Some(bytes_per_sec);
        self
    }

    /// Apply a time-of-day bandwidth schedule (`--bwlimit` timetable).
    pub fn bwlimit_schedule(mut self, schedule: BandwidthSchedule) -> Self {
        self.bwlimit_schedule = Some(schedule);
        self
    }

    /// Add an include glob pattern.
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.filter_opts.includes.push(pattern.into());
        self
    }

    /// Add an exclude glob pattern.
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.filter_opts.excludes.push(pattern.into());
        self
    }

    /// Replace all filter options with `opts`.
    pub fn filter_options(mut self, opts: FilterOptions) -> Self {
        self.filter_opts = opts;
        self.explicit_filter = None;
        self
    }

    /// Supply a pre-compiled [`FilterSet`].
    pub fn filter(mut self, filter: FilterSet) -> Self {
        self.explicit_filter = Some(filter);
        self
    }

    /// Attach a cooperative [`CancelFlag`].
    pub fn cancel_on(mut self, cancel: CancelFlag) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Attach a lock-free [`TransferProgress`] handle.
    pub fn progress(mut self, progress: Arc<TransferProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Attach an [`EventSink`] to receive push [`TransferEvent`] notifications.
    pub fn event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Attach a closure callback to receive push [`TransferEvent`] notifications.
    pub fn on_event<F>(mut self, callback: F) -> Self
    where
        F: Fn(TransferEvent) + Send + Sync + 'static,
    {
        self.event_sink = Some(FnEventSink::new(callback));
        self
    }

    /// Execute the Three-Tree bidirectional sync and return its [`BisyncReport`].
    pub async fn run(self) -> Result<BisyncReport> {
        let _job_guard = self.client.acquire_job_guard()?;

        let filter = match self.explicit_filter {
            Some(f) => f,
            None => FilterSet::from_options(&self.filter_opts)?,
        };
        let job_id = self.job_id.unwrap_or_else(|| next_job_id("bisync"));
        let (a_b, a_prefix) =
            self.client
                .resolve_target(&self.side_a, None, None, self.fsync_mode)?;
        let (b_b, b_prefix) =
            self.client
                .resolve_target(&self.side_b, None, None, self.fsync_mode)?;
        let cfg = BisyncConfig::new(
            job_id.clone(),
            self.side_a.display_label(),
            self.side_b.display_label(),
        )
        .with_prefixes(a_prefix, b_prefix)
        .with_transfers(self.transfers)
        .with_conflict_strategy(self.conflict_strategy)
        .with_resync(self.resync)
        .with_force_empty_side(self.force_empty_side)
        .with_max_delete(self.max_delete)
        .with_max_delete_percent(self.max_delete_percent)
        .with_dry_run(self.dry_run)
        .with_filter(filter)
        .with_bwlimit(self.bwlimit)
        .with_bwlimit_schedule(self.bwlimit_schedule);

        let journal = self.client.journal()?;
        let mut engine = BisyncEngine::new(
            a_b,
            b_b,
            journal,
            self.client.buffer_pool().clone(),
            self.client.clock().clone(),
            self.cancel.unwrap_or_default(),
        );
        if let Some(p) = self.progress {
            engine = engine.with_progress(p);
        }
        if let Some(s) = self.event_sink {
            engine = engine.with_event_sink(s);
        }
        let index = self.client.open_sync_index(&job_id)?;
        engine.run(&cfg, index).await
    }
}
