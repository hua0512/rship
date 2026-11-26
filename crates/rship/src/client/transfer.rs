use rship_core::Result;
use rship_core::adaptive::FalconConfig;
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::bandwidth::BandwidthSchedule;
use rship_core::engine::{CancelFlag, DeleteMode, EngineConfig, RunReport, TransferEngine};
use rship_core::filter::{FilterOptions, FilterSet};
use rship_core::path::RelPath;
use rship_core::progress::{EventSink, FnEventSink, TransferEvent, TransferProgress};
use rship_core::state::JobMode;
use rship_core::types::FsyncMode;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::{RshipClient, TransferTarget, next_job_id};

#[derive(Debug)]
pub(super) enum TransferShape {
    Directory,
    SingleFile,
    FileList(Vec<String>),
}

/// Fluent builder for executing a `copy`, `sync`, `move`, single-file, or explicit
/// file-list transfer through [`RshipClient`].
#[must_use = "transfer builders do nothing unless `.run().await` is called"]
pub struct TransferBuilder<'a> {
    client: &'a RshipClient,
    mode: JobMode,
    src: TransferTarget,
    dst: TransferTarget,
    shape: TransferShape,
    job_id: Option<String>,
    transfers: usize,
    part_concurrency: usize,
    chunk_size: Option<u64>,
    delete: bool,
    delete_mode: DeleteMode,
    max_delete: Option<u64>,
    max_delete_percent: Option<f64>,
    fsync_mode: Option<FsyncMode>,
    backup_dir: Option<TransferTarget>,
    checksum: bool,
    dry_run: bool,
    force_type_replace: bool,
    max_retries: u32,
    base_retry_delay: Duration,
    filter_opts: FilterOptions,
    explicit_filter: Option<FilterSet>,
    bwlimit: Option<u64>,
    bwlimit_schedule: Option<BandwidthSchedule>,
    adaptive_concurrency: bool,
    falcon_config: Option<FalconConfig>,
    delete_empty_src_dirs: bool,
    strict_source: bool,
    strict_source_dir: Option<PathBuf>,
    strict_source_max_bytes: u64,
    allow_server_side_copy: bool,
    no_traverse: bool,
    baseline_mode: rship_core::state::BaselineMode,
    cancel: Option<CancelFlag>,
    progress: Option<Arc<TransferProgress>>,
    event_sink: Option<Arc<dyn EventSink>>,
}

impl fmt::Debug for TransferBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferBuilder")
            .field("mode", &self.mode)
            .field("src", &self.src)
            .field("dst", &self.dst)
            .field("shape", &self.shape)
            .field("job_id", &self.job_id)
            .field("transfers", &self.transfers)
            .field("part_concurrency", &self.part_concurrency)
            .field("delete", &self.delete)
            .field("dry_run", &self.dry_run)
            .field("checksum", &self.checksum)
            .finish()
    }
}

impl<'a> TransferBuilder<'a> {
    pub(super) fn new(
        client: &'a RshipClient,
        mode: JobMode,
        src: TransferTarget,
        dst: TransferTarget,
        shape: TransferShape,
    ) -> Self {
        let defaults = &client.config().defaults;
        let filter_opts = FilterOptions {
            includes: defaults.include.clone(),
            excludes: defaults.exclude.clone(),
            ..Default::default()
        };
        Self {
            client,
            mode,
            src,
            dst,
            shape,
            job_id: None,
            transfers: defaults.transfers.max(1),
            part_concurrency: defaults.part_concurrency.max(1),
            chunk_size: None,
            delete: matches!(mode, JobMode::Sync),
            delete_mode: DeleteMode::After,
            max_delete: None,
            max_delete_percent: None,
            fsync_mode: None,
            backup_dir: None,
            checksum: defaults.checksum.unwrap_or(false),
            dry_run: false,
            force_type_replace: defaults.force_type_replace.unwrap_or(false),
            max_retries: defaults.retries.unwrap_or(5),
            base_retry_delay: Duration::from_millis(50),
            filter_opts,
            explicit_filter: None,
            bwlimit: None,
            bwlimit_schedule: None,
            adaptive_concurrency: defaults.adaptive.unwrap_or(false),
            falcon_config: None,
            delete_empty_src_dirs: false,
            strict_source: defaults.strict_source.unwrap_or(false),
            strict_source_dir: None,
            strict_source_max_bytes: 256 * 1024 * 1024,
            allow_server_side_copy: !defaults.no_server_side_copy.unwrap_or(false),
            no_traverse: false,
            baseline_mode: rship_core::state::BaselineMode::Auto,
            cancel: None,
            progress: None,
            event_sink: None,
        }
    }

    /// Set a custom durable job identifier (otherwise auto-generated).
    pub fn job_id(mut self, id: impl Into<String>) -> Self {
        self.job_id = Some(id.into());
        self
    }

    /// Set concurrent file worker count (`--transfers`).
    pub fn transfers(mut self, n: usize) -> Self {
        self.transfers = n.max(1);
        self
    }

    /// Set concurrent parts per multipart upload (`--part-concurrency`).
    pub fn part_concurrency(mut self, n: usize) -> Self {
        self.part_concurrency = n.max(1);
        self
    }

    /// Override the resumable/multipart chunk size in bytes.
    pub fn chunk_size(mut self, bytes: u64) -> Self {
        self.chunk_size = Some(bytes);
        self
    }

    /// Cap sustained transfer throughput in bytes/sec (`--bwlimit`).
    pub fn bwlimit(mut self, bytes_per_sec: u64) -> Self {
        self.bwlimit = Some(bytes_per_sec);
        self
    }

    /// Apply a time-of-day bandwidth schedule (`--bwlimit` timetable).
    pub fn bwlimit_schedule(mut self, schedule: BandwidthSchedule) -> Self {
        self.bwlimit_schedule = Some(schedule);
        self
    }

    /// Compare files by checksum instead of size + mtime (`--checksum`).
    pub fn checksum(mut self, enabled: bool) -> Self {
        self.checksum = enabled;
        self
    }

    /// Simulate the transfer without mutating destination or deleting sources.
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Enable or disable destination deletion for `sync` runs.
    pub fn delete(mut self, enabled: bool) -> Self {
        self.delete = enabled;
        self
    }

    /// Configure when extraneous destination files are deleted during `sync`
    /// (`DeleteMode::After`, `DeleteMode::During`, or `DeleteMode::Before`).
    pub fn delete_mode(mut self, mode: DeleteMode) -> Self {
        self.delete_mode = mode;
        self
    }

    /// Trip the deletion circuit breaker if planned deletes exceed `limit`.
    pub fn max_delete(mut self, limit: u64) -> Self {
        self.max_delete = Some(limit);
        self
    }

    /// Trip the deletion circuit breaker if planned file deletes exceed `percent`% (`0.0..=100.0`)
    /// of observed destination files (when [`Self::max_delete`] is not set).
    pub fn max_delete_percent(mut self, percent: f64) -> Self {
        self.max_delete_percent = Some(percent);
        self
    }

    /// Override the local filesystem durability policy (`--fsync=always|batch|never`) for this transfer.
    pub fn fsync_mode(mut self, mode: FsyncMode) -> Self {
        self.fsync_mode = Some(mode);
        self
    }

    /// Archive overwritten or deleted destination files into `target` (`--backup-dir`).
    pub fn backup_dir(mut self, target: impl Into<TransferTarget>) -> Self {
        self.backup_dir = Some(target.into());
        self
    }

    /// When moving directories, prune empty source directories after all transfers succeed.
    pub fn delete_empty_src_dirs(mut self, enabled: bool) -> Self {
        self.delete_empty_src_dirs = enabled;
        self
    }

    /// Allow replacing a destination file with a directory (or vice versa).
    pub fn force_type_replace(mut self, enabled: bool) -> Self {
        self.force_type_replace = enabled;
        self
    }

    /// Set high-level per-file/chunk retry count (`--retries`).
    pub fn retries(mut self, count: u32) -> Self {
        self.max_retries = count;
        self
    }

    /// Set the base exponential backoff delay between retries.
    pub fn base_retry_delay(mut self, delay: Duration) -> Self {
        self.base_retry_delay = delay;
        self
    }

    /// Enable Falcon dual-lane online adaptive concurrency control.
    pub fn adaptive_concurrency(mut self, enabled: bool) -> Self {
        self.adaptive_concurrency = enabled;
        self
    }

    /// Provide an explicit [`FalconConfig`] for adaptive concurrency.
    pub fn falcon_config(mut self, cfg: FalconConfig) -> Self {
        self.falcon_config = Some(cfg);
        self.adaptive_concurrency = true;
        self
    }

    /// Snapshot source files locally before uploading to prevent `SourceMutated` loops.
    pub fn strict_source(mut self, enabled: bool) -> Self {
        self.strict_source = enabled;
        self
    }

    /// Set the maximum snapshot size allowed under [`Self::strict_source`].
    pub fn strict_source_max_bytes(mut self, max_bytes: u64) -> Self {
        self.strict_source_max_bytes = max_bytes;
        self
    }

    /// Set the directory used for [`Self::strict_source`] snapshots.
    pub fn strict_source_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.strict_source_dir = Some(dir.into());
        self
    }

    /// Enable or disable zero-bandwidth cloud server-side copy / local fast-copy.
    pub fn allow_server_side_copy(mut self, allow: bool) -> Self {
        self.allow_server_side_copy = allow;
        self
    }

    /// Skip full tree listing when filtering via an explicit file list (`--no-traverse`).
    pub fn no_traverse(mut self, enabled: bool) -> Self {
        self.no_traverse = enabled;
        self
    }

    /// Control when verified transfers persist durable `sync_baseline` rows (`auto`, `all`, `none`).
    pub fn baseline_mode(mut self, mode: rship_core::state::BaselineMode) -> Self {
        self.baseline_mode = mode;
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

    /// Attach a cooperative [`CancelFlag`] for graceful cancellation.
    pub fn cancel_on(mut self, cancel: CancelFlag) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Attach a lock-free [`TransferProgress`] handle for live polling.
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

    /// Execute the configured transfer and return its [`RunReport`].
    pub async fn run(self) -> Result<RunReport> {
        let _job_guard = self.client.acquire_job_guard()?;

        let filter = match self.explicit_filter {
            Some(f) => f,
            None => FilterSet::from_options(&self.filter_opts)?,
        };
        let job_id = self.job_id.unwrap_or_else(|| next_job_id("job"));
        let cancel = self.cancel.unwrap_or_default();

        let mut cfg = EngineConfig::new(
            job_id.clone(),
            self.mode,
            self.src.display_label(),
            self.dst.display_label(),
        )
        .with_transfers(self.transfers)
        .with_part_concurrency(self.part_concurrency)
        .with_chunk_size(self.chunk_size)
        .with_delete(self.delete && matches!(self.mode, JobMode::Sync))
        .with_delete_mode(self.delete_mode)
        .with_max_delete(self.max_delete)
        .with_max_delete_percent(self.max_delete_percent)
        .with_checksum(self.checksum)
        .with_dry_run(self.dry_run)
        .with_force_type_replace(self.force_type_replace)
        .with_max_retries(self.max_retries)
        .with_base_retry_delay(self.base_retry_delay)
        .with_filter(filter)
        .with_bwlimit(self.bwlimit)
        .with_bwlimit_schedule(self.bwlimit_schedule)
        .with_adaptive_concurrency(self.adaptive_concurrency)
        .with_falcon_config(self.falcon_config)
        .with_delete_source_after_transfer(matches!(self.mode, JobMode::Move))
        .with_delete_empty_src_dirs(self.delete_empty_src_dirs)
        .with_strict_source(self.strict_source)
        .with_strict_source_dir(self.strict_source_dir)
        .with_strict_source_max_bytes(self.strict_source_max_bytes)
        .with_allow_server_side_copy(self.allow_server_side_copy)
        .with_no_traverse(self.no_traverse)
        .with_baseline_mode(self.baseline_mode);

        if let Some(bk_target) = &self.backup_dir {
            let (bk_b, bk_prefix) =
                self.client
                    .resolve_target(bk_target, None, None, self.fsync_mode)?;
            cfg = cfg.with_backup_dir(bk_b, bk_prefix);
        }

        let journal = self.client.journal()?;
        let build_engine = |src_b: Arc<dyn StorageBackend>, dst_b: Arc<dyn StorageBackend>| {
            let mut engine = TransferEngine::new(
                src_b,
                dst_b,
                journal.clone(),
                self.client.buffer_pool().clone(),
                self.client.clock().clone(),
                cancel.clone(),
            );
            if let Some(p) = self.progress.clone() {
                engine = engine.with_progress(p);
            }
            if let Some(s) = self.event_sink.clone() {
                engine = engine.with_event_sink(s);
            }
            engine
        };

        let report = match self.shape {
            TransferShape::SingleFile => {
                let (src_b, src_rel) = self
                    .client
                    .resolve_file_target(&self.src, false, None, None, None)?;
                let (dst_b, dst_rel) = self.client.resolve_file_target(
                    &self.dst,
                    !self.dry_run,
                    None,
                    None,
                    self.fsync_mode,
                )?;
                let engine = build_engine(src_b, dst_b);
                engine
                    .run_single_file(&cfg, &BackendPath::from_rel(src_rel), &dst_rel)
                    .await?
            }
            TransferShape::FileList(raw_files) => {
                let mut rels = Vec::with_capacity(raw_files.len());
                for raw in raw_files {
                    let rel = RelPath::parse(&raw)?;
                    if !rel.is_root() {
                        rels.push(rel);
                    }
                }
                let (src_b, src_prefix) =
                    self.client.resolve_target(&self.src, None, None, None)?;
                let (dst_b, dst_prefix) =
                    self.client
                        .resolve_target(&self.dst, None, None, self.fsync_mode)?;
                cfg = cfg
                    .with_prefixes(src_prefix, dst_prefix)
                    .with_no_traverse(true);
                let engine = build_engine(src_b, dst_b);
                engine.run_file_list(&cfg, &rels).await?
            }
            TransferShape::Directory => {
                let (src_b, src_prefix) =
                    self.client.resolve_target(&self.src, None, None, None)?;
                let (dst_b, dst_prefix) =
                    self.client
                        .resolve_target(&self.dst, None, None, self.fsync_mode)?;
                cfg = cfg.with_prefixes(src_prefix, dst_prefix);
                let engine = build_engine(src_b, dst_b);
                let index = self.client.open_sync_index(&job_id)?;
                engine.run(&cfg, index).await?
            }
        };

        Ok(report)
    }
}
