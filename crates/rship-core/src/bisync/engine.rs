//! [`BisyncEngine`] coordinator: concurrent dual-side observation, keyset-paginated
//! O(changed files) planning, directory staging, and job lifecycle tracking.

use futures::StreamExt;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::warn;

use super::{
    BisyncAction, BisyncConfig, BisyncReport, ConflictStrategy, make_bisync_baseline,
    plan_three_tree,
};
use crate::backend::{BackendPath, ListOptions, StorageBackend};
use crate::bandwidth::BandwidthLimiter;
use crate::buffer::BufferPool;
use crate::clock::Clock;
use crate::engine::diff::{DeleteSpillLog, DeleteTarget, DiffItem, StreamingMergeDiffSource};
use crate::engine::{
    CancelFlag, DurabilityFence, FileTransferResult, MAX_REPORT_ERRORS, ProtectedDirs,
    TransferErrorInfo, check_overlapping_roots, make_prefixed_pair_key, strip_raw_prefix,
};
use crate::error::{Error, Result};
use crate::filter::FilterSet;
use crate::path::RelPath;
use crate::progress::{EventSink, JobEventEmitter, JobEventGuard, TransferPhase, TransferProgress};
use crate::state::{
    BaselineRecord, BisyncPairState, ConflictKind, JobMode, JobRecord, JobStatus, JournalStore,
    SourceVersion, SyncDiffIndex,
};
use crate::types::{Capabilities, Entry, EntryKind};

const DIFF_PAGE_SIZE: usize = 512;
const OBSERVE_BATCH_SIZE: usize = 2000;

struct SideDeleteLogs {
    files: DeleteSpillLog,
    dirs: BTreeMap<usize, DeleteSpillLog>,
    scratch_dir: Option<Arc<dyn crate::state::RunScratchDir>>,
}

impl SideDeleteLogs {
    fn new(scratch_dir: Option<Arc<dyn crate::state::RunScratchDir>>) -> Self {
        Self {
            files: DeleteSpillLog::new(scratch_dir.clone()),
            dirs: BTreeMap::new(),
            scratch_dir,
        }
    }

    async fn push_entry(&mut self, e: Entry) -> Result<()> {
        let kind = e.kind;
        let expected_version =
            (kind != EntryKind::Directory).then(|| SourceVersion::from_entry(&e));
        let bp = BackendPath::from_entry(&e);
        let nfc = e.nfc_path;
        let target = DeleteTarget {
            nfc_path: nfc.clone(),
            backend_path: bp,
            kind,
            expected_version,
        };
        if kind == EntryKind::Directory {
            let depth = nfc.segments().count();
            self.dirs
                .entry(depth)
                .or_insert_with(|| DeleteSpillLog::new(self.scratch_dir.clone()))
                .push_async(target)
                .await
        } else {
            self.files.push_async(target).await
        }
    }
}

/// Forward cursor over `sync_baseline` rows (`next_baseline_page`) used to collect stale
/// file baselines (deleted on both A and B) into a bounded hybrid [`DeleteSpillLog`] in
/// `O(1)` RAM during ordered streaming bisync. Deletions are NEVER applied inline — they
/// commit strictly in Phase 3 after both sides finish completely with zero errors.
struct BaselineRetireCursor<'a> {
    journal: &'a Arc<dyn JournalStore>,
    pair_key: &'a str,
    buf: VecDeque<BaselineRecord>,
    last_key: Option<String>,
    eof: bool,
}

impl<'a> BaselineRetireCursor<'a> {
    fn new(journal: &'a Arc<dyn JournalStore>, pair_key: &'a str, enabled: bool) -> Self {
        Self {
            journal,
            pair_key,
            buf: VecDeque::new(),
            last_key: None,
            eof: !enabled,
        }
    }

    async fn refill(&mut self) -> Result<()> {
        if !self.buf.is_empty() || self.eof {
            return Ok(());
        }
        let page = self
            .journal
            .next_baseline_page(self.pair_key, self.last_key.as_deref(), DIFF_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            self.eof = true;
            return Ok(());
        }
        if let Some(last) = page.last() {
            self.last_key = Some(last.nfc_path.as_str().to_string());
        }
        self.buf.extend(page);
        Ok(())
    }

    /// Record any `EntryKind::File` baseline rows strictly preceding `observed_nfc_path`
    /// (or all remaining rows when `observed_nfc_path` is `None`) into `retire_log`.
    async fn advance_into(
        &mut self,
        observed_nfc_path: Option<&str>,
        retire_log: &mut DeleteSpillLog,
    ) -> Result<()> {
        loop {
            self.refill().await?;
            let Some(front) = self.buf.front() else {
                return Ok(());
            };
            if let Some(cur) = observed_nfc_path {
                match front.nfc_path.as_str().cmp(cur) {
                    std::cmp::Ordering::Less => {
                        let stale = self.buf.pop_front().unwrap();
                        if stale.kind == EntryKind::File {
                            retire_log
                                .push_async(DeleteTarget {
                                    backend_path: BackendPath::from_rel(stale.nfc_path.clone()),
                                    nfc_path: stale.nfc_path,
                                    kind: EntryKind::File,
                                    expected_version: None,
                                })
                                .await?;
                        }
                    }
                    std::cmp::Ordering::Equal => {
                        self.buf.pop_front();
                        return Ok(());
                    }
                    std::cmp::Ordering::Greater => return Ok(()),
                }
            } else {
                let stale = self.buf.pop_front().unwrap();
                if stale.kind == EntryKind::File {
                    retire_log
                        .push_async(DeleteTarget {
                            backend_path: BackendPath::from_rel(stale.nfc_path.clone()),
                            nfc_path: stale.nfc_path,
                            kind: EntryKind::File,
                            expected_version: None,
                        })
                        .await?;
                }
            }
        }
    }
}

pub struct BisyncEngine {
    pub(super) side_a: Arc<dyn StorageBackend>,
    pub(super) side_b: Arc<dyn StorageBackend>,
    /// The caller's journal wrapped in a [`DurabilityFence`] over both sides.
    pub(super) journal: Arc<dyn JournalStore>,
    pub(super) fence: Arc<DurabilityFence>,
    pub(super) pool: BufferPool,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) cancel: CancelFlag,
    pub(super) progress: Option<Arc<TransferProgress>>,
    pub(super) events: Option<Arc<dyn EventSink>>,
}

impl BisyncEngine {
    pub fn new(
        side_a: Arc<dyn StorageBackend>,
        side_b: Arc<dyn StorageBackend>,
        journal: Arc<dyn JournalStore>,
        pool: BufferPool,
        clock: Arc<dyn Clock>,
        cancel: CancelFlag,
    ) -> Self {
        let fence =
            DurabilityFence::new(journal, vec![side_a.clone(), side_b.clone()], clock.clone());
        Self {
            side_a,
            side_b,
            journal: fence.clone(),
            fence,
            pool,
            clock,
            cancel,
            progress: None,
            events: None,
        }
    }

    pub fn with_progress(mut self, progress: Arc<TransferProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.events = Some(sink);
        self
    }

    fn set_phase(&self, emitter: &JobEventEmitter, phase: TransferPhase) {
        if let Some(p) = &self.progress {
            p.set_phase(phase);
        }
        emitter.emit_phase(phase);
    }

    pub async fn run(
        &self,
        cfg: &BisyncConfig,
        index: Arc<dyn SyncDiffIndex>,
    ) -> Result<BisyncReport> {
        // One retry budget for the whole run, shared by every per-file transfer.
        let mut run_cfg = cfg.clone();
        run_cfg.run_retry_quota = Some(Arc::new(crate::engine::TokenBucketRetryQuota::default()));
        let cfg = &run_cfg;
        check_overlapping_roots(
            &self.side_a.endpoint_identity(),
            &cfg.a_prefix,
            &self.side_b.endpoint_identity(),
            &cfg.b_prefix,
            &cfg.filter,
        )?;
        crate::engine::validate_max_delete_percent(cfg.max_delete_percent)?;

        let bwlimit = if let Some(ref sched) = cfg.bwlimit_schedule {
            Some(BandwidthLimiter::from_schedule_with_clock(
                sched.clone(),
                self.clock.clone(),
            )?)
        } else {
            cfg.bwlimit_bytes_per_sec
                .map(|rate| BandwidthLimiter::new_with_clock(rate, self.clock.clone()))
                .transpose()?
        };

        let (event_guard, emitter) =
            JobEventGuard::start(&cfg.job_id, JobMode::Sync, self.events.clone());

        let mut started_job: Option<JobRecord> = None;
        let run_res: Result<BisyncReport> = async {
            let now_s = self.clock.now_unix_secs();
            let scan_started_ns = self.clock.now_unix_nanos();
            let pair_key = make_prefixed_pair_key(
                &self.side_a.endpoint_identity(),
                &cfg.a_prefix,
                &self.side_b.endpoint_identity(),
                &cfg.b_prefix,
            );
            let prev_pair_state = self.journal.get_bisync_state(&pair_key).await?;
            let has_existing_baselines = if cfg.resync || cfg.force_empty_side {
                false
            } else {
                !self
                    .journal
                    .next_baseline_page(&pair_key, None, 1)
                    .await?
                    .is_empty()
            };
            let cur_filter_hash = cfg.filter.fingerprint_sha256();
            if !cfg.resync
                && let Some(ref prev) = prev_pair_state
                && prev.filter_hash != cur_filter_hash
            {
                return Err(Error::precondition_failed(
                    "bisync filter rules changed since last sync; re-run with --resync to rebuild baseline safely",
                ));
            }

            let job_rec = JobRecord {
                job_id: cfg.job_id.clone(),
                mode: JobMode::Sync,
                src_spec: cfg.a_spec.clone(),
                dst_spec: cfg.b_spec.clone(),
                status: JobStatus::Running,
                files_total: 0,
                files_done: 0,
                bytes_total: 0,
                bytes_done: 0,
                created_at: now_s,
                updated_at: now_s,
                options_json: None,
                resume_cursor: None,
            };
            if !cfg.dry_run {
                self.journal.upsert_job(&job_rec).await?;
            }
            let job = started_job.insert(job_rec);

            let mut report = BisyncReport {
                job_id: cfg.job_id.clone(),
                ..Default::default()
            };

            let a_caps = self.side_a.capabilities();
            let b_caps = self.side_b.capabilities();
            let mut active_ops = self.load_active_ops_for_bisync(cfg).await?;
            let need_empty_guard = !cfg.resync
                && !cfg.force_empty_side
                && (prev_pair_state
                    .as_ref()
                    .is_some_and(|prev| prev.last_a_files > 0 && prev.last_b_files > 0)
                    || has_existing_baselines);
            // When filters are active alongside the empty-side guard, use the full-observation
            // `SyncDiffIndex` path so we know exact post-filter file counts on both sides BEFORE
            // any Phase 2 mutation. For unfiltered ordered S3/GCS/Azure streams, Gear 1 Page 1
            // proves non-emptiness in O(1) RAM before item 0!
            let can_stream_merge = a_caps.supports_ordered_utf8_list
                && b_caps.supports_ordered_utf8_list
                && a_caps.case_sensitive
                && b_caps.case_sensitive
                && cfg.filter.files_from_paths().is_none()
                && !(need_empty_guard && !cfg.filter.is_empty());

            let mut deletes_a = SideDeleteLogs::new(cfg.scratch_dir.clone());
            let mut deletes_b = SideDeleteLogs::new(cfg.scratch_dir.clone());
            let mut deferred_baseline_retires = DeleteSpillLog::new(cfg.scratch_dir.clone());
            let mut protected_a_dirs = ProtectedDirs::default();
            let mut protected_b_dirs = ProtectedDirs::default();
            let mut planned_deletes: u64 = 0;
            let mut planned_file_deletes_a: u64 = 0;
            let mut planned_file_deletes_b: u64 = 0;
            let mut observed_a_files: u64 = 0;
            let mut observed_b_files: u64 = 0;
            let mut created_on_a: u64 = 0;
            let mut created_on_b: u64 = 0;
            let mkdir_conc = cfg.transfers.clamp(1, 8);
            let copy_conc = cfg.transfers.max(1);

            let check_empty_side = |obs_a: u64, obs_b: u64| -> Result<()> {
                if cfg.resync || cfg.force_empty_side {
                    return Ok(());
                }
                let empty_side = if obs_a == 0 && obs_b > 0 {
                    Some("side A")
                } else if obs_b == 0 && obs_a > 0 {
                    Some("side B")
                } else {
                    None
                };
                if let Some(side) = empty_side {
                    if let Some(ref prev) = prev_pair_state
                        && prev.last_a_files > 0
                        && prev.last_b_files > 0
                    {
                        return Err(Error::precondition_failed(format!(
                            "bisync empty-side safety guard: {side} unexpectedly observed 0 files (previously {} on A, {} on B); check mounts/credentials or pass --force-empty-side",
                            prev.last_a_files, prev.last_b_files
                        )));
                    }
                    if has_existing_baselines {
                        return Err(Error::precondition_failed(format!(
                            "bisync empty-side safety guard: {side} unexpectedly observed 0 files while prior sync baselines exist; check mounts/credentials or pass --force-empty-side or --resync"
                        )));
                    }
                }
                Ok(())
            };

            let allow_deletes = if can_stream_merge {
                // Zero-disk streaming merge-join path for ordered UTF-8 object stores (S3/GCS/Azure).
                self.set_phase(&emitter, TransferPhase::Observing);
                let dir_pruner = ListOptions::recursive()
                    .with_filter_pruning(&cfg.filter, &RelPath::root())
                    .dir_pruner()
                    .cloned();
                let mut diff = StreamingMergeDiffSource::start(
                    self.side_a.clone(),
                    cfg.a_prefix.clone(),
                    self.side_b.clone(),
                    cfg.b_prefix.clone(),
                    None,
                    dir_pruner.clone(),
                    dir_pruner,
                    self.cancel.clone(),
                )
                .await?;
                if let Some(p) = &self.progress {
                    p.set_totals_discovered(diff.totals_known_immediately());
                }

                // Pre-mutation empty-side disaster guard (O(1) RAM):
                // Do NOT execute any Phase 2 mutations (`process_bisync_chunk`) until either:
                // - Both sides are proven to contain >= 1 post-filter `File`, OR
                // - EOF/probe proves BOTH sides have 0 matching files (0 & 0 is allowed).
                // If one side has 0 matching files and the other has >= 1 (even when filters
                // exclude Page 1 files or Page 1 had >1,000 empty directory markers), abort
                // cleanly with zero mutations!
                let mut guard_cleared = !need_empty_guard;
                let mut a_proven_non_empty = false;
                let mut b_proven_non_empty = false;
                let mut early_state_persisted = false;

                // Collect stale/unvisited baseline keys into `deferred_baseline_retires`
                // (`DeleteSpillLog`) rather than deleting inline mid-stream — committed strictly
                // in Phase 3 ONLY if both sides complete with zero errors (also covers `--resync`!).
                let mut retire_cursor = BaselineRetireCursor::new(
                    &self.journal,
                    &pair_key,
                    !cfg.dry_run && (cfg.filter.is_empty() || cfg.resync),
                );
                let mut chunk_pairs: Vec<(Option<Entry>, Option<Entry>)> =
                    Vec::with_capacity(DIFF_PAGE_SIZE);

                loop {
                    if self.cancel.is_cancelled() {
                        report.cancelled = true;
                        break;
                    }
                    chunk_pairs.clear();
                    let mut hit_eof = false;
                    while chunk_pairs.len() < DIFF_PAGE_SIZE {
                        if self.cancel.is_cancelled() {
                            report.cancelled = true;
                            break;
                        }
                        let Some(item) = diff.next_item().await else {
                            hit_eof = true;
                            break;
                        };
                        match item {
                            DiffItem::Conflict(c) => {
                                emitter.emit_conflict(c.clone());
                                report.push_conflict(c);
                            }
                            DiffItem::SrcOnly(a) => {
                                if cfg.filter.matches_entry(&a, scan_started_ns) {
                                    if a.kind == EntryKind::File {
                                        observed_a_files += 1;
                                        a_proven_non_empty = true;
                                        retire_cursor
                                            .advance_into(
                                                Some(a.nfc_path.as_str()),
                                                &mut deferred_baseline_retires,
                                            )
                                            .await?;
                                    }
                                    chunk_pairs.push((Some(a), None));
                                } else {
                                    protected_a_dirs.protect_ancestors(&a.nfc_path);
                                }
                            }
                            DiffItem::DstOnly(b) => {
                                if cfg.filter.matches_entry(&b, scan_started_ns) {
                                    if b.kind == EntryKind::File {
                                        observed_b_files += 1;
                                        b_proven_non_empty = true;
                                        retire_cursor
                                            .advance_into(
                                                Some(b.nfc_path.as_str()),
                                                &mut deferred_baseline_retires,
                                            )
                                            .await?;
                                    }
                                    chunk_pairs.push((None, Some(b)));
                                } else {
                                    protected_b_dirs.protect_ancestors(&b.nfc_path);
                                }
                            }
                            DiffItem::Both { src: a, dst: b } => {
                                let a_ok = cfg.filter.matches_entry(&a, scan_started_ns);
                                let b_ok = cfg.filter.matches_entry(&b, scan_started_ns);
                                if !a_ok {
                                    protected_a_dirs.protect_ancestors(&a.nfc_path);
                                }
                                if !b_ok {
                                    protected_b_dirs.protect_ancestors(&b.nfc_path);
                                }
                                if a_ok && b_ok {
                                    if a.kind == EntryKind::File {
                                        observed_a_files += 1;
                                        a_proven_non_empty = true;
                                    }
                                    if b.kind == EntryKind::File {
                                        observed_b_files += 1;
                                        b_proven_non_empty = true;
                                    }
                                    if a.kind == EntryKind::File || b.kind == EntryKind::File {
                                        retire_cursor
                                            .advance_into(
                                                Some(a.nfc_path.as_str()),
                                                &mut deferred_baseline_retires,
                                            )
                                            .await?;
                                    }
                                    chunk_pairs.push((Some(a), Some(b)));
                                } else {
                                    // Asymmetrical filter match (e.g. `--min-size`/`--max-age`
                                    // matched only one side): count whichever matched and leave
                                    // both sides & baseline untouched rather than overwriting or
                                    // deleting the unmatched side.
                                    if a_ok && a.kind == EntryKind::File {
                                        observed_a_files += 1;
                                        a_proven_non_empty = true;
                                    }
                                    if b_ok && b.kind == EntryKind::File {
                                        observed_b_files += 1;
                                        b_proven_non_empty = true;
                                    }
                                    if a.kind == EntryKind::File || b.kind == EntryKind::File {
                                        retire_cursor
                                            .advance_into(
                                                Some(a.nfc_path.as_str()),
                                                &mut deferred_baseline_retires,
                                            )
                                            .await?;
                                    }
                                }
                            }
                        }
                    }

                    if !guard_cleared && !chunk_pairs.is_empty() && !report.cancelled {
                        if a_proven_non_empty && b_proven_non_empty {
                            guard_cleared = true;
                        } else if hit_eof {
                            if diff.src_complete() && diff.dst_complete() {
                                if let Err(e) =
                                    check_empty_side(observed_a_files, observed_b_files)
                                {
                                    self.finish_job(job, JobStatus::Failed, cfg.dry_run)
                                        .await?;
                                    return Err(e);
                                }
                                guard_cleared = true;
                            } else {
                                // Incomplete listing on an unverified empty side: skip mutation
                                // and let EOF error handling below report the listing failure.
                                break;
                            }
                        } else {
                            // First chunk filled while at least one side has not yet yielded a
                            // matching file (e.g. wiped side or >1,000 leading empty dir markers).
                            // Probe ONLY the zero-file side(s) in O(1) RAM, short-circuiting on
                            // the first matching file before executing any mutation!
                            let mut probe_complete = true;
                            if !a_proven_non_empty {
                                match backend_has_any_matching_file(
                                    &self.side_a,
                                    &cfg.a_prefix,
                                    &cfg.filter,
                                    scan_started_ns,
                                    &self.cancel,
                                )
                                .await
                                {
                                    Some(true) => a_proven_non_empty = true,
                                    Some(false) => {}
                                    None => probe_complete = false,
                                }
                            }
                            if probe_complete && !b_proven_non_empty {
                                match backend_has_any_matching_file(
                                    &self.side_b,
                                    &cfg.b_prefix,
                                    &cfg.filter,
                                    scan_started_ns,
                                    &self.cancel,
                                )
                                .await
                                {
                                    Some(true) => b_proven_non_empty = true,
                                    Some(false) => {}
                                    None => probe_complete = false,
                                }
                            }
                            if probe_complete {
                                if let Err(e) = check_empty_side(
                                    u64::from(a_proven_non_empty),
                                    u64::from(b_proven_non_empty),
                                ) {
                                    self.finish_job(job, JobStatus::Failed, cfg.dry_run)
                                        .await?;
                                    return Err(e);
                                }
                                guard_cleared = true;
                            } else {
                                break;
                            }
                        }
                    }

                    if guard_cleared && !chunk_pairs.is_empty() && !report.cancelled {
                        if !early_state_persisted
                            && !cfg.dry_run
                            && (prev_pair_state.is_none() || cfg.resync)
                            && (observed_a_files > 0 || observed_b_files > 0)
                        {
                            self.journal
                                .upsert_bisync_state(&BisyncPairState {
                                    pair_key: pair_key.clone(),
                                    filter_hash: cur_filter_hash.to_string(),
                                    last_a_files: observed_a_files,
                                    last_b_files: observed_b_files,
                                    updated_at: self.clock.now_unix_secs(),
                                })
                                .await?;
                            early_state_persisted = true;
                        }
                        self.process_bisync_chunk(
                            &mut chunk_pairs,
                            cfg,
                            &pair_key,
                            &a_caps,
                            &b_caps,
                            true,
                            mkdir_conc,
                            copy_conc,
                            bwlimit.as_ref(),
                            &emitter,
                            job,
                            &mut report,
                            &mut deletes_a,
                            &mut deletes_b,
                            Some(&mut deferred_baseline_retires),
                            &mut planned_deletes,
                            &mut planned_file_deletes_a,
                            &mut planned_file_deletes_b,
                            &mut created_on_a,
                            &mut created_on_b,
                            &mut active_ops,
                        )
                        .await?;
                    }
                    if hit_eof || report.cancelled {
                        break;
                    }
                }

                if let Some(p) = &self.progress {
                    p.set_totals_discovered(true);
                }
                for info in diff.drain_errors() {
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                }
                let a_ok = diff.src_complete() && !report.cancelled;
                let b_ok = diff.dst_complete() && !report.cancelled;
                report.a_observation_complete = a_ok;
                report.b_observation_complete = b_ok;
                if a_ok && b_ok {
                    if let Err(e) = check_empty_side(observed_a_files, observed_b_files) {
                        self.finish_job(job, JobStatus::Failed, cfg.dry_run)
                            .await?;
                        return Err(e);
                    }
                    if !report.has_errors() {
                        retire_cursor
                            .advance_into(None, &mut deferred_baseline_retires)
                            .await?;
                    }
                }
                a_ok && b_ok && !report.has_errors()
            } else {
                // Phase 1: Concurrently observe both sides into adaptive hybrid SyncDiffIndex.
                self.set_phase(&emitter, TransferPhase::Observing);
                let ((a_ok, a_files, a_errs, prot_a), (b_ok, b_files, b_errs, prot_b)) = tokio::join!(
                    self.observe(
                        &self.side_a,
                        &cfg.a_prefix,
                        &cfg.filter,
                        scan_started_ns,
                        true,
                        &index
                    ),
                    self.observe(
                        &self.side_b,
                        &cfg.b_prefix,
                        &cfg.filter,
                        scan_started_ns,
                        false,
                        &index
                    ),
                );
                protected_a_dirs = prot_a;
                protected_b_dirs = prot_b;
                observed_a_files = a_files;
                observed_b_files = b_files;
                report.a_observation_complete = a_ok;
                report.b_observation_complete = b_ok;
                for info in a_errs.into_iter().chain(b_errs) {
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                }

                if self.cancel.is_cancelled() {
                    report.cancelled = true;
                    self.finish_job(job, JobStatus::Paused, cfg.dry_run)
                        .await?;
                    return Ok(report);
                }

                if a_ok
                    && b_ok
                    && let Err(e) = check_empty_side(observed_a_files, observed_b_files)
                {
                    self.finish_job(job, JobStatus::Failed, cfg.dry_run)
                        .await?;
                    return Err(e);
                }

                let both_case_sensitive = a_caps.case_sensitive && b_caps.case_sensitive;
                let index_conflicts = index
                    .finalize_and_detect_conflicts(both_case_sensitive)
                    .await?;
                let blocked_paths: HashSet<RelPath> = index_conflicts
                    .iter()
                    .map(|c| c.nfc_path.clone())
                    .collect();
                for c in index_conflicts {
                    emitter.emit_conflict(c.clone());
                    report.push_conflict(c);
                }

                // Observation Completeness Gate: ANY scan error disables ALL deletes on BOTH sides!
                let allow_deletes = a_ok && b_ok && !report.has_errors();

                // `--resync` explicitly discards stale baselines for this pair so both trees merge
                // their union cleanly without inferring deletions from outdated merge-base rows.
                if cfg.resync && !cfg.dry_run && allow_deletes {
                    self.journal.delete_pair_baselines(&pair_key).await?;
                }

                // Persist initial `bisync_state` right after Phase 1 observation (before Phase 2
                // transfers start) so an interrupted first run never leaves the empty-side guard
                // unarmed on the next run.
                if !cfg.dry_run
                    && a_ok
                    && b_ok
                    && (prev_pair_state.is_none() || cfg.resync)
                    && (observed_a_files > 0 || observed_b_files > 0)
                {
                    self.journal
                        .upsert_bisync_state(&BisyncPairState {
                            pair_key: pair_key.clone(),
                            filter_hash: cur_filter_hash.to_string(),
                            last_a_files: observed_a_files,
                            last_b_files: observed_b_files,
                            updated_at: self.clock.now_unix_secs(),
                        })
                        .await?;
                }

                // Phase 2: Stream Pass A and Pass B in bounded 512-row chunks (O(chunk) RAM!).
                let mut chunk_pairs: Vec<(Option<Entry>, Option<Entry>)> =
                    Vec::with_capacity(DIFF_PAGE_SIZE);
                let mut after_a = 0i64;
                loop {
                    if self.cancel.is_cancelled() {
                        report.cancelled = true;
                        break;
                    }
                    let page = index.next_src_page(after_a, DIFF_PAGE_SIZE).await?;
                    if page.is_empty() {
                        break;
                    }
                    chunk_pairs.clear();
                    for row in page {
                        after_a = row.row_id;
                        let Some(a_entry) = row.src else { continue };
                        if blocked_paths.contains(&a_entry.nfc_path) {
                            continue;
                        }
                        chunk_pairs.push((Some(a_entry), row.dst));
                    }
                    if !chunk_pairs.is_empty() {
                        self.process_bisync_chunk(
                            &mut chunk_pairs,
                            cfg,
                            &pair_key,
                            &a_caps,
                            &b_caps,
                            allow_deletes,
                            mkdir_conc,
                            copy_conc,
                            bwlimit.as_ref(),
                            &emitter,
                            job,
                            &mut report,
                            &mut deletes_a,
                            &mut deletes_b,
                            None,
                            &mut planned_deletes,
                            &mut planned_file_deletes_a,
                            &mut planned_file_deletes_b,
                            &mut created_on_a,
                            &mut created_on_b,
                            &mut active_ops,
                        )
                        .await?;
                    }
                    if report.cancelled {
                        break;
                    }
                }

                let mut after_b = 0i64;
                while !report.cancelled {
                    if self.cancel.is_cancelled() {
                        report.cancelled = true;
                        break;
                    }
                    let page = index.next_dst_only_page(after_b, DIFF_PAGE_SIZE).await?;
                    if page.is_empty() {
                        break;
                    }
                    chunk_pairs.clear();
                    for row in page {
                        after_b = row.row_id;
                        let Some(b_entry) = row.dst else { continue };
                        if blocked_paths.contains(&b_entry.nfc_path) {
                            continue;
                        }
                        chunk_pairs.push((None, Some(b_entry)));
                    }
                    if !chunk_pairs.is_empty() {
                        self.process_bisync_chunk(
                            &mut chunk_pairs,
                            cfg,
                            &pair_key,
                            &a_caps,
                            &b_caps,
                            allow_deletes,
                            mkdir_conc,
                            copy_conc,
                            bwlimit.as_ref(),
                            &emitter,
                            job,
                            &mut report,
                            &mut deletes_a,
                            &mut deletes_b,
                            None,
                            &mut planned_deletes,
                            &mut planned_file_deletes_a,
                            &mut planned_file_deletes_b,
                            &mut created_on_a,
                            &mut created_on_b,
                            &mut active_ops,
                        )
                        .await?;
                    }
                }
                allow_deletes
            };

            if report.cancelled {
                if !cfg.dry_run
                    && (prev_pair_state.is_none() || cfg.resync)
                    && (created_on_a > 0 || created_on_b > 0)
                {
                    let _ = self
                        .journal
                        .upsert_bisync_state(&BisyncPairState {
                            pair_key: pair_key.clone(),
                            filter_hash: cur_filter_hash.to_string(),
                            last_a_files: observed_a_files.saturating_add(created_on_a),
                            last_b_files: observed_b_files.saturating_add(created_on_b),
                            updated_at: self.clock.now_unix_secs(),
                        })
                        .await;
                }
                job.bytes_done = report.bytes_transferred;
                self.finish_job(job, JobStatus::Paused, cfg.dry_run)
                    .await?;
                return Ok(report);
            }

            self.set_phase(&emitter, TransferPhase::Finalizing);

            // Flush deferred local writes on both sides, then commit the baselines held
            // back behind that flush, BEFORE Phase-3 deletes (D2 batch durability).
            if !cfg.dry_run {
                self.fence.drain().await?;
            }

            // Enforce `--max-delete` (explicit count or default percentage) circuit breaker
            // BEFORE performing any deletion!
            let delete_trip_msg: Option<String> = if let Some(lim) = cfg.max_delete {
                (planned_deletes > lim).then(|| {
                    format!(
                        "bisync delete circuit breaker tripped: {planned_deletes} deletions exceed --max-delete={lim}"
                    )
                })
            } else if let Some(pct) = cfg.max_delete_percent
                && !(cfg.force_empty_side && (observed_a_files == 0 || observed_b_files == 0))
            {
                let limit_for = |obs: u64| ((obs as f64) * pct / 100.0).floor() as u64;
                let total_file_deletes =
                    planned_file_deletes_a.saturating_add(planned_file_deletes_b);
                let total_obs = observed_a_files.max(observed_b_files);
                if observed_a_files > 0 && planned_file_deletes_a > limit_for(observed_a_files) {
                    let lim = limit_for(observed_a_files);
                    Some(format!(
                        "bisync delete circuit breaker tripped: planned {planned_file_deletes_a} file deletions on side A exceeds --max-delete={pct}% ({lim} of {observed_a_files} observed files)"
                    ))
                } else if observed_b_files > 0
                    && planned_file_deletes_b > limit_for(observed_b_files)
                {
                    let lim = limit_for(observed_b_files);
                    Some(format!(
                        "bisync delete circuit breaker tripped: planned {planned_file_deletes_b} file deletions on side B exceeds --max-delete={pct}% ({lim} of {observed_b_files} observed files)"
                    ))
                } else if total_obs > 0 && total_file_deletes > limit_for(total_obs) {
                    let lim = limit_for(total_obs);
                    Some(format!(
                        "bisync delete circuit breaker tripped: planned {total_file_deletes} file deletions exceeds --max-delete={pct}% ({lim} of {total_obs} observed files)"
                    ))
                } else {
                    None
                }
            } else {
                None
            };
            let deletes_tripped = delete_trip_msg.is_some();
            if let Some(msg) = delete_trip_msg {
                let err = Error::precondition_failed(msg.clone());
                let info = TransferErrorInfo::from_error_with_message(None, &err, msg);
                if let Some(p) = &self.progress {
                    p.inc_errors();
                }
                emitter.emit_error(info.clone());
                report.push_error(info);
            }

            // Phase 3: Apply deletions & deferred baseline retirements ONLY if zero errors
            // occurred on observations & copies!
            let mut deleted_files_a = 0u64;
            let mut deleted_files_b = 0u64;
            if allow_deletes && !deletes_tripped && !report.has_errors() && !report.cancelled {
                let del_conc = cfg.transfers.clamp(1, 16);
                let (deleted_a, del_files_a) = self
                    .execute_side_delete_logs(
                        &self.side_a,
                        &cfg.a_prefix,
                        "A",
                        deletes_a.files,
                        deletes_a.dirs,
                        &protected_a_dirs,
                        &pair_key,
                        del_conc,
                        cfg.dry_run,
                        &emitter,
                        &mut report,
                    )
                    .await?;
                report.deleted_on_a += deleted_a;
                deleted_files_a += del_files_a;

                if !report.cancelled {
                    let (deleted_b, del_files_b) = self
                        .execute_side_delete_logs(
                            &self.side_b,
                            &cfg.b_prefix,
                            "B",
                            deletes_b.files,
                            deletes_b.dirs,
                            &protected_b_dirs,
                            &pair_key,
                            del_conc,
                            cfg.dry_run,
                            &emitter,
                            &mut report,
                        )
                        .await?;
                    report.deleted_on_b += deleted_b;
                    deleted_files_b += del_files_b;
                }

                if !cfg.dry_run
                    && !report.cancelled
                    && !report.has_errors()
                    && !deferred_baseline_retires.is_empty()
                {
                    let mut reader = deferred_baseline_retires.into_reader_async().await?;
                    let mut raw_chunk = Vec::with_capacity(DIFF_PAGE_SIZE);
                    let mut keys = Vec::with_capacity(DIFF_PAGE_SIZE);
                    while reader
                        .next_chunk_async(DIFF_PAGE_SIZE, &mut raw_chunk)
                        .await?
                        > 0
                    {
                        keys.clear();
                        for item in raw_chunk.drain(..) {
                            keys.push(item.nfc_path);
                        }
                        let _ = self.journal.delete_baselines_batch(&pair_key, &keys).await;
                    }
                }
            } else if (!allow_deletes || report.has_errors()) && planned_deletes > 0 {
                warn!("skipping bisync deletions due to observation/transfer errors");
            }

            let status = if report.cancelled {
                JobStatus::Paused
            } else if report.has_errors() {
                JobStatus::Failed
            } else if report.has_conflicts() {
                JobStatus::CompletedWithConflicts
            } else {
                JobStatus::Completed
            };
            job.bytes_done = report.bytes_transferred;
            self.finish_job(job, status, cfg.dry_run).await?;
            if !cfg.dry_run
                && !report.cancelled
                && !report.has_errors()
                && report.a_observation_complete
                && report.b_observation_complete
            {
                let final_a_files = observed_a_files
                    .saturating_add(created_on_a)
                    .saturating_sub(deleted_files_a);
                let final_b_files = observed_b_files
                    .saturating_add(created_on_b)
                    .saturating_sub(deleted_files_b);
                self.journal
                    .upsert_bisync_state(&BisyncPairState {
                        pair_key: pair_key.clone(),
                        filter_hash: cur_filter_hash.to_string(),
                        last_a_files: final_a_files,
                        last_b_files: final_b_files,
                        updated_at: self.clock.now_unix_secs(),
                    })
                    .await?;
            } else if !cfg.dry_run
                && (prev_pair_state.is_none() || cfg.resync)
                && (created_on_a > 0 || created_on_b > 0)
            {
                let _ = self
                    .journal
                    .upsert_bisync_state(&BisyncPairState {
                        pair_key: pair_key.clone(),
                        filter_hash: cur_filter_hash.to_string(),
                        last_a_files: observed_a_files.saturating_add(created_on_a),
                        last_b_files: observed_b_files.saturating_add(created_on_b),
                        updated_at: self.clock.now_unix_secs(),
                    })
                    .await;
            }
            self.set_phase(&emitter, TransferPhase::Completed);
            Ok(report)
        }
        .await;

        match run_res {
            Ok(report) => {
                event_guard.finish(
                    report.copied_a_to_b + report.copied_b_to_a,
                    report.converged_skipped,
                    report.bytes_transferred,
                    report.errors.len(),
                    report.conflicts.len(),
                    report.cancelled,
                );
                Ok(report)
            }
            Err(err) => {
                if let Some(mut job) = started_job
                    && job.status == JobStatus::Running
                {
                    let fail_status = if err.retry == crate::error::RetryClass::Cancelled
                        || self.cancel.is_cancelled()
                    {
                        JobStatus::Paused
                    } else {
                        JobStatus::Failed
                    };
                    let _ = self.finish_job(&mut job, fail_status, cfg.dry_run).await;
                }
                event_guard.finish_err(&err);
                Err(err)
            }
        }
    }

    /// Plan and immediately execute one bounded `<= 512`-item chunk of bisync pairs,
    /// keeping work queues strictly `O(chunk)` in RAM while buffering deletions into
    /// hybrid [`SideDeleteLogs`] until Phase 3 completeness + `--max-delete` checks pass.
    #[allow(clippy::too_many_arguments)]
    async fn process_bisync_chunk(
        &self,
        chunk_pairs: &mut Vec<(Option<Entry>, Option<Entry>)>,
        cfg: &BisyncConfig,
        pair_key: &str,
        a_caps: &Capabilities,
        b_caps: &Capabilities,
        allow_deletes: bool,
        mkdir_conc: usize,
        copy_conc: usize,
        bwlimit: Option<&Arc<BandwidthLimiter>>,
        emitter: &JobEventEmitter,
        job: &mut JobRecord,
        report: &mut BisyncReport,
        deletes_a: &mut SideDeleteLogs,
        deletes_b: &mut SideDeleteLogs,
        mut deferred_retires: Option<&mut DeleteSpillLog>,
        planned_deletes: &mut u64,
        planned_file_deletes_a: &mut u64,
        planned_file_deletes_b: &mut u64,
        created_on_a: &mut u64,
        created_on_b: &mut u64,
        active_ops: &mut std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>>,
    ) -> Result<()> {
        let mut baselines = if cfg.resync {
            std::collections::HashMap::new()
        } else {
            let paths: Vec<RelPath> = chunk_pairs
                .iter()
                .filter_map(|(a, b)| a.as_ref().or(b.as_ref()).map(|e| e.nfc_path.clone()))
                .collect();
            self.journal.get_baselines_batch(pair_key, &paths).await?
        };

        let mut mkdirs_a: BTreeMap<usize, Vec<RelPath>> = BTreeMap::new();
        let mut mkdirs_b: BTreeMap<usize, Vec<RelPath>> = BTreeMap::new();
        let mut chunk_actions: Vec<BisyncAction> = Vec::new();
        let mut stale_baselines: Vec<RelPath> = Vec::new();

        for (a_opt, b_opt) in chunk_pairs.drain(..) {
            let nfc_path = match (&a_opt, &b_opt) {
                (Some(a), _) => &a.nfc_path,
                (None, Some(b)) => &b.nfc_path,
                (None, None) => continue,
            };
            let base = baselines.remove(nfc_path);
            let is_file_noop = a_opt.as_ref().is_some_and(|a| a.kind == EntryKind::File)
                && b_opt.as_ref().is_some_and(|b| b.kind == EntryKind::File);
            let action = plan_three_tree(
                a_opt.as_ref(),
                b_opt.as_ref(),
                base.as_ref(),
                a_caps,
                b_caps,
                allow_deletes,
            );
            let action = self.force_copy_if_integrity_marked(
                action,
                a_opt.as_ref(),
                b_opt.as_ref(),
                nfc_path,
                active_ops,
            );
            self.classify_planned_action(
                action,
                nfc_path,
                is_file_noop,
                cfg,
                pair_key,
                emitter,
                report,
                &mut mkdirs_a,
                &mut mkdirs_b,
                deletes_a,
                deletes_b,
                planned_deletes,
                planned_file_deletes_a,
                planned_file_deletes_b,
                &mut stale_baselines,
                &mut chunk_actions,
                active_ops,
            )
            .await?;
        }

        if !stale_baselines.is_empty() && !cfg.dry_run {
            if let Some(ref mut log) = deferred_retires {
                for rel in stale_baselines {
                    log.push_async(DeleteTarget {
                        backend_path: BackendPath::from_rel(rel.clone()),
                        nfc_path: rel,
                        kind: EntryKind::File,
                        expected_version: None,
                    })
                    .await?;
                }
            } else {
                let _ = self
                    .journal
                    .delete_baselines_batch(pair_key, &stale_baselines)
                    .await;
            }
        }

        if !mkdirs_a.is_empty() || !mkdirs_b.is_empty() {
            self.set_phase(emitter, TransferPhase::CreatingDirs);
            self.execute_mkdirs_by_depth(
                &self.side_a,
                &cfg.a_prefix,
                "A",
                mkdirs_a,
                mkdir_conc,
                cfg.dry_run,
                emitter,
                report,
            )
            .await?;
            self.execute_mkdirs_by_depth(
                &self.side_b,
                &cfg.b_prefix,
                "B",
                mkdirs_b,
                mkdir_conc,
                cfg.dry_run,
                emitter,
                report,
            )
            .await?;
        }

        if report.cancelled || chunk_actions.is_empty() {
            return Ok(());
        }

        for action in &chunk_actions {
            match action {
                BisyncAction::CopyAToB { a, .. } => {
                    job.files_total += 1;
                    job.bytes_total = job.bytes_total.saturating_add(a.size);
                    if let Some(p) = &self.progress {
                        p.add_planned_file(a.size);
                    }
                }
                BisyncAction::CopyBToA { b, .. } => {
                    job.files_total += 1;
                    job.bytes_total = job.bytes_total.saturating_add(b.size);
                    if let Some(p) = &self.progress {
                        p.add_planned_file(b.size);
                    }
                }
                BisyncAction::Conflict { kind, a, b, .. } => {
                    let is_type_flip = matches!(
                        kind,
                        ConflictKind::TypeFlipFileOverDir | ConflictKind::TypeFlipDirOverFile
                    );
                    if !is_type_flip {
                        match cfg.conflict_strategy {
                            ConflictStrategy::PreferA => {
                                if let Some(ae) = a {
                                    job.files_total += 1;
                                    job.bytes_total = job.bytes_total.saturating_add(ae.size);
                                    if let Some(p) = &self.progress {
                                        p.add_planned_file(ae.size);
                                    }
                                }
                            }
                            ConflictStrategy::PreferB => {
                                if let Some(be) = b {
                                    job.files_total += 1;
                                    job.bytes_total = job.bytes_total.saturating_add(be.size);
                                    if let Some(p) = &self.progress {
                                        p.add_planned_file(be.size);
                                    }
                                }
                            }
                            ConflictStrategy::KeepBoth => match (a, b) {
                                (Some(ae), Some(be)) => {
                                    job.files_total += 3;
                                    job.bytes_total = job
                                        .bytes_total
                                        .saturating_add(be.size)
                                        .saturating_add(be.size)
                                        .saturating_add(ae.size);
                                    if let Some(p) = &self.progress {
                                        p.add_planned_file(be.size);
                                        p.add_planned_file(be.size);
                                        p.add_planned_file(ae.size);
                                    }
                                }
                                (Some(ae), None) => {
                                    job.files_total += 1;
                                    job.bytes_total = job.bytes_total.saturating_add(ae.size);
                                    if let Some(p) = &self.progress {
                                        p.add_planned_file(ae.size);
                                    }
                                }
                                (None, Some(be)) => {
                                    job.files_total += 1;
                                    job.bytes_total = job.bytes_total.saturating_add(be.size);
                                    if let Some(p) = &self.progress {
                                        p.add_planned_file(be.size);
                                    }
                                }
                                (None, None) => {}
                            },
                            ConflictStrategy::Abort => {}
                        }
                    }
                }
                _ => {}
            }
        }

        self.set_phase(emitter, TransferPhase::Transferring);
        let track_reverse_ops = !cfg.dry_run && !active_ops.is_empty();
        let a_ep = track_reverse_ops.then(|| self.side_a.endpoint_identity());
        let b_ep = track_reverse_ops.then(|| self.side_b.endpoint_identity());
        let mut outcomes = futures::stream::iter(chunk_actions)
            .map(|action| {
                let copy_meta = if track_reverse_ops {
                    match &action {
                        BisyncAction::CopyAToB { a, .. } => {
                            Some((a.nfc_path.clone(), b_ep.clone().unwrap_or_default()))
                        }
                        BisyncAction::CopyBToA { b, .. } => {
                            Some((b.nfc_path.clone(), a_ep.clone().unwrap_or_default()))
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                async move {
                    let res = self
                        .execute_work_action(
                            action, cfg, pair_key, a_caps, b_caps, emitter, bwlimit,
                        )
                        .await;
                    (copy_meta, res)
                }
            })
            .buffer_unordered(copy_conc);

        while let Some((copy_meta, res)) = outcomes.next().await {
            let out = res?;
            if out.cancelled {
                report.cancelled = true;
            }
            if !out.cancelled
                && out.errors.is_empty()
                && let Some((rel, committed_dst_ep)) = copy_meta
                && let Some(ops) = active_ops.remove(&rel)
            {
                let reverse_ops: Vec<_> = ops
                    .into_iter()
                    .filter(|op| op.dst_endpoint != committed_dst_ep)
                    .collect();
                if !reverse_ops.is_empty() {
                    self.retire_bisync_ops(reverse_ops, false).await?;
                }
            }
            report.copied_a_to_b += out.copied_a_to_b;
            report.copied_b_to_a += out.copied_b_to_a;
            *created_on_a += out.created_on_a;
            *created_on_b += out.created_on_b;
            job.files_done = job.files_done.saturating_add(out.files_done);
            report.bytes_transferred = report
                .bytes_transferred
                .saturating_add(out.bytes_transferred);
            report.conflicts_resolved += out.conflicts_resolved;
            if let Some(c) = out.conflict {
                report.push_conflict(c);
            }
            for err in out.errors {
                report.push_error(err);
            }
            if let Some(da) = out.extra_delete_a {
                *planned_deletes += 1;
                if da.kind != EntryKind::Directory {
                    *planned_file_deletes_a += 1;
                }
                if cfg.max_delete.is_none_or(|lim| *planned_deletes <= lim) {
                    deletes_a.push_entry(da).await?;
                }
            }
            if let Some(db) = out.extra_delete_b {
                *planned_deletes += 1;
                if db.kind != EntryKind::Directory {
                    *planned_file_deletes_b += 1;
                }
                if cfg.max_delete.is_none_or(|lim| *planned_deletes <= lim) {
                    deletes_b.push_entry(db).await?;
                }
            }
        }
        Ok(())
    }

    async fn load_active_ops_for_bisync(
        &self,
        cfg: &BisyncConfig,
    ) -> Result<std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>>> {
        if cfg.dry_run {
            return Ok(std::collections::HashMap::new());
        }
        let ops = self.journal.list_active_operations().await?;
        if ops.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let a_ep = self.side_a.endpoint_identity();
        let b_ep = self.side_b.endpoint_identity();
        let mut map: std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>> =
            std::collections::HashMap::new();
        for op in ops {
            let rel_opt = if op.src_endpoint == a_ep && op.dst_endpoint == b_ep {
                op.dst_nfc_path.strip_prefix(&cfg.b_prefix)
            } else if op.src_endpoint == b_ep && op.dst_endpoint == a_ep {
                op.dst_nfc_path.strip_prefix(&cfg.a_prefix)
            } else {
                None
            };
            if let Some(rel) = rel_opt
                && !rel.is_root()
            {
                map.entry(rel).or_default().push(op);
            }
        }
        Ok(map)
    }

    /// A path with an [`crate::state::OperationState::IntegrityFailed`] marker holds
    /// corrupt bytes on the marker's destination side. While that side still holds the
    /// recorded corrupt object, the path is never treated as in sync (no baseline over it)
    /// and the corrupt copy is never propagated: it is re-copied from the good side.
    fn force_copy_if_integrity_marked(
        &self,
        action: BisyncAction,
        a: Option<&Entry>,
        b: Option<&Entry>,
        nfc_path: &RelPath,
        active_ops: &std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>>,
    ) -> BisyncAction {
        let Some(marker) = active_ops.get(nfc_path).and_then(|ops| {
            ops.iter()
                .find(|o| o.state == crate::state::OperationState::IntegrityFailed)
        }) else {
            return action;
        };
        let (Some(a), Some(b)) = (a, b) else {
            return action;
        };
        if a.kind != EntryKind::File || b.kind != EntryKind::File {
            return action;
        }
        let corrupt_on_b = marker.dst_endpoint == self.side_b.endpoint_identity();
        let corrupt = if corrupt_on_b { b } else { a };
        if !crate::state::integrity_marker_matches(marker, corrupt) {
            // The corrupt object was replaced since (e.g. edited by the user): plan normally.
            return action;
        }
        tracing::warn!(path = %nfc_path, "bisync side holds bytes that failed checksum verification; re-copying from the other side");
        if corrupt_on_b {
            BisyncAction::CopyAToB {
                a: a.clone(),
                b_existing: Some(b.clone()),
            }
        } else {
            BisyncAction::CopyBToA {
                b: b.clone(),
                a_existing: Some(a.clone()),
            }
        }
    }

    /// Crash-recovery guard (see `TransferEngine::distrust_unflushed_skip`): sides that look
    /// converged by size and mtime are only trusted when no leftover `Completing` operation
    /// wrote one of them to a side that defers durability, or when a common content hash
    /// matches. Otherwise the leftover operations are dropped and the copy is redone in the
    /// direction the interrupted operation ran, overwriting the possibly unflushed file.
    async fn distrust_unflushed_convergence(
        &self,
        cfg: &BisyncConfig,
        a: &Entry,
        b: &Entry,
        active_ops: &mut std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>>,
    ) -> Result<Option<BisyncAction>> {
        if a.kind != EntryKind::File || b.kind != EntryKind::File {
            return Ok(None);
        }
        let b_ep = self.side_b.endpoint_identity();
        let Some(written_b) = active_ops.get(&a.nfc_path).and_then(|ops| {
            ops.iter()
                .rev()
                .find(|op| {
                    matches!(
                        op.state,
                        crate::state::OperationState::Completing
                            | crate::state::OperationState::NeedsReconciliation
                    )
                })
                .map(|op| op.dst_endpoint == b_ep)
        }) else {
            return Ok(None);
        };
        let written_side = if written_b {
            &self.side_b
        } else {
            &self.side_a
        };
        if !written_side.defers_durable_writes() {
            return Ok(None);
        }
        let a_bp = BackendPath::join_prefixed(
            &cfg.a_prefix,
            a.raw_path(),
            &a.nfc_path,
            a.node_id.clone(),
            Some(EntryKind::File),
        )?;
        let b_bp = BackendPath::join_prefixed(
            &cfg.b_prefix,
            b.raw_path(),
            &b.nfc_path,
            b.node_id.clone(),
            Some(EntryKind::File),
        )?;
        let a_caps = self.side_a.capabilities();
        let b_caps = self.side_b.capabilities();
        let content_matches = match a_caps.best_common_hash(&b_caps) {
            Some(kind) => {
                let (ha, hb) = tokio::join!(
                    self.side_a.compute_hash(&a_bp, kind),
                    self.side_b.compute_hash(&b_bp, kind)
                );
                matches!((ha, hb), (Ok(Some(x)), Ok(Some(y))) if x.hex.eq_ignore_ascii_case(&y.hex))
            }
            None => false,
        };
        if content_matches {
            return Ok(None);
        }
        tracing::warn!(
            path = %a.nfc_path,
            "bisync file written by an interrupted run is not verifiably intact; copying it again"
        );
        if let Some(ops) = active_ops.remove(&a.nfc_path) {
            self.retire_bisync_ops(ops, false).await?;
        }
        Ok(Some(if written_b {
            BisyncAction::CopyAToB {
                a: a.clone(),
                b_existing: Some(b.clone()),
            }
        } else {
            BisyncAction::CopyBToA {
                b: b.clone(),
                a_existing: Some(a.clone()),
            }
        }))
    }

    async fn retire_bisync_ops(
        &self,
        ops: Vec<crate::state::OperationRecord>,
        keep_last_for_atomic_commit: bool,
    ) -> Result<Option<String>> {
        // Integrity markers are cleared only by a verified transfer of the path.
        let ops: Vec<_> = ops
            .into_iter()
            .filter(|o| o.state != crate::state::OperationState::IntegrityFailed)
            .collect();
        if ops.is_empty() {
            return Ok(None);
        }
        let b_ep = self.side_b.endpoint_identity();
        let mut atomic_id: Option<String> = None;
        for op in ops {
            if op.session_token.is_some()
                && !matches!(
                    op.state,
                    crate::state::OperationState::Completing
                        | crate::state::OperationState::NeedsReconciliation
                )
            {
                let dst_side = if op.dst_endpoint == b_ep {
                    &self.side_b
                } else {
                    &self.side_a
                };
                let _ = dst_side.abort_upload(&op).await;
            }
            if keep_last_for_atomic_commit {
                if let Some(prev) = atomic_id.replace(op.op_id) {
                    self.journal.delete_operation(&prev).await?;
                }
            } else {
                self.journal.delete_operation(&op.op_id).await?;
            }
        }
        Ok(atomic_id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn classify_planned_action(
        &self,
        action: BisyncAction,
        nfc_path: &RelPath,
        is_file_noop: bool,
        cfg: &BisyncConfig,
        pair_key: &str,
        emitter: &JobEventEmitter,
        report: &mut BisyncReport,
        mkdirs_a: &mut BTreeMap<usize, Vec<RelPath>>,
        mkdirs_b: &mut BTreeMap<usize, Vec<RelPath>>,
        deletes_a: &mut SideDeleteLogs,
        deletes_b: &mut SideDeleteLogs,
        planned_deletes: &mut u64,
        planned_file_deletes_a: &mut u64,
        planned_file_deletes_b: &mut u64,
        stale_baselines: &mut Vec<RelPath>,
        work_actions: &mut Vec<BisyncAction>,
        active_ops: &mut std::collections::HashMap<RelPath, Vec<crate::state::OperationRecord>>,
    ) -> Result<()> {
        match action {
            BisyncAction::Noop => {
                if is_file_noop {
                    if !cfg.dry_run
                        && let Some(ops) = active_ops.remove(nfc_path)
                    {
                        self.retire_bisync_ops(ops, false).await?;
                    }
                    report.converged_skipped += 1;
                    if let Some(p) = &self.progress {
                        p.add_planned_skip();
                    }
                }
            }
            BisyncAction::ConvergedUpdateBaseline { a, b } => {
                if !cfg.dry_run
                    && let Some(redo) = self
                        .distrust_unflushed_convergence(cfg, &a, &b, active_ops)
                        .await?
                {
                    work_actions.push(redo);
                    return Ok(());
                }
                report.converged_skipped += 1;
                if let Some(p) = &self.progress {
                    p.add_planned_skip();
                }
                if !cfg.dry_run {
                    let rec = make_bisync_baseline(pair_key, &a, &b, &self.clock);
                    let retire_op_id = match active_ops.remove(&a.nfc_path) {
                        Some(ops) => self.retire_bisync_ops(ops, true).await?,
                        None => None,
                    };
                    self.journal
                        .commit_verified_transfer(
                            retire_op_id.as_deref(),
                            Some(&rec),
                            &cfg.job_id,
                            0,
                        )
                        .await?;
                }
                emitter
                    .emit_file_completed(FileTransferResult::skipped(a.nfc_path.as_str(), false));
            }
            BisyncAction::RetireStaleBaseline(rel) => {
                if !cfg.dry_run {
                    stale_baselines.push(rel);
                }
            }
            BisyncAction::MkdirOnA(rel) => {
                let depth = rel.segments().count();
                mkdirs_a.entry(depth).or_default().push(rel);
            }
            BisyncAction::MkdirOnB(rel) => {
                let depth = rel.segments().count();
                mkdirs_b.entry(depth).or_default().push(rel);
            }
            BisyncAction::DeleteOnA(e) => {
                *planned_deletes += 1;
                if e.kind != EntryKind::Directory {
                    *planned_file_deletes_a += 1;
                }
                if cfg.max_delete.is_none_or(|lim| *planned_deletes <= lim) {
                    deletes_a.push_entry(e).await?;
                }
            }
            BisyncAction::DeleteOnB(e) => {
                *planned_deletes += 1;
                if e.kind != EntryKind::Directory {
                    *planned_file_deletes_b += 1;
                }
                if cfg.max_delete.is_none_or(|lim| *planned_deletes <= lim) {
                    deletes_b.push_entry(e).await?;
                }
            }
            other => work_actions.push(other),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_mkdirs_by_depth(
        &self,
        backend: &Arc<dyn StorageBackend>,
        prefix: &RelPath,
        side_label: &str,
        mkdirs: BTreeMap<usize, Vec<RelPath>>,
        conc: usize,
        dry_run: bool,
        emitter: &JobEventEmitter,
        report: &mut BisyncReport,
    ) -> Result<()> {
        for (_depth, dirs) in mkdirs {
            if self.cancel.is_cancelled() {
                report.cancelled = true;
                break;
            }
            if dry_run {
                report.dirs_created += dirs.len() as u64;
                continue;
            }
            let mut targets = Vec::with_capacity(dirs.len());
            for rel in dirs {
                targets.push(prefix.join_path(&rel));
            }
            let b = backend.clone();
            let mut stream = futures::stream::iter(targets)
                .map(move |target| {
                    let b = b.clone();
                    async move {
                        let res = b.mkdir(&target).await;
                        (target, res)
                    }
                })
                .buffer_unordered(conc);
            while let Some((target, res)) = stream.next().await {
                if let Err(e) = res {
                    if let Some(p) = &self.progress {
                        p.inc_errors();
                    }
                    let msg = format!("mkdir {side_label} `{target}`: {e}");
                    let info = TransferErrorInfo::from_error_with_message(
                        Some(target.as_str().to_string()),
                        &e,
                        msg,
                    );
                    emitter.emit_error(info.clone());
                    report.push_error(info);
                } else {
                    report.dirs_created += 1;
                    if let Some(p) = &self.progress {
                        p.inc_dirs_created();
                    }
                }
            }
        }
        Ok(())
    }

    async fn observe(
        &self,
        backend: &Arc<dyn StorageBackend>,
        prefix: &RelPath,
        filter: &FilterSet,
        scan_started_ns: i64,
        is_side_a: bool,
        index: &Arc<dyn SyncDiffIndex>,
    ) -> (bool, u64, Vec<TransferErrorInfo>, ProtectedDirs) {
        let mut errors = Vec::new();
        let mut complete = true;
        let mut files_observed = 0u64;
        let mut protected_dirs = ProtectedDirs::default();
        let list_opts =
            crate::backend::ListOptions::recursive().with_filter_pruning(filter, prefix);
        let mut stream = match backend.list_with_options(prefix, &list_opts).await {
            Ok(s) => s,
            Err(e) => {
                errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &e,
                    format!("bisync list `{}` failed: {e}", backend.name()),
                ));
                return (false, 0, errors, protected_dirs);
            }
        };
        let mut batch = Vec::with_capacity(OBSERVE_BATCH_SIZE);
        while let Some(item) = stream.next().await {
            if self.cancel.is_cancelled() {
                complete = false;
                break;
            }
            match item {
                Ok(mut entry) => {
                    if !prefix.is_root() {
                        let old_raw = entry.raw_path.take();
                        if let Some(rel) = entry.nfc_path.strip_prefix(prefix) {
                            entry.nfc_path = rel;
                        } else {
                            continue;
                        }
                        if let Some(raw_full) = old_raw
                            && let Some(raw_rel) = strip_raw_prefix(&raw_full, prefix.as_str())
                        {
                            entry.set_raw_path(&raw_rel);
                        }
                    }
                    if entry.nfc_path.is_root() {
                        continue;
                    }
                    if !filter.matches_entry(&entry, scan_started_ns) {
                        protected_dirs.protect_ancestors(&entry.nfc_path);
                        continue;
                    }
                    if entry.kind == EntryKind::File {
                        files_observed += 1;
                    }
                    batch.push(entry);
                    if batch.len() >= OBSERVE_BATCH_SIZE {
                        let chunk =
                            std::mem::replace(&mut batch, Vec::with_capacity(OBSERVE_BATCH_SIZE));
                        let res = if is_side_a {
                            index.insert_src_batch(chunk).await
                        } else {
                            index.insert_dst_batch(chunk).await
                        };
                        if let Err(e) = res {
                            errors.push(TransferErrorInfo::from_error_with_message(
                                None,
                                &e,
                                format!("bisync index insert failed: {e}"),
                            ));
                            complete = false;
                            break;
                        }
                    }
                }
                Err(e) => {
                    complete = false;
                    if errors.len() < MAX_REPORT_ERRORS {
                        errors.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("bisync observe `{}` error: {e}", backend.name()),
                        ));
                    }
                }
            }
        }
        if !batch.is_empty() {
            let res = if is_side_a {
                index.insert_src_batch(batch).await
            } else {
                index.insert_dst_batch(batch).await
            };
            if let Err(e) = res {
                errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &e,
                    format!("bisync index flush failed: {e}"),
                ));
                complete = false;
            }
        }
        (complete, files_observed, errors, protected_dirs)
    }

    async fn finish_job(
        &self,
        job: &mut JobRecord,
        status: JobStatus,
        dry_run: bool,
    ) -> Result<()> {
        if !dry_run {
            job.status = status;
            job.updated_at = self.clock.now_unix_secs();
            self.journal.upsert_job(job).await?;
        }
        Ok(())
    }
}

/// O(1)-memory short-circuiting probe checking whether `backend` under `prefix` contains
/// at least one `EntryKind::File` matching `filter`. Returns:
/// - `Some(true)` as soon as the first matching file is observed
/// - `Some(false)` only after reaching clean EOF with zero listing errors
/// - `None` if cancelled or if listing encountered an error (fail-closed)
async fn backend_has_any_matching_file(
    backend: &Arc<dyn StorageBackend>,
    prefix: &RelPath,
    filter: &FilterSet,
    now_ns: i64,
    cancel: &CancelFlag,
) -> Option<bool> {
    let opts = ListOptions::recursive().with_filter_pruning(filter, prefix);
    let mut stream = backend.list_with_options(prefix, &opts).await.ok()?;
    while let Some(item) = stream.next().await {
        if cancel.is_cancelled() {
            return None;
        }
        match item {
            Ok(mut entry) => {
                if !prefix.is_root() {
                    let Some(stripped) = entry.nfc_path.strip_prefix(prefix) else {
                        continue;
                    };
                    if stripped.is_root() {
                        continue;
                    }
                    entry.nfc_path = stripped;
                }
                if entry.kind == EntryKind::File && filter.matches_entry(&entry, now_ns) {
                    return Some(true);
                }
            }
            Err(_) => return None,
        }
    }
    Some(false)
}
