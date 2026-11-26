//! Unison / Dropbox Canopy Three-Tree Bidirectional Sync (`bisync`).
//!
//! Computes deterministic converging reconciliation actions over:
//! - **Tree A** (`side_a` observed into `SyncDiffIndex::src_entries`)
//! - **Tree B** (`side_b` observed into `SyncDiffIndex::dst_entries`)
//! - **Merge-Base O** (dual-side durable `sync_baseline` in SQLite!)
//!
//! Safety guarantees:
//! - Concurrent edits on BOTH sides or edit-vs-delete conflicts are NEVER silently
//!   overwritten; under `ConflictStrategy::KeepBoth` (default), both versions are
//!   preserved via an explicit `<stem>.conflict-<ts>.<ext>` sibling copy!
//! - File↔Directory type flips are ALWAYS surfaced as conflicts without destroying trees.
//! - **Observation Completeness Gate**: any scan error on EITHER side disables ALL
//!   deletions on BOTH sides.

mod engine;
mod ops;
#[cfg(test)]
mod tests;

pub use engine::BisyncEngine;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::bandwidth::BandwidthSchedule;
use crate::clock::Clock;
use crate::engine::{MAX_REPORT_CONFLICTS, MAX_REPORT_ERRORS, RetryQuota, TransferErrorInfo};
use crate::error::{Error, ErrorCategory, Result};
use crate::filter::FilterSet;
use crate::path::RelPath;
use crate::state::{BaselineRecord, ConflictKind, RunScratchDir, SyncConflict};
use crate::types::{Capabilities, Entry, EntryKind};

/// Policy applied when BOTH sides diverged since the last synchronized baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConflictStrategy {
    /// Preserve both versions: keep Side A at canonical path and write Side B's
    /// conflicting version to `<stem>.conflict-<ts>.<ext>` on both sides (zero data loss!).
    #[default]
    KeepBoth,
    /// Leave both sides untouched and report an explicit `SyncConflict` (Unison strict mode).
    Abort,
    /// Side A explicitly wins conflicts.
    PreferA,
    /// Side B explicitly wins conflicts.
    PreferB,
}

impl ConflictStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepBoth => "keep_both",
            Self::Abort => "abort",
            Self::PreferA => "prefer_a",
            Self::PreferB => "prefer_b",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "keep-both" | "keep_both" | "both" => Some(Self::KeepBoth),
            "abort" | "none" | "skip" => Some(Self::Abort),
            "prefer-a" | "prefer_a" | "a" => Some(Self::PreferA),
            "prefer-b" | "prefer_b" | "b" => Some(Self::PreferB),
            _ => None,
        }
    }
}

impl fmt::Display for ConflictStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ConflictStrategy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
            .ok_or_else(|| Error::invalid_path(format!("unknown conflict strategy `{s}`")))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BisyncConfig {
    pub job_id: String,
    pub a_spec: String,
    pub b_spec: String,
    pub a_prefix: RelPath,
    pub b_prefix: RelPath,
    pub transfers: usize,
    pub conflict_strategy: ConflictStrategy,
    /// Allow merging two non-empty trees that have no prior baseline.
    pub resync: bool,
    /// Allow proceeding when one previously non-empty side suddenly observes 0 files
    /// (bypassing the unmounted-drive / empty-side disaster guard).
    pub force_empty_side: bool,
    pub max_delete: Option<u64>,
    /// Maximum percentage (`0.0..=100.0`) of observed files allowed to be deleted in a single
    /// bisync run when `max_delete` is `None` (default: `Some(50.0)`). Explicit `max_delete`
    /// takes precedence when set; set to `None` to disable percentage gating.
    pub max_delete_percent: Option<f64>,
    pub dry_run: bool,
    pub filter: FilterSet,
    pub bwlimit_bytes_per_sec: Option<u64>,
    /// Optional time-of-day bandwidth schedule (`--bwlimit "08:00,10M 23:00,off"`).
    pub bwlimit_schedule: Option<BandwidthSchedule>,
    /// Optional lazily-materialized scratch directory for `DeleteSpillLog`.
    pub scratch_dir: Option<Arc<dyn RunScratchDir>>,
    /// Optional retry budget shared by every transfer of the run (both directions). When
    /// `None`, transfers into a side use that backend's
    /// [`crate::backend::StorageBackend::retry_quota`], else one token bucket per run.
    pub retry_quota: Option<Arc<dyn RetryQuota>>,
    /// Optional backoff jitter source shared by every transfer of the run (see
    /// [`crate::engine::EngineConfig::retry_jitter`]).
    pub retry_jitter: Option<Arc<crate::engine::BackoffJitter>>,
    /// Per-run fallback quota pinned by `BisyncEngine::run`.
    pub(crate) run_retry_quota: Option<Arc<dyn RetryQuota>>,
}

impl BisyncConfig {
    pub fn new(
        job_id: impl Into<String>,
        a_spec: impl Into<String>,
        b_spec: impl Into<String>,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            a_spec: a_spec.into(),
            b_spec: b_spec.into(),
            a_prefix: RelPath::root(),
            b_prefix: RelPath::root(),
            transfers: 4,
            conflict_strategy: ConflictStrategy::KeepBoth,
            resync: false,
            force_empty_side: false,
            max_delete: None,
            max_delete_percent: Some(50.0),
            dry_run: false,
            filter: FilterSet::default(),
            bwlimit_bytes_per_sec: None,
            bwlimit_schedule: None,
            scratch_dir: None,
            retry_quota: None,
            retry_jitter: None,
            run_retry_quota: None,
        }
    }

    /// Share `quota` across every transfer of the run (see [`Self::retry_quota`]).
    pub fn with_retry_quota(mut self, quota: Option<Arc<dyn RetryQuota>>) -> Self {
        self.retry_quota = quota;
        self
    }

    /// Seed the retry backoff jitter so the run's backoff durations are reproducible.
    pub fn with_retry_jitter_seed(mut self, seed: u64) -> Self {
        self.retry_jitter = Some(Arc::new(crate::engine::BackoffJitter::seeded(seed)));
        self
    }

    /// Retry quota for a transfer into `dst`: explicit, else the backend's shared quota,
    /// else the per-run fallback.
    pub(crate) fn transfer_retry_quota(
        &self,
        dst: &dyn crate::backend::StorageBackend,
    ) -> Option<Arc<dyn RetryQuota>> {
        self.retry_quota
            .clone()
            .or_else(|| dst.retry_quota())
            .or_else(|| self.run_retry_quota.clone())
    }

    pub fn with_prefixes(mut self, a_prefix: RelPath, b_prefix: RelPath) -> Self {
        self.a_prefix = a_prefix;
        self.b_prefix = b_prefix;
        self
    }

    pub fn with_transfers(mut self, transfers: usize) -> Self {
        self.transfers = transfers.max(1);
        self
    }

    pub fn with_conflict_strategy(mut self, strategy: ConflictStrategy) -> Self {
        self.conflict_strategy = strategy;
        self
    }

    pub fn with_resync(mut self, resync: bool) -> Self {
        self.resync = resync;
        self
    }

    pub fn with_force_empty_side(mut self, force: bool) -> Self {
        self.force_empty_side = force;
        self
    }

    pub fn with_max_delete(mut self, max_delete: Option<u64>) -> Self {
        self.max_delete = max_delete;
        self
    }

    pub fn with_max_delete_percent(mut self, max_delete_percent: Option<f64>) -> Self {
        self.max_delete_percent = max_delete_percent;
        self
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_filter(mut self, filter: FilterSet) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_bwlimit(mut self, bytes_per_sec: Option<u64>) -> Self {
        self.bwlimit_bytes_per_sec = bytes_per_sec;
        self
    }

    pub fn with_bwlimit_schedule(mut self, schedule: Option<BandwidthSchedule>) -> Self {
        self.bwlimit_schedule = schedule;
        self
    }

    pub fn with_scratch_dir(mut self, scratch_dir: Option<Arc<dyn RunScratchDir>>) -> Self {
        self.scratch_dir = scratch_dir;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BisyncAction {
    Noop,
    ConvergedUpdateBaseline {
        a: Entry,
        b: Entry,
    },
    CopyAToB {
        a: Entry,
        b_existing: Option<Entry>,
    },
    CopyBToA {
        b: Entry,
        a_existing: Option<Entry>,
    },
    MkdirOnA(RelPath),
    MkdirOnB(RelPath),
    DeleteOnA(Entry),
    DeleteOnB(Entry),
    RetireStaleBaseline(RelPath),
    Conflict {
        nfc_path: RelPath,
        kind: ConflictKind,
        a: Option<Entry>,
        b: Option<Entry>,
        detail: String,
    },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BisyncReport {
    pub job_id: String,
    pub copied_a_to_b: u64,
    pub copied_b_to_a: u64,
    pub deleted_on_a: u64,
    pub deleted_on_b: u64,
    pub dirs_created: u64,
    pub converged_skipped: u64,
    pub conflicts_resolved: u64,
    pub bytes_transferred: u64,
    pub conflicts: Vec<SyncConflict>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub conflicts_truncated: u64,
    pub errors: Vec<String>,
    /// Typed per-error diagnostics preserving [`crate::error::ErrorKind`], [`ErrorCategory`], and [`crate::error::RetryClass`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_details: Vec<TransferErrorInfo>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub errors_truncated: u64,
    pub a_observation_complete: bool,
    pub b_observation_complete: bool,
    pub cancelled: bool,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl BisyncReport {
    pub fn push_error(&mut self, info: TransferErrorInfo) {
        if self.errors.len() < MAX_REPORT_ERRORS {
            self.errors.push(info.message.clone());
            self.error_details.push(info);
        } else {
            self.errors_truncated = self.errors_truncated.saturating_add(1);
        }
    }

    pub fn push_conflict(&mut self, conflict: SyncConflict) {
        if self.conflicts.len() < MAX_REPORT_CONFLICTS {
            self.conflicts.push(conflict);
        } else {
            self.conflicts_truncated = self.conflicts_truncated.saturating_add(1);
        }
    }

    pub fn is_success(&self) -> bool {
        !self.cancelled && !self.has_errors() && !self.has_conflicts()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty() || self.errors_truncated > 0
    }

    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty() || self.conflicts_truncated > 0
    }

    /// Return the highest-priority machine-readable [`ErrorCategory`] for this run,
    /// or `None` when the run succeeded without cancellation, errors, or conflicts.
    pub fn primary_error_category(&self) -> Option<ErrorCategory> {
        if self.cancelled {
            return Some(ErrorCategory::Cancelled);
        }
        if !self.errors.is_empty() {
            return ErrorCategory::primary(self.error_details.iter().map(|e| e.category))
                .or(Some(ErrorCategory::Other));
        }
        if !self.conflicts.is_empty() {
            return Some(ErrorCategory::Conflict);
        }
        None
    }
}

/// Pure deterministic Three-Tree Planner over `(A, B, Baseline O)`.
pub fn plan_three_tree(
    a: Option<&Entry>,
    b: Option<&Entry>,
    baseline: Option<&BaselineRecord>,
    a_caps: &Capabilities,
    b_caps: &Capabilities,
    allow_deletes: bool,
) -> BisyncAction {
    let tol_ns = a_caps
        .effective_mtime_tolerance(b_caps)
        .as_nanos()
        .min(i64::MAX as u128) as i64;

    match (a, b, baseline) {
        (None, None, Some(o)) => BisyncAction::RetireStaleBaseline(o.nfc_path.clone()),
        (None, None, None) => BisyncAction::Noop,

        // Directory handling
        (Some(ae), Some(be), _)
            if ae.kind == EntryKind::Directory && be.kind == EntryKind::Directory =>
        {
            BisyncAction::Noop
        }
        (Some(ae), Some(be), _) if ae.kind != be.kind => {
            let kind = if ae.kind == EntryKind::File {
                ConflictKind::TypeFlipFileOverDir
            } else {
                ConflictKind::TypeFlipDirOverFile
            };
            BisyncAction::Conflict {
                nfc_path: ae.nfc_path.clone(),
                kind,
                a: Some(ae.clone()),
                b: Some(be.clone()),
                detail: format!(
                    "type flip on `{}`: side A is {:?}, side B is {:?}",
                    ae.nfc_path, ae.kind, be.kind
                ),
            }
        }
        (Some(ae), None, None) if ae.kind == EntryKind::Directory => {
            BisyncAction::MkdirOnB(ae.nfc_path.clone())
        }
        (None, Some(be), None) if be.kind == EntryKind::Directory => {
            BisyncAction::MkdirOnA(be.nfc_path.clone())
        }
        (Some(ae), None, Some(_)) if ae.kind == EntryKind::Directory => {
            if allow_deletes {
                BisyncAction::DeleteOnA(ae.clone())
            } else {
                BisyncAction::Noop
            }
        }
        (None, Some(be), Some(_)) if be.kind == EntryKind::Directory => {
            if allow_deletes {
                BisyncAction::DeleteOnB(be.clone())
            } else {
                BisyncAction::Noop
            }
        }

        // File created on A only (no prior baseline)
        (Some(ae), None, None) => BisyncAction::CopyAToB {
            a: ae.clone(),
            b_existing: None,
        },
        // File created on B only (no prior baseline)
        (None, Some(be), None) => BisyncAction::CopyBToA {
            b: be.clone(),
            a_existing: None,
        },

        // File deleted on A while present on B (prior baseline exists!)
        (None, Some(be), Some(o)) => {
            if b_matches_baseline(be, o, tol_ns) {
                if allow_deletes {
                    BisyncAction::DeleteOnB(be.clone())
                } else {
                    BisyncAction::Noop
                }
            } else {
                BisyncAction::Conflict {
                    nfc_path: be.nfc_path.clone(),
                    kind: ConflictKind::ModifyDeleteConflict,
                    a: None,
                    b: Some(be.clone()),
                    detail: format!(
                        "`{}` was deleted on side A but modified on side B since last sync",
                        be.nfc_path
                    ),
                }
            }
        }

        // File deleted on B while present on A (prior baseline exists!)
        (Some(ae), None, Some(o)) => {
            if a_matches_baseline(ae, o, tol_ns) {
                if allow_deletes {
                    BisyncAction::DeleteOnA(ae.clone())
                } else {
                    BisyncAction::Noop
                }
            } else {
                BisyncAction::Conflict {
                    nfc_path: ae.nfc_path.clone(),
                    kind: ConflictKind::ModifyDeleteConflict,
                    a: Some(ae.clone()),
                    b: None,
                    detail: format!(
                        "`{}` was deleted on side B but modified on side A since last sync",
                        ae.nfc_path
                    ),
                }
            }
        }

        // Both exist, NO prior baseline (initial sync / `--resync`)
        (Some(ae), Some(be), None) => {
            if entries_equivalent(ae, be, tol_ns) {
                BisyncAction::ConvergedUpdateBaseline {
                    a: ae.clone(),
                    b: be.clone(),
                }
            } else {
                BisyncAction::Conflict {
                    nfc_path: ae.nfc_path.clone(),
                    kind: ConflictKind::ConcurrentBisyncEdit,
                    a: Some(ae.clone()),
                    b: Some(be.clone()),
                    detail: format!(
                        "`{}` exists with different contents/metadata on both sides with no prior baseline",
                        ae.nfc_path
                    ),
                }
            }
        }

        // Both exist AND prior baseline exists -> classic Three-Tree reconciliation!
        (Some(ae), Some(be), Some(o)) => {
            let a_same = a_matches_baseline(ae, o, tol_ns);
            let b_same = b_matches_baseline(be, o, tol_ns);
            match (a_same, b_same) {
                (true, true) => BisyncAction::Noop,
                (false, true) => BisyncAction::CopyAToB {
                    a: ae.clone(),
                    b_existing: Some(be.clone()),
                },
                (true, false) => BisyncAction::CopyBToA {
                    b: be.clone(),
                    a_existing: Some(ae.clone()),
                },
                (false, false) => {
                    if entries_equivalent(ae, be, tol_ns) {
                        BisyncAction::ConvergedUpdateBaseline {
                            a: ae.clone(),
                            b: be.clone(),
                        }
                    } else {
                        BisyncAction::Conflict {
                            nfc_path: ae.nfc_path.clone(),
                            kind: ConflictKind::ConcurrentBisyncEdit,
                            a: Some(ae.clone()),
                            b: Some(be.clone()),
                            detail: format!(
                                "`{}` was modified independently on both side A and side B",
                                ae.nfc_path
                            ),
                        }
                    }
                }
            }
        }
    }
}

fn a_matches_baseline(a: &Entry, o: &BaselineRecord, tol_ns: i64) -> bool {
    if a.size != o.size {
        return false;
    }
    if let (Some(ac), Some(ohk), Some(ohex)) = (&a.checksum, o.hash_kind, o.hash_hex.as_deref())
        && ac.kind == ohk
        && !ac.hex.contains('-')
        && !ohex.contains('-')
    {
        return ac.hex.eq_ignore_ascii_case(ohex);
    }
    a.mtime_ns.abs_diff(o.src_mtime_ns) <= u64::try_from(tol_ns).unwrap_or(0)
}

fn b_matches_baseline(b: &Entry, o: &BaselineRecord, tol_ns: i64) -> bool {
    if b.size != o.size {
        return false;
    }
    if let (Some(be), Some(oe)) = (b.etag.as_deref(), o.dst_etag.as_deref()) {
        return be == oe;
    }
    if let (Some(bc), Some(ohk), Some(ohex)) = (&b.checksum, o.hash_kind, o.hash_hex.as_deref())
        && bc.kind == ohk
        && !bc.hex.contains('-')
        && !ohex.contains('-')
    {
        return bc.hex.eq_ignore_ascii_case(ohex);
    }
    b.mtime_ns.abs_diff(o.dst_mtime_ns) <= u64::try_from(tol_ns).unwrap_or(0)
}

fn entries_equivalent(a: &Entry, b: &Entry, tol_ns: i64) -> bool {
    if a.size != b.size {
        return false;
    }
    if let (Some(ac), Some(bc)) = (&a.checksum, &b.checksum)
        && ac.kind == bc.kind
        && !ac.hex.contains('-')
        && !bc.hex.contains('-')
    {
        return ac.hex.eq_ignore_ascii_case(&bc.hex);
    }
    a.mtime_ns.abs_diff(b.mtime_ns) <= u64::try_from(tol_ns).unwrap_or(0)
}

/// Construct a deterministic, collision-free conflict sibling path
/// (`dir/report.pdf` -> `dir/report.conflict-<ts>.pdf`).
pub fn make_conflict_path(orig: &RelPath, unix_secs: i64) -> Result<RelPath> {
    let name = orig
        .file_name()
        .ok_or_else(|| Error::invalid_path("cannot derive conflict name for root"))?;
    let conflict_name = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.conflict-{unix_secs}.{ext}"),
        _ => format!("{name}.conflict-{unix_secs}"),
    };
    match orig.parent() {
        Some(parent) => parent.join(&conflict_name),
        None => RelPath::parse(&conflict_name),
    }
}

#[derive(Default)]
pub(super) struct BisyncWorkOutcome {
    pub(super) copied_a_to_b: u64,
    pub(super) copied_b_to_a: u64,
    pub(super) created_on_a: u64,
    pub(super) created_on_b: u64,
    pub(super) files_done: u64,
    pub(super) bytes_transferred: u64,
    pub(super) conflicts_resolved: u64,
    pub(super) conflict: Option<SyncConflict>,
    pub(super) errors: Vec<TransferErrorInfo>,
    pub(super) extra_delete_a: Option<Entry>,
    pub(super) extra_delete_b: Option<Entry>,
    pub(super) cancelled: bool,
}

pub(super) fn make_bisync_baseline(
    pair_key: &str,
    a: &Entry,
    b: &Entry,
    clock: &Arc<dyn Clock>,
) -> BaselineRecord {
    let (hash_kind, hash_hex) = match (&a.checksum, &b.checksum) {
        (Some(c), _) | (None, Some(c)) => (Some(c.kind), Some(c.hex.clone())),
        (None, None) => (None, None),
    };
    BaselineRecord {
        pair_key: pair_key.to_string(),
        nfc_path: a.nfc_path.clone(),
        kind: EntryKind::File,
        src_node_id: a.node_id.clone(),
        dst_node_id: b.node_id.clone(),
        size: a.size,
        src_mtime_ns: a.mtime_ns,
        dst_mtime_ns: b.mtime_ns,
        dst_etag: b.etag.clone(),
        hash_kind,
        hash_hex,
        updated_at: clock.now_unix_secs(),
    }
}
