use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use super::check_overlapping_roots;
use crate::adaptive::FalconConfig;
use crate::backend::StorageBackend;
use crate::bandwidth::BandwidthSchedule;
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::filter::FilterSet;
use crate::path::RelPath;
use crate::state::{BaselineMode, JobMode, RunScratchDir};

/// Controls when extraneous destination items are deleted during `sync`
/// (Observation Completeness Gate and `--max-delete` are strictly enforced in all modes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeleteMode {
    /// Delete extraneous destination files ONLY after all source transfers succeed (safest default).
    #[default]
    After,
    /// Delete extraneous destination files BEFORE transferring new files (frees disk/quota first).
    Before,
    /// Delete extraneous destination files concurrently alongside transfers once observation completes.
    During,
}

impl DeleteMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::After => "after",
            Self::Before => "before",
            Self::During => "during",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "after" => Some(Self::After),
            "before" => Some(Self::Before),
            "during" => Some(Self::During),
            _ => None,
        }
    }
}

impl fmt::Display for DeleteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeleteMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::config(format!("unknown delete mode `{s}`")))
    }
}

const MAX_BACKUP_CACHED_DIRS: usize = 16_384;
const MAX_PROTECTED_DIRS: usize = 65_536;

/// Bounded ancestor tracker for directories that contain at least one filtered-out
/// (excluded) entry. Protected directories MUST NEVER be queued or deleted so file-level
/// filters (`--exclude "*.env"`, `--include`, `--min-size`, `--max-age`) cannot cause
/// recursive folder deletion on local or cloud backends.
#[derive(Debug, Default)]
pub(crate) struct ProtectedDirs {
    dirs: HashSet<RelPath>,
    suppress_all: bool,
}

impl ProtectedDirs {
    pub(crate) fn protect_ancestors(&mut self, path: &RelPath) {
        if self.suppress_all {
            return;
        }
        let mut cur = path.parent();
        while let Some(parent) = cur {
            if parent.is_root() {
                break;
            }
            if self.dirs.contains(&parent) {
                break;
            }
            if self.dirs.len() >= MAX_PROTECTED_DIRS {
                self.dirs.clear();
                self.suppress_all = true;
                return;
            }
            cur = parent.parent();
            self.dirs.insert(parent);
        }
    }

    pub(crate) fn is_protected(&self, dir: &RelPath) -> bool {
        self.suppress_all || self.dirs.contains(dir)
    }
}

/// Destination archive target for `--backup-dir`: overwritten or deleted destination
/// files are copied here before mutation/removal.
#[derive(Clone)]
pub struct BackupTarget {
    pub backend: Arc<dyn StorageBackend>,
    pub prefix: RelPath,
    created_dirs: Arc<std::sync::Mutex<HashSet<RelPath>>>,
}

impl BackupTarget {
    pub fn new(backend: Arc<dyn StorageBackend>, prefix: RelPath) -> Self {
        Self {
            backend,
            prefix,
            created_dirs: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Returns `true` if `dir` has not yet been created in this backup target, recording it
    /// in a bounded cache so repeated archival into the same prefix avoids redundant `mkdir`
    /// RPCs (e.g. `PutObject("<parent>/")` on S3).
    pub(crate) fn mark_dir_if_new(&self, dir: &RelPath) -> bool {
        let Ok(mut guard) = self.created_dirs.lock() else {
            return true;
        };
        if guard.contains(dir) {
            return false;
        }
        if guard.len() >= MAX_BACKUP_CACHED_DIRS {
            guard.clear();
        }
        guard.insert(dir.clone());
        true
    }
}

pub(crate) fn validate_backup_dir_overlap(
    src_endpoint: &str,
    src_prefix: &RelPath,
    dst_endpoint: &str,
    dst_prefix: &RelPath,
    backup: &BackupTarget,
) -> Result<()> {
    let empty_filter = FilterSet::default();
    check_overlapping_roots(
        src_endpoint,
        src_prefix,
        &backup.backend.endpoint_identity(),
        &backup.prefix,
        &empty_filter,
    )
    .map_err(|e| Error::invalid_path(format!("--backup-dir overlaps source: {e}")))?;
    check_overlapping_roots(
        dst_endpoint,
        dst_prefix,
        &backup.backend.endpoint_identity(),
        &backup.prefix,
        &empty_filter,
    )
    .map_err(|e| Error::invalid_path(format!("--backup-dir overlaps destination: {e}")))?;
    Ok(())
}

impl fmt::Debug for BackupTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupTarget")
            .field("endpoint", &self.backend.endpoint_identity())
            .field("prefix", &self.prefix)
            .finish()
    }
}

/// Single ceiling for retry backoff and server `Retry-After` hints (30 s).
///
/// [`EngineConfig::max_retry_delay`] defaults to this value, and it matches the default
/// `max_delay` of the backends' HTTP retry policy so a `Retry-After` hint is capped the
/// same way at both layers.
pub const DEFAULT_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Source of full-jitter samples for engine retry backoff.
///
/// A seeded jitter makes backoff durations reproducible: under an instant-sleep virtual
/// clock every backoff advances virtual time (which Falcon reads), so deterministic
/// simulation tests must seed it to replay a run exactly. Samples are a SplitMix64
/// sequence over `seed`, drawn in call order.
#[derive(Debug)]
pub struct BackoffJitter {
    seed: u64,
    counter: AtomicU64,
}

impl BackoffJitter {
    /// Reproducible jitter: the same seed yields the same sample sequence.
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
        }
    }

    /// Jitter seeded from process entropy (the default when no seed is configured).
    pub fn from_entropy() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x243f_6a88_85a3_08d3);
        Self::seeded(h.finish())
    }

    /// Process-wide entropy-seeded jitter shared by runs without a configured seed.
    pub(crate) fn process_default() -> Arc<Self> {
        static DEFAULT: OnceLock<Arc<BackoffJitter>> = OnceLock::new();
        DEFAULT
            .get_or_init(|| Arc::new(Self::from_entropy()))
            .clone()
    }

    /// Next 64-bit sample.
    pub fn next_u64(&self) -> u64 {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut z = self
            .seed
            .wrapping_add(seq.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Shared retry budget preventing retry storms during sustained backend outages
/// (AWS SDK standard retry-quota semantics).
pub trait RetryQuota: Send + Sync + fmt::Debug {
    /// Attempt to consume retry budget before issuing a retry.
    /// Returns `false` when the budget is exhausted (caller must fail fast).
    fn try_acquire(&self, is_timeout: bool) -> bool;

    /// Refund retry budget on a successful operation.
    fn record_success(&self, was_retry: bool, was_timeout_retry: bool);
}

/// Lock-free token-bucket [`RetryQuota`] implementation (AWS SDK defaults:
/// `max_tokens = 500`, `retry_cost = 5`, `timeout_retry_cost = 10`, `no_retry_increment = 1`).
#[derive(Debug)]
pub struct TokenBucketRetryQuota {
    max_tokens: u32,
    retry_cost: u32,
    timeout_retry_cost: u32,
    no_retry_increment: u32,
    available: AtomicU32,
}

impl Default for TokenBucketRetryQuota {
    fn default() -> Self {
        Self::new(500, 5, 10, 1)
    }
}

impl TokenBucketRetryQuota {
    pub fn new(
        max_tokens: u32,
        retry_cost: u32,
        timeout_retry_cost: u32,
        no_retry_increment: u32,
    ) -> Self {
        Self {
            max_tokens,
            retry_cost,
            timeout_retry_cost,
            no_retry_increment,
            available: AtomicU32::new(max_tokens),
        }
    }

    pub fn available(&self) -> u32 {
        self.available.load(Ordering::Acquire)
    }

    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    pub fn retry_cost(&self) -> u32 {
        self.retry_cost
    }

    pub fn timeout_retry_cost(&self) -> u32 {
        self.timeout_retry_cost
    }

    pub fn no_retry_increment(&self) -> u32 {
        self.no_retry_increment
    }
}

impl RetryQuota for TokenBucketRetryQuota {
    fn try_acquire(&self, is_timeout: bool) -> bool {
        let cost = if is_timeout {
            self.timeout_retry_cost
        } else {
            self.retry_cost
        };
        self.available
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                cur.checked_sub(cost)
            })
            .is_ok()
    }

    fn record_success(&self, was_retry: bool, was_timeout_retry: bool) {
        if !was_retry && self.available.load(Ordering::Relaxed) >= self.max_tokens {
            return;
        }
        let refund = if was_retry {
            if was_timeout_retry {
                self.timeout_retry_cost
            } else {
                self.retry_cost
            }
        } else {
            self.no_retry_increment
        };
        let _ = self
            .available
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_add(refund).min(self.max_tokens))
            });
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EngineConfig {
    pub job_id: String,
    pub mode: JobMode,
    pub src_spec: String,
    pub dst_spec: String,
    pub src_prefix: RelPath,
    pub dst_prefix: RelPath,
    pub transfers: usize,
    pub part_concurrency: usize,
    pub chunk_size_override: Option<u64>,
    pub delete: bool,
    /// When `delete = true`, controls whether deletions run `after` (default), `before`, or `during` transfers.
    pub delete_mode: DeleteMode,
    pub max_delete: Option<u64>,
    /// Optional percentage ceiling (`0.0..=100.0`) on destination file deletions when
    /// `max_delete` is `None` (default: `None`). Explicit `max_delete` takes precedence.
    pub max_delete_percent: Option<f64>,
    /// Optional `--backup-dir` archive target receiving overwritten or deleted destination files.
    pub backup_dir: Option<BackupTarget>,
    pub checksum: bool,
    pub dry_run: bool,
    pub force_type_replace: bool,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    /// Maximum ceiling applied to both exponential backoff and server `Retry-After` hints
    /// (default: [`DEFAULT_MAX_RETRY_DELAY`], 30 s).
    pub max_retry_delay: Duration,
    /// Optional shared retry budget across engine retries. When `None`, a run uses the
    /// destination backend's [`StorageBackend::retry_quota`] (one budget per remote
    /// account), or else one [`TokenBucketRetryQuota::default`] shared by every file of the
    /// run.
    pub retry_quota: Option<Arc<dyn RetryQuota>>,
    /// Optional backoff jitter source. `None` uses a process-wide entropy-seeded source;
    /// set [`Self::with_retry_jitter_seed`] for reproducible backoff (DST).
    pub retry_jitter: Option<Arc<BackoffJitter>>,
    pub filter: FilterSet,
    /// Optional sustained transfer bandwidth ceiling in bytes/sec (`--bwlimit`).
    pub bwlimit_bytes_per_sec: Option<u64>,
    /// Optional time-of-day bandwidth schedule (`--bwlimit "08:00,10M 23:00,off"`).
    /// Takes precedence over `bwlimit_bytes_per_sec` when set.
    pub bwlimit_schedule: Option<BandwidthSchedule>,
    /// Enable Falcon dual-lane (`SmallPipelined` <= 1 MiB vs `LargeStreaming` > 1 MiB)
    /// online adaptive concurrency control (`--adaptive`).
    pub adaptive_concurrency: bool,
    /// Optional explicit Falcon controller configuration (defaults to scaling from `transfers`).
    pub falcon_config: Option<FalconConfig>,
    /// Delete each source file ONLY AFTER destination write is verified & committed (`rship move`).
    pub delete_source_after_transfer: bool,
    /// When moving, also prune empty source directories after all file moves succeed.
    pub delete_empty_src_dirs: bool,
    /// Freeze each source file into a quota-bounded local snapshot before uploading so actively
    /// written files don't fail mid-upload with `SourceMutated` (`--strict-source`).
    pub strict_source: bool,
    /// Directory for `--strict-source` private snapshots (defaults to OS temp dir).
    pub strict_source_dir: Option<PathBuf>,
    /// Maximum per-file snapshot size allowed under `--strict-source` (default: 256 MiB).
    pub strict_source_max_bytes: u64,
    /// Allow zero-bandwidth cloud server-side copy when source and destination share a backend.
    pub allow_server_side_copy: bool,
    /// Skip full directory tree traversal when `--files-from` is supplied (stat only listed paths).
    pub no_traverse: bool,
    /// Policy controlling when verified transfers write `sync_baseline` rows (`auto` by default).
    pub baseline_mode: BaselineMode,
    /// Optional serialized JSON of CLI options persisted into `jobs.options_json` for `rship resume`.
    pub options_json: Option<String>,
    /// Optional lexicographic `StartAfter` resume cursor (populated by `rship resume` on
    /// ordered object-store `copy`/`move` jobs to skip already-completed key ranges in `O(1)`).
    pub resume_cursor: Option<String>,
    /// Optional lazily-materialized per-job scratch directory (`LazyRunDir`) shared by
    /// `DeleteSpillLog` and `--strict-source` (zero disk I/O unless actually needed).
    pub scratch_dir: Option<Arc<dyn RunScratchDir>>,
}

impl EngineConfig {
    pub fn new(
        job_id: impl Into<String>,
        mode: JobMode,
        src_spec: impl Into<String>,
        dst_spec: impl Into<String>,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            mode,
            src_spec: src_spec.into(),
            dst_spec: dst_spec.into(),
            src_prefix: RelPath::root(),
            dst_prefix: RelPath::root(),
            transfers: 4,
            part_concurrency: 4,
            chunk_size_override: None,
            delete: matches!(mode, JobMode::Sync),
            delete_mode: DeleteMode::After,
            max_delete: None,
            max_delete_percent: None,
            backup_dir: None,
            checksum: false,
            dry_run: false,
            force_type_replace: false,
            max_retries: 5,
            base_retry_delay: Duration::from_millis(50),
            max_retry_delay: DEFAULT_MAX_RETRY_DELAY,
            retry_quota: None,
            retry_jitter: None,
            filter: FilterSet::default(),
            bwlimit_bytes_per_sec: None,
            bwlimit_schedule: None,
            adaptive_concurrency: false,
            falcon_config: None,
            delete_source_after_transfer: matches!(mode, JobMode::Move),
            delete_empty_src_dirs: false,
            strict_source: false,
            strict_source_dir: None,
            strict_source_max_bytes: 256 * 1024 * 1024,
            allow_server_side_copy: true,
            no_traverse: false,
            baseline_mode: BaselineMode::Auto,
            options_json: None,
            resume_cursor: None,
            scratch_dir: None,
        }
    }

    pub fn with_prefixes(mut self, src_prefix: RelPath, dst_prefix: RelPath) -> Self {
        self.src_prefix = src_prefix;
        self.dst_prefix = dst_prefix;
        self
    }

    pub fn with_transfers(mut self, transfers: usize) -> Self {
        self.transfers = transfers.max(1);
        self
    }

    pub fn with_part_concurrency(mut self, part_concurrency: usize) -> Self {
        self.part_concurrency = part_concurrency.max(1);
        self
    }

    pub fn with_chunk_size(mut self, bytes: Option<u64>) -> Self {
        self.chunk_size_override = bytes;
        self
    }

    pub fn with_delete(mut self, delete: bool) -> Self {
        self.delete = delete;
        self
    }

    pub fn with_delete_mode(mut self, mode: DeleteMode) -> Self {
        self.delete_mode = mode;
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

    pub fn with_backup_dir(mut self, backend: Arc<dyn StorageBackend>, prefix: RelPath) -> Self {
        self.backup_dir = Some(BackupTarget::new(backend, prefix));
        self
    }

    pub fn with_checksum(mut self, checksum: bool) -> Self {
        self.checksum = checksum;
        self
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_force_type_replace(mut self, force: bool) -> Self {
        self.force_type_replace = force;
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_base_retry_delay(mut self, delay: Duration) -> Self {
        self.base_retry_delay = delay;
        self
    }

    pub fn with_max_retry_delay(mut self, delay: Duration) -> Self {
        self.max_retry_delay = delay;
        self
    }

    pub fn with_retry_quota(mut self, quota: Option<Arc<dyn RetryQuota>>) -> Self {
        self.retry_quota = quota;
        self
    }

    /// Seed the retry backoff jitter so a run's backoff durations are reproducible.
    pub fn with_retry_jitter_seed(mut self, seed: u64) -> Self {
        self.retry_jitter = Some(Arc::new(BackoffJitter::seeded(seed)));
        self
    }

    pub(crate) fn jitter(&self) -> Arc<BackoffJitter> {
        self.retry_jitter
            .clone()
            .unwrap_or_else(BackoffJitter::process_default)
    }

    pub(crate) fn resolve_retry_quota(&self) -> Arc<dyn RetryQuota> {
        self.retry_quota
            .clone()
            .unwrap_or_else(|| Arc::new(TokenBucketRetryQuota::default()))
    }

    /// Pin one retry quota for a whole run: the explicit [`Self::retry_quota`], else the
    /// destination backend's shared quota, else a fresh per-run token bucket.
    pub(crate) fn pin_run_retry_quota(&mut self, dst: &dyn StorageBackend) {
        if self.retry_quota.is_none() {
            self.retry_quota = Some(
                dst.retry_quota()
                    .unwrap_or_else(|| Arc::new(TokenBucketRetryQuota::default())),
            );
        }
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

    pub(crate) fn build_bwlimit(
        &self,
        clock: &Arc<dyn Clock>,
    ) -> Result<Option<Arc<crate::bandwidth::BandwidthLimiter>>> {
        if let Some(ref sched) = self.bwlimit_schedule {
            Ok(Some(
                crate::bandwidth::BandwidthLimiter::from_schedule_with_clock(
                    sched.clone(),
                    clock.clone(),
                )?,
            ))
        } else if let Some(rate) = self.bwlimit_bytes_per_sec {
            Ok(Some(crate::bandwidth::BandwidthLimiter::new_with_clock(
                rate,
                clock.clone(),
            )?))
        } else {
            Ok(None)
        }
    }

    pub fn with_adaptive_concurrency(mut self, enabled: bool) -> Self {
        self.adaptive_concurrency = enabled;
        self
    }

    pub fn with_falcon_config(mut self, cfg: Option<FalconConfig>) -> Self {
        self.falcon_config = cfg;
        self
    }

    pub fn with_delete_source_after_transfer(mut self, delete: bool) -> Self {
        self.delete_source_after_transfer = delete;
        self
    }

    pub fn with_delete_empty_src_dirs(mut self, delete: bool) -> Self {
        self.delete_empty_src_dirs = delete;
        self
    }

    pub fn with_strict_source(mut self, enabled: bool) -> Self {
        self.strict_source = enabled;
        self
    }

    pub fn with_strict_source_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.strict_source_dir = dir;
        self
    }

    pub fn with_strict_source_max_bytes(mut self, max_bytes: u64) -> Self {
        self.strict_source_max_bytes = max_bytes;
        self
    }

    pub fn with_allow_server_side_copy(mut self, allow: bool) -> Self {
        self.allow_server_side_copy = allow;
        self
    }

    pub fn with_no_traverse(mut self, no_traverse: bool) -> Self {
        self.no_traverse = no_traverse;
        self
    }

    pub fn with_baseline_mode(mut self, mode: BaselineMode) -> Self {
        self.baseline_mode = mode;
        self
    }

    pub fn with_options_json(mut self, options_json: Option<String>) -> Self {
        self.options_json = options_json;
        self
    }

    pub fn with_resume_cursor(mut self, resume_cursor: Option<String>) -> Self {
        self.resume_cursor = resume_cursor;
        self
    }

    pub fn with_scratch_dir(mut self, scratch_dir: Option<Arc<dyn RunScratchDir>>) -> Self {
        self.scratch_dir = scratch_dir;
        self
    }
}
