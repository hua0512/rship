use std::time::Duration;

#[cfg(doc)]
use super::ChaosBackend;
use crate::error::Error;

/// Deterministic SplitMix64 PRNG (zero external dependencies) backing seeded DST fault schedules.
#[derive(Debug, Clone)]
pub(in crate::chaos) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(in crate::chaos) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(in crate::chaos) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(in crate::chaos) fn chance_pct(&mut self, pct: u8) -> bool {
        if pct == 0 {
            return false;
        }
        if pct >= 100 {
            return true;
        }
        (self.next_u64() % 100) < u64::from(pct)
    }

    pub(in crate::chaos) fn range_u64(&mut self, min_inclusive: u64, max_inclusive: u64) -> u64 {
        if max_inclusive <= min_inclusive {
            return min_inclusive;
        }
        let span = max_inclusive - min_inclusive + 1;
        min_inclusive + (self.next_u64() % span)
    }
}

/// Operation category queried by [`ChaosBackend`] against a seeded [`FaultSchedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChaosOp {
    List,
    Stat,
    BeginUpload,
    UploadChunk,
    QueryUpload,
    FinishUpload,
    PutSingleShot,
    ReconcileOperation,
    Delete,
}

/// Concrete deterministic fault produced by [`FaultSchedule::next_fault`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectedFault {
    RateLimited { retry_after: Duration },
    Network503(&'static str),
    SessionExpired,
    PartialChunkDrop,
    LostCommitResponse,
}

impl InjectedFault {
    pub(super) fn into_error(self) -> Error {
        match self {
            Self::RateLimited { retry_after } => {
                Error::rate_limited("429 injected seeded rate limit", Some(retry_after))
            }
            Self::Network503(msg) => Error::network(msg),
            Self::SessionExpired => Error::session_expired("injected seeded session expiry"),
            Self::PartialChunkDrop => {
                Error::network("503 injected seeded mid-chunk socket disconnect")
            }
            Self::LostCommitResponse => Error::network("503 injected seeded lost commit response"),
        }
    }
}

/// Per-operation fault injection probabilities (0..=100%) for [`FaultSchedule::random`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomFaultProfile {
    /// Percentage chance of injecting a transient error during `list_stream` / `list_ordered_page`.
    pub list_error_pct: u8,
    /// Percentage chance of injecting a transient error during `stat`.
    pub stat_error_pct: u8,
    /// Percentage chance of injecting a transient error during `begin_upload`.
    pub begin_upload_error_pct: u8,
    /// Percentage chance of injecting `429 RateLimited` (with `Retry-After`) during upload RPCs.
    pub rate_limit_pct: u8,
    /// Percentage chance of injecting `503 Network` during upload/query RPCs.
    pub network_error_pct: u8,
    /// Percentage chance of injecting `SessionExpired` during `upload_chunk` / `query_upload`.
    pub session_expired_pct: u8,
    /// Percentage chance of persisting partial bytes then dropping connection in sequential `upload_chunk`.
    pub partial_chunk_drop_pct: u8,
    /// Percentage chance of committing then dropping the response (`finish_upload` / final chunk / `put_single_shot`).
    pub lost_commit_response_pct: u8,
    /// Percentage chance of injecting a transient error during `reconcile_operation`.
    pub reconcile_error_pct: u8,
    /// Percentage chance of injecting a transient error during `delete`.
    pub delete_error_pct: u8,
    /// Hard cap on total randomized faults injected by one schedule so every seeded run converges.
    pub max_total_faults: u32,
    /// Upper bound (milliseconds) for synthesized `Retry-After` headers on `429` faults.
    pub max_retry_after_ms: u64,
}

impl Default for RandomFaultProfile {
    fn default() -> Self {
        Self::moderate()
    }
}

impl RandomFaultProfile {
    /// Realistic mixed fault profile exercising every retry, session-expiry, partial-chunk,
    /// ambiguous-commit, list, stat, reconcile, and delete path.
    pub fn moderate() -> Self {
        Self {
            list_error_pct: 12,
            stat_error_pct: 8,
            begin_upload_error_pct: 12,
            rate_limit_pct: 15,
            network_error_pct: 12,
            session_expired_pct: 10,
            partial_chunk_drop_pct: 15,
            lost_commit_response_pct: 20,
            reconcile_error_pct: 12,
            delete_error_pct: 15,
            max_total_faults: 32,
            max_retry_after_ms: 5_000,
        }
    }

    /// Aggressive stress profile with higher per-RPC fault rates and larger fault budget.
    pub fn heavy() -> Self {
        Self {
            list_error_pct: 18,
            stat_error_pct: 12,
            begin_upload_error_pct: 18,
            rate_limit_pct: 22,
            network_error_pct: 18,
            session_expired_pct: 15,
            partial_chunk_drop_pct: 20,
            lost_commit_response_pct: 28,
            reconcile_error_pct: 18,
            delete_error_pct: 20,
            max_total_faults: 48,
            max_retry_after_ms: 10_000,
        }
    }
}

/// Internal deterministic PRNG state embedded inside [`FaultSchedule::random`].
#[derive(Debug, Clone)]
pub struct RandomFaultState {
    rng: SplitMix64,
    profile: RandomFaultProfile,
    injected: u32,
}

impl RandomFaultState {
    fn new(seed: u64, profile: RandomFaultProfile) -> Self {
        Self {
            rng: SplitMix64::new(seed),
            profile,
            injected: 0,
        }
    }

    fn retry_after(&mut self) -> Duration {
        let cap = self.profile.max_retry_after_ms.max(1);
        Duration::from_millis(self.rng.range_u64(1, cap))
    }

    fn transient_error(&mut self, msg: &'static str) -> InjectedFault {
        if self.rng.next_u64() & 1 == 0 {
            InjectedFault::RateLimited {
                retry_after: self.retry_after(),
            }
        } else {
            InjectedFault::Network503(msg)
        }
    }

    fn next_fault(&mut self, op: ChaosOp) -> Option<InjectedFault> {
        if self.injected >= self.profile.max_total_faults {
            return None;
        }
        let fault = match op {
            ChaosOp::List => self
                .rng
                .chance_pct(self.profile.list_error_pct)
                .then(|| self.transient_error("503 injected seeded list error")),
            ChaosOp::Stat => self
                .rng
                .chance_pct(self.profile.stat_error_pct)
                .then(|| self.transient_error("503 injected seeded stat error")),
            ChaosOp::BeginUpload => self
                .rng
                .chance_pct(self.profile.begin_upload_error_pct)
                .then(|| self.transient_error("503 injected seeded begin_upload error")),
            ChaosOp::UploadChunk => {
                if self.rng.chance_pct(self.profile.rate_limit_pct) {
                    Some(InjectedFault::RateLimited {
                        retry_after: self.retry_after(),
                    })
                } else if self.rng.chance_pct(self.profile.network_error_pct) {
                    Some(InjectedFault::Network503(
                        "503 injected seeded upload_chunk error",
                    ))
                } else if self.rng.chance_pct(self.profile.session_expired_pct) {
                    Some(InjectedFault::SessionExpired)
                } else if self.rng.chance_pct(self.profile.partial_chunk_drop_pct) {
                    Some(InjectedFault::PartialChunkDrop)
                } else {
                    None
                }
            }
            ChaosOp::QueryUpload => {
                if self.rng.chance_pct(self.profile.session_expired_pct) {
                    Some(InjectedFault::SessionExpired)
                } else if self.rng.chance_pct(self.profile.rate_limit_pct) {
                    Some(InjectedFault::RateLimited {
                        retry_after: self.retry_after(),
                    })
                } else if self.rng.chance_pct(self.profile.network_error_pct) {
                    Some(InjectedFault::Network503(
                        "503 injected seeded query_upload error",
                    ))
                } else {
                    None
                }
            }
            ChaosOp::FinishUpload => {
                if self.rng.chance_pct(self.profile.lost_commit_response_pct) {
                    Some(InjectedFault::LostCommitResponse)
                } else if self.rng.chance_pct(self.profile.rate_limit_pct) {
                    Some(InjectedFault::RateLimited {
                        retry_after: self.retry_after(),
                    })
                } else if self.rng.chance_pct(self.profile.network_error_pct) {
                    Some(InjectedFault::Network503(
                        "503 injected seeded finish_upload error",
                    ))
                } else {
                    None
                }
            }
            ChaosOp::PutSingleShot => {
                if self.rng.chance_pct(self.profile.lost_commit_response_pct) {
                    Some(InjectedFault::LostCommitResponse)
                } else if self.rng.chance_pct(self.profile.rate_limit_pct) {
                    Some(InjectedFault::RateLimited {
                        retry_after: self.retry_after(),
                    })
                } else if self.rng.chance_pct(self.profile.network_error_pct) {
                    Some(InjectedFault::Network503(
                        "503 injected seeded put_single_shot error",
                    ))
                } else {
                    None
                }
            }
            ChaosOp::ReconcileOperation => self
                .rng
                .chance_pct(self.profile.reconcile_error_pct)
                .then(|| self.transient_error("503 injected seeded reconcile error")),
            ChaosOp::Delete => self
                .rng
                .chance_pct(self.profile.delete_error_pct)
                .then(|| self.transient_error("503 injected seeded delete error")),
        };
        if fault.is_some() {
            self.injected += 1;
        }
        fault
    }
}

#[derive(Debug, Clone, Default)]
pub struct FaultSchedule {
    /// Fail first N `upload_chunk` calls with `429 RateLimited`.
    pub fail_chunk_rate_limit_remaining: u32,
    /// Drop connection (network error) AFTER persisting partial bytes on N chunk calls.
    pub drop_after_partial_chunk_remaining: u32,
    /// Expire the remote session (`404`/`NoSuchUpload`) on next `upload_chunk` or `query_upload`.
    pub expire_session_remaining: u32,
    /// Commit object on final chunk/finish, then return a network timeout so the
    /// client observes an **ambiguous commit** and must reconcile!
    pub drop_final_commit_response_remaining: u32,
    /// Emit a partial listing error during `list_stream`.
    pub inject_list_error: bool,
    /// Simulate a live same-length middle edit of a source file after N `open_read` calls.
    pub mutate_source_after_reads: Option<(String, u32)>,
    /// Fail `put_single_shot` permanently for specific relative paths (e.g., `TestSyncWithErrors`).
    pub fail_put_paths: std::collections::HashSet<String>,
    /// Commit corrupted bytes (one flipped byte) on the next N final commits
    /// (`put_single_shot`, final sequential chunk, or `finish_upload`).
    pub corrupt_commit_remaining: u32,
    /// When `true`, a corrupted commit is detected "server side" and reported as the
    /// backend checksum-mismatch error (like the GDrive/S3 streaming MD5 checks); when
    /// `false`, the corrupted object is returned as a successful commit.
    pub corrupt_commit_reports_mismatch: bool,
    /// Corrupt the bytes served by the next N `open_read` calls (one flipped byte in the
    /// middle of the object) without changing the object's advertised checksum.
    pub corrupt_reads_remaining: u32,
    /// Fail `delete` for these relative paths with a permanent error on every call.
    pub fail_delete_paths: std::collections::HashSet<String>,
    /// Fail `put_single_shot` for these relative paths with a retryable `503` on every call.
    pub fail_put_transient_paths: std::collections::HashSet<String>,
    /// Panic inside `put_single_shot` / `begin_upload` (simulating a backend bug that
    /// unwinds a transfer worker).
    pub panic_on_upload: bool,
    /// Optional deterministic seeded fault generator constructed by [`FaultSchedule::random`].
    #[doc(hidden)]
    pub random: Option<RandomFaultState>,
}

/// Error a [`ChaosBackend`] returns for a corrupted commit when
/// [`FaultSchedule::corrupt_commit_reports_mismatch`] is set, mirroring
/// `rship_backends::common::checksum_mismatch_error`.
pub(super) fn chaos_checksum_mismatch(context: &str) -> Error {
    Error::integrity(format!(
        "{context} checksum mismatch (MD5): expected streamed digest, got server digest"
    ))
}

impl FaultSchedule {
    /// Build a deterministic seeded randomized fault schedule backed by SplitMix64.
    pub fn random(seed: u64, profile: RandomFaultProfile) -> Self {
        Self {
            random: Some(RandomFaultState::new(seed, profile)),
            ..Default::default()
        }
    }

    /// Advance the seeded PRNG (if configured) and return the next fault for `op`.
    pub fn next_fault(&mut self, op: ChaosOp) -> Option<InjectedFault> {
        self.random.as_mut().and_then(|r| r.next_fault(op))
    }

    /// Total number of randomized faults emitted by this schedule so far.
    pub fn random_faults_injected(&self) -> u32 {
        self.random.as_ref().map_or(0, |r| r.injected)
    }
}
