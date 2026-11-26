//! Per-remote/principal isolated CUBIC adaptive rate limiter, retry-quota token
//! bucket, and write-QPS pacer (modeled after AWS SDK Adaptive Retry Mode +
//! Google Drive write-ceiling pacing).

use rand::RngExt;
use rship_core::RetryQuota;
use rship_core::clock::{Clock, SystemClock};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Transport plane used to isolate rate limiting between Control Plane metadata
/// RPCs and Data Plane bulk uploads/downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimiterPlane {
    Control,
    Data,
}

/// Isolation key ensuring independent remotes, principals, or transport planes
/// never share rate limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LimiterScope {
    pub remote: String,
    pub principal: String,
    pub plane: Option<LimiterPlane>,
}

impl LimiterScope {
    pub fn new(remote: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            principal: principal.into(),
            plane: None,
        }
    }

    pub fn with_plane(
        remote: impl Into<String>,
        principal: impl Into<String>,
        plane: LimiterPlane,
    ) -> Self {
        Self {
            remote: remote.into(),
            principal: principal.into(),
            plane: Some(plane),
        }
    }

    pub fn control(remote: impl Into<String>, principal: impl Into<String>) -> Self {
        Self::with_plane(remote, principal, LimiterPlane::Control)
    }

    pub fn data(remote: impl Into<String>, principal: impl Into<String>) -> Self {
        Self::with_plane(remote, principal, LimiterPlane::Data)
    }

    /// Return a copy of this scope pinned to a specific transport plane.
    pub fn for_plane(mut self, plane: LimiterPlane) -> Self {
        self.plane = Some(plane);
        self
    }
}

#[derive(Debug, Clone)]
pub struct CubicConfig {
    /// Multiplicative decrease factor on throttle (`0.7` per AWS SDK).
    pub beta: f64,
    /// CUBIC scale constant `C` (`0.4` per AWS SDK).
    pub scale_constant: f64,
    /// Minimum send rate (requests/sec).
    pub min_fill_rate: f64,
    /// Maximum send rate ceiling (requests/sec).
    pub max_fill_rate: f64,
    /// Exponential smoothing factor for measured send rate (`0.8`).
    pub smooth: f64,
    /// Minimum token bucket capacity.
    pub min_capacity: f64,
    /// Coalescing window (seconds) during which concurrent throttle signals apply
    /// at most one multiplicative `beta` cut (defaults to `0.5s`, matching the
    /// measurement bucket).
    pub throttle_window_secs: f64,
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            beta: 0.7,
            scale_constant: 0.4,
            min_fill_rate: 0.5,
            max_fill_rate: 25_000.0,
            smooth: 0.8,
            min_capacity: 1.0,
            throttle_window_secs: 0.5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryQuotaConfig {
    /// Maximum retry quota tokens (AWS SDK default: 500).
    pub max_tokens: u32,
    /// Cost for retrying a non-timeout error (AWS SDK default: 5).
    pub retry_cost: u32,
    /// Cost for retrying a timeout error (AWS SDK default: 10).
    pub timeout_retry_cost: u32,
    /// Refund on initial (non-retry) request success (AWS SDK default: 1).
    pub no_retry_increment: u32,
}

impl Default for RetryQuotaConfig {
    fn default() -> Self {
        Self {
            max_tokens: 500,
            retry_cost: 5,
            timeout_retry_cost: 10,
            no_retry_increment: 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RateLimiterConfig {
    pub cubic: CubicConfig,
    pub retry_quota: RetryQuotaConfig,
    /// Optional proactive global API TPS ceiling covering both read and write requests (`--tpslimit`).
    pub tps_limit: Option<f64>,
    /// Burst capacity for `tps_limit` (defaults to `max(1.0, tps_limit)`).
    pub tps_burst: Option<f64>,
    /// Optional dedicated write-QPS ceiling (e.g. `Some(8.0)` for Google Drive file creations).
    pub write_qps: Option<f64>,
    /// Burst capacity for the write-QPS bucket (defaults to `max(1.0, write_qps)`).
    pub write_burst: Option<f64>,
}

impl RateLimiterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tps_limit(mut self, tps: f64) -> Self {
        self.tps_limit = (tps.is_finite() && tps > 0.0).then_some(tps);
        self
    }

    pub fn with_tps_burst(mut self, burst: f64) -> Self {
        self.tps_burst = Some(burst);
        self
    }

    pub fn with_write_qps(mut self, qps: f64) -> Self {
        self.write_qps = Some(qps);
        self
    }

    pub fn with_write_burst(mut self, burst: f64) -> Self {
        self.write_burst = Some(burst);
        self
    }

    pub fn with_cubic(mut self, cubic: CubicConfig) -> Self {
        self.cubic = cubic;
        self
    }

    pub fn with_retry_quota(mut self, retry_quota: RetryQuotaConfig) -> Self {
        self.retry_quota = retry_quota;
        self
    }
}

#[derive(Debug)]
struct CubicState {
    enabled: bool,
    fill_rate: f64,
    max_capacity: f64,
    current_capacity: f64,
    last_timestamp_secs: Option<f64>,
    measured_tx_rate: f64,
    last_tx_rate_bucket: f64,
    request_count_in_bucket: u64,
    last_max_rate: f64,
    last_throttle_time_secs: f64,
    last_throttle_cut_secs: Option<f64>,
    time_window: f64,
}

impl CubicState {
    fn new(cfg: &CubicConfig, now: f64) -> Self {
        Self {
            enabled: false,
            fill_rate: cfg.min_fill_rate,
            max_capacity: cfg.min_capacity,
            current_capacity: cfg.min_capacity,
            last_timestamp_secs: None,
            measured_tx_rate: 0.0,
            last_tx_rate_bucket: now.floor(),
            request_count_in_bucket: 0,
            last_max_rate: 0.0,
            last_throttle_time_secs: now,
            last_throttle_cut_secs: None,
            time_window: 0.0,
        }
    }

    fn refill(&mut self, now: f64) {
        if let Some(last) = self.last_timestamp_secs {
            let elapsed = (now - last).max(0.0);
            self.current_capacity =
                (self.current_capacity + elapsed * self.fill_rate).min(self.max_capacity);
        }
        self.last_timestamp_secs = Some(now);
    }

    fn update_measured_rate(&mut self, cfg: &CubicConfig, now: f64) {
        let bucket = (now * 2.0).floor() / 2.0; // 0.5s measurement windows
        self.request_count_in_bucket += 1;
        if bucket > self.last_tx_rate_bucket {
            let elapsed = (bucket - self.last_tx_rate_bucket).max(0.5);
            let current_rate = self.request_count_in_bucket as f64 / elapsed;
            self.measured_tx_rate =
                current_rate * cfg.smooth + self.measured_tx_rate * (1.0 - cfg.smooth);
            self.request_count_in_bucket = 0;
            self.last_tx_rate_bucket = bucket;
        }
    }

    fn update_fill_rate(&mut self, cfg: &CubicConfig, new_rate: f64, now: f64) {
        self.refill(now);
        let clamped = new_rate.clamp(cfg.min_fill_rate, cfg.max_fill_rate);
        self.fill_rate = clamped;
        self.max_capacity = clamped.max(cfg.min_capacity);
        self.current_capacity = self.current_capacity.min(self.max_capacity);
    }

    fn calculate_time_window(&mut self, cfg: &CubicConfig) {
        let num = self.last_max_rate * (1.0 - cfg.beta);
        self.time_window = (num / cfg.scale_constant).cbrt();
    }

    fn cubic_success(&self, cfg: &CubicConfig, now: f64) -> f64 {
        let dt = (now - self.last_throttle_time_secs).max(0.0);
        let delta = dt - self.time_window;
        cfg.scale_constant * delta.powi(3) + self.last_max_rate
    }

    fn on_throttle(&mut self, cfg: &CubicConfig, now: f64) {
        self.update_measured_rate(cfg, now);
        if cfg.throttle_window_secs.is_finite()
            && cfg.throttle_window_secs > 0.0
            && let Some(last_cut) = self.last_throttle_cut_secs
        {
            let elapsed = now - last_cut;
            if elapsed >= 0.0 && elapsed < cfg.throttle_window_secs {
                // Coalesce concurrent throttle signals within the window so N
                // parallel workers hitting 429/503 only apply one beta cut.
                if self.current_capacity < 0.0 {
                    self.current_capacity = 0.0;
                }
                return;
            }
        }
        let base_rate = if !self.enabled {
            self.measured_tx_rate.max(cfg.min_fill_rate * 2.0)
        } else {
            self.measured_tx_rate
                .min(self.fill_rate)
                .max(cfg.min_fill_rate)
        };
        self.enabled = true;
        self.last_max_rate = base_rate;
        self.last_throttle_time_secs = now;
        self.last_throttle_cut_secs = Some(now);
        self.calculate_time_window(cfg);
        let reduced = (self.last_max_rate * cfg.beta).max(cfg.min_fill_rate);
        if self.current_capacity < 0.0 {
            self.current_capacity = 0.0;
        }
        self.update_fill_rate(cfg, reduced, now);
    }

    fn on_success(&mut self, cfg: &CubicConfig, now: f64) {
        self.update_measured_rate(cfg, now);
        if !self.enabled {
            return;
        }
        let target = self.cubic_success(cfg, now);
        // Cap growth smoothly so a single idle gap doesn't immediately jump to infinity.
        let capped = target.min(self.measured_tx_rate.max(self.fill_rate) * 2.0 + 1.0);
        self.update_fill_rate(cfg, capped, now);
        // Disengage CUBIC gating after sustained healthy recovery so a single transient
        // `503 SlowDown` never permanently caps high-throughput object-store migrations.
        const HEALTHY_RECOVERY_SECS: f64 = 30.0;
        let disengage_threshold = (self.last_max_rate * 1.5).max(50.0).min(cfg.max_fill_rate);
        if (now - self.last_throttle_time_secs) >= HEALTHY_RECOVERY_SECS
            && self.fill_rate >= disengage_threshold
        {
            self.enabled = false;
            self.last_throttle_cut_secs = None;
        }
    }

    /// Reserve 1 send token, returning how long the caller must sleep before sending.
    fn reserve_token(&mut self, now: f64) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        self.refill(now);
        if self.current_capacity >= 1.0 {
            self.current_capacity -= 1.0;
            return Duration::ZERO;
        }
        let deficit = 1.0 - self.current_capacity;
        self.current_capacity -= 1.0;
        let wait_secs = (deficit / self.fill_rate).max(0.0);
        Duration::from_secs_f64(wait_secs)
    }
}

#[derive(Debug)]
struct WriteBucketState {
    qps: f64,
    burst: f64,
    tokens: f64,
    last_secs: f64,
}

impl WriteBucketState {
    fn new(qps: f64, burst: Option<f64>, now: f64) -> Self {
        let qps = qps.max(0.01);
        let burst = burst.unwrap_or_else(|| qps.max(1.0)).max(1.0);
        Self {
            qps,
            burst,
            tokens: burst,
            last_secs: now,
        }
    }

    fn reserve(&mut self, now: f64) -> Duration {
        let elapsed = (now - self.last_secs).max(0.0);
        self.tokens = (self.tokens + elapsed * self.qps).min(self.burst);
        self.last_secs = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let deficit = 1.0 - self.tokens;
            self.tokens -= 1.0; // reserve slot so concurrent writers serialize cleanly
            Duration::from_secs_f64((deficit / self.qps).max(0.0))
        }
    }
}

#[derive(Debug)]
struct RetryQuotaState {
    available: u32,
}

#[derive(Debug)]
struct LimiterInner {
    cubic: CubicState,
    retry_quota: RetryQuotaState,
    tps_bucket: Option<WriteBucketState>,
    write_bucket: Option<WriteBucketState>,
}

/// Snapshot of limiter telemetry useful for diagnostics & testing.
#[derive(Debug, Clone, Copy)]
pub struct LimiterSnapshot {
    pub cubic_enabled: bool,
    pub fill_rate: f64,
    pub retry_quota_available: u32,
    pub retry_quota_max: u32,
}

/// Isolated per-`(remote, principal)` rate limiter combining:
/// 1. Optional proactive global API TPS pacer (`--tpslimit`, reads + writes)
/// 2. CUBIC adaptive send-rate limiter (reactive on 403/429/503)
/// 3. Retry quota token bucket
/// 4. Optional write-QPS pacer (e.g. GDrive create/write ceiling)
#[derive(Debug)]
pub struct ScopedLimiter {
    scope: LimiterScope,
    cfg: RateLimiterConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<LimiterInner>,
}

impl ScopedLimiter {
    pub fn new(scope: LimiterScope, cfg: RateLimiterConfig, clock: Arc<dyn Clock>) -> Self {
        let now = now_secs(&clock);
        let tps_bucket = cfg
            .tps_limit
            .filter(|&qps| qps.is_finite() && qps > 0.0)
            .map(|qps| WriteBucketState::new(qps, cfg.tps_burst, now));
        let write_bucket = cfg
            .write_qps
            .map(|qps| WriteBucketState::new(qps, cfg.write_burst, now));
        let inner = LimiterInner {
            cubic: CubicState::new(&cfg.cubic, now),
            retry_quota: RetryQuotaState {
                available: cfg.retry_quota.max_tokens,
            },
            tps_bucket,
            write_bucket,
        };
        Self {
            scope,
            cfg,
            clock,
            inner: Mutex::new(inner),
        }
    }

    pub fn scope(&self) -> &LimiterScope {
        &self.scope
    }

    /// The injectable clock driving this limiter's token buckets and sleeps.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Sleep for `duration` through the injected [`Clock`] so deterministic simulation
    /// tests can virtualise retry backoff and pacing waits. With the production
    /// [`SystemClock`] this is exactly `tokio::time::sleep(duration)`.
    pub async fn sleep(&self, duration: Duration) {
        if !duration.is_zero() {
            self.clock.sleep(duration).await;
        }
    }

    /// Acquire a global TPS + CUBIC send permit before issuing an HTTP request.
    pub async fn acquire_send_permit(&self) {
        let wait = {
            let now = now_secs(&self.clock);
            let mut guard = self.inner.lock().expect("limiter mutex poisoned");
            let tps_wait = match guard.tps_bucket.as_mut() {
                Some(tb) => tb.reserve(now),
                None => Duration::ZERO,
            };
            let cubic_wait = guard.cubic.reserve_token(now);
            tps_wait.max(cubic_wait)
        };
        if !wait.is_zero() {
            self.clock.sleep(wait).await;
        }
    }

    /// Acquire a write-QPS permit before issuing a rate-sensitive mutation
    /// (e.g. Google Drive file creation / `mkdir`).
    pub async fn acquire_write_permit(&self) {
        let wait = {
            let now = now_secs(&self.clock);
            let mut guard = self.inner.lock().expect("limiter mutex poisoned");
            match guard.write_bucket.as_mut() {
                Some(wb) => wb.reserve(now),
                None => Duration::ZERO,
            }
        };
        if !wait.is_zero() {
            self.clock.sleep(wait).await;
        }
    }

    /// Attempt to consume retry quota before retrying a failed request.
    /// Returns `false` if sustained outages have exhausted retry budget (caller must fail fast).
    pub fn try_acquire_retry_quota(&self, is_timeout: bool) -> bool {
        let cost = if is_timeout {
            self.cfg.retry_quota.timeout_retry_cost
        } else {
            self.cfg.retry_quota.retry_cost
        };
        let mut guard = self.inner.lock().expect("limiter mutex poisoned");
        if guard.retry_quota.available >= cost {
            guard.retry_quota.available -= cost;
            true
        } else {
            false
        }
    }

    /// Record a successful response: advances CUBIC recovery and refunds retry quota.
    pub fn record_success(&self, was_retry: bool, was_timeout_retry: bool) {
        let now = now_secs(&self.clock);
        let mut guard = self.inner.lock().expect("limiter mutex poisoned");
        guard.cubic.on_success(&self.cfg.cubic, now);
        self.refund_retry_quota_locked(&mut guard, was_retry, was_timeout_retry);
    }

    /// Refund retry quota for a successful operation WITHOUT touching CUBIC (used when the
    /// engine's transfer-level retries share this limiter's bucket via [`RetryQuota`]).
    pub fn refund_retry_quota(&self, was_retry: bool, was_timeout_retry: bool) {
        let mut guard = self.inner.lock().expect("limiter mutex poisoned");
        self.refund_retry_quota_locked(&mut guard, was_retry, was_timeout_retry);
    }

    fn refund_retry_quota_locked(
        &self,
        guard: &mut LimiterInner,
        was_retry: bool,
        was_timeout_retry: bool,
    ) {
        let refund = if was_retry {
            if was_timeout_retry {
                self.cfg.retry_quota.timeout_retry_cost
            } else {
                self.cfg.retry_quota.retry_cost
            }
        } else {
            self.cfg.retry_quota.no_retry_increment
        };
        guard.retry_quota.available = guard
            .retry_quota
            .available
            .saturating_add(refund)
            .min(self.cfg.retry_quota.max_tokens);
    }

    /// Record a throttling signal (`429`, `503`, GDrive `403 userRateLimitExceeded`).
    pub fn record_throttle(&self) {
        let now = now_secs(&self.clock);
        let mut guard = self.inner.lock().expect("limiter mutex poisoned");
        guard.cubic.on_throttle(&self.cfg.cubic, now);
    }

    /// Compute full-jitter exponential backoff (`[0, min(cap, base * 2^attempt)]`),
    /// honoring an explicit server `Retry-After` hint when present.
    pub fn backoff_delay(
        &self,
        attempt: u32,
        base: Duration,
        cap: Duration,
        retry_after: Option<Duration>,
    ) -> Duration {
        if let Some(ra) = retry_after {
            if !ra.is_zero() {
                return ra.min(cap);
            }
            if cap.is_zero() {
                return Duration::ZERO;
            }
            // Apply a non-zero jitter floor for `Retry-After: 0` (or past HTTP-date)
            // so callers never spin in a 0ms tight loop.
            let floor_ceiling = base.max(Duration::from_millis(50)).min(cap);
            let max_ms = floor_ceiling.as_millis().min(u128::from(u64::MAX)) as u64;
            if max_ms == 0 {
                return cap;
            }
            let min_ms = (max_ms / 2).max(1);
            return Duration::from_millis(rand::rng().random_range(min_ms..=max_ms));
        }
        let exp = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        let ceiling = base.saturating_mul(exp).min(cap);
        let ceiling_ms = ceiling.as_millis().min(u128::from(u64::MAX)) as u64;
        if ceiling_ms == 0 {
            return Duration::ZERO;
        }
        let jitter_ms = rand::rng().random_range(0..=ceiling_ms);
        Duration::from_millis(jitter_ms)
    }

    pub fn snapshot(&self) -> LimiterSnapshot {
        let guard = self.inner.lock().expect("limiter mutex poisoned");
        LimiterSnapshot {
            cubic_enabled: guard.cubic.enabled,
            fill_rate: guard.cubic.fill_rate,
            retry_quota_available: guard.retry_quota.available,
            retry_quota_max: self.cfg.retry_quota.max_tokens,
        }
    }
}

/// The engine's transfer-level retries draw from the same per-(remote, principal, plane)
/// token bucket as the backend's HTTP-level retries, so retries cannot stack into
/// separate budgets (see `StorageBackend::retry_quota`).
impl RetryQuota for ScopedLimiter {
    fn try_acquire(&self, is_timeout: bool) -> bool {
        self.try_acquire_retry_quota(is_timeout)
    }

    fn record_success(&self, was_retry: bool, was_timeout_retry: bool) {
        self.refund_retry_quota(was_retry, was_timeout_retry);
    }
}

/// Thread-safe registry creating strictly isolated [`ScopedLimiter`] instances
/// per `(remote, principal)`.
#[derive(Clone)]
pub struct LimiterRegistry {
    default_cfg: RateLimiterConfig,
    clock: Arc<dyn Clock>,
    entries: Arc<Mutex<HashMap<LimiterScope, Arc<ScopedLimiter>>>>,
}

impl LimiterRegistry {
    pub fn new(default_cfg: RateLimiterConfig) -> Self {
        Self::with_clock(default_cfg, SystemClock::shared())
    }

    pub fn with_clock(default_cfg: RateLimiterConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            default_cfg,
            clock,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_or_create(&self, scope: LimiterScope) -> Arc<ScopedLimiter> {
        self.get_or_create_with_config(scope, self.default_cfg.clone())
    }

    pub fn get_or_create_with_config(
        &self,
        scope: LimiterScope,
        mut cfg: RateLimiterConfig,
    ) -> Arc<ScopedLimiter> {
        if cfg.tps_limit.is_none() {
            cfg.tps_limit = self.default_cfg.tps_limit;
            cfg.tps_burst = self.default_cfg.tps_burst;
        }
        let mut guard = self.entries.lock().expect("registry mutex poisoned");
        guard
            .entry(scope.clone())
            .or_insert_with(|| Arc::new(ScopedLimiter::new(scope, cfg, self.clock.clone())))
            .clone()
    }
}

fn now_secs(clock: &Arc<dyn Clock>) -> f64 {
    clock.now_unix_nanos() as f64 / 1_000_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::clock::VirtualClock;

    #[test]
    fn cubic_throttles_multiplicatively_and_recovers_while_isolating_scopes() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let registry = LimiterRegistry::with_clock(RateLimiterConfig::default(), clock.clone());

        let scope_a = LimiterScope::new("gdrive-a", "alice@example.com");
        let scope_b = LimiterScope::new("gdrive-b", "bob@example.com");
        let lim_a = registry.get_or_create(scope_a);
        let lim_b = registry.get_or_create(scope_b);

        // Warm up measured send rate on A: 20 requests over 1 second -> ~20 req/s.
        for _ in 0..10 {
            lim_a.record_success(false, false);
        }
        clock.advance(Duration::from_millis(500));
        for _ in 0..10 {
            lim_a.record_success(false, false);
        }
        clock.advance(Duration::from_millis(500));
        lim_a.record_success(false, false);

        assert!(!lim_a.snapshot().cubic_enabled);

        // Throttle A -> CUBIC activates and reduces rate, B stays completely untouched!
        lim_a.record_throttle();
        let snap_a1 = lim_a.snapshot();
        assert!(snap_a1.cubic_enabled);
        assert!(!lim_b.snapshot().cubic_enabled);

        // Advance time and record successes -> CUBIC recovers upward.
        clock.advance(Duration::from_secs(5));
        for _ in 0..10 {
            lim_a.record_success(false, false);
        }
        let snap_a2 = lim_a.snapshot();
        assert!(
            snap_a2.fill_rate > snap_a1.fill_rate,
            "expected CUBIC recovery: {} -> {}",
            snap_a1.fill_rate,
            snap_a2.fill_rate
        );
    }

    #[test]
    fn retry_quota_prevents_retry_storms_and_refunds_on_success() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg = RateLimiterConfig {
            retry_quota: RetryQuotaConfig {
                max_tokens: 15,
                retry_cost: 5,
                timeout_retry_cost: 10,
                no_retry_increment: 1,
            },
            ..Default::default()
        };
        let lim = ScopedLimiter::new(LimiterScope::new("r", "p"), cfg, clock);

        assert!(lim.try_acquire_retry_quota(false)); // 15 -> 10
        assert!(lim.try_acquire_retry_quota(true)); // 10 -> 0
        assert!(!lim.try_acquire_retry_quota(false)); // exhausted -> fail fast!

        // Refund on successful retry restores retry tokens.
        lim.record_success(true, true); // 0 -> 10
        assert_eq!(lim.snapshot().retry_quota_available, 10);
        assert!(lim.try_acquire_retry_quota(false)); // 10 -> 5
    }

    #[tokio::test(start_paused = true)]
    async fn write_qps_bucket_paces_burst_then_throttles() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg = RateLimiterConfig {
            write_qps: Some(2.0),
            write_burst: Some(2.0),
            ..Default::default()
        };
        let lim = ScopedLimiter::new(LimiterScope::new("gdrive", "u"), cfg, clock);

        let t0 = tokio::time::Instant::now();
        // First 2 writes consume burst immediately.
        lim.acquire_write_permit().await;
        lim.acquire_write_permit().await;
        assert_eq!(t0.elapsed(), Duration::ZERO);

        // 3rd write must sleep ~500ms at 2 QPS.
        lim.acquire_write_permit().await;
        assert!(t0.elapsed() >= Duration::from_millis(490));
    }

    #[tokio::test(start_paused = true)]
    async fn pacing_waits_sleep_through_the_injected_clock() {
        // DST: with an instant-sleep virtual clock, write-QPS and TPS pacing must advance
        // VIRTUAL time instead of parking on tokio timers.
        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let cfg = RateLimiterConfig {
            write_qps: Some(2.0),
            write_burst: Some(1.0),
            tps_limit: Some(2.0),
            tps_burst: Some(1.0),
            ..Default::default()
        };
        let lim = ScopedLimiter::new(LimiterScope::new("gdrive", "u"), cfg, clock.clone());
        let v0 = clock.now_unix_nanos();
        let t0 = tokio::time::Instant::now();
        lim.acquire_write_permit().await;
        lim.acquire_write_permit().await;
        lim.acquire_send_permit().await;
        lim.acquire_send_permit().await;
        assert_eq!(t0.elapsed(), Duration::ZERO, "no tokio timer may be used");
        assert!(
            clock.now_unix_nanos() - v0 >= 490_000_000,
            "pacing must advance the injected clock"
        );
        lim.sleep(Duration::from_secs(3)).await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn tps_limit_paces_send_permits_and_inherits_from_registry() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let default_cfg = RateLimiterConfig {
            tps_limit: Some(2.0),
            tps_burst: Some(2.0),
            ..Default::default()
        };
        let registry = LimiterRegistry::with_clock(default_cfg, clock);
        // Backend supplies custom write_qps without tps_limit -> inherits registry tps_limit.
        let lim = registry.get_or_create_with_config(
            LimiterScope::new("gdrive2", "u"),
            RateLimiterConfig {
                write_qps: Some(8.0),
                ..Default::default()
            },
        );
        let t0 = tokio::time::Instant::now();
        lim.acquire_send_permit().await;
        lim.acquire_send_permit().await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
        lim.acquire_send_permit().await;
        assert!(t0.elapsed() >= Duration::from_millis(490));
    }

    #[tokio::test(start_paused = true)]
    async fn tps_limit_zero_or_non_positive_is_unlimited() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg_builder = RateLimiterConfig::default().with_tps_limit(0.0);
        assert!(cfg_builder.tps_limit.is_none());
        assert!(
            RateLimiterConfig::default()
                .with_tps_limit(-5.0)
                .tps_limit
                .is_none()
        );
        assert!(
            RateLimiterConfig::default()
                .with_tps_limit(f64::NAN)
                .tps_limit
                .is_none()
        );

        // Even if constructed directly with `tps_limit: Some(0.0)`, ScopedLimiter must not throttle.
        let lim = ScopedLimiter::new(
            LimiterScope::new("gdrive", "u"),
            RateLimiterConfig {
                tps_limit: Some(0.0),
                tps_burst: Some(1.0),
                ..Default::default()
            },
            clock,
        );
        let t0 = tokio::time::Instant::now();
        for _ in 0..20 {
            lim.acquire_send_permit().await;
        }
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    #[test]
    fn cubic_high_ceiling_and_auto_disengages_after_sustained_healthy_recovery() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg = RateLimiterConfig::default();
        assert!(
            cfg.cubic.max_fill_rate >= 10_000.0,
            "default CUBIC ceiling must not cap high-QPS S3 workloads at 200 req/s"
        );
        let lim = ScopedLimiter::new(LimiterScope::new("s3", "bucket"), cfg, clock.clone());

        // Trigger a single transient 503 SlowDown.
        lim.record_throttle();
        assert!(lim.snapshot().cubic_enabled);

        // Advance through 60s of healthy traffic and verify CUBIC recovers past 200 req/s
        // and eventually auto-disengages completely.
        for _ in 0..60 {
            clock.advance(Duration::from_secs(1));
            for _ in 0..50 {
                lim.record_success(false, false);
            }
        }
        assert!(
            !lim.snapshot().cubic_enabled,
            "CUBIC should auto-disengage after sustained healthy recovery (snap={:?})",
            lim.snapshot()
        );
    }

    #[test]
    fn cubic_reserve_token_staggers_concurrent_callers_without_thundering_herd() {
        // P2-2: Concurrent callers under active CUBIC throttling must receive strictly
        // increasing wait durations (1/fill_rate spacing), never identical wakeups.
        let cfg = CubicConfig::default();
        let mut state = CubicState::new(&cfg, 100.0);
        state.on_throttle(&cfg, 100.0);
        state.fill_rate = 10.0;
        state.current_capacity = 0.0;

        let w1 = state.reserve_token(100.0);
        let w2 = state.reserve_token(100.0);
        let w3 = state.reserve_token(100.0);
        assert!(w1 >= Duration::from_millis(95) && w1 <= Duration::from_millis(105));
        assert!(
            w2 >= w1 + Duration::from_millis(95),
            "2nd caller must be staggered past 1st (w1={w1:?}, w2={w2:?})"
        );
        assert!(
            w3 >= w2 + Duration::from_millis(95),
            "3rd caller must be staggered past 2nd (w2={w2:?}, w3={w3:?})"
        );

        // Subsequent throttle resets negative debt back to 0.0 before recomputing fill_rate.
        state.on_throttle(&cfg, 100.0);
        assert!(state.current_capacity >= 0.0);
    }

    #[test]
    fn cubic_coalesces_concurrent_throttles_into_single_cut_per_window() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let lim = ScopedLimiter::new(
            LimiterScope::new("s3", "bucket"),
            RateLimiterConfig::default(),
            clock.clone(),
        );

        // Warm up measured send rate to ~100 req/s over 1s.
        for _ in 0..50 {
            lim.record_success(false, false);
        }
        clock.advance(Duration::from_millis(500));
        for _ in 0..50 {
            lim.record_success(false, false);
        }
        clock.advance(Duration::from_millis(500));
        lim.record_success(false, false);

        // 16 concurrent workers all receive 429/503 at the exact same timestamp.
        // CUBIC must cut fill_rate ONCE (by beta=0.7), NOT 16 times (0.7^16 -> min_fill_rate)!
        for _ in 0..16 {
            lim.record_throttle();
        }
        let snap = lim.snapshot();
        assert!(snap.cubic_enabled);
        assert!(
            snap.fill_rate >= 50.0,
            "16 concurrent throttles must not compound cuts down to min_fill_rate; got fill_rate={}",
            snap.fill_rate
        );

        // Additional throttle within the 0.5s window still coalesces (no second cut).
        clock.advance(Duration::from_millis(250));
        lim.record_throttle();
        assert!(
            (lim.snapshot().fill_rate - snap.fill_rate).abs() < 1e-9,
            "throttle within throttle_window_secs must not cut again"
        );

        // Once the 0.5s window elapses, a fresh throttle applies one new beta cut.
        clock.advance(Duration::from_millis(300));
        lim.record_throttle();
        assert!(
            lim.snapshot().fill_rate < snap.fill_rate,
            "throttle after throttle_window_secs must apply a new multiplicative cut ({} -> {})",
            snap.fill_rate,
            lim.snapshot().fill_rate
        );
    }

    #[test]
    fn limiter_plane_isolates_control_and_data_planes() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let registry = LimiterRegistry::with_clock(RateLimiterConfig::default(), clock);

        let ctrl = registry.get_or_create(LimiterScope::control("gdrive", "alice@example.com"));
        let data = registry.get_or_create(LimiterScope::data("gdrive", "alice@example.com"));
        let legacy = registry.get_or_create(LimiterScope::new("gdrive", "alice@example.com"));

        assert_eq!(ctrl.scope().plane, Some(LimiterPlane::Control));
        assert_eq!(data.scope().plane, Some(LimiterPlane::Data));
        assert_eq!(legacy.scope().plane, None);
        assert!(!Arc::ptr_eq(&ctrl, &data));
        assert!(!Arc::ptr_eq(&ctrl, &legacy));
        assert!(!Arc::ptr_eq(&data, &legacy));

        data.record_throttle();
        assert!(data.snapshot().cubic_enabled);
        assert!(!ctrl.snapshot().cubic_enabled);
        assert!(!legacy.snapshot().cubic_enabled);
    }

    #[test]
    fn backoff_delay_uses_full_jitter_and_caps_retry_after() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let lim = ScopedLimiter::new(
            LimiterScope::new("s3", "bucket"),
            RateLimiterConfig::default(),
            clock,
        );

        let base = Duration::from_millis(100);
        let cap = Duration::from_secs(10);
        let ceiling_ms = 800u64; // attempt 3 -> 100ms * 2^3 = 800ms
        let mut saw_below_half = false;
        for _ in 0..500 {
            let d = lim.backoff_delay(3, base, cap, None);
            assert!(d <= Duration::from_millis(ceiling_ms));
            if d < Duration::from_millis(ceiling_ms / 2) {
                saw_below_half = true;
            }
        }
        assert!(
            saw_below_half,
            "full jitter must sample across [0, ceiling_ms], not [ceiling_ms/2, ceiling_ms]"
        );

        // Retry-After is honored and capped at `cap`.
        assert_eq!(
            lim.backoff_delay(0, base, cap, Some(Duration::from_secs(3))),
            Duration::from_secs(3)
        );
        assert_eq!(
            lim.backoff_delay(0, base, cap, Some(Duration::from_secs(30))),
            cap
        );
    }

    #[test]
    fn backoff_delay_applies_nonzero_jitter_floor_on_retry_after_zero() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let lim = ScopedLimiter::new(
            LimiterScope::new("dropbox", "acct"),
            RateLimiterConfig::default(),
            clock,
        );
        let base = Duration::from_millis(100);
        let cap = Duration::from_secs(10);
        for _ in 0..50 {
            let d = lim.backoff_delay(0, base, cap, Some(Duration::ZERO));
            assert!(
                !d.is_zero() && d <= base,
                "expected non-zero jittered delay <= {base:?}, got {d:?}"
            );
        }
        assert_eq!(
            lim.backoff_delay(0, base, Duration::ZERO, Some(Duration::ZERO)),
            Duration::ZERO
        );
    }
}
