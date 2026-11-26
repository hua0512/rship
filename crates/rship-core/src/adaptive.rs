//! Falcon-inspired Dual-Lane Online Adaptive Concurrency Controller
//! (Arslan et al., SC '16 HARP; SC '21 / IEEE TPDS '23 Falcon).
//!
//! Separates transfers into:
//! - **Small-File Pipelined Lane** (`<= small_file_threshold`, default `1 MiB`)
//! - **Large-File Streaming Lane** (`> small_file_threshold`)
//!
//! Probes concurrency upward via gradient ascent on the Falcon utility function
//! `U(c) = throughput / c^K` and backs off multiplicatively on `429`/`503`
//! throttling or error spikes, enforcing dynamic live concurrency via race-free
//! async [`LanePermit`] gates.

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;

use crate::clock::{Clock, SystemClock};
use crate::error::Result;
use crate::source::ByteStream;

pub const DEFAULT_SMALL_FILE_THRESHOLD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferLane {
    SmallPipelined,
    LargeStreaming,
}

#[derive(Debug, Clone)]
pub struct FalconConfig {
    pub small_file_threshold_bytes: u64,
    pub small_min: usize,
    pub small_max: usize,
    pub small_initial: usize,
    pub large_min: usize,
    pub large_max: usize,
    pub large_initial: usize,
    /// Concurrency overhead exponent `K > 1.0` penalizing diminishing returns.
    pub utility_k: f64,
    /// Multiplicative decrease factor on throttle (`429`/`503`).
    pub throttle_beta: f64,
    /// Minimum telemetry window duration before probing concurrency upward.
    pub window_duration: Duration,
}

impl Default for FalconConfig {
    fn default() -> Self {
        Self {
            small_file_threshold_bytes: DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
            small_min: 2,
            small_max: 32,
            small_initial: 6,
            large_min: 1,
            large_max: 16,
            large_initial: 4,
            utility_k: 1.02,
            throttle_beta: 0.7,
            window_duration: Duration::from_secs(1),
        }
    }
}

impl FalconConfig {
    /// Build a bounded dual-lane config scaled cleanly from a user `--transfers` ceiling.
    pub fn from_max_transfers(max_transfers: usize) -> Self {
        let large_max = max_transfers.max(1);
        let large_initial = (large_max / 2).clamp(1, large_max);
        let small_max = (large_max.saturating_mul(2)).clamp(2, 256);
        let small_initial = large_max.clamp(2, small_max);
        Self {
            small_min: 1,
            small_max,
            small_initial,
            large_min: 1,
            large_max,
            large_initial,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct LaneGateState {
    in_flight: usize,
    limit: usize,
}

#[derive(Debug)]
struct LaneGate {
    state: Mutex<LaneGateState>,
    in_flight_atomic: AtomicUsize,
    notify: Notify,
}

impl LaneGate {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LaneGateState {
                in_flight: 0,
                limit: limit.max(1),
            }),
            in_flight_atomic: AtomicUsize::new(0),
            notify: Notify::new(),
        })
    }

    async fn acquire(self: &Arc<Self>) -> LanePermit {
        loop {
            // Register waiter BEFORE checking condition under lock so no wakeups can be lost.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state.lock().expect("lane gate mutex poisoned");
                if st.in_flight < st.limit {
                    st.in_flight += 1;
                    self.in_flight_atomic.store(st.in_flight, Ordering::Release);
                    return LanePermit { gate: self.clone() };
                }
            }
            notified.await;
        }
    }

    fn set_limit(&self, new_limit: usize) {
        let mut st = self.state.lock().expect("lane gate mutex poisoned");
        let target = new_limit.max(1);
        let grew = target > st.limit;
        st.limit = target;
        drop(st);
        if grew {
            self.notify.notify_waiters();
        }
    }

    fn in_flight(&self) -> usize {
        self.in_flight_atomic.load(Ordering::Acquire)
    }
}

/// RAII concurrency permit bound to a [`TransferLane`].
#[derive(Debug)]
pub struct LanePermit {
    gate: Arc<LaneGate>,
}

impl Drop for LanePermit {
    fn drop(&mut self) {
        {
            let mut st = self.gate.state.lock().expect("lane gate mutex poisoned");
            st.in_flight = st.in_flight.saturating_sub(1);
            self.gate
                .in_flight_atomic
                .store(st.in_flight, Ordering::Release);
        }
        self.gate.notify.notify_one();
    }
}

#[derive(Debug)]
struct LaneState {
    min_c: usize,
    max_c: usize,
    current_c: usize,
    last_utility: Option<f64>,
    last_direction: i32,
    window_bytes: u64,
    window_throttles: u32,
    window_errors: u32,
    window_start_nanos: i64,
    last_cut_nanos: Option<i64>,
}

impl LaneState {
    fn new(min_c: usize, max_c: usize, initial: usize, now_nanos: i64) -> Self {
        let min_c = min_c.max(1);
        let max_c = max_c.max(min_c);
        Self {
            min_c,
            max_c,
            current_c: initial.clamp(min_c, max_c),
            last_utility: None,
            last_direction: 1,
            window_bytes: 0,
            window_throttles: 0,
            window_errors: 0,
            window_start_nanos: now_nanos,
            last_cut_nanos: None,
        }
    }

    fn update(
        &mut self,
        bytes_transferred: u64,
        elapsed_secs: f64,
        throttles: u32,
        errors: u32,
        utility_k: f64,
        throttle_beta: f64,
    ) -> usize {
        if throttles > 0 || errors > 0 {
            let reduced = ((self.current_c as f64) * throttle_beta).floor() as usize;
            self.current_c = reduced.clamp(self.min_c, self.max_c);
            self.last_utility = None;
            self.last_direction = -1;
            return self.current_c;
        }

        let dt = elapsed_secs.max(0.01);
        let throughput = bytes_transferred as f64 / dt;
        let utility = throughput / (self.current_c as f64).powf(utility_k);

        let next_dir = match self.last_utility {
            None => 1,
            Some(prev) => {
                // Only reverse direction when utility degrades past a 2% noise band.
                if utility >= prev * 0.98 {
                    if self.last_direction == 0 {
                        1
                    } else {
                        self.last_direction
                    }
                } else {
                    -self.last_direction
                }
            }
        };

        let step = if self.current_c >= 8 { 2 } else { 1 };
        let proposed = if next_dir >= 0 {
            self.current_c.saturating_add(step)
        } else {
            self.current_c.saturating_sub(step)
        };
        self.current_c = proposed.clamp(self.min_c, self.max_c);
        self.last_utility = Some(utility);
        self.last_direction = next_dir;
        self.current_c
    }
}

#[inline]
fn duration_to_nanos(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

#[derive(Debug)]
struct Lane {
    state: Mutex<LaneState>,
    gate: Arc<LaneGate>,
    current_c: AtomicUsize,
    max_c: usize,
    live_bytes: AtomicU64,
    window_start_nanos: AtomicI64,
}

impl Lane {
    fn new(min_c: usize, max_c: usize, initial: usize, now_nanos: i64) -> Self {
        let st = LaneState::new(min_c, max_c, initial, now_nanos);
        let current_c = st.current_c;
        let max_c = st.max_c;
        let gate = LaneGate::new(current_c);
        Self {
            state: Mutex::new(st),
            gate,
            current_c: AtomicUsize::new(current_c),
            max_c,
            live_bytes: AtomicU64::new(0),
            window_start_nanos: AtomicI64::new(now_nanos),
        }
    }

    fn flush_live_bytes_if_due(&self, cfg: &FalconConfig, clock: &dyn Clock) {
        let window_ns = duration_to_nanos(cfg.window_duration);
        let now_ns = clock.now_unix_nanos();
        let start_ns = self.window_start_nanos.load(Ordering::Acquire);
        if now_ns >= start_ns && now_ns.saturating_sub(start_ns) < window_ns {
            return;
        }

        let updated = match self.state.try_lock() {
            Ok(mut guard) => {
                if now_ns < guard.window_start_nanos {
                    guard.window_start_nanos = now_ns;
                    self.window_start_nanos.store(now_ns, Ordering::Release);
                    return;
                }
                let elapsed_ns = now_ns.saturating_sub(guard.window_start_nanos);
                if elapsed_ns < window_ns {
                    return;
                }
                let streamed = self.live_bytes.swap(0, Ordering::AcqRel);
                let b = guard.window_bytes.saturating_add(streamed);
                let t = guard.window_throttles;
                let e = guard.window_errors;
                guard.window_bytes = 0;
                guard.window_throttles = 0;
                guard.window_errors = 0;
                guard.window_start_nanos = now_ns;
                self.window_start_nanos.store(now_ns, Ordering::Release);
                if b > 0 || t > 0 || e > 0 {
                    let elapsed_secs = elapsed_ns as f64 / 1_000_000_000.0;
                    let new_c =
                        guard.update(b, elapsed_secs, t, e, cfg.utility_k, cfg.throttle_beta);
                    self.current_c.store(new_c, Ordering::Release);
                    Some(new_c)
                } else {
                    None
                }
            }
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(_)) => panic!("falcon lane mutex poisoned"),
        };

        if let Some(new_c) = updated {
            self.gate.set_limit(new_c);
        }
    }

    fn record_event(
        &self,
        cfg: &FalconConfig,
        clock: &dyn Clock,
        bytes_transferred: u64,
        throttles: u32,
        errors: u32,
    ) -> usize {
        let now_ns = clock.now_unix_nanos();
        let window_ns = duration_to_nanos(cfg.window_duration);
        let updated = {
            let mut guard = self.state.lock().expect("falcon lane mutex poisoned");
            let streamed = self.live_bytes.swap(0, Ordering::AcqRel);
            guard.window_bytes = guard
                .window_bytes
                .saturating_add(streamed)
                .saturating_add(bytes_transferred);

            if now_ns < guard.window_start_nanos {
                guard.window_start_nanos = now_ns;
                self.window_start_nanos.store(now_ns, Ordering::Release);
            }

            if throttles > 0 || errors > 0 {
                // Enforce at most ONE multiplicative cut per `window_duration` so a burst of
                // concurrent 429/503 responses from in-flight siblings cannot cascade `c` to 1.
                let within_cut_cooldown = guard
                    .last_cut_nanos
                    .is_some_and(|last| now_ns >= last && now_ns.saturating_sub(last) < window_ns);
                if within_cut_cooldown {
                    None
                } else {
                    let elapsed_secs =
                        now_ns.saturating_sub(guard.window_start_nanos) as f64 / 1_000_000_000.0;
                    let b = guard.window_bytes;
                    let t = guard.window_throttles.saturating_add(throttles);
                    let e = guard.window_errors.saturating_add(errors);
                    guard.window_bytes = 0;
                    guard.window_throttles = 0;
                    guard.window_errors = 0;
                    guard.window_start_nanos = now_ns;
                    guard.last_cut_nanos = Some(now_ns);
                    self.window_start_nanos.store(now_ns, Ordering::Release);
                    let new_c =
                        guard.update(b, elapsed_secs, t, e, cfg.utility_k, cfg.throttle_beta);
                    self.current_c.store(new_c, Ordering::Release);
                    Some(new_c)
                }
            } else {
                let elapsed_ns = now_ns.saturating_sub(guard.window_start_nanos);
                if elapsed_ns >= window_ns {
                    let b = guard.window_bytes;
                    let t = guard.window_throttles;
                    let e = guard.window_errors;
                    guard.window_bytes = 0;
                    guard.window_throttles = 0;
                    guard.window_errors = 0;
                    guard.window_start_nanos = now_ns;
                    self.window_start_nanos.store(now_ns, Ordering::Release);
                    if b > 0 || t > 0 || e > 0 {
                        let elapsed_secs = elapsed_ns as f64 / 1_000_000_000.0;
                        let new_c =
                            guard.update(b, elapsed_secs, t, e, cfg.utility_k, cfg.throttle_beta);
                        self.current_c.store(new_c, Ordering::Release);
                        Some(new_c)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(new_c) = updated {
            self.gate.set_limit(new_c);
            new_c
        } else {
            self.current_c.load(Ordering::Acquire)
        }
    }
}

/// Thread-safe Dual-Lane Falcon adaptive concurrency controller with live async gates.
#[derive(Debug)]
pub struct FalconController {
    cfg: FalconConfig,
    clock: Arc<dyn Clock>,
    small: Lane,
    large: Lane,
}

impl FalconController {
    pub fn new(cfg: FalconConfig) -> Self {
        Self::with_clock(cfg, SystemClock::shared())
    }

    pub fn with_clock(cfg: FalconConfig, clock: Arc<dyn Clock>) -> Self {
        let now_ns = clock.now_unix_nanos();
        let small = Lane::new(cfg.small_min, cfg.small_max, cfg.small_initial, now_ns);
        let large = Lane::new(cfg.large_min, cfg.large_max, cfg.large_initial, now_ns);
        Self {
            cfg,
            clock,
            small,
            large,
        }
    }

    #[inline]
    fn lane(&self, lane: TransferLane) -> &Lane {
        match lane {
            TransferLane::SmallPipelined => &self.small,
            TransferLane::LargeStreaming => &self.large,
        }
    }

    pub fn classify(&self, file_size: u64) -> TransferLane {
        if file_size <= self.cfg.small_file_threshold_bytes {
            TransferLane::SmallPipelined
        } else {
            TransferLane::LargeStreaming
        }
    }

    pub fn concurrency(&self, lane: TransferLane) -> usize {
        self.lane(lane).current_c.load(Ordering::Acquire)
    }

    pub fn max_concurrency(&self, lane: TransferLane) -> usize {
        self.lane(lane).max_c
    }

    pub fn in_flight(&self, lane: TransferLane) -> usize {
        self.lane(lane).gate.in_flight()
    }

    /// Acquire a live concurrency permit for `lane`, dynamically adapting to updates.
    pub async fn acquire_permit(&self, lane: TransferLane) -> LanePermit {
        self.lane(lane).gate.acquire().await
    }

    /// Feed one completed telemetry window into the controller and immediately
    /// adjust the live gate concurrency for `lane`.
    pub fn observe_window(
        &self,
        lane: TransferLane,
        bytes_transferred: u64,
        elapsed_secs: f64,
        throttles: u32,
        errors: u32,
    ) -> usize {
        let l = self.lane(lane);
        let new_c = {
            let mut guard = l.state.lock().expect("falcon lane mutex poisoned");
            let new_c = guard.update(
                bytes_transferred,
                elapsed_secs,
                throttles,
                errors,
                self.cfg.utility_k,
                self.cfg.throttle_beta,
            );
            if throttles > 0 || errors > 0 {
                guard.last_cut_nanos = Some(self.clock.now_unix_nanos());
            }
            l.current_c.store(new_c, Ordering::Release);
            new_c
        };
        l.gate.set_limit(new_c);
        new_c
    }

    /// Record live streamed bytes on `lane` without waiting for a file to complete.
    ///
    /// Uses a lock-free atomic counter plus atomic window-timestamp gate so hot-path
    /// streaming chunks do not contend on a mutex; once `window_duration` elapses,
    /// flushes live bytes into the lane window and evaluates throughput probing.
    pub fn record_bytes(&self, lane: TransferLane, bytes: u64) {
        let l = self.lane(lane);
        if bytes > 0 {
            l.live_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        l.flush_live_bytes_if_due(&self.cfg, self.clock.as_ref());
    }

    /// Wrap a [`ByteStream`] so every streamed chunk feeds live bytes into Falcon on `lane`.
    pub fn track_stream(self: &Arc<Self>, lane: TransferLane, stream: ByteStream) -> ByteStream {
        Box::pin(FalconByteStream {
            inner: stream,
            controller: self.clone(),
            lane,
        })
    }

    /// Record a completed transfer (or transient/throttle error) on `lane`.
    /// Throttles/errors perform at most ONE multiplicative cut per `window_duration`;
    /// healthy transfers trigger gradient probing once `window_duration` elapses.
    pub fn record_transfer(
        &self,
        lane: TransferLane,
        bytes_transferred: u64,
        throttles: u32,
        errors: u32,
    ) -> usize {
        self.lane(lane).record_event(
            &self.cfg,
            self.clock.as_ref(),
            bytes_transferred,
            throttles,
            errors,
        )
    }

    /// Signal a `429`/`503` throttle event observed during a retry loop.
    pub fn record_throttle(&self, lane: TransferLane) -> usize {
        self.record_transfer(lane, 0, 1, 0)
    }
}

struct FalconByteStream {
    inner: ByteStream,
    controller: Arc<FalconController>,
    lane: TransferLane,
}

impl Stream for FalconByteStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if !chunk.is_empty() {
                    this.controller.record_bytes(this.lane, chunk.len() as u64);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_probes_upward_to_saturation_and_backs_off_on_throttle() {
        let ctrl = FalconController::new(FalconConfig::default());
        assert_eq!(ctrl.classify(16 * 1024), TransferLane::SmallPipelined);
        assert_eq!(
            ctrl.classify(10 * 1024 * 1024),
            TransferLane::LargeStreaming
        );

        // Simulated WAN link saturating around concurrency = 8 (10 MB/s per stream up to 80 MB/s).
        let mut c = ctrl.concurrency(TransferLane::LargeStreaming);
        assert_eq!(c, 4);
        for _ in 0..6 {
            let eff_throughput = (c.min(8) as u64) * 10 * 1024 * 1024;
            c = ctrl.observe_window(TransferLane::LargeStreaming, eff_throughput, 1.0, 0, 0);
        }
        assert!(
            (6..=12).contains(&c),
            "expected Falcon to probe upward near link knee (8), got {c}"
        );

        // Throttle spike triggers immediate multiplicative decrease!
        let before = c;
        let after = ctrl.observe_window(TransferLane::LargeStreaming, 1024 * 1024, 1.0, 2, 0);
        assert!(
            after < before,
            "expected backoff on throttle: {before} -> {after}"
        );
    }

    #[tokio::test]
    async fn lane_gate_enforces_dynamic_limit_and_releases_permits() {
        let cfg = FalconConfig {
            large_min: 1,
            large_max: 4,
            large_initial: 2,
            ..Default::default()
        };
        let ctrl = Arc::new(FalconController::new(cfg));
        let p1 = ctrl.acquire_permit(TransferLane::LargeStreaming).await;
        let p2 = ctrl.acquire_permit(TransferLane::LargeStreaming).await;
        assert_eq!(ctrl.in_flight(TransferLane::LargeStreaming), 2);

        // Third acquire blocks until either a permit drops or concurrency grows!
        let ctrl_c = ctrl.clone();
        let waiter = tokio::spawn(async move {
            let p3 = ctrl_c.acquire_permit(TransferLane::LargeStreaming).await;
            assert_eq!(ctrl_c.in_flight(TransferLane::LargeStreaming), 3);
            drop(p3);
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        // Probing upward unlocks the waiter immediately without dropping p1/p2!
        let grown = ctrl.observe_window(TransferLane::LargeStreaming, 10 * 1024 * 1024, 1.0, 0, 0);
        assert_eq!(grown, 3);
        waiter.await.unwrap();

        drop(p1);
        drop(p2);
        assert_eq!(ctrl.in_flight(TransferLane::LargeStreaming), 0);
    }

    #[test]
    fn simultaneous_throttles_within_window_cut_concurrency_only_once() {
        use crate::clock::VirtualClock;

        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg = FalconConfig {
            large_min: 1,
            large_max: 32,
            large_initial: 16,
            throttle_beta: 0.7,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        };
        let ctrl = FalconController::with_clock(cfg, clock.clone());
        assert_eq!(ctrl.concurrency(TransferLane::LargeStreaming), 16);

        // 8 concurrent workers/parts all report 429 within the same 1s window.
        let mut last_c = 16;
        for i in 0..8 {
            clock.advance(Duration::from_millis(50 * i));
            if i >= 4 {
                // Keep all 8 inside the 1s cooldown window from t=0.
                clock.set_unix_nanos(1_700_000_000_000_000_000 + 800_000_000);
            }
            last_c = ctrl.record_throttle(TransferLane::LargeStreaming);
        }
        // Expected: single multiplicative cut floor(16 * 0.7) == 11, NOT 8 cuts down to 1!
        assert_eq!(
            last_c, 11,
            "8 simultaneous 429 throttles in one window must cut concurrency ONCE (16 -> 11), got {last_c}"
        );

        // Once the full window_duration elapses after the cut, a NEW throttle cuts once more (11 -> 7).
        clock.set_unix_nanos(1_700_000_001_000_000_000);
        assert_eq!(ctrl.record_throttle(TransferLane::LargeStreaming), 7);
        // Further throttles inside the new 1s window stay at 7.
        for _ in 0..5 {
            assert_eq!(ctrl.record_throttle(TransferLane::LargeStreaming), 7);
        }

        // After cooldown expires with healthy traffic (no new throttles), suppressed throttles
        // must NOT trigger a phantom cut; Falcon probes upward cleanly (7 -> 8).
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            ctrl.record_transfer(TransferLane::LargeStreaming, 10 * 1024 * 1024, 0, 0),
            8
        );
    }

    #[test]
    fn live_record_bytes_advances_throughput_and_probes_upward_before_completion() {
        use crate::clock::VirtualClock;

        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let cfg = FalconConfig {
            large_min: 1,
            large_max: 16,
            large_initial: 4,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        };
        let ctrl = FalconController::with_clock(cfg, clock.clone());
        assert_eq!(ctrl.concurrency(TransferLane::LargeStreaming), 4);

        // Streaming chunks within the first window accumulate lock-freely without changing c yet.
        ctrl.record_bytes(TransferLane::LargeStreaming, 4 * 1024 * 1024);
        clock.advance(Duration::from_millis(500));
        ctrl.record_bytes(TransferLane::LargeStreaming, 4 * 1024 * 1024);
        assert_eq!(ctrl.concurrency(TransferLane::LargeStreaming), 4);

        // Once window_duration elapses, the next live chunk flushes and probes upward BEFORE file finishes!
        clock.advance(Duration::from_millis(500));
        ctrl.record_bytes(TransferLane::LargeStreaming, 4 * 1024 * 1024);
        assert_eq!(
            ctrl.concurrency(TransferLane::LargeStreaming),
            5,
            "expected live record_bytes() to probe concurrency upward (4 -> 5) mid-transfer"
        );

        // Second healthy window with higher throughput probes upward again (5 -> 6).
        clock.advance(Duration::from_secs(1));
        ctrl.record_bytes(TransferLane::LargeStreaming, 18 * 1024 * 1024);
        assert_eq!(ctrl.concurrency(TransferLane::LargeStreaming), 6);
    }
}
