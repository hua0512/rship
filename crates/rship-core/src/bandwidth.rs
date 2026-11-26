//! Smooth byte-level token-bucket bandwidth limiter (`--bwlimit`), supporting
//! both fixed byte rates (`"10M"`) and rclone-compatible time-of-day schedules
//! (`"08:00,10M 23:00,off"`).
//!
//! Shared across all concurrent transfer workers without holding mutexes across
//! sleeps and slices large `Bytes` buffers zero-copy (`Bytes::split_to`) so
//! bandwidth shaping remains smooth and immediately responsive to `SIGINT`.

use bytes::Bytes;
use futures::Stream;
use rship_core_local_imports::*;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

mod rship_core_local_imports {
    pub use crate::clock::{Clock, SystemClock, sleep_owned};
    pub use crate::engine::CancelFlag;
    pub use crate::error::{Error, Result};
    pub use crate::source::ByteStream;
}

const SLICE_STEP_BYTES: usize = 64 * 1024;
const SCHEDULE_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// One time-of-day rate slot (`HH:MM` -> optional bytes/sec; `None` = unlimited/`off`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthSlot {
    /// Minutes since local midnight (`0..1440`).
    pub minute_of_day: u16,
    /// Sustained byte rate ceiling (`None` = unlimited / `off`).
    pub bytes_per_sec: Option<u64>,
}

/// Time-of-day bandwidth schedule (`--bwlimit "08:00,10M 23:00,off"` or `"10M"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthSchedule {
    slots: Vec<BandwidthSlot>,
}

impl BandwidthSchedule {
    /// Construct a constant single-rate schedule (`bytes_per_sec` must be `> 0`).
    pub fn constant(bytes_per_sec: u64) -> Result<Self> {
        if bytes_per_sec == 0 {
            return Err(Error::invalid_geometry("bwlimit bytes_per_sec must be > 0"));
        }
        Ok(Self {
            slots: vec![BandwidthSlot {
                minute_of_day: 0,
                bytes_per_sec: Some(bytes_per_sec),
            }],
        })
    }

    /// Parse either a single rate (`"10M"`, `"500K"`, `"off"`, `"0"`) or a
    /// space-separated rclone timetable (`"08:00,10M 23:00,off"`).
    ///
    /// Returns `Ok(None)` when the entire schedule is unconditionally unlimited (`"off"` / `"0"`).
    pub fn parse(raw: &str) -> Result<Option<Self>> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::config("empty --bwlimit value"));
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() == 1 && !tokens[0].contains(',') {
            let rate = parse_rate_token(tokens[0])?;
            return Ok(rate.map(|r| Self {
                slots: vec![BandwidthSlot {
                    minute_of_day: 0,
                    bytes_per_sec: Some(r),
                }],
            }));
        }

        let mut slots = Vec::with_capacity(tokens.len());
        for tok in tokens {
            let Some((time_str, rate_str)) = tok.split_once(',') else {
                return Err(Error::config(format!(
                    "invalid --bwlimit schedule entry `{tok}` (expected `HH:MM,RATE`, e.g. `08:00,10M 23:00,off`)"
                )));
            };
            let minute_of_day = parse_hhmm(time_str)?;
            let bytes_per_sec = parse_rate_token(rate_str)?;
            slots.push(BandwidthSlot {
                minute_of_day,
                bytes_per_sec,
            });
        }
        if slots.is_empty() {
            return Ok(None);
        }
        slots.sort_by_key(|s| s.minute_of_day);
        // Deduplicate identical minute entries (last wins) so binary lookup is deterministic.
        let mut deduped: Vec<BandwidthSlot> = Vec::with_capacity(slots.len());
        for slot in slots {
            if let Some(last) = deduped.last_mut()
                && last.minute_of_day == slot.minute_of_day
            {
                *last = slot;
            } else {
                deduped.push(slot);
            }
        }
        if deduped.iter().all(|s| s.bytes_per_sec.is_none()) {
            return Ok(None);
        }
        Ok(Some(Self { slots: deduped }))
    }

    pub fn slots(&self) -> &[BandwidthSlot] {
        &self.slots
    }

    /// Look up the active byte rate at `minute_of_day` (`0..1440`), wrapping around
    /// midnight to the last slot of the previous day when `minute_of_day` precedes the
    /// earliest entry.
    pub fn rate_at_minute(&self, minute_of_day: u16) -> Option<u64> {
        let mut chosen: Option<&BandwidthSlot> = None;
        for slot in &self.slots {
            if slot.minute_of_day <= minute_of_day {
                chosen = Some(slot);
            } else {
                break;
            }
        }
        chosen
            .or_else(|| self.slots.last())
            .and_then(|s| s.bytes_per_sec)
    }

    fn current_local_rate(&self) -> Option<u64> {
        let minute = crate::time::local_minute_of_day();
        self.rate_at_minute(minute)
    }
}

fn parse_hhmm(raw: &str) -> Result<u16> {
    let s = raw.trim();
    let Some((h_s, m_s)) = s.split_once(':') else {
        return Err(Error::config(format!(
            "invalid schedule time `{raw}` (expected HH:MM)"
        )));
    };
    let h: u16 = h_s
        .parse()
        .map_err(|_| Error::config(format!("invalid schedule hour in `{raw}`")))?;
    let m: u16 = m_s
        .parse()
        .map_err(|_| Error::config(format!("invalid schedule minute in `{raw}`")))?;
    if h >= 24 || m >= 60 {
        return Err(Error::config(format!(
            "schedule time `{raw}` out of range (expected 00:00..23:59)"
        )));
    }
    Ok(h * 60 + m)
}

fn parse_rate_token(raw: &str) -> Result<Option<u64>> {
    let s = raw.trim();
    if s.eq_ignore_ascii_case("off") || s == "0" {
        return Ok(None);
    }
    let split_idx = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let num_str = &s[..split_idx];
    let unit = s[split_idx..].trim().to_ascii_lowercase();
    let num: u64 = num_str
        .parse()
        .map_err(|_| Error::config(format!("invalid --bwlimit rate `{raw}`")))?;
    if num == 0 {
        return Ok(None);
    }
    let mult: u64 = match unit.as_str() {
        "" | "b" | "b/s" => 1,
        "k" | "kb" | "kib" | "k/s" | "kb/s" | "kib/s" => 1024,
        "m" | "mb" | "mib" | "m/s" | "mb/s" | "mib/s" => 1024 * 1024,
        "g" | "gb" | "gib" | "g/s" | "gb/s" | "gib/s" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" | "t/s" | "tb/s" | "tib/s" => 1024u64 * 1024 * 1024 * 1024,
        _ => {
            return Err(Error::config(format!(
                "unknown --bwlimit unit `{unit}` in `{raw}` (expected K, M, G, T, or off)"
            )));
        }
    };
    let bytes = num
        .checked_mul(mult)
        .ok_or_else(|| Error::config(format!("--bwlimit rate `{raw}` overflows u64")))?;
    Ok(Some(bytes))
}

fn burst_for_rate(rate: f64) -> f64 {
    // Keep burst bounded to ~250ms of traffic (clamped to [16 KiB, 1 MiB]) for smooth pacing.
    (rate * 0.25)
        .clamp(16.0 * 1024.0, 1024.0 * 1024.0)
        .min(rate.max(4096.0))
}

#[derive(Debug, Clone, Copy)]
enum PaceInstant {
    Monotonic(Instant),
    VirtualNanos(i64),
}

impl PaceInstant {
    fn now(clock: &dyn Clock) -> Self {
        if clock.is_instant_sleep() {
            Self::VirtualNanos(clock.now_unix_nanos())
        } else {
            Self::Monotonic(Instant::now())
        }
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        match (self, earlier) {
            (Self::Monotonic(a), Self::Monotonic(b)) => a.saturating_duration_since(b),
            (Self::VirtualNanos(a), Self::VirtualNanos(b)) => {
                let delta = a.saturating_sub(b).max(0) as u64;
                Duration::from_nanos(delta)
            }
            _ => Duration::ZERO,
        }
    }
}

#[derive(Debug)]
struct BucketState {
    rate_bps: Option<f64>,
    burst_bytes: f64,
    tokens: f64,
    last_refill: PaceInstant,
    last_schedule_check: PaceInstant,
}

/// Thread-safe token-bucket byte rate limiter (`bytes/sec`) with optional time-of-day schedule.
#[derive(Debug)]
pub struct BandwidthLimiter {
    schedule: Option<BandwidthSchedule>,
    clock: Arc<dyn Clock>,
    state: Mutex<BucketState>,
}

impl BandwidthLimiter {
    pub fn new(bytes_per_sec: u64) -> Result<Arc<Self>> {
        Self::new_with_clock(bytes_per_sec, SystemClock::shared())
    }

    pub fn new_with_clock(bytes_per_sec: u64, clock: Arc<dyn Clock>) -> Result<Arc<Self>> {
        if bytes_per_sec == 0 {
            return Err(Error::invalid_geometry("bwlimit bytes_per_sec must be > 0"));
        }
        let rate = bytes_per_sec as f64;
        let burst = burst_for_rate(rate);
        let now = PaceInstant::now(clock.as_ref());
        Ok(Arc::new(Self {
            schedule: None,
            clock,
            state: Mutex::new(BucketState {
                rate_bps: Some(rate),
                burst_bytes: burst,
                tokens: burst,
                last_refill: now,
                last_schedule_check: now,
            }),
        }))
    }

    pub fn from_schedule(schedule: BandwidthSchedule) -> Result<Arc<Self>> {
        Self::from_schedule_with_clock(schedule, SystemClock::shared())
    }

    pub fn from_schedule_with_clock(
        schedule: BandwidthSchedule,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>> {
        if schedule.slots.len() == 1
            && let Some(fixed) = schedule.slots[0].bytes_per_sec
        {
            return Self::new_with_clock(fixed, clock);
        }
        let initial_rate = schedule.current_local_rate().map(|r| r as f64);
        let burst = initial_rate.map(burst_for_rate).unwrap_or(0.0);
        let now = PaceInstant::now(clock.as_ref());
        Ok(Arc::new(Self {
            schedule: Some(schedule),
            clock,
            state: Mutex::new(BucketState {
                rate_bps: initial_rate,
                burst_bytes: burst,
                tokens: burst,
                last_refill: now,
                last_schedule_check: now,
            }),
        }))
    }

    pub fn rate_bytes_per_sec(&self) -> u64 {
        let g = self.state.lock().expect("bwlimit mutex poisoned");
        g.rate_bps.unwrap_or(0.0) as u64
    }

    /// Reserve `bytes` from the shared bucket and return how long the caller must wait.
    pub fn reserve(&self, bytes: usize) -> Duration {
        if bytes == 0 {
            return Duration::ZERO;
        }
        let now = PaceInstant::now(self.clock.as_ref());
        let mut g = self.state.lock().expect("bwlimit mutex poisoned");
        if let Some(ref sched) = self.schedule
            && now.saturating_duration_since(g.last_schedule_check) >= SCHEDULE_RECHECK_INTERVAL
        {
            g.last_schedule_check = now;
            let new_rate = sched.current_local_rate().map(|r| r as f64);
            if new_rate != g.rate_bps {
                g.rate_bps = new_rate;
                g.burst_bytes = new_rate.map(burst_for_rate).unwrap_or(0.0);
                g.tokens = g.tokens.min(g.burst_bytes).max(0.0);
                g.last_refill = now;
            }
        }

        let Some(rate_bps) = g.rate_bps else {
            g.last_refill = now;
            return Duration::ZERO;
        };

        let elapsed = now.saturating_duration_since(g.last_refill).as_secs_f64();
        g.tokens = (g.tokens + elapsed * rate_bps).min(g.burst_bytes);
        g.last_refill = now;

        let need = bytes as f64;
        if g.tokens >= need {
            g.tokens -= need;
            Duration::ZERO
        } else {
            let deficit = need - g.tokens;
            g.tokens -= need; // reserve ahead so concurrent workers serialize cleanly
            Duration::from_secs_f64((deficit / rate_bps).max(0.0))
        }
    }

    /// Wrap any `ByteStream` with smooth zero-copy byte pacing and `SIGINT` awareness.
    pub fn wrap_stream(self: &Arc<Self>, stream: ByteStream, cancel: CancelFlag) -> ByteStream {
        let cancel_fut = Box::pin(cancel.cancelled_owned());
        Box::pin(ThrottledByteStream {
            inner: stream,
            limiter: self.clone(),
            cancel,
            cancel_fut,
            pending: None,
            sleep: None,
            done: false,
        })
    }
}

struct ThrottledByteStream {
    inner: ByteStream,
    limiter: Arc<BandwidthLimiter>,
    cancel: CancelFlag,
    cancel_fut: Pin<Box<dyn Future<Output = ()> + Send>>,
    pending: Option<Bytes>,
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    done: bool,
}

impl Stream for ThrottledByteStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if this.cancel.is_cancelled() || this.cancel_fut.as_mut().poll(cx).is_ready() {
            this.done = true;
            return Poll::Ready(Some(Err(Error::cancelled(
                "transfer cancelled during bwlimit",
            ))));
        }

        loop {
            // Wait out any active pacing sleep first.
            if let Some(sleep) = this.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {
                        this.sleep = None;
                    }
                }
            }

            // If we have a queued piece ready after sleeping, emit it!
            if let Some(mut buf) = this.pending.take() {
                if buf.len() <= SLICE_STEP_BYTES {
                    return Poll::Ready(Some(Ok(buf)));
                }
                let piece = buf.split_to(SLICE_STEP_BYTES);
                let wait = this.limiter.reserve(buf.len().min(SLICE_STEP_BYTES));
                if !wait.is_zero() {
                    this.sleep = Some(sleep_owned(this.limiter.clock.clone(), wait));
                }
                this.pending = Some(buf);
                return Poll::Ready(Some(Ok(piece)));
            }

            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        return Poll::Ready(Some(Ok(chunk)));
                    }
                    let emit_len = chunk.len().min(SLICE_STEP_BYTES);
                    let wait = this.limiter.reserve(emit_len);
                    this.pending = Some(chunk);
                    if !wait.is_zero() {
                        this.sleep = Some(sleep_owned(this.limiter.clock.clone(), wait));
                    }
                    // Loop back so any newly created sleep is polled properly (never returning
                    // `Poll::Pending` if the timer already fired) and `pending` is emitted once ready.
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test(start_paused = true)]
    async fn bandwidth_limiter_shapes_sustained_stream_rate_accurately() {
        // 100 KiB/s cap, stream 300 KiB -> burst ~25 KiB, remaining ~275 KiB takes ~2.75s!
        let lim = BandwidthLimiter::new(100 * 1024).unwrap();
        let data = Bytes::from(vec![0xAAu8; 300 * 1024]);
        let raw: ByteStream = Box::pin(futures::stream::once(async move { Ok(data) }));
        let mut throttled = lim.wrap_stream(raw, CancelFlag::new());

        let t0 = Instant::now();
        let mut total = 0usize;
        while let Some(item) = throttled.next().await {
            total += item.unwrap().len();
        }
        assert_eq!(total, 300 * 1024);
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(2400) && elapsed <= Duration::from_millis(3200),
            "expected ~2.75s paced transfer, got {elapsed:?}"
        );
    }

    #[test]
    fn bandwidth_schedule_parses_single_rates_and_wraparound_timetables() {
        assert!(BandwidthSchedule::parse("off").unwrap().is_none());
        assert!(BandwidthSchedule::parse("0").unwrap().is_none());

        let single = BandwidthSchedule::parse("10M").unwrap().unwrap();
        assert_eq!(single.rate_at_minute(0), Some(10 * 1024 * 1024));
        assert_eq!(single.rate_at_minute(12 * 60), Some(10 * 1024 * 1024));

        // Wrap-around schedule: 08:00 -> 10M, 23:00 -> off (unlimited overnight 23:00..07:59!)
        let sched = BandwidthSchedule::parse("08:00,10M 23:00,off")
            .unwrap()
            .unwrap();
        assert_eq!(sched.rate_at_minute(0), None); // 00:00 wraps to 23:00 -> off
        assert_eq!(sched.rate_at_minute(7 * 60 + 59), None); // 07:59 -> off
        assert_eq!(sched.rate_at_minute(8 * 60), Some(10 * 1024 * 1024)); // 08:00 -> 10M
        assert_eq!(sched.rate_at_minute(15 * 60 + 30), Some(10 * 1024 * 1024));
        assert_eq!(sched.rate_at_minute(22 * 60 + 59), Some(10 * 1024 * 1024));
        assert_eq!(sched.rate_at_minute(23 * 60), None); // 23:00 -> off

        assert!(BandwidthSchedule::parse("25:00,10M").is_err());
        assert!(BandwidthSchedule::parse("08:00").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_stream_wakes_immediately_on_cancel_during_sleep() {
        let lim = BandwidthLimiter::new(1024).unwrap();
        let data = Bytes::from(vec![0xBBu8; 256 * 1024]);
        let raw: ByteStream = Box::pin(futures::stream::once(async move { Ok(data) }));
        let cancel = CancelFlag::new();
        let mut throttled = lim.wrap_stream(raw, cancel.clone());

        // First piece emits immediately (burst); subsequent pieces require multi-second sleep.
        let _ = throttled.next().await.unwrap().unwrap();
        let cancel_bg = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_bg.cancel();
        });

        let t0 = Instant::now();
        let err = loop {
            match throttled.next().await {
                Some(Ok(_)) => continue,
                Some(Err(e)) => break e,
                None => panic!("expected cancellation error before stream finished"),
            }
        };
        assert!(err.is_cancelled(), "expected Cancelled error, got {err:?}");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "cancellation should wake pacing sleep immediately, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn bandwidth_limiter_with_virtual_clock_instant_sleep_advances_deterministically() {
        use crate::clock::VirtualClock;

        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let lim = BandwidthLimiter::new_with_clock(100 * 1024, clock.clone()).unwrap();
        let data = Bytes::from(vec![0xCCu8; 300 * 1024]);
        let raw: ByteStream = Box::pin(futures::stream::once(async move { Ok(data) }));
        let mut throttled = lim.wrap_stream(raw, CancelFlag::new());

        let wall_start = std::time::Instant::now();
        let start_ns = clock.now_unix_nanos();
        let mut total = 0usize;
        while let Some(item) = throttled.next().await {
            total += item.unwrap().len();
        }
        assert_eq!(total, 300 * 1024);
        let virtual_elapsed = Duration::from_nanos((clock.now_unix_nanos() - start_ns) as u64);
        assert!(
            virtual_elapsed >= Duration::from_millis(2400)
                && virtual_elapsed <= Duration::from_millis(3200),
            "expected ~2.75s virtual paced time, got {virtual_elapsed:?}"
        );
        assert!(
            wall_start.elapsed() < Duration::from_secs(1),
            "virtual instant-sleep bwlimit must not stall on wall time"
        );
    }
}
