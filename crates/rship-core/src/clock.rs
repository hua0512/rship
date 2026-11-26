use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Injectable clock enabling deterministic simulation testing (DST).
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now_unix_nanos(&self) -> i64;

    fn now_unix_secs(&self) -> i64 {
        self.now_unix_nanos().div_euclid(1_000_000_000)
    }

    fn now_system_time(&self) -> SystemTime {
        let ns = self.now_unix_nanos();
        if ns >= 0 {
            UNIX_EPOCH + Duration::from_nanos(ns as u64)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_nanos(ns.unsigned_abs()))
                .unwrap_or(UNIX_EPOCH)
        }
    }

    /// Sleep for `duration`, injectable for deterministic simulation tests.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    /// Returns `true` if [`Clock::sleep`] completes immediately by advancing virtual
    /// time instead of waiting on wall-clock timers.
    fn is_instant_sleep(&self) -> bool {
        false
    }
}

/// Owned `'static` wrapper around [`Clock::sleep`] for stream/future combinators
/// that must store an active sleep future without borrowing `&dyn Clock`.
pub fn sleep_owned(
    clock: Arc<dyn Clock>,
    duration: Duration,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    Box::pin(async move {
        clock.sleep(duration).await;
    })
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    pub fn shared() -> Arc<dyn Clock> {
        Arc::new(Self)
    }
}

impl Clock for SystemClock {
    fn now_unix_nanos(&self) -> i64 {
        system_time_to_unix_nanos(SystemTime::now())
    }
}

/// Deterministic controllable clock for DST and unit tests.
#[derive(Debug)]
pub struct VirtualClock {
    nanos: AtomicI64,
    instant_sleep: bool,
}

impl VirtualClock {
    pub fn new(initial_unix_secs: i64) -> Self {
        Self {
            nanos: AtomicI64::new(initial_unix_secs.saturating_mul(1_000_000_000)),
            instant_sleep: false,
        }
    }

    /// Create a deterministic clock whose [`Clock::sleep`] immediately advances
    /// virtual time by `duration` and yields once instead of waiting on wall time.
    pub fn new_instant_sleep(initial_unix_secs: i64) -> Self {
        Self::new(initial_unix_secs).with_instant_sleep()
    }

    /// Configure [`Clock::sleep`] to immediately advance virtual time by `duration`
    /// and yield once instead of waiting on wall-clock timers.
    pub fn with_instant_sleep(mut self) -> Self {
        self.instant_sleep = true;
        self
    }

    pub fn advance(&self, delta: Duration) {
        let add = i64::try_from(delta.as_nanos()).unwrap_or(i64::MAX);
        let _ = self
            .nanos
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                Some(cur.saturating_add(add))
            });
    }

    pub fn set_unix_nanos(&self, nanos: i64) {
        self.nanos.store(nanos, Ordering::SeqCst);
    }
}

impl Clock for VirtualClock {
    fn now_unix_nanos(&self) -> i64 {
        self.nanos.load(Ordering::SeqCst)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        if self.instant_sleep {
            Box::pin(async move {
                self.advance(duration);
                tokio::task::yield_now().await;
            })
        } else {
            Box::pin(tokio::time::sleep(duration))
        }
    }

    fn is_instant_sleep(&self) -> bool {
        self.instant_sleep
    }
}

pub fn system_time_to_unix_nanos(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => {
            let neg = i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX);
            -neg
        }
    }
}

pub fn unix_nanos_to_system_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_nanos(ns.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn virtual_clock_instant_sleep_advances_time_without_wall_stall() {
        let clock = VirtualClock::new_instant_sleep(1_700_000_000);
        let wall_start = std::time::Instant::now();
        clock.sleep(Duration::from_secs(3600)).await;
        assert_eq!(clock.now_unix_secs(), 1_700_003_600);
        assert!(
            wall_start.elapsed() < Duration::from_secs(2),
            "instant sleep must not stall on wall time"
        );
    }
}
