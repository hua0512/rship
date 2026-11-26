//! Multi-account quota & throttle failover pool for Rust embedders and multi-account
//! upload pipelines (e.g. rotating across Google Drive accounts on 750 GiB/day
//! `ErrorKind::QuotaExceeded` or heavy `ErrorKind::RateLimited` bursts).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::backend::StorageBackend;
use crate::clock::{Clock, SystemClock};
use crate::error::{Error, ErrorKind, Result, RetryClass};

/// Default cooldown applied when an account hits daily upload quota (24 hours).
pub const DEFAULT_QUOTA_COOLDOWN: Duration = Duration::from_secs(24 * 3600);

/// Default short cooldown applied when an account is heavily rate-limited (30 seconds).
pub const DEFAULT_THROTTLE_COOLDOWN: Duration = Duration::from_secs(30);

struct AccountSlot {
    name: String,
    backend: Arc<dyn StorageBackend>,
    in_flight: AtomicUsize,
    cooldown_until_unix_secs: Mutex<Option<i64>>,
    quota_exhaustions: AtomicU64,
    throttle_events: AtomicU64,
}

/// Point-in-time health snapshot of one account in a [`FailoverPool`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccountStatus {
    pub name: String,
    pub available: bool,
    pub in_flight: usize,
    pub cooldown_until_unix_secs: Option<i64>,
    pub quota_exhaustions: u64,
    pub throttle_events: u64,
}

/// RAII lease returned by [`FailoverPool::acquire`]. Automatically releases the
/// account's `in_flight` counter on drop.
#[must_use]
pub struct AccountLease {
    pool: FailoverPool,
    idx: usize,
}

impl fmt::Debug for AccountLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountLease")
            .field("account", &self.name())
            .finish()
    }
}

impl AccountLease {
    pub fn name(&self) -> &str {
        &self.pool.inner.slots[self.idx].name
    }

    pub fn backend(&self) -> Arc<dyn StorageBackend> {
        self.pool.inner.slots[self.idx].backend.clone()
    }

    /// Mark this leased account as quota-exhausted (e.g. GDrive 750 GiB/day cap).
    pub fn mark_quota_exceeded(&self, cooldown: Duration) {
        self.pool.mark_quota_exceeded(self.name(), cooldown);
    }

    /// Mark this leased account as temporarily throttled.
    pub fn mark_throttled(&self, cooldown: Duration) {
        self.pool.mark_throttled(self.name(), cooldown);
    }
}

impl Drop for AccountLease {
    fn drop(&mut self) {
        self.pool.inner.slots[self.idx]
            .in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct FailoverPoolInner {
    slots: Vec<AccountSlot>,
    cursor: AtomicUsize,
    clock: Arc<dyn Clock>,
}

/// Thread-safe, least-loaded round-robin pool of storage accounts with automatic
/// cooldown & failover on `ErrorKind::QuotaExceeded` / `ErrorKind::RateLimited`.
#[derive(Clone)]
pub struct FailoverPool {
    inner: Arc<FailoverPoolInner>,
}

impl fmt::Debug for FailoverPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.inner.slots.iter().map(|s| s.name.as_str()).collect();
        f.debug_struct("FailoverPool")
            .field("accounts", &names)
            .finish()
    }
}

impl FailoverPool {
    pub fn new(accounts: Vec<(String, Arc<dyn StorageBackend>)>) -> Result<Self> {
        Self::with_clock(accounts, SystemClock::shared())
    }

    pub fn with_clock(
        accounts: Vec<(String, Arc<dyn StorageBackend>)>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        if accounts.is_empty() {
            return Err(Error::invalid_geometry(
                "FailoverPool requires at least one backend account",
            ));
        }
        let slots = accounts
            .into_iter()
            .map(|(name, backend)| AccountSlot {
                name,
                backend,
                in_flight: AtomicUsize::new(0),
                cooldown_until_unix_secs: Mutex::new(None),
                quota_exhaustions: AtomicU64::new(0),
                throttle_events: AtomicU64::new(0),
            })
            .collect();
        Ok(Self {
            inner: Arc::new(FailoverPoolInner {
                slots,
                cursor: AtomicUsize::new(0),
                clock,
            }),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.slots.is_empty()
    }

    /// Acquire the healthiest available account (fewest `in_flight` operations,
    /// round-robin tie-break), skipping accounts currently in cooldown.
    pub fn acquire(&self) -> Result<AccountLease> {
        self.acquire_excluding(&[])
    }

    /// Acquire the healthiest available account while excluding specific account names
    /// already attempted in the current failover loop.
    pub fn acquire_excluding(&self, excluded: &[String]) -> Result<AccountLease> {
        let now = self.inner.clock.now_unix_secs();
        let n = self.inner.slots.len();
        let start = self.inner.cursor.fetch_add(1, Ordering::Relaxed) % n;

        let mut best: Option<(usize, usize)> = None; // (slot_idx, in_flight)
        for step in 0..n {
            let idx = (start + step) % n;
            let slot = &self.inner.slots[idx];
            if excluded.iter().any(|e| e == &slot.name) {
                continue;
            }
            let available = {
                let mut guard = slot
                    .cooldown_until_unix_secs
                    .lock()
                    .expect("cooldown mutex poisoned");
                match *guard {
                    Some(until) if now < until => false,
                    Some(_) => {
                        *guard = None;
                        true
                    }
                    None => true,
                }
            };
            if !available {
                continue;
            }
            let load = slot.in_flight.load(Ordering::Relaxed);
            if best.is_none_or(|(_, best_load)| load < best_load) {
                best = Some((idx, load));
            }
        }

        let Some((idx, _)) = best else {
            return Err(Error::new(
                ErrorKind::QuotaExceeded,
                RetryClass::Permanent,
                "all accounts in failover pool are currently exhausted or cooling down",
            ));
        };

        self.inner.slots[idx]
            .in_flight
            .fetch_add(1, Ordering::Relaxed);
        Ok(AccountLease {
            pool: self.clone(),
            idx,
        })
    }

    /// Put `account_name` into quota-exhausted cooldown for `cooldown`.
    pub fn mark_quota_exceeded(&self, account_name: &str, cooldown: Duration) {
        let until = self
            .inner
            .clock
            .now_unix_secs()
            .saturating_add(cooldown.as_secs().min(i64::MAX as u64) as i64);
        if let Some(slot) = self.inner.slots.iter().find(|s| s.name == account_name) {
            slot.quota_exhaustions.fetch_add(1, Ordering::Relaxed);
            let mut guard = slot
                .cooldown_until_unix_secs
                .lock()
                .expect("cooldown mutex poisoned");
            *guard = Some(guard.map_or(until, |prev| prev.max(until)));
        }
    }

    /// Put `account_name` into short throttle cooldown for `cooldown`.
    pub fn mark_throttled(&self, account_name: &str, cooldown: Duration) {
        let until = self
            .inner
            .clock
            .now_unix_secs()
            .saturating_add(cooldown.as_secs().min(i64::MAX as u64) as i64);
        if let Some(slot) = self.inner.slots.iter().find(|s| s.name == account_name) {
            slot.throttle_events.fetch_add(1, Ordering::Relaxed);
            let mut guard = slot
                .cooldown_until_unix_secs
                .lock()
                .expect("cooldown mutex poisoned");
            *guard = Some(guard.map_or(until, |prev| prev.max(until)));
        }
    }

    /// Immediately clear any cooldown on `account_name`.
    pub fn reset_account(&self, account_name: &str) {
        if let Some(slot) = self.inner.slots.iter().find(|s| s.name == account_name) {
            *slot
                .cooldown_until_unix_secs
                .lock()
                .expect("cooldown mutex poisoned") = None;
        }
    }

    /// Snapshot current health and load of every account in the pool.
    pub fn statuses(&self) -> Vec<AccountStatus> {
        let now = self.inner.clock.now_unix_secs();
        self.inner
            .slots
            .iter()
            .map(|slot| {
                let until = *slot
                    .cooldown_until_unix_secs
                    .lock()
                    .expect("cooldown mutex poisoned");
                let active_until = until.filter(|&u| now < u);
                AccountStatus {
                    name: slot.name.clone(),
                    available: active_until.is_none(),
                    in_flight: slot.in_flight.load(Ordering::Relaxed),
                    cooldown_until_unix_secs: active_until,
                    quota_exhaustions: slot.quota_exhaustions.load(Ordering::Relaxed),
                    throttle_events: slot.throttle_events.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Execute `op` across healthy accounts in the pool, automatically failing over
    /// to another healthy account whenever `op` fails with `ErrorKind::QuotaExceeded`
    /// or `ErrorKind::RateLimited`.
    pub async fn run_with_failover<T, F, Fut>(
        &self,
        quota_cooldown: Duration,
        throttle_cooldown: Duration,
        mut op: F,
    ) -> Result<(String, T)>
    where
        F: FnMut(String, Arc<dyn StorageBackend>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut tried: Vec<String> = Vec::with_capacity(self.len());
        let mut last_err: Option<Error> = None;

        while tried.len() < self.len() {
            let lease = match self.acquire_excluding(&tried) {
                Ok(l) => l,
                Err(pool_err) => return Err(last_err.unwrap_or(pool_err)),
            };
            let acct_name = lease.name().to_string();
            let backend = lease.backend();

            match op(acct_name.clone(), backend).await {
                Ok(val) => return Ok((acct_name, val)),
                Err(e) if e.kind == ErrorKind::QuotaExceeded => {
                    lease.mark_quota_exceeded(quota_cooldown);
                    tried.push(acct_name);
                    last_err = Some(e);
                }
                Err(e) if e.kind == ErrorKind::RateLimited => {
                    lease.mark_throttled(throttle_cooldown);
                    tried.push(acct_name);
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::new(
                ErrorKind::QuotaExceeded,
                RetryClass::Permanent,
                "all accounts in failover pool failed",
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaos::ChaosBackend;
    use crate::clock::VirtualClock;

    fn dummy_accounts(n: usize) -> Vec<(String, Arc<dyn StorageBackend>)> {
        (1..=n)
            .map(|i| {
                let name = format!("gdrive{}", i + 1);
                let b: Arc<dyn StorageBackend> =
                    Arc::new(ChaosBackend::sequential_gdrive_like(&name, 256 * 1024));
                (name, b)
            })
            .collect()
    }

    #[tokio::test]
    async fn failover_pool_rotates_on_quota_exhaustion_and_recovers_after_cooldown() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let pool = FailoverPool::with_clock(dummy_accounts(3), clock.clone()).unwrap();

        // Simulate gdrive2 hitting 750 GiB/day quota -> automatic failover to gdrive3!
        let (winner, val) = pool
            .run_with_failover(
                DEFAULT_QUOTA_COOLDOWN,
                DEFAULT_THROTTLE_COOLDOWN,
                |acct, _backend| async move {
                    if acct == "gdrive2" {
                        Err(Error::new(
                            ErrorKind::QuotaExceeded,
                            RetryClass::Permanent,
                            "750 GiB daily upload limit reached",
                        ))
                    } else {
                        Ok(format!("uploaded via {acct}"))
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(winner, "gdrive3");
        assert_eq!(val, "uploaded via gdrive3");

        let statuses = pool.statuses();
        assert!(!statuses[0].available);
        assert_eq!(statuses[0].quota_exhaustions, 1);
        assert!(statuses[1].available);
        assert!(statuses[2].available);

        // Exhaust remaining two accounts -> pool returns QuotaExceeded cleanly.
        pool.mark_quota_exceeded("gdrive3", DEFAULT_QUOTA_COOLDOWN);
        pool.mark_quota_exceeded("gdrive4", DEFAULT_QUOTA_COOLDOWN);
        let err = pool.acquire().expect_err("all accounts exhausted");
        assert_eq!(err.kind, ErrorKind::QuotaExceeded);

        // Advance clock past 24h cooldown -> accounts become healthy again!
        clock.advance(Duration::from_secs(24 * 3600 + 1));
        let lease = pool.acquire().unwrap();
        assert!(pool.statuses().iter().all(|s| s.available));
        drop(lease);
    }

    #[test]
    fn failover_pool_prefers_least_loaded_account() {
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let pool = FailoverPool::with_clock(dummy_accounts(3), clock).unwrap();

        let l1 = pool.acquire().unwrap();
        let l2 = pool.acquire().unwrap();
        let l3 = pool.acquire().unwrap();
        assert_ne!(l1.name(), l2.name());
        assert_ne!(l2.name(), l3.name());
        assert_ne!(l1.name(), l3.name());
        drop(l2);
        // After dropping l2, next acquire MUST pick l2's account (in_flight == 0).
        let l4 = pool.acquire().unwrap();
        assert_eq!(l4.name(), "gdrive3");
    }
}
