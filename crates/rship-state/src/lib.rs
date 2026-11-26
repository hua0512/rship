//! Bundled SQLite durable state store (`StateActor`), ephemeral per-run
//! disk-backed sorted-merge `SqliteSyncIndex`, stale-run sweeper, and
//! cross-platform exclusive process lock.

#![forbid(unsafe_code)]

pub mod actor;
pub mod lock;
pub(crate) mod schema;
pub mod sync_index;

pub use actor::StateActor;
pub use lock::{ProcessLock, sweep_stale_locks};
pub use sync_index::{
    AdaptiveHybridDiffIndex, DEFAULT_RAM_SPILL_THRESHOLD, LazyRunDir, SqliteSyncIndex,
    sweep_stale_runs, sweep_stale_runs_with_min_age,
};
