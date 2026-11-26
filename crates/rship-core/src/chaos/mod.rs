//! Deterministic Simulation Testing (DST) harness:
//! - `ChaosBackend`: in-memory `StorageBackend` supporting both Sequential
//!   (GDrive-like) and ParallelParts (S3-like) topologies with fault injection
//!   (429, mid-chunk disconnects, expired sessions, ambiguous final commits,
//!   partial listing errors, duplicate names, and live source mutations).
//! - `InMemoryJournal` & `InMemorySyncIndex`: pure-Rust test stores so `rship-core`
//!   exercises the full write-ahead recovery engine without touching disk.

mod backend;
mod crash_sweep;
mod failpoint;
mod faults;

pub use backend::ChaosBackend;
pub use crash_sweep::{
    CrashJournalHarness, CrashSweepScenario, InMemoryJournalHarness, run_crash_sweep,
    standard_crash_sweep_scenarios,
};
pub use failpoint::{FailingJournalStore, FailpointCoordinator, JournalBoundary, JournalFault};
pub use faults::{ChaosOp, FaultSchedule, InjectedFault, RandomFaultProfile, RandomFaultState};

// -----------------------------------------------------------------------------
// In-memory JournalStore & SyncDiffIndex aliases for pure `rship-core` DST tests
// -----------------------------------------------------------------------------

/// In-memory [`crate::state::JournalStore`] alias backed by [`crate::state::MemoryJournalStore`].
pub type InMemoryJournal = crate::state::MemoryJournalStore;

/// In-memory [`crate::state::SyncDiffIndex`] alias backed by [`crate::state::MemorySyncIndex`].
pub type InMemorySyncIndex = crate::state::MemorySyncIndex;

#[cfg(test)]
mod tests;
