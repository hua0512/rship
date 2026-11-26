//! Core domain types, memory-bounded streaming primitives, write-ahead
//! resumable transfer engine, deterministic planner, and backend contracts
//! for `rship`.
//!
//! `rship-core` is intentionally free of SQLite and HTTP/socket dependencies
//! so the entire planner and transfer state machine remain fast to compile and
//! deterministically testable.

#![forbid(unsafe_code)]

pub mod adaptive;
pub mod backend;
pub mod bandwidth;
pub mod bisync;
pub mod buffer;
pub mod chunking;
pub mod clock;
pub mod crc32c;
pub mod encoding;
pub mod engine;
pub mod error;
pub mod failover;
pub mod filter;
pub mod memory;
pub mod path;
pub mod planner;
pub mod progress;
pub mod rclone_ini;
pub mod source;
pub mod state;
pub mod time;
pub mod types;

#[cfg(any(test, feature = "test-utils"))]
pub mod chaos;
#[cfg(any(test, feature = "test-utils"))]
pub mod conformance;

pub use engine::{RetryQuota, TokenBucketRetryQuota};
pub use error::{Error, ErrorCategory, ErrorKind, Result, RetryClass};
pub use types::FsyncMode;
