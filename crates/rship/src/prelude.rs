//! Curated prelude importing the most commonly used `rship` SDK types.
//!
//! ```rust
//! use rship::prelude::*;
//! ```

pub use crate::client::{
    BisyncBuilder, ClientBuilder, ResolvedTarget, RshipClient, TransferBuilder, TransferTarget,
};
pub use crate::config::{
    AppConfig, AppPaths, AzureblobRemoteConfig, CryptRemoteConfig, DefaultsConfig,
    DropboxRemoteConfig, GcsRemoteConfig, GdriveRemoteConfig, LocalRemoteConfig,
    OnedriveRemoteConfig, RemoteConfig, RuntimeOptions, S3RemoteConfig, SftpRemoteConfig,
    TransferOptions, TransferProfile, WebdavRemoteConfig,
};
pub use rship_core::backend::{BackendPath, EntryStream, ListOptions, StorageBackend};
pub use rship_core::bandwidth::BandwidthSchedule;
pub use rship_core::bisync::{BisyncConfig, BisyncReport, ConflictStrategy};
pub use rship_core::engine::{
    CancelFlag, DeleteMode, EngineConfig, FileTransferResult, FileTransferStatus, RunReport,
    TransferEngine, TransferErrorInfo,
};
pub use rship_core::error::{Error, ErrorCategory, ErrorKind, Result, RetryClass};
pub use rship_core::failover::{
    AccountLease, AccountStatus, DEFAULT_QUOTA_COOLDOWN, DEFAULT_THROTTLE_COOLDOWN, FailoverPool,
};
pub use rship_core::filter::{FilterOptions, FilterRule, FilterSet};
pub use rship_core::path::{RelPath, TargetPath};
pub use rship_core::progress::{
    ActiveTransferSnapshot, ChannelEventSink, EventSink, FnEventSink, OverflowPolicy,
    ProgressSnapshot, TransferEvent, TransferPhase, TransferProgress,
};
pub use rship_core::state::{
    BaselineMode, JobMode, JobRecord, JobStatus, JournalStore, MemoryJournalStore, MemorySyncIndex,
    SyncConflict, SyncDiffIndex,
};
pub use rship_core::types::{
    BackendKind, ByteRange, Capabilities, Checksum, Entry, EntryKind, FsyncMode, HashKind, NodeId,
    StorageQuota,
};
