use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, ErrorCategory, ErrorKind, Result, RetryClass};
use crate::progress::JobEventEmitter;
use crate::state::SyncConflict;

/// Hard ceiling on per-file result entries retained in [`RunReport::file_results`]
/// so million-file syncs stay within low-memory bounds while batch jobs get exact attribution.
pub const MAX_REPORT_FILE_RESULTS: usize = 10_000;
/// Unified ceiling on retained error strings/details in [`RunReport`] across all phases.
pub const MAX_REPORT_ERRORS: usize = 1_000;
/// Unified ceiling on retained [`SyncConflict`] entries in [`RunReport`].
pub const MAX_REPORT_CONFLICTS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileTransferStatus {
    Transferred,
    ServerSideCopied,
    Skipped,
    Failed,
}

impl FileTransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transferred => "transferred",
            Self::ServerSideCopied => "server_side_copied",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "transferred" => Some(Self::Transferred),
            "server_side_copied" => Some(Self::ServerSideCopied),
            "skipped" => Some(Self::Skipped),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl fmt::Display for FileTransferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FileTransferStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or_else(|| Error::invalid_path(format!("unknown file status `{s}`")))
    }
}

/// Structured, serializable error detail preserved in [`RunReport::error_details`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TransferErrorInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub kind: ErrorKind,
    #[serde(default)]
    pub category: ErrorCategory,
    pub retry_class: RetryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    pub message: String,
}

impl TransferErrorInfo {
    pub fn from_error(path: Option<String>, err: &Error) -> Self {
        Self::from_error_with_message(path, err, err.to_string())
    }

    pub fn from_error_with_message(
        path: Option<String>,
        err: &Error,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path,
            kind: err.kind,
            category: err.category(),
            retry_class: err.retry,
            retry_after_ms: err
                .retry_after
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FileTransferResult {
    pub path: String,
    pub status: FileTransferStatus,
    pub bytes: u64,
    pub source_deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<ErrorKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_category: Option<ErrorCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_class: Option<RetryClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl FileTransferResult {
    pub fn transferred(path: impl Into<String>, bytes: u64, source_deleted: bool) -> Self {
        Self {
            path: path.into(),
            status: FileTransferStatus::Transferred,
            bytes,
            source_deleted,
            error: None,
            error_kind: None,
            error_category: None,
            retry_class: None,
            retry_after_ms: None,
        }
    }

    pub fn server_side_copied(path: impl Into<String>, bytes: u64, source_deleted: bool) -> Self {
        Self {
            path: path.into(),
            status: FileTransferStatus::ServerSideCopied,
            bytes,
            source_deleted,
            error: None,
            error_kind: None,
            error_category: None,
            retry_class: None,
            retry_after_ms: None,
        }
    }

    pub fn skipped(path: impl Into<String>, source_deleted: bool) -> Self {
        Self {
            path: path.into(),
            status: FileTransferStatus::Skipped,
            bytes: 0,
            source_deleted,
            error: None,
            error_kind: None,
            error_category: None,
            retry_class: None,
            retry_after_ms: None,
        }
    }

    pub fn failed(path: impl Into<String>, err: &Error) -> Self {
        Self::failed_with_message(path, err, err.to_string())
    }

    pub fn failed_with_message(
        path: impl Into<String>,
        err: &Error,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            status: FileTransferStatus::Failed,
            bytes: 0,
            source_deleted: false,
            error: Some(message.into()),
            error_kind: Some(err.kind),
            error_category: Some(err.category()),
            retry_class: Some(err.retry),
            retry_after_ms: err
                .retry_after
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        }
    }

    pub fn from_error_info(path: impl Into<String>, info: &TransferErrorInfo) -> Self {
        Self {
            path: path.into(),
            status: FileTransferStatus::Failed,
            bytes: 0,
            source_deleted: false,
            error: Some(info.message.clone()),
            error_kind: Some(info.kind),
            error_category: Some(info.category),
            retry_class: Some(info.retry_class),
            retry_after_ms: info.retry_after_ms,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunReport {
    pub job_id: String,
    pub files_transferred: u64,
    pub files_skipped: u64,
    pub server_side_copies: u64,
    pub sources_deleted: u64,
    pub dirs_created: u64,
    pub items_deleted: u64,
    pub bytes_transferred: u64,
    pub conflicts: Vec<SyncConflict>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub conflicts_truncated: u64,
    pub errors: Vec<String>,
    /// Typed per-error diagnostics preserving [`ErrorKind`], [`RetryClass`], and `retry_after_ms`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_details: Vec<TransferErrorInfo>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub errors_truncated: u64,
    pub file_results: Vec<FileTransferResult>,
    pub file_results_truncated: bool,
    pub src_observation_complete: bool,
    pub dst_observation_complete: bool,
    pub cancelled: bool,
    pub final_small_concurrency: Option<usize>,
    pub final_large_concurrency: Option<usize>,
    /// Non-fatal safety warning emitted when a `sync` run deletes more than 50% of
    /// observed destination files (without aborting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_delete_warning: Option<String>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl RunReport {
    pub fn push_error(&mut self, info: TransferErrorInfo) {
        if self.errors.len() < MAX_REPORT_ERRORS {
            self.errors.push(info.message.clone());
            self.error_details.push(info);
        } else {
            self.errors_truncated = self.errors_truncated.saturating_add(1);
        }
    }

    pub fn push_conflict(&mut self, conflict: SyncConflict) {
        if self.conflicts.len() < MAX_REPORT_CONFLICTS {
            self.conflicts.push(conflict);
        } else {
            self.conflicts_truncated = self.conflicts_truncated.saturating_add(1);
        }
    }

    pub fn is_success(&self) -> bool {
        !self.cancelled && !self.has_errors() && !self.has_conflicts()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty() || self.errors_truncated > 0
    }

    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty() || self.conflicts_truncated > 0
    }

    /// Return the highest-priority machine-readable [`ErrorCategory`] for this run,
    /// or `None` when the run succeeded without cancellation, errors, or conflicts.
    pub fn primary_error_category(&self) -> Option<ErrorCategory> {
        if self.cancelled {
            return Some(ErrorCategory::Cancelled);
        }
        if !self.errors.is_empty() {
            return ErrorCategory::primary(self.error_details.iter().map(|e| e.category))
                .or(Some(ErrorCategory::Other));
        }
        if !self.conflicts.is_empty() {
            return Some(ErrorCategory::Conflict);
        }
        None
    }
}

pub(super) fn push_file_result(
    results: &mut Vec<FileTransferResult>,
    truncated: &mut bool,
    emitter: Option<&JobEventEmitter>,
    item: FileTransferResult,
) {
    if let Some(em) = emitter {
        em.emit_file_completed(item.clone());
    }
    if results.len() < MAX_REPORT_FILE_RESULTS {
        results.push(item);
    } else {
        *truncated = true;
    }
}

/// Cooperative cancellation handle triggered by `SIGINT` / Ctrl-C, backed by both an
/// `AtomicBool` fast path and a `tokio::sync::Notify` so in-flight `JoinSet` / `select!`
/// waiters wake immediately on signal.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<CancelFlagInner>);

#[derive(Debug, Default)]
struct CancelFlagInner {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl CancelFlag {
    pub fn new() -> Self {
        Self(Arc::new(CancelFlagInner {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }))
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves immediately if already cancelled, or as soon as [`Self::cancel`] is called.
    pub async fn cancelled(&self) {
        let notified = self.0.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }

    /// Owned `'static` future resolving as soon as this flag is cancelled.
    pub fn cancelled_owned(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let flag = self.clone();
        async move { flag.cancelled().await }
    }
}
