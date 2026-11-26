//! Declarative transfer defaults (`[defaults]`) and reusable named profiles
//! (`[profiles.<name>]`) shared between `config.toml`, the `rship` SDK, and `rship-cli`.
//!
//! Both [`DefaultsConfig`] and [`TransferProfile`] compose the single shared
//! [`TransferOptions`] struct via `#[serde(flatten)]` and `Deref`/`DerefMut`, avoiding
//! duplicated option definitions while keeping `[defaults]`'s concrete `transfers` and
//! `part_concurrency` fields 100% backwards-compatible.

use rship_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use super::REDACTED_SECRET;

/// Scrub embedded `user:pass@` credentials from a proxy URL so `Debug` output and
/// `rship config show` never leak proxy passwords.
pub(crate) fn redact_proxy_url(url: &str) -> String {
    let Some(scheme_pos) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = scheme_pos + 3;
    let tail = &url[after_scheme..];
    let line_end = tail.find(['\n', '\r']).unwrap_or(tail.len());
    let span = &tail[..line_end];
    if let Some(at_idx) = span.rfind('@') {
        let mut out = String::with_capacity(url.len() + REDACTED_SECRET.len());
        out.push_str(&url[..after_scheme]);
        out.push_str(REDACTED_SECRET);
        out.push('@');
        out.push_str(&tail[at_idx + 1..]);
        out
    } else {
        url.to_string()
    }
}

fn merge_unique<T: Clone + PartialEq>(first: &[T], second: &[T]) -> Vec<T> {
    let mut out = Vec::with_capacity(first.len() + second.len());
    for item in first.iter().chain(second.iter()) {
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    out
}

/// Shared optional transfer, safety, filtering, and network settings flattened into both
/// `[defaults]` ([`DefaultsConfig`]) and `[profiles.<name>]` ([`TransferProfile`]).
#[must_use]
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TransferOptions {
    /// Enable or disable Falcon dual-lane adaptive concurrency (`--adaptive` / `--no-adaptive`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<bool>,
    /// Protocol chunk size override (e.g. `"64M"`, `"128M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<String>,
    /// Hard cap for engine-owned `BufferPool` (e.g. `"8M"`, `"16M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_buffer_mem: Option<String>,
    /// Sustained bandwidth limit or time-of-day timetable (e.g. `"20M"`, `"08:00,10M 23:00,off"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bwlimit: Option<String>,
    /// Deletion circuit breaker count (`"100"`), percentage (`"50%"`), or `"off"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delete: Option<String>,
    /// Local filesystem fsync durability mode (`"always"`, `"batch"`, `"never"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fsync: Option<String>,
    /// Compare files by checksum instead of size + mtime (`--checksum`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<bool>,
    /// Allow replacing a file with a directory or vice versa (`--force-type-replace`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_type_replace: Option<bool>,
    /// Follow local source symlinks (`-L` / `--copy-links`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_links: Option<bool>,
    /// Archive overwritten or deleted destination files into this non-overlapping target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    /// When extraneous destination files are deleted during `sync` (`"after"`, `"during"`, `"before"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_mode: Option<String>,
    /// Freeze each source file into a private local snapshot before upload (`--strict-source`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_source: Option<bool>,
    /// Maximum per-file snapshot size allowed under `strict_source` (e.g. `"256M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_source_max_size: Option<String>,
    /// Disable cloud server-side copy and force streaming relay (`--no-server-side-copy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_server_side_copy: Option<bool>,
    /// Per-file/session transfer retry limit (`--retries`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// Baseline persistence policy (`"auto"`, `"all"`, `"none"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// Disable destination advisory process lock (`--no-lock`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_lock: Option<bool>,
    /// Default `bisync` conflict strategy (`"keep-both"`, `"abort"`, `"prefer-a"`, `"prefer-b"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_strategy: Option<String>,
    /// Glob patterns to exclude (appended onto lower-precedence layers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// Glob patterns to include (appended onto lower-precedence layers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// Exclude pattern files (appended onto lower-precedence layers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_from: Vec<PathBuf>,
    /// Ordered `+`/`-` filter rule files (higher-precedence layers evaluated first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_from: Vec<PathBuf>,
    /// Minimum file size filter (e.g. `"1K"`, `"10M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_size: Option<String>,
    /// Maximum file size filter (e.g. `"100M"`, `"2G"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<String>,
    /// Minimum file modification age filter (e.g. `"1h"`, `"7d"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_age: Option<String>,
    /// Maximum file modification age filter (e.g. `"30m"`, `"30d"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<String>,
    /// Explicit HTTP/HTTPS/SOCKS5 proxy URL (`--proxy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Custom PEM CA certificate bundle path (`--ca-cert`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
    /// TCP/TLS connect timeout (e.g. `"15s"`, `"30s"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<String>,
    /// Data-plane byte-progress idle stall timeout (e.g. `"30s"`, `"2m"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stall_timeout: Option<String>,
    /// Control-plane metadata/RPC timeout (e.g. `"60s"`, `"2m"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_timeout: Option<String>,
    /// Global proactive API requests-per-second ceiling (`0` = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpslimit: Option<f64>,
    /// Per-HTTP-request low-level retry count on cloud backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_level_retries: Option<u32>,
}

impl TransferOptions {
    /// Layer `overlay` on top of `self`.
    ///
    /// Scalar fields in `overlay` win when `Some`. Unordered filter lists (`exclude`,
    /// `include`, `exclude_from`) append `overlay` onto `self` (deduplicating exact
    /// matches), while ordered `filter_from` rule files place `overlay` first so more
    /// specific rules win under first-match-wins evaluation.
    pub fn merged_with(&self, overlay: &Self) -> Self {
        Self {
            adaptive: overlay.adaptive.or(self.adaptive),
            chunk_size: overlay
                .chunk_size
                .clone()
                .or_else(|| self.chunk_size.clone()),
            max_buffer_mem: overlay
                .max_buffer_mem
                .clone()
                .or_else(|| self.max_buffer_mem.clone()),
            bwlimit: overlay.bwlimit.clone().or_else(|| self.bwlimit.clone()),
            max_delete: overlay
                .max_delete
                .clone()
                .or_else(|| self.max_delete.clone()),
            fsync: overlay.fsync.clone().or_else(|| self.fsync.clone()),
            checksum: overlay.checksum.or(self.checksum),
            force_type_replace: overlay.force_type_replace.or(self.force_type_replace),
            copy_links: overlay.copy_links.or(self.copy_links),
            backup_dir: overlay
                .backup_dir
                .clone()
                .or_else(|| self.backup_dir.clone()),
            delete_mode: overlay
                .delete_mode
                .clone()
                .or_else(|| self.delete_mode.clone()),
            strict_source: overlay.strict_source.or(self.strict_source),
            strict_source_max_size: overlay
                .strict_source_max_size
                .clone()
                .or_else(|| self.strict_source_max_size.clone()),
            no_server_side_copy: overlay.no_server_side_copy.or(self.no_server_side_copy),
            retries: overlay.retries.or(self.retries),
            baseline: overlay.baseline.clone().or_else(|| self.baseline.clone()),
            no_lock: overlay.no_lock.or(self.no_lock),
            conflict_strategy: overlay
                .conflict_strategy
                .clone()
                .or_else(|| self.conflict_strategy.clone()),
            exclude: merge_unique(&self.exclude, &overlay.exclude),
            include: merge_unique(&self.include, &overlay.include),
            exclude_from: merge_unique(&self.exclude_from, &overlay.exclude_from),
            filter_from: merge_unique(&overlay.filter_from, &self.filter_from),
            min_size: overlay.min_size.clone().or_else(|| self.min_size.clone()),
            max_size: overlay.max_size.clone().or_else(|| self.max_size.clone()),
            min_age: overlay.min_age.clone().or_else(|| self.min_age.clone()),
            max_age: overlay.max_age.clone().or_else(|| self.max_age.clone()),
            proxy: overlay.proxy.clone().or_else(|| self.proxy.clone()),
            ca_cert: overlay.ca_cert.clone().or_else(|| self.ca_cert.clone()),
            connect_timeout: overlay
                .connect_timeout
                .clone()
                .or_else(|| self.connect_timeout.clone()),
            stall_timeout: overlay
                .stall_timeout
                .clone()
                .or_else(|| self.stall_timeout.clone()),
            control_timeout: overlay
                .control_timeout
                .clone()
                .or_else(|| self.control_timeout.clone()),
            tpslimit: overlay.tpslimit.or(self.tpslimit),
            low_level_retries: overlay.low_level_retries.or(self.low_level_retries),
        }
    }

    pub(crate) fn redact_in_place(&mut self) {
        if let Some(url) = self.proxy.as_mut() {
            let scrubbed = redact_proxy_url(url);
            if scrubbed != *url {
                *url = scrubbed;
            }
        }
    }

    pub(crate) fn push_summary_parts(&self, parts: &mut Vec<String>) {
        if let Some(a) = self.adaptive {
            parts.push(format!("adaptive={}", if a { "on" } else { "off" }));
        }
        if let Some(ref bw) = self.bwlimit {
            parts.push(format!("bwlimit={bw}"));
        }
        if let Some(ref cs) = self.chunk_size {
            parts.push(format!("chunk={cs}"));
        }
        if let Some(ref mem) = self.max_buffer_mem {
            parts.push(format!("buf={mem}"));
        }
        if let Some(ref md) = self.max_delete {
            parts.push(format!("max_delete={md}"));
        }
        if let Some(ref dm) = self.delete_mode {
            parts.push(format!("delete={dm}"));
        }
        if let Some(ref f) = self.fsync {
            parts.push(format!("fsync={f}"));
        }
        if self.checksum == Some(true) {
            parts.push("checksum".to_string());
        }
        if let Some(ref bk) = self.backup_dir {
            parts.push(format!("backup_dir={bk}"));
        }
        if let Some(ref cs) = self.conflict_strategy {
            parts.push(format!("conflict={cs}"));
        }
        if let Some(r) = self.retries {
            parts.push(format!("retries={r}"));
        }
        if !self.exclude.is_empty() {
            parts.push(format!("exclude({})", self.exclude.len()));
        }
        if !self.include.is_empty() {
            parts.push(format!("include({})", self.include.len()));
        }
        if !self.exclude_from.is_empty() {
            parts.push(format!("exclude_from({})", self.exclude_from.len()));
        }
        if !self.filter_from.is_empty() {
            parts.push(format!("filter_from({})", self.filter_from.len()));
        }
        if let Some(tps) = self.tpslimit {
            parts.push(format!("tpslimit={tps}"));
        }
        if let Some(ref proxy) = self.proxy {
            parts.push(format!("proxy={}", redact_proxy_url(proxy)));
        }
    }
}

impl fmt::Debug for TransferOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferOptions")
            .field("adaptive", &self.adaptive)
            .field("chunk_size", &self.chunk_size)
            .field("max_buffer_mem", &self.max_buffer_mem)
            .field("bwlimit", &self.bwlimit)
            .field("max_delete", &self.max_delete)
            .field("fsync", &self.fsync)
            .field("checksum", &self.checksum)
            .field("force_type_replace", &self.force_type_replace)
            .field("copy_links", &self.copy_links)
            .field("backup_dir", &self.backup_dir)
            .field("delete_mode", &self.delete_mode)
            .field("strict_source", &self.strict_source)
            .field("strict_source_max_size", &self.strict_source_max_size)
            .field("no_server_side_copy", &self.no_server_side_copy)
            .field("retries", &self.retries)
            .field("baseline", &self.baseline)
            .field("no_lock", &self.no_lock)
            .field("conflict_strategy", &self.conflict_strategy)
            .field("exclude", &self.exclude)
            .field("include", &self.include)
            .field("exclude_from", &self.exclude_from)
            .field("filter_from", &self.filter_from)
            .field("min_size", &self.min_size)
            .field("max_size", &self.max_size)
            .field("min_age", &self.min_age)
            .field("max_age", &self.max_age)
            .field("proxy", &self.proxy.as_deref().map(redact_proxy_url))
            .field("ca_cert", &self.ca_cert)
            .field("connect_timeout", &self.connect_timeout)
            .field("stall_timeout", &self.stall_timeout)
            .field("control_timeout", &self.control_timeout)
            .field("tpslimit", &self.tpslimit)
            .field("low_level_retries", &self.low_level_retries)
            .finish()
    }
}

/// Reusable named transfer, filter, safety, and network preset stored under
/// `[profiles.<name>]` in `config.toml` and selectable via `-p/--profile <NAME>`.
///
/// Unspecified fields inherit from `[defaults]` and built-in engine defaults; explicit
/// CLI flags always take highest precedence.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TransferProfile {
    /// Parallel file transfer workers (`--transfers`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfers: Option<usize>,
    /// Concurrent parts per parallel-multipart upload (`--part-concurrency`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_concurrency: Option<usize>,
    /// Shared optional transfer, safety, filter, and network overrides.
    #[serde(flatten)]
    pub options: TransferOptions,
}

impl Deref for TransferProfile {
    type Target = TransferOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for TransferProfile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

impl TransferProfile {
    /// Create an empty profile with no overrides set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set concurrent file worker count (`--transfers`, clamped to at least 1).
    pub fn with_transfers(mut self, transfers: usize) -> Self {
        self.transfers = Some(transfers.max(1));
        self
    }

    /// Set concurrent multipart part uploads (`--part-concurrency`, clamped to at least 1).
    pub fn with_part_concurrency(mut self, part_concurrency: usize) -> Self {
        self.part_concurrency = Some(part_concurrency.max(1));
        self
    }

    /// Enable or disable Falcon dual-lane adaptive concurrency.
    pub fn with_adaptive(mut self, adaptive: bool) -> Self {
        self.options.adaptive = Some(adaptive);
        self
    }

    /// Set a sustained bandwidth cap or timetable (`"20M"`, `"08:00,10M 23:00,off"`).
    pub fn with_bwlimit(mut self, bwlimit: impl Into<String>) -> Self {
        self.options.bwlimit = Some(bwlimit.into());
        self
    }

    /// Set the protocol chunk size override (`"64M"`, `"128M"`).
    pub fn with_chunk_size(mut self, chunk_size: impl Into<String>) -> Self {
        self.options.chunk_size = Some(chunk_size.into());
        self
    }

    /// Set the engine `BufferPool` memory cap (`"8M"`, `"16M"`).
    pub fn with_max_buffer_mem(mut self, max_buffer_mem: impl Into<String>) -> Self {
        self.options.max_buffer_mem = Some(max_buffer_mem.into());
        self
    }

    /// Set the deletion circuit breaker (`"100"`, `"50%"`, or `"off"`).
    pub fn with_max_delete(mut self, max_delete: impl Into<String>) -> Self {
        self.options.max_delete = Some(max_delete.into());
        self
    }

    /// Set the local filesystem fsync durability mode (`"always"`, `"batch"`, `"never"`).
    pub fn with_fsync(mut self, fsync: impl Into<String>) -> Self {
        self.options.fsync = Some(fsync.into());
        self
    }

    /// Enable or disable checksum-based file comparison.
    pub fn with_checksum(mut self, checksum: bool) -> Self {
        self.options.checksum = Some(checksum);
        self
    }

    /// Set the `sync` deletion timing (`"after"`, `"during"`, `"before"`).
    pub fn with_delete_mode(mut self, delete_mode: impl Into<String>) -> Self {
        self.options.delete_mode = Some(delete_mode.into());
        self
    }

    /// Set the backup archive directory target for overwritten or deleted files.
    pub fn with_backup_dir(mut self, backup_dir: impl Into<String>) -> Self {
        self.options.backup_dir = Some(backup_dir.into());
        self
    }

    /// Set the per-file/session transfer retry limit.
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.options.retries = Some(retries);
        self
    }

    /// Append an exclude glob pattern to this profile.
    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.options.exclude.push(pattern.into());
        self
    }

    /// Append an include glob pattern to this profile.
    pub fn with_include(mut self, pattern: impl Into<String>) -> Self {
        self.options.include.push(pattern.into());
        self
    }

    /// Set an explicit proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`).
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.options.proxy = Some(proxy.into());
        self
    }

    /// Set a global proactive API TPS ceiling (`0` = unlimited).
    pub fn with_tpslimit(mut self, tpslimit: f64) -> Self {
        self.options.tpslimit = Some(tpslimit);
        self
    }

    /// Layer `overlay` on top of `self` (see [`TransferOptions::merged_with`]).
    pub fn merged_with(&self, overlay: &Self) -> Self {
        Self {
            transfers: overlay.transfers.or(self.transfers),
            part_concurrency: overlay.part_concurrency.or(self.part_concurrency),
            options: self.options.merged_with(&overlay.options),
        }
    }

    pub(crate) fn redact_in_place(&mut self) {
        self.options.redact_in_place();
    }

    /// Concise single-line human summary of the active settings in this profile.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(t) = self.transfers {
            parts.push(format!("transfers={t}"));
        }
        if let Some(pc) = self.part_concurrency {
            parts.push(format!("parts={pc}"));
        }
        self.options.push_summary_parts(&mut parts);
        if parts.is_empty() {
            "(empty)".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// Default settings stored in `[defaults]` of `config.toml`.
///
/// Applied automatically across CLI commands and `RshipClient` operations unless
/// overridden by a `-p/--profile <NAME>` preset or an explicit CLI flag.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DefaultsConfig {
    /// Default parallel file transfers (`--transfers`, default `4`).
    #[serde(default = "default_transfers")]
    pub transfers: usize,
    /// Default concurrent parts per multipart upload (`--part-concurrency`, default `4`).
    #[serde(default = "default_part_concurrency")]
    pub part_concurrency: usize,
    /// Shared optional transfer, safety, filter, and network defaults.
    #[serde(flatten)]
    pub options: TransferOptions,
}

impl Deref for DefaultsConfig {
    type Target = TransferOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for DefaultsConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

impl DefaultsConfig {
    /// Create default settings (`transfers = 4`, `part_concurrency = 4`, all optional overrides unset).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set default parallel file transfers (clamped to at least 1).
    pub fn with_transfers(mut self, transfers: usize) -> Self {
        self.transfers = transfers.max(1);
        self
    }

    /// Set default concurrent parts per multipart upload (clamped to at least 1).
    pub fn with_part_concurrency(mut self, part_concurrency: usize) -> Self {
        self.part_concurrency = part_concurrency.max(1);
        self
    }

    /// Enable or disable Falcon dual-lane adaptive concurrency by default.
    pub fn with_adaptive(mut self, adaptive: bool) -> Self {
        self.options.adaptive = Some(adaptive);
        self
    }

    /// Set the default sustained bandwidth limit or timetable.
    pub fn with_bwlimit(mut self, bwlimit: impl Into<String>) -> Self {
        self.options.bwlimit = Some(bwlimit.into());
        self
    }

    /// Set the default deletion circuit breaker (`"100"`, `"50%"`, or `"off"`).
    pub fn with_max_delete(mut self, max_delete: impl Into<String>) -> Self {
        self.options.max_delete = Some(max_delete.into());
        self
    }

    /// Set the default local filesystem durability policy (`"always"`, `"batch"`, `"never"`).
    pub fn with_fsync(mut self, fsync: impl Into<String>) -> Self {
        self.options.fsync = Some(fsync.into());
        self
    }

    /// Append a default exclude glob pattern.
    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.options.exclude.push(pattern.into());
        self
    }

    /// Set a default proxy URL.
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.options.proxy = Some(proxy.into());
        self
    }

    /// Set a default global API TPS ceiling.
    pub fn with_tpslimit(mut self, tpslimit: f64) -> Self {
        self.options.tpslimit = Some(tpslimit);
        self
    }

    /// Convert `[defaults]` into a base [`TransferProfile`] layer ready to merge with a
    /// named `[profiles.<name>]` overlay and explicit CLI flags.
    pub fn to_profile(&self) -> TransferProfile {
        TransferProfile {
            transfers: Some(self.transfers.max(1)),
            part_concurrency: Some(self.part_concurrency.max(1)),
            options: self.options.clone(),
        }
    }

    pub(crate) fn redact_in_place(&mut self) {
        self.options.redact_in_place();
    }
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            transfers: default_transfers(),
            part_concurrency: default_part_concurrency(),
            options: TransferOptions::default(),
        }
    }
}

fn default_transfers() -> usize {
    4
}

fn default_part_concurrency() -> usize {
    4
}

/// Resolve `[defaults]` overlaid with an optional named `[profiles.<name>]` entry.
pub(crate) fn resolve_named_profile(
    defaults: &DefaultsConfig,
    profiles: &BTreeMap<String, TransferProfile>,
    name: Option<&str>,
) -> Result<TransferProfile> {
    let base = defaults.to_profile();
    let Some(raw_name) = name else {
        return Ok(base);
    };
    let trimmed = raw_name.trim();
    if let Some(overlay) = profiles.get(trimmed) {
        Ok(base.merged_with(overlay))
    } else if profiles.is_empty() {
        Err(rship_core::Error::config(format!(
            "unknown profile `{trimmed}` (no `[profiles.<name>]` sections are configured in config.toml)"
        )))
    } else {
        let names: Vec<&str> = profiles.keys().map(String::as_str).collect();
        Err(rship_core::Error::config(format!(
            "unknown profile `{trimmed}` (available profiles: {})",
            names.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_merge_layers_scalars_and_filter_lists_cleanly() {
        let mut defaults = DefaultsConfig::new()
            .with_transfers(8)
            .with_part_concurrency(6)
            .with_bwlimit("20M")
            .with_exclude(".git/")
            .with_proxy("http://alice:supersecret@proxy.internal:8080");
        defaults
            .filter_from
            .push(PathBuf::from("default-rules.txt"));

        let mut backup = TransferProfile::new()
            .with_adaptive(true)
            .with_bwlimit("5M")
            .with_max_delete("100")
            .with_exclude(".git/")
            .with_exclude("*.tmp");
        backup.filter_from.push(PathBuf::from("backup-rules.txt"));

        let mut profiles = BTreeMap::new();
        profiles.insert("backup".to_string(), backup);

        let resolved = resolve_named_profile(&defaults, &profiles, Some("backup")).unwrap();
        assert_eq!(resolved.transfers, Some(8));
        assert_eq!(resolved.part_concurrency, Some(6));
        assert_eq!(resolved.adaptive, Some(true));
        assert_eq!(resolved.bwlimit.as_deref(), Some("5M"));
        assert_eq!(resolved.max_delete.as_deref(), Some("100"));
        assert_eq!(resolved.exclude, vec![".git/", "*.tmp"]);
        assert_eq!(
            resolved.filter_from,
            vec![
                PathBuf::from("backup-rules.txt"),
                PathBuf::from("default-rules.txt")
            ]
        );
        assert_eq!(
            resolved.proxy.as_deref(),
            Some("http://alice:supersecret@proxy.internal:8080")
        );

        let dbg = format!("{resolved:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("***REDACTED***@proxy.internal:8080"));
    }

    #[test]
    fn unknown_profile_lists_available_names() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "fast".to_string(),
            TransferProfile::new().with_adaptive(true),
        );
        profiles.insert(
            "nightly".to_string(),
            TransferProfile::new().with_bwlimit("5M"),
        );

        let err =
            resolve_named_profile(&DefaultsConfig::default(), &profiles, Some("typo")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown profile `typo`"));
        assert!(msg.contains("fast, nightly"));
    }

    #[test]
    fn default_config_toml_stays_minimal_and_roundtrips_profiles() {
        let cfg = crate::config::AppConfig::new();
        let raw = toml::to_string_pretty(&cfg).unwrap();
        assert!(raw.contains("transfers = 4"));
        assert!(raw.contains("part_concurrency = 4"));
        assert!(!raw.contains("profiles"));
        assert!(!raw.contains("exclude"));

        let parsed: crate::config::AppConfig = toml::from_str(
            r#"
[defaults]
transfers = 6
adaptive = true
exclude = [".git/", "target/"]

[profiles.nightly]
bwlimit = "08:00,5M 23:00,off"
max_delete = "25%"
exclude = ["*.tmp"]
"#,
        )
        .unwrap();
        let eff = parsed.resolve_profile(Some("nightly")).unwrap();
        assert_eq!(eff.transfers, Some(6));
        assert_eq!(eff.adaptive, Some(true));
        assert_eq!(eff.bwlimit.as_deref(), Some("08:00,5M 23:00,off"));
        assert_eq!(eff.max_delete.as_deref(), Some("25%"));
        assert_eq!(eff.exclude, vec![".git/", "target/", "*.tmp"]);
    }
}
