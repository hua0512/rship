//! Declarative TOML configuration, remote definitions, secret redaction, and
//! cross-platform application directory resolution shared between the `rship` SDK
//! and `rship-cli`.

mod paths;
mod profiles;
mod remotes;

pub use paths::{AppPaths, default_rclone_conf_path, load_config, save_config, write_private_file};
pub use profiles::{DefaultsConfig, TransferOptions, TransferProfile};
pub use remotes::{
    AzureblobRemoteConfig, CryptRemoteConfig, DropboxRemoteConfig, GcsRemoteConfig,
    GdriveRemoteConfig, LocalRemoteConfig, OnedriveRemoteConfig, RemoteConfig, S3RemoteConfig,
    SftpRemoteConfig, WebdavRemoteConfig,
};

use rship_core::types::FsyncMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// Replacement placeholder written by [`redact_config`] for inline secrets.
pub const REDACTED_SECRET: &str = "***REDACTED***";

/// Ephemeral process-level runtime overrides kept separate from persisted [`AppConfig`].
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeOptions {
    /// Fast-fail Google Drive uploads with `ErrorKind::QuotaExceeded` on HTTP
    /// `403 userRateLimitExceeded` (750 GiB/day cap) without retrying.
    pub gdrive_stop_on_upload_limit: bool,
    /// Override per-request low-level HTTP retry count on Google Drive backends.
    pub gdrive_low_level_retries: Option<u32>,
    /// Follow local filesystem symlinks when reading/listing (`--copy-links` / `-L`).
    /// Destination mutations ALWAYS continue enforcing symlink-escape containment.
    pub copy_links: bool,
    /// Local filesystem fsync durability policy (`--fsync=always|batch|never`, default `batch`).
    pub fsync_mode: FsyncMode,
    /// Optional explicit connect timeout for SFTP backends (decoupled from the `http` feature).
    pub sftp_connect_timeout: Option<Duration>,
    /// Optional explicit I/O stall timeout for SFTP backends (decoupled from the `http` feature).
    pub sftp_io_timeout: Option<Duration>,
}

impl RuntimeOptions {
    /// Create default runtime overrides.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable Google Drive upload-limit fast-fail.
    pub fn with_gdrive_stop_on_upload_limit(mut self, stop: bool) -> Self {
        self.gdrive_stop_on_upload_limit = stop;
        self
    }

    /// Override per-request low-level retry limit for Google Drive backends.
    pub fn with_gdrive_low_level_retries(mut self, retries: Option<u32>) -> Self {
        self.gdrive_low_level_retries = retries;
        self
    }

    /// Enable or disable dereferencing symlinks on local filesystem reads/listings.
    pub fn with_copy_links(mut self, copy_links: bool) -> Self {
        self.copy_links = copy_links;
        self
    }

    /// Configure the local filesystem durability policy (`--fsync=always|batch|never`).
    pub fn with_fsync_mode(mut self, fsync_mode: FsyncMode) -> Self {
        self.fsync_mode = fsync_mode;
        self
    }

    /// Override the TCP/SSH connect timeout for SFTP backends.
    pub fn with_sftp_connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.sftp_connect_timeout = timeout;
        self
    }

    /// Override the SFTP I/O stall timeout for SFTP backends.
    pub fn with_sftp_io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.sftp_io_timeout = timeout;
        self
    }
}

/// Top-level `rship` application and remote registry configuration (`config.toml`).
#[must_use]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AppConfig {
    /// Default transfer, filter, and network settings applied when not overridden.
    #[serde(default)]
    pub defaults: DefaultsConfig,
    /// Named transfer/filter/network presets (`[profiles.<name>]`) selectable via `--profile`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, TransferProfile>,
    /// Named remote definitions keyed by remote alias (e.g. `"gdrive2"`, `"r2"`).
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteConfig>,
}

impl AppConfig {
    /// Create an empty configuration with default concurrency settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override default settings and return `self` for chaining.
    pub fn with_defaults(mut self, defaults: DefaultsConfig) -> Self {
        self.defaults = defaults;
        self
    }

    /// Insert or replace a named [`TransferProfile`] preset (`[profiles.<name>]`) and return `self`.
    pub fn with_profile(mut self, name: impl Into<String>, profile: TransferProfile) -> Self {
        self.profiles.insert(name.into(), profile);
        self
    }

    /// Resolve effective transfer/filter/network settings by layering an optional named
    /// `[profiles.<name>]` preset on top of `[defaults]`.
    pub fn resolve_profile(&self, name: Option<&str>) -> rship_core::Result<TransferProfile> {
        profiles::resolve_named_profile(&self.defaults, &self.profiles, name)
    }

    /// Insert or replace a named remote configuration and return `self` for chaining.
    ///
    /// Accepts either [`RemoteConfig`] or any provider-specific `*RemoteConfig` struct.
    pub fn with_remote(mut self, name: impl Into<String>, remote: impl Into<RemoteConfig>) -> Self {
        self.remotes.insert(name.into(), remote.into());
        self
    }

    /// Return a deep clone with all inline secrets (and embedded proxy credentials)
    /// replaced by [`REDACTED_SECRET`] (preserving safe `keyring://` references).
    pub fn redacted(&self) -> Self {
        redact_config(self)
    }
}

/// Return a cloned [`AppConfig`] with every inline secret and embedded proxy password
/// masked by [`REDACTED_SECRET`].
pub fn redact_config(cfg: &AppConfig) -> AppConfig {
    let mut out = cfg.clone();
    out.defaults.redact_in_place();
    for profile in out.profiles.values_mut() {
        profile.redact_in_place();
    }
    for remote in out.remotes.values_mut() {
        remote.redact_in_place();
    }
    out
}
