//! Dropbox v2 API configuration & chunk geometry constants.

use std::time::Duration;

use crate::common::http::RetryPolicyConfig;

pub const DEFAULT_DROPBOX_API_URL: &str = "https://api.dropboxapi.com/2";
pub const DEFAULT_DROPBOX_CONTENT_URL: &str = "https://content.dropboxapi.com/2";
pub const DEFAULT_DROPBOX_AUTH_URL: &str = "https://www.dropbox.com/oauth2/authorize";
pub const DEFAULT_DROPBOX_TOKEN_URL: &str = "https://api.dropboxapi.com/oauth2/token";

/// Dropbox requires non-final upload session chunks to be multiples of 4 MiB
/// (matching Dropbox's 4 MiB content-hash block boundary).
pub const DROPBOX_CHUNK_ALIGN_BYTES: u64 = 4 * 1024 * 1024;
/// Safe ceiling below Dropbox's 150 MiB per-request upload limit (37 × 4 MiB = 148 MiB).
pub const MAX_DROPBOX_CHUNK_BYTES: u64 = 37 * DROPBOX_CHUNK_ALIGN_BYTES;
/// Default single-shot `/files/upload` cutoff (4 MiB; resumable sessions used above this).
pub const DEFAULT_DROPBOX_SINGLE_SHOT_MAX: u64 = 4 * 1024 * 1024;
/// Default resumable chunk size: 48 MiB (12 × 4 MiB, matches rclone's default).
pub const DEFAULT_DROPBOX_CHUNK_SIZE: u64 = 12 * DROPBOX_CHUNK_ALIGN_BYTES;

#[derive(Debug, Clone)]
pub struct DropboxConfig {
    pub remote_name: String,
    pub api_base_url: String,
    pub content_base_url: String,
    pub auth_url: String,
    pub token_url: String,
    /// Optional root subpath inside Dropbox (normalized without trailing `/`).
    pub root_path: String,
    /// Optional Dropbox namespace ID / path-root override (`Dropbox-API-Path-Root`).
    pub root_namespace: Option<String>,
    /// Optional Dropbox team member ID (`dbmid:...`) or email to impersonate (`Dropbox-API-Select-User`).
    pub impersonate: Option<String>,
    /// Whether to include/query shared folders (`--dropbox-shared-folders`).
    pub shared_folders: bool,
    /// Optional explicit chunk alignment override (for fast unit/conformance tests).
    pub chunk_align_override: Option<u64>,
    pub single_shot_max_bytes: u64,
    pub default_chunk_size: u64,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl DropboxConfig {
    pub fn new(remote_name: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            api_base_url: DEFAULT_DROPBOX_API_URL.to_string(),
            content_base_url: DEFAULT_DROPBOX_CONTENT_URL.to_string(),
            auth_url: DEFAULT_DROPBOX_AUTH_URL.to_string(),
            token_url: DEFAULT_DROPBOX_TOKEN_URL.to_string(),
            root_path: String::new(),
            root_namespace: None,
            impersonate: None,
            shared_folders: false,
            chunk_align_override: None,
            single_shot_max_bytes: DEFAULT_DROPBOX_SINGLE_SHOT_MAX,
            default_chunk_size: DEFAULT_DROPBOX_CHUNK_SIZE,
            max_retries: 6,
            base_retry_delay: Duration::from_millis(250),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    pub fn with_root_path(mut self, root_path: impl Into<String>) -> Self {
        self.root_path = root_path.into();
        self
    }

    pub fn with_root_namespace(mut self, root_namespace: impl Into<String>) -> Self {
        self.root_namespace = Some(root_namespace.into());
        self
    }

    pub fn with_impersonate(mut self, impersonate: impl Into<String>) -> Self {
        self.impersonate = Some(impersonate.into());
        self
    }

    pub fn with_shared_folders(mut self, shared_folders: bool) -> Self {
        self.shared_folders = shared_folders;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_retry_delays(mut self, base_delay: Duration, max_delay: Duration) -> Self {
        self.base_retry_delay = base_delay;
        self.max_retry_delay = max_delay;
        self
    }

    pub fn retry_policy(&self) -> RetryPolicyConfig {
        RetryPolicyConfig::new()
            .with_max_retries(self.max_retries)
            .with_delays(self.base_retry_delay, self.max_retry_delay)
    }

    /// Format a Dropbox API v2 path (`""` for root, `"/a/b"` for non-root).
    ///
    /// Strips `'/'` separators only so legitimate filenames/folders with leading or
    /// trailing spaces are preserved verbatim.
    pub fn api_path(&self, rel: &str) -> String {
        let base = self.root_path.trim_matches('/');
        let sub = rel.trim_matches('/');
        match (base.is_empty(), sub.is_empty()) {
            (true, true) => String::new(),
            (true, false) => format!("/{sub}"),
            (false, true) => format!("/{base}"),
            (false, false) => format!("/{base}/{sub}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_path_strips_slashes_only_and_preserves_whitespace() {
        let cfg = DropboxConfig::new("dbx");
        assert_eq!(cfg.api_path(""), "");
        assert_eq!(cfg.api_path("/"), "");
        assert_eq!(cfg.api_path(" leading.txt"), "/ leading.txt");
        assert_eq!(cfg.api_path("trailing.txt "), "/trailing.txt ");
        assert_eq!(cfg.api_path(" dir / file .txt "), "/ dir / file .txt ");

        let rooted = cfg.with_root_path("/ backups /");
        assert_eq!(rooted.api_path(""), "/ backups ");
        assert_eq!(rooted.api_path(" file.txt "), "/ backups / file.txt ");
    }
}
