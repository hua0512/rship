//! Configuration for [`crate::gdrive::GdriveBackend`].

use std::time::Duration;

pub const DEFAULT_API_BASE_URL: &str = "https://www.googleapis.com/drive/v3";
pub const DEFAULT_UPLOAD_BASE_URL: &str = "https://www.googleapis.com/upload/drive/v3";
pub const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const DEFAULT_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/drive";

pub const GDRIVE_CHUNK_ALIGN_BYTES: u64 = 256 * 1024;
pub const GDRIVE_SINGLE_SHOT_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const GDRIVE_DEFAULT_CHUNK_SIZE: u64 = 256 * 1024 * 1024;
pub const GDRIVE_DEFAULT_WRITE_QPS: f64 = 8.0;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GdriveConfig {
    pub remote_name: String,
    pub api_base_url: String,
    pub upload_base_url: String,
    pub token_url: String,
    pub auth_url: String,
    /// Root folder ID (`"root"` for My Drive, or a specific folder/Shared Drive ID).
    pub root_folder_id: String,
    /// Optional Shared Drive (`team_drive`) ID. When set, queries use
    /// `corpora=drive&driveId=<id>` and `supportsAllDrives=true&includeItemsFromAllDrives=true`.
    pub shared_drive_id: Option<String>,
    pub scope: String,
    /// Optional write/create QPS limit (default: 8.0 creates/sec, dynamically backed off by CUBIC on 403/429).
    pub write_qps: Option<f64>,
    /// Files `<= single_shot_max_bytes` use 1-request `uploadType=multipart`.
    pub single_shot_max_bytes: u64,
    /// Default resumable chunk size (must be a positive multiple of 256 KiB).
    pub default_chunk_size: u64,
    /// Move deleted files to Drive Trash instead of permanently deleting them.
    pub use_trash_on_delete: bool,
    /// When enabled, `list_stream` synchronizes the durable `gdrive_nodes` ID graph via
    /// `changes.list` and projects listings from local SQLite inventory instead of
    /// recursively crawling Drive folders on every run.
    pub use_changes_feed: bool,
    /// When enabled (`--drive-stop-on-upload-limit`), treat HTTP `403 userRateLimitExceeded`
    /// with `"User rate limit exceeded."` as a fatal `ErrorKind::QuotaExceeded` (750 GiB/day cap)
    /// so transfers fail fast instead of retrying.
    pub stop_on_upload_limit: bool,
    /// Only list/query files shared with the user (`sharedWithMe = true`) at root.
    pub shared_with_me: bool,
    /// Only list/query trashed files (`trashed = true`).
    pub trashed_only: bool,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl GdriveConfig {
    pub fn new(remote_name: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            upload_base_url: DEFAULT_UPLOAD_BASE_URL.to_string(),
            token_url: DEFAULT_TOKEN_URL.to_string(),
            auth_url: DEFAULT_AUTH_URL.to_string(),
            root_folder_id: "root".to_string(),
            shared_drive_id: None,
            scope: DEFAULT_SCOPE.to_string(),
            write_qps: Some(GDRIVE_DEFAULT_WRITE_QPS),
            single_shot_max_bytes: GDRIVE_SINGLE_SHOT_MAX_BYTES,
            default_chunk_size: GDRIVE_DEFAULT_CHUNK_SIZE,
            use_trash_on_delete: true,
            use_changes_feed: false,
            stop_on_upload_limit: false,
            shared_with_me: false,
            trashed_only: false,
            max_retries: 6,
            base_retry_delay: Duration::from_millis(200),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    /// Returns `true` when this backend targets Google Drive's hidden `appDataFolder`
    /// space (`drive.appfolder` / `drive.appdata` scope or `root_folder_id == "appDataFolder"`).
    pub fn is_app_data_folder(&self) -> bool {
        if self.root_folder_id == "appDataFolder" {
            return true;
        }
        if self.shared_drive_id.is_some()
            || (!self.root_folder_id.is_empty() && self.root_folder_id != "root")
            || self.scope.trim().is_empty()
        {
            return false;
        }
        let resolved = resolve_gdrive_scope(&self.scope);
        resolved
            .split_ascii_whitespace()
            .all(|s| s == "https://www.googleapis.com/auth/drive.appdata")
    }

    /// Stable corpus ID used to scope `gdrive_nodes` and `change_tokens`.
    pub fn corpus_id(&self) -> &str {
        self.shared_drive_id
            .as_deref()
            .unwrap_or_else(|| self.effective_root_id())
    }

    /// Effective starting root folder ID (Shared Drive ID or `"appDataFolder"` when
    /// `root_folder_id` is `"root"` or empty).
    pub fn effective_root_id(&self) -> &str {
        if let Some(drive_id) = &self.shared_drive_id
            && (self.root_folder_id.is_empty() || self.root_folder_id == "root")
        {
            return drive_id;
        }
        if self.is_app_data_folder()
            && (self.root_folder_id.is_empty() || self.root_folder_id == "root")
        {
            return "appDataFolder";
        }
        if self.root_folder_id.is_empty() {
            "root"
        } else {
            &self.root_folder_id
        }
    }

    pub fn with_root_folder_id(mut self, id: impl Into<String>) -> Self {
        self.root_folder_id = id.into();
        self
    }

    pub fn with_shared_drive_id(mut self, id: impl Into<String>) -> Self {
        self.shared_drive_id = Some(id.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    pub fn with_write_qps(mut self, qps: Option<f64>) -> Self {
        self.write_qps = qps;
        self
    }

    pub fn with_default_chunk_size(mut self, bytes: u64) -> Self {
        self.default_chunk_size = bytes;
        self
    }

    pub fn with_use_trash_on_delete(mut self, use_trash: bool) -> Self {
        self.use_trash_on_delete = use_trash;
        self
    }

    pub fn with_use_changes_feed(mut self, enabled: bool) -> Self {
        self.use_changes_feed = enabled;
        self
    }

    pub fn with_stop_on_upload_limit(mut self, stop: bool) -> Self {
        self.stop_on_upload_limit = stop;
        self
    }

    pub fn with_shared_with_me(mut self, enabled: bool) -> Self {
        self.shared_with_me = enabled;
        self
    }

    pub fn with_trashed_only(mut self, enabled: bool) -> Self {
        self.trashed_only = enabled;
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = url.into();
        self
    }

    pub fn with_upload_base_url(mut self, url: impl Into<String>) -> Self {
        self.upload_base_url = url.into();
        self
    }
}

/// Resolve a comma- or whitespace-separated list of Google Drive scope aliases or full
/// OAuth2 scope URLs into a space-delimited canonical scope string.
pub fn resolve_gdrive_scope(raw: &str) -> String {
    let mut resolved: Vec<String> = Vec::new();
    for token in raw.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mapped = match trimmed.to_ascii_lowercase().as_str() {
            "drive" | "full" => DEFAULT_SCOPE.to_string(),
            "drive.readonly" | "readonly" | "read_only" => {
                "https://www.googleapis.com/auth/drive.readonly".to_string()
            }
            "drive.file" | "file" => "https://www.googleapis.com/auth/drive.file".to_string(),
            "drive.appfolder" | "drive.appdata" | "appfolder" | "appdata" => {
                "https://www.googleapis.com/auth/drive.appdata".to_string()
            }
            "drive.metadata.readonly" => {
                "https://www.googleapis.com/auth/drive.metadata.readonly".to_string()
            }
            "drive.metadata" => "https://www.googleapis.com/auth/drive.metadata".to_string(),
            "drive.photos.readonly" => {
                "https://www.googleapis.com/auth/drive.photos.readonly".to_string()
            }
            lower if lower.starts_with("https://") || lower.starts_with("http://") => {
                trimmed.to_string()
            }
            _ => format!("https://www.googleapis.com/auth/{trimmed}"),
        };
        if !resolved.contains(&mapped) {
            resolved.push(mapped);
        }
    }
    if resolved.is_empty() {
        DEFAULT_SCOPE.to_string()
    } else {
        resolved.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_trash_on_delete_and_resolves_scopes() {
        let cfg = GdriveConfig::new("gd");
        assert!(cfg.use_trash_on_delete);
        assert!(!cfg.shared_with_me);
        assert!(!cfg.trashed_only);
        assert!(!cfg.is_app_data_folder());
        assert_eq!(cfg.effective_root_id(), "root");

        assert_eq!(resolve_gdrive_scope(""), DEFAULT_SCOPE);
        assert_eq!(resolve_gdrive_scope("   "), DEFAULT_SCOPE);
        assert_eq!(resolve_gdrive_scope("full"), DEFAULT_SCOPE);
        assert_eq!(
            resolve_gdrive_scope("readonly"),
            "https://www.googleapis.com/auth/drive.readonly"
        );
        assert_eq!(
            resolve_gdrive_scope("drive.appfolder"),
            "https://www.googleapis.com/auth/drive.appdata"
        );
        assert_eq!(
            resolve_gdrive_scope("drive.readonly, drive.metadata.readonly, drive.readonly"),
            "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.metadata.readonly"
        );
        assert_eq!(
            resolve_gdrive_scope("https://www.googleapis.com/auth/drive.file"),
            "https://www.googleapis.com/auth/drive.file"
        );

        let app_cfg = GdriveConfig::new("app").with_scope("drive.appfolder");
        assert!(app_cfg.is_app_data_folder());
        assert_eq!(app_cfg.effective_root_id(), "appDataFolder");
        assert_eq!(app_cfg.corpus_id(), "appDataFolder");

        let multi_cfg = GdriveConfig::new("multi").with_scope("drive,drive.appfolder");
        assert!(!multi_cfg.is_app_data_folder());
        assert_eq!(multi_cfg.effective_root_id(), "root");
    }
}
