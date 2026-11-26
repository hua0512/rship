//! Google Cloud Storage backend configuration, scope aliases, and strict object-name URL encoding.

use std::time::Duration;

pub const DEFAULT_GCS_API_URL: &str = "https://storage.googleapis.com/storage/v1";
pub const DEFAULT_GCS_UPLOAD_URL: &str = "https://storage.googleapis.com/upload/storage/v1";
pub const DEFAULT_GCS_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const DEFAULT_GCS_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const DEFAULT_GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.full_control";

/// GCS requires non-final resumable upload chunks to be exact multiples of 256 KiB.
pub const GCS_CHUNK_ALIGN_BYTES: u64 = 256 * 1024;
/// Default resumable chunk size (16 MiB = 64 × 256 KiB).
pub const DEFAULT_GCS_CHUNK_SIZE: u64 = 16 * 1024 * 1024;
/// Default threshold below which single-shot `uploadType=multipart` is used (8 MiB).
pub const DEFAULT_GCS_SINGLE_SHOT_MAX: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GcsConfig {
    pub remote_name: String,
    pub bucket: String,
    pub prefix: String,
    pub project_number: Option<String>,
    pub user_project: Option<String>,
    pub storage_class: Option<String>,
    pub api_base_url: String,
    pub upload_base_url: String,
    pub auth_url: String,
    pub token_url: String,
    pub scope: String,
    pub chunk_size: u64,
    pub single_shot_max_bytes: u64,
    pub anonymous: bool,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl GcsConfig {
    pub fn new(remote_name: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            bucket: bucket.into(),
            prefix: String::new(),
            project_number: None,
            user_project: None,
            storage_class: None,
            api_base_url: DEFAULT_GCS_API_URL.to_string(),
            upload_base_url: DEFAULT_GCS_UPLOAD_URL.to_string(),
            auth_url: DEFAULT_GCS_AUTH_URL.to_string(),
            token_url: DEFAULT_GCS_TOKEN_URL.to_string(),
            scope: DEFAULT_GCS_SCOPE.to_string(),
            chunk_size: DEFAULT_GCS_CHUNK_SIZE,
            single_shot_max_bytes: DEFAULT_GCS_SINGLE_SHOT_MAX,
            anonymous: false,
            max_retries: 5,
            base_retry_delay: Duration::from_millis(200),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_user_project(mut self, project: impl Into<String>) -> Self {
        let project = project.into();
        let trimmed = project.trim();
        self.user_project = (!trimmed.is_empty()).then(|| trimmed.to_string());
        self
    }

    /// Effective `userProject` billing project ID (`user_project` falling back to `project_number`).
    pub fn effective_user_project(&self) -> Option<&str> {
        self.user_project
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.project_number
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
    }

    /// Normalize configured prefix to either `""` or `"prefix/"`.
    pub fn normalized_prefix(&self) -> String {
        let trimmed = self.prefix.trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}/")
        }
    }

    /// Join `self.prefix` and a relative object key into the full bucket object name.
    pub fn full_key(&self, rel: &str) -> String {
        let p = self.normalized_prefix();
        let r = rel.trim_start_matches('/');
        if p.is_empty() {
            r.to_string()
        } else if r.is_empty() {
            p
        } else {
            format!("{p}{r}")
        }
    }

    /// Strip `self.prefix` from a full bucket object name, returning `None` if outside prefix.
    pub fn strip_prefix<'a>(&self, full: &'a str) -> Option<&'a str> {
        let p = self.normalized_prefix();
        if p.is_empty() {
            Some(full)
        } else {
            full.strip_prefix(&p)
        }
    }

    /// Round `chunk_size` cleanly to a valid multiple of 256 KiB.
    pub fn aligned_chunk_size(&self) -> u64 {
        let aligned = (self.chunk_size / GCS_CHUNK_ALIGN_BYTES) * GCS_CHUNK_ALIGN_BYTES;
        aligned.max(GCS_CHUNK_ALIGN_BYTES)
    }

    /// Configure both `api_base_url` and `upload_base_url` from a root or `/storage/v1` endpoint.
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        let (api, upload) = resolve_gcs_endpoint_urls(endpoint);
        self.api_base_url = api;
        self.upload_base_url = upload;
        self
    }
}

/// Derive `(api_base_url, upload_base_url)` from a custom GCS endpoint root (such as
/// `http://127.0.0.1:4443` for `fake-gcs-server` or `https://storage.mycorp.internal`).
pub fn resolve_gcs_endpoint_urls(endpoint: &str) -> (String, String) {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let root = trimmed
        .strip_suffix("/upload/storage/v1")
        .or_else(|| trimmed.strip_suffix("/storage/v1"))
        .unwrap_or(trimmed);
    (
        format!("{root}/storage/v1"),
        format!("{root}/upload/storage/v1"),
    )
}

/// Resolve friendly GCS OAuth scope aliases into full Google scope URLs.
pub fn resolve_gcs_scope(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "full" | "full_control" | "devstorage.full_control" => {
            "https://www.googleapis.com/auth/devstorage.full_control".to_string()
        }
        "read_write" | "rw" | "devstorage.read_write" => {
            "https://www.googleapis.com/auth/devstorage.read_write".to_string()
        }
        "read_only" | "readonly" | "ro" | "devstorage.read_only" => {
            "https://www.googleapis.com/auth/devstorage.read_only".to_string()
        }
        "cloud-platform" | "cloud_platform" => {
            "https://www.googleapis.com/auth/cloud-platform".to_string()
        }
        _ => raw.trim().to_string(),
    }
}

/// Strict RFC 3986 single-segment percent encoding required by GCS JSON API `/b/{bucket}/o/{object}`:
/// encodes `/` as `%2F`, `#` as `%23`, `?` as `%3F`, `+` as `%2B`, `%` as `%25`, spaces as `%20`,
/// and all non-ASCII UTF-8 bytes.
pub fn gcs_encode_object_name(input: &str) -> String {
    crate::common::http::percent_encode_segment(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_gcs_object_names_with_slashes_special_chars_and_utf8() {
        assert_eq!(
            gcs_encode_object_name("dir/a + b #1?x=1%20/中文.txt"),
            "dir%2Fa%20%2B%20b%20%231%3Fx%3D1%2520%2F%E4%B8%AD%E6%96%87.txt"
        );
        assert_eq!(
            gcs_encode_object_name("safe_file-1.0~v2"),
            "safe_file-1.0~v2"
        );
    }

    #[test]
    fn resolves_scope_aliases_and_prefixes() {
        assert_eq!(
            resolve_gcs_scope("read_only"),
            "https://www.googleapis.com/auth/devstorage.read_only"
        );
        assert_eq!(resolve_gcs_scope("full"), DEFAULT_GCS_SCOPE);
        let mut cfg = GcsConfig::new("gcs", "my-bucket");
        cfg.prefix = "/archive/2026/".into();
        assert_eq!(cfg.full_key("a/b.bin"), "archive/2026/a/b.bin");
        assert_eq!(cfg.strip_prefix("archive/2026/a/b.bin"), Some("a/b.bin"));
        assert_eq!(cfg.strip_prefix("other/a.bin"), None);

        let (api, up) = resolve_gcs_endpoint_urls("http://127.0.0.1:4443/");
        assert_eq!(api, "http://127.0.0.1:4443/storage/v1");
        assert_eq!(up, "http://127.0.0.1:4443/upload/storage/v1");
        let (api2, up2) = resolve_gcs_endpoint_urls("http://127.0.0.1:4443/storage/v1");
        assert_eq!(api2, "http://127.0.0.1:4443/storage/v1");
        assert_eq!(up2, "http://127.0.0.1:4443/upload/storage/v1");
    }

    #[test]
    fn user_project_prefers_explicit_over_project_number_and_ignores_blank() {
        let mut cfg = GcsConfig::new("gcs", "bkt");
        assert_eq!(cfg.user_project, None);
        assert_eq!(cfg.effective_user_project(), None);

        cfg.project_number = Some(" 12345 ".to_string());
        assert_eq!(cfg.effective_user_project(), Some("12345"));

        let cfg_with_up = cfg.clone().with_user_project(" pay-proj ");
        assert_eq!(cfg_with_up.user_project.as_deref(), Some("pay-proj"));
        assert_eq!(cfg_with_up.effective_user_project(), Some("pay-proj"));

        let cfg_blank = cfg.with_user_project("   ");
        assert_eq!(cfg_blank.user_project, None);
        assert_eq!(cfg_blank.effective_user_project(), Some("12345"));
    }
}
