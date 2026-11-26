//! WebDAV remote configuration and vendor profiles.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

use crate::common::http::RetryPolicyConfig;

pub const DEFAULT_WEBDAV_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB (Nextcloud v2 friendly)
pub const DEFAULT_WEBDAV_SINGLE_SHOT_MAX: u64 = 10 * 1024 * 1024;
pub const MAX_NEXTCLOUD_CHUNK_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebdavChunkNaming {
    /// Nextcloud Chunking v2 (28+ / S3 direct multipart): `1..=10000`.
    NumericPart,
    /// ownCloud Chunking v2: `{offset:016}-{end_exclusive:016}`.
    ByteRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebdavVendor {
    Nextcloud,
    Owncloud,
    Alist,
    Synology,
    Infinicloud,
    #[default]
    Generic,
}

impl WebdavVendor {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "nextcloud" => Some(Self::Nextcloud),
            "owncloud" => Some(Self::Owncloud),
            "alist" | "openlist" => Some(Self::Alist),
            "synology" => Some(Self::Synology),
            "infinicloud" => Some(Self::Infinicloud),
            "other" | "generic" | "" => Some(Self::Generic),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nextcloud => "nextcloud",
            Self::Owncloud => "owncloud",
            Self::Alist => "alist",
            Self::Synology => "synology",
            Self::Infinicloud => "infinicloud",
            Self::Generic => "generic",
        }
    }

    /// Whether this vendor supports Nextcloud/OwnCloud Chunked Upload v2
    /// (`/remote.php/dav/uploads/<user>/<op_id>` or `/dav/uploads/<user>/<op_id>`).
    pub fn supports_chunked_v2(self) -> bool {
        matches!(self, Self::Nextcloud | Self::Owncloud)
    }

    /// Whether this vendor supports the `X-OC-Mtime` header on `PUT` / `MOVE .file`
    /// to preserve Unix second-granularity modification times.
    pub fn supports_oc_mtime(self) -> bool {
        matches!(self, Self::Nextcloud | Self::Owncloud)
    }

    /// Whether this vendor understands the Nextcloud/ownCloud checksum headers: `X-Hash`
    /// on `PUT` (the server returns `X-Hash-MD5` computed while writing), `OC-Checksum` on
    /// `PUT`/`MOVE` (ownCloud validates it, Nextcloud stores it), and `OC-Checksum` on `GET`.
    /// Other vendors expose no content hash, so transfers to and from them are unverified.
    pub fn supports_oc_checksums(self) -> bool {
        matches!(self, Self::Nextcloud | Self::Owncloud)
    }

    /// Chunk filename convention inside the chunked-v2 staging collection.
    pub fn chunk_naming(self) -> WebdavChunkNaming {
        match self {
            Self::Nextcloud => WebdavChunkNaming::NumericPart,
            _ => WebdavChunkNaming::ByteRange,
        }
    }
}

#[derive(Clone, Default)]
pub enum WebdavAuth {
    #[default]
    None,
    Basic {
        username: String,
        password: String,
    },
    Bearer {
        token: String,
    },
}

impl std::fmt::Debug for WebdavAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Bearer { .. } => f
                .debug_struct("Bearer")
                .field("token", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct WebdavConfig {
    pub remote_name: String,
    /// Root WebDAV URL (e.g., `https://cloud.example.com/remote.php/dav/files/alice/`).
    pub url: String,
    pub vendor: WebdavVendor,
    pub auth: WebdavAuth,
    /// Optional custom HTTP headers applied to all WebDAV control and data requests.
    pub headers: Vec<(String, String)>,
    /// Optional explicit Nextcloud/OwnCloud chunked upload root URL
    /// (auto-derived from `/remote.php/dav/files/<user>` or `/dav/files/<user>` when omitted).
    pub chunked_upload_root: Option<String>,
    pub single_shot_max_bytes: Option<u64>,
    pub default_chunk_size: Option<u64>,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl std::fmt::Debug for WebdavConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, _)| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_struct("WebdavConfig")
            .field("remote_name", &self.remote_name)
            .field("url", &self.url)
            .field("vendor", &self.vendor)
            .field("auth", &self.auth)
            .field("headers", &redacted_headers)
            .field("chunked_upload_root", &self.chunked_upload_root)
            .field("single_shot_max_bytes", &self.single_shot_max_bytes)
            .field("default_chunk_size", &self.default_chunk_size)
            .field("max_retries", &self.max_retries)
            .field("base_retry_delay", &self.base_retry_delay)
            .field("max_retry_delay", &self.max_retry_delay)
            .finish()
    }
}

impl WebdavConfig {
    pub fn new(remote_name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            url: url.into(),
            vendor: WebdavVendor::Generic,
            auth: WebdavAuth::None,
            headers: Vec::new(),
            chunked_upload_root: None,
            single_shot_max_bytes: None,
            default_chunk_size: None,
            max_retries: 5,
            base_retry_delay: Duration::from_millis(200),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
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

    pub fn normalized_base_url(&self) -> String {
        self.url.trim().trim_end_matches('/').to_string()
    }

    /// Resolve the Nextcloud/OwnCloud/oCIS v2 chunked upload base URL if chunking is supported.
    pub fn resolve_chunked_upload_root(&self) -> Option<String> {
        if !self.vendor.supports_chunked_v2() {
            return None;
        }
        if let Some(custom) = &self.chunked_upload_root {
            let trimmed = custom.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return Some(normalize_url_preserving_encoding(trimmed));
            }
        }
        let base = normalize_url_preserving_encoding(&self.normalized_base_url());
        // Standard Nextcloud/OwnCloud layout:
        //   https://host/remote.php/dav/files/<user>[/optional/subpath]
        // -> https://host/remote.php/dav/uploads/<user>
        if let Some((prefix, rest)) = base.split_once("/remote.php/dav/files/") {
            let user = rest.split('/').next().unwrap_or("").trim();
            if !user.is_empty() {
                return Some(format!("{prefix}/remote.php/dav/uploads/{user}"));
            }
        }
        // oCIS / short WebDAV layout:
        //   https://host[/prefix]/dav/files/<user>[/optional/subpath]
        // -> https://host[/prefix]/dav/uploads/<user>
        if let Some((prefix, rest)) = base.split_once("/dav/files/") {
            let user = rest.split('/').next().unwrap_or("").trim();
            if !user.is_empty() {
                return Some(format!("{prefix}/dav/uploads/{user}"));
            }
        }
        None
    }
}

fn normalize_url_preserving_encoding(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.as_str().trim_end_matches('/').to_string()
        }
        Err(_) => raw.trim().trim_end_matches('/').to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_chunked_upload_root_supports_nextcloud_owncloud_and_ocis_and_encodes_user() {
        let mut nc = WebdavConfig::new(
            "nc",
            "https://cloud.example.com/remote.php/dav/files/alice/sub/dir",
        );
        nc.vendor = WebdavVendor::Nextcloud;
        assert_eq!(
            nc.resolve_chunked_upload_root().as_deref(),
            Some("https://cloud.example.com/remote.php/dav/uploads/alice")
        );

        let mut ocis = WebdavConfig::new("ocis", "https://ocis.example.com/dav/files/alice bob");
        ocis.vendor = WebdavVendor::Nextcloud;
        assert_eq!(
            ocis.resolve_chunked_upload_root().as_deref(),
            Some("https://ocis.example.com/dav/uploads/alice%20bob")
        );

        let mut ocis_prefixed = WebdavConfig::new(
            "ocis-prefix",
            "https://ocis.example.com/owncloud/dav/files/alice/docs",
        );
        ocis_prefixed.vendor = WebdavVendor::Owncloud;
        assert_eq!(
            ocis_prefixed.resolve_chunked_upload_root().as_deref(),
            Some("https://ocis.example.com/owncloud/dav/uploads/alice")
        );

        let generic = WebdavConfig::new("gen", "https://dav.example.com/dav/files/alice");
        assert_eq!(generic.resolve_chunked_upload_root(), None);
    }

    #[test]
    fn vendor_capabilities_split_chunked_mtime_checksums_and_chunk_naming() {
        assert!(WebdavVendor::Nextcloud.supports_chunked_v2());
        assert!(WebdavVendor::Nextcloud.supports_oc_mtime());
        assert!(WebdavVendor::Nextcloud.supports_oc_checksums());
        assert_eq!(
            WebdavVendor::Nextcloud.chunk_naming(),
            WebdavChunkNaming::NumericPart
        );

        assert!(WebdavVendor::Owncloud.supports_chunked_v2());
        assert!(WebdavVendor::Owncloud.supports_oc_mtime());
        assert!(WebdavVendor::Owncloud.supports_oc_checksums());
        assert_eq!(
            WebdavVendor::Owncloud.chunk_naming(),
            WebdavChunkNaming::ByteRange
        );

        for v in [
            WebdavVendor::Alist,
            WebdavVendor::Synology,
            WebdavVendor::Infinicloud,
            WebdavVendor::Generic,
        ] {
            assert!(!v.supports_chunked_v2());
            assert!(!v.supports_oc_mtime());
            assert!(!v.supports_oc_checksums());
        }
    }
}
