//! Microsoft OneDrive & SharePoint backend configuration.

use std::time::Duration;

use crate::common::http::RetryPolicyConfig;

pub const DEFAULT_GRAPH_API_URL: &str = "https://graph.microsoft.com/v1.0";
pub const DEFAULT_ONEDRIVE_AUTH_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
pub const DEFAULT_ONEDRIVE_TOKEN_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";
pub const DEFAULT_ONEDRIVE_SCOPE: &str = "Files.ReadWrite.All offline_access";

/// Microsoft Graph sovereign cloud regions supported by OneDrive / SharePoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnedriveRegion {
    #[default]
    Global,
    Us,
    De,
    Cn,
}

impl OnedriveRegion {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "global" => Some(Self::Global),
            "us" => Some(Self::Us),
            "de" => Some(Self::De),
            "cn" => Some(Self::Cn),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Us => "us",
            Self::De => "de",
            Self::Cn => "cn",
        }
    }

    /// Return `(api_base_url, auth_url, token_url)` for this cloud region.
    pub fn endpoints(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Global => (
                "https://graph.microsoft.com/v1.0",
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            ),
            Self::Us => (
                "https://graph.microsoft.us/v1.0",
                "https://login.microsoftonline.us/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.us/common/oauth2/v2.0/token",
            ),
            Self::De => (
                "https://graph.microsoft.de/v1.0",
                "https://login.microsoftonline.de/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.de/common/oauth2/v2.0/token",
            ),
            Self::Cn => (
                "https://microsoftgraph.chinacloudapi.cn/v1.0",
                "https://login.chinacloudapi.cn/common/oauth2/v2.0/authorize",
                "https://login.chinacloudapi.cn/common/oauth2/v2.0/token",
            ),
        }
    }
}

/// Microsoft OneDrive drive flavor (`personal`, `business`, `documentLibrary`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnedriveDriveType {
    Personal,
    Business,
    DocumentLibrary,
}

impl OnedriveDriveType {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "personal" => Some(Self::Personal),
            "business" => Some(Self::Business),
            "documentlibrary" | "document_library" | "sharepoint" => Some(Self::DocumentLibrary),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Business => "business",
            Self::DocumentLibrary => "documentLibrary",
        }
    }

    /// Business and SharePoint Document Library drives only report `quickXorHash` (never
    /// `sha256Hash` or `sha1Hash`).
    pub fn is_business_or_sharepoint(self) -> bool {
        matches!(self, Self::Business | Self::DocumentLibrary)
    }
}

/// Microsoft Graph requires every non-final upload session chunk to be a strict multiple of 320 KiB.
pub const ONEDRIVE_CHUNK_ALIGN_BYTES: u64 = 320 * 1024;
/// Microsoft Graph hard per-chunk ceiling: 60 MiB (192 * 320 KiB).
pub const MAX_ONEDRIVE_CHUNK_BYTES: u64 = 60 * 1024 * 1024;
/// Graph single-shot simple upload ceiling: 4 MiB.
pub const DEFAULT_ONEDRIVE_SINGLE_SHOT_MAX: u64 = 4 * 1024 * 1024;
/// Default resumable chunk size: 10 MiB (32 * 320 KiB = 10,485,760 bytes, exact multiple of 320 KiB).
pub const DEFAULT_ONEDRIVE_CHUNK_SIZE: u64 = 32 * ONEDRIVE_CHUNK_ALIGN_BYTES;

#[derive(Debug, Clone)]
pub struct OnedriveConfig {
    pub remote_name: String,
    /// Optional explicit Graph Drive ID (required for SharePoint Document Libraries;
    /// when `None`, targets `/me/drive`).
    pub drive_id: Option<String>,
    pub region: OnedriveRegion,
    pub drive_type: Option<OnedriveDriveType>,
    pub api_base_url: String,
    pub auth_url: String,
    pub token_url: String,
    pub scope: String,
    pub single_shot_max_bytes: u64,
    pub default_chunk_size: u64,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl OnedriveConfig {
    pub fn new(remote_name: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            drive_id: None,
            region: OnedriveRegion::Global,
            drive_type: None,
            api_base_url: DEFAULT_GRAPH_API_URL.to_string(),
            auth_url: DEFAULT_ONEDRIVE_AUTH_URL.to_string(),
            token_url: DEFAULT_ONEDRIVE_TOKEN_URL.to_string(),
            scope: DEFAULT_ONEDRIVE_SCOPE.to_string(),
            single_shot_max_bytes: DEFAULT_ONEDRIVE_SINGLE_SHOT_MAX,
            default_chunk_size: DEFAULT_ONEDRIVE_CHUNK_SIZE,
            max_retries: 5,
            base_retry_delay: Duration::from_millis(250),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    pub fn with_region(mut self, region: OnedriveRegion) -> Self {
        let (prev_api, prev_auth, prev_tok) = self.region.endpoints();
        let (api, auth, tok) = region.endpoints();
        if self.api_base_url == prev_api || self.api_base_url == DEFAULT_GRAPH_API_URL {
            self.api_base_url = api.to_string();
        }
        if self.auth_url == prev_auth || self.auth_url == DEFAULT_ONEDRIVE_AUTH_URL {
            self.auth_url = auth.to_string();
        }
        if self.token_url == prev_tok || self.token_url == DEFAULT_ONEDRIVE_TOKEN_URL {
            self.token_url = tok.to_string();
        }
        self.region = region;
        self
    }

    pub fn with_drive_type(mut self, drive_type: OnedriveDriveType) -> Self {
        self.drive_type = Some(drive_type);
        self
    }

    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.default_chunk_size = chunk_size;
        self
    }

    pub fn is_business_or_sharepoint(&self) -> bool {
        self.drive_type
            .is_some_and(OnedriveDriveType::is_business_or_sharepoint)
    }

    /// Resolve region endpoints without clobbering explicit custom URLs.
    pub(crate) fn with_resolved_region_endpoints(self) -> Self {
        let region = self.region;
        self.with_region(region)
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

    /// Resolve `{api_base_url}/drives/{drive_id}` or `{api_base_url}/me/drive`.
    pub fn drive_base_url(&self) -> String {
        let base = self.api_base_url.trim_end_matches('/');
        match self.drive_id.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(id) => format!("{base}/drives/{}", id.trim()),
            None => format!("{base}/me/drive"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scope_omits_user_read() {
        assert!(!DEFAULT_ONEDRIVE_SCOPE.contains("User.Read"));
        assert!(DEFAULT_ONEDRIVE_SCOPE.contains("Files.ReadWrite.All"));
        assert!(DEFAULT_ONEDRIVE_SCOPE.contains("offline_access"));
    }

    #[test]
    fn region_resolves_sovereign_endpoints_without_clobbering_custom_urls() {
        let cn = OnedriveConfig::new("od-cn").with_region(OnedriveRegion::Cn);
        assert_eq!(
            cn.api_base_url,
            "https://microsoftgraph.chinacloudapi.cn/v1.0"
        );
        assert_eq!(
            cn.auth_url,
            "https://login.chinacloudapi.cn/common/oauth2/v2.0/authorize"
        );
        assert_eq!(
            cn.token_url,
            "https://login.chinacloudapi.cn/common/oauth2/v2.0/token"
        );

        let us = OnedriveConfig::new("od-us").with_region(OnedriveRegion::Us);
        assert_eq!(us.api_base_url, "https://graph.microsoft.us/v1.0");
        let de = OnedriveConfig::new("od-de").with_region(OnedriveRegion::De);
        assert_eq!(de.api_base_url, "https://graph.microsoft.de/v1.0");

        let mut custom = OnedriveConfig::new("od-custom");
        custom.api_base_url = "https://mock.local/v1.0".to_string();
        let custom = custom.with_region(OnedriveRegion::Cn);
        assert_eq!(custom.api_base_url, "https://mock.local/v1.0");
        assert_eq!(
            custom.token_url,
            "https://login.chinacloudapi.cn/common/oauth2/v2.0/token"
        );
    }
}
