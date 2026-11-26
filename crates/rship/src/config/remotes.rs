use rship_core::types::BackendKind;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::secrets::is_keyring_ref;

use super::REDACTED_SECRET;

fn debug_secret_opt(opt: &Option<String>) -> Option<&str> {
    opt.as_deref().map(|v| {
        if is_keyring_ref(v) {
            v
        } else {
            REDACTED_SECRET
        }
    })
}

fn debug_secret_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| {
            let shown = if is_keyring_ref(v) {
                v.as_str()
            } else {
                REDACTED_SECRET
            };
            (k.as_str(), shown)
        })
        .collect()
}

fn redact_opt(field: &mut Option<String>) {
    if let Some(v) = field.as_mut()
        && !is_keyring_ref(v)
    {
        *v = REDACTED_SECRET.to_string();
    }
}

/// Declarative Google Drive v3 remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GdriveRemoteConfig {
    /// OAuth 2.0 Desktop client ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// OAuth 2.0 client secret (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Starting folder ID (`"root"` for My Drive, or a specific folder/Shared Drive ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_folder_id: Option<String>,
    /// Optional Google Shared Drive (`team_drive`) ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_drive_id: Option<String>,
    /// OAuth scope URL or alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Path to a Google Service Account JSON key file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_file: Option<PathBuf>,
    /// Domain-Wide Delegation user email (`sub` claim) for Service Accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonate: Option<String>,
    /// Move deleted items to Trash instead of permanently deleting them (default: `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_trash: Option<bool>,
    /// Enable incremental `changes.list` local SQLite inventory syncing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_changes_feed: Option<bool>,
    /// Only list/query files shared with the user (`sharedWithMe = true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with_me: Option<bool>,
    /// Only list/query trashed files (`trashed = true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_only: Option<bool>,
    /// Per-remote file creation/write QPS ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_qps: Option<f64>,
    /// Fast-fail with `QuotaExceeded` on HTTP `403 userRateLimitExceeded` uploads (750 GiB/day cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_on_upload_limit: Option<bool>,
    /// Per-remote low-level HTTP retry limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    /// Custom Google Drive API base URL (testing/proxies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Custom Google Drive upload base URL (testing/proxies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_base_url: Option<String>,
    /// Custom OAuth token endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// Custom OAuth authorization endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// Optional static Bearer access token (testing or short-lived automation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl GdriveRemoteConfig {
    /// Create an empty Google Drive remote configuration ready for fluent customization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the OAuth 2.0 client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the OAuth 2.0 client secret (inline or `keyring://rship/...`).
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the starting Google Drive folder ID (`"root"` or specific folder ID).
    pub fn with_root_folder_id(mut self, folder_id: impl Into<String>) -> Self {
        self.root_folder_id = Some(folder_id.into());
        self
    }

    /// Set the Google Shared Drive (`team_drive`) ID.
    pub fn with_shared_drive_id(mut self, drive_id: impl Into<String>) -> Self {
        self.shared_drive_id = Some(drive_id.into());
        self
    }

    /// Set the OAuth scope URL or alias.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the path to a Google Service Account JSON key file.
    pub fn with_service_account_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.service_account_file = Some(path.into());
        self
    }

    /// Set the Domain-Wide Delegation user email (`sub` claim) for Service Accounts.
    pub fn with_impersonate(mut self, email: impl Into<String>) -> Self {
        self.impersonate = Some(email.into());
        self
    }

    /// Control whether deletes move files to Trash (`true`) or delete permanently (`false`).
    pub fn with_use_trash(mut self, use_trash: bool) -> Self {
        self.use_trash = Some(use_trash);
        self
    }

    /// Enable or disable incremental `changes.list` local SQLite inventory syncing.
    pub fn with_use_changes_feed(mut self, enabled: bool) -> Self {
        self.use_changes_feed = Some(enabled);
        self
    }

    /// Filter listings to files shared with the user (`sharedWithMe = true`).
    pub fn with_shared_with_me(mut self, enabled: bool) -> Self {
        self.shared_with_me = Some(enabled);
        self
    }

    /// Filter listings to trashed files (`trashed = true`).
    pub fn with_trashed_only(mut self, enabled: bool) -> Self {
        self.trashed_only = Some(enabled);
        self
    }

    /// Set the per-remote file creation/write QPS ceiling.
    pub fn with_write_qps(mut self, qps: f64) -> Self {
        self.write_qps = Some(qps);
        self
    }

    /// Fast-fail on HTTP `403 userRateLimitExceeded` daily upload quota errors.
    pub fn with_stop_on_upload_limit(mut self, stop: bool) -> Self {
        self.stop_on_upload_limit = Some(stop);
        self
    }

    /// Set the per-remote low-level HTTP retry limit.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Override the Google Drive API base URL (testing or custom proxies).
    pub fn with_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Override the Google Drive upload base URL (testing or custom proxies).
    pub fn with_upload_base_url(mut self, url: impl Into<String>) -> Self {
        self.upload_base_url = Some(url.into());
        self
    }

    /// Override the OAuth token endpoint URL.
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Override the OAuth authorization endpoint URL.
    pub fn with_auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Set a static Bearer access token (testing or short-lived automation).
    pub fn with_access_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for GdriveRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GdriveRemoteConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &debug_secret_opt(&self.client_secret))
            .field("root_folder_id", &self.root_folder_id)
            .field("shared_drive_id", &self.shared_drive_id)
            .field("scope", &self.scope)
            .field("service_account_file", &self.service_account_file)
            .field("impersonate", &self.impersonate)
            .field("use_trash", &self.use_trash)
            .field("use_changes_feed", &self.use_changes_feed)
            .field("shared_with_me", &self.shared_with_me)
            .field("trashed_only", &self.trashed_only)
            .field("write_qps", &self.write_qps)
            .field("stop_on_upload_limit", &self.stop_on_upload_limit)
            .field("max_retries", &self.max_retries)
            .field("api_base_url", &self.api_base_url)
            .field("upload_base_url", &self.upload_base_url)
            .field("token_url", &self.token_url)
            .field("auth_url", &self.auth_url)
            .field("access_token", &debug_secret_opt(&self.access_token))
            .finish()
    }
}

/// Declarative S3-compatible remote configuration (AWS, R2, MinIO, OSS, B2, etc.).
#[must_use]
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct S3RemoteConfig {
    /// S3 provider profile name (e.g. `"aws"`, `"r2"`, `"minio"`, `"oss"`, `"b2"`).
    #[serde(default = "default_s3_provider")]
    pub provider: String,
    /// Optional default bucket name (if omitted, `<bucket>/...` is read from target path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Optional key prefix within the bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// S3 region name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Custom S3 endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// AWS Access Key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// AWS Secret Access Key (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    /// Optional AWS STS session token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// Resolve credentials from environment variables, `~/.aws/credentials`, ECS, or EC2 IMDSv2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_auth: Option<bool>,
    /// Named AWS profile in `~/.aws/credentials` / `~/.aws/config` (enables dynamic credential chain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Override path-style vs virtual-hosted-style addressing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_path_style: Option<bool>,
    /// Force real SHA-256 payload signing even over HTTPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_sigv4: Option<bool>,
    /// Payload signing mode override: `"auto"` (default), `"unsigned"`, or `"strict_sha256"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_signing: Option<String>,
    /// Send `If-Match: <etag>` on source `GetObject` range reads (default: `true`; set `false`
    /// for S3 gateways such as older OpenStack Swift S3 that reject or mis-handle `If-Match`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_read_etag: Option<bool>,
    /// Optional storage class header (`x-amz-storage-class`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Server-Side Encryption mode: `"AES256"` (`sse-s3`) or `"aws:kms"` (`sse-kms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse: Option<String>,
    /// Optional AWS KMS Key ID or ARN used when `sse = "aws:kms"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    /// Send native provider checksum headers on uploads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_upload_checksum: Option<bool>,
    /// Parallel prefix listing worker count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_prefix_concurrency: Option<usize>,
}

impl Default for S3RemoteConfig {
    fn default() -> Self {
        Self {
            provider: default_s3_provider(),
            bucket: None,
            prefix: None,
            region: None,
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            env_auth: None,
            profile: None,
            force_path_style: None,
            strict_sigv4: None,
            payload_signing: None,
            pin_read_etag: None,
            storage_class: None,
            sse: None,
            kms_key_id: None,
            send_upload_checksum: None,
            list_prefix_concurrency: None,
        }
    }
}

impl S3RemoteConfig {
    /// Create an S3-compatible remote configuration for `provider` (e.g. `"aws"`, `"r2"`, `"minio"`).
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            ..Self::default()
        }
    }

    /// Set the default S3 bucket name.
    pub fn with_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Set the default object key prefix inside the bucket.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Set the S3 signing/endpoint region.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set a custom S3 endpoint URL (required for R2, MinIO, B2, etc.).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the AWS Access Key ID.
    pub fn with_access_key_id(mut self, access_key_id: impl Into<String>) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self
    }

    /// Set the AWS Secret Access Key (inline or `keyring://rship/...`).
    pub fn with_secret_access_key(mut self, secret_access_key: impl Into<String>) -> Self {
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// Set static `(access_key_id, secret_access_key)` credentials together.
    pub fn with_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// Set an optional AWS STS session token.
    pub fn with_session_token(mut self, session_token: impl Into<String>) -> Self {
        self.session_token = Some(session_token.into());
        self
    }

    /// Enable or disable dynamic AWS credential resolution (`env`, `~/.aws`, ECS, IMDSv2).
    pub fn with_env_auth(mut self, env_auth: bool) -> Self {
        self.env_auth = Some(env_auth);
        self
    }

    /// Select a named AWS profile from `~/.aws/credentials` / `~/.aws/config`.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Override path-style vs virtual-hosted-style bucket addressing.
    pub fn with_force_path_style(mut self, force_path_style: bool) -> Self {
        self.force_path_style = Some(force_path_style);
        self
    }

    /// Force strict SHA-256 payload signing even over HTTPS.
    pub fn with_strict_sigv4(mut self, strict: bool) -> Self {
        self.strict_sigv4 = Some(strict);
        self
    }

    /// Set payload signing mode (`"auto"`, `"unsigned"`, or `"strict_sha256"`).
    pub fn with_payload_signing(mut self, mode: impl Into<String>) -> Self {
        self.payload_signing = Some(mode.into());
        self
    }

    /// Control whether `If-Match: <etag>` is sent on source range reads.
    pub fn with_pin_read_etag(mut self, pin: bool) -> Self {
        self.pin_read_etag = Some(pin);
        self
    }

    /// Set the S3 storage class header (`x-amz-storage-class`).
    pub fn with_storage_class(mut self, storage_class: impl Into<String>) -> Self {
        self.storage_class = Some(storage_class.into());
        self
    }

    /// Set Server-Side Encryption mode (`"AES256"` or `"aws:kms"`).
    pub fn with_sse(mut self, sse: impl Into<String>) -> Self {
        self.sse = Some(sse.into());
        self
    }

    /// Set the AWS KMS key ID or ARN used when `sse = "aws:kms"`.
    pub fn with_kms_key_id(mut self, kms_key_id: impl Into<String>) -> Self {
        self.kms_key_id = Some(kms_key_id.into());
        self
    }

    /// Control whether native checksum headers are attached to uploads.
    pub fn with_send_upload_checksum(mut self, send: bool) -> Self {
        self.send_upload_checksum = Some(send);
        self
    }

    /// Set parallel prefix listing worker concurrency.
    pub fn with_list_prefix_concurrency(mut self, concurrency: usize) -> Self {
        self.list_prefix_concurrency = Some(concurrency);
        self
    }
}

impl std::fmt::Debug for S3RemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3RemoteConfig")
            .field("provider", &self.provider)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &debug_secret_opt(&self.secret_access_key),
            )
            .field("session_token", &debug_secret_opt(&self.session_token))
            .field("env_auth", &self.env_auth)
            .field("profile", &self.profile)
            .field("force_path_style", &self.force_path_style)
            .field("strict_sigv4", &self.strict_sigv4)
            .field("payload_signing", &self.payload_signing)
            .field("pin_read_etag", &self.pin_read_etag)
            .field("storage_class", &self.storage_class)
            .field("sse", &self.sse)
            .field("kms_key_id", &self.kms_key_id)
            .field("send_upload_checksum", &self.send_upload_checksum)
            .field("list_prefix_concurrency", &self.list_prefix_concurrency)
            .finish()
    }
}

fn default_s3_provider() -> String {
    "aws".to_string()
}

/// Declarative Microsoft OneDrive / SharePoint remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OnedriveRemoteConfig {
    /// Microsoft Entra ID Application (client) ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional OAuth client secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Optional specific SharePoint/OneDrive `drive_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_id: Option<String>,
    /// Sovereign Microsoft Cloud region (`"global"`, `"us"`, `"de"`, `"cn"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// OneDrive drive flavor (`"personal"`, `"business"`, `"documentLibrary"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_type: Option<String>,
    /// Resumable upload chunk size in bytes (must be a multiple of 320 KiB, up to 60 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,
    /// OAuth scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Custom Microsoft Graph API base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Custom OAuth authorization endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// Custom OAuth token endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// Optional static Bearer access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl OnedriveRemoteConfig {
    /// Create an empty OneDrive remote configuration ready for fluent customization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Microsoft Entra ID Application (client) ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the OAuth client secret (inline or `keyring://rship/...`).
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Target a specific SharePoint or OneDrive `drive_id`.
    pub fn with_drive_id(mut self, drive_id: impl Into<String>) -> Self {
        self.drive_id = Some(drive_id.into());
        self
    }

    /// Set the Microsoft Graph sovereign cloud region (`"global"`, `"us"`, `"de"`, `"cn"`).
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set the OneDrive drive flavor (`"personal"`, `"business"`, `"documentLibrary"`).
    pub fn with_drive_type(mut self, drive_type: impl Into<String>) -> Self {
        self.drive_type = Some(drive_type.into());
        self
    }

    /// Set the resumable upload chunk size in bytes (320 KiB-aligned, max 60 MiB).
    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = Some(chunk_size);
        self
    }

    /// Set the OAuth scope string.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Override the Microsoft Graph API base URL.
    pub fn with_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Override the OAuth authorization endpoint URL.
    pub fn with_auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Override the OAuth token endpoint URL.
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Set a static Bearer access token.
    pub fn with_access_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for OnedriveRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnedriveRemoteConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &debug_secret_opt(&self.client_secret))
            .field("drive_id", &self.drive_id)
            .field("region", &self.region)
            .field("drive_type", &self.drive_type)
            .field("chunk_size", &self.chunk_size)
            .field("scope", &self.scope)
            .field("api_base_url", &self.api_base_url)
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("access_token", &debug_secret_opt(&self.access_token))
            .finish()
    }
}

/// Declarative WebDAV remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WebdavRemoteConfig {
    /// Base WebDAV endpoint URL.
    pub url: String,
    /// Optional server vendor profile (`nextcloud`, `owncloud`, `alist`, `synology`, `infinicloud`, `generic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Basic auth username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Basic auth password (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Bearer token auth (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    /// External command configured in `rclone.conf` (`bearer_token_command`).
    /// Not executed automatically at runtime; requires explicit `bearer_token` or Basic auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_command: Option<String>,
    /// Custom HTTP headers `(name, value)` applied to all WebDAV requests
    /// (values may use `keyring://rship/...` pointers and are redacted in `Debug`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Custom Nextcloud/OwnCloud chunked upload staging URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunked_upload_root: Option<String>,
}

impl WebdavRemoteConfig {
    /// Create a WebDAV remote configuration targeting `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }

    /// Set the WebDAV server vendor profile (`nextcloud`, `owncloud`, `alist`, `synology`, `infinicloud`, `generic`).
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Set the HTTP Basic auth username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the HTTP Basic auth password (inline or `keyring://rship/...`).
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set HTTP Basic auth `(username, password)` together.
    pub fn with_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Set HTTP Bearer token authentication (inline or `keyring://rship/...`).
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Record an external `bearer_token_command` (not executed automatically).
    pub fn with_bearer_token_command(mut self, cmd: impl Into<String>) -> Self {
        self.bearer_token_command = Some(cmd.into());
        self
    }

    /// Replace custom HTTP headers sent with every WebDAV request.
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// Append a custom HTTP header `(name, value)` to every WebDAV request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set a custom Nextcloud/OwnCloud chunked upload staging root URL.
    pub fn with_chunked_upload_root(mut self, root: impl Into<String>) -> Self {
        self.chunked_upload_root = Some(root.into());
        self
    }
}

impl std::fmt::Debug for WebdavRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebdavRemoteConfig")
            .field("url", &self.url)
            .field("vendor", &self.vendor)
            .field("username", &self.username)
            .field("password", &debug_secret_opt(&self.password))
            .field("bearer_token", &debug_secret_opt(&self.bearer_token))
            .field(
                "bearer_token_command",
                &debug_secret_opt(&self.bearer_token_command),
            )
            .field("headers", &debug_secret_headers(&self.headers))
            .field("chunked_upload_root", &self.chunked_upload_root)
            .finish()
    }
}

/// Declarative SSH/SFTP remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SftpRemoteConfig {
    /// SSH server hostname or IP address.
    pub host: String,
    /// SSH TCP port (default: 22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH login username.
    pub user: String,
    /// Optional remote root directory path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    /// Password authentication secret (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Path to SSH private key file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    /// Inline SSH private key PEM material (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    /// Passphrase for encrypted SSH private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_passphrase: Option<String>,
    /// Host key verification policy (`accept-new`, `strict`, `insecure`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_policy: Option<String>,
    /// Custom OpenSSH `known_hosts` file path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_path: Option<PathBuf>,
}

impl SftpRemoteConfig {
    /// Create an SFTP remote configuration for `user@host`.
    pub fn new(host: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            ..Self::default()
        }
    }

    /// Set the SSH TCP port (defaults to 22).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the remote root directory path.
    pub fn with_root_path(mut self, root_path: impl Into<String>) -> Self {
        self.root_path = Some(root_path.into());
        self
    }

    /// Set SSH password authentication (inline or `keyring://rship/...`).
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the path to an SSH private key file.
    pub fn with_key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.key_file = Some(path.into());
        self
    }

    /// Set inline SSH private key PEM material (inline or `keyring://rship/...`).
    pub fn with_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.key_pem = Some(pem.into());
        self
    }

    /// Set the passphrase for an encrypted SSH private key.
    pub fn with_key_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.key_passphrase = Some(passphrase.into());
        self
    }

    /// Set the SSH host key verification policy (`accept-new`, `strict`, `insecure`).
    pub fn with_host_key_policy(mut self, policy: impl Into<String>) -> Self {
        self.host_key_policy = Some(policy.into());
        self
    }

    /// Set a custom OpenSSH `known_hosts` file path.
    pub fn with_known_hosts_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts_path = Some(path.into());
        self
    }
}

impl std::fmt::Debug for SftpRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpRemoteConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("root_path", &self.root_path)
            .field("password", &debug_secret_opt(&self.password))
            .field("key_file", &self.key_file)
            .field("key_pem", &debug_secret_opt(&self.key_pem))
            .field("key_passphrase", &debug_secret_opt(&self.key_passphrase))
            .field("host_key_policy", &self.host_key_policy)
            .field("known_hosts_path", &self.known_hosts_path)
            .finish()
    }
}

/// Declarative Dropbox v2 remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DropboxRemoteConfig {
    /// Dropbox App Key (`client_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional Dropbox App Secret (`client_secret`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Optional starting root path inside Dropbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    /// Optional Dropbox namespace ID / path-root override (`Dropbox-API-Path-Root`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_namespace: Option<String>,
    /// Optional Dropbox team member ID (`dbmid:...`) or email to impersonate (`Dropbox-API-Select-User`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonate: Option<String>,
    /// Whether to include/query shared folders (`--dropbox-shared-folders`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_folders: Option<bool>,
    /// Custom Dropbox RPC API base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Custom Dropbox Content API base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_base_url: Option<String>,
    /// Custom OAuth authorization endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// Custom OAuth token endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// Optional static Bearer access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl DropboxRemoteConfig {
    /// Create an empty Dropbox remote configuration ready for fluent customization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Dropbox App Key (`client_id`).
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the Dropbox App Secret (`client_secret`, inline or `keyring://rship/...`).
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the starting root path inside Dropbox.
    pub fn with_root_path(mut self, root_path: impl Into<String>) -> Self {
        self.root_path = Some(root_path.into());
        self
    }

    /// Set the Dropbox namespace ID / path-root override (`Dropbox-API-Path-Root`).
    pub fn with_root_namespace(mut self, root_namespace: impl Into<String>) -> Self {
        self.root_namespace = Some(root_namespace.into());
        self
    }

    /// Set the Dropbox team member ID (`dbmid:...`) or email to impersonate (`Dropbox-API-Select-User`).
    pub fn with_impersonate(mut self, impersonate: impl Into<String>) -> Self {
        self.impersonate = Some(impersonate.into());
        self
    }

    /// Enable or disable querying Dropbox shared folders.
    pub fn with_shared_folders(mut self, enabled: bool) -> Self {
        self.shared_folders = Some(enabled);
        self
    }

    /// Override the Dropbox RPC API base URL.
    pub fn with_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Override the Dropbox Content API base URL.
    pub fn with_content_base_url(mut self, url: impl Into<String>) -> Self {
        self.content_base_url = Some(url.into());
        self
    }

    /// Override the OAuth authorization endpoint URL.
    pub fn with_auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Override the OAuth token endpoint URL.
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Set a static Bearer access token.
    pub fn with_access_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for DropboxRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxRemoteConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &debug_secret_opt(&self.client_secret))
            .field("root_path", &self.root_path)
            .field("root_namespace", &self.root_namespace)
            .field("impersonate", &self.impersonate)
            .field("shared_folders", &self.shared_folders)
            .field("api_base_url", &self.api_base_url)
            .field("content_base_url", &self.content_base_url)
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("access_token", &debug_secret_opt(&self.access_token))
            .finish()
    }
}

/// Declarative Google Cloud Storage (GCS) JSON API remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GcsRemoteConfig {
    /// Optional default GCS bucket name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Optional object prefix within the bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Optional GCP project number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_number: Option<String>,
    /// Optional billing project ID sent as `userProject` for Requester Pays buckets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_project: Option<String>,
    /// Optional GCS storage class (`STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// OAuth 2.0 client ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// OAuth 2.0 client secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// OAuth scope URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Path to a Google Service Account JSON key file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_file: Option<PathBuf>,
    /// Optional Domain-Wide Delegation user email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonate: Option<String>,
    /// Resolve ambient GCP environment/metadata credentials (`env_auth` in `rclone.conf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_auth: Option<bool>,
    /// Access public buckets without authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<bool>,
    /// Custom GCS root endpoint URL (derives JSON API & upload base URLs unless overridden).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Custom GCS JSON API base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Custom GCS upload API base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_base_url: Option<String>,
    /// Custom OAuth authorization endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// Custom OAuth token endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// Optional static Bearer access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl GcsRemoteConfig {
    /// Create an empty Google Cloud Storage remote configuration ready for fluent customization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default GCS bucket name.
    pub fn with_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Set the default object prefix inside the bucket.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Set the GCP project number.
    pub fn with_project_number(mut self, project_number: impl Into<String>) -> Self {
        self.project_number = Some(project_number.into());
        self
    }

    /// Set the billing project ID (`userProject`) for Requester Pays buckets.
    pub fn with_user_project(mut self, user_project: impl Into<String>) -> Self {
        self.user_project = Some(user_project.into());
        self
    }

    /// Set the default GCS storage class (`STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`).
    pub fn with_storage_class(mut self, storage_class: impl Into<String>) -> Self {
        self.storage_class = Some(storage_class.into());
        self
    }

    /// Set the OAuth 2.0 client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the OAuth 2.0 client secret (inline or `keyring://rship/...`).
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the OAuth scope URL.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the path to a Google Service Account JSON key file.
    pub fn with_service_account_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.service_account_file = Some(path.into());
        self
    }

    /// Set the Domain-Wide Delegation user email for Service Accounts.
    pub fn with_impersonate(mut self, email: impl Into<String>) -> Self {
        self.impersonate = Some(email.into());
        self
    }

    /// Enable or disable ambient GCP environment credential resolution (`env_auth`).
    pub fn with_env_auth(mut self, env_auth: bool) -> Self {
        self.env_auth = Some(env_auth);
        self
    }

    /// Enable or disable anonymous access for public GCS buckets.
    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = Some(anonymous);
        self
    }

    /// Set a custom GCS root endpoint URL (derives API and upload base URLs unless overridden).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Override the GCS JSON API base URL.
    pub fn with_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Override the GCS upload API base URL.
    pub fn with_upload_base_url(mut self, url: impl Into<String>) -> Self {
        self.upload_base_url = Some(url.into());
        self
    }

    /// Override the OAuth authorization endpoint URL.
    pub fn with_auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    /// Override the OAuth token endpoint URL.
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Set a static Bearer access token.
    pub fn with_access_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for GcsRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsRemoteConfig")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("project_number", &self.project_number)
            .field("user_project", &self.user_project)
            .field("storage_class", &self.storage_class)
            .field("client_id", &self.client_id)
            .field("client_secret", &debug_secret_opt(&self.client_secret))
            .field("scope", &self.scope)
            .field("service_account_file", &self.service_account_file)
            .field("impersonate", &self.impersonate)
            .field("env_auth", &self.env_auth)
            .field("anonymous", &self.anonymous)
            .field("endpoint", &self.endpoint)
            .field("api_base_url", &self.api_base_url)
            .field("upload_base_url", &self.upload_base_url)
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("access_token", &debug_secret_opt(&self.access_token))
            .finish()
    }
}

/// Declarative Azure Blob Storage remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AzureblobRemoteConfig {
    /// Azure storage account name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Optional default container name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Optional blob prefix within the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Base64 Shared Key secret (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Pre-signed SAS URL or query token (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas_url: Option<String>,
    /// Custom Azure Blob / Azurite endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional blob access tier (`Hot`, `Cool`, `Cold`, `Archive`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_tier: Option<String>,
    /// Access public containers anonymously.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<bool>,
}

impl AzureblobRemoteConfig {
    /// Create an empty Azure Blob Storage remote configuration ready for fluent customization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Azure storage account name.
    pub fn with_account(mut self, account: impl Into<String>) -> Self {
        self.account = Some(account.into());
        self
    }

    /// Set the default Azure Blob container name.
    pub fn with_container(mut self, container: impl Into<String>) -> Self {
        self.container = Some(container.into());
        self
    }

    /// Set the default blob prefix inside the container.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Set the base64 Shared Key secret (inline or `keyring://rship/...`).
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Set a pre-signed SAS URL or query token (inline or `keyring://rship/...`).
    pub fn with_sas_url(mut self, sas_url: impl Into<String>) -> Self {
        self.sas_url = Some(sas_url.into());
        self
    }

    /// Override the Azure Blob / Azurite endpoint URL.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the default blob access tier (`Hot`, `Cool`, `Cold`, `Archive`).
    pub fn with_access_tier(mut self, access_tier: impl Into<String>) -> Self {
        self.access_tier = Some(access_tier.into());
        self
    }

    /// Enable or disable anonymous access for public containers.
    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = Some(anonymous);
        self
    }
}

impl std::fmt::Debug for AzureblobRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureblobRemoteConfig")
            .field("account", &self.account)
            .field("container", &self.container)
            .field("prefix", &self.prefix)
            .field("key", &debug_secret_opt(&self.key))
            .field("sas_url", &debug_secret_opt(&self.sas_url))
            .field("endpoint", &self.endpoint)
            .field("access_tier", &self.access_tier)
            .field("anonymous", &self.anonymous)
            .finish()
    }
}

/// Declarative STREAM OAE2 client-side encryption overlay remote configuration.
#[must_use]
#[derive(Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CryptRemoteConfig {
    /// Underlying remote target, e.g. `my-s3:bucket/vault`, `gdrive:vault`, or `/local/vault`.
    pub remote: String,
    /// Passphrase for Argon2id key derivation (or `keyring://rship/...` pointer).
    /// Can also be supplied via the `RSHIP_CRYPT_PASSWORD` environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Direct 64-character hex master key (or `keyring://rship/...` pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
    /// Optional Argon2id salt string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// Filename encryption mode: `"standard"` (default, deterministic base32 SIV) or `"off"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename_encryption: Option<String>,
}

impl CryptRemoteConfig {
    /// Create a STREAM OAE2 encryption overlay wrapping `remote` (e.g. `"my-s3:bucket/vault"`).
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            ..Self::default()
        }
    }

    /// Set the Argon2id passphrase (inline or `keyring://rship/...`).
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set a direct 64-character hex master key (inline or `keyring://rship/...`).
    pub fn with_key_hex(mut self, key_hex: impl Into<String>) -> Self {
        self.key_hex = Some(key_hex.into());
        self
    }

    /// Set an optional Argon2id key-derivation salt.
    pub fn with_salt(mut self, salt: impl Into<String>) -> Self {
        self.salt = Some(salt.into());
        self
    }

    /// Set the filename encryption mode (`"standard"` or `"off"`).
    pub fn with_filename_encryption(mut self, mode: impl Into<String>) -> Self {
        self.filename_encryption = Some(mode.into());
        self
    }
}

impl std::fmt::Debug for CryptRemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptRemoteConfig")
            .field("remote", &self.remote)
            .field("password", &debug_secret_opt(&self.password))
            .field("key_hex", &debug_secret_opt(&self.key_hex))
            .field("salt", &self.salt)
            .field("filename_encryption", &self.filename_encryption)
            .finish()
    }
}

/// Declarative local filesystem directory remote configuration.
#[must_use]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LocalRemoteConfig {
    /// Root directory path on disk.
    pub root: PathBuf,
    /// Filename encoding mode: `"identity"` (default) or `"windows_safe"` (`WindowsSafe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl LocalRemoteConfig {
    /// Create a local filesystem remote configuration rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            encoding: None,
        }
    }

    /// Set the filename encoding mode (`"identity"` or `"windows_safe"`).
    pub fn with_encoding(mut self, encoding: impl Into<String>) -> Self {
        self.encoding = Some(encoding.into());
        self
    }
}

/// Tagged union of all supported declarative remote configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteConfig {
    /// Local filesystem directory remote.
    Local(Box<LocalRemoteConfig>),
    /// Google Drive v3 remote.
    Gdrive(Box<GdriveRemoteConfig>),
    /// S3-compatible object storage remote.
    S3(Box<S3RemoteConfig>),
    /// Microsoft OneDrive / SharePoint remote.
    Onedrive(Box<OnedriveRemoteConfig>),
    /// WebDAV remote.
    Webdav(Box<WebdavRemoteConfig>),
    /// SSH/SFTP remote.
    Sftp(Box<SftpRemoteConfig>),
    /// Dropbox v2 remote.
    Dropbox(Box<DropboxRemoteConfig>),
    /// Google Cloud Storage remote.
    Gcs(Box<GcsRemoteConfig>),
    /// Azure Blob Storage remote.
    Azureblob(Box<AzureblobRemoteConfig>),
    /// Zero-knowledge STREAM OAE2 encryption overlay remote.
    Crypt(Box<CryptRemoteConfig>),
}

impl RemoteConfig {
    /// Construct a local filesystem remote rooted at `root`.
    pub fn local(root: impl Into<PathBuf>) -> Self {
        Self::Local(Box::new(LocalRemoteConfig::new(root)))
    }

    /// Construct a Google Drive remote from [`GdriveRemoteConfig`].
    pub fn gdrive(cfg: GdriveRemoteConfig) -> Self {
        Self::Gdrive(Box::new(cfg))
    }

    /// Construct an S3-compatible remote from [`S3RemoteConfig`].
    pub fn s3(cfg: S3RemoteConfig) -> Self {
        Self::S3(Box::new(cfg))
    }

    /// Construct a Microsoft OneDrive remote from [`OnedriveRemoteConfig`].
    pub fn onedrive(cfg: OnedriveRemoteConfig) -> Self {
        Self::Onedrive(Box::new(cfg))
    }

    /// Construct a WebDAV remote from [`WebdavRemoteConfig`].
    pub fn webdav(cfg: WebdavRemoteConfig) -> Self {
        Self::Webdav(Box::new(cfg))
    }

    /// Construct an SSH/SFTP remote from [`SftpRemoteConfig`].
    pub fn sftp(cfg: SftpRemoteConfig) -> Self {
        Self::Sftp(Box::new(cfg))
    }

    /// Construct a Dropbox remote from [`DropboxRemoteConfig`].
    pub fn dropbox(cfg: DropboxRemoteConfig) -> Self {
        Self::Dropbox(Box::new(cfg))
    }

    /// Construct a Google Cloud Storage remote from [`GcsRemoteConfig`].
    pub fn gcs(cfg: GcsRemoteConfig) -> Self {
        Self::Gcs(Box::new(cfg))
    }

    /// Construct an Azure Blob Storage remote from [`AzureblobRemoteConfig`].
    pub fn azureblob(cfg: AzureblobRemoteConfig) -> Self {
        Self::Azureblob(Box::new(cfg))
    }

    /// Construct a STREAM OAE2 encryption overlay remote from [`CryptRemoteConfig`].
    pub fn crypt(cfg: CryptRemoteConfig) -> Self {
        Self::Crypt(Box::new(cfg))
    }

    /// Canonical lowercase driver identifier string.
    pub fn kind_str(&self) -> &'static str {
        self.kind().as_str()
    }

    /// Strongly-typed backend driver kind.
    pub fn kind(&self) -> BackendKind {
        match self {
            Self::Local(_) => BackendKind::Local,
            Self::Gdrive(_) => BackendKind::Gdrive,
            Self::S3(_) => BackendKind::S3,
            Self::Onedrive(_) => BackendKind::Onedrive,
            Self::Webdav(_) => BackendKind::Webdav,
            Self::Sftp(_) => BackendKind::Sftp,
            Self::Dropbox(_) => BackendKind::Dropbox,
            Self::Gcs(_) => BackendKind::Gcs,
            Self::Azureblob(_) => BackendKind::Azureblob,
            Self::Crypt(_) => BackendKind::Crypt,
        }
    }

    /// Visit every `(field_name, field_value)` secret slot on this remote configuration.
    ///
    /// Serves as the single source of truth for secret redaction, inline-secret counting,
    /// storage badges, and OS Keyring cleanup.
    pub fn visit_secrets(&self, mut f: impl FnMut(&'static str, &Option<String>)) {
        match self {
            Self::Local(_) => {}
            Self::Gdrive(g) => {
                f("client_secret", &g.client_secret);
                f("access_token", &g.access_token);
            }
            Self::S3(s) => {
                f("secret_access_key", &s.secret_access_key);
                f("session_token", &s.session_token);
            }
            Self::Onedrive(o) => {
                f("client_secret", &o.client_secret);
                f("access_token", &o.access_token);
            }
            Self::Webdav(w) => {
                f("password", &w.password);
                f("bearer_token", &w.bearer_token);
                f("bearer_token_command", &w.bearer_token_command);
            }
            Self::Sftp(s) => {
                f("password", &s.password);
                f("key_passphrase", &s.key_passphrase);
                f("key_pem", &s.key_pem);
            }
            Self::Dropbox(d) => {
                f("client_secret", &d.client_secret);
                f("access_token", &d.access_token);
            }
            Self::Gcs(g) => {
                f("client_secret", &g.client_secret);
                f("access_token", &g.access_token);
            }
            Self::Azureblob(a) => {
                f("key", &a.key);
                f("sas_url", &a.sas_url);
            }
            Self::Crypt(c) => {
                f("password", &c.password);
                f("key_hex", &c.key_hex);
            }
        }
    }

    /// Mutably visit every `(field_name, field_value)` secret slot on this remote configuration.
    pub fn visit_secrets_mut(&mut self, mut f: impl FnMut(&'static str, &mut Option<String>)) {
        match self {
            Self::Local(_) => {}
            Self::Gdrive(g) => {
                f("client_secret", &mut g.client_secret);
                f("access_token", &mut g.access_token);
            }
            Self::S3(s) => {
                f("secret_access_key", &mut s.secret_access_key);
                f("session_token", &mut s.session_token);
            }
            Self::Onedrive(o) => {
                f("client_secret", &mut o.client_secret);
                f("access_token", &mut o.access_token);
            }
            Self::Webdav(w) => {
                f("password", &mut w.password);
                f("bearer_token", &mut w.bearer_token);
                f("bearer_token_command", &mut w.bearer_token_command);
            }
            Self::Sftp(s) => {
                f("password", &mut s.password);
                f("key_passphrase", &mut s.key_passphrase);
                f("key_pem", &mut s.key_pem);
            }
            Self::Dropbox(d) => {
                f("client_secret", &mut d.client_secret);
                f("access_token", &mut d.access_token);
            }
            Self::Gcs(g) => {
                f("client_secret", &mut g.client_secret);
                f("access_token", &mut g.access_token);
            }
            Self::Azureblob(a) => {
                f("key", &mut a.key);
                f("sas_url", &mut a.sas_url);
            }
            Self::Crypt(c) => {
                f("password", &mut c.password);
                f("key_hex", &mut c.key_hex);
            }
        }
    }

    /// Mask all inline secrets in place (preserving safe `keyring://` references).
    pub fn redact_in_place(&mut self) {
        self.visit_secrets_mut(|_, field| redact_opt(field));
        if let Self::Webdav(w) = self {
            for (_, val) in &mut w.headers {
                if !is_keyring_ref(val) {
                    *val = REDACTED_SECRET.to_string();
                }
            }
        }
    }
}

impl From<LocalRemoteConfig> for RemoteConfig {
    fn from(cfg: LocalRemoteConfig) -> Self {
        Self::Local(Box::new(cfg))
    }
}

impl From<GdriveRemoteConfig> for RemoteConfig {
    fn from(cfg: GdriveRemoteConfig) -> Self {
        Self::gdrive(cfg)
    }
}

impl From<S3RemoteConfig> for RemoteConfig {
    fn from(cfg: S3RemoteConfig) -> Self {
        Self::s3(cfg)
    }
}

impl From<OnedriveRemoteConfig> for RemoteConfig {
    fn from(cfg: OnedriveRemoteConfig) -> Self {
        Self::onedrive(cfg)
    }
}

impl From<WebdavRemoteConfig> for RemoteConfig {
    fn from(cfg: WebdavRemoteConfig) -> Self {
        Self::webdav(cfg)
    }
}

impl From<SftpRemoteConfig> for RemoteConfig {
    fn from(cfg: SftpRemoteConfig) -> Self {
        Self::sftp(cfg)
    }
}

impl From<DropboxRemoteConfig> for RemoteConfig {
    fn from(cfg: DropboxRemoteConfig) -> Self {
        Self::dropbox(cfg)
    }
}

impl From<GcsRemoteConfig> for RemoteConfig {
    fn from(cfg: GcsRemoteConfig) -> Self {
        Self::gcs(cfg)
    }
}

impl From<AzureblobRemoteConfig> for RemoteConfig {
    fn from(cfg: AzureblobRemoteConfig) -> Self {
        Self::azureblob(cfg)
    }
}

impl From<CryptRemoteConfig> for RemoteConfig {
    fn from(cfg: CryptRemoteConfig) -> Self {
        Self::crypt(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use std::collections::BTreeMap;

    #[test]
    fn legacy_toml_without_new_fields_deserializes_and_omits_empty_defaults() {
        let legacy_toml = r#"
[remotes.loc]
type = "local"
root = "/var/backups"

[remotes.gd]
type = "gdrive"
client_id = "cid"

[remotes.od]
type = "onedrive"
client_id = "od-cid"

[remotes.dav]
type = "webdav"
url = "https://dav.example.com"

[remotes.sf]
type = "sftp"
host = "sftp.example.com"
user = "alice"

[remotes.dbx]
type = "dropbox"
client_id = "dbx-cid"

[remotes.gcs]
type = "gcs"
bucket = "my-gcs"
"#;
        let parsed: AppConfig = toml::from_str(legacy_toml).expect("legacy TOML must deserialize");

        match parsed.remotes.get("loc") {
            Some(RemoteConfig::Local(l)) => {
                assert_eq!(l.root, PathBuf::from("/var/backups"));
                assert_eq!(l.encoding, None);
            }
            other => panic!("expected Local, got {other:?}"),
        }
        match parsed.remotes.get("gd") {
            Some(RemoteConfig::Gdrive(g)) => {
                assert_eq!(g.use_trash, None);
                assert_eq!(g.shared_with_me, None);
                assert_eq!(g.trashed_only, None);
            }
            other => panic!("expected Gdrive, got {other:?}"),
        }
        match parsed.remotes.get("od") {
            Some(RemoteConfig::Onedrive(o)) => {
                assert_eq!(o.region, None);
                assert_eq!(o.drive_type, None);
                assert_eq!(o.chunk_size, None);
            }
            other => panic!("expected Onedrive, got {other:?}"),
        }
        match parsed.remotes.get("dav") {
            Some(RemoteConfig::Webdav(w)) => {
                assert!(w.headers.is_empty());
                assert_eq!(w.bearer_token_command, None);
            }
            other => panic!("expected Webdav, got {other:?}"),
        }
        match parsed.remotes.get("sf") {
            Some(RemoteConfig::Sftp(s)) => {
                assert_eq!(s.key_pem, None);
            }
            other => panic!("expected Sftp, got {other:?}"),
        }
        match parsed.remotes.get("dbx") {
            Some(RemoteConfig::Dropbox(d)) => {
                assert_eq!(d.root_namespace, None);
                assert_eq!(d.impersonate, None);
                assert_eq!(d.shared_folders, None);
            }
            other => panic!("expected Dropbox, got {other:?}"),
        }
        match parsed.remotes.get("gcs") {
            Some(RemoteConfig::Gcs(g)) => {
                assert_eq!(g.endpoint, None);
                assert_eq!(g.user_project, None);
                assert_eq!(g.env_auth, None);
            }
            other => panic!("expected Gcs, got {other:?}"),
        }

        let serialized = toml::to_string(&parsed).unwrap();
        assert!(!serialized.contains("encoding"));
        assert!(!serialized.contains("shared_with_me"));
        assert!(!serialized.contains("headers"));
        assert!(!serialized.contains("bearer_token_command"));
        assert!(!serialized.contains("key_pem"));
        assert!(!serialized.contains("user_project"));
    }

    #[test]
    fn local_remote_config_encoding_roundtrips_and_converts() {
        let cfg = LocalRemoteConfig::new("/tmp/root").with_encoding("windows_safe");
        let app = AppConfig::new().with_remote("loc", cfg);
        let toml_str = toml::to_string(&app).unwrap();
        assert!(toml_str.contains("encoding = \"windows_safe\""));

        let decoded: AppConfig = toml::from_str(&toml_str).unwrap();
        match decoded.remotes.get("loc") {
            Some(RemoteConfig::Local(l)) => {
                assert_eq!(l.root, PathBuf::from("/tmp/root"));
                assert_eq!(l.encoding.as_deref(), Some("windows_safe"));
            }
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn builders_populate_new_fields_and_debug_visit_redact_handle_secrets() {
        let gd = GdriveRemoteConfig::new()
            .with_shared_with_me(true)
            .with_trashed_only(true);
        assert_eq!(gd.shared_with_me, Some(true));
        assert_eq!(gd.trashed_only, Some(true));

        let od = OnedriveRemoteConfig::new()
            .with_region("cn")
            .with_drive_type("business")
            .with_chunk_size(5 * 1024 * 1024);
        assert_eq!(od.region.as_deref(), Some("cn"));
        assert_eq!(od.drive_type.as_deref(), Some("business"));
        assert_eq!(od.chunk_size, Some(5 * 1024 * 1024));

        let dbx = DropboxRemoteConfig::new()
            .with_root_namespace("ns:42")
            .with_impersonate("dbmid:u1")
            .with_shared_folders(true);
        assert_eq!(dbx.root_namespace.as_deref(), Some("ns:42"));
        assert_eq!(dbx.impersonate.as_deref(), Some("dbmid:u1"));
        assert_eq!(dbx.shared_folders, Some(true));

        let gcs = GcsRemoteConfig::new()
            .with_endpoint("http://127.0.0.1:4443")
            .with_user_project("pay-proj")
            .with_env_auth(true);
        assert_eq!(gcs.endpoint.as_deref(), Some("http://127.0.0.1:4443"));
        assert_eq!(gcs.user_project.as_deref(), Some("pay-proj"));
        assert_eq!(gcs.env_auth, Some(true));

        let mut dav_rcfg: RemoteConfig = WebdavRemoteConfig::new("https://dav.example.com")
            .with_header("X-Secret-Header", "inline-header-secret")
            .with_header("X-Keyring-Header", "keyring://rship/dav.hdr")
            .with_bearer_token_command("secret-cmd --token")
            .into();
        let mut sftp_rcfg: RemoteConfig = SftpRemoteConfig::new("host", "alice")
            .with_key_pem("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_BODY")
            .into();

        // Debug must redact inline secrets/header values/commands while keeping keyring refs & header names.
        let dav_dbg = format!("{dav_rcfg:?}");
        assert!(dav_dbg.contains("X-Secret-Header"));
        assert!(!dav_dbg.contains("inline-header-secret"));
        assert!(dav_dbg.contains("keyring://rship/dav.hdr"));
        assert!(!dav_dbg.contains("secret-cmd"));
        assert!(dav_dbg.contains(REDACTED_SECRET));

        let sftp_dbg = format!("{sftp_rcfg:?}");
        assert!(!sftp_dbg.contains("SECRET_KEY_BODY"));
        assert!(sftp_dbg.contains(REDACTED_SECRET));

        // visit_secrets must yield bearer_token_command and key_pem.
        let mut dav_slots = BTreeMap::new();
        dav_rcfg.visit_secrets(|k, v| {
            dav_slots.insert(k, v.clone());
        });
        assert_eq!(
            dav_slots
                .get("bearer_token_command")
                .and_then(|v| v.as_deref()),
            Some("secret-cmd --token")
        );

        let mut sftp_slots = BTreeMap::new();
        sftp_rcfg.visit_secrets(|k, v| {
            sftp_slots.insert(k, v.clone());
        });
        assert_eq!(
            sftp_slots.get("key_pem").and_then(|v| v.as_deref()),
            Some("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_BODY")
        );

        // visit_secrets_mut & redact_in_place must mask inline values and preserve keyring refs.
        dav_rcfg.redact_in_place();
        match &dav_rcfg {
            RemoteConfig::Webdav(w) => {
                assert_eq!(w.bearer_token_command.as_deref(), Some(REDACTED_SECRET));
                assert_eq!(
                    w.headers,
                    vec![
                        ("X-Secret-Header".to_string(), REDACTED_SECRET.to_string()),
                        (
                            "X-Keyring-Header".to_string(),
                            "keyring://rship/dav.hdr".to_string()
                        ),
                    ]
                );
            }
            other => panic!("expected Webdav, got {other:?}"),
        }

        sftp_rcfg.redact_in_place();
        match &sftp_rcfg {
            RemoteConfig::Sftp(s) => {
                assert_eq!(s.key_pem.as_deref(), Some(REDACTED_SECRET));
            }
            other => panic!("expected Sftp, got {other:?}"),
        }
    }
}
